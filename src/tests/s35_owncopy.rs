// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Live outgoing sibling rows, observed through subscription before any explicit history sync.
use ramflux_sdk::LocalBusClient;
use serde_json::{Value, json};
use std::time::Duration;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const ACCOUNT: &str = "bob_s35_account";

pub(super) async fn assert_live_sent_messages(
    primary: &mut LocalBusClient,
    sibling: &mut LocalBusClient,
    alice_commitment: &str,
    own_commitment: &str,
) -> TestResult {
    call(sibling, "bus.subscribe", json!({"topics":["*"],"since_seq":null})).await?;
    call(primary, "message.submit", json!({
        "conversation_id":"conv_s35_alice_bob","message_id":"s35_bob_sent_dm","envelope_id":"s35_bob_sent_envelope",
        "source_principal_id":"principal_s35_bob","sender_id":"bob_device_s35_a",
        "recipient_device_id":"alice_device_s35","recipient_principal_commitment":alice_commitment,
        "target_delivery_id":"target_s35_alice","encrypted_body_base64":"",
        "plaintext_body_base64":ramflux_protocol::encode_base64url(b"s35 outgoing live DM"),
        "created_at":super::itest_now_unix_seconds(),"ttl":300
    })).await?;
    observe(
        sibling,
        "conv_s35_alice_bob",
        "s35_bob_sent_dm",
        "s35 outgoing live DM",
        own_commitment,
    )
    .await?;
    call(
        primary,
        "group.create",
        json!({"group_id":"s35_own_group","creator_id":"bob_device_s35_a",
        "creator_target_delivery_id":"target_s35_bob_a"}),
    )
    .await?;
    call(primary, "group.member.add", json!({"group_id":"s35_own_group","member_id":"alice_device_s35",
        "role":"member","target_delivery_id":"target_s35_alice","member_principal_commitment":alice_commitment})).await?;
    let submitted = call(primary, "group.send", json!({
        "group_id":"s35_own_group","conversation_id":"s35_own_group_thread","message_id":"s35_bob_sent_group",
        "sender_id":"bob_device_s35_a","encrypted_body_base64":"",
        "plaintext_body_base64":ramflux_protocol::encode_base64url(b"s35 outgoing live group"),"ttl":300
    })).await?;
    assert_eq!(submitted["message_id"], "s35_bob_sent_group");
    observe(
        sibling,
        "s35_own_group_thread",
        "s35_bob_sent_group",
        "s35 outgoing live group",
        own_commitment,
    )
    .await?;
    // Re-reading must keep the same single row after additional autonomous sync cycles.
    tokio::time::sleep(Duration::from_millis(750)).await;
    assert_row(
        sibling,
        "conv_s35_alice_bob",
        "s35_bob_sent_dm",
        "s35 outgoing live DM",
        own_commitment,
    )
    .await?;
    assert_row(
        sibling,
        "s35_own_group_thread",
        "s35_bob_sent_group",
        "s35 outgoing live group",
        own_commitment,
    )
    .await?;
    Ok(())
}
async fn call(bus: &mut LocalBusClient, method: &str, body: Value) -> TestResult<Value> {
    Ok(bus.request(Some(ACCOUNT.into()), "owncopy", method, body).await?)
}
async fn observe(
    bus: &mut LocalBusClient,
    conversation: &str,
    message: &str,
    text: &str,
    root: &str,
) -> TestResult {
    tokio::time::timeout(Duration::from_secs(35), async {
        loop {
            let event = bus.next_event().await?;
            let row = &event.body["message"];
            if row["original_message_id"] == message {
                assert_eq!(row["direction"], "outgoing");
                assert_eq!(row["sender_device_id"], "bob_device_s35_a");
                assert_eq!(row["sender_root_commitment"], root);
                break;
            }
        }
        Ok::<_, Box<dyn std::error::Error>>(())
    })
    .await
    .map_err(|_| format!("s35 live outgoing subscription timed out for {message}"))??;
    assert_row(bus, conversation, message, text, root).await
}
async fn assert_row(
    bus: &mut LocalBusClient,
    conversation: &str,
    message: &str,
    text: &str,
    root: &str,
) -> TestResult {
    let snapshot = call(bus, "message.list", json!({"conversation_id":conversation})).await?;
    let rows = snapshot["messages"].as_array().ok_or("s35 missing messages")?;
    let rows = rows.iter().filter(|r| r["original_message_id"] == message).collect::<Vec<_>>();
    assert_eq!(rows.len(), 1, "one live outgoing row per original envelope/source");
    assert_eq!(rows[0]["body_utf8"], text);
    assert_eq!(rows[0]["direction"], "outgoing");
    assert_eq!(rows[0]["sender_device_id"], "bob_device_s35_a");
    assert_eq!(rows[0]["sender_root_commitment"], root);
    Ok(())
}

pub(super) async fn assert_history_keeps_one_row(
    primary: &mut LocalBusClient,
    sibling: &mut LocalBusClient,
    relay_endpoint: &str,
) -> TestResult {
    let exported = call(
        primary,
        "device.sync.export",
        serde_json::to_value(ramflux_sdk::LocalBusDeviceSyncExportRequest {
            target_device_id: "bob_device_s35_b".into(),
            relay_endpoint: relay_endpoint.into(),
            relay_service_key_base64: None,
            chunk_size: Some(4096),
        })?,
    )
    .await?;
    assert_eq!(exported["transfer"]["state"], "complete");
    let imported = call(
        sibling,
        "device.sync.import",
        serde_json::to_value(ramflux_sdk::LocalBusDeviceSyncImportRequest {
            envelope: exported["envelope"].clone(),
            relay_service_key_base64: None,
        })?,
    )
    .await?;
    assert_eq!(imported["imported_dm_sessions"], 0);
    for (conversation, text) in [
        ("conv_s35_alice_bob", "s35 outgoing live DM"),
        ("s35_own_group_thread", "s35 outgoing live group"),
    ] {
        let snapshot =
            call(sibling, "message.list", json!({"conversation_id":conversation})).await?;
        let rows = snapshot["messages"].as_array().ok_or("s35 history rows")?;
        assert_eq!(
            rows.iter().filter(|row| row["body_utf8"] == text).count(),
            1,
            "history must not duplicate the live outgoing body: {text}"
        );
    }
    Ok(())
}
