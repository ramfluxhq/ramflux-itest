// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Live outgoing sibling rows, observed through subscription before any explicit history sync.
use ramflux_sdk::LocalBusClient;
use serde_json::{Value, json};
use std::{path::Path, time::Duration};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const ACCOUNT: &str = "bob_s35_account";
struct ExpectedRow<'a> {
    conversation: &'a str,
    message: &'a str,
    message_field: &'a str,
    text: &'a str,
    root: &'a str,
}

pub(super) async fn assert_live_sent_messages(
    primary: &mut LocalBusClient,
    sibling: &mut LocalBusClient,
    alice_commitment: &str,
    own_commitment: &str,
    sibling_socket: &Path,
) -> TestResult {
    // Observe live message rows separately from command responses and history-import progress.
    // Dropping this scoped connection ends the subscription before explicit history sync.
    let mut events = LocalBusClient::connect(sibling_socket).await?;
    call(&mut events, "bus.subscribe", json!({
        "topics":["message.received","group.message.received","message.updated"],"since_seq":null
    })).await?;
    call(primary, "message.submit", json!({
        "conversation_id":"conv_s35_alice_bob","message_id":"s35_bob_sent_dm","envelope_id":"s35_bob_sent_envelope",
        "source_principal_id":"principal_s35_bob","sender_id":"bob_device_s35_a",
        "recipient_device_id":"alice_device_s35","recipient_principal_commitment":alice_commitment,
        "target_delivery_id":"target_s35_alice","encrypted_body_base64":"",
        "plaintext_body_base64":ramflux_protocol::encode_base64url(b"s35 outgoing live DM"),
        "created_at":super::itest_now_unix_seconds(),"ttl":300
    })).await?;
    let dm = ExpectedRow {
        conversation: "conv_s35_alice_bob",
        message: "s35_bob_sent_dm",
        message_field: "original_message_id",
        text: "s35 outgoing live DM",
        root: own_commitment,
    };
    observe(&mut events, sibling, &dm).await?;
    call(
        primary,
        "group.create",
        json!({"group_id":"s35_own_group","creator_id":"bob_device_s35_a",
        "creator_target_delivery_id":"target_s35_bob_a","conversation_id":"s35_own_group_thread"}),
    )
    .await?;
    call(primary, "group.member.add", json!({"group_id":"s35_own_group","member_id":"alice_device_s35",
        "role":"member","target_delivery_id":"target_s35_alice","member_principal_commitment":alice_commitment})).await?;
    let submitted = call(primary, "group.send", json!({
        "group_id":"s35_own_group","conversation_id":"s35_own_group_thread","message_id":"s35_bob_sent_group",
        "sender_id":"bob_device_s35_a","encrypted_body_base64":"",
        "plaintext_body_base64":ramflux_protocol::encode_base64url(b"s35 outgoing live group"),"ttl":300
    })).await?;
    let group_message = ramflux_protocol::group_message_id(
        "s35_own_group",
        own_commitment,
        "bob_device_s35_a",
        "s35_bob_sent_group",
    )?;
    assert_eq!(submitted["message_id"], group_message);
    assert_eq!(submitted["client_message_id"], "s35_bob_sent_group");
    let group = ExpectedRow {
        conversation: "s35_own_group_thread",
        message: &group_message,
        message_field: "message_id",
        text: "s35 outgoing live group",
        root: own_commitment,
    };
    observe(&mut events, sibling, &group).await?;
    // Re-reading must keep the same single row after additional autonomous sync cycles.
    tokio::time::sleep(Duration::from_millis(750)).await;
    assert_row(sibling, &dm).await?;
    assert_row(sibling, &group).await?;
    Ok(())
}
async fn call(bus: &mut LocalBusClient, method: &str, body: Value) -> TestResult<Value> {
    Ok(bus.request(Some(ACCOUNT.into()), "owncopy", method, body).await?)
}
async fn observe(
    events: &mut LocalBusClient,
    bus: &mut LocalBusClient,
    expected: &ExpectedRow<'_>,
) -> TestResult {
    let &ExpectedRow { message, message_field, root, .. } = expected;
    tokio::time::timeout(Duration::from_secs(35), async {
        loop {
            let event = events.next_event().await?;
            if event.method == "stream.lagged" {
                return Err("s35 live message observer lagged".into());
            }
            let row = &event.body["message"];
            if row[message_field] == message {
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
    assert_row(bus, expected).await
}
async fn assert_row(bus: &mut LocalBusClient, expected: &ExpectedRow<'_>) -> TestResult {
    let &ExpectedRow { conversation, message, message_field, text, root } = expected;
    let snapshot = call(bus, "message.list", json!({"conversation_id":conversation})).await?;
    let rows = snapshot["messages"].as_array().ok_or("s35 missing messages")?;
    assert_eq!(
        rows.iter().filter(|row| row["body_utf8"] == text).count(),
        1,
        "one body across original delivery and live own copy"
    );
    let rows = rows.iter().filter(|row| row[message_field] == message).collect::<Vec<_>>();
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
