// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Fresh contacts must resolve their own actionable DM routes without fixture-supplied peer keys.
#![cfg(feature = "realnet")]
use super::*;
use serde_json::{Value, json};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[test]
fn contact01_realnet_add_then_dm() -> TestResult {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping contact01: set RAMFLUX_ITEST_REALNET=1 on the QA container host");
        return Ok(());
    }
    let topology = start_client_discovery_topology_named("ramflux-contact01", 60600)?;
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async {
        wait_for_private_gateway_quic("127.0.0.1:60643".parse()?, &topology.ca).await?;
        let binary = mvp_s4_build_rf_binary().await?;
        let root = temp_root("contact01")?;
        let a = root.join("alice.sock");
        let b = root.join("bob.sock");
        let (a_stop, a_rx) = tokio::sync::watch::channel(false);
        let (b_stop, b_rx) = tokio::sync::watch::channel(false);
        let a_server = ramflux_sdk::serve_local_bus_until(
            ramflux_sdk::LocalBusConfig::new(&a, root.join("a")),
            a_rx,
        );
        let b_server = ramflux_sdk::serve_local_bus_until(
            ramflux_sdk::LocalBusConfig::new(&b, root.join("b")),
            b_rx,
        );
        let flow = async {
            let result = async {
                mvp_s4_wait_for_socket(&a).await?;
                mvp_s4_wait_for_socket(&b).await?;
                configure(&binary, &a, &topology.origin).await?;
                configure(&binary, &b, &topology.origin).await?;
                create(&binary, &a, "alice", "a1", "a2").await?;
                create(&binary, &b, "bob", "b1", "b2").await?;
                let mut alice = ramflux_sdk::LocalBusClient::connect(&a).await?;
                let mut bob = ramflux_sdk::LocalBusClient::connect(&b).await?;
                let added = rf(
                    &binary,
                    &a,
                    &["contact", "add", "--account", "alice", "--principal", "bob"],
                )
                .await?;
                assert_contact(&added, "bob")?;
                let accepted =
                    call(&mut bob, "bob", "contact.accept", json!({"principal_id":"alice"}))
                        .await?;
                assert_contact(&accepted, "alice")?;
                exchange(&mut alice, &mut bob, "alice", "bob", "principal").await?;
                // A second fresh pair proves card resolution without identity state from principal lookup.
                create(&binary, &a, "carol", "c1", "c2").await?;
                create(&binary, &b, "dave", "d1", "d2").await?;
                let carol = rf(&binary, &a, &["contact", "card", "--account", "carol"]).await?;
                let dave = rf(&binary, &b, &["contact", "card", "--account", "dave"]).await?;
                let added = rf(
                    &binary,
                    &a,
                    &[
                        "contact",
                        "add",
                        "--account",
                        "carol",
                        "--card",
                        dave["card"].as_str().ok_or("missing card")?,
                    ],
                )
                .await?;
                assert_contact(&added, "dave")?;
                let accepted =
                    call(&mut bob, "dave", "contact.accept", json!({"card":carol["link"]})).await?;
                assert_contact(&accepted, "carol")?;
                exchange(&mut alice, &mut bob, "carol", "dave", "card").await?;
                Ok::<(), Box<dyn std::error::Error>>(())
            }
            .await;
            let _ = a_stop.send(true);
            let _ = b_stop.send(true);
            result
        };
        let (a_result, b_result, result) = tokio::time::timeout(Duration::from_mins(5), async {
            tokio::join!(a_server, b_server, Box::pin(flow))
        })
        .await?;
        a_result?;
        b_result?;
        result?;
        std::fs::remove_dir_all(root)?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}
async fn rf(binary: &Path, socket: &Path, args: &[&str]) -> TestResult<Value> {
    let mut all = vec!["--socket", socket.to_str().ok_or("socket path")?];
    all.extend_from_slice(args);
    mvp_s10_rf_json(binary, &all, "contact01").await
}
async fn configure(binary: &Path, socket: &Path, origin: &str) -> TestResult {
    rf(binary, socket, &["node", "add", origin]).await?;
    rf(binary, socket, &["node", "confirm", "localhost"]).await?;
    rf(binary, socket, &["node", "set-default", "localhost"]).await?;
    Ok(())
}
async fn create(binary: &Path, socket: &Path, id: &str, root: &str, device: &str) -> TestResult {
    let created = rf(
        binary,
        socket,
        &[
            "account",
            "create",
            "--node",
            "localhost",
            "--account",
            id,
            "--principal",
            id,
            "--device",
            id,
            "--target",
            id,
            "--secret",
            "test-only-secret",
            "--root-seed-byte-hex",
            root,
            "--device-seed-byte-hex",
            device,
        ],
    )
    .await?;
    assert_eq!(created["local_account_id"], id);
    Ok(())
}
fn assert_contact(response: &Value, principal: &str) -> TestResult {
    let contact = &response["contact"];
    assert_eq!(contact["principal_id"], principal);
    assert_eq!(contact["reachable"], true);
    assert_eq!(contact["verified"], false);
    assert!(!contact["root_commitment"].as_str().ok_or("root commitment missing")?.is_empty());
    Ok(())
}
async fn call(
    bus: &mut ramflux_sdk::LocalBusClient,
    id: &str,
    method: &str,
    body: Value,
) -> TestResult<Value> {
    Ok(bus.request(Some(id.into()), "contact01", method, body).await?)
}
async fn identity(
    bus: &mut ramflux_sdk::LocalBusClient,
    id: &str,
    peer: &str,
) -> TestResult<Value> {
    let directory = call(bus, id, "identity.directory", json!({})).await?;
    let row = directory["identities"]
        .as_array()
        .ok_or("missing identities")?
        .iter()
        .find(|r| r["principal_id"] == peer)
        .ok_or("contact did not populate the identity directory")?
        .clone();
    assert_eq!(row["reachable"], true);
    assert_eq!(row["verified"], false);
    assert_eq!(row["safety_number_available"], true);
    assert_eq!(row["safety_number"].as_array().map(Vec::len), Some(12));
    Ok(row)
}
async fn exchange(
    a: &mut ramflux_sdk::LocalBusClient,
    b: &mut ramflux_sdk::LocalBusClient,
    alice: &str,
    bob: &str,
    label: &str,
) -> TestResult {
    let bob_row = identity(a, alice, bob).await?;
    let alice_row = identity(b, bob, alice).await?;
    let safety_a = call(
        a,
        alice,
        "contact.safety_number",
        json!({"contact_identity_commitment":bob_row["contact_identity_commitment"]}),
    )
    .await?;
    let safety_b = call(
        b,
        bob,
        "contact.safety_number",
        json!({"contact_identity_commitment":alice_row["contact_identity_commitment"]}),
    )
    .await?;
    assert_eq!(safety_a["safety_number"], safety_b["safety_number"]);
    let conversation = format!("contact01-{label}");
    send(a, alice, &bob_row, &conversation, &format!("{label}-hello")).await?;
    read(b, bob, &conversation, &format!("{label}-hello"), alice).await?;
    send(b, bob, &alice_row, &conversation, &format!("{label}-reply")).await?;
    read(a, alice, &conversation, &format!("{label}-reply"), bob).await?;
    Ok(())
}
async fn send(
    bus: &mut ramflux_sdk::LocalBusClient,
    own: &str,
    peer: &Value,
    conversation: &str,
    text: &str,
) -> TestResult {
    let status = call(bus, own, "account.status", json!({})).await?;
    let device = peer["devices"]
        .as_array()
        .and_then(|devices| devices.first())
        .ok_or("resolved contact has no device")?;
    let sent=call(bus,own,"message.submit",json!({"conversation_id":conversation,"message_id":text,"envelope_id":format!("contact01-{text}"),"source_principal_id":status["principal_id"],"sender_id":status["device_id"],"recipient_device_id":device["device_id"],"recipient_principal_commitment":peer["contact_identity_commitment"],"target_delivery_id":device["target_delivery_id"],"encrypted_body_base64":"","plaintext_body_base64":ramflux_protocol::encode_base64url(text.as_bytes()),"created_at":realnet_now_i64(),"ttl":3600})).await?;
    assert!(!sent.is_null());
    Ok(())
}
async fn read(
    bus: &mut ramflux_sdk::LocalBusClient,
    id: &str,
    conversation: &str,
    text: &str,
    sender: &str,
) -> TestResult {
    for _ in 0..100 {
        let response =
            call(bus, id, "message.read", json!({"conversation_id":conversation})).await?;
        if let Some(message) = response["messages"]
            .as_array()
            .and_then(|messages| messages.iter().find(|m| m["message_id"] == text))
        {
            assert_eq!(message["body_utf8"], text);
            assert_eq!(message["sender_id"], sender);
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(format!("contact DM was not received: {id}/{conversation}/{text}").into())
}
