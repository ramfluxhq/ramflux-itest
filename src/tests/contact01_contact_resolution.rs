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
    let mut diagnostics = ContactFailureLogs { topology: &topology, completed: false };
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let result = runtime.block_on(async {
        wait_for_private_gateway_quic("127.0.0.1:60643".parse()?, &topology.ca).await?;
        let binary = mvp_s4_build_rf_binary().await?;
        let root = temp_root("contact01")?;
        let a = root.join("alice.sock");
        let b = root.join("bob.sock");
        let (a_stop, a_rx) = tokio::sync::watch::channel(false);
        let (b_stop, b_rx) = tokio::sync::watch::channel(false);
        let config = |socket: &Path, directory: PathBuf| {
            let mut config = ramflux_sdk::LocalBusConfig::new(socket, directory);
            config.custody_vault =
                Some(std::sync::Arc::new(ramflux_sdk::custody::MemoryPrimaryVault::default()));
            config
        };
        let a_server = ramflux_sdk::serve_local_bus_until(config(&a, root.join("a")), a_rx);
        let b_server = ramflux_sdk::serve_local_bus_until(config(&b, root.join("b")), b_rx);
        let flow = async {
            let result = async {
                mvp_s4_wait_for_socket(&a).await?;
                mvp_s4_wait_for_socket(&b).await?;
                configure(&binary, &a, &topology.origin).await?;
                configure(&binary, &b, &topology.origin).await?;
                let alice_account = create_native_account(&a, "Alice").await?;
                let bob_account = create_native_account(&b, "Bob").await?;
                let mut alice = ramflux_sdk::LocalBusClient::connect(&a).await?;
                let mut bob = ramflux_sdk::LocalBusClient::connect(&b).await?;
                let added = rf(
                    &binary,
                    &a,
                    &[
                        "contact",
                        "add",
                        "--account",
                        &alice_account.account_id,
                        "--principal",
                        &bob_account.principal_id,
                    ],
                )
                .await?;
                assert_contact(&added, &bob_account, "lookup")?;
                let accepted = call(
                    &mut bob,
                    &bob_account.account_id,
                    "contact.accept",
                    json!({"principal_id":alice_account.principal_id}),
                )
                .await?;
                assert_contact(&accepted, &alice_account, "lookup")?;
                exchange(&mut alice, &mut bob, &alice_account, &bob_account, "principal").await?;
                exchange_cards(&binary, &a, &b, &mut alice, &mut bob).await?;
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
    });
    diagnostics.completed = result.is_ok();
    result
}

struct ContactFailureLogs<'a> {
    topology: &'a ClientDiscoveryTopology,
    completed: bool,
}
impl Drop for ContactFailureLogs<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.topology.dump_contact_failure_logs();
        }
    }
}

async fn rf(binary: &Path, socket: &Path, args: &[&str]) -> TestResult<Value> {
    let mut all = vec!["--socket", socket.to_str().ok_or("socket path")?];
    all.extend_from_slice(args);
    eprintln!("STEP: contact01 rf begin args={args:?}");
    let result = mvp_s10_rf_json(binary, &all, "contact01").await;
    match &result {
        Ok(value) => eprintln!("STEP: contact01 rf ok args={args:?} response={value}"),
        Err(error) => eprintln!("STEP: contact01 rf failed args={args:?} error={error}"),
    }
    result
}
async fn configure(binary: &Path, socket: &Path, origin: &str) -> TestResult {
    rf(binary, socket, &["node", "add", origin]).await?;
    rf(binary, socket, &["node", "confirm", "localhost"]).await?;
    rf(binary, socket, &["node", "set-default", "localhost"]).await?;
    Ok(())
}
fn assert_contact(response: &Value, peer: &NativeAccount, source: &str) -> TestResult {
    let contact = &response["contact"];
    assert_eq!(contact["principal_id"], peer.principal_id);
    assert_eq!(contact["kind_asserted"], "human");
    assert_eq!(contact["display_name"], peer.display_name);
    assert_eq!(contact["reachable"], true);
    assert_eq!(contact["verified"], false);
    assert_eq!(contact["root_source"], source);
    assert_ne!(contact["root_commitment"].as_str().ok_or("root commitment missing")?, "");
    Ok(())
}
async fn call(
    bus: &mut ramflux_sdk::LocalBusClient,
    id: &str,
    method: &str,
    body: Value,
) -> TestResult<Value> {
    eprintln!("STEP: contact01 call begin account={id} method={method} body={body}");
    match bus.request(Some(id.into()), "contact01", method, body).await {
        Ok(value) => {
            let response = value.to_string();
            let shown = response.get(..response.floor_char_boundary(1024)).unwrap_or_default();
            eprintln!("STEP: contact01 call ok account={id} method={method} response={shown}");
            Ok(value)
        }
        Err(error) => {
            eprintln!("STEP: contact01 call failed account={id} method={method} error={error}");
            Err(error.into())
        }
    }
}
async fn identity(
    bus: &mut ramflux_sdk::LocalBusClient,
    id: &str,
    peer: &NativeAccount,
) -> TestResult<Value> {
    let directory = call(bus, id, "identity.directory", json!({})).await?;
    let row = directory["identities"]
        .as_array()
        .ok_or("missing identities")?
        .iter()
        .find(|r| r["principal_id"] == peer.principal_id)
        .ok_or("contact did not populate the identity directory")?
        .clone();
    assert_eq!(row["kind"], "human");
    assert_eq!(row["kind_verified"], true);
    assert_eq!(row["display_name"], peer.display_name);
    assert_eq!(row["mixed_script"], false);
    assert!(row["display_name_confusable_with"].is_null());
    assert_eq!(row["reachable"], true);
    assert_eq!(row["verified"], false);
    assert_eq!(row["safety_number_available"], true);
    assert_eq!(row["safety_number"].as_array().map(Vec::len), Some(12));
    Ok(row)
}
pub(super) async fn exchange(
    a: &mut ramflux_sdk::LocalBusClient,
    b: &mut ramflux_sdk::LocalBusClient,
    alice: &NativeAccount,
    bob: &NativeAccount,
    label: &str,
) -> TestResult {
    let bob_row = identity(a, &alice.account_id, bob).await?;
    let alice_row = identity(b, &bob.account_id, alice).await?;
    let safety_a = call(
        a,
        &alice.account_id,
        "contact.safety_number",
        json!({"contact_identity_commitment":bob_row["contact_identity_commitment"]}),
    )
    .await?;
    let safety_b = call(
        b,
        &bob.account_id,
        "contact.safety_number",
        json!({"contact_identity_commitment":alice_row["contact_identity_commitment"]}),
    )
    .await?;
    assert_eq!(safety_a["safety_number"], safety_b["safety_number"]);
    let conversation = format!("contact01-{label}");
    send(a, &alice.account_id, &bob_row, &conversation, &format!("{label}-hello")).await?;
    read(b, &bob.account_id, &conversation, &format!("{label}-hello"), &alice.device_id).await?;
    send(b, &bob.account_id, &alice_row, &conversation, &format!("{label}-reply")).await?;
    read(a, &alice.account_id, &conversation, &format!("{label}-reply"), &bob.device_id).await?;
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
    let sent=call(bus,own,"message.submit",json!({"conversation_id":conversation,"message_id":message_id(text),"envelope_id":message_id(text),"source_principal_id":status["principal_id"],"sender_id":status["device_id"],"recipient_device_id":device["device_id"],"recipient_principal_commitment":peer["contact_identity_commitment"],"target_delivery_id":device["target_delivery_id"],"encrypted_body_base64":"","plaintext_body_base64":ramflux_protocol::encode_base64url(text.as_bytes()),"created_at":realnet_now_i64(),"ttl":3600})).await?;
    assert!(!sent.is_null());
    Ok(())
}
/// Received DMs are identified by the AAD-bound envelope id, so submit both ids equal.
fn message_id(text: &str) -> String {
    format!("contact01-{text}")
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
            .and_then(|messages| messages.iter().find(|m| m["message_id"] == message_id(text)))
        {
            assert_eq!(message["body_utf8"], text);
            assert_eq!(message["sender_id"], sender);
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(format!("contact DM was not received: {id}/{conversation}/{text}").into())
}

async fn exchange_cards(
    binary: &Path,
    alice_socket: &Path,
    bob_socket: &Path,
    alice: &mut ramflux_sdk::LocalBusClient,
    bob: &mut ramflux_sdk::LocalBusClient,
) -> TestResult {
    // A second fresh pair proves card resolution without identity state from principal lookup.
    let carol_account = create_native_account(alice_socket, "Carol").await?;
    let dave_account = create_native_account(bob_socket, "Dave").await?;
    let carol =
        rf(binary, alice_socket, &["contact", "card", "--account", &carol_account.account_id])
            .await?;
    let dave =
        rf(binary, bob_socket, &["contact", "card", "--account", &dave_account.account_id]).await?;
    let added = rf(
        binary,
        alice_socket,
        &[
            "contact",
            "add",
            "--account",
            &carol_account.account_id,
            "--card",
            dave["card"].as_str().ok_or("missing card")?,
        ],
    )
    .await?;
    assert_contact(&added, &dave_account, "card")?;
    let accepted =
        call(bob, &dave_account.account_id, "contact.accept", json!({"card":carol["link"]}))
            .await?;
    assert_contact(&accepted, &carol_account, "card")?;
    exchange(alice, bob, &carol_account, &dave_account, "card").await?;
    Ok(())
}
