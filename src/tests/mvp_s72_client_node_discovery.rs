// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Client discovery, confirmation, account binding, and DM over the production node topology.
#![cfg(feature = "realnet")]
use super::*;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[test]
fn mvp_s72_realnet_client_node_discovery_and_bound_dm() -> TestResult {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping s72: set RAMFLUX_ITEST_REALNET=1 on Linux with a container runtime");
        return Ok(());
    }
    let topology = start_client_discovery_topology()?;
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async {
        wait_for_private_gateway_quic("127.0.0.1:58443".parse()?, &topology.ca).await?;
        let binary = mvp_s4_build_rf_binary().await?;
        let root = temp_root("s72_node_discovery")?;
        let alice = root.join("alice.sock");
        let bob = root.join("bob.sock");
        let (alice_stop, alice_rx) = tokio::sync::watch::channel(false);
        let (bob_stop, bob_rx) = tokio::sync::watch::channel(false);
        let alice_server = ramflux_sdk::serve_local_bus_until(
            crate::harness::legacy_accounts::config(&alice, root.join("alice")),
            alice_rx,
        );
        let bob_server = ramflux_sdk::serve_local_bus_until(
            crate::harness::legacy_accounts::config(&bob, root.join("bob")),
            bob_rx,
        );
        let flow = async {
            let result = async {
                mvp_s4_wait_for_socket(&alice).await?;
                mvp_s4_wait_for_socket(&bob).await?;
                let alice = alice.to_str().ok_or("invalid alice socket")?;
                let bob = bob.to_str().ok_or("invalid bob socket")?;
                add_confirm(&binary, alice, &topology.origin).await?;
                add_confirm(&binary, bob, &topology.origin).await?;
                assert_pre_account_probe(&binary, alice).await?;
                let alice_commitment =
                    create_bound_account(&binary, alice, "alice", "a1", "a2").await?;
                let bob_commitment = create_bound_account(&binary, bob, "bob", "b1", "b2").await?;
                round_trip(&binary, alice, bob, &alice_commitment, &bob_commitment).await?;
                assert_record_rejections(&binary, alice, &topology.origin).await?;
                rf_failure(&binary, alice, &["node", "remove", "localhost"], "account is bound")
                    .await?;
                rf(&binary, alice, &["node", "disable", "localhost"]).await?;
                let status =
                    rf(&binary, alice, &["account", "status", "--account", "alice"]).await?;
                assert_eq!(status["node_id"], "localhost");
                Ok::<_, Box<dyn std::error::Error>>(())
            }
            .await;
            let _ = alice_stop.send(true);
            let _ = bob_stop.send(true);
            result
        };
        let (alice_result, bob_result, flow_result) =
            tokio::time::timeout(Duration::from_mins(5), async {
                tokio::join!(alice_server, bob_server, flow)
            })
            .await?;
        alice_result?;
        bob_result?;
        flow_result
    })?;
    Ok(())
}

async fn rf(binary: &Path, socket: &str, args: &[&str]) -> TestResult<Value> {
    let mut all = vec!["--socket", socket];
    all.extend_from_slice(args);
    mvp_s10_rf_json(binary, &all, "s72 client discovery").await
}

async fn rf_failure(binary: &Path, socket: &str, args: &[&str], expected: &str) -> TestResult {
    let output = tokio::time::timeout(
        Duration::from_secs(30),
        tokio::process::Command::new(binary)
            .args(["--socket", socket])
            .args(args)
            .kill_on_drop(true)
            .output(),
    )
    .await??;
    assert!(!output.status.success(), "command unexpectedly succeeded: {args:?}");
    let stderr = String::from_utf8(output.stderr)?;
    assert!(stderr.contains(expected), "expected {expected:?}, received {stderr}");
    Ok(())
}

async fn add_confirm(binary: &Path, socket: &str, origin: &str) -> TestResult {
    let added = rf(binary, socket, &["node", "add", origin]).await?;
    assert_eq!(added["node"]["node_id"], "localhost");
    assert_eq!(added["persisted"], false);
    let before = rf(binary, socket, &["node", "list"]).await?;
    assert_eq!(before["nodes"].as_array().ok_or("nodes missing")?.len(), 0);
    let confirmed = rf(binary, socket, &["node", "confirm", "localhost"]).await?;
    assert_eq!(confirmed["pin_source"], "tofu");
    assert!(
        confirmed["safety_warnings"]
            .as_array()
            .ok_or("warnings missing")?
            .iter()
            .any(|warning| warning == "tofu_unverified")
    );
    rf(binary, socket, &["node", "set-default", "localhost"]).await?;
    Ok(())
}

async fn assert_pre_account_probe(binary: &Path, socket: &str) -> TestResult {
    let mut last = Value::Null;
    for _ in 0..30 {
        last = rf(binary, socket, &["node", "probe", "localhost"]).await?;
        if last["healthy"] == true {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert_eq!(last["healthy"], true, "probe failed: {last}");
    assert_eq!(last["gateway"]["app"], "ok");
    assert_eq!(last["gateway"]["session"], "requires_account");
    assert_eq!(
        last["prekey"]["status"], "failed",
        "the fixture explicitly advertises an HTTP prekey origin; TLS probe must not claim success"
    );
    Ok(())
}

async fn create_bound_account(
    binary: &Path,
    socket: &str,
    account: &str,
    root: &str,
    device: &str,
) -> TestResult<String> {
    let result = rf(
        binary,
        socket,
        &[
            "account",
            "itest-legacy-create",
            "--node",
            "localhost",
            "--account",
            account,
            "--principal",
            account,
            "--device",
            account,
            "--target",
            account,
            "--secret",
            "test-only-secret",
            "--root-seed-byte-hex",
            root,
            "--device-seed-byte-hex",
            device,
            "--gateway-addr",
            "127.0.0.1:1",
            "--server-name",
            "ignored.invalid",
            "--ca-cert",
            "missing-development-override.pem",
        ],
    )
    .await?;
    let status = rf(binary, socket, &["account", "status", "--account", account]).await?;
    assert_eq!(status["node_id"], "localhost");
    Ok(result["principal_commitment"].as_str().ok_or("missing commitment")?.to_owned())
}

async fn accept_both_contacts(binary: &Path, alice: &str, bob: &str) -> TestResult {
    for (socket, requester, target, link) in
        [(alice, "alice", "bob", "s72-friend"), (bob, "bob", "alice", "s72-friend-bob-alice")]
    {
        let added = rf(
            binary,
            socket,
            &[
                "contact",
                "add",
                "--account",
                requester,
                "--link",
                link,
                "--requester",
                requester,
                "--target",
                target,
            ],
        )
        .await?;
        assert_eq!(added["state"], "accepted", "contact {requester}->{target}: {added}");
    }
    Ok(())
}

async fn round_trip(
    binary: &Path,
    alice: &str,
    bob: &str,
    alice_commitment: &str,
    bob_commitment: &str,
) -> TestResult {
    accept_both_contacts(binary, alice, bob).await?;
    rf(
        binary,
        alice,
        &[
            "dm",
            "send",
            "--account",
            "alice",
            "--conversation",
            "s72-dm",
            "--message",
            "s72-message",
            "--envelope",
            "s72-envelope",
            "--source-principal",
            "alice",
            "--sender",
            "alice",
            "--recipient-principal-commitment",
            bob_commitment,
            "--recipient-device",
            "bob",
            "--target",
            "bob",
            "--body",
            "client discovery DM",
        ],
    )
    .await?;
    let read =
        rf(binary, bob, &["dm", "read", "--account", "bob", "--conversation", "s72-dm"]).await?;
    let messages = read["decrypted_messages"].as_array().ok_or("missing messages")?;
    assert_eq!(messages.len(), 1);
    assert_eq!(
        ramflux_protocol::decode_base64url(
            messages[0]["plaintext_body_base64"].as_str().ok_or("missing plaintext")?
        )?,
        b"client discovery DM"
    );
    rf(
        binary,
        bob,
        &[
            "dm",
            "send",
            "--account",
            "bob",
            "--conversation",
            "s72-dm",
            "--message",
            "s72-reply-message",
            "--envelope",
            "s72-reply",
            "--source-principal",
            "bob",
            "--sender",
            "bob",
            "--recipient-principal-commitment",
            alice_commitment,
            "--recipient-device",
            "alice",
            "--target",
            "alice",
            "--body",
            "client discovery reply",
        ],
    )
    .await?;
    let reply =
        rf(binary, alice, &["dm", "read", "--account", "alice", "--conversation", "s72-dm"])
            .await?;
    let replies = reply["decrypted_messages"].as_array().ok_or("missing replies")?;
    assert!(replies.iter().any(|message| message["plaintext_body_base64"].as_str().is_some_and(
        |encoded| {
            ramflux_protocol::decode_base64url(encoded)
                .is_ok_and(|plain| plain == b"client discovery reply")
        }
    )));
    Ok(())
}

async fn assert_record_rejections(binary: &Path, socket: &str, origin: &str) -> TestResult {
    let url = format!("{origin}/.well-known/ramflux/client");
    let record: ramflux_protocol::WellKnownClientRecord =
        ramflux_node_core::itest_http_get_json(&url)?;
    let fixture = ClientRecordOrigin::start(record.clone())?;
    rf(binary, socket, &["node", "add", &fixture.url, "--refresh"]).await?;
    rf(binary, socket, &["node", "confirm", "localhost"]).await?;
    let mut expired = record.clone();
    expired.updated_at = realnet_now_u64().saturating_sub(1000);
    expired.expires_at = realnet_now_u64().saturating_sub(301);
    sign_client_record(&mut expired, [0x49; 32])?;
    fixture.replace(expired)?;
    rf_failure(binary, socket, &["node", "add", &fixture.url, "--refresh"], "expired").await?;
    assert_eq!(
        rf(binary, socket, &["node", "probe", "localhost"]).await?["discovery"]["status"],
        "expired"
    );
    let mut tampered = record.clone();
    tampered.gateway_server_name = "tampered.invalid".to_owned();
    fixture.replace(tampered)?;
    rf_failure(binary, socket, &["node", "add", &fixture.url, "--refresh"], "verification failed")
        .await?;
    assert_eq!(
        rf(binary, socket, &["node", "probe", "localhost"]).await?["discovery"]["status"],
        "invalid_signature"
    );
    let mut changed = record.clone();
    sign_client_record(&mut changed, [0x50; 32])?;
    fixture.replace(changed)?;
    assert_eq!(
        rf(binary, socket, &["node", "probe", "localhost"]).await?["discovery"]["status"],
        "key_changed"
    );
    let added = rf(binary, socket, &["node", "add", &fixture.url, "--refresh"]).await?;
    assert!(
        added["node"]["safety_warnings"]
            .as_array()
            .ok_or("missing warnings")?
            .iter()
            .any(|warning| warning == "key_changed")
    );
    rf_failure(binary, socket, &["node", "confirm", "localhost"], "node key changed").await?;
    fixture.replace(record.clone())?;
    let added = rf(binary, socket, &["node", "add", &fixture.url, "--refresh"]).await?;
    assert!(
        added["node"]["safety_warnings"]
            .as_array()
            .ok_or("missing warnings")?
            .iter()
            .any(|warning| warning == "key_changed")
    );
    let replaced = rf(
        binary,
        socket,
        &[
            "node",
            "confirm",
            "localhost",
            "--pin-source",
            "operator",
            "--expected-public-key",
            &record.node_public_key,
        ],
    )
    .await?;
    assert_eq!(replaced["safety_warnings"], serde_json::json!([]));
    Ok(())
}
