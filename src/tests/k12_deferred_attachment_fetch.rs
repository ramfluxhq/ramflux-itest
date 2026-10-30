// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Deferred DM attachment fetch, isolated failure/retry, restart and operation replay.
#![cfg(feature = "realnet")]
use super::*;
use serde_json::{Value, json};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const PROJECT: &str = "ramflux-k12-deferred-attachment";
const OBJECT: &str = "object_k12";

#[test]
fn k12_realnet_deferred_attachment_fetch() -> TestResult {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping k12: set RAMFLUX_ITEST_REALNET=1 on the QA container host");
        return Ok(());
    }
    if std::env::var("RAMFLUX_OBJECT_V3").as_deref() != Ok("1")
        || std::env::var("RAMFLUX_CROSS_GATEWAY").as_deref() != Ok("1")
    {
        return Err("k12 requires RAMFLUX_OBJECT_V3=1 RAMFLUX_CROSS_GATEWAY=1".into());
    }
    let mut stack = start_client_directory_stack_named(
        PROJECT,
        S8ComposePorts {
            gateway_http: 64_501,
            gateway_quic: 64_571,
            router_http: 64_500,
            router_mesh: 64_572,
            notify_http: 64_503,
            federation_http: 64_502,
            federation_mesh: 64_573,
            relay_http: 64_504,
            relay_media_udp: 64_540,
            signaling_turn_udp: 64_578,
            signaling_turn_tcp: 64_579,
            retention_http: 64_507,
        },
        &[(
            "RAMFLUX_RELAY_ITEST_CAPTURE_FILE".to_owned(),
            "/var/lib/ramflux/relay/k12-capture.jsonl".to_owned(),
        )],
    )?;
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(run(&stack.node))?;
    stack.node.guard.mark_success();
    Ok(())
}

async fn run(node: &S8RealnetNode) -> TestResult {
    wait_relay_quic_healthy(S73_RELAY_QUIC, "ramflux-relay", &node.ca_cert).await?;
    wait_for_private_gateway_quic(S73_GATEWAY_B_QUIC.parse()?, &node.ca_cert).await?;
    let root = temp_root("k12_deferred")?;
    let alice_socket = PathBuf::from(format!("/tmp/rf-k12-a-{}.sock", std::process::id()));
    let bob_socket = PathBuf::from(format!("/tmp/rf-k12-b-{}.sock", std::process::id()));
    let binary = mvp_s4_build_rf_binary().await?;
    let profiles = root.join("native-nodes.json");
    std::fs::write(&profiles, serde_json::to_vec(&[native_node_profile(node, S73_RELAY_QUIC)?])?)?;
    let mut alice_command = native_client_directory_daemon_command(
        &binary,
        &alice_socket,
        &root.join("alice"),
        &node.ca_cert,
        None,
    );
    alice_command
        .arg("--builtin-nodes")
        .arg(&profiles)
        .env("RAMFLUX_SYNC_ATTACHMENT_PREFETCH", "0");
    let mut alice_process = alice_command.spawn()?;
    let mut bob_command = native_client_directory_daemon_command(
        &binary,
        &bob_socket,
        &root.join("bob"),
        &node.ca_cert,
        None,
    );
    bob_command.arg("--builtin-nodes").arg(&profiles).env("RAMFLUX_SYNC_ATTACHMENT_PREFETCH", "0");
    let mut bob_process = bob_command.spawn()?;
    let result = tokio::time::timeout(Duration::from_mins(5), async {
        mvp_s4_wait_for_socket(&alice_socket).await?;
        mvp_s4_wait_for_socket(&bob_socket).await?;
        let mut alice = ramflux_sdk::LocalBusClient::connect(&alice_socket).await?;
        let mut bob = ramflux_sdk::LocalBusClient::connect(&bob_socket).await?;
        select_native_node(&mut alice, &node.node_id).await?;
        select_native_node(&mut bob, &node.node_id).await?;
        let a = create_native_account(&alice_socket, "Alice").await?;
        let b = create_native_account(&bob_socket, "Bob").await?;
        send(&mut alice, &mut bob, &a, &b).await?;
        let received = call(
            &mut bob,
            &b.account_id,
            "message.receive",
            json!({"conversation_id":"dm_k12","limit":20,"auto_fetch_attachments":false}),
        )
        .await?;
        assert!(
            received.to_string().contains("env_k12"),
            "message must be received without a download"
        );
        let directory = call(&mut bob, "bob", "object.directory", json!({})).await?;
        assert_eq!(directory["objects"][0]["transfer_state"], "not_fetched");
        assert_eq!(
            directory["objects"][0]["object_id"]
                .as_str()
                .or(directory["objects"][0]["id"].as_str()),
            Some(OBJECT)
        );
        // Reopen the native account actor while retaining the headless test vault. A daemon
        // process restart deliberately loses an in-memory vault and cannot authenticate.
        call(&mut bob, &b.account_id, "account.lock", json!({})).await?;
        bob.request(
            Some(b.account_id.clone()),
            "account",
            "account.unlock",
            json!({"passphrase":NATIVE_DATA_PASSPHRASE}),
        )
        .await?;
        fetch_failure_and_retry(node, &mut bob, &b.account_id).await?;
        let bytes =
            call(&mut bob, &b.account_id, "object.get", json!({"object_id":OBJECT})).await?;
        assert_eq!(
            ramflux_protocol::decode_base64url(
                bytes["plaintext_base64"].as_str().ok_or("missing bytes")?
            )?,
            b"k12 deferred bytes"
        );
        Ok::<(), Box<dyn std::error::Error>>(())
    })
    .await;
    let _ = alice_process.start_kill();
    let _ = bob_process.start_kill();
    let _ = alice_process.wait().await;
    let _ = bob_process.wait().await;
    let _ = std::fs::remove_file(alice_socket);
    let _ = std::fs::remove_file(bob_socket);
    result??;
    std::fs::remove_dir_all(root)?;
    Ok(())
}

async fn fetch_failure_and_retry(
    node: &S8RealnetNode,
    bob: &mut ramflux_sdk::LocalBusClient,
    bob_account: &str,
) -> TestResult {
    let body = json!({"object_id":OBJECT,"operation_id":"k12-fetch"});
    let before =
        call(bob, bob_account, "message.read", json!({"conversation_id":"dm_k12","limit":20}))
            .await?;
    assert_eq!(
        before["messages"].as_array().map(Vec::len),
        Some(1),
        "receipt must already be visible"
    );
    assert_eq!(before["messages"][0]["message_id"], "env_k12");
    run_docker_compose_project_with_options(
        &node.guard.deploy_root,
        PROJECT,
        &node.guard.env,
        &["stop", "ramflux-relay"],
        false,
    )?;
    let failure = call(bob, bob_account, "object.fetch", body.clone()).await;
    // Restore the relay even if the request unexpectedly fails at the IPC layer.
    run_docker_compose_project_with_options(
        &node.guard.deploy_root,
        PROJECT,
        &node.guard.env,
        &["start", "ramflux-relay"],
        false,
    )?;
    let failure = failure?;
    assert_eq!(failure["transfer_state"], "failed");
    assert_eq!(failure["retryable"], true);
    let failed = call(bob, bob_account, "object.directory", json!({})).await?;
    assert_eq!(failed["objects"][0]["transfer_state"], "failed");
    assert!(failed["objects"][0]["last_error"].is_string());
    assert_eq!(
        call(bob, bob_account, "message.read", json!({"conversation_id":"dm_k12","limit":20}))
            .await?,
        before
    );
    wait_relay_quic_healthy(S73_RELAY_QUIC, "ramflux-relay", &node.ca_cert).await?;
    let success = call(bob, bob_account, "object.fetch", body.clone()).await?;
    assert_eq!(success["transfer_state"], "available");
    let listed = call(bob, bob_account, "object.directory", json!({})).await?;
    assert_eq!(listed["objects"][0]["transfer_state"], "available");
    run_docker_compose_project_with_options(
        &node.guard.deploy_root,
        PROJECT,
        &node.guard.env,
        &["stop", "ramflux-relay"],
        false,
    )?;
    let replay = call(bob, bob_account, "object.fetch", body).await;
    let offline_read = call(bob, bob_account, "object.get", json!({"object_id":OBJECT})).await;
    run_docker_compose_project_with_options(
        &node.guard.deploy_root,
        PROJECT,
        &node.guard.env,
        &["start", "ramflux-relay"],
        false,
    )?;
    assert_eq!(replay?, success, "successful receipt must replay with relay offline");
    let offline_read = offline_read?;
    assert_eq!(
        ramflux_protocol::decode_base64url(
            offline_read["plaintext_base64"].as_str().ok_or("missing offline bytes")?
        )?,
        b"k12 deferred bytes"
    );
    for value in [failure, failed, success, listed] {
        for private in ["access_grant", "key_slot", "object_key", "content_key", "ciphertext"] {
            assert!(!value.to_string().contains(private), "fetch/directory leaked {private}");
        }
    }
    Ok(())
}

async fn call(
    bus: &mut ramflux_sdk::LocalBusClient,
    account: &str,
    method: &str,
    body: Value,
) -> TestResult<Value> {
    Ok(bus.request(Some(account.to_owned()), "client", method, serde_json::to_value(body)?).await?)
}

async fn send(
    alice: &mut ramflux_sdk::LocalBusClient,
    bob: &mut ramflux_sdk::LocalBusClient,
    a: &NativeAccount,
    b: &NativeAccount,
) -> TestResult {
    call(alice, &a.account_id, "contact.add", json!({"principal_id":b.principal_id})).await?;
    call(bob, &b.account_id, "contact.accept", json!({"principal_id":a.principal_id})).await?;
    call(alice,&a.account_id,"message.submit",json!({"conversation_id":"dm_k12","message_id":"message_k12","envelope_id":"env_k12","source_principal_id":a.principal_id,"sender_id":a.device_id,"recipient_device_id":b.device_id,"recipient_principal_commitment":b.anchor,"target_delivery_id":b.delivery_id,"encrypted_body_base64":"","plaintext_body_base64":ramflux_protocol::encode_base64url(b"message with deferred attachment"),"created_at":realnet_now_i64(),"ttl":3600,"attachments":[{"object_id":OBJECT,"plaintext_base64":ramflux_protocol::encode_base64url(b"k12 deferred bytes"),"chunk_size":4096,"relay_endpoint":"http://127.0.0.1:64504"}]})).await?;
    Ok(())
}
