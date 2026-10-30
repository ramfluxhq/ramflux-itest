// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! A fresh native restore remains local-only until explicit phrase recovery promotes its branch.
#![cfg(feature = "realnet")]
use super::*;
use serde_json::{Value, json};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[test]
fn mvp_s47_realnet_restore_device_rejoin_manifest_gate() -> TestResult {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }
    crate::harness::sdk_receive_diagnostics::install();
    let mut stack = start_client_directory_stack_named(
        "ramflux-s47-restore-device",
        S8ComposePorts {
            gateway_http: 64_761,
            gateway_quic: 64_621,
            router_http: 64_760,
            router_mesh: 64_622,
            notify_http: 64_763,
            federation_http: 64_762,
            federation_mesh: 64_623,
            relay_http: 64_764,
            relay_media_udp: 64_171,
            signaling_turn_udp: 64_640,
            signaling_turn_tcp: 64_641,
            retention_http: 64_767,
        },
        &[("RAMFLUX_ITEST_RELAY_CLIENT_QUIC_PORT".into(), "64765".into())],
    )?;
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(run(&stack.node))?;
    stack.node.guard.mark_success();
    Ok(())
}

async fn run(node: &S8RealnetNode) -> TestResult {
    wait_relay_quic_healthy("127.0.0.1:64765", "ramflux-relay", &node.ca_cert).await?;
    wait_for_private_gateway_quic(node.gateway_quic_addr, &node.ca_cert).await?;
    let root = temp_root("s47_native_restore")?;
    let sockets = [root.join("alice.sock"), root.join("replacement.sock"), root.join("bob.sock")];
    let profiles = root.join("native-nodes.json");
    std::fs::write(
        &profiles,
        serde_json::to_vec(&[native_node_profile(node, "127.0.0.1:64765")?])?,
    )?;
    let binary = mvp_s4_build_rf_binary().await?;
    let mut children = Vec::new();
    for (index, socket) in sockets.iter().enumerate() {
        let mut command = native_client_directory_daemon_command(
            &binary,
            socket,
            &root.join(format!("account-{index}")),
            &node.ca_cert,
            None,
        );
        command
            .arg("--builtin-nodes")
            .arg(&profiles)
            .env("RAMFLUX_SDK_RELAY_QUIC_ADDR", "127.0.0.1:64765");
        children.push(command.spawn()?);
    }
    let result = tokio::time::timeout(Duration::from_mins(4), flow(node, &sockets, &root)).await;
    for child in &mut children {
        let _ = child.start_kill();
        let _ = child.wait().await;
    }
    let _ = std::fs::remove_dir_all(&root);
    result??;
    Ok(())
}

async fn flow(node: &S8RealnetNode, sockets: &[PathBuf; 3], root: &Path) -> TestResult {
    for socket in sockets {
        mvp_s4_wait_for_socket(socket).await?;
    }
    let mut alice = ramflux_sdk::LocalBusClient::connect(&sockets[0]).await?;
    let mut replacement = ramflux_sdk::LocalBusClient::connect(&sockets[1]).await?;
    let mut bob = ramflux_sdk::LocalBusClient::connect(&sockets[2]).await?;
    for bus in [&mut alice, &mut replacement, &mut bob] {
        select_native_node(bus, &node.node_id).await?;
    }
    let alice_account = create_native_account(&sockets[0], "Alice").await?;
    let bob_account = create_native_account(&sockets[2], "Bob").await?;
    call(
        &mut alice,
        &alice_account.account_id,
        "contact.add",
        json!({"principal_id":bob_account.principal_id}),
    )
    .await?;
    call(
        &mut bob,
        &bob_account.account_id,
        "contact.accept",
        json!({"principal_id":alice_account.principal_id}),
    )
    .await?;
    send(
        &mut bob,
        &bob_account,
        &alice_account.anchor,
        &alice_account.device_id,
        &alice_account.delivery_id,
        "s47-before-restore",
    )
    .await?;
    wait_for_message(&mut alice, &alice_account.account_id, "s47-before-restore").await?;

    let archive = root.join("alice.rfbackup");
    create_native_backup(&mut alice, &alice_account.account_id, &archive).await?;
    let restored_id = restore_native_backup(&mut replacement, &archive, true).await?;
    call(
        &mut replacement,
        &restored_id,
        "account.unlock",
        json!({"passphrase":NATIVE_RESTORED_PASSPHRASE}),
    )
    .await?;
    let pending = call(&mut replacement, &restored_id, "account.status", json!({})).await?;
    crate::harness::sdk_receive_diagnostics::response("s47 pending restore", &pending);
    assert_eq!(pending["networking"], "networking_pending");
    assert_ne!(pending["device_id"], alice_account.device_id);
    wait_for_message(&mut replacement, &restored_id, "s47-before-restore").await?;
    let refusal = replacement
        .request_frame_response(ramflux_sdk::LocalBusFrame::request(
            "s47-pending-receive",
            Some(restored_id.clone()),
            "message",
            "message.receive",
            json!({"limit":1,"conversation_id":null,"auto_fetch_attachments":false}),
        ))
        .await?;
    assert_eq!(refusal.error.as_ref().map(|error| error.code.as_str()), Some("NetworkingPending"));
    crate::harness::sdk_receive_diagnostics::failure_state(&mut replacement, &restored_id).await;
    promote_and_verify(
        &sockets[1],
        &restored_id,
        &alice_account,
        &bob_account,
        &mut replacement,
        &mut bob,
    )
    .await
}

async fn promote_and_verify(
    replacement_socket: &Path,
    restored_id: &str,
    alice_account: &NativeAccount,
    bob_account: &NativeAccount,
    replacement: &mut ramflux_sdk::LocalBusClient,
    bob: &mut ramflux_sdk::LocalBusClient,
) -> TestResult {
    let recovered = recover_native_account(
        replacement_socket,
        restored_id,
        alice_account,
        NATIVE_RESTORED_PASSPHRASE,
    )
    .await?;
    assert_eq!(recovered.networking, ramflux_sdk::custody::CreationState::Live);
    let current = call(replacement, restored_id, "account.status", json!({})).await?;
    assert_eq!(current["networking"], "live");
    let refreshed = call(
        bob,
        &bob_account.account_id,
        "device.refresh",
        json!({"principal_commitment":alice_account.anchor}),
    )
    .await?;
    let devices = refreshed["devices"].as_array().ok_or("native roster missing")?;
    assert_eq!(devices.len(), 2);
    assert!(devices.iter().any(|device| {
        device["device_id"] == alice_account.device_id && device["status"] == "revoked"
    }));
    let current_device = current["device_id"].as_str().ok_or("replacement device missing")?;
    let current_delivery =
        current["target_delivery_id"].as_str().ok_or("replacement delivery missing")?;
    assert!(
        devices.iter().any(|device| {
            device["device_id"] == current_device && device["status"] == "active"
        })
    );
    assert!(
        send(
            bob,
            bob_account,
            &alice_account.anchor,
            &alice_account.device_id,
            &alice_account.delivery_id,
            "s47-revoked-target",
        )
        .await
        .is_err()
    );
    send(
        bob,
        bob_account,
        &alice_account.anchor,
        current_device,
        current_delivery,
        "s47-after-recovery",
    )
    .await?;
    wait_for_message(replacement, restored_id, "s47-after-recovery").await?;
    Ok(())
}

async fn call(
    bus: &mut ramflux_sdk::LocalBusClient,
    account: &str,
    method: &str,
    body: Value,
) -> TestResult<Value> {
    Ok(bus
        .request(Some(account.into()), method.split('.').next().ok_or("method")?, method, body)
        .await?)
}

async fn send(
    bus: &mut ramflux_sdk::LocalBusClient,
    owner: &NativeAccount,
    anchor: &str,
    device: &str,
    delivery: &str,
    id: &str,
) -> TestResult<Value> {
    call(
        bus,
        &owner.account_id,
        "message.submit",
        json!({
            "conversation_id":"s47-thread","message_id":id,"envelope_id":id,
            "source_principal_id":owner.principal_id,"sender_id":owner.device_id,
            "recipient_device_id":device,"recipient_principal_commitment":anchor,
            "target_delivery_id":delivery,"encrypted_body_base64":"",
            "plaintext_body_base64":ramflux_protocol::encode_base64url(b"native restore traffic"),
            "created_at":realnet_now_i64(),"ttl":600
        }),
    )
    .await
}

async fn wait_for_message(
    bus: &mut ramflux_sdk::LocalBusClient,
    account: &str,
    message: &str,
) -> TestResult {
    for _ in 0..100 {
        let rows =
            call(bus, account, "message.read", json!({"conversation_id":"s47-thread"})).await?;
        if rows["messages"]
            .as_array()
            .is_some_and(|rows| rows.iter().any(|row| row["message_id"] == message))
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(format!("native restore message {message} was not received").into())
}
