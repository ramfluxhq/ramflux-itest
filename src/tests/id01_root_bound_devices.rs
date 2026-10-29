// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Native daemon registration, explicit phrase promotion and peer-side signed revocation.
#![cfg(feature = "realnet")]
use super::*;
use serde_json::{Value, json};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
#[test]
fn id01_realnet_root_bound_device_add_revoke() -> TestResult {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping ID-01: set RAMFLUX_ITEST_REALNET=1 on the QA host");
        return Ok(());
    }
    if std::env::var("RAMFLUX_OBJECT_V3").as_deref() != Ok("1")
        || std::env::var("RAMFLUX_CROSS_GATEWAY").as_deref() != Ok("1")
    {
        return Err("ID-01 requires RAMFLUX_OBJECT_V3=1 RAMFLUX_CROSS_GATEWAY=1".into());
    }
    let stack = start_client_directory_stack_named(
        "ramflux-id01-device-authority",
        S8ComposePorts {
            gateway_http: 65_401,
            gateway_quic: 65_471,
            router_http: 65_400,
            router_mesh: 65_472,
            notify_http: 65_403,
            federation_http: 65_402,
            federation_mesh: 65_473,
            relay_http: 65_404,
            relay_media_udp: 65_440,
            signaling_turn_udp: 65_478,
            signaling_turn_tcp: 65_479,
            retention_http: 65_407,
        },
        &[
            ("RAMFLUX_ITEST_GATEWAY_B_HTTP_PORT".into(), "65408".into()),
            ("RAMFLUX_ITEST_GATEWAY_B_QUIC_PORT".into(), "65474".into()),
            ("RAMFLUX_ITEST_GATEWAY_B_TCP_PORT".into(), "65474".into()),
            ("RAMFLUX_ITEST_RELAY_CLIENT_QUIC_PORT".into(), "65475".into()),
            (
                COMPOSE_FAILURE_LOG_SERVICES_ENV.into(),
                "ramflux-router,ramflux-gateway,ramflux-gateway-b,ramflux-relay".into(),
            ),
        ],
    )?;
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(run(&stack.node))
}

async fn run(node: &S8RealnetNode) -> TestResult {
    wait_relay_quic_healthy("127.0.0.1:65475", "ramflux-relay", &node.ca_cert).await?;
    wait_for_private_gateway_quic(node.gateway_quic_addr, &node.ca_cert).await?;
    let root = temp_root("id01")?;
    let sockets = [root.join("a.sock"), root.join("b.sock"), root.join("replacement.sock")];
    let profiles = root.join("native-nodes.json");
    std::fs::write(
        &profiles,
        serde_json::to_vec(&[native_node_profile(node, "127.0.0.1:65475")?])?,
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
        command.arg("--builtin-nodes").arg(&profiles);
        command.env("RAMFLUX_SDK_RELAY_QUIC_ADDR", "127.0.0.1:65475");
        children.push(command.spawn()?);
    }
    let result = tokio::time::timeout(Duration::from_secs(180), flow(node, &sockets, &root)).await;
    for child in &mut children {
        let _ = child.start_kill();
        let _ = child.wait().await;
    }
    let _ = std::fs::remove_dir_all(root);
    result??;
    Ok(())
}

async fn flow(node: &S8RealnetNode, sockets: &[PathBuf; 3], root: &Path) -> TestResult {
    for socket in sockets {
        mvp_s4_wait_for_socket(socket).await?;
    }
    let mut a = ramflux_sdk::LocalBusClient::connect(&sockets[0]).await?;
    let mut b = ramflux_sdk::LocalBusClient::connect(&sockets[1]).await?;
    let mut replacement = ramflux_sdk::LocalBusClient::connect(&sockets[2]).await?;
    for bus in [&mut a, &mut b, &mut replacement] {
        select_native_node(bus, &node.node_id).await?;
    }
    let alice = create_native_account(&sockets[0], "Alice").await?;
    let bob = create_native_account(&sockets[1], "Bob").await?;
    call(&mut a, &alice.account_id, "contact.add", json!({"principal_id":bob.principal_id}))
        .await?;
    call(&mut b, &bob.account_id, "contact.accept", json!({"principal_id":alice.principal_id}))
        .await?;
    let original = call(
        &mut b,
        &bob.account_id,
        "device.refresh",
        json!({"principal_commitment":alice.anchor}),
    )
    .await?;
    assert_eq!(original["device_set_epoch"], (1_u64 << 32) + 1);
    assert_eq!(original["kind_asserted"], "human");
    assert_eq!(original["kind_verified"], true);
    assert_eq!(original["safety_kind_verified"], false);
    send(&mut b, &bob, &alice.anchor, &alice.device_id, &alice.delivery_id, "id01-before-recovery")
        .await?;
    history(&mut a, &alice.account_id, "id01-before-recovery").await?;
    let archive = root.join("alice.rfbackup");
    create_native_backup(&mut a, &alice.account_id, &archive).await?;
    let id = restore_native_backup(&mut replacement, &archive, true).await?;
    call(&mut replacement, &id, "account.unlock", json!({"passphrase":NATIVE_RESTORED_PASSPHRASE}))
        .await?;
    let pending = call(&mut replacement, &id, "account.status", json!({})).await?;
    assert_eq!(pending["networking"], "networking_pending");
    assert_ne!(pending["device_id"], alice.device_id);
    let refusal = replacement
        .request_frame_response(ramflux_sdk::LocalBusFrame::request(
            "pending-receive",
            Some(id.clone()),
            "message",
            "message.receive",
            json!({"limit":1,"conversation_id":null,"auto_fetch_attachments":false}),
        ))
        .await?;
    assert_eq!(refusal.error.as_ref().map(|error| error.code.as_str()), Some("NetworkingPending"));
    // SAS pairing is separate. Explicit phrase recovery promotes the replacement and retires A.
    let recovered =
        recover_native_account(&sockets[2], &id, &alice, NATIVE_RESTORED_PASSPHRASE).await?;
    assert_eq!(recovered.networking, ramflux_sdk::custody::CreationState::Live);
    history(&mut replacement, &id, "id01-before-recovery").await?;
    assert_replacement(&mut a, &mut b, &mut replacement, &alice, &bob, &id).await
}

async fn assert_replacement(
    a: &mut ramflux_sdk::LocalBusClient,
    b: &mut ramflux_sdk::LocalBusClient,
    replacement: &mut ramflux_sdk::LocalBusClient,
    alice: &NativeAccount,
    bob: &NativeAccount,
    id: &str,
) -> TestResult {
    let observed =
        call(b, &bob.account_id, "device.refresh", json!({"principal_commitment":alice.anchor}))
            .await?;
    assert_eq!(observed["device_set_epoch"], (2_u64 << 32) + 1);
    let devices = observed["devices"].as_array().ok_or("native roster missing")?;
    assert_eq!(devices.len(), 2);
    let retired = devices
        .iter()
        .find(|device| device["device_id"] == alice.device_id)
        .ok_or("signed old-branch tombstone missing")?;
    assert_eq!(retired["status"], "revoked");
    assert!(retired["revoked_at"].as_u64().is_some());
    assert!(
        send(b, bob, &alice.anchor, &alice.device_id, &alice.delivery_id, "id01-retired-target")
            .await
            .is_err()
    );
    // A still has its old local credential: the current authority must refuse its new traffic.
    assert!(
        send(a, alice, &bob.anchor, &bob.device_id, &bob.delivery_id, "id01-retired-signer")
            .await
            .is_err()
    );
    let current = call(replacement, id, "account.status", json!({})).await?;
    assert_eq!(current["networking"], "live");
    send(
        b,
        bob,
        &alice.anchor,
        current["device_id"].as_str().ok_or("replacement branch missing")?,
        current["target_delivery_id"].as_str().ok_or("replacement route missing")?,
        "id01-after-recovery",
    )
    .await?;
    history(replacement, id, "id01-after-recovery").await?;
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
            "conversation_id":"id01-thread", "message_id":id, "envelope_id":id,
            "source_principal_id":owner.principal_id, "sender_id":owner.device_id,
            "recipient_device_id":device, "recipient_principal_commitment":anchor,
            "target_delivery_id":delivery,"encrypted_body_base64":"",
            "plaintext_body_base64":ramflux_protocol::encode_base64url(b"native device traffic"),
            "created_at":realnet_now_i64(), "ttl":600
        }),
    )
    .await
}

async fn history(
    bus: &mut ramflux_sdk::LocalBusClient,
    account: &str,
    message: &str,
) -> TestResult {
    for _ in 0..100 {
        let rows =
            call(bus, account, "message.read", json!({"conversation_id":"id01-thread"})).await?;
        if let Some(row) = rows["messages"]
            .as_array()
            .and_then(|rows| rows.iter().find(|row| row["message_id"] == message))
        {
            assert_eq!(row["body_utf8"], "native device traffic");
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err("native device traffic was not received".into())
}
