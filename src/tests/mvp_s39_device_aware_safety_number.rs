// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Native safety numbers follow the account anchor while roster verification follows authority.
#![cfg(feature = "realnet")]
use super::*;
use serde_json::{Value, json};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[test]
fn mvp_s39_realnet_device_aware_safety_number_fail_closed() -> TestResult {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }
    let mut stack = start_client_directory_stack_named(
        "ramflux-s39-device-aware-safety",
        S8ComposePorts {
            gateway_http: 65_181,
            gateway_quic: 65_451,
            router_http: 65_180,
            router_mesh: 65_452,
            notify_http: 65_183,
            federation_http: 65_182,
            federation_mesh: 65_453,
            relay_http: 65_184,
            relay_media_udp: 65_100,
            signaling_turn_udp: 65_478,
            signaling_turn_tcp: 65_479,
            retention_http: 65_187,
        },
        &[("RAMFLUX_ITEST_RELAY_CLIENT_QUIC_PORT".into(), "65185".into())],
    )?;
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(run(&stack.node))?;
    stack.node.guard.mark_success();
    Ok(())
}

async fn run(node: &S8RealnetNode) -> TestResult {
    wait_relay_quic_healthy("127.0.0.1:65185", "ramflux-relay", &node.ca_cert).await?;
    wait_for_private_gateway_quic(node.gateway_quic_addr, &node.ca_cert).await?;
    let root = temp_root("s39_native_safety")?;
    let sockets = [root.join("alice.sock"), root.join("bob.sock"), root.join("replacement.sock")];
    let profiles = root.join("native-nodes.json");
    std::fs::write(
        &profiles,
        serde_json::to_vec(&[native_node_profile(node, "127.0.0.1:65185")?])?,
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
            .env("RAMFLUX_SDK_RELAY_QUIC_ADDR", "127.0.0.1:65185");
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
    let mut bob = ramflux_sdk::LocalBusClient::connect(&sockets[1]).await?;
    let mut replacement = ramflux_sdk::LocalBusClient::connect(&sockets[2]).await?;
    for bus in [&mut alice, &mut bob, &mut replacement] {
        select_native_node(bus, &node.node_id).await?;
    }
    let alice_account = create_native_account(&sockets[0], "Alice").await?;
    let bob_account = create_native_account(&sockets[1], "Bob").await?;
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
    let alice_initial = safety(&mut alice, &alice_account.account_id, &bob_account.anchor).await?;
    let bob_initial = safety(&mut bob, &bob_account.account_id, &alice_account.anchor).await?;
    assert_eq!(alice_initial["safety_number"], bob_initial["safety_number"]);
    assert_eq!(alice_initial["fingerprint_hex"], bob_initial["fingerprint_hex"]);
    assert_eq!(alice_initial["self_device_count"], 1);
    assert_eq!(bob_initial["contact_device_count"], 1);
    call(
        &mut bob,
        &bob_account.account_id,
        "contact.verify",
        json!({"contact_identity_commitment":alice_account.anchor}),
    )
    .await?;

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
    assert_eq!(pending["networking"], "networking_pending");
    assert_ne!(pending["device_id"], alice_account.device_id);
    let recovered = recover_native_account(
        &sockets[2],
        &restored_id,
        &alice_account,
        NATIVE_RESTORED_PASSPHRASE,
    )
    .await?;
    assert_eq!(recovered.networking, ramflux_sdk::custody::CreationState::Live);

    call(
        &mut bob,
        &bob_account.account_id,
        "device.refresh",
        json!({"principal_commitment":alice_account.anchor}),
    )
    .await?;
    let bob_after = safety(&mut bob, &bob_account.account_id, &alice_account.anchor).await?;
    assert_eq!(bob_after["safety_number"], bob_initial["safety_number"]);
    assert_eq!(bob_after["fingerprint_hex"], bob_initial["fingerprint_hex"]);
    assert_ne!(bob_after["contact_device_set_hash"], bob_initial["contact_device_set_hash"]);
    assert_eq!(bob_after["contact_device_count"], 1);
    assert_eq!(bob_after["verification_state"], "verification_stale");

    let manifest = fetch_manifest(&node.gateway_url, &alice_account.anchor)?;
    assert!(manifest["custody"].is_object(), "S39 must exercise native custody evidence");
    ramflux_sdk::RamfluxClient::verify_device_manifest_json(
        manifest.clone(),
        &alice_account.anchor,
    )?;
    assert_tamper_rejected(manifest.clone(), &alice_account.anchor, |value| {
        value["root_public_key"] =
            json!(ramflux_crypto::public_key_base64url_from_seed([0x5a; 32]));
    });
    assert_tamper_rejected(manifest.clone(), &alice_account.anchor, |value| {
        value["custody"]["publication"]["record"]["signature"] = json!("tampered");
    });
    assert_tamper_rejected(manifest, &alice_account.anchor, |value| {
        value["devices"][0]["prekey_bundle"]["signature_by_device_identity"] = json!("tampered");
    });
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

async fn safety(
    bus: &mut ramflux_sdk::LocalBusClient,
    account: &str,
    contact: &str,
) -> TestResult<Value> {
    call(bus, account, "contact.safety_number", json!({"contact_identity_commitment":contact}))
        .await
}

fn fetch_manifest(gateway_url: &str, anchor: &str) -> TestResult<Value> {
    Ok(ramflux_node_core::itest_http_get_json(&format!(
        "{gateway_url}/mvp1/device-manifest/{anchor}"
    ))?)
}

fn assert_tamper_rejected(mut manifest: Value, anchor: &str, mutate: impl FnOnce(&mut Value)) {
    mutate(&mut manifest);
    assert!(
        ramflux_sdk::RamfluxClient::verify_device_manifest_json(manifest, anchor).is_err(),
        "tampered native manifest must fail closed"
    );
}
