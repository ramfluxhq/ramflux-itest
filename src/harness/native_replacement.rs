// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Native replacement-device coverage shared by slices whose concurrent-device behavior remains legacy.
#![cfg(all(test, feature = "realnet"))]
use ramflux_sdk::LocalBusClient;
use serde_json::json;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

pub(crate) async fn assert_native_replacement_lifecycle(
    node: &super::S8RealnetNode,
    relay: &str,
    scenario: &str,
) -> Result {
    super::wait_relay_quic_healthy(relay, "ramflux-relay", &node.ca_cert).await?;
    super::wait_for_private_gateway_quic(node.gateway_quic_addr, &node.ca_cert).await?;
    let root = super::temp_root(scenario)?;
    let primary_socket = root.join("primary.sock");
    let replacement_socket = root.join("replacement.sock");
    let profiles = root.join("native-nodes.json");
    std::fs::write(&profiles, serde_json::to_vec(&[super::native_node_profile(node, relay)?])?)?;
    let binary = super::mvp_s4_build_rf_binary().await?;
    let mut children = Vec::new();
    for (index, socket) in [&primary_socket, &replacement_socket].iter().enumerate() {
        let mut command = super::native_client_directory_daemon_command(
            &binary,
            socket,
            &root.join(format!("account-{index}")),
            &node.ca_cert,
            None,
        );
        command.arg("--builtin-nodes").arg(&profiles).env("RAMFLUX_SDK_RELAY_QUIC_ADDR", relay);
        children.push(command.spawn()?);
    }
    let result = tokio::time::timeout(
        std::time::Duration::from_mins(4),
        replacement_flow(node, &primary_socket, &replacement_socket, &root),
    )
    .await;
    for child in &mut children {
        let _ = child.start_kill();
        let _ = child.wait().await;
    }
    let _ = std::fs::remove_dir_all(&root);
    result??;
    Ok(())
}

async fn replacement_flow(
    node: &super::S8RealnetNode,
    primary_socket: &std::path::Path,
    replacement_socket: &std::path::Path,
    root: &std::path::Path,
) -> Result {
    super::mvp_s4_wait_for_socket(primary_socket).await?;
    super::mvp_s4_wait_for_socket(replacement_socket).await?;
    let mut primary = LocalBusClient::connect(primary_socket).await?;
    let mut replacement = LocalBusClient::connect(replacement_socket).await?;
    super::select_native_node(&mut primary, &node.node_id).await?;
    super::select_native_node(&mut replacement, &node.node_id).await?;
    let owner = super::create_native_account(primary_socket, "Native replacement owner").await?;
    let archive = root.join("native-replacement.rfbackup");
    super::create_native_backup(&mut primary, &owner.account_id, &archive).await?;
    let restored_id = super::restore_native_backup(&mut replacement, &archive, true).await?;
    replacement
        .request(
            Some(restored_id.clone()),
            "account",
            "account.unlock",
            json!({"passphrase":super::NATIVE_RESTORED_PASSPHRASE}),
        )
        .await?;
    let pending = replacement
        .request(Some(restored_id.clone()), "account", "account.status", json!({}))
        .await?;
    assert_eq!(pending["networking"], "networking_pending");
    assert_eq!(pending["principal_commitment"], owner.anchor);
    assert_ne!(pending["device_id"], owner.device_id);
    let replacement_device =
        pending["device_id"].as_str().ok_or("replacement device missing")?.to_owned();
    let refusal = replacement
        .request_frame_response(ramflux_sdk::LocalBusFrame::request(
            "native-replacement-pending-receive",
            Some(restored_id.clone()),
            "message",
            "message.receive",
            json!({"limit":1,"conversation_id":null,"auto_fetch_attachments":false}),
        ))
        .await?;
    assert_eq!(refusal.error.as_ref().map(|error| error.code.as_str()), Some("NetworkingPending"));
    let recovered = super::recover_native_account(
        replacement_socket,
        &restored_id,
        &owner,
        super::NATIVE_RESTORED_PASSPHRASE,
    )
    .await?;
    assert_eq!(recovered.networking, ramflux_sdk::custody::CreationState::Live);
    let live =
        replacement.request(Some(restored_id), "account", "account.status", json!({})).await?;
    assert_eq!(live["networking"], "live");
    assert_eq!(live["device_id"], replacement_device);
    Ok(())
}
