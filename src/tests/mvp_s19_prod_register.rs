// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use super::*;

#[cfg(feature = "realnet")]
#[test]
fn mvp_s19_realnet_prod_node_register_dm() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    let node = start_s10_private_node_compose()?;
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async {
        wait_for_private_gateway_quic(node.gateway_quic_addr, &node.ca_cert).await?;
        Box::pin(mvp_s19_assert_prod_node_register_prekey_dm(
            node.gateway_quic_addr,
            &node.ca_cert,
        ))
        .await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    drop(node);
    Ok(())
}

#[cfg(feature = "realnet")]
#[allow(clippy::too_many_lines)]
async fn mvp_s19_assert_prod_node_register_prekey_dm(
    gateway_quic_addr: std::net::SocketAddr,
    ca_cert: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let temp_root = temp_root("s19_prod_register")?;
    let rf_binary = mvp_s4_build_rf_binary().await?;
    let alice_socket = temp_root.join("alice/rfd.sock");
    let bob_socket = temp_root.join("bob/rfd.sock");
    let (alice_shutdown_tx, alice_shutdown_rx) = tokio::sync::watch::channel(false);
    let (bob_shutdown_tx, bob_shutdown_rx) = tokio::sync::watch::channel(false);
    let alice_config =
        ramflux_sdk::LocalBusConfig::new(&alice_socket, temp_root.join("alice/data"));
    let bob_config = ramflux_sdk::LocalBusConfig::new(&bob_socket, temp_root.join("bob/data"));
    let alice_server = ramflux_sdk::serve_local_bus_until(alice_config, alice_shutdown_rx);
    let bob_server = ramflux_sdk::serve_local_bus_until(bob_config, bob_shutdown_rx);
    let client_flow = async {
        let result = async {
            mvp_s4_wait_for_socket(&alice_socket).await?;
            mvp_s4_wait_for_socket(&bob_socket).await?;
            let alice_socket_arg = mvp_s4_path_arg(&alice_socket);
            let bob_socket_arg = mvp_s4_path_arg(&bob_socket);
            let ca_cert_arg = mvp_s4_path_arg(ca_cert);
            let gateway_addr = gateway_quic_addr.to_string();
            mvp_s10_create_rf_account(
                &rf_binary,
                &alice_socket_arg,
                "alice_s19_account",
                "principal_s19_alice",
                "alice_device_s19",
                "target_s19_alice",
                &gateway_addr,
                &ca_cert_arg,
                "19",
                "1a",
            )
            .await?;
            mvp_s19_assert_account_transport_quic(
                &rf_binary,
                &alice_socket_arg,
                "alice_s19_account",
            )
            .await?;
            mvp_s10_create_rf_account(
                &rf_binary,
                &bob_socket_arg,
                "bob_s19_account",
                "principal_s19_bob",
                "bob_device_s19",
                "target_s19_bob",
                &gateway_addr,
                &ca_cert_arg,
                "1b",
                "1c",
            )
            .await?;
            mvp_s19_assert_account_transport_quic(&rf_binary, &bob_socket_arg, "bob_s19_account")
                .await?;
            let plaintext = b"s19 production register prekey dm";
            let submitted = mvp_s10_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &alice_socket_arg,
                    "dm",
                    "send",
                    "--account",
                    "alice_s19_account",
                    "--conversation",
                    "conv_s19_prod_register",
                    "--message",
                    "msg_s19_prod_register_dm",
                    "--envelope",
                    "env_s19_prod_register_dm",
                    "--source-principal",
                    "principal_s19_alice",
                    "alice_s19",
                    "--recipient-device",
                    "bob_device_s19",
                    "--target",
                    "target_s19_bob",
                    "--body",
                    std::str::from_utf8(plaintext)?,
                ],
                "s19 alice dm send",
            )
            .await?;
            assert_eq!(submitted["envelope"]["envelope_id"], "env_s19_prod_register_dm");
            let encrypted_payload = submitted["envelope"]["encrypted_payload"]
                .as_str()
                .ok_or("missing S19 encrypted payload")?;
            assert_node_opaque_payload(encrypted_payload, plaintext);
            mvp_s19_assert_dm_used_gateway_prekey(
                encrypted_payload,
                "bob_device_s19",
                "bob_device_s19:signed:1",
            )?;
            let bob_read = mvp_s10_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &bob_socket_arg,
                    "dm",
                    "read",
                    "--account",
                    "bob_s19_account",
                    "--conversation",
                    "conv_s19_prod_register",
                ],
                "s19 bob dm read",
            )
            .await?;
            let decrypted = bob_read["decrypted_messages"]
                .as_array()
                .ok_or("missing S19 decrypted messages")?;
            assert_eq!(decrypted.len(), 1);
            assert_eq!(decrypted[0]["message_id"].as_str(), Some("env_s19_prod_register_dm"));
            let body = ramflux_protocol::decode_base64url(
                decrypted[0]["plaintext_body_base64"].as_str().ok_or("missing S19 plaintext")?,
            )?;
            assert_eq!(body, plaintext);
            Ok::<(), Box<dyn std::error::Error>>(())
        }
        .await;
        let _ = alice_shutdown_tx.send(true);
        let _ = bob_shutdown_tx.send(true);
        result
    };
    let (alice_result, bob_result, flow_result) =
        Box::pin(tokio::time::timeout(Duration::from_mins(3), async {
            tokio::join!(alice_server, bob_server, client_flow)
        }))
        .await
        .map_err(|_elapsed| "S19 prod register flow timed out")?;
    alice_result?;
    bob_result?;
    flow_result?;
    std::fs::remove_dir_all(&temp_root)?;
    Ok(())
}

#[cfg(feature = "realnet")]
async fn mvp_s19_assert_account_transport_quic(
    rf_binary: &Path,
    socket: &str,
    account: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let status = mvp_s10_rf_json(
        rf_binary,
        &["--socket", socket, "account", "status", "--account", account],
        &format!("s19 account status {account}"),
    )
    .await?;
    assert_eq!(
        status["active_transport_kind"].as_str(),
        Some(ramflux_sdk::GatewaySessionTransportKind::Quic.wire_name()),
        "S19 account {account} must stay on QUIC, status={status}"
    );
    Ok(())
}

#[cfg(feature = "realnet")]
fn mvp_s19_assert_dm_used_gateway_prekey(
    encrypted_payload: &str,
    recipient_device_id: &str,
    signed_prekey_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let envelope_bytes = ramflux_protocol::decode_base64url(encrypted_payload)?;
    let envelope: serde_json::Value = serde_json::from_slice(&envelope_bytes)?;
    assert_eq!(envelope["schema"].as_str(), Some("ramflux.sdk.dm_x3dh_envelope.v1"));
    let x3dh = envelope["x3dh"].as_object().ok_or("missing S19 X3DH header")?;
    assert_eq!(
        x3dh.get("recipient_device_id").and_then(serde_json::Value::as_str),
        Some(recipient_device_id)
    );
    assert_eq!(
        x3dh.get("recipient_signed_prekey_id").and_then(serde_json::Value::as_str),
        Some(signed_prekey_id)
    );
    Ok(())
}
