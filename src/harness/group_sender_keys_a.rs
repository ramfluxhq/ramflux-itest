// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use crate::*;

#[cfg(all(test, feature = "realnet"))]
#[allow(clippy::too_many_lines)]
pub(crate) async fn mvp_s21_assert_rf_group_receive_decrypt(
    gateway_quic_addr: std::net::SocketAddr,
    ca_cert: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let temp_root = temp_root("s21_group_read")?;
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
    let flow = async {
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
                "alice_s21_account",
                "principal_s21_alice",
                "alice_device_s21",
                "target_s21_alice",
                &gateway_addr,
                &ca_cert_arg,
                "e1",
                "e2",
            )
            .await?;
            mvp_s21_assert_account_transport_quic(
                &rf_binary,
                &alice_socket_arg,
                "alice_s21_account",
                "after create",
            )
            .await?;
            mvp_s10_create_rf_account(
                &rf_binary,
                &bob_socket_arg,
                "bob_s21_account",
                "principal_s21_bob",
                "bob_device_s21",
                "target_s21_bob",
                &gateway_addr,
                &ca_cert_arg,
                "f1",
                "f2",
            )
            .await?;
            mvp_s21_assert_account_transport_quic(
                &rf_binary,
                &bob_socket_arg,
                "bob_s21_account",
                "after create",
            )
            .await?;
            let created = mvp_s10_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &alice_socket_arg,
                    "group",
                    "create",
                    "--account",
                    "alice_s21_account",
                    "--group",
                    "group_s21",
                    "--creator",
                    "alice_device_s21",
                    "--member",
                    "bob_device_s21",
                ],
                "s21 group create",
            )
            .await?;
            assert_eq!(created["group_id"], "group_s21");
            let distribution_payload =
                created["sender_key_distribution"]["envelope"]["encrypted_payload"]
                    .as_str()
                    .ok_or("missing S21 sender-key distribution payload")?;
            assert_node_opaque_payload(
                distribution_payload,
                b"ramflux.sdk.group_sender_key.distribution",
            );
            let plaintext = b"s21 rf group read sender-key plaintext";
            let sent = mvp_s10_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &alice_socket_arg,
                    "group",
                    "send",
                    "--account",
                    "alice_s21_account",
                    "--group",
                    "group_s21",
                    "--conversation",
                    "conv_s21_group",
                    "--message",
                    "msg_s21_group",
                    "--sender",
                    "alice_device_s21",
                    "--envelope",
                    "env_s21_group",
                    "--source-principal",
                    "principal_s21_alice",
                    "--target",
                    "target_s21_bob",
                    "--body",
                    std::str::from_utf8(plaintext)?,
                ],
                "s21 group send",
            )
            .await?;
            let encrypted_payload = sent["submitted"]["envelope"]["encrypted_payload"]
                .as_str()
                .ok_or("missing S21 group encrypted payload")?;
            assert_node_opaque_payload(encrypted_payload, plaintext);
            let read = mvp_s10_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &bob_socket_arg,
                    "group",
                    "read",
                    "--account",
                    "bob_s21_account",
                    "--group",
                    "group_s21",
                    "--conversation",
                    "conv_s21_group",
                ],
                "s21 bob group read",
            )
            .await?;
            let decrypted =
                read["decrypted_messages"].as_array().ok_or("missing S21 decrypted messages")?;
            assert_eq!(decrypted.len(), 1);
            assert_eq!(decrypted[0]["message_id"].as_str(), Some("env_s21_group"));
            assert_eq!(decrypted[0]["body_utf8"].as_str(), Some(std::str::from_utf8(plaintext)?));
            let body = ramflux_protocol::decode_base64url(
                decrypted[0]["plaintext_body_base64"].as_str().ok_or("missing S21 plaintext")?,
            )?;
            assert_eq!(body, plaintext);
            mvp_s21_assert_account_transport_quic(
                &rf_binary,
                &alice_socket_arg,
                "alice_s21_account",
                "after group read",
            )
            .await?;
            mvp_s21_assert_account_transport_quic(
                &rf_binary,
                &bob_socket_arg,
                "bob_s21_account",
                "after group read",
            )
            .await?;
            Ok::<(), Box<dyn std::error::Error>>(())
        }
        .await;
        let _ = alice_shutdown_tx.send(true);
        let _ = bob_shutdown_tx.send(true);
        result
    };
    let (alice_result, bob_result, flow_result) =
        Box::pin(tokio::time::timeout(Duration::from_mins(3), async {
            tokio::join!(alice_server, bob_server, flow)
        }))
        .await
        .map_err(|_elapsed| "S21 group read flow timed out")?;
    alice_result?;
    bob_result?;
    flow_result?;
    std::fs::remove_dir_all(&temp_root)?;
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s21_assert_account_transport_quic(
    rf_binary: &Path,
    socket_arg: &str,
    account: &str,
    phase: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let status = mvp_s10_rf_json(
        rf_binary,
        &["--socket", socket_arg, "account", "status", "--account", account],
        &format!("s21 account status {account} {phase}"),
    )
    .await?;
    assert_eq!(
        status["active_transport_kind"].as_str(),
        Some(ramflux_sdk::GatewaySessionTransportKind::Quic.wire_name()),
        "S21 account {account} must stay on QUIC {phase}, status={status}"
    );
    let session_id = status["session_id"]
        .as_str()
        .ok_or_else(|| format!("S21 account {account} missing session_id {phase}: {status}"))?;
    assert!(!session_id.is_empty(), "S21 account {account} has empty session_id {phase}: {status}");
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
#[allow(clippy::too_many_lines)]
pub(crate) async fn mvp_s23_assert_cross_node_group(
    node_a: &S22ProductionNode,
    node_b: &S22ProductionNode,
) -> Result<(), Box<dyn std::error::Error>> {
    let rf_binary = mvp_s4_build_rf_binary().await?;
    let peered = mvp_s10_rf_json(
        &rf_binary,
        &[
            "admin",
            "federation",
            "peer",
            "--node-a-admin-url",
            &node_a.admin_url,
            "--node-a-token",
            &node_a.admin_token,
            "--node-a-id",
            &node_a.node_id,
            "--node-a-well-known-url",
            &node_a.well_known_url,
            "--node-b-admin-url",
            &node_b.admin_url,
            "--node-b-token",
            &node_b.admin_token,
            "--node-b-id",
            &node_b.node_id,
            "--node-b-well-known-url",
            &node_b.well_known_url,
            "--capabilities",
            "opaque_delivery,federation_relay",
        ],
        "s23 rf admin federation peer",
    )
    .await?;
    assert_eq!(peered["a_to_b"]["can_deliver"], true);
    assert_eq!(peered["b_to_a"]["can_deliver"], true);
    assert_s22_mesh_quic_listener_ready(node_a)?;
    assert_s22_mesh_quic_listener_ready(node_b)?;

    let temp_root = temp_root("s23_cross_node_group")?;
    let alice_socket = temp_root.join("alice/rfd.sock");
    let bob_socket = temp_root.join("bob/rfd.sock");
    let (alice_shutdown_tx, alice_shutdown_rx) = tokio::sync::watch::channel(false);
    let (bob_shutdown_tx, bob_shutdown_rx) = tokio::sync::watch::channel(false);
    let alice_config =
        ramflux_sdk::LocalBusConfig::new(&alice_socket, temp_root.join("alice/data"));
    let bob_config = ramflux_sdk::LocalBusConfig::new(&bob_socket, temp_root.join("bob/data"));
    let alice_server = ramflux_sdk::serve_local_bus_until(alice_config, alice_shutdown_rx);
    let bob_server = ramflux_sdk::serve_local_bus_until(bob_config, bob_shutdown_rx);
    let flow = async {
        let result = async {
            mvp_s4_wait_for_socket(&alice_socket).await?;
            mvp_s4_wait_for_socket(&bob_socket).await?;
            let alice_socket_arg = mvp_s4_path_arg(&alice_socket);
            let bob_socket_arg = mvp_s4_path_arg(&bob_socket);
            let ca_cert_arg = mvp_s4_path_arg(&node_a.ca_cert);
            mvp_s8_create_rf_account(
                &rf_binary,
                &alice_socket_arg,
                "alice_s23_account",
                "principal_s23_alice",
                "alice_device_s23",
                "target_s23_alice",
                &node_a.gateway_quic_addr.to_string(),
                &node_a.admin_url,
                &ca_cert_arg,
                "31",
                "32",
            )
            .await?;
            assert_production_account_transport_quic(
                &rf_binary,
                &alice_socket_arg,
                "alice_s23_account",
                "S23 after create",
            )
            .await?;
            mvp_s8_create_rf_account(
                &rf_binary,
                &bob_socket_arg,
                "bob_s23_account",
                "principal_s23_bob",
                "bob_device_s23",
                "target_s23_bob",
                &node_b.gateway_quic_addr.to_string(),
                &node_b.admin_url,
                &ca_cert_arg,
                "33",
                "34",
            )
            .await?;
            assert_production_account_transport_quic(
                &rf_binary,
                &bob_socket_arg,
                "bob_s23_account",
                "S23 after create",
            )
            .await?;
            let node_b_mesh_before_group_create = s22_mesh_observability(node_b)?;
            let created = mvp_s10_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &alice_socket_arg,
                    "group",
                    "create",
                    "--account",
                    "alice_s23_account",
                    "--group",
                    "group_s23_cross_node",
                    "--creator",
                    "alice_device_s23",
                    "--member",
                    "bob_device_s23",
                    "--member-target-delivery",
                    "target_s23_bob",
                    "--federation-url",
                    &node_a.admin_url,
                    "--federation-admin-token",
                    &node_a.admin_token,
                    "--source-node",
                    &node_a.node_id,
                    "--target-node",
                    &node_b.node_id,
                    "--recipient-prekey-url",
                    &node_b.admin_url,
                ],
                "s23 cross-node group create",
            )
            .await?;
            assert_eq!(created["group_id"], "group_s23_cross_node");
            assert_eq!(created["sender_key_distribution"]["accepted"], true);
            let node_b_mesh_after_group_create = s22_mesh_observability(node_b)?;
            assert_s22_quic_inbound_delta(
                &node_b_mesh_before_group_create,
                &node_b_mesh_after_group_create,
            );

            let plaintext = b"s23 cross-node group sender-key plaintext";
            let node_b_mesh_before_group_send = s22_mesh_observability(node_b)?;
            let sent = mvp_s10_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &alice_socket_arg,
                    "group",
                    "send",
                    "--account",
                    "alice_s23_account",
                    "--group",
                    "group_s23_cross_node",
                    "--conversation",
                    "conv_s23_cross_node_group",
                    "--message",
                    "msg_s23_group_1",
                    "--sender",
                    "alice_device_s23",
                    "--envelope",
                    "env_s23_group_1",
                    "--source-principal",
                    "principal_s23_alice",
                    "--target",
                    "target_s23_bob",
                    "--body",
                    std::str::from_utf8(plaintext)?,
                    "--federation-url",
                    &node_a.admin_url,
                    "--federation-admin-token",
                    &node_a.admin_token,
                    "--source-node",
                    &node_a.node_id,
                    "--target-node",
                    &node_b.node_id,
                    "--recipient-prekey-url",
                    &node_b.admin_url,
                ],
                "s23 cross-node group send",
            )
            .await?;
            assert_eq!(sent["federated_submitted"]["accepted"], true);
            let node_b_mesh_after_group_send = s22_mesh_observability(node_b)?;
            assert_s22_quic_inbound_delta(
                &node_b_mesh_before_group_send,
                &node_b_mesh_after_group_send,
            );

            let read = mvp_s10_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &bob_socket_arg,
                    "group",
                    "read",
                    "--account",
                    "bob_s23_account",
                    "--group",
                    "group_s23_cross_node",
                    "--conversation",
                    "conv_s23_cross_node_group",
                ],
                "s23 bob cross-node group read",
            )
            .await?;
            let entries =
                read["gateway_entries"].as_array().ok_or("missing S23 gateway entries")?;
            assert_eq!(entries.len(), 2);
            assert_node_opaque_payload(
                entries[0]["envelope"]["encrypted_payload"]
                    .as_str()
                    .ok_or("missing S23 sender-key payload")?,
                b"ramflux.sdk.group_sender_key.distribution",
            );
            assert_node_opaque_payload(
                entries[1]["envelope"]["encrypted_payload"]
                    .as_str()
                    .ok_or("missing S23 group encrypted payload")?,
                plaintext,
            );
            let decrypted =
                read["decrypted_messages"].as_array().ok_or("missing S23 decrypted messages")?;
            assert_eq!(decrypted.len(), 1);
            assert_eq!(decrypted[0]["message_id"].as_str(), Some("env_s23_group_1"));
            let body = ramflux_protocol::decode_base64url(
                decrypted[0]["plaintext_body_base64"].as_str().ok_or("missing S23 plaintext")?,
            )?;
            assert_eq!(body, plaintext);
            assert_production_account_transport_quic(
                &rf_binary,
                &alice_socket_arg,
                "alice_s23_account",
                "S23 after group read",
            )
            .await?;
            assert_production_account_transport_quic(
                &rf_binary,
                &bob_socket_arg,
                "bob_s23_account",
                "S23 after group read",
            )
            .await?;
            Ok::<(), Box<dyn std::error::Error>>(())
        }
        .await;
        let _ = alice_shutdown_tx.send(true);
        let _ = bob_shutdown_tx.send(true);
        result
    };
    let (alice_result, bob_result, flow_result) =
        Box::pin(tokio::time::timeout(Duration::from_mins(3), async {
            tokio::join!(alice_server, bob_server, flow)
        }))
        .await
        .map_err(|_elapsed| "S23 production cross-node group flow timed out")?;
    alice_result?;
    bob_result?;
    flow_result?;
    std::fs::remove_dir_all(&temp_root)?;
    Ok(())
}
