// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use crate::*;

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s22_assert_prod_peer_cross_node_dm(
    node_a: &S22ProductionNode,
    node_b: &S22ProductionNode,
) -> Result<(), Box<dyn std::error::Error>> {
    Box::pin(mvp_s22_assert_prod_peer_cross_node_dm_inner(node_a, node_b, false)).await
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s22_assert_prod_peer_cross_node_dm_after_federation_restart(
    node_a: &S22ProductionNode,
    node_b: &S22ProductionNode,
) -> Result<(), Box<dyn std::error::Error>> {
    Box::pin(mvp_s22_assert_prod_peer_cross_node_dm_inner(node_a, node_b, true)).await
}

#[cfg(all(test, feature = "realnet"))]
#[allow(clippy::too_many_lines)]
async fn mvp_s22_assert_prod_peer_cross_node_dm_inner(
    node_a: &S22ProductionNode,
    node_b: &S22ProductionNode,
    restart_node_b_federation: bool,
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
        "s22 rf admin federation peer",
    )
    .await?;
    assert_eq!(peered["a_to_b"]["can_deliver"], true);
    assert_eq!(peered["b_to_a"]["can_deliver"], true);
    assert_eq!(peered["a_to_b"]["discovered"]["source"], "WellKnown");
    assert_eq!(peered["b_to_a"]["discovered"]["source"], "WellKnown");
    assert_s22_mesh_quic_listener_ready(node_a)?;
    assert_s22_mesh_quic_listener_ready(node_b)?;

    let temp_root = temp_root("s22_prod_federation_rf")?;
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
                "alice_s22_account",
                "principal_s22_alice",
                "alice_device_s22",
                "target_s22_alice",
                &node_a.gateway_quic_addr.to_string(),
                &node_a.admin_url,
                &ca_cert_arg,
                "21",
                "22",
            )
            .await?;
            assert_production_account_transport_quic(
                &rf_binary,
                &alice_socket_arg,
                "alice_s22_account",
                "after create",
            )
            .await?;
            let bob_commitment = mvp_s8_create_rf_account(
                &rf_binary,
                &bob_socket_arg,
                "bob_s22_account",
                "principal_s22_bob",
                "bob_device_s22",
                "target_s22_bob",
                &node_b.gateway_quic_addr.to_string(),
                &node_b.admin_url,
                &ca_cert_arg,
                "23",
                "24",
            )
            .await?;
            assert_production_account_transport_quic(
                &rf_binary,
                &bob_socket_arg,
                "bob_s22_account",
                "after create",
            )
            .await?;
            let plaintext = b"s22 production peered federated rf dm plaintext";
            let node_b_mesh_before_dm = s22_mesh_observability(node_b)?;
            let submitted = mvp_s10_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &alice_socket_arg,
                    "dm",
                    "send",
                    "--account",
                    "alice_s22_account",
                    "--conversation",
                    "conv_s22_cross_node",
                    "--message",
                    "msg_s22_cross_node_1",
                    "--envelope",
                    "env_s22_cross_node_dm_1",
                    "--source-principal",
                    "principal_s22_alice",
                    "--sender",
                    "alice_s22",
                    "--recipient-principal-commitment",
                    bob_commitment.as_str(),
                    "--recipient-device",
                    "bob_device_s22",
                    "--target",
                    "target_s22_bob",
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
                "s22 alice cross-node dm send",
            )
            .await?;
            assert_eq!(submitted["accepted"], true);
            assert_eq!(submitted["delivery"]["target_delivery_id"], "target_s22_bob");
            // The forward ack (FederatedEnvelopeForwardResponse.delivery) carries no envelope;
            // verify node-opaque on what actually lands in bob's inbox after cross-node forward.
            let bob_read = mvp_s10_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &bob_socket_arg,
                    "dm",
                    "read",
                    "--account",
                    "bob_s22_account",
                    "--conversation",
                    "conv_s22_cross_node",
                ],
                "s22 bob cross-node dm read",
            )
            .await?;
            assert_node_opaque_payload(
                bob_read["gateway_entries"][0]["envelope"]["encrypted_payload"]
                    .as_str()
                    .ok_or("missing S22 forwarded encrypted payload")?,
                plaintext,
            );
            let decrypted = bob_read["decrypted_messages"]
                .as_array()
                .ok_or("missing S22 decrypted messages")?;
            assert_eq!(decrypted.len(), 1);
            assert_eq!(decrypted[0]["message_id"].as_str(), Some("env_s22_cross_node_dm_1"));
            let body = ramflux_protocol::decode_base64url(
                decrypted[0]["plaintext_body_base64"].as_str().ok_or("missing S22 plaintext")?,
            )?;
            assert_eq!(body, plaintext);
            let node_b_mesh_after_dm = s22_mesh_observability(node_b)?;
            assert_s22_quic_inbound_delta(&node_b_mesh_before_dm, &node_b_mesh_after_dm);
            assert_production_account_transport_quic(
                &rf_binary,
                &alice_socket_arg,
                "alice_s22_account",
                "after first dm",
            )
            .await?;
            assert_production_account_transport_quic(
                &rf_binary,
                &bob_socket_arg,
                "bob_s22_account",
                "after first dm",
            )
            .await?;
            if restart_node_b_federation {
                restart_s22_federation_service(node_b)?;
                assert_s22_mesh_quic_listener_ready(node_b)?;
                let peered_after_restart = mvp_s10_rf_json(
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
                    "s22 rf admin federation peer after federation restart",
                )
                .await?;
                assert_eq!(peered_after_restart["a_to_b"]["can_deliver"], true);
                assert_eq!(peered_after_restart["b_to_a"]["can_deliver"], true);
                let restart_plaintext = b"s22 after federation restart plaintext";
                let node_b_mesh_before_restart_dm = s22_mesh_observability(node_b)?;
                let submitted_after_restart = mvp_s10_rf_json(
                    &rf_binary,
                    &[
                        "--socket",
                        &alice_socket_arg,
                        "dm",
                        "send",
                        "--account",
                        "alice_s22_account",
                        "--conversation",
                        "conv_s22_cross_node",
                        "--message",
                        "msg_s22_cross_node_after_restart",
                        "--envelope",
                        "env_s22_cross_node_dm_after_restart",
                        "--source-principal",
                        "principal_s22_alice",
                        "--sender",
                        "alice_s22",
                        "--recipient-principal-commitment",
                        bob_commitment.as_str(),
                        "--recipient-device",
                        "bob_device_s22",
                        "--target",
                        "target_s22_bob",
                        "--body",
                        std::str::from_utf8(restart_plaintext)?,
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
                    "s22 alice cross-node dm send after federation restart",
                )
                .await?;
                assert_eq!(submitted_after_restart["accepted"], true);
                let bob_read_after_restart = mvp_s10_rf_json(
                    &rf_binary,
                    &[
                        "--socket",
                        &bob_socket_arg,
                        "dm",
                        "read",
                        "--account",
                        "bob_s22_account",
                        "--conversation",
                        "conv_s22_cross_node",
                    ],
                    "s22 bob cross-node dm read after federation restart",
                )
                .await?;
                let decrypted_after_restart = bob_read_after_restart["decrypted_messages"]
                    .as_array()
                    .ok_or("missing S22 decrypted messages after restart")?;
                assert!(
                    decrypted_after_restart.iter().any(|message| {
                        message["message_id"].as_str()
                            == Some("env_s22_cross_node_dm_after_restart")
                    }),
                    "missing S22 post-restart DM: {decrypted_after_restart:?}"
                );
                let node_b_mesh_after_restart_dm = s22_mesh_observability(node_b)?;
                assert_s22_quic_inbound_delta(
                    &node_b_mesh_before_restart_dm,
                    &node_b_mesh_after_restart_dm,
                );
                assert_production_account_transport_quic(
                    &rf_binary,
                    &alice_socket_arg,
                    "alice_s22_account",
                    "after federation restart dm",
                )
                .await?;
                assert_production_account_transport_quic(
                    &rf_binary,
                    &bob_socket_arg,
                    "bob_s22_account",
                    "after federation restart dm",
                )
                .await?;
            }
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
        .map_err(|_elapsed| "S22 production federation rf flow timed out")?;
    alice_result?;
    bob_result?;
    flow_result?;
    std::fs::remove_dir_all(&temp_root)?;
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
#[derive(serde::Deserialize)]
pub(crate) struct S22MeshObservabilitySnapshot {
    quic_listener_ready: bool,
    quic_listener_local_addr: Option<String>,
    quic_listener_last_error: Option<String>,
    tcp_inbound_s8_envelopes: u64,
    quic_inbound_s8_envelopes: u64,
}

#[cfg(all(test, feature = "realnet"))]
#[derive(serde::Serialize)]
struct S22MeshObservabilityRequest<'a> {
    admin_token: &'a str,
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn s22_mesh_observability(
    node: &S22ProductionNode,
) -> Result<S22MeshObservabilitySnapshot, Box<dyn std::error::Error>> {
    Ok(ramflux_node_core::itest_http_post_json(
        &format!("{}/s8/federation/mesh-observability", node.admin_url),
        &S22MeshObservabilityRequest { admin_token: &node.admin_token },
    )?)
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn assert_s22_mesh_quic_listener_ready(
    node: &S22ProductionNode,
) -> Result<(), Box<dyn std::error::Error>> {
    let snapshot = s22_mesh_observability(node)?;
    assert!(
        snapshot.quic_listener_ready,
        "node {} expected S22 mesh QUIC listener ready, addr={:?}, error={:?}",
        node.node_id, snapshot.quic_listener_local_addr, snapshot.quic_listener_last_error
    );
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn assert_s22_quic_inbound_delta(
    before: &S22MeshObservabilitySnapshot,
    after: &S22MeshObservabilitySnapshot,
) {
    let quic_delta =
        after.quic_inbound_s8_envelopes.saturating_sub(before.quic_inbound_s8_envelopes);
    let tcp_delta = after.tcp_inbound_s8_envelopes.saturating_sub(before.tcp_inbound_s8_envelopes);
    assert!(quic_delta >= 1, "expected S22 QUIC mesh inbound envelope, got delta={quic_delta}");
    assert_eq!(tcp_delta, 0, "expected S22 no TCP mesh inbound envelopes during QUIC path");
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn assert_production_account_transport_quic(
    rf_binary: &Path,
    socket_arg: &str,
    account: &str,
    phase: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let status = mvp_s10_rf_json(
        rf_binary,
        &["--socket", socket_arg, "account", "status", "--account", account],
        &format!("s22 account status {account} {phase}"),
    )
    .await?;
    assert_eq!(
        status["active_transport_kind"].as_str(),
        Some(ramflux_sdk::GatewaySessionTransportKind::Quic.wire_name()),
        "production account {account} must stay on QUIC {phase}, status={status}"
    );
    let session_id = status["session_id"].as_str().ok_or_else(|| {
        format!("production account {account} missing session_id {phase}: {status}")
    })?;
    assert!(
        !session_id.is_empty(),
        "production account {account} has empty session_id {phase}: {status}"
    );
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s8_accept_local_friend_projection(
    rf_binary: &Path,
    alice_socket: &str,
    bob_socket: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    realnet_step("create alice local friend projection", format!("socket={alice_socket}"));
    let alice_contact = mvp_s4_rf_json(
        rf_binary,
        &[
            "--socket",
            alice_socket,
            "contact",
            "add",
            "--account",
            "alice_s8_account",
            "--link",
            "friend_link_s8_cross_node",
            "--requester",
            "alice_s8",
            "--target",
            "bob_s8",
        ],
    )
    .await?;
    assert_eq!(alice_contact["state"], "accepted");
    realnet_step("create bob local friend projection", format!("socket={bob_socket}"));
    let bob_contact = mvp_s4_rf_json(
        rf_binary,
        &[
            "--socket",
            bob_socket,
            "contact",
            "add",
            "--account",
            "bob_s8_account",
            "--link",
            "friend_link_s8_cross_node",
            "--requester",
            "alice_s8",
            "--target",
            "bob_s8",
        ],
    )
    .await?;
    assert_eq!(bob_contact["state"], "accepted");
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s8_send_and_read_cross_node_dm(
    rf_binary: &Path,
    alice_socket: &str,
    bob_socket: &str,
    bob_commitment: &str,
    node_a: &S8RealnetNode,
    node_b: &S8RealnetNode,
) -> Result<(), Box<dyn std::error::Error>> {
    let plaintext = b"s8 true two-node federated rf dm plaintext";
    realnet_step(
        "rf dm send cross-node",
        format!(
            "source_node={} target_node={} federation_url={} recipient_prekey_url={} envelope=env_s8_cross_node_dm_1 target_delivery=target_s8_bob",
            node_a.node_id, node_b.node_id, node_a.federation_url, node_b.gateway_url
        ),
    );
    let submitted = mvp_s4_rf_json(
        rf_binary,
        &[
            "--socket",
            alice_socket,
            "dm",
            "send",
            "--account",
            "alice_s8_account",
            "--conversation",
            "conv_s8_cross_node",
            "--message",
            "msg_s8_cross_node_1",
            "--envelope",
            "env_s8_cross_node_dm_1",
            "--source-principal",
            "principal_s8_alice",
            "--sender",
            "alice_s8",
            "--recipient-principal-commitment",
            bob_commitment,
            "--recipient-device",
            "bob_device_s8",
            "--target",
            "target_s8_bob",
            "--body",
            std::str::from_utf8(plaintext)?,
            "--federation-url",
            &node_a.federation_url,
            "--source-node",
            &node_a.node_id,
            "--target-node",
            &node_b.node_id,
            "--recipient-prekey-url",
            &node_b.gateway_url,
        ],
    )
    .await?;
    assert_eq!(submitted["accepted"], true);
    assert_eq!(submitted["source_node_id"], node_a.node_id);
    assert_eq!(submitted["target_node_id"], node_b.node_id);
    assert_eq!(submitted["delivery"]["target_delivery_id"], "target_s8_bob");
    assert!(matches!(submitted["delivery"]["outcome"].as_str(), Some("online" | "offline_queued")));

    realnet_step(
        "waiting for node-b inbox via rf read",
        format!(
            "node={} socket={bob_socket} account=bob_s8_account conversation=conv_s8_cross_node",
            node_b.node_id
        ),
    );
    let bob_read = mvp_s4_rf_json(
        rf_binary,
        &[
            "--socket",
            bob_socket,
            "dm",
            "read",
            "--account",
            "bob_s8_account",
            "--conversation",
            "conv_s8_cross_node",
        ],
    )
    .await?;
    let entries = bob_read["gateway_entries"].as_array().ok_or("missing S8 gateway entries")?;
    realnet_step(
        "node-b inbox read returned",
        format!("entries={} node={}", entries.len(), node_b.node_id),
    );
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["envelope"]["envelope_id"], "env_s8_cross_node_dm_1");
    assert_node_opaque_payload(
        entries[0]["envelope"]["encrypted_payload"]
            .as_str()
            .ok_or("missing S8 encrypted payload")?,
        plaintext,
    );
    let decrypted =
        bob_read["decrypted_messages"].as_array().ok_or("missing S8 decrypted messages")?;
    assert_eq!(decrypted.len(), 1);
    assert_eq!(decrypted[0]["message_id"].as_str(), Some("env_s8_cross_node_dm_1"));
    let decoded = ramflux_protocol::decode_base64url(
        decrypted[0]["plaintext_body_base64"].as_str().ok_or("missing S8 plaintext")?,
    )?;
    assert_eq!(decoded, plaintext);
    Ok(())
}
