// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use crate::*;

#[cfg(all(test, feature = "realnet"))]
#[allow(clippy::too_many_lines)]
pub(crate) async fn mvp_s24_assert_group_out_of_order_key(
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
        "s24 rf admin federation peer",
    )
    .await?;
    assert_eq!(peered["a_to_b"]["can_deliver"], true);
    assert_eq!(peered["b_to_a"]["can_deliver"], true);
    assert_s22_mesh_quic_listener_ready(node_a)?;
    assert_s22_mesh_quic_listener_ready(node_b)?;

    let temp_root = temp_root("s24_group_out_of_order_key")?;
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
                "alice_s24_account",
                "principal_s24_alice",
                "alice_device_s24",
                "target_s24_alice",
                &node_a.gateway_quic_addr.to_string(),
                &node_a.admin_url,
                &ca_cert_arg,
                "41",
                "42",
            )
            .await?;
            assert_production_account_transport_quic(
                &rf_binary,
                &alice_socket_arg,
                "alice_s24_account",
                "S24 after create",
            )
            .await?;
            mvp_s8_create_rf_account(
                &rf_binary,
                &bob_socket_arg,
                "bob_s24_account",
                "principal_s24_bob",
                "bob_device_s24",
                "target_s24_bob",
                &node_b.gateway_quic_addr.to_string(),
                &node_b.admin_url,
                &ca_cert_arg,
                "43",
                "44",
            )
            .await?;
            assert_production_account_transport_quic(
                &rf_binary,
                &bob_socket_arg,
                "bob_s24_account",
                "S24 after create",
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
                    "alice_s24_account",
                    "--group",
                    "group_s24_out_of_order",
                    "--creator",
                    "alice_device_s24",
                    "--member",
                    "bob_device_s24",
                ],
                "s24 group create without remote key",
            )
            .await?;
            assert_eq!(created["group_id"], "group_s24_out_of_order");
            assert!(
                created["members"]
                    .as_array()
                    .is_some_and(|members| members.iter().any(|member| member == "bob_device_s24")),
                "S24 Alice group fixture did not include Bob as a member: {created}"
            );
            let bob_group_created = mvp_s10_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &bob_socket_arg,
                    "group",
                    "create",
                    "--account",
                    "bob_s24_account",
                    "--group",
                    "group_s24_out_of_order",
                    "--creator",
                    "alice_device_s24",
                    "--member",
                    "bob_device_s24",
                ],
                "s24 bob group projection before key",
            )
            .await?;
            assert!(
                bob_group_created["members"]
                    .as_array()
                    .is_some_and(|members| members.iter().any(|member| member == "bob_device_s24")),
                "S24 Bob group fixture did not include Bob as a member: {bob_group_created}"
            );

            let plaintext = b"s24 group message before sender key";
            let node_b_mesh_before_group_send = s22_mesh_observability(node_b)?;
            let sent = mvp_s10_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &alice_socket_arg,
                    "group",
                    "send",
                    "--account",
                    "alice_s24_account",
                    "--group",
                    "group_s24_out_of_order",
                    "--conversation",
                    "conv_s24_group",
                    "--message",
                    "msg_s24_group_1",
                    "--sender",
                    "alice_device_s24",
                    "--envelope",
                    "env_s24_group_1",
                    "--source-principal",
                    "principal_s24_alice",
                    "--target",
                    "target_s24_bob",
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
                "s24 group message before key",
            )
            .await?;
            assert_eq!(sent["federated_submitted"]["accepted"], true);
            let node_b_mesh_after_group_send = s22_mesh_observability(node_b)?;
            assert_s22_quic_inbound_delta(
                &node_b_mesh_before_group_send,
                &node_b_mesh_after_group_send,
            );

            let first_read = mvp_s10_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &bob_socket_arg,
                    "group",
                    "read",
                    "--account",
                    "bob_s24_account",
                    "--group",
                    "group_s24_out_of_order",
                    "--conversation",
                    "conv_s24_group",
                ],
                "s24 bob read before sender key",
            )
            .await?;
            assert_eq!(first_read["decrypted_messages"].as_array().map_or(0, Vec::len), 0);
            assert_eq!(first_read["messages"].as_array().map_or(0, Vec::len), 0);
            assert_eq!(first_read["pending_undecrypted_count"], 1);
            assert_node_opaque_payload(
                first_read["gateway_entries"][0]["envelope"]["encrypted_payload"]
                    .as_str()
                    .ok_or("missing S24 pending encrypted payload")?,
                plaintext,
            );

            let mut alice_bus = ramflux_sdk::LocalBusClient::connect(&alice_socket).await?;
            let exported = alice_bus
                .request(
                    Some("alice_s24_account".to_owned()),
                    "group",
                    "group.sender_key.export",
                    &ramflux_sdk::LocalBusGroupSenderKeyExportRequest {
                        group_id: "group_s24_out_of_order".to_owned(),
                        sender_id: "alice_device_s24".to_owned(),
                    },
                )
                .await?;
            let distribution_base64 = exported["distribution_base64"]
                .as_str()
                .ok_or("missing S24 exported sender-key distribution")?;
            let mut bob_bus = ramflux_sdk::LocalBusClient::connect(&bob_socket).await?;
            let sender_key = bob_bus
                .request(
                    Some("bob_s24_account".to_owned()),
                    "group",
                    "group.sender_key.import",
                    &ramflux_sdk::LocalBusGroupSenderKeyImportRequest {
                        distribution_base64: distribution_base64.to_owned(),
                    },
                )
                .await?;
            assert_eq!(sender_key["group_id"], "group_s24_out_of_order");
            assert_eq!(sender_key["sender_id"], "alice_device_s24");
            assert_eq!(sender_key["pending_undecrypted_count"], 0);
            let decrypted_on_key_arrival = sender_key["decrypted_messages"]
                .as_array()
                .ok_or("missing S24 decrypted messages on key arrival")?;
            assert_eq!(decrypted_on_key_arrival.len(), 1);
            assert_eq!(decrypted_on_key_arrival[0]["message_id"].as_str(), Some("env_s24_group_1"));
            let body = ramflux_protocol::decode_base64url(
                decrypted_on_key_arrival[0]["plaintext_body_base64"]
                    .as_str()
                    .ok_or("missing S24 key-arrival plaintext")?,
            )?;
            assert_eq!(body, plaintext);

            let projected_state = bob_bus
                .request(
                    Some("bob_s24_account".to_owned()),
                    "message",
                    "message.read",
                    &ramflux_sdk::LocalBusConversationRequest {
                        conversation_id: "conv_s24_group".to_owned(),
                    },
                )
                .await?;
            let projected = projected_state["messages"].as_array().ok_or("missing S24 messages")?;
            assert_eq!(projected.len(), 1);
            assert_eq!(projected[0]["message_id"].as_str(), Some("env_s24_group_1"));
            assert_production_account_transport_quic(
                &rf_binary,
                &alice_socket_arg,
                "alice_s24_account",
                "S24 after pending replay",
            )
            .await?;
            assert_production_account_transport_quic(
                &rf_binary,
                &bob_socket_arg,
                "bob_s24_account",
                "S24 after pending replay",
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
        .map_err(|_elapsed| "S24 out-of-order group key flow timed out")?;
    alice_result?;
    bob_result?;
    flow_result?;
    std::fs::remove_dir_all(&temp_root)?;
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
#[derive(serde::Deserialize)]
struct S9MeshObservabilitySnapshot {
    quic_listener_ready: bool,
    quic_listener_local_addr: Option<String>,
    quic_listener_last_error: Option<String>,
    tcp_inbound_s8_envelopes: u64,
    quic_inbound_s8_envelopes: u64,
}

#[cfg(all(test, feature = "realnet"))]
fn s9_mesh_observability(
    node: &S8RealnetNode,
) -> Result<S9MeshObservabilitySnapshot, Box<dyn std::error::Error>> {
    Ok(ramflux_node_core::itest_http_get_json(&format!(
        "{}/s8/federation/mesh-observability",
        node.federation_url
    ))?)
}

#[cfg(all(test, feature = "realnet"))]
fn assert_s9_mesh_quic_listener_ready(
    node: &S8RealnetNode,
) -> Result<(), Box<dyn std::error::Error>> {
    let snapshot = s9_mesh_observability(node)?;
    assert!(
        snapshot.quic_listener_ready,
        "node {} expected mesh QUIC listener ready, addr={:?}, error={:?}",
        node.node_id, snapshot.quic_listener_local_addr, snapshot.quic_listener_last_error
    );
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
fn assert_s9_quic_inbound_delta(
    before: &S9MeshObservabilitySnapshot,
    after: &S9MeshObservabilitySnapshot,
) {
    let quic_delta =
        after.quic_inbound_s8_envelopes.saturating_sub(before.quic_inbound_s8_envelopes);
    let tcp_delta = after.tcp_inbound_s8_envelopes.saturating_sub(before.tcp_inbound_s8_envelopes);
    assert!(quic_delta >= 1, "expected S9 QUIC mesh inbound envelope, got delta={quic_delta}");
    assert_eq!(tcp_delta, 0, "expected S9 no TCP mesh inbound envelopes during QUIC path");
}

#[cfg(all(test, feature = "realnet"))]
#[allow(clippy::too_many_lines)]
pub(crate) async fn mvp_s9_assert_cross_node_friend_rf(
    node_a: &S8RealnetNode,
    node_b: &S8RealnetNode,
    _ca_cert: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    mvp_s8_establish_trusted_links(node_a, node_b)?;
    assert_s9_mesh_quic_listener_ready(node_a)?;
    assert_s9_mesh_quic_listener_ready(node_b)?;
    let temp_root = temp_root("s9_cross_node_friend_rf")?;
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
        realnet_step("S9 wait alice local bus socket", format!("path={}", alice_socket.display()));
        tokio::time::timeout(Duration::from_secs(10), mvp_s4_wait_for_socket(&alice_socket))
            .await
            .map_err(|_elapsed| "S9 wait alice local bus socket timed out")??;
        realnet_step("S9 wait bob local bus socket", format!("path={}", bob_socket.display()));
        tokio::time::timeout(Duration::from_secs(10), mvp_s4_wait_for_socket(&bob_socket))
            .await
            .map_err(|_elapsed| "S9 wait bob local bus socket timed out")??;
        let alice_socket_arg = mvp_s4_path_arg(&alice_socket);
        let bob_socket_arg = mvp_s4_path_arg(&bob_socket);
        // Cross-node setup: each node has its own per-node CA, so alice (node_a) and bob (node_b)
        // must register with their OWN node CA (matching s8). A single shared CA fails QUIC TLS
        // verification against the other node's gateway.
        let alice_ca_cert_arg = mvp_s4_path_arg(&node_a.ca_cert);
        let bob_ca_cert_arg = mvp_s4_path_arg(&node_b.ca_cert);
        realnet_step(
            "S9 create alice account",
            format!(
                "node={} gateway={} quic={} target=target_s9_alice",
                node_a.node_id, node_a.gateway_url, node_a.gateway_quic_addr
            ),
        );
        let alice_commitment = mvp_s8_create_rf_account(
            &rf_binary,
            &alice_socket_arg,
            "alice_s9_account",
            "principal_s9_alice",
            "alice_device_s9",
            "target_s9_alice",
            &node_a.gateway_quic_addr.to_string(),
            &node_a.gateway_url,
            &alice_ca_cert_arg,
            "a9",
            "aa",
        )
        .await?;
        realnet_step(
            "S9 create bob account",
            format!(
                "node={} gateway={} quic={} target=target_s9_bob",
                node_b.node_id, node_b.gateway_url, node_b.gateway_quic_addr
            ),
        );
        let bob_commitment = mvp_s8_create_rf_account(
            &rf_binary,
            &bob_socket_arg,
            "bob_s9_account",
            "principal_s9_bob",
            "bob_device_s9",
            "target_s9_bob",
            &node_b.gateway_quic_addr.to_string(),
            &node_b.gateway_url,
            &bob_ca_cert_arg,
            "b9",
            "ba",
        )
        .await?;
        realnet_step(
            "S9 send cross-node friend request",
            format!(
                "source_node={} target_node={} federation_url={} recipient_prekey_url={} envelope=env_s9_friend_request target=target_s9_bob",
                node_a.node_id, node_b.node_id, node_a.federation_url, node_b.gateway_url
            ),
        );
        let node_b_mesh_before_request = s9_mesh_observability(node_b)?;
        let request = mvp_s9_rf_contact_request(
            &rf_binary,
            &alice_socket_arg,
            "alice_s9_account",
            "msg_s9_friend_request",
            "env_s9_friend_request",
            "principal_s9_alice",
            &alice_commitment,
            "bob_device_s9",
            "target_s9_bob",
            &node_a.federation_url,
            "node_a.realnet",
            "node_b.realnet",
            &node_b.gateway_url,
        )
        .await?;
        realnet_step("S9 friend request returned", format!("accepted={}", request["accepted"]));
        assert_eq!(request["accepted"], true);
        realnet_step("S9 bob reads friend request", "conversation=conv_s9_friend");
        let bob_request = mvp_s9_rf_json_step(
            "S9 bob dm read friend request",
            &rf_binary,
            &[
                "--socket",
                &bob_socket_arg,
                "dm",
                "read",
                "--account",
                "bob_s9_account",
                "--conversation",
                "conv_s9_friend",
            ],
        )
        .await?;
        let request_entries =
            bob_request["gateway_entries"].as_array().ok_or("missing S9 request entry")?;
        assert_eq!(request_entries.len(), 1);
        assert_node_opaque_payload(
            request_entries[0]["envelope"]["encrypted_payload"]
                .as_str()
                .ok_or("missing S9 request encrypted payload")?,
            b"friend.requested",
        );
        let request_plaintext = mvp_s9_first_plaintext(&bob_request)?;
        assert!(request_plaintext.contains("\"type\":\"friend.requested\""));
        let node_b_mesh_after_request = s9_mesh_observability(node_b)?;
        assert_s9_quic_inbound_delta(&node_b_mesh_before_request, &node_b_mesh_after_request);

        realnet_step(
            "S9 send cross-node friend accept",
            format!(
                "source_node={} target_node={} federation_url={} recipient_prekey_url={} envelope=env_s9_friend_accept target=target_s9_alice",
                node_b.node_id, node_a.node_id, node_b.federation_url, node_a.gateway_url
            ),
        );
        let node_a_mesh_before_accept = s9_mesh_observability(node_a)?;
        let accept = mvp_s9_rf_contact_accept(
            &rf_binary,
            &bob_socket_arg,
            "bob_s9_account",
            "msg_s9_friend_accept",
            "env_s9_friend_accept",
            "principal_s9_bob",
            &bob_commitment,
            "alice_device_s9",
            "target_s9_alice",
            &node_b.federation_url,
            "node_b.realnet",
            "node_a.realnet",
            &node_a.gateway_url,
        )
        .await?;
        realnet_step("S9 friend accept returned", format!("accepted={}", accept["delivery"]["accepted"]));
        assert_eq!(accept["link"]["state"], "accepted");
        assert_eq!(accept["delivery"]["accepted"], true);
        realnet_step("S9 alice reads friend accept", "conversation=conv_s9_friend");
        let alice_accept = mvp_s9_rf_json_step(
            "S9 alice dm read friend accept",
            &rf_binary,
            &[
                "--socket",
                &alice_socket_arg,
                "dm",
                "read",
                "--account",
                "alice_s9_account",
                "--conversation",
                "conv_s9_friend",
            ],
        )
        .await?;
        let accept_plaintext = mvp_s9_first_plaintext(&alice_accept)?;
        assert!(accept_plaintext.contains("\"type\":\"friend.accepted\""));
        let node_a_mesh_after_accept = s9_mesh_observability(node_a)?;
        assert_s9_quic_inbound_delta(&node_a_mesh_before_accept, &node_a_mesh_after_accept);
        realnet_step("S9 assert alice friend link", "account=alice_s9_account");
        mvp_s9_assert_friend_link(&rf_binary, &alice_socket_arg, "alice_s9_account").await?;
        realnet_step("S9 assert bob friend link", "account=bob_s9_account");
        mvp_s9_assert_friend_link(&rf_binary, &bob_socket_arg, "bob_s9_account").await?;

        realnet_step(
            "S9 revoke node-a route to node-b",
            format!("federation_url={} peer=node_b.realnet", node_a.federation_url),
        );
        set_mvp4_federation_route_status(
            &node_a.federation_url,
            "node_b.realnet",
            ramflux_node_core::FederationTrustStatus::Revoked,
        )?;
        realnet_step("S9 verify revoked friend request rejected", "peer=node_b.realnet");
        let rejected = tokio::time::timeout(
            Duration::from_secs(45),
            mvp_s4_rf_failure(
                &rf_binary,
                &mvp_s9_contact_request_args(
                    &alice_socket_arg,
                    "alice_s9_account",
                    "msg_s9_friend_rejected",
                    "env_s9_friend_rejected",
                    "principal_s9_alice",
                    &alice_commitment,
                    "bob_device_s9",
                    "target_s9_bob",
                    &node_a.federation_url,
                    "node_a.realnet",
                    "node_b.realnet",
                    &node_b.gateway_url,
                ),
            ),
        )
        .await
        .map_err(|_elapsed| "S9 revoked friend request failure check timed out")??;
        assert!(
            rejected.contains("federation delivery paused for node_b.realnet"),
            "unexpected S9 revoked friend rejection: {rejected}"
        );
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
        .map_err(|_elapsed| "S9 cross-node friend rf flow timed out")?;
    alice_result?;
    bob_result?;
    flow_result?;
    std::fs::remove_dir_all(&temp_root)?;
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn mvp_s9_rf_contact_request(
    rf_binary: &Path,
    socket: &str,
    account: &str,
    message: &str,
    envelope: &str,
    source_principal: &str,
    sender: &str,
    recipient_device: &str,
    target_delivery: &str,
    federation_url: &str,
    source_node: &str,
    target_node: &str,
    recipient_prekey_url: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    mvp_s9_rf_json_step(
        "S9 contact request rf",
        rf_binary,
        &mvp_s9_contact_request_args(
            socket,
            account,
            message,
            envelope,
            source_principal,
            sender,
            recipient_device,
            target_delivery,
            federation_url,
            source_node,
            target_node,
            recipient_prekey_url,
        ),
    )
    .await
}
