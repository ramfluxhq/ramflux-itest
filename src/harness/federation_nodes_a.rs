// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use crate::*;

#[cfg(all(test, feature = "realnet"))]
#[derive(Clone, Copy)]
pub(crate) struct S22ProductionPorts {
    pub(crate) gateway: u16,
    pub(crate) federation_admin: u16,
    pub(crate) federation_mesh: u16,
    pub(crate) signaling_turn_udp: u16,
    pub(crate) signaling_turn_tcp: u16,
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) struct S22ProductionNode {
    pub(crate) node_id: String,
    pub(crate) admin_url: String,
    pub(crate) well_known_url: String,
    pub(crate) gateway_quic_addr: std::net::SocketAddr,
    pub(crate) ca_cert: PathBuf,
    pub(crate) admin_token: String,
    pub(crate) guard: ProductionComposeDownGuard,
}

#[cfg(all(test, feature = "realnet"))]
#[derive(Clone, Copy)]
pub(crate) struct S8ComposePorts {
    pub(crate) gateway_http: u16,
    pub(crate) gateway_quic: u16,
    pub(crate) router_http: u16,
    pub(crate) router_mesh: u16,
    pub(crate) notify_http: u16,
    pub(crate) federation_http: u16,
    pub(crate) federation_mesh: u16,
    pub(crate) relay_http: u16,
    pub(crate) relay_media_udp: u16,
    pub(crate) signaling_turn_udp: u16,
    pub(crate) signaling_turn_tcp: u16,
    pub(crate) retention_http: u16,
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) struct S8RealnetNode {
    pub(crate) node_id: String,
    pub(crate) federation_node_public_key: String,
    pub(crate) gateway_url: String,
    pub(crate) federation_url: String,
    pub(crate) federation_well_known_base: String,
    pub(crate) gateway_quic_addr: std::net::SocketAddr,
    pub(crate) ca_cert: PathBuf,
    pub(crate) federation_mesh_endpoint: String,
    pub(crate) guard: ComposeProjectDownGuard,
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s8_assert_cross_node_rf_dm(
    node_a: &S8RealnetNode,
    node_b: &S8RealnetNode,
    _ca_cert: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    realnet_step(
        "begin S8 cross-node rf dm",
        format!(
            "node_a={} node_b={} federation_a={} federation_b={}",
            node_a.node_id, node_b.node_id, node_a.federation_url, node_b.federation_url
        ),
    );
    mvp_s8_establish_trusted_links(node_a, node_b)?;
    Box::pin(mvp_s8_assert_cross_node_rf_dm_after_trust(node_a, node_b)).await
}

#[cfg(all(test, feature = "realnet"))]
#[allow(clippy::too_many_lines)]
pub(crate) async fn mvp_s8_assert_cross_node_rf_dm_after_trust(
    node_a: &S8RealnetNode,
    node_b: &S8RealnetNode,
) -> Result<(), Box<dyn std::error::Error>> {
    let temp_root = temp_root("s8_federation_rf")?;
    realnet_step("build rf binary", format!("temp_root={}", temp_root.display()));
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
            realnet_step(
                "waiting for alice local bus socket",
                format!("path={}", alice_socket.display()),
            );
            mvp_s4_wait_for_socket(&alice_socket).await?;
            realnet_step(
                "waiting for bob local bus socket",
                format!("path={}", bob_socket.display()),
            );
            mvp_s4_wait_for_socket(&bob_socket).await?;
            let alice_socket_arg = mvp_s4_path_arg(&alice_socket);
            let bob_socket_arg = mvp_s4_path_arg(&bob_socket);
            let alice_ca_cert_arg = mvp_s4_path_arg(&node_a.ca_cert);
            let bob_ca_cert_arg = mvp_s4_path_arg(&node_b.ca_cert);
            realnet_step(
                "register identity on node-a",
                format!(
                    "node={} gateway_url={} quic={} account=alice_s8_account target=target_s8_alice ca={}",
                    node_a.node_id, node_a.gateway_url, node_a.gateway_quic_addr, alice_ca_cert_arg
                ),
            );
            mvp_s8_create_rf_account(
                &rf_binary,
                &alice_socket_arg,
                "alice_s8_account",
                "principal_s8_alice",
                "alice_device_s8",
                "target_s8_alice",
                &node_a.gateway_quic_addr.to_string(),
                &node_a.gateway_url,
                &alice_ca_cert_arg,
                "81",
                "82",
            )
            .await?;
            realnet_step(
                "register identity on node-b",
                format!(
                    "node={} gateway_url={} quic={} account=bob_s8_account target=target_s8_bob ca={}",
                    node_b.node_id, node_b.gateway_url, node_b.gateway_quic_addr, bob_ca_cert_arg
                ),
            );
            mvp_s8_create_rf_account(
                &rf_binary,
                &bob_socket_arg,
                "bob_s8_account",
                "principal_s8_bob",
                "bob_device_s8",
                "target_s8_bob",
                &node_b.gateway_quic_addr.to_string(),
                &node_b.gateway_url,
                &bob_ca_cert_arg,
                "91",
                "92",
            )
            .await?;
            realnet_step("create local friend projections", "alice_socket+bob_socket");
            mvp_s8_accept_local_friend_projection(&rf_binary, &alice_socket_arg, &bob_socket_arg)
                .await?;
            realnet_step(
                "send cross-node DM",
                format!(
                    "source_node={} target_node={} federation_url={} recipient_prekey_url={}",
                    node_a.node_id, node_b.node_id, node_a.federation_url, node_b.gateway_url
                ),
            );
            mvp_s8_send_and_read_cross_node_dm(
                &rf_binary,
                &alice_socket_arg,
                &bob_socket_arg,
                node_a,
                node_b,
            )
            .await?;
            realnet_step(
                "revoke federation route after delivery",
                format!(
                    "node={} peer={} url={}",
                    node_a.node_id, node_b.node_id, node_a.federation_url
                ),
            );
            set_mvp4_federation_route_status(
                &node_a.federation_url,
                &node_b.node_id,
                ramflux_node_core::FederationTrustStatus::Revoked,
            )?;
            realnet_step(
                "verify revoked route rejects send",
                format!("source_node={} target_node={}", node_a.node_id, node_b.node_id),
            );
            let rejected = mvp_s4_rf_failure(
                &rf_binary,
                &[
                    "--socket",
                    &alice_socket_arg,
                    "dm",
                    "send",
                    "--account",
                    "alice_s8_account",
                    "--conversation",
                    "conv_s8_cross_node",
                    "--message",
                    "msg_s8_cross_node_rejected",
                    "--envelope",
                    "env_s8_cross_node_rejected",
                    "--source-principal",
                    "principal_s8_alice",
                    "alice_s8",
                    "--recipient-device",
                    "bob_device_s8",
                    "--target",
                    "target_s8_bob",
                    "--body",
                    "s8 revoked trust plaintext",
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
            assert!(
                rejected.contains(&format!("federation delivery paused for {}", node_b.node_id)),
                "unexpected S8 revoked trust rejection: {rejected}"
            );
            Ok::<(), Box<dyn std::error::Error>>(())
        }
        .await;
        let _ = alice_shutdown_tx.send(true);
        let _ = bob_shutdown_tx.send(true);
        result
    };
    let (alice_result, bob_result, flow_result) =
        tokio::join!(alice_server, bob_server, client_flow);
    alice_result?;
    bob_result?;
    flow_result?;
    std::fs::remove_dir_all(&temp_root)?;
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp_s8_establish_trusted_links(
    node_a: &S8RealnetNode,
    node_b: &S8RealnetNode,
) -> Result<(), Box<dyn std::error::Error>> {
    let now = realnet_now_i64();
    let invitation_expires_at = now.saturating_add(86_400);
    realnet_step(
        "establish trusted links invitation A->B",
        format!(
            "node=node-a local={} peer={} url={} peer_mesh={} peer_ca={}",
            node_a.node_id,
            node_b.node_id,
            node_a.federation_url,
            node_b.federation_mesh_endpoint,
            node_b.ca_cert.display()
        ),
    );
    let mut a_to_b = mvp8_handshake_request(
        &node_b.node_id,
        "fh_s8_a_to_b",
        &["opaque_delivery", "federation_relay"],
        Some(mvp8_invitation_with_ca(
            "inv_s8_a_to_b",
            &node_b.node_id,
            &["opaque_delivery", "federation_relay"],
            invitation_expires_at,
            std::fs::read_to_string(&node_b.ca_cert)?,
        )?),
        now,
    )?;
    a_to_b.route.endpoint.clone_from(&node_b.federation_mesh_endpoint);
    let admitted_ab = mvp8_post_handshake(&node_a.federation_url, &a_to_b)?;
    realnet_step(
        "trusted link admitted A->B",
        format!(
            "local={} peer={} accepted={} capabilities={:?}",
            node_a.node_id,
            node_b.node_id,
            admitted_ab.accepted,
            admitted_ab.negotiated_capabilities
        ),
    );
    assert!(admitted_ab.accepted);
    assert!(admitted_ab.negotiated_capabilities.contains(&"opaque_delivery".to_owned()));

    realnet_step(
        "establish trusted links invitation B->A",
        format!(
            "node=node-b local={} peer={} url={} peer_mesh={} peer_ca={}",
            node_b.node_id,
            node_a.node_id,
            node_b.federation_url,
            node_a.federation_mesh_endpoint,
            node_a.ca_cert.display()
        ),
    );
    let mut b_to_a = mvp8_handshake_request(
        &node_a.node_id,
        "fh_s8_b_to_a",
        &["opaque_delivery", "federation_relay"],
        Some(mvp8_invitation_with_ca(
            "inv_s8_b_to_a",
            &node_a.node_id,
            &["opaque_delivery", "federation_relay"],
            invitation_expires_at,
            std::fs::read_to_string(&node_a.ca_cert)?,
        )?),
        now,
    )?;
    b_to_a.route.endpoint.clone_from(&node_a.federation_mesh_endpoint);
    let admitted_ba = mvp8_post_handshake(&node_b.federation_url, &b_to_a)?;
    realnet_step(
        "trusted link admitted B->A",
        format!(
            "local={} peer={} accepted={} capabilities={:?}",
            node_b.node_id,
            node_a.node_id,
            admitted_ba.accepted,
            admitted_ba.negotiated_capabilities
        ),
    );
    assert!(admitted_ba.accepted);
    assert!(admitted_ba.negotiated_capabilities.contains(&"opaque_delivery".to_owned()));
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s12_assert_discovery_pinning_rf_dm(
    node_a: &S8RealnetNode,
    node_b: &S8RealnetNode,
    _ca_cert: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    realnet_step(
        "begin S12 discovery pinning flow",
        format!("resolver={} target={}", node_a.node_id, node_b.node_id),
    );
    mvp_s12_establish_discovered_trusted_links(node_a, node_b)?;
    realnet_step(
        "verify S12 pin hijack rejection",
        format!("resolver={} target={}", node_a.node_id, node_b.node_id),
    );
    mvp_s12_assert_pin_hijack_rejected(node_a, node_b)?;
    assert_s12_mesh_quic_listener_ready(node_a)?;
    assert_s12_mesh_quic_listener_ready(node_b)?;
    let node_b_mesh_before_dm = s12_mesh_observability(node_b)?;
    Box::pin(mvp_s8_assert_cross_node_rf_dm_after_trust(node_a, node_b)).await?;
    let node_b_mesh_after_dm = s12_mesh_observability(node_b)?;
    assert_s12_quic_inbound_delta(&node_b_mesh_before_dm, &node_b_mesh_after_dm);
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
#[derive(serde::Deserialize)]
struct S12MeshObservabilitySnapshot {
    quic_listener_ready: bool,
    quic_listener_local_addr: Option<String>,
    quic_listener_last_error: Option<String>,
    tcp_inbound_s8_envelopes: u64,
    quic_inbound_s8_envelopes: u64,
}

#[cfg(all(test, feature = "realnet"))]
fn s12_mesh_observability(
    node: &S8RealnetNode,
) -> Result<S12MeshObservabilitySnapshot, Box<dyn std::error::Error>> {
    Ok(ramflux_node_core::itest_http_get_json(&format!(
        "{}/s8/federation/mesh-observability",
        node.federation_url
    ))?)
}

#[cfg(all(test, feature = "realnet"))]
fn assert_s12_mesh_quic_listener_ready(
    node: &S8RealnetNode,
) -> Result<(), Box<dyn std::error::Error>> {
    let snapshot = s12_mesh_observability(node)?;
    assert!(
        snapshot.quic_listener_ready,
        "node {} expected S12 mesh QUIC listener ready, addr={:?}, error={:?}",
        node.node_id, snapshot.quic_listener_local_addr, snapshot.quic_listener_last_error
    );
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
fn assert_s12_quic_inbound_delta(
    before: &S12MeshObservabilitySnapshot,
    after: &S12MeshObservabilitySnapshot,
) {
    let quic_delta =
        after.quic_inbound_s8_envelopes.saturating_sub(before.quic_inbound_s8_envelopes);
    let tcp_delta = after.tcp_inbound_s8_envelopes.saturating_sub(before.tcp_inbound_s8_envelopes);
    assert!(quic_delta >= 1, "expected S12 QUIC mesh inbound envelope, got delta={quic_delta}");
    assert_eq!(tcp_delta, 0, "expected S12 no TCP mesh inbound envelopes during QUIC path");
}

#[cfg(all(test, feature = "realnet"))]
#[allow(clippy::too_many_lines)]
pub(crate) fn mvp_s12_establish_discovered_trusted_links(
    node_a: &S8RealnetNode,
    node_b: &S8RealnetNode,
) -> Result<(), Box<dyn std::error::Error>> {
    let now = realnet_now_i64();
    let invitation_expires_at = now.saturating_add(86_400);
    realnet_step(
        "A fetch node-b well-known",
        format!(
            "resolver={} target={} url={}/.well-known/ramflux/server",
            node_a.node_id, node_b.node_id, node_b.federation_well_known_base
        ),
    );
    let discovered_b = mvp_s12_discover_well_known(node_a, node_b)?;
    realnet_step(
        "A verified and pinned node-b well-known",
        format!(
            "resolver={} target={} endpoint={} key={} ca_len={}",
            node_a.node_id,
            discovered_b.node_id,
            discovered_b.node_endpoint,
            discovered_b.node_public_key,
            discovered_b.node_ca_cert_pem.len()
        ),
    );
    assert_eq!(discovered_b.source, ramflux_node_core::FederationDiscoverySource::WellKnown);
    assert_eq!(discovered_b.pin_state, ramflux_node_core::FederationPinState::Pinned);
    assert_eq!(discovered_b.node_endpoint, node_b.federation_mesh_endpoint);
    assert_eq!(discovered_b.node_public_key, node_b.federation_node_public_key);
    realnet_step(
        "A read node-b discovery pin",
        format!("url={}/s12/federation/discovery/pin/{}", node_a.federation_url, node_b.node_id),
    );
    let pin_b: Option<ramflux_node_core::FederationNodePin> =
        ramflux_node_core::itest_http_get_json(&format!(
            "{}/s12/federation/discovery/pin/{}",
            node_a.federation_url, node_b.node_id
        ))?;
    assert_eq!(
        pin_b.as_ref().map(|pin| pin.pinned_node_public_key.as_str()),
        Some(discovered_b.node_public_key.as_str())
    );

    realnet_step(
        "A admit discovered B",
        format!(
            "local={} peer={} endpoint={} ca={}",
            node_a.node_id,
            node_b.node_id,
            discovered_b.node_endpoint,
            node_b.ca_cert.display()
        ),
    );
    let mut a_to_b = mvp8_handshake_request(
        &node_b.node_id,
        "fh_s12_a_to_b",
        &["opaque_delivery", "federation_relay"],
        Some(mvp8_invitation_with_ca(
            "inv_s12_a_to_b",
            &node_b.node_id,
            &["opaque_delivery", "federation_relay"],
            invitation_expires_at,
            std::fs::read_to_string(&node_b.ca_cert)?,
        )?),
        now,
    )?;
    a_to_b.route.endpoint = discovered_b.node_endpoint;
    let admitted_ab = mvp8_post_handshake(&node_a.federation_url, &a_to_b)?;
    realnet_step(
        "A admitted discovered B",
        format!(
            "local={} peer={} accepted={}",
            node_a.node_id, node_b.node_id, admitted_ab.accepted
        ),
    );
    assert!(admitted_ab.accepted);

    realnet_step(
        "B fetch node-a well-known",
        format!(
            "resolver={} target={} url={}/.well-known/ramflux/server",
            node_b.node_id, node_a.node_id, node_a.federation_well_known_base
        ),
    );
    let discovered_a = mvp_s12_discover_well_known(node_b, node_a)?;
    realnet_step(
        "B verified and pinned node-a well-known",
        format!(
            "resolver={} target={} endpoint={} key={} ca_len={}",
            node_b.node_id,
            discovered_a.node_id,
            discovered_a.node_endpoint,
            discovered_a.node_public_key,
            discovered_a.node_ca_cert_pem.len()
        ),
    );
    assert_eq!(discovered_a.source, ramflux_node_core::FederationDiscoverySource::WellKnown);
    assert_eq!(discovered_a.node_endpoint, node_a.federation_mesh_endpoint);
    realnet_step(
        "B admit discovered A",
        format!(
            "local={} peer={} endpoint={} ca={}",
            node_b.node_id,
            node_a.node_id,
            discovered_a.node_endpoint,
            node_a.ca_cert.display()
        ),
    );
    let mut b_to_a = mvp8_handshake_request(
        &node_a.node_id,
        "fh_s12_b_to_a",
        &["opaque_delivery", "federation_relay"],
        Some(mvp8_invitation_with_ca(
            "inv_s12_b_to_a",
            &node_a.node_id,
            &["opaque_delivery", "federation_relay"],
            invitation_expires_at,
            std::fs::read_to_string(&node_a.ca_cert)?,
        )?),
        now,
    )?;
    b_to_a.route.endpoint = discovered_a.node_endpoint;
    let admitted_ba = mvp8_post_handshake(&node_b.federation_url, &b_to_a)?;
    realnet_step(
        "B admitted discovered A",
        format!(
            "local={} peer={} accepted={}",
            node_b.node_id, node_a.node_id, admitted_ba.accepted
        ),
    );
    assert!(admitted_ba.accepted);
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp_s12_discover_well_known(
    resolver_node: &S8RealnetNode,
    target_node: &S8RealnetNode,
) -> Result<ramflux_node_core::FederationDiscoveryResult, Box<dyn std::error::Error>> {
    realnet_step(
        "POST federation discovery resolve",
        format!(
            "resolver={} resolver_url={} target={} well_known_url={}/.well-known/ramflux/server",
            resolver_node.node_id,
            resolver_node.federation_url,
            target_node.node_id,
            target_node.federation_well_known_base
        ),
    );
    Ok(ramflux_node_core::itest_http_post_json(
        &format!("{}/s12/federation/discovery/resolve", resolver_node.federation_url),
        &serde_json::json!({
            "request": {
                "node_id": target_node.node_id,
                "now": realnet_now_u64(),
                "well_known_url": format!("{}/.well-known/ramflux/server", target_node.federation_well_known_base),
                "dns_srv_records": [{
                    "priority": 10_u16,
                    "weight": 10_u16,
                    "target": "unused-srv.example",
                    "port": 443_u16
                }],
                "address_records": ["203.0.113.9"],
                "directory_endpoint": "directory-cache.invalid:443"
            }
        }),
    )?)
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp_s12_assert_pin_hijack_rejected(
    resolver_node: &S8RealnetNode,
    target_node: &S8RealnetNode,
) -> Result<(), Box<dyn std::error::Error>> {
    realnet_step(
        "fetch real well-known before forged pin test",
        format!(
            "target={} url={}/.well-known/ramflux/server",
            target_node.node_id, target_node.federation_url
        ),
    );
    let mut forged: ramflux_node_core::FederationServerRecord =
        ramflux_node_core::itest_http_get_json(&format!(
            "{}/.well-known/ramflux/server",
            target_node.federation_url
        ))?;
    let forged_seed = [0x5c; 32];
    forged.node_public_key = ramflux_crypto::public_key_base64url_from_seed(forged_seed);
    ramflux_node_core::sign_federation_server_record_with_seed(&mut forged, forged_seed)?;
    realnet_step(
        "POST forged well-known discovery resolve",
        format!(
            "resolver={} target={} url={}",
            resolver_node.node_id, target_node.node_id, resolver_node.federation_url
        ),
    );
    let rejected = ramflux_node_core::itest_http_post_json::<_, serde_json::Value>(
        &format!("{}/s12/federation/discovery/resolve", resolver_node.federation_url),
        &serde_json::json!({
            "request": {
                "node_id": target_node.node_id,
                "now": realnet_now_u64(),
                "well_known_url": format!("{}/.well-known/ramflux/server", target_node.federation_well_known_base)
            },
            "well_known_record": forged
        }),
    );
    let Err(error) = rejected else {
        return Err("forged well-known key unexpectedly replaced the existing pin".into());
    };
    let message = error.to_string();
    assert!(message.contains("key pin mismatch"), "{message}");
    Ok(())
}
