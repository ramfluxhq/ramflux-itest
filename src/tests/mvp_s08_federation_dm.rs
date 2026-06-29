// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use super::*;

#[cfg(feature = "realnet")]
#[test]
fn mvp_s8_local_rf_federation_full_chain_no_hang() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    runtime.block_on(async {
        Box::pin(mvp_s8_assert_local_rf_federation_full_chain_no_hang()).await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    Ok(())
}

#[cfg(feature = "realnet")]
#[test]
fn mvp_s8_realnet_federation_cross_node_rf_dm_network_forward()
-> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    run_s8_cross_node_rf_dm_network_forward(
        "mvp_s8_realnet_federation_cross_node_rf_dm_network_forward",
        "default",
        18_000,
        &[],
        ExpectedMeshInboundTransport::Quic,
    )
}

#[cfg(feature = "realnet")]
#[test]
fn mvp_s8_realnet_federation_quic_only_cross_node_rf_dm_network_forward()
-> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    run_s8_cross_node_rf_dm_network_forward(
        "mvp_s8_realnet_federation_quic_only_cross_node_rf_dm_network_forward",
        "quic-only",
        38_000,
        &[("RAMFLUX_FEDERATION_DISABLE_TCP_FALLBACK".to_owned(), "1".to_owned())],
        ExpectedMeshInboundTransport::Quic,
    )
}

#[cfg(feature = "realnet")]
#[test]
fn mvp_s8_realnet_federation_compio_quic_only_cross_node_rf_dm_network_forward()
-> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    if std::env::var("RAMFLUX_FEDERATION_COMPIO").as_deref() != Ok("1") {
        eprintln!("skipping federation compio realnet test; set RAMFLUX_FEDERATION_COMPIO=1");
        return Ok(());
    }

    run_s8_cross_node_rf_dm_network_forward_with_node_env_and_destination_compio(
        "mvp_s8_realnet_federation_compio_quic_only_cross_node_rf_dm_network_forward",
        "compio-quic-only",
        28_000,
        &[],
        &[("RAMFLUX_FEDERATION_DISABLE_TCP_FALLBACK".to_owned(), "1".to_owned())],
        true,
        ExpectedMeshInboundTransport::Quic,
    )
}

#[cfg(feature = "realnet")]
#[test]
fn mvp_s8_realnet_federation_compio_sender_quic_only_cross_node_rf_dm_network_forward()
-> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    if std::env::var("RAMFLUX_FEDERATION_COMPIO").as_deref() != Ok("1") {
        eprintln!("skipping federation compio realnet test; set RAMFLUX_FEDERATION_COMPIO=1");
        return Ok(());
    }

    run_s8_cross_node_rf_dm_network_forward_with_node_env_and_compio(
        "mvp_s8_realnet_federation_compio_sender_quic_only_cross_node_rf_dm_network_forward",
        "compio-sender-quic-only",
        60_000,
        &[("RAMFLUX_FEDERATION_DISABLE_TCP_FALLBACK".to_owned(), "1".to_owned())],
        &[("RAMFLUX_FEDERATION_DISABLE_TCP_FALLBACK".to_owned(), "1".to_owned())],
        true,
        false,
        ExpectedMeshInboundTransport::Quic,
    )
}

#[cfg(feature = "realnet")]
#[test]
fn mvp_s8_realnet_federation_force_tcp_cross_node_rf_dm_network_forward()
-> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    run_s8_cross_node_rf_dm_network_forward(
        "mvp_s8_realnet_federation_force_tcp_cross_node_rf_dm_network_forward",
        "force-tcp",
        48_000,
        &[("RAMFLUX_FEDERATION_FORCE_TCP_MESH".to_owned(), "1".to_owned())],
        ExpectedMeshInboundTransport::Tcp,
    )
}

#[cfg(feature = "realnet")]
#[test]
fn mvp_s8_realnet_federation_quic_down_falls_back_tcp_cross_node_rf_dm_network_forward()
-> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    run_s8_cross_node_rf_dm_network_forward_with_node_env(
        "mvp_s8_realnet_federation_quic_down_falls_back_tcp_cross_node_rf_dm_network_forward",
        "quic-down-fallback",
        58_000,
        &[],
        &[("RAMFLUX_FEDERATION_DISABLE_QUIC_LISTENER".to_owned(), "1".to_owned())],
        ExpectedMeshInboundTransport::Tcp,
    )
}

#[cfg(feature = "realnet")]
#[test]
fn mvp_s26_realnet_federation_offline_peer_spool_retry() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    run_s26_offline_peer_spool_retry()
}

#[cfg(feature = "realnet")]
#[test]
fn mvp_s29_realnet_federation_partition_failover_chaos() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }
    if std::env::var("RAMFLUX_CHAOS").as_deref() != Ok("1") {
        eprintln!("skipping federation partition chaos test; set RAMFLUX_CHAOS=1");
        return Ok(());
    }

    run_s29_partition_failover_chaos()
}

#[cfg(feature = "realnet")]
#[derive(Clone, Copy)]
enum ExpectedMeshInboundTransport {
    Tcp,
    Quic,
}

#[cfg(feature = "realnet")]
#[derive(serde::Deserialize)]
struct MeshObservabilitySnapshot {
    quic_listener_ready: bool,
    quic_listener_local_addr: Option<String>,
    quic_listener_last_error: Option<String>,
    tcp_inbound_s8_envelopes: u64,
    quic_inbound_s8_envelopes: u64,
}

#[cfg(feature = "realnet")]
fn run_s8_cross_node_rf_dm_network_forward(
    test_name: &'static str,
    project_suffix: &'static str,
    port_base: u16,
    extra_env: &[(String, String)],
    expected_transport: ExpectedMeshInboundTransport,
) -> Result<(), Box<dyn std::error::Error>> {
    run_s8_cross_node_rf_dm_network_forward_with_node_env(
        test_name,
        project_suffix,
        port_base,
        extra_env,
        extra_env,
        expected_transport,
    )
}

#[cfg(feature = "realnet")]
fn run_s8_cross_node_rf_dm_network_forward_with_node_env(
    test_name: &'static str,
    project_suffix: &'static str,
    port_base: u16,
    source_env: &[(String, String)],
    destination_env: &[(String, String)],
    expected_transport: ExpectedMeshInboundTransport,
) -> Result<(), Box<dyn std::error::Error>> {
    run_s8_cross_node_rf_dm_network_forward_with_node_env_and_destination_compio(
        test_name,
        project_suffix,
        port_base,
        source_env,
        destination_env,
        false,
        expected_transport,
    )
}

#[cfg(feature = "realnet")]
#[allow(clippy::too_many_arguments)]
fn run_s8_cross_node_rf_dm_network_forward_with_node_env_and_destination_compio(
    test_name: &'static str,
    project_suffix: &'static str,
    port_base: u16,
    source_env: &[(String, String)],
    destination_env: &[(String, String)],
    destination_federation_compio: bool,
    expected_transport: ExpectedMeshInboundTransport,
) -> Result<(), Box<dyn std::error::Error>> {
    run_s8_cross_node_rf_dm_network_forward_with_node_env_and_compio(
        test_name,
        project_suffix,
        port_base,
        source_env,
        destination_env,
        false,
        destination_federation_compio,
        expected_transport,
    )
}

#[cfg(feature = "realnet")]
#[allow(clippy::too_many_arguments)]
fn run_s8_cross_node_rf_dm_network_forward_with_node_env_and_compio(
    test_name: &'static str,
    project_suffix: &'static str,
    port_base: u16,
    source_env: &[(String, String)],
    destination_env: &[(String, String)],
    source_federation_compio: bool,
    destination_federation_compio: bool,
    expected_transport: ExpectedMeshInboundTransport,
) -> Result<(), Box<dyn std::error::Error>> {
    realnet_step("TEST s8 start", test_name);
    let node_a = start_s8_realnet_compose_project_with_env_and_federation_compio(
        &format!("ramflux-s8-node-a-{project_suffix}"),
        S8ComposePorts {
            gateway_http: port_base + 181,
            gateway_quic: port_base + 451,
            router_http: port_base + 180,
            router_mesh: port_base + 452,
            notify_http: port_base + 183,
            federation_http: port_base + 182,
            federation_mesh: port_base + 453,
            relay_http: port_base + 184,
            relay_media_udp: port_base + 100,
            signaling_turn_udp: port_base + 478,
            signaling_turn_tcp: port_base + 479,
            retention_http: port_base + 187,
        },
        source_env,
        source_federation_compio,
    )?;
    realnet_step(
        "TEST s8 node-a ready",
        format!(
            "node={} gateway={} federation={}",
            node_a.node_id, node_a.gateway_url, node_a.federation_url
        ),
    );
    let node_b = start_s8_realnet_compose_project_with_env_and_federation_compio(
        &format!("ramflux-s8-node-b-{project_suffix}"),
        S8ComposePorts {
            gateway_http: port_base + 1_181,
            gateway_quic: port_base + 1_451,
            router_http: port_base + 1_180,
            router_mesh: port_base + 1_452,
            notify_http: port_base + 1_183,
            federation_http: port_base + 1_182,
            federation_mesh: port_base + 1_453,
            relay_http: port_base + 1_184,
            relay_media_udp: port_base + 1_100,
            signaling_turn_udp: port_base + 1_478,
            signaling_turn_tcp: port_base + 1_479,
            retention_http: port_base + 1_187,
        },
        destination_env,
        destination_federation_compio,
    )?;
    realnet_step(
        "TEST s8 node-b ready",
        format!(
            "node={} gateway={} federation={}",
            node_b.node_id, node_b.gateway_url, node_b.federation_url
        ),
    );
    assert_s8_mesh_quic_listener_state(&node_b, expected_transport)?;
    let before_transport = s8_mesh_observability(&node_b)?;
    let code_root = code_root();
    let ca_cert = code_root.join("ramflux/deploy/certs/ca.pem");
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async {
        realnet_step("TEST s8 enter async federation flow", "invitation path");
        Box::pin(mvp_s8_assert_cross_node_rf_dm(&node_a, &node_b, &ca_cert)).await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    let after_transport = s8_mesh_observability(&node_b)?;
    assert_s8_mesh_inbound_transport(&before_transport, &after_transport, expected_transport);
    drop(node_b);
    drop(node_a);
    Ok(())
}

#[cfg(feature = "realnet")]
fn s8_mesh_observability(
    node: &S8RealnetNode,
) -> Result<MeshObservabilitySnapshot, Box<dyn std::error::Error>> {
    Ok(ramflux_node_core::itest_http_get_json(&format!(
        "{}/s8/federation/mesh-observability",
        node.federation_url
    ))?)
}

#[cfg(feature = "realnet")]
fn assert_s8_mesh_quic_listener_state(
    node: &S8RealnetNode,
    expected_transport: ExpectedMeshInboundTransport,
) -> Result<(), Box<dyn std::error::Error>> {
    let snapshot = s8_mesh_observability(node)?;
    match expected_transport {
        ExpectedMeshInboundTransport::Quic => {
            assert!(
                snapshot.quic_listener_ready,
                "node {} expected mesh QUIC listener ready, addr={:?}, error={:?}",
                node.node_id, snapshot.quic_listener_local_addr, snapshot.quic_listener_last_error
            );
        }
        ExpectedMeshInboundTransport::Tcp => {}
    }
    Ok(())
}

#[cfg(feature = "realnet")]
fn assert_s8_mesh_inbound_transport(
    before: &MeshObservabilitySnapshot,
    after: &MeshObservabilitySnapshot,
    expected_transport: ExpectedMeshInboundTransport,
) {
    let tcp_delta = after.tcp_inbound_s8_envelopes.saturating_sub(before.tcp_inbound_s8_envelopes);
    let quic_delta =
        after.quic_inbound_s8_envelopes.saturating_sub(before.quic_inbound_s8_envelopes);
    match expected_transport {
        ExpectedMeshInboundTransport::Tcp => {
            assert!(tcp_delta >= 1, "expected TCP mesh inbound envelope, got delta={tcp_delta}");
            assert_eq!(quic_delta, 0, "expected no QUIC mesh inbound envelopes during TCP path");
        }
        ExpectedMeshInboundTransport::Quic => {
            assert!(quic_delta >= 1, "expected QUIC mesh inbound envelope, got delta={quic_delta}");
            assert_eq!(tcp_delta, 0, "expected no TCP mesh inbound envelopes during QUIC path");
        }
    }
}

#[cfg(feature = "realnet")]
fn run_s26_offline_peer_spool_retry() -> Result<(), Box<dyn std::error::Error>> {
    realnet_step("TEST s26 start", "mvp_s26_realnet_federation_offline_peer_spool_retry");
    let source_env = vec![
        ("RAMFLUX_FEDERATION_SPOOL_RETRY_INTERVAL_SECS".to_owned(), "1".to_owned()),
        ("RAMFLUX_FEDERATION_SPOOL_TTL_SECONDS".to_owned(), "120".to_owned()),
    ];
    let node_a = start_s8_realnet_compose_project_with_env(
        "ramflux-s26-spool-node-a",
        S8ComposePorts {
            gateway_http: 62_181,
            gateway_quic: 62_451,
            router_http: 62_180,
            router_mesh: 62_452,
            notify_http: 62_183,
            federation_http: 62_182,
            federation_mesh: 62_453,
            relay_http: 62_184,
            relay_media_udp: 62_100,
            signaling_turn_udp: 62_478,
            signaling_turn_tcp: 62_479,
            retention_http: 62_187,
        },
        &source_env,
    )?;
    let node_b = start_s8_realnet_compose_project(
        "ramflux-s26-spool-node-b",
        S8ComposePorts {
            gateway_http: 63_181,
            gateway_quic: 63_451,
            router_http: 63_180,
            router_mesh: 63_452,
            notify_http: 63_183,
            federation_http: 63_182,
            federation_mesh: 63_453,
            relay_http: 63_184,
            relay_media_udp: 63_100,
            signaling_turn_udp: 63_478,
            signaling_turn_tcp: 63_479,
            retention_http: 63_187,
        },
    )?;
    mvp_s8_establish_trusted_links(&node_a, &node_b)?;
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async {
        run_s26_offline_peer_spool_retry_flow(&node_a, &node_b).await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    drop(node_b);
    drop(node_a);
    Ok(())
}

#[cfg(feature = "realnet")]
#[allow(clippy::too_many_lines)]
async fn run_s26_offline_peer_spool_retry_flow(
    node_a: &S8RealnetNode,
    node_b: &S8RealnetNode,
) -> Result<(), Box<dyn std::error::Error>> {
    let temp_root = temp_root("s26_federation_spool")?;
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
            let alice_ca_cert_arg = mvp_s4_path_arg(&node_a.ca_cert);
            let bob_ca_cert_arg = mvp_s4_path_arg(&node_b.ca_cert);
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
            let bob_commitment = mvp_s8_create_rf_account(
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
            mvp_s8_accept_local_friend_projection(&rf_binary, &alice_socket_arg, &bob_socket_arg)
                .await?;
            stop_s8_federation_service(node_b)?;
            let plaintext = b"s26 offline federation spool plaintext";
            let submitted = mvp_s4_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &alice_socket_arg,
                    "dm",
                    "send",
                    "--account",
                    "alice_s8_account",
                    "--conversation",
                    "conv_s26_spool",
                    "--message",
                    "msg_s26_spooled",
                    "--envelope",
                    "env_s26_spooled_dm_1",
                    "--source-principal",
                    "principal_s8_alice",
                    "--sender",
                    "alice_s8",
                    "--recipient-principal-commitment",
                    bob_commitment.as_str(),
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
            assert_eq!(
                submitted["delivery"]["outcome"].as_str(),
                Some("federation_spooled_offline_peer")
            );
            restart_s8_federation_service(node_b)?;
            wait_for_s26_spooled_dm(&rf_binary, &bob_socket_arg, plaintext).await?;
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

#[cfg(feature = "realnet")]
fn stop_s8_federation_service(node: &S8RealnetNode) -> Result<(), Box<dyn std::error::Error>> {
    realnet_step(
        "stop S26 peer federation",
        format!("project={} node={}", node.guard.project_name, node.node_id),
    );
    run_docker_compose_project_with_options(
        &node.guard.deploy_root,
        &node.guard.project_name,
        &node.guard.env,
        &["stop", "ramflux-federation"],
        node.guard.federation_compio,
    )
}

#[cfg(feature = "realnet")]
fn restart_s8_federation_service(node: &S8RealnetNode) -> Result<(), Box<dyn std::error::Error>> {
    realnet_step(
        "restart S26 peer federation",
        format!("project={} node={}", node.guard.project_name, node.node_id),
    );
    run_docker_compose_project_with_options(
        &node.guard.deploy_root,
        &node.guard.project_name,
        &node.guard.env,
        &["start", "ramflux-federation"],
        node.guard.federation_compio,
    )?;
    wait_for_federation(&node.federation_url)
}

#[cfg(feature = "realnet")]
async fn wait_for_s26_spooled_dm(
    rf_binary: &Path,
    bob_socket: &str,
    plaintext: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(45);
    let mut last_error: Option<Box<dyn std::error::Error>> = None;
    while std::time::Instant::now() < deadline {
        match mvp_s4_rf_json(
            rf_binary,
            &[
                "--socket",
                bob_socket,
                "dm",
                "read",
                "--account",
                "bob_s8_account",
                "--conversation",
                "conv_s26_spool",
            ],
        )
        .await
        {
            Ok(bob_read) => {
                if s26_read_contains_spooled_dm(&bob_read, plaintext)? {
                    return Ok(());
                }
            }
            Err(error) => {
                last_error = Some(error);
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    Err(last_error.unwrap_or_else(|| "S26 spooled DM was not delivered after peer restart".into()))
}

#[cfg(feature = "realnet")]
fn s26_read_contains_spooled_dm(
    bob_read: &serde_json::Value,
    plaintext: &[u8],
) -> Result<bool, Box<dyn std::error::Error>> {
    let Some(entries) = bob_read["gateway_entries"].as_array() else {
        return Ok(false);
    };
    let delivered = entries
        .iter()
        .any(|entry| entry["envelope"]["envelope_id"].as_str() == Some("env_s26_spooled_dm_1"));
    if !delivered {
        return Ok(false);
    }
    let Some(decrypted) = bob_read["decrypted_messages"].as_array() else {
        return Ok(false);
    };
    for message in decrypted {
        if message["message_id"].as_str() == Some("env_s26_spooled_dm_1") {
            let decoded = ramflux_protocol::decode_base64url(
                message["plaintext_body_base64"].as_str().ok_or("missing S26 plaintext")?,
            )?;
            return Ok(decoded == plaintext);
        }
    }
    Ok(false)
}

#[cfg(feature = "realnet")]
fn run_s29_partition_failover_chaos() -> Result<(), Box<dyn std::error::Error>> {
    realnet_step("TEST s29 start", "mvp_s29_realnet_federation_partition_failover_chaos");
    let source_env = vec![
        ("RAMFLUX_FEDERATION_SPOOL_RETRY_INTERVAL_SECS".to_owned(), "1".to_owned()),
        ("RAMFLUX_FEDERATION_SPOOL_TTL_SECONDS".to_owned(), "300".to_owned()),
    ];
    let node_a = start_s8_realnet_compose_project_with_env(
        "ramflux-s29-chaos-node-a",
        S8ComposePorts {
            gateway_http: 54_181,
            gateway_quic: 54_451,
            router_http: 54_180,
            router_mesh: 54_452,
            notify_http: 54_183,
            federation_http: 54_182,
            federation_mesh: 54_453,
            relay_http: 54_184,
            relay_media_udp: 54_100,
            signaling_turn_udp: 54_478,
            signaling_turn_tcp: 54_479,
            retention_http: 54_187,
        },
        &source_env,
    )?;
    let node_b = start_s8_realnet_compose_project(
        "ramflux-s29-chaos-node-b",
        S8ComposePorts {
            gateway_http: 55_181,
            gateway_quic: 55_451,
            router_http: 55_180,
            router_mesh: 55_452,
            notify_http: 55_183,
            federation_http: 55_182,
            federation_mesh: 55_453,
            relay_http: 55_184,
            relay_media_udp: 55_100,
            signaling_turn_udp: 55_478,
            signaling_turn_tcp: 55_479,
            retention_http: 55_187,
        },
    )?;
    mvp_s8_establish_trusted_links(&node_a, &node_b)?;
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async {
        run_s29_partition_failover_chaos_flow(&node_a, &node_b).await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    drop(node_b);
    drop(node_a);
    Ok(())
}

#[cfg(feature = "realnet")]
async fn run_s29_partition_failover_chaos_flow(
    node_a: &S8RealnetNode,
    node_b: &S8RealnetNode,
) -> Result<(), Box<dyn std::error::Error>> {
    let temp_root = temp_root("s29_federation_partition")?;
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
            let bob_commitment =
                s29_create_accounts(&rf_binary, node_a, node_b, &alice_socket_arg, &bob_socket_arg)
                    .await?;
            mvp_s8_accept_local_friend_projection(&rf_binary, &alice_socket_arg, &bob_socket_arg)
                .await?;
            let batch1 = s29_envelope_ids("batch1", 20);
            let batch2 = s29_envelope_ids("batch2", 20);
            s29_send_batch(
                &rf_binary,
                &alice_socket_arg,
                &bob_commitment,
                node_a,
                node_b,
                &batch1,
                None,
            )
            .await?;
            wait_for_s29_delivered_envelopes(&rf_binary, &bob_socket_arg, &batch1, 45).await?;
            let mut partition = S29FederationPartitionGuard::disconnect(node_b)?;
            s29_send_batch(
                &rf_binary,
                &alice_socket_arg,
                &bob_commitment,
                node_a,
                node_b,
                &batch2,
                Some("federation_spooled_offline_peer"),
            )
            .await?;
            assert_s29_batch_absent(&rf_binary, &bob_socket_arg, &batch2).await?;
            restart_s8_federation_service(node_b)?;
            partition.reconnect()?;
            let mut expected = batch1;
            expected.extend(batch2);
            wait_for_s29_delivered_envelopes(&rf_binary, &bob_socket_arg, &expected, 90).await?;
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

#[cfg(feature = "realnet")]
async fn s29_create_accounts(
    rf_binary: &Path,
    node_a: &S8RealnetNode,
    node_b: &S8RealnetNode,
    alice_socket: &str,
    bob_socket: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let alice_ca_cert = mvp_s4_path_arg(&node_a.ca_cert);
    let bob_ca_cert = mvp_s4_path_arg(&node_b.ca_cert);
    mvp_s8_create_rf_account(
        rf_binary,
        alice_socket,
        "alice_s8_account",
        "principal_s8_alice",
        "alice_device_s8",
        "target_s8_alice",
        &node_a.gateway_quic_addr.to_string(),
        &node_a.gateway_url,
        &alice_ca_cert,
        "29",
        "2a",
    )
    .await?;
    let bob_commitment = mvp_s8_create_rf_account(
        rf_binary,
        bob_socket,
        "bob_s8_account",
        "principal_s8_bob",
        "bob_device_s8",
        "target_s8_bob",
        &node_b.gateway_quic_addr.to_string(),
        &node_b.gateway_url,
        &bob_ca_cert,
        "2b",
        "2c",
    )
    .await?;
    Ok(bob_commitment)
}

#[cfg(feature = "realnet")]
fn s29_envelope_ids(batch: &str, count: usize) -> Vec<String> {
    (0..count).map(|index| format!("env_s29_{batch}_{index:02}")).collect()
}

#[cfg(feature = "realnet")]
async fn s29_send_batch(
    rf_binary: &Path,
    alice_socket: &str,
    bob_commitment: &str,
    node_a: &S8RealnetNode,
    node_b: &S8RealnetNode,
    envelope_ids: &[String],
    expected_outcome: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    for (index, envelope_id) in envelope_ids.iter().enumerate() {
        let body = format!("s29 partition chaos plaintext {envelope_id}");
        let message_id = format!("msg_s29_{index:02}_{envelope_id}");
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
                "conv_s29_partition",
                "--message",
                &message_id,
                "--envelope",
                envelope_id,
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
                &body,
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
        assert_eq!(submitted["accepted"], true, "S29 send not accepted: {submitted}");
        if let Some(outcome) = expected_outcome {
            assert_eq!(
                submitted["delivery"]["outcome"].as_str(),
                Some(outcome),
                "unexpected S29 delivery outcome for {envelope_id}: {submitted}"
            );
        }
    }
    Ok(())
}

#[cfg(feature = "realnet")]
async fn assert_s29_batch_absent(
    rf_binary: &Path,
    bob_socket: &str,
    envelope_ids: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    let read = s29_read_bob_dm(rf_binary, bob_socket).await?;
    let delivered = s29_delivered_envelope_ids(&read);
    for envelope_id in envelope_ids {
        assert!(
            !delivered.contains(envelope_id),
            "S29 partitioned peer unexpectedly received {envelope_id}: {delivered:?}"
        );
    }
    Ok(())
}

#[cfg(feature = "realnet")]
async fn wait_for_s29_delivered_envelopes(
    rf_binary: &Path,
    bob_socket: &str,
    expected: &[String],
    timeout_secs: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    let mut last_delivered = Vec::new();
    while std::time::Instant::now() < deadline {
        if let Ok(read) = s29_read_bob_dm(rf_binary, bob_socket).await {
            last_delivered = s29_delivered_envelope_ids(&read);
            if s29_contains_all(&last_delivered, expected) {
                assert_s29_exactly_once_and_ordered(&last_delivered, expected);
                return Ok(());
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    Err(format!(
        "S29 expected envelopes not delivered before timeout; expected={expected:?} delivered={last_delivered:?}"
    )
    .into())
}

#[cfg(feature = "realnet")]
async fn s29_read_bob_dm(
    rf_binary: &Path,
    bob_socket: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    mvp_s4_rf_json(
        rf_binary,
        &[
            "--socket",
            bob_socket,
            "dm",
            "read",
            "--account",
            "bob_s8_account",
            "--conversation",
            "conv_s29_partition",
        ],
    )
    .await
}

#[cfg(feature = "realnet")]
fn s29_delivered_envelope_ids(read: &serde_json::Value) -> Vec<String> {
    read["gateway_entries"].as_array().map_or_else(Vec::new, |entries| {
        entries
            .iter()
            .filter_map(|entry| entry["envelope"]["envelope_id"].as_str().map(str::to_owned))
            .collect()
    })
}

#[cfg(feature = "realnet")]
fn s29_contains_all(delivered: &[String], expected: &[String]) -> bool {
    expected.iter().all(|envelope_id| delivered.contains(envelope_id))
}

#[cfg(feature = "realnet")]
fn assert_s29_exactly_once_and_ordered(delivered: &[String], expected: &[String]) {
    let filtered: Vec<&String> = delivered.iter().filter(|id| expected.contains(id)).collect();
    let expected_refs: Vec<&String> = expected.iter().collect();
    assert_eq!(
        filtered, expected_refs,
        "S29 delivered envelopes were not strictly ordered; delivered={delivered:?}"
    );
    for envelope_id in expected {
        let count = delivered.iter().filter(|id| *id == envelope_id).count();
        assert_eq!(
            count, 1,
            "S29 expected exactly-once delivery for {envelope_id}, count={count}, delivered={delivered:?}"
        );
    }
}

#[cfg(feature = "realnet")]
struct S29FederationPartitionGuard {
    network: String,
    container: String,
    alias: String,
    connected: bool,
}

#[cfg(feature = "realnet")]
impl S29FederationPartitionGuard {
    fn disconnect(node: &S8RealnetNode) -> Result<Self, Box<dyn std::error::Error>> {
        let network = std::env::var("RAMFLUX_ITEST_SHARED_NETWORK")
            .unwrap_or_else(|_| "ramflux-itest-mesh".to_owned());
        let container = s29_find_federation_container(&node.guard.project_name)?;
        let alias = federation_dns_alias(&node.guard.project_name);
        realnet_step(
            "S29 partition node-b federation",
            format!("project={} network={network} container={container}", node.guard.project_name),
        );
        s29_run_container_runtime(&["network", "disconnect", &network, &container])?;
        Ok(Self { network, container, alias, connected: false })
    }

    fn reconnect(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self.connected {
            return Ok(());
        }
        realnet_step(
            "S29 heal node-b federation partition",
            format!("network={} container={} alias={}", self.network, self.container, self.alias),
        );
        s29_connect_container_to_network(&self.network, &self.container, &self.alias)?;
        self.connected = true;
        Ok(())
    }
}

#[cfg(feature = "realnet")]
impl Drop for S29FederationPartitionGuard {
    fn drop(&mut self) {
        if !self.connected {
            let _ = s29_connect_container_to_network(&self.network, &self.container, &self.alias);
        }
    }
}

#[cfg(feature = "realnet")]
fn s29_connect_container_to_network(
    network: &str,
    container: &str,
    alias: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    s29_run_container_runtime(&["network", "connect", "--alias", alias, network, container])
}

#[cfg(feature = "realnet")]
fn s29_find_federation_container(project_name: &str) -> Result<String, Box<dyn std::error::Error>> {
    for runtime in ["podman", "docker"] {
        let output =
            std::process::Command::new(runtime).args(["ps", "--format", "{{.Names}}"]).output();
        let Ok(output) = output else {
            continue;
        };
        if !output.status.success() {
            continue;
        }
        let names = String::from_utf8(output.stdout)?;
        if let Some(name) = names.lines().find(|name| {
            name.contains(project_name)
                && (name.contains("ramflux-federation") || name.contains("federation"))
        }) {
            return Ok(name.to_owned());
        }
    }
    Err(format!("could not find federation container for project {project_name}").into())
}

#[cfg(feature = "realnet")]
fn s29_run_container_runtime(args: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    let mut last_error = String::new();
    for runtime in ["podman", "docker"] {
        let status = std::process::Command::new(runtime).args(args).status();
        match status {
            Ok(status) if status.success() => return Ok(()),
            Ok(status) => {
                last_error = format!("{runtime} {args:?} failed with {status}");
            }
            Err(error) => {
                last_error = format!("{runtime} {args:?} failed: {error}");
            }
        }
    }
    Err(last_error.into())
}
