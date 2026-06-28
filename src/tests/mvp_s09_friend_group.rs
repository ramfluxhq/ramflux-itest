// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use super::*;

#[cfg(feature = "realnet")]
#[test]
fn mvp_s9_realnet_cross_node_friend_rf_request_accept() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    let node_a = start_s8_realnet_compose_project(
        "ramflux-s9-node-a",
        S8ComposePorts {
            gateway_http: 38_181,
            gateway_quic: 38_451,
            router_http: 38_180,
            router_mesh: 37_451,
            notify_http: 38_183,
            federation_http: 38_182,
            federation_mesh: 38_452,
            relay_http: 38_184,
            relay_media_udp: 39_100,
            signaling_turn_udp: 33_478,
            signaling_turn_tcp: 33_479,
            retention_http: 38_187,
        },
    )?;
    let node_b = start_s8_realnet_compose_project(
        "ramflux-s9-node-b",
        S8ComposePorts {
            gateway_http: 48_181,
            gateway_quic: 48_451,
            router_http: 48_180,
            router_mesh: 47_451,
            notify_http: 48_183,
            federation_http: 48_182,
            federation_mesh: 48_452,
            relay_http: 48_184,
            relay_media_udp: 49_100,
            signaling_turn_udp: 43_478,
            signaling_turn_tcp: 43_479,
            retention_http: 48_187,
        },
    )?;
    let code_root = code_root();
    let ca_cert = code_root.join("ramflux-deploy/certs/ca.pem");
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async {
        realnet_step(
            "TEST s9 wait node-a gateway QUIC",
            format!("node={} quic={}", node_a.node_id, node_a.gateway_quic_addr),
        );
        wait_for_private_gateway_quic(node_a.gateway_quic_addr, &node_a.ca_cert).await?;
        realnet_step(
            "TEST s9 wait node-b gateway QUIC",
            format!("node={} quic={}", node_b.node_id, node_b.gateway_quic_addr),
        );
        wait_for_private_gateway_quic(node_b.gateway_quic_addr, &node_b.ca_cert).await?;
        Box::pin(mvp_s9_assert_cross_node_friend_rf(&node_a, &node_b, &ca_cert)).await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    drop(node_b);
    drop(node_a);
    Ok(())
}

#[cfg(feature = "realnet")]
#[test]
fn mvp_s9_realnet_group_receive_idempotent() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    let realnet = start_realnet_compose()?;
    let code_root = code_root();
    let ca_cert = code_root.join("ramflux-deploy/certs/ca.pem");
    let gateway_quic_addr: std::net::SocketAddr = std::env::var("RAMFLUX_ITEST_GATEWAY_QUIC_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:18443".to_owned())
        .parse()?;
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async {
        Box::pin(mvp_s9_assert_group_receive_idempotent(
            gateway_quic_addr,
            &ca_cert,
            &realnet.gateway_url,
        ))
        .await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    drop(realnet);
    Ok(())
}
