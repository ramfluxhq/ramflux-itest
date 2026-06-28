// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use super::*;

#[cfg(feature = "realnet")]
#[test]
fn mvp_s12_realnet_federation_discovery_well_known_pinning_rf_dm()
-> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    realnet_step("TEST s12 start", "mvp_s12_realnet_federation_discovery_well_known_pinning_rf_dm");
    let node_a = start_s8_realnet_compose_project(
        "ramflux-s12-node-a",
        S8ComposePorts {
            gateway_http: 58_181,
            gateway_quic: 58_451,
            router_http: 58_180,
            router_mesh: 57_451,
            notify_http: 58_183,
            federation_http: 58_182,
            federation_mesh: 58_452,
            relay_http: 58_184,
            relay_media_udp: 59_100,
            signaling_turn_udp: 55_478,
            signaling_turn_tcp: 55_479,
            retention_http: 58_187,
        },
    )?;
    realnet_step(
        "TEST s12 node-a ready",
        format!(
            "node={} gateway={} federation={}",
            node_a.node_id, node_a.gateway_url, node_a.federation_url
        ),
    );
    let node_b = start_s8_realnet_compose_project(
        "ramflux-s12-node-b",
        S8ComposePorts {
            gateway_http: 63_181,
            gateway_quic: 63_451,
            router_http: 63_180,
            router_mesh: 62_451,
            notify_http: 63_183,
            federation_http: 63_182,
            federation_mesh: 63_452,
            relay_http: 63_184,
            relay_media_udp: 64_100,
            signaling_turn_udp: 61_478,
            signaling_turn_tcp: 61_479,
            retention_http: 63_187,
        },
    )?;
    realnet_step(
        "TEST s12 node-b ready",
        format!(
            "node={} gateway={} federation={}",
            node_b.node_id, node_b.gateway_url, node_b.federation_url
        ),
    );
    let code_root = code_root();
    let ca_cert = code_root.join("ramflux/deploy/certs/ca.pem");
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async {
        realnet_step("TEST s12 enter async federation flow", "well-known discovery path");
        Box::pin(mvp_s12_assert_discovery_pinning_rf_dm(&node_a, &node_b, &ca_cert)).await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    drop(node_b);
    drop(node_a);
    Ok(())
}
