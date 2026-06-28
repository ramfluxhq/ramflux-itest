// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use super::*;

#[cfg(feature = "realnet")]
#[test]
fn mvp_s22_realnet_prod_federation_peer_cross_node_dm() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    let node_a = start_s22_production_node(
        "ramflux-s22-prod-node-a",
        "node_a.realnet",
        S22ProductionPorts {
            gateway: 64_143,
            federation_admin: 64_182,
            federation_mesh: 64_452,
            signaling_turn_udp: 65_478,
            signaling_turn_tcp: 65_479,
        },
    )?;
    let node_b = start_s22_production_node(
        "ramflux-s22-prod-node-b",
        "node_b.realnet",
        S22ProductionPorts {
            gateway: 65_143,
            federation_admin: 65_182,
            federation_mesh: 65_452,
            signaling_turn_udp: 62_478,
            signaling_turn_tcp: 62_479,
        },
    )?;
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async {
        Box::pin(mvp_s22_assert_prod_peer_cross_node_dm(&node_a, &node_b)).await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    drop(node_b);
    drop(node_a);
    Ok(())
}

#[cfg(feature = "realnet")]
#[test]
fn mvp_s22_realnet_federation_node_restart_keeps_peer_pin() -> Result<(), Box<dyn std::error::Error>>
{
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    let node_a = start_s22_production_node(
        "ramflux-s22-restart-node-a",
        "node_a.realnet",
        S22ProductionPorts {
            gateway: 60_143,
            federation_admin: 60_182,
            federation_mesh: 60_452,
            signaling_turn_udp: 60_478,
            signaling_turn_tcp: 60_479,
        },
    )?;
    let node_b = start_s22_production_node(
        "ramflux-s22-restart-node-b",
        "node_b.realnet",
        S22ProductionPorts {
            gateway: 61_143,
            federation_admin: 61_182,
            federation_mesh: 61_452,
            signaling_turn_udp: 61_478,
            signaling_turn_tcp: 61_479,
        },
    )?;
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async {
        Box::pin(mvp_s22_assert_prod_peer_cross_node_dm_after_federation_restart(&node_a, &node_b))
            .await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    drop(node_b);
    drop(node_a);
    Ok(())
}
