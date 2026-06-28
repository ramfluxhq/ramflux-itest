// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use super::*;

#[cfg(feature = "realnet")]
#[test]
fn mvp_s24_realnet_group_out_of_order_key() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    let node_a = start_s22_production_node(
        "ramflux-s24-prod-node-a",
        "node_a.realnet",
        S22ProductionPorts {
            gateway: 52_143,
            federation_admin: 52_182,
            federation_mesh: 52_452,
            signaling_turn_udp: 52_478,
            signaling_turn_tcp: 52_479,
        },
    )?;
    let node_b = start_s22_production_node(
        "ramflux-s24-prod-node-b",
        "node_b.realnet",
        S22ProductionPorts {
            gateway: 53_143,
            federation_admin: 53_182,
            federation_mesh: 53_452,
            signaling_turn_udp: 53_478,
            signaling_turn_tcp: 53_479,
        },
    )?;
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async {
        Box::pin(mvp_s24_assert_group_out_of_order_key(&node_a, &node_b)).await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    drop(node_b);
    drop(node_a);
    Ok(())
}
