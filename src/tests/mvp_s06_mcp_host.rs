// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use super::*;

#[cfg(feature = "realnet")]
#[test]
fn mvp_s6_realnet_mcp_host_grant_dual_mode() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    let realnet = start_realnet_compose()?;
    let code_root = code_root();
    let ca_cert = code_root.join("ramflux/deploy/certs/ca.pem");
    let gateway_quic_addr: std::net::SocketAddr = std::env::var("RAMFLUX_ITEST_GATEWAY_QUIC_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:18443".to_owned())
        .parse()?;

    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async {
        Box::pin(mvp_s6_assert_rf_mcp_flow(gateway_quic_addr, &ca_cert, &realnet.gateway_url))
            .await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    drop(realnet);
    Ok(())
}

#[cfg(feature = "realnet")]
#[test]
fn mvp_s6_realnet_mcp_grant_persistence_after_daemon_restart()
-> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    let realnet = start_realnet_compose()?;
    let code_root = code_root();
    let ca_cert = code_root.join("ramflux/deploy/certs/ca.pem");
    let gateway_quic_addr: std::net::SocketAddr = std::env::var("RAMFLUX_ITEST_GATEWAY_QUIC_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:18443".to_owned())
        .parse()?;

    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async {
        Box::pin(mvp_s6_assert_mcp_grant_persistence_after_daemon_restart(
            gateway_quic_addr,
            &ca_cert,
        ))
        .await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    drop(realnet);
    Ok(())
}
