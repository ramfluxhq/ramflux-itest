// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use super::*;

#[cfg(feature = "realnet")]
#[test]
fn mvp_s1_realnet_gateway_session_quic_lifecycle_resume_preauth()
-> Result<(), Box<dyn std::error::Error>> {
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

    mvp_s1_enable_gateway_preauth(&realnet.gateway_url)?;
    let router_url = std::env::var("RAMFLUX_ITEST_ROUTER_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:18080".to_owned());
    wait_for_itest_service(&router_url, "router")?;
    mvp_s1_register_identity(&router_url)?;
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async {
        mvp_s1_assert_bad_cookie_rejected(gateway_quic_addr, &ca_cert).await?;
        let cookie = mvp_s1_fetch_pre_auth_cookie(gateway_quic_addr, &ca_cert).await?;
        mvp_s1_assert_gateway_session_lifecycle(gateway_quic_addr, &ca_cert, &cookie).await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    drop(realnet);
    Ok(())
}
