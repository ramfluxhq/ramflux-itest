// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use super::*;

#[cfg(feature = "realnet")]
#[test]
fn mvp_s2_realnet_sdk_session_dm_resume_cursor() -> Result<(), Box<dyn std::error::Error>> {
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
        mvp_s2_assert_sdk_session_dm_resume(&realnet.gateway_url, gateway_quic_addr, &ca_cert)
            .await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    drop(realnet);
    Ok(())
}

#[cfg(feature = "realnet")]
#[test]
fn mvp_s2_realnet_sdk_session_dm_resume_cursor_tcp_tls() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    let realnet = start_realnet_compose()?;
    let code_root = code_root();
    let ca_cert = code_root.join("ramflux-deploy/certs/ca.pem");
    let gateway_tcp_addr: std::net::SocketAddr = std::env::var("RAMFLUX_ITEST_GATEWAY_TCP_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:18443".to_owned())
        .parse()?;

    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async {
        mvp_s2_assert_sdk_session_dm_resume_tcp_tls(
            &realnet.gateway_url,
            gateway_tcp_addr,
            &ca_cert,
        )
        .await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    drop(realnet);
    Ok(())
}

#[cfg(feature = "realnet")]
#[test]
fn mvp_s2_realnet_sdk_session_dm_resume_cursor_auto_prefers_quic()
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

    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async {
        mvp_s2_assert_sdk_session_dm_resume_auto_prefers_quic(
            &realnet.gateway_url,
            gateway_quic_addr,
            &ca_cert,
        )
        .await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    drop(realnet);
    Ok(())
}

#[cfg(feature = "realnet")]
#[test]
fn mvp_s2_realnet_sdk_session_auto_quic_survives_frame_delay()
-> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    let realnet = start_realnet_compose_with_env(&[(
        "RAMFLUX_ITEST_GATEWAY_FRAME_DELAY_MS".to_owned(),
        "1800".to_owned(),
    )])?;
    let code_root = code_root();
    let ca_cert = code_root.join("ramflux-deploy/certs/ca.pem");
    let gateway_quic_addr: std::net::SocketAddr = std::env::var("RAMFLUX_ITEST_GATEWAY_QUIC_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:18443".to_owned())
        .parse()?;

    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async {
        mvp_s2_assert_sdk_session_dm_resume_auto_quic_survives_frame_delay(
            &realnet.gateway_url,
            gateway_quic_addr,
            &ca_cert,
        )
        .await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    drop(realnet);
    Ok(())
}

#[cfg(feature = "realnet")]
#[test]
fn mvp_s2_realnet_sdk_session_dm_resume_cursor_udp_unreachable_falls_back_tcp_tls()
-> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    let realnet = start_realnet_compose()?;
    let code_root = code_root();
    let ca_cert = code_root.join("ramflux-deploy/certs/ca.pem");
    let blocked_quic_addr: std::net::SocketAddr =
        std::env::var("RAMFLUX_ITEST_GATEWAY_BLOCKED_QUIC_ADDR")
            .unwrap_or_else(|_| "127.0.0.1:9".to_owned())
            .parse()?;
    let gateway_tcp_addr: std::net::SocketAddr = std::env::var("RAMFLUX_ITEST_GATEWAY_TCP_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:18443".to_owned())
        .parse()?;

    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async {
        mvp_s2_assert_sdk_session_dm_resume_auto_falls_back_tcp_tls(
            &realnet.gateway_url,
            blocked_quic_addr,
            gateway_tcp_addr,
            &ca_cert,
        )
        .await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    drop(realnet);
    Ok(())
}

#[cfg(feature = "realnet")]
#[test]
fn mvp_s2_realnet_compio_gateway_quic_session_online_push() -> Result<(), Box<dyn std::error::Error>>
{
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }
    if std::env::var("RAMFLUX_GATEWAY_COMPIO").as_deref() != Ok("1") {
        eprintln!("skipping compio gateway realnet test; set RAMFLUX_GATEWAY_COMPIO=1");
        return Ok(());
    }

    let realnet = start_realnet_compose_with_env_and_gateway_compio(&[], true)?;
    let code_root = code_root();
    let ca_cert = code_root.join("ramflux-deploy/certs/ca.pem");
    let gateway_quic_addr: std::net::SocketAddr = std::env::var("RAMFLUX_ITEST_GATEWAY_QUIC_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:18443".to_owned())
        .parse()?;

    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async {
        mvp_s2_assert_sdk_session_dm_resume(&realnet.gateway_url, gateway_quic_addr, &ca_cert)
            .await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    drop(realnet);
    Ok(())
}
