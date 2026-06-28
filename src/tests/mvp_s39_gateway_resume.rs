// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use super::*;

#[cfg(feature = "realnet")]
#[test]
fn mvp_s39_realnet_gateway_session_resume_token_rejoin() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    let realnet = start_realnet_compose_with_env(&[(
        "RAMFLUX_GATEWAY_RESUME_WINDOW_SECONDS".to_owned(),
        "2".to_owned(),
    )])?;
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
        let cookie = mvp_s1_fetch_pre_auth_cookie(gateway_quic_addr, &ca_cert).await?;
        mvp_s39_assert_resume_rejoin(gateway_quic_addr, &ca_cert, &router_url, &cookie).await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    drop(realnet);
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s39_assert_resume_rejoin(
    gateway_quic_addr: std::net::SocketAddr,
    ca_cert: &Path,
    router_url: &str,
    cookie: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (_endpoint, connection, mut send, mut recv) =
        mvp_s1_open_quic_stream(gateway_quic_addr, ca_cert).await?;
    let open = mvp_s1_open_frame(Some(cookie.to_owned()), 1_760_000_001, "s39_initial");
    let auth = mvp_s1_auth_frame(&open)?;
    mvp_s1_write_client_frame(
        &mut send,
        &ramflux_node_core::GatewayClientFrame::Open { open: open.clone() },
    )
    .await?;
    mvp_s1_write_client_frame(&mut send, &ramflux_node_core::GatewayClientFrame::Auth { auth })
        .await?;
    let initial = mvp_s1_expect_session_established(&mut recv).await?;

    mvp_s39_submit_acknowledged(&mut send, &mut recv, &open).await?;
    connection.close(0_u32.into(), b"s39-disconnect-before-resume");

    let queued: ramflux_node_core::ItestMvp0SubmitResponse =
        ramflux_node_core::itest_http_post_json(
            &format!("{router_url}/mvp0/envelope"),
            &itest_envelope("env_s39_offline_resume", "target_s1_gateway_session"),
        )?;
    assert!(matches!(queued.outcome.as_str(), "online" | "offline_queued"));

    let mut resumed = mvp_s39_open_with_resume(
        gateway_quic_addr,
        ca_cert,
        cookie,
        "s39_valid_resume",
        Some((&initial.session_id, &initial.resume_token, 1)),
    )
    .await?;
    assert_eq!(resumed.session.session_id, initial.session_id);
    assert_eq!(resumed.session.accepted_cursor.as_ref().map(|cursor| cursor.inbox_seq), Some(1));
    mvp_s1_write_client_frame(
        &mut resumed.send,
        &ramflux_node_core::GatewayClientFrame::Resume {
            resume: ramflux_node_core::GatewayResumeFrame {
                target_delivery_id: "target_s1_gateway_session".to_owned(),
                after_inbox_seq: 1,
                limit: 10,
                resume_token: resumed.session.resume_token.clone(),
            },
        },
    )
    .await?;
    let entries = mvp_s1_expect_resume_entries(&mut resumed.recv).await?;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].envelope.envelope_id, "env_s39_offline_resume");
    mvp_s1_write_client_frame(
        &mut resumed.send,
        &ramflux_node_core::GatewayClientFrame::Ack { ack: itest_ack("env_s39_offline_resume") },
    )
    .await?;
    let cursor = mvp_s1_expect_ack(&mut resumed.recv).await?;
    assert_eq!(cursor.inbox_seq, 2);
    let _cursor_frame = mvp_s1_expect_cursor(&mut resumed.recv).await?;
    mvp_s1_write_client_frame(
        &mut resumed.send,
        &ramflux_node_core::GatewayClientFrame::Resume {
            resume: ramflux_node_core::GatewayResumeFrame {
                target_delivery_id: "target_s1_gateway_session".to_owned(),
                after_inbox_seq: 1,
                limit: 10,
                resume_token: resumed.session.resume_token.clone(),
            },
        },
    )
    .await?;
    assert!(mvp_s1_expect_resume_entries(&mut resumed.recv).await?.is_empty());
    resumed.connection.close(0_u32.into(), b"s39-valid-resume-done");

    let forged = mvp_s39_open_with_forged_resume(
        gateway_quic_addr,
        ca_cert,
        cookie,
        "s39_forged_resume",
        &initial.session_id,
        "forged_resume_token_hash",
    )
    .await?;
    assert_ne!(forged.session.session_id, initial.session_id);
    forged.connection.close(0_u32.into(), b"s39-forged-resume-done");

    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    let expired = mvp_s39_open_with_resume(
        gateway_quic_addr,
        ca_cert,
        cookie,
        "s39_expired_resume",
        Some((&initial.session_id, &initial.resume_token, 2)),
    )
    .await?;
    assert_ne!(expired.session.session_id, initial.session_id);
    expired.connection.close(0_u32.into(), b"s39-expired-resume-done");
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s39_submit_acknowledged(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    open: &ramflux_node_core::GatewayOpenFrame,
) -> Result<(), Box<dyn std::error::Error>> {
    let submit = mvp_s1_submit_frame(
        open,
        itest_envelope("env_s39_acknowledged_before_resume", "target_s1_gateway_session"),
    )?;
    mvp_s1_write_client_frame(send, &ramflux_node_core::GatewayClientFrame::Submit { submit })
        .await?;
    let delivered = mvp_s1_expect_deliver(recv).await?;
    assert_eq!(delivered.envelope.envelope_id, "env_s39_acknowledged_before_resume");
    mvp_s1_write_client_frame(
        send,
        &ramflux_node_core::GatewayClientFrame::Ack {
            ack: itest_ack("env_s39_acknowledged_before_resume"),
        },
    )
    .await?;
    let cursor = mvp_s1_expect_ack(recv).await?;
    assert_eq!(cursor.inbox_seq, 1);
    let _cursor_frame = mvp_s1_expect_cursor(recv).await?;
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
struct S39GatewaySession {
    _endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    session: ramflux_node_core::GatewaySessionEstablishedFrame,
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s39_open_with_resume(
    gateway_quic_addr: std::net::SocketAddr,
    ca_cert: &Path,
    cookie: &str,
    nonce_suffix: &str,
    resume: Option<(&str, &str, u64)>,
) -> Result<S39GatewaySession, Box<dyn std::error::Error>> {
    let (endpoint, connection, mut send, mut recv) =
        mvp_s1_open_quic_stream(gateway_quic_addr, ca_cert).await?;
    let mut open = mvp_s1_open_frame(Some(cookie.to_owned()), 1_760_000_002, nonce_suffix);
    if let Some((previous_session_id, resume_token, last_seen_inbox_seq)) = resume {
        open.previous_session_id = Some(previous_session_id.to_owned());
        open.resume_token_hash = Some(ramflux_node_core::gateway_resume_token_hash(resume_token));
        open.last_seen_inbox_seq = Some(last_seen_inbox_seq);
    }
    let auth = mvp_s1_auth_frame(&open)?;
    mvp_s1_write_client_frame(&mut send, &ramflux_node_core::GatewayClientFrame::Open { open })
        .await?;
    mvp_s1_write_client_frame(&mut send, &ramflux_node_core::GatewayClientFrame::Auth { auth })
        .await?;
    let session = mvp_s1_expect_session_established(&mut recv).await?;
    Ok(S39GatewaySession { _endpoint: endpoint, connection, send, recv, session })
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s39_open_with_forged_resume(
    gateway_quic_addr: std::net::SocketAddr,
    ca_cert: &Path,
    cookie: &str,
    nonce_suffix: &str,
    previous_session_id: &str,
    resume_token_hash: &str,
) -> Result<S39GatewaySession, Box<dyn std::error::Error>> {
    let (endpoint, connection, mut send, mut recv) =
        mvp_s1_open_quic_stream(gateway_quic_addr, ca_cert).await?;
    let mut open = mvp_s1_open_frame(Some(cookie.to_owned()), 1_760_000_002, nonce_suffix);
    open.previous_session_id = Some(previous_session_id.to_owned());
    open.resume_token_hash = Some(resume_token_hash.to_owned());
    open.last_seen_inbox_seq = Some(1);
    let auth = mvp_s1_auth_frame(&open)?;
    mvp_s1_write_client_frame(&mut send, &ramflux_node_core::GatewayClientFrame::Open { open })
        .await?;
    mvp_s1_write_client_frame(&mut send, &ramflux_node_core::GatewayClientFrame::Auth { auth })
        .await?;
    let session = mvp_s1_expect_session_established(&mut recv).await?;
    Ok(S39GatewaySession { _endpoint: endpoint, connection, send, recv, session })
}
