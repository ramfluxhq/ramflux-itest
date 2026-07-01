// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use super::*;

#[cfg(all(test, feature = "realnet"))]
const MVP_S39_PRODUCER_ROOT_SEED: [u8; 32] = [0x69; 32];
#[cfg(all(test, feature = "realnet"))]
const MVP_S39_PRODUCER_DEVICE_SEED: [u8; 32] = [0x6A; 32];

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
    let ca_cert = code_root.join("ramflux/deploy/certs/ca.pem");
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
        mvp_s39_assert_resume_rejoin(gateway_quic_addr, &ca_cert, &cookie).await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    drop(realnet);
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s39_assert_resume_rejoin(
    gateway_quic_addr: std::net::SocketAddr,
    ca_cert: &Path,
    initial_cookie: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (_endpoint, connection, mut send, mut recv) =
        mvp_s1_open_quic_stream(gateway_quic_addr, ca_cert).await?;
    eprintln!("S39-STEP: initial open/auth before");
    let open = mvp_s1_open_frame(Some(initial_cookie.to_owned()), 1_760_000_001, "s39_initial");
    let auth = mvp_s1_auth_frame(&open)?;
    mvp_s1_write_client_frame(
        &mut send,
        &ramflux_node_core::GatewayClientFrame::Open { open: open.clone() },
    )
    .await?;
    mvp_s1_write_client_frame(&mut send, &ramflux_node_core::GatewayClientFrame::Auth { auth })
        .await?;
    let initial = mvp_s1_expect_session_established(&mut recv).await?;
    eprintln!("S39-STEP: initial session_established after");

    eprintln!("S39-STEP: producer identity register before");
    mvp_s39_register_producer_device(&mut send, &mut recv).await?;
    eprintln!("S39-STEP: producer identity register after");
    eprintln!("S39-STEP: initial submit+ack before");
    mvp_s39_submit_acknowledged(&mut send, &mut recv, &open).await?;
    eprintln!("S39-STEP: initial submit+ack after");
    mvp_s39_close_session_and_wait_offline(connection, send, recv).await?;
    eprintln!("S39-STEP: initial close/drain after");

    let producer_cookie = mvp_s1_fetch_pre_auth_cookie(gateway_quic_addr, ca_cert).await?;
    eprintln!("S39-STEP: producer offline submit before");
    mvp_s39_submit_offline_resume_candidate(gateway_quic_addr, ca_cert, &producer_cookie).await?;
    eprintln!("S39-STEP: producer offline submit after");

    let resume_cookie = mvp_s1_fetch_pre_auth_cookie(gateway_quic_addr, ca_cert).await?;
    eprintln!("S39-STEP: resume open/auth before");
    let mut resumed = mvp_s39_open_with_resume(
        gateway_quic_addr,
        ca_cert,
        &resume_cookie,
        "s39_valid_resume",
        Some((&initial.session_id, &initial.resume_token, 1)),
    )
    .await?;
    eprintln!("S39-STEP: resume session_established after");
    assert_eq!(resumed.session.session_id, initial.session_id);
    assert_eq!(resumed.session.accepted_cursor.as_ref().map(|cursor| cursor.inbox_seq), Some(1));
    eprintln!("S39-STEP: resume frame before");
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
    eprintln!("S39-STEP: resume entries after count={}", entries.len());
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].envelope.envelope_id, "env_s39_offline_resume");
    eprintln!("S39-STEP: resume ack before");
    mvp_s1_write_client_frame(
        &mut resumed.send,
        &ramflux_node_core::GatewayClientFrame::Ack { ack: itest_ack("env_s39_offline_resume") },
    )
    .await?;
    let cursor = mvp_s1_expect_ack(&mut resumed.recv).await?;
    assert_eq!(cursor.inbox_seq, 2);
    assert_eq!(cursor.target_delivery_id, "target_s1_gateway_session");
    assert_eq!(cursor.last_envelope_id.as_deref(), Some("env_s39_offline_resume"));
    assert!(cursor.acked_envelope_ids.contains(&"env_s39_offline_resume".to_owned()));
    let cursor_frame =
        mvp_s1_expect_cursor(&mut resumed.recv).await?.ok_or("missing S39 resume ack cursor")?;
    assert_eq!(cursor_frame, cursor);
    eprintln!("S39-STEP: resume ack+cursor after");
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

    mvp_s39_assert_invalid_resume_tokens_are_rejected(gateway_quic_addr, ca_cert, &initial).await?;
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s39_close_session_and_wait_offline(
    connection: quinn::Connection,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("S39-STEP: initial close frame before");
    mvp_s1_write_client_frame(
        &mut send,
        &ramflux_node_core::GatewayClientFrame::Close {
            reason: "s39-disconnect-before-resume".to_owned(),
        },
    )
    .await?;
    match mvp_s1_read_server_frame(&mut recv).await? {
        ramflux_node_core::GatewayServerFrame::Drain { reason, .. } => {
            assert!(
                reason.starts_with("client_close:s39-disconnect-before-resume"),
                "unexpected S39 drain reason: {reason}"
            );
        }
        other => return Err(format!("expected S39 drain on close, got {other:?}").into()),
    }
    match mvp_s1_read_server_frame(&mut recv).await? {
        ramflux_node_core::GatewayServerFrame::Close { reason } => {
            assert_eq!(reason, "s39-disconnect-before-resume");
        }
        other => return Err(format!("expected S39 close after drain, got {other:?}").into()),
    }
    connection.close(0_u32.into(), b"s39-disconnect-before-resume");
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s39_assert_invalid_resume_tokens_are_rejected(
    gateway_quic_addr: std::net::SocketAddr,
    ca_cert: &Path,
    initial: &ramflux_node_core::GatewaySessionEstablishedFrame,
) -> Result<(), Box<dyn std::error::Error>> {
    let forged_cookie = mvp_s1_fetch_pre_auth_cookie(gateway_quic_addr, ca_cert).await?;
    eprintln!("S39-STEP: forged resume open before");
    let forged = mvp_s39_open_with_forged_resume(
        gateway_quic_addr,
        ca_cert,
        &forged_cookie,
        "s39_forged_resume",
        &initial.session_id,
        "forged_resume_token_hash",
    )
    .await?;
    assert_ne!(forged.session.session_id, initial.session_id);
    forged.connection.close(0_u32.into(), b"s39-forged-resume-done");
    eprintln!("S39-STEP: forged resume rejected after");

    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    let expired_cookie = mvp_s1_fetch_pre_auth_cookie(gateway_quic_addr, ca_cert).await?;
    eprintln!("S39-STEP: expired resume open before");
    let expired = mvp_s39_open_with_resume(
        gateway_quic_addr,
        ca_cert,
        &expired_cookie,
        "s39_expired_resume",
        Some((&initial.session_id, &initial.resume_token, 2)),
    )
    .await?;
    assert_ne!(expired.session.session_id, initial.session_id);
    expired.connection.close(0_u32.into(), b"s39-expired-resume-done");
    eprintln!("S39-STEP: expired resume rejected after");
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s39_register_producer_device(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
) -> Result<(), Box<dyn std::error::Error>> {
    let request = mvp_s1_identity_register_request(GatewayFrameIdentitySpec {
        principal_id: "principal_s39_producer",
        device_id: "device_s39_producer",
        target_delivery_id: "target_s39_producer",
        gateway_id: "ramflux-gateway",
        session_id: "pre_session_s39_producer",
        push_alias_hash: Some("push_alias_s39_producer"),
        source_ip_hash: Some("mvp_s39_source"),
        root_seed: MVP_S39_PRODUCER_ROOT_SEED,
        device_seed: MVP_S39_PRODUCER_DEVICE_SEED,
        device_epoch: 1,
    })?;
    mvp_s1_write_client_frame(
        send,
        &ramflux_node_core::GatewayClientFrame::IdentityRegister { request },
    )
    .await?;
    match mvp_s1_read_server_frame(recv).await? {
        ramflux_node_core::GatewayServerFrame::IdentityRegistered { response } => {
            assert_eq!(response.device_id, "device_s39_producer");
            assert_eq!(response.target_delivery_id, "target_s39_producer");
            Ok(())
        }
        other => {
            Err(format!("expected identity_registered for S39 producer, got {other:?}").into())
        }
    }
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s39_submit_offline_resume_candidate(
    gateway_quic_addr: std::net::SocketAddr,
    ca_cert: &Path,
    cookie: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("S39-STEP: producer open/auth before");
    let mut producer = mvp_s39_open_registered_device(
        gateway_quic_addr,
        ca_cert,
        cookie,
        S39RegisteredDevice {
            principal_id: "principal_s39_producer",
            device_id: "device_s39_producer",
            target_delivery_id: "target_s39_producer",
            device_seed: MVP_S39_PRODUCER_DEVICE_SEED,
            device_epoch: 1,
            nonce_suffix: "producer_offline_submit",
        },
    )
    .await?;
    eprintln!("S39-STEP: producer session_established after");
    let submit = mvp_s1_submit_frame(
        &producer.open,
        itest_envelope("env_s39_offline_resume", "target_s1_gateway_session"),
    )?;
    mvp_s1_write_client_frame(
        &mut producer.send,
        &ramflux_node_core::GatewayClientFrame::Submit { submit },
    )
    .await?;
    eprintln!("S39-STEP: producer submit frame written after");
    let delivered = mvp_s1_expect_deliver(&mut producer.recv).await?;
    eprintln!("S39-STEP: producer deliver echo after");
    assert_eq!(delivered.envelope.envelope_id, "env_s39_offline_resume");
    assert_eq!(delivered.target_delivery_id, "target_s1_gateway_session");
    assert_eq!(delivered.inbox_seq, 2);
    let wake = mvp_s1_read_server_frame(&mut producer.recv).await?;
    eprintln!("S39-STEP: producer wake frame after");
    assert!(
        matches!(wake, ramflux_node_core::GatewayServerFrame::InBandWake { ref target_delivery_id, .. } if target_delivery_id == "target_s1_gateway_session"),
        "expected S39 offline wake after producer submit, got {wake:?}"
    );
    producer.connection.close(0_u32.into(), b"s39-producer-done");
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
    open: ramflux_node_core::GatewayOpenFrame,
    session: ramflux_node_core::GatewaySessionEstablishedFrame,
}

#[cfg(all(test, feature = "realnet"))]
struct S39RegisteredDevice<'a> {
    principal_id: &'a str,
    device_id: &'a str,
    target_delivery_id: &'a str,
    device_seed: [u8; 32],
    device_epoch: u64,
    nonce_suffix: &'a str,
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s39_open_registered_device(
    gateway_quic_addr: std::net::SocketAddr,
    ca_cert: &Path,
    cookie: &str,
    device: S39RegisteredDevice<'_>,
) -> Result<S39GatewaySession, Box<dyn std::error::Error>> {
    let (endpoint, connection, mut send, mut recv) =
        mvp_s1_open_quic_stream(gateway_quic_addr, ca_cert).await?;
    let mut open = mvp_s1_open_frame(Some(cookie.to_owned()), 1_760_000_002, device.nonce_suffix);
    open.client_instance_id = format!("rf_s39_{}", device.device_id);
    open.device_id = device.device_id.to_owned();
    open.target_delivery_id = device.target_delivery_id.to_owned();
    open.stream_nonce = format!("nonce_s39_{}", device.nonce_suffix);
    let auth = mvp_s1_auth_frame_for_registered_device(
        &open,
        device.principal_id,
        device.device_epoch,
        device.device_seed,
    )?;
    mvp_s1_write_client_frame(
        &mut send,
        &ramflux_node_core::GatewayClientFrame::Open { open: open.clone() },
    )
    .await?;
    mvp_s1_write_client_frame(&mut send, &ramflux_node_core::GatewayClientFrame::Auth { auth })
        .await?;
    let session = mvp_s1_expect_session_established(&mut recv).await?;
    Ok(S39GatewaySession { _endpoint: endpoint, connection, send, recv, open, session })
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
    mvp_s1_write_client_frame(
        &mut send,
        &ramflux_node_core::GatewayClientFrame::Open { open: open.clone() },
    )
    .await?;
    mvp_s1_write_client_frame(&mut send, &ramflux_node_core::GatewayClientFrame::Auth { auth })
        .await?;
    let session = mvp_s1_expect_session_established(&mut recv).await?;
    Ok(S39GatewaySession { _endpoint: endpoint, connection, send, recv, open, session })
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
    mvp_s1_write_client_frame(
        &mut send,
        &ramflux_node_core::GatewayClientFrame::Open { open: open.clone() },
    )
    .await?;
    mvp_s1_write_client_frame(&mut send, &ramflux_node_core::GatewayClientFrame::Auth { auth })
        .await?;
    let session = mvp_s1_expect_session_established(&mut recv).await?;
    Ok(S39GatewaySession { _endpoint: endpoint, connection, send, recv, open, session })
}
