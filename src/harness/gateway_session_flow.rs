// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use crate::*;

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn start_s10_private_node_compose() -> Result<S10PrivateNode, Box<dyn std::error::Error>>
{
    let code_root = code_root();
    let deploy_root = code_root.join("ramflux-deploy");
    run_deploy_script(&code_root, "ramflux-deploy/scripts/bootstrap-ca.sh")?;
    run_deploy_script(&code_root, "ramflux-deploy/scripts/issue-certs.sh")?;
    run_deploy_script(&code_root, "ramflux-deploy/scripts/build-prod-images.sh")?;
    let env = vec![
        ("RAMFLUX_GATEWAY_TCP_PORT".to_owned(), "54_443".replace('_', "")),
        ("RAMFLUX_GATEWAY_QUIC_PORT".to_owned(), "54_443".replace('_', "")),
        ("RAMFLUX_SIGNALING_TURN_UDP_PORT".to_owned(), "53_478".replace('_', "")),
        ("RAMFLUX_SIGNALING_TURN_TCP_PORT".to_owned(), "53_479".replace('_', "")),
    ];
    run_production_compose_project(
        &deploy_root,
        "ramflux-s10-private-node",
        &env,
        &["up", "--build", "-d"],
    )?;
    let guard =
        ProductionComposeDownGuard::new(deploy_root, "ramflux-s10-private-node".to_owned(), env);
    Ok(S10PrivateNode {
        gateway_quic_addr: std::net::SocketAddr::from(([127, 0, 0, 1], 54_443)),
        ca_cert: code_root.join("ramflux-deploy/certs/ca.pem"),
        _guard: guard,
    })
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn start_s22_production_node(
    project_name: &str,
    node_id: &str,
    ports: S22ProductionPorts,
) -> Result<S22ProductionNode, Box<dyn std::error::Error>> {
    let code_root = code_root();
    let deploy_root = code_root.join("ramflux-deploy");
    run_deploy_script(&code_root, "ramflux-deploy/scripts/bootstrap-ca.sh")?;
    run_deploy_script(&code_root, "ramflux-deploy/scripts/issue-certs.sh")?;
    run_deploy_script(&code_root, "ramflux-deploy/scripts/build-prod-images.sh")?;
    let admin_token = format!("admin-token-{project_name}");
    let node_signing_seed = realnet_node_signing_seed(node_id);
    let env = vec![
        ("RAMFLUX_GATEWAY_TCP_PORT".to_owned(), ports.gateway.to_string()),
        ("RAMFLUX_GATEWAY_QUIC_PORT".to_owned(), ports.gateway.to_string()),
        ("RAMFLUX_SIGNALING_TURN_UDP_PORT".to_owned(), ports.signaling_turn_udp.to_string()),
        ("RAMFLUX_SIGNALING_TURN_TCP_PORT".to_owned(), ports.signaling_turn_tcp.to_string()),
        ("RAMFLUX_FEDERATION_ADMIN_PORT".to_owned(), ports.federation_admin.to_string()),
        ("RAMFLUX_FEDERATION_MESH_PORT".to_owned(), ports.federation_mesh.to_string()),
        ("RAMFLUX_FEDERATION_ADMIN_TOKEN".to_owned(), admin_token.clone()),
        ("RAMFLUX_FEDERATION_NODE_ID".to_owned(), node_id.to_owned()),
        (
            "RAMFLUX_FEDERATION_NODE_SIGNING_SEED_B64URL".to_owned(),
            ramflux_protocol::encode_base64url(node_signing_seed),
        ),
        (
            "RAMFLUX_FEDERATION_PUBLIC_ENDPOINT".to_owned(),
            format!("host.docker.internal:{}", ports.federation_mesh),
        ),
    ];
    run_production_compose_project(&deploy_root, project_name, &env, &["up", "--build", "-d"])?;
    let guard = ProductionComposeDownGuard::new(deploy_root, project_name.to_owned(), env);
    let admin_url = format!("http://127.0.0.1:{}", ports.federation_admin);
    wait_for_federation(&admin_url)?;
    Ok(S22ProductionNode {
        node_id: node_id.to_owned(),
        admin_url: admin_url.clone(),
        // admin_url (127.0.0.1) is reached by rf on the host; well_known_url is fetched by the
        // *peer node's container*, so it must resolve host->container via host.docker.internal.
        well_known_url: format!(
            "http://host.docker.internal:{}/.well-known/ramflux/server",
            ports.federation_admin
        ),
        gateway_quic_addr: std::net::SocketAddr::from(([127, 0, 0, 1], ports.gateway)),
        ca_cert: code_root.join("ramflux-deploy/certs/ca.pem"),
        admin_token,
        guard,
    })
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn restart_s22_federation_service(
    node: &S22ProductionNode,
) -> Result<(), Box<dyn std::error::Error>> {
    realnet_step(
        "restart s22 federation service",
        format!("project={} node={}", node.guard.project_name, node.node_id),
    );
    run_production_compose_project(
        &node.guard.deploy_root,
        &node.guard.project_name,
        &node.guard.env,
        &["restart", "ramflux-federation"],
    )?;
    wait_for_federation(&node.admin_url)?;
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn s8_compose_env(ports: S8ComposePorts) -> Vec<(String, String)> {
    [
        ("RAMFLUX_ITEST_GATEWAY_HTTP_PORT", ports.gateway_http),
        ("RAMFLUX_ITEST_GATEWAY_QUIC_PORT", ports.gateway_quic),
        ("RAMFLUX_ITEST_GATEWAY_TCP_PORT", ports.gateway_quic),
        ("RAMFLUX_ITEST_ROUTER_HTTP_PORT", ports.router_http),
        ("RAMFLUX_ITEST_ROUTER_MESH_PORT", ports.router_mesh),
        ("RAMFLUX_ITEST_NOTIFY_HTTP_PORT", ports.notify_http),
        ("RAMFLUX_ITEST_FEDERATION_HTTP_PORT", ports.federation_http),
        ("RAMFLUX_ITEST_FEDERATION_MESH_PORT", ports.federation_mesh),
        ("RAMFLUX_ITEST_RELAY_HTTP_PORT", ports.relay_http),
        ("RAMFLUX_ITEST_RELAY_MEDIA_UDP_PORT", ports.relay_media_udp),
        ("RAMFLUX_ITEST_SIGNALING_TURN_UDP_PORT", ports.signaling_turn_udp),
        ("RAMFLUX_ITEST_SIGNALING_TURN_TCP_PORT", ports.signaling_turn_tcp),
        ("RAMFLUX_ITEST_RETENTION_HTTP_PORT", ports.retention_http),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_owned(), value.to_string()))
    .collect::<Vec<_>>()
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp_s1_enable_gateway_preauth(
    gateway_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let policy = ramflux_node_core::GatewayPreAuthPolicy {
        enabled: true,
        per_source_ip_handshake_rate: 0,
        window_seconds: 60,
        cookie_ttl_seconds: 5,
        auth_deadline_ms: 1_000,
        cookie_secret: ramflux_node_core::DEFAULT_PRE_AUTH_COOKIE_SECRET.to_owned(),
    };
    let response: ramflux_node_core::GatewayPreAuthPolicy =
        ramflux_node_core::itest_http_post_json(
            &format!("{gateway_url}/mvp6/preauth/policy"),
            &policy,
        )?;
    assert_eq!(response, policy);
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s1_assert_bad_cookie_rejected(
    gateway_quic_addr: std::net::SocketAddr,
    ca_cert: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let forged = mvp_s1_open_frame(Some("forged-cookie".to_owned()), 1_760_000_001, "bad_forged");
    let rejected = mvp_s1_single_open_response(gateway_quic_addr, ca_cert, forged).await?;
    assert!(
        matches!(rejected, ramflux_node_core::GatewayServerFrame::Nack { ref reason } if reason.contains("pre_auth_rejected")),
        "forged cookie was not rejected: {rejected:?}"
    );

    let expired_cookie = ramflux_node_core::sign_pre_auth_cookie(
        "mvp_s1_source",
        ramflux_node_core::PRE_AUTH_PROTOCOL_VERSION,
        1_760_000_000,
        ramflux_node_core::DEFAULT_PRE_AUTH_COOKIE_SECRET,
    );
    let expired = mvp_s1_open_frame(Some(expired_cookie), 1_760_000_010, "bad_expired");
    let rejected = mvp_s1_single_open_response(gateway_quic_addr, ca_cert, expired).await?;
    assert!(
        matches!(rejected, ramflux_node_core::GatewayServerFrame::Nack { ref reason } if reason.contains("pre_auth_rejected")),
        "expired cookie was not rejected: {rejected:?}"
    );
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s1_fetch_pre_auth_cookie(
    gateway_quic_addr: std::net::SocketAddr,
    ca_cert: &Path,
) -> Result<String, Box<dyn std::error::Error>> {
    let open = mvp_s1_open_frame(None, 1_760_000_000, "challenge");
    let frame = mvp_s1_single_open_response(gateway_quic_addr, ca_cert, open).await?;
    match frame {
        ramflux_node_core::GatewayServerFrame::Nack { reason } => reason
            .strip_prefix("pre_auth_cookie_required:")
            .map(ToOwned::to_owned)
            .ok_or_else(|| format!("unexpected pre-auth challenge reason: {reason}").into()),
        other => Err(format!("expected pre-auth challenge NACK, got {other:?}").into()),
    }
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s1_single_open_response(
    gateway_quic_addr: std::net::SocketAddr,
    ca_cert: &Path,
    open: ramflux_node_core::GatewayOpenFrame,
) -> Result<ramflux_node_core::GatewayServerFrame, Box<dyn std::error::Error>> {
    let (_endpoint, connection, mut send, mut recv) =
        mvp_s1_open_quic_stream(gateway_quic_addr, ca_cert).await?;
    mvp_s1_write_client_frame(&mut send, &ramflux_node_core::GatewayClientFrame::Open { open })
        .await?;
    let frame = mvp_s1_read_server_frame(&mut recv).await?;
    connection.close(0_u32.into(), b"s1-single-open-done");
    Ok(frame)
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s1_assert_gateway_session_lifecycle(
    gateway_quic_addr: std::net::SocketAddr,
    ca_cert: &Path,
    cookie: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (_endpoint, connection, mut send, mut recv) =
        mvp_s1_open_quic_stream(gateway_quic_addr, ca_cert).await?;
    let open = mvp_s1_open_frame(Some(cookie.to_owned()), 1_760_000_001, "main");
    let auth = mvp_s1_auth_frame(&open)?;
    mvp_s1_write_client_frame(
        &mut send,
        &ramflux_node_core::GatewayClientFrame::Open { open: open.clone() },
    )
    .await?;
    mvp_s1_write_client_frame(&mut send, &ramflux_node_core::GatewayClientFrame::Auth { auth })
        .await?;
    let established = mvp_s1_expect_session_established(&mut recv).await?;
    assert_eq!(established.accepted_cursor, None);
    assert!(!established.resume_token.is_empty());

    mvp_s1_assert_submit_ack_and_wake(&mut send, &mut recv, &open).await?;
    mvp_s1_submit_unacked_resume_candidate(&mut send, &mut recv, &open).await?;
    connection.close(0_u32.into(), b"s1-resume-test-disconnect");

    mvp_s1_assert_resume_and_close(gateway_quic_addr, ca_cert, cookie).await
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s1_assert_submit_ack_and_wake(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    open: &ramflux_node_core::GatewayOpenFrame,
) -> Result<(), Box<dyn std::error::Error>> {
    let plaintext = b"s1 plaintext must stay client-side";
    let mut alice_dm =
        ramflux_crypto::DmSession::initiator([0x51; 32], [0xa1; 32], [0xb1; 32], [0xc1; 32])?;
    let mut bob_dm =
        ramflux_crypto::DmSession::recipient([0x51; 32], [0xb1; 32], [0xa1; 32], [0xc1; 32])?;
    let ciphertext = alice_dm.encrypt(plaintext, b"mvp_s1_raw_frame_ad")?;
    let mut envelope = itest_envelope("env_s1_quic_session_ack", "target_s1_gateway_session");
    envelope.encrypted_payload = serde_json::to_string(&ciphertext)?;
    assert_node_opaque_payload(&envelope.encrypted_payload, plaintext);
    let submit = mvp_s1_submit_frame(open, envelope.clone())?;
    mvp_s1_write_client_frame(send, &ramflux_node_core::GatewayClientFrame::Submit { submit })
        .await?;
    let delivered = mvp_s1_expect_deliver(recv).await?;
    assert_eq!(delivered.envelope.envelope_id, "env_s1_quic_session_ack");
    assert_eq!(delivered.inbox_seq, 1);
    assert_eq!(delivered.envelope.encrypted_payload, envelope.encrypted_payload);
    let delivered_ciphertext: ramflux_crypto::DmCiphertext =
        serde_json::from_str(&delivered.envelope.encrypted_payload)?;
    assert_eq!(bob_dm.decrypt(&delivered_ciphertext, b"mvp_s1_raw_frame_ad")?, plaintext);

    mvp_s1_write_client_frame(
        send,
        &ramflux_node_core::GatewayClientFrame::Ack { ack: itest_ack("env_s1_quic_session_ack") },
    )
    .await?;
    let ack_cursor = mvp_s1_expect_ack(recv).await?;
    assert_eq!(ack_cursor.inbox_seq, 1);
    assert!(ack_cursor.acked_envelope_ids.contains(&"env_s1_quic_session_ack".to_owned()));
    let cursor = mvp_s1_expect_cursor(recv).await?.ok_or("missing S1 ack cursor")?;
    assert_eq!(cursor.inbox_seq, 1);

    mvp_s1_write_client_frame(
        send,
        &ramflux_node_core::GatewayClientFrame::Ack { ack: itest_ack("env_s1_quic_session_ack") },
    )
    .await?;
    let duplicate_ack_cursor = mvp_s1_expect_ack(recv).await?;
    assert_eq!(duplicate_ack_cursor.inbox_seq, 1);
    assert!(
        duplicate_ack_cursor.acked_envelope_ids.contains(&"env_s1_quic_session_ack".to_owned())
    );
    let duplicate_cursor =
        mvp_s1_expect_cursor(recv).await?.ok_or("missing S1 duplicate ack cursor")?;
    assert_eq!(duplicate_cursor.inbox_seq, 1);

    let offline = mvp_s1_submit_frame(
        open,
        itest_envelope("env_s1_quic_session_wake", "target_s1_gateway_offline"),
    )?;
    mvp_s1_write_client_frame(
        send,
        &ramflux_node_core::GatewayClientFrame::Submit { submit: offline },
    )
    .await?;
    let offline_delivered = mvp_s1_expect_deliver(recv).await?;
    assert_eq!(offline_delivered.envelope.envelope_id, "env_s1_quic_session_wake");
    let wake = mvp_s1_read_server_frame(recv).await?;
    assert!(
        matches!(wake, ramflux_node_core::GatewayServerFrame::InBandWake { ref target_delivery_id, .. } if target_delivery_id == "target_s1_gateway_offline"),
        "expected in_band_wake for offline target, got {wake:?}"
    );
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s1_submit_unacked_resume_candidate(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    open: &ramflux_node_core::GatewayOpenFrame,
) -> Result<(), Box<dyn std::error::Error>> {
    let replay_envelope = itest_envelope("env_s1_quic_session_resume", "target_s1_gateway_session");
    let submit = mvp_s1_submit_frame(open, replay_envelope)?;
    mvp_s1_write_client_frame(send, &ramflux_node_core::GatewayClientFrame::Submit { submit })
        .await?;
    let replay_delivery = mvp_s1_expect_deliver(recv).await?;
    assert_eq!(replay_delivery.envelope.envelope_id, "env_s1_quic_session_resume");
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s1_assert_resume_and_close(
    gateway_quic_addr: std::net::SocketAddr,
    ca_cert: &Path,
    cookie: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (_endpoint2, connection2, mut send2, mut recv2) =
        mvp_s1_open_quic_stream(gateway_quic_addr, ca_cert).await?;
    let resume_open = mvp_s1_open_frame(Some(cookie.to_owned()), 1_760_000_002, "resume");
    let resume_auth = mvp_s1_auth_frame(&resume_open)?;
    mvp_s1_write_client_frame(
        &mut send2,
        &ramflux_node_core::GatewayClientFrame::Open { open: resume_open },
    )
    .await?;
    mvp_s1_write_client_frame(
        &mut send2,
        &ramflux_node_core::GatewayClientFrame::Auth { auth: resume_auth },
    )
    .await?;
    let resumed_session = mvp_s1_expect_session_established(&mut recv2).await?;
    mvp_s1_write_client_frame(
        &mut send2,
        &ramflux_node_core::GatewayClientFrame::Resume {
            resume: ramflux_node_core::GatewayResumeFrame {
                target_delivery_id: "target_s1_gateway_session".to_owned(),
                after_inbox_seq: 1,
                limit: 10,
                resume_token: resumed_session.resume_token.clone(),
            },
        },
    )
    .await?;
    let replayed = mvp_s1_expect_resume_entries(&mut recv2).await?;
    assert_eq!(replayed.len(), 1);
    assert_eq!(replayed[0].envelope.envelope_id, "env_s1_quic_session_resume");

    mvp_s1_write_client_frame(
        &mut send2,
        &ramflux_node_core::GatewayClientFrame::Ack {
            ack: itest_ack("env_s1_quic_session_resume"),
        },
    )
    .await?;
    let resume_cursor = mvp_s1_expect_ack(&mut recv2).await?;
    assert_eq!(resume_cursor.inbox_seq, 2);
    let _cursor_frame = mvp_s1_expect_cursor(&mut recv2).await?;
    mvp_s1_write_client_frame(
        &mut send2,
        &ramflux_node_core::GatewayClientFrame::Resume {
            resume: ramflux_node_core::GatewayResumeFrame {
                target_delivery_id: "target_s1_gateway_session".to_owned(),
                after_inbox_seq: 1,
                limit: 10,
                resume_token: resumed_session.resume_token,
            },
        },
    )
    .await?;
    let replayed = mvp_s1_expect_resume_entries(&mut recv2).await?;
    assert!(replayed.is_empty(), "acked S1 envelope replayed again: {replayed:?}");

    mvp_s1_write_client_frame(
        &mut send2,
        &ramflux_node_core::GatewayClientFrame::Close { reason: "test_done".to_owned() },
    )
    .await?;
    let drain = mvp_s1_read_server_frame(&mut recv2).await?;
    assert!(
        matches!(drain, ramflux_node_core::GatewayServerFrame::Drain { ref session_id, .. } if session_id == &resumed_session.session_id),
        "expected drain before close, got {drain:?}"
    );
    let close = mvp_s1_read_server_frame(&mut recv2).await?;
    assert!(matches!(close, ramflux_node_core::GatewayServerFrame::Close { .. }));
    connection2.close(0_u32.into(), b"s1-done");
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s1_open_quic_stream(
    gateway_quic_addr: std::net::SocketAddr,
    ca_cert: &Path,
) -> Result<
    (quinn::Endpoint, quinn::Connection, quinn::SendStream, quinn::RecvStream),
    Box<dyn std::error::Error>,
> {
    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(ramflux_transport::quic_gateway_client_config(ca_cert)?);
    let connecting = endpoint.connect(gateway_quic_addr, "localhost")?;
    let connection = tokio::time::timeout(Duration::from_secs(10), connecting).await??;
    let (send, recv) =
        tokio::time::timeout(Duration::from_secs(10), connection.open_bi()).await??;
    Ok((endpoint, connection, send, recv))
}
