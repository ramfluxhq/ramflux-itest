// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use super::*;

#[cfg(feature = "realnet")]
#[test]
fn mvp_s50_realnet_cross_gateway_forward_deliver() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }
    if !mvp_s50_cross_gateway_enabled() {
        eprintln!("skipping cross-gateway test; set RAMFLUX_CROSS_GATEWAY=1");
        return Ok(());
    }

    let realnet = start_realnet_compose()?;
    let ca_cert = code_root().join("ramflux/deploy/certs/ca.pem");
    let primary_gateway_addr: std::net::SocketAddr =
        std::env::var("RAMFLUX_ITEST_GATEWAY_QUIC_ADDR")
            .unwrap_or_else(|_| "127.0.0.1:18443".to_owned())
            .parse()?;
    let secondary_gateway_addr = mvp_s50_gateway_b_quic_addr()?;
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async {
        wait_for_private_gateway_quic(primary_gateway_addr, &ca_cert).await?;
        wait_for_private_gateway_quic(secondary_gateway_addr, &ca_cert).await?;
        mvp_s50_assert_cross_gateway_forward_deliver(
            primary_gateway_addr,
            secondary_gateway_addr,
            &ca_cert,
            &realnet.gateway_url,
        )
        .await
    })?;
    drop(realnet);
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
#[allow(clippy::too_many_lines)]
async fn mvp_s50_assert_cross_gateway_forward_deliver(
    primary_gateway_addr: std::net::SocketAddr,
    secondary_gateway_addr: std::net::SocketAddr,
    ca_cert: &std::path::Path,
    gateway_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    mvp_s50_register_gateway_device(
        gateway_url,
        MvpS50FrameDevice {
            principal_id: "principal_s50_alice",
            device_id: "alice_device_s50",
            target_delivery_id: "target_s50_alice",
            gateway_id: "gw-a",
            session_id: "pre_session_s50_alice",
            root_seed: [0x5a; 32],
            device_seed: [0x5b; 32],
            device_epoch: 1,
            nonce_suffix: "alice_gw_a",
        },
    )?;
    mvp_s50_register_gateway_device(
        gateway_url,
        MvpS50FrameDevice {
            principal_id: "principal_s50_bob",
            device_id: "bob_device_s50",
            target_delivery_id: "target_s50_bob",
            gateway_id: "gw-b",
            session_id: "pre_session_s50_bob",
            root_seed: [0x5c; 32],
            device_seed: [0x5d; 32],
            device_epoch: 1,
            nonce_suffix: "bob_gw_b",
        },
    )?;

    let mut bob = mvp_s50_open_registered_gateway_frame_session(
        secondary_gateway_addr,
        ca_cert,
        MvpS50FrameDevice {
            principal_id: "principal_s50_bob",
            device_id: "bob_device_s50",
            target_delivery_id: "target_s50_bob",
            gateway_id: "gw-b",
            session_id: "pre_session_s50_bob",
            root_seed: [0x5c; 32],
            device_seed: [0x5d; 32],
            device_epoch: 1,
            nonce_suffix: "bob_gw_b",
        },
    )
    .await?;
    assert_eq!(bob.session.gateway_id, "gw-b");
    let previous_bob_cursor =
        bob.session.accepted_cursor.as_ref().map_or(0, |cursor| cursor.inbox_seq);

    let mut alice = mvp_s50_open_registered_gateway_frame_session(
        primary_gateway_addr,
        ca_cert,
        MvpS50FrameDevice {
            principal_id: "principal_s50_alice",
            device_id: "alice_device_s50",
            target_delivery_id: "target_s50_alice",
            gateway_id: "gw-a",
            session_id: "pre_session_s50_alice",
            root_seed: [0x5a; 32],
            device_seed: [0x5b; 32],
            device_epoch: 1,
            nonce_suffix: "alice_gw_a",
        },
    )
    .await?;
    assert_eq!(alice.session.gateway_id, "gw-a");

    let mut envelope = itest_envelope("env_s50_cross_gateway_alice_to_bob", "target_s50_bob");
    envelope.source_principal_id = "principal_s50_alice".to_owned();
    envelope.source_device_id = "alice_device_s50".to_owned();
    envelope.encrypted_payload =
        ramflux_protocol::encode_base64url(b"s50 cross gateway frame payload");
    envelope.payload_hash = ramflux_crypto::blake3_256_base64url(
        "ramflux.test.s50.cross_gateway_forward.v1",
        envelope.encrypted_payload.as_bytes(),
    );
    let submit = mvp_s1_submit_frame(&alice.open, envelope.clone())?;
    mvp_s1_write_client_frame(
        &mut alice.send,
        &ramflux_node_core::GatewayClientFrame::Submit { submit },
    )
    .await?;

    let sender_echo = mvp_s1_expect_deliver(&mut alice.recv).await?;
    assert_eq!(sender_echo.envelope.envelope_id, "env_s50_cross_gateway_alice_to_bob");
    assert_eq!(sender_echo.target_delivery_id, "target_s50_bob");

    let delivered = mvp_s1_expect_deliver(&mut bob.recv).await?;
    assert_eq!(delivered.envelope.envelope_id, "env_s50_cross_gateway_alice_to_bob");
    assert_eq!(delivered.target_delivery_id, "target_s50_bob");
    assert_eq!(delivered.envelope.encrypted_payload, envelope.encrypted_payload);
    assert!(
        delivered.inbox_seq > previous_bob_cursor,
        "cross-gateway Deliver did not advance Bob cursor beyond {previous_bob_cursor}: {delivered:?}"
    );

    mvp_s1_write_client_frame(
        &mut bob.send,
        &ramflux_node_core::GatewayClientFrame::Ack {
            ack: itest_ack("env_s50_cross_gateway_alice_to_bob"),
        },
    )
    .await?;
    let ack_cursor = mvp_s1_expect_ack(&mut bob.recv).await?;
    assert_eq!(ack_cursor.target_delivery_id, "target_s50_bob");
    assert_eq!(ack_cursor.inbox_seq, delivered.inbox_seq);
    assert_eq!(ack_cursor.last_envelope_id.as_deref(), Some("env_s50_cross_gateway_alice_to_bob"));
    assert!(
        ack_cursor.acked_envelope_ids.contains(&"env_s50_cross_gateway_alice_to_bob".to_owned())
    );
    let cursor_frame =
        mvp_s1_expect_cursor(&mut bob.recv).await?.ok_or("missing S50 Bob ack cursor")?;
    assert_eq!(cursor_frame, ack_cursor);

    alice.connection.close(0_u32.into(), b"s50-alice-frame-done");
    bob.connection.close(0_u32.into(), b"s50-bob-frame-done");
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
fn mvp_s50_register_gateway_device(
    gateway_url: &str,
    device: MvpS50FrameDevice<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let request = mvp_s1_identity_register_request(GatewayFrameIdentitySpec {
        principal_id: device.principal_id,
        device_id: device.device_id,
        target_delivery_id: device.target_delivery_id,
        gateway_id: device.gateway_id,
        session_id: device.session_id,
        push_alias_hash: Some(device.target_delivery_id),
        source_ip_hash: Some("mvp_s50_source"),
        root_seed: device.root_seed,
        device_seed: device.device_seed,
        device_epoch: device.device_epoch,
    })?;
    let response = register_mvp1_identity(gateway_url, &request)?;
    assert_eq!(response.device_id, device.device_id);
    assert_eq!(response.target_delivery_id, device.target_delivery_id);
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s50_open_registered_gateway_frame_session(
    gateway_quic_addr: std::net::SocketAddr,
    ca_cert: &std::path::Path,
    device: MvpS50FrameDevice<'_>,
) -> Result<MvpS50GatewayFrameSession, Box<dyn std::error::Error>> {
    let (endpoint, connection, mut send, mut recv) =
        mvp_s1_open_quic_stream(gateway_quic_addr, ca_cert).await?;
    let mut open = mvp_s1_open_frame(None, 1_760_000_050, device.nonce_suffix);
    open.client_instance_id = format!("rf_s50_{}", device.device_id);
    open.device_id = device.device_id.to_owned();
    open.target_delivery_id = device.target_delivery_id.to_owned();
    open.stream_nonce = format!("nonce_s50_{}", device.nonce_suffix);
    open.source_ip_hash = Some("mvp_s50_source".to_owned());
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
    Ok(MvpS50GatewayFrameSession { _endpoint: endpoint, connection, send, recv, open, session })
}

#[cfg(all(test, feature = "realnet"))]
fn mvp_s50_gateway_b_quic_addr() -> Result<std::net::SocketAddr, Box<dyn std::error::Error>> {
    if let Ok(addr) = std::env::var("RAMFLUX_ITEST_GATEWAY_B_QUIC_ADDR") {
        return Ok(addr.parse()?);
    }
    let port: u16 = std::env::var("RAMFLUX_ITEST_GATEWAY_B_QUIC_PORT")
        .unwrap_or_else(|_| "18444".to_owned())
        .parse()?;
    Ok(std::net::SocketAddr::from(([127, 0, 0, 1], port)))
}

#[cfg(all(test, feature = "realnet"))]
fn mvp_s50_cross_gateway_enabled() -> bool {
    std::env::var("RAMFLUX_CROSS_GATEWAY").is_ok_and(|value| {
        matches!(value.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on")
    })
}

#[cfg(all(test, feature = "realnet"))]
#[derive(Clone, Copy)]
struct MvpS50FrameDevice<'a> {
    principal_id: &'a str,
    device_id: &'a str,
    target_delivery_id: &'a str,
    gateway_id: &'a str,
    session_id: &'a str,
    root_seed: [u8; 32],
    device_seed: [u8; 32],
    device_epoch: u64,
    nonce_suffix: &'a str,
}

#[cfg(all(test, feature = "realnet"))]
struct MvpS50GatewayFrameSession {
    _endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    open: ramflux_node_core::GatewayOpenFrame,
    session: ramflux_node_core::GatewaySessionEstablishedFrame,
}
