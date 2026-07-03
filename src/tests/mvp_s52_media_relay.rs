// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use super::*;

#[cfg(feature = "realnet")]
#[test]
fn mvp_s52_realnet_opaque_media_udp_relay_enforces_token_and_source_binding()
-> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    let _realnet = start_realnet_compose()?;
    let relay_addr = s52_relay_addr()?;
    let issued_at = realnet_now_u64();
    let sender_token = s52_media_relay_token(
        issued_at,
        "alloc_s52_media_sender",
        "alloc_s52_media_receiver",
        "alice_media_hash_s52",
        "bob_media_hash_s52",
    )?;
    let receiver_token = s52_media_relay_token(
        issued_at,
        "alloc_s52_media_receiver",
        "alloc_s52_media_sender",
        "bob_media_hash_s52",
        "alice_media_hash_s52",
    )?;
    let sender = s52_media_socket()?;
    let receiver = s52_media_socket()?;
    let hijack = s52_media_socket()?;

    let forbidden_key = b"SRTP_MEDIA_KEY_S52_NEVER_RELAYED";
    let sender_payload = b"ramflux-s52-opaque-media:a-to-b:ciphertext-only";
    let receiver_payload = b"ramflux-s52-opaque-media:b-to-a:ciphertext-only";
    assert!(!sender_payload.windows(forbidden_key.len()).any(|window| window == forbidden_key));
    assert!(!receiver_payload.windows(forbidden_key.len()).any(|window| window == forbidden_key));

    s52_send_media_relay_packet(&receiver, relay_addr, &receiver_token, b"bind-receiver")?;
    s52_send_media_relay_packet(&sender, relay_addr, &sender_token, sender_payload)?;
    assert_eq!(s52_recv_media(&receiver)?, sender_payload);

    s52_send_media_relay_packet(&hijack, relay_addr, &sender_token, b"source-hijack")?;
    assert!(
        s52_recv_media_timeout(&receiver)?.is_none(),
        "relay accepted a token from a different UDP source"
    );

    let mut forged = sender_token.clone();
    forged.mac = "forged".to_owned();
    s52_send_media_relay_packet(&sender, relay_addr, &forged, b"forged-open-relay")?;
    assert!(s52_recv_media_timeout(&receiver)?.is_none(), "relay accepted a forged token MAC");

    s52_send_media_relay_packet(&receiver, relay_addr, &receiver_token, receiver_payload)?;
    let relayed_to_sender = s52_recv_media(&sender)?;
    assert_eq!(relayed_to_sender, receiver_payload);
    assert!(!relayed_to_sender.windows(forbidden_key.len()).any(|window| window == forbidden_key));
    Ok(())
}

#[cfg(feature = "realnet")]
fn s52_relay_addr() -> Result<std::net::SocketAddr, Box<dyn std::error::Error>> {
    Ok(std::env::var("RAMFLUX_ITEST_RELAY_MEDIA_UDP_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:19000".to_owned())
        .parse()?)
}

#[cfg(feature = "realnet")]
fn s52_media_relay_token(
    issued_at: u64,
    allocation_id: &str,
    target_allocation_id: &str,
    identity_hash: &str,
    peer_hash: &str,
) -> Result<ramflux_node_core::TurnMediaRelayToken, Box<dyn std::error::Error>> {
    Ok(ramflux_node_core::sign_turn_media_relay_token(
        b"ramflux-relay-itest-service-key",
        ramflux_node_core::TurnMediaRelayToken {
            call_id: "call_s52_media_relay".to_owned(),
            allocation_id: allocation_id.to_owned(),
            target_allocation_id: target_allocation_id.to_owned(),
            flow_id: "flow_s52_media_relay".to_owned(),
            identity_hash: identity_hash.to_owned(),
            peer_hash: peer_hash.to_owned(),
            issued_at,
            expires_at: issued_at.saturating_add(600),
            nonce: format!("nonce_s52_{allocation_id}_{target_allocation_id}"),
            mac: String::new(),
        },
    )?)
}

#[cfg(feature = "realnet")]
fn s52_media_socket() -> Result<std::net::UdpSocket, Box<dyn std::error::Error>> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(std::time::Duration::from_secs(2)))?;
    socket.set_write_timeout(Some(std::time::Duration::from_secs(2)))?;
    Ok(socket)
}

#[cfg(feature = "realnet")]
fn s52_send_media_relay_packet(
    socket: &std::net::UdpSocket,
    relay_addr: std::net::SocketAddr,
    token: &ramflux_node_core::TurnMediaRelayToken,
    payload: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let packet = ramflux_node_core::encode_turn_media_relay_packet(
        &ramflux_node_core::TurnMediaRelayPacketHeader { token: token.clone() },
        payload,
    )?;
    socket.send_to(&packet, relay_addr)?;
    Ok(())
}

#[cfg(feature = "realnet")]
fn s52_recv_media(socket: &std::net::UdpSocket) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    s52_recv_media_timeout(socket)?.ok_or_else(|| "timed out waiting for relayed media".into())
}

#[cfg(feature = "realnet")]
fn s52_recv_media_timeout(
    socket: &std::net::UdpSocket,
) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
    let mut response = [0_u8; 2048];
    match socket.recv_from(&mut response) {
        Ok((len, _peer)) => Ok(Some(response[..len].to_vec())),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) =>
        {
            Ok(None)
        }
        Err(error) => Err(error.into()),
    }
}
