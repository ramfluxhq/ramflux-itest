// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Synthetic mono Opus packets over RTP/SFrame, checked at both sides of opaque UDP forwarding.
use super::*;
const OPUS_SILENCE: &[u8] = &[0xf8, 0xff, 0xfe];
struct Engine {
    socket: std::sync::Arc<tokio::net::UdpSocket>,
    token: String,
    lease_id: String,
    side: u8,
    rebind_key: [u8; 32],
    sender: ramflux_crypto::SFrameSender,
    receiver: ramflux_crypto::SFrameReceiver,
    ssrc: u32,
}
impl Engine {
    async fn new(value: &Value, ssrc: u32) -> VoiceResult<Self> {
        let endpoint = value["relay"]["endpoint"].as_str().ok_or("media endpoint missing")?;
        let token = value["relay"]["token"].as_str().ok_or("media token missing")?.to_owned();
        let send = &value["sframe"]["send"];
        let receive = &value["sframe"]["receive"];
        let key = |v: &Value| -> VoiceResult<Vec<u8>> {
            Ok(ramflux_protocol::decode_base64url(
                v["base_key"].as_str().ok_or("media key missing")?,
            )?)
        };
        let sender = ramflux_crypto::SFrameSender::new(
            &key(send)?,
            send["kid"].as_u64().ok_or("send KID missing")?,
        )?;
        let receiver = ramflux_crypto::SFrameReceiver::new(
            &key(receive)?,
            receive["kid"].as_u64().ok_or("receive KID missing")?,
        )?;
        let socket = std::sync::Arc::new(tokio::net::UdpSocket::bind("0.0.0.0:0").await?);
        socket.connect(endpoint).await?;
        let lease_id = value["relay"]["lease_id"].as_str().ok_or("lease id missing")?.to_owned();
        let side = u8::try_from(value["relay"]["side"].as_u64().ok_or("relay side missing")?)?;
        let bytes = ramflux_protocol::decode_base64url(
            value["relay"]["rebind_key"].as_str().ok_or("rebind key missing")?,
        )?;
        let rebind_key = bytes.as_slice().try_into().map_err(|_| "rebind key length")?;
        Ok(Self { socket, token, lease_id, side, rebind_key, sender, receiver, ssrc })
    }
    fn packet(&mut self, seq: u16) -> VoiceResult<Vec<u8>> {
        let mut header = vec![0x80, 111];
        header.extend(seq.to_be_bytes());
        header.extend((u32::from(seq) * 960).to_be_bytes());
        header.extend(self.ssrc.to_be_bytes());
        let frame = self.sender.seal(&header, OPUS_SILENCE)?;
        assert_ne!(frame, OPUS_SILENCE);
        header.extend(frame);
        Ok(header)
    }
    async fn send(&self, packet: &[u8]) -> VoiceResult {
        self.socket.send(&ramflux_node_core::encode_voice_datagram(&self.token, packet)?).await?;
        Ok(())
    }
    fn open(&mut self, packet: &[u8], seq: u16, ssrc: u32) -> VoiceResult {
        if packet.len() < 12 {
            return Err("truncated RTP packet".into());
        }
        assert_eq!(&packet[..2], &[0x80, 111]);
        assert_eq!(&packet[2..4], &seq.to_be_bytes());
        assert_eq!(&packet[4..8], &(u32::from(seq) * 960).to_be_bytes());
        assert_eq!(&packet[8..12], &ssrc.to_be_bytes());
        assert_eq!(self.receiver.open(&packet[..12], &packet[12..])?, OPUS_SILENCE);
        Ok(())
    }
}
async fn one_way(from: &mut Engine, to: &mut Engine, seq: u16, probe: bool) -> VoiceResult {
    let packet = from.packet(seq)?;
    let mut buffer = [0_u8; 2048];
    let attempts = if probe { 20 } else { 1 };
    for _ in 0..attempts {
        // Refresh both authenticated source bindings before sending an actual media packet.
        from.send(&[]).await?;
        to.send(&[]).await?;
        from.send(&packet).await?;
        let deadline =
            tokio::time::Instant::now() + Duration::from_millis(if probe { 100 } else { 2000 });
        loop {
            let received = tokio::time::timeout_at(deadline, to.socket.recv(&mut buffer)).await;
            let Ok(received) = received else {
                break;
            };
            let len = received?;
            let wire = &buffer[..len];
            if wire.starts_with(b"RFVC") {
                let response = ramflux_crypto::voice_rebind_response(
                    &to.rebind_key,
                    &to.lease_id,
                    to.side,
                    wire,
                )?;
                to.send(&response).await?;
                continue;
            }
            if wire.len() < 12 {
                return Err("truncated forwarded media".into());
            }
            let received_seq = u16::from_be_bytes([wire[2], wire[3]]);
            if received_seq < seq {
                assert!(
                    to.receiver.open(&wire[..12], &wire[12..]).is_err(),
                    "a delayed probe duplicate must remain rejected"
                );
                continue;
            }
            assert_eq!(
                wire, packet,
                "relay must forward exactly the opaque packet, without its token"
            );
            to.open(wire, seq, from.ssrc)?;
            assert!(
                to.receiver.open(&wire[..12], &wire[12..]).is_err(),
                "replayed media must be refused"
            );
            return Ok(());
        }
    }
    Err("voice relay did not forward an authenticated opaque packet".into())
}
pub(super) async fn round_trip(alice: &Value, bob: &Value) -> VoiceResult {
    let mut a = Engine::new(alice, 0x1111_1111).await?;
    let mut b = Engine::new(bob, 0x2222_2222).await?;
    one_way(&mut a, &mut b, 0, true).await?;
    one_way(&mut b, &mut a, 0, true).await?;
    rebind(&mut a, &mut b).await?;
    let keep_a = a.socket.clone();
    let keep_b = b.socket.clone();
    let packet_a = ramflux_node_core::encode_voice_datagram(&a.token, &[])?;
    let packet_b = ramflux_node_core::encode_voice_datagram(&b.token, &[])?;
    let media = async {
        tokio::time::sleep(Duration::from_secs(6)).await;
        for seq in 3..=10 {
            one_way(&mut a, &mut b, seq, false).await?;
            one_way(&mut b, &mut a, seq, false).await?;
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    };
    tokio::select! {
        result = media => result,
        result = keep_alive(keep_a, keep_b, packet_a, packet_b) => result,
    }
}
async fn keep_alive(
    a: std::sync::Arc<tokio::net::UdpSocket>,
    b: std::sync::Arc<tokio::net::UdpSocket>,
    packet_a: Vec<u8>,
    packet_b: Vec<u8>,
) -> VoiceResult {
    let mut tick = tokio::time::interval(Duration::from_secs(5));
    loop {
        tick.tick().await;
        a.send(&packet_a).await?;
        b.send(&packet_b).await?;
    }
}

async fn rebind(account: &mut Engine, peer: &mut Engine) -> VoiceResult {
    realnet_step(
        "voice rebind",
        "cookie plus copied token must fail; private HMAC proof must succeed",
    );
    let socket = std::sync::Arc::new(tokio::net::UdpSocket::bind("0.0.0.0:0").await?);
    socket.connect(account.socket.peer_addr()?).await?;
    socket.send(&ramflux_node_core::encode_voice_datagram(&account.token, &[])?).await?;
    let mut buffer = [0; 2048];
    let len = tokio::time::timeout(Duration::from_secs(3), socket.recv(&mut buffer)).await??;
    let challenge = &buffer[..len];
    let forged = ramflux_crypto::voice_rebind_response(
        &[0; 32],
        &account.lease_id,
        account.side,
        challenge,
    )?;
    socket.send(&ramflux_node_core::encode_voice_datagram(&account.token, &forged)?).await?;
    // This packet must still arrive at the old pinned socket after a token thief's cookie echo.
    one_way(peer, account, 1, false).await?;
    let response = ramflux_crypto::voice_rebind_response(
        &account.rebind_key,
        &account.lease_id,
        account.side,
        challenge,
    )?;
    socket.send(&ramflux_node_core::encode_voice_datagram(&account.token, &response)?).await?;
    account.socket = socket;
    // Keep the existing SFrame sender/counter and replay window when only the socket changes.
    one_way(peer, account, 2, true).await?;
    one_way(account, peer, 1, true).await?;
    Ok(())
}
