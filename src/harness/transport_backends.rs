// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use crate::*;

#[cfg(all(test, feature = "realnet"))]
pub(crate) const ATTR_REQUESTED_TRANSPORT: u16 = 0x0019;

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp10_spawn_https_json_transport_server(
    tls: &ramflux_transport::MeshTlsConfig,
) -> Result<Mvp10HttpsJsonServer, Box<dyn std::error::Error>> {
    let server = ramflux_transport::MeshTlsServer::bind("127.0.0.1:0", tls)?;
    let addr = server.local_addr()?;
    let thread = std::thread::Builder::new()
        .name("mvp10-https-json-transport-server".to_owned())
        .spawn(move || {
        let mut stream = server.accept()?;
        let request = ramflux_transport::read_mesh_http_request(&mut stream)?
            .ok_or_else(|| anyhow::anyhow!("missing https_json request"))?;
        if request.method != "POST" || request.path != "/transport/submit" {
            ramflux_transport::write_mesh_text_response(&mut stream, "404 Not Found", "not found")?;
            return Ok(());
        }
        let submit: ramflux_transport::SubmitEnvelopeRequest =
            serde_json::from_slice(&request.body)?;
        let result = ramflux_transport::transport_submit_result(
            ramflux_transport::BackendKind::HttpsJson,
            &submit,
        )?;
        ramflux_transport::write_mesh_json_response(&mut stream, "200 OK", &result)?;
        Ok(())
    })?;
    Ok((addr, thread))
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp10_spawn_quic_transport_server(
    tls: &ramflux_transport::MeshTlsConfig,
) -> Result<Mvp10AsyncServer, Box<dyn std::error::Error>> {
    let config = ramflux_transport::quic_gateway_server_config(tls)?;
    let endpoint = quinn::Endpoint::server(config, "127.0.0.1:0".parse()?)?;
    let addr = endpoint.local_addr()?;
    let task = tokio::spawn(async move {
        let connecting =
            endpoint.accept().await.ok_or_else(|| anyhow::anyhow!("missing QUIC connection"))?;
        let connection = connecting.await?;
        let (mut send, mut recv) = connection.accept_bi().await?;
        let request: ramflux_transport::GatewayQuicRequest =
            ramflux_transport::read_quic_json_frame(&mut recv).await?;
        let body = if request.method == "POST" && request.path == "/transport/submit" {
            let submit: ramflux_transport::SubmitEnvelopeRequest =
                serde_json::from_value(request.body)?;
            let result = ramflux_transport::transport_submit_result(
                ramflux_transport::BackendKind::QuicQuinn,
                &submit,
            )?;
            serde_json::to_value(result)?
        } else {
            serde_json::json!({"error":"not found"})
        };
        ramflux_transport::write_quic_json_frame(
            &mut send,
            &ramflux_transport::GatewayQuicResponse { status: 200, body },
        )
        .await?;
        connection.closed().await;
        Ok(())
    });
    Ok((addr, task))
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp10_spawn_h2_transport_server()
-> Result<Mvp10AsyncServer, Box<dyn std::error::Error>> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let task = tokio::spawn(async move {
        let (stream, _peer_addr) = listener.accept().await?;
        let mut connection = h2::server::handshake(stream).await?;
        let Some(request) = connection.accept().await else {
            return Err(anyhow::anyhow!("missing HTTP/2 request"));
        };
        let (request, mut respond) = request?;
        if request.uri().path() != "/ramflux.transport.v1.Transport/SubmitEnvelope" {
            let response = http::Response::builder().status(404).body(())?;
            respond.send_response(response, true)?;
            return Ok(());
        }
        let mut body = request.into_body();
        let mut bytes = Vec::new();
        while let Some(chunk) = body.data().await {
            bytes.extend_from_slice(&chunk?);
        }
        let submit: ramflux_transport::SubmitEnvelopeRequest = serde_json::from_slice(&bytes)?;
        let result = ramflux_transport::transport_submit_result(
            ramflux_transport::BackendKind::GrpcH2,
            &submit,
        )?;
        let response = http::Response::builder()
            .status(200)
            .header("content-type", "application/json")
            .body(())?;
        let mut send = respond.send_response(response, false)?;
        send.send_data(bytes::Bytes::from(serde_json::to_vec(&result)?), true)?;
        while let Some(request) = connection.accept().await {
            let (_request, mut respond) = request?;
            let response = http::Response::builder().status(404).body(())?;
            respond.send_response(response, true)?;
        }
        Ok(())
    });
    Ok((addr, task))
}

#[cfg(test)]
pub(crate) struct TransportSmokeFixture<'a> {
    pub(crate) signed_request: &'a ramflux_protocol::SignedRequest,
    pub(crate) envelope: &'a ramflux_protocol::Envelope,
    pub(crate) ack: &'a ramflux_protocol::Ack,
    pub(crate) nack: &'a ramflux_protocol::Nack,
    pub(crate) cursor: &'a ramflux_protocol::Cursor,
    pub(crate) expected_envelope_canonical: &'a [u8],
}

#[cfg(test)]
pub(crate) async fn smoke_backend<B: ramflux_transport::TransportBackend>(
    backend: &B,
    kind: ramflux_transport::BackendKind,
    fixture: &TransportSmokeFixture<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(backend.kind(), kind);
    let session = backend.open().await?;
    assert_eq!(session.backend, kind);
    let session = backend
        .auth(
            session,
            ramflux_transport::AuthRequest {
                device_id: "dev_a".to_owned(),
                signed_request_hash: "fixture-request-hash".to_owned(),
            },
        )
        .await?;
    assert_eq!(session.backend, kind);

    let submit = backend
        .submit_envelope(ramflux_transport::SubmitEnvelopeRequest {
            signed_request: fixture.signed_request.clone(),
            envelope: fixture.envelope.clone(),
        })
        .await?;
    assert_eq!(submit.backend, kind);
    assert_eq!(submit.envelope.envelope_id, fixture.envelope.envelope_id);
    assert_eq!(submit.envelope.payload_hash, fixture.envelope.payload_hash);
    assert_eq!(submit.envelope_canonical, fixture.expected_envelope_canonical);

    let delivery = backend.deliver().await?;
    assert_eq!(delivery.backend, kind);
    assert_eq!(delivery.envelope.envelope_id, fixture.envelope.envelope_id);
    assert_eq!(delivery.envelope.payload_hash, fixture.envelope.payload_hash);

    let ack_frame = backend.ack(fixture.ack.clone()).await?;
    assert_eq!(ack_frame.backend, kind);
    assert_eq!(ack_frame.ack.envelope_id, fixture.envelope.envelope_id);
    assert_eq!(ack_frame.ack.cursor_after.as_deref(), Some("cur_01"));

    let nack_frame = backend.nack(fixture.nack.clone()).await?;
    assert_eq!(nack_frame.backend, kind);
    assert_eq!(nack_frame.nack.envelope_id, fixture.envelope.envelope_id);
    assert_eq!(nack_frame.nack.reason, ramflux_protocol::NackReason::HomeNodeMigrated);

    let cursor_frame = backend.cursor(fixture.cursor.clone()).await?;
    assert_eq!(cursor_frame.backend, kind);
    assert_eq!(cursor_frame.cursor.cursor_id, "cur_01");
    assert_eq!(cursor_frame.cursor.inbox_seq, 42);
    Ok(())
}

#[cfg(test)]
pub(crate) async fn smoke_single_backend<B: ramflux_transport::TransportBackend>(
    backend: &B,
    kind: ramflux_transport::BackendKind,
) -> Result<(), Box<dyn std::error::Error>> {
    let root = fixture_root();
    let envelope = read_typed::<ramflux_protocol::Envelope>(
        &root,
        ramflux_protocol::fixture_json_path(fixture("envelope")?),
    )?;
    let signed_request = read_typed::<ramflux_protocol::SignedRequest>(
        &root,
        ramflux_protocol::fixture_json_path(fixture("signed_request")?),
    )?;
    let ack = read_typed::<ramflux_protocol::Ack>(
        &root,
        ramflux_protocol::fixture_json_path(fixture("ack")?),
    )?;
    let nack = read_typed::<ramflux_protocol::Nack>(
        &root,
        ramflux_protocol::fixture_json_path(fixture("nack")?),
    )?;
    let cursor = read_typed::<ramflux_protocol::Cursor>(
        &root,
        ramflux_protocol::fixture_json_path(fixture("cursor")?),
    )?;
    let envelope_canonical = ramflux_protocol::canonical_json_bytes(&envelope)?;
    smoke_backend(
        backend,
        kind,
        &TransportSmokeFixture {
            signed_request: &signed_request,
            envelope: &envelope,
            ack: &ack,
            nack: &nack,
            cursor: &cursor,
            expected_envelope_canonical: &envelope_canonical,
        },
    )
    .await
}

#[cfg(test)]
pub(crate) async fn authenticate_backend<B: ramflux_transport::TransportBackend>(
    backend: &B,
) -> Result<ramflux_transport::TransportSession, Box<dyn std::error::Error>> {
    let session = backend.open().await?;
    let authed = backend
        .auth(
            session,
            ramflux_transport::AuthRequest {
                device_id: "dev_a".to_owned(),
                signed_request_hash: "fixture-request-hash".to_owned(),
            },
        )
        .await?;
    Ok(authed)
}
