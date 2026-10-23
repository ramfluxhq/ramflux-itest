// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Native demo CLI verification against signed discovery, gateway sessions and relay QUIC.
use ramflux_protocol::WellKnownClientRecord;
use serde_json::{Value, json};
use std::process::Output;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Clone, Copy)]
enum GatewayMode {
    Quic,
    TcpFallback,
    WrongNack,
}
#[derive(Clone, Copy)]
enum Trust {
    Valid,
    WrongCa,
    WrongName,
}
struct Fixture {
    origin: String,
    key: String,
    frames: Arc<Mutex<Vec<String>>>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    endpoints: Vec<quinn::Endpoint>,
    _blackhole: Option<std::net::UdpSocket>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        for endpoint in &self.endpoints {
            endpoint.close(0_u32.into(), b"test finished");
        }
        for task in &self.tasks {
            task.abort();
        }
    }
}
impl Fixture {
    async fn start(mode: GatewayMode, trust: Trust, relay_status: u16) -> TestResult<Self> {
        let (ca, tls) = credentials()?;
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let tcp_addr = tcp.local_addr()?;
        let frames = Arc::new(Mutex::new(Vec::new()));
        let mut tasks = vec![serve_tcp(tcp, Arc::clone(&tls), mode, Arc::clone(&frames))];
        let mut endpoints = Vec::new();
        let mut blackhole = None;
        let quic_addr = if matches!(mode, GatewayMode::TcpFallback) {
            let socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
            let addr = socket.local_addr()?;
            blackhole = Some(socket);
            addr
        } else {
            let endpoint = quinn::Endpoint::server(quic_config(&tls)?, "127.0.0.1:0".parse()?)?;
            let addr = endpoint.local_addr()?;
            tasks.push(serve_quic(endpoint.clone(), Some(mode), relay_status, Arc::clone(&frames)));
            endpoints.push(endpoint);
            addr
        };
        let relay = quinn::Endpoint::server(quic_config(&tls)?, "127.0.0.1:0".parse()?)?;
        let relay_addr = relay.local_addr()?;
        tasks.push(serve_quic(relay.clone(), None, relay_status, Arc::clone(&frames)));
        endpoints.push(relay);
        let mut record = discovery_record(ca, quic_addr, tcp_addr, relay_addr)?;
        match trust {
            Trust::Valid => {}
            Trust::WrongCa => record.node_ca_cert_pem = credentials()?.0,
            Trust::WrongName => "untrusted.invalid".clone_into(&mut record.gateway_server_name),
        }
        record.signature = ramflux_crypto::sign_canonical_bytes_with_seed(
            &ramflux_protocol::client_discovery_signing_bytes(&record)?,
            [0x11; 32],
        );
        let key = record.node_public_key.clone();
        let http = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let origin = format!("http://{}", http.local_addr()?);
        tasks.push(serve_discovery(http, serde_json::to_vec(&record)?));
        Ok(Self { origin, key, frames, tasks, endpoints, _blackhole: blackhole })
    }
    async fn verify(&self, pin: Option<String>) -> TestResult<Output> {
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_demo-node-tool"));
        command.args(["verify", &self.origin, pin.as_deref().unwrap_or(&self.key)]);
        for name in
            ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"]
        {
            command.env_remove(name);
        }
        Ok(tokio::task::spawn_blocking(move || command.output()).await??)
    }
    fn frames(&self) -> Vec<String> {
        self.frames.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone()
    }
}

fn credentials() -> TestResult<(String, Arc<rustls::ServerConfig>)> {
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])?;
    let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_single_cert(
        vec![certificate.cert.der().clone()],
        rustls_pki_types::PrivatePkcs8KeyDer::from(certificate.signing_key.serialize_der()).into(),
    )?;
    Ok((certificate.cert.pem(), Arc::new(tls)))
}
fn quic_config(tls: &rustls::ServerConfig) -> TestResult<quinn::ServerConfig> {
    Ok(quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls.clone())?,
    )))
}
fn discovery_record(
    ca: String,
    quic: std::net::SocketAddr,
    tcp: std::net::SocketAddr,
    relay: std::net::SocketAddr,
) -> TestResult<WellKnownClientRecord> {
    let timestamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
    Ok(WellKnownClientRecord {
        schema: ramflux_protocol::WELL_KNOWN_CLIENT_SCHEMA.to_owned(),
        node_id: "demo.invalid".to_owned(),
        node_public_key: ramflux_crypto::public_key_base64url_from_seed([0x11; 32]),
        node_ca_cert_pem: ca,
        gateway_quic_addr: quic.to_string(),
        gateway_tcp_addr: tcp.to_string(),
        gateway_server_name: "localhost".to_owned(),
        relay_quic_addr: relay.to_string(),
        relay_server_name: "localhost".to_owned(),
        prekey_http_url: "http://127.0.0.1:1".to_owned(),
        signaling_turn_addr: "127.0.0.1:3478".to_owned(),
        protocol_versions: vec!["v1".to_owned()],
        client_capabilities: vec!["object_relay_v3".to_owned()],
        updated_at: timestamp,
        expires_at: timestamp + 3600,
        signature: String::new(),
    })
}
fn gateway_reply(request: &Value, mode: GatewayMode, frames: &Mutex<Vec<String>>) -> Value {
    let kind = request
        .get("frame_type")
        .or_else(|| request.get("method"))
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    frames.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(kind.to_owned());
    if request.get("method").is_some() {
        return json!({"status":404,"body":{"error":"gateway session protocol required"}});
    }
    json!({"frame_type":"nack","reason":if matches!(mode,GatewayMode::WrongNack) {"wrong protocol reason"} else {ramflux_protocol::GATEWAY_FIRST_FRAME_NACK_REASON}})
}
fn serve_quic(
    endpoint: quinn::Endpoint,
    mode: Option<GatewayMode>,
    relay_status: u16,
    frames: Arc<Mutex<Vec<String>>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let frames = Arc::clone(&frames);
            tokio::spawn(async move {
                let result: TestResult = async {
                    let connection = incoming.await?;
                    let (mut send, mut recv) = connection.accept_bi().await?;
                    let request: Value = ramflux_transport::read_quic_json_frame(&mut recv).await?;
                    let response = if let Some(mode) = mode {
                        gateway_reply(&request, mode, &frames)
                    } else {
                        assert_eq!(request["method"], "GET");
                        assert_eq!(request["path"], "/healthz");
                        json!({"status":relay_status,"body":{"status":"fixture"}})
                    };
                    ramflux_transport::write_quic_json_frame(&mut send, &response).await?;
                    connection.closed().await;
                    Ok(())
                }
                .await;
                // A negative trust test intentionally aborts the handshake.
                let _ = result;
            });
        }
    })
}
fn serve_tcp(
    listener: tokio::net::TcpListener,
    tls: Arc<rustls::ServerConfig>,
    mode: GatewayMode,
    frames: Arc<Mutex<Vec<String>>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::clone(&tls));
            let frames = Arc::clone(&frames);
            tokio::spawn(async move {
                let result: TestResult = async {
                    let mut stream = acceptor.accept(socket).await?;
                    let len = stream.read_u32().await?;
                    if len > 1024 * 1024 {
                        return Err("test frame too large".into());
                    }
                    let mut bytes = vec![0; len as usize];
                    stream.read_exact(&mut bytes).await?;
                    let response = serde_json::to_vec(&gateway_reply(
                        &serde_json::from_slice(&bytes)?,
                        mode,
                        &frames,
                    ))?;
                    stream.write_u32(u32::try_from(response.len())?).await?;
                    stream.write_all(&response).await?;
                    stream.flush().await?;
                    Ok(())
                }
                .await;
                let _ = result;
            });
        }
    })
}
fn serve_discovery(
    listener: tokio::net::TcpListener,
    body: Vec<u8>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if let Ok((mut socket, _)) = listener.accept().await {
            let mut request = Vec::new();
            while request.len() < 8192 && !request.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                if socket.read_exact(&mut byte).await.is_err() {
                    return;
                }
                request.push(byte[0]);
            }
            assert!(request.starts_with(b"GET /.well-known/ramflux/client "));
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            if socket.write_all(header.as_bytes()).await.is_ok() {
                let _ = socket.write_all(&body).await;
            }
        }
    })
}
fn output_text(output: &Output) -> String {
    format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn status_uses_gateway_session_frames_and_prints_verified_fingerprint() -> TestResult {
    let fixture = Fixture::start(GatewayMode::Quic, Trust::Valid, 200).await?;
    let output = fixture.verify(None).await?;
    let text = output_text(&output);
    assert!(output.status.success(), "{text}");
    assert!(
        text.contains("gateway pre-account health: healthy (quic=ok tcp=not_attempted"),
        "{text}"
    );
    assert!(text.contains("session=requires_account"), "{text}");
    assert!(text.contains("relay QUIC TLS/application health: healthy"), "{text}");
    let fingerprint = ramflux_protocol::hash_hex(
        ramflux_protocol::CLIENT_DISCOVERY_DOMAIN,
        fixture.key.as_bytes(),
    );
    assert!(text.contains(&format!("node key fingerprint: {fingerprint}")), "{text}");
    assert_eq!(fixture.frames(), vec!["heartbeat"]);
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn status_falls_back_to_verified_tcp_tls_when_quic_is_unavailable() -> TestResult {
    let fixture = Fixture::start(GatewayMode::TcpFallback, Trust::Valid, 200).await?;
    let output = fixture.verify(None).await?;
    let text = output_text(&output);
    assert!(output.status.success(), "{text}");
    assert!(text.contains("quic=failed tcp=ok"), "{text}");
    assert_eq!(fixture.frames(), vec!["heartbeat"]);
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn status_rejects_a_different_nack_even_on_verified_transports() -> TestResult {
    let fixture = Fixture::start(GatewayMode::WrongNack, Trust::Valid, 200).await?;
    let output = fixture.verify(None).await?;
    let text = output_text(&output);
    assert!(!output.status.success());
    assert!(text.contains("unexpected_response"), "{text}");
    assert_eq!(fixture.frames(), vec!["heartbeat", "heartbeat"]);
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn status_keeps_relay_application_health_required() -> TestResult {
    let fixture = Fixture::start(GatewayMode::Quic, Trust::Valid, 503).await?;
    let output = fixture.verify(None).await?;
    let text = output_text(&output);
    assert!(!output.status.success());
    assert!(text.contains("relay QUIC unhealthy"), "{text}");
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn status_rejects_untrusted_gateway_ca_or_server_name() -> TestResult {
    for trust in [Trust::WrongCa, Trust::WrongName] {
        let fixture = Fixture::start(GatewayMode::Quic, trust, 200).await?;
        let output = fixture.verify(None).await?;
        let text = output_text(&output);
        assert!(!output.status.success());
        assert!(text.contains("not_available"), "{text}");
        assert_eq!(fixture.frames(), Vec::<String>::new());
    }
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn status_does_not_probe_or_print_a_fingerprint_for_a_wrong_operator_pin() -> TestResult {
    let fixture = Fixture::start(GatewayMode::Quic, Trust::Valid, 200).await?;
    let output =
        fixture.verify(Some(ramflux_crypto::public_key_base64url_from_seed([0x22; 32]))).await?;
    let text = output_text(&output);
    assert!(!output.status.success());
    assert!(text.contains("does not match operator pin"), "{text}");
    assert!(!text.contains("node key fingerprint:"));
    assert_eq!(fixture.frames(), Vec::<String>::new());
    Ok(())
}
