// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use crate::*;
#[cfg(all(test, feature = "realnet"))]
static S13_RUSTLS_PROVIDER: std::sync::Once = std::sync::Once::new();

#[cfg(all(test, feature = "realnet"))]
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub(crate) struct Mvp10QuicLanObjectSyncRequest {
    pub(crate) phase: String,
    pub(crate) manifest: ramflux_sync::ChunkManifest,
    pub(crate) chunks: Vec<ramflux_sync::ChunkPayload>,
}

#[cfg(all(test, feature = "realnet"))]
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub(crate) struct Mvp10QuicLanObjectSyncResponse {
    pub(crate) missing: ramflux_sync::MissingChunkBitmap,
    pub(crate) resume_token: ramflux_sync::ResumeToken,
    pub(crate) complete: bool,
    pub(crate) assembled_cipher_hash: Option<String>,
    pub(crate) assembled_ciphertext: Option<String>,
    pub(crate) node_visible_plaintext: bool,
    pub(crate) node_visible_object_key: bool,
}

#[cfg(all(test, feature = "realnet"))]
impl S13MockPushProvider {
    pub(crate) fn start(expected_requests: usize) -> Result<Self, Box<dyn std::error::Error>> {
        Self::start_with_delay(expected_requests, Duration::ZERO)
    }

    pub(crate) fn start_with_delay(
        expected_requests: usize,
        provider_delay: Duration,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // Bind 0.0.0.0 (not 127.0.0.1): the notify CONTAINER reaches this mock via
        // host.docker.internal -> the host's gateway IP, so a loopback-only listener
        // refuses the connection. 0.0.0.0 accepts it on the bridge interface.
        let listener = std::net::TcpListener::bind("0.0.0.0:0")?;
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?;
        s13_ensure_ring_crypto_provider_installed();
        let certified =
            rcgen::generate_simple_self_signed(vec!["host.docker.internal".to_owned()])?;
        let ca_pem = certified.cert.pem();
        let cert_der = rustls_pki_types::CertificateDer::from(certified.cert.der().to_vec());
        let key_der = rustls_pki_types::PrivateKeyDer::Pkcs8(
            rustls_pki_types::PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der()),
        );
        let requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let done = std::sync::Arc::new(std::sync::Condvar::new());
        let thread_requests = std::sync::Arc::clone(&requests);
        let thread_done = std::sync::Arc::clone(&done);
        let thread = std::thread::spawn(move || {
            run_s13_mock_h2_server(S13MockH2ServerConfig {
                listener,
                cert_der,
                key_der,
                expected_requests,
                provider_delay,
                requests: thread_requests,
                done: thread_done,
            });
        });
        Ok(Self { addr, ca_pem, requests, done, _thread: thread })
    }

    pub(crate) fn container_url(&self, path: &str) -> String {
        format!("https://host.docker.internal:{}{path}", self.addr.port())
    }

    pub(crate) fn ca_pem_secret_ref(&self) -> String {
        format!("literal:{}", self.ca_pem)
    }

    pub(crate) fn wait_for_requests(
        &self,
        timeout: Duration,
    ) -> Result<Vec<S13MockPushRequest>, Box<dyn std::error::Error>> {
        let deadline = std::time::Instant::now() + timeout;
        let mut guard =
            self.requests.lock().map_err(|error| format!("mock push lock poisoned: {error}"))?;
        while guard.len() < 2 {
            let now = std::time::Instant::now();
            if now >= deadline {
                return Err(format!("timed out waiting for mock push; got {}", guard.len()).into());
            }
            let remaining = deadline.saturating_duration_since(now);
            let (next_guard, _timeout) = self
                .done
                .wait_timeout(guard, remaining)
                .map_err(|error| format!("mock push condvar poisoned: {error}"))?;
            guard = next_guard;
        }
        Ok(guard.clone())
    }
}

#[cfg(all(test, feature = "realnet"))]
struct S13MockH2ServerConfig {
    listener: std::net::TcpListener,
    cert_der: rustls_pki_types::CertificateDer<'static>,
    key_der: rustls_pki_types::PrivateKeyDer<'static>,
    expected_requests: usize,
    provider_delay: Duration,
    requests: std::sync::Arc<std::sync::Mutex<Vec<S13MockPushRequest>>>,
    done: std::sync::Arc<std::sync::Condvar>,
}

#[cfg(all(test, feature = "realnet"))]
fn run_s13_mock_h2_server(config: S13MockH2ServerConfig) {
    s13_ensure_ring_crypto_provider_installed();
    let Ok(runtime) = tokio::runtime::Builder::new_multi_thread().enable_all().build() else {
        return;
    };
    runtime.block_on(async move {
        let Ok(listener) = tokio::net::TcpListener::from_std(config.listener) else {
            return;
        };
        let Ok(mut server_config) = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![config.cert_der], config.key_der)
        else {
            return;
        };
        server_config.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(server_config));
        while config.requests.lock().map_or(0, |guard| guard.len()) < config.expected_requests {
            let Ok((stream, _peer)) = listener.accept().await else {
                break;
            };
            tokio::spawn(handle_s13_mock_h2_connection(
                acceptor.clone(),
                stream,
                config.provider_delay,
                std::sync::Arc::clone(&config.requests),
                std::sync::Arc::clone(&config.done),
            ));
        }
    });
}

#[cfg(all(test, feature = "realnet"))]
fn s13_ensure_ring_crypto_provider_installed() {
    S13_RUSTLS_PROVIDER.call_once(|| {
        let _result = rustls::crypto::ring::default_provider().install_default();
    });
}

#[cfg(all(test, feature = "realnet"))]
async fn handle_s13_mock_h2_connection(
    acceptor: tokio_rustls::TlsAcceptor,
    stream: tokio::net::TcpStream,
    provider_delay: Duration,
    requests: std::sync::Arc<std::sync::Mutex<Vec<S13MockPushRequest>>>,
    done: std::sync::Arc<std::sync::Condvar>,
) {
    let Ok(tls) = acceptor.accept(stream).await else {
        return;
    };
    let Ok(mut connection) = h2::server::handshake(tls).await else {
        return;
    };
    while let Some(result) = connection.accept().await {
        let Ok((request, respond)) = result else {
            return;
        };
        let request_log = std::sync::Arc::clone(&requests);
        let done_signal = std::sync::Arc::clone(&done);
        tokio::spawn(async move {
            handle_s13_mock_h2_request(request, respond, provider_delay, request_log, done_signal)
                .await;
        });
    }
}

#[cfg(all(test, feature = "realnet"))]
async fn handle_s13_mock_h2_request(
    request: http::Request<h2::RecvStream>,
    respond: h2::server::SendResponse<bytes::Bytes>,
    provider_delay: Duration,
    requests: std::sync::Arc<std::sync::Mutex<Vec<S13MockPushRequest>>>,
    done: std::sync::Arc<std::sync::Condvar>,
) {
    let path = request.uri().path().to_owned();
    let headers = request
        .headers()
        .iter()
        .filter_map(|(key, value)| {
            Some((key.as_str().to_ascii_lowercase(), value.to_str().ok()?.to_owned()))
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    let Some(body) = read_s13_h2_body(request.into_body()).await else {
        return;
    };
    if path == "/fcm/token" {
        send_s13_h2_response(
            respond,
            200,
            br#"{"access_token":"stub_fcm_access_token","expires_in":3600}"#,
        );
        return;
    }
    let Ok(payload) = s13_provider_payload_from_body(&path, &headers, &body) else {
        send_s13_h2_response(respond, 400, b"{}");
        return;
    };
    if let Ok(mut guard) = requests.lock() {
        guard.push(S13MockPushRequest { path, headers, payload });
        done.notify_all();
    }
    if !provider_delay.is_zero() {
        tokio::time::sleep(provider_delay).await;
    }
    send_s13_h2_response(respond, 202, b"{}");
}

#[cfg(all(test, feature = "realnet"))]
async fn read_s13_h2_body(mut body_stream: h2::RecvStream) -> Option<Vec<u8>> {
    let mut body = Vec::new();
    while let Some(chunk) = body_stream.data().await {
        let Ok(chunk) = chunk else {
            return None;
        };
        body.extend_from_slice(&chunk);
    }
    Some(body)
}

#[cfg(all(test, feature = "realnet"))]
fn send_s13_h2_response(
    mut respond: h2::server::SendResponse<bytes::Bytes>,
    status: u16,
    body: &'static [u8],
) {
    let response = http::Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(());
    if let Ok(response) = response
        && let Ok(mut send) = respond.send_response(response, false)
    {
        let _ = send.send_data(bytes::Bytes::from_static(body), true);
    }
}

#[cfg(all(test, feature = "realnet"))]
#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub(crate) struct Mvp3ObjectManifestEvent {
    pub(crate) event_type: String,
    pub(crate) object_id: String,
    pub(crate) manifest_hash: String,
    pub(crate) chunk_size: usize,
    pub(crate) total_chunks: u32,
    pub(crate) object_created_group_key_epoch: Option<u64>,
}

#[cfg(all(test, feature = "realnet"))]
#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub(crate) struct Mvp3ObjectTombstoneEvent {
    pub(crate) event_type: String,
    pub(crate) object_id: String,
    pub(crate) manifest_hash: String,
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn expected_mvp3_missing_chunks(total_chunks: u32, received: &[u32]) -> Vec<u32> {
    (0..total_chunks).filter(|index| !received.contains(index)).collect()
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn remaining_mvp3_chunks<'a>(
    chunks: &'a [ramflux_sync::ChunkPayload],
    received: &[u32],
) -> Vec<&'a ramflux_sync::ChunkPayload> {
    chunks.iter().filter(|chunk| !received.contains(&chunk.chunk_index)).collect()
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) struct Mvp1LocalDbFixture {
    pub(crate) root: PathBuf,
    pub(crate) bob_key: ramflux_storage::AccountDbKey,
    pub(crate) bob_db_path: PathBuf,
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn assert_reopened_bob_local_state(
    db: &ramflux_storage::AccountDb,
    first_plaintext: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        ramflux_storage::EventStore::event_body(db, "evt_bob_identity")?,
        Some(b"bob_realnet".to_vec())
    );
    assert_eq!(
        ramflux_storage::EventStore::event_body(db, "evt_bob_device")?,
        Some(b"bob_device_realnet".to_vec())
    );
    let restored_messages = db.direct_messages("conv_mvp1_realnet")?;
    assert_eq!(restored_messages.len(), 1);
    assert_eq!(restored_messages[0].encrypted_body, first_plaintext);
    let projection = db.conversation_projection("conv_mvp1_realnet", "bob")?;
    assert_eq!(projection.message_count, 1);
    assert_eq!(projection.last_message_id.as_deref(), Some("msg_mvp1_db_1"));
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn assert_sqlcipher_file_encrypted(
    path: &Path,
    forbidden_needles: &[&[u8]],
) -> Result<(), Box<dyn std::error::Error>> {
    let bytes = fs::read(path)?;
    for needle in forbidden_needles {
        assert!(
            !contains_subslice(&bytes, needle),
            "SQLCipher file leaked forbidden bytes: {needle:?}"
        );
    }
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|window| window == needle)
}

#[cfg(test)]
pub(crate) struct FrankingEvidenceParts {
    pub(crate) plaintext: &'static [u8],
    pub(crate) sender_device_id_hash: &'static [u8],
    pub(crate) message_event_id: &'static str,
    pub(crate) canonical_header_bytes: &'static [u8],
    pub(crate) associated_data: &'static [u8],
    pub(crate) ciphertext: &'static [u8],
    pub(crate) opening_key: [u8; 32],
    pub(crate) commitment_key: [u8; 32],
}

#[cfg(test)]
#[derive(Clone)]
pub(crate) struct Mvp6KtFixture {
    pub(crate) bob_leaf_v1: ramflux_crypto::KtLeaf,
    pub(crate) bob_leaf_v1_hash: [u8; 32],
    pub(crate) bob_inclusion_proof_v1: ramflux_crypto::KtInclusionProof,
    pub(crate) old_tree_head: ramflux_crypto::KtSignedTreeHead,
    pub(crate) new_tree_head: ramflux_crypto::KtSignedTreeHead,
    pub(crate) new_leaf_hashes: Vec<[u8; 32]>,
    pub(crate) append_consistency_proof: ramflux_crypto::KtConsistencyProof,
}

#[cfg(test)]
pub(crate) fn assert_dm_double_ratchet_pcs_and_skipped_keys()
-> Result<(), Box<dyn std::error::Error>> {
    let root_seed = [0x51; 32];
    let alice_initial_ratchet = ramflux_crypto::X25519KeyPair::from_seed([0xA1; 32]);
    let bob_initial_ratchet = ramflux_crypto::X25519KeyPair::from_seed([0xB1; 32]);
    let mut alice = ramflux_crypto::DmSession::initiator_with_remote_ratchet(
        root_seed,
        [0xa1; 32],
        [0xb1; 32],
        [0xc1; 32],
        &alice_initial_ratchet,
        bob_initial_ratchet.public,
    )?;
    let mut bob = ramflux_crypto::DmSession::recipient_with_local_ratchet(
        root_seed,
        [0xb1; 32],
        [0xa1; 32],
        [0xc1; 32],
        &bob_initial_ratchet,
    )?;
    let initial_alice_root = *alice.root_key.expose();
    let initial_alice_pub = alice.ratchet_public_key().ok_or("missing alice ratchet pub")?;

    let alice_first = alice.encrypt(b"s11 alice first", b"s11-ad")?;
    assert_eq!(alice_first.ratchet_public_key, Some(initial_alice_pub));
    assert_eq!(
        bob.decrypt(&alice_first, b"s11-ad").map_err(|err| format!("alice_first: {err}"))?,
        b"s11 alice first"
    );
    assert_ne!(*bob.root_key.expose(), root_seed);

    let bob_reply = bob.encrypt(b"s11 bob reply", b"s11-ad")?;
    let bob_reply_pub = bob_reply.ratchet_public_key.ok_or("missing bob reply ratchet pub")?;
    assert_ne!(bob_reply_pub, bob_initial_ratchet.public);
    assert_ne!(*bob.root_key.expose(), root_seed);

    let mut old_chain_only = ramflux_crypto::DmSession::recipient(
        initial_alice_root,
        [0xb1; 32],
        [0xa1; 32],
        [0xc1; 32],
    )?;
    assert!(old_chain_only.decrypt(&bob_reply, b"s11-ad").is_err());
    assert_eq!(
        alice.decrypt(&bob_reply, b"s11-ad").map_err(|err| format!("bob_reply: {err}"))?,
        b"s11 bob reply"
    );
    assert_ne!(*alice.root_key.expose(), initial_alice_root);
    assert_ne!(alice.ratchet_public_key(), Some(initial_alice_pub));

    let third = alice.encrypt(b"s11 alice third", b"s11-ad")?;
    let fourth = alice.encrypt(b"s11 alice fourth", b"s11-ad")?;
    let fifth = alice.encrypt(b"s11 alice fifth", b"s11-ad")?;
    assert_eq!(
        bob.decrypt(&fifth, b"s11-ad").map_err(|err| format!("fifth: {err}"))?,
        b"s11 alice fifth"
    );
    assert_eq!(
        bob.decrypt(&third, b"s11-ad").map_err(|err| format!("third: {err}"))?,
        b"s11 alice third"
    );
    assert_eq!(
        bob.decrypt(&fourth, b"s11-ad").map_err(|err| format!("fourth: {err}"))?,
        b"s11 alice fourth"
    );

    bob.max_skip = 1;
    let sixth = alice.encrypt(b"s11 alice sixth", b"s11-ad")?;
    let seventh = alice.encrypt(b"s11 alice seventh", b"s11-ad")?;
    let eighth = alice.encrypt(b"s11 alice eighth", b"s11-ad")?;
    let _ = (sixth, seventh);
    assert!(bob.decrypt(&eighth, b"s11-ad").is_err());
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
struct S11RealnetGatewayPair {
    temp_root: PathBuf,
    alice: ramflux_sdk::RamfluxClient,
    bob: ramflux_sdk::RamfluxClient,
    alice_engine: ramflux_sdk::GatewaySessionEngine,
    bob_engine: ramflux_sdk::GatewaySessionEngine,
}

#[cfg(all(test, feature = "realnet"))]
async fn s11_realnet_gateway_pair(
    gateway_quic_addr: std::net::SocketAddr,
    ca_cert: &Path,
    gateway_url: &str,
) -> Result<S11RealnetGatewayPair, Box<dyn std::error::Error>> {
    let temp_root = std::env::temp_dir().join(format!(
        "ramflux_s11_ratchet_{}_{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos()
    ));
    if temp_root.exists() {
        std::fs::remove_dir_all(&temp_root)?;
    }
    std::fs::create_dir_all(&temp_root)?;

    let alice = mvp_s2_registered_sdk_client(
        &temp_root.join("alice"),
        "alice_s11_account",
        "principal_s11_alice",
        "alice_device_s11",
        "target_s11_alice",
        [0xA1; 32],
        [0xA2; 32],
        gateway_url,
    )?;
    let bob = mvp_s2_registered_sdk_client(
        &temp_root.join("bob"),
        "bob_s11_account",
        "principal_s11_bob",
        "bob_device_s11",
        "target_s11_bob",
        [0xB1; 32],
        [0xB2; 32],
        gateway_url,
    )?;
    let alice_config = mvp_s2_gateway_config(
        gateway_quic_addr,
        ca_cert,
        "principal_s11_alice",
        "alice_device_s11",
        "target_s11_alice",
        MvpS2GatewayTransport::Quic,
    )?;
    let bob_config = mvp_s2_gateway_config(
        gateway_quic_addr,
        ca_cert,
        "principal_s11_bob",
        "bob_device_s11",
        "target_s11_bob",
        MvpS2GatewayTransport::Quic,
    )?;
    let alice_engine = alice.connect_gateway_session(alice_config).await?;
    let bob_engine = bob.connect_gateway_session(bob_config).await?;
    assert_eq!(
        alice_engine.active_transport_kind(),
        ramflux_sdk::GatewaySessionTransportKind::Quic
    );
    assert_eq!(bob_engine.active_transport_kind(), ramflux_sdk::GatewaySessionTransportKind::Quic);
    Ok(S11RealnetGatewayPair { temp_root, alice, bob, alice_engine, bob_engine })
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn assert_dm_double_ratchet_realnet_gateway_quic(
    gateway_quic_addr: std::net::SocketAddr,
    ca_cert: &Path,
    gateway_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let S11RealnetGatewayPair { temp_root, alice, bob, mut alice_engine, mut bob_engine } =
        s11_realnet_gateway_pair(gateway_quic_addr, ca_cert, gateway_url).await?;

    let root_seed = [0x51; 32];
    let alice_initial_ratchet = ramflux_crypto::X25519KeyPair::from_seed([0xA1; 32]);
    let bob_initial_ratchet = ramflux_crypto::X25519KeyPair::from_seed([0xB1; 32]);
    let mut alice_dm = ramflux_crypto::DmSession::initiator_with_remote_ratchet(
        root_seed,
        [0xa1; 32],
        [0xb1; 32],
        [0xc1; 32],
        &alice_initial_ratchet,
        bob_initial_ratchet.public,
    )?;
    let mut bob_dm = ramflux_crypto::DmSession::recipient_with_local_ratchet(
        root_seed,
        [0xb1; 32],
        [0xa1; 32],
        [0xc1; 32],
        &bob_initial_ratchet,
    )?;

    let alice_first_plaintext = b"s11 realnet alice first ratchet";
    let alice_first = alice_dm.encrypt(alice_first_plaintext, b"s11-realnet-ad")?;
    let alice_first_body = serde_json::to_vec(&alice_first)?;
    let alice_first_message = ramflux_sdk::GatewayDirectMessage {
        conversation_id: "conv_s11_realnet".to_owned(),
        message_id: "msg_s11_alice_first".to_owned(),
        envelope_id: "env_s11_alice_first".to_owned(),
        source_principal_id: "principal_s11_alice".to_owned(),
        sender_id: "alice_s11".to_owned(),
        recipient_device_id: Some("bob_device_s11".to_owned()),
        target_delivery_id: "target_s11_bob".to_owned(),
        encrypted_body: alice_first_body,
        created_at: itest_now_unix_seconds(),
        ttl: ITEST_REPLAY_TTL_SECONDS,
    };
    let submitted =
        alice.send_direct_message_via_gateway(&mut alice_engine, alice_first_message).await?;
    assert_eq!(submitted.envelope.envelope_id, "env_s11_alice_first");
    assert_node_opaque_payload(&submitted.envelope.encrypted_payload, alice_first_plaintext);

    let bob_deliveries = bob.receive_gateway_deliveries(&mut bob_engine, 10).await?;
    let bob_received = bob_deliveries.first().ok_or("missing S11 alice ratchet delivery")?;
    assert_eq!(bob_received.envelope.envelope_id, "env_s11_alice_first");
    let bob_ciphertext_bytes =
        ramflux_protocol::decode_base64url(&bob_received.envelope.encrypted_payload)?;
    let bob_ciphertext: ramflux_crypto::DmCiphertext =
        serde_json::from_slice(&bob_ciphertext_bytes)?;
    let bob_plaintext = bob_dm.decrypt(&bob_ciphertext, b"s11-realnet-ad")?;
    assert_eq!(bob_plaintext, alice_first_plaintext);

    let bob_reply_plaintext = b"s11 realnet bob reply ratchet";
    let bob_reply = bob_dm.encrypt(bob_reply_plaintext, b"s11-realnet-ad")?;
    assert!(bob_reply.ratchet_public_key.is_some());
    let bob_reply_body = serde_json::to_vec(&bob_reply)?;
    let bob_reply_message = ramflux_sdk::GatewayDirectMessage {
        conversation_id: "conv_s11_realnet".to_owned(),
        message_id: "msg_s11_bob_reply".to_owned(),
        envelope_id: "env_s11_bob_reply".to_owned(),
        source_principal_id: "principal_s11_bob".to_owned(),
        sender_id: "bob_s11".to_owned(),
        recipient_device_id: Some("alice_device_s11".to_owned()),
        target_delivery_id: "target_s11_alice".to_owned(),
        encrypted_body: bob_reply_body,
        created_at: itest_now_unix_seconds(),
        ttl: ITEST_REPLAY_TTL_SECONDS,
    };
    let reply_submitted =
        bob.send_direct_message_via_gateway(&mut bob_engine, bob_reply_message).await?;
    assert_eq!(reply_submitted.envelope.envelope_id, "env_s11_bob_reply");
    assert_node_opaque_payload(&reply_submitted.envelope.encrypted_payload, bob_reply_plaintext);

    let alice_deliveries = alice.receive_gateway_deliveries(&mut alice_engine, 10).await?;
    let alice_received =
        alice_deliveries.first().ok_or("missing S11 bob ratchet reply delivery")?;
    assert_eq!(alice_received.envelope.envelope_id, "env_s11_bob_reply");
    let alice_ciphertext_bytes =
        ramflux_protocol::decode_base64url(&alice_received.envelope.encrypted_payload)?;
    let alice_ciphertext: ramflux_crypto::DmCiphertext =
        serde_json::from_slice(&alice_ciphertext_bytes)?;
    let alice_plaintext = alice_dm.decrypt(&alice_ciphertext, b"s11-realnet-ad")?;
    assert_eq!(alice_plaintext, bob_reply_plaintext);
    assert_ne!(*alice_dm.root_key.expose(), root_seed);
    assert_ne!(*bob_dm.root_key.expose(), root_seed);

    let _ = alice_engine.close("s11_done").await;
    let _ = bob_engine.close("s11_done").await;
    std::fs::remove_dir_all(&temp_root)?;
    Ok(())
}
