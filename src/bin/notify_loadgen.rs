// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, Uri};
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use hyper_util::rt::TokioExecutor;
use ramflux_protocol::{
    DeliveryClass, Envelope, Ext, NotificationDeliveryClass, NotificationWake, Priority,
    PushPriority, SignatureAlg, SignedFields,
};
use std::convert::Infallible;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::task::JoinSet;

const DEFAULT_CONNS: usize = 256;
const DEFAULT_INFLIGHT: usize = 64;
const DEFAULT_TOTAL: usize = 1_000_000;
const DEFAULT_CARDINALITY: usize = 4096;
const DEFAULT_NODE_SERVICE_SEED: &str = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA";
const DEFAULT_RELAY_SERVICE_KEY: &[u8] = b"ramflux-relay-itest-service-key";

type LoadgenClient = Client<HttpConnector, Full<Bytes>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LoadgenTarget {
    NotifyWake,
    GatewayEnvelope,
    FederationForward,
    RelayObject,
}

impl LoadgenTarget {
    fn from_env() -> Result<Self, String> {
        match env_string("RAMFLUX_LOADGEN_TARGET", "notify_wake").as_str() {
            "notify_wake" | "notify" => Ok(Self::NotifyWake),
            "gateway_envelope" | "gateway" => Ok(Self::GatewayEnvelope),
            "federation_forward" | "federation" => Ok(Self::FederationForward),
            "relay_object" | "relay" => Ok(Self::RelayObject),
            value => Err(format!("unknown RAMFLUX_LOADGEN_TARGET {value}")),
        }
    }

    const fn wire_name(self) -> &'static str {
        match self {
            Self::NotifyWake => "notify_wake",
            Self::GatewayEnvelope => "gateway_envelope",
            Self::FederationForward => "federation_forward",
            Self::RelayObject => "relay_object",
        }
    }

    const fn default_url(self) -> &'static str {
        match self {
            Self::NotifyWake => "http://127.0.0.1:18083/s13/notify/wake",
            Self::GatewayEnvelope => "http://127.0.0.1:18081/mvp0/envelope",
            Self::FederationForward => "http://127.0.0.1:18082/s8/federation/forward",
            Self::RelayObject => "http://127.0.0.1:18084/relay/v1/object/put_chunk",
        }
    }
}

#[derive(Clone, Debug)]
struct LoadgenConfig {
    target: LoadgenTarget,
    uri: Uri,
    conns: usize,
    inflight: usize,
    total: usize,
    cardinality: usize,
    node_service_seed: [u8; 32],
    device_signing_seed: [u8; 32],
    federation_source_seed: Option<[u8; 32]>,
    source_node_id: String,
    target_node_id: String,
    relay_service_key: Arc<Vec<u8>>,
}

#[derive(Clone, Debug)]
struct LoadgenCounters {
    next_request: Arc<AtomicUsize>,
    completed: Arc<AtomicUsize>,
    errors: Arc<AtomicUsize>,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = LoadgenConfig::from_env()?;
    let client = loadgen_client();
    let counters = LoadgenCounters {
        next_request: Arc::new(AtomicUsize::new(0)),
        completed: Arc::new(AtomicUsize::new(0)),
        errors: Arc::new(AtomicUsize::new(0)),
    };
    let started = Instant::now();
    let mut workers = JoinSet::new();

    for _worker_index in 0..config.conns {
        workers.spawn(run_loadgen_worker(client.clone(), config.clone(), counters.clone()));
    }

    while let Some(result) = workers.join_next().await {
        match result {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                counters.errors.fetch_add(1, Ordering::Relaxed);
                eprintln!("ramflux_loadgen worker_error={error}");
            }
            Err(error) => {
                counters.errors.fetch_add(1, Ordering::Relaxed);
                eprintln!("ramflux_loadgen worker_join_error={error}");
            }
        }
    }

    let elapsed = started.elapsed();
    let elapsed_secs = elapsed.as_secs_f64().max(f64::EPSILON);
    let completed = counters.completed.load(Ordering::Relaxed);
    let errors = counters.errors.load(Ordering::Relaxed);
    #[allow(clippy::cast_precision_loss)]
    let per_sec = completed as f64 / elapsed_secs;
    println!(
        "LOADGEN target={} per_sec={per_sec:.2} completed={completed} total={} elapsed_ms={} errors={errors}",
        config.target.wire_name(),
        config.total,
        elapsed.as_millis()
    );
    Ok(())
}

impl LoadgenConfig {
    fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        let target = LoadgenTarget::from_env()?;
        let uri = env_string("RAMFLUX_LOADGEN_URL", target.default_url()).parse::<Uri>()?;
        let conns = env_usize("RAMFLUX_LOADGEN_CONNS", DEFAULT_CONNS)?.max(1);
        let inflight = env_usize("RAMFLUX_LOADGEN_INFLIGHT", DEFAULT_INFLIGHT)?.max(1);
        let total = env_usize("RAMFLUX_LOADGEN_TOTAL", DEFAULT_TOTAL)?.max(1);
        let cardinality = env_usize("RAMFLUX_LOADGEN_TARGET_CARDINALITY", DEFAULT_CARDINALITY)
            .or_else(|_| env_usize("RAMFLUX_LOADGEN_DEVICE_CARDINALITY", DEFAULT_CARDINALITY))?
            .max(1);
        let node_service_seed = decode_seed_env(
            ramflux_node_core::NODE_SERVICE_SIGNING_SEED_ENV,
            DEFAULT_NODE_SERVICE_SEED,
        )?;
        let device_signing_seed = decode_seed_env(
            "RAMFLUX_LOADGEN_DEVICE_SIGNING_SEED_B64URL",
            DEFAULT_NODE_SERVICE_SEED,
        )?;
        let source_node_id = env_string("RAMFLUX_LOADGEN_SOURCE_NODE_ID", "node_a.realnet");
        let target_node_id = env_string("RAMFLUX_LOADGEN_TARGET_NODE_ID", "node_b.realnet");
        let federation_source_seed =
            decode_optional_seed_env("RAMFLUX_LOADGEN_FEDERATION_SOURCE_SEED_B64URL")?;
        let relay_service_key = Arc::new(
            std::env::var("RAMFLUX_LOADGEN_RELAY_SERVICE_KEY")
                .map_or_else(|_| DEFAULT_RELAY_SERVICE_KEY.to_vec(), String::into_bytes),
        );
        Ok(Self {
            target,
            uri,
            conns,
            inflight,
            total,
            cardinality,
            node_service_seed,
            device_signing_seed,
            federation_source_seed,
            source_node_id,
            target_node_id,
            relay_service_key,
        })
    }

    fn request_body(&self, request_index: usize) -> Result<Vec<u8>, String> {
        match self.target {
            LoadgenTarget::NotifyWake => notify_loadgen_wake_body(request_index, self),
            LoadgenTarget::GatewayEnvelope => gateway_envelope_body(request_index, self),
            LoadgenTarget::FederationForward => federation_forward_body(request_index, self),
            LoadgenTarget::RelayObject => relay_object_body(request_index, self),
        }
    }
}

fn loadgen_client() -> LoadgenClient {
    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    Client::builder(TokioExecutor::new()).pool_max_idle_per_host(usize::MAX).build(connector)
}

async fn run_loadgen_worker(
    client: LoadgenClient,
    config: LoadgenConfig,
    counters: LoadgenCounters,
) -> Result<(), Infallible> {
    let mut requests = JoinSet::new();
    loop {
        while requests.len() < config.inflight {
            let Some(request_index) = next_request_index(&config, &counters) else {
                break;
            };
            requests.spawn(send_loadgen_request(client.clone(), config.clone(), request_index));
        }
        if requests.is_empty() {
            break;
        }
        match requests.join_next().await {
            Some(Ok(Ok(()))) => {
                counters.completed.fetch_add(1, Ordering::Relaxed);
            }
            Some(Ok(Err(error))) => {
                counters.errors.fetch_add(1, Ordering::Relaxed);
                eprintln!("ramflux_loadgen request_error={error}");
            }
            Some(Err(error)) => {
                counters.errors.fetch_add(1, Ordering::Relaxed);
                eprintln!("ramflux_loadgen request_join_error={error}");
            }
            None => break,
        }
    }
    Ok(())
}

fn next_request_index(config: &LoadgenConfig, counters: &LoadgenCounters) -> Option<usize> {
    let request_index = counters.next_request.fetch_add(1, Ordering::Relaxed);
    (request_index < config.total).then_some(request_index)
}

async fn send_loadgen_request(
    client: LoadgenClient,
    config: LoadgenConfig,
    request_index: usize,
) -> Result<(), String> {
    let body = Bytes::from(config.request_body(request_index)?);
    match send_loadgen_request_once(client.clone(), &config, body.clone()).await {
        Ok(()) => Ok(()),
        Err(error) if error.starts_with("transport:") => {
            send_loadgen_request_once(client, &config, body)
                .await
                .map_err(|retry_error| format!("{error}; retry_error={retry_error}"))
        }
        Err(error) => Err(error),
    }
}

async fn send_loadgen_request_once(
    client: LoadgenClient,
    config: &LoadgenConfig,
    body: Bytes,
) -> Result<(), String> {
    let request = Request::builder()
        .method(Method::POST)
        .uri(config.uri.clone())
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .header(hyper::header::CONNECTION, "keep-alive")
        .body(Full::new(body))
        .map_err(|error| error.to_string())?;
    let response = client.request(request).await.map_err(|error| format!("transport: {error}"))?;
    let status = response.status();
    let body = response
        .into_body()
        .collect()
        .await
        .map_err(|error| format!("transport: {error}"))?
        .to_bytes();
    if !status.is_success() {
        let sample = String::from_utf8_lossy(&body);
        return Err(format!(
            "{} returned status {status}: {}",
            config.target.wire_name(),
            sample.chars().take(240).collect::<String>()
        ));
    }
    Ok(())
}

fn notify_loadgen_wake_body(wake_index: usize, config: &LoadgenConfig) -> Result<Vec<u8>, String> {
    let device_index = wake_index % config.cardinality;
    let mut wake = notify_loadgen_wake(wake_index, device_index);
    sign_notify_loadgen_wake(&mut wake, config.node_service_seed)?;
    serde_json::to_vec(&serde_json::json!({
        "device_delivery_id": notify_loadgen_device_id(device_index),
        "wake": wake,
        "queued_at": 1_760_000_000_u64 + u64::try_from(wake_index).unwrap_or(u64::MAX),
        "dnd_active": false
    }))
    .map_err(|error| error.to_string())
}

fn notify_loadgen_wake(wake_index: usize, device_index: usize) -> NotificationWake {
    NotificationWake {
        schema: ramflux_protocol::domain::NOTIFICATION_WAKE.to_owned(),
        version: 1,
        domain: ramflux_protocol::domain::NOTIFICATION_WAKE.to_owned(),
        ext: Ext::default(),
        signed: signed_fields(ramflux_node_core::NODE_SERVICE_SIGNING_KEY_ID),
        wake_id: format!("wake_notify_perf_{wake_index:06}"),
        push_alias: format!("notify_perf_alias_{device_index}"),
        delivery_class: NotificationDeliveryClass::UserContentNotification,
        priority: PushPriority::Normal,
        ttl: 86_400,
        collapse_key: Some(format!("target:{}:content", notify_loadgen_device_id(device_index))),
        encrypted_hint: Some(format!("notify_perf_encrypted_hint_{wake_index:06}")),
    }
}

fn sign_notify_loadgen_wake(wake: &mut NotificationWake, seed: [u8; 32]) -> Result<(), String> {
    ramflux_node_core::NODE_SERVICE_SIGNING_KEY_ID.clone_into(&mut wake.signed.signing_key_id);
    wake.signed.signature_alg = SignatureAlg::Ed25519;
    wake.signed.signature = ramflux_crypto::sign_protocol_object_with_seed(wake, seed)
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn gateway_envelope_body(index: usize, config: &LoadgenConfig) -> Result<Vec<u8>, String> {
    let target_index = index % config.cardinality;
    let envelope = signed_loadgen_envelope(
        "env_loadgen_gateway",
        index,
        &loadgen_device_id("target_loadgen_gateway", target_index),
        config.device_signing_seed,
    )?;
    serde_json::to_vec(&envelope).map_err(|error| error.to_string())
}

fn federation_forward_body(index: usize, config: &LoadgenConfig) -> Result<Vec<u8>, String> {
    let target_index = index % config.cardinality;
    let envelope = signed_loadgen_envelope(
        "env_loadgen_federation",
        index,
        &loadgen_device_id("target_loadgen_federation", target_index),
        config.device_signing_seed,
    )?;
    let mut request = ramflux_node_core::FederatedEnvelopeForwardRequest {
        signed: ramflux_node_core::default_federation_forward_signed_fields(),
        admin_token: String::new(),
        source_node_id: config.source_node_id.clone(),
        target_node_id: config.target_node_id.clone(),
        delivery_class: "opaque_event".to_owned(),
        required_capability: "opaque_delivery".to_owned(),
        envelope,
    };
    let source_seed = config
        .federation_source_seed
        .unwrap_or_else(|| realnet_loadgen_node_signing_seed(&config.source_node_id));
    ramflux_node_core::sign_federated_envelope_forward(&mut request, source_seed)
        .map_err(|error| error.to_string())?;
    serde_json::to_vec(&request).map_err(|error| error.to_string())
}

fn signed_loadgen_envelope(
    prefix: &str,
    index: usize,
    target_delivery_id: &str,
    seed: [u8; 32],
) -> Result<Envelope, String> {
    let encrypted_payload = format!("ciphertext_{prefix}_{index:012}");
    let mut envelope = Envelope {
        schema: ramflux_protocol::domain::ENVELOPE.to_owned(),
        version: 1,
        domain: ramflux_protocol::domain::ENVELOPE.to_owned(),
        ext: Ext::default(),
        signed: signed_fields("loadgen-device-ed25519-v1"),
        envelope_id: format!("{prefix}_{index:012}"),
        source_principal_id: "principal_loadgen".to_owned(),
        source_device_id: "device_loadgen".to_owned(),
        target_delivery_id: target_delivery_id.to_owned(),
        routing_set_id: None,
        delivery_class: DeliveryClass::OpaqueEvent,
        priority: Priority::Normal,
        ttl: 3_600,
        created_at: 1_760_000_000_i64 + i64::try_from(index).unwrap_or(i64::MAX),
        payload_hash: ramflux_crypto::blake3_256_base64url(
            "ramflux.loadgen.envelope_payload.v1",
            encrypted_payload.as_bytes(),
        ),
        encrypted_payload,
    };
    envelope.signed.signature = ramflux_crypto::sign_protocol_object_with_seed(&envelope, seed)
        .map_err(|error| error.to_string())?;
    Ok(envelope)
}

fn relay_object_body(index: usize, config: &LoadgenConfig) -> Result<Vec<u8>, String> {
    let target_index = index % config.cardinality;
    let now = current_epoch_seconds();
    let object_id = format!("object_mvp3_loadgen_{target_index:06}_{index:012}");
    let object_plaintext = format!("mvp3 relay loadgen object plaintext {index:012}").into_bytes();
    let manifest =
        ramflux_sync::chunk_manifest_for_object(&object_id, &object_plaintext, 1024, Some(3));
    let chunk = ramflux_sync::chunk_payload(&[0xA5; 32], &manifest, 0, &object_plaintext);
    let chunk_id = format!("{}:{}", manifest.object_id, chunk.chunk_index);
    let mut token = relay_loadgen_token(
        &config.relay_service_key,
        index,
        &manifest.object_id,
        &manifest.manifest_hash,
        &chunk_id,
        now,
    )?;
    let permission = relay_loadgen_permission(&manifest.object_id, &manifest.manifest_hash, now)?;
    token.mac = ramflux_node_core::relay_token_mac(&config.relay_service_key, &token)
        .map_err(|error| error.to_string())?;
    let frame = ramflux_node_core::ObjectChunkFrame {
        schema: "ramflux.object_chunk_frame.v1".to_owned(),
        object_id: manifest.object_id,
        manifest_hash: manifest.manifest_hash,
        chunk_index: chunk.chunk_index,
        chunk_id,
        chunk_cipher_hash: chunk.cipher_hash,
        cipher_size: u64::try_from(chunk.ciphertext.len()).unwrap_or(u64::MAX),
        encrypted_chunk: chunk.ciphertext,
        relay_token: token,
        object_permission_envelope: permission,
        expires_at: now + ramflux_node_core::OBJECT_RELAY_CHUNK_DEFAULT_TTL_SECONDS,
        delete_after_ack: true,
    };
    serde_json::to_vec(&frame).map_err(|error| error.to_string())
}

fn relay_loadgen_token(
    service_key: &[u8],
    index: usize,
    object_id: &str,
    manifest_hash: &str,
    chunk_id: &str,
    now: u64,
) -> Result<ramflux_node_core::RelayToken, String> {
    let mut token = ramflux_node_core::RelayToken {
        token_id: format!("relay_loadgen_token_{index:012}"),
        object_id: object_id.to_owned(),
        manifest_hash: manifest_hash.to_owned(),
        chunk_id: chunk_id.to_owned(),
        recipient_device_hash: "loadgen_recipient_device_hash".to_owned(),
        owner_signing_key_id: "loadgen_owner_fixture".to_owned(),
        owner_public_key: ramflux_crypto::fixture_public_key_base64url(),
        issuer_service: "router".to_owned(),
        audience_service: "ramflux-relay".to_owned(),
        token_version: ramflux_node_core::OBJECT_RELAY_TOKEN_VERSION,
        capabilities: vec![ramflux_node_core::ObjectRelayCapability::Put],
        delete_after_ack: true,
        issued_at: now,
        expires_at: now + ramflux_node_core::OBJECT_RELAY_CHUNK_DEFAULT_TTL_SECONDS,
        nonce: format!("relay_loadgen_nonce_{index:012}"),
        mac: String::new(),
    };
    token.mac = ramflux_node_core::relay_token_mac(service_key, &token)
        .map_err(|error| error.to_string())?;
    Ok(token)
}

fn relay_loadgen_permission(
    object_id: &str,
    manifest_hash: &str,
    now: u64,
) -> Result<ramflux_node_core::ObjectPermissionEnvelope, String> {
    let mut permission = ramflux_node_core::ObjectPermissionEnvelope {
        object_id: object_id.to_owned(),
        manifest_hash: manifest_hash.to_owned(),
        grantee_device_hash: "loadgen_recipient_device_hash".to_owned(),
        capability: ramflux_node_core::ObjectRelayCapability::Put,
        issued_at: now,
        expires_at: now + ramflux_node_core::OBJECT_RELAY_CHUNK_DEFAULT_TTL_SECONDS,
        owner_signing_key_id: "loadgen_owner_fixture".to_owned(),
        owner_public_key: ramflux_crypto::fixture_public_key_base64url(),
        owner_signature: String::new(),
    };
    permission.owner_signature = ramflux_crypto::sign_canonical_bytes(
        &ramflux_node_core::object_permission_canonical_bytes(&permission)
            .map_err(|error| error.to_string())?,
    );
    Ok(permission)
}

fn signed_fields(signing_key_id: &str) -> SignedFields {
    SignedFields {
        signing_key_id: signing_key_id.to_owned(),
        signature_alg: SignatureAlg::Ed25519,
        signature: String::new(),
    }
}

fn decode_seed_env(name: &str, default_seed: &str) -> Result<[u8; 32], String> {
    let seed = std::env::var(name).unwrap_or_else(|_| default_seed.to_owned());
    ramflux_node_core::decode_node_service_signing_seed(&seed).map_err(|error| error.to_string())
}

fn decode_optional_seed_env(name: &str) -> Result<Option<[u8; 32]>, String> {
    match std::env::var(name) {
        Ok(seed) => ramflux_node_core::decode_node_service_signing_seed(&seed)
            .map(Some)
            .map_err(|error| error.to_string()),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(error) => Err(error.to_string()),
    }
}

fn realnet_loadgen_node_signing_seed(node_id: &str) -> [u8; 32] {
    ramflux_crypto::blake3_256("ramflux.itest.realnet.federation_node_key.v1", node_id.as_bytes())
}

fn notify_loadgen_device_id(index: usize) -> String {
    format!("target_s13_notify_perf_{index:04}")
}

fn loadgen_device_id(prefix: &str, index: usize) -> String {
    format!("{prefix}_{index:06}")
}

fn current_epoch_seconds() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |duration| duration.as_secs())
}

fn env_string(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_owned())
}

fn env_usize(name: &str, default: usize) -> Result<usize, Box<dyn std::error::Error>> {
    match std::env::var(name) {
        Ok(value) => Ok(value.parse()?),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(Box::new(error)),
    }
}
