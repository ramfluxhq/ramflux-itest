// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(clippy::cast_precision_loss)]
#![allow(clippy::too_many_lines)]

use ramflux_protocol::{DeliveryClass, Envelope, Ext, Priority, SignatureAlg, SignedFields};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::task::JoinSet;

const DEFAULT_TOTAL: usize = 100_000;
const DEFAULT_CONNECTIONS: usize = 16;
const DEFAULT_INFLIGHT_PER_CONNECTION: usize = 256;
const DEFAULT_CARDINALITY: usize = 4096;
const DEFAULT_DEVICE_SIGNING_SEED: &str = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA";
const DEFAULT_GATEWAY_QUIC_ADDR: &str = "127.0.0.1:18443";
const DEFAULT_GATEWAY_SERVER_NAME: &str = "localhost";
const DEFAULT_GATEWAY_CA_CERT: &str = "../ramflux/deploy/certs/ca.pem";
const DEFAULT_FEDERATION_MESH_ENDPOINT: &str = "127.0.0.1:65453";
const DEFAULT_FEDERATION_SERVER_NAME: &str = "ramflux-federation";
const DEFAULT_SOURCE_NODE_ID: &str = "node_a.realnet";
const DEFAULT_TARGET_NODE_ID: &str = "node_b.realnet";
const DEFAULT_FEDERATION_SOURCE_CA_CERT: &str =
    "../ramflux/deploy/.itest-node-certs/ramflux-s8-perf-node-a-inbound-load/certs/ca.pem";
const DEFAULT_FEDERATION_SOURCE_CERT: &str = "../ramflux/deploy/.itest-node-certs/ramflux-s8-perf-node-a-inbound-load/certs/federation/federation.pem";
const DEFAULT_FEDERATION_SOURCE_KEY: &str = "../ramflux/deploy/.itest-node-certs/ramflux-s8-perf-node-a-inbound-load/certs/federation/federation-key.pem";
const DEFAULT_FEDERATION_PEER_CA: &str =
    "../ramflux/deploy/.itest-node-certs/ramflux-s8-perf-node-b-inbound-load/certs/ca.pem";
const DEFAULT_GATEWAY_METRICS_URL: &str = "http://127.0.0.1:18081/perf/metrics";
const DEFAULT_ROUTER_METRICS_URL: &str = "http://127.0.0.1:18080/perf/metrics";
const DEFAULT_ARTIFACT_PATH: &str = "target/ramflux_quic_loadgen_latest.json";

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum LoadgenTarget {
    GatewayQuicEnvelope,
    FederationMeshQuicInbound,
}

impl LoadgenTarget {
    fn from_env() -> Result<Self, String> {
        match env_string("RAMFLUX_LOADGEN_TARGET", "gateway_quic_envelope").as_str() {
            "gateway_quic_envelope" | "gateway_quic" | "gateway" => Ok(Self::GatewayQuicEnvelope),
            "federation_mesh_quic_inbound" | "federation_mesh_quic" | "federation_mesh" => {
                Ok(Self::FederationMeshQuicInbound)
            }
            value => Err(format!("unknown RAMFLUX_LOADGEN_TARGET {value}")),
        }
    }

    const fn wire_name(self) -> &'static str {
        match self {
            Self::GatewayQuicEnvelope => "gateway_quic_envelope",
            Self::FederationMeshQuicInbound => "federation_mesh_quic_inbound",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum SignMode {
    Pregenerated,
    Inline,
}

impl SignMode {
    fn from_env() -> Result<Self, String> {
        match env_string("RAMFLUX_LOADGEN_MODE", "pregen").as_str() {
            "pregen" | "pregenerated" => Ok(Self::Pregenerated),
            "inline" | "end_to_end" => Ok(Self::Inline),
            value => Err(format!("unknown RAMFLUX_LOADGEN_MODE {value}")),
        }
    }
}

#[derive(Clone, Debug)]
struct LoadgenConfig {
    target: LoadgenTarget,
    mode: SignMode,
    total: usize,
    connections: usize,
    inflight_per_connection: usize,
    cardinality: usize,
    created_at: i64,
    ttl: u32,
    device_signing_seed: [u8; 32],
    gateway_quic_addr: std::net::SocketAddr,
    gateway_server_name: String,
    gateway_ca_cert: PathBuf,
    federation_mesh_endpoints: Vec<String>,
    federation_server_name: String,
    federation_tls: ramflux_transport::MeshTlsConfig,
    federation_peer_ca_pems: Vec<String>,
    source_node_id: String,
    target_node_id: String,
    request_timeout: Duration,
    gateway_metrics_url: Option<String>,
    router_metrics_url: Option<String>,
    artifact_path: PathBuf,
}

#[derive(Clone)]
enum LoadgenRequest {
    Gateway(ramflux_transport::GatewayQuicRequest),
    Federation(Box<ramflux_node_core::FederatedEnvelopeForwardRequest>),
}

#[derive(Default)]
struct WorkerSummary {
    attempted: usize,
    completed: usize,
    errors: usize,
    latency_us: Vec<u128>,
    queue_wait_us: Vec<u128>,
    error_samples: BTreeMap<String, String>,
}

struct RequestMeasurement {
    latency_us: u128,
    queue_wait_us: u128,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = LoadgenConfig::from_env()?;
    let generated_at_unix = current_epoch_seconds();
    let metrics_before = MetricsSnapshot::capture(&config);
    let mesh_perf_before = ramflux_transport::mesh_perf_snapshot();
    let pregenerated = if config.mode == SignMode::Pregenerated {
        Some(Arc::new(pregenerate_requests(&config)?))
    } else {
        None
    };
    let gateway_clients = if config.target == LoadgenTarget::GatewayQuicEnvelope {
        connect_gateway_clients(&config).await?
    } else {
        Vec::new()
    };

    let started = Instant::now();
    let next_index = Arc::new(AtomicUsize::new(0));
    let mut workers = JoinSet::new();
    for worker_index in 0..config.connections {
        let worker_config = config.clone();
        let worker_next = Arc::clone(&next_index);
        let worker_requests = pregenerated.clone();
        let gateway_client = gateway_clients.get(worker_index).cloned();
        workers.spawn(run_worker(
            worker_index,
            worker_config,
            worker_next,
            worker_requests,
            gateway_client,
        ));
    }

    let mut summary = WorkerSummary::default();
    while let Some(result) = workers.join_next().await {
        match result {
            Ok(worker) => merge_summary(&mut summary, worker),
            Err(error) => {
                summary.errors = summary.errors.saturating_add(1);
                summary
                    .error_samples
                    .entry("worker_join_error".to_owned())
                    .or_insert_with(|| error.to_string());
            }
        }
    }
    let elapsed = started.elapsed();
    let metrics_after = MetricsSnapshot::capture(&config);
    let mesh_perf_after = ramflux_transport::mesh_perf_snapshot();
    let artifact_context = ArtifactContext {
        config: &config,
        generated_at_unix,
        elapsed,
        summary,
        metrics_before: &metrics_before,
        metrics_after: &metrics_after,
        mesh_perf_before: &mesh_perf_before,
        mesh_perf_after: &mesh_perf_after,
    };
    let artifact = build_artifact(artifact_context);
    write_artifact(&config.artifact_path, &artifact)?;
    println!("{}", serde_json::to_string_pretty(&artifact)?);
    eprintln!("ramflux_quic_loadgen artifact={}", config.artifact_path.display());
    Ok(())
}

impl LoadgenConfig {
    fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        let target = LoadgenTarget::from_env()?;
        let mode = SignMode::from_env()?;
        let total = env_usize("RAMFLUX_LOADGEN_TOTAL", DEFAULT_TOTAL)?.max(1);
        let connections = env_usize("RAMFLUX_LOADGEN_CONNECTIONS", DEFAULT_CONNECTIONS)?.max(1);
        let inflight_per_connection =
            env_usize("RAMFLUX_LOADGEN_INFLIGHT_PER_CONNECTION", DEFAULT_INFLIGHT_PER_CONNECTION)?
                .max(1);
        let cardinality =
            env_usize("RAMFLUX_LOADGEN_TARGET_CARDINALITY", DEFAULT_CARDINALITY)?.max(1);
        let created_at = i64::try_from(current_epoch_seconds())?;
        let ttl = env_u32("RAMFLUX_LOADGEN_TTL_SECS", 3_600)?;
        let device_signing_seed = decode_seed_env(
            "RAMFLUX_LOADGEN_DEVICE_SIGNING_SEED_B64URL",
            DEFAULT_DEVICE_SIGNING_SEED,
        )?;
        let gateway_quic_addr = env_string("RAMFLUX_LOADGEN_GATEWAY_QUIC_ADDR", "")
            .if_empty(|| env_string("RAMFLUX_ITEST_GATEWAY_QUIC_ADDR", DEFAULT_GATEWAY_QUIC_ADDR))
            .parse()?;
        let gateway_server_name =
            env_string("RAMFLUX_LOADGEN_GATEWAY_SERVER_NAME", DEFAULT_GATEWAY_SERVER_NAME);
        let gateway_ca_cert =
            PathBuf::from(env_string("RAMFLUX_LOADGEN_GATEWAY_CA_CERT", DEFAULT_GATEWAY_CA_CERT));
        let federation_mesh_endpoints = env_string("RAMFLUX_LOADGEN_FEDERATION_MESH_ENDPOINTS", "")
            .if_empty(|| {
                env_string(
                    "RAMFLUX_LOADGEN_FEDERATION_MESH_ENDPOINT",
                    DEFAULT_FEDERATION_MESH_ENDPOINT,
                )
            })
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
        let federation_server_name =
            env_string("RAMFLUX_LOADGEN_FEDERATION_SERVER_NAME", DEFAULT_FEDERATION_SERVER_NAME);
        let federation_tls = ramflux_transport::MeshTlsConfig {
            ca_cert: PathBuf::from(env_string(
                "RAMFLUX_LOADGEN_FEDERATION_SOURCE_CA_CERT",
                DEFAULT_FEDERATION_SOURCE_CA_CERT,
            )),
            service_cert: PathBuf::from(env_string(
                "RAMFLUX_LOADGEN_FEDERATION_SOURCE_CERT",
                DEFAULT_FEDERATION_SOURCE_CERT,
            )),
            service_key: PathBuf::from(env_string(
                "RAMFLUX_LOADGEN_FEDERATION_SOURCE_KEY",
                DEFAULT_FEDERATION_SOURCE_KEY,
            )),
        };
        let federation_peer_ca_pems = federation_peer_ca_pems()?;
        let source_node_id = env_string("RAMFLUX_LOADGEN_SOURCE_NODE_ID", DEFAULT_SOURCE_NODE_ID);
        let target_node_id = env_string("RAMFLUX_LOADGEN_TARGET_NODE_ID", DEFAULT_TARGET_NODE_ID);
        let request_timeout =
            Duration::from_secs(u64::from(env_u32("RAMFLUX_LOADGEN_REQUEST_TIMEOUT_SECS", 30)?));
        let gateway_metrics_url =
            env_optional_string("RAMFLUX_LOADGEN_GATEWAY_METRICS_URL", DEFAULT_GATEWAY_METRICS_URL);
        let router_metrics_url =
            env_optional_string("RAMFLUX_LOADGEN_ROUTER_METRICS_URL", DEFAULT_ROUTER_METRICS_URL);
        let artifact_path =
            PathBuf::from(env_string("RAMFLUX_LOADGEN_ARTIFACT", DEFAULT_ARTIFACT_PATH));
        if target == LoadgenTarget::FederationMeshQuicInbound
            && federation_mesh_endpoints.is_empty()
        {
            return Err("federation mesh target requires at least one endpoint".into());
        }
        Ok(Self {
            target,
            mode,
            total,
            connections,
            inflight_per_connection,
            cardinality,
            created_at,
            ttl,
            device_signing_seed,
            gateway_quic_addr,
            gateway_server_name,
            gateway_ca_cert,
            federation_mesh_endpoints,
            federation_server_name,
            federation_tls,
            federation_peer_ca_pems,
            source_node_id,
            target_node_id,
            request_timeout,
            gateway_metrics_url,
            router_metrics_url,
            artifact_path,
        })
    }

    fn make_request(&self, index: usize) -> Result<LoadgenRequest, String> {
        let target_index = index % self.cardinality;
        let target_delivery_id = loadgen_device_id(self.target.wire_name(), target_index);
        let envelope_id = format!("env_{}_{index:012}", self.target.wire_name());
        let envelope = signed_loadgen_envelope(
            &envelope_id,
            &target_delivery_id,
            self.created_at,
            self.ttl,
            self.device_signing_seed,
        )?;
        match self.target {
            LoadgenTarget::GatewayQuicEnvelope => {
                Ok(LoadgenRequest::Gateway(ramflux_transport::GatewayQuicRequest {
                    method: "POST".to_owned(),
                    path: "/mvp0/envelope".to_owned(),
                    body: serde_json::to_value(envelope).map_err(|error| error.to_string())?,
                }))
            }
            LoadgenTarget::FederationMeshQuicInbound => {
                let mut request = ramflux_node_core::FederatedEnvelopeForwardRequest {
                    signed: ramflux_node_core::default_federation_forward_signed_fields(),
                    admin_token: String::new(),
                    source_node_id: self.source_node_id.clone(),
                    target_node_id: self.target_node_id.clone(),
                    delivery_class: "opaque_event".to_owned(),
                    required_capability: "opaque_delivery".to_owned(),
                    envelope,
                };
                ramflux_node_core::sign_federated_envelope_forward(
                    &mut request,
                    realnet_node_signing_seed(&self.source_node_id),
                )
                .map_err(|error| error.to_string())?;
                Ok(LoadgenRequest::Federation(Box::new(request)))
            }
        }
    }
}

async fn connect_gateway_clients(
    config: &LoadgenConfig,
) -> Result<Vec<Arc<ramflux_transport::QuicGatewayClient>>, Box<dyn std::error::Error>> {
    let mut clients = Vec::with_capacity(config.connections);
    for _index in 0..config.connections {
        let mut client = ramflux_transport::QuicGatewayClient::connect(
            "0.0.0.0:0".parse()?,
            config.gateway_quic_addr,
            &config.gateway_server_name,
            &config.gateway_ca_cert,
            config.request_timeout,
        )
        .await?;
        client.set_session_timeout(config.request_timeout);
        clients.push(Arc::new(client));
    }
    Ok(clients)
}

fn pregenerate_requests(config: &LoadgenConfig) -> Result<Vec<LoadgenRequest>, String> {
    (0..config.total).map(|index| config.make_request(index)).collect()
}

async fn run_worker(
    worker_index: usize,
    config: LoadgenConfig,
    next_index: Arc<AtomicUsize>,
    pregenerated: Option<Arc<Vec<LoadgenRequest>>>,
    gateway_client: Option<Arc<ramflux_transport::QuicGatewayClient>>,
) -> WorkerSummary {
    let mut summary = WorkerSummary::default();
    let mut requests = JoinSet::new();
    loop {
        while requests.len() < config.inflight_per_connection {
            let index = next_index.fetch_add(1, Ordering::Relaxed);
            if index >= config.total {
                break;
            }
            let config = config.clone();
            let pregenerated = pregenerated.clone();
            let gateway_client = gateway_client.clone();
            let enqueued_at = Instant::now();
            requests.spawn(async move {
                let queue_wait_us = enqueued_at.elapsed().as_micros();
                let request = match pregenerated {
                    Some(requests) => requests
                        .get(index)
                        .cloned()
                        .ok_or_else(|| format!("missing pregenerated request index {index}"))?,
                    None => config.make_request(index)?,
                };
                let started = Instant::now();
                send_request(worker_index, index, &config, gateway_client, request).await?;
                Ok::<RequestMeasurement, String>(RequestMeasurement {
                    latency_us: started.elapsed().as_micros(),
                    queue_wait_us,
                })
            });
        }
        if requests.is_empty() {
            break;
        }
        match requests.join_next().await {
            Some(Ok(Ok(measurement))) => {
                summary.attempted = summary.attempted.saturating_add(1);
                summary.completed = summary.completed.saturating_add(1);
                summary.latency_us.push(measurement.latency_us);
                summary.queue_wait_us.push(measurement.queue_wait_us);
            }
            Some(Ok(Err(error))) => {
                summary.attempted = summary.attempted.saturating_add(1);
                record_error(&mut summary, error);
            }
            Some(Err(error)) => {
                summary.attempted = summary.attempted.saturating_add(1);
                record_error(&mut summary, format!("request_join_error: {error}"));
            }
            None => break,
        }
    }
    summary
}

async fn send_request(
    worker_index: usize,
    _index: usize,
    config: &LoadgenConfig,
    gateway_client: Option<Arc<ramflux_transport::QuicGatewayClient>>,
    request: LoadgenRequest,
) -> Result<(), String> {
    match request {
        LoadgenRequest::Gateway(request) => {
            let client = gateway_client.ok_or("gateway target missing QUIC client")?;
            let expected_target = request
                .body
                .get("target_delivery_id")
                .and_then(serde_json::Value::as_str)
                .ok_or("gateway request missing target_delivery_id")?
                .to_owned();
            let response = client.request(&request).await.map_err(|error| error.to_string())?;
            decode_gateway_submit_response(&response, &expected_target)
        }
        LoadgenRequest::Federation(request) => {
            let endpoint = config.federation_mesh_endpoints
                [worker_index % config.federation_mesh_endpoints.len()]
            .clone();
            let tls = config.federation_tls.clone();
            let server_name = config.federation_server_name.clone();
            let peer_ca_pems = config.federation_peer_ca_pems.clone();
            tokio::task::spawn_blocking(move || {
                let response: ramflux_node_core::FederatedEnvelopeForwardResponse =
                    ramflux_transport::mesh_quic_post_json_with_peer_ca_pems(
                        &endpoint,
                        "/s8/federation/envelope",
                        &tls,
                        &server_name,
                        &peer_ca_pems,
                        request.as_ref(),
                    )
                    .map_err(|error| error.to_string())?;
                validate_federation_response(&response, &request.envelope.target_delivery_id)
            })
            .await
            .map_err(|error| error.to_string())?
        }
    }
}

fn decode_gateway_submit_response(
    response: &ramflux_transport::GatewayQuicResponse,
    expected_target: &str,
) -> Result<(), String> {
    if !(200..300).contains(&response.status) {
        return Err(format!("gateway QUIC status {} body={}", response.status, response.body));
    }
    let submit: ramflux_node_core::EnvelopeSubmitResponse =
        serde_json::from_value(response.body.clone()).map_err(|error| error.to_string())?;
    if submit.outcome != "offline_queued" {
        return Err(format!("unexpected gateway outcome {}", submit.outcome));
    }
    if submit.target_delivery_id != expected_target {
        return Err(format!(
            "unexpected gateway target {}, expected {expected_target}",
            submit.target_delivery_id
        ));
    }
    if submit.inbox_seq.is_none() {
        return Err(format!("gateway response missing inbox_seq for {expected_target}"));
    }
    Ok(())
}

fn validate_federation_response(
    response: &ramflux_node_core::FederatedEnvelopeForwardResponse,
    expected_target: &str,
) -> Result<(), String> {
    if !response.accepted {
        return Err("federation response not accepted".to_owned());
    }
    if response.delivery.outcome != "offline_queued" {
        return Err(format!("unexpected federation outcome {}", response.delivery.outcome));
    }
    if response.delivery.target_delivery_id != expected_target {
        return Err(format!(
            "unexpected federation target {}, expected {expected_target}",
            response.delivery.target_delivery_id
        ));
    }
    if response.delivery.inbox_seq.is_none() {
        return Err(format!("federation response missing inbox_seq for {expected_target}"));
    }
    Ok(())
}

fn signed_loadgen_envelope(
    envelope_id: &str,
    target_delivery_id: &str,
    created_at: i64,
    ttl: u32,
    seed: [u8; 32],
) -> Result<Envelope, String> {
    let encrypted_payload = format!("ciphertext_{envelope_id}");
    let mut envelope = Envelope {
        schema: ramflux_protocol::domain::ENVELOPE.to_owned(),
        version: 1,
        domain: ramflux_protocol::domain::ENVELOPE.to_owned(),
        ext: Ext::default(),
        signed: SignedFields {
            signing_key_id: "loadgen-device-ed25519-v1".to_owned(),
            signature_alg: SignatureAlg::Ed25519,
            signature: String::new(),
        },
        envelope_id: envelope_id.to_owned(),
        source_principal_id: "principal_loadgen".to_owned(),
        source_device_id: "device_loadgen".to_owned(),
        target_delivery_id: target_delivery_id.to_owned(),
        routing_set_id: None,
        delivery_class: DeliveryClass::OpaqueEvent,
        priority: Priority::Normal,
        ttl,
        created_at,
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

#[derive(serde::Serialize)]
struct MetricsSnapshot {
    gateway: Option<serde_json::Value>,
    router: Option<serde_json::Value>,
}

impl MetricsSnapshot {
    fn capture(config: &LoadgenConfig) -> Self {
        Self {
            gateway: config.gateway_metrics_url.as_deref().and_then(fetch_json_metric),
            router: config.router_metrics_url.as_deref().and_then(fetch_json_metric),
        }
    }
}

fn fetch_json_metric(url: &str) -> Option<serde_json::Value> {
    match ramflux_node_core::itest_http_get_json(url) {
        Ok(value) => Some(value),
        Err(error) => {
            eprintln!("ramflux_quic_loadgen metric_fetch_error url={url} error={error}");
            None
        }
    }
}

struct ArtifactContext<'a> {
    config: &'a LoadgenConfig,
    generated_at_unix: u64,
    elapsed: Duration,
    summary: WorkerSummary,
    metrics_before: &'a MetricsSnapshot,
    metrics_after: &'a MetricsSnapshot,
    mesh_perf_before: &'a ramflux_transport::MeshHttpPerfSnapshot,
    mesh_perf_after: &'a ramflux_transport::MeshHttpPerfSnapshot,
}

fn build_artifact(context: ArtifactContext<'_>) -> serde_json::Value {
    let config = context.config;
    let mut summary = context.summary;
    summary.latency_us.sort_unstable();
    summary.queue_wait_us.sort_unstable();
    let completed = summary.completed;
    let attempted = summary.attempted;
    let elapsed_secs = context.elapsed.as_secs_f64().max(f64::EPSILON);
    let throughput = completed as f64 / elapsed_secs;
    let error_rate = if attempted == 0 { 0.0 } else { summary.errors as f64 / attempted as f64 };
    serde_json::json!({
        "schema": "ramflux.itest.quic_loadgen.result.v1",
        "generated_at_unix": context.generated_at_unix,
        "target": config.target,
        "mode": config.mode,
        "connections": config.connections,
        "inflight_per_connection": config.inflight_per_connection,
        "total_configured": config.total,
        "target_cardinality": config.cardinality,
        "ttl_seconds": config.ttl,
        "elapsed_ms": context.elapsed.as_millis(),
        "attempted": attempted,
        "completed": completed,
        "errors": summary.errors,
        "error_rate": error_rate,
        "throughput_envelopes_per_sec": throughput,
        "latency": latency_summary(&summary.latency_us),
        "client_queue_wait": latency_summary(&summary.queue_wait_us),
        "error_samples": summary.error_samples,
        "metrics": {
            "gateway_url": config.gateway_metrics_url,
            "router_url": config.router_metrics_url,
            "before": context.metrics_before,
            "after": context.metrics_after,
            "delta": {
                "gateway": metrics_delta("gateway", context.metrics_before.gateway.as_ref(), context.metrics_after.gateway.as_ref(), completed),
                "router": metrics_delta("router", context.metrics_before.router.as_ref(), context.metrics_after.router.as_ref(), completed)
            }
        },
        "mesh_transport": {
            "before": context.mesh_perf_before,
            "after": context.mesh_perf_after
        },
        "baseline_note": match config.target {
            LoadgenTarget::GatewayQuicEnvelope => "gateway QUIC ingress load; N persistent QuicGatewayClient connections and M inflight bidirectional streams per connection; signed envelopes can be pregenerated outside the measured window.",
            LoadgenTarget::FederationMeshQuicInbound => "federation mesh QUIC inbound load; direct /s8/federation/envelope mesh request path, bypassing the /s8/federation/forward HTTP ingress. ramflux_transport mesh client caches persistent connections per endpoint.",
        }
    })
}

fn metrics_delta(
    service: &str,
    before: Option<&serde_json::Value>,
    after: Option<&serde_json::Value>,
    completed: usize,
) -> serde_json::Value {
    let Some(before) = before else {
        return serde_json::Value::Null;
    };
    let Some(after) = after else {
        return serde_json::Value::Null;
    };
    match service {
        "gateway" => serde_json::json!({
            "gateway_submit_received_delta": json_delta(before, after, "/node/gateway_submit_received_total")
        }),
        "router" => {
            let accepted = json_delta(before, after, "/node/router_envelope_accepted_total");
            let denominator = accepted.max(u64::try_from(completed).unwrap_or(u64::MAX));
            serde_json::json!({
                "router_envelope_accepted_delta": accepted,
                "router_replay_guard_checks_delta": json_delta(before, after, "/node/router_replay_guard_checks_total"),
                "router_replay_guard_redb_writes_delta": json_delta(before, after, "/node/router_replay_guard_redb_writes_total"),
                "router_submit_total_avg_us": json_avg_delta(before, after, "/node/router_submit_total_us_total", denominator),
                "router_submit_save_avg_us": json_avg_delta(before, after, "/node/router_submit_save_us_total", denominator),
                "router_submit_dispatch_avg_us": json_avg_delta(before, after, "/node/router_submit_dispatch_us_total", denominator),
                "router_submit_response_avg_us": json_avg_delta(before, after, "/node/router_submit_response_us_total", denominator),
                "router_replay_guard_check_avg_us": json_avg_delta(before, after, "/node/router_replay_guard_check_us_total", json_delta(before, after, "/node/router_replay_guard_checks_total")),
                "router_save_total_avg_us": json_avg_delta(before, after, "/node/router_save_total_us_total", denominator),
                "router_save_inbox_avg_us": json_avg_delta(before, after, "/node/router_save_inbox_us_total", denominator),
                "router_save_replay_guard_avg_us": json_avg_delta(before, after, "/node/router_save_replay_guard_us_total", denominator),
                "router_save_begin_write_avg_us": json_avg_delta(before, after, "/node/router_save_begin_write_us_total", denominator),
                "router_save_mutation_avg_us": json_avg_delta(before, after, "/node/router_save_mutation_us_total", denominator),
                "router_save_commit_avg_us": json_avg_delta(before, after, "/node/router_save_commit_us_total", denominator)
            })
        }
        _ => serde_json::Value::Null,
    }
}

fn json_delta(before: &serde_json::Value, after: &serde_json::Value, pointer: &str) -> u64 {
    json_u64(after, pointer).saturating_sub(json_u64(before, pointer))
}

fn json_avg_delta(
    before: &serde_json::Value,
    after: &serde_json::Value,
    pointer: &str,
    denominator: u64,
) -> Option<f64> {
    if denominator == 0 {
        return None;
    }
    Some(json_delta(before, after, pointer) as f64 / denominator as f64)
}

fn json_u64(value: &serde_json::Value, pointer: &str) -> u64 {
    value.pointer(pointer).and_then(serde_json::Value::as_u64).unwrap_or_default()
}

fn latency_summary(values: &[u128]) -> serde_json::Value {
    if values.is_empty() {
        return serde_json::json!({
            "count": 0,
            "p50_us": null,
            "p95_us": null,
            "p99_us": null,
            "max_us": null
        });
    }
    serde_json::json!({
        "count": values.len(),
        "p50_us": percentile(values, 50),
        "p95_us": percentile(values, 95),
        "p99_us": percentile(values, 99),
        "max_us": values[values.len() - 1]
    })
}

fn percentile(values: &[u128], percentile: usize) -> u128 {
    let last = values.len().saturating_sub(1);
    let index = last.saturating_mul(percentile) / 100;
    values[index]
}

fn merge_summary(total: &mut WorkerSummary, worker: WorkerSummary) {
    total.attempted = total.attempted.saturating_add(worker.attempted);
    total.completed = total.completed.saturating_add(worker.completed);
    total.errors = total.errors.saturating_add(worker.errors);
    total.latency_us.extend(worker.latency_us);
    total.queue_wait_us.extend(worker.queue_wait_us);
    for (category, sample) in worker.error_samples {
        total.error_samples.entry(category).or_insert(sample);
    }
}

fn record_error(summary: &mut WorkerSummary, error: String) {
    summary.errors = summary.errors.saturating_add(1);
    let category = error_category(&error);
    summary.error_samples.entry(category).or_insert(error);
}

fn error_category(error: &str) -> String {
    error
        .split([':', '\n'])
        .next()
        .filter(|value| !value.is_empty())
        .unwrap_or("request_error")
        .chars()
        .take(80)
        .collect()
}

fn write_artifact(
    path: &Path,
    value: &serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = path.parent().filter(|parent| !parent.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_vec_pretty(value)?)?;
    Ok(())
}

fn federation_peer_ca_pems() -> Result<Vec<String>, Box<dyn std::error::Error>> {
    if let Some(pem) = env_optional_string("RAMFLUX_LOADGEN_FEDERATION_PEER_CA_PEM", "") {
        return Ok(vec![pem]);
    }
    let file = env_string("RAMFLUX_LOADGEN_FEDERATION_PEER_CA_FILE", DEFAULT_FEDERATION_PEER_CA);
    Ok(vec![std::fs::read_to_string(file)?])
}

fn decode_seed_env(name: &str, default_seed: &str) -> Result<[u8; 32], String> {
    let seed = std::env::var(name).unwrap_or_else(|_| default_seed.to_owned());
    ramflux_node_core::decode_node_service_signing_seed(&seed).map_err(|error| error.to_string())
}

fn realnet_node_signing_seed(node_id: &str) -> [u8; 32] {
    ramflux_crypto::blake3_256("ramflux.itest.realnet.federation_node_key.v1", node_id.as_bytes())
}

fn loadgen_device_id(prefix: &str, index: usize) -> String {
    format!("{prefix}_target_{index:06}")
}

fn current_epoch_seconds() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |duration| duration.as_secs())
}

fn env_string(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_owned())
}

fn env_optional_string(name: &str, default: &str) -> Option<String> {
    let value = env_string(name, default);
    (!value.is_empty()).then_some(value)
}

fn env_usize(name: &str, default: usize) -> Result<usize, Box<dyn std::error::Error>> {
    match std::env::var(name) {
        Ok(value) => Ok(value.parse()?),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(Box::new(error)),
    }
}

fn env_u32(name: &str, default: u32) -> Result<u32, Box<dyn std::error::Error>> {
    match std::env::var(name) {
        Ok(value) => Ok(value.parse()?),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(Box::new(error)),
    }
}

trait EmptyStringExt {
    fn if_empty<F>(self, fallback: F) -> Self
    where
        F: FnOnce() -> Self;
}

impl EmptyStringExt for String {
    fn if_empty<F>(self, fallback: F) -> Self
    where
        F: FnOnce() -> Self,
    {
        if self.is_empty() { fallback() } else { self }
    }
}
