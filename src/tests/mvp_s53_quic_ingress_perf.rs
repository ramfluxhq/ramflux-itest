// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(clippy::cast_precision_loss)]
// Perf plan constants below are consumed only by the realnet-gated test in this module; keep
// them available in all test builds but silence dead_code when realnet is compiled out.
#![cfg_attr(not(feature = "realnet"), allow(dead_code))]

use crate::quic_loadgen_core::{LoadgenConfig, run_loadgen};
use crate::*;
use serde_json::json;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_CONNECTIONS: usize = 32;
const DEFAULT_INFLIGHT: usize = 128;
const DEFAULT_TOTAL: usize = 200_000;
const DEFAULT_CARDINALITY: usize = 4096;
const DEFAULT_WAL_COMMIT_WINDOW_US: u64 = 200;

#[cfg(feature = "realnet")]
#[test]
#[allow(clippy::too_many_lines)]
fn mvp_s53_realnet_quic_ingress_wal_window_compare() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping s53 QUIC ingress perf; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }
    if std::env::var("RAMFLUX_ITEST_PERF").as_deref() != Ok("1") {
        eprintln!("skipping s53 QUIC ingress perf; set RAMFLUX_ITEST_PERF=1");
        return Ok(());
    }

    let plan = S53PerfPlan::from_env()?;
    let off = run_s53_stage(&plan, S53Stage::WalWindowOff)?;
    let on = run_s53_stage(&plan, S53Stage::WalWindowOn)?;
    assert_s53_min_throughput(&plan, &on)?;
    let comparison = build_s53_comparison(&plan, &off, &on);
    let artifact = s53_artifact_path("mvp_s53_quic_ingress_wal_window_compare_latest.json")?;
    std::fs::write(&artifact, serde_json::to_vec_pretty(&comparison)?)?;
    eprintln!("RAMFLUX_PERF_STAGE {}", serde_json::to_string(&comparison)?);
    eprintln!("mvp_s53 QUIC ingress comparison artifact={}", artifact.display());
    Ok(())
}

#[cfg(feature = "realnet")]
#[derive(Clone, Debug, serde::Serialize)]
struct S53PerfPlan {
    connections: usize,
    inflight_per_connection: usize,
    total: usize,
    target_cardinality: usize,
    gateway_compio: bool,
    server_transport: String,
    wal_commit_window_on_us: u64,
    min_throughput_per_sec: f64,
}

#[cfg(feature = "realnet")]
impl S53PerfPlan {
    fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        let wal_commit_window_on_us =
            env_u64("RAMFLUX_PERF_WAL_COMMIT_WINDOW_US", DEFAULT_WAL_COMMIT_WINDOW_US)?;
        if wal_commit_window_on_us == 0 {
            return Err("RAMFLUX_PERF_WAL_COMMIT_WINDOW_US must be >0 for s53 wal_window_on".into());
        }
        Ok(Self {
            connections: env_usize("RAMFLUX_PERF_QUIC_CONNECTIONS", DEFAULT_CONNECTIONS)?.max(1),
            inflight_per_connection: env_usize_any(
                &["RAMFLUX_PERF_QUIC_INFLIGHT", "RAMFLUX_PERF_QUIC_INFLIGHT_PER_CONNECTION"],
                DEFAULT_INFLIGHT,
            )?
            .max(1),
            total: env_usize_any(
                &["RAMFLUX_PERF_TOTAL", "RAMFLUX_PERF_TOTAL_REQUESTS"],
                DEFAULT_TOTAL,
            )?
            .max(1),
            target_cardinality: env_usize("RAMFLUX_PERF_TARGET_CARDINALITY", DEFAULT_CARDINALITY)?
                .max(1),
            gateway_compio: std::env::var("RAMFLUX_GATEWAY_COMPIO").as_deref() == Ok("1"),
            server_transport: std::env::var("RAMFLUX_PERF_SERVER_TRANSPORT")
                .map_or_else(|_| "quic".to_owned(), |value| value.trim().to_ascii_lowercase()),
            wal_commit_window_on_us,
            min_throughput_per_sec: env_f64("RAMFLUX_PERF_MIN_THROUGHPUT_PER_SEC", 0.0)?,
        })
    }

    fn enforce_quic_assertions(&self) -> bool {
        self.server_transport != "http"
    }
}

#[cfg(feature = "realnet")]
#[derive(Clone, Copy)]
enum S53Stage {
    WalWindowOff,
    WalWindowOn,
}

#[cfg(feature = "realnet")]
impl S53Stage {
    const fn label(self) -> &'static str {
        match self {
            Self::WalWindowOff => "wal_window_off",
            Self::WalWindowOn => "wal_window_on",
        }
    }

    fn wal_commit_window_us(self, plan: &S53PerfPlan) -> u64 {
        match self {
            Self::WalWindowOff => 0,
            Self::WalWindowOn => plan.wal_commit_window_on_us,
        }
    }
}

#[cfg(feature = "realnet")]
fn run_s53_stage(
    plan: &S53PerfPlan,
    stage: S53Stage,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let label = stage.label();
    let wal_commit_window_us = stage.wal_commit_window_us(plan);
    let mut compose_env = vec![
        ("RAMFLUX_ITEST_PERF".to_owned(), "1".to_owned()),
        ("RAMFLUX_ROUTER_GROUP_COMMIT".to_owned(), "0".to_owned()),
        ("RAMFLUX_ROUTER_WAL_COMMIT_WINDOW_US".to_owned(), wal_commit_window_us.to_string()),
        (
            "RAMFLUX_ROUTER_WAL_SHARDS".to_owned(),
            std::env::var("RAMFLUX_PERF_WAL_SHARDS").unwrap_or_default(),
        ),
        (
            "RAMFLUX_ROUTER_WAL_PIPELINE".to_owned(),
            std::env::var("RAMFLUX_PERF_WAL_PIPELINE").unwrap_or_else(|_| "0".to_owned()),
        ),
        (
            "RAMFLUX_ROUTER_WAL_DIR".to_owned(),
            std::env::var("RAMFLUX_PERF_WAL_DIR").unwrap_or_default(),
        ),
        (
            "RAMFLUX_ROUTER_ASYNC_INGRESS_SOCKETS".to_owned(),
            std::env::var("RAMFLUX_PERF_INGRESS_SOCKETS").unwrap_or_default(),
        ),
    ];
    if plan.enforce_quic_assertions() {
        compose_env.push(("RAMFLUX_ROUTER_ASYNC_INGRESS".to_owned(), "1".to_owned()));
        compose_env.push(("RAMFLUX_ROUTER_ASYNC_INGRESS_RUNTIME".to_owned(), "tokio".to_owned()));
        compose_env
            .push(("RAMFLUX_ROUTER_ASYNC_LISTEN_ADDR".to_owned(), "0.0.0.0:17444".to_owned()));
        compose_env
            .push(("RAMFLUX_ROUTER_ASYNC_ENDPOINT".to_owned(), "ramflux-router:17444".to_owned()));
    } else {
        compose_env.push(("RAMFLUX_ROUTER_ASYNC_INGRESS".to_owned(), "0".to_owned()));
        compose_env.push(("RAMFLUX_ROUTER_ASYNC_ENDPOINT".to_owned(), String::new()));
        compose_env.push(("RAMFLUX_NOTIFY_MESH_ENDPOINT".to_owned(), String::new()));
    }
    let realnet =
        start_realnet_compose_with_env_and_gateway_compio(&compose_env, plan.gateway_compio)?;
    let gateway_url = realnet.gateway_url.clone();
    let router_url = std::env::var("RAMFLUX_ITEST_ROUTER_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:18080".to_owned());
    reset_s53_metrics(&gateway_url, &router_url)?;

    let gateway_quic_addr: std::net::SocketAddr = std::env::var("RAMFLUX_ITEST_GATEWAY_QUIC_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:18443".to_owned())
        .parse()?;
    let ca_cert = code_root().join("ramflux/deploy/certs/ca.pem");
    let artifact_path = s53_artifact_path(&format!("mvp_s53_quic_ingress_{label}_latest.json"))?;
    let config = LoadgenConfig::gateway_quic_envelope(
        plan.total,
        plan.connections,
        plan.inflight_per_connection,
        plan.target_cardinality,
        gateway_quic_addr,
        "localhost".to_owned(),
        ca_cert.clone(),
        Some(format!("{gateway_url}/perf/metrics")),
        Some(format!("{router_url}/perf/metrics")),
        artifact_path,
    )?;

    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    runtime.block_on(wait_for_private_gateway_quic(gateway_quic_addr, &ca_cert))?;
    let mut artifact = runtime.block_on(run_loadgen(config))?;
    if let Some(object) = artifact.as_object_mut() {
        object.insert("stage".to_owned(), json!(label));
        object.insert("router_group_commit".to_owned(), json!(0));
        object.insert("router_wal_commit_window_us".to_owned(), json!(wal_commit_window_us));
        object.insert("quic_assertions_enabled".to_owned(), json!(plan.enforce_quic_assertions()));
    }
    if plan.enforce_quic_assertions() {
        assert_s53_quic_clean_stage(label, &artifact)?;
    }
    eprintln!("RAMFLUX_PERF_STAGE {}", serde_json::to_string(&artifact)?);
    Ok(artifact)
}

#[cfg(feature = "realnet")]
fn build_s53_comparison(
    plan: &S53PerfPlan,
    off: &serde_json::Value,
    on: &serde_json::Value,
) -> serde_json::Value {
    let off_throughput = json_f64(off, "/throughput_envelopes_per_sec");
    let on_throughput = json_f64(on, "/throughput_envelopes_per_sec");
    json!({
        "schema": "ramflux.itest.mvp_s53.quic_ingress_wal_window_compare.v2",
        "generated_at_unix": current_epoch_seconds(),
        "plan": plan,
        "stages": {
            "wal_window_off": off,
            "wal_window_on": on
        },
        "comparison": {
            "throughput_off_envelopes_per_sec": off_throughput,
            "throughput_on_envelopes_per_sec": on_throughput,
            "throughput_on_over_off": ratio(on_throughput, off_throughput),
            "gateway_mesh_client_open_bi_us_delta_off": json_u64(off, "/metrics/delta/gateway/mesh_client_open_bi_us_delta"),
            "gateway_mesh_client_open_bi_us_delta_on": json_u64(on, "/metrics/delta/gateway/mesh_client_open_bi_us_delta"),
            "router_quic_streams_accepted_delta_off": json_u64(off, "/metrics/delta/router/mesh_server_quic_streams_accepted_delta"),
            "router_quic_streams_accepted_delta_on": json_u64(on, "/metrics/delta/router/mesh_server_quic_streams_accepted_delta"),
            "router_save_commit_avg_us_off": json_f64(off, "/metrics/delta/router/router_save_commit_avg_us"),
            "router_save_commit_avg_us_on": json_f64(on, "/metrics/delta/router/router_save_commit_avg_us"),
            "router_submit_save_avg_us_off": json_f64(off, "/metrics/delta/router/router_submit_save_avg_us"),
            "router_submit_save_avg_us_on": json_f64(on, "/metrics/delta/router/router_submit_save_avg_us"),
            "router_replay_guard_redb_writes_off": json_u64(off, "/metrics/delta/router/router_replay_guard_redb_writes_delta"),
            "router_replay_guard_redb_writes_on": json_u64(on, "/metrics/delta/router/router_replay_guard_redb_writes_delta")
        }
    })
}

#[cfg(feature = "realnet")]
fn assert_s53_quic_clean_stage(
    label: &str,
    artifact: &serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    // open_bi is a QUIC-only client op (mesh_http.rs never records it), so a
    // non-zero gateway delta proves the gateway->router/notify hop opened QUIC
    // streams rather than silently using the blocking mTLS HTTP mesh client.
    let gateway_open_bi_us =
        json_u64(artifact, "/metrics/delta/gateway/mesh_client_open_bi_us_delta");
    if gateway_open_bi_us == 0 {
        return Err(format!(
            "s53 measured a non-QUIC path (open_bi=0) stage={label} pointer=/metrics/delta/gateway/mesh_client_open_bi_us_delta"
        )
        .into());
    }

    // Router-side proof the traffic arrived over QUIC: streams_accepted is
    // incremented only by the QUIC ingress server (mesh_quic.rs), never by the
    // HTTP mesh server. mesh_client_tls_handshakes / mesh_client_requests are
    // NOT usable here -- both the QUIC and HTTP client paths bump them, so they
    // stay non-zero on a clean QUIC run and cannot flag a fallback.
    let router_quic_streams_accepted =
        json_u64(artifact, "/metrics/delta/router/mesh_server_quic_streams_accepted_delta");
    if router_quic_streams_accepted == 0 {
        return Err(format!(
            "s53 router accepted no QUIC streams (mesh_server_quic_streams_accepted=0) stage={label}; gateway->router hop did not ride QUIC"
        )
        .into());
    }
    Ok(())
}

#[cfg(feature = "realnet")]
fn assert_s53_min_throughput(
    plan: &S53PerfPlan,
    on: &serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let throughput = json_f64(on, "/throughput_envelopes_per_sec").unwrap_or_default();
    eprintln!(
        "mvp_s53 wal_window_on throughput_envelopes_per_sec={throughput:.2} min={:.2}",
        plan.min_throughput_per_sec
    );
    // Set RAMFLUX_PERF_MIN_THROUGHPUT_PER_SEC=100000 once the clean QUIC baseline reaches
    // 100k/s and should become a hard perf gate.
    if plan.min_throughput_per_sec > 0.0 && throughput < plan.min_throughput_per_sec {
        return Err(format!(
            "s53 wal_window_on throughput {throughput:.2}/s below RAMFLUX_PERF_MIN_THROUGHPUT_PER_SEC {:.2}/s",
            plan.min_throughput_per_sec
        )
        .into());
    }
    Ok(())
}

#[cfg(feature = "realnet")]
fn reset_s53_metrics(
    gateway_url: &str,
    router_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let _: serde_json::Value =
        ramflux_node_core::itest_http_post_json(&format!("{gateway_url}/perf/metrics/reset"), &())?;
    let _: serde_json::Value =
        ramflux_node_core::itest_http_post_json(&format!("{router_url}/perf/metrics/reset"), &())?;
    Ok(())
}

#[cfg(feature = "realnet")]
fn s53_artifact_path(file_name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let dir = std::env::var("RAMFLUX_PERF_ARTIFACT_DIR")
        .map_or_else(|_| code_root().join("ramflux-itest/perf-artifacts"), PathBuf::from);
    std::fs::create_dir_all(&dir)?;
    Ok(dir.join(file_name))
}

#[cfg(feature = "realnet")]
fn env_usize(name: &str, default: usize) -> Result<usize, Box<dyn std::error::Error>> {
    match std::env::var(name) {
        Ok(value) => Ok(value.parse()?),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(Box::new(error)),
    }
}

#[cfg(feature = "realnet")]
fn env_u64(name: &str, default: u64) -> Result<u64, Box<dyn std::error::Error>> {
    match std::env::var(name) {
        Ok(value) => Ok(value.parse()?),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(Box::new(error)),
    }
}

#[cfg(feature = "realnet")]
fn env_f64(name: &str, default: f64) -> Result<f64, Box<dyn std::error::Error>> {
    match std::env::var(name) {
        Ok(value) => Ok(value.parse()?),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(Box::new(error)),
    }
}

#[cfg(feature = "realnet")]
fn env_usize_any(names: &[&str], default: usize) -> Result<usize, Box<dyn std::error::Error>> {
    for name in names {
        match std::env::var(name) {
            Ok(value) => return Ok(value.parse()?),
            Err(std::env::VarError::NotPresent) => {}
            Err(error) => return Err(Box::new(error)),
        }
    }
    Ok(default)
}

#[cfg(feature = "realnet")]
fn json_f64(value: &serde_json::Value, pointer: &str) -> Option<f64> {
    value.pointer(pointer).and_then(serde_json::Value::as_f64)
}

#[cfg(feature = "realnet")]
fn json_u64(value: &serde_json::Value, pointer: &str) -> u64 {
    value.pointer(pointer).and_then(serde_json::Value::as_u64).unwrap_or_default()
}

#[cfg(feature = "realnet")]
fn ratio(numerator: Option<f64>, denominator: Option<f64>) -> Option<f64> {
    let denominator = denominator?;
    if denominator == 0.0 {
        return None;
    }
    numerator.map(|value| value / denominator)
}

#[cfg(feature = "realnet")]
fn current_epoch_seconds() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |duration| duration.as_secs())
}
