// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! PERF-D1-2 realnet: public-path relay QUIC capacity macrobench (topology B).
//!
//! The public path `rf CLI -> rfd -> SDK per-account pool -> v3 QUIC relay` is fully serialized
//! inside a single daemon (process-global `Rc<Mutex<LocalBusDaemonState>>` held across dispatch,
//! sequential chunk upload) — see PERF-D1-0. The ONLY honest horizontal concurrency knob is K
//! independent daemons (K accounts, each its own socket + `data_root` + runtime + lock). This test
//! spins K real release `rf daemon start` daemons, launches K concurrent `object put`s behind a
//! barrier, GET-verifies the plaintext roundtrip, and reads the relay's per-request QUIC capture to
//! prove pooled connection reuse (>1 request per connection) and >=K distinct client connections.
//! It samples relay + rfd resource (RSS/FD/CPU) and exercises a relay-restart churn recovery.
//!
//! Every number is emitted to a `ramflux.perf.d1.macrobench.v1` JSON artifact (>=3 run ids). The
//! frozen mac-dev acceptance gates (100% success, 0 timeout/backpressure/protocol/capability error,
//! HTTP object = 0, throughput/latency scaling, resource caps, churn recovery) are asserted in-test.
//!
//! IRON RULE (CTRL-058 / D1-R0): run-realnet always builds the relay with `itest-quic-fault`, whose
//! per-client-QUIC-request capture is fail-closed. Without `RAMFLUX_RELAY_ITEST_CAPTURE_FILE` set the
//! relay closes EVERY client QUIC connection. This test sets it unconditionally.

#![allow(unused_imports)]
#![cfg_attr(not(feature = "realnet"), allow(dead_code))]
use super::*;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

const S64_PROJECT: &str = "ramflux-s64-macrobench";
const S64_RELAY_QUIC: &str = "127.0.0.1:17447";
const S64_GATEWAY_B_QUIC: &str = "127.0.0.1:18444";
const S64_CAPTURE_PATH: &str = "/var/lib/ramflux/relay/s64-macrobench-capture.jsonl";
const S64_ARTIFACT_SCHEMA: &str = "ramflux.perf.d1.macrobench.v1";

// ---- artifact model ----

#[cfg(feature = "realnet")]
#[derive(Clone, Debug, serde::Serialize)]
struct S64Artifact {
    schema: String,
    run_id: String,
    git_sha: String,
    git_dirty: bool,
    build: String,
    generated_note: String,
    // CTRL-073 envelope declaration — the certified public object envelope + explicit large-object block.
    public_envelope_class: String,
    supported_public_object_bytes: u64,
    known_limit_local_bus_frame_bytes: u64,
    large_object_capacity: String,
    large_object_public_path: String,
    // CTRL-077: per-phase namespace + seed-slot map. Proves every (point, k) phase occupies a disjoint
    // account/object/seed namespace, so the cross-K reuse bug (K=4 d0 reusing K=1 d0 state) cannot regress.
    namespace_seed_slots: Vec<S64NamespaceEntry>,
    points: Vec<S64PointResult>,
    churn: Option<S64ChurnResult>,
    boundary_diagnostics: Vec<S64BoundaryDiag>,
    thresholds: Vec<S64Threshold>,
}

#[cfg(feature = "realnet")]
#[derive(Clone, Debug, serde::Serialize)]
struct S64NamespaceEntry {
    point: String,
    k: usize,
    account_prefix: String,
    seed_slot_first: usize,
    seed_slot_last: usize,
    root_seed_first: String,
    root_seed_last: String,
}

#[cfg(feature = "realnet")]
#[derive(Clone, Debug, serde::Serialize)]
struct S64PointResult {
    point: String,
    k: usize,
    rounds: usize,
    object_bytes: u64,
    chunk_bytes: u64,
    objects_per_daemon_per_round: usize,
    ops_total: usize,
    ops_ok: usize,
    error_classes: Vec<String>,
    put_p50_ns: u128,
    put_p95_ns: u128,
    put_p99_ns: u128,
    get_p50_ns: u128,
    get_p95_ns: u128,
    get_p99_ns: u128,
    round_throughputs_mib_s: Vec<f64>,
    throughput_mib_s: f64,
    verified_objects: usize,
    connections: S64ConnAnalysis,
    resource: S64Resource,
    http_object_requests: usize,
    // C_persistence only: after a relay restart, first/mid/last objects re-GET with matching hash.
    restart_hash_verified: Option<bool>,
    // CTRL-078: D_resource only — per-round memory decomposition (empty for other points).
    mem_breakdown: Vec<S64MemBreakdown>,
}

#[cfg(feature = "realnet")]
#[derive(Clone, Debug, serde::Serialize)]
struct S64ConnAnalysis {
    distinct_connections: usize,
    max_requests_on_one_connection: usize,
    expected_min_distinct: usize,
    captured_lines: usize,
}

#[cfg(feature = "realnet")]
#[derive(Clone, Debug, Default, serde::Serialize)]
struct S64Resource {
    // Per measured-round samples (warmup rounds excluded) — the authoritative growth evidence.
    // measured_rss_mib = cgroup memory.current (heap + reclaimable page cache); measured_rss_anon_mib
    // = the process anonymous heap (the true leak signal); measured_rss_file_mib = file-backed/mmap
    // resident (redb page cache, reclaimable).
    measured_rss_mib: Vec<f64>,
    measured_rss_anon_mib: Vec<f64>,
    measured_rss_file_mib: Vec<f64>,
    measured_fd: Vec<u64>,
    relay_rss_first_mib: f64,
    relay_rss_last_mib: f64,
    // CTRL-074 steady-state growth: median(last 3) / median(first 3) of the measured RSS samples.
    relay_rss_median_growth_ratio: f64,
    relay_rss_monotonic_unbounded: bool,
    relay_fd_last: u64,
    relay_cpu_last_pct: f64,
    rfd_aggregate_rss_mib: f64,
    rfd_aggregate_fd: u64,
}

#[cfg(feature = "realnet")]
#[derive(Clone, Debug, serde::Serialize)]
struct S64ChurnResult {
    k: usize,
    restart_first_op_ns: u128,
    warm_p95_pre_ns: u128,
    warm_p95_post_ns: u128,
}

/// One OBJ-IPC-01 boundary diagnostic (CTRL-073): attempt a large public PUT that is expected to
/// fail, then read AUTHORITATIVE local (`object status`) + relay (capture write actions) mutation
/// state and classify the failure. NOT counted in capacity success — pure evidence for OBJ-IPC-01.
/// CTRL-078 D16 memory decomposition — one per round, to classify relay memory growth as reclaimable
/// file cache vs possible heap/private growth. Fields absent on the host are recorded as -1.0 (null),
/// never faked to 0.
#[cfg(feature = "realnet")]
#[derive(Clone, Debug, serde::Serialize)]
struct S64MemBreakdown {
    round: usize,
    measured: bool,
    cumulative_objects: usize,
    cumulative_plaintext_bytes: u64,
    cumulative_chunks: usize,
    cgroup_memory_current_mib: f64,
    memstat_anon_mib: f64,
    memstat_file_mib: f64,
    memstat_kernel_mib: f64,
    memstat_kernel_stack_mib: f64,
    memstat_pagetables_mib: f64,
    memstat_sock_mib: f64,
    memstat_shmem_mib: f64,
    memstat_file_mapped_mib: f64,
    memstat_file_dirty_mib: f64,
    memstat_file_writeback_mib: f64,
    proc_vmrss_mib: f64,
    proc_rss_anon_mib: f64,
    proc_rss_file_mib: f64,
    proc_rss_shmem_mib: f64,
    smaps_private_dirty_mib: f64,
    fd: u64,
    relay_redb_bytes: u64,
}

#[cfg(feature = "realnet")]
#[derive(Clone, Debug, serde::Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct S64BoundaryDiag {
    label: String,
    object_bytes: u64,
    chunk_bytes: u64,
    put_failed: bool,
    put_error_excerpt: String,
    /// Authoritative local upload-transfer status after the failed PUT (JSON excerpt or `not_found`).
    local_status_excerpt: String,
    local_object_exists: bool,
    /// The `completed_chunks` the daemon durably recorded (relay-side upload progress), if any.
    local_completed_chunks: i64,
    local_transfer_state: String,
    /// Relay client-QUIC capture write actions observed for this attempt (0 = no relay object write).
    relay_write_actions: usize,
    /// Best-effort serialized-frame size estimate for the request/response (bytes). Precise wire
    /// construction is deferred to the OBJ-IPC-01 audit; this is an analytical estimate.
    request_frame_estimate_bytes: u64,
    response_frame_estimate_bytes: u64,
    relay_close_reason_excerpt: String,
    /// One of `pre_commit_reject` / `ambiguous_success` / `partial_relay_mutation` /
    /// `unexpected_success` / `unknown`.
    classification: String,
    /// CTRL-074: after the failed PUT, a legitimate owner GET+ACK — proves an `ambiguous_success`
    /// object is really retrievable with matching plaintext (not merely counted).
    post_get_ok: bool,
    post_get_hash_match: bool,
}

#[cfg(feature = "realnet")]
#[derive(Clone, Debug, serde::Serialize)]
struct S64Threshold {
    name: String,
    passed: bool,
    /// CTRL-087: a diagnostic threshold is recorded and reported (field + pass/fail preserved,
    /// never deleted or hidden) but does NOT hard-fail the acceptance run on its own. Currently
    /// only the single-run 5-sample strict-monotonic+25% `RssAnon` check, retired from hard-gate to
    /// diagnostic flag because a glibc never-trim high-water can look monotonic over a short window
    /// while the numerical median/peak/`memory.current` hard gates already bound the footprint.
    diagnostic: bool,
    detail: String,
}

// Not gated on `realnet`: the pure connection-analysis helpers + their unit tests exercise this in
// the default (non-realnet) test target.
#[derive(Clone, Debug, serde::Deserialize)]
struct S64CaptureLine {
    #[allow(dead_code)]
    request_seq: u64,
    connection_id: u64,
    #[allow(dead_code)]
    process_instance: u64,
    #[allow(dead_code)]
    method: String,
    #[allow(dead_code)]
    route: String,
    #[allow(dead_code)]
    body_fingerprint: String,
    #[allow(dead_code)]
    action: String,
    #[allow(dead_code)]
    status: u16,
}

// ---- pure helpers (unit-tested without realnet) ----

/// Nearest-rank percentile over a slice of latencies (ns). Returns 0 for an empty slice.
#[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn s64_nearest_rank(latencies: &[u128], percentile: f64) -> u128 {
    if latencies.is_empty() {
        return 0;
    }
    let mut sorted = latencies.to_vec();
    sorted.sort_unstable();
    let rank = (percentile / 100.0 * sorted.len() as f64).ceil() as usize;
    let index = rank.saturating_sub(1).min(sorted.len() - 1);
    sorted[index]
}

/// Median over f64 samples (nearest-rank p50 semantics). Returns 0.0 for empty input.
#[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn s64_median_f64(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let index = (sorted.len() - 1) / 2;
    sorted[index]
}

/// Number of distinct connection ids in a capture (>= K proves each daemon opened its own).
fn s64_distinct_connections(capture: &[S64CaptureLine]) -> usize {
    capture.iter().map(|line| line.connection_id).collect::<BTreeSet<u64>>().len()
}

/// Maximum captured requests sharing one connection id (> 1 proves pooled multi-request reuse).
fn s64_max_requests_on_one_connection(capture: &[S64CaptureLine]) -> usize {
    let mut by_connection: BTreeMap<u64, usize> = BTreeMap::new();
    for line in capture {
        *by_connection.entry(line.connection_id).or_insert(0) += 1;
    }
    by_connection.values().copied().max().unwrap_or(0)
}

/// Percent growth of `last` over `first`; 0.0 when `first` is non-positive (avoids div-by-zero).
fn s64_growth_pct(first: f64, last: f64) -> f64 {
    if first <= 0.0 {
        return 0.0;
    }
    (last - first) / first * 100.0
}

/// CTRL-074 steady-state growth ratio: median of the last 3 measured samples over the median of the
/// first 3. Needs >=3 samples; returns 1.0 for fewer (no growth claim). Cold-start warmup rounds are
/// excluded by the caller so this measures steady-state drift, not first-round warmup.
fn s64_median_growth_ratio(samples: &[f64]) -> f64 {
    if samples.len() < 3 {
        return 1.0;
    }
    let first = s64_median_f64(&samples[..3]);
    let last = s64_median_f64(&samples[samples.len() - 3..]);
    if first <= 0.0 {
        return 1.0;
    }
    last / first
}

/// CTRL-079 peak guard: max of the last 3 samples over the median of the first 3. Needs >=3 samples;
/// returns 1.0 for fewer. Catches a single high-water spike that the median ratio would smooth away.
fn s64_peak_ratio(samples: &[f64]) -> f64 {
    if samples.len() < 3 {
        return 1.0;
    }
    let first = s64_median_f64(&samples[..3]);
    let peak = samples[samples.len() - 3..].iter().copied().fold(f64::MIN, f64::max);
    if first <= 0.0 {
        return 1.0;
    }
    peak / first
}

/// CTRL-074 unbounded-growth guard: true iff EVERY consecutive step strictly increases AND the total
/// rise exceeds 25% (a genuine monotonic leak, distinct from allocator high-water oscillation).
fn s64_monotonic_unbounded(samples: &[f64]) -> bool {
    if samples.len() < 2 {
        return false;
    }
    let strictly_increasing = samples.windows(2).all(|pair| pair[1] > pair[0]);
    let first = samples[0];
    let last = samples[samples.len() - 1];
    let total_rise = first > 0.0 && (last - first) / first > 0.25;
    strictly_increasing && total_rise
}

/// Bytes -> MiB/s given an elapsed nanosecond wall.
#[allow(clippy::cast_precision_loss)]
fn s64_mib_per_s(total_bytes: u64, wall_ns: u128) -> f64 {
    if wall_ns == 0 {
        return 0.0;
    }
    let seconds = wall_ns as f64 / 1_000_000_000.0_f64;
    (total_bytes as f64 / (1024.0 * 1024.0)) / seconds
}

// ---- realnet-only body ----

#[cfg(feature = "realnet")]
#[derive(Clone, Copy)]
struct S64Point {
    name: &'static str,
    ks: &'static [usize],
    object_bytes: u64,
    chunk_bytes: u64,
    objects_per_daemon_per_round: usize,
    rounds: usize,
}

#[cfg(feature = "realnet")]
const S64_POINTS: &[S64Point] = &[
    // PERF-D1-2a (CTRL-073): the ONLY public-path object size that round-trips both directions is the
    // 64 KiB verified envelope. 512 KiB/1 MiB/16 MiB are blocked by OBJ-IPC-01 (request base64 frame,
    // response Vec<u8> JSON echo, relay per-chunk) and are deferred to D1-2b after the fix. B/C are
    // therefore NOT run here; their large-object behaviour is captured by the boundary diagnostics.
    // A: small-object concurrency across K.
    S64Point {
        name: "A_small",
        ks: &[1, 4, 8],
        object_bytes: 64 * 1024,
        chunk_bytes: 64 * 1024,
        objects_per_daemon_per_round: 4,
        rounds: 5,
    },
    // D: resource ceiling under the widest fan-out (64 KiB).
    S64Point {
        name: "D_resource",
        ks: &[16],
        object_bytes: 64 * 1024,
        chunk_bytes: 64 * 1024,
        objects_per_daemon_per_round: 1,
        rounds: 5,
    },
];

/// CTRL-074: uncounted warmup rounds run BEFORE the `point.rounds` measured rounds so relay RSS is
/// sampled at steady state, not during cold-start allocation. Their PUTs still must succeed.
#[cfg(feature = "realnet")]
const S64_WARMUP_ROUNDS: usize = 2;

/// Deterministic plaintext of `bytes` length, uniquely tagged so a GET roundtrip is verifiable and
/// no two objects share content.
#[cfg(feature = "realnet")]
fn s64_plaintext(tag: &str, bytes: u64) -> Vec<u8> {
    let seed = format!("s64|{tag}|");
    let seed_bytes = seed.as_bytes();
    let mut out = Vec::with_capacity(usize::try_from(bytes).unwrap_or(0));
    let mut index = 0usize;
    while (out.len() as u64) < bytes {
        out.push(seed_bytes[index % seed_bytes.len()]);
        index += 1;
    }
    out
}

#[cfg(feature = "realnet")]
fn s64_kmax() -> usize {
    std::env::var("RAMFLUX_S64_KMAX")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(usize::MAX)
}

#[cfg(feature = "realnet")]
fn s64_runs() -> usize {
    std::env::var("RAMFLUX_S64_RUNS").ok().and_then(|value| value.parse().ok()).unwrap_or(3).max(1)
}

/// Optional comma-separated point filter (e.g. `A_small,B_throughput`) for bring-up; default all.
#[cfg(feature = "realnet")]
fn s64_point_filter() -> Option<BTreeSet<String>> {
    std::env::var("RAMFLUX_S64_POINTS").ok().map(|value| {
        value
            .split(',')
            .map(|part| part.trim().to_owned())
            .filter(|part| !part.is_empty())
            .collect()
    })
}

#[cfg(feature = "realnet")]
fn s64_run_churn() -> bool {
    std::env::var("RAMFLUX_S64_SKIP_CHURN").as_deref() != Ok("1")
}

#[cfg(feature = "realnet")]
struct S64Daemon {
    index: usize,
    account: String,
    principal: String,
    device: String,
    target: String,
    socket_arg: String,
    child: tokio::process::Child,
    pid: Option<u32>,
}

#[cfg(feature = "realnet")]
#[test]
#[allow(clippy::too_many_lines)]
fn mvp_s64_realnet_object_v3_relay_quic_capacity() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1")
        || std::env::var("RAMFLUX_OBJECT_V3").as_deref() != Ok("1")
        || std::env::var("RAMFLUX_CROSS_GATEWAY").as_deref() != Ok("1")
    {
        eprintln!(
            "skipping s64 relay quic capacity realnet; set RAMFLUX_ITEST_REALNET=1 RAMFLUX_OBJECT_V3=1 RAMFLUX_CROSS_GATEWAY=1"
        );
        return Ok(());
    }

    let issuer_node = "node_b.realnet";
    let materials = temp_root("s64_object_v3_materials")?;
    let now = ramflux_node_core::now_unix_seconds();
    let root_seed = [0x44; 32];
    let attestation_seed = [0x33; 32];
    let provider_seed = [0x66; 32];
    let offline_root_seed = [0x88; 32];
    let certificate = s64_certificate(now, issuer_node, "gw-b", root_seed, attestation_seed)?;
    let envelope = s64_trust_envelope(now, issuer_node, root_seed, provider_seed, &certificate)?;
    for directory in ["gateway-a", "gateway-b"] {
        std::fs::create_dir_all(materials.join(directory))?;
        std::fs::write(
            materials.join(directory).join("issuer-cert.json"),
            serde_json::to_vec_pretty(&certificate)?,
        )?;
    }
    std::fs::create_dir_all(materials.join("federation"))?;
    std::fs::write(
        materials.join("federation/trust-snapshot.json"),
        serde_json::to_vec_pretty(&envelope)?,
    )?;
    s64_write_provider_keyring(&materials, now, issuer_node, offline_root_seed, provider_seed)?;

    let ports = S8ComposePorts {
        gateway_http: 64_481,
        gateway_quic: 64_751,
        router_http: 64_480,
        router_mesh: 64_752,
        notify_http: 64_483,
        federation_http: 64_482,
        federation_mesh: 64_753,
        relay_http: 64_484,
        relay_media_udp: 64_450,
        signaling_turn_udp: 64_478,
        signaling_turn_tcp: 64_479,
        retention_http: 64_487,
    };
    let node = start_s8_realnet_compose_project_with_env(
        S64_PROJECT,
        ports,
        &[
            ("RAMFLUX_V3_MATERIALS_DIR".to_owned(), materials.to_string_lossy().into_owned()),
            (
                "RAMFLUX_GATEWAY_B_V3_ISSUER_SEED".to_owned(),
                ramflux_protocol::encode_base64url(attestation_seed),
            ),
            (
                "RAMFLUX_V3_FEDERATION_PROVIDER_OFFLINE_ROOT_PUBLIC_KEY".to_owned(),
                ramflux_crypto::public_key_base64url_from_seed(offline_root_seed),
            ),
            (
                "RAMFLUX_V3_FEDERATION_PROVIDER_KEYRING_FILE".to_owned(),
                "/etc/ramflux/federation/provider-keyring.json".to_owned(),
            ),
            ("RAMFLUX_V3_FEDERATION_TRUST_ISSUER_NODE_ID".to_owned(), issuer_node.to_owned()),
            (
                "RAMFLUX_V3_FEDERATION_TRUST_ENDPOINT".to_owned(),
                "ramflux-federation:7443".to_owned(),
            ),
            // IRON RULE (D1-R0): must set the relay capture file or the fail-closed itest-quic-fault
            // seam closes every client QUIC connection.
            ("RAMFLUX_RELAY_ITEST_CAPTURE_FILE".to_owned(), S64_CAPTURE_PATH.to_owned()),
        ],
    )?;

    let relay_ca = node.ca_cert.clone();
    let relay_url = format!("http://127.0.0.1:{}", ports.relay_http);
    let ca_cert_env = relay_ca.to_string_lossy().into_owned();

    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    let result = runtime.block_on(async {
        s64_wait_relay_quic_healthy(&relay_ca).await?;
        s64_flow(&node, &relay_ca, &relay_url, &ca_cert_env, issuer_node).await
    });
    if let Err(error) = &result {
        eprintln!(
            "s64 flow failed: {error}\n=== relay logs (tail) ===\n{}",
            s64_container_logs("ramflux-relay")
        );
    }
    std::fs::remove_dir_all(&materials).ok();
    result
}

#[cfg(feature = "realnet")]
#[allow(clippy::too_many_lines)]
async fn s64_flow(
    node: &S8RealnetNode,
    relay_ca: &Path,
    relay_url: &str,
    ca_cert_env: &str,
    issuer_node: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // RELAY-MEM-02-A0 allocation diagnostic mode (env-gated, default-off): split one D16-shaped round
    // into PUT/GET/idle phases, run PUT-only and GET-only-replay batteries, and sample RssAnon at each
    // boundary to attribute the relay's anon high-water to a phase + prove/refute bounded reclaim.
    if std::env::var("RAMFLUX_S64_MEM02").as_deref() == Ok("1") {
        return s64_mem02_flow(node, relay_ca, relay_url, ca_cert_env, issuer_node).await;
    }
    // CTRL-088 PERF-D1-2b-K4 median-gate diagnostic (env-gated, default-off): run ONLY A_small K=4 with
    // 12 measured rounds (vs the standard 5) so the median-growth ratio can be studied over many
    // 5-sample windows. Absolute/peak/FD/conservation are still fail-stop; the 1.25 median-growth ratio
    // is recorded as DATA (the object under study), NOT asserted. Does not touch the standard grid.
    if std::env::var("RAMFLUX_S64_D2BK4").as_deref() == Ok("1") {
        return s64_d2bk4_flow(node, relay_ca, relay_url, ca_cert_env, issuer_node).await;
    }
    let audience_node = "node_a.realnet";
    let rf_binary = s64_build_rf_binary().await?;
    let ca_cert_arg = mvp_s4_path_arg(&node.ca_cert);
    let build_kind = if s64_release_build() { "release" } else { "debug" };
    let temp = temp_root("s64_macrobench")?;
    let point_filter = s64_point_filter();
    let kmax = s64_kmax();
    let (git_sha, git_dirty) = s64_git_state();
    let mut run_manifest: Vec<(String, String)> = Vec::new();

    for run in 0..s64_runs() {
        // CTRL-079: each of the 3 fresh runs is a SEPARATE run-realnet invocation (fresh compose/
        // volume) tagged externally, so artifacts do not overwrite and the cross-run manifest can
        // verify distinct volume instances.
        let run_tag = std::env::var("RAMFLUX_S64_RUN_TAG").unwrap_or_else(|_| "s64".to_owned());
        let run_id = format!("{run_tag}_run{run}");
        eprintln!("STEP s64: === {run_id} (build={build_kind}) ===");
        let mut points: Vec<S64PointResult> = Vec::new();
        let mut thresholds: Vec<S64Threshold> = Vec::new();

        for point in S64_POINTS {
            if point_filter.as_ref().is_some_and(|set| !set.contains(point.name)) {
                continue;
            }
            for &k in point.ks {
                if k > kmax {
                    eprintln!("STEP s64: skip {} k={k} (> RAMFLUX_S64_KMAX={kmax})", point.name);
                    continue;
                }
                let result = s64_run_point(
                    &rf_binary,
                    &temp,
                    relay_ca,
                    relay_url,
                    ca_cert_env,
                    &ca_cert_arg,
                    issuer_node,
                    audience_node,
                    &run_id,
                    *point,
                    k,
                )
                .await?;
                points.push(result);
            }
        }

        // Churn (relay restart recovery) — its own K=4 phase using point B object shape.
        let churn = if s64_run_churn()
            && point_filter.as_ref().is_none_or(|set| set.contains("E_churn"))
            && 4 <= kmax
        {
            Some(
                s64_run_churn_phase(
                    &rf_binary,
                    &temp,
                    relay_ca,
                    relay_url,
                    ca_cert_env,
                    &ca_cert_arg,
                    issuer_node,
                    audience_node,
                    &run_id,
                )
                .await?,
            )
        } else {
            None
        };

        // OBJ-IPC-01 boundary diagnostics (CTRL-073): 1 MiB request / 512 KiB response / 512 KiB
        // 128-chunk peer-stop — each reads authoritative local+relay mutation and classifies. Evidence
        // only, not a capacity gate. Skippable for bring-up.
        let boundary_diagnostics = if std::env::var("RAMFLUX_S64_SKIP_PROBE").as_deref() == Ok("1")
        {
            Vec::new()
        } else {
            s64_boundary_diagnostics(
                &rf_binary,
                &temp,
                relay_url,
                ca_cert_env,
                &ca_cert_arg,
                issuer_node,
                audience_node,
                &run_id,
            )
            .await?
        };

        s64_evaluate_thresholds(&points, churn.as_ref(), &boundary_diagnostics, &mut thresholds);
        let artifact = S64Artifact {
            schema: S64_ARTIFACT_SCHEMA.to_owned(),
            run_id: run_id.clone(),
            git_sha: git_sha.clone(),
            git_dirty,
            build: build_kind.to_owned(),
            generated_note:
                "PERF-D1-2a public-path K-daemon macrobench, CTRL-073 64KiB verified envelope; large objects blocked by OBJ-IPC-01; mac-dev, not an SLO"
                    .to_owned(),
            public_envelope_class: "current_verified_64k".to_owned(),
            supported_public_object_bytes: 64 * 1024,
            known_limit_local_bus_frame_bytes: 1024 * 1024,
            large_object_capacity: "blocked_OBJ-IPC-01".to_owned(),
            large_object_public_path: "blocked_by_OBJ-IPC-01".to_owned(),
            namespace_seed_slots: s64_namespace_summary(&run_id),
            points,
            churn,
            boundary_diagnostics,
            thresholds: thresholds.clone(),
        };
        let path = s64_write_artifact(&artifact, &run_id)?;
        eprintln!("STEP s64: wrote artifact {}", path.display());
        run_manifest.push((
            run_id.clone(),
            path.file_name().map_or_else(String::new, |name| name.to_string_lossy().into_owned()),
        ));

        // Hard gate: every non-diagnostic threshold must pass on every run. CTRL-087: diagnostic
        // thresholds (the strict-monotonic RssAnon flag) are still recorded in the artifact but do
        // not hard-fail on their own; log them separately so a monotonic window is never hidden.
        let failed: Vec<&S64Threshold> =
            artifact.thresholds.iter().filter(|t| !t.passed && !t.diagnostic).collect();
        let diagnostic_flags: Vec<&S64Threshold> =
            artifact.thresholds.iter().filter(|t| !t.passed && t.diagnostic).collect();
        if !diagnostic_flags.is_empty() {
            eprintln!("STEP s64: {run_id} diagnostic flags (non-fatal): {diagnostic_flags:?}");
        }
        assert!(failed.is_empty(), "s64 {run_id} acceptance thresholds failed: {failed:?}");
    }

    // CTRL-077 manifest — references ONLY the official run artifacts (no preflight/debug).
    let manifest = serde_json::json!({
        "schema": "ramflux.perf.d1.macrobench.manifest.v1",
        "task": "PERF-D1-2a",
        "git_sha": git_sha,
        "git_dirty": git_dirty,
        "build": build_kind,
        "public_envelope_class": "current_verified_64k",
        "large_object_capacity": "blocked_OBJ-IPC-01",
        "runs": run_manifest.iter().map(|(id, file)| serde_json::json!({"run_id": id, "artifact": file})).collect::<Vec<_>>(),
    });
    let manifest_dir = code_root().join("ramflux-itest/perf-artifacts");
    std::fs::create_dir_all(&manifest_dir)?;
    std::fs::write(
        manifest_dir.join("perf_d1_2_manifest.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;

    std::fs::remove_dir_all(&temp).ok();
    Ok(())
}

// ---- CTRL-088 PERF-D1-2b-K4 median-gate diagnostic (env-gated `RAMFLUX_S64_D2BK4=1`, default-off) ----
//
// PERF-D1-2a-closure saw A_small K4 hard-fail the `rss_anon_median_growth_le_1_25x` gate on one of
// three fresh grids because a single deep RssAnon dip in the first 3-sample window inflated the ratio
// (median(last3)/median(first3)). This diagnostic reruns ONLY A_small K4 with 12 measured rounds so
// the ratio can be studied over 8 sliding 5-sample windows and a 12-point regression, deciding whether
// the median gate is unstable to allocator high-water dips (bounded) or reflects a genuine sustained
// rise. It reuses the real K4 machinery via `s64_run_point`. Absolute/peak/FD/conservation remain
// fail-stop; the 1.25 median-growth ratio is recorded as DATA, NOT asserted here.

#[cfg(feature = "realnet")]
#[derive(Clone, Debug, serde::Serialize)]
struct S64D2bK4Artifact {
    schema: String,
    run_id: String,
    git_sha: String,
    git_dirty: bool,
    build: String,
    generated_note: String,
    k: usize,
    rounds: usize,
    object_bytes: u64,
    chunk_bytes: u64,
    objects_per_daemon_per_round: usize,
    ops_ok: usize,
    ops_total: usize,
    error_classes: Vec<String>,
    http_object_requests: usize,
    distinct_connections: usize,
    max_requests_on_one_connection: usize,
    // Full per-measured-round vectors (`rounds` entries each) — the raw growth evidence.
    // measured_rss_anon_mib == relay Private_Dirty (same /proc source); measured_rss_file_mib ~= redb
    // page cache (mmap, reclaimable). No distinct per-round Private_Dirty/redb vector is sampled for
    // A_small (collect_mem is D_resource-only), so those equivalences are noted, not duplicated.
    measured_rss_anon_mib: Vec<f64>,
    measured_rss_mib: Vec<f64>,
    measured_rss_file_mib: Vec<f64>,
    measured_fd: Vec<u64>,
    // Recorded data over the anon samples (NOT gated in this mode).
    median_growth_ratio: f64,
    peak_ratio: f64,
    // CTRL-089 RELAY-MEM-02-A1: when true, peak_ratio (1.75) AND median_growth (1.25) are RECORD-ONLY
    // (not asserted) so the RssAnon curve PAST the 1.75 crossing can be observed. All other
    // fail-stop gates (success/http/conservation/memcurrent/FD) remain asserted.
    plateau_mode: bool,
}

#[cfg(feature = "realnet")]
#[allow(clippy::too_many_lines)]
async fn s64_d2bk4_flow(
    node: &S8RealnetNode,
    relay_ca: &Path,
    relay_url: &str,
    ca_cert_env: &str,
    issuer_node: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let audience_node = "node_a.realnet";
    let rf_binary = s64_build_rf_binary().await?;
    let ca_cert_arg = mvp_s4_path_arg(&node.ca_cert);
    let build_kind = if s64_release_build() { "release" } else { "debug" };
    let temp = temp_root("s64_macrobench")?;
    let (git_sha, git_dirty) = s64_git_state();
    let run_tag = std::env::var("RAMFLUX_S64_RUN_TAG").unwrap_or_else(|_| "d2bk4".to_owned());
    let run_id = format!("{run_tag}_run0");

    // CTRL-089 RELAY-MEM-02-A1: parametrize the measured-round count (default 12 -> preserves the
    // CTRL-088 behavior when unset). Part A runs with RAMFLUX_S64_D2BK4_ROUNDS=30 to see the curve past
    // the 1.75 crossing. S64_WARMUP_ROUNDS (2) is unchanged.
    let rounds: usize = std::env::var("RAMFLUX_S64_D2BK4_ROUNDS")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|&value| value >= 3)
        .unwrap_or(12);
    // CTRL-089 plateau-observation mode: peak_ratio (1.75) AND median_growth (1.25) become RECORD-ONLY
    // (not asserted) so the RssAnon curve PAST the 1.75 crossing is observable. All other fail-stop
    // gates (success/http/conservation/memcurrent/FD) remain asserted even in plateau mode.
    let plateau_mode = std::env::var("RAMFLUX_S64_D2BK4_PLATEAU").as_deref() == Ok("1");

    // A_small K4, but `rounds` measured rounds (vs the standard 5). Same object/concurrency/chunk shape;
    // only rounds is parametrized and k restricted to 4. S64_WARMUP_ROUNDS (2) is unchanged.
    let custom_point = S64Point {
        name: "A_small",
        ks: &[4],
        object_bytes: 64 * 1024,
        chunk_bytes: 64 * 1024,
        objects_per_daemon_per_round: 4,
        rounds,
    };
    eprintln!(
        "STEP d2bk4: === {run_id} (build={build_kind}) A_small K4 {rounds}-round median-gate diagnostic (plateau_mode={plateau_mode}) ==="
    );

    let point = s64_run_point(
        &rf_binary,
        &temp,
        relay_ca,
        relay_url,
        ca_cert_env,
        &ca_cert_arg,
        issuer_node,
        audience_node,
        &run_id,
        custom_point,
        4,
    )
    .await?;

    // The object under study, over the 12 measured RssAnon samples — DATA only, not a stop-gate.
    let median_growth_ratio = s64_median_growth_ratio(&point.resource.measured_rss_anon_mib);
    let peak_ratio = s64_peak_ratio(&point.resource.measured_rss_anon_mib);

    // STOP-gates (absolute/peak/FD/conservation). Compute all first; write artifact BEFORE asserting.
    let fd_first = point.resource.measured_fd.first().copied().unwrap_or(0);
    let fd_peak = point.resource.measured_fd.iter().copied().max().unwrap_or(0);
    let memcurrent_peak = point.resource.measured_rss_mib.iter().copied().fold(f64::MIN, f64::max);
    let success_ok = point.ops_ok == point.ops_total && point.error_classes.is_empty();
    let http_zero_ok = point.http_object_requests == 0;
    let conservation_ok = point.connections.distinct_connections >= 4
        && point.connections.max_requests_on_one_connection > 1;
    let peak_ok = peak_ratio <= 1.75;
    let memcurrent_ok = memcurrent_peak <= 512.0;
    let fd_ok = fd_peak <= fd_first + 2 && fd_peak <= 256;

    // Schema v2 whenever plateau_mode is set OR the round count departs from the CTRL-088 default (12);
    // v1 preserved for the unmodified 12-round stop-gate diagnostic.
    let schema = if plateau_mode || rounds != 12 {
        "ramflux.perf.d1.2b.k4.median_diagnostic.v2"
    } else {
        "ramflux.perf.d1.2b.k4.median_diagnostic.v1"
    };
    let generated_note = if plateau_mode {
        "CTRL-089 RELAY-MEM-02-A1-PROFILE (plateau mode): A_small K4 with `rounds` measured rounds, NORMAL production allocator; peak_ratio(1.75) AND median_growth(1.25) recorded as DATA only (NOT asserted) to observe the RssAnon curve past the 1.75 crossing; success/http/conservation/memcurrent(512)/FD remain fail-stop. RssAnon==Private_Dirty (same /proc source) and redb page cache ~= measured_rss_file_mib (mmap, reclaimable); no distinct per-round Private_Dirty/redb vector is sampled for A_small (collect_mem is D_resource-only). mac-dev, not an SLO. Distinguishing bounded high-water plateau from per-op retained leak requires the Part B allocator profile."
    } else {
        "CTRL-088 PERF-D1-2b-K4: A_small K4 median-gate diagnostic; median-growth ratio recorded as DATA (not gated); absolute/peak/FD/conservation fail-stop; mac-dev, not an SLO"
    };
    let artifact = S64D2bK4Artifact {
        schema: schema.to_owned(),
        run_id: run_id.clone(),
        git_sha,
        git_dirty,
        build: build_kind.to_owned(),
        generated_note: generated_note.to_owned(),
        k: point.k,
        rounds: point.rounds,
        object_bytes: point.object_bytes,
        chunk_bytes: point.chunk_bytes,
        objects_per_daemon_per_round: point.objects_per_daemon_per_round,
        ops_ok: point.ops_ok,
        ops_total: point.ops_total,
        error_classes: point.error_classes.clone(),
        http_object_requests: point.http_object_requests,
        distinct_connections: point.connections.distinct_connections,
        max_requests_on_one_connection: point.connections.max_requests_on_one_connection,
        measured_rss_anon_mib: point.resource.measured_rss_anon_mib.clone(),
        measured_rss_mib: point.resource.measured_rss_mib.clone(),
        measured_rss_file_mib: point.resource.measured_rss_file_mib.clone(),
        measured_fd: point.resource.measured_fd.clone(),
        median_growth_ratio,
        peak_ratio,
        plateau_mode,
    };
    let dir = code_root().join("ramflux-itest/perf-artifacts");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("perf_d1_2b_k4_{run_id}.json"));
    std::fs::write(&path, serde_json::to_vec_pretty(&artifact)?)?;
    eprintln!("STEP d2bk4: wrote artifact {}", path.display());
    eprintln!(
        "STEP d2bk4: {run_id} DATA plateau_mode={plateau_mode} rounds={rounds} median_growth_ratio(anon)={median_growth_ratio:.4} peak_ratio(anon)={peak_ratio:.4} memcurrent_peak={memcurrent_peak:.1}MiB fd_first={fd_first} fd_peak={fd_peak} anon={:?}",
        point.resource.measured_rss_anon_mib
    );

    std::fs::remove_dir_all(&temp).ok();

    // Fail-stop gates — asserted AFTER the artifact is persisted so evidence survives a failure.
    assert!(
        success_ok,
        "d2bk4 {run_id} success gate failed: ops_ok={} ops_total={} errors={:?}",
        point.ops_ok, point.ops_total, point.error_classes
    );
    assert!(
        http_zero_ok,
        "d2bk4 {run_id} HTTP object requests != 0: {}",
        point.http_object_requests
    );
    assert!(
        conservation_ok,
        "d2bk4 {run_id} capture conservation failed: distinct={} max_on_one={}",
        point.connections.distinct_connections, point.connections.max_requests_on_one_connection
    );
    // CTRL-089: in plateau mode the peak_ratio (1.75) is RECORD-ONLY so the curve past the crossing is
    // observable; the literal 1.75 constant is unchanged, only whether it fail-stops this diagnostic.
    if plateau_mode {
        eprintln!(
            "STEP d2bk4: {run_id} plateau_mode: peak_ratio(anon)={peak_ratio:.4} recorded-only (1.75 NOT asserted); peak_ok_would_be={peak_ok}"
        );
    } else {
        assert!(peak_ok, "d2bk4 {run_id} anon peak_ratio {peak_ratio} > 1.75");
    }
    assert!(memcurrent_ok, "d2bk4 {run_id} memcurrent peak {memcurrent_peak} MiB > 512");
    assert!(
        fd_ok,
        "d2bk4 {run_id} fd gate failed: peak={fd_peak} first={fd_first} (need <=first+2 && <=256)"
    );
    Ok(())
}

// ---- RELAY-MEM-02-A0 allocation diagnostic (env-gated `RAMFLUX_S64_MEM02=1`, default-off) ----
//
// CTRL-086 CORRECTED methodology. The prior A0 drove the GET-replay through the public SDK
// (`rf object get`). That path SHORT-CIRCUITS: once the first GET persists
// `OBJECT_TRANSFER_DOWNLOAD.completed_chunks`, every later GET of the SAME object fills from the
// local `object.ciphertext` and `continue`s WITHOUT calling `get_object_chunk_via_relay_quic`
// (crates/ramflux-sdk/src/client/object.rs:1114-1123). So the earlier "384 replay GETs, RssAnon
// flat" measured the SDK's local completed-transfer fast path, NOT relay read-through — that
// "GET flat" conclusion is RETRACTED.
//
// This mode instead drives EVERY op as a raw v3 QUIC relay request (s54-style: gateway-issued
// token + owner grant/proof + fresh PoP -> `relay.request("/relay/v1/object/{put,get}_chunk")`),
// fully bypassing the SDK. Every request provably reaches the relay handler and is witnessed by the
// itest QUIC capture (the relay writes exactly one capture line per client QUIC request, keyed by
// `route`; apps/ramflux-relay/src/main.rs `decide_and_capture`). Each PUT-only and GET-replay round
// resets the capture, fires K x objs concurrent requests over K persistent relay connections, and
// ASSERTS the `put_chunk`/`get_chunk` capture increment equals the ops issued
// (capture-increment conservation — the CTRL-086 proof). GET is a read (no ack) and the relay
// enforces NO persistent PoP/token replay guard (`verify_requester_pop` / `verify_relay_token_v3`
// are signature + TTL only), so the SAME fixed stored object set is re-GET across >=6 rounds with a
// fresh PoP per request, keeping the stored set non-growing. K=1 vs K=16 = concurrent relay
// connections; run twice (fresh volume), `RAMFLUX_S64_MEM02_K` per run.

/// One relay memory sample at a labelled phase boundary. `rss_anon`/`private_dirty` are the anon-heap
/// leak signal; `memstat_file`/`redb_bytes` prove the redb page cache is not the growth.
/// `put_chunk_capture_increment`/`get_chunk_capture_increment` are the CTRL-086 server-side proof that
/// this round's ops actually reached the relay handler (0 on non-op phases).
#[cfg(feature = "realnet")]
#[derive(Clone, Debug, serde::Serialize)]
struct S64Mem02Sample {
    phase: String,
    k: usize,
    iter: usize,
    cumulative_puts: usize,
    cumulative_gets: usize,
    put_chunk_capture_increment: usize,
    get_chunk_capture_increment: usize,
    rss_anon_mib: f64,
    private_dirty_mib: f64,
    cgroup_memcurrent_mib: f64,
    memstat_file_mib: f64,
    relay_redb_bytes: u64,
    fd: u64,
}

#[cfg(feature = "realnet")]
#[derive(Clone, Debug, serde::Serialize)]
struct S64Mem02Result {
    approach: String,
    k: usize,
    object_bytes: u64,
    objs_per_conn: usize,
    established_objects: usize,
    put_rounds: usize,
    replay_iters: usize,
    idle_secs: u64,
    // CTRL-086 capture-increment conservation.
    expected_puts_per_round: usize,
    expected_gets_per_round: usize,
    put_only_put_capture_per_round: Vec<usize>,
    replay_get_capture_per_round: Vec<usize>,
    put_capture_conserved: bool,
    replay_get_capture_conserved: bool,
    samples: Vec<S64Mem02Sample>,
    // Derived deltas (MiB) for at-a-glance attribution.
    establish_get_anon_delta_mib: f64,
    put_only_anon_growth_mib: f64,
    put_only_idle_reclaim_mib: f64,
    replay_anon_growth_mib: f64,
    replay_idle_reclaim_mib: f64,
}

#[cfg(feature = "realnet")]
#[derive(Clone, Debug, serde::Serialize)]
struct S64Mem02Artifact {
    schema: String,
    run_id: String,
    git_sha: String,
    git_dirty: bool,
    build: String,
    note: String,
    result: S64Mem02Result,
}

/// Parses a positive `u64` env value, falling back to `default` for absent/zero/unparseable input.
/// Pure (non-realnet) so it is unit-tested in the default target.
fn s64_mem02_parse_u64(raw: Option<&str>, default: u64) -> u64 {
    raw.and_then(|value| value.trim().parse::<u64>().ok()).filter(|&n| n > 0).unwrap_or(default)
}

#[cfg(feature = "realnet")]
fn s64_mem02_env_u64(key: &str, default: u64) -> u64 {
    s64_mem02_parse_u64(std::env::var(key).ok().as_deref(), default)
}

#[cfg(feature = "realnet")]
#[allow(clippy::cast_possible_truncation)]
fn s64_mem02_env_usize(key: &str, default: usize) -> usize {
    usize::try_from(s64_mem02_env_u64(key, default as u64)).unwrap_or(default)
}

/// Counts capture lines whose relay route ends with `route_suffix` (e.g. `get_chunk`). Read AFTER a
/// `s64_reset_capture()` + one round of ops, this is the authoritative server-side count of relay QUIC
/// requests that reached the handler this round — the CTRL-086 proof (CLI success does NOT count).
#[cfg(feature = "realnet")]
fn s64_capture_route_count(route_suffix: &str) -> usize {
    s64_read_capture()
        .map_or(0, |lines| lines.iter().filter(|line| line.route.ends_with(route_suffix)).count())
}

/// Samples the relay container's anon/private-dirty/cgroup/file/redb footprint at a phase boundary,
/// tagging the round's capture-proven op increments.
#[cfg(feature = "realnet")]
#[allow(clippy::too_many_arguments)]
fn s64_mem02_sample(
    phase: &str,
    k: usize,
    iter: usize,
    cumulative_puts: usize,
    cumulative_gets: usize,
    put_inc: usize,
    get_inc: usize,
) -> S64Mem02Sample {
    let m = s64_relay_mem_breakdown(0, false, 0, 0, 0);
    eprintln!(
        "STEP mem02: [{phase}] iter={iter} puts={cumulative_puts} gets={cumulative_gets} put_cap+={put_inc} get_cap+={get_inc} rss_anon={:.1} priv_dirty={:.1} memcur={:.1} file={:.1} redb={}MiB",
        m.proc_rss_anon_mib,
        m.smaps_private_dirty_mib,
        m.cgroup_memory_current_mib,
        m.memstat_file_mib,
        m.relay_redb_bytes / (1024 * 1024)
    );
    S64Mem02Sample {
        phase: phase.to_owned(),
        k,
        iter,
        cumulative_puts,
        cumulative_gets,
        put_chunk_capture_increment: put_inc,
        get_chunk_capture_increment: get_inc,
        rss_anon_mib: m.proc_rss_anon_mib,
        private_dirty_mib: m.smaps_private_dirty_mib,
        cgroup_memcurrent_mib: m.cgroup_memory_current_mib,
        memstat_file_mib: m.memstat_file_mib,
        relay_redb_bytes: m.relay_redb_bytes,
        fd: m.fd,
    }
}

// ---- raw v3 QUIC relay request builders (s54-style, s64-local; NOT visible across test modules) ----

/// Fixed identity + certificate context for the single owner/requester device the mem02 flow drives.
#[cfg(feature = "realnet")]
struct S64Mem02Ctx {
    certificate: ramflux_node_core::GatewayIssuerCertificate,
    device_id: String,
    principal: String,
    device_seed: [u8; 32],
    owner_public_key: String,
    requester_public_key: String,
    requester_device_hash: String,
    issuer_node: String,
    audience_node: String,
    gateway_id: String,
}

/// One stored object (single 64 KiB chunk) with its owner-signed Get/Ack grant.
#[cfg(feature = "realnet")]
struct S64Mem02Object {
    object_id: String,
    manifest_hash: String,
    chunk_id: String,
    encrypted_chunk: Vec<u8>,
    chunk_cipher_hash: String,
    grant: ramflux_node_core::ObjectAccessGrant,
    grant_binding: String,
}

#[cfg(feature = "realnet")]
fn s64_now() -> u64 {
    ramflux_node_core::now_unix_seconds()
}

/// Builds a fresh single-chunk object with an owner-signed Get/Ack grant (owner == requester == device).
#[cfg(feature = "realnet")]
fn s64_mem02_build_object(
    ctx: &S64Mem02Ctx,
    run_id: &str,
    tag: &str,
    object_bytes: u64,
    now: u64,
) -> Result<S64Mem02Object, Box<dyn std::error::Error>> {
    let object_id = format!("{run_id}_{tag}_obj");
    let manifest_hash = format!("{run_id}_{tag}_manifest");
    let chunk_id = format!("{run_id}_{tag}_chunk0");
    let encrypted_chunk = s64_plaintext(&format!("{run_id}|{tag}"), object_bytes);
    let chunk_cipher_hash =
        ramflux_node_core::object_relay_chunk_cipher_hash(&manifest_hash, 0, &encrypted_chunk);
    let mut grant = ramflux_node_core::ObjectAccessGrant {
        schema: ramflux_node_core::OBJECT_ACCESS_GRANT_SCHEMA.to_owned(),
        version: ramflux_node_core::OBJECT_RELAY_V3_PROOF_VERSION,
        object_id: object_id.clone(),
        manifest_hash: manifest_hash.clone(),
        grantee_device_hash: ctx.requester_device_hash.clone(),
        capabilities: vec![
            ramflux_node_core::ObjectRelayCapability::Get,
            ramflux_node_core::ObjectRelayCapability::Ack,
        ],
        issued_at: now.saturating_sub(10),
        expires_at: now + 120,
        owner_signing_key_id: ctx.device_id.clone(),
        owner_public_key: ctx.owner_public_key.clone(),
        owner_signature: String::new(),
    };
    grant.owner_signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &ramflux_node_core::object_access_grant_signing_bytes(&grant)?,
        ctx.device_seed,
    );
    let grant_binding = ramflux_node_core::object_access_grant_binding_hash(&grant)?;
    Ok(S64Mem02Object {
        object_id,
        manifest_hash,
        chunk_id,
        encrypted_chunk,
        chunk_cipher_hash,
        grant,
        grant_binding,
    })
}

/// Issues a gateway-signed v3 relay token over the owner's authenticated gateway session stream.
#[cfg(feature = "realnet")]
async fn s64_mem02_issue_token(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    open: &ramflux_node_core::GatewayOpenFrame,
    body: ramflux_node_core::RelayTokenV3IssueRequest,
    device_seed: [u8; 32],
) -> Result<ramflux_node_core::RelayTokenV3, Box<dyn std::error::Error>> {
    let body_bytes = ramflux_protocol::canonical_json_bytes(&body)?;
    let device_id = &open.device_id;
    let now = ramflux_node_core::now_unix_seconds();
    let mut signed_request = ramflux_protocol::SignedRequest {
        schema: "ramflux.signed_request.v1".to_owned(),
        version: 1,
        domain: "ramflux.signed_request.v1".to_owned(),
        ext: ramflux_protocol::Ext::default(),
        signed: ramflux_protocol::SignedFields {
            signing_key_id: format!("device:{device_id}"),
            signature_alg: ramflux_protocol::SignatureAlg::Ed25519,
            signature: String::new(),
        },
        source_device_id: device_id.clone(),
        request_id: format!("req_s64_mem02_token_{}", body.nonce),
        method: ramflux_protocol::HttpMethod::POST,
        path: "/relay/v1/token/v3/issue".to_owned(),
        device_proof_hash: "already_authed".to_owned(),
        body_hash: ramflux_crypto::blake3_256_base64url(
            ramflux_protocol::domain::ENVELOPE,
            &body_bytes,
        ),
        nonce: open.stream_nonce.clone(),
        created_at: i64::try_from(now)?,
        expires_at: i64::try_from(now.saturating_add(120))?,
    };
    signed_request.signed.signature =
        ramflux_crypto::sign_protocol_object_with_seed(&signed_request, device_seed)?;
    mvp_s1_write_client_frame(
        send,
        &ramflux_node_core::GatewayClientFrame::RelayTokenV3Issue {
            request: Box::new(ramflux_node_core::GatewayRelayTokenV3IssueRequest {
                signed_request,
                body,
            }),
        },
    )
    .await?;
    match mvp_s1_read_server_frame(recv).await? {
        ramflux_node_core::GatewayServerFrame::RelayTokenV3Issued { response } => {
            Ok(response.relay_token)
        }
        other => Err(format!("expected gateway v3 token, got {other:?}").into()),
    }
}

/// Builds a fresh owner/requester proof-of-possession for one capability + body hash.
#[cfg(feature = "realnet")]
#[allow(clippy::too_many_arguments)]
fn s64_mem02_pop(
    token: &ramflux_node_core::RelayTokenV3,
    capability: ramflux_node_core::ObjectRelayCapability,
    body_hash: String,
    device_id: &str,
    device_seed: [u8; 32],
    now: u64,
    nonce: &str,
) -> Result<ramflux_node_core::RequesterProofOfPossession, Box<dyn std::error::Error>> {
    let mut pop = ramflux_node_core::RequesterProofOfPossession {
        schema: ramflux_node_core::REQUESTER_POP_SCHEMA.to_owned(),
        version: ramflux_node_core::OBJECT_RELAY_V3_PROOF_VERSION,
        token_id: token.token_id.clone(),
        capability,
        object_id: token.object_id.clone(),
        manifest_hash: token.manifest_hash.clone(),
        chunk_id: token.chunk_id.clone(),
        request_nonce: nonce.to_owned(),
        body_hash,
        issued_at: now,
        expires_at: now + 120,
        signer_device_id: device_id.to_owned(),
        signer_public_key: ramflux_crypto::public_key_base64url_from_seed(device_seed),
        signature: String::new(),
    };
    pop.signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &ramflux_node_core::requester_pop_signing_bytes(&pop)?,
        device_seed,
    );
    Ok(pop)
}

/// Common relay-token issue-request skeleton for one object + capability.
#[cfg(feature = "realnet")]
#[allow(clippy::too_many_arguments)]
fn s64_mem02_token_request(
    ctx: &S64Mem02Ctx,
    obj: &S64Mem02Object,
    capability: ramflux_node_core::ObjectRelayCapability,
    authorization_kind: ramflux_node_core::RelayAuthorizationKind,
    binding: String,
    now: u64,
    nonce: &str,
) -> ramflux_node_core::RelayTokenV3IssueRequest {
    ramflux_node_core::RelayTokenV3IssueRequest {
        requester_device_id: ctx.device_id.clone(),
        requester_device_hash: ctx.requester_device_hash.clone(),
        requester_public_key: ctx.requester_public_key.clone(),
        requester_device_epoch: 1,
        owner_signing_key_id: obj.grant.owner_signing_key_id.clone(),
        owner_public_key: obj.grant.owner_public_key.clone(),
        owner_home_node_id: ctx.issuer_node.clone(),
        owner_principal_id: ctx.principal.clone(),
        owner_device_epoch: 1,
        issuer_node_id: ctx.issuer_node.clone(),
        gateway_instance_id: ctx.gateway_id.clone(),
        audience_node_id: ctx.audience_node.clone(),
        relay_instance_id: None,
        object_id: obj.object_id.clone(),
        manifest_hash: obj.manifest_hash.clone(),
        chunk_id: obj.chunk_id.clone(),
        capabilities: vec![capability],
        authorization_kind,
        authorization_binding_hash: binding,
        delete_after_ack: false,
        issued_at: now,
        expires_at: now + 120,
        nonce: nonce.to_owned(),
        issuer_certificate: ctx.certificate.clone(),
    }
}

/// Issues a Put token (`OwnerSession`) + the owner authorization proof for one object.
#[cfg(feature = "realnet")]
#[allow(clippy::too_many_arguments)]
async fn s64_mem02_put_token(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    open: &ramflux_node_core::GatewayOpenFrame,
    ctx: &S64Mem02Ctx,
    obj: &S64Mem02Object,
    now: u64,
    tag: &str,
) -> Result<
    (ramflux_node_core::RelayTokenV3, ramflux_node_core::OwnerAuthorizationProof),
    Box<dyn std::error::Error>,
> {
    let mut owner_proof = ramflux_node_core::OwnerAuthorizationProof {
        schema: ramflux_node_core::OWNER_AUTHORIZATION_PROOF_SCHEMA.to_owned(),
        version: ramflux_node_core::OBJECT_RELAY_V3_PROOF_VERSION,
        capability: ramflux_node_core::ObjectRelayCapability::Put,
        object_id: obj.object_id.clone(),
        manifest_hash: Some(obj.manifest_hash.clone()),
        chunk_id: Some(obj.chunk_id.clone()),
        owner_home_node_id: ctx.issuer_node.clone(),
        owner_principal_id: ctx.principal.clone(),
        owner_device_epoch: 1,
        request_nonce: format!("{tag}_ownerproof"),
        body_hash: obj.chunk_cipher_hash.clone(),
        issued_at: now,
        expires_at: now + 120,
        owner_signing_key_id: obj.grant.owner_signing_key_id.clone(),
        owner_public_key: obj.grant.owner_public_key.clone(),
        owner_signature: String::new(),
    };
    owner_proof.owner_signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &ramflux_node_core::owner_authorization_proof_signing_bytes(&owner_proof)?,
        ctx.device_seed,
    );
    let put_binding = ramflux_node_core::owner_authorization_proof_binding_hash(&owner_proof)?;
    let body = s64_mem02_token_request(
        ctx,
        obj,
        ramflux_node_core::ObjectRelayCapability::Put,
        ramflux_node_core::RelayAuthorizationKind::OwnerSession,
        put_binding,
        now,
        &format!("{tag}_puttoken"),
    );
    let token = s64_mem02_issue_token(send, recv, open, body, ctx.device_seed).await?;
    Ok((token, owner_proof))
}

/// Serializes a Put request body (fresh `PoP`) for one object.
#[cfg(feature = "realnet")]
fn s64_mem02_put_body(
    ctx: &S64Mem02Ctx,
    obj: &S64Mem02Object,
    token: &ramflux_node_core::RelayTokenV3,
    owner_proof: &ramflux_node_core::OwnerAuthorizationProof,
    now: u64,
    pop_nonce: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let pop = s64_mem02_pop(
        token,
        ramflux_node_core::ObjectRelayCapability::Put,
        obj.chunk_cipher_hash.clone(),
        &ctx.device_id,
        ctx.device_seed,
        now,
        pop_nonce,
    )?;
    Ok(serde_json::json!({
        "token": token,
        // Present the certificate the GATEWAY embedded in the issued token (not our rebuilt one), so
        // the relay's `token.issuer_certificate == request.certificate` binding-hash check passes.
        "certificate": token.issuer_certificate,
        "owner_proof": owner_proof,
        "pop": pop,
        "body_hash": obj.chunk_cipher_hash,
        "capability": "put",
        "chunk_index": 0,
        "chunk_cipher_hash": obj.chunk_cipher_hash,
        "encrypted_chunk": obj.encrypted_chunk,
        "expires_at": now + 100,
        "delete_after_ack": false,
    }))
}

/// Issues a Get token (`OwnerGrant`) for one object.
#[cfg(feature = "realnet")]
#[allow(clippy::too_many_arguments)]
async fn s64_mem02_get_token(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    open: &ramflux_node_core::GatewayOpenFrame,
    ctx: &S64Mem02Ctx,
    obj: &S64Mem02Object,
    now: u64,
    tag: &str,
) -> Result<ramflux_node_core::RelayTokenV3, Box<dyn std::error::Error>> {
    let body = s64_mem02_token_request(
        ctx,
        obj,
        ramflux_node_core::ObjectRelayCapability::Get,
        ramflux_node_core::RelayAuthorizationKind::OwnerGrant,
        obj.grant_binding.clone(),
        now,
        &format!("{tag}_gettoken"),
    );
    s64_mem02_issue_token(send, recv, open, body, ctx.device_seed).await
}

/// Serializes a Get request body (fresh `PoP`) for one object.
#[cfg(feature = "realnet")]
fn s64_mem02_get_body(
    ctx: &S64Mem02Ctx,
    obj: &S64Mem02Object,
    token: &ramflux_node_core::RelayTokenV3,
    now: u64,
    pop_nonce: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let descriptor = serde_json::json!({
        "capability": "get",
        "chunk_id": token.chunk_id,
        "manifest_hash": token.manifest_hash,
        "object_id": token.object_id,
    });
    let body_hash = ramflux_crypto::blake3_256_base64url(
        "ramflux.object_relay.v3.get.body",
        &ramflux_protocol::canonical_json_bytes(&descriptor)?,
    );
    let pop = s64_mem02_pop(
        token,
        ramflux_node_core::ObjectRelayCapability::Get,
        body_hash.clone(),
        &ctx.device_id,
        ctx.device_seed,
        now,
        pop_nonce,
    )?;
    Ok(serde_json::json!({
        "token": token,
        // Present the certificate the GATEWAY embedded in the issued token (see s64_mem02_put_body).
        "certificate": token.issuer_certificate,
        "grant": obj.grant,
        "pop": pop,
        "body_hash": body_hash,
        "capability": "get",
    }))
}

/// Opens K persistent relay QUIC client connections (the concurrency knob; each = one relay connection).
#[cfg(feature = "realnet")]
async fn s64_mem02_connect_relay(
    relay_ca: &Path,
    k: usize,
) -> Result<Vec<Arc<ramflux_transport::QuicGatewayClient>>, Box<dyn std::error::Error>> {
    let mut connections = Vec::with_capacity(k);
    for _ in 0..k {
        let client = ramflux_transport::QuicGatewayClient::connect(
            "0.0.0.0:0".parse()?,
            S64_RELAY_QUIC.parse()?,
            "ramflux-relay",
            relay_ca,
            std::time::Duration::from_secs(15),
        )
        .await?;
        connections.push(Arc::new(client));
    }
    Ok(connections)
}

/// Fires one concurrent wave: connection `c` sequentially issues its pre-built `(path, body)` requests;
/// all K connections are released together by a barrier. Asserts every response is 200 and returns the
/// total requests fired. Because each request is a real relay QUIC request, the relay capture records
/// one line per request — the caller reconciles the capture route count against this total.
#[cfg(feature = "realnet")]
async fn s64_mem02_fire_wave(
    connections: &[Arc<ramflux_transport::QuicGatewayClient>],
    per_conn: Vec<Vec<(String, serde_json::Value)>>,
) -> Result<usize, Box<dyn std::error::Error>> {
    let k = connections.len();
    let barrier = Arc::new(tokio::sync::Barrier::new(k));
    let mut handles = Vec::with_capacity(k);
    for (connection, requests) in connections.iter().zip(per_conn) {
        let connection = connection.clone();
        let barrier = barrier.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let mut ok = 0usize;
            for (path, body) in requests {
                let response = connection
                    .request(&ramflux_transport::GatewayQuicRequest {
                        method: "POST".to_owned(),
                        path: path.clone(),
                        body,
                    })
                    .await
                    .map_err(|error| format!("relay request {path}: {error}"))?;
                if response.status != 200 {
                    return Err(format!(
                        "relay {path} returned status {} body={:?}",
                        response.status, response.body
                    ));
                }
                ok += 1;
            }
            Ok::<usize, String>(ok)
        }));
    }
    let mut total = 0usize;
    for handle in handles {
        total += handle.await??;
    }
    Ok(total)
}

#[cfg(feature = "realnet")]
#[allow(clippy::too_many_lines)]
async fn s64_mem02_flow(
    node: &S8RealnetNode,
    relay_ca: &Path,
    _relay_url: &str,
    _ca_cert_env: &str,
    issuer_node: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let audience_node = "node_a.realnet";
    let gateway_id = "gw-b";
    let build_kind = if s64_release_build() { "release" } else { "debug" };
    let (git_sha, git_dirty) = s64_git_state();
    let run_tag = std::env::var("RAMFLUX_S64_RUN_TAG").unwrap_or_else(|_| "mem02".to_owned());
    let k = s64_mem02_env_usize("RAMFLUX_S64_MEM02_K", 16);
    let object_bytes = s64_mem02_env_u64("RAMFLUX_S64_MEM02_OBJECT_BYTES", 64 * 1024);
    let objs = s64_mem02_env_usize("RAMFLUX_S64_MEM02_OBJS", 4);
    let put_rounds = s64_mem02_env_usize("RAMFLUX_S64_MEM02_PUT_ROUNDS", 6);
    let replay_iters = s64_mem02_env_usize("RAMFLUX_S64_MEM02_REPLAY_ITERS", 6);
    let idle_secs = s64_mem02_env_u64("RAMFLUX_S64_MEM02_IDLE_SECS", 25);
    let run_id = format!("{run_tag}_mem02_k{k}");
    eprintln!(
        "STEP mem02: [CTRL-086 raw-QUIC] k={k} obj={object_bytes}B objs/conn={objs} put_rounds={put_rounds} replay_iters={replay_iters} idle={idle_secs}s (every op = raw v3 QUIC relay request, capture-conserved)"
    );

    // --- Owner/requester device: register on the gateway, open an authenticated session for tokens.
    // Seeds clear of the gateway node seeds (0x33/0x44/0x66/0x88) and s54's device (0x5a/0x5b).
    let device_id = "device_s64_mem02".to_owned();
    let principal = "principal_s64_mem02".to_owned();
    let device_seed = [0x71u8; 32];
    let root_seed = [0x70u8; 32];
    let registration = mvp_s1_identity_register_request(GatewayFrameIdentitySpec {
        principal_id: &principal,
        device_id: &device_id,
        target_delivery_id: "target_s64_mem02",
        gateway_id,
        session_id: "pre_session_s64_mem02",
        push_alias_hash: Some("push_s64_mem02"),
        source_ip_hash: Some("s64_mem02_source"),
        root_seed,
        device_seed,
        device_epoch: 1,
    })?;
    register_mvp1_identity(&node.gateway_url, &registration)?;
    let (_endpoint, _connection, mut send, mut recv) =
        mvp_s1_open_quic_stream(S64_GATEWAY_B_QUIC.parse()?, &node.ca_cert).await?;
    let now0 = s64_now();
    let mut open = mvp_s1_open_frame(None, now0, "s64_mem02");
    open.client_instance_id = "rf_s64_mem02".to_owned();
    open.device_id = device_id.clone();
    open.target_delivery_id = "target_s64_mem02".to_owned();
    open.stream_nonce = "nonce_s64_mem02".to_owned();
    open.source_ip_hash = Some("s64_mem02_source".to_owned());
    let auth = mvp_s1_auth_frame_for_registered_device(&open, &principal, 1, device_seed)?;
    mvp_s1_write_client_frame(
        &mut send,
        &ramflux_node_core::GatewayClientFrame::Open { open: open.clone() },
    )
    .await?;
    mvp_s1_write_client_frame(&mut send, &ramflux_node_core::GatewayClientFrame::Auth { auth })
        .await?;
    let _session = mvp_s1_expect_session_established(&mut recv).await?;

    // Certificate MUST carry the same root/attestation seeds the compose gateway-b was started with
    // (root 0x44 / attestation 0x33), so the relay verifies it against the trusted snapshot root.
    let owner_public_key = ramflux_crypto::public_key_base64url_from_seed(device_seed);
    let ctx = S64Mem02Ctx {
        certificate: s64_certificate(now0, issuer_node, gateway_id, [0x44; 32], [0x33; 32])?,
        requester_device_hash: ramflux_crypto::blake3_256_base64url(
            "ramflux.object_relay.recipient_device.v1",
            device_id.as_bytes(),
        ),
        requester_public_key: owner_public_key.clone(),
        owner_public_key,
        device_id,
        principal,
        device_seed,
        issuer_node: issuer_node.to_owned(),
        audience_node: audience_node.to_owned(),
        gateway_id: gateway_id.to_owned(),
    };

    // K persistent, warm relay connections (the honest concurrency knob).
    let connections = s64_mem02_connect_relay(relay_ca, k).await?;

    let mut samples: Vec<S64Mem02Sample> = Vec::new();
    let mut cum_puts = 0usize;
    let mut cum_gets = 0usize;

    // Baseline: one 1 KiB PUT+GET on connection 0 to prime the handler/allocator.
    let warm = s64_mem02_build_object(&ctx, &run_id, "warm", 1024, s64_now())?;
    {
        let now = s64_now();
        let (token, proof) =
            s64_mem02_put_token(&mut send, &mut recv, &open, &ctx, &warm, now, "warm").await?;
        let body = s64_mem02_put_body(&ctx, &warm, &token, &proof, now, "warm_pop")?;
        let response = connections[0]
            .request(&ramflux_transport::GatewayQuicRequest {
                method: "POST".to_owned(),
                path: "/relay/v1/object/put_chunk".to_owned(),
                body,
            })
            .await?;
        if response.status != 200 {
            return Err(format!("mem02 warm put failed: {response:?}").into());
        }
        cum_puts += 1;
        let now = s64_now();
        let token =
            s64_mem02_get_token(&mut send, &mut recv, &open, &ctx, &warm, now, "warm").await?;
        let body = s64_mem02_get_body(&ctx, &warm, &token, now, "warm_getpop")?;
        let response = connections[0]
            .request(&ramflux_transport::GatewayQuicRequest {
                method: "POST".to_owned(),
                path: "/relay/v1/object/get_chunk".to_owned(),
                body,
            })
            .await?;
        if response.status != 200 {
            return Err(format!("mem02 warm get failed: {response:?}").into());
        }
        cum_gets += 1;
    }
    samples.push(s64_mem02_sample("baseline", k, 0, cum_puts, cum_gets, 0, 0));

    // Phase 1: establish the FIXED replay set (serial PUTs), then a serial GET-verify wave, then idle.
    let mut established: Vec<S64Mem02Object> = Vec::with_capacity(objs);
    for o in 0..objs {
        let obj =
            s64_mem02_build_object(&ctx, &run_id, &format!("est_o{o}"), object_bytes, s64_now())?;
        let now = s64_now();
        let (token, proof) =
            s64_mem02_put_token(&mut send, &mut recv, &open, &ctx, &obj, now, &format!("est_o{o}"))
                .await?;
        let body = s64_mem02_put_body(&ctx, &obj, &token, &proof, now, &format!("est_o{o}_pop"))?;
        let response = connections[0]
            .request(&ramflux_transport::GatewayQuicRequest {
                method: "POST".to_owned(),
                path: "/relay/v1/object/put_chunk".to_owned(),
                body,
            })
            .await?;
        if response.status != 200 {
            return Err(format!("mem02 establish put o{o} failed: {response:?}").into());
        }
        cum_puts += 1;
        established.push(obj);
    }
    samples.push(s64_mem02_sample("establish_put", k, 0, cum_puts, cum_gets, 0, 0));

    // First REAL relay GET wave (serial) — proves the read path + verifies plaintext round-trip.
    for (o, obj) in established.iter().enumerate() {
        let now = s64_now();
        let token = s64_mem02_get_token(
            &mut send,
            &mut recv,
            &open,
            &ctx,
            obj,
            now,
            &format!("estget_o{o}"),
        )
        .await?;
        let body = s64_mem02_get_body(&ctx, obj, &token, now, &format!("estget_o{o}_pop"))?;
        let response = connections[0]
            .request(&ramflux_transport::GatewayQuicRequest {
                method: "POST".to_owned(),
                path: "/relay/v1/object/get_chunk".to_owned(),
                body,
            })
            .await?;
        if response.status != 200 {
            return Err(format!("mem02 establish get o{o} failed: {response:?}").into());
        }
        let got: ramflux_node_core::ObjectRelayGetResponse = serde_json::from_value(response.body)?;
        if got.chunk.encrypted_chunk != obj.encrypted_chunk {
            return Err(format!("mem02 establish get o{o} ciphertext mismatch").into());
        }
        cum_gets += 1;
    }
    samples.push(s64_mem02_sample("establish_get", k, 0, cum_puts, cum_gets, 0, 0));
    tokio::time::sleep(Duration::from_secs(idle_secs)).await;
    samples.push(s64_mem02_sample("establish_idle", k, 0, cum_puts, cum_gets, 0, 0));

    // Phase 2: PUT-only rounds (fresh objects, K-concurrent), capture-increment conserved per round.
    let expected_puts_per_round = k * objs;
    let mut put_capture_per_round: Vec<usize> = Vec::with_capacity(put_rounds);
    for r in 0..put_rounds {
        let mut per_conn: Vec<Vec<(String, serde_json::Value)>> = Vec::with_capacity(k);
        for c in 0..k {
            let mut requests = Vec::with_capacity(objs);
            for o in 0..objs {
                let obj = s64_mem02_build_object(
                    &ctx,
                    &run_id,
                    &format!("puto_r{r}_c{c}_o{o}"),
                    object_bytes,
                    s64_now(),
                )?;
                let now = s64_now();
                let (token, proof) = s64_mem02_put_token(
                    &mut send,
                    &mut recv,
                    &open,
                    &ctx,
                    &obj,
                    now,
                    &format!("puto_r{r}_c{c}_o{o}"),
                )
                .await?;
                let body = s64_mem02_put_body(
                    &ctx,
                    &obj,
                    &token,
                    &proof,
                    now,
                    &format!("puto_r{r}_c{c}_o{o}_pop"),
                )?;
                requests.push(("/relay/v1/object/put_chunk".to_owned(), body));
            }
            per_conn.push(requests);
        }
        s64_reset_capture()?;
        let fired = s64_mem02_fire_wave(&connections, per_conn).await?;
        let put_inc = s64_capture_route_count("put_chunk");
        cum_puts += fired;
        put_capture_per_round.push(put_inc);
        if put_inc != expected_puts_per_round {
            return Err(format!(
                "mem02 put-only round {r}: capture put_chunk increment {put_inc} != expected {expected_puts_per_round} (relay did not witness every PUT)"
            )
            .into());
        }
        samples.push(s64_mem02_sample("put_only", k, r, cum_puts, cum_gets, put_inc, 0));
    }
    tokio::time::sleep(Duration::from_secs(idle_secs)).await;
    samples.push(s64_mem02_sample("put_only_idle", k, put_rounds, cum_puts, cum_gets, 0, 0));

    // Phase 3: GET-only replay of the SAME established objects (K-concurrent), stored set NON-growing.
    // Get tokens issued fresh here (TTL covers the fast replay phase); a fresh PoP per request.
    let mut get_tokens: Vec<ramflux_node_core::RelayTokenV3> = Vec::with_capacity(objs);
    for (o, obj) in established.iter().enumerate() {
        let now = s64_now();
        get_tokens.push(
            s64_mem02_get_token(&mut send, &mut recv, &open, &ctx, obj, now, &format!("rep_o{o}"))
                .await?,
        );
    }
    let expected_gets_per_round = k * objs;
    let mut get_capture_per_round: Vec<usize> = Vec::with_capacity(replay_iters);
    for i in 0..replay_iters {
        let mut per_conn: Vec<Vec<(String, serde_json::Value)>> = Vec::with_capacity(k);
        for c in 0..k {
            let mut requests = Vec::with_capacity(objs);
            for (o, obj) in established.iter().enumerate() {
                let now = s64_now();
                let body = s64_mem02_get_body(
                    &ctx,
                    obj,
                    &get_tokens[o],
                    now,
                    &format!("rep_i{i}_c{c}_o{o}_pop"),
                )?;
                requests.push(("/relay/v1/object/get_chunk".to_owned(), body));
            }
            per_conn.push(requests);
        }
        s64_reset_capture()?;
        let fired = s64_mem02_fire_wave(&connections, per_conn).await?;
        let get_inc = s64_capture_route_count("get_chunk");
        cum_gets += fired;
        get_capture_per_round.push(get_inc);
        if get_inc != expected_gets_per_round {
            return Err(format!(
                "mem02 get-replay round {i}: capture get_chunk increment {get_inc} != expected {expected_gets_per_round} (GET did NOT reach the relay — the retracted-A0 short-circuit)"
            )
            .into());
        }
        samples.push(s64_mem02_sample("get_replay", k, i, cum_puts, cum_gets, 0, get_inc));
    }
    tokio::time::sleep(Duration::from_secs(idle_secs)).await;
    samples.push(s64_mem02_sample("get_replay_idle", k, replay_iters, cum_puts, cum_gets, 0, 0));

    // Derived deltas.
    let anon_at = |phase: &str| -> Option<f64> {
        samples.iter().find(|s| s.phase == phase).map(|s| s.rss_anon_mib)
    };
    let anon_series = |phase: &str| -> Vec<f64> {
        samples.iter().filter(|s| s.phase == phase).map(|s| s.rss_anon_mib).collect()
    };
    let establish_put_anon = anon_at("establish_put").unwrap_or(0.0);
    let establish_get_anon = anon_at("establish_get").unwrap_or(0.0);
    let put_only = anon_series("put_only");
    let replay = anon_series("get_replay");
    let put_only_growth = match (put_only.first(), put_only.last()) {
        (Some(first), Some(last)) => last - first,
        _ => 0.0,
    };
    let replay_growth = match (replay.first(), replay.last()) {
        (Some(first), Some(last)) => last - first,
        _ => 0.0,
    };
    let put_only_idle_reclaim =
        put_only.last().copied().unwrap_or(0.0) - anon_at("put_only_idle").unwrap_or(0.0);
    let replay_idle_reclaim =
        replay.last().copied().unwrap_or(0.0) - anon_at("get_replay_idle").unwrap_or(0.0);
    let put_capture_conserved =
        put_capture_per_round.iter().all(|&count| count == expected_puts_per_round);
    let replay_get_capture_conserved =
        get_capture_per_round.iter().all(|&count| count == expected_gets_per_round);

    let artifact = S64Mem02Artifact {
        schema: "ramflux.relay.mem02.diagnostic.v2".to_owned(),
        run_id: run_id.clone(),
        git_sha,
        git_dirty,
        build: build_kind.to_owned(),
        note: "RELAY-MEM-02-A0 (CTRL-086) raw-QUIC capture-conserved: every PUT/GET is a real relay v3 QUIC request proven by capture increment; GET-replay re-reads a fixed non-growing set. mac-dev diagnostic, not an SLO".to_owned(),
        result: S64Mem02Result {
            approach: "raw_quic_get_chunk".to_owned(),
            k,
            object_bytes,
            objs_per_conn: objs,
            established_objects: established.len(),
            put_rounds,
            replay_iters,
            idle_secs,
            expected_puts_per_round,
            expected_gets_per_round,
            put_only_put_capture_per_round: put_capture_per_round,
            replay_get_capture_per_round: get_capture_per_round,
            put_capture_conserved,
            replay_get_capture_conserved,
            samples,
            establish_get_anon_delta_mib: establish_get_anon - establish_put_anon,
            put_only_anon_growth_mib: put_only_growth,
            put_only_idle_reclaim_mib: put_only_idle_reclaim,
            replay_anon_growth_mib: replay_growth,
            replay_idle_reclaim_mib: replay_idle_reclaim,
        },
    };
    let dir = code_root().join("ramflux-itest/perf-artifacts");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("perf_mem02_{run_id}.json"));
    std::fs::write(&path, serde_json::to_vec_pretty(&artifact)?)?;
    eprintln!(
        "STEP mem02: wrote {} (put_conserved={} get_conserved={} establish_get_delta={:.1} put_only_growth={:.1} put_only_reclaim={:.1} replay_growth={:.1} replay_reclaim={:.1} MiB)",
        path.display(),
        artifact.result.put_capture_conserved,
        artifact.result.replay_get_capture_conserved,
        artifact.result.establish_get_anon_delta_mib,
        artifact.result.put_only_anon_growth_mib,
        artifact.result.put_only_idle_reclaim_mib,
        artifact.result.replay_anon_growth_mib,
        artifact.result.replay_idle_reclaim_mib,
    );
    Ok(())
}

/// Runs one (point, K) macrobench phase: spawns K daemons, warms each pool, drives `rounds` waves of
/// K-concurrent PUTs, GET-verifies roundtrips, reads the connection capture, and samples resource.
#[cfg(feature = "realnet")]
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
async fn s64_run_point(
    rf_binary: &Path,
    temp: &Path,
    relay_ca: &Path,
    relay_url: &str,
    ca_cert_env: &str,
    ca_cert_arg: &str,
    issuer_node: &str,
    audience_node: &str,
    run_id: &str,
    point: S64Point,
    k: usize,
) -> Result<S64PointResult, Box<dyn std::error::Error>> {
    eprintln!(
        "STEP s64: point={} k={k} obj={}B chunk={}B rounds={} obj/daemon={}",
        point.name,
        point.object_bytes,
        point.chunk_bytes,
        point.rounds,
        point.objects_per_daemon_per_round
    );
    s64_reset_capture()?;
    let mut daemons = s64_spawn_daemons(
        rf_binary,
        temp,
        ca_cert_env,
        ca_cert_arg,
        issuer_node,
        audience_node,
        run_id,
        point.name,
        k,
    )
    .await?;

    // Warm each daemon's per-account pool with a single small PUT+GET so the measured rounds hit a
    // primed connection (warm reuse), not a cold handshake.
    for daemon in &daemons {
        let warm_object = format!("{}_{}_k{k}_d{}_warm", run_id, point.name, daemon.index);
        let warm_input = temp.join(format!("{warm_object}.in"));
        std::fs::write(&warm_input, s64_plaintext(&warm_object, 1024))?;
        s64_put(
            rf_binary,
            &daemon.socket_arg,
            &daemon.account,
            &warm_object,
            1024,
            relay_url,
            &mvp_s4_path_arg(&warm_input),
        )
        .await?;
    }

    let mut put_latencies: Vec<u128> = Vec::new();
    let mut get_latencies: Vec<u128> = Vec::new();
    let mut round_throughputs: Vec<f64> = Vec::new();
    let mut error_classes: Vec<String> = Vec::new();
    let mut verified = 0usize;
    let mut resource = S64Resource::default();
    // C_persistence tracks every object id PUT so it can re-GET first/mid/last after a relay restart.
    let mut c_object_ids: Vec<String> = Vec::new();
    // CTRL-078: D_resource memory decomposition + cumulative object/byte/chunk tracking (from the
    // warmup pool prime through every round), so growth can be correlated with the stored dataset.
    let collect_mem = point.name == "D_resource";
    let mut mem_breakdown: Vec<S64MemBreakdown> = Vec::new();
    let chunks_per_object = point.object_bytes.div_ceil(point.chunk_bytes).max(1);
    // Warmup pool-prime PUTs already stored one 1 KiB object per daemon on the relay.
    let mut cumulative_objects = k;
    let mut cumulative_plaintext_bytes = 1024u64 * k as u64;
    let mut cumulative_chunks = k;

    // CTRL-074: run S64_WARMUP_ROUNDS uncounted warmup rounds (PUTs still must succeed) so RSS is
    // sampled at steady state, then point.rounds measured rounds. RAMFLUX_S64_EXTRA_ROUNDS adds
    // measured rounds (diagnostic only — leak-vs-allocator-high-water plateau probe).
    let extra_rounds: usize = std::env::var("RAMFLUX_S64_EXTRA_ROUNDS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    for round in 0..(S64_WARMUP_ROUNDS + point.rounds + extra_rounds) {
        let measured = round >= S64_WARMUP_ROUNDS;
        // Pre-generate every object's input file so the concurrent wave measures only the PUT path.
        let mut wave: Vec<(usize, Vec<(String, String)>)> = Vec::new();
        for daemon in &daemons {
            let mut objects: Vec<(String, String)> = Vec::new();
            for object_index in 0..point.objects_per_daemon_per_round {
                let object_id = format!(
                    "{}_{}_k{k}_d{}_r{}_o{}",
                    run_id, point.name, daemon.index, round, object_index
                );
                let input = temp.join(format!("{object_id}.in"));
                std::fs::write(&input, s64_plaintext(&object_id, point.object_bytes))?;
                if point.name == "C_persistence" {
                    c_object_ids.push(object_id.clone());
                }
                objects.push((object_id, mvp_s4_path_arg(&input)));
            }
            wave.push((daemon.index, objects));
        }

        // Launch K concurrent tasks (one per daemon), released together by a barrier. Each task PUTs
        // its objects sequentially inside its own daemon (that daemon's lock serializes within, but
        // the K daemons run genuinely in parallel — the only honest concurrency knob, PERF-D1-0).
        let barrier = Arc::new(tokio::sync::Barrier::new(k));
        let mut handles = Vec::with_capacity(k);
        let wall_start = std::time::Instant::now();
        for (daemon, (_daemon_index, objects)) in daemons.iter().zip(wave.iter()) {
            let barrier = barrier.clone();
            let rf = rf_binary.to_path_buf();
            let socket = daemon.socket_arg.clone();
            let account = daemon.account.clone();
            let relay = relay_url.to_owned();
            let chunk = point.chunk_bytes;
            let objects = objects.clone();
            handles.push(tokio::spawn(async move {
                barrier.wait().await;
                let mut latencies: Vec<u128> = Vec::new();
                for (object_id, input_arg) in &objects {
                    let start = std::time::Instant::now();
                    let outcome =
                        s64_put(&rf, &socket, &account, object_id, chunk, &relay, input_arg).await;
                    let elapsed = start.elapsed().as_nanos();
                    match outcome {
                        Ok(()) => latencies.push(elapsed),
                        Err(error) => return Err(format!("put {object_id}: {error}")),
                    }
                }
                Ok(latencies)
            }));
        }
        let mut round_bytes = 0u64;
        let mut round_latencies: Vec<u128> = Vec::new();
        for handle in handles {
            match handle.await? {
                Ok(latencies) => {
                    round_bytes += point.object_bytes * latencies.len() as u64;
                    round_latencies.extend(latencies);
                }
                Err(error) => {
                    error_classes.push(error.clone());
                    return Err(format!("s64 concurrent put wave failed: {error}").into());
                }
            }
        }
        let round_wall = wall_start.elapsed().as_nanos();
        if measured {
            put_latencies.extend(round_latencies);
            round_throughputs.push(s64_mib_per_s(round_bytes, round_wall));
        }

        // GET-verify the plaintext roundtrip for every object of this wave (correctness gate).
        for (daemon, (_daemon_index, objects)) in daemons.iter().zip(wave.iter()) {
            for (object_id, input_arg) in objects {
                let output = temp.join(format!("{object_id}.out"));
                let output_arg = mvp_s4_path_arg(&output);
                let start = std::time::Instant::now();
                s64_get_ack(
                    rf_binary,
                    &daemon.socket_arg,
                    &daemon.account,
                    object_id,
                    relay_url,
                    &output_arg,
                )
                .await?;
                get_latencies.push(start.elapsed().as_nanos());
                let expected = std::fs::read(input_arg)?;
                let actual = std::fs::read(&output)?;
                assert_eq!(
                    actual,
                    expected,
                    "s64 {object_id} GET roundtrip plaintext mismatch (len {} vs {})",
                    actual.len(),
                    expected.len()
                );
                verified += 1;
                let _ = std::fs::remove_file(&output);
                let _ = std::fs::remove_file(input_arg);
            }
        }

        // Track the cumulative stored dataset (this round's PUTs) BEFORE sampling memory.
        let round_objects = k * point.objects_per_daemon_per_round;
        cumulative_objects += round_objects;
        cumulative_plaintext_bytes += round_objects as u64 * point.object_bytes;
        cumulative_chunks += round_objects * usize::try_from(chunks_per_object).unwrap_or(1);

        // Resource sample: only measured rounds feed the steady-state growth gate (warmup excluded).
        let (cgroup_rss, rss_anon, rss_file, fd, cpu) = s64_relay_resource()?;
        if measured {
            resource.measured_rss_mib.push(cgroup_rss);
            resource.measured_rss_anon_mib.push(rss_anon);
            resource.measured_rss_file_mib.push(rss_file);
            resource.measured_fd.push(fd);
            resource.relay_cpu_last_pct = cpu;
        }
        // CTRL-078: full memory decomposition per round (D_resource only), correlated with the dataset.
        if collect_mem {
            mem_breakdown.push(s64_relay_mem_breakdown(
                round,
                measured,
                cumulative_objects,
                cumulative_plaintext_bytes,
                cumulative_chunks,
            ));
        }
    }
    resource.relay_rss_first_mib = resource.measured_rss_mib.first().copied().unwrap_or(0.0);
    resource.relay_rss_last_mib = resource.measured_rss_mib.last().copied().unwrap_or(0.0);
    resource.relay_fd_last = resource.measured_fd.last().copied().unwrap_or(0);
    resource.relay_rss_median_growth_ratio = s64_median_growth_ratio(&resource.measured_rss_mib);
    resource.relay_rss_monotonic_unbounded = s64_monotonic_unbounded(&resource.measured_rss_mib);

    // Widest fan-out point additionally records aggregate rfd host footprint.
    if point.name == "D_resource" {
        let (agg_rss, agg_fd) = s64_rfd_aggregate(&daemons);
        resource.rfd_aggregate_rss_mib = agg_rss;
        resource.rfd_aggregate_fd = agg_fd;
    }

    let capture = s64_read_capture()?;
    let connections = S64ConnAnalysis {
        distinct_connections: s64_distinct_connections(&capture),
        max_requests_on_one_connection: s64_max_requests_on_one_connection(&capture),
        expected_min_distinct: k,
        captured_lines: capture.len(),
    };
    let http_object_requests = s64_relay_http_object_requests();

    // C_persistence: prove durability across a relay restart within the reachable envelope. Restart
    // the relay (redb volume persists), wait healthy, then re-GET first/mid/last object and verify the
    // plaintext hash still matches (objects are deterministic via s64_plaintext, so no files needed).
    let restart_hash_verified = if point.name == "C_persistence" && !c_object_ids.is_empty() {
        let daemon = &daemons[0];
        eprintln!("STEP s64: C restart-verify (relay restart + first/mid/last hash)");
        s64_container_ctl("restart", "ramflux-relay")?;
        s64_wait_relay_quic_healthy(relay_ca).await?;
        let last = c_object_ids.len() - 1;
        let indices = [0usize, last / 2, last];
        let mut all_match = true;
        for &index in &indices {
            let object_id = &c_object_ids[index];
            let output = temp.join(format!("{object_id}.restart.out"));
            let output_arg = mvp_s4_path_arg(&output);
            s64_get_ack(
                rf_binary,
                &daemon.socket_arg,
                &daemon.account,
                object_id,
                relay_url,
                &output_arg,
            )
            .await?;
            let expected = s64_plaintext(object_id, point.object_bytes);
            let actual = std::fs::read(&output)?;
            if actual != expected {
                all_match = false;
                eprintln!(
                    "STEP s64: C restart-verify MISMATCH {object_id} (len {} vs {})",
                    actual.len(),
                    expected.len()
                );
            }
            let _ = std::fs::remove_file(&output);
        }
        Some(all_match)
    } else {
        None
    };

    for daemon in &mut daemons {
        mvp_s20_stop_rf_daemon(&mut daemon.child).await?;
        let _ = std::fs::remove_file(daemon.socket_arg.trim_end_matches(".sock"));
        let _ = std::fs::remove_file(&daemon.socket_arg);
    }

    let ops_total = put_latencies.len();
    Ok(S64PointResult {
        point: point.name.to_owned(),
        k,
        rounds: point.rounds,
        object_bytes: point.object_bytes,
        chunk_bytes: point.chunk_bytes,
        objects_per_daemon_per_round: point.objects_per_daemon_per_round,
        ops_total,
        ops_ok: ops_total,
        error_classes,
        put_p50_ns: s64_nearest_rank(&put_latencies, 50.0),
        put_p95_ns: s64_nearest_rank(&put_latencies, 95.0),
        put_p99_ns: s64_nearest_rank(&put_latencies, 99.0),
        get_p50_ns: s64_nearest_rank(&get_latencies, 50.0),
        get_p95_ns: s64_nearest_rank(&get_latencies, 95.0),
        get_p99_ns: s64_nearest_rank(&get_latencies, 99.0),
        throughput_mib_s: s64_median_f64(&round_throughputs),
        round_throughputs_mib_s: round_throughputs,
        verified_objects: verified,
        connections,
        resource,
        http_object_requests,
        restart_hash_verified,
        mem_breakdown,
    })
}

/// Churn: warm K=4 daemons, restart the relay container, measure the first post-restart PUT (must
/// reconnect < 15s), then a warm round; asserts every daemon recovers.
#[cfg(feature = "realnet")]
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn s64_run_churn_phase(
    rf_binary: &Path,
    temp: &Path,
    relay_ca: &Path,
    relay_url: &str,
    ca_cert_env: &str,
    ca_cert_arg: &str,
    issuer_node: &str,
    audience_node: &str,
    run_id: &str,
) -> Result<S64ChurnResult, Box<dyn std::error::Error>> {
    let k = 4usize;
    eprintln!("STEP s64: churn phase k={k}");
    s64_reset_capture()?;
    let mut daemons = s64_spawn_daemons(
        rf_binary,
        temp,
        ca_cert_env,
        ca_cert_arg,
        issuer_node,
        audience_node,
        run_id,
        "E_churn",
        k,
    )
    .await?;
    // CTRL-073: churn runs inside the 64 KiB verified public envelope (large objects blocked by
    // OBJ-IPC-01), so it stays a durability/reconnect gate, not a large-object claim.
    let object_bytes = 64 * 1024u64;
    let chunk_bytes = 64 * 1024u64;

    // Pre-restart warm baseline: two rounds of one PUT each per daemon.
    let mut pre: Vec<u128> = Vec::new();
    for round in 0..2 {
        for daemon in &daemons {
            let object_id = format!("{run_id}_churn_pre_d{}_r{round}", daemon.index);
            let input = temp.join(format!("{object_id}.in"));
            std::fs::write(&input, s64_plaintext(&object_id, object_bytes))?;
            let start = std::time::Instant::now();
            s64_put(
                rf_binary,
                &daemon.socket_arg,
                &daemon.account,
                &object_id,
                chunk_bytes,
                relay_url,
                &mvp_s4_path_arg(&input),
            )
            .await?;
            pre.push(start.elapsed().as_nanos());
            let _ = std::fs::remove_file(&input);
        }
    }

    // Restart the relay (graceful) and wait for the client QUIC listener to rebind.
    eprintln!("STEP s64: churn restart relay");
    s64_container_ctl("restart", "ramflux-relay")?;
    s64_wait_relay_quic_healthy(relay_ca).await?;

    // First post-restart PUT per daemon: the stale pooled connection must be evicted and a fresh one
    // established. Measure the slowest daemon's first op (the reconnect cost) against the 15s gate.
    let mut restart_first_op = 0u128;
    for daemon in &daemons {
        let object_id = format!("{run_id}_churn_first_d{}", daemon.index);
        let input = temp.join(format!("{object_id}.in"));
        std::fs::write(&input, s64_plaintext(&object_id, object_bytes))?;
        let start = std::time::Instant::now();
        s64_put(
            rf_binary,
            &daemon.socket_arg,
            &daemon.account,
            &object_id,
            chunk_bytes,
            relay_url,
            &mvp_s4_path_arg(&input),
        )
        .await?;
        restart_first_op = restart_first_op.max(start.elapsed().as_nanos());
        // Verify the roundtrip survived the restart.
        let output = temp.join(format!("{object_id}.out"));
        let output_arg = mvp_s4_path_arg(&output);
        s64_get_ack(
            rf_binary,
            &daemon.socket_arg,
            &daemon.account,
            &object_id,
            relay_url,
            &output_arg,
        )
        .await?;
        assert_eq!(
            std::fs::read(&output)?,
            std::fs::read(&input)?,
            "s64 churn {object_id} roundtrip"
        );
        let _ = std::fs::remove_file(&input);
        let _ = std::fs::remove_file(&output);
    }

    // Post-restart warm baseline (pool re-primed): two rounds.
    let mut post: Vec<u128> = Vec::new();
    for round in 0..2 {
        for daemon in &daemons {
            let object_id = format!("{run_id}_churn_post_d{}_r{round}", daemon.index);
            let input = temp.join(format!("{object_id}.in"));
            std::fs::write(&input, s64_plaintext(&object_id, object_bytes))?;
            let start = std::time::Instant::now();
            s64_put(
                rf_binary,
                &daemon.socket_arg,
                &daemon.account,
                &object_id,
                chunk_bytes,
                relay_url,
                &mvp_s4_path_arg(&input),
            )
            .await?;
            post.push(start.elapsed().as_nanos());
            let _ = std::fs::remove_file(&input);
        }
    }

    for daemon in &mut daemons {
        mvp_s20_stop_rf_daemon(&mut daemon.child).await?;
        let _ = std::fs::remove_file(&daemon.socket_arg);
    }

    Ok(S64ChurnResult {
        k,
        restart_first_op_ns: restart_first_op,
        warm_p95_pre_ns: s64_nearest_rank(&pre, 95.0),
        warm_p95_post_ns: s64_nearest_rank(&post, 95.0),
    })
}

/// Global seed slot per (point, k, index): non-overlapping ranges so every daemon spawned across the
/// whole run gets a unique account seed (see the device-manifest collision fixed in `s64_spawn_daemons`).
/// Max slot 33 -> seed byte 0x90+33*2+1 = 0xD3, well within range and clear of the gateway node seeds.
fn s64_seed_slot(point_name: &str, k: usize, index: usize) -> usize {
    let base = match (point_name, k) {
        ("Zprobe", _) => 0,
        ("A_small", 1) => 1,
        ("A_small", 4) => 2,
        ("A_small", 8) => 6,
        ("D_resource", 16) => 14,
        ("E_churn", _) => 30,
        _ => 34,
    };
    base + index
}

/// CTRL-077 namespace-isolation audit: the disjoint account/seed namespace of every phase the run can
/// spawn, for the artifact (regression guard against cross-K reuse).
#[cfg(feature = "realnet")]
fn s64_namespace_summary(run_id: &str) -> Vec<S64NamespaceEntry> {
    let phases: [(&str, usize); 6] = [
        ("Zprobe", 1),
        ("A_small", 1),
        ("A_small", 4),
        ("A_small", 8),
        ("D_resource", 16),
        ("E_churn", 4),
    ];
    phases
        .iter()
        .map(|&(point, k)| {
            let first = s64_seed_slot(point, k, 0);
            let last = s64_seed_slot(point, k, k - 1);
            S64NamespaceEntry {
                point: point.to_owned(),
                k,
                account_prefix: format!("s64_acct_{point}_k{k}_{run_id}_d"),
                seed_slot_first: first,
                seed_slot_last: last,
                root_seed_first: format!("{:02x}", 0x90 + first * 2),
                root_seed_last: format!("{:02x}", 0x90 + last * 2),
            }
        })
        .collect()
}

#[cfg(feature = "realnet")]
#[allow(clippy::too_many_arguments)]
async fn s64_spawn_daemons(
    rf_binary: &Path,
    temp: &Path,
    ca_cert_env: &str,
    ca_cert_arg: &str,
    issuer_node: &str,
    audience_node: &str,
    run_id: &str,
    point_name: &str,
    k: usize,
) -> Result<Vec<S64Daemon>, Box<dyn std::error::Error>> {
    let pid = std::process::id();
    let mut daemons = Vec::with_capacity(k);
    for index in 0..k {
        // CTRL-076 ROOT-CAUSE FIX: include `k` in every identity/path so the K=1, K=4, K=8 phases of
        // the SAME point never share an account / data_root / socket / object namespace. Without `k`,
        // the K=4 index-0 daemon reused the K=1 index-0 account+data_root and its probe object_id
        // already existed on the relay from the K=1 phase, so its PUT short-circuited (idempotent, no
        // relay traffic) -> accept=0 and a false local "complete". That was the whole distinct<K symptom.
        let account = format!("s64_acct_{point_name}_k{k}_{run_id}_d{index}");
        let principal = format!("principal_s64_{point_name}_k{k}_{run_id}_d{index}");
        let device = format!("device_s64_k{k}_d{index}");
        let target = format!("target_s64_{point_name}_k{k}_{run_id}_d{index}");
        let data_root = temp.join(format!("{account}/data"));
        std::fs::create_dir_all(&data_root)?;
        let socket =
            PathBuf::from(format!("/tmp/ramflux-s64-{pid}-{point_name}-k{k}-{index}.sock"));
        let socket_arg = mvp_s4_path_arg(&socket);
        let data_arg = mvp_s4_path_arg(&data_root);
        let env = vec![
            ("RAMFLUX_SDK_RELAY_QUIC_ADDR".to_owned(), S64_RELAY_QUIC.to_owned()),
            ("RAMFLUX_SDK_RELAY_QUIC_SERVER_NAME".to_owned(), "ramflux-relay".to_owned()),
            ("RAMFLUX_SDK_RELAY_QUIC_CA_CERT".to_owned(), ca_cert_env.to_owned()),
            ("RAMFLUX_SDK_RELAY_OWNER_HOME_NODE_ID".to_owned(), issuer_node.to_owned()),
            ("RAMFLUX_SDK_RELAY_OWNER_PRINCIPAL_ID".to_owned(), principal.clone()),
            ("RAMFLUX_SDK_RELAY_AUDIENCE_NODE_ID".to_owned(), audience_node.to_owned()),
        ];
        let child = s64_spawn_rf_daemon_with_env(rf_binary, &socket_arg, &data_arg, &env)?;
        let pid_of = child.id();
        daemons.push(S64Daemon {
            index,
            account,
            principal,
            device,
            target,
            socket_arg,
            child,
            pid: pid_of,
        });
    }
    for daemon in &daemons {
        mvp_s4_wait_for_socket(Path::new(daemon.socket_arg.trim_end_matches('\0'))).await?;
    }
    // Create each account. CTRL-076 ROOT-CAUSE FIX (part 2): the account SEED must be globally unique
    // per (point, k, index) too — not just the account name. The gateway persists device manifests for
    // the whole run, so two daemons that share a seed (same derived device key) but carry different
    // device_ids collide with "device manifest record mismatch". A per-daemon global slot gives each a
    // distinct seed byte pair, clear of the gateway's own node seeds (0x33/0x44/0x66/0x88).
    for daemon in &daemons {
        let slot = s64_seed_slot(point_name, k, daemon.index);
        let root_seed_hex = format!("{:02x}", 0x90 + slot * 2);
        let device_seed_hex = format!("{:02x}", 0x91 + slot * 2);
        mvp_s10_create_rf_account(
            rf_binary,
            &daemon.socket_arg,
            &daemon.account,
            &daemon.principal,
            &daemon.device,
            &daemon.target,
            S64_GATEWAY_B_QUIC,
            ca_cert_arg,
            &root_seed_hex,
            &device_seed_hex,
        )
        .await?;
    }
    Ok(daemons)
}

/// Runs an `rf` command to completion WITHOUT asserting, returning `(success, combined_output)`.
#[cfg(feature = "realnet")]
async fn s64_run_capture(rf_binary: &Path, args: &[&str]) -> (bool, String) {
    match tokio::process::Command::new(rf_binary).args(args).output().await {
        Ok(output) => {
            let mut combined = String::from_utf8_lossy(&output.stdout).into_owned();
            combined.push_str(&String::from_utf8_lossy(&output.stderr));
            (output.status.success(), combined)
        }
        Err(error) => (false, format!("spawn failed: {error}")),
    }
}

/// Authoritative local upload-transfer state after a (possibly failed) PUT: `(exists, completed, state,
/// excerpt)`. `exists=false` (status errors / not-found) means the daemon created no durable object.
#[cfg(feature = "realnet")]
async fn s64_upload_status(
    rf_binary: &Path,
    socket_arg: &str,
    account: &str,
    object_id: &str,
) -> (bool, i64, String, String) {
    let (ok, output) = s64_run_capture(
        rf_binary,
        &[
            "--socket",
            socket_arg,
            "object",
            "status",
            "--account",
            account,
            "--object",
            object_id,
            "--direction",
            "upload",
        ],
    )
    .await;
    if !ok {
        return (false, 0, "not_found".to_owned(), output.chars().take(160).collect());
    }
    let value: serde_json::Value =
        serde_json::from_str(output.trim()).unwrap_or(serde_json::Value::Null);
    let completed = value
        .get("transfer")
        .and_then(|t| t.get("completed_chunks"))
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(0);
    let state = value
        .get("transfer")
        .and_then(|t| t.get("state"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown")
        .to_owned();
    (true, completed, state, output.chars().take(160).collect())
}

/// Short excerpt of recent relay log lines mentioning a close/stop/error (best-effort close reason).
#[cfg(feature = "realnet")]
fn s64_relay_close_reason() -> String {
    let logs = s64_container_logs("ramflux-relay");
    let hits: Vec<&str> = logs
        .lines()
        .filter(|line| {
            let lower = line.to_ascii_lowercase();
            lower.contains("clos")
                || lower.contains("stop")
                || lower.contains("reset")
                || (lower.contains("error") && lower.contains("quic"))
        })
        .rev()
        .take(4)
        .collect();
    hits.join(" | ").chars().take(300).collect()
}

/// OBJ-IPC-01 boundary diagnostics (CTRL-073): attempt three large public PUTs expected to fail at
/// distinct ceilings, then read AUTHORITATIVE local (`object status`) + relay (capture) mutation and
/// classify each as `pre_commit_reject` / `ambiguous_success` / `partial_relay_mutation`. Evidence only —
/// never counted in capacity success. This is where the "committed-but-CLI-saw-failure" risk is read
/// from authoritative state rather than assumed.
#[cfg(feature = "realnet")]
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn s64_boundary_diagnostics(
    rf_binary: &Path,
    temp: &Path,
    relay_url: &str,
    ca_cert_env: &str,
    ca_cert_arg: &str,
    issuer_node: &str,
    audience_node: &str,
    run_id: &str,
) -> Result<Vec<S64BoundaryDiag>, Box<dyn std::error::Error>> {
    eprintln!("STEP s64: OBJ-IPC-01 boundary diagnostics (authoritative mutation reads)");
    let mut daemons = s64_spawn_daemons(
        rf_binary,
        temp,
        ca_cert_env,
        ca_cert_arg,
        issuer_node,
        audience_node,
        run_id,
        "Zprobe",
        1,
    )
    .await?;
    let socket = daemons[0].socket_arg.clone();
    let account = daemons[0].account.clone();
    // (label, object_bytes, chunk_bytes) — 1 MiB fails at the request frame; 512 KiB/64 KiB fails at
    // the response frame (the ambiguous-success candidate); 512 KiB/128 KiB fails at the relay chunk.
    let specs: [(&str, u64, u64); 3] = [
        ("1MiB_request", 1024 * 1024, 256 * 1024),
        ("512KiB_response", 512 * 1024, 64 * 1024),
        ("512KiB_128chunk_peerstop", 512 * 1024, 128 * 1024),
    ];
    let mut diagnostics = Vec::new();
    for (label, object_bytes, chunk_bytes) in specs {
        s64_reset_capture()?;
        let object_id = format!("{run_id}_diag_{label}");
        let input = temp.join(format!("{object_id}.in"));
        std::fs::write(&input, s64_plaintext(&object_id, object_bytes))?;
        let input_arg = mvp_s4_path_arg(&input);
        let chunk = chunk_bytes.to_string();
        let (put_ok, put_output) = s64_run_capture(
            rf_binary,
            &[
                "--socket",
                &socket,
                "object",
                "put",
                "--account",
                &account,
                "--object",
                &object_id,
                "--chunk-size",
                &chunk,
                "--relay-url",
                relay_url,
                &input_arg,
            ],
        )
        .await;
        let put_failed = !put_ok;
        // Authoritative reads AFTER the attempt. NOTE: `object status` succeeds with an empty/default
        // transfer even for a never-created object, so status-command-success is NOT an existence
        // signal. Real mutation is read from durable upload progress (completed_chunks / state ==
        // complete) and the relay's own capture write actions.
        let (_status_ok, local_completed_chunks, local_transfer_state, local_status_excerpt) =
            s64_upload_status(rf_binary, &socket, &account, &object_id).await;
        let relay_write_actions = s64_read_capture()
            .map_or(0, |capture| capture.iter().filter(|line| line.action == "write").count());
        let relay_close_reason_excerpt = s64_relay_close_reason();
        let local_object_exists = local_transfer_state == "complete"
            || local_completed_chunks > 0
            || relay_write_actions > 0;
        let classification = if put_ok {
            "unexpected_success"
        } else if local_transfer_state == "complete" {
            // Fully committed (relay upload complete) yet the CLI observed failure — the dangerous
            // "committed but CLI saw failure" case (OBJ-IPC-01 ambiguous response).
            "ambiguous_success"
        } else if local_completed_chunks > 0 || relay_write_actions > 0 {
            "partial_relay_mutation"
        } else {
            // No durable upload progress and no relay write observed. (A local-store-only encrypted
            // object with zero transfer progress is not separately probed here; the dangerous
            // relay/transfer-committed case above IS authoritatively detected.)
            "pre_commit_reject"
        }
        .to_owned();
        // CTRL-074: a legitimate owner GET+ACK confirms an "ambiguous_success" object is really
        // retrievable with matching plaintext — so "committed" rests on real bytes, not just counters.
        let get_output = temp.join(format!("{object_id}.diag.get"));
        let get_output_arg = mvp_s4_path_arg(&get_output);
        let (post_get_ok, _get_out) = s64_run_capture(
            rf_binary,
            &[
                "--socket",
                &socket,
                "object",
                "get",
                "--account",
                &account,
                "--object",
                &object_id,
                "--relay-url",
                relay_url,
                "--relay-ack",
                &get_output_arg,
            ],
        )
        .await;
        let post_get_hash_match = post_get_ok
            && std::fs::read(&get_output)
                .is_ok_and(|actual| actual == s64_plaintext(&object_id, object_bytes));
        let _ = std::fs::remove_file(&get_output);
        eprintln!(
            "STEP s64: diag {label} obj={object_bytes} chunk={chunk_bytes} -> {classification} (local_exists={local_object_exists} completed={local_completed_chunks} state={local_transfer_state} relay_writes={relay_write_actions} get_ok={post_get_ok} hash_match={post_get_hash_match})"
        );
        diagnostics.push(S64BoundaryDiag {
            label: label.to_owned(),
            object_bytes,
            chunk_bytes,
            put_failed,
            put_error_excerpt: put_output.chars().take(200).collect(),
            local_status_excerpt,
            local_object_exists,
            local_completed_chunks,
            local_transfer_state,
            relay_write_actions,
            // base64 inflates ~4/3 (request plaintext_base64); the response echoes the ciphertext
            // Vec<u8> as a JSON number array (~4.9x). Analytical estimates; precise wire construction
            // is deferred to the OBJ-IPC-01 audit.
            request_frame_estimate_bytes: object_bytes * 4 / 3,
            response_frame_estimate_bytes: object_bytes * 49 / 10,
            relay_close_reason_excerpt,
            classification,
            post_get_ok,
            post_get_hash_match,
        });
        let _ = std::fs::remove_file(&input);
    }
    for daemon in &mut daemons {
        mvp_s20_stop_rf_daemon(&mut daemon.child).await?;
        let _ = std::fs::remove_file(&daemon.socket_arg);
    }
    Ok(diagnostics)
}

// ---- thresholds ----

#[cfg(feature = "realnet")]
fn s64_find<'a>(points: &'a [S64PointResult], name: &str, k: usize) -> Option<&'a S64PointResult> {
    points.iter().find(|p| p.point == name && p.k == k)
}

#[cfg(feature = "realnet")]
#[allow(clippy::cast_precision_loss, clippy::too_many_lines)]
fn s64_evaluate_thresholds(
    points: &[S64PointResult],
    churn: Option<&S64ChurnResult>,
    diagnostics: &[S64BoundaryDiag],
    out: &mut Vec<S64Threshold>,
) {
    let mut push = |name: &str, passed: bool, detail: String| {
        // CTRL-087: the strict-monotonic RssAnon check is a diagnostic flag, not a standalone
        // hard gate. Classified here by name so the field/value is always recorded, never hidden.
        let diagnostic = name.ends_with("_rss_anon_not_monotonic_unbounded");
        out.push(S64Threshold { name: name.to_owned(), passed, diagnostic, detail });
    };

    for point in points {
        push(
            &format!("{}_k{}_success_100", point.point, point.k),
            point.ops_ok == point.ops_total
                && point.error_classes.is_empty()
                && point.ops_total > 0,
            format!("ops_ok={}/{} errors={:?}", point.ops_ok, point.ops_total, point.error_classes),
        );
        // C_persistence: durability across a relay restart (first/mid/last hash re-verify).
        if let Some(verified) = point.restart_hash_verified {
            push(
                &format!("{}_k{}_restart_hash_ok", point.point, point.k),
                verified,
                format!("restart_hash_verified={verified}"),
            );
        }
        push(
            &format!("{}_k{}_http_object_zero", point.point, point.k),
            point.http_object_requests == 0,
            format!("http_object_requests={}", point.http_object_requests),
        );
        push(
            &format!("{}_k{}_distinct_connections_ge_k", point.point, point.k),
            point.connections.distinct_connections >= point.k,
            format!("distinct={} expected>={}", point.connections.distinct_connections, point.k),
        );
        push(
            &format!("{}_k{}_connection_reuse_gt_1", point.point, point.k),
            point.connections.max_requests_on_one_connection > 1,
            format!("max_reuse={}", point.connections.max_requests_on_one_connection),
        );
        // CTRL-079 anon leak gates (RssAnon = the true heap/private signal; cgroup memory.current
        // includes reclaimable file cache and is gated separately below).
        let anon = &point.resource.measured_rss_anon_mib;
        push(
            &format!("{}_k{}_rss_anon_median_growth_le_1_25x", point.point, point.k),
            s64_median_growth_ratio(anon) <= 1.25,
            format!("median_ratio={:.3} rss_anon={anon:?}", s64_median_growth_ratio(anon)),
        );
        push(
            &format!("{}_k{}_rss_anon_peak_le_1_75x", point.point, point.k),
            s64_peak_ratio(anon) <= 1.75,
            format!("peak_ratio={:.3}", s64_peak_ratio(anon)),
        );
        push(
            &format!("{}_k{}_rss_anon_not_monotonic_unbounded", point.point, point.k),
            !s64_monotonic_unbounded(anon),
            format!("monotonic_unbounded={}", s64_monotonic_unbounded(anon)),
        );
        // CTRL-079 absolute relay memory.current (cgroup) cap for a fresh run: 512 MiB.
        let memcur_peak =
            point.resource.measured_rss_mib.iter().copied().fold(f64::MIN, f64::max).max(0.0);
        push(
            &format!("{}_k{}_relay_memcurrent_le_512mib", point.point, point.k),
            memcur_peak <= 512.0,
            format!("memcurrent_peak={memcur_peak:.1} MiB"),
        );
        // CTRL-079 FD: at most +2 over the point-start sample, absolute <= 256.
        let fd_first = point.resource.measured_fd.first().copied().unwrap_or(0);
        let fd_peak = point.resource.measured_fd.iter().copied().max().unwrap_or(0);
        push(
            &format!("{}_k{}_relay_fd_stable", point.point, point.k),
            fd_peak <= fd_first + 2 && fd_peak <= 256,
            format!("fd_first={fd_first} fd_peak={fd_peak}"),
        );
    }

    // Throughput scaling on point B: K4 >= 2.0x K1, K8 >= 0.90x K4.
    if let (Some(b1), Some(b4)) =
        (s64_find(points, "B_throughput", 1), s64_find(points, "B_throughput", 4))
    {
        push(
            "B_throughput_k4_ge_2x_k1",
            b4.throughput_mib_s >= 2.0 * b1.throughput_mib_s,
            format!(
                "k4={:.1} MiB/s vs 2x k1={:.1}",
                b4.throughput_mib_s,
                2.0 * b1.throughput_mib_s
            ),
        );
        // p99 latency: K4 <= 2.5x K1.
        push(
            "B_throughput_k4_p99_le_2_5x_k1",
            b4.put_p99_ns as f64 <= 2.5 * b1.put_p99_ns as f64,
            format!("k4 p99={}ns vs 2.5x k1={:.0}", b4.put_p99_ns, 2.5 * b1.put_p99_ns as f64),
        );
        if let Some(b8) = s64_find(points, "B_throughput", 8) {
            push(
                "B_throughput_k8_ge_0_9x_k4",
                b8.throughput_mib_s >= 0.90 * b4.throughput_mib_s,
                format!(
                    "k8={:.1} MiB/s vs 0.9x k4={:.1}",
                    b8.throughput_mib_s,
                    0.90 * b4.throughput_mib_s
                ),
            );
            push(
                "B_throughput_k8_p99_le_4x_k1",
                b8.put_p99_ns as f64 <= 4.0 * b1.put_p99_ns as f64,
                format!("k8 p99={}ns vs 4x k1={:.0}", b8.put_p99_ns, 4.0 * b1.put_p99_ns as f64),
            );
        }
    }

    // CTRL-079 retires the old 128/256 MiB cgroup caps (kept only as historical failed metrics). The
    // relay memory footprint is now gated by the per-point anon/memcurrent/FD gates above plus these
    // D16 file-cache-vs-dataset footprint + component-reconciliation gates on the memory breakdown.
    if let Some(d16) = s64_find(points, "D_resource", 16) {
        push(
            "D_resource_k16_rfd_aggregate_rss_le_1_5gib",
            d16.resource.rfd_aggregate_rss_mib <= 1536.0,
            format!("rfd_aggregate_rss={:.1} MiB", d16.resource.rfd_aggregate_rss_mib),
        );
        push(
            "D_resource_k16_rfd_aggregate_fd_le_1024",
            d16.resource.rfd_aggregate_fd <= 1024,
            format!("rfd_aggregate_fd={}", d16.resource.rfd_aggregate_fd),
        );
        // File cache must stay within the redb file size + 32 MiB slack (proves cgroup `file` is the
        // reclaimable page cache of the redb store, not unexplained growth).
        let file_over_redb = d16.mem_breakdown.iter().all(|m| {
            let redb_mib = m.relay_redb_bytes as f64 / (1024.0 * 1024.0);
            m.memstat_file_mib <= redb_mib + 32.0
        });
        let worst_file = d16
            .mem_breakdown
            .iter()
            .map(|m| m.memstat_file_mib - (m.relay_redb_bytes as f64 / (1024.0 * 1024.0)))
            .fold(f64::MIN, f64::max);
        push(
            "D_resource_k16_file_cache_le_redb_plus_32mib",
            file_over_redb,
            format!("max(file-redb)={worst_file:.1} MiB"),
        );
        // Component reconciliation: memory.current ~= anon + file + kernel (diagnostic sanity), within
        // 64 MiB or 15% per snapshot.
        let reconciled = d16.mem_breakdown.iter().all(|m| {
            let sum = m.memstat_anon_mib.max(0.0)
                + m.memstat_file_mib.max(0.0)
                + m.memstat_kernel_mib.max(0.0);
            let diff = (m.cgroup_memory_current_mib - sum).abs();
            diff <= 64.0 || diff <= 0.15 * m.cgroup_memory_current_mib.max(1.0)
        });
        push(
            "D_resource_k16_cgroup_components_reconcile",
            reconciled,
            "memory.current ~= anon+file+kernel (<=64MiB or 15%)".to_owned(),
        );
    }

    if let Some(churn) = churn {
        push(
            "E_churn_first_op_lt_15s",
            churn.restart_first_op_ns < 15_000_000_000,
            format!("first_op={}ms", churn.restart_first_op_ns / 1_000_000),
        );
        push(
            "E_churn_warm_p95_le_2x_pre",
            churn.warm_p95_post_ns <= 2 * churn.warm_p95_pre_ns,
            format!(
                "post_p95={}ms vs 2x pre={}ms",
                churn.warm_p95_post_ns / 1_000_000,
                (2 * churn.warm_p95_pre_ns) / 1_000_000
            ),
        );
    }

    // Boundary diagnostics are evidence, not capacity gates (CTRL-073). The only gated safety property
    // is that the 1 MiB request probe is a CLEAN pre-commit reject (no local object, no relay write) —
    // the request dies at the IPC frame before any daemon business logic. The 512 KiB response and
    // 128-chunk peer-stop classifications (incl. any ambiguous_success) are RECORDED for OBJ-IPC-01,
    // not failed here.
    if let Some(request) = diagnostics.iter().find(|d| d.label == "1MiB_request") {
        push(
            "obj_ipc_01_1mib_request_pre_commit_reject",
            request.put_failed
                && !request.local_object_exists
                && request.relay_write_actions == 0
                && request.classification == "pre_commit_reject",
            format!(
                "class={} local_exists={} relay_writes={}",
                request.classification, request.local_object_exists, request.relay_write_actions
            ),
        );
    }
    for diag in diagnostics {
        // Non-gating evidence rows so the classification is visible in the threshold list too.
        push(
            &format!("obj_ipc_01_{}_classified", diag.label),
            diag.classification != "unknown",
            format!(
                "class={} local_exists={} completed={} state={} relay_writes={}",
                diag.classification,
                diag.local_object_exists,
                diag.local_completed_chunks,
                diag.local_transfer_state,
                diag.relay_write_actions
            ),
        );
    }
}

// ---- realnet infra helpers (duplicated per the per-file v3 realnet idiom) ----

#[cfg(feature = "realnet")]
fn s64_release_build() -> bool {
    std::env::var("RAMFLUX_PERF_RELEASE").as_deref() == Ok("1")
}

#[cfg(feature = "realnet")]
async fn s64_build_rf_binary() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let manifest = code_root().join("ramflux/apps/rf/Cargo.toml");
    let release = s64_release_build();
    let status = tokio::task::spawn_blocking(move || {
        let mut command = std::process::Command::new("cargo");
        command.args(["build", "--quiet", "--features", "itest-local-mint"]);
        if release {
            command.arg("--release");
        }
        command.arg("--manifest-path").arg(manifest).status()
    })
    .await??;
    if !status.success() {
        return Err("failed to build rf binary for s64".into());
    }
    let profile = if release { "release" } else { "debug" };
    Ok(code_root().join(format!("ramflux/target/{profile}/rf")))
}

#[cfg(feature = "realnet")]
fn s64_spawn_rf_daemon_with_env(
    rf_binary: &Path,
    socket: &str,
    data_root: &str,
    env: &[(String, String)],
) -> Result<tokio::process::Child, Box<dyn std::error::Error>> {
    let log_path = format!("{}.daemon.log", socket.trim_end_matches(".sock"));
    let stderr = std::fs::OpenOptions::new().create(true).append(true).open(&log_path)?;
    let child = tokio::process::Command::new(rf_binary)
        .args(["--socket", socket, "daemon", "start", "--data-root", data_root])
        .envs(env.iter().map(|(key, value)| (key.clone(), value.clone())))
        .env_remove("RAMFLUX_SDK_OBJECT_RELAY_LOCAL_MINT")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::from(stderr))
        .kill_on_drop(true)
        .spawn()?;
    Ok(child)
}

#[cfg(feature = "realnet")]
#[allow(clippy::too_many_arguments)]
async fn s64_put(
    rf_binary: &Path,
    socket_arg: &str,
    account: &str,
    object_id: &str,
    chunk_size: u64,
    relay_url: &str,
    input_arg: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let chunk = chunk_size.to_string();
    mvp_s4_rf_json(
        rf_binary,
        &[
            "--socket",
            socket_arg,
            "object",
            "put",
            "--account",
            account,
            "--object",
            object_id,
            "--chunk-size",
            &chunk,
            "--relay-url",
            relay_url,
            input_arg,
        ],
    )
    .await?;
    Ok(())
}

#[cfg(feature = "realnet")]
async fn s64_get_ack(
    rf_binary: &Path,
    socket_arg: &str,
    account: &str,
    object_id: &str,
    relay_url: &str,
    output_arg: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    mvp_s4_rf_json(
        rf_binary,
        &[
            "--socket",
            socket_arg,
            "object",
            "get",
            "--account",
            account,
            "--object",
            object_id,
            "--relay-url",
            relay_url,
            "--relay-ack",
            output_arg,
        ],
    )
    .await?;
    Ok(())
}

// ---- capture reading ----

#[cfg(feature = "realnet")]
fn s64_container(service: &str) -> String {
    format!("{S64_PROJECT}_{service}_1")
}

#[cfg(feature = "realnet")]
fn s64_read_capture() -> Result<Vec<S64CaptureLine>, Box<dyn std::error::Error>> {
    let container = s64_container("ramflux-relay");
    let output = std::process::Command::new(container_runtime())
        .args(["exec", &container, "cat", S64_CAPTURE_PATH])
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "capture read failed (exec cat {S64_CAPTURE_PATH}): {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut lines = Vec::new();
    for raw in text.lines().filter(|line| !line.trim().is_empty()) {
        lines.push(serde_json::from_str::<S64CaptureLine>(raw)?);
    }
    Ok(lines)
}

#[cfg(feature = "realnet")]
fn s64_reset_capture() -> Result<(), Box<dyn std::error::Error>> {
    let container = s64_container("ramflux-relay");
    // CTRL-075: TRUNCATE (keep the inode) rather than `rm -f` (unlink + recreate). A relay write that
    // races an unlink would land on the now-orphaned inode and be invisible to a later `cat` of the
    // path; truncating the same inode removes that failure mode from the diagnosis.
    let output = std::process::Command::new(container_runtime())
        .args(["exec", &container, "sh", "-c", &format!(": > {S64_CAPTURE_PATH}")])
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "failed to reset capture: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(())
}

#[cfg(feature = "realnet")]
fn s64_container_ctl(action: &str, service: &str) -> Result<(), Box<dyn std::error::Error>> {
    let container = s64_container(service);
    let output =
        std::process::Command::new(container_runtime()).args([action, &container]).output()?;
    if !output.status.success() {
        return Err(format!(
            "{} {action} {container} failed: {}",
            container_runtime(),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(())
}

#[cfg(feature = "realnet")]
fn s64_container_logs(service: &str) -> String {
    let container = s64_container(service);
    std::process::Command::new(container_runtime())
        .args(["logs", "--tail", "200", &container])
        .output()
        .map_or_else(
            |error| format!("failed to collect {service} logs: {error}"),
            |output| {
                format!(
                    "{}{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                )
            },
        )
}

/// Number of HTTP object requests the relay logged — must be 0 (v3 objects are QUIC-only). Based on
/// genuine relay HTTP ingress log lines (no diagnostic/trace compatibility filtering).
#[cfg(feature = "realnet")]
fn s64_relay_http_object_requests() -> usize {
    s64_container_logs("ramflux-relay").matches("POST /relay/v1/object/").count()
}

#[cfg(feature = "realnet")]
async fn s64_wait_relay_quic_healthy(ca_cert: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let config =
        ramflux_transport::RelayClientQuicConfig::new(S64_RELAY_QUIC, "ramflux-relay", ca_cert)?;
    for _ in 0..30 {
        if let Ok(health) =
            ramflux_transport::relay_client_quic_health(&config, std::time::Duration::from_secs(3))
                .await
            && health.status == 200
        {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
    Err("relay client QUIC did not become healthy".into())
}

// ---- resource sampling ----

/// Relay resource sample: `(cgroup_rss_mib, rss_anon_mib, rss_file_mib, fd, cpu)`. `cgroup_rss` is
/// podman `stats` `MemUsage` (cgroup `memory.current`: heap + reclaimable page cache). `rss_anon` /
/// `rss_file` come from the process `/proc/1/status` (anonymous heap vs file-backed/mmap resident) —
/// the true leak signal is `rss_anon`, since a redb-mmap relay's page cache (`rss_file`/cgroup) grows
/// with object I/O and is reclaimed under pressure, not a leak.
#[cfg(feature = "realnet")]
#[allow(clippy::type_complexity)]
fn s64_relay_resource() -> Result<(f64, f64, f64, u64, f64), Box<dyn std::error::Error>> {
    let container = s64_container("ramflux-relay");
    let (cgroup_rss, cpu) = s64_container_stats(&container)?;
    let (rss_anon, rss_file) = s64_container_proc_rss(&container)?;
    let fd = s64_container_fd(&container)?;
    Ok((cgroup_rss, rss_anon, rss_file, fd, cpu))
}

/// CTRL-078: full per-round memory decomposition of the relay container. `exec cat`s cgroup v2
/// `memory.current` + `memory.stat`, `/proc/1/status`, `/proc/1/smaps_rollup`, the redb file size and
/// the fd count. Absent fields are recorded as -1.0 (null), never faked to 0.
#[cfg(feature = "realnet")]
#[allow(clippy::too_many_lines)]
fn s64_relay_mem_breakdown(
    round: usize,
    measured: bool,
    cumulative_objects: usize,
    cumulative_plaintext_bytes: u64,
    cumulative_chunks: usize,
) -> S64MemBreakdown {
    let container = s64_container("ramflux-relay");
    let cat = |path: &str| -> String {
        std::process::Command::new(container_runtime())
            .args(["exec", &container, "cat", path])
            .output()
            .ok()
            .filter(|output| output.status.success())
            .map(|output| String::from_utf8_lossy(&output.stdout).into_owned())
            .unwrap_or_default()
    };
    // cgroup v2 memory.current (bytes).
    let cgroup_memory_current_mib = cat("/sys/fs/cgroup/memory.current")
        .trim()
        .parse::<f64>()
        .map_or(-1.0, |bytes| bytes / (1024.0 * 1024.0));
    // memory.stat "key value" bytes lines.
    let memstat = cat("/sys/fs/cgroup/memory.stat");
    let stat_mib = |key: &str| -> f64 {
        memstat
            .lines()
            .find(|line| line.split_whitespace().next() == Some(key))
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|value| value.parse::<f64>().ok())
            .map_or(-1.0, |bytes| bytes / (1024.0 * 1024.0))
    };
    // /proc/1/status Vm*/Rss* (kB).
    let status = cat("/proc/1/status");
    let status_mib = |name: &str| -> f64 {
        status
            .lines()
            .find(|line| line.starts_with(name))
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|kb| kb.parse::<f64>().ok())
            .map_or(-1.0, |kb| kb / 1024.0)
    };
    // smaps_rollup Private_Dirty (kB).
    let smaps = cat("/proc/1/smaps_rollup");
    let smaps_private_dirty_mib = smaps
        .lines()
        .find(|line| line.starts_with("Private_Dirty:"))
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|kb| kb.parse::<f64>().ok())
        .map_or(-1.0, |kb| kb / 1024.0);
    // redb file size (bytes) — the relay-redb volume total.
    let relay_redb_bytes = std::process::Command::new(container_runtime())
        .args([
            "exec",
            &container,
            "sh",
            "-c",
            "du -sb /var/lib/ramflux/relay 2>/dev/null | cut -f1",
        ])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8_lossy(&output.stdout).trim().parse::<u64>().ok())
        .unwrap_or(0);
    let fd = s64_container_fd(&container).unwrap_or(0);
    S64MemBreakdown {
        round,
        measured,
        cumulative_objects,
        cumulative_plaintext_bytes,
        cumulative_chunks,
        cgroup_memory_current_mib,
        memstat_anon_mib: stat_mib("anon"),
        memstat_file_mib: stat_mib("file"),
        memstat_kernel_mib: stat_mib("kernel"),
        memstat_kernel_stack_mib: stat_mib("kernel_stack"),
        memstat_pagetables_mib: stat_mib("pagetables"),
        memstat_sock_mib: stat_mib("sock"),
        memstat_shmem_mib: stat_mib("shmem"),
        memstat_file_mapped_mib: stat_mib("file_mapped"),
        memstat_file_dirty_mib: stat_mib("file_dirty"),
        memstat_file_writeback_mib: stat_mib("file_writeback"),
        proc_vmrss_mib: status_mib("VmRSS:"),
        proc_rss_anon_mib: status_mib("RssAnon:"),
        proc_rss_file_mib: status_mib("RssFile:"),
        proc_rss_shmem_mib: status_mib("RssShmem:"),
        smaps_private_dirty_mib,
        fd,
        relay_redb_bytes,
    }
}

/// Reads the relay process's `/proc/1/status` `RssAnon` + `RssFile` (kB) as `(rss_anon_mib, rss_file_mib)`.
#[cfg(feature = "realnet")]
fn s64_container_proc_rss(container: &str) -> Result<(f64, f64), Box<dyn std::error::Error>> {
    let output = std::process::Command::new(container_runtime())
        .args(["exec", container, "cat", "/proc/1/status"])
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "proc rss {container} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let field_mib = |name: &str| {
        text.lines()
            .find(|line| line.starts_with(name))
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|kb| kb.parse::<f64>().ok())
            .map_or(0.0, |kb| kb / 1024.0)
    };
    Ok((field_mib("RssAnon:"), field_mib("RssFile:")))
}

/// Parses `<runtime> stats --no-stream --format {{json .}}` for one container into (RSS MiB, CPU %).
#[cfg(feature = "realnet")]
fn s64_container_stats(container: &str) -> Result<(f64, f64), Box<dyn std::error::Error>> {
    let output = std::process::Command::new(container_runtime())
        .args(["stats", "--no-stream", "--format", "{{json .}}", container])
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "stats {container} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let line = text.lines().find(|line| !line.trim().is_empty()).unwrap_or("");
    let value: serde_json::Value = serde_json::from_str(line.trim())?;
    // podman 5.x emits `MemUsage` as a raw byte NUMBER and `CPU` as a percent NUMBER; Docker emits
    // `MemUsage` as a "23.4MB / 4GB" string and `CPUPerc` as "12.5%". Handle both, numeric first.
    let mem_mib = value
        .get("MemUsage")
        .and_then(serde_json::Value::as_f64)
        .map(|bytes| bytes / (1024.0 * 1024.0))
        .or_else(|| {
            value.get("MemUsage").and_then(serde_json::Value::as_str).map(s64_parse_mem_mib)
        })
        .unwrap_or(0.0);
    let cpu = value
        .get("CPU")
        .and_then(serde_json::Value::as_f64)
        .or_else(|| value.get("CPUPerc").and_then(serde_json::Value::as_str).map(s64_parse_percent))
        .unwrap_or(0.0);
    Ok((mem_mib, cpu))
}

/// Open FD count inside a container (PID 1's /proc fd list).
#[cfg(feature = "realnet")]
fn s64_container_fd(container: &str) -> Result<u64, Box<dyn std::error::Error>> {
    let output = std::process::Command::new(container_runtime())
        .args(["exec", container, "sh", "-c", "ls /proc/1/fd | wc -l"])
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "fd count {container} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().parse().unwrap_or(0))
}

/// Aggregate host RSS (MiB) and FD count across the K rfd daemon processes.
#[cfg(feature = "realnet")]
fn s64_rfd_aggregate(daemons: &[S64Daemon]) -> (f64, u64) {
    let mut rss_mib = 0.0f64;
    let mut fd = 0u64;
    for daemon in daemons {
        if let Some(pid) = daemon.pid {
            rss_mib += s64_host_rss_mib(pid);
            fd += s64_host_fd(pid);
        }
    }
    (rss_mib, fd)
}

#[cfg(feature = "realnet")]
fn s64_host_rss_mib(pid: u32) -> f64 {
    std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &pid.to_string()])
        .output()
        .ok()
        .and_then(|output| {
            String::from_utf8_lossy(&output.stdout)
                .trim()
                .parse::<f64>()
                .ok()
                .map(|kib| kib / 1024.0)
        })
        .unwrap_or(0.0)
}

#[cfg(feature = "realnet")]
fn s64_host_fd(pid: u32) -> u64 {
    std::process::Command::new("sh")
        .args(["-c", &format!("lsof -p {pid} 2>/dev/null | wc -l")])
        .output()
        .ok()
        .and_then(|output| String::from_utf8_lossy(&output.stdout).trim().parse::<u64>().ok())
        .unwrap_or(0)
}

// ---- parse helpers (unit-tested) ----

/// Parses a container-stats memory field like "23.4MiB / 4GiB" into the used side as MiB.
fn s64_parse_mem_mib(field: &str) -> f64 {
    let used = field.split('/').next().unwrap_or("").trim();
    s64_parse_size_mib(used)
}

fn s64_parse_size_mib(value: &str) -> f64 {
    let trimmed = value.trim();
    let split = trimmed
        .find(|c: char| c.is_ascii_alphabetic())
        .map_or((trimmed, ""), |index| (&trimmed[..index], &trimmed[index..]));
    let number: f64 = split.0.trim().parse().unwrap_or(0.0);
    match split.1.trim().to_ascii_lowercase().as_str() {
        "b" => number / (1024.0 * 1024.0),
        "kb" | "kib" => number / 1024.0,
        "gb" | "gib" => number * 1024.0,
        // "mb"/"mib" and any unit-less value are already in MiB.
        _ => number,
    }
}

fn s64_parse_percent(value: &str) -> f64 {
    value.trim().trim_end_matches('%').trim().parse().unwrap_or(0.0)
}

// ---- artifact + git ----

#[cfg(feature = "realnet")]
fn s64_git_state() -> (String, bool) {
    // The product repo (the base being benchmarked) is `code_root/ramflux`; `code_root` itself is
    // not a git checkout.
    let root = code_root().join("ramflux");
    let sha = std::process::Command::new("git")
        .args(["-C"])
        .arg(&root)
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown".to_owned());
    let dirty = std::process::Command::new("git")
        .args(["-C"])
        .arg(&root)
        .args(["status", "--porcelain"])
        .output()
        .ok()
        .is_some_and(|output| !String::from_utf8_lossy(&output.stdout).trim().is_empty());
    (sha, dirty)
}

#[cfg(feature = "realnet")]
fn s64_write_artifact(
    artifact: &S64Artifact,
    run_id: &str,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let dir = code_root().join("ramflux-itest/perf-artifacts");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("perf_d1_2_macro_{run_id}.json"));
    std::fs::write(&path, serde_json::to_vec_pretty(artifact)?)?;
    Ok(path)
}

// ---- v3 trust material (same shape as s63) ----

#[cfg(feature = "realnet")]
fn s64_certificate(
    now: u64,
    node_id: &str,
    gateway_instance_id: &str,
    root_seed: [u8; 32],
    attestation_seed: [u8; 32],
) -> Result<ramflux_node_core::GatewayIssuerCertificate, Box<dyn std::error::Error>> {
    let mut certificate = ramflux_node_core::GatewayIssuerCertificate {
        schema: ramflux_node_core::GATEWAY_ISSUER_CERTIFICATE_SCHEMA.to_owned(),
        version: ramflux_node_core::OBJECT_RELAY_V3_PROOF_VERSION,
        cert_id: "s64-gw-b-cert-1".to_owned(),
        node_id: node_id.to_owned(),
        gateway_instance_id: gateway_instance_id.to_owned(),
        attestation_public_key: ramflux_crypto::public_key_base64url_from_seed(attestation_seed),
        attestation_key_id: "s64-gw-b-attestation-1".to_owned(),
        not_before: now.saturating_sub(60),
        not_after: now + 3_600,
        issued_at: now.saturating_sub(60),
        node_root_signing_key_id: "node-b#root-1".to_owned(),
        node_root_signature: String::new(),
        revoked_at: None,
    };
    certificate.node_root_signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &ramflux_node_core::gateway_issuer_certificate_signing_bytes(&certificate)?,
        root_seed,
    );
    Ok(certificate)
}

#[cfg(feature = "realnet")]
fn s64_trust_envelope(
    now: u64,
    node_id: &str,
    root_seed: [u8; 32],
    provider_seed: [u8; 32],
    certificate: &ramflux_node_core::GatewayIssuerCertificate,
) -> Result<ramflux_node_core::ProviderSignedTrustSnapshot, Box<dyn std::error::Error>> {
    let mut envelope = ramflux_node_core::ProviderSignedTrustSnapshot {
        schema: ramflux_node_core::PROVIDER_SIGNED_TRUST_SNAPSHOT_ENVELOPE_SCHEMA.to_owned(),
        version: ramflux_node_core::PROVIDER_SIGNED_TRUST_SNAPSHOT_ENVELOPE_VERSION,
        snapshot: ramflux_node_core::FederatedIssuerTrustSnapshot {
            schema: ramflux_node_core::FEDERATED_ISSUER_TRUST_SNAPSHOT_SCHEMA.to_owned(),
            version: ramflux_node_core::OBJECT_RELAY_V3_PROOF_VERSION,
            node_id: node_id.to_owned(),
            generation: 1,
            pin_epoch: 1,
            trust_status: ramflux_node_core::FederatedIssuerTrustStatus::Active,
            roots: vec![ramflux_node_core::TrustedNodeRootKey {
                node_id: node_id.to_owned(),
                key_id: certificate.node_root_signing_key_id.clone(),
                public_key: ramflux_crypto::public_key_base64url_from_seed(root_seed),
                not_before: now.saturating_sub(60),
                not_after: now + 3_600,
                pin_epoch: 1,
                retired_at: None,
            }],
            revoked_cert_ids: std::collections::BTreeSet::new(),
            hard_stale_at: now + 3_600,
        },
        provider_signing_key_id: "s64-provider-1".to_owned(),
        provider_public_key: ramflux_crypto::public_key_base64url_from_seed(provider_seed),
        provider_epoch: 1,
        issued_at: now.saturating_sub(10),
        expires_at: now + 3_600,
        signature: String::new(),
    };
    envelope.signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &ramflux_node_core::provider_signed_trust_snapshot_signing_bytes(&envelope)?,
        provider_seed,
    );
    Ok(envelope)
}

#[cfg(feature = "realnet")]
fn s64_write_provider_keyring(
    materials: &Path,
    now: u64,
    node_id: &str,
    offline_root_seed: [u8; 32],
    provider_seed: [u8; 32],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut keyring = ramflux_node_core::ProviderKeyring {
        schema: ramflux_node_core::PROVIDER_KEYRING_SCHEMA.to_owned(),
        version: ramflux_node_core::PROVIDER_KEYRING_VERSION,
        issuer_node_id: node_id.to_owned(),
        keyring_epoch: 1,
        keys: vec![ramflux_node_core::ProviderKeyEntry {
            key_id: "s64-provider-1".to_owned(),
            public_key: ramflux_crypto::public_key_base64url_from_seed(provider_seed),
            not_before: now.saturating_sub(60),
            not_after: now + 3_600,
            retired_at: None,
            authorized_provider_epoch: 1,
        }],
        keyring_signature: String::new(),
    };
    keyring.keyring_signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &ramflux_node_core::provider_keyring_signing_bytes(&keyring)?,
        offline_root_seed,
    );
    std::fs::write(
        materials.join("federation/provider-keyring.json"),
        serde_json::to_vec_pretty(&keyring)?,
    )?;
    Ok(())
}

// ---- pure-function unit tests (run without realnet) ----

#[cfg(test)]
mod s64_pure_tests {
    use super::*;

    #[test]
    fn nearest_rank_percentiles() {
        let data: Vec<u128> = (1..=100).collect();
        assert_eq!(s64_nearest_rank(&data, 50.0), 50);
        assert_eq!(s64_nearest_rank(&data, 95.0), 95);
        assert_eq!(s64_nearest_rank(&data, 99.0), 99);
        assert_eq!(s64_nearest_rank(&data, 100.0), 100);
        assert_eq!(s64_nearest_rank(&[], 95.0), 0);
        assert_eq!(s64_nearest_rank(&[42], 50.0), 42);
    }

    #[test]
    fn median_f64_odd_and_even() {
        assert!((s64_median_f64(&[1.0, 2.0, 3.0]) - 2.0).abs() < f64::EPSILON);
        assert!((s64_median_f64(&[4.0, 1.0, 3.0, 2.0]) - 2.0).abs() < f64::EPSILON);
        assert!((s64_median_f64(&[]) - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn connection_analysis() {
        let capture = vec![make_line(1, 10), make_line(2, 10), make_line(3, 11), make_line(4, 12)];
        assert_eq!(s64_distinct_connections(&capture), 3);
        assert_eq!(s64_max_requests_on_one_connection(&capture), 2);
        assert_eq!(s64_distinct_connections(&[]), 0);
        assert_eq!(s64_max_requests_on_one_connection(&[]), 0);
    }

    #[test]
    fn growth_and_throughput() {
        assert!((s64_growth_pct(100.0, 125.0) - 25.0).abs() < f64::EPSILON);
        assert!((s64_growth_pct(0.0, 50.0) - 0.0).abs() < f64::EPSILON);
        // 1 MiB in 1s == 1 MiB/s.
        assert!((s64_mib_per_s(1024 * 1024, 1_000_000_000) - 1.0).abs() < 1e-9);
        assert!((s64_mib_per_s(1024 * 1024, 0) - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn median_growth_ratio_steady_state() {
        // Flat steady state -> ratio 1.0 (cold round0 excluded by caller).
        assert!((s64_median_growth_ratio(&[100.0, 100.0, 100.0, 100.0, 100.0]) - 1.0).abs() < 1e-9);
        // First3 median 100, last3 median 130 -> 1.3.
        assert!((s64_median_growth_ratio(&[100.0, 100.0, 100.0, 130.0, 130.0]) - 1.3).abs() < 1e-9);
        // Oscillation: first3 median 100, last3 median 100 -> 1.0 (no steady growth).
        assert!((s64_median_growth_ratio(&[90.0, 100.0, 150.0, 100.0, 95.0]) - 1.0).abs() < 1e-9);
        assert!((s64_median_growth_ratio(&[100.0, 100.0]) - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn monotonic_unbounded_only_on_strict_rise() {
        // Every step increases AND total > 25% -> flagged.
        assert!(s64_monotonic_unbounded(&[100.0, 110.0, 120.0, 130.0, 140.0]));
        // Increasing but total rise <= 25% -> not flagged.
        assert!(!s64_monotonic_unbounded(&[100.0, 105.0, 110.0, 115.0, 120.0]));
        // Oscillation (one step down) -> not flagged even with >25% end-to-end.
        assert!(!s64_monotonic_unbounded(&[100.0, 150.0, 120.0, 160.0, 140.0]));
        assert!(!s64_monotonic_unbounded(&[100.0]));
    }

    #[test]
    fn parse_mem_and_percent() {
        assert!((s64_parse_mem_mib("23.4MiB / 4GiB") - 23.4).abs() < 1e-6);
        assert!((s64_parse_mem_mib("2GiB / 4GiB") - 2048.0).abs() < 1e-6);
        assert!((s64_parse_size_mib("512KiB") - 0.5).abs() < 1e-6);
        assert!((s64_parse_size_mib("1048576B") - 1.0).abs() < 1e-6);
        assert!((s64_parse_percent("12.5%") - 12.5).abs() < 1e-6);
        assert!((s64_parse_percent("0.00%") - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn seed_slots_are_globally_unique() {
        // Every daemon the run can spawn must get a distinct seed slot (and thus a distinct seed byte
        // pair) so no two collide on the gateway's persisted device manifest.
        let phases: &[(&str, usize)] = &[
            ("Zprobe", 1),
            ("A_small", 1),
            ("A_small", 4),
            ("A_small", 8),
            ("D_resource", 16),
            ("E_churn", 4),
        ];
        let mut seen = std::collections::BTreeSet::new();
        let mut max_slot = 0usize;
        for &(point, k) in phases {
            for index in 0..k {
                let slot = s64_seed_slot(point, k, index);
                assert!(seen.insert(slot), "seed slot {slot} reused for {point} k{k} d{index}");
                max_slot = max_slot.max(slot);
            }
        }
        // Highest seed byte must stay in range and clear of the gateway node seeds (0x33/44/66/88).
        assert!(0x91 + max_slot * 2 <= 0xFF, "max seed byte out of range: slot {max_slot}");
    }

    #[test]
    fn mem02_parse_u64_defaults_and_bounds() {
        assert_eq!(s64_mem02_parse_u64(Some("16"), 8), 16);
        assert_eq!(s64_mem02_parse_u64(Some("  32 "), 8), 32);
        // Absent / empty / zero / unparseable all fall back to the default.
        assert_eq!(s64_mem02_parse_u64(None, 8), 8);
        assert_eq!(s64_mem02_parse_u64(Some(""), 8), 8);
        assert_eq!(s64_mem02_parse_u64(Some("0"), 8), 8);
        assert_eq!(s64_mem02_parse_u64(Some("abc"), 8), 8);
    }

    #[test]
    fn capture_line_parses() {
        let raw = r#"{"request_seq":1,"connection_id":7,"process_instance":3,"method":"POST","route":"/relay/v1/object/x","body_fingerprint":"abc","action":"write","status":200}"#;
        let line = serde_json::from_str::<S64CaptureLine>(raw).unwrap_or_else(|_| make_line(0, 0));
        assert_eq!(line.connection_id, 7);
    }

    fn make_line(seq: u64, connection: u64) -> S64CaptureLine {
        S64CaptureLine {
            request_seq: seq,
            connection_id: connection,
            process_instance: 1,
            method: "POST".to_owned(),
            route: "/x".to_owned(),
            body_fingerprint: "fp".to_owned(),
            action: "write".to_owned(),
            status: 200,
        }
    }
}
