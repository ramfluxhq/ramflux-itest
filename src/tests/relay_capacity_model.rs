// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Capacity benchmark artifact and capture models.
use super::*;

// ---- artifact model ----

#[cfg(feature = "realnet")]
#[derive(Clone, Debug, serde::Serialize)]
pub(super) struct S64Artifact {
    pub(super) schema: String,
    pub(super) run_id: String,
    pub(super) git_sha: String,
    pub(super) git_dirty: bool,
    pub(super) build: String,
    pub(super) generated_note: String,
    // CTRL-073 envelope declaration — the certified public object envelope + explicit large-object block.
    pub(super) public_envelope_class: String,
    pub(super) supported_public_object_bytes: u64,
    pub(super) known_limit_local_bus_frame_bytes: u64,
    pub(super) large_object_capacity: String,
    pub(super) large_object_public_path: String,
    // CTRL-077: per-phase namespace + seed-slot map. Proves every (point, k) phase occupies a disjoint
    // account/object/seed namespace, so the cross-K reuse bug (K=4 d0 reusing K=1 d0 state) cannot regress.
    pub(super) namespace_seed_slots: Vec<S64NamespaceEntry>,
    pub(super) points: Vec<S64PointResult>,
    pub(super) churn: Option<S64ChurnResult>,
    pub(super) boundary_diagnostics: Vec<S64BoundaryDiag>,
    pub(super) thresholds: Vec<S64Threshold>,
}

#[cfg(feature = "realnet")]
#[derive(Clone, Debug, serde::Serialize)]
pub(super) struct S64NamespaceEntry {
    pub(super) point: String,
    pub(super) k: usize,
    pub(super) account_prefix: String,
    pub(super) seed_slot_first: usize,
    pub(super) seed_slot_last: usize,
    pub(super) root_seed_first: String,
    pub(super) root_seed_last: String,
}

#[cfg(feature = "realnet")]
#[derive(Clone, Debug, serde::Serialize)]
pub(super) struct S64PointResult {
    pub(super) point: String,
    pub(super) k: usize,
    pub(super) rounds: usize,
    pub(super) object_bytes: u64,
    pub(super) chunk_bytes: u64,
    pub(super) objects_per_daemon_per_round: usize,
    pub(super) ops_total: usize,
    pub(super) ops_ok: usize,
    pub(super) error_classes: Vec<String>,
    pub(super) put_p50_ns: u128,
    pub(super) put_p95_ns: u128,
    pub(super) put_p99_ns: u128,
    pub(super) get_p50_ns: u128,
    pub(super) get_p95_ns: u128,
    pub(super) get_p99_ns: u128,
    pub(super) round_throughputs_mib_s: Vec<f64>,
    pub(super) throughput_mib_s: f64,
    pub(super) verified_objects: usize,
    pub(super) connections: S64ConnAnalysis,
    pub(super) resource: S64Resource,
    pub(super) http_object_requests: usize,
    // C_persistence only: after a relay restart, first/mid/last objects re-GET with matching hash.
    pub(super) restart_hash_verified: Option<bool>,
    // CTRL-078: D_resource only — per-round memory decomposition (empty for other points).
    pub(super) mem_breakdown: Vec<S64MemBreakdown>,
}

#[cfg(feature = "realnet")]
#[derive(Clone, Debug, serde::Serialize)]
pub(super) struct S64ConnAnalysis {
    pub(super) distinct_connections: usize,
    pub(super) max_requests_on_one_connection: usize,
    pub(super) expected_min_distinct: usize,
    pub(super) captured_lines: usize,
}

#[cfg(feature = "realnet")]
#[derive(Clone, Debug, Default, serde::Serialize)]
pub(super) struct S64Resource {
    // Per measured-round samples (warmup rounds excluded) — the authoritative growth evidence.
    // measured_rss_mib = cgroup memory.current (heap + reclaimable page cache); measured_rss_anon_mib
    // = the process anonymous heap (the true leak signal); measured_rss_file_mib = file-backed/mmap
    // resident (redb page cache, reclaimable).
    pub(super) measured_rss_mib: Vec<f64>,
    pub(super) measured_rss_anon_mib: Vec<f64>,
    pub(super) measured_rss_file_mib: Vec<f64>,
    pub(super) measured_fd: Vec<u64>,
    pub(super) relay_rss_first_mib: f64,
    pub(super) relay_rss_last_mib: f64,
    // CTRL-074 steady-state growth: median(last 3) / median(first 3) of the measured RSS samples.
    pub(super) relay_rss_median_growth_ratio: f64,
    pub(super) relay_rss_monotonic_unbounded: bool,
    pub(super) relay_fd_last: u64,
    pub(super) relay_cpu_last_pct: f64,
    pub(super) rfd_aggregate_rss_mib: f64,
    pub(super) rfd_aggregate_fd: u64,
}

#[cfg(feature = "realnet")]
#[derive(Clone, Debug, serde::Serialize)]
pub(super) struct S64ChurnResult {
    pub(super) k: usize,
    pub(super) restart_first_op_ns: u128,
    pub(super) warm_p95_pre_ns: u128,
    pub(super) warm_p95_post_ns: u128,
}

/// One OBJ-IPC-01 boundary diagnostic (CTRL-073): attempt a large public PUT that is expected to
/// fail, then read AUTHORITATIVE local (`object status`) + relay (capture write actions) mutation
/// state and classify the failure. NOT counted in capacity success — pure evidence for OBJ-IPC-01.
/// CTRL-078 D16 memory decomposition — one per round, to classify relay memory growth as reclaimable
/// file cache vs possible heap/private growth. Fields absent on the host are recorded as -1.0 (null),
/// never faked to 0.
#[cfg(feature = "realnet")]
#[derive(Clone, Debug, serde::Serialize)]
pub(super) struct S64MemBreakdown {
    pub(super) round: usize,
    pub(super) measured: bool,
    pub(super) cumulative_objects: usize,
    pub(super) cumulative_plaintext_bytes: u64,
    pub(super) cumulative_chunks: usize,
    pub(super) cgroup_memory_current_mib: f64,
    pub(super) memstat_anon_mib: f64,
    pub(super) memstat_file_mib: f64,
    pub(super) memstat_kernel_mib: f64,
    pub(super) memstat_kernel_stack_mib: f64,
    pub(super) memstat_pagetables_mib: f64,
    pub(super) memstat_sock_mib: f64,
    pub(super) memstat_shmem_mib: f64,
    pub(super) memstat_file_mapped_mib: f64,
    pub(super) memstat_file_dirty_mib: f64,
    pub(super) memstat_file_writeback_mib: f64,
    pub(super) proc_vmrss_mib: f64,
    pub(super) proc_rss_anon_mib: f64,
    pub(super) proc_rss_file_mib: f64,
    pub(super) proc_rss_shmem_mib: f64,
    pub(super) smaps_private_dirty_mib: f64,
    pub(super) fd: u64,
    pub(super) relay_redb_bytes: u64,
}

#[cfg(feature = "realnet")]
#[derive(Clone, Debug, serde::Serialize)]
#[allow(clippy::struct_excessive_bools)]
pub(super) struct S64BoundaryDiag {
    pub(super) label: String,
    pub(super) object_bytes: u64,
    pub(super) chunk_bytes: u64,
    pub(super) put_failed: bool,
    pub(super) put_error_excerpt: String,
    /// Authoritative local upload-transfer status after the failed PUT (JSON excerpt or `not_found`).
    pub(super) local_status_excerpt: String,
    pub(super) local_object_exists: bool,
    /// The `completed_chunks` the daemon durably recorded (relay-side upload progress), if any.
    pub(super) local_completed_chunks: i64,
    pub(super) local_transfer_state: String,
    /// Relay client-QUIC capture write actions observed for this attempt (0 = no relay object write).
    pub(super) relay_write_actions: usize,
    /// Best-effort serialized-frame size estimate for the request/response (bytes). Precise wire
    /// construction is deferred to the OBJ-IPC-01 audit; this is an analytical estimate.
    pub(super) request_frame_estimate_bytes: u64,
    pub(super) response_frame_estimate_bytes: u64,
    pub(super) relay_close_reason_excerpt: String,
    /// One of `pre_commit_reject` / `ambiguous_success` / `partial_relay_mutation` /
    /// `unexpected_success` / `unknown`.
    pub(super) classification: String,
    /// CTRL-074: after the failed PUT, a legitimate owner GET+ACK — proves an `ambiguous_success`
    /// object is really retrievable with matching plaintext (not merely counted).
    pub(super) post_get_ok: bool,
    pub(super) post_get_hash_match: bool,
}

#[cfg(feature = "realnet")]
#[derive(Clone, Debug, serde::Serialize)]
pub(super) struct S64Threshold {
    pub(super) name: String,
    pub(super) passed: bool,
    /// CTRL-087: a diagnostic threshold is recorded and reported (field + pass/fail preserved,
    /// never deleted or hidden) but does NOT hard-fail the acceptance run on its own. Currently
    /// only the single-run 5-sample strict-monotonic+25% `RssAnon` check, retired from hard-gate to
    /// diagnostic flag because a glibc never-trim high-water can look monotonic over a short window
    /// while the numerical median/peak/`memory.current` hard gates already bound the footprint.
    pub(super) diagnostic: bool,
    pub(super) detail: String,
}

// Not gated on `realnet`: the pure connection-analysis helpers + their unit tests exercise this in
// the default (non-realnet) test target.
#[derive(Clone, Debug, serde::Deserialize)]
pub(super) struct S64CaptureLine {
    #[allow(dead_code)]
    pub(super) request_seq: u64,
    pub(super) connection_id: u64,
    #[allow(dead_code)]
    pub(super) process_instance: u64,
    #[allow(dead_code)]
    pub(super) method: String,
    #[allow(dead_code)]
    pub(super) route: String,
    #[allow(dead_code)]
    pub(super) body_fingerprint: String,
    #[allow(dead_code)]
    pub(super) action: String,
    #[allow(dead_code)]
    pub(super) status: u16,
}
