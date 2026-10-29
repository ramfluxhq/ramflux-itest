// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Capacity benchmark capture, container resources, and failure diagnostics.
use super::*;

/// All six `redb::CacheStats` counters parsed from a single `redb cache probe stats` log line
/// (`used_bytes`/`evictions`/`read_hits`/`read_misses`/`write_hits`/`write_misses`).
#[cfg(feature = "realnet")]
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct S64RedbCacheStats {
    pub(super) used_bytes: u64,
    pub(super) evictions: u64,
    pub(super) read_hits: u64,
    pub(super) read_misses: u64,
    pub(super) write_hits: u64,
    pub(super) write_misses: u64,
}

/// Parses the LATEST `redb cache probe stats` line from the relay container logs into all six
/// `redb::CacheStats` counters. `None` when no probe line is present (feature off or not yet emitted).
#[cfg(feature = "realnet")]
pub(super) fn s64_relay_cache_stats() -> Option<S64RedbCacheStats> {
    let container = s64_container("ramflux-relay");
    let output = std::process::Command::new(container_runtime().ok()?)
        .args(["logs", "--tail", "4000", &container])
        .output()
        .ok()?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let mut latest: Option<S64RedbCacheStats> = None;
    for raw in text.lines().filter(|line| line.contains("redb cache probe stats")) {
        // The relay's tracing fmt colorizes fields (`\x1b[3mused_bytes\x1b[0m\x1b[2m=\x1b[0m8512`), so
        // the key and `=` and value are NOT contiguous — strip ANSI first, then parse `key=NNN`.
        let line = s64_strip_ansi(raw);
        // used_bytes + evictions are required (always present); the four hit/miss counters default to 0
        // if an older probe line omitted them (all six are emitted by the current probe).
        if let (Some(used_bytes), Some(evictions)) =
            (s64_log_field_u64(&line, "used_bytes"), s64_log_field_u64(&line, "evictions"))
        {
            latest = Some(S64RedbCacheStats {
                used_bytes,
                evictions,
                read_hits: s64_log_field_u64(&line, "read_hits").unwrap_or(0),
                read_misses: s64_log_field_u64(&line, "read_misses").unwrap_or(0),
                write_hits: s64_log_field_u64(&line, "write_hits").unwrap_or(0),
                write_misses: s64_log_field_u64(&line, "write_misses").unwrap_or(0),
            });
        }
    }
    latest
}

/// LATEST `(used_bytes, evictions)` from the redb cache probe log — thin wrapper over
/// [`s64_relay_cache_stats`] for the pre-restart warm sample (full counters not needed there).
#[cfg(feature = "realnet")]
pub(super) fn s64_relay_cache_probe() -> Option<(u64, u64)> {
    s64_relay_cache_stats().map(|stats| (stats.used_bytes, stats.evictions))
}

/// Removes ANSI CSI escape sequences (`\x1b[ ... m`) from a (ASCII) log line.
#[cfg(feature = "realnet")]
pub(super) fn s64_strip_ansi(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == 0x1b {
            i += 1;
            if i < bytes.len() && bytes[i] == b'[' {
                i += 1;
                while i < bytes.len() && !(0x40..=0x7e).contains(&bytes[i]) {
                    i += 1;
                }
                if i < bytes.len() {
                    i += 1; // skip the final byte (e.g. 'm')
                }
            }
        } else {
            out.push(char::from(bytes[i]));
            i += 1;
        }
    }
    out
}

/// Extracts the `u64` value of a `key=NNN` field from a (ANSI-stripped) tracing full-format log line.
#[cfg(feature = "realnet")]
pub(super) fn s64_log_field_u64(line: &str, key: &str) -> Option<u64> {
    let needle = format!("{key}=");
    let start = line.find(&needle)? + needle.len();
    let rest = &line[start..];
    let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
    rest.get(..end)?.parse().ok()
}

// ---- capture reading ----

#[cfg(feature = "realnet")]
pub(super) fn s64_container(service: &str) -> String {
    format!("{S64_PROJECT}_{service}_1")
}

#[cfg(feature = "realnet")]
pub(super) fn s64_read_capture() -> Result<Vec<S64CaptureLine>, Box<dyn std::error::Error>> {
    let container = s64_container("ramflux-relay");
    let output = std::process::Command::new(container_runtime()?)
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
pub(super) fn s64_reset_capture() -> Result<(), Box<dyn std::error::Error>> {
    let container = s64_container("ramflux-relay");
    // CTRL-075: TRUNCATE (keep the inode) rather than `rm -f` (unlink + recreate). A relay write that
    // races an unlink would land on the now-orphaned inode and be invisible to a later `cat` of the
    // path; truncating the same inode removes that failure mode from the diagnosis.
    let output = std::process::Command::new(container_runtime()?)
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
pub(super) fn s64_container_ctl(
    action: &str,
    service: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let container = s64_container(service);
    let output =
        std::process::Command::new(container_runtime()?).args([action, &container]).output()?;
    if !output.status.success() {
        return Err(format!(
            "{} {action} {container} failed: {}",
            container_runtime()?,
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(())
}

#[cfg(feature = "realnet")]
pub(super) fn s64_container_logs(service: &str) -> String {
    let runtime = match container_runtime() {
        Ok(runtime) => runtime,
        Err(error) => return format!("container runtime unavailable: {error}"),
    };
    let container = s64_container(service);
    std::process::Command::new(runtime)
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
pub(super) fn s64_relay_http_object_requests() -> usize {
    s64_container_logs("ramflux-relay").matches("POST /relay/v1/object/").count()
}

#[cfg(feature = "realnet")]
pub(super) async fn s64_wait_relay_quic_healthy(
    ca_cert: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
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
pub(super) fn s64_relay_resource() -> Result<(f64, f64, f64, u64, f64), Box<dyn std::error::Error>>
{
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
pub(super) fn s64_relay_mem_breakdown(
    round: usize,
    measured: bool,
    cumulative_objects: usize,
    cumulative_plaintext_bytes: u64,
    cumulative_chunks: usize,
) -> S64MemBreakdown {
    let runtime = container_runtime();
    let container = s64_container("ramflux-relay");
    let cat = |path: &str| -> String {
        let Ok(runtime) = runtime else {
            return String::new();
        };
        std::process::Command::new(runtime)
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
    let relay_redb_bytes = runtime
        .ok()
        .and_then(|runtime| {
            std::process::Command::new(runtime)
                .args([
                    "exec",
                    &container,
                    "sh",
                    "-c",
                    "du -sb /var/lib/ramflux/relay 2>/dev/null | cut -f1",
                ])
                .output()
                .ok()
        })
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
pub(super) fn s64_container_proc_rss(
    container: &str,
) -> Result<(f64, f64), Box<dyn std::error::Error>> {
    let output = std::process::Command::new(container_runtime()?)
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
pub(super) fn s64_container_stats(
    container: &str,
) -> Result<(f64, f64), Box<dyn std::error::Error>> {
    let output = std::process::Command::new(container_runtime()?)
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
pub(super) fn s64_container_fd(container: &str) -> Result<u64, Box<dyn std::error::Error>> {
    let output = std::process::Command::new(container_runtime()?)
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
pub(super) fn s64_rfd_aggregate(daemons: &[S64Daemon]) -> (f64, u64) {
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
pub(super) fn s64_host_rss_mib(pid: u32) -> f64 {
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
pub(super) fn s64_host_fd(pid: u32) -> u64 {
    std::process::Command::new("sh")
        .args(["-c", &format!("lsof -p {pid} 2>/dev/null | wc -l")])
        .output()
        .ok()
        .and_then(|output| String::from_utf8_lossy(&output.stdout).trim().parse::<u64>().ok())
        .unwrap_or(0)
}

// ---- parse helpers (unit-tested) ----

/// Parses a container-stats memory field like "23.4MiB / 4GiB" into the used side as MiB.
pub(super) fn s64_parse_mem_mib(field: &str) -> f64 {
    let used = field.split('/').next().unwrap_or("").trim();
    s64_parse_size_mib(used)
}

pub(super) fn s64_parse_size_mib(value: &str) -> f64 {
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

pub(super) fn s64_parse_percent(value: &str) -> f64 {
    value.trim().trim_end_matches('%').trim().parse().unwrap_or(0.0)
}

/// Runs an `rf` command to completion WITHOUT asserting, returning `(success, combined_output)`.
#[cfg(feature = "realnet")]
pub(super) async fn s64_run_capture(rf_binary: &Path, args: &[&str]) -> (bool, String) {
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
pub(super) async fn s64_upload_status(
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
pub(super) fn s64_relay_close_reason() -> String {
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
pub(super) async fn s64_boundary_diagnostics(
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
