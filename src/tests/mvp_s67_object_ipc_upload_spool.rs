// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

// T25-A3 (CTRL-102 / OBJ-IPC-01): the bounded local-bus UPLOAD spool, proven on the real object-v3
// stack through the public `rf` CLI -> rfd bus -> SDK path.
//
//   * Gate 1 (mvp_s67_realnet_object_ipc_16mib_upload): a 16 MiB public `rf object put` must SUCCEED
//     end to end via the streaming begin/chunk/finish spool. The old one-shot request would base64
//     the whole object into a single >1 MiB frame and be rejected; the auto-routed spool succeeds.
//     Asserts: compact terminal committed=true + plaintext_hash matches the input; the upload
//     transfer reaches `complete` over v3 QUIC; the RAMFLUX_BUS_TRACE=1 client trace shows the
//     begin + many chunk + finish protocol and NO "frame too large" (so every local-bus frame
//     stayed < 1 MiB — the symmetric cap would have rejected any oversized frame before emit, so a
//     16 MiB success is itself proof); zero HTTP object request reaches the relay; and the daemon
//     RSS is reported and bounded (O(<=16 MiB max object), not O(unbounded)).
//   * Gate 2 (mvp_s67_realnet_object_ipc_finish_drop_reconcile): a spool `object.put.finish` whose
//     local-bus RESPONSE is dropped AFTER the operation is durably `Committed` (the A2 seam, now
//     also covering `object.put.finish`) reconciles via `object.put.status` under the SAME
//     deterministic operation_id and returns compact success with reconciled=true; the relay
//     committed the content exactly once (no double mutation).
//
// The relay is always compiled with `itest-quic-fault` (fail-closed capture); this test sets the
// capture + used for the no-double-mutation proof. Trust material mirrors s55/s62/s65/s66.
#![allow(unused_imports)]
#![cfg_attr(not(feature = "realnet"), allow(dead_code))]
use super::*;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[cfg(feature = "realnet")]
const S67_ISSUER_NODE: &str = "node_b.realnet";
#[cfg(feature = "realnet")]
const S67_AUDIENCE_NODE: &str = "node_a.realnet";
#[cfg(feature = "realnet")]
const S67_RELAY_QUIC: &str = "127.0.0.1:17447";
#[cfg(feature = "realnet")]
const S67_GATEWAY_B_QUIC: &str = "127.0.0.1:18444";
#[cfg(feature = "realnet")]
const S67_PROJECT: &str = "ramflux-s67-upload-spool";
#[cfg(feature = "realnet")]
const S67_CAPTURE_PATH: &str = "/var/lib/ramflux/relay/s67-capture.jsonl";
#[cfg(feature = "realnet")]
const S67_ACCOUNT: &str = "owner_s67_account";
// 16 MiB — the maximum whole object the bounded UPLOAD spool accepts.
#[cfg(feature = "realnet")]
const S67_OBJECT_BYTES: usize = 16 * 1024 * 1024;

#[cfg(feature = "realnet")]
#[derive(Clone, Debug, serde::Deserialize)]
struct S67CaptureLine {
    route: String,
    body_fingerprint: String,
    action: String,
    status: u16,
}

#[cfg(feature = "realnet")]
#[test]
#[allow(clippy::too_many_lines)]
fn mvp_s67_realnet_object_ipc_upload_spool() -> Result<(), Box<dyn std::error::Error>> {
    if !s67_realnet_enabled() {
        eprintln!(
            "skipping s67 upload-spool realnet; set RAMFLUX_ITEST_REALNET=1 RAMFLUX_OBJECT_V3=1 RAMFLUX_CROSS_GATEWAY=1"
        );
        return Ok(());
    }

    let ports = S8ComposePorts {
        gateway_http: 64_881,
        gateway_quic: 64_951,
        router_http: 64_880,
        router_mesh: 64_952,
        notify_http: 64_883,
        federation_http: 64_882,
        federation_mesh: 64_953,
        relay_http: 64_884,
        relay_media_udp: 64_820,
        signaling_turn_udp: 64_978,
        signaling_turn_tcp: 64_979,
        retention_http: 64_887,
    };
    let stack = s67_start_stack(ports)?;
    let relay_url = format!("http://127.0.0.1:{}", ports.relay_http);

    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    let result = runtime.block_on(async {
        s67_wait_relay_quic_healthy(&stack.relay_ca).await?;

        let temp_root = temp_root("s67_upload_spool_sdk")?;
        let data_root = temp_root.join("owner/data");
        std::fs::create_dir_all(&data_root)?;
        let pid = std::process::id();
        let socket = PathBuf::from(format!("/tmp/ramflux-s67-rfd-{pid}.sock"));
        let bus_marker = format!("/tmp/ramflux-s67-bus-fault-{pid}.marker");
        let input_path = temp_root.join("s67-object-input.bin");

        let plaintext = s67_deterministic_bytes(S67_OBJECT_BYTES);
        assert_eq!(plaintext.len(), 16_777_216, "16 MiB object");
        std::fs::write(&input_path, &plaintext)?;
        let input_hash =
            ramflux_crypto::blake3_256_base64url(ramflux_protocol::domain::OBJECT, &plaintext);

        let rf_binary = s67_build_rf_binary().await?;
        let ca_cert_arg = mvp_s4_path_arg(&stack.relay_ca);
        let socket_arg = mvp_s4_path_arg(&socket);
        let data_root_arg = mvp_s4_path_arg(&data_root);
        let input_arg = mvp_s4_path_arg(&input_path);

        // ---- Gate 1: 16 MiB streaming PUT succeeds; every frame < 1 MiB; RSS bounded ----
        let fault_off_env = stack.sdk_env.clone();
        let mut daemon =
            s67_spawn_rf_daemon_with_env(&rf_binary, &socket_arg, &data_root_arg, &fault_off_env)?;
        let gate1 = async {
            mvp_s4_wait_for_socket(&socket).await?;
            mvp_s10_create_rf_account(
                &rf_binary,
                &socket_arg,
                S67_ACCOUNT,
                "principal_s67_owner",
                "owner_device_s67",
                "target_s67_owner",
                S67_GATEWAY_B_QUIC,
                &ca_cert_arg,
                "70",
                "71",
            )
            .await?;

            let (put, trace) = s67_rf_put_traced(
                &rf_binary,
                &socket_arg,
                &relay_url,
                &input_arg,
                "object_s67_16mib",
            )
            .await?;
            assert_eq!(put["object_id"], "object_s67_16mib", "compact terminal object_id");
            assert_eq!(put["committed"], true, "16 MiB PUT must be committed: {put}");
            assert!(put.get("object").is_none(), "compact terminal must not echo object");
            assert!(put.get("chunks").is_none(), "compact terminal must not echo chunks");
            assert_eq!(
                put["plaintext_hash"],
                serde_json::Value::String(input_hash.clone()),
                "terminal plaintext_hash must match the 16 MiB input: {put}"
            );

            // RAMFLUX_BUS_TRACE=1 proof: the streamed begin + many chunk + finish protocol ran, and
            // NO frame was rejected as too large. A 16 MiB success is only possible if every frame
            // stayed < 1 MiB (the symmetric writer cap rejects an oversized frame BEFORE emit).
            assert!(
                trace.contains("object.put.begin"),
                "bus trace must show object.put.begin; trace excerpt: {}",
                s67_trace_excerpt(&trace)
            );
            assert!(
                trace.contains("object.put.finish"),
                "bus trace must show object.put.finish; trace excerpt: {}",
                s67_trace_excerpt(&trace)
            );
            let chunk_frames = trace.matches("method=object.put.chunk").count();
            assert!(
                chunk_frames >= 32,
                "16 MiB at <=512 KiB chunks must be >= 32 bounded chunk frames, saw {chunk_frames}"
            );
            assert!(
                !trace.to_ascii_lowercase().contains("frame too large"),
                "no local-bus frame may exceed the 1 MiB cap; trace excerpt: {}",
                s67_trace_excerpt(&trace)
            );
            eprintln!(
                "s67 gate1: 16 MiB PUT committed; {chunk_frames} bounded chunk frames; every frame < 1 MiB"
            );

            // Upload transfer reaches complete over v3 QUIC.
            let upload = s67_object_status(&rf_binary, &socket_arg, "object_s67_16mib").await?;
            assert_eq!(
                upload["transfer"]["state"], "complete",
                "16 MiB upload must complete over QUIC: {upload}"
            );

            // Daemon RSS: bounded and consistent with O(max object <= 16 MiB), not O(unbounded).
            let rss_kib = daemon.id().and_then(s67_process_rss_kib).unwrap_or(0);
            eprintln!("s67 gate1: rfd RSS = {rss_kib} KiB after a 16 MiB PUT");
            assert!(rss_kib > 0, "must be able to read the rfd RSS");
            assert!(
                rss_kib < 800 * 1024,
                "rfd RSS {rss_kib} KiB must stay bounded (< 800 MiB) — no O(unbounded) resident object"
            );
            Ok::<(), Box<dyn std::error::Error>>(())
        };
        match tokio::time::timeout(Duration::from_mins(12), gate1).await {
            Ok(inner) => inner?,
            Err(_elapsed) => {
                let _ = mvp_s20_stop_rf_daemon(&mut daemon).await;
                return Err("s67 gate1 16 MiB flow timed out".into());
            }
        }

        // ---- Gate 2: finish-response drop after Committed reconciles via object.put.status ----
        // Restart the daemon with the bus-fault seam armed. The spooled PUT commits durably, the
        // daemon drops the object.put.finish response, and the CLI auto-status-reconnects (same
        // operation_id) and returns compact success with reconciled=true. Exactly one relay commit.
        mvp_s20_stop_rf_daemon(&mut daemon).await?;
        let _ = std::fs::remove_file(&socket);
        let _ = std::fs::remove_file(&bus_marker);
        let bus_fault_env = {
            let mut env = fault_off_env.clone();
            env.push((
                "RAMFLUX_SDK_ITEST_BUS_FAULT_MODE".to_owned(),
                "object-put-response".to_owned(),
            ));
            env.push(("RAMFLUX_SDK_ITEST_BUS_FAULT_MARKER".to_owned(), bus_marker.clone()));
            env
        };
        daemon =
            s67_spawn_rf_daemon_with_env(&rf_binary, &socket_arg, &data_root_arg, &bus_fault_env)?;

        let gate2 = async {
            mvp_s20_wait_for_daemon_status(&rf_binary, &socket_arg).await?;
            s67_reset_capture()?;
            let (reconciled, _trace) = s67_rf_put_traced(
                &rf_binary,
                &socket_arg,
                &relay_url,
                &input_arg,
                "object_s67_finish_drop",
            )
            .await?;
            assert_eq!(
                reconciled["reconciled"],
                serde_json::Value::Bool(true),
                "finish-drop PUT must reconcile to reconciled=true: {reconciled}"
            );
            assert_eq!(
                reconciled["committed"],
                serde_json::Value::Bool(true),
                "finish-drop PUT must be committed: {reconciled}"
            );
            assert_eq!(
                reconciled["plaintext_hash"],
                serde_json::Value::String(input_hash.clone()),
                "finish-drop terminal plaintext_hash must match: {reconciled}"
            );
            assert!(
                Path::new(&bus_marker).exists(),
                "the bus-fault response-drop marker must have been written (seam actually fired)"
            );
            // Relay saw the object committed exactly once (no double put_chunk mutation).
            s67_assert_no_double_mutation(&s67_read_capture()?, "/put_chunk")?;
            eprintln!("s67 gate2: finish-response drop reconciled via object.put.status; committed once");
            Ok::<(), Box<dyn std::error::Error>>(())
        };
        let gate2_result = tokio::time::timeout(Duration::from_mins(12), gate2)
            .await
            .map_err(|_elapsed| "s67 gate2 finish-drop flow timed out".to_owned());

        mvp_s20_stop_rf_daemon(&mut daemon).await?;
        let _ = std::fs::remove_file(&socket);
        let _ = std::fs::remove_file(&bus_marker);
        std::fs::remove_dir_all(&temp_root).ok();
        gate2_result?
    });

    let relay_logs = s67_container_logs("ramflux-relay");
    std::fs::remove_dir_all(&stack.materials).ok();
    if let Err(error) = &result {
        eprintln!("s67 flow failed: {error}\n=== relay logs ===\n{relay_logs}");
    }
    result?;

    // No HTTP object request may reach the relay across either gate (all v3 QUIC).
    assert!(
        !relay_logs.contains("POST /relay/v1/object/"),
        "relay must receive zero HTTP object requests in the v3 QUIC path:\n{relay_logs}"
    );
    eprintln!("s67: relay HTTP object requests = 0");
    Ok(())
}

// ---- shared setup / helpers ----

#[cfg(feature = "realnet")]
fn s67_realnet_enabled() -> bool {
    std::env::var("RAMFLUX_ITEST_REALNET").as_deref() == Ok("1")
        && std::env::var("RAMFLUX_OBJECT_V3").as_deref() == Ok("1")
        && std::env::var("RAMFLUX_CROSS_GATEWAY").as_deref() == Ok("1")
}

#[cfg(feature = "realnet")]
fn s67_deterministic_bytes(len: usize) -> Vec<u8> {
    (0..len).map(|index| u8::try_from((index * 31 + 7) % 251).unwrap_or(0)).collect()
}

#[cfg(feature = "realnet")]
fn s67_trace_excerpt(trace: &str) -> String {
    trace.lines().take(8).collect::<Vec<_>>().join(" | ")
}

#[cfg(feature = "realnet")]
struct S67Stack {
    materials: PathBuf,
    relay_ca: PathBuf,
    sdk_env: Vec<(String, String)>,
    _node: S8RealnetNode,
}

#[cfg(feature = "realnet")]
fn s67_start_stack(ports: S8ComposePorts) -> Result<S67Stack, Box<dyn std::error::Error>> {
    let materials = temp_root("s67_upload_spool_materials")?;
    let now = ramflux_node_core::now_unix_seconds();
    let root_seed = [0x44; 32];
    let attestation_seed = [0x33; 32];
    let provider_seed = [0x66; 32];
    let offline_root_seed = [0x88; 32];
    let certificate = s67_certificate(now, S67_ISSUER_NODE, "gw-b", root_seed, attestation_seed)?;
    let envelope =
        s67_trust_envelope(now, S67_ISSUER_NODE, root_seed, provider_seed, &certificate)?;
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
    s67_write_provider_keyring(&materials, now, S67_ISSUER_NODE, offline_root_seed, provider_seed)?;

    let env = vec![
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
        ("RAMFLUX_V3_FEDERATION_TRUST_ISSUER_NODE_ID".to_owned(), S67_ISSUER_NODE.to_owned()),
        ("RAMFLUX_V3_FEDERATION_TRUST_ENDPOINT".to_owned(), "ramflux-federation:7443".to_owned()),
        ("RAMFLUX_RELAY_ITEST_CAPTURE_FILE".to_owned(), S67_CAPTURE_PATH.to_owned()),
    ];

    let node = start_s8_realnet_compose_project_with_env(S67_PROJECT, ports, &env)?;
    let relay_ca = node.ca_cert.clone();
    let sdk_env = vec![
        ("RAMFLUX_SDK_RELAY_QUIC_ADDR".to_owned(), S67_RELAY_QUIC.to_owned()),
        ("RAMFLUX_SDK_RELAY_QUIC_SERVER_NAME".to_owned(), "ramflux-relay".to_owned()),
        ("RAMFLUX_SDK_RELAY_QUIC_CA_CERT".to_owned(), relay_ca.to_string_lossy().into_owned()),
        ("RAMFLUX_SDK_RELAY_OWNER_HOME_NODE_ID".to_owned(), S67_ISSUER_NODE.to_owned()),
        ("RAMFLUX_SDK_RELAY_OWNER_PRINCIPAL_ID".to_owned(), "principal_s67_owner".to_owned()),
        ("RAMFLUX_SDK_RELAY_AUDIENCE_NODE_ID".to_owned(), S67_AUDIENCE_NODE.to_owned()),
    ];
    Ok(S67Stack { materials, relay_ca, sdk_env, _node: node })
}

#[cfg(feature = "realnet")]
async fn s67_build_rf_binary() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let manifest = code_root().join("ramflux/apps/rf/Cargo.toml");
    let status = tokio::task::spawn_blocking(move || {
        std::process::Command::new("cargo")
            .args([
                "build",
                "--quiet",
                "--features",
                "itest-local-mint,itest-bus-fault",
                "--manifest-path",
            ])
            .arg(manifest)
            .status()
    })
    .await??;
    if !status.success() {
        return Err("failed to build rf binary with itest-bus-fault".into());
    }
    Ok(code_root().join("ramflux/target/debug/rf"))
}

#[cfg(feature = "realnet")]
fn s67_spawn_rf_daemon_with_env(
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

/// Runs `rf object put` with `RAMFLUX_BUS_TRACE=1`, returning `(terminal_json, client_bus_trace)`.
/// The client trace (rf-side stderr) records every local-bus frame method it writes, so the test can
/// prove the streamed begin/chunk/finish protocol ran with no oversized frame.
#[cfg(feature = "realnet")]
async fn s67_rf_put_traced(
    rf_binary: &Path,
    socket_arg: &str,
    relay_url: &str,
    input_arg: &str,
    object_id: &str,
) -> Result<(serde_json::Value, String), Box<dyn std::error::Error>> {
    let binary = rf_binary.to_path_buf();
    let args: Vec<String> = [
        "--socket",
        socket_arg,
        "object",
        "put",
        "--account",
        S67_ACCOUNT,
        "--object",
        object_id,
        "--chunk-size",
        "65536",
        "--relay-url",
        relay_url,
        input_arg,
    ]
    .iter()
    .map(|value| (*value).to_owned())
    .collect();
    let command_line = format!("{} {}", binary.display(), args.join(" "));
    let output = tokio::time::timeout(
        Duration::from_mins(10),
        tokio::task::spawn_blocking(move || {
            std::process::Command::new(binary).args(args).env("RAMFLUX_BUS_TRACE", "1").output()
        }),
    )
    .await
    .map_err(|_elapsed| format!("s67 rf put timed out: {command_line}"))???;
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    if !output.status.success() {
        return Err(format!(
            "s67 rf put failed: {command_line} stdout={} stderr={stderr}",
            String::from_utf8_lossy(&output.stdout)
        )
        .into());
    }
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).map_err(|error| {
        format!(
            "s67 rf put invalid JSON: {error} stdout={} stderr={stderr}",
            String::from_utf8_lossy(&output.stdout)
        )
    })?;
    Ok((value, stderr))
}

#[cfg(feature = "realnet")]
async fn s67_object_status(
    rf_binary: &Path,
    socket_arg: &str,
    object_id: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    mvp_s4_rf_json(
        rf_binary,
        &[
            "--socket",
            socket_arg,
            "object",
            "status",
            "--account",
            S67_ACCOUNT,
            "--object",
            object_id,
            "--direction",
            "upload",
        ],
    )
    .await
}

/// Reads a process RSS in KiB via `ps -o rss= -p <pid>` (KiB on macOS and Linux).
#[cfg(feature = "realnet")]
fn s67_process_rss_kib(pid: u32) -> Option<u64> {
    let output = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &pid.to_string()])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8_lossy(&output.stdout).trim().parse::<u64>().ok()
}

#[cfg(feature = "realnet")]
async fn s67_wait_relay_quic_healthy(ca_cert: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let config =
        ramflux_transport::RelayClientQuicConfig::new(S67_RELAY_QUIC, "ramflux-relay", ca_cert)?;
    for _ in 0..30 {
        if let Ok(health) =
            ramflux_transport::relay_client_quic_health(&config, Duration::from_secs(3)).await
            && health.status == 200
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    Err("relay client QUIC did not become healthy".into())
}

// ---- relay capture (proves committed-once / no double mutation) ----

#[cfg(feature = "realnet")]
fn s67_container(service: &str) -> String {
    format!("{S67_PROJECT}_{service}_1")
}

#[cfg(feature = "realnet")]
fn s67_reset_capture() -> Result<(), Box<dyn std::error::Error>> {
    let container = s67_container("ramflux-relay");
    let output = std::process::Command::new(container_runtime())
        .args(["exec", &container, "rm", "-f", S67_CAPTURE_PATH])
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "failed to reset relay capture: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(())
}

#[cfg(feature = "realnet")]
fn s67_read_capture() -> Result<Vec<S67CaptureLine>, Box<dyn std::error::Error>> {
    let container = s67_container("ramflux-relay");
    let output = std::process::Command::new(container_runtime())
        .args([
            "exec",
            &container,
            "sh",
            "-c",
            &format!("cat {S67_CAPTURE_PATH} 2>/dev/null || true"),
        ])
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "capture read failed (exec cat {S67_CAPTURE_PATH}): {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut lines = Vec::new();
    for raw in text.lines().filter(|line| !line.trim().is_empty()) {
        lines.push(serde_json::from_str::<S67CaptureLine>(raw)?);
    }
    Ok(lines)
}

#[cfg(feature = "realnet")]
fn s67_assert_no_double_mutation(
    capture: &[S67CaptureLine],
    route_suffix: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut seen = std::collections::BTreeSet::new();
    for line in capture.iter().filter(|line| {
        line.route.ends_with(route_suffix)
            && line.action == "write"
            && (200..300).contains(&line.status)
    }) {
        if !seen.insert(line.body_fingerprint.clone()) {
            return Err(format!(
                "double relay mutation on {route_suffix}: fingerprint {} written twice",
                line.body_fingerprint
            )
            .into());
        }
    }
    Ok(())
}

#[cfg(feature = "realnet")]
fn s67_container_logs(service: &str) -> String {
    let container = s67_container(service);
    std::process::Command::new(container_runtime()).args(["logs", &container]).output().map_or_else(
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

// ---- v3 trust material (object-v3 stack; same shape as s55/s62/s65/s66) ----

#[cfg(feature = "realnet")]
fn s67_certificate(
    now: u64,
    node_id: &str,
    gateway_instance_id: &str,
    root_seed: [u8; 32],
    attestation_seed: [u8; 32],
) -> Result<ramflux_node_core::GatewayIssuerCertificate, Box<dyn std::error::Error>> {
    let mut certificate = ramflux_node_core::GatewayIssuerCertificate {
        schema: ramflux_node_core::GATEWAY_ISSUER_CERTIFICATE_SCHEMA.to_owned(),
        version: ramflux_node_core::OBJECT_RELAY_V3_PROOF_VERSION,
        cert_id: "s67-gw-b-cert-1".to_owned(),
        node_id: node_id.to_owned(),
        gateway_instance_id: gateway_instance_id.to_owned(),
        attestation_public_key: ramflux_crypto::public_key_base64url_from_seed(attestation_seed),
        attestation_key_id: "s67-gw-b-attestation-1".to_owned(),
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
fn s67_trust_envelope(
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
        provider_signing_key_id: "s67-provider-1".to_owned(),
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
fn s67_write_provider_keyring(
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
            key_id: "s67-provider-1".to_owned(),
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
