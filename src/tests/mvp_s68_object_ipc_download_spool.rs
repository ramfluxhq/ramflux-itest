// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

// T25-A4 (CTRL-104 / OBJ-IPC-01): the bounded local-bus DOWNLOAD spool, proven on the real object-v3
// stack through the public `rf` CLI -> rfd bus -> SDK path. Symmetric to the T25-A3 UPLOAD spool
// (mvp_s67): the A3 spool is the PUT half of this round-trip.
//
//   * Gate 1 (mvp_s68_realnet_object_ipc_16mib_download): a 16 MiB public `rf object get` must SUCCEED
//     end to end via the streaming begin/read/finish DOWNLOAD spool, after a 16 MiB `rf object put`
//     (the A3 UPLOAD spool). The old one-shot GET base64'd the whole object into a single >1 MiB
//     response frame and was rejected; the auto-routed DOWNLOAD spool streams bounded reads.
//     Asserts: the output file is byte-identical to the input (blake3 match); the RAMFLUX_BUS_TRACE=1
//     client trace shows the begin + many read + finish protocol and NO "frame too large" (so every
//     local-bus frame stayed < 1 MiB — the symmetric cap would have rejected any oversized frame
//     before emit, so a 16 MiB success is itself proof); zero HTTP object request reaches the relay
//     (all v3 QUIC); and the daemon RSS is reported and bounded (O(<= 16 MiB max object)).
//   * Gate 2 (mvp_s68_realnet_object_ipc_read_drop_reconcile): a DOWNLOAD `object.get.read` whose
//     local-bus RESPONSE is dropped (the A4 bus-fault seam) closes the connection; the streaming
//     client RESTARTS the download via a fresh `object.get.begin` and re-streams from offset 0, and
//     the final output is still byte-identical. The temp output is only renamed into place after the
//     whole streamed hash matches begin's, so no partial file is ever presented as complete.
//
// Trust material mirrors s55/s62/s65/s67 (object-v3 stack).
#![allow(unused_imports)]
#![cfg_attr(not(feature = "realnet"), allow(dead_code))]
use super::*;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[cfg(feature = "realnet")]
const S68_ISSUER_NODE: &str = "node_b.realnet";
#[cfg(feature = "realnet")]
const S68_AUDIENCE_NODE: &str = "node_a.realnet";
#[cfg(feature = "realnet")]
const S68_RELAY_QUIC: &str = "127.0.0.1:17447";
#[cfg(feature = "realnet")]
const S68_GATEWAY_B_QUIC: &str = "127.0.0.1:18444";
#[cfg(feature = "realnet")]
const S68_PROJECT: &str = "ramflux-s68-download-spool";
#[cfg(feature = "realnet")]
const S68_ACCOUNT: &str = "owner_s68_account";
// 16 MiB — the maximum whole object the bounded spool accepts.
#[cfg(feature = "realnet")]
const S68_OBJECT_BYTES: usize = 16 * 1024 * 1024;

#[cfg(feature = "realnet")]
#[test]
#[allow(clippy::too_many_lines)]
fn mvp_s68_realnet_object_ipc_download_spool() -> Result<(), Box<dyn std::error::Error>> {
    if !s68_realnet_enabled() {
        eprintln!(
            "skipping s68 download-spool realnet; set RAMFLUX_ITEST_REALNET=1 RAMFLUX_OBJECT_V3=1 RAMFLUX_CROSS_GATEWAY=1"
        );
        return Ok(());
    }

    let ports = S8ComposePorts {
        gateway_http: 64_781,
        gateway_quic: 64_851,
        router_http: 64_780,
        router_mesh: 64_852,
        notify_http: 64_783,
        federation_http: 64_782,
        federation_mesh: 64_853,
        relay_http: 64_784,
        relay_media_udp: 64_720,
        signaling_turn_udp: 64_878,
        signaling_turn_tcp: 64_879,
        retention_http: 64_787,
    };
    let stack = s68_start_stack(ports)?;
    let relay_url = format!("http://127.0.0.1:{}", ports.relay_http);

    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    let result = runtime.block_on(async {
        s68_wait_relay_quic_healthy(&stack.relay_ca).await?;

        let temp_root = temp_root("s68_download_spool_sdk")?;
        let data_root = temp_root.join("owner/data");
        std::fs::create_dir_all(&data_root)?;
        let pid = std::process::id();
        let socket = PathBuf::from(format!("/tmp/ramflux-s68-rfd-{pid}.sock"));
        let bus_marker = format!("/tmp/ramflux-s68-bus-fault-{pid}.marker");
        let input_path = temp_root.join("s68-object-input.bin");
        let output_path = temp_root.join("s68-object-output.bin");
        let retry_output_path = temp_root.join("s68-object-output-2.bin");

        let plaintext = s68_deterministic_bytes(S68_OBJECT_BYTES);
        assert_eq!(plaintext.len(), 16_777_216, "16 MiB object");
        std::fs::write(&input_path, &plaintext)?;
        let input_hash =
            ramflux_crypto::blake3_256_base64url(ramflux_protocol::domain::OBJECT, &plaintext);

        let rf_binary = s68_build_rf_binary().await?;
        let ca_cert_arg = mvp_s4_path_arg(&stack.relay_ca);
        let socket_arg = mvp_s4_path_arg(&socket);
        let data_root_arg = mvp_s4_path_arg(&data_root);
        let input_arg = mvp_s4_path_arg(&input_path);
        let output_arg = mvp_s4_path_arg(&output_path);
        let retry_output_arg = mvp_s4_path_arg(&retry_output_path);

        // ---- Gate 1: 16 MiB PUT (A3 spool) then GET (A4 spool); byte-identical; frames < 1 MiB ----
        let fault_off_env = stack.sdk_env.clone();
        let mut daemon =
            s68_spawn_rf_daemon_with_env(&rf_binary, &socket_arg, &data_root_arg, &fault_off_env)?;
        let gate1 = async {
            mvp_s4_wait_for_socket(&socket).await?;
            mvp_s10_create_rf_account(
                &rf_binary,
                &socket_arg,
                S68_ACCOUNT,
                "principal_s68_owner",
                "owner_device_s68",
                "target_s68_owner",
                S68_GATEWAY_B_QUIC,
                &ca_cert_arg,
                "80",
                "81",
            )
            .await?;

            // PUT the 16 MiB object via the A3 UPLOAD spool (auto-routed by size).
            let put = s68_rf_put(&rf_binary, &socket_arg, &relay_url, &input_arg, "object_s68_16mib")
                .await?;
            assert_eq!(put["committed"], true, "16 MiB PUT must commit: {put}");
            assert_eq!(
                put["plaintext_hash"],
                serde_json::Value::String(input_hash.clone()),
                "PUT terminal plaintext_hash must match the 16 MiB input"
            );

            // GET the 16 MiB object via the A4 DOWNLOAD spool. NO --relay-ack so the relay copy
            // survives for Gate 2.
            let (get, trace) = s68_rf_get_traced(
                &rf_binary,
                &socket_arg,
                &relay_url,
                &output_arg,
                "object_s68_16mib",
                false,
            )
            .await?;
            assert_eq!(get["object_id"], "object_s68_16mib", "compact GET terminal object_id");
            assert_eq!(get["streamed"], true, "16 MiB GET must stream: {get}");
            assert_eq!(
                get["plaintext_hash"],
                serde_json::Value::String(input_hash.clone()),
                "GET terminal plaintext_hash must match the input: {get}"
            );
            assert!(get.get("plaintext_base64").is_none(), "compact GET must not echo plaintext");

            // Output byte-identical to input (blake3 match).
            let roundtrip = std::fs::read(&output_path)?;
            assert_eq!(roundtrip.len(), plaintext.len(), "roundtrip length must match");
            let output_hash =
                ramflux_crypto::blake3_256_base64url(ramflux_protocol::domain::OBJECT, &roundtrip);
            assert_eq!(output_hash, input_hash, "roundtrip blake3 must match the input");
            assert_eq!(roundtrip, plaintext, "roundtrip bytes must match the input");

            // RAMFLUX_BUS_TRACE=1 proof: the streamed begin + many read + finish protocol ran, and NO
            // frame was rejected as too large. A 16 MiB success is only possible if every frame stayed
            // < 1 MiB (the symmetric writer cap rejects an oversized frame BEFORE emit).
            assert!(
                trace.contains("object.get.begin"),
                "bus trace must show object.get.begin; excerpt: {}",
                s68_trace_excerpt(&trace)
            );
            assert!(
                trace.contains("object.get.finish"),
                "bus trace must show object.get.finish; excerpt: {}",
                s68_trace_excerpt(&trace)
            );
            let read_frames = trace.matches("method=object.get.read").count();
            assert!(
                read_frames >= 32,
                "16 MiB at <= 512 KiB reads must be >= 32 bounded read frames, saw {read_frames}"
            );
            assert!(
                !trace.to_ascii_lowercase().contains("frame too large"),
                "no local-bus frame may exceed the 1 MiB cap; excerpt: {}",
                s68_trace_excerpt(&trace)
            );
            eprintln!(
                "s68 gate1: 16 MiB GET byte-identical; {read_frames} bounded read frames; every frame < 1 MiB"
            );

            // Daemon RSS: bounded and consistent with O(max object <= 16 MiB), not O(unbounded).
            let rss_kib = daemon.id().and_then(s68_process_rss_kib).unwrap_or(0);
            eprintln!("s68 gate1: rfd RSS = {rss_kib} KiB after a 16 MiB GET");
            assert!(rss_kib > 0, "must be able to read the rfd RSS");
            assert!(
                rss_kib < 800 * 1024,
                "rfd RSS {rss_kib} KiB must stay bounded (< 800 MiB) — no O(unbounded) resident object"
            );
            Ok::<(), Box<dyn std::error::Error>>(())
        };
        match tokio::time::timeout(Duration::from_mins(14), gate1).await {
            Ok(inner) => inner?,
            Err(_elapsed) => {
                let _ = mvp_s20_stop_rf_daemon(&mut daemon).await;
                return Err("s68 gate1 16 MiB round-trip timed out".into());
            }
        }

        // ---- Gate 2: read-response drop reconciles via a restart; output still byte-identical ----
        // Restart the daemon with the A4 bus-fault seam armed. The DOWNLOAD spool serves the first
        // object.get.read, the daemon drops that response (closes the connection), and the streaming
        // client restarts via a fresh object.get.begin and re-streams from 0. The relay copy survives
        // (Gate 1 did not ack), so the re-begin re-downloads over QUIC.
        mvp_s20_stop_rf_daemon(&mut daemon).await?;
        let _ = std::fs::remove_file(&socket);
        let _ = std::fs::remove_file(&bus_marker);
        let bus_fault_env = {
            let mut env = fault_off_env.clone();
            env.push((
                "RAMFLUX_SDK_ITEST_BUS_FAULT_MODE".to_owned(),
                "object-get-read-response".to_owned(),
            ));
            env.push(("RAMFLUX_SDK_ITEST_BUS_FAULT_MARKER".to_owned(), bus_marker.clone()));
            env
        };
        daemon =
            s68_spawn_rf_daemon_with_env(&rf_binary, &socket_arg, &data_root_arg, &bus_fault_env)?;

        let gate2 = async {
            mvp_s20_wait_for_daemon_status(&rf_binary, &socket_arg).await?;
            let (get, _trace) = s68_rf_get_traced(
                &rf_binary,
                &socket_arg,
                &relay_url,
                &retry_output_arg,
                "object_s68_16mib",
                false,
            )
            .await?;
            assert_eq!(get["streamed"], true, "read-drop GET must still stream to success: {get}");
            assert_eq!(
                get["plaintext_hash"],
                serde_json::Value::String(input_hash.clone()),
                "read-drop GET terminal plaintext_hash must match: {get}"
            );
            assert!(
                Path::new(&bus_marker).exists(),
                "the bus-fault read-response-drop marker must have been written (seam actually fired)"
            );
            // The restarted download is byte-identical (no partial file presented as complete).
            let roundtrip = std::fs::read(&retry_output_path)?;
            let output_hash =
                ramflux_crypto::blake3_256_base64url(ramflux_protocol::domain::OBJECT, &roundtrip);
            assert_eq!(output_hash, input_hash, "read-drop restart roundtrip must be byte-identical");
            assert_eq!(roundtrip, plaintext, "read-drop restart bytes must match the input");
            eprintln!("s68 gate2: read-response drop reconciled via restart; output byte-identical");
            Ok::<(), Box<dyn std::error::Error>>(())
        };
        let gate2_result = tokio::time::timeout(Duration::from_mins(14), gate2)
            .await
            .map_err(|_elapsed| "s68 gate2 read-drop flow timed out".to_owned());

        mvp_s20_stop_rf_daemon(&mut daemon).await?;
        let _ = std::fs::remove_file(&socket);
        let _ = std::fs::remove_file(&bus_marker);
        std::fs::remove_dir_all(&temp_root).ok();
        gate2_result?
    });

    let relay_logs = s68_container_logs("ramflux-relay");
    std::fs::remove_dir_all(&stack.materials).ok();
    if let Err(error) = &result {
        eprintln!("s68 flow failed: {error}\n=== relay logs ===\n{relay_logs}");
    }
    result?;

    // No HTTP object request may reach the relay across either gate (all v3 QUIC).
    assert!(
        !relay_logs.contains("POST /relay/v1/object/"),
        "relay must receive zero HTTP object requests in the v3 QUIC path:\n{relay_logs}"
    );
    eprintln!("s68: relay HTTP object requests = 0");
    Ok(())
}

// ---- shared setup / helpers ----

#[cfg(feature = "realnet")]
fn s68_realnet_enabled() -> bool {
    std::env::var("RAMFLUX_ITEST_REALNET").as_deref() == Ok("1")
        && std::env::var("RAMFLUX_OBJECT_V3").as_deref() == Ok("1")
        && std::env::var("RAMFLUX_CROSS_GATEWAY").as_deref() == Ok("1")
}

#[cfg(feature = "realnet")]
fn s68_deterministic_bytes(len: usize) -> Vec<u8> {
    (0..len).map(|index| u8::try_from((index * 31 + 7) % 251).unwrap_or(0)).collect()
}

#[cfg(feature = "realnet")]
fn s68_trace_excerpt(trace: &str) -> String {
    trace.lines().take(8).collect::<Vec<_>>().join(" | ")
}

#[cfg(feature = "realnet")]
struct S68Stack {
    materials: PathBuf,
    relay_ca: PathBuf,
    sdk_env: Vec<(String, String)>,
    _node: S8RealnetNode,
}

#[cfg(feature = "realnet")]
fn s68_start_stack(ports: S8ComposePorts) -> Result<S68Stack, Box<dyn std::error::Error>> {
    let materials = temp_root("s68_download_spool_materials")?;
    let now = ramflux_node_core::now_unix_seconds();
    let root_seed = [0x44; 32];
    let attestation_seed = [0x33; 32];
    let provider_seed = [0x66; 32];
    let offline_root_seed = [0x88; 32];
    let certificate = s68_certificate(now, S68_ISSUER_NODE, "gw-b", root_seed, attestation_seed)?;
    let envelope =
        s68_trust_envelope(now, S68_ISSUER_NODE, root_seed, provider_seed, &certificate)?;
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
    s68_write_provider_keyring(&materials, now, S68_ISSUER_NODE, offline_root_seed, provider_seed)?;

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
        ("RAMFLUX_V3_FEDERATION_TRUST_ISSUER_NODE_ID".to_owned(), S68_ISSUER_NODE.to_owned()),
        ("RAMFLUX_V3_FEDERATION_TRUST_ENDPOINT".to_owned(), "ramflux-federation:7443".to_owned()),
    ];

    let node = start_s8_realnet_compose_project_with_env(S68_PROJECT, ports, &env)?;
    let relay_ca = node.ca_cert.clone();
    let sdk_env = vec![
        ("RAMFLUX_SDK_RELAY_QUIC_ADDR".to_owned(), S68_RELAY_QUIC.to_owned()),
        ("RAMFLUX_SDK_RELAY_QUIC_SERVER_NAME".to_owned(), "ramflux-relay".to_owned()),
        ("RAMFLUX_SDK_RELAY_QUIC_CA_CERT".to_owned(), relay_ca.to_string_lossy().into_owned()),
        ("RAMFLUX_SDK_RELAY_OWNER_HOME_NODE_ID".to_owned(), S68_ISSUER_NODE.to_owned()),
        ("RAMFLUX_SDK_RELAY_OWNER_PRINCIPAL_ID".to_owned(), "principal_s68_owner".to_owned()),
        ("RAMFLUX_SDK_RELAY_AUDIENCE_NODE_ID".to_owned(), S68_AUDIENCE_NODE.to_owned()),
    ];
    Ok(S68Stack { materials, relay_ca, sdk_env, _node: node })
}

#[cfg(feature = "realnet")]
async fn s68_build_rf_binary() -> Result<PathBuf, Box<dyn std::error::Error>> {
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
fn s68_spawn_rf_daemon_with_env(
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

/// Runs a 16 MiB `rf object put` (auto-routed to the A3 UPLOAD spool), returning the compact terminal.
#[cfg(feature = "realnet")]
async fn s68_rf_put(
    rf_binary: &Path,
    socket_arg: &str,
    relay_url: &str,
    input_arg: &str,
    object_id: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    mvp_s4_rf_json(
        rf_binary,
        &[
            "--socket",
            socket_arg,
            "object",
            "put",
            "--account",
            S68_ACCOUNT,
            "--object",
            object_id,
            "--chunk-size",
            "65536",
            "--relay-url",
            relay_url,
            input_arg,
        ],
    )
    .await
}

/// Runs `rf object get` with `RAMFLUX_BUS_TRACE=1`, returning `(terminal_json, client_bus_trace)`.
/// The client trace (rf-side stderr) records every local-bus frame method it writes, so the test can
/// prove the streamed begin/read/finish protocol ran with no oversized frame.
#[cfg(feature = "realnet")]
async fn s68_rf_get_traced(
    rf_binary: &Path,
    socket_arg: &str,
    relay_url: &str,
    output_arg: &str,
    object_id: &str,
    ack: bool,
) -> Result<(serde_json::Value, String), Box<dyn std::error::Error>> {
    let binary = rf_binary.to_path_buf();
    let mut args: Vec<String> = [
        "--socket",
        socket_arg,
        "object",
        "get",
        "--account",
        S68_ACCOUNT,
        "--object",
        object_id,
        "--relay-url",
        relay_url,
    ]
    .iter()
    .map(|value| (*value).to_owned())
    .collect();
    if ack {
        args.push("--relay-ack".to_owned());
    }
    args.push(output_arg.to_owned());
    let command_line = format!("{} {}", binary.display(), args.join(" "));
    let output = tokio::time::timeout(
        Duration::from_mins(12),
        tokio::task::spawn_blocking(move || {
            std::process::Command::new(binary).args(args).env("RAMFLUX_BUS_TRACE", "1").output()
        }),
    )
    .await
    .map_err(|_elapsed| format!("s68 rf get timed out: {command_line}"))???;
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    if !output.status.success() {
        return Err(format!(
            "s68 rf get failed: {command_line} stdout={} stderr={stderr}",
            String::from_utf8_lossy(&output.stdout)
        )
        .into());
    }
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).map_err(|error| {
        format!(
            "s68 rf get invalid JSON: {error} stdout={} stderr={stderr}",
            String::from_utf8_lossy(&output.stdout)
        )
    })?;
    Ok((value, stderr))
}

/// Reads a process RSS in KiB via `ps -o rss= -p <pid>` (KiB on macOS and Linux).
#[cfg(feature = "realnet")]
fn s68_process_rss_kib(pid: u32) -> Option<u64> {
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
async fn s68_wait_relay_quic_healthy(ca_cert: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let config =
        ramflux_transport::RelayClientQuicConfig::new(S68_RELAY_QUIC, "ramflux-relay", ca_cert)?;
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

#[cfg(feature = "realnet")]
fn s68_container(service: &str) -> String {
    format!("{S68_PROJECT}_{service}_1")
}

#[cfg(feature = "realnet")]
fn s68_container_logs(service: &str) -> String {
    let container = s68_container(service);
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

// ---- v3 trust material (object-v3 stack; same shape as s55/s62/s65/s67) ----

#[cfg(feature = "realnet")]
fn s68_certificate(
    now: u64,
    node_id: &str,
    gateway_instance_id: &str,
    root_seed: [u8; 32],
    attestation_seed: [u8; 32],
) -> Result<ramflux_node_core::GatewayIssuerCertificate, Box<dyn std::error::Error>> {
    let mut certificate = ramflux_node_core::GatewayIssuerCertificate {
        schema: ramflux_node_core::GATEWAY_ISSUER_CERTIFICATE_SCHEMA.to_owned(),
        version: ramflux_node_core::OBJECT_RELAY_V3_PROOF_VERSION,
        cert_id: "s68-gw-b-cert-1".to_owned(),
        node_id: node_id.to_owned(),
        gateway_instance_id: gateway_instance_id.to_owned(),
        attestation_public_key: ramflux_crypto::public_key_base64url_from_seed(attestation_seed),
        attestation_key_id: "s68-gw-b-attestation-1".to_owned(),
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
fn s68_trust_envelope(
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
        provider_signing_key_id: "s68-provider-1".to_owned(),
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
fn s68_write_provider_keyring(
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
            key_id: "s68-provider-1".to_owned(),
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
