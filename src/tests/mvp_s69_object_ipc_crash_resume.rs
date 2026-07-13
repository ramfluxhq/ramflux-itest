// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

// T25-A5 (OBJ-IPC-01): the durable object-IPC crash-resume seam, proven on the real object-v3 stack
// through the public `rf` CLI -> rfd bus -> SDK path. Closes the one crash window the in-memory spools
// left open: a mid-UPLOAD rfd abort must RESUME from the durable journal offset (not re-upload from
// zero), and a mid-DOWNLOAD rfd abort must restart the download from offset 0 without ever renaming a
// partial output into place.
//
//   * Gate 1 (mvp_s69_realnet_object_ipc_upload_crash_resume): rfd is built with the default-off
//     `object-ipc-crash-seam` and armed to abort() AFTER a chunk's durable spool fsync + durable
//     journal fsync but BEFORE the ack, at ~half of a 16 MiB `rf object put`. The first put fails
//     (rfd crashed). rfd is restarted with the seam OFF; the second put reconnects, sees
//     `object.put.status`=`resumable` with the durable `resume_offset`, RESUMES chunks from that
//     offset (uploading far fewer than a full 32 chunk frames — the acked bytes are NOT re-uploaded),
//     and finishes with a committed compact terminal. A subsequent `rf object get` round-trips
//     BYTE-IDENTICAL, the upload transfer reaches `complete` over v3 QUIC, and the relay committed the
//     object exactly once (no double put_chunk mutation).
//   * Gate 2 (mvp_s69_realnet_object_ipc_download_crash_restart): rfd is armed to abort() AFTER the
//     download spool is written + fsynced but BEFORE any read is served. The first get fails (rfd
//     crashed) and NO partial output file is ever renamed into place. rfd is restarted seam-off; the
//     second get re-begins from offset 0 and the output is BYTE-IDENTICAL.
//
// Across both gates: every local-bus frame stays < 1 MiB (a 16 MiB success is itself the proof, since
// the symmetric writer cap rejects an oversized frame before emit), zero HTTP object request reaches
// the relay (all v3 QUIC), and the rfd RSS stays bounded (O(<= 16 MiB max object), not O(unbounded)).
//
// Trust material mirrors s55/s62/s65/s67/s68 (object-v3 stack).
#![allow(unused_imports)]
#![cfg_attr(not(feature = "realnet"), allow(dead_code))]
use super::*;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[cfg(feature = "realnet")]
const S69_ISSUER_NODE: &str = "node_b.realnet";
#[cfg(feature = "realnet")]
const S69_AUDIENCE_NODE: &str = "node_a.realnet";
#[cfg(feature = "realnet")]
const S69_RELAY_QUIC: &str = "127.0.0.1:17447";
#[cfg(feature = "realnet")]
const S69_GATEWAY_B_QUIC: &str = "127.0.0.1:18444";
#[cfg(feature = "realnet")]
const S69_PROJECT: &str = "ramflux-s69-crash-resume";
#[cfg(feature = "realnet")]
const S69_CAPTURE_PATH: &str = "/var/lib/ramflux/relay/s69-capture.jsonl";
#[cfg(feature = "realnet")]
const S69_ACCOUNT: &str = "owner_s69_account";
// 16 MiB — the maximum whole object the bounded spool accepts.
#[cfg(feature = "realnet")]
const S69_OBJECT_BYTES: usize = 16 * 1024 * 1024;
// Abort the upload after ~half the object is durably journaled, so the crash lands mid-upload.
#[cfg(feature = "realnet")]
const S69_CRASH_AFTER_BYTES: usize = 8 * 1024 * 1024;

#[cfg(feature = "realnet")]
#[derive(Clone, Debug, serde::Deserialize)]
struct S69CaptureLine {
    route: String,
    body_fingerprint: String,
    action: String,
    status: u16,
}

#[cfg(feature = "realnet")]
#[test]
#[allow(clippy::too_many_lines)]
fn mvp_s69_realnet_object_ipc_crash_resume() -> Result<(), Box<dyn std::error::Error>> {
    if !s69_realnet_enabled() {
        eprintln!(
            "skipping s69 crash-resume realnet; set RAMFLUX_ITEST_REALNET=1 RAMFLUX_OBJECT_V3=1 RAMFLUX_CROSS_GATEWAY=1"
        );
        return Ok(());
    }

    let ports = S8ComposePorts {
        gateway_http: 64_681,
        gateway_quic: 64_751,
        router_http: 64_680,
        router_mesh: 64_752,
        notify_http: 64_683,
        federation_http: 64_682,
        federation_mesh: 64_753,
        relay_http: 64_684,
        relay_media_udp: 64_620,
        signaling_turn_udp: 64_778,
        signaling_turn_tcp: 64_779,
        retention_http: 64_687,
    };
    let stack = s69_start_stack(ports)?;
    let relay_url = format!("http://127.0.0.1:{}", ports.relay_http);

    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    let result = runtime.block_on(async {
        s69_wait_relay_quic_healthy(&stack.relay_ca).await?;

        let temp_root = temp_root("s69_crash_resume_sdk")?;
        let data_root = temp_root.join("owner/data");
        std::fs::create_dir_all(&data_root)?;
        let pid = std::process::id();
        let socket = PathBuf::from(format!("/tmp/ramflux-s69-rfd-{pid}.sock"));
        let upload_marker = format!("/tmp/ramflux-s69-upload-crash-{pid}.marker");
        let download_marker = format!("/tmp/ramflux-s69-download-crash-{pid}.marker");
        let input_path = temp_root.join("s69-object-input.bin");
        let get_gate1_path = temp_root.join("s69-object-get1.bin");
        let get_gate2_path = temp_root.join("s69-object-get2.bin");

        let plaintext = s69_deterministic_bytes(S69_OBJECT_BYTES);
        assert_eq!(plaintext.len(), 16_777_216, "16 MiB object");
        std::fs::write(&input_path, &plaintext)?;
        let input_hash =
            ramflux_crypto::blake3_256_base64url(ramflux_protocol::domain::OBJECT, &plaintext);

        let rf_binary = s69_build_rf_binary().await?;
        let ca_cert_arg = mvp_s4_path_arg(&stack.relay_ca);
        let socket_arg = mvp_s4_path_arg(&socket);
        let data_root_arg = mvp_s4_path_arg(&data_root);
        let input_arg = mvp_s4_path_arg(&input_path);
        let get_gate1_arg = mvp_s4_path_arg(&get_gate1_path);
        let get_gate2_arg = mvp_s4_path_arg(&get_gate2_path);

        let fault_off_env = stack.sdk_env.clone();
        let upload_fault_env = {
            let mut env = fault_off_env.clone();
            env.push((
                "RAMFLUX_SDK_ITEST_CRASH_SEAM_MODE".to_owned(),
                "upload-chunk-before-ack".to_owned(),
            ));
            env.push((
                "RAMFLUX_SDK_ITEST_CRASH_SEAM_AFTER_BYTES".to_owned(),
                S69_CRASH_AFTER_BYTES.to_string(),
            ));
            env.push(("RAMFLUX_SDK_ITEST_CRASH_SEAM_MARKER".to_owned(), upload_marker.clone()));
            env
        };
        let download_fault_env = {
            let mut env = fault_off_env.clone();
            env.push((
                "RAMFLUX_SDK_ITEST_CRASH_SEAM_MODE".to_owned(),
                "download-after-write".to_owned(),
            ));
            env.push(("RAMFLUX_SDK_ITEST_CRASH_SEAM_MARKER".to_owned(), download_marker.clone()));
            env
        };

        // ---- Gate 1: mid-upload crash then durable-offset resume ----
        let _ = std::fs::remove_file(&upload_marker);
        let mut daemon = s69_spawn_rf_daemon_with_env(
            &rf_binary,
            &socket_arg,
            &data_root_arg,
            &upload_fault_env,
        )?;
        let gate1 = async {
            mvp_s4_wait_for_socket(&socket).await?;
            mvp_s10_create_rf_account(
                &rf_binary,
                &socket_arg,
                S69_ACCOUNT,
                "principal_s69_owner",
                "owner_device_s69",
                "target_s69_owner",
                S69_GATEWAY_B_QUIC,
                &ca_cert_arg,
                "90",
                "91",
            )
            .await?;

            // First put: rfd aborts at ~half; the CLI cannot resume against a dead daemon and fails.
            let (put1_ok, put1_out) = s69_run_rf_capture(
                &rf_binary,
                &[
                    "--socket",
                    &socket_arg,
                    "object",
                    "put",
                    "--account",
                    S69_ACCOUNT,
                    "--object",
                    "object_s69_16mib",
                    "--chunk-size",
                    "65536",
                    "--relay-url",
                    &relay_url,
                    &input_arg,
                ],
            )
            .await?;
            assert!(!put1_ok, "mid-upload rfd abort must fail the first put CLI: {put1_out}");
            s69_wait_marker(Path::new(&upload_marker)).await?;
            eprintln!("s69 gate1: upload crash seam fired (rfd aborted mid-upload)");
            Ok::<(), Box<dyn std::error::Error>>(())
        };
        match tokio::time::timeout(Duration::from_mins(12), gate1).await {
            Ok(inner) => inner?,
            Err(_elapsed) => {
                let _ = mvp_s20_stop_rf_daemon(&mut daemon).await;
                return Err("s69 gate1 mid-upload crash flow timed out".into());
            }
        }
        // Reap the crashed daemon and restart from the SAME data_root with the seam OFF.
        let _ = mvp_s20_stop_rf_daemon(&mut daemon).await;
        let _ = std::fs::remove_file(&socket);
        daemon =
            s69_spawn_rf_daemon_with_env(&rf_binary, &socket_arg, &data_root_arg, &fault_off_env)?;

        let gate1_resume = async {
            mvp_s20_wait_for_daemon_status(&rf_binary, &socket_arg).await?;
            // CTRL-108 (a): after the rfd restart, re-establish relay QUIC reachability BEFORE the
            // resumed finish's cold relay handshake. A5 verifies local-bus/rfd crash-resume; it must
            // not be polluted by mac-podman UDP-forwarding staleness across the long crash cycle. This
            // mirrors the bring-up wait so the resume path sees a healthy relay.
            s69_wait_relay_quic_healthy(&stack.relay_ca).await?;
            s69_reset_capture()?;

            // Second put: rehydrated session -> object.put.status=resumable -> resume from the durable
            // offset (do NOT re-upload the acked prefix), then finish committed.
            let (put2, trace) = s69_rf_put_traced(
                &rf_binary,
                &socket_arg,
                &relay_url,
                &input_arg,
                "object_s69_16mib",
            )
            .await?;
            assert_eq!(put2["committed"], true, "resumed 16 MiB PUT must commit: {put2}");
            assert_eq!(
                put2["plaintext_hash"],
                serde_json::Value::String(input_hash.clone()),
                "resumed terminal plaintext_hash must match the 16 MiB input: {put2}"
            );

            // Resume proof: the durable prefix was NOT re-uploaded. A full 16 MiB upload is 32 bounded
            // chunk frames; resuming from ~8 MiB must send far fewer, and skips begin (the durable
            // spool identity is preserved), so the trace shows a status reconcile instead.
            assert!(
                trace.contains("object.put.status"),
                "resumed put must reconcile via object.put.status; excerpt: {}",
                s69_trace_excerpt(&trace)
            );
            assert!(
                trace.contains("object.put.finish"),
                "resumed put must finish; excerpt: {}",
                s69_trace_excerpt(&trace)
            );
            // Retry-immune proof (CTRL-108): the resumed put's FIRST observed object.put.status
            // returned state=resumable with the durable resume_offset, so the acked ~8 MiB prefix was
            // never re-uploaded — REGARDLESS of how many transport-flake retries the client made.
            // (Counting client TX-OUT chunk frames is NOT a sound proxy: legitimate retries re-send the
            // suffix, which the daemon's offset check rejects as duplicates but which still inflate the
            // raw send count; that made the old `sent_chunks < 32` assertion flaky.)
            assert_eq!(
                put2["observed_state"],
                serde_json::Value::String("resumable".to_owned()),
                "resumed put's first status must be resumable: {put2}"
            );
            assert_eq!(
                put2["observed_resume_offset"],
                serde_json::json!(S69_CRASH_AFTER_BYTES),
                "resume must reconcile from the durable ~8 MiB offset (acked prefix not re-uploaded): {put2}"
            );
            let sent_chunks = trace.matches("BUS-CLIENT-TX-OUT method=object.put.chunk").count();
            assert!(
                sent_chunks >= 8,
                "resume must still upload the remaining ~half: sent only {sent_chunks} chunk frames"
            );
            assert!(
                !trace.to_ascii_lowercase().contains("frame too large"),
                "no local-bus frame may exceed the 1 MiB cap; excerpt: {}",
                s69_trace_excerpt(&trace)
            );
            eprintln!(
                "s69 gate1: resumed from durable offset {S69_CRASH_AFTER_BYTES}; {sent_chunks} chunk frames sent (offset honored => acked prefix not re-uploaded)"
            );

            // Upload transfer reaches complete over v3 QUIC, committed exactly once (no double mutation).
            let upload = s69_object_status(&rf_binary, &socket_arg, "object_s69_16mib").await?;
            assert_eq!(
                upload["transfer"]["state"], "complete",
                "resumed 16 MiB upload must complete over QUIC: {upload}"
            );
            s69_assert_no_double_mutation(&s69_read_capture()?, "/put_chunk")?;

            // Round-trip GET is byte-identical (no --relay-ack so the relay copy survives for Gate 2).
            let (get1, _trace) = s69_rf_get_traced(
                &rf_binary,
                &socket_arg,
                &relay_url,
                &get_gate1_arg,
                "object_s69_16mib",
            )
            .await?;
            assert_eq!(
                get1["plaintext_hash"],
                serde_json::Value::String(input_hash.clone()),
                "resumed-upload GET terminal plaintext_hash must match: {get1}"
            );
            let roundtrip = std::fs::read(&get_gate1_path)?;
            let output_hash =
                ramflux_crypto::blake3_256_base64url(ramflux_protocol::domain::OBJECT, &roundtrip);
            assert_eq!(output_hash, input_hash, "resumed-upload roundtrip blake3 must match");
            assert_eq!(roundtrip, plaintext, "resumed-upload roundtrip bytes must match");

            let rss_kib = daemon.id().and_then(s69_process_rss_kib).unwrap_or(0);
            eprintln!("s69 gate1: rfd RSS = {rss_kib} KiB after resume+get");
            assert!(rss_kib > 0, "must be able to read the rfd RSS");
            assert!(
                rss_kib < 800 * 1024,
                "rfd RSS {rss_kib} KiB must stay bounded (< 800 MiB) — no O(unbounded) resident object"
            );
            eprintln!("s69 gate1: resumed upload committed once; GET byte-identical");
            Ok::<(), Box<dyn std::error::Error>>(())
        };
        match tokio::time::timeout(Duration::from_mins(14), gate1_resume).await {
            Ok(inner) => inner?,
            Err(_elapsed) => {
                let _ = mvp_s20_stop_rf_daemon(&mut daemon).await;
                return Err("s69 gate1 resume flow timed out".into());
            }
        }

        // ---- Gate 2: mid-download crash then restart-from-zero; no partial ever published ----
        mvp_s20_stop_rf_daemon(&mut daemon).await?;
        let _ = std::fs::remove_file(&socket);
        let _ = std::fs::remove_file(&download_marker);
        daemon = s69_spawn_rf_daemon_with_env(
            &rf_binary,
            &socket_arg,
            &data_root_arg,
            &download_fault_env,
        )?;
        let gate2 = async {
            mvp_s20_wait_for_daemon_status(&rf_binary, &socket_arg).await?;
            // CTRL-108 (a): re-establish relay QUIC reachability after the restart so the object fetch
            // reaches the download spool-write (where the seam fires) rather than failing early on a
            // stale relay handshake — otherwise the crash marker would never fire.
            s69_wait_relay_quic_healthy(&stack.relay_ca).await?;

            // First get: rfd aborts after the spool write, before serving any read. The CLI cannot
            // restart against a dead daemon and fails — and never renames a partial into place.
            let (get_fail_ok, get_fail_out) = s69_run_rf_capture(
                &rf_binary,
                &[
                    "--socket",
                    &socket_arg,
                    "object",
                    "get",
                    "--account",
                    S69_ACCOUNT,
                    "--object",
                    "object_s69_16mib",
                    "--relay-url",
                    &relay_url,
                    &get_gate2_arg,
                ],
            )
            .await?;
            assert!(!get_fail_ok, "mid-download rfd abort must fail the first get CLI: {get_fail_out}");
            s69_wait_marker(Path::new(&download_marker)).await?;
            assert!(
                !get_gate2_path.exists(),
                "a mid-download crash must NEVER rename a partial output into place (no false success)"
            );
            eprintln!("s69 gate2: download crash seam fired; no partial output published");
            Ok::<(), Box<dyn std::error::Error>>(())
        };
        match tokio::time::timeout(Duration::from_mins(12), gate2).await {
            Ok(inner) => inner?,
            Err(_elapsed) => {
                let _ = mvp_s20_stop_rf_daemon(&mut daemon).await;
                return Err("s69 gate2 mid-download crash flow timed out".into());
            }
        }
        // Reap the crashed daemon and restart seam-off; the retry re-begins from offset 0.
        let _ = mvp_s20_stop_rf_daemon(&mut daemon).await;
        let _ = std::fs::remove_file(&socket);
        daemon =
            s69_spawn_rf_daemon_with_env(&rf_binary, &socket_arg, &data_root_arg, &fault_off_env)?;
        let gate2_retry = async {
            mvp_s20_wait_for_daemon_status(&rf_binary, &socket_arg).await?;
            // CTRL-108 (a): relay QUIC reachability after the restart before the restart-from-zero get.
            s69_wait_relay_quic_healthy(&stack.relay_ca).await?;
            let (get2, _trace) = s69_rf_get_traced(
                &rf_binary,
                &socket_arg,
                &relay_url,
                &get_gate2_arg,
                "object_s69_16mib",
            )
            .await?;
            assert_eq!(get2["streamed"], true, "restart download must stream to success: {get2}");
            assert_eq!(
                get2["plaintext_hash"],
                serde_json::Value::String(input_hash.clone()),
                "restart-download GET terminal plaintext_hash must match: {get2}"
            );
            let roundtrip = std::fs::read(&get_gate2_path)?;
            let output_hash =
                ramflux_crypto::blake3_256_base64url(ramflux_protocol::domain::OBJECT, &roundtrip);
            assert_eq!(output_hash, input_hash, "restart-download roundtrip must be byte-identical");
            assert_eq!(roundtrip, plaintext, "restart-download bytes must match the input");
            eprintln!("s69 gate2: restart download from offset 0 byte-identical");
            Ok::<(), Box<dyn std::error::Error>>(())
        };
        let gate2_result = tokio::time::timeout(Duration::from_mins(14), gate2_retry)
            .await
            .map_err(|_elapsed| "s69 gate2 restart download flow timed out".to_owned());

        mvp_s20_stop_rf_daemon(&mut daemon).await?;
        let _ = std::fs::remove_file(&socket);
        let _ = std::fs::remove_file(&upload_marker);
        let _ = std::fs::remove_file(&download_marker);
        std::fs::remove_dir_all(&temp_root).ok();
        gate2_result?
    });

    let relay_logs = s69_container_logs("ramflux-relay");
    std::fs::remove_dir_all(&stack.materials).ok();
    if let Err(error) = &result {
        eprintln!("s69 flow failed: {error}\n=== relay logs ===\n{relay_logs}");
    }
    result?;

    // No HTTP object request may reach the relay across either gate (all v3 QUIC).
    assert!(
        !relay_logs.contains("POST /relay/v1/object/"),
        "relay must receive zero HTTP object requests in the v3 QUIC path:\n{relay_logs}"
    );
    eprintln!("s69: relay HTTP object requests = 0");
    Ok(())
}

// ---- shared setup / helpers ----

#[cfg(feature = "realnet")]
fn s69_realnet_enabled() -> bool {
    std::env::var("RAMFLUX_ITEST_REALNET").as_deref() == Ok("1")
        && std::env::var("RAMFLUX_OBJECT_V3").as_deref() == Ok("1")
        && std::env::var("RAMFLUX_CROSS_GATEWAY").as_deref() == Ok("1")
}

#[cfg(feature = "realnet")]
fn s69_deterministic_bytes(len: usize) -> Vec<u8> {
    (0..len).map(|index| u8::try_from((index * 31 + 7) % 251).unwrap_or(0)).collect()
}

#[cfg(feature = "realnet")]
fn s69_trace_excerpt(trace: &str) -> String {
    trace.lines().take(8).collect::<Vec<_>>().join(" | ")
}

#[cfg(feature = "realnet")]
struct S69Stack {
    materials: PathBuf,
    relay_ca: PathBuf,
    sdk_env: Vec<(String, String)>,
    _node: S8RealnetNode,
}

#[cfg(feature = "realnet")]
fn s69_start_stack(ports: S8ComposePorts) -> Result<S69Stack, Box<dyn std::error::Error>> {
    let materials = temp_root("s69_crash_resume_materials")?;
    let now = ramflux_node_core::now_unix_seconds();
    let root_seed = [0x44; 32];
    let attestation_seed = [0x33; 32];
    let provider_seed = [0x66; 32];
    let offline_root_seed = [0x88; 32];
    let certificate = s69_certificate(now, S69_ISSUER_NODE, "gw-b", root_seed, attestation_seed)?;
    let envelope =
        s69_trust_envelope(now, S69_ISSUER_NODE, root_seed, provider_seed, &certificate)?;
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
    s69_write_provider_keyring(&materials, now, S69_ISSUER_NODE, offline_root_seed, provider_seed)?;

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
        ("RAMFLUX_V3_FEDERATION_TRUST_ISSUER_NODE_ID".to_owned(), S69_ISSUER_NODE.to_owned()),
        ("RAMFLUX_V3_FEDERATION_TRUST_ENDPOINT".to_owned(), "ramflux-federation:7443".to_owned()),
        ("RAMFLUX_RELAY_ITEST_CAPTURE_FILE".to_owned(), S69_CAPTURE_PATH.to_owned()),
    ];

    let node = start_s8_realnet_compose_project_with_env(S69_PROJECT, ports, &env)?;
    let relay_ca = node.ca_cert.clone();
    let sdk_env = vec![
        ("RAMFLUX_SDK_RELAY_QUIC_ADDR".to_owned(), S69_RELAY_QUIC.to_owned()),
        ("RAMFLUX_SDK_RELAY_QUIC_SERVER_NAME".to_owned(), "ramflux-relay".to_owned()),
        ("RAMFLUX_SDK_RELAY_QUIC_CA_CERT".to_owned(), relay_ca.to_string_lossy().into_owned()),
        ("RAMFLUX_SDK_RELAY_OWNER_HOME_NODE_ID".to_owned(), S69_ISSUER_NODE.to_owned()),
        ("RAMFLUX_SDK_RELAY_OWNER_PRINCIPAL_ID".to_owned(), "principal_s69_owner".to_owned()),
        ("RAMFLUX_SDK_RELAY_AUDIENCE_NODE_ID".to_owned(), S69_AUDIENCE_NODE.to_owned()),
    ];
    Ok(S69Stack { materials, relay_ca, sdk_env, _node: node })
}

#[cfg(feature = "realnet")]
async fn s69_build_rf_binary() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let manifest = code_root().join("ramflux/apps/rf/Cargo.toml");
    let status = tokio::task::spawn_blocking(move || {
        std::process::Command::new("cargo")
            .args([
                "build",
                "--quiet",
                "--features",
                "itest-local-mint,object-ipc-crash-seam",
                "--manifest-path",
            ])
            .arg(manifest)
            .status()
    })
    .await??;
    if !status.success() {
        return Err("failed to build rf binary with object-ipc-crash-seam".into());
    }
    Ok(code_root().join("ramflux/target/debug/rf"))
}

#[cfg(feature = "realnet")]
fn s69_spawn_rf_daemon_with_env(
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

/// Runs an `rf` CLI command to completion, returning `(success, combined_output)`. Used for the
/// in-flight call whose daemon self-`abort()`s mid-request (expected non-zero exit).
#[cfg(feature = "realnet")]
async fn s69_run_rf_capture(
    rf_binary: &Path,
    args: &[&str],
) -> Result<(bool, String), Box<dyn std::error::Error>> {
    let binary = rf_binary.to_path_buf();
    let owned: Vec<String> = args.iter().map(|value| (*value).to_owned()).collect();
    let output = tokio::time::timeout(
        Duration::from_mins(10),
        tokio::task::spawn_blocking(move || {
            std::process::Command::new(binary).args(owned).output()
        }),
    )
    .await
    .map_err(|_elapsed| "s69 rf capture timed out".to_owned())???;
    let mut combined = String::from_utf8_lossy(&output.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&output.stderr));
    Ok((output.status.success(), combined))
}

/// Runs `rf object put` with `RAMFLUX_BUS_TRACE=1`, returning `(terminal_json, client_bus_trace)`.
#[cfg(feature = "realnet")]
async fn s69_rf_put_traced(
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
        S69_ACCOUNT,
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
    .map_err(|_elapsed| format!("s69 rf put timed out: {command_line}"))???;
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    if !output.status.success() {
        return Err(format!(
            "s69 rf put failed: {command_line} stdout={} stderr={stderr}",
            String::from_utf8_lossy(&output.stdout)
        )
        .into());
    }
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).map_err(|error| {
        format!(
            "s69 rf put invalid JSON: {error} stdout={} stderr={stderr}",
            String::from_utf8_lossy(&output.stdout)
        )
    })?;
    Ok((value, stderr))
}

/// Runs `rf object get` with `RAMFLUX_BUS_TRACE=1`, returning `(terminal_json, client_bus_trace)`.
#[cfg(feature = "realnet")]
async fn s69_rf_get_traced(
    rf_binary: &Path,
    socket_arg: &str,
    relay_url: &str,
    output_arg: &str,
    object_id: &str,
) -> Result<(serde_json::Value, String), Box<dyn std::error::Error>> {
    let binary = rf_binary.to_path_buf();
    let args: Vec<String> = [
        "--socket",
        socket_arg,
        "object",
        "get",
        "--account",
        S69_ACCOUNT,
        "--object",
        object_id,
        "--relay-url",
        relay_url,
        output_arg,
    ]
    .iter()
    .map(|value| (*value).to_owned())
    .collect();
    let command_line = format!("{} {}", binary.display(), args.join(" "));
    let output = tokio::time::timeout(
        Duration::from_mins(12),
        tokio::task::spawn_blocking(move || {
            std::process::Command::new(binary).args(args).env("RAMFLUX_BUS_TRACE", "1").output()
        }),
    )
    .await
    .map_err(|_elapsed| format!("s69 rf get timed out: {command_line}"))???;
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    if !output.status.success() {
        return Err(format!(
            "s69 rf get failed: {command_line} stdout={} stderr={stderr}",
            String::from_utf8_lossy(&output.stdout)
        )
        .into());
    }
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).map_err(|error| {
        format!(
            "s69 rf get invalid JSON: {error} stdout={} stderr={stderr}",
            String::from_utf8_lossy(&output.stdout)
        )
    })?;
    Ok((value, stderr))
}

#[cfg(feature = "realnet")]
async fn s69_object_status(
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
            S69_ACCOUNT,
            "--object",
            object_id,
            "--direction",
            "upload",
        ],
    )
    .await
}

/// Bounded poll (30s) for the daemon-written crash-seam marker — never a sleep-based timing guess.
#[cfg(feature = "realnet")]
async fn s69_wait_marker(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    for _attempt in 0..300 {
        if path.exists() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(format!("s69 crash-seam marker never appeared: {}", path.display()).into())
}

/// Reads a process RSS in KiB via `ps -o rss= -p <pid>` (KiB on macOS and Linux).
#[cfg(feature = "realnet")]
fn s69_process_rss_kib(pid: u32) -> Option<u64> {
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
async fn s69_wait_relay_quic_healthy(ca_cert: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let config =
        ramflux_transport::RelayClientQuicConfig::new(S69_RELAY_QUIC, "ramflux-relay", ca_cert)?;
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
fn s69_container(service: &str) -> String {
    format!("{S69_PROJECT}_{service}_1")
}

#[cfg(feature = "realnet")]
fn s69_reset_capture() -> Result<(), Box<dyn std::error::Error>> {
    let container = s69_container("ramflux-relay");
    let output = std::process::Command::new(container_runtime())
        .args(["exec", &container, "rm", "-f", S69_CAPTURE_PATH])
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
fn s69_read_capture() -> Result<Vec<S69CaptureLine>, Box<dyn std::error::Error>> {
    let container = s69_container("ramflux-relay");
    let output = std::process::Command::new(container_runtime())
        .args([
            "exec",
            &container,
            "sh",
            "-c",
            &format!("cat {S69_CAPTURE_PATH} 2>/dev/null || true"),
        ])
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "capture read failed (exec cat {S69_CAPTURE_PATH}): {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut lines = Vec::new();
    for raw in text.lines().filter(|line| !line.trim().is_empty()) {
        lines.push(serde_json::from_str::<S69CaptureLine>(raw)?);
    }
    Ok(lines)
}

#[cfg(feature = "realnet")]
fn s69_assert_no_double_mutation(
    capture: &[S69CaptureLine],
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
fn s69_container_logs(service: &str) -> String {
    let container = s69_container(service);
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

// ---- v3 trust material (object-v3 stack; same shape as s55/s62/s65/s67/s68) ----

#[cfg(feature = "realnet")]
fn s69_certificate(
    now: u64,
    node_id: &str,
    gateway_instance_id: &str,
    root_seed: [u8; 32],
    attestation_seed: [u8; 32],
) -> Result<ramflux_node_core::GatewayIssuerCertificate, Box<dyn std::error::Error>> {
    let mut certificate = ramflux_node_core::GatewayIssuerCertificate {
        schema: ramflux_node_core::GATEWAY_ISSUER_CERTIFICATE_SCHEMA.to_owned(),
        version: ramflux_node_core::OBJECT_RELAY_V3_PROOF_VERSION,
        cert_id: "s69-gw-b-cert-1".to_owned(),
        node_id: node_id.to_owned(),
        gateway_instance_id: gateway_instance_id.to_owned(),
        attestation_public_key: ramflux_crypto::public_key_base64url_from_seed(attestation_seed),
        attestation_key_id: "s69-gw-b-attestation-1".to_owned(),
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
fn s69_trust_envelope(
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
        provider_signing_key_id: "s69-provider-1".to_owned(),
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
fn s69_write_provider_keyring(
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
            key_id: "s69-provider-1".to_owned(),
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
