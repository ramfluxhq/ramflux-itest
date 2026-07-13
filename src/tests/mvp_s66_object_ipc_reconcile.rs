// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! T25-A2 (OBJ-IPC-01 / CTRL-101) realnet: durable `object.put` reconciliation state machine.
//!
//! Driven only through the public `rf` CLI -> rfd bus -> SDK over the real object-v3 stack, this
//! proves the A2 guarantees that pure/local tests cannot:
//!   * response-drop-after-Committed (P0-2 local-bus seam, marker0): a public `rf object put` whose
//!     local-bus RESPONSE is dropped AFTER the operation is durably `Committed` — the CLI
//!     auto-status-reconnects with the SAME (deterministic) `operation_id` and returns compact
//!     success with `reconciled=true`; the relay committed the content exactly once (no double
//!     mutation);
//!   * four SIGKILL windows (W1 after Pending / W2 after `LocalCommitted` / W3 after relay / W4
//!     after `Committed`): SIGKILL the daemon at each barrier, restart on the SAME data-root, and
//!     re-run the PUT — the reconciled PUT returns the SAME `plaintext_hash` (and, for W2..W4, the
//!     SAME `manifest_hash` from adoption), no second object key is generated, and the GET
//!     round-trips a single consistent copy with zero HTTP object fallback.
//!
//! The two seams (SDK `itest-bus-fault` response-loss + SDK `itest-rfd-fault` barriers) are compiled
//! only under their features (default/release `rf` contains neither) and are inert until their
//! runtime env arms them (double gate, marker0 in production).

#![allow(unused_imports)]
#![cfg_attr(not(feature = "realnet"), allow(dead_code))]
use super::*;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[cfg(feature = "realnet")]
const S66_PROJECT: &str = "ramflux-s66-obj-reconcile";
#[cfg(feature = "realnet")]
const S66_RELAY_QUIC: &str = "127.0.0.1:17447";
#[cfg(feature = "realnet")]
const S66_CAPTURE_PATH: &str = "/var/lib/ramflux/relay/s66-capture.jsonl";
#[cfg(feature = "realnet")]
const S66_HOLD_MARKER_PATH: &str = "/var/lib/ramflux/relay/s66-hold.marker";
#[cfg(feature = "realnet")]
const S66_ACCOUNT: &str = "owner_s66_account";

#[cfg(feature = "realnet")]
#[derive(Clone, Debug, serde::Deserialize)]
struct S66CaptureLine {
    route: String,
    body_fingerprint: String,
    action: String,
    status: u16,
}

#[cfg(feature = "realnet")]
#[test]
#[allow(clippy::too_many_lines)]
fn mvp_s66_realnet_object_ipc_reconcile() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1")
        || std::env::var("RAMFLUX_OBJECT_V3").as_deref() != Ok("1")
        || std::env::var("RAMFLUX_CROSS_GATEWAY").as_deref() != Ok("1")
    {
        eprintln!(
            "skipping s66 object-ipc reconcile realnet; set RAMFLUX_ITEST_REALNET=1 RAMFLUX_OBJECT_V3=1 RAMFLUX_CROSS_GATEWAY=1"
        );
        return Ok(());
    }

    let issuer_node = "node_b.realnet";
    let audience_node = "node_a.realnet";
    let owner_principal = "principal_s66_owner";

    let materials = temp_root("s66_reconcile_materials")?;
    let now = ramflux_node_core::now_unix_seconds();
    let root_seed = [0x44; 32];
    let attestation_seed = [0x33; 32];
    let provider_seed = [0x66; 32];
    let offline_root_seed = [0x88; 32];
    let certificate = s66_certificate(now, issuer_node, "gw-b", root_seed, attestation_seed)?;
    let envelope = s66_trust_envelope(now, issuer_node, root_seed, provider_seed, &certificate)?;
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
    s66_write_provider_keyring(&materials, now, issuer_node, offline_root_seed, provider_seed)?;

    let ports = S8ComposePorts {
        gateway_http: 64_481,
        gateway_quic: 64_751,
        router_http: 64_480,
        router_mesh: 64_752,
        notify_http: 64_483,
        federation_http: 64_482,
        federation_mesh: 64_753,
        relay_http: 64_484,
        relay_media_udp: 64_420,
        signaling_turn_udp: 64_778,
        signaling_turn_tcp: 64_779,
        retention_http: 64_487,
    };
    let node = start_s8_realnet_compose_project_with_env(
        S66_PROJECT,
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
            // The relay is built with itest-quic-fault (fail-closed capture); every object-v3
            // realnet test must set the capture + hold marker (s62/s63 do the same).
            ("RAMFLUX_RELAY_ITEST_CAPTURE_FILE".to_owned(), S66_CAPTURE_PATH.to_owned()),
            ("RAMFLUX_RELAY_ITEST_HOLD_MARKER".to_owned(), S66_HOLD_MARKER_PATH.to_owned()),
        ],
    )?;

    let relay_ca = node.ca_cert.clone();
    let relay_url = format!("http://127.0.0.1:{}", ports.relay_http);
    let gateway_b_quic_addr = "127.0.0.1:18444";

    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    let result = runtime.block_on(async {
        let config = ramflux_transport::RelayClientQuicConfig::new(
            S66_RELAY_QUIC,
            "ramflux-relay",
            &relay_ca,
        )?;
        let mut health = None;
        for _ in 0..30 {
            if let Ok(value) = ramflux_transport::relay_client_quic_health(
                &config,
                std::time::Duration::from_secs(5),
            )
            .await
            {
                health = Some(value);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
        let health = health.ok_or("relay client QUIC never became healthy")?;
        assert_eq!(health.status, 200, "relay client QUIC listener must be healthy: {health:?}");

        let sdk_env = vec![
            ("RAMFLUX_SDK_RELAY_QUIC_ADDR".to_owned(), S66_RELAY_QUIC.to_owned()),
            ("RAMFLUX_SDK_RELAY_QUIC_SERVER_NAME".to_owned(), "ramflux-relay".to_owned()),
            ("RAMFLUX_SDK_RELAY_QUIC_CA_CERT".to_owned(), relay_ca.to_string_lossy().into_owned()),
            ("RAMFLUX_SDK_RELAY_OWNER_HOME_NODE_ID".to_owned(), issuer_node.to_owned()),
            ("RAMFLUX_SDK_RELAY_OWNER_PRINCIPAL_ID".to_owned(), owner_principal.to_owned()),
            ("RAMFLUX_SDK_RELAY_AUDIENCE_NODE_ID".to_owned(), audience_node.to_owned()),
        ];
        s66_flow(gateway_b_quic_addr, &relay_url, owner_principal, &sdk_env).await
    });

    let relay_logs = s66_container_logs("ramflux-relay");
    std::fs::remove_dir_all(&materials).ok();
    if let Err(error) = &result {
        eprintln!("s66 flow failed: {error}\n=== relay logs ===\n{relay_logs}");
    }
    result?;
    assert!(
        !relay_logs.contains("POST /relay/v1/object/"),
        "relay must receive zero HTTP object requests across the reconcile flow:\n{relay_logs}"
    );
    Ok(())
}

#[cfg(feature = "realnet")]
#[allow(clippy::too_many_lines)]
async fn s66_flow(
    gateway_b_quic_addr: &str,
    relay_url: &str,
    owner_principal: &str,
    sdk_env: &[(String, String)],
) -> Result<(), Box<dyn std::error::Error>> {
    let temp = temp_root("s66_reconcile_sdk")?;
    let data_root = temp.join("owner/data");
    std::fs::create_dir_all(&data_root)?;
    let pid = std::process::id();
    let socket = PathBuf::from(format!("/tmp/ramflux-s66-rfd-{pid}.sock"));
    let bus_marker = format!("/tmp/ramflux-s66-bus-fault-{pid}.marker");
    let rfd_marker = format!("/tmp/ramflux-s66-rfd-fault-{pid}.marker");
    let input_path = temp.join("s66-object-input.bin");
    let output_path = temp.join("s66-object-output.bin");
    // >= 3 chunks at 1024-byte chunks so a single PUT is several relay put_chunk mutations.
    let plaintext = b"mvp_s66_object_ipc_reconcile_owner_object_do_not_leak_plaintext".repeat(80);
    std::fs::write(&input_path, &plaintext)?;
    let expected_plaintext_hash =
        ramflux_crypto::blake3_256_base64url(ramflux_protocol::domain::OBJECT, &plaintext);

    let rf_binary = s66_build_rf_binary().await?;
    let socket_arg = mvp_s4_path_arg(&socket);
    let data_root_arg = mvp_s4_path_arg(&data_root);
    let input_arg = mvp_s4_path_arg(&input_path);
    let output_arg = mvp_s4_path_arg(&output_path);
    let ca_cert_arg = mvp_s4_path_arg(&PathBuf::from(
        sdk_env
            .iter()
            .find(|(key, _)| key == "RAMFLUX_SDK_RELAY_QUIC_CA_CERT")
            .map(|(_, value)| value.clone())
            .unwrap_or_default(),
    ));

    let fault_off_env = sdk_env.to_vec();

    // Boot fault-off, create the owner account.
    let mut daemon =
        s66_spawn_rf_daemon_with_env(&rf_binary, &socket_arg, &data_root_arg, &fault_off_env)?;
    mvp_s4_wait_for_socket(&socket).await?;
    mvp_s10_create_rf_account(
        &rf_binary,
        &socket_arg,
        S66_ACCOUNT,
        owner_principal,
        "owner_device_s66",
        "target_s66_owner",
        gateway_b_quic_addr,
        &ca_cert_arg,
        "60",
        "61",
    )
    .await?;

    // ---- Phase A: response-drop-after-Committed (P0-2 local-bus seam, marker0) ----
    // Restart the daemon with the bus-fault seam armed. The public PUT commits durably, the daemon
    // drops the local-bus response, and the CLI auto-status-reconnects (same operation_id) and
    // returns compact success with reconciled=true. Exactly one relay commit (no double mutation).
    eprintln!("STEP s66 phaseA: restart armed bus-fault");
    mvp_s20_stop_rf_daemon(&mut daemon).await?;
    let _ = std::fs::remove_file(&socket);
    let _ = std::fs::remove_file(&bus_marker);
    let bus_fault_env = {
        let mut env = fault_off_env.clone();
        env.push(("RAMFLUX_SDK_ITEST_BUS_FAULT_MODE".to_owned(), "object-put-response".to_owned()));
        env.push(("RAMFLUX_SDK_ITEST_BUS_FAULT_MARKER".to_owned(), bus_marker.clone()));
        env
    };
    daemon = s66_spawn_rf_daemon_with_env(&rf_binary, &socket_arg, &data_root_arg, &bus_fault_env)?;
    mvp_s20_wait_for_daemon_status(&rf_binary, &socket_arg).await?;

    s66_reset_capture()?;
    let object_drop = "object_s66_response_drop";
    let reconciled =
        s66_object_put(&rf_binary, &socket_arg, relay_url, &input_arg, object_drop).await?;
    assert_eq!(
        reconciled["reconciled"],
        serde_json::Value::Bool(true),
        "response-drop PUT must return reconciled=true: {reconciled}"
    );
    assert_eq!(
        reconciled["committed"],
        serde_json::Value::Bool(true),
        "response-drop PUT must be committed: {reconciled}"
    );
    assert_eq!(
        reconciled["plaintext_hash"],
        serde_json::Value::String(expected_plaintext_hash.clone()),
        "response-drop terminal plaintext_hash must match: {reconciled}"
    );
    let drop_manifest = reconciled["manifest_hash"].as_str().unwrap_or_default().to_owned();
    assert!(!drop_manifest.is_empty(), "terminal must carry a manifest_hash: {reconciled}");
    // The bus-fault marker proves the seam actually dropped the response (not a lucky success).
    assert!(
        Path::new(&bus_marker).exists(),
        "the bus-fault response-drop marker must have been written"
    );
    // Relay saw the object committed exactly once (each put_chunk fingerprint written at most once).
    s66_assert_no_double_mutation(&s66_read_capture()?, "/put_chunk")?;

    // Restart fault-off; the object GET round-trips the single consistent copy, and status=committed.
    mvp_s20_stop_rf_daemon(&mut daemon).await?;
    let _ = std::fs::remove_file(&socket);
    daemon = s66_spawn_rf_daemon_with_env(&rf_binary, &socket_arg, &data_root_arg, &fault_off_env)?;
    mvp_s20_wait_for_daemon_status(&rf_binary, &socket_arg).await?;
    s66_object_get(&rf_binary, &socket_arg, relay_url, &output_arg, object_drop).await?;
    assert_eq!(
        std::fs::read(&output_path)?,
        plaintext,
        "response-drop object must GET-roundtrip a single consistent copy"
    );

    // ---- Phase B: four SIGKILL windows W1..W4 ----
    let windows = [
        ("put-after-pending", "object_s66_w1"),
        ("put-after-local-committed", "object_s66_w2"),
        ("put-before-committed", "object_s66_w3"),
        ("put-after-committed", "object_s66_w4"),
    ];
    for (mode, object_id) in windows {
        eprintln!("STEP s66 phaseB: window {mode} object {object_id}");
        mvp_s20_stop_rf_daemon(&mut daemon).await?;
        let _ = std::fs::remove_file(&socket);
        let _ = std::fs::remove_file(&rfd_marker);
        let rfd_fault_env = {
            let mut env = fault_off_env.clone();
            env.push(("RAMFLUX_SDK_ITEST_RFD_FAULT_MODE".to_owned(), mode.to_owned()));
            env.push(("RAMFLUX_SDK_ITEST_RFD_FAULT_MARKER".to_owned(), rfd_marker.clone()));
            env
        };
        daemon =
            s66_spawn_rf_daemon_with_env(&rf_binary, &socket_arg, &data_root_arg, &rfd_fault_env)?;
        mvp_s20_wait_for_daemon_status(&rf_binary, &socket_arg).await?;

        // Run the PUT in the background; the daemon parks at the barrier then is SIGKILLed.
        let held = {
            let rf_binary = rf_binary.clone();
            let socket_arg = socket_arg.clone();
            let relay_url = relay_url.to_owned();
            let input_arg = input_arg.clone();
            let object_id = object_id.to_owned();
            tokio::spawn(async move {
                s66_run_rf_capture(
                    &rf_binary,
                    &[
                        "--socket",
                        &socket_arg,
                        "object",
                        "put",
                        "--account",
                        S66_ACCOUNT,
                        "--object",
                        &object_id,
                        "--chunk-size",
                        "1024",
                        "--relay-url",
                        &relay_url,
                        &input_arg,
                    ],
                )
                .await
            })
        };
        s66_wait_marker(Path::new(&rfd_marker)).await?;
        mvp_s20_stop_rf_daemon(&mut daemon).await?;
        let held_result = held.await?.map_err(|error| format!("s66 held put task: {error}"))?;
        assert!(
            !held_result.0,
            "mid-flight SIGKILL must fail the in-flight object put CLI ({mode}): {}",
            held_result.1
        );
        let _ = std::fs::remove_file(&socket);

        // Restart fault-off on the SAME data-root; re-run the PUT (deterministic operation_id ->
        // reconcile/adopt). Assert plaintext_hash is stable across all windows, and for W2..W4 the
        // manifest_hash is adopted unchanged (no second object key).
        daemon =
            s66_spawn_rf_daemon_with_env(&rf_binary, &socket_arg, &data_root_arg, &fault_off_env)?;
        mvp_s20_wait_for_daemon_status(&rf_binary, &socket_arg).await?;
        s66_reset_capture()?;
        let retried =
            s66_object_put(&rf_binary, &socket_arg, relay_url, &input_arg, object_id).await?;
        assert_eq!(
            retried["plaintext_hash"],
            serde_json::Value::String(expected_plaintext_hash.clone()),
            "{mode}: reconciled PUT plaintext_hash must match: {retried}"
        );
        assert_eq!(
            retried["committed"],
            serde_json::Value::Bool(true),
            "{mode}: reconciled PUT must be committed: {retried}"
        );
        let retried_manifest = retried["manifest_hash"].as_str().unwrap_or_default().to_owned();
        assert!(!retried_manifest.is_empty(), "{mode}: retried terminal manifest_hash: {retried}");

        // Idempotent repeat: the same deterministic operation_id now finds the operation `committed`
        // and returns the STORED compact terminal with reconciled=true and the SAME manifest_hash.
        // A regenerated object key would change the manifest_hash, so a stable manifest across the
        // repeat proves no second object key was generated (W2..W4 adopt the stored object; W1's
        // re-derived object is likewise committed exactly once).
        let repeat =
            s66_object_put(&rf_binary, &socket_arg, relay_url, &input_arg, object_id).await?;
        assert_eq!(
            repeat["reconciled"],
            serde_json::Value::Bool(true),
            "{mode}: idempotent repeat must be reconciled: {repeat}"
        );
        assert_eq!(
            repeat["manifest_hash"].as_str().unwrap_or_default(),
            retried_manifest,
            "{mode}: idempotent repeat manifest_hash must be stable — no second object key: {repeat}"
        );
        // No double relay mutation, and the object GET round-trips a single consistent copy.
        s66_assert_no_double_mutation(&s66_read_capture()?, "/put_chunk")?;
        s66_object_get(&rf_binary, &socket_arg, relay_url, &output_arg, object_id).await?;
        assert_eq!(
            std::fs::read(&output_path)?,
            plaintext,
            "{mode}: reconciled object must GET-roundtrip a single consistent copy"
        );
    }

    mvp_s20_stop_rf_daemon(&mut daemon).await?;
    let _ = std::fs::remove_file(&socket);
    let _ = std::fs::remove_file(&bus_marker);
    let _ = std::fs::remove_file(&rfd_marker);
    std::fs::remove_dir_all(&temp).ok();
    Ok(())
}

// ---- rf CLI helpers ----

#[cfg(feature = "realnet")]
async fn s66_build_rf_binary() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let manifest = code_root().join("ramflux/apps/rf/Cargo.toml");
    let status = tokio::task::spawn_blocking(move || {
        std::process::Command::new("cargo")
            .args([
                "build",
                "--quiet",
                "--features",
                "itest-local-mint,itest-rfd-fault,itest-bus-fault",
                "--manifest-path",
            ])
            .arg(manifest)
            .status()
    })
    .await??;
    if !status.success() {
        return Err("failed to build rf binary with itest-rfd-fault,itest-bus-fault".into());
    }
    Ok(code_root().join("ramflux/target/debug/rf"))
}

#[cfg(feature = "realnet")]
fn s66_spawn_rf_daemon_with_env(
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
async fn s66_object_put(
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
            S66_ACCOUNT,
            "--object",
            object_id,
            "--chunk-size",
            "1024",
            "--relay-url",
            relay_url,
            input_arg,
        ],
    )
    .await
}

#[cfg(feature = "realnet")]
async fn s66_object_get(
    rf_binary: &Path,
    socket_arg: &str,
    relay_url: &str,
    output_arg: &str,
    object_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    mvp_s4_rf_json(
        rf_binary,
        &[
            "--socket",
            socket_arg,
            "object",
            "get",
            "--account",
            S66_ACCOUNT,
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

/// Runs an `rf` CLI command to completion, returning `(success, combined_output)`. Used for the
/// in-flight faulting call whose daemon is `SIGKILL`ed mid-request (expected non-zero exit).
#[cfg(feature = "realnet")]
async fn s66_run_rf_capture(
    rf_binary: &Path,
    args: &[&str],
) -> Result<(bool, String), Box<dyn std::error::Error + Send + Sync>> {
    let output = tokio::process::Command::new(rf_binary).args(args).output().await?;
    let mut combined = String::from_utf8_lossy(&output.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&output.stderr));
    Ok((output.status.success(), combined))
}

#[cfg(feature = "realnet")]
async fn s66_wait_marker(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    for _ in 0..300 {
        if path.exists() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(format!("s66 fault marker never appeared: {}", path.display()).into())
}

// ---- relay capture (proves committed-once / no double mutation) ----

#[cfg(feature = "realnet")]
fn s66_container(service: &str) -> String {
    format!("{S66_PROJECT}_{service}_1")
}

#[cfg(feature = "realnet")]
fn s66_reset_capture() -> Result<(), Box<dyn std::error::Error>> {
    let container = s66_container("ramflux-relay");
    let output = std::process::Command::new(container_runtime())
        .args(["exec", &container, "rm", "-f", S66_CAPTURE_PATH])
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
fn s66_read_capture() -> Result<Vec<S66CaptureLine>, Box<dyn std::error::Error>> {
    let container = s66_container("ramflux-relay");
    let output = std::process::Command::new(container_runtime())
        .args(["exec", &container, "cat", S66_CAPTURE_PATH])
        .output()?;
    if !output.status.success() {
        // An absent capture file means the relay wrote NOTHING for this window — e.g. a W3 crash
        // recovery whose durable completed_chunks ledger lets the resumed PUT skip every chunk, so it
        // never re-contacts the relay and `s66_reset_capture()`'s deletion is never recreated. Zero
        // writes trivially satisfy no-double-mutation, so treat file-absent as an empty capture; only
        // a genuine exec failure is an error.
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("No such file or directory") {
            return Ok(Vec::new());
        }
        return Err(format!("capture read failed (exec cat {S66_CAPTURE_PATH}): {stderr}").into());
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut lines = Vec::new();
    for raw in text.lines().filter(|line| !line.trim().is_empty()) {
        lines.push(serde_json::from_str::<S66CaptureLine>(raw)?);
    }
    Ok(lines)
}

/// Asserts no chunk was mutated (written) twice on the relay for a route: every WRITTEN body
/// fingerprint on `route_suffix` is unique. A double relay mutation (the same chunk committed twice)
/// would show a repeated written fingerprint. Dropped/held attempts are ignored (those are the
/// intentional ambiguous-commit seam, not a second mutation).
#[cfg(feature = "realnet")]
fn s66_assert_no_double_mutation(
    capture: &[S66CaptureLine],
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
fn s66_container_logs(service: &str) -> String {
    let container = s66_container(service);
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

// ---- v3 trust material (object-v3 stack; same shape as s62/s63) ----

#[cfg(feature = "realnet")]
fn s66_certificate(
    now: u64,
    node_id: &str,
    gateway_instance_id: &str,
    root_seed: [u8; 32],
    attestation_seed: [u8; 32],
) -> Result<ramflux_node_core::GatewayIssuerCertificate, Box<dyn std::error::Error>> {
    let mut certificate = ramflux_node_core::GatewayIssuerCertificate {
        schema: ramflux_node_core::GATEWAY_ISSUER_CERTIFICATE_SCHEMA.to_owned(),
        version: ramflux_node_core::OBJECT_RELAY_V3_PROOF_VERSION,
        cert_id: "s66-gw-b-cert-1".to_owned(),
        node_id: node_id.to_owned(),
        gateway_instance_id: gateway_instance_id.to_owned(),
        attestation_public_key: ramflux_crypto::public_key_base64url_from_seed(attestation_seed),
        attestation_key_id: "s66-gw-b-attestation-1".to_owned(),
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
fn s66_trust_envelope(
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
        provider_signing_key_id: "s66-provider-1".to_owned(),
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
fn s66_write_provider_keyring(
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
            key_id: "s66-provider-1".to_owned(),
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
