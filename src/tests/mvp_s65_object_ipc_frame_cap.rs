// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

// T25-A1 (CTRL-099 / OBJ-IPC-01): the symmetric 1 MiB local-bus frame cap + compact object.put
// response, proven on the real object-v3 stack through the public rf CLI -> rfd bus -> SDK path.
//
//   * Gate 1 (mvp_s65_realnet_object_ipc_512kib_put): a ~512 KiB public `rf object put` previously
//     OVERFLOWED the old ~214 KiB response ceiling (the response echoed the whole ciphertext at
//     ~4.9x). With the compact PUT response it must now SUCCEED end to end: the CLI PUT returns,
//     the upload transfer reaches `complete`, no HTTP object request reaches the relay (all v3
//     QUIC), and a GET round-trips the exact plaintext (hash match).
//   * Gate 2 (mvp_s65_realnet_object_ipc_1mib_reject): a 1 MiB one-shot `rf object put` inflates to
//     a base64 request frame > 1 MiB, so the SDK writer-side cap rejects it BEFORE emitting any
//     bytes -> the request never reaches dispatch. The CLI reports "local bus frame too large", the
//     object is ABSENT from the local store afterward (object list), and the relay's per-client-QUIC
//     request capture shows ZERO put_chunk (zero relay mutation).
//
// The relay is always compiled with `itest-quic-fault`, whose non-sensitive per-request fingerprint
// capture (RAMFLUX_RELAY_ITEST_CAPTURE_FILE) records every client-QUIC object route; Gate 2 uses it
// to prove no put_chunk was ever received. Trust material mirrors s55/s62 (object-v3 stack).
#![allow(unused_imports)]
#![cfg_attr(not(feature = "realnet"), allow(dead_code))]
use super::*;

#[cfg(feature = "realnet")]
const S65_ISSUER_NODE: &str = "node_b.realnet";
#[cfg(feature = "realnet")]
const S65_AUDIENCE_NODE: &str = "node_a.realnet";
#[cfg(feature = "realnet")]
const S65_RELAY_QUIC: &str = "127.0.0.1:17447";
#[cfg(feature = "realnet")]
const S65_GATEWAY_B_QUIC: &str = "127.0.0.1:18444";

#[cfg(feature = "realnet")]
// Fields beyond `route` are retained for the Debug output printed in the zero-put_chunk assertion
// failure message; dead-code analysis ignores derived Debug, so silence it here (harness only).
#[allow(dead_code)]
#[derive(Clone, Debug, serde::Deserialize)]
struct S65CaptureLine {
    method: String,
    route: String,
    action: String,
    status: u16,
}

// ---- Gate 1: 512 KiB public PUT succeeds (compact response), HTTP object = 0, GET hash match ----

#[cfg(feature = "realnet")]
#[test]
#[allow(clippy::too_many_lines)]
fn mvp_s65_realnet_object_ipc_512kib_put() -> Result<(), Box<dyn std::error::Error>> {
    if !s65_realnet_enabled() {
        eprintln!(
            "skipping s65 512KiB PUT realnet; set RAMFLUX_ITEST_REALNET=1 RAMFLUX_OBJECT_V3=1 RAMFLUX_CROSS_GATEWAY=1"
        );
        return Ok(());
    }

    let project = "ramflux-s65a-ipc-512k";
    let ports = S8ComposePorts {
        gateway_http: 64_281,
        gateway_quic: 64_551,
        router_http: 64_280,
        router_mesh: 64_552,
        notify_http: 64_283,
        federation_http: 64_282,
        federation_mesh: 64_553,
        relay_http: 64_284,
        relay_media_udp: 64_220,
        signaling_turn_udp: 64_578,
        signaling_turn_tcp: 64_579,
        retention_http: 64_287,
    };
    let stack =
        s65_start_stack(project, "s65a_512k_materials", ports, "principal_s65a_owner", None)?;
    let relay_url = format!("http://127.0.0.1:{}", ports.relay_http);

    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    runtime.block_on(async {
        s65_wait_relay_quic_healthy(&stack.relay_ca).await?;

        let temp_root = temp_root("s65a_512k_sdk")?;
        let data_root = temp_root.join("owner/data");
        std::fs::create_dir_all(&data_root)?;
        let socket = PathBuf::from(format!("/tmp/ramflux-s65a-rfd-{}.sock", std::process::id()));
        let input_path = temp_root.join("object-input.bin");
        let output_path = temp_root.join("object-output.bin");
        // 512 KiB plaintext: base64 ~= 699 KiB < 1 MiB request frame (fits), but > the OLD ~214 KiB
        // response ceiling the 4.9x ciphertext echo used to blow through.
        let plaintext = s65_deterministic_bytes(512 * 1024);
        assert_eq!(plaintext.len(), 524_288);
        std::fs::write(&input_path, &plaintext)?;
        let input_hash = ramflux_crypto::blake3_256_base64url(
            ramflux_protocol::domain::OBJECT,
            &plaintext,
        );

        let rf_binary = mvp_s4_build_rf_binary().await?;
        let ca_cert_arg = mvp_s4_path_arg(&stack.relay_ca);
        let socket_arg = mvp_s4_path_arg(&socket);
        let data_root_arg = mvp_s4_path_arg(&data_root);
        let input_arg = mvp_s4_path_arg(&input_path);
        let output_arg = mvp_s4_path_arg(&output_path);

        let mut daemon =
            s65_spawn_rf_daemon_with_env(&rf_binary, &socket_arg, &data_root_arg, &stack.sdk_env)?;

        let flow = async {
            mvp_s4_wait_for_socket(&socket).await?;
            mvp_s10_create_rf_account(
                &rf_binary,
                &socket_arg,
                "owner_s65a_account",
                "principal_s65a_owner",
                "owner_device_s65a",
                "target_s65a_owner",
                S65_GATEWAY_B_QUIC,
                &ca_cert_arg,
                "50",
                "51",
            )
            .await?;

            // PUT ~512 KiB. The compact response must return success (no oversized-response overflow).
            let put = mvp_s4_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &socket_arg,
                    "object",
                    "put",
                    "--account",
                    "owner_s65a_account",
                    "--object",
                    "object_s65a_512k",
                    "--chunk-size",
                    "32768",
                    "--relay-url",
                    &relay_url,
                    &input_arg,
                ],
            )
            .await?;
            // Compact response contract (T25-A1): identifiers/hashes/status only, no ciphertext echo.
            assert_eq!(put["object_id"], "object_s65a_512k", "compact PUT response object_id");
            assert_eq!(put["committed"], true, "compact PUT response committed");
            assert!(put.get("object").is_none(), "compact response must not echo object");
            assert!(put.get("chunks").is_none(), "compact response must not echo chunks");
            let put_response_len = put.to_string().len();
            assert!(
                put_response_len < 214 * 1024,
                "compact PUT response ({put_response_len} bytes) must stay far below the old ~214 KiB ceiling"
            );
            // T25-A1 opacity: run the SAME migrated assertion objects_calls_bots.rs now uses on the
            // compact IPC response — the node-visible PUT response leaks no plaintext (executes the
            // migrated opacity check on a real compact response; the s15/s16 hosts are Linux-only).
            assert_node_opaque_payload(&put.to_string(), &plaintext);
            eprintln!("s65a: 512 KiB PUT ok; compact response = {put_response_len} bytes; node-opaque (no plaintext leak)");

            // Upload transfer reaches complete over v3 QUIC.
            let upload = s65_object_status(
                &rf_binary,
                &socket_arg,
                "owner_s65a_account",
                "object_s65a_512k",
                "upload",
            )
            .await?;
            assert_eq!(
                upload["transfer"]["state"], "complete",
                "512 KiB put must complete over QUIC: {upload}"
            );

            // GET round-trips the exact plaintext (hash match).
            mvp_s4_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &socket_arg,
                    "object",
                    "get",
                    "--account",
                    "owner_s65a_account",
                    "--object",
                    "object_s65a_512k",
                    "--relay-url",
                    &relay_url,
                    "--relay-ack",
                    &output_arg,
                ],
            )
            .await?;
            let roundtrip = std::fs::read(&output_path)?;
            let output_hash = ramflux_crypto::blake3_256_base64url(
                ramflux_protocol::domain::OBJECT,
                &roundtrip,
            );
            assert_eq!(roundtrip.len(), plaintext.len(), "roundtrip length must match");
            assert_eq!(roundtrip, plaintext, "roundtrip plaintext bytes must match");
            assert_eq!(input_hash, output_hash, "roundtrip hash must match");
            eprintln!(
                "s65a: GET roundtrip hash match len={} input_hash={input_hash} output_hash={output_hash}",
                roundtrip.len()
            );
            Ok::<(), Box<dyn std::error::Error>>(())
        };

        let result = tokio::time::timeout(Duration::from_mins(6), flow)
            .await
            .map_err(|_elapsed| "s65a 512 KiB flow timed out".to_owned());
        mvp_s20_stop_rf_daemon(&mut daemon).await?;
        let _ = std::fs::remove_file(&socket);
        std::fs::remove_dir_all(&temp_root).ok();
        result?
    })?;

    // No HTTP object request may reach the relay (all v3 QUIC).
    let relay_logs = s65_container_logs(project, "ramflux-relay");
    assert!(
        !relay_logs.contains("POST /relay/v1/object/"),
        "relay must not receive any HTTP object request in the v3 QUIC path:\n{relay_logs}"
    );
    eprintln!("s65a: relay HTTP object requests = 0");

    std::fs::remove_dir_all(&stack.materials).ok();
    Ok(())
}

// ---- Gate 2: 1 MiB one-shot PUT rejected client-side BEFORE write; zero local + zero relay mutation ----

#[cfg(feature = "realnet")]
#[test]
#[allow(clippy::too_many_lines)]
fn mvp_s65_realnet_object_ipc_1mib_reject() -> Result<(), Box<dyn std::error::Error>> {
    if !s65_realnet_enabled() {
        eprintln!(
            "skipping s65 1MiB reject realnet; set RAMFLUX_ITEST_REALNET=1 RAMFLUX_OBJECT_V3=1 RAMFLUX_CROSS_GATEWAY=1"
        );
        return Ok(());
    }

    let project = "ramflux-s65b-ipc-reject";
    let capture_path = "/var/lib/ramflux/relay/s65b-ipc-capture.jsonl";
    let ports = S8ComposePorts {
        gateway_http: 64_381,
        gateway_quic: 64_651,
        router_http: 64_380,
        router_mesh: 64_652,
        notify_http: 64_383,
        federation_http: 64_382,
        federation_mesh: 64_653,
        relay_http: 64_384,
        relay_media_udp: 64_320,
        signaling_turn_udp: 64_678,
        signaling_turn_tcp: 64_679,
        retention_http: 64_387,
    };
    let stack = s65_start_stack(
        project,
        "s65b_reject_materials",
        ports,
        "principal_s65b_owner",
        Some(capture_path),
    )?;
    let relay_url = format!("http://127.0.0.1:{}", ports.relay_http);

    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    runtime.block_on(async {
        s65_wait_relay_quic_healthy(&stack.relay_ca).await?;

        let temp_root = temp_root("s65b_reject_sdk")?;
        let data_root = temp_root.join("owner/data");
        std::fs::create_dir_all(&data_root)?;
        let socket = PathBuf::from(format!("/tmp/ramflux-s65b-rfd-{}.sock", std::process::id()));
        let input_path = temp_root.join("object-input.bin");
        // Exactly 1 MiB plaintext -> base64 ~= 1.33 MiB request frame > the 1 MiB cap.
        let plaintext = s65_deterministic_bytes(1024 * 1024);
        assert_eq!(plaintext.len(), 1_048_576);
        std::fs::write(&input_path, &plaintext)?;

        let rf_binary = mvp_s4_build_rf_binary().await?;
        let ca_cert_arg = mvp_s4_path_arg(&stack.relay_ca);
        let socket_arg = mvp_s4_path_arg(&socket);
        let data_root_arg = mvp_s4_path_arg(&data_root);
        let input_arg = mvp_s4_path_arg(&input_path);

        let mut daemon =
            s65_spawn_rf_daemon_with_env(&rf_binary, &socket_arg, &data_root_arg, &stack.sdk_env)?;

        let flow = async {
            mvp_s4_wait_for_socket(&socket).await?;
            mvp_s10_create_rf_account(
                &rf_binary,
                &socket_arg,
                "owner_s65b_account",
                "principal_s65b_owner",
                "owner_device_s65b",
                "target_s65b_owner",
                S65_GATEWAY_B_QUIC,
                &ca_cert_arg,
                "50",
                "51",
            )
            .await?;

            // Reset the relay capture immediately before the reject attempt so any put_chunk the relay
            // received would be visible.
            s65_reset_capture(project, capture_path)?;

            // 1 MiB one-shot PUT: rejected client-side BEFORE the write (frame too large).
            let error_text = mvp_s4_rf_failure(
                &rf_binary,
                &[
                    "--socket",
                    &socket_arg,
                    "object",
                    "put",
                    "--account",
                    "owner_s65b_account",
                    "--object",
                    "object_s65b_reject",
                    "--chunk-size",
                    "32768",
                    "--relay-url",
                    &relay_url,
                    &input_arg,
                ],
            )
            .await?;
            assert!(
                error_text.contains("frame too large"),
                "1 MiB PUT must be rejected with a frame-too-large error, got: {error_text}"
            );
            eprintln!("s65b: 1 MiB PUT rejected client-side: {}", error_text.trim());

            // Object ABSENT from the local store (the request never reached dispatch).
            let list = mvp_s4_rf_json(
                &rf_binary,
                &["--socket", &socket_arg, "object", "list", "--account", "owner_s65b_account"],
            )
            .await?;
            let objects = list["objects"].as_array().ok_or("object list missing objects array")?;
            let present = objects
                .iter()
                .any(|object| object["object_id"] == "object_s65b_reject");
            assert!(
                !present,
                "rejected object must be ABSENT from the local store; object list = {list}"
            );
            eprintln!("s65b: rejected object absent from local store (object list len={})", objects.len());

            // Object GET must fail (absent), never silently return stale plaintext.
            let get_failure = mvp_s4_rf_failure(
                &rf_binary,
                &[
                    "--socket",
                    &socket_arg,
                    "object",
                    "get",
                    "--account",
                    "owner_s65b_account",
                    "--object",
                    "object_s65b_reject",
                    "--relay-url",
                    &relay_url,
                    &mvp_s4_path_arg(&temp_root.join("should-not-exist.bin")),
                ],
            )
            .await?;
            assert!(!get_failure.is_empty(), "get of a rejected object must fail");
            Ok::<(), Box<dyn std::error::Error>>(())
        };

        let result = tokio::time::timeout(Duration::from_mins(6), flow)
            .await
            .map_err(|_elapsed| "s65b 1 MiB reject flow timed out".to_owned());
        mvp_s20_stop_rf_daemon(&mut daemon).await?;
        let _ = std::fs::remove_file(&socket);
        std::fs::remove_dir_all(&temp_root).ok();
        result??;

        // Relay capture: ZERO put_chunk (zero relay mutation) for the rejected object.
        let capture = s65_read_capture(project, capture_path)?;
        let put_chunks: Vec<&S65CaptureLine> =
            capture.iter().filter(|line| line.route.ends_with("/put_chunk")).collect();
        assert!(
            put_chunks.is_empty(),
            "relay must show ZERO put_chunk for the rejected object; capture put_chunk lines = {put_chunks:?}"
        );
        eprintln!(
            "s65b: relay capture shows zero put_chunk (total capture lines after reset = {})",
            capture.len()
        );
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;

    let relay_logs = s65_container_logs(project, "ramflux-relay");
    assert!(
        !relay_logs.contains("object_s65b_reject"),
        "relay logs must not reference the rejected object (zero relay mutation):\n{relay_logs}"
    );

    std::fs::remove_dir_all(&stack.materials).ok();
    Ok(())
}

// ---- shared setup / helpers ----

#[cfg(feature = "realnet")]
fn s65_realnet_enabled() -> bool {
    std::env::var("RAMFLUX_ITEST_REALNET").as_deref() == Ok("1")
        && std::env::var("RAMFLUX_OBJECT_V3").as_deref() == Ok("1")
        && std::env::var("RAMFLUX_CROSS_GATEWAY").as_deref() == Ok("1")
}

#[cfg(feature = "realnet")]
fn s65_deterministic_bytes(len: usize) -> Vec<u8> {
    // A non-repeating-enough deterministic pattern so a truncated/garbled roundtrip is caught.
    (0..len).map(|index| u8::try_from((index * 31 + 7) % 251).unwrap_or(0)).collect()
}

#[cfg(feature = "realnet")]
struct S65Stack {
    materials: PathBuf,
    relay_ca: PathBuf,
    sdk_env: Vec<(String, String)>,
    _node: S8RealnetNode,
}

/// Brings up the object-v3 stack for a T25-A1 gate (trust material identical in shape to s55/s62)
/// and returns the SDK relay-QUIC + owner-lineage env for the rf daemon. `capture_file`, when set,
/// points the relay's per-client-QUIC-request fingerprint capture at a known path (Gate 2).
#[cfg(feature = "realnet")]
fn s65_start_stack(
    project: &str,
    materials_label: &str,
    ports: S8ComposePorts,
    owner_principal: &str,
    capture_file: Option<&str>,
) -> Result<S65Stack, Box<dyn std::error::Error>> {
    let materials = temp_root(materials_label)?;
    let now = ramflux_node_core::now_unix_seconds();
    let root_seed = [0x44; 32];
    let attestation_seed = [0x33; 32];
    let provider_seed = [0x66; 32];
    let offline_root_seed = [0x88; 32];
    let gateway_id = "gw-b";
    let certificate =
        s65_certificate(now, S65_ISSUER_NODE, gateway_id, root_seed, attestation_seed)?;
    let envelope =
        s65_trust_envelope(now, S65_ISSUER_NODE, root_seed, provider_seed, &certificate)?;
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
    s65_write_provider_keyring(&materials, now, S65_ISSUER_NODE, offline_root_seed, provider_seed)?;

    let mut env = vec![
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
        ("RAMFLUX_V3_FEDERATION_TRUST_ISSUER_NODE_ID".to_owned(), S65_ISSUER_NODE.to_owned()),
        ("RAMFLUX_V3_FEDERATION_TRUST_ENDPOINT".to_owned(), "ramflux-federation:7443".to_owned()),
    ];
    if let Some(path) = capture_file {
        env.push(("RAMFLUX_RELAY_ITEST_CAPTURE_FILE".to_owned(), path.to_owned()));
    }

    let node = start_s8_realnet_compose_project_with_env(project, ports, &env)?;
    let relay_ca = node.ca_cert.clone();
    let sdk_env = vec![
        ("RAMFLUX_SDK_RELAY_QUIC_ADDR".to_owned(), S65_RELAY_QUIC.to_owned()),
        ("RAMFLUX_SDK_RELAY_QUIC_SERVER_NAME".to_owned(), "ramflux-relay".to_owned()),
        ("RAMFLUX_SDK_RELAY_QUIC_CA_CERT".to_owned(), relay_ca.to_string_lossy().into_owned()),
        ("RAMFLUX_SDK_RELAY_OWNER_HOME_NODE_ID".to_owned(), S65_ISSUER_NODE.to_owned()),
        ("RAMFLUX_SDK_RELAY_OWNER_PRINCIPAL_ID".to_owned(), owner_principal.to_owned()),
        ("RAMFLUX_SDK_RELAY_AUDIENCE_NODE_ID".to_owned(), S65_AUDIENCE_NODE.to_owned()),
    ];
    Ok(S65Stack { materials, relay_ca, sdk_env, _node: node })
}

#[cfg(feature = "realnet")]
fn s65_spawn_rf_daemon_with_env(
    rf_binary: &Path,
    socket: &str,
    data_root: &str,
    env: &[(String, String)],
) -> Result<tokio::process::Child, Box<dyn std::error::Error>> {
    let child = tokio::process::Command::new(rf_binary)
        .args(["--socket", socket, "daemon", "start", "--data-root", data_root])
        .envs(env.iter().map(|(key, value)| (key.clone(), value.clone())))
        // GatewayIssued is the production path under test; never let LocalMint be selected.
        .env_remove("RAMFLUX_SDK_OBJECT_RELAY_LOCAL_MINT")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    Ok(child)
}

#[cfg(feature = "realnet")]
async fn s65_object_status(
    rf_binary: &Path,
    socket_arg: &str,
    account: &str,
    object_id: &str,
    direction: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    mvp_s4_rf_json(
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
            direction,
        ],
    )
    .await
}

#[cfg(feature = "realnet")]
async fn s65_wait_relay_quic_healthy(ca_cert: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let config =
        ramflux_transport::RelayClientQuicConfig::new(S65_RELAY_QUIC, "ramflux-relay", ca_cert)?;
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

#[cfg(feature = "realnet")]
fn s65_container(project: &str, service: &str) -> String {
    format!("{project}_{service}_1")
}

#[cfg(feature = "realnet")]
fn s65_reset_capture(project: &str, capture_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let container = s65_container(project, "ramflux-relay");
    let output = std::process::Command::new(container_runtime())
        .args(["exec", &container, "rm", "-f", capture_path])
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
fn s65_read_capture(
    project: &str,
    capture_path: &str,
) -> Result<Vec<S65CaptureLine>, Box<dyn std::error::Error>> {
    let container = s65_container(project, "ramflux-relay");
    let output = std::process::Command::new(container_runtime())
        .args(["exec", &container, "sh", "-c", &format!("cat {capture_path} 2>/dev/null || true")])
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "capture read failed (podman exec cat {capture_path}): {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut lines = Vec::new();
    for raw in text.lines().filter(|line| !line.trim().is_empty()) {
        lines.push(serde_json::from_str::<S65CaptureLine>(raw)?);
    }
    Ok(lines)
}

#[cfg(feature = "realnet")]
fn s65_container_logs(project: &str, service: &str) -> String {
    let container = s65_container(project, service);
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

// ---- v3 trust material (object-v3 stack; same shape as s55/s62) ----

#[cfg(feature = "realnet")]
fn s65_certificate(
    now: u64,
    node_id: &str,
    gateway_instance_id: &str,
    root_seed: [u8; 32],
    attestation_seed: [u8; 32],
) -> Result<ramflux_node_core::GatewayIssuerCertificate, Box<dyn std::error::Error>> {
    let mut certificate = ramflux_node_core::GatewayIssuerCertificate {
        schema: ramflux_node_core::GATEWAY_ISSUER_CERTIFICATE_SCHEMA.to_owned(),
        version: ramflux_node_core::OBJECT_RELAY_V3_PROOF_VERSION,
        cert_id: "s65-gw-b-cert-1".to_owned(),
        node_id: node_id.to_owned(),
        gateway_instance_id: gateway_instance_id.to_owned(),
        attestation_public_key: ramflux_crypto::public_key_base64url_from_seed(attestation_seed),
        attestation_key_id: "s65-gw-b-attestation-1".to_owned(),
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
fn s65_trust_envelope(
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
        provider_signing_key_id: "s65-provider-1".to_owned(),
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
fn s65_write_provider_keyring(
    materials: &std::path::Path,
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
            key_id: "s65-provider-1".to_owned(),
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
