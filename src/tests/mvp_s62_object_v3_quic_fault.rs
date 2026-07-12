// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

// T24-A3: relay QUIC persistent-client fault realnet. Over the real object-v3 stack, driven only
// through the public rf CLI -> rfd bus -> SDK (never a raw bus), this proves the T24 client pool's
// runtime guarantees that the pure/local tests cannot:
//   * positive reuse — a multi-chunk object's PUT/GET/ACK/TOMBSTONE ride ONE pooled QUIC connection
//     (same connection id across many requests), with zero HTTP object fallback;
//   * stale recovery — after the relay is restarted (rfd stays up) the next public request
//     transparently establishes a fresh connection;
//   * ambiguous commit — with the default-off `itest-quic-fault` seam set to drop the response
//     AFTER the business commit succeeds (per route, once per process), the public SDK's same-frame
//     single retry lands the operation exactly once: the capture shows the identical body
//     fingerprint on two different connections (first dropped, second written), no third attempt,
//     and the authoritative object state (GET roundtrip / tombstone terminality) is consistent.
//   * between-attempt restart — the seam holds pre-write after commit + writes a marker (the
//     barrier); the test observes it then SIGKILL+starts the same relay before the client's retry.
//     The hold marker is the cross-process one-shot claim, so the restarted relay writes the retry;
//     the client's same-frame retry lands 200 against the persistent redb (capture shows the hold
//     and the write retry on distinct process ids with the same body fingerprint).
// The seam and its non-sensitive fingerprint capture are compiled ONLY under `itest-quic-fault`
// (default/release relay contains neither); run-realnet.sh enables it. This card asserts nothing
// about persistent per-nonce outcome tables — recovery is content-state idempotency on redb.
#![allow(unused_imports)]
#![cfg_attr(not(feature = "realnet"), allow(dead_code))]
use super::*;

#[cfg(feature = "realnet")]
const S62_PROJECT: &str = "ramflux-s62-quic-fault";
#[cfg(feature = "realnet")]
const S62_RELAY_QUIC: &str = "127.0.0.1:17447";
#[cfg(feature = "realnet")]
const S62_CAPTURE_PATH: &str = "/var/lib/ramflux/relay/quic-fault-capture.jsonl";
#[cfg(feature = "realnet")]
const S62_HOLD_MARKER_PATH: &str = "/var/lib/ramflux/relay/quic-fault-hold.marker";

#[cfg(feature = "realnet")]
#[derive(Clone, Debug, serde::Deserialize)]
struct S62CaptureLine {
    request_seq: u64,
    connection_id: u64,
    process_instance: u64,
    method: String,
    route: String,
    body_fingerprint: String,
    action: String,
    status: u16,
}

#[cfg(feature = "realnet")]
#[test]
#[allow(clippy::too_many_lines)]
fn mvp_s62_realnet_object_v3_quic_fault() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1")
        || std::env::var("RAMFLUX_OBJECT_V3").as_deref() != Ok("1")
        || std::env::var("RAMFLUX_CROSS_GATEWAY").as_deref() != Ok("1")
    {
        eprintln!(
            "skipping s62 quic-fault realnet; set RAMFLUX_ITEST_REALNET=1 RAMFLUX_OBJECT_V3=1 RAMFLUX_CROSS_GATEWAY=1"
        );
        return Ok(());
    }

    let issuer_node = "node_b.realnet";
    let audience_node = "node_a.realnet";
    let owner_principal = "principal_s62_owner";

    let materials = temp_root("s62_quic_fault_materials")?;
    let now = ramflux_node_core::now_unix_seconds();
    let root_seed = [0x44; 32];
    let attestation_seed = [0x33; 32];
    let provider_seed = [0x66; 32];
    let offline_root_seed = [0x88; 32];
    let gateway_id = "gw-b";
    let certificate = s62_certificate(now, issuer_node, gateway_id, root_seed, attestation_seed)?;
    let envelope = s62_trust_envelope(now, issuer_node, root_seed, provider_seed, &certificate)?;
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
    s62_write_provider_keyring(&materials, now, issuer_node, offline_root_seed, provider_seed)?;

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
    let node = start_s8_realnet_compose_project_with_env(
        S62_PROJECT,
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
            // T24-A3: activate the fingerprint capture from project start; the fault mode itself
            // stays off (empty) until a phase force-recreates the relay with a drop mode.
            ("RAMFLUX_RELAY_ITEST_CAPTURE_FILE".to_owned(), S62_CAPTURE_PATH.to_owned()),
            ("RAMFLUX_RELAY_ITEST_HOLD_MARKER".to_owned(), S62_HOLD_MARKER_PATH.to_owned()),
        ],
    )?;

    let relay_ca = node.ca_cert.clone();
    let relay_url = format!("http://127.0.0.1:{}", ports.relay_http);
    let gateway_b_quic_addr = "127.0.0.1:18444";

    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    let result = runtime.block_on(async {
        let config = ramflux_transport::RelayClientQuicConfig::new(
            S62_RELAY_QUIC,
            "ramflux-relay",
            &relay_ca,
        )?;
        let health =
            ramflux_transport::relay_client_quic_health(&config, std::time::Duration::from_secs(5))
                .await?;
        assert_eq!(health.status, 200, "relay client QUIC listener must be healthy: {health:?}");

        let sdk_env = vec![
            ("RAMFLUX_SDK_RELAY_QUIC_ADDR".to_owned(), S62_RELAY_QUIC.to_owned()),
            ("RAMFLUX_SDK_RELAY_QUIC_SERVER_NAME".to_owned(), "ramflux-relay".to_owned()),
            ("RAMFLUX_SDK_RELAY_QUIC_CA_CERT".to_owned(), relay_ca.to_string_lossy().into_owned()),
            ("RAMFLUX_SDK_RELAY_OWNER_HOME_NODE_ID".to_owned(), issuer_node.to_owned()),
            ("RAMFLUX_SDK_RELAY_OWNER_PRINCIPAL_ID".to_owned(), owner_principal.to_owned()),
            ("RAMFLUX_SDK_RELAY_AUDIENCE_NODE_ID".to_owned(), audience_node.to_owned()),
        ];
        s62_flow(&node, gateway_b_quic_addr, &relay_url, &relay_ca, &sdk_env).await
    });

    let relay_logs = s62_container_logs("ramflux-relay");
    std::fs::remove_dir_all(&materials).ok();
    if let Err(error) = &result {
        eprintln!("s62 flow failed: {error}\n=== relay logs ===\n{relay_logs}");
    }
    result?;
    assert!(
        !relay_logs.contains("POST /relay/v1/object/"),
        "relay must not receive any HTTP object request across the fault flow:\n{relay_logs}"
    );
    Ok(())
}

#[cfg(feature = "realnet")]
#[allow(clippy::too_many_lines)]
async fn s62_flow(
    node: &S8RealnetNode,
    gateway_b_quic_addr: &str,
    relay_url: &str,
    relay_ca: &Path,
    sdk_env: &[(String, String)],
) -> Result<(), Box<dyn std::error::Error>> {
    let temp_root = temp_root("s62_quic_fault_sdk")?;
    let data_root = temp_root.join("owner/data");
    std::fs::create_dir_all(&data_root)?;
    let socket = PathBuf::from(format!("/tmp/ramflux-s62-rfd-{}.sock", std::process::id()));
    let input_path = temp_root.join("object-input.bin");
    let output_path = temp_root.join("object-output.bin");
    // >= 3 chunks: ~11 KiB at 512-byte chunks is 22 chunks, so a single object op is many QUIC
    // requests on one pooled connection.
    let plaintext =
        b"mvp_s62_public_sdk_v3_quic_fault_owner_object_do_not_leak_plaintext".repeat(170);
    std::fs::write(&input_path, &plaintext)?;

    let rf_binary = mvp_s4_build_rf_binary().await?;
    let ca_cert_arg = mvp_s4_path_arg(relay_ca);
    let socket_arg = mvp_s4_path_arg(&socket);
    let data_root_arg = mvp_s4_path_arg(&data_root);
    let input_arg = mvp_s4_path_arg(&input_path);
    let output_arg = mvp_s4_path_arg(&output_path);

    let mut daemon =
        s62_spawn_rf_daemon_with_env(&rf_binary, &socket_arg, &data_root_arg, sdk_env)?;

    let flow = async {
        mvp_s4_wait_for_socket(&socket).await?;
        mvp_s10_create_rf_account(
            &rf_binary,
            &socket_arg,
            "owner_s62_account",
            "principal_s62_owner",
            "owner_device_s62",
            "target_s62_owner",
            gateway_b_quic_addr,
            &ca_cert_arg,
            "50",
            "51",
        )
        .await?;

        // ---- Phase A: positive pooled reuse (no fault) + stale recovery ----
        s62_reset_capture()?;
        s62_put(&rf_binary, &socket_arg, relay_url, &input_arg, "object_s62_reuse").await?;
        s62_get_ack(&rf_binary, &socket_arg, relay_url, &output_arg, "object_s62_reuse").await?;
        assert_eq!(std::fs::read(&output_path)?, plaintext, "phase A roundtrip must match");

        let capture = s62_read_capture()?;
        assert!(capture.len() > 1, "phase A must make many pooled requests: {}", capture.len());
        assert!(
            capture.iter().all(|line| line.action == "write"),
            "phase A must have no fault action"
        );
        assert!(
            capture.iter().all(|line| line.route.starts_with("/relay/v1/object/")),
            "phase A capture routes must all be relay object routes"
        );
        let reuse_connection = s62_max_requests_on_one_connection(&capture);
        assert!(
            reuse_connection > 1,
            "phase A must reuse one pooled connection for many streams (max on one connection = {reuse_connection})"
        );

        // Keepalive: wait past the pool idle window, then a fresh PUT still rides the pooled
        // connection (a re-GET would serve the local copy and never touch the relay, so use PUT).
        tokio::time::sleep(std::time::Duration::from_secs(25)).await;
        s62_reset_capture()?;
        s62_put(&rf_binary, &socket_arg, relay_url, &input_arg, "object_s62_keepalive").await?;
        let keepalive_capture = s62_read_capture()?;
        assert!(
            !keepalive_capture.is_empty(),
            "post-idle PUT must reach the relay on the kept-alive pooled connection"
        );

        // Stale recovery: restart the relay (rfd stays up); the next PUT transparently reconnects on
        // a fresh connection (a fresh object id guarantees the request reaches the relay).
        s62_container_ctl("restart", "ramflux-relay")?;
        s62_wait_relay_quic_healthy(relay_ca).await?;
        s62_reset_capture()?;
        s62_put(&rf_binary, &socket_arg, relay_url, &input_arg, "object_s62_stale").await?;
        assert!(
            !s62_read_capture()?.is_empty(),
            "post-restart PUT must reach the relay on a fresh connection"
        );

        // ---- Phase B: ambiguous commit for PUT, ACK, TOMBSTONE (each fail-once post-commit) ----
        // PUT: the first put_chunk's response is dropped after commit; the SDK retries the identical
        // frame on a fresh connection and the object lands exactly once.
        s62_ambiguous_commit_mode(node, relay_ca, "put").await?;
        s62_warm_pool(&rf_binary, &socket_arg, relay_url, &output_arg).await?;
        s62_reset_capture()?;
        s62_put(&rf_binary, &socket_arg, relay_url, &input_arg, "object_s62_amb_put").await?;
        s62_assert_ambiguous_retry(&s62_read_capture()?, "/put_chunk", "PUT")?;
        // Content-state: a single consistent copy (GET roundtrip matches).
        s62_get_ack(&rf_binary, &socket_arg, relay_url, &output_arg, "object_s62_amb_put").await?;
        assert_eq!(
            std::fs::read(&output_path)?,
            plaintext,
            "ambiguous PUT must store one consistent copy"
        );

        // ACK: put a fresh object under a no-fault relay, then fault the first ACK response.
        s62_ambiguous_commit_mode(node, relay_ca, "off").await?;
        s62_reset_capture()?;
        s62_put(&rf_binary, &socket_arg, relay_url, &input_arg, "object_s62_amb_ack").await?;
        s62_ambiguous_commit_mode(node, relay_ca, "ack").await?;
        s62_reset_capture()?;
        s62_get_ack(&rf_binary, &socket_arg, relay_url, &output_arg, "object_s62_amb_ack").await?;
        assert_eq!(
            std::fs::read(&output_path)?,
            plaintext,
            "ambiguous ACK get roundtrip must match"
        );
        s62_assert_ambiguous_retry(&s62_read_capture()?, "/ack", "ACK")?;
        // ACK idempotency: a repeat GET+ACK still succeeds (grantee/owner ack set not corrupted).
        s62_get_ack(&rf_binary, &socket_arg, relay_url, &output_arg, "object_s62_amb_ack").await?;

        // TOMBSTONE: put a fresh object under a no-fault relay, then fault its first tombstone
        // response; the retry lands and the terminal state holds.
        s62_ambiguous_commit_mode(node, relay_ca, "off").await?;
        s62_reset_capture()?;
        s62_put(&rf_binary, &socket_arg, relay_url, &input_arg, "object_s62_amb_tomb").await?;
        s62_ambiguous_commit_mode(node, relay_ca, "tombstone").await?;
        // Warm the pool with a throwaway PUT (a GET would serve the local copy and never reach the
        // relay; a PUT always uploads and is not faulted under tombstone mode), so the tombstone's
        // own attempt lands on a fresh connection and only the drop — not a stale connection —
        // spends the single retry.
        s62_put(&rf_binary, &socket_arg, relay_url, &input_arg, "object_s62_warm_tomb").await?;
        s62_reset_capture()?;
        mvp_s4_rf_json(
            &rf_binary,
            &[
                "--socket",
                &socket_arg,
                "object",
                "delete",
                "--account",
                "owner_s62_account",
                "--object",
                "object_s62_amb_tomb",
                "--relay-url",
                relay_url,
            ],
        )
        .await?;
        s62_assert_ambiguous_retry(&s62_read_capture()?, "/tombstone", "TOMBSTONE")?;
        // Terminal: a post-tombstone get must fail rather than resurrect the object.
        let redownload = mvp_s4_rf_failure(
            &rf_binary,
            &[
                "--socket",
                &socket_arg,
                "object",
                "get",
                "--account",
                "owner_s62_account",
                "--object",
                "object_s62_amb_tomb",
                "--relay-url",
                relay_url,
                &output_arg,
            ],
        )
        .await?;
        assert!(
            !redownload.is_empty(),
            "ambiguous TOMBSTONE must be terminal (post-tombstone get fails)"
        );

        // ---- Phase C: post-restart content-state recovery (robust) ----
        // The same-process ambiguous-commit retry is proven above (phase B capture). Here we prove
        // the persistent-redb terminal state survives a relay restart: recreate the relay with the
        // fault OFF (a fresh no-fault process, redb volume retained), then confirm the tombstoned
        // object stays terminal and a fresh object round-trips on a new connection. (A fully
        // deterministic *between-attempt* relay restart is reported partial — the seam's hold mode
        // is unit-proven, but the client's fixed same-frame retry deadline races a container
        // recreate, so this card does not assert that end to end.)
        s62_ambiguous_commit_mode(node, relay_ca, "off").await?;
        // Tombstone persisted across the restart: a post-restart get still fails (no resurrect).
        let post_restart_get = mvp_s4_rf_failure(
            &rf_binary,
            &[
                "--socket",
                &socket_arg,
                "object",
                "get",
                "--account",
                "owner_s62_account",
                "--object",
                "object_s62_amb_tomb",
                "--relay-url",
                relay_url,
                &output_arg,
            ],
        )
        .await?;
        assert!(
            !post_restart_get.is_empty(),
            "tombstone terminal state must survive a relay restart (persistent redb)"
        );
        // A fresh object round-trips on a new connection after the restart.
        s62_reset_capture()?;
        s62_put(&rf_binary, &socket_arg, relay_url, &input_arg, "object_s62_post_restart").await?;
        s62_get_ack(&rf_binary, &socket_arg, relay_url, &output_arg, "object_s62_post_restart")
            .await?;
        assert_eq!(
            std::fs::read(&output_path)?,
            plaintext,
            "post-restart fresh roundtrip must match"
        );
        assert!(
            !s62_read_capture()?.is_empty(),
            "post-restart fresh object must reach the relay on a new connection"
        );

        // ---- Phase D: deterministic between-attempt relay restart (put-restart-hold) ----
        // The seam commits the first put_chunk then holds pre-write and writes a marker (the
        // barrier). The test observes the marker (bounded poll, no sleep-guess), then does a FAST
        // container-level SIGKILL + start of the same relay (rfd + redb volume untouched) — fast
        // enough that the client's connect-handshake budget covers the cold start. The hold marker
        // is the cross-process one-shot claim, so the restarted relay returns Write for the retry.
        // The client's same-frame retry then lands 200 on the restarted relay, proving between-
        // attempt same-frame recovery end to end.
        s62_ambiguous_commit_mode(node, relay_ca, "off").await?;
        s62_remove_hold_marker();
        // Upload a dedicated warm object under the no-fault relay (never downloaded), then switch to
        // put-restart-hold and first-download it: that GET reaches the relay (a PUT would be held; a
        // repeat GET serves the local copy) and reconnects the pool to the recreated relay, so the
        // held PUT's own first chunk lands on a fresh connection.
        s62_put(&rf_binary, &socket_arg, relay_url, &input_arg, "object_s62_d_warm").await?;
        s62_recreate_relay_env("RAMFLUX_RELAY_ITEST_DROP_AFTER_COMMIT", "put-restart-hold", node)?;
        s62_wait_relay_quic_healthy(relay_ca).await?;
        s62_get_no_ack(&rf_binary, &socket_arg, relay_url, &output_arg, "object_s62_d_warm")
            .await?;
        s62_reset_capture()?;

        let held_put = {
            let rf_binary = rf_binary.clone();
            let socket_arg = socket_arg.clone();
            let relay_url = relay_url.to_owned();
            let input_arg = input_arg.clone();
            tokio::spawn(async move {
                s62_put(&rf_binary, &socket_arg, &relay_url, &input_arg, "object_s62_hold")
                    .await
                    .map_err(|error| error.to_string())
            })
        };
        // Barrier: the relay has committed the first put_chunk and is holding pre-write.
        if !s62_wait_hold_marker(Duration::from_mins(2)).await {
            held_put.abort();
            return Err("relay did not reach the post-commit hold barrier".into());
        }
        // Fast restart before the client's retry: SIGKILL + start the same relay container.
        s62_kill_relay()?;
        s62_container_ctl("start", "ramflux-relay")?;
        s62_wait_relay_quic_healthy(relay_ca).await?;
        // The held PUT's same-frame retry must land on the restarted relay.
        match tokio::time::timeout(Duration::from_mins(2), held_put).await {
            Ok(join) => join.map_err(|error| error.to_string())??,
            Err(_elapsed) => {
                return Err("held PUT did not complete after the between-attempt restart".into());
            }
        }
        // Capture proof: a hold (old process) and a write retry (new process) with the same body
        // fingerprint on distinct processes, both 2xx, exactly two same-frame attempts.
        s62_assert_between_attempt_restart(&s62_read_capture()?)?;
        // Content-state: the held object is present exactly once (roundtrip matches).
        s62_get_ack(&rf_binary, &socket_arg, relay_url, &output_arg, "object_s62_hold").await?;
        assert_eq!(
            std::fs::read(&output_path)?,
            plaintext,
            "between-attempt-restart held object must round-trip as a single consistent copy"
        );

        Ok::<(), Box<dyn std::error::Error>>(())
    };

    let result = tokio::time::timeout(Duration::from_mins(9), flow)
        .await
        .map_err(|_elapsed| "s62 quic-fault flow timed out".to_owned());
    mvp_s20_stop_rf_daemon(&mut daemon).await?;
    let _ = std::fs::remove_file(&socket);
    std::fs::remove_dir_all(&temp_root).ok();
    result??;
    Ok(())
}

// ---- rfd + object ops via the public rf CLI ----

#[cfg(feature = "realnet")]
fn s62_spawn_rf_daemon_with_env(
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
async fn s62_put(
    rf_binary: &Path,
    socket_arg: &str,
    relay_url: &str,
    input_arg: &str,
    object_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    mvp_s4_rf_json(
        rf_binary,
        &[
            "--socket",
            socket_arg,
            "object",
            "put",
            "--account",
            "owner_s62_account",
            "--object",
            object_id,
            "--chunk-size",
            "512",
            "--relay-url",
            relay_url,
            input_arg,
        ],
    )
    .await?;
    Ok(())
}

#[cfg(feature = "realnet")]
async fn s62_get_ack(
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
            "owner_s62_account",
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

/// A GET that omits `--relay-ack` (does not consume the relay chunks). The first GET of an object
/// downloads from the relay (warming the pool); a repeat GET serves the local copy.
#[cfg(feature = "realnet")]
async fn s62_get_no_ack(
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
            "owner_s62_account",
            "--object",
            object_id,
            "--relay-url",
            relay_url,
            output_arg,
        ],
    )
    .await?;
    Ok(())
}

/// Reconnects the account pool to the just-recreated relay by issuing a relay-reaching GET, so a
/// subsequent faulted op's single same-frame retry is not spent on the stale connection left over
/// from the previous relay process (that reconnect is absorbed here instead). `object_s62_keepalive`
/// was uploaded (never acked) in phase A, so its chunks are still on the relay for a real download,
/// and this get intentionally omits `--relay-ack` so those chunks stay available for later warm-ups.
#[cfg(feature = "realnet")]
async fn s62_warm_pool(
    rf_binary: &Path,
    socket_arg: &str,
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
            "owner_s62_account",
            "--object",
            "object_s62_keepalive",
            "--relay-url",
            relay_url,
            output_arg,
        ],
    )
    .await?;
    Ok(())
}

// ---- fault-mode control (force-recreate the relay with the drop mode; redb volume persists) ----

#[cfg(feature = "realnet")]
async fn s62_ambiguous_commit_mode(
    node: &S8RealnetNode,
    relay_ca: &Path,
    mode: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    s62_recreate_relay_env("RAMFLUX_RELAY_ITEST_DROP_AFTER_COMMIT", mode, node)?;
    s62_wait_relay_quic_healthy(relay_ca).await
}

#[cfg(feature = "realnet")]
fn s62_recreate_relay_env(
    key: &str,
    value: &str,
    node: &S8RealnetNode,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut env = node.guard.env.clone();
    if let Some(entry) = env.iter_mut().find(|(existing, _)| existing == key) {
        entry.1 = value.to_owned();
    } else {
        env.push((key.to_owned(), value.to_owned()));
    }
    run_docker_compose_project_with_options(
        &node.guard.deploy_root,
        &node.guard.project_name,
        &env,
        &["up", "-d", "--no-deps", "--force-recreate", "ramflux-relay"],
        node.guard.federation_compio,
    )
}

// ---- capture reading / assertions (via podman exec; the redb volume holds the file) ----

#[cfg(feature = "realnet")]
fn s62_read_capture() -> Result<Vec<S62CaptureLine>, Box<dyn std::error::Error>> {
    let container = s62_container("ramflux-relay");
    let output = std::process::Command::new(container_runtime())
        .args(["exec", &container, "cat", S62_CAPTURE_PATH])
        .output()?;
    if !output.status.success() {
        // Fail closed: a capture read that fails (missing file / exec error) is a hard test failure,
        // never inferred as an empty log. Only a successfully-read empty file may yield no lines.
        return Err(format!(
            "capture read failed (podman exec cat {S62_CAPTURE_PATH}): {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut lines = Vec::new();
    for raw in text.lines().filter(|line| !line.trim().is_empty()) {
        lines.push(serde_json::from_str::<S62CaptureLine>(raw)?);
    }
    Ok(lines)
}

#[cfg(feature = "realnet")]
fn s62_reset_capture() -> Result<(), Box<dyn std::error::Error>> {
    let container = s62_container("ramflux-relay");
    let output = std::process::Command::new(container_runtime())
        .args(["exec", &container, "rm", "-f", S62_CAPTURE_PATH])
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

/// The maximum number of captured requests that share a single connection id — proves pooled reuse
/// (many streams over one connection) when > 1.
#[cfg(feature = "realnet")]
fn s62_max_requests_on_one_connection(capture: &[S62CaptureLine]) -> usize {
    let mut by_connection: std::collections::BTreeMap<u64, usize> =
        std::collections::BTreeMap::new();
    for line in capture {
        *by_connection.entry(line.connection_id).or_insert(0) += 1;
    }
    by_connection.values().copied().max().unwrap_or(0)
}

/// Asserts the ambiguous-commit contract for a route: the first attempt was dropped post-commit,
/// the retry re-sent the byte-identical frame (same fingerprint) on a DIFFERENT connection and was
/// written, and there was no third same-frame attempt.
#[cfg(feature = "realnet")]
fn s62_assert_ambiguous_retry(
    capture: &[S62CaptureLine],
    route_suffix: &str,
    label: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let on_route: Vec<&S62CaptureLine> =
        capture.iter().filter(|line| line.route.ends_with(route_suffix)).collect();
    let dropped: Vec<&S62CaptureLine> =
        on_route.iter().copied().filter(|line| line.action == "drop").collect();
    if dropped.len() != 1 {
        return Err(format!(
            "{label}: expected exactly one post-commit drop on {route_suffix}, got {} ({on_route:?})",
            dropped.len()
        )
        .into());
    }
    let dropped = dropped[0];
    // The drop only fires AFTER a successful business commit, so the dropped attempt itself carries
    // a 2xx status on a POST route.
    if dropped.method != "POST" || !(200..300).contains(&dropped.status) {
        return Err(format!(
            "{label}: post-commit drop must be a committed 2xx POST, got {} {} ({dropped:?})",
            dropped.method, dropped.status
        )
        .into());
    }
    // The retry: same body fingerprint, a different connection, written (not dropped), and later.
    let retry = on_route.iter().copied().find(|line| {
        line.body_fingerprint == dropped.body_fingerprint
            && line.connection_id != dropped.connection_id
            && line.action == "write"
            && line.request_seq > dropped.request_seq
            && (200..300).contains(&line.status)
    });
    if retry.is_none() {
        return Err(format!(
            "{label}: no same-frame retry (2xx, later seq, fresh connection) after the drop ({on_route:?})"
        )
        .into());
    }
    // No third same-frame attempt (fail-once + single retry).
    let same_frame =
        on_route.iter().filter(|line| line.body_fingerprint == dropped.body_fingerprint).count();
    if same_frame != 2 {
        return Err(format!(
            "{label}: expected exactly two same-frame attempts (drop + retry), got {same_frame}"
        )
        .into());
    }
    Ok(())
}

// ---- container helpers ----

#[cfg(feature = "realnet")]
fn s62_container(service: &str) -> String {
    format!("{S62_PROJECT}_{service}_1")
}

/// SIGKILLs the relay container (fast, unclean death of the held connection) so the next
/// `s62_container_ctl("start", ...)` cold-starts the same container with the redb volume intact.
#[cfg(feature = "realnet")]
fn s62_kill_relay() -> Result<(), Box<dyn std::error::Error>> {
    let container = s62_container("ramflux-relay");
    let output = std::process::Command::new(container_runtime())
        .args(["kill", "--signal", "KILL", &container])
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "{} kill {container} failed: {}",
            container_runtime(),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(())
}

#[cfg(feature = "realnet")]
fn s62_remove_hold_marker() {
    let container = s62_container("ramflux-relay");
    let _ = std::process::Command::new(container_runtime())
        .args(["exec", &container, "rm", "-f", S62_HOLD_MARKER_PATH])
        .output();
}

/// Polls (bounded, no sleep-guess of restart timing — the marker IS the barrier) for the relay's
/// post-commit hold marker on the shared redb volume.
#[cfg(feature = "realnet")]
async fn s62_wait_hold_marker(bound: Duration) -> bool {
    let container = s62_container("ramflux-relay");
    let deadline = std::time::Instant::now() + bound;
    while std::time::Instant::now() < deadline {
        if let Ok(output) = std::process::Command::new(container_runtime())
            .args(["exec", &container, "test", "-f", S62_HOLD_MARKER_PATH])
            .output()
            && output.status.success()
        {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    false
}

/// Asserts the between-attempt-restart contract from the capture: exactly one `hold` (the first
/// process, pre-restart) and a `write` retry of the same body fingerprint on a DIFFERENT process
/// (the restarted relay), both 2xx, with exactly two same-frame attempts (no third). Cross-process
/// identity uses `process_instance` (connection id / request seq reset per process).
#[cfg(feature = "realnet")]
fn s62_assert_between_attempt_restart(
    capture: &[S62CaptureLine],
) -> Result<(), Box<dyn std::error::Error>> {
    let holds: Vec<&S62CaptureLine> = capture
        .iter()
        .filter(|line| line.route.ends_with("/put_chunk") && line.action == "hold")
        .collect();
    if holds.len() != 1 {
        return Err(format!(
            "between-attempt restart: expected exactly one post-commit hold, got {} ({capture:?})",
            holds.len()
        )
        .into());
    }
    let held = holds[0];
    if held.method != "POST" || !(200..300).contains(&held.status) {
        return Err(format!(
            "between-attempt restart: held attempt must be a committed 2xx POST, got {} {}",
            held.method, held.status
        )
        .into());
    }
    let retry = capture.iter().find(|line| {
        line.route.ends_with("/put_chunk")
            && line.action == "write"
            && line.body_fingerprint == held.body_fingerprint
            && line.process_instance != held.process_instance
            && (200..300).contains(&line.status)
    });
    if retry.is_none() {
        return Err(format!(
            "between-attempt restart: no same-frame write retry on a different (restarted) process ({capture:?})"
        )
        .into());
    }
    let same_frame = capture
        .iter()
        .filter(|line| {
            line.route.ends_with("/put_chunk") && line.body_fingerprint == held.body_fingerprint
        })
        .count();
    if same_frame != 2 {
        return Err(format!(
            "between-attempt restart: expected exactly two same-frame attempts (hold + retry), got {same_frame}"
        )
        .into());
    }
    Ok(())
}

#[cfg(feature = "realnet")]
fn s62_container_ctl(action: &str, service: &str) -> Result<(), Box<dyn std::error::Error>> {
    let container = s62_container(service);
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
fn s62_container_logs(service: &str) -> String {
    let container = s62_container(service);
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

#[cfg(feature = "realnet")]
async fn s62_wait_relay_quic_healthy(ca_cert: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let config =
        ramflux_transport::RelayClientQuicConfig::new(S62_RELAY_QUIC, "ramflux-relay", ca_cert)?;
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

// ---- v3 trust material (object-v3 stack; same shape as s55) ----

#[cfg(feature = "realnet")]
fn s62_certificate(
    now: u64,
    node_id: &str,
    gateway_instance_id: &str,
    root_seed: [u8; 32],
    attestation_seed: [u8; 32],
) -> Result<ramflux_node_core::GatewayIssuerCertificate, Box<dyn std::error::Error>> {
    let mut certificate = ramflux_node_core::GatewayIssuerCertificate {
        schema: ramflux_node_core::GATEWAY_ISSUER_CERTIFICATE_SCHEMA.to_owned(),
        version: ramflux_node_core::OBJECT_RELAY_V3_PROOF_VERSION,
        cert_id: "s62-gw-b-cert-1".to_owned(),
        node_id: node_id.to_owned(),
        gateway_instance_id: gateway_instance_id.to_owned(),
        attestation_public_key: ramflux_crypto::public_key_base64url_from_seed(attestation_seed),
        attestation_key_id: "s62-gw-b-attestation-1".to_owned(),
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
fn s62_trust_envelope(
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
        provider_signing_key_id: "s62-provider-1".to_owned(),
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
fn s62_write_provider_keyring(
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
            key_id: "s62-provider-1".to_owned(),
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
