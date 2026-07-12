// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! T24-B2 realnet: rfd mid-flight SIGKILL crash-resume.
//!
//! Real `rf daemon start` (built with `itest-rfd-fault`) is crashed with SIGKILL at a
//! post-local-commit / pre-remote barrier, then restarted from the same `data_root` with the fault
//! off. Asserts the public SDK operation resumes correctly and durable state neither regresses nor
//! double-applies. Mode 3 (grantee-import: object + transfer durable, crash before relay ACK) is the
//! safety-critical anchor; Mode 1 (dm-send: send ratchet durable, crash before submit) proves no
//! nonce reuse. Modes 2/4 evidence + gaps are reported in the T24-B2 report.

#![allow(unused_imports)]
#![cfg_attr(not(feature = "realnet"), allow(dead_code))]
use super::*;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[cfg(feature = "realnet")]
#[test]
#[allow(clippy::too_many_lines)]
fn mvp_s63_realnet_object_v3_rfd_midflight_crash() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1")
        || std::env::var("RAMFLUX_OBJECT_V3").as_deref() != Ok("1")
        || std::env::var("RAMFLUX_CROSS_GATEWAY").as_deref() != Ok("1")
    {
        eprintln!(
            "skipping s63 rfd midflight crash realnet; set RAMFLUX_ITEST_REALNET=1 RAMFLUX_OBJECT_V3=1 RAMFLUX_CROSS_GATEWAY=1"
        );
        return Ok(());
    }

    let issuer_node = "node_b.realnet";
    let audience_node = "node_a.realnet";
    let alice_principal = "principal_s63_alice";
    let project = "ramflux-s63-rfd-crash";

    let materials = temp_root("s63_object_v3_materials")?;
    let now = ramflux_node_core::now_unix_seconds();
    let root_seed = [0x44; 32];
    let attestation_seed = [0x33; 32];
    let provider_seed = [0x66; 32];
    let offline_root_seed = [0x88; 32];
    let certificate = s63_certificate(now, issuer_node, "gw-b", root_seed, attestation_seed)?;
    let envelope = s63_trust_envelope(now, issuer_node, root_seed, provider_seed, &certificate)?;
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
    s63_write_provider_keyring(&materials, now, issuer_node, offline_root_seed, provider_seed)?;

    let ports = S8ComposePorts {
        gateway_http: 64_281,
        gateway_quic: 64_551,
        router_http: 64_280,
        router_mesh: 64_552,
        notify_http: 64_283,
        federation_http: 64_282,
        federation_mesh: 64_553,
        relay_http: 64_284,
        relay_media_udp: 64_250,
        signaling_turn_udp: 64_578,
        signaling_turn_tcp: 64_579,
        retention_http: 64_287,
    };
    let node = start_s8_realnet_compose_project_with_env(
        project,
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
            // REQUIRED: run-realnet builds the relay with `itest-quic-fault`, whose per-request
            // capture is fail-closed (CTRL-058). Without CAPTURE_FILE set the relay closes every
            // client QUIC connection (incl. health) -> "connection lost". Every object-v3 realnet
            // test must set this (s62 does the same).
            (
                "RAMFLUX_RELAY_ITEST_CAPTURE_FILE".to_owned(),
                "/var/lib/ramflux/relay/s63-capture.jsonl".to_owned(),
            ),
            (
                "RAMFLUX_RELAY_ITEST_HOLD_MARKER".to_owned(),
                "/var/lib/ramflux/relay/s63-hold.marker".to_owned(),
            ),
        ],
    )?;

    let relay_ca = node.ca_cert.clone();
    let relay_quic_addr = "127.0.0.1:17447";
    let gateway_b_quic_addr = "127.0.0.1:18444";
    let relay_url = format!("http://127.0.0.1:{}", ports.relay_http);
    let ca_cert_env = relay_ca.to_string_lossy().into_owned();

    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    let result = runtime.block_on(async {
        eprintln!("STEP s63: pre relay-quic health on {relay_quic_addr}");
        let config = ramflux_transport::RelayClientQuicConfig::new(
            relay_quic_addr,
            "ramflux-relay",
            &relay_ca,
        )?;
        // Relay QUIC may bind a moment after gateway/federation HTTP health; retry briefly.
        let mut health = None;
        for attempt in 0..30 {
            match ramflux_transport::relay_client_quic_health(
                &config,
                std::time::Duration::from_secs(5),
            )
            .await
            {
                Ok(value) => {
                    health = Some(value);
                    break;
                }
                Err(error) => {
                    eprintln!("STEP s63: relay health attempt {attempt} not ready: {error}");
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }
            }
        }
        let health = health.ok_or_else(|| {
            Box::<dyn std::error::Error>::from("relay client QUIC never became healthy")
        })?;
        assert_eq!(health.status, 200, "relay client QUIC listener must be healthy: {health:?}");
        eprintln!("STEP s63: relay health OK status={}", health.status);
        s63_flow(
            &node,
            gateway_b_quic_addr,
            relay_quic_addr,
            &relay_url,
            &ca_cert_env,
            issuer_node,
            audience_node,
            alice_principal,
        )
        .await
    });
    if let Err(error) = &result {
        eprintln!(
            "s63 flow failed: {error}\n=== relay logs ===\n{}",
            s63_container_logs("ramflux-relay")
        );
    }
    std::fs::remove_dir_all(&materials).ok();
    result
}

#[cfg(feature = "realnet")]
fn s63_container_logs(service: &str) -> String {
    let container = format!("ramflux-s63-rfd-crash_{service}_1");
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

/// Drives all four rfd mid-flight SIGKILL modes: 3 (grantee-import), 1 (dm-send), 2 (owner-put),
/// 4 (dm-recv), each with a real `child.kill()` at its post-local-commit / pre-remote barrier.
#[cfg(feature = "realnet")]
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
async fn s63_flow(
    node: &S8RealnetNode,
    gateway_b_quic_addr: &str,
    relay_quic_addr: &str,
    relay_url: &str,
    ca_cert_env: &str,
    issuer_node: &str,
    audience_node: &str,
    alice_principal: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let temp = temp_root("s63_rfd_crash")?;
    let alice_data = temp.join("alice/data");
    let bob_data = temp.join("bob/data");
    std::fs::create_dir_all(&alice_data)?;
    std::fs::create_dir_all(&bob_data)?;
    let pid = std::process::id();
    let alice_socket = PathBuf::from(format!("/tmp/ramflux-s63-alice-{pid}.sock"));
    let bob_socket = PathBuf::from(format!("/tmp/ramflux-s63-bob-{pid}.sock"));
    let bob_fault_marker = format!("/tmp/ramflux-s63-bob-fault-{pid}.marker");
    let input_path = temp.join("s63-attachment-input.bin");
    // 54 bytes * 80 = 4320 bytes -> with 1024-byte chunks that is >= 3 chunks.
    let plaintext = b"mvp_s63_rfd_crash_object_do_not_leak_plaintext_padding".repeat(80);
    std::fs::write(&input_path, &plaintext)?;
    let _ = std::fs::remove_file(&bob_fault_marker);

    let alice_device_id = "alice_device_s63";
    let bob_device_id = "bob_device_s63";

    let alice_env = vec![
        ("RAMFLUX_SDK_RELAY_QUIC_ADDR".to_owned(), relay_quic_addr.to_owned()),
        ("RAMFLUX_SDK_RELAY_QUIC_SERVER_NAME".to_owned(), "ramflux-relay".to_owned()),
        ("RAMFLUX_SDK_RELAY_QUIC_CA_CERT".to_owned(), ca_cert_env.to_owned()),
        ("RAMFLUX_SDK_RELAY_OWNER_HOME_NODE_ID".to_owned(), issuer_node.to_owned()),
        ("RAMFLUX_SDK_RELAY_OWNER_PRINCIPAL_ID".to_owned(), alice_principal.to_owned()),
        ("RAMFLUX_SDK_RELAY_AUDIENCE_NODE_ID".to_owned(), audience_node.to_owned()),
    ];
    // Bob's daemon arms the grantee-import fault; it holds after object+transfer are durable and
    // before the relay ACK, then parks until this test SIGKILLs it.
    let bob_env_faulted = vec![
        ("RAMFLUX_SDK_RELAY_QUIC_ADDR".to_owned(), relay_quic_addr.to_owned()),
        ("RAMFLUX_SDK_RELAY_QUIC_SERVER_NAME".to_owned(), "ramflux-relay".to_owned()),
        ("RAMFLUX_SDK_RELAY_QUIC_CA_CERT".to_owned(), ca_cert_env.to_owned()),
        ("RAMFLUX_SDK_ITEST_RFD_FAULT_MODE".to_owned(), "grantee-import".to_owned()),
        ("RAMFLUX_SDK_ITEST_RFD_FAULT_MARKER".to_owned(), bob_fault_marker.clone()),
    ];
    let bob_env_faultoff = vec![
        ("RAMFLUX_SDK_RELAY_QUIC_ADDR".to_owned(), relay_quic_addr.to_owned()),
        ("RAMFLUX_SDK_RELAY_QUIC_SERVER_NAME".to_owned(), "ramflux-relay".to_owned()),
        ("RAMFLUX_SDK_RELAY_QUIC_CA_CERT".to_owned(), ca_cert_env.to_owned()),
    ];
    let alice_fault_marker = format!("/tmp/ramflux-s63-alice-fault-{pid}.marker");
    let _ = std::fs::remove_file(&alice_fault_marker);
    // Alice's owner-lineage env, plus a dm-send fault arming (used only for the Mode 1 phase, which
    // restarts Alice with this env). It holds after the send ratchet snapshot is durable and before
    // the gateway submit, then parks until SIGKILL.
    let alice_env_faulted = {
        let mut env = alice_env.clone();
        env.push(("RAMFLUX_SDK_ITEST_RFD_FAULT_MODE".to_owned(), "dm-send".to_owned()));
        env.push(("RAMFLUX_SDK_ITEST_RFD_FAULT_MARKER".to_owned(), alice_fault_marker.clone()));
        env
    };

    let rf_binary = s63_build_rf_binary().await?;
    let ca_cert_arg = mvp_s4_path_arg(&node.ca_cert);
    let alice_socket_arg = mvp_s4_path_arg(&alice_socket);
    let bob_socket_arg = mvp_s4_path_arg(&bob_socket);
    let alice_data_arg = mvp_s4_path_arg(&alice_data);
    let bob_data_arg = mvp_s4_path_arg(&bob_data);
    let input_arg = mvp_s4_path_arg(&input_path);

    let mut alice_daemon =
        s63_spawn_rf_daemon_with_env(&rf_binary, &alice_socket_arg, &alice_data_arg, &alice_env)?;
    let mut bob_daemon =
        s63_spawn_rf_daemon_with_env(&rf_binary, &bob_socket_arg, &bob_data_arg, &bob_env_faulted)?;
    mvp_s4_wait_for_socket(&alice_socket).await?;
    mvp_s4_wait_for_socket(&bob_socket).await?;

    let alice_commitment = mvp_s10_create_rf_account(
        &rf_binary,
        &alice_socket_arg,
        "alice_s63_account",
        alice_principal,
        alice_device_id,
        "target_s63_alice",
        gateway_b_quic_addr,
        &ca_cert_arg,
        "56",
        "57",
    )
    .await?;
    let bob_commitment = mvp_s10_create_rf_account(
        &rf_binary,
        &bob_socket_arg,
        "bob_s63_account",
        "principal_s63_bob",
        bob_device_id,
        "target_s63_bob",
        gateway_b_quic_addr,
        &ca_cert_arg,
        "58",
        "59",
    )
    .await?;
    s63_add_contact(
        &rf_binary,
        &alice_socket_arg,
        "alice_s63_account",
        "alice_to_bob_s63",
        &alice_commitment,
        &bob_commitment,
    )
    .await?;
    s63_add_contact(
        &rf_binary,
        &bob_socket_arg,
        "bob_s63_account",
        "bob_to_alice_s63",
        &bob_commitment,
        &alice_commitment,
    )
    .await?;

    // ---- Mode 3: grantee-import crash before relay ACK ----
    eprintln!("STEP s63: accounts+contacts done, alice dm send (attachment)");
    // Alice sends a multi-chunk attachment DM.
    mvp_s4_rf_json(
        &rf_binary,
        &[
            "--socket",
            &alice_socket_arg,
            "dm",
            "send",
            "--account",
            "alice_s63_account",
            "--conversation",
            "conv_s63_attachment",
            "--message",
            "msg_s63_attach",
            "--envelope",
            "env_s63_attach",
            "--source-principal",
            alice_principal,
            "--sender",
            alice_device_id,
            "--recipient-principal-commitment",
            &bob_commitment,
            "--recipient-device",
            bob_device_id,
            "--target",
            "target_s63_bob",
            "--body",
            "s63 attachment body",
            "--attach",
            &input_arg,
            "--relay-url",
            relay_url,
            "--attachment-chunk-size",
            "1024",
        ],
    )
    .await?;
    let object_id = "attachment:msg_s63_attach:0";
    eprintln!("STEP s63: alice dm send OK; spawning bob import (expect barrier hold)");

    // Bob imports (dm read) — the daemon holds at the pre-ACK barrier and parks. Run it in the
    // background so this test can observe the marker and SIGKILL the parked daemon.
    let read_rf = rf_binary.clone();
    let read_socket = bob_socket_arg.clone();
    let import_handle = tokio::spawn(async move {
        s63_run_rf_capture(
            &read_rf,
            &[
                "--socket",
                &read_socket,
                "dm",
                "read",
                "--account",
                "bob_s63_account",
                "--conversation",
                "conv_s63_attachment",
            ],
        )
        .await
    });

    eprintln!("STEP s63: waiting for bob fault marker");
    s63_wait_marker(Path::new(&bob_fault_marker)).await?;
    eprintln!("STEP s63: marker observed; SIGKILL bob rfd");
    // SIGKILL Bob's rfd mid-flight (object+transfer durable, before ACK / slot-checkpoint commit).
    mvp_s20_stop_rf_daemon(&mut bob_daemon).await?;
    let import_result = match import_handle.await? {
        Ok(value) => value,
        Err(error) => return Err(format!("s63 import task failed to run: {error}").into()),
    };
    assert!(
        !import_result.0,
        "mid-flight SIGKILL must fail the in-flight import CLI; got success: {}",
        import_result.1
    );

    // Bob dead: assert the slot recv checkpoint is NOT yet committed (barrier is before it), while
    // the object + transfer are already durable.
    let _ = std::fs::remove_file(&bob_socket);
    let fingerprint_before = s63_recv_fingerprint(&bob_data)?;
    assert!(
        fingerprint_before.slot_recv_checkpoint.is_none(),
        "slot recv checkpoint must not be committed before the ACK barrier: {fingerprint_before:?}"
    );

    eprintln!("STEP s63: import CLI failed as expected; restarting bob fault-off");
    // Restart Bob from the same data_root with the fault OFF, using the stronger status poll.
    bob_daemon = s63_spawn_rf_daemon_with_env(
        &rf_binary,
        &bob_socket_arg,
        &bob_data_arg,
        &bob_env_faultoff,
    )?;
    mvp_s20_wait_for_daemon_status(&rf_binary, &bob_socket_arg).await?;

    // Retry the import: it must succeed, the object must decrypt to the original plaintext.
    eprintln!("STEP s63: bob restarted; retry import");
    let imported = mvp_s4_rf_json(
        &rf_binary,
        &[
            "--socket",
            &bob_socket_arg,
            "dm",
            "read",
            "--account",
            "bob_s63_account",
            "--conversation",
            "conv_s63_attachment",
        ],
    )
    .await?;
    let decrypted = imported["decrypted_messages"]
        .as_array()
        .ok_or("missing decrypted_messages after restart")?;
    assert!(!decrypted.is_empty(), "Bob must decrypt the attachment DM after restart");

    // object status must show the download transfer converged to complete (durable single copy).
    let status = mvp_s4_rf_json(
        &rf_binary,
        &[
            "--socket",
            &bob_socket_arg,
            "object",
            "status",
            "--account",
            "bob_s63_account",
            "--object",
            object_id,
            "--direction",
            "download",
        ],
    )
    .await?;
    assert_eq!(status["transfer"]["state"], "complete", "download transfer must be complete");

    // Idempotent re-read: importing again must not double-advance the slot ratchet.
    let _ = mvp_s4_rf_json(
        &rf_binary,
        &[
            "--socket",
            &bob_socket_arg,
            "dm",
            "read",
            "--account",
            "bob_s63_account",
            "--conversation",
            "conv_s63_attachment",
        ],
    )
    .await?;

    // Fingerprint after success: the slot recv checkpoint must now be committed exactly once.
    mvp_s20_stop_rf_daemon(&mut bob_daemon).await?;
    let _ = std::fs::remove_file(&bob_socket);
    let fingerprint_after = s63_recv_fingerprint(&bob_data)?;
    assert!(
        fingerprint_after.slot_recv_checkpoint.is_some(),
        "slot recv checkpoint must be committed after a successful import retry: {fingerprint_after:?}"
    );
    bob_daemon = s63_spawn_rf_daemon_with_env(
        &rf_binary,
        &bob_socket_arg,
        &bob_data_arg,
        &bob_env_faultoff,
    )?;
    mvp_s20_wait_for_daemon_status(&rf_binary, &bob_socket_arg).await?;

    // ---- Mode 1: dm-send crash after send-ratchet persist, before gateway submit ----
    // First establish the conversation (Alice unarmed) so the held message that gets lost is a
    // regular ratchet message, not the X3DH bootstrap — losing the very first message is a separate
    // concern from the send-ratchet crash invariant this mode exercises.
    eprintln!("STEP s63 mode1: establish conv_s63_send session");
    mvp_s4_rf_json(
        &rf_binary,
        &[
            "--socket",
            &alice_socket_arg,
            "dm",
            "send",
            "--account",
            "alice_s63_account",
            "--conversation",
            "conv_s63_send",
            "--message",
            "msg_s63_send_init",
            "--envelope",
            "env_s63_send_init",
            "--source-principal",
            alice_principal,
            "--sender",
            "alice_device_s63",
            "--recipient-principal-commitment",
            &bob_commitment,
            "--recipient-device",
            "bob_device_s63",
            "--target",
            "target_s63_bob",
            "--body",
            "s63 init send body",
            "--relay-url",
            relay_url,
        ],
    )
    .await?;
    let init_read = mvp_s4_rf_json(
        &rf_binary,
        &[
            "--socket",
            &bob_socket_arg,
            "dm",
            "read",
            "--account",
            "bob_s63_account",
            "--conversation",
            "conv_s63_send",
        ],
    )
    .await?;
    assert!(
        init_read.to_string().contains("env_s63_send_init"),
        "Bob must receive the session-establishing message: {init_read}"
    );

    eprintln!("STEP s63 mode1: restart alice armed dm-send");
    mvp_s20_stop_rf_daemon(&mut alice_daemon).await?;
    let _ = std::fs::remove_file(&alice_socket);
    alice_daemon = s63_spawn_rf_daemon_with_env(
        &rf_binary,
        &alice_socket_arg,
        &alice_data_arg,
        &alice_env_faulted,
    )?;
    mvp_s20_wait_for_daemon_status(&rf_binary, &alice_socket_arg).await?;

    // Alice sends a plain DM; the daemon holds after persisting the advanced send ratchet and before
    // the gateway submit. Run in the background so this test can SIGKILL the parked daemon.
    let send_rf = rf_binary.clone();
    let send_socket = alice_socket_arg.clone();
    let send_principal = alice_principal.to_owned();
    let send_recipient = bob_commitment.clone();
    let send_relay = relay_url.to_owned();
    let send_handle = tokio::spawn(async move {
        s63_run_rf_capture(
            &send_rf,
            &[
                "--socket",
                &send_socket,
                "dm",
                "send",
                "--account",
                "alice_s63_account",
                "--conversation",
                "conv_s63_send",
                "--message",
                "msg_s63_send_held",
                "--envelope",
                "env_s63_send_held",
                "--source-principal",
                &send_principal,
                "--sender",
                "alice_device_s63",
                "--recipient-principal-commitment",
                &send_recipient,
                "--recipient-device",
                "bob_device_s63",
                "--target",
                "target_s63_bob",
                "--body",
                "s63 held send body",
                "--relay-url",
                &send_relay,
            ],
        )
        .await
    });
    eprintln!("STEP s63 mode1: waiting for alice fault marker");
    s63_wait_marker(Path::new(&alice_fault_marker)).await?;
    eprintln!("STEP s63 mode1: marker observed; SIGKILL alice rfd");
    mvp_s20_stop_rf_daemon(&mut alice_daemon).await?;
    let send_result = match send_handle.await? {
        Ok(value) => value,
        Err(error) => return Err(format!("s63 send task failed to run: {error}").into()),
    };
    assert!(
        !send_result.0,
        "mid-flight SIGKILL must fail the in-flight dm send CLI: {}",
        send_result.1
    );

    // Restart Alice fault-off and send a NEW message. Because the held send's advanced ratchet was
    // persisted before submit (CTRL-063), the restart resumes at the next counter — the held,
    // never-submitted message's key is burned, not reused. Bob must decrypt the NEW message and must
    // never receive the held (un-submitted) one.
    let _ = std::fs::remove_file(&alice_socket);
    alice_daemon =
        s63_spawn_rf_daemon_with_env(&rf_binary, &alice_socket_arg, &alice_data_arg, &alice_env)?;
    mvp_s20_wait_for_daemon_status(&rf_binary, &alice_socket_arg).await?;
    eprintln!("STEP s63 mode1: alice restarted fault-off; send new message");
    mvp_s4_rf_json(
        &rf_binary,
        &[
            "--socket",
            &alice_socket_arg,
            "dm",
            "send",
            "--account",
            "alice_s63_account",
            "--conversation",
            "conv_s63_send",
            "--message",
            "msg_s63_send_new",
            "--envelope",
            "env_s63_send_new",
            "--source-principal",
            alice_principal,
            "--sender",
            "alice_device_s63",
            "--recipient-principal-commitment",
            &bob_commitment,
            "--recipient-device",
            "bob_device_s63",
            "--target",
            "target_s63_bob",
            "--body",
            "s63 new send body",
            "--relay-url",
            relay_url,
        ],
    )
    .await?;
    let read = mvp_s4_rf_json(
        &rf_binary,
        &[
            "--socket",
            &bob_socket_arg,
            "dm",
            "read",
            "--account",
            "bob_s63_account",
            "--conversation",
            "conv_s63_send",
        ],
    )
    .await?;
    let read_str = read.to_string();
    assert!(
        read_str.contains("env_s63_send_new"),
        "Bob must receive the new post-restart message (send ratchet advanced cleanly): {read}"
    );
    assert!(
        !read_str.contains("env_s63_send_held"),
        "Bob must NEVER receive the held, un-submitted message: {read}"
    );

    // ---- Mode 2: owner-put crash after first chunk's local bitmap commit ----
    eprintln!("STEP s63 mode2: restart alice armed owner-put");
    mvp_s20_stop_rf_daemon(&mut alice_daemon).await?;
    let _ = std::fs::remove_file(&alice_socket);
    let _ = std::fs::remove_file(&alice_fault_marker);
    let alice_env_owner_put = {
        let mut env = alice_env.clone();
        env.push(("RAMFLUX_SDK_ITEST_RFD_FAULT_MODE".to_owned(), "owner-put".to_owned()));
        env.push(("RAMFLUX_SDK_ITEST_RFD_FAULT_MARKER".to_owned(), alice_fault_marker.clone()));
        env
    };
    alice_daemon = s63_spawn_rf_daemon_with_env(
        &rf_binary,
        &alice_socket_arg,
        &alice_data_arg,
        &alice_env_owner_put,
    )?;
    mvp_s20_wait_for_daemon_status(&rf_binary, &alice_socket_arg).await?;

    let put_rf = rf_binary.clone();
    let put_socket = alice_socket_arg.clone();
    let put_input = input_arg.clone();
    let put_relay = relay_url.to_owned();
    let put_handle = tokio::spawn(async move {
        s63_run_rf_capture(
            &put_rf,
            &[
                "--socket",
                &put_socket,
                "object",
                "put",
                "--account",
                "alice_s63_account",
                "--object",
                "object_s63_ownerput",
                "--chunk-size",
                "1024",
                "--relay-url",
                &put_relay,
                &put_input,
            ],
        )
        .await
    });
    eprintln!("STEP s63 mode2: waiting for alice owner-put marker");
    s63_wait_marker(Path::new(&alice_fault_marker)).await?;
    eprintln!("STEP s63 mode2: marker observed; SIGKILL alice rfd");
    mvp_s20_stop_rf_daemon(&mut alice_daemon).await?;
    let put_result = match put_handle.await? {
        Ok(value) => value,
        Err(error) => return Err(format!("s63 put task failed to run: {error}").into()),
    };
    assert!(
        !put_result.0,
        "mid-flight SIGKILL must fail the in-flight object put CLI: {}",
        put_result.1
    );

    // Restart Alice fault-off and resume the put; it must converge to complete from the persisted
    // chunk bitmap without duplicating the already-committed chunk, and the plaintext must roundtrip.
    let _ = std::fs::remove_file(&alice_socket);
    alice_daemon =
        s63_spawn_rf_daemon_with_env(&rf_binary, &alice_socket_arg, &alice_data_arg, &alice_env)?;
    mvp_s20_wait_for_daemon_status(&rf_binary, &alice_socket_arg).await?;
    let put_before_resume = mvp_s4_rf_json(
        &rf_binary,
        &[
            "--socket",
            &alice_socket_arg,
            "object",
            "status",
            "--account",
            "alice_s63_account",
            "--object",
            "object_s63_ownerput",
            "--direction",
            "upload",
        ],
    )
    .await?;
    assert_eq!(
        put_before_resume["transfer"]["completed_chunks"], 1,
        "exactly the first chunk bitmap entry must survive SIGKILL before resume: {put_before_resume}"
    );
    assert_ne!(
        put_before_resume["transfer"]["state"], "complete",
        "the held multi-chunk upload must still require resume: {put_before_resume}"
    );
    eprintln!("STEP s63 mode2: alice restarted; resume put");
    let resumed = mvp_s4_rf_json(
        &rf_binary,
        &[
            "--socket",
            &alice_socket_arg,
            "object",
            "resume",
            "--account",
            "alice_s63_account",
            "--object",
            "object_s63_ownerput",
            "--direction",
            "upload",
            "--relay-url",
            relay_url,
        ],
    )
    .await?;
    assert_eq!(
        resumed["transfer"]["state"], "complete",
        "owner put resume must complete the transfer"
    );
    let upload_status = mvp_s4_rf_json(
        &rf_binary,
        &[
            "--socket",
            &alice_socket_arg,
            "object",
            "status",
            "--account",
            "alice_s63_account",
            "--object",
            "object_s63_ownerput",
            "--direction",
            "upload",
        ],
    )
    .await?;
    assert_eq!(
        upload_status["transfer"]["state"], "complete",
        "owner put must converge to complete after crash-resume"
    );
    let put_output = temp.join("s63-ownerput-output.bin");
    let put_output_arg = mvp_s4_path_arg(&put_output);
    mvp_s4_rf_json(
        &rf_binary,
        &[
            "--socket",
            &alice_socket_arg,
            "object",
            "get",
            "--account",
            "alice_s63_account",
            "--object",
            "object_s63_ownerput",
            "--relay-url",
            relay_url,
            "--relay-ack",
            &put_output_arg,
        ],
    )
    .await?;
    assert_eq!(
        std::fs::read(&put_output)?,
        plaintext,
        "owner put/get roundtrip plaintext must match after crash-resume"
    );

    // ---- Mode 4: dm-recv crash after recv checkpoint durable, before cursor advance ----
    eprintln!("STEP s63 mode4: restart bob armed dm-recv");
    mvp_s20_stop_rf_daemon(&mut bob_daemon).await?;
    let _ = std::fs::remove_file(&bob_socket);
    let _ = std::fs::remove_file(&bob_fault_marker);
    let bob_env_dm_recv = {
        let mut env = bob_env_faultoff.clone();
        env.push(("RAMFLUX_SDK_ITEST_RFD_FAULT_MODE".to_owned(), "dm-recv".to_owned()));
        env.push(("RAMFLUX_SDK_ITEST_RFD_FAULT_MARKER".to_owned(), bob_fault_marker.clone()));
        env
    };
    bob_daemon =
        s63_spawn_rf_daemon_with_env(&rf_binary, &bob_socket_arg, &bob_data_arg, &bob_env_dm_recv)?;
    mvp_s20_wait_for_daemon_status(&rf_binary, &bob_socket_arg).await?;

    // Alice (unarmed) sends a new plain DM on the established conversation.
    mvp_s4_rf_json(
        &rf_binary,
        &[
            "--socket",
            &alice_socket_arg,
            "dm",
            "send",
            "--account",
            "alice_s63_account",
            "--conversation",
            "conv_s63_send",
            "--message",
            "msg_s63_recv_crash",
            "--envelope",
            "env_s63_recv_crash",
            "--source-principal",
            alice_principal,
            "--sender",
            "alice_device_s63",
            "--recipient-principal-commitment",
            &bob_commitment,
            "--recipient-device",
            "bob_device_s63",
            "--target",
            "target_s63_bob",
            "--body",
            "s63 recv crash body",
            "--relay-url",
            relay_url,
        ],
    )
    .await?;

    // Bob reads; the daemon holds after the recv ratchet checkpoint is durable and before the cursor
    // advances. Run in the background so this test can SIGKILL the parked daemon.
    let recv_rf = rf_binary.clone();
    let recv_socket = bob_socket_arg.clone();
    let recv_handle = tokio::spawn(async move {
        s63_run_rf_capture(
            &recv_rf,
            &[
                "--socket",
                &recv_socket,
                "dm",
                "read",
                "--account",
                "bob_s63_account",
                "--conversation",
                "conv_s63_send",
            ],
        )
        .await
    });
    eprintln!("STEP s63 mode4: waiting for bob dm-recv marker");
    s63_wait_marker(Path::new(&bob_fault_marker)).await?;
    eprintln!("STEP s63 mode4: marker observed; SIGKILL bob rfd");
    mvp_s20_stop_rf_daemon(&mut bob_daemon).await?;
    let recv_result = match recv_handle.await? {
        Ok(value) => value,
        Err(error) => return Err(format!("s63 recv task failed to run: {error}").into()),
    };
    assert!(
        !recv_result.0,
        "mid-flight SIGKILL must fail the in-flight dm read CLI: {}",
        recv_result.1
    );

    // Bob dead: the recv checkpoint is durable but the cursor has not advanced past this message.
    let _ = std::fs::remove_file(&bob_socket);
    let fp_before = s63_recv_fingerprint_for(&bob_data, "conv_s63_send", "object_s63_unused")?;
    assert!(
        fp_before.main_recv_checkpoint.is_some(),
        "recv checkpoint must be durable before the cursor barrier: {fp_before:?}"
    );

    // Restart Bob fault-off; the second read must go through terminal recovery (CursorCatchUp): no
    // AEAD failure, the message surfaces, and the cursor advances exactly once.
    bob_daemon = s63_spawn_rf_daemon_with_env(
        &rf_binary,
        &bob_socket_arg,
        &bob_data_arg,
        &bob_env_faultoff,
    )?;
    mvp_s20_wait_for_daemon_status(&rf_binary, &bob_socket_arg).await?;
    eprintln!("STEP s63 mode4: bob restarted; recovery read");
    let recovered = mvp_s4_rf_json(
        &rf_binary,
        &[
            "--socket",
            &bob_socket_arg,
            "dm",
            "read",
            "--account",
            "bob_s63_account",
            "--conversation",
            "conv_s63_send",
        ],
    )
    .await?;
    assert!(
        recovered.to_string().contains("env_s63_recv_crash"),
        "recovery read must surface the message without an AEAD failure: {recovered}"
    );
    let recovered_messages =
        recovered["messages"].as_array().ok_or("recovery read missing messages")?;
    assert_eq!(
        recovered_messages
            .iter()
            .filter(|message| message["message_id"] == "env_s63_recv_crash")
            .count(),
        1,
        "terminal recovery must leave exactly one projection for the held envelope: {recovered}"
    );
    mvp_s20_stop_rf_daemon(&mut bob_daemon).await?;
    let _ = std::fs::remove_file(&bob_socket);
    let fp_after = s63_recv_fingerprint_for(&bob_data, "conv_s63_send", "object_s63_unused")?;
    assert_eq!(
        fp_after.receive_cursor,
        fp_before.receive_cursor + 1,
        "receive cursor must advance exactly once for the recovered envelope: before={} after={}",
        fp_before.receive_cursor,
        fp_after.receive_cursor
    );
    bob_daemon = s63_spawn_rf_daemon_with_env(
        &rf_binary,
        &bob_socket_arg,
        &bob_data_arg,
        &bob_env_faultoff,
    )?;
    mvp_s20_wait_for_daemon_status(&rf_binary, &bob_socket_arg).await?;
    // Third read: the cursor has caught up, so no new gateway deliveries are fetched (no duplicate).
    let third = mvp_s4_rf_json(
        &rf_binary,
        &[
            "--socket",
            &bob_socket_arg,
            "dm",
            "read",
            "--account",
            "bob_s63_account",
            "--conversation",
            "conv_s63_send",
        ],
    )
    .await?;
    assert_eq!(
        third["gateway_entries"].as_array().map_or(0, Vec::len),
        0,
        "third read must fetch no new gateway deliveries (cursor already caught up): {third}"
    );
    assert_eq!(
        third["messages"]
            .as_array()
            .ok_or("third read missing messages")?
            .iter()
            .filter(|message| message["message_id"] == "env_s63_recv_crash")
            .count(),
        1,
        "third read must retain exactly one local projection for the recovered envelope: {third}"
    );

    // v3 is QUIC-only for objects: across every mode the relay must have received zero HTTP object
    // requests (no HTTP fallback path was taken).
    let relay_logs = s63_container_logs("ramflux-relay");
    assert!(
        !relay_logs.contains("POST /relay/v1/object/"),
        "relay must receive zero HTTP object requests across all crash modes"
    );

    // Cleanup.
    mvp_s20_stop_rf_daemon(&mut alice_daemon).await?;
    mvp_s20_stop_rf_daemon(&mut bob_daemon).await?;
    let _ = std::fs::remove_file(&alice_socket);
    let _ = std::fs::remove_file(&bob_socket);
    let _ = std::fs::remove_file(&bob_fault_marker);
    let _ = std::fs::remove_file(&alice_fault_marker);
    std::fs::remove_dir_all(&temp).ok();
    Ok(())
}

// ---- helpers (duplicated per the per-test-file v3 realnet idiom, see s59/s60/s62) ----

#[cfg(feature = "realnet")]
async fn s63_build_rf_binary() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let manifest = code_root().join("ramflux/apps/rf/Cargo.toml");
    let status = tokio::task::spawn_blocking(move || {
        std::process::Command::new("cargo")
            .args([
                "build",
                "--quiet",
                "--features",
                "itest-local-mint,itest-rfd-fault",
                "--manifest-path",
            ])
            .arg(manifest)
            .status()
    })
    .await??;
    if !status.success() {
        return Err("failed to build rf binary with itest-rfd-fault".into());
    }
    Ok(code_root().join("ramflux/target/debug/rf"))
}

#[cfg(feature = "realnet")]
fn s63_spawn_rf_daemon_with_env(
    rf_binary: &Path,
    socket: &str,
    data_root: &str,
    env: &[(String, String)],
) -> Result<tokio::process::Child, Box<dyn std::error::Error>> {
    // Capture daemon stderr to a per-socket log so a crash-resume failure is diagnosable.
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
async fn s63_add_contact(
    rf_binary: &Path,
    socket: &str,
    account: &str,
    link: &str,
    requester: &str,
    target: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let added = mvp_s4_rf_json(
        rf_binary,
        &[
            "--socket",
            socket,
            "contact",
            "add",
            "--account",
            account,
            "--link",
            link,
            "--requester",
            requester,
            "--target",
            target,
        ],
    )
    .await?;
    assert_eq!(added["state"], "accepted");
    Ok(())
}

/// Runs an `rf` CLI command to completion, returning `(success, combined_output)`. Used for the
/// in-flight faulting call whose daemon is `SIGKILL`ed mid-request (expected non-zero exit).
#[cfg(feature = "realnet")]
async fn s63_run_rf_capture(
    rf_binary: &Path,
    args: &[&str],
) -> Result<(bool, String), Box<dyn std::error::Error + Send + Sync>> {
    let output = tokio::process::Command::new(rf_binary).args(args).output().await?;
    let mut combined = String::from_utf8_lossy(&output.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&output.stderr));
    Ok((output.status.success(), combined))
}

/// Bounded poll (20s) for the daemon-written fault marker — never a sleep-based timing guess.
#[cfg(feature = "realnet")]
async fn s63_wait_marker(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    for _attempt in 0..200 {
        if path.exists() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(format!("s63 fault marker never appeared: {}", path.display()).into())
}

/// Reads Bob's recv-commit fingerprint (main + slot checkpoints + gateway receive cursor) from the
/// persisted account DB for a given conversation/object. The daemon MUST be stopped (exclusive store
/// lock) when this is called.
#[cfg(feature = "realnet")]
fn s63_recv_fingerprint_for(
    bob_data: &Path,
    conversation_id: &str,
    object_id: &str,
) -> Result<ramflux_sdk::RecvCommitFingerprint, Box<dyn std::error::Error>> {
    let mut client = ramflux_sdk::RamfluxClient::new();
    client.open_account_index(bob_data)?;
    client.unlock_account("bob_s63_account", b"rf-local-secret")?;
    let fingerprint = client.recv_commit_fingerprint(
        conversation_id,
        object_id,
        "bob_device_s63",
        "target_s63_bob",
    )?;
    Ok(fingerprint)
}

/// Mode 3 attachment-slot fingerprint.
#[cfg(feature = "realnet")]
fn s63_recv_fingerprint(
    bob_data: &Path,
) -> Result<ramflux_sdk::RecvCommitFingerprint, Box<dyn std::error::Error>> {
    s63_recv_fingerprint_for(bob_data, "conv_s63_attachment", "attachment:msg_s63_attach:0")
}

#[cfg(feature = "realnet")]
fn s63_certificate(
    now: u64,
    node_id: &str,
    gateway_instance_id: &str,
    root_seed: [u8; 32],
    attestation_seed: [u8; 32],
) -> Result<ramflux_node_core::GatewayIssuerCertificate, Box<dyn std::error::Error>> {
    let mut certificate = ramflux_node_core::GatewayIssuerCertificate {
        schema: ramflux_node_core::GATEWAY_ISSUER_CERTIFICATE_SCHEMA.to_owned(),
        version: ramflux_node_core::OBJECT_RELAY_V3_PROOF_VERSION,
        cert_id: "s63-gw-b-cert-1".to_owned(),
        node_id: node_id.to_owned(),
        gateway_instance_id: gateway_instance_id.to_owned(),
        attestation_public_key: ramflux_crypto::public_key_base64url_from_seed(attestation_seed),
        attestation_key_id: "s63-gw-b-attestation-1".to_owned(),
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
fn s63_trust_envelope(
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
        provider_signing_key_id: "s63-provider-1".to_owned(),
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
fn s63_write_provider_keyring(
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
            key_id: "s63-provider-1".to_owned(),
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
