// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

// T21-A2: a distinct grantee (B) downloads and acknowledges an object that owner A uploaded and
// shared through a DM attachment, entirely over the v3 GatewayIssued QUIC path. A signs a Get+Ack
// grant bound to B; B signs only its own requester PoP. The whole flow runs through the real rf
// CLI -> rfd public bus -> SDK production chain (no raw bus injection), and a reliable relay HTTP
// object-ingress capture proves zero HTTP object requests: any read failure of the capture fails
// the test, and the capture only records HTTP itest object ingress, never client-facing QUIC.
#![allow(unused_imports)]
#![cfg_attr(not(feature = "realnet"), allow(dead_code))]
use super::*;

#[cfg(feature = "realnet")]
#[test]
#[allow(clippy::too_many_lines)]
fn mvp_s56_realnet_object_v3_distinct_grantee_get_ack() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1")
        || std::env::var("RAMFLUX_OBJECT_V3").as_deref() != Ok("1")
        || std::env::var("RAMFLUX_CROSS_GATEWAY").as_deref() != Ok("1")
    {
        eprintln!(
            "skipping s56 grantee v3 realnet; set RAMFLUX_ITEST_REALNET=1 RAMFLUX_OBJECT_V3=1 RAMFLUX_CROSS_GATEWAY=1"
        );
        return Ok(());
    }

    let issuer_node = "node_b.realnet";
    let audience_node = "node_a.realnet";
    let alice_principal = "principal_s56_alice";
    let project = "ramflux-s56-grantee-v3";
    let relay_container = format!("{project}_ramflux-relay_1");
    let capture_path = "/tmp/ramflux-relay-itest-capture-s56.jsonl";

    let materials = temp_root("s56_object_v3_materials")?;
    let now = ramflux_node_core::now_unix_seconds();
    let root_seed = [0x44; 32];
    let attestation_seed = [0x33; 32];
    let provider_seed = [0x66; 32];
    let offline_root_seed = [0x88; 32]; // T23-A2b2b: offline signing root for the provider keyring
    let certificate = mvp_s56_certificate(now, issuer_node, "gw-b", root_seed, attestation_seed)?;
    let envelope =
        mvp_s56_trust_envelope(now, issuer_node, root_seed, provider_seed, &certificate)?;
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
    mvp_s56_write_provider_keyring(&materials, now, issuer_node, offline_root_seed, provider_seed)?;

    let ports = S8ComposePorts {
        gateway_http: 64_171,
        gateway_quic: 64_441,
        router_http: 64_170,
        router_mesh: 64_442,
        notify_http: 64_173,
        federation_http: 64_172,
        federation_mesh: 64_443,
        relay_http: 64_174,
        relay_media_udp: 64_130,
        signaling_turn_udp: 64_468,
        signaling_turn_tcp: 64_469,
        retention_http: 64_177,
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
            ("RAMFLUX_RELAY_ITEST_CAPTURE_JSON".to_owned(), capture_path.to_owned()),
        ],
    )?;

    let relay_ca = node.ca_cert.clone();
    let relay_quic_addr = "127.0.0.1:17447";
    let gateway_b_quic_addr = "127.0.0.1:18444";
    let relay_url = format!("http://127.0.0.1:{}", ports.relay_http);
    let ca_cert_env = relay_ca.to_string_lossy().into_owned();

    // A (owner/uploader) needs QUIC transport + its owner lineage so its v3 PUT and the attachment
    // it produces bind node_b/alice/node_a. B (grantee/downloader) needs only QUIC transport: its
    // GET/ACK owner lineage comes from the A-signed attachment, not from B's environment.
    let alice_env = vec![
        ("RAMFLUX_SDK_RELAY_QUIC_ADDR".to_owned(), relay_quic_addr.to_owned()),
        ("RAMFLUX_SDK_RELAY_QUIC_SERVER_NAME".to_owned(), "ramflux-relay".to_owned()),
        ("RAMFLUX_SDK_RELAY_QUIC_CA_CERT".to_owned(), ca_cert_env.clone()),
        ("RAMFLUX_SDK_RELAY_OWNER_HOME_NODE_ID".to_owned(), issuer_node.to_owned()),
        ("RAMFLUX_SDK_RELAY_OWNER_PRINCIPAL_ID".to_owned(), alice_principal.to_owned()),
        ("RAMFLUX_SDK_RELAY_AUDIENCE_NODE_ID".to_owned(), audience_node.to_owned()),
    ];
    let bob_env = vec![
        ("RAMFLUX_SDK_RELAY_QUIC_ADDR".to_owned(), relay_quic_addr.to_owned()),
        ("RAMFLUX_SDK_RELAY_QUIC_SERVER_NAME".to_owned(), "ramflux-relay".to_owned()),
        ("RAMFLUX_SDK_RELAY_QUIC_CA_CERT".to_owned(), ca_cert_env),
    ];

    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    runtime.block_on(async {
        // The relay client-facing QUIC listener must be live before driving the SDK.
        let config = ramflux_transport::RelayClientQuicConfig::new(
            relay_quic_addr,
            "ramflux-relay",
            &relay_ca,
        )?;
        let health =
            ramflux_transport::relay_client_quic_health(&config, std::time::Duration::from_secs(5))
                .await?;
        assert_eq!(health.status, 200, "relay client QUIC listener must be healthy: {health:?}");

        // Pre-create the capture file so its absence later can only mean a genuine read failure
        // (which fails the test), never "zero requests but no file". The relay appends one JSON
        // line per HTTP itest object request; QUIC ingress never writes here.
        mvp_s56_relay_exec(&relay_container, &["touch", capture_path])?;

        let (object_id, manifest_hash) =
            mvp_s56_grantee_flow(&node, gateway_b_quic_addr, &relay_url, &alice_env, &bob_env)
                .await?;

        // Adversarial: on the same original-owner=A chunk, prove B self-signed / tampered /
        // wrong-grantee / missing-capability grants are rejected 403 by the relay and never mutate
        // the authoritative chunk entry (read via a legit owner-authorized v3 GET before and after).
        mvp_s56_grant_negatives(
            &node,
            gateway_b_quic_addr,
            &relay_ca,
            &certificate,
            &object_id,
            &manifest_hash,
        )
        .await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;

    // Reliable HTTP object-ingress = 0: read the capture from inside the relay container. A read
    // failure (missing/unreadable file) fails the test; any content line is an HTTP object request.
    let capture = mvp_s56_relay_read(&relay_container, capture_path)?;
    let http_object_requests = capture.lines().filter(|line| !line.trim().is_empty()).count();
    assert_eq!(
        http_object_requests, 0,
        "the grantee GatewayIssued path must issue zero HTTP object requests (relay itest capture):\n{capture}"
    );

    std::fs::remove_dir_all(&materials).ok();
    Ok(())
}

// T21-A2 (iii): the grantee acknowledges only after the full object is durably persisted. When the
// relay is compiled with the itest fail-first ACK seam and it is activated, Bob's first import GETs
// and persists the object but its first ACK fails, so the import returns an error while the local
// object survives; after restarting Bob's daemon the object is still decryptable and its transfer is
// complete, a second import re-ACKs successfully with the same A-signed grant, and a duplicate ACK
// is idempotent — the relay chunk entry mutates exactly once.
#[cfg(feature = "realnet")]
#[test]
#[allow(clippy::too_many_lines)]
fn mvp_s57_realnet_object_v3_ack_failure_retry() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1")
        || std::env::var("RAMFLUX_OBJECT_V3").as_deref() != Ok("1")
        || std::env::var("RAMFLUX_CROSS_GATEWAY").as_deref() != Ok("1")
    {
        eprintln!(
            "skipping s57 ack-failure retry realnet; set RAMFLUX_ITEST_REALNET=1 RAMFLUX_OBJECT_V3=1 RAMFLUX_CROSS_GATEWAY=1"
        );
        return Ok(());
    }

    let issuer_node = "node_b.realnet";
    let audience_node = "node_a.realnet";
    let alice_principal = "principal_s57_alice";
    let project = "ramflux-s57-ack-retry";

    let materials = temp_root("s57_object_v3_materials")?;
    let now = ramflux_node_core::now_unix_seconds();
    let root_seed = [0x44; 32];
    let attestation_seed = [0x33; 32];
    let provider_seed = [0x66; 32];
    let offline_root_seed = [0x88; 32]; // T23-A2b2b: offline signing root for the provider keyring
    let certificate = mvp_s56_certificate(now, issuer_node, "gw-b", root_seed, attestation_seed)?;
    let envelope =
        mvp_s56_trust_envelope(now, issuer_node, root_seed, provider_seed, &certificate)?;
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
    mvp_s56_write_provider_keyring(&materials, now, issuer_node, offline_root_seed, provider_seed)?;

    let ports = S8ComposePorts {
        gateway_http: 64_161,
        gateway_quic: 64_431,
        router_http: 64_160,
        router_mesh: 64_432,
        notify_http: 64_163,
        federation_http: 64_162,
        federation_mesh: 64_433,
        relay_http: 64_164,
        relay_media_udp: 64_140,
        signaling_turn_udp: 64_458,
        signaling_turn_tcp: 64_459,
        retention_http: 64_167,
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
            // Activate the relay fail-first v3 ACK seam for this project only.
            ("RAMFLUX_RELAY_ITEST_FAIL_FIRST_V3_ACK".to_owned(), "1".to_owned()),
        ],
    )?;

    let relay_ca = node.ca_cert.clone();
    let relay_quic_addr = "127.0.0.1:17447";
    let gateway_b_quic_addr = "127.0.0.1:18444";
    let relay_url = format!("http://127.0.0.1:{}", ports.relay_http);
    let ca_cert_env = relay_ca.to_string_lossy().into_owned();

    let alice_env = vec![
        ("RAMFLUX_SDK_RELAY_QUIC_ADDR".to_owned(), relay_quic_addr.to_owned()),
        ("RAMFLUX_SDK_RELAY_QUIC_SERVER_NAME".to_owned(), "ramflux-relay".to_owned()),
        ("RAMFLUX_SDK_RELAY_QUIC_CA_CERT".to_owned(), ca_cert_env.clone()),
        ("RAMFLUX_SDK_RELAY_OWNER_HOME_NODE_ID".to_owned(), issuer_node.to_owned()),
        ("RAMFLUX_SDK_RELAY_OWNER_PRINCIPAL_ID".to_owned(), alice_principal.to_owned()),
        ("RAMFLUX_SDK_RELAY_AUDIENCE_NODE_ID".to_owned(), audience_node.to_owned()),
    ];
    let bob_env = vec![
        ("RAMFLUX_SDK_RELAY_QUIC_ADDR".to_owned(), relay_quic_addr.to_owned()),
        ("RAMFLUX_SDK_RELAY_QUIC_SERVER_NAME".to_owned(), "ramflux-relay".to_owned()),
        ("RAMFLUX_SDK_RELAY_QUIC_CA_CERT".to_owned(), ca_cert_env),
    ];

    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    runtime.block_on(async {
        let config = ramflux_transport::RelayClientQuicConfig::new(
            relay_quic_addr,
            "ramflux-relay",
            &relay_ca,
        )?;
        let health =
            ramflux_transport::relay_client_quic_health(&config, std::time::Duration::from_secs(5))
                .await?;
        assert_eq!(health.status, 200, "relay client QUIC listener must be healthy: {health:?}");
        mvp_s57_ack_failure_flow(
            &node,
            gateway_b_quic_addr,
            &relay_url,
            &relay_ca,
            &certificate,
            &alice_env,
            &bob_env,
        )
        .await
    })?;

    std::fs::remove_dir_all(&materials).ok();
    Ok(())
}

#[cfg(feature = "realnet")]
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
async fn mvp_s57_ack_failure_flow(
    node: &S8RealnetNode,
    gateway_b_quic_addr: &str,
    relay_url: &str,
    relay_ca: &std::path::Path,
    certificate: &ramflux_node_core::GatewayIssuerCertificate,
    alice_env: &[(String, String)],
    bob_env: &[(String, String)],
) -> Result<(), Box<dyn std::error::Error>> {
    use ramflux_node_core::ObjectRelayCapability::{Ack, Get};
    let temp_root = temp_root("s57_ack_retry")?;
    let alice_data = temp_root.join("alice/data");
    let bob_data = temp_root.join("bob/data");
    std::fs::create_dir_all(&alice_data)?;
    std::fs::create_dir_all(&bob_data)?;
    let pid = std::process::id();
    let alice_socket = PathBuf::from(format!("/tmp/ramflux-s57-alice-{pid}.sock"));
    let bob_socket = PathBuf::from(format!("/tmp/ramflux-s57-bob-{pid}.sock"));
    let input_path = temp_root.join("s57-attachment-input.bin");
    let plaintext = b"mvp_s57_ack_failure_retry_object_do_not_leak_plaintext".repeat(40);
    std::fs::write(&input_path, &plaintext)?;

    let rf_binary = mvp_s4_build_rf_binary().await?;
    let ca_cert_arg = mvp_s4_path_arg(&node.ca_cert);
    let alice_socket_arg = mvp_s4_path_arg(&alice_socket);
    let bob_socket_arg = mvp_s4_path_arg(&bob_socket);
    let alice_data_arg = mvp_s4_path_arg(&alice_data);
    let bob_data_arg = mvp_s4_path_arg(&bob_data);
    let input_arg = mvp_s4_path_arg(&input_path);

    let now = ramflux_node_core::now_unix_seconds();
    let alice_seed = [0x57u8; 32];
    let alice_device_id = "alice_device_s57";
    let bob_device_id = "bob_device_s57";
    let bob_seed = [0x59u8; 32];
    let bob_device_hash = ramflux_crypto::blake3_256_base64url(
        "ramflux.object_relay.recipient_device.v1",
        bob_device_id.as_bytes(),
    );

    let mut alice_daemon = mvp_s56_spawn_rf_daemon_with_env(
        &rf_binary,
        &alice_socket_arg,
        &alice_data_arg,
        alice_env,
    )?;
    let mut bob_daemon =
        mvp_s56_spawn_rf_daemon_with_env(&rf_binary, &bob_socket_arg, &bob_data_arg, bob_env)?;

    let result = async {
        mvp_s4_wait_for_socket(&alice_socket).await?;
        mvp_s4_wait_for_socket(&bob_socket).await?;
        let alice_commitment = mvp_s10_create_rf_account(
            &rf_binary,
            &alice_socket_arg,
            "alice_s57_account",
            "principal_s57_alice",
            alice_device_id,
            "target_s57_alice",
            gateway_b_quic_addr,
            &ca_cert_arg,
            "56",
            "57",
        )
        .await?;
        let bob_commitment = mvp_s10_create_rf_account(
            &rf_binary,
            &bob_socket_arg,
            "bob_s57_account",
            "principal_s57_bob",
            bob_device_id,
            "target_s57_bob",
            gateway_b_quic_addr,
            &ca_cert_arg,
            "58",
            "59",
        )
        .await?;
        mvp_s56_add_contact(
            &rf_binary,
            &alice_socket_arg,
            "alice_s57_account",
            "alice_to_bob_s57",
            &alice_commitment,
            &bob_commitment,
        )
        .await?;
        mvp_s56_add_contact(
            &rf_binary,
            &bob_socket_arg,
            "bob_s57_account",
            "bob_to_alice_s57",
            &bob_commitment,
            &alice_commitment,
        )
        .await?;

        // A uploads + shares the object.
        mvp_s4_rf_json(
            &rf_binary,
            &[
                "--socket",
                &alice_socket_arg,
                "dm",
                "send",
                "--account",
                "alice_s57_account",
                "--conversation",
                "conv_s57_attachment",
                "--message",
                "msg_s57_attach",
                "--envelope",
                "env_s57_attach",
                "--source-principal",
                "principal_s57_alice",
                "--sender",
                alice_device_id,
                "--recipient-principal-commitment",
                &bob_commitment,
                "--recipient-device",
                bob_device_id,
                "--target",
                "target_s57_bob",
                "--body",
                "s57 attachment body",
                "--attach",
                &input_arg,
                "--relay-url",
                relay_url,
                "--attachment-chunk-size",
                "1024",
            ],
        )
        .await?;
        let object_id = "attachment:msg_s57_attach:0";

        // T21-A2a / CTRL-028 item 4: fingerprint Bob's recv-commit state BEFORE the first read.
        // Reading the encrypted account store requires Bob's daemon stopped (it holds the store
        // lock), so bounce it around a read-only in-process open. This is the "old value" baseline
        // that both the failed import and the daemon restart must preserve unchanged.
        mvp_s20_stop_rf_daemon(&mut bob_daemon).await?;
        let _ = std::fs::remove_file(&bob_socket);
        let fingerprint_baseline = mvp_s57_recv_fingerprint(&bob_data)?;
        assert!(
            fingerprint_baseline.slot_recv_checkpoint.is_none(),
            "no attachment key-slot session may be committed before the first read: \
             {fingerprint_baseline:?}"
        );
        bob_daemon =
            mvp_s56_spawn_rf_daemon_with_env(&rf_binary, &bob_socket_arg, &bob_data_arg, bob_env)?;
        mvp_s4_wait_for_socket(&bob_socket).await?;

        // Bob's first import GETs every chunk and durably persists the object + transfer, then its
        // first ACK is rejected by the relay seam, so the import returns an error.
        let first = mvp_s4_rf_failure(
            &rf_binary,
            &[
                "--socket",
                &bob_socket_arg,
                "dm",
                "read",
                "--account",
                "bob_s57_account",
                "--conversation",
                "conv_s57_attachment",
            ],
        )
        .await?;
        assert!(
            !first.is_empty(),
            "bob's first import must fail because the first ACK is rejected"
        );

        // The object + transfer were persisted before the ACK; recover the manifest hash from the
        // persisted download transfer and confirm it completed.
        let status = mvp_s4_rf_json(
            &rf_binary,
            &[
                "--socket",
                &bob_socket_arg,
                "object",
                "status",
                "--account",
                "bob_s57_account",
                "--object",
                object_id,
                "--direction",
                "download",
            ],
        )
        .await?;
        assert_eq!(
            status["transfer"]["state"], "complete",
            "the object must be durably persisted before the ACK is attempted"
        );
        let manifest_hash = status["transfer"]["manifest_hash"]
            .as_str()
            .ok_or("missing persisted manifest_hash")?
            .to_owned();
        let chunk_id = format!("object-relay:{object_id}:{manifest_hash}:0");
        // Reads go through the probe device: A grants the probe Get so its GET (probe requester)
        // satisfies grantee==requester and reads the authoritative entry without ever ACKing it.
        let probe_device_hash = ramflux_crypto::blake3_256_base64url(
            "ramflux.object_relay.recipient_device.v1",
            "probe_device_s57".as_bytes(),
        );
        let probe_grant_get = mvp_s57_owner_grant(
            object_id,
            &manifest_hash,
            &probe_device_hash,
            vec![Get],
            now,
            alice_seed,
            alice_device_id,
        )?;
        let bob_grant_ack = mvp_s57_owner_grant(
            object_id,
            &manifest_hash,
            &bob_device_hash,
            vec![Ack],
            now,
            alice_seed,
            alice_device_id,
        )?;

        // Register the read-probe device once; each authoritative read re-opens this identity.
        mvp_s57_register_probe(node)?;

        // The failed ACK must not have recorded Bob in the authoritative relay chunk entry.
        let entry_after_fail = mvp_s57_read_chunk_entry(
            node,
            gateway_b_quic_addr,
            relay_ca,
            certificate,
            &probe_grant_get,
            &chunk_id,
        )
        .await?;
        assert!(
            !mvp_s57_acked_by_contains(&entry_after_fail, &bob_device_hash),
            "a failed ACK must not mutate the relay entry: {entry_after_fail:?}"
        );

        // Restart Bob's daemon (retain data root); the persisted object must survive.
        mvp_s20_stop_rf_daemon(&mut bob_daemon).await?;
        let _ = std::fs::remove_file(&bob_socket);
        // CTRL-028 item 4: after the failed import, the main recv checkpoint, the attachment
        // key-slot recv checkpoint, and the receive cursor must all still hold their baseline
        // values — the failed ACK committed none of them, so the retry can re-decrypt.
        let fingerprint_after_fail = mvp_s57_recv_fingerprint(&bob_data)?;
        assert_eq!(
            fingerprint_after_fail, fingerprint_baseline,
            "a failed attachment import must advance neither recv checkpoint nor the receive cursor"
        );
        bob_daemon =
            mvp_s56_spawn_rf_daemon_with_env(&rf_binary, &bob_socket_arg, &bob_data_arg, bob_env)?;
        mvp_s4_wait_for_socket(&bob_socket).await?;
        let restarted_status = mvp_s4_rf_json(
            &rf_binary,
            &[
                "--socket",
                &bob_socket_arg,
                "object",
                "status",
                "--account",
                "bob_s57_account",
                "--object",
                object_id,
                "--direction",
                "download",
            ],
        )
        .await?;
        assert_eq!(
            restarted_status["transfer"]["state"], "complete",
            "the persisted download must survive a daemon restart"
        );

        // The retry re-imports and ACKs successfully (the seam is consumed on the same relay
        // process), recording Bob in acked_by. That the retry re-decrypts the SAME envelope and
        // slot ciphertext proves neither the main recv session, the attachment key-slot session, nor
        // the receive cursor advanced in Bob's persisted store during the failed first import
        // (T21-A2a / CTRL-028): had any of them been committed early, this read would fail with an
        // AEAD error instead of re-delivering.
        let retry = mvp_s4_rf_json(
            &rf_binary,
            &[
                "--socket",
                &bob_socket_arg,
                "dm",
                "read",
                "--account",
                "bob_s57_account",
                "--conversation",
                "conv_s57_attachment",
            ],
        )
        .await?;
        let retry_messages =
            retry["decrypted_messages"].as_array().ok_or("missing retry decrypted messages")?;
        assert_eq!(
            retry_messages.len(),
            1,
            "the retry must re-decrypt and re-deliver exactly the one message: {retry:?}"
        );
        assert_eq!(
            retry_messages[0]["attachments"].as_array().map(Vec::len),
            Some(1),
            "the retry must re-import exactly the one attachment: {retry:?}"
        );
        let entry_after_retry = mvp_s57_read_chunk_entry(
            node,
            gateway_b_quic_addr,
            relay_ca,
            certificate,
            &probe_grant_get,
            &chunk_id,
        )
        .await?;
        assert!(
            mvp_s57_acked_by_contains(&entry_after_retry, &bob_device_hash),
            "the retry ACK must record Bob in acked_by: {entry_after_retry:?}"
        );

        // CTRL-028 item 5: a third real dm read must NOT re-decrypt, re-import, re-project, or
        // re-ACK. The successful retry already committed the recv session, the slot session, and the
        // receive cursor as one terminal step, so this envelope is behind the cursor and yields no
        // new delivery, and the authoritative relay entry does not mutate again.
        let third = mvp_s4_rf_json(
            &rf_binary,
            &[
                "--socket",
                &bob_socket_arg,
                "dm",
                "read",
                "--account",
                "bob_s57_account",
                "--conversation",
                "conv_s57_attachment",
            ],
        )
        .await?;
        let third_messages = third["decrypted_messages"]
            .as_array()
            .ok_or("missing third read decrypted messages")?;
        assert!(
            third_messages.is_empty(),
            "a third dm read must not re-deliver the already-committed message: {third:?}"
        );
        let entry_after_third = mvp_s57_read_chunk_entry(
            node,
            gateway_b_quic_addr,
            relay_ca,
            certificate,
            &probe_grant_get,
            &chunk_id,
        )
        .await?;
        assert_eq!(
            entry_after_third, entry_after_retry,
            "a third dm read must not re-ACK or otherwise mutate the relay entry"
        );

        // A duplicate production-equivalent ACK is idempotent: the entry must not mutate again.
        // Stop Bob's daemon first so the raw duplicate ACK can open a session as Bob's device
        // without contending with the daemon's live gateway session.
        mvp_s20_stop_rf_daemon(&mut bob_daemon).await?;
        let _ = std::fs::remove_file(&bob_socket);
        // CTRL-028 item 4: after the successful retry (and the no-op third read), all three recv
        // commit fingerprints must have advanced exactly once — the main recv checkpoint now covers
        // the envelope, the slot recv checkpoint now covers the attachment key slot, and the
        // receive cursor moved past the entry.
        let fingerprint_after_retry = mvp_s57_recv_fingerprint(&bob_data)?;
        let main_recv = fingerprint_after_retry
            .main_recv_checkpoint
            .as_deref()
            .ok_or("the retry must commit the main recv session")?;
        assert!(
            main_recv.contains("env_s57_attach"),
            "the committed main recv checkpoint must cover the delivered envelope: {main_recv}"
        );
        let slot_recv = fingerprint_after_retry
            .slot_recv_checkpoint
            .as_deref()
            .ok_or("the retry must commit the attachment key-slot recv session")?;
        assert!(
            slot_recv.contains("object-slot:attachment:msg_s57_attach:0"),
            "the committed slot recv checkpoint must cover the attachment key slot: {slot_recv}"
        );
        assert!(
            fingerprint_after_retry.receive_cursor > fingerprint_after_fail.receive_cursor,
            "the successful retry must advance the receive cursor past the delivered entry: \
             {fingerprint_after_retry:?} vs {fingerprint_after_fail:?}"
        );
        let dup = mvp_s57_direct_ack(
            node,
            gateway_b_quic_addr,
            relay_ca,
            certificate,
            &bob_grant_ack,
            &chunk_id,
            bob_device_id,
            bob_seed,
        )
        .await?;
        assert_eq!(dup, 200, "a duplicate legit ACK must succeed idempotently, got {dup}");
        let entry_after_dup = mvp_s57_read_chunk_entry(
            node,
            gateway_b_quic_addr,
            relay_ca,
            certificate,
            &probe_grant_get,
            &chunk_id,
        )
        .await?;
        assert_eq!(
            entry_after_dup, entry_after_retry,
            "a duplicate ACK must not mutate the relay entry again"
        );
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;

    mvp_s20_stop_rf_daemon(&mut alice_daemon).await?;
    mvp_s20_stop_rf_daemon(&mut bob_daemon).await?;
    let _ = std::fs::remove_file(&alice_socket);
    let _ = std::fs::remove_file(&bob_socket);
    std::fs::remove_dir_all(&temp_root).ok();
    result?;
    Ok(())
}

#[cfg(feature = "realnet")]
#[allow(clippy::too_many_arguments)]
fn mvp_s57_owner_grant(
    object_id: &str,
    manifest_hash: &str,
    grantee_hash: &str,
    caps: Vec<ramflux_node_core::ObjectRelayCapability>,
    now: u64,
    owner_seed: [u8; 32],
    owner_key_id: &str,
) -> Result<ramflux_node_core::ObjectAccessGrant, Box<dyn std::error::Error>> {
    let mut grant = ramflux_node_core::ObjectAccessGrant {
        schema: ramflux_node_core::OBJECT_ACCESS_GRANT_SCHEMA.to_owned(),
        version: ramflux_node_core::OBJECT_RELAY_V3_PROOF_VERSION,
        object_id: object_id.to_owned(),
        manifest_hash: manifest_hash.to_owned(),
        grantee_device_hash: grantee_hash.to_owned(),
        capabilities: caps,
        issued_at: now.saturating_sub(10),
        expires_at: now + 300,
        owner_signing_key_id: owner_key_id.to_owned(),
        owner_public_key: ramflux_crypto::public_key_base64url_from_seed(owner_seed),
        owner_signature: String::new(),
    };
    grant.owner_signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &ramflux_node_core::object_access_grant_signing_bytes(&grant)?,
        owner_seed,
    );
    Ok(grant)
}

#[cfg(feature = "realnet")]
async fn mvp_s57_read_chunk_entry(
    node: &S8RealnetNode,
    gateway_b_quic_addr: &str,
    relay_ca: &std::path::Path,
    certificate: &ramflux_node_core::GatewayIssuerCertificate,
    grant: &ramflux_node_core::ObjectAccessGrant,
    chunk_id: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let (mut send, mut recv, open, relay) =
        mvp_s57_probe_session(node, gateway_b_quic_addr, relay_ca).await?;
    let now = ramflux_node_core::now_unix_seconds();
    let response = mvp_s56_v3_object_request(
        &mut send,
        &mut recv,
        &open,
        &relay,
        certificate,
        "probe_device_s57",
        [0x72u8; 32],
        grant,
        chunk_id,
        "principal_s57_alice",
        ramflux_node_core::ObjectRelayCapability::Get,
        "get_chunk",
        "get",
        &format!("read-{now}-{}", ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)),
        now,
    )
    .await?;
    if response.status != 200 {
        return Err(format!("legit probe GET must return 200, got {response:?}").into());
    }
    Ok(response.body.get("chunk").cloned().ok_or("probe GET response missing chunk")?)
}

#[cfg(feature = "realnet")]
#[allow(clippy::too_many_arguments)]
async fn mvp_s57_direct_ack(
    node: &S8RealnetNode,
    gateway_b_quic_addr: &str,
    relay_ca: &std::path::Path,
    certificate: &ramflux_node_core::GatewayIssuerCertificate,
    grant: &ramflux_node_core::ObjectAccessGrant,
    chunk_id: &str,
    device_id: &str,
    device_seed: [u8; 32],
) -> Result<u16, Box<dyn std::error::Error>> {
    // The duplicate ACK is issued as Bob's own already-registered device (no re-registration).
    let (mut send, mut recv, open, relay) = mvp_s57_probe_session_as(
        node,
        gateway_b_quic_addr,
        relay_ca,
        "principal_s57_bob",
        device_id,
        device_seed,
        "target_s57_bob",
        false,
    )
    .await?;
    let now = ramflux_node_core::now_unix_seconds();
    let response = mvp_s56_v3_object_request(
        &mut send,
        &mut recv,
        &open,
        &relay,
        certificate,
        device_id,
        device_seed,
        grant,
        chunk_id,
        "principal_s57_alice",
        ramflux_node_core::ObjectRelayCapability::Ack,
        "ack",
        "ack",
        &format!(
            "dup-ack-{now}-{}",
            ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
        ),
        now,
    )
    .await?;
    Ok(response.status)
}

#[cfg(feature = "realnet")]
async fn mvp_s57_probe_session(
    node: &S8RealnetNode,
    gateway_b_quic_addr: &str,
    relay_ca: &std::path::Path,
) -> Result<
    (
        quinn::SendStream,
        quinn::RecvStream,
        ramflux_node_core::GatewayOpenFrame,
        ramflux_transport::QuicGatewayClient,
    ),
    Box<dyn std::error::Error>,
> {
    // The probe device is registered once by the flow before the first read; here we only
    // re-open + authenticate it, so repeated reads do not re-register the same identity.
    mvp_s57_probe_session_as(
        node,
        gateway_b_quic_addr,
        relay_ca,
        "principal_s57_probe",
        "probe_device_s57",
        [0x72u8; 32],
        "target_s57_probe",
        false,
    )
    .await
}

#[cfg(feature = "realnet")]
fn mvp_s57_register_probe(node: &S8RealnetNode) -> Result<(), Box<dyn std::error::Error>> {
    let registration = mvp_s1_identity_register_request(GatewayFrameIdentitySpec {
        principal_id: "principal_s57_probe",
        device_id: "probe_device_s57",
        target_delivery_id: "target_s57_probe",
        gateway_id: "gw-b",
        session_id: "pre_session_s57_probe",
        push_alias_hash: Some("push_s57_probe"),
        source_ip_hash: Some("s57_probe_source"),
        root_seed: [0x73u8; 32],
        device_seed: [0x72u8; 32],
        device_epoch: 1,
    })?;
    register_mvp1_identity(&node.gateway_url, &registration)?;
    Ok(())
}

#[cfg(feature = "realnet")]
#[allow(clippy::too_many_arguments)]
async fn mvp_s57_probe_session_as(
    node: &S8RealnetNode,
    gateway_b_quic_addr: &str,
    relay_ca: &std::path::Path,
    principal_id: &str,
    device_id: &str,
    device_seed: [u8; 32],
    target_delivery_id: &str,
    register: bool,
) -> Result<
    (
        quinn::SendStream,
        quinn::RecvStream,
        ramflux_node_core::GatewayOpenFrame,
        ramflux_transport::QuicGatewayClient,
    ),
    Box<dyn std::error::Error>,
> {
    let now = ramflux_node_core::now_unix_seconds();
    // The probe device is fresh (register). Bob's device is already registered by his account, so
    // we only re-open + authenticate an existing device to issue a duplicate ACK as Bob himself.
    if register {
        let registration = mvp_s1_identity_register_request(GatewayFrameIdentitySpec {
            principal_id,
            device_id,
            target_delivery_id,
            gateway_id: "gw-b",
            session_id: "pre_session_s57_probe",
            push_alias_hash: Some("push_s57_probe"),
            source_ip_hash: Some("s57_probe_source"),
            root_seed: [0x73u8; 32],
            device_seed,
            device_epoch: 1,
        })?;
        register_mvp1_identity(&node.gateway_url, &registration)?;
    }
    let (_endpoint, _connection, mut send, mut recv) =
        mvp_s1_open_quic_stream(gateway_b_quic_addr.parse()?, &node.ca_cert).await?;
    let mut open = mvp_s1_open_frame(None, now, "s57-probe");
    open.client_instance_id = format!("rf_s57_{device_id}");
    open.device_id = device_id.to_owned();
    open.target_delivery_id = target_delivery_id.to_owned();
    // Each probe/duplicate-ACK session opens a fresh gateway stream; a unique nonce keeps the node
    // replay guard from rejecting a later session that would otherwise reuse a same-second nonce.
    open.stream_nonce = format!(
        "nonce_s57_{device_id}_{}",
        ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
    );
    open.source_ip_hash = Some("s57_probe_source".to_owned());
    let auth = mvp_s1_auth_frame_for_registered_device(&open, principal_id, 1, device_seed)?;
    mvp_s1_write_client_frame(
        &mut send,
        &ramflux_node_core::GatewayClientFrame::Open { open: open.clone() },
    )
    .await?;
    mvp_s1_write_client_frame(&mut send, &ramflux_node_core::GatewayClientFrame::Auth { auth })
        .await?;
    let _session = mvp_s1_expect_session_established(&mut recv).await?;
    let relay = ramflux_transport::QuicGatewayClient::connect(
        "0.0.0.0:0".parse()?,
        "127.0.0.1:17447".parse()?,
        "ramflux-relay",
        relay_ca,
        std::time::Duration::from_secs(5),
    )
    .await?;
    Ok((send, recv, open, relay))
}

#[cfg(feature = "realnet")]
fn mvp_s57_acked_by_contains(entry: &serde_json::Value, device_hash: &str) -> bool {
    entry["acked_by"]
        .as_array()
        .is_some_and(|acked| acked.iter().any(|value| value.as_str() == Some(device_hash)))
}

// T21-A2a / CTRL-028 item 4: read-only, in-process capture of Bob's recv-commit fingerprints from
// his persisted account store. The daemon must be stopped first (it holds an exclusive store lock);
// the read never mutates and never exposes key material. Uses the SDK's `itest-fingerprint`-gated
// read entry (enabled by the itest `realnet` feature; never compiled into the production rf binary).
#[cfg(feature = "realnet")]
fn mvp_s57_recv_fingerprint(
    bob_data: &std::path::Path,
) -> Result<ramflux_sdk::RecvCommitFingerprint, Box<dyn std::error::Error>> {
    let mut client = ramflux_sdk::RamfluxClient::new();
    client.open_account_index(bob_data)?;
    client.unlock_account("bob_s57_account", b"rf-local-secret")?;
    let fingerprint = client.recv_commit_fingerprint(
        "conv_s57_attachment",
        "attachment:msg_s57_attach:0",
        "bob_device_s57",
        "target_s57_bob",
    )?;
    Ok(fingerprint)
}

#[cfg(feature = "realnet")]
#[allow(clippy::too_many_lines)]
async fn mvp_s56_grantee_flow(
    node: &S8RealnetNode,
    gateway_b_quic_addr: &str,
    relay_url: &str,
    alice_env: &[(String, String)],
    bob_env: &[(String, String)],
) -> Result<(String, String), Box<dyn std::error::Error>> {
    let temp_root = temp_root("s56_object_v3_grantee")?;
    let alice_data = temp_root.join("alice/data");
    let bob_data = temp_root.join("bob/data");
    std::fs::create_dir_all(&alice_data)?;
    std::fs::create_dir_all(&bob_data)?;
    let pid = std::process::id();
    let alice_socket = PathBuf::from(format!("/tmp/ramflux-s56-alice-{pid}.sock"));
    let bob_socket = PathBuf::from(format!("/tmp/ramflux-s56-bob-{pid}.sock"));
    let input_path = temp_root.join("s56-attachment-input.bin");
    std::fs::create_dir_all(&temp_root)?;
    let plaintext = b"mvp_s56_distinct_grantee_v3_attachment_do_not_leak_plaintext".repeat(48);
    std::fs::write(&input_path, &plaintext)?;

    let rf_binary = mvp_s4_build_rf_binary().await?;
    let ca_cert_arg = mvp_s4_path_arg(&node.ca_cert);
    let alice_socket_arg = mvp_s4_path_arg(&alice_socket);
    let bob_socket_arg = mvp_s4_path_arg(&bob_socket);
    let alice_data_arg = mvp_s4_path_arg(&alice_data);
    let bob_data_arg = mvp_s4_path_arg(&bob_data);
    let input_arg = mvp_s4_path_arg(&input_path);

    let mut alice_daemon = mvp_s56_spawn_rf_daemon_with_env(
        &rf_binary,
        &alice_socket_arg,
        &alice_data_arg,
        alice_env,
    )?;
    let mut bob_daemon =
        mvp_s56_spawn_rf_daemon_with_env(&rf_binary, &bob_socket_arg, &bob_data_arg, bob_env)?;

    let flow = async {
        mvp_s4_wait_for_socket(&alice_socket).await?;
        mvp_s4_wait_for_socket(&bob_socket).await?;

        // Both accounts are created against gateway-b (the v3 issuer). A is the object owner; B is a
        // distinct principal/device that will receive A's grant.
        let alice_commitment = mvp_s10_create_rf_account(
            &rf_binary,
            &alice_socket_arg,
            "alice_s56_account",
            "principal_s56_alice",
            "alice_device_s56",
            "target_s56_alice",
            gateway_b_quic_addr,
            &ca_cert_arg,
            "56",
            "57",
        )
        .await?;
        let bob_commitment = mvp_s10_create_rf_account(
            &rf_binary,
            &bob_socket_arg,
            "bob_s56_account",
            "principal_s56_bob",
            "bob_device_s56",
            "target_s56_bob",
            gateway_b_quic_addr,
            &ca_cert_arg,
            "58",
            "59",
        )
        .await?;

        mvp_s56_add_contact(
            &rf_binary,
            &alice_socket_arg,
            "alice_s56_account",
            "alice_to_bob_s56",
            &alice_commitment,
            &bob_commitment,
        )
        .await?;
        mvp_s56_add_contact(
            &rf_binary,
            &bob_socket_arg,
            "bob_s56_account",
            "bob_to_alice_s56",
            &bob_commitment,
            &alice_commitment,
        )
        .await?;

        // A sends B a DM with the object attached; this uploads the object via the owner v3 QUIC
        // PUT and embeds an A-signed Get+Ack grant bound to B in the attachment ref.
        let sent = mvp_s4_rf_json(
            &rf_binary,
            &[
                "--socket",
                &alice_socket_arg,
                "dm",
                "send",
                "--account",
                "alice_s56_account",
                "--conversation",
                "conv_s56_attachment",
                "--message",
                "msg_s56_attach",
                "--envelope",
                "env_s56_attach",
                "--source-principal",
                "principal_s56_alice",
                "--sender",
                "alice_device_s56",
                "--recipient-principal-commitment",
                &bob_commitment,
                "--recipient-device",
                "bob_device_s56",
                "--target",
                "target_s56_bob",
                "--body",
                "s56 attachment body",
                "--attach",
                &input_arg,
                "--relay-url",
                relay_url,
                "--attachment-chunk-size",
                "1024",
            ],
        )
        .await?;
        assert_eq!(sent["envelope"]["envelope_id"], "env_s56_attach");

        // B reads the DM; reading auto-imports the attachment: v3 QUIC GET of every chunk using the
        // received grant, then (once the full object is durably persisted and the plaintext hash
        // verifies) a v3 QUIC ACK of every chunk with B's own PoP.
        let bob_read = mvp_s4_rf_json(
            &rf_binary,
            &[
                "--socket",
                &bob_socket_arg,
                "dm",
                "read",
                "--account",
                "bob_s56_account",
                "--conversation",
                "conv_s56_attachment",
            ],
        )
        .await?;
        let decrypted =
            bob_read["decrypted_messages"].as_array().ok_or("missing s56 decrypted messages")?;
        assert_eq!(decrypted.len(), 1, "bob must decrypt exactly one message");
        let attachments = decrypted[0]["attachments"].as_array().ok_or("missing attachments")?;
        assert_eq!(attachments.len(), 1, "bob must see one attachment");
        let attachment_plaintext = ramflux_protocol::decode_base64url(
            attachments[0]["plaintext_base64"].as_str().ok_or("missing attachment plaintext")?,
        )?;
        assert_eq!(
            attachment_plaintext, plaintext,
            "grantee must reconstruct the exact attachment plaintext over v3 QUIC"
        );
        // Capture the authoritative object identity for the crafted grant-negative probes.
        let object_id =
            attachments[0]["object_id"].as_str().ok_or("missing attachment object_id")?.to_owned();
        let manifest_hash = attachments[0]["manifest_hash"]
            .as_str()
            .ok_or("missing attachment manifest_hash")?
            .to_owned();
        Ok::<(String, String), Box<dyn std::error::Error>>((object_id, manifest_hash))
    };

    let result = tokio::time::timeout(Duration::from_mins(5), flow)
        .await
        .map_err(|_elapsed| "s56 grantee v3 flow timed out".to_owned());
    mvp_s20_stop_rf_daemon(&mut alice_daemon).await?;
    mvp_s20_stop_rf_daemon(&mut bob_daemon).await?;
    let _ = std::fs::remove_file(&alice_socket);
    let _ = std::fs::remove_file(&bob_socket);
    std::fs::remove_dir_all(&temp_root).ok();
    let captured = result??;
    Ok(captured)
}

#[cfg(feature = "realnet")]
async fn mvp_s56_add_contact(
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

#[cfg(feature = "realnet")]
#[allow(clippy::too_many_lines)]
async fn mvp_s56_grant_negatives(
    node: &S8RealnetNode,
    gateway_b_quic_addr: &str,
    relay_ca: &std::path::Path,
    certificate: &ramflux_node_core::GatewayIssuerCertificate,
    object_id: &str,
    manifest_hash: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use ramflux_node_core::ObjectRelayCapability::{Ack, Get};
    let now = ramflux_node_core::now_unix_seconds();
    // Alice (the object owner) identity, reconstructed from the deterministic account device seed
    // (rf `--device-seed-byte-hex 57` -> [0x57; 32]); this must equal the attachment grant owner.
    let alice_seed = [0x57u8; 32];
    let alice_device_id = "alice_device_s56";
    let chunk_id = format!("object-relay:{object_id}:{manifest_hash}:0");

    // Register + authenticate a probe device on gateway-b so it can mint gateway-issued v3 tokens.
    let probe_device_id = "probe_device_s56";
    let probe_seed = [0x71u8; 32];
    let probe_device_hash = ramflux_crypto::blake3_256_base64url(
        "ramflux.object_relay.recipient_device.v1",
        probe_device_id.as_bytes(),
    );
    let registration = mvp_s1_identity_register_request(GatewayFrameIdentitySpec {
        principal_id: "principal_s56_probe",
        device_id: probe_device_id,
        target_delivery_id: "target_s56_probe",
        gateway_id: "gw-b",
        session_id: "pre_session_s56_probe",
        push_alias_hash: Some("push_s56_probe"),
        source_ip_hash: Some("s56_probe_source"),
        root_seed: [0x70u8; 32],
        device_seed: probe_seed,
        device_epoch: 1,
    })?;
    register_mvp1_identity(&node.gateway_url, &registration)?;
    let (_endpoint, _connection, mut send, mut recv) =
        mvp_s1_open_quic_stream(gateway_b_quic_addr.parse()?, &node.ca_cert).await?;
    let mut open = mvp_s1_open_frame(None, now, "s56-probe");
    open.client_instance_id = "rf_s56_probe".to_owned();
    open.device_id = probe_device_id.to_owned();
    open.target_delivery_id = "target_s56_probe".to_owned();
    open.stream_nonce = "nonce_s56_probe".to_owned();
    open.source_ip_hash = Some("s56_probe_source".to_owned());
    let auth =
        mvp_s1_auth_frame_for_registered_device(&open, "principal_s56_probe", 1, probe_seed)?;
    mvp_s1_write_client_frame(
        &mut send,
        &ramflux_node_core::GatewayClientFrame::Open { open: open.clone() },
    )
    .await?;
    mvp_s1_write_client_frame(&mut send, &ramflux_node_core::GatewayClientFrame::Auth { auth })
        .await?;
    let _session = mvp_s1_expect_session_established(&mut recv).await?;

    let relay = ramflux_transport::QuicGatewayClient::connect(
        "0.0.0.0:0".parse()?,
        "127.0.0.1:17447".parse()?,
        "ramflux-relay",
        relay_ca,
        std::time::Duration::from_secs(5),
    )
    .await?;

    let make_grant =
        |grantee_hash: &str,
         caps: Vec<ramflux_node_core::ObjectRelayCapability>,
         owner_seed: [u8; 32],
         owner_key_id: &str|
         -> Result<ramflux_node_core::ObjectAccessGrant, Box<dyn std::error::Error>> {
            let mut grant = ramflux_node_core::ObjectAccessGrant {
                schema: ramflux_node_core::OBJECT_ACCESS_GRANT_SCHEMA.to_owned(),
                version: ramflux_node_core::OBJECT_RELAY_V3_PROOF_VERSION,
                object_id: object_id.to_owned(),
                manifest_hash: manifest_hash.to_owned(),
                grantee_device_hash: grantee_hash.to_owned(),
                capabilities: caps,
                issued_at: now.saturating_sub(10),
                expires_at: now + 120,
                owner_signing_key_id: owner_key_id.to_owned(),
                owner_public_key: ramflux_crypto::public_key_base64url_from_seed(owner_seed),
                owner_signature: String::new(),
            };
            grant.owner_signature = ramflux_crypto::sign_canonical_bytes_with_seed(
                &ramflux_node_core::object_access_grant_signing_bytes(&grant)?,
                owner_seed,
            );
            Ok(grant)
        };

    // Authoritative, non-mutating read of the full stored chunk entry via a legit owner-authorized
    // GET (Alice grant -> probe grantee).
    let legit_grant = make_grant(&probe_device_hash, vec![Get, Ack], alice_seed, alice_device_id)?;
    let read_entry = async |send: &mut quinn::SendStream,
                            recv: &mut quinn::RecvStream,
                            tag: &str|
           -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let response = mvp_s56_v3_object_request(
            send,
            recv,
            &open,
            &relay,
            certificate,
            probe_device_id,
            probe_seed,
            &legit_grant,
            &chunk_id,
            "principal_s56_alice",
            Get,
            "get_chunk",
            "get",
            tag,
            now,
        )
        .await?;
        if response.status != 200 {
            return Err(format!("legit probe GET must return 200, got {response:?}").into());
        }
        Ok(response.body.get("chunk").cloned().ok_or("legit GET response missing chunk")?)
    };

    let entry_before = read_entry(&mut send, &mut recv, "probe-before").await?;

    // Each attack must be rejected by the relay (403) and must leave the chunk entry unchanged.
    // 1) B self-signed grant (owner = probe, not the real owner A).
    let self_signed = make_grant(&probe_device_hash, vec![Get, Ack], probe_seed, probe_device_id)?;
    // 2) Tampered A-signed grant (signature corrupted after signing).
    let mut tampered = make_grant(&probe_device_hash, vec![Get, Ack], alice_seed, alice_device_id)?;
    tampered.owner_signature = ramflux_protocol::encode_base64url(b"s56-forged-owner-signature");
    // 3) Grant addressed to a different device than the requester.
    let wrong_grantee_hash = ramflux_crypto::blake3_256_base64url(
        "ramflux.object_relay.recipient_device.v1",
        "someone_else_device_s56".as_bytes(),
    );
    let wrong_grantee =
        make_grant(&wrong_grantee_hash, vec![Get, Ack], alice_seed, alice_device_id)?;
    // 4) Grant without Ack capability, used on the ACK route.
    let get_only = make_grant(&probe_device_hash, vec![Get], alice_seed, alice_device_id)?;

    let attacks: [(
        &str,
        &ramflux_node_core::ObjectAccessGrant,
        ramflux_node_core::ObjectRelayCapability,
        &str,
        &str,
    ); 4] = [
        ("self_signed_get", &self_signed, Get, "get_chunk", "get"),
        ("tampered_get", &tampered, Get, "get_chunk", "get"),
        ("wrong_grantee_get", &wrong_grantee, Get, "get_chunk", "get"),
        ("get_only_ack", &get_only, Ack, "ack", "ack"),
    ];
    for (tag, grant, capability, route, body_capability) in attacks {
        let response = mvp_s56_v3_object_request(
            &mut send,
            &mut recv,
            &open,
            &relay,
            certificate,
            probe_device_id,
            probe_seed,
            grant,
            &chunk_id,
            "principal_s56_alice",
            capability,
            route,
            body_capability,
            tag,
            now,
        )
        .await?;
        assert_eq!(
            response.status, 403,
            "attack {tag} must be rejected 403 by the relay, got {response:?}"
        );
        let entry_after = read_entry(&mut send, &mut recv, &format!("probe-after-{tag}")).await?;
        assert_eq!(
            entry_after, entry_before,
            "attack {tag} must not mutate the authoritative relay chunk entry"
        );
    }
    Ok(())
}

#[cfg(feature = "realnet")]
#[allow(clippy::too_many_arguments)]
async fn mvp_s56_v3_object_request(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    open: &ramflux_node_core::GatewayOpenFrame,
    relay: &ramflux_transport::QuicGatewayClient,
    certificate: &ramflux_node_core::GatewayIssuerCertificate,
    requester_device_id: &str,
    requester_seed: [u8; 32],
    grant: &ramflux_node_core::ObjectAccessGrant,
    chunk_id: &str,
    owner_principal_id: &str,
    capability: ramflux_node_core::ObjectRelayCapability,
    route: &str,
    body_capability: &str,
    nonce_tag: &str,
    now: u64,
) -> Result<ramflux_transport::GatewayQuicResponse, Box<dyn std::error::Error>> {
    let binding = ramflux_node_core::object_access_grant_binding_hash(grant)?;
    let requester_device_hash = ramflux_crypto::blake3_256_base64url(
        "ramflux.object_relay.recipient_device.v1",
        requester_device_id.as_bytes(),
    );
    let body = ramflux_node_core::RelayTokenV3IssueRequest {
        requester_device_id: requester_device_id.to_owned(),
        requester_device_hash,
        requester_public_key: ramflux_crypto::public_key_base64url_from_seed(requester_seed),
        requester_device_epoch: 1,
        owner_signing_key_id: grant.owner_signing_key_id.clone(),
        owner_public_key: grant.owner_public_key.clone(),
        owner_home_node_id: "node_b.realnet".to_owned(),
        owner_principal_id: owner_principal_id.to_owned(),
        owner_device_epoch: 1,
        issuer_node_id: "node_b.realnet".to_owned(),
        gateway_instance_id: "gw-b".to_owned(),
        audience_node_id: "node_a.realnet".to_owned(),
        relay_instance_id: None,
        object_id: grant.object_id.clone(),
        manifest_hash: grant.manifest_hash.clone(),
        chunk_id: chunk_id.to_owned(),
        capabilities: vec![capability],
        authorization_kind: ramflux_node_core::RelayAuthorizationKind::OwnerGrant,
        authorization_binding_hash: binding,
        delete_after_ack: false,
        issued_at: now,
        expires_at: now + 120,
        nonce: format!("s56-neg-token-{nonce_tag}"),
        issuer_certificate: certificate.clone(),
    };
    let token = mvp_s56_issue_token(send, recv, open, body, requester_seed).await?;
    let descriptor = serde_json::json!({
        "capability": body_capability,
        "chunk_id": chunk_id,
        "manifest_hash": grant.manifest_hash,
        "object_id": grant.object_id,
    });
    let body_hash = ramflux_crypto::blake3_256_base64url(
        &format!("ramflux.object_relay.v3.{body_capability}.body"),
        &ramflux_protocol::canonical_json_bytes(&descriptor)?,
    );
    let pop = mvp_s56_pop(
        &token,
        capability,
        body_hash.clone(),
        requester_device_id,
        requester_seed,
        now,
        &format!("s56-neg-pop-{nonce_tag}"),
    )?;
    let request_body = serde_json::json!({
        "token": token,
        "certificate": token.issuer_certificate,
        "grant": grant,
        "pop": pop,
        "body_hash": body_hash,
        "capability": body_capability,
    });
    Ok(relay
        .request(&ramflux_transport::GatewayQuicRequest {
            method: "POST".to_owned(),
            path: format!("/relay/v1/object/{route}"),
            body: request_body,
        })
        .await?)
}

#[cfg(feature = "realnet")]
async fn mvp_s56_issue_token(
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
        request_id: format!("req_s56_v3_token_{}", body.nonce),
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

#[cfg(feature = "realnet")]
#[allow(clippy::too_many_arguments)]
fn mvp_s56_pop(
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

#[cfg(feature = "realnet")]
fn mvp_s56_spawn_rf_daemon_with_env(
    rf_binary: &Path,
    socket: &str,
    data_root: &str,
    env: &[(String, String)],
) -> Result<tokio::process::Child, Box<dyn std::error::Error>> {
    let child = tokio::process::Command::new(rf_binary)
        .args(["--socket", socket, "daemon", "start", "--data-root", data_root])
        .envs(env.iter().map(|(key, value)| (key.clone(), value.clone())))
        .env_remove("RAMFLUX_SDK_OBJECT_RELAY_LOCAL_MINT")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    Ok(child)
}

#[cfg(feature = "realnet")]
fn mvp_s56_relay_exec(container: &str, args: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    let output = std::process::Command::new(container_runtime())
        .arg("exec")
        .arg(container)
        .args(args)
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "relay container exec {args:?} failed: status={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(())
}

#[cfg(feature = "realnet")]
fn mvp_s56_relay_read(container: &str, path: &str) -> Result<String, Box<dyn std::error::Error>> {
    let output = std::process::Command::new(container_runtime())
        .arg("exec")
        .arg(container)
        .arg("cat")
        .arg(path)
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "failed to read relay capture {path} (read failure fails the test): status={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(feature = "realnet")]
fn mvp_s56_certificate(
    now: u64,
    node_id: &str,
    gateway_instance_id: &str,
    root_seed: [u8; 32],
    attestation_seed: [u8; 32],
) -> Result<ramflux_node_core::GatewayIssuerCertificate, Box<dyn std::error::Error>> {
    let mut certificate = ramflux_node_core::GatewayIssuerCertificate {
        schema: ramflux_node_core::GATEWAY_ISSUER_CERTIFICATE_SCHEMA.to_owned(),
        version: ramflux_node_core::OBJECT_RELAY_V3_PROOF_VERSION,
        cert_id: "s56-gw-b-cert-1".to_owned(),
        node_id: node_id.to_owned(),
        gateway_instance_id: gateway_instance_id.to_owned(),
        attestation_public_key: ramflux_crypto::public_key_base64url_from_seed(attestation_seed),
        attestation_key_id: "s56-gw-b-attestation-1".to_owned(),
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
fn mvp_s56_trust_envelope(
    now: u64,
    node_id: &str,
    root_seed: [u8; 32],
    provider_seed: [u8; 32],
    certificate: &ramflux_node_core::GatewayIssuerCertificate,
) -> Result<ramflux_node_core::ProviderSignedTrustSnapshot, Box<dyn std::error::Error>> {
    // T23-A2b2b: keyring-era v4 envelope (provider_epoch 1, authorized by the offline-root keyring).
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
            hard_stale_at: now + 300,
        },
        provider_signing_key_id: "s56-provider-1".to_owned(),
        provider_public_key: ramflux_crypto::public_key_base64url_from_seed(provider_seed),
        provider_epoch: 1,
        issued_at: now.saturating_sub(10),
        expires_at: now + 300,
        signature: String::new(),
    };
    envelope.signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &ramflux_node_core::provider_signed_trust_snapshot_signing_bytes(&envelope)?,
        provider_seed,
    );
    Ok(envelope)
}

/// T23-A2b2b: writes the offline-root-signed provider keyring (single provider key, `provider_epoch` 1).
#[cfg(feature = "realnet")]
fn mvp_s56_write_provider_keyring(
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
            key_id: "s56-provider-1".to_owned(),
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
