// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

// T21-A1: the public SDK object bus (object.put/get/tombstone) must drive the owner
// GatewayIssued v3 path over the relay client-facing QUIC listener end to end, proving the
// four operations succeed through authenticated gateway v3 issuance + relay QUIC and that no
// HTTP object request reaches the relay. This exercises the real bus dispatch in an in-process
// local-bus server (not the s54 direct relay request builder).
#![allow(unused_imports)]
// Fixtures below are consumed only by the realnet-gated test in this module; keep them
// available in all test builds but silence dead_code when the realnet tests are compiled out.
#![cfg_attr(not(feature = "realnet"), allow(dead_code))]
use super::*;

#[cfg(feature = "realnet")]
#[test]
#[allow(clippy::too_many_lines)]
fn mvp_s55_realnet_object_v3_public_sdk_owner_four_ops() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1")
        || std::env::var("RAMFLUX_OBJECT_V3").as_deref() != Ok("1")
        || std::env::var("RAMFLUX_CROSS_GATEWAY").as_deref() != Ok("1")
    {
        eprintln!(
            "skipping s55 public SDK v3 realnet; set RAMFLUX_ITEST_REALNET=1 RAMFLUX_OBJECT_V3=1 RAMFLUX_CROSS_GATEWAY=1"
        );
        return Ok(());
    }

    // Owner lineage is anchored on node_b (the v3 issuer gateway-b), and the relay that stores the
    // object is node_a; these must match the audience the relay enforces.
    let issuer_node = "node_b.realnet";
    let audience_node = "node_a.realnet";
    let owner_principal = "principal_s55_owner";

    let materials = temp_root("s55_object_v3_materials")?;
    let now = ramflux_node_core::now_unix_seconds();
    let root_seed = [0x44; 32];
    let attestation_seed = [0x33; 32];
    let provider_seed = [0x66; 32];
    let offline_root_seed = [0x88; 32]; // T23-A2b2b: offline signing root for the provider keyring
    let gateway_id = "gw-b";
    let certificate =
        mvp_s55_certificate(now, issuer_node, gateway_id, root_seed, attestation_seed)?;
    let envelope =
        mvp_s55_trust_envelope(now, issuer_node, root_seed, provider_seed, &certificate)?;
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
    mvp_s55_write_provider_keyring(&materials, now, issuer_node, offline_root_seed, provider_seed)?;

    let ports = S8ComposePorts {
        gateway_http: 64_181,
        gateway_quic: 64_451,
        router_http: 64_180,
        router_mesh: 64_452,
        notify_http: 64_183,
        federation_http: 64_182,
        federation_mesh: 64_453,
        relay_http: 64_184,
        relay_media_udp: 64_120,
        signaling_turn_udp: 64_478,
        signaling_turn_tcp: 64_479,
        retention_http: 64_187,
    };
    let node = start_s8_realnet_compose_project_with_env(
        "ramflux-s55-object-v3-sdk",
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
        ],
    )?;

    let relay_ca = node.ca_cert.clone();
    let relay_quic_addr = "127.0.0.1:17447";
    let gateway_b_quic_addr = "127.0.0.1:18444";
    let relay_url = format!("http://127.0.0.1:{}", ports.relay_http);

    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    runtime.block_on(async {
        // Confirm the relay client-facing QUIC listener is live before driving the SDK.
        let config = ramflux_transport::RelayClientQuicConfig::new(
            relay_quic_addr,
            "ramflux-relay",
            &relay_ca,
        )?;
        let health =
            ramflux_transport::relay_client_quic_health(&config, std::time::Duration::from_secs(5))
                .await?;
        assert_eq!(health.status, 200, "relay client QUIC listener must be healthy: {health:?}");

        // The public SDK reads relay QUIC transport + owner lineage from its process environment.
        // Pass them to the rf daemon child process (rather than mutating this process' globals),
        // which mirrors production where rfd is a separate process configured via env.
        let sdk_env = vec![
            ("RAMFLUX_SDK_RELAY_QUIC_ADDR".to_owned(), relay_quic_addr.to_owned()),
            ("RAMFLUX_SDK_RELAY_QUIC_SERVER_NAME".to_owned(), "ramflux-relay".to_owned()),
            ("RAMFLUX_SDK_RELAY_QUIC_CA_CERT".to_owned(), relay_ca.to_string_lossy().into_owned()),
            ("RAMFLUX_SDK_RELAY_OWNER_HOME_NODE_ID".to_owned(), issuer_node.to_owned()),
            ("RAMFLUX_SDK_RELAY_OWNER_PRINCIPAL_ID".to_owned(), owner_principal.to_owned()),
            ("RAMFLUX_SDK_RELAY_AUDIENCE_NODE_ID".to_owned(), audience_node.to_owned()),
        ];

        mvp_s55_public_sdk_owner_flow(&node, gateway_b_quic_addr, &relay_url, &sdk_env).await
    })?;

    let relay_logs = mvp_s55_container_logs("ramflux-relay");
    assert!(
        !relay_logs.contains("POST /relay/v1/object/"),
        "relay must not receive any HTTP object request in the GatewayIssued QUIC path:\n{relay_logs}"
    );

    std::fs::remove_dir_all(&materials).ok();
    Ok(())
}

#[cfg(feature = "realnet")]
#[allow(clippy::too_many_lines)]
async fn mvp_s55_public_sdk_owner_flow(
    node: &S8RealnetNode,
    gateway_b_quic_addr: &str,
    relay_url: &str,
    sdk_env: &[(String, String)],
) -> Result<(), Box<dyn std::error::Error>> {
    let temp_root = temp_root("s55_object_v3_sdk")?;
    let data_root = temp_root.join("owner/data");
    std::fs::create_dir_all(&data_root)?;
    let socket = PathBuf::from(format!("/tmp/ramflux-s55-rfd-{}.sock", std::process::id()));
    let input_path = temp_root.join("object-input.bin");
    let output_path = temp_root.join("object-output.bin");
    std::fs::create_dir_all(&temp_root)?;
    let plaintext = b"mvp_s55_public_sdk_v3_owner_object_do_not_leak_plaintext".repeat(64);
    std::fs::write(&input_path, &plaintext)?;

    let rf_binary = mvp_s4_build_rf_binary().await?;
    let ca_cert_arg = mvp_s4_path_arg(&node.ca_cert);
    let socket_arg = mvp_s4_path_arg(&socket);
    let data_root_arg = mvp_s4_path_arg(&data_root);
    let input_arg = mvp_s4_path_arg(&input_path);
    let output_arg = mvp_s4_path_arg(&output_path);

    // Run rfd as a separate process configured with the SDK relay QUIC + owner lineage env; the
    // object bus dispatch then executes inside that daemon exactly as it would in production.
    let mut daemon =
        mvp_s55_spawn_rf_daemon_with_env(&rf_binary, &socket_arg, &data_root_arg, sdk_env)?;

    let flow = async {
        mvp_s4_wait_for_socket(&socket).await?;
        // The owner account is created against gateway-b, which holds the v3 issuer material.
        mvp_s10_create_rf_account(
            &rf_binary,
            &socket_arg,
            "owner_s55_account",
            "principal_s55_owner",
            "owner_device_s55",
            "target_s55_owner",
            gateway_b_quic_addr,
            &ca_cert_arg,
            "50",
            "51",
        )
        .await?;

        // PUT: owner uploads via gateway-issued v3 token + relay QUIC.
        mvp_s4_rf_json(
            &rf_binary,
            &[
                "--socket",
                &socket_arg,
                "object",
                "put",
                "--account",
                "owner_s55_account",
                "--object",
                "object_s55_public",
                "--chunk-size",
                "1024",
                "--relay-url",
                relay_url,
                &input_arg,
            ],
        )
        .await?;
        let upload = mvp_s55_object_status(&rf_binary, &socket_arg, "upload").await?;
        assert_eq!(upload["transfer"]["state"], "complete", "put must complete over QUIC");

        // GET + ACK: owner downloads and acknowledges via the same v3 QUIC path.
        mvp_s4_rf_json(
            &rf_binary,
            &[
                "--socket",
                &socket_arg,
                "object",
                "get",
                "--account",
                "owner_s55_account",
                "--object",
                "object_s55_public",
                "--relay-url",
                relay_url,
                "--relay-ack",
                &output_arg,
            ],
        )
        .await?;
        assert_eq!(std::fs::read(&output_path)?, plaintext, "roundtrip plaintext must match");
        let download = mvp_s55_object_status(&rf_binary, &socket_arg, "download").await?;
        assert_eq!(download["transfer"]["state"], "complete", "get must complete over QUIC");

        // TOMBSTONE: owner-session tombstone via v3 QUIC (fail-closed, no HTTP fallback).
        mvp_s4_rf_json(
            &rf_binary,
            &[
                "--socket",
                &socket_arg,
                "object",
                "delete",
                "--account",
                "owner_s55_account",
                "--object",
                "object_s55_public",
                "--relay-url",
                relay_url,
            ],
        )
        .await?;

        // After tombstone the local object is no longer visible; a re-download must fail.
        let redownload = mvp_s4_rf_failure(
            &rf_binary,
            &[
                "--socket",
                &socket_arg,
                "object",
                "get",
                "--account",
                "owner_s55_account",
                "--object",
                "object_s55_public",
                "--relay-url",
                relay_url,
                &output_arg,
            ],
        )
        .await?;
        assert!(
            !redownload.is_empty(),
            "post-tombstone get must fail rather than silently return stale plaintext"
        );
        Ok::<(), Box<dyn std::error::Error>>(())
    };

    let result = tokio::time::timeout(Duration::from_mins(5), flow)
        .await
        .map_err(|_elapsed| "s55 public SDK v3 flow timed out".to_owned());
    mvp_s20_stop_rf_daemon(&mut daemon).await?;
    let _ = std::fs::remove_file(&socket);
    std::fs::remove_dir_all(&temp_root).ok();
    result??;
    Ok(())
}

#[cfg(feature = "realnet")]
fn mvp_s55_spawn_rf_daemon_with_env(
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
async fn mvp_s55_object_status(
    rf_binary: &Path,
    socket_arg: &str,
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
            "owner_s55_account",
            "--object",
            "object_s55_public",
            "--direction",
            direction,
        ],
    )
    .await
}

#[cfg(feature = "realnet")]
fn mvp_s55_container_logs(service: &str) -> String {
    let container = format!("ramflux-s55-object-v3-sdk_{service}_1");
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
fn mvp_s55_certificate(
    now: u64,
    node_id: &str,
    gateway_instance_id: &str,
    root_seed: [u8; 32],
    attestation_seed: [u8; 32],
) -> Result<ramflux_node_core::GatewayIssuerCertificate, Box<dyn std::error::Error>> {
    let mut certificate = ramflux_node_core::GatewayIssuerCertificate {
        schema: ramflux_node_core::GATEWAY_ISSUER_CERTIFICATE_SCHEMA.to_owned(),
        version: ramflux_node_core::OBJECT_RELAY_V3_PROOF_VERSION,
        cert_id: "s55-gw-b-cert-1".to_owned(),
        node_id: node_id.to_owned(),
        gateway_instance_id: gateway_instance_id.to_owned(),
        attestation_public_key: ramflux_crypto::public_key_base64url_from_seed(attestation_seed),
        attestation_key_id: "s55-gw-b-attestation-1".to_owned(),
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
fn mvp_s55_trust_envelope(
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
        provider_signing_key_id: "s55-provider-1".to_owned(),
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
fn mvp_s55_write_provider_keyring(
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
            key_id: "s55-provider-1".to_owned(),
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
