// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

// T23-A2b2b: provider signing-key (keyring) rotation over the real object-v3 stack. The default
// production relay verifies the offline-root-signed provider KEYRING and the versioned v4
// `ProviderSignedTrustSnapshot` envelope (schema `..._envelope.v4`, `provider_epoch`). Federation
// serves the offline-signed envelope verbatim (no online key); the relay pins the offline-root public
// key + keyring file out of band and persists an anti-rollback high-water (keyring_epoch,
// provider_epoch, fingerprint, accepted signer).
//
// Every probe is a real gateway-issued v3 token over relay QUIC (public rf SDK), re-evaluated against
// the relay's current cache; never a v2/HTTP fallback. Rotation is observed by reading the relay's
// persisted cache record and by rf PUT accept/deny. The flow: K1 install -> stage K2 (not-yet-valid,
// envelope rejected) -> activate K2 (successor) -> compromised-K1 seizure rejected (higher generation
// at old epoch + forged epoch) -> same-keyring-epoch content replacement rejected -> rolled-back /
// forged-root keyring rejected inert -> retire the CURRENT signer under a provider outage (fail-closed)
// -> recover via a fresh key K3 -> relay restart preserves the high-water. HTTP object stays at 0.
#![allow(unused_imports)]
#![cfg_attr(not(feature = "realnet"), allow(dead_code))]
use super::*;

#[cfg(feature = "realnet")]
const S61_PROJECT: &str = "ramflux-s61-provider-keyring-rotation";

#[cfg(feature = "realnet")]
#[test]
#[allow(clippy::too_many_lines)]
fn mvp_s61_realnet_provider_keyring_rotation() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1")
        || std::env::var("RAMFLUX_OBJECT_V3").as_deref() != Ok("1")
        || std::env::var("RAMFLUX_CROSS_GATEWAY").as_deref() != Ok("1")
    {
        eprintln!(
            "skipping s61 provider keyring rotation realnet; set RAMFLUX_ITEST_REALNET=1 RAMFLUX_OBJECT_V3=1 RAMFLUX_CROSS_GATEWAY=1"
        );
        return Ok(());
    }

    let issuer_node = "node_b.realnet";
    let audience_node = "node_a.realnet";
    let owner_principal = "principal_s61_owner";
    let gateway_id = "gw-b";

    let materials = temp_root("s61_provider_keyring_materials")?;
    let now = ramflux_node_core::now_unix_seconds();
    let attestation_seed = [0x33; 32];
    let root_seed = [0x44; 32];
    let offline_root_seed = [0x88; 32];
    let k1_seed = [0x66; 32];
    let k2_seed = [0x99; 32];
    let k3_seed = [0xa5; 32];
    let wrong_root_seed = [0x77; 32]; // a non-pinned offline root — its keyrings must be rejected

    let cert = s61_certificate(now, issuer_node, gateway_id, root_seed, attestation_seed)?;
    let ctx = S61Ctx {
        materials: materials.clone(),
        now,
        issuer_node: issuer_node.to_owned(),
        offline_root_seed,
        root_seed,
        certificate: cert.clone(),
        k1_seed,
        k2_seed,
        k3_seed,
    };

    // G1: keyring epoch 1 = {K1(provider_epoch 1)}; a K1/e1 envelope at generation 1.
    std::fs::create_dir_all(materials.join("federation"))?;
    for directory in ["gateway-a", "gateway-b"] {
        std::fs::create_dir_all(materials.join(directory))?;
        std::fs::write(
            materials.join(directory).join("issuer-cert.json"),
            serde_json::to_vec_pretty(&cert)?,
        )?;
    }
    s61_write_keyring(&ctx, 1, &[s61_key("s61-k1", k1_seed, now - 60, now + 7_200, None, 1)])?;
    s61_publish_envelope(&ctx, "s61-k1", k1_seed, 1, 1)?;

    let ports = S8ComposePorts {
        gateway_http: 64_681,
        gateway_quic: 64_951,
        router_http: 64_680,
        router_mesh: 64_952,
        notify_http: 64_683,
        federation_http: 64_682,
        federation_mesh: 64_953,
        relay_http: 64_684,
        relay_media_udp: 64_620,
        signaling_turn_udp: 64_978,
        signaling_turn_tcp: 64_979,
        retention_http: 64_687,
    };
    let node = start_s8_realnet_compose_project_with_env(
        S61_PROJECT,
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
            ("RAMFLUX_RELAY_TRUST_SNAPSHOT_REFRESH_INTERVAL_SECONDS".to_owned(), "5".to_owned()),
        ],
    )?;

    let relay_ca = node.ca_cert.clone();
    let relay_quic_addr = "127.0.0.1:17447";
    let gateway_b_quic_addr = "127.0.0.1:18444";
    let relay_url = format!("http://127.0.0.1:{}", ports.relay_http);

    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    let result = runtime.block_on(async {
        let config = ramflux_transport::RelayClientQuicConfig::new(
            relay_quic_addr,
            "ramflux-relay",
            &relay_ca,
        )?;
        let health =
            ramflux_transport::relay_client_quic_health(&config, std::time::Duration::from_secs(5))
                .await?;
        assert_eq!(health.status, 200, "relay client QUIC listener must be healthy: {health:?}");

        let sdk_env = vec![
            ("RAMFLUX_SDK_RELAY_QUIC_ADDR".to_owned(), relay_quic_addr.to_owned()),
            ("RAMFLUX_SDK_RELAY_QUIC_SERVER_NAME".to_owned(), "ramflux-relay".to_owned()),
            ("RAMFLUX_SDK_RELAY_QUIC_CA_CERT".to_owned(), relay_ca.to_string_lossy().into_owned()),
            ("RAMFLUX_SDK_RELAY_OWNER_HOME_NODE_ID".to_owned(), issuer_node.to_owned()),
            ("RAMFLUX_SDK_RELAY_OWNER_PRINCIPAL_ID".to_owned(), owner_principal.to_owned()),
            ("RAMFLUX_SDK_RELAY_AUDIENCE_NODE_ID".to_owned(), audience_node.to_owned()),
        ];
        s61_flow(&ctx, &node, gateway_b_quic_addr, &relay_url, &sdk_env, wrong_root_seed).await
    });

    let relay_logs = s61_container_logs("ramflux-relay");
    std::fs::remove_dir_all(&materials).ok();
    result?;
    assert!(
        !relay_logs.contains("POST /relay/v1/object/"),
        "relay must not receive any HTTP object request across the rotation:\n{relay_logs}"
    );
    Ok(())
}

#[cfg(feature = "realnet")]
struct S61Ctx {
    materials: PathBuf,
    now: u64,
    issuer_node: String,
    offline_root_seed: [u8; 32],
    root_seed: [u8; 32],
    certificate: ramflux_node_core::GatewayIssuerCertificate,
    k1_seed: [u8; 32],
    k2_seed: [u8; 32],
    k3_seed: [u8; 32],
}

#[cfg(feature = "realnet")]
#[allow(clippy::too_many_lines)]
async fn s61_flow(
    ctx: &S61Ctx,
    node: &S8RealnetNode,
    gateway_b_quic_addr: &str,
    relay_url: &str,
    sdk_env: &[(String, String)],
    wrong_root_seed: [u8; 32],
) -> Result<(), Box<dyn std::error::Error>> {
    let temp_root = temp_root("s61_provider_keyring_flow")?;
    let data_root = temp_root.join("owner/data");
    std::fs::create_dir_all(&data_root)?;
    let socket = PathBuf::from(format!("/tmp/ramflux-s61-rfd-{}.sock", std::process::id()));
    let input_path = temp_root.join("object-input.bin");
    std::fs::write(&input_path, b"mvp_s61_provider_keyring_rotation_v3_object".repeat(48))?;
    let output_path = temp_root.join("object-output.bin");

    let rf_binary = mvp_s4_build_rf_binary().await?;
    let ca_cert_arg = mvp_s4_path_arg(&node.ca_cert);
    let socket_arg = mvp_s4_path_arg(&socket);
    let data_root_arg = mvp_s4_path_arg(&data_root);
    let input_arg = mvp_s4_path_arg(&input_path);
    let output_arg = mvp_s4_path_arg(&output_path);
    let now = ctx.now;

    let mut daemon = s61_spawn_rf_daemon(&rf_binary, &socket_arg, &data_root_arg, sdk_env)?;
    let flow = async {
        mvp_s4_wait_for_socket(&socket).await?;
        mvp_s10_create_rf_account(
            &rf_binary,
            &socket_arg,
            "owner_s61_account",
            "principal_s61_owner",
            "owner_device_s61",
            "target_s61_owner",
            gateway_b_quic_addr,
            &ca_cert_arg,
            "50",
            "51",
        )
        .await?;

        // Step 1: K1 installed. A public-SDK PUT is accepted; the cache records K1/e1/keyring_epoch 1.
        s61_put_ok(&rf_binary, &socket_arg, relay_url, &input_arg, "object_s61_k1").await?;
        s61_assert_cache(1, 1, "s61-k1", Some(1), "G1 K1 installed")?;

        // Step 2: stage K2 at keyring_epoch 2 but not yet valid (not_before in the future); publish a
        // K2/e2 generation-2 envelope. The relay adopts the newer keyring but REJECTS the not-yet-valid
        // envelope, so the authoritative snapshot stays K1/e1 generation 1.
        s61_write_keyring(
            ctx,
            2,
            &[
                s61_key("s61-k1", ctx.k1_seed, now - 60, now + 7_200, None, 1),
                s61_key("s61-k2", ctx.k2_seed, now + 3_600, now + 7_200, None, 2),
            ],
        )?;
        s61_publish_envelope(ctx, "s61-k2", ctx.k2_seed, 2, 2)?;
        s61_wait_refresh().await;
        s61_assert_cache(2, 1, "s61-k1", Some(1), "K2 not-yet-valid envelope rejected")?;
        s61_put_ok(&rf_binary, &socket_arg, relay_url, &input_arg, "object_s61_k1b").await?;

        // Step 3: activate K2 (keyring_epoch 3, K2 not_before in the past) and publish the K2/e2
        // generation-2 successor. The relay accepts it; the provider-epoch high-water advances to 2.
        s61_write_keyring(
            ctx,
            3,
            &[
                s61_key("s61-k1", ctx.k1_seed, now - 60, now + 7_200, None, 1),
                s61_key("s61-k2", ctx.k2_seed, now - 60, now + 7_200, None, 2),
            ],
        )?;
        s61_publish_envelope(ctx, "s61-k2", ctx.k2_seed, 2, 2)?;
        s61_wait_refresh().await;
        s61_assert_cache(3, 2, "s61-k2", Some(2), "K2 activated successor")?;
        s61_put_ok(&rf_binary, &socket_arg, relay_url, &input_arg, "object_s61_k2").await?;

        // Step 4: seizure attempts by the (now-superseded) K1 — a higher snapshot generation still at
        // provider_epoch 1, and K1 forging provider_epoch 2. Both are rejected; the cache is unchanged
        // and public-SDK PUTs keep succeeding under the K2 snapshot.
        s61_publish_envelope(ctx, "s61-k1", ctx.k1_seed, 1, 3)?; // higher generation, old epoch
        s61_wait_refresh().await;
        s61_assert_cache(3, 2, "s61-k2", Some(2), "K1 higher-generation seizure rejected")?;
        s61_publish_envelope(ctx, "s61-k1", ctx.k1_seed, 2, 3)?; // K1 forging provider_epoch 2
        s61_wait_refresh().await;
        s61_assert_cache(3, 2, "s61-k2", Some(2), "K1 forged-epoch seizure rejected")?;
        // Restore the legitimate K2 envelope for the following steps.
        s61_publish_envelope(ctx, "s61-k2", ctx.k2_seed, 2, 2)?;
        s61_wait_refresh().await;

        // Step 5: a same-keyring-epoch content replacement (offline-root-signed but different content)
        // is rejected; the keyring_epoch high-water does not move.
        s61_write_keyring(
            ctx,
            3,
            &[
                s61_key("s61-k1", ctx.k1_seed, now - 60, now + 7_200, None, 1),
                // same epoch 3 but K2 window changed => different fingerprint.
                s61_key("s61-k2", ctx.k2_seed, now - 120, now + 9_000, None, 2),
            ],
        )?;
        s61_wait_refresh().await;
        s61_assert_cache(
            3,
            2,
            "s61-k2",
            Some(2),
            "same-keyring-epoch content replacement rejected",
        )?;

        // Step 6: a rolled-back keyring (epoch 1) and a forged-root keyring (wrong offline root) are
        // both rejected; the cache stays at keyring_epoch 3. Then restore the valid epoch-3 keyring.
        s61_write_keyring(
            ctx,
            1,
            &[s61_key("s61-k1", ctx.k1_seed, now - 60, now + 7_200, None, 1)],
        )?;
        s61_wait_refresh().await;
        s61_assert_cache(3, 2, "s61-k2", Some(2), "rolled-back keyring rejected")?;
        s61_write_keyring_signed_with(
            ctx,
            wrong_root_seed,
            4,
            &[
                s61_key("s61-k1", ctx.k1_seed, now - 60, now + 7_200, None, 1),
                s61_key("s61-k2", ctx.k2_seed, now - 60, now + 7_200, None, 2),
            ],
        )?;
        s61_wait_refresh().await;
        s61_assert_cache(3, 2, "s61-k2", Some(2), "forged-root keyring rejected")?;
        s61_write_keyring(
            ctx,
            3,
            &[
                s61_key("s61-k1", ctx.k1_seed, now - 60, now + 7_200, None, 1),
                s61_key("s61-k2", ctx.k2_seed, now - 60, now + 7_200, None, 2),
            ],
        )?;
        s61_wait_refresh().await;

        // Step 7: retire the CURRENT signer (K2) at keyring_epoch 4 while federation is DOWN (a
        // provider outage: no fresh envelope). The relay adopts the retiring keyring and fails the
        // cached snapshot closed. A public-SDK PUT is denied; the object never stores.
        s61_write_keyring(
            ctx,
            4,
            &[
                s61_key("s61-k1", ctx.k1_seed, now - 60, now + 7_200, None, 1),
                s61_key("s61-k2", ctx.k2_seed, now - 60, now + 7_200, Some(now - 1), 2),
            ],
        )?;
        s61_container_ctl("stop", "ramflux-federation")?;
        s61_wait_refresh().await;
        s61_assert_cache(4, 2, "s61-k2", None, "current signer retired under outage: fail-closed")?;
        s61_put_denied(
            &rf_binary,
            &socket_arg,
            relay_url,
            &input_arg,
            "object_s61_retired",
            "current signer retired",
        )
        .await?;

        // Step 8: recover via a fresh key K3 at keyring_epoch 5. Restart federation, publish the
        // keyring + a K3/e3 generation-3 envelope; the relay recovers and PUTs succeed again.
        s61_container_ctl("start", "ramflux-federation")?;
        s61_wait_federation_healthy(node).await?;
        s61_write_keyring(
            ctx,
            5,
            &[
                s61_key("s61-k1", ctx.k1_seed, now - 60, now + 7_200, None, 1),
                s61_key("s61-k2", ctx.k2_seed, now - 60, now + 7_200, Some(now - 1), 2),
                s61_key("s61-k3", ctx.k3_seed, now - 60, now + 7_200, None, 3),
            ],
        )?;
        s61_publish_envelope(ctx, "s61-k3", ctx.k3_seed, 3, 3)?;
        s61_wait_refresh().await;
        s61_assert_cache(5, 3, "s61-k3", Some(3), "recovered via K3 successor")?;
        s61_put_ok(&rf_binary, &socket_arg, relay_url, &input_arg, "object_s61_recover").await?;

        // Step 9: restart the relay; the persisted high-water (keyring_epoch 5, provider_epoch 3,
        // signer K3, generation 3) survives, and PUTs keep succeeding.
        s61_container_ctl("restart", "ramflux-relay")?;
        s61_wait_relay_quic_healthy(&node.ca_cert).await?;
        s61_assert_cache(5, 3, "s61-k3", Some(3), "high-water preserved across relay restart")?;
        s61_put_ok(&rf_binary, &socket_arg, relay_url, &input_arg, "object_s61_restart").await?;

        // Store invariant: the retired-signer PUT was denied before any store mutation, so it is not
        // retrievable now that K3 authorization is restored (reachable-but-absent).
        s61_get_absent(
            &rf_binary,
            &socket_arg,
            relay_url,
            &output_arg,
            "object_s61_retired",
            "denied retired-signer object",
        )
        .await?;

        Ok::<(), Box<dyn std::error::Error>>(())
    };

    let result = tokio::time::timeout(std::time::Duration::from_mins(16), flow)
        .await
        .map_err(|_elapsed| "s61 provider keyring rotation flow timed out".to_owned());
    mvp_s20_stop_rf_daemon(&mut daemon).await?;
    let _ = std::fs::remove_file(&socket);
    std::fs::remove_dir_all(&temp_root).ok();
    result??;
    Ok(())
}

// ─── keyring + envelope material helpers ──────────────────────────────────────────────────────────

#[cfg(feature = "realnet")]
fn s61_key(
    key_id: &str,
    seed: [u8; 32],
    not_before: u64,
    not_after: u64,
    retired_at: Option<u64>,
    authorized_provider_epoch: u64,
) -> ramflux_node_core::ProviderKeyEntry {
    ramflux_node_core::ProviderKeyEntry {
        key_id: key_id.to_owned(),
        public_key: ramflux_crypto::public_key_base64url_from_seed(seed),
        not_before,
        not_after,
        retired_at,
        authorized_provider_epoch,
    }
}

#[cfg(feature = "realnet")]
fn s61_write_keyring(
    ctx: &S61Ctx,
    keyring_epoch: u64,
    keys: &[ramflux_node_core::ProviderKeyEntry],
) -> Result<(), Box<dyn std::error::Error>> {
    s61_write_keyring_signed_with(ctx, ctx.offline_root_seed, keyring_epoch, keys)
}

#[cfg(feature = "realnet")]
fn s61_write_keyring_signed_with(
    ctx: &S61Ctx,
    offline_root_seed: [u8; 32],
    keyring_epoch: u64,
    keys: &[ramflux_node_core::ProviderKeyEntry],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut keyring = ramflux_node_core::ProviderKeyring {
        schema: ramflux_node_core::PROVIDER_KEYRING_SCHEMA.to_owned(),
        version: ramflux_node_core::PROVIDER_KEYRING_VERSION,
        issuer_node_id: ctx.issuer_node.clone(),
        keyring_epoch,
        keys: keys.to_vec(),
        keyring_signature: String::new(),
    };
    keyring.keyring_signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &ramflux_node_core::provider_keyring_signing_bytes(&keyring)?,
        offline_root_seed,
    );
    let target = ctx.materials.join("federation/provider-keyring.json");
    let tmp = ctx.materials.join("federation/.provider-keyring.json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(&keyring)?)?;
    std::fs::rename(&tmp, &target)?;
    Ok(())
}

#[cfg(feature = "realnet")]
fn s61_publish_envelope(
    ctx: &S61Ctx,
    signing_key_id: &str,
    signing_seed: [u8; 32],
    provider_epoch: u64,
    generation: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut envelope = ramflux_node_core::ProviderSignedTrustSnapshot {
        schema: ramflux_node_core::PROVIDER_SIGNED_TRUST_SNAPSHOT_ENVELOPE_SCHEMA.to_owned(),
        version: ramflux_node_core::PROVIDER_SIGNED_TRUST_SNAPSHOT_ENVELOPE_VERSION,
        snapshot: ramflux_node_core::FederatedIssuerTrustSnapshot {
            schema: ramflux_node_core::FEDERATED_ISSUER_TRUST_SNAPSHOT_SCHEMA.to_owned(),
            version: ramflux_node_core::OBJECT_RELAY_V3_PROOF_VERSION,
            node_id: ctx.issuer_node.clone(),
            generation,
            pin_epoch: 1,
            trust_status: ramflux_node_core::FederatedIssuerTrustStatus::Active,
            roots: vec![ramflux_node_core::TrustedNodeRootKey {
                node_id: ctx.issuer_node.clone(),
                key_id: ctx.certificate.node_root_signing_key_id.clone(),
                public_key: ramflux_crypto::public_key_base64url_from_seed(ctx.root_seed),
                not_before: ctx.now.saturating_sub(60),
                not_after: ctx.now + 7_200,
                pin_epoch: 1,
                retired_at: None,
            }],
            revoked_cert_ids: std::collections::BTreeSet::new(),
            hard_stale_at: ctx.now + 7_200,
        },
        provider_signing_key_id: signing_key_id.to_owned(),
        provider_public_key: ramflux_crypto::public_key_base64url_from_seed(signing_seed),
        provider_epoch,
        issued_at: ctx.now.saturating_sub(10),
        expires_at: ctx.now + 7_200,
        signature: String::new(),
    };
    envelope.signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &ramflux_node_core::provider_signed_trust_snapshot_signing_bytes(&envelope)?,
        signing_seed,
    );
    let target = ctx.materials.join("federation/trust-snapshot.json");
    let tmp = ctx.materials.join("federation/.trust-snapshot.json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(&envelope)?)?;
    std::fs::rename(&tmp, &target)?;
    Ok(())
}

#[cfg(feature = "realnet")]
fn s61_certificate(
    now: u64,
    node_id: &str,
    gateway_instance_id: &str,
    root_seed: [u8; 32],
    attestation_seed: [u8; 32],
) -> Result<ramflux_node_core::GatewayIssuerCertificate, Box<dyn std::error::Error>> {
    let mut certificate = ramflux_node_core::GatewayIssuerCertificate {
        schema: ramflux_node_core::GATEWAY_ISSUER_CERTIFICATE_SCHEMA.to_owned(),
        version: ramflux_node_core::OBJECT_RELAY_V3_PROOF_VERSION,
        cert_id: "s61-cert-1".to_owned(),
        node_id: node_id.to_owned(),
        gateway_instance_id: gateway_instance_id.to_owned(),
        attestation_public_key: ramflux_crypto::public_key_base64url_from_seed(attestation_seed),
        attestation_key_id: "s61-attestation-1".to_owned(),
        not_before: now.saturating_sub(60),
        not_after: now + 7_200,
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

// ─── cache assertions (read the relay's persisted PersistedKeyringTrust record) ───────────────────

/// Asserts the relay's persisted keyring-era cache record: `keyring_epoch`/`provider_epoch` high-water,
/// the accepted signer key id, and the authoritative snapshot generation (`None` when the cache is
/// fail-closed with no envelope).
#[cfg(feature = "realnet")]
fn s61_assert_cache(
    keyring_epoch: u64,
    provider_epoch: u64,
    signer_key_id: &str,
    generation: Option<u64>,
    label: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let container = s61_container("ramflux-relay");
    let output = std::process::Command::new(container_runtime())
        .args(["exec", &container, "cat", "/var/lib/ramflux/relay/trust-snapshot.json"])
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "{label}: read relay keyring cache failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    let record: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(
        record["keyring_epoch_high_water"], keyring_epoch,
        "{label}: keyring_epoch_high_water"
    );
    assert_eq!(
        record["provider_epoch_high_water"], provider_epoch,
        "{label}: provider_epoch_high_water"
    );
    assert_eq!(record["accepted_signer_key_id"], signer_key_id, "{label}: accepted signer");
    match generation {
        Some(generation) => assert_eq!(
            record["envelope"]["snapshot"]["generation"], generation,
            "{label}: authoritative snapshot generation"
        ),
        None => assert!(
            record["envelope"].is_null(),
            "{label}: cache must be fail-closed (no authoritative envelope)"
        ),
    }
    Ok(())
}

// ─── rf-CLI probes + container control (self-contained copies) ────────────────────────────────────

#[cfg(feature = "realnet")]
async fn s61_put_ok(
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
            "owner_s61_account",
            "--object",
            object_id,
            "--chunk-size",
            "1024",
            "--relay-url",
            relay_url,
            input_arg,
        ],
    )
    .await?;
    let status = mvp_s4_rf_json(
        rf_binary,
        &[
            "--socket",
            socket_arg,
            "object",
            "status",
            "--account",
            "owner_s61_account",
            "--object",
            object_id,
            "--direction",
            "upload",
        ],
    )
    .await?;
    assert_eq!(
        status["transfer"]["state"], "complete",
        "{object_id}: put must complete over v3 QUIC"
    );
    Ok(())
}

#[cfg(feature = "realnet")]
async fn s61_put_denied(
    rf_binary: &Path,
    socket_arg: &str,
    relay_url: &str,
    input_arg: &str,
    object_id: &str,
    label: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let failure = mvp_s4_rf_failure(
        rf_binary,
        &[
            "--socket",
            socket_arg,
            "object",
            "put",
            "--account",
            "owner_s61_account",
            "--object",
            object_id,
            "--chunk-size",
            "1024",
            "--relay-url",
            relay_url,
            input_arg,
        ],
    )
    .await?;
    assert!(!failure.is_empty(), "{label}: put must fail closed, not silently succeed");
    Ok(())
}

#[cfg(feature = "realnet")]
async fn s61_get_absent(
    rf_binary: &Path,
    socket_arg: &str,
    relay_url: &str,
    output_arg: &str,
    object_id: &str,
    label: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let _ = std::fs::remove_file(output_arg);
    let failure = mvp_s4_rf_failure(
        rf_binary,
        &[
            "--socket",
            socket_arg,
            "object",
            "get",
            "--account",
            "owner_s61_account",
            "--object",
            object_id,
            "--relay-url",
            relay_url,
            output_arg,
        ],
    )
    .await?;
    assert!(!failure.is_empty(), "{label}: denied object must not be retrievable");
    assert!(
        std::fs::metadata(output_arg).is_err(),
        "{label}: denied object GET must not write any plaintext"
    );
    Ok(())
}

#[cfg(feature = "realnet")]
fn s61_spawn_rf_daemon(
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
async fn s61_wait_refresh() {
    tokio::time::sleep(Duration::from_secs(14)).await;
}

#[cfg(feature = "realnet")]
fn s61_container(service: &str) -> String {
    format!("{S61_PROJECT}_{service}_1")
}

#[cfg(feature = "realnet")]
fn s61_container_ctl(action: &str, service: &str) -> Result<(), Box<dyn std::error::Error>> {
    let container = s61_container(service);
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
fn s61_container_logs(service: &str) -> String {
    let container = s61_container(service);
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
async fn s61_wait_relay_quic_healthy(ca_cert: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let config =
        ramflux_transport::RelayClientQuicConfig::new("127.0.0.1:17447", "ramflux-relay", ca_cert)?;
    for _ in 0..30 {
        if let Ok(health) =
            ramflux_transport::relay_client_quic_health(&config, std::time::Duration::from_secs(3))
                .await
            && health.status == 200
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    Err("relay client QUIC did not become healthy after restart".into())
}

#[cfg(feature = "realnet")]
async fn s61_wait_federation_healthy(
    node: &S8RealnetNode,
) -> Result<(), Box<dyn std::error::Error>> {
    // The relay refreshes on its own interval; a couple of refresh windows after federation restarts
    // are enough for the next fetch to land. Give it time before publishing the recovery envelope.
    let _ = node;
    tokio::time::sleep(Duration::from_secs(8)).await;
    Ok(())
}
