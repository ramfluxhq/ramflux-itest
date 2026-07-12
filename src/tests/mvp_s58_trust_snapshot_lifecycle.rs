// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

// T23-A1: federation trust snapshot lifecycle over the real object-v3 stack. Proves the relay's
// live snapshot refresh, fail-closed status/hard-stale gating, monotonic rollback rejection, and
// restart-resume from the persistent cache — all through gateway-issued v3 + relay QUIC, never a
// v2/HTTP object fallback. The federation node hot-reads its served snapshot file per request and
// the relay refreshes on a short interval, so the test publishes new signed generations by an
// atomic rename into the materials directory (the read-only container mount still observes host
// writes). It exercises two branches: (1) node-status Active->Suspended->Active (a Suspended snapshot
// is admitted to the cache yet fails requests closed at read time — T23-A1a), plus relay restart and
// hard-stale; and (2) certificate revocation with a monotonic CRL — a successor that drops a revoked
// cert id is rejected. Recovering a revoked certificate requires rotation (deferred to T23-A2).
#![allow(unused_imports)]
#![cfg_attr(not(feature = "realnet"), allow(dead_code))]
use super::*;

#[cfg(feature = "realnet")]
const S58_PROJECT: &str = "ramflux-s58-trust-lifecycle";
#[cfg(feature = "realnet")]
const S58_PROVIDER_KEY_ID: &str = "s58-provider-1";

#[cfg(feature = "realnet")]
#[test]
#[allow(clippy::too_many_lines)]
fn mvp_s58_realnet_trust_snapshot_lifecycle() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1")
        || std::env::var("RAMFLUX_OBJECT_V3").as_deref() != Ok("1")
        || std::env::var("RAMFLUX_CROSS_GATEWAY").as_deref() != Ok("1")
    {
        eprintln!(
            "skipping s58 trust snapshot lifecycle realnet; set RAMFLUX_ITEST_REALNET=1 RAMFLUX_OBJECT_V3=1 RAMFLUX_CROSS_GATEWAY=1"
        );
        return Ok(());
    }

    let issuer_node = "node_b.realnet";
    let audience_node = "node_a.realnet";
    let owner_principal = "principal_s58_owner";
    let gateway_id = "gw-b";

    let materials = temp_root("s58_trust_lifecycle_materials")?;
    let now = ramflux_node_core::now_unix_seconds();
    let root_seed = [0x44; 32];
    let attestation_seed = [0x33; 32];
    let provider_seed = [0x66; 32];
    let wrong_provider_seed = [0x77; 32];
    // T23-A2b2b: the offline signing root that authorizes the provider keyring (independent of the
    // provider key). The relay pins its public key out of band.
    let offline_root_seed = [0x88; 32];

    let certificate = s58_certificate(now, issuer_node, gateway_id, root_seed, attestation_seed)?;
    // G1 Active, empty CRL, long hard-stale window; later generations manipulate status/CRL/hard_stale.
    let g1 = s58_trust_envelope(
        now,
        issuer_node,
        root_seed,
        provider_seed,
        &certificate,
        1,
        1,
        ramflux_node_core::FederatedIssuerTrustStatus::Active,
        std::collections::BTreeSet::new(),
        now + 3_600,
    )?;
    for directory in ["gateway-a", "gateway-b"] {
        std::fs::create_dir_all(materials.join(directory))?;
        std::fs::write(
            materials.join(directory).join("issuer-cert.json"),
            serde_json::to_vec_pretty(&certificate)?,
        )?;
    }
    std::fs::create_dir_all(materials.join("federation"))?;
    s58_publish_snapshot(&materials, &g1)?;
    s58_write_provider_keyring(&materials, now, issuer_node, offline_root_seed, provider_seed)?;

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
    let node = start_s8_realnet_compose_project_with_env(
        S58_PROJECT,
        ports,
        &[
            ("RAMFLUX_V3_MATERIALS_DIR".to_owned(), materials.to_string_lossy().into_owned()),
            (
                "RAMFLUX_GATEWAY_B_V3_ISSUER_SEED".to_owned(),
                ramflux_protocol::encode_base64url(attestation_seed),
            ),
            // T23-A2b2b: keyring-era relay trust — pin the offline-root public key + the served keyring
            // file path (the default/production relay verifies the v4 envelope against this keyring).
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
            // Short refresh so the test observes generation transitions quickly (real TTL, no clock bypass).
            ("RAMFLUX_RELAY_TRUST_SNAPSHOT_REFRESH_INTERVAL_SECONDS".to_owned(), "5".to_owned()),
        ],
    )?;

    let relay_ca = node.ca_cert.clone();
    let relay_quic_addr = "127.0.0.1:17447";
    let gateway_b_quic_addr = "127.0.0.1:18444";
    let relay_url = format!("http://127.0.0.1:{}", ports.relay_http);

    let ctx = S58Ctx {
        materials: materials.clone(),
        now,
        issuer_node: issuer_node.to_owned(),
        root_seed,
        provider_seed,
        wrong_provider_seed,
        certificate,
    };

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
        s58_lifecycle_flow(&ctx, &node, gateway_b_quic_addr, &relay_url, &sdk_env).await
    });

    // Regardless of outcome, the GatewayIssued v3 path must never fall back to an HTTP object request.
    let relay_logs = s58_container_logs("ramflux-relay");
    if let Err(error) = &result {
        // On failure, surface the relay + federation snapshot refresh/serve logs so the exact
        // generation the relay installed (or rejected) is visible.
        eprintln!("s58 lifecycle failed: {error}");
        eprintln!(
            "=== relay trust-snapshot logs ===\n{}",
            relay_logs
                .lines()
                .filter(|line| line.contains("trust snapshot")
                    || line.contains("trust_snapshot")
                    || line.contains("generation")
                    || line.contains("fail-closed")
                    || line.contains("hard_stale")
                    || line.contains("Suspended"))
                .collect::<Vec<_>>()
                .join("\n")
        );
        eprintln!(
            "=== federation snapshot logs ===\n{}",
            s58_container_logs("ramflux-federation")
                .lines()
                .filter(|line| line.contains("trust") || line.contains("snapshot"))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
    std::fs::remove_dir_all(&materials).ok();
    result?;
    assert!(
        !relay_logs.contains("POST /relay/v1/object/"),
        "relay must not receive any HTTP object request across the lifecycle:\n{relay_logs}"
    );
    Ok(())
}

#[cfg(feature = "realnet")]
struct S58Ctx {
    materials: PathBuf,
    now: u64,
    issuer_node: String,
    root_seed: [u8; 32],
    provider_seed: [u8; 32],
    wrong_provider_seed: [u8; 32],
    certificate: ramflux_node_core::GatewayIssuerCertificate,
}

#[cfg(feature = "realnet")]
#[allow(clippy::too_many_lines)]
async fn s58_lifecycle_flow(
    ctx: &S58Ctx,
    node: &S8RealnetNode,
    gateway_b_quic_addr: &str,
    relay_url: &str,
    sdk_env: &[(String, String)],
) -> Result<(), Box<dyn std::error::Error>> {
    let temp_root = temp_root("s58_trust_lifecycle_flow")?;
    let data_root = temp_root.join("owner/data");
    std::fs::create_dir_all(&data_root)?;
    let socket = PathBuf::from(format!("/tmp/ramflux-s58-rfd-{}.sock", std::process::id()));
    let input_path = temp_root.join("object-input.bin");
    let output_path = temp_root.join("object-output.bin");
    let plaintext = b"mvp_s58_trust_lifecycle_v3_owner_object_stays_opaque".repeat(48);
    std::fs::write(&input_path, &plaintext)?;

    let rf_binary = mvp_s4_build_rf_binary().await?;
    let ca_cert_arg = mvp_s4_path_arg(&node.ca_cert);
    let socket_arg = mvp_s4_path_arg(&socket);
    let data_root_arg = mvp_s4_path_arg(&data_root);
    let input_arg = mvp_s4_path_arg(&input_path);
    let output_arg = mvp_s4_path_arg(&output_path);

    let mut daemon =
        s58_spawn_rf_daemon_with_env(&rf_binary, &socket_arg, &data_root_arg, sdk_env)?;

    let flow = async {
        mvp_s4_wait_for_socket(&socket).await?;
        mvp_s10_create_rf_account(
            &rf_binary,
            &socket_arg,
            "owner_s58_account",
            "principal_s58_owner",
            "owner_device_s58",
            "target_s58_owner",
            gateway_b_quic_addr,
            &ca_cert_arg,
            "50",
            "51",
        )
        .await?;

        let revoked_of = |ids: &[&str]| {
            ids.iter().map(|id| (*id).to_owned()).collect::<std::collections::BTreeSet<String>>()
        };
        let cert_id = ctx.certificate.cert_id.clone();

        // ---- Node-status branch (Active -> Suspended -> Active), then restart + hard-stale ----

        // Step 1: G1 Active — a fresh PUT and a GET roundtrip both succeed (full v3 object path).
        // Each probe uses a distinct object id so the upload always makes a real relay round-trip.
        s58_put_ok(&rf_binary, &socket_arg, relay_url, &input_arg, "object_s58_g1").await?;
        let g1_download =
            s58_get_roundtrip(&rf_binary, &socket_arg, relay_url, &output_arg, "object_s58_g1")
                .await?;
        assert_eq!(g1_download, plaintext, "G1 Active roundtrip plaintext must match");

        // Step 2: publish a real Suspended G2. It is ADMITTED to the cache (generation advances to 2)
        // yet the read path is Active-only, so a fresh PUT is fail-closed (403). The old Active is not
        // retained — node-level suspension actually takes effect (T23-A1a).
        s58_publish_status(
            ctx,
            2,
            ramflux_node_core::FederatedIssuerTrustStatus::Suspended,
            ctx.now + 3_600,
        )?;
        s58_wait_refresh().await;
        s58_assert_cache(2, "suspended", "G2 installed")?;
        s58_put_denied(
            &rf_binary,
            &socket_arg,
            relay_url,
            &input_arg,
            "object_s58_g2",
            "G2 Suspended",
        )
        .await?;

        // Step 2b (T23-A1a closure): the Suspended state must survive a relay restart WITHOUT the
        // provider online. Stop the federation provider FIRST (so no background refresh can re-fetch
        // an Active and mask the test), restart the relay, and confirm it re-loads and re-verifies the
        // persisted G2 Suspended cache and still fails requests closed — a persisted non-Active
        // snapshot must not fail open on restart.
        s58_container_ctl("stop", "ramflux-federation")?;
        s58_container_ctl("restart", "ramflux-relay")?;
        s58_wait_relay_quic_healthy(&node.ca_cert).await?;
        s58_assert_cache(2, "suspended", "G2 persisted across restart (provider down)")?;
        s58_put_denied(
            &rf_binary,
            &socket_arg,
            relay_url,
            &input_arg,
            "object_s58_g2r",
            "G2 Suspended after restart",
        )
        .await?;
        s58_container_ctl("start", "ramflux-federation")?;

        // Step 3: rollback (old G1) and forged (wrong-provider) snapshots must be rejected and leave
        // the installed Suspended G2 in force (still 403, cache still generation 2).
        let g1_rollback = s58_trust_envelope(
            ctx.now,
            &ctx.issuer_node,
            ctx.root_seed,
            ctx.provider_seed,
            &ctx.certificate,
            1,
            1,
            ramflux_node_core::FederatedIssuerTrustStatus::Active,
            std::collections::BTreeSet::new(),
            ctx.now + 3_600,
        )?;
        s58_publish_snapshot(&ctx.materials, &g1_rollback)?;
        s58_wait_refresh().await;
        let g2_forged = s58_trust_envelope_signed_with(
            ctx.now,
            &ctx.issuer_node,
            ctx.root_seed,
            ctx.wrong_provider_seed,
            ctx.provider_seed,
            &ctx.certificate,
            3,
            3,
            ramflux_node_core::FederatedIssuerTrustStatus::Active,
            std::collections::BTreeSet::new(),
            ctx.now + 3_600,
        )?;
        s58_publish_snapshot(&ctx.materials, &g2_forged)?;
        s58_wait_refresh().await;
        s58_assert_cache(2, "suspended", "rollback/forged rejected")?;
        s58_put_denied(
            &rf_binary,
            &socket_arg,
            relay_url,
            &input_arg,
            "object_s58_g3",
            "rollback/forged rejected",
        )
        .await?;

        // Step 4: a valid Active G3 recovers the node status; a fresh PUT is restored.
        s58_publish_status(
            ctx,
            3,
            ramflux_node_core::FederatedIssuerTrustStatus::Active,
            ctx.now + 3_600,
        )?;
        s58_wait_refresh().await;
        s58_assert_cache(3, "active", "G3 recovered")?;
        s58_put_ok(&rf_binary, &socket_arg, relay_url, &input_arg, "object_s58_g4").await?;

        // Step 5: restart the relay container — it must re-load and re-verify the persistent G3 cache
        // and, before hard-stale, keep accepting. (Federation still up.)
        s58_container_ctl("restart", "ramflux-relay")?;
        s58_wait_relay_quic_healthy(&node.ca_cert).await?;
        s58_put_ok(&rf_binary, &socket_arg, relay_url, &input_arg, "object_s58_g5").await?;

        // Step 6: publish Active G4 with a SHORT hard-stale window; confirm it accepts, then stop the
        // provider and let now cross hard_stale_at. The relay keeps the last good G4 cache but must
        // reject once it is hard-stale — even though the provider is unreachable (no HTTP/v2 fallback).
        let hard_stale_at = ramflux_node_core::now_unix_seconds() + 60;
        s58_publish_status(
            ctx,
            4,
            ramflux_node_core::FederatedIssuerTrustStatus::Active,
            hard_stale_at,
        )?;
        s58_wait_refresh().await;
        s58_put_ok(&rf_binary, &socket_arg, relay_url, &input_arg, "object_s58_g6a").await?;
        s58_container_ctl("stop", "ramflux-federation")?;
        s58_sleep_until(hard_stale_at + 5).await;
        s58_put_denied(
            &rf_binary,
            &socket_arg,
            relay_url,
            &input_arg,
            "object_s58_g6b",
            "hard-stale 403",
        )
        .await?;

        // Step 7: restart the provider and publish a monotonic Active G5 (long window) — the relay
        // recovers and a fresh PUT succeeds again.
        s58_container_ctl("start", "ramflux-federation")?;
        let now5 = ramflux_node_core::now_unix_seconds();
        s58_publish_status(
            ctx,
            5,
            ramflux_node_core::FederatedIssuerTrustStatus::Active,
            now5 + 3_600,
        )?;
        s58_wait_refresh().await;
        s58_wait_refresh().await;
        s58_put_ok(&rf_binary, &socket_arg, relay_url, &input_arg, "object_s58_g7").await?;

        // ---- Certificate revocation branch (monotonic CRL; runs last since the CRL is terminal) ----

        // Step 8: publish Active G6 whose CRL revokes the gateway issuer certificate. The snapshot is
        // Active (node is fine) but the specific issuer cert is revoked, so a fresh PUT is 403.
        let now6 = ramflux_node_core::now_unix_seconds();
        s58_publish_revoked(ctx, 6, revoked_of(&[cert_id.as_str()]), now6 + 3_600)?;
        s58_wait_refresh().await;
        s58_assert_cache(6, "active", "G6 cert-revoked")?;
        let revoked_snap = s58_read_cache_snapshot()?;
        assert!(
            revoked_snap["revoked_cert_ids"]
                .as_array()
                .is_some_and(|ids| ids.iter().any(|id| id == cert_id.as_str())),
            "G6: installed cache must list the revoked cert"
        );
        s58_put_denied(
            &rf_binary,
            &socket_arg,
            relay_url,
            &input_arg,
            "object_s58_g8",
            "G6 cert revoked",
        )
        .await?;

        // Step 9: a G7 that DROPS the cert from the CRL (a silent revocation withdrawal) must be
        // rejected by the relay's monotonic-CRL successor rule; the cache stays G6 and PUT stays 403.
        // Recovering a revoked certificate requires a new certificate / rotation (deferred).
        s58_publish_revoked(ctx, 7, std::collections::BTreeSet::new(), now6 + 3_600)?;
        s58_wait_refresh().await;
        s58_assert_cache(6, "active", "G7 CRL-shrink rejected, cache unchanged")?;
        s58_put_denied(
            &rf_binary,
            &socket_arg,
            relay_url,
            &input_arg,
            "object_s58_g9",
            "G7 CRL shrink rejected",
        )
        .await?;

        Ok::<(), Box<dyn std::error::Error>>(())
    };

    let result = tokio::time::timeout(Duration::from_mins(16), flow)
        .await
        .map_err(|_elapsed| "s58 trust lifecycle flow timed out".to_owned());
    mvp_s20_stop_rf_daemon(&mut daemon).await?;
    let _ = std::fs::remove_file(&socket);
    std::fs::remove_dir_all(&temp_root).ok();
    result??;
    Ok(())
}

/// A fresh-object PUT that must succeed over the gateway-issued v3 QUIC path — proving the relay
/// currently accepts the owner. Each probe uses a distinct object id so the upload always makes a
/// real relay round-trip (never served from the daemon's local store).
#[cfg(feature = "realnet")]
async fn s58_put_ok(
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
            "owner_s58_account",
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
            "owner_s58_account",
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

/// A fresh-object PUT that must be rejected by the relay trust gate (fail-closed). A denied put
/// returns an error from the SDK and never stores the object, so the relay store is unchanged.
#[cfg(feature = "realnet")]
async fn s58_put_denied(
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
            "owner_s58_account",
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

/// A GET roundtrip that must succeed and return the original plaintext (used once under G1 to prove
/// the full v3 object path end to end).
#[cfg(feature = "realnet")]
async fn s58_get_roundtrip(
    rf_binary: &Path,
    socket_arg: &str,
    relay_url: &str,
    output_arg: &str,
    object_id: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let _ = std::fs::remove_file(output_arg);
    mvp_s4_rf_json(
        rf_binary,
        &[
            "--socket",
            socket_arg,
            "object",
            "get",
            "--account",
            "owner_s58_account",
            "--object",
            object_id,
            "--relay-url",
            relay_url,
            output_arg,
        ],
    )
    .await?;
    Ok(std::fs::read(output_arg)?)
}

#[cfg(feature = "realnet")]
/// Publish a snapshot at `generation` with a real node `status` and an empty CRL (the node-status
/// branch: Active/Suspended/Active recovery, hard-stale windows).
fn s58_publish_status(
    ctx: &S58Ctx,
    generation: u64,
    status: ramflux_node_core::FederatedIssuerTrustStatus,
    hard_stale_at: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let envelope = s58_trust_envelope(
        ctx.now,
        &ctx.issuer_node,
        ctx.root_seed,
        ctx.provider_seed,
        &ctx.certificate,
        generation,
        1,
        status,
        std::collections::BTreeSet::new(),
        hard_stale_at,
    )?;
    s58_publish_snapshot(&ctx.materials, &envelope)
}

/// Publish an Active snapshot at `generation` whose CRL contains `revoked_cert_ids` (the CRL branch:
/// revoke the gateway cert; a later successor may only grow, never shrink, the CRL).
#[cfg(feature = "realnet")]
fn s58_publish_revoked(
    ctx: &S58Ctx,
    generation: u64,
    revoked_cert_ids: std::collections::BTreeSet<String>,
    hard_stale_at: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let envelope = s58_trust_envelope(
        ctx.now,
        &ctx.issuer_node,
        ctx.root_seed,
        ctx.provider_seed,
        &ctx.certificate,
        generation,
        1,
        ramflux_node_core::FederatedIssuerTrustStatus::Active,
        revoked_cert_ids,
        hard_stale_at,
    )?;
    s58_publish_snapshot(&ctx.materials, &envelope)
}

/// Atomically replace the federation-served snapshot file. The relay's read-only bind mount still
/// observes host-side writes, and the federation node hot-reads the file per request.
#[cfg(feature = "realnet")]
fn s58_publish_snapshot(
    materials: &Path,
    envelope: &ramflux_node_core::ProviderSignedTrustSnapshot,
) -> Result<(), Box<dyn std::error::Error>> {
    let target = materials.join("federation/trust-snapshot.json");
    let tmp = materials.join("federation/.trust-snapshot.json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(envelope)?)?;
    std::fs::rename(&tmp, &target)?;
    Ok(())
}

#[cfg(feature = "realnet")]
async fn s58_wait_refresh() {
    // Refresh interval is 5s; wait for >= 2 cycles plus fetch/serve latency.
    tokio::time::sleep(Duration::from_secs(14)).await;
}

#[cfg(feature = "realnet")]
async fn s58_sleep_until(deadline_unix: u64) {
    loop {
        let now = ramflux_node_core::now_unix_seconds();
        if now >= deadline_unix {
            break;
        }
        tokio::time::sleep(Duration::from_secs(deadline_unix - now)).await;
    }
}

#[cfg(feature = "realnet")]
async fn s58_wait_relay_quic_healthy(ca_cert: &Path) -> Result<(), Box<dyn std::error::Error>> {
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
fn s58_container(service: &str) -> String {
    format!("{S58_PROJECT}_{service}_1")
}

#[cfg(feature = "realnet")]
fn s58_container_ctl(action: &str, service: &str) -> Result<(), Box<dyn std::error::Error>> {
    let container = s58_container(service);
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
fn s58_container_logs(service: &str) -> String {
    let container = s58_container(service);
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

/// Reads the relay's persisted trust-snapshot cache from inside the container and returns the inner
/// snapshot object, so each step can assert the actual installed generation / `trust_status` /
/// `revoked_cert_ids` rather than inferring from timing.
#[cfg(feature = "realnet")]
fn s58_read_cache_snapshot() -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let container = s58_container("ramflux-relay");
    let output = std::process::Command::new(container_runtime())
        .args(["exec", &container, "cat", "/var/lib/ramflux/relay/trust-snapshot.json"])
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "read relay trust cache failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    let value: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    // T23-A2b2b: the persisted keyring-era record wraps the envelope; the snapshot is at envelope.snapshot.
    Ok(value
        .get("envelope")
        .and_then(|envelope| envelope.get("snapshot"))
        .cloned()
        .unwrap_or(value))
}

/// Asserts the relay's installed cache is at `generation` with node `status`.
#[cfg(feature = "realnet")]
fn s58_assert_cache(
    generation: u64,
    status: &str,
    label: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let snap = s58_read_cache_snapshot()?;
    assert_eq!(snap["generation"], generation, "{label}: installed cache generation");
    assert_eq!(snap["trust_status"], status, "{label}: installed cache trust_status");
    Ok(())
}

#[cfg(feature = "realnet")]
fn s58_spawn_rf_daemon_with_env(
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
fn s58_certificate(
    now: u64,
    node_id: &str,
    gateway_instance_id: &str,
    root_seed: [u8; 32],
    attestation_seed: [u8; 32],
) -> Result<ramflux_node_core::GatewayIssuerCertificate, Box<dyn std::error::Error>> {
    let mut certificate = ramflux_node_core::GatewayIssuerCertificate {
        schema: ramflux_node_core::GATEWAY_ISSUER_CERTIFICATE_SCHEMA.to_owned(),
        version: ramflux_node_core::OBJECT_RELAY_V3_PROOF_VERSION,
        cert_id: "s58-gw-b-cert-1".to_owned(),
        node_id: node_id.to_owned(),
        gateway_instance_id: gateway_instance_id.to_owned(),
        attestation_public_key: ramflux_crypto::public_key_base64url_from_seed(attestation_seed),
        attestation_key_id: "s58-gw-b-attestation-1".to_owned(),
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

#[cfg(feature = "realnet")]
#[allow(clippy::too_many_arguments)]
fn s58_trust_envelope(
    now: u64,
    node_id: &str,
    root_seed: [u8; 32],
    provider_seed: [u8; 32],
    certificate: &ramflux_node_core::GatewayIssuerCertificate,
    generation: u64,
    pin_epoch: u64,
    status: ramflux_node_core::FederatedIssuerTrustStatus,
    revoked_cert_ids: std::collections::BTreeSet<String>,
    hard_stale_at: u64,
) -> Result<ramflux_node_core::ProviderSignedTrustSnapshot, Box<dyn std::error::Error>> {
    s58_trust_envelope_signed_with(
        now,
        node_id,
        root_seed,
        provider_seed,
        provider_seed,
        certificate,
        generation,
        pin_epoch,
        status,
        revoked_cert_ids,
        hard_stale_at,
    )
}

/// Build a snapshot whose declared `provider_public_key` is `declared_provider_seed`'s key but is
/// signed with `signing_seed`. When the two differ the relay must reject the envelope (forged
/// provider signature) without disturbing its installed cache.
#[cfg(feature = "realnet")]
#[allow(clippy::too_many_arguments)]
fn s58_trust_envelope_signed_with(
    now: u64,
    node_id: &str,
    root_seed: [u8; 32],
    signing_seed: [u8; 32],
    declared_provider_seed: [u8; 32],
    certificate: &ramflux_node_core::GatewayIssuerCertificate,
    generation: u64,
    // Root pinning epoch is held constant across the lifecycle: this card exercises status,
    // hard-stale and CRL transitions, not node-root rotation (that is T23-A2). Only `generation`
    // advances, so every published snapshot is a clean monotonic successor with no pin overlap.
    _pin_epoch: u64,
    status: ramflux_node_core::FederatedIssuerTrustStatus,
    revoked_cert_ids: std::collections::BTreeSet<String>,
    hard_stale_at: u64,
) -> Result<ramflux_node_core::ProviderSignedTrustSnapshot, Box<dyn std::error::Error>> {
    let pin_epoch = 1;
    // T23-A2b2b: the production/default relay verifies the keyring-era v4 envelope. This card does not
    // rotate the provider key, so `provider_epoch` is constant at 1 (the keyring's K1 entry), and the
    // offline-root-signed keyring (written once by `s58_write_provider_keyring`) authorizes it.
    let mut envelope = ramflux_node_core::ProviderSignedTrustSnapshot {
        schema: ramflux_node_core::PROVIDER_SIGNED_TRUST_SNAPSHOT_ENVELOPE_SCHEMA.to_owned(),
        version: ramflux_node_core::PROVIDER_SIGNED_TRUST_SNAPSHOT_ENVELOPE_VERSION,
        snapshot: ramflux_node_core::FederatedIssuerTrustSnapshot {
            schema: ramflux_node_core::FEDERATED_ISSUER_TRUST_SNAPSHOT_SCHEMA.to_owned(),
            version: ramflux_node_core::OBJECT_RELAY_V3_PROOF_VERSION,
            node_id: node_id.to_owned(),
            generation,
            pin_epoch,
            // Real node-level status (T23-A1a: a non-Active snapshot is admitted to the relay cache
            // and fails requests closed at read time; the old Active is not retained).
            trust_status: status,
            roots: vec![ramflux_node_core::TrustedNodeRootKey {
                node_id: node_id.to_owned(),
                key_id: certificate.node_root_signing_key_id.clone(),
                public_key: ramflux_crypto::public_key_base64url_from_seed(root_seed),
                not_before: now.saturating_sub(60),
                not_after: now + 7_200,
                pin_epoch,
                retired_at: None,
            }],
            revoked_cert_ids,
            hard_stale_at,
        },
        provider_signing_key_id: S58_PROVIDER_KEY_ID.to_owned(),
        provider_public_key: ramflux_crypto::public_key_base64url_from_seed(declared_provider_seed),
        provider_epoch: 1,
        issued_at: now.saturating_sub(10),
        expires_at: now + 7_200,
        signature: String::new(),
    };
    envelope.signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &ramflux_node_core::provider_signed_trust_snapshot_signing_bytes(&envelope)?,
        signing_seed,
    );
    Ok(envelope)
}

/// T23-A2b2b: writes the offline-root-signed provider keyring for this test's single provider key
/// (K1 = `provider_seed`, authorized for `provider_epoch` 1). The relay pins the offline-root public
/// key out of band and validates this keyring before selecting the provider key that signs the v4
/// envelope; it is written once (no provider rotation in this card).
#[cfg(feature = "realnet")]
fn s58_write_provider_keyring(
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
            key_id: S58_PROVIDER_KEY_ID.to_owned(),
            public_key: ramflux_crypto::public_key_base64url_from_seed(provider_seed),
            not_before: now.saturating_sub(60),
            not_after: now + 7_200,
            retired_at: None,
            authorized_provider_epoch: 1,
        }],
        keyring_signature: String::new(),
    };
    keyring.keyring_signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &ramflux_node_core::provider_keyring_signing_bytes(&keyring)?,
        offline_root_seed,
    );
    let target = materials.join("federation/provider-keyring.json");
    let tmp = materials.join("federation/.provider-keyring.json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(&keyring)?)?;
    std::fs::rename(&tmp, &target)?;
    Ok(())
}
