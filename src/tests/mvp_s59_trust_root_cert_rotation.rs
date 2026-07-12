// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

// T23-A2a: node-root rotation overlap + gateway certificate renewal / revocation / retirement over
// the real object-v3 stack, isolated from provider-signing-key and attestation-key rotation (those
// are T23-A2b). The gateway hot-reads its issuer certificate file per issue, so certificate renewal
// is modelled by atomically swapping `gateway-b/issuer-cert.json`; the federation snapshot carries
// the trusted node-root keys (current + previous overlap) and the certificate revocation list. Every
// positive/negative probe is a real gateway-issued v3 token over relay QUIC (fresh cert per rotation
// state, re-evaluated against the current snapshot — never a v2/HTTP fallback).
//
// Mechanism note (reported to the reviewer): rather than capturing one token and replaying it, each
// rotation state issues a *fresh* cert-N token through the real gateway (rf/public SDK) and drives it
// to the relay. The relay re-checks every request against the current snapshot (CRL + root validity),
// so a freshly-issued cert1 token under a CRL/retired-root proves the same trust-gate semantics as a
// replayed one; the request-replay guard is covered separately (T23-A1a / relay idempotency tests).
#![allow(unused_imports)]
#![cfg_attr(not(feature = "realnet"), allow(dead_code))]
use super::*;

#[cfg(feature = "realnet")]
const S59_PROJECT: &str = "ramflux-s59-root-cert-rotation";
#[cfg(feature = "realnet")]
const S59_PROVIDER_KEY_ID: &str = "s59-provider-1";

#[cfg(feature = "realnet")]
#[test]
#[allow(clippy::too_many_lines)]
fn mvp_s59_realnet_trust_root_cert_rotation() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1")
        || std::env::var("RAMFLUX_OBJECT_V3").as_deref() != Ok("1")
        || std::env::var("RAMFLUX_CROSS_GATEWAY").as_deref() != Ok("1")
    {
        eprintln!(
            "skipping s59 root/cert rotation realnet; set RAMFLUX_ITEST_REALNET=1 RAMFLUX_OBJECT_V3=1 RAMFLUX_CROSS_GATEWAY=1"
        );
        return Ok(());
    }

    let issuer_node = "node_b.realnet";
    let audience_node = "node_a.realnet";
    let owner_principal = "principal_s59_owner";
    let gateway_id = "gw-b";

    let materials = temp_root("s59_root_cert_materials")?;
    let now = ramflux_node_core::now_unix_seconds();
    let attestation_seed = [0x33; 32];
    let root1_seed = [0x44; 32];
    let root2_seed = [0x55; 32];
    let root3_seed = [0x77; 32]; // unknown root, never trusted by any snapshot
    let provider_seed = [0x66; 32];
    let offline_root_seed = [0x88; 32]; // T23-A2b2b: offline signing root for the provider keyring

    // Certificates all share the attestation key (this card is NOT attestation-key rotation); they
    // differ only in which node-root signs them and their cert_id.
    let cert1 = s59_certificate(
        now,
        issuer_node,
        gateway_id,
        "s59-cert-1",
        "node-b#root-1",
        root1_seed,
        attestation_seed,
    )?;
    // cert1b is also root1-signed but NOT revoked — used to isolate root retirement from the CRL.
    let cert1b = s59_certificate(
        now,
        issuer_node,
        gateway_id,
        "s59-cert-1b",
        "node-b#root-1",
        root1_seed,
        attestation_seed,
    )?;
    let cert2 = s59_certificate(
        now,
        issuer_node,
        gateway_id,
        "s59-cert-2",
        "node-b#root-2",
        root2_seed,
        attestation_seed,
    )?;
    let cert3 = s59_certificate(
        now,
        issuer_node,
        gateway_id,
        "s59-cert-3",
        "node-b#root-3",
        root3_seed,
        attestation_seed,
    )?;

    // G1 snapshot: pin_epoch 1, only root1 (pin1) is trusted; cert1 in the gateway file.
    let g1 = s59_trust_envelope(
        now,
        issuer_node,
        provider_seed,
        1,
        1,
        vec![s59_root(issuer_node, "node-b#root-1", root1_seed, now, 1, None)],
        std::collections::BTreeSet::new(),
        now + 7_200,
    )?;
    std::fs::create_dir_all(materials.join("federation"))?;
    for directory in ["gateway-a", "gateway-b"] {
        std::fs::create_dir_all(materials.join(directory))?;
    }
    s59_write_gateway_cert(&materials, &cert1)?;
    s59_publish_snapshot(&materials, &g1)?;
    s59_write_provider_keyring(&materials, now, issuer_node, offline_root_seed, provider_seed)?;

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
        S59_PROJECT,
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

    let ctx = S59Ctx {
        materials: materials.clone(),
        now,
        issuer_node: issuer_node.to_owned(),
        provider_seed,
        root1_seed,
        root2_seed,
        certs: S59Certs { cert1, cert1b, cert2, cert3 },
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
        s59_flow(&ctx, &node, gateway_b_quic_addr, &relay_url, &sdk_env).await
    });

    let relay_logs = s59_container_logs("ramflux-relay");
    std::fs::remove_dir_all(&materials).ok();
    result?;
    assert!(
        !relay_logs.contains("POST /relay/v1/object/"),
        "relay must not receive any HTTP object request across the rotation:\n{relay_logs}"
    );
    Ok(())
}

#[cfg(feature = "realnet")]
struct S59Certs {
    cert1: ramflux_node_core::GatewayIssuerCertificate,
    cert1b: ramflux_node_core::GatewayIssuerCertificate,
    cert2: ramflux_node_core::GatewayIssuerCertificate,
    cert3: ramflux_node_core::GatewayIssuerCertificate,
}

#[cfg(feature = "realnet")]
struct S59Ctx {
    materials: PathBuf,
    now: u64,
    issuer_node: String,
    provider_seed: [u8; 32],
    root1_seed: [u8; 32],
    root2_seed: [u8; 32],
    certs: S59Certs,
}

#[cfg(feature = "realnet")]
#[allow(clippy::too_many_lines)]
async fn s59_flow(
    ctx: &S59Ctx,
    node: &S8RealnetNode,
    gateway_b_quic_addr: &str,
    relay_url: &str,
    sdk_env: &[(String, String)],
) -> Result<(), Box<dyn std::error::Error>> {
    let temp_root = temp_root("s59_root_cert_flow")?;
    let data_root = temp_root.join("owner/data");
    std::fs::create_dir_all(&data_root)?;
    let socket = PathBuf::from(format!("/tmp/ramflux-s59-rfd-{}.sock", std::process::id()));
    let input_path = temp_root.join("object-input.bin");
    let plaintext = b"mvp_s59_root_cert_rotation_v3_owner_object".repeat(48);
    std::fs::write(&input_path, &plaintext)?;

    let rf_binary = mvp_s4_build_rf_binary().await?;
    let ca_cert_arg = mvp_s4_path_arg(&node.ca_cert);
    let socket_arg = mvp_s4_path_arg(&socket);
    let data_root_arg = mvp_s4_path_arg(&data_root);
    let input_arg = mvp_s4_path_arg(&input_path);

    let output_path = temp_root.join("object-output.bin");
    let output_arg = mvp_s4_path_arg(&output_path);
    // root1 is pinned at pin_epoch 1 (previous); root2 at pin_epoch 2 (current after rotation).
    let root1_prev =
        || s59_root(&ctx.issuer_node, "node-b#root-1", ctx.root1_seed, ctx.now, 1, None);
    let root1_retired = || {
        s59_root(&ctx.issuer_node, "node-b#root-1", ctx.root1_seed, ctx.now, 1, Some(ctx.now - 1))
    };
    let root2_cur =
        || s59_root(&ctx.issuer_node, "node-b#root-2", ctx.root2_seed, ctx.now, 2, None);
    let cert1_id = ctx.certs.cert1.cert_id.clone();
    let revoked = |ids: &[&str]| {
        ids.iter().map(|id| (*id).to_owned()).collect::<std::collections::BTreeSet<String>>()
    };

    let mut daemon =
        s59_spawn_rf_daemon_with_env(&rf_binary, &socket_arg, &data_root_arg, sdk_env)?;

    let flow = async {
        mvp_s4_wait_for_socket(&socket).await?;
        mvp_s10_create_rf_account(
            &rf_binary,
            &socket_arg,
            "owner_s59_account",
            "principal_s59_owner",
            "owner_device_s59",
            "target_s59_owner",
            gateway_b_quic_addr,
            &ca_cert_arg,
            "50",
            "51",
        )
        .await?;

        // Step 1: G1 — pin_epoch 1, root1(pin1) is the only trusted root; cert1 (root1-signed) in the
        // gateway file. A real gateway-issued cert1 token is accepted by the relay.
        s59_put_ok(&rf_binary, &socket_arg, relay_url, &input_arg, "object_s59_g1").await?;

        // Step 2: G2 — a node-root rotation. The snapshot advances to pin_epoch 2 with root2(pin2) as
        // the new current and root1(pin1) still present as a valid previous (overlap). cert1 stays in
        // the gateway file, so a fresh cert1 (root1/pin1-signed) token still succeeds — proving the
        // current/previous pin-epoch overlap.
        s59_publish(
            ctx,
            2,
            2,
            vec![root2_cur(), root1_prev()],
            std::collections::BTreeSet::new(),
            ctx.now + 7_200,
        )?;
        s59_wait_refresh().await;
        s59_assert_roots(
            2,
            2,
            &[("node-b#root-1", 1, false), ("node-b#root-2", 2, false)],
            "G2 pin1->pin2 rotation with overlap",
        )?;
        s59_put_ok(&rf_binary, &socket_arg, relay_url, &input_arg, "object_s59_g2_overlap").await?;

        // Step 3: G3 — pin_epoch 2, the CRL revokes cert1 (still in the gateway file). A fresh cert1
        // token is now fail-closed (403).
        s59_publish(
            ctx,
            3,
            2,
            vec![root2_cur(), root1_prev()],
            revoked(&[cert1_id.as_str()]),
            ctx.now + 7_200,
        )?;
        s59_wait_refresh().await;
        s59_assert_revoked(3, cert1_id.as_str(), "G3 cert1 revoked")?;
        s59_put_denied(
            &rf_binary,
            &socket_arg,
            relay_url,
            &input_arg,
            "object_s59_g3_crl",
            "cert1 CRL",
        )
        .await?;

        // Step 4: certificate renewal — swap the gateway cert to cert2 (root2/pin2-signed, not in the
        // CRL). New issues carry cert2 and succeed, recovering service via a new certificate.
        s59_write_gateway_cert(&ctx.materials, &ctx.certs.cert2)?;
        s59_put_ok(&rf_binary, &socket_arg, relay_url, &input_arg, "object_s59_g4_renewed").await?;

        // Step 5: G4 — retire root1(pin1) (retired_at in the past) while keeping the CRL superset.
        // Restart the relay so it re-loads/re-verifies the persisted G4. Then cert2 still succeeds;
        // cert1b (root1-signed, NOT in the CRL) is rejected — isolating retirement from the CRL; and
        // cert3 (unknown root) is rejected.
        s59_publish(
            ctx,
            4,
            2,
            vec![root2_cur(), root1_retired()],
            revoked(&[cert1_id.as_str()]),
            ctx.now + 7_200,
        )?;
        s59_wait_refresh().await;
        s59_container_ctl("restart", "ramflux-relay")?;
        s59_wait_relay_quic_healthy(&node.ca_cert).await?;
        s59_assert_roots(
            4,
            2,
            &[("node-b#root-1", 1, true), ("node-b#root-2", 2, false)],
            "G4 persisted across restart (root1 pin1 retired)",
        )?;

        s59_put_ok(&rf_binary, &socket_arg, relay_url, &input_arg, "object_s59_g5_cert2").await?;
        s59_write_gateway_cert(&ctx.materials, &ctx.certs.cert1b)?;
        s59_put_denied(
            &rf_binary,
            &socket_arg,
            relay_url,
            &input_arg,
            "object_s59_g5_retired",
            "root1 retired",
        )
        .await?;
        s59_write_gateway_cert(&ctx.materials, &ctx.certs.cert3)?;
        s59_put_denied(
            &rf_binary,
            &socket_arg,
            relay_url,
            &input_arg,
            "object_s59_g5_unknown",
            "unknown root",
        )
        .await?;
        // Restore cert2 for the closing positive check and the absence proofs.
        s59_write_gateway_cert(&ctx.materials, &ctx.certs.cert2)?;

        // Step 6: successor negatives — each must be rejected and leave the persisted G4 unchanged.
        // (a) generation rollback.
        s59_publish(
            ctx,
            1,
            1,
            vec![root1_prev()],
            std::collections::BTreeSet::new(),
            ctx.now + 7_200,
        )?;
        s59_wait_refresh().await;
        // (b) pin_epoch rollback — a higher generation but pin_epoch dropped back to 1.
        s59_publish(
            ctx,
            6,
            1,
            vec![root2_cur(), root1_retired()],
            revoked(&[cert1_id.as_str()]),
            ctx.now + 7_200,
        )?;
        s59_wait_refresh().await;
        // (c) provider-correctly-signed same generation=4 / pin_epoch=2 but with different root2 key
        // material (a same-generation content replacement).
        let same_gen_altered = s59_trust_envelope(
            ctx.now,
            &ctx.issuer_node,
            ctx.provider_seed,
            4,
            2,
            vec![
                s59_root(&ctx.issuer_node, "node-b#root-2", [0x88; 32], ctx.now, 2, None),
                root1_retired(),
            ],
            revoked(&[cert1_id.as_str()]),
            ctx.now + 7_200,
        )?;
        s59_publish_snapshot(&ctx.materials, &same_gen_altered)?;
        s59_wait_refresh().await;
        // (d) wrong-provider signature over an otherwise-valid successor.
        let forged = s59_trust_envelope_signed_with(
            ctx.now,
            &ctx.issuer_node,
            [0x99; 32],
            ctx.provider_seed,
            6,
            2,
            vec![root2_cur(), root1_retired()],
            revoked(&[cert1_id.as_str()]),
            ctx.now + 7_200,
        )?;
        s59_publish_snapshot(&ctx.materials, &forged)?;
        s59_wait_refresh().await;
        // All four were rejected: the persisted cache is still exactly G4.
        s59_assert_roots(
            4,
            2,
            &[("node-b#root-1", 1, true), ("node-b#root-2", 2, false)],
            "successor negatives rejected, cache stays G4",
        )?;
        s59_assert_revoked(4, cert1_id.as_str(), "G4 CRL retained")?;

        // Store invariant: each denied PUT was rejected at the trust gate before any store mutation,
        // so those object ids must not be retrievable (public SDK GET fails). cert2 authorization is
        // restored, so a reachable-but-absent object is the authoritative signal.
        for (object_id, label) in [
            ("object_s59_g3_crl", "denied cert1-CRL object"),
            ("object_s59_g5_retired", "denied retired-root object"),
            ("object_s59_g5_unknown", "denied unknown-root object"),
        ] {
            s59_get_absent(&rf_binary, &socket_arg, relay_url, &output_arg, object_id, label)
                .await?;
        }

        // Closing positive: cert2 still issues and stores a fresh object.
        s59_put_ok(&rf_binary, &socket_arg, relay_url, &input_arg, "object_s59_g6_final").await?;

        Ok::<(), Box<dyn std::error::Error>>(())
    };

    let result = tokio::time::timeout(Duration::from_mins(16), flow)
        .await
        .map_err(|_elapsed| "s59 root/cert rotation flow timed out".to_owned());
    mvp_s20_stop_rf_daemon(&mut daemon).await?;
    let _ = std::fs::remove_file(&socket);
    std::fs::remove_dir_all(&temp_root).ok();
    result??;
    Ok(())
}

#[cfg(feature = "realnet")]
async fn s59_put_ok(
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
            "owner_s59_account",
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
            "owner_s59_account",
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
async fn s59_put_denied(
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
            "owner_s59_account",
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

/// Atomically replace the gateway-b issuer certificate file (the gateway hot-reads it per issue).
#[cfg(feature = "realnet")]
fn s59_write_gateway_cert(
    materials: &Path,
    cert: &ramflux_node_core::GatewayIssuerCertificate,
) -> Result<(), Box<dyn std::error::Error>> {
    for directory in ["gateway-a", "gateway-b"] {
        let target = materials.join(directory).join("issuer-cert.json");
        let tmp = materials.join(directory).join(".issuer-cert.json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(cert)?)?;
        std::fs::rename(&tmp, &target)?;
    }
    Ok(())
}

#[cfg(feature = "realnet")]
#[allow(clippy::too_many_arguments)]
fn s59_publish(
    ctx: &S59Ctx,
    generation: u64,
    pin_epoch: u64,
    roots: Vec<ramflux_node_core::TrustedNodeRootKey>,
    revoked_cert_ids: std::collections::BTreeSet<String>,
    hard_stale_at: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let envelope = s59_trust_envelope(
        ctx.now,
        &ctx.issuer_node,
        ctx.provider_seed,
        generation,
        pin_epoch,
        roots,
        revoked_cert_ids,
        hard_stale_at,
    )?;
    s59_publish_snapshot(&ctx.materials, &envelope)
}

/// A GET (public SDK / rf) of a previously-denied object id that must fail: the denied PUT was
/// rejected at the relay trust gate before any store mutation, so the object is not retrievable.
#[cfg(feature = "realnet")]
async fn s59_get_absent(
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
            "owner_s59_account",
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
fn s59_publish_snapshot(
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
async fn s59_wait_refresh() {
    tokio::time::sleep(Duration::from_secs(14)).await;
}

#[cfg(feature = "realnet")]
fn s59_read_cache_snapshot() -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let container = s59_container("ramflux-relay");
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

/// Asserts the installed cache snapshot's generation, `pin_epoch`, and — for each expected root —
/// `key_id`, `pin_epoch`, and whether it is retired. `expected` entries are `(key_id, pin_epoch, retired)`.
#[cfg(feature = "realnet")]
fn s59_assert_roots(
    generation: u64,
    pin_epoch: u64,
    expected: &[(&str, u64, bool)],
    label: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let snap = s59_read_cache_snapshot()?;
    assert_eq!(snap["generation"], generation, "{label}: installed cache generation");
    assert_eq!(snap["pin_epoch"], pin_epoch, "{label}: installed cache pin_epoch");
    let roots = snap["roots"].as_array().ok_or("roots must be an array")?;
    for (key_id, root_pin, retired) in expected {
        let root = roots
            .iter()
            .find(|root| root["key_id"] == *key_id)
            .ok_or_else(|| format!("{label}: installed cache must contain root {key_id}"))?;
        assert_eq!(root["pin_epoch"], *root_pin, "{label}: root {key_id} pin_epoch");
        assert_eq!(
            root["retired_at"].is_null(),
            !*retired,
            "{label}: root {key_id} retirement (retired={retired})"
        );
    }
    Ok(())
}

#[cfg(feature = "realnet")]
fn s59_assert_revoked(
    generation: u64,
    cert_id: &str,
    label: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let snap = s59_read_cache_snapshot()?;
    assert_eq!(snap["generation"], generation, "{label}: installed cache generation");
    assert!(
        snap["revoked_cert_ids"].as_array().is_some_and(|ids| ids.iter().any(|id| id == cert_id)),
        "{label}: installed cache CRL must contain {cert_id}"
    );
    Ok(())
}

#[cfg(feature = "realnet")]
fn s59_container(service: &str) -> String {
    format!("{S59_PROJECT}_{service}_1")
}

#[cfg(feature = "realnet")]
fn s59_container_ctl(action: &str, service: &str) -> Result<(), Box<dyn std::error::Error>> {
    let container = s59_container(service);
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
fn s59_container_logs(service: &str) -> String {
    let container = s59_container(service);
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
async fn s59_wait_relay_quic_healthy(ca_cert: &Path) -> Result<(), Box<dyn std::error::Error>> {
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
fn s59_spawn_rf_daemon_with_env(
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
#[allow(clippy::too_many_arguments)]
fn s59_certificate(
    now: u64,
    node_id: &str,
    gateway_instance_id: &str,
    cert_id: &str,
    node_root_signing_key_id: &str,
    root_seed: [u8; 32],
    attestation_seed: [u8; 32],
) -> Result<ramflux_node_core::GatewayIssuerCertificate, Box<dyn std::error::Error>> {
    let mut certificate = ramflux_node_core::GatewayIssuerCertificate {
        schema: ramflux_node_core::GATEWAY_ISSUER_CERTIFICATE_SCHEMA.to_owned(),
        version: ramflux_node_core::OBJECT_RELAY_V3_PROOF_VERSION,
        cert_id: cert_id.to_owned(),
        node_id: node_id.to_owned(),
        gateway_instance_id: gateway_instance_id.to_owned(),
        attestation_public_key: ramflux_crypto::public_key_base64url_from_seed(attestation_seed),
        attestation_key_id: "s59-gw-b-attestation-1".to_owned(),
        not_before: now.saturating_sub(60),
        not_after: now + 7_200,
        issued_at: now.saturating_sub(60),
        node_root_signing_key_id: node_root_signing_key_id.to_owned(),
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
fn s59_root(
    node_id: &str,
    key_id: &str,
    root_seed: [u8; 32],
    now: u64,
    pin_epoch: u64,
    retired_at: Option<u64>,
) -> ramflux_node_core::TrustedNodeRootKey {
    ramflux_node_core::TrustedNodeRootKey {
        node_id: node_id.to_owned(),
        key_id: key_id.to_owned(),
        public_key: ramflux_crypto::public_key_base64url_from_seed(root_seed),
        not_before: now.saturating_sub(60),
        not_after: now + 7_200,
        pin_epoch,
        retired_at,
    }
}

#[cfg(feature = "realnet")]
#[allow(clippy::too_many_arguments)]
fn s59_trust_envelope(
    now: u64,
    node_id: &str,
    provider_seed: [u8; 32],
    generation: u64,
    pin_epoch: u64,
    roots: Vec<ramflux_node_core::TrustedNodeRootKey>,
    revoked_cert_ids: std::collections::BTreeSet<String>,
    hard_stale_at: u64,
) -> Result<ramflux_node_core::ProviderSignedTrustSnapshot, Box<dyn std::error::Error>> {
    s59_trust_envelope_signed_with(
        now,
        node_id,
        provider_seed,
        provider_seed,
        generation,
        pin_epoch,
        roots,
        revoked_cert_ids,
        hard_stale_at,
    )
}

#[cfg(feature = "realnet")]
#[allow(clippy::too_many_arguments)]
fn s59_trust_envelope_signed_with(
    now: u64,
    node_id: &str,
    signing_seed: [u8; 32],
    declared_provider_seed: [u8; 32],
    generation: u64,
    pin_epoch: u64,
    roots: Vec<ramflux_node_core::TrustedNodeRootKey>,
    revoked_cert_ids: std::collections::BTreeSet<String>,
    hard_stale_at: u64,
) -> Result<ramflux_node_core::ProviderSignedTrustSnapshot, Box<dyn std::error::Error>> {
    // T23-A2b2b: keyring-era v4 envelope. This card rotates the node-root, not the provider key, so
    // `provider_epoch` is constant at 1 (the keyring's K1 entry, written once by s59_write_provider_keyring).
    let mut envelope = ramflux_node_core::ProviderSignedTrustSnapshot {
        schema: ramflux_node_core::PROVIDER_SIGNED_TRUST_SNAPSHOT_ENVELOPE_SCHEMA.to_owned(),
        version: ramflux_node_core::PROVIDER_SIGNED_TRUST_SNAPSHOT_ENVELOPE_VERSION,
        snapshot: ramflux_node_core::FederatedIssuerTrustSnapshot {
            schema: ramflux_node_core::FEDERATED_ISSUER_TRUST_SNAPSHOT_SCHEMA.to_owned(),
            version: ramflux_node_core::OBJECT_RELAY_V3_PROOF_VERSION,
            node_id: node_id.to_owned(),
            generation,
            pin_epoch,
            trust_status: ramflux_node_core::FederatedIssuerTrustStatus::Active,
            roots,
            revoked_cert_ids,
            hard_stale_at,
        },
        provider_signing_key_id: S59_PROVIDER_KEY_ID.to_owned(),
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

/// T23-A2b2b: writes the offline-root-signed provider keyring (single provider key K1, authorized for
/// `provider_epoch` 1). Written once; this card rotates node-roots, not the provider key.
#[cfg(feature = "realnet")]
fn s59_write_provider_keyring(
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
            key_id: S59_PROVIDER_KEY_ID.to_owned(),
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
