// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

// T23-A2b1: gateway ATTESTATION private-key rotation over the real object-v3 stack, isolated from
// node-root rotation (T23-A2a) and provider-signing-key rotation (T23-A2b2). The gateway reads its
// attestation seed from the `RAMFLUX_GATEWAY_V3_ISSUER_SEED` env (fixed for the process lifetime) and
// hot-reads its issuer certificate file per issue; the loader fails closed unless
// `certificate.attestation_public_key == pubkey(seed)`. A true attestation rotation is therefore a
// single operations transaction: swap the cert file to certB (bound to seedB) AND force-recreate only
// gateway-b with env seedB. This test drives that transaction and proves:
//   * mismatch (seedA process + certB file) fails closed at the gateway consistency gate — the public
//     SDK issue fails and the relay store is not mutated;
//   * after the atomic swap+recreate, new public-SDK tokens are signed by seedB (certB) and succeed;
//   * an old certA/seedA token pre-issued through the real gateway is NOT specially treated by any
//     "pre-rotation" branch — the relay re-judges every request against the CURRENT snapshot, CRL,
//     root/cert chain and token TTL (60s skew, 300s max). So a pre-issued certA token is accepted only
//     while certA is still trusted and within its TTL, and is rejected once expired or CRL-listed.
//
// Mechanism note (reported to the reviewer): the old-attestation tokens are pre-issued through a REAL
// authenticated gateway session (not self-signed) BEFORE the rotation and first sent to the relay at
// the target step. Their owner-authorization proof is bound into the token, so it is given a long TTL
// (outliving the short token TTL) and reused verbatim at send; the proof-of-possession is rebuilt
// fresh per send (it is not bound into the token). This isolates the relay's TOKEN-TTL / CRL decision
// from proof expiry. This card does not claim any request-replay or unbounded-grace semantics; it
// asserts only current-snapshot + TTL + CRL re-evaluation. HTTP object fallback stays at zero.
#![allow(unused_imports)]
#![cfg_attr(not(feature = "realnet"), allow(dead_code))]
use super::*;

#[cfg(feature = "realnet")]
const S60_PROJECT: &str = "ramflux-s60-attestation-rotation";
#[cfg(feature = "realnet")]
const S60_PROVIDER_KEY_ID: &str = "s60-provider-1";
#[cfg(feature = "realnet")]
const S60_GATEWAY_B_QUIC: &str = "127.0.0.1:18444";
#[cfg(feature = "realnet")]
const S60_RELAY_QUIC: &str = "127.0.0.1:17447";
#[cfg(feature = "realnet")]
const S60_RAW_DEVICE: &str = "device_s60_b";
#[cfg(feature = "realnet")]
const S60_RAW_PRINCIPAL: &str = "principal_s60_b";
#[cfg(feature = "realnet")]
const S60_RAW_DEVICE_SEED: [u8; 32] = [0x5b; 32];

#[cfg(feature = "realnet")]
#[test]
#[allow(clippy::too_many_lines)]
fn mvp_s60_realnet_gateway_attestation_rotation() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1")
        || std::env::var("RAMFLUX_OBJECT_V3").as_deref() != Ok("1")
        || std::env::var("RAMFLUX_CROSS_GATEWAY").as_deref() != Ok("1")
    {
        eprintln!(
            "skipping s60 attestation rotation realnet; set RAMFLUX_ITEST_REALNET=1 RAMFLUX_OBJECT_V3=1 RAMFLUX_CROSS_GATEWAY=1"
        );
        return Ok(());
    }

    let issuer_node = "node_b.realnet";
    let audience_node = "node_a.realnet";
    let owner_principal = "principal_s60_owner";
    let gateway_id = "gw-b";

    let materials = temp_root("s60_attestation_materials")?;
    let now = ramflux_node_core::now_unix_seconds();
    let seed_a = [0x33; 32]; // attestation seed A (initial)
    let seed_b = [0x60; 32]; // attestation seed B (rotation target)
    let root_seed = [0x44; 32]; // single node-root; NOT rotated in this card
    let provider_seed = [0x66; 32];
    let offline_root_seed = [0x88; 32]; // T23-A2b2b: offline signing root for the provider keyring

    // certA and certB are signed by the SAME node-root (root1); they differ only in the attestation
    // public key (seedA vs seedB) and cert_id. Trusting root1 in the snapshot covers both.
    let cert_a = s60_certificate(
        now,
        issuer_node,
        gateway_id,
        "s60-cert-A",
        "s60-attest-A",
        "node-b#root-1",
        root_seed,
        seed_a,
    )?;
    let cert_b = s60_certificate(
        now,
        issuer_node,
        gateway_id,
        "s60-cert-B",
        "s60-attest-B",
        "node-b#root-1",
        root_seed,
        seed_b,
    )?;

    // Snapshot trusts root1 (pin_epoch 1), Active. Only the CRL changes across the flow.
    let g1 = s60_trust_envelope(
        now,
        issuer_node,
        provider_seed,
        1,
        vec![s60_root(issuer_node, "node-b#root-1", root_seed, now)],
        std::collections::BTreeSet::new(),
        now + 7_200,
    )?;
    std::fs::create_dir_all(materials.join("federation"))?;
    for directory in ["gateway-a", "gateway-b"] {
        std::fs::create_dir_all(materials.join(directory))?;
    }
    s60_write_gateway_cert(&materials, &cert_a)?;
    s60_publish_snapshot(&materials, &g1)?;
    s60_write_provider_keyring(&materials, now, issuer_node, offline_root_seed, provider_seed)?;

    let ports = S8ComposePorts {
        gateway_http: 64_581,
        gateway_quic: 64_851,
        router_http: 64_580,
        router_mesh: 64_852,
        notify_http: 64_583,
        federation_http: 64_582,
        federation_mesh: 64_853,
        relay_http: 64_584,
        relay_media_udp: 64_520,
        signaling_turn_udp: 64_878,
        signaling_turn_tcp: 64_879,
        retention_http: 64_587,
    };
    let node = start_s8_realnet_compose_project_with_env(
        S60_PROJECT,
        ports,
        &[
            ("RAMFLUX_V3_MATERIALS_DIR".to_owned(), materials.to_string_lossy().into_owned()),
            (
                "RAMFLUX_GATEWAY_B_V3_ISSUER_SEED".to_owned(),
                ramflux_protocol::encode_base64url(seed_a),
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
    let relay_url = format!("http://127.0.0.1:{}", ports.relay_http);

    let ctx = S60Ctx {
        materials: materials.clone(),
        now,
        issuer_node: issuer_node.to_owned(),
        audience_node: audience_node.to_owned(),
        owner_principal: owner_principal.to_owned(),
        gateway_id: gateway_id.to_owned(),
        provider_seed,
        root_seed,
        seed_b,
        cert_a,
        cert_b,
    };

    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    let result = runtime.block_on(async {
        let config = ramflux_transport::RelayClientQuicConfig::new(
            S60_RELAY_QUIC,
            "ramflux-relay",
            &relay_ca,
        )?;
        let health =
            ramflux_transport::relay_client_quic_health(&config, std::time::Duration::from_secs(5))
                .await?;
        assert_eq!(health.status, 200, "relay client QUIC listener must be healthy: {health:?}");

        let sdk_env = vec![
            ("RAMFLUX_SDK_RELAY_QUIC_ADDR".to_owned(), S60_RELAY_QUIC.to_owned()),
            ("RAMFLUX_SDK_RELAY_QUIC_SERVER_NAME".to_owned(), "ramflux-relay".to_owned()),
            ("RAMFLUX_SDK_RELAY_QUIC_CA_CERT".to_owned(), relay_ca.to_string_lossy().into_owned()),
            ("RAMFLUX_SDK_RELAY_OWNER_HOME_NODE_ID".to_owned(), issuer_node.to_owned()),
            ("RAMFLUX_SDK_RELAY_OWNER_PRINCIPAL_ID".to_owned(), owner_principal.to_owned()),
            ("RAMFLUX_SDK_RELAY_AUDIENCE_NODE_ID".to_owned(), audience_node.to_owned()),
        ];
        s60_flow(&ctx, &node, &relay_url, &sdk_env).await
    });

    let relay_logs = s60_container_logs("ramflux-relay");
    std::fs::remove_dir_all(&materials).ok();
    result?;
    assert!(
        !relay_logs.contains("POST /relay/v1/object/"),
        "relay must not receive any HTTP object request across the rotation:\n{relay_logs}"
    );
    Ok(())
}

#[cfg(feature = "realnet")]
struct S60Ctx {
    materials: PathBuf,
    now: u64,
    issuer_node: String,
    audience_node: String,
    owner_principal: String,
    gateway_id: String,
    provider_seed: [u8; 32],
    root_seed: [u8; 32],
    seed_b: [u8; 32],
    cert_a: ramflux_node_core::GatewayIssuerCertificate,
    cert_b: ramflux_node_core::GatewayIssuerCertificate,
}

/// A gateway-issued certA/seedA token captured before the rotation, together with the owner proof
/// (bound into the token) and chunk material needed to first-send it to the relay at a later step.
#[cfg(feature = "realnet")]
struct S60Pending {
    token: ramflux_node_core::RelayTokenV3,
    certificate: ramflux_node_core::GatewayIssuerCertificate,
    owner_proof: ramflux_node_core::OwnerAuthorizationProof,
    object_id: String,
    encrypted_chunk: Vec<u8>,
    chunk_cipher_hash: String,
}

#[cfg(feature = "realnet")]
#[allow(clippy::too_many_lines)]
async fn s60_flow(
    ctx: &S60Ctx,
    node: &S8RealnetNode,
    relay_url: &str,
    sdk_env: &[(String, String)],
) -> Result<(), Box<dyn std::error::Error>> {
    let temp_root = temp_root("s60_attestation_flow")?;
    let data_root = temp_root.join("owner/data");
    std::fs::create_dir_all(&data_root)?;
    let socket = PathBuf::from(format!("/tmp/ramflux-s60-rfd-{}.sock", std::process::id()));
    let input_path = temp_root.join("object-input.bin");
    let plaintext = b"mvp_s60_gateway_attestation_rotation_v3_object".repeat(48);
    std::fs::write(&input_path, &plaintext)?;

    let rf_binary = mvp_s4_build_rf_binary().await?;
    let ca_cert_arg = mvp_s4_path_arg(&node.ca_cert);
    let socket_arg = mvp_s4_path_arg(&socket);
    let data_root_arg = mvp_s4_path_arg(&data_root);
    let input_arg = mvp_s4_path_arg(&input_path);
    let output_path = temp_root.join("object-output.bin");
    let output_arg = mvp_s4_path_arg(&output_path);

    // Register the raw-QUIC owner device once (used to pre-issue the old-attestation tokens and to do
    // the authoritative reachable-but-absent GET checks after recovery).
    register_mvp1_identity(
        &node.gateway_url,
        &mvp_s1_identity_register_request(GatewayFrameIdentitySpec {
            principal_id: S60_RAW_PRINCIPAL,
            device_id: S60_RAW_DEVICE,
            target_delivery_id: "target_s60_b",
            gateway_id: &ctx.gateway_id,
            session_id: "pre_session_s60_b",
            push_alias_hash: Some("push_s60_b"),
            source_ip_hash: Some("s60_source"),
            root_seed: [0x5a; 32],
            device_seed: S60_RAW_DEVICE_SEED,
            device_epoch: 1,
        })?,
    )?;

    // The relay client is connected fresh per raw-QUIC send/get (below): a single long-lived client
    // connected here would idle-time-out before its first use (step 4 is minutes later) and step 7
    // restarts the relay, breaking any held connection.
    let mut daemon =
        s60_spawn_rf_daemon_with_env(&rf_binary, &socket_arg, &data_root_arg, sdk_env)?;

    let flow = async {
        mvp_s4_wait_for_socket(&socket).await?;
        mvp_s10_create_rf_account(
            &rf_binary,
            &socket_arg,
            "owner_s60_account",
            &ctx.owner_principal,
            "owner_device_s60",
            "target_s60_owner",
            S60_GATEWAY_B_QUIC,
            &ca_cert_arg,
            "50",
            "51",
        )
        .await?;

        // Step 1: gateway runs seedA + certA (file). A public-SDK PUT is signed by seedA under certA
        // and accepted by the relay (root1-trusted, not revoked, within TTL).
        s60_put_ok(&rf_binary, &socket_arg, relay_url, &input_arg, "object_s60_step1_a").await?;

        // Pre-issue three certA/seedA tokens through the real gateway (still seedA/certA), each for a
        // distinct object id, and hold them to first-send later. Fresh `issue_now` after the slow
        // build/compose/account setup keeps all TTLs meaningful and under the 300s cap.
        let issue_now = ramflux_node_core::now_unix_seconds();
        let (endpoint, connection, mut send, mut recv) =
            s60_open_gw_session(node, issue_now).await?;
        // overlap: long-lived certA token, valid at the recovery step.
        let pending_overlap = s60_presign_put(
            ctx,
            &mut send,
            &mut recv,
            issue_now,
            "object_s60_overlap",
            "s60-manifest-overlap",
            issue_now + 280,
            issue_now + 295,
        )
        .await?;
        // expired: short-lived certA token; first-used only after it expires.
        let pending_expired = s60_presign_put(
            ctx,
            &mut send,
            &mut recv,
            issue_now,
            "object_s60_expired",
            "s60-manifest-expired",
            issue_now + 60,
            issue_now + 295,
        )
        .await?;
        // crl: long-lived certA token; certA is CRL-listed before its first use.
        let pending_crl = s60_presign_put(
            ctx,
            &mut send,
            &mut recv,
            issue_now,
            "object_s60_crl",
            "s60-manifest-crl",
            issue_now + 290,
            issue_now + 295,
        )
        .await?;
        drop(send);
        drop(recv);
        drop(connection);
        drop(endpoint);

        // Step 2: mismatch — swap the gateway cert file to certB while the process still holds seedA.
        // The gateway consistency gate (cert.attestation_public_key == pubkey(seed)) fails closed, so
        // the public-SDK issue fails and the relay store is not mutated.
        s60_write_gateway_cert(&ctx.materials, &ctx.cert_b)?;
        s60_put_denied(
            &rf_binary,
            &socket_arg,
            relay_url,
            &input_arg,
            "object_s60_step2_mismatch",
            "seedA process + certB file mismatch",
        )
        .await?;

        // Step 3: atomic rotation — force-recreate ONLY gateway-b with env seedB (other services and
        // volumes untouched). certB file + seedB env now match; new public-SDK tokens are seedB-signed
        // under certB and succeed after the daemon reconnects.
        s60_recreate_gateway_b_with_seed(node, ctx.seed_b)?;
        s60_wait_gateway_b_reconnect(&rf_binary, &socket_arg, relay_url, &input_arg).await?;
        s60_put_ok(&rf_binary, &socket_arg, relay_url, &input_arg, "object_s60_step3_b").await?;

        // Step 4: the pre-issued certA/overlap token is first-sent now. certA is still root1-trusted
        // and not revoked, and the token is within TTL, so the relay accepts it — proving old-key
        // tokens keep working under the current snapshot + TTL (no rotation-before-token branch).
        let overlap_status = s60_send_pending_put(&node.ca_cert, &pending_overlap).await?;
        assert_eq!(
            overlap_status, 200,
            "pre-rotation certA token within TTL under a still-trusted cert must be accepted, got {overlap_status}"
        );

        // Step 5: wait past the expired token's TTL, then first-send it. The relay rejects it on token
        // TTL (owner proof still valid), and the store is unchanged.
        s60_wait_until(issue_now + 62).await;
        let expired_status = s60_send_pending_put(&node.ca_cert, &pending_expired).await?;
        assert_ne!(
            expired_status, 200,
            "pre-rotation certA token past its TTL must be rejected, got {expired_status}"
        );

        // Step 6: CRL-list certA (monotonic add). The relay refreshes and now rejects the certA/crl
        // token even though it is within TTL and certA's root is still trusted; the public-SDK certB
        // path keeps working.
        s60_publish(
            ctx,
            2,
            vec![s60_root(&ctx.issuer_node, "node-b#root-1", ctx.root_seed, ctx.now)],
            [ctx.cert_a.cert_id.clone()].into_iter().collect(),
            ctx.now + 7_200,
        )?;
        s60_wait_refresh().await;
        s60_assert_revoked(2, &ctx.cert_a.cert_id, "certA CRL-listed")?;
        let crl_status = s60_send_pending_put(&node.ca_cert, &pending_crl).await?;
        assert_ne!(
            crl_status, 200,
            "pre-rotation certA token under the CRL must be rejected, got {crl_status}"
        );
        s60_put_ok(&rf_binary, &socket_arg, relay_url, &input_arg, "object_s60_step6_b").await?;

        // Step 7: restart gateway-b and the relay. The persisted CRL survives (certA still revoked),
        // seedB/certB continue to issue and store, and the certA token stays rejected.
        s60_container_ctl("restart", "ramflux-gateway-b")?;
        s60_container_ctl("restart", "ramflux-relay")?;
        s60_wait_relay_quic_healthy(&node.ca_cert).await?;
        s60_assert_revoked(2, &ctx.cert_a.cert_id, "certA CRL persisted across restart")?;
        s60_wait_gateway_b_reconnect(&rf_binary, &socket_arg, relay_url, &input_arg).await?;
        s60_put_ok(&rf_binary, &socket_arg, relay_url, &input_arg, "object_s60_step7_b").await?;
        let crl_after_restart = s60_send_pending_put(&node.ca_cert, &pending_crl).await?;
        assert_ne!(
            crl_after_restart, 200,
            "certA token must stay rejected after restart, got {crl_after_restart}"
        );

        // Store invariant: the mismatch object is an rf-CLI-owned object, so its authoritative absence
        // is a public-SDK GET (certB-authorized) that must fail to retrieve any plaintext.
        s60_get_absent(
            &rf_binary,
            &socket_arg,
            relay_url,
            &output_arg,
            "object_s60_step2_mismatch",
            "denied mismatch object",
        )
        .await?;

        // The raw-QUIC denied objects (expired, crl) are owned by the raw device; prove absence with a
        // fresh certB-authorized GET (reachable-but-absent) over relay QUIC.
        let recover_now = ramflux_node_core::now_unix_seconds();
        let (endpoint, connection, mut send, mut recv) =
            s60_open_gw_session(node, recover_now).await?;
        for (object_id, manifest_hash) in
            [("object_s60_expired", "s60-manifest-expired"), ("object_s60_crl", "s60-manifest-crl")]
        {
            let status = s60_get_absent_raw(
                ctx,
                &node.ca_cert,
                &mut send,
                &mut recv,
                recover_now,
                object_id,
                manifest_hash,
            )
            .await?;
            assert_ne!(
                status, 200,
                "denied raw object {object_id} must be absent from the store (reachable certB GET), got {status}"
            );
        }
        drop(send);
        drop(recv);
        drop(connection);
        drop(endpoint);

        Ok::<(), Box<dyn std::error::Error>>(())
    };

    let result = tokio::time::timeout(std::time::Duration::from_mins(16), flow)
        .await
        .map_err(|_elapsed| "s60 attestation rotation flow timed out".to_owned());
    mvp_s20_stop_rf_daemon(&mut daemon).await?;
    let _ = std::fs::remove_file(&socket);
    std::fs::remove_dir_all(&temp_root).ok();
    result??;
    Ok(())
}

// ─── force-recreate a single gateway-b container with a new attestation seed ───────────────────────

/// Recreate ONLY `ramflux-gateway-b` with a changed `RAMFLUX_GATEWAY_B_V3_ISSUER_SEED`. The env is
/// captured at project start into the compose guard; a fresh env value only takes effect on container
/// (re)creation, so this reruns compose `up -d --no-deps --force-recreate ramflux-gateway-b` with the
/// guard's env plus the new seed. Other services and their volumes are left untouched (no `down`).
#[cfg(feature = "realnet")]
fn s60_recreate_gateway_b_with_seed(
    node: &S8RealnetNode,
    seed: [u8; 32],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut env = node.guard.env.clone();
    let key = "RAMFLUX_GATEWAY_B_V3_ISSUER_SEED";
    let encoded = ramflux_protocol::encode_base64url(seed);
    if let Some(entry) = env.iter_mut().find(|(existing, _)| existing == key) {
        entry.1 = encoded;
    } else {
        env.push((key.to_owned(), encoded));
    }
    run_docker_compose_project_with_options(
        &node.guard.deploy_root,
        &node.guard.project_name,
        &env,
        &["up", "-d", "--no-deps", "--force-recreate", "ramflux-gateway-b"],
        node.guard.federation_compio,
    )
}

/// After a gateway-b recreate/restart the daemon's session is broken; the next public-SDK PUT forces a
/// reconnect. Retry a lightweight PUT until it succeeds (or give up), so the caller can then assert.
#[cfg(feature = "realnet")]
async fn s60_wait_gateway_b_reconnect(
    rf_binary: &Path,
    socket_arg: &str,
    relay_url: &str,
    input_arg: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    for attempt in 0..20 {
        let object_id = format!("object_s60_reconnect_probe_{attempt}");
        if s60_put_ok(rf_binary, socket_arg, relay_url, input_arg, &object_id).await.is_ok() {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    }
    Err("gateway-b did not become issue-ready after recreate/restart".into())
}

#[cfg(feature = "realnet")]
async fn s60_wait_until(target_unix_seconds: u64) {
    loop {
        let now = ramflux_node_core::now_unix_seconds();
        if now >= target_unix_seconds {
            return;
        }
        let remaining = target_unix_seconds - now;
        tokio::time::sleep(std::time::Duration::from_secs(remaining.min(5))).await;
    }
}

// ─── raw-QUIC gateway session + pre-issue + first-send ─────────────────────────────────────────────

#[cfg(feature = "realnet")]
async fn s60_open_gw_session(
    node: &S8RealnetNode,
    now: u64,
) -> Result<
    (quinn::Endpoint, quinn::Connection, quinn::SendStream, quinn::RecvStream),
    Box<dyn std::error::Error>,
> {
    let (endpoint, connection, mut send, mut recv) =
        mvp_s1_open_quic_stream(S60_GATEWAY_B_QUIC.parse()?, &node.ca_cert).await?;
    let mut open = mvp_s1_open_frame(None, now, "s60-b");
    open.client_instance_id = "rf_s60_b".to_owned();
    open.device_id = S60_RAW_DEVICE.to_owned();
    open.target_delivery_id = "target_s60_b".to_owned();
    open.stream_nonce = format!("nonce_s60_{now}");
    open.source_ip_hash = Some("s60_source".to_owned());
    let auth =
        mvp_s1_auth_frame_for_registered_device(&open, S60_RAW_PRINCIPAL, 1, S60_RAW_DEVICE_SEED)?;
    mvp_s1_write_client_frame(
        &mut send,
        &ramflux_node_core::GatewayClientFrame::Open { open: open.clone() },
    )
    .await?;
    mvp_s1_write_client_frame(&mut send, &ramflux_node_core::GatewayClientFrame::Auth { auth })
        .await?;
    let _session = mvp_s1_expect_session_established(&mut recv).await?;
    // The session `open` frame is not needed after auth for token issue (the signed request carries
    // the device identity), so only the streams are returned.
    Ok((endpoint, connection, send, recv))
}

/// Issue a certA/seedA PUT token through the real gateway for `object_id`, with a caller-chosen token
/// TTL and a longer owner-proof TTL (the proof is bound into the token, so it must outlive the token).
#[cfg(feature = "realnet")]
#[allow(clippy::too_many_arguments)]
async fn s60_presign_put(
    ctx: &S60Ctx,
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    issue_now: u64,
    object_id: &str,
    manifest_hash: &str,
    token_expires_at: u64,
    proof_expires_at: u64,
) -> Result<S60Pending, Box<dyn std::error::Error>> {
    let device_id = S60_RAW_DEVICE;
    let device_seed = S60_RAW_DEVICE_SEED;
    let owner_public_key = ramflux_crypto::public_key_base64url_from_seed(device_seed);
    let requester_public_key = owner_public_key.clone();
    let requester_device_hash = ramflux_crypto::blake3_256_base64url(
        "ramflux.object_relay.recipient_device.v1",
        device_id.as_bytes(),
    );
    let chunk_id = "s60-chunk-0".to_owned();
    let encrypted_chunk = format!("s60-ciphertext-{object_id}").into_bytes();
    let chunk_cipher_hash =
        ramflux_node_core::object_relay_chunk_cipher_hash(manifest_hash, 0, &encrypted_chunk);

    let mut owner_proof = ramflux_node_core::OwnerAuthorizationProof {
        schema: ramflux_node_core::OWNER_AUTHORIZATION_PROOF_SCHEMA.to_owned(),
        version: ramflux_node_core::OBJECT_RELAY_V3_PROOF_VERSION,
        capability: ramflux_node_core::ObjectRelayCapability::Put,
        object_id: object_id.to_owned(),
        manifest_hash: Some(manifest_hash.to_owned()),
        chunk_id: Some(chunk_id.clone()),
        owner_home_node_id: ctx.issuer_node.clone(),
        owner_principal_id: S60_RAW_PRINCIPAL.to_owned(),
        owner_device_epoch: 1,
        request_nonce: format!("s60-owner-put-{object_id}"),
        body_hash: chunk_cipher_hash.clone(),
        issued_at: issue_now,
        expires_at: proof_expires_at,
        owner_signing_key_id: device_id.to_owned(),
        owner_public_key: owner_public_key.clone(),
        owner_signature: String::new(),
    };
    owner_proof.owner_signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &ramflux_node_core::owner_authorization_proof_signing_bytes(&owner_proof)?,
        device_seed,
    );
    let put_binding = ramflux_node_core::owner_authorization_proof_binding_hash(&owner_proof)?;

    let body = ramflux_node_core::RelayTokenV3IssueRequest {
        requester_device_id: device_id.to_owned(),
        requester_device_hash,
        requester_public_key,
        requester_device_epoch: 1,
        owner_signing_key_id: device_id.to_owned(),
        owner_public_key,
        owner_home_node_id: ctx.issuer_node.clone(),
        owner_principal_id: S60_RAW_PRINCIPAL.to_owned(),
        owner_device_epoch: 1,
        issuer_node_id: ctx.issuer_node.clone(),
        gateway_instance_id: ctx.gateway_id.clone(),
        audience_node_id: ctx.audience_node.clone(),
        relay_instance_id: None,
        object_id: object_id.to_owned(),
        manifest_hash: manifest_hash.to_owned(),
        chunk_id: chunk_id.clone(),
        capabilities: vec![ramflux_node_core::ObjectRelayCapability::Put],
        authorization_kind: ramflux_node_core::RelayAuthorizationKind::OwnerSession,
        authorization_binding_hash: put_binding,
        delete_after_ack: false,
        issued_at: issue_now,
        expires_at: token_expires_at,
        nonce: format!("s60-put-token-{object_id}"),
        issuer_certificate: ctx.cert_a.clone(),
    };
    let token = s60_issue_token(send, recv, device_id, body, device_seed).await?;
    Ok(S60Pending {
        token,
        certificate: ctx.cert_a.clone(),
        owner_proof,
        object_id: object_id.to_owned(),
        encrypted_chunk,
        chunk_cipher_hash,
    })
}

/// Connect a fresh relay client. Connections are made per operation so an idle QUIC connection never
/// times out between the (minutes-apart) rotation steps, and a relay restart cannot break a held one.
#[cfg(feature = "realnet")]
async fn s60_connect_relay(
    relay_ca: &Path,
) -> Result<ramflux_transport::QuicGatewayClient, Box<dyn std::error::Error>> {
    Ok(ramflux_transport::QuicGatewayClient::connect(
        "0.0.0.0:0".parse()?,
        S60_RELAY_QUIC.parse()?,
        "ramflux-relay",
        relay_ca,
        std::time::Duration::from_secs(5),
    )
    .await?)
}

/// First-send a pre-issued PUT token to the relay. The owner proof (bound into the token) is reused
/// verbatim; the proof-of-possession is rebuilt fresh at send. Returns the relay status.
#[cfg(feature = "realnet")]
async fn s60_send_pending_put(
    relay_ca: &Path,
    pending: &S60Pending,
) -> Result<u16, Box<dyn std::error::Error>> {
    let relay = s60_connect_relay(relay_ca).await?;
    let now = ramflux_node_core::now_unix_seconds();
    let pop = s60_pop(
        &pending.token,
        ramflux_node_core::ObjectRelayCapability::Put,
        pending.chunk_cipher_hash.clone(),
        S60_RAW_DEVICE,
        S60_RAW_DEVICE_SEED,
        now,
        &format!("s60-put-pop-{}-{now}", pending.object_id),
    )?;
    let response = relay
        .request(&ramflux_transport::GatewayQuicRequest {
            method: "POST".to_owned(),
            path: "/relay/v1/object/put_chunk".to_owned(),
            body: serde_json::json!({
                "token": pending.token,
                "certificate": pending.certificate,
                "owner_proof": pending.owner_proof,
                "pop": pop,
                "body_hash": pending.chunk_cipher_hash,
                "capability": "put",
                "chunk_index": 0,
                "chunk_cipher_hash": pending.chunk_cipher_hash,
                "encrypted_chunk": pending.encrypted_chunk,
                "expires_at": now + 100,
                "delete_after_ack": false,
            }),
        })
        .await?;
    Ok(response.status)
}

/// Reachable-but-absent GET over relay QUIC for a raw-QUIC denied object, using a fresh certB-signed
/// GET token issued by the recovered gateway (seedB/certB). A never-stored object returns non-200.
#[cfg(feature = "realnet")]
#[allow(clippy::too_many_arguments)]
async fn s60_get_absent_raw(
    ctx: &S60Ctx,
    relay_ca: &Path,
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    now: u64,
    object_id: &str,
    manifest_hash: &str,
) -> Result<u16, Box<dyn std::error::Error>> {
    let device_id = S60_RAW_DEVICE;
    let device_seed = S60_RAW_DEVICE_SEED;
    let owner_public_key = ramflux_crypto::public_key_base64url_from_seed(device_seed);
    let requester_device_hash = ramflux_crypto::blake3_256_base64url(
        "ramflux.object_relay.recipient_device.v1",
        device_id.as_bytes(),
    );
    let chunk_id = "s60-chunk-0".to_owned();
    let mut grant = ramflux_node_core::ObjectAccessGrant {
        schema: ramflux_node_core::OBJECT_ACCESS_GRANT_SCHEMA.to_owned(),
        version: ramflux_node_core::OBJECT_RELAY_V3_PROOF_VERSION,
        object_id: object_id.to_owned(),
        manifest_hash: manifest_hash.to_owned(),
        grantee_device_hash: requester_device_hash.clone(),
        capabilities: vec![
            ramflux_node_core::ObjectRelayCapability::Get,
            ramflux_node_core::ObjectRelayCapability::Ack,
        ],
        issued_at: now.saturating_sub(10),
        expires_at: now + 120,
        owner_signing_key_id: device_id.to_owned(),
        owner_public_key: owner_public_key.clone(),
        owner_signature: String::new(),
    };
    grant.owner_signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &ramflux_node_core::object_access_grant_signing_bytes(&grant)?,
        device_seed,
    );
    let binding = ramflux_node_core::object_access_grant_binding_hash(&grant)?;

    let body = ramflux_node_core::RelayTokenV3IssueRequest {
        requester_device_id: device_id.to_owned(),
        requester_device_hash,
        requester_public_key: owner_public_key.clone(),
        requester_device_epoch: 1,
        owner_signing_key_id: device_id.to_owned(),
        owner_public_key,
        owner_home_node_id: ctx.issuer_node.clone(),
        owner_principal_id: S60_RAW_PRINCIPAL.to_owned(),
        owner_device_epoch: 1,
        issuer_node_id: ctx.issuer_node.clone(),
        gateway_instance_id: ctx.gateway_id.clone(),
        audience_node_id: ctx.audience_node.clone(),
        relay_instance_id: None,
        object_id: object_id.to_owned(),
        manifest_hash: manifest_hash.to_owned(),
        chunk_id: chunk_id.clone(),
        capabilities: vec![ramflux_node_core::ObjectRelayCapability::Get],
        authorization_kind: ramflux_node_core::RelayAuthorizationKind::OwnerGrant,
        authorization_binding_hash: binding,
        delete_after_ack: false,
        issued_at: now,
        expires_at: now + 120,
        nonce: format!("s60-get-token-{object_id}"),
        issuer_certificate: ctx.cert_b.clone(),
    };
    let token = s60_issue_token(send, recv, device_id, body, device_seed).await?;
    let descriptor = serde_json::json!({
        "capability": "get",
        "chunk_id": token.chunk_id,
        "manifest_hash": token.manifest_hash,
        "object_id": token.object_id,
    });
    let body_hash = ramflux_crypto::blake3_256_base64url(
        "ramflux.object_relay.v3.get.body",
        &ramflux_protocol::canonical_json_bytes(&descriptor)?,
    );
    let pop = s60_pop(
        &token,
        ramflux_node_core::ObjectRelayCapability::Get,
        body_hash.clone(),
        device_id,
        device_seed,
        now,
        &format!("s60-get-pop-{object_id}"),
    )?;
    let relay = s60_connect_relay(relay_ca).await?;
    let response = relay
        .request(&ramflux_transport::GatewayQuicRequest {
            method: "POST".to_owned(),
            path: "/relay/v1/object/get_chunk".to_owned(),
            body: serde_json::json!({
                "token": token,
                "certificate": ctx.cert_b,
                "grant": grant,
                "pop": pop,
                "body_hash": body_hash,
                "capability": "get",
            }),
        })
        .await?;
    Ok(response.status)
}

#[cfg(feature = "realnet")]
async fn s60_issue_token(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    device_id: &str,
    body: ramflux_node_core::RelayTokenV3IssueRequest,
    device_seed: [u8; 32],
) -> Result<ramflux_node_core::RelayTokenV3, Box<dyn std::error::Error>> {
    let body_bytes = ramflux_protocol::canonical_json_bytes(&body)?;
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
        source_device_id: device_id.to_owned(),
        request_id: format!("req_s60_v3_token_{}", body.nonce),
        method: ramflux_protocol::HttpMethod::POST,
        path: "/relay/v1/token/v3/issue".to_owned(),
        device_proof_hash: "already_authed".to_owned(),
        body_hash: ramflux_crypto::blake3_256_base64url(
            ramflux_protocol::domain::ENVELOPE,
            &body_bytes,
        ),
        nonce: format!("s60-issue-{}-{now}", body.nonce),
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
fn s60_pop(
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

// ─── public-SDK (rf CLI) helpers ───────────────────────────────────────────────────────────────────

#[cfg(feature = "realnet")]
async fn s60_put_ok(
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
            "owner_s60_account",
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
            "owner_s60_account",
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
async fn s60_put_denied(
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
            "owner_s60_account",
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
async fn s60_get_absent(
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
            "owner_s60_account",
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

// ─── snapshot / cert publishing + cache assertions ────────────────────────────────────────────────

#[cfg(feature = "realnet")]
fn s60_write_gateway_cert(
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
fn s60_publish(
    ctx: &S60Ctx,
    generation: u64,
    roots: Vec<ramflux_node_core::TrustedNodeRootKey>,
    revoked_cert_ids: std::collections::BTreeSet<String>,
    hard_stale_at: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let envelope = s60_trust_envelope(
        ctx.now,
        &ctx.issuer_node,
        ctx.provider_seed,
        generation,
        roots,
        revoked_cert_ids,
        hard_stale_at,
    )?;
    s60_publish_snapshot(&ctx.materials, &envelope)
}

#[cfg(feature = "realnet")]
fn s60_publish_snapshot(
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
async fn s60_wait_refresh() {
    tokio::time::sleep(std::time::Duration::from_secs(14)).await;
}

#[cfg(feature = "realnet")]
fn s60_read_cache_snapshot() -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let container = s60_container("ramflux-relay");
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

#[cfg(feature = "realnet")]
fn s60_assert_revoked(
    generation: u64,
    cert_id: &str,
    label: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let snap = s60_read_cache_snapshot()?;
    assert_eq!(snap["generation"], generation, "{label}: installed cache generation");
    assert!(
        snap["revoked_cert_ids"].as_array().is_some_and(|ids| ids.iter().any(|id| id == cert_id)),
        "{label}: installed cache CRL must contain {cert_id}"
    );
    Ok(())
}

// ─── container control + certificate / snapshot builders ──────────────────────────────────────────

#[cfg(feature = "realnet")]
fn s60_container(service: &str) -> String {
    format!("{S60_PROJECT}_{service}_1")
}

#[cfg(feature = "realnet")]
fn s60_container_ctl(action: &str, service: &str) -> Result<(), Box<dyn std::error::Error>> {
    let container = s60_container(service);
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
fn s60_container_logs(service: &str) -> String {
    let container = s60_container(service);
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
async fn s60_wait_relay_quic_healthy(ca_cert: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let config =
        ramflux_transport::RelayClientQuicConfig::new(S60_RELAY_QUIC, "ramflux-relay", ca_cert)?;
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
    Err("relay client QUIC did not become healthy after restart".into())
}

#[cfg(feature = "realnet")]
fn s60_spawn_rf_daemon_with_env(
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
fn s60_certificate(
    now: u64,
    node_id: &str,
    gateway_instance_id: &str,
    cert_id: &str,
    attestation_key_id: &str,
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
        attestation_key_id: attestation_key_id.to_owned(),
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
fn s60_root(
    node_id: &str,
    key_id: &str,
    root_seed: [u8; 32],
    now: u64,
) -> ramflux_node_core::TrustedNodeRootKey {
    ramflux_node_core::TrustedNodeRootKey {
        node_id: node_id.to_owned(),
        key_id: key_id.to_owned(),
        public_key: ramflux_crypto::public_key_base64url_from_seed(root_seed),
        not_before: now.saturating_sub(60),
        not_after: now + 7_200,
        pin_epoch: 1,
        retired_at: None,
    }
}

#[cfg(feature = "realnet")]
#[allow(clippy::too_many_arguments)]
fn s60_trust_envelope(
    now: u64,
    node_id: &str,
    provider_seed: [u8; 32],
    generation: u64,
    roots: Vec<ramflux_node_core::TrustedNodeRootKey>,
    revoked_cert_ids: std::collections::BTreeSet<String>,
    hard_stale_at: u64,
) -> Result<ramflux_node_core::ProviderSignedTrustSnapshot, Box<dyn std::error::Error>> {
    // T23-A2b2b: keyring-era v4 envelope. This card rotates the gateway attestation key, not the
    // provider key, so `provider_epoch` is constant at 1 (the keyring K1 entry).
    let mut envelope = ramflux_node_core::ProviderSignedTrustSnapshot {
        schema: ramflux_node_core::PROVIDER_SIGNED_TRUST_SNAPSHOT_ENVELOPE_SCHEMA.to_owned(),
        version: ramflux_node_core::PROVIDER_SIGNED_TRUST_SNAPSHOT_ENVELOPE_VERSION,
        snapshot: ramflux_node_core::FederatedIssuerTrustSnapshot {
            schema: ramflux_node_core::FEDERATED_ISSUER_TRUST_SNAPSHOT_SCHEMA.to_owned(),
            version: ramflux_node_core::OBJECT_RELAY_V3_PROOF_VERSION,
            node_id: node_id.to_owned(),
            generation,
            pin_epoch: 1,
            trust_status: ramflux_node_core::FederatedIssuerTrustStatus::Active,
            roots,
            revoked_cert_ids,
            hard_stale_at,
        },
        provider_signing_key_id: S60_PROVIDER_KEY_ID.to_owned(),
        provider_public_key: ramflux_crypto::public_key_base64url_from_seed(provider_seed),
        provider_epoch: 1,
        issued_at: now.saturating_sub(10),
        expires_at: now + 7_200,
        signature: String::new(),
    };
    envelope.signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &ramflux_node_core::provider_signed_trust_snapshot_signing_bytes(&envelope)?,
        provider_seed,
    );
    Ok(envelope)
}

/// T23-A2b2b: writes the offline-root-signed provider keyring (single provider key K1, `provider_epoch` 1).
#[cfg(feature = "realnet")]
fn s60_write_provider_keyring(
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
            key_id: S60_PROVIDER_KEY_ID.to_owned(),
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
