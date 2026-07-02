// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use crate::*;

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s15_with_rf_accounts<Fut>(
    name: &str,
    gateway_quic_addr: std::net::SocketAddr,
    ca_cert: &Path,
    gateway_url: &str,
    run: impl FnOnce(PathBuf, String, String, String, PathBuf) -> Fut,
) -> Result<(), Box<dyn std::error::Error>>
where
    Fut: std::future::Future<Output = Result<(), Box<dyn std::error::Error>>>,
{
    let temp_root = temp_root(name)?;
    let rf_binary = mvp_s4_build_rf_binary().await?;
    let alice_socket = temp_root.join("alice/rfd.sock");
    let bob_socket = temp_root.join("bob/rfd.sock");
    let (alice_shutdown_tx, alice_shutdown_rx) = tokio::sync::watch::channel(false);
    let (bob_shutdown_tx, bob_shutdown_rx) = tokio::sync::watch::channel(false);
    let alice_config =
        ramflux_sdk::LocalBusConfig::new(&alice_socket, temp_root.join("alice/data"));
    let bob_config = ramflux_sdk::LocalBusConfig::new(&bob_socket, temp_root.join("bob/data"));
    let alice_server = ramflux_sdk::serve_local_bus_until(alice_config, alice_shutdown_rx);
    let bob_server = ramflux_sdk::serve_local_bus_until(bob_config, bob_shutdown_rx);
    let client_flow = async {
        let result = async {
            mvp_s4_wait_for_socket(&alice_socket).await?;
            mvp_s4_wait_for_socket(&bob_socket).await?;
            let gateway_addr = gateway_quic_addr.to_string();
            let ca_cert_arg = mvp_s4_path_arg(ca_cert);
            let alice_socket_arg = mvp_s4_path_arg(&alice_socket);
            let bob_socket_arg = mvp_s4_path_arg(&bob_socket);
            let bob_commitment = mvp_s4_assert_rf_accounts_and_contact(
                &rf_binary,
                &alice_socket_arg,
                &bob_socket_arg,
                &gateway_addr,
                gateway_url,
                &ca_cert_arg,
            )
            .await?;
            mvp_s15_assert_account_transport_quic(
                &rf_binary,
                &alice_socket_arg,
                "alice_s4_account",
            )
            .await?;
            mvp_s15_assert_account_transport_quic(&rf_binary, &bob_socket_arg, "bob_s4_account")
                .await?;
            run(rf_binary, alice_socket_arg, bob_socket_arg, bob_commitment, temp_root.clone())
                .await
        }
        .await;
        let _ = alice_shutdown_tx.send(true);
        let _ = bob_shutdown_tx.send(true);
        result
    };
    let (alice_result, bob_result, flow_result) =
        tokio::join!(alice_server, bob_server, client_flow);
    alice_result?;
    bob_result?;
    flow_result?;
    std::fs::remove_dir_all(&temp_root)?;
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s15_assert_account_transport_quic(
    rf_binary: &Path,
    socket: &str,
    account: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let status =
        mvp_s4_rf_json(rf_binary, &["--socket", socket, "account", "status", "--account", account])
            .await?;
    assert_eq!(
        status["active_transport_kind"].as_str(),
        Some(ramflux_sdk::GatewaySessionTransportKind::Quic.wire_name()),
        "S15 account {account} must stay on QUIC, status={status}"
    );
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
#[allow(clippy::too_many_lines)]
pub(crate) async fn mvp_s15_assert_rf_object_put_get(
    gateway_quic_addr: std::net::SocketAddr,
    ca_cert: &Path,
    gateway_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    Box::pin(mvp_s15_with_rf_accounts(
        "s15_object_put_get",
        gateway_quic_addr,
        ca_cert,
        gateway_url,
        |rf_binary, alice_socket, _bob_socket, bob_commitment, temp_root| async move {
            let plaintext = b"s15 object plaintext media bytes must stay opaque to nodes";
            let input = temp_root.join("object-input.bin");
            let output = temp_root.join("object-output.bin");
            std::fs::write(&input, plaintext)?;
            let input_arg = mvp_s4_path_arg(&input);
            let output_arg = mvp_s4_path_arg(&output);
            let put = mvp_s4_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &alice_socket,
                    "object",
                    "put",
                    "--account",
                    "alice_s4_account",
                    "--object",
                    "object_s15_media",
                    "--chunk-size",
                    "9",
                    &input_arg,
                ],
            )
            .await?;
            assert_eq!(put["object"]["object_id"], "object_s15_media");
            let chunks = put["chunks"].as_array().ok_or("missing object chunks")?;
            assert!(chunks.len() > 1);
            for chunk in chunks {
                let ciphertext =
                    chunk["ciphertext_base64"].as_str().ok_or("missing object chunk ciphertext")?;
                assert_node_opaque_payload(ciphertext, plaintext);
            }
            let share = mvp_s4_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &alice_socket,
                    "object",
                    "share",
                    "--account",
                    "alice_s4_account",
                    "--object",
                    "object_s15_media",
                    "--to",
                    "conv_s15_object",
                    "--sender",
                    "alice_device_s4",
                    "--recipient-principal-commitment",
                    &bob_commitment,
                    "--recipient-device",
                    "bob_device_s4",
                    "--target",
                    "target_s4_bob",
                ],
            )
            .await?;
            assert_eq!(share["node_visible_object_key"], false);
            let listed = mvp_s4_rf_json(
                &rf_binary,
                &["--socket", &alice_socket, "object", "list", "--account", "alice_s4_account"],
            )
            .await?;
            assert_eq!(listed["objects"].as_array().ok_or("missing object list")?.len(), 1);
            let got = mvp_s4_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &alice_socket,
                    "object",
                    "get",
                    "--account",
                    "alice_s4_account",
                    "--object",
                    "object_s15_media",
                    &output_arg,
                ],
            )
            .await?;
            assert_eq!(got["object_id"], "object_s15_media");
            assert_eq!(std::fs::read(output)?, plaintext);
            let deleted = mvp_s4_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &alice_socket,
                    "object",
                    "delete",
                    "--account",
                    "alice_s4_account",
                    "--object",
                    "object_s15_media",
                ],
            )
            .await?;
            assert_eq!(deleted["tombstoned"], true);
            Ok(())
        },
    ))
    .await
}

#[cfg(all(test, feature = "realnet"))]
#[allow(clippy::too_many_lines)]
pub(crate) async fn mvp_s15_assert_rf_object_store_persistence_after_daemon_restart(
    gateway_quic_addr: std::net::SocketAddr,
    ca_cert: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    const ACCOUNT: &str = "alice_s15_object_persist_account";
    const OBJECT_ID: &str = "object_s15_persist_media";
    let temp_root = temp_root("s15_object_store_persist")?;
    let rf_binary = mvp_s4_build_rf_binary().await?;
    let alice_socket = temp_root.join("alice/rfd.sock");
    let alice_data = temp_root.join("alice/data");
    let alice_socket_arg = mvp_s4_path_arg(&alice_socket);
    let alice_data_arg = mvp_s4_path_arg(&alice_data);
    let ca_cert_arg = mvp_s4_path_arg(ca_cert);
    let gateway_addr = gateway_quic_addr.to_string();
    let mut alice_daemon = mvp_s20_spawn_rf_daemon(&rf_binary, &alice_socket_arg, &alice_data_arg)?;
    let flow = async {
        mvp_s4_wait_for_socket(&alice_socket).await?;
        mvp_s10_create_rf_account(
            &rf_binary,
            &alice_socket_arg,
            ACCOUNT,
            "principal_s15_object_persist",
            "alice_device_s15_object_persist",
            "target_s15_object_persist",
            &gateway_addr,
            &ca_cert_arg,
            "15",
            "16",
        )
        .await?;
        mvp_s15_assert_account_transport_quic(&rf_binary, &alice_socket_arg, ACCOUNT).await?;

        let plaintext = b"s15 persistent object plaintext";
        let input = temp_root.join("persist-input.bin");
        let output_after_restart = temp_root.join("persist-output-after-restart.bin");
        std::fs::write(&input, plaintext)?;
        let input_arg = mvp_s4_path_arg(&input);
        let output_after_restart_arg = mvp_s4_path_arg(&output_after_restart);
        let put = mvp_s10_rf_json(
            &rf_binary,
            &[
                "--socket",
                &alice_socket_arg,
                "object",
                "put",
                "--account",
                ACCOUNT,
                "--object",
                OBJECT_ID,
                &input_arg,
            ],
            "s15 object persist put before restart",
        )
        .await?;
        assert_eq!(put["object"]["object_id"], OBJECT_ID);

        mvp_s20_stop_rf_daemon(&mut alice_daemon).await?;
        alice_daemon = mvp_s20_spawn_rf_daemon(&rf_binary, &alice_socket_arg, &alice_data_arg)?;
        let status = mvp_s20_wait_for_daemon_status(&rf_binary, &alice_socket_arg).await?;
        assert!(status["accounts"].as_u64().unwrap_or_default() >= 1);
        mvp_s15_assert_account_transport_quic(&rf_binary, &alice_socket_arg, ACCOUNT).await?;
        let got = mvp_s10_rf_json(
            &rf_binary,
            &[
                "--socket",
                &alice_socket_arg,
                "object",
                "get",
                "--account",
                ACCOUNT,
                "--object",
                OBJECT_ID,
                &output_after_restart_arg,
            ],
            "s15 object persist get after restart",
        )
        .await?;
        assert_eq!(got["object_id"], OBJECT_ID);
        assert_eq!(std::fs::read(&output_after_restart)?, plaintext);

        let deleted = mvp_s10_rf_json(
            &rf_binary,
            &[
                "--socket",
                &alice_socket_arg,
                "object",
                "delete",
                "--account",
                ACCOUNT,
                "--object",
                OBJECT_ID,
            ],
            "s15 object persist tombstone before restart",
        )
        .await?;
        assert_eq!(deleted["tombstoned"], true);

        mvp_s20_stop_rf_daemon(&mut alice_daemon).await?;
        alice_daemon = mvp_s20_spawn_rf_daemon(&rf_binary, &alice_socket_arg, &alice_data_arg)?;
        let status = mvp_s20_wait_for_daemon_status(&rf_binary, &alice_socket_arg).await?;
        assert!(status["accounts"].as_u64().unwrap_or_default() >= 1);
        mvp_s15_assert_account_transport_quic(&rf_binary, &alice_socket_arg, ACCOUNT).await?;
        let rejected = mvp_s10_rf_json(
            &rf_binary,
            &[
                "--socket",
                &alice_socket_arg,
                "object",
                "get",
                "--account",
                ACCOUNT,
                "--object",
                OBJECT_ID,
                &mvp_s4_path_arg(&temp_root.join("should-not-exist.bin")),
            ],
            "s15 object persist tombstone get after restart",
        )
        .await;
        assert!(rejected.is_err(), "tombstoned object was readable after restart");
        Ok::<(), Box<dyn std::error::Error>>(())
    };
    let result = tokio::time::timeout(Duration::from_mins(3), flow)
        .await
        .map_err(|_elapsed| "S15 object store persistence flow timed out")?;
    let _ = mvp_s20_stop_rf_daemon(&mut alice_daemon).await;
    result?;
    std::fs::remove_dir_all(&temp_root)?;
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s15_assert_rf_call_signaling(
    gateway_quic_addr: std::net::SocketAddr,
    ca_cert: &Path,
    gateway_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    Box::pin(mvp_s15_with_rf_accounts(
        "s15_call_signaling",
        gateway_quic_addr,
        ca_cert,
        gateway_url,
        |rf_binary, alice_socket, _bob_socket, _bob_commitment, _temp_root| async move {
            let offer = "v=0\r\na=ice-ufrag:s15\r\na=fingerprint:sha-256 opaque\r\n";
            let media_key = "s15-srtp-media-key-never-node-visible";
            let invite = mvp_s4_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &alice_socket,
                    "call",
                    "invite",
                    "--account",
                    "alice_s4_account",
                    "--call",
                    "call_s15",
                    "--to",
                    "principal_s4_bob",
                    "--offer",
                    offer,
                    "--srtp-key",
                    media_key,
                ],
            )
            .await?;
            assert_eq!(invite["state"], "invited");
            assert_eq!(invite["node_sees_sdp"], false);
            assert_eq!(invite["relay_holds_media_key"], false);
            let relay_hash =
                invite["relay"]["forwarded_payload_hash"].as_str().ok_or("missing relay hash")?;
            assert!(!relay_hash.contains("ice-ufrag"));
            assert!(!relay_hash.contains(media_key));
            let answer = mvp_s4_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &alice_socket,
                    "call",
                    "answer",
                    "--account",
                    "alice_s4_account",
                    "--call",
                    "call_s15",
                    "--answer",
                    "v=0\r\na=ice-pwd:s15-answer\r\n",
                ],
            )
            .await?;
            assert_eq!(answer["state"], "answered");
            let hangup = mvp_s4_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &alice_socket,
                    "call",
                    "hangup",
                    "--account",
                    "alice_s4_account",
                    "--call",
                    "call_s15",
                ],
            )
            .await?;
            assert_eq!(hangup["state"], "hung_up");
            Ok(())
        },
    ))
    .await
}

#[cfg(all(test, feature = "realnet"))]
#[allow(clippy::too_many_lines)]
pub(crate) async fn mvp_s15_assert_rf_bot(
    gateway_quic_addr: std::net::SocketAddr,
    ca_cert: &Path,
    gateway_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    Box::pin(mvp_s15_with_rf_accounts(
        "s15_bot",
        gateway_quic_addr,
        ca_cert,
        gateway_url,
        |rf_binary, alice_socket, _bob_socket, _bob_commitment, temp_root| async move {
            let manifest_path = temp_root.join("bot-manifest.json");
            let grant_path = temp_root.join("bot-install-grant.json");
            let attacker_manifest_path = temp_root.join("bot-manifest-attacker.json");
            let bot_seed = [0xb7; 32];
            let attacker_seed = [0xa7; 32];
            let installer_seed = [0xd2; 32];
            let manifest = mvp_s15_signed_bot_manifest(bot_seed)?;
            let grant = mvp_s15_signed_bot_install_grant(&manifest, installer_seed)?;
            let attacker_manifest = mvp_s15_resigned_bot_manifest(manifest.clone(), attacker_seed)?;
            mvp_s15_write_json(&manifest_path, &manifest)?;
            mvp_s15_write_json(&grant_path, &grant)?;
            mvp_s15_write_json(&attacker_manifest_path, &attacker_manifest)?;
            let manifest_arg = mvp_s4_path_arg(&manifest_path);
            let grant_arg = mvp_s4_path_arg(&grant_path);
            let attacker_manifest_arg = mvp_s4_path_arg(&attacker_manifest_path);
            let trusted = mvp_s4_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &alice_socket,
                    "bot",
                    "trust",
                    "add",
                    "--account",
                    "alice_s4_account",
                    "--bot",
                    "bot_s15",
                    "--public-key",
                    &ramflux_crypto::public_key_base64url_from_seed(bot_seed),
                    "--signing-key-id",
                    "bot_s15_key_1",
                ],
            )
            .await?;
            assert_eq!(trusted["trust_source"], "local_pin");
            let missing_consent = mvp_s4_rf_failure(
                &rf_binary,
                &[
                    "--socket",
                    &alice_socket,
                    "bot",
                    "install",
                    "--account",
                    "alice_s4_account",
                    "--manifest",
                    &manifest_arg,
                    "--grant",
                    &grant_arg,
                    "--consent",
                    "principal_s4_alice",
                ],
            )
            .await?;
            assert!(missing_consent.contains("CapabilityDenied"));
            let self_sign_attack = mvp_s4_rf_failure(
                &rf_binary,
                &[
                    "--socket",
                    &alice_socket,
                    "bot",
                    "install",
                    "--account",
                    "alice_s4_account",
                    "--manifest",
                    &attacker_manifest_arg,
                    "--grant",
                    &grant_arg,
                    "--consent",
                    "principal_s4_alice",
                    "principal_s4_bob",
                ],
            )
            .await?;
            // Attacker manifest is identical to the valid one except the signature. The SDK may
            // surface this through the bot manifest verifier or the bot install-grant binding, but
            // it must stay in the bot validation path and must not install anything.
            assert!(
                self_sign_attack.contains("ValidationFailed")
                    && self_sign_attack.contains("bot")
                    && self_sign_attack.contains("rejected"),
                "self-signed bot manifest was not rejected by bot validation: {self_sign_attack}"
            );
            let listed_after_self_sign = mvp_s4_rf_json(
                &rf_binary,
                &["--socket", &alice_socket, "bot", "list", "--account", "alice_s4_account"],
            )
            .await?;
            assert_eq!(
                listed_after_self_sign["bots"].as_array().ok_or("missing bots")?.len(),
                0,
                "self-signed bot manifest left an installed bot record: {listed_after_self_sign}"
            );
            let installed = mvp_s4_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &alice_socket,
                    "bot",
                    "install",
                    "--account",
                    "alice_s4_account",
                    "--manifest",
                    &manifest_arg,
                    "--grant",
                    &grant_arg,
                    "--consent",
                    "principal_s4_alice",
                    "principal_s4_bob",
                ],
            )
            .await?;
            assert_eq!(installed["state"], "installed");
            assert_eq!(installed["actor_type"], "bot");
            assert_eq!(installed["operation_origin"], "bot_actor");
            assert_eq!(installed["requested_scopes"].as_array().ok_or("missing scopes")?.len(), 2);
            let listed = mvp_s4_rf_json(
                &rf_binary,
                &["--socket", &alice_socket, "bot", "list", "--account", "alice_s4_account"],
            )
            .await?;
            assert_eq!(listed["bots"].as_array().ok_or("missing bots")?.len(), 1);
            let revoked = mvp_s4_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &alice_socket,
                    "bot",
                    "revoke",
                    "--account",
                    "alice_s4_account",
                    "--bot",
                    "bot_s15",
                ],
            )
            .await?;
            assert_eq!(revoked["state"], "revoked");
            let reinstall = mvp_s4_rf_failure(
                &rf_binary,
                &[
                    "--socket",
                    &alice_socket,
                    "bot",
                    "install",
                    "--account",
                    "alice_s4_account",
                    "--manifest",
                    &manifest_arg,
                    "--grant",
                    &grant_arg,
                    "--consent",
                    "principal_s4_alice",
                    "principal_s4_bob",
                ],
            )
            .await?;
            assert!(reinstall.contains("CapabilityDenied"));
            assert!(
                revoked["revocation_targets"]
                    .as_array()
                    .ok_or("missing revocation targets")?
                    .iter()
                    .any(|target| target.as_str() == Some("group:bot_s15"))
            );
            Ok(())
        },
    ))
    .await
}

#[cfg(all(test, feature = "realnet"))]
fn mvp_s15_signed_bot_manifest(
    bot_seed: [u8; 32],
) -> Result<ramflux_protocol::BotManifest, Box<dyn std::error::Error>> {
    let bot =
        ramflux_crypto::create_device_branch("bot_s15_principal", "bot_s15_device", 1, bot_seed);
    mvp_s15_resigned_bot_manifest(mvp_s15_unsigned_bot_manifest(), bot.signing_key.to_bytes())
}

#[cfg(all(test, feature = "realnet"))]
fn mvp_s15_resigned_bot_manifest(
    mut manifest: ramflux_protocol::BotManifest,
    signing_seed: [u8; 32],
) -> Result<ramflux_protocol::BotManifest, Box<dyn std::error::Error>> {
    let signer = ramflux_crypto::create_device_branch(
        "bot_s15_principal",
        "bot_s15_device",
        1,
        signing_seed,
    );
    manifest.signature_by_bot_identity = ramflux_crypto::sign_with_device_branch(
        &signer,
        &ramflux_sync::bot_manifest_signing_body(&manifest),
    )?;
    Ok(manifest)
}

#[cfg(all(test, feature = "realnet"))]
fn mvp_s15_unsigned_bot_manifest() -> ramflux_protocol::BotManifest {
    ramflux_protocol::BotManifest {
        schema: ramflux_protocol::domain::BOT_MANIFEST.to_owned(),
        version: 1,
        domain: ramflux_protocol::domain::BOT_MANIFEST.to_owned(),
        ext: ramflux_protocol::Ext::default(),
        signed: ramflux_protocol::SignedFields {
            signing_key_id: "bot_s15_key_1".to_owned(),
            signature_alg: ramflux_protocol::SignatureAlg::Ed25519,
            signature: "outer-signature-placeholder".to_owned(),
        },
        bot_identity_commitment: "bot_s15".to_owned(),
        actor_type: ramflux_protocol::ActorType::Bot,
        display_name: "S15 helper bot".to_owned(),
        manifest_version: "1.0.0".to_owned(),
        home_node: "bots.s15.realnet".to_owned(),
        capabilities: vec!["message:send".to_owned()],
        permissions: vec![
            "conversation:read:mentioned_context".to_owned(),
            "group:invite:principal_s4_alice".to_owned(),
            "group:invite:principal_s4_bob".to_owned(),
        ],
        owner_identity_commitment: "owner_s15".to_owned(),
        hosting_model: ramflux_protocol::HostingModel::Federated,
        a2ui_profiles: vec!["ramflux.a2ui.v1".to_owned()],
        safety_disclosure: ramflux_protocol::SafetyDisclosure {
            disclosure_version: 1,
            disclosure_text: "S15 bot sees messages explicitly shared with it.".to_owned(),
            hosting_model: ramflux_protocol::HostingModel::Federated,
            key_custody_class: ramflux_protocol::KeyCustodyClass::FederatedOperatorKey,
            operator_identity_commitment: Some("operator_s15".to_owned()),
            operator_display_name: Some("S15 Operator".to_owned()),
            can_read_dm_plaintext: true,
            can_read_group_messages_when_member: true,
            tee_attestation_hash: None,
            disclosure_hash: "s15_disclosure_hash".to_owned(),
        },
        created_at: 1_760_000_000,
        expires_at: Some(4_000_000_000),
        signature_by_bot_identity: String::new(),
        optional_signature_by_home_node: None,
        optional_signature_by_directory: None,
    }
}

#[cfg(all(test, feature = "realnet"))]
fn mvp_s15_signed_bot_install_grant(
    manifest: &ramflux_protocol::BotManifest,
    installer_seed: [u8; 32],
) -> Result<ramflux_protocol::BotInstallGrant, Box<dyn std::error::Error>> {
    let installer = ramflux_crypto::create_device_branch(
        "principal_s4_alice",
        "alice_device_s4",
        1,
        installer_seed,
    );
    let mut grant = ramflux_protocol::BotInstallGrant {
        schema: ramflux_protocol::domain::BOT_INSTALL_GRANT.to_owned(),
        version: 1,
        domain: ramflux_protocol::domain::BOT_INSTALL_GRANT.to_owned(),
        ext: ramflux_protocol::Ext::default(),
        signed: ramflux_protocol::SignedFields {
            signing_key_id: "alice_device_s4_key".to_owned(),
            signature_alg: ramflux_protocol::SignatureAlg::Ed25519,
            signature: "outer-signature-placeholder".to_owned(),
        },
        grant_id: "grant_s15_bot".to_owned(),
        bot_identity_commitment: manifest.bot_identity_commitment.clone(),
        bot_manifest_hash: ramflux_sync::bot_manifest_hash(manifest)?,
        installer_identity: "principal_s4_alice".to_owned(),
        installer_device_id: "alice_device_s4".to_owned(),
        scope: vec!["conversation:read:mentioned_context".to_owned(), "message:send".to_owned()],
        conversation_id: Some("conversation_s15_bot".to_owned()),
        group_id: Some("group_s15_bot".to_owned()),
        expires_at: 4_000_000_000,
        signature_by_installer_device: String::new(),
    };
    grant.signature_by_installer_device = ramflux_crypto::sign_with_device_branch(
        &installer,
        &ramflux_sync::bot_install_grant_signing_body(&grant),
    )?;
    Ok(grant)
}

#[cfg(all(test, feature = "realnet"))]
fn mvp_s15_write_json<T: serde::Serialize>(
    path: &Path,
    value: &T,
) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::write(path, serde_json::to_vec_pretty(value)?)?;
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
#[allow(clippy::too_many_lines)]
pub(crate) async fn mvp_s16_assert_object_secret_key_slot_dm(
    gateway_quic_addr: std::net::SocketAddr,
    ca_cert: &Path,
    gateway_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    Box::pin(mvp_s15_with_rf_accounts(
        "s16_object_secret_key_slot",
        gateway_quic_addr,
        ca_cert,
        gateway_url,
        |rf_binary, alice_socket, bob_socket, bob_commitment, temp_root| async move {
            let plaintext =
                b"s16 random object key plaintext must not be decryptable from object id";
            let input = temp_root.join("s16-object-input.bin");
            let bob_output = temp_root.join("s16-bob-output.bin");
            let package_path = temp_root.join("s16-object-share.json");
            let tampered_package_path = temp_root.join("s16-object-share-tampered.json");
            std::fs::write(&input, plaintext)?;
            let input_arg = mvp_s4_path_arg(&input);
            let output_arg = mvp_s4_path_arg(&bob_output);
            let package_arg = mvp_s4_path_arg(&package_path);
            let tampered_package_arg = mvp_s4_path_arg(&tampered_package_path);
            let put = mvp_s4_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &alice_socket,
                    "object",
                    "put",
                    "--account",
                    "alice_s4_account",
                    "--object",
                    "object_s16_secret",
                    "--chunk-size",
                    "13",
                    &input_arg,
                ],
            )
            .await?;
            let object = &put["object"];
            let ciphertext = object["ciphertext"].as_array().ok_or("missing ciphertext")?;
            let ciphertext_bytes = ciphertext
                .iter()
                .map(|value| {
                    value
                        .as_u64()
                        .and_then(|byte| u8::try_from(byte).ok())
                        .ok_or("invalid ciphertext byte")
                })
                .collect::<Result<Vec<_>, _>>()?;
            assert_node_opaque_payload(
                &ramflux_protocol::encode_base64url(&ciphertext_bytes),
                plaintext,
            );

            let share = mvp_s4_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &alice_socket,
                    "object",
                    "share",
                    "--account",
                    "alice_s4_account",
                    "--object",
                    "object_s16_secret",
                    "--to",
                    "conv_s16_object",
                    "--sender",
                    "alice_device_s4",
                    "--recipient-principal-commitment",
                    &bob_commitment,
                    "--recipient-device",
                    "bob_device_s4",
                    "--target",
                    "target_s4_bob",
                    "--out-package",
                    &package_arg,
                ],
            )
            .await?;
            assert_eq!(share["node_visible_object_key"], false);
            let package = share["package"].clone();
            let slot_bytes = serde_json::to_vec(&package["key_slot"])?;
            assert!(!contains_subslice(&slot_bytes, plaintext));
            assert!(!contains_subslice(&slot_bytes, b"object key"));
            assert!(package_path.exists());
            let mut tampered_package = package.clone();
            tampered_package["key_slot"]["recipient_device_id"] =
                serde_json::Value::String("mallory_device_s16".to_owned());
            mvp_s15_write_json(&tampered_package_path, &tampered_package)?;
            let tampered_import = mvp_s4_rf_failure(
                &rf_binary,
                &[
                    "--socket",
                    &bob_socket,
                    "object",
                    "import",
                    "--account",
                    "bob_s4_account",
                    &tampered_package_arg,
                ],
            )
            .await?;
            assert!(
                !tampered_import.is_empty(),
                "tampered S16 key slot import should fail with an error"
            );

            let imported = mvp_s4_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &bob_socket,
                    "object",
                    "import",
                    "--account",
                    "bob_s4_account",
                    &package_arg,
                ],
            )
            .await?;
            assert_eq!(imported["imported"], true);
            let got = mvp_s4_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &bob_socket,
                    "object",
                    "get",
                    "--account",
                    "bob_s4_account",
                    "--object",
                    "object_s16_secret",
                    &output_arg,
                ],
            )
            .await?;
            assert_eq!(got["object_id"], "object_s16_secret");
            assert_eq!(std::fs::read(bob_output)?, plaintext);
            Ok(())
        },
    ))
    .await
}
