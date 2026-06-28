// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use super::*;

#[cfg(feature = "realnet")]
#[test]
fn mvp0_realnet_signed_envelope_gateway_router_ack_nack_cursor()
-> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    let code_root = code_root();
    let deploy_root = code_root.join("ramflux/deploy");
    run_deploy_script(&code_root, "ramflux/deploy/scripts/bootstrap-itest.sh")?;
    run_docker_compose(&deploy_root, &["up", "--build", "-d"])?;
    let _guard = ComposeDownGuard::new(deploy_root.clone());

    let gateway_url = std::env::var("RAMFLUX_ITEST_GATEWAY_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:18081".to_owned());
    wait_for_gateway(&gateway_url)?;

    let ack_envelope = itest_envelope("env_realnet_ack", "target_realnet");
    let submit: ramflux_node_core::ItestMvp0SubmitResponse =
        ramflux_node_core::itest_http_post_json(
            &format!("{gateway_url}/mvp0/envelope"),
            &ack_envelope,
        )?;
    assert_eq!(submit.outcome, "offline_queued");
    assert_eq!(submit.target_delivery_id, "target_realnet");
    assert_eq!(submit.inbox_seq, Some(1));

    let ack_cursor: ramflux_node_core::ItestMvp0CursorResponse =
        ramflux_node_core::itest_http_post_json(
            &format!("{gateway_url}/mvp0/ack"),
            &itest_ack("env_realnet_ack"),
        )?;
    assert_eq!(ack_cursor.inbox_seq, 1);
    assert_eq!(ack_cursor.last_envelope_id.as_deref(), Some("env_realnet_ack"));
    assert!(ack_cursor.acked_envelope_ids.contains(&"env_realnet_ack".to_owned()));

    let nack_envelope = itest_envelope("env_realnet_nack", "target_realnet");
    let submit_nack: ramflux_node_core::ItestMvp0SubmitResponse =
        ramflux_node_core::itest_http_post_json(
            &format!("{gateway_url}/mvp0/envelope"),
            &nack_envelope,
        )?;
    assert_eq!(submit_nack.outcome, "offline_queued");

    let nack_cursor: ramflux_node_core::ItestMvp0CursorResponse =
        ramflux_node_core::itest_http_post_json(
            &format!("{gateway_url}/mvp0/nack"),
            &itest_nack("env_realnet_nack"),
        )?;
    assert_eq!(
        nack_cursor.nacked_envelope_ids.get("env_realnet_nack"),
        Some(&NackReason::RateLimited)
    );

    let cursor: Option<ramflux_node_core::ItestMvp0CursorResponse> =
        ramflux_node_core::itest_http_get_json(&format!(
            "{gateway_url}/mvp0/cursor/target_realnet"
        ))?;
    let cursor = cursor.ok_or("missing realnet cursor")?;
    assert_eq!(cursor.inbox_seq, 1);
    assert!(cursor.acked_envelope_ids.contains(&"env_realnet_ack".to_owned()));
    assert_eq!(cursor.nacked_envelope_ids.get("env_realnet_nack"), Some(&NackReason::RateLimited));
    Ok(())
}

#[cfg(feature = "realnet")]
#[test]
fn mvp1_realnet_identity_register_revoke_prekey() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    let code_root = code_root();
    let deploy_root = code_root.join("ramflux/deploy");
    run_deploy_script(&code_root, "ramflux/deploy/scripts/bootstrap-itest.sh")?;
    run_docker_compose(&deploy_root, &["up", "--build", "-d"])?;
    let _guard = ComposeDownGuard::new(deploy_root);

    let gateway_url = std::env::var("RAMFLUX_ITEST_GATEWAY_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:18081".to_owned());
    wait_for_gateway(&gateway_url)?;

    let fixture = mvp1_realnet_fixture()?;
    let registered: ramflux_node_core::ItestMvp1IdentityRegistrationResponse =
        ramflux_node_core::itest_http_post_json(
            &format!("{gateway_url}/mvp1/identity/register"),
            &fixture.register,
        )?;
    assert_eq!(registered.principal_id, "principal_realnet");
    assert_eq!(registered.device_id, "device_realnet");
    assert!(registered.session_bound);

    let published: ramflux_node_core::ItestMvp1PrekeyResponse =
        ramflux_node_core::itest_http_post_json(
            &format!("{gateway_url}/mvp1/prekey/publish"),
            &ramflux_node_core::ItestMvp1PublishPrekeyRequest {
                device_id: "device_realnet".to_owned(),
                bundle: fixture.prekey_bundle.clone(),
            },
        )?;
    assert_eq!(published.bundle, Some(fixture.prekey_bundle.clone()));

    let fetched: ramflux_node_core::ItestMvp1PrekeyResponse =
        ramflux_node_core::itest_http_get_json(&format!(
            "{gateway_url}/mvp1/prekey/device_realnet"
        ))?;
    assert_eq!(fetched.bundle, Some(fixture.prekey_bundle));

    let revoked: ramflux_node_core::ItestMvp1RevokeDeviceResponse =
        ramflux_node_core::itest_http_post_json(
            &format!("{gateway_url}/mvp1/device/revoke"),
            &mvp1_revoke_request("principal_realnet", [0x31; 32], "device_realnet", 1_760_000_100)?,
        )?;
    assert!(revoked.revoked);

    let revoked_bind = ramflux_node_core::itest_http_post_json::<_, serde_json::Value>(
        &format!("{gateway_url}/mvp1/identity/register"),
        &fixture.revoked_register,
    );
    assert!(revoked_bind.is_err());
    Ok(())
}

#[cfg(feature = "realnet")]
#[test]
fn mvp1_realnet_dm_e2ee_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    let realnet = start_realnet_compose()?;
    let gateway_url = &realnet.gateway_url;
    let fixture = mvp1_dm_realnet_fixture()?;
    register_mvp1_identity(gateway_url, &fixture.bob_register)?;
    publish_mvp1_prekey(gateway_url, "bob_device_realnet", &fixture.bob_prekey_bundle)?;
    register_mvp1_identity(gateway_url, &fixture.alice_register)?;

    let fetched: ramflux_node_core::ItestMvp1PrekeyResponse =
        ramflux_node_core::itest_http_get_json(&format!(
            "{gateway_url}/mvp1/prekey/bob_device_realnet"
        ))?;
    let bob_bundle = fetched.bundle.ok_or("missing bob prekey bundle")?;
    let plaintext = b"hello-mvp1-e2ee";
    let (ciphertext, mut bob_session) = encrypt_mvp1_dm(&fixture, &bob_bundle, plaintext)?;
    assert_ne!(ciphertext.ciphertext, plaintext);
    let encrypted_payload = serde_json::to_string(&ciphertext)?;
    assert!(!encrypted_payload.contains("hello-mvp1-e2ee"));

    let mut envelope = itest_envelope("env_mvp1_dm_realnet", "bob_target_mvp1_realnet");
    envelope.encrypted_payload = encrypted_payload;
    envelope.payload_hash = ramflux_crypto::blake3_256_base64url(
        "ramflux.test.dm_payload.v1",
        envelope.encrypted_payload.as_bytes(),
    );
    let submit: ramflux_node_core::ItestMvp0SubmitResponse =
        ramflux_node_core::itest_http_post_json(
            &format!("{gateway_url}/mvp0/envelope"),
            &envelope,
        )?;
    assert_eq!(submit.outcome, "online");
    assert_eq!(submit.inbox_seq, Some(1));

    let inbox: ramflux_node_core::ItestMvp1InboxResponse = ramflux_node_core::itest_http_get_json(
        &format!("{gateway_url}/mvp1/inbox/bob_target_mvp1_realnet"),
    )?;
    let delivered = inbox
        .entries
        .iter()
        .find(|entry| entry.envelope.envelope_id == "env_mvp1_dm_realnet")
        .ok_or("missing delivered DM envelope")?;
    assert_eq!(delivered.envelope.encrypted_payload, envelope.encrypted_payload);
    assert_ne!(delivered.envelope.encrypted_payload.as_bytes(), plaintext);
    assert!(!delivered.envelope.encrypted_payload.contains("hello-mvp1-e2ee"));

    let delivered_ciphertext: ramflux_crypto::DmCiphertext =
        serde_json::from_str(&delivered.envelope.encrypted_payload)?;
    let decrypted = bob_session.decrypt(&delivered_ciphertext, b"alice_device|bob_device")?;
    assert_eq!(decrypted, plaintext);

    let ack: ramflux_node_core::ItestMvp0CursorResponse = ramflux_node_core::itest_http_post_json(
        &format!("{gateway_url}/mvp0/ack"),
        &itest_ack("env_mvp1_dm_realnet"),
    )?;
    assert_eq!(ack.last_envelope_id.as_deref(), Some("env_mvp1_dm_realnet"));
    Ok(())
}

#[cfg(feature = "realnet")]
#[test]
fn mvp1_realnet_local_db_persist() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    let realnet = start_realnet_compose()?;
    let gateway_url = &realnet.gateway_url;
    let fixture = mvp1_dm_realnet_fixture()?;
    register_mvp1_identity(gateway_url, &fixture.bob_register)?;
    publish_mvp1_prekey(gateway_url, "bob_device_realnet", &fixture.bob_prekey_bundle)?;
    register_mvp1_identity(gateway_url, &fixture.alice_register)?;

    let (local_db, bob_db) = setup_mvp1_local_dbs()?;

    let fetched: ramflux_node_core::ItestMvp1PrekeyResponse =
        ramflux_node_core::itest_http_get_json(&format!(
            "{gateway_url}/mvp1/prekey/bob_device_realnet"
        ))?;
    let bob_bundle = fetched.bundle.ok_or("missing bob prekey bundle")?;
    let (mut alice_session, mut bob_session) = establish_mvp1_dm_sessions(&fixture, &bob_bundle)?;
    let first_plaintext = b"hello-mvp1-e2ee-db";
    let first = alice_session.encrypt(first_plaintext, b"alice_device|bob_device")?;
    let first_delivered =
        deliver_mvp1_dm(gateway_url, "env_mvp1_db_1", "bob_target_mvp1_realnet", &first)?;
    let first_ciphertext: ramflux_crypto::DmCiphertext =
        serde_json::from_str(&first_delivered.envelope.encrypted_payload)?;
    let first_decrypted = bob_session.decrypt(&first_ciphertext, b"alice_device|bob_device")?;
    assert_eq!(first_decrypted, first_plaintext);

    persist_bob_local_state(&bob_db, &bob_session, "msg_mvp1_db_1", &first_decrypted)?;
    let first_session = bob_session.clone();
    drop(bob_db);

    assert_mvp1_local_db_static_encryption(
        &local_db.bob_db_path,
        &[first_plaintext.as_slice(), b"hello-mvp1-e2ee-db-2".as_slice()],
        &[&first_session],
    )?;

    let reopened_bob = reopen_mvp1_bob_db(&local_db)?;
    assert_reopened_bob_local_state(&reopened_bob, first_plaintext)?;
    let mut restored_bob_session = restored_bob_session(&reopened_bob, "msg_mvp1_db_1")?;
    let second_plaintext = b"hello-mvp1-e2ee-db-2";
    let second = alice_session.encrypt(second_plaintext, b"alice_device|bob_device")?;
    let second_delivered =
        deliver_mvp1_dm(gateway_url, "env_mvp1_db_2", "bob_target_mvp1_realnet", &second)?;
    let second_ciphertext: ramflux_crypto::DmCiphertext =
        serde_json::from_str(&second_delivered.envelope.encrypted_payload)?;
    let second_decrypted =
        restored_bob_session.decrypt(&second_ciphertext, b"alice_device|bob_device")?;
    assert_eq!(second_decrypted, second_plaintext);
    persist_bob_local_state(
        &reopened_bob,
        &restored_bob_session,
        "msg_mvp1_db_2",
        &second_decrypted,
    )?;
    assert_eq!(reopened_bob.conversation_projection("conv_mvp1_realnet", "bob")?.message_count, 2);
    assert_eq!(reopened_bob.event_body("evt_alice_identity")?, None);
    let second_session = restored_bob_session.clone();
    drop(reopened_bob);
    assert_mvp1_local_db_static_encryption(
        &local_db.bob_db_path,
        &[first_plaintext.as_slice(), second_plaintext.as_slice()],
        &[&first_session, &second_session],
    )?;
    Ok(())
}
