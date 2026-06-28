// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use crate::*;

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp10_spawn_quic_lan_object_sync_server(
    tls: &ramflux_transport::MeshTlsConfig,
    content_key: [u8; 32],
    forbidden_plaintext: Vec<u8>,
    forbidden_object_key: [u8; 32],
) -> Result<Mvp10AsyncServer, Box<dyn std::error::Error>> {
    let config = ramflux_transport::quic_gateway_server_config(tls)?;
    let endpoint = quinn::Endpoint::server(config, "127.0.0.1:0".parse()?)?;
    let addr = endpoint.local_addr()?;
    let task = tokio::spawn(async move {
        let device_branch = ramflux_crypto::create_device_branch(
            "principal_mvp10_object_sync",
            "mvp10_object_sync_server",
            1,
            [0x9A; 32],
        );
        let connecting =
            endpoint.accept().await.ok_or_else(|| anyhow::anyhow!("missing QUIC LAN peer"))?;
        let connection = connecting.await?;
        let mut session: Option<ramflux_sync::ObjectSyncSession> = None;
        for _stream_index in 0..2 {
            let (mut send, mut recv) = connection.accept_bi().await?;
            let request: ramflux_transport::GatewayQuicRequest =
                ramflux_transport::read_quic_json_frame(&mut recv).await?;
            let response = if request.method == "POST" && request.path == "/object/sync" {
                let sync_request: Mvp10QuicLanObjectSyncRequest =
                    serde_json::from_value(request.body)?;
                let active = session.get_or_insert_with(|| {
                    ramflux_sync::ObjectSyncSession::new(sync_request.manifest.clone(), content_key)
                });
                for chunk in sync_request.chunks {
                    active.receive_chunk(chunk, &device_branch)?;
                }
                let missing = active.missing_chunks();
                let resume_token = active.resume_token_with_device_branch(&device_branch)?;
                let assembled = if active.is_complete() { Some(active.assemble()?) } else { None };
                let node_visible_plaintext = assembled
                    .as_ref()
                    .is_some_and(|ciphertext| contains_subslice(ciphertext, &forbidden_plaintext));
                let node_visible_object_key = assembled
                    .as_ref()
                    .is_some_and(|ciphertext| contains_subslice(ciphertext, &forbidden_object_key));
                let assembled_cipher_hash = assembled.as_ref().map(|ciphertext| {
                    ramflux_crypto::blake3_256_base64url(
                        ramflux_protocol::domain::OBJECT,
                        ciphertext,
                    )
                });
                let assembled_ciphertext =
                    assembled.as_ref().map(ramflux_protocol::encode_base64url);
                serde_json::to_value(Mvp10QuicLanObjectSyncResponse {
                    missing,
                    resume_token,
                    complete: assembled.is_some(),
                    assembled_cipher_hash,
                    assembled_ciphertext,
                    node_visible_plaintext,
                    node_visible_object_key,
                })?
            } else {
                serde_json::json!({"error":"not found"})
            };
            ramflux_transport::write_quic_json_frame(
                &mut send,
                &ramflux_transport::GatewayQuicResponse { status: 200, body: response },
            )
            .await?;
        }
        connection.closed().await;
        Ok(())
    });
    Ok((addr, task))
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp10_notification_wake(
    wake_id: &str,
    delivery_class: ramflux_protocol::NotificationDeliveryClass,
    collapse_key: &str,
    encrypted_hint: &str,
) -> ramflux_protocol::NotificationWake {
    ramflux_protocol::NotificationWake {
        schema: "ramflux.notification_wake.v1".to_owned(),
        version: 1,
        domain: "ramflux.notification_wake.v1".to_owned(),
        ext: ramflux_protocol::Ext::default(),
        signed: itest_signed_fields(),
        wake_id: wake_id.to_owned(),
        push_alias: "push_alias_mvp10_wake".to_owned(),
        delivery_class,
        priority: ramflux_protocol::PushPriority::High,
        ttl: 30,
        collapse_key: Some(collapse_key.to_owned()),
        encrypted_hint: Some(encrypted_hint.to_owned()),
    }
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp10_queue_notify_wake(
    notify_url: &str,
    wake: &ramflux_protocol::NotificationWake,
) -> Result<ramflux_node_core::NotifyQueueEntry, Box<dyn std::error::Error>> {
    let mut wake = wake.clone();
    sign_itest_notification_wake(&mut wake)?;
    Ok(ramflux_node_core::itest_http_post_json(
        &format!("{notify_url}/mvp10/notify/wake"),
        &serde_json::json!({
            "wake": wake,
            "push_alias_hash": "push_alias_hash_mvp10",
            "queued_at": 1_760_000_000_u64
        }),
    )?)
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp10_deliver_notify_wake(
    notify_url: &str,
    queue_id: &str,
) -> Result<ramflux_node_core::NotifyQueueEntry, Box<dyn std::error::Error>> {
    Ok(ramflux_node_core::itest_http_post_json(
        &format!("{notify_url}/mvp10/notify/deliver"),
        &serde_json::json!({ "queue_id": queue_id }),
    )?)
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn deliver_mvp10_full_delegation_event(
    gateway_url: &str,
    fixture: &Mvp3McpA2uiFixture,
    registry_hash: &str,
    tool_manifest_set_hash: &str,
    envelope_id: &str,
    session_label: &str,
) -> Result<Mvp10FullDelegationEvent, Box<dyn std::error::Error>> {
    let (mut app_to_cli, mut cli_receiver) =
        establish_mvp3_pairwise_sessions(Mvp3PairwiseSessionInput {
            initiator_identity: &fixture.app_identity,
            initiator_ephemeral_seed: [0x8a; 32],
            recipient_bundle: &fixture.cli_prekey_bundle,
            recipient_identity: &fixture.cli_identity,
            recipient_signed_prekey: &fixture.cli_signed_prekey,
            associated_data: b"alice_app|cli_headless_ai",
            session_label,
        })?;
    let event = Mvp10FullDelegationEvent {
        event_type: "device.full_delegation.granted".to_owned(),
        grant_id: "grant_mvp10_full_delegation_realnet".to_owned(),
        source_app_device_id: "alice_app_device_mvp3_realnet".to_owned(),
        target_ai_device_id: "cli_headless_ai_mvp3_realnet".to_owned(),
        registry_hash: registry_hash.to_owned(),
        tool_manifest_set_hash: tool_manifest_set_hash.to_owned(),
        full_delegation: true,
    };
    deliver_mvp3_control_event(Mvp3ControlDelivery {
        gateway_url,
        envelope_id,
        target_delivery_id: "cli_headless_ai_target_mvp3_realnet",
        sender_session: &mut app_to_cli,
        receiver_session: &mut cli_receiver,
        associated_data: b"alice_app|cli_headless_ai",
        event: &event,
        forbidden_node_visible: b"grant_mvp10_full_delegation_realnet",
    })
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn deliver_mvp10_full_delegation_revoke(
    gateway_url: &str,
    fixture: &Mvp3McpA2uiFixture,
    grant_id: &str,
) -> Result<Mvp10FullDelegationRevokedEvent, Box<dyn std::error::Error>> {
    let (mut app_to_cli, mut cli_receiver) =
        establish_mvp3_pairwise_sessions(Mvp3PairwiseSessionInput {
            initiator_identity: &fixture.app_identity,
            initiator_ephemeral_seed: [0x8b; 32],
            recipient_bundle: &fixture.cli_prekey_bundle,
            recipient_identity: &fixture.cli_identity,
            recipient_signed_prekey: &fixture.cli_signed_prekey,
            associated_data: b"alice_app|cli_headless_ai",
            session_label: "mvp10-realnet-app-cli-full-delegation-revoke",
        })?;
    let event = Mvp10FullDelegationRevokedEvent {
        event_type: "device.full_delegation.revoked".to_owned(),
        grant_id: grant_id.to_owned(),
        revoked_by_device_id: "alice_app_device_mvp3_realnet".to_owned(),
        revoked_at: 1_760_000_100,
    };
    deliver_mvp3_control_event(Mvp3ControlDelivery {
        gateway_url,
        envelope_id: "env_mvp10_full_delegation_revoke",
        target_delivery_id: "cli_headless_ai_target_mvp3_realnet",
        sender_session: &mut app_to_cli,
        receiver_session: &mut cli_receiver,
        associated_data: b"alice_app|cli_headless_ai",
        event: &event,
        forbidden_node_visible: b"device.full_delegation.revoked",
    })
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn setup_mvp1_local_dbs()
-> Result<(Mvp1LocalDbFixture, ramflux_storage::AccountDb), Box<dyn std::error::Error>> {
    let root = temp_root("mvp1_realnet_local_db_persist")?;
    let index = ramflux_storage::AccountIndex::open(&root)?;
    index.create_account("bob_local", "bob_realnet")?;
    index.create_account("alice_local", "alice_realnet")?;

    let bob_key = ramflux_storage::AccountDbKey::derive("bob_local", b"bob-local-secret");
    let alice_key = ramflux_storage::AccountDbKey::derive("alice_local", b"alice-local-secret");
    let bob_db = ramflux_storage::AccountDb::open(&index, "bob_local", &bob_key)?;
    let alice_db = ramflux_storage::AccountDb::open(&index, "alice_local", &alice_key)?;
    assert_eq!(bob_db.encryption_mode(), ramflux_storage::EncryptionMode::SqlCipher);

    ramflux_storage::EventStore::append_event(
        &bob_db,
        "evt_bob_identity",
        "identity.root",
        b"bob_realnet",
    )?;
    ramflux_storage::EventStore::append_event(
        &bob_db,
        "evt_bob_device",
        "identity.device",
        b"bob_device_realnet",
    )?;
    ramflux_storage::EventStore::append_event(
        &alice_db,
        "evt_alice_identity",
        "identity.root",
        b"alice_realnet",
    )?;
    let fixture = Mvp1LocalDbFixture { root, bob_key, bob_db_path: bob_db.path.clone() };
    Ok((fixture, bob_db))
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn reopen_mvp1_bob_db(
    fixture: &Mvp1LocalDbFixture,
) -> Result<ramflux_storage::AccountDb, Box<dyn std::error::Error>> {
    let index = ramflux_storage::AccountIndex::open(&fixture.root)?;
    Ok(ramflux_storage::AccountDb::open(&index, "bob_local", &fixture.bob_key)?)
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn persist_bob_local_state(
    db: &ramflux_storage::AccountDb,
    session: &ramflux_crypto::DmSession,
    message_id: &str,
    plaintext: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let session_bytes = serde_json::to_vec(&session.snapshot())?;
    let event_id = format!("evt_bob_dm_session_{message_id}");
    ramflux_storage::EventStore::append_event(db, &event_id, "dm.ratchet_session", &session_bytes)?;
    db.send_direct_message("conv_mvp1_realnet", message_id, "alice", plaintext)?;
    ramflux_storage::ProjectionStore::set_projection_checkpoint(
        db,
        "conversation:conv_mvp1_realnet",
        message_id,
    )?;
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn restored_bob_session(
    db: &ramflux_storage::AccountDb,
    message_id: &str,
) -> Result<ramflux_crypto::DmSession, Box<dyn std::error::Error>> {
    let event_id = format!("evt_bob_dm_session_{message_id}");
    let bytes = ramflux_storage::EventStore::event_body(db, &event_id)?
        .ok_or("missing persisted bob DM session")?;
    let snapshot: ramflux_crypto::DmSessionSnapshot = serde_json::from_slice(&bytes)?;
    Ok(ramflux_crypto::DmSession::from_snapshot(snapshot)?)
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn assert_mvp1_local_db_static_encryption(
    path: &Path,
    plaintexts: &[&[u8]],
    sessions: &[&ramflux_crypto::DmSession],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut forbidden_needles: Vec<&[u8]> = vec![b"SQLite format 3".as_slice()];
    forbidden_needles.extend_from_slice(plaintexts);
    for session in sessions {
        forbidden_needles.push(session.session_id.as_bytes());
        forbidden_needles.push(session.root_key.expose().as_slice());
        forbidden_needles.push(session.sending_chain_key.expose().as_slice());
        forbidden_needles.push(session.receiving_chain_key.expose().as_slice());
    }
    assert_sqlcipher_file_encrypted(path, &forbidden_needles)
}
