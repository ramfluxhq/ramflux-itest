// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use super::*;

#[cfg(feature = "realnet")]
#[test]
fn mvp2_realnet_friend_message_projection() -> Result<(), Box<dyn std::error::Error>> {
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
    let clients = setup_mvp2_local_clients()?;

    let fetched: ramflux_node_core::PrekeyResponse = ramflux_node_core::itest_http_get_json(
        &format!("{gateway_url}/mvp1/prekey/bob_device_realnet"),
    )?;
    let bob_bundle = fetched.bundle.ok_or("missing bob prekey bundle")?;
    let (mut alice_session, mut bob_session) = establish_mvp1_dm_sessions(&fixture, &bob_bundle)?;

    exchange_mvp2_friend_link(gateway_url, &clients, &mut alice_session, &mut bob_session)?;
    let plaintexts = [
        b"mvp2 friend dm 001".as_slice(),
        b"mvp2 friend dm 002".as_slice(),
        b"mvp2 friend dm 003".as_slice(),
    ];
    deliver_mvp2_friend_messages(
        gateway_url,
        &clients.bob_db,
        &mut alice_session,
        &mut bob_session,
        &plaintexts,
    )?;
    assert_mvp2_bob_conversation_projection(&clients.bob_db, &plaintexts)?;
    Ok(())
}

#[cfg(feature = "realnet")]
#[test]
fn mvp2_realnet_group_sender_keys_fanout_bot_consent() -> Result<(), Box<dyn std::error::Error>> {
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
    let bot = register_mvp2_bot_identity(gateway_url)?;
    let clients = setup_mvp2_local_clients()?;

    clients.alice_db.create_group("group_mvp2_realnet", "alice")?;
    clients.bob_db.create_group("group_mvp2_realnet", "alice")?;
    clients.bob_db.add_group_member("group_mvp2_realnet", "bob", "member")?;
    assert_mvp2_bot_consent_gate(&clients.bob_db)?;

    let fetched: ramflux_node_core::PrekeyResponse = ramflux_node_core::itest_http_get_json(
        &format!("{gateway_url}/mvp1/prekey/bob_device_realnet"),
    )?;
    let bob_bundle = fetched.bundle.ok_or("missing bob prekey bundle")?;
    let (mut alice_session, mut bob_session) = establish_mvp1_dm_sessions(&fixture, &bob_bundle)?;
    let mut group_epoch =
        ramflux_storage::GroupKeyEpochState::new("group_mvp2_realnet", ["alice".to_owned()]);
    group_epoch.add_member_no_history("bob");

    join_mvp2_bot_after_member_consents(&clients.bob_db, &mut group_epoch)?;
    deliver_mvp2_group_sender_key_distribution(
        gateway_url,
        &mut alice_session,
        &mut bob_session,
        &mut group_epoch,
    )?;
    let group_plaintext = b"mvp2 group sender keys fanout";
    let fanout = Mvp2GroupFanoutContext {
        gateway_url,
        alice_recipient_session: &mut alice_session,
        recipient_session: &mut bob_session,
        group_epoch: &group_epoch,
        bot: &bot,
        bot_target_delivery_id: &bot.target_delivery_id,
        plaintext: group_plaintext,
    };
    deliver_mvp2_group_message_fanout(fanout)?;
    assert_mvp2_group_projection(&clients.bob_db, group_plaintext)?;
    Ok(())
}

#[cfg(feature = "realnet")]
#[test]
fn mvp3_realnet_object_sync_chunk_resume_tombstone() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    let realnet = start_realnet_compose()?;
    let gateway_url = &realnet.gateway_url;
    let relay_url = &realnet.relay_url;
    let fixture = mvp1_dm_realnet_fixture()?;
    register_mvp1_identity(gateway_url, &fixture.bob_register)?;
    publish_mvp1_prekey(gateway_url, "bob_device_realnet", &fixture.bob_prekey_bundle)?;
    register_mvp1_identity(gateway_url, &fixture.alice_register)?;

    let fetched: ramflux_node_core::PrekeyResponse = ramflux_node_core::itest_http_get_json(
        &format!("{gateway_url}/mvp1/prekey/bob_device_realnet"),
    )?;
    let bob_bundle = fetched.bundle.ok_or("missing bob prekey bundle")?;
    let (mut alice_session, mut bob_session) = establish_mvp1_dm_sessions(&fixture, &bob_bundle)?;

    let plaintext = b"mvp3 object sync plaintext should stay client-side";
    let mut source = ramflux_sync::ObjectStore::new();
    let object = source.put_encrypted_object("object_mvp3_realnet", plaintext)?;
    let content_key = source.object_key(&object.object_id)?;
    assert_ne!(object.ciphertext, plaintext);
    let manifest =
        ramflux_sync::chunk_manifest_for_object(&object.object_id, &object.ciphertext, 7, Some(3));
    let mut receiver = deliver_mvp3_object_manifest(
        gateway_url,
        &mut alice_session,
        &mut bob_session,
        &manifest,
        content_key,
        plaintext,
    )?;

    let chunks = mvp3_object_chunks(&content_key, &manifest, &object.ciphertext)?;
    assert_mvp3_object_relay_put_get_ack_tombstone(relay_url, &manifest, &chunks[1])?;
    deliver_mvp3_object_chunk(gateway_url, &mut receiver, &chunks[0], plaintext)?;
    deliver_mvp3_object_chunk(gateway_url, &mut receiver, &chunks[2], plaintext)?;
    let expected_missing = expected_mvp3_missing_chunks(manifest.total_chunks, &[0, 2]);
    assert_eq!(receiver.missing_chunks().missing_indices, expected_missing);
    let resume_branch = ramflux_crypto::create_device_branch(
        "principal_mvp3_object_sync",
        "mvp3_object_sync_receiver",
        1,
        [0x8C; 32],
    );
    assert_eq!(
        receiver.resume_token_with_device_branch(&resume_branch)?.next_missing_chunk,
        Some(1)
    );
    for chunk in remaining_mvp3_chunks(&chunks, &[0, 2]) {
        deliver_mvp3_object_chunk(gateway_url, &mut receiver, chunk, plaintext)?;
    }
    assert!(receiver.is_complete());
    assert_eq!(receiver.assemble()?, object.ciphertext);
    assert_eq!(source.decrypt_object(&object.object_id)?, plaintext);

    deliver_mvp3_object_tombstone(
        gateway_url,
        &mut alice_session,
        &mut bob_session,
        &object.object_id,
        &object.manifest_hash,
        plaintext,
    )?;
    source.tombstone(&object.object_id)?;
    assert!(source.decrypt_object(&object.object_id).is_err());
    Ok(())
}

#[cfg(feature = "realnet")]
fn assert_mvp3_object_relay_put_get_ack_tombstone(
    relay_url: &str,
    manifest: &ramflux_sync::ChunkManifest,
    chunk: &ramflux_sync::ChunkPayload,
) -> Result<(), Box<dyn std::error::Error>> {
    let chunk_id = format!("{}:{}", manifest.object_id, chunk.chunk_index);
    let context = Mvp3RelayContext {
        service_key: b"ramflux-relay-itest-service-key",
        now: current_epoch_seconds(),
        manifest,
        chunk,
        chunk_id: &chunk_id,
    };
    mvp3_relay_put_chunk(relay_url, &context)?;
    mvp3_relay_get_chunk(relay_url, &context)?;
    mvp3_relay_ack_chunk(relay_url, &context)?;
    mvp3_relay_tombstone_object(relay_url, &context)?;
    mvp3_relay_reject_reput_after_tombstone(relay_url, &context)?;
    Ok(())
}

#[cfg(feature = "realnet")]
struct Mvp3RelayContext<'a> {
    service_key: &'a [u8],
    now: u64,
    manifest: &'a ramflux_sync::ChunkManifest,
    chunk: &'a ramflux_sync::ChunkPayload,
    chunk_id: &'a str,
}

#[cfg(feature = "realnet")]
fn mvp3_relay_put_chunk(
    relay_url: &str,
    context: &Mvp3RelayContext<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let frame = mvp3_relay_object_frame(
        context,
        ramflux_node_core::ObjectRelayCapability::Put,
        context.chunk_id,
        true,
    )?;
    let put: ramflux_node_core::ObjectRelayPutResponse = ramflux_node_core::itest_http_post_json(
        &format!("{relay_url}/relay/v1/object/put_chunk"),
        &frame,
    )?;
    assert_eq!(put.chunk_id, context.chunk_id);
    assert_eq!(put.status, ramflux_node_core::RelayChunkStatus::Available);
    Ok(())
}

#[cfg(feature = "realnet")]
fn mvp3_relay_get_chunk(
    relay_url: &str,
    context: &Mvp3RelayContext<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let get = ramflux_node_core::ObjectRelayGetRequest {
        chunk_id: context.chunk_id.to_owned(),
        relay_token: mvp3_relay_token_for_chunk(
            context,
            ramflux_node_core::ObjectRelayCapability::Get,
            context.now + 1,
            context.chunk_id,
            false,
        )?,
        object_permission_envelope: mvp3_relay_permission(
            ramflux_node_core::ObjectRelayCapability::Get,
            context.now + 1,
            context.manifest,
        )?,
    };
    let fetched: ramflux_node_core::ObjectRelayGetResponse =
        ramflux_node_core::itest_http_post_json(
            &format!("{relay_url}/relay/v1/object/get_chunk"),
            &get,
        )?;
    assert_eq!(fetched.chunk.encrypted_chunk, context.chunk.ciphertext);
    assert_eq!(fetched.chunk.chunk_cipher_hash, context.chunk.cipher_hash);
    Ok(())
}

#[cfg(feature = "realnet")]
fn mvp3_relay_ack_chunk(
    relay_url: &str,
    context: &Mvp3RelayContext<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let ack = ramflux_node_core::ObjectRelayAck {
        object_id: context.manifest.object_id.clone(),
        manifest_hash: context.manifest.manifest_hash.clone(),
        chunk_id: context.chunk_id.to_owned(),
        recipient_device_hash: "bob_device_realnet_hash".to_owned(),
        relay_token: mvp3_relay_token_for_chunk(
            context,
            ramflux_node_core::ObjectRelayCapability::Ack,
            context.now + 2,
            context.chunk_id,
            true,
        )?,
        object_permission_envelope: mvp3_relay_permission(
            ramflux_node_core::ObjectRelayCapability::Ack,
            context.now + 2,
            context.manifest,
        )?,
        acked_at: context.now + 2,
    };
    let acked: ramflux_node_core::ObjectRelayAckResponse =
        ramflux_node_core::itest_http_post_json(&format!("{relay_url}/relay/v1/object/ack"), &ack)?;
    assert_eq!(acked.status, ramflux_node_core::RelayChunkStatus::AckedDeleted);
    Ok(())
}

#[cfg(feature = "realnet")]
fn mvp3_relay_tombstone_object(
    relay_url: &str,
    context: &Mvp3RelayContext<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let tombstone = ramflux_node_core::ObjectRelayTombstone {
        object_id: context.manifest.object_id.clone(),
        manifest_hash: Some(context.manifest.manifest_hash.clone()),
        tombstone_hash: ramflux_crypto::blake3_256_base64url(
            "ramflux.object_relay_tombstone.mvp3_realnet.v1",
            context.manifest.object_id.as_bytes(),
        ),
        source_event_id: "event_mvp3_relay_tombstone".to_owned(),
        signed_at: context.now + 3,
        expires_at: context.now + ramflux_node_core::OBJECT_RELAY_TOMBSTONE_DEFAULT_TTL_SECONDS,
        relay_token: mvp3_relay_token_for_chunk(
            context,
            ramflux_node_core::ObjectRelayCapability::Tombstone,
            context.now + 3,
            context.chunk_id,
            false,
        )?,
        object_permission_envelope: mvp3_relay_permission(
            ramflux_node_core::ObjectRelayCapability::Tombstone,
            context.now + 3,
            context.manifest,
        )?,
    };
    let tombstoned: ramflux_node_core::ObjectRelayTombstoneResponse =
        ramflux_node_core::itest_http_post_json(
            &format!("{relay_url}/relay/v1/object/tombstone"),
            &tombstone,
        )?;
    assert_eq!(tombstoned.object_id, context.manifest.object_id);
    assert_eq!(tombstoned.tombstone_hash, tombstone.tombstone_hash);
    Ok(())
}

#[cfg(feature = "realnet")]
fn mvp3_relay_reject_reput_after_tombstone(
    relay_url: &str,
    context: &Mvp3RelayContext<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let blocked = mvp3_relay_object_frame(
        context,
        ramflux_node_core::ObjectRelayCapability::Put,
        "blocked_after_tombstone",
        false,
    )?;
    let blocked_result: Result<ramflux_node_core::ObjectRelayPutResponse, _> =
        ramflux_node_core::itest_http_post_json(
            &format!("{relay_url}/relay/v1/object/put_chunk"),
            &blocked,
        );
    assert!(blocked_result.is_err(), "tombstoned relay object accepted a new chunk");
    Ok(())
}

#[cfg(feature = "realnet")]
fn mvp3_relay_object_frame(
    context: &Mvp3RelayContext<'_>,
    capability: ramflux_node_core::ObjectRelayCapability,
    chunk_id: &str,
    delete_after_ack: bool,
) -> Result<ramflux_node_core::ObjectChunkFrame, Box<dyn std::error::Error>> {
    Ok(ramflux_node_core::ObjectChunkFrame {
        schema: "ramflux.object_chunk_frame.v1".to_owned(),
        object_id: context.manifest.object_id.clone(),
        manifest_hash: context.manifest.manifest_hash.clone(),
        chunk_index: context.chunk.chunk_index,
        chunk_id: chunk_id.to_owned(),
        chunk_cipher_hash: context.chunk.cipher_hash.clone(),
        cipher_size: context.chunk.ciphertext.len() as u64,
        encrypted_chunk: context.chunk.ciphertext.clone(),
        relay_token: mvp3_relay_token_for_chunk(
            context,
            capability,
            context.now,
            chunk_id,
            delete_after_ack,
        )?,
        object_permission_envelope: mvp3_relay_permission(
            capability,
            context.now,
            context.manifest,
        )?,
        expires_at: context.now + ramflux_node_core::OBJECT_RELAY_CHUNK_DEFAULT_TTL_SECONDS,
        delete_after_ack,
    })
}

#[cfg(feature = "realnet")]
fn mvp3_relay_token_for_chunk(
    context: &Mvp3RelayContext<'_>,
    capability: ramflux_node_core::ObjectRelayCapability,
    now: u64,
    chunk_id: &str,
    delete_after_ack: bool,
) -> Result<ramflux_node_core::RelayToken, Box<dyn std::error::Error>> {
    let mut token = ramflux_node_core::RelayToken {
        token_id: format!("mvp3_relay_token_{chunk_id}_{capability:?}"),
        object_id: context.manifest.object_id.clone(),
        manifest_hash: context.manifest.manifest_hash.clone(),
        chunk_id: chunk_id.to_owned(),
        recipient_device_hash: "bob_device_realnet_hash".to_owned(),
        owner_signing_key_id: "mvp3_owner_fixture".to_owned(),
        owner_public_key: ramflux_crypto::fixture_public_key_base64url(),
        issuer_service: "router".to_owned(),
        capabilities: vec![capability],
        delete_after_ack,
        issued_at: now,
        expires_at: now + ramflux_node_core::OBJECT_RELAY_CHUNK_DEFAULT_TTL_SECONDS,
        nonce: format!("nonce_{chunk_id}_{now}"),
        mac: String::new(),
    };
    token.mac = ramflux_node_core::relay_token_mac(context.service_key, &token)?;
    Ok(token)
}

#[cfg(feature = "realnet")]
fn mvp3_relay_permission(
    capability: ramflux_node_core::ObjectRelayCapability,
    now: u64,
    manifest: &ramflux_sync::ChunkManifest,
) -> Result<ramflux_node_core::ObjectPermissionEnvelope, Box<dyn std::error::Error>> {
    let mut permission = ramflux_node_core::ObjectPermissionEnvelope {
        object_id: manifest.object_id.clone(),
        manifest_hash: manifest.manifest_hash.clone(),
        grantee_device_hash: "bob_device_realnet_hash".to_owned(),
        capability,
        issued_at: now,
        expires_at: now + ramflux_node_core::OBJECT_RELAY_CHUNK_DEFAULT_TTL_SECONDS,
        owner_signing_key_id: "mvp3_owner_fixture".to_owned(),
        owner_public_key: ramflux_crypto::fixture_public_key_base64url(),
        owner_signature: String::new(),
    };
    permission.owner_signature = ramflux_crypto::sign_canonical_bytes(
        &ramflux_node_core::object_permission_canonical_bytes(&permission)?,
    );
    Ok(permission)
}

#[cfg(feature = "realnet")]
fn current_epoch_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

#[cfg(feature = "realnet")]
#[test]
fn mvp3_realnet_mcp_a2ui_approval_grant() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    let realnet = start_realnet_compose()?;
    let gateway_url = &realnet.gateway_url;
    let fixture = mvp3_mcp_a2ui_fixture()?;
    register_mvp1_identity(gateway_url, &fixture.app_register)?;
    register_mvp1_identity(gateway_url, &fixture.cli_register)?;
    publish_mvp1_prekey(gateway_url, "alice_app_device_mvp3_realnet", &fixture.app_prekey_bundle)?;
    publish_mvp1_prekey(gateway_url, "cli_headless_ai_mvp3_realnet", &fixture.cli_prekey_bundle)?;

    let mut registry = mcp_registry_with_search_tool();
    let approval_surface = mvp3_a2ui_approval_surface();
    let approval = deliver_mvp3_a2ui_approval_request(gateway_url, &fixture, &approval_surface)?;
    let rendered = ramflux_sync::render_a2ui_surface(
        &approval.surface,
        &BTreeSet::from(["ramflux.mvp".to_owned()]),
        &BTreeSet::from(["mcp.approve".to_owned()]),
    )?;
    assert!(rendered.semantic_snapshot.contains("surface_mvp3_mcp_approval"));

    let grant_event = deliver_mvp3_a2i_mcp_grant(
        gateway_url,
        &fixture,
        registry.registry_hash(),
        registry.tool_manifest_set_hash(),
    )?;
    let grant = ramflux_sync::McpGrantState {
        server_id: "srv".to_owned(),
        tool_name: "search".to_owned(),
        tool_scope: Some("search".to_owned()),
        registry_hash: grant_event.registry_hash,
        tool_manifest_set_hash: grant_event.tool_manifest_set_hash,
        full_delegation: false,
        allowed_capabilities: BTreeSet::from([
            serde_json::from_str::<ramflux_sync::McpCapability>(&format!(
                "\"{}\"",
                grant_event.capability
            ))?,
        ]),
        revoked: false,
        expires_at: 4_000_000_000,
    };
    assert_eq!(registry.invoke_tool("srv", "search", &grant)?, "srv:search");

    registry.install_tool(mcp_manifest(
        "srv",
        "shell",
        ramflux_sync::McpCapability::RunShell,
        None,
        ramflux_sync::RiskLevel::High,
    ));
    assert!(registry.invoke_tool("srv", "search", &grant).is_err());
    let wildcard = ramflux_sync::McpGrantState {
        server_id: "wildcard".to_owned(),
        tool_name: "wildcard".to_owned(),
        tool_scope: Some("wildcard".to_owned()),
        registry_hash: registry.registry_hash().to_owned(),
        tool_manifest_set_hash: registry.tool_manifest_set_hash().to_owned(),
        full_delegation: true,
        allowed_capabilities: BTreeSet::new(),
        revoked: false,
        expires_at: 4_000_000_000,
    };
    assert!(registry.invoke_tool("srv", "shell", &wildcard).is_err());
    Ok(())
}

#[cfg(feature = "realnet")]
#[test]
fn mvp3_realnet_webrtc_opaque_signaling_turn_no_media_key() -> Result<(), Box<dyn std::error::Error>>
{
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

    let fetched: ramflux_node_core::PrekeyResponse = ramflux_node_core::itest_http_get_json(
        &format!("{gateway_url}/mvp1/prekey/bob_device_realnet"),
    )?;
    let bob_bundle = fetched.bundle.ok_or("missing bob prekey bundle")?;
    let (mut alice_session, mut bob_session) = establish_mvp1_dm_sessions(&fixture, &bob_bundle)?;

    let offer = mvp3_call_signal("offer", "v=0\\r\\nsecret-sdp-offer", "SRTP_MEDIA_KEY_MVP3");
    let delivered_offer = deliver_mvp3_call_signal(
        gateway_url,
        "env_mvp3_webrtc_offer",
        "bob_target_mvp1_realnet",
        &mut alice_session,
        &mut bob_session,
        &offer,
    )?;
    assert_eq!(delivered_offer.signal_type, "offer");
    assert!(delivered_offer.opaque_sdp.contains("secret-sdp-offer"));

    let answer = mvp3_call_signal("answer", "v=0\\r\\nsecret-sdp-answer", "SRTP_MEDIA_KEY_MVP3");
    let delivered_answer = deliver_mvp3_call_signal(
        gateway_url,
        "env_mvp3_webrtc_answer",
        "alice_target_mvp1_realnet",
        &mut bob_session,
        &mut alice_session,
        &answer,
    )?;
    assert_eq!(delivered_answer.signal_type, "answer");
    assert!(delivered_answer.opaque_sdp.contains("secret-sdp-answer"));

    let mut signaling = ramflux_node_core::SignalingState::new();
    signaling.submit_opaque_call_envelope(mvp3_call_session("call_mvp3_realnet"));
    signaling.activate_call("call_mvp3_realnet")?;
    signaling.allocate_turn(mvp3_turn_allocation("alloc_mvp3_turn", "peer_hash_b"))?;
    assert_eq!(signaling.active_call_count(), 1);
    assert_eq!(
        signaling.allocation("alloc_mvp3_turn").map(|allocation| allocation.bandwidth_limit_bps),
        Some(2_000_000)
    );
    assert!(!signaling.srtp_media_key_visible("call_mvp3_realnet"));

    let relay = ramflux_sync::relay_opaque_call_signal(&ramflux_sync::OpaqueCallSignal {
        call_id: "call_mvp3_realnet".to_owned(),
        opaque_payload: serde_json::to_vec(&offer)?,
    });
    ramflux_sync::assert_srtp_relay_has_no_media_key(&relay)?;
    assert_ne!(relay.forwarded_payload_hash, "v=0");
    Ok(())
}
