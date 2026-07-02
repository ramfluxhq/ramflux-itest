// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use crate::*;

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp3_mcp_a2ui_fixture() -> Result<Mvp3McpA2uiFixture, Box<dyn std::error::Error>> {
    let root = ramflux_crypto::create_identity_root("alice_mvp3_realnet", [0x71; 32]);
    let app_device = ramflux_crypto::create_device_branch(
        "alice_mvp3_realnet",
        "alice_app_device_mvp3_realnet",
        1,
        [0x72; 32],
    );
    let cli_device = ramflux_crypto::create_device_branch(
        "alice_mvp3_realnet",
        "cli_headless_ai_mvp3_realnet",
        1,
        [0x73; 32],
    );
    let app_register = mvp1_named_register_request(
        &root,
        &app_device,
        "alice_app_target_mvp3_realnet",
        "alice_app_session_mvp3_realnet",
        31,
    )?;
    let cli_register = mvp1_named_register_request(
        &root,
        &cli_device,
        "cli_headless_ai_target_mvp3_realnet",
        "cli_headless_ai_session_mvp3_realnet",
        32,
    )?;
    let app_identity = ramflux_crypto::X25519KeyPair::from_seed([0x74; 32]);
    let app_signed_prekey = ramflux_crypto::X25519KeyPair::from_seed([0x75; 32]);
    let app_prekey_bundle = ramflux_crypto::create_prekey_bundle(
        &app_device,
        &app_identity,
        "spk_app_mvp3_realnet",
        &app_signed_prekey,
        None,
        None,
    )?;
    let cli_identity = ramflux_crypto::X25519KeyPair::from_seed([0x76; 32]);
    let cli_signed_prekey = ramflux_crypto::X25519KeyPair::from_seed([0x77; 32]);
    let cli_prekey_bundle = ramflux_crypto::create_prekey_bundle(
        &cli_device,
        &cli_identity,
        "spk_cli_mvp3_realnet",
        &cli_signed_prekey,
        None,
        None,
    )?;
    Ok(Mvp3McpA2uiFixture {
        app_register,
        cli_register,
        app_identity,
        app_signed_prekey,
        app_prekey_bundle,
        cli_identity,
        cli_signed_prekey,
        cli_prekey_bundle,
    })
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp3_a2ui_approval_surface() -> ramflux_sync::A2uiSurface {
    ramflux_sync::A2uiSurface {
        surface_id: "surface_mvp3_mcp_approval".to_owned(),
        catalog: "ramflux.mvp".to_owned(),
        catalog_version: "1".to_owned(),
        components: vec![ramflux_sync::A2uiComponent {
            id: "approve_search_tool".to_owned(),
            component_type: "button".to_owned(),
            action_permission: Some("mcp.approve".to_owned()),
            children: Vec::new(),
        }],
    }
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn deliver_mvp3_a2ui_approval_request(
    gateway_url: &str,
    fixture: &Mvp3McpA2uiFixture,
    surface: &ramflux_sync::A2uiSurface,
) -> Result<Mvp3A2uiApprovalRequest, Box<dyn std::error::Error>> {
    let (mut cli_to_app, mut app_receiver) =
        establish_mvp3_pairwise_sessions(Mvp3PairwiseSessionInput {
            initiator_identity: &fixture.cli_identity,
            initiator_ephemeral_seed: [0x78; 32],
            recipient_bundle: &fixture.app_prekey_bundle,
            recipient_identity: &fixture.app_identity,
            recipient_signed_prekey: &fixture.app_signed_prekey,
            associated_data: b"cli_headless_ai|alice_app",
            session_label: "mvp3-realnet-cli-app-a2ui",
        })?;
    let event = Mvp3A2uiApprovalRequest {
        event_type: "mcp.approval.request".to_owned(),
        source_device_id: "cli_headless_ai_mvp3_realnet".to_owned(),
        target_device_id: "alice_app_device_mvp3_realnet".to_owned(),
        control_session_id: "control_mvp3_mcp_realnet".to_owned(),
        surface: surface.clone(),
    };
    deliver_mvp3_control_event(Mvp3ControlDelivery {
        gateway_url,
        envelope_id: "env_mvp3_a2ui_approval_request",
        target_delivery_id: "alice_app_target_mvp3_realnet",
        sender_session: &mut cli_to_app,
        receiver_session: &mut app_receiver,
        associated_data: b"cli_headless_ai|alice_app",
        event: &event,
        forbidden_node_visible: b"surface_mvp3_mcp_approval",
    })
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn deliver_mvp3_a2i_mcp_grant(
    gateway_url: &str,
    fixture: &Mvp3McpA2uiFixture,
    registry_hash: &str,
    tool_manifest_set_hash: &str,
) -> Result<Mvp3A2iMcpGrantEvent, Box<dyn std::error::Error>> {
    let (mut app_to_cli, mut cli_receiver) =
        establish_mvp3_pairwise_sessions(Mvp3PairwiseSessionInput {
            initiator_identity: &fixture.app_identity,
            initiator_ephemeral_seed: [0x79; 32],
            recipient_bundle: &fixture.cli_prekey_bundle,
            recipient_identity: &fixture.cli_identity,
            recipient_signed_prekey: &fixture.cli_signed_prekey,
            associated_data: b"alice_app|cli_headless_ai",
            session_label: "mvp3-realnet-app-cli-a2i",
        })?;
    let event = Mvp3A2iMcpGrantEvent {
        event_type: "mcp.approval.granted".to_owned(),
        grant_id: "grant_mvp3_search_realnet".to_owned(),
        source_app_device_id: "alice_app_device_mvp3_realnet".to_owned(),
        target_ai_device_id: "cli_headless_ai_mvp3_realnet".to_owned(),
        capability: "read_conversation".to_owned(),
        registry_hash: registry_hash.to_owned(),
        tool_manifest_set_hash: tool_manifest_set_hash.to_owned(),
        risk_level: "low".to_owned(),
    };
    deliver_mvp3_control_event(Mvp3ControlDelivery {
        gateway_url,
        envelope_id: "env_mvp3_a2i_mcp_grant",
        target_delivery_id: "cli_headless_ai_target_mvp3_realnet",
        sender_session: &mut app_to_cli,
        receiver_session: &mut cli_receiver,
        associated_data: b"alice_app|cli_headless_ai",
        event: &event,
        forbidden_node_visible: b"grant_mvp3_search_realnet",
    })
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn establish_mvp3_pairwise_sessions(
    input: Mvp3PairwiseSessionInput<'_>,
) -> Result<(ramflux_crypto::DmSession, ramflux_crypto::DmSession), Box<dyn std::error::Error>> {
    let initiator_ephemeral =
        ramflux_crypto::X25519KeyPair::from_seed(input.initiator_ephemeral_seed);
    let bundle_bytes = serde_json::to_vec(input.recipient_bundle)?;
    let prekey_bundle_hash =
        ramflux_crypto::blake3_256(ramflux_protocol::domain::X3DH_PREKEY_BUNDLE, &bundle_bytes);
    let initiator_hash = ramflux_crypto::blake3_256(
        ramflux_protocol::domain::DEVICE_PROOF,
        format!("{}:initiator", input.session_label).as_bytes(),
    );
    let recipient_hash = ramflux_crypto::blake3_256(
        ramflux_protocol::domain::DEVICE_PROOF,
        format!("{}:recipient", input.session_label).as_bytes(),
    );
    let initiator = ramflux_crypto::x3dh_initiator(&ramflux_crypto::X3dhInitiatorInput {
        initiator_identity: input.initiator_identity,
        initiator_ephemeral: &initiator_ephemeral,
        initiator_device_id_hash: initiator_hash,
        recipient_device_id_hash: recipient_hash,
        recipient_bundle: input.recipient_bundle,
        associated_data: input.associated_data,
        prekey_bundle_hash: &prekey_bundle_hash,
        initial_ratchet_public: initiator_ephemeral.public,
    })?;
    let recipient = ramflux_crypto::x3dh_recipient(&ramflux_crypto::X3dhRecipientInput {
        recipient_identity: input.recipient_identity,
        recipient_signed_prekey: input.recipient_signed_prekey,
        recipient_one_time_prekey: None,
        initiator_identity_public: input.initiator_identity.public,
        initiator_ephemeral_public: initiator_ephemeral.public,
        initiator_device_id_hash: initiator_hash,
        recipient_device_id_hash: recipient_hash,
        recipient_signed_prekey_id: &input.recipient_bundle.signed_prekey_id,
        recipient_one_time_prekey_id: input.recipient_bundle.one_time_prekey_id.as_deref(),
        associated_data: input.associated_data,
        prekey_bundle_hash: &prekey_bundle_hash,
        initial_ratchet_public: initiator_ephemeral.public,
    })?;
    Ok((
        ramflux_crypto::DmSession::initiator(
            initiator.root_seed,
            initiator_hash,
            recipient_hash,
            initiator.bootstrap_transcript_hash,
        )?,
        ramflux_crypto::DmSession::recipient(
            recipient.root_seed,
            recipient_hash,
            initiator_hash,
            recipient.bootstrap_transcript_hash,
        )?,
    ))
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn deliver_mvp3_control_event<T>(
    delivery: Mvp3ControlDelivery<'_, T>,
) -> Result<T, Box<dyn std::error::Error>>
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    let Mvp3ControlDelivery {
        gateway_url,
        envelope_id,
        target_delivery_id,
        sender_session,
        receiver_session,
        associated_data,
        event,
        forbidden_node_visible,
    } = delivery;
    let event_json = serde_json::to_vec(event)?;
    let ciphertext = sender_session.encrypt(&event_json, associated_data)?;
    let delivered = deliver_mvp1_dm(gateway_url, envelope_id, target_delivery_id, &ciphertext)?;
    assert_node_opaque_payload(&delivered.envelope.encrypted_payload, forbidden_node_visible);
    let delivered_ciphertext: ramflux_crypto::DmCiphertext =
        serde_json::from_str(&delivered.envelope.encrypted_payload)?;
    let decrypted = receiver_session.decrypt(&delivered_ciphertext, associated_data)?;
    Ok(serde_json::from_slice(&decrypted)?)
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp3_call_signal(
    signal_type: &str,
    opaque_sdp: &str,
    srtp_key_material: &str,
) -> Mvp3CallSignalEvent {
    Mvp3CallSignalEvent {
        event_type: "webrtc.call_signal".to_owned(),
        call_id: "call_mvp3_realnet".to_owned(),
        signal_type: signal_type.to_owned(),
        opaque_sdp: opaque_sdp.to_owned(),
        ice_ufrag: format!("ice_{signal_type}_mvp3"),
        srtp_key_material: srtp_key_material.to_owned(),
    }
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn deliver_mvp3_call_signal(
    gateway_url: &str,
    envelope_id: &str,
    target_delivery_id: &str,
    sender_session: &mut ramflux_crypto::DmSession,
    receiver_session: &mut ramflux_crypto::DmSession,
    signal: &Mvp3CallSignalEvent,
) -> Result<Mvp3CallSignalEvent, Box<dyn std::error::Error>> {
    let signal_json = serde_json::to_vec(signal)?;
    let ciphertext = sender_session.encrypt(&signal_json, b"alice_device|bob_device")?;
    let delivered = deliver_mvp1_dm(gateway_url, envelope_id, target_delivery_id, &ciphertext)?;
    assert_node_opaque_payload(&delivered.envelope.encrypted_payload, b"v=0");
    assert_node_opaque_payload(&delivered.envelope.encrypted_payload, signal.opaque_sdp.as_bytes());
    assert_node_opaque_payload(
        &delivered.envelope.encrypted_payload,
        signal.srtp_key_material.as_bytes(),
    );
    let delivered_ciphertext: ramflux_crypto::DmCiphertext =
        serde_json::from_str(&delivered.envelope.encrypted_payload)?;
    let decrypted = receiver_session.decrypt(&delivered_ciphertext, b"alice_device|bob_device")?;
    Ok(serde_json::from_slice(&decrypted)?)
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp3_call_session(call_id: &str) -> ramflux_node_core::OpaqueCallSession {
    ramflux_node_core::OpaqueCallSession {
        call_id: call_id.to_owned(),
        caller_device_hash: "caller_hash".to_owned(),
        callee_device_hash: "callee_hash".to_owned(),
        allowed_peer_hashes: BTreeSet::from(["peer_hash_b".to_owned()]),
        created_at: 1_760_000_000,
        expires_at: 1_760_003_600,
        lifecycle: ramflux_node_core::CallSessionLifecycle::Pending,
        opaque_envelope_hash: "opaque_envelope_hash_mvp3_realnet".to_owned(),
    }
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp3_turn_allocation(
    allocation_id: &str,
    peer_hash: &str,
) -> ramflux_node_core::TurnAllocation {
    ramflux_node_core::TurnAllocation {
        allocation_id: allocation_id.to_owned(),
        call_id: "call_mvp3_realnet".to_owned(),
        username_hash: "turn_username_hash_mvp3_realnet".to_owned(),
        identity_hash: "identity_hash_mvp3_realnet".to_owned(),
        peer_hash: peer_hash.to_owned(),
        source_ip_hash: "source_ip_hash_mvp3_realnet".to_owned(),
        relay_address: "203.0.113.30:49152".to_owned(),
        bandwidth_limit_bps: 2_000_000,
        burst_limit_bps: 4_000_000,
        created_at: 1_760_000_001,
        expires_at: 1_760_000_601,
        bytes_relayed: 0,
        packets_relayed: 0,
    }
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn deliver_mvp3_object_manifest(
    gateway_url: &str,
    alice_session: &mut ramflux_crypto::DmSession,
    bob_session: &mut ramflux_crypto::DmSession,
    manifest: &ramflux_sync::ChunkManifest,
    content_key: [u8; 32],
    plaintext: &[u8],
) -> Result<ramflux_sync::ObjectSyncSession, Box<dyn std::error::Error>> {
    let event = Mvp3ObjectManifestEvent {
        event_type: "object.manifest".to_owned(),
        object_id: manifest.object_id.clone(),
        manifest_hash: manifest.manifest_hash.clone(),
        chunk_size: manifest.chunk_size,
        total_chunks: manifest.total_chunks,
        object_created_group_key_epoch: manifest.object_created_group_key_epoch,
    };
    let decrypted: Mvp3ObjectManifestEvent = deliver_mvp3_object_event(
        gateway_url,
        "env_mvp3_object_manifest",
        alice_session,
        bob_session,
        &event,
        plaintext,
    )?;
    assert_eq!(decrypted.event_type, "object.manifest");
    assert_eq!(decrypted.object_created_group_key_epoch, Some(3));
    Ok(ramflux_sync::ObjectSyncSession::new(
        ramflux_sync::ChunkManifest {
            object_id: decrypted.object_id,
            manifest_hash: decrypted.manifest_hash,
            chunk_size: decrypted.chunk_size,
            total_chunks: decrypted.total_chunks,
            object_created_group_key_epoch: decrypted.object_created_group_key_epoch,
        },
        content_key,
    ))
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp3_object_chunks(
    content_key: &[u8; 32],
    manifest: &ramflux_sync::ChunkManifest,
    ciphertext: &[u8],
) -> Result<Vec<ramflux_sync::ChunkPayload>, Box<dyn std::error::Error>> {
    let mut chunks = Vec::new();
    for index in 0..manifest.total_chunks {
        let start = usize::try_from(index)?.saturating_mul(manifest.chunk_size);
        let end = start.saturating_add(manifest.chunk_size).min(ciphertext.len());
        chunks.push(ramflux_sync::chunk_payload(
            content_key,
            manifest,
            index,
            &ciphertext[start..end],
        ));
    }
    Ok(chunks)
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn deliver_mvp3_object_chunk(
    gateway_url: &str,
    receiver: &mut ramflux_sync::ObjectSyncSession,
    chunk: &ramflux_sync::ChunkPayload,
    plaintext: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let envelope_id = format!("env_mvp3_object_chunk_{:03}", chunk.chunk_index);
    let chunk_payload = ramflux_protocol::encode_base64url(&chunk.ciphertext);
    let mut envelope = itest_envelope(&envelope_id, "bob_target_mvp1_realnet");
    envelope.encrypted_payload = chunk_payload;
    envelope.payload_hash = ramflux_crypto::blake3_256_base64url(
        "ramflux.test.object_chunk.v1",
        envelope.encrypted_payload.as_bytes(),
    );
    let submit: ramflux_node_core::EnvelopeSubmitResponse =
        ramflux_node_core::itest_http_post_json(
            &format!("{gateway_url}/mvp0/envelope"),
            &envelope,
        )?;
    assert_eq!(submit.outcome, "online");
    let inbox: ramflux_node_core::InboxFetchResponse = ramflux_node_core::itest_http_get_json(
        &format!("{gateway_url}/mvp1/inbox/bob_target_mvp1_realnet"),
    )?;
    let delivered = inbox
        .entries
        .into_iter()
        .find(|entry| entry.envelope.envelope_id == envelope_id)
        .ok_or_else(|| format!("missing delivered object chunk {envelope_id}"))?;
    assert_eq!(delivered.envelope.encrypted_payload, envelope.encrypted_payload);
    assert_node_opaque_payload(&delivered.envelope.encrypted_payload, plaintext);
    let device_branch = ramflux_crypto::create_device_branch(
        "principal_mvp3_object_sync",
        "mvp3_object_sync_receiver",
        1,
        [0x8C; 32],
    );
    receiver.receive_chunk(
        ramflux_sync::ChunkPayload {
            chunk_index: chunk.chunk_index,
            nonce: chunk.nonce.clone(),
            ciphertext: ramflux_protocol::decode_base64url(&delivered.envelope.encrypted_payload)?,
            cipher_hash: chunk.cipher_hash.clone(),
        },
        &device_branch,
    )?;
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn deliver_mvp3_object_tombstone(
    gateway_url: &str,
    alice_session: &mut ramflux_crypto::DmSession,
    bob_session: &mut ramflux_crypto::DmSession,
    object_id: &str,
    manifest_hash: &str,
    plaintext: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let event = Mvp3ObjectTombstoneEvent {
        event_type: "object.tombstone".to_owned(),
        object_id: object_id.to_owned(),
        manifest_hash: manifest_hash.to_owned(),
    };
    let decrypted: Mvp3ObjectTombstoneEvent = deliver_mvp3_object_event(
        gateway_url,
        "env_mvp3_object_tombstone",
        alice_session,
        bob_session,
        &event,
        plaintext,
    )?;
    assert_eq!(decrypted.event_type, "object.tombstone");
    assert_eq!(decrypted.object_id, object_id);
    assert_eq!(decrypted.manifest_hash, manifest_hash);
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn deliver_mvp3_object_event<T>(
    gateway_url: &str,
    envelope_id: &str,
    alice_session: &mut ramflux_crypto::DmSession,
    bob_session: &mut ramflux_crypto::DmSession,
    event: &T,
    forbidden_plaintext: &[u8],
) -> Result<T, Box<dyn std::error::Error>>
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    let event_json = serde_json::to_vec(event)?;
    assert!(
        !contains_subslice(&event_json, forbidden_plaintext),
        "object sync event leaked source plaintext before encryption"
    );
    let ciphertext = alice_session.encrypt(&event_json, b"alice_device|bob_device")?;
    let delivered =
        deliver_mvp1_dm(gateway_url, envelope_id, "bob_target_mvp1_realnet", &ciphertext)?;
    assert_node_opaque_payload(&delivered.envelope.encrypted_payload, forbidden_plaintext);
    let delivered_ciphertext: ramflux_crypto::DmCiphertext =
        serde_json::from_str(&delivered.envelope.encrypted_payload)?;
    let decrypted = bob_session.decrypt(&delivered_ciphertext, b"alice_device|bob_device")?;
    Ok(serde_json::from_slice(&decrypted)?)
}
