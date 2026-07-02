// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use crate::*;

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp1_realnet_fixture() -> Result<Mvp1RealnetFixture, Box<dyn std::error::Error>> {
    let root = ramflux_crypto::create_identity_root("principal_realnet", [0x31; 32]);
    let device =
        ramflux_crypto::create_device_branch("principal_realnet", "device_realnet", 1, [0x32; 32]);
    let root_public_key =
        ramflux_protocol::encode_base64url(root.signing_key.verifying_key().to_bytes());
    let register = mvp1_register_request(&root, &device, root_public_key.clone(), 1)?;
    let revoked_device =
        ramflux_crypto::create_device_branch("principal_realnet", "device_realnet", 2, [0x35; 32]);
    let revoked_register = mvp1_register_request(&root, &revoked_device, root_public_key, 2)?;
    let identity_key = ramflux_crypto::X25519KeyPair::from_seed([0x33; 32]);
    let signed_prekey = ramflux_crypto::X25519KeyPair::from_seed([0x34; 32]);
    let prekey_bundle = ramflux_crypto::create_prekey_bundle(
        &device,
        &identity_key,
        "spk_mvp1_realnet",
        &signed_prekey,
        None,
        None,
    )?;
    Ok(Mvp1RealnetFixture { register, revoked_register, prekey_bundle })
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp1_register_request(
    root: &ramflux_crypto::IdentityRoot,
    device: &ramflux_crypto::DeviceBranch,
    root_public_key: String,
    session_suffix: u64,
) -> Result<ramflux_node_core::IdentityRegisterRequest, Box<dyn std::error::Error>> {
    let proof = ramflux_crypto::authorize_device_branch(
        root,
        device,
        ramflux_node_core::IDENTITY_BIND_AUDIENCE,
        vec![ramflux_node_core::IDENTITY_BIND_CAPABILITY.to_owned()],
        1_760_000_000 + i64::try_from(session_suffix)?,
        1_760_003_600 + i64::try_from(session_suffix)?,
    )?;
    let root_public_key_bytes = ramflux_protocol::decode_base64url(&root_public_key)?;
    Ok(ramflux_node_core::IdentityRegisterRequest {
        principal_commitment: ramflux_crypto::blake3_256_base64url(
            "ramflux.identity.root_public_key.commitment.v1",
            &root_public_key_bytes,
        ),
        root_public_key,
        branch_public_key: ramflux_protocol::encode_base64url(
            device.signing_key.verifying_key().to_bytes(),
        ),
        proof,
        target_delivery_id: format!("target_mvp1_realnet_{session_suffix}"),
        gateway_id: "ramflux-gateway".to_owned(),
        session_id: format!("session_mvp1_realnet_{session_suffix}"),
        push_alias_hash: Some("push_alias_mvp1".to_owned()),
        now: 1_760_000_010 + i64::try_from(session_suffix)?,
        registration_pow: None,
        source_ip_hash: None,
    })
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp1_revoke_request(
    principal_id: &str,
    root_seed: [u8; 32],
    device_id: &str,
    revoked_at: i64,
) -> Result<ramflux_node_core::DeviceRevokeRequest, Box<dyn std::error::Error>> {
    #[derive(serde::Serialize)]
    struct RevokeSigningBody<'a> {
        device_id: &'a str,
        principal_commitment: &'a str,
        revoked_at: i64,
    }

    let root = ramflux_crypto::create_identity_root(principal_id, root_seed);
    let root_public_key =
        ramflux_protocol::encode_base64url(root.signing_key.verifying_key().to_bytes());
    let principal_commitment = ramflux_sdk::identity_root_public_key_commitment(&root_public_key)?;
    let signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &ramflux_protocol::canonical_json_bytes(&RevokeSigningBody {
            device_id,
            principal_commitment: &principal_commitment,
            revoked_at,
        })?,
        root_seed,
    );
    Ok(ramflux_node_core::DeviceRevokeRequest {
        device_id: device_id.to_owned(),
        principal_commitment,
        root_public_key,
        revoked_at,
        signature,
    })
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp1_dm_realnet_fixture() -> Result<Mvp1DmRealnetFixture, Box<dyn std::error::Error>>
{
    let alice_root = ramflux_crypto::create_identity_root("alice_realnet", [0x41; 32]);
    let alice_device = ramflux_crypto::create_device_branch(
        "alice_realnet",
        "alice_device_realnet",
        1,
        [0x42; 32],
    );
    let bob_root = ramflux_crypto::create_identity_root("bob_realnet", [0x43; 32]);
    let bob_device =
        ramflux_crypto::create_device_branch("bob_realnet", "bob_device_realnet", 1, [0x44; 32]);
    let alice_register = mvp1_named_register_request(
        &alice_root,
        &alice_device,
        "alice_target_mvp1_realnet",
        "alice_session_mvp1_realnet",
        11,
    )?;
    let bob_register = mvp1_named_register_request(
        &bob_root,
        &bob_device,
        "bob_target_mvp1_realnet",
        "bob_session_mvp1_realnet",
        12,
    )?;
    let bob_identity = ramflux_crypto::X25519KeyPair::from_seed([0x45; 32]);
    let bob_signed_prekey = ramflux_crypto::X25519KeyPair::from_seed([0x46; 32]);
    let bob_prekey_bundle = ramflux_crypto::create_prekey_bundle(
        &bob_device,
        &bob_identity,
        "spk_bob_mvp1_realnet",
        &bob_signed_prekey,
        None,
        None,
    )?;
    Ok(Mvp1DmRealnetFixture {
        alice_register,
        bob_register,
        alice_identity: ramflux_crypto::X25519KeyPair::from_seed([0x47; 32]),
        alice_ephemeral: ramflux_crypto::X25519KeyPair::from_seed([0x48; 32]),
        bob_identity,
        bob_signed_prekey,
        bob_prekey_bundle,
    })
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp1_named_register_request(
    root: &ramflux_crypto::IdentityRoot,
    device: &ramflux_crypto::DeviceBranch,
    target_delivery_id: &str,
    session_id: &str,
    nonce: i64,
) -> Result<ramflux_node_core::IdentityRegisterRequest, Box<dyn std::error::Error>> {
    let proof = ramflux_crypto::authorize_device_branch(
        root,
        device,
        ramflux_node_core::IDENTITY_BIND_AUDIENCE,
        vec![ramflux_node_core::IDENTITY_BIND_CAPABILITY.to_owned()],
        1_760_000_000 + nonce,
        1_760_003_600 + nonce,
    )?;
    let root_public_key =
        ramflux_protocol::encode_base64url(root.signing_key.verifying_key().to_bytes());
    let root_public_key_bytes = ramflux_protocol::decode_base64url(&root_public_key)?;
    Ok(ramflux_node_core::IdentityRegisterRequest {
        principal_commitment: ramflux_crypto::blake3_256_base64url(
            "ramflux.identity.root_public_key.commitment.v1",
            &root_public_key_bytes,
        ),
        root_public_key,
        branch_public_key: ramflux_protocol::encode_base64url(
            device.signing_key.verifying_key().to_bytes(),
        ),
        proof,
        target_delivery_id: target_delivery_id.to_owned(),
        gateway_id: "ramflux-gateway".to_owned(),
        session_id: session_id.to_owned(),
        push_alias_hash: Some(format!("push_alias_{session_id}")),
        now: 1_760_000_010 + nonce,
        registration_pow: None,
        source_ip_hash: None,
    })
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn register_mvp1_identity(
    gateway_url: &str,
    request: &ramflux_node_core::IdentityRegisterRequest,
) -> Result<ramflux_node_core::IdentityRegistrationResponse, Box<dyn std::error::Error>> {
    Ok(ramflux_node_core::itest_http_post_json(
        &format!("{gateway_url}/mvp1/identity/register"),
        request,
    )?)
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn publish_mvp1_prekey(
    gateway_url: &str,
    device_id: &str,
    bundle: &ramflux_crypto::PrekeyBundle,
) -> Result<ramflux_node_core::PrekeyResponse, Box<dyn std::error::Error>> {
    Ok(ramflux_node_core::itest_http_post_json(
        &format!("{gateway_url}/mvp1/prekey/publish"),
        &ramflux_node_core::PrekeyPublishRequest {
            device_id: device_id.to_owned(),
            bundle: bundle.clone(),
        },
    )?)
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn encrypt_mvp1_dm(
    fixture: &Mvp1DmRealnetFixture,
    bob_bundle: &ramflux_crypto::PrekeyBundle,
    plaintext: &[u8],
) -> Result<(ramflux_crypto::DmCiphertext, ramflux_crypto::DmSession), Box<dyn std::error::Error>> {
    let bundle_bytes = serde_json::to_vec(bob_bundle)?;
    let prekey_bundle_hash =
        ramflux_crypto::blake3_256(ramflux_protocol::domain::X3DH_PREKEY_BUNDLE, &bundle_bytes);
    let associated_data = b"alice_device|bob_device";
    let alice_hash = [0xa1; 32];
    let bob_hash = [0xb1; 32];
    let initiator = ramflux_crypto::x3dh_initiator(&ramflux_crypto::X3dhInitiatorInput {
        initiator_identity: &fixture.alice_identity,
        initiator_ephemeral: &fixture.alice_ephemeral,
        initiator_device_id_hash: alice_hash,
        recipient_device_id_hash: bob_hash,
        recipient_bundle: bob_bundle,
        associated_data,
        prekey_bundle_hash: &prekey_bundle_hash,
        initial_ratchet_public: fixture.alice_ephemeral.public,
    })?;
    let recipient = ramflux_crypto::x3dh_recipient(&ramflux_crypto::X3dhRecipientInput {
        recipient_identity: &fixture.bob_identity,
        recipient_signed_prekey: &fixture.bob_signed_prekey,
        recipient_one_time_prekey: None,
        initiator_identity_public: fixture.alice_identity.public,
        initiator_ephemeral_public: fixture.alice_ephemeral.public,
        initiator_device_id_hash: alice_hash,
        recipient_device_id_hash: bob_hash,
        recipient_signed_prekey_id: &bob_bundle.signed_prekey_id,
        recipient_one_time_prekey_id: bob_bundle.one_time_prekey_id.as_deref(),
        associated_data,
        prekey_bundle_hash: &prekey_bundle_hash,
        initial_ratchet_public: fixture.alice_ephemeral.public,
    })?;
    let mut alice_session = ramflux_crypto::DmSession::initiator(
        initiator.root_seed,
        alice_hash,
        bob_hash,
        initiator.bootstrap_transcript_hash,
    )?;
    let bob_session = ramflux_crypto::DmSession::recipient(
        recipient.root_seed,
        bob_hash,
        alice_hash,
        recipient.bootstrap_transcript_hash,
    )?;
    Ok((alice_session.encrypt(plaintext, associated_data)?, bob_session))
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn establish_mvp1_dm_sessions(
    fixture: &Mvp1DmRealnetFixture,
    bob_bundle: &ramflux_crypto::PrekeyBundle,
) -> Result<(ramflux_crypto::DmSession, ramflux_crypto::DmSession), Box<dyn std::error::Error>> {
    let bundle_bytes = serde_json::to_vec(bob_bundle)?;
    let prekey_bundle_hash =
        ramflux_crypto::blake3_256(ramflux_protocol::domain::X3DH_PREKEY_BUNDLE, &bundle_bytes);
    let associated_data = b"alice_device|bob_device";
    let alice_hash = [0xa1; 32];
    let bob_hash = [0xb1; 32];
    let initiator = ramflux_crypto::x3dh_initiator(&ramflux_crypto::X3dhInitiatorInput {
        initiator_identity: &fixture.alice_identity,
        initiator_ephemeral: &fixture.alice_ephemeral,
        initiator_device_id_hash: alice_hash,
        recipient_device_id_hash: bob_hash,
        recipient_bundle: bob_bundle,
        associated_data,
        prekey_bundle_hash: &prekey_bundle_hash,
        initial_ratchet_public: fixture.alice_ephemeral.public,
    })?;
    let recipient = ramflux_crypto::x3dh_recipient(&ramflux_crypto::X3dhRecipientInput {
        recipient_identity: &fixture.bob_identity,
        recipient_signed_prekey: &fixture.bob_signed_prekey,
        recipient_one_time_prekey: None,
        initiator_identity_public: fixture.alice_identity.public,
        initiator_ephemeral_public: fixture.alice_ephemeral.public,
        initiator_device_id_hash: alice_hash,
        recipient_device_id_hash: bob_hash,
        recipient_signed_prekey_id: &bob_bundle.signed_prekey_id,
        recipient_one_time_prekey_id: bob_bundle.one_time_prekey_id.as_deref(),
        associated_data,
        prekey_bundle_hash: &prekey_bundle_hash,
        initial_ratchet_public: fixture.alice_ephemeral.public,
    })?;
    Ok((
        ramflux_crypto::DmSession::initiator(
            initiator.root_seed,
            alice_hash,
            bob_hash,
            initiator.bootstrap_transcript_hash,
        )?,
        ramflux_crypto::DmSession::recipient(
            recipient.root_seed,
            bob_hash,
            alice_hash,
            recipient.bootstrap_transcript_hash,
        )?,
    ))
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn deliver_mvp1_dm(
    gateway_url: &str,
    envelope_id: &str,
    target_delivery_id: &str,
    ciphertext: &ramflux_crypto::DmCiphertext,
) -> Result<ramflux_node_core::InboxEntry, Box<dyn std::error::Error>> {
    let encrypted_payload = serde_json::to_string(ciphertext)?;
    let mut envelope = itest_envelope(envelope_id, target_delivery_id);
    envelope.encrypted_payload = encrypted_payload;
    envelope.payload_hash = ramflux_crypto::blake3_256_base64url(
        "ramflux.test.dm_payload.v1",
        envelope.encrypted_payload.as_bytes(),
    );
    let submit: ramflux_node_core::EnvelopeSubmitResponse =
        ramflux_node_core::itest_http_post_json(
            &format!("{gateway_url}/mvp0/envelope"),
            &envelope,
        )?;
    assert_eq!(submit.outcome, "online");
    let inbox: ramflux_node_core::InboxFetchResponse = ramflux_node_core::itest_http_get_json(
        &format!("{gateway_url}/mvp1/inbox/{target_delivery_id}"),
    )?;
    inbox
        .entries
        .into_iter()
        .find(|entry| entry.envelope.envelope_id == envelope_id)
        .ok_or_else(|| format!("missing delivered envelope {envelope_id}").into())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp1_inbox_entry(
    gateway_url: &str,
    target_delivery_id: &str,
    envelope_id: &str,
) -> Result<ramflux_node_core::InboxEntry, Box<dyn std::error::Error>> {
    let inbox: ramflux_node_core::InboxFetchResponse = ramflux_node_core::itest_http_get_json(
        &format!("{gateway_url}/mvp1/inbox/{target_delivery_id}"),
    )?;
    inbox
        .entries
        .into_iter()
        .find(|entry| entry.envelope.envelope_id == envelope_id)
        .ok_or_else(|| format!("missing delivered envelope {envelope_id}").into())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp10_assert_group_roles_and_member_removed(
    clients: &Mvp9LocalClients,
) -> Result<(), Box<dyn std::error::Error>> {
    clients.alice_db.create_group("group_mvp10_realnet", "alice")?;
    clients.bob_db.create_group("group_mvp10_realnet", "alice")?;
    for db in [&clients.alice_db, &clients.bob_db] {
        db.add_group_member("group_mvp10_realnet", "bob", "admin")?;
        db.add_group_member("group_mvp10_realnet", "carol", "member")?;
        assert!(matches!(
            db.remove_group_member("group_mvp10_realnet", "bob", "alice"),
            Err(ramflux_storage::StorageError::GroupPermissionDenied)
        ));
        assert!(matches!(
            db.remove_group_member("group_mvp10_realnet", "carol", "bob"),
            Err(ramflux_storage::StorageError::GroupPermissionDenied)
        ));
        assert!(matches!(
            db.ensure_group_member_can_send("group_mvp10_realnet", "carol", true),
            Err(ramflux_storage::StorageError::GroupPermissionDenied)
        ));
        db.ensure_group_member_can_send("group_mvp10_realnet", "bob", true)?;
        assert!(matches!(
            db.ensure_group_member_can_mute("group_mvp10_realnet", "carol", "bob"),
            Err(ramflux_storage::StorageError::GroupPermissionDenied)
        ));
        db.ensure_group_member_can_mute("group_mvp10_realnet", "alice", "bob")?;
    }

    let alice_group =
        clients.alice_db.remove_group_member("group_mvp10_realnet", "alice", "carol")?;
    let bob_group = clients.bob_db.remove_group_member("group_mvp10_realnet", "alice", "carol")?;
    assert!(!alice_group.members.contains("carol"));
    assert!(!bob_group.members.contains("carol"));
    assert_eq!(alice_group.members, bob_group.members);
    assert_eq!(alice_group.roles.get("bob").map(String::as_str), Some("admin"));
    assert_eq!(bob_group.roles.get("alice").map(String::as_str), Some("owner"));
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp10_assert_group_member_limit() -> Result<(), Box<dyn std::error::Error>> {
    let root = temp_root("mvp10_realnet_group_member_limit")?;
    let index = ramflux_storage::AccountIndex::open(&root)?;
    index.create_account("group_limit_mvp10_local", "group_limit_mvp10")?;
    let key =
        ramflux_storage::AccountDbKey::derive("group_limit_mvp10_local", b"group-limit-mvp10");
    let db = ramflux_storage::AccountDb::open(&index, "group_limit_mvp10_local", &key)?;
    db.create_group("group_mvp10_limit", "owner")?;
    for index in 1..1000 {
        db.add_group_member("group_mvp10_limit", &format!("member_{index:04}"), "member")?;
    }
    let full = db.group_state("group_mvp10_limit")?;
    assert_eq!(full.members.len(), 1000);
    assert!(matches!(
        db.add_group_member("group_mvp10_limit", "member_1000", "member"),
        Err(ramflux_storage::StorageError::GroupMemberLimitExceeded)
    ));
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp10_assert_group_delete_tombstone_realnet(
    gateway_url: &str,
    clients: &Mvp9LocalClients,
    alice_session: &mut ramflux_crypto::DmSession,
    bob_session: &mut ramflux_crypto::DmSession,
) -> Result<(), Box<dyn std::error::Error>> {
    let group_plaintext = br#"{"type":"message.created","group_id":"group_mvp10_realnet","conversation_id":"group_conv_mvp10_realnet","msg_event_id":"msg_mvp10_group_001","body":"mvp10 group governance secret"}"#;
    clients.alice_db.ensure_group_member_can_send("group_mvp10_realnet", "alice", true)?;
    let group_ciphertext = alice_session.encrypt(group_plaintext, b"alice_device|bob_device")?;
    let delivered_group = deliver_mvp9_dm(
        gateway_url,
        "env_mvp10_group_message",
        "bob_target_mvp1_realnet",
        &group_ciphertext,
    )?;
    let decrypted_group = decrypt_mvp9_dm(
        &delivered_group,
        bob_session,
        b"alice_device|bob_device",
        group_plaintext,
    )?;
    assert_eq!(decrypted_group, group_plaintext);
    clients.bob_db.send_direct_message(
        "group_conv_mvp10_realnet",
        "msg_mvp10_group_001",
        "alice",
        &decrypted_group,
    )?;

    let delete_plaintext = br#"{"type":"message.deleted","group_id":"group_mvp10_realnet","conversation_id":"group_conv_mvp10_realnet","msg_event_id":"msg_mvp10_group_001","tombstone_id":"tombstone_mvp10_group_001","delete_scope":"conversation_members"}"#;
    let delete_ciphertext = alice_session.encrypt(delete_plaintext, b"alice_device|bob_device")?;
    let delivered_delete = deliver_mvp9_dm(
        gateway_url,
        "env_mvp10_group_delete_tombstone",
        "bob_target_mvp1_realnet",
        &delete_ciphertext,
    )?;
    let decrypted_delete = decrypt_mvp9_dm(
        &delivered_delete,
        bob_session,
        b"alice_device|bob_device",
        delete_plaintext,
    )?;
    assert_eq!(decrypted_delete, delete_plaintext);
    let tombstone = clients.bob_db.delete_direct_message(
        "group_conv_mvp10_realnet",
        "msg_mvp10_group_001",
        "conversation_members",
        "tombstone_mvp10_group_001",
    )?;
    assert_eq!(tombstone.message_id, "msg_mvp10_group_001");
    let messages = clients.bob_db.direct_messages("group_conv_mvp10_realnet")?;
    let deleted = messages
        .iter()
        .find(|message| message.message_id == "msg_mvp10_group_001")
        .ok_or_else(|| "group message missing after tombstone".to_owned())?;
    assert!(deleted.deleted);
    assert!(deleted.encrypted_body.is_empty());
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp10_assert_call_and_conference_wake_delivery(
    notify_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let call = mvp10_queue_notify_wake(
        notify_url,
        &mvp10_notification_wake(
            "wake_mvp10_call",
            ramflux_protocol::NotificationDeliveryClass::CallWakeNotification,
            "collapse_call_mvp10",
            "opaque_call_wake_hint_mvp10",
        ),
    )?;
    assert_eq!(
        call.wake.delivery_class,
        ramflux_protocol::NotificationDeliveryClass::CallWakeNotification
    );
    assert_eq!(call.status, ramflux_node_core::NotifyQueueStatus::Pending);
    assert!(!call.wake.encrypted_hint.as_deref().unwrap_or_default().contains("SRTP_MEDIA_KEY"));
    let delivered_call = mvp10_deliver_notify_wake(notify_url, "wake_mvp10_call")?;
    assert_eq!(delivered_call.status, ramflux_node_core::NotifyQueueStatus::Delivered);
    assert_eq!(delivered_call.attempt_count, 1);

    let conference = mvp10_queue_notify_wake(
        notify_url,
        &mvp10_notification_wake(
            "wake_mvp10_conference",
            ramflux_protocol::NotificationDeliveryClass::ConferenceWakeNotification,
            "collapse_conference_mvp10",
            "opaque_conference_wake_hint_mvp10",
        ),
    )?;
    assert_eq!(
        conference.wake.delivery_class,
        ramflux_protocol::NotificationDeliveryClass::ConferenceWakeNotification
    );
    let delivered_conference = mvp10_deliver_notify_wake(notify_url, "wake_mvp10_conference")?;
    assert_eq!(delivered_conference.status, ramflux_node_core::NotifyQueueStatus::Delivered);
    assert_eq!(
        delivered_conference.wake.delivery_class,
        ramflux_protocol::NotificationDeliveryClass::ConferenceWakeNotification
    );
    Ok(())
}
