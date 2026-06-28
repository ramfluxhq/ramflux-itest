// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use super::*;

#[test]
fn dm_double_ratchet_pcs_and_skipped_keys() -> Result<(), Box<dyn std::error::Error>> {
    assert_dm_double_ratchet_pcs_and_skipped_keys()
}

#[test]
fn device_revocation_replay_guard() -> Result<(), Box<dyn std::error::Error>> {
    let root = ramflux_crypto::create_identity_root("principal_a", [0x71; 32]);
    let device = ramflux_crypto::create_device_branch("principal_a", "device_a", 1, [0x72; 32]);
    let proof = ramflux_crypto::authorize_device_branch(
        &root,
        &device,
        "ramflux-node",
        vec!["device.delivery.bind".to_owned()],
        1_760_000_000,
        1_760_003_600,
    )?;

    let mut replay_guard = ramflux_crypto::DeviceRevocationReplayGuard::new();
    replay_guard.accept_branch_proof(
        &root.signing_key.verifying_key(),
        &proof,
        "ramflux-node",
        "device.delivery.bind",
        1_760_000_001,
    )?;
    assert!(
        replay_guard
            .accept_branch_proof(
                &root.signing_key.verifying_key(),
                &proof,
                "ramflux-node",
                "device.delivery.bind",
                1_760_000_001,
            )
            .is_err()
    );

    let second = ramflux_crypto::create_device_branch("principal_a", "device_b", 1, [0x73; 32]);
    let second_proof = ramflux_crypto::authorize_device_branch(
        &root,
        &second,
        "ramflux-node",
        vec!["device.delivery.bind".to_owned()],
        1_760_000_010,
        1_760_003_610,
    )?;
    replay_guard.revoke_device("device_b");
    assert!(
        replay_guard
            .accept_branch_proof(
                &root.signing_key.verifying_key(),
                &second_proof,
                "ramflux-node",
                "device.delivery.bind",
                1_760_000_011,
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn e2ee_dm_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let bob_branch = ramflux_crypto::create_device_branch("bob", "bob_device", 1, [0x41; 32]);
    let alice_identity = ramflux_crypto::X25519KeyPair::from_seed([0x51; 32]);
    let alice_ephemeral = ramflux_crypto::X25519KeyPair::from_seed([0x52; 32]);
    let bob_identity = ramflux_crypto::X25519KeyPair::from_seed([0x61; 32]);
    let bob_signed_prekey = ramflux_crypto::X25519KeyPair::from_seed([0x62; 32]);
    let bob_one_time = ramflux_crypto::X25519KeyPair::from_seed([0x63; 32]);
    let bundle = ramflux_crypto::create_prekey_bundle(
        &bob_branch,
        &bob_identity,
        "spk_01",
        &bob_signed_prekey,
        Some("opk_01".to_owned()),
        Some(bob_one_time.public),
    )?;
    ramflux_crypto::verify_prekey_bundle(&bob_branch.signing_key.verifying_key(), &bundle)?;

    let prekey_bundle_hash =
        ramflux_crypto::blake3_256(ramflux_protocol::domain::X3DH_PREKEY_BUNDLE, b"bundle-fixture");
    let associated_data = b"alice_device|bob_device";
    let alice_hash = [0xa1; 32];
    let bob_hash = [0xb2; 32];
    let initiator_output = ramflux_crypto::x3dh_initiator(&ramflux_crypto::X3dhInitiatorInput {
        initiator_identity: &alice_identity,
        initiator_ephemeral: &alice_ephemeral,
        initiator_device_id_hash: alice_hash,
        recipient_device_id_hash: bob_hash,
        recipient_bundle: &bundle,
        associated_data,
        prekey_bundle_hash: &prekey_bundle_hash,
        initial_ratchet_public: alice_ephemeral.public,
    })?;
    let recipient_output = ramflux_crypto::x3dh_recipient(&ramflux_crypto::X3dhRecipientInput {
        recipient_identity: &bob_identity,
        recipient_signed_prekey: &bob_signed_prekey,
        recipient_one_time_prekey: Some(&bob_one_time),
        initiator_identity_public: alice_identity.public,
        initiator_ephemeral_public: alice_ephemeral.public,
        initiator_device_id_hash: alice_hash,
        recipient_device_id_hash: bob_hash,
        recipient_signed_prekey_id: &bundle.signed_prekey_id,
        recipient_one_time_prekey_id: bundle.one_time_prekey_id.as_deref(),
        associated_data,
        prekey_bundle_hash: &prekey_bundle_hash,
        initial_ratchet_public: alice_ephemeral.public,
    })?;
    assert_eq!(initiator_output.root_seed, recipient_output.root_seed);

    let mut alice_session = ramflux_crypto::DmSession::initiator(
        initiator_output.root_seed,
        alice_hash,
        bob_hash,
        initiator_output.bootstrap_transcript_hash,
    )?;
    let mut bob_session = ramflux_crypto::DmSession::recipient(
        recipient_output.root_seed,
        bob_hash,
        alice_hash,
        recipient_output.bootstrap_transcript_hash,
    )?;
    let ciphertext = alice_session.encrypt(b"hello mvp-1", b"message-header")?;
    let plaintext = bob_session.decrypt(&ciphertext, b"message-header")?;
    assert_eq!(plaintext, b"hello mvp-1");
    Ok(())
}

#[test]
fn friend_link_establish() -> Result<(), Box<dyn std::error::Error>> {
    let db = test_account_db("friend_link_establish")?;
    let link = db.establish_friend_link("link_1", "alice", "bob")?;
    assert_eq!(link.state, "accepted");
    assert_eq!(db.friend_link("link_1")?.target_id, "bob");
    Ok(())
}

#[test]
fn disappearing_message_expiry_tombstone_projection() -> Result<(), Box<dyn std::error::Error>> {
    let db = test_account_db("disappearing_message_expiry_tombstone_projection")?;
    let metadata = ramflux_storage::MessageMetadata::default();
    db.set_disappearing_policy("conv_1", 60, "on_send", "own_devices", 1_760_000_000)?;
    db.send_direct_message_at_with_metadata(ramflux_storage::DirectMessageWrite {
        conversation_id: "conv_1",
        message_id: "msg_expiring",
        sender_id: "alice",
        encrypted_body: b"old",
        metadata: &metadata,
        created_at: 1_760_000_000,
    })?;
    db.send_direct_message_at_with_metadata(ramflux_storage::DirectMessageWrite {
        conversation_id: "conv_1",
        message_id: "msg_live",
        sender_id: "alice",
        encrypted_body: b"new",
        metadata: &metadata,
        created_at: 1_760_000_100,
    })?;

    let tombstones = db.expire_disappearing_messages("conv_1", 1_760_000_061)?;
    assert_eq!(tombstones.len(), 1);
    assert_eq!(tombstones[0].message_id, "msg_expiring");
    assert_eq!(tombstones[0].delete_scope, "own_devices");

    let projection = db.conversation_projection("conv_1", "alice")?;
    assert_eq!(projection.message_count, 1);
    assert_eq!(projection.last_message_id, Some("msg_live".to_owned()));
    let messages = db.direct_messages("conv_1")?;
    let expired = messages
        .iter()
        .find(|message| message.message_id == "msg_expiring")
        .ok_or_else(|| "expired message missing from audit projection".to_owned())?;
    assert!(expired.deleted);
    assert!(expired.encrypted_body.is_empty());
    Ok(())
}
