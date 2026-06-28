// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use crate::*;

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn register_mvp2_bot_identity(
    gateway_url: &str,
) -> Result<Mvp2BotRealnetFixture, Box<dyn std::error::Error>> {
    let root = ramflux_crypto::create_identity_root("bot_realnet", [0x61; 32]);
    let device =
        ramflux_crypto::create_device_branch("bot_realnet", "bot_device_realnet", 1, [0x62; 32]);
    let register = mvp1_named_register_request(
        &root,
        &device,
        "bot_target_mvp2_realnet",
        "bot_session_mvp2_realnet",
        21,
    )?;
    register_mvp1_identity(gateway_url, &register)?;
    let identity = ramflux_crypto::X25519KeyPair::from_seed([0x63; 32]);
    let signed_prekey = ramflux_crypto::X25519KeyPair::from_seed([0x64; 32]);
    let prekey_bundle = ramflux_crypto::create_prekey_bundle(
        &device,
        &identity,
        "spk_bot_mvp2_realnet",
        &signed_prekey,
        None,
        None,
    )?;
    publish_mvp1_prekey(gateway_url, "bot_device_realnet", &prekey_bundle)?;
    Ok(Mvp2BotRealnetFixture {
        target_delivery_id: "bot_target_mvp2_realnet".to_owned(),
        identity,
        signed_prekey,
        prekey_bundle,
    })
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn setup_mvp2_local_clients() -> Result<Mvp2LocalClients, Box<dyn std::error::Error>> {
    let root = temp_root("mvp2_realnet_friend_message_projection")?;
    let index = ramflux_storage::AccountIndex::open(&root)?;
    index.create_account("alice_mvp2_local", "alice_realnet")?;
    index.create_account("bob_mvp2_local", "bob_realnet")?;
    let alice_key = ramflux_storage::AccountDbKey::derive("alice_mvp2_local", b"alice-mvp2-secret");
    let bob_key = ramflux_storage::AccountDbKey::derive("bob_mvp2_local", b"bob-mvp2-secret");
    let alice_db = ramflux_storage::AccountDb::open(&index, "alice_mvp2_local", &alice_key)?;
    let bob_db = ramflux_storage::AccountDb::open(&index, "bob_mvp2_local", &bob_key)?;
    assert_eq!(alice_db.encryption_mode(), ramflux_storage::EncryptionMode::SqlCipher);
    assert_eq!(bob_db.encryption_mode(), ramflux_storage::EncryptionMode::SqlCipher);
    Ok(Mvp2LocalClients { alice_db, bob_db })
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn exchange_mvp2_friend_link(
    gateway_url: &str,
    clients: &Mvp2LocalClients,
    alice_session: &mut ramflux_crypto::DmSession,
    bob_session: &mut ramflux_crypto::DmSession,
) -> Result<(), Box<dyn std::error::Error>> {
    let request_plaintext =
        br#"{"type":"friend_link.request","link_id":"friend_link_mvp2_realnet","from":"alice","to":"bob"}"#;
    let request = alice_session.encrypt(request_plaintext, b"alice_device|bob_device")?;
    let delivered_request = deliver_mvp1_dm(
        gateway_url,
        "env_mvp2_friend_request",
        "bob_target_mvp1_realnet",
        &request,
    )?;
    assert_node_opaque_payload(&delivered_request.envelope.encrypted_payload, request_plaintext);
    let request_ciphertext: ramflux_crypto::DmCiphertext =
        serde_json::from_str(&delivered_request.envelope.encrypted_payload)?;
    let decrypted_request = bob_session.decrypt(&request_ciphertext, b"alice_device|bob_device")?;
    assert_eq!(decrypted_request, request_plaintext);
    let bob_link =
        clients.bob_db.establish_friend_link("friend_link_mvp2_realnet", "alice", "bob")?;
    assert_eq!(bob_link.state, "accepted");

    let accept_plaintext =
        br#"{"type":"friend_link.accept","link_id":"friend_link_mvp2_realnet","from":"bob","to":"alice"}"#;
    let accept = bob_session.encrypt(accept_plaintext, b"alice_device|bob_device")?;
    let delivered_accept = deliver_mvp1_dm(
        gateway_url,
        "env_mvp2_friend_accept",
        "alice_target_mvp1_realnet",
        &accept,
    )?;
    assert_node_opaque_payload(&delivered_accept.envelope.encrypted_payload, accept_plaintext);
    let accept_ciphertext: ramflux_crypto::DmCiphertext =
        serde_json::from_str(&delivered_accept.envelope.encrypted_payload)?;
    let decrypted_accept = alice_session.decrypt(&accept_ciphertext, b"alice_device|bob_device")?;
    assert_eq!(decrypted_accept, accept_plaintext);
    let alice_link =
        clients.alice_db.establish_friend_link("friend_link_mvp2_realnet", "alice", "bob")?;
    assert_eq!(alice_link.state, "accepted");
    assert_eq!(clients.bob_db.friend_link("friend_link_mvp2_realnet")?.target_id, "bob");
    assert_eq!(clients.alice_db.friend_link("friend_link_mvp2_realnet")?.requester_id, "alice");
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn deliver_mvp2_friend_messages(
    gateway_url: &str,
    bob_db: &ramflux_storage::AccountDb,
    alice_session: &mut ramflux_crypto::DmSession,
    bob_session: &mut ramflux_crypto::DmSession,
    plaintexts: &[&[u8]],
) -> Result<(), Box<dyn std::error::Error>> {
    for (index, plaintext) in plaintexts.iter().enumerate() {
        let message_number = index + 1;
        let envelope_id = format!("env_mvp2_dm_{message_number:03}");
        let message_id = format!("msg_mvp2_{message_number:03}");
        let ciphertext = alice_session.encrypt(plaintext, b"alice_device|bob_device")?;
        let delivered =
            deliver_mvp1_dm(gateway_url, &envelope_id, "bob_target_mvp1_realnet", &ciphertext)?;
        assert_node_opaque_payload(&delivered.envelope.encrypted_payload, plaintext);
        let delivered_ciphertext: ramflux_crypto::DmCiphertext =
            serde_json::from_str(&delivered.envelope.encrypted_payload)?;
        let decrypted = bob_session.decrypt(&delivered_ciphertext, b"alice_device|bob_device")?;
        assert_eq!(decrypted, *plaintext);
        bob_db.send_direct_message("conv_mvp2_friend_realnet", &message_id, "alice", &decrypted)?;
    }
    bob_db.mark_delivered("conv_mvp2_friend_realnet", "bob", "msg_mvp2_003", 1_760_000_030, 300)?;
    bob_db.mark_read("conv_mvp2_friend_realnet", "bob", "msg_mvp2_003")?;
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn assert_mvp2_bob_conversation_projection(
    bob_db: &ramflux_storage::AccountDb,
    plaintexts: &[&[u8]],
) -> Result<(), Box<dyn std::error::Error>> {
    let messages = bob_db.direct_messages("conv_mvp2_friend_realnet")?;
    assert_eq!(messages.len(), plaintexts.len());
    for (index, message) in messages.iter().enumerate() {
        assert_eq!(message.message_id, format!("msg_mvp2_{:03}", index + 1));
        assert_eq!(message.sender_id, "alice");
        assert_eq!(message.encrypted_body, plaintexts[index]);
    }
    let projection = bob_db.conversation_projection("conv_mvp2_friend_realnet", "bob")?;
    assert_eq!(projection.message_count, u64::try_from(plaintexts.len())?);
    assert_eq!(projection.last_message_id.as_deref(), Some("msg_mvp2_003"));
    assert_eq!(projection.delivered_through_message_id.as_deref(), Some("msg_mvp2_003"));
    assert_eq!(projection.read_through_message_id.as_deref(), Some("msg_mvp2_003"));
    assert!(!projection.is_unread);
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn assert_mvp2_bot_consent_gate(
    bob_db: &ramflux_storage::AccountDb,
) -> Result<(), Box<dyn std::error::Error>> {
    let group = bob_db.group_state("group_mvp2_realnet")?;
    assert_eq!(group.group_epoch, 2);
    let current_members = BTreeSet::from(["alice".to_owned(), "bob".to_owned()]);
    let accepted = BTreeSet::from(["alice".to_owned()]);
    assert_ne!(current_members, accepted);
    assert!(!group.members.contains("bot"));
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn join_mvp2_bot_after_member_consents(
    bob_db: &ramflux_storage::AccountDb,
    group_epoch: &mut ramflux_storage::GroupKeyEpochState,
) -> Result<(), Box<dyn std::error::Error>> {
    ramflux_storage::EventStore::append_event(
        bob_db,
        "evt_mvp2_bot_disclosure_alice",
        "group.bot_key_disclosure_accepted",
        b"alice accepted bot key disclosure",
    )?;
    ramflux_storage::EventStore::append_event(
        bob_db,
        "evt_mvp2_bot_disclosure_bob",
        "group.bot_key_disclosure_accepted",
        b"bob accepted bot key disclosure",
    )?;
    let members = BTreeSet::from(["alice".to_owned(), "bob".to_owned()]);
    let accepted = BTreeSet::from(["alice".to_owned(), "bob".to_owned()]);
    assert_eq!(members, accepted);
    let group = bob_db.add_group_member("group_mvp2_realnet", "bot", "bot")?;
    assert_eq!(group.group_epoch, 3);
    assert!(group.members.contains("bot"));
    group_epoch.add_member_no_history("bot");
    assert_eq!(group_epoch.group_epoch, 3);
    assert_eq!(group_epoch.group_key_epoch, 3);
    assert!(group_epoch.assert_can_send("alice").is_err());
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn deliver_mvp2_group_sender_key_distribution(
    gateway_url: &str,
    alice_session: &mut ramflux_crypto::DmSession,
    bob_session: &mut ramflux_crypto::DmSession,
    group_epoch: &mut ramflux_storage::GroupKeyEpochState,
) -> Result<(), Box<dyn std::error::Error>> {
    let plaintext = format!(
        "{{\"type\":\"group_sender_key.distribution\",\"group\":\"group_mvp2_realnet\",\"group_epoch\":{},\"group_key_epoch\":{},\"sender\":\"alice\"}}",
        group_epoch.group_epoch, group_epoch.group_key_epoch
    );
    let ciphertext = alice_session.encrypt(plaintext.as_bytes(), b"alice_device|bob_device")?;
    let delivered = deliver_mvp1_dm(
        gateway_url,
        "env_mvp2_group_sender_key_bob",
        "bob_target_mvp1_realnet",
        &ciphertext,
    )?;
    assert_node_opaque_payload(
        &delivered.envelope.encrypted_payload,
        b"group_sender_key.distribution",
    );
    let delivered_ciphertext: ramflux_crypto::DmCiphertext =
        serde_json::from_str(&delivered.envelope.encrypted_payload)?;
    let decrypted = bob_session.decrypt(&delivered_ciphertext, b"alice_device|bob_device")?;
    assert_eq!(decrypted, plaintext.as_bytes());
    group_epoch.distribute_sender_key("alice");
    group_epoch.assert_can_send("alice")?;
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn deliver_mvp2_group_message_fanout(
    context: Mvp2GroupFanoutContext<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let Mvp2GroupFanoutContext {
        gateway_url,
        alice_recipient_session,
        recipient_session,
        group_epoch,
        bot,
        bot_target_delivery_id,
        plaintext,
    } = context;
    let group_ciphertext = group_epoch.encrypt_epoch_message_for("alice", plaintext)?;
    let recipient_payload =
        alice_recipient_session.encrypt(&group_ciphertext, b"alice_device|bob_device")?;
    let recipient_delivery = deliver_mvp1_dm(
        gateway_url,
        "env_mvp2_group_message_bob",
        "bob_target_mvp1_realnet",
        &recipient_payload,
    )?;
    assert_node_opaque_payload(&recipient_delivery.envelope.encrypted_payload, plaintext);
    let recipient_dm: ramflux_crypto::DmCiphertext =
        serde_json::from_str(&recipient_delivery.envelope.encrypted_payload)?;
    let recipient_group_ciphertext =
        recipient_session.decrypt(&recipient_dm, b"alice_device|bob_device")?;
    assert_eq!(recipient_group_ciphertext, group_ciphertext);
    let recipient_plaintext =
        group_epoch.decrypt_epoch_message_for("bob", &recipient_group_ciphertext)?;
    assert_eq!(recipient_plaintext, b"alicemvp2 group sender keys fanout");

    let (mut initiator_to_bot, mut bot_receiver) =
        establish_mvp2_alice_bot_sessions(bot, "mvp2-realnet-group-bot")?;
    let bot_payload = initiator_to_bot.encrypt(&group_ciphertext, b"alice_device|bot_device")?;
    let bot_delivery = deliver_mvp1_dm(
        gateway_url,
        "env_mvp2_group_message_bot",
        bot_target_delivery_id,
        &bot_payload,
    )?;
    assert_node_opaque_payload(&bot_delivery.envelope.encrypted_payload, plaintext);
    let bot_dm: ramflux_crypto::DmCiphertext =
        serde_json::from_str(&bot_delivery.envelope.encrypted_payload)?;
    let bot_group_ciphertext = bot_receiver.decrypt(&bot_dm, b"alice_device|bot_device")?;
    assert_eq!(bot_group_ciphertext, group_ciphertext);
    let bot_plaintext = group_epoch.decrypt_epoch_message_for("bot", &bot_group_ciphertext)?;
    assert_eq!(bot_plaintext, b"alicemvp2 group sender keys fanout");
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn establish_mvp2_alice_bot_sessions(
    bot: &Mvp2BotRealnetFixture,
    _session_label: &str,
) -> Result<(ramflux_crypto::DmSession, ramflux_crypto::DmSession), Box<dyn std::error::Error>> {
    let alice_identity = ramflux_crypto::X25519KeyPair::from_seed([0x47; 32]);
    let alice_ephemeral = ramflux_crypto::X25519KeyPair::from_seed([0x65; 32]);
    let bundle_bytes = serde_json::to_vec(&bot.prekey_bundle)?;
    let prekey_bundle_hash =
        ramflux_crypto::blake3_256(ramflux_protocol::domain::X3DH_PREKEY_BUNDLE, &bundle_bytes);
    let associated_data = b"alice_device|bot_device";
    let alice_hash =
        ramflux_crypto::blake3_256(ramflux_protocol::domain::DEVICE_PROOF, b"alice_device");
    let bot_hash =
        ramflux_crypto::blake3_256(ramflux_protocol::domain::DEVICE_PROOF, b"bot_device");
    let initiator = ramflux_crypto::x3dh_initiator(&ramflux_crypto::X3dhInitiatorInput {
        initiator_identity: &alice_identity,
        initiator_ephemeral: &alice_ephemeral,
        initiator_device_id_hash: alice_hash,
        recipient_device_id_hash: bot_hash,
        recipient_bundle: &bot.prekey_bundle,
        associated_data,
        prekey_bundle_hash: &prekey_bundle_hash,
        initial_ratchet_public: alice_ephemeral.public,
    })?;
    let recipient = ramflux_crypto::x3dh_recipient(&ramflux_crypto::X3dhRecipientInput {
        recipient_identity: &bot.identity,
        recipient_signed_prekey: &bot.signed_prekey,
        recipient_one_time_prekey: None,
        initiator_identity_public: alice_identity.public,
        initiator_ephemeral_public: alice_ephemeral.public,
        initiator_device_id_hash: alice_hash,
        recipient_device_id_hash: bot_hash,
        recipient_signed_prekey_id: &bot.prekey_bundle.signed_prekey_id,
        recipient_one_time_prekey_id: bot.prekey_bundle.one_time_prekey_id.as_deref(),
        associated_data,
        prekey_bundle_hash: &prekey_bundle_hash,
        initial_ratchet_public: alice_ephemeral.public,
    })?;
    Ok((
        ramflux_crypto::DmSession::initiator(
            initiator.root_seed,
            alice_hash,
            bot_hash,
            initiator.bootstrap_transcript_hash,
        )?,
        ramflux_crypto::DmSession::recipient(
            recipient.root_seed,
            bot_hash,
            alice_hash,
            recipient.bootstrap_transcript_hash,
        )?,
    ))
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn assert_mvp2_group_projection(
    bob_db: &ramflux_storage::AccountDb,
    group_plaintext: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    bob_db.send_direct_message(
        "group_conv_mvp2_realnet",
        "msg_mvp2_group_001",
        "alice",
        group_plaintext,
    )?;
    let projection = bob_db.conversation_projection("group_conv_mvp2_realnet", "bob")?;
    assert_eq!(projection.message_count, 1);
    assert_eq!(projection.last_message_id.as_deref(), Some("msg_mvp2_group_001"));
    let group = bob_db.group_state("group_mvp2_realnet")?;
    assert_eq!(group.group_epoch, 3);
    assert!(group.members.contains("bot"));
    Ok(())
}
