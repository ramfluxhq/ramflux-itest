// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use crate::*;

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp9_assert_disappearing_tombstone_delivery(
    gateway_url: &str,
    clients: &Mvp9LocalClients,
    alice_session: &mut ramflux_crypto::DmSession,
    bob_session: &mut ramflux_crypto::DmSession,
) -> Result<(), Box<dyn std::error::Error>> {
    mvp9_deliver_disappearing_policy_and_message(gateway_url, clients, alice_session, bob_session)?;
    mvp9_expire_and_deliver_tombstone(gateway_url, clients, alice_session, bob_session)?;
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp9_deliver_disappearing_policy_and_message(
    gateway_url: &str,
    clients: &Mvp9LocalClients,
    alice_session: &mut ramflux_crypto::DmSession,
    bob_session: &mut ramflux_crypto::DmSession,
) -> Result<(), Box<dyn std::error::Error>> {
    let policy_plaintext = br#"{"type":"conversation.disappearing_updated","conversation_id":"conv_mvp9_realnet","ttl_seconds":60,"countdown_mode":"on_send","scope":"conversation_members"}"#;
    let policy_ciphertext = alice_session.encrypt(policy_plaintext, b"alice_device|bob_device")?;
    let delivered_policy = deliver_mvp9_dm(
        gateway_url,
        "env_mvp9_disappearing_policy",
        "bob_target_mvp1_realnet",
        &policy_ciphertext,
    )?;
    assert_eq!(delivered_policy.submit.inbox_seq, Some(1));
    let decrypted_policy = decrypt_mvp9_dm(
        &delivered_policy,
        bob_session,
        b"alice_device|bob_device",
        policy_plaintext,
    )?;
    assert_eq!(decrypted_policy, policy_plaintext);
    clients.alice_db.set_disappearing_policy(
        "conv_mvp9_realnet",
        60,
        "on_send",
        "conversation_members",
        1_760_000_000,
    )?;
    clients.bob_db.set_disappearing_policy(
        "conv_mvp9_realnet",
        60,
        "on_send",
        "conversation_members",
        1_760_000_000,
    )?;

    let expiring_plaintext = br#"{"type":"message.created","conversation_id":"conv_mvp9_realnet","msg_event_id":"msg_mvp9_expiring","body":"mvp9 disappearing secret"}"#;
    let expiring_ciphertext =
        alice_session.encrypt(expiring_plaintext, b"alice_device|bob_device")?;
    let delivered_expiring = deliver_mvp9_dm(
        gateway_url,
        "env_mvp9_expiring_message",
        "bob_target_mvp1_realnet",
        &expiring_ciphertext,
    )?;
    assert_eq!(delivered_expiring.submit.inbox_seq, Some(2));
    let decrypted_expiring = decrypt_mvp9_dm(
        &delivered_expiring,
        bob_session,
        b"alice_device|bob_device",
        expiring_plaintext,
    )?;
    assert_eq!(decrypted_expiring, expiring_plaintext);
    let default_metadata = ramflux_storage::MessageMetadata::default();
    clients.alice_db.send_direct_message_at_with_metadata(ramflux_storage::DirectMessageWrite {
        conversation_id: "conv_mvp9_realnet",
        message_id: "msg_mvp9_expiring",
        sender_id: "alice",
        encrypted_body: &decrypted_expiring,
        metadata: &default_metadata,
        created_at: 1_760_000_000,
    })?;
    clients.bob_db.send_direct_message_at_with_metadata(ramflux_storage::DirectMessageWrite {
        conversation_id: "conv_mvp9_realnet",
        message_id: "msg_mvp9_expiring",
        sender_id: "alice",
        encrypted_body: &decrypted_expiring,
        metadata: &default_metadata,
        created_at: 1_760_000_000,
    })?;
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp9_expire_and_deliver_tombstone(
    gateway_url: &str,
    clients: &Mvp9LocalClients,
    alice_session: &mut ramflux_crypto::DmSession,
    bob_session: &mut ramflux_crypto::DmSession,
) -> Result<(), Box<dyn std::error::Error>> {
    let tombstones =
        clients.bob_db.expire_disappearing_messages("conv_mvp9_realnet", 1_760_000_061)?;
    assert_eq!(tombstones.len(), 1);
    assert_eq!(tombstones[0].message_id, "msg_mvp9_expiring");
    assert_eq!(tombstones[0].delete_scope, "conversation_members");
    let bob_messages = clients.bob_db.direct_messages("conv_mvp9_realnet")?;
    let bob_expired = bob_messages
        .iter()
        .find(|message| message.message_id == "msg_mvp9_expiring")
        .ok_or_else(|| "bob expired message missing from projection".to_owned())?;
    assert!(bob_expired.deleted);
    assert!(bob_expired.encrypted_body.is_empty());

    let tombstone_plaintext = br#"{"type":"event_tombstone","conversation_id":"conv_mvp9_realnet","msg_event_id":"msg_mvp9_expiring","tombstone_id":"tombstone:conv_mvp9_realnet:msg_mvp9_expiring","scope":"conversation_members"}"#;
    let tombstone_ciphertext =
        bob_session.encrypt(tombstone_plaintext, b"alice_device|bob_device")?;
    let delivered_tombstone = deliver_mvp9_dm(
        gateway_url,
        "env_mvp9_event_tombstone",
        "alice_target_mvp1_realnet",
        &tombstone_ciphertext,
    )?;
    assert_eq!(delivered_tombstone.submit.inbox_seq, Some(1));
    let decrypted_tombstone = decrypt_mvp9_dm(
        &delivered_tombstone,
        alice_session,
        b"alice_device|bob_device",
        tombstone_plaintext,
    )?;
    assert_eq!(decrypted_tombstone, tombstone_plaintext);
    clients.alice_db.delete_direct_message(
        "conv_mvp9_realnet",
        "msg_mvp9_expiring",
        "conversation_members",
        "tombstone:conv_mvp9_realnet:msg_mvp9_expiring",
    )?;
    let alice_messages = clients.alice_db.direct_messages("conv_mvp9_realnet")?;
    let alice_expired = alice_messages
        .iter()
        .find(|message| message.message_id == "msg_mvp9_expiring")
        .ok_or_else(|| "alice expired message missing from projection".to_owned())?;
    assert!(alice_expired.deleted);
    assert!(alice_expired.encrypted_body.is_empty());
    assert_eq!(
        clients
            .alice_db
            .message_tombstone("tombstone:conv_mvp9_realnet:msg_mvp9_expiring")?
            .delete_scope,
        "conversation_members"
    );
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp9_assert_reply_mention_forward_projection(
    gateway_url: &str,
    clients: &Mvp9LocalClients,
    alice_session: &mut ramflux_crypto::DmSession,
    bob_session: &mut ramflux_crypto::DmSession,
) -> Result<(), Box<dyn std::error::Error>> {
    let rich_plaintext = br#"{"type":"message.created","conversation_id":"conv_mvp9_realnet","msg_event_id":"msg_mvp9_rich","body":"mvp9 rich secret","reply_to":"msg_mvp9_expiring","mentions":["bob_identity_commitment"],"forwarded_from":{"source_message_id_hash":"source_hash_mvp9"},"forward_count":2}"#;
    let rich_ciphertext = alice_session.encrypt(rich_plaintext, b"alice_device|bob_device")?;
    let delivered_rich = deliver_mvp9_dm(
        gateway_url,
        "env_mvp9_rich_message",
        "bob_target_mvp1_realnet",
        &rich_ciphertext,
    )?;
    assert_eq!(delivered_rich.submit.inbox_seq, Some(3));
    assert_node_opaque_payload(
        &delivered_rich.entry.envelope.encrypted_payload,
        b"bob_identity_commitment",
    );
    assert_node_opaque_payload(
        &delivered_rich.entry.envelope.encrypted_payload,
        b"source_hash_mvp9",
    );
    let decrypted_rich =
        decrypt_mvp9_dm(&delivered_rich, bob_session, b"alice_device|bob_device", rich_plaintext)?;
    assert_eq!(decrypted_rich, rich_plaintext);

    let metadata = ramflux_storage::MessageMetadata {
        reply_to: Some(ramflux_storage::ReplyToMetadata {
            message_id: "msg_mvp9_expiring".to_owned(),
            quoted_cipher: Some(b"quoted-cipher-mvp9".to_vec()),
        }),
        mentions: vec!["bob_identity_commitment".to_owned()],
        forwarded_from: Some(ramflux_storage::ForwardedFromMetadata {
            source_message_id_hash: "source_hash_mvp9".to_owned(),
        }),
        forward_count: 2,
    };
    clients.bob_db.send_direct_message_at_with_metadata(ramflux_storage::DirectMessageWrite {
        conversation_id: "conv_mvp9_realnet",
        message_id: "msg_mvp9_rich",
        sender_id: "alice",
        encrypted_body: &decrypted_rich,
        metadata: &metadata,
        created_at: 1_760_000_120,
    })?;
    let messages = clients.bob_db.direct_messages("conv_mvp9_realnet")?;
    let rich = messages
        .iter()
        .find(|message| message.message_id == "msg_mvp9_rich")
        .ok_or_else(|| "rich message missing from projection".to_owned())?;
    assert_eq!(rich.metadata, metadata);
    assert!(clients.bob_db.message_mentions(
        "conv_mvp9_realnet",
        "msg_mvp9_rich",
        "bob_identity_commitment"
    )?);
    assert!(!clients.bob_db.message_mentions(
        "conv_mvp9_realnet",
        "msg_mvp9_rich",
        "carol_identity_commitment"
    )?);
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp9_assert_delivered_receipt_ttl(
    gateway_url: &str,
    clients: &Mvp9LocalClients,
    alice_session: &mut ramflux_crypto::DmSession,
    bob_session: &mut ramflux_crypto::DmSession,
) -> Result<(), Box<dyn std::error::Error>> {
    let message_plaintext = br#"{"type":"message.created","conversation_id":"conv_mvp9_transient","msg_event_id":"msg_mvp9_delivered","body":"mvp9 delivered receipt secret"}"#;
    let message_ciphertext =
        alice_session.encrypt(message_plaintext, b"alice_device|bob_device")?;
    let delivered_message = deliver_mvp9_dm(
        gateway_url,
        "env_mvp9_transient_message",
        "bob_target_mvp1_realnet",
        &message_ciphertext,
    )?;
    assert_eq!(delivered_message.submit.inbox_seq, Some(1));
    let decrypted_message = decrypt_mvp9_dm(
        &delivered_message,
        bob_session,
        b"alice_device|bob_device",
        message_plaintext,
    )?;
    clients.alice_db.send_direct_message(
        "conv_mvp9_transient",
        "msg_mvp9_delivered",
        "alice",
        &decrypted_message,
    )?;
    clients.bob_db.send_direct_message(
        "conv_mvp9_transient",
        "msg_mvp9_delivered",
        "alice",
        &decrypted_message,
    )?;

    let receipt_plaintext = br#"{"type":"receipt.delivered","conversation_id":"conv_mvp9_transient","delivered_through_message_id":"msg_mvp9_delivered","receiver_device_id":"bob_device_realnet","ttl_seconds":2}"#;
    let receipt_ciphertext = bob_session.encrypt(receipt_plaintext, b"alice_device|bob_device")?;
    let delivered_receipt = deliver_mvp9_dm(
        gateway_url,
        "env_mvp9_delivered_receipt",
        "alice_target_mvp1_realnet",
        &receipt_ciphertext,
    )?;
    assert_eq!(delivered_receipt.submit.inbox_seq, Some(1));
    let decrypted_receipt = decrypt_mvp9_dm(
        &delivered_receipt,
        alice_session,
        b"alice_device|bob_device",
        receipt_plaintext,
    )?;
    assert_eq!(decrypted_receipt, receipt_plaintext);
    let receipt = clients.alice_db.mark_delivered(
        "conv_mvp9_transient",
        "bob_device_realnet",
        "msg_mvp9_delivered",
        1_760_000_000,
        2,
    )?;
    assert_eq!(receipt.ttl_seconds, 2);
    let delivered_projection =
        clients.alice_db.conversation_projection("conv_mvp9_transient", "bob_device_realnet")?;
    assert_eq!(
        delivered_projection.delivered_through_message_id.as_deref(),
        Some("msg_mvp9_delivered")
    );
    assert_eq!(delivered_projection.read_through_message_id, None);
    assert!(delivered_projection.is_unread);

    clients.alice_db.mark_read(
        "conv_mvp9_transient",
        "bob_device_realnet",
        "msg_mvp9_delivered",
    )?;
    let read_projection =
        clients.alice_db.conversation_projection("conv_mvp9_transient", "bob_device_realnet")?;
    assert_eq!(read_projection.read_through_message_id.as_deref(), Some("msg_mvp9_delivered"));
    assert_eq!(read_projection.delivered_through_message_id.as_deref(), Some("msg_mvp9_delivered"));
    assert!(!read_projection.is_unread);
    assert_mvp9_history_has_no_transient_events(&clients.alice_db)?;

    assert_eq!(clients.alice_db.expire_delivery_receipts(1_760_000_002)?, 1);
    assert!(
        clients.alice_db.delivery_receipt("conv_mvp9_transient", "bob_device_realnet")?.is_none()
    );
    let expired_projection =
        clients.alice_db.conversation_projection("conv_mvp9_transient", "bob_device_realnet")?;
    assert_eq!(expired_projection.delivered_through_message_id, None);
    assert_eq!(expired_projection.read_through_message_id.as_deref(), Some("msg_mvp9_delivered"));
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp9_assert_typing_ttl_and_volatility(
    gateway_url: &str,
    clients: &Mvp9LocalClients,
    alice_session: &mut ramflux_crypto::DmSession,
    bob_session: &mut ramflux_crypto::DmSession,
) -> Result<(), Box<dyn std::error::Error>> {
    let typing_plaintext = br#"{"type":"typing.started","conversation_id":"conv_mvp9_transient","actor_identity":"alice_realnet","ttl_seconds":2,"privacy_scope":"contacts"}"#;
    let typing_ciphertext = alice_session.encrypt(typing_plaintext, b"alice_device|bob_device")?;
    let delivered_typing = deliver_mvp9_dm(
        gateway_url,
        "env_mvp9_typing_started",
        "bob_target_mvp1_realnet",
        &typing_ciphertext,
    )?;
    let decrypted_typing = decrypt_mvp9_dm(
        &delivered_typing,
        bob_session,
        b"alice_device|bob_device",
        typing_plaintext,
    )?;
    assert_eq!(decrypted_typing, typing_plaintext);
    clients.bob_db.typing_started(
        "conv_mvp9_transient",
        "alice_realnet",
        1_760_000_010,
        2,
        "contacts",
    );
    let active = clients.bob_db.active_typing("conv_mvp9_transient", 1_760_000_011);
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].actor_identity, "alice_realnet");
    assert_eq!(active[0].privacy_scope, "contacts");
    assert!(clients.bob_db.active_typing("conv_mvp9_transient", 1_760_000_012).is_empty());

    clients.bob_db.typing_started(
        "conv_mvp9_transient",
        "alice_realnet",
        1_760_000_020,
        30,
        "contacts",
    );
    let stop_plaintext = br#"{"type":"typing.stopped","conversation_id":"conv_mvp9_transient","actor_identity":"alice_realnet"}"#;
    let stop_ciphertext = alice_session.encrypt(stop_plaintext, b"alice_device|bob_device")?;
    let delivered_stop = deliver_mvp9_dm(
        gateway_url,
        "env_mvp9_typing_stopped",
        "bob_target_mvp1_realnet",
        &stop_ciphertext,
    )?;
    let decrypted_stop =
        decrypt_mvp9_dm(&delivered_stop, bob_session, b"alice_device|bob_device", stop_plaintext)?;
    assert_eq!(decrypted_stop, stop_plaintext);
    clients.bob_db.typing_stopped("conv_mvp9_transient", "alice_realnet");
    assert!(clients.bob_db.active_typing("conv_mvp9_transient", 1_760_000_021).is_empty());

    clients.bob_db.typing_started(
        "conv_mvp9_transient",
        "alice_realnet",
        1_760_000_030,
        30,
        "contacts",
    );
    let reopened_bob = reopen_mvp9_bob_db(clients)?;
    assert!(reopened_bob.active_typing("conv_mvp9_transient", 1_760_000_031).is_empty());
    assert_mvp9_history_has_no_transient_events(&clients.bob_db)?;
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp9_assert_contact_presence_privacy(
    gateway_url: &str,
    clients: &Mvp9LocalClients,
    alice_session: &mut ramflux_crypto::DmSession,
    bob_session: &mut ramflux_crypto::DmSession,
) -> Result<(), Box<dyn std::error::Error>> {
    assert!(clients.alice_db.contact_presence("bob_realnet", 1_760_000_040).is_none());

    let presence_plaintext = br#"{"type":"contact_presence.updated","identity_commitment":"bob_realnet","presence_state":"online","last_seen_at":1760000040,"ttl_seconds":2,"privacy_scope":"selected_contacts"}"#;
    let presence_ciphertext =
        bob_session.encrypt(presence_plaintext, b"alice_device|bob_device")?;
    let delivered_presence = deliver_mvp9_dm(
        gateway_url,
        "env_mvp9_contact_presence",
        "alice_target_mvp1_realnet",
        &presence_ciphertext,
    )?;
    let decrypted_presence = decrypt_mvp9_dm(
        &delivered_presence,
        alice_session,
        b"alice_device|bob_device",
        presence_plaintext,
    )?;
    assert_eq!(decrypted_presence, presence_plaintext);
    clients.alice_db.update_contact_presence(ramflux_storage::ContactPresenceUpdate {
        identity_commitment: "bob_realnet",
        presence_state: "online",
        last_seen_at: Some(1_760_000_040),
        observed_at: 1_760_000_040,
        ttl_seconds: 2,
        privacy_scope: "selected_contacts",
    });
    let presence = clients
        .alice_db
        .contact_presence("bob_realnet", 1_760_000_041)
        .ok_or_else(|| "explicit contact presence missing".to_owned())?;
    assert_eq!(presence.presence_state, "online");
    assert_eq!(presence.privacy_scope, "selected_contacts");
    assert_eq!(presence.last_seen_at, Some(1_760_000_040));
    assert!(clients.alice_db.contact_presence("bob_realnet", 1_760_000_042).is_none());
    let reopened_alice = reopen_mvp9_alice_db(clients)?;
    assert!(reopened_alice.contact_presence("bob_realnet", 1_760_000_041).is_none());
    assert_mvp9_history_has_no_transient_events(&clients.alice_db)?;
    Ok(())
}
