// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use super::*;

#[test]
fn direct_message_send_recv() -> Result<(), Box<dyn std::error::Error>> {
    let db = test_account_db("direct_message_send_recv")?;
    db.send_direct_message("conv_1", "msg_1", "alice", b"ciphertext")?;
    let messages = db.direct_messages("conv_1")?;
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].encrypted_body, b"ciphertext");
    Ok(())
}

#[test]
fn message_reply_mention_forward_projection() -> Result<(), Box<dyn std::error::Error>> {
    let db = test_account_db("message_reply_mention_forward_projection")?;
    db.send_direct_message("conv_1", "msg_1", "alice", b"original")?;
    let metadata = ramflux_storage::MessageMetadata {
        reply_to: Some(ramflux_storage::ReplyToMetadata {
            message_id: "msg_1".to_owned(),
            quoted_cipher: Some(b"quoted-cipher".to_vec()),
        }),
        mentions: vec!["bob_identity_commitment".to_owned()],
        forwarded_from: Some(ramflux_storage::ForwardedFromMetadata {
            source_message_id_hash: "source_hash_1".to_owned(),
        }),
        forward_count: 1,
    };
    db.send_direct_message_with_metadata("conv_1", "msg_2", "alice", b"rich", &metadata)?;

    let messages = db.direct_messages("conv_1")?;
    let rich = messages
        .iter()
        .find(|message| message.message_id == "msg_2")
        .ok_or_else(|| "rich message missing from projection".to_owned())?;
    assert_eq!(rich.metadata, metadata);
    assert!(db.message_mentions("conv_1", "msg_2", "bob_identity_commitment")?);
    assert!(!db.message_mentions("conv_1", "msg_2", "carol_identity_commitment")?);
    Ok(())
}

#[test]
fn message_delete_tombstone_projection() -> Result<(), Box<dyn std::error::Error>> {
    let db = test_account_db("message_delete_tombstone_projection")?;
    db.send_direct_message("conv_1", "msg_1", "alice", b"one")?;
    db.send_direct_message("conv_1", "msg_2", "alice", b"two")?;
    let tombstone =
        db.delete_direct_message("conv_1", "msg_2", "own_devices", "tombstone_msg_2")?;
    assert_eq!(tombstone.message_id, "msg_2");
    assert_eq!(db.message_tombstone("tombstone_msg_2")?.delete_scope, "own_devices");

    let projection = db.conversation_projection("conv_1", "alice")?;
    assert_eq!(projection.message_count, 1);
    assert_eq!(projection.last_message_id, Some("msg_1".to_owned()));
    let messages = db.direct_messages("conv_1")?;
    let deleted = messages
        .iter()
        .find(|message| message.message_id == "msg_2")
        .ok_or_else(|| "deleted message missing from audit projection".to_owned())?;
    assert!(deleted.deleted);
    assert!(deleted.encrypted_body.is_empty());
    Ok(())
}

#[test]
fn conversation_projection_read() -> Result<(), Box<dyn std::error::Error>> {
    let db = test_account_db("conversation_projection_read")?;
    db.send_direct_message("conv_1", "msg_1", "alice", b"one")?;
    db.send_direct_message("conv_1", "msg_2", "bob", b"two")?;
    let projection = db.conversation_projection("conv_1", "alice")?;
    assert_eq!(projection.message_count, 2);
    assert_eq!(projection.last_message_id, Some("msg_2".to_owned()));
    assert_eq!(projection.read_through_message_id, None);
    Ok(())
}

#[test]
fn conversation_mark_read() -> Result<(), Box<dyn std::error::Error>> {
    let db = test_account_db("conversation_mark_read")?;
    db.send_direct_message("conv_1", "msg_1", "alice", b"one")?;
    db.mark_read("conv_1", "bob", "msg_1")?;
    let projection = db.conversation_projection("conv_1", "bob")?;
    assert_eq!(projection.read_through_message_id, Some("msg_1".to_owned()));
    assert!(!projection.is_unread);
    Ok(())
}

#[test]
fn receipt_delivered_distinct_from_read() -> Result<(), Box<dyn std::error::Error>> {
    let db = test_account_db("receipt_delivered_distinct_from_read")?;
    db.send_direct_message("conv_1", "msg_1", "alice", b"one")?;
    db.send_direct_message("conv_1", "msg_2", "alice", b"two")?;

    let receipt = db.mark_delivered("conv_1", "bob_device", "msg_2", 1_760_000_010, 300)?;
    assert_eq!(receipt.delivered_through_message_id, "msg_2");
    assert_eq!(receipt.ttl_seconds, 300);
    let stored = db
        .delivery_receipt("conv_1", "bob_device")?
        .ok_or_else(|| "delivery receipt missing".to_owned())?;
    assert_eq!(stored, receipt);

    let delivered_projection = db.conversation_projection("conv_1", "bob_device")?;
    assert_eq!(delivered_projection.delivered_through_message_id, Some("msg_2".to_owned()));
    assert_eq!(delivered_projection.read_through_message_id, None);
    assert!(delivered_projection.is_unread);

    db.mark_read("conv_1", "bob_device", "msg_2")?;
    let read_projection = db.conversation_projection("conv_1", "bob_device")?;
    assert_eq!(read_projection.read_through_message_id, Some("msg_2".to_owned()));
    assert_eq!(read_projection.delivered_through_message_id, Some("msg_2".to_owned()));
    assert!(!read_projection.is_unread);

    let clamped = db.mark_delivered("conv_1", "bob_device", "msg_2", 1_760_000_020, 99_999_999)?;
    assert_eq!(clamped.ttl_seconds, 30 * 24 * 60 * 60);
    assert_eq!(db.expire_delivery_receipts(1_760_000_020 + clamped.ttl_seconds)?, 1);
    assert!(db.delivery_receipt("conv_1", "bob_device")?.is_none());
    let expired_projection = db.conversation_projection("conv_1", "bob_device")?;
    assert_eq!(expired_projection.delivered_through_message_id, None);
    assert_eq!(expired_projection.read_through_message_id, Some("msg_2".to_owned()));
    Ok(())
}

#[test]
fn unread_marker_overrides_read_state() -> Result<(), Box<dyn std::error::Error>> {
    let db = test_account_db("unread_marker_overrides_read_state")?;
    db.send_direct_message("conv_1", "msg_1", "alice", b"one")?;
    db.send_direct_message("conv_1", "msg_2", "alice", b"two")?;
    db.mark_read("conv_1", "bob", "msg_2")?;
    let read_projection = db.conversation_projection("conv_1", "bob")?;
    assert!(!read_projection.is_unread);

    db.set_unread_marker("conv_1", "bob", "msg_1", 1)?;
    let unread_projection = db.conversation_projection("conv_1", "bob")?;
    assert_eq!(unread_projection.manual_unread_message_id, Some("msg_1".to_owned()));
    assert!(unread_projection.is_unread);

    db.clear_unread_marker("conv_1", "bob", 2)?;
    let cleared_projection = db.conversation_projection("conv_1", "bob")?;
    assert_eq!(cleared_projection.manual_unread_message_id, None);
    assert!(!cleared_projection.is_unread);
    Ok(())
}

#[test]
fn typing_state_ttl_and_stop_are_volatile() -> Result<(), Box<dyn std::error::Error>> {
    let root = temp_root("typing_state_ttl_and_stop_are_volatile")?;
    let index = ramflux_storage::AccountIndex::open(&root)?;
    index.create_account("acct", "principal_commitment")?;
    let key = ramflux_storage::AccountDbKey::derive("acct", b"test-secret");
    let db = ramflux_storage::AccountDb::open(&index, "acct", &key)?;

    db.typing_started("conv_1", "alice", 1_760_000_000, 10, "contacts");
    let active = db.active_typing("conv_1", 1_760_000_005);
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].actor_identity, "alice");
    assert_eq!(active[0].privacy_scope, "contacts");

    assert!(db.active_typing("conv_1", 1_760_000_011).is_empty());
    db.typing_started("conv_1", "alice", 1_760_000_020, 10, "contacts");
    db.typing_stopped("conv_1", "alice");
    assert!(db.active_typing("conv_1", 1_760_000_021).is_empty());

    db.typing_started("conv_1", "alice", 1_760_000_030, 10, "contacts");
    let reopened = ramflux_storage::AccountDb::open(&index, "acct", &key)?;
    assert!(reopened.active_typing("conv_1", 1_760_000_031).is_empty());
    Ok(())
}

#[test]
fn contact_presence_privacy_ttl_is_volatile() -> Result<(), Box<dyn std::error::Error>> {
    let root = temp_root("contact_presence_privacy_ttl_is_volatile")?;
    let index = ramflux_storage::AccountIndex::open(&root)?;
    index.create_account("acct", "principal_commitment")?;
    let key = ramflux_storage::AccountDbKey::derive("acct", b"test-secret");
    let db = ramflux_storage::AccountDb::open(&index, "acct", &key)?;

    db.update_contact_presence(ramflux_storage::ContactPresenceUpdate {
        identity_commitment: "bob_identity_commitment",
        presence_state: "online",
        last_seen_at: Some(1_760_000_000),
        observed_at: 1_760_000_000,
        ttl_seconds: 30,
        privacy_scope: "contacts",
    });
    let presence = db
        .contact_presence("bob_identity_commitment", 1_760_000_010)
        .ok_or_else(|| "presence missing before ttl".to_owned())?;
    assert_eq!(presence.presence_state, "online");
    assert_eq!(presence.privacy_scope, "contacts");
    assert_eq!(presence.last_seen_at, Some(1_760_000_000));
    assert!(db.contact_presence("bob_identity_commitment", 1_760_000_031).is_none());

    db.update_contact_presence(ramflux_storage::ContactPresenceUpdate {
        identity_commitment: "bob_identity_commitment",
        presence_state: "recently_active",
        last_seen_at: None,
        observed_at: 1_760_000_040,
        ttl_seconds: 30,
        privacy_scope: "selected_contacts",
    });
    let reopened = ramflux_storage::AccountDb::open(&index, "acct", &key)?;
    assert!(reopened.contact_presence("bob_identity_commitment", 1_760_000_041).is_none());
    Ok(())
}

#[test]
fn conversation_archive_pin_mute_projection() -> Result<(), Box<dyn std::error::Error>> {
    let db = test_account_db("conversation_archive_pin_mute_projection")?;
    db.send_direct_message("conv_1", "msg_1", "alice", b"one")?;

    db.set_conversation_archived("conv_1", true)?;
    db.pin_conversation("conv_1", 7)?;
    db.mute_conversation("conv_1", 1_760_003_600)?;
    let projection = db.conversation_projection("conv_1", "alice")?;
    assert!(projection.is_archived);
    assert_eq!(projection.pin_order, Some(7));
    assert_eq!(projection.mute_until, Some(1_760_003_600));

    db.set_conversation_archived("conv_1", false)?;
    db.unpin_conversation("conv_1")?;
    db.unmute_conversation("conv_1")?;
    let reset = db.conversation_projection("conv_1", "alice")?;
    assert!(!reset.is_archived);
    assert_eq!(reset.pin_order, None);
    assert_eq!(reset.mute_until, None);
    Ok(())
}

#[test]
fn conversation_hide_and_clear_projection() -> Result<(), Box<dyn std::error::Error>> {
    let db = test_account_db("conversation_hide_and_clear_projection")?;
    let metadata = ramflux_storage::MessageMetadata::default();
    db.send_direct_message_at_with_metadata(ramflux_storage::DirectMessageWrite {
        conversation_id: "conv_1",
        message_id: "msg_1",
        sender_id: "alice",
        encrypted_body: b"one",
        metadata: &metadata,
        created_at: 1_760_000_000,
    })?;
    db.hide_conversation_at("conv_1", 1_760_000_010)?;
    let hidden = db.conversation_projection("conv_1", "alice")?;
    assert!(hidden.is_hidden);

    db.send_direct_message_at_with_metadata(ramflux_storage::DirectMessageWrite {
        conversation_id: "conv_1",
        message_id: "msg_2",
        sender_id: "bob",
        encrypted_body: b"two",
        metadata: &metadata,
        created_at: 1_760_000_020,
    })?;
    let resurfaced = db.conversation_projection("conv_1", "alice")?;
    assert!(!resurfaced.is_hidden);
    assert_eq!(resurfaced.message_count, 2);

    db.clear_conversation_at("conv_1", 1_760_000_025, "local_only")?;
    let cleared = db.conversation_projection("conv_1", "alice")?;
    assert_eq!(cleared.message_count, 0);
    assert_eq!(cleared.last_message_id, None);
    assert_eq!(cleared.cleared_at, Some(1_760_000_025));

    db.send_direct_message_at_with_metadata(ramflux_storage::DirectMessageWrite {
        conversation_id: "conv_1",
        message_id: "msg_3",
        sender_id: "bob",
        encrypted_body: b"three",
        metadata: &metadata,
        created_at: 1_760_000_030,
    })?;
    let after_new_message = db.conversation_projection("conv_1", "alice")?;
    assert_eq!(after_new_message.message_count, 1);
    assert_eq!(after_new_message.last_message_id, Some("msg_3".to_owned()));
    Ok(())
}
