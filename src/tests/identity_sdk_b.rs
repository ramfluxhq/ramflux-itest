// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use super::*;

#[test]
fn key_verification_kt_and_gossip_failures_mark_changed() -> Result<(), Box<dyn std::error::Error>>
{
    let fixture = mvp6_kt_fixture()?;
    let db = mvp6_verified_account_db("key_verification_kt_and_gossip_failures_mark_changed")?;
    let bob = safety_material("bob", 1);
    let bob_identity_commitment = safety_hash_text(&bob.identity_commitment);
    let verified = mvp6_mark_bob_verified(&db, &bob)?;
    assert_eq!(verified.verification_state, "verified");

    let checkpoint =
        db.store_contact_kt_checkpoint(ramflux_storage::ContactKtCheckpointUpdate {
            contact_identity_commitment: &bob_identity_commitment,
            tree_size: fixture.old_tree_head.tree_size,
            tree_root_hash: &fixture.old_tree_head.root_hash,
            leaf_index: 1,
        })?;
    assert_eq!(checkpoint.kt_tree_size, Some(fixture.old_tree_head.tree_size));

    let gossip_ok = ramflux_sync::verify_contact_gossip_checkpoint(
        ramflux_sync::ContactGossipExpectation {
            subject_identity_commitment: &bob_identity_commitment,
            lineage_head: &safety_hash_text(&bob.lineage_head),
            device_set_hash: &safety_hash_text(&ramflux_crypto::device_set_hash(&bob.devices)),
        },
        &[ramflux_sync::ContactGossipReport {
            reporter_identity_commitment: "carol".to_owned(),
            subject_identity_commitment: bob_identity_commitment.clone(),
            lineage_head: safety_hash_text(&bob.lineage_head),
            device_set_hash: safety_hash_text(&ramflux_crypto::device_set_hash(&bob.devices)),
        }],
    );
    assert!(gossip_ok.is_ok());

    let gossip_conflict = ramflux_sync::verify_contact_gossip_checkpoint(
        ramflux_sync::ContactGossipExpectation {
            subject_identity_commitment: &bob_identity_commitment,
            lineage_head: &safety_hash_text(&bob.lineage_head),
            device_set_hash: &safety_hash_text(&ramflux_crypto::device_set_hash(&bob.devices)),
        },
        &[ramflux_sync::ContactGossipReport {
            reporter_identity_commitment: "carol".to_owned(),
            subject_identity_commitment: bob_identity_commitment.clone(),
            lineage_head: "conflicting-lineage-head".to_owned(),
            device_set_hash: safety_hash_text(&ramflux_crypto::device_set_hash(&bob.devices)),
        }],
    );
    assert!(gossip_conflict.is_err());
    let changed = db.observe_contact_gossip(ramflux_storage::ContactGossipObservation {
        contact_identity_commitment: &bob_identity_commitment,
        expected_lineage_head: &safety_hash_text(&bob.lineage_head),
        reported_lineage_head: "conflicting-lineage-head",
        change_event_id: "contact_gossip.conflict:carol:bob",
        seen_at: 1_760_000_200,
    })?;
    assert_eq!(changed.verification_state, "changed");
    Ok(())
}

#[test]
fn new_device_history_backfill_checkpoint() -> Result<(), Box<dyn std::error::Error>> {
    let root = temp_root("new_device_history_backfill_checkpoint")?;
    let index = AccountIndex::open(&root)?;
    index.create_account("acct_old", "principal_commitment_old")?;
    index.create_account("acct_new", "principal_commitment_new")?;
    let old_key = AccountDbKey::derive("acct_old", b"old-device-secret");
    let new_key = AccountDbKey::derive("acct_new", b"new-device-secret");
    let old_device = ramflux_crypto::create_device_branch(
        "principal_commitment_old",
        "old_device",
        1,
        [0x42; 32],
    );
    let old_db = AccountDb::open(&index, "acct_old", &old_key)?.with_device_signer(old_device);
    let new_db = AccountDb::open(&index, "acct_new", &new_key)?;

    old_db.append_event("evt_1", "identity.created", b"identity")?;
    old_db.append_event("evt_2", "message.created", b"message")?;
    old_db.set_projection_checkpoint("conversation", "evt_2")?;
    let bundle = old_db.export_history_bundle("old_device", "new_device")?;
    new_db.import_history_bundle(&bundle)?;
    assert_eq!(new_db.event_body("evt_1")?, Some(b"identity".to_vec()));
    assert_eq!(new_db.event_body("evt_2")?, Some(b"message".to_vec()));
    assert_eq!(new_db.projection_checkpoint("conversation")?, Some("evt_2".to_owned()));
    Ok(())
}

#[test]
fn new_device_history_backfill_relay_opaque() {
    let store = ramflux_sync::ObjectStore::new();
    let relay = store.relay_history_bundle(b"encrypted-history-bundle");
    assert!(!relay.plaintext_visible);
    assert!(!relay.ciphertext_hash.is_empty());
}
