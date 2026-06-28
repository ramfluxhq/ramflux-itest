// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use crate::*;

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp6_mark_realnet_contacts_verified(
    test_name: &str,
    alice_material: &ramflux_crypto::ContactSafetyMaterial,
    bob_material: &ramflux_crypto::ContactSafetyMaterial,
) -> Result<(ramflux_storage::AccountDb, String), Box<dyn std::error::Error>> {
    let root = temp_root(test_name)?;
    let alice_index = ramflux_storage::AccountIndex::open(root.join("alice"))?;
    let bob_index = ramflux_storage::AccountIndex::open(root.join("bob"))?;
    alice_index.create_account("alice_mvp6_local", "alice_mvp6_realnet")?;
    bob_index.create_account("bob_mvp6_local", "bob_mvp6_realnet")?;
    let alice_db = ramflux_storage::AccountDb::open(
        &alice_index,
        "alice_mvp6_local",
        &ramflux_storage::AccountDbKey::derive("alice_mvp6_local", b"alice-mvp6-secret"),
    )?;
    let bob_db = ramflux_storage::AccountDb::open(
        &bob_index,
        "bob_mvp6_local",
        &ramflux_storage::AccountDbKey::derive("bob_mvp6_local", b"bob-mvp6-secret"),
    )?;

    let bob_identity_commitment = safety_hash_text(&bob_material.identity_commitment);
    let alice_identity_commitment = safety_hash_text(&alice_material.identity_commitment);
    let safety_number_hash =
        safety_hash_text(&ramflux_crypto::safety_fingerprint(alice_material, bob_material));
    let bob_device_set_hash =
        safety_hash_text(&ramflux_crypto::device_set_hash(&bob_material.devices));
    let alice_device_set_hash =
        safety_hash_text(&ramflux_crypto::device_set_hash(&alice_material.devices));
    let alice_verified =
        alice_db.mark_contact_verified(ramflux_storage::ContactVerificationUpdate {
            contact_identity_commitment: &bob_identity_commitment,
            safety_number_hash: &safety_number_hash,
            device_set_hash: &bob_device_set_hash,
            lineage_head: &safety_hash_text(&bob_material.lineage_head),
            verified_at: 1_760_000_000,
            verified_by_device_id: "alice_device_mvp6_realnet",
        })?;
    let bob_verified =
        bob_db.mark_contact_verified(ramflux_storage::ContactVerificationUpdate {
            contact_identity_commitment: &alice_identity_commitment,
            safety_number_hash: &safety_number_hash,
            device_set_hash: &alice_device_set_hash,
            lineage_head: &safety_hash_text(&alice_material.lineage_head),
            verified_at: 1_760_000_000,
            verified_by_device_id: "bob_device_mvp6_realnet",
        })?;
    assert_eq!(alice_verified.verification_state, "verified");
    assert_eq!(bob_verified.verification_state, "verified");
    Ok((alice_db, bob_identity_commitment))
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp6_verify_kt_and_gossip_paths(
    alice_db: &ramflux_storage::AccountDb,
    bob_identity_commitment: &str,
    bob_material: &ramflux_crypto::ContactSafetyMaterial,
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = mvp6_kt_fixture()?;
    let log_public_key = ramflux_crypto::fixture_verifying_key();
    let bob_kt_device = mvp6_kt_bob_device();
    ramflux_crypto::verify_kt_leaf_signature(
        &fixture.bob_leaf_v1,
        &bob_kt_device.signing_key.verifying_key(),
    )?;
    ramflux_crypto::verify_kt_inclusion_proof(
        fixture.bob_leaf_v1_hash,
        &fixture.bob_inclusion_proof_v1,
        &log_public_key,
    )?;
    ramflux_crypto::verify_kt_consistency_proof(
        &fixture.append_consistency_proof,
        &log_public_key,
    )?;
    let checkpoint =
        alice_db.store_contact_kt_checkpoint(ramflux_storage::ContactKtCheckpointUpdate {
            contact_identity_commitment: bob_identity_commitment,
            tree_size: fixture.old_tree_head.tree_size,
            tree_root_hash: &fixture.old_tree_head.root_hash,
            leaf_index: 1,
        })?;
    assert_eq!(checkpoint.verification_state, "verified");

    let lineage_head = safety_hash_text(&bob_material.lineage_head);
    let device_set_hash = safety_hash_text(&ramflux_crypto::device_set_hash(&bob_material.devices));
    ramflux_sync::verify_contact_gossip_checkpoint(
        ramflux_sync::ContactGossipExpectation {
            subject_identity_commitment: bob_identity_commitment,
            lineage_head: &lineage_head,
            device_set_hash: &device_set_hash,
        },
        &[ramflux_sync::ContactGossipReport {
            reporter_identity_commitment: "alice_mvp6_kt_realnet".to_owned(),
            subject_identity_commitment: bob_identity_commitment.to_owned(),
            lineage_head: lineage_head.clone(),
            device_set_hash: device_set_hash.clone(),
        }],
    )?;
    let unchanged = alice_db.observe_contact_gossip(ramflux_storage::ContactGossipObservation {
        contact_identity_commitment: bob_identity_commitment,
        expected_lineage_head: &lineage_head,
        reported_lineage_head: &lineage_head,
        change_event_id: "contact_gossip.ok:alice:bob",
        seen_at: 1_760_000_200,
    })?;
    assert_eq!(unchanged.verification_state, "verified");

    let mut tampered_inclusion = fixture.bob_inclusion_proof_v1;
    tampered_inclusion.audit_path[0][0] ^= 0x01;
    assert!(
        ramflux_crypto::verify_kt_inclusion_proof(
            fixture.bob_leaf_v1_hash,
            &tampered_inclusion,
            &log_public_key,
        )
        .is_err()
    );
    let changed = alice_db.observe_contact_fork(
        bob_identity_commitment,
        "kt.inclusion_failed:bob_mvp6_kt_realnet",
        1_760_000_300,
    )?;
    assert_eq!(changed.verification_state, "changed");

    let reset = mvp6_mark_bob_verified(alice_db, bob_material)?;
    assert_eq!(reset.verification_state, "verified");
    let rollback = ramflux_crypto::KtConsistencyProof {
        old_tree_head: fixture.new_tree_head,
        new_tree_head: fixture.old_tree_head,
        old_leaf_hashes: fixture.new_leaf_hashes,
        appended_leaf_hashes: Vec::new(),
    };
    assert!(ramflux_crypto::verify_kt_consistency_proof(&rollback, &log_public_key).is_err());
    let changed = alice_db.observe_contact_fork(
        bob_identity_commitment,
        "kt.consistency_failed:bob_mvp6_kt_realnet",
        1_760_000_400,
    )?;
    assert_eq!(changed.verification_state, "changed");

    let reset = mvp6_mark_bob_verified(alice_db, bob_material)?;
    assert_eq!(reset.verification_state, "verified");
    mvp6_assert_gossip_conflict_changes(
        alice_db,
        bob_identity_commitment,
        &lineage_head,
        &device_set_hash,
    )?;
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp6_assert_gossip_conflict_changes(
    alice_db: &ramflux_storage::AccountDb,
    bob_identity_commitment: &str,
    lineage_head: &str,
    device_set_hash: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let conflict = ramflux_sync::verify_contact_gossip_checkpoint(
        ramflux_sync::ContactGossipExpectation {
            subject_identity_commitment: bob_identity_commitment,
            lineage_head,
            device_set_hash,
        },
        &[ramflux_sync::ContactGossipReport {
            reporter_identity_commitment: "carol_mvp6_kt_realnet".to_owned(),
            subject_identity_commitment: bob_identity_commitment.to_owned(),
            lineage_head: "conflicting-bob-lineage-head".to_owned(),
            device_set_hash: device_set_hash.to_owned(),
        }],
    );
    assert!(conflict.is_err());
    let changed = alice_db.observe_contact_gossip(ramflux_storage::ContactGossipObservation {
        contact_identity_commitment: bob_identity_commitment,
        expected_lineage_head: lineage_head,
        reported_lineage_head: "conflicting-bob-lineage-head",
        change_event_id: "contact_gossip.conflict:carol:bob",
        seen_at: 1_760_000_500,
    })?;
    assert_eq!(changed.verification_state, "changed");
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp6_contact_safety_material(
    root: &ramflux_crypto::IdentityRoot,
    devices: &[ramflux_crypto::DeviceBranch],
    lineage_label: &str,
) -> ramflux_crypto::ContactSafetyMaterial {
    let identity_commitment = ramflux_crypto::blake3_256(
        "ramflux.mvp6.identity_commitment.v1",
        root.principal_id.as_bytes(),
    )
    .to_vec();
    let identity_key_hash = ramflux_crypto::blake3_256(
        "ramflux.mvp6.identity_key.v1",
        &root.signing_key.verifying_key().to_bytes(),
    )
    .to_vec();
    let lineage_head =
        ramflux_crypto::blake3_256("ramflux.mvp6.lineage_head.v1", lineage_label.as_bytes())
            .to_vec();
    let devices = devices
        .iter()
        .map(|device| {
            let verifying_key = device.signing_key.verifying_key().to_bytes();
            let device_label = format!("{}:{}", device.device_id, device.device_epoch);
            ramflux_crypto::DeviceSafetyMaterial {
                device_id_hash: ramflux_crypto::blake3_256(
                    "ramflux.mvp6.device_id.v1",
                    device.device_id.as_bytes(),
                )
                .to_vec(),
                device_identity_key_hash: ramflux_crypto::blake3_256(
                    "ramflux.mvp6.device_identity_key.v1",
                    &verifying_key,
                )
                .to_vec(),
                device_signing_key_hash: ramflux_crypto::blake3_256(
                    "ramflux.mvp6.device_signing_key.v1",
                    &verifying_key,
                )
                .to_vec(),
                device_x25519_identity_key_hash: ramflux_crypto::blake3_256(
                    "ramflux.mvp6.device_x25519_key.v1",
                    device_label.as_bytes(),
                )
                .to_vec(),
                device_epoch: device.device_epoch,
                branch_authorized_event_id: format!(
                    "device.branch_authorized:{}:{}",
                    device.device_id, device.device_epoch
                )
                .into_bytes(),
            }
        })
        .collect();
    ramflux_crypto::ContactSafetyMaterial {
        identity_commitment,
        identity_key_hash,
        lineage_head,
        devices,
    }
}
