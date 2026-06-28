// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use crate::*;

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn deliver_mvp4_group_partition_gossip(
    delivery: Mvp4GroupPartitionGossipDelivery<'_>,
) -> Result<Mvp4DeliveredGroupPartitionGossip, Box<dyn std::error::Error>> {
    let Mvp4GroupPartitionGossipDelivery {
        gateway_url,
        mesh,
        envelope_id,
        target_delivery_id,
        sender_session,
        receiver_session,
        associated_data,
        from_identity,
        to_identity,
        checkpoint,
    } = delivery;
    let plaintext = serde_json::to_vec(checkpoint)?;
    let ciphertext = sender_session.encrypt(&plaintext, associated_data)?;
    let ciphertext_json = serde_json::to_vec(&ciphertext)?;
    let routed = mesh.send_cross_node_message(from_identity, to_identity, &ciphertext_json)?;
    assert_eq!(routed.body_ciphertext, ciphertext_json);

    let delivered = deliver_mvp1_dm(gateway_url, envelope_id, target_delivery_id, &ciphertext)?;
    assert_eq!(delivered.target_delivery_id, target_delivery_id);
    assert_node_opaque_payload(
        &delivered.envelope.encrypted_payload,
        checkpoint.group_id.as_bytes(),
    );
    assert_node_opaque_payload(
        &delivered.envelope.encrypted_payload,
        checkpoint.lineage_head.as_bytes(),
    );
    assert_node_opaque_payload(&delivered.envelope.encrypted_payload, routed.via_node.as_bytes());
    let delivered_ciphertext: ramflux_crypto::DmCiphertext =
        serde_json::from_str(&delivered.envelope.encrypted_payload)?;
    let decrypted = receiver_session.decrypt(&delivered_ciphertext, associated_data)?;
    let checkpoint = serde_json::from_slice(&decrypted)?;
    Ok(Mvp4DeliveredGroupPartitionGossip { via_node: routed.via_node, checkpoint })
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn deliver_mvp4_cross_node_dm(
    delivery: Mvp4CrossNodeDmDelivery<'_>,
) -> Result<Mvp4DeliveredDm, Box<dyn std::error::Error>> {
    let Mvp4CrossNodeDmDelivery {
        gateway_url,
        mesh,
        envelope_id,
        target_delivery_id,
        sender_session,
        receiver_session,
        from_identity,
        to_identity,
        plaintext,
    } = delivery;
    let ciphertext = sender_session.encrypt(plaintext, b"alice_device|bob_device")?;
    let ciphertext_json = serde_json::to_vec(&ciphertext)?;
    let routed = mesh.send_cross_node_message(from_identity, to_identity, &ciphertext_json)?;
    assert_ne!(routed.via_node, "node_a.realnet");
    assert_eq!(routed.body_ciphertext, ciphertext_json);

    let delivered = deliver_mvp1_dm(gateway_url, envelope_id, target_delivery_id, &ciphertext)?;
    assert_eq!(delivered.target_delivery_id, target_delivery_id);
    assert_node_opaque_payload(&delivered.envelope.encrypted_payload, plaintext);
    assert_node_opaque_payload(&delivered.envelope.encrypted_payload, routed.via_node.as_bytes());

    let delivered_ciphertext: ramflux_crypto::DmCiphertext =
        serde_json::from_str(&delivered.envelope.encrypted_payload)?;
    let decrypted = receiver_session.decrypt(&delivered_ciphertext, b"alice_device|bob_device")?;
    Ok(Mvp4DeliveredDm { via_node: routed.via_node, decrypted_plaintext: decrypted })
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn deliver_mvp4_new_device_backfill(
    gateway_url: &str,
    sender_session: &mut ramflux_crypto::DmSession,
    receiver_session: &mut ramflux_crypto::DmSession,
) -> Result<ramflux_storage::AccountDb, Box<dyn std::error::Error>> {
    let old_root = temp_root("mvp4_realnet_home_node_migration_backfill_old")?;
    let new_root = temp_root("mvp4_realnet_home_node_migration_backfill_new")?;
    let old_index = ramflux_storage::AccountIndex::open(&old_root)?;
    let new_index = ramflux_storage::AccountIndex::open(&new_root)?;
    old_index.create_account("bob_old_mvp4", "bob_realnet")?;
    new_index.create_account("bob_new_mvp4", "bob_realnet")?;
    let old_key = ramflux_storage::AccountDbKey::derive("bob_old_mvp4", b"bob-old-mvp4");
    let new_key = ramflux_storage::AccountDbKey::derive("bob_new_mvp4", b"bob-new-mvp4");
    let bob_old_device =
        ramflux_crypto::create_device_branch("bob_realnet", "bob_device_realnet", 1, [0x44; 32]);
    let old_db = ramflux_storage::AccountDb::open(&old_index, "bob_old_mvp4", &old_key)?
        .with_device_signer(bob_old_device);
    let new_db = ramflux_storage::AccountDb::open(&new_index, "bob_new_mvp4", &new_key)?;
    ramflux_storage::EventStore::append_event(
        &old_db,
        "evt_mvp4_identity",
        "identity.home_node_migrated",
        b"identity-event",
    )?;
    ramflux_storage::EventStore::append_event(
        &old_db,
        "evt_mvp4_message",
        "message.created",
        b"message-event",
    )?;
    ramflux_storage::ProjectionStore::set_projection_checkpoint(
        &old_db,
        "conversation",
        "evt_mvp4_message",
    )?;
    let bundle =
        old_db.export_history_bundle("bob_device_realnet", "bob_new_device_mvp4_realnet")?;
    let bundle_bytes = serde_json::to_vec(&bundle)?;
    let relay = ramflux_sync::ObjectStore::new().relay_history_bundle(&bundle_bytes);
    assert!(!relay.plaintext_visible);
    assert!(!relay.ciphertext_hash.is_empty());

    let ciphertext = sender_session.encrypt(&bundle_bytes, b"alice_device|bob_device")?;
    let delivered = deliver_mvp1_dm(
        gateway_url,
        "env_mvp4_new_device_backfill",
        "bob_new_target_mvp4_realnet",
        &ciphertext,
    )?;
    assert_node_opaque_payload(&delivered.envelope.encrypted_payload, b"identity-event");
    assert_node_opaque_payload(&delivered.envelope.encrypted_payload, b"message-event");
    assert_node_opaque_payload(
        &delivered.envelope.encrypted_payload,
        bundle.checkpoint_hash.as_bytes(),
    );
    let delivered_ciphertext: ramflux_crypto::DmCiphertext =
        serde_json::from_str(&delivered.envelope.encrypted_payload)?;
    let decrypted = receiver_session.decrypt(&delivered_ciphertext, b"alice_device|bob_device")?;
    let imported_bundle: ramflux_storage::HistoryBundle = serde_json::from_slice(&decrypted)?;
    new_db.import_history_bundle(&imported_bundle)?;
    Ok(new_db)
}
