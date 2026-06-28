// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use super::*;

fn object_test_branch(device_id: &str) -> ramflux_crypto::DeviceBranch {
    ramflux_crypto::create_device_branch("principal_object_test", device_id, 1, [0x7B; 32])
}

#[test]
fn object_encrypted_transfer() -> Result<(), Box<dyn std::error::Error>> {
    let mut store = ramflux_sync::ObjectStore::new();
    let object = store.put_encrypted_object("object_1", b"file-bytes")?;
    assert_ne!(object.ciphertext, b"file-bytes");
    assert_eq!(store.decrypt_object("object_1")?, b"file-bytes");
    Ok(())
}

#[test]
fn object_quinn_lan_same_account_sync() -> Result<(), Box<dyn std::error::Error>> {
    let mut first = ramflux_sync::ObjectStore::new();
    let mut second = ramflux_sync::ObjectStore::new();
    first.put_encrypted_object("object_1", b"lan-object")?;
    first.sync_to_peer("object_1", &mut second)?;
    assert_eq!(second.decrypt_object("object_1")?, b"lan-object");
    Ok(())
}

#[test]
fn object_chunk_resume_missing_bitmap() -> Result<(), Box<dyn std::error::Error>> {
    let ciphertext = b"aaabbbccc";
    let manifest =
        ramflux_sync::chunk_manifest_for_object("object_chunked", ciphertext, 3, Some(7));
    assert_eq!(manifest.total_chunks, 3);
    assert_eq!(manifest.object_created_group_key_epoch, Some(7));

    let content_key = [0xC7; 32];
    let branch = object_test_branch("device_object_resume");
    let mut receiver = ramflux_sync::ObjectSyncSession::new(manifest.clone(), content_key);
    let first = ramflux_sync::chunk_payload(&content_key, &manifest, 0, b"aaa");
    let third = ramflux_sync::chunk_payload(&content_key, &manifest, 2, b"ccc");
    let token_after_first = receiver.receive_chunk(first, &branch)?;
    assert_eq!(token_after_first.next_missing_chunk, Some(1));
    receiver.receive_chunk(third, &branch)?;
    let missing = receiver.missing_chunks();
    assert_eq!(missing.missing_indices, vec![1]);
    let resume = receiver.resume_token_with_device_branch(&branch)?;
    assert_eq!(resume.next_missing_chunk, Some(1));
    assert_eq!(resume.received_count, 2);

    let second = ramflux_sync::chunk_payload(&content_key, &manifest, 1, b"bbb");
    receiver.receive_chunk(second, &branch)?;
    assert!(receiver.is_complete());
    assert_eq!(receiver.missing_chunks().missing_indices, Vec::<u32>::new());
    assert_eq!(receiver.assemble()?, ciphertext);

    let mut tampered = ramflux_sync::chunk_payload(&content_key, &manifest, 0, b"aaa");
    tampered.ciphertext = b"zzz".to_vec();
    tampered.cipher_hash = "wrong".to_owned();
    let mut rejector = ramflux_sync::ObjectSyncSession::new(manifest, content_key);
    assert!(rejector.receive_chunk(tampered, &branch).is_err());
    Ok(())
}

#[test]
fn object_tombstone_propagation() -> Result<(), Box<dyn std::error::Error>> {
    let mut first = ramflux_sync::ObjectStore::new();
    let mut second = ramflux_sync::ObjectStore::new();
    first.put_encrypted_object("object_1", b"delete-me")?;
    first.sync_to_peer("object_1", &mut second)?;
    first.tombstone("object_1")?;
    second.apply_tombstone_from(&first, "object_1")?;
    assert!(second.decrypt_object("object_1").is_err());
    Ok(())
}

#[test]
fn object_backup_manifest_excludes_tombstoned_content() -> Result<(), Box<dyn std::error::Error>> {
    let mut store = ramflux_sync::ObjectStore::new();
    let live = store.put_encrypted_object("object_live", b"live")?;
    let deleted = store.put_encrypted_object("object_deleted", b"deleted")?;
    store.tombstone("object_deleted")?;

    let branch = object_test_branch("device_backup_a");
    let manifest = store.backup_manifest_with_device_branch(
        ramflux_sync::BackupManifestRequest {
            backup_id: "backup_1".to_owned(),
            source_device_id: "device_a".to_owned(),
            target_device_id: "device_b".to_owned(),
            principal_commitment: "principal_commitment".to_owned(),
            event_batch_heads: vec!["event_head_1".to_owned()],
            projection_checkpoint_hash: Some("projection_hash_1".to_owned()),
            created_at: 1_760_000_000,
        },
        &branch,
    )?;
    assert!(manifest.object_manifest_hashes.contains(&live.manifest_hash));
    assert!(!manifest.object_manifest_hashes.contains(&deleted.manifest_hash));
    assert_eq!(manifest.object_tombstone_heads.len(), 1);
    ramflux_sync::verify_backup_manifest(&manifest)?;
    Ok(())
}

#[test]
fn object_backup_manifest_excludes_short_term_transport_cache()
-> Result<(), Box<dyn std::error::Error>> {
    let mut store = ramflux_sync::ObjectStore::new();
    let durable = store.put_encrypted_object("object_durable", b"durable")?;
    let transient = store.put_short_term_transport_object("object_transient", b"transient")?;

    let branch = object_test_branch("device_backup_b");
    let manifest = store.backup_manifest_with_device_branch(
        ramflux_sync::BackupManifestRequest {
            backup_id: "backup_2".to_owned(),
            source_device_id: "device_a".to_owned(),
            target_device_id: "device_b".to_owned(),
            principal_commitment: "principal_commitment".to_owned(),
            event_batch_heads: Vec::new(),
            projection_checkpoint_hash: None,
            created_at: 1_760_000_010,
        },
        &branch,
    )?;
    assert!(manifest.object_manifest_hashes.contains(&durable.manifest_hash));
    assert!(!manifest.object_manifest_hashes.contains(&transient.manifest_hash));
    assert!(manifest.object_tombstone_heads.is_empty());
    Ok(())
}

#[test]
fn object_backup_manifest_import_records_checkpoint() -> Result<(), Box<dyn std::error::Error>> {
    let mut source = ramflux_sync::ObjectStore::new();
    source.put_encrypted_object("object_import_live", b"import-live")?;
    source.put_encrypted_object("object_import_deleted", b"import-deleted")?;
    source.tombstone("object_import_deleted")?;
    let target = ramflux_sync::ObjectStore::new();

    let branch = object_test_branch("device_backup_c");
    let manifest = source.backup_manifest_with_device_branch(
        ramflux_sync::BackupManifestRequest {
            backup_id: "backup_import_1".to_owned(),
            source_device_id: "device_source".to_owned(),
            target_device_id: "device_target".to_owned(),
            principal_commitment: "principal_import".to_owned(),
            event_batch_heads: vec!["event_head_1".to_owned(), "event_head_2".to_owned()],
            projection_checkpoint_hash: Some("projection_checkpoint_hash_1".to_owned()),
            created_at: 1_760_000_020,
        },
        &branch,
    )?;
    let checkpoint = target.import_backup_manifest(&manifest, 1_760_000_030)?;

    assert_eq!(checkpoint.backup_id, "backup_import_1");
    assert_eq!(checkpoint.source_device_id, "device_source");
    assert_eq!(checkpoint.target_device_id, "device_target");
    assert_eq!(checkpoint.principal_commitment, "principal_import");
    assert_eq!(checkpoint.event_batch_head_count, 2);
    assert_eq!(checkpoint.object_manifest_count, 1);
    assert_eq!(checkpoint.object_tombstone_count, 1);
    assert_eq!(
        checkpoint.projection_checkpoint_hash.as_deref(),
        Some("projection_checkpoint_hash_1")
    );
    assert_eq!(checkpoint.imported_at, 1_760_000_030);
    Ok(())
}

#[test]
fn object_backup_manifest_rejects_tampered_signature() -> Result<(), Box<dyn std::error::Error>> {
    let mut source = ramflux_sync::ObjectStore::new();
    source.put_encrypted_object("object_import_live", b"import-live")?;
    let target = ramflux_sync::ObjectStore::new();
    let branch = object_test_branch("device_backup_d");
    let mut manifest = source.backup_manifest_with_device_branch(
        ramflux_sync::BackupManifestRequest {
            backup_id: "backup_import_2".to_owned(),
            source_device_id: "device_source".to_owned(),
            target_device_id: "device_target".to_owned(),
            principal_commitment: "principal_import".to_owned(),
            event_batch_heads: Vec::new(),
            projection_checkpoint_hash: None,
            created_at: 1_760_000_040,
        },
        &branch,
    )?;
    manifest.object_manifest_hashes.push("tampered_manifest_hash".to_owned());

    assert!(target.import_backup_manifest(&manifest, 1_760_000_050).is_err());
    assert!(ramflux_sync::verify_backup_manifest(&manifest).is_err());
    Ok(())
}
