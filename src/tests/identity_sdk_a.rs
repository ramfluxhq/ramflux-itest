// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use super::*;

#[test]
fn multi_account_smoke() -> Result<(), Box<dyn std::error::Error>> {
    let root = temp_root("multi_account_smoke")?;
    let mut client = ramflux_sdk::RamfluxClient::new();
    client.open_account_index(&root)?;
    client.create_account("acct_a", "principal_commitment_a")?;
    client.create_account("acct_b", "principal_commitment_b")?;

    client.set_active_account("acct_a")?;
    client.unlock_account("acct_a", b"secret-a")?;
    client.append_event("evt_shared", "message.created", b"account-a")?;
    assert_eq!(client.event_body("evt_shared")?, Some(b"account-a".to_vec()));

    client.set_active_account("acct_b")?;
    client.unlock_account("acct_b", b"secret-b")?;
    assert_eq!(client.event_body("evt_shared")?, None);
    client.append_event("evt_shared", "message.created", b"account-b")?;
    assert_eq!(client.event_body("evt_shared")?, Some(b"account-b".to_vec()));

    client.set_active_account("acct_a")?;
    client.unlock_account("acct_a", b"secret-a")?;
    assert_eq!(client.event_body("evt_shared")?, Some(b"account-a".to_vec()));
    assert_eq!(client.active_account()?, Some("acct_a".to_owned()));
    Ok(())
}

#[test]
fn identity_create() -> Result<(), Box<dyn std::error::Error>> {
    let root = ramflux_crypto::create_identity_root("principal_a", [0x11; 32]);
    let device = ramflux_crypto::create_device_branch("principal_a", "device_a", 1, [0x22; 32]);
    let proof = ramflux_crypto::authorize_device_branch(
        &root,
        &device,
        "ramflux-node",
        vec!["device.delivery.bind".to_owned()],
        1_760_000_000,
        1_760_003_600,
    )?;

    ramflux_crypto::verify_branch_proof(
        &root.signing_key.verifying_key(),
        &proof,
        "ramflux-node",
        "device.delivery.bind",
        1_760_000_001,
    )?;
    assert_eq!(root.principal_id, "principal_a");
    assert_eq!(device.device_id, "device_a");
    assert_eq!(proof.device_epoch, 1);
    Ok(())
}

#[test]
fn identity_add_device() -> Result<(), Box<dyn std::error::Error>> {
    let root = ramflux_crypto::create_identity_root("principal_a", [0x31; 32]);
    let first = ramflux_crypto::create_device_branch("principal_a", "device_a", 1, [0x32; 32]);
    let second = ramflux_crypto::create_device_branch("principal_a", "device_b", 1, [0x33; 32]);
    let first_proof = ramflux_crypto::authorize_device_branch(
        &root,
        &first,
        "ramflux-node",
        vec!["device.delivery.bind".to_owned()],
        1_760_000_000,
        1_760_003_600,
    )?;
    let second_proof = ramflux_crypto::authorize_device_branch(
        &root,
        &second,
        "ramflux-node",
        vec!["device.delivery.bind".to_owned(), "own_device.sync".to_owned()],
        1_760_000_100,
        1_760_003_700,
    )?;

    ramflux_crypto::verify_branch_proof(
        &root.signing_key.verifying_key(),
        &first_proof,
        "ramflux-node",
        "device.delivery.bind",
        1_760_000_101,
    )?;
    ramflux_crypto::verify_branch_proof(
        &root.signing_key.verifying_key(),
        &second_proof,
        "ramflux-node",
        "own_device.sync",
        1_760_000_101,
    )?;
    assert_ne!(first_proof.proof_id, second_proof.proof_id);
    assert_eq!(second_proof.device_id, "device_b");
    Ok(())
}

#[test]
fn account_unlock_sqlcipher() -> Result<(), Box<dyn std::error::Error>> {
    let root = temp_root("account_unlock_sqlcipher")?;
    let index = AccountIndex::open(&root)?;
    index.create_account("acct_a", "principal_commitment_a")?;
    let key_a = AccountDbKey::derive("acct_a", b"secret-a");
    let mut db = AccountDb::open(&index, "acct_a", &key_a)?;
    assert_eq!(db.encryption_mode(), EncryptionMode::SqlCipher);
    db.append_event("evt_a", "identity.created", br#"{"ok":true}"#)?;
    assert_eq!(db.event_body("evt_a")?, Some(br#"{"ok":true}"#.to_vec()));
    db.set_projection_checkpoint("conversation", "evt_a")?;
    assert_eq!(db.projection_checkpoint("conversation")?, Some("evt_a".to_owned()));

    let key_b = AccountDbKey::derive("acct_a", b"secret-b");
    db.rekey(&key_b)?;
    drop(db);
    assert!(AccountDb::open(&index, "acct_a", &key_a).is_err());
    let reopened = AccountDb::open(&index, "acct_a", &key_b)?;
    assert_eq!(reopened.event_body("evt_a")?, Some(br#"{"ok":true}"#.to_vec()));
    Ok(())
}

#[test]
fn multi_account_switch() -> Result<(), Box<dyn std::error::Error>> {
    let root = temp_root("multi_account_switch")?;
    let index = AccountIndex::open(&root)?;
    index.create_account("acct_a", "principal_commitment_a")?;
    index.create_account("acct_b", "principal_commitment_b")?;

    assert_eq!(index.active_account()?, None);
    index.set_active_account("acct_a")?;
    assert_eq!(index.active_account()?, Some("acct_a".to_owned()));
    index.set_active_account("acct_b")?;
    assert_eq!(index.active_account()?, Some("acct_b".to_owned()));
    assert!(index.set_active_account("missing").is_err());
    Ok(())
}

#[test]
fn multi_account_db_isolation() -> Result<(), Box<dyn std::error::Error>> {
    let root = temp_root("multi_account_db_isolation")?;
    let index = AccountIndex::open(&root)?;
    index.create_account("acct_a", "principal_commitment_a")?;
    index.create_account("acct_b", "principal_commitment_b")?;
    let key_a = AccountDbKey::derive("acct_a", b"shared-secret");
    let key_b = AccountDbKey::derive("acct_b", b"shared-secret");
    let db_a = AccountDb::open(&index, "acct_a", &key_a)?;
    let db_b = AccountDb::open(&index, "acct_b", &key_b)?;

    assert_eq!(db_a.encryption_mode(), EncryptionMode::SqlCipher);
    assert_eq!(db_b.encryption_mode(), EncryptionMode::SqlCipher);
    assert_ne!(db_a.path, db_b.path);
    assert_ne!(key_a.fingerprint(), key_b.fingerprint());
    db_a.append_event("evt_shared_name", "message.created", b"account-a")?;
    assert_eq!(db_a.event_body("evt_shared_name")?, Some(b"account-a".to_vec()));
    assert_eq!(db_b.event_body("evt_shared_name")?, None);
    Ok(())
}

#[test]
fn identity_lifecycle_deactivate_reactivate_projection() -> Result<(), Box<dyn std::error::Error>> {
    let root = temp_root("identity_lifecycle_deactivate_reactivate_projection")?;
    let mut client = ramflux_sdk::RamfluxClient::new();
    client.open_account_index(&root)?;
    client.create_account("acct_lifecycle", "principal_lifecycle")?;
    client.set_active_account("acct_lifecycle")?;
    client.unlock_account("acct_lifecycle", b"lifecycle-secret")?;

    let deactivated = client.apply_identity_lifecycle_event(
        "principal_lifecycle",
        "evt_identity_deactivated",
        "identity.deactivated",
        2,
        ramflux_storage::IdentityLifecycleTiming {
            reason_code: Some("user_requested"),
            timelock_until: Some(1_760_086_400),
            updated_at: 1_760_000_000,
            ..ramflux_storage::IdentityLifecycleTiming::default()
        },
    )?;
    assert_eq!(deactivated.lifecycle_state, "deactivated");
    assert!(
        client
            .send_direct_message(
                "conversation_lifecycle",
                "msg_blocked",
                "principal_lifecycle",
                b"x"
            )
            .is_err()
    );

    let reactivated = client.apply_identity_lifecycle_event(
        "principal_lifecycle",
        "evt_identity_reactivated",
        "identity.reactivated",
        3,
        ramflux_storage::IdentityLifecycleTiming {
            updated_at: 1_760_000_100,
            ..Default::default()
        },
    )?;
    assert_eq!(reactivated.lifecycle_state, "active");
    client.send_direct_message(
        "conversation_lifecycle",
        "msg_after_reactivate",
        "principal_lifecycle",
        b"ciphertext",
    )?;
    let lifecycle = client
        .identity_lifecycle("principal_lifecycle")?
        .ok_or_else(|| "missing lifecycle projection".to_owned())?;
    assert_eq!(lifecycle.causal_event_id, "evt_identity_reactivated");
    assert_eq!(lifecycle.lifecycle_epoch, 3);
    Ok(())
}

#[test]
fn identity_deleted_blocks_new_delivery() -> Result<(), Box<dyn std::error::Error>> {
    let root = temp_root("identity_deleted_blocks_new_delivery")?;
    let mut client = ramflux_sdk::RamfluxClient::new();
    client.open_account_index(&root)?;
    client.create_account("acct_deleted", "principal_deleted")?;
    client.set_active_account("acct_deleted")?;
    client.unlock_account("acct_deleted", b"deleted-secret")?;
    client.send_direct_message(
        "conversation_deleted",
        "msg_before_delete",
        "principal_deleted",
        b"ok",
    )?;

    let deleted = client.apply_identity_lifecycle_event(
        "principal_deleted",
        "evt_identity_deleted",
        "identity.deleted",
        7,
        ramflux_storage::IdentityLifecycleTiming {
            reason_code: Some("user_requested"),
            grace_window_until: Some(1_762_592_000),
            finalization_time: Some(1_762_592_001),
            updated_at: 1_762_592_001,
            ..ramflux_storage::IdentityLifecycleTiming::default()
        },
    )?;
    assert_eq!(deleted.lifecycle_state, "deleted");
    assert!(
        client
            .send_direct_message(
                "conversation_deleted",
                "msg_after_delete",
                "principal_deleted",
                b"blocked"
            )
            .is_err()
    );
    let projection = client.conversation_projection("conversation_deleted", "principal_deleted")?;
    assert_eq!(projection.message_count, 1);
    Ok(())
}

#[test]
fn sdk_facade_account_message_projection() -> Result<(), Box<dyn std::error::Error>> {
    let root = temp_root("sdk_facade_account_message_projection")?;
    let mut client = ramflux_sdk::RamfluxClient::new();
    client.create_identity_root("principal_sdk", [0x81; 32]);
    client.create_device_branch("principal_sdk", "device_sdk", 1, [0x82; 32]);
    let proof = client.authorize_current_device(
        "ramflux-node",
        vec!["device.delivery.bind".to_owned()],
        1_760_000_000,
        1_760_003_600,
    )?;
    assert_eq!(proof.device_id, "device_sdk");

    client.open_account_index(&root)?;
    client.create_account("acct_sdk", "principal_commitment_sdk")?;
    client.set_active_account("acct_sdk")?;
    assert_eq!(client.active_account()?, Some("acct_sdk".to_owned()));
    client.unlock_account("acct_sdk", b"sdk-secret")?;
    client.append_event("evt_sdk", "message.created", b"opaque")?;
    assert_eq!(client.event_body("evt_sdk")?, Some(b"opaque".to_vec()));
    client.set_projection_checkpoint("conversation", "evt_sdk")?;
    assert_eq!(client.projection_checkpoint("conversation")?, Some("evt_sdk".to_owned()));

    client.establish_friend_link("link_sdk", "alice", "bob")?;
    client.send_direct_message("conversation_sdk", "message_sdk", "alice", b"ciphertext")?;
    client.mark_read("conversation_sdk", "bob", "message_sdk")?;
    let projection = client.conversation_projection("conversation_sdk", "bob")?;
    assert_eq!(projection.message_count, 1);
    assert_eq!(projection.read_through_message_id, Some("message_sdk".to_owned()));
    Ok(())
}

#[test]
fn sdk_facade_object_mcp_a2ui() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = ramflux_sdk::RamfluxClient::new();
    let object = client.put_encrypted_object("object_sdk", b"sdk object")?;
    assert_ne!(object.ciphertext, b"sdk object");
    assert_eq!(client.decrypt_object("object_sdk")?, b"sdk object");

    client.install_mcp_tool(ramflux_sync::McpToolManifest {
        server_id: "srv".to_owned(),
        tool_name: "search".to_owned(),
        capability: ramflux_sync::McpCapability::ReadConversation,
        tool_scope: Some("search".to_owned()),
        declared_risk: ramflux_sync::RiskLevel::Low,
        manifest_version: 1,
    });
    let grant = ramflux_sync::McpGrantState {
        server_id: "srv".to_owned(),
        tool_name: "search".to_owned(),
        tool_scope: Some("search".to_owned()),
        registry_hash: client.mcp_registry_hash().to_owned(),
        tool_manifest_set_hash: client.mcp_tool_manifest_set_hash().to_owned(),
        full_delegation: false,
        allowed_capabilities: BTreeSet::from([ramflux_sync::McpCapability::ReadConversation]),
        revoked: false,
        expires_at: 4_000_000_000,
    };
    assert_eq!(client.invoke_mcp_tool("srv", "search", &grant)?, "srv:search");

    let rendered = client.render_a2ui_surface(
        &a2ui_surface("button"),
        &BTreeSet::from(["ramflux.mvp".to_owned()]),
        &BTreeSet::from(["message:send".to_owned()]),
    )?;
    assert!(rendered.semantic_snapshot.contains("surface_1"));
    Ok(())
}

#[test]
fn sdk_facade_federation_delivery() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = ramflux_sdk::RamfluxClient::new();
    client.register_node("node_a.example", "https://node-a.example");
    client.register_node("node_b.example", "https://node-b.example");
    client.establish_trusted_link("node_a.example", "node_b.example")?;
    client.bind_identity_home("alice", "node_a.example")?;
    client.bind_identity_home("bob", "node_b.example")?;
    let message = client.send_cross_node_message("alice", "bob", b"sdk federation")?;
    assert_eq!(message.via_node, "node_b.example");
    assert_eq!(message.body_ciphertext, b"sdk federation");
    Ok(())
}

#[test]
fn key_verification_safety_number_qr_fixture() {
    let alice = safety_material("alice", 1);
    let bob = safety_material("bob", 1);
    let alice_bob = ramflux_crypto::safety_number(&alice, &bob);
    let bob_alice = ramflux_crypto::safety_number(&bob, &alice);
    assert_eq!(alice_bob, bob_alice);
    assert_eq!(alice_bob.len(), 12);
    assert!(alice_bob.iter().all(|group| group.len() == 5));
}

#[test]
fn key_verification_key_change_warning_required() {
    let alice = safety_material("alice", 1);
    let bob_before = safety_material("bob", 1);
    let bob_after = safety_material("bob", 2);
    let before = ramflux_crypto::safety_fingerprint(&alice, &bob_before);
    let after = ramflux_crypto::safety_fingerprint(&alice, &bob_after);
    assert_ne!(before, after);
}

#[test]
fn key_verification_state_changes_on_device_set_mismatch() -> Result<(), Box<dyn std::error::Error>>
{
    let root = temp_root("key_verification_state_changes_on_device_set_mismatch")?;
    let index = AccountIndex::open(root)?;
    index.create_account("alice_verify", "alice_verify")?;
    let key = AccountDbKey::derive("alice_verify", b"alice-verify-secret");
    let db = AccountDb::open(&index, "alice_verify", &key)?;
    let alice = safety_material("alice", 1);
    let bob_before = safety_material("bob", 1);
    let bob_after = safety_material("bob", 2);

    let verified = db.mark_contact_verified(ramflux_storage::ContactVerificationUpdate {
        contact_identity_commitment: &safety_hash_text(&bob_before.identity_commitment),
        safety_number_hash: &safety_hash_text(&ramflux_crypto::safety_fingerprint(
            &alice,
            &bob_before,
        )),
        device_set_hash: &safety_hash_text(&ramflux_crypto::device_set_hash(&bob_before.devices)),
        lineage_head: &safety_hash_text(&bob_before.lineage_head),
        verified_at: 1_760_000_000,
        verified_by_device_id: "alice_device_verify",
    })?;
    assert_eq!(verified.verification_state, "verified");

    let changed = db.observe_contact_key_state(ramflux_storage::ContactKeyObservation {
        contact_identity_commitment: &verified.contact_identity_commitment,
        safety_number_hash: &safety_hash_text(&ramflux_crypto::safety_fingerprint(
            &alice, &bob_after,
        )),
        device_set_hash: &safety_hash_text(&ramflux_crypto::device_set_hash(&bob_after.devices)),
        lineage_head: &safety_hash_text(&bob_after.lineage_head),
        change_event_id: "device.branch_authorized:bob:2",
        seen_at: 1_760_000_100,
    })?;
    assert_eq!(changed.verification_state, "changed");
    assert_eq!(changed.last_change_event_id.as_deref(), Some("device.branch_authorized:bob:2"));
    Ok(())
}

#[test]
fn key_verification_kt_inclusion_consistency_proof() -> Result<(), Box<dyn std::error::Error>> {
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

    let mut tampered_inclusion = fixture.bob_inclusion_proof_v1.clone();
    tampered_inclusion.audit_path[0][0] ^= 0x01;
    assert!(
        ramflux_crypto::verify_kt_inclusion_proof(
            fixture.bob_leaf_v1_hash,
            &tampered_inclusion,
            &log_public_key,
        )
        .is_err()
    );

    let rollback = ramflux_crypto::KtConsistencyProof {
        old_tree_head: fixture.new_tree_head.clone(),
        new_tree_head: fixture.old_tree_head.clone(),
        old_leaf_hashes: fixture.new_leaf_hashes.clone(),
        appended_leaf_hashes: Vec::new(),
    };
    assert!(ramflux_crypto::verify_kt_consistency_proof(&rollback, &log_public_key).is_err());
    Ok(())
}
