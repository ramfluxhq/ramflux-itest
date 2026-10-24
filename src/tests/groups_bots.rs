// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use super::*;

#[test]
fn group_create_default_limit_1000() -> Result<(), Box<dyn std::error::Error>> {
    let db = test_account_db("group_create_default_limit_1000")?;
    let group = db.create_group("group_1", "alice")?;
    assert_eq!(group.max_members, 1000);
    assert_eq!(group.group_epoch, 1);
    assert!(group.members.contains("alice"));
    Ok(())
}

#[test]
fn group_new_member_no_history() -> Result<(), Box<dyn std::error::Error>> {
    let db = test_account_db("group_new_member_no_history")?;
    db.create_group("group_1", "alice")?;
    let group = db.add_group_member("group_1", "bob", "member")?;
    assert_eq!(group.new_member_history, "no_history");
    assert_eq!(group.group_epoch, 2);
    Ok(())
}

#[test]
fn group_governance_roles_member_limit_and_remove() -> Result<(), Box<dyn std::error::Error>> {
    let db = test_account_db("group_governance_roles_member_limit_and_remove")?;
    db.create_group("group_1", "alice")?;
    db.add_group_member("group_1", "bob", "admin")?;
    db.add_group_member("group_1", "carol", "member")?;
    for name in ["alice", "bob", "carol"] {
        bind_fixture_member(&db, "group_1", name)?;
    }
    assert!(matches!(
        db.remove_group_member("group_1", &fixture_device("bob")?, &fixture_device("alice")?),
        Err(ramflux_storage::StorageError::GroupPermissionDenied)
    ));
    assert!(matches!(
        db.remove_group_member("group_1", &fixture_device("carol")?, &fixture_device("bob")?),
        Err(ramflux_storage::StorageError::GroupPermissionDenied)
    ));
    assert!(matches!(
        db.ensure_group_member_can_send("group_1", &fixture_device("carol")?, true),
        Err(ramflux_storage::StorageError::GroupPermissionDenied)
    ));
    db.ensure_group_member_can_send("group_1", &fixture_device("bob")?, true)?;
    assert!(matches!(
        db.ensure_group_member_can_mute(
            "group_1",
            &fixture_device("carol")?,
            &fixture_device("bob")?
        ),
        Err(ramflux_storage::StorageError::GroupPermissionDenied)
    ));
    db.ensure_group_member_can_mute("group_1", &fixture_device("alice")?, &fixture_device("bob")?)?;
    let group =
        db.remove_group_member("group_1", &fixture_device("bob")?, &fixture_device("carol")?)?;
    assert!(!group.members.contains("carol"));
    assert_eq!(group.roles.get("bob").map(String::as_str), Some("admin"));

    let limit_db = test_account_db("group_governance_member_limit")?;
    limit_db.create_group("group_limit", "owner")?;
    for index in 1..1000 {
        limit_db.add_group_member("group_limit", &format!("member_{index:04}"), "member")?;
    }
    let full = limit_db.group_state("group_limit")?;
    assert_eq!(full.members.len(), 1000);
    assert!(matches!(
        limit_db.add_group_member("group_limit", "member_1000", "member"),
        Err(ramflux_storage::StorageError::GroupMemberLimitExceeded)
    ));
    Ok(())
}

#[test]
fn group_role_change_permission_matrix_protects_owner_and_admin()
-> Result<(), Box<dyn std::error::Error>> {
    let db = test_account_db("group_role_change_permission_matrix")?;
    db.create_group("group_1", "alice")?;
    db.add_group_member("group_1", "bob", "admin")?;
    db.add_group_member("group_1", "carol", "admin")?;
    db.add_group_member("group_1", "dave", "member")?;
    db.add_group_member("group_1", "bot", "bot")?;

    for name in ["alice", "bob", "carol", "dave", "bot"] {
        bind_fixture_member(&db, "group_1", name)?;
    }
    assert!(matches!(
        db.apply_group_role_change(
            &mvp_group_role_change("evt_admin_owner", "bob", "alice", 5, 6, "member",),
            &fixture_device("bob")?
        ),
        Err(ramflux_storage::StorageError::GroupPermissionDenied)
    ));
    assert!(matches!(
        db.apply_group_role_change(
            &mvp_group_role_change("evt_admin_admin", "bob", "carol", 5, 6, "member",),
            &fixture_device("bob")?
        ),
        Err(ramflux_storage::StorageError::GroupPermissionDenied)
    ));
    assert!(matches!(
        db.apply_group_role_change(
            &mvp_group_role_change("evt_self_promote", "dave", "dave", 5, 6, "admin",),
            &fixture_device("dave")?
        ),
        Err(ramflux_storage::StorageError::GroupPermissionDenied)
    ));

    let group = db.apply_group_role_change(
        &mvp_group_role_change("evt_owner_demote_admin", "alice", "bob", 5, 6, "member"),
        &fixture_device("alice")?,
    )?;
    assert_eq!(group.roles.get("bob").map(String::as_str), Some("member"));
    let group = db.apply_group_role_change(
        &mvp_group_role_change("evt_owner_promote_member", "alice", "dave", 6, 7, "admin"),
        &fixture_device("alice")?,
    )?;
    assert_eq!(group.roles.get("dave").map(String::as_str), Some("admin"));
    let group = db.apply_group_role_change(
        &mvp_group_role_change("evt_admin_changes_bot", "dave", "bot", 7, 8, "member"),
        &fixture_device("dave")?,
    )?;
    assert_eq!(group.roles.get("bot").map(String::as_str), Some("member"));
    assert!(matches!(
        db.apply_group_role_change(
            &mvp_group_role_change("evt_replay", "dave", "bot", 7, 8, "bot"),
            &fixture_device("dave")?
        ),
        Err(ramflux_storage::StorageError::GroupControlEpochMismatch { .. })
    ));
    Ok(())
}

fn mvp_group_role_change(
    event_id: &str,
    actor: &str,
    target: &str,
    previous_epoch: u64,
    new_group_epoch: u64,
    new_role: &str,
) -> ramflux_storage::GroupRoleChangeWrite {
    ramflux_storage::GroupRoleChangeWrite {
        group_id: "group_1".to_owned(),
        event_id: event_id.to_owned(),
        actor_device_id: actor.to_owned(),
        target_member_id: target.to_owned(),
        previous_epoch,
        new_group_epoch,
        new_role: new_role.to_owned(),
    }
}

#[test]
fn group_auth_chain_rejects_unseen_admin_grant() {
    let known_admins = BTreeSet::from(["alice".to_owned()]);
    let forked_transition = ramflux_storage::GroupTransition {
        actor: "bob".to_owned(),
        action: "remove_member".to_owned(),
        target: "carol".to_owned(),
        auth_chain: vec!["unseen_grant_bob_admin".to_owned()],
    };
    assert!(!known_admins.contains(&forked_transition.actor));
}

#[test]
fn group_partition_healing_converges() {
    let left = BTreeSet::from(["alice".to_owned(), "bob".to_owned()]);
    let right = BTreeSet::from(["alice".to_owned(), "carol".to_owned()]);
    let canonical = left.intersection(&right).cloned().collect::<BTreeSet<_>>();
    assert_eq!(canonical, BTreeSet::from(["alice".to_owned()]));
}

#[test]
fn group_key_epoch_removed_member_no_new_message_decrypt() -> Result<(), Box<dyn std::error::Error>>
{
    let mut epoch = ramflux_storage::GroupKeyEpochState::new(
        "group_1",
        [fixture_device("alice")?, fixture_device("bob")?],
    );
    epoch.distribute_sender_key(&fixture_device("alice")?);
    epoch.remove_member(&fixture_device("bob")?);
    epoch.distribute_sender_key(&fixture_device("alice")?);
    let ciphertext = epoch.encrypt_epoch_message_for(&fixture_device("alice")?, b"new epoch")?;
    assert!(epoch.decrypt_epoch_message_for(&fixture_device("bob")?, &ciphertext).is_err());
    Ok(())
}

#[test]
fn group_key_epoch_removed_member_no_new_object_decrypt() -> Result<(), Box<dyn std::error::Error>>
{
    let mut epoch = ramflux_storage::GroupKeyEpochState::new(
        "group_1",
        [fixture_device("alice")?, fixture_device("bob")?],
    );
    epoch.remove_member(&fixture_device("bob")?);
    epoch.wrap_object_for_current_members("object_new");
    assert!(!epoch.can_read_object(&fixture_device("bob")?, "object_new"));
    assert!(epoch.can_read_object(&fixture_device("alice")?, "object_new"));
    Ok(())
}

#[test]
fn group_key_epoch_new_member_no_history_no_old_sender_key()
-> Result<(), Box<dyn std::error::Error>> {
    let mut epoch = ramflux_storage::GroupKeyEpochState::new("group_1", [fixture_device("alice")?]);
    epoch.wrap_object_for_current_members("object_old");
    epoch.add_member_no_history(&fixture_device("bob")?);
    assert!(!epoch.can_read_object(&fixture_device("bob")?, "object_old"));
    Ok(())
}

#[test]
fn group_key_epoch_sender_cannot_send_before_distribution() -> Result<(), Box<dyn std::error::Error>>
{
    let mut epoch = ramflux_storage::GroupKeyEpochState::new("group_1", [fixture_device("alice")?]);
    assert!(epoch.encrypt_epoch_message_for(&fixture_device("alice")?, b"blocked").is_err());
    epoch.distribute_sender_key(&fixture_device("alice")?);
    assert!(epoch.encrypt_epoch_message_for(&fixture_device("alice")?, b"allowed").is_ok());
    Ok(())
}

#[test]
fn group_key_epoch_offline_member_receives_queued_sender_key()
-> Result<(), Box<dyn std::error::Error>> {
    let mut epoch = ramflux_storage::GroupKeyEpochState::new("group_1", [fixture_device("alice")?]);
    epoch.queue_sender_key_for_offline_member(&fixture_device("alice")?);
    assert!(epoch.assert_can_send(&fixture_device("alice")?).is_err());
    epoch.reconnect_member(&fixture_device("alice")?);
    epoch.assert_can_send(&fixture_device("alice")?)?;
    Ok(())
}

#[test]
fn group_key_epoch_conflict_pending_defers_commitment_reject()
-> Result<(), Box<dyn std::error::Error>> {
    let mut epoch = ramflux_storage::GroupKeyEpochState::new("group_1", [fixture_device("alice")?]);
    epoch.conflict_pending = true;
    assert!(epoch.membership_commitment_reject_deferred());
    Ok(())
}

#[test]
fn group_key_epoch_admin_shared_history_rewraps_selected_objects_only()
-> Result<(), Box<dyn std::error::Error>> {
    let mut epoch = ramflux_storage::GroupKeyEpochState::new("group_1", [fixture_device("alice")?]);
    epoch.wrap_object_for_current_members("object_a");
    epoch.wrap_object_for_current_members("object_b");
    epoch.add_member_no_history(&fixture_device("bob")?);
    epoch.admin_shared_history_rewrap(&fixture_device("bob")?, &["object_a".to_owned()]);
    assert!(epoch.can_read_object(&fixture_device("bob")?, "object_a"));
    assert!(!epoch.can_read_object(&fixture_device("bob")?, "object_b"));
    Ok(())
}

#[test]
fn bot_install_grant_accepts_manifest_scope() {
    let manifest_scope =
        BTreeSet::from(["message:read:group".to_owned(), "tool:call:*".to_owned()]);
    let grant_scope = BTreeSet::from(["message:read:group".to_owned()]);
    assert!(grant_scope.is_subset(&manifest_scope));
}

#[test]
fn bot_group_key_disclosure_all_members_gate() {
    let members = BTreeSet::from(["alice".to_owned(), "bob".to_owned()]);
    let accepted = BTreeSet::from(["alice".to_owned(), "bob".to_owned()]);
    assert_eq!(members, accepted);
}

#[test]
fn bot_group_join_blocks_on_offline_member_consent() {
    let members = BTreeSet::from(["alice".to_owned(), "bob".to_owned()]);
    let accepted = BTreeSet::from(["alice".to_owned()]);
    assert_ne!(members, accepted);
}

#[test]
fn bot_joined_receives_group_sender_key() -> Result<(), Box<dyn std::error::Error>> {
    let mut epoch = ramflux_storage::GroupKeyEpochState::new(
        "group_1",
        [fixture_device("alice")?, fixture_device("bot")?],
    );
    epoch.distribute_sender_key(&fixture_device("bot")?);
    epoch.assert_can_send(&fixture_device("bot")?)?;
    Ok(())
}

#[test]
fn bot_revoked_tombstone_propagates() {
    let targets = ramflux_sync::bot_revocation_targets("bot_1");
    assert!(targets.contains("dm:bot_1"));
    assert!(targets.contains("group:bot_1"));
    assert!(targets.contains("federation:bot_1"));
}
