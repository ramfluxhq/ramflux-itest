// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use crate::*;

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn realnet_node_signing_seed(node_id: &str) -> [u8; 32] {
    ramflux_crypto::blake3_256("ramflux.itest.realnet.federation_node_key.v1", node_id.as_bytes())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn realnet_node_public_key(node_id: &str) -> String {
    ramflux_crypto::public_key_base64url_from_seed(realnet_node_signing_seed(node_id))
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn realnet_now_u64() -> u64 {
    u64::try_from(itest_now_unix_seconds()).unwrap_or(0)
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn realnet_now_i64() -> i64 {
    itest_now_unix_seconds()
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn realnet_route_expires_at(now: u64) -> u64 {
    now.saturating_add(86_400)
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn publish_mvp4_named_federation_route(
    federation_url: &str,
    node_id: &str,
    trust_status: ramflux_node_core::FederationTrustStatus,
) -> Result<Mvp4FederationCanDeliverResponse, Box<dyn std::error::Error>> {
    let response: Mvp4FederationCanDeliverResponse = ramflux_node_core::itest_http_post_json(
        &format!("{federation_url}/mvp4/federation/route"),
        &mvp4_federation_route(node_id, trust_status),
    )?;
    assert_eq!(response.node_id, node_id);
    Ok(response)
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn set_mvp4_federation_route_status(
    federation_url: &str,
    node_id: &str,
    trust_status: ramflux_node_core::FederationTrustStatus,
) -> Result<Mvp4FederationCanDeliverResponse, Box<dyn std::error::Error>> {
    let response: Mvp4FederationCanDeliverResponse = ramflux_node_core::itest_http_post_json(
        &format!("{federation_url}/mvp4/federation/trust-status"),
        &Mvp4FederationTrustStatusRequest {
            node_id: node_id.to_owned(),
            trust_status,
            updated_at: realnet_now_u64(),
        },
    )?;
    assert_eq!(response.node_id, node_id);
    Ok(response)
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp4_federation_route(
    node_id: &str,
    trust_status: ramflux_node_core::FederationTrustStatus,
) -> ramflux_node_core::FederationPeerRoute {
    let now = realnet_now_u64();
    let node_public_key = realnet_node_public_key(node_id);
    ramflux_node_core::FederationPeerRoute {
        node_id: node_id.to_owned(),
        endpoint: format!("https://{node_id}/federation"),
        node_public_key_hash: ramflux_crypto::blake3_256_base64url(
            ramflux_protocol::domain::FEDERATION_HANDSHAKE,
            node_public_key.as_bytes(),
        ),
        node_capabilities: vec!["opaque_delivery".to_owned()],
        trust_status,
        updated_at: now,
        expires_at: realnet_route_expires_at(now),
        route_update_proof_hash: "route_update_proof_hash_mvp4_realnet".to_owned(),
    }
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp4_can_deliver(
    federation_url: &str,
    node_id: &str,
) -> Result<Mvp4FederationCanDeliverResponse, Box<dyn std::error::Error>> {
    Ok(ramflux_node_core::itest_http_get_json(&format!(
        "{federation_url}/mvp4/federation/can-deliver/{node_id}"
    ))?)
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp4_bob_new_device_register()
-> Result<ramflux_node_core::ItestMvp1RegisterIdentityRequest, Box<dyn std::error::Error>> {
    let bob_root = ramflux_crypto::create_identity_root("bob_realnet", [0x43; 32]);
    let bob_new_device = ramflux_crypto::create_device_branch(
        "bob_realnet",
        "bob_new_device_mvp4_realnet",
        2,
        [0x85; 32],
    );
    mvp1_named_register_request(
        &bob_root,
        &bob_new_device,
        "bob_new_target_mvp4_realnet",
        "bob_new_session_mvp4_realnet",
        41,
    )
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp4_partition_carol_fixture()
-> Result<Mvp4PartitionMemberFixture, Box<dyn std::error::Error>> {
    let carol_root = ramflux_crypto::create_identity_root("carol_realnet", [0x86; 32]);
    let carol_device = ramflux_crypto::create_device_branch(
        "carol_realnet",
        "carol_device_mvp4_realnet",
        1,
        [0x87; 32],
    );
    let register = mvp1_named_register_request(
        &carol_root,
        &carol_device,
        "carol_target_mvp4_partition_realnet",
        "carol_session_mvp4_partition_realnet",
        42,
    )?;
    let identity = ramflux_crypto::X25519KeyPair::from_seed([0x88; 32]);
    let signed_prekey = ramflux_crypto::X25519KeyPair::from_seed([0x89; 32]);
    let prekey_bundle = ramflux_crypto::create_prekey_bundle(
        &carol_device,
        &identity,
        "spk_carol_mvp4_partition_realnet",
        &signed_prekey,
        None,
        None,
    )?;
    Ok(Mvp4PartitionMemberFixture { register, identity, signed_prekey, prekey_bundle })
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp4_partition_realnet_context(
    gateway_url: &str,
    federation_url: &str,
) -> Result<Mvp4PartitionRealnetContext, Box<dyn std::error::Error>> {
    let fixture = mvp1_dm_realnet_fixture()?;
    let carol = mvp4_partition_carol_fixture()?;
    register_mvp1_identity(gateway_url, &fixture.bob_register)?;
    publish_mvp1_prekey(gateway_url, "bob_device_realnet", &fixture.bob_prekey_bundle)?;
    register_mvp1_identity(gateway_url, &fixture.alice_register)?;
    register_mvp1_identity(gateway_url, &carol.register)?;
    publish_mvp1_prekey(gateway_url, "carol_device_mvp4_realnet", &carol.prekey_bundle)?;

    let fetched_bob: ramflux_node_core::ItestMvp1PrekeyResponse =
        ramflux_node_core::itest_http_get_json(&format!(
            "{gateway_url}/mvp1/prekey/bob_device_realnet"
        ))?;
    let bob_bundle = fetched_bob.bundle.ok_or("missing bob prekey bundle")?;
    let (alice_to_bob, bob_receiver) = establish_mvp1_dm_sessions(&fixture, &bob_bundle)?;
    let fetched_carol: ramflux_node_core::ItestMvp1PrekeyResponse =
        ramflux_node_core::itest_http_get_json(&format!(
            "{gateway_url}/mvp1/prekey/carol_device_mvp4_realnet"
        ))?;
    let carol_bundle = fetched_carol.bundle.ok_or("missing carol prekey bundle")?;
    let (alice_to_carol, carol_receiver) =
        establish_mvp3_pairwise_sessions(Mvp3PairwiseSessionInput {
            initiator_identity: &fixture.alice_identity,
            initiator_ephemeral_seed: [0x94; 32],
            recipient_bundle: &carol_bundle,
            recipient_identity: &carol.identity,
            recipient_signed_prekey: &carol.signed_prekey,
            associated_data: b"alice_device|carol_device",
            session_label: "mvp4-realnet-alice-carol-group-gossip",
        })?;

    let mut mesh = ramflux_sync::FederationMesh::new();
    mesh.register_node("node_a.realnet", "https://node-a.realnet/federation");
    mesh.register_node("node_b.realnet", "https://node-b.realnet/federation");
    mesh.register_node("node_c.realnet", "https://node-c.realnet/federation");
    mesh.establish_trusted_link("node_a.realnet", "node_b.realnet")?;
    mesh.establish_trusted_link("node_a.realnet", "node_c.realnet")?;
    mesh.bind_identity_home("alice_realnet", "node_a.realnet")?;
    mesh.bind_identity_home("bob_realnet", "node_b.realnet")?;
    mesh.bind_identity_home("carol_realnet", "node_c.realnet")?;
    let bob_route = publish_mvp4_named_federation_route(
        federation_url,
        "node_b.realnet",
        ramflux_node_core::FederationTrustStatus::Active,
    )?;
    assert!(bob_route.can_deliver);
    let carol_route = publish_mvp4_named_federation_route(
        federation_url,
        "node_c.realnet",
        ramflux_node_core::FederationTrustStatus::Active,
    )?;
    assert!(carol_route.can_deliver);

    Ok(Mvp4PartitionRealnetContext {
        mesh,
        alice_to_bob,
        bob_receiver,
        alice_to_carol,
        carol_receiver,
    })
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp4_home_node_migration_steps() -> Vec<Mvp4MigrationStep> {
    vec![
        Mvp4MigrationStep { step_number: 1, name: "prepare_new_home" },
        Mvp4MigrationStep { step_number: 2, name: "bind_new_device_delivery" },
        Mvp4MigrationStep { step_number: 3, name: "sign_home_node_migration_proof" },
        Mvp4MigrationStep { step_number: 4, name: "publish_new_home_route" },
        Mvp4MigrationStep { step_number: 5, name: "mark_old_home_migrated" },
        Mvp4MigrationStep { step_number: 6, name: "notify_contacts" },
        Mvp4MigrationStep { step_number: 7, name: "forward_or_nack_old_home" },
        Mvp4MigrationStep { step_number: 8, name: "lazy_reresolve_sender" },
        Mvp4MigrationStep { step_number: 9, name: "encrypted_new_device_backfill" },
        Mvp4MigrationStep { step_number: 10, name: "checkpoint_cutover_complete" },
    ]
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp4_partition_transition(
    event_id: &str,
    actor_device_id: &str,
    action: &str,
    target_member: &str,
    lamport_time: u64,
) -> Mvp4GroupPartitionTransition {
    Mvp4GroupPartitionTransition {
        event_id: event_id.to_owned(),
        actor_device_id: actor_device_id.to_owned(),
        action: action.to_owned(),
        target_member: target_member.to_owned(),
        auth_chain_depth: 1,
        lamport_time,
        auth_chain: vec!["evt_group_created_mvp4_partition".to_owned()],
    }
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp4_partition_message(
    message_id: &str,
    sender: &str,
    message_created_group_key_epoch: u64,
) -> Mvp4GroupPartitionMessage {
    Mvp4GroupPartitionMessage {
        message_id: message_id.to_owned(),
        sender: sender.to_owned(),
        message_created_group_key_epoch,
        body_hash: ramflux_crypto::blake3_256_base64url(
            ramflux_protocol::domain::MESSAGE_EVENT,
            message_id.as_bytes(),
        ),
    }
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp4_partition_checkpoint(
    input: Mvp4PartitionCheckpointInput,
) -> Result<Mvp4GroupPartitionCheckpoint, Box<dyn std::error::Error>> {
    let mut checkpoint = Mvp4GroupPartitionCheckpoint {
        event_type: "group.partition_checkpoint.gossip".to_owned(),
        group_id: "group_mvp4_partition_realnet".to_owned(),
        partition_id: input.partition_id.to_owned(),
        observed_group_epoch: 2,
        observed_sender_key_epoch: 2,
        members: input.members,
        transitions: input.transitions,
        messages: input.messages,
        lineage_head: String::new(),
    };
    checkpoint.lineage_head = mvp4_group_lineage_head(
        &checkpoint.group_id,
        checkpoint.observed_group_epoch,
        checkpoint.observed_sender_key_epoch,
        &checkpoint.members,
        &checkpoint.transitions,
        &checkpoint.messages,
    )?;
    Ok(checkpoint)
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp4_partition_divergent_checkpoints()
-> Result<(Mvp4GroupPartitionCheckpoint, Mvp4GroupPartitionCheckpoint), Box<dyn std::error::Error>>
{
    let left = mvp4_partition_checkpoint(Mvp4PartitionCheckpointInput {
        partition_id: "partition_left_node_b",
        members: BTreeSet::from(["alice_realnet".to_owned(), "bob_realnet".to_owned()]),
        transitions: vec![mvp4_partition_transition(
            "evt_remove_carol_from_left",
            "alice_device_realnet",
            "remove_member",
            "carol_realnet",
            2,
        )],
        messages: vec![
            mvp4_partition_message("msg_left_alice", "alice_realnet", 2),
            mvp4_partition_message("msg_left_bob", "bob_realnet", 2),
        ],
    })?;
    let right = mvp4_partition_checkpoint(Mvp4PartitionCheckpointInput {
        partition_id: "partition_right_node_c",
        members: BTreeSet::from(["alice_realnet".to_owned(), "carol_realnet".to_owned()]),
        transitions: vec![mvp4_partition_transition(
            "evt_remove_bob_from_right",
            "alice_device_realnet",
            "remove_member",
            "bob_realnet",
            2,
        )],
        messages: vec![
            mvp4_partition_message("msg_right_alice", "alice_realnet", 2),
            mvp4_partition_message("msg_right_carol", "carol_realnet", 2),
        ],
    })?;
    Ok((left, right))
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn resolve_mvp4_group_partition(
    mesh: &ramflux_sync::FederationMesh,
    first: &Mvp4GroupPartitionCheckpoint,
    second: &Mvp4GroupPartitionCheckpoint,
) -> Result<Mvp4GroupCanonicalProjection, Box<dyn std::error::Error>> {
    assert_eq!(first.group_id, second.group_id);
    let canonical_members = mesh.heal_group_partition(&first.members, &second.members);
    let mut transitions = first.transitions.clone();
    transitions.extend(second.transitions.clone());
    transitions.sort_by(|left, right| {
        (left.auth_chain_depth, left.lamport_time, &left.actor_device_id, &left.event_id).cmp(&(
            right.auth_chain_depth,
            right.lamport_time,
            &right.actor_device_id,
            &right.event_id,
        ))
    });
    let auth_chain_event_ids =
        transitions.iter().map(|transition| transition.event_id.clone()).collect::<Vec<_>>();

    let mut messages = first.messages.clone();
    messages.extend(second.messages.clone());
    messages.sort_by(|left, right| {
        (left.message_created_group_key_epoch, &left.message_id)
            .cmp(&(right.message_created_group_key_epoch, &right.message_id))
    });
    let mut projected_message_ids = Vec::new();
    let mut rejected_message_ids = Vec::new();
    for message in messages {
        if canonical_members.contains(&message.sender) {
            projected_message_ids.push(message.message_id);
        } else {
            rejected_message_ids.push(message.message_id);
        }
    }

    let group_epoch = first.observed_group_epoch.max(second.observed_group_epoch) + 1;
    let sender_key_epoch =
        first.observed_sender_key_epoch.max(second.observed_sender_key_epoch) + 1;
    let lineage_input = Mvp4CanonicalLineageInput {
        group_id: &first.group_id,
        group_epoch,
        sender_key_epoch,
        members: &canonical_members,
        projected_message_ids: &projected_message_ids,
        rejected_message_ids: &rejected_message_ids,
        auth_chain_event_ids: &auth_chain_event_ids,
    };
    let group_lineage_head = mvp4_canonical_group_lineage_head(&lineage_input)?;
    Ok(Mvp4GroupCanonicalProjection {
        group_epoch,
        sender_key_epoch,
        members: canonical_members,
        projected_message_ids,
        rejected_message_ids,
        auth_chain_event_ids,
        group_lineage_head,
    })
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp4_group_lineage_head(
    group_id: &str,
    group_epoch: u64,
    sender_key_epoch: u64,
    members: &BTreeSet<String>,
    transitions: &[Mvp4GroupPartitionTransition],
    messages: &[Mvp4GroupPartitionMessage],
) -> Result<String, Box<dyn std::error::Error>> {
    let body = serde_json::to_vec(&serde_json::json!({
        "group_id": group_id,
        "group_epoch": group_epoch,
        "sender_key_epoch": sender_key_epoch,
        "members": members,
        "transitions": transitions,
        "messages": messages,
    }))?;
    Ok(ramflux_crypto::blake3_256_base64url(ramflux_protocol::domain::GROUP_EVENT, &body))
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp4_canonical_group_lineage_head(
    input: &Mvp4CanonicalLineageInput<'_>,
) -> Result<String, Box<dyn std::error::Error>> {
    let body = serde_json::to_vec(&serde_json::json!({
        "group_id": input.group_id,
        "group_epoch": input.group_epoch,
        "sender_key_epoch": input.sender_key_epoch,
        "members": input.members,
        "projected_message_ids": input.projected_message_ids,
        "rejected_message_ids": input.rejected_message_ids,
        "auth_chain_event_ids": input.auth_chain_event_ids,
    }))?;
    Ok(ramflux_crypto::blake3_256_base64url(ramflux_protocol::domain::GROUP_EVENT, &body))
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn assert_mvp4_migration_steps(steps: &[Mvp4MigrationStep]) {
    assert_eq!(steps.len(), 10);
    assert_eq!(steps[0].step_number, 1);
    assert_eq!(steps[2].name, "sign_home_node_migration_proof");
    assert_eq!(steps[6].name, "forward_or_nack_old_home");
    assert_eq!(steps[8].name, "encrypted_new_device_backfill");
}
