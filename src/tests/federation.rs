// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use super::*;

#[test]
fn federation_cross_node_friend() -> Result<(), Box<dyn std::error::Error>> {
    let mut mesh = trusted_two_node_mesh()?;
    mesh.bind_identity_home("alice", "node_a.example")?;
    mesh.bind_identity_home("bob", "node_b.example")?;
    assert_eq!(mesh.send_cross_node_friend_request("alice", "bob")?, "alice->bob");
    Ok(())
}

#[test]
fn federation_two_nodes_trusted_link() -> Result<(), Box<dyn std::error::Error>> {
    let mut mesh = ramflux_sync::FederationMesh::new();
    mesh.register_node("node_a.example", "https://node-a.example");
    mesh.register_node("node_b.example", "https://node-b.example");
    mesh.establish_trusted_link("node_a.example", "node_b.example")?;
    mesh.bind_identity_home("alice", "node_a.example")?;
    mesh.bind_identity_home("bob", "node_b.example")?;
    assert!(mesh.send_cross_node_friend_request("alice", "bob").is_ok());
    Ok(())
}

#[test]
fn federation_cross_node_message() -> Result<(), Box<dyn std::error::Error>> {
    let mut mesh = trusted_two_node_mesh()?;
    mesh.bind_identity_home("alice", "node_a.example")?;
    mesh.bind_identity_home("bob", "node_b.example")?;
    let message = mesh.send_cross_node_message("alice", "bob", b"opaque ciphertext")?;
    assert_eq!(message.via_node, "node_b.example");
    assert_eq!(message.body_ciphertext, b"opaque ciphertext");
    Ok(())
}

#[test]
fn federation_zero_directory_cross_node_dm() -> Result<(), Box<dyn std::error::Error>> {
    let mut mesh = ramflux_sync::FederationMesh::new();
    mesh.register_node("node_a.example", "https://node-a.example");
    mesh.register_node("node_b.example", "https://node-b.example");
    mesh.establish_trusted_link("node_a.example", "node_b.example")?;
    mesh.bind_identity_home("alice", "node_a.example")?;
    mesh.add_zero_directory_invite(
        "bob",
        ramflux_sync::FederationNode {
            node_id: "node_b.example".to_owned(),
            public_key: "invite-pinned-key".to_owned(),
            endpoint: "https://node-b.example".to_owned(),
            trust_status: ramflux_sync::NodeTrustStatus::Active,
        },
    );
    let message = mesh.send_cross_node_message("alice", "bob", b"zero-directory")?;
    assert_eq!(message.via_node, "node_b.example");
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
fn federation_true_key_pin_and_forward_reaches_peer_inbox() -> Result<(), Box<dyn std::error::Error>>
{
    let source_seed =
        ramflux_crypto::blake3_256("ramflux.itest.local.federation_node_key.v1", b"node_a.example");
    let target_seed =
        ramflux_crypto::blake3_256("ramflux.itest.local.federation_node_key.v1", b"node_b.example");
    let source_public_key = ramflux_crypto::public_key_base64url_from_seed(source_seed);
    let target_public_key = ramflux_crypto::public_key_base64url_from_seed(target_seed);
    assert_ne!(source_public_key, target_public_key);

    let mut source_state = ramflux_node_core::FederationTrustState::new();
    let mut target_state = ramflux_node_core::FederationTrustState::new();

    let mut node_b_record = federation_server_record_for_test(
        "node_b.example",
        "node-b-federation:7443",
        &target_public_key,
    );
    ramflux_node_core::sign_federation_server_record_with_seed(&mut node_b_record, target_seed)?;
    let discovered_b = source_state.resolve_discovery_result(
        &federation_discovery_request_for_test("node_b.example"),
        Some(&node_b_record),
        None,
    )?;
    assert_eq!(discovered_b.node_endpoint, "node-b-federation:7443");
    assert_eq!(discovered_b.node_public_key, target_public_key);
    let peer_route = federation_route_for_test(
        "node_b.example",
        &target_public_key,
        "node-b-federation:7443",
        ramflux_node_core::FederationTrustStatus::Invited,
    );
    source_state.admit_verified_discovered_peer(
        peer_route,
        &["opaque_delivery".to_owned(), "federation_relay".to_owned()],
        &["opaque_delivery".to_owned(), "federation_relay".to_owned()],
    )?;

    let route_a = federation_route_for_test(
        "node_a.example",
        &source_public_key,
        "node-a-federation:7443",
        ramflux_node_core::FederationTrustStatus::Invited,
    );
    let mut invitation_a = ramflux_node_core::FederationNodeInvitation {
        invitation_id: "inv_local_node_a".to_owned(),
        inviter_node_id: "node_b.example".to_owned(),
        candidate_node_id: "node_a.example".to_owned(),
        candidate_node_public_key: source_public_key.clone(),
        candidate_node_ca_cert_pem: include_str!("testdata/certs/ca.pem").to_owned(),
        candidate_node_public_key_hash: route_a.node_public_key_hash.clone(),
        allowed_capabilities: vec!["opaque_delivery".to_owned(), "federation_relay".to_owned()],
        expires_at: 1_760_000_900,
        signature: String::new(),
    };
    invitation_a.signature =
        ramflux_crypto::sign_protocol_object_with_seed(&invitation_a, source_seed)?;
    target_state.admit_handshake(ramflux_node_core::FederationHandshakeAdmissionRequest {
        route: route_a,
        handshake: signed_handshake_for_test("node_a.example", "node_b.example", source_seed)?,
        invitation: Some(invitation_a),
        local_capabilities: vec!["opaque_delivery".to_owned(), "federation_relay".to_owned()],
        local_protocol_versions: vec!["v1".to_owned()],
        local_transport_backends: vec!["quic_quinn".to_owned()],
        now: 1_760_000_020,
    })?;

    let mut forward = ramflux_node_core::FederatedEnvelopeForwardRequest {
        signed: ramflux_node_core::default_federation_forward_signed_fields(),
        admin_token: String::new(),
        source_node_id: "node_a.example".to_owned(),
        target_node_id: "node_b.example".to_owned(),
        delivery_class: "opaque_event".to_owned(),
        required_capability: "opaque_delivery".to_owned(),
        envelope: itest_envelope("env_local_true_key_forward", "target_node_b"),
    };
    source_state.ensure_federated_envelope_allowed(&forward, "node_b.example", 1_760_000_020)?;
    ramflux_node_core::sign_federated_envelope_forward(&mut forward, source_seed)?;
    let pinned_a =
        target_state.pinned_node_public_key("node_a.example").ok_or("missing node_a pin")?;
    ramflux_node_core::verify_federated_envelope_forward(&forward, &pinned_a)?;
    target_state.ensure_federated_envelope_allowed(&forward, "node_a.example", 1_760_000_020)?;

    let target_router = ramflux_node_core::RouterCore::new();
    let submitted = target_router.submit_envelope(forward.envelope.clone());
    assert!(matches!(submitted, ramflux_node_core::RouterSubmitOutcome::OfflineQueued(_)));
    let replay = target_router.submit_envelope(forward.envelope.clone());
    assert!(matches!(replay, ramflux_node_core::RouterSubmitOutcome::RejectedSecurity { .. }));
    let pulled = target_router.resume("target_node_b", 0, 10);
    assert_eq!(pulled.len(), 1);
    assert_eq!(pulled[0].envelope.envelope_id, "env_local_true_key_forward");

    let wrong_key = ramflux_crypto::public_key_base64url_from_seed(ramflux_crypto::blake3_256(
        "ramflux.itest.local.federation_node_key.v1",
        b"wrong-node",
    ));
    assert!(ramflux_node_core::verify_federated_envelope_forward(&forward, &wrong_key).is_err());
    Ok(())
}

#[test]
fn federation_trust_revoke_blocks_delivery() -> Result<(), Box<dyn std::error::Error>> {
    let mut mesh = trusted_two_node_mesh()?;
    mesh.bind_identity_home("alice", "node_a.example")?;
    mesh.bind_identity_home("bob", "node_b.example")?;
    mesh.revoke_trust("node_b.example")?;
    assert!(mesh.send_cross_node_message("alice", "bob", b"blocked").is_err());
    Ok(())
}

fn federation_server_record_for_test(
    node_id: &str,
    endpoint: &str,
    public_key: &str,
) -> ramflux_node_core::FederationServerRecord {
    ramflux_node_core::FederationServerRecord {
        schema: "ramflux.well_known_server.v1".to_owned(),
        node_id: node_id.to_owned(),
        node_public_key: public_key.to_owned(),
        node_ca_cert_pem: include_str!("testdata/certs/ca.pem").to_owned(),
        node_endpoint: endpoint.to_owned(),
        protocol_versions: vec!["v1".to_owned()],
        transport_backends: vec!["quic_quinn".to_owned()],
        node_capabilities: vec!["opaque_delivery".to_owned(), "federation_relay".to_owned()],
        node_policy_hash: "policy_hash".to_owned(),
        updated_at: 1_760_000_000,
        expires_at: 1_760_086_400,
        signature: String::new(),
    }
}

fn federation_discovery_request_for_test(
    node_id: &str,
) -> ramflux_node_core::FederationDiscoveryRequest {
    ramflux_node_core::FederationDiscoveryRequest {
        node_id: node_id.to_owned(),
        now: 1_760_000_020,
        invite_endpoint: None,
        well_known_url: None,
        dns_srv_records: Vec::new(),
        address_records: Vec::new(),
        directory_endpoint: None,
    }
}

fn federation_route_for_test(
    node_id: &str,
    public_key: &str,
    endpoint: &str,
    trust_status: ramflux_node_core::FederationTrustStatus,
) -> ramflux_node_core::FederationPeerRoute {
    ramflux_node_core::FederationPeerRoute {
        node_id: node_id.to_owned(),
        endpoint: endpoint.to_owned(),
        node_public_key_hash: ramflux_crypto::blake3_256_base64url(
            ramflux_protocol::domain::FEDERATION_HANDSHAKE,
            public_key.as_bytes(),
        ),
        node_capabilities: vec!["opaque_delivery".to_owned(), "federation_relay".to_owned()],
        trust_status,
        updated_at: 1_760_000_020,
        expires_at: 1_760_003_600,
        route_update_proof_hash: "route_update_proof_hash_local".to_owned(),
    }
}

fn signed_handshake_for_test(
    source_node_id: &str,
    target_node_id: &str,
    seed: [u8; 32],
) -> Result<ramflux_protocol::FederationHandshake, Box<dyn std::error::Error>> {
    let mut handshake = ramflux_protocol::FederationHandshake {
        schema: ramflux_protocol::domain::FEDERATION_HANDSHAKE.to_owned(),
        version: 1,
        domain: ramflux_protocol::domain::FEDERATION_HANDSHAKE.to_owned(),
        ext: ramflux_protocol::Ext::default(),
        signed: ramflux_protocol::SignedFields {
            signing_key_id: format!("{source_node_id}#federation"),
            signature_alg: ramflux_protocol::SignatureAlg::Ed25519,
            signature: String::new(),
        },
        handshake_id: format!("hs_{source_node_id}_{target_node_id}"),
        source_node_id: source_node_id.to_owned(),
        target_node_id: target_node_id.to_owned(),
        source_capabilities: vec!["opaque_delivery".to_owned(), "federation_relay".to_owned()],
        protocol_versions: vec!["v1".to_owned()],
        transport_backends: vec!["quic_quinn".to_owned()],
        trust_state_hash: "trust_state_hash_local".to_owned(),
        nonce: "nonce_local_handshake".to_owned(),
        created_at: 1_760_000_020,
    };
    handshake.signed.signature = ramflux_crypto::sign_protocol_object_with_seed(&handshake, seed)?;
    Ok(handshake)
}

#[test]
fn federation_home_node_migration() -> Result<(), Box<dyn std::error::Error>> {
    let mut mesh = trusted_three_node_mesh()?;
    mesh.bind_identity_home("alice", "node_a.example")?;
    mesh.bind_identity_home("bob", "node_b.example")?;
    let migration = mesh.migrate_home_node(ramflux_sync::HomeNodeMigration {
        identity: "bob".to_owned(),
        old_home_node: "node_b.example".to_owned(),
        new_home_node: "node_c.example".to_owned(),
        proof_hash: "proof_hash".to_owned(),
    })?;
    assert_eq!(migration.new_home_node, "node_c.example");
    let message = mesh.send_cross_node_message("alice", "bob", b"after migration")?;
    assert_eq!(message.via_node, "node_c.example");
    Ok(())
}

#[test]
fn federation_home_node_migration_cutover_delivery() -> Result<(), Box<dyn std::error::Error>> {
    let mut mesh = trusted_three_node_mesh()?;
    mesh.bind_identity_home("alice", "node_a.example")?;
    mesh.bind_identity_home("bob", "node_b.example")?;
    mesh.migrate_home_node(ramflux_sync::HomeNodeMigration {
        identity: "bob".to_owned(),
        old_home_node: "node_b.example".to_owned(),
        new_home_node: "node_c.example".to_owned(),
        proof_hash: "proof_hash".to_owned(),
    })?;
    let cutover = mesh.deliver_during_cutover("alice", "bob", "node_b.example", b"in-flight")?;
    assert_eq!(cutover.delivered_to, "node_c.example");
    assert!(cutover.used_forward || cutover.used_nack_reresolve);
    Ok(())
}

#[test]
fn federation_group_partition_convergence() -> Result<(), Box<dyn std::error::Error>> {
    let mesh = trusted_three_node_mesh()?;
    let left = BTreeSet::from(["alice".to_owned(), "bob".to_owned()]);
    let right = BTreeSet::from(["alice".to_owned(), "carol".to_owned()]);
    let healed = mesh.heal_group_partition(&left, &right);
    assert_eq!(healed, BTreeSet::from(["alice".to_owned()]));
    Ok(())
}

#[test]
fn federation_trust_store_restart_recovers_revocation_state()
-> Result<(), Box<dyn std::error::Error>> {
    let root = temp_root("federation_trust_store_restart_recovers_revocation_state")?;
    let store_path = root.join("federation.redb");
    let store = ramflux_node_core::FederationRedbStore::open(&store_path)?;
    let mut state = ramflux_node_core::FederationTrustState::new();
    state.upsert_route(itest_federation_route(
        "node_b.example",
        ramflux_node_core::FederationTrustStatus::Active,
    ));
    state.apply_bad_node_advisory(itest_bad_node_advisory("adv_itest_1", "node_c.example"));
    store.save_state(&state)?;
    drop(store);

    let reopened = ramflux_node_core::FederationRedbStore::open(&store_path)?;
    let mut restored =
        reopened.load_state()?.ok_or_else(|| "missing federation state".to_owned())?;
    assert!(restored.can_deliver_to("node_b.example", 1_760_000_001));
    restored.update_trust_status(
        "node_b.example",
        ramflux_node_core::FederationTrustStatus::Revoked,
        1_760_000_010,
    )?;
    assert!(!restored.can_deliver_to("node_b.example", 1_760_000_011));
    assert_eq!(restored.advisory_count(), 1);
    Ok(())
}
