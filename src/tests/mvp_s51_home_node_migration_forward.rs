// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use super::*;

#[cfg(feature = "realnet")]
const S51_ROUTER_ADMIN_TOKEN: &str = "ramflux-local-admin-token";

#[cfg(feature = "realnet")]
#[test]
fn mvp_s51_realnet_home_node_migration_forwards_within_window()
-> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    let old_home_ports = S8ComposePorts {
        gateway_http: 57_181,
        gateway_quic: 57_451,
        router_http: 57_180,
        router_mesh: 57_452,
        notify_http: 57_183,
        federation_http: 57_182,
        federation_mesh: 57_453,
        relay_http: 57_184,
        relay_media_udp: 57_100,
        signaling_turn_udp: 57_478,
        signaling_turn_tcp: 57_479,
        retention_http: 57_187,
    };
    let new_home_ports = S8ComposePorts {
        gateway_http: 58_181,
        gateway_quic: 58_451,
        router_http: 58_180,
        router_mesh: 58_452,
        notify_http: 58_183,
        federation_http: 58_182,
        federation_mesh: 58_453,
        relay_http: 58_184,
        relay_media_udp: 58_100,
        signaling_turn_udp: 58_478,
        signaling_turn_tcp: 58_479,
        retention_http: 58_187,
    };

    realnet_step("S51 start node-a", "home-node migration old home");
    let node_a =
        start_s8_realnet_compose_project("ramflux-s51-home-migration-node-a", old_home_ports)?;
    realnet_step("S51 start node-b", "home-node migration new home");
    let node_b =
        start_s8_realnet_compose_project("ramflux-s51-home-migration-node-b", new_home_ports)?;
    mvp_s8_establish_trusted_links(&node_a, &node_b)?;

    let old_home_router_url = format!("http://127.0.0.1:{}", old_home_ports.router_http);
    let new_home_router_url = format!("http://127.0.0.1:{}", new_home_ports.router_http);
    let fixture = s51_migration_fixture(&node_a, &node_b)?;

    realnet_step("S51 register identity on node-a", &node_a.gateway_url);
    register_mvp1_identity(&node_a.gateway_url, &fixture.register)?;
    realnet_step("S51 register identity on node-b", &node_b.gateway_url);
    register_mvp1_identity(&node_b.gateway_url, &fixture.register)?;

    realnet_step("S51 apply migration on node-a", &old_home_router_url);
    s51_apply_migration(&old_home_router_url, &fixture)?;
    realnet_step("S51 apply route update on node-a", &old_home_router_url);
    s51_apply_route_update(&old_home_router_url, &fixture)?;
    realnet_step("S51 apply migration on node-b", &new_home_router_url);
    s51_apply_migration(&new_home_router_url, &fixture)?;
    realnet_step("S51 apply route update on node-b", &new_home_router_url);
    s51_apply_route_update(&new_home_router_url, &fixture)?;

    let envelope_id = "env_s51_home_node_migration_forward";
    let envelope = itest_envelope(envelope_id, &fixture.target_delivery_id);
    realnet_step(
        "S51 submit to old home node-a",
        format!(
            "envelope={envelope_id} target={} old_home={} new_home={}",
            fixture.target_delivery_id, node_a.node_id, node_b.node_id
        ),
    );
    let submit: ramflux_node_core::EnvelopeSubmitResponse =
        ramflux_node_core::itest_http_post_json(
            &format!("{}/mvp0/envelope", node_a.gateway_url),
            &envelope,
        )?;
    assert_eq!(submit.outcome, "forwarded_home_node_migrated");
    assert!(submit.nack.is_none(), "migration window forward must not return a NACK");
    assert!(
        submit.inbox_seq.is_some(),
        "migration window forward returned forwarded outcome without node-b inbox_seq: {submit:?}"
    );

    let inbox = s51_wait_for_forwarded_inbox_entry(&node_b.gateway_url, &fixture, envelope_id)?;
    assert!(
        inbox.entries.iter().any(|entry| entry.envelope.envelope_id == envelope_id),
        "new home node-b inbox did not receive forwarded envelope {envelope_id}: {inbox:?}"
    );

    drop(node_b);
    drop(node_a);
    Ok(())
}

#[cfg(feature = "realnet")]
struct S51MigrationFixture {
    register: ramflux_node_core::IdentityRegisterRequest,
    target_delivery_id: String,
    migration_proof: ramflux_protocol::HomeNodeMigrationProof,
    route_update: ramflux_node_core::HomeNodeRouteUpdateProof,
}

#[cfg(feature = "realnet")]
struct S51IdentityMaterial {
    register: ramflux_node_core::IdentityRegisterRequest,
    device: ramflux_crypto::DeviceBranch,
    target_delivery_id: String,
}

#[cfg(feature = "realnet")]
fn s51_identity_material(now: i64) -> Result<S51IdentityMaterial, Box<dyn std::error::Error>> {
    let root = ramflux_crypto::create_identity_root("principal_s51_migration", [0x51; 32]);
    let device = ramflux_crypto::create_device_branch(
        "principal_s51_migration",
        "device_s51_migration",
        1,
        [0x52; 32],
    );
    let proof = ramflux_crypto::authorize_device_branch(
        &root,
        &device,
        ramflux_node_core::IDENTITY_BIND_AUDIENCE,
        vec![ramflux_node_core::IDENTITY_BIND_CAPABILITY.to_owned()],
        now.saturating_sub(60),
        now.saturating_add(86_400),
    )?;
    let root_public_key =
        ramflux_protocol::encode_base64url(root.signing_key.verifying_key().to_bytes());
    let root_public_key_bytes = ramflux_protocol::decode_base64url(&root_public_key)?;
    let target_delivery_id = "target_s51_migration".to_owned();
    let register = ramflux_node_core::IdentityRegisterRequest {
        principal_commitment: ramflux_crypto::blake3_256_base64url(
            "ramflux.identity.root_public_key.commitment.v1",
            &root_public_key_bytes,
        ),
        root_public_key,
        branch_public_key: ramflux_protocol::encode_base64url(
            device.signing_key.verifying_key().to_bytes(),
        ),
        proof,
        target_delivery_id: target_delivery_id.clone(),
        gateway_id: "ramflux-gateway".to_owned(),
        session_id: "session_s51_migration".to_owned(),
        push_alias_hash: Some("push_alias_s51_migration".to_owned()),
        now,
        registration_pow: None,
        source_ip_hash: Some("source_s51_migration".to_owned()),
    };
    Ok(S51IdentityMaterial { register, device, target_delivery_id })
}

#[cfg(feature = "realnet")]
fn s51_migration_fixture(
    node_a: &S8RealnetNode,
    node_b: &S8RealnetNode,
) -> Result<S51MigrationFixture, Box<dyn std::error::Error>> {
    let now = realnet_now_i64();
    let identity = s51_identity_material(now)?;
    let route_signer = ramflux_node_core::NodeServiceSigningKey::from_seed(
        realnet_node_signing_seed(&node_b.node_id),
    );
    let new_home_node_key_hash = ramflux_crypto::blake3_256_base64url(
        ramflux_protocol::domain::FEDERATION_HANDSHAKE,
        route_signer.public_key_base64url().as_bytes(),
    );
    let expires_at = now.saturating_add(86_400);
    let route_commitment = ramflux_node_core::HomeNodeRouteRecordCommitment {
        schema: ramflux_node_core::HOME_NODE_ROUTE_RECORD_DOMAIN.to_owned(),
        domain: ramflux_node_core::HOME_NODE_ROUTE_RECORD_DOMAIN.to_owned(),
        new_home_node: node_b.node_id.clone(),
        new_home_node_key_hash: new_home_node_key_hash.clone(),
        node_public_key: route_signer.public_key_base64url().to_owned(),
        node_endpoint: node_b.federation_mesh_endpoint.clone(),
        expires_at,
    };
    let route_record_hash = ramflux_node_core::home_node_route_record_hash(&route_commitment)?;
    let mut migration_proof = ramflux_protocol::HomeNodeMigrationProof {
        schema: ramflux_protocol::domain::HOME_NODE_MIGRATION_PROOF.to_owned(),
        domain: ramflux_protocol::domain::HOME_NODE_MIGRATION_PROOF.to_owned(),
        signed: ramflux_protocol::SignedFields {
            signing_key_id: String::new(),
            signature_alg: ramflux_protocol::SignatureAlg::Ed25519,
            signature: String::new(),
        },
        proof_id: "proof_s51_migration".to_owned(),
        identity_commitment: identity.register.proof.principal_id.clone(),
        lineage_head: "lineage_head_s51_migration".to_owned(),
        actor_device_id: identity.register.proof.device_id.clone(),
        actor_device_epoch: identity.register.proof.device_epoch,
        old_home_node: node_a.node_id.clone(),
        new_home_node: node_b.node_id.clone(),
        new_home_node_key_hash: new_home_node_key_hash.clone(),
        route_record_hash: route_record_hash.clone(),
        effective_at: now.saturating_sub(1),
        expires_at,
        issued_at: now.saturating_sub(2),
        nonce: ramflux_protocol::encode_base64url(b"nonce_s51_migration"),
        branch_proof_hash: ramflux_crypto::branch_proof_document_hash(&identity.register.proof)?,
        previous_home_node_binding_hash: None,
        old_home_node_handoff_signature: None,
    };
    migration_proof =
        ramflux_crypto::sign_home_node_migration_proof(migration_proof, &identity.device)?;
    let migration_proof_hash = ramflux_crypto::migration_proof_hash(&migration_proof)?;
    let mut route_update = ramflux_node_core::HomeNodeRouteUpdateProof {
        schema: ramflux_node_core::HOME_NODE_ROUTE_UPDATE_PROOF_DOMAIN.to_owned(),
        domain: ramflux_node_core::HOME_NODE_ROUTE_UPDATE_PROOF_DOMAIN.to_owned(),
        signed: ramflux_protocol::SignedFields {
            signing_key_id: String::new(),
            signature_alg: ramflux_protocol::SignatureAlg::Ed25519,
            signature: String::new(),
        },
        identity_commitment: identity.register.proof.principal_id.clone(),
        new_home_node: node_b.node_id.clone(),
        new_home_node_key_hash,
        node_public_key: route_signer.public_key_base64url().to_owned(),
        node_endpoint: node_b.federation_mesh_endpoint.clone(),
        route_record_hash,
        migration_proof_hash,
        issued_at: now,
        expires_at,
    };
    route_signer.sign_home_node_route_update_proof(&mut route_update)?;
    Ok(S51MigrationFixture {
        register: identity.register,
        target_delivery_id: identity.target_delivery_id,
        migration_proof,
        route_update,
    })
}

#[cfg(feature = "realnet")]
fn s51_apply_migration(
    router_url: &str,
    fixture: &S51MigrationFixture,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    Ok(ramflux_node_core::itest_http_post_json(
        &format!("{router_url}/admin/home-node-migration/apply"),
        &serde_json::json!({
            "admin_token": S51_ROUTER_ADMIN_TOKEN,
            "proof": fixture.migration_proof,
            "branch_proof": fixture.register.proof,
            "now": realnet_now_i64(),
        }),
    )?)
}

#[cfg(feature = "realnet")]
fn s51_apply_route_update(
    router_url: &str,
    fixture: &S51MigrationFixture,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    Ok(ramflux_node_core::itest_http_post_json(
        &format!("{router_url}/admin/home-node-route/update/apply"),
        &serde_json::json!({
            "admin_token": S51_ROUTER_ADMIN_TOKEN,
            "proof": fixture.route_update,
            "now": realnet_now_i64(),
        }),
    )?)
}

#[cfg(feature = "realnet")]
fn s51_wait_for_forwarded_inbox_entry(
    gateway_url: &str,
    fixture: &S51MigrationFixture,
    envelope_id: &str,
) -> Result<ramflux_node_core::InboxFetchResponse, Box<dyn std::error::Error>> {
    let url = format!("{gateway_url}/mvp1/inbox/{}", fixture.target_delivery_id);
    let mut last: Option<ramflux_node_core::InboxFetchResponse> = None;
    for _attempt in 0..20 {
        let inbox: ramflux_node_core::InboxFetchResponse =
            ramflux_node_core::itest_http_get_json(&url)?;
        if inbox.entries.iter().any(|entry| entry.envelope.envelope_id == envelope_id) {
            return Ok(inbox);
        }
        last = Some(inbox);
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    Ok(last.unwrap_or(ramflux_node_core::InboxFetchResponse {
        target_delivery_id: fixture.target_delivery_id.clone(),
        entries: Vec::new(),
    }))
}
