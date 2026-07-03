// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use super::*;

#[test]
fn mvp7_local_two_node_federated_tombstone_actor_must_be_registered_on_origin()
-> Result<(), Box<dyn std::error::Error>> {
    let node_a = ramflux_node_core::RouterCore::new();
    let node_b = ramflux_node_core::RouterCore::new();
    let request = local_mvp7_lifecycle_request(
        "mvp7_federated_deactivated",
        "mvp7_federated_deactivated_device",
    );

    assert!(node_a.mvp7_apply_lifecycle_event(&request).is_err());
    node_b.mvp1_register_identity(&local_mvp7_actor_registration(
        "mvp7_federated_deactivated",
        "mvp7_federated_deactivated_device",
        201,
    )?)?;
    assert!(node_a.mvp7_apply_lifecycle_event(&request).is_err());

    node_a.mvp1_register_identity(&local_mvp7_actor_registration(
        "mvp7_federated_deactivated",
        "mvp7_federated_deactivated_device",
        202,
    )?)?;
    let deactivated = node_a.mvp7_apply_lifecycle_event(&request)?;
    let tombstone = deactivated.tombstone.ok_or("missing lifecycle tombstone")?;
    let propagated = node_b.mvp7_apply_federated_tombstone(
        &ramflux_node_core::FederatedLifecycleTombstoneRequest {
            source_node_id: "node_a.realnet".to_owned(),
            target_delivery_id: "target_mvp7_deactivated_remote".to_owned(),
            lifecycle_state: ramflux_node_core::AccountLifecycleState::Deactivated,
            tombstone: Some(tombstone),
            deletion_proof: None,
        },
    )?;
    assert!(propagated.accepted);
    assert_eq!(propagated.lifecycle_state, ramflux_node_core::AccountLifecycleState::Deactivated);
    Ok(())
}

fn local_mvp7_lifecycle_request(
    principal_id: &str,
    actor_device_id: &str,
) -> ramflux_node_core::LifecycleEventRequest {
    ramflux_node_core::LifecycleEventRequest {
        principal_id: principal_id.to_owned(),
        event_id: format!("evt_{principal_id}_deactivated"),
        event_type: "identity.deactivated".to_owned(),
        actor_device_id: actor_device_id.to_owned(),
        lifecycle_epoch: 1,
        now: 1_760_001_000,
        reason_code: "user_requested".to_owned(),
        timelock_seconds: None,
        recovery_quorum: None,
        recovery_quorum_proof: None,
    }
}

fn local_mvp7_actor_registration(
    principal_id: &str,
    actor_device_id: &str,
    nonce: i64,
) -> Result<ramflux_node_core::IdentityRegisterRequest, Box<dyn std::error::Error>> {
    let root_seed = ramflux_crypto::blake3_256(
        "ramflux.itest.mvp7.local_two_node.root_seed.v1",
        principal_id.as_bytes(),
    );
    let root = ramflux_crypto::create_identity_root(principal_id, root_seed);
    let device = ramflux_crypto::create_device_branch(
        principal_id,
        actor_device_id,
        1,
        ramflux_crypto::FIXTURE_SIGNING_KEY_BYTES,
    );
    let proof = ramflux_crypto::authorize_device_branch(
        &root,
        &device,
        ramflux_node_core::IDENTITY_BIND_AUDIENCE,
        vec![ramflux_node_core::IDENTITY_BIND_CAPABILITY.to_owned()],
        1_760_000_000 + nonce,
        1_760_003_600 + nonce,
    )?;
    let root_public_key =
        ramflux_protocol::encode_base64url(root.signing_key.verifying_key().to_bytes());
    let root_public_key_bytes = ramflux_protocol::decode_base64url(&root_public_key)?;
    Ok(ramflux_node_core::IdentityRegisterRequest {
        principal_commitment: ramflux_crypto::blake3_256_base64url(
            "ramflux.identity.root_public_key.commitment.v1",
            &root_public_key_bytes,
        ),
        root_public_key,
        branch_public_key: ramflux_protocol::encode_base64url(
            device.signing_key.verifying_key().to_bytes(),
        ),
        proof,
        target_delivery_id: format!("target_{principal_id}_{nonce}"),
        gateway_id: "ramflux-gateway".to_owned(),
        session_id: format!("session_{principal_id}_{nonce}"),
        push_alias_hash: Some(format!("push_alias_{principal_id}_{nonce}")),
        now: 1_760_000_010 + nonce,
        registration_pow: None,
        source_ip_hash: None,
    })
}

#[cfg(feature = "realnet")]
#[test]
fn mvp7_realnet_account_lifecycle_retention_gc() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    let realnet = start_realnet_compose()?;
    let gateway_url = &realnet.gateway_url;
    let retention_url = &realnet.retention_url;
    mvp7_register_lifecycle_actor(gateway_url)?;
    let proof = mvp7_assert_lifecycle_delete_path(gateway_url)?;
    mvp7_assert_retention_gc(retention_url)?;
    assert!(!proof.proof_hash.is_empty());
    Ok(())
}

#[cfg(feature = "realnet")]
#[test]
fn mvp7_realnet_federation_tombstone_propagation_deleted_deactivated()
-> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    let realnet = start_realnet_compose()?;
    let gateway_url = &realnet.gateway_url;
    let federation_url = std::env::var("RAMFLUX_ITEST_FEDERATION_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:18082".to_owned());
    wait_for_federation(&federation_url)?;
    let mut mesh = ramflux_sync::FederationMesh::new();
    mesh.register_node("node_a.realnet", "https://node-a.realnet/federation");
    mesh.register_node("node_b.realnet", "https://node-b.realnet/federation");
    mesh.establish_trusted_link("node_a.realnet", "node_b.realnet")?;
    mesh.bind_identity_home("mvp7_federated_deleted", "node_a.realnet")?;
    publish_mvp4_named_federation_route(
        &federation_url,
        "node_b.realnet",
        ramflux_node_core::FederationTrustStatus::Active,
    )?;
    mvp7_register_lifecycle_actor_for(gateway_url, "mvp7_federated_deleted", 101)?;
    mvp7_register_lifecycle_actor_for(gateway_url, "mvp7_federated_deactivated", 102)?;

    let deleted = mvp7_assert_federated_deleted_tombstone(gateway_url, &federation_url)?;
    mvp7_assert_invalid_federated_tombstone_is_rejected(gateway_url, &federation_url, deleted)?;
    mvp7_assert_federated_deactivate_reactivate(gateway_url, &federation_url)?;
    Ok(())
}

#[cfg(feature = "realnet")]
#[test]
fn mvp7_realnet_franking_report_verified_rejected_retention()
-> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    let realnet = start_realnet_compose()?;
    let gateway_url = &realnet.gateway_url;
    let retention_url = &realnet.retention_url;
    let code_root = code_root();
    let ca_cert = code_root.join("ramflux/deploy/certs/ca.pem");
    let gateway_quic_addr: std::net::SocketAddr = std::env::var("RAMFLUX_ITEST_GATEWAY_QUIC_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:18443".to_owned())
        .parse()?;
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async {
        wait_for_private_gateway_quic(gateway_quic_addr, &ca_cert).await?;
        mvp7_assert_franking_report_pipeline(
            gateway_url,
            retention_url,
            gateway_quic_addr,
            &ca_cert,
        )
        .await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    Ok(())
}
