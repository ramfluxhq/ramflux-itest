// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use crate::*;

#[cfg(all(test, feature = "realnet"))]
pub(crate) const fn mvp7_lifecycle_step(
    event_id: &'static str,
    event_type: &'static str,
    lifecycle_epoch: u64,
    now: u64,
    timelock_seconds: Option<u64>,
) -> Mvp7LifecycleStep {
    Mvp7LifecycleStep { event_id, event_type, lifecycle_epoch, now, timelock_seconds }
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp7_lifecycle_event(
    gateway_url: &str,
    step: Mvp7LifecycleStep,
) -> Result<ramflux_node_core::LifecycleResponse, Box<dyn std::error::Error>> {
    mvp7_lifecycle_event_for(gateway_url, "mvp7_delete_principal", step)
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp7_lifecycle_event_for(
    gateway_url: &str,
    principal_id: &str,
    step: Mvp7LifecycleStep,
) -> Result<ramflux_node_core::LifecycleResponse, Box<dyn std::error::Error>> {
    Ok(ramflux_node_core::itest_http_post_json(
        &format!("{gateway_url}/mvp7/lifecycle/event"),
        &ramflux_node_core::LifecycleEventRequest {
            principal_id: principal_id.to_owned(),
            event_id: step.event_id.to_owned(),
            event_type: step.event_type.to_owned(),
            actor_device_id: mvp7_lifecycle_actor_device_id(principal_id),
            lifecycle_epoch: step.lifecycle_epoch,
            now: step.now,
            reason_code: "user_requested".to_owned(),
            timelock_seconds: step.timelock_seconds,
            recovery_quorum: None,
            recovery_quorum_proof: None,
        },
    )?)
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp7_lifecycle_actor_device_id(principal_id: &str) -> String {
    match principal_id {
        "mvp7_delete_principal" => "mvp7_delete_device".to_owned(),
        "mvp7_federated_deleted" => "mvp7_federated_deleted_device".to_owned(),
        "mvp7_federated_deactivated" => "mvp7_federated_deactivated_device".to_owned(),
        _ => format!("{principal_id}_device"),
    }
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp7_register_lifecycle_actor(
    gateway_url: &str,
) -> Result<ramflux_node_core::IdentityRegistrationResponse, Box<dyn std::error::Error>> {
    let root = ramflux_crypto::create_identity_root("mvp7_delete_principal", [0x91; 32]);
    let device = ramflux_crypto::create_device_branch(
        "mvp7_delete_principal",
        "mvp7_delete_device",
        1,
        ramflux_crypto::FIXTURE_SIGNING_KEY_BYTES,
    );
    let register = mvp1_named_register_request(
        &root,
        &device,
        "target_mvp7_delete",
        "session_mvp7_delete",
        91,
    )?;
    register_mvp1_identity(gateway_url, &register)
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp7_register_lifecycle_actor_for(
    gateway_url: &str,
    principal_id: &str,
    nonce: i64,
) -> Result<ramflux_node_core::IdentityRegistrationResponse, Box<dyn std::error::Error>> {
    let root_seed = ramflux_crypto::blake3_256(
        "ramflux.itest.mvp7.lifecycle_actor.root_seed.v1",
        principal_id.as_bytes(),
    );
    let actor_device_id = mvp7_lifecycle_actor_device_id(principal_id);
    let root = ramflux_crypto::create_identity_root(principal_id, root_seed);
    let device = ramflux_crypto::create_device_branch(
        principal_id,
        &actor_device_id,
        1,
        ramflux_crypto::FIXTURE_SIGNING_KEY_BYTES,
    );
    let register = mvp1_named_register_request(
        &root,
        &device,
        &format!("target_{principal_id}"),
        &format!("session_{principal_id}"),
        nonce,
    )?;
    register_mvp1_identity(gateway_url, &register)
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp7_deleted_tombstone_fixture(
    gateway_url: &str,
    principal_id: &str,
) -> Result<Mvp7DeletedTombstoneFixture, Box<dyn std::error::Error>> {
    let pending = mvp7_lifecycle_event_for(
        gateway_url,
        principal_id,
        mvp7_lifecycle_step(
            "evt_mvp7_fed_delete_pending",
            "identity.deleted",
            1,
            1_760_000_100,
            Some(0),
        ),
    )?;
    let tombstone = pending.tombstone.ok_or("missing federated delete tombstone")?;
    let finalized = mvp7_finalize_delete(gateway_url, principal_id, 1_760_000_101)?;
    let deletion_proof =
        finalized.record.deletion_proof.ok_or("missing federated deletion proof")?;
    Ok(Mvp7DeletedTombstoneFixture { tombstone, deletion_proof })
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp7_post_federated_tombstone(
    federation_url: &str,
    request: &ramflux_node_core::FederatedLifecycleTombstoneRequest,
) -> Result<ramflux_node_core::FederatedLifecycleTombstoneResponse, Box<dyn std::error::Error>> {
    Ok(ramflux_node_core::itest_http_post_json(
        &format!("{federation_url}/mvp7/federation/tombstone"),
        request,
    )?)
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp7_post_abuse_report(
    gateway_url: &str,
    report_id: &str,
    selected_evidence: &Mvp7SelectedFrankingEvidence,
) -> Result<ramflux_node_core::AbuseReportResponse, Box<dyn std::error::Error>> {
    let reported_node = selected_evidence.node_id.clone();
    Ok(ramflux_node_core::itest_http_post_json(
        &format!("{gateway_url}/mvp7/abuse/report"),
        &serde_json::json!({
            "report_id": report_id,
            "reporter_identity": "bob_mvp7_reporter",
            "reported_identity": "alice_mvp7_reported",
            "reported_node": reported_node,
            "selected_evidence": selected_evidence,
            "submitted_at": 1_760_000_500_u64,
        }),
    )?)
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp7_cancel_delete(
    gateway_url: &str,
    principal_id: &str,
    now: u64,
) -> Result<ramflux_node_core::LifecycleResponse, Box<dyn std::error::Error>> {
    Ok(ramflux_node_core::itest_http_post_json(
        &format!("{gateway_url}/mvp7/lifecycle/cancel"),
        &ramflux_node_core::LifecycleCancelRequest { principal_id: principal_id.to_owned(), now },
    )?)
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp7_finalize_delete(
    gateway_url: &str,
    principal_id: &str,
    now: u64,
) -> Result<ramflux_node_core::LifecycleResponse, Box<dyn std::error::Error>> {
    Ok(ramflux_node_core::itest_http_post_json(
        &format!("{gateway_url}/mvp7/lifecycle/finalize"),
        &ramflux_node_core::LifecycleFinalizeRequest { principal_id: principal_id.to_owned(), now },
    )?)
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp7_metadata(
    gateway_url: &str,
    principal_id: &str,
) -> Result<ramflux_node_core::LifecycleMetadataSummary, Box<dyn std::error::Error>> {
    Ok(ramflux_node_core::itest_http_get_json(&format!(
        "{gateway_url}/mvp7/metadata/{principal_id}"
    ))?)
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp7_retention_record(
    retention_url: &str,
    record: ramflux_node_core::RetentionMetadataRecord,
) -> Result<ramflux_node_core::RetentionMetadataRecord, Box<dyn std::error::Error>> {
    Ok(ramflux_node_core::itest_http_post_json(
        &format!("{retention_url}/mvp7/retention/record"),
        &ramflux_node_core::RetentionRecordRequest { record },
    )?)
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp7_retention_gc(
    retention_url: &str,
    now: u64,
) -> Result<ramflux_node_core::RetentionGcResponse, Box<dyn std::error::Error>> {
    Ok(ramflux_node_core::itest_http_post_json(
        &format!("{retention_url}/mvp7/retention/gc"),
        &ramflux_node_core::RetentionGcRequest { now },
    )?)
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp7_retention_finalize_identity_delete(
    retention_url: &str,
    subject_hash: &str,
) -> Result<ramflux_node_core::RetentionGcResponse, Box<dyn std::error::Error>> {
    Ok(ramflux_node_core::itest_http_post_json(
        &format!("{retention_url}/mvp7/retention/finalize_identity_delete"),
        &ramflux_node_core::RetentionIdentityDeleteRequest {
            subject_hash: subject_hash.to_owned(),
            lifecycle_epoch: 1,
            identity_deleted_event_id: format!("identity.deleted:{subject_hash}"),
            identity_lifecycle_tombstone_hash: ramflux_crypto::blake3_256_base64url(
                ramflux_protocol::domain::IDENTITY_DELETION_PROOF_TOMBSTONE,
                subject_hash.as_bytes(),
            ),
            retention_policy_id: "identity_lifecycle_tombstone.default_24_months".to_owned(),
            finalized_at: 0,
        },
    )?)
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp7_retention_record_value(
    record_id: &str,
    subject_hash: &str,
    expires_at: u64,
    legal_hold: bool,
) -> ramflux_node_core::RetentionMetadataRecord {
    ramflux_node_core::RetentionMetadataRecord {
        record_id: record_id.to_owned(),
        subject_hash: subject_hash.to_owned(),
        metadata_class: "router_inbox".to_owned(),
        source_service_id: "ramflux-router".to_owned(),
        retention_policy_id: "metadata.default_short".to_owned(),
        created_at: 1_760_000_000,
        expires_at,
        delete_after_ack: None,
        legal_hold,
        legal_hold_next_review_at: legal_hold.then_some(1_760_000_000 + 180 * 24 * 60 * 60),
        legal_basis: legal_hold.then_some("litigation_hold".to_owned()),
        legal_hold_actor: legal_hold.then_some("legal@example".to_owned()),
        legal_hold_created_at: legal_hold.then_some(1_760_000_000),
        metadata_hash: format!("hash_{record_id}"),
    }
}
