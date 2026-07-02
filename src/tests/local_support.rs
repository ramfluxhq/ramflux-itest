// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use super::*;

#[cfg(all(test, feature = "realnet"))]
pub(super) fn mvp7_assert_federated_deleted_tombstone(
    gateway_url: &str,
    federation_url: &str,
) -> Result<Mvp7DeletedTombstoneFixture, Box<dyn std::error::Error>> {
    let before: ramflux_node_core::ItestMvp0SubmitResponse =
        ramflux_node_core::itest_http_post_json(
            &format!("{gateway_url}/mvp0/envelope"),
            &itest_envelope("env_mvp7_fed_before", "target_mvp7_fed_remote"),
        )?;
    assert_eq!(before.outcome, "offline_queued");

    let deleted = mvp7_deleted_tombstone_fixture(gateway_url, "mvp7_federated_deleted")?;
    let request = ramflux_node_core::FederatedLifecycleTombstoneRequest {
        source_node_id: "node_a.realnet".to_owned(),
        target_delivery_id: "target_mvp7_fed_remote".to_owned(),
        lifecycle_state: ramflux_node_core::AccountLifecycleState::Deleted,
        tombstone: Some(deleted.tombstone.clone()),
        deletion_proof: Some(deleted.deletion_proof.clone()),
    };
    let propagated = mvp7_post_federated_tombstone(federation_url, &request)?;
    assert!(propagated.accepted);
    assert_eq!(propagated.lifecycle_state, ramflux_node_core::AccountLifecycleState::Deleted);
    assert_eq!(propagated.tombstone_hash, Some(deleted.tombstone.tombstone_hash.clone()));
    let stored: Option<ramflux_node_core::FederatedLifecycleTombstoneResponse> =
        ramflux_node_core::itest_http_get_json(&format!(
            "{federation_url}/mvp7/federation/tombstone/target_mvp7_fed_remote"
        ))?;
    assert_eq!(stored, Some(propagated));
    let rejected: ramflux_node_core::ItestMvp0SubmitResponse =
        ramflux_node_core::itest_http_post_json(
            &format!("{gateway_url}/mvp0/envelope"),
            &itest_envelope("env_mvp7_fed_after_delete", "target_mvp7_fed_remote"),
        )?;
    assert_eq!(rejected.outcome, "rejected_deleted");
    Ok(deleted)
}

#[cfg(all(test, feature = "realnet"))]
pub(super) fn mvp7_assert_invalid_federated_tombstone_is_rejected(
    gateway_url: &str,
    federation_url: &str,
    deleted: Mvp7DeletedTombstoneFixture,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut forged = deleted.tombstone.clone();
    forged.reason = "tampered".to_owned();
    let invalid = ramflux_node_core::itest_http_post_json::<_, serde_json::Value>(
        &format!("{federation_url}/mvp7/federation/tombstone"),
        &ramflux_node_core::FederatedLifecycleTombstoneRequest {
            source_node_id: "node_a.realnet".to_owned(),
            target_delivery_id: "target_mvp7_invalid_remote".to_owned(),
            lifecycle_state: ramflux_node_core::AccountLifecycleState::Deleted,
            tombstone: Some(forged),
            deletion_proof: Some(deleted.deletion_proof),
        },
    );
    assert!(invalid.is_err());
    let still_open: ramflux_node_core::ItestMvp0SubmitResponse =
        ramflux_node_core::itest_http_post_json(
            &format!("{gateway_url}/mvp0/envelope"),
            &itest_envelope("env_mvp7_invalid_still_open", "target_mvp7_invalid_remote"),
        )?;
    assert_eq!(still_open.outcome, "offline_queued");
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(super) fn mvp7_assert_federated_deactivate_reactivate(
    gateway_url: &str,
    federation_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let deactivated = mvp7_lifecycle_event_for(
        gateway_url,
        "mvp7_federated_deactivated",
        mvp7_lifecycle_step(
            "evt_mvp7_fed_deactivated",
            "identity.deactivated",
            1,
            1_760_001_000,
            None,
        ),
    )?;
    let deactivated_tombstone = deactivated.tombstone.ok_or("missing deactivated tombstone")?;
    let deactivate_request = ramflux_node_core::FederatedLifecycleTombstoneRequest {
        source_node_id: "node_a.realnet".to_owned(),
        target_delivery_id: "target_mvp7_deactivated_remote".to_owned(),
        lifecycle_state: ramflux_node_core::AccountLifecycleState::Deactivated,
        tombstone: Some(deactivated_tombstone),
        deletion_proof: None,
    };
    mvp7_post_federated_tombstone(federation_url, &deactivate_request)?;
    let paused: ramflux_node_core::ItestMvp0SubmitResponse =
        ramflux_node_core::itest_http_post_json(
            &format!("{gateway_url}/mvp0/envelope"),
            &itest_envelope("env_mvp7_paused", "target_mvp7_deactivated_remote"),
        )?;
    assert_eq!(paused.outcome, "rejected_deactivated");
    let reactivate_request = ramflux_node_core::FederatedLifecycleTombstoneRequest {
        source_node_id: "node_a.realnet".to_owned(),
        target_delivery_id: "target_mvp7_deactivated_remote".to_owned(),
        lifecycle_state: ramflux_node_core::AccountLifecycleState::Active,
        tombstone: None,
        deletion_proof: None,
    };
    mvp7_post_federated_tombstone(federation_url, &reactivate_request)?;
    let resumed: ramflux_node_core::ItestMvp0SubmitResponse =
        ramflux_node_core::itest_http_post_json(
            &format!("{gateway_url}/mvp0/envelope"),
            &itest_envelope("env_mvp7_resumed", "target_mvp7_deactivated_remote"),
        )?;
    assert_eq!(resumed.outcome, "offline_queued");
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(super) fn mvp7_assert_lifecycle_delete_path(
    gateway_url: &str,
) -> Result<ramflux_node_core::IdentityDeletionProof, Box<dyn std::error::Error>> {
    let queued: ramflux_node_core::ItestMvp0SubmitResponse =
        ramflux_node_core::itest_http_post_json(
            &format!("{gateway_url}/mvp0/envelope"),
            &itest_envelope("env_mvp7_before_delete", "target_mvp7_delete"),
        )?;
    assert_eq!(queued.outcome, "online");
    assert_eq!(queued.inbox_seq, Some(1));

    let deactivated = mvp7_lifecycle_event(
        gateway_url,
        mvp7_lifecycle_step("evt_mvp7_deactivated", "identity.deactivated", 1, 1_760_000_000, None),
    )?;
    assert_eq!(deactivated.record.state, ramflux_node_core::AccountLifecycleState::Deactivated);
    assert!(deactivated.metadata_present);
    let reactivated = mvp7_lifecycle_event(
        gateway_url,
        mvp7_lifecycle_step("evt_mvp7_reactivated", "identity.reactivated", 2, 1_760_000_010, None),
    )?;
    assert_eq!(reactivated.record.state, ramflux_node_core::AccountLifecycleState::Active);
    assert!(reactivated.metadata_present);

    let pending = mvp7_lifecycle_event(
        gateway_url,
        mvp7_lifecycle_step(
            "evt_mvp7_delete_pending",
            "identity.deleted",
            3,
            1_760_000_020,
            Some(10),
        ),
    )?;
    assert_eq!(pending.record.state, ramflux_node_core::AccountLifecycleState::DeletePending);
    assert!(pending.metadata_present);
    let early_finalize = ramflux_node_core::itest_http_post_json::<_, serde_json::Value>(
        &format!("{gateway_url}/mvp7/lifecycle/finalize"),
        &ramflux_node_core::LifecycleFinalizeRequest {
            principal_id: "mvp7_delete_principal".to_owned(),
            now: 1_760_000_025,
        },
    );
    assert!(early_finalize.is_err());
    let cancelled = mvp7_cancel_delete(gateway_url, "mvp7_delete_principal", 1_760_000_026)?;
    assert_eq!(cancelled.record.state, ramflux_node_core::AccountLifecycleState::Active);

    let pending = mvp7_lifecycle_event(
        gateway_url,
        mvp7_lifecycle_step(
            "evt_mvp7_delete_final",
            "identity.deleted",
            5,
            1_760_000_100,
            Some(10),
        ),
    )?;
    let tombstone_hash =
        pending.record.tombstone_hash.clone().ok_or_else(|| "missing tombstone hash".to_owned())?;
    let finalized = mvp7_finalize_delete(gateway_url, "mvp7_delete_principal", 1_760_000_111)?;
    assert_eq!(finalized.record.state, ramflux_node_core::AccountLifecycleState::Deleted);
    assert!(!finalized.metadata_present);
    let proof = finalized
        .record
        .deletion_proof
        .clone()
        .ok_or_else(|| "missing deletion proof".to_owned())?;
    assert_eq!(proof.tombstone_hash, tombstone_hash);
    ramflux_crypto::verify_canonical_signature(
        &ramflux_protocol::signed_bytes(&proof)?,
        &proof.signature,
        &ramflux_crypto::fixture_public_key_base64url(),
    )?;
    let metadata = mvp7_metadata(gateway_url, "mvp7_delete_principal")?;
    assert!(!metadata.metadata_present);
    assert!(!metadata.session_bound);
    assert_eq!(metadata.pending_inbox_count, 0);
    assert_eq!(metadata.tombstone_hash, Some(tombstone_hash));
    assert_eq!(metadata.deletion_proof_hash, Some(proof.proof_hash.clone()));
    let rejected: ramflux_node_core::ItestMvp0SubmitResponse =
        ramflux_node_core::itest_http_post_json(
            &format!("{gateway_url}/mvp0/envelope"),
            &itest_envelope("env_mvp7_after_delete", "target_mvp7_delete"),
        )?;
    assert_eq!(rejected.outcome, "rejected_deleted");
    assert_eq!(rejected.inbox_seq, None);
    Ok(proof)
}

#[cfg(all(test, feature = "realnet"))]
pub(super) fn mvp7_assert_retention_gc(
    retention_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    mvp7_retention_record(
        retention_url,
        mvp7_retention_record_value("expired", "mvp7_delete_principal", 1_760_000_010, false),
    )?;
    mvp7_retention_record(
        retention_url,
        mvp7_retention_record_value("legal_hold", "mvp7_delete_principal", 1_760_000_010, true),
    )?;
    mvp7_retention_record(
        retention_url,
        mvp7_retention_record_value("live", "mvp7_delete_principal", 1_760_001_000, false),
    )?;
    let gc = mvp7_retention_gc(retention_url, 1_760_000_020)?;
    assert_eq!(gc.deleted_record_ids, vec!["expired"]);
    assert_eq!(gc.retained_legal_hold_ids, vec!["legal_hold"]);
    let finalized_gc =
        mvp7_retention_finalize_identity_delete(retention_url, "mvp7_delete_principal")?;
    assert_eq!(finalized_gc.deleted_record_ids, vec!["live"]);
    assert_eq!(finalized_gc.retained_legal_hold_ids, vec!["legal_hold"]);
    assert_eq!(finalized_gc.remaining_count, 1);
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(super) fn mvp7_assert_franking_report_pipeline(
    gateway_url: &str,
    retention_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = mvp7_franking_report_fixture();
    let mut envelope = itest_envelope("env_mvp7_franking_report", "target_mvp7_franking");
    envelope.encrypted_payload = fixture.opaque_ciphertext.clone();
    envelope.payload_hash = ramflux_crypto::blake3_256_base64url(
        ramflux_protocol::domain::ENVELOPE,
        envelope.encrypted_payload.as_bytes(),
    );
    let submit: ramflux_node_core::ItestMvp0SubmitResponse =
        ramflux_node_core::itest_http_post_json(
            &format!("{gateway_url}/mvp0/envelope"),
            &envelope,
        )?;
    assert_eq!(submit.outcome, "offline_queued");
    assert_eq!(submit.inbox_seq, Some(1));
    assert_node_opaque_payload(&envelope.encrypted_payload, fixture.plaintext.as_bytes());

    let verified =
        mvp7_post_abuse_report(gateway_url, "report_mvp7_franking_verified", &fixture.evidence)?;
    assert_eq!(verified.report.status, ramflux_node_core::FrankingReportStatus::Verified);
    assert_eq!(
        verified.report.verified_commitment.as_deref(),
        Some(fixture.evidence.commitment.as_str())
    );
    assert_eq!(verified.retention_record.metadata_class, "selected_evidence");
    mvp7_retention_record(retention_url, verified.retention_record.clone())?;

    let stored: Option<ramflux_node_core::AbuseReportRecord> =
        ramflux_node_core::itest_http_get_json(&format!(
            "{gateway_url}/mvp7/abuse/report/report_mvp7_franking_verified"
        ))?;
    assert_eq!(
        stored.as_ref().map(|record| record.status),
        Some(ramflux_node_core::FrankingReportStatus::Verified)
    );

    let mut forged_plaintext = fixture.evidence.clone();
    forged_plaintext.plaintext_excerpt.push_str(" forged");
    let rejected_plaintext = mvp7_post_abuse_report(
        gateway_url,
        "report_mvp7_franking_plaintext_forged",
        &forged_plaintext,
    )?;
    assert_eq!(rejected_plaintext.report.status, ramflux_node_core::FrankingReportStatus::Rejected);
    assert!(rejected_plaintext.report.verified_commitment.is_none());

    let mut group_without_signature = fixture.evidence.clone();
    group_without_signature.evidence_kind =
        ramflux_node_core::FrankingEvidenceKind::SenderBoundGroup;
    group_without_signature.group_header_signature = None;
    let rejected_group = mvp7_post_abuse_report(
        gateway_url,
        "report_mvp7_franking_group_unbound",
        &group_without_signature,
    )?;
    assert_eq!(rejected_group.report.status, ramflux_node_core::FrankingReportStatus::Rejected);

    let gc = mvp7_retention_gc(retention_url, 1_768_000_000)?;
    assert!(gc.deleted_record_ids.contains(&verified.retention_record.record_id));
    Ok(())
}
