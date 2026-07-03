// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use super::*;

#[cfg(all(test, feature = "realnet"))]
pub(super) fn mvp7_assert_federated_deleted_tombstone(
    gateway_url: &str,
    federation_url: &str,
) -> Result<Mvp7DeletedTombstoneFixture, Box<dyn std::error::Error>> {
    let before: ramflux_node_core::EnvelopeSubmitResponse =
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
    let rejected: ramflux_node_core::EnvelopeSubmitResponse =
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
    let still_open: ramflux_node_core::EnvelopeSubmitResponse =
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
    let paused: ramflux_node_core::EnvelopeSubmitResponse =
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
    let resumed: ramflux_node_core::EnvelopeSubmitResponse =
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
    let queued: ramflux_node_core::EnvelopeSubmitResponse =
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
    let rejected: ramflux_node_core::EnvelopeSubmitResponse =
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
pub(super) async fn mvp7_assert_franking_report_pipeline(
    gateway_url: &str,
    retention_url: &str,
    gateway_quic_addr: std::net::SocketAddr,
    ca_cert: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let evidence = mvp7_real_franking_evidence_from_received_dm(gateway_quic_addr, ca_cert).await?;
    assert_eq!(evidence.node_id, "localhost");
    assert_eq!(evidence.envelope_id, "env_mvp7_franking_report");
    assert_eq!(evidence.plaintext_excerpt, "mvp7 explicitly selected reported excerpt");
    assert!(!evidence.franking_tag.is_empty());
    assert!(evidence.franking_timestamp > 1_700_000_000_000);

    let verified = mvp7_post_abuse_report(gateway_url, "report_mvp7_franking_verified", &evidence)?;
    assert_eq!(verified.report.status, ramflux_node_core::FrankingReportStatus::Verified);
    assert_eq!(verified.report.verified_commitment.as_deref(), Some(evidence.commitment.as_str()));
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

    let mut forged_plaintext = evidence.clone();
    forged_plaintext.plaintext_excerpt.push_str(" forged");
    let rejected_plaintext = mvp7_post_abuse_report(
        gateway_url,
        "report_mvp7_franking_plaintext_forged",
        &forged_plaintext,
    )?;
    assert_eq!(rejected_plaintext.report.status, ramflux_node_core::FrankingReportStatus::Rejected);
    assert!(rejected_plaintext.report.verified_commitment.is_none());

    let mut group_without_signature = evidence.clone();
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

#[cfg(all(test, feature = "realnet"))]
#[allow(clippy::too_many_lines)]
async fn mvp7_real_franking_evidence_from_received_dm(
    gateway_quic_addr: std::net::SocketAddr,
    ca_cert: &Path,
) -> Result<Mvp7SelectedFrankingEvidence, Box<dyn std::error::Error>> {
    let temp_root = temp_root("mvp7_real_franking_e2e")?;
    let alice_socket = temp_root.join("alice/rfd.sock");
    let bob_socket = temp_root.join("bob/rfd.sock");
    let (alice_shutdown_tx, alice_shutdown_rx) = tokio::sync::watch::channel(false);
    let (bob_shutdown_tx, bob_shutdown_rx) = tokio::sync::watch::channel(false);
    let alice_server = ramflux_sdk::serve_local_bus_until(
        ramflux_sdk::LocalBusConfig::new(&alice_socket, temp_root.join("alice/data")),
        alice_shutdown_rx,
    );
    let bob_server = ramflux_sdk::serve_local_bus_until(
        ramflux_sdk::LocalBusConfig::new(&bob_socket, temp_root.join("bob/data")),
        bob_shutdown_rx,
    );

    let flow = async {
        let result = async {
            mvp_s4_wait_for_socket(&alice_socket).await?;
            mvp_s4_wait_for_socket(&bob_socket).await?;
            let mut alice = ramflux_sdk::LocalBusClient::connect(&alice_socket).await?;
            let mut bob = ramflux_sdk::LocalBusClient::connect(&bob_socket).await?;
            let alice_commitment = mvp7_create_bus_account(
                &mut alice,
                gateway_quic_addr,
                ca_cert,
                "alice_mvp7_franking_account",
                "alice_mvp7_franking",
                "alice_device_mvp7_franking",
                "target_mvp7_franking_alice",
                [0x71; 32],
                [0x72; 32],
            )
            .await?;
            let bob_commitment = mvp7_create_bus_account(
                &mut bob,
                gateway_quic_addr,
                ca_cert,
                "bob_mvp7_franking_account",
                "bob_mvp7_franking",
                "bob_device_mvp7_franking",
                "target_mvp7_franking_bob",
                [0x81; 32],
                [0x82; 32],
            )
            .await?;
            let _ = alice_commitment;
            mvp7_add_bus_contact(
                &mut alice,
                "alice_mvp7_franking_account",
                "friend_link_mvp7_franking",
                "alice_mvp7_franking",
                "bob_mvp7_franking",
            )
            .await?;
            mvp7_add_bus_contact(
                &mut bob,
                "bob_mvp7_franking_account",
                "friend_link_mvp7_franking",
                "alice_mvp7_franking",
                "bob_mvp7_franking",
            )
            .await?;
            let created_at = realnet_now_i64();
            let submitted = alice
                .request(
                    Some("alice_mvp7_franking_account".to_owned()),
                    "message",
                    "message.submit",
                    &ramflux_sdk::LocalBusMessageSubmitRequest {
                        conversation_id: "conv_mvp7_franking".to_owned(),
                        message_id: "env_mvp7_franking_report".to_owned(),
                        envelope_id: "env_mvp7_franking_report".to_owned(),
                        source_principal_id: "alice_mvp7_franking".to_owned(),
                        sender_id: "alice_device_mvp7_franking".to_owned(),
                        recipient_device_id: Some("bob_device_mvp7_franking".to_owned()),
                        recipient_principal_commitment: Some(bob_commitment),
                        target_delivery_id: "target_mvp7_franking_bob".to_owned(),
                        encrypted_body_base64: String::new(),
                        plaintext_body_base64: Some(ramflux_protocol::encode_base64url(
                            b"mvp7 explicitly selected reported excerpt",
                        )),
                        created_at,
                        ttl: 3_600,
                        attachments: Vec::new(),
                        federation: None,
                    },
                )
                .await?;
            assert_eq!(submitted["envelope"]["envelope_id"], "env_mvp7_franking_report");

            let received = bob
                .request(
                    Some("bob_mvp7_franking_account".to_owned()),
                    "message",
                    "message.receive",
                    &ramflux_sdk::LocalBusMessageReceiveRequest {
                        limit: 8,
                        conversation_id: Some("conv_mvp7_franking".to_owned()),
                        auto_fetch_attachments: false,
                        relay_service_key_base64: None,
                    },
                )
                .await?;
            let decrypted = received["decrypted_messages"]
                .as_array()
                .ok_or_else(|| std::io::Error::other("decrypted_messages missing"))?;
            assert_eq!(decrypted.len(), 1);
            assert_eq!(
                decrypted[0]["plaintext_body_base64"],
                ramflux_protocol::encode_base64url(b"mvp7 explicitly selected reported excerpt")
            );
            let evidence_value = bob
                .request(
                    Some("bob_mvp7_franking_account".to_owned()),
                    "message",
                    "message.franking_evidence",
                    &serde_json::json!({
                        "conversation_id": "conv_mvp7_franking",
                        "message_id": "env_mvp7_franking_report"
                    }),
                )
                .await?;
            let evidence: Mvp7SelectedFrankingEvidence = serde_json::from_value(evidence_value)?;
            Ok::<Mvp7SelectedFrankingEvidence, Box<dyn std::error::Error>>(evidence)
        }
        .await;
        let _ = alice_shutdown_tx.send(true);
        let _ = bob_shutdown_tx.send(true);
        result
    };
    let (alice_result, bob_result, flow_result) =
        tokio::time::timeout(std::time::Duration::from_mins(2), async {
            tokio::join!(alice_server, bob_server, flow)
        })
        .await
        .map_err(|_elapsed| "mvp7 franking e2e local bus flow timed out")?;
    alice_result?;
    bob_result?;
    let evidence = flow_result?;
    std::fs::remove_dir_all(temp_root)?;
    Ok(evidence)
}

#[cfg(all(test, feature = "realnet"))]
#[allow(clippy::too_many_arguments)]
async fn mvp7_create_bus_account(
    bus: &mut ramflux_sdk::LocalBusClient,
    gateway_quic_addr: std::net::SocketAddr,
    ca_cert: &Path,
    local_account_id: &str,
    principal_id: &str,
    device_id: &str,
    target_delivery_id: &str,
    root_seed: [u8; 32],
    device_seed: [u8; 32],
) -> Result<String, Box<dyn std::error::Error>> {
    let response: ramflux_sdk::LocalBusAccountCreateResponse = serde_json::from_value(
        bus.request(
            None,
            "account",
            "account.create",
            &ramflux_sdk::LocalBusAccountCreateRequest {
                local_account_id: local_account_id.to_owned(),
                principal_id: principal_id.to_owned(),
                principal_commitment: String::new(),
                device_id: device_id.to_owned(),
                target_delivery_id: target_delivery_id.to_owned(),
                account_secret: "mvp7-franking-secret".to_owned(),
                root_seed,
                device_seed,
                client_mode: ramflux_sdk::LocalBusClientMode::AttendedCli,
                gateway: ramflux_sdk::GatewayQuicEndpointConfig {
                    bind_addr: std::net::SocketAddr::from(([0, 0, 0, 0], 0)),
                    gateway_addr: gateway_quic_addr,
                    server_name: "localhost".to_owned(),
                    ca_cert: ca_cert.to_path_buf(),
                    principal_id: principal_id.to_owned(),
                    device_id: device_id.to_owned(),
                    target_delivery_id: target_delivery_id.to_owned(),
                    prekey_http_url: None,
                },
            },
        )
        .await?,
    )?;
    assert_eq!(response.local_account_id, local_account_id);
    assert_eq!(response.device_id, device_id);
    Ok(response.principal_commitment)
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp7_add_bus_contact(
    bus: &mut ramflux_sdk::LocalBusClient,
    account_id: &str,
    link_id: &str,
    requester_id: &str,
    target_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let contact = bus
        .request(
            Some(account_id.to_owned()),
            "contact",
            "contact.add",
            &ramflux_sdk::LocalBusContactAddRequest {
                link_id: link_id.to_owned(),
                requester_id: requester_id.to_owned(),
                target_id: target_id.to_owned(),
            },
        )
        .await?;
    assert_eq!(contact["state"], "accepted");
    Ok(())
}
