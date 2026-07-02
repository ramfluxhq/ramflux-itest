// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use super::*;

const PRINCIPAL_ID: &str = "mvp_s25_social_recovery";
const ROOT_KEY_ID: &str = "root-share";
const DEVICE_KEY_ID: &str = "device-share";
const GUARDIAN_KEY_ID: &str = "guardian-share";
const GUARDIAN_B_KEY_ID: &str = "guardian-b-share";
const ROOT_SEED: [u8; 32] = [0x11; 32];
const DEVICE_SEED: [u8; 32] = [0x22; 32];
const GUARDIAN_SEED: [u8; 32] = [0x33; 32];
const GUARDIAN_B_SEED: [u8; 32] = [0x44; 32];
const ROGUE_SEED: [u8; 32] = [0x55; 32];

#[cfg(feature = "realnet")]
#[test]
fn mvp_s25_realnet_social_recovery_quorum_reactivate() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    let realnet = start_realnet_compose()?;
    let gateway_url = &realnet.gateway_url;
    mvp7_register_lifecycle_actor_for(gateway_url, PRINCIPAL_ID, 250)?;

    let deactivated = mvp7_lifecycle_event_for(
        gateway_url,
        PRINCIPAL_ID,
        mvp7_lifecycle_step(
            "evt_s25_social_recovery_deactivated",
            "identity.deactivated",
            1,
            1_760_025_000,
            None,
        ),
    )?;
    assert_eq!(deactivated.record.state, ramflux_node_core::AccountLifecycleState::Deactivated);

    let quorum = sdk_recovery_quorum(
        "quorum_s25_social_recovery",
        &[
            member(ramflux_protocol::RecoveryQuorumMemberKind::RootShare, ROOT_KEY_ID, ROOT_SEED),
            member(
                ramflux_protocol::RecoveryQuorumMemberKind::DeviceShare,
                DEVICE_KEY_ID,
                DEVICE_SEED,
            ),
            member(
                ramflux_protocol::RecoveryQuorumMemberKind::GuardianShare,
                GUARDIAN_KEY_ID,
                GUARDIAN_SEED,
            ),
        ],
    )?;

    let context = recovery_context(
        "recovery_s25_positive",
        2,
        Some("evt_s25_social_recovery_deactivated"),
        Some(1_760_025_100),
    );
    assert_recovery_negative_cases(gateway_url, &quorum, &context)?;

    let reactivated = recovery_request(
        "evt_s25_social_recovery_reactivated",
        2,
        1_760_025_101,
        quorum,
        proof(
            context,
            &[
                (ramflux_protocol::RecoveryQuorumMemberKind::RootShare, ROOT_KEY_ID, ROOT_SEED),
                (
                    ramflux_protocol::RecoveryQuorumMemberKind::GuardianShare,
                    GUARDIAN_KEY_ID,
                    GUARDIAN_SEED,
                ),
            ],
        )?,
    );
    let response = post_lifecycle(gateway_url, &reactivated)?;
    assert_eq!(response.record.state, ramflux_node_core::AccountLifecycleState::Active);
    assert!(response.metadata_present);
    drop(realnet);
    Ok(())
}

#[cfg(feature = "realnet")]
fn assert_recovery_negative_cases(
    gateway_url: &str,
    quorum: &ramflux_protocol::RecoveryQuorumConfigured,
    context: &ramflux_protocol::RecoveryApprovalContext,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_recovery_is_rejected(
        gateway_url,
        &recovery_request(
            "evt_s25_social_recovery_early",
            2,
            1_760_025_099,
            quorum.clone(),
            proof(
                context.clone(),
                &[
                    (ramflux_protocol::RecoveryQuorumMemberKind::RootShare, ROOT_KEY_ID, ROOT_SEED),
                    (
                        ramflux_protocol::RecoveryQuorumMemberKind::GuardianShare,
                        GUARDIAN_KEY_ID,
                        GUARDIAN_SEED,
                    ),
                ],
            )?,
        ),
    );
    assert_recovery_is_rejected(
        gateway_url,
        &recovery_request(
            "evt_s25_social_recovery_k_minus_one",
            2,
            1_760_025_101,
            quorum.clone(),
            proof(
                context.clone(),
                &[(ramflux_protocol::RecoveryQuorumMemberKind::RootShare, ROOT_KEY_ID, ROOT_SEED)],
            )?,
        ),
    );
    assert_recovery_is_rejected(
        gateway_url,
        &recovery_request(
            "evt_s25_social_recovery_rogue",
            2,
            1_760_025_101,
            quorum.clone(),
            proof(
                context.clone(),
                &[
                    (
                        ramflux_protocol::RecoveryQuorumMemberKind::RootShare,
                        "rogue-root",
                        ROGUE_SEED,
                    ),
                    (
                        ramflux_protocol::RecoveryQuorumMemberKind::GuardianShare,
                        GUARDIAN_KEY_ID,
                        GUARDIAN_SEED,
                    ),
                ],
            )?,
        ),
    );
    assert_recovery_is_rejected(
        gateway_url,
        &recovery_request(
            "evt_s25_social_recovery_guardian_only",
            2,
            1_760_025_101,
            guardian_only_quorum()?,
            proof(
                context.clone(),
                &[
                    (
                        ramflux_protocol::RecoveryQuorumMemberKind::GuardianShare,
                        GUARDIAN_KEY_ID,
                        GUARDIAN_SEED,
                    ),
                    (
                        ramflux_protocol::RecoveryQuorumMemberKind::GuardianShare,
                        GUARDIAN_B_KEY_ID,
                        GUARDIAN_B_SEED,
                    ),
                ],
            )?,
        ),
    );
    Ok(())
}

#[cfg(feature = "realnet")]
fn assert_recovery_is_rejected(
    gateway_url: &str,
    request: &ramflux_node_core::LifecycleEventRequest,
) {
    assert!(post_lifecycle(gateway_url, request).is_err());
}

#[cfg(feature = "realnet")]
fn guardian_only_quorum()
-> Result<ramflux_protocol::RecoveryQuorumConfigured, ramflux_sdk::SdkError> {
    sdk_recovery_quorum(
        "quorum_s25_guardian_only",
        &[
            member(
                ramflux_protocol::RecoveryQuorumMemberKind::GuardianShare,
                GUARDIAN_KEY_ID,
                GUARDIAN_SEED,
            ),
            member(
                ramflux_protocol::RecoveryQuorumMemberKind::GuardianShare,
                GUARDIAN_B_KEY_ID,
                GUARDIAN_B_SEED,
            ),
            member(
                ramflux_protocol::RecoveryQuorumMemberKind::DeviceShare,
                DEVICE_KEY_ID,
                DEVICE_SEED,
            ),
        ],
    )
}

#[cfg(feature = "realnet")]
fn post_lifecycle(
    gateway_url: &str,
    request: &ramflux_node_core::LifecycleEventRequest,
) -> Result<ramflux_node_core::LifecycleResponse, Box<dyn std::error::Error>> {
    Ok(ramflux_node_core::itest_http_post_json(
        &format!("{gateway_url}/mvp7/lifecycle/event"),
        request,
    )?)
}

#[cfg(feature = "realnet")]
fn recovery_request(
    event_id: &str,
    lifecycle_epoch: u64,
    now: u64,
    recovery_quorum: ramflux_protocol::RecoveryQuorumConfigured,
    recovery_quorum_proof: ramflux_protocol::RecoveryQuorumProof,
) -> ramflux_node_core::LifecycleEventRequest {
    ramflux_node_core::LifecycleEventRequest {
        principal_id: PRINCIPAL_ID.to_owned(),
        event_id: event_id.to_owned(),
        event_type: "identity.reactivated".to_owned(),
        actor_device_id: mvp7_lifecycle_actor_device_id(PRINCIPAL_ID),
        lifecycle_epoch,
        now,
        reason_code: "social_recovery".to_owned(),
        timelock_seconds: None,
        recovery_quorum: Some(recovery_quorum),
        recovery_quorum_proof: Some(recovery_quorum_proof),
    }
}

#[cfg(feature = "realnet")]
fn sdk_recovery_quorum(
    recovery_quorum_id: &str,
    members: &[ramflux_sdk::SdkRecoveryQuorumMember],
) -> Result<ramflux_protocol::RecoveryQuorumConfigured, ramflux_sdk::SdkError> {
    Ok(ramflux_sdk::RamfluxClient::configure_recovery_quorum(
        recovery_quorum_id,
        [0x7a; 32],
        2,
        members,
    )?
    .recovery_quorum)
}

#[cfg(feature = "realnet")]
fn recovery_context(
    recovery_id: &str,
    lifecycle_epoch: u64,
    lineage_head: Option<&str>,
    timelock_until: Option<u64>,
) -> ramflux_protocol::RecoveryApprovalContext {
    ramflux_protocol::RecoveryApprovalContext {
        recovery_id: recovery_id.to_owned(),
        event_type: "identity.reactivated".to_owned(),
        principal_id: PRINCIPAL_ID.to_owned(),
        lifecycle_epoch,
        lineage_head: lineage_head.map(str::to_owned),
        timelock_until,
    }
}

#[cfg(feature = "realnet")]
fn proof(
    context: ramflux_protocol::RecoveryApprovalContext,
    approvals: &[(ramflux_protocol::RecoveryQuorumMemberKind, &str, [u8; 32])],
) -> Result<ramflux_protocol::RecoveryQuorumProof, ramflux_sdk::SdkError> {
    let approvals = approvals
        .iter()
        .map(|(member_kind, signing_key_id, seed)| {
            ramflux_sdk::RamfluxClient::approve_recovery(
                member_kind.clone(),
                signing_key_id,
                *seed,
                &context,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ramflux_sdk::RamfluxClient::build_recovery_proof(context, approvals))
}

#[cfg(feature = "realnet")]
fn member(
    member_kind: ramflux_protocol::RecoveryQuorumMemberKind,
    signing_key_id: &str,
    seed: [u8; 32],
) -> ramflux_sdk::SdkRecoveryQuorumMember {
    ramflux_sdk::SdkRecoveryQuorumMember {
        member_kind,
        signing_key_id: signing_key_id.to_owned(),
        public_key_base64url: ramflux_sdk::recovery_member_public_key_base64url(seed),
    }
}
