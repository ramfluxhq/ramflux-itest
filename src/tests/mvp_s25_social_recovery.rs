// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
// Fixtures below are consumed only by the realnet-gated test in this module; keep them
// available in all test builds but silence dead_code when the realnet tests are compiled out.
#![cfg_attr(not(feature = "realnet"), allow(dead_code))]
use super::*;

const PRINCIPAL_ID: &str = "mvp_s25_social_recovery";
const RECOVERY_QUORUM_ID: &str = "quorum_s25_social_recovery";
const RECOVERY_SECRET: [u8; 32] = [0x7a; 32];
const ROOT_KEY_ID: &str = "root-share";
const ROOT_SEED: [u8; 32] = [0x11; 32];
const OWNER_DEVICE_SEED: [u8; 32] = [0x21; 32];
const GUARDIAN_PRINCIPAL_ID: &str = "guardian_s25_social_recovery";
const GUARDIAN_DEVICE_ID: &str = "guardian_device_s25_social_recovery";
const GUARDIAN_SEED: [u8; 32] = [0x33; 32];
const GUARDIAN_B_PRINCIPAL_ID: &str = "guardian_b_s25_social_recovery";
const GUARDIAN_B_DEVICE_ID: &str = "guardian_b_device_s25_social_recovery";
const GUARDIAN_B_SEED: [u8; 32] = [0x44; 32];

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

    let now = now_unix_u64()?;
    let deactivated = mvp7_lifecycle_event_for(
        gateway_url,
        PRINCIPAL_ID,
        mvp7_lifecycle_step(
            "evt_s25_social_recovery_deactivated",
            "identity.deactivated",
            1,
            now,
            None,
        ),
    )?;
    assert_eq!(deactivated.record.state, ramflux_node_core::AccountLifecycleState::Deactivated);

    let root = temp_root("s25_social_recovery")?;
    let owner = sdk_recovery_client(
        &root,
        "owner",
        PRINCIPAL_ID,
        &mvp7_lifecycle_actor_device_id(PRINCIPAL_ID),
        OWNER_DEVICE_SEED,
    )?;
    let guardian = sdk_recovery_client(
        &root,
        "guardian_a",
        GUARDIAN_PRINCIPAL_ID,
        GUARDIAN_DEVICE_ID,
        GUARDIAN_SEED,
    )?;
    let guardian_b = sdk_recovery_client(
        &root,
        "guardian_b",
        GUARDIAN_B_PRINCIPAL_ID,
        GUARDIAN_B_DEVICE_ID,
        GUARDIAN_B_SEED,
    )?;

    let configured =
        configure_owner_quorum(&owner, &[guardian_member(GUARDIAN_DEVICE_ID, GUARDIAN_SEED)])?;
    accept_guardian_share_e2ee(
        &owner,
        &guardian,
        &configured,
        GUARDIAN_PRINCIPAL_ID,
        now.saturating_add(300),
    )?;

    assert_recovery_negative_cases(gateway_url, now, &owner, &guardian, &guardian_b)?;

    let finalized = finalize_recovery_happy_path(&owner, &guardian, &configured.recovery_quorum)?;
    let request = recovery_request(
        "evt_s25_social_recovery_reactivated",
        2,
        now.saturating_add(1),
        finalized.recovery_quorum,
        finalized.proof,
    );
    let response = post_lifecycle(gateway_url, &request)?;
    assert_eq!(response.record.state, ramflux_node_core::AccountLifecycleState::Active);
    assert!(response.metadata_present);
    let event_types =
        response.lineage_events.iter().map(|event| event.event_type.as_str()).collect::<Vec<_>>();
    assert_eq!(
        event_types,
        vec![
            "recovery.initiated",
            "recovery.finalized",
            "identity.recovery_authorized",
            "identity.reactivated",
        ]
    );
    assert_eq!(
        response.lineage_events[0].previous_lineage_head.as_deref(),
        Some("evt_s25_social_recovery_deactivated")
    );
    for window in response.lineage_events.windows(2) {
        assert_eq!(
            window[1].previous_lineage_head.as_deref(),
            Some(window[0].lineage_head.as_str())
        );
    }
    let recovery_lineage_head =
        response.recovery_lineage_head.as_deref().ok_or("missing recovery lineage head")?;
    assert_eq!(
        response.lineage_events.last().map(|event| event.lineage_head.as_str()),
        Some(recovery_lineage_head)
    );
    assert_ne!(recovery_lineage_head, "evt_s25_social_recovery_deactivated");

    drop(realnet);
    let _ = std::fs::remove_dir_all(root);
    Ok(())
}

#[cfg(feature = "realnet")]
fn assert_recovery_negative_cases(
    gateway_url: &str,
    now: u64,
    owner: &ramflux_sdk::RamfluxClient,
    guardian: &ramflux_sdk::RamfluxClient,
    guardian_b: &ramflux_sdk::RamfluxClient,
) -> Result<(), Box<dyn std::error::Error>> {
    let future_timelock = run_recovery_collection(
        owner,
        guardian,
        "recovery_s25_future_timelock",
        now.saturating_add(60),
    )?;
    assert!(owner.finalize_recovery("recovery_s25_future_timelock").is_err());
    assert_recovery_is_rejected(
        gateway_url,
        &recovery_request(
            "evt_s25_social_recovery_early",
            2,
            now.saturating_add(1),
            future_timelock.recovery_quorum,
            future_timelock.proof,
        ),
    );

    let shortfall = run_shortfall_collection(owner, guardian, "recovery_s25_k_minus_one", now)?;
    assert!(owner.finalize_recovery("recovery_s25_k_minus_one").is_err());
    assert_recovery_is_rejected(
        gateway_url,
        &recovery_request(
            "evt_s25_social_recovery_k_minus_one",
            2,
            now.saturating_add(1),
            shortfall.recovery_quorum,
            shortfall.proof,
        ),
    );

    let guardian_only = run_guardian_only_collection(owner, guardian, guardian_b, now)?;
    assert!(owner.finalize_recovery("recovery_s25_guardian_only").is_err());
    assert_recovery_is_rejected(
        gateway_url,
        &recovery_request(
            "evt_s25_social_recovery_guardian_only",
            2,
            now.saturating_add(1),
            guardian_only.recovery_quorum,
            guardian_only.proof,
        ),
    );
    Ok(())
}

#[cfg(feature = "realnet")]
fn finalize_recovery_happy_path(
    owner: &ramflux_sdk::RamfluxClient,
    guardian: &ramflux_sdk::RamfluxClient,
    recovery_quorum: &ramflux_protocol::RecoveryQuorumConfigured,
) -> Result<ramflux_sdk::SdkFinalizedRecovery, Box<dyn std::error::Error>> {
    let collected = run_recovery_collection(
        owner,
        guardian,
        "recovery_s25_positive",
        now_unix_u64()?.saturating_sub(1),
    )?;
    assert_eq!(collected.recovery_quorum, *recovery_quorum);
    let state = owner.recovery_state("recovery_s25_positive")?;
    assert_eq!(state.state, ramflux_sdk::SdkPendingRecoveryState::QuorumReached);
    assert!(state.ready_to_finalize);
    let finalized = owner.finalize_recovery("recovery_s25_positive")?;
    assert_eq!(finalized.proof.context.recovery_id, "recovery_s25_positive");
    assert_eq!(
        owner.recovery_state("recovery_s25_positive")?.state,
        ramflux_sdk::SdkPendingRecoveryState::ReadyToFinalize
    );
    Ok(finalized)
}

#[cfg(feature = "realnet")]
fn run_recovery_collection(
    owner: &ramflux_sdk::RamfluxClient,
    guardian: &ramflux_sdk::RamfluxClient,
    recovery_id: &str,
    timelock_until: u64,
) -> Result<CollectedRecovery, Box<dyn std::error::Error>> {
    let recovery_quorum = owner_recovery_quorum(GUARDIAN_DEVICE_ID, GUARDIAN_SEED)?;
    let context =
        initiate_collecting_recovery(owner, recovery_id, recovery_quorum.clone(), timelock_until)?;
    let root_approval = ramflux_sdk::RamfluxClient::approve_recovery(
        ramflux_protocol::RecoveryQuorumMemberKind::RootShare,
        ROOT_KEY_ID,
        ROOT_SEED,
        &context,
    )?;
    owner.collect_recovery_approval(recovery_id, &root_approval)?;
    let guardian_approval =
        guardian.guardian_approve_recovery(PRINCIPAL_ID, RECOVERY_QUORUM_ID, &context)?;
    let quorum_reached = owner.collect_guardian_approval(recovery_id, &guardian_approval)?;
    assert_eq!(quorum_reached.state, ramflux_sdk::SdkPendingRecoveryState::QuorumReached);
    Ok(CollectedRecovery {
        recovery_quorum,
        proof: ramflux_sdk::RamfluxClient::build_recovery_proof(
            context,
            vec![root_approval, guardian_approval],
        ),
    })
}

#[cfg(feature = "realnet")]
fn run_shortfall_collection(
    owner: &ramflux_sdk::RamfluxClient,
    _guardian: &ramflux_sdk::RamfluxClient,
    recovery_id: &str,
    now: u64,
) -> Result<CollectedRecovery, Box<dyn std::error::Error>> {
    let recovery_quorum = owner_recovery_quorum(GUARDIAN_DEVICE_ID, GUARDIAN_SEED)?;
    let context = initiate_collecting_recovery(
        owner,
        recovery_id,
        recovery_quorum.clone(),
        now.saturating_sub(1),
    )?;
    let root_approval = ramflux_sdk::RamfluxClient::approve_recovery(
        ramflux_protocol::RecoveryQuorumMemberKind::RootShare,
        ROOT_KEY_ID,
        ROOT_SEED,
        &context,
    )?;
    let state = owner.collect_recovery_approval(recovery_id, &root_approval)?;
    assert_eq!(state.state, ramflux_sdk::SdkPendingRecoveryState::CollectingApprovals);
    Ok(CollectedRecovery {
        recovery_quorum,
        proof: ramflux_sdk::RamfluxClient::build_recovery_proof(context, vec![root_approval]),
    })
}

#[cfg(feature = "realnet")]
fn run_guardian_only_collection(
    owner: &ramflux_sdk::RamfluxClient,
    guardian: &ramflux_sdk::RamfluxClient,
    guardian_b: &ramflux_sdk::RamfluxClient,
    now: u64,
) -> Result<CollectedRecovery, Box<dyn std::error::Error>> {
    let configured = ramflux_sdk::RamfluxClient::configure_recovery_quorum(
        "quorum_s25_guardian_only",
        [0x7b; 32],
        2,
        &[
            guardian_member(GUARDIAN_DEVICE_ID, GUARDIAN_SEED),
            guardian_member(GUARDIAN_B_DEVICE_ID, GUARDIAN_B_SEED),
        ],
    )?;
    accept_guardian_share_e2ee_at(
        owner,
        guardian,
        &configured,
        GUARDIAN_PRINCIPAL_ID,
        now.saturating_add(300),
        0,
    )?;
    accept_guardian_share_e2ee_at(
        owner,
        guardian_b,
        &configured,
        GUARDIAN_B_PRINCIPAL_ID,
        now.saturating_add(300),
        1,
    )?;
    let recovery_quorum = configured.recovery_quorum;
    let context = initiate_collecting_recovery(
        owner,
        "recovery_s25_guardian_only",
        recovery_quorum.clone(),
        now.saturating_sub(1),
    )?;
    let first_guardian_approval =
        guardian.guardian_approve_recovery(PRINCIPAL_ID, "quorum_s25_guardian_only", &context)?;
    owner.collect_guardian_approval("recovery_s25_guardian_only", &first_guardian_approval)?;
    let second_guardian_approval =
        guardian_b.guardian_approve_recovery(PRINCIPAL_ID, "quorum_s25_guardian_only", &context)?;
    let state =
        owner.collect_guardian_approval("recovery_s25_guardian_only", &second_guardian_approval)?;
    assert_eq!(state.state, ramflux_sdk::SdkPendingRecoveryState::QuorumReached);
    Ok(CollectedRecovery {
        recovery_quorum,
        proof: ramflux_sdk::RamfluxClient::build_recovery_proof(
            context,
            vec![first_guardian_approval, second_guardian_approval],
        ),
    })
}

#[cfg(feature = "realnet")]
fn initiate_collecting_recovery(
    owner: &ramflux_sdk::RamfluxClient,
    recovery_id: &str,
    recovery_quorum: ramflux_protocol::RecoveryQuorumConfigured,
    timelock_until: u64,
) -> Result<ramflux_protocol::RecoveryApprovalContext, Box<dyn std::error::Error>> {
    let initiated = owner.initiate_recovery(&ramflux_sdk::SdkRecoveryInitiateRequest {
        recovery_id: recovery_id.to_owned(),
        owner_principal_id: PRINCIPAL_ID.to_owned(),
        recovery_quorum,
        lifecycle_epoch: 2,
        lineage_head: Some("evt_s25_social_recovery_deactivated".to_owned()),
        timelock_until: Some(timelock_until),
    })?;
    assert_eq!(initiated.state, ramflux_sdk::SdkPendingRecoveryState::Initiated);
    assert_eq!(
        owner.start_recovery_timelock(recovery_id)?.state,
        ramflux_sdk::SdkPendingRecoveryState::TimelockStarted
    );
    assert_eq!(
        owner.begin_recovery_approval_collection(recovery_id)?.state,
        ramflux_sdk::SdkPendingRecoveryState::CollectingApprovals
    );
    Ok(ramflux_protocol::RecoveryApprovalContext {
        recovery_id: recovery_id.to_owned(),
        event_type: "identity.reactivated".to_owned(),
        principal_id: PRINCIPAL_ID.to_owned(),
        lifecycle_epoch: 2,
        lineage_head: Some("evt_s25_social_recovery_deactivated".to_owned()),
        timelock_until: Some(timelock_until),
    })
}

#[cfg(feature = "realnet")]
fn configure_owner_quorum(
    owner: &ramflux_sdk::RamfluxClient,
    guardian_members: &[ramflux_sdk::SdkRecoveryQuorumMember],
) -> Result<ramflux_sdk::SdkRecoveryQuorumConfiguration, ramflux_sdk::SdkError> {
    let mut members = Vec::with_capacity(1 + guardian_members.len());
    members.push(member(
        ramflux_protocol::RecoveryQuorumMemberKind::RootShare,
        ROOT_KEY_ID,
        ROOT_SEED,
    ));
    members.extend_from_slice(guardian_members);
    let configured = ramflux_sdk::RamfluxClient::configure_recovery_quorum(
        RECOVERY_QUORUM_ID,
        RECOVERY_SECRET,
        2,
        &members,
    )?;
    assert!(matches!(
        configured.lineage_event_body(),
        ramflux_protocol::IdentityEventBody::RecoveryQuorumConfigured { .. }
    ));
    let event_body = configured.lineage_event_body();
    owner.append_event(
        "recovery_quorum_configured:s25",
        "recovery.quorum_configured",
        &serde_json::to_vec(&event_body)?,
    )?;
    Ok(configured)
}

#[cfg(feature = "realnet")]
fn accept_guardian_share_e2ee(
    owner: &ramflux_sdk::RamfluxClient,
    guardian: &ramflux_sdk::RamfluxClient,
    configured: &ramflux_sdk::SdkRecoveryQuorumConfiguration,
    guardian_principal_id: &str,
    expires_at: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    accept_guardian_share_e2ee_at(owner, guardian, configured, guardian_principal_id, expires_at, 0)
}

#[cfg(feature = "realnet")]
fn accept_guardian_share_e2ee_at(
    owner: &ramflux_sdk::RamfluxClient,
    guardian: &ramflux_sdk::RamfluxClient,
    configured: &ramflux_sdk::SdkRecoveryQuorumConfiguration,
    guardian_principal_id: &str,
    expires_at: u64,
    share_index: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let share = configured
        .shares
        .iter()
        .filter(|share| {
            share.member_kind == Some(ramflux_crypto::RecoveryQuorumMemberKind::GuardianShare)
        })
        .nth(share_index)
        .ok_or("missing guardian share")?;
    let invite = owner.invite_guardian(
        &format!("invite_{guardian_principal_id}"),
        &configured.recovery_quorum.recovery_quorum_id,
        guardian_principal_id,
        share,
        i64::try_from(expires_at)?,
    )?;
    let plaintext = serde_json::to_vec(&invite)?;
    let mut send_session =
        ramflux_crypto::DmSession::initiator([0x51; 32], [0x52; 32], [0x53; 32], [0x54; 32])?;
    let mut recv_session =
        ramflux_crypto::DmSession::recipient([0x51; 32], [0x53; 32], [0x52; 32], [0x54; 32])?;
    let ciphertext = send_session.encrypt(&plaintext, b"guardian.invite")?;
    assert!(
        !String::from_utf8_lossy(&serde_json::to_vec(&ciphertext)?)
            .contains(invite.share.value_base64.as_str())
    );
    let delivered = recv_session.decrypt(&ciphertext, b"guardian.invite")?;
    let delivered_invite: ramflux_sdk::SdkGuardianInviteMessage =
        serde_json::from_slice(&delivered)?;
    let accept = guardian.accept_guardian_invite(&delivered_invite)?;
    assert_eq!(accept.owner_principal_id, PRINCIPAL_ID);
    assert_eq!(accept.guardian_principal_id, guardian_principal_id);
    let shares = guardian.guardian_recovery_shares_for_owner(PRINCIPAL_ID)?;
    assert!(shares.iter().any(|record| {
        record.recovery_quorum_id == configured.recovery_quorum.recovery_quorum_id
            && record.state == "accepted"
    }));
    Ok(())
}

#[cfg(feature = "realnet")]
fn owner_recovery_quorum(
    guardian_device_id: &str,
    guardian_seed: [u8; 32],
) -> Result<ramflux_protocol::RecoveryQuorumConfigured, ramflux_sdk::SdkError> {
    Ok(ramflux_sdk::RamfluxClient::configure_recovery_quorum(
        RECOVERY_QUORUM_ID,
        RECOVERY_SECRET,
        2,
        &[
            member(ramflux_protocol::RecoveryQuorumMemberKind::RootShare, ROOT_KEY_ID, ROOT_SEED),
            guardian_member(guardian_device_id, guardian_seed),
        ],
    )?
    .recovery_quorum)
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
fn assert_recovery_is_rejected(
    gateway_url: &str,
    request: &ramflux_node_core::LifecycleEventRequest,
) {
    assert!(post_lifecycle(gateway_url, request).is_err());
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
        reason_code: "evt_s25_social_recovery_deactivated".to_owned(),
        timelock_seconds: None,
        recovery_quorum: Some(recovery_quorum),
        recovery_quorum_proof: Some(recovery_quorum_proof),
    }
}

#[cfg(feature = "realnet")]
fn sdk_recovery_client(
    root: &std::path::Path,
    account_id: &str,
    principal_id: &str,
    device_id: &str,
    device_seed: [u8; 32],
) -> Result<ramflux_sdk::RamfluxClient, Box<dyn std::error::Error>> {
    let mut client = ramflux_sdk::RamfluxClient::new();
    client.create_identity_root(principal_id, [0x21; 32]);
    client.create_device_branch(principal_id, device_id, 1, device_seed);
    client.open_account_index(root)?;
    client.create_account(account_id, principal_id)?;
    client.unlock_account(account_id, b"s25-social-recovery-secret")?;
    Ok(client)
}

#[cfg(feature = "realnet")]
fn guardian_member(device_id: &str, seed: [u8; 32]) -> ramflux_sdk::SdkRecoveryQuorumMember {
    member(
        ramflux_protocol::RecoveryQuorumMemberKind::GuardianShare,
        &format!("device:{device_id}"),
        seed,
    )
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

#[cfg(feature = "realnet")]
fn now_unix_u64() -> Result<u64, std::time::SystemTimeError> {
    Ok(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs())
}

#[cfg(feature = "realnet")]
struct CollectedRecovery {
    recovery_quorum: ramflux_protocol::RecoveryQuorumConfigured,
    proof: ramflux_protocol::RecoveryQuorumProof,
}
