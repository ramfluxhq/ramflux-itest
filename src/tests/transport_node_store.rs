// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use super::*;

#[tokio::test]
async fn transport_grpc_h2_signed_envelope() -> Result<(), Box<dyn std::error::Error>> {
    smoke_single_backend(&GrpcH2Backend::new(), BackendKind::GrpcH2).await
}

#[tokio::test]
async fn transport_quic_quinn_signed_envelope() -> Result<(), Box<dyn std::error::Error>> {
    smoke_single_backend(&QuicQuinnBackend::new(), BackendKind::QuicQuinn).await
}

#[tokio::test]
async fn transport_https_json_signed_envelope() -> Result<(), Box<dyn std::error::Error>> {
    smoke_single_backend(&HttpsJsonBackend::new(), BackendKind::HttpsJson).await
}

#[tokio::test]
async fn ack_fixture_cursor_advance() -> Result<(), Box<dyn std::error::Error>> {
    let root = fixture_root();
    let ack = read_typed::<Ack>(&root, fixture_json_path(fixture("ack")?))?;
    let backend = GrpcH2Backend::new();
    authenticate_backend(&backend).await?;
    let frame = backend.ack(ack).await?;
    assert_eq!(frame.ack.envelope_id, "env_01");
    assert_eq!(frame.ack.cursor_after.as_deref(), Some("cur_01"));
    Ok(())
}

#[tokio::test]
async fn nack_home_node_migrated_reresolve() -> Result<(), Box<dyn std::error::Error>> {
    let root = fixture_root();
    let nack = read_typed::<Nack>(&root, fixture_json_path(fixture("nack")?))?;
    let backend = QuicQuinnBackend::new();
    authenticate_backend(&backend).await?;
    let frame = backend.nack(nack).await?;
    assert_eq!(frame.nack.envelope_id, "env_01");
    assert_eq!(frame.nack.reason, NackReason::HomeNodeMigrated);
    assert_eq!(frame.nack.retry_after, None);
    Ok(())
}

#[test]
fn router_offline_inbox_ack_nack_cursor() -> Result<(), Box<dyn std::error::Error>> {
    let mut inbox = ramflux_node_core::OpaqueDeviceInbox::new();
    inbox.append(itest_envelope("env_itest_1", "target_itest"));
    inbox.append(itest_envelope("env_itest_2", "target_itest"));

    let pulled = inbox.pull_after("target_itest", 0, 10);
    assert_eq!(pulled.len(), 2);
    assert_eq!(pulled[0].inbox_seq, 1);

    let ack_state = inbox.apply_ack(&itest_ack("env_itest_1"))?;
    assert_eq!(ack_state.inbox_seq, 1);
    assert_eq!(ack_state.last_envelope_id, Some("env_itest_1".to_owned()));
    assert_eq!(inbox.pull_after("target_itest", 0, 10).len(), 1);

    let nack_state = inbox.apply_nack(&itest_nack("env_itest_2"))?;
    assert_eq!(nack_state.inbox_seq, 1);
    assert_eq!(nack_state.nacked_envelope_ids.get("env_itest_2"), Some(&NackReason::RateLimited));
    assert_eq!(inbox.pull_after("target_itest", 0, 10).len(), 1);
    Ok(())
}

#[test]
fn router_core_online_offline_resume_flow() -> Result<(), Box<dyn std::error::Error>> {
    let router = ramflux_node_core::RouterCore::new();
    router.upsert_session(itest_session(
        "target_online",
        ramflux_node_core::SessionLifecycle::Live,
    ))?;

    let online = router.submit_envelope(itest_envelope("env_online_itest", "target_online"));
    assert!(matches!(online, ramflux_node_core::RouterSubmitOutcome::Online(_)));
    if let ramflux_node_core::RouterSubmitOutcome::Online(delivery) = online {
        assert_eq!(delivery.gateway_id, "gateway_itest");
        assert_eq!(delivery.session_id, "session_target_online");
        assert_eq!(delivery.envelope.envelope_id, "env_online_itest");
    }

    let offline = router.submit_envelope(itest_envelope("env_offline_itest", "target_offline"));
    assert!(matches!(offline, ramflux_node_core::RouterSubmitOutcome::OfflineQueued(_)));
    if let ramflux_node_core::RouterSubmitOutcome::OfflineQueued(queued) = offline {
        assert_eq!(queued.entry.inbox_seq, 1);
        assert_eq!(queued.wake_hint.target_delivery_id, "target_offline");
        assert_eq!(queued.wake_hint.push_alias_hash, None);
    }

    let resumed = router.resume("target_offline", 0, 10);
    assert_eq!(resumed.len(), 1);
    assert_eq!(resumed[0].envelope.envelope_id, "env_offline_itest");

    let ack_state = router.apply_ack(&itest_ack("env_offline_itest"))?;
    assert_eq!(ack_state.inbox_seq, 1);
    assert_eq!(router.resume("target_offline", 0, 10).len(), 0);
    Ok(())
}

#[test]
fn router_redb_store_restart_recovers_offline_state() -> Result<(), Box<dyn std::error::Error>> {
    let root = temp_root("router_redb_store_restart_recovers_offline_state")?;
    let store_path = root.join("router.redb");
    let store = ramflux_node_core::RouterRedbStore::open(&store_path)?;
    let router = ramflux_node_core::RouterCore::new();
    router.upsert_session(itest_session(
        "target_online",
        ramflux_node_core::SessionLifecycle::Live,
    ))?;
    router.submit_envelope(itest_envelope("env_persisted_offline", "target_offline"));
    router.submit_envelope(itest_envelope("env_persisted_ack", "target_ack"));
    router.apply_ack(&itest_ack("env_persisted_ack"))?;
    store.save_router(&router)?;
    drop(store);

    let reopened = ramflux_node_core::RouterRedbStore::open(&store_path)?;
    let restored =
        reopened.load_router()?.ok_or_else(|| "missing persisted router snapshot".to_owned())?;
    assert!(matches!(
        restored.submit_envelope(itest_envelope("env_after_restart", "target_online")),
        ramflux_node_core::RouterSubmitOutcome::Online(_)
    ));
    assert_eq!(restored.resume("target_offline", 0, 10).len(), 1);
    assert_eq!(
        restored.cursor_state("target_ack").and_then(|cursor| cursor.last_envelope_id),
        Some("env_persisted_ack".to_owned())
    );
    Ok(())
}

#[test]
fn retention_incident_store_restart_recovers_security_metadata()
-> Result<(), Box<dyn std::error::Error>> {
    let root = temp_root("retention_incident_store_restart_recovers_security_metadata")?;
    let store_path = root.join("retention.redb");
    let store = ramflux_node_core::RetentionRedbStore::open(&store_path)?;
    store.report_incident(itest_security_incident("incident_itest_1"))?;
    store.record_rate_limit_abuse(itest_rate_limit_abuse("bucket_itest_1"))?;
    drop(store);

    let reopened = ramflux_node_core::RetentionRedbStore::open(&store_path)?;
    let state = reopened.load_state()?.ok_or_else(|| "missing retention state".to_owned())?;
    assert_eq!(state.incident_count(), 1);
    assert_eq!(
        state.incident("incident_itest_1").map(|incident| incident.retention_policy_id.as_str()),
        Some("security_incident_log.default_12_months")
    );
    assert_eq!(
        state
            .rate_limit_metadata("bucket_itest_1")
            .map(|metadata| metadata.retention_policy_id.as_str()),
        Some("rate_limit_abuse_metadata.default_30_days")
    );
    Ok(())
}

#[test]
fn notify_queue_store_restart_recovers_notification_wake() -> Result<(), Box<dyn std::error::Error>>
{
    let root = temp_root("notify_queue_store_restart_recovers_notification_wake")?;
    let store_path = root.join("notify.redb");
    let store = ramflux_node_core::NotifyRedbStore::open(&store_path)?;
    let entry = store.queue_wake(
        itest_notification_wake("wake_itest_1", 120),
        "push_alias_hash",
        1_760_000_000,
    )?;
    assert_eq!(entry.expires_at, 1_760_000_120);
    drop(store);

    let reopened = ramflux_node_core::NotifyRedbStore::open(&store_path)?;
    let mut state =
        reopened.load_state()?.ok_or_else(|| "missing notify queue state".to_owned())?;
    assert_eq!(state.pending_count(), 1);
    assert_eq!(
        state.entry("wake_itest_1").map(|entry| entry.push_alias_hash.as_str()),
        Some("push_alias_hash")
    );
    assert_eq!(state.drop_expired(1_760_000_121), 1);
    assert_eq!(
        state.entry("wake_itest_1").map(|entry| entry.status.clone()),
        Some(ramflux_node_core::NotifyQueueStatus::DroppedExpired)
    );
    Ok(())
}

#[test]
fn relay_chunk_cache_restart_recovers_encrypted_chunk() -> Result<(), Box<dyn std::error::Error>> {
    let root = temp_root("relay_chunk_cache_restart_recovers_encrypted_chunk")?;
    let store_path = root.join("relay.redb");
    let store = ramflux_node_core::RelayRedbStore::open(&store_path)?;
    store.put_chunk(&itest_relay_chunk("chunk_itest_1", 1_760_000_000, 120))?;
    drop(store);

    let reopened = ramflux_node_core::RelayRedbStore::open(&store_path)?;
    let mut state = reopened.load_state()?.ok_or_else(|| "missing relay cache state".to_owned())?;
    let chunk = state
        .get_available_chunk("chunk_itest_1", 1_760_000_010)
        .ok_or_else(|| "missing relay chunk".to_owned())?;
    assert_eq!(chunk.object_id, "object_itest_1");
    assert_eq!(chunk.encrypted_chunk, b"encrypted relay chunk");
    assert_eq!(state.expire_chunks(1_760_000_121), 1);
    assert_eq!(state.available_count(1_760_000_121), 0);
    Ok(())
}

#[test]
fn signaling_store_restart_recovers_opaque_call_turn_state()
-> Result<(), Box<dyn std::error::Error>> {
    let root = temp_root("signaling_store_restart_recovers_opaque_call_turn_state")?;
    let store_path = root.join("signaling.redb");
    let store = ramflux_node_core::SignalingRedbStore::open(&store_path)?;
    let mut state = ramflux_node_core::SignalingState::new();
    state.submit_opaque_call_envelope(itest_call_session("call_itest_1"));
    state.activate_call("call_itest_1")?;
    state.allocate_turn(itest_turn_allocation("alloc_itest_1", "call_itest_1", "peer_hash_b"))?;
    store.save_state(&state)?;
    drop(store);

    let reopened = ramflux_node_core::SignalingRedbStore::open(&store_path)?;
    let restored = reopened.load_state()?.ok_or_else(|| "missing signaling state".to_owned())?;
    assert_eq!(restored.active_call_count(), 1);
    assert_eq!(
        restored.allocation("alloc_itest_1").map(|allocation| allocation.bandwidth_limit_bps),
        Some(2_000_000)
    );
    assert!(!restored.srtp_media_key_visible("call_itest_1"));
    Ok(())
}

#[test]
fn gateway_store_restart_recovers_live_session_frames() -> Result<(), Box<dyn std::error::Error>> {
    let root = temp_root("gateway_store_restart_recovers_live_session_frames")?;
    let store_path = root.join("gateway.redb");
    let store = ramflux_node_core::GatewayRedbStore::open(&store_path)?;
    let mut state = ramflux_node_core::GatewayState::new();
    state.issue_challenge(itest_pre_auth_challenge("challenge_itest_1"));
    state.consume_challenge("challenge_itest_1", 1_760_000_001)?;
    state.open_session(itest_gateway_session("session_itest_1"));
    state.mark_live("session_itest_1", 1_760_000_010)?;
    state.deliver(ramflux_node_core::GatewayFrame::Deliver {
        session_id: "session_itest_1".to_owned(),
        envelope_id: "env_gateway_itest_1".to_owned(),
        payload_hash: "payload_hash".to_owned(),
    })?;
    store.save_state(&state)?;
    drop(store);

    let reopened = ramflux_node_core::GatewayRedbStore::open(&store_path)?;
    let mut restored = reopened.load_state()?.ok_or_else(|| "missing gateway state".to_owned())?;
    assert_eq!(
        restored.session("session_itest_1").map(|session| session.lifecycle.clone()),
        Some(ramflux_node_core::GatewaySessionLifecycle::Live)
    );
    assert_eq!(restored.queued_frame_count("session_itest_1"), 1);
    restored.drain("session_itest_1")?;
    assert_eq!(
        restored.session("session_itest_1").map(|session| session.lifecycle.clone()),
        Some(ramflux_node_core::GatewaySessionLifecycle::Draining)
    );
    Ok(())
}

#[tokio::test]
async fn transport_backend_smoke() -> Result<(), Box<dyn std::error::Error>> {
    let root = fixture_root();
    let envelope = read_typed::<Envelope>(&root, fixture_json_path(fixture("envelope")?))?;
    let signed_request =
        read_typed::<SignedRequest>(&root, fixture_json_path(fixture("signed_request")?))?;
    let ack = read_typed::<Ack>(&root, fixture_json_path(fixture("ack")?))?;
    let nack = read_typed::<Nack>(&root, fixture_json_path(fixture("nack")?))?;
    let cursor = read_typed::<Cursor>(&root, fixture_json_path(fixture("cursor")?))?;
    let envelope_canonical = ramflux_protocol::canonical_json_bytes(&envelope)?;

    let fixture = TransportSmokeFixture {
        signed_request: &signed_request,
        envelope: &envelope,
        ack: &ack,
        nack: &nack,
        cursor: &cursor,
        expected_envelope_canonical: &envelope_canonical,
    };

    smoke_backend(&GrpcH2Backend::new(), BackendKind::GrpcH2, &fixture).await?;
    smoke_backend(&QuicQuinnBackend::new(), BackendKind::QuicQuinn, &fixture).await?;
    smoke_backend(&HttpsJsonBackend::new(), BackendKind::HttpsJson, &fixture).await?;
    Ok(())
}
