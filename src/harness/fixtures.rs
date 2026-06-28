// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use crate::*;

#[cfg(test)]
pub(crate) fn fixture_root() -> PathBuf {
    code_root().join("ramflux/crates/ramflux-protocol")
}

#[cfg(test)]
pub(crate) fn temp_root(test_name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let elapsed = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?;
    let path = std::env::temp_dir().join(format!(
        "ramflux-itest-{test_name}-{}-{}",
        std::process::id(),
        elapsed.as_nanos()
    ));
    if path.exists() {
        fs::remove_dir_all(&path)?;
    }
    fs::create_dir_all(&path)?;
    Ok(path)
}

/// Root of the realnet-clone parent directory that holds the realnet checkouts.
///
/// Realnet is driven from two sibling repos checked out under one parent dir:
///   `<parent>/ramflux/`        the open monorepo (deploy infra at `ramflux/deploy`,
///                              services at `ramflux/apps/*` + `ramflux/crates/*`)
///   `<parent>/ramflux-itest/`  this integration-test harness
///
/// `CARGO_MANIFEST_DIR` is `<parent>/ramflux-itest`, so its parent is `<parent>`.
/// Deploy assets therefore resolve as `code_root().join("ramflux/deploy/...")`.
#[cfg(test)]
pub(crate) fn code_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map_or_else(|| PathBuf::from(".."), Path::to_path_buf)
}

#[cfg(test)]
pub(crate) fn test_account_db(
    test_name: &str,
) -> Result<ramflux_storage::AccountDb, Box<dyn std::error::Error>> {
    let root = temp_root(test_name)?;
    let index = ramflux_storage::AccountIndex::open(&root)?;
    index.create_account("acct", "principal_commitment")?;
    let key = ramflux_storage::AccountDbKey::derive("acct", b"test-secret");
    Ok(ramflux_storage::AccountDb::open(&index, "acct", &key)?)
}

#[cfg(test)]
pub(crate) fn read_json(
    root: &Path,
    relative: String,
) -> Result<Value, Box<dyn std::error::Error>> {
    let bytes = fs::read(root.join(relative))?;
    Ok(serde_json::from_slice(&bytes)?)
}

#[cfg(test)]
pub(crate) fn read_typed<T: serde::de::DeserializeOwned>(
    root: &Path,
    relative: String,
) -> Result<T, Box<dyn std::error::Error>> {
    let bytes = fs::read(root.join(relative))?;
    Ok(serde_json::from_slice(&bytes)?)
}

#[cfg(test)]
pub(crate) fn fixture(dir: &str) -> Result<FixtureObject, String> {
    ramflux_protocol::FIXTURE_OBJECTS
        .iter()
        .copied()
        .find(|object| object.dir == dir)
        .ok_or_else(|| format!("missing fixture object {dir}"))
}

#[cfg(test)]
pub(crate) fn read_trimmed(
    root: &Path,
    relative: String,
) -> Result<String, Box<dyn std::error::Error>> {
    Ok(fs::read_to_string(root.join(relative))?.trim().to_owned())
}

#[cfg(test)]
pub(crate) fn set_unknown_field(value: &mut Value) -> Result<(), String> {
    let object =
        value.as_object_mut().ok_or_else(|| "fixture value must be a JSON object".to_owned())?;
    object.insert("unexpected_field".to_owned(), Value::Bool(true));
    Ok(())
}

#[cfg(test)]
pub(crate) fn required_str(value: &Value, key: &str) -> Result<String, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| format!("missing string field {key}"))
}

#[cfg(test)]
pub(crate) fn invalid_signature_value() -> String {
    ramflux_protocol::encode_base64url([0_u8; 64])
}

#[cfg(test)]
pub(crate) fn replay_key(object: FixtureObject, value: &Value) -> Result<String, String> {
    let domain = required_str(value, "domain")?;
    let id = match object.dir {
        "envelope" => required_str(value, "envelope_id")?,
        "signed_request" => {
            format!("{}:{}", required_str(value, "request_id")?, required_str(value, "nonce")?)
        }
        "device_proof" => {
            format!("{}:{}", required_str(value, "device_id")?, required_str(value, "nonce")?)
        }
        "branch_proof" | "home_node_migration_proof" | "identity_deletion_proof" => {
            required_str(value, "proof_id")?
        }
        "ack" => required_str(value, "ack_id")?,
        "nack" => required_str(value, "nack_id")?,
        "cursor" => required_str(value, "cursor_id")?,
        "event_id" | "identity_event" | "friend_event" | "group_event" | "conversation_event"
        | "message_event" | "bot_event" => required_str(value, "event_id")?,
        "object_manifest" => required_str(value, "object_id")?,
        "object_chunk_request" => format!(
            "{}:{}",
            required_str(value, "request_id")?,
            optional_str(value, "resume_token")
        ),
        "a2i_control" | "a2ui_surface" => required_str(value, "correlation_id")?,
        "mcp_grant" | "bot_install_grant" => required_str(value, "grant_id")?,
        "bot_manifest" => required_str(value, "bot_identity_commitment")?,
        "notification_wake" => required_str(value, "wake_id")?,
        "federation_handshake" => required_str(value, "handshake_id")?,
        "franking_commitment" => required_str(value, "commitment")?,
        _ => return Err(format!("unknown fixture object {}", object.dir)),
    };
    Ok(format!("{domain}:{id}"))
}

#[cfg(test)]
pub(crate) fn optional_str(value: &Value, key: &str) -> String {
    value.get(key).and_then(Value::as_str).map(ToOwned::to_owned).unwrap_or_default()
}

#[cfg(test)]
pub(crate) const ITEST_REPLAY_TTL_SECONDS: u32 = 300;

#[cfg(test)]
pub(crate) fn itest_now_unix_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| i64::try_from(duration.as_secs()).unwrap_or(i64::MAX))
}

#[cfg(test)]
pub(crate) fn itest_envelope(
    envelope_id: &str,
    target_delivery_id: &str,
) -> ramflux_protocol::Envelope {
    ramflux_protocol::Envelope {
        schema: "ramflux.envelope.v1".to_owned(),
        version: 1,
        domain: "ramflux.envelope.v1".to_owned(),
        ext: ramflux_protocol::Ext::default(),
        signed: itest_signed_fields(),
        envelope_id: envelope_id.to_owned(),
        source_principal_id: "alice".to_owned(),
        source_device_id: "alice_device".to_owned(),
        target_delivery_id: target_delivery_id.to_owned(),
        routing_set_id: None,
        delivery_class: ramflux_protocol::DeliveryClass::OpaqueEvent,
        priority: ramflux_protocol::Priority::Normal,
        ttl: ITEST_REPLAY_TTL_SECONDS,
        created_at: itest_now_unix_seconds(),
        encrypted_payload: "ciphertext".to_owned(),
        payload_hash: "payload_hash".to_owned(),
    }
}

#[cfg(test)]
pub(crate) fn itest_ack(envelope_id: &str) -> ramflux_protocol::Ack {
    ramflux_protocol::Ack {
        schema: "ramflux.ack.v1".to_owned(),
        version: 1,
        domain: "ramflux.ack.v1".to_owned(),
        ext: ramflux_protocol::Ext::default(),
        signed: itest_signed_fields(),
        ack_id: format!("ack_{envelope_id}"),
        envelope_id: envelope_id.to_owned(),
        receiver_device_id: "device_a".to_owned(),
        received_at: itest_now_unix_seconds(),
        cursor_after: None,
    }
}

#[cfg(test)]
pub(crate) fn itest_nack(envelope_id: &str) -> ramflux_protocol::Nack {
    ramflux_protocol::Nack {
        schema: "ramflux.nack.v1".to_owned(),
        version: 1,
        domain: "ramflux.nack.v1".to_owned(),
        ext: ramflux_protocol::Ext::default(),
        signed: itest_signed_fields(),
        nack_id: format!("nack_{envelope_id}"),
        envelope_id: envelope_id.to_owned(),
        receiver_device_id: "device_a".to_owned(),
        reason: ramflux_protocol::NackReason::RateLimited,
        received_at: itest_now_unix_seconds(),
        retry_after: Some(30),
    }
}

#[cfg(test)]
pub(crate) fn itest_session(
    target_delivery_id: &str,
    lifecycle: ramflux_node_core::SessionLifecycle,
) -> ramflux_node_core::SessionDescriptor {
    ramflux_node_core::SessionDescriptor {
        target_delivery_id: target_delivery_id.to_owned(),
        device_id: "device_itest".to_owned(),
        gateway_id: "gateway_itest".to_owned(),
        session_id: format!("session_{target_delivery_id}"),
        device_epoch: 1,
        session_seq: 1,
        last_cursor: None,
        push_alias_hash: Some("push_alias_hash_itest".to_owned()),
        lifecycle,
    }
}

#[cfg(test)]
pub(crate) fn itest_security_incident(incident_id: &str) -> ramflux_node_core::SecurityIncident {
    ramflux_node_core::SecurityIncident {
        incident_id: incident_id.to_owned(),
        incident_class: "service_auth_failed".to_owned(),
        source_service_id: "ramflux-gateway".to_owned(),
        subject_hash: "subject_hash".to_owned(),
        severity: ramflux_node_core::IncidentSeverity::High,
        occurred_at: 1_760_000_000,
        expires_at: 1_791_536_000,
        retention_policy_id: "security_incident_log.default_12_months".to_owned(),
        metadata_hash: "metadata_hash".to_owned(),
    }
}

#[cfg(test)]
pub(crate) fn itest_rate_limit_abuse(bucket_id: &str) -> ramflux_node_core::RateLimitAbuseMetadata {
    ramflux_node_core::RateLimitAbuseMetadata {
        bucket_id: bucket_id.to_owned(),
        source_service_id: "ramflux-gateway".to_owned(),
        abuse_signal: "deviceproof_rate_limited".to_owned(),
        subject_hash: "subject_hash".to_owned(),
        attempt_count: 7,
        window_started_at: 1_760_000_000,
        window_expires_at: 1_762_592_000,
        retention_policy_id: "rate_limit_abuse_metadata.default_30_days".to_owned(),
    }
}

#[cfg(test)]
pub(crate) fn itest_notification_wake(
    wake_id: &str,
    ttl: u32,
) -> ramflux_protocol::NotificationWake {
    ramflux_protocol::NotificationWake {
        schema: "ramflux.notification_wake.v1".to_owned(),
        version: 1,
        domain: "ramflux.notification_wake.v1".to_owned(),
        ext: ramflux_protocol::Ext::default(),
        signed: itest_signed_fields(),
        wake_id: wake_id.to_owned(),
        push_alias: "push_alias_raw_notify_only".to_owned(),
        delivery_class: ramflux_protocol::NotificationDeliveryClass::SelfDeviceControlNotification,
        priority: ramflux_protocol::PushPriority::Normal,
        ttl,
        collapse_key: Some("collapse_self_device".to_owned()),
        encrypted_hint: Some("encrypted_hint".to_owned()),
    }
}

#[cfg(test)]
pub(crate) fn itest_relay_chunk(
    chunk_id: &str,
    stored_at: u64,
    ttl: u64,
) -> ramflux_node_core::RelayChunkEntry {
    ramflux_node_core::RelayChunkEntry {
        chunk_id: chunk_id.to_owned(),
        object_id: "object_itest_1".to_owned(),
        manifest_hash: "manifest_hash_itest".to_owned(),
        chunk_index: 0,
        chunk_cipher_hash: "chunk_cipher_hash_itest".to_owned(),
        encrypted_chunk: b"encrypted relay chunk".to_vec(),
        stored_at,
        expires_at: stored_at.saturating_add(ttl),
        delete_after_ack: false,
        acked_by: std::collections::BTreeSet::new(),
        status: ramflux_node_core::RelayChunkStatus::Available,
    }
}

#[cfg(test)]
pub(crate) fn itest_federation_route(
    node_id: &str,
    trust_status: ramflux_node_core::FederationTrustStatus,
) -> ramflux_node_core::FederationPeerRoute {
    ramflux_node_core::FederationPeerRoute {
        node_id: node_id.to_owned(),
        endpoint: format!("https://{node_id}"),
        node_public_key_hash: "node_public_key_hash_itest".to_owned(),
        node_capabilities: vec!["opaque_delivery".to_owned()],
        trust_status,
        updated_at: 1_760_000_000,
        expires_at: 1_762_592_000,
        route_update_proof_hash: "route_update_proof_hash_itest".to_owned(),
    }
}

#[cfg(test)]
pub(crate) fn itest_bad_node_advisory(
    advisory_id: &str,
    subject_node_id: &str,
) -> ramflux_node_core::BadNodeAdvisory {
    ramflux_node_core::BadNodeAdvisory {
        advisory_id: advisory_id.to_owned(),
        issuer_node_id: "node_a.example".to_owned(),
        subject_node_id: subject_node_id.to_owned(),
        reason_code: "warning".to_owned(),
        issued_at: 1_760_000_000,
        expires_at: 1_762_592_000,
        signature_hash: "signature_hash_itest".to_owned(),
    }
}

#[cfg(test)]
pub(crate) fn itest_call_session(call_id: &str) -> ramflux_node_core::OpaqueCallSession {
    ramflux_node_core::OpaqueCallSession {
        call_id: call_id.to_owned(),
        caller_device_hash: "caller_hash".to_owned(),
        callee_device_hash: "callee_hash".to_owned(),
        allowed_peer_hashes: BTreeSet::from(["peer_hash_b".to_owned()]),
        created_at: 1_760_000_000,
        expires_at: 1_760_003_600,
        lifecycle: ramflux_node_core::CallSessionLifecycle::Pending,
        opaque_envelope_hash: "opaque_envelope_hash_itest".to_owned(),
    }
}

#[cfg(test)]
pub(crate) fn itest_turn_allocation(
    allocation_id: &str,
    call_id: &str,
    peer_hash: &str,
) -> ramflux_node_core::TurnAllocation {
    ramflux_node_core::TurnAllocation {
        allocation_id: allocation_id.to_owned(),
        call_id: call_id.to_owned(),
        username_hash: "turn_username_hash_itest".to_owned(),
        identity_hash: "identity_hash_itest".to_owned(),
        peer_hash: peer_hash.to_owned(),
        source_ip_hash: "source_ip_hash_itest".to_owned(),
        relay_address: "203.0.113.20:49152".to_owned(),
        bandwidth_limit_bps: 2_000_000,
        burst_limit_bps: 4_000_000,
        created_at: 1_760_000_001,
        expires_at: 1_760_000_601,
        bytes_relayed: 0,
        packets_relayed: 0,
    }
}

#[cfg(test)]
pub(crate) fn itest_pre_auth_challenge(challenge_id: &str) -> ramflux_node_core::PreAuthChallenge {
    ramflux_node_core::PreAuthChallenge {
        challenge_id: challenge_id.to_owned(),
        source_ip_hash: "source_ip_hash_itest".to_owned(),
        issued_at: 1_760_000_000,
        expires_at: 1_760_000_030,
        used: false,
    }
}

#[cfg(test)]
pub(crate) fn itest_gateway_session(session_id: &str) -> ramflux_node_core::GatewaySession {
    ramflux_node_core::GatewaySession {
        session_id: session_id.to_owned(),
        target_delivery_id: "target_gateway_itest".to_owned(),
        device_id: "device_gateway_itest".to_owned(),
        opened_at: 1_760_000_001,
        last_heartbeat_at: 1_760_000_001,
        lifecycle: ramflux_node_core::GatewaySessionLifecycle::Authed,
    }
}

#[cfg(test)]
pub(crate) fn itest_signed_fields() -> ramflux_protocol::SignedFields {
    ramflux_protocol::SignedFields {
        signing_key_id: "fixture".to_owned(),
        signature_alg: ramflux_protocol::SignatureAlg::Ed25519,
        signature: "sig".to_owned(),
    }
}

#[cfg(test)]
pub(crate) fn itest_node_service_signing_seed() -> [u8; 32] {
    [
        1_u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31, 32,
    ]
}

#[cfg(test)]
pub(crate) fn itest_node_service_signing_seed_b64url() -> String {
    ramflux_protocol::encode_base64url(itest_node_service_signing_seed())
}

#[cfg(test)]
pub(crate) fn ensure_itest_node_service_signing_seed_env(env: &mut Vec<(String, String)>) {
    if !env.iter().any(|(key, _value)| key == ramflux_node_core::NODE_SERVICE_SIGNING_SEED_ENV) {
        env.push((
            ramflux_node_core::NODE_SERVICE_SIGNING_SEED_ENV.to_owned(),
            itest_node_service_signing_seed_b64url(),
        ));
    }
}

#[cfg(test)]
pub(crate) fn sign_itest_notification_wake(
    wake: &mut ramflux_protocol::NotificationWake,
) -> Result<(), ramflux_crypto::CryptoError> {
    wake.signed.signing_key_id = ramflux_node_core::NODE_SERVICE_SIGNING_KEY_ID.to_owned();
    wake.signed.signature_alg = ramflux_protocol::SignatureAlg::Ed25519;
    wake.signed.signature =
        ramflux_crypto::sign_protocol_object_with_seed(wake, itest_node_service_signing_seed())?;
    Ok(())
}
