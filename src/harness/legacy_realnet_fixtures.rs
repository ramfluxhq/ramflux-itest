// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use crate::*;

#[cfg(all(test, feature = "realnet"))]
pub(crate) struct Mvp1RealnetFixture {
    pub(crate) register: ramflux_node_core::IdentityRegisterRequest,
    pub(crate) revoked_register: ramflux_node_core::IdentityRegisterRequest,
    pub(crate) prekey_bundle: ramflux_crypto::PrekeyBundle,
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) struct Mvp1DmRealnetFixture {
    pub(crate) alice_register: ramflux_node_core::IdentityRegisterRequest,
    pub(crate) bob_register: ramflux_node_core::IdentityRegisterRequest,
    pub(crate) alice_identity: ramflux_crypto::X25519KeyPair,
    pub(crate) alice_ephemeral: ramflux_crypto::X25519KeyPair,
    pub(crate) bob_identity: ramflux_crypto::X25519KeyPair,
    pub(crate) bob_signed_prekey: ramflux_crypto::X25519KeyPair,
    pub(crate) bob_prekey_bundle: ramflux_crypto::PrekeyBundle,
}

#[cfg(all(test, feature = "realnet"))]
#[derive(Clone, Copy)]
pub(crate) struct Mvp7LifecycleStep {
    pub(crate) event_id: &'static str,
    pub(crate) event_type: &'static str,
    pub(crate) lifecycle_epoch: u64,
    pub(crate) now: u64,
    pub(crate) timelock_seconds: Option<u64>,
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) struct Mvp7DeletedTombstoneFixture {
    pub(crate) tombstone: ramflux_node_core::IdentityLifecycleTombstone,
    pub(crate) deletion_proof: ramflux_node_core::IdentityDeletionProof,
}

#[cfg(all(test, feature = "realnet"))]
#[derive(Clone)]
pub(crate) struct Mvp7FrankingReportFixture {
    pub(crate) plaintext: String,
    pub(crate) opaque_ciphertext: String,
    pub(crate) evidence: Mvp7SelectedFrankingEvidence,
}

#[cfg(all(test, feature = "realnet"))]
#[derive(Clone, serde::Serialize)]
pub(crate) struct Mvp7SelectedFrankingEvidence {
    pub(crate) evidence_kind: ramflux_node_core::FrankingEvidenceKind,
    pub(crate) node_id: String,
    pub(crate) envelope_id: String,
    pub(crate) plaintext_excerpt: String,
    pub(crate) opening_key: String,
    pub(crate) commitment_key: String,
    pub(crate) sender_device_id_hash: String,
    pub(crate) msg_event_id: String,
    pub(crate) canonical_header_bytes: String,
    pub(crate) associated_data: String,
    pub(crate) ciphertext: String,
    pub(crate) header_hash: String,
    pub(crate) associated_data_hash: String,
    pub(crate) ciphertext_hash: String,
    pub(crate) franking_commitment: String,
    pub(crate) commitment: String,
    pub(crate) franking_tag: String,
    pub(crate) franking_timestamp: u64,
    pub(crate) group_header_signature: Option<String>,
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) struct Mvp6RawHttpResponse {
    pub(crate) status: u16,
    pub(crate) body: Vec<u8>,
}

#[cfg(all(test, feature = "realnet"))]
impl Mvp6RawHttpResponse {
    pub(crate) const fn status_is_success(&self) -> bool {
        self.status >= 200 && self.status < 300
    }
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) struct Mvp2LocalClients {
    pub(crate) alice_db: ramflux_storage::AccountDb,
    pub(crate) bob_db: ramflux_storage::AccountDb,
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) struct Mvp2BotRealnetFixture {
    pub(crate) target_delivery_id: String,
    pub(crate) identity: ramflux_crypto::X25519KeyPair,
    pub(crate) signed_prekey: ramflux_crypto::X25519KeyPair,
    pub(crate) prekey_bundle: ramflux_crypto::PrekeyBundle,
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) struct Mvp2GroupFanoutContext<'a> {
    pub(crate) gateway_url: &'a str,
    pub(crate) alice_recipient_session: &'a mut ramflux_crypto::DmSession,
    pub(crate) recipient_session: &'a mut ramflux_crypto::DmSession,
    pub(crate) group_epoch: &'a ramflux_storage::GroupKeyEpochState,
    pub(crate) bot: &'a Mvp2BotRealnetFixture,
    pub(crate) bot_target_delivery_id: &'a str,
    pub(crate) plaintext: &'a [u8],
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) struct Mvp3McpA2uiFixture {
    pub(crate) app_register: ramflux_node_core::IdentityRegisterRequest,
    pub(crate) cli_register: ramflux_node_core::IdentityRegisterRequest,
    pub(crate) app_identity: ramflux_crypto::X25519KeyPair,
    pub(crate) app_signed_prekey: ramflux_crypto::X25519KeyPair,
    pub(crate) app_prekey_bundle: ramflux_crypto::PrekeyBundle,
    pub(crate) cli_identity: ramflux_crypto::X25519KeyPair,
    pub(crate) cli_signed_prekey: ramflux_crypto::X25519KeyPair,
    pub(crate) cli_prekey_bundle: ramflux_crypto::PrekeyBundle,
}

#[cfg(all(test, feature = "realnet"))]
#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub(crate) struct Mvp3A2uiApprovalRequest {
    pub(crate) event_type: String,
    pub(crate) source_device_id: String,
    pub(crate) target_device_id: String,
    pub(crate) control_session_id: String,
    pub(crate) surface: ramflux_sync::A2uiSurface,
}

#[cfg(all(test, feature = "realnet"))]
#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub(crate) struct Mvp3A2iMcpGrantEvent {
    pub(crate) event_type: String,
    pub(crate) grant_id: String,
    pub(crate) source_app_device_id: String,
    pub(crate) target_ai_device_id: String,
    pub(crate) capability: String,
    pub(crate) registry_hash: String,
    pub(crate) tool_manifest_set_hash: String,
    pub(crate) risk_level: String,
}

#[cfg(all(test, feature = "realnet"))]
#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub(crate) struct Mvp10FullDelegationEvent {
    pub(crate) event_type: String,
    pub(crate) grant_id: String,
    pub(crate) source_app_device_id: String,
    pub(crate) target_ai_device_id: String,
    pub(crate) registry_hash: String,
    pub(crate) tool_manifest_set_hash: String,
    pub(crate) full_delegation: bool,
}

#[cfg(all(test, feature = "realnet"))]
#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub(crate) struct Mvp10FullDelegationRevokedEvent {
    pub(crate) event_type: String,
    pub(crate) grant_id: String,
    pub(crate) revoked_by_device_id: String,
    pub(crate) revoked_at: i64,
}

#[cfg(all(test, feature = "realnet"))]
#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub(crate) struct Mvp3CallSignalEvent {
    pub(crate) event_type: String,
    pub(crate) call_id: String,
    pub(crate) signal_type: String,
    pub(crate) opaque_sdp: String,
    pub(crate) ice_ufrag: String,
    pub(crate) srtp_key_material: String,
}

#[cfg(all(test, feature = "realnet"))]
#[derive(Clone, Copy)]
pub(crate) struct Mvp3PairwiseSessionInput<'a> {
    pub(crate) initiator_identity: &'a ramflux_crypto::X25519KeyPair,
    pub(crate) initiator_ephemeral_seed: [u8; 32],
    pub(crate) recipient_bundle: &'a ramflux_crypto::PrekeyBundle,
    pub(crate) recipient_identity: &'a ramflux_crypto::X25519KeyPair,
    pub(crate) recipient_signed_prekey: &'a ramflux_crypto::X25519KeyPair,
    pub(crate) associated_data: &'a [u8],
    pub(crate) session_label: &'a str,
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) struct Mvp3ControlDelivery<'a, T> {
    pub(crate) gateway_url: &'a str,
    pub(crate) envelope_id: &'a str,
    pub(crate) target_delivery_id: &'a str,
    pub(crate) sender_session: &'a mut ramflux_crypto::DmSession,
    pub(crate) receiver_session: &'a mut ramflux_crypto::DmSession,
    pub(crate) associated_data: &'a [u8],
    pub(crate) event: &'a T,
    pub(crate) forbidden_node_visible: &'a [u8],
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) struct Mvp4CrossNodeDmDelivery<'a> {
    pub(crate) gateway_url: &'a str,
    pub(crate) mesh: &'a mut ramflux_sync::FederationMesh,
    pub(crate) envelope_id: &'a str,
    pub(crate) target_delivery_id: &'a str,
    pub(crate) sender_session: &'a mut ramflux_crypto::DmSession,
    pub(crate) receiver_session: &'a mut ramflux_crypto::DmSession,
    pub(crate) from_identity: &'a str,
    pub(crate) to_identity: &'a str,
    pub(crate) plaintext: &'a [u8],
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) struct Mvp4DeliveredDm {
    pub(crate) via_node: String,
    pub(crate) decrypted_plaintext: Vec<u8>,
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) struct Mvp4PartitionMemberFixture {
    pub(crate) register: ramflux_node_core::IdentityRegisterRequest,
    pub(crate) identity: ramflux_crypto::X25519KeyPair,
    pub(crate) signed_prekey: ramflux_crypto::X25519KeyPair,
    pub(crate) prekey_bundle: ramflux_crypto::PrekeyBundle,
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) struct Mvp4PartitionRealnetContext {
    pub(crate) mesh: ramflux_sync::FederationMesh,
    pub(crate) alice_to_bob: ramflux_crypto::DmSession,
    pub(crate) bob_receiver: ramflux_crypto::DmSession,
    pub(crate) alice_to_carol: ramflux_crypto::DmSession,
    pub(crate) carol_receiver: ramflux_crypto::DmSession,
}

#[cfg(all(test, feature = "realnet"))]
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub(crate) struct Mvp4GroupPartitionCheckpoint {
    pub(crate) event_type: String,
    pub(crate) group_id: String,
    pub(crate) partition_id: String,
    pub(crate) observed_group_epoch: u64,
    pub(crate) observed_sender_key_epoch: u64,
    pub(crate) members: BTreeSet<String>,
    pub(crate) transitions: Vec<Mvp4GroupPartitionTransition>,
    pub(crate) messages: Vec<Mvp4GroupPartitionMessage>,
    pub(crate) lineage_head: String,
}

#[cfg(all(test, feature = "realnet"))]
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub(crate) struct Mvp4GroupPartitionTransition {
    pub(crate) event_id: String,
    pub(crate) actor_device_id: String,
    pub(crate) action: String,
    pub(crate) target_member: String,
    pub(crate) auth_chain_depth: u32,
    pub(crate) lamport_time: u64,
    pub(crate) auth_chain: Vec<String>,
}

#[cfg(all(test, feature = "realnet"))]
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub(crate) struct Mvp4GroupPartitionMessage {
    pub(crate) message_id: String,
    pub(crate) sender: String,
    pub(crate) message_created_group_key_epoch: u64,
    pub(crate) body_hash: String,
}

#[cfg(all(test, feature = "realnet"))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Mvp4GroupCanonicalProjection {
    pub(crate) group_epoch: u64,
    pub(crate) sender_key_epoch: u64,
    pub(crate) members: BTreeSet<String>,
    pub(crate) projected_message_ids: Vec<String>,
    pub(crate) rejected_message_ids: Vec<String>,
    pub(crate) auth_chain_event_ids: Vec<String>,
    pub(crate) group_lineage_head: String,
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) struct Mvp4PartitionCheckpointInput {
    pub(crate) partition_id: &'static str,
    pub(crate) members: BTreeSet<String>,
    pub(crate) transitions: Vec<Mvp4GroupPartitionTransition>,
    pub(crate) messages: Vec<Mvp4GroupPartitionMessage>,
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) struct Mvp4GroupPartitionGossipDelivery<'a> {
    pub(crate) gateway_url: &'a str,
    pub(crate) mesh: &'a mut ramflux_sync::FederationMesh,
    pub(crate) envelope_id: &'a str,
    pub(crate) target_delivery_id: &'a str,
    pub(crate) sender_session: &'a mut ramflux_crypto::DmSession,
    pub(crate) receiver_session: &'a mut ramflux_crypto::DmSession,
    pub(crate) associated_data: &'a [u8],
    pub(crate) from_identity: &'a str,
    pub(crate) to_identity: &'a str,
    pub(crate) checkpoint: &'a Mvp4GroupPartitionCheckpoint,
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) struct Mvp4DeliveredGroupPartitionGossip {
    pub(crate) via_node: String,
    pub(crate) checkpoint: Mvp4GroupPartitionCheckpoint,
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) struct Mvp4CanonicalLineageInput<'a> {
    pub(crate) group_id: &'a str,
    pub(crate) group_epoch: u64,
    pub(crate) sender_key_epoch: u64,
    pub(crate) members: &'a BTreeSet<String>,
    pub(crate) projected_message_ids: &'a [String],
    pub(crate) rejected_message_ids: &'a [String],
    pub(crate) auth_chain_event_ids: &'a [String],
}

#[cfg(all(test, feature = "realnet"))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Mvp4MigrationStep {
    pub(crate) step_number: u8,
    pub(crate) name: &'static str,
}

#[cfg(all(test, feature = "realnet"))]
#[derive(Debug, serde::Deserialize)]
pub(crate) struct Mvp4FederationCanDeliverResponse {
    pub(crate) node_id: String,
    pub(crate) can_deliver: bool,
}

#[cfg(all(test, feature = "realnet"))]
#[derive(serde::Serialize)]
pub(crate) struct Mvp4FederationTrustStatusRequest {
    pub(crate) node_id: String,
    pub(crate) trust_status: ramflux_node_core::FederationTrustStatus,
    pub(crate) updated_at: u64,
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) struct Mvp9DeliveredDm {
    pub(crate) submit: ramflux_node_core::EnvelopeSubmitResponse,
    pub(crate) entry: ramflux_node_core::InboxEntry,
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) struct Mvp9LocalClients {
    pub(crate) root: PathBuf,
    pub(crate) alice_key: ramflux_storage::AccountDbKey,
    pub(crate) bob_key: ramflux_storage::AccountDbKey,
    pub(crate) alice_db: ramflux_storage::AccountDb,
    pub(crate) bob_db: ramflux_storage::AccountDb,
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn setup_mvp9_local_clients() -> Result<Mvp9LocalClients, Box<dyn std::error::Error>> {
    let root = temp_root("mvp9_realnet_message_features")?;
    let index = ramflux_storage::AccountIndex::open(&root)?;
    index.create_account("alice_mvp9_local", "alice_realnet")?;
    index.create_account("bob_mvp9_local", "bob_realnet")?;
    let alice_key = ramflux_storage::AccountDbKey::derive("alice_mvp9_local", b"alice-mvp9-secret");
    let bob_key = ramflux_storage::AccountDbKey::derive("bob_mvp9_local", b"bob-mvp9-secret");
    let alice_db = ramflux_storage::AccountDb::open(&index, "alice_mvp9_local", &alice_key)?;
    let bob_db = ramflux_storage::AccountDb::open(&index, "bob_mvp9_local", &bob_key)?;
    assert_eq!(alice_db.encryption_mode(), ramflux_storage::EncryptionMode::SqlCipher);
    assert_eq!(bob_db.encryption_mode(), ramflux_storage::EncryptionMode::SqlCipher);
    Ok(Mvp9LocalClients { root, alice_key, bob_key, alice_db, bob_db })
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn deliver_mvp9_dm(
    gateway_url: &str,
    envelope_id: &str,
    target_delivery_id: &str,
    ciphertext: &ramflux_crypto::DmCiphertext,
) -> Result<Mvp9DeliveredDm, Box<dyn std::error::Error>> {
    let encrypted_payload = serde_json::to_string(ciphertext)?;
    let mut envelope = itest_envelope(envelope_id, target_delivery_id);
    envelope.encrypted_payload = encrypted_payload;
    envelope.payload_hash = ramflux_crypto::blake3_256_base64url(
        "ramflux.test.dm_payload.v1",
        envelope.encrypted_payload.as_bytes(),
    );
    let submit: ramflux_node_core::EnvelopeSubmitResponse =
        ramflux_node_core::itest_http_post_json(
            &format!("{gateway_url}/mvp0/envelope"),
            &envelope,
        )?;
    assert!(matches!(submit.outcome.as_str(), "online" | "offline_queued"));
    let entry = mvp1_inbox_entry(gateway_url, target_delivery_id, envelope_id)?;
    Ok(Mvp9DeliveredDm { submit, entry })
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn decrypt_mvp9_dm(
    delivered: &Mvp9DeliveredDm,
    receiver_session: &mut ramflux_crypto::DmSession,
    associated_data: &[u8],
    forbidden_plaintext: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    assert_node_opaque_payload(&delivered.entry.envelope.encrypted_payload, forbidden_plaintext);
    let ciphertext: ramflux_crypto::DmCiphertext =
        serde_json::from_str(&delivered.entry.envelope.encrypted_payload)?;
    Ok(receiver_session.decrypt(&ciphertext, associated_data)?)
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn reopen_mvp9_alice_db(
    clients: &Mvp9LocalClients,
) -> Result<ramflux_storage::AccountDb, Box<dyn std::error::Error>> {
    let index = ramflux_storage::AccountIndex::open(&clients.root)?;
    Ok(ramflux_storage::AccountDb::open(&index, "alice_mvp9_local", &clients.alice_key)?)
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn reopen_mvp9_bob_db(
    clients: &Mvp9LocalClients,
) -> Result<ramflux_storage::AccountDb, Box<dyn std::error::Error>> {
    let index = ramflux_storage::AccountIndex::open(&clients.root)?;
    Ok(ramflux_storage::AccountDb::open(&index, "bob_mvp9_local", &clients.bob_key)?)
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn assert_mvp9_history_has_no_transient_events(
    db: &ramflux_storage::AccountDb,
) -> Result<(), Box<dyn std::error::Error>> {
    let bundle = db.export_history_bundle("device_mvp9_source", "device_mvp9_target")?;
    assert!(bundle.encrypted_event_batch.is_empty());
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) struct Mvp10OwnDevicesFixture {
    pub(crate) phone_register: ramflux_node_core::IdentityRegisterRequest,
    pub(crate) laptop_register: ramflux_node_core::IdentityRegisterRequest,
    pub(crate) revoked_register: ramflux_node_core::IdentityRegisterRequest,
    pub(crate) phone_db: ramflux_storage::AccountDb,
    pub(crate) laptop_db: ramflux_storage::AccountDb,
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) type Mvp10HttpsJsonServer =
    (std::net::SocketAddr, std::thread::JoinHandle<anyhow::Result<()>>);

#[cfg(all(test, feature = "realnet"))]
pub(crate) type Mvp10AsyncServer =
    (std::net::SocketAddr, tokio::task::JoinHandle<anyhow::Result<()>>);
