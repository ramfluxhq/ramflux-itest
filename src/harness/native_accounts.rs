// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Native realnet users are created through the ordinary exclusive local ceremony.
#![cfg(all(test, feature = "realnet"))]
use ramflux_sdk::{
    LocalBusClient, LocalBusCreationClient, LocalBusRecoveryClient, SdkError,
    custody::{BranchCredentials, MemoryPrimaryVault, PrimaryVault},
};
use std::{path::Path, sync::Mutex};
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// Public daemon-allocated identity plus the simulated user's independently retained phrase.
/// Deliberately has no Debug or serialization implementation.
pub(crate) struct NativeAccount {
    pub account_id: String,
    pub principal_id: String,
    pub device_id: String,
    pub delivery_id: String,
    pub anchor: String,
    pub display_name: String,
    phrase: Zeroizing<String>,
}

pub(crate) const NATIVE_DATA_PASSPHRASE: &str = "native realnet local data passphrase";
pub(crate) const NATIVE_RESTORED_PASSPHRASE: &str = "independent replacement local data password";

/// Test-only vault that retains copies solely for private-material leak assertions.
#[derive(Default)]
pub(crate) struct RecordingPrimaryVault {
    inner: MemoryPrimaryVault,
    secrets: Mutex<Vec<Zeroizing<Vec<u8>>>>,
}

impl RecordingPrimaryVault {
    pub(crate) fn secret_material(&self) -> std::result::Result<Vec<Zeroizing<Vec<u8>>>, SdkError> {
        Ok(self
            .secrets
            .lock()
            .map_err(|_| SdkError::CustodyVaultUnavailable)?
            .iter()
            .map(|secret| Zeroizing::new(secret.to_vec()))
            .collect())
    }

    fn record(&self, secret: &[u8]) -> std::result::Result<(), SdkError> {
        self.secrets
            .lock()
            .map_err(|_| SdkError::CustodyVaultUnavailable)?
            .push(Zeroizing::new(secret.to_vec()));
        Ok(())
    }
}

impl PrimaryVault for RecordingPrimaryVault {
    fn preflight(&self) -> std::result::Result<(), SdkError> {
        self.inner.preflight()
    }

    fn store_new(
        &self,
        reference: &str,
        key: &ramflux_crypto::custody::SelfSigningKey,
    ) -> std::result::Result<(), SdkError> {
        self.inner.store_new(reference, key)?;
        self.record(key.vault_seed().as_slice())
    }

    fn load_primary(
        &self,
        reference: &str,
    ) -> std::result::Result<ramflux_crypto::custody::SelfSigningKey, SdkError> {
        self.inner.load_primary(reference)
    }

    fn load_branch(
        &self,
        reference: &str,
        principal: &str,
        device: &ramflux_protocol::custody::DeviceRef,
    ) -> std::result::Result<BranchCredentials, SdkError> {
        self.inner.load_branch(reference, principal, device)
    }

    fn delete(&self, reference: &str) -> std::result::Result<(), SdkError> {
        self.inner.delete(reference)
    }

    fn store_branch(
        &self,
        reference: &str,
        seeds: &Zeroizing<[u8; 64]>,
    ) -> std::result::Result<(), SdkError> {
        self.inner.store_branch(reference, seeds)?;
        self.record(&seeds[..32])?;
        self.record(&seeds[32..])
    }
}

impl NativeAccount {
    pub(crate) fn recovery_phrase(&self) -> &str {
        self.phrase.as_str()
    }
}

pub(crate) fn native_node_profile(
    node: &super::S8RealnetNode,
    relay: &str,
) -> Result<ramflux_sdk::NodeProfile> {
    let now = ramflux_node_core::now_unix_seconds();
    Ok(ramflux_sdk::NodeProfile {
        discovery_url: String::new(),
        node_id: node.node_id.clone(),
        node_public_key: node.federation_node_public_key.clone(),
        pin_source: ramflux_sdk::NodePinSource::Builtin,
        ca_cert_pem: std::fs::read_to_string(&node.ca_cert)?,
        gateway: ramflux_sdk::NodeGateway {
            quic_addr: node.gateway_quic_addr.to_string(),
            tcp_addr: node.gateway_quic_addr.to_string(),
            server_name: "ramflux-gateway".into(),
        },
        relay: ramflux_sdk::NodeRelay {
            quic_addr: relay.into(),
            server_name: "ramflux-relay".into(),
        },
        prekey_http_url: node.federation_url.clone(),
        signaling_turn_addr: String::new(),
        protocol_versions: vec!["custody_v3".into()],
        client_capabilities: Vec::new(),
        discovered_at: now,
        expires_at: now + 3600,
        enabled: true,
        builtin: true,
        safety_warnings: std::collections::BTreeSet::new(),
    })
}

pub(crate) async fn select_native_node(bus: &mut LocalBusClient, node: &str) -> Result<()> {
    bus.request(None, "node", "node.set_default", serde_json::json!({"node_id":node})).await?;
    Ok(())
}

pub(crate) async fn create_native_account(
    socket: &Path,
    display_name: &str,
) -> Result<NativeAccount> {
    let mut ceremony = LocalBusCreationClient::connect(socket).await?;
    ceremony.begin(display_name, ramflux_protocol::PrincipalKind::Human).await?;
    // This buffer represents the test user's saved recovery artifact, never daemon state.
    let phrase = ceremony.show_once().await?;
    let positions = ceremony.hidden_challenge().await?;
    let saved_words: Vec<_> = phrase.split_whitespace().collect();
    let words = std::array::from_fn(|index| {
        Zeroizing::new(saved_words[usize::from(positions[index] - 1)].to_owned())
    });
    let account =
        ceremony.confirm(&words, &Zeroizing::new(NATIVE_DATA_PASSPHRASE.to_owned())).await?;
    eprintln!(
        "STEP: native creation confirmed account={} networking={:?}",
        account.account_id, account.networking
    );
    assert_eq!(account.networking, ramflux_sdk::custody::CreationState::Live);
    let mut bus = LocalBusClient::connect(socket).await?;
    let status = bus
        .request(
            Some(account.account_id.clone()),
            "account",
            "account.status",
            serde_json::json!({}),
        )
        .await?;
    let field = |name: &str| -> Result<String> {
        Ok(status[name].as_str().ok_or("native account status field missing")?.to_owned())
    };
    assert_eq!(status["networking"], "live");
    Ok(NativeAccount {
        account_id: account.account_id,
        principal_id: field("principal_id")?,
        device_id: field("device_id")?,
        delivery_id: field("target_delivery_id")?,
        anchor: field("principal_commitment")?,
        display_name: display_name.to_owned(),
        phrase,
    })
}

pub(crate) async fn recover_native_account(
    socket: &Path,
    account_id: &str,
    owner: &NativeAccount,
    passphrase: &str,
) -> Result<ramflux_sdk::LocalBusCreatedAccount> {
    let mut ceremony = LocalBusRecoveryClient::connect(socket).await?;
    let pending = ceremony.begin(account_id).await?;
    assert_eq!(pending.account_anchor, owner.anchor);
    let account = ceremony
        .confirm(&owner.phrase, &Zeroizing::new(passphrase.to_owned()), &owner.anchor)
        .await?;
    eprintln!(
        "STEP: native recovery confirmed account={} networking={:?}",
        account.account_id, account.networking
    );
    Ok(account)
}
