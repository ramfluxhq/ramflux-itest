// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Shared production-compose test trust material and cleanup.
/// RAII holder for the test-generated production trust material. Writes the three files the production
/// compose mounts and removes exactly those files on drop (leaving `.gitkeep`/`README.md` intact).
#[cfg(feature = "realnet")]
pub(crate) struct T22ProductionMaterials {
    files: Vec<std::path::PathBuf>,
}

#[cfg(feature = "realnet")]
impl T22ProductionMaterials {
    pub(crate) fn write(
        deploy_root: &std::path::Path,
        certificate: &ramflux_node_core::GatewayIssuerCertificate,
        envelope: &ramflux_node_core::ProviderSignedTrustSnapshot,
        keyring: &ramflux_node_core::ProviderKeyring,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let gateway_v3_dir = deploy_root.join("secrets/gateway-v3");
        let federation_dir = deploy_root.join("secrets/federation");
        std::fs::create_dir_all(&gateway_v3_dir)?;
        std::fs::create_dir_all(&federation_dir)?;

        let issuer_cert = gateway_v3_dir.join("issuer-cert.json");
        let trust_snapshot = federation_dir.join("trust-snapshot.json");
        let provider_keyring = federation_dir.join("provider-keyring.json");

        std::fs::write(&issuer_cert, serde_json::to_vec_pretty(certificate)?)?;
        std::fs::write(&trust_snapshot, serde_json::to_vec_pretty(envelope)?)?;
        std::fs::write(&provider_keyring, serde_json::to_vec_pretty(keyring)?)?;

        Ok(Self { files: vec![issuer_cert, trust_snapshot, provider_keyring] })
    }
}

#[cfg(feature = "realnet")]
impl Drop for T22ProductionMaterials {
    fn drop(&mut self) {
        for file in &self.files {
            let _removed = std::fs::remove_file(file);
        }
    }
}

/// Gateway v3 issuer certificate: binds the gateway attestation public key to the node root, signed by
/// the node root key. Mirrors the s55 material builder, anchored on the single production node id.
#[cfg(feature = "realnet")]
pub(crate) fn t22_certificate(
    now: u64,
    valid_for: u64,
    node_id: &str,
    gateway_instance_id: &str,
    root_seed: [u8; 32],
    attestation_seed: [u8; 32],
) -> Result<ramflux_node_core::GatewayIssuerCertificate, Box<dyn std::error::Error>> {
    let mut certificate = ramflux_node_core::GatewayIssuerCertificate {
        schema: ramflux_node_core::GATEWAY_ISSUER_CERTIFICATE_SCHEMA.to_owned(),
        version: ramflux_node_core::OBJECT_RELAY_V3_PROOF_VERSION,
        cert_id: "t22-gw-cert-1".to_owned(),
        node_id: node_id.to_owned(),
        gateway_instance_id: gateway_instance_id.to_owned(),
        attestation_public_key: ramflux_crypto::public_key_base64url_from_seed(attestation_seed),
        attestation_key_id: "t22-gw-attestation-1".to_owned(),
        not_before: now.saturating_sub(60),
        not_after: now + valid_for,
        issued_at: now.saturating_sub(60),
        node_root_signing_key_id: "node-localhost#root-1".to_owned(),
        node_root_signature: String::new(),
        revoked_at: None,
    };
    certificate.node_root_signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &ramflux_node_core::gateway_issuer_certificate_signing_bytes(&certificate)?,
        root_seed,
    );
    Ok(certificate)
}

/// Provider-signed trust snapshot envelope (keyring-era v4), carrying the node root key and signed by
/// the provider key authorized in the keyring.
#[cfg(feature = "realnet")]
pub(crate) fn t22_trust_envelope(
    now: u64,
    valid_for: u64,
    node_id: &str,
    root_seed: [u8; 32],
    provider_seed: [u8; 32],
    certificate: &ramflux_node_core::GatewayIssuerCertificate,
) -> Result<ramflux_node_core::ProviderSignedTrustSnapshot, Box<dyn std::error::Error>> {
    let mut envelope = ramflux_node_core::ProviderSignedTrustSnapshot {
        schema: ramflux_node_core::PROVIDER_SIGNED_TRUST_SNAPSHOT_ENVELOPE_SCHEMA.to_owned(),
        version: ramflux_node_core::PROVIDER_SIGNED_TRUST_SNAPSHOT_ENVELOPE_VERSION,
        snapshot: ramflux_node_core::FederatedIssuerTrustSnapshot {
            schema: ramflux_node_core::FEDERATED_ISSUER_TRUST_SNAPSHOT_SCHEMA.to_owned(),
            version: ramflux_node_core::OBJECT_RELAY_V3_PROOF_VERSION,
            node_id: node_id.to_owned(),
            generation: 1,
            pin_epoch: 1,
            trust_status: ramflux_node_core::FederatedIssuerTrustStatus::Active,
            roots: vec![ramflux_node_core::TrustedNodeRootKey {
                node_id: node_id.to_owned(),
                key_id: certificate.node_root_signing_key_id.clone(),
                public_key: ramflux_crypto::public_key_base64url_from_seed(root_seed),
                not_before: now.saturating_sub(60),
                not_after: now + valid_for,
                pin_epoch: 1,
                retired_at: None,
            }],
            revoked_cert_ids: std::collections::BTreeSet::new(),
            hard_stale_at: now + valid_for,
        },
        provider_signing_key_id: "t22-provider-1".to_owned(),
        provider_public_key: ramflux_crypto::public_key_base64url_from_seed(provider_seed),
        provider_epoch: 1,
        issued_at: now.saturating_sub(10),
        expires_at: now + valid_for,
        signature: String::new(),
    };
    envelope.signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &ramflux_node_core::provider_signed_trust_snapshot_signing_bytes(&envelope)?,
        provider_seed,
    );
    Ok(envelope)
}

/// Offline-root-signed provider keyring authorizing the single provider key for `provider_epoch` 1.
#[cfg(feature = "realnet")]
pub(crate) fn t22_provider_keyring(
    now: u64,
    valid_for: u64,
    node_id: &str,
    offline_root_seed: [u8; 32],
    provider_seed: [u8; 32],
) -> Result<ramflux_node_core::ProviderKeyring, Box<dyn std::error::Error>> {
    let mut keyring = ramflux_node_core::ProviderKeyring {
        schema: ramflux_node_core::PROVIDER_KEYRING_SCHEMA.to_owned(),
        version: ramflux_node_core::PROVIDER_KEYRING_VERSION,
        issuer_node_id: node_id.to_owned(),
        keyring_epoch: 1,
        keys: vec![ramflux_node_core::ProviderKeyEntry {
            key_id: "t22-provider-1".to_owned(),
            public_key: ramflux_crypto::public_key_base64url_from_seed(provider_seed),
            not_before: now.saturating_sub(60),
            not_after: now + valid_for,
            retired_at: None,
            authorized_provider_epoch: 1,
        }],
        keyring_signature: String::new(),
    };
    keyring.keyring_signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &ramflux_node_core::provider_keyring_signing_bytes(&keyring)?,
        offline_root_seed,
    );
    Ok(keyring)
}
