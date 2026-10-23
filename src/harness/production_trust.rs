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

#[cfg(feature = "realnet")]
#[path = "production_trust_signing.rs"]
mod signing;
#[cfg(feature = "realnet")]
pub(crate) use signing::{t22_certificate, t22_provider_keyring, t22_trust_envelope};
