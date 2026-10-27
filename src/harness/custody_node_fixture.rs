// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Explicit realnet fixture; signed discovery uses the harness's receiving-node identity.
use ramflux_protocol::custody::*;
use std::path::Path;
pub(crate) fn provision_if_enabled(
    extra_env: &[(String, String)],
    directory: &Path,
    node_id: &str,
    root_seed: [u8; 32],
) -> Result<Vec<(String, String)>, Box<dyn std::error::Error>> {
    if extra_env.iter().any(|(key, value)| key == "RAMFLUX_CUSTODY_ITEST_ENABLE" && value == "1") {
        provision(directory, node_id, root_seed)
    } else {
        Ok(Vec::new())
    }
}
fn provision(
    directory: &Path,
    node_id: &str,
    root_seed: [u8; 32],
) -> Result<Vec<(String, String)>, Box<dyn std::error::Error>> {
    let root = ed25519_dalek::SigningKey::from_bytes(&root_seed);
    let proxy_seed = [0x91; 32];
    let proxy = ed25519_dalek::SigningKey::from_bytes(&proxy_seed);
    let now = ramflux_node_core::now_unix_seconds();
    let record = ramflux_crypto::custody::sign_node_identity_record(
        &root,
        NodeIdentityRecord {
            schema: ramflux_protocol::domain::CUSTODY_NODE_RECORD.into(),
            version: 1,
            node_id: node_id.into(),
            node_signing_public_key: ramflux_protocol::encode_base64url(
                root.verifying_key().to_bytes(),
            ),
            client_tls_certificate_sha256: None,
            epoch: 1,
            previous_record_hash: None,
            issued_at: now,
            receipt_keys: vec![],
            revoked_receipt_key_ids: vec![],
            proxy_keys: vec![ProxyKey {
                key_id: ramflux_protocol::encode_base64url([0x92; 32]),
                public_key: ramflux_protocol::encode_base64url(proxy.verifying_key().to_bytes()),
                not_before: now.saturating_sub(5),
                sign_until: now + 3600,
                overlap_until: now + 605_500,
                status: ReceiptKeyStatus::Active,
                proxy_id: "ramflux-gateway".into(),
                audiences: vec![node_id.into()],
            }],
            revoked_proxy_key_ids: vec![],
            channel_binding_modes: vec![BindingMode::HomeRelayReceipt],
        },
    )?;
    std::fs::write(directory.join("certs/router/custody-node.json"), serde_json::to_vec(&record)?)?;
    Ok(vec![
        (
            "RAMFLUX_CUSTODY_NODE_PUBLIC_KEY".into(),
            ramflux_protocol::encode_base64url(root.verifying_key().to_bytes()),
        ),
        (
            "RAMFLUX_CUSTODY_PROXY_SIGNING_SEED".into(),
            ramflux_protocol::encode_base64url(proxy_seed),
        ),
        ("RAMFLUX_CUSTODY_NODE_RECORD_FILE".into(), "/etc/ramflux/mesh/custody-node.json".into()),
    ])
}
