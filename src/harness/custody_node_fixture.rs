// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Explicit realnet fixture; signed discovery uses the harness's receiving-node identity.
use ramflux_protocol::custody::*;
use std::path::Path;
pub(crate) fn provision(
    directory: &Path,
    node_id: &str,
    root_seed: [u8; 32],
) -> Result<Vec<(String, String)>, Box<dyn std::error::Error>> {
    let root = ed25519_dalek::SigningKey::from_bytes(&root_seed);
    // Instance identities must match both the base and cross-gateway compose topology.
    // Each instance has a distinct fixture key; no key is shared between proxy identities.
    let proxies = [("ramflux-gateway", 0x91), ("gw-a", 0x93), ("gw-b", 0x95)];
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
            proxy_keys: proxies
                .iter()
                .map(|(proxy_id, byte)| {
                    let proxy = ed25519_dalek::SigningKey::from_bytes(&[*byte; 32]);
                    ProxyKey {
                        key_id: ramflux_protocol::encode_base64url([*byte + 1; 32]),
                        public_key: ramflux_protocol::encode_base64url(
                            proxy.verifying_key().to_bytes(),
                        ),
                        not_before: now.saturating_sub(5),
                        sign_until: now + 3600,
                        overlap_until: now + 605_500,
                        status: ReceiptKeyStatus::Active,
                        proxy_id: (*proxy_id).into(),
                        audiences: vec![node_id.into()],
                    }
                })
                .collect(),
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
            ramflux_protocol::encode_base64url([0x91; 32]),
        ),
        (
            "RAMFLUX_CUSTODY_GATEWAY_A_SIGNING_SEED".into(),
            ramflux_protocol::encode_base64url([0x93; 32]),
        ),
        (
            "RAMFLUX_CUSTODY_GATEWAY_B_SIGNING_SEED".into(),
            ramflux_protocol::encode_base64url([0x95; 32]),
        ),
        ("RAMFLUX_CUSTODY_NODE_RECORD_FILE".into(), "/etc/ramflux/mesh/custody-node.json".into()),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Root(std::path::PathBuf);
    impl Drop for Root {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn signed_fixture_authorizes_distinct_keys_for_all_deployed_gateway_instances()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = Root(crate::temp_root("custody_deployed_gateways")?);
        std::fs::create_dir_all(root.0.join("certs/router"))?;
        let env = provision(&root.0, "fixture.example", [7; 32])?
            .into_iter()
            .collect::<std::collections::BTreeMap<_, _>>();
        let record: Envelope<NodeIdentityRecord> =
            decode(&std::fs::read(root.0.join("certs/router/custody-node.json"))?, 512 * 1024)?;
        let verified = ramflux_crypto::custody::verify_node_identity_record(
            &record,
            "fixture.example",
            env.get("RAMFLUX_CUSTODY_NODE_PUBLIC_KEY").ok_or("node key missing")?,
            ramflux_node_core::now_unix_seconds(),
        )?;
        let mut public_keys = std::collections::BTreeSet::new();
        for (id, variable) in [
            ("ramflux-gateway", "RAMFLUX_CUSTODY_PROXY_SIGNING_SEED"),
            ("gw-a", "RAMFLUX_CUSTODY_GATEWAY_A_SIGNING_SEED"),
            ("gw-b", "RAMFLUX_CUSTODY_GATEWAY_B_SIGNING_SEED"),
        ] {
            let seed: [u8; 32] =
                ramflux_protocol::decode_base64url(env.get(variable).ok_or("proxy seed missing")?)?
                    .try_into()
                    .map_err(|_| "proxy seed length")?;
            let public = ramflux_protocol::encode_base64url(
                ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key().to_bytes(),
            );
            let key = verified
                .envelope()
                .body
                .proxy_keys
                .iter()
                .find(|key| key.proxy_id == id)
                .ok_or("deployed proxy identity unauthorized")?;
            assert_eq!(key.public_key, public);
            assert_eq!(key.audiences, ["fixture.example"]);
            assert!(public_keys.insert(public), "gateway instances must not share keys");
        }
        Ok(())
    }

    #[test]
    fn native_realnet_projects_provision_custody_credentials_by_default()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = Root(crate::temp_root("custody_fixture_disabled")?);
        std::fs::create_dir_all(root.0.join("certs/router"))?;
        let values = provision(&root.0, "fixture.example", [7; 32])?;
        assert!(values.iter().any(|(key, _)| key == "RAMFLUX_CUSTODY_NODE_PUBLIC_KEY"));
        assert!(root.0.join("certs/router/custody-node.json").exists());
        Ok(())
    }
}
