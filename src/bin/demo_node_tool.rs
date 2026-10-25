// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Persistent demo trust provisioning and signed discovery/QUIC verification.
#[path = "../harness/production_trust_signing.rs"]
mod signing;

use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ramflux_protocol::{WellKnownClientRecord, encode_base64url, verify_client_discovery_record};
use ramflux_transport::{RelayClientQuicConfig, relay_client_quic_health};
use serde::{Deserialize, Serialize};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Deserialize, Serialize)]
struct Identity {
    node_id: String,
    expires_at: u64,
    root: [u8; 32],
    attestation: [u8; 32],
    provider: [u8; 32],
    offline: [u8; 32],
    discovery: [u8; 32],
    service: [u8; 32],
    admin: [u8; 32],
}

fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn random_seed() -> Result<[u8; 32]> {
    let mut seed = [0; 32];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut seed)?;
    Ok(seed)
}

fn initialize(dir: &Path, node_id: &str) -> Result {
    let identity_path = dir.join("identity.json");
    let timestamp = now()?;
    let identity: Identity = if identity_path.exists() {
        serde_json::from_slice(&std::fs::read(&identity_path)?)?
    } else {
        let identity = Identity {
            node_id: node_id.to_owned(),
            expires_at: timestamp + 365 * 86400,
            root: random_seed()?,
            attestation: random_seed()?,
            provider: random_seed()?,
            offline: random_seed()?,
            discovery: random_seed()?,
            service: random_seed()?,
            admin: random_seed()?,
        };
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(identity_path)?;
        serde_json::to_writer_pretty(&mut file, &identity)?;
        identity
    };
    if identity.node_id != node_id || identity.expires_at <= timestamp + 3600 {
        return Err(
            "identity node mismatch or trust expires within one hour; operator renewal required"
                .into(),
        );
    }
    let lifetime = identity.expires_at - timestamp;
    let certificate = signing::t22_certificate(
        timestamp,
        lifetime,
        node_id,
        "demo-gateway",
        identity.root,
        identity.attestation,
    )?;
    let envelope = signing::t22_trust_envelope(
        timestamp,
        lifetime,
        node_id,
        identity.root,
        identity.provider,
        &certificate,
    )?;
    let keyring = signing::t22_provider_keyring(
        timestamp,
        lifetime,
        node_id,
        identity.offline,
        identity.provider,
    )?;
    for (file, bytes) in [
        ("secrets/gateway-v3/issuer-cert.json", serde_json::to_vec_pretty(&certificate)?),
        ("secrets/federation/trust-snapshot.json", serde_json::to_vec_pretty(&envelope)?),
        ("secrets/federation/provider-keyring.json", serde_json::to_vec_pretty(&keyring)?),
    ] {
        let path = dir.join(file);
        std::fs::create_dir_all(path.parent().ok_or("missing parent")?)?;
        // Existing valid material is stable across restarts; recover incomplete initialization.
        if !path.exists() {
            std::fs::write(path, bytes)?;
        }
    }
    validate_saved_trust(dir, &identity, timestamp)?;
    let key_path = dir.join("certs/node-identity/node-signing.key");
    std::fs::create_dir_all(key_path.parent().ok_or("missing discovery secret directory")?)?;
    // Group-readable: the capability-dropped services read it through RAMFLUX_SECRET_GID.
    let mut key = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o640)
        .open(&key_path)?;
    key.write_all(encode_base64url(identity.discovery).as_bytes())?;
    key.sync_all()?;
    std::fs::set_permissions(&key_path, std::os::unix::fs::PermissionsExt::from_mode(0o640))?;
    let env = format!(
        "RAMFLUX_NODE_SERVICE_SIGNING_SEED_B64URL={}\nRAMFLUX_GATEWAY_V3_ISSUER_SEED={}\nRAMFLUX_FEDERATION_PROVIDER_OFFLINE_ROOT_PUBLIC_KEY={}\nRAMFLUX_FEDERATION_NODE_SIGNING_SEED_FILE=/etc/ramflux/node-identity/node-signing.key\nRAMFLUX_ROUTER_ADMIN_TOKEN={}\nRAMFLUX_FEDERATION_ADMIN_TOKEN={}\nDEMO_EXPECTED_NODE_PUBLIC_KEY={}\n",
        encode_base64url(identity.service),
        encode_base64url(identity.attestation),
        ramflux_crypto::public_key_base64url_from_seed(identity.offline),
        encode_base64url(identity.admin),
        encode_base64url(identity.admin),
        ramflux_crypto::public_key_base64url_from_seed(identity.discovery),
    );
    let mut env_file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(dir.join("identity.env"))?;
    env_file.write_all(env.as_bytes())?;
    println!("trust ready; expires_at={}", identity.expires_at);
    Ok(())
}

fn validate_saved_trust(dir: &Path, identity: &Identity, timestamp: u64) -> Result {
    let node_id = &identity.node_id;
    let saved_certificate = serde_json::from_slice::<ramflux_node_core::GatewayIssuerCertificate>(
        &std::fs::read(dir.join("secrets/gateway-v3/issuer-cert.json"))?,
    )?;
    let saved_envelope = serde_json::from_slice::<ramflux_node_core::ProviderSignedTrustSnapshot>(
        &std::fs::read(dir.join("secrets/federation/trust-snapshot.json"))?,
    )?;
    let saved_keyring = serde_json::from_slice::<ramflux_node_core::ProviderKeyring>(
        &std::fs::read(dir.join("secrets/federation/provider-keyring.json"))?,
    )?;
    let validated = ramflux_node_core::verify_provider_keyring(
        &saved_keyring,
        &ramflux_crypto::public_key_base64url_from_seed(identity.offline),
        node_id,
    )?;
    ramflux_node_core::verify_provider_signed_trust_snapshot(
        &saved_envelope,
        &validated,
        timestamp,
    )?;
    ramflux_node_core::verify_gateway_issuer_certificate(
        &saved_certificate,
        &ramflux_crypto::public_key_base64url_from_seed(identity.root),
        node_id,
        "demo-gateway",
        timestamp,
    )?;
    if saved_certificate.attestation_public_key
        != ramflux_crypto::public_key_base64url_from_seed(identity.attestation)
    {
        return Err("saved issuer certificate does not match gateway seed".into());
    }
    Ok(())
}

async fn verify(origin: &str, expected_key: &str) -> Result {
    let url = format!("{}/.well-known/ramflux/client", origin.trim_end_matches('/'));
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let mut response = client.get(url).send().await?.error_for_status()?;
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if bytes.len() + chunk.len() > 1024 * 1024 {
            return Err("discovery record exceeds size limit".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    let record: WellKnownClientRecord = serde_json::from_slice(&bytes)?;
    verify_client_discovery_record(&record, now()?)?;
    if record.node_public_key != expected_key {
        return Err("discovery public key does not match operator pin".into());
    }
    println!("discovery signature, freshness and operator pin: healthy ({})", record.node_id);
    println!(
        "node key fingerprint: {}",
        ramflux_protocol::hash_hex(
            ramflux_protocol::CLIENT_DISCOVERY_DOMAIN,
            record.node_public_key.as_bytes(),
        )
    );
    let ca = TemporaryCa::write(&record.node_ca_cert_pem)?;
    let gateway = ramflux_sdk::probe_gateway_pre_account(&record, &ca.0).await;
    if gateway.app != "ok" {
        return Err(format!(
            "gateway pre-account probe failed: {}",
            serde_json::to_string(&gateway)?
        )
        .into());
    }
    println!(
        "gateway pre-account health: healthy (quic={} tcp={} session={})",
        gateway.transport["quic"].as_str().unwrap_or("not_available"),
        gateway.transport["tcp"].as_str().unwrap_or("not_available"),
        gateway.session,
    );
    let peer = tokio::net::lookup_host(&record.relay_quic_addr)
        .await?
        .next()
        .ok_or("relay endpoint has no resolved addresses")?;
    let config = RelayClientQuicConfig::new(&peer.to_string(), &record.relay_server_name, &ca.0)?;
    let response = relay_client_quic_health(&config, Duration::from_secs(10)).await?;
    if response.status != 200 {
        return Err(format!("relay QUIC unhealthy: {response:?}").into());
    }
    println!("relay QUIC TLS/application health: healthy ({})", record.relay_quic_addr);
    Ok(())
}

struct TemporaryCa(PathBuf);
impl TemporaryCa {
    fn write(pem: &str) -> Result<Self> {
        let path = std::env::temp_dir()
            .join(format!("ramflux-demo-ca-{}.pem", encode_base64url(random_seed()?)));
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(&path)?;
        file.write_all(pem.as_bytes())?;
        Ok(Self(path))
    }
}
impl Drop for TemporaryCa {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[tokio::main]
async fn main() -> Result {
    let args: Vec<_> = std::env::args().collect();
    match args.as_slice() {
        [_, command, directory, node] if command == "init" => {
            initialize(Path::new(directory), node)
        }
        [_, command, origin, key] if command == "verify" => {
            tokio::time::timeout(Duration::from_secs(45), verify(origin, key)).await?
        }
        _ => Err("usage: demo-node-tool init DATA_DIR NODE_ID | verify ORIGIN EXPECTED_PUBLIC_KEY"
            .into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    struct TestDirectory(PathBuf);
    impl TestDirectory {
        fn create() -> Result<Self> {
            let path = std::env::temp_dir()
                .join(format!("ramflux-demo-test-{}", encode_base64url(random_seed()?)));
            std::fs::create_dir(&path)?;
            Ok(Self(path))
        }
    }
    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn restart_preserves_identity_trust_and_private_file_permissions() -> Result {
        let dir = TestDirectory::create()?;
        initialize(&dir.0, "demo.invalid")?;
        let files = [
            "identity.json",
            "identity.env",
            "certs/node-identity/node-signing.key",
            "secrets/gateway-v3/issuer-cert.json",
            "secrets/federation/provider-keyring.json",
            "secrets/federation/trust-snapshot.json",
        ];
        let before: Vec<_> = files
            .iter()
            .map(|file| std::fs::read(dir.0.join(file)))
            .collect::<std::io::Result<_>>()?;
        initialize(&dir.0, "demo.invalid")?;
        for (file, bytes) in files.iter().zip(before) {
            assert_eq!(std::fs::read(dir.0.join(file))?, bytes);
        }
        for file in ["identity.json", "identity.env"] {
            assert_eq!(std::fs::metadata(dir.0.join(file))?.permissions().mode() & 0o777, 0o600);
        }
        let key = dir.0.join("certs/node-identity/node-signing.key");
        assert_eq!(std::fs::metadata(key)?.permissions().mode() & 0o777, 0o640);
        let identity: Identity =
            serde_json::from_slice(&std::fs::read(dir.0.join("identity.json"))?)?;
        let environment = std::fs::read_to_string(dir.0.join("identity.env"))?;
        for seed in [identity.root, identity.provider, identity.offline, identity.discovery] {
            assert!(!environment.contains(&encode_base64url(seed)));
        }
        assert!(environment.contains(&encode_base64url(identity.service)));
        assert!(initialize(&dir.0, "other.invalid").is_err());
        Ok(())
    }

    #[test]
    fn refuses_tampered_existing_trust_without_overwriting_it() -> Result {
        let dir = TestDirectory::create()?;
        initialize(&dir.0, "demo.invalid")?;
        let path = dir.0.join("secrets/federation/provider-keyring.json");
        let mut keyring: ramflux_node_core::ProviderKeyring =
            serde_json::from_slice(&std::fs::read(&path)?)?;
        keyring.keyring_epoch += 1;
        let bad = serde_json::to_vec(&keyring)?;
        std::fs::write(&path, &bad)?;
        assert!(initialize(&dir.0, "demo.invalid").is_err());
        assert_eq!(std::fs::read(path)?, bad);
        Ok(())
    }

    #[test]
    fn refuses_expired_identity_without_rotating_keys() -> Result {
        let dir = TestDirectory::create()?;
        initialize(&dir.0, "demo.invalid")?;
        let path = dir.0.join("identity.json");
        let mut identity: Identity = serde_json::from_slice(&std::fs::read(&path)?)?;
        identity.expires_at = now()?;
        let expired = serde_json::to_vec(&identity)?;
        std::fs::write(&path, &expired)?;
        assert!(initialize(&dir.0, "demo.invalid").is_err());
        assert_eq!(std::fs::read(path)?, expired);
        Ok(())
    }
}
