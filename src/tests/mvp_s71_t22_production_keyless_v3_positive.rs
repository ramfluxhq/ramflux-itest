// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

// T22-A3-PROD-POSITIVE: prove the REAL production `deploy/docker-compose.yml` (not any
// `docker-compose.itest*.yml`) boots in keyless v3 mode and that the relay's client-facing QUIC
// listener reaches health — using only NON-SECRET, deterministic, test-generated trust materials.
//
// Why this exists: at product 42995ec the production relay fails closed (`compose config` `:?`) unless
// the keyring-era v3 trust chain is supplied — offline-root-signed provider keyring + provider-signed
// trust snapshot + gateway v3 issuer cert. The S10/S22 production harness does NOT generate that chain,
// so there is no runtime evidence that the production compose can start keyless-v3. This test closes
// that gap for the relay-QUIC-healthy milestone (public-SDK object over production compose is left as a
// follow-up; see the report in the module `expect`-free `Ok` path at the end).
//
// Runtime scope: build-prod-images.sh compiles the 7 node binaries on the host and the thin runtime
// images run them, so a green run REQUIRES a Linux host with a docker/podman compose provider. On macOS
// the host binaries are Mach-O and cannot run in the Linux containers; this file therefore compiles
// everywhere but only PASSES on Linux. It is gated behind RAMFLUX_T22_PRODUCTION_POSITIVE=1 and never
// runs in the default suite.
#![allow(unused_imports)]
// Fixtures below are consumed only by the realnet-gated test; keep them compiling in all builds but
// silence dead_code when realnet is compiled out.
#![cfg_attr(not(feature = "realnet"), allow(dead_code))]
use super::*;

#[cfg(feature = "realnet")]
#[test]
#[allow(clippy::too_many_lines)]
fn t22_production_keyless_v3_positive_relay_quic_health() -> Result<(), Box<dyn std::error::Error>>
{
    if std::env::var("RAMFLUX_T22_PRODUCTION_POSITIVE").as_deref() != Ok("1") {
        eprintln!(
            "skipping T22 production positive (relay QUIC health); set RAMFLUX_T22_PRODUCTION_POSITIVE=1 (Linux + docker/podman required)"
        );
        return Ok(());
    }

    let code_root = code_root();
    let deploy_root = code_root.join("ramflux/deploy");
    let compose_path = deploy_root.join("docker-compose.yml");

    // Static guard (also covered by s70): the production data plane is keyless — no legacy relay
    // object HMAC key is wired into the production compose.
    let compose = std::fs::read_to_string(&compose_path)?;
    assert!(
        !compose.contains("RAMFLUX_RELAY_SERVICE_KEY_REF"),
        "production compose must not configure the legacy relay object HMAC key"
    );

    // Single-node private deployment: the federation node id / trust issuer defaults to "localhost"
    // (see docker-compose.yml `RAMFLUX_FEDERATION_NODE_ID:-localhost` and provision-node.sh node_id).
    let issuer_node = "localhost";
    let gateway_instance_id = "gw-localhost";

    // DETERMINISTIC TEST-ONLY SEEDS. These are NOT secrets: every byte is a fixed constant checked into
    // the test, and the material derived from them is authorized only against the offline-root PUBLIC
    // key we also derive here and pin via env. No production key material is ever used or emitted.
    let root_seed = [0x44_u8; 32]; // node root signing key (roots[] in the trust snapshot)
    let attestation_seed = [0x33_u8; 32]; // gateway v3 attestation/issuer key (RAMFLUX_GATEWAY_V3_ISSUER_SEED)
    let provider_seed = [0x66_u8; 32]; // provider key that signs the trust-snapshot envelope
    let offline_root_seed = [0x88_u8; 32]; // offline signing root that authorizes the provider keyring

    // Certs + host-built binaries first (these can take minutes), THEN compute `now` and mint the trust
    // material with a generous 1-hour validity window so nothing goes stale during the image build.
    run_deploy_script(&code_root, "ramflux/deploy/scripts/bootstrap-ca.sh")?;
    run_deploy_script(&code_root, "ramflux/deploy/scripts/issue-certs.sh")?;
    run_deploy_script(&code_root, "ramflux/deploy/scripts/build-prod-images.sh")?;

    let now = ramflux_node_core::now_unix_seconds();
    let valid_for = 3_600_u64;
    let certificate = t22_certificate(
        now,
        valid_for,
        issuer_node,
        gateway_instance_id,
        root_seed,
        attestation_seed,
    )?;
    let envelope =
        t22_trust_envelope(now, valid_for, issuer_node, root_seed, provider_seed, &certificate)?;
    let keyring =
        t22_provider_keyring(now, valid_for, issuer_node, offline_root_seed, provider_seed)?;

    // Place the material at the fixed container paths the production compose bind-mounts read-only:
    //   ./secrets/gateway-v3  -> /etc/ramflux/gateway-v3   (issuer-cert.json)
    //   ./secrets/federation  -> /etc/ramflux/federation   (provider-keyring.json + trust-snapshot.json)
    // The guard removes exactly the files it wrote on drop (never the tracked .gitkeep/README), so the
    // product working tree is left clean even on panic.
    let _materials =
        T22ProductionMaterials::write(&deploy_root, &certificate, &envelope, &keyring)?;

    // Unique host ports so a concurrent S10/S22 run does not collide.
    let relay_quic_port = 57_447_u16;
    let env = vec![
        // Relay keyring-era v3 trust (all `:?` in the production compose — required to boot).
        ("RAMFLUX_FEDERATION_TRUST_ENDPOINT".to_owned(), "ramflux-federation:7443".to_owned()),
        (
            "RAMFLUX_FEDERATION_PROVIDER_OFFLINE_ROOT_PUBLIC_KEY".to_owned(),
            ramflux_crypto::public_key_base64url_from_seed(offline_root_seed),
        ),
        ("RAMFLUX_FEDERATION_TRUST_ISSUER_NODE_ID".to_owned(), issuer_node.to_owned()),
        // Gateway v3 issuance material (gateway fails closed without it).
        (
            "RAMFLUX_GATEWAY_V3_ISSUER_SEED".to_owned(),
            ramflux_protocol::encode_base64url(attestation_seed),
        ),
        // Distinct host port block.
        ("RAMFLUX_RELAY_CLIENT_QUIC_PORT".to_owned(), relay_quic_port.to_string()),
        ("RAMFLUX_GATEWAY_TCP_PORT".to_owned(), "57443".to_owned()),
        ("RAMFLUX_GATEWAY_QUIC_PORT".to_owned(), "57443".to_owned()),
        ("RAMFLUX_SIGNALING_TURN_UDP_PORT".to_owned(), "57478".to_owned()),
        ("RAMFLUX_SIGNALING_TURN_TCP_PORT".to_owned(), "57479".to_owned()),
        ("RAMFLUX_FEDERATION_ADMIN_PORT".to_owned(), "57482".to_owned()),
        ("RAMFLUX_FEDERATION_MESH_PORT".to_owned(), "57453".to_owned()),
    ];

    let project = "ramflux-t22-prod-positive";
    run_production_compose_project(&deploy_root, project, &env, &["up", "--build", "-d"])?;
    let _guard = ProductionComposeDownGuard::new(deploy_root.clone(), project.to_owned(), env);

    // Prove the relay client-facing QUIC listener reaches health over the production compose.
    let relay_ca = code_root.join("ramflux/deploy/certs/ca.pem");
    let relay_quic_addr = format!("127.0.0.1:{relay_quic_port}");
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    let health_result = runtime.block_on(async {
        let config = ramflux_transport::RelayClientQuicConfig::new(
            &relay_quic_addr,
            "ramflux-relay",
            &relay_ca,
        )?;
        // The relay may take a moment to load the keyring, fetch/verify the snapshot, and open the
        // listener; poll health rather than assuming instant readiness.
        let mut last_error: String = "relay QUIC health never attempted".to_owned();
        for _attempt in 0..30_u32 {
            match ramflux_transport::relay_client_quic_health(
                &config,
                std::time::Duration::from_secs(5),
            )
            .await
            {
                Ok(health) if health.status == 200 => return Ok(()),
                Ok(health) => last_error = format!("relay QUIC health status {}", health.status),
                Err(error) => last_error = format!("relay QUIC health error: {error}"),
            }
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
        Err::<(), Box<dyn std::error::Error>>(
            format!("relay client QUIC listener never became healthy: {last_error}").into(),
        )
    });
    if let Err(error) = health_result {
        return Err(format!(
            "{error}\n\n--- docker ps ({project}) ---\n{}\n\n--- docker logs ({project}) ---\n{}",
            t22_docker_ps(project),
            t22_project_logs(project),
        )
        .into());
    }

    // Keyless v3 fail-closed also means the relay never serves an HTTP object surface: assert no
    // client HTTP object request reached the relay while it was up.
    let relay_logs = t22_container_logs(project, "ramflux-relay");
    assert!(
        !relay_logs.contains("/relay/v1/object"),
        "production relay must not serve any HTTP object request in keyless v3 mode:\n{relay_logs}"
    );

    Ok(())
}

/// RAII holder for the test-generated production trust material. Writes the three files the production
/// compose mounts and removes exactly those files on drop (leaving `.gitkeep`/`README.md` intact).
#[cfg(feature = "realnet")]
struct T22ProductionMaterials {
    files: Vec<std::path::PathBuf>,
}

#[cfg(feature = "realnet")]
impl T22ProductionMaterials {
    fn write(
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
fn t22_certificate(
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
fn t22_trust_envelope(
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
fn t22_provider_keyring(
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

#[cfg(feature = "realnet")]
fn t22_container_logs(project: &str, service: &str) -> String {
    let container = t22_compose_service_container(project, service);
    let Some(container) = container else {
        return format!("failed to find {service} container for project {project}");
    };
    t22_logs_for_container(&container)
}

#[cfg(feature = "realnet")]
fn t22_compose_service_container(project: &str, service: &str) -> Option<String> {
    let output = std::process::Command::new(container_runtime())
        .args([
            "ps",
            "-a",
            "--filter",
            &format!("label=com.docker.compose.project={project}"),
            "--filter",
            &format!("label=com.docker.compose.service={service}"),
            "--format",
            "{{.Names}}",
        ])
        .output()
        .ok()?;
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(str::to_owned)
}

#[cfg(feature = "realnet")]
fn t22_logs_for_container(container: &str) -> String {
    std::process::Command::new(container_runtime())
        .args(["logs", "--tail", "200", container])
        .output()
        .map_or_else(
            |error| format!("failed to collect logs for {container}: {error}"),
            |output| {
                format!(
                    "{}{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                )
            },
        )
}

#[cfg(feature = "realnet")]
fn t22_docker_ps(project: &str) -> String {
    std::process::Command::new(container_runtime())
        .args([
            "ps",
            "-a",
            "--filter",
            &format!("label=com.docker.compose.project={project}"),
            "--format",
            "{{.Names}}\t{{.Status}}\t{{.Ports}}",
        ])
        .output()
        .map_or_else(
            |error| format!("failed to collect docker ps: {error}"),
            |output| {
                format!(
                    "{}{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                )
            },
        )
}

#[cfg(feature = "realnet")]
fn t22_project_logs(project: &str) -> String {
    use std::fmt::Write as _;

    let names = std::process::Command::new(container_runtime())
        .args([
            "ps",
            "-a",
            "--filter",
            &format!("label=com.docker.compose.project={project}"),
            "--format",
            "{{.Names}}",
        ])
        .output();
    let Ok(names) = names else {
        return "failed to list project containers".to_owned();
    };
    let names = String::from_utf8_lossy(&names.stdout)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if names.is_empty() {
        return "no project containers found".to_owned();
    }

    let mut logs = String::new();
    for name in names {
        let _ = write!(logs, "\n===== {name} =====\n");
        logs.push_str(&t22_logs_for_container(&name));
    }
    logs
}
