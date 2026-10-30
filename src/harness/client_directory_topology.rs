// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Signed object-v3 topology and isolated daemon configuration for client directory acceptance.
use crate::*;

pub(crate) const S73_RELAY_QUIC: &str = "127.0.0.1:17447";
pub(crate) const S73_GATEWAY_B_QUIC: &str = "127.0.0.1:18444";
const ISSUER_NODE: &str = "node_b.realnet";
const AUDIENCE_NODE: &str = "node_a.realnet";

pub(crate) struct ClientDirectoryStack {
    // Drop the compose node before removing its bind-mounted trust material.
    pub(crate) node: S8RealnetNode,
    _materials: MaterialDirectory,
}

struct MaterialDirectory(PathBuf);
struct SignedGatewayMaterials {
    directory: MaterialDirectory,
    environment: Vec<(String, String)>,
}
impl Drop for MaterialDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub(crate) fn start_client_directory_stack(
    ports: S8ComposePorts,
) -> Result<ClientDirectoryStack, Box<dyn std::error::Error>> {
    start_client_directory_stack_named("ramflux-s73-client-directory", ports, &[])
}

pub(crate) fn start_client_directory_stack_named(
    project: &str,
    ports: S8ComposePorts,
    extra_env: &[(String, String)],
) -> Result<ClientDirectoryStack, Box<dyn std::error::Error>> {
    start_client_directory_stack_with_issuer(project, ports, extra_env, ISSUER_NODE, "gw-b")
}

pub(crate) fn start_client_directory_stack_with_issuer(
    project: &str,
    ports: S8ComposePorts,
    extra_env: &[(String, String)],
    issuer: &str,
    gateway: &str,
) -> Result<ClientDirectoryStack, Box<dyn std::error::Error>> {
    let SignedGatewayMaterials { directory: materials, environment: mut env } =
        signed_gateway_materials(issuer, gateway)?;
    realnet_step("start signed v3 stack", format!("issuer={issuer} gateway={gateway}"));
    env.extend_from_slice(extra_env);
    let node = start_s8_realnet_compose_project_with_env(project, ports, &env)?;
    Ok(ClientDirectoryStack { node, _materials: materials })
}

fn signed_gateway_materials(
    issuer: &str,
    gateway: &str,
) -> Result<SignedGatewayMaterials, Box<dyn std::error::Error>> {
    let materials = MaterialDirectory(temp_root("client_directory_v3_materials")?);
    let now = ramflux_node_core::now_unix_seconds();
    let provider_seed = [0x66; 32];
    let offline_root_seed = [0x88; 32];
    let mut env = Vec::new();
    let mut selected = false;
    for (node, instance, directory, seed_key, root_seed) in [
        ("node_a.realnet", "gw-a", "gateway-a", "RAMFLUX_GATEWAY_A_V3_ISSUER_SEED", [0x43; 32]),
        ("node_b.realnet", "gw-b", "gateway-b", "RAMFLUX_GATEWAY_B_V3_ISSUER_SEED", [0x44; 32]),
    ] {
        let seed = gateway_issuer_seed(seed_key)?;
        let mut certificate = t22_certificate(now, 3600, node, instance, root_seed, seed)?;
        certificate.cert_id = format!("client-directory-{instance}-cert");
        certificate.attestation_key_id = format!("client-directory-{instance}-attestation");
        certificate.node_root_signing_key_id = format!("{node}#root-1");
        certificate.node_root_signature = ramflux_crypto::sign_canonical_bytes_with_seed(
            &ramflux_node_core::gateway_issuer_certificate_signing_bytes(&certificate)?,
            root_seed,
        );
        let envelope = t22_trust_envelope(now, 3600, node, root_seed, provider_seed, &certificate)?;
        let keyring = t22_provider_keyring(now, 3600, node, offline_root_seed, provider_seed)?;
        let gateway_dir = materials.0.join(directory);
        std::fs::create_dir_all(&gateway_dir)?;
        std::fs::write(
            gateway_dir.join("issuer-cert.json"),
            serde_json::to_vec_pretty(&certificate)?,
        )?;
        // The relay's production provider holds one issuer snapshot. Retain both signed trust
        // chains and mount the chain selected by the slice's issuing gateway.
        let trust_dir = materials.0.join("federation").join(instance);
        std::fs::create_dir_all(&trust_dir)?;
        for (name, bytes) in [
            ("trust-snapshot.json", serde_json::to_vec_pretty(&envelope)?),
            ("provider-keyring.json", serde_json::to_vec_pretty(&keyring)?),
        ] {
            std::fs::write(trust_dir.join(name), &bytes)?;
            if (node, instance) == (issuer, gateway) {
                std::fs::write(materials.0.join("federation").join(name), &bytes)?;
                selected = true;
            }
        }
        env.push((seed_key.to_owned(), ramflux_protocol::encode_base64url(seed)));
    }
    if !selected {
        return Err(format!("unsupported client-directory issuer {issuer}/{gateway}").into());
    }
    env.extend([
        ("RAMFLUX_V3_MATERIALS_DIR".to_owned(), materials.0.to_string_lossy().into_owned()),
        (
            "RAMFLUX_V3_FEDERATION_PROVIDER_OFFLINE_ROOT_PUBLIC_KEY".to_owned(),
            ramflux_crypto::public_key_base64url_from_seed(offline_root_seed),
        ),
        (
            "RAMFLUX_V3_FEDERATION_PROVIDER_KEYRING_FILE".to_owned(),
            "/etc/ramflux/federation/provider-keyring.json".to_owned(),
        ),
        ("RAMFLUX_V3_FEDERATION_TRUST_ISSUER_NODE_ID".to_owned(), issuer.to_owned()),
        ("RAMFLUX_V3_FEDERATION_TRUST_ENDPOINT".to_owned(), "ramflux-federation:7443".to_owned()),
        (
            "RAMFLUX_RELAY_ITEST_CAPTURE_JSON".to_owned(),
            "/tmp/ramflux-relay-itest-capture-s73.jsonl".to_owned(),
        ),
    ]);
    Ok(SignedGatewayMaterials { directory: materials, environment: env })
}

pub(crate) fn client_directory_relay_environment(
    ca_cert: &Path,
) -> [(String, std::ffi::OsString); 3] {
    [
        ("RAMFLUX_SDK_RELAY_QUIC_ADDR".to_owned(), S73_RELAY_QUIC.into()),
        ("RAMFLUX_SDK_RELAY_QUIC_SERVER_NAME".to_owned(), "ramflux-relay".into()),
        ("RAMFLUX_SDK_RELAY_QUIC_CA_CERT".to_owned(), ca_cert.as_os_str().to_owned()),
    ]
}

pub(crate) fn native_client_directory_daemon_command(
    rf_binary: &Path,
    socket: &Path,
    data_root: &Path,
    ca_cert: &Path,
    owner_principal: Option<&str>,
) -> tokio::process::Command {
    directory_daemon_command(rf_binary, socket, data_root, ca_cert, owner_principal, false)
}

pub(crate) fn client_directory_daemon_command(
    rf_binary: &Path,
    socket: &Path,
    data_root: &Path,
    ca_cert: &Path,
    owner_principal: Option<&str>,
) -> tokio::process::Command {
    directory_daemon_command(rf_binary, socket, data_root, ca_cert, owner_principal, true)
}

fn directory_daemon_command(
    rf_binary: &Path,
    socket: &Path,
    data_root: &Path,
    ca_cert: &Path,
    owner_principal: Option<&str>,
    legacy: bool,
) -> tokio::process::Command {
    let mut command = tokio::process::Command::new(rf_binary);
    command
        .arg("--socket")
        .arg(socket)
        .args(["daemon", "start", "--itest-memory-vault", "--data-root"])
        .arg(data_root);
    if legacy {
        command.arg("--itest-legacy-accounts");
    }
    // Bob's owner lineage must come from Alice's signed attachment, never the parent's environment.
    for key in [
        "RAMFLUX_SDK_OBJECT_RELAY_LOCAL_MINT",
        "RAMFLUX_SDK_OBJECT_RELAY_SERVICE_KEY_BASE64",
        "RAMFLUX_SDK_RELAY_OWNER_HOME_NODE_ID",
        "RAMFLUX_SDK_RELAY_OWNER_PRINCIPAL_ID",
        "RAMFLUX_SDK_RELAY_AUDIENCE_NODE_ID",
    ] {
        command.env_remove(key);
    }
    command.envs(client_directory_relay_environment(ca_cert));
    if let Some(principal) = owner_principal {
        command
            .env("RAMFLUX_SDK_RELAY_OWNER_HOME_NODE_ID", ISSUER_NODE)
            .env("RAMFLUX_SDK_RELAY_OWNER_PRINCIPAL_ID", principal)
            .env("RAMFLUX_SDK_RELAY_AUDIENCE_NODE_ID", AUDIENCE_NODE);
    }
    command
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::inherit())
        .kill_on_drop(true);
    command
}

#[cfg(test)]
mod issuer_tests {
    use super::*;

    #[test]
    fn native_daemons_keep_legacy_fixture_creation_disabled() {
        let binary = Path::new("fixture-rf");
        let socket = Path::new("fixture.sock");
        let data = Path::new("fixture-data");
        let ca = Path::new("fixture-ca.pem");
        let native = native_client_directory_daemon_command(binary, socket, data, ca, None);
        let legacy = client_directory_daemon_command(binary, socket, data, ca, None);
        assert!(!native.as_std().get_args().any(|arg| arg == "--itest-legacy-accounts"));
        assert!(legacy.as_std().get_args().any(|arg| arg == "--itest-legacy-accounts"));
        assert!(native.as_std().get_args().any(|arg| arg == "--itest-memory-vault"));
    }

    #[test]
    fn relay_environment_sets_address_server_name_and_ca_before_daemon_start() {
        let ca = Path::new("test certificates/relay-ca.pem");
        let env = client_directory_relay_environment(ca)
            .into_iter()
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(env["RAMFLUX_SDK_RELAY_QUIC_ADDR"], std::ffi::OsStr::new(S73_RELAY_QUIC));
        assert_eq!(
            env["RAMFLUX_SDK_RELAY_QUIC_SERVER_NAME"],
            std::ffi::OsStr::new("ramflux-relay")
        );
        assert_eq!(env["RAMFLUX_SDK_RELAY_QUIC_CA_CERT"], ca.as_os_str());
    }

    #[test]
    fn signed_materials_bind_selected_gateway_seed_and_owner_trust()
    -> Result<(), Box<dyn std::error::Error>> {
        for (issuer, gateway) in [("node_a.realnet", "gw-a"), ("node_b.realnet", "gw-b")] {
            let SignedGatewayMaterials { directory: materials, environment: env } =
                signed_gateway_materials(issuer, gateway)?;
            let resolved = compose_env_with_required_defaults(&env)?;
            let env = resolved.into_iter().collect::<std::collections::BTreeMap<_, _>>();
            assert_ne!(
                env["RAMFLUX_GATEWAY_A_V3_ISSUER_SEED"], env["RAMFLUX_GATEWAY_B_V3_ISSUER_SEED"],
                "each gateway must keep its own issuer key"
            );
            for (node, instance, directory, seed_key) in [
                ("node_a.realnet", "gw-a", "gateway-a", "RAMFLUX_GATEWAY_A_V3_ISSUER_SEED"),
                ("node_b.realnet", "gw-b", "gateway-b", "RAMFLUX_GATEWAY_B_V3_ISSUER_SEED"),
            ] {
                let seed: [u8; 32] = ramflux_protocol::decode_base64url(
                    env.get(seed_key).ok_or("missing issuer seed")?,
                )?
                .try_into()
                .map_err(|_| "invalid issuer seed length")?;
                let certificate: ramflux_node_core::GatewayIssuerCertificate =
                    serde_json::from_slice(&std::fs::read(
                        materials.0.join(directory).join("issuer-cert.json"),
                    )?)?;
                assert_eq!(certificate.node_id, node);
                assert_eq!(certificate.gateway_instance_id, instance);
                assert_eq!(
                    certificate.attestation_public_key,
                    ramflux_crypto::public_key_base64url_from_seed(seed)
                );
                let trust: ramflux_node_core::ProviderSignedTrustSnapshot =
                    serde_json::from_slice(&std::fs::read(
                        materials.0.join("federation").join(instance).join("trust-snapshot.json"),
                    )?)?;
                let keyring: ramflux_node_core::ProviderKeyring =
                    serde_json::from_slice(&std::fs::read(
                        materials.0.join("federation").join(instance).join("provider-keyring.json"),
                    )?)?;
                let now = ramflux_node_core::now_unix_seconds();
                let verified = ramflux_node_core::verify_provider_keyring(
                    &keyring,
                    &env["RAMFLUX_V3_FEDERATION_PROVIDER_OFFLINE_ROOT_PUBLIC_KEY"],
                    node,
                )?;
                ramflux_node_core::verify_provider_signed_trust_snapshot(&trust, &verified, now)?;
                ramflux_node_core::verify_federated_issuer_trust_snapshot(
                    &trust.snapshot,
                    node,
                    now,
                )?;
                let root = ramflux_node_core::select_trusted_node_root_key(
                    &trust.snapshot,
                    &certificate.node_root_signing_key_id,
                    now,
                )?;
                ramflux_crypto::verify_canonical_signature(
                    &ramflux_node_core::gateway_issuer_certificate_signing_bytes(&certificate)?,
                    &certificate.node_root_signature,
                    &root.public_key,
                )?;
                if (node, instance) == (issuer, gateway) {
                    assert_eq!(
                        std::fs::read(materials.0.join("federation/trust-snapshot.json"))?,
                        serde_json::to_vec_pretty(&trust)?,
                    );
                    assert_eq!(
                        std::fs::read(materials.0.join("federation/provider-keyring.json"))?,
                        serde_json::to_vec_pretty(&keyring)?,
                    );
                }
            }
            assert_eq!(env["RAMFLUX_V3_FEDERATION_TRUST_ISSUER_NODE_ID"], issuer);
            assert_eq!(
                env["RAMFLUX_V3_FEDERATION_PROVIDER_OFFLINE_ROOT_PUBLIC_KEY"],
                ramflux_crypto::public_key_base64url_from_seed([0x88; 32])
            );
        }
        Ok(())
    }
}
