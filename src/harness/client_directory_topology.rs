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
pub(crate) struct SignedGatewayMaterials {
    directory: MaterialDirectory,
    pub(crate) environment: Vec<(String, String)>,
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

pub(crate) fn signed_gateway_materials(
    issuer: &str,
    gateway: &str,
) -> Result<SignedGatewayMaterials, Box<dyn std::error::Error>> {
    let materials = MaterialDirectory(temp_root("client_directory_v3_materials")?);
    let now = ramflux_node_core::now_unix_seconds();
    let root_seed = [0x44; 32];
    let attestation_seed = [0x33; 32];
    let provider_seed = [0x66; 32];
    let offline_root_seed = [0x88; 32];
    let certificate = t22_certificate(now, 3600, issuer, gateway, root_seed, attestation_seed)?;
    let envelope = t22_trust_envelope(now, 3600, issuer, root_seed, provider_seed, &certificate)?;
    let keyring = t22_provider_keyring(now, 3600, issuer, offline_root_seed, provider_seed)?;
    for directory in ["gateway-a", "gateway-b", "federation"] {
        std::fs::create_dir_all(materials.0.join(directory))?;
    }
    for directory in ["gateway-a", "gateway-b"] {
        std::fs::write(
            materials.0.join(directory).join("issuer-cert.json"),
            serde_json::to_vec_pretty(&certificate)?,
        )?;
    }
    std::fs::write(
        materials.0.join("federation/trust-snapshot.json"),
        serde_json::to_vec_pretty(&envelope)?,
    )?;
    std::fs::write(
        materials.0.join("federation/provider-keyring.json"),
        serde_json::to_vec_pretty(&keyring)?,
    )?;
    let seed_env = if gateway == "gw-a" {
        "RAMFLUX_GATEWAY_A_V3_ISSUER_SEED"
    } else {
        "RAMFLUX_GATEWAY_B_V3_ISSUER_SEED"
    };
    let env = vec![
        ("RAMFLUX_V3_MATERIALS_DIR".to_owned(), materials.0.to_string_lossy().into_owned()),
        (seed_env.to_owned(), ramflux_protocol::encode_base64url(attestation_seed)),
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
    ];
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

pub(crate) fn client_directory_daemon_command(
    rf_binary: &Path,
    socket: &Path,
    data_root: &Path,
    ca_cert: &Path,
    owner_principal: Option<&str>,
) -> tokio::process::Command {
    let mut command = tokio::process::Command::new(rf_binary);
    command.arg("--socket").arg(socket).args(["daemon", "start", "--data-root"]).arg(data_root);
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
        for (issuer, gateway, directory, seed_key) in [
            ("node_a.realnet", "gw-a", "gateway-a", "RAMFLUX_GATEWAY_A_V3_ISSUER_SEED"),
            ("node_b.realnet", "gw-b", "gateway-b", "RAMFLUX_GATEWAY_B_V3_ISSUER_SEED"),
        ] {
            let SignedGatewayMaterials { directory: materials, environment: env } =
                signed_gateway_materials(issuer, gateway)?;
            let env = env.into_iter().collect::<std::collections::BTreeMap<_, _>>();
            let seed: [u8; 32] = ramflux_protocol::decode_base64url(
                env.get(seed_key).ok_or("missing issuer seed")?,
            )?
            .try_into()
            .map_err(|_| "invalid issuer seed length")?;
            let certificate: ramflux_node_core::GatewayIssuerCertificate = serde_json::from_slice(
                &std::fs::read(materials.0.join(directory).join("issuer-cert.json"))?,
            )?;
            assert_eq!(certificate.node_id, issuer);
            assert_eq!(certificate.gateway_instance_id, gateway);
            assert_eq!(
                certificate.attestation_public_key,
                ramflux_crypto::public_key_base64url_from_seed(seed)
            );
            ramflux_crypto::verify_canonical_signature(
                &ramflux_node_core::gateway_issuer_certificate_signing_bytes(&certificate)?,
                &certificate.node_root_signature,
                &ramflux_crypto::public_key_base64url_from_seed([0x44; 32]),
            )?;
            let trust: ramflux_node_core::ProviderSignedTrustSnapshot = serde_json::from_slice(
                &std::fs::read(materials.0.join("federation/trust-snapshot.json"))?,
            )?;
            let keyring: ramflux_node_core::ProviderKeyring = serde_json::from_slice(
                &std::fs::read(materials.0.join("federation/provider-keyring.json"))?,
            )?;
            assert_eq!(trust.snapshot.node_id, issuer);
            assert_eq!(keyring.issuer_node_id, issuer);
            assert_eq!(env["RAMFLUX_V3_FEDERATION_TRUST_ISSUER_NODE_ID"], issuer);
            assert_eq!(
                env["RAMFLUX_V3_FEDERATION_PROVIDER_OFFLINE_ROOT_PUBLIC_KEY"],
                ramflux_crypto::public_key_base64url_from_seed([0x88; 32])
            );
        }
        Ok(())
    }
}
