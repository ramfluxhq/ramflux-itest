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
    let materials = MaterialDirectory(temp_root("client_directory_v3_materials")?);
    let now = ramflux_node_core::now_unix_seconds();
    let root_seed = [0x44; 32];
    let attestation_seed = [0x33; 32];
    let provider_seed = [0x66; 32];
    let offline_root_seed = [0x88; 32];
    let certificate = t22_certificate(now, 3600, ISSUER_NODE, "gw-b", root_seed, attestation_seed)?;
    let envelope =
        t22_trust_envelope(now, 3600, ISSUER_NODE, root_seed, provider_seed, &certificate)?;
    let keyring = t22_provider_keyring(now, 3600, ISSUER_NODE, offline_root_seed, provider_seed)?;
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
    realnet_step("s73 start signed v3 stack", "issuer=node_b.realnet audience=node_a.realnet");
    let mut env = vec![
        ("RAMFLUX_V3_MATERIALS_DIR".to_owned(), materials.0.to_string_lossy().into_owned()),
        (
            "RAMFLUX_GATEWAY_B_V3_ISSUER_SEED".to_owned(),
            ramflux_protocol::encode_base64url(attestation_seed),
        ),
        (
            "RAMFLUX_V3_FEDERATION_PROVIDER_OFFLINE_ROOT_PUBLIC_KEY".to_owned(),
            ramflux_crypto::public_key_base64url_from_seed(offline_root_seed),
        ),
        (
            "RAMFLUX_V3_FEDERATION_PROVIDER_KEYRING_FILE".to_owned(),
            "/etc/ramflux/federation/provider-keyring.json".to_owned(),
        ),
        ("RAMFLUX_V3_FEDERATION_TRUST_ISSUER_NODE_ID".to_owned(), ISSUER_NODE.to_owned()),
        ("RAMFLUX_V3_FEDERATION_TRUST_ENDPOINT".to_owned(), "ramflux-federation:7443".to_owned()),
        (
            "RAMFLUX_RELAY_ITEST_CAPTURE_JSON".to_owned(),
            "/tmp/ramflux-relay-itest-capture-s73.jsonl".to_owned(),
        ),
    ];
    env.extend_from_slice(extra_env);
    let node = start_s8_realnet_compose_project_with_env(project, ports, &env)?;
    Ok(ClientDirectoryStack { node, _materials: materials })
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
    command
        .env("RAMFLUX_SDK_RELAY_QUIC_ADDR", S73_RELAY_QUIC)
        .env("RAMFLUX_SDK_RELAY_QUIC_SERVER_NAME", "ramflux-relay")
        .env("RAMFLUX_SDK_RELAY_QUIC_CA_CERT", ca_cert);
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
