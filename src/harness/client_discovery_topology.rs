// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Production topology for client-discovery acceptance.
use crate::*;

pub(crate) struct ClientDiscoveryTopology {
    pub(crate) origin: String,
    pub(crate) ca: PathBuf,
    _compose: ProductionComposeDownGuard,
    _materials: T22ProductionMaterials,
}

pub(crate) fn start_client_discovery_topology()
-> Result<ClientDiscoveryTopology, Box<dyn std::error::Error>> {
    let root = code_root();
    let deploy = root.join("ramflux/deploy");
    for file in [
        "secrets/gateway-v3/issuer-cert.json",
        "secrets/federation/trust-snapshot.json",
        "secrets/federation/provider-keyring.json",
    ] {
        if deploy.join(file).exists() {
            return Err(
                format!("test requires an isolated deployment directory; existing {file}").into()
            );
        }
    }
    for script in ["bootstrap-ca.sh", "issue-certs.sh", "build-prod-images.sh"] {
        run_deploy_script(&root, &format!("ramflux/deploy/scripts/{script}"))?;
    }
    let now = realnet_now_u64();
    let certificate =
        t22_certificate(now, 3600, "localhost", "gw-localhost", [0x44; 32], [0x33; 32])?;
    let envelope =
        t22_trust_envelope(now, 3600, "localhost", [0x44; 32], [0x66; 32], &certificate)?;
    let keyring = t22_provider_keyring(now, 3600, "localhost", [0x88; 32], [0x66; 32])?;
    let materials = T22ProductionMaterials::write(&deploy, &certificate, &envelope, &keyring)?;
    let mut env = vec![
        (
            "RAMFLUX_FEDERATION_PROVIDER_OFFLINE_ROOT_PUBLIC_KEY".to_owned(),
            ramflux_crypto::public_key_base64url_from_seed([0x88; 32]),
        ),
        (
            "RAMFLUX_GATEWAY_V3_ISSUER_SEED".to_owned(),
            ramflux_protocol::encode_base64url([0x33; 32]),
        ),
        (
            "RAMFLUX_FEDERATION_NODE_SIGNING_SEED_B64URL".to_owned(),
            ramflux_protocol::encode_base64url([0x49; 32]),
        ),
    ];
    env.extend(
        [
            ("RAMFLUX_FEDERATION_TRUST_ENDPOINT", "ramflux-federation:7443"),
            ("RAMFLUX_FEDERATION_TRUST_ISSUER_NODE_ID", "localhost"),
            ("RAMFLUX_FEDERATION_NODE_ID", "localhost"),
            ("RAMFLUX_GATEWAY_TCP_PORT", "58443"),
            ("RAMFLUX_GATEWAY_QUIC_PORT", "58443"),
            ("RAMFLUX_RELAY_CLIENT_QUIC_PORT", "58447"),
            ("RAMFLUX_SIGNALING_TURN_UDP_PORT", "58478"),
            ("RAMFLUX_SIGNALING_TURN_TCP_PORT", "58479"),
            ("RAMFLUX_FEDERATION_ADMIN_PORT", "58482"),
            ("RAMFLUX_FEDERATION_MESH_PORT", "58453"),
            ("RAMFLUX_CLIENT_GATEWAY_QUIC_ADDR", "127.0.0.1:58443"),
            ("RAMFLUX_CLIENT_GATEWAY_TCP_ADDR", "127.0.0.1:58443"),
            ("RAMFLUX_CLIENT_RELAY_QUIC_ADDR", "127.0.0.1:58447"),
            ("RAMFLUX_CLIENT_GATEWAY_SERVER_NAME", "ramflux-gateway"),
            ("RAMFLUX_CLIENT_RELAY_SERVER_NAME", "ramflux-relay"),
            ("RAMFLUX_CLIENT_PREKEY_HTTP_URL", "http://127.0.0.1:58482"),
        ]
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value.to_owned())),
    );
    let project = "ramflux-s72-client-discovery";
    let guard = ProductionComposeDownGuard::new(deploy.clone(), project.to_owned(), env.clone());
    run_production_compose_project(&deploy, project, &env, &["up", "--build", "-d"])?;
    let origin = "http://127.0.0.1:58482".to_owned();
    wait_for_federation(&origin)?;
    Ok(ClientDiscoveryTopology {
        origin,
        ca: deploy.join("certs/ca.pem"),
        _compose: guard,
        _materials: materials,
    })
}
