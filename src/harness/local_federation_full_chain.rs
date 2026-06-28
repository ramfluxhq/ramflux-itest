// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use crate::*;
use std::collections::BTreeMap;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

#[cfg(all(test, feature = "realnet"))]
const LOCAL_NODE_A_SEED: [u8; 32] = [0xa1; 32];
#[cfg(all(test, feature = "realnet"))]
const LOCAL_NODE_B_SEED: [u8; 32] = [0xb2; 32];

#[cfg(all(test, feature = "realnet"))]
#[allow(clippy::too_many_lines)]
pub(crate) async fn mvp_s8_assert_local_rf_federation_full_chain_no_hang()
-> Result<(), Box<dyn std::error::Error>> {
    let code_root = code_root();
    let ca_cert = code_root.join("ramflux-deploy/certs/ca.pem");
    let gateway_tls = ramflux_transport::MeshTlsConfig {
        ca_cert: ca_cert.clone(),
        service_cert: code_root.join("ramflux-deploy/certs/gateway/gateway.pem"),
        service_key: code_root.join("ramflux-deploy/certs/gateway/gateway-key.pem"),
    };
    let alice_gateway = LocalGatewayStub::start("alice", &gateway_tls)?;
    let bob_gateway = LocalGatewayStub::start("bob", &gateway_tls)?;
    let temp_root = short_temp_root()?;
    let federation_certs = LocalFederationTestCerts::issue(&temp_root.join("federation-certs"))?;
    let sender_trust_state = Arc::new(Mutex::new(ramflux_node_core::FederationTrustState::new()));
    let receiver_trust_state = Arc::new(Mutex::new(ramflux_node_core::FederationTrustState::new()));
    let router = LocalRouterInboxStub::start(bob_gateway.state.clone())?;
    let peer = LocalFederationPeerStub::start(
        router.url.clone(),
        federation_certs.node_b.tls.clone(),
        receiver_trust_state.clone(),
    )?;
    {
        let mut state = sender_trust_state
            .lock()
            .map_err(|error| format!("local federation state mutex poisoned: {error}"))?;
        pin_local_discovered_federation_state(
            &mut state,
            &federation_certs.node_b.ca_pem,
            &peer.endpoint,
        )?;
    }
    {
        let mut state = receiver_trust_state
            .lock()
            .map_err(|error| format!("local federation state mutex poisoned: {error}"))?;
        pin_local_discovered_peer_ca(
            &mut state,
            "node-a.local",
            "127.0.0.1:0",
            &federation_certs.node_a.ca_pem,
            LOCAL_NODE_A_SEED,
        )?;
    }
    let forward = LocalFederationForwardStub::start(
        sender_trust_state.clone(),
        federation_certs.node_a.tls.clone(),
    )?;
    let bob_prekey = LocalPrekeyStub::start(bob_gateway.state.clone())?;

    let rf_binary = mvp_s4_build_rf_binary().await?;
    let alice_socket = temp_root.join("alice/rfd.sock");
    let bob_socket = temp_root.join("bob/rfd.sock");
    let (alice_shutdown_tx, alice_shutdown_rx) = tokio::sync::watch::channel(false);
    let (bob_shutdown_tx, bob_shutdown_rx) = tokio::sync::watch::channel(false);
    let alice_config =
        ramflux_sdk::LocalBusConfig::new(&alice_socket, temp_root.join("alice/data"));
    let bob_config = ramflux_sdk::LocalBusConfig::new(&bob_socket, temp_root.join("bob/data"));
    let alice_server = ramflux_sdk::serve_local_bus_until(alice_config, alice_shutdown_rx);
    let bob_server = ramflux_sdk::serve_local_bus_until(bob_config, bob_shutdown_rx);
    let flow = async {
        mvp_s4_wait_for_socket(&alice_socket).await?;
        mvp_s4_wait_for_socket(&bob_socket).await?;
        let alice_socket_arg = mvp_s4_path_arg(&alice_socket);
        let bob_socket_arg = mvp_s4_path_arg(&bob_socket);
        let ca_cert_arg = mvp_s4_path_arg(&ca_cert);
        mvp_s8_create_rf_account(
            &rf_binary,
            &alice_socket_arg,
            "alice_s8_account",
            "principal_s8_alice",
            "alice_device_s8",
            "target_s8_alice",
            &alice_gateway.addr.to_string(),
            &bob_prekey.url,
            &ca_cert_arg,
            "81",
            "82",
        )
        .await?;
        mvp_s8_create_rf_account(
            &rf_binary,
            &bob_socket_arg,
            "bob_s8_account",
            "principal_s8_bob",
            "bob_device_s8",
            "target_s8_bob",
            &bob_gateway.addr.to_string(),
            &bob_prekey.url,
            &ca_cert_arg,
            "91",
            "92",
        )
        .await?;
        mvp_s8_accept_local_friend_projection(&rf_binary, &alice_socket_arg, &bob_socket_arg)
            .await?;
        let plaintext = "s8 true two-node federated rf dm plaintext";
        let submitted = mvp_s10_rf_json(
            &rf_binary,
            &[
                "--socket",
                &alice_socket_arg,
                "dm",
                "send",
                "--account",
                "alice_s8_account",
                "--conversation",
                "conv_s8_cross_node",
                "--message",
                "msg_s8_cross_node_1",
                "--envelope",
                "env_s8_cross_node_dm_1",
                "--source-principal",
                "principal_s8_alice",
                "alice_s8",
                "--recipient-device",
                "bob_device_s8",
                "--target",
                "target_s8_bob",
                "--body",
                plaintext,
                "--federation-url",
                &forward.url,
                "--source-node",
                "node-a.local",
                "--target-node",
                "node-b.local",
                "--recipient-prekey-url",
                &bob_prekey.url,
            ],
            "local s8 rf dm send cross-node",
        )
        .await?;
        assert_eq!(submitted["accepted"], true);
        assert_eq!(submitted["delivery"]["target_delivery_id"], "target_s8_bob");
        let bob_read = mvp_s10_rf_json(
            &rf_binary,
            &[
                "--socket",
                &bob_socket_arg,
                "dm",
                "read",
                "--account",
                "bob_s8_account",
                "--conversation",
                "conv_s8_cross_node",
            ],
            "local s8 bob rf dm read",
        )
        .await?;
        let entries =
            bob_read["gateway_entries"].as_array().ok_or("missing local gateway entries")?;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["envelope"]["envelope_id"], "env_s8_cross_node_dm_1");
        let decrypted =
            bob_read["decrypted_messages"].as_array().ok_or("missing local decrypted messages")?;
        assert_eq!(decrypted.len(), 1);
        let body = ramflux_protocol::decode_base64url(
            decrypted[0]["plaintext_body_base64"].as_str().ok_or("missing plaintext")?,
        )?;
        assert_eq!(body, plaintext.as_bytes());
        alice_shutdown_tx.send(true)?;
        bob_shutdown_tx.send(true)?;
        Ok::<(), Box<dyn std::error::Error>>(())
    };
    let (alice_result, bob_result, flow_result) =
        Box::pin(tokio::time::timeout(Duration::from_secs(30), async {
            tokio::join!(alice_server, bob_server, flow)
        }))
        .await
        .map_err(|_elapsed| "local S8 rf federation full chain timed out")?;
    alice_result?;
    bob_result?;
    flow_result?;
    std::fs::remove_dir_all(&temp_root)?;
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
fn short_temp_root() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let elapsed = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?;
    let path = PathBuf::from("/tmp").join(format!(
        "rf-s8lf-{}-{}",
        std::process::id(),
        elapsed.as_millis()
    ));
    if path.exists() {
        std::fs::remove_dir_all(&path)?;
    }
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

#[cfg(all(test, feature = "realnet"))]
struct LocalFederationTestCerts {
    node_a: LocalFederationPeerCerts,
    node_b: LocalFederationPeerCerts,
}

#[cfg(all(test, feature = "realnet"))]
impl LocalFederationTestCerts {
    fn issue(root: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            node_a: LocalFederationPeerCerts::issue(root, "node-a")?,
            node_b: LocalFederationPeerCerts::issue(root, "node-b")?,
        })
    }
}

#[cfg(all(test, feature = "realnet"))]
struct LocalFederationPeerCerts {
    tls: ramflux_transport::MeshTlsConfig,
    ca_pem: String,
}

#[cfg(all(test, feature = "realnet"))]
impl LocalFederationPeerCerts {
    fn issue(root: &Path, name: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let dir = root.join(name);
        std::fs::create_dir_all(&dir)?;
        let ca_key = dir.join("ca-key.pem");
        let ca_cert = dir.join("ca.pem");
        let service_key = dir.join("federation-key.pem");
        let service_csr = dir.join("federation.csr");
        let service_cert = dir.join("federation.pem");
        let ext = dir.join("federation.ext");
        run_openssl(&["genpkey", "-algorithm", "ED25519", "-out"], &ca_key)?;
        run_openssl(
            &[
                "req",
                "-x509",
                "-new",
                "-key",
                path_str(&ca_key)?,
                "-out",
                path_str(&ca_cert)?,
                "-days",
                "30",
                "-subj",
                "/CN=Ramflux Local Federation Test CA",
            ],
            Path::new(""),
        )?;
        run_openssl(&["genpkey", "-algorithm", "ED25519", "-out"], &service_key)?;
        run_openssl(
            &[
                "req",
                "-new",
                "-key",
                path_str(&service_key)?,
                "-out",
                path_str(&service_csr)?,
                "-subj",
                "/CN=ramflux-federation",
            ],
            Path::new(""),
        )?;
        std::fs::write(
            &ext,
            "subjectAltName = DNS:ramflux-federation, DNS:localhost\nextendedKeyUsage = serverAuth, clientAuth\nkeyUsage = digitalSignature\n",
        )?;
        run_openssl(
            &[
                "x509",
                "-req",
                "-in",
                path_str(&service_csr)?,
                "-CA",
                path_str(&ca_cert)?,
                "-CAkey",
                path_str(&ca_key)?,
                "-CAcreateserial",
                "-out",
                path_str(&service_cert)?,
                "-days",
                "30",
                "-extfile",
                path_str(&ext)?,
            ],
            Path::new(""),
        )?;
        Ok(Self {
            tls: ramflux_transport::MeshTlsConfig {
                ca_cert: ca_cert.clone(),
                service_cert,
                service_key,
            },
            ca_pem: std::fs::read_to_string(ca_cert)?,
        })
    }
}

#[cfg(all(test, feature = "realnet"))]
fn run_openssl(args: &[&str], output_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let mut command = Command::new("openssl");
    command.args(args);
    if !output_path.as_os_str().is_empty() {
        command.arg(path_str(output_path)?);
    }
    let output = command.output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!("openssl failed: {}", String::from_utf8_lossy(&output.stderr)).into())
    }
}

#[cfg(all(test, feature = "realnet"))]
fn path_str(path: &Path) -> Result<&str, Box<dyn std::error::Error>> {
    path.to_str().ok_or_else(|| format!("non-utf8 path {}", path.display()).into())
}

#[cfg(all(test, feature = "realnet"))]
fn pin_local_discovered_federation_state(
    state: &mut ramflux_node_core::FederationTrustState,
    node_b_ca_pem: &str,
    node_b_endpoint: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    pin_local_discovered_peer_ca(
        state,
        "node-b.local",
        node_b_endpoint,
        node_b_ca_pem,
        LOCAL_NODE_B_SEED,
    )?;

    let request = local_federation_discovery_request("node-b.local");
    let mut record = local_federation_server_record(
        "node-b.local",
        node_b_endpoint,
        node_b_ca_pem,
        LOCAL_NODE_B_SEED,
    )?;
    let forged_seed = [0x5c; 32];
    record.node_public_key = ramflux_crypto::public_key_base64url_from_seed(forged_seed);
    ramflux_node_core::sign_federation_server_record_with_seed(&mut record, forged_seed)?;
    let rejected = state.resolve_discovery_result(&request, Some(&record), None);
    assert!(rejected.is_err());
    assert_eq!(state.pinned_peer_ca_cert_pem("node-b.local").as_deref(), Some(node_b_ca_pem));

    state.upsert_route(ramflux_node_core::FederationPeerRoute {
        node_id: "node-b.local".to_owned(),
        endpoint: node_b_endpoint.to_owned(),
        node_public_key_hash: ramflux_crypto::blake3_256_base64url(
            ramflux_protocol::domain::FEDERATION_HANDSHAKE,
            ramflux_crypto::public_key_base64url_from_seed(LOCAL_NODE_B_SEED).as_bytes(),
        ),
        node_capabilities: vec!["opaque_delivery".to_owned(), "federation_relay".to_owned()],
        trust_status: ramflux_node_core::FederationTrustStatus::Active,
        updated_at: 1_760_000_020,
        expires_at: 1_760_086_400,
        route_update_proof_hash: "local_route_update_proof_hash".to_owned(),
    });
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
fn pin_local_discovered_peer_ca(
    state: &mut ramflux_node_core::FederationTrustState,
    node_id: &str,
    endpoint: &str,
    ca_pem: &str,
    seed: [u8; 32],
) -> Result<(), Box<dyn std::error::Error>> {
    let request = local_federation_discovery_request(node_id);
    let record = local_federation_server_record(node_id, endpoint, ca_pem, seed)?;
    let discovered = state.resolve_discovery_result(&request, Some(&record), None)?;
    assert_eq!(discovered.pin_state, ramflux_node_core::FederationPinState::Pinned);
    assert_eq!(state.pinned_peer_ca_cert_pem(node_id).as_deref(), Some(ca_pem));
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
fn local_federation_discovery_request(
    node_id: &str,
) -> ramflux_node_core::FederationDiscoveryRequest {
    ramflux_node_core::FederationDiscoveryRequest {
        node_id: node_id.to_owned(),
        now: 1_760_000_020,
        invite_endpoint: None,
        well_known_url: Some(format!("http://{node_id}/.well-known/ramflux/server")),
        dns_srv_records: Vec::new(),
        address_records: Vec::new(),
        directory_endpoint: None,
    }
}

#[cfg(all(test, feature = "realnet"))]
fn local_federation_server_record(
    node_id: &str,
    endpoint: &str,
    ca_pem: &str,
    seed: [u8; 32],
) -> Result<ramflux_node_core::FederationServerRecord, Box<dyn std::error::Error>> {
    let mut record = ramflux_node_core::FederationServerRecord {
        schema: "ramflux.well_known_server.v1".to_owned(),
        node_id: node_id.to_owned(),
        node_public_key: ramflux_crypto::public_key_base64url_from_seed(seed),
        node_ca_cert_pem: ca_pem.to_owned(),
        node_endpoint: endpoint.to_owned(),
        protocol_versions: vec!["v1".to_owned()],
        transport_backends: vec!["quic_quinn".to_owned()],
        node_capabilities: vec!["opaque_delivery".to_owned(), "federation_relay".to_owned()],
        node_policy_hash: "local_node_policy_hash".to_owned(),
        updated_at: 1_760_000_000,
        expires_at: 1_760_086_400,
        signature: String::new(),
    };
    ramflux_node_core::sign_federation_server_record_with_seed(&mut record, seed)?;
    Ok(record)
}

#[cfg(all(test, feature = "realnet"))]
#[derive(Clone)]
struct LocalGatewayState {
    prekeys: Arc<Mutex<BTreeMap<String, ramflux_crypto::PrekeyBundle>>>,
    inbox: Arc<Mutex<Vec<ramflux_sdk::GatewayInboxEntry>>>,
}

#[cfg(all(test, feature = "realnet"))]
impl LocalGatewayState {
    fn new() -> Self {
        Self {
            prekeys: Arc::new(Mutex::new(BTreeMap::new())),
            inbox: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

#[cfg(all(test, feature = "realnet"))]
struct LocalGatewayStub {
    addr: SocketAddr,
    state: LocalGatewayState,
}

#[cfg(all(test, feature = "realnet"))]
impl LocalGatewayStub {
    fn start(
        name: &'static str,
        tls: &ramflux_transport::MeshTlsConfig,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let state = LocalGatewayState::new();
        let config = ramflux_transport::quic_gateway_server_config(tls)?;
        let endpoint = quinn::Endpoint::server(config, "127.0.0.1:0".parse()?)?;
        let addr = endpoint.local_addr()?;
        let server_state = state.clone();
        tokio::spawn(async move {
            while let Some(connecting) = endpoint.accept().await {
                let Ok(connection) = connecting.await else {
                    continue;
                };
                let state = server_state.clone();
                tokio::spawn(async move {
                    while let Ok((send, recv)) = connection.accept_bi().await {
                        let state = state.clone();
                        tokio::spawn(async move {
                            let _ = handle_local_gateway_stream(name, state, send, recv).await;
                        });
                    }
                });
            }
        });
        Ok(Self { addr, state })
    }
}

#[cfg(all(test, feature = "realnet"))]
#[allow(clippy::too_many_lines)]
async fn handle_local_gateway_stream(
    name: &str,
    state: LocalGatewayState,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) -> Result<(), String> {
    match ramflux_transport::read_quic_json_frame::<ramflux_sdk::GatewayClientFrame>(&mut recv)
        .await
        .map_err(|source| source.to_string())?
    {
        ramflux_sdk::GatewayClientFrame::Open { .. } => {}
        _other => return Ok(()),
    }
    match ramflux_transport::read_quic_json_frame::<ramflux_sdk::GatewayClientFrame>(&mut recv)
        .await
        .map_err(|source| source.to_string())?
    {
        ramflux_sdk::GatewayClientFrame::Auth { .. } => {}
        _other => return Ok(()),
    }
    ramflux_transport::write_quic_json_message(
        &mut send,
        &ramflux_sdk::GatewayServerFrame::SessionEstablished {
            session: ramflux_sdk::GatewaySessionEstablishedFrame {
                session_id: format!("session_{name}"),
                gateway_id: format!("gateway_{name}"),
                accepted_cursor: None,
                resume_token: format!("resume_{name}"),
                resume_window_seconds: 300,
            },
        },
    )
    .await
    .map_err(|source| source.to_string())?;
    loop {
        let frame =
            match ramflux_transport::read_quic_json_frame::<serde_json::Value>(&mut recv).await {
                Ok(frame) => frame,
                Err(_error) => return Ok(()),
            };
        match frame.get("frame_type").and_then(serde_json::Value::as_str) {
            Some("identity_register") => {
                let request = frame
                    .get("request")
                    .cloned()
                    .ok_or_else(|| "missing identity_register request".to_owned())?;
                let target_delivery_id = request
                    .get("target_delivery_id")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                let device_id = request
                    .get("proof")
                    .and_then(|proof| proof.get("device_id"))
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                let principal_id = request
                    .get("proof")
                    .and_then(|proof| proof.get("principal_id"))
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                let device_epoch = request
                    .get("proof")
                    .and_then(|proof| proof.get("device_epoch"))
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(1);
                ramflux_transport::write_quic_json_message(
                    &mut send,
                    &serde_json::json!({
                        "frame_type": "identity_registered",
                        "response": {
                            "principal_id": principal_id,
                            "device_id": device_id,
                            "device_epoch": device_epoch,
                            "target_delivery_id": target_delivery_id,
                            "session_bound": true,
                            "registration_trust_tier": "local_stub",
                        },
                    }),
                )
                .await
                .map_err(|source| source.to_string())?;
            }
            Some("prekey_publish") => {
                let request = frame
                    .get("request")
                    .cloned()
                    .ok_or_else(|| "missing prekey_publish request".to_owned())?;
                let device_id = request
                    .get("device_id")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| "missing prekey publish device_id".to_owned())?
                    .to_owned();
                let bundle: ramflux_crypto::PrekeyBundle = serde_json::from_value(
                    request
                        .get("bundle")
                        .cloned()
                        .ok_or_else(|| "missing prekey publish bundle".to_owned())?,
                )
                .map_err(|source| source.to_string())?;
                lock_prekeys(&state)?.insert(device_id.clone(), bundle.clone());
                ramflux_transport::write_quic_json_message(
                    &mut send,
                    &serde_json::json!({
                        "frame_type": "prekey_published",
                        "response": {
                            "device_id": device_id,
                            "bundle": bundle,
                            "target_delivery_id": null,
                        },
                    }),
                )
                .await
                .map_err(|source| source.to_string())?;
            }
            Some("heartbeat") => {
                let now = frame.get("now").and_then(serde_json::Value::as_u64).unwrap_or_default();
                ramflux_transport::write_quic_json_message(
                    &mut send,
                    &ramflux_sdk::GatewayServerFrame::Heartbeat { now },
                )
                .await
                .map_err(|source| source.to_string())?;
            }
            Some("resume") => {
                let resume: ramflux_sdk::GatewayResumeFrame = serde_json::from_value(
                    frame
                        .get("resume")
                        .cloned()
                        .ok_or_else(|| "missing resume frame".to_owned())?,
                )
                .map_err(|source| source.to_string())?;
                let entries = lock_inbox(&state)?
                    .iter()
                    .filter(|entry| entry.inbox_seq > resume.after_inbox_seq)
                    .take(resume.limit)
                    .cloned()
                    .collect::<Vec<_>>();
                ramflux_transport::write_quic_json_message(
                    &mut send,
                    &ramflux_sdk::GatewayServerFrame::Resume { entries },
                )
                .await
                .map_err(|source| source.to_string())?;
            }
            Some("cursor") => {
                let target_delivery_id = frame
                    .get("target_delivery_id")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                let inbox_seq = {
                    let inbox = lock_inbox(&state)?;
                    inbox.last().map_or(0, |entry| entry.inbox_seq)
                };
                ramflux_transport::write_quic_json_message(
                    &mut send,
                    &ramflux_sdk::GatewayServerFrame::Cursor {
                        cursor: Some(ramflux_sdk::GatewayCursor {
                            target_delivery_id,
                            inbox_seq,
                            last_envelope_id: None,
                            acked_envelope_ids: Vec::new(),
                            nacked_envelope_ids: BTreeMap::new(),
                        }),
                    },
                )
                .await
                .map_err(|source| source.to_string())?;
            }
            Some("ack") => {
                let envelope_id = frame
                    .get("ack")
                    .and_then(|ack| ack.get("envelope_id"))
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                let inbox_seq = {
                    let inbox = lock_inbox(&state)?;
                    inbox.last().map_or(0, |entry| entry.inbox_seq)
                };
                ramflux_transport::write_quic_json_message(
                    &mut send,
                    &ramflux_sdk::GatewayServerFrame::Ack {
                        cursor: ramflux_sdk::GatewayCursor {
                            target_delivery_id: "target_s8_bob".to_owned(),
                            inbox_seq,
                            last_envelope_id: Some(envelope_id),
                            acked_envelope_ids: Vec::new(),
                            nacked_envelope_ids: BTreeMap::new(),
                        },
                    },
                )
                .await
                .map_err(|source| source.to_string())?;
            }
            Some("close") => {
                let reason = frame
                    .get("reason")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("local_close")
                    .to_owned();
                ramflux_transport::write_quic_json_message(
                    &mut send,
                    &ramflux_sdk::GatewayServerFrame::Close { reason },
                )
                .await
                .map_err(|source| source.to_string())?;
                return Ok(());
            }
            Some("submit") => {
                let submit: ramflux_sdk::GatewaySubmitFrame = serde_json::from_value(
                    frame
                        .get("submit")
                        .cloned()
                        .ok_or_else(|| "missing submit frame".to_owned())?,
                )
                .map_err(|source| source.to_string())?;
                let entry = ramflux_sdk::GatewayInboxEntry {
                    inbox_seq: 1,
                    target_delivery_id: submit.envelope.target_delivery_id.clone(),
                    envelope: submit.envelope,
                };
                ramflux_transport::write_quic_json_message(
                    &mut send,
                    &ramflux_sdk::GatewayServerFrame::Deliver { entry },
                )
                .await
                .map_err(|source| source.to_string())?;
            }
            Some("prekey_fetch") => {
                let device_id = frame
                    .get("device_id")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                let bundle = {
                    let prekeys = lock_prekeys(&state)?;
                    prekeys.get(&device_id).cloned()
                };
                ramflux_transport::write_quic_json_message(
                    &mut send,
                    &serde_json::json!({
                        "frame_type": "prekey",
                        "response": {
                            "device_id": device_id,
                            "bundle": bundle,
                            "target_delivery_id": null,
                        },
                    }),
                )
                .await
                .map_err(|source| source.to_string())?;
            }
            Some("nack" | "open" | "auth") | None => {}
            Some(_other) => {}
        }
    }
}

#[cfg(all(test, feature = "realnet"))]
struct LocalPrekeyStub {
    url: String,
}

#[cfg(all(test, feature = "realnet"))]
impl LocalPrekeyStub {
    fn start(state: LocalGatewayState) -> Result<Self, Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let url = format!("http://{}", listener.local_addr()?);
        std::thread::spawn(move || {
            if let Ok((mut stream, _peer)) = listener.accept() {
                let _ = handle_local_prekey_request(&mut stream, &state);
            }
        });
        Ok(Self { url })
    }
}

#[cfg(all(test, feature = "realnet"))]
fn handle_local_prekey_request(
    stream: &mut TcpStream,
    state: &LocalGatewayState,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(request) = ramflux_node_core::read_itest_http_request(stream)? else {
        return Ok(());
    };
    let device_id = request.path.trim_start_matches("/mvp1/prekey/");
    let bundle = wait_for_prekey(state, device_id)?;
    ramflux_node_core::write_itest_json_response(
        stream,
        "200 OK",
        &serde_json::json!({
            "device_id": device_id,
            "bundle": bundle,
            "target_delivery_id": "target_s8_bob",
        }),
    )?;
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
#[derive(Clone, serde::Deserialize, serde::Serialize)]
struct LocalFederationEnvelopeRequest {
    source_node_id: String,
    target_node_id: String,
    envelope: ramflux_protocol::Envelope,
}

#[cfg(all(test, feature = "realnet"))]
struct LocalFederationForwardStub {
    url: String,
}

#[cfg(all(test, feature = "realnet"))]
impl LocalFederationForwardStub {
    fn start(
        federation_state: Arc<Mutex<ramflux_node_core::FederationTrustState>>,
        node_a_tls: ramflux_transport::MeshTlsConfig,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let url = format!("http://{}", listener.local_addr()?);
        std::thread::spawn(move || {
            if let Ok((mut stream, _peer)) = listener.accept() {
                let _ = handle_local_forward_request(&mut stream, &federation_state, &node_a_tls);
            }
        });
        Ok(Self { url })
    }
}

#[cfg(all(test, feature = "realnet"))]
fn handle_local_forward_request(
    stream: &mut TcpStream,
    federation_state: &Arc<Mutex<ramflux_node_core::FederationTrustState>>,
    node_a_tls: &ramflux_transport::MeshTlsConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(request) = ramflux_node_core::read_itest_http_request(stream)? else {
        return Ok(());
    };
    let mut forward: ramflux_node_core::FederatedEnvelopeForwardRequest =
        serde_json::from_slice(&request.body)?;
    if forward.signed.signing_key_id.is_empty() {
        return Err("missing strict federation forward signing_key_id".into());
    }
    assert_local_forward_envelope_ttl(&forward.envelope)?;
    let (peer_endpoint, node_b_ca_pem) = {
        let state = federation_state
            .lock()
            .map_err(|error| format!("local federation state mutex poisoned: {error}"))?;
        let route = state.route(&forward.target_node_id).ok_or_else(|| {
            format!("missing local federation route for {}", forward.target_node_id)
        })?;
        let peer_ca = state.pinned_peer_ca_cert_pem(&forward.target_node_id).ok_or_else(|| {
            format!("missing local federation CA pin for {}", forward.target_node_id)
        })?;
        (route.endpoint.clone(), peer_ca)
    };
    ramflux_node_core::sign_federated_envelope_forward(&mut forward, LOCAL_NODE_A_SEED)?;
    let peer_ca_roots = vec![node_b_ca_pem];
    let response: ramflux_sdk::SdkFederatedEnvelopeForwardResponse =
        ramflux_transport::mesh_http_post_json_with_peer_ca_pems(
            &peer_endpoint,
            "/s8/federation/envelope",
            node_a_tls,
            "ramflux-federation",
            &peer_ca_roots,
            &forward,
        )?;
    ramflux_node_core::write_itest_json_response(
        stream,
        "200 OK",
        &ramflux_sdk::SdkFederatedEnvelopeForwardResponse {
            accepted: true,
            source_node_id: forward.source_node_id,
            target_node_id: forward.target_node_id,
            delivery: response.delivery,
        },
    )?;
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
fn assert_local_forward_envelope_ttl(
    envelope: &ramflux_protocol::Envelope,
) -> Result<(), Box<dyn std::error::Error>> {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?;
    let now = i64::try_from(now.as_secs())?;
    if envelope.ttl > ramflux_protocol::MAX_ENVELOPE_TTL_SECONDS_U32 {
        return Err(format!(
            "federated envelope ttl exceeds maximum accepted ttl: envelope_id={} ttl={}",
            envelope.envelope_id, envelope.ttl
        )
        .into());
    }
    let expires_at = envelope.created_at.checked_add(i64::from(envelope.ttl)).ok_or_else(|| {
        format!(
            "federated envelope ttl overflows expiry: envelope_id={} ttl={}",
            envelope.envelope_id, envelope.ttl
        )
    })?;
    if now > expires_at {
        return Err(format!(
            "federated envelope expired: envelope_id={} expires_at={} now={}",
            envelope.envelope_id, expires_at, now
        )
        .into());
    }
    if envelope.created_at > now + ramflux_protocol::MAX_CLOCK_SKEW_SECONDS {
        return Err(format!(
            "federated envelope created_at is in the future: envelope_id={} created_at={} now={}",
            envelope.envelope_id, envelope.created_at, now
        )
        .into());
    }
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
struct LocalFederationPeerStub {
    endpoint: String,
}

#[cfg(all(test, feature = "realnet"))]
impl LocalFederationPeerStub {
    fn start(
        router_url: String,
        node_b_tls: ramflux_transport::MeshTlsConfig,
        federation_state: Arc<Mutex<ramflux_node_core::FederationTrustState>>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let server = ramflux_transport::MeshTlsServer::bind("127.0.0.1:0", &node_b_tls)?;
        let endpoint = server.local_addr()?.to_string();
        std::thread::spawn(move || {
            if let Ok(accepted) =
                server.accept_authenticated_with_pem_roots_provider(&node_b_tls, || {
                    let state = federation_state.lock().map_err(|error| {
                        ramflux_transport::TransportError::Http(error.to_string())
                    })?;
                    Ok(state.pinned_peer_ca_cert_pems())
                })
            {
                let mut stream = accepted.stream;
                let _ = handle_local_peer_request(&mut stream, &router_url);
            }
        });
        Ok(Self { endpoint })
    }
}

#[cfg(all(test, feature = "realnet"))]
fn handle_local_peer_request(
    stream: &mut ramflux_transport::MeshTlsServerStream,
    router_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(request) = ramflux_transport::read_mesh_http_request(stream)? else {
        return Ok(());
    };
    if request.path != "/s8/federation/envelope" {
        return Err(format!("unexpected federation peer path {}", request.path).into());
    }
    let inbound_forward: ramflux_node_core::FederatedEnvelopeForwardRequest =
        serde_json::from_slice(&request.body)?;
    let node_a_public_key = ramflux_crypto::public_key_base64url_from_seed(LOCAL_NODE_A_SEED);
    ramflux_node_core::verify_federated_envelope_forward(&inbound_forward, &node_a_public_key)?;
    let inbound = LocalFederationEnvelopeRequest {
        source_node_id: inbound_forward.source_node_id.clone(),
        target_node_id: inbound_forward.target_node_id.clone(),
        envelope: inbound_forward.envelope,
    };
    let delivery: ramflux_sdk::SdkFederatedSubmitResponse =
        ramflux_node_core::itest_http_post_json(
            &format!("{router_url}/s8/router/inbox"),
            &inbound,
        )?;
    ramflux_transport::write_mesh_json_response(
        stream,
        "200 OK",
        &ramflux_sdk::SdkFederatedEnvelopeForwardResponse {
            accepted: true,
            source_node_id: inbound.source_node_id,
            target_node_id: inbound.target_node_id,
            delivery,
        },
    )?;
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
struct LocalRouterInboxStub {
    url: String,
}

#[cfg(all(test, feature = "realnet"))]
impl LocalRouterInboxStub {
    fn start(state: LocalGatewayState) -> Result<Self, Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let url = format!("http://{}", listener.local_addr()?);
        std::thread::spawn(move || {
            if let Ok((mut stream, _peer)) = listener.accept() {
                let _ = handle_local_router_inbox_request(&mut stream, &state);
            }
        });
        Ok(Self { url })
    }
}

#[cfg(all(test, feature = "realnet"))]
fn handle_local_router_inbox_request(
    stream: &mut TcpStream,
    state: &LocalGatewayState,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(request) = ramflux_node_core::read_itest_http_request(stream)? else {
        return Ok(());
    };
    let inbound: LocalFederationEnvelopeRequest = serde_json::from_slice(&request.body)?;
    let mut inbox = lock_inbox(state)?;
    let inbox_seq = u64::try_from(inbox.len())?.saturating_add(1);
    inbox.push(ramflux_sdk::GatewayInboxEntry {
        inbox_seq,
        target_delivery_id: inbound.envelope.target_delivery_id.clone(),
        envelope: inbound.envelope.clone(),
    });
    ramflux_node_core::write_itest_json_response(
        stream,
        "200 OK",
        &ramflux_sdk::SdkFederatedSubmitResponse {
            outcome: "offline_queued".to_owned(),
            target_delivery_id: inbound.envelope.target_delivery_id,
            inbox_seq: Some(inbox_seq),
            cursor: None,
        },
    )?;
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
fn wait_for_prekey(
    state: &LocalGatewayState,
    device_id: &str,
) -> Result<ramflux_crypto::PrekeyBundle, Box<dyn std::error::Error>> {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(bundle) = lock_prekeys(state)
            .map_err(|source| -> Box<dyn std::error::Error> { source.into() })?
            .get(device_id)
            .cloned()
        {
            return Ok(bundle);
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!("timed out waiting for prekey {device_id}").into());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(all(test, feature = "realnet"))]
fn lock_prekeys(
    state: &LocalGatewayState,
) -> Result<std::sync::MutexGuard<'_, BTreeMap<String, ramflux_crypto::PrekeyBundle>>, String> {
    state.prekeys.lock().map_err(|error| format!("prekey mutex poisoned: {error}"))
}

#[cfg(all(test, feature = "realnet"))]
fn lock_inbox(
    state: &LocalGatewayState,
) -> Result<std::sync::MutexGuard<'_, Vec<ramflux_sdk::GatewayInboxEntry>>, String> {
    state.inbox.lock().map_err(|error| format!("inbox mutex poisoned: {error}"))
}
