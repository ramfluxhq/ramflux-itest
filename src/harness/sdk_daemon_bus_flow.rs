// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use crate::*;

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s2_assert_sdk_session_dm_resume(
    gateway_url: &str,
    gateway_quic_addr: std::net::SocketAddr,
    ca_cert: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    mvp_s2_assert_sdk_session_dm_resume_with_transport(
        gateway_url,
        gateway_quic_addr,
        ca_cert,
        MvpS2GatewayTransport::Quic,
    )
    .await
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s2_assert_sdk_session_dm_resume_tcp_tls(
    gateway_url: &str,
    gateway_tcp_addr: std::net::SocketAddr,
    ca_cert: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    mvp_s2_assert_sdk_session_dm_resume_with_transport(
        gateway_url,
        gateway_tcp_addr,
        ca_cert,
        MvpS2GatewayTransport::TcpTls,
    )
    .await
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s2_assert_sdk_session_dm_resume_auto_prefers_quic(
    gateway_url: &str,
    gateway_quic_addr: std::net::SocketAddr,
    ca_cert: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    mvp_s2_assert_sdk_session_dm_resume_with_transport(
        gateway_url,
        gateway_quic_addr,
        ca_cert,
        MvpS2GatewayTransport::Auto {
            tcp_gateway_addr: gateway_quic_addr,
            quic_fallback_timeout: Duration::from_millis(1_500),
            expected_active: ramflux_sdk::GatewaySessionTransportKind::Quic,
        },
    )
    .await
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s2_assert_sdk_session_dm_resume_auto_quic_survives_frame_delay(
    gateway_url: &str,
    gateway_quic_addr: std::net::SocketAddr,
    ca_cert: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    mvp_s2_assert_sdk_session_dm_resume_with_transport(
        gateway_url,
        gateway_quic_addr,
        ca_cert,
        MvpS2GatewayTransport::Auto {
            tcp_gateway_addr: gateway_quic_addr,
            quic_fallback_timeout: Duration::from_millis(500),
            expected_active: ramflux_sdk::GatewaySessionTransportKind::Quic,
        },
    )
    .await
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s2_assert_sdk_session_dm_resume_auto_falls_back_tcp_tls(
    gateway_url: &str,
    blocked_quic_addr: std::net::SocketAddr,
    gateway_tcp_addr: std::net::SocketAddr,
    ca_cert: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    mvp_s2_assert_sdk_session_dm_resume_with_transport(
        gateway_url,
        blocked_quic_addr,
        ca_cert,
        MvpS2GatewayTransport::Auto {
            tcp_gateway_addr: gateway_tcp_addr,
            quic_fallback_timeout: Duration::from_secs(1),
            expected_active: ramflux_sdk::GatewaySessionTransportKind::TcpTls,
        },
    )
    .await
}

#[cfg(all(test, feature = "realnet"))]
#[derive(Clone, Copy)]
pub(crate) enum MvpS2GatewayTransport {
    Quic,
    TcpTls,
    Auto {
        tcp_gateway_addr: std::net::SocketAddr,
        quic_fallback_timeout: Duration,
        expected_active: ramflux_sdk::GatewaySessionTransportKind,
    },
}

#[cfg(all(test, feature = "realnet"))]
#[allow(clippy::too_many_lines)]
pub(crate) async fn mvp_s2_assert_sdk_session_dm_resume_with_transport(
    gateway_url: &str,
    gateway_addr: std::net::SocketAddr,
    ca_cert: &Path,
    transport: MvpS2GatewayTransport,
) -> Result<(), Box<dyn std::error::Error>> {
    let temp_root = std::env::temp_dir().join(format!(
        "ramflux_s2_sdk_{}_{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos()
    ));
    if temp_root.exists() {
        std::fs::remove_dir_all(&temp_root)?;
    }
    std::fs::create_dir_all(&temp_root)?;

    let alice = mvp_s2_registered_sdk_client(
        &temp_root.join("alice"),
        "alice_s2_account",
        "principal_s2_alice",
        "alice_s2",
        "alice_device_s2",
        "target_s2_alice",
        [0xA2; 32],
        [0xA3; 32],
        gateway_url,
    )?;
    let bob = mvp_s2_registered_sdk_client(
        &temp_root.join("bob"),
        "bob_s2_account",
        "principal_s2_bob",
        "bob_s2",
        "bob_device_s2",
        "target_s2_bob",
        [0xB2; 32],
        [0xB3; 32],
        gateway_url,
    )?;

    let alice_config = mvp_s2_gateway_config(
        gateway_addr,
        ca_cert,
        "principal_s2_alice",
        "alice_device_s2",
        "target_s2_alice",
        transport,
    )?;
    let bob_config = mvp_s2_gateway_config(
        gateway_addr,
        ca_cert,
        "principal_s2_bob",
        "bob_device_s2",
        "target_s2_bob",
        transport,
    )?;

    let mut alice_engine = alice.connect_gateway_session(alice_config).await?;
    let mut bob_engine = bob.connect_gateway_session(bob_config).await?;
    if let Some(expected) = transport.expected_active_transport_kind() {
        assert_eq!(alice_engine.active_transport_kind(), expected);
        assert_eq!(bob_engine.active_transport_kind(), expected);
    }

    let plaintext = b"s2 sdk gateway session dm plaintext";
    let mut alice_dm =
        ramflux_crypto::DmSession::initiator([0x52; 32], [0xa2; 32], [0xb2; 32], [0xc2; 32])?;
    let mut bob_dm =
        ramflux_crypto::DmSession::recipient([0x52; 32], [0xb2; 32], [0xa2; 32], [0xc2; 32])?;
    let dm_ciphertext = alice_dm.encrypt(plaintext, b"mvp_s2_sdk_ad")?;
    let encrypted_body = serde_json::to_vec(&dm_ciphertext)?;
    let message = ramflux_sdk::GatewayDirectMessage {
        conversation_id: "conv_s2_sdk".to_owned(),
        message_id: "msg_s2_sdk_1".to_owned(),
        envelope_id: "env_s2_sdk_dm_1".to_owned(),
        source_principal_id: "principal_s2_alice".to_owned(),
        sender_id: "alice_s2".to_owned(),
        recipient_device_id: None,
        target_delivery_id: "target_s2_bob".to_owned(),
        encrypted_body,
        created_at: itest_now_unix_seconds(),
        ttl: ITEST_REPLAY_TTL_SECONDS,
    };
    let submitted = alice.send_direct_message_via_gateway(&mut alice_engine, message).await?;
    assert_eq!(submitted.envelope.envelope_id, "env_s2_sdk_dm_1");
    assert_eq!(submitted.target_delivery_id, "target_s2_bob");
    assert_node_opaque_payload(&submitted.envelope.encrypted_payload, plaintext);

    let deliveries = bob.receive_gateway_deliveries(&mut bob_engine, 10).await?;
    assert_eq!(deliveries.len(), 1);
    let received = deliveries.first().ok_or("missing S2 SDK delivery")?;
    assert_eq!(received.inbox_seq, 1);
    assert_eq!(received.envelope.envelope_id, "env_s2_sdk_dm_1");
    assert!(bob.event_body("env_s2_sdk_dm_1")?.is_some());
    assert_node_opaque_payload(&received.envelope.encrypted_payload, plaintext);

    let ciphertext_bytes =
        ramflux_protocol::decode_base64url(&received.envelope.encrypted_payload)?;
    let received_ciphertext: ramflux_crypto::DmCiphertext =
        serde_json::from_slice(&ciphertext_bytes)?;
    let decrypted = bob_dm.decrypt(&received_ciphertext, b"mvp_s2_sdk_ad")?;
    assert_eq!(decrypted, plaintext);
    bob.send_direct_message("conv_s2_sdk", "msg_s2_sdk_1", "alice_s2", &decrypted)?;

    let ack_cursor = bob
        .ack_gateway_delivery(&mut bob_engine, "env_s2_sdk_dm_1", "bob_device_s2", 1_760_000_101)
        .await?;
    assert_eq!(ack_cursor.inbox_seq, 1);
    assert!(ack_cursor.acked_envelope_ids.contains(&"env_s2_sdk_dm_1".to_owned()));
    assert_eq!(bob.gateway_cursor("target_s2_bob")?, 1);

    bob_engine.reconnect(bob.gateway_cursor("target_s2_bob")?).await?;
    let replayed = bob.receive_gateway_deliveries(&mut bob_engine, 10).await?;
    assert!(replayed.is_empty(), "acked S2 SDK envelope replayed after reconnect: {replayed:?}");

    let _ = alice_engine.close("s2_done").await;
    let _ = bob_engine.close("s2_done").await;
    std::fs::remove_dir_all(&temp_root)?;
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp_s2_sdk_client(
    root: &Path,
    account_id: &str,
    principal_commitment: &str,
) -> Result<ramflux_sdk::RamfluxClient, Box<dyn std::error::Error>> {
    let mut client = ramflux_sdk::RamfluxClient::new();
    client.open_account_index(root)?;
    client.create_account(account_id, principal_commitment)?;
    client.set_active_account(account_id)?;
    client.unlock_account(account_id, b"s2-sdk-secret")?;
    Ok(client)
}

#[cfg(all(test, feature = "realnet"))]
#[allow(clippy::too_many_arguments)]
pub(crate) fn mvp_s2_registered_sdk_client(
    root: &Path,
    account_id: &str,
    principal_id: &str,
    principal_commitment: &str,
    device_id: &str,
    target_delivery_id: &str,
    root_seed: [u8; 32],
    device_seed: [u8; 32],
    gateway_url: &str,
) -> Result<ramflux_sdk::RamfluxClient, Box<dyn std::error::Error>> {
    let mut client = mvp_s2_sdk_client(root, account_id, principal_commitment)?;
    client.create_identity_root(principal_id, root_seed);
    client.create_device_branch(principal_id, device_id, 1, device_seed);
    client.initialize_and_publish_prekey_bundle(
        principal_commitment,
        device_id,
        target_delivery_id,
        device_seed,
        Some(gateway_url),
    )?;
    Ok(client)
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp_s2_gateway_config(
    gateway_addr: std::net::SocketAddr,
    ca_cert: &Path,
    principal_id: &str,
    device_id: &str,
    target_delivery_id: &str,
    transport: MvpS2GatewayTransport,
) -> Result<ramflux_sdk::GatewaySessionConfig, Box<dyn std::error::Error>> {
    let config = match transport {
        MvpS2GatewayTransport::Quic => {
            ramflux_sdk::GatewaySessionConfig::quic(ramflux_sdk::GatewayQuicEndpointConfig {
                bind_addr: "0.0.0.0:0".parse()?,
                gateway_addr,
                server_name: "localhost".to_owned(),
                ca_cert: ca_cert.to_path_buf(),
                principal_id: principal_id.to_owned(),
                device_id: device_id.to_owned(),
                target_delivery_id: target_delivery_id.to_owned(),
                prekey_http_url: None,
            })
        }
        MvpS2GatewayTransport::TcpTls => {
            ramflux_sdk::GatewaySessionConfig::tcp_tls(ramflux_sdk::GatewayTcpTlsEndpointConfig {
                bind_addr: "0.0.0.0:0".parse()?,
                gateway_addr,
                server_name: "localhost".to_owned(),
                ca_cert: ca_cert.to_path_buf(),
                principal_id: principal_id.to_owned(),
                device_id: device_id.to_owned(),
                target_delivery_id: target_delivery_id.to_owned(),
                prekey_http_url: None,
            })
        }
        MvpS2GatewayTransport::Auto { tcp_gateway_addr, quic_fallback_timeout, .. } => {
            ramflux_sdk::GatewaySessionConfig::auto(ramflux_sdk::GatewayQuicEndpointConfig {
                bind_addr: "0.0.0.0:0".parse()?,
                gateway_addr,
                server_name: "localhost".to_owned(),
                ca_cert: ca_cert.to_path_buf(),
                principal_id: principal_id.to_owned(),
                device_id: device_id.to_owned(),
                target_delivery_id: target_delivery_id.to_owned(),
                prekey_http_url: None,
            })
            .with_tcp_gateway_addr(tcp_gateway_addr)
            .with_quic_fallback_timeout(quic_fallback_timeout)
        }
    };
    Ok(config)
}

#[cfg(all(test, feature = "realnet"))]
impl MvpS2GatewayTransport {
    fn expected_active_transport_kind(self) -> Option<ramflux_sdk::GatewaySessionTransportKind> {
        match self {
            Self::Quic | Self::TcpTls => None,
            Self::Auto { expected_active, .. } => Some(expected_active),
        }
    }
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s3_assert_daemon_bus_account_create_dm(
    gateway_quic_addr: std::net::SocketAddr,
    ca_cert: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let temp_root = std::env::temp_dir().join(format!(
        "ramflux_s3_bus_{}_{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos()
    ));
    std::fs::create_dir_all(&temp_root)?;
    let alice_socket = temp_root.join("alice/rfd.sock");
    let bob_socket = temp_root.join("bob/rfd.sock");
    let (alice_shutdown_tx, alice_shutdown_rx) = tokio::sync::watch::channel(false);
    let (bob_shutdown_tx, bob_shutdown_rx) = tokio::sync::watch::channel(false);
    let alice_config =
        ramflux_sdk::LocalBusConfig::new(&alice_socket, temp_root.join("alice/data"));
    let bob_config = ramflux_sdk::LocalBusConfig::new(&bob_socket, temp_root.join("bob/data"));

    let alice_server = ramflux_sdk::serve_local_bus_until(alice_config, alice_shutdown_rx);
    let bob_server = ramflux_sdk::serve_local_bus_until(bob_config, bob_shutdown_rx);
    let client_flow = mvp_s3_run_bus_client_flow(mvp_s3_flow_config(
        gateway_quic_addr,
        ca_cert,
        &alice_socket,
        &bob_socket,
        alice_shutdown_tx,
        bob_shutdown_tx,
    ));

    let (alice_result, bob_result, flow_result) =
        tokio::join!(alice_server, bob_server, client_flow);
    alice_result?;
    bob_result?;
    flow_result?;
    std::fs::remove_dir_all(&temp_root)?;
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) struct MvpS3FlowConfig {
    pub(crate) gateway_quic_addr: std::net::SocketAddr,
    pub(crate) ca_cert: PathBuf,
    pub(crate) alice_socket: PathBuf,
    pub(crate) bob_socket: PathBuf,
    pub(crate) alice_shutdown_tx: tokio::sync::watch::Sender<bool>,
    pub(crate) bob_shutdown_tx: tokio::sync::watch::Sender<bool>,
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp_s3_flow_config(
    gateway_quic_addr: std::net::SocketAddr,
    ca_cert: &Path,
    alice_socket: &Path,
    bob_socket: &Path,
    alice_shutdown_tx: tokio::sync::watch::Sender<bool>,
    bob_shutdown_tx: tokio::sync::watch::Sender<bool>,
) -> MvpS3FlowConfig {
    MvpS3FlowConfig {
        gateway_quic_addr,
        ca_cert: ca_cert.to_path_buf(),
        alice_socket: alice_socket.to_path_buf(),
        bob_socket: bob_socket.to_path_buf(),
        alice_shutdown_tx,
        bob_shutdown_tx,
    }
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s3_run_bus_client_flow(
    config: MvpS3FlowConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut alice_bus = mvp_s3_connect_bus(&config.alice_socket).await?;
    let mut bob_bus = mvp_s3_connect_bus(&config.bob_socket).await?;
    let mut bob_subscription_bus = mvp_s3_connect_bus(&config.bob_socket).await?;
    assert_eq!(mvp_s3_socket_mode(&config.alice_socket)? & 0o777, 0o600);
    assert_eq!(mvp_s3_socket_mode(&config.bob_socket)? & 0o777, 0o600);
    mvp_s3_create_alice_account(&mut alice_bus, &config).await?;
    mvp_s3_assert_account_transport_quic(&mut alice_bus, "alice_s3_account", "after alice create")
        .await?;
    mvp_s3_assert_offline_resume_catchup(&mut alice_bus, &mut bob_bus, &config).await?;
    mvp_s3_assert_account_transport_quic(
        &mut alice_bus,
        "alice_s3_account",
        "after offline catchup",
    )
    .await?;
    mvp_s3_create_bob_account(&mut bob_bus, &config).await?;
    mvp_s3_assert_account_transport_quic(&mut bob_bus, "bob_s3_account", "after bob create")
        .await?;
    mvp_s3_open_bob_subscription(&mut bob_subscription_bus).await?;
    let plaintext = b"s3 daemon bus e2ee dm plaintext";
    let received_entries = mvp_s3_submit_and_receive(
        &mut alice_bus,
        &mut bob_bus,
        &mut bob_subscription_bus,
        plaintext,
    )
    .await?;
    mvp_s3_assert_account_transport_quic(&mut alice_bus, "alice_s3_account", "after dm receive")
        .await?;
    mvp_s3_assert_account_transport_quic(&mut bob_bus, "bob_s3_account", "after dm receive")
        .await?;
    mvp_s3_decrypt_ack_and_assert_cursor(&mut bob_bus, &received_entries, plaintext).await?;
    mvp_s3_assert_account_transport_quic(&mut bob_bus, "bob_s3_account", "after dm ack").await?;
    drop(alice_bus);
    drop(bob_bus);
    drop(bob_subscription_bus);
    config.alice_shutdown_tx.send(true)?;
    config.bob_shutdown_tx.send(true)?;
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s3_create_alice_account(
    alice_bus: &mut ramflux_sdk::LocalBusClient,
    config: &MvpS3FlowConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let alice_create = mvp_s3_account_create_request(config, MvpS3AccountSpec::alice());
    let alice_created: ramflux_sdk::LocalBusAccountCreateResponse = serde_json::from_value(
        alice_bus.request(None, "account", "account.create", &alice_create).await?,
    )?;
    assert_eq!(alice_created.client_mode, ramflux_sdk::LocalBusClientMode::AttendedCli);
    mvp_s3_assert_create_response_transport_quic(
        &alice_created,
        "alice_s3_account",
        "create response",
    );
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s3_create_bob_account(
    bob_bus: &mut ramflux_sdk::LocalBusClient,
    config: &MvpS3FlowConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let bob_create = mvp_s3_account_create_request(config, MvpS3AccountSpec::bob());
    let bob_created: ramflux_sdk::LocalBusAccountCreateResponse = serde_json::from_value(
        bob_bus.request(None, "account", "account.create", &bob_create).await?,
    )?;
    assert_eq!(bob_created.target_delivery_id, "target_s3_bob");
    mvp_s3_assert_create_response_transport_quic(&bob_created, "bob_s3_account", "create response");
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s3_assert_offline_resume_catchup(
    alice_bus: &mut ramflux_sdk::LocalBusClient,
    bob_bus: &mut ramflux_sdk::LocalBusClient,
    config: &MvpS3FlowConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let offline_plaintext = b"s3 offline catchup must stay encrypted";
    let mut alice_dm =
        ramflux_crypto::DmSession::initiator([0x73; 32], [0xa7; 32], [0xc7; 32], [0xd7; 32])?;
    let mut carol_dm =
        ramflux_crypto::DmSession::recipient([0x73; 32], [0xc7; 32], [0xa7; 32], [0xd7; 32])?;
    let offline_ciphertext = alice_dm.encrypt(offline_plaintext, b"mvp_s3_offline_ad")?;
    let offline_body = serde_json::to_vec(&offline_ciphertext)?;
    let submit = mvp_s3_submit_request_for(
        "msg_s3_offline_1",
        "env_s3_offline_1",
        "target_s3_carol_offline",
        &offline_body,
    );
    let submitted: ramflux_sdk::GatewayInboxEntry = serde_json::from_value(
        alice_bus
            .request(Some("alice_s3_account".to_owned()), "message", "message.submit", &submit)
            .await?,
    )?;
    assert_eq!(submitted.target_delivery_id, "target_s3_carol_offline");
    assert_node_opaque_payload(&submitted.envelope.encrypted_payload, offline_plaintext);
    let carol_create = mvp_s3_account_create_request(config, MvpS3AccountSpec::carol_offline());
    let carol_created: ramflux_sdk::LocalBusAccountCreateResponse = serde_json::from_value(
        bob_bus.request(None, "account", "account.create", &carol_create).await?,
    )?;
    assert_eq!(carol_created.target_delivery_id, "target_s3_carol_offline");
    mvp_s3_assert_create_response_transport_quic(
        &carol_created,
        "carol_s3_account",
        "offline create response",
    );
    mvp_s3_assert_account_transport_quic(
        bob_bus,
        "carol_s3_account",
        "after offline account create",
    )
    .await?;
    let receive = ramflux_sdk::LocalBusMessageReceiveRequest {
        limit: 10,
        conversation_id: None,
        auto_fetch_attachments: false,
        relay_service_key_base64: None,
    };
    let body = bob_bus
        .request(Some("carol_s3_account".to_owned()), "message", "message.receive", &receive)
        .await?;
    let entries = mvp_s3_entries_from_body(&body)?;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].envelope.envelope_id, "env_s3_offline_1");
    assert_node_opaque_payload(&entries[0].envelope.encrypted_payload, offline_plaintext);
    let received_ciphertext_bytes =
        ramflux_protocol::decode_base64url(&entries[0].envelope.encrypted_payload)?;
    let received_ciphertext: ramflux_crypto::DmCiphertext =
        serde_json::from_slice(&received_ciphertext_bytes)?;
    let decrypted = carol_dm.decrypt(&received_ciphertext, b"mvp_s3_offline_ad")?;
    assert_eq!(decrypted, offline_plaintext);
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s3_open_bob_subscription(
    bob_bus: &mut ramflux_sdk::LocalBusClient,
) -> Result<(), Box<dyn std::error::Error>> {
    let subscription =
        ramflux_sdk::LocalBusSubscriptionOpenRequest { topics: vec!["gateway.deliver".to_owned()] };
    let subscribed = bob_bus
        .request(Some("bob_s3_account".to_owned()), "daemon", "subscription.open", &subscription)
        .await?;
    assert_eq!(subscribed["subscribed"], serde_json::Value::Bool(true));
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s3_submit_and_receive(
    alice_bus: &mut ramflux_sdk::LocalBusClient,
    bob_bus: &mut ramflux_sdk::LocalBusClient,
    bob_subscription_bus: &mut ramflux_sdk::LocalBusClient,
    plaintext: &[u8],
) -> Result<Vec<ramflux_sdk::GatewayInboxEntry>, Box<dyn std::error::Error>> {
    let mut alice_dm =
        ramflux_crypto::DmSession::initiator([0x63; 32], [0xa3; 32], [0xb3; 32], [0xc3; 32])?;
    let dm_ciphertext = alice_dm.encrypt(plaintext, b"mvp_s3_bus_ad")?;
    let submit = mvp_s3_submit_request(&serde_json::to_vec(&dm_ciphertext)?);
    let submitted: ramflux_sdk::GatewayInboxEntry = serde_json::from_value(
        alice_bus
            .request(Some("alice_s3_account".to_owned()), "message", "message.submit", &submit)
            .await?,
    )?;
    assert_eq!(submitted.envelope.envelope_id, "env_s3_bus_dm_1");
    assert_eq!(submitted.target_delivery_id, "target_s3_bob");
    assert_node_opaque_payload(&submitted.envelope.encrypted_payload, plaintext);
    let receive = ramflux_sdk::LocalBusMessageReceiveRequest {
        limit: 10,
        conversation_id: None,
        auto_fetch_attachments: false,
        relay_service_key_base64: None,
    };
    let received_body = bob_bus
        .request(Some("bob_s3_account".to_owned()), "message", "message.receive", &receive)
        .await?;
    let received_entries = mvp_s3_entries_from_body(&received_body)?;
    assert_eq!(received_entries.len(), 1);
    let event = tokio::time::timeout(Duration::from_secs(5), bob_subscription_bus.next_event())
        .await
        .map_err(|_elapsed| "timed out waiting for cross-connection gateway.deliver fanout")??;
    assert_eq!(event.method, "gateway.deliver");
    assert_eq!(mvp_s3_entries_from_body(&event.body)?, received_entries);
    let duplicate_body = bob_bus
        .request(Some("bob_s3_account".to_owned()), "message", "message.receive", &receive)
        .await?;
    let duplicate_entries = mvp_s3_entries_from_body(&duplicate_body)?;
    assert_eq!(duplicate_entries.len(), 1);
    assert_eq!(duplicate_entries[0].envelope.envelope_id, "env_s3_bus_dm_1");
    Ok(received_entries)
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s3_decrypt_ack_and_assert_cursor(
    bob_bus: &mut ramflux_sdk::LocalBusClient,
    received_entries: &[ramflux_sdk::GatewayInboxEntry],
    plaintext: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut bob_dm =
        ramflux_crypto::DmSession::recipient([0x63; 32], [0xb3; 32], [0xa3; 32], [0xc3; 32])?;
    let received = received_entries.first().ok_or("missing S3 delivery")?;
    let ciphertext_bytes =
        ramflux_protocol::decode_base64url(&received.envelope.encrypted_payload)?;
    let received_ciphertext: ramflux_crypto::DmCiphertext =
        serde_json::from_slice(&ciphertext_bytes)?;
    assert_eq!(bob_dm.decrypt(&received_ciphertext, b"mvp_s3_bus_ad")?, plaintext);
    let ack = ramflux_sdk::LocalBusMessageAckRequest {
        envelope_id: "env_s3_bus_dm_1".to_owned(),
        receiver_device_id: "bob_device_s3".to_owned(),
        received_at: itest_now_unix_seconds(),
    };
    let cursor: ramflux_sdk::GatewayCursor = serde_json::from_value(
        bob_bus.request(Some("bob_s3_account".to_owned()), "message", "message.ack", &ack).await?,
    )?;
    assert_eq!(cursor.inbox_seq, 1);
    assert!(cursor.acked_envelope_ids.contains(&"env_s3_bus_dm_1".to_owned()));
    let receive = ramflux_sdk::LocalBusMessageReceiveRequest {
        limit: 10,
        conversation_id: None,
        auto_fetch_attachments: false,
        relay_service_key_base64: None,
    };
    let after_ack_body = bob_bus
        .request(Some("bob_s3_account".to_owned()), "message", "message.receive", &receive)
        .await?;
    assert!(mvp_s3_entries_from_body(&after_ack_body)?.is_empty());
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s3_connect_bus(
    socket_path: &Path,
) -> Result<ramflux_sdk::LocalBusClient, Box<dyn std::error::Error>> {
    for _attempt in 0..100 {
        match ramflux_sdk::LocalBusClient::connect(socket_path).await {
            Ok(client) => return Ok(client),
            Err(_error) => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    }
    Err(format!("timed out connecting to local bus socket {}", socket_path.display()).into())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp_s3_socket_mode(socket_path: &Path) -> Result<u32, Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;
    Ok(std::fs::metadata(socket_path)?.permissions().mode())
}

#[cfg(all(test, feature = "realnet"))]
fn mvp_s3_assert_create_response_transport_quic(
    response: &ramflux_sdk::LocalBusAccountCreateResponse,
    account: &str,
    phase: &str,
) {
    assert_eq!(
        response.active_transport_kind,
        ramflux_sdk::GatewaySessionTransportKind::Quic.wire_name(),
        "S3 account {account} must create on QUIC {phase}"
    );
    assert!(!response.session_id.is_empty(), "S3 account {account} missing session_id {phase}");
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s3_assert_account_transport_quic(
    bus: &mut ramflux_sdk::LocalBusClient,
    account: &str,
    phase: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let empty = serde_json::json!({});
    let status = bus.request(Some(account.to_owned()), "account", "account.status", &empty).await?;
    assert_eq!(
        status["active_transport_kind"].as_str(),
        Some(ramflux_sdk::GatewaySessionTransportKind::Quic.wire_name()),
        "S3 account {account} must stay on QUIC {phase}, status={status}"
    );
    let session_id = status["session_id"]
        .as_str()
        .ok_or_else(|| format!("S3 account {account} missing session_id {phase}: {status}"))?;
    assert!(!session_id.is_empty(), "S3 account {account} has empty session_id {phase}: {status}");
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
#[derive(Clone, Copy)]
pub(crate) struct MvpS3AccountSpec {
    pub(crate) local_account_id: &'static str,
    pub(crate) principal_id: &'static str,
    pub(crate) device_id: &'static str,
    pub(crate) target_delivery_id: &'static str,
    pub(crate) root_seed: [u8; 32],
    pub(crate) device_seed: [u8; 32],
}

#[cfg(all(test, feature = "realnet"))]
impl MvpS3AccountSpec {
    pub(crate) const fn alice() -> Self {
        Self {
            local_account_id: "alice_s3_account",
            principal_id: "principal_s3_alice",
            device_id: "alice_device_s3",
            target_delivery_id: "target_s3_alice",
            root_seed: [0xA1; 32],
            device_seed: [0xA2; 32],
        }
    }

    pub(crate) const fn bob() -> Self {
        Self {
            local_account_id: "bob_s3_account",
            principal_id: "principal_s3_bob",
            device_id: "bob_device_s3",
            target_delivery_id: "target_s3_bob",
            root_seed: [0xB1; 32],
            device_seed: [0xB2; 32],
        }
    }

    pub(crate) const fn carol_offline() -> Self {
        Self {
            local_account_id: "carol_s3_account",
            principal_id: "principal_s3_carol",
            device_id: "carol_device_s3",
            target_delivery_id: "target_s3_carol_offline",
            root_seed: [0xC1; 32],
            device_seed: [0xC2; 32],
        }
    }
}
