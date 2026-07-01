// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use super::*;

#[cfg(feature = "realnet")]
#[test]
fn mvp_s35_realnet_multi_device_activation_fanout() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    let realnet = start_realnet_compose()?;
    let ca_cert = code_root().join("ramflux/deploy/certs/ca.pem");
    let gateway_quic_addr: std::net::SocketAddr = std::env::var("RAMFLUX_ITEST_GATEWAY_QUIC_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:18443".to_owned())
        .parse()?;
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async {
        wait_for_private_gateway_quic(gateway_quic_addr, &ca_cert).await?;
        Box::pin(mvp_s35_assert_multi_device_activation(
            gateway_quic_addr,
            &ca_cert,
            &realnet.gateway_url,
        ))
        .await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    drop(realnet);
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
#[allow(clippy::too_many_lines)]
async fn mvp_s35_assert_multi_device_activation(
    gateway_quic_addr: std::net::SocketAddr,
    ca_cert: &Path,
    gateway_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let temp_root = temp_root("s35_multi_device")?;
    let bob_primary_socket = temp_root.join("bob_a/rfd.sock");
    let bob_restored_socket = temp_root.join("bob_b/rfd.sock");
    let alice_socket = temp_root.join("alice/rfd.sock");
    let backup_path = temp_root.join("bob-root-backup.ramflux.json");
    let (bob_primary_tx, bob_primary_rx) = tokio::sync::watch::channel(false);
    let (bob_restored_tx, bob_restored_rx) = tokio::sync::watch::channel(false);
    let (alice_tx, alice_rx) = tokio::sync::watch::channel(false);
    let bob_primary_server = ramflux_sdk::serve_local_bus_until(
        ramflux_sdk::LocalBusConfig::new(&bob_primary_socket, temp_root.join("bob_a/data")),
        bob_primary_rx,
    );
    let bob_restored_server = ramflux_sdk::serve_local_bus_until(
        ramflux_sdk::LocalBusConfig::new(&bob_restored_socket, temp_root.join("bob_b/data")),
        bob_restored_rx,
    );
    let alice_server = ramflux_sdk::serve_local_bus_until(
        ramflux_sdk::LocalBusConfig::new(&alice_socket, temp_root.join("alice/data")),
        alice_rx,
    );

    let flow = async {
        let result = async {
            mvp_s4_wait_for_socket(&bob_primary_socket).await?;
            mvp_s4_wait_for_socket(&bob_restored_socket).await?;
            mvp_s4_wait_for_socket(&alice_socket).await?;
            let mut bob_primary = ramflux_sdk::LocalBusClient::connect(&bob_primary_socket).await?;
            let mut bob_restored =
                ramflux_sdk::LocalBusClient::connect(&bob_restored_socket).await?;
            let mut alice = ramflux_sdk::LocalBusClient::connect(&alice_socket).await?;

            let bob_commitment = mvp_s35_create_account(
                &mut bob_primary,
                gateway_quic_addr,
                ca_cert,
                MvpS35AccountSpec {
                    local_account_id: "bob_s35_account",
                    principal_id: "principal_s35_bob",
                    device_id: "bob_device_s35_a",
                    target_delivery_id: "target_s35_bob_a",
                    root_seed: [0x35; 32],
                    device_seed: [0x36; 32],
                },
            )
            .await?;
            let alice_commitment = mvp_s35_create_account(
                &mut alice,
                gateway_quic_addr,
                ca_cert,
                MvpS35AccountSpec {
                    local_account_id: "alice_s35_account",
                    principal_id: "principal_s35_alice",
                    device_id: "alice_device_s35",
                    target_delivery_id: "target_s35_alice",
                    root_seed: [0x45; 32],
                    device_seed: [0x46; 32],
                },
            )
            .await?;

            bob_primary
                .request(
                    Some("bob_s35_account".to_owned()),
                    "account",
                    "account.backup.export",
                    &ramflux_sdk::LocalBusAccountBackupExportRequest {
                        output_path: backup_path.display().to_string(),
                        passphrase: "s35-backup-passphrase-strong".to_owned(),
                    },
                )
                .await?;
            bob_restored
                .request(
                    None,
                    "account",
                    "account.backup.import",
                    &ramflux_sdk::LocalBusAccountBackupImportRequest {
                        input_path: backup_path.display().to_string(),
                        passphrase: "s35-backup-passphrase-strong".to_owned(),
                    },
                )
                .await?;
            let activated: ramflux_sdk::LocalBusDeviceActivateResponse = serde_json::from_value(
                bob_restored
                    .request(
                        Some("bob_s35_account".to_owned()),
                        "device",
                        "device.activate",
                        &ramflux_sdk::LocalBusDeviceActivateRequest {
                            device_id: "bob_device_s35_b".to_owned(),
                            target_delivery_id: "target_s35_bob_b".to_owned(),
                            device_seed: [0x37; 32],
                            device_epoch: Some(1),
                        },
                    )
                    .await?,
            )?;
            assert_eq!(activated.device_id, "bob_device_s35_b");
            assert_eq!(activated.devices.len(), 2);

            let listed: ramflux_sdk::LocalBusDeviceListResponse = serde_json::from_value(
                bob_restored
                    .request(
                        Some("bob_s35_account".to_owned()),
                        "device",
                        "device.list",
                        &serde_json::json!({}),
                    )
                    .await?,
            )?;
            assert_eq!(listed.principal_id, "principal_s35_bob");
            assert!(
                listed
                    .devices
                    .iter()
                    .any(|device| { device.device_id == "bob_device_s35_a" && !device.is_local })
            );
            assert!(
                listed
                    .devices
                    .iter()
                    .any(|device| { device.device_id == "bob_device_s35_b" && device.is_local })
            );

            mvp_s35_add_contact(
                &mut bob_restored,
                "bob_s35_account",
                &bob_commitment,
                &alice_commitment,
            )
            .await?;
            mvp_s35_add_contact(
                &mut alice,
                "alice_s35_account",
                &alice_commitment,
                &bob_commitment,
            )
            .await?;
            let safety = bob_restored
                .request(
                    Some("bob_s35_account".to_owned()),
                    "contact",
                    "contact.safety_number",
                    &ramflux_sdk::LocalBusContactSafetyRequest {
                        contact_identity_commitment: alice_commitment.clone(),
                    },
                )
                .await?;
            assert_eq!(safety["self_device_count"], 2);

            let submitted = alice
                .request(
                    Some("alice_s35_account".to_owned()),
                    "message",
                    "message.submit",
                    &ramflux_sdk::LocalBusMessageSubmitRequest {
                        conversation_id: "conv_s35_alice_bob".to_owned(),
                        message_id: "msg_s35_alice_to_bob".to_owned(),
                        envelope_id: "env_s35_alice_to_bob".to_owned(),
                        source_principal_id: "principal_s35_alice".to_owned(),
                        sender_id: "alice_s35".to_owned(),
                        recipient_device_id: Some("bob_device_s35_a".to_owned()),
                        recipient_principal_commitment: Some(bob_commitment.clone()),
                        target_delivery_id: "target_s35_bob_a".to_owned(),
                        encrypted_body_base64: String::new(),
                        plaintext_body_base64: Some(ramflux_protocol::encode_base64url(
                            b"s35 hello both devices",
                        )),
                        created_at: itest_now_unix_seconds(),
                        ttl: 300,
                        attachments: Vec::new(),
                        federation: None,
                    },
                )
                .await?;
            assert_eq!(submitted["envelope"]["envelope_id"], "env_s35_alice_to_bob");
            let bob_primary_received = bob_primary
                .request(
                    Some("bob_s35_account".to_owned()),
                    "message",
                    "message.receive",
                    &ramflux_sdk::LocalBusMessageReceiveRequest {
                        limit: 10,
                        conversation_id: Some("conv_s35_alice_bob".to_owned()),
                        auto_fetch_attachments: false,
                        relay_service_key_base64: None,
                    },
                )
                .await?;
            assert_s35_decrypted_body(&bob_primary_received, b"s35 hello both devices")?;

            let mut sync_envelope = itest_envelope("env_s35_own_sync", "fanout-placeholder");
            sync_envelope.source_principal_id = "principal_s35_bob".to_owned();
            sync_envelope.source_device_id = "bob_device_s35_a".to_owned();
            sync_envelope.delivery_class = ramflux_protocol::DeliveryClass::SelfDeviceControl;
            sync_envelope.encrypted_payload =
                ramflux_protocol::encode_base64url(b"s35 opaque own-device dm sync");
            sync_envelope.payload_hash = ramflux_crypto::blake3_256_base64url(
                "ramflux.test.s35.own_device_sync.v1",
                sync_envelope.encrypted_payload.as_bytes(),
            );
            let fanout: ramflux_node_core::ItestMvp10OwnDeviceFanoutResponse =
                ramflux_node_core::itest_http_post_json(
                    &format!("{gateway_url}/mvp10/own-devices/fanout"),
                    &ramflux_node_core::ItestMvp10OwnDeviceFanoutRequest {
                        principal_id: "principal_s35_bob".to_owned(),
                        source_device_id: "bob_device_s35_a".to_owned(),
                        envelope: sync_envelope,
                    },
                )?;
            assert_eq!(fanout.delivered.len(), 1);
            assert_eq!(fanout.delivered[0].device_id, "bob_device_s35_b");
            let bob_restored_received = bob_restored
                .request(
                    Some("bob_s35_account".to_owned()),
                    "message",
                    "message.receive",
                    &ramflux_sdk::LocalBusMessageReceiveRequest {
                        limit: 10,
                        conversation_id: None,
                        auto_fetch_attachments: false,
                        relay_service_key_base64: None,
                    },
                )
                .await?;
            let entries = bob_restored_received["entries"]
                .as_array()
                .ok_or("missing bob B gateway entries")?;
            assert!(
                entries.iter().any(|entry| {
                    entry["envelope"]["envelope_id"]
                        == ramflux_node_core::mvp10_fanout_envelope_id(
                            "env_s35_own_sync",
                            "bob_device_s35_b",
                        )
                }),
                "Bob B did not receive own-device fanout entry: {bob_restored_received}",
            );

            mvp_s35_assert_second_device_deliver_frame_transport(gateway_quic_addr, ca_cert)
                .await?;

            drop(bob_primary);
            drop(bob_restored);
            drop(alice);
            Ok::<(), Box<dyn std::error::Error>>(())
        }
        .await;
        let _ = bob_primary_tx.send(true);
        let _ = bob_restored_tx.send(true);
        let _ = alice_tx.send(true);
        result
    };
    let (bob_primary_result, bob_restored_result, alice_result, flow_result) =
        Box::pin(tokio::time::timeout(Duration::from_mins(4), async {
            tokio::join!(bob_primary_server, bob_restored_server, alice_server, flow)
        }))
        .await
        .map_err(|_elapsed| "S35 multi-device flow timed out")?;
    bob_primary_result?;
    bob_restored_result?;
    alice_result?;
    flow_result?;
    std::fs::remove_dir_all(&temp_root)?;
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
struct MvpS35GatewayFrameSession {
    _endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    open: ramflux_node_core::GatewayOpenFrame,
    session: ramflux_node_core::GatewaySessionEstablishedFrame,
}

#[cfg(all(test, feature = "realnet"))]
struct MvpS35FrameDevice<'a> {
    principal_id: &'a str,
    device_id: &'a str,
    target_delivery_id: &'a str,
    device_seed: [u8; 32],
    device_epoch: u64,
    nonce_suffix: &'a str,
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s35_assert_second_device_deliver_frame_transport(
    gateway_quic_addr: std::net::SocketAddr,
    ca_cert: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut bob_b = mvp_s35_open_registered_gateway_frame_session(
        gateway_quic_addr,
        ca_cert,
        MvpS35FrameDevice {
            principal_id: "principal_s35_bob",
            device_id: "bob_device_s35_b",
            target_delivery_id: "target_s35_bob_b",
            device_seed: [0x37; 32],
            device_epoch: 1,
            nonce_suffix: "bob_b_deliver",
        },
    )
    .await?;
    assert!(!bob_b.session.resume_token.is_empty());
    let previous_bob_b_cursor =
        bob_b.session.accepted_cursor.as_ref().map_or(0, |cursor| cursor.inbox_seq);

    let mut alice = mvp_s35_open_registered_gateway_frame_session(
        gateway_quic_addr,
        ca_cert,
        MvpS35FrameDevice {
            principal_id: "principal_s35_alice",
            device_id: "alice_device_s35",
            target_delivery_id: "target_s35_alice",
            device_seed: [0x46; 32],
            device_epoch: 1,
            nonce_suffix: "alice_submit_to_bob_b",
        },
    )
    .await?;

    let mut envelope = itest_envelope("env_s35_frame_alice_to_bob_b", "target_s35_bob_b");
    envelope.source_principal_id = "principal_s35_alice".to_owned();
    envelope.source_device_id = "alice_device_s35".to_owned();
    envelope.encrypted_payload =
        ramflux_protocol::encode_base64url(b"s35 direct frame payload for bob b");
    envelope.payload_hash = ramflux_crypto::blake3_256_base64url(
        "ramflux.test.s35.second_device_frame.v1",
        envelope.encrypted_payload.as_bytes(),
    );
    let submit = mvp_s1_submit_frame(&alice.open, envelope.clone())?;
    mvp_s1_write_client_frame(
        &mut alice.send,
        &ramflux_node_core::GatewayClientFrame::Submit { submit },
    )
    .await?;

    let sender_echo = mvp_s1_expect_deliver(&mut alice.recv).await?;
    assert_eq!(sender_echo.envelope.envelope_id, "env_s35_frame_alice_to_bob_b");
    assert_eq!(sender_echo.target_delivery_id, "target_s35_bob_b");

    let delivered = mvp_s1_expect_deliver(&mut bob_b.recv).await?;
    assert_eq!(delivered.envelope.envelope_id, "env_s35_frame_alice_to_bob_b");
    assert_eq!(delivered.target_delivery_id, "target_s35_bob_b");
    assert_eq!(delivered.envelope.encrypted_payload, envelope.encrypted_payload);
    assert!(
        delivered.inbox_seq > previous_bob_b_cursor,
        "Bob B direct frame delivery did not advance beyond cursor {previous_bob_b_cursor}: {delivered:?}"
    );

    mvp_s1_write_client_frame(
        &mut bob_b.send,
        &ramflux_node_core::GatewayClientFrame::Ack {
            ack: itest_ack("env_s35_frame_alice_to_bob_b"),
        },
    )
    .await?;
    let ack_cursor = mvp_s1_expect_ack(&mut bob_b.recv).await?;
    assert_eq!(ack_cursor.target_delivery_id, "target_s35_bob_b");
    assert_eq!(ack_cursor.inbox_seq, delivered.inbox_seq);
    assert_eq!(ack_cursor.last_envelope_id.as_deref(), Some("env_s35_frame_alice_to_bob_b"));
    assert!(ack_cursor.acked_envelope_ids.contains(&"env_s35_frame_alice_to_bob_b".to_owned()));
    let cursor_frame =
        mvp_s1_expect_cursor(&mut bob_b.recv).await?.ok_or("missing S35 Bob B ack cursor")?;
    assert_eq!(cursor_frame, ack_cursor);

    alice.connection.close(0_u32.into(), b"s35-alice-frame-done");
    bob_b.connection.close(0_u32.into(), b"s35-bob-b-frame-done");
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s35_open_registered_gateway_frame_session(
    gateway_quic_addr: std::net::SocketAddr,
    ca_cert: &Path,
    device: MvpS35FrameDevice<'_>,
) -> Result<MvpS35GatewayFrameSession, Box<dyn std::error::Error>> {
    let (endpoint, connection, mut send, mut recv) =
        mvp_s1_open_quic_stream(gateway_quic_addr, ca_cert).await?;
    let mut open = mvp_s1_open_frame(None, 1_760_000_035, device.nonce_suffix);
    open.client_instance_id = format!("rf_s35_{}", device.device_id);
    open.device_id = device.device_id.to_owned();
    open.target_delivery_id = device.target_delivery_id.to_owned();
    open.stream_nonce = format!("nonce_s35_{}", device.nonce_suffix);
    open.source_ip_hash = Some("mvp_s35_source".to_owned());
    let auth = mvp_s1_auth_frame_for_registered_device(
        &open,
        device.principal_id,
        device.device_epoch,
        device.device_seed,
    )?;
    mvp_s1_write_client_frame(
        &mut send,
        &ramflux_node_core::GatewayClientFrame::Open { open: open.clone() },
    )
    .await?;
    mvp_s1_write_client_frame(&mut send, &ramflux_node_core::GatewayClientFrame::Auth { auth })
        .await?;
    let session = mvp_s1_expect_session_established(&mut recv).await?;
    Ok(MvpS35GatewayFrameSession { _endpoint: endpoint, connection, send, recv, open, session })
}

#[cfg(all(test, feature = "realnet"))]
struct MvpS35AccountSpec<'a> {
    local_account_id: &'a str,
    principal_id: &'a str,
    device_id: &'a str,
    target_delivery_id: &'a str,
    root_seed: [u8; 32],
    device_seed: [u8; 32],
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s35_create_account(
    bus: &mut ramflux_sdk::LocalBusClient,
    gateway_quic_addr: std::net::SocketAddr,
    ca_cert: &Path,
    spec: MvpS35AccountSpec<'_>,
) -> Result<String, Box<dyn std::error::Error>> {
    let request = ramflux_sdk::LocalBusAccountCreateRequest {
        local_account_id: spec.local_account_id.to_owned(),
        principal_id: spec.principal_id.to_owned(),
        principal_commitment: String::new(),
        device_id: spec.device_id.to_owned(),
        target_delivery_id: spec.target_delivery_id.to_owned(),
        account_secret: "s35-bus-secret".to_owned(),
        root_seed: spec.root_seed,
        device_seed: spec.device_seed,
        client_mode: ramflux_sdk::LocalBusClientMode::AttendedCli,
        gateway: ramflux_sdk::GatewayQuicEndpointConfig {
            bind_addr: std::net::SocketAddr::from(([0, 0, 0, 0], 0)),
            gateway_addr: gateway_quic_addr,
            server_name: "localhost".to_owned(),
            ca_cert: ca_cert.to_path_buf(),
            principal_id: spec.principal_id.to_owned(),
            device_id: spec.device_id.to_owned(),
            target_delivery_id: spec.target_delivery_id.to_owned(),
            prekey_http_url: None,
        },
    };
    let response: ramflux_sdk::LocalBusAccountCreateResponse =
        serde_json::from_value(bus.request(None, "account", "account.create", &request).await?)?;
    assert_eq!(response.local_account_id, spec.local_account_id);
    let transport = response.active_transport_kind.as_str();
    assert!(
        transport.starts_with("quic") || transport.starts_with("tcp"),
        "expected established quic*/tcp* transport, got {transport:?}",
    );
    Ok(response.principal_commitment)
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s35_add_contact(
    bus: &mut ramflux_sdk::LocalBusClient,
    account: &str,
    requester: &str,
    target: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let added = bus
        .request(
            Some(account.to_owned()),
            "contact",
            "contact.add",
            &ramflux_sdk::LocalBusContactAddRequest {
                link_id: format!("friend_link_s35_{requester}_{target}"),
                requester_id: requester.to_owned(),
                target_id: target.to_owned(),
            },
        )
        .await?;
    assert_eq!(added["state"], "accepted");
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
fn assert_s35_decrypted_body(
    received: &serde_json::Value,
    body: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let decrypted =
        received["decrypted_messages"].as_array().ok_or("missing S35 decrypted messages")?;
    let found = decrypted.iter().any(|message| {
        message["plaintext_body_base64"]
            .as_str()
            .and_then(|encoded| ramflux_protocol::decode_base64url(encoded).ok())
            .is_some_and(|bytes| bytes == body)
    });
    if found { Ok(()) } else { Err(format!("S35 decrypted body not found: {received}").into()) }
}
