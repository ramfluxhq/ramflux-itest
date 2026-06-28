// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use super::*;

#[cfg(feature = "realnet")]
#[test]
fn mvp_s48_realnet_own_device_history_group_key_sync() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    let ports = S8ComposePorts {
        gateway_http: 64_771,
        gateway_quic: 64_631,
        router_http: 64_770,
        router_mesh: 64_632,
        notify_http: 64_773,
        federation_http: 64_772,
        federation_mesh: 64_633,
        relay_http: 64_774,
        relay_media_udp: 64_172,
        signaling_turn_udp: 64_650,
        signaling_turn_tcp: 64_651,
        retention_http: 64_777,
    };
    let relay_capture = "/tmp/ramflux-relay-itest-capture-s48.jsonl";
    let gateway_capture = "/tmp/ramflux-gateway-itest-capture-s48.jsonl";
    let node = start_s8_realnet_compose_project_with_env(
        "ramflux-s48-own-device-sync",
        ports,
        &[
            ("RAMFLUX_RELAY_ITEST_CAPTURE_JSON".to_owned(), relay_capture.to_owned()),
            ("RAMFLUX_GATEWAY_ITEST_CAPTURE_JSON".to_owned(), gateway_capture.to_owned()),
        ],
    )?;
    let relay_url = format!("http://127.0.0.1:{}", ports.relay_http);
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async {
        wait_for_private_gateway_quic(node.gateway_quic_addr, &node.ca_cert).await?;
        Box::pin(mvp_s48_assert_own_device_sync(&node, &relay_url)).await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    drop(node);
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
#[allow(clippy::too_many_lines)]
async fn mvp_s48_assert_own_device_sync(
    node: &S8RealnetNode,
    relay_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let temp_root = temp_root("s48_own_device_sync")?;
    let alice_primary_socket = temp_root.join("alice_a/rfd.sock");
    let alice_restored_socket = temp_root.join("alice_b/rfd.sock");
    let bob_socket = temp_root.join("bob/rfd.sock");
    let alice_primary_data = temp_root.join("alice_a/data");
    let alice_restored_data = temp_root.join("alice_b/data");
    let bob_data = temp_root.join("bob/data");
    let backup_path = temp_root.join("alice-root-backup.ramflux.json");
    let (alice_primary_tx, alice_primary_rx) = tokio::sync::watch::channel(false);
    let (alice_restored_tx, alice_restored_rx) = tokio::sync::watch::channel(false);
    let (bob_tx, bob_rx) = tokio::sync::watch::channel(false);
    let alice_primary_server = ramflux_sdk::serve_local_bus_until(
        ramflux_sdk::LocalBusConfig::new(&alice_primary_socket, &alice_primary_data),
        alice_primary_rx,
    );
    let alice_restored_server = ramflux_sdk::serve_local_bus_until(
        ramflux_sdk::LocalBusConfig::new(&alice_restored_socket, &alice_restored_data),
        alice_restored_rx,
    );
    let bob_server = ramflux_sdk::serve_local_bus_until(
        ramflux_sdk::LocalBusConfig::new(&bob_socket, &bob_data),
        bob_rx,
    );

    let flow = async {
        let result = async {
            mvp_s4_wait_for_socket(&alice_primary_socket).await?;
            mvp_s4_wait_for_socket(&alice_restored_socket).await?;
            mvp_s4_wait_for_socket(&bob_socket).await?;
            let mut alice_primary =
                ramflux_sdk::LocalBusClient::connect(&alice_primary_socket).await?;
            let mut alice_restored =
                ramflux_sdk::LocalBusClient::connect(&alice_restored_socket).await?;
            let mut bob = ramflux_sdk::LocalBusClient::connect(&bob_socket).await?;

            let alice_commitment = mvp_s48_create_account(
                &mut alice_primary,
                node,
                MvpS48AccountSpec {
                    local_account_id: "alice_s48_account",
                    principal_id: "principal_s48_alice",
                    device_id: "alice_device_s48_a",
                    target_delivery_id: "target_s48_alice_a",
                    root_seed: [0x48; 32],
                    device_seed: [0x49; 32],
                },
            )
            .await?;
            let bob_commitment = mvp_s48_create_account(
                &mut bob,
                node,
                MvpS48AccountSpec {
                    local_account_id: "bob_s48_account",
                    principal_id: "principal_s48_bob",
                    device_id: "bob_device_s48",
                    target_delivery_id: "target_s48_bob",
                    root_seed: [0x58; 32],
                    device_seed: [0x59; 32],
                },
            )
            .await?;

            mvp_s48_add_contact(&mut bob, "bob_s48_account", &bob_commitment, &alice_commitment)
                .await?;
            mvp_s48_add_contact(
                &mut alice_primary,
                "alice_s48_account",
                &alice_commitment,
                &bob_commitment,
            )
            .await?;

            let dm_submit_created_at = itest_now_unix_seconds();
            mvp_s48_send_dm(
                &mut bob,
                &bob_commitment,
                &alice_commitment,
                "bob_device_s48",
                "alice_device_s48_a",
                "target_s48_alice_a",
                "conv_s48_bob_alice",
                "msg_s48_history_dm",
                dm_submit_created_at,
                b"s48 historical dm",
            )
            .await?;
            let received =
                mvp_s48_receive_dm(&mut alice_primary, "alice_s48_account", "conv_s48_bob_alice")
                    .await?;
            assert!(
                mvp_s48_decrypted_contains(&received, "s48 historical dm"),
                "s48 dm receive payload: {}",
                serde_json::to_string_pretty(&received)
                    .unwrap_or_else(|error| format!("failed to format received JSON: {error}"))
            );
            let primary_dm_list =
                mvp_s48_message_list(&mut alice_primary, "alice_s48_account", "conv_s48_bob_alice")
                    .await?;
            let dm_created_at = mvp_s48_message_created_at(&primary_dm_list, "msg_s48_history_dm")?;

            mvp_s48_seed_group(&mut alice_primary, &bob_commitment).await?;
            let group_sent = mvp_s48_send_group(
                &mut alice_primary,
                "alice_s48_account",
                "group_s48",
                "msg_s48_group_history",
                b"s48 group history",
            )
            .await?;
            assert_eq!(
                group_sent["message_id"],
                "msg_s48_group_history",
                "s48 group send payload: {}",
                serde_json::to_string_pretty(&group_sent)
                    .unwrap_or_else(|error| format!("failed to format group send JSON: {error}"))
            );
            let primary_group_list =
                mvp_s48_message_list(&mut alice_primary, "alice_s48_account", "group_s48").await?;
            let group_created_at =
                mvp_s48_message_created_at(&primary_group_list, "msg_s48_group_history")?;

            mvp_s48_backup_and_activate_restored_device(
                &mut alice_primary,
                &mut alice_restored,
                &backup_path,
            )
            .await?;

            let exported = alice_primary
                .request(
                    Some("alice_s48_account".to_owned()),
                    "device",
                    "device.sync.export",
                    &ramflux_sdk::LocalBusDeviceSyncExportRequest {
                        target_device_id: "alice_device_s48_b".to_owned(),
                        relay_endpoint: relay_url.to_owned(),
                        relay_service_key_base64: Some(
                            "ramflux-relay-itest-service-key".to_owned(),
                        ),
                        chunk_size: Some(4096),
                    },
                )
                .await?;
            assert_eq!(exported["envelope"]["target_device_id"], "alice_device_s48_b");
            assert_eq!(exported["transfer"]["state"], "complete");

            let imported = alice_restored
                .request(
                    Some("alice_s48_account".to_owned()),
                    "device",
                    "device.sync.import",
                    &ramflux_sdk::LocalBusDeviceSyncImportRequest {
                        envelope: exported["envelope"].clone(),
                        relay_service_key_base64: Some(
                            "ramflux-relay-itest-service-key".to_owned(),
                        ),
                    },
                )
                .await?;
            assert!(imported["imported_messages"].as_u64().unwrap_or(0) >= 2);
            assert!(imported["imported_dm_sessions"].as_u64().unwrap_or(0) > 0);
            assert!(imported["imported_groups"].as_u64().unwrap_or(0) > 0);
            assert!(imported["imported_sender_keys"].as_u64().unwrap_or(0) > 0);

            let restored_dm_list = mvp_s48_message_list(
                &mut alice_restored,
                "alice_s48_account",
                "conv_s48_bob_alice",
            )
            .await?;
            assert_eq!(
                mvp_s48_message_created_at(&restored_dm_list, "msg_s48_history_dm")?,
                dm_created_at
            );
            let restored_group_list =
                mvp_s48_message_list(&mut alice_restored, "alice_s48_account", "group_s48").await?;
            assert_eq!(
                mvp_s48_message_created_at(&restored_group_list, "msg_s48_group_history")?,
                group_created_at
            );
            let members = alice_restored
                .request(
                    Some("alice_s48_account".to_owned()),
                    "group",
                    "group.members",
                    &ramflux_sdk::LocalBusGroupRequest { group_id: "group_s48".to_owned() },
                )
                .await?;
            assert_eq!(members["roles"]["alice_device_s48_b"], "owner");
            assert_eq!(members["roles"]["bob_device_s48"], "member");

            let mut restored_reader = ramflux_sdk::RamfluxClient::new();
            restored_reader.open_account_index(&alice_restored_data)?;
            restored_reader.unlock_account("alice_s48_account", b"s48-bus-secret")?;
            let plaintext =
                restored_reader.decrypt_group_message("group_s48", "msg_s48_group_history")?;
            assert_eq!(plaintext, b"s48 group history");

            drop(alice_primary);
            drop(alice_restored);
            drop(bob);
            Ok::<(), Box<dyn std::error::Error>>(())
        }
        .await;
        let _ = alice_primary_tx.send(true);
        let _ = alice_restored_tx.send(true);
        let _ = bob_tx.send(true);
        result
    };
    let (alice_primary_result, alice_restored_result, bob_result, flow_result) =
        Box::pin(tokio::time::timeout(Duration::from_mins(5), async {
            tokio::join!(alice_primary_server, alice_restored_server, bob_server, flow)
        }))
        .await
        .map_err(|_elapsed| "S48 own-device sync flow timed out")?;
    alice_primary_result?;
    alice_restored_result?;
    bob_result?;
    flow_result?;
    std::fs::remove_dir_all(&temp_root)?;
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
struct MvpS48AccountSpec<'a> {
    local_account_id: &'a str,
    principal_id: &'a str,
    device_id: &'a str,
    target_delivery_id: &'a str,
    root_seed: [u8; 32],
    device_seed: [u8; 32],
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s48_create_account(
    bus: &mut ramflux_sdk::LocalBusClient,
    node: &S8RealnetNode,
    spec: MvpS48AccountSpec<'_>,
) -> Result<String, Box<dyn std::error::Error>> {
    let response: ramflux_sdk::LocalBusAccountCreateResponse = serde_json::from_value(
        bus.request(
            None,
            "account",
            "account.create",
            &ramflux_sdk::LocalBusAccountCreateRequest {
                local_account_id: spec.local_account_id.to_owned(),
                principal_id: spec.principal_id.to_owned(),
                principal_commitment: String::new(),
                device_id: spec.device_id.to_owned(),
                target_delivery_id: spec.target_delivery_id.to_owned(),
                account_secret: "s48-bus-secret".to_owned(),
                root_seed: spec.root_seed,
                device_seed: spec.device_seed,
                client_mode: ramflux_sdk::LocalBusClientMode::AttendedCli,
                gateway: ramflux_sdk::GatewayQuicEndpointConfig {
                    bind_addr: std::net::SocketAddr::from(([0, 0, 0, 0], 0)),
                    gateway_addr: node.gateway_quic_addr,
                    server_name: "localhost".to_owned(),
                    ca_cert: node.ca_cert.clone(),
                    principal_id: spec.principal_id.to_owned(),
                    device_id: spec.device_id.to_owned(),
                    target_delivery_id: spec.target_delivery_id.to_owned(),
                    prekey_http_url: None,
                },
            },
        )
        .await?,
    )?;
    assert_eq!(response.local_account_id, spec.local_account_id);
    assert_eq!(response.device_id, spec.device_id);
    Ok(response.principal_commitment)
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s48_add_contact(
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
                link_id: format!("friend_link_s48_{requester}_{target}"),
                requester_id: requester.to_owned(),
                target_id: target.to_owned(),
            },
        )
        .await?;
    assert_eq!(added["state"], "accepted");
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
#[allow(clippy::too_many_arguments)]
async fn mvp_s48_send_dm(
    bus: &mut ramflux_sdk::LocalBusClient,
    source_principal_id: &str,
    recipient_principal_commitment: &str,
    sender_id: &str,
    recipient_device_id: &str,
    target_delivery_id: &str,
    conversation_id: &str,
    message_id: &str,
    created_at: i64,
    plaintext: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let submitted = bus
        .request(
            Some("bob_s48_account".to_owned()),
            "message",
            "message.submit",
            &ramflux_sdk::LocalBusMessageSubmitRequest {
                conversation_id: conversation_id.to_owned(),
                message_id: message_id.to_owned(),
                envelope_id: message_id.to_owned(),
                source_principal_id: source_principal_id.to_owned(),
                sender_id: sender_id.to_owned(),
                recipient_device_id: Some(recipient_device_id.to_owned()),
                recipient_principal_commitment: Some(recipient_principal_commitment.to_owned()),
                target_delivery_id: target_delivery_id.to_owned(),
                encrypted_body_base64: String::new(),
                plaintext_body_base64: Some(ramflux_protocol::encode_base64url(plaintext)),
                created_at,
                ttl: 3600,
                attachments: Vec::new(),
                federation: None,
            },
        )
        .await?;
    assert_eq!(submitted["envelope"]["envelope_id"], message_id);
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s48_receive_dm(
    bus: &mut ramflux_sdk::LocalBusClient,
    account: &str,
    conversation_id: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    Ok(bus
        .request(
            Some(account.to_owned()),
            "message",
            "message.receive",
            &ramflux_sdk::LocalBusMessageReceiveRequest {
                limit: 16,
                conversation_id: Some(conversation_id.to_owned()),
                auto_fetch_attachments: false,
                relay_service_key_base64: None,
            },
        )
        .await?)
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s48_message_list(
    bus: &mut ramflux_sdk::LocalBusClient,
    account: &str,
    conversation_id: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    Ok(bus
        .request(
            Some(account.to_owned()),
            "message",
            "message.list",
            &ramflux_sdk::LocalBusConversationRequest {
                conversation_id: conversation_id.to_owned(),
            },
        )
        .await?)
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s48_seed_group(
    alice: &mut ramflux_sdk::LocalBusClient,
    bob_commitment: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let created = alice
        .request(
            Some("alice_s48_account".to_owned()),
            "group",
            "group.create",
            &ramflux_sdk::LocalBusGroupCreateRequest {
                group_id: "group_s48".to_owned(),
                creator_id: "alice_device_s48_a".to_owned(),
                creator_target_delivery_id: Some("target_s48_alice_a".to_owned()),
                creator_signing_public_key: None,
            },
        )
        .await?;
    assert_eq!(created["roles"]["alice_device_s48_a"], "owner");
    let added = alice
        .request(
            Some("alice_s48_account".to_owned()),
            "group",
            "group.member.add",
            &ramflux_sdk::LocalBusGroupMemberAddRequest {
                group_id: "group_s48".to_owned(),
                member_id: "bob_device_s48".to_owned(),
                role: "member".to_owned(),
                target_delivery_id: Some("target_s48_bob".to_owned()),
                member_principal_commitment: Some(bob_commitment.to_owned()),
                member_signing_public_key: None,
                federation: None,
            },
        )
        .await?;
    assert_eq!(added["roles"]["bob_device_s48"], "member");
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s48_send_group(
    alice: &mut ramflux_sdk::LocalBusClient,
    account: &str,
    group_id: &str,
    message_id: &str,
    plaintext: &[u8],
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    Ok(alice
        .request(
            Some(account.to_owned()),
            "group",
            "group.send",
            &ramflux_sdk::LocalBusGroupSendRequest {
                group_id: group_id.to_owned(),
                conversation_id: group_id.to_owned(),
                message_id: message_id.to_owned(),
                sender_id: "alice_device_s48_a".to_owned(),
                encrypted_body_base64: String::new(),
                plaintext_body_base64: Some(ramflux_protocol::encode_base64url(plaintext)),
                envelope_id: None,
                source_principal_id: None,
                target_delivery_id: None,
                federation: None,
                ttl: Some(3600),
            },
        )
        .await?)
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s48_backup_and_activate_restored_device(
    alice_primary: &mut ramflux_sdk::LocalBusClient,
    alice_restored: &mut ramflux_sdk::LocalBusClient,
    backup_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    alice_primary
        .request(
            Some("alice_s48_account".to_owned()),
            "account",
            "account.backup.export",
            &ramflux_sdk::LocalBusAccountBackupExportRequest {
                output_path: backup_path.display().to_string(),
                passphrase: "s48-backup-passphrase-strong".to_owned(),
            },
        )
        .await?;
    alice_restored
        .request(
            None,
            "account",
            "account.backup.import",
            &ramflux_sdk::LocalBusAccountBackupImportRequest {
                input_path: backup_path.display().to_string(),
                passphrase: "s48-backup-passphrase-strong".to_owned(),
            },
        )
        .await?;
    let activated: ramflux_sdk::LocalBusDeviceActivateResponse = serde_json::from_value(
        alice_restored
            .request(
                Some("alice_s48_account".to_owned()),
                "device",
                "device.activate",
                &ramflux_sdk::LocalBusDeviceActivateRequest {
                    device_id: "alice_device_s48_b".to_owned(),
                    target_delivery_id: "target_s48_alice_b".to_owned(),
                    device_seed: [0x4a; 32],
                    device_epoch: Some(2),
                },
            )
            .await?,
    )?;
    assert_eq!(activated.device_id, "alice_device_s48_b");
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
fn mvp_s48_decrypted_contains(value: &serde_json::Value, needle: &str) -> bool {
    value["decrypted_messages"].as_array().is_some_and(|messages| {
        messages.iter().any(|message| {
            message["plaintext_body_base64"]
                .as_str()
                .and_then(|encoded| ramflux_protocol::decode_base64url(encoded).ok())
                .and_then(|bytes| String::from_utf8(bytes).ok())
                .is_some_and(|body| body.contains(needle))
        })
    })
}

#[cfg(all(test, feature = "realnet"))]
fn mvp_s48_message_created_at(
    value: &serde_json::Value,
    message_id: &str,
) -> Result<i64, Box<dyn std::error::Error>> {
    value["messages"]
        .as_array()
        .and_then(|messages| {
            messages
                .iter()
                .find(|message| message["message_id"] == message_id)
                .and_then(|message| message["created_at"].as_i64())
        })
        .ok_or_else(|| format!("missing created_at for {message_id}").into())
}
