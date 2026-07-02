// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use super::*;

#[cfg(feature = "realnet")]
#[test]
fn mvp_s47_realnet_restore_device_rejoin_manifest_gate() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    let ports = S8ComposePorts {
        gateway_http: 64_761,
        gateway_quic: 64_621,
        router_http: 64_760,
        router_mesh: 64_622,
        notify_http: 64_763,
        federation_http: 64_762,
        federation_mesh: 64_623,
        relay_http: 64_764,
        relay_media_udp: 64_171,
        signaling_turn_udp: 64_640,
        signaling_turn_tcp: 64_641,
        retention_http: 64_767,
    };
    let gateway_capture = "/tmp/ramflux-gateway-itest-capture-s47.jsonl";
    let node = start_s8_realnet_compose_project_with_env(
        "ramflux-s47-restore-device",
        ports,
        &[("RAMFLUX_GATEWAY_ITEST_CAPTURE_JSON".to_owned(), gateway_capture.to_owned())],
    )?;
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async {
        wait_for_private_gateway_quic(node.gateway_quic_addr, &node.ca_cert).await?;
        Box::pin(mvp_s47_assert_restore_device_rejoin(
            &node,
            gateway_capture,
            "ramflux-s47-restore-device",
        ))
        .await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    drop(node);
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
#[allow(clippy::too_many_lines)]
async fn mvp_s47_assert_restore_device_rejoin(
    node: &S8RealnetNode,
    gateway_capture: &str,
    compose_project: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let temp_root = temp_root("s47_restore_device_rejoin")?;
    let alice_primary_socket = temp_root.join("alice_a/rfd.sock");
    let alice_restored_socket = temp_root.join("alice_b/rfd.sock");
    let bob_socket = temp_root.join("bob/rfd.sock");
    let backup_path = temp_root.join("alice-root-backup.ramflux.json");
    let (alice_primary_tx, alice_primary_rx) = tokio::sync::watch::channel(false);
    let (alice_restored_tx, alice_restored_rx) = tokio::sync::watch::channel(false);
    let (bob_tx, bob_rx) = tokio::sync::watch::channel(false);
    let alice_primary_server = ramflux_sdk::serve_local_bus_until(
        ramflux_sdk::LocalBusConfig::new(&alice_primary_socket, temp_root.join("alice_a/data")),
        alice_primary_rx,
    );
    let alice_restored_server = ramflux_sdk::serve_local_bus_until(
        ramflux_sdk::LocalBusConfig::new(&alice_restored_socket, temp_root.join("alice_b/data")),
        alice_restored_rx,
    );
    let bob_server = ramflux_sdk::serve_local_bus_until(
        ramflux_sdk::LocalBusConfig::new(&bob_socket, temp_root.join("bob/data")),
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

            let alice_commitment = mvp_s47_create_account(
                &mut alice_primary,
                node,
                MvpS47AccountSpec {
                    local_account_id: "alice_s47_account",
                    principal_id: "principal_s47_alice",
                    device_id: "alice_device_s47_a",
                    target_delivery_id: "target_s47_alice_a",
                    root_seed: [0x47; 32],
                    device_seed: [0x48; 32],
                },
            )
            .await?;
            let bob_commitment = mvp_s47_create_account(
                &mut bob,
                node,
                MvpS47AccountSpec {
                    local_account_id: "bob_s47_account",
                    principal_id: "principal_s47_bob",
                    device_id: "bob_device_s47",
                    target_delivery_id: "target_s47_bob",
                    root_seed: [0x57; 32],
                    device_seed: [0x58; 32],
                },
            )
            .await?;

            mvp_s47_add_contact(
                &mut alice_primary,
                "alice_s47_account",
                &alice_commitment,
                &bob_commitment,
            )
            .await?;
            mvp_s47_add_contact(&mut bob, "bob_s47_account", &bob_commitment, &alice_commitment)
                .await?;

            let bob_initial_safety =
                mvp_s47_safety(&mut bob, "bob_s47_account", &alice_commitment).await?;
            assert_eq!(bob_initial_safety["contact_device_count"], 1);
            let verified = bob
                .request(
                    Some("bob_s47_account".to_owned()),
                    "contact",
                    "contact.verify",
                    &serde_json::json!({ "contact_identity_commitment": alice_commitment.clone() }),
                )
                .await?;
            assert_eq!(verified["verification_state"], "verified");

            mvp_s47_assert_send_to_missing_device_rejected(
                &mut bob,
                &alice_commitment,
                "alice_device_s47_b",
                "target_s47_alice_b",
                "msg_s47_before_join",
            )
            .await?;

            alice_primary
                .request(
                    Some("alice_s47_account".to_owned()),
                    "account",
                    "account.backup.export",
                    &ramflux_sdk::LocalBusAccountBackupExportRequest {
                        output_path: backup_path.display().to_string(),
                        passphrase: "s47-backup-passphrase-strong".to_owned(),
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
                        passphrase: "s47-backup-passphrase-strong".to_owned(),
                    },
                )
                .await?;

            let activated: ramflux_sdk::LocalBusDeviceActivateResponse = serde_json::from_value(
                alice_restored
                    .request(
                        Some("alice_s47_account".to_owned()),
                        "device",
                        "device.activate",
                        &ramflux_sdk::LocalBusDeviceActivateRequest {
                            device_id: "alice_device_s47_b".to_owned(),
                            target_delivery_id: "target_s47_alice_b".to_owned(),
                            device_seed: [0x49; 32],
                            device_epoch: Some(2),
                        },
                    )
                    .await?,
            )?;
            assert_eq!(activated.device_id, "alice_device_s47_b");
            assert_eq!(activated.devices.len(), 2);
            mvp_s47_assert_manifest_devices(
                &node.gateway_url,
                &alice_commitment,
                &["alice_device_s47_a", "alice_device_s47_b"],
            )?;

            let bob_joined_safety =
                mvp_s47_safety(&mut bob, "bob_s47_account", &alice_commitment).await?;
            assert_eq!(bob_joined_safety["contact_device_count"], 2);
            assert_ne!(
                bob_initial_safety["contact_device_set_hash"],
                bob_joined_safety["contact_device_set_hash"]
            );
            let stale = bob
                .request(
                    Some("bob_s47_account".to_owned()),
                    "contact",
                    "contact.verification.status",
                    &ramflux_sdk::LocalBusContactSafetyRequest {
                        contact_identity_commitment: alice_commitment.clone(),
                    },
                )
                .await?;
            assert_eq!(stale["stored_verification_state"], "verified");
            assert_eq!(stale["verification_state"], "verification_stale");

            let reverified = bob
                .request(
                    Some("bob_s47_account".to_owned()),
                    "contact",
                    "contact.verify",
                    &serde_json::json!({ "contact_identity_commitment": alice_commitment.clone() }),
                )
                .await?;
            assert_eq!(reverified["verification_state"], "verified");

            mvp_s47_assert_unauthorized_device_register_rejected(node, &alice_commitment)?;

            mvp_s47_send_dm(
                &mut bob,
                &alice_commitment,
                "alice_device_s47_b",
                "target_s47_alice_b",
                "msg_s47_after_join",
                b"s47 new device can decrypt after join",
            )
            .await?;
            let alice_b_received =
                mvp_s47_receive(&mut alice_restored, "alice_s47_account", "conv_s47_bob_alice")
                    .await?;
            assert!(mvp_s47_decrypted_contains(
                &alice_b_received,
                b"s47 new device can decrypt after join"
            ));

            let revoked = alice_restored
                .request(
                    Some("alice_s47_account".to_owned()),
                    "device",
                    "device.revoke",
                    &ramflux_sdk::LocalBusDeviceRevokeRequest {
                        device_id: "alice_device_s47_b".to_owned(),
                    },
                )
                .await?;
            assert_eq!(revoked["device_id"], "alice_device_s47_b");
            assert_eq!(revoked["revoked"], true);
            mvp_s47_assert_manifest_devices(
                &node.gateway_url,
                &alice_commitment,
                &["alice_device_s47_a"],
            )?;
            let bob_revoked_safety =
                mvp_s47_safety(&mut bob, "bob_s47_account", &alice_commitment).await?;
            assert_eq!(bob_revoked_safety["contact_device_count"], 1);
            assert_ne!(
                bob_joined_safety["contact_device_set_hash"],
                bob_revoked_safety["contact_device_set_hash"]
            );
            let stale_after_revoke = bob
                .request(
                    Some("bob_s47_account".to_owned()),
                    "contact",
                    "contact.verification.status",
                    &ramflux_sdk::LocalBusContactSafetyRequest {
                        contact_identity_commitment: alice_commitment.clone(),
                    },
                )
                .await?;
            assert_eq!(stale_after_revoke["stored_verification_state"], "verified");
            assert_eq!(stale_after_revoke["verification_state"], "verification_stale");
            mvp_s47_assert_send_to_missing_device_rejected(
                &mut bob,
                &alice_commitment,
                "alice_device_s47_b",
                "target_s47_alice_b",
                "msg_s47_after_revoke",
            )
            .await?;

            mvp_s47_assert_gateway_no_private_material(compose_project, gateway_capture)?;

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
        .map_err(|_elapsed| "S47 restore-device rejoin flow timed out")?;
    alice_primary_result?;
    alice_restored_result?;
    bob_result?;
    flow_result?;
    std::fs::remove_dir_all(&temp_root)?;
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
struct MvpS47AccountSpec<'a> {
    local_account_id: &'a str,
    principal_id: &'a str,
    device_id: &'a str,
    target_delivery_id: &'a str,
    root_seed: [u8; 32],
    device_seed: [u8; 32],
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s47_create_account(
    bus: &mut ramflux_sdk::LocalBusClient,
    node: &S8RealnetNode,
    spec: MvpS47AccountSpec<'_>,
) -> Result<String, Box<dyn std::error::Error>> {
    let request = ramflux_sdk::LocalBusAccountCreateRequest {
        local_account_id: spec.local_account_id.to_owned(),
        principal_id: spec.principal_id.to_owned(),
        principal_commitment: String::new(),
        device_id: spec.device_id.to_owned(),
        target_delivery_id: spec.target_delivery_id.to_owned(),
        account_secret: "s47-bus-secret".to_owned(),
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
    };
    let response: ramflux_sdk::LocalBusAccountCreateResponse =
        serde_json::from_value(bus.request(None, "account", "account.create", &request).await?)?;
    let derived = ramflux_sdk::identity_root_public_key_commitment_for_seed(
        spec.principal_id,
        spec.root_seed,
    );
    assert_eq!(response.principal_commitment, derived);
    mvp_s47_assert_manifest_devices(
        &node.gateway_url,
        &response.principal_commitment,
        &[spec.device_id],
    )?;
    Ok(response.principal_commitment)
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s47_add_contact(
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
                link_id: format!("friend_link_s47_{requester}_{target}"),
                requester_id: requester.to_owned(),
                target_id: target.to_owned(),
            },
        )
        .await?;
    assert_eq!(added["state"], "accepted");
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s47_safety(
    bus: &mut ramflux_sdk::LocalBusClient,
    account: &str,
    contact_identity_commitment: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    Ok(bus
        .request(
            Some(account.to_owned()),
            "contact",
            "contact.safety_number",
            &ramflux_sdk::LocalBusContactSafetyRequest {
                contact_identity_commitment: contact_identity_commitment.to_owned(),
            },
        )
        .await?)
}

#[cfg(all(test, feature = "realnet"))]
fn mvp_s47_assert_manifest_devices(
    gateway_url: &str,
    identity_commitment: &str,
    expected_devices: &[&str],
) -> Result<(), Box<dyn std::error::Error>> {
    let manifest: serde_json::Value = ramflux_node_core::itest_http_get_json(&format!(
        "{gateway_url}/mvp1/device-manifest/{identity_commitment}"
    ))?;
    ramflux_sdk::RamfluxClient::verify_device_manifest_json(manifest.clone(), identity_commitment)?;
    let devices = manifest["devices"].as_array().ok_or("missing devices array")?;
    let mut actual = devices
        .iter()
        .map(|device| device["device_id"].as_str().ok_or("missing device_id"))
        .collect::<Result<Vec<_>, _>>()?;
    actual.sort_unstable();
    let mut expected = expected_devices.to_vec();
    expected.sort_unstable();
    assert_eq!(actual, expected);
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
fn mvp_s47_assert_unauthorized_device_register_rejected(
    node: &S8RealnetNode,
    alice_commitment: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let wrong_root = ramflux_crypto::create_identity_root("principal_s47_alice", [0x77; 32]);
    let wrong_branch = ramflux_crypto::create_device_branch(
        "principal_s47_alice",
        "alice_device_s47_c",
        3,
        [0x78; 32],
    );
    let now = itest_now_unix_seconds();
    let proof = ramflux_crypto::authorize_device_branch(
        &wrong_root,
        &wrong_branch,
        "ramflux-node",
        vec!["device.delivery.bind".to_owned()],
        now,
        now.saturating_add(3_600),
    )?;
    let request = ramflux_node_core::IdentityRegisterRequest {
        root_public_key: ramflux_protocol::encode_base64url(
            wrong_root.signing_key.verifying_key().to_bytes(),
        ),
        principal_commitment: alice_commitment.to_owned(),
        branch_public_key: ramflux_protocol::encode_base64url(
            wrong_branch.signing_key.verifying_key().to_bytes(),
        ),
        proof,
        target_delivery_id: "target_s47_alice_c".to_owned(),
        gateway_id: "ramflux-gateway".to_owned(),
        session_id: "s47-unauthorized-device".to_owned(),
        push_alias_hash: Some("push_alias_s47_unauthorized".to_owned()),
        now,
        registration_pow: None,
        source_ip_hash: Some("s47-unauthorized-source".to_owned()),
    };
    let error = match ramflux_node_core::itest_http_post_json::<_, serde_json::Value>(
        &format!("{}/mvp1/identity/register", node.gateway_url),
        &request,
    ) {
        Ok(value) => {
            return Err(format!("unauthorized device registration succeeded: {value}").into());
        }
        Err(error) => error.to_string(),
    };
    assert!(
        error.contains("principal commitment root mismatch")
            || error.contains("already bound to different root"),
        "unexpected unauthorized registration error: {error}",
    );
    mvp_s47_assert_manifest_devices(
        &node.gateway_url,
        alice_commitment,
        &["alice_device_s47_a", "alice_device_s47_b"],
    )?;
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s47_send_dm(
    bus: &mut ramflux_sdk::LocalBusClient,
    recipient_principal_commitment: &str,
    recipient_device_id: &str,
    target_delivery_id: &str,
    message_id: &str,
    plaintext: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let submitted = bus
        .request(
            Some("bob_s47_account".to_owned()),
            "message",
            "message.submit",
            &ramflux_sdk::LocalBusMessageSubmitRequest {
                conversation_id: "conv_s47_bob_alice".to_owned(),
                message_id: message_id.to_owned(),
                envelope_id: format!("env_{message_id}"),
                source_principal_id: "principal_s47_bob".to_owned(),
                sender_id: "bob_device_s47".to_owned(),
                recipient_device_id: Some(recipient_device_id.to_owned()),
                recipient_principal_commitment: Some(recipient_principal_commitment.to_owned()),
                target_delivery_id: target_delivery_id.to_owned(),
                encrypted_body_base64: String::new(),
                plaintext_body_base64: Some(ramflux_protocol::encode_base64url(plaintext)),
                created_at: itest_now_unix_seconds(),
                ttl: 300,
                attachments: Vec::new(),
                federation: None,
            },
        )
        .await?;
    assert_eq!(submitted["envelope"]["envelope_id"], format!("env_{message_id}"));
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s47_assert_send_to_missing_device_rejected(
    bus: &mut ramflux_sdk::LocalBusClient,
    recipient_principal_commitment: &str,
    recipient_device_id: &str,
    target_delivery_id: &str,
    message_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let error = match mvp_s47_send_dm(
        bus,
        recipient_principal_commitment,
        recipient_device_id,
        target_delivery_id,
        message_id,
        b"s47 must not fanout to absent device",
    )
    .await
    {
        Ok(()) => return Err("fanout to absent device succeeded".into()),
        Err(error) => error.to_string(),
    };
    assert!(
        error.contains("not in verified manifest") || error.contains("missing device manifest"),
        "unexpected missing-device fanout error: {error}",
    );
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s47_receive(
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
                limit: 10,
                conversation_id: Some(conversation_id.to_owned()),
                auto_fetch_attachments: false,
                relay_service_key_base64: None,
            },
        )
        .await?)
}

#[cfg(all(test, feature = "realnet"))]
fn mvp_s47_decrypted_contains(received: &serde_json::Value, body: &[u8]) -> bool {
    received["decrypted_messages"].as_array().into_iter().flatten().any(|message| {
        message["plaintext_body_base64"]
            .as_str()
            .and_then(|encoded| ramflux_protocol::decode_base64url(encoded).ok())
            .is_some_and(|bytes| bytes == body)
    })
}

#[cfg(all(test, feature = "realnet"))]
fn mvp_s47_assert_gateway_no_private_material(
    compose_project: &str,
    gateway_capture: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let capture = mvp_s47_service_file(compose_project, gateway_capture)?;
    let redb = mvp_s47_service_file(compose_project, "/var/lib/ramflux/gateway/gateway.redb")?;
    for haystack in [&capture, &redb] {
        for needle in [
            [0x47; 32].as_slice(),
            [0x48; 32].as_slice(),
            [0x49; 32].as_slice(),
            [0x57; 32].as_slice(),
            [0x58; 32].as_slice(),
            b"s47-backup-passphrase-strong".as_slice(),
        ] {
            assert!(
                !contains_subslice(haystack, needle),
                "gateway leaked private restore material"
            );
        }
    }
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
fn mvp_s47_service_file(
    compose_project: &str,
    remote_path: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let output = std::process::Command::new("docker")
        .args([
            "compose",
            "-p",
            compose_project,
            "-f",
            "docker-compose.itest.yml",
            "exec",
            "-T",
            "ramflux-gateway",
            "cat",
            remote_path,
        ])
        .current_dir(code_root().join("ramflux/deploy"))
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "failed to read gateway file {remote_path}: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(output.stdout)
}
