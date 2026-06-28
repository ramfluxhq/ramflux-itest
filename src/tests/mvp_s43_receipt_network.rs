// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use super::*;

const S43_BODY: &str = "s43 network receipt body";

#[cfg(feature = "realnet")]
#[test]
fn mvp_s43_realnet_e2ee_receipt_network_return() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    let ports = S8ComposePorts {
        gateway_http: 64_211,
        gateway_quic: 64_481,
        router_http: 64_210,
        router_mesh: 64_482,
        notify_http: 64_213,
        federation_http: 64_212,
        federation_mesh: 64_483,
        relay_http: 64_214,
        relay_media_udp: 64_130,
        signaling_turn_udp: 64_508,
        signaling_turn_tcp: 64_509,
        retention_http: 64_217,
    };
    let gateway_capture = "/tmp/ramflux-gateway-itest-capture-s43.jsonl";
    let node = start_s8_realnet_compose_project_with_env(
        "ramflux-s43-e2ee-receipts",
        ports,
        &[("RAMFLUX_GATEWAY_ITEST_CAPTURE_JSON".to_owned(), gateway_capture.to_owned())],
    )?;
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async {
        wait_for_private_gateway_quic(node.gateway_quic_addr, &node.ca_cert).await?;
        Box::pin(mvp_s43_assert_e2ee_receipts(&node, gateway_capture, "ramflux-s43-e2ee-receipts"))
            .await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    drop(node);
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
#[allow(clippy::too_many_lines)]
async fn mvp_s43_assert_e2ee_receipts(
    node: &S8RealnetNode,
    gateway_capture: &str,
    compose_project: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let temp_root = temp_root("s43_receipt_network")?;
    let alice_data = temp_root.join("alice/data");
    let bob_data = temp_root.join("bob/data");
    let charlie_data = temp_root.join("charlie/data");
    let alice_socket = temp_root.join("alice/rfd.sock");
    let bob_socket = temp_root.join("bob/rfd.sock");
    let charlie_socket = temp_root.join("charlie/rfd.sock");
    std::fs::create_dir_all(&temp_root)?;
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos())
        .to_string();
    let conversation_id = format!("conv_s43_receipts_{unique}");
    let message_id = format!("env_s43_read_receipt_{unique}");
    let forged_conversation_id = format!("conv_s43_forged_{unique}");
    let forged_message_id = format!("env_s43_forged_{unique}");

    let rf_binary = mvp_s4_build_rf_binary().await?;
    let gateway_addr = node.gateway_quic_addr.to_string();
    let ca_cert_arg = mvp_s4_path_arg(&node.ca_cert);
    let alice_socket_arg = mvp_s4_path_arg(&alice_socket);
    let bob_socket_arg = mvp_s4_path_arg(&bob_socket);
    let charlie_socket_arg = mvp_s4_path_arg(&charlie_socket);

    let (alice_tx, alice_rx) = tokio::sync::watch::channel(false);
    let (bob_tx, bob_rx) = tokio::sync::watch::channel(false);
    let (charlie_tx, charlie_rx) = tokio::sync::watch::channel(false);
    let alice_server = ramflux_sdk::serve_local_bus_until(
        ramflux_sdk::LocalBusConfig::new(&alice_socket, &alice_data),
        alice_rx,
    );
    let bob_server = ramflux_sdk::serve_local_bus_until(
        ramflux_sdk::LocalBusConfig::new(&bob_socket, &bob_data),
        bob_rx,
    );
    let charlie_server = ramflux_sdk::serve_local_bus_until(
        ramflux_sdk::LocalBusConfig::new(&charlie_socket, &charlie_data),
        charlie_rx,
    );

    let flow = async {
        let result = async {
            mvp_s4_wait_for_socket(&alice_socket).await?;
            mvp_s4_wait_for_socket(&bob_socket).await?;
            mvp_s4_wait_for_socket(&charlie_socket).await?;
            let alice_commitment = mvp_s10_create_rf_account(
                &rf_binary,
                &alice_socket_arg,
                "alice_s43_account",
                "principal_s43_alice",
                "alice_device_s43",
                "target_s43_alice",
                &gateway_addr,
                &ca_cert_arg,
                "61",
                "62",
            )
            .await?;
            let bob_commitment = mvp_s10_create_rf_account(
                &rf_binary,
                &bob_socket_arg,
                "bob_s43_account",
                "principal_s43_bob",
                "bob_device_s43",
                "target_s43_bob",
                &gateway_addr,
                &ca_cert_arg,
                "63",
                "64",
            )
            .await?;
            let charlie_commitment = mvp_s10_create_rf_account(
                &rf_binary,
                &charlie_socket_arg,
                "charlie_s43_account",
                "principal_s43_charlie",
                "charlie_device_s43",
                "target_s43_charlie",
                &gateway_addr,
                &ca_cert_arg,
                "65",
                "66",
            )
            .await?;
            mvp_s43_add_contact(
                &rf_binary,
                &alice_socket_arg,
                "alice_s43_account",
                "alice_to_bob_s43",
                &alice_commitment,
                &bob_commitment,
            )
            .await?;
            mvp_s43_add_contact(
                &rf_binary,
                &bob_socket_arg,
                "bob_s43_account",
                "bob_to_alice_s43",
                &bob_commitment,
                &alice_commitment,
            )
            .await?;
            mvp_s43_add_contact(
                &rf_binary,
                &alice_socket_arg,
                "alice_s43_account",
                "alice_to_charlie_s43",
                &alice_commitment,
                &charlie_commitment,
            )
            .await?;
            mvp_s43_add_contact(
                &rf_binary,
                &charlie_socket_arg,
                "charlie_s43_account",
                "charlie_to_alice_s43",
                &charlie_commitment,
                &alice_commitment,
            )
            .await?;

            let sent = mvp_s4_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &alice_socket_arg,
                    "dm",
                    "send",
                    "--account",
                    "alice_s43_account",
                    "--conversation",
                    &conversation_id,
                    "--message",
                    &message_id,
                    "--envelope",
                    &message_id,
                    "--source-principal",
                    "principal_s43_alice",
                    "--sender",
                    "alice_device_s43",
                    "--recipient-device",
                    "bob_device_s43",
                    "--target",
                    "target_s43_bob",
                    "--body",
                    S43_BODY,
                ],
            )
            .await?;
            assert_eq!(sent["envelope"]["envelope_id"], message_id);

            let bob_read = mvp_s4_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &bob_socket_arg,
                    "dm",
                    "read",
                    "--account",
                    "bob_s43_account",
                    "--conversation",
                    &conversation_id,
                ],
            )
            .await?;
            assert_eq!(
                bob_read["decrypted_messages"][0]["plaintext_body_base64"].as_str(),
                Some(ramflux_protocol::encode_base64url(S43_BODY.as_bytes()).as_str())
            );

            let read_at = realnet_now_i64().to_string();
            let read_receipt = mvp_s4_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &bob_socket_arg,
                    "dm",
                    "receipt",
                    "read",
                    "--account",
                    "bob_s43_account",
                    "--conversation",
                    &conversation_id,
                    "--message",
                    &message_id,
                    "--reader",
                    "bob_device_s43",
                    "--recipient-device",
                    "alice_device_s43",
                    "--target",
                    "target_s43_alice",
                    "--read-at",
                    &read_at,
                ],
            )
            .await?;
            assert_eq!(read_receipt["scope"].as_str(), Some("network_e2ee"));

            let alice_receive = mvp_s4_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &alice_socket_arg,
                    "dm",
                    "read",
                    "--account",
                    "alice_s43_account",
                    "--conversation",
                    &conversation_id,
                ],
            )
            .await?;
            assert!(
                alice_receive["decrypted_messages"].as_array().is_some_and(Vec::is_empty),
                "receipt event should not surface as a plaintext DM: {alice_receive}"
            );
            mvp_s43_assert_receipt_state(&alice_receive, &message_id, "bob_device_s43", "read")?;

            let replay = mvp_s4_rf_failure(
                &rf_binary,
                &[
                    "--socket",
                    &bob_socket_arg,
                    "dm",
                    "receipt",
                    "read",
                    "--account",
                    "bob_s43_account",
                    "--conversation",
                    &conversation_id,
                    "--message",
                    &message_id,
                    "--reader",
                    "bob_device_s43",
                    "--recipient-device",
                    "alice_device_s43",
                    "--target",
                    "target_s43_alice",
                    "--read-at",
                    &read_at,
                ],
            )
            .await?;
            assert!(
                replay.contains("replay") || replay.contains("duplicate"),
                "replayed receipt should fail closed: {replay}"
            );
            let alice_after_replay = mvp_s4_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &alice_socket_arg,
                    "dm",
                    "read",
                    "--account",
                    "alice_s43_account",
                    "--conversation",
                    &conversation_id,
                ],
            )
            .await?;
            mvp_s43_assert_receipt_state(
                &alice_after_replay,
                &message_id,
                "bob_device_s43",
                "read",
            )?;

            let delivered_at = realnet_now_i64().to_string();
            let delivered_after_read = mvp_s4_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &bob_socket_arg,
                    "dm",
                    "receipt",
                    "delivered",
                    "--account",
                    "bob_s43_account",
                    "--conversation",
                    &conversation_id,
                    "--message",
                    &message_id,
                    "--receiver-device",
                    "bob_device_s43",
                    "--recipient-device",
                    "alice_device_s43",
                    "--target",
                    "target_s43_alice",
                    "--delivered-at",
                    &delivered_at,
                ],
            )
            .await?;
            assert_eq!(delivered_after_read["scope"].as_str(), Some("network_e2ee"));
            let alice_after_delivered = mvp_s4_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &alice_socket_arg,
                    "dm",
                    "read",
                    "--account",
                    "alice_s43_account",
                    "--conversation",
                    &conversation_id,
                ],
            )
            .await?;
            mvp_s43_assert_receipt_state(
                &alice_after_delivered,
                &message_id,
                "bob_device_s43",
                "read",
            )?;

            let forged_seed = mvp_s4_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &alice_socket_arg,
                    "dm",
                    "send",
                    "--account",
                    "alice_s43_account",
                    "--conversation",
                    &forged_conversation_id,
                    "--message",
                    &forged_message_id,
                    "--envelope",
                    &forged_message_id,
                    "--source-principal",
                    "principal_s43_alice",
                    "--sender",
                    "alice_device_s43",
                    "--recipient-device",
                    "charlie_device_s43",
                    "--target",
                    "target_s43_charlie",
                    "--body",
                    "s43 forged receipt seed",
                ],
            )
            .await?;
            assert_eq!(forged_seed["envelope"]["envelope_id"], forged_message_id);
            let charlie_seed_read = mvp_s4_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &charlie_socket_arg,
                    "dm",
                    "read",
                    "--account",
                    "charlie_s43_account",
                    "--conversation",
                    &forged_conversation_id,
                ],
            )
            .await?;
            assert_eq!(
                charlie_seed_read["decrypted_messages"][0]["message_id"].as_str(),
                Some(forged_message_id.as_str())
            );

            let forged_read_at = realnet_now_i64().to_string();
            let forged = mvp_s4_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &charlie_socket_arg,
                    "dm",
                    "receipt",
                    "read",
                    "--account",
                    "charlie_s43_account",
                    "--conversation",
                    &forged_conversation_id,
                    "--message",
                    &forged_message_id,
                    "--reader",
                    "bob_device_s43",
                    "--recipient-device",
                    "alice_device_s43",
                    "--target",
                    "target_s43_alice",
                    "--read-at",
                    &forged_read_at,
                ],
            )
            .await?;
            assert_eq!(forged["scope"].as_str(), Some("network_e2ee"));
            let rejected = mvp_s4_rf_failure(
                &rf_binary,
                &[
                    "--socket",
                    &alice_socket_arg,
                    "dm",
                    "read",
                    "--account",
                    "alice_s43_account",
                    "--conversation",
                    &forged_conversation_id,
                ],
            )
            .await?;
            assert!(
                rejected.contains("receipt reader_device_id mismatch")
                    || rejected.contains("receipt reader identity mismatch"),
                "forged reader_device_id should fail closed: {rejected}"
            );

            mvp_s43_assert_gateway_opaque(compose_project, gateway_capture)?;
            Ok::<(), Box<dyn std::error::Error>>(())
        }
        .await;
        let _ = alice_tx.send(true);
        let _ = bob_tx.send(true);
        let _ = charlie_tx.send(true);
        result
    };
    let (alice_result, bob_result, charlie_result, flow_result) =
        tokio::time::timeout(Duration::from_mins(5), async {
            tokio::join!(alice_server, bob_server, charlie_server, flow)
        })
        .await
        .map_err(|_elapsed| "s43 local-bus flow timed out")?;
    flow_result?;
    alice_result?;
    bob_result?;
    charlie_result?;
    std::fs::remove_dir_all(&temp_root)?;
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s43_add_contact(
    rf_binary: &Path,
    socket: &str,
    account: &str,
    link: &str,
    requester: &str,
    target: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let added = mvp_s4_rf_json(
        rf_binary,
        &[
            "--socket",
            socket,
            "contact",
            "add",
            "--account",
            account,
            "--link",
            link,
            "--requester",
            requester,
            "--target",
            target,
        ],
    )
    .await?;
    assert_eq!(added["state"], "accepted");
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
fn mvp_s43_assert_receipt_state(
    response: &serde_json::Value,
    message_id: &str,
    device_id: &str,
    state: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let messages = response["messages"].as_array().ok_or("missing messages")?;
    let message = messages
        .iter()
        .find(|message| message["message_id"].as_str() == Some(message_id))
        .ok_or("missing message with receipt")?;
    let receipts = message["receipts"].as_array().ok_or("missing receipts")?;
    let receipt = receipts
        .iter()
        .find(|receipt| receipt["device_id"].as_str() == Some(device_id))
        .ok_or("missing device receipt")?;
    assert_eq!(receipt["state"].as_str(), Some(state));
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
fn mvp_s43_assert_gateway_opaque(
    compose_project: &str,
    gateway_capture: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let capture = mvp_s43_service_file(compose_project, gateway_capture)?;
    for needle in [
        b"ReceiptReadPrivate".as_slice(),
        b"ReceiptReadPublic".as_slice(),
        b"reader_identity".as_slice(),
        b"read_through".as_slice(),
        b"receipt:read:".as_slice(),
        b"receipt:delivered:".as_slice(),
    ] {
        assert!(
            !contains_subslice(&capture, needle),
            "gateway capture leaked E2EE receipt marker {}",
            String::from_utf8_lossy(needle)
        );
    }
    let redb = mvp_s43_service_file(compose_project, "/var/lib/ramflux/gateway/gateway.redb")?;
    for needle in [
        b"ReceiptReadPrivate".as_slice(),
        b"ReceiptReadPublic".as_slice(),
        b"reader_identity".as_slice(),
        b"read_through".as_slice(),
        b"receipt:read:".as_slice(),
        b"receipt:delivered:".as_slice(),
    ] {
        assert!(
            !contains_subslice(&redb, needle),
            "gateway store leaked E2EE receipt marker {}",
            String::from_utf8_lossy(needle)
        );
    }
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
fn mvp_s43_service_file(
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
            "failed to read {remote_path}: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(output.stdout)
}
