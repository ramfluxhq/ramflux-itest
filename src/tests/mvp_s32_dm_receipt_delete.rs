// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use super::*;

#[cfg(feature = "realnet")]
#[test]
fn mvp_s32_realnet_rf_dm_receipt_delete() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    let node = start_s10_private_node_compose()?;
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async {
        wait_for_private_gateway_quic(node.gateway_quic_addr, &node.ca_cert).await?;
        Box::pin(mvp_s32_assert_dm_receipt_delete(node.gateway_quic_addr, &node.ca_cert)).await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    drop(node);
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
#[allow(clippy::too_many_lines)]
async fn mvp_s32_assert_dm_receipt_delete(
    gateway_quic_addr: std::net::SocketAddr,
    ca_cert: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let temp_root = temp_root("s32_dm_receipt_delete")?;
    let rf_binary = mvp_s4_build_rf_binary().await?;
    let alice_socket = temp_root.join("alice/rfd.sock");
    let bob_socket = temp_root.join("bob/rfd.sock");
    let (alice_shutdown_tx, alice_shutdown_rx) = tokio::sync::watch::channel(false);
    let (bob_shutdown_tx, bob_shutdown_rx) = tokio::sync::watch::channel(false);
    let alice_server = ramflux_sdk::serve_local_bus_until(
        ramflux_sdk::LocalBusConfig::new(&alice_socket, temp_root.join("alice/data")),
        alice_shutdown_rx,
    );
    let bob_server = ramflux_sdk::serve_local_bus_until(
        ramflux_sdk::LocalBusConfig::new(&bob_socket, temp_root.join("bob/data")),
        bob_shutdown_rx,
    );

    let flow = async {
        let result = async {
            mvp_s4_wait_for_socket(&alice_socket).await?;
            mvp_s4_wait_for_socket(&bob_socket).await?;
            let gateway_addr = gateway_quic_addr.to_string();
            let ca_cert_arg = mvp_s4_path_arg(ca_cert);
            let alice_socket_arg = mvp_s4_path_arg(&alice_socket);
            let bob_socket_arg = mvp_s4_path_arg(&bob_socket);

            mvp_s10_create_rf_account(
                &rf_binary,
                &alice_socket_arg,
                "alice_s32_account",
                "principal_s32_alice",
                "alice_device_s32",
                "target_s32_alice",
                &gateway_addr,
                &ca_cert_arg,
                "52",
                "53",
            )
            .await?;
            mvp_s10_create_rf_account(
                &rf_binary,
                &bob_socket_arg,
                "bob_s32_account",
                "principal_s32_bob",
                "bob_device_s32",
                "target_s32_bob",
                &gateway_addr,
                &ca_cert_arg,
                "62",
                "63",
            )
            .await?;

            let submitted = mvp_s4_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &alice_socket_arg,
                    "dm",
                    "send",
                    "--account",
                    "alice_s32_account",
                    "--conversation",
                    "conv_s32_dm",
                    "--message",
                    "msg_s32_dm_1",
                    "--envelope",
                    "env_s32_dm_1",
                    "--source-principal",
                    "principal_s32_alice",
                    "alice_s32",
                    "--recipient-device",
                    "bob_device_s32",
                    "--target",
                    "target_s32_bob",
                    "--body",
                    "s32 receipt delete plaintext",
                ],
            )
            .await?;
            assert_eq!(submitted["envelope"]["envelope_id"], "env_s32_dm_1");

            let bob_read = mvp_s4_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &bob_socket_arg,
                    "dm",
                    "read",
                    "--account",
                    "bob_s32_account",
                    "--conversation",
                    "conv_s32_dm",
                ],
            )
            .await?;
            let decrypted = bob_read["decrypted_messages"]
                .as_array()
                .ok_or("missing S32 decrypted messages")?;
            assert_eq!(decrypted.len(), 1);
            assert_eq!(decrypted[0]["message_id"].as_str(), Some("env_s32_dm_1"));

            let delivered = mvp_s4_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &bob_socket_arg,
                    "dm",
                    "receipt",
                    "delivered",
                    "--account",
                    "bob_s32_account",
                    "--conversation",
                    "conv_s32_dm",
                    "--message",
                    "env_s32_dm_1",
                    "--receiver-device",
                    "bob_device_s32",
                ],
            )
            .await?;
            assert_eq!(delivered["conversation_id"], "conv_s32_dm");
            assert_eq!(delivered["receiver_device_id"], "bob_device_s32");
            assert_eq!(delivered["delivered_through_message_id"], "env_s32_dm_1");
            assert_eq!(delivered["scope"], "local_projection");

            let read = mvp_s4_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &bob_socket_arg,
                    "dm",
                    "receipt",
                    "read",
                    "--account",
                    "bob_s32_account",
                    "--conversation",
                    "conv_s32_dm",
                    "--message",
                    "env_s32_dm_1",
                    "--reader",
                    "bob_device_s32",
                ],
            )
            .await?;
            assert_eq!(read["conversation_id"], "conv_s32_dm");
            assert_eq!(read["reader_id"], "bob_device_s32");
            assert_eq!(read["read_through_message_id"], "env_s32_dm_1");
            assert_eq!(read["scope"], "local_projection");

            let deleted = mvp_s4_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &bob_socket_arg,
                    "dm",
                    "delete",
                    "--account",
                    "bob_s32_account",
                    "--conversation",
                    "conv_s32_dm",
                    "--message",
                    "env_s32_dm_1",
                ],
            )
            .await?;
            assert_eq!(deleted["conversation_id"], "conv_s32_dm");
            assert_eq!(deleted["message_id"], "env_s32_dm_1");
            assert_eq!(deleted["delete_scope"], "own_devices");

            let after_delete = mvp_s4_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &bob_socket_arg,
                    "dm",
                    "read",
                    "--account",
                    "bob_s32_account",
                    "--conversation",
                    "conv_s32_dm",
                ],
            )
            .await?;
            let messages = after_delete["messages"].as_array().ok_or("missing S32 messages")?;
            let Some(message) = messages
                .iter()
                .find(|message| message["message_id"].as_str() == Some("env_s32_dm_1"))
            else {
                return Err("S32 deleted message record missing from local projection".into());
            };
            assert_eq!(message["deleted"], true);
            assert_eq!(message["body_base64"].as_str(), Some(""));
            assert!(
                after_delete["decrypted_messages"].as_array().is_some_and(Vec::is_empty),
                "S32 deleted message must not decrypt after local delete",
            );

            Ok::<(), Box<dyn std::error::Error>>(())
        }
        .await;
        let _ = alice_shutdown_tx.send(true);
        let _ = bob_shutdown_tx.send(true);
        result
    };
    let (alice_result, bob_result, flow_result) =
        Box::pin(tokio::time::timeout(Duration::from_mins(3), async {
            tokio::join!(alice_server, bob_server, flow)
        }))
        .await
        .map_err(|_elapsed| "S32 client or daemon flow timed out")?;
    alice_result?;
    bob_result?;
    flow_result?;
    std::fs::remove_dir_all(&temp_root)?;
    Ok(())
}
