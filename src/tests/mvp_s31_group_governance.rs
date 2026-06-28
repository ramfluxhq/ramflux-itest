// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use super::*;

#[cfg(feature = "realnet")]
#[test]
fn mvp_s31_realnet_rf_group_governance() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    let node = start_s10_private_node_compose()?;
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async {
        wait_for_private_gateway_quic(node.gateway_quic_addr, &node.ca_cert).await?;
        Box::pin(mvp_s31_assert_rf_group_governance(node.gateway_quic_addr, &node.ca_cert)).await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    drop(node);
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
#[allow(clippy::too_many_lines)]
async fn mvp_s31_assert_rf_group_governance(
    gateway_quic_addr: std::net::SocketAddr,
    ca_cert: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let temp_root = temp_root("s31_group_governance")?;
    let rf_binary = mvp_s4_build_rf_binary().await?;
    let alice_socket = temp_root.join("alice/rfd.sock");
    let bob_socket = temp_root.join("bob/rfd.sock");
    let carol_socket = temp_root.join("carol/rfd.sock");
    let (alice_shutdown_tx, alice_shutdown_rx) = tokio::sync::watch::channel(false);
    let (bob_shutdown_tx, bob_shutdown_rx) = tokio::sync::watch::channel(false);
    let (carol_shutdown_tx, carol_shutdown_rx) = tokio::sync::watch::channel(false);
    let alice_server = ramflux_sdk::serve_local_bus_until(
        ramflux_sdk::LocalBusConfig::new(&alice_socket, temp_root.join("alice/data")),
        alice_shutdown_rx,
    );
    let bob_server = ramflux_sdk::serve_local_bus_until(
        ramflux_sdk::LocalBusConfig::new(&bob_socket, temp_root.join("bob/data")),
        bob_shutdown_rx,
    );
    let carol_server = ramflux_sdk::serve_local_bus_until(
        ramflux_sdk::LocalBusConfig::new(&carol_socket, temp_root.join("carol/data")),
        carol_shutdown_rx,
    );

    let flow = async {
        let result = async {
            mvp_s4_wait_for_socket(&alice_socket).await?;
            mvp_s4_wait_for_socket(&bob_socket).await?;
            mvp_s4_wait_for_socket(&carol_socket).await?;
            let gateway_addr = gateway_quic_addr.to_string();
            let ca_cert_arg = mvp_s4_path_arg(ca_cert);
            let alice_socket_arg = mvp_s4_path_arg(&alice_socket);
            let bob_socket_arg = mvp_s4_path_arg(&bob_socket);
            let carol_socket_arg = mvp_s4_path_arg(&carol_socket);

            mvp_s10_create_rf_account(
                &rf_binary,
                &alice_socket_arg,
                "alice_s31_account",
                "principal_s31_alice",
                "alice_device_s31",
                "target_s31_alice",
                &gateway_addr,
                &ca_cert_arg,
                "41",
                "42",
            )
            .await?;
            mvp_s10_create_rf_account(
                &rf_binary,
                &bob_socket_arg,
                "bob_s31_account",
                "principal_s31_bob",
                "bob_device_s31",
                "target_s31_bob",
                &gateway_addr,
                &ca_cert_arg,
                "43",
                "44",
            )
            .await?;
            mvp_s10_create_rf_account(
                &rf_binary,
                &carol_socket_arg,
                "carol_s31_account",
                "principal_s31_carol",
                "carol_device_s31",
                "target_s31_carol",
                &gateway_addr,
                &ca_cert_arg,
                "45",
                "46",
            )
            .await?;

            let created = mvp_s10_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &alice_socket_arg,
                    "group",
                    "create",
                    "--account",
                    "alice_s31_account",
                    "--group",
                    "group_s31",
                    "--creator",
                    "alice_device_s31",
                ],
                "s31 group create",
            )
            .await?;
            assert_eq!(created["group_id"], "group_s31");
            mvp_s31_add_group_member(
                &rf_binary,
                &alice_socket_arg,
                "bob_device_s31",
                "target_s31_bob",
            )
            .await?;
            mvp_s31_add_group_member(
                &rf_binary,
                &alice_socket_arg,
                "carol_device_s31",
                "target_s31_carol",
            )
            .await?;

            mvp_s31_group_send(
                &rf_binary,
                &alice_socket_arg,
                "msg_s31_before_remove",
                "s31 before remove",
            )
            .await?;
            mvp_s31_assert_group_read_contains(
                &rf_binary,
                &bob_socket_arg,
                "bob_s31_account",
                "msg_s31_before_remove",
                "s31 before remove",
                "s31 bob before remove",
            )
            .await?;
            mvp_s31_assert_group_read_contains(
                &rf_binary,
                &carol_socket_arg,
                "carol_s31_account",
                "msg_s31_before_remove",
                "s31 before remove",
                "s31 carol before remove",
            )
            .await?;

            let removed = mvp_s10_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &alice_socket_arg,
                    "group",
                    "member",
                    "remove",
                    "--account",
                    "alice_s31_account",
                    "--group",
                    "group_s31",
                    "--actor",
                    "alice_device_s31",
                    "--member-device",
                    "bob_device_s31",
                ],
                "s31 group member remove bob",
            )
            .await?;
            assert!(!mvp_s31_string_array_contains(&removed["members"], "bob_device_s31"));
            assert!(mvp_s31_string_array_contains(&removed["members"], "carol_device_s31"));

            mvp_s31_group_send(
                &rf_binary,
                &alice_socket_arg,
                "msg_s31_after_remove",
                "s31 after remove",
            )
            .await?;
            mvp_s31_assert_group_read_contains(
                &rf_binary,
                &carol_socket_arg,
                "carol_s31_account",
                "msg_s31_after_remove",
                "s31 after remove",
                "s31 carol after remove",
            )
            .await?;
            mvp_s31_assert_group_read_missing(
                &rf_binary,
                &bob_socket_arg,
                "bob_s31_account",
                "msg_s31_after_remove",
                "s31 removed bob after remove",
            )
            .await?;

            let policy = mvp_s10_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &alice_socket_arg,
                    "group",
                    "disappearing",
                    "set",
                    "--account",
                    "alice_s31_account",
                    "--group",
                    "group_s31",
                    "--ttl-secs",
                    "1",
                ],
                "s31 group disappearing set",
            )
            .await?;
            assert_eq!(policy["ttl_secs"], 1);
            mvp_s31_group_send(&rf_binary, &alice_socket_arg, "msg_s31_ephemeral", "s31 ephemeral")
                .await?;
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            let expired = mvp_s10_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &alice_socket_arg,
                    "group",
                    "disappearing",
                    "expire",
                    "--account",
                    "alice_s31_account",
                    "--group",
                    "group_s31",
                ],
                "s31 group disappearing expire",
            )
            .await?;
            assert!(
                expired["tombstones"].as_array().is_some_and(|items| items
                    .iter()
                    .any(|item| item["message_id"].as_str() == Some("msg_s31_ephemeral"))),
                "S31 disappearing expire did not tombstone msg_s31_ephemeral: {expired}",
            );

            let muted = mvp_s10_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &alice_socket_arg,
                    "group",
                    "mute",
                    "--account",
                    "alice_s31_account",
                    "--group",
                    "group_s31",
                    "--mute-until",
                    "1760003600",
                ],
                "s31 group mute",
            )
            .await?;
            assert_eq!(muted["mute_until"], 1_760_003_600);
            let unmuted = mvp_s10_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &alice_socket_arg,
                    "group",
                    "mute",
                    "--account",
                    "alice_s31_account",
                    "--group",
                    "group_s31",
                    "--unmute",
                ],
                "s31 group unmute",
            )
            .await?;
            assert!(unmuted["mute_until"].is_null());
            Ok::<(), Box<dyn std::error::Error>>(())
        }
        .await;
        let _ = alice_shutdown_tx.send(true);
        let _ = bob_shutdown_tx.send(true);
        let _ = carol_shutdown_tx.send(true);
        result
    };

    let (alice_result, bob_result, carol_result, flow_result) =
        tokio::time::timeout(std::time::Duration::from_mins(4), async {
            tokio::join!(alice_server, bob_server, carol_server, flow)
        })
        .await
        .map_err(|_elapsed| "S31 group governance flow timed out")?;
    alice_result?;
    bob_result?;
    carol_result?;
    flow_result?;
    std::fs::remove_dir_all(&temp_root)?;
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s31_add_group_member(
    rf_binary: &Path,
    alice_socket_arg: &str,
    member_device: &str,
    target_delivery: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let added = mvp_s10_rf_json(
        rf_binary,
        &[
            "--socket",
            alice_socket_arg,
            "group",
            "member",
            "add",
            "--account",
            "alice_s31_account",
            "--group",
            "group_s31",
            "--member-device",
            member_device,
            "--target-delivery",
            target_delivery,
        ],
        &format!("s31 group member add {member_device}"),
    )
    .await?;
    assert!(mvp_s31_string_array_contains(&added["members"], member_device));
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s31_group_send(
    rf_binary: &Path,
    alice_socket_arg: &str,
    message_id: &str,
    body: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let sent = mvp_s10_rf_json(
        rf_binary,
        &[
            "--socket",
            alice_socket_arg,
            "group",
            "send",
            "--account",
            "alice_s31_account",
            "--group",
            "group_s31",
            "--conversation",
            "group_s31",
            "--message",
            message_id,
            "--sender",
            "alice_device_s31",
            "--body",
            body,
        ],
        &format!("s31 group send {message_id}"),
    )
    .await?;
    assert_eq!(sent["message_id"], message_id);
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s31_assert_group_read_contains(
    rf_binary: &Path,
    socket_arg: &str,
    account: &str,
    message_id: &str,
    body: &str,
    phase: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let read = mvp_s31_group_read(rf_binary, socket_arg, account, phase).await?;
    let decrypted = read["decrypted_messages"]
        .as_array()
        .ok_or_else(|| format!("missing S31 decrypted messages during {phase}: {read}"))?;
    assert!(
        decrypted.iter().any(|item| item["message_id"]
            .as_str()
            .is_some_and(|id| id == message_id || id.starts_with(&format!("{message_id}:")))
            && item["body_utf8"].as_str() == Some(body)),
        "S31 did not find {message_id}/{body} during {phase}: {read}",
    );
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s31_assert_group_read_missing(
    rf_binary: &Path,
    socket_arg: &str,
    account: &str,
    message_id: &str,
    phase: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let read = mvp_s31_group_read(rf_binary, socket_arg, account, phase).await?;
    let decrypted = read["decrypted_messages"]
        .as_array()
        .ok_or_else(|| format!("missing S31 decrypted messages during {phase}: {read}"))?;
    assert!(
        decrypted.iter().all(|item| !item["message_id"]
            .as_str()
            .is_some_and(|id| id == message_id || id.starts_with(&format!("{message_id}:")))),
        "S31 removed member unexpectedly decrypted {message_id} during {phase}: {read}",
    );
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s31_group_read(
    rf_binary: &Path,
    socket_arg: &str,
    account: &str,
    phase: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    mvp_s10_rf_json(
        rf_binary,
        &[
            "--socket",
            socket_arg,
            "group",
            "read",
            "--account",
            account,
            "--group",
            "group_s31",
            "--conversation",
            "group_s31",
        ],
        phase,
    )
    .await
}

#[cfg(all(test, feature = "realnet"))]
fn mvp_s31_string_array_contains(value: &serde_json::Value, expected: &str) -> bool {
    value.as_array().is_some_and(|items| {
        items.iter().any(|item| item.as_str().is_some_and(|item| item == expected))
    })
}
