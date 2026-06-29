// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use crate::*;

#[cfg(all(test, feature = "realnet"))]
#[allow(clippy::too_many_lines)]
pub(crate) async fn mvp_s14_assert_friend_block_remove_revoke(
    gateway_quic_addr: std::net::SocketAddr,
    ca_cert: &Path,
    gateway_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let temp_root = temp_root("s14_friend_block_remove_revoke")?;
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
    let client_flow = async {
        let result = async {
            mvp_s4_wait_for_socket(&alice_socket).await?;
            mvp_s4_wait_for_socket(&bob_socket).await?;
            let gateway_addr = gateway_quic_addr.to_string();
            let ca_cert_arg = mvp_s4_path_arg(ca_cert);
            let alice_socket_arg = mvp_s4_path_arg(&alice_socket);
            let bob_socket_arg = mvp_s4_path_arg(&bob_socket);
            let alice_commitment = ramflux_sdk::identity_root_public_key_commitment_for_seed(
                "principal_s4_alice",
                [0xd1; 32],
            );
            mvp_s4_assert_rf_accounts_and_contact(
                &rf_binary,
                &alice_socket_arg,
                &bob_socket_arg,
                &gateway_addr,
                gateway_url,
                &ca_cert_arg,
            )
            .await?;
            mvp_s14_assert_account_transport_quic(
                &rf_binary,
                &alice_socket_arg,
                "alice_s4_account",
            )
            .await?;
            mvp_s14_assert_account_transport_quic(&rf_binary, &bob_socket_arg, "bob_s4_account")
                .await?;
            let link = mvp_s4_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &alice_socket_arg,
                    "contact",
                    "add",
                    "--account",
                    "alice_s4_account",
                    "--link",
                    "friend_link_s14",
                    "--requester",
                    "principal_s4_alice",
                    "--target",
                    "principal_s4_bob",
                ],
            )
            .await?;
            assert_eq!(link["state"], "accepted");

            mvp_s14_bob_send(
                &rf_binary,
                &bob_socket_arg,
                &alice_commitment,
                "msg_s14_before_block",
                "env_s14_before_block",
                "s14 visible before block",
            )
            .await?;
            let before = mvp_s14_alice_read(&rf_binary, &alice_socket_arg).await?;
            assert!(
                mvp_s14_messages(&before)?
                    .iter()
                    .any(|message| { message["message_id"] == "env_s14_before_block" })
            );
            assert!(mvp_s14_rejected(&before)?.is_empty());

            let blocked = mvp_s4_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &alice_socket_arg,
                    "contact",
                    "block",
                    "--account",
                    "alice_s4_account",
                    "--link",
                    "friend_link_s14",
                ],
            )
            .await?;
            assert_eq!(blocked["state"], "blocked");
            assert_eq!(blocked["blocked"], true);
            assert!(blocked["capability_revoked_at"].is_i64());

            mvp_s14_bob_send(
                &rf_binary,
                &bob_socket_arg,
                &alice_commitment,
                "msg_s14_blocked",
                "env_s14_blocked",
                "s14 hidden while blocked",
            )
            .await?;
            let blocked_read = mvp_s14_alice_read(&rf_binary, &alice_socket_arg).await?;
            assert!(
                !mvp_s14_messages(&blocked_read)?
                    .iter()
                    .any(|message| message["message_id"] == "env_s14_blocked")
            );
            assert!(mvp_s14_rejected(&blocked_read)?.iter().any(|message| {
                message["message_id"] == "env_s14_blocked" && message["reason"] == "friend.blocked"
            }));

            let unblocked = mvp_s4_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &alice_socket_arg,
                    "contact",
                    "unblock",
                    "--account",
                    "alice_s4_account",
                    "--link",
                    "friend_link_s14",
                ],
            )
            .await?;
            assert_eq!(unblocked["state"], "accepted");
            assert_eq!(unblocked["blocked"], false);
            assert!(unblocked["capability_revoked_at"].is_null());

            mvp_s14_bob_send(
                &rf_binary,
                &bob_socket_arg,
                &alice_commitment,
                "msg_s14_after_unblock",
                "env_s14_after_unblock",
                "s14 visible after unblock",
            )
            .await?;
            let after_unblock = mvp_s14_alice_read(&rf_binary, &alice_socket_arg).await?;
            assert!(
                mvp_s14_messages(&after_unblock)?
                    .iter()
                    .any(|message| message["message_id"] == "env_s14_after_unblock")
            );

            for (link_id, scope) in
                [("friend_link_s14_remove_me", "me"), ("friend_link_s14_remove_own", "own-devices")]
            {
                mvp_s14_add_alice_link(&rf_binary, &alice_socket_arg, link_id).await?;
                let removed = mvp_s4_rf_json(
                    &rf_binary,
                    &[
                        "--socket",
                        &alice_socket_arg,
                        "contact",
                        "remove",
                        "--account",
                        "alice_s4_account",
                        "--link",
                        link_id,
                        "--scope",
                        scope,
                    ],
                )
                .await?;
                assert_eq!(removed["state"], "removed");
                assert!(removed["capability_revoked_at"].is_null());
            }

            let removed_both = mvp_s4_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &alice_socket_arg,
                    "contact",
                    "remove",
                    "--account",
                    "alice_s4_account",
                    "--link",
                    "friend_link_s14",
                    "--scope",
                    "both",
                ],
            )
            .await?;
            assert_eq!(removed_both["state"], "removed");
            assert_eq!(removed_both["remove_scope"], "both");
            assert!(removed_both["capability_revoked_at"].is_i64());

            mvp_s14_bob_send(
                &rf_binary,
                &bob_socket_arg,
                &alice_commitment,
                "msg_s14_revoked",
                "env_s14_revoked",
                "s14 hidden after capability revoke",
            )
            .await?;
            let revoked_read = mvp_s14_alice_read(&rf_binary, &alice_socket_arg).await?;
            assert!(
                !mvp_s14_messages(&revoked_read)?
                    .iter()
                    .any(|message| message["message_id"] == "env_s14_revoked")
            );
            assert!(mvp_s14_rejected(&revoked_read)?.iter().any(|message| {
                message["message_id"] == "env_s14_revoked"
                    && message["reason"] == "friend.capability_revoked"
            }));
            let bob_contacts = mvp_s4_rf_json(
                &rf_binary,
                &["--socket", &bob_socket_arg, "contact", "list", "--account", "bob_s4_account"],
            )
            .await?;
            assert!(!bob_contacts.to_string().contains("friend_link_s14"));
            Ok::<(), Box<dyn std::error::Error>>(())
        }
        .await;
        let _ = alice_shutdown_tx.send(true);
        let _ = bob_shutdown_tx.send(true);
        result
    };
    let (alice_result, bob_result, flow_result) =
        tokio::join!(alice_server, bob_server, client_flow);
    alice_result?;
    bob_result?;
    flow_result?;
    std::fs::remove_dir_all(&temp_root)?;
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s14_assert_account_transport_quic(
    rf_binary: &Path,
    socket: &str,
    account: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let status =
        mvp_s4_rf_json(rf_binary, &["--socket", socket, "account", "status", "--account", account])
            .await?;
    assert_eq!(
        status["active_transport_kind"].as_str(),
        Some(ramflux_sdk::GatewaySessionTransportKind::Quic.wire_name()),
        "S14 account {account} must stay on QUIC, status={status}"
    );
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s14_add_alice_link(
    rf_binary: &Path,
    alice_socket: &str,
    link_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let link = mvp_s4_rf_json(
        rf_binary,
        &[
            "--socket",
            alice_socket,
            "contact",
            "add",
            "--account",
            "alice_s4_account",
            "--link",
            link_id,
            "--requester",
            "principal_s4_alice",
            "--target",
            "principal_s4_bob",
        ],
    )
    .await?;
    assert_eq!(link["state"], "accepted");
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s14_bob_send(
    rf_binary: &Path,
    bob_socket: &str,
    alice_commitment: &str,
    message_id: &str,
    envelope_id: &str,
    body: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    mvp_s4_rf_json(
        rf_binary,
        &[
            "--socket",
            bob_socket,
            "dm",
            "send",
            "--account",
            "bob_s4_account",
            "--conversation",
            "conv_s14_friend",
            "--message",
            message_id,
            "--envelope",
            envelope_id,
            "--source-principal",
            "principal_s4_bob",
            "--sender",
            "bob_s4",
            "--recipient-principal-commitment",
            alice_commitment,
            "--recipient-device",
            "alice_device_s4",
            "--target",
            "target_s4_alice",
            "--body",
            body,
        ],
    )
    .await
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s14_alice_read(
    rf_binary: &Path,
    alice_socket: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    mvp_s4_rf_json(
        rf_binary,
        &[
            "--socket",
            alice_socket,
            "dm",
            "read",
            "--account",
            "alice_s4_account",
            "--conversation",
            "conv_s14_friend",
        ],
    )
    .await
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp_s14_messages(
    value: &serde_json::Value,
) -> Result<&Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    value["messages"].as_array().ok_or_else(|| "missing S14 messages".into())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp_s14_rejected(
    value: &serde_json::Value,
) -> Result<&Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    value["rejected"].as_array().ok_or_else(|| "missing S14 rejected inbox".into())
}
