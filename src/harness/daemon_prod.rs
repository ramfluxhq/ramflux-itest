// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use crate::*;

#[cfg(all(test, feature = "realnet"))]
#[allow(clippy::too_many_lines)]
pub(crate) async fn mvp_s20_assert_daemon_restart_account_persist(
    gateway_quic_addr: std::net::SocketAddr,
    ca_cert: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let temp_root = temp_root("s20_daemon_restart")?;
    let rf_binary = mvp_s4_build_rf_binary().await?;
    let alice_socket = temp_root.join("alice/rfd.sock");
    let bob_socket = temp_root.join("bob/rfd.sock");
    let alice_data = temp_root.join("alice/data");
    let bob_data = temp_root.join("bob/data");
    let alice_socket_arg = mvp_s4_path_arg(&alice_socket);
    let bob_socket_arg = mvp_s4_path_arg(&bob_socket);
    let alice_data_arg = mvp_s4_path_arg(&alice_data);
    let bob_data_arg = mvp_s4_path_arg(&bob_data);
    let ca_cert_arg = mvp_s4_path_arg(ca_cert);
    let gateway_addr = gateway_quic_addr.to_string();
    let mut alice_daemon = mvp_s20_spawn_rf_daemon(&rf_binary, &alice_socket_arg, &alice_data_arg)?;
    let mut bob_daemon = mvp_s20_spawn_rf_daemon(&rf_binary, &bob_socket_arg, &bob_data_arg)?;
    let flow = async {
        mvp_s4_wait_for_socket(&alice_socket).await?;
        mvp_s4_wait_for_socket(&bob_socket).await?;
        mvp_s10_create_rf_account(
            &rf_binary,
            &alice_socket_arg,
            "alice_s20_account",
            "principal_s20_alice",
            "alice_device_s20",
            "target_s20_alice",
            &gateway_addr,
            &ca_cert_arg,
            "c1",
            "c2",
        )
        .await?;
        mvp_s20_assert_manifest_permissions(&alice_data, "alice_s20_account")?;
        mvp_s20_assert_account_transport_quic(
            &rf_binary,
            &alice_socket_arg,
            "alice_s20_account",
            "before restart",
        )
        .await?;
        let bob_commitment = mvp_s10_create_rf_account(
            &rf_binary,
            &bob_socket_arg,
            "bob_s20_account",
            "principal_s20_bob",
            "bob_device_s20",
            "target_s20_bob",
            &gateway_addr,
            &ca_cert_arg,
            "d1",
            "d2",
        )
        .await?;
        mvp_s20_assert_account_transport_quic(
            &rf_binary,
            &bob_socket_arg,
            "bob_s20_account",
            "before restart",
        )
        .await?;
        let contact = mvp_s10_rf_json(
            &rf_binary,
            &[
                "--socket",
                &alice_socket_arg,
                "contact",
                "add",
                "--account",
                "alice_s20_account",
                "--link",
                "friend_link_s20_alice_bob",
                "--requester",
                "principal_s20_alice",
                "--target",
                "principal_s20_bob",
            ],
            "s20 contact add alice-to-bob",
        )
        .await?;
        assert_eq!(contact["state"], "accepted");
        let first_plaintext = b"s20 before daemon restart";
        let first = mvp_s10_rf_json(
            &rf_binary,
            &[
                "--socket",
                &alice_socket_arg,
                "dm",
                "send",
                "--account",
                "alice_s20_account",
                "--conversation",
                "conv_s20_restart",
                "--message",
                "msg_s20_first",
                "--envelope",
                "env_s20_first",
                "--source-principal",
                "principal_s20_alice",
                "--sender",
                "alice_s20",
                "--recipient-principal-commitment",
                bob_commitment.as_str(),
                "--recipient-device",
                "bob_device_s20",
                "--target",
                "target_s20_bob",
                "--body",
                std::str::from_utf8(first_plaintext)?,
            ],
            "s20 first alice dm send",
        )
        .await?;
        mvp_s20_assert_recent_created_at(&first, "s20 first envelope")?;
        assert_node_opaque_payload(
            first["envelope"]["encrypted_payload"]
                .as_str()
                .ok_or("missing S20 first encrypted payload")?,
            first_plaintext,
        );
        mvp_s20_assert_bob_read_contains(
            &rf_binary,
            &bob_socket_arg,
            "env_s20_first",
            first_plaintext,
        )
        .await?;

        mvp_s20_stop_rf_daemon(&mut alice_daemon).await?;
        alice_daemon = mvp_s20_spawn_rf_daemon(&rf_binary, &alice_socket_arg, &alice_data_arg)?;
        let status = mvp_s20_wait_for_daemon_status(&rf_binary, &alice_socket_arg).await?;
        assert!(status["accounts"].as_u64().unwrap_or_default() >= 1);
        mvp_s20_assert_account_transport_quic(
            &rf_binary,
            &alice_socket_arg,
            "alice_s20_account",
            "after restart",
        )
        .await?;
        let second_plaintext = b"s20 after daemon restart";
        let second = mvp_s10_rf_json(
            &rf_binary,
            &[
                "--socket",
                &alice_socket_arg,
                "dm",
                "send",
                "--account",
                "alice_s20_account",
                "--conversation",
                "conv_s20_restart",
                "--message",
                "msg_s20_second",
                "--envelope",
                "env_s20_second",
                "--source-principal",
                "principal_s20_alice",
                "--sender",
                "alice_s20",
                "--recipient-principal-commitment",
                bob_commitment.as_str(),
                "--recipient-device",
                "bob_device_s20",
                "--target",
                "target_s20_bob",
                "--body",
                std::str::from_utf8(second_plaintext)?,
            ],
            "s20 second alice dm send after restart",
        )
        .await?;
        mvp_s20_assert_recent_created_at(&second, "s20 second envelope")?;
        assert_node_opaque_payload(
            second["envelope"]["encrypted_payload"]
                .as_str()
                .ok_or("missing S20 second encrypted payload")?,
            second_plaintext,
        );
        mvp_s20_assert_bob_read_contains(
            &rf_binary,
            &bob_socket_arg,
            "env_s20_second",
            second_plaintext,
        )
        .await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    };
    let result = tokio::time::timeout(Duration::from_mins(3), flow)
        .await
        .map_err(|_elapsed| "S20 daemon restart flow timed out")?;
    let _ = mvp_s20_stop_rf_daemon(&mut alice_daemon).await;
    let _ = mvp_s20_stop_rf_daemon(&mut bob_daemon).await;
    result?;
    std::fs::remove_dir_all(&temp_root)?;
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s20_assert_account_transport_quic(
    rf_binary: &Path,
    socket_arg: &str,
    account: &str,
    phase: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let status = mvp_s10_rf_json(
        rf_binary,
        &["--socket", socket_arg, "account", "status", "--account", account],
        &format!("s20 account status {account} {phase}"),
    )
    .await?;
    assert_eq!(
        status["active_transport_kind"].as_str(),
        Some(ramflux_sdk::GatewaySessionTransportKind::Quic.wire_name()),
        "S20 account {account} must stay on QUIC {phase}, status={status}"
    );
    let session_id = status["session_id"]
        .as_str()
        .ok_or_else(|| format!("S20 account {account} missing session_id {phase}: {status}"))?;
    assert!(!session_id.is_empty(), "S20 account {account} has empty session_id {phase}: {status}");
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
fn mvp_s20_assert_recent_created_at(
    value: &serde_json::Value,
    label: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let created_at = value["envelope"]["created_at"]
        .as_i64()
        .ok_or_else(|| format!("{label} missing envelope.created_at"))?;
    if created_at <= 1_700_000_000 || created_at == 1_760_000_000 {
        return Err(format!("{label} created_at not real clock: {created_at}").into());
    }
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp_s20_spawn_rf_daemon(
    rf_binary: &Path,
    socket: &str,
    data_root: &str,
) -> Result<tokio::process::Child, Box<dyn std::error::Error>> {
    let child = tokio::process::Command::new(rf_binary)
        .args(["--socket", socket, "daemon", "start", "--data-root", data_root])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    Ok(child)
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s20_stop_rf_daemon(
    child: &mut tokio::process::Child,
) -> Result<(), Box<dyn std::error::Error>> {
    let _ = child.kill().await;
    let _ = tokio::time::timeout(Duration::from_secs(10), child.wait()).await;
    Ok(())
}

// After a SIGKILL restart the previous daemon's socket file lingers, so file existence
// alone is not a readiness signal: poll the actual `daemon status` until the freshly
// rebound listener accepts a connection (mirrors how a real client would retry).

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s20_wait_for_daemon_status(
    rf_binary: &Path,
    socket_arg: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let mut last_err: Option<Box<dyn std::error::Error>> = None;
    for _attempt in 0..100 {
        match mvp_s10_rf_json(
            rf_binary,
            &["--socket", socket_arg, "daemon", "status"],
            "s20 alice daemon status after restart",
        )
        .await
        {
            Ok(value) => return Ok(value),
            Err(error) => last_err = Some(error),
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err(last_err.unwrap_or_else(|| "daemon status never became ready after restart".into()))
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s20_assert_bob_read_contains(
    rf_binary: &Path,
    bob_socket_arg: &str,
    expected_envelope_id: &str,
    expected_plaintext: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let bob_read = mvp_s10_rf_json(
        rf_binary,
        &[
            "--socket",
            bob_socket_arg,
            "dm",
            "read",
            "--account",
            "bob_s20_account",
            "--conversation",
            "conv_s20_restart",
        ],
        &format!("s20 bob dm read {expected_envelope_id}"),
    )
    .await?;
    let decrypted =
        bob_read["decrypted_messages"].as_array().ok_or("missing S20 decrypted messages")?;
    for message in decrypted {
        if message["message_id"].as_str() == Some(expected_envelope_id) {
            let body = ramflux_protocol::decode_base64url(
                message["plaintext_body_base64"].as_str().ok_or("missing S20 plaintext")?,
            )?;
            assert_eq!(body, expected_plaintext);
            return Ok(());
        }
    }
    Err(format!("missing decrypted S20 message {expected_envelope_id}").into())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp_s20_assert_manifest_permissions(
    data_root: &Path,
    account_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let accounts_dir = data_root.join("local_bus_accounts");
    let manifest = accounts_dir.join(format!("{account_id}.json"));
    let dir_mode = std::fs::metadata(&accounts_dir)?.permissions().mode() & 0o777;
    let file_mode = std::fs::metadata(&manifest)?.permissions().mode() & 0o777;
    assert_eq!(dir_mode, 0o700);
    assert_eq!(file_mode, 0o600);
    Ok(())
}
