// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use super::*;

#[cfg(feature = "realnet")]
#[test]
fn mvp_s30_realnet_rf_account_backup_restore() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    let realnet = start_realnet_compose()?;
    let code_root = code_root();
    let ca_cert = code_root.join("ramflux/deploy/certs/ca.pem");
    let gateway_quic_addr: std::net::SocketAddr = std::env::var("RAMFLUX_ITEST_GATEWAY_QUIC_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:18443".to_owned())
        .parse()?;

    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async {
        Box::pin(mvp_s30_assert_account_backup_restore(
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
async fn mvp_s30_assert_account_backup_restore(
    gateway_quic_addr: std::net::SocketAddr,
    ca_cert: &Path,
    gateway_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let temp_root = std::env::temp_dir().join(format!(
        "ramflux_s30_backup_{}_{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos()
    ));
    std::fs::create_dir_all(&temp_root)?;
    let rf_binary = mvp_s4_build_rf_binary().await?;
    let alice_socket = temp_root.join("alice/rfd.sock");
    let alice_restore_socket = temp_root.join("alice_restore/rfd.sock");
    let bob_socket = temp_root.join("bob/rfd.sock");
    let backup_path = temp_root.join("alice-root-backup.ramflux.json");
    let (alice_shutdown_tx, alice_shutdown_rx) = tokio::sync::watch::channel(false);
    let (alice_restore_shutdown_tx, alice_restore_shutdown_rx) = tokio::sync::watch::channel(false);
    let (bob_shutdown_tx, bob_shutdown_rx) = tokio::sync::watch::channel(false);
    let alice_config =
        ramflux_sdk::LocalBusConfig::new(&alice_socket, temp_root.join("alice/data"));
    let alice_restore_config = ramflux_sdk::LocalBusConfig::new(
        &alice_restore_socket,
        temp_root.join("alice_restore/data"),
    );
    let bob_config = ramflux_sdk::LocalBusConfig::new(&bob_socket, temp_root.join("bob/data"));

    let alice_server = ramflux_sdk::serve_local_bus_until(alice_config, alice_shutdown_rx);
    let alice_restore_server =
        ramflux_sdk::serve_local_bus_until(alice_restore_config, alice_restore_shutdown_rx);
    let bob_server = ramflux_sdk::serve_local_bus_until(bob_config, bob_shutdown_rx);
    let client_flow = async {
        let result = async {
            mvp_s4_wait_for_socket(&alice_socket).await?;
            mvp_s4_wait_for_socket(&alice_restore_socket).await?;
            mvp_s4_wait_for_socket(&bob_socket).await?;
            let gateway_addr = gateway_quic_addr.to_string();
            let ca_cert_arg = mvp_s4_path_arg(ca_cert);
            let alice_socket_arg = mvp_s4_path_arg(&alice_socket);
            let alice_restore_socket_arg = mvp_s4_path_arg(&alice_restore_socket);
            let bob_socket_arg = mvp_s4_path_arg(&bob_socket);
            let backup_path_arg = mvp_s4_path_arg(&backup_path);

            mvp_s8_create_rf_account(
                &rf_binary,
                &alice_socket_arg,
                "alice_s30_account",
                "principal_s30_alice",
                "alice_device_s30",
                "target_s30_alice",
                &gateway_addr,
                gateway_url,
                &ca_cert_arg,
                "31",
                "32",
            )
            .await?;
            let bob_commitment = mvp_s8_create_rf_account(
                &rf_binary,
                &bob_socket_arg,
                "bob_s30_account",
                "principal_s30_bob",
                "bob_device_s30",
                "target_s30_bob",
                &gateway_addr,
                gateway_url,
                &ca_cert_arg,
                "41",
                "42",
            )
            .await?;

            mvp_s30_send_and_read_dm(
                &rf_binary,
                &alice_socket_arg,
                &bob_socket_arg,
                &bob_commitment,
                "env_s30_before_backup",
                "msg_s30_before_backup",
                "s30 before backup",
            )
            .await?;

            let exported = mvp_s30_rf_json_with_env(
                &rf_binary,
                &[("RAMFLUX_ACCOUNT_BACKUP_PASSPHRASE", "s30-backup-passphrase-strong")],
                &[
                    "--socket",
                    &alice_socket_arg,
                    "account",
                    "backup",
                    "export",
                    "--account",
                    "alice_s30_account",
                    "--out",
                    &backup_path_arg,
                ],
            )
            .await?;
            assert_eq!(exported["encrypted"], true);
            let backup_bytes = std::fs::read(&backup_path)?;
            assert!(
                !String::from_utf8_lossy(&backup_bytes).contains("principal_s30_alice"),
                "S30 encrypted backup must not contain plaintext identity material",
            );

            mvp_s30_rf_json_expect_failure_with_env(
                &rf_binary,
                &[("RAMFLUX_ACCOUNT_BACKUP_PASSPHRASE", "wrong-backup-passphrase-strong")],
                &[
                    "--socket",
                    &alice_restore_socket_arg,
                    "account",
                    "backup",
                    "import",
                    "--in",
                    &backup_path_arg,
                ],
            )
            .await?;

            let imported = mvp_s30_rf_json_with_env(
                &rf_binary,
                &[("RAMFLUX_ACCOUNT_BACKUP_PASSPHRASE", "s30-backup-passphrase-strong")],
                &[
                    "--socket",
                    &alice_restore_socket_arg,
                    "account",
                    "backup",
                    "import",
                    "--in",
                    &backup_path_arg,
                ],
            )
            .await?;
            assert_eq!(imported["local_account_id"], "alice_s30_account");
            assert_eq!(imported["principal_id"], "principal_s30_alice");
            assert_eq!(imported["target_delivery_id"], "target_s30_alice");
            assert_eq!(imported["active_transport_kind"], "disconnected");

            let restored_status = mvp_s4_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &alice_restore_socket_arg,
                    "account",
                    "status",
                    "--account",
                    "alice_s30_account",
                ],
            )
            .await?;
            assert_eq!(restored_status["principal_id"], "principal_s30_alice");
            assert_eq!(restored_status["target_delivery_id"], "target_s30_alice");

            let rotated = mvp_s30_rf_json_with_env(
                &rf_binary,
                &[
                    ("RAMFLUX_ACCOUNT_OLD_PASSPHRASE", "rf-local-secret"),
                    ("RAMFLUX_ACCOUNT_NEW_PASSPHRASE", "s30-new-account-secret-strong"),
                ],
                &[
                    "--socket",
                    &alice_restore_socket_arg,
                    "account",
                    "passphrase",
                    "rotate",
                    "--account",
                    "alice_s30_account",
                ],
            )
            .await?;
            assert_eq!(rotated["rotated"], true);

            let locked = mvp_s4_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &alice_restore_socket_arg,
                    "account",
                    "lock",
                    "--account",
                    "alice_s30_account",
                ],
            )
            .await?;
            assert_eq!(locked["locked"], true);
            mvp_s30_rf_json_expect_failure(
                &rf_binary,
                &[
                    "--socket",
                    &alice_restore_socket_arg,
                    "account",
                    "status",
                    "--account",
                    "alice_s30_account",
                ],
            )
            .await?;

            // Import is intentionally offline root/account recovery. Rejoining gateway and
            // publishing a fresh restored-device prekey is Phase C2 device activation scope.

            Ok::<(), Box<dyn std::error::Error>>(())
        }
        .await;
        let _ = alice_shutdown_tx.send(true);
        let _ = alice_restore_shutdown_tx.send(true);
        let _ = bob_shutdown_tx.send(true);
        result
    };

    let (alice_result, alice_restore_result, bob_result, flow_result) =
        tokio::join!(alice_server, alice_restore_server, bob_server, client_flow);
    alice_result?;
    alice_restore_result?;
    bob_result?;
    flow_result?;
    std::fs::remove_dir_all(&temp_root)?;
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s30_send_and_read_dm(
    rf_binary: &Path,
    alice_socket: &str,
    bob_socket: &str,
    bob_commitment: &str,
    envelope_id: &str,
    message_id: &str,
    body: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let submitted = mvp_s4_rf_json(
        rf_binary,
        &[
            "--socket",
            alice_socket,
            "dm",
            "send",
            "--account",
            "alice_s30_account",
            "--conversation",
            "conv_s30_backup",
            "--message",
            message_id,
            "--envelope",
            envelope_id,
            "--source-principal",
            "principal_s30_alice",
            "--sender",
            "alice_s30",
            "--recipient-principal-commitment",
            bob_commitment,
            "--recipient-device",
            "bob_device_s30",
            "--target",
            "target_s30_bob",
            "--body",
            body,
        ],
    )
    .await?;
    assert_eq!(submitted["envelope"]["envelope_id"], envelope_id);

    let bob_read = mvp_s4_rf_json(
        rf_binary,
        &[
            "--socket",
            bob_socket,
            "dm",
            "read",
            "--account",
            "bob_s30_account",
            "--conversation",
            "conv_s30_backup",
        ],
    )
    .await?;
    let decrypted =
        bob_read["decrypted_messages"].as_array().ok_or("missing S30 decrypted messages")?;
    let found = decrypted.iter().any(|message| {
        let Some(plaintext) = message["plaintext_body_base64"].as_str() else {
            return false;
        };
        ramflux_protocol::decode_base64url(plaintext).is_ok_and(|bytes| bytes == body.as_bytes())
    });
    assert!(found, "S30 bob read did not contain expected body {body}: {bob_read}");
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s30_rf_json_with_env(
    binary: &Path,
    env: &[(&str, &str)],
    args: &[&str],
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let binary = binary.to_path_buf();
    let args = args.iter().copied().map(str::to_owned).collect::<Vec<_>>();
    let env =
        env.iter().map(|(key, value)| ((*key).to_owned(), (*value).to_owned())).collect::<Vec<_>>();
    let command_line = format!("{} {}", binary.display(), args.join(" "));
    let output = tokio::time::timeout(
        Duration::from_mins(2),
        tokio::task::spawn_blocking(move || {
            let mut command = std::process::Command::new(binary);
            command.args(args).envs(env).output()
        }),
    )
    .await
    .map_err(|_elapsed| format!("rf command timed out: {command_line}"))???;
    mvp_s30_parse_rf_json_output(&command_line, &output)
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s30_rf_json_expect_failure(
    binary: &Path,
    args: &[&str],
) -> Result<(), Box<dyn std::error::Error>> {
    mvp_s30_rf_json_expect_failure_with_env(binary, &[], args).await
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s30_rf_json_expect_failure_with_env(
    binary: &Path,
    env: &[(&str, &str)],
    args: &[&str],
) -> Result<(), Box<dyn std::error::Error>> {
    let binary = binary.to_path_buf();
    let args = args.iter().copied().map(str::to_owned).collect::<Vec<_>>();
    let env =
        env.iter().map(|(key, value)| ((*key).to_owned(), (*value).to_owned())).collect::<Vec<_>>();
    let command_line = format!("{} {}", binary.display(), args.join(" "));
    let output = tokio::time::timeout(
        Duration::from_mins(2),
        tokio::task::spawn_blocking(move || {
            let mut command = std::process::Command::new(binary);
            command.args(args).envs(env).output()
        }),
    )
    .await
    .map_err(|_elapsed| format!("rf command timed out: {command_line}"))???;
    if output.status.success() {
        return Err(format!("rf command unexpectedly succeeded: {command_line}").into());
    }
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
fn mvp_s30_parse_rf_json_output(
    command_line: &str,
    output: &std::process::Output,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let status = output.status.code().map_or_else(|| "signal".to_owned(), |code| code.to_string());
    if !output.status.success() {
        return Err(format!(
            "rf command failed: command={command_line} status={status} stdout={stdout} stderr={stderr}"
        )
        .into());
    }
    if output.stdout.is_empty() {
        return Err(format!(
            "rf command produced empty stdout: command={command_line} status={status} stdout={stdout} stderr={stderr}"
        )
        .into());
    }
    serde_json::from_slice(&output.stdout).map_err(|error| {
        format!(
            "rf command produced invalid JSON: command={command_line} status={status} error={error} stdout={stdout} stderr={stderr}"
        )
        .into()
    })
}
