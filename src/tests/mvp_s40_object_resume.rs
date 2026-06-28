// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use super::*;
use ramflux_storage::VaultSecretSource;

#[cfg(feature = "realnet")]
#[test]
fn mvp_s40_realnet_object_resume_status() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    let ports = S8ComposePorts {
        gateway_http: 64_181,
        gateway_quic: 64_451,
        router_http: 64_180,
        router_mesh: 64_452,
        notify_http: 64_183,
        federation_http: 64_182,
        federation_mesh: 64_453,
        relay_http: 64_184,
        relay_media_udp: 64_100,
        signaling_turn_udp: 64_478,
        signaling_turn_tcp: 64_479,
        retention_http: 64_187,
    };
    let capture_path = "/tmp/ramflux-relay-itest-capture.jsonl";
    let node = start_s8_realnet_compose_project_with_env(
        "ramflux-s40-object-resume",
        ports,
        &[("RAMFLUX_RELAY_ITEST_CAPTURE_JSON".to_owned(), capture_path.to_owned())],
    )?;
    let relay_url = format!("http://127.0.0.1:{}", ports.relay_http);
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async {
        wait_for_private_gateway_quic(node.gateway_quic_addr, &node.ca_cert).await?;
        Box::pin(mvp_s40_assert_object_resume_status(
            &node,
            &relay_url,
            capture_path,
            "ramflux-s40-object-resume",
        ))
        .await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    drop(node);
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
#[allow(clippy::too_many_lines)]
async fn mvp_s40_assert_object_resume_status(
    node: &S8RealnetNode,
    relay_url: &str,
    capture_path: &str,
    compose_project: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let temp_root = temp_root("s40_object_resume")?;
    let data_root = temp_root.join("alice/data");
    let socket = temp_root.join("alice/rfd.sock");
    let input_path = temp_root.join("object-input.bin");
    let output_path = temp_root.join("object-output.bin");
    let rf_binary = mvp_s4_build_rf_binary().await?;
    let plaintext_window = b"mvp_s40_plaintext_window_do_not_leak";
    let plaintext = mvp_s40_large_plaintext(plaintext_window);
    std::fs::create_dir_all(&temp_root)?;
    std::fs::write(&input_path, &plaintext)?;

    let gateway_addr = node.gateway_quic_addr.to_string();
    let ca_cert_arg = mvp_s4_path_arg(&node.ca_cert);
    let socket_arg = mvp_s4_path_arg(&socket);
    let input_arg = mvp_s4_path_arg(&input_path);
    let output_arg = mvp_s4_path_arg(&output_path);
    let service_key = "ramflux-relay-itest-service-key";

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let server = ramflux_sdk::serve_local_bus_until(
        ramflux_sdk::LocalBusConfig::new(&socket, &data_root),
        shutdown_rx,
    );
    let first_run = async {
        let result = async {
            mvp_s4_wait_for_socket(&socket).await?;
            mvp_s10_create_rf_account(
                &rf_binary,
                &socket_arg,
                "alice_s40_account",
                "principal_s40_alice",
                "alice_device_s40",
                "target_s40_alice",
                &gateway_addr,
                &ca_cert_arg,
                "a0",
                "a1",
            )
            .await?;
            let failed_put = mvp_s40_rf_failure(
                &rf_binary,
                &[
                    "--socket",
                    &socket_arg,
                    "object",
                    "put",
                    "--account",
                    "alice_s40_account",
                    "--object",
                    "object_s40_resume",
                    "--chunk-size",
                    "1024",
                    "--relay-url",
                    relay_url,
                    "--relay-service-key",
                    service_key,
                    "--relay-interrupt-after-chunks",
                    "2",
                    &input_arg,
                ],
                "interrupted object.put",
            )
            .await?;
            assert!(
                failed_put.contains("object relay upload interrupted"),
                "unexpected interrupted put error: {failed_put}"
            );
            let status = mvp_s40_object_status(&rf_binary, &socket_arg, "upload").await?;
            assert_eq!(status["transfer"]["state"], "paused");
            assert_eq!(status["transfer"]["completed_chunks"], 2);
            assert_eq!(status["transfer"]["next_chunk_index"], 2);
            Ok::<(), Box<dyn std::error::Error>>(())
        }
        .await;
        let _ = shutdown_tx.send(true);
        result
    };
    let (server_result, flow_result) =
        tokio::time::timeout(Duration::from_mins(4), async { tokio::join!(server, first_run) })
            .await
            .map_err(|_elapsed| "s40 first local-bus run timed out")?;
    flow_result?;
    server_result?;

    let (restart_tx, restart_rx) = tokio::sync::watch::channel(false);
    let restarted = ramflux_sdk::serve_local_bus_until(
        ramflux_sdk::LocalBusConfig::new(&socket, &data_root),
        restart_rx,
    );
    let resumed_flow = async {
        let result = async {
            mvp_s4_wait_for_socket(&socket).await?;
            let durable = mvp_s40_object_status(&rf_binary, &socket_arg, "upload").await?;
            assert_eq!(durable["transfer"]["state"], "paused");
            assert_eq!(durable["transfer"]["completed_chunks"], 2);
            let resumed = mvp_s4_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &socket_arg,
                    "object",
                    "resume",
                    "--account",
                    "alice_s40_account",
                    "--object",
                    "object_s40_resume",
                    "--direction",
                    "upload",
                    "--relay-url",
                    relay_url,
                    "--relay-service-key",
                    service_key,
                ],
            )
            .await?;
            assert_eq!(resumed["transfer"]["state"], "complete");
            let complete = mvp_s40_object_status(&rf_binary, &socket_arg, "upload").await?;
            assert_eq!(complete["transfer"]["state"], "complete");
            assert_eq!(
                complete["transfer"]["done_bytes"].as_u64(),
                complete["transfer"]["total_bytes"].as_u64()
            );
            let key = mvp_s40_object_key(
                &data_root,
                "alice_s40_account",
                "rf-local-secret",
                "object_s40_resume",
            )?;
            mvp_s40_assert_relay_fail_closed_on_tampered_chunk(
                relay_url,
                capture_path,
                compose_project,
            )?;
            mvp_s4_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &socket_arg,
                    "object",
                    "get",
                    "--account",
                    "alice_s40_account",
                    "--object",
                    "object_s40_resume",
                    "--relay-url",
                    relay_url,
                    "--relay-service-key",
                    service_key,
                    "--relay-ack",
                    &output_arg,
                ],
            )
            .await?;
            assert_eq!(std::fs::read(&output_path)?, plaintext);
            let download = mvp_s40_object_status(&rf_binary, &socket_arg, "download").await?;
            assert_eq!(download["transfer"]["state"], "complete");
            mvp_s40_assert_relay_opaque(compose_project, capture_path, plaintext_window, &key)?;
            Ok::<(), Box<dyn std::error::Error>>(())
        }
        .await;
        let _ = restart_tx.send(true);
        result
    };
    let (server_result, flow_result) = tokio::time::timeout(Duration::from_mins(4), async {
        tokio::join!(restarted, resumed_flow)
    })
    .await
    .map_err(|_elapsed| "s40 restarted local-bus run timed out")?;
    flow_result?;
    server_result?;
    std::fs::remove_dir_all(&temp_root)?;
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s40_object_status(
    rf_binary: &Path,
    socket_arg: &str,
    direction: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    mvp_s4_rf_json(
        rf_binary,
        &[
            "--socket",
            socket_arg,
            "object",
            "status",
            "--account",
            "alice_s40_account",
            "--object",
            "object_s40_resume",
            "--direction",
            direction,
        ],
    )
    .await
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s40_rf_failure(
    binary: &Path,
    args: &[&str],
    step: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let output = tokio::process::Command::new(binary)
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .output()
        .await?;
    if output.status.success() {
        return Err(format!("{step} unexpectedly succeeded").into());
    }
    Ok(format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ))
}

#[cfg(all(test, feature = "realnet"))]
fn mvp_s40_large_plaintext(window: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(9_000);
    for index in 0..180_u32 {
        bytes.extend_from_slice(b"s40-object-block:");
        bytes.extend_from_slice(index.to_string().as_bytes());
        bytes.extend_from_slice(b":");
        bytes.extend_from_slice(window);
        bytes.extend_from_slice(b":payload-padding\n");
    }
    bytes
}

#[cfg(all(test, feature = "realnet"))]
fn mvp_s40_object_key(
    data_root: &Path,
    account: &str,
    secret: &str,
    object_id: &str,
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let index = ramflux_storage::AccountIndex::open(data_root)?;
    let vault_secret =
        ramflux_storage::FileVaultSecretSource::new(index.root()).vault_secret(account)?;
    let wrapped = index.load_wrapped_db_key(account)?.ok_or("missing wrapped db key")?;
    let key = ramflux_storage::unwrap_with_vault_secret(
        &mvp_s40_account_db_key_encryption_key(&vault_secret, secret.as_bytes()),
        &wrapped,
    )?;
    let db = ramflux_storage::AccountDb::open(&index, account, &key)?;
    let (_objects, keys) = db.load_objects::<serde_json::Value>()?;
    keys.get(object_id).copied().ok_or_else(|| "missing object content key".into())
}

#[cfg(all(test, feature = "realnet"))]
fn mvp_s40_account_db_key_encryption_key(vault_secret: &[u8; 32], secret: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ramflux.account_db_kek.v2");
    hasher.update(vault_secret);
    hasher.update(secret);
    *hasher.finalize().as_bytes()
}

#[cfg(all(test, feature = "realnet"))]
fn mvp_s40_assert_relay_fail_closed_on_tampered_chunk(
    relay_url: &str,
    capture_path: &str,
    compose_project: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let capture = mvp_s40_relay_file(compose_project, capture_path)?;
    let first_put = String::from_utf8(capture)?
        .lines()
        .find(|line| line.contains("\"/relay/v1/object/put_chunk\""))
        .ok_or("missing captured put_chunk request")?
        .to_owned();
    let record: serde_json::Value = serde_json::from_str(&first_put)?;
    let request_body =
        record["request_body_base64url"].as_str().ok_or("missing captured request body")?;
    let mut frame: serde_json::Value =
        serde_json::from_slice(&ramflux_protocol::decode_base64url(request_body)?)?;
    frame["chunk_cipher_hash"] = serde_json::Value::String("tampered-s40-hash".to_owned());
    let rejected = ramflux_node_core::itest_http_post_json::<serde_json::Value, serde_json::Value>(
        &format!("{relay_url}/relay/v1/object/put_chunk"),
        &frame,
    );
    let Err(error) = rejected else {
        return Err("tampered chunk frame should fail closed".into());
    };
    let error = error.to_string();
    assert!(error.contains("object relay chunk hash mismatch"), "unexpected tamper error: {error}");
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
fn mvp_s40_assert_relay_opaque(
    compose_project: &str,
    capture_path: &str,
    plaintext_window: &[u8],
    object_key: &[u8; 32],
) -> Result<(), Box<dyn std::error::Error>> {
    let redb = mvp_s40_relay_file(compose_project, "/var/lib/ramflux/relay/relay.redb")?;
    assert!(
        !contains_subslice(&redb, plaintext_window),
        "relay redb leaked object plaintext window"
    );
    assert!(!contains_subslice(&redb, object_key), "relay redb leaked object key bytes");
    let capture = mvp_s40_relay_file(compose_project, capture_path)?;
    assert!(
        !contains_subslice(&capture, plaintext_window),
        "relay request/response JSON leaked object plaintext window"
    );
    assert!(
        !contains_subslice(&capture, object_key),
        "relay request/response JSON leaked object key bytes"
    );
    let key_base64url = ramflux_protocol::encode_base64url(object_key);
    assert!(
        !String::from_utf8_lossy(&capture).contains(&key_base64url),
        "relay request/response JSON leaked base64url object key"
    );
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
fn mvp_s40_relay_file(
    compose_project: &str,
    path: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let output = std::process::Command::new("docker")
        .arg("compose")
        .arg("-p")
        .arg(compose_project)
        .arg("-f")
        .arg("docker-compose.itest.yml")
        .arg("exec")
        .arg("-T")
        .arg("ramflux-relay")
        .arg("cat")
        .arg(path)
        .current_dir(code_root().join("ramflux/deploy"))
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "failed to read relay file {path}: status={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(output.stdout)
}
