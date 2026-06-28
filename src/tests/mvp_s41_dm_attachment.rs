// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use super::*;
use ramflux_storage::VaultSecretSource;

#[cfg(feature = "realnet")]
#[test]
fn mvp_s41_realnet_dm_attachment_e2ee() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    let ports = S8ComposePorts {
        gateway_http: 64_191,
        gateway_quic: 64_461,
        router_http: 64_190,
        router_mesh: 64_462,
        notify_http: 64_193,
        federation_http: 64_192,
        federation_mesh: 64_463,
        relay_http: 64_194,
        relay_media_udp: 64_110,
        signaling_turn_udp: 64_488,
        signaling_turn_tcp: 64_489,
        retention_http: 64_197,
    };
    let relay_capture = "/tmp/ramflux-relay-itest-capture-s41.jsonl";
    let gateway_capture = "/tmp/ramflux-gateway-itest-capture-s41.jsonl";
    let node = start_s8_realnet_compose_project_with_env(
        "ramflux-s41-dm-attachment",
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
        Box::pin(mvp_s41_assert_dm_attachment(
            &node,
            &relay_url,
            relay_capture,
            gateway_capture,
            "ramflux-s41-dm-attachment",
        ))
        .await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    drop(node);
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
#[allow(clippy::too_many_lines)]
async fn mvp_s41_assert_dm_attachment(
    node: &S8RealnetNode,
    relay_url: &str,
    relay_capture: &str,
    gateway_capture: &str,
    compose_project: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let temp_root = temp_root("s41_dm_attachment")?;
    let alice_data = temp_root.join("alice/data");
    let bob_data = temp_root.join("bob/data");
    let charlie_data = temp_root.join("charlie/data");
    let alice_socket = temp_root.join("alice/rfd.sock");
    let bob_socket = temp_root.join("bob/rfd.sock");
    let charlie_socket = temp_root.join("charlie/rfd.sock");
    let filename_sentinel = "mvp_s41_secret_filename_do_not_leak";
    let plaintext_window = b"mvp_s41_attachment_plaintext_window_do_not_leak";
    let input_path = temp_root.join(filename_sentinel);
    let charlie_output = temp_root.join("charlie-output.bin");
    let plaintext = mvp_s41_attachment_plaintext(plaintext_window);
    std::fs::create_dir_all(&temp_root)?;
    std::fs::write(&input_path, &plaintext)?;

    let rf_binary = mvp_s4_build_rf_binary().await?;
    let gateway_addr = node.gateway_quic_addr.to_string();
    let ca_cert_arg = mvp_s4_path_arg(&node.ca_cert);
    let alice_socket_arg = mvp_s4_path_arg(&alice_socket);
    let bob_socket_arg = mvp_s4_path_arg(&bob_socket);
    let charlie_socket_arg = mvp_s4_path_arg(&charlie_socket);
    let input_arg = mvp_s4_path_arg(&input_path);
    let charlie_output_arg = mvp_s4_path_arg(&charlie_output);
    let service_key = "ramflux-relay-itest-service-key";
    let object_id = "attachment:msg_s41_attach:0";

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
                "alice_s41_account",
                "principal_s41_alice",
                "alice_device_s41",
                "target_s41_alice",
                &gateway_addr,
                &ca_cert_arg,
                "41",
                "42",
            )
            .await?;
            let bob_commitment = mvp_s10_create_rf_account(
                &rf_binary,
                &bob_socket_arg,
                "bob_s41_account",
                "principal_s41_bob",
                "bob_device_s41",
                "target_s41_bob",
                &gateway_addr,
                &ca_cert_arg,
                "43",
                "44",
            )
            .await?;
            let _charlie_commitment = mvp_s10_create_rf_account(
                &rf_binary,
                &charlie_socket_arg,
                "charlie_s41_account",
                "principal_s41_charlie",
                "charlie_device_s41",
                "target_s41_charlie",
                &gateway_addr,
                &ca_cert_arg,
                "45",
                "46",
            )
            .await?;
            mvp_s41_add_contact(
                &rf_binary,
                &alice_socket_arg,
                "alice_s41_account",
                "alice_to_bob_s41",
                &alice_commitment,
                &bob_commitment,
            )
            .await?;
            mvp_s41_add_contact(
                &rf_binary,
                &bob_socket_arg,
                "bob_s41_account",
                "bob_to_alice_s41",
                &bob_commitment,
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
                    "alice_s41_account",
                    "--conversation",
                    "conv_s41_attachment",
                    "--message",
                    "msg_s41_attach",
                    "--envelope",
                    "env_s41_attach",
                    "--source-principal",
                    "principal_s41_alice",
                    "--sender",
                    "alice_device_s41",
                    "--recipient-device",
                    "bob_device_s41",
                    "--target",
                    "target_s41_bob",
                    "--body",
                    "s41 attachment body",
                    "--attach",
                    &input_arg,
                    "--relay-url",
                    relay_url,
                    "--relay-service-key",
                    service_key,
                    "--attachment-chunk-size",
                    "1024",
                ],
            )
            .await?;
            assert_eq!(sent["envelope"]["envelope_id"], "env_s41_attach");

            let charlie_rejected = mvp_s41_rf_failure(
                &rf_binary,
                &[
                    "--socket",
                    &charlie_socket_arg,
                    "object",
                    "get",
                    "--account",
                    "charlie_s41_account",
                    "--object",
                    object_id,
                    "--relay-url",
                    relay_url,
                    "--relay-service-key",
                    service_key,
                    &charlie_output_arg,
                ],
                "wrong recipient object get",
            )
            .await?;
            assert!(
                charlie_rejected.contains("ObjectNotFound")
                    || charlie_rejected.contains("object not found"),
                "wrong recipient should fail closed without an object key: {charlie_rejected}"
            );

            let bob_read = mvp_s4_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &bob_socket_arg,
                    "dm",
                    "read",
                    "--account",
                    "bob_s41_account",
                    "--conversation",
                    "conv_s41_attachment",
                    "--relay-service-key",
                    service_key,
                ],
            )
            .await?;
            let decrypted = bob_read["decrypted_messages"]
                .as_array()
                .ok_or("missing S41 decrypted messages")?;
            assert_eq!(decrypted.len(), 1);
            assert_eq!(decrypted[0]["message_id"].as_str(), Some("env_s41_attach"));
            assert_eq!(
                decrypted[0]["plaintext_body_base64"].as_str(),
                Some(ramflux_protocol::encode_base64url(b"s41 attachment body").as_str())
            );
            let attachments =
                decrypted[0]["attachments"].as_array().ok_or("missing attachments")?;
            assert_eq!(attachments.len(), 1);
            assert_eq!(attachments[0]["object_id"].as_str(), Some(object_id));
            let attachment_plaintext = ramflux_protocol::decode_base64url(
                attachments[0]["plaintext_base64"]
                    .as_str()
                    .ok_or("missing attachment plaintext")?,
            )?;
            assert_eq!(attachment_plaintext, plaintext);

            let wrong_device_sent = mvp_s4_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &alice_socket_arg,
                    "dm",
                    "send",
                    "--account",
                    "alice_s41_account",
                    "--conversation",
                    "conv_s41_wrong_device",
                    "--message",
                    "msg_s41_wrong_device",
                    "--envelope",
                    "env_s41_wrong_device",
                    "--source-principal",
                    "principal_s41_alice",
                    "--sender",
                    "alice_device_s41",
                    "--recipient-device",
                    "bob_device_s41",
                    "--target",
                    "target_s41_charlie",
                    "--body",
                    "s41 wrong device body",
                    "--attach",
                    &input_arg,
                    "--relay-url",
                    relay_url,
                    "--relay-service-key",
                    service_key,
                    "--attachment-chunk-size",
                    "1024",
                ],
            )
            .await?;
            assert_eq!(
                wrong_device_sent["envelope"]["envelope_id"],
                "env_s41_wrong_device"
            );
            let charlie_wrong_device = mvp_s41_rf_failure(
                &rf_binary,
                &[
                    "--socket",
                    &charlie_socket_arg,
                    "dm",
                    "read",
                    "--account",
                    "charlie_s41_account",
                    "--conversation",
                    "conv_s41_wrong_device",
                    "--relay-service-key",
                    service_key,
                ],
                "wrong recipient device read",
            )
            .await?;
            assert!(
                charlie_wrong_device.contains("missing X3DH private state for bob_device_s41")
                    || charlie_wrong_device.contains("X3DH"),
                "wrong recipient device should fail closed before attachment key import: {charlie_wrong_device}"
            );

            let object_key =
                mvp_s41_object_key(&alice_data, "alice_s41_account", "rf-local-secret", object_id)?;
            mvp_s41_assert_opaque(
                compose_project,
                relay_capture,
                gateway_capture,
                plaintext_window,
                &object_key,
                filename_sentinel.as_bytes(),
            )?;
            let wrong_device_object_key = mvp_s41_object_key(
                &alice_data,
                "alice_s41_account",
                "rf-local-secret",
                "attachment:msg_s41_wrong_device:0",
            )?;
            mvp_s41_assert_opaque(
                compose_project,
                relay_capture,
                gateway_capture,
                plaintext_window,
                &wrong_device_object_key,
                filename_sentinel.as_bytes(),
            )?;
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
        .map_err(|_elapsed| "s41 local-bus flow timed out")?;
    flow_result?;
    alice_result?;
    bob_result?;
    charlie_result?;
    std::fs::remove_dir_all(&temp_root)?;
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s41_add_contact(
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
async fn mvp_s41_rf_failure(
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
fn mvp_s41_attachment_plaintext(window: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(9_000);
    for index in 0..180_u32 {
        bytes.extend_from_slice(b"s41-attachment-block:");
        bytes.extend_from_slice(index.to_string().as_bytes());
        bytes.extend_from_slice(b":");
        bytes.extend_from_slice(window);
        bytes.extend_from_slice(b":payload-padding\n");
    }
    bytes
}

#[cfg(all(test, feature = "realnet"))]
fn mvp_s41_object_key(
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
        &mvp_s41_account_db_key_encryption_key(&vault_secret, secret.as_bytes()),
        &wrapped,
    )?;
    let db = ramflux_storage::AccountDb::open(&index, account, &key)?;
    let (_objects, keys) = db.load_objects::<serde_json::Value>()?;
    keys.get(object_id).copied().ok_or_else(|| "missing object content key".into())
}

#[cfg(all(test, feature = "realnet"))]
fn mvp_s41_account_db_key_encryption_key(vault_secret: &[u8; 32], secret: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ramflux.account_db_kek.v2");
    hasher.update(vault_secret);
    hasher.update(secret);
    *hasher.finalize().as_bytes()
}

#[cfg(all(test, feature = "realnet"))]
fn mvp_s41_assert_opaque(
    compose_project: &str,
    relay_capture: &str,
    gateway_capture: &str,
    plaintext_window: &[u8],
    object_key: &[u8; 32],
    filename_sentinel: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let relay_redb = mvp_s41_service_file(
        compose_project,
        "ramflux-relay",
        "/var/lib/ramflux/relay/relay.redb",
    )?;
    mvp_s41_assert_not_contains(&relay_redb, plaintext_window, "relay redb leaked plaintext");
    mvp_s41_assert_not_contains(&relay_redb, object_key, "relay redb leaked object key");
    mvp_s41_assert_not_contains(&relay_redb, filename_sentinel, "relay redb leaked filename");
    let relay_json = mvp_s41_service_file(compose_project, "ramflux-relay", relay_capture)?;
    mvp_s41_assert_not_contains(&relay_json, plaintext_window, "relay JSON leaked plaintext");
    mvp_s41_assert_not_contains(&relay_json, object_key, "relay JSON leaked object key");
    mvp_s41_assert_not_contains(&relay_json, filename_sentinel, "relay JSON leaked filename");

    let gateway_redb = mvp_s41_service_file(
        compose_project,
        "ramflux-gateway",
        "/var/lib/ramflux/gateway/gateway.redb",
    )?;
    mvp_s41_assert_not_contains(&gateway_redb, plaintext_window, "gateway redb leaked plaintext");
    mvp_s41_assert_not_contains(&gateway_redb, object_key, "gateway redb leaked object key");
    mvp_s41_assert_not_contains(&gateway_redb, filename_sentinel, "gateway redb leaked filename");
    let gateway_json = mvp_s41_service_file(compose_project, "ramflux-gateway", gateway_capture)?;
    mvp_s41_assert_not_contains(&gateway_json, plaintext_window, "gateway JSON leaked plaintext");
    mvp_s41_assert_not_contains(&gateway_json, object_key, "gateway JSON leaked object key");
    mvp_s41_assert_not_contains(&gateway_json, filename_sentinel, "gateway JSON leaked filename");
    let object_key_base64url = ramflux_protocol::encode_base64url(object_key);
    assert!(
        !String::from_utf8_lossy(&relay_json).contains(&object_key_base64url),
        "relay JSON leaked base64url object key"
    );
    assert!(
        !String::from_utf8_lossy(&gateway_json).contains(&object_key_base64url),
        "gateway JSON leaked base64url object key"
    );
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
fn mvp_s41_assert_not_contains(bytes: &[u8], needle: &[u8], message: &str) {
    assert!(!contains_subslice(bytes, needle), "{message}");
}

#[cfg(all(test, feature = "realnet"))]
fn mvp_s41_service_file(
    compose_project: &str,
    service: &str,
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
        .arg(service)
        .arg("cat")
        .arg(path)
        .current_dir(code_root().join("ramflux-deploy"))
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "failed to read {service} file {path}: status={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(output.stdout)
}
