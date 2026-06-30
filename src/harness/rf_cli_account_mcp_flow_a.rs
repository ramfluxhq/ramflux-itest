// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use crate::*;
use std::io::Write;

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp_s3_account_create_request(
    config: &MvpS3FlowConfig,
    spec: MvpS3AccountSpec,
) -> ramflux_sdk::LocalBusAccountCreateRequest {
    ramflux_sdk::LocalBusAccountCreateRequest {
        local_account_id: spec.local_account_id.to_owned(),
        principal_id: spec.principal_id.to_owned(),
        principal_commitment: String::new(),
        device_id: spec.device_id.to_owned(),
        target_delivery_id: spec.target_delivery_id.to_owned(),
        account_secret: "s3-bus-secret".to_owned(),
        root_seed: spec.root_seed,
        device_seed: spec.device_seed,
        client_mode: ramflux_sdk::LocalBusClientMode::AttendedCli,
        gateway: ramflux_sdk::GatewayQuicEndpointConfig {
            bind_addr: std::net::SocketAddr::from(([0, 0, 0, 0], 0)),
            gateway_addr: config.gateway_quic_addr,
            server_name: "localhost".to_owned(),
            ca_cert: config.ca_cert.clone(),
            principal_id: spec.principal_id.to_owned(),
            device_id: spec.device_id.to_owned(),
            target_delivery_id: spec.target_delivery_id.to_owned(),
            prekey_http_url: None,
        },
    }
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp_s3_submit_request(
    encrypted_body: &[u8],
) -> ramflux_sdk::LocalBusMessageSubmitRequest {
    mvp_s3_submit_request_for("msg_s3_bus_1", "env_s3_bus_dm_1", "target_s3_bob", encrypted_body)
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp_s3_submit_request_for(
    message_id: &str,
    envelope_id: &str,
    target_delivery_id: &str,
    encrypted_body: &[u8],
) -> ramflux_sdk::LocalBusMessageSubmitRequest {
    let recipient_principal_commitment = match target_delivery_id {
        "target_s3_bob" => Some(ramflux_sdk::identity_root_public_key_commitment_for_seed(
            "principal_s3_bob",
            [0xB1; 32],
        )),
        "target_s3_carol_offline" => {
            Some(ramflux_sdk::identity_root_public_key_commitment_for_seed(
                "principal_s3_carol",
                [0xC1; 32],
            ))
        }
        _ => None,
    };
    ramflux_sdk::LocalBusMessageSubmitRequest {
        conversation_id: "conv_s3_bus".to_owned(),
        message_id: message_id.to_owned(),
        envelope_id: envelope_id.to_owned(),
        source_principal_id: "principal_s3_alice".to_owned(),
        sender_id: "alice_s3".to_owned(),
        recipient_device_id: None,
        recipient_principal_commitment,
        target_delivery_id: target_delivery_id.to_owned(),
        encrypted_body_base64: ramflux_protocol::encode_base64url(encrypted_body),
        plaintext_body_base64: None,
        created_at: itest_now_unix_seconds(),
        ttl: ITEST_REPLAY_TTL_SECONDS,
        attachments: Vec::new(),
        federation: None,
    }
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp_s3_entries_from_body(
    body: &serde_json::Value,
) -> Result<Vec<ramflux_sdk::GatewayInboxEntry>, Box<dyn std::error::Error>> {
    Ok(serde_json::from_value(
        body.get("entries").cloned().ok_or("missing entries in bus response")?,
    )?)
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s4_assert_rf_cli_flow(
    gateway_quic_addr: std::net::SocketAddr,
    ca_cert: &Path,
    gateway_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let temp_root = std::env::temp_dir().join(format!(
        "ramflux_s4_rf_{}_{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos()
    ));
    std::fs::create_dir_all(&temp_root)?;
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
    let client_flow = mvp_s4_run_rf_cli_flow(MvpS4RfFlowConfig {
        rf_binary,
        gateway_quic_addr,
        gateway_url: gateway_url.to_owned(),
        ca_cert: ca_cert.to_path_buf(),
        alice_socket,
        bob_socket,
        alice_shutdown_tx,
        bob_shutdown_tx,
    });

    let (alice_result, bob_result, flow_result) =
        tokio::join!(alice_server, bob_server, client_flow);
    alice_result?;
    bob_result?;
    flow_result?;
    std::fs::remove_dir_all(&temp_root)?;
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s6_assert_rf_mcp_flow(
    gateway_quic_addr: std::net::SocketAddr,
    ca_cert: &Path,
    gateway_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let temp_root = std::env::temp_dir().join(format!(
        "ramflux_s6_mcp_{}_{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos()
    ));
    std::fs::create_dir_all(&temp_root)?;
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
            mvp_s6_step("wait_for_socket alice before");
            mvp_s6_wait_for_socket_with_timeout("alice rfd.sock", &alice_socket).await?;
            mvp_s6_step("wait_for_socket alice after");
            mvp_s6_step("wait_for_socket bob before");
            mvp_s6_wait_for_socket_with_timeout("bob rfd.sock", &bob_socket).await?;
            mvp_s6_step("wait_for_socket bob after");
            let gateway_addr = gateway_quic_addr.to_string();
            let ca_cert_arg = mvp_s4_path_arg(ca_cert);
            let alice_socket_arg = mvp_s4_path_arg(&alice_socket);
            let bob_socket_arg = mvp_s4_path_arg(&bob_socket);
            mvp_s6_step("prologue accounts/contact before");
            mvp_s6_assert_rf_accounts_and_contact_instrumented(
                &rf_binary,
                &alice_socket_arg,
                &bob_socket_arg,
                &gateway_addr,
                gateway_url,
                &ca_cert_arg,
            )
            .await?;
            mvp_s6_step("prologue accounts/contact after");
            mvp_s4_assert_account_transport_quic(
                &rf_binary,
                &alice_socket_arg,
                "alice_s4_account",
                "S6 after prologue",
            )
            .await?;
            mvp_s4_assert_account_transport_quic(
                &rf_binary,
                &bob_socket_arg,
                "bob_s4_account",
                "S6 after prologue",
            )
            .await?;
            mvp_s6_step("mcp commands before");
            mvp_s6_assert_rf_mcp_commands(&rf_binary, &alice_socket_arg).await?;
            mvp_s6_step("mcp commands after");
            mvp_s4_assert_account_transport_quic(
                &rf_binary,
                &alice_socket_arg,
                "alice_s4_account",
                "S6 after MCP commands",
            )
            .await?;
            mvp_s4_assert_account_transport_quic(
                &rf_binary,
                &bob_socket_arg,
                "bob_s4_account",
                "S6 after MCP commands",
            )
            .await?;
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
pub(crate) fn mvp_s6_step(label: &str) {
    eprintln!("S6-STEP: {label}");
    let _ = std::io::stderr().flush();
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp_s6_timeout(label: &str) -> String {
    eprintln!("S6-TIMEOUT: {label}");
    let _ = std::io::stderr().flush();
    format!("timed out during S6 step: {label}")
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s6_wait_for_socket_with_timeout(
    label: &'static str,
    socket_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    tokio::time::timeout(Duration::from_secs(10), mvp_s4_wait_for_socket(socket_path))
        .await
        .map_err(|_elapsed| mvp_s6_timeout(label))??;
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s6_rf_json_with_timeout(
    label: &'static str,
    rf_binary: &Path,
    args: &[&str],
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    mvp_s6_step(&format!("{label} before"));
    let value = tokio::time::timeout(Duration::from_secs(30), mvp_s4_rf_json(rf_binary, args))
        .await
        .map_err(|_elapsed| mvp_s6_timeout(label))??;
    mvp_s6_step(&format!("{label} after"));
    Ok(value)
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) struct MvpS4RfFlowConfig {
    pub(crate) rf_binary: PathBuf,
    pub(crate) gateway_quic_addr: std::net::SocketAddr,
    pub(crate) gateway_url: String,
    pub(crate) ca_cert: PathBuf,
    pub(crate) alice_socket: PathBuf,
    pub(crate) bob_socket: PathBuf,
    pub(crate) alice_shutdown_tx: tokio::sync::watch::Sender<bool>,
    pub(crate) bob_shutdown_tx: tokio::sync::watch::Sender<bool>,
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s4_run_rf_cli_flow(
    config: MvpS4RfFlowConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    mvp_s4_wait_for_socket(&config.alice_socket).await?;
    mvp_s4_wait_for_socket(&config.bob_socket).await?;
    let gateway_addr = config.gateway_quic_addr.to_string();
    let gateway_url = config.gateway_url;
    let ca_cert = mvp_s4_path_arg(&config.ca_cert);
    let alice_socket = mvp_s4_path_arg(&config.alice_socket);
    let bob_socket = mvp_s4_path_arg(&config.bob_socket);

    let bob_commitment = mvp_s4_assert_rf_accounts_and_contact(
        &config.rf_binary,
        &alice_socket,
        &bob_socket,
        &gateway_addr,
        &gateway_url,
        &ca_cert,
    )
    .await?;
    mvp_s4_assert_rf_dm(&config.rf_binary, &alice_socket, &bob_socket, &bob_commitment).await?;
    mvp_s4_assert_account_transport_quic(
        &config.rf_binary,
        &alice_socket,
        "alice_s4_account",
        "after rf dm",
    )
    .await?;
    mvp_s4_assert_account_transport_quic(
        &config.rf_binary,
        &bob_socket,
        "bob_s4_account",
        "after rf dm",
    )
    .await?;
    mvp_s4_assert_rf_group(&config.rf_binary, &alice_socket).await?;
    mvp_s4_assert_account_transport_quic(
        &config.rf_binary,
        &alice_socket,
        "alice_s4_account",
        "after rf group",
    )
    .await?;
    mvp_s4_assert_account_transport_quic(
        &config.rf_binary,
        &bob_socket,
        "bob_s4_account",
        "after rf group",
    )
    .await?;

    config.alice_shutdown_tx.send(true)?;
    config.bob_shutdown_tx.send(true)?;
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
#[allow(clippy::too_many_lines)]
pub(crate) async fn mvp_s4_assert_rf_accounts_and_contact(
    rf_binary: &Path,
    alice_socket: &str,
    bob_socket: &str,
    gateway_addr: &str,
    gateway_url: &str,
    ca_cert: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let alice_created = mvp_s4_rf_json(
        rf_binary,
        &[
            "--socket",
            alice_socket,
            "account",
            "create",
            "--account",
            "alice_s4_account",
            "--principal",
            "principal_s4_alice",
            "--device",
            "alice_device_s4",
            "--target",
            "target_s4_alice",
            "--gateway-addr",
            gateway_addr,
            "--prekey-http-url",
            gateway_url,
            "--ca-cert",
            ca_cert,
            "--root-seed-byte-hex",
            "d1",
            "--device-seed-byte-hex",
            "d2",
            "--secret",
            "rf-local-secret",
            "--client-mode",
            "attended_cli",
        ],
    )
    .await?;
    assert_eq!(alice_created["local_account_id"], "alice_s4_account");
    mvp_s4_assert_create_response_transport_quic(
        &alice_created,
        "alice_s4_account",
        "create response",
    )?;

    let bob_created = mvp_s4_rf_json(
        rf_binary,
        &[
            "--socket",
            bob_socket,
            "account",
            "create",
            "--account",
            "bob_s4_account",
            "--principal",
            "principal_s4_bob",
            "--device",
            "bob_device_s4",
            "--target",
            "target_s4_bob",
            "--gateway-addr",
            gateway_addr,
            "--prekey-http-url",
            gateway_url,
            "--ca-cert",
            ca_cert,
            "--root-seed-byte-hex",
            "e1",
            "--device-seed-byte-hex",
            "e2",
            "--secret",
            "rf-local-secret",
            "--client-mode",
            "attended_cli",
        ],
    )
    .await?;
    assert_eq!(bob_created["target_delivery_id"], "target_s4_bob");
    mvp_s4_assert_create_response_transport_quic(
        &bob_created,
        "bob_s4_account",
        "create response",
    )?;
    let bob_commitment = bob_created["principal_commitment"]
        .as_str()
        .ok_or("missing bob_s4 principal_commitment")?
        .to_owned();

    let status = mvp_s4_rf_json(rf_binary, &["--socket", alice_socket, "daemon", "status"]).await?;
    assert_eq!(status["accounts"], 1);

    let contact = mvp_s4_rf_json(
        rf_binary,
        &[
            "--socket",
            alice_socket,
            "contact",
            "add",
            "--account",
            "alice_s4_account",
            "--link",
            "friend_link_s4_cli",
            "--requester",
            "principal_s4_alice",
            "--target",
            "principal_s4_bob",
        ],
    )
    .await?;
    assert_eq!(contact["state"], "accepted");
    mvp_s4_assert_account_transport_quic(
        rf_binary,
        alice_socket,
        "alice_s4_account",
        "after account/contact setup",
    )
    .await?;
    mvp_s4_assert_account_transport_quic(
        rf_binary,
        bob_socket,
        "bob_s4_account",
        "after account/contact setup",
    )
    .await?;
    Ok(bob_commitment)
}

#[cfg(all(test, feature = "realnet"))]
fn mvp_s4_assert_create_response_transport_quic(
    response: &serde_json::Value,
    account: &str,
    phase: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        response["active_transport_kind"].as_str(),
        Some(ramflux_sdk::GatewaySessionTransportKind::Quic.wire_name()),
        "S4 account {account} must create on QUIC {phase}, response={response}"
    );
    let session_id = response["session_id"]
        .as_str()
        .ok_or_else(|| format!("S4 account {account} missing session_id {phase}: {response}"))?;
    assert!(
        !session_id.is_empty(),
        "S4 account {account} has empty session_id {phase}: {response}"
    );
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s4_assert_account_transport_quic(
    rf_binary: &Path,
    socket: &str,
    account: &str,
    phase: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let status =
        mvp_s4_rf_json(rf_binary, &["--socket", socket, "account", "status", "--account", account])
            .await?;
    assert_eq!(
        status["active_transport_kind"].as_str(),
        Some(ramflux_sdk::GatewaySessionTransportKind::Quic.wire_name()),
        "S4 account {account} must stay on QUIC {phase}, status={status}"
    );
    let session_id = status["session_id"]
        .as_str()
        .ok_or_else(|| format!("S4 account {account} missing session_id {phase}: {status}"))?;
    assert!(!session_id.is_empty(), "S4 account {account} has empty session_id {phase}: {status}");
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
#[allow(clippy::too_many_lines)]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn mvp_s6_assert_rf_accounts_and_contact_instrumented(
    rf_binary: &Path,
    alice_socket: &str,
    bob_socket: &str,
    gateway_addr: &str,
    gateway_url: &str,
    ca_cert: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let alice_created = mvp_s6_rf_json_with_timeout(
        "rf account create alice",
        rf_binary,
        &[
            "--socket",
            alice_socket,
            "account",
            "create",
            "--account",
            "alice_s4_account",
            "--principal",
            "principal_s4_alice",
            "--device",
            "alice_device_s4",
            "--target",
            "target_s4_alice",
            "--gateway-addr",
            gateway_addr,
            "--prekey-http-url",
            gateway_url,
            "--ca-cert",
            ca_cert,
            "--root-seed-byte-hex",
            "d1",
            "--device-seed-byte-hex",
            "d2",
            "--secret",
            "rf-local-secret",
            "--client-mode",
            "attended_cli",
        ],
    )
    .await?;
    assert_eq!(alice_created["local_account_id"], "alice_s4_account");
    mvp_s4_assert_create_response_transport_quic(
        &alice_created,
        "alice_s4_account",
        "S6 create response",
    )?;

    let bob_created = mvp_s6_rf_json_with_timeout(
        "rf account create bob",
        rf_binary,
        &[
            "--socket",
            bob_socket,
            "account",
            "create",
            "--account",
            "bob_s4_account",
            "--principal",
            "principal_s4_bob",
            "--device",
            "bob_device_s4",
            "--target",
            "target_s4_bob",
            "--gateway-addr",
            gateway_addr,
            "--prekey-http-url",
            gateway_url,
            "--ca-cert",
            ca_cert,
            "--root-seed-byte-hex",
            "e1",
            "--device-seed-byte-hex",
            "e2",
            "--secret",
            "rf-local-secret",
            "--client-mode",
            "attended_cli",
        ],
    )
    .await?;
    assert_eq!(bob_created["target_delivery_id"], "target_s4_bob");
    mvp_s4_assert_create_response_transport_quic(
        &bob_created,
        "bob_s4_account",
        "S6 create response",
    )?;

    let status = mvp_s6_rf_json_with_timeout(
        "rf daemon status alice",
        rf_binary,
        &["--socket", alice_socket, "daemon", "status"],
    )
    .await?;
    assert_eq!(status["accounts"], 1);

    let contact = mvp_s6_rf_json_with_timeout(
        "rf contact add alice-to-bob",
        rf_binary,
        &[
            "--socket",
            alice_socket,
            "contact",
            "add",
            "--account",
            "alice_s4_account",
            "--link",
            "friend_link_s4_cli",
            "--requester",
            "principal_s4_alice",
            "--target",
            "principal_s4_bob",
        ],
    )
    .await?;
    assert_eq!(contact["state"], "accepted");
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s4_assert_rf_dm(
    rf_binary: &Path,
    alice_socket: &str,
    bob_socket: &str,
    bob_commitment: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    mvp_s4_assert_rf_dm_x3dh_first_message(rf_binary, alice_socket, bob_socket, bob_commitment)
        .await?;
    mvp_s4_assert_rf_dm_ratchet_second_message(rf_binary, alice_socket, bob_socket, bob_commitment)
        .await
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s4_assert_rf_dm_x3dh_first_message(
    rf_binary: &Path,
    alice_socket: &str,
    bob_socket: &str,
    bob_commitment: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let submitted = mvp_s4_rf_json(
        rf_binary,
        &[
            "--socket",
            alice_socket,
            "dm",
            "send",
            "--account",
            "alice_s4_account",
            "--conversation",
            "conv_s4_cli",
            "--message",
            "msg_s4_cli_1",
            "--envelope",
            "env_s4_cli_dm_1",
            "--source-principal",
            "principal_s4_alice",
            "--sender",
            "alice_s4",
            "--recipient-principal-commitment",
            bob_commitment,
            "--recipient-device",
            "bob_device_s4",
            "--target",
            "target_s4_bob",
            "--body",
            "s4 rf cli dm plaintext",
        ],
    )
    .await?;
    assert_eq!(submitted["envelope"]["envelope_id"], "env_s4_cli_dm_1");
    assert_node_opaque_payload(
        submitted["envelope"]["encrypted_payload"]
            .as_str()
            .ok_or("missing S4 encrypted payload")?,
        b"s4 rf cli dm plaintext",
    );
    assert_x3dh_payload_not_conversation_seed_decryptable(
        submitted["envelope"]["encrypted_payload"]
            .as_str()
            .ok_or("missing S4 encrypted payload")?,
        "conv_s4_cli",
        "env_s4_cli_dm_1",
        "alice_device_s4",
        b"s4 rf cli dm plaintext",
        true,
    )?;
    mvp_s4_assert_dm_used_gateway_prekey(
        submitted["envelope"]["encrypted_payload"]
            .as_str()
            .ok_or("missing S4 encrypted payload")?,
        "bob_device_s4",
        "bob_device_s4:signed:1",
    )?;

    let bob_read = mvp_s4_rf_json(
        rf_binary,
        &[
            "--socket",
            bob_socket,
            "dm",
            "read",
            "--account",
            "bob_s4_account",
            "--conversation",
            "conv_s4_cli",
        ],
    )
    .await?;
    let entries = bob_read["gateway_entries"].as_array().ok_or("missing S4 gateway entries")?;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["envelope"]["envelope_id"], "env_s4_cli_dm_1");
    assert_node_opaque_payload(
        entries[0]["envelope"]["encrypted_payload"]
            .as_str()
            .ok_or("missing S4 received encrypted payload")?,
        b"s4 rf cli dm plaintext",
    );
    let decrypted =
        bob_read["decrypted_messages"].as_array().ok_or("missing S4 decrypted messages")?;
    assert_eq!(decrypted.len(), 1);
    let plaintext = ramflux_protocol::decode_base64url(
        decrypted[0]["plaintext_body_base64"].as_str().ok_or("missing S4 plaintext body")?,
    )?;
    assert_eq!(plaintext, b"s4 rf cli dm plaintext");
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
fn mvp_s4_assert_dm_used_gateway_prekey(
    encrypted_payload: &str,
    recipient_device_id: &str,
    signed_prekey_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let envelope_bytes = ramflux_protocol::decode_base64url(encrypted_payload)?;
    let envelope: serde_json::Value = serde_json::from_slice(&envelope_bytes)?;
    assert_eq!(envelope["schema"].as_str(), Some("ramflux.sdk.dm_x3dh_envelope.v1"));
    let x3dh = envelope["x3dh"].as_object().ok_or("missing S4 X3DH header")?;
    assert_eq!(
        x3dh.get("recipient_device_id").and_then(serde_json::Value::as_str),
        Some(recipient_device_id)
    );
    assert_eq!(
        x3dh.get("recipient_signed_prekey_id").and_then(serde_json::Value::as_str),
        Some(signed_prekey_id)
    );
    Ok(())
}
