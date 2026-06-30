// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use crate::*;

#[cfg(all(test, feature = "realnet"))]
#[allow(clippy::too_many_lines)]
pub(crate) async fn mvp_s4_assert_rf_cli_second_x3dh_bootstrap(
    gateway_quic_addr: std::net::SocketAddr,
    ca_cert: &Path,
    gateway_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let temp_root = temp_root("s4b_second_x3dh_bootstrap")?;
    let rf_binary = mvp_s4_build_rf_binary().await?;
    let alice_socket = temp_root.join("alice/rfd.sock");
    let bob_socket = temp_root.join("bob/rfd.sock");
    let alice_data = temp_root.join("alice/data");
    let bob_data = temp_root.join("bob/data");
    let (alice_shutdown_tx, alice_shutdown_rx) = tokio::sync::watch::channel(false);
    let (bob_shutdown_tx, bob_shutdown_rx) = tokio::sync::watch::channel(false);
    let alice_config = ramflux_sdk::LocalBusConfig::new(&alice_socket, alice_data.clone());
    let bob_config = ramflux_sdk::LocalBusConfig::new(&bob_socket, bob_data.clone());

    let alice_server = ramflux_sdk::serve_local_bus_until(alice_config, alice_shutdown_rx);
    let bob_server = ramflux_sdk::serve_local_bus_until(bob_config, bob_shutdown_rx);
    let client_flow = async move {
        let _alice_shutdown_tx = alice_shutdown_tx;
        let _bob_shutdown_tx = bob_shutdown_tx;
        mvp_s4_wait_for_socket(&alice_socket).await?;
        mvp_s4_wait_for_socket(&bob_socket).await?;
        let gateway_addr = gateway_quic_addr.to_string();
        let ca_cert = mvp_s4_path_arg(ca_cert);
        let alice_socket = mvp_s4_path_arg(&alice_socket);
        let bob_socket = mvp_s4_path_arg(&bob_socket);

        let bob_commitment = mvp_s4_assert_rf_accounts_and_contact(
            &rf_binary,
            &alice_socket,
            &bob_socket,
            &gateway_addr,
            gateway_url,
            &ca_cert,
        )
        .await?;

        let first_header = mvp_s4_send_and_read_bootstrap_dm(
            &rf_binary,
            &alice_socket,
            &bob_socket,
            &bob_commitment,
            "msg_s4b_x3dh_1",
            "env_s4b_x3dh_1",
            "s4b first x3dh bootstrap plaintext",
            "first bootstrap",
        )
        .await?;
        mvp_s4_assert_account_transport_quic(
            &rf_binary,
            &alice_socket,
            "alice_s4_account",
            "S4B after first X3DH bootstrap",
        )
        .await?;
        mvp_s4_assert_account_transport_quic(
            &rf_binary,
            &bob_socket,
            "bob_s4_account",
            "S4B after first X3DH bootstrap",
        )
        .await?;

        mvp_s4_force_dm_session_rebootstrap(
            &alice_data,
            "alice_s4_account",
            "conv_s4_cli",
            "send",
        )?;
        mvp_s4_force_dm_session_rebootstrap(&bob_data, "bob_s4_account", "conv_s4_cli", "recv")?;

        let second_header = mvp_s4_send_and_read_bootstrap_dm(
            &rf_binary,
            &alice_socket,
            &bob_socket,
            &bob_commitment,
            "msg_s4b_x3dh_2",
            "env_s4b_x3dh_2",
            "s4b second x3dh bootstrap plaintext",
            "second bootstrap",
        )
        .await?;
        assert_ne!(
            second_header["session_id"], first_header["session_id"],
            "S4B second bootstrap reused the first X3DH session_id"
        );
        assert_ne!(
            second_header["initiator_ephemeral_public"], first_header["initiator_ephemeral_public"],
            "S4B second bootstrap reused the first X3DH ephemeral public key"
        );
        mvp_s4_assert_account_transport_quic(
            &rf_binary,
            &alice_socket,
            "alice_s4_account",
            "S4B after second X3DH bootstrap",
        )
        .await?;
        mvp_s4_assert_account_transport_quic(
            &rf_binary,
            &bob_socket,
            "bob_s4_account",
            "S4B after second X3DH bootstrap",
        )
        .await
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
#[allow(clippy::too_many_arguments)]
async fn mvp_s4_send_and_read_bootstrap_dm(
    rf_binary: &Path,
    alice_socket: &str,
    bob_socket: &str,
    bob_commitment: &str,
    message_id: &str,
    envelope_id: &str,
    plaintext: &str,
    phase: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
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
            message_id,
            "--envelope",
            envelope_id,
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
            plaintext,
        ],
    )
    .await?;
    assert_eq!(submitted["envelope"]["envelope_id"], envelope_id);
    let encrypted_payload = submitted["envelope"]["encrypted_payload"]
        .as_str()
        .ok_or_else(|| format!("missing S4B encrypted payload for {phase}"))?;
    assert_x3dh_payload_not_conversation_seed_decryptable(
        encrypted_payload,
        "conv_s4_cli",
        envelope_id,
        "alice_device_s4",
        plaintext.as_bytes(),
        true,
    )?;
    let header = mvp_s4_x3dh_header(encrypted_payload)?;

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
    let decrypted = bob_read["decrypted_messages"]
        .as_array()
        .ok_or_else(|| format!("missing S4B decrypted messages for {phase}"))?;
    assert_eq!(decrypted.len(), 1, "unexpected S4B decrypted count for {phase}");
    assert_eq!(decrypted[0]["message_id"].as_str(), Some(envelope_id));
    let body = ramflux_protocol::decode_base64url(
        decrypted[0]["plaintext_body_base64"]
            .as_str()
            .ok_or_else(|| format!("missing S4B plaintext body for {phase}"))?,
    )?;
    assert_eq!(body, plaintext.as_bytes(), "unexpected S4B plaintext for {phase}");
    Ok(header)
}

#[cfg(all(test, feature = "realnet"))]
fn mvp_s4_force_dm_session_rebootstrap(
    data_root: &Path,
    account: &str,
    conversation_id: &str,
    direction: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = ramflux_sdk::RamfluxClient::new();
    client.open_account_index(data_root)?;
    client.set_active_account(account)?;
    client.unlock_account(account, b"rf-local-secret")?;
    client.set_projection_checkpoint(
        &format!("dm_session:{conversation_id}:{direction}"),
        &format!("missing_dm_session:{conversation_id}:{direction}:s4b"),
    )?;
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
fn mvp_s4_x3dh_header(
    encrypted_payload: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let payload = ramflux_protocol::decode_base64url(encrypted_payload)?;
    let envelope: serde_json::Value = serde_json::from_slice(&payload)?;
    Ok(envelope["x3dh"].as_object().ok_or("missing S4B X3DH header")?.clone().into())
}

#[cfg(all(test, feature = "realnet"))]
#[allow(clippy::too_many_lines)]
pub(crate) async fn mvp_s6_assert_mcp_grant_persistence_after_daemon_restart(
    gateway_quic_addr: std::net::SocketAddr,
    ca_cert: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    const ACCOUNT: &str = "alice_s6_persist_account";
    const SERVER_ID: &str = "srv_s6_persist";
    const TOOL_NAME: &str = "notes";
    let temp_root = temp_root("s6_mcp_grant_persist")?;
    let rf_binary = mvp_s4_build_rf_binary().await?;
    let alice_socket = temp_root.join("alice/rfd.sock");
    let alice_data = temp_root.join("alice/data");
    let alice_socket_arg = mvp_s4_path_arg(&alice_socket);
    let alice_data_arg = mvp_s4_path_arg(&alice_data);
    let ca_cert_arg = mvp_s4_path_arg(ca_cert);
    let gateway_addr = gateway_quic_addr.to_string();
    let mut alice_daemon = mvp_s20_spawn_rf_daemon(&rf_binary, &alice_socket_arg, &alice_data_arg)?;
    let flow = async {
        mvp_s6_step("mcp persist wait_for_socket before");
        mvp_s6_wait_for_socket_with_timeout("alice s6 persist rfd.sock", &alice_socket).await?;
        mvp_s6_step("mcp persist wait_for_socket after");
        mvp_s10_create_rf_account(
            &rf_binary,
            &alice_socket_arg,
            ACCOUNT,
            "principal_s6_persist_alice",
            "alice_device_s6_persist",
            "target_s6_persist_alice",
            &gateway_addr,
            &ca_cert_arg,
            "a6",
            "b6",
        )
        .await?;
        mvp_s4_assert_account_transport_quic(
            &rf_binary,
            &alice_socket_arg,
            ACCOUNT,
            "S6 persistence after create",
        )
        .await?;
        let mut bus = ramflux_sdk::LocalBusClient::connect(&alice_socket_arg).await?;
        mvp_s6_bus_request_with_timeout(
            "mcp persist attended subscription",
            bus.request(
                Some(ACCOUNT.to_owned()),
                "subscription",
                "subscription.open",
                &serde_json::json!({
                    "topics": ["mcp.approval.request"],
                    "attended_frontend": true,
                }),
            ),
        )
        .await?;
        let added = mvp_s6_bus_request_with_timeout(
            "mcp persist add low-risk tool",
            bus.request(
                Some(ACCOUNT.to_owned()),
                "mcp",
                "mcp.server.add",
                &serde_json::json!({
                    "server_id": SERVER_ID,
                    "command": "stdio-notes",
                    "tool_name": TOOL_NAME,
                    "capability": "read_conversation",
                    "tool_scope": "notes",
                    "risk_level": "low",
                }),
            ),
        )
        .await?;
        let registry_hash =
            added["registry_hash"].as_str().ok_or("missing pre-restart registry_hash")?.to_owned();
        let tool_manifest_set_hash = added["tool_manifest_set_hash"]
            .as_str()
            .ok_or("missing pre-restart tool_manifest_set_hash")?
            .to_owned();
        let first_call = mvp_s6_bus_request_with_timeout(
            "mcp persist first tool call",
            bus.request(
                Some(ACCOUNT.to_owned()),
                "mcp",
                "mcp.tool.started",
                &serde_json::json!({
                    "server_id": SERVER_ID,
                    "tool_name": TOOL_NAME,
                    "arguments": {"text": "before restart"},
                    "operation_origin": "ai_mcp",
                }),
            ),
        )
        .await?;
        assert_eq!(first_call["status"], "approval_required");
        assert_eq!(first_call["approval"]["confirmation_mode"], "attended_local");
        let approval_id =
            first_call["approval"]["approval_id"].as_str().ok_or("missing approval id")?;
        let grant = mvp_s6_bus_request_with_timeout(
            "mcp persist approve grant",
            bus.request(
                Some(ACCOUNT.to_owned()),
                "grant",
                "grant.approve",
                &serde_json::json!({ "approval_id": approval_id }),
            ),
        )
        .await?;
        assert_eq!(grant["state"]["revoked"], false);
        mvp_s4_assert_account_transport_quic(
            &rf_binary,
            &alice_socket_arg,
            ACCOUNT,
            "S6 persistence before restart",
        )
        .await?;
        drop(bus);

        mvp_s20_stop_rf_daemon(&mut alice_daemon).await?;
        alice_daemon = mvp_s20_spawn_rf_daemon(&rf_binary, &alice_socket_arg, &alice_data_arg)?;
        let status = mvp_s20_wait_for_daemon_status(&rf_binary, &alice_socket_arg).await?;
        assert!(status["accounts"].as_u64().unwrap_or_default() >= 1);
        mvp_s4_assert_account_transport_quic(
            &rf_binary,
            &alice_socket_arg,
            ACCOUNT,
            "S6 persistence after daemon restart",
        )
        .await?;
        let mut restarted_bus = ramflux_sdk::LocalBusClient::connect(&alice_socket_arg).await?;
        let tools = mvp_s6_bus_request_with_timeout(
            "mcp persist tool list after restart",
            restarted_bus.request(
                Some(ACCOUNT.to_owned()),
                "mcp",
                "mcp.tool.list",
                &serde_json::json!({}),
            ),
        )
        .await?;
        assert_eq!(tools["registry_hash"].as_str(), Some(registry_hash.as_str()));
        assert_eq!(tools["tool_manifest_set_hash"].as_str(), Some(tool_manifest_set_hash.as_str()));
        let second_call = mvp_s6_bus_request_with_timeout(
            "mcp persist authorized tool call after restart",
            restarted_bus.request(
                Some(ACCOUNT.to_owned()),
                "mcp",
                "mcp.tool.started",
                &serde_json::json!({
                    "server_id": SERVER_ID,
                    "tool_name": TOOL_NAME,
                    "arguments": {"text": "after restart"},
                    "operation_origin": "ai_mcp",
                }),
            ),
        )
        .await?;
        assert_eq!(second_call["status"], "ok");
        assert_eq!(second_call["result"], format!("{SERVER_ID}:{TOOL_NAME}"));
        mvp_s4_assert_account_transport_quic(
            &rf_binary,
            &alice_socket_arg,
            ACCOUNT,
            "S6 persistence after authorized restart call",
        )
        .await?;
        let grant_id = grant["grant_id"].as_str().ok_or("missing persisted grant_id")?;
        let revoked = mvp_s6_bus_request_with_timeout(
            "mcp persist revoke grant after restart",
            restarted_bus.request(
                Some(ACCOUNT.to_owned()),
                "grant",
                "grant.revoke",
                &serde_json::json!({ "grant_id": grant_id }),
            ),
        )
        .await?;
        assert_eq!(revoked["state"]["revoked"], true);
        drop(restarted_bus);

        mvp_s20_stop_rf_daemon(&mut alice_daemon).await?;
        alice_daemon = mvp_s20_spawn_rf_daemon(&rf_binary, &alice_socket_arg, &alice_data_arg)?;
        let revoked_status = mvp_s20_wait_for_daemon_status(&rf_binary, &alice_socket_arg).await?;
        assert!(revoked_status["accounts"].as_u64().unwrap_or_default() >= 1);
        mvp_s4_assert_account_transport_quic(
            &rf_binary,
            &alice_socket_arg,
            ACCOUNT,
            "S6 persistence after revoked restart",
        )
        .await?;
        let mut revoked_bus = ramflux_sdk::LocalBusClient::connect(&alice_socket_arg).await?;
        let revoked_call = tokio::time::timeout(
            Duration::from_secs(10),
            revoked_bus.request(
                Some(ACCOUNT.to_owned()),
                "mcp",
                "mcp.tool.started",
                &serde_json::json!({
                    "server_id": SERVER_ID,
                    "tool_name": TOOL_NAME,
                    "arguments": {"text": "after revoke restart"},
                    "operation_origin": "ai_mcp",
                }),
            ),
        )
        .await
        .map_err(|_elapsed| mvp_s6_timeout("mcp persist revoked tool call after restart"))?;
        let revoked_error = match revoked_call {
            Ok(value) => {
                return Err(
                    format!("revoked persisted grant unexpectedly succeeded: {value:?}").into()
                );
            }
            Err(error) => error.to_string(),
        };
        assert!(revoked_error.contains("GrantInvalidated"));
        let audit = mvp_s6_bus_request_with_timeout(
            "mcp persist audit list after restart",
            revoked_bus.request(
                Some(ACCOUNT.to_owned()),
                "mcp",
                "mcp.audit.list",
                &serde_json::json!({}),
            ),
        )
        .await?;
        let audit_entries = audit["audit"].as_array().ok_or("missing audit array")?;
        assert!(
            audit_entries.iter().any(|entry| entry["event_type"] == "mcp.approval.granted"),
            "audit did not include pre-restart grant event: {audit_entries:?}"
        );
        Ok::<(), Box<dyn std::error::Error>>(())
    };
    let result = tokio::time::timeout(Duration::from_mins(3), flow)
        .await
        .map_err(|_elapsed| "S6 MCP grant persistence flow timed out")?;
    let _ = mvp_s20_stop_rf_daemon(&mut alice_daemon).await;
    result?;
    std::fs::remove_dir_all(&temp_root)?;
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s4_assert_rf_dm_ratchet_second_message(
    rf_binary: &Path,
    alice_socket: &str,
    bob_socket: &str,
    bob_commitment: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let second = mvp_s4_rf_json(
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
            "msg_s4_cli_2",
            "--envelope",
            "env_s4_cli_dm_2",
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
            "s4 rf cli second ratchet plaintext",
        ],
    )
    .await?;
    assert_eq!(second["envelope"]["envelope_id"], "env_s4_cli_dm_2");
    assert_x3dh_payload_not_conversation_seed_decryptable(
        second["envelope"]["encrypted_payload"]
            .as_str()
            .ok_or("missing S4 second encrypted payload")?,
        "conv_s4_cli",
        "env_s4_cli_dm_2",
        "alice_device_s4",
        b"s4 rf cli second ratchet plaintext",
        false,
    )?;

    let bob_second = mvp_s4_rf_json(
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
    let decrypted = bob_second["decrypted_messages"]
        .as_array()
        .ok_or("missing S4 second decrypted messages")?;
    assert_eq!(decrypted.len(), 1);
    assert_eq!(decrypted[0]["message_id"].as_str(), Some("env_s4_cli_dm_2"));
    let plaintext = ramflux_protocol::decode_base64url(
        decrypted[0]
            .get("plaintext_body_base64")
            .and_then(serde_json::Value::as_str)
            .ok_or("missing S4 second plaintext body")?,
    )?;
    assert_eq!(plaintext, b"s4 rf cli second ratchet plaintext");
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s4_assert_rf_group(
    rf_binary: &Path,
    alice_socket: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let group = mvp_s4_rf_json(
        rf_binary,
        &[
            "--socket",
            alice_socket,
            "group",
            "create",
            "--account",
            "alice_s4_account",
            "--group",
            "group_s4_cli",
            "--creator",
            "alice_device_s4",
            "--member",
            "bob_device_s4",
        ],
    )
    .await?;
    assert_eq!(group["group_id"], "group_s4_cli");

    let group_sent = mvp_s4_rf_json(
        rf_binary,
        &[
            "--socket",
            alice_socket,
            "group",
            "send",
            "--account",
            "alice_s4_account",
            "--group",
            "group_s4_cli",
            "--conversation",
            "group_conv_s4_cli",
            "--message",
            "group_msg_s4_cli_1",
            "--sender",
            "alice_device_s4",
            "--body",
            "s4 rf group plaintext",
        ],
    )
    .await?;
    assert_eq!(group_sent["message_id"], "group_msg_s4_cli_1");

    let members = mvp_s4_rf_json(
        rf_binary,
        &[
            "--socket",
            alice_socket,
            "group",
            "members",
            "--account",
            "alice_s4_account",
            "--group",
            "group_s4_cli",
        ],
    )
    .await?;
    assert_eq!(members["members"].as_array().map_or(0, Vec::len), 2);
    assert_eq!(members["roles"]["alice_device_s4"], "owner");
    assert_eq!(members["roles"]["bob_device_s4"], "member");
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
#[allow(clippy::too_many_lines)]
pub(crate) async fn mvp_s6_assert_rf_mcp_commands(
    _rf_binary: &Path,
    alice_socket: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    mvp_s6_step("mcp connect subscriber before");
    let mut subscriber_bus = ramflux_sdk::LocalBusClient::connect(alice_socket).await?;
    mvp_s6_step("mcp connect subscriber after");
    mvp_s6_step("mcp connect actor before");
    let mut bus = ramflux_sdk::LocalBusClient::connect(alice_socket).await?;
    mvp_s6_step("mcp connect actor after");
    mvp_s6_bus_request_with_timeout(
        "subscription.open mcp approval fanout subscriber",
        subscriber_bus.request(
            Some("alice_s4_account".to_owned()),
            "subscription",
            "subscription.open",
            &serde_json::json!({
                "topics": ["mcp.approval.request"],
                "attended_frontend": true,
            }),
        ),
    )
    .await?;
    let added = mvp_s6_bus_request_with_timeout(
        "mcp.server.add srv_s6 echo",
        bus.request(
            Some("alice_s4_account".to_owned()),
            "mcp",
            "mcp.server.add",
            &serde_json::json!({
                "server_id": "srv_s6",
                "command": "stdio-echo",
                "tool_name": "echo",
                "capability": "external_tool_invoke",
                "tool_scope": "echo",
                "risk_level": "low",
            }),
        ),
    )
    .await?;
    let registry_hash = added["registry_hash"].as_str().ok_or("missing registry hash")?;
    assert!(!registry_hash.is_empty());

    let first_call =
        mvp_s6_call_tool(&mut bus, "echo", serde_json::json!({"text": "hello mcp"})).await?;
    assert_eq!(first_call["status"], "approval_required");
    assert_eq!(first_call["approval"]["confirmation_mode"], "remote_app");
    let approval_event =
        tokio::time::timeout(Duration::from_secs(5), subscriber_bus.next_event()).await.map_err(
            |_elapsed| "timed out waiting for cross-connection mcp.approval.request fanout",
        )??;
    assert_eq!(approval_event.method, "mcp.approval.request");
    assert_eq!(approval_event.body["event_type"], "mcp.approval.request");
    assert_eq!(
        approval_event.body["registry_hash"],
        first_call["approval"]["details"]["registry_hash"]
    );
    assert_eq!(
        approval_event.body["tool_manifest_set_hash"],
        first_call["approval"]["details"]["tool_manifest_set_hash"]
    );
    let approval_id =
        first_call["approval"]["approval_id"].as_str().ok_or("missing approval id")?;

    let local_echo_approve = mvp_s6_bus_failure(
        &mut bus,
        "grant",
        "grant.approve",
        serde_json::json!({ "approval_id": approval_id }),
    )
    .await?;
    assert!(local_echo_approve.contains("RemoteAppApprovalRequired"));

    let grant = mvp_s6_submit_app_signed_grant(&mut bus, &first_call["approval"], false).await?;
    let grant_record: ramflux_sdk::LocalMcpGrantRecord = serde_json::from_value(grant.clone())?;
    ramflux_crypto::verify_device_branch_signature(
        &grant_record.signer_public_key,
        &grant_record.signing_body,
        &grant_record.signature,
    )?;
    assert_eq!(
        grant["state"]["allowed_capabilities"]
            .as_array()
            .and_then(|items| items.first())
            .and_then(serde_json::Value::as_str),
        Some("external_tool_invoke")
    );

    let high_risk_echo = mvp_s6_bus_failure(
        &mut bus,
        "mcp",
        "mcp.tool.started",
        serde_json::json!({
            "server_id": "srv_s6",
            "tool_name": "echo",
            "arguments": {"text": "hello mcp"},
            "operation_origin": "ai_mcp",
        }),
    )
    .await?;
    assert!(high_risk_echo.contains("CapabilityDenied"));

    bus.request(
        Some("alice_s4_account".to_owned()),
        "mcp",
        "mcp.server.add",
        &serde_json::json!({
            "server_id": "srv_s6",
            "command": "stdio-echo",
            "tool_name": "notes",
            "capability": "read_conversation",
            "tool_scope": "notes",
            "risk_level": "low",
        }),
    )
    .await?;
    let notes_first =
        mvp_s6_call_tool(&mut bus, "notes", serde_json::json!({"text": "low risk"})).await?;
    assert_eq!(notes_first["status"], "approval_required");
    assert_eq!(notes_first["approval"]["confirmation_mode"], "attended_local");
    let notes_approval_id =
        notes_first["approval"]["approval_id"].as_str().ok_or("missing notes approval id")?;
    let notes_grant = bus
        .request(
            Some("alice_s4_account".to_owned()),
            "grant",
            "grant.approve",
            &serde_json::json!({ "approval_id": notes_approval_id }),
        )
        .await?;
    let notes_grant_record: ramflux_sdk::LocalMcpGrantRecord =
        serde_json::from_value(notes_grant.clone())?;
    ramflux_crypto::verify_device_branch_signature(
        &notes_grant_record.signer_public_key,
        &notes_grant_record.signing_body,
        &notes_grant_record.signature,
    )?;
    assert_eq!(
        notes_grant["state"]["allowed_capabilities"]
            .as_array()
            .and_then(|items| items.first())
            .and_then(serde_json::Value::as_str),
        Some("read_conversation")
    );
    let allowed =
        mvp_s6_call_tool(&mut bus, "notes", serde_json::json!({"text": "low risk"})).await?;
    assert_eq!(allowed["status"], "ok");
    assert_eq!(allowed["result"], "srv_s6:notes");
    assert_eq!(allowed["output"]["echo"]["text"], "low risk");

    bus.request(
        Some("alice_s4_account".to_owned()),
        "mcp",
        "mcp.server.add",
        &serde_json::json!({
            "server_id": "srv_s6",
            "command": "stdio-echo",
            "tool_name": "notes",
            "capability": "read_conversation",
            "tool_scope": "notes",
            "risk_level": "medium",
        }),
    )
    .await?;
    let risk_upgraded = mvp_s6_bus_failure(
        &mut bus,
        "mcp",
        "mcp.tool.started",
        serde_json::json!({
            "server_id": "srv_s6",
            "tool_name": "notes",
            "arguments": {"text": "risk-upgraded"},
            "operation_origin": "ai_mcp",
        }),
    )
    .await?;
    assert!(risk_upgraded.contains("GrantInvalidated"));

    bus.request(
        Some("alice_s4_account".to_owned()),
        "mcp",
        "mcp.server.add",
        &serde_json::json!({
            "server_id": "srv_s6",
            "command": "stdio-echo",
            "tool_name": "summarize",
            "capability": "external_tool_invoke",
            "tool_scope": "summarize",
            "risk_level": "low",
        }),
    )
    .await?;
    bus.request(
        Some("alice_s4_account".to_owned()),
        "mcp",
        "mcp.server.add",
        &serde_json::json!({
            "server_id": "srv_s6",
            "command": "stdio-echo",
            "tool_name": "run_shell",
            "capability": "run_shell",
            "risk_level": "high",
        }),
    )
    .await?;
    let wildcard_request = bus
        .request(
            Some("alice_s4_account".to_owned()),
            "grant",
            "grant.request",
            &serde_json::json!({
                "grant_id": "grant_s6_full",
                "server_id": serde_json::Value::Null,
                "tool_name": serde_json::Value::Null,
                "capability": "external_tool_invoke",
                "tool_scope": "wildcard",
                "full_delegation": true,
            }),
        )
        .await?;
    assert_eq!(wildcard_request["status"], "approval_required");
    assert_eq!(wildcard_request["approval"]["confirmation_mode"], "remote_app");
    let remote_approval_id =
        wildcard_request["approval"]["approval_id"].as_str().ok_or("missing remote approval id")?;
    let local_remote_approve = mvp_s6_bus_failure(
        &mut bus,
        "grant",
        "grant.approve",
        serde_json::json!({ "approval_id": remote_approval_id }),
    )
    .await?;
    assert!(local_remote_approve.contains("RemoteAppApprovalRequired"));
    assert!(local_remote_approve.contains("App-signed mcp.approval.granted"));
    let wildcard =
        mvp_s6_submit_app_signed_grant(&mut bus, &wildcard_request["approval"], true).await?;
    assert_eq!(wildcard["signing_body"]["full_delegation"], true);
    assert_eq!(wildcard["state"]["full_delegation"], true);
    let summarize = mvp_s6_bus_failure(
        &mut bus,
        "mcp",
        "mcp.tool.started",
        serde_json::json!({
            "server_id": "srv_s6",
            "tool_name": "summarize",
            "arguments": {"text": "brief"},
            "operation_origin": "ai_mcp",
        }),
    )
    .await?;
    assert!(summarize.contains("CapabilityDenied"));

    let high_risk = mvp_s6_bus_failure(
        &mut bus,
        "mcp",
        "mcp.tool.started",
        serde_json::json!({
            "server_id": "srv_s6",
            "tool_name": "run_shell",
            "arguments": {"cmd": "id"},
            "operation_origin": "ai_mcp",
        }),
    )
    .await?;
    assert!(high_risk.contains("CapabilityDenied"));

    let revoked = bus
        .request(
            Some("alice_s4_account".to_owned()),
            "grant",
            "grant.revoke",
            &serde_json::json!({ "grant_id": "grant_s6_full" }),
        )
        .await?;
    assert_eq!(revoked["state"]["revoked"], true);
    let revoked_call = mvp_s6_bus_failure(
        &mut bus,
        "mcp",
        "mcp.tool.started",
        serde_json::json!({
            "server_id": "srv_s6",
            "tool_name": "summarize",
            "arguments": {"text": "again"},
            "operation_origin": "ai_mcp",
        }),
    )
    .await?;
    assert!(revoked_call.contains("GrantInvalidated"));

    let grants = bus
        .request(Some("alice_s4_account".to_owned()), "grant", "grant.list", &serde_json::json!({}))
        .await?;
    assert!(grants["grants"].as_array().is_some_and(|items| items.len() >= 2));
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s6_call_tool(
    bus: &mut ramflux_sdk::LocalBusClient,
    tool_name: &str,
    arguments: serde_json::Value,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    mvp_s6_bus_request_with_timeout(
        "mcp.tool.started",
        bus.request(
            Some("alice_s4_account".to_owned()),
            "mcp",
            "mcp.tool.started",
            &serde_json::json!({
                "server_id": "srv_s6",
                "tool_name": tool_name,
                "arguments": arguments,
                "operation_origin": "ai_mcp",
            }),
        ),
    )
    .await
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s6_bus_request_with_timeout<'a>(
    label: &'static str,
    request: impl Future<Output = Result<serde_json::Value, ramflux_sdk::SdkError>> + 'a,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    mvp_s6_step(&format!("{label} before"));
    let value = tokio::time::timeout(Duration::from_secs(10), request)
        .await
        .map_err(|_elapsed| mvp_s6_timeout(label))?
        .map_err(|error| -> Box<dyn std::error::Error> {
            format!("local bus request failed during {label}: {error}").into()
        })?;
    mvp_s6_step(&format!("{label} after"));
    Ok(value)
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s6_bus_failure(
    bus: &mut ramflux_sdk::LocalBusClient,
    sdk_api: &str,
    method: &str,
    body: serde_json::Value,
) -> Result<String, Box<dyn std::error::Error>> {
    mvp_s6_step(&format!("{method} expected-failure before"));
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        bus.request(Some("alice_s4_account".to_owned()), sdk_api, method, &body),
    )
    .await
    .map_err(|_elapsed| mvp_s6_timeout(method))?;
    mvp_s6_step(&format!("{method} expected-failure after"));
    match result {
        Ok(value) => Err(format!("bus request unexpectedly succeeded: {value:?}").into()),
        Err(error) => Ok(error.to_string()),
    }
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s6_submit_app_signed_grant(
    bus: &mut ramflux_sdk::LocalBusClient,
    approval: &serde_json::Value,
    try_wrong_key_first: bool,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let approval_id = approval["approval_id"].as_str().ok_or("missing approval id")?;
    if try_wrong_key_first {
        let mut wrong = mvp_s6_signed_approval_grant(approval, [0xE1; 32])?;
        let app_branch = ramflux_crypto::create_device_branch(
            "principal_s4_alice",
            "alice_app_device_s6",
            1,
            [0xA6; 32],
        );
        wrong.signer_public_key =
            ramflux_protocol::encode_base64url(app_branch.signing_key.verifying_key().to_bytes());
        let rejected =
            mvp_s6_bus_failure(bus, "mcp", "mcp.approval.granted", serde_json::to_value(wrong)?)
                .await?;
        assert!(rejected.contains("SignatureVerificationFailed"));
    }
    let signed = mvp_s6_signed_approval_grant(approval, [0xA6; 32])?;
    let grant = bus
        .request(
            Some("alice_s4_account".to_owned()),
            "mcp",
            "mcp.approval.granted",
            &serde_json::to_value(signed)?,
        )
        .await?;
    assert_eq!(grant["signing_body"]["approval_id"], approval_id);
    Ok(grant)
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp_s6_signed_approval_grant(
    approval: &serde_json::Value,
    seed: [u8; 32],
) -> Result<ramflux_sdk::LocalBusMcpApprovalGrantRequest, Box<dyn std::error::Error>> {
    let approval_id = approval["approval_id"].as_str().ok_or("missing approval id")?;
    let capability: ramflux_sync::McpCapability =
        serde_json::from_value(approval["capability"].clone())?;
    let details = &approval["details"];
    let grant_id = details
        .get("requested_grant_id")
        .and_then(serde_json::Value::as_str)
        .map_or_else(|| format!("grant_{approval_id}"), str::to_owned);
    let full_delegation =
        details.get("full_delegation").and_then(serde_json::Value::as_bool).unwrap_or(false);
    let single_use =
        details.get("single_use").and_then(serde_json::Value::as_bool).unwrap_or(false);
    let arguments_hash = if single_use {
        Some(
            details
                .get("arguments_hash")
                .and_then(serde_json::Value::as_str)
                .ok_or("missing approval arguments_hash")?
                .to_owned(),
        )
    } else {
        None
    };
    let registry_hash = mvp_s6_registry_hash_from_approval(approval)?;
    let tool_manifest_set_hash = mvp_s6_tool_manifest_set_hash_from_approval(approval)?;
    let body = ramflux_sdk::LocalMcpGrantSigningBody {
        approval_id: approval_id.to_owned(),
        grant_id,
        server_id: approval["server_id"].as_str().unwrap_or("wildcard").to_owned(),
        tool_name: approval["tool_name"].as_str().unwrap_or("wildcard").to_owned(),
        tool_scope: approval["tool_scope"].as_str().map(str::to_owned),
        capability,
        registry_hash,
        tool_manifest_set_hash,
        full_delegation,
        single_use,
        arguments_hash,
        // App must sign over the daemon-assigned expires_at (computed once at approval creation),
        // not a hardcoded constant, or the daemon's reconstructed signing body won't match (item 5).
        expires_at: approval["expires_at"].as_i64().ok_or("missing approval expires_at")?,
    };
    let branch =
        ramflux_crypto::create_device_branch("principal_s4_alice", "alice_app_device_s6", 1, seed);
    let signature = ramflux_crypto::sign_with_device_branch(&branch, &body)?;
    Ok(ramflux_sdk::LocalBusMcpApprovalGrantRequest {
        approval_id: approval_id.to_owned(),
        signed_by_device_id: branch.device_id.clone(),
        signer_public_key: ramflux_protocol::encode_base64url(
            branch.signing_key.verifying_key().to_bytes(),
        ),
        signature,
    })
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp_s6_registry_hash_from_approval(
    approval: &serde_json::Value,
) -> Result<String, Box<dyn std::error::Error>> {
    approval["details"]["registry_hash"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| "missing registry hash in approval details".into())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp_s6_tool_manifest_set_hash_from_approval(
    approval: &serde_json::Value,
) -> Result<String, Box<dyn std::error::Error>> {
    approval["details"]["tool_manifest_set_hash"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| "missing tool manifest set hash in approval details".into())
}
