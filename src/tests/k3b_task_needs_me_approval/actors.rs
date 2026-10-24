// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

use super::*;
pub(super) async fn call(
    bus: &mut ramflux_sdk::LocalBusClient,
    account: &str,
    method: &str,
    body: Value,
) -> TestResult<Value> {
    Ok(bus.request(Some(account.into()), "task", method, body).await?)
}
pub(super) async fn create(
    bus: &mut ramflux_sdk::LocalBusClient,
    node: &S8RealnetNode,
    id: &str,
    owner: &str,
    seeds: (u8, u8),
    agent: bool,
) -> TestResult<Value> {
    let principal = format!("principal_k3b_{owner}");
    let device = format!("device_k3b_{id}");
    let target = format!("target_k3b_{id}");
    let request = ramflux_sdk::LocalBusAccountCreateRequest {
        node_id: None,
        local_account_id: id.into(),
        principal_id: principal.clone(),
        principal_commitment: String::new(),
        device_id: device.clone(),
        target_delivery_id: target.clone(),
        account_secret: "k3b-fixture-secret".into(),
        root_seed: [seeds.0; 32],
        device_seed: [seeds.1; 32],
        client_mode: if agent {
            ramflux_sdk::LocalBusClientMode::HeadlessAi
        } else {
            ramflux_sdk::LocalBusClientMode::AttendedCli
        },
        gateway: ramflux_sdk::GatewayQuicEndpointConfig {
            bind_addr: "0.0.0.0:0".parse()?,
            gateway_addr: S73_GATEWAY_B_QUIC.parse()?,
            server_name: "localhost".into(),
            ca_cert: node.ca_cert.clone(),
            principal_id: principal,
            device_id: device,
            target_delivery_id: target,
            prekey_http_url: None,
        },
    };
    Ok(bus.request(None, "account", "account.create", serde_json::to_value(request)?).await?)
}
pub(super) async fn wait_task(
    bus: &mut ramflux_sdk::LocalBusClient,
    id: &str,
    conversation: &str,
    version: u64,
) -> TestResult<Value> {
    for _ in 0..200 {
        let view =
            call(bus, id, "task.get", json!({"conversation_id":conversation,"task_id":"task-k3b"}))
                .await?;
        if view["version"] == version {
            assert_eq!(view["actor_kind_verified"], false);
            return Ok(view);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(format!("task version {version} did not arrive on {id}").into())
}
pub(super) async fn wait_conversation(
    bus: &mut ramflux_sdk::LocalBusClient,
    id: &str,
) -> TestResult {
    for _ in 0..200 {
        let view = call(bus, id, "conversation.directory", json!({"limit":100})).await?;
        if view["conversations"]
            .as_array()
            .is_some_and(|rows| rows.iter().any(|v| v["id"] == "dm_k3b"))
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err("ordinary DM conversation did not arrive".into())
}
pub(super) async fn approval(bus: &mut ramflux_sdk::LocalBusClient) -> TestResult<Value> {
    call(bus,"agent","mcp.server.add",json!({"server_id":"server-k3b","command":"stdio-shell","tool_name":"shell","capability":"external_tool_invoke","tool_scope":"shell","risk_level":"high"})).await?;
    let result=call(bus,"agent","mcp.tool.started",json!({"server_id":"server-k3b","tool_name":"shell","arguments":{"cmd":"echo task"},"operation_origin":"ai_mcp"})).await?;
    assert_eq!(result["status"], "approval_required");
    assert_eq!(result["approval"]["details"]["single_use"], true);
    Ok(result["approval"].clone())
}
pub(super) async fn grant_from_second_human_device(
    bus: &mut ramflux_sdk::LocalBusClient,
    approval: &Value,
) -> TestResult {
    // This is the existing App signer contract. The fixture owns the second device's key,
    // signs the daemon's immutable approval body, then submits it to the target daemon.
    let details = &approval["details"];
    let approval_id = approval["approval_id"].as_str().ok_or("approval id")?;
    let body = ramflux_sdk::LocalMcpGrantSigningBody {
        approval_id: approval_id.into(),
        grant_id: details["requested_grant_id"]
            .as_str()
            .map_or_else(|| format!("grant_{approval_id}"), str::to_owned),
        server_id: approval["server_id"].as_str().ok_or("server")?.into(),
        tool_name: approval["tool_name"].as_str().ok_or("tool")?.into(),
        tool_scope: approval["tool_scope"].as_str().map(str::to_owned),
        capability: serde_json::from_value(approval["capability"].clone())?,
        registry_hash: details["registry_hash"].as_str().ok_or("registry")?.into(),
        tool_manifest_set_hash: details["tool_manifest_set_hash"]
            .as_str()
            .ok_or("manifest")?
            .into(),
        full_delegation: false,
        single_use: true,
        arguments_hash: Some(details["arguments_hash"].as_str().ok_or("arguments")?.into()),
        expires_at: approval["expires_at"].as_i64().ok_or("expiry")?,
    };
    let device = ramflux_crypto::create_device_branch(
        "principal_k3b_human",
        "device_k3b_human2",
        1,
        [43; 32],
    );
    let signature = ramflux_crypto::sign_with_device_branch(&device, &body)?;
    let granted=call(bus,"agent","mcp.approval.granted",json!({"approval_id":approval_id,"signed_by_device_id":device.device_id,"signer_public_key":ramflux_protocol::encode_base64url(device.signing_key.verifying_key().to_bytes()),"signature":signature})).await?;
    assert_eq!(granted["signing_body"], serde_json::to_value(body)?);
    Ok(())
}
