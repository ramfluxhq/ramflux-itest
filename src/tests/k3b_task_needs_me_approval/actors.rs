// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

use super::*;
pub(super) async fn call(
    bus: &mut ramflux_sdk::LocalBusClient,
    account: &str,
    method: &str,
    body: Value,
) -> TestResult<Value> {
    traced_call(bus, Some(account), method, body).await
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
        label: None,
        kind: None,
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
    traced_call(bus, None, "account.itest_legacy.create", serde_json::to_value(request)?).await
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
            assert_eq!(view["actor_kind_verified"], true);
            assert_eq!(view["actors"]["assignee"]["actor_kind"], "headless_ai");
            assert_eq!(view["actors"]["assignee"]["actor_kind_verified"], true);
            if !view["actors"]["requester"]["principal_id"].is_null() {
                assert_eq!(view["actors"]["requester"]["actor_kind"], "human");
                assert_eq!(view["actors"]["requester"]["actor_kind_verified"], true);
            }
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
    human2: &mut ramflux_sdk::LocalBusClient,
    agent: &mut ramflux_sdk::LocalBusClient,
    grant_id: &str,
) -> TestResult<Value> {
    let mut pending = None;
    for _ in 0..300 {
        let rows = call(human2, "human2", "grant.list", json!({})).await?;
        pending = rows["approvals"]
            .as_array()
            .and_then(|a| a.iter().find(|v| v["grant_id"] == grant_id))
            .cloned();
        if pending.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let pending = pending.ok_or("remote approval did not reach requester device A2")?;
    assert_eq!(pending["task_binding"]["task_id"], "task-k3b");
    assert_eq!(pending["task_binding"]["step_id"], "step");
    assert_eq!(pending["task_binding"]["opening_revision"], 4);
    let decision =
        call(human2, "human2", "grant.approve", json!({"approval_id":pending["approval_id"]}))
            .await?;
    assert_eq!(decision["status"], "approved");
    eprintln!("STEP: requester approval receipt={decision}");
    for _ in 0..300 {
        let rows = call(agent, "agent", "grant.list", json!({})).await?;
        if let Some(grant) =
            rows["grants"].as_array().and_then(|a| a.iter().find(|v| v["grant_id"] == grant_id))
        {
            assert_eq!(grant["signed_by_device_id"], "device_k3b_human2");
            assert_eq!(grant["signing_body"]["single_use"], true);
            assert_eq!(grant["signing_body"]["task_binding"], pending["task_binding"]);
            return Ok(decision);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    approval_delivery_diagnostics(human2, "human2").await;
    approval_delivery_diagnostics(agent, "agent").await;
    Err("requester signed decision did not return to the assignee daemon".into())
}

async fn approval_delivery_diagnostics(bus: &mut ramflux_sdk::LocalBusClient, id: &str) {
    for (method, body) in [
        ("sync.status.get", json!({})),
        ("message.read", json!({"conversation_id":"dm_k3b"})),
        ("task.get", json!({"conversation_id":"dm_k3b","task_id":"task-k3b"})),
    ] {
        match call(bus, id, method, body).await {
            Ok(row) => {
                let safe = if method == "message.read" {
                    json!({"rejected":row["rejected"]})
                } else if method == "task.get" {
                    json!({"approval_decisions":row["approval_decisions"]})
                } else {
                    row
                };
                eprintln!(
                    "STEP: approval delivery diagnostics account={id} method={method} row={safe}"
                );
            }
            Err(error) => eprintln!(
                "STEP: approval delivery diagnostics account={id} method={method} error={error}"
            ),
        }
    }
}

async fn traced_call(
    bus: &mut ramflux_sdk::LocalBusClient,
    account: Option<&str>,
    method: &str,
    body: Value,
) -> TestResult<Value> {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let label =
        account.or_else(|| body["local_account_id"].as_str()).unwrap_or("daemon").to_owned();
    eprintln!("STEP: begin method={method} account={label}");
    let frame = ramflux_sdk::LocalBusFrame::request(
        format!("k3b-step-{}", NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)),
        account.map(str::to_owned),
        if method == "account.itest_legacy.create" { "account" } else { "task" },
        method,
        body,
    );
    match bus.request_frame_response(frame).await {
        Ok(response)
            if response.kind == ramflux_sdk::LocalBusFrameKind::Error
                || response.ok == Some(false) =>
        {
            let json = serde_json::to_string(&response)?;
            let detail = truncated(&json);
            eprintln!("STEP: failure method={method} account={label} response={detail}");
            Err(format!("{method} on {label} rejected: {detail}").into())
        }
        Ok(response) => {
            eprintln!("STEP: complete method={method} account={label}");
            Ok(response.body)
        }
        Err(error) => {
            let text = error.to_string();
            eprintln!("STEP: failure method={method} account={label} error={}", truncated(&text));
            Err(error.into())
        }
    }
}
fn truncated(text: &str) -> &str {
    let mut end = text.len().min(1024);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}
