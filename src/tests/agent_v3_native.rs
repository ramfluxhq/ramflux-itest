// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Native Part A acceptance for headless provisioning, DM replies, surfaces and one-device tasks.
#![cfg(feature = "realnet")]
use super::*;
use serde_json::{Value, json};
use std::os::unix::fs::PermissionsExt;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[derive(Clone, Copy)]
enum Case {
    AgentHost,
    Surface,
    Task,
}

#[test]
fn k5a_native_realnet_agent_host_dm_reply_and_bundle_consumption() -> TestResult {
    scenario(Case::AgentHost)
}

#[test]
fn k2b_native_realnet_surface_publish_and_stream_in_dm() -> TestResult {
    scenario(Case::Surface)
}

#[test]
fn k3b_native_realnet_single_device_needs_me_approval() -> TestResult {
    scenario(Case::Task)
}

fn scenario(case: Case) -> TestResult {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping native agent-v3 slice: set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }
    if std::env::var("RAMFLUX_OBJECT_V3").as_deref() != Ok("1")
        || std::env::var("RAMFLUX_CROSS_GATEWAY").as_deref() != Ok("1")
    {
        return Err("native agent-v3 slices require object-v3 and cross-gateway".into());
    }
    let (name, base) = match case {
        Case::AgentHost => ("ramflux-k5a-native-agent", 64100),
        Case::Surface => ("ramflux-k2b-native-surface", 64200),
        Case::Task => ("ramflux-k3b-native-task", 64300),
    };
    let mut stack = start_client_directory_stack_named(
        name,
        S8ComposePorts {
            gateway_http: base + 1,
            gateway_quic: base + 71,
            router_http: base,
            router_mesh: base + 72,
            notify_http: base + 3,
            federation_http: base + 2,
            federation_mesh: base + 73,
            relay_http: base + 4,
            relay_media_udp: base + 40,
            signaling_turn_udp: base + 78,
            signaling_turn_tcp: base + 79,
            retention_http: base + 7,
        },
        &[],
    )?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(run(&stack.node, case))?;
    stack.node.guard.mark_success();
    Ok(())
}

async fn run(node: &S8RealnetNode, case: Case) -> TestResult {
    wait_relay_quic_healthy(S73_RELAY_QUIC, "ramflux-relay", &node.ca_cert).await?;
    wait_for_private_gateway_quic(S73_GATEWAY_B_QUIC.parse()?, &node.ca_cert).await?;
    let root = temp_root("agent-v3-native")?;
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
    let socket = root.join("rfd.sock");
    let mut config = ramflux_sdk::LocalBusConfig::new(&socket, root.join("rfd"));
    config.builtin_nodes = vec![native_node_profile(node, S73_RELAY_QUIC)?];
    config.custody_vault =
        Some(std::sync::Arc::new(ramflux_sdk::custody::MemoryPrimaryVault::default()));
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let server = ramflux_sdk::serve_local_bus_until(config, stopped);
    let flow = async {
        mvp_s4_wait_for_socket(&socket).await?;
        let mut bus = ramflux_sdk::LocalBusClient::connect(&socket).await?;
        select_native_node(&mut bus, &node.node_id).await?;
        let human = create_native_account(&socket, "Native Owner").await?;
        let bundle = root.join("agent.bundle");
        let agent =
            create_native_agent_account(&socket, "Native Demo Agent", &human, &bundle).await?;
        assert_eq!(std::fs::metadata(&bundle)?.permissions().mode() & 0o777, 0o600);
        attend(&mut bus, &human.account_id).await?;
        connect_contacts(&mut bus, &human, &agent).await?;
        seed_dm(&mut bus, &human, &agent, "agent-v3-seed", "@agent ping").await?;
        match case {
            Case::AgentHost => {
                agent_host_case(&mut bus, &root, &socket, &bundle, &human, &agent).await?;
            }
            Case::Surface => surface_case(&mut bus, &human, &agent).await?,
            Case::Task => task_case(&mut bus, &human, &agent).await?,
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    };
    let (server_result, flow_result) = tokio::time::timeout(Duration::from_mins(6), async {
        let flow_result = flow.await;
        let _ = stop.send(true);
        let server_result = server.await;
        (server_result, flow_result)
    })
    .await?;
    server_result?;
    flow_result?;
    std::fs::remove_dir_all(root)?;
    Ok(())
}

async fn call(
    bus: &mut ramflux_sdk::LocalBusClient,
    account: &str,
    method: &str,
    body: Value,
) -> TestResult<Value> {
    Ok(bus.request(Some(account.to_owned()), "agent-v3", method, body).await?)
}

async fn attend(bus: &mut ramflux_sdk::LocalBusClient, account: &str) -> TestResult {
    call(bus, account, "subscription.open", json!({"topics":[],"attended_frontend":true})).await?;
    Ok(())
}

async fn connect_contacts(
    bus: &mut ramflux_sdk::LocalBusClient,
    human: &NativeAccount,
    agent: &NativeAccount,
) -> TestResult {
    call(bus, &human.account_id, "contact.add", json!({"principal_id":agent.principal_id})).await?;
    call(bus, &agent.account_id, "contact.accept", json!({"principal_id":human.principal_id}))
        .await?;
    for (account, peer, kind) in [
        (&human.account_id, &agent.principal_id, "headless_ai"),
        (&agent.account_id, &human.principal_id, "human"),
    ] {
        let directory = call(bus, account, "identity.directory", json!({"limit":100})).await?;
        let row = directory["identities"]
            .as_array()
            .and_then(|rows| rows.iter().find(|row| row["principal_id"] == *peer))
            .ok_or("native contact missing")?;
        assert_eq!(row["kind"], kind);
        assert_eq!(row["kind_verified"], true);
    }
    Ok(())
}

async fn seed_dm(
    bus: &mut ramflux_sdk::LocalBusClient,
    human: &NativeAccount,
    agent: &NativeAccount,
    message: &str,
    text: &str,
) -> TestResult<Value> {
    let sent=call(bus,&human.account_id,"message.submit",json!({"conversation_id":"dm_agent_v3","message_id":message,"envelope_id":message,"source_principal_id":human.principal_id,"sender_id":human.device_id,"recipient_device_id":agent.device_id,"recipient_principal_commitment":agent.anchor,"target_delivery_id":agent.delivery_id,"encrypted_body_base64":"","plaintext_body_base64":ramflux_protocol::encode_base64url(text.as_bytes()),"created_at":realnet_now_i64(),"ttl":600})).await?;
    assert_eq!(sent["delivery_state"], "submitted");
    Ok(sent)
}

async fn receive(bus: &mut ramflux_sdk::LocalBusClient, account: &str) -> TestResult {
    call(bus, account, "message.receive", json!({"limit":32,"auto_fetch_attachments":false}))
        .await?;
    Ok(())
}

async fn build_agent_host() -> TestResult<PathBuf> {
    let target = std::env::var_os("CARGO_TARGET_DIR")
        .map_or_else(|| code_root().join("ramflux/target"), PathBuf::from);
    let manifest = code_root().join("ramflux/Cargo.toml");
    let status = tokio::process::Command::new("cargo")
        .args(["build", "--bin", "ramflux-agent-host", "--features", "itest-memory-vault"])
        .arg("--manifest-path")
        .arg(manifest)
        .arg("--target-dir")
        .arg(&target)
        .env_remove("CARGO_TARGET_DIR")
        .env("RAMFLUX_ITEST_BUILD", "1")
        .status()
        .await?;
    if !status.success() {
        return Err("failed to build native agent host".into());
    }
    Ok(target.join("debug/ramflux-agent-host"))
}

async fn agent_host_case(
    bus: &mut ramflux_sdk::LocalBusClient,
    root: &Path,
    socket: &Path,
    bundle: &Path,
    human: &NativeAccount,
    agent: &NativeAccount,
) -> TestResult {
    let binary = build_agent_host().await?;
    let config = root.join("host.json");
    let state = root.join("host-state.json");
    std::fs::write(
        &config,
        serde_json::to_vec(
            &json!({"socket":socket,"state_file":state,"account_id":agent.account_id,"poll_interval_ms":50,"per_conversation_interval_ms":100,"rules":[{"pattern":"@agent ping","reply":"pong"}]}),
        )?,
    )?;
    let mut child = tokio::process::Command::new(binary)
        .args(["--config"])
        .arg(&config)
        .arg("--provisioning-bundle")
        .arg(bundle)
        .arg("--itest-memory-vault")
        .stderr(std::process::Stdio::inherit())
        .kill_on_drop(true)
        .spawn()?;
    for _ in 0..200 {
        receive(bus, &human.account_id).await?;
        let rows =
            call(bus, &human.account_id, "message.read", json!({"conversation_id":"dm_agent_v3"}))
                .await?;
        if rows["messages"].as_array().is_some_and(|messages| {
            messages
                .iter()
                .any(|row| row["sender_id"] == agent.principal_id && row["body_utf8"] == "pong")
        }) {
            assert!(!bundle.exists());
            child.start_kill()?;
            child.wait().await?;
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let _ = child.start_kill();
    let _ = child.wait().await;
    Err("native agent host did not reply to DM".into())
}

async fn surface_case(
    bus: &mut ramflux_sdk::LocalBusClient,
    human: &NativeAccount,
    agent: &NativeAccount,
) -> TestResult {
    use ramflux_protocol::{
        A2uiConversationCommand, CreateSurfaceCommand, StreamAppendCommand, SurfaceType,
    };
    receive(bus, &agent.account_id).await?;
    let create = A2uiConversationCommand::CreateSurface(CreateSurfaceCommand {
        surface_id: "native-surface".into(),
        surface_type: SurfaceType::StatusPanel,
        catalog: "basic".into(),
        catalog_version: "1".into(),
        fallback_text: "Working".into(),
        fallback_markdown: None,
        components: vec![json!({"id":"progress","text":""})],
        data_model: serde_json::Map::new(),
        allowed_actions: Vec::new(),
    });
    send_surface(bus, agent, 1, "create", create).await?;
    let stream = A2uiConversationCommand::StreamAppend(StreamAppendCommand {
        surface_id: "native-surface".into(),
        component_id: "progress".into(),
        text_delta: "Complete".into(),
        final_: true,
    });
    send_surface(bus, agent, 2, "stream", stream).await?;
    for _ in 0..100 {
        receive(bus, &human.account_id).await?;
        if let Ok(view) =
            call(bus, &human.account_id, "surface.get", json!({"surface_id":"native-surface"}))
                .await
            && view["version"] == 2
        {
            assert_eq!(view["author_principal_id"], agent.principal_id);
            assert_eq!(view["snapshot"]["components"][0]["text"], "Complete");
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err("native streamed surface did not arrive".into())
}

async fn send_surface(
    bus: &mut ramflux_sdk::LocalBusClient,
    agent: &NativeAccount,
    version: u64,
    suffix: &str,
    command: ramflux_protocol::A2uiConversationCommand,
) -> TestResult {
    let wire = serde_json::to_vec(
        &json!({"schema":"ramflux.a2ui.conversation.v2","conversationId":"dm_agent_v3","version":version,"command":command}),
    )?;
    let sent=call(bus,&agent.account_id,"surface.send",json!({"conversation_id":"dm_agent_v3","message_id":format!("native-surface-{suffix}"),"wire_base64":ramflux_protocol::encode_base64url(wire)})).await?;
    assert_eq!(sent["delivery_state"], "submitted");
    Ok(())
}

async fn task_case(
    bus: &mut ramflux_sdk::LocalBusClient,
    human: &NativeAccount,
    agent: &NativeAccount,
) -> TestResult {
    receive(bus, &agent.account_id).await?;
    call(bus,&agent.account_id,"task.propose",json!({"conversation_id":"dm_agent_v3","task_id":"native-task","message_id":"native-propose","assignee":agent.principal_id,"title":"Investigate","steps":[{"id":"step","title":"Run tool","state":"proposed"}]})).await?;
    wait_task(bus, &human.account_id, 1).await?;
    call(bus,&human.account_id,"task.accept",json!({"conversation_id":"dm_agent_v3","task_id":"native-task","message_id":"native-accept","version":2})).await?;
    wait_task(bus, &agent.account_id, 2).await?;
    call(bus,&agent.account_id,"task.update",json!({"conversation_id":"dm_agent_v3","task_id":"native-task","version":3,"state":"running","steps":[{"id":"step","title":"Run tool","state":"running"}]})).await?;
    call(bus,&agent.account_id,"mcp.server.add",json!({"server_id":"native-server","command":"stdio-shell","tool_name":"shell","capability":"external_tool_invoke","tool_scope":"shell","risk_level":"high"})).await?;
    let started=call(bus,&agent.account_id,"mcp.tool.started",json!({"server_id":"native-server","tool_name":"shell","arguments":{"cmd":"echo task"},"operation_origin":"ai_mcp"})).await?;
    assert_eq!(started["status"], "approval_required");
    let approval = &started["approval"];
    let grant_id = approval["details"]["requested_grant_id"].as_str().map_or_else(
        || format!("grant_{}", approval["approval_id"].as_str().unwrap_or_default()),
        str::to_owned,
    );
    call(bus,&agent.account_id,"task.update",json!({"conversation_id":"dm_agent_v3","task_id":"native-task","version":4,"state":"needs_me","steps":[{"id":"step","title":"Run tool","state":"needs_me","needs_me":{"kind":"approval","grant_id":grant_id}}]})).await?;
    wait_task(bus, &human.account_id, 4).await?;
    let pending = wait_approval(bus, &human.account_id, &grant_id).await?;
    let decision = call(
        bus,
        &human.account_id,
        "grant.approve",
        json!({"approval_id":pending["approval_id"]}),
    )
    .await?;
    assert_eq!(decision["status"], "approved");
    wait_grant(bus, &agent.account_id, &grant_id).await?;
    let resolved=call(bus,&human.account_id,"task.resolve",json!({"conversation_id":"dm_agent_v3","task_id":"native-task","message_id":"native-resolve","base_revision":4,"step_id":"step","target":{"kind":"approval","grant_id":grant_id},"decision_id":decision["approval_id"],"decision":"resume"})).await?;
    assert_eq!(resolved["pending"], true);
    let current = wait_task(bus, &human.account_id, 5).await?;
    assert_eq!(current["state"], "running");
    Ok(())
}

async fn wait_task(
    bus: &mut ramflux_sdk::LocalBusClient,
    account: &str,
    version: u64,
) -> TestResult<Value> {
    for _ in 0..200 {
        receive(bus, account).await?;
        let task = call(
            bus,
            account,
            "task.get",
            json!({"conversation_id":"dm_agent_v3","task_id":"native-task"}),
        )
        .await?;
        if task["version"] == version {
            assert_eq!(task["actor_kind_verified"], true);
            return Ok(task);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(format!("native task version {version} did not arrive").into())
}

async fn wait_approval(
    bus: &mut ramflux_sdk::LocalBusClient,
    account: &str,
    grant_id: &str,
) -> TestResult<Value> {
    for _ in 0..200 {
        receive(bus, account).await?;
        let rows = call(bus, account, "grant.list", json!({})).await?;
        if let Some(row) = rows["approvals"]
            .as_array()
            .and_then(|rows| rows.iter().find(|row| row["grant_id"] == grant_id))
        {
            return Ok(row.clone());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err("native task approval did not reach the human device".into())
}

async fn wait_grant(
    bus: &mut ramflux_sdk::LocalBusClient,
    account: &str,
    grant_id: &str,
) -> TestResult {
    for _ in 0..200 {
        receive(bus, account).await?;
        let rows = call(bus, account, "grant.list", json!({})).await?;
        if rows["grants"]
            .as_array()
            .is_some_and(|rows| rows.iter().any(|row| row["grant_id"] == grant_id))
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err("native task grant did not return to the agent".into())
}
