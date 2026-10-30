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
    AgentSurface,
    Surface,
    Task,
}

#[test]
fn k5a_native_realnet_agent_host_dm_reply_and_bundle_consumption() -> TestResult {
    scenario(Case::AgentHost)
}

#[test]
fn k5a2_native_realnet_agent_surface_in_dm() -> TestResult {
    scenario(Case::AgentSurface)
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
        Case::AgentSurface => ("ramflux-k5a2-native-agent-surface", 64400),
        Case::Surface => ("ramflux-k2b-native-surface", 64200),
        Case::Task => ("ramflux-k3b-native-task", 64300),
    };
    let relay_quic = format!("127.0.0.1:{}", base + 47);
    let gateway_b_quic = format!("127.0.0.1:{}", base + 89);
    let extra_env = [
        ("RAMFLUX_ITEST_RELAY_CLIENT_QUIC_PORT".to_owned(), (base + 47).to_string()),
        ("RAMFLUX_ITEST_GATEWAY_B_HTTP_PORT".to_owned(), (base + 88).to_string()),
        ("RAMFLUX_ITEST_GATEWAY_B_QUIC_PORT".to_owned(), (base + 89).to_string()),
        ("RAMFLUX_ITEST_GATEWAY_B_TCP_PORT".to_owned(), (base + 89).to_string()),
    ];
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
        &extra_env,
    )?;
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(run(
        &stack.node,
        case,
        &relay_quic,
        &gateway_b_quic,
    ))?;
    stack.node.guard.mark_success();
    Ok(())
}

async fn run(
    node: &S8RealnetNode,
    case: Case,
    relay_quic: &str,
    gateway_b_quic: &str,
) -> TestResult {
    wait_relay_quic_healthy(relay_quic, "ramflux-relay", &node.ca_cert).await?;
    wait_for_private_gateway_quic(gateway_b_quic.parse()?, &node.ca_cert).await?;
    let root = temp_root("agent-v3-native")?;
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
    let socket = root.join("rfd.sock");
    let mut config = ramflux_sdk::LocalBusConfig::new(&socket, root.join("rfd"));
    config.builtin_nodes = vec![native_node_profile(node, relay_quic)?];
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
        match case {
            Case::AgentHost => {
                agent_host_case(&mut bus, &root, &bundle, &human, &agent, false).await?;
            }
            Case::AgentSurface => {
                agent_host_case(&mut bus, &root, &bundle, &human, &agent, true).await?;
            }
            Case::Surface => {
                seed_dm(&mut bus, &human, &agent, "agent-v3-seed", "@agent ping").await?;
                surface_case(&mut bus, &socket, &human, &agent).await?;
            }
            Case::Task => {
                seed_dm(&mut bus, &human, &agent, "agent-v3-seed", "@agent ping").await?;
                task_case(&mut bus, &human, &agent).await?;
            }
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    };
    let flow = async {
        let result = flow.await;
        let _ = stop.send(true);
        result
    };
    let (server_result, flow_result) =
        Box::pin(tokio::time::timeout(Duration::from_mins(6), async {
            tokio::join!(server, flow)
        }))
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
    for (account, peer, peer_device, kind) in [
        (&human.account_id, &agent.principal_id, &agent.device_id, "headless_ai"),
        (&agent.account_id, &human.principal_id, &human.device_id, "human"),
    ] {
        let directory = call(bus, account, "identity.directory", json!({"limit":100})).await?;
        let row = directory["identities"]
            .as_array()
            .and_then(|rows| rows.iter().find(|row| row["principal_id"] == *peer))
            .ok_or("native contact missing")?;
        assert_eq!(row["kind"], kind);
        assert_eq!(row["kind_verified"], true);
        assert!(row["devices"].as_array().is_some_and(|devices| {
            devices.iter().any(|device| device["device_id"] == *peer_device)
        }));
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
    assert_eq!(sent["target_delivery_id"], agent.delivery_id);
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
    bundle: &Path,
    human: &NativeAccount,
    agent: &NativeAccount,
    surface: bool,
) -> TestResult {
    let socket = root.join("rfd.sock");
    let binary = build_agent_host().await?;
    let config = root.join("host.json");
    let state = root.join("host-state.json");
    std::fs::write(
        &config,
        serde_json::to_vec(
            &json!({"socket":socket,"state_file":state,"account_id":agent.account_id,"poll_interval_ms":50,"per_conversation_interval_ms":100,"rules":if surface {json!([{"pattern":"@agent checklist","reply":"Checklist complete","surface":{"chunk_bytes":256,"choices":[{"id":"done","label":"Done"}],"close_on_action":true}}])} else {json!([{"pattern":"@agent ping","reply":"pong"}])}}),
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
        if let Some(status) = child.try_wait()? {
            return Err(format!("native agent host exited before subscribing: {status}").into());
        }
        if state.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    if !state.exists() {
        return Err("native agent host did not subscribe before the DM seed".into());
    }
    let prompt = if surface { "@agent checklist" } else { "@agent ping" };
    seed_dm(bus, human, agent, "agent-v3-seed", prompt).await?;
    receive(bus, &agent.account_id).await?;
    let seeded =
        call(bus, &agent.account_id, "message.read", json!({"conversation_id":"dm_agent_v3"}))
            .await?;
    let seed = seeded["messages"]
        .as_array()
        .and_then(|messages| {
            messages.iter().find(|message| message["message_id"] == "agent-v3-seed")
        })
        .ok_or("native seed sender missing")?;
    let sender = seed["sender_id"].as_str().ok_or("native seed sender missing")?;
    assert!(sender == human.device_id || sender == human.principal_id);
    assert_eq!(seed["sender_root_commitment"], human.anchor);
    for _ in 0..200 {
        receive(bus, &human.account_id).await?;
        if surface {
            let listing = call(
                bus,
                &human.account_id,
                "surface.list",
                json!({"conversation_id":"dm_agent_v3"}),
            )
            .await?;
            if let Some(row) = listing["surfaces"].as_array().and_then(|rows| rows.first()) {
                let view = call(
                    bus,
                    &human.account_id,
                    "surface.get",
                    json!({"surface_ref":row["surface_ref"]}),
                )
                .await?;
                if view["snapshot"]["fallbackText"] == "Checklist complete" {
                    assert_eq!(view["author_principal_id"], agent.principal_id);
                    assert_eq!(view["streams"]["reply"], "final");
                    complete_agent_surface(bus, human, &view).await?;
                    assert!(!bundle.exists());
                    child.start_kill()?;
                    child.wait().await?;
                    return Ok(());
                }
            }
        }
        let rows =
            call(bus, &human.account_id, "message.read", json!({"conversation_id":"dm_agent_v3"}))
                .await?;
        if !surface
            && rows["messages"].as_array().is_some_and(|messages| {
                messages
                    .iter()
                    .any(|row| row["sender_id"] == agent.principal_id && row["body_utf8"] == "pong")
            })
        {
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

async fn complete_agent_surface(
    bus: &mut ramflux_sdk::LocalBusClient,
    human: &NativeAccount,
    current: &Value,
) -> TestResult {
    let values = json!({});
    let wire = serde_json::to_vec(&json!({
        "schema":"ramflux.a2ui.action.v2", "conversationId":"dm_agent_v3",
        "surfaceId":current["surface_id"], "version":current["version"],
        "surfaceHash":current["surface_hash"], "actionId":"done", "values":values,
        "argsHash":ramflux_protocol::surface_args_hash(&values)?
    }))?;
    let result=call(bus,&human.account_id,"surface.action",json!({"conversation_id":"dm_agent_v3","message_id":"native-agent-surface-action","wire_base64":ramflux_protocol::encode_base64url(wire)})).await?;
    assert_eq!(result["accepted"], true);
    for _ in 0..200 {
        receive(bus, &human.account_id).await?;
        let view = call(
            bus,
            &human.account_id,
            "surface.get",
            json!({"surface_id":current["surface_id"]}),
        )
        .await?;
        if view["closed"] == true {
            assert_eq!(view["snapshot"]["fallbackText"], "You chose Done.");
            assert_eq!(view["streams"]["reply"], "final");
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err("native agent surface did not close after the human choice".into())
}

async fn surface_case(
    bus: &mut ramflux_sdk::LocalBusClient,
    socket: &Path,
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
        allowed_actions: vec![json!({"name":"approve"})],
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
            return surface_security_case(bus, socket, human, agent, &view).await;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err("native streamed surface did not arrive".into())
}

async fn surface_security_case(
    bus: &mut ramflux_sdk::LocalBusClient,
    socket: &Path,
    human: &NativeAccount,
    agent: &NativeAccount,
    current: &Value,
) -> TestResult {
    use ramflux_protocol::{
        A2uiConversationCommand, DeleteSurfaceCommand, PatchSurfaceCommand, SurfacePatchOp,
    };
    let stale = surface_action_wire(1, current["surface_hash"].as_str().ok_or("surface hash")?)?;
    let stale_result=call(bus,&human.account_id,"surface.action",json!({"conversation_id":"dm_agent_v3","message_id":"native-action-stale","wire_base64":ramflux_protocol::encode_base64url(stale)})).await?;
    assert_eq!(stale_result["accepted"], false);
    receive(bus, &agent.account_id).await?;
    assert!(
        call(bus, &agent.account_id, "surface.get", json!({"surface_id":"native-surface"})).await?
            ["actions"]
            .as_array()
            .is_none_or(Vec::is_empty)
    );

    let mut forged_snapshot: ramflux_protocol::CreateSurfaceCommand =
        serde_json::from_value(current["snapshot"].clone())?;
    forged_snapshot.fallback_text = "forged".into();
    let unauthorized = A2uiConversationCommand::PatchSurface(PatchSurfaceCommand {
        surface_id: "native-surface".into(),
        base_surface_hash: current["surface_hash"].as_str().ok_or("surface hash")?.into(),
        ops: vec![SurfacePatchOp::SetFallbackText { fallback_text: "forged".into() }],
        new_surface_hash: ramflux_protocol::surface_snapshot_hash(&forged_snapshot)?,
    });
    let wire = serde_json::to_vec(
        &json!({"schema":"ramflux.a2ui.conversation.v2","conversationId":"dm_agent_v3","version":3,"command":unauthorized}),
    )?;
    assert!(call(bus,&human.account_id,"surface.send",json!({"conversation_id":"dm_agent_v3","message_id":"native-foreign-patch","wire_base64":ramflux_protocol::encode_base64url(wire)})).await.is_err());

    let mut watcher = ramflux_sdk::LocalBusClient::connect(socket).await?;
    call(&mut watcher, &agent.account_id, "bus.subscribe", json!({"topics":["surface.changed"]}))
        .await?;
    let action = surface_action_wire(2, current["surface_hash"].as_str().ok_or("surface hash")?)?;
    let request = json!({"conversation_id":"dm_agent_v3","message_id":"native-action","wire_base64":ramflux_protocol::encode_base64url(action)});
    assert_eq!(
        call(bus, &human.account_id, "surface.action", request.clone()).await?["accepted"],
        true
    );
    let event = tokio::time::timeout(Duration::from_secs(10), watcher.next_event()).await??;
    assert_eq!(event.method, "surface.changed");
    assert!(event.body.get("snapshot").is_none());
    assert!(event.body.get("fallback_text").is_none());
    assert!(!event.body.to_string().contains("PRIVATE_FORM_VALUE"));
    assert_eq!(call(bus, &human.account_id, "surface.action", request).await?["replayed"], true);

    let mut snapshot: ramflux_protocol::CreateSurfaceCommand =
        serde_json::from_value(current["snapshot"].clone())?;
    snapshot.fallback_text = "Complete".into();
    let patch = A2uiConversationCommand::PatchSurface(PatchSurfaceCommand {
        surface_id: "native-surface".into(),
        base_surface_hash: current["surface_hash"].as_str().ok_or("surface hash")?.into(),
        ops: vec![SurfacePatchOp::SetFallbackText { fallback_text: "Complete".into() }],
        new_surface_hash: ramflux_protocol::surface_snapshot_hash(&snapshot)?,
    });
    send_surface(bus, agent, 3, "result", patch).await?;
    let after = wait_surface(bus, &human.account_id, 3).await?;
    let close = A2uiConversationCommand::DeleteSurface(DeleteSurfaceCommand {
        surface_id: "native-surface".into(),
        reason: None,
    });
    send_surface(bus, agent, 4, "close", close).await?;
    let closed = wait_surface(bus, &human.account_id, 4).await?;
    assert_eq!(closed["closed"], true);
    assert_eq!(closed["hash_history"].as_array().map(Vec::len), Some(4));
    assert_ne!(after["version"], closed["version"]);
    Ok(())
}

fn surface_action_wire(version: u64, hash: &str) -> TestResult<Vec<u8>> {
    let values = json!({"confirmation":"PRIVATE_FORM_VALUE"});
    Ok(serde_json::to_vec(
        &json!({"schema":"ramflux.a2ui.action.v2","conversationId":"dm_agent_v3","surfaceId":"native-surface","version":version,"surfaceHash":hash,"actionId":"approve","values":values,"argsHash":ramflux_protocol::surface_args_hash(&values)?}),
    )?)
}

async fn wait_surface(
    bus: &mut ramflux_sdk::LocalBusClient,
    account: &str,
    version: u64,
) -> TestResult<Value> {
    for _ in 0..100 {
        receive(bus, account).await?;
        let view =
            call(bus, account, "surface.get", json!({"surface_id":"native-surface"})).await?;
        if view["version"] == version {
            return Ok(view);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(format!("native surface version {version} did not arrive").into())
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
    let self_accept=call(bus,&agent.account_id,"task.accept",json!({"conversation_id":"dm_agent_v3","task_id":"native-task","message_id":"native-self-accept","version":2})).await;
    assert!(self_accept.is_err(), "agent accepted its own proposal");
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
    let resolve = json!({"conversation_id":"dm_agent_v3","task_id":"native-task","message_id":"native-resolve","base_revision":4,"step_id":"step","target":{"kind":"approval","grant_id":grant_id},"decision_id":decision["approval_id"],"decision":"resume"});
    assert!(
        call(bus, &agent.account_id, "task.resolve", resolve.clone()).await.is_err(),
        "agent resolved its own intervention"
    );
    let resolved = call(bus, &human.account_id, "task.resolve", resolve.clone()).await?;
    assert_eq!(resolved["pending"], true);
    wait_task(bus, &agent.account_id, 5).await?;
    let current = wait_task(bus, &human.account_id, 5).await?;
    assert_eq!(current["state"], "running");
    let mut replay = resolve;
    replay["message_id"] = json!("native-resolve-replay");
    assert!(call(bus, &human.account_id, "task.resolve", replay).await.is_err());
    let ran=call(bus,&agent.account_id,"mcp.tool.started",json!({"server_id":"native-server","tool_name":"shell","arguments":{"cmd":"echo task"},"operation_origin":"ai_mcp"})).await?;
    assert_eq!(ran["status"], "ok");
    let reused=call(bus,&agent.account_id,"mcp.tool.started",json!({"server_id":"native-server","tool_name":"shell","arguments":{"cmd":"echo task"},"operation_origin":"ai_mcp"})).await?;
    assert_eq!(reused["status"], "approval_required", "tool grant must be single-use");
    call(bus,&agent.account_id,"task.update",json!({"conversation_id":"dm_agent_v3","task_id":"native-task","version":6,"state":"done","steps":[{"id":"step","title":"Run tool","state":"done"}]})).await?;
    assert_eq!(wait_task(bus, &human.account_id, 6).await?["state"], "done");
    let messages =
        call(bus, &human.account_id, "message.read", json!({"conversation_id":"dm_agent_v3"}))
            .await?;
    let rows = messages["messages"]
        .as_array()
        .ok_or("native task timeline missing")?
        .iter()
        .filter(|row| row["content_type"] == "task" && row["task_id"] == "native-task")
        .collect::<Vec<_>>();
    assert_ne!(rows, [] as [&serde_json::Value; 0]);
    assert!(rows.iter().all(|row| row["actor_kind_verified"] == true));
    let fallbacks = rows.iter().filter_map(|row| row["body_utf8"].as_str()).collect::<Vec<_>>();
    assert!(fallbacks.iter().any(|text| text.contains("Task native-task accepted")));
    assert!(fallbacks.iter().any(|text| text.contains("Task native-task: done")));
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
