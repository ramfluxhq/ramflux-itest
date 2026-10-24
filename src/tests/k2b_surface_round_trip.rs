// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Authenticated surface authoring, decisions, fallback and encrypted account restart.
#![cfg(feature = "realnet")]
use super::*;
use serde_json::{Value, json};
#[path = "k2b_surface_round_trip/actors.rs"]
mod actors;
#[path = "k2b_surface_round_trip/raw_probe.rs"]
mod raw_probe;
use actors::*;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
#[test]
fn k2b_realnet_surface_round_trip() -> TestResult {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping k2b: set RAMFLUX_ITEST_REALNET=1 on the QA container host");
        return Ok(());
    }
    if std::env::var("RAMFLUX_OBJECT_V3").as_deref() != Ok("1")
        || std::env::var("RAMFLUX_CROSS_GATEWAY").as_deref() != Ok("1")
    {
        return Err("k2b requires RAMFLUX_OBJECT_V3=1 RAMFLUX_CROSS_GATEWAY=1".into());
    }
    let mut stack = start_client_directory_stack_named(
        "ramflux-k2b-surfaces",
        S8ComposePorts {
            gateway_http: 64701,
            gateway_quic: 64771,
            router_http: 64700,
            router_mesh: 64772,
            notify_http: 64703,
            federation_http: 64702,
            federation_mesh: 64773,
            relay_http: 64704,
            relay_media_udp: 64740,
            signaling_turn_udp: 64778,
            signaling_turn_tcp: 64779,
            retention_http: 64707,
        },
        &[],
    )?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(run(&stack.node))?;
    stack.node.guard.mark_success();
    Ok(())
}
async fn run(node: &S8RealnetNode) -> TestResult {
    wait_relay_quic_healthy(S73_RELAY_QUIC, "ramflux-relay", &node.ca_cert).await?;
    wait_for_private_gateway_quic(S73_GATEWAY_B_QUIC.parse()?, &node.ca_cert).await?;
    let root = temp_root("k2b")?;
    let a_socket = PathBuf::from(format!("/tmp/rf-k2b-a-{}.sock", std::process::id()));
    let b_socket = PathBuf::from(format!("/tmp/rf-k2b-b-{}.sock", std::process::id()));
    let rf = mvp_s4_build_rf_binary().await?;
    let mut a =
        client_directory_daemon_command(&rf, &a_socket, &root.join("human"), &node.ca_cert, None)
            .spawn()?;
    let mut b =
        client_directory_daemon_command(&rf, &b_socket, &root.join("agent"), &node.ca_cert, None)
            .spawn()?;
    let human_sibling_socket = PathBuf::from(format!("/tmp/rf-k2b-a2-{}.sock", std::process::id()));
    let agent_sibling_socket = PathBuf::from(format!("/tmp/rf-k2b-b2-{}.sock", std::process::id()));
    let mut a2 = client_directory_daemon_command(
        &rf,
        &human_sibling_socket,
        &root.join("human2"),
        &node.ca_cert,
        None,
    )
    .spawn()?;
    let mut b2 = client_directory_daemon_command(
        &rf,
        &agent_sibling_socket,
        &root.join("agent2"),
        &node.ca_cert,
        None,
    )
    .spawn()?;
    let result=tokio::time::timeout(Duration::from_mins(6),async {
        mvp_s4_wait_for_socket(&a_socket).await?;mvp_s4_wait_for_socket(&b_socket).await?;
        let mut human=ramflux_sdk::LocalBusClient::connect(&a_socket).await?;let mut agent=ramflux_sdk::LocalBusClient::connect(&b_socket).await?;
        let own=create(&mut human,node,"human",41,false).await?;let peer=create(&mut agent,node,"agent",45,true).await?;
        mvp_s4_wait_for_socket(&human_sibling_socket).await?;mvp_s4_wait_for_socket(&agent_sibling_socket).await?;
        let mut human2=ramflux_sdk::LocalBusClient::connect(&human_sibling_socket).await?;
        let mut agent2=ramflux_sdk::LocalBusClient::connect(&agent_sibling_socket).await?;
        create_terminal(&mut human2,node,"human2","human",(41,43),false).await?;
        create_terminal(&mut agent2,node,"agent2","agent",(45,47),true).await?;
        contacts(&mut human,&mut agent,&own,&peer).await?;
        call(&mut human,"human","message.submit",json!({"conversation_id":"dm_k2b","message_id":"seed","envelope_id":"seed_k2b","source_principal_id":own["principal_id"],"sender_id":own["device_id"],"recipient_device_id":peer["device_id"],"recipient_principal_commitment":peer["principal_commitment"],"target_delivery_id":peer["target_delivery_id"],"encrypted_body_base64":"","plaintext_body_base64":ramflux_protocol::encode_base64url(b"surface conversation"),"created_at":realnet_now_i64(),"ttl":300})).await?;
        wait_conversation(&mut agent,"agent","dm_k2b").await?;
        round_trip(&mut human,&mut agent,(&mut human2,&mut agent2),&b_socket,"dm_k2b","surface-dm").await?;
        group(&mut human,&mut agent,&own,&peer).await?;
        round_trip(&mut human,&mut agent,(&mut human2,&mut agent2),&b_socket,"group_thread_k2b","surface-group").await?;
        let before=call(&mut human,"human","surface.get",json!({"surface_id":"surface-group"})).await?;
        drop(human);a.start_kill()?;a.wait().await?;let _=std::fs::remove_file(&a_socket);
        a=client_directory_daemon_command(&rf,&a_socket,&root.join("human"),&node.ca_cert,None).spawn()?;mvp_s4_wait_for_socket(&a_socket).await?;
        let mut human=ramflux_sdk::LocalBusClient::connect(&a_socket).await?;
        assert_eq!(call(&mut human,"human","surface.get",json!({"surface_id":"surface-group"})).await?,before,"surface snapshot/history/finality must survive rfd restart");
        let messages=call(&mut human,"human","message.read",json!({"conversation_id":"group_thread_k2b"})).await?;
        assert!(messages["messages"].as_array().ok_or("messages")?.iter().any(|row|row["content_type"]=="surface" && row["body_utf8"]=="Surface author=\"principal_k2b_agent\" fallback_text=\"Completed result\""));
        Ok::<(),Box<dyn std::error::Error>>(())
    }).await;
    let _ = a2.start_kill();
    let _ = b2.start_kill();
    let _ = a2.wait().await;
    let _ = b2.wait().await;
    let _ = std::fs::remove_file(human_sibling_socket);
    let _ = std::fs::remove_file(agent_sibling_socket);
    let _ = a.start_kill();
    let _ = b.start_kill();
    let _ = a.wait().await;
    let _ = b.wait().await;
    let _ = std::fs::remove_file(a_socket);
    let _ = std::fs::remove_file(b_socket);
    result??;
    std::fs::remove_dir_all(root)?;
    Ok(())
}
async fn round_trip(
    human: &mut ramflux_sdk::LocalBusClient,
    agent: &mut ramflux_sdk::LocalBusClient,
    siblings: (&mut ramflux_sdk::LocalBusClient, &mut ramflux_sdk::LocalBusClient),
    b_socket: &Path,
    conversation: &str,
    surface: &str,
) -> TestResult {
    use ramflux_protocol::{
        A2uiConversationCommand as C, CreateSurfaceCommand, PatchSurfaceCommand,
        StreamAppendCommand, SurfacePatchOp, SurfaceType,
    };
    let (human2, agent2) = siblings;
    let content = CreateSurfaceCommand {
        surface_id: surface.into(),
        surface_type: SurfaceType::StatusPanel,
        catalog: "basic".into(),
        catalog_version: "1".into(),
        fallback_text: "Working".into(),
        fallback_markdown: None,
        components: vec![json!({"id":"progress","text":""}), json!({"id":"result","text":""})],
        data_model: serde_json::Map::default(),
        allowed_actions: vec![json!({"name":"approve"})],
    };
    send_event(agent, conversation, surface, "create", 1, C::CreateSurface(content)).await?;
    let first = wait_surface(human, "human", surface, 1).await?;
    send_event(
        agent,
        conversation,
        surface,
        "stream",
        2,
        C::StreamAppend(StreamAppendCommand {
            surface_id: surface.into(),
            component_id: "progress".into(),
            text_delta: "Working...".into(),
            final_: true,
        }),
    )
    .await?;
    let current = wait_surface(human, "human", surface, 2).await?;
    for (bus, account) in [(&mut *human2, "human2"), (&mut *agent2, "agent2")] {
        let other = wait_surface(bus, account, surface, 2).await?;
        assert_eq!(other["surface_hash"], current["surface_hash"]);
    }
    let stale =
        action_wire(conversation, surface, 1, first["surface_hash"].as_str().ok_or("hash")?)?;
    assert_eq!(call(human,"human","surface.action",json!({"conversation_id":conversation,"message_id":format!("{surface}-stale"),"wire_base64":ramflux_protocol::encode_base64url(&stale)})).await?["accepted"],false);
    raw_probe::reject_at_author(human, agent, b_socket, conversation, (surface, "action"), &stale)
        .await?;
    let unauthorized = wire(
        conversation,
        3,
        C::PatchSurface(PatchSurfaceCommand {
            surface_id: surface.into(),
            base_surface_hash: current["surface_hash"].as_str().ok_or("hash")?.into(),
            new_surface_hash: current["surface_hash"].as_str().ok_or("hash")?.into(),
            ops: vec![SurfacePatchOp::SetFallbackText { fallback_text: "forged status".into() }],
        }),
    )?;
    raw_probe::reject_at_author(
        human,
        agent,
        b_socket,
        conversation,
        (surface, "event"),
        &unauthorized,
    )
    .await?;
    let mut watcher = ramflux_sdk::LocalBusClient::connect(b_socket).await?;
    call(&mut watcher, "agent", "bus.subscribe", json!({"topics":["surface.changed"]})).await?;
    let action =
        action_wire(conversation, surface, 2, current["surface_hash"].as_str().ok_or("hash")?)?;
    let request = json!({"conversation_id":conversation,"message_id":format!("{surface}-action"),"wire_base64":ramflux_protocol::encode_base64url(&action)});
    assert_eq!(call(human, "human", "surface.action", request.clone()).await?["accepted"], true);
    let accepted = wait_action(agent, surface).await?;
    assert_eq!(accepted["actions"].as_array().map(Vec::len), Some(1));
    let event = tokio::time::timeout(Duration::from_secs(10), watcher.next_event()).await??;
    assert_eq!(event.method, "surface.changed");
    assert!(event.body.get("snapshot").is_none());
    assert!(event.body.get("fallback_text").is_none());
    assert!(event.body.get("actions").is_none());
    assert!(!event.body.to_string().contains("PRIVATE_FORM_VALUE"));
    let replay = call(human, "human", "surface.action", request).await?;
    assert_eq!(replay["replayed"], true);
    reject_non_author_patch(
        human,
        conversation,
        surface,
        current["surface_hash"].as_str().ok_or("hash")?,
    )
    .await?;
    check_replica(agent, agent2, surface, &accepted).await?;
    let closed = finish_surface(human, agent, conversation, surface, &current).await?;
    for (bus, account) in [(human2, "human2"), (agent2, "agent2")] {
        let other = wait_surface(bus, account, surface, 4).await?;
        assert_eq!(other["surface_hash"], closed["surface_hash"]);
        assert_eq!(other["closed"], true);
    }
    assert_eq!(closed["hash_history"].as_array().map(Vec::len), Some(4));
    let list =
        call(human, "human", "surface.list", json!({"conversation_id":conversation})).await?;
    assert!(
        list["surfaces"].as_array().ok_or("surfaces")?.iter().any(|v| v["surface_id"] == surface)
    );
    Ok(())
}

async fn finish_surface(
    human: &mut ramflux_sdk::LocalBusClient,
    agent: &mut ramflux_sdk::LocalBusClient,
    conversation: &str,
    surface: &str,
    current: &Value,
) -> TestResult<Value> {
    use ramflux_protocol::{
        A2uiConversationCommand as C, CreateSurfaceCommand, DeleteSurfaceCommand,
        PatchSurfaceCommand, SurfacePatchOp,
    };
    let mut after: CreateSurfaceCommand = serde_json::from_value(current["snapshot"].clone())?;
    after.components[1]["text"] = json!("Complete");
    after.fallback_text = "Completed result".into();
    send_event(
        agent,
        conversation,
        surface,
        "result",
        3,
        C::PatchSurface(PatchSurfaceCommand {
            surface_id: surface.into(),
            base_surface_hash: current["surface_hash"].as_str().ok_or("hash")?.into(),
            ops: vec![
                SurfacePatchOp::ReplaceBlock { component: after.components[1].clone() },
                SurfacePatchOp::SetFallbackText { fallback_text: after.fallback_text.clone() },
            ],
            new_surface_hash: ramflux_protocol::surface_snapshot_hash(&after)?,
        }),
    )
    .await?;
    let updated = wait_surface(human, "human", surface, 3).await?;
    assert_eq!(updated["snapshot"]["fallbackText"], "Completed result");
    send_event(
        agent,
        conversation,
        surface,
        "close",
        4,
        C::DeleteSurface(DeleteSurfaceCommand { surface_id: surface.into(), reason: None }),
    )
    .await?;
    let closed = wait_surface(human, "human", surface, 4).await?;
    assert_eq!(closed["closed"], true);
    let resync = call(agent,"agent","surface.resync",json!({"surface_ref":closed["surface_ref"],"message_id":format!("{surface}-explicit-resync")})).await?;
    assert_eq!(resync["accepted"], true);
    assert_eq!(resync["delivery_state"], "submitted");
    Ok(closed)
}

async fn check_replica(
    agent: &mut ramflux_sdk::LocalBusClient,
    agent2: &mut ramflux_sdk::LocalBusClient,
    surface: &str,
    accepted: &Value,
) -> TestResult {
    let replica = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            call(
                agent,
                "agent",
                "message.receive",
                json!({"limit":32,"auto_fetch_attachments":false}),
            )
            .await?;
            call(
                agent2,
                "agent2",
                "message.receive",
                json!({"limit":32,"auto_fetch_attachments":false}),
            )
            .await?;
            let view = call(agent2, "agent2", "surface.get", json!({"surface_id":surface})).await?;
            if view["actions"].as_array().is_some_and(|a| a.len() == 1) {
                return Ok::<_, Box<dyn std::error::Error>>(view);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await??;
    assert_eq!(accepted["actions"][0]["actionable"], true);
    assert_eq!(replica["actions"][0]["actionable"], false);
    assert_eq!(replica["actions"][0]["message_id"], accepted["actions"][0]["message_id"]);
    Ok(())
}
