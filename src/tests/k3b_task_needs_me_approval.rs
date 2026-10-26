// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Task negotiation and single-use human approval on a second device over encrypted realnet DM.
#![cfg(feature = "realnet")]
use super::*;
use serde_json::{Value, json};
#[path = "k3b_task_needs_me_approval/actors.rs"]
mod actors;
use actors::*;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
#[test]
fn k3b_realnet_task_needs_me_approval() -> TestResult {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping K3b realnet; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }
    if std::env::var("RAMFLUX_OBJECT_V3").as_deref() != Ok("1")
        || std::env::var("RAMFLUX_CROSS_GATEWAY").as_deref() != Ok("1")
    {
        return Err("K3b requires RAMFLUX_OBJECT_V3=1 RAMFLUX_CROSS_GATEWAY=1".into());
    }
    let mut stack = start_client_directory_stack_named(
        "ramflux-k3b-tasks",
        S8ComposePorts {
            gateway_http: 64801,
            gateway_quic: 64871,
            router_http: 64800,
            router_mesh: 64872,
            notify_http: 64803,
            federation_http: 64802,
            federation_mesh: 64873,
            relay_http: 64804,
            relay_media_udp: 64840,
            signaling_turn_udp: 64878,
            signaling_turn_tcp: 64879,
            retention_http: 64807,
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
    let root = temp_root("k3b")?;
    let rf = mvp_s4_build_rf_binary().await?;
    let sockets = ["human", "human2", "agent"]
        .map(|id| PathBuf::from(format!("/tmp/rf-k3b-{id}-{}.sock", std::process::id())));
    let mut children = Vec::new();
    for (id, socket) in ["human", "human2", "agent"].into_iter().zip(&sockets) {
        children.push(
            client_directory_daemon_command(&rf, socket, &root.join(id), &node.ca_cert, None)
                .env("RAMFLUX_TEST_TASK_APPROVAL_DIAGNOSTICS", "1")
                .spawn()?,
        );
    }
    let result=tokio::time::timeout(Duration::from_mins(6),async{
        for socket in &sockets{mvp_s4_wait_for_socket(socket).await?;}
        let mut human=ramflux_sdk::LocalBusClient::connect(&sockets[0]).await?;
        let mut human2=ramflux_sdk::LocalBusClient::connect(&sockets[1]).await?;
        let mut agent=ramflux_sdk::LocalBusClient::connect(&sockets[2]).await?;
        let a=create(&mut human,node,"human","human",(41,42),false).await?;
        create(&mut human2,node,"human2","human",(41,43),false).await?;
        let b=create(&mut agent,node,"agent","agent",(45,46),true).await?;
        for (bus,id,own,peer) in [(&mut human,"human",&a,&b),(&mut agent,"agent",&b,&a)]{
            let accepted=call(bus,id,"contact.add",json!({"link_id":format!("k3b-{id}"),"requester_id":own["principal_commitment"],"target_id":peer["principal_commitment"]})).await?;
            assert_eq!(accepted["state"],"accepted");
        }
        call(&mut human,"human","message.submit",json!({"conversation_id":"dm_k3b","message_id":"ask-k3b","envelope_id":"ask-envelope-k3b","source_principal_id":a["principal_id"],"sender_id":a["device_id"],"recipient_device_id":b["device_id"],"recipient_principal_commitment":b["principal_commitment"],"target_delivery_id":b["target_delivery_id"],"encrypted_body_base64":"","plaintext_body_base64":ramflux_protocol::encode_base64url(b"Please investigate"),"created_at":realnet_now_i64(),"ttl":600})).await?;
        wait_conversation(&mut agent,"agent").await?;
        negotiate(&mut human,&mut human2,&mut agent,&a,&b).await?;
        Ok::<(),Box<dyn std::error::Error>>(())
    }).await;
    for child in &mut children {
        let _ = child.start_kill();
        let _ = child.wait().await;
    }
    for socket in sockets {
        let _ = std::fs::remove_file(socket);
    }
    result??;
    std::fs::remove_dir_all(root)?;
    Ok(())
}
async fn negotiate(
    human: &mut ramflux_sdk::LocalBusClient,
    human2: &mut ramflux_sdk::LocalBusClient,
    agent: &mut ramflux_sdk::LocalBusClient,
    a: &Value,
    b: &Value,
) -> TestResult {
    let proposed=call(agent,"agent","task.propose",json!({"conversation_id":"dm_k3b","task_id":"task-k3b","message_id":"propose-k3b","assignee":b["principal_id"],"title":"Investigate","steps":[{"id":"step","title":"Run shell","state":"proposed"}]})).await?;
    assert_eq!(proposed["accepted"], true);
    wait_task(human, "human", "dm_k3b", 1).await?;
    let rejected = call(
        agent,
        "agent",
        "task.accept",
        json!({"conversation_id":"dm_k3b","task_id":"task-k3b","version":2}),
    )
    .await
    .err()
    .ok_or("agent accepted its own proposal")?;
    assert!(rejected.to_string().contains("task human decision requires attended human account"));
    let accepted=call(human,"human","task.accept",json!({"conversation_id":"dm_k3b","task_id":"task-k3b","message_id":"accept-k3b","version":2})).await?;
    assert_eq!(accepted["accepted"], true);
    wait_task(agent, "agent", "dm_k3b", 2).await?;
    call(agent,"agent","task.update",json!({"conversation_id":"dm_k3b","task_id":"task-k3b","version":3,"state":"running","steps":[{"id":"step","title":"Run shell","state":"running"}]})).await?;
    let approval = approval(agent).await?;
    let grant_id = approval["details"]["requested_grant_id"].as_str().map_or_else(
        || format!("grant_{}", approval["approval_id"].as_str().unwrap_or_default()),
        str::to_owned,
    );
    call(agent,"agent","task.update",json!({"conversation_id":"dm_k3b","task_id":"task-k3b","version":4,"state":"needs_me","steps":[{"id":"step","title":"Run shell","state":"needs_me","needs_me":{"kind":"approval","grant_id":grant_id}}]})).await?;
    let current = wait_task(human2, "human2", "dm_k3b", 4).await?;
    assert_eq!(current["requester"], a["principal_id"]);
    let mut resolve = json!({"conversation_id":"dm_k3b","task_id":"task-k3b","message_id":"resolve-k3b","base_revision":4,"step_id":"step","target":{"kind":"approval","grant_id":grant_id},"decision_id":approval["approval_id"],"decision":"resume"});
    let rejected = call(agent, "agent", "task.resolve", resolve.clone())
        .await
        .err()
        .ok_or("agent resolved its own intervention")?;
    assert!(rejected.to_string().contains("task human decision requires attended human account"));
    let decision = grant_from_second_human_device(human2, agent, &grant_id).await?;
    assert_eq!(decision["decision_id"], approval["approval_id"]);
    resolve["decision_id"] = decision["approval_id"].clone();
    let resolving = call(human2, "human2", "task.resolve", resolve.clone()).await?;
    assert_eq!(
        resolving["pending"], true,
        "requester must await the assignee's actual grant check"
    );
    wait_task(agent, "agent", "dm_k3b", 5).await?;
    wait_task(human2, "human2", "dm_k3b", 5).await?;
    wait_task(human, "human", "dm_k3b", 5).await?;
    let mut replay = resolve;
    replay["message_id"] = json!("replay-k3b");
    assert!(call(human2, "human2", "task.resolve", replay).await.is_err());
    let ran=call(agent,"agent","mcp.tool.started",json!({"server_id":"server-k3b","tool_name":"shell","arguments":{"cmd":"echo task"},"operation_origin":"ai_mcp"})).await?;
    assert_eq!(ran["status"], "ok");
    let reused=call(agent,"agent","mcp.tool.started",json!({"server_id":"server-k3b","tool_name":"shell","arguments":{"cmd":"echo task"},"operation_origin":"ai_mcp"})).await?;
    assert_eq!(
        reused["status"], "approval_required",
        "tool grant remains single-use after task resolution"
    );
    call(agent,"agent","task.update",json!({"conversation_id":"dm_k3b","task_id":"task-k3b","version":6,"state":"done","steps":[{"id":"step","title":"Run shell","state":"done"}]})).await?;
    assert_eq!(wait_task(human, "human", "dm_k3b", 6).await?["state"], "done");
    let messages =
        call(human, "human", "message.read", json!({"conversation_id":"dm_k3b"})).await?;
    let task_rows = messages["messages"]
        .as_array()
        .ok_or("message timeline missing")?
        .iter()
        .filter(|row| row["content_type"] == "task" && row["task_id"] == "task-k3b")
        .collect::<Vec<_>>();
    assert!(!task_rows.is_empty(), "committed task timeline missing");
    assert!(task_rows.iter().all(|row| row["actor_kind_verified"] == true));
    let fallbacks =
        task_rows.iter().filter_map(|row| row["body_utf8"].as_str()).collect::<Vec<_>>();
    assert!(fallbacks.iter().any(|text| text.contains("Task task-k3b accepted")));
    assert!(fallbacks.iter().any(|text| text.contains("Task task-k3b: done")));
    assert!(fallbacks.iter().all(|text| !text.contains("actor kind unverified")));
    Ok(())
}
