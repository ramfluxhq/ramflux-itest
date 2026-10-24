// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Deterministic participant replies through real rfd processes and authenticated gateway delivery.
#![cfg(feature = "realnet")]
use super::*;
use serde_json::{Value, json};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
#[path = "k5a_agent_host/surfaces.rs"]
mod surfaces;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
#[test]
fn k5a_realnet_agent_replies_in_dm_and_group() -> TestResult {
    scenario(false)
}
#[test]
fn k5a2_realnet_agent_surface() -> TestResult {
    scenario(true)
}
fn scenario(surface_case: bool) -> TestResult {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping k5a: set RAMFLUX_ITEST_REALNET=1 on the QA container host");
        return Ok(());
    }
    if std::env::var("RAMFLUX_OBJECT_V3").as_deref() != Ok("1")
        || std::env::var("RAMFLUX_CROSS_GATEWAY").as_deref() != Ok("1")
    {
        return Err("k5a requires RAMFLUX_OBJECT_V3=1 RAMFLUX_CROSS_GATEWAY=1".into());
    }
    let base = if surface_case { 64500 } else { 64600 };
    let mut stack = start_client_directory_stack_named(
        if surface_case { "ramflux-k5a2-agent-surfaces" } else { "ramflux-k5a-agent-host" },
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
        .block_on(run(&stack.node, surface_case))?;
    stack.node.guard.mark_success();
    Ok(())
}
async fn run(node: &S8RealnetNode, surface_case: bool) -> TestResult {
    wait_relay_quic_healthy(S73_RELAY_QUIC, "ramflux-relay", &node.ca_cert).await?;
    wait_for_private_gateway_quic(S73_GATEWAY_B_QUIC.parse()?, &node.ca_cert).await?;
    let root = temp_root("k5a")?;
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
    let a_socket = PathBuf::from(format!("/tmp/rf-k5a-a-{}.sock", std::process::id()));
    let b_socket = PathBuf::from(format!("/tmp/rf-k5a-b-{}.sock", std::process::id()));
    let rf = mvp_s4_build_rf_binary().await?;
    let manifest = code_root().join("ramflux/Cargo.toml");
    let status = tokio::process::Command::new("cargo")
        .args(["build", "--bin", "ramflux-agent-host", "--manifest-path"])
        .arg(manifest)
        .status()
        .await?;
    if !status.success() {
        return Err("agent host build failed".into());
    }
    let binary = code_root().join("ramflux/target/debug/ramflux-agent-host");
    let mut a =
        client_directory_daemon_command(&rf, &a_socket, &root.join("alice"), &node.ca_cert, None)
            .spawn()?;
    let mut b =
        client_directory_daemon_command(&rf, &b_socket, &root.join("agent"), &node.ca_cert, None)
            .spawn()?;
    let result=tokio::time::timeout(Duration::from_mins(5),async {
        mvp_s4_wait_for_socket(&a_socket).await?;mvp_s4_wait_for_socket(&b_socket).await?;
        let mut alice=ramflux_sdk::LocalBusClient::connect(&a_socket).await?;
        let mut agent=ramflux_sdk::LocalBusClient::connect(&b_socket).await?;
        let own=create(&mut alice,node,"alice",[0x51;32],[0x52;32],false).await?;
        let peer=create(&mut agent,node,"agent",[0x53;32],[0x54;32],true).await?;
        for (bus,id,from,to) in [(&mut alice,"alice",&own,&peer),(&mut agent,"agent",&peer,&own)]{
            let contact=call(bus,id,"contact.add",json!({"link_id":format!("friend_k5a_{id}"),"requester_id":from["principal_commitment"],"target_id":to["principal_commitment"]})).await?;assert_eq!(contact["state"],"accepted");
        }
        let config=root.join("host.json");let state=root.join("cursor.json");
        std::fs::write(&config,serde_json::to_vec(&json!({"socket":b_socket,"state_file":state,"account_id":"agent","per_conversation_interval_ms":100,"rules":[{"pattern":"@agent ping","reply":"pong"},{"pattern":"@agent summarize","reply":"Summary\n- deterministic\n- complete"},{"pattern":"@agent checklist","reply":surfaces::REPLY,"surface":{"chunk_bytes":256,"choices":[{"id":"thu","label":"Thursday"},{"id":"mon","label":"Monday"}],"close_on_action":true}}]}))?)?;
        let mut host=spawn_host(&binary,&config)?;wait_checkpoint(&state,None).await?;
        send_dm(&mut alice,&own,&peer,"ping_dm").await?;
        wait_replies(&mut alice,"dm_k5a",1,&peer).await?;
        create_group(&mut alice,&mut agent,&own,&peer).await?;
        call(&mut alice,"alice","group.send",json!({"group_id":"group_k5a","conversation_id":"group_thread_k5a","message_id":"ping_group","sender_id":own["device_id"],"encrypted_body_base64":"","plaintext_body_base64":ramflux_protocol::encode_base64url(b"@agent ping")})).await?;
        wait_replies(&mut alice,"group_thread_k5a",1,&peer).await?;
        let surface = if surface_case { Some(surfaces::round_trip(&mut alice,&own,&peer).await?) } else {None};
        let before=wait_checkpoint(&state,None).await?;
        host.start_kill()?;host.wait().await?;
        let previous_inode=std::fs::metadata(&state)?.ino();
        let mut host=spawn_host(&binary,&config)?;
        let after=wait_checkpoint(&state,Some(previous_inode)).await?;assert!(after>=before,"cursor must survive process restart");
        tokio::time::sleep(Duration::from_secs(2)).await;
        wait_replies(&mut alice,"dm_k5a",1,&peer).await?;wait_replies(&mut alice,"group_thread_k5a",1,&peer).await?;
        if let Some(before)=surface {surfaces::after_restart(&mut alice,&before).await?;}
        send_dm(&mut alice,&own,&peer,"ping_dm_after_restart").await?;
        wait_replies(&mut alice,"dm_k5a",2,&peer).await?;
        host.start_kill()?;host.wait().await?;
        Ok::<(),Box<dyn std::error::Error>>(())
    }).await;
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
fn spawn_host(binary: &Path, config: &Path) -> TestResult<tokio::process::Child> {
    Ok(tokio::process::Command::new(binary)
        .arg("--config")
        .arg(config)
        .kill_on_drop(true)
        .spawn()?)
}
async fn wait_checkpoint(path: &Path, previous_inode: Option<u64>) -> TestResult<u64> {
    for _ in 0..100 {
        if previous_inode.is_some_and(|inode| {
            std::fs::metadata(path).is_ok_and(|metadata| metadata.ino() == inode)
        }) {
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        }
        if let Ok(bytes) = std::fs::read(path)
            && let Ok(state) = serde_json::from_slice::<Value>(&bytes)
            && state["pending"].is_null()
            && let Some(cursor) = state["cursor"].as_u64()
        {
            return Ok(cursor);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err("agent checkpoint not ready".into())
}
async fn call(
    bus: &mut ramflux_sdk::LocalBusClient,
    account: &str,
    method: &str,
    body: Value,
) -> TestResult<Value> {
    Ok(bus.request(Some(account.into()), "client", method, body).await?)
}
async fn create(
    bus: &mut ramflux_sdk::LocalBusClient,
    node: &S8RealnetNode,
    id: &str,
    root_seed: [u8; 32],
    device_seed: [u8; 32],
    headless: bool,
) -> TestResult<Value> {
    let principal = format!("principal_k5a_{id}");
    let device = format!("device_k5a_{id}");
    let target = format!("target_k5a_{id}");
    let request = ramflux_sdk::LocalBusAccountCreateRequest {
        node_id: None,
        kind: None,
        label: None,
        local_account_id: id.into(),
        principal_id: principal.clone(),
        principal_commitment: String::new(),
        device_id: device.clone(),
        target_delivery_id: target.clone(),
        account_secret: "k5a-fixture-secret".into(),
        root_seed,
        device_seed,
        client_mode: if headless {
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
    let created =
        bus.request(None, "account", "account.create", serde_json::to_value(request)?).await?;
    if headless {
        assert_eq!(created["client_mode"], "headless_ai");
    }
    Ok(created)
}
async fn send_dm(
    bus: &mut ramflux_sdk::LocalBusClient,
    own: &Value,
    peer: &Value,
    id: &str,
) -> TestResult {
    call(bus,"alice","message.submit",json!({"conversation_id":"dm_k5a","message_id":id,"envelope_id":format!("env_{id}"),"source_principal_id":own["principal_id"],"sender_id":own["device_id"],"recipient_device_id":peer["device_id"],"recipient_principal_commitment":peer["principal_commitment"],"target_delivery_id":peer["target_delivery_id"],"encrypted_body_base64":"","plaintext_body_base64":ramflux_protocol::encode_base64url(b"@agent ping"),"created_at":realnet_now_i64(),"ttl":300})).await?;
    Ok(())
}
async fn wait_replies(
    alice: &mut ramflux_sdk::LocalBusClient,
    conversation: &str,
    count: usize,
    agent: &Value,
) -> TestResult {
    for _ in 0..100 {
        call(alice, "alice", "message.receive", json!({"limit":32,"auto_fetch_attachments":false}))
            .await?;
        let rows =
            call(alice, "alice", "message.read", json!({"conversation_id":conversation})).await?;
        let replies = rows["messages"]
            .as_array()
            .ok_or("missing messages")?
            .iter()
            .filter(|m| m["sender_id"] == agent["device_id"] && m["content_type"] != "surface")
            .collect::<Vec<_>>();
        if replies.len() > count {
            return Err("duplicate agent reply".into());
        }
        if replies.len() == count {
            for reply in replies {
                assert_eq!(reply["body_utf8"], "pong");
            }
            let identities =
                call(alice, "alice", "identity.directory", json!({"limit":100})).await?;
            assert!(identities["identities"].as_array().ok_or("missing identities")?.iter().any(
                |i| {
                    i["principal_id"] == agent["principal_id"]
                        && i["devices"].as_array().is_some_and(|ds| {
                            ds.iter().any(|d| d["device_id"] == agent["device_id"])
                        })
                }
            ));
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err("timed out waiting for agent reply".into())
}
async fn create_group(
    alice: &mut ramflux_sdk::LocalBusClient,
    agent: &mut ramflux_sdk::LocalBusClient,
    own: &Value,
    peer: &Value,
) -> TestResult {
    let a = call(alice, "alice", "identity.directory", json!({"limit":100})).await?;
    let b = call(agent, "agent", "identity.directory", json!({"limit":100})).await?;
    let creator = a["identities"]
        .as_array()
        .ok_or("identities")?
        .iter()
        .find(|v| v["principal_id"] == own["principal_id"])
        .ok_or("creator")?;
    let member = b["identities"]
        .as_array()
        .ok_or("identities")?
        .iter()
        .find(|v| v["principal_id"] == peer["principal_id"])
        .ok_or("member")?;
    call(alice,"alice","group.create",json!({"group_id":"group_k5a","conversation_id":"group_thread_k5a","creator_id":own["device_id"],"creator_signing_public_key":creator["devices"][0]["signing_public_key"],"creator_target_delivery_id":own["target_delivery_id"]})).await?;
    call(alice,"alice","group.member.add",json!({"group_id":"group_k5a","member_id":peer["device_id"],"role":"member","member_signing_public_key":member["devices"][0]["signing_public_key"],"member_principal_commitment":peer["principal_commitment"],"target_delivery_id":peer["target_delivery_id"]})).await?;
    Ok(())
}
