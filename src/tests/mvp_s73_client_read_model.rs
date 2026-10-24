// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Resolve every follow-up action from local directories after a real DM/attachment exchange.
#![cfg(feature = "realnet")]
use super::*;
use serde_json::{Value, json};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[test]
fn mvp_s73_realnet_client_read_model_actionable_ids() -> TestResult {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping s73: set RAMFLUX_ITEST_REALNET=1 on the QA container host");
        return Ok(());
    }
    if std::env::var("RAMFLUX_OBJECT_V3").as_deref() != Ok("1")
        || std::env::var("RAMFLUX_CROSS_GATEWAY").as_deref() != Ok("1")
    {
        return Err("s73 requires RAMFLUX_OBJECT_V3=1 RAMFLUX_CROSS_GATEWAY=1".into());
    }
    let mut stack = start_client_directory_stack(S8ComposePorts {
        gateway_http: 64_301,
        gateway_quic: 64_571,
        router_http: 64_300,
        router_mesh: 64_572,
        notify_http: 64_303,
        federation_http: 64_302,
        federation_mesh: 64_573,
        relay_http: 64_304,
        relay_media_udp: 64_240,
        signaling_turn_udp: 64_578,
        signaling_turn_tcp: 64_579,
        retention_http: 64_307,
    })?;
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(run(&stack.node))?;
    stack.node.guard.mark_success();
    Ok(())
}

async fn run(node: &S8RealnetNode) -> TestResult {
    wait_relay_quic_healthy(S73_RELAY_QUIC, "ramflux-relay", &node.ca_cert).await?;
    wait_for_private_gateway_quic(S73_GATEWAY_B_QUIC.parse()?, &node.ca_cert).await?;
    let root = temp_root("s73_read_model")?;
    let alice = PathBuf::from(format!("/tmp/rf-s73-alice-{}.sock", std::process::id()));
    let bob = PathBuf::from(format!("/tmp/rf-s73-bob-{}.sock", std::process::id()));
    let binary = mvp_s4_build_rf_binary().await?;
    let mut a = client_directory_daemon_command(
        &binary,
        &alice,
        &root.join("alice"),
        &node.ca_cert,
        Some("principal_s73_alice"),
    )
    .spawn()?;
    let mut b =
        client_directory_daemon_command(&binary, &bob, &root.join("bob"), &node.ca_cert, None)
            .spawn()?;
    let result = tokio::time::timeout(Duration::from_mins(5), async {
        mvp_s4_wait_for_socket(&alice).await?;
        mvp_s4_wait_for_socket(&bob).await?;
        let mut alice = ramflux_sdk::LocalBusClient::connect(&alice).await?;
        let mut bob = ramflux_sdk::LocalBusClient::connect(&bob).await?;
        let a = create(&mut alice, node, "alice", [0x73; 32], [0x74; 32]).await?;
        let b = create(&mut bob, node, "bob", [0x75; 32], [0x76; 32]).await?;
        seed(&mut alice, &mut bob, &a, &b).await?;
        actionable_ids(&mut alice, &mut bob).await?;
        locked_profile(&mut bob).await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })
    .await;
    let _ = a.start_kill();
    let _ = b.start_kill();
    let _ = a.wait().await;
    let _ = b.wait().await;
    let _ = std::fs::remove_file(alice);
    let _ = std::fs::remove_file(bob);
    result??;
    std::fs::remove_dir_all(root)?;
    Ok(())
}

pub(super) async fn call(
    bus: &mut ramflux_sdk::LocalBusClient,
    account: &str,
    method: &str,
    body: Value,
) -> TestResult<Value> {
    Ok(bus.request(Some(account.to_owned()), "client", method, serde_json::to_value(body)?).await?)
}

pub(super) async fn create(
    bus: &mut ramflux_sdk::LocalBusClient,
    node: &S8RealnetNode,
    id: &str,
    root_seed: [u8; 32],
    device_seed: [u8; 32],
) -> TestResult<Value> {
    let device = format!("{id}_s73_device");
    let target = format!("target_s73_{id}");
    let request = ramflux_sdk::LocalBusAccountCreateRequest {
        label: None,
        kind: None,
        node_id: None,
        local_account_id: id.to_owned(),
        principal_id: format!("principal_s73_{id}"),
        principal_commitment: String::new(),
        device_id: device.clone(),
        target_delivery_id: target.clone(),
        account_secret: "s73-test-secret".to_owned(),
        root_seed,
        device_seed,
        client_mode: ramflux_sdk::LocalBusClientMode::AttendedCli,
        gateway: ramflux_sdk::GatewayQuicEndpointConfig {
            bind_addr: "0.0.0.0:0".parse()?,
            gateway_addr: S73_GATEWAY_B_QUIC.parse()?,
            server_name: "localhost".to_owned(),
            ca_cert: node.ca_cert.clone(),
            principal_id: format!("principal_s73_{id}"),
            device_id: device,
            target_delivery_id: target,
            prekey_http_url: None,
        },
    };
    let mut request = serde_json::to_value(request)?;
    request["label"] = json!(format!("Profile {id}"));
    request["kind"] = json!("human");
    let response =
        bus.request(None, "account", "account.create", serde_json::to_value(request)?).await?;
    assert_eq!(response["local_account_id"], id);
    Ok(response)
}

async fn seed(
    alice: &mut ramflux_sdk::LocalBusClient,
    bob: &mut ramflux_sdk::LocalBusClient,
    a: &Value,
    b: &Value,
) -> TestResult {
    for (bus, id, from, to) in [(&mut *alice, "alice", a, b), (&mut *bob, "bob", b, a)] {
        let contact=call(bus,id,"contact.add",json!({"link_id":format!("friend_s73_{id}"),"requester_id":from["principal_commitment"],"target_id":to["principal_commitment"]})).await?;
        assert_eq!(contact["state"], "accepted");
    }
    call(alice,"alice","message.submit",json!({"conversation_id":"dm_s73","message_id":"message_s73_seed","envelope_id":"env_s73_seed","source_principal_id":a["principal_id"],"sender_id":a["device_id"],"recipient_device_id":b["device_id"],"recipient_principal_commitment":b["principal_commitment"],"target_delivery_id":b["target_delivery_id"],"encrypted_body_base64":"","plaintext_body_base64":ramflux_protocol::encode_base64url(b"seed with attachment"),"created_at":realnet_now_i64(),"ttl":3600,"attachments":[{"object_id":"attachment_s73","plaintext_base64":ramflux_protocol::encode_base64url(b"s73 attachment bytes"),"chunk_size":4096,"relay_endpoint":"http://127.0.0.1:64304","name":"sample.txt","mime":"text/plain"}]})).await?;
    let received = call(
        bob,
        "bob",
        "message.receive",
        json!({"conversation_id":"dm_s73","limit":20,"auto_fetch_attachments":true}),
    )
    .await?;
    assert!(serde_json::to_string(&received)?.contains("env_s73_seed"));
    Ok(())
}

async fn actionable_ids(
    alice: &mut ramflux_sdk::LocalBusClient,
    bob: &mut ramflux_sdk::LocalBusClient,
) -> TestResult {
    let conversations =
        call(alice, "alice", "conversation.directory", json!({"limit":100})).await?;
    let dm = &conversations["conversations"][0];
    assert_eq!(dm["kind"], "direct");
    let identities = call(alice, "alice", "identity.directory", json!({"limit":100})).await?;
    let peer = identities["identities"]
        .as_array()
        .ok_or("missing identities")?
        .iter()
        .find(|identity| {
            identity["contact_identity_commitment"]
                == dm["direct_route"]["recipient_principal_commitment"]
        })
        .ok_or("route commitment does not join identity")?;
    let own = identities["identities"]
        .as_array()
        .ok_or("missing identities")?
        .iter()
        .find(|identity| identity["is_self"] == true)
        .ok_or("self missing")?;
    let status = call(alice, "alice", "account.status", json!({})).await?;
    assert_eq!(status["principal_commitment"], own["principal_commitment"]);
    assert!(own["principal_commitment"].is_string());
    let device = &peer["devices"][0];
    assert!(device["signing_public_key"].is_string());
    call(alice,"alice","message.submit",json!({"conversation_id":dm["id"],"message_id":"message_s73_resolved","envelope_id":"env_s73_resolved","source_principal_id":dm["self_principal_id"],"sender_id":own["devices"][0]["device_id"],"recipient_device_id":device["device_id"],"recipient_principal_commitment":peer["contact_identity_commitment"],"target_delivery_id":device["target_delivery_id"],"encrypted_body_base64":"","plaintext_body_base64":ramflux_protocol::encode_base64url(b"resolved directory ids"),"created_at":realnet_now_i64(),"ttl":3600})).await?;
    let verified = call(
        alice,
        "alice",
        "contact.verify",
        json!({"contact_identity_commitment":peer["contact_identity_commitment"]}),
    )
    .await?;
    assert_eq!(verified["verification_state"], "verified");
    group(alice, own, peer).await?;
    let objects = call(bob, "bob", "object.directory", json!({"limit":100})).await?;
    let object = &objects["objects"][0];
    assert_eq!(object["conversation_id"], dm["id"]);
    assert_eq!(object["message_id"], "env_s73_seed");
    let encoded = serde_json::to_string(&objects)?;
    for forbidden in ["ciphertext", "object_content_key", "nonce", "s73 attachment bytes"] {
        assert!(!encoded.contains(forbidden));
    }
    let downloaded = call(bob, "bob", "object.get", json!({"object_id":object["id"]})).await?;
    assert_eq!(
        downloaded["plaintext_base64"],
        ramflux_protocol::encode_base64url(b"s73 attachment bytes")
    );
    approval_context(alice, dm).await?;
    Ok(())
}

async fn group(alice: &mut ramflux_sdk::LocalBusClient, own: &Value, peer: &Value) -> TestResult {
    let creator = &own["devices"][0];
    let member = &peer["devices"][0];
    call(alice,"alice","group.create",json!({"group_id":"group_s73","conversation_id":"thread_s73_group","creator_id":creator["device_id"],"creator_signing_public_key":creator["signing_public_key"],"creator_target_delivery_id":creator["target_delivery_id"]})).await?;
    let groups = call(alice, "alice", "group.list", json!({"limit":100})).await?;
    let group = &groups["groups"][0];
    assert_eq!(group["conversation_id"], "thread_s73_group");
    assert_ne!(group["conversation_id"], group["group_id"]);
    let added=call(alice,"alice","group.member.add",json!({"group_id":group["group_id"],"member_id":member["device_id"],"role":"member","member_signing_public_key":member["signing_public_key"],"member_principal_commitment":peer["contact_identity_commitment"],"target_delivery_id":member["target_delivery_id"]})).await?;
    assert!(
        serde_json::to_string(&added)?.contains(member["device_id"].as_str().ok_or("member id")?)
    );
    let sent=call(alice,"alice","group.send",json!({"group_id":group["group_id"],"conversation_id":group["conversation_id"],"message_id":"group_message_s73","sender_id":creator["device_id"],"encrypted_body_base64":"","plaintext_body_base64":ramflux_protocol::encode_base64url(b"group directory routing")})).await?;
    assert_eq!(sent["submitted"].as_array().map(Vec::len), Some(1));
    let directory = call(alice, "alice", "conversation.directory", json!({"limit":100})).await?;
    assert!(
        directory["conversations"]
            .as_array()
            .ok_or("missing conversations")?
            .iter()
            .any(
                |row| row["id"] == group["conversation_id"] && row["group_id"] == group["group_id"]
            )
    );
    Ok(())
}

async fn approval_context(alice: &mut ramflux_sdk::LocalBusClient, dm: &Value) -> TestResult {
    call(alice, "alice", "subscription.open", json!({"topics":["mcp.approval.request"]})).await?;
    call(alice,"alice","mcp.server.add",json!({"server_id":"server_s73","command":"stdio-echo","tool_name":"echo","capability":"read_conversation","risk_level":"low"})).await?;
    let started=call(alice,"alice","mcp.tool.started",json!({"server_id":"server_s73","tool_name":"echo","arguments":{"text":"s73"},"conversation_id":dm["id"],"context_id":"context_s73"})).await?;
    assert_eq!(started["status"], "approval_required");
    let event = tokio::time::timeout(Duration::from_secs(5), alice.next_event()).await??;
    assert_eq!(event.body["conversation_id"], dm["id"]);
    let approvals = call(alice, "alice", "mcp.approval.list", json!({"limit":100})).await?;
    assert_eq!(approvals["approvals"][0]["context_id"], "context_s73");
    let servers = call(alice, "alice", "mcp.server.list", json!({"limit":100})).await?;
    assert_eq!(servers["server_details"][0]["id"], "server_s73");
    assert!(servers["server_details"][0].get("reachable").is_some());
    assert!(servers["server_details"][0].get("last_check").is_some());
    Ok(())
}

async fn locked_profile(bob: &mut ramflux_sdk::LocalBusClient) -> TestResult {
    call(bob, "bob", "account.lock", json!({})).await?;
    let list = call(bob, "bob", "account.list", json!({})).await?;
    assert_eq!(list["account_details"][0]["state"], "locked");
    assert_eq!(list["account_details"][0]["label"], "Profile bob");
    assert_eq!(list["account_details"][0]["kind"], "human");
    Ok(())
}
