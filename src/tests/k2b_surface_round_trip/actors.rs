// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain
use super::*;
pub(super) async fn call(
    bus: &mut ramflux_sdk::LocalBusClient,
    account: &str,
    method: &str,
    body: Value,
) -> TestResult<Value> {
    Ok(bus.request(Some(account.into()), "surface", method, body).await?)
}
pub(super) async fn create(
    bus: &mut ramflux_sdk::LocalBusClient,
    node: &S8RealnetNode,
    id: &str,
    seed: u8,
    headless: bool,
) -> TestResult<Value> {
    create_terminal(bus, node, id, id, (seed, seed + 1), headless).await
}
pub(super) async fn create_terminal(
    bus: &mut ramflux_sdk::LocalBusClient,
    node: &S8RealnetNode,
    id: &str,
    owner: &str,
    seeds: (u8, u8),
    headless: bool,
) -> TestResult<Value> {
    let (root_seed, device_seed) = seeds;
    let principal = format!("principal_k2b_{owner}");
    let device = format!("device_k2b_{id}");
    let target = format!("target_k2b_{id}");
    let request = ramflux_sdk::LocalBusAccountCreateRequest {
        node_id: None,
        local_account_id: id.into(),
        principal_id: principal.clone(),
        principal_commitment: String::new(),
        device_id: device.clone(),
        target_delivery_id: target.clone(),
        account_secret: "k2b-fixture-secret".into(),
        root_seed: [root_seed; 32],
        device_seed: [device_seed; 32],
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
    Ok(bus.request(None, "account", "account.create", serde_json::to_value(request)?).await?)
}
pub(super) async fn contacts(
    human: &mut ramflux_sdk::LocalBusClient,
    agent: &mut ramflux_sdk::LocalBusClient,
    a: &Value,
    b: &Value,
) -> TestResult {
    for (bus, id, own, peer) in [(human, "human", a, b), (agent, "agent", b, a)] {
        let added=call(bus,id,"contact.add",json!({"link_id":format!("link-k2b-{id}"),"requester_id":own["principal_commitment"],"target_id":peer["principal_commitment"]})).await?;
        assert_eq!(added["state"], "accepted");
    }
    Ok(())
}
pub(super) async fn wait_conversation(
    bus: &mut ramflux_sdk::LocalBusClient,
    account: &str,
    id: &str,
) -> TestResult {
    for _ in 0..100 {
        call(bus, account, "message.receive", json!({"limit":32,"auto_fetch_attachments":false}))
            .await?;
        let list = call(bus, account, "conversation.directory", json!({"limit":100})).await?;
        if list["conversations"]
            .as_array()
            .ok_or("conversations")?
            .iter()
            .any(|row| row["id"] == id)
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err("conversation did not arrive".into())
}
pub(super) async fn wait_surface(
    bus: &mut ramflux_sdk::LocalBusClient,
    account: &str,
    id: &str,
    version: u64,
) -> TestResult<Value> {
    for _ in 0..100 {
        call(bus, account, "message.receive", json!({"limit":32,"auto_fetch_attachments":false}))
            .await?;
        let view = call(bus, account, "surface.get", json!({"surface_id":id})).await?;
        if view["version"] == version {
            return Ok(view);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err("surface version did not arrive".into())
}
pub(super) async fn wait_action(
    bus: &mut ramflux_sdk::LocalBusClient,
    id: &str,
) -> TestResult<Value> {
    for _ in 0..100 {
        call(bus, "agent", "message.receive", json!({"limit":32,"auto_fetch_attachments":false}))
            .await?;
        let view = call(bus, "agent", "surface.get", json!({"surface_id":id})).await?;
        if view["actions"].as_array().is_some_and(|actions| actions.len() == 1) {
            return Ok(view);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err("surface action did not reach the author".into())
}
pub(super) fn wire(
    conversation: &str,
    version: u64,
    command: ramflux_protocol::A2uiConversationCommand,
) -> TestResult<Vec<u8>> {
    let command = serde_json::to_value(command)?;
    Ok(serde_json::to_vec(
        &json!({"schema":"ramflux.a2ui.conversation.v2","conversationId":conversation,"version":version,"command":command}),
    )?)
}
pub(super) async fn send_event(
    bus: &mut ramflux_sdk::LocalBusClient,
    conversation: &str,
    surface: &str,
    suffix: &str,
    version: u64,
    command: ramflux_protocol::A2uiConversationCommand,
) -> TestResult {
    let bytes = wire(conversation, version, command)?;
    let result=call(bus,"agent","surface.send",json!({"conversation_id":conversation,"message_id":format!("{surface}-{suffix}"),"wire_base64":ramflux_protocol::encode_base64url(bytes)})).await?;
    assert_eq!(result["accepted"], true, "surface event rejected: {result}");
    assert_eq!(
        result["delivery_state"], "submitted",
        "surface must complete the normal text submission path: {result}"
    );
    Ok(())
}
pub(super) fn action_wire(
    conversation: &str,
    surface: &str,
    version: u64,
    hash: &str,
) -> TestResult<Vec<u8>> {
    let values = json!({"confirmation":"PRIVATE_FORM_VALUE"});
    Ok(serde_json::to_vec(
        &json!({"schema":"ramflux.a2ui.action.v2","conversationId":conversation,"surfaceId":surface,"version":version,"surfaceHash":hash,"actionId":"approve","values":values,"argsHash":ramflux_protocol::surface_args_hash(&values)?}),
    )?)
}
pub(super) async fn group(
    human: &mut ramflux_sdk::LocalBusClient,
    agent: &mut ramflux_sdk::LocalBusClient,
    own: &Value,
    peer: &Value,
) -> TestResult {
    let a = call(human, "human", "identity.directory", json!({"limit":100})).await?;
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
    call(human,"human","group.create",json!({"group_id":"group_k2b","conversation_id":"group_thread_k2b","creator_id":own["device_id"],"creator_signing_public_key":creator["devices"][0]["signing_public_key"],"creator_target_delivery_id":own["target_delivery_id"]})).await?;
    call(human,"human","group.member.add",json!({"group_id":"group_k2b","member_id":peer["device_id"],"role":"member","member_signing_public_key":member["devices"][0]["signing_public_key"],"member_principal_commitment":peer["principal_commitment"],"target_delivery_id":peer["target_delivery_id"]})).await?;
    // Membership control must be delivered before the participant authors into this group.
    for _ in 0..100 {
        call(agent, "agent", "message.receive", json!({"limit":32,"auto_fetch_attachments":false}))
            .await?;
        let groups = call(agent, "agent", "group.list", json!({"limit":100})).await?;
        if groups["groups"]
            .as_array()
            .is_some_and(|groups| groups.iter().any(|g| g["group_id"] == "group_k2b"))
        {
            // Seed the group conversation link through a normal human message.
            call(human,"human","group.send",json!({"group_id":"group_k2b","conversation_id":"group_thread_k2b","message_id":"group-k2b-seed","sender_id":own["device_id"],"encrypted_body_base64":"","plaintext_body_base64":ramflux_protocol::encode_base64url(b"group surface conversation")})).await?;
            return wait_conversation(agent, "agent", "group_thread_k2b").await;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err("agent group membership did not arrive".into())
}

pub(super) async fn reject_non_author_patch(
    bus: &mut ramflux_sdk::LocalBusClient,
    conversation: &str,
    surface: &str,
    hash: &str,
) -> TestResult {
    use ramflux_protocol::{A2uiConversationCommand, PatchSurfaceCommand, SurfacePatchOp};
    let bytes = wire(
        conversation,
        3,
        A2uiConversationCommand::PatchSurface(PatchSurfaceCommand {
            surface_id: surface.into(),
            base_surface_hash: hash.into(),
            new_surface_hash: hash.into(),
            ops: vec![SurfacePatchOp::SetFallbackText {
                fallback_text: "unauthorized patch".into(),
            }],
        }),
    )?;
    let result=call(bus,"human","surface.send",json!({"conversation_id":conversation,"message_id":format!("{surface}-non-author"),"wire_base64":ramflux_protocol::encode_base64url(bytes)})).await?;
    assert_eq!(result["accepted"], false);
    assert_eq!(result["renderer_error"]["code"], "non_author_update");
    Ok(())
}
