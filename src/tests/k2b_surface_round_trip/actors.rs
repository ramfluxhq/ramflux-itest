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
        kind: None,
        label: None,
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
    let mut observed = Value::Null;
    for _ in 0..100 {
        call(bus, account, "message.receive", json!({"limit":32,"auto_fetch_attachments":false}))
            .await?;
        let view = call(bus, account, "surface.get", json!({"surface_id":id})).await?;
        observed = json!({"version":view["version"],"out_of_sync":view["out_of_sync"],"renderer_error_code":view["renderer_error"]["code"]});
        if view["version"] == version {
            return Ok(view);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(format!("surface version did not arrive: account={account} surface_id={id} expected_version={version} observed={observed}").into())
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
    human2: &mut ramflux_sdk::LocalBusClient,
    own: &Value,
    peer: &Value,
    own2: &Value,
) -> TestResult {
    let a = call(human, "human", "identity.directory", json!({"limit":100})).await?;
    let b = call(agent, "agent", "identity.directory", json!({"limit":100})).await?;
    let c = call(human2, "human2", "identity.directory", json!({"limit":100})).await?;
    let creator = device(&a, own)?;
    call(human,"human","group.create",json!({"group_id":"group_k2b","conversation_id":"group_thread_k2b","creator_id":own["device_id"],"creator_signing_public_key":creator["signing_public_key"],"creator_target_delivery_id":own["target_delivery_id"]})).await?;
    // Normal group text delivery addresses member devices. A peer sibling must join explicitly;
    // sharing its identity root alone cannot grant group membership or a delivery route.
    for (account, directory) in [(peer, &b), (own2, &c)] {
        let member = device(directory, account)?;
        call(human,"human","group.member.add",json!({"group_id":"group_k2b","member_id":account["device_id"],"role":"member","member_signing_public_key":member["signing_public_key"],"member_principal_commitment":account["principal_commitment"],"target_delivery_id":account["target_delivery_id"]})).await?;
    }
    for (bus, id) in [(agent, "agent"), (human2, "human2")] {
        wait_roster(bus, id, &[&own["device_id"], &peer["device_id"], &own2["device_id"]]).await?;
    }
    call(human,"human","group.send",json!({"group_id":"group_k2b","conversation_id":"group_thread_k2b","message_id":"group-k2b-seed","sender_id":own["device_id"],"encrypted_body_base64":"","plaintext_body_base64":ramflux_protocol::encode_base64url(b"group surface conversation")})).await?;
    Ok(())
}
fn device<'a>(directory: &'a Value, account: &Value) -> TestResult<&'a Value> {
    directory["identities"]
        .as_array()
        .ok_or("identities")?
        .iter()
        .find(|identity| identity["principal_id"] == account["principal_id"])
        .and_then(|identity| identity["devices"].as_array())
        .and_then(|devices| {
            devices.iter().find(|device| device["device_id"] == account["device_id"])
        })
        .ok_or_else(|| "local device is absent from identity directory".into())
}
async fn wait_roster(
    bus: &mut ramflux_sdk::LocalBusClient,
    account: &str,
    members: &[&Value],
) -> TestResult {
    for _ in 0..100 {
        call(bus, account, "message.receive", json!({"limit":32,"auto_fetch_attachments":false}))
            .await?;
        let groups = call(bus, account, "group.list", json!({"limit":100})).await?;
        if groups["groups"]
            .as_array()
            .is_some_and(|groups| groups.iter().any(|g| g["group_id"] == "group_k2b"))
        {
            let state =
                call(bus, account, "group.members", json!({"group_id":"group_k2b"})).await?;
            if state["members"]
                .as_array()
                .is_some_and(|actual| members.iter().all(|expected| actual.contains(expected)))
            {
                return Ok(());
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(format!("group member roster did not arrive: account={account}").into())
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
    let error=call(bus,"human","surface.send",json!({"conversation_id":conversation,"message_id":format!("{surface}-non-author"),"wire_base64":ramflux_protocol::encode_base64url(bytes)})).await.err().ok_or("non-author update was accepted")?;
    assert!(error.to_string().contains("not_author"), "unexpected local refusal: {error}");
    Ok(())
}

pub(super) fn non_author_patch_wire(
    conversation: &str,
    surface: &str,
    current: &Value,
) -> TestResult<Vec<u8>> {
    let mut snapshot: ramflux_protocol::CreateSurfaceCommand =
        serde_json::from_value(current["snapshot"].clone())?;
    snapshot.fallback_text = "forged status".into();
    wire(
        conversation,
        3,
        ramflux_protocol::A2uiConversationCommand::PatchSurface(
            ramflux_protocol::PatchSurfaceCommand {
                surface_id: surface.into(),
                base_surface_hash: current["surface_hash"].as_str().ok_or("hash")?.into(),
                new_surface_hash: ramflux_protocol::surface_snapshot_hash(&snapshot)?,
                ops: vec![ramflux_protocol::SurfacePatchOp::SetFallbackText {
                    fallback_text: snapshot.fallback_text,
                }],
            },
        ),
    )
}
