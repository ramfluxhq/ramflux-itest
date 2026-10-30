// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Born-v3 signed membership, names, removal and messages across two gateways.
#![cfg(feature = "realnet")]
use super::*;
use ramflux_sdk::{LocalBusClient, LocalBusFrame, NodeProfile};
use serde_json::{Value, json};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const GROUP: &str = "group_grpsync01";
const THREAD: &str = "thread_grpsync01";
const NAME: &str = "Shared checklist";

#[test]
fn grpsync01_realnet_membership_and_name() -> TestResult {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping grpsync01: set RAMFLUX_ITEST_REALNET=1 on the container host");
        return Ok(());
    }
    for flag in ["RAMFLUX_OBJECT_V3", "RAMFLUX_CROSS_GATEWAY"] {
        if std::env::var(flag).as_deref() != Ok("1") {
            return Err(format!("grpsync01 requires {flag}=1").into());
        }
    }
    let gateway_a_issuer_seed = ramflux_protocol::encode_base64url([0x33; 32]);
    let mut stack = start_client_directory_stack_named(
        "ramflux-grpsync01",
        S8ComposePorts {
            gateway_http: 64901,
            gateway_quic: 64971,
            router_http: 64900,
            router_mesh: 64972,
            notify_http: 64903,
            federation_http: 64902,
            federation_mesh: 64973,
            relay_http: 64904,
            relay_media_udp: 64940,
            signaling_turn_udp: 64978,
            signaling_turn_tcp: 64979,
            retention_http: 64907,
        },
        &[("RAMFLUX_GATEWAY_A_V3_ISSUER_SEED".into(), gateway_a_issuer_seed)],
    )?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(Box::pin(run(&stack.node)))?;
    stack.node.guard.mark_success();
    Ok(())
}

async fn run(node: &S8RealnetNode) -> TestResult {
    step("readiness");
    wait_relay_quic_healthy(S73_RELAY_QUIC, "ramflux-relay", &node.ca_cert).await?;
    wait_for_private_gateway_quic(node.gateway_quic_addr, &node.ca_cert).await?;
    wait_for_private_gateway_quic(S73_GATEWAY_B_QUIC.parse()?, &node.ca_cert).await?;
    let root = temp_root("grpsync01")?;
    let rf = mvp_s4_build_rf_binary().await?;
    let sockets = [root.join("owner.sock"), root.join("peer.sock")];
    let profiles =
        [native_node_profile(node, S73_RELAY_QUIC)?, gateway_b_profile(node, S73_RELAY_QUIC)?];
    let profile_files = [root.join("owner-nodes.json"), root.join("peer-nodes.json")];
    for (path, profile) in profile_files.iter().zip(&profiles) {
        std::fs::write(path, serde_json::to_vec(&[profile])?)?;
    }
    let mut daemons = Vec::new();
    for (index, actor) in ["owner", "peer"].iter().enumerate() {
        let mut command = native_client_directory_daemon_command(
            &rf,
            &sockets[index],
            &root.join(actor),
            &node.ca_cert,
            None,
        );
        command.arg("--builtin-nodes").arg(&profile_files[index]);
        daemons.push(command.spawn()?);
    }
    let result = tokio::time::timeout(
        Duration::from_mins(6),
        flow(&sockets, &profiles[0].node_id, &profiles[1].node_id),
    )
    .await;
    for daemon in &mut daemons {
        let _ = daemon.start_kill();
    }
    for daemon in &mut daemons {
        let _ = daemon.wait().await;
    }
    let _ = std::fs::remove_dir_all(root);
    result??;
    Ok(())
}

fn gateway_b_profile(node: &S8RealnetNode, relay: &str) -> TestResult<NodeProfile> {
    let mut profile = native_node_profile(node, relay)?;
    profile.node_id = "node_b.realnet".into();
    profile.gateway.quic_addr = S73_GATEWAY_B_QUIC.into();
    profile.gateway.tcp_addr = S73_GATEWAY_B_QUIC.into();
    Ok(profile)
}

async fn flow(sockets: &[PathBuf; 2], owner_node: &str, peer_node: &str) -> TestResult {
    for socket in sockets {
        mvp_s4_wait_for_socket(socket).await?;
    }
    let mut owner = LocalBusClient::connect(&sockets[0]).await?;
    let mut peer = LocalBusClient::connect(&sockets[1]).await?;
    select_native_node(&mut owner, owner_node).await?;
    select_native_node(&mut peer, peer_node).await?;
    let alice = create_native_account(&sockets[0], "Owner").await?;
    let bob = create_native_account(&sockets[1], "Peer").await?;

    step("native_contacts");
    call(&mut owner, &alice.account_id, "contact.add", json!({"principal_id":bob.principal_id}))
        .await?;
    call(&mut peer, &bob.account_id, "contact.accept", json!({"principal_id":alice.principal_id}))
        .await?;

    step("native_create_and_principal_add");
    call(
        &mut owner,
        &alice.account_id,
        "group.create",
        json!({"group_id":GROUP,"conversation_id":THREAD,"creator_id":alice.principal_id,"name":NAME}),
    )
    .await?;
    call(
        &mut owner,
        &alice.account_id,
        "group.member.add",
        json!({"group_id":GROUP,"member_id":bob.principal_id,"role":"member"}),
    )
    .await?;
    wait_state(&mut peer, &bob.account_id, 2, NAME, &[&alice.device_id, &bob.device_id]).await?;

    step("cross_gateway_native_messages");
    send(&mut owner, &alice, "owner-first").await?;
    wait_message(&mut peer, &bob.account_id, &alice, "owner-first").await?;
    send(&mut peer, &bob, "peer-first").await?;
    wait_message(&mut owner, &alice.account_id, &bob, "peer-first").await?;

    step("native_rename");
    call(
        &mut owner,
        &alice.account_id,
        "group.name.set",
        json!({"group_id":GROUP,"name":"Reviewed checklist"}),
    )
    .await?;
    for (bus, account) in [(&mut owner, alice.account_id.as_str()), (&mut peer, &bob.account_id)] {
        wait_state(bus, account, 3, "Reviewed checklist", &[&alice.device_id, &bob.device_id])
            .await?;
    }

    step("native_principal_remove");
    call(
        &mut owner,
        &alice.account_id,
        "group.member.remove",
        json!({"group_id":GROUP,"actor_id":alice.device_id,"member_id":bob.principal_id}),
    )
    .await?;
    wait_state(&mut owner, &alice.account_id, 4, "Reviewed checklist", &[&alice.device_id]).await?;
    assert_typed_send_refusal(&mut peer, &bob).await?;
    step("complete");
    Ok(())
}

async fn assert_typed_send_refusal(bus: &mut LocalBusClient, sender: &NativeAccount) -> TestResult {
    let request = LocalBusFrame::request(
        "removed-native-member-send",
        Some(sender.account_id.clone()),
        "grpsync01",
        "group.send",
        json!({"group_id":GROUP,"conversation_id":THREAD,"message_id":"removed-send",
            "sender_id":sender.principal_id,"encrypted_body_base64":"",
            "plaintext_body_base64":ramflux_protocol::encode_base64url(b"removed")}),
    );
    let refusal = bus
        .request_frame_structured(request)
        .await
        .err()
        .ok_or("removed native member send succeeded")?;
    assert!(
        matches!(&refusal, ramflux_sdk::SdkError::LocalBusRefused {code,..} if code == "GroupSendRefused"),
        "unexpected refusal: {refusal}"
    );
    Ok(())
}

async fn call(
    bus: &mut LocalBusClient,
    account: &str,
    method: &str,
    body: Value,
) -> TestResult<Value> {
    bus.request(Some(account.into()), "grpsync01", method, body)
        .await
        .map_err(|error| format!("account={account} method={method}: {error}").into())
}

async fn send(bus: &mut LocalBusClient, sender: &NativeAccount, id: &str) -> TestResult {
    call(
        bus,
        &sender.account_id,
        "group.send",
        json!({"group_id":GROUP,"conversation_id":THREAD,"message_id":id,
            "sender_id":sender.principal_id,"encrypted_body_base64":"",
            "plaintext_body_base64":ramflux_protocol::encode_base64url(id)}),
    )
    .await?;
    Ok(())
}

async fn wait_state(
    bus: &mut LocalBusClient,
    account: &str,
    epoch: u64,
    name: &str,
    members: &[&str],
) -> TestResult<Value> {
    let mut observed = Value::Null;
    for _ in 0..100 {
        call(bus, account, "message.receive", json!({"limit":32})).await?;
        if let Ok(state) = call(bus, account, "group.members", json!({"group_id":GROUP})).await {
            observed = state;
            if observed["group_epoch"] == epoch
                && observed["name"] == name
                && observed["members"].as_array().is_some_and(|actual| {
                    actual.len() == members.len()
                        && members.iter().all(|member| actual.iter().any(|value| value == member))
                })
            {
                return Ok(observed);
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(format!(
        "group state did not converge: account={account} epoch={epoch} observed={observed}"
    )
    .into())
}

async fn wait_message(
    bus: &mut LocalBusClient,
    account: &str,
    sender: &NativeAccount,
    id: &str,
) -> TestResult {
    let expected =
        ramflux_protocol::group_message_id(GROUP, &sender.anchor, &sender.device_id, id)?;
    for _ in 0..100 {
        call(bus, account, "message.receive", json!({"limit":32})).await?;
        let read = call(bus, account, "message.read", json!({"conversation_id":THREAD})).await?;
        if let Some(message) = read["messages"].as_array().and_then(|messages| {
            messages
                .iter()
                .find(|message| message["message_id"] == expected && message["body_utf8"] == id)
        }) {
            assert_eq!(message["sender_id"], sender.principal_id);
            assert_eq!(message["sender_device_id"], sender.device_id);
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(format!("native group message missing: account={account} id={id}").into())
}

fn step(phase: &str) {
    eprintln!("STEP: grpsync01 timestamp={} phase={phase}", realnet_now_i64());
}
