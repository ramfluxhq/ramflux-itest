// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Signed full-roster convergence, automatic siblings, first messages and removal fences.
#![cfg(feature = "realnet")]
use super::*;
use ramflux_sdk::{LocalBusClient, LocalBusFrame};
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
        &[],
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
    wait_for_private_gateway_quic(S73_GATEWAY_B_QUIC.parse()?, &node.ca_cert).await?;
    let root = temp_root("grpsync01")?;
    let rf = mvp_s4_build_rf_binary().await?;
    let mut daemons = Vec::new();
    let mut sockets = Vec::new();
    for actor in ["owner", "peer", "sibling"] {
        let socket = PathBuf::from(format!("/tmp/rf-gs-{actor}-{}.sock", std::process::id()));
        daemons.push(
            client_directory_daemon_command(&rf, &socket, &root.join(actor), &node.ca_cert, None)
                .spawn()?,
        );
        sockets.push(socket);
    }
    let result = tokio::time::timeout(Duration::from_mins(6), async {
        for socket in &sockets { mvp_s4_wait_for_socket(socket).await?; }
        let mut owner = LocalBusClient::connect(&sockets[0]).await?;
        let mut peer = LocalBusClient::connect(&sockets[1]).await?;
        let mut sibling = LocalBusClient::connect(&sockets[2]).await?;
        let a = create(&mut owner, node, "owner", "owner", (101, 102)).await?;
        let b = create(&mut peer, node, "peer", "peer", (111, 112)).await?;
        for (bus, account, own, other) in [(&mut owner,"owner",&a,&b),(&mut peer,"peer",&b,&a)] {
            call(bus, account, "contact.add", json!({"link_id":format!("gs-{account}"),
                "requester_id":own["principal_commitment"],"target_id":other["principal_commitment"]})).await?;
        }
        step("create_and_add_peer");
        call(&mut owner,"owner","group.create",json!({"group_id":GROUP,"conversation_id":THREAD,
            "creator_id":a["device_id"],"name":NAME})).await?;
        add(&mut owner,&b).await?;
        wait_state(&mut peer,"peer",2,NAME,&[a["device_id"].clone(),b["device_id"].clone()]).await?;
        step("automatic_sibling_activation_without_join");
        let c = create(&mut sibling,node,"sibling","owner",(101,122)).await?;
        let expected = [a["device_id"].clone(),b["device_id"].clone(),c["device_id"].clone()];
        for (bus,account) in [(&mut owner,"owner"),(&mut peer,"peer"),(&mut sibling,"sibling")] {
            wait_state(bus,account,2,NAME,&expected).await?;
        }
        send(&mut sibling,"sibling",&c,"implicit-sibling-first").await?;
        for (bus,account) in [(&mut owner,"owner"),(&mut peer,"peer")] {
            wait_message(bus,account,&c,"implicit-sibling-first").await?;
        }
        step("epoch_three_full_roster");
        add(&mut owner,&c).await?;
        let mut views = Vec::new();
        for (bus,account) in [(&mut owner,"owner"),(&mut peer,"peer"),(&mut sibling,"sibling")] {
            views.push(wait_state(bus,account,3,NAME,&expected).await?);
        }
        for view in &views[1..] {
            assert_eq!(view["member_roster"],views[0]["member_roster"],"root-qualified signed rosters differ");
        }
        assert_first_messages(&mut owner, &mut peer, &mut sibling, &a, &b, &c).await?;
        assert_role_refused(&mut peer, &a, &b).await?;
        wait_state(&mut peer,"peer",3,NAME,&expected).await?;
        step("role_and_signed_name");
        call(&mut owner,"owner","group.role.set",json!({"group_id":GROUP,"actor_id":a["device_id"],
            "member_id":b["device_id"],"member_principal_commitment":b["principal_commitment"],"role":"admin"})).await?;
        for (bus,account) in [(&mut peer,"peer"),(&mut sibling,"sibling")] {
            let view=wait_state(bus,account,4,NAME,&expected).await?;
            assert_eq!(view["roles"][b["device_id"].as_str().ok_or("peer device")?],"admin");
        }
        call(&mut owner,"owner","group.name.set",json!({"group_id":GROUP,"name":"Reviewed checklist"})).await?;
        for (bus,account) in [(&mut owner,"owner"),(&mut peer,"peer"),(&mut sibling,"sibling")] {
            wait_state(bus,account,5,"Reviewed checklist",&expected).await?;
            assert_signed_name(bus, account).await?;
        }
        step("remove_peer_and_rotate_sender_keys");
        call(&mut owner,"owner","group.member.remove",json!({"group_id":GROUP,"actor_id":a["device_id"],
            "member_id":b["device_id"],"member_principal_commitment":b["principal_commitment"]})).await?;
        let retained=[a["device_id"].clone(),c["device_id"].clone()];
        for (bus,account) in [(&mut owner,"owner"),(&mut peer,"peer"),(&mut sibling,"sibling")] {
            wait_state(bus,account,6,"Reviewed checklist",&retained).await?;
        }
        assert!(send(&mut peer,"peer",&b,"forbidden-after-removal").await.is_err());
        send(&mut owner,"owner",&a,"after-removal").await?;
        wait_message(&mut sibling,"sibling",&a,"after-removal").await?;
        for (bus,account) in [(&mut owner,"owner"),(&mut sibling,"sibling")] {
            assert_signed_name(bus, account).await?;
        }
        assert_removed_peer_excluded(&mut peer,&a).await?;
        step("complete");
        Ok::<(),Box<dyn std::error::Error>>(())
    }).await;
    for daemon in &mut daemons {
        let _ = daemon.start_kill();
    }
    for daemon in &mut daemons {
        let _ = daemon.wait().await;
    }
    for socket in &sockets {
        let _ = std::fs::remove_file(socket);
    }
    result??;
    std::fs::remove_dir_all(root)?;
    Ok(())
}
async fn assert_first_messages(
    owner: &mut LocalBusClient,
    peer: &mut LocalBusClient,
    sibling: &mut LocalBusClient,
    a: &Value,
    b: &Value,
    c: &Value,
) -> TestResult {
    step("first_epoch_three_message_from_each");
    send(owner, "owner", a, "owner-first").await?;
    send(peer, "peer", b, "peer-first").await?;
    send(sibling, "sibling", c, "sibling-first").await?;
    for (bus, account, ids) in [
        (owner, "owner", ["peer-first", "sibling-first"]),
        (peer, "peer", ["owner-first", "sibling-first"]),
        (sibling, "sibling", ["owner-first", "peer-first"]),
    ] {
        for id in ids {
            wait_message(
                bus,
                account,
                if id == "owner-first" {
                    a
                } else if id == "peer-first" {
                    b
                } else {
                    c
                },
                id,
            )
            .await?;
        }
    }
    Ok(())
}
async fn assert_removed_peer_excluded(peer: &mut LocalBusClient, sender: &Value) -> TestResult {
    let expected = expected_message_id(sender, "after-removal")?;
    for _ in 0..20 {
        call(peer, "peer", "message.receive", json!({"limit":32})).await?;
        let read = call(peer, "peer", "message.read", json!({"conversation_id":THREAD})).await?;
        assert!(
            !read["messages"]
                .as_array()
                .ok_or("messages")?
                .iter()
                .any(|m| m["message_id"] == expected || m["body_utf8"] == "after-removal"),
            "removed peer received a new epoch message"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Ok(())
}
async fn assert_role_refused(
    peer: &mut LocalBusClient,
    owner: &Value,
    member: &Value,
) -> TestResult {
    step("typed_refusal_does_not_stop_account_actor");
    let bad = LocalBusFrame::request(
        "invalid-group-role",
        Some("peer".into()),
        "ramflux.sdk.v1",
        "group.role.set",
        json!({"group_id":GROUP,"actor_id":member["device_id"],"member_id":owner["device_id"],
            "member_principal_commitment":owner["principal_commitment"],"role":"member"}),
    );
    let refusal = peer
        .request_frame_structured(bad)
        .await
        .err()
        .ok_or("unauthorized role update accepted")?;
    assert!(
        matches!(&refusal, ramflux_sdk::SdkError::LocalBusRefused { .. }),
        "untyped refusal: {refusal}"
    );
    assert!(!refusal.to_string().contains("account actor stopped"), "actor died: {refusal}");
    Ok(())
}
async fn assert_signed_name(bus: &mut LocalBusClient, account: &str) -> TestResult {
    let listed = call(bus, account, "group.list", json!({})).await?;
    assert!(
        listed["groups"]
            .as_array()
            .ok_or("groups")?
            .iter()
            .any(|group| group["group_id"] == GROUP && group["name"] == "Reviewed checklist"),
        "signed name missing from group.list: {listed}"
    );
    let directory = call(bus, account, "conversation.directory", json!({"limit":100})).await?;
    assert!(
        directory["conversations"]
            .as_array()
            .ok_or("conversations")?
            .iter()
            .any(|row| row["id"] == THREAD && row["title"] == "Reviewed checklist"),
        "name missing or overwritten: {directory}"
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
async fn create(
    bus: &mut LocalBusClient,
    node: &S8RealnetNode,
    id: &str,
    owner: &str,
    seeds: (u8, u8),
) -> TestResult<Value> {
    let principal = format!("principal_gs_{owner}");
    let device = format!("device_gs_{id}");
    let target = format!("target_gs_{id}");
    let request = ramflux_sdk::LocalBusAccountCreateRequest {
        kind: None,
        label: None,
        node_id: None,
        local_account_id: id.into(),
        principal_id: principal.clone(),
        principal_commitment: String::new(),
        device_id: device.clone(),
        target_delivery_id: target.clone(),
        account_secret: "grpsync-fixture-secret".into(),
        root_seed: [seeds.0; 32],
        device_seed: [seeds.1; 32],
        client_mode: ramflux_sdk::LocalBusClientMode::AttendedCli,
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
    Ok(bus
        .request(None, "create", "account.itest_legacy.create", serde_json::to_value(request)?)
        .await?)
}
async fn add(bus: &mut LocalBusClient, member: &Value) -> TestResult {
    call(
        bus,
        "owner",
        "group.member.add",
        json!({"group_id":GROUP,"member_id":member["device_id"],
        "member_principal_commitment":member["principal_commitment"],"role":"member"}),
    )
    .await?;
    Ok(())
}
async fn send(bus: &mut LocalBusClient, account: &str, actor: &Value, id: &str) -> TestResult {
    call(bus,account,"group.send",json!({"group_id":GROUP,"conversation_id":THREAD,"message_id":id,
        "sender_id":actor["device_id"],"encrypted_body_base64":"","plaintext_body_base64":ramflux_protocol::encode_base64url(id)})).await?;
    Ok(())
}
async fn wait_state(
    bus: &mut LocalBusClient,
    account: &str,
    epoch: u64,
    name: &str,
    members: &[Value],
) -> TestResult<Value> {
    let started = std::time::Instant::now();
    eprintln!(
        "STEP: grpsync01 timestamp={} phase=wait_state account={account} epoch={epoch} name={name:?} members={members:?} max_polls=100 retry_ms=100",
        realnet_now_i64()
    );
    let mut observed = Value::Null;
    for poll in 1..=100 {
        call(bus, account, "message.receive", json!({"limit":32})).await?;
        match call(bus, account, "group.members", json!({"group_id":GROUP})).await {
            Ok(state) => observed = state,
            Err(error) => {
                eprintln!(
                    "STEP: grpsync01 timestamp={} phase=state_poll account={account} poll={poll} elapsed_ms={} error={error}",
                    realnet_now_i64(),
                    started.elapsed().as_millis()
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        }
        eprintln!(
            "STEP: grpsync01 timestamp={} phase=state_poll account={account} poll={poll} elapsed_ms={} observed={observed}",
            realnet_now_i64(),
            started.elapsed().as_millis()
        );
        if observed["group_epoch"] == epoch
            && observed["name"] == name
            && observed["members"].as_array().is_some_and(|actual| {
                actual.len() == members.len()
                    && members.iter().all(|member| actual.contains(member))
            })
        {
            eprintln!(
                "STEP: grpsync01 timestamp={} phase=state_converged account={account} epoch={epoch} poll={poll} elapsed_ms={}",
                realnet_now_i64(),
                started.elapsed().as_millis()
            );
            return Ok(observed);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(format!(
        "group state did not converge: account={account} epoch={epoch} elapsed_ms={} polls=100 observed={observed}",
        started.elapsed().as_millis()
    )
    .into())
}
fn expected_message_id(sender: &Value, logical: &str) -> TestResult<String> {
    Ok(ramflux_protocol::group_message_id(
        GROUP,
        sender["principal_commitment"].as_str().ok_or("sender root")?,
        sender["device_id"].as_str().ok_or("sender device")?,
        logical,
    )?)
}
async fn wait_message(
    bus: &mut LocalBusClient,
    account: &str,
    sender: &Value,
    id: &str,
) -> TestResult {
    let expected = expected_message_id(sender, id)?;
    for _ in 0..100 {
        call(bus, account, "message.receive", json!({"limit":32})).await?;
        let read = call(bus, account, "message.read", json!({"conversation_id":THREAD})).await?;
        if read["messages"].as_array().is_some_and(|messages| {
            messages
                .iter()
                .any(|message| message["message_id"] == expected && message["body_utf8"] == id)
        }) {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(format!("first group message missing: account={account} id={id}").into())
}
fn step(phase: &str) {
    eprintln!("STEP: grpsync01 timestamp={} phase={phase}", realnet_now_i64());
}
