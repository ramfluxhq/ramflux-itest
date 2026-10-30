// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Two daemon processes negotiate encrypted calls and exercise the production opaque voice relay.
use crate::*;
use serde_json::{Value, json};
mod actors;
#[cfg(test)]
mod lease_lifecycle;
mod media;
type VoiceResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[derive(Clone, Copy)]
enum AccountMode {
    Native,
    Legacy,
}

pub(crate) fn assert_realnet_voice_round_trip(project: &str) -> VoiceResult {
    assert_realnet_voice_round_trip_mode(project, AccountMode::Native)
}

pub(crate) fn assert_realnet_legacy_voice_round_trip(project: &str) -> VoiceResult {
    assert_realnet_voice_round_trip_mode(project, AccountMode::Legacy)
}

fn assert_realnet_voice_round_trip_mode(project: &str, mode: AccountMode) -> VoiceResult {
    for variable in ["RAMFLUX_ITEST_VOICE", "RAMFLUX_OBJECT_V3", "RAMFLUX_CROSS_GATEWAY"] {
        if std::env::var(variable).as_deref() != Ok("1") {
            return Err(format!("voice acceptance requires {variable}=1").into());
        }
    }
    let ports = S8ComposePorts {
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
    };
    let mut stack = start_client_directory_stack_with_issuer(
        project,
        ports,
        &[
            ("RAMFLUX_ITEST_VOICE_UDP_PORT".into(), "64841".into()),
            ("RAMFLUX_RELAY_VOICE_PUBLIC_ENDPOINT".into(), "127.0.0.1:64841".into()),
        ],
        "node_a.realnet",
        "gw-a",
    )?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(run(&stack.node, mode))?;
    stack.node.guard.mark_success();
    Ok(())
}
async fn run(node: &S8RealnetNode, mode: AccountMode) -> VoiceResult {
    let root = temp_root("voice_call")?;
    let rf = actors::binary().await?;
    let sockets = [
        PathBuf::from(format!("/tmp/rf-call01-a-{}.sock", std::process::id())),
        PathBuf::from(format!("/tmp/rf-call01-b-{}.sock", std::process::id())),
    ];
    let profiles = root.join("native-nodes.json");
    if matches!(mode, AccountMode::Native) {
        std::fs::write(
            &profiles,
            serde_json::to_vec(&[native_node_profile(node, S73_RELAY_QUIC)?])?,
        )?;
    }
    let mut children = Vec::new();
    for (id, socket) in ["alice", "bob"].iter().zip(&sockets) {
        let mut command = match mode {
            AccountMode::Native => native_client_directory_daemon_command(
                &rf,
                socket,
                &root.join(id),
                &node.ca_cert,
                None,
            ),
            AccountMode::Legacy => {
                client_directory_daemon_command(&rf, socket, &root.join(id), &node.ca_cert, None)
            }
        };
        if matches!(mode, AccountMode::Native) {
            command.arg("--builtin-nodes").arg(&profiles);
        }
        children.push(command.spawn()?);
    }
    let result =
        tokio::time::timeout(Duration::from_mins(3), flow(node, &rf, &sockets, mode)).await;
    for child in &mut children {
        let _ = child.start_kill();
        let _ = child.wait().await;
    }
    for socket in sockets {
        let _ = std::fs::remove_file(socket);
    }
    let _ = std::fs::remove_dir_all(root);
    result??;
    Ok(())
}
async fn flow(
    node: &S8RealnetNode,
    rf: &Path,
    sockets: &[PathBuf; 2],
    mode: AccountMode,
) -> VoiceResult {
    for socket in sockets {
        mvp_s4_wait_for_socket(socket).await?;
    }
    let mut alice = ramflux_sdk::LocalBusClient::connect(&sockets[0]).await?;
    let mut bob = ramflux_sdk::LocalBusClient::connect(&sockets[1]).await?;
    let (a, b) = create_accounts(node, sockets, &mut alice, &mut bob, mode).await?;
    let alice_id = a["local_account_id"].as_str().ok_or("missing alice account id")?;
    let bob_id = b["local_account_id"].as_str().ok_or("missing bob account id")?;
    establish_contacts(&mut alice, &a, &mut bob, &b, mode).await?;
    for (bus, id) in [(&mut alice, alice_id), (&mut bob, bob_id)] {
        actors::call(bus, id, "bus.subscribe", json!({"topics":["call.changed"]})).await?;
    }
    actors::call(&mut alice,alice_id,"message.submit",json!({"conversation_id":"voice-thread","message_id":"voice-context","envelope_id":"voice-context-envelope","source_principal_id":a["principal_id"],"sender_id":a["device_id"],"recipient_device_id":b["device_id"],"recipient_principal_commitment":b["principal_commitment"],"target_delivery_id":b["target_delivery_id"],"encrypted_body_base64":"","plaintext_body_base64":ramflux_protocol::encode_base64url(b"voice context"),"created_at":realnet_now_i64(),"ttl":300})).await?;
    actors::wait_context(&mut bob, bob_id).await?;
    realnet_step("voice invite", "caller=alice callee=bob");
    let invite =
        actors::cli(rf, &sockets[0], "invite", alice_id, Some(("--conversation", "voice-thread")))
            .await?;
    assert_eq!(invite["state"], "outgoing_ringing");
    let id = invite["call_id"].as_str().ok_or("missing call id")?;
    assert_eq!(ramflux_protocol::decode_base64url(id)?.len(), 16);
    actors::wait_state(&mut bob, bob_id, id, "incoming_ringing").await?;
    let answered = actors::cli(rf, &sockets[1], "answer", bob_id, Some(("--call", id))).await?;
    assert_eq!(answered["state"], "connecting");
    actors::wait_state(&mut alice, alice_id, id, "active").await?;
    actors::wait_state(&mut bob, bob_id, id, "active").await?;
    realnet_step("voice media", "authenticated signaling active on both daemons");
    let own =
        actors::call(&mut alice, alice_id, "call.media.session", json!({"call_id":id})).await?;
    let peer = actors::call(&mut bob, bob_id, "call.media.session", json!({"call_id":id})).await?;
    assert_eq!(own["sframe"]["cipher_suite"], 5);
    assert_eq!(peer["sframe"]["cipher_suite"], 5);
    assert_eq!(own["sframe"]["send"]["kid"], 0);
    assert_eq!(peer["sframe"]["send"]["kid"], 1);
    assert_eq!(own["relay"]["side"], 0);
    assert_eq!(peer["relay"]["side"], 1);
    assert_eq!(own["relay"]["lease_id"], peer["relay"]["lease_id"]);
    if own["relay"]["token"] == peer["relay"]["token"]
        || own["relay"]["rebind_key"] == peer["relay"]["rebind_key"]
    {
        return Err("participant-private relay credentials overlap".into());
    }

    if own["sframe"]["send"]["base_key"] != peer["sframe"]["receive"]["base_key"]
        || peer["sframe"]["send"]["base_key"] != own["sframe"]["receive"]["base_key"]
    {
        return Err("directional media keys do not match".into());
    }
    assert!(
        actors::call(&mut alice, alice_id, "call.media.session", json!({"call_id":id}))
            .await
            .is_err(),
        "voice engines must never reacquire a used key"
    );
    media::round_trip(&own, &peer).await?;
    for bus in [&mut alice, &mut bob] {
        let event = tokio::time::timeout(Duration::from_secs(10), bus.next_event()).await??;
        assert_eq!(event.method, "call.changed");
        assert_eq!(event.body["call_id"], id);
        actors::public_fields_only(&event.body)?;
    }
    let ended = actors::cli(rf, &sockets[0], "hangup", alice_id, Some(("--call", id))).await?;
    actors::public_fields_only(&ended)?;
    realnet_step("voice caller hangup", ended.to_string());
    assert_eq!(ended["end_reason"], "completed", "caller hangup row: {ended}");
    let ended = actors::wait_state(&mut bob, bob_id, id, "ended").await?;
    actors::public_fields_only(&ended)?;
    realnet_step("voice callee ended", ended.to_string());
    assert_eq!(ended["end_reason"], "completed", "callee terminal row: {ended}");
    let timeline =
        actors::call(&mut bob, bob_id, "message.list", json!({"conversation_id":"voice-thread"}))
            .await?;
    let record = timeline["messages"]
        .as_array()
        .ok_or("timeline missing")?
        .iter()
        .find(|r| r["kind"] == "call" && r["call"]["call_id"] == id)
        .ok_or("call record missing")?;
    assert!(record["duration_seconds"].as_i64().is_some_and(|n| n >= 0));
    actors::public_fields_only(record)?;
    // A second call exercises peer rejection rather than the removed local answer stub.
    let retry =
        actors::cli(rf, &sockets[0], "invite", alice_id, Some(("--conversation", "voice-thread")))
            .await?;
    let retry_id = retry["call_id"].as_str().ok_or("retry call id missing")?;
    assert_ne!(retry_id, id);
    actors::wait_state(&mut bob, bob_id, retry_id, "incoming_ringing").await?;
    actors::cli(rf, &sockets[1], "reject", bob_id, Some(("--call", retry_id))).await?;
    assert_eq!(
        actors::wait_state(&mut alice, alice_id, retry_id, "ended").await?["end_reason"],
        "declined"
    );
    realnet_step(
        "voice complete",
        "bidirectional opaque Opus, durable timeline, hangup and rejection verified",
    );
    Ok(())
}

async fn create_accounts(
    node: &S8RealnetNode,
    sockets: &[PathBuf; 2],
    alice: &mut ramflux_sdk::LocalBusClient,
    bob: &mut ramflux_sdk::LocalBusClient,
    mode: AccountMode,
) -> VoiceResult<(Value, Value)> {
    match mode {
        AccountMode::Native => {
            select_native_node(alice, &node.node_id).await?;
            select_native_node(bob, &node.node_id).await?;
            let alice_account = create_native_account(&sockets[0], "Alice Call Fixture").await?;
            let bob_account = create_native_account(&sockets[1], "Bob Call Fixture").await?;
            Ok((native_account_value(&alice_account), native_account_value(&bob_account)))
        }
        AccountMode::Legacy => Ok((
            actors::create_legacy(alice, node, "alice", [0xc1; 32], [0xc2; 32]).await?,
            actors::create_legacy(bob, node, "bob", [0xc3; 32], [0xc4; 32]).await?,
        )),
    }
}

fn native_account_value(account: &NativeAccount) -> Value {
    json!({
        "local_account_id": account.account_id,
        "principal_id": account.principal_id,
        "device_id": account.device_id,
        "target_delivery_id": account.delivery_id,
        "principal_commitment": account.anchor,
    })
}

async fn establish_contacts(
    alice: &mut ramflux_sdk::LocalBusClient,
    a: &Value,
    bob: &mut ramflux_sdk::LocalBusClient,
    b: &Value,
    mode: AccountMode,
) -> VoiceResult {
    let alice_id = a["local_account_id"].as_str().ok_or("missing alice account id")?;
    let bob_id = b["local_account_id"].as_str().ok_or("missing bob account id")?;
    if matches!(mode, AccountMode::Legacy) {
        for (bus, id, own, peer) in [(alice, alice_id, a, b), (bob, bob_id, b, a)] {
            let accepted = actors::call(
                bus,
                id,
                "contact.add",
                json!({
                    "link_id":format!("call01-{id}"),
                    "requester_id":own["principal_commitment"],
                    "target_id":peer["principal_commitment"],
                }),
            )
            .await?;
            assert_eq!(accepted["state"], "accepted");
        }
        return Ok(());
    }
    actors::call(alice, alice_id, "contact.add", json!({"principal_id":b["principal_id"]})).await?;
    let request = actors::wait_inbound_contact_request(
        bob,
        bob_id,
        a["principal_id"].as_str().ok_or("missing alice principal")?,
    )
    .await?;
    actors::call(bob, bob_id, "contact.accept", json!({"request_id":request})).await?;
    actors::wait_accepted_contact(
        alice,
        alice_id,
        b["principal_id"].as_str().ok_or("missing bob principal")?,
    )
    .await?;
    actors::wait_accepted_contact(
        bob,
        bob_id,
        a["principal_id"].as_str().ok_or("missing alice principal")?,
    )
    .await?;
    Ok(())
}
