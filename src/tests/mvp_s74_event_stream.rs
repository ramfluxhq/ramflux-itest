// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Autonomous first-message delivery, metadata replay, and durable sequence continuation.
#![cfg(feature = "realnet")]
use super::mvp_s73_client_read_model::{call, create};
use super::*;
use serde_json::{Value, json};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[test]
fn mvp_s74_realnet_autonomous_sync_replay_and_daemon_restart() -> TestResult {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping s74: set RAMFLUX_ITEST_REALNET=1 on the QA container host");
        return Ok(());
    }
    if std::env::var("RAMFLUX_OBJECT_V3").as_deref() != Ok("1")
        || std::env::var("RAMFLUX_CROSS_GATEWAY").as_deref() != Ok("1")
    {
        return Err("s74 requires RAMFLUX_OBJECT_V3=1 RAMFLUX_CROSS_GATEWAY=1".into());
    }
    let stack = start_client_directory_stack(S8ComposePorts {
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
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(run(&stack.node))
}

async fn run(node: &S8RealnetNode) -> TestResult {
    wait_relay_quic_healthy(S73_RELAY_QUIC, "ramflux-relay", &node.ca_cert).await?;
    wait_for_private_gateway_quic(S73_GATEWAY_B_QUIC.parse()?, &node.ca_cert).await?;
    let root = temp_root("s74_stream")?;
    let alice = PathBuf::from(format!("/tmp/rf-s74-alice-{}.sock", std::process::id()));
    let bob = PathBuf::from(format!("/tmp/rf-s74-bob-{}.sock", std::process::id()));
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
    let result=tokio::time::timeout(Duration::from_mins(5),async {
        mvp_s4_wait_for_socket(&alice).await?;mvp_s4_wait_for_socket(&bob).await?;
        let mut sender=ramflux_sdk::LocalBusClient::connect(&alice).await?;
        let mut receiver=ramflux_sdk::LocalBusClient::connect(&bob).await?;
        let own=create(&mut sender,node,"alice",[0x77;32],[0x78;32]).await?;
        let peer=create(&mut receiver,node,"bob",[0x79;32],[0x7a;32]).await?;
        for(bus,id,from,to) in [(&mut sender,"alice",&own,&peer),(&mut receiver,"bob",&peer,&own)] {
            let accepted=call(bus,id,"contact.add",json!({"link_id":format!("s74-{id}"),"requester_id":from["principal_commitment"],"target_id":to["principal_commitment"]})).await?;
            assert_eq!(accepted["state"],"accepted");
        }
        let directory=call(&mut receiver,"bob","conversation.directory",json!({"limit":100})).await?;
        assert_eq!(directory["conversations"].as_array().map(Vec::len),Some(0));
        let subscribed=subscribe(&mut receiver,None).await?;
        let mut cursor=subscribed["head_seq"].as_u64().ok_or("missing head")?;
        send(&mut sender,&own,&peer,"first",true).await?;
        receive(&mut receiver,&mut cursor,"env_s74_first",true).await?;
        let messages=call(&mut receiver,"bob","message.read",json!({"conversation_id":"private_s74_first_thread"})).await?;
        assert!(serde_json::to_string(&messages)?.contains("env_s74_first"));
        let object=call(&mut receiver,"bob","object.get",json!({"object_id":"object_s74"})).await?;
        assert_eq!(object["plaintext_base64"],ramflux_protocol::encode_base64url(b"s74 private object bytes"));
        // No message.receive/group.receive RPC appears anywhere in this test.
        drop(receiver);
        send(&mut sender,&own,&peer,"offline",false).await?;
        let mut receiver=ramflux_sdk::LocalBusClient::connect(&bob).await?;
        subscribe(&mut receiver,Some(cursor)).await?;
        receive(&mut receiver,&mut cursor,"env_s74_offline",false).await?;
        let before_restart=cursor;
        drop(receiver);b.start_kill()?;b.wait().await?;
        std::fs::remove_file(&bob)?;
        b=client_directory_daemon_command(&binary,&bob,&root.join("bob"),&node.ca_cert,None).spawn()?;
        mvp_s4_wait_for_socket(&bob).await?;
        let mut receiver=ramflux_sdk::LocalBusClient::connect(&bob).await?;
        // Hydration is asynchronous; wait for account.status, never for inbound receive RPCs.
        let start=std::time::Instant::now();
        loop {
            if call(&mut receiver,"bob","account.status",json!({})).await.is_ok() {break;}
            if start.elapsed()>Duration::from_secs(20) {return Err("account did not rehydrate".into());}
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let subscribed=subscribe(&mut receiver,Some(cursor)).await?;
        assert!(subscribed["head_seq"].as_u64().ok_or("head")?>=before_restart);
        send(&mut sender,&own,&peer,"restart",false).await?;
        receive(&mut receiver,&mut cursor,"env_s74_restart",false).await?;
        assert!(cursor>before_restart);
        Ok::<(),Box<dyn std::error::Error>>(())
    }).await;
    let _ = a.start_kill();
    let _ = b.start_kill();
    let _ = a.wait().await;
    let _ = b.wait().await;
    let _ = std::fs::remove_file(&alice);
    let _ = std::fs::remove_file(&bob);
    result??;
    std::fs::remove_dir_all(root)?;
    Ok(())
}
async fn subscribe(
    bus: &mut ramflux_sdk::LocalBusClient,
    cursor: Option<u64>,
) -> TestResult<Value> {
    call(bus, "bob", "bus.subscribe", json!({"topics":["*"],"since_seq":cursor})).await
}
async fn send(
    bus: &mut ramflux_sdk::LocalBusClient,
    a: &Value,
    b: &Value,
    id: &str,
    attachment: bool,
) -> TestResult {
    let mut body = json!({"conversation_id":"private_s74_first_thread","message_id":format!("message_s74_{id}"),"envelope_id":format!("env_s74_{id}"),"source_principal_id":a["principal_id"],"sender_id":a["device_id"],"recipient_device_id":b["device_id"],"recipient_principal_commitment":b["principal_commitment"],"target_delivery_id":b["target_delivery_id"],"encrypted_body_base64":"","plaintext_body_base64":ramflux_protocol::encode_base64url(b"s74 private DM plaintext"),"created_at":realnet_now_i64(),"ttl":3600});
    if attachment {
        body["attachments"] = json!([{"object_id":"object_s74","plaintext_base64":ramflux_protocol::encode_base64url(b"s74 private object bytes"),"chunk_size":4096,"relay_endpoint":"http://127.0.0.1:64304","name":"s74.txt","mime":"text/plain"}]);
    }
    call(bus, "alice", "message.submit", body).await?;
    Ok(())
}
async fn receive(
    bus: &mut ramflux_sdk::LocalBusClient,
    cursor: &mut u64,
    envelope: &str,
    attachment: bool,
) -> TestResult {
    tokio::time::timeout(Duration::from_secs(30), async {
        let mut message = false;
        let mut progress = !attachment;
        while !message || !progress {
            let event = bus.next_event().await?;
            let seq = event.seq.ok_or("event missing sequence")?;
            assert_eq!(seq, *cursor + 1, "gap or duplicate in unfiltered replay/live stream");
            *cursor = seq;
            let encoded = serde_json::to_string(&event.body)?;
            for forbidden in [
                "s74 private DM plaintext",
                "s74 private object bytes",
                "plaintext_base64",
                "ciphertext",
                "object_content_key",
                "sender_key_seed",
            ] {
                assert!(!encoded.contains(forbidden), "journal leaked {forbidden}");
            }
            if event.method == "message.received" && event.body["message"]["message_id"] == envelope
            {
                message = true;
            }
            if event.method == "object.transfer.progress" {
                progress = true;
            }
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    })
    .await??;
    Ok(())
}
