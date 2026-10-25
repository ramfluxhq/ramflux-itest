// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! First contact through production discovery, root-bound registration and encrypted message requests.
#![cfg(feature = "realnet")]
use super::*;
use serde_json::{Value, json};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
#[test]
fn contact02_realnet_request_then_first_message() -> TestResult {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping contact02: set RAMFLUX_ITEST_REALNET=1 on the container host");
        return Ok(());
    }
    let topology = start_client_discovery_topology_named("ramflux-contact02", 65100)?;
    let mut logs = FailureLogs { topology: &topology, complete: false };
    let result = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(Box::pin(run(&topology)));
    logs.complete = result.is_ok();
    result
}
struct FailureLogs<'a> {
    topology: &'a ClientDiscoveryTopology,
    complete: bool,
}
impl Drop for FailureLogs<'_> {
    fn drop(&mut self) {
        if !self.complete {
            self.topology.dump_contact_failure_logs();
        }
    }
}
async fn run(topology: &ClientDiscoveryTopology) -> TestResult {
    wait_for_private_gateway_quic("127.0.0.1:65143".parse()?, &topology.ca).await?;
    let root = temp_root("contact02")?;
    let a = root.join("a.sock");
    let b = root.join("b.sock");
    let (stop_a, rx_a) = tokio::sync::watch::channel(false);
    let (stop_b, rx_b) = tokio::sync::watch::channel(false);
    let server_a = ramflux_sdk::serve_local_bus_until(
        ramflux_sdk::LocalBusConfig::new(&a, root.join("a")),
        rx_a,
    );
    let server_b = ramflux_sdk::serve_local_bus_until(
        ramflux_sdk::LocalBusConfig::new(&b, root.join("b")),
        rx_b,
    );
    let flow = async {
        let result=async {
            mvp_s4_wait_for_socket(&a).await?;mvp_s4_wait_for_socket(&b).await?;
            let binary=mvp_s4_build_rf_binary().await?;
            for socket in [&a,&b] {configure(&binary,socket,&topology.origin).await?;}
            let human=create(&binary,&a,"human",("a1","a2"),false).await?;
            let machine=create(&binary,&b,"machine",("b1","b2"),true).await?;
            let manual=create(&binary,&b,"manual",("c1","c2"),false).await?;
            let mut sender=ramflux_sdk::LocalBusClient::connect(&a).await?;
            let mut receiver=ramflux_sdk::LocalBusClient::connect(&b).await?;
            let mut accepted=ramflux_sdk::LocalBusClient::connect(&a).await?;
            call(&mut accepted,"human","bus.subscribe",json!({"topics":["contact.accepted"]})).await?;
            step("auto_accept_first_message_without_reciprocal_add");
            assert_eq!(call(&mut receiver,"machine","contact.requests.policy.get",json!({})).await?["contact_requests"],"auto_accept");
            call(&mut sender,"human","contact.add",json!({"principal_id":machine["principal_id"],"note":"First contact"})).await?;
            send(&mut sender,&human,&machine,"automatic-first-message").await?;
            wait_message(&mut receiver,"machine","automatic-first-message").await?;
            wait_accepted(&mut accepted,machine["principal_id"].as_str().ok_or("machine principal")?).await?;
            assert_eq!(call(&mut receiver,"machine","contact.requests.list",json!({})).await?["requests"],json!([]));
            step("manual_card_request_and_held_message");
            assert_eq!(call(&mut receiver,"manual","contact.requests.policy.get",json!({})).await?["contact_requests"],"manual");
            let mut requested=ramflux_sdk::LocalBusClient::connect(&b).await?;
            call(&mut requested,"manual","bus.subscribe",json!({"topics":["contact.requested","message.received"]})).await?;
            let card=call(&mut receiver,"manual","contact.card.export",json!({})).await?;
            call(&mut sender,"human","contact.add",json!({"card":card["card"],"note":"Manual consent preview"})).await?;
            let outgoing=call(&mut sender,"human","contact.requests.list",json!({})).await?;
            let outgoing=outgoing["requests"].as_array().and_then(|rows|rows.iter().find(|row|row["principal_id"]==manual["principal_id"])).ok_or("outgoing request missing")?;
            assert_eq!(outgoing["state"],"pending");
            assert_eq!(outgoing["direction"],"outbound");
            assert!(outgoing["request_id"].as_str().is_some());
            send(&mut sender,&human,&manual,"held-manual-first-message").await?;
            let request=wait_request(&mut receiver,"manual").await?;
            wait_requested(&mut requested,human["principal_id"].as_str().ok_or("human principal")?).await?;
            assert_eq!(request["principal_id"],human["principal_id"]);
            assert_eq!(request["safety_number"].as_array().map(Vec::len),Some(12));
            assert!(request["preview"].as_str().is_some_and(|text|text.contains("held-manual-first-message")));
            let read=call(&mut receiver,"manual","message.read",json!({"conversation_id":"contact02-held-manual-first-message"})).await?;
            assert_eq!(read["messages"],json!([]),"unaccepted content escaped its request queue");
            step("accept_releases_content_and_notifies_requester");
            call(&mut receiver,"manual","contact.accept",json!({"request_id":request["request_id"]})).await?;
            wait_message(&mut receiver,"manual","held-manual-first-message").await?;
            wait_received(&mut requested).await?;
            wait_accepted(&mut accepted,manual["principal_id"].as_str().ok_or("manual principal")?).await?;
            assert_eq!(call(&mut receiver,"manual","contact.requests.list",json!({})).await?["requests"],json!([]));
            send(&mut sender,&human,&manual,"ordinary-message-after-consent").await?;
            wait_message(&mut receiver,"manual","ordinary-message-after-consent").await?;
            step("complete");
            Ok::<(),Box<dyn std::error::Error>>(())
        }.await;
        let _ = stop_a.send(true);
        let _ = stop_b.send(true);
        result
    };
    let (a_result, b_result, result) = tokio::time::timeout(Duration::from_mins(5), async {
        tokio::join!(server_a, server_b, Box::pin(flow))
    })
    .await?;
    a_result?;
    b_result?;
    result?;
    std::fs::remove_dir_all(root)?;
    Ok(())
}
async fn rf(binary: &Path, socket: &Path, args: &[&str]) -> TestResult<Value> {
    let mut options = vec!["--socket", socket.to_str().ok_or("socket path")?];
    options.extend_from_slice(args);
    mvp_s10_rf_json(binary, &options, "contact02").await
}
async fn configure(binary: &Path, socket: &Path, origin: &str) -> TestResult {
    rf(binary, socket, &["node", "add", origin]).await?;
    rf(binary, socket, &["node", "confirm", "localhost"]).await?;
    rf(binary, socket, &["node", "set-default", "localhost"]).await?;
    Ok(())
}
async fn create(
    binary: &Path,
    socket: &Path,
    id: &str,
    seeds: (&str, &str),
    headless: bool,
) -> TestResult<Value> {
    let principal = format!("principal_contact02_{id}");
    let device = format!("device_contact02_{id}");
    let target = format!("target_contact02_{id}");
    rf(
        binary,
        socket,
        &[
            "account",
            "create",
            "--node",
            "localhost",
            "--account",
            id,
            "--principal",
            &principal,
            "--device",
            &device,
            "--target",
            &target,
            "--secret",
            "test-only-secret",
            "--root-seed-byte-hex",
            seeds.0,
            "--device-seed-byte-hex",
            seeds.1,
            "--client-mode",
            if headless { "headless_ai" } else { "attended_cli" },
        ],
    )
    .await
}
async fn call(
    bus: &mut ramflux_sdk::LocalBusClient,
    id: &str,
    method: &str,
    body: Value,
) -> TestResult<Value> {
    bus.request(Some(id.into()), "contact02", method, body)
        .await
        .map_err(|error| format!("account={id} method={method}: {error}").into())
}
async fn send(
    bus: &mut ramflux_sdk::LocalBusClient,
    source: &Value,
    target: &Value,
    text: &str,
) -> TestResult {
    call(bus,"human","message.submit",json!({"conversation_id":format!("contact02-{text}"),
        "message_id":text,"envelope_id":text,"source_principal_id":source["principal_id"],"sender_id":source["device_id"],
        "recipient_device_id":target["device_id"],"recipient_principal_commitment":target["principal_commitment"],
        "target_delivery_id":target["target_delivery_id"],"encrypted_body_base64":"",
        "plaintext_body_base64":ramflux_protocol::encode_base64url(text),"created_at":realnet_now_i64(),"ttl":300})).await?;
    Ok(())
}
async fn wait_message(bus: &mut ramflux_sdk::LocalBusClient, id: &str, text: &str) -> TestResult {
    for _ in 0..100 {
        call(bus, id, "message.receive", json!({"limit":32,"auto_fetch_attachments":false}))
            .await?;
        let read =
            call(bus, id, "message.read", json!({"conversation_id":format!("contact02-{text}")}))
                .await?;
        if read["messages"]
            .as_array()
            .is_some_and(|messages| messages.iter().any(|message| message["body_utf8"] == text))
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(format!("message did not arrive: account={id} message={text}").into())
}
async fn wait_request(bus: &mut ramflux_sdk::LocalBusClient, id: &str) -> TestResult<Value> {
    for _ in 0..100 {
        call(bus, id, "message.receive", json!({"limit":32,"auto_fetch_attachments":false}))
            .await?;
        let list = call(bus, id, "contact.requests.list", json!({})).await?;
        if let Some(request) = list["requests"]
            .as_array()
            .and_then(|rows| rows.iter().find(|row| row["message_count"] == 1))
        {
            return Ok(request.clone());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err("pending message request did not arrive".into())
}
async fn wait_accepted(bus: &mut ramflux_sdk::LocalBusClient, principal: &str) -> TestResult {
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let event = bus.next_event().await?;
            if event.method == "contact.accepted" && event.body["principal_id"] == principal {
                assert!(
                    event.body.get("manifest").is_none() && event.body.get("signature").is_none()
                );
                return Ok::<(), Box<dyn std::error::Error>>(());
            }
        }
    })
    .await??;
    Ok(())
}
async fn wait_requested(bus: &mut ramflux_sdk::LocalBusClient, principal: &str) -> TestResult {
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let event = bus.next_event().await?;
            if event.method == "contact.requested"
                && event.body["principal_id"] == principal
                && event.body["message_count"] == 1
            {
                assert!(event.body.get("preview").is_none());
                assert!(event.body.get("note").is_none());
                assert!(event.body.get("safety_number").is_none());
                assert!(event.body.get("manifest").is_none());
                assert!(event.body.get("signature").is_none());
                assert!(event.body.get("private_key").is_none());
                return Ok::<(), Box<dyn std::error::Error>>(());
            }
        }
    })
    .await??;
    Ok(())
}
async fn wait_received(bus: &mut ramflux_sdk::LocalBusClient) -> TestResult {
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let event = bus.next_event().await?;
            if event.method == "message.received"
                && event.body["message"]["conversation_id"] == "contact02-held-manual-first-message"
            {
                return Ok::<(), Box<dyn std::error::Error>>(());
            }
        }
    })
    .await??;
    Ok(())
}
fn step(phase: &str) {
    eprintln!("STEP: contact02 timestamp={} phase={phase}", realnet_now_i64());
}
