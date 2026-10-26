// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Production daemon registration, complete-set device addition and peer-side signed revocation.
#![cfg(feature = "realnet")]
use super::*;
use serde_json::{Value, json};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
#[test]
fn id01_realnet_root_bound_device_add_revoke() -> TestResult {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping ID-01: set RAMFLUX_ITEST_REALNET=1 on the QA host");
        return Ok(());
    }
    if std::env::var("RAMFLUX_OBJECT_V3").as_deref() != Ok("1")
        || std::env::var("RAMFLUX_CROSS_GATEWAY").as_deref() != Ok("1")
    {
        return Err("ID-01 requires RAMFLUX_OBJECT_V3=1 RAMFLUX_CROSS_GATEWAY=1".into());
    }
    let stack = start_client_directory_stack_named(
        "ramflux-id01-device-authority",
        S8ComposePorts {
            gateway_http: 65_401,
            gateway_quic: 65_471,
            router_http: 65_400,
            router_mesh: 65_472,
            notify_http: 65_403,
            federation_http: 65_402,
            federation_mesh: 65_473,
            relay_http: 65_404,
            relay_media_udp: 65_440,
            signaling_turn_udp: 65_478,
            signaling_turn_tcp: 65_479,
            retention_http: 65_407,
        },
        &[
            ("RAMFLUX_ITEST_GATEWAY_B_HTTP_PORT".into(), "65408".into()),
            ("RAMFLUX_ITEST_GATEWAY_B_QUIC_PORT".into(), "65474".into()),
            ("RAMFLUX_ITEST_GATEWAY_B_TCP_PORT".into(), "65474".into()),
            ("RAMFLUX_ITEST_RELAY_CLIENT_QUIC_PORT".into(), "65475".into()),
            (
                COMPOSE_FAILURE_LOG_SERVICES_ENV.into(),
                "ramflux-router,ramflux-gateway,ramflux-gateway-b,ramflux-relay".into(),
            ),
        ],
    )?;
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(run(&stack.node))
}
async fn run(node: &S8RealnetNode) -> TestResult {
    wait_relay_quic_healthy("127.0.0.1:65475", "ramflux-relay", &node.ca_cert).await?;
    wait_for_private_gateway_quic(node.gateway_quic_addr, &node.ca_cert).await?;
    let root = temp_root("id01")?;
    let sockets = [root.join("a.sock"), root.join("b.sock")];
    let binary = mvp_s4_build_rf_binary().await?;
    let mut children = Vec::new();
    for (index, socket) in sockets.iter().enumerate() {
        let mut command = client_directory_daemon_command(
            &binary,
            socket,
            &root.join(format!("account-{index}")),
            &node.ca_cert,
            None,
        );
        command.env("RAMFLUX_SDK_RELAY_QUIC_ADDR", "127.0.0.1:65475");
        children.push(command.spawn()?);
    }
    let result=tokio::time::timeout(Duration::from_secs(180),async {
        for socket in &sockets { mvp_s4_wait_for_socket(socket).await?; }
        let mut a=ramflux_sdk::LocalBusClient::connect(&sockets[0]).await?;
        let mut b=ramflux_sdk::LocalBusClient::connect(&sockets[1]).await?;
        let alice=create(&mut a,node,"alice",[0x41;32],[0x42;32]).await?;
        let bob=create(&mut b,node,"bob",[0x51;32],[0x52;32]).await?;
        for (bus,id,owner,peer) in [(&mut a,"alice",&alice,&bob),(&mut b,"bob",&bob,&alice)] {
            call(bus,id,"contact.add",json!({"link_id":format!("id01-{id}"),"requester_id":owner["principal_commitment"],"target_id":peer["principal_commitment"]})).await?;
        }
        let original=call(&mut b,"bob","device.refresh",json!({"principal_commitment":alice["principal_commitment"]})).await?;
        assert_eq!(original["device_set_epoch"],1);assert_eq!(original["kind_asserted"],"human");assert_eq!(original["kind_verified"],true);assert_eq!(original["safety_kind_verified"],false);
        let second_seed=[0x43u8;32];
        call(&mut a,"alice","device.activate",json!({"device_id":"id01-alice-two","target_delivery_id":"id01-target-alice-two","device_seed":second_seed,"device_epoch":1})).await?;
        let added=call(&mut b,"bob","device.refresh",json!({"principal_commitment":alice["principal_commitment"]})).await?;
        assert_eq!(added["device_set_epoch"],2);assert_eq!(added["devices"].as_array().map(Vec::len),Some(2));
        let sent=send(&mut b,&bob,&alice,"id01-before-revoke").await?;
        assert!(serde_json::to_string(&sent)?.contains("id01-before-revoke"));
        let revoked=call(&mut a,"alice","device.revoke",json!({"device_id":"id01-alice-two"})).await?;
        assert_eq!(revoked["revoked"],true);assert_eq!(revoked["device_set_epoch"],3);
        let observed=call(&mut b,"bob","device.refresh",json!({"principal_commitment":alice["principal_commitment"]})).await?;
        assert_eq!(observed["device_set_epoch"],3);
        let tombstone=observed["devices"].as_array().and_then(|d|d.iter().find(|d|d["device_id"]=="id01-alice-two")).ok_or("signed tombstone missing")?;
        assert_eq!(tombstone["status"],"revoked");assert!(tombstone["revoked_at"].as_i64().is_some());
        assert!(send(&mut b,&bob,&alice,"id01-after-revoke").await.is_err());
        realnet_step("ID-01 peer revocation enforced",format!("root={} epoch=3 revoked=id01-alice-two",alice["principal_commitment"]));
        Ok::<_,Box<dyn std::error::Error>>(())
    }).await;
    for child in &mut children {
        let _ = child.start_kill();
        let _ = child.wait().await;
    }
    let _ = std::fs::remove_dir_all(root);
    result??;
    Ok(())
}
async fn create(
    bus: &mut ramflux_sdk::LocalBusClient,
    node: &S8RealnetNode,
    id: &str,
    root_seed: [u8; 32],
    device_seed: [u8; 32],
) -> TestResult<Value> {
    let principal = format!("id01-{id}");
    let device = format!("id01-{id}-one");
    let target = format!("id01-target-{id}-one");
    let body = json!({"node_id":null,"local_account_id":id,"principal_id":principal,"principal_commitment":"","device_id":device,"target_delivery_id":target,"account_secret":"id01-test-secret","root_seed":root_seed,"device_seed":device_seed,"client_mode":"attended_cli","kind":"human","gateway":{"bind_addr":"0.0.0.0:0","gateway_addr":node.gateway_quic_addr.to_string(),"server_name":"localhost","ca_cert":node.ca_cert,"principal_id":principal,"device_id":device,"target_delivery_id":target,"prekey_http_url":null}});
    let value = bus.request(None, "account", "account.create", body).await?;
    assert_eq!(value["local_account_id"], id);
    Ok(value)
}
async fn call(
    bus: &mut ramflux_sdk::LocalBusClient,
    account: &str,
    method: &str,
    body: Value,
) -> TestResult<Value> {
    Ok(bus
        .request(Some(account.into()), method.split('.').next().ok_or("method")?, method, body)
        .await?)
}
async fn send(
    bus: &mut ramflux_sdk::LocalBusClient,
    bob: &Value,
    alice: &Value,
    id: &str,
) -> TestResult<Value> {
    call(bus,"bob","message.submit",json!({"conversation_id":"id01-thread","message_id":id,"envelope_id":id,"source_principal_id":bob["principal_id"],"sender_id":bob["device_id"],"recipient_device_id":"id01-alice-two","recipient_principal_commitment":alice["principal_commitment"],"target_delivery_id":"id01-target-alice-two","encrypted_body_base64":"","plaintext_body_base64":ramflux_protocol::encode_base64url(b"root-authorized device traffic"),"created_at":realnet_now_i64(),"ttl":600})).await
}
