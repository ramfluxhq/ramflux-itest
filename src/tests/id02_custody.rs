// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Born-v3 account creation, actual gateway proxy receipts and recipient-side DM proof.
#![cfg(feature = "realnet")]
use crate::*;
use ramflux_protocol::custody::{BindingMode, CustodyRefusal, DeviceRef};
use ramflux_sdk::custody::{
    CreateInput, CreationState, CustodyBusClient, CustodyConnection, CustodyNetworkConfig,
    MemoryPrimaryVault,
};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

#[test]
fn id02_born_v3_realnet_register_session_and_dm() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        return Ok(());
    }
    if std::env::var("RAMFLUX_ID02_CLIENT_CHILD").as_deref() == Ok("1") {
        return tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(client());
    }
    let ports = S8ComposePorts {
        gateway_http: 64_781,
        gateway_quic: 64_641,
        router_http: 64_780,
        router_mesh: 64_642,
        notify_http: 64_783,
        federation_http: 64_782,
        federation_mesh: 64_643,
        relay_http: 64_784,
        relay_media_udp: 64_182,
        signaling_turn_udp: 64_660,
        signaling_turn_tcp: 64_661,
        retention_http: 64_787,
    };
    let mut node = start_s8_realnet_compose_project_with_env(
        "ramflux-id02-born-v3",
        ports,
        &[("RAMFLUX_CUSTODY_ITEST_ENABLE".into(), "1".into())],
    )?;
    let mut child = std::process::Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "tests::id02_custody::id02_born_v3_realnet_register_session_and_dm",
            "--nocapture",
        ])
        .env("RAMFLUX_ID02_CLIENT_CHILD", "1")
        .env("RAMFLUX_ID02_GATEWAY", node.gateway_quic_addr.to_string())
        .env("RAMFLUX_ID02_CA", &node.ca_cert)
        .env("RAMFLUX_ID02_NODE_ID", &node.node_id)
        .env("RAMFLUX_ID02_NODE_PUBLIC_KEY", &node.federation_node_public_key)
        .spawn()?;
    let deadline = Instant::now() + Duration::from_mins(3);
    loop {
        if let Some(status) = child.try_wait()? {
            if !status.success() {
                return Err(format!("born-v3 client flow failed: {status}").into());
            }
            node.guard.mark_success();
            return Ok(());
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err("born-v3 realnet child exceeded 180 seconds".into());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}
struct Root(PathBuf);
impl Drop for Root {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
struct Shutdown(tokio::sync::watch::Sender<bool>);
impl Drop for Shutdown {
    fn drop(&mut self) {
        let _ = self.0.send(true);
    }
}
async fn create(
    socket: &Path,
    id: &str,
    principal: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut bus = loop {
        match CustodyBusClient::connect(socket).await {
            Ok(c) => break c,
            Err(error) => {
                if Instant::now() > deadline {
                    return Err(error.into());
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    };
    let anchor = bus
        .begin(&CreateInput {
            local_account_id: id.into(),
            principal_id: principal.into(),
            device_id: "primary".into(),
            display_name: principal.into(),
            principal_kind: ramflux_protocol::PrincipalKind::Human,
            custodian_account_id: None,
        })
        .await?;
    let phrase = bus.show_once().await?;
    let words: Vec<_> = phrase.split_whitespace().map(|w| Zeroizing::new(w.to_string())).collect();
    drop(phrase);
    let positions = bus.hidden_challenge().await?;
    let confirmation = std::array::from_fn(|i| words[usize::from(positions[i] - 1)].clone());
    let confirmed = bus.confirm(&confirmation).await?;
    assert_eq!(confirmed.state, CreationState::NetworkingPending);
    Ok(anchor)
}
fn network_config(
    root: &Path,
    id: &str,
) -> Result<CustodyNetworkConfig, Box<dyn std::error::Error>> {
    Ok(CustodyNetworkConfig {
        account_root: root.to_path_buf(),
        account_id: id.into(),
        device_id: "primary".into(),
        gateway_address: std::env::var("RAMFLUX_ID02_GATEWAY")?.parse()?,
        server_name: "ramflux-gateway".into(),
        ca_certificate: std::env::var_os("RAMFLUX_ID02_CA").ok_or("CA missing")?.into(),
        node_id: std::env::var("RAMFLUX_ID02_NODE_ID")?,
        node_public_key: std::env::var("RAMFLUX_ID02_NODE_PUBLIC_KEY")?,
        audience: "ramflux-router".into(),
        binding_mode: BindingMode::HomeRelayReceipt,
        allow_no_channel_binding: false,
        timeout: Duration::from_secs(20),
    })
}
async fn client() -> Result<(), Box<dyn std::error::Error>> {
    let root = Root(temp_root("id02_born_v3_client")?);
    let socket = root.0.join("bus.sock");
    let vault = Arc::new(MemoryPrimaryVault::default());
    let mut bus = ramflux_sdk::LocalBusConfig::new(&socket, &root.0);
    bus.enable_born_v3_creation = true;
    bus.custody_vault = Some(vault.clone());
    let (stop, receiver) = tokio::sync::watch::channel(false);
    let flow = async {
        let _shutdown = Shutdown(stop);
        let alice_anchor = create(&socket, "alice", "alice").await?;
        let bob_anchor = create(&socket, "bob", "bob").await?;
        create(&socket, "impostor", "alice").await?;
        let mut alice =
            CustodyConnection::connect(network_config(&root.0, "alice")?, vault.clone()).await?;
        let mut bob =
            CustodyConnection::connect(network_config(&root.0, "bob")?, vault.clone()).await?;
        assert_eq!(alice.account().state(), CreationState::Live);
        assert_eq!(bob.account().state(), CreationState::Live);
        assert_eq!(
            alice.session().ok_or("alice session missing")?.binding_mode,
            BindingMode::HomeRelayReceipt
        );
        let alice_ref = DeviceRef {
            account_anchor: alice_anchor,
            device_id: "primary".into(),
            device_epoch: 1,
        };
        let bob_ref =
            DeviceRef { account_anchor: bob_anchor, device_id: "primary".into(), device_epoch: 1 };
        let sent = alice.send_dm(&bob_ref, b"born-v3 realnet confidential hello").await?;
        let received = bob.receive_dm(0).await?;
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].envelope_id, sent);
        assert_eq!(received[0].source, alice_ref);
        assert_eq!(received[0].plaintext.as_slice(), b"born-v3 realnet confidential hello");
        bob.ack_dm(&received[0]).await?;
        assert!(bob.receive_dm(0).await?.is_empty());
        bob.send_dm(&alice_ref, b"born-v3 realnet confidential reply").await?;
        let reply = alice.receive_dm(0).await?;
        assert_eq!(reply.len(), 1);
        assert_eq!(reply[0].plaintext.as_slice(), b"born-v3 realnet confidential reply");
        assert!(matches!(
            CustodyConnection::connect(network_config(&root.0, "impostor")?, vault.clone()).await,
            Err(ramflux_sdk::SdkError::CustodyNetwork(CustodyRefusal::PrincipalIdTaken))
        ));
        assert_eq!(
            ramflux_sdk::custody::load_account(
                &root.0,
                "impostor",
                ramflux_node_core::now_unix_seconds()
            )?
            .state(),
            CreationState::NetworkingPending
        );
        // Reconnect uses fresh challenges and TLS material; persisted Live is never a session grant.
        drop(alice);
        let alice = CustodyConnection::connect(network_config(&root.0, "alice")?, vault).await?;
        assert_eq!(alice.account().state(), CreationState::Live);
        Ok::<_, Box<dyn std::error::Error>>(())
    };
    tokio::time::timeout(Duration::from_mins(2), async {
        let (daemon, result) =
            tokio::join!(ramflux_sdk::serve_local_bus_until(bus, receiver), flow);
        daemon?;
        result
    })
    .await?
}
