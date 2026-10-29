// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Born-v3 account creation, actual gateway proxy receipts and recipient-side DM proof.
#![cfg(feature = "realnet")]
use crate::*;
use ramflux_sdk::LocalBusClient;
use ramflux_sdk::custody::MemoryPrimaryVault;
use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

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
        &[("RAMFLUX_ITEST_RELAY_CLIENT_QUIC_PORT".into(), "64785".into())],
    )?;
    let mut child = std::process::Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "tests::id02_custody::id02_born_v3_realnet_register_session_and_dm",
            "--nocapture",
        ])
        .env("RAMFLUX_ID02_CLIENT_CHILD", "1")
        .env(
            "RAMFLUX_ID02_PROFILE",
            serde_json::to_string(&native_node_profile(&node, "127.0.0.1:64785")?)?,
        )
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
async fn client() -> Result<(), Box<dyn std::error::Error>> {
    let root = Root(temp_root("id02_born_v3_client")?);
    let socket = root.0.join("bus.sock");
    let profile: ramflux_sdk::NodeProfile =
        serde_json::from_str(&std::env::var("RAMFLUX_ID02_PROFILE")?)?;
    let node_id = profile.node_id.clone();
    let mut config = ramflux_sdk::LocalBusConfig::new(&socket, &root.0);
    config.custody_vault = Some(Arc::new(MemoryPrimaryVault::default()));
    config.builtin_nodes = vec![profile];
    let (stop, shutdown_rx) = tokio::sync::watch::channel(false);
    let flow = async {
        let _shutdown = Shutdown(stop);
        mvp_s4_wait_for_socket(&socket).await?;
        let mut alice_bus = LocalBusClient::connect(&socket).await?;
        let mut bob_bus = LocalBusClient::connect(&socket).await?;
        select_native_node(&mut alice_bus, &node_id).await?;
        let alice = create_native_account(&socket, "Alice").await?;
        let bob = create_native_account(&socket, "Bob").await?;
        let same_name = create_native_account(&socket, "Alice").await?;
        assert_ne!(same_name.principal_id, alice.principal_id);
        assert_ne!(same_name.anchor, alice.anchor);
        alice_bus
            .request(
                Some(alice.account_id.clone()),
                "contact",
                "contact.add",
                serde_json::json!({"principal_id":bob.principal_id}),
            )
            .await?;
        bob_bus
            .request(
                Some(bob.account_id.clone()),
                "contact",
                "contact.accept",
                serde_json::json!({"principal_id":alice.principal_id}),
            )
            .await?;
        super::contact01_contact_resolution::exchange(
            &mut alice_bus,
            &mut bob_bus,
            &alice,
            &bob,
            "id02",
        )
        .await?;
        // Reopen the ordinary account actor; persisted Live is never a session grant.
        alice_bus
            .request(
                Some(alice.account_id.clone()),
                "account",
                "account.lock",
                serde_json::json!({}),
            )
            .await?;
        alice_bus
            .request(
                Some(alice.account_id.clone()),
                "account",
                "account.unlock",
                serde_json::json!({"passphrase":NATIVE_DATA_PASSPHRASE}),
            )
            .await?;
        let status = alice_bus
            .request(
                Some(alice.account_id.clone()),
                "account",
                "account.status",
                serde_json::json!({}),
            )
            .await?;
        assert_eq!(status["networking"], "live");
        super::contact01_contact_resolution::exchange(
            &mut alice_bus,
            &mut bob_bus,
            &alice,
            &bob,
            "id02-reconnect",
        )
        .await?;
        Ok::<_, Box<dyn std::error::Error>>(())
    };
    tokio::time::timeout(
        Duration::from_mins(2),
        Box::pin(async {
            let (daemon, result) =
                tokio::join!(ramflux_sdk::serve_local_bus_until(config, shutdown_rx), flow);
            daemon?;
            result
        }),
    )
    .await?
}
