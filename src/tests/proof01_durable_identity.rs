// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Expired offline publications stay usable; live and restarted daemons renew admission proofs.
#![cfg(feature = "realnet")]
use super::*;
use serde_json::{Value, json};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const TTL: i64 = 60;
#[test]
fn proof01_realnet_durable_identity_after_session_proof_expiry() -> TestResult {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping PROOF-01: RAMFLUX_ITEST_REALNET=1 is required");
        return Ok(());
    }
    if std::env::var("RAMFLUX_OBJECT_V3").as_deref() != Ok("1")
        || std::env::var("RAMFLUX_CROSS_GATEWAY").as_deref() != Ok("1")
    {
        return Err("PROOF-01 requires object v3 and cross-gateway overlays".into());
    }
    let stack = start_client_directory_stack_named(
        "ramflux-proof01-identity",
        S8ComposePorts {
            gateway_http: 63_280,
            gateway_quic: 63_281,
            router_http: 63_282,
            router_mesh: 63_283,
            federation_http: 63_284,
            federation_mesh: 63_285,
            notify_http: 63_286,
            relay_http: 63_287,
            retention_http: 63_289,
            relay_media_udp: 63_293,
            signaling_turn_udp: 63_294,
            signaling_turn_tcp: 63_295,
        },
        &[
            ("RAMFLUX_ITEST_RELAY_CLIENT_QUIC_PORT".into(), "63288".into()),
            ("RAMFLUX_ITEST_GATEWAY_B_HTTP_PORT".into(), "63290".into()),
            ("RAMFLUX_ITEST_GATEWAY_B_QUIC_PORT".into(), "63291".into()),
            ("RAMFLUX_ITEST_GATEWAY_B_TCP_PORT".into(), "63291".into()),
            (
                COMPOSE_FAILURE_LOG_SERVICES_ENV.into(),
                "ramflux-router,ramflux-gateway,ramflux-gateway-b,ramflux-relay".into(),
            ),
        ],
    )?;
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(run(&stack.node))
}
async fn run(node: &S8RealnetNode) -> TestResult {
    wait_relay_quic_healthy("127.0.0.1:63288", "ramflux-relay", &node.ca_cert).await?;
    wait_for_private_gateway_quic(node.gateway_quic_addr, &node.ca_cert).await?;
    let root = temp_root("proof01")?;
    let binary = mvp_s4_build_rf_binary().await?;
    let sockets = [root.join("a.sock"), root.join("b.sock")];
    let data = [root.join("a"), root.join("b")];
    let spawn = |index: usize| {
        let mut command = client_directory_daemon_command(
            &binary,
            &sockets[index],
            &data[index],
            &node.ca_cert,
            None,
        );
        command
            .env("RAMFLUX_TEST_BRANCH_PROOF_TTL_SECS", TTL.to_string())
            .env("RAMFLUX_SDK_RELAY_QUIC_ADDR", "127.0.0.1:63288");
        command.spawn()
    };
    let mut a = spawn(0)?;
    let mut b = spawn(1)?;
    let result = tokio::time::timeout(Duration::from_secs(240), async {
        for socket in &sockets {
            mvp_s4_wait_for_socket(socket).await?;
        }
        let mut alice = ramflux_sdk::LocalBusClient::connect(&sockets[0]).await?;
        let mut bob = ramflux_sdk::LocalBusClient::connect(&sockets[1]).await?;
        let alice_root = create(&mut alice, node, "alice", [0xa1; 32], [0xa2; 32]).await?;
        let bob_root = create(&mut bob, node, "bob", [0xb1; 32], [0xb2; 32]).await?;
        let initial = manifest(node, &alice_root)?;
        let original = initial.devices.first().ok_or("alice device")?.branch_proof.clone();
        assert_eq!(
            original.expires_at - original.issued_at,
            TTL,
            "rf must include the default-off test proof feature"
        );
        let bob_initial = manifest(node, &bob_root)?.devices.remove(0).branch_proof;
        drop(alice);
        a.start_kill()?;
        a.wait().await?;
        std::fs::remove_file(&sockets[0])?;
        realnet_step(
            "PROOF-01 waiting for stopped account proof expiry",
            format!("expires_at={} ttl={TTL}", original.expires_at),
        );
        while itest_now_unix_seconds() <= original.expires_at + 2 {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        let expired = manifest(node, &alice_root)?;
        assert_eq!(
            expired.devices[0].branch_proof.proof_id, original.proof_id,
            "offline account must still advertise the expired registration proof"
        );
        assert!(expired.devices[0].branch_proof.expires_at < itest_now_unix_seconds());
        let added =
            call(&mut bob, "bob", "contact.add", json!({"principal_id":"proof01-alice"})).await?;
        assert_eq!(added["contact"]["principal_id"], "proof01-alice");
        assert_eq!(added["contact"]["reachable"], true);
        let bob_live = manifest(node, &bob_root)?;
        assert_ne!(bob_live.devices[0].branch_proof.proof_id, bob_initial.proof_id);
        assert!(bob_live.devices[0].branch_proof.expires_at > bob_initial.expires_at);
        assert_eq!(bob_live.signed_device_set.as_ref().map(|s| s.device_set_epoch), Some(1));
        a = spawn(0)?;
        mvp_s4_wait_for_socket(&sockets[0]).await?;
        let mut alice = ramflux_sdk::LocalBusClient::connect(&sockets[0]).await?;
        let started = std::time::Instant::now();
        loop {
            if manifest(node, &alice_root)?
                .devices
                .first()
                .is_some_and(|d| d.branch_proof.proof_id != original.proof_id)
            {
                break;
            }
            if started.elapsed() > Duration::from_secs(30) {
                return Err("restarted account did not renew its expired proof".into());
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        let renewed = manifest(node, &alice_root)?;
        assert_eq!(renewed.signed_device_set.as_ref().map(|s| s.device_set_epoch), Some(1));
        create(&mut bob, node, "carol", [0xc1; 32], [0xc2; 32]).await?;
        let added =
            call(&mut alice, "alice", "contact.add", json!({"principal_id":"proof01-carol"}))
                .await?;
        assert_eq!(added["contact"]["principal_id"], "proof01-carol");
        assert_eq!(added["contact"]["reachable"], true);
        realnet_step(
            "PROOF-01 durable lookup and renewed contact addition passed",
            format!(
                "initial_expiry={} renewed_expiry={}",
                original.expires_at, renewed.devices[0].branch_proof.expires_at
            ),
        );
        Ok::<(), Box<dyn std::error::Error>>(())
    })
    .await;
    let _ = a.start_kill();
    let _ = a.wait().await;
    let _ = b.start_kill();
    let _ = b.wait().await;
    let _ = std::fs::remove_dir_all(root);
    result??;
    Ok(())
}
fn manifest(
    node: &S8RealnetNode,
    root: &str,
) -> TestResult<ramflux_node_core::DeviceManifestResponse> {
    let manifest: Option<ramflux_node_core::DeviceManifestResponse> =
        ramflux_node_core::itest_http_get_json(&format!(
            "{}/mvp1/device-manifest/{root}",
            node.gateway_url
        ))?;
    manifest.ok_or_else(|| "published manifest missing".into())
}
async fn create(
    bus: &mut ramflux_sdk::LocalBusClient,
    node: &S8RealnetNode,
    id: &str,
    root_seed: [u8; 32],
    device_seed: [u8; 32],
) -> TestResult<String> {
    let principal = format!("proof01-{id}");
    let target = format!("proof01-target-{id}");
    let value=bus.request(None,"account","account.create",json!({"node_id":null,"local_account_id":id,"principal_id":principal,"principal_commitment":"","device_id":principal,"target_delivery_id":target,"account_secret":"proof01-test-secret","root_seed":root_seed,"device_seed":device_seed,"client_mode":"attended_cli","kind":"human","gateway":{"bind_addr":"0.0.0.0:0","gateway_addr":node.gateway_quic_addr.to_string(),"server_name":"localhost","ca_cert":node.ca_cert,"principal_id":principal,"device_id":principal,"target_delivery_id":target,"prekey_http_url":null}})).await?;
    Ok(value["principal_commitment"].as_str().ok_or("root commitment")?.into())
}
async fn call(
    bus: &mut ramflux_sdk::LocalBusClient,
    id: &str,
    method: &str,
    body: Value,
) -> TestResult<Value> {
    Ok(bus.request(Some(id.into()), "contact", method, body).await?)
}
