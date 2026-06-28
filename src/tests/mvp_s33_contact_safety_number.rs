// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use super::*;

#[cfg(feature = "realnet")]
#[test]
fn mvp_s33_realnet_rf_contact_safety_number() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    let node = start_s10_private_node_compose()?;
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async {
        wait_for_private_gateway_quic(node.gateway_quic_addr, &node.ca_cert).await?;
        Box::pin(mvp_s33_assert_contact_safety_number(node.gateway_quic_addr, &node.ca_cert))
            .await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    drop(node);
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
#[allow(clippy::too_many_lines)]
async fn mvp_s33_assert_contact_safety_number(
    gateway_quic_addr: std::net::SocketAddr,
    ca_cert: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let temp_root = temp_root("s33_contact_safety_number")?;
    let rf_binary = mvp_s4_build_rf_binary().await?;
    let alice_socket = temp_root.join("alice/rfd.sock");
    let bob_socket = temp_root.join("bob/rfd.sock");
    let (alice_shutdown_tx, alice_shutdown_rx) = tokio::sync::watch::channel(false);
    let (bob_shutdown_tx, bob_shutdown_rx) = tokio::sync::watch::channel(false);
    let alice_server = ramflux_sdk::serve_local_bus_until(
        ramflux_sdk::LocalBusConfig::new(&alice_socket, temp_root.join("alice/data")),
        alice_shutdown_rx,
    );
    let bob_server = ramflux_sdk::serve_local_bus_until(
        ramflux_sdk::LocalBusConfig::new(&bob_socket, temp_root.join("bob/data")),
        bob_shutdown_rx,
    );

    let flow = async {
        let result = async {
            mvp_s4_wait_for_socket(&alice_socket).await?;
            mvp_s4_wait_for_socket(&bob_socket).await?;
            let gateway_addr = gateway_quic_addr.to_string();
            let ca_cert_arg = mvp_s4_path_arg(ca_cert);
            let alice_socket_arg = mvp_s4_path_arg(&alice_socket);
            let bob_socket_arg = mvp_s4_path_arg(&bob_socket);

            let alice_commitment = mvp_s10_create_rf_account(
                &rf_binary,
                &alice_socket_arg,
                "alice_s33_account",
                "principal_s33_alice",
                "alice_device_s33",
                "target_s33_alice",
                &gateway_addr,
                &ca_cert_arg,
                "73",
                "74",
            )
            .await?;
            let bob_commitment = mvp_s10_create_rf_account(
                &rf_binary,
                &bob_socket_arg,
                "bob_s33_account",
                "principal_s33_bob",
                "bob_device_s33",
                "target_s33_bob",
                &gateway_addr,
                &ca_cert_arg,
                "83",
                "84",
            )
            .await?;

            mvp_s33_add_contact(
                &rf_binary,
                &alice_socket_arg,
                "alice_s33_account",
                "friend_link_s33_alice_bob",
                &alice_commitment,
                &bob_commitment,
            )
            .await?;
            mvp_s33_add_contact(
                &rf_binary,
                &bob_socket_arg,
                "bob_s33_account",
                "friend_link_s33_alice_bob",
                &alice_commitment,
                &bob_commitment,
            )
            .await?;

            let alice_safety = mvp_s4_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &alice_socket_arg,
                    "contact",
                    "safety-number",
                    "--account",
                    "alice_s33_account",
                    "--contact",
                    &bob_commitment,
                ],
            )
            .await?;
            let bob_safety = mvp_s4_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &bob_socket_arg,
                    "contact",
                    "safety-number",
                    "--account",
                    "bob_s33_account",
                    "--contact",
                    &alice_commitment,
                ],
            )
            .await?;
            assert_eq!(alice_safety["safety_number"], bob_safety["safety_number"]);
            assert_eq!(alice_safety["fingerprint_hex"], bob_safety["fingerprint_hex"]);
            assert_eq!(alice_safety["verification_state"], "unverified");
            assert_eq!(bob_safety["verification_state"], "unverified");

            let verified = mvp_s4_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &alice_socket_arg,
                    "contact",
                    "verify",
                    "--account",
                    "alice_s33_account",
                    "--contact",
                    &bob_commitment,
                    "--mark-verified",
                ],
            )
            .await?;
            assert_eq!(verified["verification_state"], "verified");
            assert_eq!(verified["fingerprint_hex"], alice_safety["fingerprint_hex"]);

            let status = mvp_s4_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &alice_socket_arg,
                    "contact",
                    "verification",
                    "status",
                    "--account",
                    "alice_s33_account",
                    "--contact",
                    &bob_commitment,
                ],
            )
            .await?;
            assert_eq!(status["verification_state"], "verified");
            assert_eq!(status["fingerprint_hex"], alice_safety["fingerprint_hex"]);

            Ok::<(), Box<dyn std::error::Error>>(())
        }
        .await;
        let _ = alice_shutdown_tx.send(true);
        let _ = bob_shutdown_tx.send(true);
        result
    };
    let (alice_result, bob_result, flow_result) =
        Box::pin(tokio::time::timeout(Duration::from_mins(3), async {
            tokio::join!(alice_server, bob_server, flow)
        }))
        .await
        .map_err(|_elapsed| "S33 client or daemon flow timed out")?;
    alice_result?;
    bob_result?;
    flow_result?;
    std::fs::remove_dir_all(&temp_root)?;
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s33_add_contact(
    rf_binary: &Path,
    socket_arg: &str,
    account: &str,
    link: &str,
    requester: &str,
    target: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let added = mvp_s4_rf_json(
        rf_binary,
        &[
            "--socket",
            socket_arg,
            "contact",
            "add",
            "--account",
            account,
            "--link",
            link,
            "--requester",
            requester,
            "--target",
            target,
        ],
    )
    .await?;
    assert_eq!(added["state"], "accepted");
    Ok(())
}
