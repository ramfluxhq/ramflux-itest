// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use super::*;

#[cfg(feature = "realnet")]
#[test]
fn mvp_s39_realnet_device_aware_safety_number_fail_closed() -> Result<(), Box<dyn std::error::Error>>
{
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    let node = start_s8_realnet_compose_project(
        "ramflux-s39-device-aware-safety",
        S8ComposePorts {
            gateway_http: 65_181,
            gateway_quic: 65_451,
            router_http: 65_180,
            router_mesh: 65_452,
            notify_http: 65_183,
            federation_http: 65_182,
            federation_mesh: 65_453,
            relay_http: 65_184,
            relay_media_udp: 65_100,
            signaling_turn_udp: 65_478,
            signaling_turn_tcp: 65_479,
            retention_http: 65_187,
        },
    )?;
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async {
        wait_for_private_gateway_quic(node.gateway_quic_addr, &node.ca_cert).await?;
        Box::pin(mvp_s39_assert_device_aware_safety_number(&node)).await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    drop(node);
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
#[allow(clippy::too_many_lines)]
async fn mvp_s39_assert_device_aware_safety_number(
    node: &S8RealnetNode,
) -> Result<(), Box<dyn std::error::Error>> {
    let temp_root = temp_root("s39_device_aware_safety_number")?;
    let alice_socket = temp_root.join("alice/rfd.sock");
    let bob_socket = temp_root.join("bob/rfd.sock");
    let (alice_tx, alice_rx) = tokio::sync::watch::channel(false);
    let (bob_tx, bob_rx) = tokio::sync::watch::channel(false);
    let alice_server = ramflux_sdk::serve_local_bus_until(
        ramflux_sdk::LocalBusConfig::new(&alice_socket, temp_root.join("alice/data")),
        alice_rx,
    );
    let bob_server = ramflux_sdk::serve_local_bus_until(
        ramflux_sdk::LocalBusConfig::new(&bob_socket, temp_root.join("bob/data")),
        bob_rx,
    );

    let flow = async {
        let result = async {
            mvp_s4_wait_for_socket(&alice_socket).await?;
            mvp_s4_wait_for_socket(&bob_socket).await?;
            let mut alice = ramflux_sdk::LocalBusClient::connect(&alice_socket).await?;
            let mut bob = ramflux_sdk::LocalBusClient::connect(&bob_socket).await?;

            let alice_commitment = mvp_s39_create_account(
                &mut alice,
                node,
                MvpS39AccountSpec {
                    local_account_id: "alice_s39_account",
                    principal_id: "principal_s39_alice",
                    device_id: "alice_device_s39_a",
                    target_delivery_id: "target_s39_alice_a",
                    root_seed: [0x39; 32],
                    device_seed: [0x3a; 32],
                },
            )
            .await?;
            let bob_commitment = mvp_s39_create_account(
                &mut bob,
                node,
                MvpS39AccountSpec {
                    local_account_id: "bob_s39_account",
                    principal_id: "principal_s39_bob",
                    device_id: "bob_device_s39",
                    target_delivery_id: "target_s39_bob",
                    root_seed: [0x49; 32],
                    device_seed: [0x4a; 32],
                },
            )
            .await?;

            mvp_s39_add_contact(
                &mut alice,
                "alice_s39_account",
                &alice_commitment,
                &bob_commitment,
            )
            .await?;
            mvp_s39_add_contact(&mut bob, "bob_s39_account", &alice_commitment, &bob_commitment)
                .await?;

            let alice_initial =
                mvp_s39_safety(&mut alice, "alice_s39_account", &bob_commitment).await?;
            let bob_initial =
                mvp_s39_safety(&mut bob, "bob_s39_account", &alice_commitment).await?;
            assert_eq!(alice_initial["safety_number"], bob_initial["safety_number"]);
            assert_eq!(alice_initial["fingerprint_hex"], bob_initial["fingerprint_hex"]);
            assert_eq!(alice_initial["self_device_count"], 1);
            assert_eq!(bob_initial["contact_device_count"], 1);

            let verified = bob
                .request(
                    Some("bob_s39_account".to_owned()),
                    "contact",
                    "contact.verify",
                    &serde_json::json!({ "contact_identity_commitment": alice_commitment.clone() }),
                )
                .await?;
            assert_eq!(verified["verification_state"], "verified");

            let activated: ramflux_sdk::LocalBusDeviceActivateResponse = serde_json::from_value(
                alice
                    .request(
                        Some("alice_s39_account".to_owned()),
                        "device",
                        "device.activate",
                        &ramflux_sdk::LocalBusDeviceActivateRequest {
                            device_id: "alice_device_s39_b".to_owned(),
                            target_delivery_id: "target_s39_alice_b".to_owned(),
                            device_seed: [0x3b; 32],
                            device_epoch: Some(2),
                        },
                    )
                    .await?,
            )?;
            assert_eq!(activated.device_id, "alice_device_s39_b");
            assert_eq!(activated.devices.len(), 2);

            let alice_after =
                mvp_s39_safety(&mut alice, "alice_s39_account", &bob_commitment).await?;
            let bob_after = mvp_s39_safety(&mut bob, "bob_s39_account", &alice_commitment).await?;
            assert_eq!(alice_after["safety_number"], bob_after["safety_number"]);
            assert_eq!(alice_after["fingerprint_hex"], bob_after["fingerprint_hex"]);
            assert_ne!(alice_after["fingerprint_hex"], alice_initial["fingerprint_hex"]);
            assert_eq!(alice_after["self_device_count"], 2);
            assert_eq!(bob_after["contact_device_count"], 2);

            let bob_status = bob
                .request(
                    Some("bob_s39_account".to_owned()),
                    "contact",
                    "contact.verification.status",
                    &ramflux_sdk::LocalBusContactSafetyRequest {
                        contact_identity_commitment: alice_commitment.clone(),
                    },
                )
                .await?;
            assert_eq!(bob_status["stored_verification_state"], "verified");
            assert_eq!(bob_status["verification_state"], "verification_stale");

            let manifest = mvp_s39_fetch_manifest(&node.gateway_url, &alice_commitment)?;
            ramflux_sdk::RamfluxClient::verify_device_manifest_json(
                manifest.clone(),
                &alice_commitment,
            )?;
            mvp_s39_assert_manifest_tamper_error(
                manifest.clone(),
                &alice_commitment,
                MvpS39Tamper::RootPublicKey,
                "root commitment mismatch",
            )?;
            mvp_s39_assert_manifest_tamper_error(
                manifest.clone(),
                &alice_commitment,
                MvpS39Tamper::BranchProof,
                "branch proof invalid",
            )?;
            mvp_s39_assert_manifest_tamper_error(
                manifest,
                &alice_commitment,
                MvpS39Tamper::PrekeyBundle,
                "prekey invalid",
            )?;

            drop(alice);
            drop(bob);
            Ok::<(), Box<dyn std::error::Error>>(())
        }
        .await;
        let _ = alice_tx.send(true);
        let _ = bob_tx.send(true);
        result
    };
    let (alice_result, bob_result, flow_result) =
        Box::pin(tokio::time::timeout(Duration::from_mins(4), async {
            tokio::join!(alice_server, bob_server, flow)
        }))
        .await
        .map_err(|_elapsed| "S39 device-aware safety number flow timed out")?;
    alice_result?;
    bob_result?;
    flow_result?;
    std::fs::remove_dir_all(&temp_root)?;
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
struct MvpS39AccountSpec<'a> {
    local_account_id: &'a str,
    principal_id: &'a str,
    device_id: &'a str,
    target_delivery_id: &'a str,
    root_seed: [u8; 32],
    device_seed: [u8; 32],
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s39_create_account(
    bus: &mut ramflux_sdk::LocalBusClient,
    node: &S8RealnetNode,
    spec: MvpS39AccountSpec<'_>,
) -> Result<String, Box<dyn std::error::Error>> {
    let request = ramflux_sdk::LocalBusAccountCreateRequest {
        local_account_id: spec.local_account_id.to_owned(),
        principal_id: spec.principal_id.to_owned(),
        principal_commitment: String::new(),
        device_id: spec.device_id.to_owned(),
        target_delivery_id: spec.target_delivery_id.to_owned(),
        account_secret: "s39-bus-secret".to_owned(),
        root_seed: spec.root_seed,
        device_seed: spec.device_seed,
        client_mode: ramflux_sdk::LocalBusClientMode::AttendedCli,
        gateway: ramflux_sdk::GatewayQuicEndpointConfig {
            bind_addr: std::net::SocketAddr::from(([0, 0, 0, 0], 0)),
            gateway_addr: node.gateway_quic_addr,
            server_name: "localhost".to_owned(),
            ca_cert: node.ca_cert.clone(),
            principal_id: spec.principal_id.to_owned(),
            device_id: spec.device_id.to_owned(),
            target_delivery_id: spec.target_delivery_id.to_owned(),
            prekey_http_url: None,
        },
    };
    let response: ramflux_sdk::LocalBusAccountCreateResponse =
        serde_json::from_value(bus.request(None, "account", "account.create", &request).await?)?;
    let derived = ramflux_sdk::identity_root_public_key_commitment_for_seed(
        spec.principal_id,
        spec.root_seed,
    );
    assert_eq!(response.principal_commitment, derived);
    let manifest = mvp_s39_fetch_manifest(&node.gateway_url, &response.principal_commitment)?;
    ramflux_sdk::RamfluxClient::verify_device_manifest_json(
        manifest,
        &response.principal_commitment,
    )?;
    Ok(response.principal_commitment)
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s39_add_contact(
    bus: &mut ramflux_sdk::LocalBusClient,
    account: &str,
    requester: &str,
    target: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let added = bus
        .request(
            Some(account.to_owned()),
            "contact",
            "contact.add",
            &ramflux_sdk::LocalBusContactAddRequest {
                link_id: format!("friend_link_s39_{requester}_{target}"),
                requester_id: requester.to_owned(),
                target_id: target.to_owned(),
            },
        )
        .await?;
    assert_eq!(added["state"], "accepted");
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s39_safety(
    bus: &mut ramflux_sdk::LocalBusClient,
    account: &str,
    contact_identity_commitment: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    Ok(bus
        .request(
            Some(account.to_owned()),
            "contact",
            "contact.safety_number",
            &ramflux_sdk::LocalBusContactSafetyRequest {
                contact_identity_commitment: contact_identity_commitment.to_owned(),
            },
        )
        .await?)
}

#[cfg(all(test, feature = "realnet"))]
fn mvp_s39_fetch_manifest(
    gateway_url: &str,
    identity_commitment: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    Ok(ramflux_node_core::itest_http_get_json(&format!(
        "{gateway_url}/mvp1/device-manifest/{identity_commitment}"
    ))?)
}

#[cfg(all(test, feature = "realnet"))]
#[derive(Clone, Copy)]
enum MvpS39Tamper {
    RootPublicKey,
    BranchProof,
    PrekeyBundle,
}

#[cfg(all(test, feature = "realnet"))]
fn mvp_s39_assert_manifest_tamper_error(
    mut manifest: serde_json::Value,
    identity_commitment: &str,
    tamper: MvpS39Tamper,
    expected_error: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    match tamper {
        MvpS39Tamper::RootPublicKey => {
            manifest["root_public_key"] =
                serde_json::json!(ramflux_crypto::public_key_base64url_from_seed([0x5a; 32]));
        }
        MvpS39Tamper::BranchProof => {
            let first_device = mvp_s39_first_manifest_device_mut(&mut manifest)?;
            mvp_s39_tamper_string_field(&mut first_device["branch_proof"], "signature")?;
        }
        MvpS39Tamper::PrekeyBundle => {
            let first_device = mvp_s39_first_manifest_device_mut(&mut manifest)?;
            mvp_s39_tamper_string_field(
                &mut first_device["prekey_bundle"],
                "signature_by_device_identity",
            )?;
        }
    }
    let error = match ramflux_sdk::RamfluxClient::verify_device_manifest_json(
        manifest,
        identity_commitment,
    ) {
        Ok(()) => return Err("tampered device manifest must fail closed".into()),
        Err(error) => error,
    };
    let error = error.to_string();
    assert!(
        error.contains(expected_error),
        "expected manifest tamper error to contain {expected_error:?}, got {error:?}",
    );
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
fn mvp_s39_first_manifest_device_mut(
    manifest: &mut serde_json::Value,
) -> Result<&mut serde_json::Value, Box<dyn std::error::Error>> {
    let devices = manifest
        .get_mut("devices")
        .and_then(serde_json::Value::as_array_mut)
        .ok_or("device manifest response missing devices array")?;
    devices.first_mut().ok_or_else(|| "device manifest response has no devices".into())
}

#[cfg(all(test, feature = "realnet"))]
fn mvp_s39_tamper_string_field(
    value: &mut serde_json::Value,
    field: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let target = value
        .get_mut(field)
        .filter(|field| field.is_string())
        .ok_or_else(|| format!("device manifest tamper target missing string field: {field}"))?;
    *target = serde_json::json!("tampered");
    Ok(())
}
