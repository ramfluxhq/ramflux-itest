// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use super::*;

#[cfg(feature = "realnet")]
#[test]
fn mvp_s44_realnet_signed_group_role_control() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    let ports = S8ComposePorts {
        gateway_http: 64_221,
        gateway_quic: 64_491,
        router_http: 64_220,
        router_mesh: 64_492,
        notify_http: 64_223,
        federation_http: 64_222,
        federation_mesh: 64_493,
        relay_http: 64_224,
        relay_media_udp: 64_140,
        signaling_turn_udp: 64_518,
        signaling_turn_tcp: 64_519,
        retention_http: 64_227,
    };
    let gateway_capture = "/tmp/ramflux-gateway-itest-capture-s44.jsonl";
    let node = start_s8_realnet_compose_project_with_env(
        "ramflux-s44-group-control",
        ports,
        &[("RAMFLUX_GATEWAY_ITEST_CAPTURE_JSON".to_owned(), gateway_capture.to_owned())],
    )?;
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async {
        wait_for_private_gateway_quic(node.gateway_quic_addr, &node.ca_cert).await?;
        Box::pin(mvp_s44_assert_signed_group_role_control(
            &node,
            gateway_capture,
            "ramflux-s44-group-control",
        ))
        .await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    drop(node);
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
#[allow(clippy::too_many_lines)]
async fn mvp_s44_assert_signed_group_role_control(
    node: &S8RealnetNode,
    gateway_capture: &str,
    compose_project: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let temp_root = temp_root("s44_group_control")?;
    let alice_socket = temp_root.join("alice/rfd.sock");
    let bob_socket = temp_root.join("bob/rfd.sock");
    let carol_socket = temp_root.join("carol/rfd.sock");
    let (alice_shutdown_tx, alice_shutdown_rx) = tokio::sync::watch::channel(false);
    let (bob_shutdown_tx, bob_shutdown_rx) = tokio::sync::watch::channel(false);
    let (carol_shutdown_tx, carol_shutdown_rx) = tokio::sync::watch::channel(false);
    let alice_server = ramflux_sdk::serve_local_bus_until(
        ramflux_sdk::LocalBusConfig::new(&alice_socket, temp_root.join("alice/data")),
        alice_shutdown_rx,
    );
    let bob_server = ramflux_sdk::serve_local_bus_until(
        ramflux_sdk::LocalBusConfig::new(&bob_socket, temp_root.join("bob/data")),
        bob_shutdown_rx,
    );
    let carol_server = ramflux_sdk::serve_local_bus_until(
        ramflux_sdk::LocalBusConfig::new(&carol_socket, temp_root.join("carol/data")),
        carol_shutdown_rx,
    );

    let flow = async {
        let result = async {
            mvp_s4_wait_for_socket(&alice_socket).await?;
            mvp_s4_wait_for_socket(&bob_socket).await?;
            mvp_s4_wait_for_socket(&carol_socket).await?;
            let rf_binary = mvp_s4_build_rf_binary().await?;
            let gateway_addr = node.gateway_quic_addr.to_string();
            let ca_cert_arg = mvp_s4_path_arg(&node.ca_cert);
            let alice_socket_arg = mvp_s4_path_arg(&alice_socket);
            let bob_socket_arg = mvp_s4_path_arg(&bob_socket);
            let carol_socket_arg = mvp_s4_path_arg(&carol_socket);
            let alice_key =
                mvp_s44_device_public_key("principal_s44_alice", "alice_device_s44", 0x42);
            let bob_key = mvp_s44_device_public_key("principal_s44_bob", "bob_device_s44", 0x44);
            let carol_key =
                mvp_s44_device_public_key("principal_s44_carol", "carol_device_s44", 0x46);

            let alice_commitment = mvp_s10_create_rf_account(
                &rf_binary,
                &alice_socket_arg,
                "alice_s44_account",
                "principal_s44_alice",
                "alice_device_s44",
                "target_s44_alice",
                &gateway_addr,
                &ca_cert_arg,
                "41",
                "42",
            )
            .await?;
            let bob_commitment = mvp_s10_create_rf_account(
                &rf_binary,
                &bob_socket_arg,
                "bob_s44_account",
                "principal_s44_bob",
                "bob_device_s44",
                "target_s44_bob",
                &gateway_addr,
                &ca_cert_arg,
                "43",
                "44",
            )
            .await?;
            let carol_commitment = mvp_s10_create_rf_account(
                &rf_binary,
                &carol_socket_arg,
                "carol_s44_account",
                "principal_s44_carol",
                "carol_device_s44",
                "target_s44_carol",
                &gateway_addr,
                &ca_cert_arg,
                "45",
                "46",
            )
            .await?;
            mvp_s44_add_contact_mesh(
                &rf_binary,
                &alice_socket_arg,
                "alice_s44_account",
                "alice",
                &alice_commitment,
                &[("bob", &bob_commitment), ("carol", &carol_commitment)],
            )
            .await?;
            mvp_s44_add_contact_mesh(
                &rf_binary,
                &bob_socket_arg,
                "bob_s44_account",
                "bob",
                &bob_commitment,
                &[("alice", &alice_commitment), ("carol", &carol_commitment)],
            )
            .await?;
            mvp_s44_add_contact_mesh(
                &rf_binary,
                &carol_socket_arg,
                "carol_s44_account",
                "carol",
                &carol_commitment,
                &[("alice", &alice_commitment), ("bob", &bob_commitment)],
            )
            .await?;

            mvp_s44_seed_group(
                &rf_binary,
                &alice_socket_arg,
                "alice_s44_account",
                [
                    ("bob_device_s44", "target_s44_bob", &bob_key),
                    ("carol_device_s44", "target_s44_carol", &carol_key),
                ],
                &alice_key,
            )
            .await?;
            mvp_s44_seed_group(
                &rf_binary,
                &bob_socket_arg,
                "bob_s44_account",
                [
                    ("bob_device_s44", "target_s44_bob", &bob_key),
                    ("carol_device_s44", "target_s44_carol", &carol_key),
                ],
                &alice_key,
            )
            .await?;
            mvp_s44_seed_group(
                &rf_binary,
                &carol_socket_arg,
                "carol_s44_account",
                [
                    ("carol_device_s44", "target_s44_carol", &carol_key),
                    ("bob_device_s44", "target_s44_bob", &bob_key),
                ],
                &alice_key,
            )
            .await?;

            let self_promote = mvp_s4_rf_failure(
                &rf_binary,
                &[
                    "--socket",
                    &bob_socket_arg,
                    "group",
                    "role",
                    "set",
                    "--account",
                    "bob_s44_account",
                    "--group",
                    "group_s44",
                    "--actor",
                    "bob_device_s44",
                    "--member-device",
                    "bob_device_s44",
                    "--role",
                    "admin",
                ],
            )
            .await?;
            assert!(self_promote.contains("group permission denied"));

            let promoted_bob = mvp_s44_role_set(
                &rf_binary,
                &alice_socket_arg,
                "alice_s44_account",
                "alice_device_s44",
                "bob_device_s44",
                "admin",
            )
            .await?;
            assert_eq!(promoted_bob["roles"]["bob_device_s44"], "admin");
            mvp_s44_receive_control(&rf_binary, &bob_socket_arg, "bob_s44_account").await?;
            mvp_s44_receive_control(&rf_binary, &carol_socket_arg, "carol_s44_account").await?;
            mvp_s44_assert_role(
                &rf_binary,
                &bob_socket_arg,
                "bob_s44_account",
                "bob_device_s44",
                "admin",
            )
            .await?;
            mvp_s44_assert_role(
                &rf_binary,
                &carol_socket_arg,
                "carol_s44_account",
                "bob_device_s44",
                "admin",
            )
            .await?;

            mvp_s44_role_set(
                &rf_binary,
                &alice_socket_arg,
                "alice_s44_account",
                "alice_device_s44",
                "carol_device_s44",
                "admin",
            )
            .await?;
            mvp_s44_receive_control(&rf_binary, &bob_socket_arg, "bob_s44_account").await?;
            mvp_s44_receive_control(&rf_binary, &carol_socket_arg, "carol_s44_account").await?;

            let owner_attack = mvp_s4_rf_failure(
                &rf_binary,
                &[
                    "--socket",
                    &bob_socket_arg,
                    "group",
                    "role",
                    "set",
                    "--account",
                    "bob_s44_account",
                    "--group",
                    "group_s44",
                    "--actor",
                    "bob_device_s44",
                    "--member-device",
                    "alice_device_s44",
                    "--role",
                    "member",
                ],
            )
            .await?;
            assert!(owner_attack.contains("group permission denied"));

            let admin_attack = mvp_s4_rf_failure(
                &rf_binary,
                &[
                    "--socket",
                    &bob_socket_arg,
                    "group",
                    "role",
                    "set",
                    "--account",
                    "bob_s44_account",
                    "--group",
                    "group_s44",
                    "--actor",
                    "bob_device_s44",
                    "--member-device",
                    "carol_device_s44",
                    "--role",
                    "member",
                ],
            )
            .await?;
            assert!(admin_attack.contains("group permission denied"));
            mvp_s44_assert_gateway_opaque(compose_project, gateway_capture)?;
            Ok::<(), Box<dyn std::error::Error>>(())
        }
        .await;
        let _ = alice_shutdown_tx.send(true);
        let _ = bob_shutdown_tx.send(true);
        let _ = carol_shutdown_tx.send(true);
        result
    };

    let (alice_result, bob_result, carol_result, flow_result) =
        tokio::time::timeout(std::time::Duration::from_mins(5), async {
            tokio::join!(alice_server, bob_server, carol_server, flow)
        })
        .await
        .map_err(|_elapsed| "S44 group control flow timed out")?;
    alice_result?;
    bob_result?;
    carol_result?;
    flow_result?;
    std::fs::remove_dir_all(&temp_root)?;
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s44_add_contact_mesh(
    rf_binary: &Path,
    socket: &str,
    account: &str,
    local_name: &str,
    requester: &str,
    peers: &[(&str, &str)],
) -> Result<(), Box<dyn std::error::Error>> {
    for (peer_name, target) in peers {
        let added = mvp_s10_rf_json(
            rf_binary,
            &[
                "--socket",
                socket,
                "contact",
                "add",
                "--account",
                account,
                "--link",
                &format!("{local_name}_to_{peer_name}_s44"),
                "--requester",
                requester,
                "--target",
                target,
            ],
            "s44 contact add",
        )
        .await?;
        assert_eq!(added["state"], "accepted");
    }
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
fn mvp_s44_device_public_key(principal: &str, device: &str, seed_byte: u8) -> String {
    let branch = ramflux_crypto::create_device_branch(principal, device, 1, [seed_byte; 32]);
    ramflux_protocol::encode_base64url(branch.signing_key.verifying_key().to_bytes())
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s44_create_group(
    rf_binary: &Path,
    socket: &str,
    account: &str,
    alice_key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let created = mvp_s10_rf_json(
        rf_binary,
        &[
            "--socket",
            socket,
            "group",
            "create",
            "--account",
            account,
            "--group",
            "group_s44",
            "--creator",
            "alice_device_s44",
            "--creator-signing-public-key",
            alice_key,
        ],
        "s44 group create",
    )
    .await?;
    assert_eq!(created["roles"]["alice_device_s44"], "owner");
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s44_seed_group(
    rf_binary: &Path,
    socket: &str,
    account: &str,
    members: [(&str, &str, &str); 2],
    alice_key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    mvp_s44_create_group(rf_binary, socket, account, alice_key).await?;
    for (member, target, public_key) in members {
        mvp_s44_add_member(
            rf_binary,
            S44MemberAdd { socket, account, member, role: "member", target, public_key },
        )
        .await?;
    }
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
struct S44MemberAdd<'a> {
    socket: &'a str,
    account: &'a str,
    member: &'a str,
    role: &'a str,
    target: &'a str,
    public_key: &'a str,
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s44_add_member(
    rf_binary: &Path,
    add: S44MemberAdd<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let added = mvp_s10_rf_json(
        rf_binary,
        &[
            "--socket",
            add.socket,
            "group",
            "member",
            "add",
            "--account",
            add.account,
            "--group",
            "group_s44",
            "--member-device",
            add.member,
            "--role",
            add.role,
            "--target-delivery",
            add.target,
            "--member-signing-public-key",
            add.public_key,
        ],
        "s44 group member add",
    )
    .await?;
    assert_eq!(added["roles"][add.member], add.role);
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s44_role_set(
    rf_binary: &Path,
    socket: &str,
    account: &str,
    actor: &str,
    member: &str,
    role: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    mvp_s10_rf_json(
        rf_binary,
        &[
            "--socket",
            socket,
            "group",
            "role",
            "set",
            "--account",
            account,
            "--group",
            "group_s44",
            "--actor",
            actor,
            "--member-device",
            member,
            "--role",
            role,
        ],
        "s44 group role set",
    )
    .await
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s44_receive_control(
    rf_binary: &Path,
    socket: &str,
    account: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let read = mvp_s10_rf_json(
        rf_binary,
        &[
            "--socket",
            socket,
            "group",
            "read",
            "--account",
            account,
            "--group",
            "group_s44",
            "--conversation",
            "group_s44",
        ],
        "s44 group receive control",
    )
    .await?;
    assert!(read["gateway_entries"].as_array().is_some_and(|items| !items.is_empty()));
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s44_assert_role(
    rf_binary: &Path,
    socket: &str,
    account: &str,
    member: &str,
    role: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let members = mvp_s10_rf_json(
        rf_binary,
        &["--socket", socket, "group", "members", "--account", account, "--group", "group_s44"],
        "s44 group members",
    )
    .await?;
    assert_eq!(members["roles"][member], role);
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
fn mvp_s44_assert_gateway_opaque(
    compose_project: &str,
    gateway_capture: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let capture = mvp_s44_service_file(compose_project, gateway_capture)?;
    let redb = mvp_s44_service_file(compose_project, "/var/lib/ramflux/gateway/gateway.redb")?;
    for haystack in [&capture, &redb] {
        for needle in [
            b"ramflux.sdk.group_control.v1".as_slice(),
            b"group.role_changed".as_slice(),
            b"RoleChanged".as_slice(),
            b"target_identity".as_slice(),
            b"new_role".as_slice(),
        ] {
            assert!(
                !contains_subslice(haystack, needle),
                "gateway leaked group control marker {}",
                String::from_utf8_lossy(needle)
            );
        }
    }
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
fn mvp_s44_service_file(
    compose_project: &str,
    remote_path: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let output = std::process::Command::new("docker")
        .args([
            "compose",
            "-p",
            compose_project,
            "-f",
            "docker-compose.itest.yml",
            "exec",
            "-T",
            "ramflux-gateway",
            "cat",
            remote_path,
        ])
        .current_dir(code_root().join("ramflux-deploy"))
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "failed to read gateway file {remote_path}: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(output.stdout)
}
