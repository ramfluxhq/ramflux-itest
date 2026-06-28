// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use super::*;

#[cfg(all(test, feature = "realnet"))]
const S45_FORWARD_SECRET_SENTINEL: &str = "mvp_s45_forward_secret_after_kick";

#[cfg(feature = "realnet")]
#[test]
fn mvp_s45_realnet_group_control_rekey() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    let ports = S8ComposePorts {
        gateway_http: 64_231,
        gateway_quic: 64_501,
        router_http: 64_230,
        router_mesh: 64_502,
        notify_http: 64_233,
        federation_http: 64_232,
        federation_mesh: 64_503,
        relay_http: 64_234,
        relay_media_udp: 64_141,
        signaling_turn_udp: 64_520,
        signaling_turn_tcp: 64_521,
        retention_http: 64_237,
    };
    let gateway_capture = "/tmp/ramflux-gateway-itest-capture-s45.jsonl";
    let node = start_s8_realnet_compose_project_with_env(
        "ramflux-s45-group-rekey",
        ports,
        &[("RAMFLUX_GATEWAY_ITEST_CAPTURE_JSON".to_owned(), gateway_capture.to_owned())],
    )?;
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async {
        wait_for_private_gateway_quic(node.gateway_quic_addr, &node.ca_cert).await?;
        Box::pin(mvp_s45_assert_group_control_rekey(
            &node,
            gateway_capture,
            "ramflux-s45-group-rekey",
        ))
        .await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    drop(node);
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
#[allow(clippy::too_many_lines)]
async fn mvp_s45_assert_group_control_rekey(
    node: &S8RealnetNode,
    gateway_capture: &str,
    compose_project: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let temp_root = temp_root("s45_group_rekey")?;
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
                mvp_s45_device_public_key("principal_s45_alice", "alice_device_s45", 0x52);
            let bob_key = mvp_s45_device_public_key("principal_s45_bob", "bob_device_s45", 0x54);
            let carol_key =
                mvp_s45_device_public_key("principal_s45_carol", "carol_device_s45", 0x56);

            let alice_commitment = mvp_s45_create_account(
                &rf_binary,
                &alice_socket_arg,
                "alice_s45_account",
                "principal_s45_alice",
                "alice_device_s45",
                "target_s45_alice",
                &gateway_addr,
                &ca_cert_arg,
                "51",
                "52",
            )
            .await?;
            let bob_commitment = mvp_s45_create_account(
                &rf_binary,
                &bob_socket_arg,
                "bob_s45_account",
                "principal_s45_bob",
                "bob_device_s45",
                "target_s45_bob",
                &gateway_addr,
                &ca_cert_arg,
                "53",
                "54",
            )
            .await?;
            let carol_commitment = mvp_s45_create_account(
                &rf_binary,
                &carol_socket_arg,
                "carol_s45_account",
                "principal_s45_carol",
                "carol_device_s45",
                "target_s45_carol",
                &gateway_addr,
                &ca_cert_arg,
                "55",
                "56",
            )
            .await?;
            mvp_s45_add_contact_mesh(
                &rf_binary,
                &alice_socket_arg,
                "alice_s45_account",
                "alice",
                &alice_commitment,
                &[("bob", &bob_commitment), ("carol", &carol_commitment)],
            )
            .await?;
            mvp_s45_add_contact_mesh(
                &rf_binary,
                &bob_socket_arg,
                "bob_s45_account",
                "bob",
                &bob_commitment,
                &[("alice", &alice_commitment), ("carol", &carol_commitment)],
            )
            .await?;
            mvp_s45_add_contact_mesh(
                &rf_binary,
                &carol_socket_arg,
                "carol_s45_account",
                "carol",
                &carol_commitment,
                &[("alice", &alice_commitment), ("bob", &bob_commitment)],
            )
            .await?;

            mvp_s45_seed_group(
                &rf_binary,
                &alice_socket_arg,
                "alice_s45_account",
                [
                    ("bob_device_s45", "target_s45_bob", &bob_key),
                    ("carol_device_s45", "target_s45_carol", &carol_key),
                ],
                &alice_key,
            )
            .await?;
            mvp_s45_seed_group(
                &rf_binary,
                &bob_socket_arg,
                "bob_s45_account",
                [
                    ("bob_device_s45", "target_s45_bob", &bob_key),
                    ("carol_device_s45", "target_s45_carol", &carol_key),
                ],
                &alice_key,
            )
            .await?;
            mvp_s45_seed_group(
                &rf_binary,
                &carol_socket_arg,
                "carol_s45_account",
                [
                    ("carol_device_s45", "target_s45_carol", &carol_key),
                    ("bob_device_s45", "target_s45_bob", &bob_key),
                ],
                &alice_key,
            )
            .await?;

            let member_kick = mvp_s4_rf_failure(
                &rf_binary,
                &[
                    "--socket",
                    &bob_socket_arg,
                    "group",
                    "member",
                    "kick",
                    "--account",
                    "bob_s45_account",
                    "--group",
                    "group_s45",
                    "--actor",
                    "bob_device_s45",
                    "--member-device",
                    "carol_device_s45",
                ],
            )
            .await?;
            assert!(member_kick.contains("group permission denied"));

            let kicked = mvp_s45_member_control(
                &rf_binary,
                &alice_socket_arg,
                "alice_s45_account",
                "kick",
                "alice_device_s45",
                "bob_device_s45",
            )
            .await?;
            assert_eq!(kicked["group_epoch"], 4);
            mvp_s45_receive(&rf_binary, &carol_socket_arg, "carol_s45_account").await?;
            mvp_s45_assert_member_absent(
                &rf_binary,
                &carol_socket_arg,
                "carol_s45_account",
                "bob_device_s45",
            )
            .await?;

            mvp_s45_send_group(
                &rf_binary,
                &carol_socket_arg,
                "carol_s45_account",
                "carol_device_s45",
                "carol_after_kick_s45",
                S45_FORWARD_SECRET_SENTINEL,
            )
            .await?;
            let alice_read =
                mvp_s45_receive(&rf_binary, &alice_socket_arg, "alice_s45_account").await?;
            assert!(mvp_s45_decrypted_contains(&alice_read, S45_FORWARD_SECRET_SENTINEL));
            let alice_message_id =
                mvp_s45_decrypted_message_id(&alice_read, S45_FORWARD_SECRET_SENTINEL)?;
            let bob_read = mvp_s45_receive(&rf_binary, &bob_socket_arg, "bob_s45_account").await?;
            assert!(!mvp_s45_decrypted_contains(&bob_read, S45_FORWARD_SECRET_SENTINEL));

            let before_delete =
                mvp_s45_members(&rf_binary, &alice_socket_arg, "alice_s45_account").await?;
            let delete = mvp_s45_delete_message(
                &rf_binary,
                &alice_socket_arg,
                "alice_s45_account",
                "alice_device_s45",
                &alice_message_id,
            )
            .await?;
            assert_eq!(delete["group_epoch"], before_delete["group_epoch"]);

            let banned = mvp_s45_member_control(
                &rf_binary,
                &alice_socket_arg,
                "alice_s45_account",
                "ban",
                "alice_device_s45",
                "carol_device_s45",
            )
            .await?;
            assert_eq!(banned["group_epoch"], 5);
            let readd = mvp_s4_rf_failure(
                &rf_binary,
                &[
                    "--socket",
                    &alice_socket_arg,
                    "group",
                    "member",
                    "add",
                    "--account",
                    "alice_s45_account",
                    "--group",
                    "group_s45",
                    "--member-device",
                    "carol_device_s45",
                    "--role",
                    "member",
                    "--target-delivery",
                    "target_s45_carol",
                    "--member-signing-public-key",
                    &carol_key,
                ],
            )
            .await?;
            assert!(readd.contains("group permission denied"));

            mvp_s45_assert_gateway_opaque(compose_project, gateway_capture)?;
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
        .map_err(|_elapsed| "S45 group control rekey flow timed out")?;
    alice_result?;
    bob_result?;
    carol_result?;
    flow_result?;
    std::fs::remove_dir_all(&temp_root)?;
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s45_add_contact_mesh(
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
                &format!("{local_name}_to_{peer_name}_s45"),
                "--requester",
                requester,
                "--target",
                target,
            ],
            "s45 contact add",
        )
        .await?;
        assert_eq!(added["state"], "accepted");
    }
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
fn mvp_s45_device_public_key(principal: &str, device: &str, seed_byte: u8) -> String {
    let branch = ramflux_crypto::create_device_branch(principal, device, 1, [seed_byte; 32]);
    ramflux_protocol::encode_base64url(branch.signing_key.verifying_key().to_bytes())
}

#[cfg(all(test, feature = "realnet"))]
#[allow(clippy::too_many_arguments)]
async fn mvp_s45_create_account(
    rf_binary: &Path,
    socket: &str,
    account: &str,
    principal: &str,
    device: &str,
    target: &str,
    gateway_addr: &str,
    ca_cert_arg: &str,
    root_seed: &str,
    device_seed: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    mvp_s10_create_rf_account(
        rf_binary,
        socket,
        account,
        principal,
        device,
        target,
        gateway_addr,
        ca_cert_arg,
        root_seed,
        device_seed,
    )
    .await
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s45_seed_group(
    rf_binary: &Path,
    socket: &str,
    account: &str,
    members: [(&str, &str, &str); 2],
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
            "group_s45",
            "--creator",
            "alice_device_s45",
            "--creator-signing-public-key",
            alice_key,
            "--creator-target-delivery",
            "target_s45_alice",
        ],
        "s45 group create",
    )
    .await?;
    assert_eq!(created["roles"]["alice_device_s45"], "owner");
    for (member, target, public_key) in members {
        let added = mvp_s10_rf_json(
            rf_binary,
            &[
                "--socket",
                socket,
                "group",
                "member",
                "add",
                "--account",
                account,
                "--group",
                "group_s45",
                "--member-device",
                member,
                "--role",
                "member",
                "--target-delivery",
                target,
                "--member-signing-public-key",
                public_key,
            ],
            "s45 group member add",
        )
        .await?;
        assert_eq!(added["roles"][member], "member");
    }
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s45_member_control(
    rf_binary: &Path,
    socket: &str,
    account: &str,
    action: &str,
    actor: &str,
    member: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    mvp_s10_rf_json(
        rf_binary,
        &[
            "--socket",
            socket,
            "group",
            "member",
            action,
            "--account",
            account,
            "--group",
            "group_s45",
            "--actor",
            actor,
            "--member-device",
            member,
            "--reason",
            "mvp_s45_test",
        ],
        "s45 group member control",
    )
    .await
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s45_send_group(
    rf_binary: &Path,
    socket: &str,
    account: &str,
    sender: &str,
    message_id: &str,
    body: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let sent = mvp_s10_rf_json(
        rf_binary,
        &[
            "--socket",
            socket,
            "group",
            "send",
            "--account",
            account,
            "--group",
            "group_s45",
            "--conversation",
            "group_s45",
            "--message",
            message_id,
            "--sender",
            sender,
            "--body",
            body,
        ],
        "s45 group send",
    )
    .await?;
    assert_eq!(sent["message_id"], message_id);
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s45_receive(
    rf_binary: &Path,
    socket: &str,
    account: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    mvp_s10_rf_json(
        rf_binary,
        &[
            "--socket",
            socket,
            "group",
            "read",
            "--account",
            account,
            "--group",
            "group_s45",
            "--conversation",
            "group_s45",
        ],
        "s45 group read",
    )
    .await
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s45_members(
    rf_binary: &Path,
    socket: &str,
    account: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    mvp_s10_rf_json(
        rf_binary,
        &["--socket", socket, "group", "members", "--account", account, "--group", "group_s45"],
        "s45 group members",
    )
    .await
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s45_assert_member_absent(
    rf_binary: &Path,
    socket: &str,
    account: &str,
    member: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let members = mvp_s45_members(rf_binary, socket, account).await?;
    assert!(members["roles"].get(member).is_none());
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s45_delete_message(
    rf_binary: &Path,
    socket: &str,
    account: &str,
    actor: &str,
    message: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    mvp_s10_rf_json(
        rf_binary,
        &[
            "--socket",
            socket,
            "group",
            "message",
            "delete",
            "--account",
            account,
            "--group",
            "group_s45",
            "--actor",
            actor,
            "--message",
            message,
            "--reason",
            "mvp_s45_delete",
        ],
        "s45 group message delete",
    )
    .await
}

#[cfg(all(test, feature = "realnet"))]
fn mvp_s45_decrypted_contains(read: &serde_json::Value, needle: &str) -> bool {
    read["decrypted_messages"].as_array().is_some_and(|messages| {
        messages
            .iter()
            .any(|message| message["body_utf8"].as_str().is_some_and(|body| body.contains(needle)))
    })
}

#[cfg(all(test, feature = "realnet"))]
fn mvp_s45_decrypted_message_id(
    read: &serde_json::Value,
    needle: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    read["decrypted_messages"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|message| message["body_utf8"].as_str().is_some_and(|body| body.contains(needle)))
        .and_then(|message| message["message_id"].as_str())
        .map(str::to_owned)
        .ok_or_else(|| format!("missing decrypted message containing {needle}").into())
}

#[cfg(all(test, feature = "realnet"))]
fn mvp_s45_assert_gateway_opaque(
    compose_project: &str,
    gateway_capture: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let capture = mvp_s45_service_file(compose_project, gateway_capture)?;
    let redb = mvp_s45_service_file(compose_project, "/var/lib/ramflux/gateway/gateway.redb")?;
    for haystack in [&capture, &redb] {
        for needle in [
            b"ramflux.sdk.group_control.v1".as_slice(),
            b"group.member_kicked".as_slice(),
            b"group.member_banned".as_slice(),
            b"group.message_deleted".as_slice(),
            b"MemberBanned".as_slice(),
            b"MessageDeleted".as_slice(),
            b"target_identity".as_slice(),
            b"banned_identity".as_slice(),
            b"removed_identity".as_slice(),
            b"group_key".as_slice(),
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
fn mvp_s45_service_file(
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
