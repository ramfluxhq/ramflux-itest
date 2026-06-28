// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use super::*;

#[cfg(all(test, feature = "realnet"))]
const S46_PRE_ACCEPT_SENTINEL: &str = "mvp_s46_pre_accept_history_sentinel";
#[cfg(all(test, feature = "realnet"))]
const S46_POST_ACCEPT_SENTINEL: &str = "mvp_s46_post_accept_message";

#[cfg(feature = "realnet")]
#[test]
fn mvp_s46_realnet_group_invite_accept() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    let ports = S8ComposePorts {
        gateway_http: 64_251,
        gateway_quic: 64_521,
        router_http: 64_250,
        router_mesh: 64_522,
        notify_http: 64_253,
        federation_http: 64_252,
        federation_mesh: 64_523,
        relay_http: 64_254,
        relay_media_udp: 64_161,
        signaling_turn_udp: 64_540,
        signaling_turn_tcp: 64_541,
        retention_http: 64_257,
    };
    let gateway_capture = "/tmp/ramflux-gateway-itest-capture-s46.jsonl";
    let node = start_s8_realnet_compose_project_with_env(
        "ramflux-s46-group-invite",
        ports,
        &[("RAMFLUX_GATEWAY_ITEST_CAPTURE_JSON".to_owned(), gateway_capture.to_owned())],
    )?;
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async {
        wait_for_private_gateway_quic(node.gateway_quic_addr, &node.ca_cert).await?;
        Box::pin(mvp_s46_assert_group_invite_accept(
            &node,
            gateway_capture,
            "ramflux-s46-group-invite",
        ))
        .await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    drop(node);
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
#[allow(clippy::too_many_lines)]
async fn mvp_s46_assert_group_invite_accept(
    node: &S8RealnetNode,
    gateway_capture: &str,
    compose_project: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let temp_root = temp_root("s46_group_invite_accept")?;
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
                mvp_s46_device_public_key("principal_s46_alice", "alice_device_s46", 0x62);
            let bob_key = mvp_s46_device_public_key("principal_s46_bob", "bob_device_s46", 0x64);
            let carol_key =
                mvp_s46_device_public_key("principal_s46_carol", "carol_device_s46", 0x66);
            let dave_key = mvp_s46_device_public_key("principal_s46_dave", "dave_device_s46", 0x68);
            let unique =
                std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos();
            let pre_message_id = format!("alice_pre_accept_s46_{unique}");
            let post_message_id = format!("alice_post_accept_s46_{unique}");

            let alice_commitment = mvp_s46_create_account(
                &rf_binary,
                &alice_socket_arg,
                "alice_s46_account",
                "principal_s46_alice",
                "alice_device_s46",
                "target_s46_alice",
                &gateway_addr,
                &ca_cert_arg,
                "61",
                "62",
            )
            .await?;
            let bob_commitment = mvp_s46_create_account(
                &rf_binary,
                &bob_socket_arg,
                "bob_s46_account",
                "principal_s46_bob",
                "bob_device_s46",
                "target_s46_bob",
                &gateway_addr,
                &ca_cert_arg,
                "63",
                "64",
            )
            .await?;
            let carol_commitment = mvp_s46_create_account(
                &rf_binary,
                &carol_socket_arg,
                "carol_s46_account",
                "principal_s46_carol",
                "carol_device_s46",
                "target_s46_carol",
                &gateway_addr,
                &ca_cert_arg,
                "65",
                "66",
            )
            .await?;
            mvp_s46_add_contact_mesh(
                &rf_binary,
                &alice_socket_arg,
                "alice_s46_account",
                "alice",
                &alice_commitment,
                &[("bob", &bob_commitment), ("carol", &carol_commitment)],
            )
            .await?;
            mvp_s46_add_contact_mesh(
                &rf_binary,
                &bob_socket_arg,
                "bob_s46_account",
                "bob",
                &bob_commitment,
                &[("alice", &alice_commitment), ("carol", &carol_commitment)],
            )
            .await?;
            mvp_s46_add_contact_mesh(
                &rf_binary,
                &carol_socket_arg,
                "carol_s46_account",
                "carol",
                &carol_commitment,
                &[("alice", &alice_commitment), ("bob", &bob_commitment)],
            )
            .await?;

            mvp_s46_seed_group(
                &rf_binary,
                &alice_socket_arg,
                "alice_s46_account",
                "group_s46",
                &[("bob_device_s46", "target_s46_bob", &bob_key)],
                &alice_key,
            )
            .await?;
            mvp_s46_seed_group(
                &rf_binary,
                &bob_socket_arg,
                "bob_s46_account",
                "group_s46",
                &[("bob_device_s46", "target_s46_bob", &bob_key)],
                &alice_key,
            )
            .await?;
            mvp_s46_seed_group(
                &rf_binary,
                &carol_socket_arg,
                "carol_s46_account",
                "group_s46",
                &[],
                &alice_key,
            )
            .await?;

            mvp_s46_send_group(
                &rf_binary,
                &alice_socket_arg,
                "alice_s46_account",
                "group_s46",
                "alice_device_s46",
                &pre_message_id,
                S46_PRE_ACCEPT_SENTINEL,
            )
            .await?;
            let bob_pre =
                mvp_s46_receive(&rf_binary, &bob_socket_arg, "bob_s46_account", "group_s46")
                    .await?;
            assert!(mvp_s46_decrypted_contains(&bob_pre, S46_PRE_ACCEPT_SENTINEL));

            let member_invite = mvp_s4_rf_failure(
                &rf_binary,
                &[
                    "--socket",
                    &bob_socket_arg,
                    "group",
                    "invite",
                    "create",
                    "--account",
                    "bob_s46_account",
                    "--group",
                    "group_s46",
                    "--actor",
                    "bob_device_s46",
                    "--invitee-device",
                    "carol_device_s46",
                    "--invitee-signing-public-key",
                    &carol_key,
                    "--target-delivery",
                    "target_s46_carol",
                    "--expires-at",
                    "4000000000",
                ],
            )
            .await?;
            assert!(member_invite.contains("group permission denied"));

            let invite = mvp_s46_invite_create(
                &rf_binary,
                &alice_socket_arg,
                "alice_s46_account",
                "group_s46",
                "alice_device_s46",
                "carol_device_s46",
                &carol_key,
                "target_s46_carol",
            )
            .await?;
            let invite_id = invite["control_event"]["body"]["invite_id"]
                .as_str()
                .ok_or("missing invite_id")?
                .to_owned();
            mvp_s46_receive(&rf_binary, &bob_socket_arg, "bob_s46_account", "group_s46").await?;
            mvp_s46_receive(&rf_binary, &carol_socket_arg, "carol_s46_account", "group_s46")
                .await?;

            let wrong_accept = mvp_s4_rf_failure(
                &rf_binary,
                &[
                    "--socket",
                    &bob_socket_arg,
                    "group",
                    "invite",
                    "accept",
                    "--account",
                    "bob_s46_account",
                    "--group",
                    "group_s46",
                    "--actor",
                    "bob_device_s46",
                    "--invite-id",
                    &invite_id,
                    "--target-delivery",
                    "target_s46_bob",
                ],
            )
            .await?;
            assert!(
                wrong_accept.contains("signature")
                    || wrong_accept.contains("acceptor")
                    || wrong_accept.contains("verification")
            );

            let accepted = mvp_s46_invite_accept(
                &rf_binary,
                &carol_socket_arg,
                "carol_s46_account",
                "group_s46",
                "carol_device_s46",
                &invite_id,
                "target_s46_carol",
            )
            .await?;
            assert_eq!(accepted["group_epoch"], 3);
            assert_eq!(accepted["roles"]["carol_device_s46"], "member");
            mvp_s46_receive(&rf_binary, &alice_socket_arg, "alice_s46_account", "group_s46")
                .await?;
            mvp_s46_receive(&rf_binary, &bob_socket_arg, "bob_s46_account", "group_s46").await?;

            let replay_accept = mvp_s4_rf_failure(
                &rf_binary,
                &[
                    "--socket",
                    &carol_socket_arg,
                    "group",
                    "invite",
                    "accept",
                    "--account",
                    "carol_s46_account",
                    "--group",
                    "group_s46",
                    "--actor",
                    "carol_device_s46",
                    "--invite-id",
                    &invite_id,
                    "--target-delivery",
                    "target_s46_carol",
                ],
            )
            .await?;
            assert!(replay_accept.contains("invite") && replay_accept.contains("state"));

            mvp_s46_send_group(
                &rf_binary,
                &alice_socket_arg,
                "alice_s46_account",
                "group_s46",
                "alice_device_s46",
                &post_message_id,
                S46_POST_ACCEPT_SENTINEL,
            )
            .await?;
            let carol_post =
                mvp_s46_receive(&rf_binary, &carol_socket_arg, "carol_s46_account", "group_s46")
                    .await?;
            assert!(!mvp_s46_decrypted_contains(&carol_post, S46_PRE_ACCEPT_SENTINEL));
            assert!(mvp_s46_decrypted_contains(&carol_post, S46_POST_ACCEPT_SENTINEL));

            mvp_s46_seed_group(
                &rf_binary,
                &alice_socket_arg,
                "alice_s46_account",
                "group_s46_ban",
                &[],
                &alice_key,
            )
            .await?;
            let dave_added = mvp_s10_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &alice_socket_arg,
                    "group",
                    "member",
                    "add",
                    "--account",
                    "alice_s46_account",
                    "--group",
                    "group_s46_ban",
                    "--member-device",
                    "dave_device_s46",
                    "--role",
                    "member",
                    "--member-signing-public-key",
                    &dave_key,
                ],
                "s46 group ban fixture member add",
            )
            .await?;
            assert_eq!(dave_added["roles"]["dave_device_s46"], "member");
            mvp_s46_member_control(
                &rf_binary,
                &alice_socket_arg,
                "alice_s46_account",
                "group_s46_ban",
                "ban",
                "alice_device_s46",
                "dave_device_s46",
            )
            .await?;
            let banned_invite = mvp_s4_rf_failure(
                &rf_binary,
                &[
                    "--socket",
                    &alice_socket_arg,
                    "group",
                    "invite",
                    "create",
                    "--account",
                    "alice_s46_account",
                    "--group",
                    "group_s46_ban",
                    "--actor",
                    "alice_device_s46",
                    "--invitee-device",
                    "dave_device_s46",
                    "--invitee-signing-public-key",
                    &dave_key,
                    "--target-delivery",
                    "target_s46_dave",
                    "--expires-at",
                    "4000000000",
                ],
            )
            .await?;
            assert!(banned_invite.contains("group permission denied"));

            mvp_s46_assert_gateway_opaque(compose_project, gateway_capture)?;
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
        .map_err(|_elapsed| "S46 group invite accept flow timed out")?;
    alice_result?;
    bob_result?;
    carol_result?;
    flow_result?;
    std::fs::remove_dir_all(&temp_root)?;
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s46_add_contact_mesh(
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
                &format!("{local_name}_to_{peer_name}_s46"),
                "--requester",
                requester,
                "--target",
                target,
            ],
            "s46 contact add",
        )
        .await?;
        assert_eq!(added["state"], "accepted");
    }
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
fn mvp_s46_device_public_key(principal: &str, device: &str, seed_byte: u8) -> String {
    let branch = ramflux_crypto::create_device_branch(principal, device, 1, [seed_byte; 32]);
    ramflux_protocol::encode_base64url(branch.signing_key.verifying_key().to_bytes())
}

#[cfg(all(test, feature = "realnet"))]
#[allow(clippy::too_many_arguments)]
async fn mvp_s46_create_account(
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
async fn mvp_s46_seed_group(
    rf_binary: &Path,
    socket: &str,
    account: &str,
    group: &str,
    members: &[(&str, &str, &str)],
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
            group,
            "--creator",
            "alice_device_s46",
            "--creator-signing-public-key",
            alice_key,
            "--creator-target-delivery",
            "target_s46_alice",
        ],
        "s46 group create",
    )
    .await?;
    assert_eq!(created["roles"]["alice_device_s46"], "owner");
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
                group,
                "--member-device",
                member,
                "--role",
                "member",
                "--target-delivery",
                target,
                "--member-signing-public-key",
                public_key,
            ],
            &format!("s46 group member add account={account} group={group} member={member}"),
        )
        .await?;
        assert_eq!(added["roles"][*member], "member");
    }
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
#[allow(clippy::too_many_arguments)]
async fn mvp_s46_invite_create(
    rf_binary: &Path,
    socket: &str,
    account: &str,
    group: &str,
    actor: &str,
    invitee: &str,
    invitee_key: &str,
    target: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    mvp_s10_rf_json(
        rf_binary,
        &[
            "--socket",
            socket,
            "group",
            "invite",
            "create",
            "--account",
            account,
            "--group",
            group,
            "--actor",
            actor,
            "--invitee-device",
            invitee,
            "--invitee-signing-public-key",
            invitee_key,
            "--target-delivery",
            target,
            "--expires-at",
            "4000000000",
        ],
        "s46 group invite create",
    )
    .await
}

#[cfg(all(test, feature = "realnet"))]
#[allow(clippy::too_many_arguments)]
async fn mvp_s46_invite_accept(
    rf_binary: &Path,
    socket: &str,
    account: &str,
    group: &str,
    actor: &str,
    invite_id: &str,
    target: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    mvp_s10_rf_json(
        rf_binary,
        &[
            "--socket",
            socket,
            "group",
            "invite",
            "accept",
            "--account",
            account,
            "--group",
            group,
            "--actor",
            actor,
            "--invite-id",
            invite_id,
            "--target-delivery",
            target,
        ],
        "s46 group invite accept",
    )
    .await
}

#[cfg(all(test, feature = "realnet"))]
#[allow(clippy::too_many_arguments)]
async fn mvp_s46_member_control(
    rf_binary: &Path,
    socket: &str,
    account: &str,
    group: &str,
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
            group,
            "--actor",
            actor,
            "--member-device",
            member,
            "--reason",
            "mvp_s46_test",
        ],
        "s46 group member control",
    )
    .await
}

#[cfg(all(test, feature = "realnet"))]
#[allow(clippy::too_many_arguments)]
async fn mvp_s46_send_group(
    rf_binary: &Path,
    socket: &str,
    account: &str,
    group: &str,
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
            group,
            "--conversation",
            group,
            "--message",
            message_id,
            "--sender",
            sender,
            "--body",
            body,
        ],
        &format!("s46 group send message_id={message_id}"),
    )
    .await?;
    assert_eq!(sent["message_id"], message_id);
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s46_receive(
    rf_binary: &Path,
    socket: &str,
    account: &str,
    group: &str,
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
            group,
            "--conversation",
            group,
        ],
        "s46 group read",
    )
    .await
}

#[cfg(all(test, feature = "realnet"))]
fn mvp_s46_decrypted_contains(read: &serde_json::Value, needle: &str) -> bool {
    read["decrypted_messages"].as_array().is_some_and(|messages| {
        messages
            .iter()
            .any(|message| message["body_utf8"].as_str().is_some_and(|body| body.contains(needle)))
    })
}

#[cfg(all(test, feature = "realnet"))]
fn mvp_s46_assert_gateway_opaque(
    compose_project: &str,
    gateway_capture: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let capture = mvp_s46_service_file(compose_project, gateway_capture)?;
    let redb = mvp_s46_service_file(compose_project, "/var/lib/ramflux/gateway/gateway.redb")?;
    for haystack in [&capture, &redb] {
        for needle in [
            b"ramflux.sdk.group_control.v1".as_slice(),
            b"group.member_invited".as_slice(),
            b"group.member_accepted".as_slice(),
            b"MemberInvitedV2".as_slice(),
            b"MemberAccepted".as_slice(),
            b"invitee_identity".as_slice(),
            b"invitee_signing_public_key".as_slice(),
            b"invited_role".as_slice(),
            b"group_key".as_slice(),
            S46_PRE_ACCEPT_SENTINEL.as_bytes(),
            S46_POST_ACCEPT_SENTINEL.as_bytes(),
        ] {
            assert!(
                !contains_subslice(haystack, needle),
                "gateway leaked group invite marker {}",
                String::from_utf8_lossy(needle)
            );
        }
    }
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
fn mvp_s46_service_file(
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
        .current_dir(code_root().join("ramflux/deploy"))
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
