// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use crate::*;

#[cfg(all(test, feature = "realnet"))]
const MVP_S1_ROOT_SEED: [u8; 32] = [0x51; 32];
#[cfg(all(test, feature = "realnet"))]
const MVP_S1_DEVICE_SEED: [u8; 32] = [0x52; 32];

#[cfg(all(test, feature = "realnet"))]
#[allow(clippy::too_many_lines)]
pub(crate) async fn mvp_s10_assert_private_node_rf_dm(
    gateway_quic_addr: std::net::SocketAddr,
    ca_cert: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let temp_root = temp_root("s10_private_node_rf")?;
    let rf_binary = mvp_s4_build_rf_binary().await?;
    let alice_socket = temp_root.join("alice/rfd.sock");
    let bob_socket = temp_root.join("bob/rfd.sock");
    let (alice_shutdown_tx, alice_shutdown_rx) = tokio::sync::watch::channel(false);
    let (bob_shutdown_tx, bob_shutdown_rx) = tokio::sync::watch::channel(false);
    let alice_config =
        ramflux_sdk::LocalBusConfig::new(&alice_socket, temp_root.join("alice/data"));
    let bob_config = ramflux_sdk::LocalBusConfig::new(&bob_socket, temp_root.join("bob/data"));
    let alice_server = ramflux_sdk::serve_local_bus_until(alice_config, alice_shutdown_rx);
    let bob_server = ramflux_sdk::serve_local_bus_until(bob_config, bob_shutdown_rx);
    let client_flow = async {
        let result = async {
            mvp_s4_wait_for_socket(&alice_socket).await?;
            mvp_s4_wait_for_socket(&bob_socket).await?;
            let alice_socket_arg = mvp_s4_path_arg(&alice_socket);
            let bob_socket_arg = mvp_s4_path_arg(&bob_socket);
            let ca_cert_arg = mvp_s4_path_arg(ca_cert);
            mvp_s10_create_rf_account(
                &rf_binary,
                &alice_socket_arg,
                "alice_s10_account",
                "principal_s10_alice",
                "alice_device_s10",
                "target_s10_alice",
                &gateway_quic_addr.to_string(),
                &ca_cert_arg,
                "a1",
                "a2",
            )
            .await?;
            let alice_status = mvp_s10_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &alice_socket_arg,
                    "account",
                    "status",
                    "--account",
                    "alice_s10_account",
                ],
                "alice account status",
            )
            .await?;
            assert_eq!(
                alice_status["active_transport_kind"].as_str(),
                Some(ramflux_sdk::GatewaySessionTransportKind::Quic.wire_name()),
                "S10 alice private-node session must stay on QUIC, status={alice_status}"
            );
            let bob_commitment = mvp_s10_create_rf_account(
                &rf_binary,
                &bob_socket_arg,
                "bob_s10_account",
                "principal_s10_bob",
                "bob_device_s10",
                "target_s10_bob",
                &gateway_quic_addr.to_string(),
                &ca_cert_arg,
                "b1",
                "b2",
            )
            .await?;
            let contact = mvp_s10_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &alice_socket_arg,
                    "contact",
                    "add",
                    "--account",
                    "alice_s10_account",
                    "--link",
                    "friend_link_s10_alice_bob",
                    "--requester",
                    "principal_s10_alice",
                    "--target",
                    "principal_s10_bob",
                ],
                "s10 contact add alice-to-bob",
            )
            .await?;
            assert_eq!(contact["state"], "accepted");
            let bob_status = mvp_s10_rf_json(
                &rf_binary,
                &["--socket", &bob_socket_arg, "account", "status", "--account", "bob_s10_account"],
                "bob account status",
            )
            .await?;
            assert_eq!(
                bob_status["active_transport_kind"].as_str(),
                Some(ramflux_sdk::GatewaySessionTransportKind::Quic.wire_name()),
                "S10 bob private-node session must stay on QUIC, status={bob_status}"
            );
            let plaintext = b"s10 private production node rf dm plaintext";
            let submitted = mvp_s10_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &alice_socket_arg,
                    "dm",
                    "send",
                    "--account",
                    "alice_s10_account",
                    "--conversation",
                    "conv_s10_private",
                    "--message",
                    "msg_s10_private_dm",
                    "--envelope",
                    "env_s10_private_dm",
                    "--source-principal",
                    "principal_s10_alice",
                    "--sender",
                    "alice_s10",
                    "--recipient-principal-commitment",
                    bob_commitment.as_str(),
                    "--recipient-device",
                    "bob_device_s10",
                    "--target",
                    "target_s10_bob",
                    "--body",
                    std::str::from_utf8(plaintext)?,
                ],
                "alice dm send",
            )
            .await?;
            assert_eq!(submitted["envelope"]["envelope_id"], "env_s10_private_dm");
            assert_node_opaque_payload(
                submitted["envelope"]["encrypted_payload"]
                    .as_str()
                    .ok_or("missing S10 encrypted payload")?,
                plaintext,
            );
            let bob_read = mvp_s10_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &bob_socket_arg,
                    "dm",
                    "read",
                    "--account",
                    "bob_s10_account",
                    "--conversation",
                    "conv_s10_private",
                ],
                "bob dm read",
            )
            .await?;
            let decrypted = bob_read["decrypted_messages"]
                .as_array()
                .ok_or("missing S10 decrypted messages")?;
            assert_eq!(decrypted.len(), 1);
            assert_eq!(decrypted[0]["message_id"].as_str(), Some("env_s10_private_dm"));
            let body = ramflux_protocol::decode_base64url(
                decrypted[0]["plaintext_body_base64"].as_str().ok_or("missing S10 plaintext")?,
            )?;
            assert_eq!(body, plaintext);
            Ok::<(), Box<dyn std::error::Error>>(())
        }
        .await;
        let _ = alice_shutdown_tx.send(true);
        let _ = bob_shutdown_tx.send(true);
        result
    };
    let (alice_result, bob_result, flow_result) =
        Box::pin(tokio::time::timeout(Duration::from_mins(3), async {
            tokio::join!(alice_server, bob_server, client_flow)
        }))
        .await
        .map_err(|_elapsed| "S10 client or daemon flow timed out")?;
    alice_result?;
    bob_result?;
    flow_result?;
    std::fs::remove_dir_all(&temp_root)?;
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn mvp_s10_create_rf_account(
    rf_binary: &Path,
    socket: &str,
    account: &str,
    principal: &str,
    device: &str,
    target: &str,
    gateway_addr: &str,
    ca_cert: &str,
    root_seed_hex: &str,
    device_seed_hex: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let created = mvp_s10_rf_json(
        rf_binary,
        &[
            "--socket",
            socket,
            "account",
            "create",
            "--account",
            account,
            "--principal",
            principal,
            "--device",
            device,
            "--target",
            target,
            "--gateway-addr",
            gateway_addr,
            "--ca-cert",
            ca_cert,
            "--root-seed-byte-hex",
            root_seed_hex,
            "--device-seed-byte-hex",
            device_seed_hex,
            "--secret",
            "rf-local-secret",
            "--client-mode",
            "attended_cli",
        ],
        &format!("account create {account}"),
    )
    .await?;
    assert_eq!(created["local_account_id"], account);
    assert_eq!(created["target_delivery_id"], target);
    Ok(created["principal_commitment"].as_str().ok_or("missing principal_commitment")?.to_owned())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s4_rf_failure(
    binary: &Path,
    args: &[&str],
) -> Result<String, Box<dyn std::error::Error>> {
    let binary = binary.to_path_buf();
    let args = args.iter().copied().map(str::to_owned).collect::<Vec<_>>();
    let command_line = format!("{} {}", binary.display(), args.join(" "));
    let output = match tokio::time::timeout(
        Duration::from_mins(2),
        tokio::task::spawn_blocking(move || std::process::Command::new(binary).args(args).output()),
    )
    .await
    {
        Ok(result) => result??,
        Err(_elapsed) => {
            return Err(format!("rf command timed out expecting failure: {command_line}").into());
        }
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let status = output.status.code().map_or_else(|| "signal".to_owned(), |code| code.to_string());
    if output.status.success() {
        return Err(format!(
            "rf command unexpectedly succeeded: command={command_line} status={status} stdout={stdout} stderr={stderr}"
        )
        .into());
    }
    Ok(format!("{stdout}{stderr}"))
}

#[cfg(all(test, feature = "realnet"))]
#[derive(Clone, Copy)]
pub(crate) struct MvpS7AccountSpec {
    pub(crate) account_id: &'static str,
    pub(crate) principal_id: &'static str,
    pub(crate) member_id: &'static str,
    pub(crate) device_id: &'static str,
    pub(crate) target_delivery_id: &'static str,
    pub(crate) root_seed: [u8; 32],
    pub(crate) device_seed: [u8; 32],
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) const MVP_S7_ALICE: MvpS7AccountSpec = MvpS7AccountSpec {
    account_id: "alice_s7_account",
    principal_id: "principal_s7_alice",
    member_id: "alice_device_s7",
    device_id: "alice_device_s7",
    target_delivery_id: "target_s7_alice",
    root_seed: [0xA7; 32],
    device_seed: [0xA8; 32],
};

#[cfg(all(test, feature = "realnet"))]
pub(crate) const MVP_S7_BOB: MvpS7AccountSpec = MvpS7AccountSpec {
    account_id: "bob_s7_account",
    principal_id: "principal_s7_bob",
    member_id: "bob_device_s7",
    device_id: "bob_device_s7",
    target_delivery_id: "target_s7_bob",
    root_seed: [0xB7; 32],
    device_seed: [0xB8; 32],
};

#[cfg(all(test, feature = "realnet"))]
pub(crate) const MVP_S7_CAROL: MvpS7AccountSpec = MvpS7AccountSpec {
    account_id: "carol_s7_account",
    principal_id: "principal_s7_carol",
    member_id: "carol_device_s7",
    device_id: "carol_device_s7",
    target_delivery_id: "target_s7_carol",
    root_seed: [0xC7; 32],
    device_seed: [0xC8; 32],
};

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s4_rf_json(
    binary: &Path,
    args: &[&str],
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let binary = binary.to_path_buf();
    let args = args.iter().copied().map(str::to_owned).collect::<Vec<_>>();
    let command_line = format!("{} {}", binary.display(), args.join(" "));
    let output = match tokio::time::timeout(
        Duration::from_mins(2),
        tokio::task::spawn_blocking(move || std::process::Command::new(binary).args(args).output()),
    )
    .await
    {
        Ok(result) => result??,
        Err(_elapsed) => return Err(format!("rf command timed out: {command_line}").into()),
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let status = output.status.code().map_or_else(|| "signal".to_owned(), |code| code.to_string());
    if !output.status.success() {
        return Err(format!(
            "rf command failed: command={command_line} status={status} stdout={stdout} stderr={stderr}"
        )
        .into());
    }
    if output.stdout.is_empty() {
        return Err(format!(
            "rf command produced empty stdout: command={command_line} status={status} stdout={stdout} stderr={stderr}"
        )
        .into());
    }
    serde_json::from_slice(&output.stdout).map_err(|error| {
        format!(
            "rf command produced invalid JSON: command={command_line} status={status} error={error} stdout={stdout} stderr={stderr}"
        )
        .into()
    })
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s1_write_client_frame(
    send: &mut quinn::SendStream,
    frame: &ramflux_node_core::GatewayClientFrame,
) -> Result<(), Box<dyn std::error::Error>> {
    tokio::time::timeout(
        Duration::from_secs(10),
        ramflux_transport::write_quic_json_message(send, frame),
    )
    .await??;
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s1_read_server_frame(
    recv: &mut quinn::RecvStream,
) -> Result<ramflux_node_core::GatewayServerFrame, Box<dyn std::error::Error>> {
    Ok(tokio::time::timeout(Duration::from_secs(10), ramflux_transport::read_quic_json_frame(recv))
        .await??)
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s1_expect_session_established(
    recv: &mut quinn::RecvStream,
) -> Result<ramflux_node_core::GatewaySessionEstablishedFrame, Box<dyn std::error::Error>> {
    match mvp_s1_read_server_frame(recv).await? {
        ramflux_node_core::GatewayServerFrame::SessionEstablished { session } => Ok(session),
        other => Err(format!("expected session_established, got {other:?}").into()),
    }
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s1_expect_deliver(
    recv: &mut quinn::RecvStream,
) -> Result<ramflux_node_core::InboxEntry, Box<dyn std::error::Error>> {
    match mvp_s1_read_server_frame(recv).await? {
        ramflux_node_core::GatewayServerFrame::Deliver { entry } => Ok(entry),
        other => Err(format!("expected deliver, got {other:?}").into()),
    }
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s1_expect_ack(
    recv: &mut quinn::RecvStream,
) -> Result<ramflux_node_core::ItestMvp0CursorResponse, Box<dyn std::error::Error>> {
    match mvp_s1_read_server_frame(recv).await? {
        ramflux_node_core::GatewayServerFrame::Ack { cursor } => Ok(cursor),
        other => Err(format!("expected ack, got {other:?}").into()),
    }
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s1_expect_cursor(
    recv: &mut quinn::RecvStream,
) -> Result<Option<ramflux_node_core::ItestMvp0CursorResponse>, Box<dyn std::error::Error>> {
    match mvp_s1_read_server_frame(recv).await? {
        ramflux_node_core::GatewayServerFrame::Cursor { cursor } => Ok(cursor),
        other => Err(format!("expected cursor, got {other:?}").into()),
    }
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s1_expect_resume_entries(
    recv: &mut quinn::RecvStream,
) -> Result<Vec<ramflux_node_core::InboxEntry>, Box<dyn std::error::Error>> {
    match mvp_s1_read_server_frame(recv).await? {
        ramflux_node_core::GatewayServerFrame::Resume { entries } => Ok(entries),
        other => Err(format!("expected resume, got {other:?}").into()),
    }
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp_s1_register_identity(
    gateway_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let root = ramflux_crypto::create_identity_root("principal_s1_realnet", MVP_S1_ROOT_SEED);
    let branch = ramflux_crypto::create_device_branch(
        "principal_s1_realnet",
        "device_s1_realnet",
        1,
        MVP_S1_DEVICE_SEED,
    );
    let now = itest_now_unix_seconds();
    let proof = ramflux_crypto::authorize_device_branch(
        &root,
        &branch,
        ramflux_node_core::ITEST_MVP1_AUDIENCE,
        vec![ramflux_node_core::ITEST_MVP1_BIND_CAPABILITY.to_owned()],
        now,
        now.saturating_add(i64::from(ITEST_REPLAY_TTL_SECONDS)),
    )?;
    let root_public_key =
        ramflux_protocol::encode_base64url(root.signing_key.verifying_key().to_bytes());
    let root_public_key_bytes = ramflux_protocol::decode_base64url(&root_public_key)?;
    let request = ramflux_node_core::ItestMvp1RegisterIdentityRequest {
        principal_commitment: ramflux_crypto::blake3_256_base64url(
            "ramflux.identity.root_public_key.commitment.v1",
            &root_public_key_bytes,
        ),
        root_public_key,
        branch_public_key: ramflux_protocol::encode_base64url(
            branch.signing_key.verifying_key().to_bytes(),
        ),
        proof,
        target_delivery_id: "target_s1_gateway_session".to_owned(),
        gateway_id: "ramflux-gateway".to_owned(),
        session_id: "pre_session_s1_realnet".to_owned(),
        push_alias_hash: Some("push_alias_s1_realnet".to_owned()),
        now,
        registration_pow: None,
        source_ip_hash: Some("mvp_s1_source".to_owned()),
    };
    let response: ramflux_node_core::ItestMvp1IdentityRegistrationResponse =
        ramflux_node_core::itest_http_post_json(
            &format!("{gateway_url}/mvp1/identity/register"),
            &request,
        )?;
    assert_eq!(response.device_id, "device_s1_realnet");
    assert_eq!(response.target_delivery_id, "target_s1_gateway_session");
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp_s1_open_frame(
    pre_auth_cookie: Option<String>,
    pre_auth_now: u64,
    nonce_suffix: &str,
) -> ramflux_node_core::GatewayOpenFrame {
    ramflux_node_core::GatewayOpenFrame {
        protocol_version: ramflux_node_core::GATEWAY_SESSION_PROTOCOL_VERSION.to_owned(),
        transport_kind: "quic_quinn".to_owned(),
        client_instance_id: "rf_s1_realnet".to_owned(),
        device_id: "device_s1_realnet".to_owned(),
        target_delivery_id: "target_s1_gateway_session".to_owned(),
        stream_nonce: format!("nonce_s1_{nonce_suffix}"),
        previous_session_id: None,
        resume_token_hash: None,
        last_seen_inbox_seq: Some(0),
        max_inflight_downstream: 32,
        max_inflight_upstream: 32,
        pre_auth_cookie,
        pre_auth_now: Some(pre_auth_now),
        source_ip_hash: Some("mvp_s1_source".to_owned()),
    }
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp_s1_auth_frame(
    open: &ramflux_node_core::GatewayOpenFrame,
) -> Result<ramflux_node_core::GatewayAuthFrame, Box<dyn std::error::Error>> {
    let now = itest_now_unix_seconds();
    let expires_at = now.saturating_add(i64::from(ITEST_REPLAY_TTL_SECONDS));
    let mut device_proof = ramflux_protocol::DeviceProof {
        schema: "ramflux.device_proof.v1".to_owned(),
        version: 1,
        domain: "ramflux.device_proof.v1".to_owned(),
        ext: ramflux_protocol::Ext::default(),
        signed: mvp_s1_signed_fields(""),
        principal_id: "principal_s1_realnet".to_owned(),
        device_id: open.device_id.clone(),
        device_epoch: 1,
        branch_proof_hash: "branch_proof_hash_s1".to_owned(),
        capability_scope: vec!["gateway.session".to_owned()],
        nonce: open.stream_nonce.clone(),
        expires_at,
    };
    device_proof.signed.signature =
        ramflux_crypto::sign_protocol_object_with_seed(&device_proof, MVP_S1_DEVICE_SEED)?;
    let device_proof_bytes = ramflux_protocol::canonical_json_bytes(&device_proof)?;
    let mut signed_request = ramflux_protocol::SignedRequest {
        schema: "ramflux.signed_request.v1".to_owned(),
        version: 1,
        domain: "ramflux.signed_request.v1".to_owned(),
        ext: ramflux_protocol::Ext::default(),
        signed: mvp_s1_signed_fields(""),
        source_device_id: open.device_id.clone(),
        request_id: format!("req_s1_{}", open.stream_nonce),
        method: ramflux_protocol::HttpMethod::POST,
        path: "/gateway/session/auth".to_owned(),
        device_proof_hash: ramflux_crypto::blake3_256_base64url(
            ramflux_node_core::GATEWAY_DEVICE_PROOF_HASH_DOMAIN,
            &device_proof_bytes,
        ),
        body_hash: ramflux_node_core::gateway_open_hash(open),
        nonce: open.stream_nonce.clone(),
        created_at: now,
        expires_at,
    };
    signed_request.signed.signature =
        ramflux_crypto::sign_protocol_object_with_seed(&signed_request, MVP_S1_DEVICE_SEED)?;
    Ok(ramflux_node_core::GatewayAuthFrame { signed_request, device_proof })
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp_s1_submit_frame(
    open: &ramflux_node_core::GatewayOpenFrame,
    envelope: ramflux_protocol::Envelope,
) -> Result<ramflux_node_core::GatewaySubmitFrame, Box<dyn std::error::Error>> {
    let now = itest_now_unix_seconds();
    let expires_at = now.saturating_add(i64::from(ITEST_REPLAY_TTL_SECONDS));
    let mut signed_request = ramflux_protocol::SignedRequest {
        schema: "ramflux.signed_request.v1".to_owned(),
        version: 1,
        domain: "ramflux.signed_request.v1".to_owned(),
        ext: ramflux_protocol::Ext::default(),
        signed: mvp_s1_signed_fields(""),
        source_device_id: open.device_id.clone(),
        request_id: format!("req_submit_{}", envelope.envelope_id),
        method: ramflux_protocol::HttpMethod::POST,
        path: "/gateway/session/submit".to_owned(),
        device_proof_hash: "already_authed".to_owned(),
        body_hash: ramflux_crypto::blake3_256_base64url(
            ramflux_protocol::domain::ENVELOPE,
            &ramflux_protocol::canonical_json_bytes(&envelope)?,
        ),
        nonce: open.stream_nonce.clone(),
        created_at: now,
        expires_at,
    };
    signed_request.signed.signature =
        ramflux_crypto::sign_protocol_object_with_seed(&signed_request, MVP_S1_DEVICE_SEED)?;
    Ok(ramflux_node_core::GatewaySubmitFrame { signed_request, envelope })
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp_s1_signed_fields(signature: &str) -> ramflux_protocol::SignedFields {
    ramflux_protocol::SignedFields {
        signing_key_id: "device:device_s1_realnet".to_owned(),
        signature_alg: ramflux_protocol::SignatureAlg::Ed25519,
        signature: signature.to_owned(),
    }
}
