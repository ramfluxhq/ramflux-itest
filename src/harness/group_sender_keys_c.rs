// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use crate::*;

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s9_rf_json_step(
    step: &'static str,
    rf_binary: &Path,
    args: &[&str],
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    realnet_step(format!("{step} before"), format!("argc={}", args.len()));
    let value = tokio::time::timeout(Duration::from_secs(45), mvp_s4_rf_json(rf_binary, args))
        .await
        .map_err(|_elapsed| format!("{step} timed out"))??;
    realnet_step(format!("{step} after"), "ok");
    Ok(value)
}

#[cfg(all(test, feature = "realnet"))]
#[allow(clippy::too_many_arguments)]
pub(crate) fn mvp_s9_contact_request_args<'a>(
    socket: &'a str,
    account: &'a str,
    message: &'a str,
    envelope: &'a str,
    source_principal: &'a str,
    sender: &'a str,
    recipient_device: &'a str,
    target_delivery: &'a str,
    federation_url: &'a str,
    source_node: &'a str,
    target_node: &'a str,
    recipient_prekey_url: &'a str,
) -> Vec<&'a str> {
    vec![
        "--socket",
        socket,
        "contact",
        "request",
        "--account",
        account,
        "--link",
        "friend_link_s9_cross_node",
        "--requester",
        "alice_s9",
        "--target",
        "bob_s9",
        "--conversation",
        "conv_s9_friend",
        "--message",
        message,
        "--envelope",
        envelope,
        "--source-principal",
        source_principal,
        "--sender",
        sender,
        "--recipient-device",
        recipient_device,
        "--target-delivery",
        target_delivery,
        "--federation-url",
        federation_url,
        "--source-node",
        source_node,
        "--target-node",
        target_node,
        "--recipient-prekey-url",
        recipient_prekey_url,
    ]
}

#[cfg(all(test, feature = "realnet"))]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn mvp_s9_rf_contact_accept(
    rf_binary: &Path,
    socket: &str,
    account: &str,
    message: &str,
    envelope: &str,
    source_principal: &str,
    sender: &str,
    recipient_device: &str,
    target_delivery: &str,
    federation_url: &str,
    source_node: &str,
    target_node: &str,
    recipient_prekey_url: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    mvp_s9_rf_json_step(
        "S9 contact accept rf",
        rf_binary,
        &[
            "--socket",
            socket,
            "contact",
            "accept",
            "--account",
            account,
            "--link",
            "friend_link_s9_cross_node",
            "--requester",
            "alice_s9",
            "--target",
            "bob_s9",
            "--conversation",
            "conv_s9_friend",
            "--message",
            message,
            "--envelope",
            envelope,
            "--source-principal",
            source_principal,
            "--sender",
            sender,
            "--recipient-device",
            recipient_device,
            "--target-delivery",
            target_delivery,
            "--federation-url",
            federation_url,
            "--source-node",
            source_node,
            "--target-node",
            target_node,
            "--recipient-prekey-url",
            recipient_prekey_url,
        ],
    )
    .await
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp_s9_first_plaintext(
    value: &serde_json::Value,
) -> Result<String, Box<dyn std::error::Error>> {
    let decrypted =
        value["decrypted_messages"].as_array().ok_or("missing S9 plaintext messages")?;
    let first = decrypted.first().ok_or("missing S9 first plaintext")?;
    let bytes = ramflux_protocol::decode_base64url(
        first["plaintext_body_base64"].as_str().ok_or("missing S9 plaintext body")?,
    )?;
    Ok(String::from_utf8(bytes)?)
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s9_assert_friend_link(
    rf_binary: &Path,
    socket: &str,
    account: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let contacts = mvp_s9_rf_json_step(
        "S9 contact list rf",
        rf_binary,
        &["--socket", socket, "contact", "list", "--account", account],
    )
    .await?;
    let links = contacts["contacts"].as_array().ok_or("missing contacts")?;
    assert!(links.iter().any(|link| {
        link["link_id"] == "friend_link_s9_cross_node" && link["state"] == "accepted"
    }));
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
#[allow(clippy::too_many_lines)]
pub(crate) async fn mvp_s9_assert_group_receive_idempotent(
    gateway_quic_addr: std::net::SocketAddr,
    ca_cert: &Path,
    gateway_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let temp_root = temp_root("s9_group_idempotent")?;
    let alice = mvp_s7_client(&temp_root.join("alice"), MVP_S7_ALICE, gateway_url)?;
    let mut bob = mvp_s7_client(&temp_root.join("bob"), MVP_S7_BOB, gateway_url)?;
    for client in [&alice, &bob] {
        mvp_s7_setup_group_projection(client)?;
    }
    let mut alice_engine = alice
        .connect_gateway_session(mvp_s7_gateway_config(
            gateway_quic_addr,
            ca_cert,
            gateway_url,
            MVP_S7_ALICE,
        )?)
        .await?;
    let mut bob_engine = bob
        .connect_gateway_session(mvp_s7_gateway_config(
            gateway_quic_addr,
            ca_cert,
            gateway_url,
            MVP_S7_BOB,
        )?)
        .await?;
    mvp_s9_assert_gateway_quic_active(&alice_engine, "alice after connect");
    mvp_s9_assert_gateway_quic_active(&bob_engine, "bob after connect");
    let distribution = alice
        .export_group_sender_key_distribution("group_s7_sender_key", MVP_S7_ALICE.member_id)?;
    mvp_s7_send_sender_key_distribution(
        &alice,
        &mut alice_engine,
        &mut bob,
        &mut bob_engine,
        MVP_S7_BOB,
        "dist_conv_s9_bob",
        "env_s9_sender_key_bob_epoch3",
        &distribution,
    )
    .await?;
    mvp_s9_assert_gateway_quic_active(&alice_engine, "alice after sender-key distribution");
    mvp_s9_assert_gateway_quic_active(&bob_engine, "bob after sender-key distribution");

    let first_plaintext = b"s9 group idempotent first";
    let first_ciphertext = alice.encrypt_group_message(
        "group_s7_sender_key",
        MVP_S7_ALICE.member_id,
        first_plaintext,
    )?;
    mvp_s7_submit_group_message(
        &alice,
        &mut alice_engine,
        MVP_S7_BOB,
        "env_s9_group_first",
        "group_msg_s9_first",
        &first_ciphertext,
        first_plaintext,
    )
    .await?;
    let first_entry =
        mvp_s7_receive_group_entry(&bob, &mut bob_engine, "env_s9_group_first").await?;
    let first =
        bob.append_group_gateway_delivery("group_conv_s7", "group_msg_s9_first", &first_entry)?;
    assert_eq!(first, first_plaintext);
    let duplicate =
        bob.append_group_gateway_delivery("group_conv_s7", "group_msg_s9_first", &first_entry)?;
    assert!(duplicate.is_empty());
    let replay = bob.append_group_gateway_delivery(
        "group_conv_s7",
        "group_msg_s9_first_replay",
        &first_entry,
    )?;
    assert!(replay.is_empty());
    mvp_s9_assert_gateway_quic_active(&alice_engine, "alice after first group receive");
    mvp_s9_assert_gateway_quic_active(&bob_engine, "bob after first group receive");

    let second_plaintext = b"s9 group idempotent second after duplicate";
    let second_ciphertext = alice.encrypt_group_message(
        "group_s7_sender_key",
        MVP_S7_ALICE.member_id,
        second_plaintext,
    )?;
    mvp_s7_submit_group_message(
        &alice,
        &mut alice_engine,
        MVP_S7_BOB,
        "env_s9_group_second",
        "group_msg_s9_second",
        &second_ciphertext,
        second_plaintext,
    )
    .await?;
    let second_entry =
        mvp_s7_receive_group_entry(&bob, &mut bob_engine, "env_s9_group_second").await?;
    let second =
        bob.append_group_gateway_delivery("group_conv_s7", "group_msg_s9_second", &second_entry)?;
    assert_eq!(second, second_plaintext);
    bob.ack_gateway_delivery(
        &mut bob_engine,
        "env_s9_group_first",
        MVP_S7_BOB.device_id,
        1_760_000_801,
    )
    .await?;
    bob.ack_gateway_delivery(
        &mut bob_engine,
        "env_s9_group_second",
        MVP_S7_BOB.device_id,
        1_760_000_802,
    )
    .await?;
    mvp_s9_assert_gateway_quic_active(&alice_engine, "alice after group acks");
    mvp_s9_assert_gateway_quic_active(&bob_engine, "bob after group acks");
    std::fs::remove_dir_all(&temp_root)?;
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
fn mvp_s9_assert_gateway_quic_active(engine: &ramflux_sdk::GatewaySessionEngine, phase: &str) {
    assert_eq!(
        engine.active_transport_kind(),
        ramflux_sdk::GatewaySessionTransportKind::Quic,
        "S9 group idempotent gateway session must stay on QUIC {phase}"
    );
    assert!(
        !engine.session().session_id.is_empty(),
        "S9 group idempotent gateway session missing session_id {phase}"
    );
}
