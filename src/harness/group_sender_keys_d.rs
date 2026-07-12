// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use crate::*;

#[cfg(all(test, feature = "realnet"))]
#[allow(clippy::too_many_lines)]
pub(crate) async fn mvp_s7_assert_group_sender_key_e2ee(
    gateway_quic_addr: std::net::SocketAddr,
    ca_cert: &Path,
    gateway_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let temp_root = temp_root("s7_group_sender_key")?;
    let alice = mvp_s7_client(&temp_root.join("alice"), MVP_S7_ALICE, gateway_url)?;
    let mut bob = mvp_s7_client(&temp_root.join("bob"), MVP_S7_BOB, gateway_url)?;
    let mut carol = mvp_s7_client(&temp_root.join("carol"), MVP_S7_CAROL, gateway_url)?;

    for client in [&alice, &bob, &carol] {
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
    let mut carol_engine = carol
        .connect_gateway_session(mvp_s7_gateway_config(
            gateway_quic_addr,
            ca_cert,
            gateway_url,
            MVP_S7_CAROL,
        )?)
        .await?;
    mvp_s7_assert_gateway_quic_active(&alice_engine, "alice after connect");
    mvp_s7_assert_gateway_quic_active(&bob_engine, "bob after connect");
    mvp_s7_assert_gateway_quic_active(&carol_engine, "carol after connect");

    let distribution = alice
        .export_group_sender_key_distribution("group_s7_sender_key", MVP_S7_ALICE.member_id)?;
    let decoded_distribution: ramflux_sdk::SdkGroupSenderKeyDistribution =
        serde_json::from_slice(&distribution)?;
    assert_eq!(decoded_distribution.group_key_epoch, 3);
    let public_placeholder = ramflux_crypto::blake3_256(
        "ramflux.sdk.group.local_sender_key.v1",
        b"group_s7_sender_key:alice_device_s7:3",
    );
    assert_ne!(
        decoded_distribution.sender_key_seed, public_placeholder,
        "sender key matched an independently derivable placeholder seed"
    );

    mvp_s7_send_sender_key_distribution(
        &alice,
        &mut alice_engine,
        &mut bob,
        &mut bob_engine,
        MVP_S7_BOB,
        "dist_conv_s7_bob",
        "env_s7_sender_key_bob_epoch3",
        &distribution,
    )
    .await?;
    mvp_s7_send_sender_key_distribution(
        &alice,
        &mut alice_engine,
        &mut carol,
        &mut carol_engine,
        MVP_S7_CAROL,
        "dist_conv_s7_carol",
        "env_s7_sender_key_carol_epoch3",
        &distribution,
    )
    .await?;
    mvp_s7_assert_gateway_quic_active(&alice_engine, "alice after epoch3 distribution fanout");
    mvp_s7_assert_gateway_quic_active(&bob_engine, "bob after epoch3 distribution fanout");
    mvp_s7_assert_gateway_quic_active(&carol_engine, "carol after epoch3 distribution fanout");

    let first_plaintext = b"s7 sender-key group message one";
    let first_ciphertext = alice.encrypt_group_message(
        "group_s7_sender_key",
        MVP_S7_ALICE.member_id,
        first_plaintext,
    )?;
    assert!(
        !contains_subslice(&first_ciphertext, first_plaintext),
        "group sender-key ciphertext stored sender plaintext"
    );
    mvp_s7_assert_group_sender_key_ad_tamper_rejects(
        &mut bob,
        &first_ciphertext,
        first_plaintext,
        4,
    )?;
    let bob_first = mvp_s7_deliver_group_message(
        &alice,
        &mut alice_engine,
        &bob,
        &mut bob_engine,
        MVP_S7_BOB,
        "env_s7_group_msg1_bob",
        "msg_s7_group_1",
        &first_ciphertext,
        first_plaintext,
    )
    .await?;
    let carol_first = mvp_s7_deliver_group_message(
        &alice,
        &mut alice_engine,
        &carol,
        &mut carol_engine,
        MVP_S7_CAROL,
        "env_s7_group_msg1_carol",
        "msg_s7_group_1",
        &first_ciphertext,
        first_plaintext,
    )
    .await?;
    assert_eq!(bob_first, first_plaintext);
    assert_eq!(carol_first, first_plaintext);
    mvp_s7_assert_gateway_quic_active(&alice_engine, "alice after first group delivery");
    mvp_s7_assert_gateway_quic_active(&bob_engine, "bob after first group delivery");
    mvp_s7_assert_gateway_quic_active(&carol_engine, "carol after first group delivery");

    let second_plaintext = b"s7 sender-key second message without redistribution";
    let second_ciphertext = alice.encrypt_group_message(
        "group_s7_sender_key",
        MVP_S7_ALICE.member_id,
        second_plaintext,
    )?;
    let bob_second = mvp_s7_deliver_group_message(
        &alice,
        &mut alice_engine,
        &bob,
        &mut bob_engine,
        MVP_S7_BOB,
        "env_s7_group_msg2_bob",
        "msg_s7_group_2",
        &second_ciphertext,
        second_plaintext,
    )
    .await?;
    let carol_second = mvp_s7_deliver_group_message(
        &alice,
        &mut alice_engine,
        &carol,
        &mut carol_engine,
        MVP_S7_CAROL,
        "env_s7_group_msg2_carol",
        "msg_s7_group_2",
        &second_ciphertext,
        second_plaintext,
    )
    .await?;
    assert_eq!(bob_second, second_plaintext);
    assert_eq!(carol_second, second_plaintext);
    mvp_s7_assert_gateway_quic_active(&alice_engine, "alice after second group delivery");
    mvp_s7_assert_gateway_quic_active(&bob_engine, "bob after second group delivery");
    mvp_s7_assert_gateway_quic_active(&carol_engine, "carol after second group delivery");

    let alice_after_remove = alice.remove_group_member(
        "group_s7_sender_key",
        MVP_S7_ALICE.member_id,
        MVP_S7_CAROL.member_id,
    )?;
    assert_eq!(alice_after_remove.group_epoch, 4);
    let bob_after_remove = bob.remove_group_member(
        "group_s7_sender_key",
        MVP_S7_ALICE.member_id,
        MVP_S7_CAROL.member_id,
    )?;
    assert_eq!(bob_after_remove.group_epoch, 4);

    let epoch4_distribution = alice
        .export_group_sender_key_distribution("group_s7_sender_key", MVP_S7_ALICE.member_id)?;
    let decoded_epoch4: ramflux_sdk::SdkGroupSenderKeyDistribution =
        serde_json::from_slice(&epoch4_distribution)?;
    assert_eq!(decoded_epoch4.group_key_epoch, 4);
    assert_ne!(
        decoded_epoch4.sender_key_seed, decoded_distribution.sender_key_seed,
        "epoch transition reused the removed-member epoch sender key"
    );
    mvp_s7_send_sender_key_distribution(
        &alice,
        &mut alice_engine,
        &mut bob,
        &mut bob_engine,
        MVP_S7_BOB,
        "dist_conv_s7_bob_epoch4",
        "env_s7_sender_key_bob_epoch4",
        &epoch4_distribution,
    )
    .await?;
    mvp_s7_assert_gateway_quic_active(&alice_engine, "alice after epoch4 distribution");
    mvp_s7_assert_gateway_quic_active(&bob_engine, "bob after epoch4 distribution");
    mvp_s7_assert_gateway_quic_active(&carol_engine, "carol after epoch4 distribution");

    let after_remove_plaintext = b"s7 sender-key after carol removal";
    let after_remove_ciphertext = alice.encrypt_group_message(
        "group_s7_sender_key",
        MVP_S7_ALICE.member_id,
        after_remove_plaintext,
    )?;
    let bob_after_remove_plaintext = mvp_s7_deliver_group_message(
        &alice,
        &mut alice_engine,
        &bob,
        &mut bob_engine,
        MVP_S7_BOB,
        "env_s7_group_msg3_bob",
        "msg_s7_group_3",
        &after_remove_ciphertext,
        after_remove_plaintext,
    )
    .await?;
    assert_eq!(bob_after_remove_plaintext, after_remove_plaintext);

    mvp_s7_deliver_removed_member_message_and_assert_old_epoch_key_fails(
        &alice,
        &mut alice_engine,
        &carol,
        &mut carol_engine,
        MVP_S7_CAROL,
        "env_s7_group_msg3_carol",
        "msg_s7_group_3",
        &after_remove_ciphertext,
        after_remove_plaintext,
    )
    .await?;
    mvp_s7_assert_gateway_quic_active(&alice_engine, "alice after post-removal PCS check");
    mvp_s7_assert_gateway_quic_active(&bob_engine, "bob after post-removal PCS check");
    mvp_s7_assert_gateway_quic_active(&carol_engine, "carol after post-removal PCS check");

    let _ = alice_engine.close("s7_done").await;
    let _ = bob_engine.close("s7_done").await;
    let _ = carol_engine.close("s7_done").await;
    fs::remove_dir_all(&temp_root)?;
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
fn mvp_s7_assert_group_sender_key_ad_tamper_rejects(
    recipient: &mut ramflux_sdk::RamfluxClient,
    encrypted_body: &[u8],
    forbidden_plaintext: &[u8],
    tampered_epoch: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    #[derive(serde::Deserialize)]
    struct GroupEncryptedEnvelopeProbe {
        schema: String,
        group_id: String,
        sender_id: String,
        group_key_epoch: u64,
        ciphertext: ramflux_crypto::DmCiphertext,
    }

    #[derive(serde::Deserialize)]
    struct GroupSenderKeyStateProbe {
        session_snapshot: ramflux_crypto::DmSessionSnapshot,
    }

    let envelope: GroupEncryptedEnvelopeProbe = serde_json::from_slice(encrypted_body)?;
    assert_eq!(
        envelope.schema, "ramflux.sdk.group_sender_key.message.v1",
        "S7 AD-binding probe expected a group sender-key ciphertext envelope"
    );
    assert_ne!(
        tampered_epoch, envelope.group_key_epoch,
        "S7 AD-binding probe must mutate the associated-data epoch"
    );
    let checkpoint = format!(
        "group_sender_key:{}:{}:{}:recv",
        envelope.group_id, envelope.sender_id, envelope.group_key_epoch
    );
    let event_id = recipient.projection_checkpoint(&checkpoint)?.ok_or_else(|| {
        format!("missing S7 recipient sender-key checkpoint for AD probe {checkpoint}")
    })?;
    let state_bytes = recipient
        .event_body(&event_id)?
        .ok_or_else(|| format!("missing S7 recipient sender-key state event {event_id}"))?;
    let state: GroupSenderKeyStateProbe = serde_json::from_slice(&state_bytes)?;
    let mut session = ramflux_crypto::DmSession::from_snapshot(state.session_snapshot)?;
    let tampered_ad = format!(
        "ramflux.group.sender_key.v1|{}|{}|{}",
        envelope.group_id, envelope.sender_id, tampered_epoch
    )
    .into_bytes();

    match session.decrypt(&envelope.ciphertext, &tampered_ad) {
        Ok(plaintext) => {
            return Err(format!(
                "group sender-key AD tamper decrypted with mutated epoch {tampered_epoch}: {}",
                String::from_utf8_lossy(&plaintext)
            )
            .into());
        }
        Err(error) => {
            let message = error.to_string();
            assert!(
                !message.contains("missing group sender key"),
                "S7 AD-binding probe did not use the recipient's real sender key: {message}"
            );
            assert!(
                message.contains("aead") || message.contains("commitment"),
                "S7 AD-binding probe expected hard AEAD/commitment failure, got: {message}"
            );
        }
    }
    assert!(
        !contains_subslice(encrypted_body, forbidden_plaintext),
        "S7 AD-binding probe ciphertext leaked forbidden plaintext"
    );
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
fn mvp_s7_assert_gateway_quic_active(engine: &ramflux_sdk::GatewaySessionEngine, phase: &str) {
    assert_eq!(
        engine.active_transport_kind(),
        ramflux_sdk::GatewaySessionTransportKind::Quic,
        "S7 group sender-key gateway session must stay on QUIC {phase}"
    );
    assert!(
        !engine.session().session_id.is_empty(),
        "S7 group sender-key gateway session missing session_id {phase}"
    );
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp_s7_client(
    root: &Path,
    spec: MvpS7AccountSpec,
    gateway_url: &str,
) -> Result<ramflux_sdk::RamfluxClient, Box<dyn std::error::Error>> {
    let mut client = ramflux_sdk::RamfluxClient::new();
    client.create_identity_root(spec.principal_id, spec.root_seed);
    client.create_device_branch(spec.principal_id, spec.device_id, 1, spec.device_seed);
    client.open_account_index(root)?;
    let principal_commitment = ramflux_sdk::identity_root_public_key_commitment_for_seed(
        spec.principal_id,
        spec.root_seed,
    );
    client.create_account(spec.account_id, &principal_commitment)?;
    client.set_active_account(spec.account_id)?;
    client.unlock_account(spec.account_id, b"s7-sdk-secret")?;
    client.initialize_and_publish_prekey_bundle(
        &principal_commitment,
        spec.device_id,
        spec.target_delivery_id,
        spec.device_seed,
        Some(gateway_url),
    )?;
    Ok(client)
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp_s7_gateway_config(
    gateway_quic_addr: std::net::SocketAddr,
    ca_cert: &Path,
    gateway_url: &str,
    spec: MvpS7AccountSpec,
) -> Result<ramflux_sdk::GatewaySessionConfig, Box<dyn std::error::Error>> {
    Ok(ramflux_sdk::GatewaySessionConfig::quic(ramflux_sdk::GatewayQuicEndpointConfig {
        bind_addr: "0.0.0.0:0".parse()?,
        gateway_addr: gateway_quic_addr,
        server_name: "localhost".to_owned(),
        ca_cert: ca_cert.to_path_buf(),
        principal_id: spec.principal_id.to_owned(),
        device_id: spec.device_id.to_owned(),
        target_delivery_id: spec.target_delivery_id.to_owned(),
        prekey_http_url: Some(gateway_url.to_owned()),
    }))
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp_s7_setup_group_projection(
    client: &ramflux_sdk::RamfluxClient,
) -> Result<(), Box<dyn std::error::Error>> {
    client.create_group("group_s7_sender_key", MVP_S7_ALICE.member_id)?;
    client.add_group_member("group_s7_sender_key", MVP_S7_BOB.member_id, "member")?;
    client.add_group_member("group_s7_sender_key", MVP_S7_CAROL.member_id, "member")?;
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn mvp_s7_send_sender_key_distribution(
    sender: &ramflux_sdk::RamfluxClient,
    sender_engine: &mut ramflux_sdk::GatewaySessionEngine,
    recipient: &mut ramflux_sdk::RamfluxClient,
    recipient_engine: &mut ramflux_sdk::GatewaySessionEngine,
    recipient_spec: MvpS7AccountSpec,
    conversation_id: &str,
    envelope_id: &str,
    distribution: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let message = mvp_s7_gateway_message(
        conversation_id,
        envelope_id,
        envelope_id,
        recipient_spec,
        Vec::new(),
    );
    let submitted = sender
        .send_plaintext_direct_message_via_gateway(sender_engine, message, distribution)
        .await?;
    assert_eq!(submitted.target_delivery_id, recipient_spec.target_delivery_id);
    assert_node_opaque_payload(&submitted.envelope.encrypted_payload, distribution);
    // T24-A2: the receive path now takes the account's relay QUIC pool for attachment fetches.
    // This harness disables attachment auto-fetch (`false`), so the pool is unused here but still
    // required by the signature; a fresh functional-default pool suffices.
    let relay_quic_pool = ramflux_transport::RelayQuicPool::new(
        ramflux_transport::RelayQuicPoolConfig::functional_default()?,
    );
    let delivered = recipient
        .receive_gateway_plaintext_deliveries(
            recipient_engine,
            &relay_quic_pool,
            10,
            conversation_id,
            false,
            None,
        )
        .await?;
    assert_eq!(delivered.len(), 1);
    assert_eq!(delivered[0].entry.envelope.envelope_id, envelope_id);
    let delivered_distribution =
        ramflux_protocol::decode_base64url(&delivered[0].plaintext_body_base64)?;
    assert_eq!(delivered_distribution, distribution);
    recipient.import_group_sender_key_distribution(&delivered_distribution)?;
    recipient
        .ack_gateway_delivery(
            recipient_engine,
            envelope_id,
            recipient_spec.device_id,
            1_760_000_701,
        )
        .await?;
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn mvp_s7_deliver_group_message(
    sender: &ramflux_sdk::RamfluxClient,
    sender_engine: &mut ramflux_sdk::GatewaySessionEngine,
    recipient: &ramflux_sdk::RamfluxClient,
    recipient_engine: &mut ramflux_sdk::GatewaySessionEngine,
    recipient_spec: MvpS7AccountSpec,
    envelope_id: &str,
    message_id: &str,
    encrypted_body: &[u8],
    forbidden_plaintext: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    mvp_s7_submit_group_message(
        sender,
        sender_engine,
        recipient_spec,
        envelope_id,
        message_id,
        encrypted_body,
        forbidden_plaintext,
    )
    .await?;
    let entry = mvp_s7_receive_group_entry(recipient, recipient_engine, envelope_id).await?;
    let plaintext = recipient.append_group_gateway_delivery("group_conv_s7", message_id, &entry)?;
    recipient
        .ack_gateway_delivery(
            recipient_engine,
            envelope_id,
            recipient_spec.device_id,
            1_760_000_702,
        )
        .await?;
    Ok(plaintext)
}

#[cfg(all(test, feature = "realnet"))]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn mvp_s7_deliver_removed_member_message_and_assert_old_epoch_key_fails(
    sender: &ramflux_sdk::RamfluxClient,
    sender_engine: &mut ramflux_sdk::GatewaySessionEngine,
    removed: &ramflux_sdk::RamfluxClient,
    removed_engine: &mut ramflux_sdk::GatewaySessionEngine,
    removed_spec: MvpS7AccountSpec,
    envelope_id: &str,
    message_id: &str,
    encrypted_body: &[u8],
    forbidden_plaintext: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    mvp_s7_submit_group_message(
        sender,
        sender_engine,
        removed_spec,
        envelope_id,
        message_id,
        encrypted_body,
        forbidden_plaintext,
    )
    .await?;
    let entry = mvp_s7_receive_group_entry(removed, removed_engine, envelope_id).await?;
    let delivered_ciphertext =
        ramflux_protocol::decode_base64url(&entry.envelope.encrypted_payload)?;
    assert_eq!(
        delivered_ciphertext, encrypted_body,
        "S7 removed-member PCS must probe the exact ciphertext delivered through gateway"
    );
    mvp_s7_assert_old_epoch_key_rejects_new_epoch_ciphertext(
        removed,
        &delivered_ciphertext,
        forbidden_plaintext,
    )?;
    removed
        .ack_gateway_delivery(removed_engine, envelope_id, removed_spec.device_id, 1_760_000_703)
        .await?;
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
fn mvp_s7_assert_old_epoch_key_rejects_new_epoch_ciphertext(
    removed: &ramflux_sdk::RamfluxClient,
    encrypted_body: &[u8],
    forbidden_plaintext: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    #[derive(serde::Deserialize)]
    struct GroupEncryptedEnvelopeProbe {
        schema: String,
        group_id: String,
        sender_id: String,
        group_key_epoch: u64,
        ciphertext: ramflux_crypto::DmCiphertext,
    }

    #[derive(serde::Deserialize)]
    struct GroupSenderKeyStateProbe {
        session_snapshot: ramflux_crypto::DmSessionSnapshot,
    }

    let envelope: GroupEncryptedEnvelopeProbe = serde_json::from_slice(encrypted_body)?;
    assert_eq!(
        envelope.schema, "ramflux.sdk.group_sender_key.message.v1",
        "S7 PCS expected a group sender-key ciphertext envelope"
    );
    assert_eq!(
        envelope.group_key_epoch, 4,
        "S7 PCS probe must use the post-removal epoch-4 ciphertext"
    );

    let old_epoch = 3_u64;
    let checkpoint =
        format!("group_sender_key:{}:{}:{old_epoch}:recv", envelope.group_id, envelope.sender_id);
    let event_id = removed
        .projection_checkpoint(&checkpoint)?
        .ok_or_else(|| format!("missing S7 removed-member old epoch checkpoint {checkpoint}"))?;
    let state_bytes = removed
        .event_body(&event_id)?
        .ok_or_else(|| format!("missing S7 removed-member old epoch state event {event_id}"))?;
    let state: GroupSenderKeyStateProbe = serde_json::from_slice(&state_bytes)?;
    let mut old_epoch_session = ramflux_crypto::DmSession::from_snapshot(state.session_snapshot)?;
    let associated_data = format!(
        "ramflux.group.sender_key.v1|{}|{}|{}",
        envelope.group_id, envelope.sender_id, envelope.group_key_epoch
    )
    .into_bytes();

    match old_epoch_session.decrypt(&envelope.ciphertext, &associated_data) {
        Ok(plaintext) => {
            return Err(format!(
                "removed member decrypted epoch-4 ciphertext with old epoch-3 key: {}",
                String::from_utf8_lossy(&plaintext)
            )
            .into());
        }
        Err(error) => {
            let message = error.to_string();
            assert!(
                !message.contains("missing group sender key"),
                "S7 PCS did not exercise Carol's real old epoch-3 key: {message}"
            );
            assert!(
                message.contains("aead") || message.contains("commitment"),
                "S7 PCS expected hard AEAD/commitment failure with Carol's old epoch-3 key, got: {message}"
            );
        }
    }

    assert!(
        !contains_subslice(encrypted_body, forbidden_plaintext),
        "S7 post-removal group ciphertext leaked forbidden plaintext"
    );
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn mvp_s7_submit_group_message(
    sender: &ramflux_sdk::RamfluxClient,
    sender_engine: &mut ramflux_sdk::GatewaySessionEngine,
    recipient_spec: MvpS7AccountSpec,
    envelope_id: &str,
    message_id: &str,
    encrypted_body: &[u8],
    forbidden_plaintext: &[u8],
) -> Result<ramflux_sdk::GatewayInboxEntry, Box<dyn std::error::Error>> {
    let message = mvp_s7_gateway_message(
        "group_conv_s7",
        message_id,
        envelope_id,
        recipient_spec,
        encrypted_body.to_vec(),
    );
    let submitted = sender.submit_direct_message_via_gateway(sender_engine, message).await?;
    assert_eq!(submitted.envelope.envelope_id, envelope_id);
    assert_eq!(submitted.target_delivery_id, recipient_spec.target_delivery_id);
    assert_node_opaque_payload(&submitted.envelope.encrypted_payload, forbidden_plaintext);
    Ok(submitted)
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s7_receive_group_entry(
    recipient: &ramflux_sdk::RamfluxClient,
    recipient_engine: &mut ramflux_sdk::GatewaySessionEngine,
    envelope_id: &str,
) -> Result<ramflux_sdk::GatewayInboxEntry, Box<dyn std::error::Error>> {
    let deliveries = recipient.receive_gateway_deliveries(recipient_engine, 10).await?;
    deliveries
        .into_iter()
        .find(|entry| entry.envelope.envelope_id == envelope_id)
        .ok_or_else(|| format!("missing S7 group delivery {envelope_id}").into())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp_s7_gateway_message(
    conversation_id: &str,
    message_id: &str,
    envelope_id: &str,
    recipient: MvpS7AccountSpec,
    encrypted_body: Vec<u8>,
) -> ramflux_sdk::GatewayDirectMessage {
    ramflux_sdk::GatewayDirectMessage {
        conversation_id: conversation_id.to_owned(),
        message_id: message_id.to_owned(),
        envelope_id: envelope_id.to_owned(),
        source_principal_id: MVP_S7_ALICE.principal_id.to_owned(),
        sender_id: MVP_S7_ALICE.member_id.to_owned(),
        recipient_device_id: Some(recipient.device_id.to_owned()),
        target_delivery_id: recipient.target_delivery_id.to_owned(),
        encrypted_body,
        created_at: itest_now_unix_seconds(),
        ttl: ITEST_REPLAY_TTL_SECONDS,
    }
}
