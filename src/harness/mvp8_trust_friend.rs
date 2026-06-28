// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use crate::*;

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp8_assert_invitation_capability_and_suspend(
    federation_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    mvp8_assert_valid_invitation_and_capabilities(federation_url)?;
    mvp8_assert_invitation_and_downgrade_rejections(federation_url)?;
    mvp8_assert_suspend_resume_revoke(federation_url)?;
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp8_assert_valid_invitation_and_capabilities(
    federation_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let now = realnet_now_i64();
    let invitation_expires_at = now.saturating_add(86_400);
    let request = mvp8_handshake_request(
        "node_b.realnet",
        "fh_mvp8_valid",
        &["opaque_delivery", "federation_relay"],
        Some(mvp8_invitation(
            "inv_mvp8_valid",
            "node_b.realnet",
            &["opaque_delivery", "federation_relay"],
            invitation_expires_at,
        )?),
        now,
    )?;
    let admitted = mvp8_post_handshake(federation_url, &request)?;
    assert!(admitted.accepted);
    assert_eq!(admitted.trust_status, ramflux_node_core::FederationTrustStatus::Active);
    assert_eq!(
        admitted.negotiated_capabilities,
        vec!["federation_relay".to_owned(), "opaque_delivery".to_owned()]
    );
    let can_deliver = mvp4_can_deliver(federation_url, "node_b.realnet")?;
    assert!(can_deliver.can_deliver);
    let negotiated: Vec<String> = ramflux_node_core::itest_http_get_json(&format!(
        "{federation_url}/mvp8/federation/capabilities/node_b.realnet"
    ))?;
    assert_eq!(negotiated, admitted.negotiated_capabilities);
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp8_assert_invitation_and_downgrade_rejections(
    federation_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let now = realnet_now_i64();
    let invitation_expires_at = now.saturating_add(86_400);
    let valid_for_downgrade = mvp8_handshake_request(
        "node_b.realnet",
        "fh_mvp8_valid_for_downgrade",
        &["opaque_delivery", "federation_relay"],
        Some(mvp8_invitation(
            "inv_mvp8_valid_for_downgrade",
            "node_b.realnet",
            &["opaque_delivery", "federation_relay"],
            invitation_expires_at,
        )?),
        now,
    )?;
    let admitted = mvp8_post_handshake(federation_url, &valid_for_downgrade)?;
    assert!(admitted.accepted);

    let missing_invitation_request = mvp8_handshake_request(
        "node_c.realnet",
        "fh_mvp8_missing_invitation",
        &["opaque_delivery"],
        None,
        now,
    )?;
    let missing_invitation = mvp8_post_handshake(federation_url, &missing_invitation_request);
    assert!(missing_invitation.is_err());

    let expired_invitation_request = mvp8_handshake_request(
        "node_c.realnet",
        "fh_mvp8_expired_invitation",
        &["opaque_delivery"],
        Some(mvp8_invitation(
            "inv_mvp8_expired",
            "node_c.realnet",
            &["opaque_delivery"],
            1_760_000_000,
        )?),
        now,
    )?;
    let expired_invitation = mvp8_post_handshake(federation_url, &expired_invitation_request);
    assert!(expired_invitation.is_err());

    let mut tampered = mvp8_invitation(
        "inv_mvp8_tampered",
        "node_c.realnet",
        &["opaque_delivery"],
        invitation_expires_at,
    )?;
    tampered.allowed_capabilities.push("object_relay".to_owned());
    let tampered_invitation_request = mvp8_handshake_request(
        "node_c.realnet",
        "fh_mvp8_tampered_invitation",
        &["opaque_delivery"],
        Some(tampered),
        now,
    )?;
    let tampered_invitation = mvp8_post_handshake(federation_url, &tampered_invitation_request);
    assert!(tampered_invitation.is_err());

    let downgrade_request = mvp8_handshake_request(
        "node_b.realnet",
        "fh_mvp8_downgrade",
        &["opaque_delivery"],
        Some(mvp8_invitation(
            "inv_mvp8_downgrade",
            "node_b.realnet",
            &["opaque_delivery", "federation_relay"],
            invitation_expires_at,
        )?),
        now,
    )?;
    let downgrade = mvp8_post_handshake(federation_url, &downgrade_request);
    assert!(downgrade.is_err());
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp8_assert_suspend_resume_revoke(
    federation_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let suspended = set_mvp4_federation_route_status(
        federation_url,
        "node_b.realnet",
        ramflux_node_core::FederationTrustStatus::Suspended,
    )?;
    assert!(!suspended.can_deliver);
    let resumed = set_mvp4_federation_route_status(
        federation_url,
        "node_b.realnet",
        ramflux_node_core::FederationTrustStatus::Active,
    )?;
    assert!(resumed.can_deliver);
    let revoked = set_mvp4_federation_route_status(
        federation_url,
        "node_b.realnet",
        ramflux_node_core::FederationTrustStatus::Revoked,
    )?;
    assert!(!revoked.can_deliver);
    let revive_revoked = set_mvp4_federation_route_status(
        federation_url,
        "node_b.realnet",
        ramflux_node_core::FederationTrustStatus::Active,
    );
    assert!(revive_revoked.is_err());
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp8_admit_friend_node(
    federation_url: &str,
    node_id: &str,
    nonce: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let now = realnet_now_i64();
    let request = mvp8_handshake_request(
        node_id,
        &format!("fh_{nonce}"),
        &["opaque_delivery", "friend_request"],
        Some(mvp8_invitation(
            &format!("inv_{nonce}"),
            node_id,
            &["opaque_delivery", "friend_request"],
            now.saturating_add(86_400),
        )?),
        now,
    )?;
    let admitted = mvp8_post_handshake(federation_url, &request)?;
    assert!(admitted.accepted);
    assert!(admitted.negotiated_capabilities.contains(&"friend_request".to_owned()));
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp8_assert_cross_node_friend_accepts(
    gateway_url: &str,
    federation_url: &str,
    clients: &Mvp2LocalClients,
    alice_session: &mut ramflux_crypto::DmSession,
    bob_session: &mut ramflux_crypto::DmSession,
) -> Result<(), Box<dyn std::error::Error>> {
    let request_plaintext = br#"{"type":"friend_link.request","link_id":"friend_link_mvp8_realnet","from":"alice_realnet","to":"bob_realnet"}"#;
    let request = alice_session.encrypt(request_plaintext, b"alice_device|bob_device")?;
    let request_response = mvp8_post_federated_friend_request(
        federation_url,
        "node_a.realnet",
        "node_b.realnet",
        "env_mvp8_friend_request",
        "bob_target_mvp1_realnet",
        &request,
    )?;
    assert!(request_response.accepted);
    assert!(matches!(request_response.delivery.outcome.as_str(), "online" | "offline_queued"));
    let delivered_request =
        mvp1_inbox_entry(gateway_url, "bob_target_mvp1_realnet", "env_mvp8_friend_request")?;
    assert_node_opaque_payload(&delivered_request.envelope.encrypted_payload, request_plaintext);
    let request_ciphertext: ramflux_crypto::DmCiphertext =
        serde_json::from_str(&delivered_request.envelope.encrypted_payload)?;
    assert_eq!(
        bob_session.decrypt(&request_ciphertext, b"alice_device|bob_device")?,
        request_plaintext
    );
    let bob_link =
        clients.bob_db.establish_friend_link("friend_link_mvp8_realnet", "alice", "bob")?;
    assert_eq!(bob_link.state, "accepted");

    let accept_plaintext = br#"{"type":"friend_link.accept","link_id":"friend_link_mvp8_realnet","from":"bob_realnet","to":"alice_realnet"}"#;
    let accept = bob_session.encrypt(accept_plaintext, b"alice_device|bob_device")?;
    let accept_response = mvp8_post_federated_friend_request(
        federation_url,
        "node_b.realnet",
        "node_a.realnet",
        "env_mvp8_friend_accept",
        "alice_target_mvp1_realnet",
        &accept,
    )?;
    assert!(accept_response.accepted);
    assert!(matches!(accept_response.delivery.outcome.as_str(), "online" | "offline_queued"));
    let delivered_accept =
        mvp1_inbox_entry(gateway_url, "alice_target_mvp1_realnet", "env_mvp8_friend_accept")?;
    assert_node_opaque_payload(&delivered_accept.envelope.encrypted_payload, accept_plaintext);
    let accept_ciphertext: ramflux_crypto::DmCiphertext =
        serde_json::from_str(&delivered_accept.envelope.encrypted_payload)?;
    assert_eq!(
        alice_session.decrypt(&accept_ciphertext, b"alice_device|bob_device")?,
        accept_plaintext
    );
    let alice_link =
        clients.alice_db.establish_friend_link("friend_link_mvp8_realnet", "alice", "bob")?;
    assert_eq!(alice_link.state, "accepted");
    assert_eq!(clients.bob_db.friend_link("friend_link_mvp8_realnet")?.target_id, "bob");
    assert_eq!(clients.alice_db.friend_link("friend_link_mvp8_realnet")?.requester_id, "alice");
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp8_assert_cross_node_friend_rejections(
    federation_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    mvp8_admit_friend_node(federation_url, "node_d.realnet", "mvp8_friend_d")?;
    let suspended = set_mvp4_federation_route_status(
        federation_url,
        "node_d.realnet",
        ramflux_node_core::FederationTrustStatus::Suspended,
    )?;
    assert!(!suspended.can_deliver);
    assert!(
        mvp8_post_federated_friend_request(
            federation_url,
            "node_a.realnet",
            "node_d.realnet",
            "env_mvp8_friend_suspended",
            "target_mvp8_suspended",
            &mvp8_dummy_friend_ciphertext(),
        )
        .is_err()
    );

    mvp8_admit_friend_node(federation_url, "node_e.realnet", "mvp8_friend_e")?;
    let revoked = set_mvp4_federation_route_status(
        federation_url,
        "node_e.realnet",
        ramflux_node_core::FederationTrustStatus::Revoked,
    )?;
    assert!(!revoked.can_deliver);
    assert!(
        mvp8_post_federated_friend_request(
            federation_url,
            "node_a.realnet",
            "node_e.realnet",
            "env_mvp8_friend_revoked",
            "target_mvp8_revoked",
            &mvp8_dummy_friend_ciphertext(),
        )
        .is_err()
    );

    let no_friend_capability = mvp8_handshake_request(
        "node_f.realnet",
        "fh_mvp8_no_friend_capability",
        &["opaque_delivery"],
        Some(mvp8_invitation(
            "inv_mvp8_no_friend_capability",
            "node_f.realnet",
            &["opaque_delivery"],
            realnet_now_i64().saturating_add(86_400),
        )?),
        realnet_now_i64(),
    )?;
    assert!(mvp8_post_handshake(federation_url, &no_friend_capability)?.accepted);
    assert!(
        mvp8_post_federated_friend_request(
            federation_url,
            "node_a.realnet",
            "node_f.realnet",
            "env_mvp8_friend_no_capability",
            "target_mvp8_no_capability",
            &mvp8_dummy_friend_ciphertext(),
        )
        .is_err()
    );
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp8_post_federated_friend_request(
    federation_url: &str,
    source_node_id: &str,
    target_node_id: &str,
    envelope_id: &str,
    target_delivery_id: &str,
    ciphertext: &ramflux_crypto::DmCiphertext,
) -> Result<ramflux_node_core::FederatedFriendRequestResponse, Box<dyn std::error::Error>> {
    let mut envelope = itest_envelope(envelope_id, target_delivery_id);
    envelope.encrypted_payload = serde_json::to_string(ciphertext)?;
    envelope.payload_hash = ramflux_crypto::blake3_256_base64url(
        ramflux_protocol::domain::ENVELOPE,
        envelope.encrypted_payload.as_bytes(),
    );
    Ok(ramflux_node_core::itest_http_post_json(
        &format!("{federation_url}/mvp8/federation/friend-request"),
        &ramflux_node_core::FederatedFriendRequestEnvelope {
            source_node_id: source_node_id.to_owned(),
            target_node_id: target_node_id.to_owned(),
            delivery_class: "opaque_event".to_owned(),
            required_capability: "friend_request".to_owned(),
            envelope,
        },
    )?)
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp8_dummy_friend_ciphertext() -> ramflux_crypto::DmCiphertext {
    ramflux_crypto::DmCiphertext {
        session_id: "dummy_session".to_owned(),
        nonce: [0_u8; 12],
        ciphertext: b"dummy_ciphertext".to_vec(),
        counter: 0,
        ratchet_public_key: None,
        previous_chain_length: 0,
        sender_device_id_hash: [0_u8; 32],
        recipient_device_id_hash: [0_u8; 32],
        device_epoch: 0,
        message_event_id: "dummy_message".to_owned(),
        canonical_header_bytes: Vec::new(),
        header_hash: String::new(),
        key_commitment: String::new(),
        franking_commitment: String::new(),
        commitment: String::new(),
        ciphertext_hash: String::new(),
    }
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp8_post_handshake(
    federation_url: &str,
    request: &ramflux_node_core::FederationHandshakeAdmissionRequest,
) -> Result<ramflux_node_core::FederationHandshakeAdmissionResponse, Box<dyn std::error::Error>> {
    Ok(ramflux_node_core::itest_http_post_json(
        &format!("{federation_url}/mvp8/federation/handshake"),
        request,
    )?)
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp8_handshake_request(
    node_id: &str,
    handshake_id: &str,
    source_capabilities: &[&str],
    invitation: Option<ramflux_node_core::FederationNodeInvitation>,
    now: i64,
) -> Result<ramflux_node_core::FederationHandshakeAdmissionRequest, Box<dyn std::error::Error>> {
    let source_seed = realnet_node_signing_seed(node_id);
    let mut handshake = ramflux_protocol::FederationHandshake {
        schema: ramflux_protocol::domain::FEDERATION_HANDSHAKE.to_owned(),
        version: 1,
        domain: ramflux_protocol::domain::FEDERATION_HANDSHAKE.to_owned(),
        ext: ramflux_protocol::Ext::default(),
        signed: ramflux_protocol::SignedFields {
            signing_key_id: format!("{node_id}#federation"),
            signature_alg: ramflux_protocol::SignatureAlg::Ed25519,
            signature: String::new(),
        },
        handshake_id: handshake_id.to_owned(),
        source_node_id: node_id.to_owned(),
        target_node_id: "node_a.realnet".to_owned(),
        source_capabilities: source_capabilities
            .iter()
            .map(|capability| (*capability).to_owned())
            .collect(),
        protocol_versions: vec!["v1".to_owned()],
        transport_backends: vec!["quic_quinn".to_owned()],
        trust_state_hash: "trust_state_hash_mvp8".to_owned(),
        nonce: format!("nonce_{handshake_id}"),
        created_at: now,
    };
    handshake.signed.signature =
        ramflux_crypto::sign_protocol_object_with_seed(&handshake, source_seed)?;
    Ok(ramflux_node_core::FederationHandshakeAdmissionRequest {
        route: mvp4_federation_route(node_id, ramflux_node_core::FederationTrustStatus::Invited),
        handshake,
        invitation,
        local_capabilities: vec![
            "opaque_delivery".to_owned(),
            "federation_relay".to_owned(),
            "friend_request".to_owned(),
            "object_relay".to_owned(),
        ],
        local_protocol_versions: vec!["v1".to_owned()],
        local_transport_backends: vec!["quic_quinn".to_owned(), "https_json".to_owned()],
        now,
    })
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp8_invitation(
    invitation_id: &str,
    candidate_node_id: &str,
    allowed_capabilities: &[&str],
    expires_at: i64,
) -> Result<ramflux_node_core::FederationNodeInvitation, Box<dyn std::error::Error>> {
    let candidate_node_ca_cert_pem =
        std::fs::read_to_string(code_root().join("ramflux-deploy/certs/federation/ca.pem"))?;
    mvp8_invitation_with_ca(
        invitation_id,
        candidate_node_id,
        allowed_capabilities,
        expires_at,
        candidate_node_ca_cert_pem,
    )
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp8_invitation_with_ca(
    invitation_id: &str,
    candidate_node_id: &str,
    allowed_capabilities: &[&str],
    expires_at: i64,
    candidate_node_ca_cert_pem: String,
) -> Result<ramflux_node_core::FederationNodeInvitation, Box<dyn std::error::Error>> {
    let candidate_seed = realnet_node_signing_seed(candidate_node_id);
    let candidate_public_key = ramflux_crypto::public_key_base64url_from_seed(candidate_seed);
    let mut invitation = ramflux_node_core::FederationNodeInvitation {
        invitation_id: invitation_id.to_owned(),
        inviter_node_id: "node_a.realnet".to_owned(),
        candidate_node_id: candidate_node_id.to_owned(),
        candidate_node_public_key_hash: ramflux_crypto::blake3_256_base64url(
            ramflux_protocol::domain::FEDERATION_HANDSHAKE,
            candidate_public_key.as_bytes(),
        ),
        candidate_node_public_key: candidate_public_key,
        candidate_node_ca_cert_pem,
        allowed_capabilities: allowed_capabilities
            .iter()
            .map(|capability| (*capability).to_owned())
            .collect(),
        expires_at,
        signature: String::new(),
    };
    invitation.signature =
        ramflux_crypto::sign_protocol_object_with_seed(&invitation, candidate_seed)?;
    Ok(invitation)
}
