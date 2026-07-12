// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use super::*;

#[cfg(feature = "realnet")]
#[test]
#[allow(clippy::too_many_lines)]
fn mvp_s54_realnet_object_v3_runtime_starts_with_trust_material()
-> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1")
        || std::env::var("RAMFLUX_OBJECT_V3").as_deref() != Ok("1")
        || std::env::var("RAMFLUX_CROSS_GATEWAY").as_deref() != Ok("1")
    {
        eprintln!(
            "skipping v3 realnet test; set RAMFLUX_ITEST_REALNET=1 RAMFLUX_OBJECT_V3=1 RAMFLUX_CROSS_GATEWAY=1"
        );
        return Ok(());
    }

    let materials = temp_root("s54_object_v3_materials")?;
    let now = ramflux_node_core::now_unix_seconds();
    let root_seed = [0x44; 32];
    let attestation_seed = [0x33; 32];
    let provider_seed = [0x66; 32];
    let offline_root_seed = [0x88; 32]; // T23-A2b2b: offline signing root for the provider keyring
    let issuer_node = "node_b.realnet";
    let gateway_id = "gw-b";
    let certificate =
        mvp_s54_certificate(now, issuer_node, gateway_id, root_seed, attestation_seed)?;
    let envelope =
        mvp_s54_trust_envelope(now, issuer_node, root_seed, provider_seed, &certificate)?;
    for directory in ["gateway-a", "gateway-b"] {
        std::fs::create_dir_all(materials.join(directory))?;
        std::fs::write(
            materials.join(directory).join("issuer-cert.json"),
            serde_json::to_vec_pretty(&certificate)?,
        )?;
    }
    std::fs::create_dir_all(materials.join("federation"))?;
    std::fs::write(
        materials.join("federation/trust-snapshot.json"),
        serde_json::to_vec_pretty(&envelope)?,
    )?;
    mvp_s54_write_provider_keyring(&materials, now, issuer_node, offline_root_seed, provider_seed)?;

    let ports = S8ComposePorts {
        gateway_http: 64_191,
        gateway_quic: 64_461,
        router_http: 64_190,
        router_mesh: 64_462,
        notify_http: 64_193,
        federation_http: 64_192,
        federation_mesh: 64_463,
        relay_http: 64_194,
        relay_media_udp: 64_110,
        signaling_turn_udp: 64_488,
        signaling_turn_tcp: 64_489,
        retention_http: 64_197,
    };
    let node = start_s8_realnet_compose_project_with_env(
        "ramflux-s54-object-v3",
        ports,
        &[
            ("RAMFLUX_V3_MATERIALS_DIR".to_owned(), materials.to_string_lossy().into_owned()),
            (
                "RAMFLUX_GATEWAY_B_V3_ISSUER_SEED".to_owned(),
                ramflux_protocol::encode_base64url(attestation_seed),
            ),
            (
                "RAMFLUX_V3_FEDERATION_PROVIDER_OFFLINE_ROOT_PUBLIC_KEY".to_owned(),
                ramflux_crypto::public_key_base64url_from_seed(offline_root_seed),
            ),
            (
                "RAMFLUX_V3_FEDERATION_PROVIDER_KEYRING_FILE".to_owned(),
                "/etc/ramflux/federation/provider-keyring.json".to_owned(),
            ),
            ("RAMFLUX_V3_FEDERATION_TRUST_ISSUER_NODE_ID".to_owned(), issuer_node.to_owned()),
            (
                "RAMFLUX_V3_FEDERATION_TRUST_ENDPOINT".to_owned(),
                "ramflux-federation:7443".to_owned(),
            ),
        ],
    )?;
    let relay_ca = node.ca_cert.clone();
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async {
        let config = ramflux_transport::RelayClientQuicConfig::new(
            "127.0.0.1:17447",
            "ramflux-relay",
            &relay_ca,
        )?;
        let response =
            ramflux_transport::relay_client_quic_health(&config, std::time::Duration::from_secs(5))
                .await?;
        assert_eq!(response.status, 200);

        let device_id = "device_s54_b";
        let device_seed = [0x5b; 32];
        let registration = mvp_s1_identity_register_request(GatewayFrameIdentitySpec {
            principal_id: "principal_s54_b",
            device_id,
            target_delivery_id: "target_s54_b",
            gateway_id: "gw-b",
            session_id: "pre_session_s54_b",
            push_alias_hash: Some("push_s54_b"),
            source_ip_hash: Some("s54_source"),
            root_seed: [0x5a; 32],
            device_seed,
            device_epoch: 1,
        })?;
        register_mvp1_identity(&node.gateway_url, &registration)?;
        let (_endpoint, _connection, mut send, mut recv) =
            mvp_s1_open_quic_stream("127.0.0.1:18444".parse()?, &node.ca_cert).await?;
        let mut open = mvp_s1_open_frame(None, now, "s54-b");
        open.client_instance_id = "rf_s54_b".to_owned();
        open.device_id = device_id.to_owned();
        open.target_delivery_id = "target_s54_b".to_owned();
        open.stream_nonce = "nonce_s54_b".to_owned();
        open.source_ip_hash = Some("s54_source".to_owned());
        let auth =
            mvp_s1_auth_frame_for_registered_device(&open, "principal_s54_b", 1, device_seed)?;
        mvp_s1_write_client_frame(
            &mut send,
            &ramflux_node_core::GatewayClientFrame::Open { open: open.clone() },
        )
        .await?;
        mvp_s1_write_client_frame(&mut send, &ramflux_node_core::GatewayClientFrame::Auth { auth })
            .await?;
        let _session = mvp_s1_expect_session_established(&mut recv).await?;

        let owner_seed = device_seed;
        let owner_public_key = ramflux_crypto::public_key_base64url_from_seed(owner_seed);
        let requester_public_key = ramflux_crypto::public_key_base64url_from_seed(device_seed);
        let requester_device_hash = ramflux_crypto::blake3_256_base64url(
            "ramflux.object_relay.recipient_device.v1",
            device_id.as_bytes(),
        );
        let mut grant = ramflux_node_core::ObjectAccessGrant {
            schema: ramflux_node_core::OBJECT_ACCESS_GRANT_SCHEMA.to_owned(),
            version: ramflux_node_core::OBJECT_RELAY_V3_PROOF_VERSION,
            object_id: "s54-object".to_owned(),
            manifest_hash: "s54-manifest".to_owned(),
            grantee_device_hash: requester_device_hash.clone(),
            capabilities: vec![
                ramflux_node_core::ObjectRelayCapability::Get,
                ramflux_node_core::ObjectRelayCapability::Ack,
            ],
            issued_at: now.saturating_sub(10),
            expires_at: now + 120,
            owner_signing_key_id: device_id.to_owned(),
            owner_public_key: owner_public_key.clone(),
            owner_signature: String::new(),
        };
        grant.owner_signature = ramflux_crypto::sign_canonical_bytes_with_seed(
            &ramflux_node_core::object_access_grant_signing_bytes(&grant)?,
            owner_seed,
        );
        let binding = ramflux_node_core::object_access_grant_binding_hash(&grant)?;
        let relay = ramflux_transport::QuicGatewayClient::connect(
            "0.0.0.0:0".parse()?,
            "127.0.0.1:17447".parse()?,
            "ramflux-relay",
            &relay_ca,
            std::time::Duration::from_secs(5),
        )
        .await?;

        let encrypted_chunk = b"s54-realnet-v3-ciphertext".to_vec();
        let chunk_cipher_hash = ramflux_node_core::object_relay_chunk_cipher_hash(
            &grant.manifest_hash,
            0,
            &encrypted_chunk,
        );
        let mut owner_proof = ramflux_node_core::OwnerAuthorizationProof {
            schema: ramflux_node_core::OWNER_AUTHORIZATION_PROOF_SCHEMA.to_owned(),
            version: ramflux_node_core::OBJECT_RELAY_V3_PROOF_VERSION,
            capability: ramflux_node_core::ObjectRelayCapability::Put,
            object_id: grant.object_id.clone(),
            manifest_hash: Some(grant.manifest_hash.clone()),
            chunk_id: Some("s54-chunk-0".to_owned()),
            owner_home_node_id: "node_b.realnet".to_owned(),
            owner_principal_id: "principal_s54_b".to_owned(),
            owner_device_epoch: 1,
            request_nonce: "s54-owner-put".to_owned(),
            body_hash: chunk_cipher_hash.clone(),
            issued_at: now,
            expires_at: now + 120,
            owner_signing_key_id: grant.owner_signing_key_id.clone(),
            owner_public_key: grant.owner_public_key.clone(),
            owner_signature: String::new(),
        };
        owner_proof.owner_signature = ramflux_crypto::sign_canonical_bytes_with_seed(
            &ramflux_node_core::owner_authorization_proof_signing_bytes(&owner_proof)?,
            owner_seed,
        );
        let put_binding = ramflux_node_core::owner_authorization_proof_binding_hash(&owner_proof)?;
        let put_body = ramflux_node_core::RelayTokenV3IssueRequest {
            requester_device_id: device_id.to_owned(),
            requester_device_hash: ramflux_crypto::blake3_256_base64url(
                "ramflux.object_relay.recipient_device.v1",
                device_id.as_bytes(),
            ),
            requester_public_key: requester_public_key.clone(),
            requester_device_epoch: 1,
            owner_signing_key_id: grant.owner_signing_key_id.clone(),
            owner_public_key: grant.owner_public_key.clone(),
            owner_home_node_id: "node_b.realnet".to_owned(),
            owner_principal_id: "principal_s54_b".to_owned(),
            owner_device_epoch: 1,
            issuer_node_id: "node_b.realnet".to_owned(),
            gateway_instance_id: "gw-b".to_owned(),
            audience_node_id: "node_a.realnet".to_owned(),
            relay_instance_id: None,
            object_id: grant.object_id.clone(),
            manifest_hash: grant.manifest_hash.clone(),
            chunk_id: "s54-chunk-0".to_owned(),
            capabilities: vec![ramflux_node_core::ObjectRelayCapability::Put],
            authorization_kind: ramflux_node_core::RelayAuthorizationKind::OwnerSession,
            authorization_binding_hash: put_binding,
            delete_after_ack: false,
            issued_at: now,
            expires_at: now + 120,
            nonce: "s54-put-token".to_owned(),
            issuer_certificate: certificate.clone(),
        };
        let put_token = mvp_s54_issue_token(&mut send, &mut recv, &open, put_body, device_seed).await?;
        let put_pop = mvp_s54_pop(
            &put_token,
            ramflux_node_core::ObjectRelayCapability::Put,
            chunk_cipher_hash.clone(),
            device_id,
            device_seed,
            now,
            "s54-put-pop",
        )?;
        let put_response = relay
            .request(&ramflux_transport::GatewayQuicRequest {
                method: "POST".to_owned(),
                path: "/relay/v1/object/put_chunk".to_owned(),
                body: serde_json::json!({
                    "token": put_token,
                    "certificate": certificate,
                    "owner_proof": owner_proof,
                    "pop": put_pop,
                    "body_hash": chunk_cipher_hash,
                    "capability": "put",
                    "chunk_index": 0,
                    "chunk_cipher_hash": chunk_cipher_hash,
                    "encrypted_chunk": encrypted_chunk,
                    "expires_at": now + 100,
                    "delete_after_ack": false,
                }),
            })
            .await?;
        assert_eq!(put_response.status, 200, "v3 put must mutate relay store: {put_response:?}");

        let body = ramflux_node_core::RelayTokenV3IssueRequest {
            requester_device_id: device_id.to_owned(),
            requester_device_hash,
            requester_public_key: requester_public_key.clone(),
            requester_device_epoch: 1,
            owner_signing_key_id: grant.owner_signing_key_id.clone(),
            owner_public_key: grant.owner_public_key.clone(),
            owner_home_node_id: "node_b.realnet".to_owned(),
            owner_principal_id: "principal_s54_b".to_owned(),
            owner_device_epoch: 1,
            issuer_node_id: "node_b.realnet".to_owned(),
            gateway_instance_id: "gw-b".to_owned(),
            audience_node_id: "node_a.realnet".to_owned(),
            relay_instance_id: None,
            object_id: grant.object_id.clone(),
            manifest_hash: grant.manifest_hash.clone(),
            chunk_id: "s54-chunk-0".to_owned(),
            capabilities: vec![ramflux_node_core::ObjectRelayCapability::Get],
            authorization_kind: ramflux_node_core::RelayAuthorizationKind::OwnerGrant,
            authorization_binding_hash: binding.clone(),
            delete_after_ack: false,
            issued_at: now,
            expires_at: now + 120,
            nonce: "s54-token-nonce".to_owned(),
            issuer_certificate: certificate.clone(),
        };
        let token = mvp_s54_issue_token(&mut send, &mut recv, &open, body, device_seed).await?;
        assert_eq!(token.issuer_node_id, "node_b.realnet");
        let descriptor = serde_json::json!({
            "capability": "get",
            "chunk_id": token.chunk_id,
            "manifest_hash": token.manifest_hash,
            "object_id": token.object_id,
        });
        let body_hash = ramflux_crypto::blake3_256_base64url(
            "ramflux.object_relay.v3.get.body",
            &ramflux_protocol::canonical_json_bytes(&descriptor)?,
        );
        let pop = mvp_s54_pop(
            &token,
            ramflux_node_core::ObjectRelayCapability::Get,
            body_hash.clone(),
            device_id,
            device_seed,
            now,
            "s54-pop-nonce",
        )?;
        let request_body = serde_json::json!({
            "token": token,
            "certificate": certificate,
            "grant": grant,
            "pop": pop,
            "body_hash": body_hash,
            "capability": "get",
        });
        let response = relay
            .request(&ramflux_transport::GatewayQuicRequest {
                method: "POST".to_owned(),
                path: "/relay/v1/object/get_chunk".to_owned(),
                body: request_body,
            })
            .await?;
        if response.status != 200 {
            let relay_logs = mvp_s54_container_logs("ramflux-relay");
            let federation_logs = mvp_s54_container_logs("ramflux-federation");
            return Err(format!(
                "authorized v3 request should return the stored chunk: {response:?}\nrelay logs:\n{relay_logs}\nfederation logs:\n{federation_logs}"
            )
            .into());
        }

        let ack_descriptor = serde_json::json!({
            "capability": "ack",
            "chunk_id": "s54-chunk-0",
            "manifest_hash": grant.manifest_hash.clone(),
            "object_id": grant.object_id.clone(),
        });
        let ack_body_hash = ramflux_crypto::blake3_256_base64url(
            "ramflux.object_relay.v3.ack.body",
            &ramflux_protocol::canonical_json_bytes(&ack_descriptor)?,
        );
        let ack_body = ramflux_node_core::RelayTokenV3IssueRequest {
            requester_device_id: device_id.to_owned(),
            requester_device_hash: ramflux_crypto::blake3_256_base64url(
                "ramflux.object_relay.recipient_device.v1",
                device_id.as_bytes(),
            ),
            requester_public_key: requester_public_key.clone(),
            requester_device_epoch: 1,
            owner_signing_key_id: grant.owner_signing_key_id.clone(),
            owner_public_key: grant.owner_public_key.clone(),
            owner_home_node_id: "node_b.realnet".to_owned(),
            owner_principal_id: "principal_s54_b".to_owned(),
            owner_device_epoch: 1,
            issuer_node_id: "node_b.realnet".to_owned(),
            gateway_instance_id: "gw-b".to_owned(),
            audience_node_id: "node_a.realnet".to_owned(),
            relay_instance_id: None,
            object_id: grant.object_id.clone(),
            manifest_hash: grant.manifest_hash.clone(),
            chunk_id: "s54-chunk-0".to_owned(),
            capabilities: vec![ramflux_node_core::ObjectRelayCapability::Ack],
            authorization_kind: ramflux_node_core::RelayAuthorizationKind::OwnerGrant,
            authorization_binding_hash: binding.clone(),
            delete_after_ack: false,
            issued_at: now,
            expires_at: now + 120,
            nonce: "s54-ack-token".to_owned(),
            issuer_certificate: certificate.clone(),
        };
        let ack_token = mvp_s54_issue_token(&mut send, &mut recv, &open, ack_body, device_seed).await?;
        let ack_pop = mvp_s54_pop(
            &ack_token,
            ramflux_node_core::ObjectRelayCapability::Ack,
            ack_body_hash.clone(),
            device_id,
            device_seed,
            now,
            "s54-ack-pop",
        )?;
        let ack_response = relay
            .request(&ramflux_transport::GatewayQuicRequest {
                method: "POST".to_owned(),
                path: "/relay/v1/object/ack".to_owned(),
                body: serde_json::json!({
                    "token": ack_token,
                    "certificate": certificate,
                    "grant": grant,
                    "pop": ack_pop,
                    "body_hash": ack_body_hash,
                    "capability": "ack",
                }),
            })
            .await?;
        assert_eq!(ack_response.status, 200, "v3 ack must mutate relay state: {ack_response:?}");

        let tombstone_expires_at = now + 120;
        let source_event_id = "s54-tombstone-event".to_owned();
        let tombstone_descriptor = serde_json::json!({
            "expires_at": tombstone_expires_at,
            "manifest_hash": grant.manifest_hash.clone(),
            "object_id": grant.object_id.clone(),
            "signed_at": now,
            "source_event_id": source_event_id.clone(),
        });
        let tombstone_hash = ramflux_crypto::blake3_256_base64url(
            "ramflux.object_relay.tombstone.v3",
            &ramflux_protocol::canonical_json_bytes(&tombstone_descriptor)?,
        );
        let mut tombstone_proof = ramflux_node_core::OwnerAuthorizationProof {
            schema: ramflux_node_core::OWNER_AUTHORIZATION_PROOF_SCHEMA.to_owned(),
            version: ramflux_node_core::OBJECT_RELAY_V3_PROOF_VERSION,
            capability: ramflux_node_core::ObjectRelayCapability::Tombstone,
            object_id: grant.object_id.clone(),
            manifest_hash: Some(grant.manifest_hash.clone()),
            chunk_id: None,
            owner_home_node_id: "node_b.realnet".to_owned(),
            owner_principal_id: "principal_s54_b".to_owned(),
            owner_device_epoch: 1,
            request_nonce: "s54-tombstone-owner".to_owned(),
            body_hash: tombstone_hash.clone(),
            issued_at: now,
            expires_at: tombstone_expires_at,
            owner_signing_key_id: grant.owner_signing_key_id.clone(),
            owner_public_key: grant.owner_public_key.clone(),
            owner_signature: String::new(),
        };
        tombstone_proof.owner_signature = ramflux_crypto::sign_canonical_bytes_with_seed(
            &ramflux_node_core::owner_authorization_proof_signing_bytes(&tombstone_proof)?,
            owner_seed,
        );
        let tombstone_binding = ramflux_node_core::owner_authorization_proof_binding_hash(&tombstone_proof)?;
        let tombstone_body = ramflux_node_core::RelayTokenV3IssueRequest {
            requester_device_id: device_id.to_owned(),
            requester_device_hash: ramflux_crypto::blake3_256_base64url(
                "ramflux.object_relay.recipient_device.v1",
                device_id.as_bytes(),
            ),
            requester_public_key: requester_public_key.clone(),
            requester_device_epoch: 1,
            owner_signing_key_id: grant.owner_signing_key_id.clone(),
            owner_public_key: grant.owner_public_key.clone(),
            owner_home_node_id: "node_b.realnet".to_owned(),
            owner_principal_id: "principal_s54_b".to_owned(),
            owner_device_epoch: 1,
            issuer_node_id: "node_b.realnet".to_owned(),
            gateway_instance_id: "gw-b".to_owned(),
            audience_node_id: "node_a.realnet".to_owned(),
            relay_instance_id: None,
            object_id: grant.object_id.clone(),
            manifest_hash: grant.manifest_hash.clone(),
            chunk_id: format!("object-relay:{}:{}:tombstone", grant.object_id, grant.manifest_hash),
            capabilities: vec![ramflux_node_core::ObjectRelayCapability::Tombstone],
            authorization_kind: ramflux_node_core::RelayAuthorizationKind::OwnerSession,
            authorization_binding_hash: tombstone_binding,
            delete_after_ack: false,
            issued_at: now,
            expires_at: tombstone_expires_at,
            nonce: "s54-tombstone-token".to_owned(),
            issuer_certificate: certificate.clone(),
        };
        let tombstone_token =
            mvp_s54_issue_token(&mut send, &mut recv, &open, tombstone_body, device_seed).await?;
        let tombstone_pop = mvp_s54_pop(
            &tombstone_token,
            ramflux_node_core::ObjectRelayCapability::Tombstone,
            tombstone_hash.clone(),
            device_id,
            device_seed,
            now,
            "s54-tombstone-pop",
        )?;
        let tombstone_response = relay
            .request(&ramflux_transport::GatewayQuicRequest {
                method: "POST".to_owned(),
                path: "/relay/v1/object/tombstone".to_owned(),
                body: serde_json::json!({
                    "token": tombstone_token,
                    "certificate": certificate,
                    "owner_proof": tombstone_proof,
                    "pop": tombstone_pop,
                    "body_hash": tombstone_hash,
                    "capability": "tombstone",
                    "tombstone_hash": tombstone_hash,
                    "source_event_id": source_event_id,
                    "signed_at": now,
                    "expires_at": tombstone_expires_at,
                }),
            })
            .await?;
        assert_eq!(
            tombstone_response.status, 200,
            "v3 tombstone must mutate relay state: {tombstone_response:?}"
        );
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    drop(node);
    std::fs::remove_dir_all(materials)?;
    Ok(())
}

#[cfg(feature = "realnet")]
async fn mvp_s54_issue_token(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    open: &ramflux_node_core::GatewayOpenFrame,
    body: ramflux_node_core::RelayTokenV3IssueRequest,
    device_seed: [u8; 32],
) -> Result<ramflux_node_core::RelayTokenV3, Box<dyn std::error::Error>> {
    let body_bytes = ramflux_protocol::canonical_json_bytes(&body)?;
    let device_id = &open.device_id;
    let now = ramflux_node_core::now_unix_seconds();
    let mut signed_request = ramflux_protocol::SignedRequest {
        schema: "ramflux.signed_request.v1".to_owned(),
        version: 1,
        domain: "ramflux.signed_request.v1".to_owned(),
        ext: ramflux_protocol::Ext::default(),
        signed: ramflux_protocol::SignedFields {
            signing_key_id: format!("device:{device_id}"),
            signature_alg: ramflux_protocol::SignatureAlg::Ed25519,
            signature: String::new(),
        },
        source_device_id: device_id.clone(),
        request_id: format!("req_s54_v3_token_{}", body.nonce),
        method: ramflux_protocol::HttpMethod::POST,
        path: "/relay/v1/token/v3/issue".to_owned(),
        device_proof_hash: "already_authed".to_owned(),
        body_hash: ramflux_crypto::blake3_256_base64url(
            ramflux_protocol::domain::ENVELOPE,
            &body_bytes,
        ),
        nonce: open.stream_nonce.clone(),
        created_at: i64::try_from(now)?,
        expires_at: i64::try_from(now.saturating_add(120))?,
    };
    signed_request.signed.signature =
        ramflux_crypto::sign_protocol_object_with_seed(&signed_request, device_seed)?;
    mvp_s1_write_client_frame(
        send,
        &ramflux_node_core::GatewayClientFrame::RelayTokenV3Issue {
            request: Box::new(ramflux_node_core::GatewayRelayTokenV3IssueRequest {
                signed_request,
                body,
            }),
        },
    )
    .await?;
    match mvp_s1_read_server_frame(recv).await? {
        ramflux_node_core::GatewayServerFrame::RelayTokenV3Issued { response } => {
            Ok(response.relay_token)
        }
        other => Err(format!("expected gateway v3 token, got {other:?}").into()),
    }
}

#[cfg(feature = "realnet")]
#[allow(clippy::too_many_arguments)]
fn mvp_s54_pop(
    token: &ramflux_node_core::RelayTokenV3,
    capability: ramflux_node_core::ObjectRelayCapability,
    body_hash: String,
    device_id: &str,
    device_seed: [u8; 32],
    now: u64,
    nonce: &str,
) -> Result<ramflux_node_core::RequesterProofOfPossession, Box<dyn std::error::Error>> {
    let mut pop = ramflux_node_core::RequesterProofOfPossession {
        schema: ramflux_node_core::REQUESTER_POP_SCHEMA.to_owned(),
        version: ramflux_node_core::OBJECT_RELAY_V3_PROOF_VERSION,
        token_id: token.token_id.clone(),
        capability,
        object_id: token.object_id.clone(),
        manifest_hash: token.manifest_hash.clone(),
        chunk_id: token.chunk_id.clone(),
        request_nonce: nonce.to_owned(),
        body_hash,
        issued_at: now,
        expires_at: now + 120,
        signer_device_id: device_id.to_owned(),
        signer_public_key: ramflux_crypto::public_key_base64url_from_seed(device_seed),
        signature: String::new(),
    };
    pop.signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &ramflux_node_core::requester_pop_signing_bytes(&pop)?,
        device_seed,
    );
    Ok(pop)
}

#[cfg(feature = "realnet")]
fn mvp_s54_container_logs(service: &str) -> String {
    let container = format!("ramflux-s54-object-v3_{service}_1");
    std::process::Command::new(container_runtime()).args(["logs", &container]).output().map_or_else(
        |error| format!("failed to collect {service} logs: {error}"),
        |output| {
            format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        },
    )
}

#[cfg(feature = "realnet")]
fn mvp_s54_certificate(
    now: u64,
    node_id: &str,
    gateway_instance_id: &str,
    root_seed: [u8; 32],
    attestation_seed: [u8; 32],
) -> Result<ramflux_node_core::GatewayIssuerCertificate, Box<dyn std::error::Error>> {
    let mut certificate = ramflux_node_core::GatewayIssuerCertificate {
        schema: ramflux_node_core::GATEWAY_ISSUER_CERTIFICATE_SCHEMA.to_owned(),
        version: ramflux_node_core::OBJECT_RELAY_V3_PROOF_VERSION,
        cert_id: "s54-gw-b-cert-1".to_owned(),
        node_id: node_id.to_owned(),
        gateway_instance_id: gateway_instance_id.to_owned(),
        attestation_public_key: ramflux_crypto::public_key_base64url_from_seed(attestation_seed),
        attestation_key_id: "s54-gw-b-attestation-1".to_owned(),
        not_before: now.saturating_sub(60),
        not_after: now + 3_600,
        issued_at: now.saturating_sub(60),
        node_root_signing_key_id: "node-b#root-1".to_owned(),
        node_root_signature: String::new(),
        revoked_at: None,
    };
    certificate.node_root_signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &ramflux_node_core::gateway_issuer_certificate_signing_bytes(&certificate)?,
        root_seed,
    );
    Ok(certificate)
}

#[cfg(feature = "realnet")]
fn mvp_s54_trust_envelope(
    now: u64,
    node_id: &str,
    root_seed: [u8; 32],
    provider_seed: [u8; 32],
    certificate: &ramflux_node_core::GatewayIssuerCertificate,
) -> Result<ramflux_node_core::ProviderSignedTrustSnapshot, Box<dyn std::error::Error>> {
    // T23-A2b2b: keyring-era v4 envelope (provider_epoch 1, authorized by the offline-root-signed
    // keyring written by mvp_s54_write_provider_keyring). No provider rotation in this card.
    let mut envelope = ramflux_node_core::ProviderSignedTrustSnapshot {
        schema: ramflux_node_core::PROVIDER_SIGNED_TRUST_SNAPSHOT_ENVELOPE_SCHEMA.to_owned(),
        version: ramflux_node_core::PROVIDER_SIGNED_TRUST_SNAPSHOT_ENVELOPE_VERSION,
        snapshot: ramflux_node_core::FederatedIssuerTrustSnapshot {
            schema: ramflux_node_core::FEDERATED_ISSUER_TRUST_SNAPSHOT_SCHEMA.to_owned(),
            version: ramflux_node_core::OBJECT_RELAY_V3_PROOF_VERSION,
            node_id: node_id.to_owned(),
            generation: 1,
            pin_epoch: 1,
            trust_status: ramflux_node_core::FederatedIssuerTrustStatus::Active,
            roots: vec![ramflux_node_core::TrustedNodeRootKey {
                node_id: node_id.to_owned(),
                key_id: certificate.node_root_signing_key_id.clone(),
                public_key: ramflux_crypto::public_key_base64url_from_seed(root_seed),
                not_before: now.saturating_sub(60),
                not_after: now + 3_600,
                pin_epoch: 1,
                retired_at: None,
            }],
            revoked_cert_ids: std::collections::BTreeSet::new(),
            hard_stale_at: now + 300,
        },
        provider_signing_key_id: "s54-provider-1".to_owned(),
        provider_public_key: ramflux_crypto::public_key_base64url_from_seed(provider_seed),
        provider_epoch: 1,
        issued_at: now.saturating_sub(10),
        expires_at: now + 300,
        signature: String::new(),
    };
    envelope.signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &ramflux_node_core::provider_signed_trust_snapshot_signing_bytes(&envelope)?,
        provider_seed,
    );
    Ok(envelope)
}

/// T23-A2b2b: writes the offline-root-signed provider keyring (single provider key, `provider_epoch` 1)
/// to `<materials>/federation/provider-keyring.json` for the default keyring-era relay.
#[cfg(feature = "realnet")]
fn mvp_s54_write_provider_keyring(
    materials: &std::path::Path,
    now: u64,
    node_id: &str,
    offline_root_seed: [u8; 32],
    provider_seed: [u8; 32],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut keyring = ramflux_node_core::ProviderKeyring {
        schema: ramflux_node_core::PROVIDER_KEYRING_SCHEMA.to_owned(),
        version: ramflux_node_core::PROVIDER_KEYRING_VERSION,
        issuer_node_id: node_id.to_owned(),
        keyring_epoch: 1,
        keys: vec![ramflux_node_core::ProviderKeyEntry {
            key_id: "s54-provider-1".to_owned(),
            public_key: ramflux_crypto::public_key_base64url_from_seed(provider_seed),
            not_before: now.saturating_sub(60),
            not_after: now + 3_600,
            retired_at: None,
            authorized_provider_epoch: 1,
        }],
        keyring_signature: String::new(),
    };
    keyring.keyring_signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &ramflux_node_core::provider_keyring_signing_bytes(&keyring)?,
        offline_root_seed,
    );
    std::fs::write(
        materials.join("federation/provider-keyring.json"),
        serde_json::to_vec_pretty(&keyring)?,
    )?;
    Ok(())
}
