// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use crate::*;

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp10_assert_full_delegation_revoke(
    gateway_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = mvp3_mcp_a2ui_fixture()?;
    register_mvp1_identity(gateway_url, &fixture.app_register)?;
    register_mvp1_identity(gateway_url, &fixture.cli_register)?;
    publish_mvp1_prekey(gateway_url, "alice_app_device_mvp3_realnet", &fixture.app_prekey_bundle)?;
    publish_mvp1_prekey(gateway_url, "cli_headless_ai_mvp3_realnet", &fixture.cli_prekey_bundle)?;

    let mut registry = mcp_registry_with_search_tool();
    registry.install_tool(mcp_external_tool_manifest("srv", "summarize", "summarize"));
    let grant_event = deliver_mvp10_full_delegation_event(
        gateway_url,
        &fixture,
        registry.registry_hash(),
        registry.tool_manifest_set_hash(),
        "env_mvp10_full_delegation_grant",
        "mvp10-realnet-app-cli-full-delegation-grant",
    )?;
    assert!(grant_event.full_delegation);
    let mut grant = ramflux_sync::McpGrantState {
        server_id: "wildcard".to_owned(),
        tool_name: "wildcard".to_owned(),
        tool_scope: Some("wildcard".to_owned()),
        registry_hash: grant_event.registry_hash,
        tool_manifest_set_hash: grant_event.tool_manifest_set_hash,
        full_delegation: true,
        allowed_capabilities: BTreeSet::new(),
        revoked: false,
        expires_at: 4_000_000_000,
    };
    assert_eq!(registry.invoke_tool("srv", "search", &grant)?, "srv:search");
    assert_eq!(registry.invoke_tool("srv", "summarize", &grant)?, "srv:summarize");

    let revoked =
        deliver_mvp10_full_delegation_revoke(gateway_url, &fixture, &grant_event.grant_id)?;
    assert_eq!(revoked.event_type, "device.full_delegation.revoked");
    assert_eq!(revoked.grant_id, grant_event.grant_id);
    grant.revoked = true;
    assert!(matches!(
        registry.invoke_tool("srv", "search", &grant),
        Err(ramflux_sync::SyncError::GrantInvalidated)
    ));
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp10_assert_stun_binding_realnet() -> Result<(), Box<dyn std::error::Error>> {
    let signaling_addr: std::net::SocketAddr =
        std::env::var("RAMFLUX_ITEST_SIGNALING_TURN_UDP_ADDR")
            .unwrap_or_else(|_| "127.0.0.1:3478".to_owned())
            .parse()?;
    let binding = stun_binding_request(signaling_addr)?;
    assert_eq!(binding.message_type, STUN_BINDING_SUCCESS);
    let mapped = binding.xor_mapped_address.ok_or("missing XOR-MAPPED-ADDRESS")?;
    assert_ne!(mapped.port(), 0);
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp10_assert_own_devices_sync(
    gateway_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = mvp10_own_devices_fixture()?;
    for request in [&fixture.phone_register, &fixture.laptop_register, &fixture.revoked_register] {
        register_mvp1_identity(gateway_url, request)?;
    }
    let revoked: ramflux_node_core::ItestMvp1RevokeDeviceResponse =
        ramflux_node_core::itest_http_post_json(
            &format!("{gateway_url}/mvp1/device/revoke"),
            &mvp1_revoke_request(
                "alice_mvp10_own",
                [0xb1; 32],
                "alice_revoked_mvp10_own",
                1_760_010_001,
            )?,
        )?;
    assert!(revoked.revoked);

    let plaintext =
        br#"{"type":"own_device.sync","event_id":"evt_mvp10_own_001","body":"mvp10 own-device secret"}"#;
    let encrypted_payload =
        ramflux_protocol::encode_base64url(b"opaque own-device encrypted event mvp10");
    let mut envelope = itest_envelope("env_mvp10_own_device_sync", "fanout-placeholder");
    "alice_mvp10_own".clone_into(&mut envelope.source_principal_id);
    "alice_phone_mvp10_own".clone_into(&mut envelope.source_device_id);
    envelope.encrypted_payload = encrypted_payload;
    envelope.payload_hash = ramflux_crypto::blake3_256_base64url(
        "ramflux.test.own_device_sync.v1",
        envelope.encrypted_payload.as_bytes(),
    );

    let fanout: ramflux_node_core::ItestMvp10OwnDeviceFanoutResponse =
        ramflux_node_core::itest_http_post_json(
            &format!("{gateway_url}/mvp10/own-devices/fanout"),
            &ramflux_node_core::ItestMvp10OwnDeviceFanoutRequest {
                principal_id: "alice_mvp10_own".to_owned(),
                source_device_id: "alice_phone_mvp10_own".to_owned(),
                envelope,
            },
        )?;
    assert_eq!(fanout.principal_id, "alice_mvp10_own");
    assert_eq!(fanout.delivered.len(), 1);
    let delivery = fanout.delivered.first().ok_or("missing own-device delivery")?;
    assert_eq!(delivery.device_id, "alice_laptop_mvp10_own");
    assert_eq!(delivery.target_delivery_id, "alice_laptop_target_mvp10_own");
    assert!(matches!(delivery.outcome.as_str(), "online" | "offline_queued"));
    let inbox_seq = delivery.inbox_seq.ok_or("missing own-device inbox seq")?;

    let laptop_inbox = mvp1_inbox(gateway_url, "alice_laptop_target_mvp10_own", 0, 10)?;
    assert_eq!(laptop_inbox.entries.len(), 1);
    let laptop_entry = laptop_inbox.entries.first().ok_or("missing laptop inbox entry")?;
    assert_eq!(laptop_entry.inbox_seq, inbox_seq);
    assert_eq!(
        laptop_entry.envelope.envelope_id,
        ramflux_node_core::mvp10_fanout_envelope_id(
            "env_mvp10_own_device_sync",
            "alice_laptop_mvp10_own"
        )
    );
    assert_node_opaque_payload(&laptop_entry.envelope.encrypted_payload, plaintext);

    let after_cursor = mvp1_inbox(gateway_url, "alice_laptop_target_mvp10_own", inbox_seq, 10)?;
    assert!(after_cursor.entries.is_empty());
    let revoked_inbox = mvp1_inbox(gateway_url, "alice_revoked_target_mvp10_own", 0, 10)?;
    assert!(revoked_inbox.entries.is_empty());

    ramflux_storage::EventStore::append_event(
        &fixture.phone_db,
        "evt_mvp10_own_001",
        "own_device.sync",
        plaintext,
    )?;
    ramflux_storage::EventStore::append_event(
        &fixture.laptop_db,
        "evt_mvp10_own_001",
        "own_device.sync",
        plaintext,
    )?;
    assert_eq!(
        ramflux_storage::EventStore::event_body(&fixture.phone_db, "evt_mvp10_own_001")?,
        ramflux_storage::EventStore::event_body(&fixture.laptop_db, "evt_mvp10_own_001")?
    );
    assert_eq!(
        ramflux_storage::EventStore::event_body(&fixture.laptop_db, "evt_mvp10_own_001")?,
        Some(plaintext.to_vec())
    );
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp10_own_devices_fixture()
-> Result<Mvp10OwnDevicesFixture, Box<dyn std::error::Error>> {
    let root = ramflux_crypto::create_identity_root("alice_mvp10_own", [0xb1; 32]);
    let phone = ramflux_crypto::create_device_branch(
        "alice_mvp10_own",
        "alice_phone_mvp10_own",
        1,
        [0xb2; 32],
    );
    let laptop = ramflux_crypto::create_device_branch(
        "alice_mvp10_own",
        "alice_laptop_mvp10_own",
        1,
        [0xb3; 32],
    );
    let revoked = ramflux_crypto::create_device_branch(
        "alice_mvp10_own",
        "alice_revoked_mvp10_own",
        1,
        [0xb4; 32],
    );
    let phone_register = mvp1_named_register_request(
        &root,
        &phone,
        "alice_phone_target_mvp10_own",
        "alice_phone_session_mvp10_own",
        310,
    )?;
    let laptop_register = mvp1_named_register_request(
        &root,
        &laptop,
        "alice_laptop_target_mvp10_own",
        "alice_laptop_session_mvp10_own",
        311,
    )?;
    let revoked_register = mvp1_named_register_request(
        &root,
        &revoked,
        "alice_revoked_target_mvp10_own",
        "alice_revoked_session_mvp10_own",
        312,
    )?;
    let phone_root = temp_root("mvp10_own_device_phone")?;
    let phone_index = ramflux_storage::AccountIndex::open(&phone_root)?;
    phone_index.create_account("alice_phone_mvp10_local", "alice_mvp10_own")?;
    let phone_key =
        ramflux_storage::AccountDbKey::derive("alice_phone_mvp10_local", b"phone-mvp10-own");
    let phone_db =
        ramflux_storage::AccountDb::open(&phone_index, "alice_phone_mvp10_local", &phone_key)?;
    let laptop_root = temp_root("mvp10_own_device_laptop")?;
    let laptop_index = ramflux_storage::AccountIndex::open(&laptop_root)?;
    laptop_index.create_account("alice_laptop_mvp10_local", "alice_mvp10_own")?;
    let laptop_key =
        ramflux_storage::AccountDbKey::derive("alice_laptop_mvp10_local", b"laptop-mvp10-own");
    let laptop_db =
        ramflux_storage::AccountDb::open(&laptop_index, "alice_laptop_mvp10_local", &laptop_key)?;
    Ok(Mvp10OwnDevicesFixture {
        phone_register,
        laptop_register,
        revoked_register,
        phone_db,
        laptop_db,
    })
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp1_inbox(
    gateway_url: &str,
    target_delivery_id: &str,
    after_inbox_seq: u64,
    limit: usize,
) -> Result<ramflux_node_core::ItestMvp1InboxResponse, Box<dyn std::error::Error>> {
    Ok(ramflux_node_core::itest_http_get_json(&format!(
        "{gateway_url}/mvp1/inbox/{target_delivery_id}?after={after_inbox_seq}&limit={limit}"
    ))?)
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp10_assert_three_backend_real_delivery(
    code_root: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let tls = ramflux_transport::MeshTlsConfig {
        ca_cert: code_root.join("ramflux-deploy/certs/ca.pem"),
        service_cert: code_root.join("ramflux-deploy/certs/gateway/gateway.pem"),
        service_key: code_root.join("ramflux-deploy/certs/gateway/gateway-key.pem"),
    };
    let root = fixture_root();
    let signed_request = read_typed::<ramflux_protocol::SignedRequest>(
        &root,
        ramflux_protocol::fixture_json_path(fixture("signed_request")?),
    )?;
    let envelope = read_typed::<ramflux_protocol::Envelope>(
        &root,
        ramflux_protocol::fixture_json_path(fixture("envelope")?),
    )?;
    let signed_request_signature_bytes = ramflux_protocol::signed_bytes(&signed_request)?;
    ramflux_crypto::verify_fixture_signature(
        &signed_request_signature_bytes,
        &signed_request.signed.signature,
    )?;
    let envelope_signature_bytes = ramflux_protocol::signed_bytes(&envelope)?;
    ramflux_crypto::verify_fixture_signature(
        &envelope_signature_bytes,
        &envelope.signed.signature,
    )?;
    let request =
        ramflux_transport::SubmitEnvelopeRequest { signed_request, envelope: envelope.clone() };
    let expected_signed_request_canonical =
        ramflux_protocol::canonical_json_bytes(&request.signed_request)?;
    let expected_envelope_canonical = ramflux_protocol::canonical_json_bytes(&envelope)?;

    let (https_addr, https_thread) = mvp10_spawn_https_json_transport_server(&tls)?;
    let (quic_addr, quic_task) = mvp10_spawn_quic_transport_server(&tls)?;
    let (h2_addr, h2_task) = mvp10_spawn_h2_transport_server().await?;

    let backends: Vec<(&str, Box<dyn ramflux_transport::TransportBackend>)> = vec![
        (
            "grpc_h2",
            Box::new(ramflux_transport::GrpcH2Backend::connect_h2(
                h2_addr,
                "/ramflux.transport.v1.Transport/SubmitEnvelope",
            )),
        ),
        (
            "quic_quinn",
            Box::new(ramflux_transport::QuicQuinnBackend::connect_quic(
                "0.0.0.0:0".parse()?,
                quic_addr,
                "localhost",
                tls.ca_cert.clone(),
                "/transport/submit",
                Duration::from_secs(10),
            )),
        ),
        (
            "https_json",
            Box::new(ramflux_transport::HttpsJsonBackend::connect_https_json(
                https_addr.to_string(),
                "/transport/submit",
                tls,
                "localhost",
            )),
        ),
    ];

    for (name, backend) in backends {
        let session = backend.open().await?;
        let session = backend
            .auth(
                session,
                ramflux_transport::AuthRequest {
                    device_id: "dev_a".to_owned(),
                    signed_request_hash: "fixture-request-hash".to_owned(),
                },
            )
            .await?;
        assert_eq!(session.backend.as_str(), name);
        let result = backend.submit_envelope(request.clone()).await?;
        assert_eq!(result.backend.as_str(), name);
        assert_eq!(result.signed_request_canonical, expected_signed_request_canonical);
        assert_eq!(result.envelope_canonical, expected_envelope_canonical);
        assert_eq!(result.envelope.envelope_id, envelope.envelope_id);
        assert_eq!(result.envelope.payload_hash, envelope.payload_hash);
        assert_node_opaque_payload(&result.envelope.encrypted_payload, b"plaintext");
    }

    h2_task.await??;
    quic_task.await??;
    https_thread.join().map_err(|_error| "https_json transport server thread panicked")??;
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
#[allow(clippy::too_many_lines)]
pub(crate) async fn mvp10_assert_quic_lan_object_sync(
    code_root: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let tls = ramflux_transport::MeshTlsConfig {
        ca_cert: code_root.join("ramflux-deploy/certs/ca.pem"),
        service_cert: code_root.join("ramflux-deploy/certs/gateway/gateway.pem"),
        service_key: code_root.join("ramflux-deploy/certs/gateway/gateway-key.pem"),
    };
    let plaintext = b"mvp10 real quic lan object sync plaintext; chunk resume must reconstruct this exact object";
    let mut source = ramflux_sync::ObjectStore::new();
    let object = source.put_encrypted_object("object_mvp10_quic_lan", plaintext)?;
    let content_key = source.object_key(&object.object_id)?;
    assert_ne!(object.ciphertext, plaintext);
    let object_key_probe =
        ramflux_crypto::blake3_256(ramflux_protocol::domain::OBJECT, object.object_id.as_bytes());
    assert!(!contains_subslice(&object.ciphertext, plaintext));
    assert!(!contains_subslice(&object.ciphertext, &object_key_probe));

    let manifest = ramflux_sync::chunk_manifest_for_object(
        &object.object_id,
        &object.ciphertext,
        11,
        Some(10),
    );
    let chunks = mvp3_object_chunks(&content_key, &manifest, &object.ciphertext)?;
    let initial_indices = [0_u32, 2_u32];
    let initial_chunks = chunks
        .iter()
        .filter(|chunk| initial_indices.contains(&chunk.chunk_index))
        .cloned()
        .collect::<Vec<_>>();
    let initial_request = Mvp10QuicLanObjectSyncRequest {
        phase: "initial".to_owned(),
        manifest: manifest.clone(),
        chunks: initial_chunks,
    };
    let initial_frame = serde_json::to_vec(&initial_request)?;
    assert!(!contains_subslice(&initial_frame, plaintext));
    assert!(!contains_subslice(&initial_frame, &object_key_probe));

    let (peer_addr, server_task) = mvp10_spawn_quic_lan_object_sync_server(
        &tls,
        content_key,
        plaintext.to_vec(),
        object_key_probe,
    )?;
    let client = ramflux_transport::QuicGatewayClient::connect(
        "0.0.0.0:0".parse()?,
        peer_addr,
        "localhost",
        &tls.ca_cert,
        Duration::from_secs(10),
    )
    .await?;
    let initial_response = mvp10_quic_lan_sync_request(&client, initial_request).await?;
    let expected_missing = expected_mvp3_missing_chunks(manifest.total_chunks, &initial_indices);
    assert_eq!(initial_response.missing.missing_indices, expected_missing);
    assert_eq!(initial_response.resume_token.next_missing_chunk, Some(1));
    assert!(!initial_response.complete);
    assert!(!initial_response.node_visible_plaintext);
    assert!(!initial_response.node_visible_object_key);

    let resume_chunks = chunks
        .iter()
        .filter(|chunk| initial_response.missing.missing_indices.contains(&chunk.chunk_index))
        .cloned()
        .collect::<Vec<_>>();
    let resume_request = Mvp10QuicLanObjectSyncRequest {
        phase: "resume".to_owned(),
        manifest: manifest.clone(),
        chunks: resume_chunks,
    };
    let resume_frame = serde_json::to_vec(&resume_request)?;
    assert!(!contains_subslice(&resume_frame, plaintext));
    assert!(!contains_subslice(&resume_frame, &object_key_probe));
    let final_response = mvp10_quic_lan_sync_request(&client, resume_request).await?;
    assert!(final_response.complete);
    assert!(final_response.missing.missing_indices.is_empty());
    assert!(!final_response.node_visible_plaintext);
    assert!(!final_response.node_visible_object_key);
    assert_eq!(
        final_response.assembled_cipher_hash.as_deref(),
        Some(
            ramflux_crypto::blake3_256_base64url(
                ramflux_protocol::domain::OBJECT,
                &object.ciphertext,
            )
            .as_str()
        )
    );
    let assembled_ciphertext = ramflux_protocol::decode_base64url(
        final_response.assembled_ciphertext.as_deref().ok_or("missing assembled ciphertext")?,
    )?;
    assert_eq!(assembled_ciphertext, object.ciphertext);
    let mut receiver = ramflux_sync::ObjectStore::new();
    let received_object = receiver.put_received_encrypted_object_with_key(
        &object.object_id,
        &object.manifest_hash,
        &assembled_ciphertext,
        &object.plaintext_hash,
        source.object_key(&object.object_id)?,
    );
    assert_eq!(received_object.manifest_hash, object.manifest_hash);
    assert_eq!(receiver.decrypt_object(&object.object_id)?, plaintext);
    drop(client);
    server_task.await??;
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp10_quic_lan_sync_request(
    client: &ramflux_transport::QuicGatewayClient,
    value: Mvp10QuicLanObjectSyncRequest,
) -> Result<Mvp10QuicLanObjectSyncResponse, Box<dyn std::error::Error>> {
    let response = client
        .request(&ramflux_transport::GatewayQuicRequest {
            method: "POST".to_owned(),
            path: "/object/sync".to_owned(),
            body: serde_json::to_value(value)?,
        })
        .await?;
    if response.status != 200 {
        return Err(format!("QUIC LAN sync status {}", response.status).into());
    }
    Ok(serde_json::from_value(response.body)?)
}
