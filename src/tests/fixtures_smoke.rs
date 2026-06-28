// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use super::*;

#[test]
fn fixture_canonical() -> Result<(), Box<dyn std::error::Error>> {
    let root = fixture_root();
    for object in FIXTURE_OBJECTS {
        let json = read_json(&root, fixture_json_path(object))?;
        parse_fixture_value(object, json.clone())?;
        let canonical_value = signed_value(&json)?;
        let canonical = ramflux_protocol::canonical_json_bytes(&canonical_value)?;
        let expected_canonical = fs::read(root.join(fixture_canonical_path(object)))?;
        assert_eq!(canonical, expected_canonical, "canonical mismatch for {}", object.dir);

        let expected_hash = read_trimmed(&root, fixture_hash_path(object))?;
        assert_eq!(
            hash_hex(object.domain, &canonical),
            expected_hash,
            "hash mismatch for {}",
            object.dir
        );

        let mut unknown = json;
        set_unknown_field(&mut unknown)?;
        assert!(
            parse_fixture_value(object, unknown).is_err(),
            "unknown top-level field accepted for {}",
            object.dir
        );
    }
    Ok(())
}

#[test]
fn fixture_signature() -> Result<(), Box<dyn std::error::Error>> {
    let root = fixture_root();
    for object in FIXTURE_OBJECTS {
        let canonical = fs::read(root.join(fixture_canonical_path(object)))?;
        let signature = read_trimmed(&root, fixture_sig_path(object))?;
        ramflux_crypto::verify_fixture_signature(&canonical, &signature)?;

        if object.signed {
            let json = read_json(&root, fixture_json_path(object))?;
            let signature_from_json = required_str(&json, "signature")?;
            assert_eq!(
                signature, signature_from_json,
                "fixture.sig and JSON signature differ for {}",
                object.dir
            );
        }

        let invalid_json = read_json(&root, fixture_invalid_signature_path(object))?;
        let invalid_canonical =
            ramflux_protocol::canonical_json_bytes(&signed_value(&invalid_json)?)?;
        let invalid_signature = if object.signed {
            required_str(&invalid_json, "signature")?
        } else {
            invalid_signature_value()
        };
        assert!(
            ramflux_crypto::verify_fixture_signature(&invalid_canonical, &invalid_signature)
                .is_err(),
            "invalid signature accepted for {}",
            object.dir
        );
    }
    Ok(())
}

#[test]
fn fixture_replay_negative() -> Result<(), Box<dyn std::error::Error>> {
    let root = fixture_root();
    for object in FIXTURE_OBJECTS {
        let mut seen = BTreeSet::new();
        let original = read_json(&root, fixture_json_path(object))?;
        let replay = read_json(&root, fixture_replay_path(object))?;
        let original_key = replay_key(object, &original)?;
        assert!(
            seen.insert(original_key.clone()),
            "first replay key insert failed for {}",
            object.dir
        );
        let replay_key = replay_key(object, &replay)?;
        assert_eq!(
            original_key, replay_key,
            "negative replay fixture did not duplicate key for {}",
            object.dir
        );
        assert!(!seen.insert(replay_key), "negative replay accepted for {}", object.dir);
    }
    Ok(())
}

#[test]
fn fixture_smoke() -> Result<(), Box<dyn std::error::Error>> {
    let root = fixture_root();
    let mut object_count = 0;
    for object in FIXTURE_OBJECTS {
        let json = read_json(&root, fixture_json_path(object))?;
        parse_fixture_value(object, json.clone())?;
        let canonical = ramflux_protocol::canonical_json_bytes(&signed_value(&json)?)?;
        let expected_canonical = fs::read(root.join(fixture_canonical_path(object)))?;
        let expected_hash = read_trimmed(&root, fixture_hash_path(object))?;
        assert_eq!(canonical, expected_canonical, "canonical mismatch for {}", object.dir);
        assert_eq!(hash_hex(object.domain, &canonical), expected_hash);
        object_count += 1;
    }
    assert_eq!(object_count, FIXTURE_OBJECTS.len());
    Ok(())
}

#[test]
fn e2e_scenario_smoke() -> Result<(), Box<dyn std::error::Error>> {
    let root = temp_root("e2e_scenario_smoke")?;
    let mut client = ramflux_sdk::RamfluxClient::new();
    client.create_identity_root("alice", [0x91; 32]);
    client.create_device_branch("alice", "alice_device", 1, [0x92; 32]);
    let proof = client.authorize_current_device(
        "ramflux-node",
        vec!["device.delivery.bind".to_owned()],
        1_760_000_000,
        1_760_003_600,
    )?;
    assert_eq!(proof.device_id, "alice_device");

    client.open_account_index(&root)?;
    client.create_account("alice_local", "alice_commitment")?;
    client.set_active_account("alice_local")?;
    client.unlock_account("alice_local", b"alice-secret")?;
    client.append_event("evt_identity", "identity.created", b"identity")?;
    client.establish_friend_link("friend_link_1", "alice", "bob")?;
    client.send_direct_message("conv_1", "msg_1", "alice", b"opaque message")?;
    client.mark_read("conv_1", "bob", "msg_1")?;
    let projection = client.conversation_projection("conv_1", "bob")?;
    assert_eq!(projection.message_count, 1);

    let object = client.put_encrypted_object("object_e2e", b"file bytes")?;
    assert_eq!(client.decrypt_object(&object.object_id)?, b"file bytes");

    client.install_mcp_tool(ramflux_sync::McpToolManifest {
        server_id: "srv_e2e".to_owned(),
        tool_name: "search".to_owned(),
        capability: ramflux_sync::McpCapability::ReadConversation,
        tool_scope: Some("search".to_owned()),
        declared_risk: ramflux_sync::RiskLevel::Low,
        manifest_version: 1,
    });
    let grant = ramflux_sync::McpGrantState {
        server_id: "srv_e2e".to_owned(),
        tool_name: "search".to_owned(),
        tool_scope: Some("search".to_owned()),
        registry_hash: client.mcp_registry_hash().to_owned(),
        tool_manifest_set_hash: client.mcp_tool_manifest_set_hash().to_owned(),
        full_delegation: false,
        allowed_capabilities: BTreeSet::from([ramflux_sync::McpCapability::ReadConversation]),
        revoked: false,
        expires_at: 4_000_000_000,
    };
    assert_eq!(client.invoke_mcp_tool("srv_e2e", "search", &grant)?, "srv_e2e:search");

    client.register_node("node_a.example", "https://node-a.example");
    client.register_node("node_b.example", "https://node-b.example");
    client.establish_trusted_link("node_a.example", "node_b.example")?;
    client.bind_identity_home("alice", "node_a.example")?;
    client.bind_identity_home("bob", "node_b.example")?;
    let federated = client.send_cross_node_message("alice", "bob", b"federated")?;
    assert_eq!(federated.via_node, "node_b.example");

    let router = ramflux_node_core::RouterCore::new();
    router
        .upsert_session(itest_session("target_e2e", ramflux_node_core::SessionLifecycle::Live))?;
    assert!(matches!(
        router.submit_envelope(itest_envelope("env_e2e", "target_e2e")),
        ramflux_node_core::RouterSubmitOutcome::Online(_)
    ));
    Ok(())
}

#[test]
fn negative_authorization_smoke() -> Result<(), Box<dyn std::error::Error>> {
    let root = ramflux_crypto::create_identity_root("principal_neg", [0x93; 32]);
    let device = ramflux_crypto::create_device_branch("principal_neg", "device_neg", 1, [0x94; 32]);
    let proof = ramflux_crypto::authorize_device_branch(
        &root,
        &device,
        "ramflux-node",
        vec!["device.delivery.bind".to_owned()],
        1_760_000_000,
        1_760_003_600,
    )?;
    assert!(
        ramflux_crypto::verify_branch_proof(
            &root.signing_key.verifying_key(),
            &proof,
            "ramflux-node",
            "own_device.sync",
            1_760_000_001,
        )
        .is_err()
    );

    let mut registry = ramflux_sync::McpRegistry::new();
    registry.install_tool(ramflux_sync::McpToolManifest {
        server_id: "srv_neg".to_owned(),
        tool_name: "shell".to_owned(),
        capability: ramflux_sync::McpCapability::RunShell,
        tool_scope: None,
        declared_risk: ramflux_sync::RiskLevel::High,
        manifest_version: 1,
    });
    let grant = ramflux_sync::McpGrantState {
        server_id: "wildcard".to_owned(),
        tool_name: "wildcard".to_owned(),
        tool_scope: Some("wildcard".to_owned()),
        registry_hash: registry.registry_hash().to_owned(),
        tool_manifest_set_hash: registry.tool_manifest_set_hash().to_owned(),
        full_delegation: true,
        allowed_capabilities: BTreeSet::new(),
        revoked: false,
        expires_at: 4_000_000_000,
    };
    assert!(registry.invoke_tool("srv_neg", "shell", &grant).is_err());

    assert!(
        ramflux_sync::render_a2ui_surface(
            &a2ui_surface("button"),
            &BTreeSet::from(["ramflux.mvp".to_owned()]),
            &BTreeSet::new(),
        )
        .is_err()
    );

    let mut mesh = trusted_two_node_mesh()?;
    mesh.bind_identity_home("alice", "node_a.example")?;
    mesh.bind_identity_home("bob", "node_b.example")?;
    mesh.revoke_trust("node_b.example")?;
    assert!(mesh.send_cross_node_message("alice", "bob", b"blocked").is_err());
    Ok(())
}
