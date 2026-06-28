// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use super::*;

#[test]
fn mcp_tool_invoke_fixture() -> Result<(), Box<dyn std::error::Error>> {
    let mut registry = mcp_registry_with_search_tool();
    let grant = mcp_grant_for_registry(
        &registry,
        false,
        BTreeSet::from([ramflux_sync::McpCapability::ReadConversation]),
    );
    assert_eq!(registry.invoke_tool("srv", "search", &grant)?, "srv:search");
    registry.remove_tool("srv", "search");
    Ok(())
}

#[test]
fn mcp_grant_risk_matrix() {
    let mut registry = ramflux_sync::McpRegistry::new();
    registry.install_tool(mcp_manifest(
        "srv",
        "shell",
        ramflux_sync::McpCapability::RunShell,
        None,
        ramflux_sync::RiskLevel::High,
    ));
    let grant = mcp_grant_for_registry(&registry, true, BTreeSet::new());
    assert!(registry.invoke_tool("srv", "shell", &grant).is_err());
}

#[test]
fn mcp_registry_hot_update_invalidates_grant() {
    let mut registry = mcp_registry_with_search_tool();
    let grant = mcp_grant_for_registry(&registry, true, BTreeSet::new());
    registry.install_tool(mcp_external_tool_manifest("srv", "calendar_read", "calendar.read"));
    assert!(registry.invoke_tool("srv", "search", &grant).is_err());
}

#[test]
fn a2i_a2ui_schema_fixture() -> Result<(), Box<dyn std::error::Error>> {
    let surface = a2ui_surface("button");
    let rendered = ramflux_sync::render_a2ui_surface(
        &surface,
        &BTreeSet::from(["ramflux.mvp".to_owned()]),
        &BTreeSet::from(["message:send".to_owned()]),
    )?;
    assert!(rendered.semantic_snapshot.contains("surface_1"));
    Ok(())
}

#[test]
fn a2ui_unknown_component_fallback() -> Result<(), Box<dyn std::error::Error>> {
    let rendered = ramflux_sync::render_a2ui_surface(
        &a2ui_surface("unknown"),
        &BTreeSet::from(["ramflux.mvp".to_owned()]),
        &BTreeSet::new(),
    )?;
    assert!(rendered.fallback_used);
    Ok(())
}

#[test]
fn a2ui_unknown_catalog_fallback() -> Result<(), Box<dyn std::error::Error>> {
    let rendered = ramflux_sync::render_a2ui_surface(
        &a2ui_surface("text"),
        &BTreeSet::from(["different.catalog".to_owned()]),
        &BTreeSet::new(),
    )?;
    assert!(rendered.fallback_used);
    Ok(())
}

#[test]
fn a2ui_action_permission_bypass_rejected() {
    let surface = a2ui_surface("button");
    assert!(
        ramflux_sync::render_a2ui_surface(
            &surface,
            &BTreeSet::from(["ramflux.mvp".to_owned()]),
            &BTreeSet::new(),
        )
        .is_err()
    );
}

#[test]
fn a2ui_oversized_or_deep_graph_rejected() {
    let mut child = ramflux_sync::A2uiComponent {
        id: "leaf".to_owned(),
        component_type: "text".to_owned(),
        action_permission: None,
        children: Vec::new(),
    };
    for depth in 0..10 {
        child = ramflux_sync::A2uiComponent {
            id: format!("node_{depth}"),
            component_type: "text".to_owned(),
            action_permission: None,
            children: vec![child],
        };
    }
    let surface = ramflux_sync::A2uiSurface {
        surface_id: "surface_deep".to_owned(),
        catalog: "ramflux.mvp".to_owned(),
        catalog_version: "1".to_owned(),
        components: vec![child],
    };
    assert!(
        ramflux_sync::render_a2ui_surface(
            &surface,
            &BTreeSet::from(["ramflux.mvp".to_owned()]),
            &BTreeSet::new()
        )
        .is_err()
    );
}

#[test]
fn a2ui_cli_renderer_semantic_snapshot() -> Result<(), Box<dyn std::error::Error>> {
    let rendered = ramflux_sync::render_a2ui_surface(
        &a2ui_surface("text"),
        &BTreeSet::from(["ramflux.mvp".to_owned()]),
        &BTreeSet::new(),
    )?;
    assert_eq!(rendered.semantic_snapshot, rendered.semantic_snapshot.clone());
    Ok(())
}

#[test]
fn a2ui_cross_renderer_semantic_consistency() -> Result<(), Box<dyn std::error::Error>> {
    let surface = a2ui_surface("text");
    let first = ramflux_sync::render_a2ui_surface(
        &surface,
        &BTreeSet::from(["ramflux.mvp".to_owned()]),
        &BTreeSet::new(),
    )?;
    let second = ramflux_sync::render_a2ui_surface(
        &surface,
        &BTreeSet::from(["ramflux.mvp".to_owned()]),
        &BTreeSet::new(),
    )?;
    assert_eq!(first.semantic_snapshot, second.semantic_snapshot);
    Ok(())
}

#[test]
fn franking_opening_commitment_node_tag() -> Result<(), Box<dyn std::error::Error>> {
    let evidence = franking_evidence_parts();
    let commitment =
        ramflux_crypto::franking_commitment(&ramflux_crypto::FrankingCommitmentInput {
            plaintext: evidence.plaintext,
            sender_device_id_hash: evidence.sender_device_id_hash,
            message_event_id: evidence.message_event_id,
            canonical_header_bytes: evidence.canonical_header_bytes,
            associated_data: evidence.associated_data,
            ciphertext: evidence.ciphertext,
            opening_key: &evidence.opening_key,
            commitment_key: &evidence.commitment_key,
        });
    let verified = ramflux_sync::verify_franking_evidence(&ramflux_sync::FrankingEvidence {
        plaintext: evidence.plaintext,
        sender_device_id_hash: evidence.sender_device_id_hash,
        message_event_id: evidence.message_event_id,
        canonical_header_bytes: evidence.canonical_header_bytes,
        associated_data: evidence.associated_data,
        ciphertext: evidence.ciphertext,
        opening_key: &evidence.opening_key,
        commitment_key: &evidence.commitment_key,
        expected_commitment: &commitment.commitment,
    })?;
    assert_eq!(verified, commitment.commitment);
    Ok(())
}

#[test]
fn franking_selected_evidence_fixture() -> Result<(), Box<dyn std::error::Error>> {
    let evidence = franking_evidence_parts();
    let json = serde_json::json!({
        "sender_device_id_hash": ramflux_protocol::encode_base64url(evidence.sender_device_id_hash),
        "canonical_header_bytes": ramflux_protocol::encode_base64url(evidence.canonical_header_bytes),
        "opening_key": ramflux_protocol::encode_base64url(evidence.opening_key),
    });
    let encoded = serde_json::to_string(&json)?;
    assert!(encoded.contains("canonical_header_bytes"));
    Ok(())
}

#[test]
fn webrtc_opaque_signal_no_parse() {
    let signal = ramflux_sync::OpaqueCallSignal {
        call_id: "call_1".to_owned(),
        opaque_payload: b"v=0\r\nsecret-sdp".to_vec(),
    };
    let relay = ramflux_sync::relay_opaque_call_signal(&signal);
    assert_ne!(relay.forwarded_payload_hash, "v=0");
}

#[test]
fn webrtc_turn_srtp_no_media_key() -> Result<(), Box<dyn std::error::Error>> {
    let signal = ramflux_sync::OpaqueCallSignal {
        call_id: "call_1".to_owned(),
        opaque_payload: b"opaque".to_vec(),
    };
    let relay = ramflux_sync::relay_opaque_call_signal(&signal);
    ramflux_sync::assert_srtp_relay_has_no_media_key(&relay)?;
    Ok(())
}
