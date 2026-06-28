// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use crate::*;

#[cfg(test)]
pub(crate) fn mcp_registry_with_search_tool() -> ramflux_sync::McpRegistry {
    let mut registry = ramflux_sync::McpRegistry::new();
    registry.install_tool(mcp_external_tool_manifest("srv", "search", "search"));
    registry
}

#[cfg(test)]
pub(crate) fn mcp_external_tool_manifest(
    server_id: &str,
    tool_name: &str,
    tool_scope: &str,
) -> ramflux_sync::McpToolManifest {
    ramflux_sync::McpToolManifest {
        server_id: server_id.to_owned(),
        tool_name: tool_name.to_owned(),
        capability: ramflux_sync::McpCapability::ReadConversation,
        tool_scope: Some(tool_scope.to_owned()),
        declared_risk: ramflux_sync::RiskLevel::Low,
        manifest_version: 1,
    }
}

#[cfg(test)]
pub(crate) fn mcp_manifest(
    server_id: &str,
    tool_name: &str,
    capability: ramflux_sync::McpCapability,
    tool_scope: Option<&str>,
    risk: ramflux_sync::RiskLevel,
) -> ramflux_sync::McpToolManifest {
    ramflux_sync::McpToolManifest {
        server_id: server_id.to_owned(),
        tool_name: tool_name.to_owned(),
        capability,
        tool_scope: tool_scope.map(str::to_owned),
        declared_risk: risk,
        manifest_version: 1,
    }
}

#[cfg(test)]
pub(crate) fn mcp_grant_for_registry(
    registry: &ramflux_sync::McpRegistry,
    full_delegation: bool,
    allowed_capabilities: BTreeSet<ramflux_sync::McpCapability>,
) -> ramflux_sync::McpGrantState {
    ramflux_sync::McpGrantState {
        server_id: if full_delegation { "wildcard" } else { "srv" }.to_owned(),
        tool_name: if full_delegation { "wildcard" } else { "search" }.to_owned(),
        tool_scope: Some(if full_delegation { "wildcard" } else { "search" }.to_owned()),
        registry_hash: registry.registry_hash().to_owned(),
        tool_manifest_set_hash: registry.tool_manifest_set_hash().to_owned(),
        full_delegation,
        allowed_capabilities,
        revoked: false,
        expires_at: 4_000_000_000,
    }
}

#[cfg(test)]
pub(crate) fn a2ui_surface(component_type: &str) -> ramflux_sync::A2uiSurface {
    ramflux_sync::A2uiSurface {
        surface_id: "surface_1".to_owned(),
        catalog: "ramflux.mvp".to_owned(),
        catalog_version: "1".to_owned(),
        components: vec![ramflux_sync::A2uiComponent {
            id: "component_1".to_owned(),
            component_type: component_type.to_owned(),
            action_permission: if component_type == "button" {
                Some("message:send".to_owned())
            } else {
                None
            },
            children: Vec::new(),
        }],
    }
}

#[cfg(test)]
pub(crate) fn franking_evidence_parts() -> FrankingEvidenceParts {
    FrankingEvidenceParts {
        plaintext: b"reported plaintext",
        sender_device_id_hash: b"sender-device-hash",
        message_event_id: "msg_event_1",
        canonical_header_bytes: br#"{"counter":1}"#,
        associated_data: b"conversation_1",
        ciphertext: b"ciphertext",
        opening_key: [0x42; 32],
        commitment_key: [0x43; 32],
    }
}
