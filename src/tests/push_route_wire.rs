// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! The SDK's push route frames and the node's frame types must stay wire compatible.
use super::*;

fn signed_request(
    path: &str,
) -> Result<ramflux_protocol::SignedRequest, Box<dyn std::error::Error>> {
    Ok(serde_json::from_value(serde_json::json!({
        "schema": "ramflux.signed_request.v1", "version": 1, "domain": "ramflux.signed_request.v1",
        "signing_key_id": "device:phone", "signature_alg": "ed25519", "signature": "fixture",
        "ext": { "session_id": "s1" }, "source_device_id": "phone", "request_id": "req-1", "method": "POST",
        "path": path, "device_proof_hash": "already_authed", "body_hash": "hash",
        "nonce": "nonce", "created_at": 1, "expires_at": 2
    }))?)
}

#[test]
fn sdk_push_route_frames_parse_as_node_frames_with_identical_body_hashes()
-> Result<(), Box<dyn std::error::Error>> {
    for provider in [
        ramflux_sdk::GatewayPushProvider::Apns,
        ramflux_sdk::GatewayPushProvider::Fcm,
        ramflux_sdk::GatewayPushProvider::WebPush,
    ] {
        let body = ramflux_sdk::GatewayPushRouteRegistration {
            provider,
            token: "token".into(),
            endpoint: None,
            webpush_p256dh: None,
            webpush_auth: Some("auth".into()),
        };
        let frame = ramflux_sdk::GatewayClientFrame::PushRouteRegister {
            request: Box::new(ramflux_sdk::GatewayPushRouteFrame {
                signed_request: signed_request(ramflux_node_core::PUSH_ROUTE_PATH)?,
                body: body.clone(),
            }),
        };
        let node: ramflux_node_core::GatewayClientFrame =
            serde_json::from_slice(&serde_json::to_vec(&frame)?)?;
        let ramflux_node_core::GatewayClientFrame::PushRouteRegister { request } = node else {
            return Err("SDK registration did not parse as a node registration".into());
        };
        assert_eq!(
            ramflux_protocol::canonical_json_bytes(&request.body)?,
            ramflux_protocol::canonical_json_bytes(&body)?,
            "the gateway would recompute a different body hash"
        );
    }
    let deregister = ramflux_sdk::GatewayClientFrame::PushRouteDeregister {
        request: Box::new(ramflux_sdk::GatewayPushRouteDeregistrationFrame {
            signed_request: signed_request(ramflux_node_core::PUSH_ROUTE_DELETE_PATH)?,
            body: ramflux_sdk::GatewayPushRouteDeregistration::default(),
        }),
    };
    let node: ramflux_node_core::GatewayClientFrame =
        serde_json::from_slice(&serde_json::to_vec(&deregister)?)?;
    assert!(matches!(node, ramflux_node_core::GatewayClientFrame::PushRouteDeregister { .. }));
    for reply in [
        ramflux_node_core::GatewayServerFrame::PushRouteRegistered {
            expires_at: 9,
            request_id: Some("req-1".into()),
        },
        ramflux_node_core::GatewayServerFrame::PushRouteRefused {
            request_id: "req-1".into(),
            reason: "refused".into(),
        },
        ramflux_node_core::GatewayServerFrame::PushRouteDeregistered {
            request_id: "req-1".into(),
            removed: 1,
        },
    ] {
        let sdk: ramflux_sdk::GatewayServerFrame =
            serde_json::from_slice(&serde_json::to_vec(&reply)?)?;
        assert_eq!(serde_json::to_value(&sdk)?, serde_json::to_value(&reply)?);
    }
    Ok(())
}
