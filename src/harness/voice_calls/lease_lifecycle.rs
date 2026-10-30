// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Reproduce the relay boundary when terminal signaling races a peer's lease refresh.
use ramflux_node_core::{NodeCoreError, VoiceRelayState};
use ramflux_protocol::{CallEndpoint, VoiceAllocationRequest, VoiceLeaseConsent};

#[test]
fn released_voice_lease_refuses_a_concurrent_callee_refresh()
-> Result<(), Box<dyn std::error::Error>> {
    let endpoint = |principal: &str, device: &str, seed| CallEndpoint {
        principal_id: principal.into(),
        root_public_key: ramflux_crypto::public_key_base64url_from_seed([seed; 32]),
        device_id: device.into(),
    };
    let scope = VoiceAllocationRequest {
        call_id: ramflux_protocol::encode_base64url([1; 16]),
        caller: endpoint("caller", "caller-device", 2),
        callee: endpoint("callee", "callee-device", 3),
    };
    let mut relay = VoiceRelayState::default();
    let own = relay.allocate("node", &scope, "relay:19001", 100)?;
    let mut consent = VoiceLeaseConsent {
        scope: scope.clone(),
        lease_id: own.lease_id.clone(),
        expires_at: own.hard_expires_at,
        signature: String::new(),
    };
    consent.signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &ramflux_protocol::voice_lease_consent_bytes(&consent)?,
        [3; 32],
    );
    let initial = relay.accept_verified("node", &consent, "relay:19001", 101)?;
    let refreshed_expiry = relay.renew_consented("node", &consent, 120)?;
    assert!(refreshed_expiry > initial.expires_at);
    // The SDK releases before delivering its pending Hangup. The peer can still be processing
    // the preceding renewed offer, even though its existing media lease has not expired.
    relay.release("node", &scope)?;
    assert!(121 < initial.expires_at);
    let refused = relay.accept_verified("node", &consent, "relay:19001", 121);
    assert!(
        matches!(&refused, Err(NodeCoreError::Unauthorized(reason))
            if reason == "voice lease unavailable"),
        "released lease must refuse the still-unexpired peer refresh as voice lease unavailable"
    );
    eprintln!(
        "STEP: voice lease race reproduced: allocate -> accept -> renew -> release -> peer accept = Unauthorized(voice lease unavailable), before original expiry"
    );
    Ok(())
}
