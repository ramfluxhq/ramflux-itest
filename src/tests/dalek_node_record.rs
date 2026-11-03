// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! A frozen integration-node signature shared with the product crypto vectors.
use ed25519_dalek::{Signature, SigningKey};
use ramflux_crypto::custody::{sign_node_identity_record, verify_node_identity_record};
use ramflux_protocol::custody::{Envelope, NodeIdentityRecord, signing_bytes};

#[test]
fn integration_signing_key_matches_product_api_and_frozen_node_signature()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../../fixtures/dalek_node_record.json"))?;
    let expected: Envelope<NodeIdentityRecord> = serde_json::from_value(fixture["record"].clone())?;
    let key = SigningKey::from_bytes(&[7; 32]);
    let actual = sign_node_identity_record(&key, expected.body.clone())?;
    assert_eq!(actual.signature, expected.signature);
    assert_eq!(
        ramflux_protocol::canonical_json_bytes(&actual)?,
        ramflux_protocol::canonical_json_bytes(&expected)?
    );
    verify_node_identity_record(
        &actual,
        "fixture.example",
        &expected.body.node_signing_public_key,
        1_700_000_000,
    )?;
    let signature = Signature::from_slice(&ramflux_protocol::decode_base64url(&actual.signature)?)?;
    key.verifying_key().verify_strict(
        &signing_bytes(ramflux_protocol::domain::CUSTODY_NODE_RECORD, &actual.body)?,
        &signature,
    )?;
    Ok(())
}
