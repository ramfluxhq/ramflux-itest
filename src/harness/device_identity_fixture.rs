// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Deterministic native certificate chains for local group state fixtures.

pub(crate) fn fixture_device(
    name: &str,
) -> Result<ramflux_crypto::RootQualifiedDeviceRef, ramflux_crypto::CryptoError> {
    use ramflux_crypto::custody::{GenesisInput, MasterKey, RecoveryPhrase, SelfSigningKey};
    let seed = |domain| ramflux_crypto::blake3_256(domain, name.as_bytes());
    // Distinct deterministic fixture domains replace the historical legacy root signer.
    let phrase = RecoveryPhrase::from_entropy(&seed("ramflux.itest.native.entropy.v1"))?;
    let master = MasterKey::from_phrase(&phrase)?;
    let primary = SelfSigningKey::from_vault_seed(&zeroize::Zeroizing::new(seed(
        "ramflux.itest.native.primary.v1",
    )));
    let branch =
        ramflux_crypto::create_device_branch(name, name, 1, seed("ramflux.itest.native.branch.v1"));
    let agreement =
        ramflux_crypto::X25519KeyPair::from_seed(seed("ramflux.itest.native.agreement.v1"));
    let record = ramflux_crypto::custody::create_genesis(
        &master,
        &primary,
        &branch,
        &agreement,
        GenesisInput {
            principal_kind: ramflux_protocol::PrincipalKind::Human,
            display_name: "Fixture User".into(),
            issued_at: 100,
            master_cert_id: ramflux_protocol::encode_base64url(seed(
                "ramflux.itest.native.master-cert.v1",
            )),
            branch_cert_id: ramflux_protocol::encode_base64url(seed(
                "ramflux.itest.native.branch-cert.v1",
            )),
            external_human_primary: None,
        },
    )?;
    let verified = ramflux_crypto::custody::verify_record(&record, 100, None, None)?;
    ramflux_crypto::RootQualifiedDeviceRef::from_custody_record(&verified, name)
}

pub(crate) fn bind_fixture_member(
    db: &ramflux_storage::AccountDb,
    group: &str,
    name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let device = fixture_device(name)?;
    db.persist_group_member_device_key(group, &device, "owned-fixture-key")?;
    Ok(())
}
