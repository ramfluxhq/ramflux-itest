// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Owned-root identities for local group state fixtures.

pub(crate) fn fixture_device(
    name: &str,
) -> Result<ramflux_crypto::RootQualifiedDeviceRef, ramflux_crypto::CryptoError> {
    let seed = ramflux_crypto::blake3_256("ramflux.itest.device.root.v1", name.as_bytes());
    let root = ramflux_crypto::create_identity_root(name, seed);
    ramflux_crypto::RootQualifiedDeviceRef::for_owned_account_device(&root, name)
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
