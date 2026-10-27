// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Root-bound identity registration fixtures shared by realnet slices.

#![allow(unused_imports)]
use crate::*;

#[cfg(all(test, feature = "realnet"))]
#[derive(Clone, Copy)]
pub(crate) struct RootedDeviceSetSpec<'a> {
    pub(crate) members: &'a [&'a ramflux_crypto::DeviceBranch],
    pub(crate) epoch: u64,
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) struct RootedRegistrationSpec<'a> {
    pub(crate) root: &'a ramflux_crypto::IdentityRoot,
    pub(crate) device: &'a ramflux_crypto::DeviceBranch,
    pub(crate) device_set: RootedDeviceSetSpec<'a>,
    pub(crate) target_delivery_id: &'a str,
    pub(crate) gateway_id: &'a str,
    pub(crate) session_id: &'a str,
    pub(crate) push_alias_hash: Option<&'a str>,
    pub(crate) source_ip_hash: Option<&'a str>,
    pub(crate) principal_kind: ramflux_protocol::PrincipalKind,
    pub(crate) proof_issued_at: i64,
    pub(crate) proof_expires_at: i64,
    pub(crate) now: i64,
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn rooted_identity_register_request(
    spec: &RootedRegistrationSpec<'_>,
) -> Result<ramflux_node_core::IdentityRegisterRequest, Box<dyn std::error::Error>> {
    let agreement = agreement_key(spec.device);
    let mut proof = ramflux_crypto::authorize_device_branch_v2(
        spec.root,
        spec.device,
        ramflux_crypto::BranchAuthorization {
            audience: ramflux_node_core::IDENTITY_BIND_AUDIENCE,
            capability_scope: vec![ramflux_node_core::IDENTITY_BIND_CAPABILITY.into()],
            issued_at: spec.proof_issued_at,
            expires_at: spec.proof_expires_at,
            principal_kind: spec.principal_kind,
            agreement_identity_public_key: agreement.public,
        },
    )?;
    proof.proof_id = ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?);
    proof.signature = ramflux_crypto::sign_canonical_bytes_with_seed(
        &ramflux_crypto::branch_proof_signing_bytes(&proof)?,
        spec.root.signing_key.to_bytes(),
    );
    let devices = spec
        .device_set
        .members
        .iter()
        .map(|member| rooted_device_set_entry(member))
        .collect::<Result<Vec<_>, _>>()?;
    let device_set = ramflux_crypto::sign_device_set(
        spec.root,
        ramflux_crypto::DeviceSetSigningInput {
            principal_kind: spec.principal_kind,
            device_set_epoch: spec.device_set.epoch,
            devices,
        },
    )?;
    let root_public_key =
        ramflux_protocol::encode_base64url(spec.root.signing_key.verifying_key().to_bytes());
    Ok(ramflux_node_core::IdentityRegisterRequest {
        device_set: Some(device_set),
        principal_commitment: ramflux_crypto::identity_root_commitment(
            &spec.root.signing_key.verifying_key(),
        ),
        root_public_key,
        branch_public_key: ramflux_protocol::encode_base64url(
            spec.device.signing_key.verifying_key().to_bytes(),
        ),
        proof,
        target_delivery_id: spec.target_delivery_id.to_owned(),
        gateway_id: spec.gateway_id.to_owned(),
        session_id: spec.session_id.to_owned(),
        push_alias_hash: spec.push_alias_hash.map(str::to_owned),
        now: spec.now,
        registration_pow: None,
        source_ip_hash: spec.source_ip_hash.map(str::to_owned),
    })
}

#[cfg(all(test, feature = "realnet"))]
fn agreement_key(device: &ramflux_crypto::DeviceBranch) -> ramflux_crypto::X25519KeyPair {
    ramflux_crypto::X25519KeyPair::from_seed(device.signing_key.to_bytes())
}

#[cfg(all(test, feature = "realnet"))]
fn rooted_device_set_entry(
    device: &ramflux_crypto::DeviceBranch,
) -> Result<ramflux_protocol::SignedDeviceSetEntry, Box<dyn std::error::Error>> {
    let agreement = agreement_key(device);
    let keys = ramflux_crypto::device_key_commitments(
        &ramflux_protocol::encode_base64url(device.signing_key.verifying_key().to_bytes()),
        &ramflux_protocol::encode_base64url(agreement.public),
    )?;
    Ok(ramflux_protocol::SignedDeviceSetEntry {
        device_id: device.device_id.clone(),
        device_epoch: device.device_epoch,
        signing_key_commitment: keys.0,
        agreement_key_commitment: keys.1,
        status: ramflux_protocol::DeviceSetStatus::Active,
        revoked_at: None,
    })
}

#[cfg(all(test, feature = "realnet"))]
mod tests {
    use super::*;

    #[test]
    fn rooted_registration_admits_initial_and_cumulative_device_sets()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = ramflux_crypto::create_identity_root("rooted-fixture", [0x11; 32]);
        let first =
            ramflux_crypto::create_device_branch("rooted-fixture", "rooted-first", 1, [0x12; 32]);
        let second =
            ramflux_crypto::create_device_branch("rooted-fixture", "rooted-second", 1, [0x13; 32]);
        let now = itest_now_unix_seconds();
        let first_request = request(&root, &first, &[&first], 1, now)?;
        let repeated_request = request(&root, &first, &[&first], 1, now)?;
        let second_request = request(&root, &second, &[&first, &second], 2, now)?;
        let router = ramflux_node_core::RouterCore::new();

        assert_ne!(first_request.proof.proof_id, repeated_request.proof.proof_id);
        router.mvp1_register_identity(&first_request)?;
        router.mvp1_register_identity(&second_request)?;

        assert_eq!(
            router
                .signed_device_set(&first_request.principal_commitment)
                .map(|record| (record.device_set_epoch, record.devices.len())),
            Some((2, 2))
        );
        Ok(())
    }

    fn request<'a>(
        root: &'a ramflux_crypto::IdentityRoot,
        device: &'a ramflux_crypto::DeviceBranch,
        members: &'a [&'a ramflux_crypto::DeviceBranch],
        epoch: u64,
        now: i64,
    ) -> Result<ramflux_node_core::IdentityRegisterRequest, Box<dyn std::error::Error>> {
        rooted_identity_register_request(&RootedRegistrationSpec {
            root,
            device,
            device_set: RootedDeviceSetSpec { members, epoch },
            target_delivery_id: device.device_id.as_str(),
            gateway_id: "ramflux-gateway",
            session_id: device.device_id.as_str(),
            push_alias_hash: None,
            source_ip_hash: None,
            principal_kind: ramflux_protocol::PrincipalKind::Human,
            proof_issued_at: now.saturating_sub(10),
            proof_expires_at: now.saturating_add(100),
            now,
        })
    }
}
