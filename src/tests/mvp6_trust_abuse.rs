// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use super::*;

#[cfg(feature = "realnet")]
#[test]
fn mvp6_realnet_key_verification_safety_number_change_warning()
-> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    let realnet = start_realnet_compose()?;
    let gateway_url = &realnet.gateway_url;
    let alice_root = ramflux_crypto::create_identity_root("alice_mvp6_realnet", [0x91; 32]);
    let alice_device = ramflux_crypto::create_device_branch(
        "alice_mvp6_realnet",
        "alice_device_mvp6_realnet",
        1,
        [0x92; 32],
    );
    let bob_root = ramflux_crypto::create_identity_root("bob_mvp6_realnet", [0x93; 32]);
    let bob_device_v1 = ramflux_crypto::create_device_branch(
        "bob_mvp6_realnet",
        "bob_device_mvp6_realnet",
        1,
        [0x94; 32],
    );
    let bob_device_v2 = ramflux_crypto::create_device_branch(
        "bob_mvp6_realnet",
        "bob_device_mvp6_realnet_tablet",
        2,
        [0x95; 32],
    );

    let alice_register = mvp1_named_register_request(
        &alice_root,
        &alice_device,
        "alice_target_mvp6_realnet",
        "alice_session_mvp6_realnet",
        61,
    )?;
    let bob_register = mvp1_named_register_request(
        &bob_root,
        &bob_device_v1,
        "bob_target_mvp6_realnet",
        "bob_session_mvp6_realnet",
        62,
    )?;
    register_mvp1_identity(gateway_url, &alice_register)?;
    register_mvp1_identity(gateway_url, &bob_register)?;

    let alice_material = mvp6_contact_safety_material(
        &alice_root,
        std::slice::from_ref(&alice_device),
        "alice_head_v1",
    );
    let bob_material_v1 = mvp6_contact_safety_material(
        &bob_root,
        std::slice::from_ref(&bob_device_v1),
        "bob_head_v1",
    );
    let alice_bob_number = ramflux_crypto::safety_number(&alice_material, &bob_material_v1);
    let bob_alice_number = ramflux_crypto::safety_number(&bob_material_v1, &alice_material);
    assert_eq!(alice_bob_number, bob_alice_number);
    assert_eq!(alice_bob_number.len(), 12);
    assert!(alice_bob_number.iter().all(|group| group.len() == 5));

    let (alice_db, bob_identity_commitment) = mvp6_mark_realnet_contacts_verified(
        "mvp6_realnet_key_verification_safety_number_change_warning",
        &alice_material,
        &bob_material_v1,
    )?;

    let bob_register_v2 = mvp1_named_register_request(
        &bob_root,
        &bob_device_v2,
        "bob_target_mvp6_realnet_tablet",
        "bob_session_mvp6_realnet_tablet",
        63,
    )?;
    register_mvp1_identity(gateway_url, &bob_register_v2)?;
    let bob_material_v2 = mvp6_contact_safety_material(
        &bob_root,
        &[bob_device_v1, bob_device_v2],
        "bob_head_v2_device_added",
    );
    let changed = alice_db.observe_contact_key_state(ramflux_storage::ContactKeyObservation {
        contact_identity_commitment: &bob_identity_commitment,
        safety_number_hash: &safety_hash_text(&ramflux_crypto::safety_fingerprint(
            &alice_material,
            &bob_material_v2,
        )),
        device_set_hash: &safety_hash_text(&ramflux_crypto::device_set_hash(
            &bob_material_v2.devices,
        )),
        lineage_head: &safety_hash_text(&bob_material_v2.lineage_head),
        change_event_id: "device.branch_authorized:bob_mvp6_realnet_tablet",
        seen_at: 1_760_000_100,
    })?;
    assert_eq!(changed.verification_state, "changed");
    assert_eq!(
        changed.last_change_event_id.as_deref(),
        Some("device.branch_authorized:bob_mvp6_realnet_tablet")
    );
    Ok(())
}

#[cfg(feature = "realnet")]
#[test]
fn mvp6_realnet_kt_inclusion_consistency_gossip_fallback() -> Result<(), Box<dyn std::error::Error>>
{
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    let realnet = start_realnet_compose()?;
    let gateway_url = &realnet.gateway_url;
    let alice_root = ramflux_crypto::create_identity_root("alice_mvp6_kt_realnet", [0xa1; 32]);
    let alice_device = ramflux_crypto::create_device_branch(
        "alice_mvp6_kt_realnet",
        "alice_device_mvp6_kt_realnet",
        1,
        [0xa2; 32],
    );
    let bob_root = ramflux_crypto::create_identity_root("bob_mvp6_kt_realnet", [0xa3; 32]);
    let bob_device = ramflux_crypto::create_device_branch(
        "bob_mvp6_kt_realnet",
        "bob_device_mvp6_kt_realnet",
        1,
        [0xa4; 32],
    );
    register_mvp1_identity(
        gateway_url,
        &mvp1_named_register_request(
            &alice_root,
            &alice_device,
            "alice_target_mvp6_kt_realnet",
            "alice_session_mvp6_kt_realnet",
            71,
        )?,
    )?;
    register_mvp1_identity(
        gateway_url,
        &mvp1_named_register_request(
            &bob_root,
            &bob_device,
            "bob_target_mvp6_kt_realnet",
            "bob_session_mvp6_kt_realnet",
            72,
        )?,
    )?;

    let alice_material = mvp6_contact_safety_material(
        &alice_root,
        std::slice::from_ref(&alice_device),
        "alice_kt_head_v1",
    );
    let bob_material = mvp6_contact_safety_material(
        &bob_root,
        std::slice::from_ref(&bob_device),
        "bob_kt_head_v1",
    );
    let (alice_db, bob_identity_commitment) = mvp6_mark_realnet_contacts_verified(
        "mvp6_realnet_kt_inclusion_consistency_gossip_fallback",
        &alice_material,
        &bob_material,
    )?;
    mvp6_verify_kt_and_gossip_paths(&alice_db, &bob_identity_commitment, &bob_material)?;
    Ok(())
}

#[cfg(feature = "realnet")]
#[test]
fn mvp6_realnet_registration_antisybil_pow_tier_budget() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    let realnet = start_realnet_compose()?;
    let gateway_url = &realnet.gateway_url;
    mvp6_set_registration_policy(
        gateway_url,
        &ramflux_node_core::ItestRegistrationPolicy {
            challenge_policy: ramflux_node_core::RegistrationChallengePolicy::Pow,
            pow_difficulty_bits: MVP6_REGISTRATION_POW_BITS,
            per_source_ip_registration_limit: 2,
            registration_window_seconds: 60,
        },
    )?;

    mvp6_assert_pow_registration_policy(gateway_url)?;
    mvp6_assert_friend_request_budget(
        gateway_url,
        "mvp6_challenged_alice",
        &ramflux_node_core::RegistrationTrustTier::Challenged,
        "friend_target",
        1_760_000_200,
    )?;

    mvp6_set_registration_policy(
        gateway_url,
        &ramflux_node_core::ItestRegistrationPolicy {
            challenge_policy: ramflux_node_core::RegistrationChallengePolicy::None,
            pow_difficulty_bits: 0,
            per_source_ip_registration_limit: 100,
            registration_window_seconds: 60,
        },
    )?;
    let newbie = mvp6_realnet_register_request("mvp6_new_budget", 86, None)?;
    let newbie_registered = register_mvp1_identity(gateway_url, &newbie)?;
    assert_eq!(
        newbie_registered.registration_trust_tier,
        ramflux_node_core::RegistrationTrustTier::New
    );
    mvp6_assert_friend_request_budget(
        gateway_url,
        "mvp6_new_budget",
        &ramflux_node_core::RegistrationTrustTier::New,
        "new_friend_target",
        1_760_000_300,
    )?;
    Ok(())
}

#[cfg(feature = "realnet")]
#[test]
fn mvp6_realnet_gateway_preauth_dos_cookie_slowloris() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    let realnet = start_realnet_compose()?;
    let gateway_url = &realnet.gateway_url;
    mvp6_set_preauth_policy(
        gateway_url,
        &ramflux_node_core::GatewayPreAuthPolicy {
            enabled: true,
            per_source_ip_handshake_rate: 1,
            window_seconds: 60,
            cookie_ttl_seconds: 2,
            auth_deadline_ms: 1_000,
            cookie_secret: ramflux_node_core::DEFAULT_PRE_AUTH_COOKIE_SECRET.to_owned(),
        },
    )?;

    let first = mvp6_preauth_probe(gateway_url, None, 1_760_000_000)?;
    assert_eq!(first.status, 200);
    let challenge = mvp6_preauth_probe(gateway_url, None, 1_760_000_001)?;
    assert_eq!(challenge.status, 401);
    let challenge_body: ramflux_node_core::GatewayPreAuthChallengeResponse =
        serde_json::from_slice(&challenge.body)?;
    assert!(!challenge_body.pre_auth_cookie.is_empty());

    let accepted =
        mvp6_preauth_probe(gateway_url, Some(&challenge_body.pre_auth_cookie), 1_760_000_002)?;
    assert_eq!(accepted.status, 200);
    let forged = mvp6_preauth_probe(gateway_url, Some("forged-cookie"), 1_760_000_003)?;
    assert!(!forged.status_is_success());
    let expired =
        mvp6_preauth_probe(gateway_url, Some(&challenge_body.pre_auth_cookie), 1_760_000_010)?;
    assert!(!expired.status_is_success());

    mvp6_assert_slowloris_closed(gateway_url)?;
    let metrics = mvp6_preauth_metrics(gateway_url)?;
    assert!(metrics.pre_auth_cookie_required >= 1);
    assert!(metrics.pre_auth_cookie_failed >= 2);
    assert!(metrics.deviceproof_rate_limited >= 1);
    assert!(metrics.slowloris_auth_timeout >= 1);
    Ok(())
}
