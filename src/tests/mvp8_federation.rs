// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use super::*;

#[cfg(feature = "realnet")]
#[test]
fn mvp8_realnet_federation_trust_invitation_capability_suspend()
-> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    let realnet = start_realnet_compose()?;
    let federation_url = std::env::var("RAMFLUX_ITEST_FEDERATION_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:18082".to_owned());
    wait_for_federation(&federation_url)?;
    mvp8_assert_invitation_capability_and_suspend(&federation_url)?;
    drop(realnet);
    Ok(())
}

#[cfg(feature = "realnet")]
#[test]
fn mvp8_realnet_cross_node_friend_request_acceptance() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    let realnet = start_realnet_compose()?;
    let gateway_url = &realnet.gateway_url;
    let federation_url = std::env::var("RAMFLUX_ITEST_FEDERATION_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:18082".to_owned());
    wait_for_federation(&federation_url)?;

    let fixture = mvp1_dm_realnet_fixture()?;
    register_mvp1_identity(gateway_url, &fixture.bob_register)?;
    publish_mvp1_prekey(gateway_url, "bob_device_realnet", &fixture.bob_prekey_bundle)?;
    register_mvp1_identity(gateway_url, &fixture.alice_register)?;
    let fetched: ramflux_node_core::ItestMvp1PrekeyResponse =
        ramflux_node_core::itest_http_get_json(&format!(
            "{gateway_url}/mvp1/prekey/bob_device_realnet"
        ))?;
    let bob_bundle = fetched.bundle.ok_or("missing bob prekey bundle")?;
    let (mut alice_session, mut bob_session) = establish_mvp1_dm_sessions(&fixture, &bob_bundle)?;
    let clients = setup_mvp2_local_clients()?;

    mvp8_admit_friend_node(&federation_url, "node_b.realnet", "mvp8_friend_b")?;
    mvp8_admit_friend_node(&federation_url, "node_a.realnet", "mvp8_friend_a")?;
    mvp8_assert_cross_node_friend_accepts(
        gateway_url,
        &federation_url,
        &clients,
        &mut alice_session,
        &mut bob_session,
    )?;
    mvp8_assert_cross_node_friend_rejections(&federation_url)?;
    Ok(())
}
