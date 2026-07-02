// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use super::*;

#[cfg(feature = "realnet")]
#[test]
fn mvp9_realnet_message_features_disappearing_reply_mention_forward_projection()
-> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    let realnet = start_realnet_compose()?;
    let gateway_url = &realnet.gateway_url;
    let fixture = mvp1_dm_realnet_fixture()?;
    register_mvp1_identity(gateway_url, &fixture.bob_register)?;
    publish_mvp1_prekey(gateway_url, "bob_device_realnet", &fixture.bob_prekey_bundle)?;
    register_mvp1_identity(gateway_url, &fixture.alice_register)?;
    let fetched: ramflux_node_core::PrekeyResponse = ramflux_node_core::itest_http_get_json(
        &format!("{gateway_url}/mvp1/prekey/bob_device_realnet"),
    )?;
    let bob_bundle = fetched.bundle.ok_or("missing bob prekey bundle")?;
    let (mut alice_session, mut bob_session) = establish_mvp1_dm_sessions(&fixture, &bob_bundle)?;
    let clients = setup_mvp9_local_clients()?;

    mvp9_assert_disappearing_tombstone_delivery(
        gateway_url,
        &clients,
        &mut alice_session,
        &mut bob_session,
    )?;
    mvp9_assert_reply_mention_forward_projection(
        gateway_url,
        &clients,
        &mut alice_session,
        &mut bob_session,
    )?;
    Ok(())
}

#[cfg(feature = "realnet")]
#[test]
fn mvp9_realnet_transient_typing_presence_delivered_receipt()
-> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    let realnet = start_realnet_compose()?;
    let gateway_url = &realnet.gateway_url;
    let fixture = mvp1_dm_realnet_fixture()?;
    register_mvp1_identity(gateway_url, &fixture.bob_register)?;
    publish_mvp1_prekey(gateway_url, "bob_device_realnet", &fixture.bob_prekey_bundle)?;
    register_mvp1_identity(gateway_url, &fixture.alice_register)?;
    let fetched: ramflux_node_core::PrekeyResponse = ramflux_node_core::itest_http_get_json(
        &format!("{gateway_url}/mvp1/prekey/bob_device_realnet"),
    )?;
    let bob_bundle = fetched.bundle.ok_or("missing bob prekey bundle")?;
    let (mut alice_session, mut bob_session) = establish_mvp1_dm_sessions(&fixture, &bob_bundle)?;
    let clients = setup_mvp9_local_clients()?;

    mvp9_assert_delivered_receipt_ttl(gateway_url, &clients, &mut alice_session, &mut bob_session)?;
    mvp9_assert_typing_ttl_and_volatility(
        gateway_url,
        &clients,
        &mut alice_session,
        &mut bob_session,
    )?;
    mvp9_assert_contact_presence_privacy(
        gateway_url,
        &clients,
        &mut alice_session,
        &mut bob_session,
    )?;
    Ok(())
}
