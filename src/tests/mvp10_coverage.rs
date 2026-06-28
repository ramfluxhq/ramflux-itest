// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use super::*;

#[cfg(feature = "realnet")]
#[test]
fn mvp10_realnet_group_governance_roles_member_limit_delete_projection()
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
    let fetched: ramflux_node_core::ItestMvp1PrekeyResponse =
        ramflux_node_core::itest_http_get_json(&format!(
            "{gateway_url}/mvp1/prekey/bob_device_realnet"
        ))?;
    let bob_bundle = fetched.bundle.ok_or("missing bob prekey bundle")?;
    let (mut alice_session, mut bob_session) = establish_mvp1_dm_sessions(&fixture, &bob_bundle)?;
    let clients = setup_mvp9_local_clients()?;

    mvp10_assert_group_roles_and_member_removed(&clients)?;
    mvp10_assert_group_member_limit()?;
    mvp10_assert_group_delete_tombstone_realnet(
        gateway_url,
        &clients,
        &mut alice_session,
        &mut bob_session,
    )?;
    Ok(())
}

#[cfg(feature = "realnet")]
#[test]
fn mvp10_realnet_mvp3_gaps_wake_delegation_revoke_stun() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    let realnet = start_realnet_compose()?;
    let gateway_url = &realnet.gateway_url;
    let notify_url = &realnet.notify_url;
    mvp10_assert_call_and_conference_wake_delivery(notify_url)?;
    mvp10_assert_full_delegation_revoke(gateway_url)?;
    mvp10_assert_stun_binding_realnet()?;
    Ok(())
}

#[cfg(feature = "realnet")]
#[test]
fn mvp10_realnet_own_devices_sync_fanout_cursor_revoke() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    let realnet = start_realnet_compose()?;
    mvp10_assert_own_devices_sync(&realnet.gateway_url)?;
    Ok(())
}

#[cfg(feature = "realnet")]
#[test]
fn mvp10_realnet_three_backend_real_delivery_signed_envelope()
-> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    let _realnet = start_realnet_compose()?;
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    runtime.block_on(mvp10_assert_three_backend_real_delivery(&code_root()))?;
    Ok(())
}

#[cfg(feature = "realnet")]
#[test]
fn mvp10_realnet_quic_lan_object_sync_chunk_resume() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    let _realnet = start_realnet_compose()?;
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    runtime.block_on(mvp10_assert_quic_lan_object_sync(&code_root()))?;
    Ok(())
}
