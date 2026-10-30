// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Native realnet users are created through the ordinary exclusive local ceremony.
#![cfg(all(test, feature = "realnet"))]
use ramflux_sdk::{LocalBusClient, LocalBusCreationClient, LocalBusRecoveryClient};
use std::path::Path;
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// Public daemon-allocated identity plus the simulated user's independently retained phrase.
/// Deliberately has no Debug or serialization implementation.
pub(crate) struct NativeAccount {
    pub account_id: String,
    pub principal_id: String,
    pub device_id: String,
    pub delivery_id: String,
    pub anchor: String,
    pub display_name: String,
    phrase: Zeroizing<String>,
}

pub(crate) const NATIVE_DATA_PASSPHRASE: &str = "native realnet local data passphrase";
pub(crate) const NATIVE_RESTORED_PASSPHRASE: &str = "independent replacement local data password";

pub(crate) fn native_node_profile(
    node: &super::S8RealnetNode,
    relay: &str,
) -> Result<ramflux_sdk::NodeProfile> {
    let now = ramflux_node_core::now_unix_seconds();
    Ok(ramflux_sdk::NodeProfile {
        discovery_url: String::new(),
        node_id: node.node_id.clone(),
        node_public_key: node.federation_node_public_key.clone(),
        pin_source: ramflux_sdk::NodePinSource::Builtin,
        ca_cert_pem: std::fs::read_to_string(&node.ca_cert)?,
        gateway: ramflux_sdk::NodeGateway {
            quic_addr: node.gateway_quic_addr.to_string(),
            tcp_addr: node.gateway_quic_addr.to_string(),
            server_name: "ramflux-gateway".into(),
        },
        relay: ramflux_sdk::NodeRelay {
            quic_addr: relay.into(),
            server_name: "ramflux-relay".into(),
        },
        prekey_http_url: node.federation_url.clone(),
        signaling_turn_addr: String::new(),
        protocol_versions: vec!["custody_v3".into()],
        client_capabilities: Vec::new(),
        discovered_at: now,
        expires_at: now + 3600,
        enabled: true,
        builtin: true,
        safety_warnings: std::collections::BTreeSet::new(),
    })
}

pub(crate) async fn select_native_node(bus: &mut LocalBusClient, node: &str) -> Result<()> {
    bus.request(None, "node", "node.set_default", serde_json::json!({"node_id":node})).await?;
    Ok(())
}

pub(crate) async fn create_native_account(
    socket: &Path,
    display_name: &str,
) -> Result<NativeAccount> {
    let mut ceremony = LocalBusCreationClient::connect(socket).await?;
    ceremony.begin(display_name, ramflux_protocol::PrincipalKind::Human).await?;
    // This buffer represents the test user's saved recovery artifact, never daemon state.
    let phrase = ceremony.show_once().await?;
    let positions = ceremony.hidden_challenge().await?;
    let saved_words: Vec<_> = phrase.split_whitespace().collect();
    let words = std::array::from_fn(|index| {
        Zeroizing::new(saved_words[usize::from(positions[index] - 1)].to_owned())
    });
    let account =
        ceremony.confirm(&words, &Zeroizing::new(NATIVE_DATA_PASSPHRASE.to_owned())).await?;
    drop(ceremony);
    let status = wait_native_account_live(socket, &account.account_id).await?;
    eprintln!(
        "STEP: native creation confirmed account={} networking={:?}",
        account.account_id, status["networking"]
    );
    let field = |name: &str| -> Result<String> {
        Ok(status[name].as_str().ok_or("native account status field missing")?.to_owned())
    };
    Ok(NativeAccount {
        account_id: account.account_id,
        principal_id: field("principal_id")?,
        device_id: field("device_id")?,
        delivery_id: field("target_delivery_id")?,
        anchor: field("principal_commitment")?,
        display_name: display_name.to_owned(),
        phrase,
    })
}

/// Create a native externally-custodied participant and export its one-use local data credential.
pub(crate) async fn create_native_agent_account(
    socket: &Path,
    display_name: &str,
    owner: &NativeAccount,
    bundle_path: &Path,
) -> Result<NativeAccount> {
    let mut ceremony = LocalBusCreationClient::connect(socket).await?;
    ceremony.begin_headless(display_name, &owner.account_id).await?;
    let phrase = ceremony.show_once().await?;
    let positions = ceremony.hidden_challenge().await?;
    let saved_words: Vec<_> = phrase.split_whitespace().collect();
    let words = std::array::from_fn(|index| {
        Zeroizing::new(saved_words[usize::from(positions[index] - 1)].to_owned())
    });
    let account = ceremony.confirm_headless(&words).await?;
    drop(ceremony);
    let status = wait_native_account_live(socket, &account.account_id).await?;
    let mut bus = LocalBusClient::connect(socket).await?;
    bus.request(
        Some(owner.account_id.clone()),
        "stream",
        "subscription.open",
        serde_json::json!({"topics":[],"attended_frontend":true}),
    )
    .await?;
    bus.request(
        Some(owner.account_id.clone()),
        "account",
        "account.export_agent_credentials",
        serde_json::json!({"account":account.account_id,"path":bundle_path}),
    )
    .await?;
    let field = |name: &str| -> Result<String> {
        Ok(status[name].as_str().ok_or("native agent status field missing")?.to_owned())
    };
    assert_eq!(status["display_name"], display_name);
    Ok(NativeAccount {
        account_id: account.account_id,
        principal_id: field("principal_id")?,
        device_id: field("device_id")?,
        delivery_id: field("target_delivery_id")?,
        anchor: field("principal_commitment")?,
        display_name: display_name.to_owned(),
        phrase,
    })
}

async fn wait_native_account_live(socket: &Path, account_id: &str) -> Result<serde_json::Value> {
    let mut bus = LocalBusClient::connect(socket).await?;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        let status = bus
            .request(
                Some(account_id.to_owned()),
                "account",
                "account.status",
                serde_json::json!({}),
            )
            .await?;
        if status["networking"] == "live" {
            assert!(status["networking_reason"].is_null());
            return Ok(status);
        }
        if tokio::time::Instant::now() >= deadline {
            return Err("native account networking did not become live".into());
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
}

pub(crate) async fn recover_native_account(
    socket: &Path,
    account_id: &str,
    owner: &NativeAccount,
    passphrase: &str,
) -> Result<ramflux_sdk::LocalBusCreatedAccount> {
    let mut ceremony = LocalBusRecoveryClient::connect(socket).await?;
    let pending = ceremony.begin(account_id).await?;
    assert_eq!(pending.account_anchor, owner.anchor);
    let account = ceremony
        .confirm(&owner.phrase, &Zeroizing::new(passphrase.to_owned()), &owner.anchor)
        .await?;
    eprintln!(
        "STEP: native recovery confirmed account={} networking={:?}",
        account.account_id, account.networking
    );
    Ok(account)
}
