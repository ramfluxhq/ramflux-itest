// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Isolated SDK owner configuration for the s35 history-export client process.
use std::{net::SocketAddr, path::Path};
pub(super) const OWNER_HOME_NODE: &str = "node_b.realnet";
pub(super) fn child_command(
    executable: &Path,
    gateway: SocketAddr,
    ca: &Path,
    relay: &str,
) -> tokio::process::Command {
    let mut command = tokio::process::Command::new(executable);
    command
        .args([
            "--exact",
            "tests::mvp_s35_multi_device::mvp_s35_realnet_multi_device_activation_fanout",
            "--nocapture",
        ])
        .env("RAMFLUX_S35_CLIENT_ENV_READY", "1")
        .env("RAMFLUX_S35_GATEWAY_QUIC_ADDR", gateway.to_string())
        .env("RAMFLUX_S35_CA_CERT", ca)
        .env("RAMFLUX_S35_RELAY_HTTP_URL", relay)
        .env("RAMFLUX_SDK_RELAY_OWNER_HOME_NODE_ID", OWNER_HOME_NODE)
        // History export belongs to Bob; ordinary Alice DMs do not allocate relay objects.
        .env("RAMFLUX_SDK_RELAY_OWNER_PRINCIPAL_ID", "principal_s35_bob")
        .env_remove("RAMFLUX_SDK_OBJECT_RELAY_LOCAL_MINT")
        .env_remove("RAMFLUX_SDK_OBJECT_RELAY_SERVICE_KEY_BASE64")
        .env("RAMFLUX_SDK_RELAY_AUDIENCE_NODE_ID", "node_a.realnet")
        .env("RAMFLUX_SDK_RELAY_QUIC_ADDR", "127.0.0.1:63365")
        .env("RAMFLUX_SDK_RELAY_QUIC_SERVER_NAME", "ramflux-relay")
        .env("RAMFLUX_SDK_RELAY_QUIC_CA_CERT", ca);
    command
}

pub(super) fn run_client() -> Result<(), Box<dyn std::error::Error>> {
    let gateway = std::env::var("RAMFLUX_S35_GATEWAY_QUIC_ADDR")?.parse()?;
    let ca =
        std::path::PathBuf::from(std::env::var_os("RAMFLUX_S35_CA_CERT").ok_or("s35 CA missing")?);
    let relay = std::env::var("RAMFLUX_S35_RELAY_HTTP_URL")?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(super::mvp_s35_assert_multi_device_activation(gateway, &ca, &relay))
}

#[test]
fn s35_history_sync_child_has_explicit_owner_authority_and_its_own_relay_endpoint()
-> Result<(), Box<dyn std::error::Error>> {
    use std::collections::BTreeMap;
    let command = child_command(
        Path::new("test-binary"),
        "127.0.0.1:63361".parse()?,
        Path::new("fixture.pem"),
        "http://127.0.0.1:63354",
    );
    let env = command
        .as_std()
        .get_envs()
        .map(|(k, v)| {
            (k.to_string_lossy().into_owned(), v.map(|v| v.to_string_lossy().into_owned()))
        })
        .collect::<BTreeMap<_, _>>();
    for (key, value) in [
        ("RAMFLUX_S35_CLIENT_ENV_READY", "1"),
        ("RAMFLUX_S35_GATEWAY_QUIC_ADDR", "127.0.0.1:63361"),
        ("RAMFLUX_S35_CA_CERT", "fixture.pem"),
        ("RAMFLUX_S35_RELAY_HTTP_URL", "http://127.0.0.1:63354"),
        ("RAMFLUX_SDK_RELAY_OWNER_HOME_NODE_ID", OWNER_HOME_NODE),
        ("RAMFLUX_SDK_RELAY_OWNER_PRINCIPAL_ID", "principal_s35_bob"),
        ("RAMFLUX_SDK_RELAY_AUDIENCE_NODE_ID", "node_a.realnet"),
        ("RAMFLUX_SDK_RELAY_QUIC_ADDR", "127.0.0.1:63365"),
        ("RAMFLUX_SDK_RELAY_QUIC_CA_CERT", "fixture.pem"),
    ] {
        assert_eq!(env.get(key).and_then(Option::as_deref), Some(value), "{key}");
    }
    assert_eq!(env.get("RAMFLUX_SDK_OBJECT_RELAY_LOCAL_MINT"), Some(&None));
    assert_eq!(env.get("RAMFLUX_SDK_OBJECT_RELAY_SERVICE_KEY_BASE64"), Some(&None));
    Ok(())
}
