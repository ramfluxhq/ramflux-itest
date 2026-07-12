// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use crate::*;

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn realnet_step(label: impl AsRef<str>, fields: impl AsRef<str>) {
    eprintln!("STEP: {} {}", label.as_ref(), fields.as_ref());
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn wait_for_gateway(gateway_url: &str) -> Result<(), Box<dyn std::error::Error>> {
    for attempt in 0..60 {
        realnet_step(
            "waiting for gateway health",
            format!("attempt={attempt} url={gateway_url}/healthz"),
        );
        let health = ramflux_node_core::itest_http_get_json::<serde_json::Value>(&format!(
            "{gateway_url}/healthz"
        ));
        if health.is_ok() {
            realnet_step("gateway health ready", format!("url={gateway_url}/healthz"));
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    Err("gateway did not become ready".into())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn wait_for_federation(federation_url: &str) -> Result<(), Box<dyn std::error::Error>> {
    for attempt in 0..60 {
        realnet_step(
            "waiting for federation health",
            format!("attempt={attempt} url={federation_url}/healthz"),
        );
        let health = ramflux_node_core::itest_http_get_json::<serde_json::Value>(&format!(
            "{federation_url}/healthz"
        ));
        if health.is_ok() {
            realnet_step("federation health ready", format!("url={federation_url}/healthz"));
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    Err("federation did not become ready".into())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn wait_for_itest_service(
    service_url: &str,
    service_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    for attempt in 0..60 {
        realnet_step(
            "waiting for itest service health",
            format!("service={service_name} attempt={attempt} url={service_url}/healthz"),
        );
        let health = ramflux_node_core::itest_http_get_json::<serde_json::Value>(&format!(
            "{service_url}/healthz"
        ));
        if health.is_ok() {
            realnet_step(
                "itest service health ready",
                format!("service={service_name} url={service_url}/healthz"),
            );
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    Err(format!("{service_name} did not become ready").into())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn start_realnet_compose() -> Result<RealnetCompose, Box<dyn std::error::Error>> {
    start_realnet_compose_with_env(&[])
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn start_realnet_compose_with_env(
    env: &[(String, String)],
) -> Result<RealnetCompose, Box<dyn std::error::Error>> {
    start_realnet_compose_with_env_and_overrides(env, false, false, false)
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn start_realnet_compose_with_env_and_gateway_compio(
    env: &[(String, String)],
    gateway_compio: bool,
) -> Result<RealnetCompose, Box<dyn std::error::Error>> {
    start_realnet_compose_with_env_and_overrides(env, gateway_compio, false, false)
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn start_realnet_compose_with_env_and_notify_compio(
    env: &[(String, String)],
    notify_compio: bool,
) -> Result<RealnetCompose, Box<dyn std::error::Error>> {
    start_realnet_compose_with_env_and_overrides(env, false, notify_compio, false)
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn start_realnet_compose_with_env_and_notify_overrides(
    env: &[(String, String)],
    notify_compio: bool,
    notify_tokio_concurrent: bool,
) -> Result<RealnetCompose, Box<dyn std::error::Error>> {
    start_realnet_compose_with_env_and_overrides(env, false, notify_compio, notify_tokio_concurrent)
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn start_realnet_compose_with_env_and_overrides(
    env: &[(String, String)],
    gateway_compio: bool,
    notify_compio: bool,
    notify_tokio_concurrent: bool,
) -> Result<RealnetCompose, Box<dyn std::error::Error>> {
    let code_root = code_root();
    let deploy_root = code_root.join("ramflux/deploy");
    run_deploy_script(&code_root, "ramflux/deploy/scripts/bootstrap-itest.sh")?;
    let mut compose_env = env.to_vec();
    if !compose_env.iter().any(|(key, _value)| key == "RAMFLUX_FEDERATION_NODE_SIGNING_SEED_B64URL")
    {
        compose_env.push((
            "RAMFLUX_FEDERATION_NODE_SIGNING_SEED_B64URL".to_owned(),
            ramflux_protocol::encode_base64url([
                1_u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
            ]),
        ));
    }
    ensure_itest_node_service_signing_seed_env(&mut compose_env);
    run_docker_compose_with_env_and_overrides(
        &deploy_root,
        &compose_env,
        &["up", "--build", "-d"],
        gateway_compio,
        notify_compio,
        notify_tokio_concurrent,
    )?;
    let guard = ComposeDownGuard::new_with_overrides(
        deploy_root,
        gateway_compio,
        notify_compio,
        notify_tokio_concurrent,
    );
    let gateway_url = std::env::var("RAMFLUX_ITEST_GATEWAY_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:18081".to_owned());
    let notify_url = std::env::var("RAMFLUX_ITEST_NOTIFY_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:18083".to_owned());
    let relay_url = std::env::var("RAMFLUX_ITEST_RELAY_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:18084".to_owned());
    let retention_url = std::env::var("RAMFLUX_ITEST_RETENTION_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:18087".to_owned());
    wait_for_gateway(&gateway_url)?;
    wait_for_itest_service(&notify_url, "notify")?;
    wait_for_itest_service(&relay_url, "relay")?;
    wait_for_itest_service(&retention_url, "retention")?;
    Ok(RealnetCompose { gateway_url, notify_url, relay_url, retention_url, _guard: guard })
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn wait_for_private_gateway_quic(
    gateway_quic_addr: std::net::SocketAddr,
    ca_cert: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = tokio::time::Instant::now() + Duration::from_mins(1);
    loop {
        match ramflux_transport::QuicGatewayClient::connect(
            "0.0.0.0:0".parse()?,
            gateway_quic_addr,
            "localhost",
            ca_cert,
            Duration::from_secs(2),
        )
        .await
        {
            Ok(_client) => return Ok(()),
            Err(error) if tokio::time::Instant::now() < deadline => {
                tracing::debug!(%error, "waiting for private gateway QUIC");
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(error) => {
                return Err(format!("private gateway QUIC did not become ready: {error}").into());
            }
        }
    }
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s10_rf_json(
    binary: &Path,
    args: &[&str],
    step: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    // tokio::process::Command does NOT auto-pipe stdout/stderr (unlike std's `.output()`),
    // so without these `Stdio::piped()` calls `wait_with_output()` returns EMPTY stdout/stderr
    // and the test mis-reads rf's real output as "empty stdout" -- the root cause that masked
    // 7 S10 debugging rounds. rf was printing correctly; the harness just wasn't capturing it.
    let child = tokio::process::Command::new(binary)
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let output = match tokio::time::timeout(Duration::from_mins(2), child.wait_with_output()).await
    {
        Ok(result) => result?,
        Err(_elapsed) => {
            return Err(format!("rf command timed out during {step}").into());
        }
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let status = output.status.code().map_or_else(|| "signal".to_owned(), |code| code.to_string());
    if !output.status.success() {
        return Err(format!(
            "rf command failed during {step}: status={status} stdout={stdout} stderr={stderr}"
        )
        .into());
    }
    if output.stdout.is_empty() {
        return Err(format!(
            "rf command produced empty stdout during {step}: status={status} stdout={stdout} stderr={stderr}"
        )
        .into());
    }
    serde_json::from_slice(&output.stdout).map_err(|error| {
        format!(
            "rf command produced invalid JSON during {step}: status={status} error={error} stdout={stdout} stderr={stderr}"
        )
        .into()
    })
}

#[cfg(all(test, feature = "realnet"))]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn mvp_s8_create_rf_account(
    rf_binary: &Path,
    socket: &str,
    account: &str,
    principal: &str,
    device: &str,
    target: &str,
    gateway_addr: &str,
    gateway_url: &str,
    ca_cert: &str,
    root_seed_hex: &str,
    device_seed_hex: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let created = mvp_s4_rf_json(
        rf_binary,
        &[
            "--socket",
            socket,
            "account",
            "create",
            "--account",
            account,
            "--principal",
            principal,
            "--device",
            device,
            "--target",
            target,
            "--gateway-addr",
            gateway_addr,
            "--prekey-http-url",
            gateway_url,
            "--ca-cert",
            ca_cert,
            "--root-seed-byte-hex",
            root_seed_hex,
            "--device-seed-byte-hex",
            device_seed_hex,
            "--secret",
            "rf-local-secret",
            "--client-mode",
            "attended_cli",
        ],
    )
    .await?;
    assert_eq!(created["local_account_id"], account);
    assert_eq!(created["target_delivery_id"], target);
    Ok(created["principal_commitment"].as_str().ok_or("missing principal_commitment")?.to_owned())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s4_build_rf_binary() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let manifest = code_root().join("ramflux/apps/rf/Cargo.toml");
    let status = tokio::task::spawn_blocking(move || {
        std::process::Command::new("cargo")
            // T22-A1 / RQ-04: the itest rf binary enables itest-local-mint so LocalMint object tests
            // (e.g. mvp_s40 `--relay-service-key`) keep working. Production rf is built without it.
            .args(["build", "--quiet", "--features", "itest-local-mint", "--manifest-path"])
            .arg(manifest)
            .status()
    })
    .await??;
    if !status.success() {
        return Err("failed to build rf binary".into());
    }
    Ok(code_root().join("ramflux/target/debug/rf"))
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s4_wait_for_socket(
    socket_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    for _attempt in 0..100 {
        if socket_path.exists() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err(format!("timed out waiting for {}", socket_path.display()).into())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp_s4_path_arg(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn assert_node_opaque_payload(encrypted_payload: &str, plaintext: &[u8]) {
    assert!(
        !contains_subslice(encrypted_payload.as_bytes(), plaintext),
        "node-visible encrypted payload leaked plaintext"
    );
    if let Ok(decoded) = ramflux_protocol::decode_base64url(encrypted_payload) {
        assert_ne!(
            decoded, plaintext,
            "node-visible encrypted payload is a reversible base64 plaintext encoding"
        );
        assert!(
            !contains_subslice(&decoded, plaintext),
            "node-visible encrypted payload decodes to bytes containing plaintext"
        );
    }
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn assert_x3dh_payload_not_conversation_seed_decryptable(
    encrypted_payload: &str,
    conversation_id: &str,
    envelope_id: &str,
    device_id: &str,
    plaintext: &[u8],
    expect_x3dh_header: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_node_opaque_payload(encrypted_payload, plaintext);
    let payload = ramflux_protocol::decode_base64url(encrypted_payload)?;
    let envelope: serde_json::Value = serde_json::from_slice(&payload)?;
    assert_eq!(envelope["schema"], "ramflux.sdk.dm_x3dh_envelope.v1");
    assert_eq!(envelope["x3dh"].is_object(), expect_x3dh_header);
    if expect_x3dh_header {
        let header_ephemeral_public: [u8; 32] =
            serde_json::from_value(envelope["x3dh"]["initiator_ephemeral_public"].clone())?;
        let public_seed_material = format!("{conversation_id}:{envelope_id}:{device_id}");
        let public_seed = ramflux_crypto::blake3_256(
            "ramflux.sdk.x3dh.ephemeral.v1",
            public_seed_material.as_bytes(),
        );
        let public_derived_key = ramflux_crypto::X25519KeyPair::from_seed(public_seed);
        assert_ne!(
            header_ephemeral_public, public_derived_key.public,
            "X3DH ephemeral public key matched the old public-value-derived private key"
        );
    }
    let ciphertext: ramflux_crypto::DmCiphertext =
        serde_json::from_value(envelope["ciphertext"].clone())?;
    let legacy_seed =
        ramflux_crypto::blake3_256("ramflux.sdk.dm_session.v1", conversation_id.as_bytes());
    let mut legacy_session = ramflux_crypto::DmSession::recipient(
        legacy_seed,
        [0xb0; 32],
        [0xa0; 32],
        ramflux_crypto::blake3_256(
            ramflux_protocol::domain::DM_RATCHET_ROOT,
            conversation_id.as_bytes(),
        ),
    )?;
    assert!(
        legacy_session.decrypt(&ciphertext, conversation_id.as_bytes()).is_err(),
        "conversation_id-derived placeholder key decrypted the X3DH payload"
    );
    Ok(())
}
