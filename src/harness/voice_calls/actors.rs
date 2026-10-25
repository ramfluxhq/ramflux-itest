// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Process and RPC setup for the voice acceptance fixture, without media-secret diagnostics.
use super::*;
pub(super) async fn binary() -> VoiceResult<PathBuf> {
    let manifest = code_root().join("ramflux/apps/rf/Cargo.toml");
    let target = code_root().join("ramflux/target");
    let status = tokio::process::Command::new("cargo")
        .args(["build", "--bin", "rf", "--features", "itest-local-mint", "--manifest-path"])
        .arg(manifest)
        .arg("--target-dir")
        .arg(&target)
        .env_remove("CARGO_TARGET_DIR")
        .status()
        .await?;
    if !status.success() {
        return Err("voice fixture rf build failed".into());
    }
    Ok(target.join("debug/rf"))
}
pub(super) async fn create(
    bus: &mut ramflux_sdk::LocalBusClient,
    node: &S8RealnetNode,
    id: &str,
    root_seed: [u8; 32],
    device_seed: [u8; 32],
) -> VoiceResult<Value> {
    let principal = format!("principal_call01_{id}");
    let device = format!("device_call01_{id}");
    let target = format!("target_call01_{id}");
    let request = ramflux_sdk::LocalBusAccountCreateRequest {
        node_id: None,
        kind: Some("human".into()),
        label: None,
        local_account_id: id.into(),
        principal_id: principal.clone(),
        principal_commitment: String::new(),
        device_id: device.clone(),
        target_delivery_id: target.clone(),
        account_secret: "voice-fixture-secret".into(),
        root_seed,
        device_seed,
        client_mode: ramflux_sdk::LocalBusClientMode::AttendedCli,
        gateway: ramflux_sdk::GatewayQuicEndpointConfig {
            bind_addr: "0.0.0.0:0".parse()?,
            gateway_addr: "127.0.0.1:64871".parse()?,
            server_name: "localhost".into(),
            ca_cert: node.ca_cert.clone(),
            principal_id: principal,
            device_id: device,
            target_delivery_id: target,
            prekey_http_url: None,
        },
    };
    Ok(bus.request(None, "account", "account.create", serde_json::to_value(request)?).await?)
}
pub(super) async fn call(
    bus: &mut ramflux_sdk::LocalBusClient,
    account: &str,
    method: &str,
    body: Value,
) -> VoiceResult<Value> {
    Ok(bus.request(Some(account.into()), "voice", method, body).await?)
}
pub(super) async fn cli(
    rf: &Path,
    socket: &Path,
    action: &str,
    account: &str,
    argument: Option<(&str, &str)>,
) -> VoiceResult<Value> {
    let socket = socket.to_str().ok_or("invalid socket path")?;
    let mut args = vec!["--socket", socket, "call", action, "--account", account];
    if let Some((flag, value)) = argument {
        args.extend([flag, value]);
    }
    mvp_s4_rf_json(rf, &args).await
}
pub(super) async fn wait_context(bus: &mut ramflux_sdk::LocalBusClient) -> VoiceResult {
    for _ in 0..200 {
        let read =
            call(bus, "bob", "message.read", json!({"conversation_id":"voice-thread"})).await?;
        if read["messages"]
            .as_array()
            .is_some_and(|rows| rows.iter().any(|r| r["body_utf8"] == "voice context"))
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err("voice context was not received by the daemon".into())
}
pub(super) async fn wait_state(
    bus: &mut ramflux_sdk::LocalBusClient,
    account: &str,
    id: &str,
    state: &str,
) -> VoiceResult<Value> {
    for _ in 0..200 {
        let listed = call(bus, account, "call.list", json!({})).await?;
        if let Some(row) =
            listed["calls"].as_array().and_then(|rows| rows.iter().find(|r| r["call_id"] == id))
        {
            if row["state"] == state {
                return Ok(row.clone());
            }
            if row["state"] == "ended" {
                return Err(format!(
                    "voice ended while waiting for {state}: reason={}",
                    row["end_reason"]
                )
                .into());
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(format!("timed out waiting for voice state {state}").into())
}
pub(super) fn public_fields_only(value: &Value) -> VoiceResult {
    match value {
        Value::Object(fields) => {
            for (key, value) in fields {
                if ["base_key", "caller_token", "callee_token", "sframe", "allocation", "token"]
                    .contains(&key.as_str())
                {
                    return Err("media secrets entered a public call projection".into());
                }
                public_fields_only(value)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                public_fields_only(value)?;
            }
        }
        _ => {}
    }
    Ok(())
}
