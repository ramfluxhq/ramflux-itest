// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Process and RPC setup for the voice acceptance fixture, without media-secret diagnostics.
use super::*;
pub(super) async fn binary() -> VoiceResult<PathBuf> {
    let manifest = code_root().join("ramflux/apps/rf/Cargo.toml");
    let target = code_root().join("ramflux/target");
    let status = tokio::process::Command::new("cargo")
        .args(["build", "--bin", "rf", "--features", "itest-memory-vault", "--manifest-path"])
        .arg(manifest)
        .arg("--target-dir")
        .arg(&target)
        .env("RAMFLUX_ITEST_BUILD", "1")
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
    socket: &Path,
    node: &S8RealnetNode,
    display_name: &str,
) -> VoiceResult<Value> {
    let added = bus.request(None, "node", "node.add", json!({"url":node.federation_url})).await?;
    assert_eq!(added["node"]["node_id"], node.node_id);
    bus.request(
        None,
        "node",
        "node.confirm",
        json!({
            "node_id":node.node_id,
            "pin_source":"operator",
            "expected_public_key":node.federation_node_public_key,
        }),
    )
    .await?;
    bus.request(None, "node", "node.set_default", json!({"node_id":node.node_id})).await?;

    let mut ceremony = ramflux_sdk::LocalBusCreationClient::connect(socket).await?;
    ceremony.begin(display_name, ramflux_protocol::PrincipalKind::Human).await?;
    let phrase = ceremony.show_once().await?;
    let remembered = phrase
        .split_whitespace()
        .map(|word| zeroize::Zeroizing::new(word.to_owned()))
        .collect::<Vec<_>>();
    if remembered.len() != 24 {
        return Err("native voice fixture received an invalid recovery phrase".into());
    }
    drop(phrase);
    let positions = ceremony.hidden_challenge().await?;
    let answers =
        std::array::from_fn(|index| remembered[usize::from(positions[index] - 1)].clone());
    drop(remembered);
    let created = ceremony
        .confirm(&answers, &zeroize::Zeroizing::new("voice fixture data passphrase".into()))
        .await?;
    let account = created.account_id;
    for _ in 0..300 {
        let status =
            bus.request(Some(account.clone()), "account", "account.status", json!({})).await?;
        if status["networking"] == "live" && status["session_id"].is_string() {
            return Ok(status);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(format!("native voice account {account} did not become live").into())
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
    let selector = argument.map(|(flag, value)| format!("{flag}={value}"));
    if let Some(selector) = selector.as_deref() {
        args.push(selector);
    }
    mvp_s4_rf_json(rf, &args).await
}
pub(super) async fn wait_context(
    bus: &mut ramflux_sdk::LocalBusClient,
    account: &str,
) -> VoiceResult {
    for _ in 0..200 {
        let read =
            call(bus, account, "message.read", json!({"conversation_id":"voice-thread"})).await?;
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
                    json!({"end_reason":row["end_reason"],"failure_reason":row["failure_reason"]})
                )
                .into());
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(format!("timed out waiting for voice state {state}").into())
}
pub(super) async fn wait_inbound_contact_request(
    bus: &mut ramflux_sdk::LocalBusClient,
    account: &str,
    principal: &str,
) -> VoiceResult<String> {
    for _ in 0..200 {
        let listed = call(bus, account, "contact.requests.list", json!({})).await?;
        if let Some(id) = listed["requests"].as_array().and_then(|requests| {
            requests.iter().find_map(|request| {
                if request["direction"] == "inbound"
                    && request["state"] == "pending"
                    && request["principal_id"] == principal
                {
                    request["request_id"].as_str().map(str::to_owned)
                } else {
                    None
                }
            })
        }) {
            return Ok(id);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(format!("timed out waiting for native contact request from {principal}").into())
}
pub(super) async fn wait_accepted_contact(
    bus: &mut ramflux_sdk::LocalBusClient,
    account: &str,
    principal: &str,
) -> VoiceResult {
    for _ in 0..200 {
        let listed = call(bus, account, "contact.list", json!({})).await?;
        if listed["contacts"].as_array().is_some_and(|contacts| {
            contacts.iter().any(|contact| {
                contact["principal_id"] == principal && contact["state"] == "accepted"
            })
        }) {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(format!("timed out waiting for accepted native contact {principal}").into())
}
pub(super) fn public_fields_only(value: &Value) -> VoiceResult {
    match value {
        Value::Object(fields) => {
            for (key, value) in fields {
                if [
                    "base_key",
                    "caller_token",
                    "callee_token",
                    "sframe",
                    "allocation",
                    "token",
                    "rebind_key",
                ]
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
