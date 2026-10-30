// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Native group host replies, verified attribution, durable restart and membership fences.
use super::*;
const GROUP: &str = "native-agent-group";
const THREAD: &str = "native-agent-group-thread";

pub(super) async fn run(
    bus: &mut ramflux_sdk::LocalBusClient,
    root: &Path,
    bundle: &Path,
    human: &NativeAccount,
    agent: &NativeAccount,
) -> TestResult {
    let binary = build_agent_host().await?;
    let config = root.join("group-host.json");
    let state = root.join("group-host-state.json");
    std::fs::write(
        &config,
        serde_json::to_vec(&json!({
            "socket":root.join("rfd.sock"),"state_file":state,"account_id":agent.account_id,
            "poll_interval_ms":50,"per_conversation_interval_ms":100,
            "rules":[{"pattern":"@agent ping","reply":"pong"}]
        }))?,
    )?;
    let mut host = spawn(&binary, &config, Some(bundle))?;
    checkpoint(&state, None).await?;
    assert!(!bundle.exists(), "one-use native bundle survived host startup");
    call(
        bus,
        &human.account_id,
        "group.create",
        json!({"group_id":GROUP,
        "conversation_id":THREAD,"creator_id":human.principal_id,"name":"Native agent"}),
    )
    .await?;
    call(
        bus,
        &human.account_id,
        "group.member.add",
        json!({"group_id":GROUP,
        "member_id":agent.device_id,"member_principal_commitment":agent.anchor,"role":"member"}),
    )
    .await?;
    wait_membership(bus, agent, true).await?;
    send(bus, human, "native-group-ping").await?;
    wait_replies(bus, human, agent, 1).await?;
    let before = checkpoint(&state, None).await?;
    host.start_kill()?;
    host.wait().await?;
    let sentinel = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(1);
    std::fs::File::options().write(true).open(&state)?.set_modified(sentinel)?;
    let mut host = spawn(&binary, &config, None)?;
    let after = checkpoint(&state, Some(sentinel)).await?;
    assert!(after >= before, "group cursor regressed across process restart");
    // Drain several polls; exactly one existing reply must remain after replay/reconnect.
    for _ in 0..20 {
        assert_reply_count(bus, human, agent, 1).await?;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    send(bus, human, "native-group-ping-after-restart").await?;
    wait_replies(bus, human, agent, 2).await?;
    call(
        bus,
        &human.account_id,
        "group.member.remove",
        json!({"group_id":GROUP,
        "actor_id":human.principal_id,"member_id":agent.device_id,
        "member_principal_commitment":agent.anchor}),
    )
    .await?;
    wait_membership(bus, agent, false).await?;
    let error = call(bus, &agent.account_id, "group.send", json!({"group_id":GROUP,
        "conversation_id":THREAD,"message_id":"removed-agent-speech","sender_id":agent.principal_id,
        "encrypted_body_base64":"","plaintext_body_base64":ramflux_protocol::encode_base64url(b"forbidden")}))
        .await.err().ok_or("removed native agent was allowed to speak")?;
    assert!(matches!(error.downcast_ref::<ramflux_sdk::SdkError>(),
        Some(ramflux_sdk::SdkError::LocalBusRefused { code, .. }) if code == "GroupSendRefused"));
    send(bus, human, "native-group-after-removal").await?;
    for _ in 0..20 {
        assert_reply_count(bus, human, agent, 2).await?;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(host.try_wait()?.is_none(), "membership refusal stopped the host");
    host.start_kill()?;
    host.wait().await?;
    Ok(())
}

fn spawn(binary: &Path, config: &Path, bundle: Option<&Path>) -> TestResult<tokio::process::Child> {
    let mut command = tokio::process::Command::new(binary);
    command.arg("--config").arg(config).arg("--itest-memory-vault");
    if let Some(bundle) = bundle {
        command.arg("--provisioning-bundle").arg(bundle);
    }
    Ok(command.stderr(std::process::Stdio::inherit()).kill_on_drop(true).spawn()?)
}

async fn checkpoint(path: &Path, stale: Option<std::time::SystemTime>) -> TestResult<u64> {
    for _ in 0..200 {
        if !stale.is_some_and(|stale| {
            std::fs::metadata(path).and_then(|m| m.modified()).is_ok_and(|at| at == stale)
        }) && let Ok(bytes) = std::fs::read(path)
            && let Ok(value) = serde_json::from_slice::<Value>(&bytes)
            && let Some(cursor) = value["cursor"].as_u64()
        {
            return Ok(cursor);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err("native group host checkpoint did not become ready".into())
}

async fn wait_membership(
    bus: &mut ramflux_sdk::LocalBusClient,
    agent: &NativeAccount,
    member: bool,
) -> TestResult {
    for _ in 0..200 {
        receive(bus, &agent.account_id).await?;
        if let Ok(view) =
            call(bus, &agent.account_id, "group.members", json!({"group_id":GROUP})).await
        {
            let present = view["members"]
                .as_array()
                .is_some_and(|rows| rows.contains(&json!(agent.device_id)));
            if present == member {
                assert!(view["member_roster"].is_array(), "native group lacks signed roster");
                return Ok(());
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(format!("native agent group membership did not become {member}").into())
}

async fn send(
    bus: &mut ramflux_sdk::LocalBusClient,
    human: &NativeAccount,
    id: &str,
) -> TestResult {
    call(
        bus,
        &human.account_id,
        "group.send",
        json!({"group_id":GROUP,"conversation_id":THREAD,
        "message_id":id,"sender_id":human.principal_id,"encrypted_body_base64":"",
        "plaintext_body_base64":ramflux_protocol::encode_base64url(b"@agent ping")}),
    )
    .await?;
    Ok(())
}

async fn replies(
    bus: &mut ramflux_sdk::LocalBusClient,
    human: &NativeAccount,
    agent: &NativeAccount,
) -> TestResult<usize> {
    receive(bus, &human.account_id).await?;
    let rows =
        call(bus, &human.account_id, "message.read", json!({"conversation_id":THREAD})).await?;
    let replies = rows["messages"]
        .as_array()
        .ok_or("group messages")?
        .iter()
        .filter(|row| row["sender_id"] == agent.principal_id)
        .collect::<Vec<_>>();
    for reply in &replies {
        assert_eq!(reply["sender_device_id"], agent.device_id);
        assert_eq!(reply["sender_root_commitment"], agent.anchor);
        assert_eq!(reply["body_utf8"], "pong");
    }
    let directory =
        call(bus, &human.account_id, "identity.directory", json!({"limit":100})).await?;
    assert!(directory["identities"].as_array().ok_or("identities")?.iter().any(|row| {
        row["principal_id"] == agent.principal_id
            && row["kind"] == "headless_ai"
            && row["kind_verified"] == true
            && row["contact_identity_commitment"] == agent.anchor
            && row["devices"]
                .as_array()
                .is_some_and(|devices| devices.iter().any(|d| d["device_id"] == agent.device_id))
    }));
    Ok(replies.len())
}
async fn wait_replies(
    bus: &mut ramflux_sdk::LocalBusClient,
    human: &NativeAccount,
    agent: &NativeAccount,
    count: usize,
) -> TestResult {
    for _ in 0..200 {
        let found = replies(bus, human, agent).await?;
        assert!(found <= count, "duplicate native group reply");
        if found == count {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(format!("missing native group reply count={count}").into())
}
async fn assert_reply_count(
    bus: &mut ramflux_sdk::LocalBusClient,
    human: &NativeAccount,
    agent: &NativeAccount,
    count: usize,
) -> TestResult {
    assert_eq!(
        replies(bus, human, agent).await?,
        count,
        "group reply count changed without a fresh command"
    );
    Ok(())
}
