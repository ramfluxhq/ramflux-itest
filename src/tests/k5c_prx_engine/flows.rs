// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Bounded full and supervised channel scenarios on signed native conversations.
use super::*;
pub(super) async fn full(context: &mut Context) -> TestResult {
    eprintln!("STEP: k5c (a) one signed DM reply, bound=60s");
    context.send(DM, "k5c-ping", "k5c ping").await?;
    context.reply(DM, 1, fake_llm::PING, 60).await?;
    eprintln!("STEP: k5c (b) ordered stream and one final text, bound=60s");
    tokio::time::timeout(Duration::from_secs(60), async {
        context.send(DM, "k5c-stream", "k5c stream").await?;
        context.reply(DM, 2, &fake_llm::streamed_text(), 60).await?;
        stream(context, &fake_llm::streamed_text()).await
    })
    .await??;
    eprintln!("STEP: k5c (c) full tool execution with progress and no grant, bound=60s");
    context.send(DM, "k5c-tool-full", "k5c tool").await?;
    context.reply(DM, 3, "TOOL_RAN", 60).await?;
    let grants =
        call(&mut context.alice, &context.human.account_id, "grant.list", json!({})).await?;
    assert_eq!(
        grants["approvals"].as_array().ok_or("approval rows")?.len(),
        0,
        "full mode opened a grant"
    );
    let surfaces = surface_views(context, DM).await?;
    assert!(
        surfaces.iter().any(|s| s["snapshot"]["components"][0]["text"]
            .as_str()
            .is_some_and(|s| s.contains("file_read"))),
        "tool progress absent"
    );
    eprintln!("STEP: k5c (d) group deletion erases model context, bound=60s per phase");
    group(context).await?;
    let marker = format!("K5C-ERASE-{}", std::process::id());
    context.send(THREAD, "k5c-remember", &format!("@agent remember {marker}")).await?;
    context.reply(THREAD, 1, fake_llm::PING, 60).await?;
    let started = Instant::now();
    context.stop_host().await?;
    context.restart().await?;
    call(
        &mut context.agent,
        &context.ai.account_id,
        "bus.subscribe",
        json!({"topics":["message.updated"]}),
    )
    .await?;
    call(&mut context.alice,&context.human.account_id,"group.message.delete",json!({"group_id":GROUP,"conversation_id":THREAD,"message_id":"k5c-remember","actor_id":context.human.principal_id})).await?;
    let deletion_sequence = tokio::time::timeout(Duration::from_secs(45), async {
        loop {
            let event = context.agent.next_event().await?;
            if event.method == "message.updated"
                && event.body["message"]["message_id"] == "k5c-remember"
                && event.body["message"]["deleted"] == true
            {
                return event
                    .seq
                    .ok_or_else(|| Box::<dyn std::error::Error>::from("deletion sequence absent"));
            }
        }
    })
    .await??;
    erased(context, "k5c-remember", deletion_sequence).await?;
    let stats = context.stop_host().await?;
    let erase_elapsed = started.elapsed();
    let after = context.llm.count()?;
    context.restart().await?;
    context.send(THREAD, "k5c-recall", "@agent k5c ping recall").await?;
    context.reply(THREAD, 2, fake_llm::PING, 60).await?;
    assert!(context.llm.absent_since(after, &marker)?, "erased group marker reached the model");
    assert!(
        stats["erases"]["acked"].as_u64().is_some_and(|n| n >= 1),
        "erase was not acknowledged by PRX"
    );
    assert!(erase_elapsed < Duration::from_secs(60), "erase acknowledgement exceeded 60s");
    eprintln!("STEP: k5c (e) removal sends agent_revoked, retains Ramflux rows, no later reply");
    call(&mut context.alice,&context.human.account_id,"group.member.remove",json!({"group_id":GROUP,"actor_id":context.human.principal_id,"member_id":context.ai.device_id,"member_principal_commitment":context.ai.anchor})).await?;
    removed(context).await?;
    let stats = context.stop_host().await?;
    assert!(
        stats["controls"]["agent_revoked"].as_u64().is_some_and(|n| n >= 1),
        "removal control not counted"
    );
    context.restart().await?;
    context.send(THREAD, "k5c-after-removal", "@agent k5c ping").await?;
    for _ in 0..20 {
        assert_eq!(context.replies(THREAD).await?.len(), 2, "removed agent replied");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    context.stop_host().await?;
    eprintln!("STEP: k5c all full-mode scenarios complete root={}", context.root.display());
    Ok(())
}
async fn surface_views(context: &mut Context, conversation: &str) -> TestResult<Vec<Value>> {
    context.receive().await?;
    let listing = call(
        &mut context.alice,
        &context.human.account_id,
        "surface.list",
        json!({"conversation_id":conversation}),
    )
    .await?;
    let mut views = Vec::new();
    for row in listing["surfaces"].as_array().ok_or("surface rows")? {
        views.push(
            call(
                &mut context.alice,
                &context.human.account_id,
                "surface.get",
                json!({"surface_ref":row["surface_ref"]}),
            )
            .await?,
        );
    }
    Ok(views)
}
async fn stream(context: &mut Context, text: &str) -> TestResult {
    loop {
        let views = surface_views(context, DM).await?;
        if let Some(view) = views
            .iter()
            .find(|v| v["snapshot"]["components"][0]["text"] == text && v["closed"] == true)
        {
            assert_eq!(view["snapshot"]["fallbackText"], text);
            assert_eq!(view["streams"]["reply"], "final");
            assert_eq!(view["out_of_sync"], false);
            assert_eq!(view["author_principal_id"], context.ai.principal_id);
            let history = view["hash_history"].as_array().ok_or("surface history absent")?;
            let versions = history
                .iter()
                .map(|h| h["version"].as_u64().ok_or("surface history version"))
                .collect::<Result<Vec<_>, _>>()?;
            assert_eq!(
                versions,
                (1..=view["version"].as_u64().ok_or("surface version")?).collect::<Vec<_>>(),
                "create and append/patch/close versions must be contiguous"
            );
            assert!(versions.len() >= 5, "stream never created/appended/finalized/patched/closed");
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
async fn group(context: &mut Context) -> TestResult {
    call(&mut context.alice,&context.human.account_id,"group.create",json!({"group_id":GROUP,"conversation_id":THREAD,"creator_id":context.human.principal_id,"name":"K5C channel"})).await?;
    call(&mut context.alice,&context.human.account_id,"group.member.add",json!({"group_id":GROUP,"member_id":context.ai.device_id,"member_principal_commitment":context.ai.anchor,"role":"member"})).await?;
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            call(
                &mut context.agent,
                &context.ai.account_id,
                "message.receive",
                json!({"limit":64,"auto_fetch_attachments":false}),
            )
            .await?;
            let rows = call(
                &mut context.agent,
                &context.ai.account_id,
                "conversation.directory",
                json!({"limit":100}),
            )
            .await?;
            if rows["conversations"]
                .as_array()
                .is_some_and(|rs| rs.iter().any(|r| r["id"] == THREAD && r["removed"] != true))
            {
                return Ok::<_, Box<dyn std::error::Error>>(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await??;
    Ok(())
}
async fn erased(context: &mut Context, message: &str, sequence: u64) -> TestResult {
    tokio::time::timeout(Duration::from_secs(45), async {
        loop {
            let read = call(
                &mut context.agent,
                &context.ai.account_id,
                "message.read",
                json!({"conversation_id":THREAD}),
            )
            .await?;
            let deleted = read["messages"].as_array().is_some_and(|rows| {
                rows.iter().any(|r| r["message_id"] == message && r["deleted"] == true)
            });
            let state = context.checkpoint()?;
            let outbox = state["engine"]["erases"].as_object().ok_or("erase outbox absent")?;
            if deleted
                && state["cursor"].as_u64().is_some_and(|cursor| cursor >= sequence)
                && !outbox.values().any(|e| e["params"]["message_id"] == message)
            {
                return Ok::<_, Box<dyn std::error::Error>>(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await??;
    Ok(())
}
async fn removed(context: &mut Context) -> TestResult {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let rows = call(
                &mut context.agent,
                &context.ai.account_id,
                "conversation.directory",
                json!({"limit":100}),
            )
            .await?;
            let state = context.checkpoint()?;
            if rows["conversations"]
                .as_array()
                .is_some_and(|rows| rows.iter().any(|r| r["id"] == THREAD && r["removed"] == true))
                && !state["engine"]["controls"]
                    .as_object()
                    .ok_or("controls")?
                    .values()
                    .any(|c| c["params"]["conversation_id"] == THREAD)
                && !state["engine"]["turns"]
                    .as_object()
                    .ok_or("turns")?
                    .values()
                    .any(|t| t["conversation"] == THREAD)
            {
                return Ok::<_, Box<dyn std::error::Error>>(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await??;
    Ok(())
}
pub(super) async fn supervised(context: &mut Context) -> TestResult {
    for (index, approved, expected) in [(1, true, "TOOL_RAN"), (2, false, "TOOL_REFUSED")] {
        eprintln!("STEP: k5c2 signed grant decision approved={approved}, bound=45s");
        tokio::time::timeout(Duration::from_secs(45), async {
            context.send(DM, &format!("k5c-supervised-{index}"), "k5c tool").await?;
            decide(context, approved).await?;
            context.reply(DM, index, expected, 45).await
        })
        .await??;
    }
    eprintln!("STEP: k5c2 no human action expires, bound=75s");
    let before = context.llm.count()?;
    context.send(DM, "k5c-timeout", "k5c tool").await?;
    tokio::time::timeout(Duration::from_secs(75), async {
        loop {
            let rows = context.replies(DM).await?;
            assert!(rows.len() <= 3, "duplicate approval-timeout reply");
            if rows.len() == 3 {
                assert!(
                    rows[2]["body_utf8"].as_str().is_some_and(|t| t.contains("approval_timeout")),
                    "missing typed timeout reply"
                );
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Ok::<_, Box<dyn std::error::Error>>(())
    })
    .await??;
    assert!(context.llm.absent_since(before, fake_llm::TOOL_MARKER)?, "expired tool executed");
    context.stop_host().await?;
    Ok(())
}
async fn decide(context: &mut Context, approved: bool) -> TestResult {
    let task = loop {
        context.receive().await?;
        let listing = call(
            &mut context.alice,
            &context.human.account_id,
            "task.list",
            json!({"conversation_id":DM}),
        )
        .await?;
        if let Some(task) = listing["tasks"].as_array().and_then(|rows| {
            rows.iter().find(|t| t["state"] == "proposed" || t["state"] == "pending")
        }) {
            break task.clone();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    let id = task["task_id"].as_str().ok_or("task id")?;
    call(&mut context.alice,&context.human.account_id,"task.accept",json!({"conversation_id":DM,"task_id":id,"message_id":format!("accept-{id}"),"version":task["version"].as_u64().ok_or("task version")?+1})).await?;
    let (view, approval) = loop {
        context.receive().await?;
        let view = call(
            &mut context.alice,
            &context.human.account_id,
            "task.get",
            json!({"conversation_id":DM,"task_id":id}),
        )
        .await?;
        let grants =
            call(&mut context.alice, &context.human.account_id, "grant.list", json!({})).await?;
        if view["state"] == "needs_me" {
            let grant = &view["steps"][0]["needs_me"]["grant_id"];
            if let Some(approval) = grants["approvals"]
                .as_array()
                .and_then(|rows| rows.iter().find(|a| a["grant_id"] == *grant))
            {
                break (view, approval.clone());
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    let decision = call(
        &mut context.alice,
        &context.human.account_id,
        if approved { "grant.approve" } else { "grant.deny" },
        json!({"approval_id":approval["approval_id"]}),
    )
    .await?;
    assert_eq!(decision["status"], if approved { "approved" } else { "denied" });
    call(&mut context.alice,&context.human.account_id,"task.resolve",json!({"conversation_id":DM,"task_id":id,"message_id":format!("resolve-{id}"),"base_revision":view["version"],"step_id":view["steps"][0]["id"],"target":{"kind":"approval","grant_id":approval["grant_id"]},"decision_id":decision["approval_id"],"decision":if approved{"resume"}else{"deny"}})).await?;
    Ok(())
}
