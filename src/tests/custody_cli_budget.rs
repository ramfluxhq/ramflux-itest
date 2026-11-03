// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Exercise custody admission through real terminal-created accounts and polling daemons.
#![cfg(feature = "realnet")]
use super::grp_cli_born_v3::{Cli, field};
use crate::harness::custody_budget::DailyBudgetPlan;
use crate::harness::native_cli::{contacts_at, native_rf_binary};
#[path = "custody_cli_budget/admission.rs"]
mod admission;
#[path = "custody_cli_budget/target.rs"]
mod target;
use super::*;
use serde_json::Value;
use target::BudgetTarget;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const PROJECT: &str = "ramflux-custody-cli-budget";
const ADMISSION_GAP: Duration = Duration::from_secs(20);

struct Clients<'a, 'binary> {
    alice: &'a Cli<'binary>,
    bob: &'a Cli<'binary>,
    restored: &'a Cli<'binary>,
}

#[test]
fn custody_cli_budget_realnet_poll_stop_and_restore() -> TestResult {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping custody_cli_budget: set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }
    // A configured operator target must never fall back to a disposable node.
    if let Some(target) = BudgetTarget::operator_from_env()? {
        return tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(run(&target));
    }
    let mut stack = start_client_directory_stack_with_issuer(
        PROJECT,
        S8ComposePorts {
            gateway_http: 64901,
            gateway_quic: 64971,
            router_http: 64900,
            router_mesh: 64972,
            notify_http: 64903,
            federation_http: 64902,
            federation_mesh: 64973,
            relay_http: 64904,
            relay_media_udp: 64940,
            signaling_turn_udp: 64978,
            signaling_turn_tcp: 64979,
            retention_http: 64907,
        },
        &[
            ("RAMFLUX_CUSTODY_NEW_PRINCIPALS_PER_PREFIX_PER_DAY".into(), "8".into()),
            ("RAMFLUX_CUSTODY_NEW_PRINCIPALS_PER_DAY".into(), "256".into()),
        ],
        "node_a.realnet",
        "gw-a",
    )?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(run(&BudgetTarget::private(&stack.node)?))?;
    stack.node.guard.mark_success();
    Ok(())
}

async fn run(target: &BudgetTarget) -> TestResult {
    let inspection = target.inspect().await?;
    let plan = DailyBudgetPlan::inspect(&inspection, target.prefix.as_deref(), target.fresh_limit)?;
    let remaining = plan.remaining();
    eprintln!(
        "BUDGET start: prefix={:?} observed_count={} start_count={} limit={} reset_at={} remaining={remaining}",
        plan.prefix, plan.observed_count, plan.start_count, plan.limit, plan.reset_at
    );
    if remaining == 0 {
        eprintln!("BUDGET SKIP: inspected daily prefix quota is exhausted; no principals created");
        return Ok(());
    }
    let root = temp_root("custody-budget")?;
    let binary = match std::env::var_os("RAMFLUX_CUSTODY_BUDGET_RF_BINARY") {
        Some(path) => PathBuf::from(path),
        None => native_rf_binary().await?,
    };
    let profiles = root.join("nodes.json");
    std::fs::write(&profiles, serde_json::to_vec(&[&target.profile])?)?;
    let ca = root.join("ca.pem");
    std::fs::write(&ca, &target.profile.ca_cert_pem)?;
    let alice = Cli { binary: &binary, socket: root.join("a.sock") };
    let bob = Cli { binary: &binary, socket: root.join("b.sock") };
    let restored = Cli { binary: &binary, socket: root.join("r.sock") };
    let mut children = Vec::new();
    for (cli, name) in [(&alice, "alice"), (&bob, "bob"), (&restored, "restore")] {
        if name == "bob" && remaining == 1 {
            continue;
        }
        children.push(target.daemon(cli, &root.join(name), &ca, &profiles).spawn()?);
    }
    let primary = children.first_mut().ok_or("primary daemon missing")?;
    // Preserve the original poll/restore allowance, adding only the mandatory
    // inter-admission spacing for this node's inspected remainder.
    let timeout = Duration::from_secs(
        900_u64.saturating_add(remaining.saturating_mul(ADMISSION_GAP.as_secs())),
    );
    let result = tokio::time::timeout(
        timeout,
        flow(
            target,
            &plan,
            &Clients { alice: &alice, bob: &bob, restored: &restored },
            &root,
            primary,
        ),
    )
    .await;
    if let Ok(Err(error)) = &result {
        eprintln!("FLOW ERROR: {error}");
    }
    for child in &mut children {
        let _ = child.start_kill();
    }
    for child in &mut children {
        let _ = child.wait().await;
    }
    let final_counts = target.snapshot("clients stopped").await?;
    if final_counts["outstanding"] != 0 {
        tokio::time::sleep(Duration::from_secs(300)).await;
        assert_eq!(target.snapshot("idle 300s").await?["outstanding"], 0);
    }
    result??;
    std::fs::remove_dir_all(root)?;
    Ok(())
}

async fn flow(
    target: &BudgetTarget,
    plan: &DailyBudgetPlan,
    clients: &Clients<'_, '_>,
    root: &Path,
    primary: &mut tokio::process::Child,
) -> TestResult {
    let alice = clients.alice;
    let bob = clients.bob;
    let restored = clients.restored;
    mvp_s4_wait_for_socket(&restored.socket).await?;
    restored.call(&["node", "set-default", &target.profile.node_id]).await?;
    target.snapshot("before create").await?;
    plan.verify_progress(&target.inspect().await?, 0)?;
    let a = admission::principal(alice, target, "Budget Alice", None).await?;
    let mut accepted = 1;
    plan.verify_progress(&target.inspect().await?, accepted)?;
    target.snapshot("alice live").await?;
    let b = if plan.remaining() >= 2 {
        tokio::time::sleep(ADMISSION_GAP).await;
        plan.verify_progress(&target.inspect().await?, accepted)?;
        let b = admission::principal(bob, target, "Budget Bob", None).await?;
        accepted += 1;
        plan.verify_progress(&target.inspect().await?, accepted)?;
        target.snapshot("bob live").await?;
        contacts_at(alice, bob, &target.profile.node_id, &target.profile.prekey_http_url, &a, &b)
            .await?;
        send_first_dm(alice, &a, &b).await?;
        Some(b)
    } else {
        eprintln!(
            "BUDGET one remaining slot: poll and restore one principal; no second admission for DM setup"
        );
        None
    };
    let aid = field(&a, "account_id")?;
    poll(target, plan, clients, aid, b.as_ref(), accepted).await?;
    restore(target, alice, restored, root, primary, aid).await?;
    plan.verify_progress(&target.inspect().await?, accepted)?;
    while accepted < plan.remaining() {
        tokio::time::sleep(ADMISSION_GAP).await;
        plan.verify_progress(&target.inspect().await?, accepted)?;
        let number = accepted + 1;
        admission::isolated_principal(target, alice.binary, root, number, None).await?;
        accepted = number;
        plan.verify_progress(&target.inspect().await?, accepted)?;
        eprintln!(
            "BUDGET accepted: start_count={} + accepted={accepted} = {}",
            plan.start_count,
            plan.start_count + accepted
        );
    }
    tokio::time::sleep(ADMISSION_GAP).await;
    plan.verify_progress(&target.inspect().await?, accepted)?;
    admission::isolated_principal(
        target,
        alice.binary,
        root,
        accepted + 1,
        Some((field(&a, "principal_id")?, plan.reset_at)),
    )
    .await?;
    plan.verify_progress(&target.inspect().await?, accepted)?;
    eprintln!(
        "BUDGET complete: start_count={} accepted={accepted} durable_count={} limit={} reset_at={}; one typed refusal",
        plan.start_count,
        plan.start_count + accepted,
        plan.limit,
        plan.reset_at
    );
    Ok(())
}

async fn poll(
    target: &BudgetTarget,
    plan: &DailyBudgetPlan,
    clients: &Clients<'_, '_>,
    aid: &str,
    b: Option<&Value>,
    accepted: u64,
) -> TestResult {
    let alice = clients.alice;
    let bob = clients.bob;
    for round in 0..60 {
        let mut participants = vec![(alice, aid)];
        if let Some(b) = b {
            participants.push((bob, field(b, "account_id")?));
        }
        for (cli, id) in participants {
            if b.is_some() {
                cli.call(&["dm", "list", "--account", id, "--conversation", "contact-cli-v3"])
                    .await?;
            }
            cli.call(&["contact", "list", "--account", id]).await?;
            cli.call(&["account", "status", "--account", id]).await?;
        }
        target.snapshot(&format!("poll {round}")).await?;
        plan.verify_progress(&target.inspect().await?, accepted)?;
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
    Ok(())
}

async fn send_first_dm(alice: &Cli<'_>, a: &Value, b: &Value) -> TestResult {
    let aid = field(a, "account_id")?;
    let sent = alice
        .call(&[
            "dm",
            "send",
            "--account",
            aid,
            "--conversation",
            "contact-cli-v3",
            "--message",
            "budget-first",
            "--envelope",
            "budget-first",
            "--source-principal",
            field(a, "principal_id")?,
            "--sender",
            field(a, "device_id")?,
            "--recipient-device",
            field(b, "device_id")?,
            "--recipient-principal-commitment",
            field(b, "principal_commitment")?,
            "--target",
            field(b, "target_delivery_id")?,
            "--body",
            "custody budget first DM",
        ])
        .await?;
    eprintln!("STEP first DM inbox_seq={}", sent["inbox_seq"]);
    assert!(sent["inbox_seq"].as_u64().is_some_and(|seq| seq > 0));
    Ok(())
}

async fn restore(
    target: &BudgetTarget,
    alice: &Cli<'_>,
    restored: &Cli<'_>,
    root: &Path,
    primary: &mut tokio::process::Child,
    aid: &str,
) -> TestResult {
    // Stop the original before restoring its exact branch into a fresh daemon.
    let archive = root.join("alice.rfbackup");
    let mut export = tokio::process::Command::new(alice.binary);
    export
        .args([
            "--socket",
            alice.socket.to_str().ok_or("socket encoding")?,
            "account",
            "backup",
            "export",
            "--account",
            aid,
            "--out",
        ])
        .arg(&archive)
        .env("RAMFLUX_ACCOUNT_BACKUP_PASSPHRASE", "custody budget fixture archive passphrase");
    let output = export.output().await?;
    assert!(
        output.status.success(),
        "backup export failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    primary.start_kill()?;
    primary.wait().await?;
    target.snapshot("original stopped").await?;
    let mut import = tokio::process::Command::new(alice.binary);
    import
        .args([
            "--socket",
            restored.socket.to_str().ok_or("socket encoding")?,
            "account",
            "backup",
            "import",
            "--in",
        ])
        .arg(&archive)
        .args(["--new-passphrase-env", "RAMFLUX_BUDGET_RESTORE_PASSPHRASE"])
        .env("RAMFLUX_ACCOUNT_BACKUP_PASSPHRASE", "custody budget fixture archive passphrase")
        .env("RAMFLUX_BUDGET_RESTORE_PASSPHRASE", "custody budget restored data passphrase");
    let output = import.output().await?;
    assert!(
        output.status.success(),
        "backup import failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    target.snapshot("restored").await?;
    Ok(())
}
