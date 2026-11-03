// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! One ordinary human ceremony per admission, with no extra principal on refusal.
use super::*;
use crate::harness::custody_budget::require_daily_capacity_hint;

pub(super) async fn principal(
    cli: &Cli<'_>,
    target: &BudgetTarget,
    name: &str,
    refused: Option<(&str, u64)>,
) -> TestResult<Value> {
    mvp_s4_wait_for_socket(&cli.socket).await?;
    cli.call(&["node", "set-default", &target.profile.node_id]).await?;
    let created = cli.create_pending(name).await?;
    let id = field(&created, "account_id")?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
    let status = loop {
        let status = cli.call(&["account", "status", "--account", id]).await?;
        if status["networking"] == "live" || status["networking_reason"]["kind"] == "node_busy" {
            break status;
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(format!("admission did not reach a typed outcome: {status}").into());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    };
    if let Some((first_principal, reset)) = refused {
        assert_ne!(status["networking"], "live", "principal after the remainder was admitted");
        assert_eq!(status["networking_reason"]["kind"], "node_busy", "{status}");
        require_daily_capacity_hint(&status, reset)?;
        let output = tokio::process::Command::new(cli.binary)
            .args([
                "--socket",
                cli.socket.to_str().ok_or("socket encoding")?,
                "contact",
                "add",
                "--account",
                id,
                "--principal",
                first_principal,
            ])
            .kill_on_drop(true)
            .output()
            .await?;
        assert!(!output.status.success(), "a refused principal obtained networking");
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(text.contains("Capacity"), "missing typed Capacity refusal: {text}");
        eprintln!("BUDGET next principal: Capacity scope=prefix_daily reset_at={reset}");
    } else {
        assert_eq!(status["networking"], "live", "remaining admission was refused: {status}");
    }
    Ok(status)
}

pub(super) async fn isolated_principal(
    target: &BudgetTarget,
    binary: &Path,
    root: &Path,
    number: u64,
    refused: Option<(&str, u64)>,
) -> TestResult<Value> {
    let cli = Cli { binary, socket: root.join(format!("q{number}.sock")) };
    let mut daemon = target
        .daemon(
            &cli,
            &root.join(format!("client-{number}")),
            &root.join("ca.pem"),
            &root.join("nodes.json"),
        )
        .spawn()?;
    let result = principal(&cli, target, &format!("Budget {number}"), refused).await;
    let _ = daemon.start_kill();
    let _ = daemon.wait().await;
    result
}
