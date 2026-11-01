// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Exercise custody admission through real terminal-created accounts and polling daemons.
#![cfg(feature = "realnet")]
use super::grp_cli_born_v3::{Cli, contacts, field};
use super::*;
use serde_json::Value;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const ROUTER: &str = "http://127.0.0.1:64900";

#[test]
fn custody_cli_budget_realnet_poll_stop_and_restore() -> TestResult {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping custody_cli_budget: set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }
    let mut stack = start_client_directory_stack_with_issuer(
        "ramflux-custody-cli-budget",
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
        &[],
        "node_a.realnet",
        "gw-a",
    )?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(run(&stack.node))?;
    stack.node.guard.mark_success();
    Ok(())
}

async fn snapshot(label: &str) -> TestResult<Value> {
    let response = reqwest::get(format!("{ROUTER}/perf/metrics")).await?;
    let value: Value = serde_json::from_slice(&response.error_for_status()?.bytes().await?)?;
    let counts = value.get("custody").ok_or("custody metrics missing")?.clone();
    eprintln!("BUDGET {label}: {counts}");
    Ok(counts)
}

async fn run(node: &S8RealnetNode) -> TestResult {
    wait_for_private_gateway_quic(node.gateway_quic_addr, &node.ca_cert).await?;
    let root = temp_root("custody-budget")?;
    let binary = if let Some(path) = std::env::var_os("RAMFLUX_CUSTODY_BUDGET_RF_BINARY") {
        PathBuf::from(path)
    } else {
        mvp_s4_build_rf_binary().await?
    };
    let profiles = root.join("nodes.json");
    std::fs::write(&profiles, serde_json::to_vec(&[native_node_profile(node, S73_RELAY_QUIC)?])?)?;
    let alice = Cli { binary: &binary, socket: root.join("a.sock") };
    let bob = Cli { binary: &binary, socket: root.join("b.sock") };
    let restored = Cli { binary: &binary, socket: root.join("r.sock") };
    let mut children = Vec::new();
    for (cli, name) in [(&alice, "alice"), (&bob, "bob"), (&restored, "restore")] {
        let mut command = native_client_directory_daemon_command(
            &binary,
            &cli.socket,
            &root.join(name),
            &node.ca_cert,
            None,
        );
        command
            .arg("--builtin-nodes")
            .arg(&profiles)
            .env("RAMFLUX_ACCOUNT_BACKUP_PASSPHRASE", "custody budget fixture archive passphrase")
            .env("RAMFLUX_BUDGET_RESTORE_PASSPHRASE", "custody budget restored data passphrase");
        children.push(command.spawn()?);
    }
    let primary = children.first_mut().ok_or("primary daemon missing")?;
    let result = tokio::time::timeout(
        Duration::from_mins(15),
        flow(node, &alice, &bob, &restored, &root, primary),
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
    let final_counts = snapshot("clients stopped").await?;
    if final_counts["outstanding"] != 0 {
        tokio::time::sleep(Duration::from_secs(300)).await;
        assert_eq!(snapshot("idle 300s").await?["outstanding"], 0);
    }
    result??;
    std::fs::remove_dir_all(root)?;
    Ok(())
}

async fn flow(
    node: &S8RealnetNode,
    alice: &Cli<'_>,
    bob: &Cli<'_>,
    restored: &Cli<'_>,
    root: &Path,
    primary: &mut tokio::process::Child,
) -> TestResult {
    for cli in [alice, bob, restored] {
        mvp_s4_wait_for_socket(&cli.socket).await?;
        cli.call(&["node", "set-default", &node.node_id]).await?;
    }
    snapshot("before create").await?;
    let a = alice.create("Budget Alice").await?;
    snapshot("alice live").await?;
    let b = bob.create("Budget Bob").await?;
    snapshot("bob live").await?;
    contacts(alice, bob, node, &a, &b).await?;
    let aid = field(&a, "account_id")?;
    let bid = field(&b, "account_id")?;
    send_first_dm(alice, &a, &b).await?;
    for round in 0..60 {
        for (cli, id) in [(alice, aid), (bob, bid)] {
            cli.call(&["dm", "list", "--account", id, "--conversation", "contact-cli-v3"]).await?;
            cli.call(&["contact", "list", "--account", id]).await?;
            cli.call(&["account", "status", "--account", id]).await?;
        }
        snapshot(&format!("poll {round}")).await?;
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
    restore(alice, restored, root, primary, aid).await?;
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
    snapshot("original stopped").await?;
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
    snapshot("restored").await?;
    Ok(())
}
