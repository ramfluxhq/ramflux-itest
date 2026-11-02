// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Data-only offline import followed by explicit terminal recovery and ordinary admission.
#![cfg(feature = "realnet")]
use super::*;
use crate::harness::native_cli::{
    AttendedRestore, NativeCli as Cli, RESTORE_LOCAL_PASSPHRASE, contacts, field, native_rf_binary,
};
use serde_json::Value;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const THREAD: &str = "restore-cli-dm";
const GROUP: &str = "restore-cli-group";
const GROUP_TEXT: &str = "Group history survives attended recovery";
const ARCHIVE_SECRET: &str = "restore CLI archive fixture password";

#[test]
fn restore_cli_born_v3_realnet_offline_import_recover_and_history() -> TestResult {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping restore_cli_born_v3: set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }
    if std::env::var("RAMFLUX_OBJECT_V3").as_deref() != Ok("1") {
        return Err("restore_cli_born_v3 requires RAMFLUX_OBJECT_V3=1".into());
    }
    let mut stack = start_client_directory_stack_with_issuer(
        "ramflux-restore-cli-born-v3",
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

async fn run(node: &S8RealnetNode) -> TestResult {
    wait_for_private_gateway_quic(node.gateway_quic_addr, &node.ca_cert).await?;
    let root = temp_root("restore-cli-v3")?;
    let binary = native_rf_binary().await?;
    let profiles = root.join("nodes.json");
    std::fs::write(&profiles, serde_json::to_vec(&[native_node_profile(node, S73_RELAY_QUIC)?])?)?;
    let alice = Cli { binary: &binary, socket: root.join("a.sock") };
    let bob = Cli { binary: &binary, socket: root.join("b.sock") };
    let restored = Cli { binary: &binary, socket: root.join("r.sock") };
    let mut daemons = Vec::new();
    for (cli, name) in [(&alice, "alice"), (&bob, "bob"), (&restored, "restored")] {
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
            .env("RUST_LOG", "ramflux_sdk=debug")
            .stderr(std::fs::File::create(root.join(format!("{name}.log")))?);
        daemons.push(command.spawn()?);
    }
    let result =
        tokio::time::timeout(Duration::from_mins(10), flow(&alice, &bob, &restored, node, &root))
            .await;
    for daemon in &mut daemons {
        let _ = daemon.start_kill();
    }
    for daemon in &mut daemons {
        let _ = daemon.wait().await;
    }
    eprintln!("STEP: restore_cli_born_v3 artifacts={}", root.display());
    result??;
    std::fs::remove_dir_all(root)?;
    Ok(())
}

async fn backup_call(cli: &Cli<'_>, args: &[&str]) -> TestResult<Value> {
    let output = tokio::process::Command::new(cli.binary)
        .arg("--socket")
        .arg(&cli.socket)
        .args(args)
        .env("RAMFLUX_ACCOUNT_BACKUP_PASSPHRASE", ARCHIVE_SECRET)
        .env("RESTORE_LOCAL_PASSPHRASE", RESTORE_LOCAL_PASSPHRASE)
        .kill_on_drop(true)
        .output()
        .await?;
    if !output.status.success() {
        return Err(
            format!("backup CLI failed: {}", String::from_utf8_lossy(&output.stderr)).into()
        );
    }
    Ok(serde_json::from_slice(&output.stdout)?)
}

async fn live(cli: &Cli<'_>, account: &str) -> TestResult<Value> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
    loop {
        let status = cli.call(&["account", "status", &format!("--account={account}")]).await?;
        if status["networking"] == "live" {
            return Ok(status);
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(format!("account admission did not reach Live: {status}").into());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

async fn send_dm(cli: &Cli<'_>, sender: &Value, receiver: &Value, n: usize) -> TestResult {
    cli.call(&[
        "dm",
        "send",
        "--account",
        field(sender, "account_id")?,
        "--conversation",
        THREAD,
        "--message",
        &format!("restore-dm-{n}"),
        "--envelope",
        &format!("restore-env-{n}"),
        "--source-principal",
        field(sender, "principal_id")?,
        "--sender",
        field(sender, "device_id")?,
        "--recipient-device",
        field(receiver, "device_id")?,
        "--recipient-principal-commitment",
        field(receiver, "principal_commitment")?,
        "--target",
        field(receiver, "target_delivery_id")?,
        "--body",
        &format!("Restore history message {n}"),
    ])
    .await?;
    Ok(())
}

fn texts(value: &Value) -> Vec<&str> {
    // Prefer the history projection; receive-only rows can be empty after a previous read.
    value["messages"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|row| row["body_utf8"].as_str().or_else(|| row["plaintext_utf8"].as_str()))
        .collect()
}

async fn wait_history(cli: &Cli<'_>, account: &str, expected: usize) -> TestResult {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
    loop {
        let read = cli
            .call(&["dm", "list", &format!("--account={account}"), "--conversation", THREAD])
            .await?;
        let found = texts(&read);
        if found.len() == expected {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(format!("expected {expected} DM messages: {read}").into());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

async fn group_history(alice: &Cli<'_>, bob: &Cli<'_>, a: &Value, b: &Value) -> TestResult {
    let aid = field(a, "account_id")?;
    let bid = field(b, "account_id")?;
    alice
        .call(&[
            "group",
            "create",
            "--account",
            aid,
            "--group",
            GROUP,
            "--creator",
            field(a, "principal_id")?,
        ])
        .await?;
    alice
        .call(&[
            "group",
            "member",
            "add",
            "--account",
            aid,
            "--group",
            GROUP,
            "--member-device",
            field(b, "device_id")?,
            "--member-principal-commitment",
            field(b, "principal_commitment")?,
            "--target-delivery",
            field(b, "target_delivery_id")?,
        ])
        .await?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
    loop {
        bob.call(&["dm", "list", "--account", bid, "--conversation", THREAD]).await?;
        if let Ok(state) = bob.call(&["group", "members", "--account", bid, "--group", GROUP]).await
            && state["group_epoch"] == 2
        {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            return Err("group membership did not reach Bob".into());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    bob.call(&[
        "group",
        "send",
        "--account",
        bid,
        "--group",
        GROUP,
        "--conversation",
        GROUP,
        "--message",
        "restore-group-message",
        "--sender",
        field(b, "principal_id")?,
        "--body",
        GROUP_TEXT,
    ])
    .await?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
    loop {
        let read = alice
            .call(&["group", "read", "--account", aid, "--group", GROUP, "--conversation", GROUP])
            .await?;
        if texts(&read).contains(&GROUP_TEXT) {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(format!("group history missing before export: {read}").into());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

async fn flow(
    alice: &Cli<'_>,
    bob: &Cli<'_>,
    restored: &Cli<'_>,
    node: &S8RealnetNode,
    root: &Path,
) -> TestResult {
    for cli in [alice, bob, restored] {
        mvp_s4_wait_for_socket(&cli.socket).await?;
        cli.call(&["node", "set-default", &node.node_id]).await?;
    }
    eprintln!("STEP: restore_cli_born_v3 retain phrase only in attended helper memory");
    let (ceremony, created) = AttendedRestore::start(alice).await?;
    let a = live(alice, field(&created, "account_id")?).await?;
    let b = bob.create("Restore peer").await?;
    let aid = field(&a, "account_id")?;
    let bid = field(&b, "account_id")?;
    contacts(alice, bob, node, &a, &b).await?;
    for n in 0..6 {
        if n % 2 == 0 {
            send_dm(bob, &b, &a, n).await?;
        } else {
            send_dm(alice, &a, &b, n).await?;
        }
        wait_history(alice, aid, n + 1).await?;
        wait_history(bob, bid, n + 1).await?;
    }
    group_history(alice, bob, &a, &b).await?;
    let archive = root.join("account.rfb");
    let path = archive.to_str().ok_or("archive path")?;
    let exported = backup_call(
        alice,
        &["account", "backup", "export", &format!("--account={aid}"), "--out", path],
    )
    .await?;
    assert_eq!(exported["state"], "done");
    let id = fresh_import(restored, path).await?;
    assert_ne!(id, aid);
    eprintln!(
        "STEP: restore_cli_born_v3 offline import persisted; recover through controlling terminal"
    );
    let recovered = ceremony.recover(restored, &id).await?;
    assert_eq!(recovered["account_id"], id);
    let status = live(restored, &id).await?;
    assert_eq!(status["principal_commitment"], a["principal_commitment"]);
    assert_ne!(status["device_id"], a["device_id"]);
    let history = restored
        .call(&["dm", "list", &format!("--account={id}"), "--conversation", THREAD])
        .await?;
    assert_eq!(history["messages"].as_array().map(Vec::len), Some(6), "{history}");
    let restored_texts = texts(&history);
    assert_eq!(restored_texts.len(), 6, "{history}");
    for n in 0..6 {
        assert!(
            restored_texts.contains(&format!("Restore history message {n}").as_str()),
            "{history}"
        );
    }
    let group = restored
        .call(&[
            "group",
            "read",
            &format!("--account={id}"),
            "--group",
            GROUP,
            "--conversation",
            GROUP,
        ])
        .await?;
    assert!(texts(&group).contains(&GROUP_TEXT), "{group}");
    eprintln!(
        "STEP: restore_cli_born_v3 Live after recovery; exact six DM messages and group plaintext restored"
    );
    Ok(())
}

async fn fresh_import(restored: &Cli<'_>, path: &str) -> TestResult<String> {
    eprintln!("STEP: restore_cli_born_v3 fresh import without setup refuses before verification");
    let refused = tokio::process::Command::new(restored.binary)
        .arg("--socket")
        .arg(&restored.socket)
        .args(["account", "backup", "import", "--in", path])
        .env_remove("RAMFLUX_ACCOUNT_BACKUP_PASSPHRASE")
        .kill_on_drop(true)
        .output()
        .await?;
    assert_eq!(refused.status.code(), Some(1));
    let error = String::from_utf8(refused.stderr)?;
    assert!(
        error.contains("restore_setup_required") && error.contains("--new-passphrase-env"),
        "{error}"
    );
    assert!(!error.contains("networking_pending"));
    let imported = backup_call(
        restored,
        &[
            "account",
            "backup",
            "import",
            "--in",
            path,
            "--new-passphrase-env=RESTORE_LOCAL_PASSPHRASE",
        ],
    )
    .await?;
    assert_eq!(imported["state"], "done");
    let id = field(&imported, "local_account_id")?;
    assert_eq!(imported["networking"], "networking_pending");
    assert_eq!(
        imported["next_command"],
        serde_json::json!([
            "rf",
            "--socket",
            restored.socket,
            "account",
            "recover",
            format!("--account={id}")
        ])
    );
    let listed = restored.call(&["account", "list"]).await?;
    assert!(
        listed["account_details"]
            .as_array()
            .ok_or("account list details")?
            .iter()
            .any(|row| row["local_account_id"] == id)
    );
    let pending = restored.call(&["account", "status", &format!("--account={id}")]).await?;
    assert_eq!(pending["networking"], "networking_pending");
    assert_eq!(pending["state"], "locked");
    Ok(id.to_owned())
}
