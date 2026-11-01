// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Same-node born-v3 groups through the public rf command surface, including its terminal ceremony.
#![cfg(feature = "realnet")]
use super::*;
use serde_json::Value;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const GROUP: &str = "-grp-cli-born-v3";
const THREAD: &str = "-conv-cli-born-v3";
const TEXT: &str = "Born-v3 CLI group delivery";

#[test]
fn grp_cli_born_v3_realnet_same_node_delivery() -> TestResult {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping grp_cli_born_v3: set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }
    if std::env::var("RAMFLUX_OBJECT_V3").as_deref() != Ok("1") {
        return Err("grp_cli_born_v3 requires RAMFLUX_OBJECT_V3=1".into());
    }
    let mut stack = start_client_directory_stack_with_issuer(
        "ramflux-grp-cli-born-v3",
        S8ComposePorts {
            gateway_http: 64801,
            gateway_quic: 64871,
            router_http: 64800,
            router_mesh: 64872,
            notify_http: 64803,
            federation_http: 64802,
            federation_mesh: 64873,
            relay_http: 64804,
            relay_media_udp: 64840,
            signaling_turn_udp: 64878,
            signaling_turn_tcp: 64879,
            retention_http: 64807,
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

struct Cli<'a> {
    binary: &'a Path,
    socket: PathBuf,
}
impl Cli<'_> {
    async fn call(&self, args: &[&str]) -> TestResult<Value> {
        let mut all = vec!["--socket", self.socket.to_str().ok_or("socket encoding")?];
        all.extend_from_slice(args);
        mvp_s10_rf_json(self.binary, &all, &args.join(" ")).await
    }
    async fn create(&self, name: &str) -> TestResult<Value> {
        let child = tokio::process::Command::new("python3")
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/tests/grp_cli_born_v3/create.py"))
            .arg(self.binary)
            .arg(&self.socket)
            .arg(name)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        let output =
            tokio::time::timeout(Duration::from_secs(110), child.wait_with_output()).await??;
        if !output.status.success() {
            return Err(format!(
                "CLI account ceremony failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        let created: Value = serde_json::from_slice(&output.stdout)?;
        let id = field(&created, "account_id")?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
        loop {
            let status = self.call(&["account", "status", "--account", id]).await?;
            if status["networking"] == "live" {
                return Ok(status);
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(
                    format!("born-v3 account networking did not become live: {status}").into()
                );
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }
}
fn field<'a>(value: &'a Value, name: &str) -> TestResult<&'a str> {
    value[name].as_str().ok_or_else(|| format!("missing field {name}: {value}").into())
}
async fn run(node: &S8RealnetNode) -> TestResult {
    wait_for_private_gateway_quic(node.gateway_quic_addr, &node.ca_cert).await?;
    let root = temp_root("grp-cli-v3")?;
    let binary = mvp_s4_build_rf_binary().await?;
    let profiles = root.join("nodes.json");
    std::fs::write(&profiles, serde_json::to_vec(&[native_node_profile(node, S73_RELAY_QUIC)?])?)?;
    let alice = Cli { binary: &binary, socket: root.join("a.sock") };
    let bob = Cli { binary: &binary, socket: root.join("b.sock") };
    let mut daemons = Vec::new();
    for (cli, label) in [(&alice, "alice"), (&bob, "bob")] {
        let mut command = native_client_directory_daemon_command(
            &binary,
            &cli.socket,
            &root.join(label),
            &node.ca_cert,
            None,
        );
        command.arg("--builtin-nodes").arg(&profiles).env("RUST_LOG", "ramflux_sdk=info");
        daemons.push(command.spawn()?);
    }
    let result = tokio::time::timeout(Duration::from_mins(8), flow(&alice, &bob, node)).await;
    for daemon in &mut daemons {
        let _ = daemon.start_kill();
    }
    for daemon in &mut daemons {
        let _ = daemon.wait().await;
    }
    result??;
    std::fs::remove_dir_all(root)?;
    Ok(())
}
async fn flow(alice: &Cli<'_>, bob: &Cli<'_>, node: &S8RealnetNode) -> TestResult {
    for cli in [alice, bob] {
        mvp_s4_wait_for_socket(&cli.socket).await?;
        cli.call(&["node", "set-default", &node.node_id]).await?;
    }
    eprintln!("STEP: grp_cli_born_v3 create accounts using rf terminal ceremony");
    let a = alice.create("Alice").await?;
    let b = bob.create("Bob").await?;
    let aid = field(&a, "account_id")?;
    let bid = field(&b, "account_id")?;
    let ap = field(&a, "principal_id")?;
    contacts(alice, bob, node, &a, &b).await?;
    eprintln!("STEP: grp_cli_born_v3 create group and add device selector");
    alice.call(&["group", "create", "--account", aid, "--group", GROUP, "--creator", ap]).await?;
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
            field(&b, "device_id")?,
            "--member-principal-commitment",
            field(&b, "principal_commitment")?,
            "--target-delivery",
            field(&b, "target_delivery_id")?,
        ])
        .await?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        bob.call(&["dm", "list", "--account", bid, "--conversation", "contact-cli-v3"]).await?;
        if let Ok(state) = bob.call(&["group", "members", "--account", bid, "--group", GROUP]).await
            && state["group_epoch"] == 2
            && state["members"].as_array().is_some_and(|members| {
                members.len() == 2
                    && [a["device_id"].clone(), b["device_id"].clone()]
                        .iter()
                        .all(|id| members.contains(id))
            })
        {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            return Err("receiver did not reach epoch 2 with both devices before send".into());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    eprintln!("STEP: grp_cli_born_v3 receiver at epoch 2; send with principal selector");
    send(alice, aid, ap, "-cli-born-v3-first", TEXT).await?;
    wait_text(bob, bid, TEXT).await?;
    eprintln!("STEP: grp_cli_born_v3 bob replies after divergent-selector read");
    send(bob, bid, field(&b, "principal_id")?, "-cli-born-v3-reply", "Bob reply after read")
        .await?;
    wait_text(alice, aid, "Bob reply after read").await?;
    eprintln!("STEP: grp_cli_born_v3 alice renames after send and reply");
    alice
        .call(&[
            "group",
            "rename",
            "--account",
            aid,
            "--group",
            GROUP,
            "--name",
            "Renamed after reply",
            "--request-id",
            "-cli-rename",
        ])
        .await?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        bob.call(&["dm", "list", "--account", bid, "--conversation", "contact-cli-v3"]).await?;
        let state = bob.call(&["group", "members", "--account", bid, "--group", GROUP]).await?;
        if state["name"] == "Renamed after reply" {
            eprintln!("STEP: grp_cli_born_v3 bob observed post-send signed rename");
            return Ok(());
        }
        assert!(tokio::time::Instant::now() < deadline, "post-send rename missing: {state}");
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

async fn send(
    cli: &Cli<'_>,
    account: &str,
    principal: &str,
    message: &str,
    text: &str,
) -> TestResult {
    let sent = cli
        .call(&[
            "group",
            "send",
            "--account",
            account,
            "--group",
            GROUP,
            "--conversation",
            THREAD,
            "--message",
            message,
            "--sender",
            principal,
            "--body",
            text,
        ])
        .await?;
    assert_eq!(sent["submitted"].as_array().map(Vec::len), Some(1), "same-node send: {sent}");
    assert_eq!(sent["federated_submitted"].as_array().map(Vec::len), Some(0));
    Ok(())
}

async fn wait_text(cli: &Cli<'_>, account: &str, text: &str) -> TestResult {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
    loop {
        let read = cli
            .call(&[
                "group",
                "read",
                "--account",
                account,
                "--group",
                GROUP,
                "--conversation",
                THREAD,
            ])
            .await?;
        if ["messages", "decrypted_messages"].iter().any(|key| {
            read[key].as_array().is_some_and(|rows| {
                rows.iter().any(|row| row["body_utf8"] == text || row["plaintext_utf8"] == text)
            })
        }) {
            eprintln!("STEP: grp_cli_born_v3 receiver read expected plaintext: {text}");
            return Ok(());
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "born-v3 CLI group message missing after epoch 2 and successful same-node send: {read}"
        );
        cli.call(&["dm", "list", "--account", account, "--conversation", "contact-cli-v3"]).await?;
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

async fn contacts(
    alice: &Cli<'_>,
    bob: &Cli<'_>,
    node: &S8RealnetNode,
    a: &Value,
    b: &Value,
) -> TestResult {
    let aid = field(a, "account_id")?;
    let bid = field(b, "account_id")?;
    let ap = field(a, "principal_id")?;
    let bp = field(b, "principal_id")?;
    alice.call(&["contact", "add", "--account", aid, "--principal", bp]).await?;
    eprintln!("STEP: grp_cli_born_v3 wait for incoming contact request");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(150);
    let link = loop {
        bob.call(&["dm", "list", "--account", bid, "--conversation", "contact-cli-v3"]).await?;
        let contacts = bob.call(&["contact", "list", "--account", bid]).await?;
        if let Some(link) = contacts["contacts"].as_array().and_then(|rows| {
            rows.iter().find(|row| {
                row["requester_id"]
                    .as_str()
                    .is_some_and(|id| id == ap || Some(id) == a["principal_commitment"].as_str())
            })
        }) {
            break link.clone();
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(format!("contact request missing: {contacts}").into());
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    };
    bob.call(&[
        "contact",
        "accept",
        "--account",
        bid,
        "--link",
        field(&link, "link_id")?,
        "--requester",
        field(&link, "requester_id")?,
        "--target",
        field(&link, "target_id")?,
        "--conversation",
        "contact-cli-v3",
        "--message",
        "accept-cli-v3",
        "--envelope",
        "accept-cli-v3",
        "--source-principal",
        bp,
        "--sender",
        field(b, "device_id")?,
        "--recipient-device",
        field(a, "device_id")?,
        "--target-delivery",
        field(a, "target_delivery_id")?,
        "--federation-url",
        &node.federation_url,
        "--source-node",
        &node.node_id,
        "--target-node",
        &node.node_id,
        "--recipient-prekey-url",
        &node.federation_url,
    ])
    .await?;
    for (cli, id, peer) in [(alice, aid, b), (bob, bid, a)] {
        cli.call(&[
            "contact",
            "safety-number",
            "--account",
            id,
            "--contact",
            field(peer, "principal_commitment")?,
        ])
        .await?;
    }
    Ok(())
}
