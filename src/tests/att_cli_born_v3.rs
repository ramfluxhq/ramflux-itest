// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Born-v3 attachment delivery through two ordinary CLI daemons and the discovered QUIC relay.
#![cfg(feature = "realnet")]
use super::*;
use crate::harness::native_cli::{NativeCli as Cli, contacts, field, native_rf_binary};
use serde_json::Value;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const THREAD: &str = "-conv-att-cli-v3";
const MESSAGE: &str = "-msg-att-cli-v3";
const TEXT: &str = "Born-v3 CLI attachment delivery";

#[test]
fn att_cli_born_v3_realnet_same_node_attachment() -> TestResult {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping att_cli_born_v3: set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }
    if std::env::var("RAMFLUX_OBJECT_V3").as_deref() != Ok("1") {
        return Err("att_cli_born_v3 requires RAMFLUX_OBJECT_V3=1".into());
    }
    let mut stack = start_client_directory_stack_with_issuer(
        "ramflux-att-cli-born-v3",
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
    let result = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(run(&stack.node));
    assert!(result.is_ok(), "born-v3 CLI attachment flow failed: {result:?}");
    stack.node.guard.mark_success();
    Ok(())
}

async fn run(node: &S8RealnetNode) -> TestResult {
    wait_for_private_gateway_quic(node.gateway_quic_addr, &node.ca_cert).await?;
    let root = temp_root("att-cli-v3")?;
    let binary = native_rf_binary().await?;
    let profile = native_node_profile(node, S73_RELAY_QUIC)?;
    let relay_url = format!("quic://{}", profile.relay.quic_addr);
    let profiles = root.join("nodes.json");
    std::fs::write(&profiles, serde_json::to_vec(&[profile])?)?;
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
        // Use the pinned node profile as an operator does, without endpoint/auth overrides.
        for name in [
            "RAMFLUX_SDK_RELAY_QUIC_ADDR",
            "RAMFLUX_SDK_RELAY_QUIC_SERVER_NAME",
            "RAMFLUX_SDK_RELAY_QUIC_CA_CERT",
        ] {
            command.env_remove(name);
        }
        command
            .arg("--builtin-nodes")
            .arg(&profiles)
            .env("RUST_LOG", "ramflux_sdk=info,ramflux_sdk::attachment_timing=debug")
            .stderr(std::fs::File::create(root.join(format!("{label}.log")))?);
        daemons.push(command.spawn()?);
    }
    let result =
        tokio::time::timeout(Duration::from_mins(10), flow(&alice, &bob, node, &root, &relay_url))
            .await;
    for daemon in &mut daemons {
        let _ = daemon.start_kill();
    }
    for daemon in &mut daemons {
        let _ = daemon.wait().await;
    }
    let mut logging_ready = true;
    for label in ["alice", "bob"] {
        let path = root.join(format!("{label}.log"));
        let logs = std::fs::read_to_string(&path)?;
        logging_ready &= logs.contains("local bus daemon ready");
        eprintln!(
            "STEP: att_cli_born_v3 daemon={label} stderr_bytes={} log={}",
            logs.len(),
            path.display()
        );
        if !logs.is_empty() {
            eprintln!("{logs}");
        }
    }
    eprintln!("STEP: att_cli_born_v3 artifacts={}", root.display());
    result??;
    if !logging_ready {
        return Err(
            "native CLI daemon readiness diagnostic missing with SDK logging enabled".into()
        );
    }
    std::fs::remove_dir_all(root)?;
    Ok(())
}

async fn send(
    cli: &Cli<'_>,
    sender: &Value,
    receiver: &Value,
    message: &str,
    text: &str,
    attachment: Option<(&str, &str)>,
) -> TestResult<Value> {
    let mut args = vec![
        "dm",
        "send",
        "--account",
        field(sender, "account_id")?,
        "--conversation",
        THREAD,
        "--message",
        message,
        "--envelope",
        message,
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
        text,
    ];
    if let Some((path, relay)) = attachment {
        args.extend(["--attach", path, "--relay-url", relay, "--attachment-chunk-size", "1024"]);
    }
    cli.call(&args).await
}

async fn wait_dm(cli: &Cli<'_>, account: &str, text: &str) -> TestResult {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
    loop {
        let value =
            cli.call(&["dm", "list", "--account", account, "--conversation", THREAD]).await?;
        if ["messages", "decrypted_messages"].iter().any(|key| {
            value[key].as_array().is_some_and(|rows| {
                rows.iter().any(|row| row["body_utf8"] == text || row["plaintext_utf8"] == text)
            })
        }) {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err("CLI DM did not arrive before attachment send".into());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

async fn flow(
    alice: &Cli<'_>,
    bob: &Cli<'_>,
    node: &S8RealnetNode,
    root: &Path,
    relay_url: &str,
) -> TestResult {
    for cli in [alice, bob] {
        mvp_s4_wait_for_socket(&cli.socket).await?;
        cli.call(&["node", "set-default", &node.node_id]).await?;
    }
    eprintln!("STEP: att_cli_born_v3 create native accounts using rf terminal ceremony");
    let a = alice.create("Alice").await?;
    let b = bob.create("Bob").await?;
    contacts(alice, bob, node, &a, &b).await?;
    send(alice, &a, &b, "-dm-before-a", "Alice before attachment", None).await?;
    wait_dm(bob, field(&b, "account_id")?, "Alice before attachment").await?;
    send(bob, &b, &a, "-dm-before-b", "Bob before attachment", None).await?;
    wait_dm(alice, field(&a, "account_id")?, "Bob before attachment").await?;
    let mut bytes = vec![0; 300_000];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    let input = root.join("attachment.bin");
    std::fs::write(&input, &bytes)?;
    eprintln!("STEP: att_cli_born_v3 send bytes={} relay={relay_url}", bytes.len());
    let send_started = tokio::time::Instant::now();
    let sent =
        send(alice, &a, &b, MESSAGE, TEXT, Some((input.to_str().ok_or("input path")?, relay_url)))
            .await?;
    assert_eq!(sent["envelope"]["envelope_id"], MESSAGE);
    let received = read_attachment(bob, field(&b, "account_id")?, &bytes).await;
    if received.is_ok() {
        eprintln!(
            "STEP: att_cli_born_v3 send_to_verified_bytes_ms={}",
            send_started.elapsed().as_millis()
        );
    }
    let object = format!("attachment:{MESSAGE}:0");
    let mut lists_ok = true;
    for (cli, account, label) in
        [(alice, field(&a, "account_id")?, "alice"), (bob, field(&b, "account_id")?, "bob")]
    {
        match cli.call(&["object", "list", "--account", account]).await {
            Ok(value) => {
                let found = value["objects"].as_array().is_some_and(|rows| {
                    rows.iter().any(|row| row["object_id"] == object || row["id"] == object)
                });
                eprintln!(
                    "STEP: att_cli_born_v3 object list daemon={label} attachment_present={found}"
                );
                lists_ok &= found;
            }
            Err(error) => {
                eprintln!("STEP: att_cli_born_v3 object list daemon={label} failed: {error}");
                lists_ok = false;
            }
        }
    }
    received?;
    if !lists_ok {
        return Err("born-v3 object list failed after attachment delivery".into());
    }
    send(bob, &b, &a, "-dm-after-attachment", "Bob after attachment", None).await?;
    wait_dm(alice, field(&a, "account_id")?, "Bob after attachment").await?;
    eprintln!("STEP: att_cli_born_v3 recipient gateway remains usable after attachment fetch");
    Ok(())
}

const ATTACHMENT_READ_OUTER_SECONDS: u64 = 240;
const ATTACHMENT_READ_WAIT_SECONDS: u64 = 210;

async fn read_attachment(cli: &Cli<'_>, account: &str, expected: &[u8]) -> TestResult {
    // The test uses the grant window; individual page and SDK operation budgets stay unchanged.
    let started = tokio::time::Instant::now();
    eprintln!("STEP: att_cli_born_v3 receiver starts grant-window completion test");
    let deadline = started + Duration::from_secs(ATTACHMENT_READ_OUTER_SECONDS);
    let wait = ATTACHMENT_READ_WAIT_SECONDS.to_string();
    read_attachment_with(expected, async || {
        // Leave startup/response margin so the CLI can classify expiry before the child is killed.
        cli.call_until(
            &["dm", "read", "--account", account, "--conversation", THREAD, "--wait", &wait],
            deadline,
        )
        .await
    })
    .await?;
    eprintln!(
        "STEP: att_cli_born_v3 receiver read identical {} bytes elapsed_ms={}",
        expected.len(),
        started.elapsed().as_millis()
    );
    Ok(())
}

async fn read_attachment_with<F>(expected: &[u8], fetch: F) -> TestResult
where
    F: std::ops::AsyncFnOnce() -> TestResult<Value>,
{
    let value = fetch().await.map_err(|error| {
        if error.to_string().contains("attachment fetch deferred; retry object.fetch") {
            format!("attachment wait budget exhausted: {error}")
        } else {
            format!("born-v3 CLI attachment dm read failed after successful send: {error}")
        }
    })?;
    if let Some(rows) = value["decrypted_messages"].as_array() {
        for row in rows {
            if let Some(attachments) = row["attachments"].as_array() {
                for attachment in attachments {
                    if let Some(encoded) = attachment["plaintext_base64"].as_str() {
                        let bytes = ramflux_protocol::decode_base64url(encoded)?;
                        if bytes != expected {
                            return Err("received attachment bytes differ from sender".into());
                        }
                        return Ok(());
                    }
                }
            }
        }
    }
    Err("born-v3 CLI attachment plaintext missing after successful send".into())
}

#[tokio::test]
async fn attachment_read_rejects_the_first_generic_error_and_names_budget_exhaustion() -> TestResult
{
    for message in ["generic receive failure", "attachment fetch deferred; retry object.fetch"] {
        let mut calls = 0;
        let result = read_attachment_with(b"expected", async || {
            calls += 1;
            Err(message.into())
        })
        .await;
        assert_eq!(calls, 1);
        let error = result.err().ok_or("a single error must fail the scenario")?.to_string();
        assert!(error.contains(message));
        assert_eq!(
            error.contains("wait budget exhausted"),
            message.starts_with("attachment fetch deferred")
        );
    }
    Ok(())
}

#[tokio::test]
async fn attachment_read_checks_the_received_bytes() -> TestResult {
    let value = serde_json::json!({"decrypted_messages":[{"attachments":[{
        "plaintext_base64":ramflux_protocol::encode_base64url(b"expected")
    }]}]});
    read_attachment_with(b"expected", async || Ok(value.clone())).await?;
    assert!(read_attachment_with(b"different", async || Ok(value)).await.is_err());
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn attachment_read_classifies_cli_expiry_before_the_outer_deadline() -> TestResult {
    let started = tokio::time::Instant::now();
    let deadline = started + Duration::from_secs(ATTACHMENT_READ_OUTER_SECONDS);
    let result = tokio::time::timeout_at(
        deadline,
        read_attachment_with(b"expected", async || {
            // A child starts after its harness deadline is anchored, including on a quiet runner.
            tokio::time::sleep(Duration::from_millis(1)).await;
            tokio::time::sleep(Duration::from_secs(ATTACHMENT_READ_WAIT_SECONDS)).await;
            Err("attachment fetch deferred; retry object.fetch".into())
        }),
    )
    .await;
    assert!(result.is_ok(), "the outer deadline killed the CLI before wait-budget classification");
    let error = result?.err().ok_or("deferred CLI read unexpectedly succeeded")?.to_string();
    assert!(error.contains("attachment wait budget exhausted"));
    assert!(!error.contains("rf command timed out"));
    assert!(tokio::time::Instant::now() + Duration::from_secs(29) < deadline);
    Ok(())
}
