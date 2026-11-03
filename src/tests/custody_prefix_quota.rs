// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Nine terminal-created principals behind one source exercise durable publication admission.
#![cfg(feature = "realnet")]
use super::grp_cli_born_v3::{Cli, field};
use super::*;
use crate::harness::custody_budget::require_daily_capacity_hint;
use serde_json::Value;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const PROJECT: &str = "ramflux-custody-prefix-quota";

#[test]
fn custody_prefix_quota_realnet_ninth_principal() -> TestResult {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping custody_prefix_quota: set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }
    // Run once without this setting (the production default), then once with 16.
    let configured = std::env::var("RAMFLUX_ITEST_CUSTODY_PREFIX_PER_DAY").ok();
    if configured.as_deref().is_some_and(|value| value != "16") {
        return Err("quota fixture accepts only an unset limit or 16".into());
    }
    let extra = configured
        .as_ref()
        .map(|value| {
            vec![("RAMFLUX_CUSTODY_NEW_PRINCIPALS_PER_PREFIX_PER_DAY".into(), value.clone())]
        })
        .unwrap_or_default();
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
        &extra,
        "node_a.realnet",
        "gw-a",
    )?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(run(&stack.node, configured.is_some()))?;
    stack.node.guard.mark_success();
    Ok(())
}

async fn run(node: &S8RealnetNode, configured: bool) -> TestResult {
    wait_for_private_gateway_quic(node.gateway_quic_addr, &node.ca_cert).await?;
    let root = temp_root("custody-prefix-quota")?;
    let binary = match std::env::var_os("RAMFLUX_CUSTODY_BUDGET_RF_BINARY") {
        Some(path) => PathBuf::from(path),
        None => mvp_s4_build_rf_binary().await?,
    };
    let profiles = root.join("nodes.json");
    std::fs::write(&profiles, serde_json::to_vec(&[native_node_profile(node, S73_RELAY_QUIC)?])?)?;
    tokio::time::timeout(
        Duration::from_mins(12),
        flow(&root, &binary, &profiles, node, configured),
    )
    .await??;
    std::fs::remove_dir_all(root)?;
    Ok(())
}

async fn flow(
    root: &Path,
    binary: &Path,
    profiles: &Path,
    node: &S8RealnetNode,
    configured: bool,
) -> TestResult {
    let mut first_principal = String::new();
    for number in 1..=9 {
        // Separate participants must not share daemon account/driver state. Stopping each one
        // also proves that the network quota persists independently of live client sessions.
        let cli = Cli { binary, socket: root.join(format!("q{number}.sock")) };
        let mut command = native_client_directory_daemon_command(
            binary,
            &cli.socket,
            &root.join(format!("client-{number}")),
            &node.ca_cert,
            None,
        );
        command.arg("--builtin-nodes").arg(profiles);
        let mut daemon = command.spawn()?;
        let result = principal(&cli, node, configured, number, &mut first_principal).await;
        let _ = daemon.start_kill();
        let _ = daemon.wait().await;
        result?;
        if number != 9 {
            tokio::time::sleep(Duration::from_secs(20)).await;
        }
    }
    inspect_quota(configured)
}

async fn principal(
    cli: &Cli<'_>,
    node: &S8RealnetNode,
    configured: bool,
    number: u8,
    first_principal: &mut String,
) -> TestResult {
    mvp_s4_wait_for_socket(&cli.socket).await?;
    cli.call(&["node", "set-default", &node.node_id]).await?;
    let created = cli.create_pending(&format!("Quota {number}")).await?;
    let id = field(&created, "account_id")?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
    let status = loop {
        let status = cli.call(&["account", "status", "--account", id]).await?;
        if status["networking"] == "live" || status["networking_reason"]["kind"] == "node_busy" {
            break status;
        }
        if tokio::time::Instant::now() >= deadline {
            break status;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    };
    if number == 9 && !configured {
        assert_ne!(status["networking"], "live", "default ninth principal was admitted");
        assert_eq!(status["networking_reason"]["kind"], "node_busy", "{status}");
        let inspection = quota_inspection()?;
        let reset = daily_prefix_row(&inspection)?["reset_at"].as_u64().ok_or("reset missing")?;
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
                first_principal.as_str(),
            ])
            .output()
            .await?;
        assert!(!output.status.success());
        let output = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.contains("Capacity"), "expected typed Capacity: {output}");
        eprintln!("QUOTA default ninth: Capacity, cooldown=300s");
    } else {
        assert_eq!(
            status["networking"], "live",
            "principal {number}, configured={configured}: {status}"
        );
        if number == 1 {
            *first_principal = field(&status, "principal_id")?.into();
        }
        eprintln!("QUOTA principal {number}: live, configured={configured}");
    }
    Ok(())
}

fn quota_inspection() -> TestResult<Value> {
    let certs = code_root().join("ramflux/deploy/.itest-node-certs").join(PROJECT).join("certs");
    let tls = ramflux_transport::MeshTlsConfig {
        ca_cert: certs.join("ca.pem"),
        service_cert: certs.join("gateway/gateway.pem"),
        service_key: certs.join("gateway/gateway-key.pem"),
    };
    ramflux_transport::MeshHttpClient::new()
        .post_json(
            "127.0.0.1:64972",
            "/admin/custody/budgets",
            &tls,
            "router",
            &serde_json::json!({"admin_token": itest_admin_token()}),
        )
        .map_err(Into::into)
}

fn daily_prefix_row(inspection: &Value) -> TestResult<&Value> {
    inspection["rows"]
        .as_array()
        .ok_or("budget rows missing")?
        .iter()
        .find(|row| row["scope"] == "prefix" && row["budget"] == "publication_daily")
        .ok_or_else(|| "daily prefix receipt missing".into())
}

fn inspect_quota(configured: bool) -> TestResult {
    let inspection = quota_inspection()?;
    let prefix = daily_prefix_row(&inspection)?;
    assert_eq!(prefix["count"], if configured { 9 } else { 8 });
    assert_eq!(prefix["limit"], if configured { 16 } else { 8 });
    assert_eq!(prefix["reset_at"].as_u64().ok_or("reset missing")? % 86400, 0);
    eprintln!("QUOTA durable inspection: {inspection}");
    if !configured {
        let names = std::process::Command::new(container_runtime()?)
            .args([
                "ps",
                "--filter",
                &format!("label=com.docker.compose.project={PROJECT}"),
                "--filter",
                "label=com.docker.compose.service=ramflux-router",
                "--format",
                "{{.Names}}",
            ])
            .output()?;
        assert!(names.status.success());
        let name = String::from_utf8(names.stdout)?;
        let logs = std::process::Command::new(container_runtime()?)
            .args(["logs", name.trim()])
            .output()?;
        assert!(logs.status.success());
        let logs = format!(
            "{}{}",
            String::from_utf8_lossy(&logs.stdout),
            String::from_utf8_lossy(&logs.stderr)
        );
        // Tracing ANSI control sequences separate keys and values on some runtimes.
        let logs = logs.replace("\u{1b}[0m", "").replace("\u{1b}[3m", "").replace("\u{1b}[2m", "");
        assert!(
            logs.lines().any(|line| line.contains("publication_daily")
                && line.contains("scope=\"prefix\"")
                && line.contains("count=8")
                && line.contains("limit=8")),
            "missing scoped publication_daily refusal warning"
        );
        eprintln!(
            "QUOTA warn verified: budget=\"publication_daily\" scope=\"prefix\" count=8 limit=8"
        );
    }
    Ok(())
}
