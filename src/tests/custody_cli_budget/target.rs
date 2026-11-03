// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Separate a disposable Compose fixture from an explicitly configured operator node.
use super::*;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OperatorTarget {
    profile: ramflux_sdk::NodeProfile,
    prefix: String,
    quota_command: Vec<String>,
    metrics_command: Vec<String>,
}

enum Inspection {
    Private(PathBuf),
    Operator(Vec<String>),
}

enum Metrics {
    Http(String),
    Operator(Vec<String>),
}

pub(super) struct BudgetTarget {
    pub(super) profile: ramflux_sdk::NodeProfile,
    pub(super) prefix: Option<String>,
    pub(super) fresh_limit: Option<u64>,
    inspection: Inspection,
    metrics: Metrics,
}

impl BudgetTarget {
    pub(super) fn operator_from_env() -> TestResult<Option<Self>> {
        let Some(path) = std::env::var_os("RAMFLUX_CUSTODY_BUDGET_TARGET") else {
            return Ok(None);
        };
        let target: OperatorTarget = serde_json::from_slice(&std::fs::read(path)?)?;
        if target.profile.pin_source != ramflux_sdk::NodePinSource::Builtin
            || !target.profile.builtin
            || !target.profile.enabled
            || target.profile.expires_at <= ramflux_node_core::now_unix_seconds()
        {
            return Err(
                "operator target needs an enabled, current, operator-verified builtin profile"
                    .into(),
            );
        }
        if target.prefix.is_empty()
            || target.quota_command.is_empty()
            || target.metrics_command.is_empty()
        {
            return Err("operator target needs its prefix hash and both inspection commands".into());
        }
        eprintln!("BUDGET target=operator node={}", target.profile.node_id);
        Ok(Some(Self {
            profile: target.profile,
            prefix: Some(target.prefix),
            fresh_limit: None,
            inspection: Inspection::Operator(target.quota_command),
            metrics: Metrics::Operator(target.metrics_command),
        }))
    }

    pub(super) fn private(node: &S8RealnetNode) -> TestResult<Self> {
        eprintln!("BUDGET target=private_compose node={}", node.node_id);
        Ok(Self {
            profile: native_node_profile(node, S73_RELAY_QUIC)?,
            prefix: None,
            // This disposable fixture explicitly selects the default 8/256 policy.
            fresh_limit: Some(8),
            inspection: Inspection::Private(
                code_root().join("ramflux/deploy/.itest-node-certs").join(PROJECT).join("certs"),
            ),
            metrics: Metrics::Http("http://127.0.0.1:64900/perf/metrics".into()),
        })
    }

    pub(super) async fn inspect(&self) -> TestResult<Value> {
        match &self.inspection {
            Inspection::Operator(command) => command_json(command).await,
            Inspection::Private(certs) => {
                let certs = certs.clone();
                let result = tokio::task::spawn_blocking(move || {
                    let tls = ramflux_transport::MeshTlsConfig {
                        ca_cert: certs.join("ca.pem"),
                        service_cert: certs.join("gateway/gateway.pem"),
                        service_key: certs.join("gateway/gateway-key.pem"),
                    };
                    ramflux_transport::MeshHttpClient::new()
                        .post_json::<_, Value>(
                            "127.0.0.1:64972",
                            "/admin/custody/budgets",
                            &tls,
                            "router",
                            &serde_json::json!({"admin_token":itest_admin_token()}),
                        )
                        .map_err(|error| error.to_string())
                })
                .await?;
                result.map_err(Into::into)
            }
        }
    }

    pub(super) async fn snapshot(&self, label: &str) -> TestResult<Value> {
        let value = match &self.metrics {
            Metrics::Http(url) => {
                let response = reqwest::get(url).await?.error_for_status()?;
                serde_json::from_slice(&response.bytes().await?)?
            }
            Metrics::Operator(command) => command_json(command).await?,
        };
        let counts = value.get("custody").ok_or("custody metrics missing")?.clone();
        eprintln!("BUDGET {label}: {counts}");
        Ok(counts)
    }

    pub(super) fn daemon(
        &self,
        cli: &Cli<'_>,
        data: &Path,
        ca: &Path,
        profiles: &Path,
    ) -> tokio::process::Command {
        let mut command =
            native_client_directory_daemon_command(cli.binary, &cli.socket, data, ca, None);
        command
            .arg("--builtin-nodes")
            .arg(profiles)
            .env("RAMFLUX_SDK_RELAY_QUIC_ADDR", &self.profile.relay.quic_addr)
            .env("RAMFLUX_SDK_RELAY_QUIC_SERVER_NAME", &self.profile.relay.server_name)
            .env("RAMFLUX_ACCOUNT_BACKUP_PASSPHRASE", "custody budget fixture archive passphrase")
            .env("RAMFLUX_BUDGET_RESTORE_PASSPHRASE", "custody budget restored data passphrase");
        command
    }
}

async fn command_json(command: &[String]) -> TestResult<Value> {
    let (program, arguments) = command.split_first().ok_or("inspection command missing")?;
    let child = tokio::process::Command::new(program)
        .args(arguments)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        // Operator credentials and diagnostics must not enter test logs.
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    let output = tokio::time::timeout(Duration::from_secs(30), child.wait_with_output()).await??;
    if !output.status.success() {
        return Err(format!("operator inspection failed: {}", output.status).into());
    }
    Ok(serde_json::from_slice(&output.stdout)?)
}
