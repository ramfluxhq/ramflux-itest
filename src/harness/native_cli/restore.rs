// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! The terminal helper retains recovery words in its own memory and emits only public results.
use super::{NativeCli, TestResult};
use serde_json::{Value, json};
use std::{path::Path, process::Stdio, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::{Child, ChildStdout},
};

pub(crate) struct AttendedRestore {
    child: Child,
    output: BufReader<ChildStdout>,
}
impl AttendedRestore {
    pub(crate) async fn start(source: &NativeCli<'_>) -> TestResult<(Self, Value)> {
        let mut child = tokio::process::Command::new("python3")
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/harness/native_cli/recover.py"))
            .arg(source.binary)
            .arg(&source.socket)
            .env("RESTORE_LOCAL_PASSPHRASE", super::RESTORE_LOCAL_PASSPHRASE)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()?;
        let output = BufReader::new(child.stdout.take().ok_or("ceremony stdout")?);
        let mut session = Self { child, output };
        let account = session.read().await?;
        Ok((session, account))
    }
    async fn read(&mut self) -> TestResult<Value> {
        let mut line = String::new();
        let length =
            tokio::time::timeout(Duration::from_secs(120), self.output.read_line(&mut line))
                .await??;
        if length == 0 {
            return Err("terminal ceremony exited without a public result".into());
        }
        let value = serde_json::from_str(&line)?;
        if let Some(error) = ceremony_error(&value) {
            return Err(error.into());
        }
        Ok(value)
    }
    pub(crate) async fn recover(
        mut self,
        target: &NativeCli<'_>,
        account: &str,
    ) -> TestResult<Value> {
        let request = json!({"socket": target.socket, "account_id": account});
        let mut input = self.child.stdin.take().ok_or("ceremony stdin")?;
        input.write_all(format!("{request}\n").as_bytes()).await?;
        drop(input);
        let recovered = self.read().await?;
        let status = tokio::time::timeout(Duration::from_secs(10), self.child.wait()).await??;
        if !status.success() {
            return Err("terminal recovery ceremony failed".into());
        }
        Ok(recovered)
    }
}

fn ceremony_error(value: &Value) -> Option<String> {
    let error = value.get("fixture_error")?;
    let code = error
        .get("code")
        .and_then(Value::as_str)
        .filter(|code| {
            matches!(
                *code,
                "custody_setup_invalid"
                    | "custody_expired"
                    | "confirmation_failed"
                    | "vault_unavailable"
                    | "no_node"
                    | "fingerprint_mismatch"
                    | "other_cli_error"
                    | "helper_failed"
            )
        })
        .unwrap_or("unclassified");
    Some(format!(
        "attended recovery failed: code={code}, exit={:?}, confirmed={:?}, phrase_sent={:?}, password_sent={:?}",
        error.get("exit").and_then(Value::as_i64),
        error.get("confirmed").and_then(Value::as_u64),
        error.get("phrase_sent").and_then(Value::as_bool),
        error.get("password_sent").and_then(Value::as_bool),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_diagnostics_do_not_echo_unknown_error_values() {
        let private = "private fixture payload";
        let message = ceremony_error(&json!({"fixture_error": {
            "code":private,"detail":private,"exit":1,"confirmed":1,
            "phrase_sent":true,"password_sent":true
        }}))
        .expect("public diagnostic");
        assert!(!message.contains(private));
        assert!(message.contains("code=unclassified"));
        assert!(message.contains("confirmed=Some(1)"));
        assert_eq!(ceremony_error(&json!({"account_id":"installed"})), None);
    }
}
