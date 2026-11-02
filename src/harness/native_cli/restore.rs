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
        Ok(serde_json::from_str(&line)?)
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
