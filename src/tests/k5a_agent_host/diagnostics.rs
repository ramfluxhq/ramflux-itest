// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Capture redacted host failure evidence without exposing prepared message bodies.
use super::*;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::OpenOptionsExt;
pub(super) struct HostEvidence {
    pub state: PathBuf,
    stderr: PathBuf,
}
impl HostEvidence {
    pub fn new(root: &Path) -> Self {
        Self { state: root.join("cursor.json"), stderr: root.join("agent-host.stderr") }
    }
    pub fn spawn(&self, binary: &Path, config: &Path) -> TestResult<tokio::process::Child> {
        let stderr =
            std::fs::OpenOptions::new().create(true).append(true).mode(0o600).open(&self.stderr)?;
        Ok(tokio::process::Command::new(binary)
            .arg("--config")
            .arg(config)
            .stderr(std::process::Stdio::from(stderr))
            .kill_on_drop(true)
            .spawn()?)
    }
    fn summary(&self) -> Value {
        let state = std::fs::File::open(&self.state)
            .ok()
            .and_then(|file| {
                let mut bytes = Vec::new();
                file.take(524_289).read_to_end(&mut bytes).ok()?;
                if bytes.len() > 524_288 {
                    return None;
                }
                serde_json::from_slice::<Value>(&bytes).ok()
            })
            .unwrap_or(Value::Null);
        let stderr = (|| -> std::io::Result<String> {
            let mut file = std::fs::File::open(&self.stderr)?;
            let size = file.metadata()?.len();
            file.seek(SeekFrom::Start(size.saturating_sub(8192)))?;
            let mut bytes = Vec::new();
            file.take(8192).read_to_end(&mut bytes)?;
            Ok(String::from_utf8_lossy(&bytes).into_owned())
        })()
        .unwrap_or_else(|_| "host stderr unavailable".into());
        json!({"cursor":state["cursor"],"last_refusal":state["last_refusal"],
            "pending_method":state["pending"]["method"],"stderr_tail":stderr})
    }
    pub fn report(&self) {
        eprintln!("K5A HOST FAILURE EVIDENCE: {}", self.summary());
    }
}
#[test]
fn host_failure_evidence_keeps_refusal_and_stderr_but_omits_prepared_payloads() -> TestResult {
    let root = temp_root("host-diagnostics")?;
    let evidence = HostEvidence::new(&root);
    std::fs::write(
        &evidence.state,
        serde_json::to_vec(
            &json!({"cursor":42,"last_refusal":{"reason":"invalid_request"},"pending":{"method":"message.submit","body":{"text":"private prepared reply"}}}),
        )?,
    )?;
    std::fs::write(
        &evidence.stderr,
        format!("{}agent host reconnecting: rfd request or connection failed", "x".repeat(10_000)),
    )?;
    let value = evidence.summary();
    assert_eq!(value["cursor"], 42);
    assert_eq!(value["last_refusal"]["reason"], "invalid_request");
    assert_eq!(value["pending_method"], "message.submit");
    let stderr = value["stderr_tail"].as_str().ok_or("stderr")?;
    assert!(stderr.contains("reconnecting"));
    assert!(stderr.len() <= 8192);
    assert!(!value.to_string().contains("private prepared reply"));
    std::fs::remove_dir_all(root)?;
    Ok(())
}
