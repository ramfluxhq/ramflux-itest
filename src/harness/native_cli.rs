// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Native human CLI ceremonies and consent shared by end-to-end command scenarios.
use crate::*;
use serde_json::Value;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

pub(crate) struct NativeCli<'a> {
    pub(crate) binary: &'a Path,
    pub(crate) socket: PathBuf,
}
impl NativeCli<'_> {
    pub(crate) async fn call(&self, args: &[&str]) -> TestResult<Value> {
        let mut all = vec!["--socket", self.socket.to_str().ok_or("socket encoding")?];
        all.extend_from_slice(args);
        mvp_s10_rf_json(self.binary, &all, &args.join(" ")).await
    }
    pub(crate) async fn call_until(
        &self,
        args: &[&str],
        deadline: tokio::time::Instant,
    ) -> TestResult<Value> {
        let mut all = vec!["--socket", self.socket.to_str().ok_or("socket encoding")?];
        all.extend_from_slice(args);
        mvp_s10_rf_json_until(self.binary, &all, &args.join(" "), deadline).await
    }
    pub(crate) async fn create_pending(&self, name: &str) -> TestResult<Value> {
        let child = tokio::process::Command::new("python3")
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/harness/native_cli/create.py"))
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
        Ok(serde_json::from_slice(&output.stdout)?)
    }
    pub(crate) async fn create(&self, name: &str) -> TestResult<Value> {
        let created = self.create_pending(name).await?;
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
pub(crate) fn field<'a>(value: &'a Value, name: &str) -> TestResult<&'a str> {
    value[name].as_str().ok_or_else(|| format!("missing field {name}: {value}").into())
}
pub(crate) async fn contacts(
    alice: &NativeCli<'_>,
    bob: &NativeCli<'_>,
    node: &S8RealnetNode,
    a: &Value,
    b: &Value,
) -> TestResult {
    contacts_at(alice, bob, &node.node_id, &node.federation_url, a, b).await
}

pub(crate) async fn contacts_at(
    alice: &NativeCli<'_>,
    bob: &NativeCli<'_>,
    node_id: &str,
    federation_url: &str,
    a: &Value,
    b: &Value,
) -> TestResult {
    let aid = field(a, "account_id")?;
    let bid = field(b, "account_id")?;
    let ap = field(a, "principal_id")?;
    let bp = field(b, "principal_id")?;
    alice.call(&["contact", "add", "--account", aid, "--principal", bp]).await?;
    eprintln!("STEP: native_cli wait for incoming contact request");
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
        federation_url,
        "--source-node",
        node_id,
        "--target-node",
        node_id,
        "--recipient-prekey-url",
        federation_url,
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

/// Build the same native diagnostic binary used by operator acceptance.
pub(crate) async fn native_rf_binary() -> TestResult<PathBuf> {
    use std::hash::{Hash, Hasher};
    let target = std::env::var_os("CARGO_TARGET_DIR")
        .map_or_else(|| code_root().join("ramflux/target"), PathBuf::from);
    let target = if target.is_absolute() { target } else { std::env::current_dir()?.join(target) };
    let manifest = code_root().join("ramflux/apps/rf/Cargo.toml");
    // SDK's mixed crate types have unqualified library outputs. Keep this native-only build
    // separate from broader test features and from another source checkout's cached executable.
    let mut source = std::collections::hash_map::DefaultHasher::new();
    manifest.hash(&mut source);
    let target = target.join("native-cli").join(format!("{:016x}", source.finish()));
    let build_target = target.clone();
    let status = tokio::task::spawn_blocking(move || {
        std::process::Command::new("cargo")
            .args(["build", "--quiet", "--features", "itest-memory-vault", "--manifest-path"])
            .arg(manifest)
            .env("CARGO_TARGET_DIR", build_target)
            .env("RAMFLUX_ITEST_BUILD", "1")
            .status()
    })
    .await??;
    if !status.success() {
        return Err("native rf build failed".into());
    }
    Ok(target.join("debug/rf"))
}

#[path = "native_cli/restore.rs"]
mod restore;
pub(crate) use restore::AttendedRestore;

pub(crate) const RESTORE_LOCAL_PASSPHRASE: &str = "restore CLI independent local fixture password";
