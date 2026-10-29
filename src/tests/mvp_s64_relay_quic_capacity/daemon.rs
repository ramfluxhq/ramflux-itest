// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Build and launch the capacity fixture's explicitly enabled integration daemon.
use super::*;

#[cfg(feature = "realnet")]
pub(super) fn s64_release_build() -> bool {
    std::env::var("RAMFLUX_PERF_RELEASE").as_deref() == Ok("1")
}

#[cfg(feature = "realnet")]
pub(super) async fn s64_build_rf_binary() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let manifest = code_root().join("ramflux/apps/rf/Cargo.toml");
    let release = s64_release_build();
    let status = tokio::task::spawn_blocking(move || {
        let mut command = std::process::Command::new("cargo");
        command.env("RAMFLUX_ITEST_BUILD", "1");
        command.args([
            "build",
            "--quiet",
            "--features",
            "itest-local-mint,itest-memory-vault,itest-legacy-accounts",
        ]);
        if release {
            command.arg("--release");
        }
        command.arg("--manifest-path").arg(manifest).status()
    })
    .await??;
    if !status.success() {
        return Err("failed to build rf binary for s64".into());
    }
    let profile = if release { "release" } else { "debug" };
    Ok(crate::harness::legacy_accounts::target_dir().join(profile).join("rf"))
}

#[cfg(feature = "realnet")]
pub(super) fn s64_spawn_rf_daemon_with_env(
    rf_binary: &Path,
    socket: &str,
    data_root: &str,
    env: &[(String, String)],
) -> Result<tokio::process::Child, Box<dyn std::error::Error>> {
    let log_path = format!("{}.daemon.log", socket.trim_end_matches(".sock"));
    let stderr = std::fs::OpenOptions::new().create(true).append(true).open(&log_path)?;
    let child = tokio::process::Command::new(rf_binary)
        .args([
            "--socket",
            socket,
            "daemon",
            "start",
            "--itest-legacy-accounts",
            "--data-root",
            data_root,
        ])
        .envs(env.iter().map(|(key, value)| (key.clone(), value.clone())))
        .env_remove("RAMFLUX_SDK_OBJECT_RELAY_LOCAL_MINT")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::from(stderr))
        .kill_on_drop(true)
        .spawn()?;
    Ok(child)
}
