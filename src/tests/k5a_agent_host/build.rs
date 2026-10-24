// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Build the exact executable path launched by this fixture, independent of parent target settings.
use super::*;
pub(super) async fn binary(
    name: &str,
    manifest: &Path,
    features: Option<&str>,
) -> TestResult<PathBuf> {
    let target = code_root().join("ramflux/target");
    let mut command = tokio::process::Command::new("cargo");
    command
        .args(["build", "--bin", name, "--manifest-path"])
        .arg(manifest)
        .arg("--target-dir")
        .arg(&target)
        .env_remove("CARGO_TARGET_DIR");
    if let Some(features) = features {
        command.args(["--features", features]);
    }
    if !command.status().await?.success() {
        return Err(format!("failed to build {name}").into());
    }
    let path = target.join("debug").join(name);
    let metadata = std::fs::metadata(&path)?;
    eprintln!("STEP: k5a built binary={name} path={} bytes={}", path.display(), metadata.len());
    Ok(path)
}
