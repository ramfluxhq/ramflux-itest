// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Render enabled native custody profiles with their signed fixture inputs and no engine calls.
use super::*;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

fn native_inputs(directory: &Path) -> HarnessResult<Vec<(String, String)>> {
    std::fs::create_dir_all(directory.join("certs/router"))?;
    let mut inputs = crate::harness::custody_node_fixture::provision(
        directory,
        "localhost",
        ramflux_crypto::random_32()?,
    )?;
    for (key, value) in [
        ("RAMFLUX_CUSTODY_HANDSHAKE_POOL", "256"),
        ("RAMFLUX_CUSTODY_AUTHENTICATED_POOL", "1024"),
        ("RAMFLUX_CUSTODY_AUTH_TIMEOUT_MS", "10000"),
    ] {
        inputs.push((key.into(), value.into()));
    }
    Ok(inputs)
}

fn check_native_render(
    command: &mut std::process::Command,
    deploy: &Path,
    provider: &str,
    gateways: usize,
    env: &[(String, String)],
) -> HarnessResult<()> {
    command.arg("config");
    if provider == "docker" {
        command.args(["--format", "json"]);
    }
    let rendered =
        command.envs(env.iter().map(|(key, value)| (key, value))).current_dir(deploy).output()?;
    assert!(rendered.status.success(), "native Compose config render failed");
    let mut checker = std::process::Command::new("python3")
        .args(["-I", "-B", "-c", include_str!("compose_native_inventory.py")])
        .arg(deploy)
        .arg(provider)
        .arg(gateways.to_string())
        .envs(env.iter().map(|(key, value)| (key, value)))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    checker.stdin.take().ok_or("native render checker stdin")?.write_all(&rendered.stdout)?;
    let validation = checker.wait_with_output()?;
    assert!(validation.status.success(), "{}", String::from_utf8_lossy(&validation.stderr));
    eprintln!("native rendered inputs: {}", String::from_utf8_lossy(&validation.stdout).trim());
    Ok(())
}

#[test]
fn native_custody_profiles_preserve_all_inputs_through_product_preflight() -> HarnessResult<()> {
    if std::env::var("RAMFLUX_ITEST_PREFLIGHT_NATIVE").as_deref() != Ok("1") {
        eprintln!("native config-only proof not requested");
        return Ok(());
    }
    let provider = crate::container_runtime()?;
    let deploy = super::super::self_referencing_defaults::pinned_product_deploy_dir()?
        .ok_or("pinned product checkout required")?;
    let material = SecurityMaterial::generate()?;
    let inputs = native_inputs(&material.directory)?;
    let env = super::super::compose_env_with_required_defaults(&inputs)?;
    let expected = super::super::compose_input_aliases::MIGRATED_KEYS
        .iter()
        .copied()
        .filter(|key| key.starts_with("RAMFLUX_CUSTODY_"))
        .collect::<std::collections::BTreeSet<_>>();
    let supplied =
        inputs.iter().map(|(key, _)| key.as_str()).collect::<std::collections::BTreeSet<_>>();
    assert_eq!(supplied, expected, "cover every native custody Compose alias");
    for (key, expected) in &inputs {
        let alias = super::super::compose_input_aliases::alias(key).ok_or("custody alias")?;
        assert!(!expected.is_empty(), "explicit native inputs must be configured");
        assert!(env.contains(&(key.clone(), expected.clone())));
        assert!(env.contains(&(alias, expected.clone())));
    }
    let engine = material.directory.join("config-only-engine");
    std::fs::write(
        &engine,
        "#!/bin/sh\nif [ \"$1\" = --version ]; then echo 'podman version 5.4.2'; exit 0; fi\nexit 91\n",
    )?;
    std::fs::set_permissions(&engine, std::fs::Permissions::from_mode(0o700))?;
    let production =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/custody-production.compose.yml");
    for (label, gateways, files) in [
        ("production", 1, vec![deploy.join("docker-compose.yml"), production]),
        ("itest", 1, vec![deploy.join("docker-compose.itest.yml")]),
        (
            "k2b",
            2,
            vec![
                deploy.join("docker-compose.itest.yml"),
                deploy.join("docker-compose.itest.cross-gateway.yml"),
                deploy.join("docker-compose.itest.object-v3.yml"),
            ],
        ),
    ] {
        let mut compose = std::process::Command::new(provider);
        compose.arg("compose");
        if provider == "podman" {
            compose.arg("--podman-path").arg(&engine);
        }
        let _file = super::super::add_compose_env_file_arg(&mut compose, "native-render", &env)?;
        compose.args(["-p", "ramflux-native-config-only"]);
        for file in &files {
            compose.arg("-f").arg(file);
        }
        super::super::run_compose_preflight(&compose, &deploy, &env)?;
        check_native_render(&mut compose, &deploy, provider, gateways, &env)?;
        eprintln!("native product preflight config-only PASS: provider={provider} profile={label}");
    }
    std::fs::remove_dir_all(material.directory)?;
    Ok(())
}
