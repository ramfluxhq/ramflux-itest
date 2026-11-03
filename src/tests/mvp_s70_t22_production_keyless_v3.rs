// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#[cfg(feature = "realnet")]
use super::*;

#[cfg(feature = "realnet")]
const TRUST_KEYS: [&str; 3] = [
    "RAMFLUX_FEDERATION_TRUST_ENDPOINT",
    "RAMFLUX_FEDERATION_PROVIDER_OFFLINE_ROOT_PUBLIC_KEY",
    "RAMFLUX_FEDERATION_TRUST_ISSUER_NODE_ID",
];

// Use `compose version --short`, not the human-readable banner or executable name.
fn docker_v2(version: &str) -> bool {
    let version = version.trim().trim_start_matches('v');
    let Some((major, rest)) = version.split_once('.') else { return false };
    major.parse::<u64>().is_ok_and(|major| major >= 2)
        && rest.split('.').next().is_some_and(|minor| minor.parse::<u64>().is_ok())
        && !version.to_ascii_lowercase().contains("podman")
}

#[test]
fn compose_provider_detection_does_not_mistake_a_docker_shim_for_docker_v2() {
    for version in ["v2.39.1", "2.39.1", "5.0.0", "v10.1.0\n"] {
        assert!(docker_v2(version), "{version}");
    }
    for version in [
        "",
        "1.29.2",
        "Docker Compose version v2.39.1",
        "podman-compose version 1.3.0",
        "5.8.1 podman",
        "Emulate Docker CLI using podman. 2.39.1",
    ] {
        assert!(!docker_v2(version), "{version}");
    }
}

#[cfg(feature = "realnet")]
fn clean_command(program: &str, env: &[(String, String)]) -> std::process::Command {
    let mut command = std::process::Command::new(program);
    for (key, _) in std::env::vars_os() {
        if key
            .to_str()
            .is_some_and(|key| key.starts_with("RAMFLUX_") || key.starts_with("RF_COMPOSE_"))
        {
            command.env_remove(key);
        }
    }
    command.envs(env.iter().map(|(key, value)| (key, value)));
    command
}

#[cfg(feature = "realnet")]
fn provider() -> Result<(String, Vec<&'static str>), Box<dyn std::error::Error>> {
    let selected = match std::env::var("RAMFLUX_S70_COMPOSE_PROVIDER") {
        Ok(selected) => selected,
        Err(_) => container_runtime()?.to_owned(),
    };
    match selected.as_str() {
        "docker" | "podman" => Ok((selected, vec!["compose"])),
        "podman-compose" => Ok((selected, vec![])),
        _ => Err("RAMFLUX_S70_COMPOSE_PROVIDER must be docker, podman or podman-compose".into()),
    }
}

#[cfg(feature = "realnet")]
#[test]
fn t22_production_keyless_v3_compose_smoke() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_T22_PRODUCTION_SMOKE").as_deref() != Ok("1") {
        eprintln!("skipping T22 production compose smoke; set RAMFLUX_T22_PRODUCTION_SMOKE=1");
        return Ok(());
    }
    let deploy = code_root().join("ramflux/deploy");
    let compose_path = deploy.join("docker-compose.yml");
    let compose = std::fs::read_to_string(&compose_path)?;
    assert!(!compose.contains("RAMFLUX_RELAY_SERVICE_KEY_REF"));
    for key in TRUST_KEYS {
        assert!(compose.contains(&format!("{key}: \"${{{key}:?")));
    }
    let env = production_inputs(&compose)?;
    let (program, prefix) = provider()?;
    let mut version_command = clean_command(&program, &env);
    version_command.args(&prefix).arg("version");
    if program == "docker" {
        version_command.arg("--short");
    }
    let version = version_command.output()?;
    assert!(version.status.success(), "Compose provider version failed");
    let version = format!(
        "{}{}",
        String::from_utf8_lossy(&version.stdout),
        String::from_utf8_lossy(&version.stderr)
    );
    eprintln!("s70 provider: {}", version.trim());
    let is_docker_v2 = docker_v2(&version);
    assert!(program != "docker" || is_docker_v2, "docker leg requires Docker Compose v2+");
    check_preflight(&deploy, &compose_path, &env, &program, is_docker_v2)?;
    if is_docker_v2 {
        let inputs: Vec<_> =
            env.iter().filter(|(key, _)| !TRUST_KEYS.contains(&key.as_str())).cloned().collect();
        let file = write_compose_env_file("s70-docker-negative", &inputs)?;
        let output = clean_command(&program, &inputs)
            .args(&prefix)
            .arg("--env-file")
            .arg(file.path())
            .arg("-f")
            .arg(&compose_path)
            .arg("config")
            .current_dir(&deploy)
            .output()?;
        assert!(!output.status.success(), "Docker v2 accepted missing required inputs");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(TRUST_KEYS.iter().any(|key| stderr.contains(key)));
        eprintln!("s70 docker-v2 config refusal checked");
    }
    check_startup(&program, &prefix)
}

#[cfg(feature = "realnet")]
fn production_inputs(compose: &str) -> Result<Vec<(String, String)>, Box<dyn std::error::Error>> {
    let mut env = compose_env_with_required_defaults(&[])?;
    // Preflight validates presence, not cryptographic correctness. Fill unrelated
    // production inputs so a failure cannot be attributed to a different key.
    for part in compose.split("${").skip(1) {
        if let Some((key, _)) = part.split_once(":?")
            && key.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
            && !env.iter().any(|(existing, _)| existing == key)
        {
            env.push((key.to_owned(), "s70-concrete-fixture-input".to_owned()));
        }
    }
    Ok(env)
}

#[cfg(feature = "realnet")]
fn check_preflight(
    deploy: &Path,
    compose_path: &Path,
    env: &[(String, String)],
    program: &str,
    is_docker_v2: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let preflight = |file: &Path, inputs: &[(String, String)]| {
        clean_command("python3", inputs)
            .arg(deploy.join("scripts/compose-preflight.py"))
            .args(["--provider", program])
            .arg("--env-file")
            .arg(file)
            .arg("-f")
            .arg(compose_path)
            .current_dir(deploy)
            .output()
    };
    let good_file = write_compose_env_file("s70-valid", env)?;
    let good = preflight(good_file.path(), env)?;
    assert!(
        good.status.success(),
        "positive preflight control failed: {}",
        String::from_utf8_lossy(&good.stderr)
    );
    for key in TRUST_KEYS {
        for bad in [None, Some(""), Some("  "), Some("${S70_DO_NOT_LOG:?private-sentinel}")] {
            let mut inputs = env.to_vec();
            inputs.retain(|(name, _)| name != key);
            // Inject the value into the process environment, where dotenv expansion
            // cannot accidentally turn a literal expression into an empty string.
            let file = write_compose_env_file("s70-negative", &inputs)?;
            if let Some(bad) = bad {
                inputs.push((key.to_owned(), bad.to_owned()));
            }
            let output = preflight(file.path(), &inputs)?;
            assert!(!output.status.success(), "preflight accepted invalid {key}");
            assert_eq!(
                String::from_utf8_lossy(&output.stderr).trim(),
                format!(
                    "Compose preflight refused settings: {}",
                    // Both providers refuse an explicitly empty :? value during rendering.
                    // Docker also refuses an absent value; Podman 1.3 leaves it literal.
                    if bad == Some("") || (is_docker_v2 && bad.is_none()) {
                        "CONFIG_RENDER"
                    } else {
                        key
                    }
                )
            );
            assert!(output.stdout.is_empty(), "preflight must not print configuration");
        }
    }
    Ok(())
}

#[cfg(feature = "realnet")]
fn check_startup(program: &str, prefix: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    // Deliberately bypass preflight. An isolated real relay image has no mounts,
    // ports or dependencies; startup must reject the literal before reading config.
    let image = std::env::var("RAMFLUX_S70_RELAY_IMAGE")
        .ok()
        .filter(|image| !image.trim().is_empty())
        .ok_or("set RAMFLUX_S70_RELAY_IMAGE to an image built from the pinned product")?;
    let root = temp_root("s70-startup")?;
    let startup = root.join("compose.json");
    std::fs::write(
        &startup,
        serde_json::to_vec(&serde_json::json!({
            "services": {"relay": {"image": image}}
        }))?,
    )?;
    let mut cleanup = clean_command(program, &[]);
    cleanup
        .args(prefix)
        .arg("-p")
        .arg(format!("s70-{}", std::process::id()))
        .arg("-f")
        .arg(&startup)
        .arg("down");
    let _cleanup = StartupCleanup { command: cleanup, root };
    for key in TRUST_KEYS {
        let output = clean_command(program, &[])
            .args(prefix)
            .arg("-p")
            .arg(format!("s70-{}", std::process::id()))
            .arg("-f")
            .arg(&startup)
            .args(["run", "--rm", "--no-deps", "-T", "-e"])
            .arg(format!("{key}=${{S70_DO_NOT_LOG:?private-sentinel}}"))
            .args(["relay", "--config", "/s70/no-config.toml"])
            .output()?;
        assert!(!output.status.success(), "relay accepted unresolved {key}");
        let diagnostic = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            diagnostic.contains(&format!("unexpanded environment setting: {key}")),
            "relay must return the typed unresolved-input error for {key}: {diagnostic}"
        );
        assert!(!diagnostic.contains("S70_DO_NOT_LOG"));
        assert!(!diagnostic.contains("private-sentinel"));
    }
    Ok(())
}

#[cfg(feature = "realnet")]
struct StartupCleanup {
    command: std::process::Command,
    root: PathBuf,
}

#[cfg(feature = "realnet")]
impl Drop for StartupCleanup {
    fn drop(&mut self) {
        if !self.command.output().is_ok_and(|output| output.status.success()) {
            eprintln!("s70 isolated startup project cleanup failed");
        }
        let _removed = std::fs::remove_dir_all(&self.root);
    }
}
