// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Isolate minimal Compose fixtures from the caller's stack and engine overrides.
use std::{path::Path, process::Command};

pub(super) fn sanitize(command: &mut Command) {
    let names = std::env::vars_os()
        .map(|(name, _)| name)
        .chain(command.get_envs().map(|(name, _)| name.to_owned()))
        .filter(|name| {
            ["COMPOSE_", "DOCKER_", "PODMAN_", "CONTAINER_"]
                .iter()
                .any(|prefix| name.as_encoded_bytes().starts_with(prefix.as_bytes()))
        })
        .collect::<Vec<_>>();
    for name in names {
        // Keep explicit removals: the shared preflight copies get_envs() into its
        // own command, so it must receive the same removals as the provider.
        command.env_remove(name);
    }
}

pub(super) fn runtime_command(runtime: &str) -> Command {
    let mut command = Command::new(runtime);
    sanitize(&mut command);
    command
}

pub(super) fn compose_command(runtime: &str, directory: &Path, project: &str) -> Command {
    let mut command = runtime_command(runtime);
    command
        .args(["compose", "-p", project, "-f"])
        .arg(directory.join("docker-compose.itest.yml"))
        .current_dir(directory);
    command
}

#[test]
fn fixture_commands_remove_inherited_compose_and_engine_overrides()
-> Result<(), Box<dyn std::error::Error>> {
    const CHILD: &str = "RAMFLUX_ITEST_CLEAN_FIXTURE_CHILD";
    const OVERRIDES: &[&str] = &[
        "COMPOSE_FILE",
        "COMPOSE_PROJECT_NAME",
        "COMPOSE_PROFILES",
        "COMPOSE_PATH_SEPARATOR",
        "COMPOSE_ENV_FILES",
        "COMPOSE_PROJECT_DIR",
        "COMPOSE_DISABLE_ENV_FILE",
        "COMPOSE_FUTURE_SETTING",
        "DOCKER_HOST",
        "DOCKER_CONTEXT",
        "DOCKER_CONFIG",
        "DOCKER_TLS_VERIFY",
        "DOCKER_CERT_PATH",
        "CONTAINER_HOST",
        "CONTAINER_CONNECTION",
        "PODMAN_COMPOSE_PROVIDER",
    ];
    if std::env::var(CHILD).as_deref() != Ok("1") {
        let mut child = Command::new(std::env::current_exe()?);
        child
            .args([
                "--exact",
                concat!(
                    "harness::realnet_compose_stun::compose_network::fixture_commands::",
                    "fixture_commands_remove_inherited_compose_and_engine_overrides"
                ),
                "--nocapture",
            ])
            .env(CHILD, "1");
        for name in OVERRIDES {
            child.env(name, "/nonexistent.yml");
        }
        assert!(child.status()?.success());
        return Ok(());
    }
    assert_eq!(std::env::var("COMPOSE_FILE")?, "/nonexistent.yml");
    let directory = std::env::temp_dir().join("fixture-command-only");
    let command = compose_command("fixture-provider", &directory, "fixture-project");
    let environment = command.get_envs().collect::<std::collections::BTreeMap<_, _>>();
    for name in OVERRIDES {
        assert_eq!(environment.get(std::ffi::OsStr::new(name)), Some(&None), "remove {name}");
    }
    let args = command.get_args().collect::<Vec<_>>();
    assert_eq!(&args[..4], ["compose", "-p", "fixture-project", "-f"]);
    assert_eq!(args[4], directory.join("docker-compose.itest.yml"));
    // The child starts with the polluted process environment. The actual command
    // must remove it without changing that process or losing ordinary host inputs.
    let mut shell = runtime_command("sh");
    shell.args([
        "-c",
        "test -z \"${COMPOSE_FILE+x}\" && test -z \"${DOCKER_HOST+x}\" && test -n \"$PATH\"",
    ]);
    assert!(shell.status()?.success());
    assert_eq!(std::env::var("COMPOSE_FILE")?, "/nonexistent.yml");
    Ok(())
}
