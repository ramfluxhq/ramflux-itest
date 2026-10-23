// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Opt-in service logs on fixture failure, collected before compose teardown.
use super::{
    ItestComposeOverrides, add_compose_env_file_arg, add_itest_compose_files,
    compose_env_with_required_defaults, container_runtime,
};
use crate::realnet_step;
use std::path::Path;

pub(crate) const COMPOSE_FAILURE_LOG_SERVICES_ENV: &str = "RAMFLUX_ITEST_FAILURE_LOG_SERVICES";

pub(super) fn dump_compose_failure_logs(
    deploy_root: &Path,
    project_name: &str,
    env: &[(String, String)],
    overrides: ItestComposeOverrides,
) {
    let Some((_, services)) = env.iter().find(|(key, _)| key == COMPOSE_FAILURE_LOG_SERVICES_ENV)
    else {
        return;
    };
    let compose_env = compose_env_with_required_defaults(env);
    for service in services.split(',').filter(|service| !service.is_empty()) {
        realnet_step(
            "failure container logs begin",
            format!("project={project_name} service={service}"),
        );
        let result =
            collect_service_logs(deploy_root, project_name, &compose_env, overrides, service);
        match result {
            Ok(output) => {
                eprintln!("{}", String::from_utf8_lossy(&output.stdout));
                eprintln!("{}", String::from_utf8_lossy(&output.stderr));
                realnet_step(
                    "failure container logs end",
                    format!("project={project_name} service={service} exit={}", output.status),
                );
            }
            Err(error) => realnet_step(
                "failure container logs unavailable",
                format!("project={project_name} service={service}: {error}"),
            ),
        }
    }
}

fn collect_service_logs(
    deploy_root: &Path,
    project_name: &str,
    env: &[(String, String)],
    overrides: ItestComposeOverrides,
    service: &str,
) -> Result<std::process::Output, Box<dyn std::error::Error>> {
    let mut command = std::process::Command::new(container_runtime());
    command.arg("compose");
    let _env_file = add_compose_env_file_arg(&mut command, project_name, env)?;
    command.arg("-p").arg(project_name);
    add_itest_compose_files(&mut command, overrides);
    Ok(command
        .args(["logs", "--timestamps", service])
        .envs(env.iter().map(|(key, value)| (key, value)))
        .current_dir(deploy_root)
        .output()?)
}

#[cfg(unix)]
mod tests {
    use super::*;
    use crate::ComposeProjectDownGuard;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn failure_logs_precede_teardown_for_errors_and_unwinding()
    -> Result<(), Box<dyn std::error::Error>> {
        if let Ok(mode) = std::env::var("RAMFLUX_ITEST_DIAGNOSTIC_CHILD_MODE") {
            return exercise_guard(&mode);
        }
        let root = crate::temp_root("compose_failure_log_order")?;
        let runtime = root.join("docker");
        std::fs::write(
            &runtime,
            r#"#!/bin/sh
if [ "$1" = --version ]; then exit 0; fi
while [ "$#" -gt 0 ]; do
    case "$1" in
        logs)
            shift
            shift
            printf 'logs %s\n' "$1" >> "$RAMFLUX_ITEST_DIAGNOSTIC_JOURNAL"
            printf 'fixture log stdout: %s\n' "$1"
            printf 'fixture log stderr: %s\n' "$1" >&2
            if [ "$RAMFLUX_ITEST_DIAGNOSTIC_CHILD_MODE" = logs-error ] && [ "$1" = ramflux-relay ]; then exit 7; fi
            exit 0 ;;
        down) printf 'down\n' >> "$RAMFLUX_ITEST_DIAGNOSTIC_JOURNAL"; exit 0 ;;
    esac
    shift
done
exit 0
"#,
        )?;
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o755))?;
        let test_name = concat!(
            "harness::realnet_compose_stun::failure_diagnostics::tests::",
            "failure_logs_precede_teardown_for_errors_and_unwinding"
        );
        for mode in ["error", "panic", "success", "logs-error"] {
            let journal = root.join(format!("{mode}.journal"));
            let output = std::process::Command::new(std::env::current_exe()?)
                .args(["--exact", test_name, "--nocapture", "--test-threads=1"])
                .env("PATH", &root)
                .env("RAMFLUX_ITEST_DIAGNOSTIC_CHILD_MODE", mode)
                .env("RAMFLUX_ITEST_DIAGNOSTIC_JOURNAL", &journal)
                .env("RAMFLUX_ITEST_DIAGNOSTIC_DEPLOY_ROOT", &root)
                .env_remove("RAMFLUX_ITEST_LOG_DIR")
                .output()?;
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(output.status.success(), "mode={mode}\n{stdout}\n{stderr}");
            // An exact filter matching no tests also exits zero; require the child actually ran.
            assert!(stdout.contains("1 passed"), "child did not exercise the guard: {stdout}");
            for line in stderr.lines().filter(|line| line.starts_with("STEP:")) {
                let (_, timestamp) =
                    line.rsplit_once(" ts_unix_ms=").ok_or("STEP timestamp missing")?;
                assert!(timestamp.parse::<u128>()? > 0, "invalid STEP timestamp: {line}");
            }
            let commands = std::fs::read_to_string(journal)?;
            if mode == "success" {
                assert_eq!(commands, "down\n");
                assert!(!stderr.contains("fixture log stdout"));
            } else {
                assert_eq!(
                    commands,
                    "logs ramflux-relay\nlogs ramflux-gateway\nlogs ramflux-gateway-b\ndown\n"
                );
                for service in ["ramflux-relay", "ramflux-gateway", "ramflux-gateway-b"] {
                    assert!(stderr.contains(&format!("fixture log stdout: {service}")));
                    assert!(stderr.contains(&format!("fixture log stderr: {service}")));
                }
                assert!(!stdout.contains("fixture log stdout"));
                if mode == "logs-error" {
                    assert!(stderr.contains("exit status: 7"));
                }
            }
        }
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    fn exercise_guard(mode: &str) -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::var("RAMFLUX_ITEST_DIAGNOSTIC_DEPLOY_ROOT")?;
        let env = vec![(
            COMPOSE_FAILURE_LOG_SERVICES_ENV.to_owned(),
            "ramflux-relay,ramflux-gateway,ramflux-gateway-b".to_owned(),
        )];
        let guard = ComposeProjectDownGuard::new(
            root.into(),
            "ramflux-log-order-fixture".to_owned(),
            env,
            false,
        );
        if mode == "panic" {
            let outcome = std::panic::catch_unwind(move || {
                let _guard = guard;
                assert!(std::hint::black_box(false), "injected assertion failure");
            });
            assert!(outcome.is_err());
        } else if mode == "success" {
            let mut guard = guard;
            guard.env.retain(|(key, _)| key != COMPOSE_FAILURE_LOG_SERVICES_ENV);
        } else {
            let outcome: Result<(), Box<dyn std::error::Error>> = {
                let _guard = guard;
                Err("injected flow error".into())
            };
            assert_eq!(
                outcome.err().ok_or("expected injected failure")?.to_string(),
                "injected flow error"
            );
        }
        Ok(())
    }
}
