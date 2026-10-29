// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Resolve one container engine for startup, preflight, diagnostics, and cleanup.
use std::sync::OnceLock;

const OVERRIDE: &str = "RAMFLUX_ITEST_CONTAINER_RUNTIME";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ContainerRuntimeError {
    InvalidOverride,
    Unavailable,
}

impl std::fmt::Display for ContainerRuntimeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidOverride => "RAMFLUX_ITEST_CONTAINER_RUNTIME must be docker or podman",
            Self::Unavailable => "neither docker nor podman has a successful version probe",
        })
    }
}

impl std::error::Error for ContainerRuntimeError {}

/// Resolve and cache the explicit override or the first supported engine.
///
/// # Errors
/// Returns a typed error for an invalid override or unavailable engines.
pub(crate) fn container_runtime() -> Result<&'static str, ContainerRuntimeError> {
    static RUNTIME: OnceLock<Result<&'static str, ContainerRuntimeError>> = OnceLock::new();
    *RUNTIME.get_or_init(detect_runtime)
}

fn detect_runtime() -> Result<&'static str, ContainerRuntimeError> {
    if let Some(value) = std::env::var_os(OVERRIDE) {
        return match value.to_str() {
            Some("docker") => Ok("docker"),
            Some("podman") => Ok("podman"),
            _ => Err(ContainerRuntimeError::InvalidOverride),
        };
    }
    if let Ok(output) = std::process::Command::new("docker").arg("--version").output()
        && output.status.success()
    {
        // Podman emulation identifies itself in the version or shim banner, on either
        // stream. A successful command alone does not establish a Docker Compose provider.
        let is_podman = [&output.stdout, &output.stderr]
            .iter()
            .any(|bytes| String::from_utf8_lossy(bytes).to_ascii_lowercase().contains("podman"));
        return Ok(if is_podman { "podman" } else { "docker" });
    }
    if let Ok(output) = std::process::Command::new("podman").arg("--version").output()
        && output.status.success()
    {
        return Ok("podman");
    }
    Err(ContainerRuntimeError::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn run_case(
        name: &str,
        docker: &str,
        podman: &str,
        override_value: Option<&str>,
        expected: &str,
    ) -> TestResult {
        if let Ok(expected) = std::env::var("RAMFLUX_ITEST_RUNTIME_EXPECTED") {
            let result = container_runtime();
            assert_eq!(result, container_runtime(), "resolution must be stable within a process");
            match expected.as_str() {
                "invalid" => assert_eq!(result, Err(ContainerRuntimeError::InvalidOverride)),
                "unavailable" => assert_eq!(result, Err(ContainerRuntimeError::Unavailable)),
                runtime => assert_eq!(result?, runtime),
            }
            return Ok(());
        }
        let root = crate::temp_root("container_runtime_probe")?;
        let journal = root.join("probes");
        for (binary, body) in [("docker", docker), ("podman", podman)] {
            let path = root.join(binary);
            std::fs::write(
                &path,
                format!(
                    "#!/bin/sh\nprintf '{binary}\\n' >> \"$RAMFLUX_ITEST_RUNTIME_JOURNAL\"\n{body}\n"
                ),
            )?;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
        }
        let mut child = std::process::Command::new(std::env::current_exe()?);
        child
            .args(["--exact", name, "--nocapture", "--test-threads=1"])
            .env("PATH", &root)
            .env("RAMFLUX_ITEST_RUNTIME_EXPECTED", expected)
            .env("RAMFLUX_ITEST_RUNTIME_JOURNAL", &journal)
            .env_remove(OVERRIDE);
        if let Some(value) = override_value {
            child.env(OVERRIDE, value);
        }
        let output = child.output()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(output.status.success(), "{stdout}\n{}", String::from_utf8_lossy(&output.stderr));
        assert!(stdout.contains("1 passed"), "child must run the exact check: {stdout}");
        let probes = std::fs::read_to_string(&journal).unwrap_or_default();
        let expected_probes = if override_value.is_some() {
            0
        } else if docker.contains("exit 1") {
            2
        } else {
            1
        };
        assert_eq!(probes.lines().count(), expected_probes, "probe results must be cached");
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn detects_podman_shim_on_path() -> TestResult {
        let name = concat!("harness::container_runtime::tests::", "detects_podman_shim_on_path");
        run_case(
            name,
            "echo 'Emulate Docker CLI using PoDmAn' >&2\necho 'Docker version 27.0.0'",
            "exit 1",
            None,
            "podman",
        )?;
        run_case(name, "echo 'podman version 5.4.2'", "exit 1", None, "podman")
    }

    #[test]
    fn detects_real_docker_on_path() -> TestResult {
        run_case(
            concat!("harness::container_runtime::tests::", "detects_real_docker_on_path"),
            "echo 'Docker version 28.0.4, build test'",
            "exit 1",
            None,
            "docker",
        )
    }

    #[test]
    fn runtime_override_wins() -> TestResult {
        let name = concat!("harness::container_runtime::tests::", "runtime_override_wins");
        for runtime in ["docker", "podman"] {
            run_case(name, "exit 1", "exit 1", Some(runtime), runtime)?;
        }
        Ok(())
    }

    #[test]
    fn invalid_runtime_override_is_typed_error() -> TestResult {
        run_case(
            concat!(
                "harness::container_runtime::tests::",
                "invalid_runtime_override_is_typed_error"
            ),
            "echo Docker",
            "echo podman",
            Some("other"),
            "invalid",
        )
    }

    #[test]
    fn falls_back_to_podman_and_reports_missing_engines() -> TestResult {
        let name = concat!(
            "harness::container_runtime::tests::",
            "falls_back_to_podman_and_reports_missing_engines"
        );
        run_case(name, "exit 1", "echo 'podman version 5.4.2'", None, "podman")?;
        run_case(name, "exit 1", "exit 1", None, "unavailable")
    }
}
