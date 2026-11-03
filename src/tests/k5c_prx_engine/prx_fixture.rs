// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! One immutable external-engine source identity for this fixture.
pub(super) const PRX_SHA: &str = "0785e3f82c87da243b6fd1e64c9a9ba3769d17f7";

#[cfg(feature = "realnet")]
pub(super) mod runtime {
    use super::super::TestResult;
    use super::PRX_SHA;
    use crate::harness::container_runtime;
    use serde_json::Value;
    use std::{fs, os::unix::fs::PermissionsExt, path::Path, process::Command};
    pub(crate) struct PrxProcess {
        runtime: &'static str,
        name: String,
    }
    impl PrxProcess {
        pub(crate) fn diagnostics(&self) {
            if let Ok(output) = Command::new(self.runtime)
                .args(["inspect", "--format", "{{.State.Status}} {{.State.ExitCode}}", &self.name])
                .output()
            {
                eprintln!(
                    "STEP: k5c failure prx_process={}",
                    String::from_utf8_lossy(&output.stdout).trim()
                );
            }
        }
    }
    impl Drop for PrxProcess {
        fn drop(&mut self) {
            let _ = Command::new(self.runtime).args(["rm", "--force", &self.name]).output();
        }
    }
    fn id(flag: &str) -> TestResult<String> {
        let output = Command::new("id").arg(flag).output()?;
        if !output.status.success() {
            return Err("cannot determine fixture uid/gid".into());
        }
        Ok(String::from_utf8(output.stdout)?.trim().into())
    }
    pub(crate) fn start(root: &Path, account: &str, port: u16) -> TestResult<PrxProcess> {
        let runtime = container_runtime()?;
        let tag = format!("localhost/ramflux-itest-prx:{}", &PRX_SHA[..8]);
        let inspect = Command::new(runtime).args(["image", "inspect", &tag]).output()?;
        if !inspect.status.success() {
            return Err("build the pinned fixtures/prx/Containerfile image before the slice".into());
        }
        let images: Value = serde_json::from_slice(&inspect.stdout)?;
        let image =
            images.as_array().and_then(|v| v.first()).ok_or("fixture image inspect empty")?;
        let revision = image["Config"]["Labels"]["org.opencontainers.image.revision"]
            .as_str()
            .ok_or("fixture image revision absent")?;
        assert_eq!(revision, PRX_SHA);
        let image_id = image["Id"].as_str().ok_or("fixture image ID absent")?;
        eprintln!("STEP: k5c pinned PRX revision={revision} image={image_id}");
        let home = root.join("prx-home");
        let config = home.join(".openprx");
        let workspace = config.join("workspace");
        let run = root.join("prx-run");
        for path in [&home, &config, &workspace, &run] {
            fs::create_dir_all(path)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
        let tool = workspace.join("k5c-tool.txt");
        fs::write(&tool, "K5C_TOOL_EXECUTED")?;
        fs::set_permissions(tool, fs::Permissions::from_mode(0o600))?;
        let account = serde_json::to_string(account)?;
        let body = format!(
            r#"api_key = "fixture-key"
default_provider = "custom:http://127.0.0.1:{port}/v1"
default_model = "fixture-model"
[memory]
backend = "sqlite"
auto_save = true
[autonomy]
level = "full"
workspace_only = true
[channels_config]
cli = false
[channels_config.ramflux]
socket_path = "/run/k5c/ramflux.sock"
authorization_mode = "follow_rf"
max_in_flight_per_conversation = 1
on_new_message = "queue"
turn_wall_clock_secs = 45
encrypt_at_rest = true
[channels_config.ramflux.accounts.{account}]
cross_conversation_retrieval = false
"#
        );
        let path = config.join("config.toml");
        fs::write(&path, body)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        let name = format!("k5c-prx-{}", std::process::id());
        let mut command = Command::new(runtime);
        command.args([
            "run",
            "-d",
            "--name",
            &name,
            "--network",
            "host",
            "--user",
            &format!("{}:{}", id("-u")?, id("-g")?),
        ]);
        if runtime == "podman" {
            command.args(["--userns", "keep-id"]);
        }
        command.args([
            "-v",
            &format!("{}:/prx-home", home.display()),
            "-v",
            &format!("{}:/run/k5c", run.display()),
            &tag,
            "--config-dir",
            "/prx-home/.openprx",
            "channel",
            "start",
        ]);
        let output = command.output()?;
        if !output.status.success() {
            return Err("pinned PRX container failed to start".into());
        }
        Ok(PrxProcess { runtime, name })
    }
}
#[cfg(feature = "realnet")]
pub(super) use runtime::start;
