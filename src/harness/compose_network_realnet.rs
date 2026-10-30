// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Two real Compose projects sharing the pinned product's external network declaration.
use super::super::{add_compose_env_file_arg, compose_down_timeout, run_compose_preflight};
use super::fixture_commands::{compose_command, runtime_command, sanitize};
use super::*;
use std::path::PathBuf;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn network_id(network: &str) -> Result<String, Box<dyn std::error::Error>> {
    let runtime = super::super::container_runtime()?;
    let output = runtime_command(runtime).args(["network", "inspect", network]).output()?;
    assert!(output.status.success(), "shared network must still exist");
    let value: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    value[0]
        .get("Id")
        .or_else(|| value[0].get("id"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| "network identity missing".into())
}

struct NetworkFixture {
    directory: PathBuf,
    network: String,
}

impl NetworkFixture {
    fn run(&self, project: &str, args: &[&str]) -> TestResult {
        let runtime = super::super::container_runtime()?;
        if args.contains(&"up") {
            ensure_network_with_command(&self.network, runtime, sanitize)?;
        }
        let env = vec![(NETWORK_ENV.into(), self.network.clone())];
        let mut command = compose_command(runtime, &self.directory, project);
        let _env_file = add_compose_env_file_arg(&mut command, project, &env)?;
        run_compose_preflight(&command, &self.directory, &env)?;
        let status =
            command.args(args).envs(env.iter().map(|(key, value)| (key, value))).status()?;
        if !status.success() {
            return Err(
                format!("fixture Compose project {project} {args:?} failed with {status}").into()
            );
        }
        Ok(())
    }
}

struct FixtureProject<'a> {
    fixture: &'a NetworkFixture,
    project: String,
}

impl Drop for FixtureProject<'_> {
    fn drop(&mut self) {
        if let Err(error) = self.fixture.run(
            &self.project,
            &["down", "--timeout", &compose_down_timeout(), "-v", "--remove-orphans"],
        ) {
            eprintln!("fixture project cleanup failed: {error}");
        }
    }
}

impl Drop for NetworkFixture {
    fn drop(&mut self) {
        // This random, test-owned network is removed only after both project guards.
        // Never force removal: an unexpected attached endpoint must preserve the mesh.
        if let Ok(runtime) = super::super::container_runtime() {
            let _removed = runtime_command(runtime).args(["network", "rm", &self.network]).status();
        }
        let _removed = std::fs::remove_dir_all(&self.directory);
    }
}

fn assert_project_attached(project: &str, network: &str) -> TestResult {
    let runtime = super::super::container_runtime()?;
    let containers = runtime_command(runtime)
        .args(["ps", "-q", "--filter", &format!("label=com.docker.compose.project={project}")])
        .output()?;
    assert!(containers.status.success());
    let ids = String::from_utf8(containers.stdout)?;
    let ids = ids.split_whitespace().collect::<Vec<_>>();
    assert_eq!(ids.len(), 1, "one running probe in {project}");
    let inspection = runtime_command(runtime).args(["inspect", ids[0]]).output()?;
    assert!(inspection.status.success());
    let value: serde_json::Value = serde_json::from_slice(&inspection.stdout)?;
    assert_eq!(value[0]["State"]["Running"], true);
    assert!(value[0]["NetworkSettings"]["Networks"].get(network).is_some());
    assert!(runtime_command(runtime).args(["exec", ids[0], "true"]).status()?.success());
    Ok(())
}

#[test]
fn realnet_two_projects_share_ready_network_and_teardown_preserves_the_other() -> TestResult {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping network Compose regression; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }
    let directory = crate::temp_root("compose-network")?;
    let suffix = ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?).to_lowercase();
    let fixture = NetworkFixture { directory, network: format!("ramflux-network-{suffix}") };
    let deploy = super::super::self_referencing_defaults::pinned_product_deploy_dir()?
        .ok_or("pinned product checkout required")?;
    let product_compose = std::fs::read_to_string(deploy.join("docker-compose.itest.yml"))?;
    let (_, networks) = product_compose
        .split_once("\nnetworks:\n")
        .ok_or("product network declarations missing")?;
    assert!(networks.contains("external: true"), "the shared mesh must remain external");
    std::fs::write(
        fixture.directory.join("docker-compose.itest.yml"),
        format!(
            "services:\n  probe:\n    image: docker.io/library/debian:trixie-slim\n    command: [sleep, '300']\n    networks:\n      default: {{}}\n      ramflux-itest-mesh: {{}}\nnetworks:\n{networks}"
        ),
    )?;
    let runtime = super::super::container_runtime()?;
    // Exercise simultaneous creators in separate threads, then consecutive projects on
    // the same engine. Unit tests force the losing-create interleaving deterministically.
    let barrier = std::sync::Barrier::new(2);
    std::thread::scope(|scope| -> TestResult {
        let workers = (0..2)
            .map(|_| {
                scope.spawn(|| {
                    barrier.wait();
                    ensure_network_with_command(&fixture.network, runtime, sanitize)
                        .map_err(|error| error.to_string())
                })
            })
            .collect::<Vec<_>>();
        for worker in workers {
            worker.join().map_err(|_| "network creator thread panicked")??;
        }
        Ok(())
    })?;
    // Remove the network before startup while still supplying its fixture name.
    // Creating only the process-wide default would leave the fixture network absent.
    assert!(runtime_command(runtime).args(["network", "rm", &fixture.network]).status()?.success());
    let first = format!("ramflux-net-a-{suffix}");
    let second = format!("ramflux-net-b-{suffix}");
    // Arm guards before up, so even a partially failed startup is cleaned up.
    let guard_a = FixtureProject { fixture: &fixture, project: first.clone() };
    fixture.run(&first, &["up", "-d"])?;
    let mesh_id = network_id(&fixture.network)?;
    let guard_b = FixtureProject { fixture: &fixture, project: second.clone() };
    fixture.run(&second, &["up", "-d"])?;
    assert_eq!(network_id(&fixture.network)?, mesh_id);
    assert_project_attached(&first, &fixture.network)?;
    assert_project_attached(&second, &fixture.network)?;
    drop(guard_a);
    assert_eq!(network_id(&fixture.network)?, mesh_id);
    assert_project_attached(&second, &fixture.network)?;
    let guard_a = FixtureProject { fixture: &fixture, project: first.clone() };
    fixture.run(&first, &["up", "-d"])?;
    assert_project_attached(&first, &fixture.network)?;
    drop(guard_b);
    assert_eq!(network_id(&fixture.network)?, mesh_id);
    assert_project_attached(&first, &fixture.network)?;
    drop(guard_a);
    assert_eq!(
        network_id(&fixture.network)?,
        mesh_id,
        "external mesh survives the last project teardown without replacement"
    );
    eprintln!(
        "two-project network regression passed: concurrent create, back-to-back up, teardown, restart"
    );
    Ok(())
}
