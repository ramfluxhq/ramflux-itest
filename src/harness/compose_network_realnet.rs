// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Two real Compose projects sharing the pinned product's external network declaration.
use super::super::{
    ComposeProjectDownGuard, ItestComposeOverrides, run_docker_compose_project_with_overrides,
};
use super::*;
use std::path::{Path, PathBuf};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn network_id(network: &str) -> Result<String, Box<dyn std::error::Error>> {
    let runtime = super::super::container_runtime()?;
    let output = Command::new(runtime).args(["network", "inspect", network]).output()?;
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

impl Drop for NetworkFixture {
    fn drop(&mut self) {
        // This random, test-owned network is removed only after both project guards.
        // Never force removal: an unexpected attached endpoint must preserve the mesh.
        if let Ok(runtime) = super::super::container_runtime() {
            let _removed = Command::new(runtime).args(["network", "rm", &self.network]).status();
        }
        let _removed = std::fs::remove_dir_all(&self.directory);
    }
}

fn assert_project_attached(project: &str, network: &str) -> TestResult {
    let runtime = super::super::container_runtime()?;
    let containers = Command::new(runtime)
        .args(["ps", "-q", "--filter", &format!("label=com.docker.compose.project={project}")])
        .output()?;
    assert!(containers.status.success());
    let ids = String::from_utf8(containers.stdout)?;
    let ids = ids.split_whitespace().collect::<Vec<_>>();
    assert_eq!(ids.len(), 1, "one running probe in {project}");
    let inspection = Command::new(runtime).args(["inspect", ids[0]]).output()?;
    assert!(inspection.status.success());
    let value: serde_json::Value = serde_json::from_slice(&inspection.stdout)?;
    assert_eq!(value[0]["State"]["Running"], true);
    assert!(value[0]["NetworkSettings"]["Networks"].get(network).is_some());
    assert!(Command::new(runtime).args(["exec", ids[0], "true"]).status()?.success());
    Ok(())
}

fn start_project(directory: &Path, project: &str, env: &[(String, String)]) -> TestResult {
    run_docker_compose_project_with_overrides(
        directory,
        project,
        env,
        &["up", "-d"],
        ItestComposeOverrides::default(),
    )
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
    let env = vec![(NETWORK_ENV.into(), fixture.network.clone())];
    // Exercise simultaneous creators in separate threads, then consecutive projects on
    // the same engine. Unit tests force the losing-create interleaving deterministically.
    let barrier = std::sync::Barrier::new(2);
    std::thread::scope(|scope| -> TestResult {
        let workers = (0..2)
            .map(|_| {
                scope.spawn(|| {
                    barrier.wait();
                    ensure_itest_shared_network(&env).map_err(|error| error.to_string())
                })
            })
            .collect::<Vec<_>>();
        for worker in workers {
            worker.join().map_err(|_| "network creator thread panicked")??;
        }
        Ok(())
    })?;
    // Begin startup from an absent fixture override as well: creating only the
    // process-wide default would leave Compose referring to a missing network.
    let runtime = super::super::container_runtime()?;
    assert!(Command::new(runtime).args(["network", "rm", &fixture.network]).status()?.success());
    let first = format!("ramflux-net-a-{suffix}");
    let second = format!("ramflux-net-b-{suffix}");
    // Arm guards before up, so even a partially failed startup is cleaned up.
    let guard_a =
        ComposeProjectDownGuard::new(fixture.directory.clone(), first.clone(), env.clone(), false);
    start_project(&fixture.directory, &first, &env)?;
    let mesh_id = network_id(&fixture.network)?;
    let guard_b =
        ComposeProjectDownGuard::new(fixture.directory.clone(), second.clone(), env.clone(), false);
    start_project(&fixture.directory, &second, &env)?;
    assert_eq!(network_id(&fixture.network)?, mesh_id);
    assert_project_attached(&first, &fixture.network)?;
    assert_project_attached(&second, &fixture.network)?;
    drop(guard_a);
    assert_eq!(network_id(&fixture.network)?, mesh_id);
    assert_project_attached(&second, &fixture.network)?;
    let guard_a =
        ComposeProjectDownGuard::new(fixture.directory.clone(), first.clone(), env.clone(), false);
    start_project(&fixture.directory, &first, &env)?;
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
