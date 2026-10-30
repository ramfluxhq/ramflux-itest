// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Prepare the external federation mesh; Compose projects never own or remove it.
//!
//! The mesh must outlive every attached project, including projects in other processes.
//! Keep it external and reusable even after the last local guard drops. A process-local
//! reference count cannot safely decide whether another process is about to attach.
use std::{process::Command, time::Duration};

const NETWORK_ENV: &str = "RAMFLUX_ITEST_SHARED_NETWORK";
const DEFAULT_NETWORK: &str = "ramflux-itest-mesh";

pub(super) fn supply_network_name(
    env: &mut Vec<(String, String)>,
) -> Result<(), Box<dyn std::error::Error>> {
    if !env.iter().any(|(key, _)| key == NETWORK_ENV) {
        env.push((
            NETWORK_ENV.into(),
            std::env::var(NETWORK_ENV).unwrap_or_else(|_| DEFAULT_NETWORK.into()),
        ));
    }
    network_name(env)?;
    Ok(())
}

fn network_name(env: &[(String, String)]) -> Result<&str, Box<dyn std::error::Error>> {
    let names = env.iter().filter(|(key, _)| key == NETWORK_ENV).collect::<Vec<_>>();
    let [(_, name)] = names.as_slice() else {
        return Err(format!("{NETWORK_ENV} must be supplied exactly once").into());
    };
    if !name.bytes().next().is_some_and(|byte| byte.is_ascii_alphanumeric())
        || !name.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
    {
        return Err(format!("{NETWORK_ENV} must be a valid container network name").into());
    }
    Ok(name)
}

pub(super) fn ensure_itest_shared_network(
    env: &[(String, String)],
) -> Result<(), Box<dyn std::error::Error>> {
    let network = network_name(env)?;
    let runtime = super::container_runtime()?;
    ensure_network(
        network,
        |operation| {
            let output = Command::new(runtime)
                .args(["network", operation, network])
                .output()
                .map_err(|error| error.to_string())?;
            if output.status.success() {
                Ok(())
            } else {
                Err(format!(
                    "{}: {}",
                    output.status,
                    String::from_utf8_lossy(&output.stderr).trim()
                ))
            }
        },
        || std::thread::sleep(Duration::from_millis(100)),
        50,
    )?;
    crate::realnet_step("shared network ready", format!("runtime={runtime} network={network}"));
    Ok(())
}

fn ensure_network(
    network: &str,
    mut probe: impl FnMut(&str) -> Result<(), String>,
    mut wait: impl FnMut(),
    attempts: usize,
) -> Result<(), String> {
    if probe("inspect").is_ok() {
        return Ok(());
    }
    // Another process can win between inspect and create. Readiness, rather than
    // create's exit status or error wording, determines whether it is safe to proceed.
    let create = probe("create");
    let mut last_inspect = String::new();
    for attempt in 0..attempts {
        match probe("inspect") {
            Ok(()) => return Ok(()),
            Err(error) => last_inspect = error,
        }
        if attempt + 1 < attempts {
            wait();
        }
    }
    Err(format!(
        "container network {network} did not become ready after {attempts} probes; create={create:?}; inspect={last_inspect}"
    ))
}

#[path = "compose_network_realnet.rs"]
mod realnet;
#[path = "compose_network_tests.rs"]
mod tests;
