// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
// The scaffold is intentionally realnet-gated. Default test/check builds compile it
// but do not require Docker or a Linux runner.
use super::*;

#[cfg(feature = "realnet")]
#[test]
fn t22_production_keyless_v3_compose_smoke() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_T22_PRODUCTION_SMOKE").as_deref() != Ok("1") {
        eprintln!("skipping T22 production compose smoke; set RAMFLUX_T22_PRODUCTION_SMOKE=1");
        return Ok(());
    }

    let deploy_root = code_root().join("ramflux/deploy");
    let compose_path = deploy_root.join("docker-compose.yml");
    let compose = std::fs::read_to_string(&compose_path)?;

    // T22-A3/RQ-04 static production-surface guard: the default production relay
    // must not be configured with the legacy object HMAC key, and it must require
    // the keyring-era v3 trust material explicitly.
    assert!(
        !compose.contains("RAMFLUX_RELAY_SERVICE_KEY_REF"),
        "production compose must not configure the legacy relay object HMAC key"
    );
    for required in [
        "RAMFLUX_FEDERATION_TRUST_ENDPOINT: \"${RAMFLUX_FEDERATION_TRUST_ENDPOINT:?",
        "RAMFLUX_FEDERATION_PROVIDER_OFFLINE_ROOT_PUBLIC_KEY: \"${RAMFLUX_FEDERATION_PROVIDER_OFFLINE_ROOT_PUBLIC_KEY:?",
        "RAMFLUX_FEDERATION_TRUST_ISSUER_NODE_ID: \"${RAMFLUX_FEDERATION_TRUST_ISSUER_NODE_ID:?",
    ] {
        assert!(
            compose.contains(required),
            "production compose must fail closed through required v3 keyring variable: {required}"
        );
    }

    let runtime = container_runtime();
    let output = std::process::Command::new(runtime)
        .arg("compose")
        .arg("-f")
        .arg("docker-compose.yml")
        .arg("config")
        .env_remove("RAMFLUX_FEDERATION_TRUST_ENDPOINT")
        .env_remove("RAMFLUX_FEDERATION_PROVIDER_OFFLINE_ROOT_PUBLIC_KEY")
        .env_remove("RAMFLUX_FEDERATION_TRUST_ISSUER_NODE_ID")
        .current_dir(&deploy_root)
        .output()?;
    assert!(
        !output.status.success(),
        "production compose config must fail closed when v3 keyring material is absent"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("RAMFLUX_FEDERATION_TRUST_ENDPOINT")
            || stderr.contains("RAMFLUX_FEDERATION_PROVIDER_OFFLINE_ROOT_PUBLIC_KEY")
            || stderr.contains("RAMFLUX_FEDERATION_TRUST_ISSUER_NODE_ID"),
        "compose config failure must identify missing v3 material; stderr={stderr}"
    );

    Ok(())
}
