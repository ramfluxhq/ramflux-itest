// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Pinned external engine fixture and authenticated real-channel acceptance.
#[path = "k5c_prx_engine/prx_fixture.rs"]
mod prx_fixture;
#[test]
fn prx_fixture_pin_matches_containerfile() {
    let source = include_str!("../../fixtures/prx/Containerfile");
    let pin = source.lines().find_map(|line| line.strip_prefix("ARG PRX_SHA=")).unwrap_or("");
    assert_eq!(pin, prx_fixture::PRX_SHA);
    assert!(source.contains("git rev-parse HEAD"));
    assert!(source.contains("cargo build --release --locked --bin prx"));
    assert!(source.contains("rust:1.99.0-slim@sha256:"));
    assert!(source.contains("debian:trixie-slim@sha256:"));
}

#[cfg(feature = "realnet")]
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
#[cfg(feature = "realnet")]
#[path = "k5c_prx_engine/fake_llm.rs"]
mod fake_llm;
#[cfg(feature = "realnet")]
#[path = "k5c_prx_engine/scenario.rs"]
mod scenario;
#[cfg(feature = "realnet")]
#[test]
fn k5c_realnet_prx_engine_dm_reply() -> TestResult {
    scenario::run(false)
}
#[cfg(feature = "realnet")]
#[test]
fn k5c2_realnet_prx_engine_supervised_approval() -> TestResult {
    scenario::run(true)
}
