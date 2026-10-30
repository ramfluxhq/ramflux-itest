// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Production call signaling and opaque bidirectional voice media acceptance.
#![cfg(feature = "realnet")]
use super::*;
#[test]
fn call01_realnet_voice_round_trip() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!(
            "skipping voice acceptance: set RAMFLUX_ITEST_REALNET=1 on the QA container host"
        );
        return Ok(());
    }
    assert_realnet_voice_round_trip("ramflux-call01-voice")
}

#[test]
fn call01_realnet_legacy_voice_round_trip() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!(
            "skipping legacy voice acceptance: set RAMFLUX_ITEST_REALNET=1 on the QA container host"
        );
        return Ok(());
    }
    assert_realnet_legacy_voice_round_trip("ramflux-call01-legacy-voice")
}
