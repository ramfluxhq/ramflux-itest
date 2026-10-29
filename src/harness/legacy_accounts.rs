// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Temporary, explicitly selected account setup for fixtures awaiting native migration.
use std::path::PathBuf;

pub(crate) fn config(
    socket: impl Into<PathBuf>,
    data: impl Into<PathBuf>,
) -> ramflux_sdk::LocalBusConfig {
    ramflux_sdk::LocalBusConfig::new(socket, data).with_itest_legacy_accounts()
}

#[cfg(feature = "realnet")]
pub(crate) fn target_dir() -> PathBuf {
    std::env::var_os("CARGO_TARGET_DIR")
        .map_or_else(|| crate::code_root().join("ramflux/target"), PathBuf::from)
}
