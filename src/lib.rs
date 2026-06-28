// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Open cargo integration test harness for Ramflux MVP-0 fixtures.

#![cfg_attr(test, allow(clippy::items_after_test_module))]

#[cfg(test)]
use ramflux_protocol::FixtureObject;
#[cfg(test)]
use serde_json::Value;
#[cfg(test)]
use std::collections::BTreeSet;
#[cfg(test)]
use std::fs;
#[cfg(all(test, feature = "realnet"))]
use std::io::{Read, Write};
#[cfg(all(test, feature = "realnet"))]
use std::net::{TcpStream, ToSocketAddrs};
#[cfg(all(test, feature = "realnet"))]
use std::os::unix::fs::PermissionsExt;
#[cfg(test)]
use std::path::{Path, PathBuf};
#[cfg(all(test, feature = "realnet"))]
use std::time::Duration;

pub const CRATE_NAME: &str = "ramflux-itest";
#[cfg(all(test, feature = "realnet"))]
const MVP6_REGISTRATION_POW_BITS: u8 = 8;

#[must_use]
pub const fn crate_name() -> &'static str {
    CRATE_NAME
}

#[cfg(test)]
mod harness;
#[cfg(test)]
pub(crate) use harness::*;

#[cfg(test)]
mod tests;
