// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Explicit fixture defaults and lint for migrated Compose interpolation inputs.
//!
//! podman-compose 1.3.0 keeps such a self-referencing default as the literal string
//! `${KEY:-default}` when the outer variable is unset (Docker Compose v2 expands it). A service
//! that merely parses the value falls back to its own default; one that opens the value as a
//! path (notify's provider credentials file) exits. The harness therefore passes each of these
//! keys explicitly: the fixture's value when it set one, else the caller's process environment
//! (compose would have interpolated exactly that), else the compose default.
use super::compose_env_with_required_defaults;
use std::path::{Path, PathBuf};

/// Former self-referencing Compose inputs, now supplied explicitly by the fixture generator.
/// `compose_env_with_required_defaults` applies them with `ensure_compose_default_env`, so a
/// fixture's own value always wins, and a value present in the process environment (operator
/// knobs such as `RAMFLUX_ITEST_PERF=1` or `RAMFLUX_RELAY_REDB_CACHE_BYTES`) replaces the table
/// default. Keys the harness already derives elsewhere (node id, signing seed, federation and
/// relay trust material) are not repeated here.
pub(super) const COMPOSE_FIXTURE_DEFAULTS: &[(&str, &str)] = &[
    ("RAMFLUX_CUSTODY_NODE_PUBLIC_KEY", ""),
    ("RAMFLUX_CUSTODY_PROXY_SIGNING_SEED", ""),
    ("RAMFLUX_CUSTODY_NODE_RECORD_FILE", ""),
    // docker-compose.itest.yml: every service
    ("RAMFLUX_ITEST_PERF", "0"),
    // docker-compose.itest.yml + docker-compose.itest.cross-gateway.yml: gateway
    ("RAMFLUX_ITEST_GATEWAY_FRAME_DELAY_MS", "0"),
    ("RAMFLUX_GATEWAY_QUIC_WORKER_THREADS", ""),
    ("RAMFLUX_GATEWAY_QUIC_MAX_CONCURRENT_BIDI_STREAMS", "4096"),
    ("RAMFLUX_GATEWAY_QUIC_RECEIVE_WINDOW", "16777216"),
    ("RAMFLUX_GATEWAY_QUIC_STREAM_RECEIVE_WINDOW", "1048576"),
    ("RAMFLUX_GATEWAY_QUIC_SEND_WINDOW", "16777216"),
    ("RAMFLUX_GATEWAY_ITEST_CAPTURE_JSON", "/tmp/ramflux-gateway-itest-capture.jsonl"),
    ("RAMFLUX_ROUTER_ASYNC_POOL_SIZE", "8"),
    ("RAMFLUX_MESH_QUIC_CLIENT_POOL_SIZE", "8"),
    // docker-compose.itest.yml: gateway, router and federation mesh QUIC tuning
    ("RAMFLUX_MESH_QUIC_MAX_CONCURRENT_BIDI_STREAMS", "4096"),
    ("RAMFLUX_MESH_QUIC_RECEIVE_WINDOW", "16777216"),
    ("RAMFLUX_MESH_QUIC_STREAM_RECEIVE_WINDOW", "1048576"),
    ("RAMFLUX_MESH_QUIC_SEND_WINDOW", "16777216"),
    // docker-compose.itest.yml: router
    ("RAMFLUX_ROUTER_GROUP_COMMIT", "0"),
    ("RAMFLUX_ROUTER_ASYNC_INGRESS_SOCKETS", "1"),
    ("RAMFLUX_ROUTER_ASYNC_WORKER_THREADS", ""),
    ("RAMFLUX_ROUTER_WAL_BATCH_MAX", "256"),
    ("RAMFLUX_ROUTER_WAL_QUEUE_CAPACITY", "4096"),
    ("RAMFLUX_ROUTER_WAL_COMMIT_WINDOW_US", "0"),
    ("RAMFLUX_ROUTER_WAL_PIPELINE", "0"),
    ("RAMFLUX_ROUTER_WAL_DIR", ""),
    ("RAMFLUX_ROUTER_WAL_SHARDS", ""),
    // docker-compose.itest.yml: notify (empty = no node-owned provider credentials; s13 sets both)
    ("RAMFLUX_NOTIFY_PROVIDER_CREDENTIALS_FILE", ""),
    ("RAMFLUX_NOTIFY_WEBPUSH_ORIGINS", ""),
    // docker-compose.itest.yml: federation
    ("RAMFLUX_FEDERATION_DISABLE_QUIC_LISTENER", "0"),
    ("RAMFLUX_FEDERATION_PUBLIC_MAX_CONNECTIONS", "64"),
    ("RAMFLUX_FEDERATION_PUBLIC_MAX_HEADER_BYTES", "8192"),
    ("RAMFLUX_FEDERATION_PUBLIC_MAX_BODY_BYTES", "65536"),
    ("RAMFLUX_FEDERATION_PUBLIC_REQUEST_TIMEOUT_SECONDS", "10"),
    ("RAMFLUX_FEDERATION_ADMIN_MAX_HEADER_BYTES", "65536"),
    ("RAMFLUX_FEDERATION_ADMIN_MAX_BODY_BYTES", "1048576"),
    ("RAMFLUX_FEDERATION_ADMIN_REQUEST_TIMEOUT_SECONDS", "30"),
    // docker-compose.itest.yml: relay
    ("RAMFLUX_RELAY_ITEST_CAPTURE_JSON", "/tmp/ramflux-relay-itest-capture.jsonl"),
    // docker-compose.itest.object-v3.yml: relay fault injection and profiling hooks (all off)
    ("RAMFLUX_RELAY_ITEST_FAIL_FIRST_V3_ACK", ""),
    ("RAMFLUX_RELAY_ITEST_DROP_AFTER_COMMIT", ""),
    ("RAMFLUX_RELAY_ITEST_HOLD_MARKER", ""),
    ("RAMFLUX_RELAY_ALLOC_PROF_FILE", ""),
    ("RAMFLUX_RELAY_REDB_CACHE_BYTES", ""),
    // docker-compose.itest.voice.yml: relay
    ("RAMFLUX_RELAY_VOICE_PUBLIC_ENDPOINT", "127.0.0.1:19001"),
];

/// The value compose would interpolate for `${key:-default}`: the process environment of the
/// harness when the variable is present there (operator knobs must keep reaching the services),
/// else the compose default.
pub(super) fn outer_or_default(key: &str, default: &str) -> String {
    std::env::var_os(key)
        .or_else(|| super::compose_input_aliases::alias(key).and_then(std::env::var_os))
        .map_or_else(|| default.to_owned(), |value| value.to_string_lossy().into_owned())
}

/// One `KEY: "${KEY:-default}"` occurrence in a compose file.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct SelfReferencingDefault {
    pub(super) file: String,
    pub(super) line: usize,
    pub(super) key: String,
    pub(super) default: String,
}

/// Finds every environment entry whose default references the entry's own key.
/// Only `environment:` entries are affected: a `${VAR:-x}` inside a port mapping or a
/// differently named outer variable expands correctly.
pub(super) fn self_referencing_defaults(file: &str, text: &str) -> Vec<SelfReferencingDefault> {
    text.lines()
        .enumerate()
        .filter_map(|(index, line)| {
            let (key, value) = environment_entry(line)?;
            let default = self_referencing_default(key, value)?;
            Some(SelfReferencingDefault {
                file: file.to_owned(),
                line: index + 1,
                key: key.to_owned(),
                default: default.to_owned(),
            })
        })
        .collect()
}

/// `KEY: value` (mapping form) or `- KEY=value` (list form) with an environment-variable key.
fn environment_entry(line: &str) -> Option<(&str, &str)> {
    let line = line.trim_start();
    let (key, value) = match line.strip_prefix("- ") {
        Some(item) => item.trim_start().split_once('=')?,
        None => line.split_once(':')?,
    };
    let key = key.trim_end();
    let is_env_key =
        key.bytes().next().is_some_and(|byte| byte.is_ascii_uppercase() || byte == b'_')
            && key
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_');
    is_env_key.then_some((key, value.trim()))
}

/// The default of `${KEY:-default}` or `${KEY-default}`, with optional `"`/`'` quoting and an
/// optional trailing `# comment`.
fn self_referencing_default<'a>(key: &str, value: &'a str) -> Option<&'a str> {
    let unquoted = value.strip_prefix(['"', '\'']).unwrap_or(value);
    let rest = unquoted.strip_prefix("${")?.strip_prefix(key)?;
    let rest = rest.strip_prefix(":-").or_else(|| rest.strip_prefix('-'))?;
    let (default, tail) = rest.split_once('}')?;
    let tail = tail.trim_start_matches(['"', '\'']).trim_start();
    (tail.is_empty() || tail.starts_with('#')).then_some(default)
}

/// The product SHA every `ramfluxhq/ramflux.git` dependency of this crate pins.
fn pinned_product_sha() -> Result<String, Box<dyn std::error::Error>> {
    let manifest = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"))?;
    let marker = "ramfluxhq/ramflux.git\", rev = \"";
    let mut pins = manifest
        .match_indices(marker)
        .map(|(index, _)| manifest[index + marker.len()..].chars().take(40).collect::<String>())
        .collect::<Vec<_>>();
    pins.sort();
    pins.dedup();
    match pins.as_slice() {
        [pin] if pin.len() == 40 && pin.bytes().all(|byte| byte.is_ascii_hexdigit()) => {
            Ok(pin.clone())
        }
        other => {
            Err(format!("Cargo.toml must pin exactly one product SHA, found {other:?}").into())
        }
    }
}

/// The `deploy/` directory of the pinned product tree: `RAMFLUX_ITEST_PRODUCT_DEPLOY_DIR` when
/// set (it must exist: CI sets it, and the gate stays hard there), else cargo's git checkout of
/// the pinned SHA, else the sibling `../ramflux` checkout the realnet fixtures use (a warning
/// names its revision when it is not the pin), else `None` so a local run can skip.
pub(super) fn pinned_product_deploy_dir() -> Result<Option<PathBuf>, Box<dyn std::error::Error>> {
    if let Some(dir) = std::env::var_os("RAMFLUX_ITEST_PRODUCT_DEPLOY_DIR") {
        let dir = PathBuf::from(dir);
        if !dir.join("docker-compose.itest.yml").is_file() {
            return Err(format!(
                "RAMFLUX_ITEST_PRODUCT_DEPLOY_DIR={} has no docker-compose.itest.yml",
                dir.display()
            )
            .into());
        }
        return Ok(Some(dir));
    }
    let sha = pinned_product_sha()?;
    let cargo_home = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo")));
    if let Some(checkouts) = cargo_home.map(|home| home.join("git/checkouts"))
        && let Ok(entries) = std::fs::read_dir(&checkouts)
    {
        for entry in entries.flatten() {
            if entry.file_name().to_string_lossy().starts_with("ramflux-") {
                let checkout = entry.path().join(&sha[..7]);
                let deploy = checkout.join("deploy");
                if checkout.join(".cargo-ok").is_file()
                    && deploy.join("docker-compose.itest.yml").is_file()
                {
                    return Ok(Some(deploy));
                }
            }
        }
    }
    let sibling = super::code_root().join("ramflux");
    if sibling.join("deploy/docker-compose.itest.yml").is_file() {
        let head = std::process::Command::new("git")
            .args(["-C", &sibling.to_string_lossy(), "rev-parse", "HEAD"])
            .output()
            .ok()
            .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned());
        if let Some(head) = head
            && head != sha
        {
            eprintln!(
                "warning: linting sibling checkout {} at {head}, not the pinned product {sha}",
                sibling.display()
            );
        }
        return Ok(Some(sibling.join("deploy")));
    }
    Ok(None)
}

fn itest_compose_files(deploy: &Path) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let mut files = std::fs::read_dir(deploy)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name().and_then(|name| name.to_str()).is_some_and(|name| {
                name.starts_with("docker-compose.itest")
                    && Path::new(name).extension().is_some_and(|extension| extension == "yml")
            })
        })
        .collect::<Vec<_>>();
    files.sort();
    Ok(files)
}

mod tests {
    use super::*;

    fn value_of<'a>(env: &'a [(String, String)], key: &str) -> Vec<&'a str> {
        env.iter()
            .filter(|(existing, _)| existing == key)
            .map(|(_, value)| value.as_str())
            .collect()
    }

    #[test]
    fn finds_every_environment_entry_shape_that_references_its_own_key() {
        let text = r#"services:
  ramflux-notify:
    environment:
      RAMFLUX_NOTIFY_WEBPUSH_ORIGINS: "${RAMFLUX_NOTIFY_WEBPUSH_ORIGINS:-}"
      RAMFLUX_NODE_ID: "${RAMFLUX_NODE_ID:-localhost}"  # trailing comment
      RAMFLUX_SINGLE: '${RAMFLUX_SINGLE:-single}'
      RAMFLUX_NO_COLON: ${RAMFLUX_NO_COLON-plain}
      - RAMFLUX_LIST=${RAMFLUX_LIST:-list}
      RAMFLUX_GATEWAY_V3_ISSUER_SEED: "${RAMFLUX_GATEWAY_A_V3_ISSUER_SEED:-}"
      RAMFLUX_ITEST_HTTP: "1"
      RAMFLUX_SUFFIX: "${RAMFLUX_SUFFIX:-x}:443"
      # RAMFLUX_COMMENTED: "${RAMFLUX_COMMENTED:-x}"
    ports:
      - "${RAMFLUX_ITEST_NOTIFY_HTTP_PORT:-18083}:18083"
networks:
  default:
    name: "${RAMFLUX_ITEST_SHARED_NETWORK:-ramflux-itest-mesh}"
"#;
        let found = self_referencing_defaults("docker-compose.itest.yml", text)
            .into_iter()
            .map(|entry| (entry.line, entry.key, entry.default))
            .collect::<Vec<_>>();
        assert_eq!(
            found,
            vec![
                (4, "RAMFLUX_NOTIFY_WEBPUSH_ORIGINS".to_owned(), String::new()),
                (5, "RAMFLUX_NODE_ID".to_owned(), "localhost".to_owned()),
                (6, "RAMFLUX_SINGLE".to_owned(), "single".to_owned()),
                (7, "RAMFLUX_NO_COLON".to_owned(), "plain".to_owned()),
                (8, "RAMFLUX_LIST".to_owned(), "list".to_owned()),
            ]
        );
    }

    #[test]
    fn pinned_itest_compose_inputs_have_aliases_and_no_self_referencing_defaults()
    -> Result<(), Box<dyn std::error::Error>> {
        let Some(deploy) = pinned_product_deploy_dir()? else {
            eprintln!(
                "skipping compose self-referencing lint: no checkout of the pinned product \
                 (cargo git checkout, ../ramflux, or RAMFLUX_ITEST_PRODUCT_DEPLOY_DIR)"
            );
            return Ok(());
        };
        let files = itest_compose_files(&deploy)?;
        assert!(!files.is_empty(), "no docker-compose.itest*.yml under {}", deploy.display());
        let supplied = compose_env_with_required_defaults(&[]);
        let mut uncovered = Vec::new();
        let mut seen = 0;
        for path in &files {
            let name = path.file_name().and_then(|name| name.to_str()).unwrap_or_default();
            for entry in self_referencing_defaults(name, &std::fs::read_to_string(path)?) {
                seen += 1;
                if !supplied.iter().any(|(key, _)| *key == entry.key) {
                    uncovered.push(format!(
                        "{}:{}: {}: \"${{{}:-{}}}\"",
                        entry.file, entry.line, entry.key, entry.key, entry.default
                    ));
                }
            }
        }
        eprintln!(
            "compose self-referencing defaults: {seen} entries in {} files under {}",
            files.len(),
            deploy.display()
        );
        assert_eq!(seen, 0, "never reintroduce self-referencing Compose defaults");
        assert!(
            uncovered.is_empty(),
            "self-referencing compose defaults the harness does not supply (podman-compose 1.3.0 \
             keeps them literal); add each key to COMPOSE_FIXTURE_DEFAULTS in {}:\n{}",
            file!(),
            uncovered.join("\n")
        );
        let mapping: std::collections::BTreeMap<String, String> =
            serde_json::from_str(&std::fs::read_to_string(deploy.join("compose-inputs.json"))?)?;
        assert_eq!(mapping.len(), super::super::compose_input_aliases::MIGRATED_KEYS.len());
        for (old, new) in &mapping {
            assert_eq!(super::super::compose_input_aliases::alias(old).as_ref(), Some(new));
        }
        for path in &files {
            let text = std::fs::read_to_string(path)?;
            for new in mapping.values().filter(|new| text.contains(&format!("${{{new}"))) {
                assert!(supplied.iter().any(|(key, _)| key == new), "missing Compose alias: {new}");
            }
        }
        Ok(())
    }

    #[test]
    fn default_table_has_unique_keys_without_duplicating_explicit_defaults() {
        let mut keys = COMPOSE_FIXTURE_DEFAULTS.iter().map(|(key, _)| *key).collect::<Vec<_>>();
        let count = keys.len();
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(keys.len(), count, "duplicate key in COMPOSE_FIXTURE_DEFAULTS");
        let supplied = compose_env_with_required_defaults(&[]);
        for (key, default) in COMPOSE_FIXTURE_DEFAULTS {
            let expected = outer_or_default(key, default);
            assert_eq!(value_of(&supplied, key), vec![expected.as_str()], "{key} supplied once");
        }
    }

    #[test]
    fn fixture_values_win_over_table_defaults() {
        let env = compose_env_with_required_defaults(&[(
            "RAMFLUX_NOTIFY_WEBPUSH_ORIGINS".to_owned(),
            "http://127.0.0.1:9".to_owned(),
        )]);
        assert_eq!(value_of(&env, "RAMFLUX_NOTIFY_WEBPUSH_ORIGINS"), vec!["http://127.0.0.1:9"]);
    }

    /// Mirrors what compose interpolates: a key present in the process environment reaches the
    /// compose env with that value, an absent key gets the table default. Runs the same way under
    /// an operator's `RAMFLUX_ITEST_PERF=1 cargo test ...` and reports what it saw, so it doubles
    /// as the env pass-through smoke on a QA host.
    #[test]
    fn process_environment_values_pass_through_to_the_compose_env() {
        let supplied = compose_env_with_required_defaults(&[]);
        for key in ["RAMFLUX_ITEST_PERF", "RAMFLUX_RELAY_REDB_CACHE_BYTES"] {
            let outer = std::env::var_os(key).map(|value| value.to_string_lossy().into_owned());
            let (_, default) = COMPOSE_FIXTURE_DEFAULTS
                .iter()
                .find(|(table_key, _)| *table_key == key)
                .unwrap_or(&("", ""));
            let expected = outer.clone().unwrap_or_else(|| (*default).to_owned());
            eprintln!(
                "compose env {key}={:?} (process environment: {})",
                expected,
                outer.as_deref().map_or("absent".to_owned(), |value| format!("{value:?}"))
            );
            assert_eq!(value_of(&supplied, key), vec![expected.as_str()]);
        }
    }

    /// Proves the pass-through with concrete values by re-running this test in a child process
    /// whose environment carries `RAMFLUX_ITEST_PERF=1` and `RAMFLUX_RELAY_REDB_CACHE_BYTES`,
    /// and that a fixture value still beats the process environment.
    #[test]
    fn exported_operator_knobs_reach_the_compose_env_unchanged()
    -> Result<(), Box<dyn std::error::Error>> {
        if std::env::var_os("RAMFLUX_ITEST_OUTER_ENV_CHILD").is_some() {
            let supplied = compose_env_with_required_defaults(&[]);
            assert_eq!(value_of(&supplied, "RAMFLUX_ITEST_PERF"), vec!["1"]);
            assert_eq!(value_of(&supplied, "RAMFLUX_RELAY_REDB_CACHE_BYTES"), vec!["16777216"]);
            assert_eq!(value_of(&supplied, "RAMFLUX_ROUTER_WAL_SHARDS"), vec![""]);
            let fixture = compose_env_with_required_defaults(&[(
                "RAMFLUX_ITEST_PERF".to_owned(),
                "fixture".to_owned(),
            )]);
            assert_eq!(value_of(&fixture, "RAMFLUX_ITEST_PERF"), vec!["fixture"]);
            return Ok(());
        }
        let test_name = concat!(
            "harness::realnet_compose_stun::self_referencing_defaults::tests::",
            "exported_operator_knobs_reach_the_compose_env_unchanged"
        );
        let output = std::process::Command::new(std::env::current_exe()?)
            .args(["--exact", test_name, "--test-threads=1"])
            .env("RAMFLUX_ITEST_OUTER_ENV_CHILD", "1")
            .env("RAMFLUX_ITEST_PERF", "1")
            .env("RAMFLUX_RELAY_REDB_CACHE_BYTES", "16777216")
            .env_remove("RAMFLUX_ROUTER_WAL_SHARDS")
            .output()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{stdout}\n{stderr}");
        // An exact filter matching no tests also exits zero; require the child actually ran.
        assert!(stdout.contains("1 passed"), "child did not run the check: {stdout}");
        Ok(())
    }
}
