// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Concrete outer values for every `KEY: "${KEY:-default}"` in the itest compose files.
//!
//! podman-compose 1.3.0 keeps such a self-referencing default as the literal string
//! `${KEY:-default}` when the outer variable is unset (Docker Compose v2 expands it). A service
//! that merely parses the value falls back to its own default; one that opens the value as a
//! path (notify's provider credentials file) exits. The harness therefore passes each of these
//! keys explicitly, with the value the compose file would have chosen, unless a fixture set it.
use super::compose_env_with_required_defaults;
use std::path::{Path, PathBuf};

/// Self-referencing keys of `deploy/docker-compose.itest*.yml` and their compose defaults.
/// `compose_env_with_required_defaults` applies them with `ensure_compose_default_env`, so a
/// fixture's own value always wins. Keys the harness already derives elsewhere (node id, signing
/// seed, federation and relay trust material) are not repeated here.
pub(super) const COMPOSE_SELF_REFERENCING_DEFAULTS: &[(&str, &str)] = &[
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

/// One `KEY: "${KEY:-default}"` occurrence in a compose file.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct SelfReferencingDefault {
    pub(super) file: String,
    pub(super) line: usize,
    pub(super) key: String,
    pub(super) default: String,
}

/// Finds every environment entry whose default references the entry's own key.
/// Only the `environment:` mapping form `KEY: "${KEY:-default}"` is affected: a `${VAR:-x}`
/// inside a port mapping or a differently named outer variable expands correctly.
pub(super) fn self_referencing_defaults(file: &str, text: &str) -> Vec<SelfReferencingDefault> {
    text.lines()
        .enumerate()
        .filter_map(|(index, line)| {
            let (key, value) = line.trim_start().split_once(':')?;
            if key.is_empty()
                || !key
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte == b'_' || byte.is_ascii_digit())
            {
                return None;
            }
            let value = value.trim().trim_matches('"');
            let rest = value.strip_prefix("${")?.strip_prefix(key)?.strip_prefix(":-")?;
            let default = rest.strip_suffix('}')?;
            Some(SelfReferencingDefault {
                file: file.to_owned(),
                line: index + 1,
                key: key.to_owned(),
                default: default.to_owned(),
            })
        })
        .collect()
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
/// set, else cargo's git checkout of the pinned SHA, else the sibling `../ramflux` checkout the
/// realnet fixtures use.
pub(super) fn pinned_product_deploy_dir() -> Result<PathBuf, Box<dyn std::error::Error>> {
    if let Ok(dir) = std::env::var("RAMFLUX_ITEST_PRODUCT_DEPLOY_DIR") {
        return Ok(PathBuf::from(dir));
    }
    let sha = pinned_product_sha()?;
    let cargo_home = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo")));
    let mut candidates = Vec::new();
    if let Some(checkouts) = cargo_home.map(|home| home.join("git/checkouts"))
        && let Ok(entries) = std::fs::read_dir(&checkouts)
    {
        for entry in entries.flatten() {
            if entry.file_name().to_string_lossy().starts_with("ramflux-") {
                let checkout = entry.path().join(&sha[..7]);
                if checkout.join(".cargo-ok").is_file() {
                    candidates.push(checkout.join("deploy"));
                }
            }
        }
    }
    candidates.push(super::code_root().join("ramflux/deploy"));
    candidates
        .into_iter()
        .find(|deploy| deploy.join("docker-compose.itest.yml").is_file())
        .ok_or_else(|| format!("no checkout of pinned product {sha} with deploy/ found").into())
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

    #[test]
    fn finds_only_environment_entries_that_reference_their_own_key() {
        let text = r#"services:
  ramflux-notify:
    environment:
      RAMFLUX_NOTIFY_WEBPUSH_ORIGINS: "${RAMFLUX_NOTIFY_WEBPUSH_ORIGINS:-}"
      RAMFLUX_NODE_ID: "${RAMFLUX_NODE_ID:-localhost}"
      RAMFLUX_GATEWAY_V3_ISSUER_SEED: "${RAMFLUX_GATEWAY_A_V3_ISSUER_SEED:-}"
      RAMFLUX_ITEST_HTTP: "1"
      # RAMFLUX_COMMENTED: "${RAMFLUX_COMMENTED:-x}"
    ports:
      - "${RAMFLUX_ITEST_NOTIFY_HTTP_PORT:-18083}:18083"
"#;
        let found = self_referencing_defaults("docker-compose.itest.yml", text);
        assert_eq!(
            found,
            vec![
                SelfReferencingDefault {
                    file: "docker-compose.itest.yml".to_owned(),
                    line: 4,
                    key: "RAMFLUX_NOTIFY_WEBPUSH_ORIGINS".to_owned(),
                    default: String::new(),
                },
                SelfReferencingDefault {
                    file: "docker-compose.itest.yml".to_owned(),
                    line: 5,
                    key: "RAMFLUX_NODE_ID".to_owned(),
                    default: "localhost".to_owned(),
                },
            ]
        );
    }

    #[test]
    fn pinned_itest_compose_self_referencing_defaults_are_supplied_by_the_harness()
    -> Result<(), Box<dyn std::error::Error>> {
        let deploy = pinned_product_deploy_dir()?;
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
        assert!(seen > 0, "no self-referencing defaults found under {}", deploy.display());
        assert!(
            uncovered.is_empty(),
            "self-referencing compose defaults the harness does not supply (podman-compose 1.3.0 \
             keeps them literal); add each key to COMPOSE_SELF_REFERENCING_DEFAULTS in {}:\n{}",
            file!(),
            uncovered.join("\n")
        );
        Ok(())
    }

    #[test]
    fn default_table_has_unique_keys_without_duplicating_explicit_defaults() {
        let mut keys =
            COMPOSE_SELF_REFERENCING_DEFAULTS.iter().map(|(key, _)| *key).collect::<Vec<_>>();
        let count = keys.len();
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(keys.len(), count, "duplicate key in COMPOSE_SELF_REFERENCING_DEFAULTS");
        let supplied = compose_env_with_required_defaults(&[]);
        for (key, value) in COMPOSE_SELF_REFERENCING_DEFAULTS {
            let values = supplied
                .iter()
                .filter(|(supplied_key, _)| supplied_key == key)
                .map(|(_, supplied_value)| supplied_value.as_str())
                .collect::<Vec<_>>();
            assert_eq!(values, vec![*value], "{key} must be supplied exactly once from the table");
        }
    }

    #[test]
    fn fixture_values_win_over_table_defaults() {
        let env = compose_env_with_required_defaults(&[(
            "RAMFLUX_NOTIFY_WEBPUSH_ORIGINS".to_owned(),
            "http://127.0.0.1:9".to_owned(),
        )]);
        let values = env
            .iter()
            .filter(|(key, _)| key == "RAMFLUX_NOTIFY_WEBPUSH_ORIGINS")
            .map(|(_, value)| value.as_str())
            .collect::<Vec<_>>();
        assert_eq!(values, vec!["http://127.0.0.1:9"]);
    }
}
