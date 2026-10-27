// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Compose interpolation names are distinct from service environment names.
use std::sync::OnceLock;

pub(super) const MIGRATED_KEYS: &[&str] = &[
    "RAMFLUX_CLIENT_GATEWAY_QUIC_ADDR",
    "RAMFLUX_CLIENT_GATEWAY_SERVER_NAME",
    "RAMFLUX_CLIENT_GATEWAY_TCP_ADDR",
    "RAMFLUX_CLIENT_PREKEY_HTTP_URL",
    "RAMFLUX_CLIENT_RELAY_QUIC_ADDR",
    "RAMFLUX_CLIENT_RELAY_SERVER_NAME",
    "RAMFLUX_CLIENT_SIGNALING_TURN_ADDR",
    "RAMFLUX_FEDERATION_PUBLIC_MAX_HEADER_BYTES",
    "RAMFLUX_FEDERATION_PUBLIC_MAX_BODY_BYTES",
    "RAMFLUX_FEDERATION_PUBLIC_REQUEST_TIMEOUT_SECONDS",
    "RAMFLUX_FEDERATION_ADMIN_MAX_HEADER_BYTES",
    "RAMFLUX_FEDERATION_ADMIN_MAX_BODY_BYTES",
    "RAMFLUX_FEDERATION_ADMIN_REQUEST_TIMEOUT_SECONDS",
    "RAMFLUX_FEDERATION_ADMIN_TOKEN",
    "RAMFLUX_FEDERATION_DISABLE_QUIC_LISTENER",
    "RAMFLUX_FEDERATION_DISABLE_TCP_FALLBACK",
    "RAMFLUX_FEDERATION_FORCE_TCP_MESH",
    "RAMFLUX_FEDERATION_NODE_ID",
    "RAMFLUX_FEDERATION_PROVIDER_KEYRING_FILE",
    "RAMFLUX_FEDERATION_PUBLIC_ENDPOINT",
    "RAMFLUX_FEDERATION_PUBLIC_MAX_CONNECTIONS",
    "RAMFLUX_FEDERATION_TRUST_SNAPSHOT_FILE",
    "RAMFLUX_GATEWAY_ITEST_CAPTURE_JSON",
    "RAMFLUX_GATEWAY_QUIC_MAX_CONCURRENT_BIDI_STREAMS",
    "RAMFLUX_GATEWAY_QUIC_RECEIVE_WINDOW",
    "RAMFLUX_GATEWAY_QUIC_SEND_WINDOW",
    "RAMFLUX_GATEWAY_QUIC_STREAM_RECEIVE_WINDOW",
    "RAMFLUX_GATEWAY_QUIC_WORKER_THREADS",
    "RAMFLUX_GATEWAY_V3_ISSUER_CERT_FILE",
    "RAMFLUX_GATEWAY_V3_ISSUER_SEED",
    "RAMFLUX_ITEST_GATEWAY_FRAME_DELAY_MS",
    "RAMFLUX_ITEST_PERF",
    "RAMFLUX_MESH_QUIC_CLIENT_POOL_SIZE",
    "RAMFLUX_MESH_QUIC_MAX_CONCURRENT_BIDI_STREAMS",
    "RAMFLUX_MESH_QUIC_RECEIVE_WINDOW",
    "RAMFLUX_MESH_QUIC_SEND_WINDOW",
    "RAMFLUX_MESH_QUIC_STREAM_RECEIVE_WINDOW",
    "RAMFLUX_NODE_ID",
    "RAMFLUX_NODE_SERVICE_SIGNING_SEED_B64URL",
    "RAMFLUX_NOTIFY_PROVIDER_CREDENTIALS_FILE",
    "RAMFLUX_NOTIFY_WEBPUSH_ORIGINS",
    "RAMFLUX_RELAY_ALLOC_PROF_FILE",
    "RAMFLUX_RELAY_ITEST_CAPTURE_FILE",
    "RAMFLUX_RELAY_ITEST_CAPTURE_JSON",
    "RAMFLUX_RELAY_ITEST_DROP_AFTER_COMMIT",
    "RAMFLUX_RELAY_ITEST_FAIL_FIRST_V3_ACK",
    "RAMFLUX_RELAY_ITEST_HOLD_MARKER",
    "RAMFLUX_RELAY_REDB_CACHE_BYTES",
    "RAMFLUX_RELAY_TRUST_SNAPSHOT_CACHE_FILE",
    "RAMFLUX_RELAY_TRUST_SNAPSHOT_REFRESH_INTERVAL_SECONDS",
    "RAMFLUX_RELAY_VOICE_PUBLIC_ENDPOINT",
    "RAMFLUX_ROUTER_ADMIN_TOKEN",
    "RAMFLUX_ROUTER_ASYNC_INGRESS_SOCKETS",
    "RAMFLUX_ROUTER_ASYNC_POOL_SIZE",
    "RAMFLUX_ROUTER_ASYNC_WORKER_THREADS",
    "RAMFLUX_ROUTER_GROUP_COMMIT",
    "RAMFLUX_ROUTER_WAL_BATCH_MAX",
    "RAMFLUX_ROUTER_WAL_COMMIT_WINDOW_US",
    "RAMFLUX_ROUTER_WAL_DIR",
    "RAMFLUX_ROUTER_WAL_PIPELINE",
    "RAMFLUX_ROUTER_WAL_QUEUE_CAPACITY",
    "RAMFLUX_ROUTER_WAL_SHARDS",
];

pub(super) fn alias(key: &str) -> Option<String> {
    MIGRATED_KEYS
        .contains(&key)
        .then(|| format!("RF_COMPOSE_{}", key.trim_start_matches("RAMFLUX_")))
}

pub(super) fn forward_aliases(env: &mut Vec<(String, String)>, fixture: &[(String, String)]) {
    let process = std::env::vars_os()
        .filter_map(|(key, value)| Some((key.into_string().ok()?, value.into_string().ok()?)))
        .collect::<std::collections::BTreeMap<_, _>>();
    forward_with_process(env, fixture, &process);
}

fn forward_with_process(
    env: &mut Vec<(String, String)>,
    fixture: &[(String, String)],
    process: &std::collections::BTreeMap<String, String>,
) {
    let get = |key: &str| {
        fixture.iter().rev().find(|(name, _)| name == key).map(|(_, value)| value.clone())
    };
    for &old in MIGRATED_KEYS {
        let Some(new) = alias(old) else {
            continue;
        };
        // Explicit fixture values win over inherited process settings. Otherwise retain
        // BOTH inherited names so preflight can refuse a conflicting operator migration.
        let fixture_old = get(old);
        let fixture_new = get(&new);
        let value = fixture_old
            .clone()
            .or_else(|| fixture_new.clone())
            .or_else(|| process.get(old).cloned())
            .or_else(|| process.get(&new).cloned())
            .or_else(|| env.iter().find(|(name, _)| name == old).map(|(_, value)| value.clone()));
        let Some(value) = value else {
            continue;
        };
        if let Some((_, existing)) = env.iter_mut().find(|(name, _)| name == old) {
            existing.clone_from(&value);
        } else {
            env.push((old.to_owned(), value.clone()));
        }
        let alias_value =
            fixture_new.or(fixture_old).or_else(|| process.get(&new).cloned()).unwrap_or(value);
        if let Some((_, existing)) = env.iter_mut().find(|(name, _)| name == &new) {
            *existing = alias_value;
        } else {
            env.push((new, alias_value));
        }
    }
}

/// Generated per test process; never a checked-in bearer secret on a published listener.
pub(crate) fn itest_admin_token() -> &'static str {
    static TOKEN: OnceLock<String> = OnceLock::new();
    // Entropy failure leaves the value empty: Compose's required input refuses startup.
    TOKEN
        .get_or_init(|| {
            ramflux_crypto::random_32().map(ramflux_protocol::encode_base64url).unwrap_or_default()
        })
        .as_str()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alias_forwarding_preserves_fixture_empty_values_and_explicit_conflicts() {
        let mut env = vec![
            ("RAMFLUX_NOTIFY_PROVIDER_CREDENTIALS_FILE".into(), String::new()),
            ("RAMFLUX_FEDERATION_ADMIN_TOKEN".into(), "fixture-secret".into()),
            ("RF_COMPOSE_FEDERATION_ADMIN_TOKEN".into(), "different-secret".into()),
        ];
        let fixture = env.clone();
        forward_with_process(&mut env, &fixture, &std::collections::BTreeMap::new());
        assert!(
            env.contains(&("RF_COMPOSE_NOTIFY_PROVIDER_CREDENTIALS_FILE".into(), String::new()))
        );
        assert_eq!(
            env.iter().filter(|(key, _)| key == "RF_COMPOSE_FEDERATION_ADMIN_TOKEN").count(),
            1
        );
        assert!(
            env.contains(&("RF_COMPOSE_FEDERATION_ADMIN_TOKEN".into(), "different-secret".into()))
        );
        assert_eq!(itest_admin_token().len(), 43);
        assert_ne!(itest_admin_token(), "ramflux-local-admin-token");
    }

    #[test]
    fn compose_preflight_accepts_generated_tokens_and_refuses_conflicting_fixture_aliases()
    -> Result<(), Box<dyn std::error::Error>> {
        let env = super::super::compose_env_with_required_defaults(&[]);
        let mut command = std::process::Command::new("container-engine-must-not-run");
        let file = super::super::add_compose_env_file_arg(&mut command, "preflight-good", &env)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(file.path())?.permissions().mode() & 0o777, 0o600);
        }
        drop(file);
        let mut conflict = env;
        conflict.retain(|(key, _)| key != "RF_COMPOSE_FEDERATION_ADMIN_TOKEN");
        conflict.push(("RF_COMPOSE_FEDERATION_ADMIN_TOKEN".into(), "different-secret".into()));
        assert!(
            super::super::add_compose_env_file_arg(&mut command, "preflight-bad", &conflict)
                .is_err()
        );
        Ok(())
    }
}

#[cfg(test)]
mod precedence_tests {
    use super::*;

    #[test]
    fn inherited_conflicting_names_reach_preflight_unchanged_and_fixture_values_win() {
        let old = "RAMFLUX_FEDERATION_ADMIN_TOKEN";
        let new = "RF_COMPOSE_FEDERATION_ADMIN_TOKEN";
        let process =
            [(old.to_owned(), "old-secret".to_owned()), (new.to_owned(), "new-secret".to_owned())]
                .into_iter()
                .collect();
        let mut generated = vec![(old.to_owned(), "generated-secret".to_owned())];
        forward_with_process(&mut generated, &[], &process);
        assert!(generated.contains(&(old.to_owned(), "old-secret".to_owned())));
        assert!(generated.contains(&(new.to_owned(), "new-secret".to_owned())));
        let fixture = vec![(old.to_owned(), "fixture-secret".to_owned())];
        forward_with_process(&mut generated, &fixture, &process);
        assert!(generated.contains(&(old.to_owned(), "fixture-secret".to_owned())));
        assert!(generated.contains(&(new.to_owned(), "fixture-secret".to_owned())));
        let fixture = vec![(new.to_owned(), "new-only-fixture".to_owned())];
        forward_with_process(&mut generated, &fixture, &process);
        assert!(generated.contains(&(old.to_owned(), "new-only-fixture".to_owned())));
        assert!(generated.contains(&(new.to_owned(), "new-only-fixture".to_owned())));
    }
}

#[cfg(test)]
mod duplicate_input_tests {
    use super::*;

    #[test]
    fn duplicate_fixture_inputs_keep_compose_last_assignment_semantics() {
        let old = "RAMFLUX_FEDERATION_ADMIN_TOKEN";
        let new = "RF_COMPOSE_FEDERATION_ADMIN_TOKEN";
        let fixture =
            vec![(old.to_owned(), "first".to_owned()), (old.to_owned(), "last".to_owned())];
        let mut env = fixture.clone();
        forward_with_process(&mut env, &fixture, &std::collections::BTreeMap::new());
        assert_eq!(
            env.iter().rev().find(|(key, _)| key == new).map(|(_, value)| value.as_str()),
            Some("last")
        );
        assert_eq!(
            env.iter().rev().find(|(key, _)| key == old).map(|(_, value)| value.as_str()),
            Some("last")
        );
    }
}
