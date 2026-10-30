// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Deterministic network creation races and readiness failures without an engine.
use super::*;

#[test]
fn existing_network_is_reused_without_creation() -> Result<(), String> {
    ensure_network(
        "mesh",
        |op| {
            assert_eq!(op, "inspect");
            Ok(())
        },
        || {},
        3,
    )
}

fn scripted_readiness(create: Result<(), String>) -> Result<(), String> {
    let mut steps = vec![
        ("inspect", Err("not found".into())),
        ("create", create),
        ("inspect", Err("not visible yet".into())),
        ("inspect", Ok(())),
    ]
    .into_iter();
    let mut waits = 0;
    ensure_network(
        "mesh",
        |operation| {
            let (expected, result) = steps.next().ok_or("unexpected command")?;
            assert_eq!(operation, expected);
            result
        },
        || waits += 1,
        3,
    )?;
    assert!(steps.next().is_none());
    assert_eq!(waits, 1);
    Ok(())
}

#[test]
fn concurrent_creator_is_accepted_only_after_readiness() -> Result<(), String> {
    scripted_readiness(Err("already exists".into()))
}

#[test]
fn successful_creation_still_waits_for_readiness() -> Result<(), String> {
    scripted_readiness(Ok(()))
}

#[test]
fn permanently_missing_network_fails_before_compose() {
    for create_succeeds in [false, true] {
        let mut probes = 0;
        let error = ensure_network(
            "mesh",
            |operation| {
                probes += 1;
                if operation == "create" && create_succeeds {
                    Ok(())
                } else {
                    Err("daemon unavailable".into())
                }
            },
            || {},
            3,
        )
        .err();
        assert!(error.is_some_and(
            |error| error.contains("daemon unavailable") && error.contains("3 probes")
        ));
        assert_eq!(probes, 5);
    }
}

#[test]
fn fixture_network_name_is_the_same_name_created_and_passed_to_compose()
-> Result<(), Box<dyn std::error::Error>> {
    let mut env = vec![(NETWORK_ENV.into(), "fixture-mesh".into())];
    supply_network_name(&mut env)?;
    assert_eq!(network_name(&env)?, "fixture-mesh");
    assert_eq!(env.len(), 1);
    let generated = super::super::compose_env_with_required_defaults(&env)?;
    assert_eq!(network_name(&generated)?, "fixture-mesh");
    Ok(())
}

#[test]
fn invalid_or_duplicate_network_names_are_refused() {
    for name in ["", "-option", "bad\nname", "bad name", "${MESH}"] {
        assert!(supply_network_name(&mut vec![(NETWORK_ENV.into(), name.into())]).is_err());
    }
    assert!(
        supply_network_name(&mut vec![
            (NETWORK_ENV.into(), "one".into()),
            (NETWORK_ENV.into(), "two".into())
        ])
        .is_err()
    );
}
