// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Bind opaque rf selector values to their flags before spawning a CLI subprocess.
const OPAQUE_FLAGS: &[&str] = &[
    "--relay-service-key",
    "--relay-service-key-base64",
    "--subject",
    "--account",
    "--action-id",
    "--actor",
    "--approval",
    "--author",
    "--bot",
    "--call",
    "--capability",
    "--catalog",
    "--consent",
    "--contact",
    "--conversation",
    "--creator",
    "--creator-signing-public-key",
    "--creator-target-delivery",
    "--cursor",
    "--custodian",
    "--device",
    "--envelope",
    "--event",
    "--expected-commitment",
    "--expected-public-key",
    "--grant",
    "--group",
    "--invite-id",
    "--invitee-device",
    "--invitee-principal-commitment",
    "--invitee-signing-public-key",
    "--link",
    "--member",
    "--member-device",
    "--member-principal-commitment",
    "--member-signing-public-key",
    "--member-target-delivery",
    "--message",
    "--node",
    "--node-a-id",
    "--node-b-id",
    "--node-id",
    "--object",
    "--permission",
    "--principal",
    "--principal-commitment",
    "--public-key",
    "--reader",
    "--receiver-device",
    "--recipient-device",
    "--recipient-principal-commitment",
    "--replace-provisional-root",
    "--request-id",
    "--requester",
    "--sender",
    "--server",
    "--signing-key-id",
    "--source-device",
    "--source-node",
    "--source-principal",
    "--surface-id",
    "--surface-ref",
    "--target",
    "--target-delivery",
    "--target-device",
    "--target-node",
    "--to",
    "--tombstone",
    "--tool",
];

pub(crate) fn rf_cli_args(args: impl IntoIterator<Item = impl AsRef<str>>) -> Vec<String> {
    let mut words = args.into_iter();
    let mut result = Vec::new();
    while let Some(word) = words.next() {
        let word = word.as_ref();
        if word == "--" {
            result.push(word.to_owned());
            result.extend(words.map(|value| value.as_ref().to_owned()));
            break;
        }
        if OPAQUE_FLAGS.contains(&word) {
            if let Some(value) = words.next() {
                result.push(format!("{word}={}", value.as_ref()));
            } else {
                result.push(word.to_owned());
            }
        } else {
            result.push(word.to_owned());
        }
    }
    result
}

#[test]
fn opaque_values_use_equals_without_changing_boolean_flags_or_positionals() {
    assert_eq!(
        rf_cli_args([
            "contact",
            "verify",
            "--mark-verified",
            "--account",
            "-account",
            "--contact",
            "-abc",
            "--sender=-sender",
            "--member",
            "first",
            "--member",
            "-second",
            "--body",
            "hello",
        ]),
        [
            "contact",
            "verify",
            "--mark-verified",
            "--account=-account",
            "--contact=-abc",
            "--sender=-sender",
            "--member=first",
            "--member=-second",
            "--body",
            "hello"
        ]
    );
    assert_eq!(rf_cli_args(["--", "--contact", "-abc"]), ["--", "--contact", "-abc"]);
    assert_eq!(rf_cli_args(["--contact"]), ["--contact"]);
}

#[test]
fn every_shared_opaque_flag_binds_a_hyphen_leading_value() {
    for flag in OPAQUE_FLAGS {
        assert_eq!(rf_cli_args([*flag, "-abc"]), [format!("{flag}=-abc")]);
    }
}
