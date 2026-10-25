// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Materialize fixture discovery identities as mounted secrets rather than container environment.
use std::{io::Write, path::Path};
pub(crate) fn write_discovery_secret(
    deploy: &Path,
    env: &[(String, String)],
) -> Result<(), Box<dyn std::error::Error>> {
    let Some((_, encoded)) =
        env.iter().find(|(key, _)| key == "RAMFLUX_FEDERATION_NODE_SIGNING_SEED_B64URL")
    else {
        return Err("fixture discovery identity missing".into());
    };
    let bytes = ramflux_protocol::decode_base64url(encoded)?;
    if bytes.len() != 32 {
        return Err("fixture discovery secret must contain 32 bytes".into());
    }
    let certs = env
        .iter()
        .find(|(key, _)| key == "RAMFLUX_CERTS_DIR")
        .map_or_else(|| deploy.join("certs"), |(_, value)| deploy.join(value));
    let path = certs.join("node-identity/node-signing.key");
    std::fs::create_dir_all(path.parent().ok_or("secret parent missing")?)?;
    let temporary = path.with_extension(format!("key.{}", std::process::id()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    file.write_all(encoded.as_bytes())?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(temporary, path)?;
    Ok(())
}
#[test]
fn fixture_secret_matches_discovery_pin_and_has_private_mode()
-> Result<(), Box<dyn std::error::Error>> {
    let root = super::temp_root("server-secret")?;
    let seed = ramflux_protocol::encode_base64url([91; 32]);
    write_discovery_secret(
        &root,
        &[("RAMFLUX_FEDERATION_NODE_SIGNING_SEED_B64URL".into(), seed.clone())],
    )?;
    let path = root.join("certs/node-identity/node-signing.key");
    assert_eq!(std::fs::read_to_string(&path)?, seed);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
    }
    let custom = root.join("per-node");
    write_discovery_secret(
        &root,
        &[
            ("RAMFLUX_FEDERATION_NODE_SIGNING_SEED_B64URL".into(), seed.clone()),
            ("RAMFLUX_CERTS_DIR".into(), custom.to_string_lossy().into_owned()),
        ],
    )?;
    assert_eq!(std::fs::read_to_string(custom.join("node-identity/node-signing.key"))?, seed);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
