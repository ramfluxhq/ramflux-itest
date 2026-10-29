// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Per-process test secrets for the required inputs declared by the pinned product.
use std::path::PathBuf;
use std::sync::OnceLock;

type HarnessResult<T> = Result<T, Box<dyn std::error::Error>>;

#[derive(serde::Deserialize)]
struct SecurityInput {
    service_key: String,
    key: String,
    fixture_key: String,
    default: String,
}

fn required_inputs() -> HarnessResult<&'static [SecurityInput]> {
    static INPUTS: OnceLock<Result<Vec<SecurityInput>, String>> = OnceLock::new();
    INPUTS
        .get_or_init(|| {
            let load = || -> HarnessResult<Vec<SecurityInput>> {
                let deploy = super::self_referencing_defaults::pinned_product_deploy_dir()?
                    .ok_or("pinned product checkout required for security input inventory")?;
                let output = std::process::Command::new("python3")
                    .args(["-B", "-c", include_str!("compose_security_inventory.py")])
                    .arg(deploy)
                    .output()?;
                if !output.status.success() {
                    return Err(format!(
                        "required Compose security input inventory failed: {}",
                        String::from_utf8_lossy(&output.stderr)
                    )
                    .into());
                }
                Ok(serde_json::from_slice(&output.stdout)?)
            };
            load().map_err(|error| error.to_string())
        })
        .as_deref()
        .map_err(|error| error.clone().into())
}

struct SecurityMaterial {
    directory: PathBuf,
    issuer_seed: String,
    offline_root_public_key: String,
}

impl SecurityMaterial {
    fn generate() -> HarnessResult<Self> {
        use std::io::Write;
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

        let issuer_seed = ramflux_crypto::random_32()?;
        let offline_root_seed = ramflux_crypto::random_32()?;
        let directory = std::env::temp_dir().join(format!(
            "ramflux-itest-security-{}",
            ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
        ));
        std::fs::DirBuilder::new().mode(0o700).create(&directory)?;
        let mut seed_file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(directory.join("offline-root.seed"))?;
        seed_file.write_all(&offline_root_seed)?;
        seed_file.sync_all()?;
        Ok(Self {
            directory,
            issuer_seed: ramflux_protocol::encode_base64url(issuer_seed),
            offline_root_public_key: ramflux_crypto::public_key_base64url_from_seed(
                offline_root_seed,
            ),
        })
    }
}

fn security_material() -> HarnessResult<&'static SecurityMaterial> {
    static MATERIAL: OnceLock<Result<SecurityMaterial, String>> = OnceLock::new();
    MATERIAL
        .get_or_init(|| SecurityMaterial::generate().map_err(|error| error.to_string()))
        .as_ref()
        .map_err(|error| error.clone().into())
}

pub(super) fn supply_required_inputs(env: &mut Vec<(String, String)>) -> HarnessResult<()> {
    for input in required_inputs()? {
        // Alias forwarding has already preserved fixture/process precedence, including
        // explicit empty inputs and conflicting aliases for the product to refuse.
        if env.iter().any(|(key, _)| key == &input.key) {
            continue;
        }
        let value = if let Some(value) = std::env::var_os(&input.key) {
            value.to_string_lossy().into_owned()
        } else if !input.default.is_empty() {
            input.default.clone()
        } else {
            match input.service_key.as_str() {
                "RAMFLUX_GATEWAY_V3_ISSUER_SEED" => security_material()?.issuer_seed.clone(),
                "RAMFLUX_FEDERATION_PROVIDER_OFFLINE_ROOT_PUBLIC_KEY" => {
                    security_material()?.offline_root_public_key.clone()
                }
                "RAMFLUX_FEDERATION_TRUST_ENDPOINT" => "ramflux-federation:7443".to_owned(),
                "RAMFLUX_FEDERATION_TRUST_ISSUER_NODE_ID" => "localhost".to_owned(),
                key => return Err(format!("no fixture generator for required input {key}").into()),
            }
        };
        env.push((input.key.clone(), value.clone()));
        if input.fixture_key != input.key {
            env.push((input.fixture_key.clone(), value));
        }
    }
    // Keep the private half exclusively in the harness temp directory, out of Compose env.
    let material = security_material()?;
    if !material.directory.join("offline-root.seed").is_file() {
        return Err("generated offline-root private material is missing".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_product_required_security_input_is_nonempty() -> HarnessResult<()> {
        let env = super::super::compose_env_with_required_defaults(&[])?;
        for input in required_inputs()? {
            let value = env.iter().find(|(key, _)| key == &input.key).map(|(_, value)| value);
            assert!(value.is_some_and(|value| !value.trim().is_empty()), "{}", input.key);
        }
        Ok(())
    }

    #[test]
    fn secrets_are_fresh_and_private_root_matches_public_key() -> HarnessResult<()> {
        use std::os::unix::fs::PermissionsExt;
        let first = SecurityMaterial::generate()?;
        let second = SecurityMaterial::generate()?;
        assert_ne!(first.issuer_seed, second.issuer_seed);
        assert_ne!(first.offline_root_public_key, second.offline_root_public_key);
        for material in [first, second] {
            let path = material.directory.join("offline-root.seed");
            let seed: [u8; 32] = std::fs::read(&path)?.try_into().map_err(|_| "seed length")?;
            assert_eq!(
                ramflux_crypto::public_key_base64url_from_seed(seed),
                material.offline_root_public_key
            );
            assert_eq!(std::fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
            assert_eq!(std::fs::metadata(&material.directory)?.permissions().mode() & 0o777, 0o700);
            std::fs::remove_dir_all(material.directory)?;
        }
        Ok(())
    }

    #[test]
    fn supplied_signed_material_and_explicit_empty_inputs_are_preserved() -> HarnessResult<()> {
        for supplied in
            [String::new(), ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)]
        {
            let fixture = required_inputs()?
                .iter()
                .filter(|input| {
                    matches!(
                        input.service_key.as_str(),
                        "RAMFLUX_GATEWAY_V3_ISSUER_SEED"
                            | "RAMFLUX_FEDERATION_PROVIDER_OFFLINE_ROOT_PUBLIC_KEY"
                    )
                })
                .map(|input| (input.key.clone(), supplied.clone()))
                .collect::<Vec<_>>();
            let env = super::super::compose_env_with_required_defaults(&fixture)?;
            for (key, value) in fixture {
                assert!(env.contains(&(key, value)));
            }
        }
        Ok(())
    }

    #[test]
    fn product_preflight_renders_required_security_inputs() -> HarnessResult<()> {
        let Ok(provider) = std::env::var("RAMFLUX_ITEST_PREFLIGHT_RENDER") else {
            eprintln!("config render not requested (set RAMFLUX_ITEST_PREFLIGHT_RENDER)");
            return Ok(());
        };
        let deploy = super::super::self_referencing_defaults::pinned_product_deploy_dir()?
            .ok_or("pinned product checkout required")?;
        let env = super::super::compose_env_with_required_defaults(&[(
            "RAMFLUX_ITEST_FEDERATION_ADMIN_PORT".to_owned(),
            "18084".to_owned(),
        )])?;
        let render_material = SecurityMaterial::generate()?;
        let engine = render_material.directory.join("config-only-engine");
        std::fs::write(
            &engine,
            "#!/bin/sh\nif [ \"$1\" = --version ]; then echo 'podman version 5.4.2'; exit 0; fi\nexit 91\n",
        )?;
        std::fs::set_permissions(&engine, std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
        let mut files = std::fs::read_dir(&deploy)?
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name == "docker-compose.yml" || name.starts_with("docker-compose.itest"))
            .filter(|name| std::path::Path::new(name).extension().is_some_and(|ext| ext == "yml"))
            .collect::<Vec<_>>();
        files.sort();
        for name in files {
            let mut compose = std::process::Command::new("render-only");
            let _file = super::super::add_compose_env_file_arg(&mut compose, "security", &env)?;
            if name != "docker-compose.yml" && name != "docker-compose.itest.yml" {
                compose.args(["-f", "docker-compose.itest.yml"]);
            }
            if name == "docker-compose.itest.object-v3.yml" {
                compose.args(["-f", "docker-compose.itest.cross-gateway.yml"]);
            }
            compose.args(["-f", &name]);
            let status = std::process::Command::new("python3")
                .arg("-B")
                .arg(deploy.join("scripts/compose-preflight.py"))
                .args(["--provider", &provider])
                .args(compose.get_args())
                // Config rendering needs no engine. Prevent even accidental engine calls.
                .args(if provider == "docker" {
                    Vec::<&std::ffi::OsStr>::new()
                } else {
                    vec![std::ffi::OsStr::new("--podman-path"), engine.as_os_str()]
                })
                .envs(env.iter().map(|(key, value)| (key, value)))
                .current_dir(&deploy)
                .status()?;
            assert!(status.success(), "product preflight rejected {name}");
            eprintln!("product preflight config-only PASS: {name}");
        }
        std::fs::remove_dir_all(render_material.directory)?;
        Ok(())
    }
}
