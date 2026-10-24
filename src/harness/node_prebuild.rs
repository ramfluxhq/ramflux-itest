// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Compose fixtures build their own staged node binaries before images can consume old files.
#[cfg(feature = "realnet")]
use std::{
    collections::BTreeSet,
    path::Path,
    sync::{Mutex, OnceLock},
};

#[cfg(feature = "realnet")]
pub(crate) fn ensure_node_prebuild(
    root: &Path,
    federation_compio: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    static READY: OnceLock<Mutex<BTreeSet<(std::path::PathBuf, bool)>>> = OnceLock::new();
    let mut ready = READY
        .get_or_init(|| Mutex::new(BTreeSet::new()))
        .lock()
        .map_err(|_| "node prebuild lock poisoned")?;
    let key = (root.to_path_buf(), federation_compio);
    if ready.contains(&key) {
        return Ok(());
    }
    crate::realnet_step(
        "prepare current node binaries",
        format!("source={}", root.join("ramflux").display()),
    );
    let mut env = vec![("RAMFLUX_REALNET_PREBUILD_ONLY".to_owned(), "1".to_owned())];
    if federation_compio {
        env.push(("RAMFLUX_FEDERATION_COMPIO".into(), "1".into()));
    }
    super::realnet_compose_stun::run_deploy_script_with_env(
        root,
        "ramflux/deploy/scripts/run-realnet.sh",
        &env,
    )?;
    ready.insert(key);
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
mod tests {
    use super::*;
    #[test]
    fn compose_prebuild_retries_failure_and_stages_current_nodes_once_per_variant()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = crate::temp_root("node-prebuild")?;
        let scripts = root.join("ramflux/deploy/scripts");
        std::fs::create_dir_all(&scripts)?;
        let script = scripts.join("run-realnet.sh");
        std::fs::write(&script, "#!/bin/sh\nexit 1\n")?;
        assert!(ensure_node_prebuild(&root, false).is_err());
        std::fs::write(
            &script,
            "#!/bin/sh\nset -eu\n[ \"$RAMFLUX_REALNET_PREBUILD_ONLY\" = 1 ]\nprintf '%s\\n' \"${RAMFLUX_FEDERATION_COMPIO:-0}\" >> prebuild-runs\nprintf current > staged-node\n",
        )?;
        std::fs::write(root.join("staged-node"), "old-main")?;
        ensure_node_prebuild(&root, false)?;
        assert_eq!(std::fs::read_to_string(root.join("staged-node"))?, "current");
        ensure_node_prebuild(&root, false)?;
        assert_eq!(std::fs::read_to_string(root.join("prebuild-runs"))?.lines().count(), 1);
        ensure_node_prebuild(&root, true)?;
        assert_eq!(std::fs::read_to_string(root.join("prebuild-runs"))?.lines().last(), Some("1"));
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
