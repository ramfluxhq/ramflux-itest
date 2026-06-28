// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use crate::*;

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp6_set_registration_policy(
    gateway_url: &str,
    policy: &ramflux_node_core::ItestRegistrationPolicy,
) -> Result<ramflux_node_core::ItestRegistrationPolicy, Box<dyn std::error::Error>> {
    Ok(ramflux_node_core::itest_http_post_json(
        &format!("{gateway_url}/mvp6/registration/policy"),
        policy,
    )?)
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp6_set_preauth_policy(
    gateway_url: &str,
    policy: &ramflux_node_core::GatewayPreAuthPolicy,
) -> Result<ramflux_node_core::GatewayPreAuthPolicy, Box<dyn std::error::Error>> {
    Ok(ramflux_node_core::itest_http_post_json(
        &format!("{gateway_url}/mvp6/preauth/policy"),
        policy,
    )?)
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp6_preauth_probe(
    gateway_url: &str,
    cookie: Option<&str>,
    now: u64,
) -> Result<Mvp6RawHttpResponse, Box<dyn std::error::Error>> {
    let mut headers = vec![("X-Ramflux-PreAuth-Now".to_owned(), now.to_string())];
    if let Some(cookie) = cookie {
        headers.push(("X-Ramflux-PreAuth-Cookie".to_owned(), cookie.to_owned()));
    }
    mvp6_raw_http_json(gateway_url, "POST", "/mvp6/preauth/probe", &serde_json::json!({}), &headers)
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp6_preauth_metrics(
    gateway_url: &str,
) -> Result<ramflux_node_core::GatewayPreAuthMetrics, Box<dyn std::error::Error>> {
    let response = mvp6_raw_http_json(
        gateway_url,
        "GET",
        "/mvp6/preauth/metrics",
        &serde_json::json!({}),
        &[],
    )?;
    if !response.status_is_success() {
        return Err(format!("metrics status {}", response.status).into());
    }
    Ok(serde_json::from_slice(&response.body)?)
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp6_assert_slowloris_closed(
    gateway_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (host_port, _path) = mvp6_parse_http_url(gateway_url)?;
    let addr =
        host_port.to_socket_addrs()?.next().ok_or_else(|| format!("cannot resolve {host_port}"))?;
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5))?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
    stream.write_all(
        b"POST /mvp6/preauth/probe HTTP/1.1\r\nHost: ramflux-gateway\r\nContent-Length: 2\r\n",
    )?;
    std::thread::sleep(Duration::from_millis(1_500));
    let mut buf = [0_u8; 1];
    match stream.read(&mut buf) {
        Ok(0) => Ok(()),
        Ok(_) => Err("slowloris connection produced response bytes".into()),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::TimedOut
                    | std::io::ErrorKind::WouldBlock
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::UnexpectedEof
            ) =>
        {
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp6_raw_http_json<T: serde::Serialize>(
    gateway_url: &str,
    method: &str,
    path: &str,
    value: &T,
    headers: &[(String, String)],
) -> Result<Mvp6RawHttpResponse, Box<dyn std::error::Error>> {
    let (host_port, _base_path) = mvp6_parse_http_url(gateway_url)?;
    let body = if method == "GET" { Vec::new() } else { serde_json::to_vec(value)? };
    let addr =
        host_port.to_socket_addrs()?.next().ok_or_else(|| format!("cannot resolve {host_port}"))?;
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: {host_port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    )?;
    for (name, value) in headers {
        write!(stream, "{name}: {value}\r\n")?;
    }
    stream.write_all(b"\r\n")?;
    stream.write_all(&body)?;
    mvp6_parse_raw_http_response(ramflux_node_core::read_http_response_by_content_length(
        &mut stream,
    )?)
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp6_parse_raw_http_response(
    response: ramflux_node_core::ItestHttpResponse,
) -> Result<Mvp6RawHttpResponse, Box<dyn std::error::Error>> {
    let status = response
        .status_line
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .ok_or("missing response status")?
        .parse()?;
    Ok(Mvp6RawHttpResponse { status, body: response.body })
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp6_parse_http_url(url: &str) -> Result<(&str, &str), Box<dyn std::error::Error>> {
    let rest = url.strip_prefix("http://").ok_or_else(|| format!("unsupported url {url}"))?;
    let Some((host_port, path)) = rest.split_once('/') else {
        return Ok((rest, "/"));
    };
    Ok((host_port, &url[url.len() - path.len() - 1..]))
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp6_assert_pow_registration_policy(
    gateway_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let missing_pow = mvp6_realnet_register_request("mvp6_missing_pow", 81, None)?;
    assert!(register_mvp1_identity(gateway_url, &missing_pow).is_err());
    let bad_pow = mvp6_realnet_register_request(
        "mvp6_bad_pow",
        82,
        Some(ramflux_node_core::ItestRegistrationPowProof { nonce: 0, difficulty_bits: 0 }),
    )?;
    assert!(register_mvp1_identity(gateway_url, &bad_pow).is_err());

    let alice = mvp6_realnet_register_request(
        "mvp6_challenged_alice",
        83,
        Some(mvp6_registration_pow("mvp6_challenged_alice", MVP6_REGISTRATION_POW_BITS)),
    )?;
    let alice_registered = register_mvp1_identity(gateway_url, &alice)?;
    assert_eq!(
        alice_registered.registration_trust_tier,
        ramflux_node_core::RegistrationTrustTier::Challenged
    );
    let bob = mvp6_realnet_register_request(
        "mvp6_challenged_bob",
        84,
        Some(mvp6_registration_pow("mvp6_challenged_bob", MVP6_REGISTRATION_POW_BITS)),
    )?;
    assert!(register_mvp1_identity(gateway_url, &bob).is_ok());
    let carol_limited = mvp6_realnet_register_request(
        "mvp6_source_limited_carol",
        85,
        Some(mvp6_registration_pow("mvp6_source_limited_carol", MVP6_REGISTRATION_POW_BITS)),
    )?;
    assert!(register_mvp1_identity(gateway_url, &carol_limited).is_err());
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp6_assert_friend_request_budget(
    gateway_url: &str,
    source_principal_id: &str,
    tier: &ramflux_node_core::RegistrationTrustTier,
    target_prefix: &str,
    now_base: i64,
) -> Result<(), Box<dyn std::error::Error>> {
    for index in 0..ramflux_node_core::friend_request_budget_limit(tier) {
        let response = mvp6_submit_friend_request(
            gateway_url,
            source_principal_id,
            &format!("{target_prefix}_{index}"),
            now_base + i64::from(index),
        )?;
        assert_eq!(&response.registration_trust_tier, tier);
    }
    assert!(
        mvp6_submit_friend_request(
            gateway_url,
            source_principal_id,
            &format!("{target_prefix}_over_budget"),
            now_base + 10,
        )
        .is_err()
    );
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp6_submit_friend_request(
    gateway_url: &str,
    source_principal_id: &str,
    target_principal_id: &str,
    now: i64,
) -> Result<ramflux_node_core::ItestMvp6FriendRequestBudgetResponse, Box<dyn std::error::Error>> {
    Ok(ramflux_node_core::itest_http_post_json(
        &format!("{gateway_url}/mvp6/friend/request"),
        &ramflux_node_core::ItestMvp6FriendRequestBudgetRequest {
            source_principal_id: source_principal_id.to_owned(),
            target_principal_id: target_principal_id.to_owned(),
            now,
        },
    )?)
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp6_registration_pow(
    principal_id: &str,
    difficulty_bits: u8,
) -> ramflux_node_core::ItestRegistrationPowProof {
    ramflux_node_core::ItestRegistrationPowProof {
        nonce: ramflux_crypto::solve_registration_pow(principal_id, difficulty_bits),
        difficulty_bits,
    }
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp6_realnet_register_request(
    principal_id: &str,
    nonce: i64,
    registration_pow: Option<ramflux_node_core::ItestRegistrationPowProof>,
) -> Result<ramflux_node_core::ItestMvp1RegisterIdentityRequest, Box<dyn std::error::Error>> {
    let root = ramflux_crypto::create_identity_root(principal_id, mvp6_seed(0xb1, nonce)?);
    let device = ramflux_crypto::create_device_branch(
        principal_id,
        &format!("{principal_id}_device"),
        1,
        mvp6_seed(0xc1, nonce)?,
    );
    let mut request = mvp1_named_register_request(
        &root,
        &device,
        &format!("{principal_id}_target"),
        &format!("{principal_id}_session"),
        nonce,
    )?;
    request.registration_pow = registration_pow;
    Ok(request)
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp6_seed(prefix: u8, nonce: i64) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let mut seed = [prefix; 32];
    seed[24..].copy_from_slice(&u64::try_from(nonce)?.to_be_bytes());
    Ok(seed)
}

#[cfg(test)]
pub(crate) fn safety_material(name: &str, epoch: u64) -> ramflux_crypto::ContactSafetyMaterial {
    let identity_commitment =
        ramflux_crypto::blake3_256("ramflux.test.identity_commitment.v1", name.as_bytes()).to_vec();
    let identity_key_hash =
        ramflux_crypto::blake3_256("ramflux.test.identity_key.v1", name.as_bytes()).to_vec();
    let device_seed = format!("{name}:{epoch}");
    ramflux_crypto::ContactSafetyMaterial {
        identity_commitment,
        identity_key_hash,
        lineage_head: ramflux_crypto::blake3_256(
            "ramflux.test.lineage_head.v1",
            format!("{name}:lineage:{epoch}").as_bytes(),
        )
        .to_vec(),
        devices: vec![ramflux_crypto::DeviceSafetyMaterial {
            device_id_hash: ramflux_crypto::blake3_256(
                "ramflux.test.device_id.v1",
                device_seed.as_bytes(),
            )
            .to_vec(),
            device_identity_key_hash: ramflux_crypto::blake3_256(
                "ramflux.test.device_identity_key.v1",
                device_seed.as_bytes(),
            )
            .to_vec(),
            device_signing_key_hash: ramflux_crypto::blake3_256(
                "ramflux.test.device_signing_key.v1",
                device_seed.as_bytes(),
            )
            .to_vec(),
            device_x25519_identity_key_hash: ramflux_crypto::blake3_256(
                "ramflux.test.device_x25519_key.v1",
                device_seed.as_bytes(),
            )
            .to_vec(),
            device_epoch: epoch,
            branch_authorized_event_id: format!("branch_authorized_{name}_{epoch}").into_bytes(),
        }],
    }
}

#[cfg(test)]
pub(crate) fn safety_hash_text(bytes: &[u8]) -> String {
    ramflux_protocol::encode_base64url(bytes)
}

#[cfg(test)]
pub(crate) fn mvp6_kt_bob_device() -> ramflux_crypto::DeviceBranch {
    ramflux_crypto::create_device_branch("bob_kt", "bob_kt_device", 1, [0x62; 32])
}

#[cfg(test)]
pub(crate) fn mvp6_kt_fixture() -> Result<Mvp6KtFixture, Box<dyn std::error::Error>> {
    let log_key = ramflux_crypto::fixture_signing_key();
    let bob_device = mvp6_kt_bob_device();
    let alice_leaf = mvp6_signed_kt_leaf("alice_kt", "node-a.example", 1, &bob_device)?;
    let bob_leaf_v1 = mvp6_signed_kt_leaf("bob_kt", "node-b.example", 2, &bob_device)?;
    let carol_leaf = mvp6_signed_kt_leaf("carol_kt", "node-c.example", 3, &bob_device)?;
    let dana_leaf = mvp6_signed_kt_leaf("dana_kt", "node-a.example", 4, &bob_device)?;
    let old_leaf_hashes = vec![
        ramflux_crypto::kt_leaf_canonical_hash(&alice_leaf)?,
        ramflux_crypto::kt_leaf_canonical_hash(&bob_leaf_v1)?,
        ramflux_crypto::kt_leaf_canonical_hash(&carol_leaf)?,
    ];
    let bob_leaf_v1_hash = old_leaf_hashes[1];
    let new_leaf_hashes = vec![
        old_leaf_hashes[0],
        old_leaf_hashes[1],
        old_leaf_hashes[2],
        ramflux_crypto::kt_leaf_canonical_hash(&dana_leaf)?,
    ];
    let old_root = ramflux_crypto::kt_merkle_root(&old_leaf_hashes);
    let new_root = ramflux_crypto::kt_merkle_root(&new_leaf_hashes);
    let old_tree_head = ramflux_crypto::sign_kt_tree_head(
        old_leaf_hashes.len() as u64,
        old_root,
        1_760_000_000,
        &log_key,
    )?;
    let new_tree_head = ramflux_crypto::sign_kt_tree_head(
        new_leaf_hashes.len() as u64,
        new_root,
        1_760_000_100,
        &log_key,
    )?;
    let bob_inclusion_proof_v1 = ramflux_crypto::KtInclusionProof {
        leaf_index: 1,
        tree_size: old_leaf_hashes.len(),
        audit_path: ramflux_crypto::kt_inclusion_proof(&old_leaf_hashes, 1)?,
        tree_head: old_tree_head.clone(),
    };
    let append_consistency_proof = ramflux_crypto::KtConsistencyProof {
        old_leaf_hashes,
        appended_leaf_hashes: vec![new_leaf_hashes[3]],
        old_tree_head: old_tree_head.clone(),
        new_tree_head: new_tree_head.clone(),
    };
    Ok(Mvp6KtFixture {
        bob_leaf_v1,
        bob_leaf_v1_hash,
        bob_inclusion_proof_v1,
        old_tree_head,
        new_tree_head,
        new_leaf_hashes,
        append_consistency_proof,
    })
}

#[cfg(test)]
pub(crate) fn mvp6_signed_kt_leaf(
    name: &str,
    home_node: &str,
    sequence: u64,
    device: &ramflux_crypto::DeviceBranch,
) -> Result<ramflux_crypto::KtLeaf, Box<dyn std::error::Error>> {
    let material = safety_material(name, 1);
    Ok(ramflux_crypto::sign_kt_leaf(
        ramflux_crypto::KtLeafInput {
            identity_commitment: &safety_hash_text(&material.identity_commitment),
            lineage_head: &safety_hash_text(&material.lineage_head),
            device_set_hash: &safety_hash_text(&ramflux_crypto::device_set_hash(&material.devices)),
            home_node,
            sequence,
            created_at: 1_760_000_000 + i64::try_from(sequence)?,
        },
        &device.signing_key,
    )?)
}

#[cfg(test)]
pub(crate) fn mvp6_verified_account_db(
    test_name: &str,
) -> Result<ramflux_storage::AccountDb, Box<dyn std::error::Error>> {
    let root = temp_root(test_name)?;
    let index = ramflux_storage::AccountIndex::open(root)?;
    index.create_account("alice_verify", "alice_verify")?;
    let key = ramflux_storage::AccountDbKey::derive("alice_verify", b"alice-verify-secret");
    Ok(ramflux_storage::AccountDb::open(&index, "alice_verify", &key)?)
}

#[cfg(test)]
pub(crate) fn mvp6_mark_bob_verified(
    db: &ramflux_storage::AccountDb,
    bob: &ramflux_crypto::ContactSafetyMaterial,
) -> Result<ramflux_storage::ContactVerificationRecord, Box<dyn std::error::Error>> {
    let alice = safety_material("alice", 1);
    Ok(db.mark_contact_verified(ramflux_storage::ContactVerificationUpdate {
        contact_identity_commitment: &safety_hash_text(&bob.identity_commitment),
        safety_number_hash: &safety_hash_text(&ramflux_crypto::safety_fingerprint(&alice, bob)),
        device_set_hash: &safety_hash_text(&ramflux_crypto::device_set_hash(&bob.devices)),
        lineage_head: &safety_hash_text(&bob.lineage_head),
        verified_at: 1_760_000_000,
        verified_by_device_id: "alice_device_verify",
    })?)
}
