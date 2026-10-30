// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! A fresh native restore remains local-only until explicit phrase recovery promotes its branch.
#![cfg(feature = "realnet")]
use super::*;
use serde_json::{Value, json};
use std::sync::Arc;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const S47_GATEWAY_CAPTURE: &str = "/tmp/ramflux-gateway-itest-capture-s47.jsonl";
const S47_COMPOSE_PROJECT: &str = "ramflux-s47-restore-device";

#[test]
fn mvp_s47_realnet_restore_device_rejoin_manifest_gate() -> TestResult {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }
    crate::harness::sdk_receive_diagnostics::install();
    let mut stack = start_client_directory_stack_named(
        S47_COMPOSE_PROJECT,
        S8ComposePorts {
            gateway_http: 64_761,
            gateway_quic: 64_621,
            router_http: 64_760,
            router_mesh: 64_622,
            notify_http: 64_763,
            federation_http: 64_762,
            federation_mesh: 64_623,
            relay_http: 64_764,
            relay_media_udp: 64_171,
            signaling_turn_udp: 64_640,
            signaling_turn_tcp: 64_641,
            retention_http: 64_767,
        },
        &[
            ("RAMFLUX_ITEST_RELAY_CLIENT_QUIC_PORT".into(), "64765".into()),
            ("RAMFLUX_GATEWAY_ITEST_CAPTURE_JSON".into(), S47_GATEWAY_CAPTURE.into()),
        ],
    )?;
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(run(&stack.node))?;
    stack.node.guard.mark_success();
    Ok(())
}

async fn run(node: &S8RealnetNode) -> TestResult {
    wait_relay_quic_healthy("127.0.0.1:64765", "ramflux-relay", &node.ca_cert).await?;
    wait_for_private_gateway_quic(node.gateway_quic_addr, &node.ca_cert).await?;
    let root = temp_root("s47_native_restore")?;
    let sockets = [root.join("alice.sock"), root.join("replacement.sock"), root.join("bob.sock")];
    let profile = native_node_profile(node, "127.0.0.1:64765")?;
    let vaults: [Arc<RecordingPrimaryVault>; 3] = std::array::from_fn(|_| Arc::default());
    let mut configs = Vec::new();
    let mut stops = Vec::new();
    for (index, socket) in sockets.iter().enumerate() {
        let mut config =
            ramflux_sdk::LocalBusConfig::new(socket, root.join(format!("account-{index}")));
        config.custody_vault = Some(vaults[index].clone());
        config.builtin_nodes = vec![profile.clone()];
        let (stop, receiver) = tokio::sync::watch::channel(false);
        stops.push(stop);
        configs.push((config, receiver));
    }
    let [alice, replacement, bob] = configs.try_into().map_err(|_| "S47 daemon config count")?;
    let client_flow = async {
        let result = flow(node, &sockets, &root, &vaults).await;
        for stop in stops {
            let _ = stop.send(true);
        }
        result
    };
    let result = Box::pin(tokio::time::timeout(Duration::from_mins(4), async {
        let (alice_result, replacement_result, bob_result, flow_result) = tokio::join!(
            ramflux_sdk::serve_local_bus_until(alice.0, alice.1),
            ramflux_sdk::serve_local_bus_until(replacement.0, replacement.1),
            ramflux_sdk::serve_local_bus_until(bob.0, bob.1),
            client_flow,
        );
        alice_result?;
        replacement_result?;
        bob_result?;
        flow_result
    }))
    .await;
    let _ = std::fs::remove_dir_all(&root);
    result??;
    Ok(())
}

async fn flow(
    node: &S8RealnetNode,
    sockets: &[PathBuf; 3],
    root: &Path,
    vaults: &[Arc<RecordingPrimaryVault>; 3],
) -> TestResult {
    for socket in sockets {
        mvp_s4_wait_for_socket(socket).await?;
    }
    let mut alice = ramflux_sdk::LocalBusClient::connect(&sockets[0]).await?;
    let mut replacement = ramflux_sdk::LocalBusClient::connect(&sockets[1]).await?;
    let mut bob = ramflux_sdk::LocalBusClient::connect(&sockets[2]).await?;
    for bus in [&mut alice, &mut replacement, &mut bob] {
        select_native_node(bus, &node.node_id).await?;
    }
    let alice_account = create_native_account(&sockets[0], "Alice").await?;
    let bob_account = create_native_account(&sockets[2], "Bob").await?;
    assert_foreign_registration_refused(node, &alice_account).await?;
    let added = call(
        &mut alice,
        &alice_account.account_id,
        "contact.add",
        json!({"principal_id":bob_account.principal_id}),
    )
    .await?;
    assert_eq!(added["contact"]["root_commitment"], bob_account.anchor);
    wait_for_pending_native_contact_request(&mut bob, &bob_account.account_id, &alice_account)
        .await?;
    let accepted = call(
        &mut bob,
        &bob_account.account_id,
        "contact.accept",
        json!({"principal_id":alice_account.principal_id}),
    )
    .await?;
    assert_eq!(accepted["state"], "accepted");
    assert_eq!(accepted["contact"]["root_commitment"], alice_account.anchor);
    send(
        &mut bob,
        &bob_account,
        &alice_account.anchor,
        &alice_account.device_id,
        &alice_account.delivery_id,
        "s47-before-restore",
    )
    .await?;
    wait_for_message(&mut alice, &alice_account.account_id, "s47-before-restore").await?;

    let archive = root.join("alice.rfbackup");
    create_native_backup(&mut alice, &alice_account.account_id, &archive).await?;
    let restored_id = restore_native_backup(&mut replacement, &archive, true).await?;
    call(
        &mut replacement,
        &restored_id,
        "account.unlock",
        json!({"passphrase":NATIVE_RESTORED_PASSPHRASE}),
    )
    .await?;
    let pending = call(&mut replacement, &restored_id, "account.status", json!({})).await?;
    crate::harness::sdk_receive_diagnostics::response("s47 pending restore", &pending);
    assert_eq!(pending["networking"], "networking_pending");
    assert_ne!(pending["device_id"], alice_account.device_id);
    wait_for_message(&mut replacement, &restored_id, "s47-before-restore").await?;
    let refusal = replacement
        .request_frame_response(ramflux_sdk::LocalBusFrame::request(
            "s47-pending-receive",
            Some(restored_id.clone()),
            "message",
            "message.receive",
            json!({"limit":1,"conversation_id":null,"auto_fetch_attachments":false}),
        ))
        .await?;
    assert_eq!(refusal.error.as_ref().map(|error| error.code.as_str()), Some("NetworkingPending"));
    crate::harness::sdk_receive_diagnostics::failure_state(&mut replacement, &restored_id).await;
    promote_and_verify(
        &sockets[1],
        &restored_id,
        &alice_account,
        &bob_account,
        &mut replacement,
        &mut bob,
    )
    .await?;
    assert_gateway_has_no_private_material(&alice_account, vaults)?;
    Ok(())
}

async fn promote_and_verify(
    replacement_socket: &Path,
    restored_id: &str,
    alice_account: &NativeAccount,
    bob_account: &NativeAccount,
    replacement: &mut ramflux_sdk::LocalBusClient,
    bob: &mut ramflux_sdk::LocalBusClient,
) -> TestResult {
    let recovered = recover_native_account(
        replacement_socket,
        restored_id,
        alice_account,
        NATIVE_RESTORED_PASSPHRASE,
    )
    .await?;
    assert_eq!(recovered.networking, ramflux_sdk::custody::CreationState::Live);
    let current = call(replacement, restored_id, "account.status", json!({})).await?;
    assert_eq!(current["networking"], "live");
    let refreshed = call(
        bob,
        &bob_account.account_id,
        "device.refresh",
        json!({"principal_commitment":alice_account.anchor}),
    )
    .await?;
    let devices = refreshed["devices"].as_array().ok_or("native roster missing")?;
    assert_eq!(devices.len(), 2);
    assert!(devices.iter().any(|device| {
        device["device_id"] == alice_account.device_id && device["status"] == "revoked"
    }));
    let current_device = current["device_id"].as_str().ok_or("replacement device missing")?;
    let current_delivery =
        current["target_delivery_id"].as_str().ok_or("replacement delivery missing")?;
    assert!(
        devices.iter().any(|device| {
            device["device_id"] == current_device && device["status"] == "active"
        })
    );
    assert!(
        send(
            bob,
            bob_account,
            &alice_account.anchor,
            &alice_account.device_id,
            &alice_account.delivery_id,
            "s47-revoked-target",
        )
        .await
        .is_err()
    );
    send(
        bob,
        bob_account,
        &alice_account.anchor,
        current_device,
        current_delivery,
        "s47-after-recovery",
    )
    .await?;
    wait_for_message(replacement, restored_id, "s47-after-recovery").await?;
    Ok(())
}

async fn call(
    bus: &mut ramflux_sdk::LocalBusClient,
    account: &str,
    method: &str,
    body: Value,
) -> TestResult<Value> {
    Ok(bus
        .request(Some(account.into()), method.split('.').next().ok_or("method")?, method, body)
        .await?)
}

async fn send(
    bus: &mut ramflux_sdk::LocalBusClient,
    owner: &NativeAccount,
    anchor: &str,
    device: &str,
    delivery: &str,
    id: &str,
) -> TestResult<Value> {
    call(
        bus,
        &owner.account_id,
        "message.submit",
        json!({
            "conversation_id":"s47-thread","message_id":id,"envelope_id":id,
            "source_principal_id":owner.principal_id,"sender_id":owner.device_id,
            "recipient_device_id":device,"recipient_principal_commitment":anchor,
            "target_delivery_id":delivery,"encrypted_body_base64":"",
            "plaintext_body_base64":ramflux_protocol::encode_base64url(b"native restore traffic"),
            "created_at":realnet_now_i64(),"ttl":600
        }),
    )
    .await
}

async fn wait_for_message(
    bus: &mut ramflux_sdk::LocalBusClient,
    account: &str,
    message: &str,
) -> TestResult {
    for _ in 0..100 {
        let rows =
            call(bus, account, "message.read", json!({"conversation_id":"s47-thread"})).await?;
        if let Some(row) = rows["messages"]
            .as_array()
            .and_then(|rows| rows.iter().find(|row| row["message_id"] == message))
        {
            assert_eq!(
                row["body_utf8"], "native restore traffic",
                "S47 restored device must decrypt the delivered body"
            );
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(format!("native restore message {message} was not received").into())
}

#[allow(clippy::too_many_lines)]
async fn assert_foreign_registration_refused(
    node: &S8RealnetNode,
    alice: &NativeAccount,
) -> TestResult {
    use ramflux_protocol::custody::{
        CustodyProofAction, CustodyRefusal, CustodyServerFrame, DeviceRef, Publication,
    };

    let before = fetch_s47_manifest(&node.gateway_url, &alice.anchor)?;
    let before_manifest = ramflux_protocol::canonical_json_bytes(&before)?;
    let before_device_set = ramflux_protocol::canonical_json_bytes(
        before
            .pointer("/custody/publication/record")
            .ok_or("S47 native device set missing before foreign registration")?,
    )?;

    let branch = ramflux_crypto::create_device_branch(
        "principal-s47-foreign",
        "device-s47-foreign",
        1,
        [0x47; 32],
    );
    let agreement = ramflux_crypto::X25519KeyPair::from_seed([0x48; 32]);
    let foreign_phrase = ramflux_crypto::custody::RecoveryPhrase::from_entropy(&[0x45; 32])?;
    let foreign_master = ramflux_crypto::custody::MasterKey::from_phrase(&foreign_phrase)?;
    let foreign_primary = ramflux_crypto::custody::SelfSigningKey::from_vault_seed(
        &zeroize::Zeroizing::new([0x46; 32]),
    );
    let foreign_record = ramflux_crypto::custody::create_genesis(
        &foreign_master,
        &foreign_primary,
        &branch,
        &agreement,
        ramflux_crypto::custody::GenesisInput {
            principal_kind: ramflux_protocol::PrincipalKind::Human,
            display_name: "S47 foreign root".into(),
            issued_at: u64::try_from(realnet_now_i64())?,
            master_cert_id: ramflux_protocol::encode_base64url([0x4a; 32]),
            branch_cert_id: ramflux_protocol::encode_base64url([0x4b; 32]),
            external_human_primary: None,
        },
    )?;
    let signed_prekey = ramflux_crypto::X25519KeyPair::from_seed([0x49; 32]);
    let bundle = ramflux_crypto::create_prekey_bundle(
        &branch,
        &agreement,
        "s47-foreign-prekey",
        &signed_prekey,
        None,
        None,
    )?;
    let register = CustodyProofAction::Register { prekey_bundle: serde_json::to_value(bundle)? };
    let claimed = DeviceRef {
        account_anchor: alice.anchor.clone(),
        device_id: branch.device_id.clone(),
        device_epoch: branch.device_epoch,
    };
    let registration_refusal = attempt_foreign_custody_action(
        node,
        &claimed,
        &branch,
        &foreign_record,
        register,
        [0x4c; 32],
    )
    .await?;
    assert_eq!(
        registration_refusal,
        CustodyServerFrame::Refused { code: CustodyRefusal::BindingRefused },
        "foreign-device S47 registration must receive the binding refusal"
    );

    let mut foreign_claiming_alice = foreign_record.clone();
    foreign_claiming_alice.body.account_anchor.clone_from(&alice.anchor);
    let publish = CustodyProofAction::Publish {
        publication: Box::new(Publication {
            record: foreign_claiming_alice.clone(),
            compacted_ids: None,
        }),
    };
    let publication_refusal = attempt_foreign_custody_action(
        node,
        &claimed,
        &branch,
        &foreign_claiming_alice,
        publish,
        [0x4d; 32],
    )
    .await?;
    assert_eq!(
        publication_refusal,
        CustodyServerFrame::Refused { code: CustodyRefusal::InvalidInput },
        "foreign-signed S47 publication claiming Alice's anchor must be refused"
    );

    let after = fetch_s47_manifest(&node.gateway_url, &alice.anchor)?;
    assert_eq!(ramflux_protocol::canonical_json_bytes(&after)?, before_manifest);
    assert_eq!(
        ramflux_protocol::canonical_json_bytes(
            after
                .pointer("/custody/publication/record")
                .ok_or("S47 native device set missing after foreign registration")?,
        )?,
        before_device_set
    );
    Ok(())
}

async fn attempt_foreign_custody_action(
    node: &S8RealnetNode,
    claimed: &ramflux_protocol::custody::DeviceRef,
    branch: &ramflux_crypto::DeviceBranch,
    record: &ramflux_protocol::custody::Envelope<ramflux_protocol::custody::DeviceSet>,
    action: ramflux_protocol::custody::CustodyProofAction,
    proof_id: [u8; 32],
) -> TestResult<ramflux_protocol::custody::CustodyServerFrame> {
    use ramflux_crypto::custody::{branch_exporter_hash, sign_branch_proof_v3};
    use ramflux_protocol::custody::{
        BindingMode, BranchProofV3, CustodyClientFrame, CustodyServerFrame,
    };
    use ramflux_transport::{GatewaySessionFrameSink, GatewaySessionFrameSource};

    let (_, mut stream) = ramflux_transport::TcpTlsGatewayClient::connect(
        "0.0.0.0:0".parse()?,
        node.gateway_quic_addr,
        "ramflux-gateway",
        &node.ca_cert,
        Duration::from_secs(10),
    )
    .await?;
    stream
        .send_frame(&serde_json::to_vec(&CustodyClientFrame::CustodyOpen {
            binding_mode: BindingMode::HomeRelayReceipt,
        })?)
        .await?;
    let opened: CustodyServerFrame = serde_json::from_slice(&stream.recv_frame().await?)?;
    assert!(matches!(opened, CustodyServerFrame::NodeIdentity { .. }));
    stream
        .send_frame(&serde_json::to_vec(&CustodyClientFrame::Challenge {
            device_ref: claimed.clone(),
            action: action.clone(),
        })?)
        .await?;
    let challenged: CustodyServerFrame = serde_json::from_slice(&stream.recv_frame().await?)?;
    let refusal = match challenged {
        CustodyServerFrame::Challenge { challenge } => {
            let nonce: [u8; 32] = ramflux_protocol::decode_base64url(&challenge.challenge_nonce)?
                .try_into()
                .map_err(|_| "S47 custody challenge nonce length")?;
            let issued = u64::try_from(realnet_now_i64())?;
            let proof = sign_branch_proof_v3(
                branch,
                BranchProofV3 {
                    schema: ramflux_protocol::domain::BRANCH_PROOF_V3.into(),
                    version: 3,
                    device_ref: claimed.clone(),
                    certificate_hash: ramflux_protocol::custody::object_hash(
                        record.body.devices[0]
                            .branch_certificate
                            .as_ref()
                            .ok_or("S47 foreign branch certificate missing")?,
                    )?,
                    record_hash: ramflux_protocol::custody::object_hash(record)?,
                    proof_id: ramflux_protocol::encode_base64url(proof_id),
                    challenge_nonce: challenge.challenge_nonce,
                    action_hash: challenge.action_hash,
                    audience: challenge.audience,
                    binding_mode: BindingMode::HomeRelayReceipt,
                    transport_binding: branch_exporter_hash(&stream.custody_exporter(&nonce)?),
                    issued_at: issued,
                    expires_at: challenge.expires_at.min(issued.saturating_add(300)),
                },
            )?;
            stream
                .send_frame(&serde_json::to_vec(&CustodyClientFrame::Prove {
                    action,
                    proof: Box::new(proof),
                })?)
                .await?;
            serde_json::from_slice(&stream.recv_frame().await?)?
        }
        response => response,
    };
    Ok(refusal)
}

fn fetch_s47_manifest(gateway_url: &str, anchor: &str) -> TestResult<Value> {
    Ok(ramflux_node_core::itest_http_get_json(&format!(
        "{gateway_url}/mvp1/device-manifest/{anchor}"
    ))?)
}

fn assert_gateway_has_no_private_material(
    alice: &NativeAccount,
    vaults: &[Arc<RecordingPrimaryVault>; 3],
) -> TestResult {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let capture = s47_service_file("ramflux-gateway", S47_GATEWAY_CAPTURE)?;
    let gateway_database =
        s47_service_file("ramflux-gateway", "/var/lib/ramflux/gateway/gateway.redb")?;
    let router_database =
        s47_service_file("ramflux-router", "/var/lib/ramflux/router/router.redb")?;
    assert!(
        contains_subslice(&capture, b"s47-after-recovery"),
        "S47 gateway capture positive control is missing the known recovery marker"
    );
    let phrase = ramflux_crypto::custody::RecoveryPhrase::parse(alice.recovery_phrase())?;
    let entropy = phrase.entropy();
    let mut master_seed = zeroize::Zeroizing::new([0_u8; 32]);
    // Mirrors ramflux_crypto::custody::MasterKey::from_phrase; cross-check its public key below.
    Hkdf::<Sha256>::new(Some(&[0_u8; 32]), &entropy)
        .expand(ramflux_protocol::domain::CUSTODY_MASTER_SEED.as_bytes(), &mut *master_seed)
        .map_err(|_| "S47 master seed derivation failed")?;
    assert_eq!(
        ed25519_dalek::SigningKey::from_bytes(&master_seed).verifying_key().to_bytes(),
        ramflux_protocol::decode_base64url(
            &ramflux_crypto::custody::MasterKey::from_phrase(&phrase)?.public_key(),
        )?
        .as_slice(),
        "itest master-seed derivation drifted from product"
    );
    let mut secrets = vec![
        zeroize::Zeroizing::new(alice.recovery_phrase().as_bytes().to_vec()),
        zeroize::Zeroizing::new(NATIVE_DATA_PASSPHRASE.as_bytes().to_vec()),
        zeroize::Zeroizing::new(NATIVE_RESTORED_PASSPHRASE.as_bytes().to_vec()),
        zeroize::Zeroizing::new(NATIVE_BACKUP_PASSPHRASE.as_bytes().to_vec()),
        zeroize::Zeroizing::new(master_seed.to_vec()),
    ];
    for vault in vaults {
        secrets.extend(vault.secret_material()?);
    }
    for (index, secret) in secrets.iter().enumerate() {
        let encoded = ramflux_protocol::encode_base64url(secret.as_slice());
        for (surface, bytes) in [
            ("gateway capture", capture.as_slice()),
            ("gateway database", gateway_database.as_slice()),
            ("router database", router_database.as_slice()),
        ] {
            assert!(
                !contains_subslice(bytes, secret),
                "gateway {surface} leaked S47 private dictionary entry {index}"
            );
            assert!(
                !String::from_utf8_lossy(bytes).contains(&encoded),
                "gateway {surface} leaked base64url S47 private dictionary entry {index}"
            );
        }
    }
    Ok(())
}

fn s47_service_file(service: &str, path: &str) -> TestResult<Vec<u8>> {
    let (mut command, _env_file) = checked_itest_compose_command("s47-read-service-file")?;
    let output = command
        .arg("-p")
        .arg(S47_COMPOSE_PROJECT)
        .arg("-f")
        .arg("docker-compose.itest.yml")
        .arg("exec")
        .arg("-T")
        .arg(service)
        .arg("cat")
        .arg(path)
        .current_dir(code_root().join("ramflux/deploy"))
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "failed to read S47 {service} file {path}: status={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(output.stdout)
}
