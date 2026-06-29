// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use crate::*;

#[cfg(all(test, feature = "realnet"))]
#[allow(clippy::too_many_lines)]
pub(crate) async fn mvp_s17_assert_a2i_a2ui_control_surface(
    gateway_quic_addr: std::net::SocketAddr,
    ca_cert: &Path,
    gateway_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    mvp_s17_assert_encrypted_self_device_control(gateway_url)?;
    Box::pin(mvp_s15_with_rf_accounts(
        "s17_a2i_a2ui_control_surface",
        gateway_quic_addr,
        ca_cert,
        gateway_url,
        |rf_binary, alice_socket, bob_socket, _bob_commitment, temp_root| async move {
            let appended = mvp_s4_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &alice_socket,
                    "a2i",
                    "append",
                    "--account",
                    "alice_s4_account",
                    "--event",
                    "a2i_evt_s17_1",
                    "--type",
                    "mcp.user_message",
                    "--source-device",
                    "alice_device_s4",
                    "--target-device",
                    "bob_device_s4",
                    "--control-domain",
                    "message",
                    "--action",
                    "context_share",
                    "--subject",
                    "s17 app-to-intelligence private directive",
                ],
            )
            .await?;
            assert_eq!(appended["event"]["event_type"], "mcp.user_message");
            assert_eq!(appended["event"]["control_domain"], "message");
            assert_eq!(appended["event"]["action"], "context_share");
            assert_eq!(appended["event"]["acknowledged"], false);
            assert_eq!(appended["submitted"]["target_delivery_id"], "target_s4_bob");
            let payload = appended["submitted"]["envelope"]["encrypted_payload"]
                .as_str()
                .ok_or("missing submitted encrypted payload")?;
            assert_node_opaque_payload(payload, b"s17 app-to-intelligence private directive");

            let pending = mvp_s4_rf_json(
                &rf_binary,
                &["--socket", &bob_socket, "a2i", "list", "--account", "bob_s4_account"],
            )
            .await?;
            assert_eq!(pending["events"].as_array().map_or(0, Vec::len), 1);
            assert_eq!(pending["events"][0]["event_type"], "mcp.user_message");
            assert_eq!(pending["events"][0]["source_device_id"], "alice_device_s4");
            assert_eq!(pending["events"][0]["target_device_id"], "bob_device_s4");
            let subject =
                pending["events"][0]["subject_base64"].as_str().ok_or("missing pending subject")?;
            assert_eq!(
                ramflux_protocol::decode_base64url(subject)?,
                b"s17 app-to-intelligence private directive"
            );
            let acked = mvp_s4_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &bob_socket,
                    "a2i",
                    "ack",
                    "--account",
                    "bob_s4_account",
                    "--event",
                    "a2i_evt_s17_1",
                ],
            )
            .await?;
            assert_eq!(acked["acknowledged"], true);

            let surface = mvp_s17_a2ui_surface();
            let surface_path = temp_root.join("s17-a2ui-surface.json");
            std::fs::write(&surface_path, serde_json::to_vec_pretty(&surface)?)?;
            let surface_arg = mvp_s4_path_arg(&surface_path);
            let rendered = mvp_s4_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &alice_socket,
                    "a2ui",
                    "render",
                    "--account",
                    "alice_s4_account",
                    "--surface",
                    &surface_arg,
                    "--permission",
                    "mcp.approve",
                ],
            )
            .await?;
            assert_eq!(rendered["fallback_used"], false);
            assert!(
                rendered["semantic_snapshot"]
                    .as_str()
                    .is_some_and(|snapshot| snapshot.contains("approval_card"))
            );
            let surface_hash = rendered["surface_hash"].as_str().ok_or("missing surface hash")?;
            assert_eq!(surface_hash, ramflux_sync::a2ui_surface_hash(&surface)?);

            let action = ramflux_sync::A2uiAction {
                surface_id: "surface_s17_approval".to_owned(),
                surface_hash: surface_hash.to_owned(),
                component_id: "approve_s17".to_owned(),
                permission: "mcp.approve".to_owned(),
                source_device_id: "alice_device_s4".to_owned(),
                target_device_id: "cli_ai_device_s17".to_owned(),
                created_at: itest_now_unix_seconds(),
                nonce: "nonce_s17_a2ui_action".to_owned(),
                signature: String::new(),
            };
            let action_path = temp_root.join("s17-a2ui-action.json");
            let wrong_source_action_path = temp_root.join("s17-a2ui-action-wrong-source.json");
            std::fs::write(&action_path, serde_json::to_vec_pretty(&action)?)?;
            let action_arg = mvp_s4_path_arg(&action_path);
            let wrong_source_action = ramflux_sync::A2uiAction {
                source_device_id: "mallory_device_s17".to_owned(),
                nonce: "nonce_s17_a2ui_wrong_source".to_owned(),
                ..action.clone()
            };
            std::fs::write(
                &wrong_source_action_path,
                serde_json::to_vec_pretty(&wrong_source_action)?,
            )?;
            let wrong_source_action_arg = mvp_s4_path_arg(&wrong_source_action_path);
            let wrong_source_rejected = mvp_s4_rf_failure(
                &rf_binary,
                &[
                    "--socket",
                    &alice_socket,
                    "a2ui",
                    "action",
                    "--account",
                    "alice_s4_account",
                    "--surface",
                    &surface_arg,
                    "--action",
                    &wrong_source_action_arg,
                ],
            )
            .await?;
            assert!(
                wrong_source_rejected.contains("source device mismatch"),
                "wrong-source S17 A2UI action should be rejected, stderr={wrong_source_rejected}"
            );
            let accepted = mvp_s4_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &alice_socket,
                    "a2ui",
                    "action",
                    "--account",
                    "alice_s4_account",
                    "--surface",
                    &surface_arg,
                    "--action",
                    &action_arg,
                ],
            )
            .await?;
            assert_eq!(accepted["accepted"], true);
            assert_eq!(accepted["permission"], "mcp.approve");
            assert_eq!(accepted["event"]["event_type"], "ramflux.a2ui.action_submitted");
            assert_eq!(accepted["result"]["event_type"], "ramflux.a2ui.action_result");
            assert!(
                accepted["action"]["signature"]
                    .as_str()
                    .is_some_and(|signature| !signature.is_empty())
            );
            Ok(())
        },
    ))
    .await
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp_s17_assert_encrypted_self_device_control(
    gateway_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = mvp3_mcp_a2ui_fixture()?;
    register_mvp1_identity(gateway_url, &fixture.app_register)?;
    register_mvp1_identity(gateway_url, &fixture.cli_register)?;
    publish_mvp1_prekey(gateway_url, "alice_app_device_mvp3_realnet", &fixture.app_prekey_bundle)?;
    publish_mvp1_prekey(gateway_url, "cli_headless_ai_mvp3_realnet", &fixture.cli_prekey_bundle)?;
    let (mut app_to_cli, mut cli_receiver) =
        establish_mvp3_pairwise_sessions(Mvp3PairwiseSessionInput {
            initiator_identity: &fixture.app_identity,
            initiator_ephemeral_seed: [0xd1; 32],
            recipient_bundle: &fixture.cli_prekey_bundle,
            recipient_identity: &fixture.cli_identity,
            recipient_signed_prekey: &fixture.cli_signed_prekey,
            associated_data: b"alice_app|cli_headless_ai",
            session_label: "s17-realnet-a2i-control",
        })?;
    let event = ramflux_sync::A2iControlEvent {
        event_id: "a2i_evt_s17_encrypted".to_owned(),
        event_type: "mcp.user_message".to_owned(),
        source_device_id: "alice_app_device_mvp3_realnet".to_owned(),
        target_device_id: "cli_headless_ai_mvp3_realnet".to_owned(),
        control_domain: "message".to_owned(),
        action: "context_share".to_owned(),
        subject_base64: ramflux_protocol::encode_base64url(
            b"s17 encrypted self-device control subject",
        ),
        created_at: 1_760_000_710,
        acknowledged: false,
    };
    let delivered = deliver_mvp3_control_event(Mvp3ControlDelivery {
        gateway_url,
        envelope_id: "env_s17_a2i_control",
        target_delivery_id: "cli_headless_ai_target_mvp3_realnet",
        sender_session: &mut app_to_cli,
        receiver_session: &mut cli_receiver,
        associated_data: b"alice_app|cli_headless_ai",
        event: &event,
        forbidden_node_visible: b"s17 encrypted self-device control subject",
    })?;
    assert_eq!(delivered, event);
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
#[allow(clippy::too_many_lines)]
pub(crate) async fn mvp_s18_assert_a2i_encrypted_self_device_delivery(
    gateway_quic_addr: std::net::SocketAddr,
    ca_cert: &Path,
    gateway_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    mvp_s18_assert_encrypted_self_device_control_ad_binding(gateway_url)?;
    Box::pin(mvp_s15_with_rf_accounts(
        "s18_a2i_encrypted_self_device_delivery",
        gateway_quic_addr,
        ca_cert,
        gateway_url,
        |rf_binary, alice_socket, bob_socket, _bob_commitment, _temp_root| async move {
            let appended = mvp_s4_rf_json(
                &rf_binary,
                &[
                    "--socket",
                    &alice_socket,
                    "a2i",
                    "append",
                    "--account",
                    "alice_s4_account",
                    "--event",
                    "a2i_evt_s18_quic",
                    "--type",
                    "mcp.user_message",
                    "--source-device",
                    "alice_device_s4",
                    "--target-device",
                    "bob_device_s4",
                    "--control-domain",
                    "message",
                    "--action",
                    "context_share",
                    "--subject",
                    "s18 encrypted a2i over quic",
                ],
            )
            .await?;
            assert_eq!(appended["event"]["event_id"], "a2i_evt_s18_quic");
            assert_eq!(appended["submitted"]["target_delivery_id"], "target_s4_bob");
            let payload = appended["submitted"]["envelope"]["encrypted_payload"]
                .as_str()
                .ok_or("missing S18 submitted encrypted payload")?;
            assert_node_opaque_payload(payload, b"s18 encrypted a2i over quic");

            let pending = mvp_s4_rf_json(
                &rf_binary,
                &["--socket", &bob_socket, "a2i", "list", "--account", "bob_s4_account"],
            )
            .await?;
            let event = pending["events"]
                .as_array()
                .ok_or("missing S18 pending A2I events")?
                .iter()
                .find(|event| event["event_id"] == "a2i_evt_s18_quic")
                .ok_or("missing S18 QUIC A2I event")?;
            let subject = event["subject_base64"].as_str().ok_or("missing S18 pending subject")?;
            assert_eq!(
                ramflux_protocol::decode_base64url(subject)?,
                b"s18 encrypted a2i over quic"
            );
            Ok(())
        },
    ))
    .await
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp_s18_assert_encrypted_self_device_control_ad_binding(
    gateway_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = mvp3_mcp_a2ui_fixture()?;
    register_mvp1_identity(gateway_url, &fixture.app_register)?;
    register_mvp1_identity(gateway_url, &fixture.cli_register)?;
    publish_mvp1_prekey(gateway_url, "alice_app_device_mvp3_realnet", &fixture.app_prekey_bundle)?;
    publish_mvp1_prekey(gateway_url, "cli_headless_ai_mvp3_realnet", &fixture.cli_prekey_bundle)?;
    let (mut app_to_cli, mut cli_receiver) =
        establish_mvp3_pairwise_sessions(Mvp3PairwiseSessionInput {
            initiator_identity: &fixture.app_identity,
            initiator_ephemeral_seed: [0xe1; 32],
            recipient_bundle: &fixture.cli_prekey_bundle,
            recipient_identity: &fixture.cli_identity,
            recipient_signed_prekey: &fixture.cli_signed_prekey,
            associated_data: b"alice_app|cli_headless_ai",
            session_label: "s18-realnet-a2i-control",
        })?;
    let event = ramflux_sync::A2iControlEvent {
        event_id: "a2i_evt_s18_encrypted".to_owned(),
        event_type: "mcp.user_message".to_owned(),
        source_device_id: "alice_app_device_mvp3_realnet".to_owned(),
        target_device_id: "cli_headless_ai_mvp3_realnet".to_owned(),
        control_domain: "message".to_owned(),
        action: "context_share".to_owned(),
        subject_base64: ramflux_protocol::encode_base64url(
            b"s18 encrypted self-device control subject",
        ),
        created_at: 1_760_000_810,
        acknowledged: false,
    };
    let event_json = serde_json::to_vec(&event)?;
    let ciphertext = app_to_cli.encrypt(&event_json, b"alice_app|cli_headless_ai")?;
    let delivered = deliver_mvp1_dm(
        gateway_url,
        "env_s18_a2i_control",
        "cli_headless_ai_target_mvp3_realnet",
        &ciphertext,
    )?;
    assert_node_opaque_payload(
        &delivered.envelope.encrypted_payload,
        b"s18 encrypted self-device control subject",
    );
    let delivered_ciphertext: ramflux_crypto::DmCiphertext =
        serde_json::from_str(&delivered.envelope.encrypted_payload)?;
    let mut wrong_ad_receiver = cli_receiver.clone();
    assert!(
        wrong_ad_receiver.decrypt(&delivered_ciphertext, b"cli_headless_ai|alice_app").is_err(),
        "S18 self-device A2I control must reject wrong associated data"
    );
    let decrypted = cli_receiver.decrypt(&delivered_ciphertext, b"alice_app|cli_headless_ai")?;
    let delivered_event: ramflux_sync::A2iControlEvent = serde_json::from_slice(&decrypted)?;
    assert_eq!(delivered_event, event);
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp_s17_a2ui_surface() -> ramflux_sync::A2uiSurface {
    ramflux_sync::A2uiSurface {
        surface_id: "surface_s17_approval".to_owned(),
        catalog: "ramflux.basic.v1".to_owned(),
        catalog_version: "1".to_owned(),
        components: vec![ramflux_sync::A2uiComponent {
            id: "approve_s17".to_owned(),
            component_type: "approval_card".to_owned(),
            action_permission: Some("mcp.approve".to_owned()),
            children: Vec::new(),
        }],
    }
}
