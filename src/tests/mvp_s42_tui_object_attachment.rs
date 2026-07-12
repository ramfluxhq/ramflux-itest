// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
// Fixtures below are consumed only by the realnet-gated test in this module; keep them
// available in all test builds but silence dead_code when the realnet tests are compiled out.
#![cfg_attr(not(feature = "realnet"), allow(dead_code))]
use super::*;

const S42_CONVERSATION_ID: &str = "conv_s42_tui_attachment";
const S42_BODY: &str = "s42 tui attachment body";
const S42_OBJECT_ID: &str = "object_s42_tui_attachment";
const S42_ATTACHMENT: &[u8] = b"mvp_s42_tui_attachment_plaintext_bytes";

#[cfg(feature = "realnet")]
#[test]
fn mvp_s42_realnet_tui_object_attachment_panel() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    let ports = S8ComposePorts {
        gateway_http: 64_201,
        gateway_quic: 64_471,
        router_http: 64_200,
        router_mesh: 64_472,
        notify_http: 64_203,
        federation_http: 64_202,
        federation_mesh: 64_473,
        relay_http: 64_204,
        relay_media_udp: 64_120,
        signaling_turn_udp: 64_498,
        signaling_turn_tcp: 64_499,
        retention_http: 64_207,
    };
    let relay_capture = "/tmp/ramflux-relay-itest-capture-s42.jsonl";
    let node = start_s8_realnet_compose_project_with_env(
        "ramflux-s42-tui-object-attachment",
        ports,
        &[("RAMFLUX_RELAY_ITEST_CAPTURE_JSON".to_owned(), relay_capture.to_owned())],
    )?;
    let relay_url = format!("http://127.0.0.1:{}", ports.relay_http);
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async {
        wait_for_private_gateway_quic(node.gateway_quic_addr, &node.ca_cert).await?;
        Box::pin(mvp_s42_assert_tui_object_attachment(&node, &relay_url)).await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    drop(node);
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
#[allow(clippy::too_many_lines)]
async fn mvp_s42_assert_tui_object_attachment(
    node: &S8RealnetNode,
    relay_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let temp_root = temp_root("s42_tui_object_attachment")?;
    let alice_socket = temp_root.join("alice/rfd.sock");
    let bob_socket = temp_root.join("bob/rfd.sock");
    let alice_data = temp_root.join("alice/data");
    let bob_data = temp_root.join("bob/data");
    let rf_binary = mvp_s4_build_rf_binary().await?;
    let gateway_addr = node.gateway_quic_addr.to_string();
    let ca_cert_arg = mvp_s4_path_arg(&node.ca_cert);
    let alice_socket_arg = mvp_s4_path_arg(&alice_socket);
    let bob_socket_arg = mvp_s4_path_arg(&bob_socket);
    let service_key = "ramflux-relay-itest-service-key";

    let (alice_tx, alice_rx) = tokio::sync::watch::channel(false);
    let (bob_tx, bob_rx) = tokio::sync::watch::channel(false);
    let alice_server = ramflux_sdk::serve_local_bus_until(
        ramflux_sdk::LocalBusConfig::new(&alice_socket, &alice_data),
        alice_rx,
    );
    let bob_server = ramflux_sdk::serve_local_bus_until(
        ramflux_sdk::LocalBusConfig::new(&bob_socket, &bob_data),
        bob_rx,
    );

    let flow = async {
        let result = async {
            mvp_s4_wait_for_socket(&alice_socket).await?;
            mvp_s4_wait_for_socket(&bob_socket).await?;
            let alice_commitment = mvp_s10_create_rf_account(
                &rf_binary,
                &alice_socket_arg,
                "alice_s42_account",
                "principal_s42_alice",
                "alice_device_s42",
                "target_s42_alice",
                &gateway_addr,
                &ca_cert_arg,
                "52",
                "53",
            )
            .await?;
            let bob_commitment = mvp_s10_create_rf_account(
                &rf_binary,
                &bob_socket_arg,
                "bob_s42_account",
                "principal_s42_bob",
                "bob_device_s42",
                "target_s42_bob",
                &gateway_addr,
                &ca_cert_arg,
                "54",
                "55",
            )
            .await?;
            mvp_s42_add_contact(
                &rf_binary,
                &alice_socket_arg,
                "alice_s42_account",
                "alice_to_bob_s42",
                &alice_commitment,
                &bob_commitment,
            )
            .await?;
            mvp_s42_add_contact(
                &rf_binary,
                &bob_socket_arg,
                "bob_s42_account",
                "bob_to_alice_s42",
                &bob_commitment,
                &alice_commitment,
            )
            .await?;

            let mut alice_tui = ramflux_cli_pro::TuiApp::new("alice_s42_account");
            alice_tui.set_local_device_id("alice_device_s42");
            let mut alice_bus = ramflux_cli_pro::SdkLocalBus::connect(&alice_socket).await?;
            alice_tui
                .refresh_all(&mut alice_bus)
                .await
                .map_err(s42_context("alice refresh_all"))?;
            assert!(!alice_tui.state.conversations.is_empty());
            alice_tui.state.conversations[0].id = S42_CONVERSATION_ID.to_owned();
            alice_tui.state.conversations[0].title = "Bob S42".to_owned();
            alice_tui.state.conversations[0].recipient_device_id =
                Some("bob_device_s42".to_owned());
            alice_tui.state.conversations[0].target_delivery_id = Some("target_s42_bob".to_owned());
            alice_tui.queue_attachment_bytes_for_relay(
                S42_OBJECT_ID,
                S42_ATTACHMENT,
                relay_url,
                Some(service_key.to_owned()),
            );
            alice_tui.state.selected_panel = ramflux_cli_pro::Panel::Messages;
            alice_tui
                .handle_input(&mut alice_bus, ramflux_cli_pro::TuiInput::EnterCompose)
                .await
                .map_err(s42_context("alice enter compose"))?;
            for value in S42_BODY.chars() {
                alice_tui
                    .handle_input(&mut alice_bus, ramflux_cli_pro::TuiInput::Char(value))
                    .await
                    .map_err(s42_context("alice type body"))?;
            }
            alice_tui
                .handle_input(&mut alice_bus, ramflux_cli_pro::TuiInput::Enter)
                .await
                .map_err(s42_context("alice submit attachment dm"))?;
            assert!(
                alice_tui.state.messages.iter().any(|message| {
                    message.body == S42_BODY
                        && message.attachments.iter().any(|item| item.object_id == S42_OBJECT_ID)
                }),
                "Alice TUI did not render queued attachment after send",
            );

            let mut bob_tui = ramflux_cli_pro::TuiApp::new("bob_s42_account");
            bob_tui.set_local_device_id("bob_device_s42");
            let mut bob_bus = ramflux_cli_pro::SdkLocalBus::connect(&bob_socket).await?;
            bob_tui.state.conversations.push(ramflux_cli_pro::ConversationRow {
                id: S42_CONVERSATION_ID.to_owned(),
                title: "Alice S42".to_owned(),
                last_message: String::new(),
                unread: 0,
                status: "synced".to_owned(),
                recipient_device_id: Some("alice_device_s42".to_owned()),
                target_delivery_id: Some("target_s42_alice".to_owned()),
            });
            bob_tui
                .receive_messages_with_attachment_relay_key(
                    &mut bob_bus,
                    Some(service_key.to_owned()),
                )
                .await
                .map_err(s42_context("bob receive attachment"))?;
            let received = bob_tui
                .state
                .messages
                .iter()
                .find(|message| {
                    message.body == S42_BODY
                        && message.attachments.iter().any(|item| item.object_id == S42_OBJECT_ID)
                })
                .ok_or("Bob TUI did not render decrypted attachment row")?;
            let attachment = received
                .attachments
                .iter()
                .find(|item| item.object_id == S42_OBJECT_ID)
                .ok_or("missing S42 attachment row")?;
            assert_eq!(attachment.status, "decrypted");
            let plaintext = ramflux_protocol::decode_base64url(
                attachment.plaintext_base64.as_deref().ok_or("missing attachment plaintext")?,
            )?;
            assert_eq!(plaintext, S42_ATTACHMENT);

            alice_tui
                .refresh_object_status(&mut alice_bus, S42_OBJECT_ID, Some("upload"))
                .await
                .map_err(s42_context("alice object status"))?;
            alice_tui.state.selected_panel = ramflux_cli_pro::Panel::Objects;
            let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(120, 28))?;
            terminal.draw(|frame| alice_tui.render(frame))?;
            let buffer = terminal
                .backend()
                .buffer()
                .content()
                .iter()
                .map(ratatui::buffer::Cell::symbol)
                .collect::<String>();
            assert!(buffer.contains(S42_OBJECT_ID), "object panel missing object id: {buffer}");
            assert!(buffer.contains("complete"), "object panel missing complete state: {buffer}");
            assert!(buffer.contains("100%"), "object panel missing transfer percent: {buffer}");

            drop(alice_bus);
            drop(bob_bus);
            Ok::<(), Box<dyn std::error::Error>>(())
        }
        .await;
        let _ = alice_tx.send(true);
        let _ = bob_tx.send(true);
        result
    };
    let (alice_result, bob_result, flow_result) =
        Box::pin(tokio::time::timeout(Duration::from_mins(5), async {
            tokio::join!(alice_server, bob_server, flow)
        }))
        .await
        .map_err(|_elapsed| "S42 TUI object attachment flow timed out")?;
    alice_result?;
    bob_result?;
    flow_result?;
    std::fs::remove_dir_all(&temp_root)?;
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s42_add_contact(
    rf_binary: &Path,
    socket: &str,
    account: &str,
    link: &str,
    requester: &str,
    target: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let added = mvp_s4_rf_json(
        rf_binary,
        &[
            "--socket",
            socket,
            "contact",
            "add",
            "--account",
            account,
            "--link",
            link,
            "--requester",
            requester,
            "--target",
            target,
        ],
    )
    .await?;
    assert_eq!(added["state"], "accepted");
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
fn s42_context(label: &'static str) -> impl FnOnce(ramflux_cli_pro::TuiError) -> std::io::Error {
    move |error| std::io::Error::other(format!("{label}: {error}"))
}
