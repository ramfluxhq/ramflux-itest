// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use super::*;

#[cfg(feature = "realnet")]
#[test]
fn mvp_s49_realnet_tui_account_switch_and_contact_add() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    let node = start_s10_private_node_compose()?;
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async {
        wait_for_private_gateway_quic(node.gateway_quic_addr, &node.ca_cert).await?;
        Box::pin(mvp_s49_assert_tui_account_switch_and_contact_add(
            node.gateway_quic_addr,
            &node.ca_cert,
        ))
        .await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    drop(node);
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
#[allow(clippy::too_many_lines)]
async fn mvp_s49_assert_tui_account_switch_and_contact_add(
    gateway_quic_addr: std::net::SocketAddr,
    ca_cert: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let temp_root = temp_root("s49_tui_account_contact")?;
    let rf_binary = mvp_s4_build_rf_binary().await?;
    let alice_socket = temp_root.join("alice/rfd.sock");
    let bob_socket = temp_root.join("bob/rfd.sock");
    let alice_data = temp_root.join("alice/data");
    let bob_data = temp_root.join("bob/data");
    let gateway_addr = gateway_quic_addr.to_string();
    let ca_cert_arg = mvp_s4_path_arg(ca_cert);
    let alice_socket_arg = mvp_s4_path_arg(&alice_socket);
    let bob_socket_arg = mvp_s4_path_arg(&bob_socket);
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
                "alice_s49_account",
                "principal_s49_alice",
                "alice_device_s49",
                "target_s49_alice",
                &gateway_addr,
                &ca_cert_arg,
                "91",
                "92",
            )
            .await?;
            let carol_commitment = mvp_s10_create_rf_account(
                &rf_binary,
                &alice_socket_arg,
                "carol_s49_account",
                "principal_s49_carol",
                "carol_device_s49",
                "target_s49_carol",
                &gateway_addr,
                &ca_cert_arg,
                "93",
                "94",
            )
            .await?;
            let bob_commitment = mvp_s10_create_rf_account(
                &rf_binary,
                &bob_socket_arg,
                "bob_s49_account",
                "principal_s49_bob",
                "bob_device_s49",
                "target_s49_bob",
                &gateway_addr,
                &ca_cert_arg,
                "95",
                "96",
            )
            .await?;
            assert_ne!(alice_commitment, carol_commitment);
            assert_ne!(carol_commitment, bob_commitment);

            let mut app = ramflux_cli_pro::TuiApp::new("alice_s49_account");
            let mut tui_bus = ramflux_cli_pro::SdkLocalBus::connect(&alice_socket).await?;
            app.refresh_all(&mut tui_bus).await?;
            app.state.selected_panel = ramflux_cli_pro::Panel::Contacts;

            mvp_s49_type_and_submit(&mut app, &mut tui_bus, "switch carol_s49_account").await?;
            assert_eq!(app.state.account_id, "carol_s49_account");

            let add_command =
                format!("add friend_link_s49_carol_bob {carol_commitment} {bob_commitment}");
            mvp_s49_type_and_submit(&mut app, &mut tui_bus, &add_command).await?;
            assert!(
                app.state.contacts.iter().any(|contact| {
                    contact.link_id == "friend_link_s49_carol_bob"
                        && contact.requester == carol_commitment
                        && contact.target == bob_commitment
                        && contact.state == "accepted"
                }),
                "TUI contact.add did not render the accepted real-commitment link: {:?}",
                app.state.contacts
            );

            let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(140, 24))?;
            terminal.draw(|frame| app.render(frame))?;
            let buffer = terminal
                .backend()
                .buffer()
                .content()
                .iter()
                .map(ratatui::buffer::Cell::symbol)
                .collect::<String>();
            assert!(
                buffer.contains("friend_link_s49_carol_bob"),
                "contacts panel did not render added link: {buffer}"
            );
            assert!(
                buffer.contains("add/switch/accept"),
                "contacts panel did not expose add/switch command hint: {buffer}"
            );

            let account_list = ramflux_sdk::LocalBusClient::connect(&alice_socket)
                .await?
                .request(None, "account", "account.list", &serde_json::json!({}))
                .await?;
            assert_eq!(
                account_list["active_account_id"].as_str(),
                Some("carol_s49_account"),
                "TUI account.switch did not update daemon active account: {account_list}",
            );

            drop(tui_bus);
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
        .map_err(|_elapsed| "S49 TUI account/contact flow timed out")?;
    alice_result?;
    bob_result?;
    flow_result?;
    std::fs::remove_dir_all(&temp_root)?;
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s49_type_and_submit(
    app: &mut ramflux_cli_pro::TuiApp,
    bus: &mut ramflux_cli_pro::SdkLocalBus,
    command: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    app.handle_input(bus, ramflux_cli_pro::TuiInput::EnterCompose).await?;
    for value in command.chars() {
        app.handle_input(bus, ramflux_cli_pro::TuiInput::Char(value)).await?;
    }
    app.handle_input(bus, ramflux_cli_pro::TuiInput::Enter).await?;
    Ok(())
}
