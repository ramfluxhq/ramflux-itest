// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use super::*;

#[cfg(feature = "realnet")]
#[test]
fn mvp_s36_realnet_tui_remote_app_approval() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    let node = start_s10_private_node_compose()?;
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async {
        wait_for_private_gateway_quic(node.gateway_quic_addr, &node.ca_cert).await?;
        Box::pin(mvp_s36_assert_tui_remote_app_approval(node.gateway_quic_addr, &node.ca_cert))
            .await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    drop(node);
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
#[allow(clippy::too_many_lines)]
async fn mvp_s36_assert_tui_remote_app_approval(
    gateway_quic_addr: std::net::SocketAddr,
    ca_cert: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let temp_root = temp_root("s36_tui_remote_app_approval")?;
    let alice_socket = temp_root.join("alice/rfd.sock");
    let (alice_shutdown_tx, alice_shutdown_rx) = tokio::sync::watch::channel(false);
    let alice_server = ramflux_sdk::serve_local_bus_until(
        ramflux_sdk::LocalBusConfig::new(&alice_socket, temp_root.join("alice/data")),
        alice_shutdown_rx,
    );

    let flow = async {
        let result = async {
            mvp_s4_wait_for_socket(&alice_socket).await?;
            let mut alice_setup_bus = ramflux_sdk::LocalBusClient::connect(&alice_socket).await?;
            mvp_s36_create_account(&mut alice_setup_bus, gateway_quic_addr, ca_cert).await?;

            let mut app = ramflux_cli_pro::TuiApp::new("alice_s4_account");
            let mut tui_bus = ramflux_cli_pro::SdkLocalBus::connect(&alice_socket).await?;
            app.refresh_all(&mut tui_bus).await?;

            let first_call = mvp_s36_create_remote_app_approval(&mut alice_setup_bus).await?;
            let approval_event =
                mvp_s36_next_tui_event(&mut tui_bus, "mcp.approval.request remote_app").await?;
            app.handle_bus_event(&approval_event)?;
            app.state.selected_panel = ramflux_cli_pro::Panel::Approvals;
            assert!(
                app.state.approvals.iter().any(|approval| {
                    approval.id == "approval_srv_s36_shell_1"
                        && approval.confirmation_mode == "remote_app"
                }),
                "TUI did not surface remote_app approval: {:?}",
                app.state.approvals,
            );
            let rendered = mvp_s36_render_tui(&app)?;
            assert!(rendered.contains("remote_app"), "missing remote_app marker: {rendered}");
            assert!(rendered.contains("remote_app:"), "missing remote_app hint: {rendered}");
            assert!(rendered.contains("App"), "missing App-signature marker: {rendered}");

            app.handle_input(&mut tui_bus, ramflux_cli_pro::TuiInput::Char('a')).await?;
            assert_eq!(
                app.state.status_message.as_deref(),
                Some("该审批需 App 端签名授权(remote_app)")
            );

            let grant = mvp_s6_submit_app_signed_grant(
                &mut alice_setup_bus,
                &first_call["approval"],
                false,
            )
            .await?;
            assert_eq!(grant["signing_body"]["approval_id"], "approval_srv_s36_shell_1");

            app.refresh_all(&mut tui_bus).await?;
            assert!(
                app.state
                    .approvals
                    .iter()
                    .all(|approval| approval.id != "approval_srv_s36_shell_1"),
                "TUI did not clear App-signed remote_app approval: {:?}",
                app.state.approvals,
            );

            drop(tui_bus);
            drop(alice_setup_bus);
            Ok::<(), Box<dyn std::error::Error>>(())
        }
        .await;
        let _ = alice_shutdown_tx.send(true);
        result
    };
    let (alice_result, flow_result) =
        Box::pin(tokio::time::timeout(Duration::from_mins(4), async {
            tokio::join!(alice_server, flow)
        }))
        .await
        .map_err(|_elapsed| "S36 TUI remote_app approval flow timed out")?;
    alice_result?;
    flow_result?;
    std::fs::remove_dir_all(&temp_root)?;
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s36_create_account(
    bus: &mut ramflux_sdk::LocalBusClient,
    gateway_quic_addr: std::net::SocketAddr,
    ca_cert: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let request = ramflux_sdk::LocalBusAccountCreateRequest {
        local_account_id: "alice_s4_account".to_owned(),
        principal_id: "principal_s4_alice".to_owned(),
        principal_commitment: String::new(),
        device_id: "alice_device_s36".to_owned(),
        target_delivery_id: "target_s36_alice".to_owned(),
        account_secret: "s36-bus-secret".to_owned(),
        root_seed: [0x3c; 32],
        device_seed: [0xA6; 32],
        client_mode: ramflux_sdk::LocalBusClientMode::AttendedCli,
        gateway: ramflux_sdk::GatewayQuicEndpointConfig {
            bind_addr: std::net::SocketAddr::from(([0, 0, 0, 0], 0)),
            gateway_addr: gateway_quic_addr,
            server_name: "localhost".to_owned(),
            ca_cert: ca_cert.to_path_buf(),
            principal_id: "principal_s4_alice".to_owned(),
            device_id: "alice_device_s36".to_owned(),
            target_delivery_id: "target_s36_alice".to_owned(),
            prekey_http_url: None,
        },
    };
    let response: ramflux_sdk::LocalBusAccountCreateResponse =
        serde_json::from_value(bus.request(None, "account", "account.create", &request).await?)?;
    assert_eq!(response.local_account_id, "alice_s4_account");
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s36_create_remote_app_approval(
    bus: &mut ramflux_sdk::LocalBusClient,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let added = bus
        .request(
            Some("alice_s4_account".to_owned()),
            "mcp",
            "mcp.server.add",
            &serde_json::json!({
                "server_id": "srv_s36",
                "command": "stdio-shell",
                "tool_name": "shell",
                "capability": "external_tool_invoke",
                "tool_scope": "shell",
                "risk_level": "high",
            }),
        )
        .await?;
    assert!(added["registry_hash"].as_str().is_some_and(|value| !value.is_empty()));
    let first_call = bus
        .request(
            Some("alice_s4_account".to_owned()),
            "mcp",
            "mcp.tool.started",
            &serde_json::json!({
                "server_id": "srv_s36",
                "tool_name": "shell",
                "arguments": {"cmd": "echo hello"},
                "operation_origin": "ai_mcp",
            }),
        )
        .await?;
    assert_eq!(first_call["status"], "approval_required");
    assert_eq!(first_call["approval"]["approval_id"], "approval_srv_s36_shell_1");
    assert_eq!(first_call["approval"]["confirmation_mode"], "remote_app");
    Ok(first_call)
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s36_next_tui_event(
    bus: &mut ramflux_cli_pro::SdkLocalBus,
    label: &str,
) -> Result<ramflux_sdk::LocalBusFrame, Box<dyn std::error::Error>> {
    Ok(tokio::time::timeout(Duration::from_secs(5), ramflux_cli_pro::TuiBus::next_event(bus))
        .await
        .map_err(|_elapsed| format!("timed out waiting for TUI event: {label}"))??)
}

#[cfg(all(test, feature = "realnet"))]
fn mvp_s36_render_tui(app: &ramflux_cli_pro::TuiApp) -> Result<String, Box<dyn std::error::Error>> {
    let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(140, 28))?;
    terminal.draw(|frame| app.render(frame))?;
    Ok(terminal.backend().buffer().content().iter().map(ratatui::buffer::Cell::symbol).collect())
}
