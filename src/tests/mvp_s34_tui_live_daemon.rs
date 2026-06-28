// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use super::*;

#[cfg(feature = "realnet")]
#[test]
fn mvp_s34_realnet_tui_live_daemon() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    let node = start_s10_private_node_compose()?;
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async {
        wait_for_private_gateway_quic(node.gateway_quic_addr, &node.ca_cert).await?;
        Box::pin(mvp_s34_assert_tui_live_daemon(node.gateway_quic_addr, &node.ca_cert)).await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    drop(node);
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
#[allow(clippy::too_many_lines)]
async fn mvp_s34_assert_tui_live_daemon(
    gateway_quic_addr: std::net::SocketAddr,
    ca_cert: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let temp_root = temp_root("s34_tui_live_daemon")?;
    let alice_socket = temp_root.join("alice/rfd.sock");
    let bob_socket = temp_root.join("bob/rfd.sock");
    let (alice_shutdown_tx, alice_shutdown_rx) = tokio::sync::watch::channel(false);
    let (bob_shutdown_tx, bob_shutdown_rx) = tokio::sync::watch::channel(false);
    let alice_server = ramflux_sdk::serve_local_bus_until(
        ramflux_sdk::LocalBusConfig::new(&alice_socket, temp_root.join("alice/data")),
        alice_shutdown_rx,
    );
    let bob_server = ramflux_sdk::serve_local_bus_until(
        ramflux_sdk::LocalBusConfig::new(&bob_socket, temp_root.join("bob/data")),
        bob_shutdown_rx,
    );

    let flow = async {
        let result = async {
            mvp_s4_wait_for_socket(&alice_socket).await?;
            mvp_s4_wait_for_socket(&bob_socket).await?;
            let mut alice_setup_bus = ramflux_sdk::LocalBusClient::connect(&alice_socket).await?;
            let mut bob_bus = ramflux_sdk::LocalBusClient::connect(&bob_socket).await?;
            let alice_commitment = mvp_s34_create_account(
                &mut alice_setup_bus,
                gateway_quic_addr,
                ca_cert,
                MvpS34AccountSpec {
                    local_account_id: "alice_s34_account",
                    principal_id: "principal_s34_alice",
                    device_id: "alice_device_s34",
                    target_delivery_id: "target_s34_alice",
                    root_seed: [0x34; 32],
                    device_seed: [0x35; 32],
                },
            )
            .await?;
            let bob_commitment = mvp_s34_create_account(
                &mut bob_bus,
                gateway_quic_addr,
                ca_cert,
                MvpS34AccountSpec {
                    local_account_id: "bob_s34_account",
                    principal_id: "principal_s34_bob",
                    device_id: "bob_device_s34",
                    target_delivery_id: "target_s34_bob",
                    root_seed: [0x36; 32],
                    device_seed: [0x37; 32],
                },
            )
            .await?;
            mvp_s34_seed_tui_projections(
                &mut alice_setup_bus,
                &mut bob_bus,
                &alice_commitment,
                &bob_commitment,
            )
            .await?;

            let mut app = ramflux_cli_pro::TuiApp::new("alice_s34_account");
            let mut tui_bus = ramflux_cli_pro::SdkLocalBus::connect(&alice_socket).await?;
            app.refresh_all(&mut tui_bus).await?;
            assert!(
                !app.state.conversations.is_empty(),
                "TUI refresh must load/default conversations",
            );
            assert_eq!(app.state.contacts.len(), 1);
            assert_eq!(app.state.groups.len(), 1);
            app.state.conversations[0].id = "conv_s34_tui_dm".to_owned();
            app.state.conversations[0].title = "Bob S34".to_owned();
            app.state.conversations[0].recipient_device_id = Some("bob_device_s34".to_owned());
            app.state.conversations[0].target_delivery_id = Some("target_s34_bob".to_owned());

            app.state.selected_panel = ramflux_cli_pro::Panel::Messages;
            for value in "s34 tui demo send".chars() {
                app.handle_input(&mut tui_bus, ramflux_cli_pro::TuiInput::Char(value)).await?;
            }
            app.handle_input(&mut tui_bus, ramflux_cli_pro::TuiInput::Enter).await?;
            assert!(app.state.messages.iter().any(|message| message.body == "s34 tui demo send"));
            let bob_received = bob_bus
                .request(
                    Some("bob_s34_account".to_owned()),
                    "message",
                    "message.receive",
                    &ramflux_sdk::LocalBusMessageReceiveRequest {
                        limit: 10,
                        conversation_id: None,
                        auto_fetch_attachments: false,
                        relay_service_key_base64: None,
                    },
                )
                .await?;
            assert!(
                bob_received["entries"].as_array().is_some_and(|entries| entries.iter().any(
                    |entry| entry
                        .pointer("/envelope/envelope_id")
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|envelope_id| envelope_id.starts_with("tui_env_"))
                )),
                "Bob did not receive TUI-submitted S34 DM: {bob_received}",
            );

            mvp_s34_send_bob_to_alice(&mut bob_bus).await?;
            let receive = ramflux_sdk::LocalBusMessageReceiveRequest {
                limit: 10,
                conversation_id: None,
                auto_fetch_attachments: false,
                relay_service_key_base64: None,
            };
            let alice_received = alice_setup_bus
                .request(
                    Some("alice_s34_account".to_owned()),
                    "message",
                    "message.receive",
                    &receive,
                )
                .await?;
            assert!(
                alice_received["entries"].as_array().is_some_and(|entries| entries.iter().any(
                    |entry| entry
                        .pointer("/envelope/envelope_id")
                        .and_then(serde_json::Value::as_str)
                        == Some("env_s34_bob_to_alice")
                )),
                "Alice daemon did not receive Bob's S34 delivery: {alice_received}",
            );
            let delivery_event =
                mvp_s34_next_tui_event(&mut tui_bus, "gateway.deliver after Bob message").await?;
            app.handle_bus_event(&delivery_event)?;
            assert!(
                app.state.messages.iter().any(|message| message.id == "env_s34_bob_to_alice"),
                "TUI did not append gateway.deliver event to message view",
            );

            mvp_s34_create_mcp_approval(&mut alice_setup_bus).await?;
            let approval_event =
                mvp_s34_next_tui_event(&mut tui_bus, "mcp.approval.request").await?;
            app.handle_bus_event(&approval_event)?;
            assert!(
                app.state.approvals.iter().any(|approval| approval.id == "approval_srv_s34_echo_1"),
                "TUI did not append MCP approval event",
            );
            app.state.selected_panel = ramflux_cli_pro::Panel::Approvals;
            app.handle_input(&mut tui_bus, ramflux_cli_pro::TuiInput::Char('a')).await?;
            assert!(
                app.state.approvals.is_empty(),
                "TUI approve action should refresh approvals and clear the approved request",
            );

            drop(tui_bus);
            drop(alice_setup_bus);
            drop(bob_bus);
            Ok::<(), Box<dyn std::error::Error>>(())
        }
        .await;
        let _ = alice_shutdown_tx.send(true);
        let _ = bob_shutdown_tx.send(true);
        result
    };
    let (alice_result, bob_result, flow_result) =
        Box::pin(tokio::time::timeout(Duration::from_mins(4), async {
            tokio::join!(alice_server, bob_server, flow)
        }))
        .await
        .map_err(|_elapsed| "S34 TUI live daemon flow timed out")?;
    alice_result?;
    bob_result?;
    flow_result?;
    std::fs::remove_dir_all(&temp_root)?;
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
struct MvpS34AccountSpec<'a> {
    local_account_id: &'a str,
    principal_id: &'a str,
    device_id: &'a str,
    target_delivery_id: &'a str,
    root_seed: [u8; 32],
    device_seed: [u8; 32],
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s34_create_account(
    bus: &mut ramflux_sdk::LocalBusClient,
    gateway_quic_addr: std::net::SocketAddr,
    ca_cert: &Path,
    spec: MvpS34AccountSpec<'_>,
) -> Result<String, Box<dyn std::error::Error>> {
    let request = ramflux_sdk::LocalBusAccountCreateRequest {
        local_account_id: spec.local_account_id.to_owned(),
        principal_id: spec.principal_id.to_owned(),
        principal_commitment: String::new(),
        device_id: spec.device_id.to_owned(),
        target_delivery_id: spec.target_delivery_id.to_owned(),
        account_secret: "s34-bus-secret".to_owned(),
        root_seed: spec.root_seed,
        device_seed: spec.device_seed,
        client_mode: ramflux_sdk::LocalBusClientMode::AttendedCli,
        gateway: ramflux_sdk::GatewayQuicEndpointConfig {
            bind_addr: std::net::SocketAddr::from(([0, 0, 0, 0], 0)),
            gateway_addr: gateway_quic_addr,
            server_name: "localhost".to_owned(),
            ca_cert: ca_cert.to_path_buf(),
            principal_id: spec.principal_id.to_owned(),
            device_id: spec.device_id.to_owned(),
            target_delivery_id: spec.target_delivery_id.to_owned(),
            prekey_http_url: None,
        },
    };
    let response: ramflux_sdk::LocalBusAccountCreateResponse =
        serde_json::from_value(bus.request(None, "account", "account.create", &request).await?)?;
    assert_eq!(response.local_account_id, spec.local_account_id);
    // QUIC-first with mandatory TCP fallback: either established transport is valid.
    let transport = response.active_transport_kind.as_str();
    assert!(
        transport.starts_with("quic") || transport.starts_with("tcp"),
        "expected established quic*/tcp* transport, got {transport:?}"
    );
    Ok(response.principal_commitment)
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s34_seed_tui_projections(
    alice_bus: &mut ramflux_sdk::LocalBusClient,
    bob_bus: &mut ramflux_sdk::LocalBusClient,
    alice_commitment: &str,
    bob_commitment: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let alice_contact = ramflux_sdk::LocalBusContactAddRequest {
        link_id: "friend_link_s34_alice_bob".to_owned(),
        requester_id: alice_commitment.to_owned(),
        target_id: bob_commitment.to_owned(),
    };
    let added = alice_bus
        .request(Some("alice_s34_account".to_owned()), "contact", "contact.add", &alice_contact)
        .await?;
    assert_eq!(added["state"], "accepted");

    let bob_contact = ramflux_sdk::LocalBusContactAddRequest {
        link_id: "friend_link_s34_bob_alice".to_owned(),
        requester_id: bob_commitment.to_owned(),
        target_id: alice_commitment.to_owned(),
    };
    let added = bob_bus
        .request(Some("bob_s34_account".to_owned()), "contact", "contact.add", &bob_contact)
        .await?;
    assert_eq!(added["state"], "accepted");

    let group = ramflux_sdk::LocalBusGroupCreateRequest {
        group_id: "group_s34".to_owned(),
        creator_id: "alice_device_s34".to_owned(),
        creator_signing_public_key: None,
        creator_target_delivery_id: None,
    };
    let created = alice_bus
        .request(Some("alice_s34_account".to_owned()), "group", "group.create", &group)
        .await?;
    assert_eq!(created["group_id"], "group_s34");
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s34_send_bob_to_alice(
    bob_bus: &mut ramflux_sdk::LocalBusClient,
) -> Result<(), Box<dyn std::error::Error>> {
    let submit = ramflux_sdk::LocalBusMessageSubmitRequest {
        conversation_id: "conv_tui_default".to_owned(),
        message_id: "msg_s34_bob_to_alice".to_owned(),
        envelope_id: "env_s34_bob_to_alice".to_owned(),
        source_principal_id: "principal_s34_bob".to_owned(),
        sender_id: "bob_s34".to_owned(),
        recipient_device_id: Some("alice_device_s34".to_owned()),
        recipient_principal_commitment: None,
        target_delivery_id: "target_s34_alice".to_owned(),
        encrypted_body_base64: String::new(),
        plaintext_body_base64: Some(ramflux_protocol::encode_base64url(b"s34 inbound to tui")),
        created_at: itest_now_unix_seconds(),
        ttl: ITEST_REPLAY_TTL_SECONDS,
        attachments: Vec::new(),
        federation: None,
    };
    let submitted = bob_bus
        .request(Some("bob_s34_account".to_owned()), "message", "message.submit", &submit)
        .await?;
    assert_eq!(submitted["envelope"]["envelope_id"], "env_s34_bob_to_alice");
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s34_create_mcp_approval(
    alice_bus: &mut ramflux_sdk::LocalBusClient,
) -> Result<(), Box<dyn std::error::Error>> {
    let added = alice_bus
        .request(
            Some("alice_s34_account".to_owned()),
            "mcp",
            "mcp.server.add",
            &serde_json::json!({
                "server_id": "srv_s34",
                "command": "stdio-echo",
                "tool_name": "echo",
                "capability": "read_conversation",
                "tool_scope": "echo",
                "risk_level": "low",
            }),
        )
        .await?;
    assert!(added["registry_hash"].as_str().is_some_and(|value| !value.is_empty()));
    let first_call = alice_bus
        .request(
            Some("alice_s34_account".to_owned()),
            "mcp",
            "mcp.tool.started",
            &serde_json::json!({
                "server_id": "srv_s34",
                "tool_name": "echo",
                "arguments": {"text": "hello tui"},
                "operation_origin": "attended_tui",
            }),
        )
        .await?;
    assert_eq!(first_call["status"], "approval_required");
    assert_eq!(first_call["approval"]["approval_id"], "approval_srv_s34_echo_1");
    assert_eq!(first_call["approval"]["confirmation_mode"], "attended_local");
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s34_next_tui_event(
    bus: &mut ramflux_cli_pro::SdkLocalBus,
    label: &str,
) -> Result<ramflux_sdk::LocalBusFrame, Box<dyn std::error::Error>> {
    Ok(tokio::time::timeout(Duration::from_secs(5), ramflux_cli_pro::TuiBus::next_event(bus))
        .await
        .map_err(|_elapsed| format!("timed out waiting for TUI event: {label}"))??)
}
