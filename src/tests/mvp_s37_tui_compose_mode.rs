// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use super::*;

const S37_BODY: &str = "relax xray lol";
const S37_CONVERSATION_ID: &str = "conv_s37_tui_dm";

#[cfg(feature = "realnet")]
#[test]
fn mvp_s37_realnet_tui_compose_mode_dm() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    let node = start_s10_private_node_compose()?;
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async {
        wait_for_private_gateway_quic(node.gateway_quic_addr, &node.ca_cert).await?;
        Box::pin(mvp_s37_assert_tui_compose_mode(node.gateway_quic_addr, &node.ca_cert)).await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    drop(node);
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
#[allow(clippy::too_many_lines)]
async fn mvp_s37_assert_tui_compose_mode(
    gateway_quic_addr: std::net::SocketAddr,
    ca_cert: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let temp_root = temp_root("s37_tui_compose_mode")?;
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
            let alice_commitment = mvp_s37_create_account(
                &mut alice_setup_bus,
                gateway_quic_addr,
                ca_cert,
                MvpS37AccountSpec {
                    local_account_id: "alice_s37_account",
                    principal_id: "principal_s37_alice",
                    device_id: "alice_device_s37",
                    target_delivery_id: "target_s37_alice",
                    root_seed: [0x38; 32],
                    device_seed: [0x39; 32],
                },
            )
            .await?;
            let bob_commitment = mvp_s37_create_account(
                &mut bob_bus,
                gateway_quic_addr,
                ca_cert,
                MvpS37AccountSpec {
                    local_account_id: "bob_s37_account",
                    principal_id: "principal_s37_bob",
                    device_id: "bob_device_s37",
                    target_delivery_id: "target_s37_bob",
                    root_seed: [0x3a; 32],
                    device_seed: [0x3b; 32],
                },
            )
            .await?;
            mvp_s37_add_contact(
                &mut alice_setup_bus,
                "alice_s37_account",
                &alice_commitment,
                &bob_commitment,
            )
            .await?;
            mvp_s37_add_contact(
                &mut bob_bus,
                "bob_s37_account",
                &bob_commitment,
                &alice_commitment,
            )
            .await?;

            let mut app = ramflux_cli_pro::TuiApp::new("alice_s37_account");
            let mut tui_bus = ramflux_cli_pro::SdkLocalBus::connect(&alice_socket).await?;
            app.refresh_all(&mut tui_bus).await?;
            assert!(
                !app.state.conversations.is_empty(),
                "TUI refresh must load/default conversations",
            );
            app.state.conversations[0].id = S37_CONVERSATION_ID.to_owned();
            app.state.conversations[0].title = "Bob S37".to_owned();
            app.state.conversations[0].recipient_device_id = Some("bob_device_s37".to_owned());
            app.state.conversations[0].target_delivery_id = Some("target_s37_bob".to_owned());

            app.state.selected_panel = ramflux_cli_pro::Panel::Messages;
            app.handle_input(&mut tui_bus, ramflux_cli_pro::TuiInput::EnterCompose).await?;
            for value in S37_BODY.chars() {
                app.handle_input(&mut tui_bus, ramflux_cli_pro::TuiInput::Char(value)).await?;
            }
            app.handle_input(&mut tui_bus, ramflux_cli_pro::TuiInput::Enter).await?;
            assert!(
                app.state.messages.iter().any(|message| message.body == S37_BODY),
                "TUI did not keep composed body in local view",
            );

            let bob_received = bob_bus
                .request(
                    Some("bob_s37_account".to_owned()),
                    "message",
                    "message.receive",
                    &ramflux_sdk::LocalBusMessageReceiveRequest {
                        limit: 10,
                        conversation_id: Some(S37_CONVERSATION_ID.to_owned()),
                        auto_fetch_attachments: false,
                        relay_service_key_base64: None,
                    },
                )
                .await?;
            assert_s37_bob_decrypted_body(&bob_received)?;

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
        .map_err(|_elapsed| "S37 TUI compose flow timed out")?;
    alice_result?;
    bob_result?;
    flow_result?;
    std::fs::remove_dir_all(&temp_root)?;
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
struct MvpS37AccountSpec<'a> {
    local_account_id: &'a str,
    principal_id: &'a str,
    device_id: &'a str,
    target_delivery_id: &'a str,
    root_seed: [u8; 32],
    device_seed: [u8; 32],
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s37_create_account(
    bus: &mut ramflux_sdk::LocalBusClient,
    gateway_quic_addr: std::net::SocketAddr,
    ca_cert: &Path,
    spec: MvpS37AccountSpec<'_>,
) -> Result<String, Box<dyn std::error::Error>> {
    let request = ramflux_sdk::LocalBusAccountCreateRequest {
        local_account_id: spec.local_account_id.to_owned(),
        principal_id: spec.principal_id.to_owned(),
        principal_commitment: String::new(),
        device_id: spec.device_id.to_owned(),
        target_delivery_id: spec.target_delivery_id.to_owned(),
        account_secret: "s37-bus-secret".to_owned(),
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
    let transport = response.active_transport_kind.as_str();
    assert!(
        transport.starts_with("quic") || transport.starts_with("tcp"),
        "expected established quic*/tcp* transport, got {transport:?}",
    );
    Ok(response.principal_commitment)
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s37_add_contact(
    bus: &mut ramflux_sdk::LocalBusClient,
    account: &str,
    requester: &str,
    target: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let added = bus
        .request(
            Some(account.to_owned()),
            "contact",
            "contact.add",
            &ramflux_sdk::LocalBusContactAddRequest {
                link_id: format!("friend_link_s37_{requester}_{target}"),
                requester_id: requester.to_owned(),
                target_id: target.to_owned(),
            },
        )
        .await?;
    assert_eq!(added["state"], "accepted");
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
fn assert_s37_bob_decrypted_body(
    bob_received: &serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(decrypted) = bob_received["decrypted_messages"].as_array() else {
        return Err(format!("missing S37 decrypted messages: {bob_received}").into());
    };
    for message in decrypted {
        let Some(plaintext) = message["plaintext_body_base64"].as_str() else {
            continue;
        };
        if ramflux_protocol::decode_base64url(plaintext)? == S37_BODY.as_bytes() {
            return Ok(());
        }
    }
    Err(format!("Bob did not decrypt TUI compose body: {bob_received}").into())
}
