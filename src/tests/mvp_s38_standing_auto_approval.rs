// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use super::*;

#[cfg(feature = "realnet")]
#[test]
fn mvp_s38_realnet_mcp_standing_auto_approval() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    let node = start_s10_private_node_compose()?;
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async {
        wait_for_private_gateway_quic(node.gateway_quic_addr, &node.ca_cert).await?;
        Box::pin(mvp_s38_assert_standing_auto_approval(node.gateway_quic_addr, &node.ca_cert))
            .await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    drop(node);
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
#[allow(clippy::too_many_lines)]
async fn mvp_s38_assert_standing_auto_approval(
    gateway_quic_addr: std::net::SocketAddr,
    ca_cert: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let temp_root = temp_root("s38_standing_auto_approval")?;
    let socket = temp_root.join("alice/rfd.sock");
    // Restart block binds a fresh socket path (same data_root) so the existence-based
    // wait does not race a stale socket file left by the first daemon — mirrors mvp_s30.
    let socket_restore = temp_root.join("alice/rfd-restore.sock");
    let data_root = temp_root.join("alice/data");
    let account_request = mvp_s38_account_request(gateway_quic_addr, ca_cert);

    {
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let server = ramflux_sdk::serve_local_bus_until(
            ramflux_sdk::LocalBusConfig::new(&socket, &data_root),
            shutdown_rx,
        );
        let flow = async {
            let result = async {
                mvp_s4_wait_for_socket(&socket).await?;
                let mut bus = ramflux_sdk::LocalBusClient::connect(&socket).await?;
                let created: ramflux_sdk::LocalBusAccountCreateResponse = serde_json::from_value(
                    bus.request(None, "account", "account.create", &account_request).await?,
                )?;
                assert_eq!(created.local_account_id, "alice_s38_account");

                mvp_s38_install_tool(
                    &mut bus,
                    "notes",
                    "read_conversation",
                    "low",
                    Some("thread:s38"),
                )
                .await?;
                mvp_s38_install_tool(
                    &mut bus,
                    "shell",
                    "external_tool_invoke",
                    "high",
                    Some("shell"),
                )
                .await?;

                let standing =
                    mvp_s38_create_standing(&mut bus, "notes", Some("thread:s38"), None).await?;
                assert_eq!(standing["revoked"], false);
                let auto = mvp_s38_call_tool(&mut bus, "notes").await?;
                assert_eq!(auto["status"], "ok");
                assert_eq!(auto["standing_approval_id"], standing["standing_approval_id"]);
                let pending = mvp_s38_pending_approvals(&mut bus).await?;
                assert_eq!(pending.len(), 0, "standing approval created a pending approval");
                let audit = mvp_s38_audit(&mut bus).await?;
                assert!(
                    audit.iter().any(|entry| {
                        entry["event_type"] == "mcp.standing_auto_approval.invoked"
                            && entry["outcome"] == "allowed"
                    }),
                    "missing standing auto-approval audit: {audit:?}",
                );
                let revoked_initial = bus
                    .request(
                        Some("alice_s38_account".to_owned()),
                        "grant",
                        "grant.revoke_standing_approval",
                        &serde_json::json!({
                            "standing_approval_id": standing["standing_approval_id"],
                        }),
                    )
                    .await?;
                assert_eq!(revoked_initial["revoked"], true);

                let high_standing =
                    mvp_s38_create_standing(&mut bus, "shell", Some("shell"), None).await;
                assert!(high_standing.is_err(), "high risk standing approval must be rejected");
                let high = mvp_s38_call_tool(&mut bus, "shell").await?;
                assert_eq!(high["status"], "approval_required");
                assert_eq!(high["approval"]["confirmation_mode"], "remote_app");

                let expiring =
                    mvp_s38_create_standing(&mut bus, "notes", Some("thread:s38"), Some(1)).await?;
                tokio::time::sleep(Duration::from_secs(2)).await;
                let expired = mvp_s38_call_tool(&mut bus, "notes").await?;
                assert_eq!(expired["status"], "approval_required");
                assert_ne!(expired["approval"]["approval_id"], serde_json::Value::Null);
                assert_ne!(expired["approval"]["approval_id"], expiring["standing_approval_id"]);

                let revokable =
                    mvp_s38_create_standing(&mut bus, "notes", Some("thread:s38"), None).await?;
                let revoked = bus
                    .request(
                        Some("alice_s38_account".to_owned()),
                        "grant",
                        "grant.revoke_standing_approval",
                        &serde_json::json!({
                            "standing_approval_id": revokable["standing_approval_id"],
                        }),
                    )
                    .await?;
                assert_eq!(revoked["revoked"], true);
                let after_revoke = mvp_s38_call_tool(&mut bus, "notes").await?;
                assert_eq!(after_revoke["status"], "approval_required");

                let persistent =
                    mvp_s38_create_standing(&mut bus, "notes", Some("thread:s38"), None).await?;
                assert_eq!(persistent["revoked"], false);

                drop(bus);
                Ok::<(), Box<dyn std::error::Error>>(())
            }
            .await;
            let _ = shutdown_tx.send(true);
            result
        };
        let (server_result, flow_result) = tokio::join!(server, flow);
        server_result?;
        flow_result?;
    }

    {
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let server = ramflux_sdk::serve_local_bus_until(
            ramflux_sdk::LocalBusConfig::new(&socket_restore, &data_root),
            shutdown_rx,
        );
        let flow = async {
            let result = async {
                mvp_s4_wait_for_socket(&socket_restore).await?;
                let mut bus = ramflux_sdk::LocalBusClient::connect(&socket_restore).await?;
                let restored: ramflux_sdk::LocalBusAccountCreateResponse = serde_json::from_value(
                    bus.request(None, "account", "account.create", &account_request).await?,
                )?;
                assert_eq!(restored.local_account_id, "alice_s38_account");
                let standings = bus
                    .request(
                        Some("alice_s38_account".to_owned()),
                        "grant",
                        "grant.list_standing_approvals",
                        &serde_json::json!({}),
                    )
                    .await?;
                assert!(
                    standings["standing_approvals"].as_array().is_some_and(|items| {
                        items
                            .iter()
                            .any(|item| item["tool_name"] == "notes" && item["revoked"] == false)
                    }),
                    "standing approval did not survive restart: {standings:?}",
                );
                let invoked = mvp_s38_call_tool(&mut bus, "notes").await?;
                assert_eq!(invoked["status"], "ok");
                assert!(mvp_s38_pending_approvals(&mut bus).await?.is_empty());
                drop(bus);
                Ok::<(), Box<dyn std::error::Error>>(())
            }
            .await;
            let _ = shutdown_tx.send(true);
            result
        };
        let (server_result, flow_result) = tokio::join!(server, flow);
        server_result?;
        flow_result?;
    }

    std::fs::remove_dir_all(&temp_root)?;
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
fn mvp_s38_account_request(
    gateway_quic_addr: std::net::SocketAddr,
    ca_cert: &Path,
) -> ramflux_sdk::LocalBusAccountCreateRequest {
    ramflux_sdk::LocalBusAccountCreateRequest {
        local_account_id: "alice_s38_account".to_owned(),
        principal_id: "principal_s38_alice".to_owned(),
        principal_commitment: String::new(),
        device_id: "alice_device_s38".to_owned(),
        target_delivery_id: "target_s38_alice".to_owned(),
        account_secret: "s38-bus-secret".to_owned(),
        root_seed: [0x38; 32],
        device_seed: [0xD8; 32],
        client_mode: ramflux_sdk::LocalBusClientMode::AttendedCli,
        gateway: ramflux_sdk::GatewayQuicEndpointConfig {
            bind_addr: std::net::SocketAddr::from(([0, 0, 0, 0], 0)),
            gateway_addr: gateway_quic_addr,
            server_name: "localhost".to_owned(),
            ca_cert: ca_cert.to_path_buf(),
            principal_id: "principal_s38_alice".to_owned(),
            device_id: "alice_device_s38".to_owned(),
            target_delivery_id: "target_s38_alice".to_owned(),
            prekey_http_url: None,
        },
    }
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s38_install_tool(
    bus: &mut ramflux_sdk::LocalBusClient,
    tool_name: &str,
    capability: &str,
    risk_level: &str,
    tool_scope: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let response = bus
        .request(
            Some("alice_s38_account".to_owned()),
            "mcp",
            "mcp.server.add",
            &serde_json::json!({
                "server_id": "srv_s38",
                "command": format!("stdio-{tool_name}"),
                "tool_name": tool_name,
                "capability": capability,
                "tool_scope": tool_scope,
                "risk_level": risk_level,
            }),
        )
        .await?;
    assert!(response["registry_hash"].as_str().is_some_and(|value| !value.is_empty()));
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s38_create_standing(
    bus: &mut ramflux_sdk::LocalBusClient,
    tool_name: &str,
    tool_scope: Option<&str>,
    ttl_seconds: Option<i64>,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    Ok(bus
        .request(
            Some("alice_s38_account".to_owned()),
            "grant",
            "grant.create_standing_approval",
            &serde_json::json!({
                "server_id": "srv_s38",
                "tool_name": tool_name,
                "tool_scope": tool_scope,
                "ttl_seconds": ttl_seconds,
            }),
        )
        .await?)
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s38_call_tool(
    bus: &mut ramflux_sdk::LocalBusClient,
    tool_name: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    Ok(bus
        .request(
            Some("alice_s38_account".to_owned()),
            "mcp",
            "mcp.tool.started",
            &serde_json::json!({
                "server_id": "srv_s38",
                "tool_name": tool_name,
                "arguments": {"text": "s38"},
                "operation_origin": "ai_mcp",
            }),
        )
        .await?)
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s38_pending_approvals(
    bus: &mut ramflux_sdk::LocalBusClient,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let response = bus
        .request(
            Some("alice_s38_account".to_owned()),
            "mcp",
            "mcp.approval.list",
            &serde_json::json!({}),
        )
        .await?;
    Ok(response["approvals"].as_array().cloned().unwrap_or_default())
}

#[cfg(all(test, feature = "realnet"))]
async fn mvp_s38_audit(
    bus: &mut ramflux_sdk::LocalBusClient,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let response = bus
        .request(
            Some("alice_s38_account".to_owned()),
            "mcp",
            "mcp.audit.list",
            &serde_json::json!({}),
        )
        .await?;
    Ok(response["audit"].as_array().cloned().unwrap_or_default())
}
