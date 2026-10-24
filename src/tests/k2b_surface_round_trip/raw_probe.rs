// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Receiver probes deliberately bypass surface.send/action sender preflight.
use super::*;
pub(super) async fn reject_at_author(
    human: &mut ramflux_sdk::LocalBusClient,
    agent: &mut ramflux_sdk::LocalBusClient,
    socket: &Path,
    conversation: &str,
    probe: (&str, &str),
    wire: &[u8],
) -> TestResult {
    let (surface, kind) = probe;
    let id = format!("{surface}-raw-{kind}");
    let mut body = json!({"schema":"ramflux.surface.carrier.v2","content_type":"surface","payload_kind":kind,"conversation_id":conversation,"surface_id":surface,"message_id":id,"sender_principal_id":"principal_k2b_human","sender_device_id":"device_k2b_human","author_principal_id":"principal_k2b_agent","wire_base64":ramflux_protocol::encode_base64url(wire)});
    let branch = ramflux_crypto::create_device_branch(
        "principal_k2b_human",
        "device_k2b_human",
        1,
        [42; 32],
    );
    let signature = ramflux_crypto::sign_with_device_branch(
        &branch,
        &json!({"domain":"ramflux.surface.carrier.v2","body":body}),
    )?;
    body["signature"] = json!(signature);
    let mut raw = b"ramflux.surface.v2\n".to_vec();
    raw.extend(serde_json::to_vec(&body)?);
    let mut watcher = ramflux_sdk::LocalBusClient::connect(socket).await?;
    call(&mut watcher, "agent", "bus.subscribe", json!({"topics":["surface.rejected"]})).await?;
    let before = call(agent, "agent", "surface.get", json!({"surface_id":surface})).await?;
    let mut delivery_ids = vec![id.clone()];
    if conversation == "group_thread_k2b" {
        let sent = call(human,"human","group.send",json!({"group_id":"group_k2b","conversation_id":conversation,"message_id":id,"sender_id":"device_k2b_human","encrypted_body_base64":"","plaintext_body_base64":ramflux_protocol::encode_base64url(raw)})).await?;
        delivery_ids = sent["submitted"]
            .as_array()
            .ok_or("submitted deliveries")?
            .iter()
            .filter_map(|row| row["envelope"]["envelope_id"].as_str().map(str::to_owned))
            .collect();
        assert_ne!(delivery_ids, [] as [String; 0]);
    } else {
        let directory = call(human, "human", "identity.directory", json!({"limit":100})).await?;
        let peer = directory["identities"]
            .as_array()
            .ok_or("identities")?
            .iter()
            .find(|row| row["principal_id"] == "principal_k2b_agent")
            .ok_or("author identity")?;
        call(human,"human","message.submit",json!({"conversation_id":conversation,"message_id":id,"envelope_id":id,"source_principal_id":"principal_k2b_human","sender_id":"device_k2b_human","recipient_device_id":"device_k2b_agent","recipient_principal_commitment":peer["contact_identity_commitment"],"target_delivery_id":"target_k2b_agent","encrypted_body_base64":"","plaintext_body_base64":ramflux_protocol::encode_base64url(raw),"created_at":realnet_now_i64(),"ttl":300})).await?;
    }
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            call(
                agent,
                "agent",
                "message.receive",
                json!({"limit":32,"auto_fetch_attachments":false}),
            )
            .await?;
            if let Ok(event) =
                tokio::time::timeout(Duration::from_millis(300), watcher.next_event()).await
            {
                let event = event?;
                if event.method == "surface.rejected"
                    && event.body["envelope_id"]
                        .as_str()
                        .is_some_and(|id| delivery_ids.iter().any(|sent| sent == id))
                {
                    let code = &event.body["renderer_error"]["code"];
                    assert!(
                        code == "non_author_update" || code == "renderer_error",
                        "unexpected reject: {}",
                        event.body
                    );
                    return Ok::<(), Box<dyn std::error::Error>>(());
                }
            }
        }
    })
    .await??;
    let after = call(agent, "agent", "surface.get", json!({"surface_id":surface})).await?;
    assert_eq!(after, before, "foreign rejects must not mutate the author's view");
    Ok(())
}
