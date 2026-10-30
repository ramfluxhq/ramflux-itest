// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Receiver probes deliberately bypass surface.send/action sender preflight.
use super::*;
fn signed_probe(
    conversation: &str,
    surface: &str,
    kind: &str,
    wire: &[u8],
    before: &Value,
) -> TestResult<Vec<u8>> {
    let id = format!("{surface}-raw-{kind}");
    let mut body = json!({"schema":"ramflux.surface.carrier.v2","content_type":"surface","payload_kind":kind,"conversation_id":conversation,"surface_id":surface,"message_id":id,"sender_principal_id":"principal_k2b_human","sender_device_id":"device_k2b_human","author_principal_id":"principal_k2b_agent","wire_base64":ramflux_protocol::encode_base64url(wire)});
    if kind == "event" {
        let event = ramflux_protocol::A2uiConversationEvent::from_wire_bytes(wire)?;
        let ramflux_protocol::A2uiConversationCommand::PatchSurface(patch) = event.command() else {
            return Err("raw non-author event probe expects a patch".into());
        };
        let author = before["author_device_id"].as_str().ok_or("surface author device")?;
        body["snapshot"] = json!({"surface_hash":patch.new_surface_hash,"author_device_id":author});
    }
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
    Ok(raw)
}

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
    let before = call(agent, "agent", "surface.get", json!({"surface_id":surface})).await?;
    let raw = signed_probe(conversation, surface, kind, wire, &before)?;
    let mut watcher = ramflux_sdk::LocalBusClient::connect(socket).await?;
    call(&mut watcher, "agent", "bus.subscribe", json!({"topics":["surface.rejected"]})).await?;
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
    waits::condition(&format!("receiver rejection surface={surface} kind={kind}"), async {
        loop {
            // Retain a partial event read across polling ticks. Finish each bus
            // receive request before reusing the same client for surface.get.
            let event = {
                let pending_event = watcher.next_event();
                tokio::pin!(pending_event);
                loop {
                    call(
                        agent,
                        "agent",
                        "message.receive",
                        json!({"limit":32,"auto_fetch_attachments":false}),
                    )
                    .await?;
                    if let Ok(event) =
                        tokio::time::timeout(Duration::from_millis(300), &mut pending_event).await
                    {
                        break event?;
                    }
                }
            };
            if event.method == "surface.rejected"
                && event.body["envelope_id"]
                    .as_str()
                    .is_some_and(|id| delivery_ids.iter().any(|sent| sent == id))
            {
                let code = &event.body["renderer_error"]["code"];
                let expected = if kind == "event" { "non_author_update" } else { "renderer_error" };
                assert_eq!(code, expected, "unexpected reject: {}", event.body);
                return Ok(());
            }
        }
    })
    .await?;
    let after = call(agent, "agent", "surface.get", json!({"surface_id":surface})).await?;
    assert_eq!(after, before, "foreign rejects must not mutate the author's view");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn raw_receiver_probe_signs_a_hash_bearing_delta_without_a_full_snapshot() -> TestResult {
        let before = json!({"author_device_id":"device_k2b_agent"});
        let content: ramflux_protocol::CreateSurfaceCommand = serde_json::from_value(
            json!({"surfaceId":"surface","surfaceType":"status_panel","catalog":"basic","catalogVersion":"1","fallbackText":"forged status","components":[{"id":"result","text":""}],"dataModel":{},"allowedActions":[]}),
        )?;
        let hash = ramflux_protocol::surface_snapshot_hash(&content)?;
        let wire = actors::wire(
            "thread",
            3,
            ramflux_protocol::A2uiConversationCommand::PatchSurface(
                ramflux_protocol::PatchSurfaceCommand {
                    surface_id: "surface".into(),
                    base_surface_hash: hash.clone(),
                    new_surface_hash: hash.clone(),
                    ops: vec![ramflux_protocol::SurfacePatchOp::SetFallbackText {
                        fallback_text: content.fallback_text,
                    }],
                },
            ),
        )?;
        let bytes = signed_probe("thread", "surface", "event", &wire, &before)?;
        let raw = bytes.strip_prefix(b"ramflux.surface.v2\n").ok_or("carrier prefix")?;
        let mut body: Value = serde_json::from_slice(raw)?;
        assert_eq!(body["snapshot"]["surface_hash"], hash);
        assert_eq!(body["snapshot"]["author_device_id"], "device_k2b_agent");
        assert!(body["snapshot"].get("checkpoint_base64").is_none());
        let signature =
            body.as_object_mut().ok_or("body")?.remove("signature").ok_or("signature")?;
        let branch = ramflux_crypto::create_device_branch(
            "principal_k2b_human",
            "device_k2b_human",
            1,
            [42; 32],
        );
        ramflux_crypto::verify_device_branch_signature(
            &ramflux_protocol::encode_base64url(branch.signing_key.verifying_key().to_bytes()),
            &json!({"domain":"ramflux.surface.carrier.v2","body":body}),
            signature.as_str().ok_or("signature string")?,
        )?;
        Ok(())
    }
}
