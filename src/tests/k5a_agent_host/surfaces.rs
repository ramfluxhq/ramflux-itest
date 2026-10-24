// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Real headless host: typed streaming, a human choice, result fallback and restart equivalence.
use super::*;
pub(super) const REPLY: &str = concat!(
    "Checklist\n",
    "- Verify the original protocol bytes and canonical snapshot hash.\n",
    "- Verify that surface versions advance through deterministic chunks.\n",
    "- Verify that only the last stream fragment finalizes the reply block.\n",
    "- Verify that every quoted fallback retains the verified author label.\n",
    "- Verify that the choice reaches the author through authenticated delivery.\n",
    "- Verify that the result patch clears choices and updates its fallback.\n",
    "- Verify that the final surface is closed and survives a host restart."
);

pub(super) async fn round_trip(
    bus: &mut ramflux_sdk::LocalBusClient,
    own: &Value,
    peer: &Value,
) -> TestResult<Value> {
    call(bus,"alice","group.send",json!({"group_id":"group_k5a","conversation_id":"group_thread_k5a","message_id":"checklist_k5a2","sender_id":own["device_id"],"encrypted_body_base64":"","plaintext_body_base64":ramflux_protocol::encode_base64url(b"@agent checklist")})).await?;
    let current = wait(bus, None, false).await?;
    assert_eq!(current["snapshot"]["components"][0]["text"], REPLY);
    assert_eq!(current["author_principal_id"], peer["principal_id"]);
    assert_eq!(current["streams"]["reply"], "final");
    assert_eq!(current["out_of_sync"], false);
    assert!(
        current["version"].as_u64().ok_or("version")? >= 4,
        "create, multiple chunks, fallback patch"
    );
    assert_eq!(current["snapshot"]["fallbackText"], REPLY);
    assert!(!current["closed"].as_bool().ok_or("closed state")?);
    let values = json!({});
    let action = serde_json::to_vec(
        &json!({"schema":"ramflux.a2ui.action.v2","conversationId":"group_thread_k5a","surfaceId":current["surface_id"],"version":current["version"],"surfaceHash":current["surface_hash"],"actionId":"thu","values":values,"argsHash":ramflux_protocol::surface_args_hash(&values)?}),
    )?;
    let random = ramflux_crypto::random_32()?;
    let sent=call(bus,"alice","surface.action",json!({"conversation_id":"group_thread_k5a","author_principal_id":peer["principal_id"],"message_id":ramflux_protocol::encode_base64url(&random[..16]),"wire_base64":ramflux_protocol::encode_base64url(action)})).await?;
    assert_eq!(sent["accepted"], true);
    let completed = wait(bus, current["surface_id"].as_str(), true).await?;
    assert_eq!(completed["snapshot"]["fallbackText"], "You chose Thursday.");
    assert_eq!(completed["streams"]["reply"], "final");
    assert_eq!(completed["out_of_sync"], false);
    let snapshot: ramflux_protocol::CreateSurfaceCommand =
        serde_json::from_value(completed["snapshot"].clone())?;
    assert_eq!(snapshot.allowed_actions, [] as [Value; 0]);
    assert_eq!(ramflux_protocol::surface_snapshot_hash(&snapshot)?, completed["surface_hash"]);
    let read =
        call(bus, "alice", "message.read", json!({"conversation_id":"group_thread_k5a"})).await?;
    let author = peer["principal_id"].as_str().ok_or("principal")?;
    let expected = format!("Surface author=\"{author}\" fallback_text=\"You chose Thursday.\"");
    assert!(
        read["messages"]
            .as_array()
            .ok_or("messages")?
            .iter()
            .any(|row| row["content_type"] == "surface" && row["body_utf8"] == expected)
    );
    Ok(completed)
}
async fn wait(
    bus: &mut ramflux_sdk::LocalBusClient,
    id: Option<&str>,
    closed: bool,
) -> TestResult<Value> {
    for _ in 0..200 {
        call(bus, "alice", "message.receive", json!({"limit":32,"auto_fetch_attachments":false}))
            .await?;
        let listing =
            call(bus, "alice", "surface.list", json!({"conversation_id":"group_thread_k5a"}))
                .await?;
        let rows = listing["surfaces"].as_array().ok_or("surfaces")?;
        assert!(rows.len() <= 1, "one prompt must create one surface");
        if let Some(row) = rows.first() {
            let reference = row["surface_ref"].as_str().ok_or("surface reference")?;
            let view = call(bus, "alice", "surface.get", json!({"surface_ref":reference})).await?;
            if id.is_some_and(|id| view["surface_id"] != id) {
                return Err("surface identity changed".into());
            }
            if closed && view["closed"] == true
                || !closed && view["snapshot"]["fallbackText"] == REPLY
            {
                return Ok(view);
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err("agent surface did not converge".into())
}
pub(super) async fn after_restart(
    bus: &mut ramflux_sdk::LocalBusClient,
    before: &Value,
) -> TestResult {
    let after = wait(bus, before["surface_id"].as_str(), true).await?;
    assert_eq!(&after, before, "host restart must not change the surface or repeat the choice");
    Ok(())
}

#[test]
fn canonical_snapshot_empty_actions_are_omitted_and_decode_without_changing_the_hash() -> TestResult
{
    let snapshot = ramflux_protocol::CreateSurfaceCommand {
        surface_id: "canonical-empty-actions".into(),
        surface_type: ramflux_protocol::SurfaceType::StatusPanel,
        catalog: "basic".into(),
        catalog_version: "1".into(),
        fallback_text: "Done".into(),
        fallback_markdown: None,
        components: vec![],
        data_model: serde_json::Map::new(),
        allowed_actions: vec![],
    };
    let wire = serde_json::to_value(&snapshot)?;
    assert!(wire.get("allowedActions").is_none());
    let decoded: ramflux_protocol::CreateSurfaceCommand = serde_json::from_value(wire.clone())?;
    assert_eq!(decoded.allowed_actions, [] as [Value; 0]);
    assert_eq!(
        ramflux_protocol::surface_snapshot_hash(&decoded)?,
        ramflux_protocol::surface_snapshot_hash(&snapshot)?
    );
    let mut invalid = wire;
    invalid["allowedActions"] = Value::Null;
    assert!(serde_json::from_value::<ramflux_protocol::CreateSurfaceCommand>(invalid).is_err());
    Ok(())
}
