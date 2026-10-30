// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Native test-provider signing for adversarial carriers that bypass sender preflight.
use super::*;
use ramflux_sdk::{
    SdkError,
    custody::{BranchCredentials, MemoryPrimaryVault, PrimaryVault},
};
use std::{collections::BTreeMap, sync::Mutex};
use zeroize::Zeroizing;

#[derive(Default)]
pub(super) struct ProbeVault {
    inner: MemoryPrimaryVault,
    branches: Mutex<BTreeMap<String, Zeroizing<[u8; 64]>>>,
    signers: Mutex<BTreeMap<String, ramflux_crypto::DeviceBranch>>,
}
impl PrimaryVault for ProbeVault {
    fn preflight(&self) -> Result<(), SdkError> {
        self.inner.preflight()
    }
    fn store_new(
        &self,
        reference: &str,
        key: &ramflux_crypto::custody::SelfSigningKey,
    ) -> Result<(), SdkError> {
        self.inner.store_new(reference, key)
    }
    fn load_primary(
        &self,
        reference: &str,
    ) -> Result<ramflux_crypto::custody::SelfSigningKey, SdkError> {
        self.inner.load_primary(reference)
    }
    fn delete(&self, reference: &str) -> Result<(), SdkError> {
        self.branches.lock().map_err(|_| SdkError::CustodyVaultUnavailable)?.remove(reference);
        self.inner.delete(reference)
    }
    fn store_branch(&self, reference: &str, seeds: &Zeroizing<[u8; 64]>) -> Result<(), SdkError> {
        self.inner.store_branch(reference, seeds)?;
        self.branches
            .lock()
            .map_err(|_| SdkError::CustodyVaultUnavailable)?
            .insert(reference.into(), seeds.clone());
        Ok(())
    }
    fn load_branch(
        &self,
        reference: &str,
        principal: &str,
        device: &ramflux_protocol::custody::DeviceRef,
    ) -> Result<BranchCredentials, SdkError> {
        let branches = self.branches.lock().map_err(|_| SdkError::CustodyVaultUnavailable)?;
        let seeds = branches.get(reference).ok_or(SdkError::CustodyVaultUnavailable)?;
        let mut signing = Zeroizing::new([0; 32]);
        signing.copy_from_slice(&seeds[..32]);
        self.signers.lock().map_err(|_| SdkError::CustodyVaultUnavailable)?.insert(
            principal.into(),
            ramflux_crypto::create_device_branch(
                principal,
                &device.device_id,
                device.device_epoch,
                *signing,
            ),
        );
        self.inner.load_branch(reference, principal, device)
    }
    fn store_provisioning_secret(&self, reference: &str, secret: &[u8]) -> Result<(), SdkError> {
        self.inner.store_provisioning_secret(reference, secret)
    }
    fn load_provisioning_secret(&self, reference: &str) -> Result<Zeroizing<Vec<u8>>, SdkError> {
        self.inner.load_provisioning_secret(reference)
    }
}

pub(super) async fn reject_at_author(
    bus: &mut ramflux_sdk::LocalBusClient,
    socket: &Path,
    human: &NativeAccount,
    agent: &NativeAccount,
    vault: &ProbeVault,
    kind: &str,
    wire: &[u8],
) -> TestResult {
    let before =
        call(bus, &agent.account_id, "surface.get", json!({"surface_id":"native-surface"})).await?;
    let id = format!("native-raw-{kind}");
    let mut body = json!({"schema":"ramflux.surface.carrier.v2","content_type":"surface","payload_kind":kind,"conversation_id":"dm_agent_v3","surface_id":"native-surface","message_id":id,"sender_principal_id":human.principal_id,"sender_device_id":human.device_id,"author_principal_id":agent.principal_id,"wire_base64":ramflux_protocol::encode_base64url(wire)});
    if kind == "event" {
        let event = ramflux_protocol::A2uiConversationEvent::from_wire_bytes(wire)?;
        let ramflux_protocol::A2uiConversationCommand::PatchSurface(patch) = event.command() else {
            return Err("expected patch probe".into());
        };
        body["snapshot"] = json!({"surface_hash":patch.new_surface_hash,"author_device_id":before["author_device_id"]});
    }
    {
        let signers = vault.signers.lock().map_err(|_| "probe vault locked")?;
        let signer = signers.get(&human.principal_id).ok_or("native human signer absent")?;
        body["signature"] = json!(ramflux_crypto::sign_with_device_branch(
            signer,
            &json!({"domain":"ramflux.surface.carrier.v2","body":body})
        )?);
    }
    let mut raw = b"ramflux.surface.v2\n".to_vec();
    raw.extend(serde_json::to_vec(&body)?);
    let mut watcher = ramflux_sdk::LocalBusClient::connect(socket).await?;
    call(&mut watcher, &agent.account_id, "bus.subscribe", json!({"topics":["surface.rejected"]}))
        .await?;
    call(bus,&human.account_id,"message.submit",json!({"conversation_id":"dm_agent_v3","message_id":id,"envelope_id":id,"source_principal_id":human.principal_id,"sender_id":human.device_id,"recipient_device_id":agent.device_id,"recipient_principal_commitment":agent.anchor,"target_delivery_id":agent.delivery_id,"encrypted_body_base64":"","plaintext_body_base64":ramflux_protocol::encode_base64url(raw),"created_at":realnet_now_i64(),"ttl":300})).await?;
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            receive(bus, &agent.account_id).await?;
            if let Ok(event) =
                tokio::time::timeout(Duration::from_millis(100), watcher.next_event()).await
            {
                let event = event?;
                if event.method == "surface.rejected" && event.body["envelope_id"] == id {
                    assert_eq!(
                        event.body["renderer_error"]["code"],
                        if kind == "event" { "non_author_update" } else { "renderer_error" },
                        "{}",
                        event.body
                    );
                    return Ok::<_, Box<dyn std::error::Error>>(());
                }
            }
        }
    })
    .await??;
    assert_eq!(
        call(bus, &agent.account_id, "surface.get", json!({"surface_id":"native-surface"})).await?,
        before,
        "receiver rejection mutated the author view"
    );
    Ok(())
}
