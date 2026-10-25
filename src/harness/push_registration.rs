// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! S13 production push registration: root-bound devices, authenticated gateway sessions and
//! node-owned provider credentials mounted into notify.
#![allow(unused_imports)]
use crate::*;

/// One root-bound device registered through the router and authenticated on the gateway.
#[cfg(all(test, feature = "realnet"))]
#[derive(Clone, Copy, Debug)]
pub(crate) struct S13Device {
    pub(crate) principal_id: &'static str,
    pub(crate) device_id: &'static str,
    pub(crate) target_delivery_id: &'static str,
    pub(crate) root_seed: [u8; 32],
    pub(crate) device_seed: [u8; 32],
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) const S13_SENDER: S13Device = S13Device {
    principal_id: "principal_s13_alice",
    device_id: "device_s13_alice",
    target_delivery_id: "target_s13_alice",
    root_seed: [0x13; 32],
    device_seed: [0x31; 32],
};

#[cfg(all(test, feature = "realnet"))]
pub(crate) const S13_RECIPIENT: S13Device = S13Device {
    principal_id: "principal_s13_bob",
    device_id: "device_s13_bob",
    target_delivery_id: "target_s13_bob_offline",
    root_seed: [0x14; 32],
    device_seed: [0x41; 32],
};

#[cfg(all(test, feature = "realnet"))]
impl S13Device {
    pub(crate) fn root_commitment(&self) -> String {
        let root = ramflux_crypto::create_identity_root(self.principal_id, self.root_seed);
        ramflux_crypto::identity_root_commitment(&root.signing_key.verifying_key())
    }

    fn signed_fields(&self) -> ramflux_protocol::SignedFields {
        ramflux_protocol::SignedFields {
            signing_key_id: format!("device:{}", self.device_id),
            signature_alg: ramflux_protocol::SignatureAlg::Ed25519,
            signature: String::new(),
        }
    }
}

/// Registers the device with a root-signed device set (the legacy branch proof is read-only).
#[cfg(all(test, feature = "realnet"))]
pub(crate) fn s13_register_rooted_device(
    router_url: &str,
    device: S13Device,
) -> Result<(), Box<dyn std::error::Error>> {
    let root = ramflux_crypto::create_identity_root(device.principal_id, device.root_seed);
    let branch = ramflux_crypto::create_device_branch(
        device.principal_id,
        device.device_id,
        1,
        device.device_seed,
    );
    let agreement = ramflux_crypto::X25519KeyPair::from_seed(device.device_seed);
    let now = itest_now_unix_seconds();
    let proof = ramflux_crypto::authorize_device_branch_v2(
        &root,
        &branch,
        ramflux_crypto::BranchAuthorization {
            audience: ramflux_node_core::IDENTITY_BIND_AUDIENCE,
            capability_scope: vec![ramflux_node_core::IDENTITY_BIND_CAPABILITY.into()],
            issued_at: now,
            expires_at: now.saturating_add(i64::from(ITEST_REPLAY_TTL_SECONDS)),
            principal_kind: ramflux_protocol::PrincipalKind::Human,
            agreement_identity_public_key: agreement.public,
        },
    )?;
    let branch_public_key =
        ramflux_protocol::encode_base64url(branch.signing_key.verifying_key().to_bytes());
    let keys = ramflux_crypto::device_key_commitments(
        &branch_public_key,
        &ramflux_protocol::encode_base64url(agreement.public),
    )?;
    let device_set = ramflux_crypto::sign_device_set(
        &root,
        ramflux_crypto::DeviceSetSigningInput {
            principal_kind: ramflux_protocol::PrincipalKind::Human,
            device_set_epoch: 1,
            devices: vec![ramflux_protocol::SignedDeviceSetEntry {
                device_id: device.device_id.into(),
                device_epoch: 1,
                signing_key_commitment: keys.0,
                agreement_key_commitment: keys.1,
                status: ramflux_protocol::DeviceSetStatus::Active,
                revoked_at: None,
            }],
        },
    )?;
    let root_public_key =
        ramflux_protocol::encode_base64url(root.signing_key.verifying_key().to_bytes());
    let request = ramflux_node_core::IdentityRegisterRequest {
        device_set: Some(device_set),
        principal_commitment: ramflux_crypto::blake3_256_base64url(
            "ramflux.identity.root_public_key.commitment.v1",
            &root.signing_key.verifying_key().to_bytes(),
        ),
        root_public_key,
        branch_public_key,
        proof,
        target_delivery_id: device.target_delivery_id.to_owned(),
        gateway_id: "ramflux-gateway".to_owned(),
        session_id: format!("pre_session_{}", device.device_id),
        push_alias_hash: Some(format!("push_alias_{}", device.device_id)),
        now,
        registration_pow: None,
        source_ip_hash: Some(format!("s13_source_{}", device.device_id)),
    };
    let response: serde_json::Value = ramflux_node_core::itest_http_post_json(
        &format!("{router_url}/mvp1/identity/register"),
        &request,
    )?;
    if response.get("device_id").and_then(serde_json::Value::as_str) != Some(device.device_id) {
        return Err(format!("S13 rooted registration refused: {response}").into());
    }
    Ok(())
}

/// An authenticated gateway session for one S13 device.
#[cfg(all(test, feature = "realnet"))]
pub(crate) struct S13Session {
    pub(crate) _endpoint: quinn::Endpoint,
    pub(crate) connection: quinn::Connection,
    pub(crate) send: quinn::SendStream,
    pub(crate) recv: quinn::RecvStream,
    pub(crate) open: ramflux_node_core::GatewayOpenFrame,
    pub(crate) session_id: String,
    pub(crate) device: S13Device,
    request_counter: u64,
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn s13_open_session(
    gateway_quic_addr: std::net::SocketAddr,
    ca_cert: &Path,
    device: S13Device,
) -> Result<S13Session, Box<dyn std::error::Error>> {
    let (endpoint, connection, mut send, mut recv) =
        mvp_s1_open_quic_stream(gateway_quic_addr, ca_cert).await?;
    let mut open = mvp_s1_open_frame(None, itest_now_unix_seconds().unsigned_abs(), "s13");
    open.client_instance_id = format!("rf_s13_{}", device.device_id);
    open.device_id = device.device_id.to_owned();
    open.target_delivery_id = device.target_delivery_id.to_owned();
    open.stream_nonce = format!("nonce_s13_{}_{}", device.device_id, itest_now_unix_seconds());
    open.source_ip_hash = Some("mvp_s13_source".to_owned());
    let mut auth =
        mvp_s1_auth_frame_for_registered_device(&open, device.principal_id, 1, device.device_seed)?;
    auth.device_proof
        .ext
        .ext
        .insert("source_root_commitment".into(), serde_json::json!(device.root_commitment()));
    auth.device_proof.signed.signature =
        ramflux_crypto::sign_protocol_object_with_seed(&auth.device_proof, device.device_seed)?;
    auth.signed_request.device_proof_hash = ramflux_crypto::blake3_256_base64url(
        ramflux_node_core::GATEWAY_DEVICE_PROOF_HASH_DOMAIN,
        &ramflux_protocol::canonical_json_bytes(&auth.device_proof)?,
    );
    auth.signed_request.signed.signature =
        ramflux_crypto::sign_protocol_object_with_seed(&auth.signed_request, device.device_seed)?;
    mvp_s1_write_client_frame(
        &mut send,
        &ramflux_node_core::GatewayClientFrame::Open { open: open.clone() },
    )
    .await?;
    mvp_s1_write_client_frame(&mut send, &ramflux_node_core::GatewayClientFrame::Auth { auth })
        .await?;
    let session = mvp_s1_expect_session_established(&mut recv).await?;
    Ok(S13Session {
        _endpoint: endpoint,
        connection,
        send,
        recv,
        open,
        session_id: session.session_id,
        device,
        request_counter: 0,
    })
}

#[cfg(all(test, feature = "realnet"))]
impl S13Session {
    fn signed_request<T: serde::Serialize>(
        &mut self,
        path: &str,
        body: &T,
        session_binding: Option<&str>,
    ) -> Result<ramflux_protocol::SignedRequest, Box<dyn std::error::Error>> {
        self.request_counter += 1;
        let now = itest_now_unix_seconds();
        let mut ext = ramflux_protocol::Ext::default();
        if let Some(session_id) = session_binding {
            ext.ext.insert("session_id".into(), serde_json::json!(session_id));
        }
        let mut request = ramflux_protocol::SignedRequest {
            schema: "ramflux.signed_request.v1".to_owned(),
            version: 1,
            domain: "ramflux.signed_request.v1".to_owned(),
            ext,
            signed: self.device.signed_fields(),
            source_device_id: self.device.device_id.to_owned(),
            request_id: format!("req_s13_{}_{}", self.device.device_id, self.request_counter),
            method: ramflux_protocol::HttpMethod::POST,
            path: path.to_owned(),
            device_proof_hash: "already_authed".to_owned(),
            body_hash: ramflux_crypto::blake3_256_base64url(
                ramflux_protocol::domain::ENVELOPE,
                &ramflux_protocol::canonical_json_bytes(body)?,
            ),
            nonce: format!("{}_{}", self.open.stream_nonce, self.request_counter),
            created_at: now,
            expires_at: now.saturating_add(i64::from(ITEST_REPLAY_TTL_SECONDS)),
        };
        request.signed.signature =
            ramflux_crypto::sign_protocol_object_with_seed(&request, self.device.device_seed)?;
        Ok(request)
    }

    /// Registers a push route over this session; `session_binding` overrides the bound session.
    pub(crate) async fn register_push_route(
        &mut self,
        body: ramflux_node_core::PushRouteRegistration,
        session_binding: Option<&str>,
    ) -> Result<ramflux_node_core::GatewayServerFrame, Box<dyn std::error::Error>> {
        let binding = session_binding.map_or_else(|| self.session_id.clone(), str::to_owned);
        let signed_request =
            self.signed_request(ramflux_node_core::PUSH_ROUTE_PATH, &body, Some(&binding))?;
        mvp_s1_write_client_frame(
            &mut self.send,
            &ramflux_node_core::GatewayClientFrame::PushRouteRegister {
                request: Box::new(ramflux_node_core::PushRouteRegistrationFrame {
                    signed_request,
                    body,
                }),
            },
        )
        .await?;
        loop {
            match mvp_s1_read_server_frame(&mut self.recv).await? {
                ramflux_node_core::GatewayServerFrame::InBandWake { .. }
                | ramflux_node_core::GatewayServerFrame::Deliver { .. } => {}
                frame => return Ok(frame),
            }
        }
    }

    /// Submits a root-bound envelope from this device.
    pub(crate) async fn submit(
        &mut self,
        mut envelope: ramflux_protocol::Envelope,
    ) -> Result<ramflux_node_core::InboxEntry, Box<dyn std::error::Error>> {
        envelope.source_principal_id = self.device.principal_id.to_owned();
        envelope.source_device_id = self.device.device_id.to_owned();
        envelope.ext.ext.insert(
            "source_root_commitment".into(),
            serde_json::json!(self.device.root_commitment()),
        );
        envelope.signed = self.device.signed_fields();
        envelope.signed.signature = ramflux_crypto::sign_canonical_bytes_with_seed(
            &ramflux_protocol::envelope_sender_signed_bytes(&envelope)?,
            self.device.device_seed,
        );
        let signed_request = self.signed_request("/gateway/session/submit", &envelope, None)?;
        let expected = envelope.envelope_id.clone();
        mvp_s1_write_client_frame(
            &mut self.send,
            &ramflux_node_core::GatewayClientFrame::Submit {
                submit: ramflux_node_core::GatewaySubmitFrame { signed_request, envelope },
            },
        )
        .await?;
        loop {
            match mvp_s1_read_server_frame(&mut self.recv).await? {
                ramflux_node_core::GatewayServerFrame::Deliver { entry }
                    if entry.envelope.envelope_id == expected =>
                {
                    return Ok(entry);
                }
                ramflux_node_core::GatewayServerFrame::Deliver { .. }
                | ramflux_node_core::GatewayServerFrame::InBandWake { .. } => {}
                other => return Err(format!("expected S13 submit delivery, got {other:?}").into()),
            }
        }
    }
}

/// Node-owned provider credentials, mounted read-only into notify (never client-supplied).
#[cfg(all(test, feature = "realnet"))]
pub(crate) struct S13ProviderConfig {
    path: PathBuf,
    pub(crate) env: Vec<(String, String)>,
}

#[cfg(all(test, feature = "realnet"))]
impl Drop for S13ProviderConfig {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn s13_provider_config(
    mock: &S13MockPushProvider,
) -> Result<S13ProviderConfig, Box<dyn std::error::Error>> {
    let dir = code_root().join("ramflux/deploy/certs/notify");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("s13-provider-credentials.json");
    std::fs::write(&path, serde_json::to_vec(&s13_provider_credentials(mock))?)?;
    let origin = mock.container_url("");
    Ok(S13ProviderConfig {
        path,
        env: vec![
            (
                "RAMFLUX_NOTIFY_PROVIDER_CREDENTIALS_FILE".to_owned(),
                "/etc/ramflux/mesh/s13-provider-credentials.json".to_owned(),
            ),
            ("RAMFLUX_NOTIFY_WEBPUSH_ORIGINS".to_owned(), origin),
        ],
    })
}
