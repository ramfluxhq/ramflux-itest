// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use crate::*;

#[cfg(all(test, feature = "realnet"))]
pub(crate) async fn mvp_s13_assert_push_provider_wake_bridge(
    gateway_quic_addr: std::net::SocketAddr,
    ca_cert: &Path,
    notify_url: &str,
    mock: &S13MockPushProvider,
) -> Result<(), Box<dyn std::error::Error>> {
    mvp_s13_register_provider_credentials(notify_url, mock)?;
    mvp_s13_register_push_route(
        notify_url,
        ramflux_node_core::PushProviderKind::WebPush,
        "s13-webpush",
        "target_s13_bob_offline",
        "webpush-token-s13",
        &mock.container_url("/webpush"),
    )?;
    mvp_s13_register_push_route(
        notify_url,
        ramflux_node_core::PushProviderKind::Fcm,
        "s13-fcm",
        "target_s13_bob_offline",
        "fcm-token-s13",
        &mock.container_url("/fcm"),
    )?;

    let (_endpoint, connection, mut send, mut recv) =
        mvp_s1_open_quic_stream(gateway_quic_addr, ca_cert).await?;
    let open = mvp_s1_open_frame(None, 1_760_000_000, "s13_push");
    let auth = mvp_s1_auth_frame(&open)?;
    mvp_s1_write_client_frame(
        &mut send,
        &ramflux_node_core::GatewayClientFrame::Open { open: open.clone() },
    )
    .await?;
    mvp_s1_write_client_frame(&mut send, &ramflux_node_core::GatewayClientFrame::Auth { auth })
        .await?;
    let _established = mvp_s1_expect_session_established(&mut recv).await?;

    let mut envelope = itest_envelope("env_s13_push_dm", "target_s13_bob_offline");
    envelope.encrypted_payload =
        ramflux_protocol::encode_base64url(b"s13 opaque ciphertext not plaintext");
    envelope.payload_hash = ramflux_crypto::blake3_256_base64url(
        ramflux_protocol::domain::ENVELOPE,
        envelope.encrypted_payload.as_bytes(),
    );
    let plaintext = b"s13 forbidden plaintext conversation_id group_id SRTP_MEDIA_KEY run_shell";
    assert_node_opaque_payload(&envelope.encrypted_payload, plaintext);
    let submit = mvp_s1_submit_frame(&open, envelope)?;
    mvp_s1_write_client_frame(&mut send, &ramflux_node_core::GatewayClientFrame::Submit { submit })
        .await?;
    let delivered = mvp_s1_expect_deliver(&mut recv).await?;
    assert_eq!(delivered.envelope.envelope_id, "env_s13_push_dm");
    let wake = mvp_s1_read_server_frame(&mut recv).await?;
    assert!(
        matches!(wake, ramflux_node_core::GatewayServerFrame::InBandWake { ref target_delivery_id, .. } if target_delivery_id == "target_s13_bob_offline"),
        "expected S13 in-band wake, got {wake:?}"
    );
    connection.close(0_u32.into(), b"s13-push-done");

    let requests = mock.wait_for_requests(Duration::from_secs(10))?;
    assert_eq!(requests.len(), 2);
    let providers = requests
        .iter()
        .map(|request| request.payload.provider.clone())
        .collect::<std::collections::BTreeSet<_>>();
    assert!(providers.contains(&ramflux_node_core::PushProviderKind::WebPush));
    assert!(providers.contains(&ramflux_node_core::PushProviderKind::Fcm));
    for request in requests {
        assert_s13_provider_request(&request, plaintext)?;
    }
    assert_s13_provider_attempts_recorded(notify_url)?;
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
fn assert_s13_provider_attempts_recorded(
    notify_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let attempts =
        poll_s13_provider_attempts(notify_url, "wake_env_s13_push_dm", 2, Duration::from_secs(10))?;
    assert_eq!(attempts.len(), 2, "expected two S13 provider attempts: {attempts:?}");
    let providers = attempts
        .iter()
        .map(|attempt| attempt.provider.clone())
        .collect::<std::collections::BTreeSet<_>>();
    assert!(providers.contains(&ramflux_node_core::PushProviderKind::WebPush));
    assert!(providers.contains(&ramflux_node_core::PushProviderKind::Fcm));
    for attempt in &attempts {
        assert_eq!(attempt.queue_id, "wake_env_s13_push_dm");
        assert_eq!(attempt.device_delivery_id, "target_s13_bob_offline");
        assert!(attempt.accepted, "S13 provider attempt was not accepted: {attempt:?}");
        assert_eq!(attempt.action, ramflux_node_core::NotifyDeliveryAction::Accept);
        assert_eq!(
            attempt.delivery_class,
            ramflux_protocol::NotificationDeliveryClass::UserContentNotification
        );
        assert!(!attempt.push_alias_hash.is_empty());
        assert!(!attempt.collapse_key_hash.is_empty());
        assert_eq!(attempt.error_class, None);
    }
    let attempts_json = serde_json::to_vec(&attempts)?;
    for forbidden in [
        b"webpush-token-s13".as_slice(),
        b"fcm-token-s13".as_slice(),
        b"host.docker.internal".as_slice(),
        b"/webpush".as_slice(),
        b"/fcm".as_slice(),
    ] {
        assert!(
            !attempts_json.windows(forbidden.len()).any(|window| window == forbidden),
            "provider attempts leaked provider secret or endpoint: {}",
            String::from_utf8_lossy(forbidden)
        );
    }
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
fn poll_s13_provider_attempts(
    notify_url: &str,
    queue_id: &str,
    expected_count: usize,
    timeout: Duration,
) -> Result<Vec<ramflux_node_core::ProviderPushAttempt>, Box<dyn std::error::Error>> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let attempts: Vec<ramflux_node_core::ProviderPushAttempt> =
            ramflux_node_core::itest_http_get_json(&format!(
                "{notify_url}/s13/notify/provider-attempts/{queue_id}"
            ))?;
        if attempts.len() >= expected_count {
            return Ok(attempts);
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!(
                "timed out waiting for S13 provider attempts: queue_id={queue_id} observed={} expected={expected_count}",
                attempts.len()
            )
            .into());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(all(test, feature = "realnet"))]
fn assert_s13_provider_request(
    request: &S13MockPushRequest,
    plaintext: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    assert!(matches!(request.path.as_str(), "/webpush" | "/fcm"));
    assert_eq!(request.headers.get("ttl").map(String::as_str), Some("86400"));
    assert_eq!(request.headers.get("urgency").map(String::as_str), Some("normal"));
    assert_eq!(
        request.headers.get("ramflux-delivery-class").map(String::as_str),
        Some("user_content_notification")
    );
    assert!(request.headers.contains_key("ramflux-push-alias-hash"));
    assert!(request.headers.contains_key("ramflux-collapse-key-hash"));
    assert_s13_provider_auth_headers(request)?;
    assert_eq!(
        request.payload.delivery_class,
        ramflux_protocol::NotificationDeliveryClass::UserContentNotification
    );
    assert!(request.payload.collapse_key.as_deref().unwrap_or_default().contains("target:"));
    let payload_json = serde_json::to_vec(&request.payload)?;
    for forbidden in [
        b"s13 forbidden plaintext".as_slice(),
        b"conversation_id".as_slice(),
        b"group_id".as_slice(),
        b"SRTP_MEDIA_KEY".as_slice(),
        b"run_shell".as_slice(),
    ] {
        assert!(
            !payload_json.windows(forbidden.len()).any(|window| window == forbidden),
            "push payload leaked forbidden plaintext: {}",
            String::from_utf8_lossy(forbidden)
        );
    }
    let hint = request.payload.encrypted_hint.as_deref().ok_or("missing encrypted_hint")?;
    assert_node_opaque_payload(hint, plaintext);
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
fn assert_s13_provider_auth_headers(
    request: &S13MockPushRequest,
) -> Result<(), Box<dyn std::error::Error>> {
    if request.payload.provider == ramflux_node_core::PushProviderKind::WebPush {
        assert_eq!(request.headers.get("content-encoding").map(String::as_str), Some("aes128gcm"));
        let authorization =
            request.headers.get("authorization").ok_or("missing webpush authorization")?;
        assert!(authorization.starts_with("vapid t="));
    } else if request.payload.provider == ramflux_node_core::PushProviderKind::Fcm {
        assert_eq!(
            request.headers.get("authorization").map(String::as_str),
            Some("Bearer stub_fcm_access_token")
        );
    }
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp_s13_register_provider_credentials(
    notify_url: &str,
    mock: &S13MockPushProvider,
) -> Result<(), Box<dyn std::error::Error>> {
    let fcm_account = serde_json::json!({
        "client_email": "s13-fcm@example.iam.gserviceaccount.com",
        "private_key": S13_RSA_PRIVATE_KEY,
        "token_uri": mock.container_url("/fcm/token")
    })
    .to_string();
    let fcm =
        ramflux_node_core::ProviderCredential::Fcm(ramflux_node_core::FcmProviderCredential {
            credential_id: "s13-fcm".to_owned(),
            project_id: "s13-project".to_owned(),
            service_account_json_ref: format!("literal:{fcm_account}"),
            oauth_scope: "https://www.googleapis.com/auth/firebase.messaging".to_owned(),
            oauth_token_url: Some(mock.container_url("/fcm/token")),
            provider_ca_pem_ref: Some(mock.ca_pem_secret_ref()),
        });
    let webpush = ramflux_node_core::ProviderCredential::WebPush(
        ramflux_node_core::WebPushProviderCredential {
            credential_id: "s13-webpush".to_owned(),
            vapid_public_key_ref: "literal:s13-vapid-public-key".to_owned(),
            vapid_private_key_ref: format!("literal:{S13_EC_PRIVATE_KEY}"),
            subject: "mailto:ops@ramflux.example".to_owned(),
            provider_ca_pem_ref: Some(mock.ca_pem_secret_ref()),
        },
    );
    let _: serde_json::Value = ramflux_node_core::itest_http_post_json(
        &format!("{notify_url}/s13/notify/provider-credential"),
        &fcm,
    )?;
    let _: serde_json::Value = ramflux_node_core::itest_http_post_json(
        &format!("{notify_url}/s13/notify/provider-credential"),
        &webpush,
    )?;
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn mvp_s13_register_push_route(
    notify_url: &str,
    provider: ramflux_node_core::PushProviderKind,
    credential_id: &str,
    device_delivery_id: &str,
    token: &str,
    endpoint: &str,
) -> Result<ramflux_node_core::DevicePushRoute, Box<dyn std::error::Error>> {
    let (webpush_p256dh, webpush_auth) = if provider == ramflux_node_core::PushProviderKind::WebPush
    {
        (Some(s13_webpush_subscription_p256dh()?), Some(s13_webpush_subscription_auth()))
    } else {
        (None, None)
    };
    Ok(ramflux_node_core::itest_http_post_json(
        &format!("{notify_url}/s13/notify/push-route"),
        &ramflux_node_core::DevicePushRoute {
            device_delivery_id: device_delivery_id.to_owned(),
            provider,
            credential_id: Some(credential_id.to_owned()),
            token: token.to_owned(),
            endpoint: endpoint.to_owned(),
            webpush_p256dh,
            webpush_auth,
            registered_at: 1_760_000_000,
            expires_at: 4_102_444_800,
        },
    )?)
}

#[cfg(all(test, feature = "realnet"))]
#[derive(Clone, Debug)]
pub(crate) struct S13MockPushRequest {
    pub(crate) path: String,
    pub(crate) headers: std::collections::BTreeMap<String, String>,
    pub(crate) payload: ramflux_node_core::ProviderPushPayload,
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn s13_provider_payload_from_body(
    path: &str,
    headers: &std::collections::BTreeMap<String, String>,
    body: &[u8],
) -> Result<ramflux_node_core::ProviderPushPayload, Box<dyn std::error::Error>> {
    if path.contains("webpush")
        && headers.get("content-encoding").map(String::as_str) == Some("aes128gcm")
    {
        let plaintext = decrypt_s13_webpush_body(body)?;
        return provider_payload_from_json(path, headers, &plaintext);
    }
    if let Ok(payload) = serde_json::from_slice::<ramflux_node_core::ProviderPushPayload>(body) {
        return Ok(payload);
    }
    provider_payload_from_json(path, headers, body)
}

#[cfg(all(test, feature = "realnet"))]
fn provider_payload_from_json(
    path: &str,
    headers: &std::collections::BTreeMap<String, String>,
    body: &[u8],
) -> Result<ramflux_node_core::ProviderPushPayload, Box<dyn std::error::Error>> {
    let value: serde_json::Value = serde_json::from_slice(body)?;
    let provider = if path.contains("fcm") {
        ramflux_node_core::PushProviderKind::Fcm
    } else if path.contains("webpush") {
        ramflux_node_core::PushProviderKind::WebPush
    } else {
        ramflux_node_core::PushProviderKind::Apns
    };
    let data = value.get("message").and_then(|message| message.get("data")).unwrap_or(&value);
    let android = value
        .get("message")
        .and_then(|message| message.get("android"))
        .unwrap_or(&serde_json::Value::Null);
    let wake_id = data
        .get("wake_id")
        .and_then(serde_json::Value::as_str)
        .ok_or("missing wake_id")?
        .to_owned();
    let delivery_class_value =
        data.get("delivery_class").cloned().ok_or("missing delivery_class")?;
    let delivery_class = serde_json::from_value(delivery_class_value)?;
    let encrypted_hint =
        data.get("encrypted_hint").and_then(serde_json::Value::as_str).map(ToOwned::to_owned);
    let ttl = headers
        .get("ttl")
        .and_then(|ttl| ttl.parse::<u32>().ok())
        .or_else(|| {
            android
                .get("ttl")
                .and_then(serde_json::Value::as_str)
                .and_then(|ttl| ttl.strip_suffix('s'))
                .and_then(|ttl| ttl.parse::<u32>().ok())
        })
        .unwrap_or(0);
    let priority = match headers.get("urgency").map(String::as_str) {
        Some("high") => ramflux_protocol::PushPriority::High,
        Some("low") => ramflux_protocol::PushPriority::Low,
        _ => ramflux_protocol::PushPriority::Normal,
    };
    let collapse_key = headers.get("ramflux-collapse-key").cloned().or_else(|| {
        android.get("collapse_key").and_then(serde_json::Value::as_str).map(ToOwned::to_owned)
    });
    Ok(ramflux_node_core::ProviderPushPayload {
        wake_id,
        provider,
        delivery_class,
        priority,
        ttl,
        collapse_key,
        encrypted_hint,
    })
}

#[cfg(all(test, feature = "realnet"))]
const S13_WEBPUSH_SUBSCRIPTION_PRIVATE_KEY_BYTES: [u8; 32] = [7_u8; 32];

#[cfg(all(test, feature = "realnet"))]
const S13_WEBPUSH_AUTH_SECRET: [u8; 16] = *b"ramflux-s13-auth";

#[cfg(all(test, feature = "realnet"))]
fn s13_webpush_subscription_secret() -> Result<p256::SecretKey, Box<dyn std::error::Error>> {
    Ok(p256::SecretKey::from_slice(&S13_WEBPUSH_SUBSCRIPTION_PRIVATE_KEY_BYTES)?)
}

#[cfg(all(test, feature = "realnet"))]
fn s13_webpush_subscription_p256dh() -> Result<String, Box<dyn std::error::Error>> {
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    let secret = s13_webpush_subscription_secret()?;
    let public = secret.public_key();
    Ok(ramflux_protocol::encode_base64url(public.to_encoded_point(false).as_bytes()))
}

#[cfg(all(test, feature = "realnet"))]
fn s13_webpush_subscription_auth() -> String {
    ramflux_protocol::encode_base64url(S13_WEBPUSH_AUTH_SECRET)
}

#[cfg(all(test, feature = "realnet"))]
fn decrypt_s13_webpush_body(body: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use aes_gcm::aead::{Aead, KeyInit};

    if body.len() < 16 + 4 + 1 {
        return Err("webpush body too short".into());
    }
    let salt: [u8; 16] = body[0..16].try_into()?;
    let _record_size = u32::from_be_bytes(body[16..20].try_into()?);
    let key_id_len = usize::from(body[20]);
    let key_start = 21;
    let key_end = key_start + key_id_len;
    if key_id_len != 65 || body.len() <= key_end {
        return Err("invalid webpush key id length".into());
    }
    let server_public_bytes: [u8; 65] = body[key_start..key_end].try_into()?;
    let ciphertext = &body[key_end..];
    let server_public = p256::PublicKey::from_sec1_bytes(&server_public_bytes)?;
    let client_secret = s13_webpush_subscription_secret()?;
    let shared_secret =
        p256::ecdh::diffie_hellman(client_secret.to_nonzero_scalar(), server_public.as_affine());
    let client_public = client_secret.public_key();
    let client_public_bytes = {
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        client_public.to_encoded_point(false)
    };

    let mut key_info = Vec::with_capacity("WebPush: info\0".len() + 65 + 65);
    key_info.extend_from_slice(b"WebPush: info\0");
    key_info.extend_from_slice(client_public_bytes.as_bytes());
    key_info.extend_from_slice(&server_public_bytes);
    let key_hkdf = hkdf::Hkdf::<sha2::Sha256>::new(
        Some(&S13_WEBPUSH_AUTH_SECRET),
        shared_secret.raw_secret_bytes(),
    );
    let mut ikm = [0_u8; 32];
    key_hkdf
        .expand(&key_info, &mut ikm)
        .map_err(|error| format!("webpush key hkdf expand failed: {error:?}"))?;

    let content_hkdf = hkdf::Hkdf::<sha2::Sha256>::new(Some(&salt), &ikm);
    let mut cek = [0_u8; 16];
    content_hkdf
        .expand(b"Content-Encoding: aes128gcm\0", &mut cek)
        .map_err(|error| format!("webpush cek hkdf expand failed: {error:?}"))?;
    let mut nonce = [0_u8; 12];
    content_hkdf
        .expand(b"Content-Encoding: nonce\0", &mut nonce)
        .map_err(|error| format!("webpush nonce hkdf expand failed: {error:?}"))?;
    let cipher = aes_gcm::Aes128Gcm::new(aes_gcm::Key::<aes_gcm::Aes128Gcm>::from_slice(&cek));
    let mut plaintext = cipher
        .decrypt(aes_gcm::Nonce::from_slice(&nonce), ciphertext)
        .map_err(|_| "webpush aes128gcm decrypt failed".to_owned())?;
    match plaintext.pop() {
        Some(0x02) => Ok(plaintext),
        _ => Err("missing webpush final record delimiter".into()),
    }
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) struct S13MockPushProvider {
    pub(crate) addr: std::net::SocketAddr,
    pub(crate) ca_pem: String,
    pub(crate) requests: std::sync::Arc<std::sync::Mutex<Vec<S13MockPushRequest>>>,
    pub(crate) done: std::sync::Arc<std::sync::Condvar>,
    pub(crate) _thread: std::thread::JoinHandle<()>,
}

#[cfg(all(test, feature = "realnet"))]
const S13_EC_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgwyBphzPT6zP0T3HT\nmUd3y/OXm9uWxWxy8nbR0YWA22ShRANCAAQAIpCYq6Tsdeuzzy1sjb/0VLEcd1+r\nQs8681WYx7uSG+akC/YXdlGjSeyiRGjZYJ1KHqoa2d4mAQwi9XAZuDT5\n-----END PRIVATE KEY-----\n";

#[cfg(all(test, feature = "realnet"))]
const S13_RSA_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDaY/75TY51Ab/H\nIZA1AOc1lmYt5cEcQ4w381HI5X+rBtZTf/D7IMKNZo6ElM3u/LQuWD3q3hjO7W3t\nIz3NmSHvuigILaQQNIho7dLIxQQylCChhMwktvIM/T4ZVtBeLjBAYPipWxiUXe3H\nPHpv5HXOX5aKGi3LoJ8B9h0xdj38ufwgIhLPTnJbGyVRzwqbMIGDc9XFr5DXUIO0\nIyvgOq38SObQu7oKaoGQqFCWwBH8ziDbjKSOPBL0cRSo7k6XeUfcqyp1MqCXTz6A\noIa7CSx950oO95K6YBwmzJm9EOC8awc1RiQdHyDaUGQXtdAptaiwmzbdCgeY6iRU\n7bg53/nhAgMBAAECggEAIdZEzwdjZKFQ6lS6yAjr9Ji+cSsReMRwfnTD6F7CoVLt\ntJdJ/6brmJwExemxCe/RJ63Cvi1g5k18RDXlzAFcyYzBdMREO2yK8XMJFH64xUYV\nKOFvUzBIoEGWibeH5lJoEHmAiEDrNdsNzdpYKsEDjbuwEpVhdhTcviGOFA1QJ7lh\n+DLKnDV5iEEvHQjNmRAMbM5jVbpo+yD8V2dNcExc1DTHamlPpFBrYz27Hn/RHRUi\nWJ/i5j6p09s6DW4Dt+ARjELVTGMUd0CTx3pPswrEIWfmmZMfhV8ZZG/Z0Fq+FT55\n6Aoo/tlt33Oa5wKE1I+ASiq5EecVUCmDcaRb3/BvfwKBgQD3J9Pbscqo4R+7rivL\nZYgmITGL2sUcHgt9SxUh5Q60hNQLqcR1GZi9ISyYWqoEeHoU4cOac+SU3fMUbrJY\nLv1OYHU1vzp0NhBcaXsW+M2D64V+PR9dATfdcXGBLm2RibgolEd1D2gq9CaIam//\nc7g/oZ6x/4D1g3TmH9CrlXZERwKBgQDiNKelCnYXWCOKMJ8b4i3jmZ6LyJN3p9hh\nvKs0x2433fvn5m+dPX5wVbkEIKqOqQaKYguKyV6r9qyTsFObZeWnaf18OGhRKcip\nij8K544ZcEZGDrQKs0WDSmydnPktMDSbh06aUjuJf2G2mccnRaCT4UPtphzlYMGH\noJk5H9KslwKBgQC1JNKo5WD0b7NTWe8tLugfkhp/N0NaPUcMeJgvdHNXqTbEqZOc\ng7snewX1UBXmGurXHTTAogo5dYawRgWejioHZLjjQJm2DN3m7URS7N2rv1Xi1SeE\ngd0RBxE6re2OSpLX4v2QdU9SlAkd2GznnEfBE1J9gRdiWgu2kkDdUTkSBwKBgAeX\nCrT/99xqqa6eWQhfe3iyk95O2ZvfNuR4pyn7MxiOy0AJvF8DTDXKuo2H5xEoXL7R\n8V8zyIhum3XNKdECB0WpycacQevPQhtmNx1PjbYOzVzWa3Ycc82m9qQHO1knz+wU\nCzAkaDkB3C57VHJd5Lhxi4zy0O9lYrkBS4LeLXx7AoGAFE3noYLw9uXW9o7RuUow\nnEt8ijaC82HXcMBD9OTxOozV26HhU2YTsp6/JSH/VSzXC5PbayejAuRocMky6sOm\n0Ac+mBda0iIlvUtj7pyPaHY1Wxhkf7h+CjJpNmefknv14+bxwI5QH1gxQNAat+2q\n5bSDXCCQFTOvLxmyvIXiZ2s=\n-----END PRIVATE KEY-----\n";
