// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Public server APIs retain encrypted routes without persisting their decryption key.
use ramflux_node_core::{DevicePushRoute, NodeSecret, NotifyRedbStore, PushProviderKind};
#[test]
fn mounted_route_key_is_required_to_reopen_saved_provider_tokens()
-> Result<(), Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!(
        "rf-srv-data-{}-{}",
        std::process::id(),
        ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
    ));
    std::fs::create_dir(&root)?;
    let path = root.join("notify.redb");
    let key = NodeSecret::ephemeral()?;
    let store = NotifyRedbStore::open_with_route_key(&path, key.clone())?;
    let route = DevicePushRoute {
        device_delivery_id: "opaque-delivery-id".into(),
        provider: PushProviderKind::Fcm,
        credential_id: Some("node-fcm".into()),
        token: "provider-token-private-at-rest".into(),
        endpoint: "https://fcm.googleapis.com:443/v1/projects/project/messages:send".into(),
        webpush_p256dh: None,
        webpush_auth: None,
        registered_at: 100,
        expires_at: 200,
    };
    store.register_push_route(route.clone())?;
    drop(store);
    assert!(
        !std::fs::read(&path)?
            .windows(route.token.len())
            .any(|bytes| bytes == route.token.as_bytes())
    );
    assert!(NotifyRedbStore::open_with_route_key(&path, NodeSecret::ephemeral()?).is_err());
    let store = NotifyRedbStore::open_with_route_key(&path, key)?;
    assert_eq!(
        store.load_state()?.ok_or("route state")?.push_routes("opaque-delivery-id", 100),
        vec![route]
    );
    store.sweep_retention(200)?;
    assert_eq!(
        store.load_state()?.unwrap_or_default().push_routes("opaque-delivery-id", 100).len(),
        0
    );
    drop(store);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
