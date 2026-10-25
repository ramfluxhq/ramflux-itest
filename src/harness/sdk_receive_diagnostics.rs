// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Bounded receive-failure diagnostics for in-process realnet daemons.
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use tracing::{
    Event, Metadata, Subscriber,
    field::{Field, Visit},
    span::{Attributes, Id, Record},
};

#[derive(Default)]
struct Diagnostics {
    spans: AtomicU64,
    events: AtomicUsize,
}
#[derive(Default)]
struct Fields(BTreeMap<String, String>);
impl Visit for Fields {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if matches!(
            field.name(),
            "message"
                | "error"
                | "reason"
                | "reason_code"
                | "error_code"
                | "envelope_id"
                | "inbox_seq"
                | "source_device_id"
                | "target_delivery_id"
                | "account_id"
                | "local_account_id"
                | "device_id"
        ) {
            self.0.insert(field.name().into(), format!("{value:?}").chars().take(2048).collect());
        }
    }
}
impl Subscriber for Diagnostics {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        *metadata.level() <= tracing::Level::DEBUG
            && (metadata.target().starts_with("ramflux_sdk")
                || metadata.target().starts_with("ramflux_transport"))
    }
    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(self.spans.fetch_add(1, Ordering::Relaxed) + 1)
    }
    fn record(&self, _: &Id, _: &Record<'_>) {}
    fn record_follows_from(&self, _: &Id, _: &Id) {}
    fn enter(&self, _: &Id) {}
    fn exit(&self, _: &Id) {}
    fn event(&self, event: &Event<'_>) {
        if self.events.fetch_add(1, Ordering::Relaxed) >= 512 {
            return;
        }
        let mut fields = Fields::default();
        event.record(&mut fields);
        crate::realnet_step(
            "s47 daemon event",
            serde_json::json!({
                "target":event.metadata().target(),"level":event.metadata().level().as_str(),
                "thread":format!("{:?}",std::thread::current().id()),"fields":fields.0,
            })
            .to_string(),
        );
    }
    fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
        Some(tracing::level_filters::LevelFilter::DEBUG)
    }
}
pub(crate) fn install() {
    if let Err(error) = tracing::subscriber::set_global_default(Diagnostics::default()) {
        crate::realnet_step("s47 daemon logger unavailable", error.to_string());
    }
}
pub(crate) fn response(phase: &str, value: &serde_json::Value) {
    crate::realnet_step(
        "s47 receive response",
        format!(
            "phase={phase} response={}",
            value.to_string().chars().take(32768).collect::<String>()
        ),
    );
}
pub(crate) async fn failure_state(bus: &mut ramflux_sdk::LocalBusClient, account: &str) {
    for (service, method, body) in [
        ("sync", "sync.status.get", serde_json::json!({})),
        ("contact", "contact.list", serde_json::json!({"limit":10})),
        (
            "message",
            "message.list",
            serde_json::json!({"conversation_id":"conv_s47_bob_alice","limit":10}),
        ),
    ] {
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            bus.request(Some(account.into()), service, method, body),
        )
        .await;
        let text = match result {
            Ok(Ok(value)) => value.to_string(),
            Ok(Err(error)) => format!("bus error: {error}"),
            Err(_) => "diagnostic timeout".into(),
        };
        crate::realnet_step(
            "s47 restored daemon state",
            format!("method={method} response={}", text.chars().take(32768).collect::<String>()),
        );
    }
}
