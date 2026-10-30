// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Observe native inbound delivery before exercising the explicit accept path.
#![cfg(all(test, feature = "realnet"))]
use super::NativeAccount;
use ramflux_sdk::LocalBusClient;
use serde::Deserialize;
use std::{fmt, time::Duration};

#[derive(Debug)]
pub(crate) struct PendingContactRequestTimeout {
    receiver: String,
    requester: String,
}

impl fmt::Display for PendingContactRequestTimeout {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "pending inbound contact request from {} did not reach {} within 20 seconds",
            self.requester, self.receiver
        )
    }
}

impl std::error::Error for PendingContactRequestTimeout {}

#[derive(Deserialize)]
struct RequestList {
    requests: Vec<Request>,
}

#[derive(Deserialize)]
struct Request {
    principal_id: String,
    root_commitment: String,
    direction: String,
    state: String,
}

pub(crate) async fn wait_for_pending_native_contact_request(
    receiver: &mut LocalBusClient,
    receiver_account: &str,
    requester: &NativeAccount,
) -> Result<(), Box<dyn std::error::Error>> {
    let delivered = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let response = receiver
                .request(
                    Some(receiver_account.to_owned()),
                    "contact",
                    "contact.requests.list",
                    serde_json::json!({}),
                )
                .await?;
            let list: RequestList = serde_json::from_value(response)?;
            if list.requests.iter().any(|request| {
                request.principal_id == requester.principal_id
                    && request.root_commitment == requester.anchor
                    && request.direction == "inbound"
                    && request.state == "pending"
            }) {
                eprintln!("STEP: pending inbound contact request observed before accept");
                return Ok::<(), Box<dyn std::error::Error>>(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    delivered.map_err(|_| PendingContactRequestTimeout {
        receiver: receiver_account.to_owned(),
        requester: requester.principal_id.clone(),
    })?
}
