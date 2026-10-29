// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Attended native data archive fixtures use only the ordinary daemon job methods.
#![cfg(all(test, feature = "realnet"))]
use ramflux_sdk::{
    LocalBusClient,
    backup::{BackupJob, BackupJobState},
};
use serde_json::json;
use std::path::Path;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const ARCHIVE_SECRET: &str = "realnet archive password independent of data";

async fn attend(bus: &mut LocalBusClient) -> Result<()> {
    bus.request(
        None,
        "stream",
        "subscription.open",
        json!({
            "topics":["account.backup.job.changed"],"since_seq":0,"attended_frontend":true
        }),
    )
    .await?;
    Ok(())
}

async fn finished(
    bus: &mut LocalBusClient,
    mut response: serde_json::Value,
    expected: BackupJobState,
) -> Result<BackupJob> {
    let mut row: BackupJob = serde_json::from_value(response["job"].take())?;
    loop {
        if row.state == expected {
            return Ok(row);
        }
        if row.state.terminal() {
            return Err(format!("native archive job failed: {:?}", row.error).into());
        }
        tokio::select! {
            event = bus.next_event() => { event?; }
            () = tokio::time::sleep(std::time::Duration::from_millis(100)) => {}
        }
        let rows = bus.request(None, "account", "account.backup.jobs", json!({})).await?;
        let jobs: Vec<BackupJob> = serde_json::from_value(rows["jobs"].clone())?;
        row =
            jobs.into_iter().find(|next| next.job_id == row.job_id).ok_or("archive job missing")?;
    }
}

pub(crate) async fn create_native_backup(
    bus: &mut LocalBusClient,
    account: &str,
    path: &Path,
) -> Result<()> {
    attend(bus).await?;
    let response = bus
        .request(
            Some(account.into()),
            "account",
            "account.backup.create",
            json!({"output_path":path,"passphrase":ARCHIVE_SECRET}),
        )
        .await?;
    finished(bus, response, BackupJobState::Done).await?;
    Ok(())
}

pub(crate) async fn restore_native_backup(
    bus: &mut LocalBusClient,
    path: &Path,
    new_installation: bool,
) -> Result<String> {
    attend(bus).await?;
    let response = bus
        .request(
            None,
            "account",
            "account.restore.verify",
            json!({"input_path":path,"passphrase":ARCHIVE_SECRET}),
        )
        .await?;
    let verified = finished(bus, response, BackupJobState::Verified).await?;
    let mut body = json!({"job_id":verified.job_id});
    if new_installation {
        body["passphrase"] = super::NATIVE_RESTORED_PASSPHRASE.into();
    }
    let response = bus.request(None, "account", "account.restore.install", body).await?;
    let installed = finished(bus, response, BackupJobState::Done).await?;
    Ok(installed.archive.ok_or("installed archive preview missing")?.local_account_id)
}
