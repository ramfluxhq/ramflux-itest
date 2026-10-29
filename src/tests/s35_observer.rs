// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Scoped message-row observation on a continuously drained, independent bus connection.
use ramflux_sdk::LocalBusClient;
use serde_json::{Value, json};
use std::{error::Error, future::Future, path::Path};
use tokio::{sync::oneshot, task::JoinHandle};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
type Rows = [oneshot::Receiver<Value>; 2];
const TOPICS: [&str; 3] = ["message.received", "group.message.received", "message.updated"];

pub(super) struct MessageObserver {
    worker: JoinHandle<Result<(), String>>,
}
impl MessageObserver {
    pub(super) async fn connect(
        socket: &Path,
        targets: [(&str, &str); 2],
    ) -> TestResult<(Self, Rows)> {
        let mut bus = LocalBusClient::connect(socket).await?;
        bus.request(
            Some("bob_s35_account".into()),
            "owncopy",
            "bus.subscribe",
            json!({"topics":TOPICS,"since_seq":null}),
        )
        .await?;
        let [(first_tx, first_rx), (second_tx, second_rx)] =
            std::array::from_fn(|_| oneshot::channel());
        let targets = targets.map(|(field, id)| (field.to_owned(), id.to_owned()));
        let worker = tokio::spawn(drain(bus, targets, [Some(first_tx), Some(second_tx)]));
        Ok((Self { worker }, [first_rx, second_rx]))
    }

    pub(super) async fn during(mut self, work: impl Future<Output = TestResult>) -> TestResult {
        let result = tokio::select! {
            result = work => result,
            result = &mut self.worker => return Err(worker_error(result)),
        };
        self.worker.abort();
        match (&mut self.worker).await {
            Err(error) if error.is_cancelled() => result,
            outcome => Err(worker_error(outcome)),
        }
    }
}
impl Drop for MessageObserver {
    fn drop(&mut self) {
        // Also cancel on a failed assertion or cancellation of the surrounding test flow.
        self.worker.abort();
    }
}
fn worker_error(outcome: Result<Result<(), String>, tokio::task::JoinError>) -> Box<dyn Error> {
    match outcome {
        Ok(Err(error)) => error.into(),
        Ok(Ok(())) => "s35 message observer stopped unexpectedly".into(),
        Err(error) => format!("s35 message observer task failed: {error}").into(),
    }
}
async fn drain(
    mut bus: LocalBusClient,
    targets: [(String, String); 2],
    mut senders: [Option<oneshot::Sender<Value>>; 2],
) -> Result<(), String> {
    loop {
        let event = bus.next_event().await.map_err(|error| error.to_string())?;
        if event.method == "stream.lagged" {
            return Err(format!("s35 message observer stream.lagged: {}", event.body));
        }
        if !TOPICS.contains(&event.method.as_str()) {
            continue;
        }
        let row = &event.body["message"];
        for ((field, id), sender) in targets.iter().zip(&mut senders) {
            if row[field] == id.as_str()
                && let Some(sender) = sender.take()
            {
                let _ = sender.send(row.clone());
            }
        }
    }
}

#[cfg(test)]
#[path = "s35_observer_tests.rs"]
mod tests;
