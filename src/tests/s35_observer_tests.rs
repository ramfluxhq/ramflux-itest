// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Native socket regressions for S35 observation, RPC isolation, and scoped shutdown.
use super::*;
use ramflux_sdk::{LocalBusFrame, LocalBusFrameKind};
use std::{io::ErrorKind, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
};

async fn read(stream: &mut UnixStream) -> TestResult<LocalBusFrame> {
    let len = stream.read_u32().await?;
    let mut bytes = vec![0; usize::try_from(len)?];
    stream.read_exact(&mut bytes).await?;
    Ok(serde_json::from_slice(&bytes)?)
}
async fn write(stream: &mut UnixStream, frame: &LocalBusFrame) -> TestResult {
    let bytes = serde_json::to_vec(frame)?;
    stream.write_u32(u32::try_from(bytes.len())?).await?;
    stream.write_all(&bytes).await?;
    Ok(())
}
async fn respond(stream: &mut UnixStream, mut frame: LocalBusFrame) -> TestResult {
    frame.kind = LocalBusFrameKind::Response;
    frame.ok = Some(true);
    frame.body = json!({});
    write(stream, &frame).await
}
async fn subscribed(listener: &UnixListener) -> TestResult<UnixStream> {
    let (mut stream, _) = listener.accept().await?;
    let request = read(&mut stream).await?;
    assert_eq!(request.method, "bus.subscribe");
    assert_eq!(request.account_id.as_deref(), Some("bob_s35_account"));
    assert_eq!(request.body, json!({"topics":TOPICS,"since_seq":null}));
    respond(&mut stream, request).await?;
    Ok(stream)
}
async fn assert_closed(stream: &mut UnixStream) -> TestResult {
    let read = tokio::time::timeout(Duration::from_secs(2), stream.read_u8()).await?;
    assert!(read.is_err_and(|error| error.kind() == ErrorKind::UnexpectedEof));
    Ok(())
}
fn event(seq: u64, topic: &str, row: &Value) -> LocalBusFrame {
    let mut frame = LocalBusFrame::request(
        "subscription",
        Some("bob_s35_account".into()),
        "stream",
        topic,
        json!({"message":row}),
    );
    frame.kind = LocalBusFrameKind::Event;
    frame.seq = Some(seq);
    frame
}

#[tokio::test]
async fn drains_during_pending_rpc_and_closes_before_later_rpc() -> TestResult {
    let root = crate::temp_root("s35_observer_burst")?;
    let socket = root.join("bus.sock");
    let listener = UnixListener::bind(&socket)?;
    let server = async {
        let (mut rpc, _) = listener.accept().await?;
        let mut stream = subscribed(&listener).await?;
        let request = read(&mut rpc).await?;
        assert_eq!(request.method, "message.list", "RPC connection must be unsubscribed");
        for seq in 1..=256 {
            let (topic, row) = match seq {
                1 => ("message.received", json!({"original_message_id":"dm"})),
                2 => ("group.message.received", json!({"message_id":"group"})),
                _ => ("message.updated", json!({"message_id":"unrelated"})),
            };
            write(&mut stream, &event(seq, topic, &row)).await?;
            tokio::task::yield_now().await;
        }
        // Hold the command response until all events have been emitted, including 254
        // events after both expected observations. Their consumer must remain active.
        respond(&mut rpc, request).await?;
        assert_closed(&mut stream).await?;
        let later = read(&mut rpc).await?;
        assert_eq!(later.method, "device.sync.import");
        respond(&mut rpc, later).await
    };
    let client = async {
        let mut rpc = LocalBusClient::connect(&socket).await?;
        let (observer, mut rows) = MessageObserver::connect(
            &socket,
            [("original_message_id", "dm"), ("message_id", "group")],
        )
        .await?;
        observer
            .during(async {
                rpc.request(Some("bob_s35_account".into()), "test", "message.list", json!({}))
                    .await?;
                assert_eq!((&mut rows[0]).await?["original_message_id"], "dm");
                assert_eq!((&mut rows[1]).await?["message_id"], "group");
                Ok(())
            })
            .await?;
        rpc.request(Some("bob_s35_account".into()), "test", "device.sync.import", json!({}))
            .await?;
        Ok::<_, Box<dyn Error>>(())
    };
    Box::pin(tokio::time::timeout(Duration::from_secs(10), async {
        let (server, client) = tokio::join!(server, client);
        server?;
        client
    }))
    .await??;
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test]
async fn lagged_stream_fails_pending_work_and_closes_connection() -> TestResult {
    let root = crate::temp_root("s35_observer_lagged")?;
    let socket = root.join("bus.sock");
    let listener = UnixListener::bind(&socket)?;
    let server = async {
        let mut stream = subscribed(&listener).await?;
        write(&mut stream, &event(40, "stream.lagged", &Value::Null)).await?;
        assert_closed(&mut stream).await
    };
    let client = async {
        let (observer, _rows) =
            MessageObserver::connect(&socket, [("id", "dm"), ("id", "group")]).await?;
        let result = observer.during(std::future::pending()).await;
        assert!(result.is_err_and(|error| error.to_string().contains("stream.lagged")));
        Ok::<_, Box<dyn Error>>(())
    };
    tokio::time::timeout(Duration::from_secs(10), async {
        let (server, client) = tokio::join!(server, client);
        server?;
        client
    })
    .await??;
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test]
async fn helper_error_and_cancellation_close_observer_connections() -> TestResult {
    for cancel in [false, true] {
        let root = crate::temp_root("s35_observer_shutdown")?;
        let socket = root.join("bus.sock");
        let listener = UnixListener::bind(&socket)?;
        let server = async {
            let mut stream = subscribed(&listener).await?;
            assert_closed(&mut stream).await
        };
        let client = async {
            let (observer, _rows) =
                MessageObserver::connect(&socket, [("id", "dm"), ("id", "group")]).await?;
            if cancel {
                assert!(
                    tokio::time::timeout(
                        Duration::from_millis(20),
                        observer.during(std::future::pending())
                    )
                    .await
                    .is_err()
                );
            } else {
                let result = observer.during(async { Err("expected helper failure".into()) }).await;
                assert_eq!(
                    result.err().map(|error| error.to_string()).as_deref(),
                    Some("expected helper failure")
                );
            }
            Ok::<_, Box<dyn Error>>(())
        };
        tokio::time::timeout(Duration::from_secs(10), async {
            let (server, client) = tokio::join!(server, client);
            server?;
            client
        })
        .await??;
        std::fs::remove_dir_all(root)?;
    }
    Ok(())
}
