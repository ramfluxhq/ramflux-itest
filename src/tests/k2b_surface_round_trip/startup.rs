// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Await an accepting daemon, rather than the existence of its socket file.
use super::{TestResult, waits};
use ramflux_sdk::{LocalBusClient, SdkError};
use std::{io::ErrorKind, path::Path, time::Duration};

pub(super) async fn connect(
    socket: &Path,
    child: &mut tokio::process::Child,
) -> TestResult<LocalBusClient> {
    wait(socket, || {
        if let Some(status) = child.try_wait()? {
            return Err(format!(
                "daemon exited before accepting connections: socket={} status={status}",
                socket.display()
            )
            .into());
        }
        Ok(())
    })
    .await
}

async fn wait(
    socket: &Path,
    mut check_process: impl FnMut() -> TestResult,
) -> TestResult<LocalBusClient> {
    waits::condition(&format!("daemon accepting connections socket={}", socket.display()), async {
        loop {
            check_process()?;
            match LocalBusClient::connect(socket).await {
                Ok(client) => return Ok(client),
                Err(SdkError::Io(error))
                    if matches!(
                        error.kind(),
                        ErrorKind::NotFound | ErrorKind::ConnectionRefused
                    ) =>
                {
                    eprintln!("STEP: k2b daemon socket={} not_ready={error}", socket.display());
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(error) => return Err(error.into()),
            }
        }
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn existing_socket_must_accept_connections_before_startup_completes() -> TestResult {
        let root = crate::temp_root("k2b-socket")?;
        let socket = Path::new("/tmp")
            .join(root.file_name().ok_or("temporary root name")?)
            .with_extension("sock");
        // Dropping a listener leaves a path that exists but refuses connections.
        drop(std::os::unix::net::UnixListener::bind(&socket)?);
        assert!(socket.exists());
        let error = LocalBusClient::connect(&socket)
            .await
            .err()
            .ok_or("stale socket accepted a connection")?;
        assert!(
            matches!(error, SdkError::Io(ref io) if io.kind() == ErrorKind::ConnectionRefused),
            "{error}"
        );
        let server_socket = socket.clone();
        let server = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            std::fs::remove_file(&server_socket)?;
            let listener = tokio::net::UnixListener::bind(server_socket)?;
            let (stream, _) = listener.accept().await?;
            Ok::<_, std::io::Error>(stream)
        });
        waits::WaitBudget::new(tokio::time::Instant::now())
            .run(async {
                let _client = wait(&socket, || Ok(())).await?;
                let _server = server.await??;
                Ok(())
            })
            .await?;
        std::fs::remove_file(socket)?;
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[tokio::test]
    async fn exited_daemon_is_reported_without_retrying_until_the_deadline() -> TestResult {
        let checks = std::cell::Cell::new(0_u8);
        let error = waits::WaitBudget::new(tokio::time::Instant::now())
            .run(async {
                wait(Path::new("/tmp/k2b-no-listener.sock"), || {
                    checks.set(checks.get().saturating_add(1));
                    Err("daemon exited: exit status 1".into())
                })
                .await?;
                Ok(())
            })
            .await
            .err()
            .ok_or("exited daemon was ignored")?;
        assert!(error.to_string().contains("daemon exited"), "{error}");
        assert_eq!(checks.get(), 1);
        Ok(())
    }
}
