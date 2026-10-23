// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Bounded client-facing relay QUIC readiness for object transport fixtures.
use crate::realnet_step;
use std::future::Future;
use std::path::Path;
use std::time::{Duration, Instant};

const MAX_ATTEMPTS: u32 = 30;
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);
const RETRY_DELAY: Duration = Duration::from_secs(2);

pub(crate) async fn wait_relay_quic_healthy(
    peer_addr: &str,
    server_name: &str,
    ca_cert: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = ramflux_transport::RelayClientQuicConfig::new(peer_addr, server_name, ca_cert)?;
    let context =
        format!("addr={peer_addr} server_name={server_name} ca_cert={}", ca_cert.display());
    wait_with_probe(
        &context,
        |timeout| {
            let config = &config;
            async move {
                ramflux_transport::relay_client_quic_health(config, timeout)
                    .await
                    .map(|health| health.status)
                    .map_err(|error| error.to_string())
            }
        },
        tokio::time::sleep,
    )
    .await
}

async fn wait_with_probe<Probe, ProbeFuture, Pause, PauseFuture>(
    context: &str,
    mut probe: Probe,
    mut pause: Pause,
) -> Result<(), Box<dyn std::error::Error>>
where
    Probe: FnMut(Duration) -> ProbeFuture,
    ProbeFuture: Future<Output = Result<u16, String>>,
    Pause: FnMut(Duration) -> PauseFuture,
    PauseFuture: Future<Output = ()>,
{
    let started = Instant::now();
    let mut last_error = String::new();
    for attempt in 1..=MAX_ATTEMPTS {
        realnet_step(
            "relay QUIC readiness probe begin",
            format!(
                "{context} attempt={attempt}/{MAX_ATTEMPTS} timeout_ms={} elapsed_ms={}",
                PROBE_TIMEOUT.as_millis(),
                started.elapsed().as_millis()
            ),
        );
        match probe(PROBE_TIMEOUT).await {
            Ok(200) => {
                realnet_step(
                    "relay QUIC readiness healthy",
                    format!(
                        "{context} attempt={attempt}/{MAX_ATTEMPTS} elapsed_ms={}",
                        started.elapsed().as_millis()
                    ),
                );
                return Ok(());
            }
            Ok(status) => last_error = format!("health status {status}"),
            Err(error) => last_error = error,
        }
        realnet_step(
            "relay QUIC readiness probe failed",
            format!(
                "{context} attempt={attempt}/{MAX_ATTEMPTS} elapsed_ms={} retry_delay_ms={} error={last_error}",
                started.elapsed().as_millis(),
                RETRY_DELAY.as_millis()
            ),
        );
        // Preserve the existing s62 policy, including its delay after the final failed attempt.
        pause(RETRY_DELAY).await;
    }
    realnet_step(
        "relay QUIC readiness exhausted",
        format!(
            "{context} attempts={MAX_ATTEMPTS} elapsed_ms={} error={last_error}",
            started.elapsed().as_millis()
        ),
    );
    Err(format!("relay client QUIC did not become healthy after {MAX_ATTEMPTS} attempts ({context}); last error: {last_error}").into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn readiness_stops_immediately_on_a_healthy_response()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut attempts = 0;
        let mut delays = Vec::new();
        wait_with_probe(
            "immediate readiness fixture",
            |timeout| {
                assert_eq!(timeout, Duration::from_secs(3));
                attempts += 1;
                std::future::ready(Ok(200))
            },
            |delay| {
                delays.push(delay);
                std::future::ready(())
            },
        )
        .await?;
        assert_eq!(attempts, 1);
        assert_eq!(delays, [] as [Duration; 0]);
        Ok(())
    }

    #[tokio::test]
    async fn readiness_retries_transport_errors_and_nonhealthy_responses()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut attempts = 0;
        let mut delays = Vec::new();
        wait_with_probe(
            "delayed readiness fixture",
            |timeout| {
                assert_eq!(timeout, Duration::from_secs(3));
                attempts += 1;
                std::future::ready(match attempts {
                    1 => Err("connection lost".to_owned()),
                    2 => Ok(503),
                    _ => Ok(200),
                })
            },
            |delay| {
                delays.push(delay);
                std::future::ready(())
            },
        )
        .await?;
        assert_eq!(attempts, 3);
        assert_eq!(delays, vec![Duration::from_secs(2); 2]);
        Ok(())
    }

    #[tokio::test]
    async fn readiness_exhaustion_preserves_bounds_and_last_error()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut attempts = 0;
        let mut delays = Vec::new();
        let result = wait_with_probe(
            "unreachable readiness fixture",
            |timeout| {
                assert_eq!(timeout, Duration::from_secs(3));
                attempts += 1;
                std::future::ready(Err(format!("connection lost at attempt {attempts}")))
            },
            |delay| {
                delays.push(delay);
                std::future::ready(())
            },
        )
        .await;
        assert_eq!(attempts, 30);
        assert_eq!(delays, vec![Duration::from_secs(2); 30]);
        let error = result.err().ok_or("an unreachable relay must fail readiness")?.to_string();
        assert!(error.contains("after 30 attempts"));
        assert!(error.contains("connection lost at attempt 30"));
        Ok(())
    }
}
