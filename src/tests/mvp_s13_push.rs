// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use super::*;

#[cfg(feature = "realnet")]
const S27_TOTAL_WAKES: usize = 2_000;
#[cfg(feature = "realnet")]
const S27_DEVICE_CARDINALITY: usize = 128;
#[cfg(feature = "realnet")]
const S27_ROUTE_COUNT: usize = 2;
#[cfg(feature = "realnet")]
const S27_EXPECTED_PUSHES: usize = S27_TOTAL_WAKES * S27_ROUTE_COUNT;

#[cfg(feature = "realnet")]
#[test]
fn mvp_s13_realnet_push_provider_wake_bridge() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    let realnet = start_realnet_compose()?;
    let code_root = code_root();
    let ca_cert = code_root.join("ramflux-deploy/certs/ca.pem");
    let gateway_quic_addr: std::net::SocketAddr = std::env::var("RAMFLUX_ITEST_GATEWAY_QUIC_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:18443".to_owned())
        .parse()?;
    let router_url = std::env::var("RAMFLUX_ITEST_ROUTER_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:18080".to_owned());
    wait_for_itest_service(&router_url, "router")?;
    mvp_s1_register_identity(&router_url)?;
    let mock = S13MockPushProvider::start(2)?;
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async {
        Box::pin(mvp_s13_assert_push_provider_wake_bridge(
            gateway_quic_addr,
            &ca_cert,
            &realnet.notify_url,
            &mock,
        ))
        .await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    drop(mock);
    drop(realnet);
    Ok(())
}

#[cfg(feature = "realnet")]
#[test]
fn mvp_s13_realnet_compio_notify_push_provider_wake_bridge()
-> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }
    if std::env::var("RAMFLUX_NOTIFY_COMPIO").as_deref() != Ok("1") {
        eprintln!("skipping compio notify realnet test; set RAMFLUX_NOTIFY_COMPIO=1");
        return Ok(());
    }

    let realnet = start_realnet_compose_with_env_and_notify_compio(&[], true)?;
    let code_root = code_root();
    let ca_cert = code_root.join("ramflux-deploy/certs/ca.pem");
    let gateway_quic_addr: std::net::SocketAddr = std::env::var("RAMFLUX_ITEST_GATEWAY_QUIC_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:18443".to_owned())
        .parse()?;
    let router_url = std::env::var("RAMFLUX_ITEST_ROUTER_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:18080".to_owned());
    wait_for_itest_service(&router_url, "router")?;
    mvp_s1_register_identity(&router_url)?;
    let mock = S13MockPushProvider::start(2)?;
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async {
        Box::pin(mvp_s13_assert_push_provider_wake_bridge(
            gateway_quic_addr,
            &ca_cert,
            &realnet.notify_url,
            &mock,
        ))
        .await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    drop(mock);
    drop(realnet);
    Ok(())
}

#[cfg(feature = "realnet")]
#[test]
fn mvp_s28_realnet_notify_soak() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }
    if std::env::var("RAMFLUX_SOAK").as_deref() != Ok("1") {
        eprintln!("skipping notify soak test; set RAMFLUX_SOAK=1");
        return Ok(());
    }

    let settings = notify_soak_settings()?;

    let notify_env = vec![
        ("RAMFLUX_NOTIFY_WAL".to_owned(), "1".to_owned()),
        ("RAMFLUX_NOTIFY_ASYNC_ACCEPT".to_owned(), "1".to_owned()),
        ("RAMFLUX_NOTIFY_ASYNC_INGRESS".to_owned(), "1".to_owned()),
    ];
    let realnet = start_realnet_compose_with_env(&notify_env)?;
    let mock = S13MockPushProvider::start(settings.mock_capacity_pushes)?;
    let plan = NotifyFanoutPerfPlan {
        concurrency: vec![1],
        total_wakes: settings.mock_capacity_wakes,
        route_count: S27_ROUTE_COUNT,
        device_cardinality: settings.device_cardinality,
        provider_delay_ms: 0,
        http_timeout_secs: 120,
        max_error_rate: 0.0,
        async_accept: true,
        pipeline_depth: 1,
        client_workers: 1,
        skip_delivery: false,
    };
    register_notify_perf_routes(&realnet.notify_url, &mock, &plan)?;

    let mut client = NotifyPerfKeepAliveClient::new(
        &format!("{}/s13/notify/wake", realnet.notify_url),
        Duration::from_secs(plan.http_timeout_secs),
    )?;
    let interval = Duration::from_secs_f64(1.0 / notify_perf_usize_to_f64(settings.wakes_per_sec));
    let health_interval = Duration::from_secs(settings.health_interval_secs);
    let started = std::time::Instant::now();
    let mut next_health = started + health_interval;
    let mut last_push_count = 0_usize;
    let mut expected_wakes = std::collections::BTreeSet::new();
    let soak_deadline = started + Duration::from_secs(settings.soak_secs);
    let mut wake_index = 0_usize;

    while std::time::Instant::now() < soak_deadline {
        let response = submit_notify_perf_wake(&mut client, &plan, wake_index)?;
        assert!(!response.queue_id.is_empty(), "notify soak wake returned empty queue id");
        expected_wakes.insert(format!("wake_notify_perf_{wake_index:06}"));

        let now = std::time::Instant::now();
        if now >= next_health {
            assert_notify_soak_health(&realnet.notify_url)?;
            let push_count = s13_mock_push_count(&mock)?;
            assert!(
                push_count >= last_push_count,
                "notify soak mock push count regressed: previous={last_push_count} current={push_count}"
            );
            assert!(
                push_count > last_push_count || wake_index + 1 < settings.wakes_per_sec,
                "notify soak delivery did not advance between health checks: push_count={push_count}"
            );
            last_push_count = push_count;
            eprintln!(
                "RAMFLUX_NOTIFY_SOAK_PROGRESS elapsed_secs={} submitted={} delivered={}",
                started.elapsed().as_secs(),
                wake_index + 1,
                push_count
            );
            next_health += health_interval;
        }

        let target_elapsed = interval.mul_f64(notify_perf_usize_to_f64(wake_index + 1));
        let elapsed = started.elapsed();
        if let Some(remaining) = target_elapsed.checked_sub(elapsed) {
            std::thread::sleep(remaining);
        }
        wake_index = wake_index.saturating_add(1);
    }

    assert_notify_soak_health(&realnet.notify_url)?;
    let delivery_timeout =
        Duration::from_secs(notify_perf_env_u64("RAMFLUX_SOAK_DELIVERY_TIMEOUT_SECS", 120)?);
    let actual_submitted = expected_wakes.len();
    let expected_pushes = actual_submitted
        .checked_mul(S27_ROUTE_COUNT)
        .ok_or("notify soak actual expected push count overflow")?;
    let requests = wait_for_s27_mock_push_requests(&mock, expected_pushes, delivery_timeout)?;
    assert_s27_wakes_delivered_exactly_once(&requests, &expected_wakes);
    assert_notify_soak_logs_clean()?;
    eprintln!(
        "RAMFLUX_NOTIFY_SOAK_OK submitted={} delivered={} target_wakes={} elapsed_secs={}",
        actual_submitted,
        requests.len(),
        settings.theoretical_wakes,
        started.elapsed().as_secs()
    );
    drop(mock);
    drop(realnet);
    Ok(())
}

#[cfg(feature = "realnet")]
struct NotifySoakSettings {
    soak_secs: u64,
    wakes_per_sec: usize,
    health_interval_secs: u64,
    device_cardinality: usize,
    theoretical_wakes: usize,
    mock_capacity_wakes: usize,
    mock_capacity_pushes: usize,
}

#[cfg(feature = "realnet")]
fn notify_soak_settings() -> Result<NotifySoakSettings, Box<dyn std::error::Error>> {
    let soak_secs = notify_perf_env_u64("RAMFLUX_SOAK_SECS", 600)?.max(1);
    let wakes_per_sec = notify_perf_env_usize("RAMFLUX_SOAK_WAKES_PER_SEC", 100)?.max(1);
    let health_interval_secs = notify_perf_env_u64("RAMFLUX_SOAK_HEALTH_INTERVAL_SECS", 30)?.max(1);
    let device_cardinality = notify_perf_env_usize("RAMFLUX_SOAK_DEVICE_CARDINALITY", 128)?.max(1);
    let theoretical_wakes = usize::try_from(soak_secs)?
        .checked_mul(wakes_per_sec)
        .ok_or("notify soak wake count overflow")?;
    let mock_capacity_wakes =
        theoretical_wakes.checked_add(wakes_per_sec).ok_or("notify soak mock capacity overflow")?;
    let mock_capacity_pushes = mock_capacity_wakes
        .checked_mul(S27_ROUTE_COUNT)
        .ok_or("notify soak mock push capacity overflow")?;
    Ok(NotifySoakSettings {
        soak_secs,
        wakes_per_sec,
        health_interval_secs,
        device_cardinality,
        theoretical_wakes,
        mock_capacity_wakes,
        mock_capacity_pushes,
    })
}

#[cfg(feature = "realnet")]
#[test]
fn mvp_s27_realnet_notify_shard_wal_crash_recovery() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    let notify_env = vec![
        ("RAMFLUX_NOTIFY_WAL".to_owned(), "1".to_owned()),
        ("RAMFLUX_NOTIFY_WAL_RAW_ENQUEUE".to_owned(), "1".to_owned()),
        ("RAMFLUX_NOTIFY_ASYNC_ACCEPT".to_owned(), "1".to_owned()),
        ("RAMFLUX_NOTIFY_ASYNC_INGRESS".to_owned(), "1".to_owned()),
        ("RAMFLUX_NOTIFY_INGEST_SHARDS".to_owned(), "4".to_owned()),
        // Keep the first process from racing delivery before the kill-9 cut.
        // On restart the queue is already non-empty, so workers scan and deliver immediately.
        ("RAMFLUX_NOTIFY_ASYNC_DELIVERY_IDLE_SLEEP_MS".to_owned(), "60000".to_owned()),
    ];
    let deploy_root = code_root().join("ramflux-deploy");
    let realnet = start_realnet_compose_with_env(&notify_env)?;
    // Sized for the 2000 recovered wakes (x ROUTE_COUNT) plus the one fresh
    // post-restart wake (x ROUTE_COUNT); the mock stops accepting once it has
    // recorded its expected count, so it must include the final wake's pushes.
    let mock = S13MockPushProvider::start(S27_EXPECTED_PUSHES + S27_ROUTE_COUNT)?;
    mvp_s13_register_provider_credentials(&realnet.notify_url, &mock)?;
    for device_index in 0..S27_DEVICE_CARDINALITY {
        let device_id = notify_perf_device_id(device_index);
        mvp_s13_register_push_route(
            &realnet.notify_url,
            ramflux_node_core::PushProviderKind::WebPush,
            "s13-webpush",
            &device_id,
            &format!("webpush-token-s27-{device_index}"),
            &mock.container_url("/webpush"),
        )?;
        mvp_s13_register_push_route(
            &realnet.notify_url,
            ramflux_node_core::PushProviderKind::Fcm,
            "s13-fcm",
            &device_id,
            &format!("fcm-token-s27-{device_index}"),
            &mock.container_url("/fcm"),
        )?;
    }

    let plan = NotifyFanoutPerfPlan {
        concurrency: vec![1],
        total_wakes: S27_TOTAL_WAKES,
        route_count: S27_ROUTE_COUNT,
        device_cardinality: S27_DEVICE_CARDINALITY,
        provider_delay_ms: 0,
        http_timeout_secs: 120,
        max_error_rate: 0.0,
        async_accept: true,
        pipeline_depth: 1,
        client_workers: 1,
        skip_delivery: false,
    };
    let mut expected_wakes = std::collections::BTreeSet::new();
    for wake_index in 0..S27_TOTAL_WAKES {
        let request = notify_perf_wake_request(&plan, wake_index)?;
        let response: serde_json::Value = ramflux_node_core::itest_http_post_json(
            &format!("{}/s13/notify/wake", realnet.notify_url),
            &request,
        )?;
        let durable_queue_id = response
            .get("queue_id")
            .or_else(|| response.get("entry").and_then(|entry| entry.get("queue_id")))
            .and_then(serde_json::Value::as_str);
        assert!(
            durable_queue_id.is_some(),
            "S27 wake did not return durable queue_id: {response:?}"
        );
        expected_wakes.insert(format!("wake_notify_perf_{wake_index:06}"));
    }

    realnet_step("kill notify for S27 WAL recovery", "service=ramflux-notify signal=KILL");
    run_docker_compose_with_env_and_overrides(
        &deploy_root,
        &notify_env,
        &["kill", "-s", "KILL", "ramflux-notify"],
        false,
        false,
        false,
    )?;
    // kill -s KILL leaves the container exited (not removed); `up -d` would hit a
    // name conflict. `start` restarts the same exited container with its WAL/redb
    // volumes intact -- the faithful "process crashed, restart" that triggers
    // per-shard WAL recovery.
    run_docker_compose_with_env_and_overrides(
        &deploy_root,
        &notify_env,
        &["start", "ramflux-notify"],
        false,
        false,
        false,
    )?;
    wait_for_itest_service(&realnet.notify_url, "notify")?;

    let requests =
        wait_for_s27_mock_push_requests(&mock, S27_EXPECTED_PUSHES, Duration::from_mins(1))?;
    assert_s27_wakes_delivered_exactly_once(&requests, &expected_wakes);
    let new_wake_index = S27_TOTAL_WAKES;
    let new_request = notify_perf_wake_request(&plan, new_wake_index)?;
    let _response: serde_json::Value = ramflux_node_core::itest_http_post_json(
        &format!("{}/s13/notify/wake", realnet.notify_url),
        &new_request,
    )?;
    let new_wake_id = format!("wake_notify_perf_{new_wake_index:06}");
    wait_for_s27_wake_delivery(&mock, &new_wake_id, Duration::from_secs(10))?;
    drop(mock);
    drop(realnet);
    Ok(())
}

#[cfg(feature = "realnet")]
#[test]
fn mvp_s13_perf_realnet_notify_fanout_load() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }
    if std::env::var("RAMFLUX_ITEST_PERF").as_deref() != Ok("1") {
        eprintln!("skipping notify fanout perf test; set RAMFLUX_ITEST_PERF=1");
        return Ok(());
    }

    let plan = NotifyFanoutPerfPlan::from_env()?;
    let runtime = notify_perf_runtime_from_env();
    let notify_compio = runtime == "compio";
    let notify_tokio_concurrent = runtime == "tokio-concurrent";
    let mut notify_env = Vec::new();
    if plan.async_accept {
        notify_env.push(("RAMFLUX_NOTIFY_ASYNC_ACCEPT".to_owned(), "1".to_owned()));
    } else {
        notify_env.push(("RAMFLUX_NOTIFY_ASYNC_ACCEPT".to_owned(), "0".to_owned()));
    }
    // Forward async-ingress + its worker count into the notify container so the
    // perf path can exercise the tokio async server that feeds the group-commit
    // writer concurrently (default stays the blocking thread-pool server).
    if std::env::var("RAMFLUX_NOTIFY_ASYNC_INGRESS").as_deref() == Ok("1") {
        notify_env.push(("RAMFLUX_NOTIFY_ASYNC_INGRESS".to_owned(), "1".to_owned()));
        if let Ok(workers) = std::env::var("RAMFLUX_NOTIFY_ASYNC_INGRESS_WORKERS") {
            notify_env.push(("RAMFLUX_NOTIFY_ASYNC_INGRESS_WORKERS".to_owned(), workers));
        }
    }
    // Forward the Tier0 WAL hot-queue toggle (+ its dir) into the notify
    // container so the perf path can exercise the append-only WAL instead of
    // the redb queue. Default (unset) keeps the redb path.
    if std::env::var("RAMFLUX_NOTIFY_WAL").as_deref() == Ok("1") {
        notify_env.push(("RAMFLUX_NOTIFY_WAL".to_owned(), "1".to_owned()));
        let wal_dir = std::env::var("RAMFLUX_NOTIFY_WAL_DIR")
            .unwrap_or_else(|_| "/tmp/ramflux-notify-wal".to_owned());
        notify_env.push(("RAMFLUX_NOTIFY_WAL_DIR".to_owned(), wal_dir));
    }
    let realnet = start_realnet_compose_with_env_and_notify_overrides(
        &notify_env,
        notify_compio,
        notify_tokio_concurrent,
    )?;
    let expected_pushes = plan.total_wakes.saturating_mul(plan.route_count);
    let mock =
        S13MockPushProvider::start_with_delay(expected_pushes, plan.provider_delay_duration())?;
    register_notify_perf_routes(&realnet.notify_url, &mock, &plan)?;
    let artifact = notify_perf_artifact_path("mvp_s13_notify_fanout_load_latest.json")?;
    let mut stages = Vec::with_capacity(plan.concurrency.len());
    write_notify_perf_artifact(&artifact, &runtime, &plan, &stages)?;
    for concurrency in &plan.concurrency {
        let stage =
            run_notify_fanout_perf_stage(&realnet.notify_url, &plan, *concurrency, &runtime);
        eprintln!("RAMFLUX_PERF_STAGE {}", serde_json::to_string(&stage)?);
        stages.push(stage);
        write_notify_perf_artifact(&artifact, &runtime, &plan, &stages)?;
    }
    eprintln!("mvp_s13 notify fanout perf artifact={}", artifact.display());
    enforce_notify_fanout_error_rate(&plan, &stages)?;
    drop(mock);
    drop(realnet);
    Ok(())
}

#[cfg(feature = "realnet")]
#[derive(Clone, Debug, serde::Serialize)]
struct NotifyFanoutPerfPlan {
    concurrency: Vec<usize>,
    total_wakes: usize,
    route_count: usize,
    device_cardinality: usize,
    provider_delay_ms: u64,
    http_timeout_secs: u64,
    max_error_rate: f64,
    async_accept: bool,
    pipeline_depth: usize,
    client_workers: usize,
    skip_delivery: bool,
}

#[cfg(feature = "realnet")]
impl NotifyFanoutPerfPlan {
    fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        let concurrency = notify_perf_env_usize_list("RAMFLUX_NOTIFY_PERF_CONCURRENCY", &[48])?;
        let total_wakes = notify_perf_env_usize("RAMFLUX_NOTIFY_PERF_TOTAL_WAKES", 200)?;
        let route_count = notify_perf_env_usize("RAMFLUX_NOTIFY_PERF_ROUTE_COUNT", 8)?;
        let device_cardinality =
            notify_perf_env_usize("RAMFLUX_NOTIFY_PERF_DEVICE_CARDINALITY", 64)?;
        let provider_delay_ms = notify_perf_env_u64("RAMFLUX_NOTIFY_PERF_PROVIDER_DELAY_MS", 25)?;
        let http_timeout_secs = notify_perf_env_u64("RAMFLUX_NOTIFY_PERF_HTTP_TIMEOUT_SECS", 120)?;
        let max_error_rate = notify_perf_env_f64("RAMFLUX_NOTIFY_PERF_MAX_ERROR_RATE", 0.05)?;
        let async_accept = notify_perf_default_enabled_env("RAMFLUX_NOTIFY_PERF_ASYNC");
        let pipeline_depth =
            notify_perf_env_usize("RAMFLUX_NOTIFY_PERF_PIPELINE_DEPTH", 64)?.max(1);
        let client_workers = notify_perf_env_usize(
            "RAMFLUX_NOTIFY_PERF_CLIENT_WORKERS",
            std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get),
        )?
        .max(1);
        let skip_delivery =
            std::env::var("RAMFLUX_NOTIFY_PERF_SKIP_DELIVERY").as_deref() == Ok("1");
        Ok(Self {
            concurrency,
            total_wakes: total_wakes.max(1),
            route_count: route_count.max(1),
            device_cardinality: device_cardinality.max(1),
            provider_delay_ms,
            http_timeout_secs,
            max_error_rate,
            async_accept,
            pipeline_depth,
            client_workers,
            skip_delivery,
        })
    }

    fn provider_delay_duration(&self) -> Duration {
        Duration::from_millis(self.provider_delay_ms)
    }
}

#[cfg(feature = "realnet")]
#[derive(Clone, Debug, serde::Serialize)]
struct NotifyFanoutPerfStageReport {
    runtime: String,
    concurrency: usize,
    total_wakes: usize,
    route_count: usize,
    device_cardinality: usize,
    provider_delay_ms: u64,
    http_timeout_secs: u64,
    max_error_rate: f64,
    async_accept: bool,
    pipeline_depth: usize,
    client_workers: usize,
    skip_delivery: bool,
    successful_wakes: usize,
    provider_attempts: usize,
    provider_accepted: usize,
    provider_errors: usize,
    elapsed_ms: u128,
    wake_per_sec: f64,
    enqueue_wake_per_sec: f64,
    provider_push_per_sec: f64,
    delivery_push_per_sec: f64,
    delivery_elapsed_ms: u128,
    error_rate: f64,
    p50_us: u128,
    p95_us: u128,
    p99_us: u128,
    provider_accepted_by_kind: std::collections::BTreeMap<String, usize>,
    transport_errors: usize,
    correctness_errors: usize,
    sample_error: Option<String>,
}

#[cfg(feature = "realnet")]
#[derive(Debug)]
enum NotifyFanoutPerfMessage {
    Success(NotifyFanoutPerfResult),
    Error(String),
}

#[cfg(feature = "realnet")]
#[derive(Debug)]
struct NotifyFanoutPerfResult {
    queue_id: String,
    latency_us: u128,
    attempts: Vec<ramflux_node_core::ProviderPushAttempt>,
}

#[cfg(feature = "realnet")]
#[derive(serde::Deserialize)]
struct NotifyFanoutPerfWakeResponse {
    entry: ramflux_node_core::NotifyQueueEntry,
    attempts: Vec<ramflux_node_core::ProviderPushAttempt>,
}

#[cfg(feature = "realnet")]
fn register_notify_perf_routes(
    notify_url: &str,
    mock: &S13MockPushProvider,
    plan: &NotifyFanoutPerfPlan,
) -> Result<(), Box<dyn std::error::Error>> {
    mvp_s13_register_provider_credentials(notify_url, mock)?;
    for device_index in 0..plan.device_cardinality {
        let device_delivery_id = notify_perf_device_id(device_index);
        for route_index in 0..plan.route_count {
            let provider = if route_index % 2 == 0 {
                ramflux_node_core::PushProviderKind::WebPush
            } else {
                ramflux_node_core::PushProviderKind::Fcm
            };
            let (credential_id, endpoint_path) = match provider {
                ramflux_node_core::PushProviderKind::WebPush => ("s13-webpush", "/webpush"),
                ramflux_node_core::PushProviderKind::Fcm => ("s13-fcm", "/fcm"),
                ramflux_node_core::PushProviderKind::Apns => ("s13-apns", "/apns"),
            };
            let token = format!("notify-perf-token-{device_index}-{route_index}");
            mvp_s13_register_push_route(
                notify_url,
                provider,
                credential_id,
                &device_delivery_id,
                &token,
                &mock.container_url(endpoint_path),
            )?;
        }
    }
    Ok(())
}

#[cfg(feature = "realnet")]
fn run_notify_fanout_perf_stage(
    notify_url: &str,
    plan: &NotifyFanoutPerfPlan,
    concurrency: usize,
    runtime: &str,
) -> NotifyFanoutPerfStageReport {
    let concurrency = concurrency.max(1);
    let started = std::time::Instant::now();
    let (mut results, mut errors) = if plan.async_accept {
        run_notify_fanout_perf_async_client_stage(notify_url, plan, concurrency)
    } else {
        run_notify_fanout_perf_blocking_client_stage(notify_url, plan, concurrency)
    };
    let elapsed = started.elapsed();
    emit_notify_enqueue_stage(plan, concurrency, runtime, &results, &errors, elapsed);
    let delivery_started = std::time::Instant::now();
    let delivery_elapsed = if plan.async_accept && !plan.skip_delivery {
        let queue_ids = results.iter().map(|result| result.queue_id.clone()).collect::<Vec<_>>();
        match poll_notify_perf_provider_attempts(notify_url, &queue_ids, plan) {
            Ok(attempts_by_queue) => {
                for result in &mut results {
                    result.attempts =
                        attempts_by_queue.get(&result.queue_id).cloned().unwrap_or_default();
                }
            }
            Err(error) => errors.push(error.to_string()),
        }
        delivery_started.elapsed()
    } else {
        elapsed
    };
    let observations = NotifyFanoutStageObservations {
        elapsed,
        delivery_elapsed,
        results: &results,
        errors: &errors,
    };
    notify_fanout_stage_report(plan, concurrency, &observations, runtime)
}

#[cfg(feature = "realnet")]
fn emit_notify_enqueue_stage(
    plan: &NotifyFanoutPerfPlan,
    concurrency: usize,
    runtime: &str,
    results: &[NotifyFanoutPerfResult],
    errors: &[String],
    elapsed: Duration,
) {
    let elapsed_secs = elapsed.as_secs_f64().max(0.001);
    let enqueue_wake_per_sec = notify_perf_usize_to_f64(results.len()) / elapsed_secs;
    let total_observed = results.len() + errors.len();
    let error_rate = if total_observed == 0 {
        0.0
    } else {
        notify_perf_usize_to_f64(errors.len()) / notify_perf_usize_to_f64(total_observed)
    };
    let stage = serde_json::json!({
        "runtime": runtime,
        "concurrency": concurrency,
        "total_wakes": plan.total_wakes,
        "successful_wakes": results.len(),
        "transport_errors": errors.len(),
        "elapsed_ms": elapsed.as_millis(),
        "enqueue_wake_per_sec": enqueue_wake_per_sec,
        "error_rate": error_rate,
        "async_accept": plan.async_accept,
        "pipeline_depth": plan.pipeline_depth,
        "client_workers": plan.client_workers,
        "skip_delivery": plan.skip_delivery,
        "sample_error": errors.first(),
    });
    eprintln!("RAMFLUX_NOTIFY_ENQUEUE_STAGE {stage}");
}

#[cfg(feature = "realnet")]
fn run_notify_fanout_perf_blocking_client_stage(
    notify_url: &str,
    plan: &NotifyFanoutPerfPlan,
    concurrency: usize,
) -> (Vec<NotifyFanoutPerfResult>, Vec<String>) {
    let next_wake = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (sender, receiver) = std::sync::mpsc::channel::<NotifyFanoutPerfMessage>();
    let mut workers = Vec::with_capacity(concurrency);
    for _worker_index in 0..concurrency {
        workers.push(spawn_notify_fanout_perf_worker(
            sender.clone(),
            std::sync::Arc::clone(&next_wake),
            notify_url.to_owned(),
            plan.clone(),
        ));
    }
    drop(sender);
    let mut results = Vec::with_capacity(plan.total_wakes);
    let mut errors = Vec::new();
    for message in receiver {
        match message {
            NotifyFanoutPerfMessage::Success(result) => results.push(result),
            NotifyFanoutPerfMessage::Error(error) => errors.push(error),
        }
    }
    for worker in workers {
        if worker.join().is_err() {
            errors.push("notify perf worker panicked".to_owned());
        }
    }
    (results, errors)
}

#[cfg(feature = "realnet")]
fn run_notify_fanout_perf_async_client_stage(
    notify_url: &str,
    plan: &NotifyFanoutPerfPlan,
    concurrency: usize,
) -> (Vec<NotifyFanoutPerfResult>, Vec<String>) {
    match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(plan.client_workers)
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime.block_on(run_notify_fanout_perf_async_client_stage_inner(
            notify_url.to_owned(),
            plan.clone(),
            concurrency,
        )),
        Err(error) => (Vec::new(), vec![format!("notify async perf client runtime: {error}")]),
    }
}

#[cfg(feature = "realnet")]
async fn run_notify_fanout_perf_async_client_stage_inner(
    notify_url: String,
    plan: NotifyFanoutPerfPlan,
    concurrency: usize,
) -> (Vec<NotifyFanoutPerfResult>, Vec<String>) {
    let next_wake = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut handles = Vec::with_capacity(concurrency);
    for _worker_index in 0..concurrency {
        let worker_next_wake = std::sync::Arc::clone(&next_wake);
        let worker_notify_url = notify_url.clone();
        let worker_plan = plan.clone();
        handles.push(tokio::spawn(async move {
            run_notify_fanout_perf_async_worker(worker_notify_url, worker_plan, worker_next_wake)
                .await
        }));
    }
    let mut results = Vec::with_capacity(plan.total_wakes);
    let mut errors = Vec::new();
    for handle in handles {
        match handle.await {
            Ok(messages) => {
                for message in messages {
                    match message {
                        NotifyFanoutPerfMessage::Success(result) => results.push(result),
                        NotifyFanoutPerfMessage::Error(error) => errors.push(error),
                    }
                }
            }
            Err(error) => errors.push(format!("notify async perf worker panicked: {error}")),
        }
    }
    (results, errors)
}

#[cfg(feature = "realnet")]
async fn run_notify_fanout_perf_async_worker(
    notify_url: String,
    plan: NotifyFanoutPerfPlan,
    next_wake: std::sync::Arc<std::sync::atomic::AtomicUsize>,
) -> Vec<NotifyFanoutPerfMessage> {
    let wake_url = format!("{notify_url}/s13/notify/wake");
    let mut client =
        match NotifyPerfAsyncClient::new(&wake_url, Duration::from_secs(plan.http_timeout_secs)) {
            Ok(client) => client,
            Err(error) => return vec![NotifyFanoutPerfMessage::Error(error.to_string())],
        };
    let mut messages = Vec::new();
    loop {
        let mut batch = Vec::with_capacity(plan.pipeline_depth);
        for _ in 0..plan.pipeline_depth {
            let wake_index = next_wake.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if wake_index >= plan.total_wakes {
                break;
            }
            batch.push(wake_index);
        }
        if batch.is_empty() {
            break;
        }
        match submit_notify_perf_wake_pipeline_async(&mut client, &plan, &batch).await {
            Ok(results) => {
                messages.extend(results.into_iter().map(NotifyFanoutPerfMessage::Success));
            }
            Err(error) => {
                let error = error.to_string();
                messages.extend(
                    batch.iter().map(|_wake_index| NotifyFanoutPerfMessage::Error(error.clone())),
                );
            }
        }
    }
    messages
}

#[cfg(feature = "realnet")]
fn spawn_notify_fanout_perf_worker(
    sender: std::sync::mpsc::Sender<NotifyFanoutPerfMessage>,
    next_wake: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    notify_url: String,
    plan: NotifyFanoutPerfPlan,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let wake_url = format!("{notify_url}/s13/notify/wake");
        let mut client = match NotifyPerfKeepAliveClient::new(
            &wake_url,
            Duration::from_secs(plan.http_timeout_secs),
        ) {
            Ok(client) => client,
            Err(error) => {
                let _ = sender.send(NotifyFanoutPerfMessage::Error(error.to_string()));
                return;
            }
        };
        if plan.async_accept {
            run_notify_fanout_perf_pipeline_worker(&sender, &next_wake, &mut client, &plan);
        } else {
            run_notify_fanout_perf_ping_pong_worker(&sender, &next_wake, &mut client, &plan);
        }
    })
}

#[cfg(feature = "realnet")]
fn run_notify_fanout_perf_pipeline_worker(
    sender: &std::sync::mpsc::Sender<NotifyFanoutPerfMessage>,
    next_wake: &std::sync::atomic::AtomicUsize,
    client: &mut NotifyPerfKeepAliveClient,
    plan: &NotifyFanoutPerfPlan,
) {
    loop {
        let mut batch = Vec::with_capacity(plan.pipeline_depth);
        for _ in 0..plan.pipeline_depth {
            let wake_index = next_wake.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if wake_index >= plan.total_wakes {
                break;
            }
            batch.push(wake_index);
        }
        if batch.is_empty() {
            break;
        }
        send_notify_fanout_perf_pipeline_result(sender, client, plan, &batch);
    }
}

#[cfg(feature = "realnet")]
fn send_notify_fanout_perf_pipeline_result(
    sender: &std::sync::mpsc::Sender<NotifyFanoutPerfMessage>,
    client: &mut NotifyPerfKeepAliveClient,
    plan: &NotifyFanoutPerfPlan,
    batch: &[usize],
) {
    match submit_notify_perf_wake_pipeline(client, plan, batch) {
        Ok(results) => {
            for result in results {
                let _ = sender.send(NotifyFanoutPerfMessage::Success(result));
            }
        }
        Err(error) => {
            let error = error.to_string();
            for _wake_index in batch {
                let _ = sender.send(NotifyFanoutPerfMessage::Error(error.clone()));
            }
        }
    }
}

#[cfg(feature = "realnet")]
fn run_notify_fanout_perf_ping_pong_worker(
    sender: &std::sync::mpsc::Sender<NotifyFanoutPerfMessage>,
    next_wake: &std::sync::atomic::AtomicUsize,
    client: &mut NotifyPerfKeepAliveClient,
    plan: &NotifyFanoutPerfPlan,
) {
    loop {
        let wake_index = next_wake.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if wake_index >= plan.total_wakes {
            break;
        }
        let message = match submit_notify_perf_wake(client, plan, wake_index) {
            Ok(result) => NotifyFanoutPerfMessage::Success(result),
            Err(error) => NotifyFanoutPerfMessage::Error(error.to_string()),
        };
        let _ = sender.send(message);
    }
}

#[cfg(feature = "realnet")]
fn submit_notify_perf_wake(
    client: &mut NotifyPerfKeepAliveClient,
    plan: &NotifyFanoutPerfPlan,
    wake_index: usize,
) -> Result<NotifyFanoutPerfResult, Box<dyn std::error::Error>> {
    let request = notify_perf_wake_request(plan, wake_index)?;
    let started = std::time::Instant::now();
    let response: NotifyFanoutPerfWakeResponse = client.post_json(&request)?;
    Ok(NotifyFanoutPerfResult {
        queue_id: response.entry.queue_id,
        latency_us: started.elapsed().as_micros(),
        attempts: response.attempts,
    })
}

#[cfg(feature = "realnet")]
fn submit_notify_perf_wake_pipeline(
    client: &mut NotifyPerfKeepAliveClient,
    plan: &NotifyFanoutPerfPlan,
    wake_indices: &[usize],
) -> Result<Vec<NotifyFanoutPerfResult>, Box<dyn std::error::Error>> {
    let mut requests = Vec::with_capacity(wake_indices.len());
    let mut started = Vec::with_capacity(wake_indices.len());
    for wake_index in wake_indices {
        requests.push(notify_perf_wake_request(plan, *wake_index)?);
        started.push(std::time::Instant::now());
    }
    let responses: Vec<NotifyFanoutPerfWakeResponse> = client.post_json_pipeline(&requests)?;
    Ok(responses
        .into_iter()
        .zip(started)
        .map(|(response, started)| NotifyFanoutPerfResult {
            queue_id: response.entry.queue_id,
            latency_us: started.elapsed().as_micros(),
            attempts: response.attempts,
        })
        .collect())
}

#[cfg(feature = "realnet")]
async fn submit_notify_perf_wake_pipeline_async(
    client: &mut NotifyPerfAsyncClient,
    plan: &NotifyFanoutPerfPlan,
    wake_indices: &[usize],
) -> Result<Vec<NotifyFanoutPerfResult>, Box<dyn std::error::Error>> {
    let mut requests = Vec::with_capacity(wake_indices.len());
    let mut started = Vec::with_capacity(wake_indices.len());
    for wake_index in wake_indices {
        requests.push(notify_perf_wake_request(plan, *wake_index)?);
        started.push(std::time::Instant::now());
    }
    let responses: Vec<NotifyFanoutPerfWakeResponse> = client.post_json_pipeline(&requests).await?;
    Ok(responses
        .into_iter()
        .zip(started)
        .map(|(response, started)| NotifyFanoutPerfResult {
            queue_id: response.entry.queue_id,
            latency_us: started.elapsed().as_micros(),
            attempts: response.attempts,
        })
        .collect())
}

#[cfg(feature = "realnet")]
fn notify_perf_wake_request(
    plan: &NotifyFanoutPerfPlan,
    wake_index: usize,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let device_index = wake_index % plan.device_cardinality;
    let mut wake = notify_perf_wake(wake_index, device_index);
    sign_itest_notification_wake(&mut wake)?;
    Ok(serde_json::json!({
        "device_delivery_id": notify_perf_device_id(device_index),
        "wake": wake,
        "queued_at": 1_760_000_000_u64 + u64::try_from(wake_index)?,
        "dnd_active": false
    }))
}

#[cfg(feature = "realnet")]
fn notify_perf_wake(wake_index: usize, device_index: usize) -> ramflux_protocol::NotificationWake {
    ramflux_protocol::NotificationWake {
        schema: ramflux_protocol::domain::NOTIFICATION_WAKE.to_owned(),
        version: 1,
        domain: ramflux_protocol::domain::NOTIFICATION_WAKE.to_owned(),
        ext: ramflux_protocol::Ext::default(),
        signed: itest_signed_fields(),
        wake_id: format!("wake_notify_perf_{wake_index:06}"),
        push_alias: format!("notify_perf_alias_{device_index}"),
        delivery_class: ramflux_protocol::NotificationDeliveryClass::UserContentNotification,
        priority: ramflux_protocol::PushPriority::Normal,
        ttl: 86_400,
        collapse_key: Some(format!("target:{}:content", notify_perf_device_id(device_index))),
        encrypted_hint: Some(format!("notify_perf_encrypted_hint_{wake_index:06}")),
    }
}

#[cfg(feature = "realnet")]
fn notify_perf_device_id(device_index: usize) -> String {
    format!("target_s13_notify_perf_{device_index:04}")
}

#[cfg(feature = "realnet")]
fn wait_for_s27_mock_push_requests(
    mock: &S13MockPushProvider,
    expected_count: usize,
    timeout: Duration,
) -> Result<Vec<S13MockPushRequest>, Box<dyn std::error::Error>> {
    let deadline = std::time::Instant::now() + timeout;
    let mut guard =
        mock.requests.lock().map_err(|error| format!("mock push lock poisoned: {error}"))?;
    while guard.len() < expected_count {
        let now = std::time::Instant::now();
        if now >= deadline {
            return Err(format!(
                "timed out waiting for S27 mock pushes; got {} expected {expected_count}",
                guard.len()
            )
            .into());
        }
        let remaining = deadline.saturating_duration_since(now);
        let (next_guard, _timeout) = mock
            .done
            .wait_timeout(guard, remaining)
            .map_err(|error| format!("mock push condvar poisoned: {error}"))?;
        guard = next_guard;
    }
    drop(guard);
    std::thread::sleep(Duration::from_secs(1));
    let guard =
        mock.requests.lock().map_err(|error| format!("mock push lock poisoned: {error}"))?;
    Ok(guard.clone())
}

#[cfg(feature = "realnet")]
fn s13_mock_push_count(mock: &S13MockPushProvider) -> Result<usize, Box<dyn std::error::Error>> {
    let guard =
        mock.requests.lock().map_err(|error| format!("mock push lock poisoned: {error}"))?;
    Ok(guard.len())
}

#[cfg(feature = "realnet")]
fn assert_notify_soak_health(notify_url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let _health: serde_json::Value =
        ramflux_node_core::itest_http_get_json(&format!("{notify_url}/healthz"))?;
    Ok(())
}

#[cfg(feature = "realnet")]
fn assert_notify_soak_logs_clean() -> Result<(), Box<dyn std::error::Error>> {
    let Some(logs) = read_notify_container_logs() else {
        eprintln!("RAMFLUX_NOTIFY_SOAK_LOG_WARN unable_to_collect_notify_container_logs");
        return Ok(());
    };
    assert_notify_soak_logs_have_no_error_markers(&logs)
}

#[cfg(feature = "realnet")]
fn read_notify_container_logs() -> Option<String> {
    let container_name = find_notify_container_name()?;
    for runtime in ["podman", "docker"] {
        let output =
            std::process::Command::new(runtime).arg("logs").arg(&container_name).output().ok()?;
        if output.status.success() {
            let mut logs = String::from_utf8_lossy(&output.stdout).into_owned();
            logs.push_str(&String::from_utf8_lossy(&output.stderr));
            return Some(logs);
        }
    }
    None
}

#[cfg(feature = "realnet")]
fn find_notify_container_name() -> Option<String> {
    for runtime in ["podman", "docker"] {
        let output = std::process::Command::new(runtime)
            .arg("ps")
            .arg("--format")
            .arg("{{.Names}}")
            .output()
            .ok()?;
        if !output.status.success() {
            continue;
        }
        let names = String::from_utf8_lossy(&output.stdout);
        if let Some(name) =
            names.lines().find(|name| name.contains("ramflux-notify") || name.contains("notify"))
        {
            return Some(name.to_owned());
        }
    }
    None
}

#[cfg(feature = "realnet")]
fn assert_notify_soak_logs_have_no_error_markers(
    logs: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let lowercase = logs.to_ascii_lowercase();
    let bad_marker = lowercase.contains("panic")
        || logs.contains(" panicked")
        || logs.contains("level=ERROR")
        || logs.contains(" ERROR ");
    if bad_marker {
        let tail = logs
            .lines()
            .rev()
            .take(80)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
            .join("\n");
        return Err(format!("notify soak logs contain panic/error marker:\n{tail}").into());
    }
    Ok(())
}

#[cfg(feature = "realnet")]
fn assert_s27_wakes_delivered_exactly_once(
    requests: &[S13MockPushRequest],
    expected_wakes: &std::collections::BTreeSet<String>,
) {
    let mut counts =
        std::collections::BTreeMap::<(String, ramflux_node_core::PushProviderKind), usize>::new();
    for request in requests {
        *counts
            .entry((request.payload.wake_id.clone(), request.payload.provider.clone()))
            .or_insert(0) += 1;
    }
    for wake_id in expected_wakes {
        for provider in
            [ramflux_node_core::PushProviderKind::WebPush, ramflux_node_core::PushProviderKind::Fcm]
        {
            let count = counts.get(&(wake_id.clone(), provider.clone())).copied().unwrap_or(0);
            assert_eq!(
                count, 1,
                "S27 wake/provider was not delivered exactly once: wake_id={wake_id} provider={provider:?} count={count}"
            );
        }
    }
    let expected_pairs = expected_wakes.len().saturating_mul(2);
    assert_eq!(
        counts.len(),
        expected_pairs,
        "S27 observed unexpected wake/provider pairs: observed={} expected={expected_pairs}",
        counts.len()
    );
    assert_eq!(
        requests.len(),
        expected_pairs,
        "S27 observed duplicate provider requests: observed={} expected={expected_pairs}",
        requests.len()
    );
}

#[cfg(feature = "realnet")]
fn wait_for_s27_wake_delivery(
    mock: &S13MockPushProvider,
    wake_id: &str,
    timeout: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = std::time::Instant::now() + timeout;
    let mut guard =
        mock.requests.lock().map_err(|error| format!("mock push lock poisoned: {error}"))?;
    loop {
        let delivered = guard.iter().filter(|request| request.payload.wake_id == wake_id).count();
        if delivered >= 2 {
            return Ok(());
        }
        let now = std::time::Instant::now();
        if now >= deadline {
            return Err(format!(
                "timed out waiting for S27 post-restart wake delivery: wake_id={wake_id} observed={delivered}"
            )
            .into());
        }
        let remaining = deadline.saturating_duration_since(now);
        let (next_guard, _timeout) = mock
            .done
            .wait_timeout(guard, remaining)
            .map_err(|error| format!("mock push condvar poisoned: {error}"))?;
        guard = next_guard;
    }
}

#[cfg(feature = "realnet")]
struct NotifyFanoutStageObservations<'a> {
    elapsed: Duration,
    delivery_elapsed: Duration,
    results: &'a [NotifyFanoutPerfResult],
    errors: &'a [String],
}

#[cfg(feature = "realnet")]
fn notify_fanout_stage_report(
    plan: &NotifyFanoutPerfPlan,
    concurrency: usize,
    observations: &NotifyFanoutStageObservations<'_>,
    runtime: &str,
) -> NotifyFanoutPerfStageReport {
    let mut latencies =
        observations.results.iter().map(|result| result.latency_us).collect::<Vec<_>>();
    latencies.sort_unstable();
    let provider_attempts =
        observations.results.iter().map(|result| result.attempts.len()).sum::<usize>();
    let mut provider_accepted = 0_usize;
    let mut provider_errors = 0_usize;
    let mut provider_accepted_by_kind = std::collections::BTreeMap::new();
    for attempt in observations.results.iter().flat_map(|result| result.attempts.iter()) {
        if attempt.accepted {
            provider_accepted += 1;
            *provider_accepted_by_kind.entry(format!("{:?}", attempt.provider)).or_insert(0) += 1;
        } else {
            provider_errors += 1;
        }
    }
    let elapsed_secs = observations.elapsed.as_secs_f64().max(0.001);
    let delivery_elapsed_secs = observations.delivery_elapsed.as_secs_f64().max(0.001);
    let total_observed = observations.results.len() + observations.errors.len();
    NotifyFanoutPerfStageReport {
        runtime: runtime.to_owned(),
        concurrency,
        total_wakes: plan.total_wakes,
        route_count: plan.route_count,
        device_cardinality: plan.device_cardinality,
        provider_delay_ms: plan.provider_delay_ms,
        http_timeout_secs: plan.http_timeout_secs,
        max_error_rate: plan.max_error_rate,
        async_accept: plan.async_accept,
        pipeline_depth: plan.pipeline_depth,
        client_workers: plan.client_workers,
        skip_delivery: plan.skip_delivery,
        successful_wakes: observations.results.len(),
        provider_attempts,
        provider_accepted,
        provider_errors,
        elapsed_ms: observations.elapsed.as_millis(),
        wake_per_sec: notify_perf_usize_to_f64(observations.results.len()) / elapsed_secs,
        enqueue_wake_per_sec: notify_perf_usize_to_f64(observations.results.len()) / elapsed_secs,
        provider_push_per_sec: notify_perf_usize_to_f64(provider_accepted) / elapsed_secs,
        delivery_push_per_sec: notify_perf_usize_to_f64(provider_accepted) / delivery_elapsed_secs,
        delivery_elapsed_ms: observations.delivery_elapsed.as_millis(),
        error_rate: if total_observed == 0 {
            0.0
        } else {
            notify_perf_usize_to_f64(observations.errors.len())
                / notify_perf_usize_to_f64(total_observed)
        },
        p50_us: notify_perf_percentile(&latencies, 500),
        p95_us: notify_perf_percentile(&latencies, 950),
        p99_us: notify_perf_percentile(&latencies, 990),
        provider_accepted_by_kind,
        transport_errors: observations.errors.len(),
        correctness_errors: 0,
        sample_error: observations.errors.first().cloned(),
    }
}

#[cfg(feature = "realnet")]
fn poll_notify_perf_provider_attempts(
    notify_url: &str,
    queue_ids: &[String],
    plan: &NotifyFanoutPerfPlan,
) -> Result<
    std::collections::BTreeMap<String, Vec<ramflux_node_core::ProviderPushAttempt>>,
    Box<dyn std::error::Error>,
> {
    let mut pending = queue_ids.iter().cloned().collect::<std::collections::BTreeSet<_>>();
    let mut attempts_by_queue = std::collections::BTreeMap::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(plan.http_timeout_secs);
    while !pending.is_empty() {
        let mut completed = Vec::new();
        for queue_id in &pending {
            let attempts: Vec<ramflux_node_core::ProviderPushAttempt> =
                ramflux_node_core::itest_http_get_json(&format!(
                    "{notify_url}/s13/notify/provider-attempts/{queue_id}"
                ))?;
            if attempts.len() >= plan.route_count {
                attempts_by_queue.insert(queue_id.clone(), attempts);
                completed.push(queue_id.clone());
            }
        }
        for queue_id in completed {
            pending.remove(&queue_id);
        }
        if pending.is_empty() {
            return Ok(attempts_by_queue);
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!(
                "timed out waiting for notify async provider attempts: pending={} expected_attempts_per_queue={}",
                pending.len(),
                plan.route_count
            )
            .into());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Ok(attempts_by_queue)
}

#[cfg(feature = "realnet")]
fn notify_perf_usize_to_f64(value: usize) -> f64 {
    u32::try_from(value).map_or(f64::from(u32::MAX), f64::from)
}

#[cfg(feature = "realnet")]
fn notify_perf_runtime_from_env() -> String {
    if std::env::var("RAMFLUX_NOTIFY_COMPIO").as_deref() == Ok("1")
        || std::env::var("RAMFLUX_NOTIFY_RUNTIME").as_deref() == Ok("compio")
    {
        "compio".to_owned()
    } else if std::env::var("RAMFLUX_NOTIFY_RUNTIME").as_deref() == Ok("tokio-concurrent") {
        "tokio-concurrent".to_owned()
    } else {
        "current".to_owned()
    }
}

#[cfg(feature = "realnet")]
fn notify_perf_default_enabled_env(name: &str) -> bool {
    std::env::var(name).map_or(true, |value| {
        let trimmed = value.trim();
        !(trimmed == "0"
            || trimmed.eq_ignore_ascii_case("false")
            || trimmed.eq_ignore_ascii_case("off")
            || trimmed.eq_ignore_ascii_case("no"))
    })
}

#[cfg(feature = "realnet")]
fn enforce_notify_fanout_error_rate(
    plan: &NotifyFanoutPerfPlan,
    stages: &[NotifyFanoutPerfStageReport],
) -> Result<(), Box<dyn std::error::Error>> {
    if plan.max_error_rate >= 1.0 {
        return Ok(());
    }
    let failures = stages
        .iter()
        .filter(|stage| stage.error_rate > plan.max_error_rate)
        .map(|stage| {
            format!(
                "concurrency={} error_rate={:.6} sample_error={}",
                stage.concurrency,
                stage.error_rate,
                stage.sample_error.as_deref().unwrap_or("<none>")
            )
        })
        .collect::<Vec<_>>();
    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "notify fanout perf error_rate exceeded max_error_rate={:.6}: {}",
            plan.max_error_rate,
            failures.join("; ")
        )
        .into())
    }
}

#[cfg(feature = "realnet")]
struct NotifyPerfKeepAliveClient {
    host_port: String,
    path: String,
    timeout: Duration,
    stream: Option<TcpStream>,
    read_buffer: Vec<u8>,
}

#[cfg(feature = "realnet")]
impl NotifyPerfKeepAliveClient {
    fn new(url: &str, timeout: Duration) -> Result<Self, Box<dyn std::error::Error>> {
        let (host_port, path) = notify_perf_parse_http_url(url)?;
        Ok(Self {
            host_port: host_port.to_owned(),
            path: path.to_owned(),
            timeout,
            stream: None,
            read_buffer: Vec::new(),
        })
    }

    fn post_json<T: serde::Serialize, R: serde::de::DeserializeOwned>(
        &mut self,
        value: &T,
    ) -> Result<R, Box<dyn std::error::Error>> {
        match self.post_json_once(value) {
            Ok(response) => Ok(response),
            Err(NotifyPerfHttpError::Transport(first_error)) => {
                self.reset_connection();
                self.post_json_once(value).map_err(|retry_error| {
                    format!("notify keep-alive transport error: {first_error}; retry failed: {retry_error}")
                        .into()
                })
            }
            Err(error) => Err(error.into()),
        }
    }

    fn post_json_once<T: serde::Serialize, R: serde::de::DeserializeOwned>(
        &mut self,
        value: &T,
    ) -> Result<R, NotifyPerfHttpError> {
        let body = serde_json::to_vec(value)
            .map_err(|source| NotifyPerfHttpError::Decode(source.to_string()))?;
        if self.stream.is_none() {
            self.stream = Some(self.connect()?);
        }
        self.write_json_request(&body)?;
        self.flush_stream()?;
        let response = self.read_http_response_by_content_length()?;
        if !response.keep_alive {
            self.reset_connection();
        }
        if !response.status_is_success() {
            return Err(NotifyPerfHttpError::Http(format!(
                "non-success response: {} body={}",
                response.status_line,
                String::from_utf8_lossy(&response.body)
            )));
        }
        serde_json::from_slice(&response.body)
            .map_err(|source| NotifyPerfHttpError::Decode(source.to_string()))
    }

    fn post_json_pipeline<T: serde::Serialize, R: serde::de::DeserializeOwned>(
        &mut self,
        values: &[T],
    ) -> Result<Vec<R>, Box<dyn std::error::Error>> {
        match self.post_json_pipeline_once(values) {
            Ok(responses) => Ok(responses),
            Err(NotifyPerfHttpError::Transport(first_error)) => {
                self.reset_connection();
                self.post_json_pipeline_once(values).map_err(|retry_error| {
                    format!(
                        "notify keep-alive pipeline transport error: {first_error}; retry failed: {retry_error}"
                    )
                    .into()
                })
            }
            Err(error) => Err(error.into()),
        }
    }

    fn post_json_pipeline_once<T: serde::Serialize, R: serde::de::DeserializeOwned>(
        &mut self,
        values: &[T],
    ) -> Result<Vec<R>, NotifyPerfHttpError> {
        if self.stream.is_none() {
            self.stream = Some(self.connect()?);
        }
        let bodies = values
            .iter()
            .map(|value| {
                serde_json::to_vec(value)
                    .map_err(|source| NotifyPerfHttpError::Decode(source.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        for body in &bodies {
            self.write_json_request(body)?;
        }
        self.flush_stream()?;
        let mut responses = Vec::with_capacity(values.len());
        for index in 0..values.len() {
            let response = self.read_http_response_by_content_length()?;
            if !response.status_is_success() {
                return Err(NotifyPerfHttpError::Http(format!(
                    "non-success response: {} body={}",
                    response.status_line,
                    String::from_utf8_lossy(&response.body)
                )));
            }
            let keep_alive = response.keep_alive;
            responses.push(
                serde_json::from_slice(&response.body)
                    .map_err(|source| NotifyPerfHttpError::Decode(source.to_string()))?,
            );
            if !keep_alive {
                self.reset_connection();
                if index + 1 != values.len() {
                    return Err(NotifyPerfHttpError::Transport(
                        "notify server closed pipelined connection before all responses".to_owned(),
                    ));
                }
            }
        }
        Ok(responses)
    }

    fn write_json_request(&mut self, body: &[u8]) -> Result<(), NotifyPerfHttpError> {
        let stream = self.stream.as_mut().ok_or_else(|| {
            NotifyPerfHttpError::Transport("missing notify perf stream".to_owned())
        })?;
        write!(
            stream,
            "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
            self.path,
            self.host_port,
            body.len()
        )
        .map_err(|source| NotifyPerfHttpError::Transport(source.to_string()))?;
        stream.write_all(body).map_err(|source| NotifyPerfHttpError::Transport(source.to_string()))
    }

    fn flush_stream(&mut self) -> Result<(), NotifyPerfHttpError> {
        let stream = self.stream.as_mut().ok_or_else(|| {
            NotifyPerfHttpError::Transport("missing notify perf stream".to_owned())
        })?;
        stream.flush().map_err(|source| NotifyPerfHttpError::Transport(source.to_string()))
    }

    fn read_http_response_by_content_length(
        &mut self,
    ) -> Result<ramflux_node_core::ItestHttpResponse, NotifyPerfHttpError> {
        let header_end = loop {
            if let Some(header_end) = notify_perf_find_http_header_end(&self.read_buffer) {
                break header_end;
            }
            self.read_more()?;
        };
        let header = std::str::from_utf8(&self.read_buffer[..header_end]).map_err(|source| {
            NotifyPerfHttpError::Transport(format!("bad response header utf8: {source}"))
        })?;
        let mut lines = header.lines();
        let status_line = lines
            .next()
            .ok_or_else(|| NotifyPerfHttpError::Transport("missing status line".to_owned()))?
            .to_owned();
        let mut content_length = None;
        let mut keep_alive = false;
        for line in lines {
            let Some((name, value)) = line.trim_end().split_once(':') else {
                continue;
            };
            if name.eq_ignore_ascii_case("Content-Length") {
                content_length = Some(value.trim().parse::<usize>().map_err(|source| {
                    NotifyPerfHttpError::Transport(format!("bad response content length: {source}"))
                })?);
            } else if name.eq_ignore_ascii_case("Connection") {
                keep_alive = notify_perf_connection_keep_alive(value.trim());
            }
        }
        let content_length = content_length.ok_or_else(|| {
            NotifyPerfHttpError::Transport("response missing Content-Length".to_owned())
        })?;
        let body_start =
            header_end + notify_perf_http_header_separator_len(&self.read_buffer, header_end);
        let response_end = body_start.saturating_add(content_length);
        while self.read_buffer.len() < response_end {
            self.read_more()?;
        }
        let body = self.read_buffer[body_start..response_end].to_vec();
        self.read_buffer.drain(..response_end);
        Ok(ramflux_node_core::ItestHttpResponse { status_line, body, keep_alive })
    }

    fn read_more(&mut self) -> Result<(), NotifyPerfHttpError> {
        let stream = self.stream.as_mut().ok_or_else(|| {
            NotifyPerfHttpError::Transport("missing notify perf stream".to_owned())
        })?;
        let mut chunk = [0_u8; 8192];
        let bytes = stream
            .read(&mut chunk)
            .map_err(|source| NotifyPerfHttpError::Transport(source.to_string()))?;
        if bytes == 0 {
            return Err(NotifyPerfHttpError::Transport(
                "notify perf connection closed while reading response".to_owned(),
            ));
        }
        self.read_buffer.extend_from_slice(&chunk[..bytes]);
        Ok(())
    }

    fn reset_connection(&mut self) {
        self.stream = None;
        self.read_buffer.clear();
    }

    fn connect(&self) -> Result<TcpStream, NotifyPerfHttpError> {
        let addr = self
            .host_port
            .to_socket_addrs()
            .map_err(|source| NotifyPerfHttpError::Transport(source.to_string()))?
            .next()
            .ok_or_else(|| {
                NotifyPerfHttpError::Transport(format!("cannot resolve {}", self.host_port))
            })?;
        let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5))
            .map_err(|source| NotifyPerfHttpError::Transport(source.to_string()))?;
        stream
            .set_nodelay(true)
            .map_err(|source| NotifyPerfHttpError::Transport(source.to_string()))?;
        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(|source| NotifyPerfHttpError::Transport(source.to_string()))?;
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .map_err(|source| NotifyPerfHttpError::Transport(source.to_string()))?;
        Ok(stream)
    }
}

#[cfg(feature = "realnet")]
struct NotifyPerfAsyncClient {
    host_port: String,
    path: String,
    timeout: Duration,
    stream: Option<tokio::net::TcpStream>,
    read_buffer: Vec<u8>,
}

#[cfg(feature = "realnet")]
impl NotifyPerfAsyncClient {
    fn new(url: &str, timeout: Duration) -> Result<Self, Box<dyn std::error::Error>> {
        let (host_port, path) = notify_perf_parse_http_url(url)?;
        Ok(Self {
            host_port: host_port.to_owned(),
            path: path.to_owned(),
            timeout,
            stream: None,
            read_buffer: Vec::new(),
        })
    }

    async fn post_json_pipeline<T: serde::Serialize, R: serde::de::DeserializeOwned>(
        &mut self,
        values: &[T],
    ) -> Result<Vec<R>, Box<dyn std::error::Error>> {
        match self.post_json_pipeline_once(values).await {
            Ok(responses) => Ok(responses),
            Err(NotifyPerfHttpError::Transport(first_error)) => {
                self.reset_connection();
                self.post_json_pipeline_once(values).await.map_err(|retry_error| {
                    format!(
                        "notify async pipeline transport error: {first_error}; retry failed: {retry_error}"
                    )
                    .into()
                })
            }
            Err(error) => Err(error.into()),
        }
    }

    async fn post_json_pipeline_once<T: serde::Serialize, R: serde::de::DeserializeOwned>(
        &mut self,
        values: &[T],
    ) -> Result<Vec<R>, NotifyPerfHttpError> {
        if self.stream.is_none() {
            self.stream = Some(self.connect().await?);
        }
        let bodies = values
            .iter()
            .map(|value| {
                serde_json::to_vec(value)
                    .map_err(|source| NotifyPerfHttpError::Decode(source.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        for body in &bodies {
            self.write_json_request(body).await?;
        }
        self.flush_stream().await?;
        let mut responses = Vec::with_capacity(values.len());
        for index in 0..values.len() {
            let response = self.read_http_response_by_content_length().await?;
            if !response.status_is_success() {
                return Err(NotifyPerfHttpError::Http(format!(
                    "non-success response: {} body={}",
                    response.status_line,
                    String::from_utf8_lossy(&response.body)
                )));
            }
            let keep_alive = response.keep_alive;
            responses.push(
                serde_json::from_slice(&response.body)
                    .map_err(|source| NotifyPerfHttpError::Decode(source.to_string()))?,
            );
            if !keep_alive {
                self.reset_connection();
                if index + 1 != values.len() {
                    return Err(NotifyPerfHttpError::Transport(
                        "notify server closed async pipelined connection before all responses"
                            .to_owned(),
                    ));
                }
            }
        }
        Ok(responses)
    }

    async fn write_json_request(&mut self, body: &[u8]) -> Result<(), NotifyPerfHttpError> {
        use tokio::io::AsyncWriteExt;

        let stream = self.stream.as_mut().ok_or_else(|| {
            NotifyPerfHttpError::Transport("missing notify async perf stream".to_owned())
        })?;
        let header = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
            self.path,
            self.host_port,
            body.len()
        );
        stream
            .write_all(header.as_bytes())
            .await
            .map_err(|source| NotifyPerfHttpError::Transport(source.to_string()))?;
        stream
            .write_all(body)
            .await
            .map_err(|source| NotifyPerfHttpError::Transport(source.to_string()))
    }

    async fn flush_stream(&mut self) -> Result<(), NotifyPerfHttpError> {
        use tokio::io::AsyncWriteExt;

        let stream = self.stream.as_mut().ok_or_else(|| {
            NotifyPerfHttpError::Transport("missing notify async perf stream".to_owned())
        })?;
        stream.flush().await.map_err(|source| NotifyPerfHttpError::Transport(source.to_string()))
    }

    async fn read_http_response_by_content_length(
        &mut self,
    ) -> Result<ramflux_node_core::ItestHttpResponse, NotifyPerfHttpError> {
        let header_end = loop {
            if let Some(header_end) = notify_perf_find_http_header_end(&self.read_buffer) {
                break header_end;
            }
            self.read_more().await?;
        };
        let header = std::str::from_utf8(&self.read_buffer[..header_end]).map_err(|source| {
            NotifyPerfHttpError::Transport(format!("bad response header utf8: {source}"))
        })?;
        let mut lines = header.lines();
        let status_line = lines
            .next()
            .ok_or_else(|| NotifyPerfHttpError::Transport("missing status line".to_owned()))?
            .to_owned();
        let mut content_length = None;
        let mut keep_alive = false;
        for line in lines {
            let Some((name, value)) = line.trim_end().split_once(':') else {
                continue;
            };
            if name.eq_ignore_ascii_case("Content-Length") {
                content_length = Some(value.trim().parse::<usize>().map_err(|source| {
                    NotifyPerfHttpError::Transport(format!("bad response content length: {source}"))
                })?);
            } else if name.eq_ignore_ascii_case("Connection") {
                keep_alive = notify_perf_connection_keep_alive(value.trim());
            }
        }
        let content_length = content_length.ok_or_else(|| {
            NotifyPerfHttpError::Transport("response missing Content-Length".to_owned())
        })?;
        let body_start =
            header_end + notify_perf_http_header_separator_len(&self.read_buffer, header_end);
        let response_end = body_start.saturating_add(content_length);
        while self.read_buffer.len() < response_end {
            self.read_more().await?;
        }
        let body = self.read_buffer[body_start..response_end].to_vec();
        self.read_buffer.drain(..response_end);
        Ok(ramflux_node_core::ItestHttpResponse { status_line, body, keep_alive })
    }

    async fn read_more(&mut self) -> Result<(), NotifyPerfHttpError> {
        use tokio::io::AsyncReadExt;

        let stream = self.stream.as_mut().ok_or_else(|| {
            NotifyPerfHttpError::Transport("missing notify async perf stream".to_owned())
        })?;
        let mut chunk = [0_u8; 8192];
        let read = tokio::time::timeout(self.timeout, stream.read(&mut chunk))
            .await
            .map_err(|_elapsed| {
                NotifyPerfHttpError::Transport(format!(
                    "notify async perf response read timed out after {:?}",
                    self.timeout
                ))
            })?
            .map_err(|source| NotifyPerfHttpError::Transport(source.to_string()))?;
        if read == 0 {
            return Err(NotifyPerfHttpError::Transport(
                "notify async perf connection closed while reading response".to_owned(),
            ));
        }
        self.read_buffer.extend_from_slice(&chunk[..read]);
        Ok(())
    }

    fn reset_connection(&mut self) {
        self.stream = None;
        self.read_buffer.clear();
    }

    async fn connect(&self) -> Result<tokio::net::TcpStream, NotifyPerfHttpError> {
        let stream = tokio::time::timeout(
            Duration::from_secs(5),
            tokio::net::TcpStream::connect(&self.host_port),
        )
        .await
        .map_err(|_elapsed| {
            NotifyPerfHttpError::Transport(format!(
                "notify async perf connect timed out: {}",
                self.host_port
            ))
        })?
        .map_err(|source| NotifyPerfHttpError::Transport(source.to_string()))?;
        stream
            .set_nodelay(true)
            .map_err(|source| NotifyPerfHttpError::Transport(source.to_string()))?;
        Ok(stream)
    }
}

#[cfg(feature = "realnet")]
fn notify_perf_find_http_header_end(raw: &[u8]) -> Option<usize> {
    raw.windows(4)
        .position(|window| window == b"\r\n\r\n")
        .or_else(|| raw.windows(2).position(|window| window == b"\n\n"))
}

#[cfg(feature = "realnet")]
fn notify_perf_http_header_separator_len(raw: &[u8], header_end: usize) -> usize {
    if raw.get(header_end..header_end + 4) == Some(b"\r\n\r\n") { 4 } else { 2 }
}

#[cfg(feature = "realnet")]
fn notify_perf_connection_keep_alive(value: &str) -> bool {
    let mut keep_alive = false;
    for part in value.split(',') {
        let part = part.trim();
        if part.eq_ignore_ascii_case("close") {
            return false;
        }
        if part.eq_ignore_ascii_case("keep-alive") {
            keep_alive = true;
        }
    }
    keep_alive
}

#[cfg(feature = "realnet")]
#[derive(Debug)]
enum NotifyPerfHttpError {
    Transport(String),
    Http(String),
    Decode(String),
}

#[cfg(feature = "realnet")]
impl std::fmt::Display for NotifyPerfHttpError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(error) => write!(formatter, "transport error: {error}"),
            Self::Http(error) => write!(formatter, "{error}"),
            Self::Decode(error) => write!(formatter, "decode error: {error}"),
        }
    }
}

#[cfg(feature = "realnet")]
impl std::error::Error for NotifyPerfHttpError {}

#[cfg(feature = "realnet")]
fn notify_perf_parse_http_url(url: &str) -> Result<(&str, &str), Box<dyn std::error::Error>> {
    let Some(rest) = url.strip_prefix("http://") else {
        return Err(format!("unsupported url {url}").into());
    };
    let Some((_host_port, path)) = rest.split_once('/') else {
        return Ok((rest, "/"));
    };
    Ok((&rest[..rest.len() - path.len() - 1], &url[url.len() - path.len() - 1..]))
}

#[cfg(feature = "realnet")]
fn notify_perf_percentile(sorted: &[u128], per_mille: usize) -> u128 {
    if sorted.is_empty() {
        return 0;
    }
    let index = ((sorted.len() - 1) * per_mille) / 1000;
    sorted[index]
}

#[cfg(feature = "realnet")]
fn write_notify_perf_artifact(
    artifact: &Path,
    runtime: &str,
    plan: &NotifyFanoutPerfPlan,
    stages: &[NotifyFanoutPerfStageReport],
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = artifact.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let report = serde_json::json!({
        "bench": "mvp_s13_perf_realnet_notify_fanout_load",
        "runtime": runtime,
        "plan": plan,
        "stages": stages,
        "note": "current is serial notify fanout with per-provider tokio runtime creation; tokio-concurrent is per-device worker fanout with a shared tokio provider runtime; compio is per-shard fanout scheduling with the same shared provider runtime"
    });
    std::fs::write(artifact, serde_json::to_vec_pretty(&report)?)?;
    Ok(())
}

#[cfg(feature = "realnet")]
fn notify_perf_artifact_path(file_name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let dir = code_root().join("ramflux-itest/perf-artifacts");
    std::fs::create_dir_all(&dir)?;
    Ok(dir.join(file_name))
}

#[cfg(feature = "realnet")]
fn notify_perf_env_usize(name: &str, default: usize) -> Result<usize, Box<dyn std::error::Error>> {
    match std::env::var(name) {
        Ok(value) => Ok(value.parse::<usize>()?),
        Err(_) => Ok(default),
    }
}

#[cfg(feature = "realnet")]
fn notify_perf_env_u64(name: &str, default: u64) -> Result<u64, Box<dyn std::error::Error>> {
    match std::env::var(name) {
        Ok(value) => Ok(value.parse::<u64>()?),
        Err(_) => Ok(default),
    }
}

#[cfg(feature = "realnet")]
fn notify_perf_env_f64(name: &str, default: f64) -> Result<f64, Box<dyn std::error::Error>> {
    match std::env::var(name) {
        Ok(value) => Ok(value.parse::<f64>()?),
        Err(_) => Ok(default),
    }
}

#[cfg(feature = "realnet")]
fn notify_perf_env_usize_list(
    name: &str,
    default: &[usize],
) -> Result<Vec<usize>, Box<dyn std::error::Error>> {
    let Ok(value) = std::env::var(name) else {
        return Ok(default.to_vec());
    };
    value
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(|part| Ok(part.parse::<usize>()?.max(1)))
        .collect()
}
