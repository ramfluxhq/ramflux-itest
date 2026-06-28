// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use super::*;

#[cfg(feature = "realnet")]
#[test]
fn mvp5_realnet_internal_mtls_gateway_router() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    let realnet = start_realnet_compose()?;
    let gateway_url = &realnet.gateway_url;

    let envelope = itest_envelope("env_mvp5_mtls_gateway_router", "target_mvp5_mtls");
    let submit: ramflux_node_core::ItestMvp0SubmitResponse =
        ramflux_node_core::itest_http_post_json(
            &format!("{gateway_url}/mvp0/envelope"),
            &envelope,
        )?;
    assert_eq!(submit.outcome, "offline_queued");
    assert_eq!(submit.target_delivery_id, "target_mvp5_mtls");
    assert_eq!(submit.inbox_seq, Some(1));

    let ack_cursor: ramflux_node_core::ItestMvp0CursorResponse =
        ramflux_node_core::itest_http_post_json(
            &format!("{gateway_url}/mvp0/ack"),
            &itest_ack("env_mvp5_mtls_gateway_router"),
        )?;
    assert_eq!(ack_cursor.inbox_seq, 1);
    assert_eq!(ack_cursor.last_envelope_id.as_deref(), Some("env_mvp5_mtls_gateway_router"));
    assert!(ack_cursor.acked_envelope_ids.contains(&"env_mvp5_mtls_gateway_router".to_owned()));

    let cursor: Option<ramflux_node_core::ItestMvp0CursorResponse> =
        ramflux_node_core::itest_http_get_json(&format!(
            "{gateway_url}/mvp0/cursor/target_mvp5_mtls"
        ))?;
    let cursor = cursor.ok_or("missing mTLS router cursor")?;
    assert_eq!(cursor.inbox_seq, 1);
    assert!(cursor.acked_envelope_ids.contains(&"env_mvp5_mtls_gateway_router".to_owned()));
    assert!(!plaintext_router_mesh_probe()?);
    Ok(())
}

#[cfg(feature = "realnet")]
#[test]
fn mvp5_realnet_quic_gateway_submit_ack_cursor() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    let realnet = start_realnet_compose()?;
    let code_root = code_root();
    let ca_cert = code_root.join("ramflux/deploy/certs/ca.pem");
    let gateway_quic_addr: std::net::SocketAddr = std::env::var("RAMFLUX_ITEST_GATEWAY_QUIC_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:18443".to_owned())
        .parse()?;

    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async {
        let client = ramflux_transport::QuicGatewayClient::connect(
            "0.0.0.0:0".parse()?,
            gateway_quic_addr,
            "localhost",
            &ca_cert,
            std::time::Duration::from_secs(10),
        )
        .await?;

        let envelope = itest_envelope("env_mvp5_quic_gateway", "target_mvp5_quic");
        let submit: ramflux_node_core::ItestMvp0SubmitResponse =
            client.post_json("/mvp0/envelope", &envelope).await?;
        assert_eq!(submit.outcome, "offline_queued");
        assert_eq!(submit.target_delivery_id, "target_mvp5_quic");
        assert_eq!(submit.inbox_seq, Some(1));

        let ack_cursor: ramflux_node_core::ItestMvp0CursorResponse =
            client.post_json("/mvp0/ack", &itest_ack("env_mvp5_quic_gateway")).await?;
        assert_eq!(ack_cursor.inbox_seq, 1);
        assert_eq!(ack_cursor.last_envelope_id.as_deref(), Some("env_mvp5_quic_gateway"));
        assert!(ack_cursor.acked_envelope_ids.contains(&"env_mvp5_quic_gateway".to_owned()));

        let cursor: Option<ramflux_node_core::ItestMvp0CursorResponse> =
            client.get_json("/mvp0/cursor/target_mvp5_quic").await?;
        let cursor = cursor.ok_or("missing QUIC gateway cursor")?;
        assert_eq!(cursor.inbox_seq, 1);
        assert!(cursor.acked_envelope_ids.contains(&"env_mvp5_quic_gateway".to_owned()));
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    drop(realnet);
    Ok(())
}

#[cfg(feature = "realnet")]
#[test]
fn mvp5_realnet_turn_webrtc_udp_allocate_relay_opaque() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    let _realnet = start_realnet_compose()?;
    let signaling_addr: std::net::SocketAddr =
        std::env::var("RAMFLUX_ITEST_SIGNALING_TURN_UDP_ADDR")
            .unwrap_or_else(|_| "127.0.0.1:3478".to_owned())
            .parse()?;
    let relay_addr: std::net::SocketAddr = std::env::var("RAMFLUX_ITEST_RELAY_MEDIA_UDP_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:19000".to_owned())
        .parse()?;

    let binding = stun_binding_request(signaling_addr)?;
    assert_eq!(binding.message_type, STUN_BINDING_SUCCESS);
    let mapped = binding.xor_mapped_address.ok_or("missing XOR-MAPPED-ADDRESS")?;
    assert_ne!(mapped.port(), 0);

    let allocation = turn_allocate_request(signaling_addr)?;
    assert_eq!(allocation.message_type, TURN_ALLOCATE_SUCCESS);
    let relayed = allocation.xor_relayed_address.ok_or("missing XOR-RELAYED-ADDRESS")?;
    assert_ne!(relayed.port(), 0);
    assert_eq!(allocation.lifetime_secs, Some(600));

    let srtp_key = b"SRTP_MEDIA_KEY_MVP5_TURN_REALNET";
    let opaque_a_to_b = b"ramflux-opaque-srtp-packet:v1:a-to-b:ciphertext-only";
    let opaque_b_to_a = b"ramflux-opaque-srtp-packet:v1:b-to-a:ciphertext-only";
    assert!(!opaque_a_to_b.windows(srtp_key.len()).any(|window| window == srtp_key));
    assert!(!opaque_b_to_a.windows(srtp_key.len()).any(|window| window == srtp_key));

    let service_key = b"ramflux-relay-itest-service-key";
    let token_issued_at =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
    let token_a = mvp5_media_relay_token(
        service_key,
        token_issued_at,
        Mvp5MediaRelayTokenSpec {
            allocation_id: "alloc_mvp5_media_a",
            target_allocation_id: "alloc_mvp5_media_b",
            identity_hash: "alice_media_hash_mvp5",
            peer_hash: "bob_media_hash_mvp5",
        },
    )?;
    let token_b = mvp5_media_relay_token(
        service_key,
        token_issued_at,
        Mvp5MediaRelayTokenSpec {
            allocation_id: "alloc_mvp5_media_b",
            target_allocation_id: "alloc_mvp5_media_a",
            identity_hash: "bob_media_hash_mvp5",
            peer_hash: "alice_media_hash_mvp5",
        },
    )?;
    let socket_a = mvp5_media_socket()?;
    let socket_b = mvp5_media_socket()?;

    mvp5_send_media_relay_packet(&socket_b, relay_addr, &token_b, b"bind-b")?;
    mvp5_send_media_relay_packet(&socket_a, relay_addr, &token_a, opaque_a_to_b)?;
    let relayed_to_b = mvp5_recv_media(&socket_b)?;
    assert_eq!(relayed_to_b, opaque_a_to_b);
    assert!(!relayed_to_b.windows(srtp_key.len()).any(|window| window == srtp_key));

    mvp5_send_media_relay_packet(&socket_b, relay_addr, &token_b, opaque_b_to_a)?;
    let relayed_to_a = mvp5_recv_media(&socket_a)?;
    assert_eq!(relayed_to_a, opaque_b_to_a);
    assert!(!relayed_to_a.windows(srtp_key.len()).any(|window| window == srtp_key));

    let mut forged = token_a.clone();
    forged.mac = "forged".to_owned();
    mvp5_send_media_relay_packet(&socket_a, relay_addr, &forged, b"forged-open-relay")?;
    assert!(mvp5_recv_media_timeout(&socket_b)?.is_none());
    Ok(())
}

#[cfg(feature = "realnet")]
#[derive(Clone, Copy)]
struct Mvp5MediaRelayTokenSpec<'a> {
    allocation_id: &'a str,
    target_allocation_id: &'a str,
    identity_hash: &'a str,
    peer_hash: &'a str,
}

#[cfg(feature = "realnet")]
fn mvp5_media_relay_token(
    service_key: &[u8],
    issued_at: u64,
    spec: Mvp5MediaRelayTokenSpec<'_>,
) -> Result<ramflux_node_core::TurnMediaRelayToken, Box<dyn std::error::Error>> {
    Ok(ramflux_node_core::sign_turn_media_relay_token(
        service_key,
        ramflux_node_core::TurnMediaRelayToken {
            call_id: "call_mvp5_media_relay".to_owned(),
            allocation_id: spec.allocation_id.to_owned(),
            target_allocation_id: spec.target_allocation_id.to_owned(),
            flow_id: "flow_mvp5_media_relay".to_owned(),
            identity_hash: spec.identity_hash.to_owned(),
            peer_hash: spec.peer_hash.to_owned(),
            issued_at,
            expires_at: issued_at + 600,
            nonce: format!("nonce_mvp5_{}_{}", spec.allocation_id, spec.target_allocation_id),
            mac: String::new(),
        },
    )?)
}

#[cfg(feature = "realnet")]
fn mvp5_media_socket() -> Result<std::net::UdpSocket, Box<dyn std::error::Error>> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(std::time::Duration::from_secs(2)))?;
    socket.set_write_timeout(Some(std::time::Duration::from_secs(2)))?;
    Ok(socket)
}

#[cfg(feature = "realnet")]
fn mvp5_send_media_relay_packet(
    socket: &std::net::UdpSocket,
    relay_addr: std::net::SocketAddr,
    token: &ramflux_node_core::TurnMediaRelayToken,
    payload: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let packet = ramflux_node_core::encode_turn_media_relay_packet(
        &ramflux_node_core::TurnMediaRelayPacketHeader { token: token.clone() },
        payload,
    )?;
    socket.send_to(&packet, relay_addr)?;
    Ok(())
}

#[cfg(feature = "realnet")]
fn mvp5_recv_media(socket: &std::net::UdpSocket) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    mvp5_recv_media_timeout(socket)?.ok_or_else(|| "timed out waiting for relayed media".into())
}

#[cfg(feature = "realnet")]
fn mvp5_recv_media_timeout(
    socket: &std::net::UdpSocket,
) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
    let mut response = [0_u8; 2048];
    match socket.recv_from(&mut response) {
        Ok((len, _peer)) => Ok(Some(response[..len].to_vec())),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) =>
        {
            Ok(None)
        }
        Err(error) => Err(error.into()),
    }
}

#[cfg(feature = "realnet")]
#[test]
fn mvp5_realnet_load_gateway_router_concurrent_submit() -> Result<(), Box<dyn std::error::Error>> {
    const CONCURRENCY: usize = 48;
    const TOTAL_ENVELOPES: usize = 384;
    const MIN_THROUGHPUT_ENVELOPES_PER_SEC: f64 = 5.0;

    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    let realnet = start_realnet_compose()?;
    let gateway_url = realnet.gateway_url.clone();
    let target_delivery_id = "target_mvp5_load_router";
    let (sender, receiver) = std::sync::mpsc::channel::<Result<(u64, String), String>>();
    let started = std::time::Instant::now();

    std::thread::scope(|scope| {
        for worker_id in 0..CONCURRENCY {
            let sender = sender.clone();
            let gateway_url = gateway_url.clone();
            scope.spawn(move || {
                for index in (worker_id..TOTAL_ENVELOPES).step_by(CONCURRENCY) {
                    let envelope_id = format!("env_mvp5_load_{index:04}");
                    let envelope = itest_envelope(&envelope_id, target_delivery_id);
                    let result: Result<
                        ramflux_node_core::ItestMvp0SubmitResponse,
                        ramflux_node_core::NodeCoreError,
                    > = ramflux_node_core::itest_http_post_json(
                        &format!("{gateway_url}/mvp0/envelope"),
                        &envelope,
                    );
                    let message = match result {
                        Ok(submit) => {
                            if submit.outcome != "offline_queued" {
                                Err(format!("{envelope_id}: unexpected outcome {}", submit.outcome))
                            } else if submit.target_delivery_id != target_delivery_id {
                                Err(format!(
                                    "{envelope_id}: wrong target {}",
                                    submit.target_delivery_id
                                ))
                            } else {
                                submit
                                    .inbox_seq
                                    .map(|seq| (seq, envelope_id))
                                    .ok_or_else(|| "missing inbox_seq".to_owned())
                            }
                        }
                        Err(error) => Err(format!("{envelope_id}: {error}")),
                    };
                    if sender.send(message).is_err() {
                        return;
                    }
                }
            });
        }
    });
    drop(sender);

    let mut submitted = Vec::with_capacity(TOTAL_ENVELOPES);
    for message in receiver {
        match message {
            Ok(seq_and_id) => submitted.push(seq_and_id),
            Err(error) => return Err(error.into()),
        }
    }
    let elapsed = started.elapsed();
    assert_eq!(submitted.len(), TOTAL_ENVELOPES);

    submitted.sort_by_key(|(seq, _envelope_id)| *seq);
    for (expected_seq, (actual_seq, _envelope_id)) in (1_u64..).zip(submitted.iter()) {
        assert_eq!(*actual_seq, expected_seq);
    }
    let throughput = f64::from(u32::try_from(submitted.len())?) / elapsed.as_secs_f64();
    eprintln!(
        "mvp5 load: concurrency={CONCURRENCY} total={TOTAL_ENVELOPES} elapsed_ms={} throughput_envelopes_per_sec={throughput:.2}",
        elapsed.as_millis()
    );
    assert!(
        throughput >= MIN_THROUGHPUT_ENVELOPES_PER_SEC,
        "throughput {throughput:.2} below floor {MIN_THROUGHPUT_ENVELOPES_PER_SEC:.2}"
    );

    for (expected_seq, (_submit_seq, envelope_id)) in (1_u64..).zip(submitted.iter()) {
        let ack_cursor: ramflux_node_core::ItestMvp0CursorResponse =
            ramflux_node_core::itest_http_post_json(
                &format!("{gateway_url}/mvp0/ack"),
                &itest_ack(envelope_id),
            )?;
        assert_eq!(ack_cursor.inbox_seq, expected_seq);
        assert!(ack_cursor.acked_envelope_ids.contains(envelope_id));
    }

    let cursor: Option<ramflux_node_core::ItestMvp0CursorResponse> =
        ramflux_node_core::itest_http_get_json(&format!(
            "{gateway_url}/mvp0/cursor/{target_delivery_id}"
        ))?;
    let cursor = cursor.ok_or("missing load-test cursor")?;
    assert_eq!(cursor.inbox_seq, u64::try_from(TOTAL_ENVELOPES)?);
    assert_eq!(cursor.acked_envelope_ids.len(), TOTAL_ENVELOPES);
    for (_seq, envelope_id) in &submitted {
        assert!(cursor.acked_envelope_ids.contains(envelope_id));
    }
    Ok(())
}

#[cfg(feature = "realnet")]
const MVP5_PERF_TRANSPORT_SATURATION_RATE: f64 = 0.05;

#[cfg(feature = "realnet")]
#[test]
#[allow(clippy::too_many_lines)]
fn mvp5_perf_realnet_gateway_router_submit_ack_baseline() -> Result<(), Box<dyn std::error::Error>>
{
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet perf test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }
    if std::env::var("RAMFLUX_ITEST_PERF").as_deref() != Ok("1") {
        eprintln!("skipping realnet perf baseline; set RAMFLUX_ITEST_PERF=1");
        return Ok(());
    }

    let realnet = start_realnet_compose()?;
    let gateway_url = realnet.gateway_url.clone();
    let router_url = std::env::var("RAMFLUX_ITEST_ROUTER_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:18080".to_owned());
    let plan = Mvp5PerfPlan::from_env()?;
    let deploy_root = code_root().join("ramflux/deploy");
    mvp5_perf_reset_metrics(&gateway_url, &router_url)?;
    let sampler = Mvp5ContainerStatsSampler::start(deploy_root);
    let warmup = mvp5_perf_warmup(&gateway_url, plan.warmup_concurrency, plan.warmup_duration);
    mvp5_perf_reset_metrics(&gateway_url, &router_url)?;

    let artifact = mvp5_perf_artifact_path("mvp5_gateway_router_load_latest.json")?;
    let generated_at_unix = mvp5_perf_now_unix_seconds()?;
    let mut stages = Vec::new();
    mvp5_perf_write_artifact(Mvp5PerfArtifactContext {
        artifact: &artifact,
        generated_at_unix,
        warmup: &warmup,
        stages: &stages,
        plan: &plan,
        gateway_url: &gateway_url,
        router_url: &router_url,
        stats_samples: &sampler.snapshot(),
    })?;
    for config in plan.stage_configs() {
        let stage = mvp5_perf_run_stage(&gateway_url, &config)?;
        eprintln!("RAMFLUX_PERF_STAGE {}", serde_json::to_string(&stage)?);
        let saturated = stage.saturated;
        let stage_name = stage.name.clone();
        stages.push(stage);
        mvp5_perf_write_artifact(Mvp5PerfArtifactContext {
            artifact: &artifact,
            generated_at_unix,
            warmup: &warmup,
            stages: &stages,
            plan: &plan,
            gateway_url: &gateway_url,
            router_url: &router_url,
            stats_samples: &sampler.snapshot(),
        })?;
        if saturated {
            eprintln!("mvp5 perf baseline saturated at stage={stage_name}; stopping higher load");
            break;
        }
    }
    let stats_samples = sampler.stop();
    mvp5_perf_write_artifact(Mvp5PerfArtifactContext {
        artifact: &artifact,
        generated_at_unix,
        warmup: &warmup,
        stages: &stages,
        plan: &plan,
        gateway_url: &gateway_url,
        router_url: &router_url,
        stats_samples: &stats_samples,
    })?;
    eprintln!("mvp5 perf baseline artifact={}", artifact.display());
    Ok(())
}

#[cfg(feature = "realnet")]
#[test]
#[allow(clippy::too_many_lines)]
fn mvp5_perf_realnet_quic_gateway_router_load() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet QUIC perf test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }
    if std::env::var("RAMFLUX_ITEST_PERF").as_deref() != Ok("1") {
        eprintln!("skipping realnet QUIC perf load; set RAMFLUX_ITEST_PERF=1");
        return Ok(());
    }

    let gateway_compio = std::env::var("RAMFLUX_GATEWAY_COMPIO").as_deref() == Ok("1");
    let realnet = start_realnet_compose_with_env_and_gateway_compio(&[], gateway_compio)?;
    let gateway_url = realnet.gateway_url.clone();
    let router_url = std::env::var("RAMFLUX_ITEST_ROUTER_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:18080".to_owned());
    let gateway_quic_addr: std::net::SocketAddr = std::env::var("RAMFLUX_ITEST_GATEWAY_QUIC_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:18443".to_owned())
        .parse()?;
    let ca_cert = code_root().join("ramflux/deploy/certs/ca.pem");
    let plan = Mvp5PerfPlan::from_env()?;
    let deploy_root = code_root().join("ramflux/deploy");
    mvp5_perf_reset_metrics(&gateway_url, &router_url)?;
    let sampler = Mvp5ContainerStatsSampler::start(deploy_root);

    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    let clients = runtime.block_on(mvp5_perf_connect_quic_clients(
        gateway_quic_addr,
        &ca_cert,
        plan.quic_connections,
    ))?;
    let warmup = runtime.block_on(mvp5_perf_quic_warmup(
        &clients,
        plan.warmup_concurrency,
        plan.warmup_duration,
    ));
    mvp5_perf_reset_metrics(&gateway_url, &router_url)?;

    let artifact = mvp5_perf_artifact_path("mvp5_quic_gateway_router_load_latest.json")?;
    let generated_at_unix = mvp5_perf_now_unix_seconds()?;
    let mut stages = Vec::new();
    mvp5_perf_write_artifact(Mvp5PerfArtifactContext {
        artifact: &artifact,
        generated_at_unix,
        warmup: &warmup,
        stages: &stages,
        plan: &plan,
        gateway_url: &gateway_url,
        router_url: &router_url,
        stats_samples: &sampler.snapshot(),
    })?;
    for config in plan.stage_configs() {
        let stage = runtime.block_on(mvp5_perf_run_quic_stage(&clients, &config))?;
        eprintln!("RAMFLUX_PERF_STAGE {}", serde_json::to_string(&stage)?);
        let saturated = stage.saturated;
        let stage_name = stage.name.clone();
        stages.push(stage);
        mvp5_perf_write_artifact(Mvp5PerfArtifactContext {
            artifact: &artifact,
            generated_at_unix,
            warmup: &warmup,
            stages: &stages,
            plan: &plan,
            gateway_url: &gateway_url,
            router_url: &router_url,
            stats_samples: &sampler.snapshot(),
        })?;
        if saturated {
            eprintln!("mvp5 QUIC perf load saturated at stage={stage_name}; stopping higher load");
            break;
        }
    }
    let stats_samples = sampler.stop();
    mvp5_perf_write_artifact(Mvp5PerfArtifactContext {
        artifact: &artifact,
        generated_at_unix,
        warmup: &warmup,
        stages: &stages,
        plan: &plan,
        gateway_url: &gateway_url,
        router_url: &router_url,
        stats_samples: &stats_samples,
    })?;
    eprintln!("mvp5 QUIC perf load artifact={}", artifact.display());
    Ok(())
}

#[cfg(feature = "realnet")]
#[test]
#[allow(clippy::too_many_lines)]
fn mvp_s8_perf_realnet_federation_forward_load() -> Result<(), Box<dyn std::error::Error>> {
    const PORT_BASE: u16 = 62_000;

    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet federation perf test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }
    if std::env::var("RAMFLUX_ITEST_PERF").as_deref() != Ok("1") {
        eprintln!("skipping realnet federation perf load; set RAMFLUX_ITEST_PERF=1");
        return Ok(());
    }

    let source_ports = S8ComposePorts {
        gateway_http: PORT_BASE + 181,
        gateway_quic: PORT_BASE + 451,
        router_http: PORT_BASE + 180,
        router_mesh: PORT_BASE + 452,
        notify_http: PORT_BASE + 183,
        federation_http: PORT_BASE + 182,
        federation_mesh: PORT_BASE + 453,
        relay_http: PORT_BASE + 184,
        relay_media_udp: PORT_BASE + 100,
        signaling_turn_udp: PORT_BASE + 478,
        signaling_turn_tcp: PORT_BASE + 479,
        retention_http: PORT_BASE + 187,
    };
    let destination_ports = S8ComposePorts {
        gateway_http: PORT_BASE + 1_181,
        gateway_quic: PORT_BASE + 1_451,
        router_http: PORT_BASE + 1_180,
        router_mesh: PORT_BASE + 1_452,
        notify_http: PORT_BASE + 1_183,
        federation_http: PORT_BASE + 1_182,
        federation_mesh: PORT_BASE + 1_453,
        relay_http: PORT_BASE + 1_184,
        relay_media_udp: PORT_BASE + 1_100,
        signaling_turn_udp: PORT_BASE + 1_478,
        signaling_turn_tcp: PORT_BASE + 1_479,
        retention_http: PORT_BASE + 1_187,
    };
    let node_a =
        start_s8_realnet_compose_project("ramflux-s8-perf-node-a-forward-load", source_ports)?;
    let node_b =
        start_s8_realnet_compose_project("ramflux-s8-perf-node-b-forward-load", destination_ports)?;
    mvp_s8_establish_trusted_links(&node_a, &node_b)?;
    mvp_s8_perf_assert_mesh_quic_ready(&node_a)?;
    mvp_s8_perf_assert_mesh_quic_ready(&node_b)?;

    let node_b_router_url = format!("http://127.0.0.1:{}", destination_ports.router_http);
    let plan = Mvp5PerfPlan::from_env()?;
    mvp5_perf_reset_metrics(&node_a.gateway_url, &node_b_router_url)?;
    let sampler = Mvp5ContainerStatsSampler::start(code_root().join("ramflux/deploy"));
    let warmup = mvp_s8_perf_federation_warmup(
        &node_a.federation_url,
        &node_a.node_id,
        &node_b.node_id,
        plan.warmup_concurrency,
        plan.warmup_duration,
    );
    mvp5_perf_reset_metrics(&node_a.gateway_url, &node_b_router_url)?;

    let artifact = mvp5_perf_artifact_path("mvp_s8_federation_forward_load_latest.json")?;
    let generated_at_unix = mvp5_perf_now_unix_seconds()?;
    let mut stages = Vec::new();
    mvp5_perf_write_artifact(Mvp5PerfArtifactContext {
        artifact: &artifact,
        generated_at_unix,
        warmup: &warmup,
        stages: &stages,
        plan: &plan,
        gateway_url: &node_a.gateway_url,
        router_url: &node_b_router_url,
        stats_samples: &sampler.snapshot(),
    })?;
    for config in plan.stage_configs() {
        let stage = mvp_s8_perf_run_federation_stage(&node_a, &node_b, &config)?;
        eprintln!("RAMFLUX_PERF_STAGE {}", serde_json::to_string(&stage)?);
        let saturated = stage.saturated;
        let stage_name = stage.name.clone();
        stages.push(stage);
        mvp5_perf_write_artifact(Mvp5PerfArtifactContext {
            artifact: &artifact,
            generated_at_unix,
            warmup: &warmup,
            stages: &stages,
            plan: &plan,
            gateway_url: &node_a.gateway_url,
            router_url: &node_b_router_url,
            stats_samples: &sampler.snapshot(),
        })?;
        if saturated {
            eprintln!(
                "mvp_s8 federation forward perf load saturated at stage={stage_name}; stopping higher load"
            );
            break;
        }
    }
    let stats_samples = sampler.stop();
    mvp5_perf_write_artifact(Mvp5PerfArtifactContext {
        artifact: &artifact,
        generated_at_unix,
        warmup: &warmup,
        stages: &stages,
        plan: &plan,
        gateway_url: &node_a.gateway_url,
        router_url: &node_b_router_url,
        stats_samples: &stats_samples,
    })?;
    eprintln!("mvp_s8 federation forward perf load artifact={}", artifact.display());
    Ok(())
}

#[cfg(feature = "realnet")]
#[test]
#[allow(clippy::too_many_lines)]
fn mvp_s8_perf_realnet_federation_envelope_inbound_load() -> Result<(), Box<dyn std::error::Error>>
{
    const PORT_BASE: u16 = 64_000;
    const NODE_A_PROJECT: &str = "ramflux-s8-perf-node-a-inbound-load";
    const NODE_B_PROJECT: &str = "ramflux-s8-perf-node-b-inbound-load";

    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!(
            "skipping realnet federation mesh inbound perf test; set RAMFLUX_ITEST_REALNET=1"
        );
        return Ok(());
    }
    if std::env::var("RAMFLUX_ITEST_PERF").as_deref() != Ok("1") {
        eprintln!("skipping realnet federation mesh inbound perf load; set RAMFLUX_ITEST_PERF=1");
        return Ok(());
    }

    let source_ports = S8ComposePorts {
        gateway_http: PORT_BASE + 181,
        gateway_quic: PORT_BASE + 451,
        router_http: PORT_BASE + 180,
        router_mesh: PORT_BASE + 452,
        notify_http: PORT_BASE + 183,
        federation_http: PORT_BASE + 182,
        federation_mesh: PORT_BASE + 453,
        relay_http: PORT_BASE + 184,
        relay_media_udp: PORT_BASE + 100,
        signaling_turn_udp: PORT_BASE + 478,
        signaling_turn_tcp: PORT_BASE + 479,
        retention_http: PORT_BASE + 187,
    };
    let destination_ports = S8ComposePorts {
        gateway_http: PORT_BASE + 1_181,
        gateway_quic: PORT_BASE + 1_451,
        router_http: PORT_BASE + 1_180,
        router_mesh: PORT_BASE + 1_452,
        notify_http: PORT_BASE + 1_183,
        federation_http: PORT_BASE + 1_182,
        federation_mesh: PORT_BASE + 1_453,
        relay_http: PORT_BASE + 1_184,
        relay_media_udp: PORT_BASE + 1_100,
        signaling_turn_udp: PORT_BASE + 1_478,
        signaling_turn_tcp: PORT_BASE + 1_479,
        retention_http: PORT_BASE + 1_187,
    };
    let node_a = start_s8_realnet_compose_project(NODE_A_PROJECT, source_ports)?;
    let destination_federation_compio =
        std::env::var("RAMFLUX_FEDERATION_COMPIO").as_deref() == Ok("1");
    let node_b = start_s8_realnet_compose_project_with_env_and_federation_compio(
        NODE_B_PROJECT,
        destination_ports,
        &[],
        destination_federation_compio,
    )?;
    mvp_s8_establish_trusted_links(&node_a, &node_b)?;
    mvp_s8_perf_assert_mesh_quic_ready(&node_b)?;

    let plan = Mvp5PerfPlan::from_env()?;
    let node_b_router_url = format!("http://127.0.0.1:{}", destination_ports.router_http);
    let target_cardinality = mvp5_perf_env_usize("RAMFLUX_S8_PERF_TARGET_CARDINALITY", 1)?;
    mvp5_perf_reset_metrics(&node_a.gateway_url, &node_b_router_url)?;
    let sampler = Mvp5ContainerStatsSampler::start(code_root().join("ramflux/deploy"));
    let endpoint = format!("127.0.0.1:{}", destination_ports.federation_mesh);
    let source_tls = mvp_s8_perf_federation_tls(NODE_A_PROJECT);
    let destination_ca_pem = std::fs::read_to_string(&node_b.ca_cert)?;
    let peer_ca_pems = vec![destination_ca_pem];
    let inbound_context = MvpS8PerfInboundContext {
        endpoint: endpoint.clone(),
        source_tls: source_tls.clone(),
        peer_ca_pems: peer_ca_pems.clone(),
        source_node_id: node_a.node_id.clone(),
        target_node_id: node_b.node_id.clone(),
        router_url: node_b_router_url.clone(),
        target_cardinality,
    };
    let warmup = mvp_s8_perf_federation_inbound_warmup(
        &inbound_context,
        plan.warmup_concurrency,
        plan.warmup_duration,
    );
    mvp5_perf_reset_metrics(&node_a.gateway_url, &node_b_router_url)?;

    let artifact = mvp5_perf_artifact_path("mvp_s8_federation_envelope_inbound_load_latest.json")?;
    let generated_at_unix = mvp5_perf_now_unix_seconds()?;
    let mut stages = Vec::new();
    mvp5_perf_write_artifact(Mvp5PerfArtifactContext {
        artifact: &artifact,
        generated_at_unix,
        warmup: &warmup,
        stages: &stages,
        plan: &plan,
        gateway_url: &node_a.gateway_url,
        router_url: &node_b_router_url,
        stats_samples: &sampler.snapshot(),
    })?;
    for config in plan.stage_configs() {
        let stage =
            mvp_s8_perf_run_federation_inbound_stage(&inbound_context, &node_a, &node_b, &config)?;
        eprintln!("RAMFLUX_PERF_STAGE {}", serde_json::to_string(&stage)?);
        let saturated = stage.saturated;
        let stage_name = stage.name.clone();
        stages.push(stage);
        mvp5_perf_write_artifact(Mvp5PerfArtifactContext {
            artifact: &artifact,
            generated_at_unix,
            warmup: &warmup,
            stages: &stages,
            plan: &plan,
            gateway_url: &node_a.gateway_url,
            router_url: &node_b_router_url,
            stats_samples: &sampler.snapshot(),
        })?;
        if saturated {
            eprintln!(
                "mvp_s8 federation mesh inbound perf load saturated at stage={stage_name}; stopping higher load"
            );
            break;
        }
    }
    let stats_samples = sampler.stop();
    mvp5_perf_write_artifact(Mvp5PerfArtifactContext {
        artifact: &artifact,
        generated_at_unix,
        warmup: &warmup,
        stages: &stages,
        plan: &plan,
        gateway_url: &node_a.gateway_url,
        router_url: &node_b_router_url,
        stats_samples: &stats_samples,
    })?;
    eprintln!("mvp_s8 federation mesh inbound perf load artifact={}", artifact.display());
    Ok(())
}

#[cfg(feature = "realnet")]
#[derive(Clone, Copy)]
struct Mvp5PerfArtifactContext<'a> {
    artifact: &'a std::path::Path,
    generated_at_unix: u64,
    warmup: &'a serde_json::Value,
    stages: &'a [Mvp5PerfStageReport],
    plan: &'a Mvp5PerfPlan,
    gateway_url: &'a str,
    router_url: &'a str,
    stats_samples: &'a [serde_json::Value],
}

#[cfg(feature = "realnet")]
fn mvp5_perf_write_artifact(
    context: Mvp5PerfArtifactContext<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let gateway_metrics = mvp5_perf_get_json_or_error(
        &format!("{}/perf/metrics", context.gateway_url),
        "gateway_metrics",
    );
    let router_metrics = mvp5_perf_get_json_or_error(
        &format!("{}/perf/metrics", context.router_url),
        "router_metrics",
    );
    let report = serde_json::json!({
        "schema": "ramflux.mvp5_gateway_router_load.v2",
        "baseline_note": "gateway-to-router submit/ack load harness; transport error-rate is measured and does not fail the harness; correctness violations still fail",
        "generated_at_unix": context.generated_at_unix,
        "plan": context.plan,
        "warmup": context.warmup,
        "stages": context.stages,
        "gateway_metrics": gateway_metrics,
        "router_metrics": router_metrics,
        "test_process_transport_metrics": ramflux_transport::mesh_perf_snapshot(),
        "container_stats_samples": context.stats_samples,
        "derived": {
            "gateway_mesh_handshake_ratio": mvp5_perf_ratio(
                gateway_metrics.pointer("/transport/mesh_client_tls_handshakes_total"),
                gateway_metrics.pointer("/transport/mesh_client_requests_total")
            ),
            "router_replay_guard_writes_per_envelope": mvp5_perf_ratio(
                router_metrics.pointer("/node/router_replay_guard_redb_writes_total"),
                router_metrics.pointer("/node/router_envelope_accepted_total")
            ),
            "federation_inbound_diagnosis": mvp5_perf_federation_inbound_diagnosis(
                context.stages,
                &router_metrics
            )
        }
    });
    std::fs::write(context.artifact, serde_json::to_vec_pretty(&report)?)?;
    Ok(())
}

#[cfg(feature = "realnet")]
fn mvp5_perf_get_json_or_error(url: &str, label: &str) -> serde_json::Value {
    match ramflux_node_core::itest_http_get_json::<serde_json::Value>(url) {
        Ok(value) => value,
        Err(error) => serde_json::json!({
            "error": true,
            "label": label,
            "category": mvp5_perf_transport_error_category(label, &error.to_string()),
            "sample": mvp5_perf_error_sample(error.to_string()),
        }),
    }
}

#[cfg(feature = "realnet")]
#[derive(Clone, Debug, serde::Serialize)]
struct Mvp5PerfPlan {
    concurrency: Vec<usize>,
    total_requests: Option<usize>,
    duration_secs: Option<u64>,
    quic_connections: usize,
    warmup_concurrency: usize,
    warmup_duration_secs: u64,
    #[serde(skip)]
    warmup_duration: std::time::Duration,
}

#[cfg(feature = "realnet")]
impl Mvp5PerfPlan {
    fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        let concurrency = mvp5_perf_env_usize_list("RAMFLUX_PERF_CONCURRENCY", &[48])?;
        let total_requests = mvp5_perf_env_optional_usize("RAMFLUX_PERF_TOTAL_REQUESTS")?;
        let duration_secs = mvp5_perf_env_optional_u64("RAMFLUX_PERF_DURATION_SECS")?;
        let quic_connections = mvp5_perf_env_usize("RAMFLUX_PERF_QUIC_CONNECTIONS", 1)?;
        let warmup_concurrency = mvp5_perf_env_usize("RAMFLUX_PERF_WARMUP_CONCURRENCY", 16)?;
        let warmup_duration_secs = mvp5_perf_env_u64("RAMFLUX_PERF_WARMUP_SECS", 15)?;
        Ok(Self {
            concurrency,
            total_requests: total_requests.or_else(|| duration_secs.is_none().then_some(1_000)),
            duration_secs,
            quic_connections,
            warmup_concurrency,
            warmup_duration_secs,
            warmup_duration: std::time::Duration::from_secs(warmup_duration_secs),
        })
    }

    fn stage_configs(&self) -> Vec<Mvp5PerfStageConfig> {
        self.concurrency
            .iter()
            .copied()
            .map(|concurrency| Mvp5PerfStageConfig {
                name: mvp5_perf_stage_name(concurrency, self.total_requests, self.duration_secs),
                concurrency,
                total_requests: self.total_requests,
                duration: self.duration_secs.map(std::time::Duration::from_secs),
            })
            .collect()
    }
}

#[cfg(feature = "realnet")]
#[derive(Clone, Debug)]
struct Mvp5PerfStageConfig {
    name: String,
    concurrency: usize,
    total_requests: Option<usize>,
    duration: Option<std::time::Duration>,
}

#[cfg(feature = "realnet")]
#[derive(Clone, Debug, serde::Serialize)]
struct Mvp5PerfStageReport {
    name: String,
    concurrency: usize,
    total_envelopes: usize,
    configured_total_requests: Option<usize>,
    configured_duration_ms: Option<u128>,
    successful_pairs: usize,
    saturated: bool,
    saturation_threshold: f64,
    error_rate: f64,
    elapsed_ms: u128,
    throughput_envelopes_per_sec: f64,
    attempted_throughput_envelopes_per_sec: f64,
    submit_latency: Mvp5LatencySummary,
    ack_latency: Mvp5LatencySummary,
    transport_error_counts: std::collections::BTreeMap<String, u64>,
    transport_error_rates: std::collections::BTreeMap<String, f64>,
    transport_error_samples: std::collections::BTreeMap<String, String>,
    correctness: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    deduped_idempotent_retries: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    federation_mesh_transport: Option<MvpS8PerfFederationTransportReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    federation_receive_perf: Option<MvpS8PerfFederationReceivePerfReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    router_submit_perf: Option<Mvp5PerfRouterSubmitDelta>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_mesh_transport: Option<Mvp5PerfMeshTransportDelta>,
    #[serde(skip_serializing_if = "Option::is_none")]
    federation_server_mesh_transport: Option<Mvp5PerfMeshTransportDelta>,
    baseline_note: String,
}

#[cfg(feature = "realnet")]
#[derive(Clone, Debug, serde::Serialize)]
struct MvpS8PerfFederationTransportReport {
    quic_inbound_delta: u64,
    tcp_inbound_delta: u64,
    total_inbound_delta: u64,
    tcp_fallback_rate: f64,
}

#[cfg(feature = "realnet")]
#[derive(Clone, Debug, serde::Serialize)]
struct MvpS8PerfFederationReceivePerfReport {
    total: MvpS8PerfTimingDelta,
    target_check: MvpS8PerfTimingDelta,
    trust_snapshot: MvpS8PerfTimingDelta,
    policy_check: MvpS8PerfTimingDelta,
    pin_lookup: MvpS8PerfTimingDelta,
    signature_verify: MvpS8PerfTimingDelta,
    signature_body: MvpS8PerfTimingDelta,
    signature_signature_parse: MvpS8PerfTimingDelta,
    signature_key_parse: MvpS8PerfTimingDelta,
    signature_ed25519_verify: MvpS8PerfTimingDelta,
    router_post: MvpS8PerfTimingDelta,
}

#[cfg(feature = "realnet")]
#[derive(Clone, Debug, serde::Serialize)]
struct MvpS8PerfTimingDelta {
    count_delta: u64,
    total_us_delta: u64,
    avg_us_delta: Option<f64>,
    cumulative_max_us: u64,
}

#[cfg(feature = "realnet")]
#[derive(Clone, Debug, serde::Serialize)]
struct Mvp5PerfMeshTransportDelta {
    requests_delta: u64,
    tls_handshakes_delta: u64,
    connect_count_delta: u64,
    connect_ms_delta: u64,
    pool_hits_delta: u64,
    pool_misses_delta: u64,
    pool_idle_evictions_delta: u64,
    cached_request_failures_delta: u64,
    retries_delta: u64,
    retry_successes_delta: u64,
    retry_failures_delta: u64,
    request_timeouts_delta: u64,
    exchange_count_delta: u64,
    exchange_us_delta: u64,
    exchange_avg_us: Option<f64>,
    runtime_jobs_dequeued_delta: u64,
    runtime_queue_wait_us_delta: u64,
    runtime_queue_wait_avg_us: Option<f64>,
    server_quic_connections_accepted_delta: u64,
    server_quic_streams_accepted_delta: u64,
    server_quic_stream_accept_us_delta: u64,
    server_quic_stream_accept_avg_us: Option<f64>,
    server_quic_request_read_us_delta: u64,
    server_quic_request_read_avg_us: Option<f64>,
    server_quic_response_write_us_delta: u64,
    server_quic_response_write_avg_us: Option<f64>,
    cached_request_failure_rate: Option<f64>,
    request_timeout_rate: Option<f64>,
}

#[cfg(feature = "realnet")]
#[derive(Clone, Debug, serde::Serialize)]
struct Mvp5PerfRouterSubmitDelta {
    envelope_accepted_delta: u64,
    submit_total_us_delta: u64,
    submit_total_avg_us: Option<f64>,
    submit_decode_avg_us: Option<f64>,
    submit_dispatch_avg_us: Option<f64>,
    submit_save_avg_us: Option<f64>,
    submit_response_avg_us: Option<f64>,
    replay_guard_check_avg_us: Option<f64>,
    save_total_avg_us: Option<f64>,
    save_inbox_avg_us: Option<f64>,
    save_replay_guard_avg_us: Option<f64>,
    save_begin_write_avg_us: Option<f64>,
    save_mutation_avg_us: Option<f64>,
    save_commit_avg_us: Option<f64>,
    target_local_delta: u64,
    target_remote_delta: u64,
    target_same_core_rate: Option<f64>,
    target_local_avg_us: Option<f64>,
    target_remote_avg_us: Option<f64>,
}

#[cfg(feature = "realnet")]
#[derive(Clone)]
struct MvpS8PerfInboundContext {
    endpoint: String,
    source_tls: ramflux_transport::MeshTlsConfig,
    peer_ca_pems: Vec<String>,
    source_node_id: String,
    target_node_id: String,
    router_url: String,
    target_cardinality: usize,
}

#[cfg(feature = "realnet")]
#[derive(Clone, Debug, serde::Serialize)]
struct Mvp5LatencySummary {
    count: usize,
    p50_us: u128,
    p95_us: u128,
    p99_us: u128,
    max_us: u128,
}

#[cfg(feature = "realnet")]
#[derive(Clone, Debug)]
struct Mvp5PerfResult {
    seq: u64,
    envelope_id: String,
    submit_us: u128,
    ack_us: u128,
}

#[cfg(feature = "realnet")]
#[derive(Clone, Debug)]
enum Mvp5PerfMessage {
    Success(Mvp5PerfResult),
    BenignEvent { category: String, sample: String },
    TransportError { category: String, sample: String },
    CorrectnessError { category: String, sample: String },
}

#[cfg(feature = "realnet")]
fn mvp5_perf_warmup(
    gateway_url: &str,
    concurrency: usize,
    duration: std::time::Duration,
) -> serde_json::Value {
    let deadline = std::time::Instant::now() + duration;
    let counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    std::thread::scope(|scope| {
        for worker_id in 0..concurrency {
            let gateway_url = gateway_url.to_owned();
            let counter = std::sync::Arc::clone(&counter);
            scope.spawn(move || {
                while std::time::Instant::now() < deadline {
                    let index = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let envelope_id = format!("env_mvp5_perf_warmup_{worker_id}_{index}");
                    let envelope = itest_envelope(&envelope_id, "target_mvp5_perf_warmup");
                    let Ok(submit) = ramflux_node_core::itest_http_post_json::<
                        _,
                        ramflux_node_core::ItestMvp0SubmitResponse,
                    >(
                        &format!("{gateway_url}/mvp0/envelope"), &envelope
                    ) else {
                        continue;
                    };
                    if submit.outcome == "offline_queued" {
                        let _ = ramflux_node_core::itest_http_post_json::<
                            _,
                            ramflux_node_core::ItestMvp0CursorResponse,
                        >(
                            &format!("{gateway_url}/mvp0/ack"), &itest_ack(&envelope_id)
                        );
                    }
                }
            });
        }
    });
    serde_json::json!({
        "concurrency": concurrency,
        "duration_ms": duration.as_millis(),
        "attempted_envelopes": counter.load(std::sync::atomic::Ordering::Relaxed)
    })
}

#[cfg(feature = "realnet")]
async fn mvp5_perf_connect_quic_clients(
    gateway_quic_addr: std::net::SocketAddr,
    ca_cert: &std::path::Path,
    connections: usize,
) -> Result<Vec<std::sync::Arc<ramflux_transport::QuicGatewayClient>>, Box<dyn std::error::Error>> {
    let mut clients = Vec::with_capacity(connections);
    for _index in 0..connections {
        let client = ramflux_transport::QuicGatewayClient::connect(
            "0.0.0.0:0".parse()?,
            gateway_quic_addr,
            "localhost",
            ca_cert,
            std::time::Duration::from_secs(10),
        )
        .await?;
        clients.push(std::sync::Arc::new(client));
    }
    Ok(clients)
}

#[cfg(feature = "realnet")]
async fn mvp5_perf_quic_warmup(
    clients: &[std::sync::Arc<ramflux_transport::QuicGatewayClient>],
    concurrency: usize,
    duration: std::time::Duration,
) -> serde_json::Value {
    let deadline = tokio::time::Instant::now() + duration;
    let counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut tasks = tokio::task::JoinSet::new();
    for worker_id in 0..concurrency {
        let client = std::sync::Arc::clone(&clients[worker_id % clients.len()]);
        let counter = std::sync::Arc::clone(&counter);
        tasks.spawn(async move {
            while tokio::time::Instant::now() < deadline {
                let index = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let envelope_id = format!("env_mvp5_perf_quic_warmup_{worker_id}_{index}");
                let envelope = itest_envelope(&envelope_id, "target_mvp5_perf_quic_warmup");
                let Ok(submit) = client
                    .post_json::<_, ramflux_node_core::ItestMvp0SubmitResponse>(
                        "/mvp0/envelope",
                        &envelope,
                    )
                    .await
                else {
                    continue;
                };
                if submit.outcome == "offline_queued" {
                    let _ = client
                        .post_json::<_, ramflux_node_core::ItestMvp0CursorResponse>(
                            "/mvp0/ack",
                            &itest_ack(&envelope_id),
                        )
                        .await;
                }
            }
        });
    }
    while tasks.join_next().await.is_some() {}
    serde_json::json!({
        "transport": "quic_gateway",
        "connections": clients.len(),
        "concurrency": concurrency,
        "duration_ms": duration.as_millis(),
        "attempted_envelopes": counter.load(std::sync::atomic::Ordering::Relaxed)
    })
}

#[cfg(feature = "realnet")]
#[derive(serde::Deserialize)]
struct MvpS8PerfMeshObservabilitySnapshot {
    quic_listener_ready: bool,
    quic_listener_local_addr: Option<String>,
    quic_listener_last_error: Option<String>,
    tcp_inbound_s8_envelopes: u64,
    quic_inbound_s8_envelopes: u64,
    receive_perf: MvpS8PerfReceivePerfSnapshot,
    transport_perf: ramflux_transport::MeshHttpPerfSnapshot,
}

#[cfg(feature = "realnet")]
#[derive(serde::Deserialize)]
struct MvpS8PerfReceivePerfSnapshot {
    total: MvpS8PerfTimingSnapshot,
    target_check: MvpS8PerfTimingSnapshot,
    trust_snapshot: MvpS8PerfTimingSnapshot,
    policy_check: MvpS8PerfTimingSnapshot,
    pin_lookup: MvpS8PerfTimingSnapshot,
    signature_verify: MvpS8PerfTimingSnapshot,
    signature_body: MvpS8PerfTimingSnapshot,
    signature_signature_parse: MvpS8PerfTimingSnapshot,
    signature_key_parse: MvpS8PerfTimingSnapshot,
    signature_ed25519_verify: MvpS8PerfTimingSnapshot,
    router_post: MvpS8PerfTimingSnapshot,
}

#[cfg(feature = "realnet")]
#[derive(serde::Deserialize)]
struct MvpS8PerfTimingSnapshot {
    count: u64,
    total_us: u64,
    max_us: u64,
}

#[cfg(feature = "realnet")]
fn mvp_s8_perf_mesh_observability(
    node: &S8RealnetNode,
) -> Result<MvpS8PerfMeshObservabilitySnapshot, Box<dyn std::error::Error>> {
    Ok(ramflux_node_core::itest_http_get_json(&format!(
        "{}/s8/federation/mesh-observability",
        node.federation_url
    ))?)
}

#[cfg(feature = "realnet")]
fn mvp_s8_perf_assert_mesh_quic_ready(
    node: &S8RealnetNode,
) -> Result<(), Box<dyn std::error::Error>> {
    let snapshot = mvp_s8_perf_mesh_observability(node)?;
    assert!(
        snapshot.quic_listener_ready,
        "node {} expected federation perf mesh QUIC listener ready, addr={:?}, error={:?}",
        node.node_id, snapshot.quic_listener_local_addr, snapshot.quic_listener_last_error
    );
    Ok(())
}

#[cfg(feature = "realnet")]
fn mvp_s8_perf_receive_delta(
    before: &MvpS8PerfReceivePerfSnapshot,
    after: &MvpS8PerfReceivePerfSnapshot,
) -> Result<MvpS8PerfFederationReceivePerfReport, Box<dyn std::error::Error>> {
    Ok(MvpS8PerfFederationReceivePerfReport {
        total: mvp_s8_perf_timing_delta(&before.total, &after.total)?,
        target_check: mvp_s8_perf_timing_delta(&before.target_check, &after.target_check)?,
        trust_snapshot: mvp_s8_perf_timing_delta(&before.trust_snapshot, &after.trust_snapshot)?,
        policy_check: mvp_s8_perf_timing_delta(&before.policy_check, &after.policy_check)?,
        pin_lookup: mvp_s8_perf_timing_delta(&before.pin_lookup, &after.pin_lookup)?,
        signature_verify: mvp_s8_perf_timing_delta(
            &before.signature_verify,
            &after.signature_verify,
        )?,
        signature_body: mvp_s8_perf_timing_delta(&before.signature_body, &after.signature_body)?,
        signature_signature_parse: mvp_s8_perf_timing_delta(
            &before.signature_signature_parse,
            &after.signature_signature_parse,
        )?,
        signature_key_parse: mvp_s8_perf_timing_delta(
            &before.signature_key_parse,
            &after.signature_key_parse,
        )?,
        signature_ed25519_verify: mvp_s8_perf_timing_delta(
            &before.signature_ed25519_verify,
            &after.signature_ed25519_verify,
        )?,
        router_post: mvp_s8_perf_timing_delta(&before.router_post, &after.router_post)?,
    })
}

#[cfg(feature = "realnet")]
fn mvp_s8_perf_timing_delta(
    before: &MvpS8PerfTimingSnapshot,
    after: &MvpS8PerfTimingSnapshot,
) -> Result<MvpS8PerfTimingDelta, Box<dyn std::error::Error>> {
    let count_delta = after.count.saturating_sub(before.count);
    let total_us_delta = after.total_us.saturating_sub(before.total_us);
    let avg_us_delta = if count_delta == 0 {
        None
    } else {
        Some(f64::from(u32::try_from(total_us_delta)?) / f64::from(u32::try_from(count_delta)?))
    };
    Ok(MvpS8PerfTimingDelta {
        count_delta,
        total_us_delta,
        avg_us_delta,
        cumulative_max_us: after.max_us,
    })
}

#[cfg(feature = "realnet")]
fn mvp5_perf_mesh_transport_delta(
    before: &ramflux_transport::MeshHttpPerfSnapshot,
    after: &ramflux_transport::MeshHttpPerfSnapshot,
) -> Result<Mvp5PerfMeshTransportDelta, Box<dyn std::error::Error>> {
    let requests_delta =
        after.mesh_client_requests_total.saturating_sub(before.mesh_client_requests_total);
    let pool_hits_delta =
        after.mesh_client_pool_hits_total.saturating_sub(before.mesh_client_pool_hits_total);
    let cached_request_failures_delta = after
        .mesh_client_cached_request_failures_total
        .saturating_sub(before.mesh_client_cached_request_failures_total);
    let request_timeouts_delta = after
        .mesh_client_request_timeouts_total
        .saturating_sub(before.mesh_client_request_timeouts_total);
    let exchange_count_delta =
        after.mesh_client_exchange_count.saturating_sub(before.mesh_client_exchange_count);
    let exchange_us_delta =
        after.mesh_client_exchange_us_total.saturating_sub(before.mesh_client_exchange_us_total);
    let runtime_jobs_dequeued_delta = after
        .mesh_client_runtime_jobs_dequeued_total
        .saturating_sub(before.mesh_client_runtime_jobs_dequeued_total);
    let runtime_queue_wait_us_delta = after
        .mesh_client_runtime_queue_wait_us_total
        .saturating_sub(before.mesh_client_runtime_queue_wait_us_total);
    let server_quic_streams_accepted_delta = after
        .mesh_server_quic_streams_accepted_total
        .saturating_sub(before.mesh_server_quic_streams_accepted_total);
    let server_quic_stream_accept_us_delta = after
        .mesh_server_quic_stream_accept_us_total
        .saturating_sub(before.mesh_server_quic_stream_accept_us_total);
    let server_quic_request_read_us_delta = after
        .mesh_server_quic_request_read_us_total
        .saturating_sub(before.mesh_server_quic_request_read_us_total);
    let server_quic_response_write_us_delta = after
        .mesh_server_quic_response_write_us_total
        .saturating_sub(before.mesh_server_quic_response_write_us_total);
    Ok(Mvp5PerfMeshTransportDelta {
        requests_delta,
        tls_handshakes_delta: after
            .mesh_client_tls_handshakes_total
            .saturating_sub(before.mesh_client_tls_handshakes_total),
        connect_count_delta: after
            .mesh_client_connect_count
            .saturating_sub(before.mesh_client_connect_count),
        connect_ms_delta: after
            .mesh_client_connect_ms_total
            .saturating_sub(before.mesh_client_connect_ms_total),
        pool_hits_delta,
        pool_misses_delta: after
            .mesh_client_pool_misses_total
            .saturating_sub(before.mesh_client_pool_misses_total),
        pool_idle_evictions_delta: after
            .mesh_client_pool_idle_evictions_total
            .saturating_sub(before.mesh_client_pool_idle_evictions_total),
        cached_request_failures_delta,
        retries_delta: after
            .mesh_client_retries_total
            .saturating_sub(before.mesh_client_retries_total),
        retry_successes_delta: after
            .mesh_client_retry_successes_total
            .saturating_sub(before.mesh_client_retry_successes_total),
        retry_failures_delta: after
            .mesh_client_retry_failures_total
            .saturating_sub(before.mesh_client_retry_failures_total),
        request_timeouts_delta,
        exchange_count_delta,
        exchange_us_delta,
        exchange_avg_us: mvp5_perf_ratio_from_u64(exchange_us_delta, exchange_count_delta)?,
        runtime_jobs_dequeued_delta,
        runtime_queue_wait_us_delta,
        runtime_queue_wait_avg_us: mvp5_perf_ratio_from_u64(
            runtime_queue_wait_us_delta,
            runtime_jobs_dequeued_delta,
        )?,
        server_quic_connections_accepted_delta: after
            .mesh_server_quic_connections_accepted_total
            .saturating_sub(before.mesh_server_quic_connections_accepted_total),
        server_quic_streams_accepted_delta,
        server_quic_stream_accept_us_delta,
        server_quic_stream_accept_avg_us: mvp5_perf_ratio_from_u64(
            server_quic_stream_accept_us_delta,
            server_quic_streams_accepted_delta,
        )?,
        server_quic_request_read_us_delta,
        server_quic_request_read_avg_us: mvp5_perf_ratio_from_u64(
            server_quic_request_read_us_delta,
            server_quic_streams_accepted_delta,
        )?,
        server_quic_response_write_us_delta,
        server_quic_response_write_avg_us: mvp5_perf_ratio_from_u64(
            server_quic_response_write_us_delta,
            server_quic_streams_accepted_delta,
        )?,
        cached_request_failure_rate: mvp5_perf_ratio_from_u64(
            cached_request_failures_delta,
            pool_hits_delta,
        )?,
        request_timeout_rate: mvp5_perf_ratio_from_u64(request_timeouts_delta, requests_delta)?,
    })
}

#[cfg(feature = "realnet")]
fn mvp5_perf_router_submit_delta(
    before: &serde_json::Value,
    after: &serde_json::Value,
) -> Result<Mvp5PerfRouterSubmitDelta, Box<dyn std::error::Error>> {
    let envelope_accepted_delta = mvp5_perf_json_u64(after, "/node/router_envelope_accepted_total")
        .saturating_sub(mvp5_perf_json_u64(before, "/node/router_envelope_accepted_total"));
    let replay_guard_checks_delta =
        mvp5_perf_json_u64(after, "/node/router_replay_guard_checks_total")
            .saturating_sub(mvp5_perf_json_u64(before, "/node/router_replay_guard_checks_total"));
    let submit_total_us_delta =
        mvp5_perf_json_delta(before, after, "/node/router_submit_total_us_total");
    let target_local_delta =
        mvp5_perf_json_delta(before, after, "/node/router_submit_target_local_total");
    let target_remote_delta =
        mvp5_perf_json_delta(before, after, "/node/router_submit_target_remote_total");
    let target_dispatch_total = target_local_delta.saturating_add(target_remote_delta);
    Ok(Mvp5PerfRouterSubmitDelta {
        envelope_accepted_delta,
        submit_total_us_delta,
        submit_total_avg_us: mvp5_perf_ratio_from_u64(
            submit_total_us_delta,
            envelope_accepted_delta,
        )?,
        submit_decode_avg_us: mvp5_perf_ratio_from_u64(
            mvp5_perf_json_delta(before, after, "/node/router_submit_decode_us_total"),
            envelope_accepted_delta,
        )?,
        submit_dispatch_avg_us: mvp5_perf_ratio_from_u64(
            mvp5_perf_json_delta(before, after, "/node/router_submit_dispatch_us_total"),
            envelope_accepted_delta,
        )?,
        submit_save_avg_us: mvp5_perf_ratio_from_u64(
            mvp5_perf_json_delta(before, after, "/node/router_submit_save_us_total"),
            envelope_accepted_delta,
        )?,
        submit_response_avg_us: mvp5_perf_ratio_from_u64(
            mvp5_perf_json_delta(before, after, "/node/router_submit_response_us_total"),
            envelope_accepted_delta,
        )?,
        replay_guard_check_avg_us: mvp5_perf_ratio_from_u64(
            mvp5_perf_json_delta(before, after, "/node/router_replay_guard_check_us_total"),
            replay_guard_checks_delta,
        )?,
        save_total_avg_us: mvp5_perf_ratio_from_u64(
            mvp5_perf_json_delta(before, after, "/node/router_save_total_us_total"),
            envelope_accepted_delta,
        )?,
        save_inbox_avg_us: mvp5_perf_ratio_from_u64(
            mvp5_perf_json_delta(before, after, "/node/router_save_inbox_us_total"),
            envelope_accepted_delta,
        )?,
        save_replay_guard_avg_us: mvp5_perf_ratio_from_u64(
            mvp5_perf_json_delta(before, after, "/node/router_save_replay_guard_us_total"),
            envelope_accepted_delta,
        )?,
        save_begin_write_avg_us: mvp5_perf_ratio_from_u64(
            mvp5_perf_json_delta(before, after, "/node/router_save_begin_write_us_total"),
            envelope_accepted_delta,
        )?,
        save_mutation_avg_us: mvp5_perf_ratio_from_u64(
            mvp5_perf_json_delta(before, after, "/node/router_save_mutation_us_total"),
            envelope_accepted_delta,
        )?,
        save_commit_avg_us: mvp5_perf_ratio_from_u64(
            mvp5_perf_json_delta(before, after, "/node/router_save_commit_us_total"),
            envelope_accepted_delta,
        )?,
        target_local_delta,
        target_remote_delta,
        target_same_core_rate: mvp5_perf_ratio_from_u64(target_local_delta, target_dispatch_total)?,
        target_local_avg_us: mvp5_perf_ratio_from_u64(
            mvp5_perf_json_delta(before, after, "/node/router_submit_target_local_us_total"),
            target_local_delta,
        )?,
        target_remote_avg_us: mvp5_perf_ratio_from_u64(
            mvp5_perf_json_delta(before, after, "/node/router_submit_target_remote_us_total"),
            target_remote_delta,
        )?,
    })
}

#[cfg(feature = "realnet")]
fn mvp5_perf_json_delta(before: &serde_json::Value, after: &serde_json::Value, path: &str) -> u64 {
    mvp5_perf_json_u64(after, path).saturating_sub(mvp5_perf_json_u64(before, path))
}

#[cfg(feature = "realnet")]
fn mvp5_perf_json_u64(value: &serde_json::Value, path: &str) -> u64 {
    value.pointer(path).and_then(serde_json::Value::as_u64).unwrap_or_default()
}

#[cfg(feature = "realnet")]
fn mvp5_perf_federation_inbound_diagnosis(
    stages: &[Mvp5PerfStageReport],
    router_metrics: &serde_json::Value,
) -> serde_json::Value {
    let stage_diagnoses =
        stages.iter().filter_map(mvp5_perf_federation_inbound_stage_diagnosis).collect::<Vec<_>>();
    serde_json::json!({
        "stage_diagnoses": stage_diagnoses,
        "router_submit_total_avg_us": mvp5_perf_json_avg(
            router_metrics.pointer("/node/router_submit_total_us_total"),
            router_metrics.pointer("/node/router_envelope_accepted_total")
        ),
        "router_submit_save_avg_us": mvp5_perf_json_avg(
            router_metrics.pointer("/node/router_submit_save_us_total"),
            router_metrics.pointer("/node/router_envelope_accepted_total")
        ),
        "router_save_total_avg_us": mvp5_perf_json_avg(
            router_metrics.pointer("/node/router_save_total_us_total"),
            router_metrics.pointer("/node/router_envelope_accepted_total")
        ),
        "router_save_inbox_avg_us": mvp5_perf_json_avg(
            router_metrics.pointer("/node/router_save_inbox_us_total"),
            router_metrics.pointer("/node/router_envelope_accepted_total")
        ),
        "router_save_begin_write_avg_us": mvp5_perf_json_avg(
            router_metrics.pointer("/node/router_save_begin_write_us_total"),
            router_metrics.pointer("/node/router_envelope_accepted_total")
        ),
        "router_save_mutation_avg_us": mvp5_perf_json_avg(
            router_metrics.pointer("/node/router_save_mutation_us_total"),
            router_metrics.pointer("/node/router_envelope_accepted_total")
        ),
        "router_save_commit_avg_us": mvp5_perf_json_avg(
            router_metrics.pointer("/node/router_save_commit_us_total"),
            router_metrics.pointer("/node/router_envelope_accepted_total")
        ),
        "router_replay_guard_check_avg_us": mvp5_perf_json_avg(
            router_metrics.pointer("/node/router_replay_guard_check_us_total"),
            router_metrics.pointer("/node/router_replay_guard_checks_total")
        )
    })
}

#[cfg(feature = "realnet")]
struct Mvp5PerfFederationStageDiagnosisMetrics {
    client_timeout_rate: f64,
    cached_failure_rate: f64,
    client_runtime_queue_wait_avg: f64,
    server_request_read_avg: f64,
    server_stream_accept_avg: f64,
    server_response_write_avg: f64,
    federation_to_router_exchange_avg: f64,
    signature_body_avg: f64,
    signature_signature_parse_avg: f64,
    signature_key_parse_avg: f64,
    signature_ed25519_verify_avg: f64,
    router_submit_total_avg: f64,
    router_save_total_avg: f64,
    router_save_begin_write_avg: f64,
    router_save_commit_avg: f64,
}

#[cfg(feature = "realnet")]
fn mvp5_perf_federation_inbound_stage_diagnosis(
    stage: &Mvp5PerfStageReport,
) -> Option<serde_json::Value> {
    let receive = stage.federation_receive_perf.as_ref()?;
    let total_avg = receive.total.avg_us_delta.unwrap_or_default();
    let segments = [
        ("target_check", &receive.target_check),
        ("trust_snapshot", &receive.trust_snapshot),
        ("policy_check", &receive.policy_check),
        ("pin_lookup", &receive.pin_lookup),
        ("signature_verify", &receive.signature_verify),
        ("router_post", &receive.router_post),
    ];
    let (primary_segment, primary_avg_us) = segments
        .iter()
        .filter_map(|(name, timing)| timing.avg_us_delta.map(|avg| (*name, avg)))
        .max_by(|(_left_name, left), (_right_name, right)| {
            left.partial_cmp(right).unwrap_or(std::cmp::Ordering::Equal)
        })
        .unwrap_or(("unknown", 0.0));
    let metrics = mvp5_perf_federation_stage_diagnosis_metrics(stage);
    let primary_hypothesis = mvp5_perf_federation_stage_primary_hypothesis(
        total_avg,
        primary_segment,
        primary_avg_us,
        &metrics,
    );
    Some(serde_json::json!({
        "stage": stage.name,
        "concurrency": stage.concurrency,
        "saturated": stage.saturated,
        "successful_pairs": stage.successful_pairs,
        "error_rate": stage.error_rate,
        "throughput_envelopes_per_sec": stage.throughput_envelopes_per_sec,
        "total_receive_avg_us": total_avg,
        "primary_server_segment": primary_segment,
        "primary_server_segment_avg_us": primary_avg_us,
        "primary_server_segment_share": mvp5_perf_ratio_f64(primary_avg_us, total_avg),
        "client_request_timeout_rate": metrics.client_timeout_rate,
        "client_cached_request_failure_rate": metrics.cached_failure_rate,
        "client_runtime_queue_wait_avg_us": metrics.client_runtime_queue_wait_avg,
        "server_quic_stream_accept_avg_us": metrics.server_stream_accept_avg,
        "server_quic_request_read_avg_us": metrics.server_request_read_avg,
        "server_quic_response_write_avg_us": metrics.server_response_write_avg,
        "federation_to_router_mesh_http_exchange_avg_us": metrics.federation_to_router_exchange_avg,
        "signature_body_avg_us": metrics.signature_body_avg,
        "signature_signature_parse_avg_us": metrics.signature_signature_parse_avg,
        "signature_key_parse_avg_us": metrics.signature_key_parse_avg,
        "signature_ed25519_verify_avg_us": metrics.signature_ed25519_verify_avg,
        "router_submit_total_avg_us": metrics.router_submit_total_avg,
        "router_save_total_avg_us": metrics.router_save_total_avg,
        "router_save_begin_write_avg_us": metrics.router_save_begin_write_avg,
        "router_save_commit_avg_us": metrics.router_save_commit_avg,
        "primary_hypothesis": primary_hypothesis
    }))
}

#[cfg(feature = "realnet")]
fn mvp5_perf_federation_stage_diagnosis_metrics(
    stage: &Mvp5PerfStageReport,
) -> Mvp5PerfFederationStageDiagnosisMetrics {
    Mvp5PerfFederationStageDiagnosisMetrics {
        client_timeout_rate: stage
            .client_mesh_transport
            .as_ref()
            .and_then(|transport| transport.request_timeout_rate)
            .unwrap_or_default(),
        cached_failure_rate: stage
            .client_mesh_transport
            .as_ref()
            .and_then(|transport| transport.cached_request_failure_rate)
            .unwrap_or_default(),
        client_runtime_queue_wait_avg: stage
            .client_mesh_transport
            .as_ref()
            .and_then(|transport| transport.runtime_queue_wait_avg_us)
            .unwrap_or_default(),
        server_request_read_avg: stage
            .federation_server_mesh_transport
            .as_ref()
            .and_then(|transport| transport.server_quic_request_read_avg_us)
            .unwrap_or_default(),
        server_stream_accept_avg: stage
            .federation_server_mesh_transport
            .as_ref()
            .and_then(|transport| transport.server_quic_stream_accept_avg_us)
            .unwrap_or_default(),
        server_response_write_avg: stage
            .federation_server_mesh_transport
            .as_ref()
            .and_then(|transport| transport.server_quic_response_write_avg_us)
            .unwrap_or_default(),
        federation_to_router_exchange_avg: stage
            .federation_server_mesh_transport
            .as_ref()
            .and_then(|transport| transport.exchange_avg_us)
            .unwrap_or_default(),
        signature_body_avg: stage
            .federation_receive_perf
            .as_ref()
            .and_then(|receive| receive.signature_body.avg_us_delta)
            .unwrap_or_default(),
        signature_signature_parse_avg: stage
            .federation_receive_perf
            .as_ref()
            .and_then(|receive| receive.signature_signature_parse.avg_us_delta)
            .unwrap_or_default(),
        signature_key_parse_avg: stage
            .federation_receive_perf
            .as_ref()
            .and_then(|receive| receive.signature_key_parse.avg_us_delta)
            .unwrap_or_default(),
        signature_ed25519_verify_avg: stage
            .federation_receive_perf
            .as_ref()
            .and_then(|receive| receive.signature_ed25519_verify.avg_us_delta)
            .unwrap_or_default(),
        router_submit_total_avg: stage
            .router_submit_perf
            .as_ref()
            .and_then(|router| router.submit_total_avg_us)
            .unwrap_or_default(),
        router_save_total_avg: stage
            .router_submit_perf
            .as_ref()
            .and_then(|router| router.save_total_avg_us)
            .unwrap_or_default(),
        router_save_begin_write_avg: stage
            .router_submit_perf
            .as_ref()
            .and_then(|router| router.save_begin_write_avg_us)
            .unwrap_or_default(),
        router_save_commit_avg: stage
            .router_submit_perf
            .as_ref()
            .and_then(|router| router.save_commit_avg_us)
            .unwrap_or_default(),
    }
}

#[cfg(feature = "realnet")]
fn mvp5_perf_federation_stage_primary_hypothesis(
    total_avg: f64,
    primary_segment: &str,
    primary_avg_us: f64,
    metrics: &Mvp5PerfFederationStageDiagnosisMetrics,
) -> &'static str {
    if metrics.client_timeout_rate >= 0.05 || metrics.cached_failure_rate >= 0.05 {
        "mesh_quic_cached_connection_probe_timeout_or_reconnect"
    } else if metrics.client_runtime_queue_wait_avg >= total_avg * 0.5 {
        "test_process_mesh_quic_runtime_queueing"
    } else if metrics.router_save_begin_write_avg >= metrics.router_submit_total_avg * 0.5 {
        "router_redb_begin_write_queueing"
    } else if metrics.router_save_commit_avg >= metrics.router_submit_total_avg * 0.5 {
        "router_redb_commit"
    } else if metrics.router_save_total_avg >= metrics.router_submit_total_avg * 0.5 {
        "router_redb_write_transaction"
    } else if metrics.router_submit_total_avg >= primary_avg_us * 0.7 {
        "router_handler_or_redb"
    } else if metrics.federation_to_router_exchange_avg >= primary_avg_us * 0.7 {
        "federation_to_router_mesh_http_round_trip"
    } else if metrics.server_request_read_avg >= total_avg * 0.5
        || metrics.server_stream_accept_avg >= total_avg * 0.5
    {
        "mesh_quic_server_accept_or_request_read"
    } else if metrics.server_response_write_avg >= total_avg * 0.5 {
        "mesh_quic_server_response_write_or_client_fin"
    } else if primary_segment == "router_post" && primary_avg_us >= total_avg * 0.5 {
        "router_submit_or_redb_single_writer"
    } else if primary_segment == "signature_verify" && primary_avg_us >= total_avg * 0.3 {
        mvp5_perf_federation_signature_hypothesis(metrics)
    } else if matches!(primary_segment, "trust_snapshot" | "policy_check" | "pin_lookup") {
        "federation_trust_read_or_policy"
    } else {
        "mixed_or_unclassified"
    }
}

#[cfg(feature = "realnet")]
fn mvp5_perf_federation_signature_hypothesis(
    metrics: &Mvp5PerfFederationStageDiagnosisMetrics,
) -> &'static str {
    let segments = [
        ("federation_signature_body_canonicalization", metrics.signature_body_avg),
        ("federation_signature_signature_parse", metrics.signature_signature_parse_avg),
        ("federation_signature_key_parse", metrics.signature_key_parse_avg),
        ("federation_signature_ed25519_verify", metrics.signature_ed25519_verify_avg),
    ];
    segments
        .iter()
        .max_by(|(_left_name, left), (_right_name, right)| {
            left.partial_cmp(right).unwrap_or(std::cmp::Ordering::Equal)
        })
        .map_or("pinned_source_signature_verify", |(name, _value)| *name)
}

#[cfg(feature = "realnet")]
fn mvp5_perf_json_avg(
    total: Option<&serde_json::Value>,
    count: Option<&serde_json::Value>,
) -> Option<f64> {
    let total = total.and_then(serde_json::Value::as_u64)?;
    let count = count.and_then(serde_json::Value::as_u64)?;
    let total = u32::try_from(total).ok()?;
    let count = u32::try_from(count).ok()?;
    mvp5_perf_ratio_f64(f64::from(total), f64::from(count))
}

#[cfg(feature = "realnet")]
fn mvp5_perf_ratio_f64(numerator: f64, denominator: f64) -> Option<f64> {
    if denominator <= 0.0 {
        return None;
    }
    Some(numerator / denominator)
}

#[cfg(feature = "realnet")]
fn mvp_s8_perf_federation_tls(project_name: &str) -> ramflux_transport::MeshTlsConfig {
    let cert_root =
        code_root().join("ramflux/deploy/.itest-node-certs").join(project_name).join("certs");
    ramflux_transport::MeshTlsConfig {
        ca_cert: cert_root.join("ca.pem"),
        service_cert: cert_root.join("federation/federation.pem"),
        service_key: cert_root.join("federation/federation-key.pem"),
    }
}

#[cfg(feature = "realnet")]
fn mvp_s8_perf_signed_federation_envelope(
    source_node_id: &str,
    target_node_id: &str,
    envelope_id: &str,
    target_delivery_id: &str,
) -> Result<ramflux_node_core::FederatedEnvelopeForwardRequest, Box<dyn std::error::Error>> {
    let mut request = ramflux_node_core::FederatedEnvelopeForwardRequest {
        signed: ramflux_node_core::default_federation_forward_signed_fields(),
        admin_token: String::new(),
        source_node_id: source_node_id.to_owned(),
        target_node_id: target_node_id.to_owned(),
        delivery_class: "opaque_event".to_owned(),
        required_capability: "opaque_delivery".to_owned(),
        envelope: itest_envelope(envelope_id, target_delivery_id),
    };
    ramflux_node_core::sign_federated_envelope_forward(
        &mut request,
        realnet_node_signing_seed(source_node_id),
    )?;
    Ok(request)
}

#[cfg(feature = "realnet")]
fn mvp_s8_perf_post_mesh_inbound(
    endpoint: &str,
    source_tls: &ramflux_transport::MeshTlsConfig,
    peer_ca_pems: &[String],
    request: &ramflux_node_core::FederatedEnvelopeForwardRequest,
) -> Result<ramflux_node_core::FederatedEnvelopeForwardResponse, ramflux_transport::TransportError>
{
    ramflux_transport::mesh_quic_post_json_with_peer_ca_pems(
        endpoint,
        "/s8/federation/envelope",
        source_tls,
        "ramflux-federation",
        peer_ca_pems,
        request,
    )
}

#[cfg(feature = "realnet")]
fn mvp_s8_perf_federation_inbound_warmup(
    context: &MvpS8PerfInboundContext,
    concurrency: usize,
    duration: std::time::Duration,
) -> serde_json::Value {
    let deadline = std::time::Instant::now() + duration;
    let counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    std::thread::scope(|scope| {
        for worker_id in 0..concurrency {
            let context = context.clone();
            let counter = std::sync::Arc::clone(&counter);
            scope.spawn(move || {
                while std::time::Instant::now() < deadline {
                    let index = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let envelope_id = format!("env_s8_perf_inbound_warmup_{worker_id}_{index}");
                    let target_delivery_id = format!("target_s8_perf_inbound_warmup_{index:06}");
                    let Ok(request) = mvp_s8_perf_signed_federation_envelope(
                        &context.source_node_id,
                        &context.target_node_id,
                        &envelope_id,
                        &target_delivery_id,
                    ) else {
                        continue;
                    };
                    let _ = mvp_s8_perf_post_mesh_inbound(
                        &context.endpoint,
                        &context.source_tls,
                        &context.peer_ca_pems,
                        &request,
                    );
                }
            });
        }
    });
    serde_json::json!({
        "transport": "federation_mesh_quic_inbound",
        "mesh_quic_connection_model": "ramflux_transport cached one connection per peer/CA, concurrent bi-streams",
        "concurrency": concurrency,
        "duration_ms": duration.as_millis(),
        "attempted_envelopes": counter.load(std::sync::atomic::Ordering::Relaxed)
    })
}

#[cfg(feature = "realnet")]
fn mvp_s8_perf_federation_warmup(
    federation_url: &str,
    source_node_id: &str,
    target_node_id: &str,
    concurrency: usize,
    duration: std::time::Duration,
) -> serde_json::Value {
    let deadline = std::time::Instant::now() + duration;
    let counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    std::thread::scope(|scope| {
        for worker_id in 0..concurrency {
            let federation_url = federation_url.to_owned();
            let source_node_id = source_node_id.to_owned();
            let target_node_id = target_node_id.to_owned();
            let counter = std::sync::Arc::clone(&counter);
            scope.spawn(move || {
                while std::time::Instant::now() < deadline {
                    let index = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let envelope_id = format!("env_s8_perf_warmup_{worker_id}_{index}");
                    let target_delivery_id = format!("target_s8_perf_warmup_{index:06}");
                    let request = ramflux_node_core::FederatedEnvelopeForwardRequest {
                        signed: ramflux_node_core::default_federation_forward_signed_fields(),
                        admin_token: String::new(),
                        source_node_id: source_node_id.clone(),
                        target_node_id: target_node_id.clone(),
                        delivery_class: "opaque_event".to_owned(),
                        required_capability: "opaque_delivery".to_owned(),
                        envelope: itest_envelope(&envelope_id, &target_delivery_id),
                    };
                    let _ = ramflux_node_core::itest_http_post_json::<
                        _,
                        ramflux_node_core::FederatedEnvelopeForwardResponse,
                    >(
                        &format!("{federation_url}/s8/federation/forward"), &request
                    );
                }
            });
        }
    });
    serde_json::json!({
        "transport": "federation_forward",
        "concurrency": concurrency,
        "duration_ms": duration.as_millis(),
        "attempted_envelopes": counter.load(std::sync::atomic::Ordering::Relaxed)
    })
}

#[cfg(feature = "realnet")]
fn mvp_s8_perf_is_deduped_idempotent_retry(
    response: &ramflux_node_core::FederatedEnvelopeForwardResponse,
    target_delivery_id: &str,
) -> bool {
    response.accepted
        && response.delivery.target_delivery_id == target_delivery_id
        && response.delivery.outcome.starts_with("rejected_security:")
        && response.delivery.outcome.contains("replay")
}

#[cfg(feature = "realnet")]
#[allow(clippy::too_many_lines)]
fn mvp5_perf_run_stage(
    gateway_url: &str,
    config: &Mvp5PerfStageConfig,
) -> Result<Mvp5PerfStageReport, Box<dyn std::error::Error>> {
    let name = config.name.as_str();
    let target_delivery_id = format!("target_mvp5_perf_{name}");
    let (sender, receiver) = std::sync::mpsc::channel::<Mvp5PerfMessage>();
    let next_index = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let started = std::time::Instant::now();
    let deadline = config.duration.map(|duration| started + duration);
    std::thread::scope(|scope| {
        for _worker_id in 0..config.concurrency {
            let sender = sender.clone();
            let gateway_url = gateway_url.to_owned();
            let target_delivery_id = target_delivery_id.clone();
            let next_index = std::sync::Arc::clone(&next_index);
            scope.spawn(move || {
                loop {
                    if deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
                        break;
                    }
                    let index = next_index.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if config.total_requests.is_some_and(|total| index >= total) {
                        break;
                    }
                    let envelope_id = format!("env_mvp5_perf_{name}_{index:06}");
                    let envelope = itest_envelope(&envelope_id, &target_delivery_id);
                    let submit_started = std::time::Instant::now();
                    let submit = ramflux_node_core::itest_http_post_json::<
                        _,
                        ramflux_node_core::ItestMvp0SubmitResponse,
                    >(
                        &format!("{gateway_url}/mvp0/envelope"), &envelope
                    );
                    let submit_us = submit_started.elapsed().as_micros();
                    let message = match submit {
                        Ok(submit) if submit.outcome == "offline_queued" => {
                            let ack_started = std::time::Instant::now();
                            let ack = ramflux_node_core::itest_http_post_json::<
                                _,
                                ramflux_node_core::ItestMvp0CursorResponse,
                            >(
                                &format!("{gateway_url}/mvp0/ack"),
                                &itest_ack(&envelope_id),
                            );
                            let ack_us = ack_started.elapsed().as_micros();
                            match (submit.inbox_seq, ack) {
                                (Some(seq), Ok(_cursor)) => {
                                    Mvp5PerfMessage::Success(Mvp5PerfResult {
                                        seq,
                                        envelope_id,
                                        submit_us,
                                        ack_us,
                                    })
                                }
                                (None, Ok(_cursor)) => Mvp5PerfMessage::CorrectnessError {
                                    category: "missing_inbox_seq".to_owned(),
                                    sample: envelope_id,
                                },
                                (_seq, Err(error)) => Mvp5PerfMessage::TransportError {
                                    category: mvp5_perf_transport_error_category(
                                        "ack_error",
                                        &error.to_string(),
                                    ),
                                    sample: mvp5_perf_error_sample(error.to_string()),
                                },
                            }
                        }
                        Ok(submit) => Mvp5PerfMessage::CorrectnessError {
                            category: "unexpected_submit_outcome".to_owned(),
                            sample: format!("{}:{envelope_id}", submit.outcome),
                        },
                        Err(error) => Mvp5PerfMessage::TransportError {
                            category: mvp5_perf_transport_error_category(
                                "submit_error",
                                &error.to_string(),
                            ),
                            sample: mvp5_perf_error_sample(error.to_string()),
                        },
                    };
                    if sender.send(message).is_err() {
                        return;
                    }
                }
            });
        }
    });
    drop(sender);

    let mut results = Vec::with_capacity(config.total_requests.unwrap_or_default());
    let mut transport_error_counts = std::collections::BTreeMap::<String, u64>::new();
    let mut transport_error_samples = std::collections::BTreeMap::<String, String>::new();
    let mut correctness_error_counts = std::collections::BTreeMap::<String, u64>::new();
    let mut correctness_error_samples = std::collections::BTreeMap::<String, String>::new();
    for message in receiver {
        match message {
            Mvp5PerfMessage::Success(result) => results.push(result),
            Mvp5PerfMessage::TransportError { category, sample } => {
                *transport_error_counts.entry(category.clone()).or_default() += 1;
                transport_error_samples.entry(category).or_insert(sample);
            }
            Mvp5PerfMessage::BenignEvent { category, sample }
            | Mvp5PerfMessage::CorrectnessError { category, sample } => {
                *correctness_error_counts.entry(category.clone()).or_default() += 1;
                correctness_error_samples.entry(category).or_insert(sample);
            }
        }
    }
    let transport_error_total = transport_error_counts.values().sum::<u64>();
    let total_envelopes = results
        .len()
        .checked_add(usize::try_from(transport_error_total)?)
        .ok_or("mvp5 perf attempted envelope count overflow")?;
    if total_envelopes == 0 {
        return Err(format!("mvp5 perf stage {name} produced no attempts").into());
    }
    if !correctness_error_counts.is_empty() {
        return Err(format!(
            "mvp5 perf stage {name} correctness errors: counts={correctness_error_counts:?} samples={correctness_error_samples:?}"
        )
        .into());
    }
    let degraded_by_transport = !transport_error_counts.is_empty();
    if results.is_empty() && !degraded_by_transport {
        return Err(
            format!("mvp5 perf stage {name} produced no successful submit+ack pairs").into()
        );
    }
    if config.duration.is_none() && !degraded_by_transport && results.len() != total_envelopes {
        return Err(format!(
            "mvp5 perf stage {name} completed {} of {total_envelopes}",
            results.len()
        )
        .into());
    }
    results.sort_by_key(|result| result.seq);
    let mut previous_seq = None;
    for result in &results {
        if previous_seq == Some(result.seq) {
            return Err(format!("mvp5 perf stage {name} duplicate seq {}", result.seq).into());
        }
        previous_seq = Some(result.seq);
    }
    if !degraded_by_transport {
        for (expected_seq, result) in (1_u64..).zip(results.iter()) {
            if result.seq != expected_seq {
                return Err(format!(
                    "mvp5 perf stage {name} seq gap: expected {expected_seq}, got {}",
                    result.seq
                )
                .into());
            }
        }
    }
    let expected_cursor_seq = if degraded_by_transport {
        results.iter().map(|result| result.seq).max().unwrap_or_default()
    } else {
        u64::try_from(total_envelopes)?
    };
    let expected_acked_len = if degraded_by_transport { results.len() } else { total_envelopes };
    let cursor = match ramflux_node_core::itest_http_get_json::<
        Option<ramflux_node_core::ItestMvp0CursorResponse>,
    >(&format!("{gateway_url}/mvp0/cursor/{target_delivery_id}"))
    {
        Ok(Some(cursor)) => Some(cursor),
        Ok(None) if degraded_by_transport => None,
        Ok(None) => return Err(format!("missing cursor for {target_delivery_id}").into()),
        Err(error) if degraded_by_transport => {
            let sample = error.to_string();
            let category = mvp5_perf_transport_error_category("cursor_error", &sample);
            *transport_error_counts.entry(category.clone()).or_default() += 1;
            transport_error_samples.entry(category).or_insert(mvp5_perf_error_sample(sample));
            None
        }
        Err(error) => return Err(Box::new(error)),
    };
    if let Some(cursor) = &cursor {
        if !degraded_by_transport && cursor.inbox_seq != expected_cursor_seq {
            return Err(format!(
                "mvp5 perf stage {name} cursor seq mismatch seq={} expected={expected_cursor_seq}",
                cursor.inbox_seq
            )
            .into());
        }
        if !degraded_by_transport && cursor.acked_envelope_ids.len() != expected_acked_len {
            return Err(format!(
                "mvp5 perf stage {name} cursor ack count mismatch acked={} expected={expected_acked_len}",
                cursor.acked_envelope_ids.len()
            )
            .into());
        }
        for result in &results {
            if !cursor.acked_envelope_ids.contains(&result.envelope_id) {
                return Err(format!(
                    "mvp5 perf stage {name} missing ack for successful envelope {}",
                    result.envelope_id
                )
                .into());
            }
        }
    }
    let transport_error_rates = mvp5_perf_error_rates(&transport_error_counts, total_envelopes)?;
    let max_transport_error_rate = transport_error_rates.values().copied().fold(0.0_f64, f64::max);
    let saturated = max_transport_error_rate > MVP5_PERF_TRANSPORT_SATURATION_RATE;
    let elapsed = started.elapsed();
    let mut submit_latencies = results.iter().map(|result| result.submit_us).collect::<Vec<_>>();
    let mut ack_latencies = results.iter().map(|result| result.ack_us).collect::<Vec<_>>();
    let successful_pairs = results.len();
    let correctness = serde_json::json!({
        "mode": if cursor.is_none() {
            "cursor_unavailable_due_transport_errors"
        } else if degraded_by_transport {
            "degraded_by_transport_errors"
        } else {
            "strict"
        },
        "inbox_seq": cursor.as_ref().map(|cursor| cursor.inbox_seq),
        "acked_envelope_ids": cursor.as_ref().map(|cursor| cursor.acked_envelope_ids.len()),
        "successful_pairs": successful_pairs,
        "expected_total": total_envelopes,
        "max_successful_seq": results.iter().map(|result| result.seq).max().unwrap_or_default(),
    });
    Ok(Mvp5PerfStageReport {
        name: name.to_owned(),
        concurrency: config.concurrency,
        total_envelopes,
        configured_total_requests: config.total_requests,
        configured_duration_ms: config.duration.map(|duration| duration.as_millis()),
        successful_pairs,
        saturated,
        saturation_threshold: MVP5_PERF_TRANSPORT_SATURATION_RATE,
        error_rate: max_transport_error_rate,
        elapsed_ms: elapsed.as_millis(),
        throughput_envelopes_per_sec: f64::from(u32::try_from(successful_pairs)?)
            / elapsed.as_secs_f64(),
        attempted_throughput_envelopes_per_sec: f64::from(u32::try_from(total_envelopes)?)
            / elapsed.as_secs_f64(),
        submit_latency: mvp5_latency_summary(&mut submit_latencies),
        ack_latency: mvp5_latency_summary(&mut ack_latencies),
        transport_error_rates,
        transport_error_counts,
        transport_error_samples,
        correctness,
        deduped_idempotent_retries: None,
        federation_mesh_transport: None,
        federation_receive_perf: None,
        router_submit_perf: None,
        client_mesh_transport: None,
        federation_server_mesh_transport: None,
        baseline_note: "unoptimized baseline; transport error-rate is an optimization target, not a pass/fail gate".to_owned(),
    })
}

#[cfg(feature = "realnet")]
#[allow(clippy::too_many_lines)]
fn mvp_s8_perf_run_federation_stage(
    node_a: &S8RealnetNode,
    node_b: &S8RealnetNode,
    config: &Mvp5PerfStageConfig,
) -> Result<Mvp5PerfStageReport, Box<dyn std::error::Error>> {
    let name = format!("federation_{}", config.name);
    let (sender, receiver) = std::sync::mpsc::channel::<Mvp5PerfMessage>();
    let next_index = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mesh_before = mvp_s8_perf_mesh_observability(node_b)?;
    let started = std::time::Instant::now();
    let deadline = config.duration.map(|duration| started + duration);
    std::thread::scope(|scope| {
        for _worker_id in 0..config.concurrency {
            let sender = sender.clone();
            let federation_url = node_a.federation_url.clone();
            let source_node = node_a.node_id.clone();
            let destination_node = node_b.node_id.clone();
            let next_index = std::sync::Arc::clone(&next_index);
            let config = config.clone();
            let name = name.clone();
            scope.spawn(move || {
                loop {
                    if deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
                        break;
                    }
                    let index = next_index.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if config.total_requests.is_some_and(|total| index >= total) {
                        break;
                    }
                    let envelope_id = format!("env_s8_perf_{name}_{index:06}");
                    let target_delivery_id = format!("target_s8_perf_{name}_{index:06}");
                    let request = ramflux_node_core::FederatedEnvelopeForwardRequest {
                        signed: ramflux_node_core::default_federation_forward_signed_fields(),
                        admin_token: String::new(),
                        source_node_id: source_node.clone(),
                        target_node_id: destination_node.clone(),
                        delivery_class: "opaque_event".to_owned(),
                        required_capability: "opaque_delivery".to_owned(),
                        envelope: itest_envelope(&envelope_id, &target_delivery_id),
                    };
                    let started = std::time::Instant::now();
                    let response = ramflux_node_core::itest_http_post_json::<
                        _,
                        ramflux_node_core::FederatedEnvelopeForwardResponse,
                    >(
                        &format!("{federation_url}/s8/federation/forward"), &request
                    );
                    let forward_us = started.elapsed().as_micros();
                    let message = match response {
                        Ok(response)
                            if response.accepted
                                && response.delivery.outcome == "offline_queued"
                                && response.delivery.target_delivery_id == target_delivery_id =>
                        {
                            match (response.delivery.inbox_seq, u64::try_from(index)) {
                                (Some(_inbox_seq), Ok(seq)) => {
                                    Mvp5PerfMessage::Success(Mvp5PerfResult {
                                        seq: seq.saturating_add(1),
                                        envelope_id,
                                        submit_us: forward_us,
                                        ack_us: 0,
                                    })
                                }
                                (None, _) => Mvp5PerfMessage::CorrectnessError {
                                    category: "missing_inbox_seq".to_owned(),
                                    sample: envelope_id,
                                },
                                (_some, Err(error)) => Mvp5PerfMessage::CorrectnessError {
                                    category: "index_overflow".to_owned(),
                                    sample: error.to_string(),
                                },
                            }
                        }
                        Ok(response)
                            if mvp_s8_perf_is_deduped_idempotent_retry(
                                &response,
                                &target_delivery_id,
                            ) =>
                        {
                            Mvp5PerfMessage::BenignEvent {
                                category: "deduped_idempotent_retry".to_owned(),
                                sample: format!(
                                    "outcome={} envelope={envelope_id}",
                                    response.delivery.outcome
                                ),
                            }
                        }
                        Ok(response) => {
                            let category =
                                if response.delivery.target_delivery_id == target_delivery_id {
                                    "unexpected_forward_response"
                                } else {
                                    "wrong_forward_target"
                                };
                            Mvp5PerfMessage::CorrectnessError {
                                category: category.to_owned(),
                                sample: format!(
                                    "accepted={} outcome={} target={} envelope={envelope_id}",
                                    response.accepted,
                                    response.delivery.outcome,
                                    response.delivery.target_delivery_id
                                ),
                            }
                        }
                        Err(error) => Mvp5PerfMessage::TransportError {
                            category: mvp5_perf_transport_error_category(
                                "forward_error",
                                &error.to_string(),
                            ),
                            sample: mvp5_perf_error_sample(error.to_string()),
                        },
                    };
                    if sender.send(message).is_err() {
                        return;
                    }
                }
            });
        }
    });
    drop(sender);

    let mut results = Vec::with_capacity(config.total_requests.unwrap_or_default());
    let mut benign_event_counts = std::collections::BTreeMap::<String, u64>::new();
    let mut benign_event_samples = std::collections::BTreeMap::<String, String>::new();
    let mut transport_error_counts = std::collections::BTreeMap::<String, u64>::new();
    let mut transport_error_samples = std::collections::BTreeMap::<String, String>::new();
    let mut correctness_error_counts = std::collections::BTreeMap::<String, u64>::new();
    let mut correctness_error_samples = std::collections::BTreeMap::<String, String>::new();
    for message in receiver {
        match message {
            Mvp5PerfMessage::Success(result) => results.push(result),
            Mvp5PerfMessage::BenignEvent { category, sample } => {
                *benign_event_counts.entry(category.clone()).or_default() += 1;
                benign_event_samples.entry(category).or_insert(sample);
            }
            Mvp5PerfMessage::TransportError { category, sample } => {
                *transport_error_counts.entry(category.clone()).or_default() += 1;
                transport_error_samples.entry(category).or_insert(sample);
            }
            Mvp5PerfMessage::CorrectnessError { category, sample } => {
                *correctness_error_counts.entry(category.clone()).or_default() += 1;
                correctness_error_samples.entry(category).or_insert(sample);
            }
        }
    }
    let benign_event_total = benign_event_counts.values().sum::<u64>();
    let transport_error_total = transport_error_counts.values().sum::<u64>();
    let total_envelopes = results
        .len()
        .checked_add(usize::try_from(transport_error_total)?)
        .and_then(|total| total.checked_add(usize::try_from(benign_event_total).ok()?))
        .ok_or("mvp_s8 federation perf attempted envelope count overflow")?;
    if total_envelopes == 0 {
        return Err(format!("mvp_s8 federation perf stage {name} produced no attempts").into());
    }
    if !correctness_error_counts.is_empty() {
        return Err(format!(
            "mvp_s8 federation perf stage {name} correctness errors: counts={correctness_error_counts:?} samples={correctness_error_samples:?}"
        )
        .into());
    }
    let degraded_by_transport = !transport_error_counts.is_empty();
    let observed_nonfatal_total =
        results
            .len()
            .checked_add(usize::try_from(benign_event_total)?)
            .ok_or("mvp_s8 federation perf observed nonfatal count overflow")?;
    if observed_nonfatal_total == 0 && !degraded_by_transport {
        return Err(format!(
            "mvp_s8 federation perf stage {name} produced no successful or benign forwards"
        )
        .into());
    }
    if config.duration.is_none()
        && !degraded_by_transport
        && observed_nonfatal_total != total_envelopes
    {
        return Err(format!(
            "mvp_s8 federation perf stage {name} observed {observed_nonfatal_total} nonfatal outcomes of {total_envelopes}"
        )
        .into());
    }
    results.sort_by_key(|result| result.seq);
    let mut previous_seq = None;
    for result in &results {
        if previous_seq == Some(result.seq) {
            return Err(format!(
                "mvp_s8 federation perf stage {name} duplicate seq {}",
                result.seq
            )
            .into());
        }
        previous_seq = Some(result.seq);
    }
    let transport_error_rates = mvp5_perf_error_rates(&transport_error_counts, total_envelopes)?;
    let max_transport_error_rate = transport_error_rates.values().copied().fold(0.0_f64, f64::max);
    let saturated = max_transport_error_rate > MVP5_PERF_TRANSPORT_SATURATION_RATE;
    let elapsed = started.elapsed();
    let mesh_after = mvp_s8_perf_mesh_observability(node_b)?;
    let quic_inbound_delta =
        mesh_after.quic_inbound_s8_envelopes.saturating_sub(mesh_before.quic_inbound_s8_envelopes);
    let tcp_inbound_delta =
        mesh_after.tcp_inbound_s8_envelopes.saturating_sub(mesh_before.tcp_inbound_s8_envelopes);
    let total_inbound_delta = quic_inbound_delta.saturating_add(tcp_inbound_delta);
    let tcp_fallback_rate = if total_inbound_delta == 0 {
        0.0
    } else {
        f64::from(u32::try_from(tcp_inbound_delta)?)
            / f64::from(u32::try_from(total_inbound_delta)?)
    };
    let federation_mesh_transport = MvpS8PerfFederationTransportReport {
        quic_inbound_delta,
        tcp_inbound_delta,
        total_inbound_delta,
        tcp_fallback_rate,
    };
    let mut forward_latencies = results.iter().map(|result| result.submit_us).collect::<Vec<_>>();
    let mut empty_ack_latencies = Vec::new();
    let successful_pairs = results.len();
    let deduped_idempotent_retries =
        benign_event_counts.get("deduped_idempotent_retry").copied().unwrap_or_default();
    let correctness = serde_json::json!({
        "mode": if degraded_by_transport {
            "degraded_by_transport_errors"
        } else {
            "strict"
        },
        "successful_forwards": successful_pairs,
        "benign_event_counts": benign_event_counts,
        "benign_event_samples": benign_event_samples,
        "expected_total": total_envelopes,
        "max_successful_seq": results.iter().map(|result| result.seq).max().unwrap_or_default(),
    });
    Ok(Mvp5PerfStageReport {
        name,
        concurrency: config.concurrency,
        total_envelopes,
        configured_total_requests: config.total_requests,
        configured_duration_ms: config.duration.map(|duration| duration.as_millis()),
        successful_pairs,
        saturated,
        saturation_threshold: MVP5_PERF_TRANSPORT_SATURATION_RATE,
        error_rate: max_transport_error_rate,
        elapsed_ms: elapsed.as_millis(),
        throughput_envelopes_per_sec: f64::from(u32::try_from(successful_pairs)?)
            / elapsed.as_secs_f64(),
        attempted_throughput_envelopes_per_sec: f64::from(u32::try_from(total_envelopes)?)
            / elapsed.as_secs_f64(),
        submit_latency: mvp5_latency_summary(&mut forward_latencies),
        ack_latency: mvp5_latency_summary(&mut empty_ack_latencies),
        transport_error_rates,
        transport_error_counts,
        transport_error_samples,
        correctness,
        deduped_idempotent_retries: Some(deduped_idempotent_retries),
        federation_mesh_transport: Some(federation_mesh_transport),
        federation_receive_perf: None,
        router_submit_perf: None,
        client_mesh_transport: None,
        federation_server_mesh_transport: None,
        baseline_note: "federation forward load; submit_latency records node-a /s8/federation/forward API round-trip through node-a trust checks, mesh transport, and node-b receive/router submit. Client-to-node-a ingress is itest HTTP connection-per-request, so throughput may be ingress-limited; use a future QUIC ingress harness to isolate raw A2 mesh-QUIC capacity.".to_owned(),
    })
}

#[cfg(feature = "realnet")]
#[allow(clippy::too_many_lines)]
fn mvp_s8_perf_run_federation_inbound_stage(
    inbound_context: &MvpS8PerfInboundContext,
    node_a: &S8RealnetNode,
    node_b: &S8RealnetNode,
    config: &Mvp5PerfStageConfig,
) -> Result<Mvp5PerfStageReport, Box<dyn std::error::Error>> {
    let name = format!("federation_inbound_{}", config.name);
    let (sender, receiver) = std::sync::mpsc::channel::<Mvp5PerfMessage>();
    let next_index = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mesh_before = mvp_s8_perf_mesh_observability(node_b)?;
    let client_mesh_before = ramflux_transport::mesh_perf_snapshot();
    let router_metrics_before = mvp5_perf_get_json_or_error(
        &format!("{}/perf/metrics", inbound_context.router_url),
        "router_metrics_before",
    );
    let started = std::time::Instant::now();
    let deadline = config.duration.map(|duration| started + duration);
    std::thread::scope(|scope| {
        for _worker_id in 0..config.concurrency {
            let sender = sender.clone();
            let inbound_context = inbound_context.clone();
            let source_node = node_a.node_id.clone();
            let destination_node = node_b.node_id.clone();
            let next_index = std::sync::Arc::clone(&next_index);
            let config = config.clone();
            let name = name.clone();
            scope.spawn(move || {
                loop {
                    if deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
                        break;
                    }
                    let index = next_index.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if config.total_requests.is_some_and(|total| index >= total) {
                        break;
                    }
                    let envelope_id = format!("env_s8_perf_{name}_{index:06}");
                    let target_delivery_id = mvp5_perf_target_for_index(
                        &format!("target_s8_perf_{name}"),
                        index,
                        inbound_context.target_cardinality,
                    );
                    let request = match mvp_s8_perf_signed_federation_envelope(
                        &source_node,
                        &destination_node,
                        &envelope_id,
                        &target_delivery_id,
                    ) {
                        Ok(request) => request,
                        Err(error) => {
                            let _ = sender.send(Mvp5PerfMessage::CorrectnessError {
                                category: "sign_forward_error".to_owned(),
                                sample: error.to_string(),
                            });
                            return;
                        }
                    };
                    let started = std::time::Instant::now();
                    let response = mvp_s8_perf_post_mesh_inbound(
                        &inbound_context.endpoint,
                        &inbound_context.source_tls,
                        &inbound_context.peer_ca_pems,
                        &request,
                    );
                    let forward_us = started.elapsed().as_micros();
                    let message = match response {
                        Ok(response)
                            if response.accepted
                                && response.delivery.outcome == "offline_queued"
                                && response.delivery.target_delivery_id == target_delivery_id =>
                        {
                            match (response.delivery.inbox_seq, u64::try_from(index)) {
                                (Some(_inbox_seq), Ok(seq)) => {
                                    Mvp5PerfMessage::Success(Mvp5PerfResult {
                                        seq: seq.saturating_add(1),
                                        envelope_id,
                                        submit_us: forward_us,
                                        ack_us: 0,
                                    })
                                }
                                (None, _) => Mvp5PerfMessage::CorrectnessError {
                                    category: "missing_inbox_seq".to_owned(),
                                    sample: envelope_id,
                                },
                                (_some, Err(error)) => Mvp5PerfMessage::CorrectnessError {
                                    category: "index_overflow".to_owned(),
                                    sample: error.to_string(),
                                },
                            }
                        }
                        Ok(response)
                            if mvp_s8_perf_is_deduped_idempotent_retry(
                                &response,
                                &target_delivery_id,
                            ) =>
                        {
                            Mvp5PerfMessage::BenignEvent {
                                category: "deduped_idempotent_retry".to_owned(),
                                sample: format!(
                                    "outcome={} envelope={envelope_id}",
                                    response.delivery.outcome
                                ),
                            }
                        }
                        Ok(response) => {
                            let category =
                                if response.delivery.target_delivery_id == target_delivery_id {
                                    "unexpected_forward_response"
                                } else {
                                    "wrong_forward_target"
                                };
                            Mvp5PerfMessage::CorrectnessError {
                                category: category.to_owned(),
                                sample: format!(
                                    "accepted={} outcome={} target={} envelope={envelope_id}",
                                    response.accepted,
                                    response.delivery.outcome,
                                    response.delivery.target_delivery_id
                                ),
                            }
                        }
                        Err(error) => Mvp5PerfMessage::TransportError {
                            category: mvp5_perf_transport_error_category(
                                "mesh_inbound_error",
                                &error.to_string(),
                            ),
                            sample: mvp5_perf_error_sample(error.to_string()),
                        },
                    };
                    if sender.send(message).is_err() {
                        return;
                    }
                }
            });
        }
    });
    drop(sender);

    let mut results = Vec::with_capacity(config.total_requests.unwrap_or_default());
    let mut benign_event_counts = std::collections::BTreeMap::<String, u64>::new();
    let mut benign_event_samples = std::collections::BTreeMap::<String, String>::new();
    let mut transport_error_counts = std::collections::BTreeMap::<String, u64>::new();
    let mut transport_error_samples = std::collections::BTreeMap::<String, String>::new();
    let mut correctness_error_counts = std::collections::BTreeMap::<String, u64>::new();
    let mut correctness_error_samples = std::collections::BTreeMap::<String, String>::new();
    for message in receiver {
        match message {
            Mvp5PerfMessage::Success(result) => results.push(result),
            Mvp5PerfMessage::BenignEvent { category, sample } => {
                *benign_event_counts.entry(category.clone()).or_default() += 1;
                benign_event_samples.entry(category).or_insert(sample);
            }
            Mvp5PerfMessage::TransportError { category, sample } => {
                *transport_error_counts.entry(category.clone()).or_default() += 1;
                transport_error_samples.entry(category).or_insert(sample);
            }
            Mvp5PerfMessage::CorrectnessError { category, sample } => {
                *correctness_error_counts.entry(category.clone()).or_default() += 1;
                correctness_error_samples.entry(category).or_insert(sample);
            }
        }
    }
    let benign_event_total = benign_event_counts.values().sum::<u64>();
    let transport_error_total = transport_error_counts.values().sum::<u64>();
    let total_envelopes = results
        .len()
        .checked_add(usize::try_from(transport_error_total)?)
        .and_then(|total| total.checked_add(usize::try_from(benign_event_total).ok()?))
        .ok_or("mvp_s8 federation inbound perf attempted envelope count overflow")?;
    if total_envelopes == 0 {
        return Err(
            format!("mvp_s8 federation inbound perf stage {name} produced no attempts").into()
        );
    }
    if !correctness_error_counts.is_empty() {
        return Err(format!(
            "mvp_s8 federation inbound perf stage {name} correctness errors: counts={correctness_error_counts:?} samples={correctness_error_samples:?}"
        )
        .into());
    }
    let degraded_by_transport = !transport_error_counts.is_empty();
    let observed_nonfatal_total =
        results
            .len()
            .checked_add(usize::try_from(benign_event_total)?)
            .ok_or("mvp_s8 federation inbound perf observed nonfatal count overflow")?;
    if observed_nonfatal_total == 0 && !degraded_by_transport {
        return Err(format!(
            "mvp_s8 federation inbound perf stage {name} produced no successful or benign forwards"
        )
        .into());
    }
    if config.duration.is_none()
        && !degraded_by_transport
        && observed_nonfatal_total != total_envelopes
    {
        return Err(format!(
            "mvp_s8 federation inbound perf stage {name} observed {observed_nonfatal_total} nonfatal outcomes of {total_envelopes}"
        )
        .into());
    }
    results.sort_by_key(|result| result.seq);
    let mut previous_seq = None;
    for result in &results {
        if previous_seq == Some(result.seq) {
            return Err(format!(
                "mvp_s8 federation inbound perf stage {name} duplicate seq {}",
                result.seq
            )
            .into());
        }
        previous_seq = Some(result.seq);
    }
    let transport_error_rates = mvp5_perf_error_rates(&transport_error_counts, total_envelopes)?;
    let max_transport_error_rate = transport_error_rates.values().copied().fold(0.0_f64, f64::max);
    let saturated = max_transport_error_rate > MVP5_PERF_TRANSPORT_SATURATION_RATE;
    let elapsed = started.elapsed();
    let client_mesh_after = ramflux_transport::mesh_perf_snapshot();
    let mesh_after = mvp_s8_perf_mesh_observability(node_b)?;
    let router_metrics_after = mvp5_perf_get_json_or_error(
        &format!("{}/perf/metrics", inbound_context.router_url),
        "router_metrics_after",
    );
    let quic_inbound_delta =
        mesh_after.quic_inbound_s8_envelopes.saturating_sub(mesh_before.quic_inbound_s8_envelopes);
    let tcp_inbound_delta =
        mesh_after.tcp_inbound_s8_envelopes.saturating_sub(mesh_before.tcp_inbound_s8_envelopes);
    let total_inbound_delta = quic_inbound_delta.saturating_add(tcp_inbound_delta);
    let tcp_fallback_rate = if total_inbound_delta == 0 {
        0.0
    } else {
        f64::from(u32::try_from(tcp_inbound_delta)?)
            / f64::from(u32::try_from(total_inbound_delta)?)
    };
    let federation_mesh_transport = MvpS8PerfFederationTransportReport {
        quic_inbound_delta,
        tcp_inbound_delta,
        total_inbound_delta,
        tcp_fallback_rate,
    };
    let federation_receive_perf =
        mvp_s8_perf_receive_delta(&mesh_before.receive_perf, &mesh_after.receive_perf)?;
    let client_mesh_transport =
        mvp5_perf_mesh_transport_delta(&client_mesh_before, &client_mesh_after)?;
    let federation_server_mesh_transport =
        mvp5_perf_mesh_transport_delta(&mesh_before.transport_perf, &mesh_after.transport_perf)?;
    let router_submit_perf =
        mvp5_perf_router_submit_delta(&router_metrics_before, &router_metrics_after)?;
    let mut forward_latencies = results.iter().map(|result| result.submit_us).collect::<Vec<_>>();
    let mut empty_ack_latencies = Vec::new();
    let successful_pairs = results.len();
    let deduped_idempotent_retries =
        benign_event_counts.get("deduped_idempotent_retry").copied().unwrap_or_default();
    let correctness = serde_json::json!({
        "mode": if degraded_by_transport {
            "degraded_by_transport_errors"
        } else {
            "strict"
        },
        "successful_inbound_forwards": successful_pairs,
        "benign_event_counts": benign_event_counts,
        "benign_event_samples": benign_event_samples,
        "expected_total": total_envelopes,
        "target_cardinality": inbound_context.target_cardinality,
        "max_successful_seq": results.iter().map(|result| result.seq).max().unwrap_or_default(),
    });
    Ok(Mvp5PerfStageReport {
        name,
        concurrency: config.concurrency,
        total_envelopes,
        configured_total_requests: config.total_requests,
        configured_duration_ms: config.duration.map(|duration| duration.as_millis()),
        successful_pairs,
        saturated,
        saturation_threshold: MVP5_PERF_TRANSPORT_SATURATION_RATE,
        error_rate: max_transport_error_rate,
        elapsed_ms: elapsed.as_millis(),
        throughput_envelopes_per_sec: f64::from(u32::try_from(successful_pairs)?)
            / elapsed.as_secs_f64(),
        attempted_throughput_envelopes_per_sec: f64::from(u32::try_from(total_envelopes)?)
            / elapsed.as_secs_f64(),
        submit_latency: mvp5_latency_summary(&mut forward_latencies),
        ack_latency: mvp5_latency_summary(&mut empty_ack_latencies),
        transport_error_rates,
        transport_error_counts,
        transport_error_samples,
        correctness,
        deduped_idempotent_retries: Some(deduped_idempotent_retries),
        federation_mesh_transport: Some(federation_mesh_transport),
        federation_receive_perf: Some(federation_receive_perf),
        router_submit_perf: Some(router_submit_perf),
        client_mesh_transport: Some(client_mesh_transport),
        federation_server_mesh_transport: Some(federation_server_mesh_transport),
        baseline_note: "federation mesh inbound load; submit_latency records host test client using node-a federation mTLS cert and node-a federation signature directly against node-b /s8/federation/envelope over ramflux_transport cached mesh QUIC. This isolates A2 mesh QUIC receive plus node-b pinned-source verification, A1 trust read, and node-b router submit; no federation HTTP /forward ingress is involved.".to_owned(),
    })
}

#[cfg(feature = "realnet")]
#[allow(clippy::too_many_lines)]
async fn mvp5_perf_run_quic_stage(
    clients: &[std::sync::Arc<ramflux_transport::QuicGatewayClient>],
    config: &Mvp5PerfStageConfig,
) -> Result<Mvp5PerfStageReport, Box<dyn std::error::Error>> {
    let name = format!("quic_{}", config.name);
    let target_delivery_id = format!("target_mvp5_perf_{name}");
    let next_index = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let started = std::time::Instant::now();
    let deadline = config.duration.map(|duration| started + duration);
    let mut tasks = tokio::task::JoinSet::new();
    for worker_id in 0..config.concurrency {
        let client = std::sync::Arc::clone(&clients[worker_id % clients.len()]);
        let target_delivery_id = target_delivery_id.clone();
        let next_index = std::sync::Arc::clone(&next_index);
        let config = config.clone();
        let name = name.clone();
        tasks.spawn(async move {
            let mut messages = Vec::new();
            loop {
                if deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
                    break;
                }
                let index = next_index.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if config.total_requests.is_some_and(|total| index >= total) {
                    break;
                }
                let envelope_id = format!("env_mvp5_perf_{name}_{index:06}");
                let envelope = itest_envelope(&envelope_id, &target_delivery_id);
                let submit_started = std::time::Instant::now();
                let submit = client
                    .post_json::<_, ramflux_node_core::ItestMvp0SubmitResponse>(
                        "/mvp0/envelope",
                        &envelope,
                    )
                    .await;
                let submit_us = submit_started.elapsed().as_micros();
                let message = match submit {
                    Ok(submit) if submit.outcome == "offline_queued" => {
                        let ack_started = std::time::Instant::now();
                        let ack = client
                            .post_json::<_, ramflux_node_core::ItestMvp0CursorResponse>(
                                "/mvp0/ack",
                                &itest_ack(&envelope_id),
                            )
                            .await;
                        let ack_us = ack_started.elapsed().as_micros();
                        match (submit.inbox_seq, ack) {
                            (Some(seq), Ok(_cursor)) => Mvp5PerfMessage::Success(Mvp5PerfResult {
                                seq,
                                envelope_id,
                                submit_us,
                                ack_us,
                            }),
                            (None, Ok(_cursor)) => Mvp5PerfMessage::CorrectnessError {
                                category: "missing_inbox_seq".to_owned(),
                                sample: envelope_id,
                            },
                            (_seq, Err(error)) => Mvp5PerfMessage::TransportError {
                                category: mvp5_perf_transport_error_category(
                                    "ack_error",
                                    &error.to_string(),
                                ),
                                sample: mvp5_perf_error_sample(error.to_string()),
                            },
                        }
                    }
                    Ok(submit) => Mvp5PerfMessage::CorrectnessError {
                        category: "unexpected_submit_outcome".to_owned(),
                        sample: format!("{}:{envelope_id}", submit.outcome),
                    },
                    Err(error) => Mvp5PerfMessage::TransportError {
                        category: mvp5_perf_transport_error_category(
                            "submit_error",
                            &error.to_string(),
                        ),
                        sample: mvp5_perf_error_sample(error.to_string()),
                    },
                };
                messages.push(message);
            }
            messages
        });
    }

    let mut results = Vec::with_capacity(config.total_requests.unwrap_or_default());
    let mut transport_error_counts = std::collections::BTreeMap::<String, u64>::new();
    let mut transport_error_samples = std::collections::BTreeMap::<String, String>::new();
    let mut correctness_error_counts = std::collections::BTreeMap::<String, u64>::new();
    let mut correctness_error_samples = std::collections::BTreeMap::<String, String>::new();
    while let Some(joined) = tasks.join_next().await {
        for message in joined? {
            match message {
                Mvp5PerfMessage::Success(result) => results.push(result),
                Mvp5PerfMessage::TransportError { category, sample } => {
                    *transport_error_counts.entry(category.clone()).or_default() += 1;
                    transport_error_samples.entry(category).or_insert(sample);
                }
                Mvp5PerfMessage::BenignEvent { category, sample }
                | Mvp5PerfMessage::CorrectnessError { category, sample } => {
                    *correctness_error_counts.entry(category.clone()).or_default() += 1;
                    correctness_error_samples.entry(category).or_insert(sample);
                }
            }
        }
    }
    let transport_error_total = transport_error_counts.values().sum::<u64>();
    let total_envelopes = results
        .len()
        .checked_add(usize::try_from(transport_error_total)?)
        .ok_or("mvp5 QUIC perf attempted envelope count overflow")?;
    if total_envelopes == 0 {
        return Err(format!("mvp5 QUIC perf stage {name} produced no attempts").into());
    }
    if !correctness_error_counts.is_empty() {
        return Err(format!(
            "mvp5 QUIC perf stage {name} correctness errors: counts={correctness_error_counts:?} samples={correctness_error_samples:?}"
        )
        .into());
    }
    let degraded_by_transport = !transport_error_counts.is_empty();
    if results.is_empty() && !degraded_by_transport {
        return Err(
            format!("mvp5 QUIC perf stage {name} produced no successful submit+ack pairs").into()
        );
    }
    if config.duration.is_none() && !degraded_by_transport && results.len() != total_envelopes {
        return Err(format!(
            "mvp5 QUIC perf stage {name} completed {} of {total_envelopes}",
            results.len()
        )
        .into());
    }
    results.sort_by_key(|result| result.seq);
    let mut previous_seq = None;
    for result in &results {
        if previous_seq == Some(result.seq) {
            return Err(format!("mvp5 QUIC perf stage {name} duplicate seq {}", result.seq).into());
        }
        previous_seq = Some(result.seq);
    }
    if !degraded_by_transport {
        for (expected_seq, result) in (1_u64..).zip(results.iter()) {
            if result.seq != expected_seq {
                return Err(format!(
                    "mvp5 QUIC perf stage {name} seq gap: expected {expected_seq}, got {}",
                    result.seq
                )
                .into());
            }
        }
    }
    let expected_cursor_seq = if degraded_by_transport {
        results.iter().map(|result| result.seq).max().unwrap_or_default()
    } else {
        u64::try_from(total_envelopes)?
    };
    let expected_acked_len = if degraded_by_transport { results.len() } else { total_envelopes };
    let cursor = match clients[0]
        .get_json::<Option<ramflux_node_core::ItestMvp0CursorResponse>>(&format!(
            "/mvp0/cursor/{target_delivery_id}"
        ))
        .await
    {
        Ok(Some(cursor)) => Some(cursor),
        Ok(None) if degraded_by_transport => None,
        Ok(None) => return Err(format!("missing QUIC cursor for {target_delivery_id}").into()),
        Err(error) if degraded_by_transport => {
            let sample = error.to_string();
            let category = mvp5_perf_transport_error_category("cursor_error", &sample);
            *transport_error_counts.entry(category.clone()).or_default() += 1;
            transport_error_samples.entry(category).or_insert(mvp5_perf_error_sample(sample));
            None
        }
        Err(error) => return Err(Box::new(error)),
    };
    if let Some(cursor) = &cursor {
        if !degraded_by_transport && cursor.inbox_seq != expected_cursor_seq {
            return Err(format!(
                "mvp5 QUIC perf stage {name} cursor seq mismatch seq={} expected={expected_cursor_seq}",
                cursor.inbox_seq
            )
            .into());
        }
        if !degraded_by_transport && cursor.acked_envelope_ids.len() != expected_acked_len {
            return Err(format!(
                "mvp5 QUIC perf stage {name} cursor ack count mismatch acked={} expected={expected_acked_len}",
                cursor.acked_envelope_ids.len()
            )
            .into());
        }
        for result in &results {
            if !cursor.acked_envelope_ids.contains(&result.envelope_id) {
                return Err(format!(
                    "mvp5 QUIC perf stage {name} missing ack for successful envelope {}",
                    result.envelope_id
                )
                .into());
            }
        }
    }
    let transport_error_rates = mvp5_perf_error_rates(&transport_error_counts, total_envelopes)?;
    let max_transport_error_rate = transport_error_rates.values().copied().fold(0.0_f64, f64::max);
    let saturated = max_transport_error_rate > MVP5_PERF_TRANSPORT_SATURATION_RATE;
    let elapsed = started.elapsed();
    let mut submit_latencies = results.iter().map(|result| result.submit_us).collect::<Vec<_>>();
    let mut ack_latencies = results.iter().map(|result| result.ack_us).collect::<Vec<_>>();
    let successful_pairs = results.len();
    let correctness = serde_json::json!({
        "mode": if cursor.is_none() {
            "cursor_unavailable_due_transport_errors"
        } else if degraded_by_transport {
            "degraded_by_transport_errors"
        } else {
            "strict"
        },
        "inbox_seq": cursor.as_ref().map(|cursor| cursor.inbox_seq),
        "acked_envelope_ids": cursor.as_ref().map(|cursor| cursor.acked_envelope_ids.len()),
        "successful_pairs": successful_pairs,
        "expected_total": total_envelopes,
        "max_successful_seq": results.iter().map(|result| result.seq).max().unwrap_or_default(),
    });
    Ok(Mvp5PerfStageReport {
        name,
        concurrency: config.concurrency,
        total_envelopes,
        configured_total_requests: config.total_requests,
        configured_duration_ms: config.duration.map(|duration| duration.as_millis()),
        successful_pairs,
        saturated,
        saturation_threshold: MVP5_PERF_TRANSPORT_SATURATION_RATE,
        error_rate: max_transport_error_rate,
        elapsed_ms: elapsed.as_millis(),
        throughput_envelopes_per_sec: f64::from(u32::try_from(successful_pairs)?)
            / elapsed.as_secs_f64(),
        attempted_throughput_envelopes_per_sec: f64::from(u32::try_from(total_envelopes)?)
            / elapsed.as_secs_f64(),
        submit_latency: mvp5_latency_summary(&mut submit_latencies),
        ack_latency: mvp5_latency_summary(&mut ack_latencies),
        transport_error_rates,
        transport_error_counts,
        transport_error_samples,
        correctness,
        deduped_idempotent_retries: None,
        federation_mesh_transport: None,
        federation_receive_perf: None,
        router_submit_perf: None,
        client_mesh_transport: None,
        federation_server_mesh_transport: None,
        baseline_note:
            "QUIC gateway load; logical requests reuse configured persistent QUIC connections"
                .to_owned(),
    })
}

#[cfg(feature = "realnet")]
fn mvp5_perf_stage_name(
    concurrency: usize,
    total_requests: Option<usize>,
    duration_secs: Option<u64>,
) -> String {
    match (total_requests, duration_secs) {
        (Some(total), Some(duration)) => {
            format!("load_c{concurrency}_n{total}_d{duration}s")
        }
        (Some(total), None) => format!("load_c{concurrency}_n{total}"),
        (None, Some(duration)) => format!("load_c{concurrency}_d{duration}s"),
        (None, None) => format!("load_c{concurrency}_n1000"),
    }
}

#[cfg(feature = "realnet")]
fn mvp5_perf_target_for_index(base: &str, index: usize, cardinality: usize) -> String {
    if cardinality <= 1 { base.to_owned() } else { format!("{base}_{}", index % cardinality) }
}

#[cfg(feature = "realnet")]
fn mvp5_perf_env_usize(name: &str, default: usize) -> Result<usize, Box<dyn std::error::Error>> {
    match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => {
            let parsed = value.trim().parse::<usize>()?;
            if parsed == 0 {
                return Err(format!("{name} must be greater than zero").into());
            }
            Ok(parsed)
        }
        Ok(_) | Err(std::env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(Box::new(error)),
    }
}

#[cfg(feature = "realnet")]
fn mvp5_perf_env_u64(name: &str, default: u64) -> Result<u64, Box<dyn std::error::Error>> {
    match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => {
            let parsed = value.trim().parse::<u64>()?;
            if parsed == 0 {
                return Err(format!("{name} must be greater than zero").into());
            }
            Ok(parsed)
        }
        Ok(_) | Err(std::env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(Box::new(error)),
    }
}

#[cfg(feature = "realnet")]
fn mvp5_perf_env_optional_usize(name: &str) -> Result<Option<usize>, Box<dyn std::error::Error>> {
    match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => {
            let parsed = value.trim().parse::<usize>()?;
            if parsed == 0 {
                return Err(format!("{name} must be greater than zero").into());
            }
            Ok(Some(parsed))
        }
        Ok(_) | Err(std::env::VarError::NotPresent) => Ok(None),
        Err(error) => Err(Box::new(error)),
    }
}

#[cfg(feature = "realnet")]
fn mvp5_perf_env_optional_u64(name: &str) -> Result<Option<u64>, Box<dyn std::error::Error>> {
    match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => {
            let parsed = value.trim().parse::<u64>()?;
            if parsed == 0 {
                return Err(format!("{name} must be greater than zero").into());
            }
            Ok(Some(parsed))
        }
        Ok(_) | Err(std::env::VarError::NotPresent) => Ok(None),
        Err(error) => Err(Box::new(error)),
    }
}

#[cfg(feature = "realnet")]
fn mvp5_perf_env_usize_list(
    name: &str,
    default: &[usize],
) -> Result<Vec<usize>, Box<dyn std::error::Error>> {
    match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => {
            let mut parsed = Vec::new();
            for part in value.split(',') {
                let item = part.trim().parse::<usize>()?;
                if item == 0 {
                    return Err(format!("{name} entries must be greater than zero").into());
                }
                parsed.push(item);
            }
            if parsed.is_empty() {
                return Err(format!("{name} must contain at least one concurrency").into());
            }
            Ok(parsed)
        }
        Ok(_) | Err(std::env::VarError::NotPresent) => Ok(default.to_vec()),
        Err(error) => Err(Box::new(error)),
    }
}

#[cfg(feature = "realnet")]
fn mvp5_perf_transport_error_category(prefix: &str, error: &str) -> String {
    let lower = error.to_ascii_lowercase();
    let kind = if lower.contains("connection reset") {
        "connection_reset"
    } else if lower.contains("connection refused") || lower.contains("os error 111") {
        "connection_refused"
    } else if lower.contains("broken pipe") {
        "broken_pipe"
    } else if lower.contains("timed out") || lower.contains("timeout") {
        "timeout"
    } else if lower.contains("http 5") || lower.contains("status 5") {
        "http_5xx"
    } else if lower.contains("sdkerror") || lower.contains("sdk error") {
        "sdk_error"
    } else {
        "other"
    };
    format!("{prefix}.{kind}")
}

#[cfg(feature = "realnet")]
fn mvp5_perf_error_sample(error: String) -> String {
    const MAX_SAMPLE_CHARS: usize = 300;
    if error.chars().count() <= MAX_SAMPLE_CHARS {
        return error;
    }
    let mut sample = error.chars().take(MAX_SAMPLE_CHARS).collect::<String>();
    sample.push_str("...");
    sample
}

#[cfg(feature = "realnet")]
fn mvp5_perf_error_rates(
    counts: &std::collections::BTreeMap<String, u64>,
    total: usize,
) -> Result<std::collections::BTreeMap<String, f64>, Box<dyn std::error::Error>> {
    let total = u32::try_from(total)?;
    let mut rates = std::collections::BTreeMap::new();
    for (category, count) in counts {
        let count = u32::try_from(*count)?;
        rates.insert(category.clone(), f64::from(count) / f64::from(total));
    }
    Ok(rates)
}

#[cfg(feature = "realnet")]
fn mvp5_latency_summary(latencies: &mut [u128]) -> Mvp5LatencySummary {
    latencies.sort_unstable();
    Mvp5LatencySummary {
        count: latencies.len(),
        p50_us: mvp5_percentile(latencies, 500),
        p95_us: mvp5_percentile(latencies, 950),
        p99_us: mvp5_percentile(latencies, 990),
        max_us: latencies.last().copied().unwrap_or_default(),
    }
}

#[cfg(feature = "realnet")]
fn mvp5_percentile(sorted: &[u128], per_mille: usize) -> u128 {
    if sorted.is_empty() {
        return 0;
    }
    let index = sorted
        .len()
        .saturating_mul(per_mille)
        .saturating_add(999)
        .saturating_div(1_000)
        .saturating_sub(1)
        .min(sorted.len() - 1);
    sorted[index]
}

#[cfg(feature = "realnet")]
fn mvp5_perf_reset_metrics(
    gateway_url: &str,
    router_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let _: serde_json::Value =
        ramflux_node_core::itest_http_post_json(&format!("{gateway_url}/perf/metrics/reset"), &())?;
    let _: serde_json::Value =
        ramflux_node_core::itest_http_post_json(&format!("{router_url}/perf/metrics/reset"), &())?;
    Ok(())
}

#[cfg(feature = "realnet")]
fn mvp5_perf_artifact_path(
    file_name: &str,
) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let dir = code_root().join("ramflux-itest/perf-artifacts");
    std::fs::create_dir_all(&dir)?;
    Ok(dir.join(file_name))
}

#[cfg(feature = "realnet")]
fn mvp5_perf_now_unix_seconds() -> Result<u64, Box<dyn std::error::Error>> {
    Ok(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs())
}

#[cfg(feature = "realnet")]
fn mvp5_perf_ratio(
    numerator: Option<&serde_json::Value>,
    denominator: Option<&serde_json::Value>,
) -> Option<f64> {
    let numerator = numerator.and_then(serde_json::Value::as_u64)?;
    let denominator = denominator.and_then(serde_json::Value::as_u64)?;
    if denominator == 0 {
        return None;
    }
    let numerator = u32::try_from(numerator).ok()?;
    let denominator = u32::try_from(denominator).ok()?;
    Some(f64::from(numerator) / f64::from(denominator))
}

#[cfg(feature = "realnet")]
fn mvp5_perf_ratio_from_u64(
    numerator: u64,
    denominator: u64,
) -> Result<Option<f64>, Box<dyn std::error::Error>> {
    if denominator == 0 {
        return Ok(None);
    }
    Ok(Some(f64::from(u32::try_from(numerator)?) / f64::from(u32::try_from(denominator)?)))
}

#[cfg(feature = "realnet")]
struct Mvp5ContainerStatsSampler {
    running: std::sync::Arc<std::sync::atomic::AtomicBool>,
    samples: std::sync::Arc<std::sync::Mutex<Vec<serde_json::Value>>>,
    handle: Option<std::thread::JoinHandle<()>>,
}

#[cfg(feature = "realnet")]
impl Mvp5ContainerStatsSampler {
    fn start(deploy_root: std::path::PathBuf) -> Self {
        let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let samples = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let thread_running = std::sync::Arc::clone(&running);
        let thread_samples = std::sync::Arc::clone(&samples);
        let handle = std::thread::spawn(move || {
            while thread_running.load(std::sync::atomic::Ordering::Relaxed) {
                let sample = mvp5_container_stats_sample(&deploy_root);
                if let Ok(mut samples) = thread_samples.lock() {
                    samples.push(sample);
                }
                std::thread::sleep(std::time::Duration::from_secs(5));
            }
            let sample = mvp5_container_stats_sample(&deploy_root);
            if let Ok(mut samples) = thread_samples.lock() {
                samples.push(sample);
            }
        });
        Self { running, samples, handle: Some(handle) }
    }

    fn snapshot(&self) -> Vec<serde_json::Value> {
        self.samples.lock().map_or_else(|_| Vec::new(), |samples| samples.clone())
    }

    fn stop(mut self) -> Vec<serde_json::Value> {
        self.running.store(false, std::sync::atomic::Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        match std::sync::Arc::try_unwrap(self.samples) {
            Ok(samples) => samples.into_inner().unwrap_or_default(),
            Err(samples) => samples.lock().map_or_else(|_| Vec::new(), |samples| samples.clone()),
        }
    }
}

#[cfg(feature = "realnet")]
fn mvp5_container_stats_sample(deploy_root: &std::path::Path) -> serde_json::Value {
    let timestamp = mvp5_perf_now_unix_seconds().unwrap_or_default();
    let ids = match std::process::Command::new("docker")
        .arg("compose")
        .arg("-f")
        .arg("docker-compose.itest.yml")
        .arg("ps")
        .arg("-q")
        .arg("ramflux-gateway")
        .arg("ramflux-router")
        .current_dir(deploy_root)
        .output()
    {
        Ok(output) if output.status.success() => String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>(),
        Ok(output) => {
            return serde_json::json!({
                "timestamp_unix": timestamp,
                "error": format!("docker compose ps failed with {}", output.status)
            });
        }
        Err(error) => {
            return serde_json::json!({
                "timestamp_unix": timestamp,
                "error": format!("docker compose ps failed: {error}")
            });
        }
    };
    if ids.is_empty() {
        return serde_json::json!({"timestamp_unix": timestamp, "stats": []});
    }
    let output = std::process::Command::new("docker")
        .arg("stats")
        .arg("--no-stream")
        .arg("--format")
        .arg("{{json .}}")
        .args(&ids)
        .output();
    match output {
        Ok(output) if output.status.success() => {
            let lines = String::from_utf8_lossy(&output.stdout)
                .lines()
                .map(str::to_owned)
                .collect::<Vec<_>>();
            serde_json::json!({"timestamp_unix": timestamp, "stats": lines})
        }
        Ok(output) => serde_json::json!({
            "timestamp_unix": timestamp,
            "error": format!("docker stats failed with {}", output.status)
        }),
        Err(error) => {
            serde_json::json!({"timestamp_unix": timestamp, "error": format!("docker stats failed: {error}")})
        }
    }
}

#[cfg(feature = "realnet")]
#[test]
fn mvp4_realnet_trusted_zero_directory_cross_node_dm() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    realnet_step("TEST mvp4 start", "mvp4_realnet_trusted_zero_directory_cross_node_dm");
    let node_a = start_s8_realnet_compose_project(
        "ramflux-mvp4-node-a",
        S8ComposePorts {
            gateway_http: 54_181,
            gateway_quic: 54_451,
            router_http: 54_180,
            router_mesh: 54_453,
            notify_http: 54_183,
            federation_http: 54_182,
            federation_mesh: 54_452,
            relay_http: 54_184,
            relay_media_udp: 54_100,
            signaling_turn_udp: 54_478,
            signaling_turn_tcp: 54_479,
            retention_http: 54_187,
        },
    )?;
    realnet_step(
        "TEST mvp4 node-a ready",
        format!(
            "node={} gateway={} federation={}",
            node_a.node_id, node_a.gateway_url, node_a.federation_url
        ),
    );
    let node_b = start_s8_realnet_compose_project(
        "ramflux-mvp4-node-b",
        S8ComposePorts {
            gateway_http: 64_181,
            gateway_quic: 64_451,
            router_http: 64_180,
            router_mesh: 64_453,
            notify_http: 64_183,
            federation_http: 64_182,
            federation_mesh: 64_452,
            relay_http: 64_184,
            relay_media_udp: 64_100,
            signaling_turn_udp: 64_478,
            signaling_turn_tcp: 64_479,
            retention_http: 64_187,
        },
    )?;
    realnet_step(
        "TEST mvp4 node-b ready",
        format!(
            "node={} gateway={} federation={}",
            node_b.node_id, node_b.gateway_url, node_b.federation_url
        ),
    );
    assert_ne!(node_a.federation_node_public_key, node_b.federation_node_public_key);
    let ca_cert = code_root().join("ramflux/deploy/certs/ca.pem");
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async {
        realnet_step("TEST mvp4 enter async federation flow", "zero-directory invitation path");
        Box::pin(mvp_s8_assert_cross_node_rf_dm(&node_a, &node_b, &ca_cert)).await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    drop(node_b);
    drop(node_a);
    Ok(())
}

#[cfg(feature = "realnet")]
#[test]
fn mvp4_realnet_home_node_migration_backfill() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    let realnet = start_realnet_compose()?;
    let gateway_url = &realnet.gateway_url;
    let federation_url = std::env::var("RAMFLUX_ITEST_FEDERATION_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:18082".to_owned());
    wait_for_federation(&federation_url)?;

    let fixture = mvp1_dm_realnet_fixture()?;
    register_mvp1_identity(gateway_url, &fixture.bob_register)?;
    publish_mvp1_prekey(gateway_url, "bob_device_realnet", &fixture.bob_prekey_bundle)?;
    register_mvp1_identity(gateway_url, &fixture.alice_register)?;
    register_mvp1_identity(gateway_url, &mvp4_bob_new_device_register()?)?;

    let fetched: ramflux_node_core::ItestMvp1PrekeyResponse =
        ramflux_node_core::itest_http_get_json(&format!(
            "{gateway_url}/mvp1/prekey/bob_device_realnet"
        ))?;
    let bob_bundle = fetched.bundle.ok_or("missing bob prekey bundle")?;
    let (mut alice_session, mut bob_session) = establish_mvp1_dm_sessions(&fixture, &bob_bundle)?;

    let mut mesh = ramflux_sync::FederationMesh::new();
    mesh.register_node("node_a.realnet", "https://node-a.realnet/federation");
    mesh.register_node("node_b.realnet", "https://node-b.realnet/federation");
    mesh.register_node("node_c.realnet", "https://node-c.realnet/federation");
    mesh.establish_trusted_link("node_a.realnet", "node_b.realnet")?;
    mesh.establish_trusted_link("node_a.realnet", "node_c.realnet")?;
    mesh.bind_identity_home("alice_realnet", "node_a.realnet")?;
    mesh.bind_identity_home("bob_realnet", "node_b.realnet")?;

    assert_mvp4_migration_steps(&mvp4_home_node_migration_steps());
    let old_route = publish_mvp4_named_federation_route(
        &federation_url,
        "node_b.realnet",
        ramflux_node_core::FederationTrustStatus::Active,
    )?;
    assert!(old_route.can_deliver);
    let new_route = publish_mvp4_named_federation_route(
        &federation_url,
        "node_c.realnet",
        ramflux_node_core::FederationTrustStatus::Active,
    )?;
    assert!(new_route.can_deliver);

    let migration = mesh.migrate_home_node(ramflux_sync::HomeNodeMigration {
        identity: "bob_realnet".to_owned(),
        old_home_node: "node_b.realnet".to_owned(),
        new_home_node: "node_c.realnet".to_owned(),
        proof_hash: "home_node_migration_proof_hash_mvp4".to_owned(),
    })?;
    assert_eq!(migration.new_home_node, "node_c.realnet");
    let migrated_old = set_mvp4_federation_route_status(
        &federation_url,
        "node_b.realnet",
        ramflux_node_core::FederationTrustStatus::Migrated,
    )?;
    assert!(migrated_old.can_deliver);

    let cutover = mesh.deliver_during_cutover(
        "alice_realnet",
        "bob_realnet",
        "node_b.realnet",
        b"opaque-cutover",
    )?;
    assert_eq!(cutover.delivered_to, "node_c.realnet");
    assert!(cutover.used_forward || cutover.used_nack_reresolve);

    let migrated_plaintext = br#"{"type":"federation.dm","migration_proof_hash":"home_node_migration_proof_hash_mvp4","body":"after-migration"}"#;
    let migrated_dm = deliver_mvp4_cross_node_dm(Mvp4CrossNodeDmDelivery {
        gateway_url,
        mesh: &mut mesh,
        envelope_id: "env_mvp4_after_migration_dm",
        target_delivery_id: "bob_target_mvp1_realnet",
        sender_session: &mut alice_session,
        receiver_session: &mut bob_session,
        from_identity: "alice_realnet",
        to_identity: "bob_realnet",
        plaintext: migrated_plaintext,
    })?;
    assert_eq!(migrated_dm.via_node, "node_c.realnet");
    assert_eq!(migrated_dm.decrypted_plaintext, migrated_plaintext);

    let imported =
        deliver_mvp4_new_device_backfill(gateway_url, &mut alice_session, &mut bob_session)?;
    assert_eq!(imported.event_body("evt_mvp4_identity")?, Some(b"identity-event".to_vec()));
    assert_eq!(imported.event_body("evt_mvp4_message")?, Some(b"message-event".to_vec()));
    assert_eq!(
        imported.projection_checkpoint("conversation")?,
        Some("evt_mvp4_message".to_owned())
    );
    Ok(())
}

#[cfg(feature = "realnet")]
#[test]
fn mvp4_realnet_partition_convergence_gossip() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping realnet full test; set RAMFLUX_ITEST_REALNET=1");
        return Ok(());
    }

    let realnet = start_realnet_compose()?;
    let gateway_url = &realnet.gateway_url;
    let federation_url = std::env::var("RAMFLUX_ITEST_FEDERATION_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:18082".to_owned());
    wait_for_federation(&federation_url)?;

    let mut context = mvp4_partition_realnet_context(gateway_url, &federation_url)?;
    let (left, right) = mvp4_partition_divergent_checkpoints()?;

    let left_delivery = deliver_mvp4_group_partition_gossip(Mvp4GroupPartitionGossipDelivery {
        gateway_url,
        mesh: &mut context.mesh,
        envelope_id: "env_mvp4_partition_left_checkpoint",
        target_delivery_id: "bob_target_mvp1_realnet",
        sender_session: &mut context.alice_to_bob,
        receiver_session: &mut context.bob_receiver,
        associated_data: b"alice_device|bob_device",
        from_identity: "alice_realnet",
        to_identity: "bob_realnet",
        checkpoint: &left,
    })?;
    assert_eq!(left_delivery.via_node, "node_b.realnet");
    assert_eq!(left_delivery.checkpoint, left);

    let right_delivery = deliver_mvp4_group_partition_gossip(Mvp4GroupPartitionGossipDelivery {
        gateway_url,
        mesh: &mut context.mesh,
        envelope_id: "env_mvp4_partition_right_checkpoint",
        target_delivery_id: "carol_target_mvp4_partition_realnet",
        sender_session: &mut context.alice_to_carol,
        receiver_session: &mut context.carol_receiver,
        associated_data: b"alice_device|carol_device",
        from_identity: "alice_realnet",
        to_identity: "carol_realnet",
        checkpoint: &right,
    })?;
    assert_eq!(right_delivery.via_node, "node_c.realnet");
    assert_eq!(right_delivery.checkpoint, right);

    let bob_projection = resolve_mvp4_group_partition(
        &context.mesh,
        &left_delivery.checkpoint,
        &right_delivery.checkpoint,
    )?;
    let carol_projection = resolve_mvp4_group_partition(
        &context.mesh,
        &right_delivery.checkpoint,
        &left_delivery.checkpoint,
    )?;
    assert_eq!(bob_projection, carol_projection);
    assert_eq!(bob_projection.group_epoch, 3);
    assert_eq!(bob_projection.sender_key_epoch, 3);
    assert_eq!(bob_projection.members, BTreeSet::from(["alice_realnet".to_owned()]));
    assert_eq!(
        bob_projection.projected_message_ids,
        vec!["msg_left_alice".to_owned(), "msg_right_alice".to_owned()]
    );
    assert_eq!(
        bob_projection.rejected_message_ids,
        vec!["msg_left_bob".to_owned(), "msg_right_carol".to_owned()]
    );
    assert_eq!(
        bob_projection.auth_chain_event_ids,
        vec!["evt_remove_bob_from_right".to_owned(), "evt_remove_carol_from_left".to_owned()]
    );
    assert!(!bob_projection.group_lineage_head.is_empty());
    Ok(())
}
