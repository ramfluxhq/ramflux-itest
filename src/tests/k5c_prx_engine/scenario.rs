// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

//! Real native daemons, real PRX container and deterministic in-memory model endpoint.
use super::{
    TestResult,
    fake_llm::{self, FakeLlm},
    prx_fixture,
};
use crate::*;
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
#[path = "flows.rs"]
mod flows;
const DM: &str = "k5c-dm";
const GROUP: &str = "k5c-group";
const THREAD: &str = "k5c-group-thread";
pub(super) fn run(supervised: bool) -> TestResult {
    if std::env::var("RAMFLUX_ITEST_REALNET").as_deref() != Ok("1") {
        eprintln!("skipping k5c: set RAMFLUX_ITEST_REALNET=1 on a container host");
        return Ok(());
    }
    let base = if supervised { 63900 } else { 63800 };
    let topology = start_client_discovery_topology_named(
        if supervised { "ramflux-k5c2-prx" } else { "ramflux-k5c-prx" },
        base,
    )?;
    let result =
        tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async {
            wait_for_private_gateway_quic(
                format!("127.0.0.1:{}", base + 43).parse()?,
                &topology.ca,
            )
            .await?;
            let mut context = Context::start(&topology, supervised).await?;
            let result = if supervised {
                flows::supervised(&mut context).await
            } else {
                flows::full(&mut context).await
            };
            if result.is_err() {
                context.failure_diagnostics();
            }
            result
        });
    if result.is_err() {
        topology.dump_contact_failure_logs();
    }
    result
}
struct Context {
    root: PathBuf,
    state: PathBuf,
    config: PathBuf,
    log: PathBuf,
    host_binary: PathBuf,
    host: tokio::process::Child,
    _daemons: [tokio::process::Child; 2],
    prx: prx_fixture::runtime::PrxProcess,
    alice: ramflux_sdk::LocalBusClient,
    agent: ramflux_sdk::LocalBusClient,
    human: NativeAccount,
    ai: NativeAccount,
    llm: FakeLlm,
}
async fn call(
    bus: &mut ramflux_sdk::LocalBusClient,
    account: &str,
    method: &str,
    body: Value,
) -> TestResult<Value> {
    Ok(bus.request(Some(account.into()), "k5c", method, body).await?)
}
async fn binary(name: &str, features: &str) -> TestResult<PathBuf> {
    let target = std::env::var_os("CARGO_TARGET_DIR")
        .map_or_else(|| code_root().join("ramflux/target"), PathBuf::from);
    let status = tokio::process::Command::new("cargo")
        .args(["build", "--manifest-path"])
        .arg(code_root().join("ramflux/Cargo.toml"))
        .args(["--bin", name, "--features", features, "--target-dir"])
        .arg(&target)
        .env_remove("CARGO_TARGET_DIR")
        .env("RAMFLUX_ITEST_BUILD", "1")
        .status()
        .await?;
    if !status.success() {
        return Err(format!("k5c binary build failed: {name}").into());
    }
    Ok(target.join("debug").join(name))
}
async fn configure(rf: &Path, socket: &Path, origin: &str) -> TestResult {
    for args in [
        vec!["node", "add", origin],
        vec!["node", "confirm", "localhost"],
        vec!["node", "set-default", "localhost"],
    ] {
        let mut full = vec!["--socket", socket.to_str().ok_or("socket path")?];
        full.extend(args);
        mvp_s10_rf_json(rf, &full, "k5c node profile").await?;
    }
    Ok(())
}
fn spawn_host(
    binary: &Path,
    config: &Path,
    log: &Path,
    bundle: Option<&Path>,
) -> TestResult<tokio::process::Child> {
    let file = fs::OpenOptions::new().create(true).append(true).open(log)?;
    fs::set_permissions(log, fs::Permissions::from_mode(0o600))?;
    let mut command = tokio::process::Command::new(binary);
    command
        .args(["--config"])
        .arg(config)
        .arg("--itest-memory-vault")
        .kill_on_drop(true)
        .stdout(std::process::Stdio::null())
        .stderr(file);
    if let Some(bundle) = bundle {
        command.arg("--provisioning-bundle").arg(bundle);
    }
    Ok(command.spawn()?)
}
impl Context {
    fn failure_diagnostics(&mut self) {
        eprintln!("STEP: k5c failure host_status={:?}", self.host.try_wait());
        if let Ok(logs) = fs::read_to_string(&self.log) {
            // Host diagnostic lines contain typed reasons/counters, never frame bodies.
            for line in logs
                .lines()
                .filter(|line| line.starts_with("agent host "))
                .rev()
                .take(40)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
            {
                eprintln!("STEP: k5c failure {line}");
            }
        }
        if let Ok(state) = self.checkpoint() {
            for field in ["inbound", "turns", "erases", "decisions"] {
                eprintln!(
                    "STEP: k5c failure checkpoint_{field}={}",
                    state["engine"][field].as_object().map_or(0, serde_json::Map::len)
                );
            }
        }
        self.prx.diagnostics();
    }
    async fn start(topology: &ClientDiscoveryTopology, supervised: bool) -> TestResult<Self> {
        let root = temp_root("k5c")?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        let rf = binary("rf", "itest-local-mint,itest-memory-vault").await?;
        let host_binary = binary("ramflux-agent-host", "itest-memory-vault").await?;
        let a = root.join("a.sock");
        let b = root.join("b.sock");
        let daemon = |socket: &Path, data: &str| {
            let mut command = native_client_directory_daemon_command(
                &rf,
                socket,
                &root.join(data),
                &topology.ca,
                None,
            );
            command
                .kill_on_drop(true)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null());
            command.spawn()
        };
        let daemons = [daemon(&a, "a")?, daemon(&b, "b")?];
        mvp_s4_wait_for_socket(&a).await?;
        mvp_s4_wait_for_socket(&b).await?;
        configure(&rf, &a, &topology.origin).await?;
        configure(&rf, &b, &topology.origin).await?;
        let human = create_native_account(&a, "K5C member").await?;
        let custodian = create_native_account(&b, "K5C custodian").await?;
        let bundle = root.join("agent.bundle");
        let ai = create_native_agent_account(&b, "K5C agent", &custodian, &bundle).await?;
        let mut alice = ramflux_sdk::LocalBusClient::connect(&a).await?;
        let mut agent = ramflux_sdk::LocalBusClient::connect(&b).await?;
        call(&mut alice, &human.account_id, "contact.add", json!({"principal_id":ai.principal_id}))
            .await?;
        call(
            &mut agent,
            &ai.account_id,
            "contact.accept",
            json!({"principal_id":human.principal_id}),
        )
        .await?;
        call(
            &mut alice,
            &human.account_id,
            "subscription.open",
            json!({"topics":[],"attended_frontend":true}),
        )
        .await?;
        if supervised {
            verify(&mut alice, &mut agent, &human, &ai).await?;
        }
        let llm = FakeLlm::start()?;
        let prx = prx_fixture::start(&root, &ai.account_id, llm.port)?;
        mvp_s4_wait_for_socket(&root.join("prx-run/ramflux.sock")).await?;
        let config = root.join("host.json");
        let state = root.join("state.json");
        let log = root.join("host.log");
        fs::write(
            &config,
            serde_json::to_vec(
                &json!({"socket":b,"state_file":state,"account_id":ai.account_id,"poll_interval_ms":50,"per_conversation_interval_ms":100,
            "engine":{"prx_bridge":{"socket_path":root.join("prx-run/ramflux.sock"),"authorization":if supervised{"supervised"}else{"full"},"turn_timeout_s":75}}}),
            )?,
        )?;
        fs::set_permissions(&config, fs::Permissions::from_mode(0o600))?;
        let host = spawn_host(&host_binary, &config, &log, Some(&bundle))?;
        let mut context = Self {
            root,
            state,
            config,
            log,
            host_binary,
            host,
            _daemons: daemons,
            prx,
            alice,
            agent,
            human,
            ai,
            llm,
        };
        if let Err(error) = context.ready().await {
            context.failure_diagnostics();
            return Err(error);
        }
        assert!(!bundle.exists(), "agent provisioning bundle was not consumed");
        Ok(context)
    }
    async fn ready(&mut self) -> TestResult {
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if self.host.try_wait()?.is_some() {
                    return Err("agent-host exited before checkpoint".into());
                }
                if self.checkpoint().is_ok_and(|s| s["cursor"].is_u64()) {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await?
    }
    fn checkpoint(&self) -> TestResult<Value> {
        Ok(serde_json::from_slice(&fs::read(&self.state)?)?)
    }
    async fn receive(&mut self) -> TestResult {
        call(
            &mut self.alice,
            &self.human.account_id,
            "message.receive",
            json!({"limit":64,"auto_fetch_attachments":false}),
        )
        .await?;
        Ok(())
    }
    async fn send(&mut self, conversation: &str, id: &str, text: &str) -> TestResult {
        if conversation == THREAD {
            call(&mut self.alice,&self.human.account_id,"group.send",json!({"group_id":GROUP,"conversation_id":THREAD,"message_id":id,"sender_id":self.human.principal_id,"encrypted_body_base64":"","plaintext_body_base64":ramflux_protocol::encode_base64url(text.as_bytes()),"metadata":{"mentions":[self.ai.principal_id]}})).await?;
        } else {
            let directory = call(
                &mut self.alice,
                &self.human.account_id,
                "identity.directory",
                json!({"limit":100}),
            )
            .await?;
            let peer = directory["identities"]
                .as_array()
                .and_then(|rows| rows.iter().find(|p| p["principal_id"] == self.ai.principal_id))
                .ok_or("agent route absent")?;
            let device = peer["devices"]
                .as_array()
                .and_then(|rows| rows.iter().find(|d| d["device_id"] == self.ai.device_id))
                .ok_or("agent device absent")?;
            call(&mut self.alice,&self.human.account_id,"message.submit",json!({"conversation_id":conversation,"message_id":id,"envelope_id":id,"source_principal_id":self.human.principal_id,"sender_id":self.human.device_id,"recipient_device_id":device["device_id"],"recipient_principal_commitment":peer["contact_identity_commitment"],"target_delivery_id":device["target_delivery_id"],"encrypted_body_base64":"","plaintext_body_base64":ramflux_protocol::encode_base64url(text.as_bytes()),"created_at":realnet_now_i64(),"ttl":300})).await?;
        }
        Ok(())
    }
    async fn replies(&mut self, conversation: &str) -> TestResult<Vec<Value>> {
        self.receive().await?;
        let read = call(
            &mut self.alice,
            &self.human.account_id,
            "message.read",
            json!({"conversation_id":conversation}),
        )
        .await?;
        let rows = read["messages"].as_array().ok_or("message rows absent")?;
        Ok(rows
            .iter()
            .filter(|m| {
                m["sender_id"] == self.ai.principal_id
                    && m["content_type"] != "surface"
                    && m["deleted"] != true
            })
            .cloned()
            .collect())
    }
    async fn reply(
        &mut self,
        conversation: &str,
        count: usize,
        expected: &str,
        bound: u64,
    ) -> TestResult {
        tokio::time::timeout(Duration::from_secs(bound), async {
            loop {
                let replies = self.replies(conversation).await?;
                assert!(replies.len() <= count, "duplicate signed text reply");
                if replies.len() == count {
                    let reply = replies.last().ok_or("reply missing")?;
                    assert_eq!(reply["body_utf8"], expected);
                    assert_eq!(reply["sender_device_id"], self.ai.device_id);
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await?
    }
    async fn stop_host(&mut self) -> TestResult<Value> {
        let pid = self.host.id().ok_or("host pid absent")?;
        let status =
            tokio::process::Command::new("kill").args(["-INT", &pid.to_string()]).status().await?;
        assert!(status.success());
        assert!(tokio::time::timeout(Duration::from_secs(10), self.host.wait()).await??.success());
        let logs = fs::read_to_string(&self.log)?;
        let counters = logs
            .lines()
            .rev()
            .find_map(|s| s.strip_prefix("agent host bridge stats "))
            .ok_or("bridge stats absent at shutdown")?;
        Ok(serde_json::from_str(counters)?)
    }
    async fn restart(&mut self) -> TestResult {
        self.host = spawn_host(&self.host_binary, &self.config, &self.log, None)?;
        self.ready().await
    }
}
async fn verify(
    a: &mut ramflux_sdk::LocalBusClient,
    b: &mut ramflux_sdk::LocalBusClient,
    human: &NativeAccount,
    ai: &NativeAccount,
) -> TestResult {
    let mut numbers = Vec::new();
    for (bus, owner, peer) in [(a, human, ai), (b, ai, human)] {
        let number = call(
            bus,
            &owner.account_id,
            "contact.safety_number",
            json!({"contact_identity_commitment":peer.anchor}),
        )
        .await?;
        numbers.push(number["safety_number"].clone());
        let checked = call(
            bus,
            &owner.account_id,
            "contact.verify",
            json!({"contact_identity_commitment":peer.anchor}),
        )
        .await?;
        assert_eq!(checked["verification_state"], "verified");
    }
    assert_eq!(numbers[0], numbers[1]);
    Ok(())
}
