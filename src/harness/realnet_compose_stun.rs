// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Span Brain

#![allow(unused_imports)]
use crate::*;

#[cfg(all(test, feature = "realnet"))]
#[derive(Clone, Copy, Default)]
pub(crate) struct ItestComposeOverrides {
    pub(crate) federation_compio: bool,
    pub(crate) gateway_compio: bool,
    pub(crate) notify_mesh: bool,
    pub(crate) notify_runtime: NotifyRuntimeComposeOverride,
}

#[cfg(all(test, feature = "realnet"))]
impl ItestComposeOverrides {
    fn with_env_defaults(self) -> Self {
        Self { notify_mesh: self.notify_mesh || notify_mesh_compose_enabled(), ..self }
    }
}

#[cfg(all(test, feature = "realnet"))]
#[derive(Clone, Copy, Default, Eq, PartialEq)]
pub(crate) enum NotifyRuntimeComposeOverride {
    #[default]
    Current,
    TokioConcurrent,
    Compio,
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn run_deploy_script(
    code_root: &Path,
    script: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let status = std::process::Command::new("sh").arg(script).current_dir(code_root).status()?;
    if !status.success() {
        return Err(format!("{script} failed with {status}").into());
    }
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn run_deploy_script_with_env(
    code_root: &Path,
    script: &str,
    env: &[(String, String)],
) -> Result<(), Box<dyn std::error::Error>> {
    let status = std::process::Command::new("sh")
        .arg(script)
        .envs(env.iter().map(|(key, value)| (key, value)))
        .current_dir(code_root)
        .status()?;
    if !status.success() {
        return Err(format!("{script} failed with {status}").into());
    }
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn run_docker_compose(
    deploy_root: &Path,
    args: &[&str],
) -> Result<(), Box<dyn std::error::Error>> {
    run_docker_compose_with_env(deploy_root, &[], args)
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn run_docker_compose_with_env(
    deploy_root: &Path,
    env: &[(String, String)],
    args: &[&str],
) -> Result<(), Box<dyn std::error::Error>> {
    run_docker_compose_with_env_and_overrides(deploy_root, env, args, false, false, false)
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn run_docker_compose_with_env_and_overrides(
    deploy_root: &Path,
    env: &[(String, String)],
    args: &[&str],
    gateway_compio: bool,
    notify_compio: bool,
    notify_tokio_concurrent: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    ensure_itest_shared_network()?;
    let compose_env = compose_env_with_required_defaults(env);
    let mut command = std::process::Command::new("docker");
    command.arg("compose");
    let _env_file = add_compose_env_file_arg(&mut command, "itest", &compose_env)?;
    add_itest_compose_files(
        &mut command,
        ItestComposeOverrides {
            gateway_compio,
            notify_runtime: notify_compose_override(notify_compio, notify_tokio_concurrent),
            ..ItestComposeOverrides::default()
        },
    );
    command
        .args(args)
        .envs(compose_env.iter().map(|(key, value)| (key, value)))
        .current_dir(deploy_root);
    let status = command.status()?;
    if !status.success() {
        return Err(format!("docker compose {args:?} failed with {status}").into());
    }
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) struct ComposeDownGuard {
    pub(crate) deploy_root: PathBuf,
    pub(crate) gateway_compio: bool,
    pub(crate) notify_compio: bool,
    pub(crate) notify_tokio_concurrent: bool,
}

#[cfg(all(test, feature = "realnet"))]
impl ComposeDownGuard {
    pub(crate) fn new(deploy_root: PathBuf) -> Self {
        Self::new_with_overrides(deploy_root, false, false, false)
    }

    pub(crate) fn new_with_overrides(
        deploy_root: PathBuf,
        gateway_compio: bool,
        notify_compio: bool,
        notify_tokio_concurrent: bool,
    ) -> Self {
        Self { deploy_root, gateway_compio, notify_compio, notify_tokio_concurrent }
    }
}

#[cfg(all(test, feature = "realnet"))]
impl Drop for ComposeDownGuard {
    fn drop(&mut self) {
        let compose_env = compose_env_with_required_defaults(&[]);
        let mut command = std::process::Command::new("docker");
        command.arg("compose");
        let _env_file = add_compose_env_file_arg(&mut command, "itest-down", &compose_env).ok();
        add_itest_compose_files(
            &mut command,
            ItestComposeOverrides {
                gateway_compio: self.gateway_compio,
                notify_runtime: notify_compose_override(
                    self.notify_compio,
                    self.notify_tokio_concurrent,
                ),
                ..ItestComposeOverrides::default()
            },
        );
        let _status = command
            .arg("down")
            .arg("-v")
            .envs(compose_env.iter().map(|(key, value)| (key, value)))
            .current_dir(&self.deploy_root)
            .status();
    }
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) struct ComposeProjectDownGuard {
    pub(crate) deploy_root: PathBuf,
    pub(crate) project_name: String,
    pub(crate) env: Vec<(String, String)>,
    pub(crate) federation_compio: bool,
    pub(crate) gateway_compio: bool,
    pub(crate) notify_compio: bool,
}

#[cfg(all(test, feature = "realnet"))]
impl ComposeProjectDownGuard {
    pub(crate) fn new(
        deploy_root: PathBuf,
        project_name: String,
        env: Vec<(String, String)>,
        federation_compio: bool,
    ) -> Self {
        Self::new_with_overrides(deploy_root, project_name, env, federation_compio, false, false)
    }

    pub(crate) fn new_with_overrides(
        deploy_root: PathBuf,
        project_name: String,
        env: Vec<(String, String)>,
        federation_compio: bool,
        gateway_compio: bool,
        notify_compio: bool,
    ) -> Self {
        Self { deploy_root, project_name, env, federation_compio, gateway_compio, notify_compio }
    }
}

#[cfg(all(test, feature = "realnet"))]
impl Drop for ComposeProjectDownGuard {
    fn drop(&mut self) {
        let compose_env = compose_env_with_required_defaults(&self.env);
        dump_compose_logs(
            &self.deploy_root,
            &self.project_name,
            &compose_env,
            self.federation_compio,
            self.gateway_compio,
            self.notify_compio,
        );
        let mut command = std::process::Command::new("docker");
        command.arg("compose");
        let _env_file =
            add_compose_env_file_arg(&mut command, &self.project_name, &compose_env).ok();
        command.arg("-p").arg(&self.project_name);
        add_itest_compose_files(
            &mut command,
            ItestComposeOverrides {
                federation_compio: self.federation_compio,
                gateway_compio: self.gateway_compio,
                notify_runtime: if self.notify_compio {
                    NotifyRuntimeComposeOverride::Compio
                } else {
                    NotifyRuntimeComposeOverride::Current
                },
                ..ItestComposeOverrides::default()
            },
        );
        let _status = command
            .arg("down")
            .arg("-v")
            .arg("--remove-orphans")
            .envs(compose_env.iter().map(|(key, value)| (key, value)))
            .current_dir(&self.deploy_root)
            .status();
    }
}

#[cfg(all(test, feature = "realnet"))]
fn dump_compose_logs(
    deploy_root: &Path,
    project_name: &str,
    env: &[(String, String)],
    federation_compio: bool,
    gateway_compio: bool,
    notify_compio: bool,
) {
    let Ok(log_dir) = std::env::var("RAMFLUX_ITEST_LOG_DIR") else {
        return;
    };
    let log_dir = PathBuf::from(log_dir);
    if std::fs::create_dir_all(&log_dir).is_err() {
        return;
    }
    let Ok(log_file) = std::fs::File::create(log_dir.join(format!("{project_name}.log"))) else {
        return;
    };
    let Ok(log_file_for_stderr) = log_file.try_clone() else {
        return;
    };
    let mut command = std::process::Command::new("docker");
    command.arg("compose");
    let _env_file = add_compose_env_file_arg(&mut command, project_name, env).ok();
    command.arg("-p").arg(project_name);
    add_itest_compose_files(
        &mut command,
        ItestComposeOverrides {
            federation_compio,
            gateway_compio,
            notify_runtime: if notify_compio {
                NotifyRuntimeComposeOverride::Compio
            } else {
                NotifyRuntimeComposeOverride::Current
            },
            ..ItestComposeOverrides::default()
        },
    );
    let _status = command
        .arg("logs")
        .arg("--timestamps")
        .envs(env.iter().map(|(key, value)| (key, value)))
        .current_dir(deploy_root)
        .stdout(std::process::Stdio::from(log_file))
        .stderr(std::process::Stdio::from(log_file_for_stderr))
        .status();
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) struct ProductionComposeDownGuard {
    pub(crate) deploy_root: PathBuf,
    pub(crate) project_name: String,
    pub(crate) env: Vec<(String, String)>,
}

#[cfg(all(test, feature = "realnet"))]
impl ProductionComposeDownGuard {
    pub(crate) fn new(
        deploy_root: PathBuf,
        project_name: String,
        env: Vec<(String, String)>,
    ) -> Self {
        Self { deploy_root, project_name, env }
    }
}

#[cfg(all(test, feature = "realnet"))]
impl Drop for ProductionComposeDownGuard {
    fn drop(&mut self) {
        let compose_env = compose_env_with_required_defaults(&self.env);
        let mut command = std::process::Command::new("docker");
        command.arg("compose");
        let _env_file =
            add_compose_env_file_arg(&mut command, &self.project_name, &compose_env).ok();
        let _status = command
            .arg("-p")
            .arg(&self.project_name)
            .arg("-f")
            .arg("docker-compose.yml")
            .arg("down")
            .arg("-v")
            .arg("--remove-orphans")
            .envs(compose_env.iter().map(|(key, value)| (key, value)))
            .current_dir(&self.deploy_root)
            .status();
    }
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) struct S10PrivateNode {
    pub(crate) gateway_quic_addr: std::net::SocketAddr,
    pub(crate) ca_cert: PathBuf,
    pub(crate) _guard: ProductionComposeDownGuard,
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn run_docker_compose_project_with_options(
    deploy_root: &Path,
    project_name: &str,
    env: &[(String, String)],
    args: &[&str],
    federation_compio: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    run_docker_compose_project_with_overrides(
        deploy_root,
        project_name,
        env,
        args,
        ItestComposeOverrides { federation_compio, ..ItestComposeOverrides::default() },
    )
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn run_docker_compose_project_with_overrides(
    deploy_root: &Path,
    project_name: &str,
    env: &[(String, String)],
    args: &[&str],
    overrides: ItestComposeOverrides,
) -> Result<(), Box<dyn std::error::Error>> {
    ensure_itest_shared_network()?;
    let compose_env = compose_env_with_required_defaults(env);
    let mut command = std::process::Command::new("docker");
    command.arg("compose");
    let _env_file = add_compose_env_file_arg(&mut command, project_name, &compose_env)?;
    command.arg("-p").arg(project_name);
    add_itest_compose_files(&mut command, overrides);
    command
        .args(args)
        .envs(compose_env.iter().map(|(key, value)| (key, value)))
        .current_dir(deploy_root);
    let status = command.status()?;
    if !status.success() {
        return Err(
            format!("docker compose project {project_name} {args:?} failed with {status}").into()
        );
    }
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
fn add_itest_compose_files(command: &mut std::process::Command, overrides: ItestComposeOverrides) {
    let overrides = overrides.with_env_defaults();
    command.arg("-f").arg("docker-compose.itest.yml");
    if overrides.federation_compio {
        command.arg("-f").arg("docker-compose.itest.federation-compio.yml");
    }
    if overrides.gateway_compio {
        command.arg("-f").arg("docker-compose.itest.gateway-compio.yml");
    }
    if cross_gateway_compose_enabled() {
        command.arg("-f").arg("docker-compose.itest.cross-gateway.yml");
    }
    if overrides.notify_mesh {
        command.arg("-f").arg("docker-compose.itest.notify-mesh.yml");
    }
    match overrides.notify_runtime {
        NotifyRuntimeComposeOverride::Current => {}
        NotifyRuntimeComposeOverride::TokioConcurrent => {
            command.arg("-f").arg("docker-compose.itest.notify-tokio-concurrent.yml");
        }
        NotifyRuntimeComposeOverride::Compio => {
            command.arg("-f").arg("docker-compose.itest.notify-compio.yml");
        }
    }
}

#[cfg(all(test, feature = "realnet"))]
fn compose_env_with_required_defaults(env: &[(String, String)]) -> Vec<(String, String)> {
    let mut compose_env = env.to_vec();
    ensure_itest_node_service_signing_seed_env(&mut compose_env);
    if !compose_env.iter().any(|(key, _value)| key == "RAMFLUX_FEDERATION_NODE_SIGNING_SEED_B64URL")
    {
        compose_env.push((
            "RAMFLUX_FEDERATION_NODE_SIGNING_SEED_B64URL".to_owned(),
            itest_node_service_signing_seed_b64url(),
        ));
    }
    if !compose_env.iter().any(|(key, _value)| key == "RAMFLUX_NODE_ID") {
        compose_env.push(("RAMFLUX_NODE_ID".to_owned(), "localhost".to_owned()));
    }
    compose_env
}

#[cfg(all(test, feature = "realnet"))]
struct ComposeEnvFile {
    path: PathBuf,
}

#[cfg(all(test, feature = "realnet"))]
impl ComposeEnvFile {
    fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(all(test, feature = "realnet"))]
impl Drop for ComposeEnvFile {
    fn drop(&mut self) {
        let _removed = std::fs::remove_file(&self.path);
    }
}

#[cfg(all(test, feature = "realnet"))]
fn add_compose_env_file_arg(
    command: &mut std::process::Command,
    label: &str,
    env: &[(String, String)],
) -> Result<ComposeEnvFile, Box<dyn std::error::Error>> {
    let env_file = write_compose_env_file(label, env)?;
    command.arg("--env-file").arg(env_file.path());
    Ok(env_file)
}

#[cfg(all(test, feature = "realnet"))]
fn write_compose_env_file(
    label: &str,
    env: &[(String, String)],
) -> Result<ComposeEnvFile, Box<dyn std::error::Error>> {
    static ENV_FILE_COUNTER: std::sync::atomic::AtomicUsize =
        std::sync::atomic::AtomicUsize::new(0);

    let sequence = ENV_FILE_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let safe_label = sanitize_compose_env_label(label);
    let path = std::env::temp_dir()
        .join(format!("ramflux-itest-compose-{safe_label}-{}-{sequence}.env", std::process::id()));
    let mut file = std::fs::File::create(&path)?;
    for (key, value) in env {
        use std::io::Write;
        writeln!(file, "{key}={value}")?;
    }
    Ok(ComposeEnvFile { path })
}

#[cfg(all(test, feature = "realnet"))]
fn sanitize_compose_env_label(label: &str) -> String {
    let sanitized = label
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
        .collect::<String>()
        .trim_matches('-')
        .to_owned();
    if sanitized.is_empty() { "compose".to_owned() } else { sanitized }
}

#[cfg(all(test, feature = "realnet"))]
fn notify_compose_override(
    notify_compio: bool,
    notify_tokio_concurrent: bool,
) -> NotifyRuntimeComposeOverride {
    if notify_compio {
        NotifyRuntimeComposeOverride::Compio
    } else if notify_tokio_concurrent {
        NotifyRuntimeComposeOverride::TokioConcurrent
    } else {
        NotifyRuntimeComposeOverride::Current
    }
}

#[cfg(all(test, feature = "realnet"))]
fn cross_gateway_compose_enabled() -> bool {
    compose_bool_env("RAMFLUX_CROSS_GATEWAY")
}

#[cfg(all(test, feature = "realnet"))]
fn notify_mesh_compose_enabled() -> bool {
    compose_bool_env("RAMFLUX_NOTIFY_MESH")
}

#[cfg(all(test, feature = "realnet"))]
fn compose_bool_env(name: &str) -> bool {
    std::env::var(name).is_ok_and(|value| {
        matches!(value.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on")
    })
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn ensure_itest_shared_network() -> Result<(), Box<dyn std::error::Error>> {
    let network = std::env::var("RAMFLUX_ITEST_SHARED_NETWORK")
        .unwrap_or_else(|_| "ramflux-itest-mesh".to_owned());
    let inspect = std::process::Command::new("docker")
        .arg("network")
        .arg("inspect")
        .arg(&network)
        .status()?;
    if inspect.success() {
        return Ok(());
    }
    let create =
        std::process::Command::new("docker").arg("network").arg("create").arg(&network).status()?;
    if create.success() {
        Ok(())
    } else {
        Err(format!("docker network create {network} failed with {create}").into())
    }
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn run_production_compose_project(
    deploy_root: &Path,
    project_name: &str,
    env: &[(String, String)],
    args: &[&str],
) -> Result<(), Box<dyn std::error::Error>> {
    let compose_env = compose_env_with_required_defaults(env);
    let mut command = std::process::Command::new("docker");
    command.arg("compose");
    let _env_file = add_compose_env_file_arg(&mut command, project_name, &compose_env)?;
    command
        .arg("-p")
        .arg(project_name)
        .arg("-f")
        .arg("docker-compose.yml")
        .args(args)
        .envs(compose_env.iter().map(|(key, value)| (key, value)))
        .current_dir(deploy_root);
    let status = command.status()?;
    if !status.success() {
        return Err(format!(
            "docker compose production project {project_name} {args:?} failed with {status}"
        )
        .into());
    }
    Ok(())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn plaintext_router_mesh_probe() -> Result<bool, Box<dyn std::error::Error>> {
    use std::io::{Read, Write};

    let addr = std::env::var("RAMFLUX_ITEST_ROUTER_MESH_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:17443".to_owned());
    let mut stream = std::net::TcpStream::connect(addr)?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(std::time::Duration::from_secs(2)))?;
    stream.write_all(b"GET /healthz HTTP/1.1\r\nHost: ramflux-router\r\n\r\n")?;
    let mut response = [0_u8; 8];
    match stream.read(&mut response) {
        Ok(count) => Ok(response[..count].starts_with(b"HTTP/1.")),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::UnexpectedEof
                    | std::io::ErrorKind::TimedOut
                    | std::io::ErrorKind::WouldBlock
            ) =>
        {
            Ok(false)
        }
        Err(error) => Err(error.into()),
    }
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) const STUN_HEADER_LEN: usize = 20;

#[cfg(all(test, feature = "realnet"))]
pub(crate) const STUN_MAGIC_COOKIE: u32 = 0x2112_A442;

#[cfg(all(test, feature = "realnet"))]
pub(crate) const STUN_BINDING_REQUEST: u16 = 0x0001;

#[cfg(all(test, feature = "realnet"))]
pub(crate) const STUN_BINDING_SUCCESS: u16 = 0x0101;

#[cfg(all(test, feature = "realnet"))]
pub(crate) const TURN_ALLOCATE_REQUEST: u16 = 0x0003;

#[cfg(all(test, feature = "realnet"))]
pub(crate) const TURN_ALLOCATE_SUCCESS: u16 = 0x0103;

#[cfg(all(test, feature = "realnet"))]
pub(crate) const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

#[cfg(all(test, feature = "realnet"))]
pub(crate) const ATTR_LIFETIME: u16 = 0x000D;

#[cfg(all(test, feature = "realnet"))]
pub(crate) const ATTR_XOR_RELAYED_ADDRESS: u16 = 0x0016;

#[cfg(all(test, feature = "realnet"))]
pub(crate) struct StunTurnResponse {
    pub(crate) message_type: u16,
    pub(crate) xor_mapped_address: Option<std::net::SocketAddr>,
    pub(crate) xor_relayed_address: Option<std::net::SocketAddr>,
    pub(crate) lifetime_secs: Option<u32>,
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn stun_binding_request(
    server: std::net::SocketAddr,
) -> Result<StunTurnResponse, Box<dyn std::error::Error>> {
    let transaction_id = *b"mvp5bind0001";
    let request = stun_request(STUN_BINDING_REQUEST, &transaction_id, &[])?;
    let response = udp_roundtrip(server, &request)?;
    parse_stun_response(&response, &transaction_id)
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn turn_allocate_request(
    server: std::net::SocketAddr,
) -> Result<StunTurnResponse, Box<dyn std::error::Error>> {
    let transaction_id = *b"mvp5alloc001";
    let requested_transport = stun_attr(ATTR_REQUESTED_TRANSPORT, &[17, 0, 0, 0])?;
    let request = stun_request(TURN_ALLOCATE_REQUEST, &transaction_id, &[requested_transport])?;
    let response = udp_roundtrip(server, &request)?;
    parse_stun_response(&response, &transaction_id)
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn udp_roundtrip(
    server: std::net::SocketAddr,
    request: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
    socket.set_write_timeout(Some(std::time::Duration::from_secs(10)))?;
    socket.send_to(request, server)?;
    let mut response = [0_u8; 1500];
    let (len, _peer) = socket.recv_from(&mut response)?;
    Ok(response[..len].to_vec())
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn stun_request(
    message_type: u16,
    transaction_id: &[u8; 12],
    attrs: &[Vec<u8>],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let body_len: usize = attrs.iter().map(Vec::len).sum();
    let body_len = u16::try_from(body_len)?;
    let mut request = Vec::with_capacity(STUN_HEADER_LEN + usize::from(body_len));
    request.extend_from_slice(&message_type.to_be_bytes());
    request.extend_from_slice(&body_len.to_be_bytes());
    request.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    request.extend_from_slice(transaction_id);
    for attr in attrs {
        request.extend_from_slice(attr);
    }
    Ok(request)
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn stun_attr(
    attr_type: u16,
    value: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let len = u16::try_from(value.len())?;
    let mut attr = Vec::with_capacity(4 + padded_stun_attr_len(value.len()));
    attr.extend_from_slice(&attr_type.to_be_bytes());
    attr.extend_from_slice(&len.to_be_bytes());
    attr.extend_from_slice(value);
    while attr.len() % 4 != 0 {
        attr.push(0);
    }
    Ok(attr)
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn parse_stun_response(
    response: &[u8],
    transaction_id: &[u8; 12],
) -> Result<StunTurnResponse, Box<dyn std::error::Error>> {
    if response.len() < STUN_HEADER_LEN {
        return Err("short STUN response".into());
    }
    let message_type = u16::from_be_bytes([response[0], response[1]]);
    let message_len = usize::from(u16::from_be_bytes([response[2], response[3]]));
    let magic_cookie = u32::from_be_bytes([response[4], response[5], response[6], response[7]]);
    if magic_cookie != STUN_MAGIC_COOKIE {
        return Err("bad STUN response magic cookie".into());
    }
    if &response[8..20] != transaction_id {
        return Err("STUN transaction id mismatch".into());
    }
    if response.len() < STUN_HEADER_LEN + message_len {
        return Err("truncated STUN response body".into());
    }
    let mut parsed = StunTurnResponse {
        message_type,
        xor_mapped_address: None,
        xor_relayed_address: None,
        lifetime_secs: None,
    };
    let mut offset = STUN_HEADER_LEN;
    let end = STUN_HEADER_LEN + message_len;
    while offset + 4 <= end {
        let attr_type = u16::from_be_bytes([response[offset], response[offset + 1]]);
        let attr_len =
            usize::from(u16::from_be_bytes([response[offset + 2], response[offset + 3]]));
        offset += 4;
        if offset + attr_len > end {
            return Err("truncated STUN attribute".into());
        }
        let value = &response[offset..offset + attr_len];
        match attr_type {
            ATTR_XOR_MAPPED_ADDRESS => parsed.xor_mapped_address = Some(parse_xor_addr(value)?),
            ATTR_XOR_RELAYED_ADDRESS => parsed.xor_relayed_address = Some(parse_xor_addr(value)?),
            ATTR_LIFETIME if value.len() == 4 => {
                parsed.lifetime_secs =
                    Some(u32::from_be_bytes([value[0], value[1], value[2], value[3]]));
            }
            _ => {}
        }
        offset += padded_stun_attr_len(attr_len);
    }
    Ok(parsed)
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn parse_xor_addr(
    value: &[u8],
) -> Result<std::net::SocketAddr, Box<dyn std::error::Error>> {
    if value.len() != 8 || value[1] != 0x01 {
        return Err("unsupported XOR address attribute".into());
    }
    let port = u16::from_be_bytes([value[2], value[3]]) ^ u16::try_from(STUN_MAGIC_COOKIE >> 16)?;
    let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
    let ip = std::net::Ipv4Addr::new(
        value[4] ^ cookie[0],
        value[5] ^ cookie[1],
        value[6] ^ cookie[2],
        value[7] ^ cookie[3],
    );
    Ok(std::net::SocketAddr::V4(std::net::SocketAddrV4::new(ip, port)))
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) const fn padded_stun_attr_len(len: usize) -> usize {
    (len + 3) & !3
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) struct RealnetCompose {
    pub(crate) gateway_url: String,
    pub(crate) notify_url: String,
    pub(crate) relay_url: String,
    pub(crate) retention_url: String,
    pub(crate) _guard: ComposeDownGuard,
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn start_s8_realnet_compose_project(
    project_name: &str,
    ports: S8ComposePorts,
) -> Result<S8RealnetNode, Box<dyn std::error::Error>> {
    start_s8_realnet_compose_project_with_env(project_name, ports, &[])
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn start_s8_realnet_compose_project_with_env(
    project_name: &str,
    ports: S8ComposePorts,
    extra_env: &[(String, String)],
) -> Result<S8RealnetNode, Box<dyn std::error::Error>> {
    start_s8_realnet_compose_project_with_env_and_federation_compio(
        project_name,
        ports,
        extra_env,
        false,
    )
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn start_s8_realnet_compose_project_with_env_and_federation_compio(
    project_name: &str,
    ports: S8ComposePorts,
    extra_env: &[(String, String)],
    federation_compio: bool,
) -> Result<S8RealnetNode, Box<dyn std::error::Error>> {
    let code_root = code_root();
    let deploy_root = code_root.join("ramflux/deploy");
    let node_id = if project_name.contains("node-b") { "node_b.realnet" } else { "node_a.realnet" }
        .to_owned();
    realnet_step(
        "start compose project",
        format!("project={project_name} node={node_id} deploy={}", deploy_root.display()),
    );
    let project_deploy_dir = deploy_root.join(".itest-node-certs").join(project_name);
    if project_deploy_dir.exists() {
        realnet_step(
            "remove stale node cert dir",
            format!("project={project_name} path={}", project_deploy_dir.display()),
        );
        std::fs::remove_dir_all(&project_deploy_dir)?;
    }
    std::fs::create_dir_all(&project_deploy_dir)?;
    let cert_env = vec![
        ("RAMFLUX_DEPLOY_DIR".to_owned(), project_deploy_dir.to_string_lossy().into_owned()),
        ("RAMFLUX_NODE_ID".to_owned(), node_id.clone()),
    ];
    realnet_step(
        "bootstrap per-node CA",
        format!("project={project_name} node={node_id} dir={}", project_deploy_dir.display()),
    );
    run_deploy_script_with_env(&code_root, "ramflux/deploy/scripts/bootstrap-ca.sh", &cert_env)?;
    realnet_step(
        "issue per-node service certs",
        format!("project={project_name} node={node_id} dir={}", project_deploy_dir.display()),
    );
    run_deploy_script_with_env(&code_root, "ramflux/deploy/scripts/issue-certs.sh", &cert_env)?;
    let node_signing_seed = realnet_node_signing_seed(&node_id);
    let node_public_key = ramflux_crypto::public_key_base64url_from_seed(node_signing_seed);
    let federation_dns_alias = federation_dns_alias(project_name);
    let mut env = s8_compose_env(ports);
    env.push(("RAMFLUX_NODE_ID".to_owned(), node_id.clone()));
    env.push((
        "RAMFLUX_CERTS_DIR".to_owned(),
        project_deploy_dir.join("certs").to_string_lossy().into_owned(),
    ));
    env.push(("RAMFLUX_ITEST_FEDERATION_DNS_ALIAS".to_owned(), federation_dns_alias.clone()));
    env.push((
        "RAMFLUX_FEDERATION_PUBLIC_ENDPOINT".to_owned(),
        format!("{federation_dns_alias}:7443"),
    ));
    env.push(("RAMFLUX_FEDERATION_NODE_ID".to_owned(), node_id.clone()));
    env.push((
        "RAMFLUX_FEDERATION_NODE_SIGNING_SEED_B64URL".to_owned(),
        ramflux_protocol::encode_base64url(node_signing_seed),
    ));
    ensure_itest_node_service_signing_seed_env(&mut env);
    env.extend(extra_env.iter().cloned());
    realnet_step(
        "docker compose up",
        format!(
            "project={project_name} node={node_id} federation_alias={federation_dns_alias} gateway_port={} federation_http_port={} federation_mesh_port={}",
            ports.gateway_http, ports.federation_http, ports.federation_mesh
        ),
    );
    run_docker_compose_project_with_options(
        &deploy_root,
        project_name,
        &env,
        &["up", "--build", "-d"],
        federation_compio,
    )?;
    let guard =
        ComposeProjectDownGuard::new(deploy_root, project_name.to_owned(), env, federation_compio);
    let ca_snapshot = std::env::temp_dir().join(format!(
        "{project_name}_ca_{}_{}.pem",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos()
    ));
    std::fs::copy(project_deploy_dir.join("certs/ca.pem"), &ca_snapshot)?;
    let gateway_url = format!("http://127.0.0.1:{}", ports.gateway_http);
    let federation_url = format!("http://127.0.0.1:{}", ports.federation_http);
    realnet_step("wait for node gateway", format!("node={node_id} url={gateway_url}"));
    wait_for_gateway(&gateway_url)?;
    realnet_step("wait for node federation", format!("node={node_id} url={federation_url}"));
    wait_for_federation(&federation_url)?;
    realnet_step(
        "compose project ready",
        format!(
            "project={project_name} node={node_id} gateway_url={gateway_url} federation_url={federation_url} well_known_base=http://{federation_dns_alias}:18082 mesh_endpoint={federation_dns_alias}:7443 ca={}",
            ca_snapshot.display()
        ),
    );
    Ok(S8RealnetNode {
        node_id,
        federation_node_public_key: node_public_key,
        gateway_url,
        federation_url,
        federation_well_known_base: format!("http://{federation_dns_alias}:18082"),
        gateway_quic_addr: std::net::SocketAddr::from(([127, 0, 0, 1], ports.gateway_quic)),
        ca_cert: ca_snapshot,
        federation_mesh_endpoint: format!("{federation_dns_alias}:7443"),
        guard,
    })
}

#[cfg(all(test, feature = "realnet"))]
pub(crate) fn federation_dns_alias(project_name: &str) -> String {
    format!(
        "{}-ramflux-federation",
        project_name
            .chars()
            .map(|ch| if ch.is_ascii_alphanumeric() { ch.to_ascii_lowercase() } else { '-' })
            .collect::<String>()
            .trim_matches('-')
    )
}
