use crate::CliCommand;
use outbound_witness_core::session::{
    ApprovalRequest, ApprovalResponse, CredentialRouteSummary, NetworkIntent, RuntimeCapability,
    SessionAuditRecord, SessionHandle, SessionRecord, SessionSpec, SessionState,
};
use outbound_witness_core::workspace::{
    apply_diff, collect_diff, snapshot_workspace, WorkspaceDiff,
};
use outbound_witness_core::{
    evaluate_event, Destination, EnforcementMode, NetworkEvent, PolicyDecision, ProcessIdentity,
    RuleConfig, WitnessEvent,
};
use outbound_witness_proxy::{
    broker::CredentialRoute, evaluate_request_detailed, write_json, ApprovalGrant, ApprovalScope,
    DeniedRequest, PreAuthorization, ProxyConfig, ProxyDecision, ProxyMode, ProxyRequest,
};
use std::process::{Command, Stdio};
use std::{
    fs, io,
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const POLICY_VERSION: &str = "session-v0.2";
const LOCK_TIMEOUT: Duration = Duration::from_secs(5);
const LOCK_STALE_AFTER: Duration = Duration::from_secs(300);
/// A token command that never returns must not block session startup or
/// shutdown forever. Long cloud CLI calls usually finish in seconds.
const TOKEN_COMMAND_TIMEOUT: Duration = Duration::from_secs(60);

/// Serializes CLI mutations of the proxy control plane (approvals, denials,
/// session records). Approve/deny are short-lived one-shot processes, so a
/// lock file with create_new + stale detection is enough; the atomic renames
/// in `write_json` guarantee readers never see torn JSON. The token keeps a
/// process whose lock was taken over from deleting the new holder's lock.
struct StateLock {
    path: PathBuf,
    token: String,
}

impl StateLock {
    fn acquire(state_dir: &Path) -> Result<Self, String> {
        fs::create_dir_all(state_dir).map_err(|error| error.to_string())?;
        let path = state_dir.join("control.lock");
        let started = Instant::now();
        loop {
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(mut file) => {
                    let token = format!(
                        "{}-{}",
                        std::process::id(),
                        SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_nanos()
                    );
                    let _ = io::Write::write_all(&mut file, token.as_bytes());
                    return Ok(Self { path, token });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    if Self::is_stale(&path) {
                        let _ = fs::remove_file(&path);
                        continue;
                    }
                    if started.elapsed() >= LOCK_TIMEOUT {
                        return Err(format!("无法获取控制锁 {}: 超时", path.display()));
                    }
                    thread::sleep(Duration::from_millis(50));
                }
                Err(error) => {
                    return Err(format!("无法获取控制锁 {}: {error}", path.display()));
                }
            }
        }
    }

    fn is_stale(path: &Path) -> bool {
        fs::metadata(path)
            .and_then(|metadata| metadata.modified())
            .map(|modified| modified.elapsed().unwrap_or(Duration::ZERO) >= LOCK_STALE_AFTER)
            .unwrap_or(false)
    }
}

impl Drop for StateLock {
    fn drop(&mut self) {
        // Only remove the lock if it is still ours. If the stale-lock timeout
        // let another process take over, deleting its lock would let a third
        // writer in concurrently.
        if fs::read_to_string(&self.path).ok().as_deref() == Some(self.token.as_str()) {
            let _ = fs::remove_file(&self.path);
        }
    }
}

pub fn build_docker_agent_args(
    spec: &SessionSpec,
    snapshot_dir: &Path,
    internal_network: &str,
    proxy_host: &str,
) -> Vec<String> {
    let mut args = vec![
        "run".into(),
        "--rm".into(),
        "--name".into(),
        format!("ow-{}-agent", spec.id),
        "--network".into(),
        internal_network.into(),
        "--workdir".into(),
        "/workspace".into(),
        "--mount".into(),
        format!(
            "type=bind,source={},target=/workspace",
            snapshot_dir.display()
        ),
        "--cap-drop".into(),
        "ALL".into(),
        "--security-opt".into(),
        "no-new-privileges:true".into(),
        "-e".into(),
        format!("HTTP_PROXY=http://{proxy_host}:3128"),
        "-e".into(),
        format!("HTTPS_PROXY=http://{proxy_host}:3128"),
        "-e".into(),
        format!("ALL_PROXY=http://{proxy_host}:3128"),
        "-e".into(),
        "NO_PROXY=localhost,127.0.0.1".into(),
    ];
    // External DNS resolution is not needed: the agent sends hostnames to the
    // proxy via CONNECT. Pointing the upstream resolver at loopback closes the
    // easiest DNS-tunnelling path out of the internal network. Container-name
    // resolution (`proxy`) still comes from Docker's embedded resolver at
    // 127.0.0.11. Set OW_AGENT_DNS=<server> to override, or OW_AGENT_DNS=none
    // to leave Docker's default resolver in place.
    match std::env::var("OW_AGENT_DNS") {
        Ok(value) if value.is_empty() || value == "none" => {}
        Ok(value) => {
            args.push("--dns".into());
            args.push(value);
        }
        Err(_) => {
            args.push("--dns".into());
            args.push("127.0.0.1".into());
        }
    }
    // Advertise the broker base URL only. The credential itself stays in the
    // proxy container, so the agent can call a route but never read the key.
    for route in &spec.credential_routes {
        args.push("-e".into());
        args.push(format!(
            "OW_BROKER_{}_BASE_URL=http://{proxy_host}:8080/{}",
            route.route.to_ascii_uppercase().replace('-', "_"),
            route.route
        ));
    }
    // Run the content-addressed digest captured at session start, not the tag.
    // Otherwise a tag moved between `image inspect` and `docker run` would let
    // the agent run different content than the approvals were bound to.
    let image = spec.image_id.as_deref().unwrap_or(&spec.image);
    args.push(image.to_string());
    args.extend(spec.command.iter().cloned());
    args
}

pub fn doctor_runtime(json: bool) -> Result<String, String> {
    let capability = probe_docker();
    if json {
        return serde_json::to_string_pretty(&capability).map_err(|error| error.to_string());
    }
    Ok(format!(
        "Docker runtime\n可执行文件: {}\nDaemon: {}\n版本: {}\n强制能力: {}\n说明: {}",
        if capability.available {
            "可用"
        } else {
            "未找到"
        },
        if capability.daemon_ready {
            "已就绪"
        } else {
            "未就绪"
        },
        capability.version.as_deref().unwrap_or("未知"),
        capability.enforcement,
        capability.message
    ))
}

pub fn run_session_command(command: &CliCommand) -> Result<String, String> {
    let subcommand = command
        .session_subcommand
        .as_deref()
        .ok_or_else(|| "session 子命令缺失".to_string())?;
    match subcommand {
        "start" => {
            let capability = probe_docker();
            if !capability.daemon_ready {
                return Err(format!(
                    "Docker-compatible runtime 未就绪：{}。先运行 `ow doctor runtime`，启动 Docker Desktop 或 Colima 后重试。",
                    capability.message
                ));
            }
            let spec = spec_from_command(command)?;
            run_docker_session(spec)
        }
        "status" => render_session_status(command),
        "requests" => render_pending_requests(command),
        "diff" => render_diff(command),
        "apply" => {
            let state = command_state_dir(command)?;
            let session_id = command.session_id.as_deref().unwrap();
            apply_session_diff(&state, session_id, &command.paths)?;
            Ok(format!("已将指定 diff 写回宿主工作区: {session_id}"))
        }
        "export" => {
            let state = command_state_dir(command)?;
            let session_id = command.session_id.as_deref().unwrap();
            let output = command
                .output
                .as_deref()
                .ok_or_else(|| "session export 需要 --output".to_string())?;
            export_session_audit(&state, session_id, Path::new(output))?;
            let public_key = crate::signing::public_key_hex(&state)?;
            Ok(format!(
                "审计已导出: {output}\n已用本机签名密钥签名。公钥（交给验证方，用于确认来源）:\n{public_key}"
            ))
        }
        "approve" => approve_request(command),
        "deny" => deny_request(command),
        "preauth" => match command.policy_action.as_deref() {
            Some("add") => preauth_add(command),
            Some("list") => preauth_list(command),
            Some("remove") => preauth_remove(command),
            other => Err(format!("未知 preauth 动作: {}", other.unwrap_or("(缺失)"))),
        },
        other => Err(format!("未知 session 子命令: {other}")),
    }
}

fn run_docker_session(mut spec: SessionSpec) -> Result<String, String> {
    let image = spec.image.clone();
    ensure_image(&image)?;
    spec.image_id = Some(image_digest(&image)?);
    ensure_proxy_image()?;
    let record = prepare_session(spec)?;
    let state_dir = record.spec.state_dir.clone();
    let session_id = record.spec.id.clone();
    let prepared = record
        .prepared
        .clone()
        .ok_or_else(|| "Session 缺少 prepared state".to_string())?;
    let internal_network = format!("ow-{session_id}-internal");
    let egress_network = format!("ow-{session_id}-egress");
    let proxy_name = format!("ow-{session_id}-proxy");
    create_network(&internal_network, true)?;
    create_network(&egress_network, false)?;
    let result = (|| {
        let proxy_args = build_proxy_args(
            &proxy_name,
            &internal_network,
            &prepared.proxy_state_dir,
            &record.spec,
        );
        run_docker(&proxy_args, None)?;
        run_docker(
            &[
                "network".into(),
                "connect".into(),
                egress_network.clone(),
                proxy_name.clone(),
            ],
            None,
        )?;
        // `docker run -d` succeeds even when the container exits immediately.
        // Starting the agent without a live proxy would silently disable the
        // only egress control the session has.
        if !wait_for_container(&proxy_name, Duration::from_secs(5)) {
            let _ = update_session_record(&state_dir, &session_id, |record| {
                record.state = SessionState::Failed;
                record.error = Some("代理容器未能保持运行".into());
                Ok(())
            });
            return Err("代理容器未能保持运行，Session 不会在无出站控制的情况下启动".to_string());
        }
        let handle = SessionHandle {
            session_id: session_id.clone(),
            runtime_id: format!("ow-{session_id}-agent"),
            proxy_id: proxy_name.clone(),
        };
        update_session_record(&state_dir, &session_id, |record| {
            record.handle = Some(handle);
            record.state = SessionState::Running;
            Ok(())
        })?;
        let agent_args = build_docker_agent_args(
            &record.spec,
            &prepared.snapshot_dir,
            &internal_network,
            "proxy",
        );
        // Short-lived credentials are renewed while the agent runs, so a long
        // session does not outlive its token. A corrupt broker file aborts the
        // session instead of silently running without credential renewal.
        let routes =
            match read_json_vec::<CredentialRoute>(&prepared.proxy_state_dir.join("broker.json")) {
                Ok(routes) => routes,
                Err(error) => {
                    let _ = update_session_record(&state_dir, &session_id, |record| {
                        record.state = SessionState::Failed;
                        record.error = Some(error.clone());
                        record.handle = None;
                        Ok(())
                    });
                    return Err(error);
                }
            };
        let refresh = spawn_credential_refresh(routes, prepared.proxy_state_dir.clone());
        let output = match run_docker_output(&agent_args) {
            Ok(output) => output,
            Err(error) => {
                refresh.stop();
                let _ = update_session_record(&state_dir, &session_id, |record| {
                    record.state = SessionState::Failed;
                    record.error = Some(error.clone());
                    record.handle = None;
                    Ok(())
                });
                return Err(error);
            }
        };
        refresh.stop();
        let proxy_alive = container_is_running(&proxy_name);
        update_session_record(&state_dir, &session_id, |record| {
            record.state = if output.status_success && proxy_alive {
                SessionState::Completed
            } else {
                SessionState::Failed
            };
            record.error = if !proxy_alive {
                Some("代理容器在 Session 结束前已停止，出站证据不完整".into())
            } else if !output.status_success {
                Some(format!("agent 退出码 {}", output.exit_code))
            } else {
                None
            };
            record.handle = None;
            Ok(())
        })?;
        // Collect the diff only after the terminal state is persisted, so a
        // diff error cannot leave the session stuck in Running.
        if let Err(error) = collect_session_diff(&state_dir, &session_id) {
            let _ = update_session_record(&state_dir, &session_id, |record| {
                record.error = Some(format!("diff 采集失败: {error}"));
                if record.state == SessionState::Completed {
                    record.state = SessionState::Failed;
                }
                Ok(())
            });
        }
        record_proxy_witnesses(&state_dir, &session_id)?;
        let final_record = load_session_record(&state_dir, &session_id)?;
        Ok(format!(
            "Session {}\n状态: {:?}\n容器退出码: {}\n{}",
            session_id,
            final_record.state,
            output.exit_code,
            output.stdout.trim()
        ))
    })();
    let _ = run_docker(&["rm".into(), "-f".into(), proxy_name], None);
    let _ = run_docker(&["network".into(), "rm".into(), internal_network], None);
    let _ = run_docker(&["network".into(), "rm".into(), egress_network], None);
    result
}

pub fn build_proxy_args(
    proxy_name: &str,
    internal_network: &str,
    state_dir: &Path,
    spec: &SessionSpec,
) -> Vec<String> {
    let mut args = vec![
        "run".into(),
        "-d".into(),
        "--rm".into(),
        "--name".into(),
        proxy_name.into(),
        "--network".into(),
        internal_network.into(),
        "--network-alias".into(),
        "proxy".into(),
        "--mount".into(),
        format!("type=bind,source={},target=/state", state_dir.display()),
        // The proxy holds usable credentials, so it gets the same treatment as
        // an untrusted service: no capabilities, no privilege escalation, a
        // read-only root filesystem, and a writable state mount only.
        "--cap-drop".into(),
        "ALL".into(),
        "--security-opt".into(),
        "no-new-privileges:true".into(),
        "--read-only".into(),
        "--tmpfs".into(),
        "/tmp:rw,noexec,nosuid,size=8m".into(),
        "--pids-limit".into(),
        "256".into(),
        "--memory".into(),
        "512m".into(),
        "-e".into(),
        "OW_PROXY_STATE_DIR=/state".into(),
        "-e".into(),
        format!(
            "OW_PROXY_MODE={}",
            if spec.mode == outbound_witness_core::EnforcementMode::Strict {
                "strict"
            } else {
                "observe"
            }
        ),
        "-e".into(),
        format!("OW_PROXY_TIMEOUT_MS={}", spec.approval_timeout_secs * 1000),
    ];
    if let Some(image_id) = &spec.image_id {
        args.push("-e".into());
        args.push(format!("OW_PROXY_IMAGE_ID={image_id}"));
    }
    // Run as the owner of the state directory so the proxy can write request
    // evidence without container root. On non-Unix hosts Docker Desktop
    // handles ownership mapping itself.
    if let Some(owner) = state_dir_owner(state_dir) {
        args.push("--user".into());
        args.push(owner);
    }
    if std::env::var_os("OW_PROXY_ALLOW_PRIVATE").is_some() {
        args.push("-e".into());
        args.push("OW_PROXY_ALLOW_PRIVATE".into());
    }
    args.push("-e".into());
    args.push("OW_PROXY_BROKER_LISTEN=0.0.0.0:8080".into());
    // Credentials are passed to the proxy container only, by variable name, so
    // the host environment supplies the value and the agent never sees it.
    for route in &spec.credential_routes {
        if let Some(name) = &route.secret_env {
            args.push("-e".into());
            args.push(name.clone());
        }
    }
    args.push("outbound-witness/proxy:local".into());
    args
}

#[cfg(unix)]
fn state_dir_owner(state_dir: &Path) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    fs::metadata(state_dir)
        .ok()
        .map(|metadata| format!("{}:{}", metadata.uid(), metadata.gid()))
}

#[cfg(not(unix))]
fn state_dir_owner(_state_dir: &Path) -> Option<String> {
    None
}

#[derive(Debug)]
struct DockerOutput {
    status_success: bool,
    exit_code: i32,
    stdout: String,
}

fn run_docker(args: &[String], container_name: Option<&str>) -> Result<DockerOutput, String> {
    let mut command = Command::new("docker");
    command.args(args);
    let result = run_docker_output_from(command)?;
    if !result.status_success {
        let label = container_name.unwrap_or("docker");
        return Err(format!("{label} command failed: {}", result.stdout.trim()));
    }
    Ok(result)
}

fn run_docker_output(args: &[String]) -> Result<DockerOutput, String> {
    let mut command = Command::new("docker");
    command.args(args);
    run_docker_output_from(command)
}

fn container_is_running(name: &str) -> bool {
    Command::new("docker")
        .args(["inspect", "--format", "{{.State.Running}}", name])
        .output()
        .map(|output| {
            output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == "true"
        })
        .unwrap_or(false)
}

fn wait_for_container(name: &str, timeout: Duration) -> bool {
    let started = Instant::now();
    loop {
        if container_is_running(name) {
            return true;
        }
        if started.elapsed() >= timeout {
            return false;
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn run_docker_output_from(mut command: Command) -> Result<DockerOutput, String> {
    let output = command.output().map_err(|error| error.to_string())?;
    Ok(DockerOutput {
        status_success: output.status.success(),
        exit_code: output.status.code().unwrap_or(1),
        stdout: format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    })
}

fn create_network(name: &str, internal: bool) -> Result<(), String> {
    let mut args = vec!["network".into(), "create".into()];
    if internal {
        args.push("--internal".into());
    }
    args.push(name.into());
    run_docker(&args, None).map(|_| ())
}

fn ensure_image(image: &str) -> Result<(), String> {
    let output = Command::new("docker")
        .args(["image", "inspect", image])
        .output()
        .map_err(|error| error.to_string())?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "目标镜像不存在: {image}；请显式构建或准备该镜像，不会自动拉取外部镜像。"
        ))
    }
}

fn ensure_proxy_image() -> Result<(), String> {
    let image = "outbound-witness/proxy:local";
    let inspect = Command::new("docker")
        .args(["image", "inspect", image])
        .output();
    if inspect
        .map(|output| output.status.success())
        .unwrap_or(false)
    {
        return Ok(());
    }
    Err("本地 egress proxy 镜像不存在。为避免自动下载或拉取镜像，请先由用户显式运行：`docker build -t outbound-witness/proxy:local -f proxy-image/Dockerfile .`".into())
}

/// Resolves the content-addressed digest (`docker image inspect .Id`) of a
/// locally present image. Approval grants bind to this digest so they cannot
/// be replayed against a different agent binary.
fn image_digest(image: &str) -> Result<String, String> {
    let output = Command::new("docker")
        .args(["image", "inspect", image, "--format", "{{.Id}}"])
        .output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err(format!(
            "无法解析镜像 {image} 的内容摘要: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let digest = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if digest.is_empty() {
        return Err(format!("镜像 {image} 没有可用的内容摘要"));
    }
    Ok(digest)
}

fn approve_request(command: &CliCommand) -> Result<String, String> {
    let state_dir = command_state_dir(command)?;
    let request_id = command.request_id.as_deref().unwrap();
    let _lock = StateLock::acquire(&state_dir)?;
    let (session_dir, request) = find_proxy_request(&state_dir, request_id)?;
    let scope = match command.scope.as_deref().unwrap_or("once") {
        "once" => ApprovalScope::Once,
        "host" => ApprovalScope::Host,
        "session" => ApprovalScope::Session,
        other => return Err(format!("未知授权范围: {other}，可选 once/host/session")),
    };
    // Bind the grant to the image digest attested at session start, so an
    // approval issued for one agent build cannot be replayed against another.
    let session_id = proxy_session_id(&session_dir)?;
    let record = load_session_record(&state_dir, &session_id)?;
    let expires_at_ms = command
        .ttl
        .map(|ttl| now_millis().saturating_add(ttl.saturating_mul(1000)));
    let mut approvals = read_json_vec::<ApprovalGrant>(&session_dir.join("approvals.json"))?;
    approvals.push(ApprovalGrant {
        request_id: if scope == ApprovalScope::Once {
            Some(request.request_id.clone())
        } else {
            None
        },
        host: request.host.clone(),
        port: Some(request.port),
        scope: scope.clone(),
        expires_at_ms,
        image_id: record.spec.image_id.clone(),
    });
    write_json(&session_dir.join("approvals.json"), &approvals)?;
    append_approval_audit(
        &state_dir,
        &session_dir,
        &request,
        match scope {
            ApprovalScope::Once => ApprovalResponse::AllowOnce,
            ApprovalScope::Host => ApprovalResponse::AllowHost,
            ApprovalScope::Session => ApprovalResponse::AllowSession,
        },
    )?;
    Ok(format!(
        "已批准 {} -> {}:{}（授权绑定端口）",
        request.request_id, request.host, request.port
    ))
}

fn deny_request(command: &CliCommand) -> Result<String, String> {
    let state_dir = command_state_dir(command)?;
    let request_id = command.request_id.as_deref().unwrap();
    let _lock = StateLock::acquire(&state_dir)?;
    let (session_dir, request) = find_proxy_request(&state_dir, request_id)?;
    let mut denials = read_json_vec::<DeniedRequest>(&session_dir.join("denials.json"))?;
    denials.push(DeniedRequest {
        request_id: Some(request.request_id.clone()),
        host: request.host.clone(),
        port: Some(request.port),
    });
    write_json(&session_dir.join("denials.json"), &denials)?;
    append_approval_audit(&state_dir, &session_dir, &request, ApprovalResponse::Deny)?;
    Ok(format!(
        "已拒绝 {} -> {}:{}",
        request.request_id, request.host, request.port
    ))
}

/// Turns a recorded decision source into an audit sentence, so an exported
/// record distinguishes an automatic policy allow from a human approval.
fn decision_source_note(source: &str) -> String {
    match source {
        "pre_authorized" => "代理决定来自预授权策略（自动放行，未经人工逐条批准）".to_string(),
        "manual_approval" => "代理决定来自人工批准".to_string(),
        "observe" => "代理处于观察模式，未做阻断".to_string(),
        "denied" => "代理决定来自显式拒绝".to_string(),
        "timeout" => "代理因授权超时而拒绝".to_string(),
        "credential_broker" => {
            "代理决定来自凭据路由（凭据由代理注入，未进入 agent 容器）".to_string()
        }
        "blocked_target" => "代理拒绝：目标解析到非公网地址（SSRF 防护）".to_string(),
        "connect_failed" => "代理已放行，但上游 TCP 连接失败".to_string(),
        other => format!("代理决定来自 CONNECT 授权（{other}）"),
    }
}

/// Maps the decision the proxy recorded at runtime to its effect. Runtime
/// decisions are authoritative: re-evaluating a TTL-bound grant at export time
/// can turn an allowed request into a block just because its grant expired.
fn decision_from_source(source: &str) -> Option<ProxyDecision> {
    match source {
        "observe" | "pre_authorized" | "manual_approval" | "credential_broker" => {
            Some(ProxyDecision::Allow)
        }
        "denied" | "timeout" | "blocked_target" | "connect_failed" => Some(ProxyDecision::Block),
        _ => None,
    }
}

fn preauth_file(state_dir: &Path, session_id: &str) -> PathBuf {
    state_dir
        .join(session_id)
        .join("proxy-state")
        .join("preauth.json")
}

fn preauth_add(command: &CliCommand) -> Result<String, String> {
    let state_dir = command_state_dir(command)?;
    let session_id = command.session_id.as_deref().unwrap();
    let host = command.host.as_deref().unwrap();
    let port = command.port.unwrap();
    let _lock = StateLock::acquire(&state_dir)?;
    let mut record = load_session_record(&state_dir, session_id)?;
    let path = preauth_file(&state_dir, session_id);
    let mut rules = read_json_vec::<PreAuthorization>(&path)?;
    let expires_at_ms = command
        .ttl
        .map(|ttl| now_millis().saturating_add(ttl.saturating_mul(1000)));
    rules.retain(|rule| !(rule.host == host && rule.port == port));
    rules.push(PreAuthorization {
        host: host.to_string(),
        port,
        expires_at_ms,
        note: command.note.clone(),
    });
    write_json(&path, &rules)?;
    // Keep the effective policy inside the exported session record.
    let entry = format!("{host}:{port}");
    if !record.spec.pre_authorized_hosts.contains(&entry) {
        record.spec.pre_authorized_hosts.push(entry);
    }
    save_session_record(&record)?;
    let ttl_note = match command.ttl {
        Some(ttl) => format!("，{ttl} 秒后失效"),
        None => "，直到 Session 结束".to_string(),
    };
    Ok(format!("已预授权 {host}:{port}{ttl_note}"))
}

fn preauth_list(command: &CliCommand) -> Result<String, String> {
    let state_dir = command_state_dir(command)?;
    let session_id = command.session_id.as_deref().unwrap();
    let rules = read_json_vec::<PreAuthorization>(&preauth_file(&state_dir, session_id))?;
    if command.json {
        return serde_json::to_string_pretty(&rules).map_err(|error| error.to_string());
    }
    if rules.is_empty() {
        return Ok("尚无预授权规则。".into());
    }
    Ok(rules
        .iter()
        .map(|rule| {
            let expiry = match rule.expires_at_ms {
                Some(value) => format!("expires_at_ms={value}"),
                None => "会话期间有效".to_string(),
            };
            format!(
                "{}:{}\t{}\t{}",
                rule.host,
                rule.port,
                expiry,
                rule.note.as_deref().unwrap_or("")
            )
        })
        .collect::<Vec<_>>()
        .join("\n"))
}

fn preauth_remove(command: &CliCommand) -> Result<String, String> {
    let state_dir = command_state_dir(command)?;
    let session_id = command.session_id.as_deref().unwrap();
    let host = command.host.as_deref().unwrap();
    let port = command.port.unwrap();
    let _lock = StateLock::acquire(&state_dir)?;
    let path = preauth_file(&state_dir, session_id);
    let mut rules = read_json_vec::<PreAuthorization>(&path)?;
    let before = rules.len();
    rules.retain(|rule| !(rule.host == host && rule.port == port));
    write_json(&path, &rules)?;
    let mut record = load_session_record(&state_dir, session_id)?;
    let entry = format!("{host}:{port}");
    record
        .spec
        .pre_authorized_hosts
        .retain(|value| value != &entry);
    save_session_record(&record)?;
    if before == rules.len() {
        return Ok(format!("未找到预授权 {host}:{port}"));
    }
    Ok(format!("已移除预授权 {host}:{port}"))
}

fn find_proxy_request(
    state_dir: &Path,
    request_id: &str,
) -> Result<(PathBuf, ProxyRequest), String> {
    if !state_dir.exists() {
        return Err(format!("找不到 request: {request_id}"));
    }
    for entry in fs::read_dir(state_dir).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let proxy_state = entry.path().join("proxy-state");
        let request_path = proxy_state
            .join("requests")
            .join(format!("{request_id}.json"));
        if request_path.exists() {
            let source = fs::read_to_string(&request_path).map_err(|error| error.to_string())?;
            let request = serde_json::from_str(&source).map_err(|error| error.to_string())?;
            return Ok((proxy_state, request));
        }
    }
    Err(format!("找不到 request: {request_id}"))
}

fn append_approval_audit(
    state_dir: &Path,
    proxy_state_dir: &Path,
    request: &ProxyRequest,
    response: ApprovalResponse,
) -> Result<(), String> {
    let session_id = proxy_session_id(proxy_state_dir)?;
    let mut record = load_session_record(state_dir, &session_id)?;
    let mut approval = ApprovalRequest::new(
        request.request_id.clone(),
        request.host.clone(),
        request.created_at_ms,
    );
    approval.port = request.port;
    approval.response = Some(response.clone());
    record.pending_requests.push(approval.clone());
    record.audit.push(SessionAuditRecord {
        session_id: session_id.clone(),
        snapshot_hash: record
            .snapshot
            .as_ref()
            .map(|snapshot| snapshot.snapshot_hash.clone())
            .unwrap_or_default(),
        runtime_digest: format!("{}:{}", record.spec.runtime, record.spec.image),
        policy_version: POLICY_VERSION.into(),
        image_id: record.spec.image_id.clone(),
        approval_request: Some(approval),
        approval_response: Some(response),
        diff_hash: record.diff.as_ref().map(|diff| diff.diff_hash.clone()),
        writeback_result: None,
        event: None,
        evaluation: None,
        proxy_request_id: None,
    });
    save_session_record(&record)
}

fn proxy_session_id(proxy_state_dir: &Path) -> Result<String, String> {
    proxy_state_dir
        .parent()
        .and_then(Path::file_name)
        .and_then(|value| value.to_str())
        .map(str::to_string)
        .ok_or_else(|| "无法推断 Session ID".to_string())
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Reads a JSON control file. A missing file is an empty list (first run),
/// but an unreadable or corrupt file is an error: silently treating damaged
/// approvals, denials, or evidence as empty would fail open.
fn read_json_vec<T: serde::de::DeserializeOwned>(path: &Path) -> Result<Vec<T>, String> {
    match fs::read_to_string(path) {
        Ok(source) => serde_json::from_str(&source)
            .map_err(|error| format!("无法解析控制文件 {}: {error}", path.display())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(format!("无法读取控制文件 {}: {error}", path.display())),
    }
}

pub fn prepare_session(mut spec: SessionSpec) -> Result<SessionRecord, String> {
    spec.workspace = fs::canonicalize(&spec.workspace)
        .map_err(|error| format!("无法读取工作区 {}: {error}", spec.workspace.display()))?;
    if !spec.workspace.is_dir() {
        return Err(format!("工作区不是目录: {}", spec.workspace.display()));
    }
    spec.state_dir = normalize_state_dir(&spec.state_dir)?;
    if spec.id.is_empty() {
        spec.id = session_id(&spec.workspace);
    }
    let session_dir = spec.state_dir.join(&spec.id);
    if session_dir.exists() {
        return Err(format!("Session 已存在: {}", spec.id));
    }
    let snapshot_dir = session_dir.join("snapshot");
    let proxy_state_dir = session_dir.join("proxy-state");
    fs::create_dir_all(&proxy_state_dir).map_err(|error| error.to_string())?;
    fs::create_dir_all(proxy_state_dir.join("requests")).map_err(|error| error.to_string())?;
    fs::write(proxy_state_dir.join("approvals.json"), "[]\n").map_err(|error| error.to_string())?;
    let pre_authorizations = spec
        .pre_authorized_hosts
        .iter()
        .map(|entry| parse_pre_authorization(entry))
        .collect::<Result<Vec<_>, String>>()?;
    write_json(&proxy_state_dir.join("preauth.json"), &pre_authorizations)
        .map_err(|error| error.to_string())?;
    if let Some(path) = spec.credential_routes_path.clone() {
        let source = fs::read_to_string(&path)
            .map_err(|error| format!("无法读取凭据路由文件 {path}: {error}"))?;
        let routes: Vec<CredentialRoute> =
            serde_json::from_str(&source).map_err(|error| format!("凭据路由文件无效: {error}"))?;
        for route in &routes {
            route.validate()?;
        }
        write_json(&proxy_state_dir.join("broker.json"), &routes)
            .map_err(|error| error.to_string())?;
        // A short-lived credential is produced on the host and written next to
        // the proxy state, which the agent container never mounts.
        for route in &routes {
            if route.token_command.is_none() {
                continue;
            }
            let secret = run_token_command(route)?;
            write_route_secret(&proxy_state_dir, route, &secret)?;
        }
        spec.credential_routes = routes
            .iter()
            .map(|route| CredentialRouteSummary {
                route: route.route.clone(),
                upstream_host: route.upstream_host.clone(),
                upstream_port: route.upstream_port,
                secret_env: route.secret_env.clone(),
                secret_file: route.secret_file.clone(),
            })
            .collect();
    }
    let manifest = snapshot_workspace(&spec.workspace, &snapshot_dir, &spec.excluded_paths)?;
    let prepared = outbound_witness_core::session::PreparedSession {
        session_id: spec.id.clone(),
        snapshot_dir,
        proxy_state_dir,
        spec: spec.clone(),
    };
    let mut record = SessionRecord::new(spec);
    record.snapshot = Some(manifest.clone());
    record.prepared = Some(prepared);
    record.audit.push(SessionAuditRecord {
        session_id: record.spec.id.clone(),
        snapshot_hash: manifest.snapshot_hash,
        runtime_digest: format!("{}:{}", record.spec.runtime, record.spec.image),
        policy_version: POLICY_VERSION.into(),
        image_id: record.spec.image_id.clone(),
        approval_request: None,
        approval_response: None,
        diff_hash: None,
        writeback_result: None,
        event: None,
        evaluation: None,
        proxy_request_id: None,
    });
    save_session_record(&record)?;
    Ok(record)
}

pub fn load_session_record(state_dir: &Path, session_id: &str) -> Result<SessionRecord, String> {
    let state_dir = normalize_state_dir(state_dir)?;
    let source = fs::read_to_string(state_dir.join(session_id).join("session.json"))
        .map_err(|error| format!("无法读取 Session {session_id}: {error}"))?;
    serde_json::from_str(&source).map_err(|error| format!("Session 记录无效: {error}"))
}

pub fn record_proxy_witnesses(state_dir: &Path, session_id: &str) -> Result<(), String> {
    let _lock = StateLock::acquire(state_dir)?;
    record_proxy_witnesses_locked(state_dir, session_id)
}

fn record_proxy_witnesses_locked(state_dir: &Path, session_id: &str) -> Result<(), String> {
    let mut record = load_session_record(state_dir, session_id)?;
    let proxy_state = record
        .prepared
        .as_ref()
        .map(|prepared| prepared.proxy_state_dir.clone())
        .unwrap_or_else(|| {
            record
                .spec
                .state_dir
                .join(&record.spec.id)
                .join("proxy-state")
        });
    let mut requests = read_proxy_request_records(&proxy_state)?;
    requests.sort_by(|left, right| {
        left.created_at_ms
            .cmp(&right.created_at_ms)
            .then_with(|| left.request_id.cmp(&right.request_id))
    });
    let approvals = read_json_vec::<ApprovalGrant>(&proxy_state.join("approvals.json"))?;
    let denials = read_json_vec::<DeniedRequest>(&proxy_state.join("denials.json"))?;
    let pre_authorizations = read_json_vec::<PreAuthorization>(&proxy_state.join("preauth.json"))?;
    let mut seen_hosts = Vec::new();
    for request in &requests {
        let first_seen = !seen_hosts.iter().any(|host| host == &request.host);
        seen_hosts.push(request.host.clone());
        let evaluation_result = evaluate_request_detailed(
            request,
            &ProxyConfig {
                mode: if record.spec.mode == EnforcementMode::Strict {
                    ProxyMode::Strict
                } else {
                    ProxyMode::Observe
                },
                approval_timeout_ms: record.spec.approval_timeout_secs.saturating_mul(1000),
                image_id: record.spec.image_id.clone(),
            },
            &approvals,
            &denials,
            &pre_authorizations,
            now_millis(),
        );
        // The proxy records why it allowed or blocked a connection at runtime;
        // fall back to the recomputed reason only for request files written by
        // older versions that did not persist a decision.
        let source = request
            .decision_source
            .clone()
            .unwrap_or_else(|| evaluation_result.source.as_str().to_string());
        let decision = decision_from_source(&source).unwrap_or(evaluation_result.decision);
        let mut event = witness_from_proxy_request(&record.spec, request, first_seen);
        let mut evaluation = evaluate_event(&event, &RuleConfig::default(), record.spec.mode);
        evaluation.decision = policy_decision_from_proxy(decision, record.spec.mode);
        evaluation.explanation = format!(
            "{}，不来自文件风险分。{}",
            decision_source_note(&source),
            evaluation.explanation
        );
        event.consent = None;
        record
            .audit
            .retain(|entry| entry.proxy_request_id.as_deref() != Some(request.request_id.as_str()));
        record.audit.push(SessionAuditRecord {
            session_id: record.spec.id.clone(),
            snapshot_hash: record
                .snapshot
                .as_ref()
                .map(|snapshot| snapshot.snapshot_hash.clone())
                .unwrap_or_default(),
            runtime_digest: format!("{}:{}", record.spec.runtime, record.spec.image),
            policy_version: POLICY_VERSION.into(),
            image_id: record.spec.image_id.clone(),
            approval_request: None,
            approval_response: None,
            diff_hash: record.diff.as_ref().map(|diff| diff.diff_hash.clone()),
            writeback_result: None,
            event: Some(event),
            evaluation: Some(evaluation),
            proxy_request_id: Some(request.request_id.clone()),
        });
    }
    record.network_intents = requests
        .iter()
        .map(|request| NetworkIntent {
            request_id: request.request_id.clone(),
            host: request.host.clone(),
            port: request.port,
            protocol: "https".into(),
            timestamp: request.created_at_ms.to_string(),
            bytes_sent: request.bytes_sent,
        })
        .collect();
    save_session_record(&record)
}

fn is_request_record(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    !name.starts_with('.') && path.extension().and_then(|value| value.to_str()) == Some("json")
}

/// Reads every CONNECT evidence record. A missing requests directory or a
/// corrupt record is an error: exporting a signed audit that silently omitted
/// damaged evidence would be worse than refusing to export.
fn read_proxy_request_records(state_dir: &Path) -> Result<Vec<ProxyRequest>, String> {
    let requests_dir = state_dir.join("requests");
    let entries = fs::read_dir(&requests_dir)
        .map_err(|error| format!("无法读取请求记录目录 {}: {error}", requests_dir.display()))?;
    let mut requests = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| error.to_string())?;
        let path = entry.path();
        if !is_request_record(&path) {
            continue;
        }
        let source = fs::read_to_string(&path)
            .map_err(|error| format!("无法读取请求记录 {}: {error}", path.display()))?;
        let request = serde_json::from_str::<ProxyRequest>(&source)
            .map_err(|error| format!("请求记录损坏 {}: {error}", path.display()))?;
        requests.push(request);
    }
    Ok(requests)
}

fn witness_from_proxy_request(
    spec: &SessionSpec,
    request: &ProxyRequest,
    first_seen: bool,
) -> WitnessEvent {
    WitnessEvent {
        process: ProcessIdentity {
            pid: 0,
            executable: spec.image.clone(),
            name: spec
                .command
                .first()
                .cloned()
                .unwrap_or_else(|| "session".into()),
            version: spec.image_id.clone(),
            signer: None,
            parent_pid: None,
            parent_name: None,
            executable_sha256: spec.image_id.clone(),
        },
        network: NetworkEvent {
            destination: Destination {
                host: request.host.clone(),
                ip: None,
                port: request.port,
                protocol: "https".into(),
            },
            bytes_sent: request.bytes_sent,
            timestamp: format!("{}", request.created_at_ms),
        },
        file_events: Vec::new(),
        archive_created: false,
        first_seen_destination: first_seen,
        consent: None,
    }
}

fn policy_decision_from_proxy(decision: ProxyDecision, _mode: EnforcementMode) -> PolicyDecision {
    match decision {
        ProxyDecision::Allow => PolicyDecision::Allow,
        ProxyDecision::Pending | ProxyDecision::Block => PolicyDecision::Block,
    }
}

pub fn collect_session_diff(state_dir: &Path, session_id: &str) -> Result<WorkspaceDiff, String> {
    let _lock = StateLock::acquire(state_dir)?;
    let mut record = load_session_record(state_dir, session_id)?;
    let snapshot = record
        .snapshot
        .as_ref()
        .ok_or_else(|| "Session 缺少工作区快照".to_string())?;
    let diff = collect_diff(
        &snapshot.source_root,
        &snapshot.snapshot_root,
        &snapshot.excluded_paths,
    )?;
    record.diff = Some(diff.clone());
    if let Some(audit) = record.audit.iter_mut().find(|entry| entry.event.is_none()) {
        audit.diff_hash = Some(diff.diff_hash.clone());
    }
    save_session_record(&record)?;
    Ok(diff)
}

pub fn apply_session_diff(
    state_dir: &Path,
    session_id: &str,
    paths: &[String],
) -> Result<(), String> {
    if paths.is_empty() {
        return Err("session apply 至少需要一个 --path；默认不自动写回宿主工作区".into());
    }
    let _lock = StateLock::acquire(state_dir)?;
    let mut record = load_session_record(state_dir, session_id)?;
    // The snapshot belongs to the agent and can keep changing while a session
    // runs. A writeback before the terminal state could apply bytes that differ
    // from the diff the user reviewed, so it is refused outright.
    match record.state {
        SessionState::Completed | SessionState::Failed | SessionState::Blocked => {}
        other => {
            return Err(format!(
                "Session 尚未结束（{:?}），拒绝写回；请等待 Session 结束并重新查看 diff 后再 apply",
                other
            ));
        }
    }
    // Do not generate a diff implicitly: the user must have seen the entries
    // they are about to copy onto the host. `session diff` records the diff.
    let diff = record.diff.clone().ok_or_else(|| {
        "尚未收集并查看 diff，拒绝写回；请先运行 `outbound-witness session diff <session-id>` 确认内容后再 apply".to_string()
    })?;
    apply_diff(&diff.source_root, &diff.snapshot_root, &diff, paths)?;
    // A dedicated writeback record is stronger evidence than mutating the
    // last audit entry: it says which diff was applied, to which paths, and
    // becomes part of the hash chain.
    record.audit.push(SessionAuditRecord {
        session_id: record.spec.id.clone(),
        snapshot_hash: record
            .snapshot
            .as_ref()
            .map(|snapshot| snapshot.snapshot_hash.clone())
            .unwrap_or_default(),
        runtime_digest: format!("{}:{}", record.spec.runtime, record.spec.image),
        policy_version: POLICY_VERSION.into(),
        image_id: record.spec.image_id.clone(),
        approval_request: None,
        approval_response: None,
        diff_hash: Some(diff.diff_hash.clone()),
        writeback_result: Some(format!("applied: {}", paths.join(","))),
        event: None,
        evaluation: None,
        proxy_request_id: None,
    });
    // The host now matches the selected snapshot entries, so the old diff is
    // stale. Require a fresh `session diff` before any second writeback.
    record.diff = None;
    save_session_record(&record)
}

pub fn export_session_audit(
    state_dir: &Path,
    session_id: &str,
    output: &Path,
) -> Result<(), String> {
    let _lock = StateLock::acquire(state_dir)?;
    // Backfill CONNECT evidence for sessions that ended without a clean
    // shutdown. Without this, a Ctrl-C or a crashed desktop process would
    // export a record with no proxy witnesses at all.
    record_proxy_witnesses_locked(state_dir, session_id)?;
    let mut record = load_session_record(state_dir, session_id)?;
    // Chain the audit before exporting so the file carries a verifiable digest
    // over its own contents, then sign it so the origin can be checked.
    record.chain_audit();
    crate::signing::sign_record(state_dir, &mut record)?;
    let rendered = if output.extension().and_then(|value| value.to_str()) == Some("html") {
        audit_html(&record)?
    } else {
        serde_json::to_string_pretty(&record).map_err(|error| error.to_string())?
    };
    fs::write(output, rendered)
        .map_err(|error| format!("无法写入审计 {}: {error}", output.display()))
}

fn save_session_record(record: &SessionRecord) -> Result<(), String> {
    let directory = record.spec.state_dir.join(&record.spec.id);
    fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
    write_json(&directory.join("session.json"), record)
}

/// Applies one mutation to the latest on-disk record under the control lock.
/// Callers that keep a record in memory across a long operation must use this
/// instead of saving their stale copy, otherwise an approval written by another
/// process can be silently overwritten.
fn update_session_record<F>(
    state_dir: &Path,
    session_id: &str,
    mutate: F,
) -> Result<SessionRecord, String>
where
    F: FnOnce(&mut SessionRecord) -> Result<(), String>,
{
    let _lock = StateLock::acquire(state_dir)?;
    let mut record = load_session_record(state_dir, session_id)?;
    mutate(&mut record)?;
    save_session_record(&record)?;
    Ok(record)
}

fn render_session_status(command: &CliCommand) -> Result<String, String> {
    let state_dir = command_state_dir(command)?;
    let mut records = Vec::new();
    if !state_dir.exists() {
        return Ok("尚无本地 Session。".into());
    }
    for entry in fs::read_dir(&state_dir).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        if !entry.path().is_dir() {
            continue;
        }
        let session_id = entry.file_name().to_string_lossy().into_owned();
        if !entry.path().join("session.json").exists() {
            continue;
        }
        let record = load_session_record(&state_dir, &session_id)?;
        records.push(record);
    }
    records.sort_by(|left, right| left.spec.id.cmp(&right.spec.id));
    if command.json {
        return serde_json::to_string_pretty(&records).map_err(|error| error.to_string());
    }
    if records.is_empty() {
        return Ok("尚无本地 Session。".into());
    }
    Ok(records
        .iter()
        .map(|record| {
            format!(
                "{}\t{:?}\t{}\t{}",
                record.spec.id,
                record.state,
                record.spec.workspace.display(),
                record.spec.command.join(" ")
            )
        })
        .collect::<Vec<_>>()
        .join("\n"))
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PendingRequestView {
    pub session_id: String,
    pub session_state: SessionState,
    pub request_id: String,
    pub host: String,
    pub port: u16,
    pub bytes_sent: u64,
    /// `pending` | `allowed` | `denied`
    pub decision: String,
    /// Why the decision was reached: observe | pre_authorized |
    /// manual_approval | denied | timeout | pending.
    #[serde(default)]
    pub source: String,
}

/// Lists every proxy request recorded under the state directory together with
/// its current control decision, so UIs can surface approvals waiting for the
/// user while a session is still running.
pub fn pending_requests(state_dir: &Path) -> Result<Vec<PendingRequestView>, String> {
    let mut views = Vec::new();
    if !state_dir.exists() {
        return Ok(views);
    }
    for entry in fs::read_dir(state_dir).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        if !entry.path().is_dir() {
            continue;
        }
        let session_id = entry.file_name().to_string_lossy().into_owned();
        if !entry.path().join("session.json").exists() {
            continue;
        }
        let record = load_session_record(state_dir, &session_id)?;
        let proxy_state = entry.path().join("proxy-state");
        let approvals = read_json_vec::<ApprovalGrant>(&proxy_state.join("approvals.json"))?;
        let denials = read_json_vec::<DeniedRequest>(&proxy_state.join("denials.json"))?;
        let pre_authorizations =
            read_json_vec::<PreAuthorization>(&proxy_state.join("preauth.json"))?;
        let config = ProxyConfig {
            mode: if record.spec.mode == outbound_witness_core::EnforcementMode::Strict {
                ProxyMode::Strict
            } else {
                ProxyMode::Observe
            },
            approval_timeout_ms: record.spec.approval_timeout_secs * 1000,
            image_id: record.spec.image_id.clone(),
        };
        let requests_dir = proxy_state.join("requests");
        let request_entries = fs::read_dir(&requests_dir)
            .map_err(|error| format!("无法读取请求记录目录 {}: {error}", requests_dir.display()))?;
        for request_entry in request_entries {
            let request_entry = request_entry.map_err(|error| error.to_string())?;
            let path = request_entry.path();
            if !is_request_record(&path) {
                continue;
            }
            let source = fs::read_to_string(&path)
                .map_err(|error| format!("无法读取请求记录 {}: {error}", path.display()))?;
            let request = serde_json::from_str::<ProxyRequest>(&source)
                .map_err(|error| format!("请求记录损坏 {}: {error}", path.display()))?;
            let evaluation = evaluate_request_detailed(
                &request,
                &config,
                &approvals,
                &denials,
                &pre_authorizations,
                now_millis(),
            );
            let decision = match request
                .decision_source
                .as_deref()
                .and_then(decision_from_source)
            {
                Some(outbound_witness_proxy::ProxyDecision::Allow) => "allowed",
                Some(outbound_witness_proxy::ProxyDecision::Block) => "denied",
                Some(outbound_witness_proxy::ProxyDecision::Pending) => "pending",
                None => match evaluation.decision {
                    outbound_witness_proxy::ProxyDecision::Allow => "allowed",
                    outbound_witness_proxy::ProxyDecision::Block => "denied",
                    outbound_witness_proxy::ProxyDecision::Pending => "pending",
                },
            };
            let source = request
                .decision_source
                .clone()
                .unwrap_or_else(|| evaluation.source.as_str().to_string());
            views.push(PendingRequestView {
                session_id: session_id.clone(),
                session_state: record.state.clone(),
                request_id: request.request_id,
                host: request.host,
                port: request.port,
                bytes_sent: request.bytes_sent,
                decision: decision.into(),
                source,
            });
        }
    }
    views.sort_by(|left, right| {
        left.session_id
            .cmp(&right.session_id)
            .then(left.request_id.cmp(&right.request_id))
    });
    Ok(views)
}

fn render_pending_requests(command: &CliCommand) -> Result<String, String> {
    let state_dir = command_state_dir(command)?;
    let views = pending_requests(&state_dir)?;
    if command.json {
        return serde_json::to_string_pretty(&views).map_err(|error| error.to_string());
    }
    if views.is_empty() {
        return Ok("没有待处理的代理请求。".into());
    }
    Ok(views
        .iter()
        .map(|view| {
            format!(
                "{}\t{}\t{}:{} ({} bytes)",
                view.decision, view.session_id, view.host, view.port, view.bytes_sent
            )
        })
        .collect::<Vec<_>>()
        .join("\n"))
}

fn render_diff(command: &CliCommand) -> Result<String, String> {
    let state_dir = command_state_dir(command)?;
    let session_id = command.session_id.as_deref().unwrap();
    let diff = collect_session_diff(&state_dir, session_id)?;
    if command.json {
        return serde_json::to_string_pretty(&diff).map_err(|error| error.to_string());
    }
    if diff.entries.is_empty() {
        return Ok(format!("{session_id}: 无工作区变更"));
    }
    Ok(diff
        .entries
        .iter()
        .map(|entry| format!("{:?}\t{}", entry.kind, entry.relative_path))
        .collect::<Vec<_>>()
        .join("\n"))
}

/// State directory for a command, exposed so non-session commands can locate
/// the signing key that lives beside the session records.
pub fn state_dir_for(command: &CliCommand) -> Result<PathBuf, String> {
    command_state_dir(command)
}

fn command_state_dir(command: &CliCommand) -> Result<PathBuf, String> {
    let path = command
        .state_dir
        .as_deref()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".outbound-witness/sessions"));
    normalize_state_dir(&path)
}

fn spec_from_command(command: &CliCommand) -> Result<SessionSpec, String> {
    let workspace = command
        .workspace
        .as_deref()
        .map(PathBuf::from)
        .ok_or_else(|| "session start 需要 --workspace".to_string())?;
    let mut spec = SessionSpec::new(workspace, command.command.clone(), command.mode);
    spec.state_dir = command_state_dir(command)?;
    if let Some(runtime) = &command.runtime {
        spec.runtime = runtime.clone();
    }
    if let Some(image) = &command.image {
        spec.image = image.clone();
    }
    spec.pre_authorized_hosts = command.allow_hosts.clone();
    spec.credential_routes_path = command.credential_routes.clone();
    Ok(spec)
}

/// Parses a host:port entry from --allow-host into a session-scoped rule.
/// Runs a route's host-side token command and returns the trimmed stdout.
fn run_token_command(route: &CredentialRoute) -> Result<String, String> {
    run_token_command_with_timeout(route, TOKEN_COMMAND_TIMEOUT)
}

fn run_token_command_with_timeout(
    route: &CredentialRoute,
    timeout: Duration,
) -> Result<String, String> {
    let command = route
        .token_command
        .as_ref()
        .ok_or_else(|| format!("路由 {} 没有 token_command", route.route))?;
    let mut child = Command::new(&command[0])
        .args(&command[1..])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("执行 token_command 失败（{}）: {error}", route.route))?;
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if started.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!(
                        "token_command 超时（{}，{} 秒）；请缩短命令或改用 secret_env",
                        route.route,
                        timeout.as_secs()
                    ));
                }
                thread::sleep(Duration::from_millis(50));
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!(
                    "等待 token_command 失败（{}）: {error}",
                    route.route
                ));
            }
        }
    }
    let output = child
        .wait_with_output()
        .map_err(|error| format!("读取 token_command 输出失败（{}）: {error}", route.route))?;
    if !output.status.success() {
        return Err(format!(
            "token_command 失败（{}）：{}",
            route.route,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let secret = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if secret.is_empty() {
        return Err(format!("token_command 没有输出凭据（{}）", route.route));
    }
    Ok(secret)
}

fn write_route_secret(
    proxy_state_dir: &Path,
    route: &CredentialRoute,
    secret: &str,
) -> Result<(), String> {
    let relative = route
        .secret_file
        .as_deref()
        .filter(|path| !path.is_empty())
        .ok_or_else(|| format!("凭据路由 {} 没有声明 secret_file", route.route))?;
    let relative = Path::new(relative);
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(format!(
            "凭据文件必须是 state 目录内的相对路径: {}",
            relative.display()
        ));
    }
    let path = proxy_state_dir.join(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    write_secret_file(&path, secret)
}

/// Renews short-lived credentials while the agent runs. The thread stops when
/// the session ends, so nothing is refreshed after the container is gone.
struct CredentialRefresh {
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl CredentialRefresh {
    fn stop(mut self) {
        use std::sync::atomic::Ordering;
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn spawn_credential_refresh(
    routes: Vec<CredentialRoute>,
    proxy_state_dir: PathBuf,
) -> CredentialRefresh {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    let stop = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    let Some(ttl) = routes
        .iter()
        .filter(|route| route.token_command.is_some())
        .filter_map(|route| route.token_ttl_secs)
        .min()
    else {
        return CredentialRefresh { stop, handle: None };
    };
    // Renew at half the lifetime so one slow refresh cannot let a token expire.
    let interval = Duration::from_secs((ttl / 2).max(1));
    let handle = thread::spawn(move || {
        let mut last = Instant::now();
        while !flag.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_millis(200));
            if last.elapsed() < interval {
                continue;
            }
            last = Instant::now();
            for route in &routes {
                if route.token_command.is_none() {
                    continue;
                }
                match run_token_command(route) {
                    Ok(secret) => {
                        if let Err(error) = write_route_secret(&proxy_state_dir, route, &secret) {
                            eprintln!("凭据轮换写入失败（{}）: {error}", route.route);
                        }
                    }
                    Err(error) => eprintln!("凭据轮换失败（{}）: {error}", route.route),
                }
            }
        }
    });
    CredentialRefresh {
        stop,
        handle: Some(handle),
    }
}

/// Writes a credential file only the owner can read. The host writes it; the
/// agent container has no mount for the proxy state directory at all.
#[cfg(unix)]
fn write_secret_file(path: &Path, value: &str) -> Result<(), String> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| format!("无法写入凭据文件 {}: {error}", path.display()))?;
    io::Write::write_all(&mut file, value.as_bytes())
        .map_err(|error| format!("无法写入凭据文件 {}: {error}", path.display()))
}

#[cfg(not(unix))]
fn write_secret_file(path: &Path, value: &str) -> Result<(), String> {
    fs::write(path, value).map_err(|error| format!("无法写入凭据文件 {}: {error}", path.display()))
}

fn parse_pre_authorization(entry: &str) -> Result<PreAuthorization, String> {
    let (host, port) = entry
        .rsplit_once(':')
        .ok_or_else(|| format!("预授权需要 host:port，收到: {entry}"))?;
    let port = port
        .parse::<u16>()
        .map_err(|_| format!("预授权端口无效: {entry}"))?;
    if host.is_empty() {
        return Err(format!("预授权主机为空: {entry}"));
    }
    Ok(PreAuthorization {
        host: host.to_string(),
        port,
        expires_at_ms: None,
        note: Some("session start --allow-host".into()),
    })
}

fn normalize_state_dir(path: &Path) -> Result<PathBuf, String> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    Ok(std::env::current_dir()
        .map_err(|error| error.to_string())?
        .join(path))
}

fn session_id(workspace: &Path) -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let digest = outbound_witness_core::sha256_hex(workspace.display().to_string().as_bytes());
    format!("session-{millis}-{}", &digest[..10])
}

fn audit_html(record: &SessionRecord) -> Result<String, String> {
    let json = serde_json::to_string_pretty(record).map_err(|error| error.to_string())?;
    Ok(format!(
        "<!doctype html><html lang=\"zh-CN\"><meta charset=\"utf-8\"><title>Outbound Witness 审计</title><style>body{{font-family:ui-monospace,Menlo,monospace;margin:32px;line-height:1.5}}pre{{white-space:pre-wrap;word-break:break-word}}</style><h1>Outbound Witness Session 审计</h1><p>Session: {}</p><pre>{}</pre></html>",
        html_escape(&record.spec.id),
        html_escape(&json)
    ))
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

pub fn probe_docker() -> RuntimeCapability {
    let version = Command::new("docker").arg("--version").output();
    let Ok(version_output) = version else {
        return RuntimeCapability {
            runtime: "docker".into(),
            available: false,
            daemon_ready: false,
            version: None,
            enforcement: "不可用".into(),
            message: "未找到 docker 命令".into(),
        };
    };
    if !version_output.status.success() {
        return RuntimeCapability {
            runtime: "docker".into(),
            available: false,
            daemon_ready: false,
            version: None,
            enforcement: "不可用".into(),
            message: String::from_utf8_lossy(&version_output.stderr)
                .trim()
                .into(),
        };
    }
    let version = String::from_utf8_lossy(&version_output.stdout)
        .trim()
        .to_string();
    let info = Command::new("docker")
        .args(["info", "--format", "{{.ServerVersion}}"])
        .output();
    match info {
        Ok(output) if output.status.success() => RuntimeCapability {
            runtime: "docker".into(),
            available: true,
            daemon_ready: true,
            version: Some(String::from_utf8_lossy(&output.stdout).trim().to_string()),
            enforcement: "可启动受控容器；代理镜像可用后提供结构性出站约束".into(),
            message: "Docker daemon 已连接".into(),
        },
        Ok(output) => RuntimeCapability {
            runtime: "docker".into(),
            available: true,
            daemon_ready: false,
            version: Some(version),
            enforcement: "不可用".into(),
            message: String::from_utf8_lossy(&output.stderr).trim().into(),
        },
        Err(error) => RuntimeCapability {
            runtime: "docker".into(),
            available: true,
            daemon_ready: false,
            version: Some(version),
            enforcement: "不可用".into(),
            message: error.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token_route(command: Vec<&str>) -> CredentialRoute {
        CredentialRoute {
            route: "test".into(),
            upstream_host: "api.example.test".into(),
            upstream_port: 443,
            header: "authorization".into(),
            secret_env: None,
            secret_file: Some("credentials/test".into()),
            token_command: Some(command.into_iter().map(str::to_string).collect()),
            token_ttl_secs: None,
            max_requests_per_minute: None,
            note: None,
        }
    }

    #[cfg(unix)]
    #[test]
    fn token_command_returns_trimmed_stdout() {
        let route = token_route(vec!["sh", "-c", "printf '  token-value\\n'"]);
        let value = run_token_command_with_timeout(&route, Duration::from_secs(5))
            .expect("token command should succeed");
        assert_eq!(value, "token-value");
    }

    #[cfg(unix)]
    #[test]
    fn token_command_is_killed_after_the_timeout() {
        let route = token_route(vec!["sh", "-c", "sleep 5; printf token"]);
        let error = run_token_command_with_timeout(&route, Duration::from_millis(200))
            .expect_err("a hanging token command must time out");
        assert!(error.contains("超时"), "unexpected error: {error}");
    }
}
