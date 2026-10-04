use outbound_witness_core::{
    evaluate_event, AuditLedger, ConsentGrant, Destination, EnforcementMode, EvaluationResult,
    FileEvent, FileEventKind, NetworkEvent, PolicyDecision, ProcessIdentity, RuleConfig,
    WitnessEvent,
};
use std::fs;

pub mod session_runtime;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliCommand {
    pub name: String,
    pub mode: EnforcementMode,
    pub json: bool,
    pub output: Option<String>,
    pub input: Option<String>,
    pub session_subcommand: Option<String>,
    pub workspace: Option<String>,
    pub command: Vec<String>,
    pub session_id: Option<String>,
    pub request_id: Option<String>,
    pub paths: Vec<String>,
    pub scope: Option<String>,
    pub ttl: Option<u64>,
    pub state_dir: Option<String>,
    pub runtime: Option<String>,
    pub image: Option<String>,
    /// Hosts pre-authorized for a session start, each written as host:port.
    pub allow_hosts: Vec<String>,
    /// Action for the preauth subcommand: add, list, or remove.
    pub policy_action: Option<String>,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub note: Option<String>,
    /// Host-side JSON file describing credential broker routes.
    pub credential_routes: Option<String>,
}

pub fn parse_args(args: &[String]) -> Result<CliCommand, String> {
    if args.get(1).map(String::as_str) == Some("session") {
        return parse_session_args(args);
    }
    if args.get(1).map(String::as_str) == Some("doctor") {
        return Ok(CliCommand {
            name: "doctor".into(),
            session_subcommand: args.get(2).cloned(),
            ..CliCommand::default()
        });
    }
    let name = args.get(1).cloned().unwrap_or_else(|| "help".into());
    let mut command = CliCommand {
        name,
        ..CliCommand::default()
    };
    let mut index = 2;
    while index < args.len() {
        match args[index].as_str() {
            "--mode" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--mode 需要 observe 或 strict".to_string())?;
                command.mode = parse_mode(value)?;
                index += 2;
            }
            "--json" => {
                command.json = true;
                index += 1;
            }
            "--export" => {
                command.output = Some(
                    args.get(index + 1)
                        .ok_or_else(|| "--export 需要输出路径".to_string())?
                        .clone(),
                );
                index += 2;
            }
            value if command.name == "mode" && index == 2 => {
                command.mode = parse_mode(value)?;
                index += 1;
            }
            value if command.name == "evaluate" && command.input.is_none() => {
                command.input = Some(value.to_string());
                index += 1;
            }
            value => return Err(format!("未知参数: {value}")),
        }
    }
    if command.name == "evaluate" && command.input.is_none() {
        return Err("evaluate 需要事件或 benchmark JSON 文件路径".into());
    }
    Ok(command)
}

impl Default for CliCommand {
    fn default() -> Self {
        Self {
            name: "help".into(),
            mode: EnforcementMode::Observe,
            json: false,
            output: None,
            input: None,
            session_subcommand: None,
            workspace: None,
            command: Vec::new(),
            session_id: None,
            request_id: None,
            paths: Vec::new(),
            scope: None,
            ttl: None,
            state_dir: None,
            runtime: None,
            image: None,
            allow_hosts: Vec::new(),
            policy_action: None,
            host: None,
            port: None,
            note: None,
            credential_routes: None,
        }
    }
}

fn parse_session_args(args: &[String]) -> Result<CliCommand, String> {
    let mut command = CliCommand {
        name: "session".into(),
        session_subcommand: args.get(2).cloned(),
        ..CliCommand::default()
    };
    let subcommand = command
        .session_subcommand
        .as_deref()
        .ok_or_else(|| {
            "session 需要 start/status/requests/approve/deny/diff/apply/export/preauth".to_string()
        })?;
    let mut index = 3;
    while index < args.len() {
        if subcommand == "start" && args[index] == "--" {
            command.command = args[index + 1..].to_vec();
            break;
        }
        match args[index].as_str() {
            "--workspace" => {
                command.workspace = Some(required_value(args, &mut index, "--workspace")?);
            }
            "--mode" => {
                command.mode = parse_mode(&required_value(args, &mut index, "--mode")?)?;
            }
            "--state-dir" => {
                command.state_dir = Some(required_value(args, &mut index, "--state-dir")?);
            }
            "--runtime" => {
                command.runtime = Some(required_value(args, &mut index, "--runtime")?);
            }
            "--image" => {
                command.image = Some(required_value(args, &mut index, "--image")?);
            }
            "--scope" => {
                command.scope = Some(required_value(args, &mut index, "--scope")?);
            }
            "--ttl" => {
                let value = required_value(args, &mut index, "--ttl")?;
                command.ttl = Some(value.parse().map_err(|_| {
                    format!("--ttl 需要正整数秒数，收到: {value}")
                })?);
            }
            "--path" => {
                command
                    .paths
                    .push(required_value(args, &mut index, "--path")?);
            }
            "--output" => {
                command.output = Some(required_value(args, &mut index, "--output")?);
            }
            "--allow-host" => {
                let value = required_value(args, &mut index, "--allow-host")?;
                validate_allow_host(&value)?;
                command.allow_hosts.push(value);
            }
            "--host" => {
                command.host = Some(required_value(args, &mut index, "--host")?);
            }
            "--port" => {
                let value = required_value(args, &mut index, "--port")?;
                command.port = Some(
                    value
                        .parse()
                        .map_err(|_| format!("--port 需要 1-65535 的端口，收到: {value}"))?,
                );
            }
            "--note" => {
                command.note = Some(required_value(args, &mut index, "--note")?);
            }
            "--credential-routes" => {
                command.credential_routes =
                    Some(required_value(args, &mut index, "--credential-routes")?);
            }
            "--json" => command.json = true,
            value
                if command.session_id.is_none()
                    && matches!(subcommand, "status" | "diff" | "apply" | "export") =>
            {
                command.session_id = Some(value.into());
            }
            value if command.request_id.is_none() && matches!(subcommand, "approve" | "deny") => {
                command.request_id = Some(value.into());
            }
            value
                if subcommand == "preauth"
                    && command.policy_action.is_none()
                    && matches!(value, "add" | "list" | "remove") =>
            {
                command.policy_action = Some(value.into());
            }
            value if subcommand == "preauth" && command.session_id.is_none() => {
                command.session_id = Some(value.into());
            }
            value => return Err(format!("session 未知参数: {value}")),
        }
        index += 1;
    }
    if subcommand == "start" && command.command.is_empty() {
        return Err("session start 需要 -- 后面的目标命令".into());
    }
    if subcommand == "start" && command.workspace.is_none() {
        return Err("session start 需要 --workspace".into());
    }
    if matches!(subcommand, "approve" | "deny") && command.request_id.is_none() {
        return Err(format!("session {subcommand} 需要 request-id"));
    }
    if matches!(subcommand, "diff" | "apply" | "export") && command.session_id.is_none() {
        return Err(format!("session {subcommand} 需要 session-id"));
    }
    if subcommand == "preauth" {
        let action = command
            .policy_action
            .as_deref()
            .ok_or_else(|| "session preauth 需要 add/list/remove".to_string())?;
        if command.session_id.is_none() {
            return Err(format!("session preauth {action} 需要 session-id"));
        }
        if matches!(action, "add" | "remove") && (command.host.is_none() || command.port.is_none())
        {
            return Err(format!("session preauth {action} 需要 --host 和 --port"));
        }
    }
    Ok(command)
}

/// Pre-authorizations are always port-bound, so a malformed entry must be
/// rejected before a session starts rather than silently widening the rule.
fn validate_allow_host(value: &str) -> Result<(), String> {
    let (host, port) = value
        .rsplit_once(':')
        .ok_or_else(|| format!("--allow-host 需要 host:port，收到: {value}"))?;
    if host.is_empty() {
        return Err(format!("--allow-host 主机为空: {value}"));
    }
    port.parse::<u16>()
        .map_err(|_| format!("--allow-host 端口无效: {value}"))?;
    Ok(())
}

fn required_value(args: &[String], index: &mut usize, flag: &str) -> Result<String, String> {
    let value = args
        .get(*index + 1)
        .ok_or_else(|| format!("{flag} 需要参数"))?
        .clone();
    *index += 1;
    Ok(value)
}

fn parse_mode(value: &str) -> Result<EnforcementMode, String> {
    match value {
        "observe" => Ok(EnforcementMode::Observe),
        "strict" => Ok(EnforcementMode::Strict),
        _ => Err(format!("未知模式: {value}，可选 observe 或 strict")),
    }
}

pub fn evaluate_demo(mode: EnforcementMode) -> EvaluationResult {
    evaluate_event(&demo_event(), &RuleConfig::default(), mode)
}

pub fn run(args: Vec<String>) -> Result<String, String> {
    let command = parse_args(&args)?;
    match command.name.as_str() {
        "help" => Ok(help_text()),
        "status" => {
            let status = serde_json::json!({
                "product": "outbound-witness",
                "version": env!("CARGO_PKG_VERSION"),
                "mode": match command.mode { EnforcementMode::Observe => "observe", EnforcementMode::Strict => "strict" },
                "telemetry": false,
                "https_decryption": false,
                "platform_adapter": std::env::consts::OS,
            });
            if command.json {
                serde_json::to_string_pretty(&status).map_err(|error| error.to_string())
            } else {
                Ok(format!(
                    "Outbound Witness {}\n模式: {}\n遥测: 关闭\nHTTPS 解密: 关闭\n平台: {}",
                    env!("CARGO_PKG_VERSION"),
                    command_mode_label(command.mode),
                    std::env::consts::OS
                ))
            }
        }
        "demo" => render_evaluation(demo_event(), &command),
        "evaluate" => render_evaluation(
            load_event_file(command.input.as_deref().unwrap())?,
            &command,
        ),
        "doctor" => session_runtime::doctor_runtime(command.json),
        "session" => session_runtime::run_session_command(&command),
        "mode" => Ok(format!(
            "当前命令模式: {}",
            command_mode_label(command.mode)
        )),
        other => Err(format!("未知命令: {other}\n\n{}", help_text())),
    }
}

fn command_mode_label(mode: EnforcementMode) -> &'static str {
    match mode {
        EnforcementMode::Observe => "观察 observe",
        EnforcementMode::Strict => "严格 strict",
    }
}

fn render_result(result: &EvaluationResult, mode: EnforcementMode) -> String {
    let decision = match result.decision {
        PolicyDecision::Allow => "ALLOW 放行",
        PolicyDecision::Alert => "ALERT 告警",
        PolicyDecision::Block => "BLOCK 阻断",
    };
    let signals = result
        .signals
        .iter()
        .map(|signal| format!("- [{}] {}", signal.code, signal.explanation))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "Outbound Witness 演示事件\n模式: {}\n决策: {decision}\n风险分数: {}\n说明: {}\n风险信号:\n{}",
        command_mode_label(mode), result.risk_score, result.explanation, signals
    )
}

fn help_text() -> String {
    "用法:\n  outbound-witness status [--mode observe|strict] [--json]\n  outbound-witness demo [--mode observe|strict] [--json] [--export audit.json]\n  outbound-witness evaluate <event-or-benchmark.json> [--mode observe|strict] [--json] [--export audit.json]\n  outbound-witness doctor runtime [--json]\n  outbound-witness session start --workspace . [--mode strict] -- <command> [args...]\n  outbound-witness session status\n  outbound-witness session approve <request-id> --scope once|host|session [--ttl <seconds>]\n  outbound-witness session deny <request-id>\n  outbound-witness session requests [--json]\n  outbound-witness session diff <session-id>\n  outbound-witness session apply <session-id> --path path/to/file\n  outbound-witness session export <session-id> --output audit.json\n\n说明:\n  默认完全本地运行，不上传遥测，不解密 HTTPS，不保存文件正文。\n  evaluate 的风险分不决定 Session 出站。Session 严格模式对未批准的 HTTPS CONNECT 默认等待 120 秒后拒绝。\n  once 只放行这一次请求；host 放行该主机直到 --ttl；session 放行该主机直到会话结束，忽略 --ttl。".into()
}

fn render_evaluation(mut event: WitnessEvent, command: &CliCommand) -> Result<String, String> {
    event.resolve_executable_sha256();
    let result = evaluate_event(&event, &RuleConfig::default(), command.mode);
    let mut ledger = AuditLedger::new();
    ledger.append(&event, &result);
    if let Some(path) = &command.output {
        fs::write(path, ledger.to_json().map_err(|error| error.to_string())?)
            .map_err(|error| format!("无法写入 {path}: {error}"))?;
    }
    if command.json {
        serde_json::to_string_pretty(&result).map_err(|error| error.to_string())
    } else {
        Ok(render_result(&result, command.mode))
    }
}

fn load_event_file(path: &str) -> Result<WitnessEvent, String> {
    let source = fs::read_to_string(path).map_err(|error| format!("无法读取 {path}: {error}"))?;
    let document: serde_json::Value =
        serde_json::from_str(&source).map_err(|error| format!("无效 JSON: {error}"))?;
    let event = document.get("event").cloned().unwrap_or(document);
    serde_json::from_value(event).map_err(|error| format!("事件格式无效: {error}"))
}

fn demo_event() -> WitnessEvent {
    let process = ProcessIdentity {
        pid: 4242,
        executable: "/Applications/ExampleAI.app/Contents/MacOS/example-ai".into(),
        name: "example-ai".into(),
        version: Some("0.1-demo".into()),
        signer: Some("Example AI".into()),
        parent_pid: Some(101),
        parent_name: Some("zsh".into()),
        executable_sha256: None,
    };
    WitnessEvent {
        process,
        network: NetworkEvent {
            destination: Destination {
                host: "upload.example.test".into(),
                ip: Some("203.0.113.10".into()),
                port: 443,
                protocol: "https".into(),
            },
            bytes_sent: 8_000_000,
            timestamp: "2026-09-22T09:00:00Z".into(),
        },
        file_events: vec![
            FileEvent {
                path: "/workspace/.env".into(),
                kind: FileEventKind::Read,
                bytes: 1_024,
                sha256: Some("demo-env-hash".into()),
                timestamp: "2026-09-22T08:59:45Z".into(),
            },
            FileEvent {
                path: "/workspace/.git/objects/pack/pack-demo".into(),
                kind: FileEventKind::Read,
                bytes: 6_000_000,
                sha256: Some("demo-git-hash".into()),
                timestamp: "2026-09-22T08:59:50Z".into(),
            },
        ],
        archive_created: true,
        first_seen_destination: true,
        consent: Some(ConsentGrant {
            executable_sha256: "never-matches-demo".into(),
            process_version: "0.1-demo".into(),
            destination_host: "not-this-host".into(),
            destination_port: Some(443),
            path_prefix: "/workspace".into(),
            expires_at: None,
            scope: "session".into(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_demo_command_and_strict_mode() {
        let command = parse_args(&[
            "outbound-witness".into(),
            "demo".into(),
            "--mode".into(),
            "strict".into(),
        ])
        .expect("command should parse");

        assert_eq!(command.name, "demo");
        assert_eq!(command.mode, EnforcementMode::Strict);
    }

    #[test]
    fn demo_result_reports_block_in_strict_mode() {
        let result = evaluate_demo(EnforcementMode::Strict);

        assert_eq!(result.decision, PolicyDecision::Block);
        assert!(!result.explanation.is_empty());
    }

    #[test]
    fn parses_evaluate_command_with_fixture_path() {
        let command = parse_args(&[
            "outbound-witness".into(),
            "evaluate".into(),
            "fixtures/sensitive-batch-upload.json".into(),
            "--mode".into(),
            "strict".into(),
        ])
        .expect("command should parse");

        assert_eq!(
            command.input.as_deref(),
            Some("fixtures/sensitive-batch-upload.json")
        );
        assert_eq!(command.mode, EnforcementMode::Strict);
    }
}
