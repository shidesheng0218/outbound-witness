use outbound_witness_core::{evaluate_event, EnforcementMode, RuleConfig};
use serde::Serialize;
use tauri::Emitter;

#[derive(Debug, Serialize)]
struct DemoResponse {
    risk_score: u8,
    decision: String,
    explanation: String,
    signals: Vec<SignalResponse>,
}

#[derive(Debug, Serialize)]
struct SignalResponse {
    code: String,
    explanation: String,
}

#[tauri::command]
fn evaluate_demo(mode: String) -> DemoResponse {
    let mode = if mode == "strict" {
        EnforcementMode::Strict
    } else {
        EnforcementMode::Observe
    };
    let mut event = demo_fixture::demo_event_for_desktop();
    event.resolve_executable_sha256();
    let result = evaluate_event(&event, &RuleConfig::default(), mode);
    DemoResponse {
        risk_score: result.risk_score,
        decision: format!("{:?}", result.decision),
        explanation: result.explanation,
        signals: result
            .signals
            .into_iter()
            .map(|signal| SignalResponse {
                code: signal.code,
                explanation: signal.explanation,
            })
            .collect(),
    }
}

#[tauri::command]
fn cli(command: Vec<String>) -> Result<String, String> {
    let mut args = vec!["ow".to_string()];
    args.extend(command);
    outbound_witness::run(args)
}

#[tauri::command]
fn session_status() -> Result<String, String> {
    outbound_witness::run(vec![
        "ow".into(),
        "session".into(),
        "status".into(),
        "--json".into(),
    ])
}

#[derive(Debug, Serialize, Clone)]
struct SessionFinishedPayload {
    session_id: Option<String>,
    success: bool,
    output: String,
}

/// Starts a controlled session on a background thread and returns
/// immediately. The frontend polls `session_status` / `session requests`
/// while it runs, and we emit a `session-finished` event with the CLI output
/// when the agent container exits.
#[tauri::command]
fn session_start(
    app: tauri::AppHandle,
    workspace: String,
    image: String,
    mode: String,
    command: Vec<String>,
) -> Result<String, String> {
    let mut args = vec![
        "ow".into(),
        "session".into(),
        "start".into(),
        "--workspace".into(),
        workspace,
        "--mode".into(),
        mode,
        "--image".into(),
        image,
        "--".into(),
    ];
    args.extend(command);
    std::thread::spawn(move || {
        let result = outbound_witness::run(args);
        let (success, output) = match &result {
            Ok(output) => (true, output.clone()),
            Err(error) => (false, error.clone()),
        };
        // `ow session start` prints "Session <id>" on its first output line.
        let session_id = output
            .lines()
            .next()
            .and_then(|line| line.strip_prefix("Session "))
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        let _ = app.emit(
            "session-finished",
            SessionFinishedPayload {
                session_id,
                success,
                output,
            },
        );
    });
    Ok("已在后台启动，正在准备隔离快照……".into())
}

#[tauri::command]
fn session_apply(session_id: String, paths: Vec<String>) -> Result<String, String> {
    let mut command = vec!["ow".into(), "session".into(), "apply".into(), session_id];
    for path in paths {
        command.push("--path".into());
        command.push(path);
    }
    outbound_witness::run(command)
}

#[tauri::command]
fn session_export(session_id: String, output: String) -> Result<String, String> {
    outbound_witness::run(vec![
        "ow".into(),
        "session".into(),
        "export".into(),
        session_id,
        "--output".into(),
        output,
    ])
}

mod demo_fixture {
    use outbound_witness_core::{
        ConsentGrant, Destination, FileEvent, FileEventKind, NetworkEvent, ProcessIdentity,
        WitnessEvent,
    };

    pub fn demo_event_for_desktop() -> WitnessEvent {
        WitnessEvent {
            process: ProcessIdentity {
                pid: 4242,
                executable: "/Applications/ExampleAI.app/Contents/MacOS/example-ai".into(),
                name: "example-ai".into(),
                version: Some("0.1-demo".into()),
                signer: Some("Example AI".into()),
                parent_pid: Some(101),
                parent_name: Some("zsh".into()),
                executable_sha256: None,
            },
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
                    path: "/workspace/.git/objects/pack/demo".into(),
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
}

fn main() {
    run()
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            evaluate_demo,
            cli,
            session_status,
            session_start,
            session_apply,
            session_export
        ])
        .run(tauri::generate_context!())
        .expect("error while running outbound-witness desktop");
}
