use outbound_witness::run;
use outbound_witness::session_runtime::{
    apply_session_diff, collect_session_diff, export_session_audit, load_session_record,
    prepare_session, record_proxy_witnesses,
};
use outbound_witness_core::session::{EnforcementMode, SessionSpec, SessionState};
use outbound_witness_proxy::ProxyRequest;
use std::fs;
use std::path::PathBuf;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_dir(label: &str) -> PathBuf {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("outbound-witness-cli-{label}-{now}"));
    fs::create_dir_all(&path).expect("temp directory should be created");
    path
}

#[test]
fn prepared_session_persists_sanitized_snapshot_and_never_copies_secret() {
    let workspace = temp_dir("workspace");
    let state = temp_dir("state");
    fs::write(workspace.join("main.rs"), "fn main() {}").unwrap();
    fs::write(workspace.join(".env"), "TOKEN=secret").unwrap();

    let mut spec = SessionSpec::new(
        workspace.clone(),
        vec!["example-agent".into()],
        EnforcementMode::Strict,
    );
    spec.state_dir = state.clone();
    let record = prepare_session(spec).expect("session should prepare");
    let record_path = state.join(&record.spec.id).join("session.json");

    assert!(record_path.exists());
    assert!(record
        .prepared
        .as_ref()
        .unwrap()
        .snapshot_dir
        .join("main.rs")
        .exists());
    assert!(!record
        .prepared
        .as_ref()
        .unwrap()
        .snapshot_dir
        .join(".env")
        .exists());
    assert_eq!(
        load_session_record(&state, &record.spec.id)
            .unwrap()
            .spec
            .id,
        record.spec.id
    );
}

#[test]
fn token_command_writes_a_private_credential_file_that_never_enters_the_record() {
    let workspace = temp_dir("cred-workspace");
    let state = temp_dir("cred-state");
    fs::write(workspace.join("main.rs"), "fn main() {}").unwrap();

    let routes_path = state.join("routes.json");
    fs::write(
        &routes_path,
        r#"[{"route":"cloud","upstream_host":"api.example.test","header":"authorization","secret_file":"credentials/cloud","token_command":["sh","-c","printf %s short-lived-token"]}]"#,
    )
    .unwrap();

    let mut spec = SessionSpec::new(
        workspace.clone(),
        vec!["example-agent".into()],
        EnforcementMode::Strict,
    );
    spec.state_dir = state.clone();
    spec.credential_routes_path = Some(routes_path.display().to_string());
    let record = prepare_session(spec).expect("session should prepare");

    let secret_path = state
        .join(&record.spec.id)
        .join("proxy-state")
        .join("credentials")
        .join("cloud");
    assert_eq!(
        fs::read_to_string(&secret_path).unwrap(),
        "short-lived-token"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&secret_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the credential file must not be group or world readable");
    }

    assert_eq!(record.spec.credential_routes.len(), 1);
    assert_eq!(
        record.spec.credential_routes[0].secret_file.as_deref(),
        Some("credentials/cloud")
    );
    let serialized = serde_json::to_string(&record).unwrap();
    assert!(
        !serialized.contains("short-lived-token"),
        "the credential value must never be written into the session record"
    );
}

#[test]
fn a_failing_token_command_aborts_the_session() {
    let workspace = temp_dir("cred-fail-workspace");
    let state = temp_dir("cred-fail-state");
    fs::write(workspace.join("main.rs"), "fn main() {}").unwrap();

    let routes_path = state.join("routes.json");
    fs::write(
        &routes_path,
        r#"[{"route":"cloud","upstream_host":"api.example.test","header":"authorization","secret_file":"credentials/cloud","token_command":["sh","-c","echo boom >&2; exit 3"]}]"#,
    )
    .unwrap();

    let mut spec = SessionSpec::new(
        workspace.clone(),
        vec!["example-agent".into()],
        EnforcementMode::Strict,
    );
    spec.state_dir = state.clone();
    spec.credential_routes_path = Some(routes_path.display().to_string());
    let error = prepare_session(spec).expect_err("a failing token command must abort the session");
    assert!(error.contains("token_command 失败"), "unexpected error: {error}");
    assert!(error.contains("boom"), "the command stderr should be surfaced: {error}");
}

#[test]
fn pre_authorizations_are_seeded_at_start_and_manageable_via_cli() {
    let workspace = temp_dir("preauth-workspace");
    let state = temp_dir("preauth-state");
    fs::write(workspace.join("main.rs"), "fn main() {}").unwrap();

    let mut spec = SessionSpec::new(
        workspace.clone(),
        vec!["example-agent".into()],
        EnforcementMode::Strict,
    );
    spec.state_dir = state.clone();
    spec.pre_authorized_hosts = vec!["api.example.test:443".into()];
    let record = prepare_session(spec).expect("session should prepare");

    let preauth_path = state
        .join(&record.spec.id)
        .join("proxy-state")
        .join("preauth.json");
    let seeded: Vec<serde_json::Value> =
        serde_json::from_str(&fs::read_to_string(&preauth_path).unwrap()).unwrap();
    assert_eq!(seeded.len(), 1);
    assert_eq!(seeded[0]["host"], "api.example.test");
    assert_eq!(seeded[0]["port"], 443);

    let added = run(vec![
        "outbound-witness".into(),
        "session".into(),
        "preauth".into(),
        "add".into(),
        record.spec.id.clone(),
        "--state-dir".into(),
        state.display().to_string(),
        "--host".into(),
        "*.github.com".into(),
        "--port".into(),
        "443".into(),
        "--ttl".into(),
        "60".into(),
    ])
    .expect("preauth add should succeed");
    assert!(added.contains("已预授权"), "unexpected output: {added}");

    let listed = run(vec![
        "outbound-witness".into(),
        "session".into(),
        "preauth".into(),
        "list".into(),
        record.spec.id.clone(),
        "--state-dir".into(),
        state.display().to_string(),
    ])
    .expect("preauth list should succeed");
    assert!(listed.contains("api.example.test:443"));
    assert!(listed.contains("*.github.com:443"));

    let reloaded = load_session_record(&state, &record.spec.id).unwrap();
    assert!(reloaded
        .spec
        .pre_authorized_hosts
        .contains(&"*.github.com:443".to_string()));

    let removed = run(vec![
        "outbound-witness".into(),
        "session".into(),
        "preauth".into(),
        "remove".into(),
        record.spec.id.clone(),
        "--state-dir".into(),
        state.display().to_string(),
        "--host".into(),
        "api.example.test".into(),
        "--port".into(),
        "443".into(),
    ])
    .expect("preauth remove should succeed");
    assert!(removed.contains("已移除"), "unexpected output: {removed}");
}

#[test]
fn collect_apply_and_export_keep_host_unchanged_until_selected_diff_is_applied() {
    let workspace = temp_dir("workspace-diff");
    let state = temp_dir("state-diff");
    fs::write(workspace.join("main.rs"), "before").unwrap();
    let mut spec = SessionSpec::new(
        workspace.clone(),
        vec!["example-agent".into()],
        EnforcementMode::Strict,
    );
    spec.state_dir = state.clone();
    let record = prepare_session(spec).unwrap();
    let snapshot = record.prepared.as_ref().unwrap().snapshot_dir.clone();
    fs::write(snapshot.join("main.rs"), "after").unwrap();
    fs::write(snapshot.join("added.rs"), "new").unwrap();

    let diff = collect_session_diff(&state, &record.spec.id).expect("diff should collect");
    assert_eq!(
        fs::read_to_string(workspace.join("main.rs")).unwrap(),
        "before"
    );
    assert_eq!(diff.entries.len(), 2);
    apply_session_diff(&state, &record.spec.id, &["main.rs".into()]).unwrap();
    assert_eq!(
        fs::read_to_string(workspace.join("main.rs")).unwrap(),
        "after"
    );
    assert!(!workspace.join("added.rs").exists());

    let audit = state.join("audit.html");
    export_session_audit(&state, &record.spec.id, &audit).expect("audit should export");
    let rendered = fs::read_to_string(audit).unwrap();
    assert!(rendered.contains(&record.spec.id));
    assert!(!rendered.contains("TOKEN=secret"));
}

#[test]
fn approve_and_deny_commands_write_local_proxy_control_files() {
    let workspace = temp_dir("workspace-approval");
    let state = temp_dir("state-approval");
    fs::write(workspace.join("main.rs"), "before").unwrap();
    let mut spec = SessionSpec::new(
        workspace,
        vec!["example-agent".into()],
        EnforcementMode::Strict,
    );
    spec.state_dir = state.clone();
    let record = prepare_session(spec).unwrap();
    let proxy_state = state.join(&record.spec.id).join("proxy-state");
    let request = ProxyRequest {
        request_id: "req-approval".into(),
        host: "upload.example.test".into(),
        port: 443,
        created_at_ms: 1_000,
        bytes_sent: 0,
        decision_source: None,
    };
    fs::write(
        proxy_state.join("requests/req-approval.json"),
        serde_json::to_string_pretty(&request).unwrap(),
    )
    .unwrap();

    let approved = run(vec![
        "ow".into(),
        "session".into(),
        "approve".into(),
        "req-approval".into(),
        "--scope".into(),
        "host".into(),
        "--state-dir".into(),
        state.to_string_lossy().into_owned(),
    ])
    .unwrap();
    assert!(approved.contains("已批准"));
    let approvals = fs::read_to_string(proxy_state.join("approvals.json")).unwrap();
    assert!(approvals.contains("upload.example.test"));

    let denied_request = ProxyRequest {
        request_id: "req-deny".into(),
        ..request
    };
    fs::write(
        proxy_state.join("requests/req-deny.json"),
        serde_json::to_string_pretty(&denied_request).unwrap(),
    )
    .unwrap();
    let denied = run(vec![
        "ow".into(),
        "session".into(),
        "deny".into(),
        "req-deny".into(),
        "--state-dir".into(),
        state.to_string_lossy().into_owned(),
    ])
    .unwrap();
    assert!(denied.contains("已拒绝"));
    assert!(fs::read_to_string(proxy_state.join("denials.json"))
        .unwrap()
        .contains("req-deny"));
}

#[test]
fn concurrent_approvals_never_lose_each_other() {
    let workspace = temp_dir("workspace-concurrent-approval");
    let state = temp_dir("state-concurrent-approval");
    fs::write(workspace.join("main.rs"), "before").unwrap();
    let mut spec = SessionSpec::new(
        workspace,
        vec!["example-agent".into()],
        EnforcementMode::Strict,
    );
    spec.state_dir = state.clone();
    let record = prepare_session(spec).unwrap();
    let proxy_state = state.join(&record.spec.id).join("proxy-state");

    let write_request = |request_id: &str, host: &str| {
        let request = ProxyRequest {
            request_id: request_id.into(),
            host: host.into(),
            port: 443,
            created_at_ms: 1_000,
            bytes_sent: 0,
            decision_source: None,
        };
        fs::write(
            proxy_state.join(format!("requests/{request_id}.json")),
            serde_json::to_string_pretty(&request).unwrap(),
        )
        .unwrap();
    };
    write_request("req-concurrent-a", "a.example.test");
    write_request("req-concurrent-b", "b.example.test");

    let state_for_threads = state.to_string_lossy().into_owned();
    let approve = |request_id: &'static str| {
        let state_dir = state_for_threads.clone();
        thread::spawn(move || {
            run(vec![
                "ow".into(),
                "session".into(),
                "approve".into(),
                request_id.into(),
                "--scope".into(),
                "host".into(),
                "--state-dir".into(),
                state_dir,
            ])
            .unwrap()
        })
    };
    let first = approve("req-concurrent-a");
    let second = approve("req-concurrent-b");
    assert!(first.join().unwrap().contains("已批准"));
    assert!(second.join().unwrap().contains("已批准"));

    let approvals =
        fs::read_to_string(proxy_state.join("approvals.json")).unwrap();
    assert!(approvals.contains("a.example.test"), "lost approval a: {approvals}");
    assert!(approvals.contains("b.example.test"), "lost approval b: {approvals}");
    assert!(!state.join("control.lock").exists(), "lock file must be released");
}

#[test]
fn approval_binds_to_session_image_digest_and_proxy_enforces_binding() {
    let workspace = temp_dir("workspace-image-binding");
    let state = temp_dir("state-image-binding");
    fs::write(workspace.join("main.rs"), "before").unwrap();
    let mut spec = SessionSpec::new(
        workspace,
        vec!["example-agent".into()],
        EnforcementMode::Strict,
    );
    spec.state_dir = state.clone();
    spec.image_id = Some("sha256:demo-digest".into());
    let record = prepare_session(spec).unwrap();
    let proxy_state = state.join(&record.spec.id).join("proxy-state");
    let request = ProxyRequest {
        request_id: "req-bound".into(),
        host: "upload.example.test".into(),
        port: 443,
        created_at_ms: 1_000,
        bytes_sent: 0,
        decision_source: None,
    };
    fs::write(
        proxy_state.join("requests/req-bound.json"),
        serde_json::to_string_pretty(&request).unwrap(),
    )
    .unwrap();

    run(vec![
        "ow".into(),
        "session".into(),
        "approve".into(),
        "req-bound".into(),
        "--scope".into(),
        "host".into(),
        "--ttl".into(),
        "300".into(),
        "--state-dir".into(),
        state.to_string_lossy().into_owned(),
    ])
    .unwrap();

    let approvals: Vec<outbound_witness_proxy::ApprovalGrant> =
        serde_json::from_str(&fs::read_to_string(proxy_state.join("approvals.json")).unwrap())
            .unwrap();
    assert_eq!(approvals.len(), 1);
    assert_eq!(approvals[0].image_id.as_deref(), Some("sha256:demo-digest"));
    let expires = approvals[0].expires_at_ms.expect("ttl should set expiry");
    assert!(expires > 1_000);

    let config = outbound_witness_proxy::ProxyConfig {
        mode: outbound_witness_proxy::ProxyMode::Strict,
        approval_timeout_ms: 10_000,
        image_id: Some("sha256:demo-digest".into()),
    };
    assert_eq!(
        outbound_witness_proxy::evaluate_request(&request, &config, &approvals, 5_000),
        outbound_witness_proxy::ProxyDecision::Allow
    );
    let other_config = outbound_witness_proxy::ProxyConfig {
        image_id: Some("sha256:other-digest".into()),
        ..config
    };
    assert_eq!(
        outbound_witness_proxy::evaluate_request(&request, &other_config, &approvals, 5_000),
        outbound_witness_proxy::ProxyDecision::Pending
    );
}

#[test]
fn session_requests_lists_pending_allowed_and_denied_states() {
    let workspace = temp_dir("workspace-requests");
    let state = temp_dir("state-requests");
    fs::write(workspace.join("main.rs"), "before").unwrap();
    let mut spec = SessionSpec::new(
        workspace,
        vec!["example-agent".into()],
        EnforcementMode::Strict,
    );
    spec.state_dir = state.clone();
    let record = prepare_session(spec).unwrap();
    let proxy_state = state.join(&record.spec.id).join("proxy-state");

    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let write_request = |request_id: &str| {
        let request = ProxyRequest {
            request_id: request_id.into(),
            host: "upload.example.test".into(),
            port: 443,
            created_at_ms: now_ms,
            bytes_sent: 0,
            decision_source: None,
        };
        fs::write(
            proxy_state.join(format!("requests/{request_id}.json")),
            serde_json::to_string_pretty(&request).unwrap(),
        )
        .unwrap();
    };
    write_request("req-list-pending");
    write_request("req-list-allowed");
    write_request("req-list-denied");

    // Approve one, deny one, leave one untouched.
    fs::write(
        proxy_state.join("requests/req-list-allowed.json"),
        serde_json::to_string_pretty(&ProxyRequest {
            request_id: "req-list-allowed".into(),
            host: "allowed.example.test".into(),
            port: 443,
            created_at_ms: now_ms,
            bytes_sent: 0,
            decision_source: None,
        })
        .unwrap(),
    )
    .unwrap();
    run(vec![
        "ow".into(),
        "session".into(),
        "approve".into(),
        "req-list-allowed".into(),
        "--scope".into(),
        "once".into(),
        "--state-dir".into(),
        state.to_string_lossy().into_owned(),
    ])
    .unwrap();
    run(vec![
        "ow".into(),
        "session".into(),
        "deny".into(),
        "req-list-denied".into(),
        "--state-dir".into(),
        state.to_string_lossy().into_owned(),
    ])
    .unwrap();

    let listed = run(vec![
        "ow".into(),
        "session".into(),
        "requests".into(),
        "--json".into(),
        "--state-dir".into(),
        state.to_string_lossy().into_owned(),
    ])
    .unwrap();
    let views: Vec<outbound_witness::session_runtime::PendingRequestView> =
        serde_json::from_str(&listed).unwrap();
    assert_eq!(views.len(), 3);
    let decision_of = |request_id: &str| {
        views
            .iter()
            .find(|view| view.request_id == request_id)
            .map(|view| view.decision.as_str())
    };
    assert_eq!(decision_of("req-list-pending"), Some("pending"));
    assert_eq!(decision_of("req-list-allowed"), Some("allowed"));
    assert_eq!(decision_of("req-list-denied"), Some("denied"));
}

#[test]
fn collecting_diff_does_not_mark_a_failed_session_completed() {
    let workspace = temp_dir("workspace-failed-diff");
    let state = temp_dir("state-failed-diff");
    fs::write(workspace.join("main.rs"), "before").unwrap();
    let mut spec = SessionSpec::new(
        workspace,
        vec!["example-agent".into()],
        EnforcementMode::Strict,
    );
    spec.state_dir = state.clone();
    let mut record = prepare_session(spec).unwrap();
    record.state = SessionState::Failed;
    record.error = Some("agent exited 1".into());
    let record_path = state.join(&record.spec.id).join("session.json");
    fs::write(&record_path, serde_json::to_string_pretty(&record).unwrap()).unwrap();

    collect_session_diff(&state, &record.spec.id).unwrap();
    let restored = load_session_record(&state, &record.spec.id).unwrap();
    assert_eq!(restored.state, SessionState::Failed);
    assert_eq!(restored.error.as_deref(), Some("agent exited 1"));
    assert!(restored.diff.is_some());
}

#[test]
fn recorded_proxy_requests_become_audited_witness_events() {
    let workspace = temp_dir("workspace-witness");
    let state = temp_dir("state-witness");
    fs::write(workspace.join("main.rs"), "before").unwrap();
    let mut spec = SessionSpec::new(
        workspace,
        vec!["example-agent".into()],
        EnforcementMode::Strict,
    );
    spec.state_dir = state.clone();
    spec.image_id = Some("sha256:demo".into());
    let record = prepare_session(spec).unwrap();
    let proxy_state = state.join(&record.spec.id).join("proxy-state");
    let write = |id: &str, host: &str, created: u64| {
        let request = ProxyRequest {
            request_id: id.into(),
            host: host.into(),
            port: 443,
            created_at_ms: created,
            bytes_sent: 128,
            decision_source: None,
        };
        fs::write(
            proxy_state.join(format!("requests/{id}.json")),
            serde_json::to_string_pretty(&request).unwrap(),
        )
        .unwrap();
    };
    write("req-first", "upload.example.test", 1_000);
    write("req-second", "upload.example.test", 2_000);

    record_proxy_witnesses(&state, &record.spec.id).unwrap();
    let restored = load_session_record(&state, &record.spec.id).unwrap();
    let witnessed: Vec<_> = restored
        .audit
        .iter()
        .filter(|entry| entry.event.is_some())
        .collect();
    assert_eq!(witnessed.len(), 2);
    let first = witnessed[0].event.as_ref().unwrap();
    assert!(first.first_seen_destination);
    assert!(first.file_events.is_empty());
    assert!(!first.archive_created);
    assert_eq!(first.network.destination.host, "upload.example.test");
    let first_eval = witnessed[0].evaluation.as_ref().unwrap();
    assert!(first_eval.risk_score < 70);
    assert_eq!(
        first_eval.decision,
        outbound_witness_core::PolicyDecision::Block
    );
    assert!(!witnessed[1].event.as_ref().unwrap().first_seen_destination);
    assert_eq!(restored.state, SessionState::Preparing);

    record_proxy_witnesses(&state, &record.spec.id).unwrap();
    let again = load_session_record(&state, &record.spec.id).unwrap();
    assert_eq!(
        again.audit.iter().filter(|entry| entry.event.is_some()).count(),
        2
    );

    collect_session_diff(&state, &record.spec.id).unwrap();
    let after_diff = load_session_record(&state, &record.spec.id).unwrap();
    assert!(after_diff
        .audit
        .iter()
        .filter(|entry| entry.event.is_some())
        .all(|entry| entry.evaluation.is_some()));
    assert!(after_diff.diff.is_some());
}
