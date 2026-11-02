use outbound_witness_core::session::{
    approval_decision, default_exclusions, network_allowed, ApprovalRequest, ApprovalResponse,
    EnforcementMode, NetworkPolicy, SessionDecision, SessionSpec,
};
use outbound_witness_core::workspace::{apply_diff, collect_diff, snapshot_workspace, DiffKind};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_dir(label: &str) -> PathBuf {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("outbound-witness-{label}-{now}"));
    fs::create_dir_all(&path).expect("temp directory should be created");
    path
}

#[test]
fn default_session_excludes_development_secrets_and_history() {
    let exclusions = default_exclusions();
    assert!(exclusions.iter().any(|value| value == ".env"));
    assert!(exclusions.iter().any(|value| value == ".git"));
    assert!(exclusions.iter().any(|value| value == ".ssh"));

    let spec = SessionSpec::new(
        "/workspace".into(),
        vec!["example-agent".into()],
        EnforcementMode::Strict,
    );
    assert!(spec.excluded_paths.contains(&".env".into()));
    assert_eq!(spec.approval_timeout_secs, 120);
}

#[test]
fn strict_network_policy_only_allows_explicit_hosts() {
    let policy = NetworkPolicy::strict(vec!["api.example.test".into()]);
    assert!(network_allowed(&policy, "api.example.test"));
    assert!(!network_allowed(&policy, "upload.example.test"));
}

#[test]
fn approval_request_times_out_to_block_and_allow_response_overrides_timeout() {
    let pending = ApprovalRequest::new("req-1".into(), "upload.example.test".into(), 1_000);
    assert_eq!(pending.timeout_ms, 120_000);
    assert_eq!(
        approval_decision(&pending, 11_001),
        SessionDecision::Pending
    );
    assert_eq!(approval_decision(&pending, 121_001), SessionDecision::Block);

    let allowed = ApprovalRequest {
        response: Some(ApprovalResponse::AllowOnce),
        ..pending
    };
    assert_eq!(approval_decision(&allowed, 11_001), SessionDecision::Allow);
}

#[test]
fn snapshot_excludes_sensitive_files_and_diff_apply_requires_explicit_paths() {
    let source = temp_dir("workspace");
    let snapshot = temp_dir("snapshot");
    fs::write(source.join("README.md"), "before").expect("source file should be written");
    fs::write(source.join(".env"), "SECRET=do-not-copy").expect("secret should be written");
    fs::create_dir_all(source.join(".git")).expect("git directory should be created");
    fs::write(source.join(".git/config"), "private").expect("git file should be written");

    let manifest = snapshot_workspace(&source, &snapshot, &default_exclusions())
        .expect("snapshot should succeed");
    assert!(snapshot.join("README.md").exists());
    assert!(!snapshot.join(".env").exists());
    assert!(!snapshot.join(".git").exists());
    assert_eq!(manifest.files.len(), 1);

    fs::write(snapshot.join("README.md"), "after").expect("snapshot should be mutable");
    fs::write(snapshot.join("new.txt"), "new").expect("new file should be written");
    let diff = collect_diff(&source, &snapshot, &default_exclusions()).expect("diff should work");
    assert!(diff
        .entries
        .iter()
        .any(|entry| entry.relative_path == "README.md" && entry.kind == DiffKind::Modified));
    assert!(diff
        .entries
        .iter()
        .any(|entry| entry.relative_path == "new.txt" && entry.kind == DiffKind::Added));

    apply_diff(&source, &snapshot, &diff, &["README.md".into()])
        .expect("selected diff should apply");
    assert_eq!(
        fs::read_to_string(source.join("README.md")).unwrap(),
        "after"
    );
    assert!(!source.join("new.txt").exists());
}

#[test]
fn apply_refuses_when_host_file_changed_after_diff() {
    let source = temp_dir("conflict-source");
    let snapshot = temp_dir("conflict-snapshot");
    fs::write(source.join("README.md"), "before").expect("source file should be written");
    snapshot_workspace(&source, &snapshot, &default_exclusions()).expect("snapshot should succeed");
    fs::write(snapshot.join("README.md"), "after").expect("snapshot should be mutable");
    let diff = collect_diff(&source, &snapshot, &default_exclusions()).expect("diff should work");

    // The host file moves on after the diff was taken.
    fs::write(source.join("README.md"), "host edit").expect("host file should be writable");

    let error = apply_diff(&source, &snapshot, &diff, &["README.md".into()])
        .expect_err("writeback must refuse to clobber a changed host file");
    assert!(
        error.contains("宿主文件已被修改"),
        "unexpected error message: {error}"
    );
    assert_eq!(
        fs::read_to_string(source.join("README.md")).unwrap(),
        "host edit",
        "the host file must be left untouched when the writeback is refused"
    );
}

#[cfg(unix)]
#[test]
fn apply_refuses_when_selected_path_traverses_symlink() {
    let source = temp_dir("symlink-source");
    let snapshot = temp_dir("symlink-snapshot");
    fs::create_dir_all(source.join("sub")).expect("sub directory should be created");
    fs::write(source.join("sub/file.txt"), "before").expect("source file should be written");
    snapshot_workspace(&source, &snapshot, &default_exclusions()).expect("snapshot should succeed");
    fs::write(snapshot.join("sub/file.txt"), "after").expect("snapshot should be mutable");
    let diff = collect_diff(&source, &snapshot, &default_exclusions()).expect("diff should work");

    // Replace the real directory with a link pointing outside the workspace.
    let outside = temp_dir("symlink-outside");
    fs::remove_dir_all(source.join("sub")).expect("sub directory should be removable");
    std::os::unix::fs::symlink(&outside, source.join("sub")).expect("symlink should be created");

    let error = apply_diff(&source, &snapshot, &diff, &["sub/file.txt".into()])
        .expect_err("writeback must refuse to follow a symlinked parent");
    assert!(
        error.contains("符号链接"),
        "unexpected error message: {error}"
    );
    assert!(
        !outside.join("file.txt").exists(),
        "nothing may be written through the symlink"
    );
}
