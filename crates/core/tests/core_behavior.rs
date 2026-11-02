use outbound_witness_core::{
    evaluate_event, AuditLedger, ConsentGrant, Destination, EnforcementMode, FileEvent,
    FileEventKind, NetworkEvent, PolicyDecision, ProcessIdentity, RuleConfig, WitnessEvent,
};

fn process() -> ProcessIdentity {
    ProcessIdentity {
        pid: 42,
        executable: "/Applications/Example.app/Contents/MacOS/example".into(),
        name: "example".into(),
        version: Some("1.2.3".into()),
        signer: Some("Example Inc.".into()),
        parent_pid: Some(7),
        parent_name: Some("shell".into()),
        executable_sha256: Some("demo-binary-content-hash".into()),
    }
}

fn upload_event() -> WitnessEvent {
    WitnessEvent {
        process: process(),
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
                sha256: Some("abc123".into()),
                timestamp: "2026-09-22T08:59:45Z".into(),
            },
            FileEvent {
                path: "/workspace/src/main.rs".into(),
                kind: FileEventKind::Read,
                bytes: 2_048,
                sha256: Some("def456".into()),
                timestamp: "2026-09-22T08:59:50Z".into(),
            },
        ],
        archive_created: true,
        first_seen_destination: true,
        consent: None,
    }
}

#[test]
fn sensitive_file_batch_and_archive_produce_explainable_high_risk() {
    let result = evaluate_event(
        &upload_event(),
        &RuleConfig::default(),
        EnforcementMode::Observe,
    );

    assert_eq!(result.decision, PolicyDecision::Alert);
    assert!(result.risk_score >= 80);
    assert!(result.signals.iter().any(|s| s.code == "sensitive_path"));
    assert!(result
        .signals
        .iter()
        .any(|s| s.code == "archive_before_upload"));
    assert!(result.explanation.contains(".env"));
}

#[test]
fn strict_mode_blocks_high_risk_external_upload() {
    let result = evaluate_event(
        &upload_event(),
        &RuleConfig::default(),
        EnforcementMode::Strict,
    );

    assert_eq!(result.decision, PolicyDecision::Block);
}

#[test]
fn valid_consent_allows_matching_process_destination_and_scope() {
    let mut event = upload_event();
    event.file_events = vec![FileEvent {
        path: "/workspace/src/main.rs".into(),
        kind: FileEventKind::Read,
        bytes: 2_048,
        sha256: None,
        timestamp: "2026-09-22T08:59:50Z".into(),
    }];
    event.archive_created = false;
    event.first_seen_destination = false;
    event.consent = Some(outbound_witness_core::ConsentGrant {
        executable_sha256: "demo-binary-content-hash".into(),
        process_version: "1.2.3".into(),
        destination_host: "upload.example.test".into(),
        destination_port: Some(443),
        path_prefix: "/workspace".into(),
        expires_at: Some("2026-09-23T09:00:00Z".into()),
        scope: "session".into(),
    });

    let result = evaluate_event(&event, &RuleConfig::default(), EnforcementMode::Strict);

    assert_eq!(result.decision, PolicyDecision::Allow);
    assert!(result.consent_applied);
}

#[test]
fn consent_never_applies_without_attested_executable_content_hash() {
    let mut event = upload_event();
    event.process.executable_sha256 = None;
    event.consent = Some(outbound_witness_core::ConsentGrant {
        executable_sha256: "demo-binary-content-hash".into(),
        process_version: "1.2.3".into(),
        destination_host: "upload.example.test".into(),
        destination_port: Some(443),
        path_prefix: "/workspace".into(),
        expires_at: Some("2026-09-23T09:00:00Z".into()),
        scope: "session".into(),
    });

    let result = evaluate_event(&event, &RuleConfig::default(), EnforcementMode::Strict);

    assert_eq!(result.decision, PolicyDecision::Block);
    assert!(!result.consent_applied);
}

#[test]
fn compute_executable_sha256_hashes_file_contents_and_fails_closed_on_missing_file() {
    let mut identity = process();
    identity.executable = String::new();
    assert_eq!(identity.compute_executable_sha256(), None);

    let temp = std::env::temp_dir().join(format!("ow-binary-{}", std::process::id()));
    std::fs::write(&temp, b"fake-binary-contents").unwrap();
    identity.executable = temp.to_string_lossy().into_owned();
    let hash = identity
        .compute_executable_sha256()
        .expect("hash should compute");
    assert_eq!(
        hash,
        outbound_witness_core::sha256_hex(b"fake-binary-contents"),
        "must hash file contents, never the path string"
    );
    let _ = std::fs::remove_file(&temp);
}

#[test]
fn resolve_executable_sha256_populates_only_when_missing() {
    let mut event = upload_event();
    event.process.executable_sha256 = None;
    event.resolve_executable_sha256();
    assert_eq!(event.process.executable_sha256, None);

    let temp = std::env::temp_dir().join(format!("ow-resolve-{}", std::process::id()));
    std::fs::write(&temp, b"resolved-binary").unwrap();
    event.process.executable = temp.to_string_lossy().into_owned();
    event.resolve_executable_sha256();
    assert_eq!(
        event.process.executable_sha256,
        Some(outbound_witness_core::sha256_hex(b"resolved-binary"))
    );
    let _ = std::fs::remove_file(&temp);
}

#[test]
fn unparseable_consent_expiry_does_not_match() {
    let mut event = upload_event();
    event.file_events.clear();
    event.archive_created = false;
    event.first_seen_destination = false;
    event.consent = Some(ConsentGrant {
        executable_sha256: "demo-binary-content-hash".into(),
        process_version: "1.2.3".into(),
        destination_host: "upload.example.test".into(),
        destination_port: Some(443),
        path_prefix: "/workspace".into(),
        expires_at: Some("next week".into()),
        scope: "session".into(),
    });
    let result = evaluate_event(&event, &RuleConfig::default(), EnforcementMode::Strict);
    assert!(!result.consent_applied);
}

#[test]
fn process_version_change_invalidates_existing_consent() {
    let mut event = upload_event();
    event.consent = Some(outbound_witness_core::ConsentGrant {
        executable_sha256: "demo-binary-content-hash".into(),
        process_version: "1.2.2".into(),
        destination_host: "upload.example.test".into(),
        destination_port: Some(443),
        path_prefix: "/workspace".into(),
        expires_at: Some("2026-09-23T09:00:00Z".into()),
        scope: "always".into(),
    });

    let result = evaluate_event(&event, &RuleConfig::default(), EnforcementMode::Strict);

    assert_eq!(result.decision, PolicyDecision::Block);
    assert!(!result.consent_applied);
}

#[test]
fn benchmark_fixtures_match_their_expected_decisions() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for file in [
        "benign-git-push.json",
        "sensitive-batch-upload.json",
        "archive-upload-with-consent.json",
    ] {
        let source =
            std::fs::read_to_string(root.join("fixtures").join(file)).expect("fixture should read");
        let document: serde_json::Value =
            serde_json::from_str(&source).expect("fixture should parse");
        let mut event: WitnessEvent =
            serde_json::from_value(document["event"].clone()).expect("event should parse");
        if !std::path::Path::new(&event.process.executable).is_absolute() {
            event.process.executable = root
                .join(&event.process.executable)
                .to_string_lossy()
                .into_owned();
        }
        event.resolve_executable_sha256();
        for (mode, key) in [
            (EnforcementMode::Observe, "observe"),
            (EnforcementMode::Strict, "strict"),
        ] {
            let Some(expected) = document["expected"][key].as_str() else {
                continue;
            };
            let result = evaluate_event(&event, &RuleConfig::default(), mode);
            assert_eq!(
                format!("{:?}", result.decision),
                expected,
                "{file} {key} decision mismatch"
            );
        }
    }
}

#[test]
fn audit_ledger_exports_events_without_file_contents_and_with_chain_hashes() {
    let mut ledger = AuditLedger::new();
    let result = evaluate_event(
        &upload_event(),
        &RuleConfig::default(),
        EnforcementMode::Observe,
    );
    ledger.append(&upload_event(), &result);

    let json = ledger.to_json().expect("ledger should serialize");

    assert!(json.contains("upload.example.test"));
    assert!(json.contains("abc123"));
    assert!(!json.contains("file_contents"));
    assert!(json.contains("chain_hash"));
}

#[test]
fn audit_ledger_chain_verification_detects_tampering() {
    let mut ledger = AuditLedger::new();
    let result = evaluate_event(
        &upload_event(),
        &RuleConfig::default(),
        EnforcementMode::Observe,
    );
    ledger.append(&upload_event(), &result);
    ledger.verify_chain().expect("fresh ledger must verify");

    ledger.records[0].evaluation.risk_score = 0;
    assert!(
        ledger.verify_chain().is_err(),
        "editing a record after append must break the chain"
    );
}

#[test]
fn consent_accepts_fractional_seconds_and_timezone_offsets() {
    let mut event = upload_event();
    event.file_events.clear();
    event.archive_created = false;
    event.first_seen_destination = false;
    event.consent = Some(ConsentGrant {
        executable_sha256: "demo-binary-content-hash".into(),
        process_version: "1.2.3".into(),
        destination_host: "upload.example.test".into(),
        destination_port: Some(443),
        path_prefix: "/workspace".into(),
        expires_at: Some("2026-09-23T17:00:00.500+08:00".into()),
        scope: "session".into(),
    });
    let result = evaluate_event(&event, &RuleConfig::default(), EnforcementMode::Strict);
    assert!(result.consent_applied);

    event.consent.as_mut().unwrap().expires_at = Some("2026-09-21T09:00:00+08:00".into());
    let expired = evaluate_event(&event, &RuleConfig::default(), EnforcementMode::Strict);
    assert!(!expired.consent_applied);
}

#[test]
fn platform_adapter_reports_capabilities_without_claiming_kernel_access() {
    let capabilities = outbound_witness_core::platform::current_capabilities();

    assert!(!capabilities.os.is_empty());
    assert!(capabilities.network_adapter.contains("adapter"));
    assert!(capabilities.file_adapter.contains("adapter"));
    assert!(!capabilities.kernel_enforcement_claimed);
}

#[test]
fn consent_bound_to_port_does_not_authorise_other_ports() {
    let mut event = upload_event();
    event.file_events.clear();
    event.archive_created = false;
    event.first_seen_destination = false;
    event.consent = Some(ConsentGrant {
        executable_sha256: "demo-binary-content-hash".into(),
        process_version: "1.2.3".into(),
        destination_host: "upload.example.test".into(),
        destination_port: Some(8443),
        path_prefix: "/workspace".into(),
        expires_at: Some("2026-09-23T09:00:00Z".into()),
        scope: "session".into(),
    });

    let result = evaluate_event(&event, &RuleConfig::default(), EnforcementMode::Strict);

    assert!(
        !result.consent_applied,
        "a grant for 8443 must not authorise the 443 event"
    );
}

#[test]
fn legacy_consent_without_port_keeps_wildcard_behaviour() {
    let mut event = upload_event();
    event.file_events.clear();
    event.archive_created = false;
    event.first_seen_destination = false;
    event.consent = Some(ConsentGrant {
        executable_sha256: "demo-binary-content-hash".into(),
        process_version: "1.2.3".into(),
        destination_host: "upload.example.test".into(),
        destination_port: None,
        path_prefix: "/workspace".into(),
        expires_at: Some("2026-09-23T09:00:00Z".into()),
        scope: "session".into(),
    });

    let result = evaluate_event(&event, &RuleConfig::default(), EnforcementMode::Strict);

    assert!(result.consent_applied);
}
