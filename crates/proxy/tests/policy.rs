use outbound_witness_proxy::{
    evaluate_request, evaluate_request_detailed, evaluate_request_with_denials, next_request_id,
    parse_connect_target, write_json, ApprovalGrant, ApprovalScope, DecisionSource,
    DeniedRequest, PreAuthorization, ProxyConfig, ProxyDecision, ProxyMode, ProxyRequest,
};
use std::collections::HashSet;

#[test]
fn parses_https_connect_target_without_decrypting_payload() {
    assert_eq!(
        parse_connect_target("CONNECT api.example.test:443 HTTP/1.1\r\n").unwrap(),
        ("api.example.test".into(), 443)
    );
}

#[test]
fn strict_proxy_pauses_unknown_host_then_blocks_on_timeout() {
    let request = ProxyRequest {
        request_id: "req-1".into(),
        host: "upload.example.test".into(),
        port: 443,
        created_at_ms: 1_000,
        bytes_sent: 0,
        decision_source: None,
    };
    let config = ProxyConfig {
        mode: ProxyMode::Strict,
        approval_timeout_ms: 10_000,
        image_id: None,
    };
    assert_eq!(
        evaluate_request(&request, &config, &[], 5_000),
        ProxyDecision::Pending
    );
    assert_eq!(
        evaluate_request(&request, &config, &[], 11_000),
        ProxyDecision::Block
    );
}

#[test]
fn approval_grant_allows_only_matching_request_or_host() {
    let request = ProxyRequest {
        request_id: "req-1".into(),
        host: "upload.example.test".into(),
        port: 443,
        created_at_ms: 1_000,
        bytes_sent: 0,
        decision_source: None,
    };
    let config = ProxyConfig {
        mode: ProxyMode::Strict,
        approval_timeout_ms: 10_000,
        image_id: None,
    };
    let grant = ApprovalGrant {
        request_id: Some("req-1".into()),
        host: "upload.example.test".into(),
        port: Some(443),
        scope: ApprovalScope::Once,
        expires_at_ms: Some(20_000),
        image_id: None,
    };
    assert_eq!(
        evaluate_request(&request, &config, &[grant], 5_000),
        ProxyDecision::Allow
    );
}

#[test]
fn explicit_denial_blocks_before_approval_is_considered() {
    let request = ProxyRequest {
        request_id: "req-1".into(),
        host: "upload.example.test".into(),
        port: 443,
        created_at_ms: 1_000,
        bytes_sent: 0,
        decision_source: None,
    };
    let config = ProxyConfig {
        mode: ProxyMode::Strict,
        approval_timeout_ms: 10_000,
        image_id: None,
    };
    let approval = ApprovalGrant {
        request_id: Some("req-1".into()),
        host: "upload.example.test".into(),
        port: Some(443),
        scope: ApprovalScope::Once,
        expires_at_ms: Some(20_000),
        image_id: None,
    };
    let denial = DeniedRequest {
        request_id: Some("req-1".into()),
        host: "upload.example.test".into(),
        port: Some(443),
    };
    assert_eq!(
        evaluate_request_with_denials(&request, &config, &[approval], &[denial], 5_000),
        ProxyDecision::Block
    );
}

#[test]
fn request_ids_are_unique_even_within_the_same_millisecond() {
    let ids = (0..200)
        .map(|_| next_request_id(1_000))
        .collect::<HashSet<_>>();
    assert_eq!(ids.len(), 200, "request ids must never collide");
    assert!(ids.iter().all(|id| id.starts_with("req-1000-")));
}

#[test]
fn write_json_leaves_no_temp_files_and_round_trips() {
    let dir = std::env::temp_dir().join(format!(
        "ow-proxy-write-json-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("approvals.json");
    let grant = ApprovalGrant {
        request_id: Some("req-1".into()),
        host: "upload.example.test".into(),
        port: Some(443),
        scope: ApprovalScope::Host,
        expires_at_ms: None,
        image_id: None,
    };
    write_json(&path, &vec![grant.clone()]).unwrap();
    let restored: Vec<ApprovalGrant> =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(restored, vec![grant]);
    let leftovers = std::fs::read_dir(&dir)
        .unwrap()
        .filter(|entry| {
            entry
                .as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".tmp-")
        })
        .count();
    assert_eq!(leftovers, 0, "atomic write must not leave temp files behind");
    let _ = std::fs::remove_dir_all(&dir);
}

fn bound_grant(image_id: Option<&str>) -> ApprovalGrant {
    ApprovalGrant {
        request_id: None,
        host: "upload.example.test".into(),
        // Legacy wildcard: grants written before port binding keep matching
        // every port on the host, which is what the image-binding tests want.
        port: None,
        scope: ApprovalScope::Host,
        expires_at_ms: None,
        image_id: image_id.map(str::to_string),
    }
}

fn bound_config(image_id: Option<&str>) -> ProxyConfig {
    ProxyConfig {
        mode: ProxyMode::Strict,
        approval_timeout_ms: 10_000,
        image_id: image_id.map(str::to_string),
    }
}

#[test]
fn grant_applies_only_when_image_binding_matches() {
    let request = ProxyRequest {
        request_id: "req-1".into(),
        host: "upload.example.test".into(),
        port: 443,
        created_at_ms: 1_000,
        bytes_sent: 0,
        decision_source: None,
    };
    assert_eq!(
        evaluate_request(
            &request,
            &bound_config(Some("sha256:aaa")),
            &[bound_grant(Some("sha256:aaa"))],
            5_000
        ),
        ProxyDecision::Allow
    );
    assert_eq!(
        evaluate_request(
            &request,
            &bound_config(Some("sha256:bbb")),
            &[bound_grant(Some("sha256:aaa"))],
            5_000
        ),
        ProxyDecision::Pending
    );
}

#[test]
fn image_binding_fails_closed_on_missing_identity_on_either_side() {
    let request = ProxyRequest {
        request_id: "req-1".into(),
        host: "upload.example.test".into(),
        port: 443,
        created_at_ms: 1_000,
        bytes_sent: 0,
        decision_source: None,
    };
    // Proxy enforces a binding but the grant carries none (legacy grant):
    // rejected even though host matches.
    assert_eq!(
        evaluate_request(
            &request,
            &bound_config(Some("sha256:aaa")),
            &[bound_grant(None)],
            5_000
        ),
        ProxyDecision::Pending
    );
    // Grant asserts an identity but the proxy has no binding context:
    // rejected as well.
    assert_eq!(
        evaluate_request(
            &request,
            &bound_config(None),
            &[bound_grant(Some("sha256:aaa"))],
            5_000
        ),
        ProxyDecision::Pending
    );
}

#[test]
fn host_scope_expires_but_session_scope_lasts_without_ttl() {
    let request = ProxyRequest {
        request_id: "req-2".into(),
        host: "upload.example.test".into(),
        port: 443,
        created_at_ms: 1_000,
        bytes_sent: 0,
        decision_source: None,
    };
    let config = ProxyConfig {
        mode: ProxyMode::Strict,
        approval_timeout_ms: 10_000,
        image_id: None,
    };
    let host_grant = ApprovalGrant {
        request_id: None,
        host: "upload.example.test".into(),
        port: Some(443),
        scope: ApprovalScope::Host,
        expires_at_ms: Some(5_000),
        image_id: None,
    };
    assert_eq!(
        evaluate_request(&request, &config, &[host_grant], 4_000),
        ProxyDecision::Allow
    );
    assert_eq!(
        evaluate_request(
            &request,
            &config,
            &[ApprovalGrant {
                request_id: None,
                host: "upload.example.test".into(),
                port: Some(443),
                scope: ApprovalScope::Host,
                expires_at_ms: Some(5_000),
                image_id: None,
            }],
            6_000
        ),
        ProxyDecision::Pending
    );
    let session_grant = ApprovalGrant {
        request_id: None,
        host: "upload.example.test".into(),
        port: Some(443),
        scope: ApprovalScope::Session,
        expires_at_ms: Some(5_000),
        image_id: None,
    };
    assert_eq!(
        evaluate_request(&request, &config, &[session_grant], 60_000),
        ProxyDecision::Allow
    );
}

fn strict_config() -> ProxyConfig {
    ProxyConfig {
        mode: ProxyMode::Strict,
        approval_timeout_ms: 10_000,
        image_id: None,
    }
}

fn request_on_port(port: u16) -> ProxyRequest {
    ProxyRequest {
        request_id: "req-1".into(),
        host: "upload.example.test".into(),
        port,
        created_at_ms: 1_000,
        bytes_sent: 0,
        decision_source: None,
    }
}

#[test]
fn grant_bound_to_port_does_not_cover_other_ports_on_same_host() {
    let grant = ApprovalGrant {
        request_id: None,
        host: "upload.example.test".into(),
        port: Some(443),
        scope: ApprovalScope::Session,
        expires_at_ms: None,
        image_id: None,
    };
    assert_eq!(
        evaluate_request(&request_on_port(443), &strict_config(), std::slice::from_ref(&grant), 5_000),
        ProxyDecision::Allow
    );
    assert_eq!(
        evaluate_request(&request_on_port(8443), &strict_config(), &[grant], 5_000),
        ProxyDecision::Pending,
        "a grant for 443 must not silently cover another port on the same host"
    );
}

#[test]
fn legacy_grant_without_port_keeps_wildcard_behaviour() {
    let grant = ApprovalGrant {
        request_id: None,
        host: "upload.example.test".into(),
        port: None,
        scope: ApprovalScope::Session,
        expires_at_ms: None,
        image_id: None,
    };
    assert_eq!(
        evaluate_request(&request_on_port(8443), &strict_config(), &[grant], 5_000),
        ProxyDecision::Allow
    );
}

#[test]
fn denial_bound_to_port_does_not_block_other_ports() {
    let denial = DeniedRequest {
        request_id: None,
        host: "upload.example.test".into(),
        port: Some(443),
    };
    assert_eq!(
        evaluate_request_with_denials(
            &request_on_port(443),
            &strict_config(),
            &[],
            std::slice::from_ref(&denial),
            5_000
        ),
        ProxyDecision::Block
    );
    assert_eq!(
        evaluate_request_with_denials(
            &request_on_port(8443),
            &strict_config(),
            &[],
            &[denial],
            5_000
        ),
        ProxyDecision::Pending,
        "a denial for 443 must not block another port on the same host"
    );
}

fn request_for(host: &str, port: u16) -> ProxyRequest {
    ProxyRequest {
        request_id: "req-1".into(),
        host: host.into(),
        port,
        created_at_ms: 1_000,
        bytes_sent: 0,
        decision_source: None,
    }
}

fn rule(host: &str, port: u16, expires_at_ms: Option<u64>) -> PreAuthorization {
    PreAuthorization {
        host: host.into(),
        port,
        expires_at_ms,
        note: None,
    }
}

#[test]
fn pre_authorization_allows_matching_host_and_port_without_pausing() {
    let evaluation = evaluate_request_detailed(
        &request_for("api.example.test", 443),
        &strict_config(),
        &[],
        &[],
        &[rule("api.example.test", 443, None)],
        5_000,
    );
    assert_eq!(evaluation.decision, ProxyDecision::Allow);
    assert_eq!(
        evaluation.source,
        DecisionSource::PreAuthorized,
        "a policy allow must be distinguishable from a human approval"
    );
}

#[test]
fn pre_authorization_is_port_bound_and_expires() {
    let expired = rule("api.example.test", 443, Some(4_000));
    assert_eq!(
        evaluate_request_detailed(
            &request_for("api.example.test", 8443),
            &strict_config(),
            &[],
            &[],
            std::slice::from_ref(&expired),
            1_000,
        )
        .decision,
        ProxyDecision::Pending,
        "a rule for 443 must not cover another port"
    );
    assert_eq!(
        evaluate_request_detailed(
            &request_for("api.example.test", 443),
            &strict_config(),
            &[],
            &[],
            &[expired],
            5_000,
        )
        .decision,
        ProxyDecision::Pending,
        "an expired rule must stop applying"
    );
}

#[test]
fn wildcard_pre_authorization_covers_subdomains_and_bare_suffix_only() {
    let wildcard = rule("*.example.test", 443, None);
    let decision = |host: &str| {
        evaluate_request_detailed(
            &request_for(host, 443),
            &strict_config(),
            &[],
            &[],
            std::slice::from_ref(&wildcard),
            5_000,
        )
        .decision
    };
    assert_eq!(decision("api.example.test"), ProxyDecision::Allow);
    assert_eq!(decision("example.test"), ProxyDecision::Allow);
    assert_eq!(decision("evil-example.test"), ProxyDecision::Pending);
    assert_eq!(decision("example.test.evil.com"), ProxyDecision::Pending);
}

#[test]
fn explicit_denial_overrides_pre_authorization() {
    let denial = DeniedRequest {
        request_id: None,
        host: "api.example.test".into(),
        port: Some(443),
    };
    let evaluation = evaluate_request_detailed(
        &request_for("api.example.test", 443),
        &strict_config(),
        &[],
        &[denial],
        &[rule("api.example.test", 443, None)],
        5_000,
    );
    assert_eq!(evaluation.decision, ProxyDecision::Block);
    assert_eq!(evaluation.source, DecisionSource::Denied);
}

#[test]
fn manual_approval_is_reported_with_its_own_source() {
    let grant = ApprovalGrant {
        request_id: None,
        host: "api.example.test".into(),
        port: Some(443),
        scope: ApprovalScope::Session,
        expires_at_ms: None,
        image_id: None,
    };
    let evaluation = evaluate_request_detailed(
        &request_for("api.example.test", 443),
        &strict_config(),
        &[grant],
        &[],
        &[],
        5_000,
    );
    assert_eq!(evaluation.decision, ProxyDecision::Allow);
    assert_eq!(evaluation.source, DecisionSource::ManualApproval);
}

#[test]
fn grants_and_denials_without_port_field_deserialize_as_wildcard() {
    let grant: ApprovalGrant = serde_json::from_str(
        r#"{"request_id":null,"host":"upload.example.test","scope":"Session","expires_at_ms":null,"image_id":null}"#,
    )
    .expect("grants written before port binding must still deserialize");
    assert_eq!(grant.port, None);

    let denial: DeniedRequest = serde_json::from_str(
        r#"{"request_id":null,"host":"upload.example.test"}"#,
    )
    .expect("denials written before port binding must still deserialize");
    assert_eq!(denial.port, None);
}
