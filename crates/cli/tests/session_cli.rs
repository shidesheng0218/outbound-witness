use outbound_witness::parse_args;
use outbound_witness::session_runtime::{build_docker_agent_args, build_proxy_args};
use outbound_witness_core::session::{CredentialRouteSummary, EnforcementMode, SessionSpec};
use std::path::Path;

#[test]
fn parses_session_start_with_workspace_and_command_after_separator() {
    let args = vec![
        "ow".into(),
        "session".into(),
        "start".into(),
        "--workspace".into(),
        ".".into(),
        "--mode".into(),
        "strict".into(),
        "--".into(),
        "example-agent".into(),
        "--task".into(),
        "inspect".into(),
    ];

    let command = parse_args(&args).expect("session start should parse");
    assert_eq!(command.session_subcommand.as_deref(), Some("start"));
    assert_eq!(command.workspace.as_deref(), Some("."));
    assert_eq!(command.mode, EnforcementMode::Strict);
    assert_eq!(command.command, vec!["example-agent", "--task", "inspect"]);
}

#[test]
fn docker_agent_command_has_no_privileged_host_or_docker_socket_escape_hatch() {
    let spec = SessionSpec::new(
        "/tmp/workspace".into(),
        vec!["example-agent".into(), "inspect".into()],
        EnforcementMode::Strict,
    );
    let args = build_docker_agent_args(&spec, Path::new("/tmp/snapshot"), "ow-internal", "proxy");
    assert!(args.windows(2).any(|pair| pair == ["--name", "ow--agent"]));
    assert!(args
        .windows(2)
        .any(|pair| pair == ["--network", "ow-internal"]));
    assert!(args
        .iter()
        .any(|value| value.contains("HTTP_PROXY=http://proxy:3128")));
    assert!(!args.iter().any(|value| value == "--privileged"));
    assert!(!args.iter().any(|value| value == "--network=host"));
    assert!(!args.iter().any(|value| value.contains("docker.sock")));
}

#[test]
fn credentials_reach_the_proxy_container_and_never_the_agent() {
    let mut spec = SessionSpec::new(
        "/tmp/workspace".into(),
        vec!["example-agent".into()],
        EnforcementMode::Strict,
    );
    spec.id = "session-test".into();
    spec.credential_routes = vec![CredentialRouteSummary {
        route: "anthropic".into(),
        upstream_host: "api.anthropic.com".into(),
        upstream_port: 443,
        secret_env: "ANTHROPIC_API_KEY".into(),
    }];

    let agent = build_docker_agent_args(&spec, Path::new("/tmp/snapshot"), "ow-internal", "proxy");
    assert!(
        agent
            .iter()
            .any(|value| value.contains("OW_BROKER_ANTHROPIC_BASE_URL=http://proxy:8080/anthropic")),
        "the agent should learn the broker URL"
    );
    assert!(
        !agent.iter().any(|value| value.contains("ANTHROPIC_API_KEY")),
        "the agent container must never receive the credential variable"
    );

    let proxy = build_proxy_args("ow-proxy", "ow-internal", Path::new("/tmp/state"), &spec);
    assert!(
        proxy
            .windows(2)
            .any(|pair| pair == ["-e", "ANTHROPIC_API_KEY"]),
        "the proxy container is the only place the credential variable is passed"
    );
    assert!(proxy
        .iter()
        .any(|value| value.contains("OW_PROXY_BROKER_LISTEN=0.0.0.0:8080")));
}
