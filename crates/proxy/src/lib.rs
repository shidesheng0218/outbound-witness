pub mod broker;

use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Hard ceiling on concurrent proxy/broker connections. The agent is
/// untrusted; without this it can exhaust proxy threads and host memory by
/// opening connections and never finishing the request.
const MAX_CONNECTIONS: usize = 256;
/// Hard ceiling on request records written for one session. Request files are
/// evidence, so they are not deleted while the session lives; the cap keeps a
/// hostile agent from filling the disk.
const MAX_REQUEST_FILES: usize = 5_000;
/// Upper bound on reading a request or response header block, and on the
/// whole header read (not just each individual read).
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_PROXY_HEADER_BYTES: usize = 16 * 1024;

static ACTIVE_CONNECTIONS: AtomicUsize = AtomicUsize::new(0);
static REQUEST_FILES: AtomicUsize = AtomicUsize::new(0);

/// RAII guard for one proxy connection slot. Dropping it always releases the
/// slot, including on error paths.
struct ConnectionGuard;

impl ConnectionGuard {
    fn acquire() -> Option<Self> {
        loop {
            let current = ACTIVE_CONNECTIONS.load(Ordering::Relaxed);
            if current >= MAX_CONNECTIONS {
                return None;
            }
            if ACTIVE_CONNECTIONS
                .compare_exchange_weak(current, current + 1, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                return Some(Self);
            }
        }
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        ACTIVE_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Reserves a slot for one new request file. Returns false once the session's
/// evidence budget is exhausted.
fn reserve_request_file() -> bool {
    let current = REQUEST_FILES.fetch_add(1, Ordering::Relaxed);
    if current >= MAX_REQUEST_FILES {
        REQUEST_FILES.fetch_sub(1, Ordering::Relaxed);
        false
    } else {
        true
    }
}

/// Seeds the request-file counter from records already present on disk. Called
/// once when the proxy starts so a restart cannot bypass the budget.
pub fn seed_request_file_count(state_dir: &Path) {
    let count = fs::read_dir(state_dir.join("requests"))
        .map(|entries| {
            entries
                .flatten()
                .filter(|entry| {
                    entry.path().extension().and_then(|value| value.to_str()) == Some("json")
                })
                .count()
        })
        .unwrap_or(0);
    REQUEST_FILES.store(count, Ordering::Relaxed);
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProxyMode {
    Observe,
    Strict,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProxyDecision {
    Allow,
    Pending,
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ApprovalScope {
    Once,
    Host,
    Session,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApprovalGrant {
    pub request_id: Option<String>,
    pub host: String,
    /// Port the grant is bound to. Grants written before port binding existed
    /// deserialize as `None`, which keeps the historical wildcard behaviour
    /// (every port on `host`); the CLI now always records the port of the
    /// approved request so one approval cannot cover unrelated services.
    #[serde(default)]
    pub port: Option<u16>,
    pub scope: ApprovalScope,
    pub expires_at_ms: Option<u64>,
    /// Content-addressed digest of the agent image this grant binds to, e.g.
    /// the `docker image inspect .Id` of the session image. `None` means the
    /// grant was written without an identity assertion; the proxy fails
    /// closed and rejects such grants whenever it runs with a binding
    /// configured.
    #[serde(default)]
    pub image_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProxyRequest {
    pub request_id: String,
    pub host: String,
    pub port: u16,
    pub created_at_ms: u64,
    pub bytes_sent: u64,
    /// Why the proxy allowed this request ("observe", "pre_authorized",
    /// "manual_approval"). None while the request is still pending, so an
    /// exported audit can tell an automatic policy allow apart from a human
    /// approval.
    #[serde(default)]
    pub decision_source: Option<String>,
}

/// A rule that allows matching CONNECT requests without pausing for a human.
/// Pre-authorizations live inside one session's proxy state directory, so they
/// cannot outlive the session that declared them.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PreAuthorization {
    /// Exact host, or a "*." prefix pattern that also matches the bare suffix.
    pub host: String,
    /// Port this rule covers. Required: a rule never silently spans ports.
    pub port: u16,
    /// Absolute expiry in milliseconds since the epoch. None means the rule
    /// lasts as long as the session state directory exists.
    #[serde(default)]
    pub expires_at_ms: Option<u64>,
    /// Free-form reason, carried into the audit trail.
    #[serde(default)]
    pub note: Option<String>,
}

/// Where a proxy decision came from. Recorded so an exported audit can show
/// whether a connection was let through by policy or by a person.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DecisionSource {
    Observe,
    PreAuthorized,
    ManualApproval,
    Denied,
    Timeout,
    Pending,
    /// The target hostname resolved only to non-public addresses (loopback,
    /// private, link-local, metadata, and similar), so the proxy refused it
    /// after policy allowed the CONNECT.
    BlockedTarget,
    /// Policy allowed the request but the upstream TCP connection failed.
    ConnectFailed,
}

impl DecisionSource {
    pub fn as_str(self) -> &'static str {
        match self {
            DecisionSource::Observe => "observe",
            DecisionSource::PreAuthorized => "pre_authorized",
            DecisionSource::ManualApproval => "manual_approval",
            DecisionSource::Denied => "denied",
            DecisionSource::Timeout => "timeout",
            DecisionSource::Pending => "pending",
            DecisionSource::BlockedTarget => "blocked_target",
            DecisionSource::ConnectFailed => "connect_failed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestEvaluation {
    pub decision: ProxyDecision,
    pub source: DecisionSource,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProxyConfig {
    pub mode: ProxyMode,
    pub approval_timeout_ms: u64,
    /// Identity the proxy enforces for approval grants, usually the agent
    /// image digest passed via `OW_PROXY_IMAGE_ID`. `None` disables binding
    /// enforcement (standalone/legacy use).
    #[serde(default)]
    pub image_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeniedRequest {
    pub request_id: Option<String>,
    pub host: String,
    /// Port the denial is bound to; `None` keeps the legacy wildcard for
    /// denials written before port binding existed.
    #[serde(default)]
    pub port: Option<u16>,
}

/// Generates a process-unique request id. Concurrent connections accepted in
/// the same millisecond must never collide, otherwise one request file would
/// overwrite the other and leave a connection pending until timeout.
pub fn next_request_id(now_ms: u64) -> String {
    let counter = REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    format!("req-{now_ms}-{}-{counter}-{nanos}", std::process::id())
}

pub fn parse_connect_target(line: &str) -> Result<(String, u16), String> {
    let mut parts = line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| "empty proxy request".to_string())?;
    let target = parts
        .next()
        .ok_or_else(|| "CONNECT target missing".to_string())?;
    if method != "CONNECT" {
        return Err("only HTTPS CONNECT is supported".into());
    }
    let (host, port) = target
        .rsplit_once(':')
        .ok_or_else(|| "CONNECT target must be host:port".to_string())?;
    let port = port
        .parse::<u16>()
        .map_err(|_| "invalid target port".to_string())?;
    if host.is_empty() {
        return Err("empty target host".into());
    }
    Ok((host.to_string(), port))
}

pub fn evaluate_request(
    request: &ProxyRequest,
    config: &ProxyConfig,
    approvals: &[ApprovalGrant],
    now_ms: u64,
) -> ProxyDecision {
    evaluate_request_with_denials(request, config, approvals, &[], now_ms)
}

pub fn evaluate_request_with_denials(
    request: &ProxyRequest,
    config: &ProxyConfig,
    approvals: &[ApprovalGrant],
    denials: &[DeniedRequest],
    now_ms: u64,
) -> ProxyDecision {
    evaluate_request_detailed(request, config, approvals, denials, &[], now_ms).decision
}

/// Full evaluation including pre-authorization rules and the reason for the
/// decision. Precedence: explicit denial, then observe mode, then a matching
/// pre-authorization, then a human approval, then the approval timeout.
pub fn evaluate_request_detailed(
    request: &ProxyRequest,
    config: &ProxyConfig,
    approvals: &[ApprovalGrant],
    denials: &[DeniedRequest],
    pre_authorizations: &[PreAuthorization],
    now_ms: u64,
) -> RequestEvaluation {
    if denials.iter().any(|denial| denial_applies(denial, request)) {
        return RequestEvaluation {
            decision: ProxyDecision::Block,
            source: DecisionSource::Denied,
        };
    }
    if config.mode == ProxyMode::Observe {
        return RequestEvaluation {
            decision: ProxyDecision::Allow,
            source: DecisionSource::Observe,
        };
    }
    if pre_authorizations
        .iter()
        .any(|rule| preauth_applies(rule, request, now_ms))
    {
        return RequestEvaluation {
            decision: ProxyDecision::Allow,
            source: DecisionSource::PreAuthorized,
        };
    }
    if approvals
        .iter()
        .any(|grant| grant_applies_with_binding(grant, request, now_ms, config.image_id.as_deref()))
    {
        return RequestEvaluation {
            decision: ProxyDecision::Allow,
            source: DecisionSource::ManualApproval,
        };
    }
    if now_ms
        >= request
            .created_at_ms
            .saturating_add(config.approval_timeout_ms)
    {
        RequestEvaluation {
            decision: ProxyDecision::Block,
            source: DecisionSource::Timeout,
        }
    } else {
        RequestEvaluation {
            decision: ProxyDecision::Pending,
            source: DecisionSource::Pending,
        }
    }
}

/// Matches an exact host, or a "*." prefix pattern that also covers the bare
/// suffix (the convention used by the reference egress proxies).
fn host_matches(pattern: &str, host: &str) -> bool {
    match pattern.strip_prefix("*.") {
        Some(suffix) => host == suffix || host.ends_with(&format!(".{suffix}")),
        None => pattern == host,
    }
}

fn preauth_applies(rule: &PreAuthorization, request: &ProxyRequest, now_ms: u64) -> bool {
    if rule.port != request.port {
        return false;
    }
    if let Some(expires_at_ms) = rule.expires_at_ms {
        if now_ms > expires_at_ms {
            return false;
        }
    }
    host_matches(&rule.host, &request.host)
}

fn denial_applies(denial: &DeniedRequest, request: &ProxyRequest) -> bool {
    denial.host == request.host
        && denial.port.is_none_or(|port| port == request.port)
        && denial
            .request_id
            .as_deref()
            .is_none_or(|request_id| request_id == request.request_id)
}

fn grant_applies_with_binding(
    grant: &ApprovalGrant,
    request: &ProxyRequest,
    now_ms: u64,
    binding: Option<&str>,
) -> bool {
    if grant.host != request.host {
        return false;
    }
    if let Some(port) = grant.port {
        if port != request.port {
            return false;
        }
    }
    if grant.scope != ApprovalScope::Session {
        if let Some(expires_at_ms) = grant.expires_at_ms {
            if now_ms > expires_at_ms {
                return false;
            }
        }
    }
    // Image identity binding, mirroring the core consent model: when either
    // side asserts an identity, both must agree. Anything else fails closed.
    match (binding, grant.image_id.as_deref()) {
        (Some(expected), Some(actual)) if expected == actual => {}
        (None, None) => {}
        _ => return false,
    }
    match grant.scope {
        ApprovalScope::Once => grant.request_id.as_deref() == Some(request.request_id.as_str()),
        ApprovalScope::Host | ApprovalScope::Session => true,
    }
}

pub fn run_from_env() -> Result<(), String> {
    let state_dir = PathBuf::from(
        std::env::var("OW_PROXY_STATE_DIR")
            .map_err(|_| "OW_PROXY_STATE_DIR is required".to_string())?,
    );
    let listen = std::env::var("OW_PROXY_LISTEN").unwrap_or_else(|_| "0.0.0.0:3128".into());
    let mode = match std::env::var("OW_PROXY_MODE")
        .unwrap_or_else(|_| "strict".into())
        .as_str()
    {
        "observe" => ProxyMode::Observe,
        "strict" => ProxyMode::Strict,
        other => return Err(format!("unsupported proxy mode: {other}")),
    };
    let timeout_ms = std::env::var("OW_PROXY_TIMEOUT_MS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(120_000);
    let image_id = std::env::var("OW_PROXY_IMAGE_ID")
        .ok()
        .filter(|value| !value.is_empty());
    fs::create_dir_all(state_dir.join("requests")).map_err(|error| error.to_string())?;
    seed_request_file_count(&state_dir);
    // SSRF protection is on by default. Operators who genuinely need an
    // internal upstream can opt out explicitly for this proxy container.
    let allow_private = std::env::var("OW_PROXY_ALLOW_PRIVATE")
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let listener = TcpListener::bind(&listen).map_err(|error| format!("bind {listen}: {error}"))?;
    let config = ProxyConfig {
        mode,
        approval_timeout_ms: timeout_ms,
        image_id,
    };
    // The credential broker shares the state directory but listens separately,
    // so CONNECT policy and credential injection stay independent.
    let broker_state_dir = state_dir.clone();
    let broker_listen =
        std::env::var("OW_PROXY_BROKER_LISTEN").unwrap_or_else(|_| "0.0.0.0:8080".into());
    thread::spawn(move || {
        if let Err(error) = broker::serve(broker_state_dir, broker_listen) {
            eprintln!("broker listener failed: {error}");
        }
    });
    for incoming in listener.incoming() {
        let client = incoming.map_err(|error| error.to_string())?;
        let config = config.clone();
        let state_dir = state_dir.clone();
        thread::spawn(move || {
            if let Err(error) = handle_client(client, &state_dir, &config, allow_private) {
                eprintln!("proxy connection failed: {error}");
            }
        });
    }
    Ok(())
}

/// Refuses loopback, private, link-local, CGNAT, documentation, multicast, and
/// metadata-style addresses. The proxy itself makes the outbound connection, so
/// without this an approved hostname could resolve to the cloud metadata
/// endpoint or another service only the proxy can reach.
fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.is_multicast()
                || octets[0] == 0
                || (octets[0] == 100 && (64..=127).contains(&octets[1]))
                || (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19))
                || octets[0] >= 240)
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public_ip(IpAddr::V4(v4));
            }
            let segments = v6.segments();
            let documentation = segments[0] == 0x2001 && segments[1] == 0x0db8;
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
                || documentation)
        }
    }
}

/// Resolves the CONNECT target and removes every non-public address. The proxy
/// connects to the returned addresses, not to the hostname again, so a DNS
/// answer cannot change between policy approval and connection setup.
fn resolve_target_addrs(
    host: &str,
    port: u16,
    allow_private: bool,
) -> Result<Vec<SocketAddr>, String> {
    let resolved = (host, port)
        .to_socket_addrs()
        .map_err(|error| format!("解析目标 {host}:{port} 失败: {error}"))?;
    let addresses = resolved
        .filter(|address| allow_private || is_public_ip(address.ip()))
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        return Err(format!(
            "目标 {host}:{port} 只解析到非公网地址，已按 SSRF 防护拒绝"
        ));
    }
    Ok(addresses)
}

fn connect_any(addresses: &[SocketAddr]) -> Result<TcpStream, String> {
    let mut last_error = String::from("没有可用地址");
    for address in addresses {
        match TcpStream::connect(address) {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = format!("{address}: {error}"),
        }
    }
    Err(format!("连接目标失败: {last_error}"))
}

fn write_status(stream: &mut TcpStream, status: &str) {
    let _ = stream.write_all(
        format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes(),
    );
    let _ = stream.flush();
}

fn record_decision(
    path: &Path,
    request: &ProxyRequest,
    source: DecisionSource,
) -> Result<(), String> {
    write_json(
        path,
        &ProxyRequest {
            decision_source: Some(source.as_str().to_string()),
            ..request.clone()
        },
    )
}

fn handle_client(
    mut client: TcpStream,
    state_dir: &Path,
    config: &ProxyConfig,
    allow_private: bool,
) -> Result<(), String> {
    let Some(_guard) = ConnectionGuard::acquire() else {
        write_status(&mut client, "503 Service Unavailable");
        return Ok(());
    };
    let _ = client.set_read_timeout(Some(HEADER_READ_TIMEOUT));
    let _ = client.set_write_timeout(Some(HEADER_READ_TIMEOUT));
    let header = read_headers(&mut client)?;
    // The tunnel itself may be long-lived; only the header exchange is
    // bounded.
    let _ = client.set_read_timeout(None);
    let _ = client.set_write_timeout(None);
    let first_line = header
        .lines()
        .next()
        .ok_or_else(|| "proxy request has no request line".to_string())?;
    let (host, port) = parse_connect_target(first_line)?;
    let request = ProxyRequest {
        request_id: next_request_id(now_ms()),
        host,
        port,
        created_at_ms: now_ms(),
        bytes_sent: 0,
        decision_source: None,
    };
    if !reserve_request_file() {
        write_status(&mut client, "429 Too Many Requests");
        return Ok(());
    }
    let request_path = state_dir
        .join("requests")
        .join(format!("{}.json", request.request_id));
    write_json(&request_path, &request)?;

    let allowed_by;
    loop {
        let approvals = read_approvals(state_dir);
        let denials = read_denials(state_dir);
        let pre_authorizations = read_pre_authorizations(state_dir);
        let evaluation = evaluate_request_detailed(
            &request,
            config,
            &approvals,
            &denials,
            &pre_authorizations,
            now_ms(),
        );
        match evaluation.decision {
            ProxyDecision::Allow => {
                allowed_by = evaluation.source;
                // Persist the reason immediately so the session request list
                // can show why a connection was let through before it ends.
                record_decision(&request_path, &request, allowed_by)?;
                break;
            }
            ProxyDecision::Block => {
                let _ = record_decision(&request_path, &request, evaluation.source);
                write_status(&mut client, "403 Forbidden");
                return Ok(());
            }
            ProxyDecision::Pending => thread::sleep(Duration::from_millis(100)),
        }
    }

    let targets = match resolve_target_addrs(&request.host, request.port, allow_private) {
        Ok(targets) => targets,
        Err(error) => {
            eprintln!("{error}");
            let _ = record_decision(&request_path, &request, DecisionSource::BlockedTarget);
            write_status(&mut client, "403 Forbidden");
            return Ok(());
        }
    };
    let mut upstream = match connect_any(&targets) {
        Ok(stream) => stream,
        Err(error) => {
            eprintln!("{error}");
            let _ = record_decision(&request_path, &request, DecisionSource::ConnectFailed);
            write_status(&mut client, "502 Bad Gateway");
            return Ok(());
        }
    };
    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .map_err(|error| error.to_string())?;
    let upload_client = client.try_clone().map_err(|error| error.to_string())?;
    let mut upload_upstream = upstream.try_clone().map_err(|error| error.to_string())?;
    let upload = thread::spawn(move || {
        let mut reader = upload_client;
        io::copy(&mut reader, &mut upload_upstream).unwrap_or(0)
    });
    let mut download_client = client;
    let received = io::copy(&mut upstream, &mut download_client).unwrap_or(0);
    let sent = upload.join().unwrap_or(0);
    let _ = download_client.shutdown(Shutdown::Both);

    let completed = ProxyRequest {
        bytes_sent: sent,
        decision_source: Some(allowed_by.as_str().to_string()),
        ..request
    };
    write_json(&request_path, &completed)?;
    eprintln!("proxy completed request: sent={sent} received={received}");
    Ok(())
}

fn read_headers(stream: &mut TcpStream) -> Result<String, String> {
    let started = Instant::now();
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 1024];
    while bytes.len() < MAX_PROXY_HEADER_BYTES {
        if started.elapsed() > HEADER_READ_TIMEOUT {
            return Err("读取请求头超时".to_string());
        }
        let count = stream
            .read(&mut buffer)
            .map_err(|error| error.to_string())?;
        if count == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..count]);
        if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    String::from_utf8(bytes).map_err(|error| error.to_string())
}

fn read_approvals(state_dir: &Path) -> Vec<ApprovalGrant> {
    fs::read_to_string(state_dir.join("approvals.json"))
        .ok()
        .and_then(|source| serde_json::from_str(&source).ok())
        .unwrap_or_default()
}

fn read_pre_authorizations(state_dir: &Path) -> Vec<PreAuthorization> {
    fs::read_to_string(state_dir.join("preauth.json"))
        .ok()
        .and_then(|source| serde_json::from_str(&source).ok())
        .unwrap_or_default()
}

fn read_denials(state_dir: &Path) -> Vec<DeniedRequest> {
    fs::read_to_string(state_dir.join("denials.json"))
        .ok()
        .and_then(|source| serde_json::from_str(&source).ok())
        .unwrap_or_default()
}

/// Writes JSON atomically: serialize to a unique temp file in the same
/// directory, then rename over the target. Readers either see the complete
/// old file or the complete new one, never a torn write.
pub fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let json = serde_json::to_string_pretty(value).map_err(|error| error.to_string())?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("invalid target path: {}", path.display()))?;
    let temp_path = path.with_file_name(format!(
        ".{file_name}.tmp-{}-{}",
        std::process::id(),
        REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    fs::write(&temp_path, json).map_err(|error| error.to_string())?;
    fs::rename(&temp_path, path).map_err(|error| error.to_string())
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(value: &str) -> IpAddr {
        value.parse().expect("test address should parse")
    }

    #[test]
    fn blocks_non_public_target_addresses() {
        for value in [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "198.18.0.1",
            "224.0.0.1",
            "::1",
            "fc00::1",
            "fe80::1",
            "2001:db8::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(!is_public_ip(ip(value)), "{value} must be refused");
        }
        for value in ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"] {
            assert!(is_public_ip(ip(value)), "{value} must be allowed");
        }
    }

    #[test]
    fn connection_guard_releases_its_slot() {
        let before = ACTIVE_CONNECTIONS.load(Ordering::Relaxed);
        let guard = ConnectionGuard::acquire().expect("a slot should be available");
        assert_eq!(ACTIVE_CONNECTIONS.load(Ordering::Relaxed), before + 1);
        drop(guard);
        assert_eq!(ACTIVE_CONNECTIONS.load(Ordering::Relaxed), before);
    }
}
