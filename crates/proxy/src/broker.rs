//! Credential broker: the agent never holds a real credential.
//!
//! The agent sends a **plain HTTP** request to the broker on the internal
//! Docker network. The broker looks the credential up in its own process
//! environment (which the agent container does not share), makes its own
//! certificate-verified HTTPS call upstream, injects the credential header,
//! and relays the response back.
//!
//! This deliberately does not decrypt any agent TLS session: the agent never
//! opens TLS towards the upstream at all. The trade-off is that the broker
//! process is a new trust boundary, because it holds usable credentials.

use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::write_json;

/// Largest request body the broker will forward. Anything bigger is refused
/// instead of being buffered, so a hostile agent cannot exhaust broker memory.
const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;
/// Largest header block accepted from the agent.
const MAX_HEADER_BYTES: usize = 32 * 1024;
/// Largest upstream response relayed for one request. The response is streamed
/// rather than buffered, so this only bounds the total bytes of one request.
const MAX_STREAM_BYTES: u64 = 256 * 1024 * 1024;
/// Largest upstream response header block accepted before giving up.
const MAX_UPSTREAM_HEAD_BYTES: usize = 64 * 1024;

/// One credential route. The secret value itself is never stored here: the route
/// only says where the broker should resolve it at request time.
///
/// Exactly one of `secret_env` or `secret_file` must be set. A file source lets
/// the host rotate a short-lived credential (see `token_command`) without
/// restarting the proxy, and it never passes through the agent container.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredentialRoute {
    /// First path segment the agent calls, e.g. "anthropic".
    pub route: String,
    /// Upstream host the broker connects to over verified TLS.
    pub upstream_host: String,
    #[serde(default = "default_upstream_port")]
    pub upstream_port: u16,
    /// Header the credential is injected into, e.g. "x-api-key".
    pub header: String,
    /// Name of the broker-side environment variable holding the secret.
    #[serde(default)]
    pub secret_env: Option<String>,
    /// Path to the secret, relative to the proxy state directory. The host
    /// writes this file; the agent container never mounts that directory.
    #[serde(default)]
    pub secret_file: Option<String>,
    /// Command the CLI runs on the host at session start to produce the secret
    /// for `secret_file`, e.g. a cloud CLI printing a short-lived token.
    #[serde(default)]
    pub token_command: Option<Vec<String>>,
    #[serde(default)]
    pub note: Option<String>,
}

fn default_upstream_port() -> u16 {
    443
}

impl CredentialRoute {
    /// Rejects route definitions that would corrupt the upstream request.
    pub fn validate(&self) -> Result<(), String> {
        if self.route.is_empty()
            || !self
                .route
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(format!(
                "凭据路由名只能包含字母、数字、- 和 _，收到: {}",
                self.route
            ));
        }
        if self.upstream_host.is_empty() || self.upstream_host.contains('/') {
            return Err(format!("凭据上游主机无效: {}", self.upstream_host));
        }
        if !is_valid_header_name(&self.header) {
            return Err(format!("凭据注入头名称无效: {}", self.header));
        }
        let env_name = self.secret_env.as_deref().filter(|name| !name.is_empty());
        let file_path = self.secret_file.as_deref().filter(|path| !path.is_empty());
        match (env_name, file_path) {
            (Some(name), None) => {
                if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                    return Err(format!("凭据环境变量名无效: {name}"));
                }
            }
            (None, Some(path)) => {
                let path = Path::new(path);
                if path.is_absolute()
                    || path.components().any(|component| {
                        matches!(
                            component,
                            Component::ParentDir | Component::RootDir | Component::Prefix(_)
                        )
                    })
                {
                    return Err(format!(
                        "凭据文件必须是 state 目录内的相对路径: {}",
                        path.display()
                    ));
                }
            }
            (Some(_), Some(_)) => {
                return Err("凭据路由只能声明 secret_env 或 secret_file 其中之一".to_string());
            }
            (None, None) => {
                return Err("凭据路由需要 secret_env 或 secret_file".to_string());
            }
        }
        if let Some(command) = &self.token_command {
            if command.is_empty() {
                return Err("token_command 不能为空".to_string());
            }
            if file_path.is_none() {
                return Err("token_command 只能配合 secret_file 使用".to_string());
            }
        }
        Ok(())
    }
}

/// Resolves the credential for one request. A file source wins so the host can
/// rotate a short-lived token while the session is running.
pub fn resolve_secret(state_dir: &Path, route: &CredentialRoute) -> Result<String, String> {
    if let Some(relative) = route.secret_file.as_deref().filter(|path| !path.is_empty()) {
        let path = state_dir.join(relative);
        let value = fs::read_to_string(&path)
            .map_err(|error| format!("无法读取凭据文件 {}: {error}", path.display()))?;
        let value = value.trim_end_matches(['\r', '\n']).to_string();
        if value.is_empty() {
            return Err(format!("凭据文件为空: {}", path.display()));
        }
        return Ok(value);
    }
    match route.secret_env.as_deref().filter(|name| !name.is_empty()) {
        Some(name) => match std::env::var(name) {
            Ok(value) if !value.is_empty() => Ok(value),
            _ => Err(format!("broker 缺少凭据环境变量 {name}")),
        },
        None => Err("凭据路由没有可用的凭据来源".to_string()),
    }
}

fn is_valid_header_name(name: &str) -> bool {
    !name.is_empty()
        && name.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '!' | '#' | '$' | '%' | '&' | '\'' | '*' | '+' | '-' | '.' | '^' | '_' | '`' | '|' | '~')
        })
}

/// Headers copied from the agent request to the upstream request. Everything
/// else is dropped, which keeps the agent from smuggling routing or credential
/// headers through the broker.
const FORWARDED_HEADERS: &[&str] = &[
    "content-type",
    "accept",
    "anthropic-version",
    "anthropic-beta",
    "openai-beta",
    "openai-organization",
];

pub fn read_routes(state_dir: &Path) -> Vec<CredentialRoute> {
    fs::read_to_string(state_dir.join("broker.json"))
        .ok()
        .and_then(|source| serde_json::from_str(&source).ok())
        .unwrap_or_default()
}

/// Splits "/route/rest" into ("route", "/rest"). A bare "/route" maps to "/".
pub fn split_route(target: &str) -> Result<(String, String), String> {
    let trimmed = target
        .strip_prefix('/')
        .ok_or_else(|| "broker 只接受以 / 开头的路径".to_string())?;
    if trimmed.starts_with('/') {
        return Err("broker 路径不能以 // 开头".to_string());
    }
    match trimmed.split_once('/') {
        Some((route, rest)) => Ok((route.to_string(), format!("/{rest}"))),
        None => Ok((trimmed.to_string(), "/".to_string())),
    }
}

/// Parses the request line. Only origin-form targets are accepted so the agent
/// cannot make the broker speak to an arbitrary authority.
pub fn parse_request_line(line: &str) -> Result<(String, String), String> {
    let mut parts = line.split_whitespace();
    let method = parts.next().ok_or_else(|| "broker 请求行为空".to_string())?;
    let target = parts
        .next()
        .ok_or_else(|| "broker 请求缺少路径".to_string())?;
    let version = parts.next().unwrap_or("HTTP/1.1");
    if !version.starts_with("HTTP/1.") {
        return Err(format!("不支持的 HTTP 版本: {version}"));
    }
    if !matches!(method, "GET" | "POST" | "PUT" | "PATCH" | "DELETE") {
        return Err(format!("broker 不支持的方法: {method}"));
    }
    if target.contains(' ') || target.contains('\r') || target.contains('\n') {
        return Err("broker 路径包含非法字符".to_string());
    }
    if !target.starts_with('/') {
        return Err("broker 只接受 origin-form 路径".to_string());
    }
    Ok((method.to_string(), target.to_string()))
}

fn parse_headers(head: &str) -> Result<Vec<(String, String)>, String> {
    let mut headers = Vec::new();
    for line in head.lines().skip(1) {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            break;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| format!("broker 头部缺少冒号: {line}"))?;
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim().to_string();
        if name.is_empty() || value.contains('\r') || value.contains('\n') {
            return Err("broker 头部非法".to_string());
        }
        headers.push((name, value));
    }
    Ok(headers)
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.as_str())
}

/// Builds the upstream request. Pure so the header policy is unit-testable
/// without a network or a TLS stack.
pub fn build_upstream_request(
    route: &CredentialRoute,
    method: &str,
    upstream_path: &str,
    headers: &[(String, String)],
    body: &[u8],
    secret: &str,
) -> Result<Vec<u8>, String> {
    if secret.contains('\r') || secret.contains('\n') {
        return Err("凭据值包含换行，拒绝注入".to_string());
    }
    let mut request = Vec::new();
    request.extend_from_slice(format!("{method} {upstream_path} HTTP/1.1\r\n").as_bytes());
    let host_header = if route.upstream_port == 443 {
        route.upstream_host.clone()
    } else {
        format!("{}:{}", route.upstream_host, route.upstream_port)
    };
    request.extend_from_slice(format!("Host: {host_header}\r\n").as_bytes());
    request.extend_from_slice(format!("{}: {secret}\r\n", route.header).as_bytes());
    request.extend_from_slice(b"user-agent: outbound-witness-broker\r\n");
    for name in FORWARDED_HEADERS {
        if *name == route.header.to_ascii_lowercase() {
            continue;
        }
        if let Some(value) = header_value(headers, name) {
            request.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        }
    }
    if !body.is_empty() {
        request.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    }
    request.extend_from_slice(b"Connection: close\r\n\r\n");
    request.extend_from_slice(body);
    Ok(request)
}

fn read_head(stream: &mut TcpStream) -> Result<String, String> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 1024];
    while bytes.len() < MAX_HEADER_BYTES {
        let count = stream.read(&mut buffer).map_err(|e| e.to_string())?;
        if count == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..count]);
        if bytes.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    String::from_utf8(bytes).map_err(|error| error.to_string())
}

fn read_body(stream: &mut TcpStream, headers: &[(String, String)]) -> Result<Vec<u8>, String> {
    if header_value(headers, "transfer-encoding").is_some() {
        return Err("broker 不支持 chunked 请求体，请使用 Content-Length".to_string());
    }
    let length = match header_value(headers, "content-length") {
        Some(value) => value
            .parse::<usize>()
            .map_err(|_| format!("Content-Length 无效: {value}"))?,
        None => return Ok(Vec::new()),
    };
    if length > MAX_BODY_BYTES {
        return Err(format!(
            "请求体 {} 字节超过 broker 上限 {} 字节",
            length, MAX_BODY_BYTES
        ));
    }
    let mut body = vec![0_u8; length];
    stream
        .read_exact(&mut body)
        .map_err(|error| format!("读取请求体失败: {error}"))?;
    Ok(body)
}

fn write_error(stream: &mut TcpStream, status: &str, message: &str) {
    let body = format!("{message}\n");
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

fn tls_connect(
    route: &CredentialRoute,
) -> Result<rustls::StreamOwned<rustls::ClientConnection, TcpStream>, String> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| error.to_string())?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server_name = rustls::pki_types::ServerName::try_from(route.upstream_host.clone())
        .map_err(|_| format!("上游主机名无效: {}", route.upstream_host))?;
    let connection = rustls::ClientConnection::new(Arc::new(config), server_name)
        .map_err(|error| error.to_string())?;
    Ok(rustls::StreamOwned::new(
        connection,
        TcpStream::connect((route.upstream_host.as_str(), route.upstream_port))
            .map_err(|error| format!("连接上游失败: {error}"))?,
    ))
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
}

/// Streams the upstream response to the client as it arrives. The header block
/// is forwarded the moment it is complete, so a streaming upstream (SSE) reaches
/// the agent without waiting for the whole body to finish.
fn relay_response(upstream: &mut impl Read, client: &mut TcpStream) -> Result<u64, String> {
    let mut total: u64 = 0;
    let mut buffer = [0_u8; 16 * 1024];
    let mut head = Vec::new();
    let mut headers_forwarded = false;

    loop {
        let count = upstream.read(&mut buffer).map_err(|error| error.to_string())?;
        if count == 0 {
            break;
        }
        total = total.saturating_add(count as u64);
        if total > MAX_STREAM_BYTES {
            return Err(format!("上游响应超过 {MAX_STREAM_BYTES} 字节上限，已中断"));
        }
        if headers_forwarded {
            client
                .write_all(&buffer[..count])
                .map_err(|error| error.to_string())?;
            client.flush().map_err(|error| error.to_string())?;
            continue;
        }
        head.extend_from_slice(&buffer[..count]);
        if find_header_end(&head).is_some() {
            client.write_all(&head).map_err(|error| error.to_string())?;
            client.flush().map_err(|error| error.to_string())?;
            headers_forwarded = true;
            head.clear();
            continue;
        }
        if head.len() > MAX_UPSTREAM_HEAD_BYTES {
            return Err("上游响应头超过上限".to_string());
        }
    }

    if !headers_forwarded && !head.is_empty() {
        // The upstream closed before completing its header block. Pass on what
        // arrived so the agent sees a truncated response instead of hanging.
        client.write_all(&head).map_err(|error| error.to_string())?;
    }
    Ok(total)
}

fn next_broker_request_id(now_ms: u64) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    format!("broker-{now_ms}-{}-{nanos}", std::process::id())
}

fn record_broker_request(
    state_dir: &Path,
    route: &CredentialRoute,
    bytes_sent: u64,
) -> Result<(), String> {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let request = crate::ProxyRequest {
        request_id: next_broker_request_id(now_ms),
        host: route.upstream_host.clone(),
        port: route.upstream_port,
        created_at_ms: now_ms,
        bytes_sent,
        decision_source: Some("credential_broker".to_string()),
    };
    let path = state_dir
        .join("requests")
        .join(format!("{}.json", request.request_id));
    write_json(&path, &request)
}

fn handle_client(mut client: TcpStream, state_dir: &Path) -> Result<(), String> {
    let head = read_head(&mut client)?;
    let request_line = head
        .lines()
        .next()
        .ok_or_else(|| "broker 收到空请求".to_string())?;
    let (method, target) = match parse_request_line(request_line) {
        Ok(parsed) => parsed,
        Err(error) => {
            write_error(&mut client, "400 Bad Request", &error);
            return Ok(());
        }
    };
    let headers = match parse_headers(&head) {
        Ok(headers) => headers,
        Err(error) => {
            write_error(&mut client, "400 Bad Request", &error);
            return Ok(());
        }
    };
    let (route_name, upstream_path) = match split_route(&target) {
        Ok(parsed) => parsed,
        Err(error) => {
            write_error(&mut client, "400 Bad Request", &error);
            return Ok(());
        }
    };
    let routes = read_routes(state_dir);
    let Some(route) = routes.iter().find(|route| route.route == route_name) else {
        write_error(
            &mut client,
            "404 Not Found",
            &format!("未配置凭据路由: {route_name}"),
        );
        return Ok(());
    };
    let secret = match resolve_secret(state_dir, route) {
        Ok(secret) => secret,
        Err(error) => {
            write_error(&mut client, "502 Bad Gateway", &error);
            return Ok(());
        }
    };
    let body = match read_body(&mut client, &headers) {
        Ok(body) => body,
        Err(error) => {
            write_error(&mut client, "413 Payload Too Large", &error);
            return Ok(());
        }
    };
    let upstream_request =
        match build_upstream_request(route, &method, &upstream_path, &headers, &body, &secret) {
            Ok(request) => request,
            Err(error) => {
                write_error(&mut client, "500 Internal Server Error", &error);
                return Ok(());
            }
        };
    let mut upstream = match tls_connect(route) {
        Ok(upstream) => upstream,
        Err(error) => {
            write_error(&mut client, "502 Bad Gateway", &error);
            return Ok(());
        }
    };
    if let Err(error) = upstream
        .write_all(&upstream_request)
        .and_then(|()| upstream.flush())
    {
        write_error(&mut client, "502 Bad Gateway", &format!("写入上游失败: {error}"));
        return Ok(());
    }
    // Once the response starts streaming we can no longer send an HTTP error, so
    // a relay failure is logged and the connection is simply closed.
    let relayed = match relay_response(&mut upstream, &mut client) {
        Ok(relayed) => relayed,
        Err(error) => {
            eprintln!("broker relay failed: {error}");
            return Ok(());
        }
    };
    eprintln!("broker relayed {relayed} bytes from {}", route.upstream_host);
    record_broker_request(state_dir, route, body.len() as u64)
}

/// Starts the broker listener. Called alongside the CONNECT listener so one
/// proxy container serves both roles.
pub fn serve(state_dir: PathBuf, listen: String) -> Result<(), String> {
    fs::create_dir_all(state_dir.join("requests")).map_err(|error| error.to_string())?;
    let listener = TcpListener::bind(&listen)
        .map_err(|error| format!("broker bind {listen}: {error}"))?;
    for incoming in listener.incoming() {
        let client = incoming.map_err(|error| error.to_string())?;
        let state_dir = state_dir.clone();
        thread::spawn(move || {
            if let Err(error) = handle_client(client, &state_dir) {
                eprintln!("broker connection failed: {error}");
            }
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route() -> CredentialRoute {
        CredentialRoute {
            route: "anthropic".into(),
            upstream_host: "api.example.test".into(),
            upstream_port: 443,
            header: "x-api-key".into(),
            secret_env: Some("ANTHROPIC_API_KEY".into()),
            secret_file: None,
            token_command: None,
            note: None,
        }
    }

    #[test]
    fn splits_route_and_preserves_the_rest_of_the_path() {
        assert_eq!(
            split_route("/anthropic/v1/messages").unwrap(),
            ("anthropic".into(), "/v1/messages".into())
        );
        assert_eq!(
            split_route("/anthropic").unwrap(),
            ("anthropic".into(), "/".into())
        );
        assert!(split_route("//evil").is_err());
        assert!(split_route("http://evil.test/").is_err());
    }

    #[test]
    fn rejects_absolute_targets_and_unknown_methods() {
        assert!(
            parse_request_line("GET http://evil.test/ HTTP/1.1").is_err(),
            "an absolute-form target must never reach the broker"
        );
        assert_eq!(
            parse_request_line("POST /anthropic/v1 HTTP/1.1").unwrap(),
            ("POST".into(), "/anthropic/v1".into())
        );
        assert!(parse_request_line("TRACE /anthropic HTTP/1.1").is_err());
        assert!(parse_request_line("GET /a b HTTP/1.1").is_err());
    }

    #[test]
    fn injects_the_credential_and_drops_everything_else() {
        let headers = vec![
            ("content-type".to_string(), "application/json".to_string()),
            ("authorization".to_string(), "Bearer agent-supplied".to_string()),
            ("x-api-key".to_string(), "agent-supplied".to_string()),
            ("host".to_string(), "evil.test".to_string()),
            ("cookie".to_string(), "session=1".to_string()),
        ];
        let request = build_upstream_request(
            &route(),
            "POST",
            "/v1/messages",
            &headers,
            b"{}",
            "real-secret",
        )
        .unwrap();
        let text = String::from_utf8(request).unwrap();

        assert!(text.starts_with("POST /v1/messages HTTP/1.1\r\n"));
        assert!(text.contains("Host: api.example.test\r\n"));
        assert!(text.contains("x-api-key: real-secret\r\n"));
        assert!(text.contains("content-type: application/json\r\n"));
        assert!(!text.contains("agent-supplied"));
        assert!(!text.contains("evil.test"));
        assert!(!text.contains("cookie"));
        assert!(text.ends_with("\r\n\r\n{}"));
    }

    #[test]
    fn refuses_a_credential_containing_a_newline() {
        let error = build_upstream_request(&route(), "GET", "/", &[], &[], "bad\nvalue")
            .expect_err("header injection must be refused");
        assert!(error.contains("换行"), "unexpected error: {error}");
    }

    #[test]
    fn validates_route_definitions() {
        assert!(route().validate().is_ok());
        let mut bad = route();
        bad.route = "../escape".into();
        assert!(bad.validate().is_err());
        let mut bad_header = route();
        bad_header.header = "x-api-key: injected".into();
        assert!(bad_header.validate().is_err());
        let mut bad_env = route();
        bad_env.secret_env = Some("A B".into());
        assert!(bad_env.validate().is_err());
    }

    #[test]
    fn requires_exactly_one_credential_source() {
        let mut both = route();
        both.secret_file = Some("credentials/anthropic".into());
        assert!(both.validate().is_err(), "two sources must be refused");

        let mut neither = route();
        neither.secret_env = None;
        assert!(neither.validate().is_err(), "no source must be refused");

        let mut file_only = route();
        file_only.secret_env = None;
        file_only.secret_file = Some("credentials/anthropic".into());
        assert!(file_only.validate().is_ok());

        let mut escaping = route();
        escaping.secret_env = None;
        escaping.secret_file = Some("../outside".into());
        assert!(escaping.validate().is_err(), "path escape must be refused");

        let mut orphan_command = route();
        orphan_command.token_command = Some(vec!["echo".into()]);
        assert!(
            orphan_command.validate().is_err(),
            "token_command without secret_file must be refused"
        );
    }

    #[test]
    fn resolves_secrets_from_files_and_reports_missing_sources() {
        let dir = std::env::temp_dir().join(format!("ow-broker-secret-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("credentials")).unwrap();
        std::fs::write(dir.join("credentials/anthropic"), "file-secret\n").unwrap();

        let mut file_route = route();
        file_route.secret_env = None;
        file_route.secret_file = Some("credentials/anthropic".into());
        assert_eq!(
            resolve_secret(&dir, &file_route).unwrap(),
            "file-secret",
            "the trailing newline must be trimmed"
        );

        let mut missing = file_route.clone();
        missing.secret_file = Some("credentials/absent".into());
        assert!(resolve_secret(&dir, &missing).is_err());

        let mut env_route = route();
        env_route.secret_env = Some("OW_TEST_ABSENT_ENV_VAR".into());
        assert!(resolve_secret(&dir, &env_route).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn finds_the_end_of_the_header_block() {
        assert_eq!(find_header_end(b"HTTP/1.1 200 OK\r\n\r\nbody"), Some(19));
        assert_eq!(find_header_end(b"HTTP/1.1 200 OK\r\n"), None);
    }

    #[test]
    fn includes_the_port_in_host_header_only_when_non_default() {
        let mut custom = route();
        custom.upstream_port = 8443;
        let text = String::from_utf8(
            build_upstream_request(&custom, "GET", "/", &[], &[], "s").unwrap(),
        )
        .unwrap();
        assert!(text.contains("Host: api.example.test:8443\r\n"));
    }
}
