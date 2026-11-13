use crate::events::FileActivityRecord;
use crate::workspace::{WorkspaceDiff, WorkspaceManifest};
use crate::{ConsentGrant, EvaluationResult, WitnessEvent};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub use crate::EnforcementMode;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicy {
    pub allowed_hosts: Vec<String>,
    pub proxy_required: bool,
    pub allow_loopback: bool,
}

impl NetworkPolicy {
    pub fn strict(allowed_hosts: Vec<String>) -> Self {
        Self {
            allowed_hosts,
            proxy_required: true,
            allow_loopback: true,
        }
    }

    pub fn observe() -> Self {
        Self {
            allowed_hosts: Vec::new(),
            proxy_required: false,
            allow_loopback: true,
        }
    }
}

pub fn network_allowed(policy: &NetworkPolicy, host: &str) -> bool {
    if policy.allow_loopback && matches!(host, "localhost" | "127.0.0.1" | "::1") {
        return true;
    }
    policy.allowed_hosts.iter().any(|allowed| {
        allowed == host || (allowed.starts_with("*.") && host.ends_with(&allowed[1..]))
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SessionSpec {
    pub id: String,
    pub workspace: PathBuf,
    pub command: Vec<String>,
    pub allowed_paths: Vec<PathBuf>,
    pub excluded_paths: Vec<String>,
    pub network_policy: NetworkPolicy,
    pub mode: EnforcementMode,
    pub approval_timeout_secs: u64,
    pub runtime: String,
    pub image: String,
    /// Content-addressed digest of `image` attested at session start (the
    /// `docker image inspect .Id`). Approval grants bind to it so a grant
    /// issued for one session image cannot be replayed against another.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_id: Option<String>,
    /// Hosts pre-authorized at session start, each written as host:port. They
    /// are seeded into the session proxy state so the proxy can allow matching
    /// CONNECT requests without pausing for a human.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pre_authorized_hosts: Vec<String>,
    /// Credential broker routes for this session. Secret values live only in the
    /// proxy container environment; these summaries let the runtime pass the
    /// right variables to the right container and let the audit show which
    /// credentials a session could reach.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credential_routes: Vec<CredentialRouteSummary>,
    /// Host-side JSON file the routes were read from, kept for provenance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_routes_path: Option<String>,
    pub state_dir: PathBuf,
}

impl SessionSpec {
    pub fn new(workspace: PathBuf, command: Vec<String>, mode: EnforcementMode) -> Self {
        Self {
            id: String::new(),
            workspace,
            command,
            allowed_paths: Vec::new(),
            excluded_paths: default_exclusions(),
            network_policy: if mode == EnforcementMode::Strict {
                NetworkPolicy::strict(Vec::new())
            } else {
                NetworkPolicy::observe()
            },
            mode,
            approval_timeout_secs: 120,
            runtime: "docker".into(),
            image: "outbound-witness/session-base:latest".into(),
            image_id: None,
            pre_authorized_hosts: Vec::new(),
            credential_routes: Vec::new(),
            credential_routes_path: None,
            state_dir: PathBuf::from(".outbound-witness/sessions"),
        }
    }
}

/// Paths that are never copied into a session snapshot. Beyond version-control
/// and browser state this covers the usual credential stores, so a snapshot
/// cannot hand an agent a private key or a cloud token it was never meant to
/// have.
pub fn default_exclusions() -> Vec<String> {
    vec![
        ".env".into(),
        ".env.*".into(),
        ".git".into(),
        ".ssh".into(),
        ".aws".into(),
        ".gnupg".into(),
        ".kube".into(),
        ".docker".into(),
        ".gem".into(),
        ".npmrc".into(),
        ".netrc".into(),
        ".pypirc".into(),
        ".git-credentials".into(),
        ".pgpass".into(),
        "id_rsa".into(),
        "id_ed25519".into(),
        "id_ecdsa".into(),
        ".outbound-witness".into(),
        "Library/Application Support/Google/Chrome".into(),
        "AppData/Local/Google/Chrome".into(),
    ]
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SessionState {
    Preparing,
    Running,
    WaitingApproval,
    Completed,
    Blocked,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileAccessEvent {
    pub path: String,
    pub operation: String,
    pub bytes: u64,
    pub timestamp: String,
}

/// Broker route summary kept in the session record. The secret value itself
/// never appears here: only the name of the environment variable that holds it
/// inside the proxy container.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CredentialRouteSummary {
    pub route: String,
    pub upstream_host: String,
    pub upstream_port: u16,
    /// Name of the proxy-side environment variable, when the route uses one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_env: Option<String>,
    /// Proxy-state-relative path to a host-written secret file, when the route
    /// uses one. A short-lived token produced by token_command lands here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_file: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NetworkIntent {
    pub request_id: String,
    pub host: String,
    pub port: u16,
    pub protocol: String,
    pub timestamp: String,
    pub bytes_sent: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ApprovalResponse {
    AllowOnce,
    AllowHost,
    AllowSession,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalRequest {
    pub request_id: String,
    pub host: String,
    pub port: u16,
    pub created_at_ms: u64,
    pub timeout_ms: u64,
    pub response: Option<ApprovalResponse>,
}

impl ApprovalRequest {
    pub fn new(request_id: String, host: String, created_at_ms: u64) -> Self {
        Self {
            request_id,
            host,
            port: 443,
            created_at_ms,
            timeout_ms: 120_000,
            response: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SessionDecision {
    Allow,
    Pending,
    Block,
}

pub fn approval_decision(request: &ApprovalRequest, now_ms: u64) -> SessionDecision {
    match request.response {
        Some(ApprovalResponse::AllowOnce)
        | Some(ApprovalResponse::AllowHost)
        | Some(ApprovalResponse::AllowSession) => SessionDecision::Allow,
        Some(ApprovalResponse::Deny) => SessionDecision::Block,
        None if now_ms >= request.created_at_ms.saturating_add(request.timeout_ms) => {
            SessionDecision::Block
        }
        None => SessionDecision::Pending,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparedSession {
    pub session_id: String,
    pub snapshot_dir: PathBuf,
    pub proxy_state_dir: PathBuf,
    pub spec: SessionSpec,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SessionHandle {
    pub session_id: String,
    pub runtime_id: String,
    pub proxy_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeCapability {
    pub runtime: String,
    pub available: bool,
    pub daemon_ready: bool,
    pub version: Option<String>,
    pub enforcement: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SessionAuditRecord {
    pub session_id: String,
    pub snapshot_hash: String,
    pub runtime_digest: String,
    pub policy_version: String,
    /// Image digest the approval grants of this record bind to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_id: Option<String>,
    pub approval_request: Option<ApprovalRequest>,
    pub approval_response: Option<ApprovalResponse>,
    pub diff_hash: Option<String>,
    pub writeback_result: Option<String>,
    pub event: Option<WitnessEvent>,
    pub evaluation: Option<EvaluationResult>,
    /// Proxy request id when this record was built from a CONNECT. Used to
    /// replace the same witness on a later collection instead of appending.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_request_id: Option<String>,
}

/// Detached signature over an exported session record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuditSignature {
    pub algorithm: String,
    /// Public key that produced the signature, hex encoded. Convenience only: a
    /// verifier must compare it against a key obtained from a trusted channel,
    /// because anyone can mint a key pair and sign a fabricated record.
    pub public_key: String,
    pub value: String,
    /// Optional Merkle tree hash proof for the entire audit chain,
    /// allowing verification without re-hashing all records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_hash: Option<String>,
    /// RFC 3339 timestamp when the signature was created. Use a local clock or
    /// a trusted external time source for credibility.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_at: Option<String>,
    /// Optional transparent log entry ID (e.g., Rekor log ID or equivalent).
    /// Anchors the signature to an external, append-only registry if available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_entry_id: Option<String>,
}

impl AuditSignature {
    /// Mark this signature as verified against a local clock and (optionally)
    /// a transparent log. Useful for exporting verification metadata.
    pub fn with_verification_proof(
        mut self,
        signed_at: String,
        log_entry_id: Option<String>,
    ) -> Self {
        self.signed_at = Some(signed_at);
        self.log_entry_id = log_entry_id;
        self
    }
}

/// Commitment to the complete audit chain. A hash chain alone cannot detect
/// trailing truncation: dropping the last records (and their hashes) leaves a
/// perfectly valid prefix. The seal records how many records were present and
/// the final root at signing time, so a verifier can reject a shortened export.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuditSeal {
    pub record_count: usize,
    pub root_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SessionRecord {
    pub spec: SessionSpec,
    pub state: SessionState,
    pub snapshot: Option<WorkspaceManifest>,
    pub prepared: Option<PreparedSession>,
    pub handle: Option<SessionHandle>,
    pub diff: Option<WorkspaceDiff>,
    pub pending_requests: Vec<ApprovalRequest>,
    pub network_intents: Vec<NetworkIntent>,
    pub audit: Vec<SessionAuditRecord>,
    /// SHA-256 chain over `audit`, one hash per record, recomputed before an
    /// export. A third party can re-derive it with the verify command without
    /// trusting the process that produced the file.
    #[serde(default)]
    pub audit_chain: Vec<String>,
    /// Ed25519 signature produced at export time. A hash chain proves the file
    /// was not altered; the signature is what can prove who produced it.
    #[serde(default)]
    pub signature: Option<AuditSignature>,
    /// Record count and root hash at signing time. Optional so records written
    /// before seals existed still deserialize; verification treats a missing
    /// seal as "completeness cannot be proven" rather than as valid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_seal: Option<AuditSeal>,
    /// File activity summary from observer (if available). Empty if no observer was active.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_activity: Option<FileActivityRecord>,
    pub error: Option<String>,
}

impl SessionRecord {
    pub fn new(spec: SessionSpec) -> Self {
        Self {
            spec,
            state: SessionState::Preparing,
            snapshot: None,
            prepared: None,
            handle: None,
            diff: None,
            pending_requests: Vec::new(),
            network_intents: Vec::new(),
            audit: Vec::new(),
            audit_chain: Vec::new(),
            signature: None,
            audit_seal: None,
            file_activity: None,
            error: None,
        }
    }

    /// Recomputes the audit hash chain. Each link covers the record and the
    /// previous link, so editing, reordering, or dropping a record breaks it.
    pub fn chain_audit(&mut self) {
        let mut previous: Option<String> = None;
        let mut chain = Vec::with_capacity(self.audit.len());
        for record in &self.audit {
            let material =
                serde_json::to_vec(&(record, &previous)).expect("audit records must serialize");
            let hash = crate::sha256_hex(&material);
            previous = Some(hash.clone());
            chain.push(hash);
        }
        self.audit_chain = chain;
        self.audit_seal = Some(AuditSeal {
            record_count: self.audit.len(),
            root_hash: self.audit_chain.last().cloned(),
        });
    }

    /// Re-derives the chain and reports the first record that does not match.
    /// When an `audit_seal` is present its record count and root hash are
    /// checked too, which is what makes trailing truncation detectable.
    pub fn verify_audit_chain(&self) -> Result<(), (usize, String)> {
        if self.audit_chain.len() != self.audit.len() {
            return Err((
                0,
                format!(
                    "审计链长度 {} 与记录数 {} 不一致",
                    self.audit_chain.len(),
                    self.audit.len()
                ),
            ));
        }
        let mut previous: Option<String> = None;
        for (index, record) in self.audit.iter().enumerate() {
            let material =
                serde_json::to_vec(&(record, &previous)).expect("audit records must serialize");
            let expected = crate::sha256_hex(&material);
            if self.audit_chain[index] != expected {
                return Err((index, "chain_hash 与记录内容不匹配".to_string()));
            }
            previous = Some(expected);
        }
        if let Some(seal) = &self.audit_seal {
            if seal.record_count != self.audit.len() {
                return Err((
                    0,
                    format!(
                        "完整性封条记录数 {} 与当前记录数 {} 不一致（可能被截断）",
                        seal.record_count,
                        self.audit.len()
                    ),
                ));
            }
            if seal.root_hash.as_ref() != self.audit_chain.last() {
                return Err((0, "完整性封条根哈希与审计链末尾不一致".to_string()));
            }
        }
        Ok(())
    }
}

pub trait SessionRuntime {
    fn prepare(&self, spec: &SessionSpec) -> Result<PreparedSession, String>;
    fn start(&self, session: &PreparedSession) -> Result<SessionHandle, String>;
    fn stop(&self, session: &SessionHandle) -> Result<(), String>;
    fn collect_diff(
        &self,
        session: &SessionHandle,
    ) -> Result<crate::workspace::WorkspaceDiff, String>;
    fn apply_diff(
        &self,
        diff: &crate::workspace::WorkspaceDiff,
        paths: &[String],
    ) -> Result<(), String>;
}

pub trait EgressController {
    fn pause(&self, request: &ApprovalRequest) -> Result<(), String>;
    fn allow(&self, request_id: &str, grant: ConsentGrant) -> Result<(), String>;
    fn block(&self, request_id: &str, reason: &str) -> Result<(), String>;
}
