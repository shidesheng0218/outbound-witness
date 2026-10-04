use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub mod platform;
pub mod session;
pub mod workspace;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum EnforcementMode {
    Observe,
    Strict,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow,
    Alert,
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FileEventKind {
    Read,
    ArchiveCreated,
    Metadata,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub executable: String,
    pub name: String,
    pub version: Option<String>,
    pub signer: Option<String>,
    pub parent_pid: Option<u32>,
    pub parent_name: Option<String>,
    /// SHA-256 of the executable file contents, attested by the event source.
    /// `None` means the content hash is unknown; consent matching treats it
    /// as "no match" and fails closed rather than degrading to a path-based
    /// comparison. See `compute_executable_sha256` and
    /// `WitnessEvent::resolve_executable_sha256`.
    #[serde(default)]
    pub executable_sha256: Option<String>,
}

impl ProcessIdentity {
    /// Hashes the executable file contents (not the path). Returns `None`
    /// when the file cannot be read, so callers never fall back to a weaker
    /// path-string comparison by accident.
    pub fn compute_executable_sha256(&self) -> Option<String> {
        std::fs::read(&self.executable).ok().map(|bytes| sha256_hex(&bytes))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Destination {
    pub host: String,
    pub ip: Option<String>,
    pub port: u16,
    pub protocol: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkEvent {
    pub destination: Destination,
    pub bytes_sent: u64,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileEvent {
    pub path: String,
    pub kind: FileEventKind,
    pub bytes: u64,
    pub sha256: Option<String>,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsentGrant {
    pub executable_sha256: String,
    pub process_version: String,
    pub destination_host: String,
    /// Port the consent is bound to. Grants written before port binding
    /// existed deserialize as `None`, which keeps the historical wildcard
    /// behaviour (any port on `destination_host`). Every grant produced by
    /// the CLI now carries the port of the approved request, so approving a
    /// host can no longer silently authorise every port on it.
    #[serde(default)]
    pub destination_port: Option<u16>,
    pub path_prefix: String,
    pub expires_at: Option<String>,
    pub scope: String,
}

impl ConsentGrant {
    fn applies_to(&self, event: &WitnessEvent) -> bool {
        // Fail closed: without a content hash attested for the executable,
        // a consent grant never matches, no matter what it declares.
        match event.process.executable_sha256.as_deref() {
            Some(hash) if hash == self.executable_sha256.as_str() => {}
            _ => return false,
        }
        if self.destination_host != event.network.destination.host
            || event.process.version.as_deref() != Some(self.process_version.as_str())
        {
            return false;
        }

        if let Some(port) = self.destination_port {
            if port != event.network.destination.port {
                return false;
            }
        }

        if let Some(expiry) = &self.expires_at {
            let (Ok(expiry), Ok(event_time)) = (
                parse_rfc3339_millis(expiry),
                parse_rfc3339_millis(&event.network.timestamp),
            ) else {
                return false;
            };
            if expiry < event_time {
                return false;
            }
        }

        event
            .file_events
            .iter()
            .all(|file| path_in_scope(&file.path, &self.path_prefix))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WitnessEvent {
    pub process: ProcessIdentity,
    pub network: NetworkEvent,
    pub file_events: Vec<FileEvent>,
    pub archive_created: bool,
    pub first_seen_destination: bool,
    pub consent: Option<ConsentGrant>,
}

impl WitnessEvent {
    /// Fills in the process content hash when the event source did not attest
    /// one and the executable file is readable. Evaluation should call this so
    /// consent checks bind to real file contents instead of path strings.
    pub fn resolve_executable_sha256(&mut self) {
        if self.process.executable_sha256.is_none() {
            self.process.executable_sha256 = self.process.compute_executable_sha256();
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuleConfig {
    pub sensitive_path_fragments: Vec<String>,
    pub batch_file_count: usize,
    pub high_upload_bytes: u64,
    pub sensitive_path_points: u8,
    pub batch_read_points: u8,
    pub archive_points: u8,
    pub first_seen_points: u8,
    pub high_upload_points: u8,
    pub high_risk_threshold: u8,
}

impl Default for RuleConfig {
    fn default() -> Self {
        Self {
            sensitive_path_fragments: vec![
                "/.env".into(),
                "/.git/".into(),
                "/.ssh/".into(),
                "/Library/Application Support/Google/Chrome/".into(),
                "/AppData/Local/Google/Chrome/".into(),
            ],
            batch_file_count: 2,
            high_upload_bytes: 5 * 1024 * 1024,
            sensitive_path_points: 50,
            batch_read_points: 20,
            archive_points: 30,
            first_seen_points: 15,
            high_upload_points: 10,
            high_risk_threshold: 70,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RiskSignal {
    pub code: String,
    pub points: u8,
    pub explanation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvaluationResult {
    pub risk_score: u8,
    pub signals: Vec<RiskSignal>,
    pub decision: PolicyDecision,
    pub explanation: String,
    pub consent_applied: bool,
}


fn parse_rfc3339_millis(value: &str) -> Result<i64, ()> {
    let value = value.strip_suffix('Z').ok_or(())?;
    let (date, time) = value.split_once('T').ok_or(())?;
    let mut dates = date.split('-');
    let year: i64 = dates.next().ok_or(())?.parse().map_err(|_| ())?;
    let month: u32 = dates.next().ok_or(())?.parse().map_err(|_| ())?;
    let day: u32 = dates.next().ok_or(())?.parse().map_err(|_| ())?;
    if dates.next().is_some() || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return Err(());
    }
    let mut times = time.split(':');
    let hour: u32 = times.next().ok_or(())?.parse().map_err(|_| ())?;
    let minute: u32 = times.next().ok_or(())?.parse().map_err(|_| ())?;
    let second: u32 = times.next().ok_or(())?.parse().map_err(|_| ())?;
    if times.next().is_some() || hour > 23 || minute > 59 || second > 60 {
        return Err(());
    }
    let days = days_from_civil(year, month, day)?;
    Ok(days * 86_400 + i64::from(hour) * 3_600 + i64::from(minute) * 60 + i64::from(second))
}

fn days_from_civil(year: i64, month: u32, day: u32) -> Result<i64, ()> {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let yoe = year.rem_euclid(400) as u64;
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp as u64 + 2) / 5 + day as u64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Ok((era * 146_097 + doe as i64) - 719_468)
}

pub fn evaluate_event(
    event: &WitnessEvent,
    config: &RuleConfig,
    mode: EnforcementMode,
) -> EvaluationResult {
    let mut signals = Vec::new();
    let sensitive_paths: Vec<&FileEvent> = event
        .file_events
        .iter()
        .filter(|file| is_sensitive_path(&file.path, config))
        .collect();

    if !sensitive_paths.is_empty() {
        let names = sensitive_paths
            .iter()
            .map(|file| file.path.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        signals.push(RiskSignal {
            code: "sensitive_path".into(),
            points: config.sensitive_path_points,
            explanation: format!("读取了敏感路径: {names}"),
        });
    }

    if event.file_events.len() >= config.batch_file_count {
        signals.push(RiskSignal {
            code: "batch_read".into(),
            points: config.batch_read_points,
            explanation: format!("短时间关联到 {} 个文件读取事件", event.file_events.len()),
        });
    }

    if event.archive_created {
        signals.push(RiskSignal {
            code: "archive_before_upload".into(),
            points: config.archive_points,
            explanation: "检测到文件归档行为并紧邻外部联网事件".into(),
        });
    }

    if event.first_seen_destination {
        signals.push(RiskSignal {
            code: "first_seen_destination".into(),
            points: config.first_seen_points,
            explanation: format!("目标 {} 首次出现", event.network.destination.host),
        });
    }

    if event.network.bytes_sent >= config.high_upload_bytes {
        signals.push(RiskSignal {
            code: "large_upload".into(),
            points: config.high_upload_points,
            explanation: format!("单次外发流量达到 {} bytes", event.network.bytes_sent),
        });
    }

    let risk_score = signals
        .iter()
        .map(|signal| signal.points as u16)
        .sum::<u16>()
        .min(100) as u8;
    let consent_applied = event
        .consent
        .as_ref()
        .is_some_and(|consent| consent.applies_to(event));
    let high_risk = risk_score >= config.high_risk_threshold;
    let decision = if consent_applied {
        PolicyDecision::Allow
    } else if high_risk && mode == EnforcementMode::Strict {
        PolicyDecision::Block
    } else if high_risk {
        PolicyDecision::Alert
    } else {
        PolicyDecision::Allow
    };
    let explanation = if consent_applied {
        "匹配到用户授权，允许该出站事件".into()
    } else if signals.is_empty() {
        "未命中当前规则".into()
    } else {
        signals
            .iter()
            .map(|signal| signal.explanation.as_str())
            .collect::<Vec<_>>()
            .join("；")
    };

    EvaluationResult {
        risk_score,
        signals,
        decision,
        explanation,
        consent_applied,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditRecord {
    pub event: WitnessEvent,
    pub evaluation: EvaluationResult,
    pub previous_chain_hash: Option<String>,
    pub chain_hash: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditLedger {
    pub records: Vec<AuditRecord>,
}

impl AuditLedger {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn append(&mut self, event: &WitnessEvent, evaluation: &EvaluationResult) {
        let previous_chain_hash = self.records.last().map(|record| record.chain_hash.clone());
        let material = serde_json::to_vec(&(event, evaluation, &previous_chain_hash))
            .expect("audit records must serialize");
        let chain_hash = sha256_hex(&material);
        self.records.push(AuditRecord {
            event: event.clone(),
            evaluation: evaluation.clone(),
            previous_chain_hash,
            chain_hash,
        });
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

fn is_sensitive_path(path: &str, config: &RuleConfig) -> bool {
    config
        .sensitive_path_fragments
        .iter()
        .any(|fragment| path.contains(fragment))
        || path.ends_with("/.env")
        || path.ends_with("/.git")
}

fn path_in_scope(path: &str, prefix: &str) -> bool {
    path == prefix || path.starts_with(&format!("{}/", prefix.trim_end_matches('/')))
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}
