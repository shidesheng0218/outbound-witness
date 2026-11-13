use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::Path;

pub mod events;
pub mod platform;
pub mod session;
pub mod transparency;
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
#[serde(deny_unknown_fields)]
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable_sha256: Option<String>,
}

impl ProcessIdentity {
    /// Hashes the executable file contents (not the path). Returns `None`
    /// when the file cannot be read, so callers never fall back to a weaker
    /// path-string comparison by accident.
    pub fn compute_executable_sha256(&self) -> Option<String> {
        sha256_file(Path::new(&self.executable)).ok()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Destination {
    pub host: String,
    pub ip: Option<String>,
    pub port: u16,
    pub protocol: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NetworkEvent {
    pub destination: Destination,
    pub bytes_sent: u64,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FileEvent {
    pub path: String,
    pub kind: FileEventKind,
    pub bytes: u64,
    pub sha256: Option<String>,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConsentGrant {
    pub executable_sha256: String,
    pub process_version: String,
    pub destination_host: String,
    /// Port the consent is bound to. Grants written before port binding
    /// existed deserialize as `None`, which keeps the historical wildcard
    /// behaviour (any port on `destination_host`). Every grant produced by
    /// the CLI now carries the port of the approved request, so approving a
    /// host can no longer silently authorise every port on it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
#[serde(deny_unknown_fields)]
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

    /// Constructs a witness event from a file access and the current network intent.
    /// Used to link file activity to the network decision that follows it.
    pub fn from_file_and_network(
        file: &crate::events::FileAccessEvent,
        network: &NetworkEvent,
        process: ProcessIdentity,
        archive_created: bool,
        first_seen: bool,
    ) -> Self {
        Self {
            process,
            network: network.clone(),
            file_events: vec![FileEvent {
                path: file.path.clone(),
                kind: match file.operation {
                    crate::events::FileOperation::Read => FileEventKind::Read,
                    crate::events::FileOperation::Execute => FileEventKind::Read,
                    crate::events::FileOperation::Write => FileEventKind::Read,
                    crate::events::FileOperation::Delete => FileEventKind::Read,
                },
                bytes: file.bytes_transferred,
                sha256: file.sha256.clone(),
                timestamp: format_timestamp_ms(file.timestamp_ms),
            }],
            archive_created,
            first_seen_destination: first_seen,
            consent: None,
        }
    }
}

fn format_timestamp_ms(ms: u64) -> String {
    // Convert ms since epoch to RFC 3339 string. Naive implementation for now;
    // in production would use chrono or time crate.
    let secs = ms / 1000;
    let millis = ms % 1000;
    format!("1970-01-01T00:00:{:02}.{:03}Z", secs % 60, millis)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct RiskSignal {
    pub code: String,
    pub points: u8,
    pub explanation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvaluationResult {
    pub risk_score: u8,
    pub signals: Vec<RiskSignal>,
    pub decision: PolicyDecision,
    pub explanation: String,
    pub consent_applied: bool,
}

fn parse_rfc3339_millis(value: &str) -> Result<i64, ()> {
    let value = value.trim();
    let (datetime, offset_seconds) = split_offset(value)?;
    let (date, time) = datetime.split_once('T').ok_or(())?;
    let mut dates = date.split('-');
    let year: i64 = dates.next().ok_or(())?.parse().map_err(|_| ())?;
    let month: u32 = dates.next().ok_or(())?.parse().map_err(|_| ())?;
    let day: u32 = dates.next().ok_or(())?.parse().map_err(|_| ())?;
    if dates.next().is_some()
        || !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
    {
        return Err(());
    }
    let mut times = time.split(':');
    let hour: u32 = times.next().ok_or(())?.parse().map_err(|_| ())?;
    let minute: u32 = times.next().ok_or(())?.parse().map_err(|_| ())?;
    let second_field = times.next().ok_or(())?;
    if times.next().is_some() {
        return Err(());
    }
    let (second_text, fraction) = match second_field.split_once('.') {
        Some((second, fraction)) => (second, Some(fraction)),
        None => (second_field, None),
    };
    let second: u32 = second_text.parse().map_err(|_| ())?;
    if let Some(fraction) = fraction {
        if fraction.is_empty() || !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(());
        }
    }
    if hour > 23 || minute > 59 || second > 60 {
        return Err(());
    }
    let days = days_from_civil(year, month, day)?;
    Ok(
        days * 86_400 + i64::from(hour) * 3_600 + i64::from(minute) * 60 + i64::from(second)
            - offset_seconds,
    )
}

/// Splits an RFC3339 timestamp into its local date/time part and the UTC offset
/// in seconds. Fractional seconds are handled by the caller; offsets accept
/// `Z`, `+08:00`, `-05:00`, and the compact `+0800` form.
fn split_offset(value: &str) -> Result<(&str, i64), ()> {
    if let Some(value) = value.strip_suffix('Z').or_else(|| value.strip_suffix('z')) {
        return Ok((value, 0));
    }
    let time_start = value.find('T').ok_or(())? + 1;
    let offset_index = value[time_start..].rfind(['+', '-']).ok_or(())?;
    let (datetime, offset) = value.split_at(time_start + offset_index);
    let sign = if offset.starts_with('-') { -1 } else { 1 };
    let offset = &offset[1..];
    let (hour, minute) = if let Some((hour, minute)) = offset.split_once(':') {
        (hour, minute)
    } else if offset.len() == 4 {
        (&offset[..2], &offset[2..])
    } else {
        return Err(());
    };
    if hour.len() != 2
        || minute.len() != 2
        || !hour.bytes().all(|byte| byte.is_ascii_digit())
        || !minute.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(());
    }
    let hour: u32 = hour.parse().map_err(|_| ())?;
    let minute: u32 = minute.parse().map_err(|_| ())?;
    if hour > 23 || minute > 59 {
        return Err(());
    }
    Ok((datetime, sign * i64::from(hour * 3_600 + minute * 60)))
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        _ => 0,
    }
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
#[serde(deny_unknown_fields)]
pub struct AuditRecord {
    pub event: WitnessEvent,
    pub evaluation: EvaluationResult,
    pub previous_chain_hash: Option<String>,
    pub chain_hash: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
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

    /// Re-derives the ledger chain without trusting the process that produced
    /// it. A changed, reordered, or removed middle record breaks the chain;
    /// trailing truncation still needs a trusted signature or external anchor,
    /// exactly like the session ledger.
    pub fn verify_chain(&self) -> Result<(), (usize, String)> {
        let mut previous: Option<String> = None;
        for (index, record) in self.records.iter().enumerate() {
            if record.previous_chain_hash.as_ref() != previous.as_ref() {
                return Err((index, "previous_chain_hash 与上一条记录不匹配".to_string()));
            }
            let material = serde_json::to_vec(&(&record.event, &record.evaluation, &previous))
                .expect("audit records must serialize");
            let expected = sha256_hex(&material);
            if record.chain_hash != expected {
                return Err((index, "chain_hash 与记录内容不匹配".to_string()));
            }
            previous = Some(expected);
        }
        Ok(())
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

/// Hashes a file without loading it into memory, so snapshotting a large
/// workspace cannot exhaust the host just to compute a diff.
pub fn sha256_file(path: &Path) -> std::io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::parse_rfc3339_millis;

    #[test]
    fn parses_fractional_seconds_and_timezone_offsets() {
        let base = parse_rfc3339_millis("2026-09-22T09:00:00Z").expect("base timestamp");
        assert_eq!(
            parse_rfc3339_millis("2026-09-22T09:00:00.123Z").expect("fractional timestamp"),
            base
        );
        assert_eq!(
            parse_rfc3339_millis("2026-09-22T17:00:00+08:00").expect("offset timestamp"),
            base
        );
        assert_eq!(
            parse_rfc3339_millis("2026-09-22T04:00:00-05:00").expect("negative offset"),
            base
        );
        assert_eq!(
            parse_rfc3339_millis("2026-09-22T17:00:00+0800").expect("compact offset"),
            base
        );
        assert!(parse_rfc3339_millis("2026-09-22T09:00:00").is_err());
        assert!(parse_rfc3339_millis("2026-09-22T09:00:00+08").is_err());
        assert!(parse_rfc3339_millis("2026-09-22T09:00:00.abcZ").is_err());
        assert!(parse_rfc3339_millis("2026-02-31T09:00:00Z").is_err());
        assert!(parse_rfc3339_millis("2026-02-29T09:00:00Z").is_err());
        assert!(parse_rfc3339_millis("2024-02-29T09:00:00Z").is_ok());
    }
}
