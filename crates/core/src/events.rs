use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::SystemTime;

/// Runtime source for file/process events. Implementations can range from
/// stubs (sampling, testing) to kernel-level (eBPF, ESF, ETW).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventSource {
    /// Stub (for testing or when the OS has no observer).
    #[serde(rename = "stub")]
    Stub,
    /// eBPF (Linux).
    #[serde(rename = "ebpf")]
    EbpfLinux,
    /// EndpointSecurity (macOS).
    #[serde(rename = "endpoint_security")]
    EndpointSecurity,
    /// Event Tracing for Windows.
    #[serde(rename = "etw")]
    ETW,
}

impl EventSource {
    /// Human-readable name suitable for diagnostics and audit logs.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Stub => "stub",
            Self::EbpfLinux => "ebpf",
            Self::EndpointSecurity => "endpoint-security",
            Self::ETW => "etw",
        }
    }

    /// Whether this source is backed by kernel/OS infrastructure vs. user-space heuristics.
    pub fn is_kernel_backed(&self) -> bool {
        !matches!(self, Self::Stub)
    }
}

/// A single file access observed during a session. May come from eBPF, ESF, or be inferred
/// from snapshot deltas. File paths are always absolute or workspace-relative.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FileAccessEvent {
    /// Absolute path or workspace-relative path, depending on source.
    pub path: String,
    /// Read, Write, Execute, or Delete.
    pub operation: FileOperation,
    /// Size of data accessed (bytes read or written), 0 if not applicable.
    pub bytes_transferred: u64,
    /// SHA-256 of file contents (if read and hash was computed), for dedup & forensics.
    pub sha256: Option<String>,
    /// Milliseconds since Unix epoch.
    pub timestamp_ms: u64,
    /// Process that performed the access (PID, name, etc.). `None` means unknown/inferred.
    pub process: Option<ProcessContext>,
    /// Which observer/source recorded this event.
    pub source: EventSource,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub enum FileOperation {
    #[serde(rename = "read")]
    Read,
    #[serde(rename = "write")]
    Write,
    #[serde(rename = "execute")]
    Execute,
    #[serde(rename = "delete")]
    Delete,
}

/// Minimal process context at the time of a file access, for linking file & network events.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProcessContext {
    pub pid: u32,
    pub name: String,
    pub uid: Option<u32>,
}

/// Aggregate file activity within a session: all reads, writes, archives, and which
/// paths were touched. Updated incrementally as Session progresses.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FileActivityRecord {
    /// All observed file accesses, indexed by path for fast lookup.
    pub accesses: BTreeMap<String, Vec<FileAccessEvent>>,
    /// If true, an archive (zip, tar, etc.) was detected or created; indicates potential data exfil preparation.
    pub archive_detected: bool,
    /// Source of archive detection (e.g., "process name match" or "magic bytes").
    pub archive_source: Option<String>,
    /// Total bytes read across all accesses.
    pub total_bytes_read: u64,
    /// Highest-risk path fragments observed (sorted by sensitivity score).
    pub sensitive_paths_touched: Vec<(String, u8)>,
}

impl FileActivityRecord {
    /// Record a file access, merging with existing entries for the same path.
    pub fn record(&mut self, event: FileAccessEvent) {
        self.total_bytes_read += event.bytes_transferred;
        self.accesses
            .entry(event.path.clone())
            .or_insert_with(Vec::new)
            .push(event);
    }

    /// Check if a sensitive path fragment was touched, return count and earliest timestamp.
    pub fn touched_sensitive(&self, sensitive_patterns: &[String]) -> Vec<(String, usize)> {
        self.accesses
            .keys()
            .filter_map(|path| {
                for pattern in sensitive_patterns {
                    if path.contains(pattern) {
                        let count = self.accesses[path].len();
                        return Some((path.clone(), count));
                    }
                }
                None
            })
            .collect()
    }

    /// Summarize for audit: how many files accessed, which operations, any risky signals.
    pub fn summary(&self) -> String {
        let read_count = self
            .accesses
            .values()
            .flat_map(|events| {
                events
                    .iter()
                    .filter(|e| matches!(e.operation, FileOperation::Read))
            })
            .count();
        let write_count = self
            .accesses
            .values()
            .flat_map(|events| {
                events
                    .iter()
                    .filter(|e| matches!(e.operation, FileOperation::Write))
            })
            .count();
        let archive = if self.archive_detected {
            "; archive detected"
        } else {
            ""
        };
        format!(
            "{} files: {} reads, {} writes{}",
            self.accesses.len(),
            read_count,
            write_count,
            archive
        )
    }
}

/// Observer trait: abstracts over eBPF, EndpointSecurity, ETW, or stub implementations.
/// Implementations can be swapped without changing session or evaluation logic.
pub trait EventObserver: Send + Sync {
    /// Start observing the given PID. Called when Session's proxy container starts.
    fn attach(&mut self, pid: u32) -> Result<(), String>;

    /// Stop observing. Called when Session exits.
    fn detach(&mut self) -> Result<(), String>;

    /// Poll for new events. Called periodically or on-demand by session runtime.
    /// Returns newly observed file/process events since last poll.
    fn poll(&mut self) -> Result<Vec<FileAccessEvent>, String>;

    /// Which event source is this observer backed by.
    fn source(&self) -> EventSource;

    /// Human-readable name for logs/diagnostics.
    fn name(&self) -> &str;

    /// Whether this observer is currently attached and working.
    fn is_active(&self) -> bool;
}

/// Stub implementation: returns no events. Used when OS support is unavailable or for testing.
pub struct StubObserver {
    active: bool,
}

impl StubObserver {
    pub fn new() -> Self {
        Self { active: false }
    }
}

impl Default for StubObserver {
    fn default() -> Self {
        Self::new()
    }
}

impl EventObserver for StubObserver {
    fn attach(&mut self, _pid: u32) -> Result<(), String> {
        self.active = true;
        Ok(())
    }

    fn detach(&mut self) -> Result<(), String> {
        self.active = false;
        Ok(())
    }

    fn poll(&mut self) -> Result<Vec<FileAccessEvent>, String> {
        Ok(Vec::new())
    }

    fn source(&self) -> EventSource {
        EventSource::Stub
    }

    fn name(&self) -> &str {
        "stub-observer"
    }

    fn is_active(&self) -> bool {
        self.active
    }
}
