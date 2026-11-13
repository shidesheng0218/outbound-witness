use serde::{Deserialize, Serialize};

/// Interface to a transparency log backend (e.g., Rekor, custom log).
/// Allows the export to anchor its signature to an external, append-only registry,
/// so a third party can verify: "this export was recorded at this time in this log."
pub trait TransparencyLog: Send + Sync {
    /// Submit a signed audit record to the log. Returns a unique entry ID or error.
    /// Callers should then include this ID in the export, making the signature
    /// independently verifiable against the log.
    fn submit(&self, signed_export: &SignedExport) -> Result<TransparencyLogEntry, String>;

    /// Retrieve a previously submitted entry by ID. Used for verification.
    fn fetch(&self, entry_id: &str) -> Result<Option<TransparencyLogEntry>, String>;

    /// Public URL for the log's API (for documentation / verification steps).
    fn base_url(&self) -> &str;

    /// Name (e.g., "rekor", "custom-sigstore-log").
    fn name(&self) -> &str;
}

/// One entry in a transparency log: the exported audit, signed, and the receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransparencyLogEntry {
    /// Unique ID in the log (e.g., Rekor's "entryID").
    pub entry_id: String,
    /// When the log accepted this entry.
    pub timestamp_rfc3339: String,
    /// Merkle tree inclusion proof (digest, path, etc.). Used for independent verification.
    pub inclusion_proof: String,
    /// Public key that signed the audit (embedded in the export).
    pub public_key: String,
}

/// Signed export ready to submit to a transparency log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedExport {
    /// The export JSON (session record with signature).
    pub export_json: String,
    /// RFC 3339 timestamp when signed.
    pub signed_at: String,
    /// Ed25519 signature over the export.
    pub signature: String,
    /// Public key (hex).
    pub public_key: String,
}

/// Stub implementation: succeeds but doesn't really submit anywhere. Used for testing
/// or when transparency logs are unavailable.
pub struct StubTransparencyLog {}

impl TransparencyLog for StubTransparencyLog {
    fn submit(&self, _signed_export: &SignedExport) -> Result<TransparencyLogEntry, String> {
        Ok(TransparencyLogEntry {
            entry_id: "stub-entry-123".into(),
            timestamp_rfc3339: "2025-01-01T00:00:00Z".into(),
            inclusion_proof: "stub".into(),
            public_key: "stub".into(),
        })
    }

    fn fetch(&self, _entry_id: &str) -> Result<Option<TransparencyLogEntry>, String> {
        Ok(None)
    }

    fn base_url(&self) -> &str {
        "https://transparency-log.local (stub)"
    }

    fn name(&self) -> &str {
        "stub-transparency-log"
    }
}

/// Rekor integration: submits & retrieves entries from the Sigstore transparency log.
/// Requires network access. Entry IDs are UUIDs returned by Rekor.
///
/// This is a reference implementation; real Rekor clients use the official SDK.
/// Currently gated behind manual feature flag (not in Cargo.toml yet).
#[allow(dead_code)]
pub struct RekorClient {
    base_url: String,
}

#[allow(dead_code)]
impl RekorClient {
    pub fn new(base_url: String) -> Self {
        Self { base_url }
    }
}

impl TransparencyLog for RekorClient {
    fn submit(&self, _signed_export: &SignedExport) -> Result<TransparencyLogEntry, String> {
        // TODO: POST to Rekor API
        Err("rekor integration not yet implemented".into())
    }

    fn fetch(&self, entry_id: &str) -> Result<Option<TransparencyLogEntry>, String> {
        // TODO: GET from Rekor API
        Err(format!("fetch {entry_id} from Rekor not yet implemented"))
    }

    fn base_url(&self) -> &str {
        &self.base_url
    }

    fn name(&self) -> &str {
        "rekor"
    }
}

/// Helper: export a signed audit to a transparency log and update the export
/// with the receipt. Decoupled from main export logic so it can be added incrementally.
pub fn publish_to_transparency_log(
    export: &mut crate::session::SessionRecord,
    log: &dyn TransparencyLog,
) -> Result<(), String> {
    if export.signature.is_none() {
        return Err("export must be signed before publishing to transparency log".into());
    }

    let signed_export = SignedExport {
        export_json: serde_json::to_string(export)
            .map_err(|e| format!("failed to serialize export: {e}"))?,
        signed_at: export
            .signature
            .as_ref()
            .and_then(|sig| sig.signed_at.clone())
            .unwrap_or_else(|| "unknown".to_string()),
        signature: export
            .signature
            .as_ref()
            .map(|sig| sig.value.clone())
            .unwrap_or_default(),
        public_key: export
            .signature
            .as_ref()
            .map(|sig| sig.public_key.clone())
            .unwrap_or_default(),
    };

    let entry = log.submit(&signed_export)?;
    if let Some(sig) = export.signature.as_mut() {
        sig.log_entry_id = Some(entry.entry_id);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_transparency_log_always_succeeds() {
        let log = StubTransparencyLog {};
        let export = SignedExport {
            export_json: "{}".into(),
            signed_at: "2025-01-01T00:00:00Z".into(),
            signature: "sig".into(),
            public_key: "key".into(),
        };
        let entry = log.submit(&export).expect("stub should not fail");
        assert!(!entry.entry_id.is_empty());
    }
}
