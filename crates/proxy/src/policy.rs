use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, SystemTime};

/// Policy-driven credential broker: controls what the agent can do with injected
/// credentials. Replaces the narrow "inject header" model with proper authorization.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BrokerPolicy {
    /// Route this policy protects (e.g., "cloud", "openai", "aws").
    pub route: String,

    /// Upstream host (e.g., "api.openai.com"). Agent cannot redirect.
    pub upstream_host: String,
    pub upstream_port: u16,

    /// HTTP methods the agent is allowed to use with this route.
    /// Empty means all methods. Common: ["POST"] for API calls, ["GET"] for reads.
    #[serde(default)]
    pub allowed_methods: Vec<String>,

    /// URL path prefixes the agent can access. Empty means all paths.
    /// Example: ["/v1/chat/completions", "/v1/embeddings"]
    #[serde(default)]
    pub allowed_paths: Vec<String>,

    /// Max bytes the agent can send per time window (budget). Prevents
    /// silently exfiltrating the entire codebase.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_bytes_per_hour: Option<u64>,

    /// Max requests per time window. Prevents DoS or repeated exfil attempts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_requests_per_minute: Option<u32>,

    /// If true, response bodies are scrubbed from logs/audit. Used for sensitive
    /// payloads where we log the request but not the answer.
    #[serde(default)]
    pub redact_response_body: bool,

    /// If true, request body is hashed (for dedup) but not logged verbatim.
    /// Prevents credentials or prompts appearing in plaintext audit files.
    #[serde(default)]
    pub hash_request_body: bool,

    /// TTL for credentials injected via this route. Prevents long-lived
    /// tokens from accumulating risk. None = no expiry (use with caution).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_ttl_seconds: Option<u64>,

    /// Bound to a specific process image SHA-256 (like consent grants).
    /// Only the named executable can use this credential.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_sha256: Option<String>,
}

impl BrokerPolicy {
    /// Check if the given request (method, path, byte count) is allowed under this policy.
    pub fn allows_request(&self, method: &str, path: &str, _bytes_sent: u64) -> Result<(), String> {
        if !self.allowed_methods.is_empty() && !self.allowed_methods.contains(&method.to_string()) {
            return Err(format!(
                "broker policy forbids method {} (allowed: {})",
                method,
                self.allowed_methods.join(",")
            ));
        }

        if !self.allowed_paths.is_empty()
            && !self
                .allowed_paths
                .iter()
                .any(|prefix| path.starts_with(prefix))
        {
            return Err(format!(
                "broker policy forbids path {} (allowed: {})",
                path,
                self.allowed_paths.join(",")
            ));
        }

        // Budget checking would go here, but requires state (request count, bytes this hour).
        // For now, this is the structure.
        Ok(())
    }
}

/// Budget tracking for a single route+credential pair. Enforced per session.
#[derive(Debug, Clone, Default)]
pub struct RouteBudget {
    /// Last reset time.
    pub last_reset: Option<SystemTime>,
    /// Cumulative bytes sent this window.
    pub bytes_sent_this_window: u64,
    /// Request count this minute.
    pub requests_this_minute: u32,
}

impl RouteBudget {
    /// Check if adding `bytes` would exceed the hourly limit. Does NOT consume budget.
    pub fn would_exceed_hourly(&self, bytes: u64, limit: u64) -> bool {
        self.bytes_sent_this_window.saturating_add(bytes) > limit
    }

    /// Check if a new request would exceed per-minute rate. Does NOT consume budget.
    pub fn would_exceed_rate(&self, limit: u32) -> bool {
        self.requests_this_minute >= limit
    }

    /// Consume bytes and increment request count. Caller should have checked limits first.
    pub fn consume(&mut self, bytes: u64) {
        self.bytes_sent_this_window = self.bytes_sent_this_window.saturating_add(bytes);
        self.requests_this_minute = self.requests_this_minute.saturating_add(1);
    }

    /// Reset budgets if the window has elapsed.
    pub fn reset_if_expired(&mut self) {
        let now = SystemTime::now();
        if let Some(last) = self.last_reset {
            if now.duration_since(last).unwrap_or(Duration::MAX) > Duration::from_secs(3600) {
                self.bytes_sent_this_window = 0;
                self.requests_this_minute = 0;
                self.last_reset = Some(now);
            }
        } else {
            self.last_reset = Some(now);
        }
    }
}

/// Runtime broker state: policies + live budget tracking.
pub struct PolicyBroker {
    policies: HashMap<String, BrokerPolicy>,
    budgets: HashMap<String, RouteBudget>,
}

impl PolicyBroker {
    pub fn new() -> Self {
        Self {
            policies: HashMap::new(),
            budgets: HashMap::new(),
        }
    }

    pub fn add_policy(&mut self, policy: BrokerPolicy) {
        let route = policy.route.clone();
        self.policies.insert(route.clone(), policy);
        self.budgets.insert(route, RouteBudget::default());
    }

    /// Authorize a request: check policy + budget. Returns error if denied.
    pub fn authorize(
        &mut self,
        route: &str,
        method: &str,
        path: &str,
        bytes: u64,
    ) -> Result<(), String> {
        let policy = self
            .policies
            .get(route)
            .ok_or_else(|| format!("unknown route: {route}"))?
            .clone();

        policy.allows_request(method, path, bytes)?;

        if let Some(budget) = self.budgets.get_mut(route) {
            budget.reset_if_expired();
            if let Some(limit) = policy.max_bytes_per_hour {
                if budget.would_exceed_hourly(bytes, limit) {
                    return Err(format!(
                        "route {route} budget exceeded: {}/{} bytes",
                        budget.bytes_sent_this_window, limit
                    ));
                }
            }
            if let Some(limit) = policy.max_requests_per_minute {
                if budget.would_exceed_rate(limit) {
                    return Err(format!(
                        "route {route} rate limit: {} req/min",
                        budget.requests_this_minute
                    ));
                }
            }
            budget.consume(bytes);
        }
        Ok(())
    }
}

impl Default for PolicyBroker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_enforces_allowed_methods() {
        let policy = BrokerPolicy {
            route: "openai".into(),
            upstream_host: "api.openai.com".into(),
            upstream_port: 443,
            allowed_methods: vec!["POST".into()],
            allowed_paths: vec!["/v1/chat/completions".into()],
            max_bytes_per_hour: None,
            max_requests_per_minute: None,
            redact_response_body: false,
            hash_request_body: false,
            credential_ttl_seconds: None,
            process_sha256: None,
        };
        assert!(policy
            .allows_request("POST", "/v1/chat/completions", 100)
            .is_ok());
        assert!(policy
            .allows_request("GET", "/v1/chat/completions", 100)
            .is_err());
    }

    #[test]
    fn budget_tracking() {
        let mut budget = RouteBudget::default();
        let limit = 1000;
        assert!(!budget.would_exceed_hourly(500, limit));
        budget.consume(500);
        assert!(!budget.would_exceed_hourly(400, limit));
        assert!(budget.would_exceed_hourly(600, limit));
    }
}
