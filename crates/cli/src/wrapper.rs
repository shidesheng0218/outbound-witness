use std::path::PathBuf;

/// CLI wrapper that intercepts arbitrary commands and runs them inside a
/// managed Session. The wrapper handles:
/// - Session lifecycle (start, monitor, export, cleanup)
/// - Credential injection via Broker
/// - Approval delegation to system UI
/// - Event observation (if observer is available)
///
/// Usage:
///   outbound-witness run [OPTIONS] -- <command> [args]
///
/// Or as shebang for scripting:
///   #!/usr/bin/env outbound-witness-run
///   cd /workspace && claude-dev analyze --deep
///
/// This replaces the need to manually call `session start` and manages
/// the full lifecycle transparently.
pub struct SessionWrapper {
    workspace: PathBuf,
    command: Vec<String>,
    mode: String,
    allowed_hosts: Vec<String>,
    credential_routes: Option<PathBuf>,
    observer_enabled: bool,
    state_dir: Option<PathBuf>,
}

impl SessionWrapper {
    /// Create a new wrapper from CLI args. Typically called from `run` subcommand.
    pub fn from_args(
        workspace: PathBuf,
        command: Vec<String>,
        mode: String,
        allowed_hosts: Vec<String>,
    ) -> Self {
        Self {
            workspace,
            command,
            mode,
            allowed_hosts,
            credential_routes: None,
            observer_enabled: false,
            state_dir: None,
        }
    }

    /// Enable the file observer (if available for this OS).
    pub fn with_observer(mut self) -> Self {
        self.observer_enabled = true;
        self
    }

    /// Set the credential broker routes file.
    pub fn with_credentials(mut self, path: PathBuf) -> Self {
        self.credential_routes = Some(path);
        self
    }

    /// Set the state directory (defaults to .outbound-witness/sessions).
    pub fn with_state_dir(mut self, path: PathBuf) -> Self {
        self.state_dir = Some(path);
        self
    }

    /// Execute the command inside a managed Session. Returns exit code.
    ///
    /// Steps:
    /// 1. Create & prepare Session (snapshot, proxy, observer if enabled)
    /// 2. Spawn command subprocess with proxy env vars
    /// 3. Poll observer, approve requests as needed
    /// 4. On command exit: collect evidence, export audit, cleanup
    ///
    /// If anything fails, cleans up and returns error exit code (1).
    pub fn run(&self) -> i32 {
        // TODO: implement full wrapper logic
        // For now, this is the stub showing structure.
        eprintln!("SessionWrapper::run() – not yet implemented");
        1
    }

    /// Test-friendly: dry run, print what would happen without executing.
    pub fn dry_run(&self) {
        eprintln!("SessionWrapper dry run:");
        eprintln!("  workspace: {}", self.workspace.display());
        eprintln!("  command: {}", self.command.join(" "));
        eprintln!("  mode: {}", self.mode);
        eprintln!("  allowed_hosts: {:?}", self.allowed_hosts);
        eprintln!("  observer: {}", self.observer_enabled);
    }
}

/// Alternative entry point: shebang wrapper that reads the first line
/// of a script and wraps the rest. Used for minimal-friction agent scripts.
///
/// Example script:
///   #!/usr/bin/env outbound-witness-run
///   # outbound-witness: mode=strict, hosts=api.openai.com:443
///   python3 -m agent analyze_repo.py
///
/// The wrapper parses the directive comment, extracts config, then wraps
/// the script body in a Session.
pub fn parse_shebang_directive(line: &str) -> Result<ShebangConfig, String> {
    let line = line.trim();
    if !line.starts_with("# outbound-witness:") {
        return Err("not an outbound-witness shebang".into());
    }
    let rest = &line[19..]; // skip "# outbound-witness:"
    let mut config = ShebangConfig::default();

    for part in rest.split(',') {
        let part = part.trim();
        if let Some((key, value)) = part.split_once('=') {
            match key.trim() {
                "mode" => config.mode = value.trim().to_string(),
                "hosts" => {
                    for host in value.split(';') {
                        config.allowed_hosts.push(host.trim().to_string());
                    }
                }
                "observer" => config.observer_enabled = value.trim() == "true",
                _ => {} // ignore unknown keys
            }
        }
    }
    Ok(config)
}

#[derive(Debug, Default)]
pub struct ShebangConfig {
    pub mode: String,
    pub allowed_hosts: Vec<String>,
    pub observer_enabled: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shebang_parsing() {
        let directive =
            "# outbound-witness: mode=strict, hosts=api.openai.com:443;api.anthropic.com:443";
        let config = parse_shebang_directive(directive).expect("should parse");
        assert_eq!(config.mode, "strict");
        assert_eq!(config.allowed_hosts.len(), 2);
        assert_eq!(config.allowed_hosts[0], "api.openai.com:443");
    }
}
