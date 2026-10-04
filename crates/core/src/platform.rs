use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PlatformCapabilities {
    pub os: String,
    pub network_adapter: String,
    pub file_adapter: String,
    pub kernel_enforcement_claimed: bool,
    pub notes: Vec<String>,
}

/// Returns the conservative capability statement shown to users and the CLI.
/// The portable core never claims native enforcement until a platform adapter
/// has been installed and positively reports that it is active.
pub fn current_capabilities() -> PlatformCapabilities {
    let os = std::env::consts::OS.to_string();
    let (network_adapter, file_adapter, notes) = match os.as_str() {
        "macos" => (
            "macos-network-adapter (scaffold)".into(),
            "macos-file-adapter (scaffold)".into(),
            vec![
                "portable event ingestion is active".into(),
                "native Network Extension and Endpoint Security wiring is not claimed yet".into(),
            ],
        ),
        "windows" => (
            "windows-network-adapter (scaffold)".into(),
            "windows-file-adapter (scaffold)".into(),
            vec![
                "portable event ingestion is active".into(),
                "native WFP and file minifilter wiring is not claimed yet".into(),
            ],
        ),
        other => (
            format!("{other}-network-adapter (portable)"),
            format!("{other}-file-adapter (portable)"),
            vec!["portable event ingestion only".into()],
        ),
    };

    PlatformCapabilities {
        os,
        network_adapter,
        file_adapter,
        kernel_enforcement_claimed: false,
        notes,
    }
}
