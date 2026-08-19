/// Constants used throughout the Ramparts MCP scanner
///
/// This module centralizes commonly used constants to reduce duplication
/// and improve maintainability.
/// Default batch size for LLM API calls
pub const DEFAULT_LLM_BATCH_SIZE: usize = 10;

/// Common error and status messages
pub mod messages {
    pub const OPENAI_NOT_CONFIGURED: &str = "OpenAI API not configured, returning empty result";
    pub const YARA_PRE_SCAN_LOADED: &str = "YARA pre-scan scanner loaded successfully";
    pub const YARA_PRE_SCAN_FAILED: &str = "Failed to load YARA pre-scan scanner";
    pub const YARA_POST_SCAN_LOADED: &str = "YARA post-scan scanner loaded successfully";
    pub const YARA_POST_SCAN_FAILED: &str = "Failed to load YARA post-scan scanner";
}

/// Common HTTP and protocol constants
pub mod protocol {
    pub const USER_AGENT: &str = concat!("ramparts/", env!("CARGO_PKG_VERSION"));

    /// The MCP protocol version ramparts speaks, taken from the SDK rather
    /// than written out by hand.
    ///
    /// This string used to be pinned as `"2025-06-18"` in six places across
    /// two files, so it silently drifted from whatever the linked rmcp
    /// actually negotiates. Sourcing it from `ProtocolVersion::LATEST` means
    /// an SDK bump carries the advertised version with it — the 3.1.2 upgrade
    /// moved it to `2025-11-25` on its own.
    pub fn mcp_version() -> String {
        rmcp::model::ProtocolVersion::LATEST.to_string()
    }
}
