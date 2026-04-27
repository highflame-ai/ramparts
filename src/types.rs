use crate::security::SecurityScanResult;
use crate::taxonomy::OwaspTag;
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Original YARA rule metadata from the rule definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraRuleMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<String>,
    // `default` is required so `replay` can read JSON we previously wrote
    // — `skip_serializing_if` omits the field when empty, and without
    // `default` deserialization fails on the missing key.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

/// Result of a YARA scan operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraScanResult {
    pub target_type: String, // "tool", "prompt", "resource"
    pub target_name: String,
    pub rule_name: String, // The actual YARA rule name (e.g., "EnvironmentVariableLeakage")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_file: Option<String>, // The rule file name (e.g., "secrets_leakage")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_text: Option<String>,
    pub context: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_metadata: Option<YaraRuleMetadata>,
    /// OWASP MCP Top 10 categories this finding maps to. Populated from the
    /// rule name via `taxonomy::tags_for_yara_rule`. Empty when no mapping
    /// exists yet for the rule — the finding is still reported.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub owasp_tags: Vec<OwaspTag>,
    // Execution summary fields (when target_type is "summary")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phase: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rules_executed: Option<Vec<String>>, // Rules executed (format: "filename:rulename" or just "filename" for file-level)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_issues_detected: Option<Vec<String>>, // Rules that detected issues (format: "filename:rulename")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_items_scanned: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_matches: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>, // "success", "warning", "error"
}

// ============================================================================
// CORE TYPES - Main data structures for MCP scanning
// ============================================================================

/// Configuration builder for scan options
#[derive(Debug, Clone)]
pub struct ScanConfigBuilder {
    timeout: u64,
    http_timeout: u64,
    detailed: bool,
    format: String,
    auth_headers: Option<HashMap<String, String>>,
    // When true, do not call the LLM; instead, return the prompts that would be used
    return_prompts: bool,
    only: Option<Vec<ArtifactKind>>,
}

impl Default for ScanConfigBuilder {
    fn default() -> Self {
        Self {
            timeout: 60,
            http_timeout: 30,
            detailed: false,
            format: "text".to_string(),
            auth_headers: None,
            return_prompts: false,
            only: None,
        }
    }
}

impl ScanConfigBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn timeout(mut self, timeout: u64) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn http_timeout(mut self, http_timeout: u64) -> Self {
        self.http_timeout = http_timeout;
        self
    }

    pub fn detailed(mut self, detailed: bool) -> Self {
        self.detailed = detailed;
        self
    }

    pub fn format(mut self, format: String) -> Self {
        self.format = format;
        self
    }

    pub fn auth_headers(mut self, auth_headers: Option<HashMap<String, String>>) -> Self {
        self.auth_headers = auth_headers;
        self
    }

    pub fn return_prompts(mut self, return_prompts: bool) -> Self {
        self.return_prompts = return_prompts;
        self
    }

    pub fn only(mut self, only: Option<Vec<ArtifactKind>>) -> Self {
        self.only = only;
        self
    }

    pub fn build(self) -> ScanOptions {
        ScanOptions {
            timeout: self.timeout,
            http_timeout: self.http_timeout,
            detailed: self.detailed,
            format: self.format,
            auth_headers: self.auth_headers,
            return_prompts: self.return_prompts,
            only: self.only,
        }
    }
}

/// Configuration validation utilities
pub mod config_utils {
    use super::{Result, ScanOptions};

    pub fn validate_scan_config(options: &ScanOptions) -> Result<()> {
        if options.timeout == 0 {
            return Err(anyhow::anyhow!("Timeout must be greater than 0"));
        }

        if options.http_timeout == 0 {
            return Err(anyhow::anyhow!("HTTP timeout must be greater than 0"));
        }

        if options.timeout < options.http_timeout {
            return Err(anyhow::anyhow!(
                "Total timeout must be greater than or equal to HTTP timeout"
            ));
        }

        Ok(())
    }
}

/// Which artifact kinds (tools, prompts, resources) a scan covers. When
/// `None`, every kind is included. When `Some`, the scan keeps only the
/// listed kinds and discards the others before security analysis runs —
/// see ramparts `--only` flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArtifactKind {
    Tools,
    Prompts,
    Resources,
}

impl ArtifactKind {
    /// Parse a CLI value like `"tools,prompts"` into a set of kinds.
    /// Returns an error on unknown tokens so a typo doesn't silently
    /// turn into "scan everything".
    pub fn parse_set(raw: &str) -> Result<Vec<Self>> {
        let mut out = Vec::new();
        for token in raw.split(',') {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }
            let kind = match token.to_ascii_lowercase().as_str() {
                "tool" | "tools" => ArtifactKind::Tools,
                "prompt" | "prompts" => ArtifactKind::Prompts,
                "resource" | "resources" => ArtifactKind::Resources,
                other => {
                    return Err(anyhow::anyhow!(
                        "Unknown artifact kind '{other}' in --only. \
                         Expected: tools, prompts, resources (comma-separated)"
                    ))
                }
            };
            if !out.contains(&kind) {
                out.push(kind);
            }
        }
        Ok(out)
    }
}

/// Scan options configuration
#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub timeout: u64,
    pub http_timeout: u64,
    pub detailed: bool,
    pub format: String,
    pub auth_headers: Option<HashMap<String, String>>,
    /// When true, do not call the LLM; instead, return prompts to the caller
    pub return_prompts: bool,
    /// Restrict the scan to a subset of artifact kinds. `None` = scan all.
    /// Set via the `--only` CLI flag; see `ArtifactKind::parse_set`.
    pub only: Option<Vec<ArtifactKind>>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            timeout: 60,
            http_timeout: 30,
            detailed: false,
            format: "text".to_string(),
            auth_headers: None,
            return_prompts: false,
            only: None,
        }
    }
}

/// Main scan result structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub url: String,
    pub status: ScanStatus,
    pub timestamp: DateTime<Utc>,
    pub response_time_ms: u64,
    pub server_info: Option<MCPServerInfo>,
    pub tools: Vec<MCPTool>,
    pub resources: Vec<MCPResource>,
    pub prompts: Vec<MCPPrompt>,
    pub security_issues: Option<SecurityScanResult>,
    pub yara_results: Vec<YaraScanResult>,
    pub errors: Vec<String>,
    /// Ramparts release version that produced this scan
    /// (`env!("CARGO_PKG_VERSION")`). Useful for triage when an
    /// archived JSON / replayed scan turns up months later — the
    /// reader can correlate detections to a specific scanner build.
    #[serde(default)]
    pub ramparts_version: String,
    /// Short git commit ramparts was built from (e.g. `c70cdce`).
    /// Empty when built outside a git checkout.
    #[serde(default)]
    pub ramparts_commit: String,
    /// IDE source that provided this server configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ide_source: Option<String>,
    /// If set, LLM calls were deferred and these are the prompts per batch
    #[serde(skip_serializing_if = "Option::is_none")]
    pub llm_prompts: Option<Vec<LlmPrompt>>,
}

/// Exported prompt bundle for deferring LLM calls to the caller
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmPrompt {
    /// One of: "tool", "prompt", "resource"
    pub target_type: String,
    /// Zero-based batch index
    pub batch_index: usize,
    /// The full prompt text that would be sent to the LLM
    pub prompt: String,
    /// Full request body that Ramparts would send to the LLM API (OpenAI-compatible)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_body: Option<serde_json::Value>,
    /// The LLM endpoint that would be used (if configured)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// Names of items included in this batch (tool names, prompt names, or resource names)
    pub item_names: Vec<String>,
}

/// Scan status enumeration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScanStatus {
    Success,
    Failed(String),
    Timeout,
    ConnectionError(String),
    AuthenticationError(String),
}

impl ScanResult {
    pub fn new(url: String) -> Self {
        Self {
            url,
            status: ScanStatus::Success,
            timestamp: Utc::now(),
            response_time_ms: 0,
            server_info: None,
            tools: Vec::new(),
            resources: Vec::new(),
            prompts: Vec::new(),
            security_issues: None,
            yara_results: Vec::new(),
            errors: Vec::new(),
            ramparts_version: env!("CARGO_PKG_VERSION").to_string(),
            ramparts_commit: env!("GIT_COMMIT_SHORT").to_string(),
            ide_source: None,
            llm_prompts: None,
        }
    }

    pub fn add_error(&mut self, error: String) {
        self.errors.push(error.clone());
        if matches!(self.status, ScanStatus::Success) {
            self.status = ScanStatus::Failed(error);
        }
    }
}

/// MCP server information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MCPServerInfo {
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    pub capabilities: Vec<String>,
    pub metadata: HashMap<String, serde_json::Value>,
}

/// MCP tool definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MCPTool {
    pub name: String,
    pub description: Option<String>,
    pub input_schema: Option<serde_json::Value>,
    pub output_schema: Option<serde_json::Value>,
    pub parameters: HashMap<String, serde_json::Value>,
    pub category: Option<String>,
    pub tags: Vec<String>,
    pub deprecated: bool,
    // Preserve the original JSON schema from the MCP server
    pub raw_json: Option<serde_json::Value>,
}

/// MCP session information
#[derive(Debug, Clone)]
pub struct MCPSession {
    pub server_info: Option<MCPServerInfo>,
    pub endpoint_url: String, // Store the successful endpoint URL for reuse
    pub auth_headers: Option<HashMap<String, String>>, // Store auth headers for reuse
    pub session_id: Option<String>, // Store session ID for stateful MCP servers (e.g., GitHub Copilot)
}

/// MCP resource definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MCPResource {
    #[serde(rename = "uri")]
    pub uri: String,
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "description")]
    pub description: Option<String>,
    #[serde(rename = "mimeType")]
    pub mime_type: Option<String>,
    #[serde(rename = "size")]
    pub size: Option<u64>,
    #[serde(rename = "metadata")]
    pub metadata: HashMap<String, serde_json::Value>,
    // Preserve the original JSON schema from the MCP server
    #[serde(skip)]
    pub raw_json: Option<serde_json::Value>,
}

/// MCP prompt argument definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MCPPromptArgument {
    pub name: String,
    pub description: Option<String>,
    pub required: Option<bool>,
}

/// MCP prompt definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MCPPrompt {
    pub name: String,
    pub description: Option<String>,
    pub arguments: Option<Vec<MCPPromptArgument>>,
    // Preserve the original JSON schema from the MCP server
    #[serde(skip)]
    pub raw_json: Option<serde_json::Value>,
}

/// Tool response structure
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct ToolResponse {
    pub tools: Vec<MCPTool>,
    pub total_count: usize,
    pub response_timestamp: DateTime<Utc>,
}

/// Prompt response structure
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct PromptResponse {
    pub prompts: Vec<MCPPrompt>,
    pub total_count: usize,
    pub response_timestamp: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_config_builder() {
        let config = ScanConfigBuilder::new()
            .timeout(120)
            .http_timeout(60)
            .detailed(true)
            .format("json".to_string())
            .auth_headers(Some(HashMap::from([(
                "Authorization".to_string(),
                "Bearer token".to_string(),
            )])))
            .build();

        assert_eq!(config.timeout, 120);
        assert_eq!(config.http_timeout, 60);
        assert!(config.detailed);
        assert_eq!(config.format, "json");
        assert!(config.auth_headers.is_some());
    }

    #[test]
    fn test_scan_config_builder_default() {
        let config = ScanConfigBuilder::new().build();
        assert_eq!(config.timeout, 60);
        assert_eq!(config.http_timeout, 30);
        assert!(!config.detailed);
        assert_eq!(config.format, "text");
        assert!(config.auth_headers.is_none());
    }

    #[test]
    fn test_validate_scan_config_valid() {
        let options = ScanOptions {
            timeout: 60,
            http_timeout: 30,
            detailed: false,
            format: "json".to_string(),
            auth_headers: None,
            return_prompts: false,
            only: None,
        };

        let result = config_utils::validate_scan_config(&options);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_scan_config_invalid_timeout() {
        let options = ScanOptions {
            timeout: 0,
            http_timeout: 30,
            detailed: false,
            format: "json".to_string(),
            auth_headers: None,
            return_prompts: false,
            only: None,
        };

        let result = config_utils::validate_scan_config(&options);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Timeout must be greater than 0"));
    }

    #[test]
    fn test_validate_scan_config_invalid_http_timeout() {
        let options = ScanOptions {
            timeout: 60,
            http_timeout: 0,
            detailed: false,
            format: "json".to_string(),
            auth_headers: None,
            return_prompts: false,
            only: None,
        };

        let result = config_utils::validate_scan_config(&options);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("HTTP timeout must be greater than 0"));
    }

    #[test]
    fn test_validate_scan_config_timeout_less_than_http_timeout() {
        let options = ScanOptions {
            timeout: 10,
            http_timeout: 30,
            detailed: false,
            format: "json".to_string(),
            auth_headers: None,
            return_prompts: false,
            only: None,
        };

        let result = config_utils::validate_scan_config(&options);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Total timeout must be greater than or equal to HTTP timeout"));
    }

    #[test]
    fn test_scan_result_new() {
        let result = ScanResult::new("http://example.com".to_string());
        assert_eq!(result.url, "http://example.com");
        assert!(matches!(result.status, ScanStatus::Success));
        assert_eq!(result.tools.len(), 0);
        assert_eq!(result.resources.len(), 0);
        assert_eq!(result.prompts.len(), 0);
        assert_eq!(result.errors.len(), 0);
    }

    #[test]
    fn test_scan_result_add_error() {
        let mut result = ScanResult::new("http://example.com".to_string());
        result.add_error("Test error".to_string());

        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.errors[0], "Test error");
    }

    #[test]
    fn test_yara_rule_metadata() {
        let metadata = YaraRuleMetadata {
            name: Some("test_rule".to_string()),
            author: Some("Test Author".to_string()),
            date: Some("2024-01-01".to_string()),
            version: Some("1.0".to_string()),
            description: Some("A test rule".to_string()),
            severity: Some("HIGH".to_string()),
            category: Some("security".to_string()),
            confidence: Some("high".to_string()),
            tags: vec!["security".to_string(), "test".to_string()],
        };

        assert_eq!(metadata.name, Some("test_rule".to_string()));
        assert_eq!(metadata.author, Some("Test Author".to_string()));
        assert_eq!(metadata.severity, Some("HIGH".to_string()));
        assert_eq!(metadata.tags.len(), 2);
    }

    #[test]
    fn test_yara_scan_result() {
        let result = YaraScanResult {
            target_type: "tool".to_string(),
            target_name: "test_tool".to_string(),
            rule_name: "test_rule".to_string(),
            rule_file: Some("test_file".to_string()),
            matched_text: Some("matched content".to_string()),
            context: "test context".to_string(),
            rule_metadata: None,
            owasp_tags: Vec::new(),
            phase: Some("pre-scan".to_string()),
            rules_executed: Some(vec![
                "secrets_leakage:SecretsLeakage".to_string(),
                "cross_origin_escalation:CrossDomainContamination".to_string(),
            ]),
            security_issues_detected: Some(vec![
                "secrets_leakage:EnvironmentVariableLeakage".to_string()
            ]),
            total_items_scanned: Some(10),
            total_matches: Some(2),
            status: Some("warning".to_string()),
        };

        assert_eq!(result.target_type, "tool");
        assert_eq!(result.target_name, "test_tool");
        assert_eq!(result.rule_name, "test_rule");
        assert_eq!(result.matched_text, Some("matched content".to_string()));
        assert_eq!(result.context, "test context");
        assert_eq!(result.phase, Some("pre-scan".to_string()));
        assert_eq!(result.total_items_scanned, Some(10));
        assert_eq!(result.total_matches, Some(2));
        assert_eq!(result.status, Some("warning".to_string()));
    }
}
