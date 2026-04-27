use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use tracing::{debug, warn};
use url::Url;

/// MCP Configuration structure for reading from IDE config files
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MCPConfig {
    /// List of MCP server configurations from IDE config files
    pub servers: Option<Vec<MCPServerConfig>>,
    /// Global configuration options
    pub options: Option<MCPGlobalOptions>,
    /// Authentication headers for all servers
    pub auth_headers: Option<HashMap<String, String>>,
}

/// Cursor-specific MCP Configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CursorMCPConfig {
    /// List of MCP server configurations using Cursor's format
    #[serde(rename = "mcpServers")]
    pub mcp_servers: Option<HashMap<String, CursorMCPServerConfig>>,
    /// Cursor's settings (if any)
    pub settings: Option<HashMap<String, serde_json::Value>>,
}

/// Cursor-specific MCP server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CursorMCPServerConfig {
    /// Server command
    pub command: Option<String>,
    /// Server arguments
    pub args: Option<Vec<String>>,
    /// Working directory
    pub cwd: Option<String>,
    /// Environment variables
    pub env: Option<HashMap<String, String>>,
    /// Transport configuration
    pub transport: Option<CursorTransportConfig>,
    /// Server description
    pub description: Option<String>,
    /// Available tools
    pub tools: Option<Vec<String>>,
    /// Server URL (for HTTP transport)
    pub url: Option<String>,
    /// Authentication headers
    pub headers: Option<HashMap<String, String>>,
}

/// Cursor transport configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CursorTransportConfig {
    /// Transport type
    #[serde(rename = "type")]
    pub transport_type: Option<String>,
    /// Host for HTTP transport
    pub host: Option<String>,
    /// Port for HTTP transport
    pub port: Option<u16>,
}

/// Claude Desktop configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaudeDesktopConfig {
    /// List of MCP server configurations using Claude Desktop's format
    #[serde(rename = "mcpServers")]
    pub mcp_servers: Option<HashMap<String, ClaudeDesktopServerConfig>>,
    /// Global settings
    #[serde(rename = "globalShortcut")]
    pub global_shortcut: Option<String>,
    /// Other settings
    #[serde(flatten)]
    pub other_settings: Option<HashMap<String, serde_json::Value>>,
}

/// Claude Desktop MCP server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaudeDesktopServerConfig {
    /// Server command
    pub command: Option<String>,
    /// Server arguments
    pub args: Option<Vec<String>>,
    /// Environment variables
    pub env: Option<HashMap<String, String>>,
    /// Working directory
    pub cwd: Option<String>,
    /// Disabled flag
    pub disabled: Option<bool>,
    /// Server URL (for HTTP servers)
    pub url: Option<String>,
    /// Authentication headers
    pub headers: Option<HashMap<String, String>>,
}

/// VS Code settings structure (can contain MCP configuration)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VSCodeSettings {
    /// MCP servers configuration in VS Code settings
    #[serde(rename = "mcp.servers")]
    pub mcp_servers: Option<HashMap<String, VSCodeMCPServerConfig>>,
    /// Other VS Code settings
    #[serde(flatten)]
    pub other_settings: Option<HashMap<String, serde_json::Value>>,
}

/// VS Code MCP server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VSCodeMCPServerConfig {
    /// Server command
    pub command: Option<String>,
    /// Server arguments
    pub args: Option<Vec<String>>,
    /// Environment variables
    pub env: Option<HashMap<String, String>>,
    /// Working directory
    pub cwd: Option<String>,
    /// Server URL
    pub url: Option<String>,
    /// Transport type (e.g., "http", "stdio")
    #[serde(rename = "type")]
    pub transport_type: Option<String>,
    /// Authentication headers
    pub headers: Option<HashMap<String, String>>,
}

/// New VS Code MCP configuration structure (for mcp.json files)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VSCodeMCPConfig {
    /// MCP servers configuration in new VS Code format
    pub servers: Option<HashMap<String, VSCodeMCPServerConfig>>,
    /// Inputs configuration
    pub inputs: Option<Vec<serde_json::Value>>,
}

/// VS Code MCP configuration with `VSCodeServerConfig` (for configs with description field)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VSCodeObjectMCPConfig {
    /// MCP servers configuration in VS Code format with descriptions
    pub servers: Option<HashMap<String, VSCodeServerConfig>>,
    /// Inputs configuration
    pub inputs: Option<Vec<serde_json::Value>>,
}

/// Individual MCP server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MCPServerConfig {
    /// Server name or identifier
    pub name: Option<String>,
    /// Server URL (optional for STDIO servers)
    pub url: Option<String>,
    /// Server command (for STDIO servers)
    pub command: Option<String>,
    /// Command arguments (for STDIO servers)
    pub args: Option<Vec<String>>,
    /// Environment variables
    pub env: Option<HashMap<String, String>>,
    /// Server description
    pub description: Option<String>,
    /// Authentication headers specific to this server
    pub auth_headers: Option<HashMap<String, String>>,
    /// Server-specific options
    pub options: Option<MCPServerOptions>,
}

impl MCPServerConfig {
    /// Get display URL for logging and display purposes
    pub fn to_display_url(&self) -> String {
        if let Some(url) = &self.url {
            url.clone()
        } else if let Some(command) = &self.command {
            // For STDIO servers, create a more descriptive URL
            if let Some(name) = &self.name {
                // Include the server name if available: stdio:npx[server-name]
                format!("stdio:{command}[{name}]")
            } else if let Some(args) = &self.args {
                // If no name but has args, show the main package/argument
                if let Some(main_arg) = args.first() {
                    format!("stdio:{command}[{main_arg}]")
                } else {
                    format!("stdio:{command}[unknown]")
                }
            } else {
                format!("stdio:{command}")
            }
        } else {
            "unknown".to_string()
        }
    }

    /// Get actual URL for scanning (returns None for STDIO servers)
    pub fn scan_url(&self) -> Option<&str> {
        self.url.as_deref()
    }

    /// Generate a unique key for deduplication
    pub fn dedup_key(&self) -> String {
        if let Some(url) = &self.url {
            // For HTTP servers, use normalized URL with explicit prefix to prevent collisions
            format!("http:{}", MCPConfigManager::normalize_url(url))
        } else {
            // For STDIO servers, use name + command + args to create unique key with explicit prefix
            let name = self.name.as_deref().unwrap_or("unnamed");
            let command = self.command.as_deref().unwrap_or("unknown");
            let args = if let Some(args) = &self.args {
                args.join(" ")
            } else {
                String::new()
            };
            format!("stdio:{name}:{command}:{args}")
        }
    }
}

/// Global configuration options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MCPGlobalOptions {
    /// Default timeout in seconds
    pub timeout: Option<u64>,
    /// Default HTTP timeout in seconds
    pub http_timeout: Option<u64>,
    /// Default output format
    pub format: Option<String>,
    /// Whether to include detailed output by default
    pub detailed: Option<bool>,
}

/// Server-specific options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MCPServerOptions {
    /// Server-specific timeout
    pub timeout: Option<u64>,
    /// Server-specific HTTP timeout
    pub http_timeout: Option<u64>,
    /// Server-specific output format
    pub format: Option<String>,
    /// Whether to include detailed output for this server
    pub detailed: Option<bool>,
}

// IDE-specific configuration formats

/// VS Code MCP configuration format with array of servers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VSCodeArrayMCPConfig {
    /// Servers as array (alternative VS Code format)
    pub servers: Option<Vec<VSCodeArrayServerConfig>>,
    /// Inputs array
    pub inputs: Option<Vec<serde_json::Value>>,
}

/// VS Code server configuration in array format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VSCodeArrayServerConfig {
    /// Server name
    pub name: Option<String>,
    /// Server URL (for HTTP servers)
    pub url: Option<String>,
    /// Command to run (for STDIO servers)
    pub command: Option<String>,
    /// Arguments for the command
    pub args: Option<Vec<String>>,
    /// Environment variables
    pub env: Option<HashMap<String, String>>,
    /// Server type (http, stdio, etc.)
    #[serde(rename = "type")]
    pub server_type: Option<String>,
    /// Description
    pub description: Option<String>,
    /// Authentication headers
    pub headers: Option<HashMap<String, String>>,
}

/// VS Code server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VSCodeServerConfig {
    /// Server type (http, stdio, etc.)
    #[serde(rename = "type")]
    pub server_type: Option<String>,
    /// Server URL
    pub url: Option<String>,
    /// Command to run (for stdio servers)
    pub command: Option<String>,
    /// Arguments for the command
    pub args: Option<Vec<String>>,
    /// Environment variables
    pub env: Option<HashMap<String, String>>,
    /// Gallery flag
    pub gallery: Option<bool>,
    /// Description
    pub description: Option<String>,
    /// Authentication headers
    pub headers: Option<HashMap<String, String>>,
}

/// Cursor server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct CursorServerConfig {
    pub command: String,
    pub args: Vec<String>,
    pub env: Option<HashMap<String, String>>,
}

/// Windsurf MCP configuration format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindsurfMCPConfig {
    /// Servers configuration
    pub servers: Option<HashMap<String, WindsurfServerConfig>>,
    /// Global configuration
    pub global: Option<MCPGlobalOptions>,
}

/// Windsurf server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindsurfServerConfig {
    pub url: Option<String>,
    pub command: Option<String>,
    pub args: Option<Vec<String>>,
    pub env: Option<HashMap<String, String>>,
    #[serde(rename = "type")]
    pub server_type: Option<String>,
    pub description: Option<String>,
    /// Authentication headers
    pub headers: Option<HashMap<String, String>>,
}

/// Claude Desktop MCP configuration format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaudeMCPConfig {
    /// MCP servers configuration
    #[serde(rename = "mcpServers")]
    pub mcp_servers: Option<HashMap<String, ClaudeServerConfig>>,
    /// Alternative naming
    pub servers: Option<HashMap<String, ClaudeServerConfig>>,
}

/// Claude Desktop server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaudeServerConfig {
    pub command: Option<String>,
    pub args: Option<Vec<String>>,
    pub env: Option<HashMap<String, String>>,
    pub url: Option<String>,
    #[serde(rename = "type")]
    pub server_type: Option<String>,
    /// Authentication headers
    pub headers: Option<HashMap<String, String>>,
}

/// Claude Code MCP configuration format (extracted from ~/.claude/settings.json)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaudeCodeConfig {
    /// MCP servers configuration
    #[serde(rename = "mcpServers")]
    pub mcp_servers: Option<HashMap<String, ClaudeCodeServerConfig>>,
}

/// Claude Code server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaudeCodeServerConfig {
    #[serde(rename = "type")]
    pub server_type: String,
    pub command: String,
    pub args: Vec<String>,
    pub env: Option<HashMap<String, String>>,
}

/// Zed MCP configuration format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZedMCPConfig {
    /// Context servers as array of objects
    pub context_servers: Option<Vec<HashMap<String, ZedServerConfig>>>,
}

/// Zed server configuration with command object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZedServerConfig {
    /// Command configuration
    pub command: Option<ZedCommandConfig>,
    /// Direct URL (for HTTP servers)
    pub url: Option<String>,
    /// Environment variables
    pub env: Option<HashMap<String, String>>,
    /// Authentication headers
    pub headers: Option<HashMap<String, String>>,
}

/// Zed command configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZedCommandConfig {
    /// Path to executable
    pub path: String,
    /// Command arguments
    pub args: Option<Vec<String>>,
}

/// Zencoder MCP configuration format (simple command-based)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZencoderMCPConfig {
    /// Command to run
    pub command: String,
    /// Command arguments
    pub args: Option<Vec<String>>,
    /// Environment variables
    pub env: Option<HashMap<String, String>>,
}

// Conversion implementations

impl From<VSCodeMCPConfig> for MCPConfig {
    fn from(vscode_config: VSCodeMCPConfig) -> Self {
        let servers = vscode_config.servers.map(|servers_map| {
            servers_map
                .into_iter()
                .map(|(name, server_config)| MCPServerConfig {
                    name: Some(name),
                    url: server_config.url,
                    command: server_config.command,
                    args: server_config.args,
                    env: server_config.env,
                    description: None, // VSCodeMCPServerConfig doesn't have a description field
                    auth_headers: server_config.headers,
                    options: None,
                })
                .collect()
        });

        MCPConfig {
            servers,
            options: None,
            auth_headers: None,
        }
    }
}

impl From<VSCodeObjectMCPConfig> for MCPConfig {
    fn from(vscode_config: VSCodeObjectMCPConfig) -> Self {
        let servers = vscode_config.servers.map(|servers_map| {
            servers_map
                .into_iter()
                .map(|(name, server_config)| MCPServerConfig {
                    name: Some(name),
                    url: server_config.url,
                    command: server_config.command,
                    args: server_config.args,
                    env: server_config.env,
                    description: server_config.description, // VSCodeServerConfig has a description field
                    auth_headers: server_config.headers,
                    options: None,
                })
                .collect()
        });

        MCPConfig {
            servers,
            options: None,
            auth_headers: None,
        }
    }
}

impl From<VSCodeArrayMCPConfig> for MCPConfig {
    fn from(vscode_config: VSCodeArrayMCPConfig) -> Self {
        let servers = vscode_config.servers.map(|servers_vec| {
            servers_vec
                .into_iter()
                .map(|server_config| MCPServerConfig {
                    name: server_config.name,
                    url: server_config.url,
                    command: server_config.command,
                    args: server_config.args,
                    env: server_config.env,
                    description: server_config.description,
                    auth_headers: server_config.headers,
                    options: None,
                })
                .collect()
        });

        MCPConfig {
            servers,
            options: None,
            auth_headers: None,
        }
    }
}

impl From<CursorMCPConfig> for MCPConfig {
    fn from(cursor_config: CursorMCPConfig) -> Self {
        let servers = cursor_config.mcp_servers.map(|servers_map| {
            servers_map
                .into_iter()
                .map(|(name, server_config)| MCPServerConfig {
                    name: Some(name),
                    url: server_config.url,
                    command: server_config.command,
                    args: server_config.args,
                    env: server_config.env,
                    description: server_config.description,
                    auth_headers: server_config.headers,
                    options: None,
                })
                .collect()
        });

        MCPConfig {
            servers,
            options: None,
            auth_headers: None,
        }
    }
}

impl From<WindsurfMCPConfig> for MCPConfig {
    fn from(windsurf_config: WindsurfMCPConfig) -> Self {
        let servers = windsurf_config.servers.map(|servers_map| {
            servers_map
                .into_iter()
                .map(|(name, server_config)| MCPServerConfig {
                    name: Some(name),
                    url: server_config.url,
                    command: server_config.command,
                    args: server_config.args,
                    env: server_config.env,
                    description: server_config.description,
                    auth_headers: server_config.headers,
                    options: None,
                })
                .collect()
        });

        MCPConfig {
            servers,
            options: windsurf_config.global,
            auth_headers: None,
        }
    }
}

impl From<ClaudeMCPConfig> for MCPConfig {
    fn from(claude_config: ClaudeMCPConfig) -> Self {
        // Try mcp_servers first, then servers
        let servers_map = claude_config.mcp_servers.or(claude_config.servers);

        let servers = servers_map.map(|servers_map| {
            servers_map
                .into_iter()
                .map(|(name, server_config)| MCPServerConfig {
                    name: Some(name),
                    url: server_config.url,
                    command: server_config.command,
                    args: server_config.args,
                    env: server_config.env,
                    description: None,
                    auth_headers: server_config.headers,
                    options: None,
                })
                .collect()
        });

        MCPConfig {
            servers,
            options: None,
            auth_headers: None,
        }
    }
}

impl From<ClaudeCodeConfig> for MCPConfig {
    fn from(claude_code_config: ClaudeCodeConfig) -> Self {
        let servers = claude_code_config.mcp_servers.map(|servers_map| {
            servers_map
                .into_iter()
                .map(|(name, server_config)| MCPServerConfig {
                    name: Some(name),
                    url: None,
                    command: Some(server_config.command),
                    args: Some(server_config.args),
                    env: server_config.env,
                    description: None,
                    auth_headers: None,
                    options: None,
                })
                .collect()
        });

        MCPConfig {
            servers,
            options: None,
            auth_headers: None,
        }
    }
}

impl From<ZedMCPConfig> for MCPConfig {
    fn from(zed_config: ZedMCPConfig) -> Self {
        let servers = zed_config.context_servers.map(|context_servers| {
            context_servers
                .into_iter()
                .flat_map(|server_map| {
                    server_map
                        .into_iter()
                        .map(|(name, server_config)| MCPServerConfig {
                            name: Some(name),
                            url: server_config.url,
                            command: server_config.command.as_ref().map(|cmd| cmd.path.clone()),
                            args: server_config
                                .command
                                .as_ref()
                                .and_then(|cmd| cmd.args.clone()),
                            env: server_config.env,
                            description: server_config.command.as_ref().map(|cmd| {
                                format!(
                                    "Command: {} {}",
                                    cmd.path,
                                    cmd.args
                                        .as_ref()
                                        .map(|args| args.join(" "))
                                        .unwrap_or_default()
                                )
                            }),
                            auth_headers: server_config.headers,
                            options: None,
                        })
                })
                .collect()
        });

        MCPConfig {
            servers,
            options: None,
            auth_headers: None,
        }
    }
}

impl From<ZencoderMCPConfig> for MCPConfig {
    fn from(zencoder_config: ZencoderMCPConfig) -> Self {
        let servers = Some(vec![MCPServerConfig {
            name: Some("zencoder".to_string()),
            url: None,
            command: Some(zencoder_config.command),
            args: zencoder_config.args,
            env: zencoder_config.env,
            description: Some("Zencoder MCP server".to_string()),
            auth_headers: None,
            options: None,
        }]);

        MCPConfig {
            servers,
            options: None,
            auth_headers: None,
        }
    }
}

/// Supported MCP client types
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MCPClient {
    Cursor,
    Windsurf,
    VSCode,
    Claude,
    ClaudeCode,
    Gemini,
    Neovim,
    Helix,
    Zed,
    Zencoder,
}

impl MCPClient {
    pub fn name(&self) -> &'static str {
        match self {
            MCPClient::Cursor => "cursor",
            MCPClient::Windsurf => "windsurf",
            MCPClient::VSCode => "vscode",
            MCPClient::Claude => "claude",
            MCPClient::ClaudeCode => "claude-code",
            MCPClient::Gemini => "gemini",
            MCPClient::Neovim => "neovim",
            MCPClient::Helix => "helix",
            MCPClient::Zed => "zed",
            MCPClient::Zencoder => "zencoder",
        }
    }
}

/// Cache for discovered configuration paths to avoid repeated filesystem operations
static CONFIG_PATHS_CACHE: LazyLock<Vec<(PathBuf, MCPClient)>> =
    LazyLock::new(MCPConfigManager::discover_config_paths);

/// IDE configuration file manager for MCP scanner
pub struct MCPConfigManager {
    config_paths: Vec<(PathBuf, MCPClient)>,
}

impl MCPConfigManager {
    /// Normalize URL for consistent deduplication
    /// Removes trailing slashes, converts to lowercase, and handles localhost aliases
    fn normalize_url(url: &str) -> String {
        let mut normalized = url.trim().to_lowercase();

        // Remove trailing slashes
        if normalized.ends_with('/') && normalized != "http://" && normalized != "https://" {
            normalized = normalized.trim_end_matches('/').to_string();
        }

        // Normalize localhost variants
        normalized = normalized
            .replace("127.0.0.1", "localhost")
            .replace("0.0.0.0", "localhost");

        // Normalize port defaults - currently no-op, but placeholder for future enhancement
        if (normalized.starts_with("http://localhost")
            || normalized.starts_with("https://localhost"))
            && !normalized.contains(':')
        {
            // Don't add default port, keep as-is for now
        }

        normalized
    }
    /// Create a new configuration manager with platform-specific IDE config paths
    pub fn new() -> Self {
        Self {
            config_paths: CONFIG_PATHS_CACHE.clone(),
        }
    }

    /// Create a new configuration manager with fresh path discovery (bypasses cache)
    /// Creates a new `MCPConfigManager` without using the cache
    #[allow(dead_code)] // Used in tests and for bypassing cache when needed
    pub fn new_uncached() -> Self {
        let paths = Self::discover_config_paths();
        Self {
            config_paths: paths,
        }
    }

    /// Discover MCP configuration paths based on platform and IDE
    fn discover_config_paths() -> Vec<(PathBuf, MCPClient)> {
        let mut paths = Vec::new();

        // First, add workspace-level configurations (highest priority)
        paths.extend(Self::get_workspace_paths());

        // Then add platform-specific global configurations
        let platform = env::consts::OS;

        match platform {
            "windows" => {
                paths.extend(Self::get_windows_paths());
            }
            "macos" | "darwin" => {
                paths.extend(Self::get_macos_paths());
            }
            _ => {
                // Linux and other Unix-like systems
                paths.extend(Self::get_unix_paths());
            }
        }

        paths
    }

    /// Get workspace-level MCP configuration paths (current working directory and workspace)
    fn get_workspace_paths() -> Vec<(PathBuf, MCPClient)> {
        let mut paths = Vec::new();

        // Current working directory workspace configurations
        let current_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));

        // VS Code workspace configurations
        paths.push((
            current_dir.join(".vscode").join("mcp.json"),
            MCPClient::VSCode,
        ));
        paths.push((
            current_dir.join(".vscode").join("settings.json"),
            MCPClient::VSCode,
        ));

        // Cursor workspace configurations
        paths.push((
            current_dir.join(".cursor").join("mcp.json"),
            MCPClient::Cursor,
        ));
        paths.push((
            current_dir.join(".cursor").join("settings.json"),
            MCPClient::Cursor,
        ));
        // Cursor repo-embedded MCP configuration used by some editors
        // Example: .cursor/rules/mcp.json (supply-chain sensitive)
        paths.push((
            current_dir.join(".cursor").join("rules").join("mcp.json"),
            MCPClient::Cursor,
        ));

        // Claude Code workspace configurations
        paths.push((
            current_dir.join(".claude").join("settings.json"),
            MCPClient::ClaudeCode,
        ));
        paths.push((
            current_dir.join(".claude").join("settings.local.json"),
            MCPClient::ClaudeCode,
        ));
        paths.push((
            current_dir.join(".claude").join("mcp.json"),
            MCPClient::Claude,
        ));

        // Windsurf workspace configurations
        paths.push((
            current_dir.join(".windsurf").join("mcp.json"),
            MCPClient::Windsurf,
        ));
        paths.push((
            current_dir.join(".windsurf").join("mcp_config.json"),
            MCPClient::Windsurf,
        ));

        // Gemini CLI workspace configurations
        paths.push((
            current_dir.join(".gemini").join("settings.json"),
            MCPClient::Gemini,
        ));

        // Also check parent directories up to 3 levels for project root configurations
        let mut parent = current_dir.parent();
        let mut level = 0;
        while let Some(dir) = parent {
            if level >= 3 {
                break;
            }

            // Look for common project indicators
            if dir.join(".git").exists()
                || dir.join("package.json").exists()
                || dir.join("Cargo.toml").exists()
                || dir.join("pyproject.toml").exists()
                || dir.join("requirements.txt").exists()
            {
                // VS Code project root configurations
                paths.push((dir.join(".vscode").join("mcp.json"), MCPClient::VSCode));
                paths.push((dir.join(".vscode").join("settings.json"), MCPClient::VSCode));

                // Cursor project root configurations
                paths.push((dir.join(".cursor").join("mcp.json"), MCPClient::Cursor));
                // Cursor repo-embedded MCP configuration in project root
                paths.push((
                    dir.join(".cursor").join("rules").join("mcp.json"),
                    MCPClient::Cursor,
                ));

                // Claude Code project root configurations
                paths.push((
                    dir.join(".claude").join("settings.json"),
                    MCPClient::ClaudeCode,
                ));
                paths.push((
                    dir.join(".claude").join("settings.local.json"),
                    MCPClient::ClaudeCode,
                ));
                paths.push((dir.join(".claude").join("mcp.json"), MCPClient::Claude));

                // Windsurf project root configurations
                paths.push((dir.join(".windsurf").join("mcp.json"), MCPClient::Windsurf));
                paths.push((
                    dir.join(".windsurf").join("mcp_config.json"),
                    MCPClient::Windsurf,
                ));

                // Gemini CLI project root configurations
                paths.push((dir.join(".gemini").join("settings.json"), MCPClient::Gemini));

                break; // Stop at first project root found
            }

            parent = dir.parent();
            level += 1;
        }

        paths
    }

    /// Get Windows-specific MCP configuration paths
    fn get_windows_paths() -> Vec<(PathBuf, MCPClient)> {
        let mut paths = Vec::new();

        // Try APPDATA first, then fallback to home directory
        if let Ok(appdata) = env::var("APPDATA") {
            let appdata_path = PathBuf::from(appdata);

            // Cursor
            paths.push((
                appdata_path
                    .join("Cursor")
                    .join("User")
                    .join("globalStorage")
                    .join("rooveterinaryinc.cursor-mcp")
                    .join("mcp.json"),
                MCPClient::Cursor,
            ));
            paths.push((
                appdata_path.join("Cursor").join("User").join("mcp.json"),
                MCPClient::Cursor,
            ));

            // Windsurf
            paths.push((
                appdata_path.join("Windsurf").join("User").join("mcp.json"),
                MCPClient::Windsurf,
            ));
            paths.push((
                appdata_path
                    .join("Codeium")
                    .join("Windsurf")
                    .join("mcp_config.json"),
                MCPClient::Windsurf,
            ));

            // VS Code
            paths.push((
                appdata_path.join("Code").join("User").join("mcp.json"),
                MCPClient::VSCode,
            ));

            // Claude Desktop
            paths.push((
                appdata_path.join("Claude").join("mcp.json"),
                MCPClient::Claude,
            ));
        } else {
            // Fallback: try LOCALAPPDATA if APPDATA is missing
            if let Ok(localappdata) = env::var("LOCALAPPDATA") {
                let localappdata_path = PathBuf::from(localappdata);

                paths.push((
                    localappdata_path
                        .join("Cursor")
                        .join("User")
                        .join("mcp.json"),
                    MCPClient::Cursor,
                ));
                paths.push((
                    localappdata_path
                        .join("Programs")
                        .join("Windsurf")
                        .join("mcp.json"),
                    MCPClient::Windsurf,
                ));
                paths.push((
                    localappdata_path
                        .join("Programs")
                        .join("Microsoft VS Code")
                        .join("mcp.json"),
                    MCPClient::VSCode,
                ));
            }
        }

        // User home directory configs (Unix-style on Windows)
        if let Some(home_dir) = dirs::home_dir() {
            paths.push((home_dir.join(".cursor").join("mcp.json"), MCPClient::Cursor));
            paths.push((home_dir.join(".vscode").join("mcp.json"), MCPClient::VSCode));
            paths.push((home_dir.join(".claude").join("mcp.json"), MCPClient::Claude));
            paths.push((
                home_dir.join(".claude").join("settings.json"),
                MCPClient::ClaudeCode,
            ));
            paths.push((
                home_dir.join(".gemini").join("settings.json"),
                MCPClient::Gemini,
            ));

            // Windows-specific AppData fallback in user profile
            let user_appdata = home_dir.join("AppData").join("Roaming");
            if user_appdata.exists() {
                // Cursor
                paths.push((
                    user_appdata.join("Cursor").join("User").join("mcp.json"),
                    MCPClient::Cursor,
                ));

                // VS Code
                paths.push((
                    user_appdata.join("Code").join("User").join("mcp.json"),
                    MCPClient::VSCode,
                ));
                paths.push((
                    user_appdata.join("Code").join("User").join("settings.json"),
                    MCPClient::VSCode,
                ));

                // Claude Desktop
                paths.push((
                    user_appdata
                        .join("Claude")
                        .join("claude_desktop_config.json"),
                    MCPClient::Claude,
                ));

                // Windsurf
                paths.push((
                    user_appdata.join("Windsurf").join("User").join("mcp.json"),
                    MCPClient::Windsurf,
                ));
                paths.push((
                    user_appdata
                        .join("Codeium")
                        .join("Windsurf")
                        .join("mcp_config.json"),
                    MCPClient::Windsurf,
                ));

                // Claude Code enterprise managed settings
                if let Ok(program_data) = env::var("PROGRAMDATA") {
                    paths.push((
                        PathBuf::from(program_data)
                            .join("ClaudeCode")
                            .join("managed-settings.json"),
                        MCPClient::ClaudeCode,
                    ));
                }
            }
        }

        paths
    }

    /// Get macOS-specific MCP configuration paths
    fn get_macos_paths() -> Vec<(PathBuf, MCPClient)> {
        let mut paths = Vec::new();

        if let Some(home_dir) = dirs::home_dir() {
            let app_support = home_dir.join("Library").join("Application Support");

            // Cursor
            paths.push((
                app_support
                    .join("Cursor")
                    .join("User")
                    .join("globalStorage")
                    .join("rooveterinaryinc.cursor-mcp")
                    .join("mcp.json"),
                MCPClient::Cursor,
            ));
            paths.push((
                app_support.join("Cursor").join("User").join("mcp.json"),
                MCPClient::Cursor,
            ));
            paths.push((home_dir.join(".cursor").join("mcp.json"), MCPClient::Cursor));

            // Windsurf
            paths.push((
                app_support.join("Windsurf").join("User").join("mcp.json"),
                MCPClient::Windsurf,
            ));
            paths.push((
                app_support
                    .join("Codeium")
                    .join("Windsurf")
                    .join("mcp_config.json"),
                MCPClient::Windsurf,
            ));
            paths.push((
                home_dir
                    .join(".codeium")
                    .join("windsurf")
                    .join("mcp_config.json"),
                MCPClient::Windsurf,
            ));

            // VS Code - multiple configuration locations
            paths.push((
                app_support.join("Code").join("User").join("mcp.json"),
                MCPClient::VSCode,
            ));
            paths.push((
                app_support.join("Code").join("User").join("settings.json"),
                MCPClient::VSCode,
            ));
            paths.push((home_dir.join(".vscode").join("mcp.json"), MCPClient::VSCode));
            paths.push((
                home_dir.join(".vscode").join("settings.json"),
                MCPClient::VSCode,
            ));

            // Claude Desktop - uses claude_desktop_config.json
            paths.push((
                app_support
                    .join("Claude")
                    .join("claude_desktop_config.json"),
                MCPClient::Claude,
            ));
            paths.push((
                app_support
                    .join("Claude")
                    .join("User")
                    .join("claude_desktop_config.json"),
                MCPClient::Claude,
            ));

            // Claude Code - User/Global scope
            paths.push((
                home_dir.join(".claude").join("settings.json"),
                MCPClient::ClaudeCode,
            ));
            paths.push((home_dir.join(".claude").join("mcp.json"), MCPClient::Claude));
            paths.push((
                home_dir.join(".gemini").join("settings.json"),
                MCPClient::Gemini,
            ));

            // Zed
            paths.push((app_support.join("Zed").join("mcp.json"), MCPClient::Zed));

            // Zencoder
            paths.push((
                app_support.join("Zencoder").join("mcp.json"),
                MCPClient::Zencoder,
            ));

            // Claude Code enterprise managed settings
            paths.push((
                PathBuf::from("/Library/Application Support/ClaudeCode/managed-settings.json"),
                MCPClient::ClaudeCode,
            ));

            // Unix-style configs in home directory
            let config_dir = home_dir.join(".config");
            paths.push((config_dir.join("nvim").join("mcp.json"), MCPClient::Neovim));
            paths.push((config_dir.join("helix").join("mcp.json"), MCPClient::Helix));
        }

        paths
    }

    /// Get Unix/Linux-specific MCP configuration paths
    fn get_unix_paths() -> Vec<(PathBuf, MCPClient)> {
        let mut paths = Vec::new();

        if let Some(home_dir) = dirs::home_dir() {
            let config_dir = home_dir.join(".config");

            // Cursor
            paths.push((home_dir.join(".cursor").join("mcp.json"), MCPClient::Cursor));
            paths.push((
                config_dir.join("Cursor").join("User").join("mcp.json"),
                MCPClient::Cursor,
            ));

            // Windsurf
            paths.push((
                home_dir.join(".windsurf").join("mcp.json"),
                MCPClient::Windsurf,
            ));
            paths.push((
                home_dir
                    .join(".codeium")
                    .join("windsurf")
                    .join("mcp_config.json"),
                MCPClient::Windsurf,
            ));
            paths.push((
                config_dir.join("Windsurf").join("User").join("mcp.json"),
                MCPClient::Windsurf,
            ));

            // VS Code
            paths.push((home_dir.join(".vscode").join("mcp.json"), MCPClient::VSCode));
            paths.push((
                home_dir.join(".vscode").join("settings.json"),
                MCPClient::VSCode,
            ));
            paths.push((
                config_dir.join("Code").join("User").join("mcp.json"),
                MCPClient::VSCode,
            ));

            // Claude Desktop
            paths.push((home_dir.join(".claude").join("mcp.json"), MCPClient::Claude));
            // Claude Code
            paths.push((
                home_dir.join(".claude").join("settings.json"),
                MCPClient::ClaudeCode,
            ));
            paths.push((
                home_dir.join(".gemini").join("settings.json"),
                MCPClient::Gemini,
            ));
            paths.push((
                config_dir.join("Code").join("User").join("settings.json"),
                MCPClient::VSCode,
            ));

            // Claude Desktop - uses claude_desktop_config.json
            paths.push((
                home_dir.join(".claude").join("claude_desktop_config.json"),
                MCPClient::Claude,
            ));
            paths.push((
                config_dir.join("claude").join("claude_desktop_config.json"),
                MCPClient::Claude,
            ));

            // Claude Code - User/Global scope already added above
            paths.push((home_dir.join(".claude").join("mcp.json"), MCPClient::Claude));

            // Neovim
            paths.push((config_dir.join("nvim").join("mcp.json"), MCPClient::Neovim));

            // Helix
            paths.push((config_dir.join("helix").join("mcp.json"), MCPClient::Helix));

            // Zed
            paths.push((config_dir.join("zed").join("mcp.json"), MCPClient::Zed));

            // Zencoder
            paths.push((
                config_dir.join("zencoder").join("mcp.json"),
                MCPClient::Zencoder,
            ));

            // Claude Code enterprise managed settings
            paths.push((
                PathBuf::from("/etc/claude-code/managed-settings.json"),
                MCPClient::ClaudeCode,
            ));
        }

        paths
    }

    /// Get client type from a configuration file path using component-based matching
    /// Determines the MCP client type based on the configuration file path
    pub fn detect_client<P: AsRef<Path>>(path: P) -> Option<MCPClient> {
        let path = path.as_ref();
        let components: Vec<_> = path
            .components()
            .filter_map(|c| c.as_os_str().to_str())
            .map(str::to_lowercase)
            .collect();

        // Check specific file names FIRST for most precise detection
        if let Some(filename) = path.file_name().and_then(|n| n.to_str()) {
            match filename {
                "claude_desktop_config.json" => return Some(MCPClient::Claude),
                "settings.json" => {
                    // Check if it's in a Claude Code directory (exact match)
                    if components.iter().any(|c| c == ".claude") {
                        return Some(MCPClient::ClaudeCode);
                    }
                    // Check if it's in a VS Code directory (exact matches)
                    if components
                        .iter()
                        .any(|c| c == "code" || c == "vscode" || c == ".vscode")
                    {
                        return Some(MCPClient::VSCode);
                    }
                }
                "settings.local.json" if components.iter().any(|c| c == ".claude") => {
                    // Claude Code local settings (exact match)
                    return Some(MCPClient::ClaudeCode);
                }
                "managed-settings.json"
                    if components
                        .iter()
                        .any(|c| c == "claudecode" || c == "claude-code") =>
                {
                    // Claude Code enterprise managed settings (exact component matches)
                    return Some(MCPClient::ClaudeCode);
                }
                _ => {}
            }
        }

        // Check path components for broader matching
        for component in &components {
            match component.as_str() {
                // Exact matches first
                "cursor" | ".cursor" => return Some(MCPClient::Cursor),
                "windsurf" => return Some(MCPClient::Windsurf),

                "claude" | ".claude" => return Some(MCPClient::Claude),
                "gemini" | ".gemini" => return Some(MCPClient::Gemini),
                "zed" => return Some(MCPClient::Zed),
                "zencoder" => return Some(MCPClient::Zencoder),
                "helix" => return Some(MCPClient::Helix),
                "nvim" | "neovim" => return Some(MCPClient::Neovim),
                "code" | "vscode" | ".vscode" => return Some(MCPClient::VSCode),

                // Exact path component matches (avoiding false positives)
                "codeium" | ".codeium" => return Some(MCPClient::Windsurf), // Codeium directory means Windsurf context

                // Partial matches with disambiguation for compound paths
                c if c.starts_with("cursor") && !c.contains("vscode") => {
                    return Some(MCPClient::Cursor)
                }
                c if c == "microsoft vs code"
                    || (c.contains("microsoft") && c.contains("code")) =>
                {
                    return Some(MCPClient::VSCode)
                }

                _ => {} // Keep looking
            }
        }

        // Fallback: check full path string for edge cases
        let path_str = path.to_string_lossy().to_lowercase();
        if path_str.contains("rooveterinaryinc.cursor-mcp") {
            return Some(MCPClient::Cursor);
        }

        None
    }

    /// Load configuration from all available IDE config files
    pub fn load_config(&self) -> MCPConfig {
        let mut merged_config = MCPConfig::default();
        let mut loaded_configs = 0;
        let mut failed_configs = Vec::new();

        // Only show existing config files
        let existing_configs: Vec<_> = self
            .config_paths
            .iter()
            .filter(|(path, _)| path.exists())
            .collect();

        if !existing_configs.is_empty() {
            println!("🔍 Found {} IDE config files:", existing_configs.len());
            for (path, client) in existing_configs {
                println!("  ✓ {} IDE: {}", client.name(), path.display());
            }
            println!();
        }

        for (path, client) in &self.config_paths {
            match Self::load_config_from_path(path) {
                Ok(config) => {
                    // Validate configuration before merging
                    if let Err(validation_error) = Self::validate_config(&config) {
                        warn!(
                            "Invalid MCP configuration in {} ({}): {}",
                            client.name(),
                            path.display(),
                            validation_error
                        );
                        failed_configs.push((path.clone(), validation_error));
                        continue;
                    }

                    // Display what was found in this config file
                    let server_count = config.servers.as_ref().map(|s| s.len()).unwrap_or(0);
                    println!(
                        "📁 {} IDE config: {} ({} servers)",
                        client.name(),
                        path.display(),
                        server_count
                    );

                    if let Some(ref servers) = config.servers {
                        for server in servers {
                            let server_name = server.name.as_deref().unwrap_or("unnamed");
                            let server_type = if server.command.is_some() {
                                "STDIO"
                            } else {
                                "HTTP"
                            };
                            println!(
                                "  └─ {} [{}]: {}",
                                server_name,
                                server_type,
                                server.to_display_url()
                            );
                        }
                    }

                    Self::merge_config_with_source(&mut merged_config, &config, client.name());
                    loaded_configs += 1;
                    debug!(
                        "Loaded MCP configuration from {} IDE: {}",
                        client.name(),
                        path.display()
                    );
                }
                Err(e) => {
                    if path.exists() {
                        // File exists but couldn't be parsed - this is an error
                        warn!(
                            "Failed to parse MCP configuration from {} IDE at {}: {}",
                            client.name(),
                            path.display(),
                            e
                        );
                        failed_configs.push((path.clone(), e));
                    } else {
                        // File doesn't exist - this is normal
                        debug!(
                            "No MCP configuration found for {} IDE at: {}",
                            client.name(),
                            path.display()
                        );
                    }
                }
            }
        }

        if loaded_configs == 0 && failed_configs.is_empty() {
            debug!("No MCP configuration files found in any supported IDE locations");
        } else if !failed_configs.is_empty() {
            warn!(
                "Found {} configuration files with errors",
                failed_configs.len()
            );
        }

        merged_config
    }

    /// Helper function to parse Cursor-compatible MCP configuration format
    /// Used by Claude, Claude Code, Cursor, Windsurf, and Gemini
    fn try_parse_cursor_compatible_config(content: &str, client_name: &str) -> Option<MCPConfig> {
        if let Ok(cursor_config) = serde_json::from_str::<CursorMCPConfig>(content) {
            debug!("Parsed as {} configuration format", client_name);
            Some(Self::convert_cursor_config(cursor_config))
        } else {
            None
        }
    }

    /// Returns `true` only when the parsed `MCPConfig` actually contains at
    /// least one server.
    ///
    /// Several IDE config schemas have all fields `Option`-wrapped, so a JSON
    /// document keyed differently than expected (e.g., a Claude-Desktop-style
    /// `{"mcpServers": ...}` file at a VS Code path) parses as a syntactically
    /// valid but empty `MCPConfig`. Without this gate, the early-return in
    /// `load_config_from_path` swallows that case and the caller's fallback
    /// chain never runs. See ramparts#85.
    fn config_has_servers(config: &MCPConfig) -> bool {
        config
            .servers
            .as_ref()
            .is_some_and(|servers| !servers.is_empty())
    }

    /// Load configuration from a specific IDE config path
    pub fn load_config_from_path(path: &Path) -> Result<MCPConfig> {
        if !path.exists() {
            return Err(anyhow!(
                "IDE configuration file does not exist: {}",
                path.display()
            ));
        }

        let content = fs::read_to_string(path)
            .map_err(|e| anyhow!("Failed to read IDE config file {}: {}", path.display(), e))?;

        // Detect IDE type by checking the client type from path
        let client = Self::detect_client(path);
        let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

        // Try parsing based on client type and file name
        match client {
            Some(MCPClient::Cursor) => {
                if let Some(config) =
                    Self::try_parse_cursor_compatible_config(&content, "Cursor MCP")
                {
                    return Ok(config);
                }
            }
            Some(MCPClient::Claude) => {
                // Claude Desktop uses claude_desktop_config.json
                if filename == "claude_desktop_config.json" {
                    if let Ok(claude_config) = serde_json::from_str::<ClaudeDesktopConfig>(&content)
                    {
                        debug!("Parsed as Claude Desktop configuration format");
                        return Ok(Self::convert_claude_desktop_config(claude_config));
                    }
                }
                // Claude mcp.json files use Cursor format
                else if filename == "mcp.json" {
                    if let Some(config) =
                        Self::try_parse_cursor_compatible_config(&content, "Claude MCP")
                    {
                        return Ok(config);
                    }
                }
            }
            Some(MCPClient::ClaudeCode)
                if filename == "settings.json" || filename == "settings.local.json" =>
            {
                // Claude Code uses settings.json files in .claude directory
                if let Some(config) =
                    Self::try_parse_cursor_compatible_config(&content, "Claude Code")
                {
                    return Ok(config);
                }
            }
            Some(MCPClient::Windsurf) | Some(MCPClient::Gemini) => {
                // Windsurf and Gemini use Cursor-compatible format
                let client_name = format!("{} MCP", client.as_ref().unwrap().name());
                if let Some(config) =
                    Self::try_parse_cursor_compatible_config(&content, &client_name)
                {
                    return Ok(config);
                }
            }
            Some(MCPClient::VSCode) => {
                // VS Code settings.json may contain MCP configuration
                if filename == "settings.json" {
                    if let Ok(vscode_config) = serde_json::from_str::<VSCodeSettings>(&content) {
                        let parsed = Self::convert_vscode_config(vscode_config);
                        if Self::config_has_servers(&parsed) {
                            debug!("Parsed as VS Code settings configuration format");
                            return Ok(parsed);
                        }
                    }
                }
                // VS Code mcp.json uses the new format
                else if filename == "mcp.json" {
                    if let Ok(vscode_mcp_config) = serde_json::from_str::<VSCodeMCPConfig>(&content)
                    {
                        let parsed = Self::convert_vscode_mcp_config(vscode_mcp_config);
                        if Self::config_has_servers(&parsed) {
                            debug!("Parsed as VS Code MCP configuration format");
                            return Ok(parsed);
                        }
                    }
                }
            }
            _ => {}
        }

        // Fallback chain. Used when client detection didn't match (or matched
        // VS Code but the schema-specific parsers produced an empty config —
        // e.g., a Claude-Desktop-style `{"mcpServers": ...}` saved at a VS
        // Code path). The first parser to yield a non-empty config wins.
        let mcp_config_parse = serde_json::from_str::<MCPConfig>(&content);
        if let Ok(ref config) = mcp_config_parse {
            if Self::config_has_servers(config) {
                return Ok(config.clone());
            }
        }

        if let Some(config) =
            Self::try_parse_cursor_compatible_config(&content, "Cursor MCP (fallback)")
        {
            if Self::config_has_servers(&config) {
                return Ok(config);
            }
        }

        if let Ok(claude_config) = serde_json::from_str::<ClaudeDesktopConfig>(&content) {
            let parsed = Self::convert_claude_desktop_config(claude_config);
            if Self::config_has_servers(&parsed) {
                debug!("Parsed as Claude Desktop configuration format (fallback)");
                return Ok(parsed);
            }
        }

        if let Ok(vscode_config) = serde_json::from_str::<VSCodeSettings>(&content) {
            let parsed = Self::convert_vscode_config(vscode_config);
            if Self::config_has_servers(&parsed) {
                debug!("Parsed as VS Code settings configuration format (fallback)");
                return Ok(parsed);
            }
        }

        if let Ok(vscode_mcp_config) = serde_json::from_str::<VSCodeMCPConfig>(&content) {
            let parsed = Self::convert_vscode_mcp_config(vscode_mcp_config);
            if Self::config_has_servers(&parsed) {
                debug!("Parsed as VS Code MCP configuration format (fallback)");
                return Ok(parsed);
            }
        }

        // Nothing yielded a non-empty config. If at least one parser succeeded
        // syntactically, return that empty config so the caller still sees a
        // "0 servers" entry; otherwise surface the original parse error.
        match mcp_config_parse {
            Ok(config) => Ok(config),
            Err(e) => Err(anyhow!(
                "Failed to parse IDE config file {}: {}",
                path.display(),
                e
            )),
        }
    }

    /// Convert Cursor MCP configuration to standard format
    fn convert_cursor_config(cursor_config: CursorMCPConfig) -> MCPConfig {
        let servers = cursor_config.mcp_servers.map(|mcp_servers| {
            mcp_servers
                .into_iter()
                .filter_map(|(name, server_config)| {
                    // Use explicit URL first, then build from transport config, then handle STDIO servers
                    if let Some(url) = server_config.url {
                        // HTTP server with explicit URL
                        Some(MCPServerConfig {
                            name: Some(name),
                            url: Some(url),
                            command: None,
                            args: None,
                            env: None,
                            description: server_config.description,
                            auth_headers: server_config.headers,
                            options: None,
                        })
                    } else if let Some(transport) = &server_config.transport {
                        // HTTP server with transport configuration
                        let host = transport.host.as_deref().unwrap_or("localhost");
                        let port = transport.port.unwrap_or(8080);
                        #[allow(clippy::match_same_arms)]
                        let scheme = match transport.transport_type.as_deref() {
                            Some("http" | "streamable-http") => "http",
                            Some("https") => "https",
                            _ => "http",
                        };
                        let url = format!("{scheme}://{host}:{port}");

                        Some(MCPServerConfig {
                            name: Some(name),
                            url: Some(url),
                            command: None,
                            args: None,
                            env: None,
                            description: server_config.description,
                            auth_headers: server_config.headers,
                            options: None,
                        })
                    } else if server_config.command.is_some() {
                        // STDIO server with command configuration
                        Some(MCPServerConfig {
                            name: Some(name.clone()),
                            url: None, // STDIO servers don't use URLs
                            command: server_config.command,
                            args: server_config.args,
                            env: server_config.env,
                            description: server_config.description,
                            auth_headers: server_config.headers,
                            options: None,
                        })
                    } else {
                        // Skip servers without proper configuration
                        None
                    }
                })
                .collect()
        });

        MCPConfig {
            servers,
            options: None, // Could convert cursor settings to options if needed
            auth_headers: None,
        }
    }

    /// Convert Claude Desktop configuration to standard format
    fn convert_claude_desktop_config(claude_config: ClaudeDesktopConfig) -> MCPConfig {
        let servers = claude_config.mcp_servers.map(|mcp_servers| {
            mcp_servers
                .into_iter()
                .filter_map(|(name, server_config)| {
                    // Skip disabled servers
                    if server_config.disabled.unwrap_or(false) {
                        return None;
                    }

                    // Use explicit URL if provided, otherwise build from command
                    let url = if let Some(url) = server_config.url {
                        url
                    } else if server_config.command.is_some() {
                        // For command-based servers, create a placeholder URL
                        // This represents a local server that will be started by the command
                        format!("stdio://{name}")
                    } else {
                        // Skip servers without explicit configuration
                        return None;
                    };

                    Some(MCPServerConfig {
                        name: Some(name),
                        url: Some(url),
                        command: None,
                        args: None,
                        env: None,
                        description: None, // Claude Desktop format doesn't include descriptions
                        auth_headers: server_config.headers,
                        options: None,
                    })
                })
                .collect()
        });

        MCPConfig {
            servers,
            options: None,
            auth_headers: None,
        }
    }

    /// Convert VS Code settings configuration to standard format
    fn convert_vscode_config(vscode_config: VSCodeSettings) -> MCPConfig {
        let servers = vscode_config.mcp_servers.map(|mcp_servers| {
            mcp_servers
                .into_iter()
                .filter_map(|(name, server_config)| {
                    let is_http = server_config.url.is_some();
                    let is_stdio = server_config.command.is_some();

                    if !is_http && !is_stdio {
                        return None;
                    }

                    Some(MCPServerConfig {
                        name: Some(name),
                        url: if is_http { server_config.url } else { None },
                        command: if is_stdio {
                            server_config.command
                        } else {
                            None
                        },
                        args: if is_stdio { server_config.args } else { None },
                        env: server_config.env,
                        description: None, // VS Code settings don't typically include descriptions
                        auth_headers: None,
                        options: None,
                    })
                })
                .collect()
        });

        MCPConfig {
            servers,
            options: None,
            auth_headers: None,
        }
    }

    /// Convert VS Code MCP configuration (new mcp.json format) to standard format
    fn convert_vscode_mcp_config(vscode_mcp_config: VSCodeMCPConfig) -> MCPConfig {
        let servers = vscode_mcp_config.servers.map(|servers| {
            servers
                .into_iter()
                .filter_map(|(name, server_config)| {
                    let is_http = server_config.url.is_some();
                    let is_stdio = server_config.command.is_some();

                    if !is_http && !is_stdio {
                        return None;
                    }

                    Some(MCPServerConfig {
                        name: Some(name),
                        url: if is_http { server_config.url } else { None },
                        command: if is_stdio {
                            server_config.command
                        } else {
                            None
                        },
                        args: if is_stdio { server_config.args } else { None },
                        env: server_config.env,
                        description: None, // VS Code MCP format doesn't include descriptions
                        auth_headers: server_config.headers,
                        options: None,
                    })
                })
                .collect()
        });

        MCPConfig {
            servers,
            options: None,
            auth_headers: None,
        }
    }

    /// Try to parse using IDE-specific format, then fall back to standard format with better error reporting
    #[allow(dead_code)]
    fn try_parse_with_fallback<F>(
        ide_name: &str,
        content: &str,
        ide_parser: F,
        path: &Path,
    ) -> Result<MCPConfig>
    where
        F: Fn(&str) -> Result<MCPConfig>,
    {
        match ide_parser(content) {
            Ok(config) => Ok(config),
            Err(ide_error) => {
                // Try standard format as fallback
                match Self::parse_standard_config(content) {
                    Ok(config) => {
                        debug!(
                            "{} format parsing failed for {}, but standard format succeeded. {} error was: {}",
                            ide_name,
                            path.display(),
                            ide_name,
                            ide_error
                        );
                        Ok(config)
                    }
                    Err(standard_error) => {
                        Err(anyhow!(
                            "Failed to parse IDE config file {} in both {} format and standard format. {} format error: {}. Standard format error: {}",
                            path.display(),
                            ide_name,
                            ide_name,
                            ide_error,
                            standard_error
                        ))
                    }
                }
            }
        }
    }

    /// Parse standard Ramparts MCP config format
    #[allow(dead_code)]
    fn parse_standard_config(content: &str) -> Result<MCPConfig> {
        serde_json::from_str(content).map_err(|e| anyhow!("Standard format parsing failed: {}", e))
    }

    /// Parse VS Code MCP config format
    #[allow(dead_code)]
    fn parse_vscode_config(content: &str) -> Result<MCPConfig> {
        // Try array format first (more common), then object format with descriptions, then basic object format
        if let Ok(vscode_array_config) = serde_json::from_str::<VSCodeArrayMCPConfig>(content) {
            Ok(vscode_array_config.into())
        } else if let Ok(vscode_object_config) =
            serde_json::from_str::<VSCodeObjectMCPConfig>(content)
        {
            Ok(vscode_object_config.into())
        } else {
            let vscode_config: VSCodeMCPConfig = serde_json::from_str(content)?;
            Ok(vscode_config.into())
        }
    }

    /// Parse Cursor MCP config format  
    #[allow(dead_code)]
    fn parse_cursor_config(content: &str) -> Result<MCPConfig> {
        let cursor_config: CursorMCPConfig = serde_json::from_str(content)?;
        Ok(cursor_config.into())
    }

    /// Parse Windsurf MCP config format
    #[allow(dead_code)]
    fn parse_windsurf_config(content: &str) -> Result<MCPConfig> {
        let windsurf_config: WindsurfMCPConfig = serde_json::from_str(content)?;
        Ok(windsurf_config.into())
    }

    /// Parse Claude Desktop MCP config format
    #[allow(dead_code)]
    fn parse_claude_config(content: &str) -> Result<MCPConfig> {
        let claude_config: ClaudeMCPConfig = serde_json::from_str(content)?;
        Ok(claude_config.into())
    }

    /// Parse Claude Code MCP config format (from ~/.claude/settings.json)
    #[allow(dead_code)]
    fn parse_claude_code_config(content: &str) -> Result<MCPConfig> {
        let claude_code_config: ClaudeCodeConfig = serde_json::from_str(content)?;
        Ok(claude_code_config.into())
    }

    /// Parse Zed MCP config format
    #[allow(dead_code)]
    fn parse_zed_config(content: &str) -> Result<MCPConfig> {
        let zed_config: ZedMCPConfig = serde_json::from_str(content)?;
        Ok(zed_config.into())
    }

    /// Parse Zencoder MCP config format
    #[allow(dead_code)]
    fn parse_zencoder_config(content: &str) -> Result<MCPConfig> {
        let zencoder_config: ZencoderMCPConfig = serde_json::from_str(content)?;
        Ok(zencoder_config.into())
    }

    /// Merge two configurations with IDE source information
    /// Handles server deduplication based on URL and preserves IDE source
    fn merge_config_with_source(base: &mut MCPConfig, other: &MCPConfig, ide_name: &str) {
        // Clone the config and add IDE source info to each server
        let mut config_with_source = other.clone();
        if let Some(ref mut servers) = config_with_source.servers {
            for server in servers.iter_mut() {
                // Store IDE name in description field with a prefix
                let ide_info = format!("IDE:{ide_name}");
                match &server.description {
                    Some(desc) => {
                        server.description = Some(format!("{desc} [{ide_info}]"));
                    }
                    None => {
                        server.description = Some(format!("[{ide_info}]"));
                    }
                }
            }
        }

        Self::merge_config(base, &config_with_source);
    }

    /// Merge two configurations, with the second one taking precedence
    /// Handles server deduplication based on URL
    fn merge_config(base: &mut MCPConfig, other: &MCPConfig) {
        // Merge servers with deduplication
        if let Some(other_servers) = &other.servers {
            match &mut base.servers {
                Some(base_servers) => {
                    // Pre-allocate HashMap with capacity hint for better performance
                    let total_capacity = base_servers.len() + other_servers.len();
                    let mut server_map: HashMap<String, MCPServerConfig> =
                        HashMap::with_capacity(total_capacity);

                    // Move existing servers to the map using drain() to avoid cloning
                    for server in base_servers.drain(..) {
                        let key = server.dedup_key();
                        server_map.insert(key, server);
                    }

                    // Add new servers - we must clone since we're borrowing from other
                    for server in other_servers {
                        let key = server.dedup_key();
                        server_map.insert(key, server.clone());
                    }

                    // Convert back to vector
                    *base_servers = server_map.into_values().collect();
                }
                None => {
                    // Avoid cloning the entire vector - move if possible
                    base.servers = Some(other_servers.clone());
                }
            }
        }

        // Merge global options
        if let Some(other_options) = &other.options {
            match &mut base.options {
                Some(base_options) => {
                    if other_options.timeout.is_some() {
                        base_options.timeout = other_options.timeout;
                    }
                    if other_options.http_timeout.is_some() {
                        base_options.http_timeout = other_options.http_timeout;
                    }
                    if other_options.format.is_some() {
                        base_options.format.clone_from(&other_options.format);
                    }
                    if other_options.detailed.is_some() {
                        base_options.detailed = other_options.detailed;
                    }
                }
                None => {
                    base.options = Some(other_options.clone());
                }
            }
        }

        // Merge auth headers
        if let Some(other_auth_headers) = &other.auth_headers {
            match &mut base.auth_headers {
                Some(base_auth_headers) => {
                    for (key, value) in other_auth_headers {
                        base_auth_headers.insert(key.clone(), value.clone());
                    }
                }
                None => {
                    base.auth_headers = Some(other_auth_headers.clone());
                }
            }
        }
    }

    /// Validate a loaded MCP configuration with comprehensive checks
    fn validate_server_count(servers: &[MCPServerConfig]) -> Result<()> {
        if servers.len() > 100 {
            return Err(anyhow!(
                "Too many servers configured ({}). Maximum recommended: 100",
                servers.len()
            ));
        }
        Ok(())
    }

    /// Comprehensive server configuration validation
    fn validate_server_config(server: &MCPServerConfig, server_index: usize) -> Result<()> {
        // Validate that server has either URL or command, but not both
        match (&server.url, &server.command) {
            (Some(url), None) => {
                // HTTP server - validate URL
                Self::validate_server_url(url, server_index)?;
            }
            (None, Some(command)) => {
                // STDIO server - validate command and args
                Self::validate_stdio_server(command, server.args.as_ref(), server_index)?;
            }
            (Some(_), Some(_)) => {
                return Err(anyhow!(
                    "Server {} cannot have both URL and command specified - choose HTTP (url) or STDIO (command)",
                    server_index
                ));
            }
            (None, None) => {
                return Err(anyhow!(
                    "Server {} must have either URL (for HTTP servers) or command (for STDIO servers) specified",
                    server_index
                ));
            }
        }

        // Validate server name if present
        if let Some(name) = &server.name {
            Self::validate_server_name(name, server_index)?;
        }

        // Validate environment variables if present
        if let Some(env) = &server.env {
            Self::validate_env_vars(env, server_index)?;
        }

        Ok(())
    }

    /// Validate STDIO server configuration
    fn validate_stdio_server(
        command: &str,
        args: Option<&Vec<String>>,
        server_index: usize,
    ) -> Result<()> {
        if command.trim().is_empty() {
            return Err(anyhow!("Server {} has empty command", server_index));
        }

        if command.len() > 1024 {
            return Err(anyhow!(
                "Server {} command too long ({}), maximum 1024 characters",
                server_index,
                command.len()
            ));
        }

        // Validate command doesn't contain dangerous characters
        if command.contains('\0') || command.contains('\n') || command.contains('\r') {
            return Err(anyhow!(
                "Server {} command contains invalid characters",
                server_index
            ));
        }

        // Validate arguments if present
        if let Some(args_vec) = args {
            if args_vec.len() > 100 {
                return Err(anyhow!(
                    "Server {} has too many arguments ({}), maximum 100",
                    server_index,
                    args_vec.len()
                ));
            }

            for (arg_index, arg) in args_vec.iter().enumerate() {
                if arg.len() > 4096 {
                    return Err(anyhow!(
                        "Server {} argument {} too long ({}), maximum 4096 characters",
                        server_index,
                        arg_index,
                        arg.len()
                    ));
                }

                if arg.contains('\0') {
                    return Err(anyhow!(
                        "Server {} argument {} contains null character",
                        server_index,
                        arg_index
                    ));
                }
            }
        }

        Ok(())
    }

    /// Validate environment variables
    fn validate_env_vars(env: &HashMap<String, String>, server_index: usize) -> Result<()> {
        if env.len() > 100 {
            return Err(anyhow!(
                "Server {} has too many environment variables ({}), maximum 100",
                server_index,
                env.len()
            ));
        }

        for (key, value) in env {
            if key.trim().is_empty() {
                return Err(anyhow!(
                    "Server {} has empty environment variable name",
                    server_index
                ));
            }

            if key.len() > 1024 {
                return Err(anyhow!(
                    "Server {} environment variable name '{}' too long ({}), maximum 1024 characters",
                    server_index,
                    key,
                    key.len()
                ));
            }

            if value.len() > 8192 {
                return Err(anyhow!(
                    "Server {} environment variable value for '{}' too long ({}), maximum 8192 characters",
                    server_index,
                    key,
                    value.len()
                ));
            }

            // Validate key format (must be valid environment variable name)
            if !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                return Err(anyhow!(
                    "Server {} environment variable name '{}' contains invalid characters (only alphanumeric and underscore allowed)",
                    server_index,
                    key
                ));
            }

            if key.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                return Err(anyhow!(
                    "Server {} environment variable name '{}' cannot start with a digit",
                    server_index,
                    key
                ));
            }
        }

        Ok(())
    }

    fn validate_server_url(url_str: &str, server_index: usize) -> Result<()> {
        if url_str.is_empty() {
            return Err(anyhow!("Server {} has empty URL", server_index));
        }

        let url_str = url_str.trim();
        if url_str.len() > 2048 {
            return Err(anyhow!(
                "Server {} URL too long ({}), maximum 2048 characters",
                server_index,
                url_str.len()
            ));
        }

        // stdio: URLs should not be handled here - they should use command field instead
        if url_str.starts_with("stdio:") {
            return Err(anyhow!(
                "Server {} uses deprecated stdio: URL format. Use 'command' and 'args' fields instead of 'url' for STDIO servers",
                server_index
            ));
        }

        // Parse HTTP/HTTPS URLs using the url crate
        if url_str.starts_with("http://") || url_str.starts_with("https://") {
            match Url::parse(url_str) {
                Ok(parsed_url) => {
                    // Validate port if present
                    if let Some(port) = parsed_url.port() {
                        if port == 0 {
                            return Err(anyhow!(
                                "Server {} has invalid port 0: {}",
                                server_index,
                                url_str
                            ));
                        }
                    }
                    Ok(())
                }
                Err(e) => Err(anyhow!(
                    "Server {} has malformed URL '{}': {}",
                    server_index,
                    url_str,
                    e
                )),
            }
        } else {
            Err(anyhow!(
                "Server {} has invalid URL scheme: {}. Supported: http://, https://, stdio:",
                server_index,
                url_str
            ))
        }
    }

    fn validate_server_name(name: &str, server_index: usize) -> Result<()> {
        let name = name.trim();
        if name.is_empty() {
            return Err(anyhow!("Server {} has empty name", server_index));
        }

        if name.len() > 255 {
            return Err(anyhow!(
                "Server {} name too long ({}), maximum 255 characters",
                server_index,
                name.len()
            ));
        }

        Ok(())
    }

    fn validate_auth_headers(
        auth_headers: &HashMap<String, String>,
        server_index: usize,
    ) -> Result<()> {
        for (header_name, header_value) in auth_headers {
            if header_name.trim().is_empty() {
                return Err(anyhow!(
                    "Server {} has empty auth header name",
                    server_index
                ));
            }
            if header_value.trim().is_empty() {
                return Err(anyhow!(
                    "Server {} has empty auth header value for '{}'",
                    server_index,
                    header_name
                ));
            }
            if header_name.len() > 1024 || header_value.len() > 4096 {
                return Err(anyhow!(
                    "Server {} has auth header that's too long",
                    server_index
                ));
            }
        }
        Ok(())
    }

    fn validate_server_description(description: &str, server_index: usize) -> Result<()> {
        if description.len() > 1000 {
            return Err(anyhow!(
                "Server {} description too long ({}), maximum 1000 characters",
                server_index,
                description.len()
            ));
        }
        Ok(())
    }

    fn validate_global_auth_headers(global_auth_headers: &HashMap<String, String>) -> Result<()> {
        for (header_name, header_value) in global_auth_headers {
            if header_name.trim().is_empty() || header_value.trim().is_empty() {
                return Err(anyhow!(
                    "Global auth headers cannot have empty names or values"
                ));
            }
        }
        Ok(())
    }

    fn validate_config(config: &MCPConfig) -> Result<()> {
        if let Some(servers) = &config.servers {
            Self::validate_server_count(servers)?;

            let mut seen_dedup_keys = HashMap::new();
            let mut seen_names = HashMap::new();

            for (i, server) in servers.iter().enumerate() {
                // Validate the entire server configuration
                Self::validate_server_config(server, i)?;

                // Check for duplicate servers using the same deduplication logic as merge
                let dedup_key = server.dedup_key();
                if let Some(existing_index) = seen_dedup_keys.get(&dedup_key) {
                    return Err(anyhow!(
                        "Duplicate server configuration detected: server {} and server {} both resolve to the same configuration (key: '{}')",
                        existing_index, i, dedup_key
                    ));
                }
                seen_dedup_keys.insert(dedup_key, i);

                if let Some(name) = &server.name {
                    Self::validate_server_name(name, i)?;
                    let name = name.trim();
                    if let Some(existing_index) = seen_names.get(name) {
                        return Err(anyhow!(
                            "Duplicate server name '{}': server {} and server {} both use this name",
                            name, existing_index, i
                        ));
                    }
                    seen_names.insert(name.to_string(), i);
                }

                if let Some(auth_headers) = &server.auth_headers {
                    Self::validate_auth_headers(auth_headers, i)?;
                }

                if let Some(description) = &server.description {
                    Self::validate_server_description(description, i)?;
                }
            }
        }

        if let Some(global_auth_headers) = &config.auth_headers {
            Self::validate_global_auth_headers(global_auth_headers)?;
        }

        Ok(())
    }

    /// Check if any IDE configuration files exist
    pub fn has_config_files(&self) -> bool {
        self.config_paths.iter().any(|(path, _)| path.exists())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_load_config_from_path() {
        let temp_dir = tempdir().unwrap();
        let config_path = temp_dir.path().join("test_config.json");

        let config_content = r#"{
            "servers": [
                {
                    "name": "test-server",
                    "url": "http://localhost:3000",
                    "description": "Test server"
                }
            ],
            "options": {
                "timeout": 60,
                "format": "json"
            }
        }"#;

        fs::write(&config_path, config_content).unwrap();

        let config = MCPConfigManager::load_config_from_path(&config_path).unwrap();

        assert!(config.servers.is_some());
        assert_eq!(config.servers.unwrap().len(), 1);
        assert!(config.options.is_some());
    }

    #[test]
    fn test_merge_config() {
        let mut base = MCPConfig::default();
        let other = MCPConfig {
            servers: Some(vec![MCPServerConfig {
                name: Some("server1".to_string()),
                url: Some("http://localhost:3000".to_string()),
                command: None,
                args: None,
                env: None,
                description: None,
                auth_headers: None,
                options: None,
            }]),
            options: Some(MCPGlobalOptions {
                timeout: Some(60),
                http_timeout: None,
                format: Some("json".to_string()),
                detailed: None,
            }),
            auth_headers: None,
        };

        MCPConfigManager::merge_config(&mut base, &other);

        assert!(base.servers.is_some());
        assert_eq!(base.servers.unwrap().len(), 1);
        assert!(base.options.is_some());
    }

    #[test]
    fn test_merge_config_deduplication() {
        let mut base = MCPConfig {
            servers: Some(vec![MCPServerConfig {
                name: Some("server1".to_string()),
                url: Some("http://localhost:3000".to_string()),
                command: None,
                args: None,
                env: None,
                description: None,
                auth_headers: None,
                options: None,
            }]),
            options: None,
            auth_headers: None,
        };

        let other = MCPConfig {
            servers: Some(vec![
                MCPServerConfig {
                    name: Some("server1-updated".to_string()),
                    url: Some("http://localhost:3000".to_string()), // Same URL - should replace
                    command: None,
                    args: None,
                    env: None,
                    description: Some("Updated server".to_string()),
                    auth_headers: None,
                    options: None,
                },
                MCPServerConfig {
                    name: Some("server2".to_string()),
                    url: Some("http://localhost:4000".to_string()), // Different URL - should add
                    command: None,
                    args: None,
                    env: None,
                    description: None,
                    auth_headers: None,
                    options: None,
                },
            ]),
            options: None,
            auth_headers: None,
        };

        MCPConfigManager::merge_config(&mut base, &other);

        let servers = base.servers.unwrap();
        assert_eq!(servers.len(), 2); // Should have 2 servers, not 3

        // Find the server with URL localhost:3000 - should be the updated one
        let updated_server = servers
            .iter()
            .find(|s| s.url.as_deref() == Some("http://localhost:3000"))
            .unwrap();
        assert_eq!(updated_server.name.as_ref().unwrap(), "server1-updated");
        assert_eq!(
            updated_server.description.as_ref().unwrap(),
            "Updated server"
        );

        // Should also have the new server
        let new_server = servers
            .iter()
            .find(|s| s.url.as_deref() == Some("http://localhost:4000"))
            .unwrap();
        assert_eq!(new_server.name.as_ref().unwrap(), "server2");
    }

    #[test]
    fn test_detect_client() {
        assert_eq!(
            MCPConfigManager::detect_client("/home/user/.cursor/mcp.json"),
            Some(MCPClient::Cursor)
        );
        assert_eq!(
            MCPConfigManager::detect_client("/home/user/.codeium/windsurf/mcp_config.json"),
            Some(MCPClient::Windsurf)
        );
        assert_eq!(
            MCPConfigManager::detect_client("/home/user/.vscode/mcp.json"),
            Some(MCPClient::VSCode)
        );
        assert_eq!(
            MCPConfigManager::detect_client("/home/user/.claude/mcp.json"),
            Some(MCPClient::Claude)
        );
        assert_eq!(
            MCPConfigManager::detect_client("/home/user/.config/nvim/mcp.json"),
            Some(MCPClient::Neovim)
        );
        assert_eq!(
            MCPConfigManager::detect_client("/some/unknown/path.json"),
            None
        );
    }

    #[test]
    fn test_validate_config() {
        // Valid config
        let valid_config = MCPConfig {
            servers: Some(vec![MCPServerConfig {
                name: Some("test".to_string()),
                url: Some("http://localhost:3000".to_string()),
                command: None,
                args: None,
                env: None,
                description: None,
                auth_headers: None,
                options: None,
            }]),
            options: None,
            auth_headers: None,
        };
        assert!(MCPConfigManager::validate_config(&valid_config).is_ok());

        // Invalid config - empty URL
        let invalid_config = MCPConfig {
            servers: Some(vec![MCPServerConfig {
                name: Some("test".to_string()),
                url: Some(String::new()),
                command: None,
                args: None,
                env: None,
                description: None,
                auth_headers: None,
                options: None,
            }]),
            options: None,
            auth_headers: None,
        };
        assert!(MCPConfigManager::validate_config(&invalid_config).is_err());

        // Invalid config - bad URL format
        let invalid_config2 = MCPConfig {
            servers: Some(vec![MCPServerConfig {
                name: Some("test".to_string()),
                url: Some("not-a-url".to_string()),
                command: None,
                args: None,
                env: None,
                description: None,
                auth_headers: None,
                options: None,
            }]),
            options: None,
            auth_headers: None,
        };
        assert!(MCPConfigManager::validate_config(&invalid_config2).is_err());
    }

    #[test]
    fn test_mcp_client_enum() {
        assert_eq!(MCPClient::Cursor.name(), "cursor");
        assert_eq!(MCPClient::Windsurf.name(), "windsurf");
        assert_eq!(MCPClient::VSCode.name(), "vscode");
        assert_eq!(MCPClient::Claude.name(), "claude");
        assert_eq!(MCPClient::Neovim.name(), "neovim");
        assert_eq!(MCPClient::Helix.name(), "helix");
        assert_eq!(MCPClient::Zed.name(), "zed");
        assert_eq!(MCPClient::Zencoder.name(), "zencoder");
    }

    #[test]
    fn test_url_normalization() {
        assert_eq!(
            MCPConfigManager::normalize_url("HTTP://LOCALHOST:3000/"),
            "http://localhost:3000"
        );
        assert_eq!(
            MCPConfigManager::normalize_url("http://127.0.0.1:3000"),
            "http://localhost:3000"
        );
        assert_eq!(
            MCPConfigManager::normalize_url("https://0.0.0.0:8080/"),
            "https://localhost:8080"
        );
        assert_eq!(MCPConfigManager::normalize_url("stdio:test"), "stdio:test");
        assert_eq!(
            MCPConfigManager::normalize_url("http://example.com/path/"),
            "http://example.com/path"
        );
    }

    #[test]
    fn test_enhanced_client_detection() {
        use std::path::PathBuf;

        // Test exact component matches
        assert_eq!(
            MCPConfigManager::detect_client(PathBuf::from(
                "/Applications/Cursor.app/Contents/mcp.json"
            )),
            Some(MCPClient::Cursor)
        );

        // Test Windows paths - use forward slashes for cross-platform compatibility
        assert_eq!(
            MCPConfigManager::detect_client(PathBuf::from(
                "C:/Users/test/AppData/Roaming/Code/User/mcp.json"
            )),
            Some(MCPClient::VSCode)
        );

        // Test extension ID path
        assert_eq!(
            MCPConfigManager::detect_client(PathBuf::from(
                "/home/user/.config/rooveterinaryinc.cursor-mcp/config.json"
            )),
            Some(MCPClient::Cursor)
        );

        // Test disambiguation - should not match generic "code" in paths
        assert_eq!(
            MCPConfigManager::detect_client(PathBuf::from(
                "/home/user/my-code-project/config.json"
            )),
            None
        );
    }

    #[test]
    fn test_enhanced_validation() {
        // Test duplicate URL detection with normalization
        let config_with_duplicate_urls = MCPConfig {
            servers: Some(vec![
                MCPServerConfig {
                    name: Some("server1".to_string()),
                    url: Some("http://localhost:3000".to_string()),
                    command: None,
                    args: None,
                    env: None,
                    description: None,
                    auth_headers: None,
                    options: None,
                },
                MCPServerConfig {
                    name: Some("server2".to_string()),
                    url: Some("HTTP://LOCALHOST:3000/".to_string()), // Different case and trailing slash
                    command: None,
                    args: None,
                    env: None,
                    description: None,
                    auth_headers: None,
                    options: None,
                },
            ]),
            options: None,
            auth_headers: None,
        };
        assert!(MCPConfigManager::validate_config(&config_with_duplicate_urls).is_err());

        // Test duplicate names
        let config_with_duplicate_names = MCPConfig {
            servers: Some(vec![
                MCPServerConfig {
                    name: Some("same-name".to_string()),
                    url: Some("http://localhost:3000".to_string()),
                    command: None,
                    args: None,
                    env: None,
                    description: None,
                    auth_headers: None,
                    options: None,
                },
                MCPServerConfig {
                    name: Some("same-name".to_string()),
                    url: Some("http://localhost:4000".to_string()),
                    command: None,
                    args: None,
                    env: None,
                    description: None,
                    auth_headers: None,
                    options: None,
                },
            ]),
            options: None,
            auth_headers: None,
        };
        assert!(MCPConfigManager::validate_config(&config_with_duplicate_names).is_err());

        // Test invalid port
        let config_with_invalid_port = MCPConfig {
            servers: Some(vec![MCPServerConfig {
                name: Some("test".to_string()),
                url: Some("http://localhost:0".to_string()),
                command: None,
                args: None,
                env: None,
                description: None,
                auth_headers: None,
                options: None,
            }]),
            options: None,
            auth_headers: None,
        };
        assert!(MCPConfigManager::validate_config(&config_with_invalid_port).is_err());
    }

    #[test]
    fn test_platform_detection() {
        // Test that platform detection works without panicking
        let paths = MCPConfigManager::discover_config_paths();
        assert!(
            !paths.is_empty(),
            "Should discover some configuration paths"
        );
    }

    #[test]
    fn test_merge_config_with_normalization() {
        let mut base = MCPConfig {
            servers: Some(vec![MCPServerConfig {
                name: Some("server1".to_string()),
                url: Some("http://localhost:3000/".to_string()), // With trailing slash
                command: None,
                args: None,
                env: None,
                description: None,
                auth_headers: None,
                options: None,
            }]),
            options: None,
            auth_headers: None,
        };

        let other = MCPConfig {
            servers: Some(vec![MCPServerConfig {
                name: Some("server1-updated".to_string()),
                url: Some("HTTP://LOCALHOST:3000".to_string()), // Different case, no trailing slash
                command: None,
                args: None,
                env: None,
                description: Some("Updated".to_string()),
                auth_headers: None,
                options: None,
            }]),
            options: None,
            auth_headers: None,
        };

        MCPConfigManager::merge_config(&mut base, &other);

        let servers = base.servers.unwrap();
        assert_eq!(servers.len(), 1); // Should be deduplicated due to URL normalization
        assert_eq!(servers[0].name.as_ref().unwrap(), "server1-updated");
        assert_eq!(servers[0].description.as_ref().unwrap(), "Updated");
    }

    #[test]
    fn test_vscode_config_parsing() {
        let vscode_content = r#"{
            "servers": {
                "github": {
                    "type": "http",
                    "url": "https://api.githubcopilot.com/mcp/",
                    "gallery": true
                },
                "local-fs": {
                    "type": "stdio",
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
                    "description": "Local filesystem access"
                }
            },
            "inputs": []
        }"#;

        // Test VS Code format parsing
        let result = MCPConfigManager::parse_vscode_config(vscode_content);
        assert!(
            result.is_ok(),
            "Failed to parse VS Code config: {:?}",
            result.err()
        );

        let config = result.unwrap();
        assert!(config.servers.is_some());
        let servers = config.servers.unwrap();
        assert_eq!(servers.len(), 2);

        // Check github server
        let github_server = servers
            .iter()
            .find(|s| s.name.as_deref() == Some("github"))
            .unwrap();
        assert_eq!(
            github_server.url,
            Some("https://api.githubcopilot.com/mcp/".to_string())
        );

        // Check local-fs server
        let fs_server = servers
            .iter()
            .find(|s| s.name.as_deref() == Some("local-fs"))
            .unwrap();
        assert_eq!(fs_server.url, None);
        assert_eq!(
            fs_server.description,
            Some("Local filesystem access".to_string())
        );
    }

    #[test]
    fn test_zed_config_parsing() {
        let zed_content = r#"{
            "context_servers": [
                {
                    "mcp-server-git": {
                        "command": {
                            "path": "uvx",
                            "args": ["mcp-server-git"]
                        }
                    }
                },
                {
                    "filesystem": {
                        "command": {
                            "path": "node",
                            "args": ["/path/to/filesystem-server.js", "/tmp"]
                        }
                    }
                }
            ]
        }"#;

        // Test Zed format parsing
        let result = MCPConfigManager::parse_zed_config(zed_content);
        assert!(
            result.is_ok(),
            "Failed to parse Zed config: {:?}",
            result.err()
        );

        let config = result.unwrap();
        assert!(config.servers.is_some());
        let servers = config.servers.unwrap();
        assert_eq!(servers.len(), 2);

        // Check git server
        let git_server = servers
            .iter()
            .find(|s| s.name.as_deref() == Some("mcp-server-git"))
            .unwrap();
        assert_eq!(git_server.url, None);
        assert!(git_server
            .description
            .as_ref()
            .unwrap()
            .contains("uvx mcp-server-git"));

        // Check filesystem server
        let fs_server = servers
            .iter()
            .find(|s| s.name.as_deref() == Some("filesystem"))
            .unwrap();
        assert_eq!(fs_server.url, None);
        assert!(fs_server
            .description
            .as_ref()
            .unwrap()
            .contains("node /path/to/filesystem-server.js /tmp"));
    }

    #[test]
    fn test_zencoder_config_parsing() {
        let zencoder_content = r#"{
            "command": "uvx",
            "args": ["mcp-server-git", "--repository", "path/to/git/repo"]
        }"#;

        // Test Zencoder format parsing
        let result = MCPConfigManager::parse_zencoder_config(zencoder_content);
        assert!(
            result.is_ok(),
            "Failed to parse Zencoder config: {:?}",
            result.err()
        );

        let config = result.unwrap();
        assert!(config.servers.is_some());
        let servers = config.servers.unwrap();
        assert_eq!(servers.len(), 1);

        // Check zencoder server
        let zencoder_server = &servers[0];
        assert_eq!(zencoder_server.name.as_deref(), Some("zencoder"));
        assert_eq!(zencoder_server.url, None);
        assert_eq!(zencoder_server.command.as_deref(), Some("uvx"));
        assert_eq!(
            zencoder_server.args,
            Some(vec![
                "mcp-server-git".to_string(),
                "--repository".to_string(),
                "path/to/git/repo".to_string()
            ])
        );
        assert_eq!(
            zencoder_server.description.as_deref(),
            Some("Zencoder MCP server")
        );
    }

    #[test]
    fn test_cursor_config_parsing() {
        let cursor_content = r#"{
            "mcpServers": {
                "airbnb": {
                    "command": "npx",
                    "args": ["-y", "@openbnb/mcp-server-airbnb"]
                },
                "playwright": {
                    "command": "npx",
                    "args": ["-y", "@executeautomation/playwright-mcp-server"]
                },
                "time": {
                    "command": "uvx",
                    "args": ["mcp-server-time"],
                    "env": {
                        "TZ": "UTC"
                    }
                }
            }
        }"#;

        // Test Cursor format parsing
        let result = MCPConfigManager::parse_cursor_config(cursor_content);
        assert!(
            result.is_ok(),
            "Failed to parse Cursor config: {:?}",
            result.err()
        );

        let config = result.unwrap();
        assert!(config.servers.is_some());
        let servers = config.servers.unwrap();
        assert_eq!(servers.len(), 3);

        // Check airbnb server
        let airbnb_server = servers
            .iter()
            .find(|s| s.name.as_deref() == Some("airbnb"))
            .unwrap();
        assert_eq!(airbnb_server.command, Some("npx".to_string()));
        assert_eq!(
            airbnb_server.args,
            Some(vec![
                "-y".to_string(),
                "@openbnb/mcp-server-airbnb".to_string()
            ])
        );
        assert_eq!(airbnb_server.url, None);

        // Check time server with env
        let time_server = servers
            .iter()
            .find(|s| s.name.as_deref() == Some("time"))
            .unwrap();
        assert_eq!(time_server.command, Some("uvx".to_string()));
        assert!(time_server.env.is_some());
        let env = time_server.env.as_ref().unwrap();
        assert_eq!(env.get("TZ"), Some(&"UTC".to_string()));
    }

    #[test]
    fn test_windsurf_config_parsing() {
        let windsurf_content = r#"{
            "servers": {
                "git": {
                    "command": "uvx",
                    "args": ["mcp-server-git"],
                    "type": "stdio"
                },
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
                    "description": "File system access",
                    "env": {
                        "NODE_ENV": "development"
                    }
                }
            },
            "global": {
                "timeout": 30
            }
        }"#;

        // Test Windsurf format parsing
        let result = MCPConfigManager::parse_windsurf_config(windsurf_content);
        assert!(
            result.is_ok(),
            "Failed to parse Windsurf config: {:?}",
            result.err()
        );

        let config = result.unwrap();
        assert!(config.servers.is_some());
        let servers = config.servers.unwrap();
        assert_eq!(servers.len(), 2);

        // Check git server
        let git_server = servers
            .iter()
            .find(|s| s.name.as_deref() == Some("git"))
            .unwrap();
        assert_eq!(git_server.command, Some("uvx".to_string()));
        assert_eq!(git_server.args, Some(vec!["mcp-server-git".to_string()]));

        // Check filesystem server
        let fs_server = servers
            .iter()
            .find(|s| s.name.as_deref() == Some("filesystem"))
            .unwrap();
        assert_eq!(
            fs_server.description,
            Some("File system access".to_string())
        );
        assert!(fs_server.env.is_some());
    }

    #[test]
    fn test_claude_desktop_config_parsing() {
        let claude_content = r#"{
            "mcpServers": {
                "brave-search": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-brave-search"],
                    "env": {
                        "BRAVE_API_KEY": "your-api-key"
                    }
                },
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users/username/Desktop"],
                    "type": "stdio"
                }
            }
        }"#;

        // Test Claude Desktop format parsing
        let result = MCPConfigManager::parse_claude_config(claude_content);
        assert!(
            result.is_ok(),
            "Failed to parse Claude Desktop config: {:?}",
            result.err()
        );

        let config = result.unwrap();
        assert!(config.servers.is_some());
        let servers = config.servers.unwrap();
        assert_eq!(servers.len(), 2);

        // Check brave-search server
        let brave_server = servers
            .iter()
            .find(|s| s.name.as_deref() == Some("brave-search"))
            .unwrap();
        assert_eq!(brave_server.command, Some("npx".to_string()));
        assert!(brave_server.env.is_some());
        let env = brave_server.env.as_ref().unwrap();
        assert_eq!(env.get("BRAVE_API_KEY"), Some(&"your-api-key".to_string()));

        // Check filesystem server
        let fs_server = servers
            .iter()
            .find(|s| s.name.as_deref() == Some("filesystem"))
            .unwrap();
        assert_eq!(fs_server.command, Some("npx".to_string()));
        assert!(fs_server
            .args
            .as_ref()
            .unwrap()
            .contains(&"/Users/username/Desktop".to_string()));
    }

    #[test]
    fn test_claude_code_config_parsing() {
        let claude_code_content = r#"{
            "numStartups": 36,
            "installMethod": "unknown", 
            "mcpServers": {
                "sequential-thinking": {
                    "type": "stdio",
                    "command": "npx",
                    "args": ["-y", "u/modelcontextprotocol/server-sequential-thinking"],
                    "env": {}
                },
                "filesystem": {
                    "type": "stdio",
                    "command": "uvx",
                    "args": ["mcp-server-filesystem", "/tmp"],
                    "env": {
                        "DEBUG": "true"
                    }
                }
            }
        }"#;

        // Test Claude Code format parsing
        let result = MCPConfigManager::parse_claude_code_config(claude_code_content);
        assert!(
            result.is_ok(),
            "Failed to parse Claude Code config: {:?}",
            result.err()
        );

        let config = result.unwrap();
        assert!(config.servers.is_some());
        let servers = config.servers.unwrap();
        assert_eq!(servers.len(), 2);

        // Check sequential-thinking server
        let seq_server = servers
            .iter()
            .find(|s| s.name.as_deref() == Some("sequential-thinking"))
            .unwrap();
        assert_eq!(seq_server.command, Some("npx".to_string()));
        assert_eq!(
            seq_server.args,
            Some(vec![
                "-y".to_string(),
                "u/modelcontextprotocol/server-sequential-thinking".to_string()
            ])
        );
        assert_eq!(seq_server.url, None);

        // Check filesystem server with env
        let fs_server = servers
            .iter()
            .find(|s| s.name.as_deref() == Some("filesystem"))
            .unwrap();
        assert_eq!(fs_server.command, Some("uvx".to_string()));
        assert!(fs_server.env.is_some());
        let env = fs_server.env.as_ref().unwrap();
        assert_eq!(env.get("DEBUG"), Some(&"true".to_string()));
    }

    #[test]
    fn test_vscode_array_config_parsing() {
        let vscode_array_content = r#"{
            "servers": [
                {
                    "name": "time",
                    "command": "uvx",
                    "args": ["mcp-server-time"]
                },
                {
                    "name": "everything",
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-everything"]
                },
                {
                    "name": "git",
                    "command": "uvx",
                    "args": ["mcp-server-git"]
                },
                {
                    "name": "Neon",
                    "command": "npx",
                    "args": ["-y", "mcp-remote", "https://mcp.neon.tech/mcp"]
                }
            ]
        }"#;

        // Test VS Code array format parsing
        let result = MCPConfigManager::parse_vscode_config(vscode_array_content);
        assert!(
            result.is_ok(),
            "Failed to parse VS Code array config: {:?}",
            result.err()
        );

        let config = result.unwrap();
        assert!(config.servers.is_some());
        let servers = config.servers.unwrap();
        assert_eq!(servers.len(), 4);

        // Check time server
        let time_server = servers
            .iter()
            .find(|s| s.name.as_deref() == Some("time"))
            .unwrap();
        assert_eq!(time_server.command, Some("uvx".to_string()));
        assert_eq!(time_server.args, Some(vec!["mcp-server-time".to_string()]));

        // Check Neon server
        let neon_server = servers
            .iter()
            .find(|s| s.name.as_deref() == Some("Neon"))
            .unwrap();
        assert_eq!(neon_server.command, Some("npx".to_string()));
        assert!(neon_server
            .args
            .as_ref()
            .unwrap()
            .contains(&"https://mcp.neon.tech/mcp".to_string()));
    }

    #[test]
    fn test_client_path_detection_claude_code() {
        // Test Claude Code vs Claude Desktop path detection
        assert_eq!(
            MCPConfigManager::detect_client("/home/user/.claude/settings.json"),
            Some(MCPClient::ClaudeCode)
        );
        assert_eq!(
            MCPConfigManager::detect_client("/home/user/.claude/settings.local.json"),
            Some(MCPClient::ClaudeCode)
        );
        assert_eq!(
            MCPConfigManager::detect_client("/home/user/.claude/mcp.json"),
            Some(MCPClient::Claude)
        );

        // Test Windsurf path detection (corrected path)
        assert_eq!(
            MCPConfigManager::detect_client("/home/user/.codeium/windsurf/mcp_config.json"),
            Some(MCPClient::Windsurf)
        );
    }

    #[test]
    fn test_gemini_config_parsing() {
        let gemini_content = r#"{
            "mcpServers": {
                "github": {
                    "command": "npx",
                    "args": [
                        "-y",
                        "@modelcontextprotocol/server-github"
                    ],
                    "env": {
                        "GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_example_personal_access_token12345"
                    }
                },
                "gitlab": {
                    "command": "npx",
                    "args": [
                        "-y",
                        "@modelcontextprotocol/server-gitlab"
                    ]
                },
                "cloudflare-observability": {
                    "command": "npx",
                    "args": ["mcp-remote", "https://observability.mcp.cloudflare.com/sse"]
                },
                "cloudflare-bindings": {
                    "command": "npx",
                    "args": ["mcp-remote", "https://bindings.mcp.cloudflare.com/sse"]
                }
            }
        }"#;

        // Test Gemini format parsing (reuses Cursor parsing logic since format is the same)
        let result = MCPConfigManager::parse_cursor_config(gemini_content);
        assert!(
            result.is_ok(),
            "Failed to parse Gemini config: {:?}",
            result.err()
        );

        let config = result.unwrap();
        assert!(config.servers.is_some());
        let servers = config.servers.unwrap();
        assert_eq!(servers.len(), 4);

        // Check github server with env
        let github_server = servers
            .iter()
            .find(|s| s.name.as_deref() == Some("github"))
            .unwrap();
        assert_eq!(github_server.command, Some("npx".to_string()));
        assert_eq!(
            github_server.args,
            Some(vec![
                "-y".to_string(),
                "@modelcontextprotocol/server-github".to_string()
            ])
        );
        assert_eq!(github_server.url, None);
        assert!(github_server.env.is_some());
        let env = github_server.env.as_ref().unwrap();
        assert_eq!(
            env.get("GITHUB_PERSONAL_ACCESS_TOKEN"),
            Some(&"ghp_example_personal_access_token12345".to_string())
        );

        // Check gitlab server
        let gitlab_server = servers
            .iter()
            .find(|s| s.name.as_deref() == Some("gitlab"))
            .unwrap();
        assert_eq!(gitlab_server.command, Some("npx".to_string()));
        assert_eq!(
            gitlab_server.args,
            Some(vec![
                "-y".to_string(),
                "@modelcontextprotocol/server-gitlab".to_string()
            ])
        );

        // Check cloudflare-observability server
        let cf_obs_server = servers
            .iter()
            .find(|s| s.name.as_deref() == Some("cloudflare-observability"))
            .unwrap();
        assert_eq!(cf_obs_server.command, Some("npx".to_string()));
        assert_eq!(
            cf_obs_server.args,
            Some(vec![
                "mcp-remote".to_string(),
                "https://observability.mcp.cloudflare.com/sse".to_string()
            ])
        );

        // Check cloudflare-bindings server
        let cf_bind_server = servers
            .iter()
            .find(|s| s.name.as_deref() == Some("cloudflare-bindings"))
            .unwrap();
        assert_eq!(cf_bind_server.command, Some("npx".to_string()));
        assert_eq!(
            cf_bind_server.args,
            Some(vec![
                "mcp-remote".to_string(),
                "https://bindings.mcp.cloudflare.com/sse".to_string()
            ])
        );
    }

    #[test]
    fn test_client_path_detection_gemini() {
        // Test Gemini path detection
        assert_eq!(
            MCPConfigManager::detect_client("/home/user/.gemini/settings.json"),
            Some(MCPClient::Gemini)
        );
        assert_eq!(
            MCPConfigManager::detect_client("/Users/user/.gemini/settings.json"),
            Some(MCPClient::Gemini)
        );

        // Test combined with other path detections
        assert_eq!(
            MCPConfigManager::detect_client("/home/user/.claude/settings.json"),
            Some(MCPClient::ClaudeCode)
        );
        assert_eq!(
            MCPConfigManager::detect_client("/home/user/.codeium/windsurf/mcp_config.json"),
            Some(MCPClient::Windsurf)
        );
    }

    #[test]
    fn test_client_name_mappings_complete() {
        // Test all client name mappings including Claude Code and Gemini
        assert_eq!(MCPClient::Cursor.name(), "cursor");
        assert_eq!(MCPClient::Windsurf.name(), "windsurf");
        assert_eq!(MCPClient::VSCode.name(), "vscode");
        assert_eq!(MCPClient::Claude.name(), "claude");
        assert_eq!(MCPClient::ClaudeCode.name(), "claude-code");
        assert_eq!(MCPClient::Gemini.name(), "gemini");
        assert_eq!(MCPClient::Neovim.name(), "neovim");
        assert_eq!(MCPClient::Helix.name(), "helix");
        assert_eq!(MCPClient::Zed.name(), "zed");
        assert_eq!(MCPClient::Zencoder.name(), "zencoder");
    }
}

/// Scanner Configuration structure for reading from config.yaml
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerConfig {
    /// LLM configuration
    pub llm: LLMConfig,
    /// Scanner configuration
    pub scanner: ScannerSettings,
    /// Security configuration
    pub security: SecurityConfig,
    /// Logging configuration
    pub logging: LoggingConfig,
    /// Performance configuration
    pub performance: PerformanceConfig,
}

/// LLM Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LLMConfig {
    /// Model provider (openai, anthropic, local, etc.)
    pub provider: String,
    /// Model name/identifier
    pub model: String,
    /// Base URL for the API
    pub base_url: String,
    /// API key (can also be set via environment variable)
    pub api_key: String,
    /// Request timeout in seconds
    pub timeout: u64,
    /// Maximum tokens for LLM responses
    pub max_tokens: u32,
    /// Temperature for LLM responses
    pub temperature: f32,
}

/// Scanner Settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerSettings {
    /// Default HTTP timeout for MCP server connections (seconds)
    pub http_timeout: u64,
    /// Default scan timeout (seconds)
    pub scan_timeout: u64,
    /// Enable/disable detailed output
    pub detailed: bool,
    /// Output format (json, table, text)
    pub format: String,
    /// Enable/disable parallel execution
    pub parallel: bool,
    /// Number of retries for failed requests
    pub max_retries: u32,
    /// Initial delay for retry backoff (milliseconds)
    pub retry_delay_ms: u64,
    /// Maximum number of tools to process in a single LLM batch
    pub llm_batch_size: u32,
    /// Enable/disable YARA rule scanning
    pub enable_yara: bool,
}

/// Security Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Enable/disable security scanning
    pub enabled: bool,
    /// Minimum severity level to report
    pub min_severity: String,
    /// Enable/disable specific vulnerability checks
    pub checks: SecurityChecks,
}

/// Security Checks Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct SecurityChecks {
    pub tool_poisoning: bool,
    pub secrets_leakage: bool,
    pub sql_injection: bool,
    pub command_injection: bool,
    pub path_traversal: bool,
    pub auth_bypass: bool,
    pub prompt_injection: bool,
    pub pii_leakage: bool,
    pub jailbreak: bool,
}

/// Logging Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level (trace, debug, info, warn, error)
    pub level: String,
    /// Enable/disable colored output
    pub colored: bool,
    /// Enable/disable timestamps in logs
    pub timestamps: bool,
}

/// Performance Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    /// Enable/disable performance tracking
    pub tracking: bool,
    /// Threshold for slow execution warnings (milliseconds)
    pub slow_threshold_ms: u64,
}

/// Tool Refresh Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct ToolRefreshConfig {
    /// Enable/disable automatic tool refresh
    pub enabled: bool,
    /// Refresh interval in hours
    pub interval_hours: u64,
    /// Start time for daily refresh (HH:MM format, UTC)
    pub start_time: String,
    /// List of servers to refresh automatically (empty = refresh discovered servers)
    pub servers: Vec<ToolRefreshServerConfig>,
    /// Rate limiting configuration
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
}

/// Rate limiting configuration for tool refresh
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct RateLimitConfig {
    /// Maximum number of concurrent server refreshes
    pub max_concurrent: usize,
    /// Delay between server refreshes in milliseconds
    pub delay_between_servers_ms: u64,
    /// Maximum requests per minute per server
    pub max_requests_per_minute: u64,
}

/// Tool refresh server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolRefreshServerConfig {
    /// Server URL
    pub url: String,
    /// Authentication headers
    #[serde(default)]
    pub auth_headers: HashMap<String, String>,
    /// Connection timeout in seconds
    #[serde(default = "default_refresh_timeout")]
    pub timeout: u64,
}

impl ToolRefreshServerConfig {
    /// Apply environment variable mappings to auth headers
    #[allow(dead_code)] // Future feature - will be used when scheduler is re-enabled
    pub fn with_env_mappings(mut self) -> Self {
        self.auth_headers = apply_env_mappings(self.auth_headers);
        self
    }
}

fn default_refresh_timeout() -> u64 {
    30
}

/// Apply environment variable mappings to auth headers
/// Maps generic environment variables to standard auth headers
pub fn apply_env_mappings(mut headers: HashMap<String, String>) -> HashMap<String, String> {
    // Check for LLM_API_KEY environment variable
    if let Ok(llm_api_key) = std::env::var("LLM_API_KEY") {
        // Only add if Authorization header is not already set
        if !headers.contains_key("Authorization") && !headers.contains_key("authorization") {
            headers.insert("Authorization".to_string(), format!("Bearer {llm_api_key}"));
            debug!("Applied LLM_API_KEY environment variable to Authorization header");
        }
    }

    // Check for other common generic environment variables
    if let Ok(api_key) = std::env::var("API_KEY") {
        if !headers.contains_key("Authorization") && !headers.contains_key("authorization") {
            headers.insert("Authorization".to_string(), format!("Bearer {api_key}"));
            debug!("Applied API_KEY environment variable to Authorization header");
        }
    }

    // Check for X-API-Key style headers
    if let Ok(x_api_key) = std::env::var("X_API_KEY") {
        if !headers.contains_key("X-API-Key") && !headers.contains_key("x-api-key") {
            headers.insert("X-API-Key".to_string(), x_api_key);
            debug!("Applied X_API_KEY environment variable to X-API-Key header");
        }
    }

    headers
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_concurrent: 3,              // Max 3 concurrent refreshes
            delay_between_servers_ms: 1000, // 1 second delay between servers
            max_requests_per_minute: 10,    // Max 10 requests per minute per server
        }
    }
}

impl Default for ToolRefreshConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_hours: 24,              // Daily refresh
            start_time: "02:00".to_string(), // 2 AM UTC
            servers: Vec::new(),
            rate_limit: RateLimitConfig::default(),
        }
    }
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            llm: LLMConfig {
                provider: "openai".to_string(),
                model: "gpt-4o".to_string(),
                base_url: "https://api.openai.com/v1/chat/completions".to_string(),
                api_key: String::new(),
                timeout: 30,
                max_tokens: 4000,
                temperature: 0.1,
            },
            scanner: ScannerSettings {
                http_timeout: 30,
                scan_timeout: 60,
                detailed: false,
                format: "table".to_string(),
                parallel: true,
                max_retries: 3,
                retry_delay_ms: 1000,
                llm_batch_size: 10,
                enable_yara: true,
            },
            security: SecurityConfig {
                enabled: true,
                min_severity: "low".to_string(),
                checks: SecurityChecks {
                    tool_poisoning: true,
                    secrets_leakage: true,
                    sql_injection: true,
                    command_injection: true,
                    path_traversal: true,
                    auth_bypass: true,
                    prompt_injection: true,
                    pii_leakage: true,
                    jailbreak: true,
                },
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                colored: true,
                timestamps: true,
            },
            performance: PerformanceConfig {
                tracking: true,
                slow_threshold_ms: 5000,
            },
        }
    }
}

/// Scanner Configuration Manager
pub struct ScannerConfigManager {
    config_path: PathBuf,
}

impl ScannerConfigManager {
    /// Create a new scanner configuration manager
    pub fn new() -> Self {
        let config_path = PathBuf::from("config.yaml");
        Self { config_path }
    }

    /// Load configuration from config.yaml
    pub fn load_config(&self) -> Result<ScannerConfig> {
        if !self.config_path.exists() {
            debug!("No config.yaml found, using default configuration");
            return Ok(ScannerConfig::default());
        }

        let content = fs::read_to_string(&self.config_path)
            .map_err(|e| anyhow!("Failed to read config.yaml: {}", e))?;

        // Expand environment variables in the content
        let expanded_content = Self::expand_env_vars(&content)?;

        let config: ScannerConfig = serde_yaml::from_str(&expanded_content)
            .map_err(|e| anyhow!("Failed to parse config.yaml: {}", e))?;

        debug!("Loaded configuration from config.yaml");
        Ok(config)
    }

    /// Expand environment variables in configuration content
    /// Supports ${VAR:-default} syntax for environment variable substitution
    fn expand_env_vars(content: &str) -> Result<String> {
        use regex::Regex;

        // Regex to match ${VAR:-default} or ${VAR} patterns
        let env_var_regex = Regex::new(r"\$\{([A-Z_][A-Z0-9_]*)(:-([^}]*))?\}")
            .map_err(|e| anyhow!("Failed to compile environment variable regex: {}", e))?;

        // Use replace_all for efficient single-pass replacement
        let result = env_var_regex.replace_all(content, |caps: &regex::Captures| {
            let var_name = &caps[1];
            let default_value = caps.get(3).map(|m| m.as_str()).unwrap_or("");

            // Get environment variable value or use default
            let replacement = match std::env::var(var_name) {
                Ok(value) if !value.is_empty() => value,
                _ => default_value.to_string(),
            };

            debug!(
                "Expanding environment variable: {} -> {}",
                var_name,
                if replacement.is_empty() {
                    "<empty>"
                } else {
                    "<set>"
                }
            );

            replacement
        });

        Ok(result.into_owned())
    }

    /// Save configuration to config.yaml
    pub fn save_config(&self, config: &ScannerConfig) -> Result<()> {
        let content = serde_yaml::to_string(config)
            .map_err(|e| anyhow!("Failed to serialize configuration: {}", e))?;

        fs::write(&self.config_path, content)
            .map_err(|e| anyhow!("Failed to write config.yaml: {}", e))?;

        debug!("Saved configuration to config.yaml");
        Ok(())
    }

    /// Check if config.yaml exists
    pub fn has_config_file(&self) -> bool {
        self.config_path.exists()
    }
}

#[cfg(test)]
mod scanner_config_tests {
    use super::*;
    use std::env;

    #[test]
    fn test_expand_env_vars_with_defaults() {
        let content = r#"
llm:
  provider: ${LLM_PROVIDER:-openai}
  model: ${LLM_MODEL:-gpt-4o}
  base_url: ${LLM_URL:-https://api.openai.com/v1/chat/completions}
  api_key: ${LLM_API_KEY:-}
"#;

        let result = ScannerConfigManager::expand_env_vars(content).unwrap();

        // Should use defaults when environment variables are not set
        assert!(result.contains("provider: openai"));
        assert!(result.contains("model: gpt-4o"));
        assert!(result.contains("base_url: https://api.openai.com/v1/chat/completions"));
        assert!(result.contains("api_key: "));
    }

    #[test]
    fn test_expand_env_vars_with_env_values() {
        // Set test environment variables
        env::set_var("TEST_LLM_PROVIDER", "anthropic");
        env::set_var("TEST_LLM_MODEL", "claude-3");
        env::set_var("TEST_LLM_URL", "https://api.anthropic.com/v1/messages");
        env::set_var("TEST_LLM_API_KEY", "test-key-123");

        let content = r#"
llm:
  provider: ${TEST_LLM_PROVIDER:-openai}
  model: ${TEST_LLM_MODEL:-gpt-4o}
  base_url: ${TEST_LLM_URL:-https://api.openai.com/v1/chat/completions}
  api_key: ${TEST_LLM_API_KEY:-}
"#;

        let result = ScannerConfigManager::expand_env_vars(content).unwrap();

        // Should use environment variable values
        assert!(result.contains("provider: anthropic"));
        assert!(result.contains("model: claude-3"));
        assert!(result.contains("base_url: https://api.anthropic.com/v1/messages"));
        assert!(result.contains("api_key: test-key-123"));

        // Clean up test environment variables
        env::remove_var("TEST_LLM_PROVIDER");
        env::remove_var("TEST_LLM_MODEL");
        env::remove_var("TEST_LLM_URL");
        env::remove_var("TEST_LLM_API_KEY");
    }

    #[test]
    fn test_expand_env_vars_mixed_content() {
        env::set_var("TEST_MIXED_VAR", "test-value");

        let content = r#"
normal_field: regular_value
env_field: ${TEST_MIXED_VAR:-default}
another_field: ${NONEXISTENT_VAR:-fallback}
"#;

        let result = ScannerConfigManager::expand_env_vars(content).unwrap();

        assert!(result.contains("normal_field: regular_value"));
        assert!(result.contains("env_field: test-value"));
        assert!(result.contains("another_field: fallback"));

        env::remove_var("TEST_MIXED_VAR");
    }

    #[test]
    fn test_config_loading_with_env_vars() {
        // Set test environment variables
        env::set_var("TEST_CONFIG_LLM_PROVIDER", "test-provider");
        env::set_var("TEST_CONFIG_LLM_MODEL", "test-model");
        env::set_var("TEST_CONFIG_LLM_API_KEY", "test-key");

        // Create a temporary config content
        let config_content = r#"
llm:
  provider: ${TEST_CONFIG_LLM_PROVIDER:-openai}
  model: ${TEST_CONFIG_LLM_MODEL:-gpt-4o}
  base_url: ${TEST_CONFIG_LLM_URL:-https://api.openai.com/v1/chat/completions}
  api_key: ${TEST_CONFIG_LLM_API_KEY:-}
  timeout: 30
  max_tokens: 4000
  temperature: 0.1
scanner:
  http_timeout: 30
  scan_timeout: 60
  detailed: false
  format: table
  parallel: true
  max_retries: 3
  retry_delay_ms: 1000
  llm_batch_size: 10
  enable_yara: true
security:
  enabled: true
  min_severity: low
  checks:
    tool_poisoning: true
    secrets_leakage: true
    sql_injection: true
    command_injection: true
    path_traversal: true
    auth_bypass: true
    prompt_injection: true
    pii_leakage: true
    jailbreak: true
logging:
  level: warn
  colored: true
  timestamps: true
performance:
  tracking: true
  slow_threshold_ms: 5000
"#;

        // Expand environment variables
        let expanded = ScannerConfigManager::expand_env_vars(config_content).unwrap();

        // Parse the expanded configuration
        let config: ScannerConfig = serde_yaml::from_str(&expanded).unwrap();

        // Verify the environment variables were used
        assert_eq!(config.llm.provider, "test-provider");
        assert_eq!(config.llm.model, "test-model");
        assert_eq!(
            config.llm.base_url,
            "https://api.openai.com/v1/chat/completions"
        ); // default used
        assert_eq!(config.llm.api_key, "test-key");

        // Clean up
        env::remove_var("TEST_CONFIG_LLM_PROVIDER");
        env::remove_var("TEST_CONFIG_LLM_MODEL");
        env::remove_var("TEST_CONFIG_LLM_API_KEY");
    }

    #[test]
    fn test_security_scanner_with_env_config() {
        use crate::security::SecurityScanner;

        // Set test environment variables
        env::set_var("TEST_SECURITY_LLM_PROVIDER", "test-provider");
        env::set_var("TEST_SECURITY_LLM_MODEL", "test-model");
        env::set_var("TEST_SECURITY_LLM_URL", "https://test.api.com/v1/chat");
        env::set_var("TEST_SECURITY_LLM_API_KEY", "test-security-key");

        // Create a config with environment variables
        let config_content = r#"
llm:
  provider: ${TEST_SECURITY_LLM_PROVIDER:-openai}
  model: ${TEST_SECURITY_LLM_MODEL:-gpt-4o}
  base_url: ${TEST_SECURITY_LLM_URL:-https://api.openai.com/v1/chat/completions}
  api_key: ${TEST_SECURITY_LLM_API_KEY:-}
  timeout: 30
  max_tokens: 4000
  temperature: 0.1
scanner:
  http_timeout: 30
  scan_timeout: 60
  detailed: false
  format: table
  parallel: true
  max_retries: 3
  retry_delay_ms: 1000
  llm_batch_size: 10
  enable_yara: true
security:
  enabled: true
  min_severity: low
  checks:
    tool_poisoning: true
    secrets_leakage: true
    sql_injection: true
    command_injection: true
    path_traversal: true
    auth_bypass: true
    prompt_injection: true
    pii_leakage: true
    jailbreak: true
logging:
  level: warn
  colored: true
  timestamps: true
performance:
  tracking: true
  slow_threshold_ms: 5000
"#;

        // Expand environment variables and parse config
        let expanded = ScannerConfigManager::expand_env_vars(config_content).unwrap();
        let config: ScannerConfig = serde_yaml::from_str(&expanded).unwrap();

        // Create SecurityScanner with the config
        let security_scanner = SecurityScanner::with_config(config);

        // Verify the SecurityScanner has the correct configuration
        assert_eq!(security_scanner.model_name, "test-model");
        assert_eq!(
            security_scanner.model_endpoint,
            Some("https://test.api.com/v1/chat".to_string())
        );
        assert_eq!(
            security_scanner.api_key,
            Some("test-security-key".to_string())
        );

        // Clean up
        env::remove_var("TEST_SECURITY_LLM_PROVIDER");
        env::remove_var("TEST_SECURITY_LLM_MODEL");
        env::remove_var("TEST_SECURITY_LLM_URL");
        env::remove_var("TEST_SECURITY_LLM_API_KEY");
    }
}
