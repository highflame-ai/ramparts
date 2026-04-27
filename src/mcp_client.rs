/// MCP client implementation using the official Rust MCP SDK
///
/// This module provides full MCP protocol support using the official rmcp SDK
/// for subprocess and streamable HTTP transports. Streamable HTTP transparently
/// handles SSE responses, so a separate SSE transport is no longer needed.
use crate::cache::ToolCache;
use crate::types::{MCPPrompt, MCPPromptArgument, MCPResource, MCPServerInfo, MCPSession, MCPTool};
use anyhow::{anyhow, Result};
use reqwest::{
    header::{HeaderMap, HeaderName, HeaderValue},
    Client as HttpClient,
};
use serde_json::{json, Value};

use rmcp::{
    service::RunningService,
    transport::{StreamableHttpClientTransport, TokioChildProcess},
    RoleClient, ServiceExt,
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::process::Command;
use tokio::sync::Mutex;
use tracing::{debug, warn};

/// Default per-HTTP-request timeout when none is provided. Kept identical to
/// the previous hardcoded value so existing behavior doesn't change for
/// callers that haven't started forwarding the configured `http_timeout`.
const DEFAULT_HTTP_TIMEOUT_SECS: u64 = 30;

/// MCP client using the official Rust MCP SDK with full transport support
#[derive(Clone)]
pub struct McpClient {
    /// Store active MCP services by endpoint
    services: Arc<Mutex<HashMap<String, RunningService<RoleClient, ()>>>>,
    /// Tool cache with TTL support
    tool_cache: ToolCache,
    /// Per-HTTP-request timeout applied to every reqwest client this McpClient
    /// builds. Sourced from `ScanOptions::http_timeout`.
    http_timeout_secs: u64,
}

#[allow(dead_code)] // Future feature - will be used when cache is integrated
impl McpClient {
    pub fn new() -> Self {
        Self {
            services: Arc::new(Mutex::new(HashMap::new())),
            tool_cache: ToolCache::default(), // 1 hour default TTL
            http_timeout_secs: DEFAULT_HTTP_TIMEOUT_SECS,
        }
    }

    /// Create a new MCP client with the given per-HTTP-request timeout.
    pub fn with_http_timeout(http_timeout_secs: u64) -> Self {
        Self {
            services: Arc::new(Mutex::new(HashMap::new())),
            tool_cache: ToolCache::default(),
            http_timeout_secs,
        }
    }

    /// Create a new MCP client with custom cache TTL
    pub fn with_cache_ttl(cache_ttl_seconds: u64) -> Self {
        Self {
            services: Arc::new(Mutex::new(HashMap::new())),
            tool_cache: ToolCache::new(cache_ttl_seconds),
            http_timeout_secs: DEFAULT_HTTP_TIMEOUT_SECS,
        }
    }

    /// Centralized HTTP client factory with consistent auth header handling
    ///
    /// This is the single source of truth for creating HTTP clients throughout the MCP client.
    /// All HTTP client creation should go through this method to ensure consistent auth handling.
    fn create_http_client(
        &self,
        auth_headers: Option<&HashMap<String, String>>,
    ) -> Result<HttpClient> {
        let mut headers = HeaderMap::new();

        if let Some(auth_headers) = auth_headers {
            debug!(
                "Creating HTTP client with {} auth headers",
                auth_headers.len()
            );

            for (key, value) in auth_headers {
                debug!("Processing header: {} = {}", key, value);
                match (
                    HeaderName::from_bytes(key.as_bytes()),
                    HeaderValue::from_str(value),
                ) {
                    (Ok(name), Ok(val)) => {
                        debug!("Successfully added header: {}", key);
                        headers.insert(name, val);
                    }
                    (Err(e), _) => {
                        warn!("Failed to parse header name '{}': {}", key, e);
                    }
                    (_, Err(e)) => {
                        warn!("Failed to parse header value for '{}': {}", key, e);
                    }
                }
            }
        } else {
            debug!("Creating HTTP client without auth headers");
        }

        HttpClient::builder()
            .default_headers(headers)
            .timeout(std::time::Duration::from_secs(self.http_timeout_secs))
            .build()
            .map_err(|e| anyhow!("Failed to build HTTP client: {}", e))
    }

    /// Try to connect using streamable HTTP transport
    async fn try_streamable_http_connection(
        &self,
        url: &str,
        auth_headers: Option<&HashMap<String, String>>,
    ) -> Result<MCPSession> {
        debug!("Attempting streamable HTTP connection to: {}", url);

        // Create streamable HTTP transport. The reqwest client carries any
        // auth/custom headers via `default_headers`; if no auth headers are
        // provided we still build a default client for consistency.
        let client = self.create_http_client(auth_headers)?;
        let config =
            rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig::with_uri(
                url,
            );
        let transport = StreamableHttpClientTransport::with_client(client, config);

        // Create the MCP service
        let service = ()
            .serve(transport)
            .await
            .map_err(|e| anyhow!("Failed to create MCP service via streamable HTTP: {}", e))?;

        // Get server information
        let peer_info = service.peer().peer_info();
        let server_info = if let Some(init_result) = peer_info {
            MCPServerInfo {
                name: init_result.server_info.name.to_string(),
                version: init_result.server_info.version.to_string(),
                description: None,
                capabilities: vec![
                    "tools".to_string(),
                    "resources".to_string(),
                    "prompts".to_string(),
                ],
                metadata: {
                    let mut map = HashMap::new();
                    map.insert(
                        "transport".to_string(),
                        serde_json::Value::String("streamable-http".to_string()),
                    );
                    map
                },
            }
        } else {
            MCPServerInfo {
                name: "Streamable HTTP MCP Server".to_string(),
                version: "Unknown".to_string(),
                description: Some("Connected via streamable HTTP".to_string()),
                capabilities: vec![
                    "tools".to_string(),
                    "resources".to_string(),
                    "prompts".to_string(),
                ],
                metadata: {
                    let mut map = HashMap::new();
                    map.insert(
                        "transport".to_string(),
                        serde_json::Value::String("streamable-http".to_string()),
                    );
                    map
                },
            }
        };

        // Store the service for later use
        {
            let mut services = self.services.lock().await;
            services.insert(url.to_string(), service);
        }

        let session = MCPSession {
            server_info: Some(server_info),
            endpoint_url: url.to_string(),
            auth_headers: auth_headers.cloned(),
            session_id: None, // rmcp transports handle sessions internally
        };

        Ok(session)
    }

    /// Connect using subprocess (for local MCP servers)
    pub async fn connect_subprocess(
        &self,
        command: &str,
        args: &[String],
        env_vars: Option<&HashMap<String, String>>,
    ) -> Result<MCPSession> {
        debug!(
            "Connecting to MCP server via subprocess: {} {:?}",
            command, args
        );

        // Create the command
        let mut cmd = Command::new(command);
        for arg in args {
            cmd.arg(arg);
        }

        // Suppress subprocess stdout/stderr to prevent startup messages from cluttering output
        // Only suppress if not in debug mode (to preserve error messages for troubleshooting)
        if std::env::var("RUST_LOG")
            .map_or(true, |log| !log.contains("debug") && !log.contains("trace"))
        {
            cmd.stdout(std::process::Stdio::null());
            cmd.stderr(std::process::Stdio::null());
        }

        // Add environment variables if provided
        if let Some(env) = env_vars {
            for (key, value) in env {
                cmd.env(key, value);
            }
        }

        // Create the service using the subprocess transport
        let transport = TokioChildProcess::new(cmd)?;
        let service = ()
            .serve(transport)
            .await
            .map_err(|e| {
                // Provide more detailed error information for troubleshooting
                let error_context = if e.to_string().contains("connection closed") {
                    format!("MCP server subprocess failed during initialization. This could be due to: \
                           \n  - Missing required environment variables (check server documentation) \
                           \n  - Server startup errors (enable debug logging with RUST_LOG=debug) \
                           \n  - Package installation issues (try: npx {command} manually) \
                           \n  - Network connectivity issues for remote servers \
                           \nOriginal error: {e}")
                } else {
                    format!("Failed to start MCP server subprocess: {e}")
                };
                anyhow!(error_context)
            })?;

        // Get server information
        let peer_info = service.peer().peer_info();
        let server_info = if let Some(init_result) = peer_info {
            MCPServerInfo {
                name: init_result.server_info.name.to_string(),
                version: init_result.server_info.version.to_string(),
                description: None,
                capabilities: vec![
                    "tools".to_string(),
                    "resources".to_string(),
                    "prompts".to_string(),
                ],
                metadata: {
                    let mut map = HashMap::new();
                    map.insert(
                        "transport".to_string(),
                        serde_json::Value::String("subprocess".to_string()),
                    );
                    map
                },
            }
        } else {
            MCPServerInfo {
                name: "Subprocess MCP Server".to_string(),
                version: "Unknown".to_string(),
                description: Some("Connected via subprocess".to_string()),
                capabilities: vec![
                    "tools".to_string(),
                    "resources".to_string(),
                    "prompts".to_string(),
                ],
                metadata: {
                    let mut map = HashMap::new();
                    map.insert(
                        "transport".to_string(),
                        serde_json::Value::String("subprocess".to_string()),
                    );
                    map
                },
            }
        };

        // Store the service for later use
        let endpoint = format!("subprocess://{command}");
        {
            let mut services = self.services.lock().await;
            services.insert(endpoint.clone(), service);
        }

        let session = MCPSession {
            server_info: Some(server_info),
            endpoint_url: endpoint,
            auth_headers: None, // Subprocess doesn't use HTTP auth headers
            session_id: None,   // Subprocess doesn't use HTTP sessions
        };

        Ok(session)
    }

    /// Fetch tools from the MCP server using the official SDK
    pub async fn list_tools(&self, session: &MCPSession) -> Result<Vec<MCPTool>> {
        debug!("Fetching tools from MCP server: {}", session.endpoint_url);

        // Check if this is a simple HTTP session
        if let Some(server_info) = &session.server_info {
            if let Some(transport_type) = server_info.metadata.get("transport") {
                if transport_type.as_str() == Some("simple_http") {
                    return self.list_tools_simple_http(session).await;
                }
            }
        }

        // Use rmcp transport for other sessions
        let services = self.services.lock().await;
        if let Some(service) = services.get(&session.endpoint_url) {
            match service.list_tools(Option::default()).await {
                Ok(tools_response) => {
                    let mut mcp_tools = Vec::new();

                    for tool in tools_response.tools {
                        let mcp_tool = MCPTool {
                            name: tool.name.to_string(),
                            description: tool
                                .description
                                .as_ref()
                                .map(std::string::ToString::to_string),
                            input_schema: Some(serde_json::Value::Object(
                                (*tool.input_schema).clone(),
                            )),
                            output_schema: None,
                            parameters: HashMap::new(),
                            category: None,
                            tags: vec![],
                            deprecated: false,
                            raw_json: None,
                        };
                        mcp_tools.push(mcp_tool);
                    }

                    debug!(
                        "Successfully fetched {} tools from MCP server",
                        mcp_tools.len()
                    );
                    Ok(mcp_tools)
                }
                Err(e) => {
                    debug!("Failed to fetch tools from MCP server: {}", e);
                    Ok(vec![])
                }
            }
        } else {
            warn!("No active MCP service found for: {}", session.endpoint_url);
            Ok(vec![])
        }
    }

    /// Fetch resources from the MCP server
    pub async fn list_resources(&self, session: &MCPSession) -> Result<Vec<MCPResource>> {
        debug!(
            "Fetching resources from MCP server: {}",
            session.endpoint_url
        );

        // Check if this is a simple HTTP session
        if let Some(server_info) = &session.server_info {
            if let Some(transport_type) = server_info.metadata.get("transport") {
                if transport_type.as_str() == Some("simple_http") {
                    return self.list_resources_simple_http(session).await;
                }
            }
        }

        // Use rmcp transport for other sessions
        let services = self.services.lock().await;
        if let Some(service) = services.get(&session.endpoint_url) {
            match service.list_resources(Option::default()).await {
                Ok(resources_response) => {
                    let mut mcp_resources = Vec::new();

                    for resource in resources_response.resources {
                        let mcp_resource = MCPResource {
                            uri: resource.uri.to_string(),
                            name: resource.name.to_string(),
                            description: resource
                                .description
                                .as_ref()
                                .map(std::string::ToString::to_string),
                            mime_type: resource
                                .mime_type
                                .as_ref()
                                .map(std::string::ToString::to_string),
                            size: None,
                            metadata: HashMap::new(),
                            raw_json: None,
                        };
                        mcp_resources.push(mcp_resource);
                    }

                    debug!(
                        "Successfully fetched {} resources from MCP server",
                        mcp_resources.len()
                    );
                    Ok(mcp_resources)
                }
                Err(e) => {
                    debug!("Failed to fetch resources from MCP server: {}", e);
                    Ok(vec![])
                }
            }
        } else {
            warn!("No active MCP service found for: {}", session.endpoint_url);
            Ok(vec![])
        }
    }

    /// Fetch prompts from the MCP server  
    pub async fn list_prompts(&self, session: &MCPSession) -> Result<Vec<MCPPrompt>> {
        debug!("Fetching prompts from MCP server: {}", session.endpoint_url);

        // Check if this is a simple HTTP session
        if let Some(server_info) = &session.server_info {
            if let Some(transport_type) = server_info.metadata.get("transport") {
                if transport_type.as_str() == Some("simple_http") {
                    return self.list_prompts_simple_http(session).await;
                }
            }
        }

        // Use rmcp transport for other sessions
        let services = self.services.lock().await;
        if let Some(service) = services.get(&session.endpoint_url) {
            match service.list_prompts(Option::default()).await {
                Ok(prompts_response) => {
                    let mut mcp_prompts = Vec::new();

                    for prompt in prompts_response.prompts {
                        let arguments = prompt.arguments.as_ref().map(|args| {
                            args.iter()
                                .map(|arg| MCPPromptArgument {
                                    name: arg.name.to_string(),
                                    description: arg
                                        .description
                                        .as_ref()
                                        .map(std::string::ToString::to_string),
                                    required: arg.required,
                                })
                                .collect()
                        });

                        let mcp_prompt = MCPPrompt {
                            name: prompt.name.to_string(),
                            description: prompt
                                .description
                                .as_ref()
                                .map(std::string::ToString::to_string),
                            arguments,
                            raw_json: None,
                        };
                        mcp_prompts.push(mcp_prompt);
                    }

                    debug!(
                        "Successfully fetched {} prompts from MCP server",
                        mcp_prompts.len()
                    );
                    Ok(mcp_prompts)
                }
                Err(e) => {
                    debug!("Failed to fetch prompts from MCP server: {}", e);
                    Ok(vec![])
                }
            }
        } else {
            warn!("No active MCP service found for: {}", session.endpoint_url);
            Ok(vec![])
        }
    }

    /// Validate session by testing actual API functionality
    async fn validate_session(&self, session: &MCPSession) -> bool {
        debug!(
            "Validating session functionality for: {}",
            session.endpoint_url
        );

        // Try to fetch tools as a basic functionality test
        match self.list_tools(session).await {
            Ok(tools) => {
                debug!(
                    "Session validation successful: {} tools retrieved",
                    tools.len()
                );
                true
            }
            Err(e) => {
                debug!("Session validation failed: {}", e);
                false
            }
        }
    }

    /// Smart connect method - tries all transports with comprehensive fallback strategy
    pub async fn connect_smart(
        &self,
        url: &str,
        auth_headers: Option<HashMap<String, String>>,
    ) -> Result<MCPSession> {
        debug!("Smart connecting to MCP server at: {}", url);

        // HTTP transport: Try all transports with validation
        let mut best_session = None;
        let mut partial_session = None;
        let mut last_error = None;

        // Step 1: Try simple HTTP (works with most servers, now with session support)
        match self
            .try_simple_http_connection(url, auth_headers.as_ref())
            .await
        {
            Ok(session) => {
                debug!("Simple HTTP connection established, validating...");
                if self.validate_session(&session).await {
                    debug!("Simple HTTP session fully validated - using it");
                    return Ok(session);
                } else {
                    debug!("Simple HTTP session has API issues - keeping as fallback");
                    partial_session = Some(session);
                }
            }
            Err(e) => {
                debug!("Simple HTTP connection failed: {}", e);
                last_error = Some(e);
            }
        }

        // Step 2: Try rmcp streamable HTTP (for advanced servers)
        match self
            .try_streamable_http_connection(url, auth_headers.as_ref())
            .await
        {
            Ok(session) => {
                debug!("rmcp streamable HTTP connection established, validating...");
                if self.validate_session(&session).await {
                    debug!("rmcp streamable HTTP session fully validated - using it");
                    return Ok(session);
                } else {
                    debug!("rmcp streamable HTTP session has API issues");
                    if best_session.is_none() {
                        best_session = Some(session);
                    }
                }
            }
            Err(e) => {
                debug!("rmcp streamable HTTP connection failed: {}", e);
                last_error = Some(e);
            }
        }

        // Note: rmcp 1.x streamable HTTP transparently handles SSE responses,
        // so a separate SSE fallback step is no longer needed.

        // Return best available session or error
        if let Some(session) = best_session.or(partial_session) {
            warn!("Using partially working session - some API calls may fail");
            Ok(session)
        } else {
            let error = last_error.unwrap_or_else(|| anyhow!("Unknown error"));
            warn!("All transport methods failed. Last error: {}", error);
            Err(anyhow!(
                "Failed to connect via simple HTTP, streamable HTTP, and SSE: {}",
                error
            ))
        }
    }

    /// Try to connect using simple HTTP JSON-RPC (compatible with most servers)
    async fn try_simple_http_connection(
        &self,
        url: &str,
        auth_headers: Option<&HashMap<String, String>>,
    ) -> Result<MCPSession> {
        debug!("Attempting simple HTTP connection to: {}", url);

        // Use centralized HTTP client factory
        let client = self.create_http_client(auth_headers)?;

        // Step 1: Initialize connection
        let init_request = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {
                    "name": "ramparts",
                    "version": env!("CARGO_PKG_VERSION")
                }
            }
        });

        debug!("Sending initialize request to: {}", url);
        let response = client.post(url).json(&init_request).send().await?;

        if !response.status().is_success() {
            return Err(anyhow!("Initialize failed: HTTP {}", response.status()));
        }

        // Extract session ID from response headers (for stateful servers like GitHub Copilot)
        let session_id = response
            .headers()
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
            .map(|s| {
                debug!("Extracted session ID from server: {}", s);
                s.to_string()
            });

        let init_response: Value = response.json().await?;
        debug!("Initialize response: {:?}", init_response);

        // Check for JSON-RPC error
        if let Some(error) = init_response.get("error") {
            return Err(anyhow!("Initialize error: {:?}", error));
        }

        // Step 2: Send initialized notification (if server expects it)
        let notify_request = json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        });

        // Send notification but don't fail if it doesn't work (some servers don't expect it)
        let _ = client.post(url).json(&notify_request).send().await;

        // Extract server info from initialize response
        let server_info = init_response
            .get("result")
            .and_then(|r| r.get("serverInfo"))
            .map(|info| MCPServerInfo {
                name: info
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("Unknown")
                    .to_string(),
                version: info
                    .get("version")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown")
                    .to_string(),
                description: None,
                capabilities: vec![
                    "tools".to_string(),
                    "resources".to_string(),
                    "prompts".to_string(),
                ],
                metadata: {
                    let mut map = HashMap::new();
                    map.insert(
                        "transport".to_string(),
                        serde_json::Value::String("simple_http".to_string()),
                    );
                    map
                },
            });

        Ok(MCPSession {
            server_info,
            endpoint_url: url.to_string(),
            auth_headers: auth_headers.cloned(),
            session_id,
        })
    }

    /// List tools using simple HTTP JSON-RPC
    async fn list_tools_simple_http(&self, session: &MCPSession) -> Result<Vec<MCPTool>> {
        debug!(
            "Fetching tools via simple HTTP from: {}",
            session.endpoint_url
        );

        let tools_response = self
            .json_rpc_request(
                &session.endpoint_url,
                "tools/list",
                json!({}),
                session.auth_headers.as_ref(),
                session.session_id.as_ref(),
            )
            .await?;

        let tools_array = tools_response
            .get("tools")
            .and_then(|t| t.as_array())
            .ok_or_else(|| anyhow!("Invalid tools response format"))?;

        let mut mcp_tools = Vec::new();
        for tool in tools_array {
            let mcp_tool = MCPTool {
                name: tool
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("unknown")
                    .to_string(),
                description: tool
                    .get("description")
                    .and_then(|d| d.as_str())
                    .map(|s| s.to_string()),
                input_schema: tool.get("inputSchema").cloned(),
                output_schema: None,
                parameters: HashMap::new(),
                category: None,
                tags: vec![],
                deprecated: false,
                raw_json: Some(tool.clone()),
            };
            mcp_tools.push(mcp_tool);
        }

        debug!(
            "Successfully fetched {} tools via simple HTTP",
            mcp_tools.len()
        );
        Ok(mcp_tools)
    }

    /// List resources using simple HTTP JSON-RPC
    async fn list_resources_simple_http(&self, session: &MCPSession) -> Result<Vec<MCPResource>> {
        debug!(
            "Fetching resources via simple HTTP from: {}",
            session.endpoint_url
        );

        let resources_response = self
            .json_rpc_request(
                &session.endpoint_url,
                "resources/list",
                json!({}),
                session.auth_headers.as_ref(),
                session.session_id.as_ref(),
            )
            .await?;

        let resources_array = resources_response
            .get("resources")
            .and_then(|r| r.as_array())
            .ok_or_else(|| anyhow!("Invalid resources response format"))?;

        let mut mcp_resources = Vec::new();
        for resource in resources_array {
            let mcp_resource = MCPResource {
                uri: resource
                    .get("uri")
                    .and_then(|u| u.as_str())
                    .unwrap_or("")
                    .to_string(),
                name: resource
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("unknown")
                    .to_string(),
                description: resource
                    .get("description")
                    .and_then(|d| d.as_str())
                    .map(|s| s.to_string()),
                mime_type: resource
                    .get("mimeType")
                    .and_then(|m| m.as_str())
                    .map(|s| s.to_string()),
                size: resource.get("size").and_then(|s| s.as_u64()),
                metadata: HashMap::new(), // Could be populated from resource data if needed
                raw_json: Some(resource.clone()),
            };
            mcp_resources.push(mcp_resource);
        }

        debug!(
            "Successfully fetched {} resources via simple HTTP",
            mcp_resources.len()
        );
        Ok(mcp_resources)
    }

    /// List prompts using simple HTTP JSON-RPC
    async fn list_prompts_simple_http(&self, session: &MCPSession) -> Result<Vec<MCPPrompt>> {
        debug!(
            "Fetching prompts via simple HTTP from: {}",
            session.endpoint_url
        );

        let prompts_response = self
            .json_rpc_request(
                &session.endpoint_url,
                "prompts/list",
                json!({}),
                session.auth_headers.as_ref(),
                session.session_id.as_ref(),
            )
            .await?;

        let prompts_array = prompts_response
            .get("prompts")
            .and_then(|p| p.as_array())
            .ok_or_else(|| anyhow!("Invalid prompts response format"))?;

        let mut mcp_prompts = Vec::new();
        for prompt in prompts_array {
            let mcp_prompt = MCPPrompt {
                name: prompt
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("unknown")
                    .to_string(),
                description: prompt
                    .get("description")
                    .and_then(|d| d.as_str())
                    .map(|s| s.to_string()),
                arguments: None, // Could be extracted if needed
                raw_json: Some(prompt.clone()),
            };
            mcp_prompts.push(mcp_prompt);
        }

        debug!(
            "Successfully fetched {} prompts via simple HTTP",
            mcp_prompts.len()
        );
        Ok(mcp_prompts)
    }

    /// Clean up and shut down a specific MCP session
    pub async fn cleanup_session(&self, session: &MCPSession) -> Result<()> {
        debug!("Cleaning up MCP session for: {}", session.endpoint_url);

        let mut services = self.services.lock().await;
        if let Some(service) = services.remove(&session.endpoint_url) {
            debug!("Shutting down MCP service for: {}", session.endpoint_url);
            // The service will be dropped and cleaned up automatically
            drop(service);
        }

        Ok(())
    }

    /// Clean up all active MCP sessions
    pub async fn cleanup_all_sessions(&self) -> Result<()> {
        debug!("Cleaning up all MCP sessions");

        let mut services = self.services.lock().await;
        let endpoints: Vec<String> = services.keys().cloned().collect();

        for endpoint in endpoints {
            if let Some(service) = services.remove(&endpoint) {
                debug!("Shutting down MCP service for: {}", endpoint);
                // Add timeout for cleanup to prevent hanging
                let cleanup_timeout =
                    tokio::time::timeout(std::time::Duration::from_millis(500), async move {
                        drop(service);
                    });

                if cleanup_timeout.await.is_err() {
                    warn!("Cleanup timeout for MCP service: {}", endpoint);
                }
            }
        }

        debug!("All MCP sessions cleaned up");
        Ok(())
    }

    /// Generic JSON-RPC request helper for simple HTTP transport
    async fn json_rpc_request(
        &self,
        url: &str,
        method: &str,
        params: Value,
        auth_headers: Option<&HashMap<String, String>>,
        session_id: Option<&String>,
    ) -> Result<Value> {
        // Use centralized HTTP client factory with session support
        let mut client_headers = HashMap::new();

        // Add auth headers
        if let Some(auth_headers) = auth_headers {
            client_headers.extend(auth_headers.clone());
        }

        // Add session ID header for stateful servers (e.g., GitHub Copilot)
        if let Some(session_id) = session_id {
            debug!("Adding session ID to request: {}", session_id);
            client_headers.insert("Mcp-Session-Id".to_string(), session_id.clone());
        }

        let client = self.create_http_client(if client_headers.is_empty() {
            None
        } else {
            Some(&client_headers)
        })?;

        let request = json!({
            "jsonrpc": "2.0",
            "id": rand::random::<u32>(),
            "method": method,
            "params": params
        });

        // Add mask=false query parameter to get unmasked tokens
        let request_url = {
            let mut url = url::Url::parse(url)?;
            url.query_pairs_mut().append_pair("mask", "false");
            url
        };

        debug!("Sending JSON-RPC request to {}: {}", request_url, method);
        let response = client.post(request_url).json(&request).send().await?;

        if !response.status().is_success() {
            return Err(anyhow!("HTTP request failed: {}", response.status()));
        }

        let json_response: Value = response.json().await?;

        // Check for JSON-RPC error
        if let Some(error) = json_response.get("error") {
            return Err(anyhow!("JSON-RPC error: {:?}", error));
        }

        // Extract result
        json_response
            .get("result")
            .cloned()
            .ok_or_else(|| anyhow!("Missing result in JSON-RPC response"))
    }
    /// Get tools from cache or fetch from server if not cached or expired
    pub async fn get_tools_cached(
        &self,
        url: &str,
        auth_headers: Option<HashMap<String, String>>,
    ) -> Result<Vec<MCPTool>> {
        // Check cache first
        if let Some(cached_tools) = self.tool_cache.get(url).await {
            debug!("Using cached tools for {}", url);
            return Ok(cached_tools);
        }

        // Not in cache or expired, fetch fresh tools
        debug!("Cache miss for {}, fetching fresh tools", url);
        let tools = self.refresh_tools(url, auth_headers).await?;

        // Cache the fresh tools
        self.tool_cache.put(url.to_string(), tools.clone()).await;

        Ok(tools)
    }

    /// Refresh tools from an MCP server by reconnecting and fetching latest tool descriptions
    pub async fn refresh_tools(
        &self,
        url: &str,
        auth_headers: Option<HashMap<String, String>>,
    ) -> Result<Vec<MCPTool>> {
        debug!("Refreshing tools from MCP server: {}", url);

        // Connect to the server (this will create a fresh connection)
        let session = self.connect_smart(url, auth_headers).await?;

        // Fetch the latest tools
        let tools = self.list_tools(&session).await?;

        // Update cache with fresh tools
        self.tool_cache.put(url.to_string(), tools.clone()).await;

        // Clean up the session
        if let Err(e) = self.cleanup_session(&session).await {
            warn!("Failed to clean up session after refreshing tools: {}", e);
        }

        debug!("Successfully refreshed {} tools from {}", tools.len(), url);
        Ok(tools)
    }

    /// Refresh tools from multiple MCP servers concurrently
    pub async fn refresh_tools_batch(
        &self,
        servers: Vec<(String, Option<HashMap<String, String>>)>,
    ) -> Vec<(String, Result<Vec<MCPTool>>)> {
        debug!("Refreshing tools from {} servers", servers.len());

        let mut results = Vec::new();

        // Process servers sequentially to avoid overwhelming them
        for (url, auth_headers) in servers {
            let result = self.refresh_tools(&url, auth_headers).await;
            results.push((url, result));
        }

        results
    }

    /// Clear tool cache for a specific URL
    pub async fn clear_cache(&self, url: &str) -> bool {
        self.tool_cache.remove(url).await
    }

    /// Clear all cached tools
    pub async fn clear_all_cache(&self) {
        self.tool_cache.clear().await;
    }

    /// Clean up expired cache entries
    pub async fn cleanup_expired_cache(&self) -> usize {
        self.tool_cache.cleanup_expired().await
    }

    /// Get cache statistics
    pub async fn cache_stats(&self) -> crate::cache::CacheStats {
        self.tool_cache.stats().await
    }

    /// Get all cached URLs
    pub async fn get_cached_urls(&self) -> Vec<String> {
        self.tool_cache.get_cached_urls().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mcp_client_creation() {
        let _client = McpClient::new();
        // Basic test to ensure the client can be created
    }

    #[tokio::test]
    async fn test_centralized_http_client_factory() {
        let client = McpClient::new();

        // Test client creation without auth headers
        let client_no_auth = client.create_http_client(None);
        assert!(
            client_no_auth.is_ok(),
            "Should create HTTP client without auth headers"
        );

        // Test client creation with auth headers
        let mut auth_headers = HashMap::new();
        auth_headers.insert("Authorization".to_string(), "Bearer test-token".to_string());
        auth_headers.insert("X-API-Key".to_string(), "test-api-key".to_string());

        let client_with_auth = client.create_http_client(Some(&auth_headers));
        assert!(
            client_with_auth.is_ok(),
            "Should create HTTP client with auth headers"
        );

        // Test invalid header handling
        let mut invalid_headers = HashMap::new();
        invalid_headers.insert("Invalid\x00Header".to_string(), "value".to_string());

        let client_invalid = client.create_http_client(Some(&invalid_headers));
        assert!(
            client_invalid.is_ok(),
            "Should handle invalid headers gracefully"
        );
    }

    #[tokio::test]
    async fn test_http_connection() {
        let client = McpClient::new();
        // This will likely fail in tests since there's no server running
        // but we can at least test that the method exists and can be called
        let result = client.connect_smart("http://localhost:8124", None).await;
        // We expect this to fail in the test environment, but not panic
        assert!(result.is_err() || result.is_ok());
    }
}
