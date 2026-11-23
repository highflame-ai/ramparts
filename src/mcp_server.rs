use std::sync::Arc;

use crate::core::{MCPScannerCore, ScanRequest};
use crate::scanner::MCPScanner;
use crate::types::ScanConfigBuilder;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::schemars::JsonSchema;
use rmcp::{
    handler::server::router::tool::ToolRouter,
    model::{CallToolResult, ContentBlock, ServerCapabilities, ServerConfig},
    tool, tool_handler, tool_router,
    transport::{
        io::stdio,
        streamable_http_server::{
            session::local::LocalSessionManager, tower::StreamableHttpService,
            StreamableHttpServerConfig,
        },
    },
    ErrorData, ServiceExt,
};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, JsonSchema)]
struct ScanParams {
    url: String,
    #[serde(default)]
    detailed: bool,
    #[serde(default)]
    auth_headers: Option<std::collections::HashMap<String, String>>,
    #[serde(default)]
    format: Option<String>,
    #[serde(default)]
    timeout: Option<u64>,
    #[serde(default, rename = "httpTimeout")]
    http_timeout: Option<u64>,
    /// If true, do not call the LLM; return prompts instead
    #[serde(default, rename = "returnPrompts")]
    return_prompts: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
struct ScanConfigParams {
    #[serde(default)]
    detailed: Option<bool>,
    #[serde(default)]
    auth_headers: Option<std::collections::HashMap<String, String>>,
    #[serde(default)]
    format: Option<String>,
    #[serde(default)]
    timeout: Option<u64>,
    #[serde(default, rename = "httpTimeout")]
    http_timeout: Option<u64>,
    /// If true, do not call the LLM; return prompts instead
    #[serde(default, rename = "returnPrompts")]
    return_prompts: Option<bool>,
}

/// Minimal MCP server that exposes scan and scan-config tools only.
#[derive(Clone)]
pub struct RampartsMcpServer {
    // Required by the `#[tool_router]` macro expansion even when not read directly.
    #[allow(dead_code)]
    tool_router: ToolRouter<Self>,
    core: Arc<MCPScannerCore>,
    /// Served over a network transport (streamable HTTP / SSE) rather than
    /// stdio: callers may be remote, so private targets are refused and
    /// scan-config (which starts the host's configured servers) is off.
    network: bool,
}

#[tool_router]
impl RampartsMcpServer {
    pub fn new(network: bool) -> Self {
        let core = MCPScannerCore::new().expect("core init");
        Self {
            tool_router: Self::tool_router(),
            core: Arc::new(core),
            network,
        }
    }

    #[tool(
        name = "scan",
        description = "Scan an MCP server URL and return security findings as JSON"
    )]
    async fn scan(&self, params: Parameters<ScanParams>) -> Result<CallToolResult, ErrorData> {
        let p = params.0;
        let url = tool_target(&p.url, self.network)
            .map_err(|e| ErrorData::invalid_params(e.message().to_string(), None))?;
        let request = ScanRequest {
            url,
            timeout: p.timeout,
            http_timeout: p.http_timeout,
            detailed: Some(p.detailed),
            format: p.format,
            auth_headers: p.auth_headers,
            // Default to returning prompts (no LLM call) for MCP tool flow
            return_prompts: Some(p.return_prompts.unwrap_or(true)),
            reference_url: None,
        };

        let resp = self.core.scan(request).await;
        if let Some(result) = resp.result {
            let json = serde_json::to_string(&result)
                .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
            Ok(CallToolResult::success(vec![ContentBlock::text(json)]))
        } else {
            Err(ErrorData::invalid_request(
                resp.error.unwrap_or_else(|| "scan failed".to_string()),
                None,
            ))
        }
    }

    #[tool(
        name = "scan-config",
        description = "Scan MCP servers from IDE configuration files and return results as JSON"
    )]
    async fn scan_config(
        &self,
        params: Parameters<ScanConfigParams>,
    ) -> Result<CallToolResult, ErrorData> {
        if self.network {
            return Err(ErrorData::invalid_request(
                "scan-config is only available over the stdio transport: it starts the \
                 MCP servers configured on this host"
                    .to_string(),
                None,
            ));
        }
        let p = params.0;
        let mut builder = ScanConfigBuilder::new();
        if let Some(d) = p.detailed {
            builder = builder.detailed(d);
        }
        if let Some(fmt) = p.format {
            builder = builder.format(fmt);
        }
        if let Some(t) = p.timeout {
            builder = builder.timeout(t);
        }
        if let Some(ht) = p.http_timeout {
            builder = builder.http_timeout(ht);
        }
        if let Some(headers) = p.auth_headers {
            builder = builder.auth_headers(Some(headers));
        }
        // Default to returning prompts (no LLM call) for MCP tool flow
        builder = builder.return_prompts(p.return_prompts.unwrap_or(true));

        let options = builder.build();
        let scanner = MCPScanner::with_timeout(options.http_timeout)
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        let results = scanner
            .scan_config_by_ide(options)
            .await
            .map_err(|e| ErrorData::invalid_request(e.to_string(), None))?;
        let json = serde_json::to_string(&results)
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        Ok(CallToolResult::success(vec![ContentBlock::text(json)]))
    }
}

/// Scan target for the `scan` tool. Over stdio the caller is the user's own
/// local agent, so `stdio:` (local-process) targets are allowed, as on the
/// CLI. Over the network transports they are refused: a remote caller must
/// not be able to start processes on this host. Everything else must be an
/// http(s) URL (see `server::http_target`).
fn tool_target(url: &str, network: bool) -> Result<String, crate::server::TargetError> {
    if !network && url.trim_start().starts_with("stdio:") {
        return Ok(url.trim().to_string());
    }
    crate::server::http_target(url)
}

#[tool_handler]
impl rmcp::ServerHandler for RampartsMcpServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build()).with_instructions(
            "Ramparts MCP server - provides scan and scan-config tools for MCP security scanning",
        )
    }
}

/// Run the MCP server over stdio transport.
pub async fn run_stdio_server() -> Result<(), Box<dyn std::error::Error>> {
    let handler = RampartsMcpServer::new(false);
    let service = handler.serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}

/// Run the MCP server over the HTTP+SSE endpoint.
///
/// In rmcp 1.x, SSE is no longer a separate server transport — it is delivered
/// as part of the streamable HTTP transport. This function is preserved for CLI
/// compatibility and delegates to the streamable HTTP server.
pub async fn run_sse_server(host: &str, port: u16) -> Result<(), Box<dyn std::error::Error>> {
    run_streamable_http_server(host, port).await
}

/// Run the MCP server over streamable HTTP transport using a Tower service (Axum-compatible)
pub async fn run_streamable_http_server(
    host: &str,
    port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    use axum::routing::any_service;
    use axum::Router;
    use tower::ServiceBuilder;

    let bind = crate::net_policy::resolve_bind(host, port).await?;
    // Tool calls now come from network callers: the scanner refuses
    // local-process targets from here on.
    crate::net_policy::enter_remote_mode();
    let token = crate::net_policy::api_token(host, "the MCP server");
    let loopback_without_token = token.is_none() && crate::net_policy::is_loopback_host(host);

    let service: StreamableHttpService<RampartsMcpServer, LocalSessionManager> =
        StreamableHttpService::new(
            || Ok(RampartsMcpServer::new(true)),
            std::sync::Arc::new(LocalSessionManager::default()),
            StreamableHttpServerConfig::default(),
        );

    let app = Router::new()
        .route("/", any_service(ServiceBuilder::new().service(service)))
        .route_layer(axum::middleware::from_fn(move |req, next| {
            crate::net_policy::require_token(token.clone(), req, next)
        }));
    // Loopback without a token: refuse requests addressed to any other Host,
    // so a web page can't reach the endpoint by DNS rebinding.
    let app = if loopback_without_token {
        app.layer(axum::middleware::from_fn(
            crate::net_policy::require_loopback_host,
        ))
    } else {
        app
    };
    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::tool_target;

    #[test]
    fn stdio_targets_allowed_over_stdio_only() {
        assert!(tool_target("stdio:npx:-y:some-mcp", false).is_ok());
        assert!(tool_target("stdio:npx:-y:some-mcp", true).is_err());
        assert!(tool_target("stdio://bash:-c:id;@example.com", true).is_err());
        for network in [false, true] {
            assert!(tool_target("https://mcp.example.com", network).is_ok());
            assert!(tool_target("file:///etc/passwd", network).is_err());
        }
    }
}
