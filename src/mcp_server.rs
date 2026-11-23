use std::sync::Arc;

use crate::core::{MCPScannerCore, ScanRequest};
use crate::scanner::MCPScanner;
use crate::types::ScanConfigBuilder;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::schemars::JsonSchema;
use rmcp::{
    handler::server::router::tool::ToolRouter,
    model::{CallToolResult, ContentBlock, ServerCapabilities, ServerInfo},
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
        // http(s) MCP endpoints only: other schemes make the scanner start
        // a local process, which a tool caller (an agent, or a remote client)
        // must not be able to request.
        let url = crate::server::http_target(&p.url, self.network)
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

#[tool_handler]
impl rmcp::ServerHandler for RampartsMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build()).with_instructions(
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

    let bare = crate::server::bare_host(host);
    let bind: std::net::SocketAddr = match bare.parse::<std::net::IpAddr>() {
        Ok(ip) => std::net::SocketAddr::new(ip, port),
        Err(_) => tokio::net::lookup_host((bare, port))
            .await?
            .next()
            .ok_or("could not resolve --host")?,
    };

    // Callers may be remote: scans must not reach this host or private
    // networks (URL, DNS answers and redirects).
    if std::env::var("RAMPARTS_ALLOW_PRIVATE_TARGETS").is_ok_and(|v| v == "1") {
        tracing::warn!("RAMPARTS_ALLOW_PRIVATE_TARGETS=1: MCP scans may reach private networks");
    } else {
        crate::net_policy::block_private_targets();
    }
    let token: Option<Arc<str>> = std::env::var("RAMPARTS_API_TOKEN")
        .ok()
        .filter(|t| !t.is_empty())
        .map(Into::into);
    if token.is_none() && !crate::server::is_loopback_host(host) {
        tracing::warn!(
            "RAMPARTS_API_TOKEN is not set and the MCP server binds {host}: it is \
             unauthenticated. Set a token or bind 127.0.0.1."
        );
    }

    let service: StreamableHttpService<RampartsMcpServer, LocalSessionManager> =
        StreamableHttpService::new(
            || Ok(RampartsMcpServer::new(true)),
            std::sync::Arc::new(LocalSessionManager::default()),
            StreamableHttpServerConfig::default(),
        );

    let app = Router::new()
        .route("/", any_service(ServiceBuilder::new().service(service)))
        .route_layer(axum::middleware::from_fn(move |req, next| {
            crate::server::require_token(token.clone(), req, next)
        }));
    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
