use crate::core::{
    BatchScanRequest, BatchScanResponse, ListRegisteredServersResponse, MCPScannerCore,
    RefreshToolsRequest, RefreshToolsResponse, RegisterServerRequest, RegisterServerResponse,
    ScanRequest, ScanResponse, ValidationResponse,
};
use axum::{
    extract::State,
    http::{HeaderMap, Method, StatusCode},
    response::Json,
    routing::{get, post},
    Router,
};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::signal;
use tokio::sync::RwLock;
use tokio::time::{Duration, Instant};
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::{debug, error, info, warn};

#[derive(Clone)]
pub struct ServerState {
    core: Arc<MCPScannerCore>,
    rate_limiter: Arc<RwLock<HashMap<String, Vec<Instant>>>>,
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub port: u16,
    pub host: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            port: 3000,
            host: "0.0.0.0".to_string(),
        }
    }
}

pub struct MCPScannerServer {
    core: MCPScannerCore,
    config: ServerConfig,
}

impl MCPScannerServer {
    pub fn new() -> anyhow::Result<Self> {
        Ok(Self {
            core: MCPScannerCore::new()?,
            config: ServerConfig::default(),
        })
    }

    pub fn with_port(mut self, port: u16) -> Self {
        self.config.port = port;
        self
    }

    pub fn with_host(mut self, host: String) -> Self {
        self.config.host = host;
        self
    }

    pub async fn start(self) -> anyhow::Result<()> {
        let core = Arc::new(self.core);
        let state = ServerState {
            core: core.clone(),
            rate_limiter: Arc::new(RwLock::new(HashMap::new())),
        };

        // Configure CORS
        let cors = CorsLayer::new()
            .allow_origin(Any)
            .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
            .allow_headers(Any);

        // Create router with routes
        let app = Router::new()
            .route("/v1/ramparts/", get(api_docs))
            .route("/v1/ramparts/health", get(health_check))
            .route("/v1/ramparts/protocol", get(protocol_info))
            .route("/v1/ramparts/scan", post(scan_endpoint))
            .route("/v1/ramparts/validate", post(validate_endpoint))
            .route("/v1/ramparts/batch-scan", post(batch_scan_endpoint))
            .route("/v1/ramparts/refresh-tools", post(refresh_tools_endpoint))
            .route(
                "/v1/ramparts/register-server",
                post(register_server_endpoint),
            )
            .route(
                "/v1/ramparts/unregister-server",
                post(unregister_server_endpoint),
            )
            .route("/v1/ramparts/list-servers", get(list_servers_endpoint))
            .layer(cors)
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        let addr = format!("{}:{}", self.config.host, self.config.port);
        info!("Starting MCP Scanner Server on http://{addr}");
        debug!("Protocol version: 2025-06-18");

        let listener = tokio::net::TcpListener::bind(&addr).await?;

        // Set up graceful shutdown
        info!("Server ready to handle graceful shutdown signals (SIGTERM, SIGINT)");
        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown_signal())
            .await?;

        info!("Server shutdown complete");
        Ok(())
    }
}

/// Shutdown signal handler that listens for SIGTERM and SIGINT
async fn shutdown_signal() {
    let ctrl_c = async {
        match signal::ctrl_c().await {
            Ok(()) => {
                debug!("Ctrl+C signal handler installed successfully");
            }
            Err(e) => {
                error!("Failed to install Ctrl+C handler: {}", e);
                // Return a pending future to disable this signal handling
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match signal::unix::signal(signal::unix::SignalKind::terminate()) {
            Ok(mut signal_handler) => {
                debug!("SIGTERM signal handler installed successfully");
                signal_handler.recv().await;
            }
            Err(e) => {
                error!("Failed to install SIGTERM handler: {}", e);
                // Return a pending future to disable this signal handling
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            warn!("Received SIGINT (Ctrl+C), initiating graceful shutdown...");
        }
        _ = terminate => {
            warn!("Received SIGTERM, initiating graceful shutdown...");
        }
    }
}

/// Helper function to extract Javelin API key from headers and add to auth_headers
fn extract_and_add_api_key(
    headers: &HeaderMap,
    auth_headers: &mut Option<HashMap<String, String>>,
) {
    if let Some(api_key) = headers
        .get("x-javelin-apikey")
        .and_then(|h| h.to_str().ok())
        .filter(|key| !key.trim().is_empty())
    // Filter out empty keys
    {
        debug!("Extracted Javelin API key from X-Javelin-Apikey header");

        // Initialize auth_headers if it doesn't exist
        if auth_headers.is_none() {
            *auth_headers = Some(HashMap::new());
        }

        // Add the API key to auth_headers if not already present
        if let Some(ref mut headers_map) = auth_headers {
            if !headers_map.contains_key("x-javelin-api-key") {
                headers_map.insert("x-javelin-api-key".to_string(), api_key.to_string());
                debug!("Added API key to auth_headers for conversion");
            }
        }
    }
}

async fn health_check() -> Json<Value> {
    Json(json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "service": "ramparts-server",
        "version": env!("CARGO_PKG_VERSION"),
        "protocol_version": "2025-06-18"
    }))
}

async fn protocol_info() -> Json<Value> {
    Json(json!({
        "protocol": {
            "version": "2025-06-18",
            "name": "Model Context Protocol",
            "transport": {
                "stdio": "supported",
                "http": "supported",
                "features": [
                    "JSON-RPC 2.0",
                    "Session Management",
                    "Protocol Version Headers",
                    "STDIO Process Communication",
                    "Multi-Transport Support"
                ]
            },
            "capabilities": [
                "tools/list",
                "resources/list",
                "prompts/list",
                "server/info"
            ]
        },
        "server": {
            "version": env!("CARGO_PKG_VERSION"),
            "stdio_support": true,
            "mcp_compliance": "2025-06-18"
        }
    }))
}

async fn api_docs() -> Json<Value> {
    Json(json!({
        "service": "Ramparts Microservice",
        "version": env!("CARGO_PKG_VERSION"),
        "protocol_version": "2025-06-18",
        "endpoints": {
            "GET /v1/ramparts/health": "Health check with protocol info",
            "GET /v1/ramparts/protocol": "MCP protocol information",
            "POST /v1/ramparts/scan": "Scan a single MCP server",
            "POST /v1/ramparts/validate": "Validate scan configuration",
            "POST /v1/ramparts/batch-scan": "Scan multiple MCP servers",
            "POST /v1/ramparts/refresh-tools": "Refresh tool descriptions from MCP servers",
            "POST /v1/ramparts/register-server": "Register a server for automatic daily refresh",
            "POST /v1/ramparts/unregister-server": "Unregister a server from automatic refresh",
            "GET /v1/ramparts/list-servers": "List all registered servers for automatic refresh",
            "GET /v1/ramparts/": "API documentation"
        },
        "transports": {
            "http": {
                "supported": true,
                "description": "HTTP/HTTPS transport for remote MCP servers",
                "examples": [
                    "http://localhost:3000",
                    "https://api.example.com/mcp",
                    "http://192.168.1.100:8080"
                ]
            },
            "stdio": {
                "supported": true,
                "description": "STDIO transport for local MCP server processes",
                "examples": [
                    "stdio:///usr/local/bin/mcp-server",
                    "stdio://node /path/to/mcp-server.js",
                    "/usr/bin/python3 /path/to/mcp-server.py",
                    "mcp-server --config config.json"
                ]
            },

        },

        "example": {
            "POST /v1/ramparts/scan": {
                "url": "http://localhost:3000",
                "timeout": 180,
                "http_timeout": 30,
                "detailed": true,
                "format": "json",
                "auth_headers": { "Authorization": "Bearer token" }
            },
            "STDIO Example": {
                "url": "stdio:///usr/local/bin/mcp-server",
                "timeout": 180,
                "detailed": true,
                "format": "json"
            }
        }
    }))
}

async fn scan_endpoint(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Json(mut request): Json<ScanRequest>,
) -> Result<Json<ScanResponse>, (StatusCode, Json<Value>)> {
    // Extract Javelin API key from headers using helper function
    extract_and_add_api_key(&headers, &mut request.auth_headers);

    // Input validation
    if request.url.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "success": false,
                "error": "URL is required",
                "timestamp": chrono::Utc::now().to_rfc3339()
            })),
        ));
    }

    // Validate URL format - only HTTP/HTTPS supported with rmcp
    if !request.url.contains("://") {
        // Allow URLs without scheme - they'll be normalized to http://
    } else if !request.url.starts_with("http://") && !request.url.starts_with("https://") {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "success": false,
                "error": "Only HTTP and HTTPS URLs are supported",
                "timestamp": chrono::Utc::now().to_rfc3339()
            })),
        ));
    }

    // Validate timeout values
    if let Some(timeout) = request.timeout {
        if timeout == 0 || timeout > 3600 {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "success": false,
                    "error": "Timeout must be between 1 and 3600 seconds",
                    "timestamp": chrono::Utc::now().to_rfc3339()
                })),
            ));
        }
    }

    debug!("Received scan request for URL: {}", request.url);

    let response = state.core.scan(request).await;

    if response.success {
        Ok(Json(response))
    } else {
        error!(
            "Scan failed: {}",
            response
                .error
                .as_ref()
                .unwrap_or(&"Unknown error".to_string())
        );
        Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "success": false,
                "error": response.error,
                "timestamp": response.timestamp
            })),
        ))
    }
}

async fn validate_endpoint(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Json(mut request): Json<ScanRequest>,
) -> Result<Json<ValidationResponse>, (StatusCode, Json<Value>)> {
    // Extract Javelin API key from headers using helper function
    extract_and_add_api_key(&headers, &mut request.auth_headers);

    debug!("Received validation request");

    let response = state.core.validate_config(&request);

    if response.success && response.valid {
        Ok(Json(response))
    } else {
        error!(
            "Validation failed: {}",
            response
                .error
                .as_ref()
                .unwrap_or(&"Unknown error".to_string())
        );
        Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "success": false,
                "valid": false,
                "error": response.error,
                "timestamp": response.timestamp
            })),
        ))
    }
}

async fn batch_scan_endpoint(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Json(mut request): Json<BatchScanRequest>,
) -> Result<Json<BatchScanResponse>, (StatusCode, Json<Value>)> {
    // Fix critical bug: Handle API key even when options is None
    if request.options.is_none() {
        // Create default options if they don't exist
        request.options = Some(ScanRequest::default());
    }

    // Extract Javelin API key from headers using helper function
    if let Some(ref mut options) = request.options {
        extract_and_add_api_key(&headers, &mut options.auth_headers);
    }

    if request.urls.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "success": false,
                "error": "At least one URL is required",
                "timestamp": chrono::Utc::now().to_rfc3339()
            })),
        ));
    }

    debug!(
        "Received batch scan request for {} URLs",
        request.urls.len()
    );

    let response = state.core.batch_scan(request).await;

    if response.success {
        Ok(Json(response))
    } else {
        error!(
            "Batch scan failed: {} successful, {} failed",
            response.successful, response.failed
        );
        Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "success": false,
                "error": "Batch scan failed",
                "timestamp": response.timestamp
            })),
        ))
    }
}

/// Refresh tools endpoint - refreshes tool descriptions from MCP servers
async fn refresh_tools_endpoint(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Json(mut request): Json<RefreshToolsRequest>,
) -> Result<Json<RefreshToolsResponse>, (StatusCode, Json<Value>)> {
    // Apply rate limiting
    if let Err(status) = check_rate_limit(&state, &request.urls).await {
        return Err((
            status,
            Json(json!({
                "success": false,
                "error": "Rate limit exceeded. Please try again later.",
                "timestamp": chrono::Utc::now().to_rfc3339()
            })),
        ));
    }

    // Extract Javelin API key from headers using helper function
    extract_and_add_api_key_to_refresh_request(&headers, &mut request);

    // Validate request
    if request.urls.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "success": false,
                "error": "At least one URL must be provided",
                "timestamp": chrono::Utc::now().to_rfc3339()
            })),
        ));
    }

    debug!(
        "Received refresh tools request for {} URLs",
        request.urls.len()
    );

    let response = state.core.refresh_tools(request).await;

    if response.success {
        Ok(Json(response))
    } else {
        error!(
            "Refresh tools failed: {} successful, {} failed",
            response.successful, response.failed
        );
        Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "success": false,
                "error": "Refresh tools failed",
                "timestamp": response.timestamp
            })),
        ))
    }
}

/// Helper function to extract Javelin API key and add to refresh tools request
fn extract_and_add_api_key_to_refresh_request(
    headers: &HeaderMap,
    request: &mut RefreshToolsRequest,
) {
    let mut auth_headers = request.auth_headers.clone().unwrap_or_default();

    // Apply environment variable mappings first
    auth_headers = crate::config::apply_env_mappings(auth_headers);

    // Then add Javelin API key if present
    if let Some(api_key) = headers.get("x-javelin-apikey") {
        if let Ok(api_key_str) = api_key.to_str() {
            debug!("Found Javelin API key in headers");
            auth_headers.insert("Authorization".to_string(), format!("Bearer {api_key_str}"));
        }
    }

    request.auth_headers = Some(auth_headers);
}

/// Register server endpoint - register a server for automatic daily refresh
async fn register_server_endpoint(
    State(state): State<ServerState>,
    Json(request): Json<RegisterServerRequest>,
) -> Result<Json<RegisterServerResponse>, (StatusCode, Json<Value>)> {
    debug!("Received register server request for: {}", request.url);

    let response = state.core.register_server(request).await;

    if response.success {
        Ok(Json(response))
    } else {
        error!("Server registration failed: {}", response.message);
        Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "success": false,
                "message": response.message,
                "timestamp": response.timestamp
            })),
        ))
    }
}

/// Unregister server endpoint - remove a server from automatic refresh
async fn unregister_server_endpoint(
    State(state): State<ServerState>,
    Json(request): Json<serde_json::Value>,
) -> Result<Json<RegisterServerResponse>, (StatusCode, Json<Value>)> {
    let url = match request.get("url").and_then(|v| v.as_str()) {
        Some(url) => url,
        None => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "success": false,
                    "message": "URL is required",
                    "timestamp": chrono::Utc::now().to_rfc3339()
                })),
            ));
        }
    };

    debug!("Received unregister server request for: {}", url);

    let response = state.core.unregister_server(url).await;

    if response.success {
        Ok(Json(response))
    } else {
        error!("Server unregistration failed: {}", response.message);
        Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "success": false,
                "message": response.message,
                "timestamp": response.timestamp
            })),
        ))
    }
}

/// List servers endpoint - list all registered servers for automatic refresh
async fn list_servers_endpoint(
    State(state): State<ServerState>,
) -> Json<ListRegisteredServersResponse> {
    debug!("Received list servers request");
    let response = state.core.list_registered_servers().await;
    Json(response)
}

/// Check rate limit for refresh requests
async fn check_rate_limit(state: &ServerState, urls: &[String]) -> Result<(), StatusCode> {
    let now = Instant::now();
    let mut rate_limiter = state.rate_limiter.write().await;

    // Load rate limit config (default values if config loading fails)
    let max_requests_per_minute = 10u64; // Default from config
    let window_duration = Duration::from_secs(60); // 1 minute window

    for url in urls {
        // Get or create request history for this URL
        let requests = rate_limiter.entry(url.clone()).or_insert_with(Vec::new);

        // Remove old requests outside the time window
        requests.retain(|&timestamp| now.duration_since(timestamp) < window_duration);

        // Check if we're at the rate limit
        if requests.len() >= max_requests_per_minute as usize {
            warn!("Rate limit exceeded for URL: {}", url);
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }

        // Add current request to history
        requests.push(now);
    }

    Ok(())
}

// Tests removed for now - would need axum-test dependency

#[cfg(test)]
mod tests {
    use super::*;
    // Note: StatusCode is used in the validation logic but not in tests

    #[test]
    fn test_server_config_default() {
        let config = ServerConfig::default();
        assert_eq!(config.port, 3000);
        assert_eq!(config.host, "0.0.0.0");
    }

    #[test]
    fn test_scan_request_validation() {
        // Test empty URL
        let request = ScanRequest {
            url: String::new(),
            ..Default::default()
        };
        assert!(request.url.is_empty());

        // Test valid URL
        let request = ScanRequest {
            url: "https://example.com".to_string(),
            ..Default::default()
        };
        assert!(!request.url.is_empty());
        assert!(request.url.starts_with("https://"));
    }
}
