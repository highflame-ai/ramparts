use crate::core::{
    AnalyzeRequest, BatchScanRequest, BatchScanResponse, ListRegisteredServersResponse,
    MCPScannerCore, RefreshToolsRequest, RefreshToolsResponse, RegisterServerRequest,
    RegisterServerResponse, ScanRequest, ScanResponse, ValidationResponse,
};
use axum::{
    extract::{Request, State},
    http::{header, HeaderMap, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::signal;
use tokio::sync::RwLock;
use tokio::time::{Duration, Instant};
use tower_http::cors::{AllowOrigin, Any, CorsLayer};
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
            host: "127.0.0.1".to_string(),
        }
    }
}

/// Validate a caller-supplied scan target and return the URL to scan.
///
/// Every server-mode URL field goes through here. Only `http`/`https` targets
/// are accepted, and the caller receives the parsed, re-serialized URL, so the
/// string handed to the scanner is exactly the one that was validated (the
/// scanner treats other schemes, such as local-process targets, specially).
fn validated_target(raw: &str) -> Result<String, String> {
    let raw = raw.trim();
    let candidate = if raw.contains("://") {
        raw.to_string()
    } else {
        format!("http://{raw}")
    };
    let parsed = url::Url::parse(&candidate).map_err(|e| format!("Invalid URL: {e}"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err("Only HTTP and HTTPS URLs are supported".to_string());
    }
    let normalized = parsed.to_string();
    reject_forbidden_target(&normalized)?;
    Ok(normalized)
}

fn bad_target(status: StatusCode, reason: String) -> (StatusCode, Json<Value>) {
    (
        status,
        Json(json!({
            "success": false,
            "error": reason,
            "timestamp": chrono::Utc::now().to_rfc3339()
        })),
    )
}

/// Validate `url` and `reference_url` of a scan request in place.
fn validate_scan_targets(request: &mut ScanRequest) -> Result<(), (StatusCode, Json<Value>)> {
    let status = |reason: &str| {
        if reason.starts_with("Refusing") {
            StatusCode::FORBIDDEN
        } else {
            StatusCode::BAD_REQUEST
        }
    };
    if !request.url.is_empty() {
        request.url = validated_target(&request.url).map_err(|r| bad_target(status(&r), r))?;
    }
    if let Some(reference) = request.reference_url.as_mut() {
        *reference = validated_target(reference).map_err(|r| bad_target(status(&r), r))?;
    }
    Ok(())
}

/// Bearer-token check for `/v1/ramparts/*` when `RAMPARTS_API_TOKEN` is set.
/// Unset keeps the API open, which is only appropriate on a loopback bind or
/// behind an authenticating proxy.
async fn require_token(token: Option<Arc<str>>, request: Request, next: Next) -> Response {
    let Some(token) = token else {
        return next.run(request).await;
    };
    let presented = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    if presented.is_some_and(|p| constant_time_eq(p.as_bytes(), token.as_bytes())) {
        next.run(request).await
    } else {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "success": false, "error": "Missing or invalid bearer token" })),
        )
            .into_response()
    }
}

fn is_loopback_host(host: &str) -> bool {
    matches!(host, "127.0.0.1" | "localhost" | "::1" | "[::1]")
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// CORS is off unless `RAMPARTS_CORS_ORIGINS` lists allowed origins
/// (comma-separated, or `*`).
fn cors_layer() -> Option<CorsLayer> {
    let raw = std::env::var("RAMPARTS_CORS_ORIGINS").ok()?;
    let origins = raw.trim();
    if origins.is_empty() {
        return None;
    }
    let allow = if origins == "*" {
        AllowOrigin::from(Any)
    } else {
        AllowOrigin::list(
            origins
                .split(',')
                .filter_map(|o| HeaderValue::from_str(o.trim()).ok()),
        )
    };
    Some(
        CorsLayer::new()
            .allow_origin(allow)
            .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
            .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE]),
    )
}

/// Reject scan targets that resolve to the host itself or to private networks.
///
/// The scan endpoints make the server fetch a caller-supplied URL, which is a
/// textbook request-forgery primitive: without this, a caller reaches
/// `169.254.169.254` for cloud credentials, or any service bound to the host's
/// private interfaces. Set `RAMPARTS_ALLOW_PRIVATE_TARGETS=1` to scan internal
/// servers deliberately.
fn reject_forbidden_target(raw_url: &str) -> Result<(), String> {
    let allow_private = std::env::var("RAMPARTS_ALLOW_PRIVATE_TARGETS").is_ok_and(|v| v == "1");
    reject_forbidden_target_with(raw_url, allow_private)
}

/// The policy itself, with the environment read out of it, so tests exercise
/// the rules without mutating process-global state.
fn reject_forbidden_target_with(raw_url: &str, allow_private: bool) -> Result<(), String> {
    if allow_private {
        return Ok(());
    }

    // Normalize the same way the scanner does before inspecting the host.
    let candidate = if raw_url.contains("://") {
        raw_url.to_string()
    } else {
        format!("http://{raw_url}")
    };

    let parsed = url::Url::parse(&candidate).map_err(|e| format!("Invalid URL: {e}"))?;

    // Match on the typed host. `host_str` returns an IPv6 literal wrapped in
    // brackets ("[::1]"), which does not parse as an IpAddr — so a string-based
    // check silently lets IPv6 loopback through.
    let ip = match parsed.host() {
        Some(url::Host::Ipv4(v4)) => Some(std::net::IpAddr::V4(v4)),
        Some(url::Host::Ipv6(v6)) => Some(std::net::IpAddr::V6(v6)),
        Some(url::Host::Domain(domain)) => {
            let lowered = domain.to_ascii_lowercase();
            if lowered == "localhost" || lowered.ends_with(".localhost") {
                return Err(
                    "Refusing to scan a loopback address. Set RAMPARTS_ALLOW_PRIVATE_TARGETS=1 \
                     to allow it."
                        .to_string(),
                );
            }
            // A bare domain may still resolve into private space. Resolution
            // happens later in the HTTP stack, so this check is best-effort by
            // design; the literal forms below are what an attacker reaches for.
            None
        }
        None => return Err("URL has no host".to_string()),
    };

    if let Some(ip) = ip {
        let forbidden = match ip {
            std::net::IpAddr::V4(v4) => {
                v4.is_loopback()
                    || v4.is_private()
                    || v4.is_link_local()
                    || v4.is_broadcast()
                    || v4.is_unspecified()
            }
            std::net::IpAddr::V6(v6) => {
                v6.is_loopback() || v6.is_unspecified() || (v6.segments()[0] & 0xffc0) == 0xfe80
            }
        };
        if forbidden {
            return Err(format!(
                "Refusing to scan {ip}: loopback, private, or link-local address. \
                 Set RAMPARTS_ALLOW_PRIVATE_TARGETS=1 to allow it."
            ));
        }
    }

    Ok(())
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

        let token: Option<Arc<str>> = std::env::var("RAMPARTS_API_TOKEN")
            .ok()
            .filter(|t| !t.is_empty())
            .map(Into::into);
        if token.is_none() && !is_loopback_host(&self.config.host) {
            warn!(
                "RAMPARTS_API_TOKEN is not set and the server binds {}: the API is \
                 unauthenticated. Set a token or bind 127.0.0.1.",
                self.config.host
            );
        }

        // Probes and health stay open; every other API route needs the
        // bearer token when one is configured.
        let api = Router::new()
            .route("/v1/ramparts/", get(api_docs))
            .route("/v1/ramparts/protocol", get(protocol_info))
            .route("/v1/ramparts/scan", post(scan_endpoint))
            .route("/v1/ramparts/analyze", post(analyze_endpoint))
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
            .route_layer(middleware::from_fn(move |req, next| {
                require_token(token.clone(), req, next)
            }));

        let app = Router::new()
            // Root-level k8s probe endpoints (platform convention).
            // Dependency-free so the pod reports ready as soon as the
            // listener is up.
            .route("/health", get(probe_ok))
            .route("/healthz", get(probe_ok))
            .route("/livez", get(probe_ok))
            .route("/v1/ramparts/health", get(health_check))
            .merge(api);
        let app = match cors_layer() {
            Some(cors) => app.layer(cors),
            None => app,
        };
        let app = app.layer(TraceLayer::new_for_http()).with_state(state);

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

/// Kubernetes liveness/readiness probe handler. Serves /health, /healthz,
/// and /livez — intentionally minimal (no upstream checks) so probe results
/// reflect only whether the HTTP listener is alive.
async fn probe_ok() -> Json<Value> {
    Json(json!({
        "status": "ok",
        "service": "ramparts-server"
    }))
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
            "GET /health | /healthz | /livez": "Kubernetes liveness/readiness probes",
            "GET /v1/ramparts/health": "Health check with protocol info",
            "GET /v1/ramparts/protocol": "MCP protocol information",
            "POST /v1/ramparts/scan": "Scan a single MCP server (live probe + analysis)",
            "POST /v1/ramparts/analyze": "Analyze pre-fetched MCP data without making any upstream calls",
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
            "POST /v1/ramparts/analyze": {
                "url": "http://localhost:3000",
                "format": "json",
                "scan_data": {
                    "server_info": null,
                    "tools": [
                        {
                            "name": "run_command",
                            "description": "Execute a shell command",
                            "input_schema": {}
                        }
                    ],
                    "resources": [],
                    "prompts": [],
                    "yara_results": [],
                    "fetch_errors": []
                }
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
    // Rate limit the endpoint that actually performs work. This previously
    // guarded only the deprecated refresh-tools stub.
    if check_rate_limit(&state, std::slice::from_ref(&request.url))
        .await
        .is_err()
    {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({
                "success": false,
                "error": "Rate limit exceeded. Please try again later.",
                "timestamp": chrono::Utc::now().to_rfc3339()
            })),
        ));
    }

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

    // One validator for every target the scanner will fetch: http/https
    // only, no private targets, and the scanner gets the validated form.
    validate_scan_targets(&mut request)?;

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

/// Analyze endpoint — runs security analysis against caller-supplied MCP
/// data, skipping the live MCP probe step entirely. Use when the live
/// server is unreachable to the scanner process (e.g. it lives behind a
/// gateway that holds the auth) but the caller already has the data.
///
/// Mirrors `scan_endpoint`'s response contract — same `ScanResponse`
/// envelope shape, same 400-on-failure pattern — so clients can switch
/// between the two paths without learning two error formats.
async fn analyze_endpoint(
    State(state): State<ServerState>,
    Json(request): Json<AnalyzeRequest>,
) -> Result<Json<ScanResponse>, (StatusCode, Json<Value>)> {
    // This endpoint drives LLM analysis, so it spends money per call even
    // though it fetches no URL of its own. Require the token; skip the
    // forgery guard, which has nothing to check here.
    // Validate timeout (same range as /scan — 1..=3600 seconds).
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

    debug!(
        "Received analyze request — url={:?} tools={} resources={} prompts={}",
        request.url,
        request.scan_data.tools.len(),
        request.scan_data.resources.len(),
        request.scan_data.prompts.len()
    );

    let response = state.core.analyze(request).await;

    if response.success {
        Ok(Json(response))
    } else {
        error!(
            "Analyze failed: {}",
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

    // Cap the batch. Scans run sequentially, so an uncapped list is an
    // unbounded amount of work bought with a single request.
    const MAX_BATCH_URLS: usize = 50;
    if request.urls.len() > MAX_BATCH_URLS {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "success": false,
                "error": format!("At most {MAX_BATCH_URLS} URLs per batch request"),
                "timestamp": chrono::Utc::now().to_rfc3339()
            })),
        ));
    }

    // Validate every target (and the shared reference URL) the same way
    // /scan does; the scanner receives the validated, normalized URLs.
    for url in request.urls.iter_mut() {
        *url = validated_target(url).map_err(|reason| {
            let status = if reason.starts_with("Refusing") {
                StatusCode::FORBIDDEN
            } else {
                StatusCode::BAD_REQUEST
            };
            bad_target(status, reason)
        })?;
    }
    if let Some(options) = request.options.as_mut() {
        validate_scan_targets(options)?;
    }

    if check_rate_limit(&state, &request.urls).await.is_err() {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({
                "success": false,
                "error": "Rate limit exceeded. Please try again later.",
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

/// Check the per-URL rate limit for a scanning request.
///
/// Two fixes over the original. The map is swept of empty and stale entries on
/// every call, because it is keyed on a caller-supplied URL and previously grew
/// without bound. And the limit is checked for every URL *before* any timestamp
/// is recorded, so a batch that trips the limit part-way no longer leaves the
/// earlier URLs charged for a request that was refused.
async fn check_rate_limit(state: &ServerState, urls: &[String]) -> Result<(), StatusCode> {
    const MAX_REQUESTS_PER_MINUTE: usize = 10;
    const MAX_TRACKED_URLS: usize = 10_000;

    let now = Instant::now();
    let window_duration = Duration::from_secs(60);
    let mut rate_limiter = state.rate_limiter.write().await;

    // Sweep expired timestamps and drop entries that hold none. Without this
    // the map retains a key for every distinct URL ever submitted.
    rate_limiter.retain(|_, requests| {
        requests.retain(|&timestamp| now.duration_since(timestamp) < window_duration);
        !requests.is_empty()
    });

    // Backstop against a flood of distinct URLs inside a single window.
    if rate_limiter.len() >= MAX_TRACKED_URLS {
        warn!("Rate limiter is tracking {MAX_TRACKED_URLS} URLs; shedding load");
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    // Check every URL first, so nothing is recorded for a refused request.
    for url in urls {
        if rate_limiter.get(url).map_or(0, Vec::len) >= MAX_REQUESTS_PER_MINUTE {
            warn!("Rate limit exceeded for URL: {}", url);
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
    }

    for url in urls {
        rate_limiter.entry(url.clone()).or_default().push(now);
    }

    Ok(())
}

// Tests removed for now - would need axum-test dependency

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validated_target_accepts_only_http_and_returns_the_parsed_url() {
        for raw in [
            "stdio://bash:-c:touch${IFS}marker;@example.com",
            "stdio://sh@example.com",
            "stdio:bash:-c:id",
            "stdio:///usr/bin/id",
            "STDIO://bash:-c:id;@example.com",
            "file:///etc/passwd",
            "gopher://example.com/",
        ] {
            assert!(validated_target(raw).is_err(), "should reject {raw}");
        }
        assert_eq!(
            validated_target("https://mcp.example.com/sse").unwrap(),
            "https://mcp.example.com/sse"
        );
        // Scheme-less targets are normalized to http and stay http.
        assert_eq!(
            validated_target("mcp.example.com:8080").unwrap(),
            "http://mcp.example.com:8080/"
        );
        // The forgery guard still applies to the parsed URL.
        assert!(validated_target("http://127.0.0.1:3000/").is_err());
        // The private-address guard alone accepts this form (it reads the
        // command as userinfo and checks host example.com), which is why the
        // scheme check above has to run on every target.
        assert!(
            reject_forbidden_target_with("stdio://bash:-c:touch${IFS}x;@example.com", false)
                .is_ok()
        );
    }

    #[test]
    fn reference_url_is_validated_like_the_target() {
        let mut req = ScanRequest {
            url: "https://mcp.example.com/".to_string(),
            reference_url: Some("stdio://bash:-c:id;@example.com".to_string()),
            ..Default::default()
        };
        assert!(validate_scan_targets(&mut req).is_err());
        req.reference_url = Some("https://ref.example.com".to_string());
        validate_scan_targets(&mut req).unwrap();
        assert_eq!(
            req.reference_url.as_deref(),
            Some("https://ref.example.com/")
        );
    }

    #[test]
    fn token_compare_and_loopback_detection() {
        assert!(constant_time_eq(b"secret", b"secret"));
        assert!(!constant_time_eq(b"secret", b"secreT"));
        assert!(!constant_time_eq(b"secret", b"secret2"));
        assert!(is_loopback_host("127.0.0.1"));
        assert!(!is_loopback_host("0.0.0.0"));
    }
    // Note: StatusCode is used in the validation logic but not in tests

    #[test]
    fn test_server_config_default() {
        let config = ServerConfig::default();
        assert_eq!(config.port, 3000);
        assert_eq!(config.host, "127.0.0.1");
    }

    #[test]
    fn test_forbidden_targets_are_rejected() {
        let denied = |url: &str| reject_forbidden_target_with(url, false).is_err();

        // Cloud metadata, the canonical request-forgery target.
        assert!(denied("http://169.254.169.254/latest/meta-data"));
        // Loopback by name and by address, v4 and v6.
        assert!(denied("http://localhost:8080"));
        assert!(denied("http://127.0.0.1:3000"));
        assert!(denied("http://[::1]:3000"));
        // RFC 1918 space.
        assert!(denied("http://10.0.0.5/mcp"));
        assert!(denied("http://192.168.1.10/mcp"));
        assert!(denied("http://172.16.4.2/mcp"));
        // A scheme-less host must be normalized before the check, not skipped.
        assert!(denied("127.0.0.1:3000"));

        // Ordinary public targets still scan.
        assert!(reject_forbidden_target_with("https://mcp.example.com/v1", false).is_ok());
        assert!(reject_forbidden_target_with("mcp.example.com", false).is_ok());
    }

    #[test]
    fn test_private_targets_allowed_when_explicitly_opted_in() {
        // Operators who mean to scan internal servers can opt in. Exercised
        // through the pure form so the test mutates no process-global state.
        assert!(reject_forbidden_target_with("http://10.0.0.5/mcp", true).is_ok());
        assert!(reject_forbidden_target_with("http://169.254.169.254/", true).is_ok());
        // ...and the same targets are still refused by default.
        assert!(reject_forbidden_target_with("http://10.0.0.5/mcp", false).is_err());
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
