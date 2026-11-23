# API Reference

This document provides detailed information about the Ramparts REST API server mode.

## Server Mode Overview

Think of Ramparts server mode as your security scanner running as a service instead of a one-off command. While `ramparts scan` is great for quick checks, the server mode gives you a REST API that your applications, CI/CD pipelines, and monitoring systems can talk to.

### When Should You Use Server Mode?

If you're running `ramparts scan` more than once, you probably want server mode. Here are some common scenarios:

**You're building CI/CD pipelines** and want to fail builds when MCP servers have critical security issues. Instead of installing and running the CLI in every pipeline, just POST to `/v1/ramparts/scan` and check the response.

**Your team is using multiple MCP servers** and you want a centralized way to monitor their security posture. Start one Ramparts server, point it at all your MCP endpoints, and you've got a security dashboard.

**You're integrating security scanning into an existing application.** Maybe you're building a developer portal that needs to show MCP server security status, or you want to automatically scan servers when they're added to your system.

**You need scheduled scanning** without setting up complex cron jobs. The API makes it easy to build simple monitoring scripts that run regular scans and send alerts when issues are found.

### What You Get

Server mode handles multiple requests concurrently, so your team can scan different servers simultaneously without waiting. The JSON responses are consistent and easy to parse, making it simple to build automation around the results.

You also get health check endpoints for monitoring, batch scanning for efficiency, intelligent change detection to avoid unnecessary scans, and all the same security detection capabilities as the CLI—just wrapped in a REST API that plays nicely with modern development workflows.

### 🆕 Intelligent Change Detection

The enhanced scan API includes intelligent change detection that automatically tracks tool changes and skips scans when nothing has changed. This reduces network overhead and provides detailed change tracking for monitoring tool evolution.

**Key Benefits:**
- **Efficiency**: Skip scans when tools haven't changed
- **Monitoring**: Track tool evolution with detailed change summaries
- **Integration**: Works seamlessly with Javelin MCP for tool refresh
- **Flexibility**: Configurable sensitivity levels for different use cases

## Starting the Server

Start Ramparts as a REST API server for continuous monitoring and integration with other systems:

```bash
# Start server on 127.0.0.1:3000 (loopback only)
ramparts server

# Expose it on all interfaces: always set a token when you do
RAMPARTS_API_TOKEN=change-me ramparts server --port 8080 --host 0.0.0.0
```

| Setting | Default | Effect |
|---|---|---|
| `--host` | `127.0.0.1` | Bind address. Use `0.0.0.0` only together with `RAMPARTS_API_TOKEN` or an authenticating proxy. |
| `RAMPARTS_API_TOKEN` | unset | When set, every `/v1/ramparts/*` endpoint except `/v1/ramparts/health` requires `Authorization: Bearer <token>`. |
| `RAMPARTS_CORS_ORIGINS` | unset | Comma-separated origins allowed to call the API from a browser, or `*`. When unset: no CORS on a loopback bind; any origin on an exposed bind (as the deployed service needs for browser clients). |
| Host check | on for a loopback bind without a token | Requests must be addressed to a loopback host (`localhost`, `127.0.0.1`, `[::1]`), so web pages can't reach the API via DNS rebinding. |

Scan targets (`url`, `urls`, `reference_url`) must be `http` or `https` URLs. Private and loopback MCP servers can be scanned; cloud metadata addresses (`169.254.0.0/16`, `fe80::/10`, `fd00:ec2::254`) are refused.

Once started, the server provides a REST API with the following endpoints:



## API Endpoints

### 1. Health Check
**GET /v1/ramparts/health**

Check server health and protocol information.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2024-01-01T12:00:00.000Z",
  "service": "ramparts-server",
  "version": "0.2.0",
  "protocol_version": "2025-06-18"
}
```

### 2. Protocol Information
**GET /v1/ramparts/protocol**

Get detailed MCP protocol information and supported capabilities.

**Response:**
```json
{
  "protocol": {
    "version": "2025-06-18",
    "name": "Model Context Protocol",
    "transport": {
      "stdio": "supported",
      "http": "supported",
      "features": [
        "JSON-RPC 2.0",
        "Stateful Session Management",
        "Protocol Version Headers", 
        "STDIO Process Communication",
        "Intelligent Transport Fallback",
        "rmcp Library Integration",
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
    "version": "0.2.0",
    "stdio_support": true,
    "mcp_compliance": "2025-06-18"
  }
}
```

### 3. API Documentation
**GET /v1/ramparts/**

Get interactive API documentation with examples.

**Response:**
```json
{
  "service": "Ramparts Microservice",
  "version": "0.2.0",
  "protocol_version": "2025-06-18",
  "endpoints": {
    "GET /v1/ramparts/health": "Health check with protocol info",
    "GET /v1/ramparts/protocol": "MCP protocol information",
    "POST /v1/ramparts/scan": "Scan a single MCP server",
    "POST /v1/ramparts/validate": "Validate scan configuration",
    "POST /v1/ramparts/batch-scan": "Scan multiple MCP servers",
    "POST /v1/ramparts/refresh-tools": "Refresh tool descriptions from MCP servers",
    "GET /v1/ramparts/": "API documentation"
  },
  "transports": {
    "http": {
      "supported": true,
      "description": "HTTP/HTTPS transport with intelligent fallback (simple HTTP, rmcp streamable, SSE)",
      "features": ["session_management", "authentication_headers", "automatic_fallback"],
      "examples": [
        "http://localhost:3000",
        "https://api.githubcopilot.com/mcp"
      ]
    },
    "stdio": {
      "supported": true,
      "description": "STDIO transport for local MCP server processes using rmcp subprocess implementation",
      "features": ["process_management", "argument_parsing", "concurrent_execution"],
      "examples": [
        "stdio:npx:mcp-server-commands",
        "stdio:python3:/path/to/server.py",
        "stdio:///usr/local/bin/mcp-server"
      ]
    }
  }
}
```

### 4. Single Server Scan
**POST /v1/ramparts/scan**

Scan a single MCP server for security vulnerabilities with intelligent change detection.

**Basic Request:**
```json
{
  "url": "https://api.githubcopilot.com/mcp/",
  "timeout": 180,
  "http_timeout": 30,
  "detailed": true,
  "format": "json",
  "auth_headers": {
    "Authorization": "Bearer your-token-here",
    "X-API-Key": "your-api-key"
  }
}
```

**Enhanced Request with Change Detection:**
```json
{
  "url": "https://api.githubcopilot.com/mcp/",
  "timeout": 180,
  "http_timeout": 30,
  "detailed": true,
  "format": "json",
  "auth_headers": {
    "Authorization": "Bearer your-token-here"
  },
  "javelin_mcp_url": "https://javelin.live/mcp/example/",
  "reference_mcp_url": "https://api.githubcopilot.com/mcp/",
  "force_scan": false,
  "include_diff": true,
  "change_detection": {
    "enabled": true,
    "compare_schemas": true,
    "compare_descriptions": true,
    "ignore_fields": ["timestamp"],
    "sensitivity": "moderate"
  }
}
```

**Request Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `url` | string | Yes | MCP server URL to scan |
| `timeout` | number | No | Overall scan timeout in seconds (default: 180) |
| `http_timeout` | number | No | HTTP request timeout in seconds (default: 30) |
| `detailed` | boolean | No | Include detailed vulnerability information (default: false) |
| `format` | string | No | Response format: "json" or "text" (default: "json") |
| `auth_headers` | object | No | Authentication headers for the MCP server |
| `return_prompts` | boolean | No | Return prompts instead of LLM analysis (default: false) |

**🆕 Change Detection Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `javelin_mcp_url` | string | No | Javelin MCP URL for tool refresh |
| `reference_mcp_url` | string | No | Reference URL for comparison baseline |
| `force_scan` | boolean | No | Force scan even if no changes detected (default: false) |
| `include_diff` | boolean | No | Include detailed change summary (default: false) |
| `change_detection` | object | No | Change detection configuration |

**Change Detection Configuration:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `enabled` | boolean | Enable change detection (default: true when javelin_mcp_url provided) |
| `compare_schemas` | boolean | Compare tool input/output schemas (default: true) |
| `compare_descriptions` | boolean | Compare tool descriptions (default: true) |
| `ignore_fields` | array | Fields to ignore during comparison |
| `sensitivity` | string | Comparison sensitivity: "strict", "moderate", "loose" (default: "moderate") |

**Javelin Integration Headers:**

For Javelin MCP servers, you can include the `X-Javelin-Apikey` header which will be automatically converted to the appropriate authentication formats:

```bash
curl -X POST http://localhost:3000/v1/ramparts/scan \
  -H "Content-Type: application/json" \
  -H "X-Javelin-Apikey: your-javelin-key" \
  -d '{
    "url": "https://api.githubcopilot.com/mcp/",
    "timeout": 60
  }'
```

**Request Fields:**
- `url` (required): MCP server URL or STDIO command
- `timeout` (optional): Total scan timeout in seconds (1-3600, default: 60)
- `http_timeout` (optional): HTTP request timeout in seconds (default: 30)
- `detailed` (optional): Enable detailed analysis (default: false)
- `format` (optional): Output format - "json", "table", "text", "raw" (default: "table")
- `auth_headers` (optional): Authentication headers as key-value pairs

**Special Headers:**
- `X-Javelin-Apikey`: When included in request headers, automatically adds appropriate authentication for Javelin MCP servers

**STDIO Examples:**
```json
{
  "url": "stdio:///usr/local/bin/mcp-server",
  "timeout": 180,
  "detailed": true,
  "format": "json"
}
```

```json
{
  "url": "node /path/to/mcp-server.js --config config.json",
  "timeout": 180,
  "detailed": true
}
```

**Success Response (200):**
```json
{
  "success": true,
      "result": {
      "url": "https://api.githubcopilot.com/mcp/",
      "status": "Success",
      "timestamp": "2024-01-01T12:00:00.000Z",
      "response_time_ms": 1234,
      "server_info": {
        "name": "github-mcp-server",
        "version": "1.0.0",
        "description": "GitHub Copilot MCP server for code assistance",
        "capabilities": ["tools", "resources", "prompts"],
        "metadata": {
          "transport": "http"
        }
      },
    "tools": [
      {
        "name": "create_file",
        "description": "Create a new file",
        "input_schema": {
          "type": "object",
          "properties": {
            "path": { "type": "string" },
            "content": { "type": "string" }
          }
        },
        "parameters": {},
        "category": "file_system",
        "tags": ["write", "create"],
        "deprecated": false,
        "llm_analysis": "The create_file tool accepts a path parameter that could be vulnerable to path traversal attacks if not properly validated.",
        "security_scan_results": [
          {
            "scan_type": "llm_analysis",
            "issue_type": "PathTraversal",
            "severity": "HIGH",
            "message": "Tool vulnerable to path traversal attacks",
            "description": "Tool allows potential path traversal attacks",
            "details": "The path parameter is not validated, allowing potential directory traversal"
          },
          {
            "scan_type": "yara_rules",
            "rule_name": "PathTraversalVulnerability",
            "rule_file": "path_traversal",
            "context": "Path traversal vulnerability detected in tool",
            "rule_metadata": {
              "severity": "HIGH",
              "description": "Detects potential path traversal vulnerabilities"
            }
          }
        ]
      }
    ],
    "resources": [],
    "prompts": [],
    "security_issues": {
      "issues": [
        {
          "scan_type": "llm_analysis",
          "target_type": "tool",
          "target_name": "create_file",
          "issue_type": "PathTraversal",
          "severity": "HIGH",
          "message": "Tool vulnerable to path traversal attacks",
          "description": "Tool allows potential path traversal attacks",
          "details": "The path parameter is not validated, allowing potential directory traversal"
        },
        {
          "scan_type": "yara_rules",
          "target_type": "tool",
          "target_name": "create_file",
          "rule_name": "PathTraversalVulnerability",
          "rule_file": "path_traversal",
          "context": "Path traversal vulnerability detected in tool",
          "rule_metadata": {
            "severity": "HIGH",
            "description": "Detects potential path traversal vulnerabilities"
          }
        }
      ],
      "llm_issues_count": 1,
      "yara_issues_count": 1,
      "total_issues_count": 2
    },
    "security_scan_summary": {
      "total_security_issues": 2,
      "llm_scan_issues": 1,
      "yara_scan_issues": 1,
      "tool_issues": 1,
      "resource_issues": 0,
      "prompt_issues": 0
    },
    "errors": []
  },
  "error": null,
  "timestamp": "2024-01-01T12:00:00.000Z",

  // 🆕 Change Detection Fields
  "refresh_happened": true,
  "changes_detected": true,
  "change_summary": {
    "total_changes": 3,
    "tools_added": ["new_tool"],
    "tools_removed": ["old_tool"],
    "tools_modified": [
      {
        "tool_name": "existing_tool",
        "change_type": "description",
        "old_value": "Old description",
        "new_value": "New description",
        "diff": "Description changed"
      }
    ],
    "change_types": ["tools_added", "tools_removed", "tools_modified"]
  },
  "scan_skipped": false,
  "cache_hit": false
}
```

**🆕 Change Detection Response Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `refresh_happened` | boolean | Whether tools were refreshed from Javelin MCP |
| `changes_detected` | boolean | Whether changes were detected compared to baseline |
| `change_summary` | object | Detailed summary of changes (when `include_diff: true`) |
| `scan_skipped` | boolean | Whether scan was skipped due to no changes |
| `cache_hit` | boolean | Whether cached results were used |

**Change Summary Object:**

| Field | Type | Description |
|-------|------|-------------|
| `total_changes` | number | Total number of changes detected |
| `tools_added` | array | Names of tools that were added |
| `tools_removed` | array | Names of tools that were removed |
| `tools_modified` | array | Details of tools that were modified |
| `change_types` | array | Types of changes detected |

**Benefits of Change Detection:**
- **Efficiency**: Skip scans when tools haven't changed
- **Monitoring**: Track tool evolution over time
- **Alerting**: Get notified only when changes occur
- **Debugging**: Understand what changed between scans

**Error Response (400):**
```json
{
  "success": false,
  "error": "URL is required",
  "timestamp": "2024-01-01T12:00:00.000Z"
}
```

### 5. Configuration Validation
**POST /v1/ramparts/validate**

Validate scan configuration without performing actual scan.

**Request Body:**
```json
{
  "url": "https://api.githubcopilot.com/mcp/",
  "timeout": 60,
  "http_timeout": 30,
  "detailed": false,
  "format": "json"
}
```

**Success Response (200):**
```json
{
  "success": true,
  "valid": true,
  "error": null,
  "timestamp": "2024-01-01T12:00:00.000Z"
}
```

**Validation Error Response (400):**
```json
{
  "success": false,
  "valid": false,
  "error": "Timeout must be between 1 and 3600 seconds",
  "timestamp": "2024-01-01T12:00:00.000Z"
}
```

### 6. Batch Scan
**POST /v1/ramparts/batch-scan**

Scan multiple MCP servers with shared configuration.

**Request Body:**
```json
{
  "urls": [
    "https://api.example1.com/mcp/",
    "https://api.example2.com/mcp/",
    "stdio:///usr/local/bin/mcp-server"
  ],
  "options": {
    "url": "",
    "timeout": 180,
    "http_timeout": 30,
    "detailed": true,
    "format": "json",
    "auth_headers": {
      "Authorization": "Bearer shared-token"
    }
  }
}
```

**Javelin Integration:**
```bash
curl -X POST http://localhost:3000/v1/ramparts/batch-scan \
  -H "Content-Type: application/json" \
  -H "X-Javelin-Apikey: your-javelin-key" \
  -d '{
    "urls": ["https://api.githubcopilot.com/mcp/"],
    "options": {"detailed": true}
  }'
```

**Request Fields:**
- `urls` (required): Array of MCP server URLs or STDIO commands
- `options` (optional): Shared scan configuration. Note: the `url` field in options is ignored and overridden by each URL in the `urls` array

**Special Headers:**
- `X-Javelin-Apikey`: When included in request headers, automatically adds appropriate authentication for Javelin MCP servers

**Response (200):**
```json
{
  "success": true,
  "results": [
    {
      "success": true,
      "result": {
        "url": "https://api.example1.com/mcp/",
        "status": "Success",
        "timestamp": "2024-01-01T12:00:00.000Z",
        "response_time_ms": 1234,
        "server_info": { /* Server info object */ },
        "tools": [ /* Tools array */ ],
        "resources": [],
        "prompts": [],
        "security_scan_summary": { /* Security scan summary */ },
        "errors": []
      },
      "error": null,
      "timestamp": "2024-01-01T12:00:00.000Z"
    },
    {
      "success": true,
      "result": {
        "url": "https://api.example2.com/mcp/",
        "status": { "Failed": "Failed to initialize MCP session with any protocol version" },
        "timestamp": "2024-01-01T12:00:01.000Z", 
        "response_time_ms": 0,
        "server_info": null,
        "tools": [],
        "resources": [],
        "prompts": [],
        "security_scan_summary": null,
        "errors": ["Scan operation failed: Failed to initialize MCP session with any protocol version"]
      },
      "error": null,
      "timestamp": "2024-01-01T12:00:01.000Z"
    }
  ],
  "total": 3,
  "successful": 2,
  "failed": 1,
  "timestamp": "2024-01-01T12:00:02.000Z"
}
```

## Using the API

### Example: Basic Health Check
```bash
curl -X GET http://localhost:3000/v1/ramparts/health
```

### Example: Single Server Scan
```bash
curl -X POST http://localhost:3000/v1/ramparts/scan \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://api.githubcopilot.com/mcp/",
    "timeout": 60,
    "detailed": true,
    "format": "json",
    "auth_headers": {
      "Authorization": "Bearer your-token"
    }
  }'
```

### 7. Refresh Tools
**POST /v1/ramparts/refresh-tools**

Refresh tool descriptions from one or more MCP servers. This endpoint fetches the latest tool definitions from the specified servers and updates the internal cache.

**Request Body:**
```json
{
  "urls": [
    "https://api.githubcopilot.com/mcp/",
    "https://api.openai.com/mcp/"
  ],
  "auth_headers": {
    "Authorization": "Bearer your-token"
  },
  "timeout": 60
}
```

**Request Fields:**
- `urls` (required): Array of MCP server URLs to refresh tools from
- `auth_headers` (optional): Authentication headers for the MCP servers
- `timeout` (optional): Timeout in seconds for each server connection (default: 30)

**Success Response (200):**
```json
{
  "success": true,
  "results": [
    {
      "url": "https://api.githubcopilot.com/mcp/",
      "success": true,
      "tools_count": 5,
      "tools": [
        {
          "name": "create_file",
          "description": "Create a new file",
          "input_schema": {
            "type": "object",
            "properties": {
              "path": { "type": "string" },
              "content": { "type": "string" }
            }
          }
        }
      ],
      "error": null
    }
  ],
  "total": 1,
  "successful": 1,
  "failed": 0,
  "timestamp": "2024-01-01T12:00:00.000Z"
}
```

**Error Response (400):**
```json
{
  "success": false,
  "error": "At least one URL must be provided",
  "timestamp": "2024-01-01T12:00:00.000Z"
}
```

**Javelin Integration:**
```bash
curl -X POST http://localhost:3000/v1/ramparts/refresh-tools \
  -H "Content-Type: application/json" \
  -H "X-Javelin-Apikey: your-javelin-key" \
  -d '{
    "urls": ["https://api.githubcopilot.com/mcp/"],
    "timeout": 60
  }'
```

### Example: STDIO Server Scan
```bash
curl -X POST http://localhost:3000/v1/ramparts/scan \
  -H "Content-Type: application/json" \
  -d '{
    "url": "stdio:///usr/local/bin/my-mcp-server",
    "timeout": 120,
    "detailed": true
  }'
```

### Example: Batch Scan
```bash
curl -X POST http://localhost:3000/v1/ramparts/batch-scan \
  -H "Content-Type: application/json" \
  -d '{
    "urls": [
          "https://api.githubcopilot.com/mcp/",
    "https://api.openai.com/mcp/"
    ],
    "options": {
      "url": "",
      "timeout": 60,
      "detailed": false,
      "format": "json"
    }
  }'
```

### Example: Configuration Validation
```bash
curl -X POST http://localhost:3000/v1/ramparts/validate \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://api.githubcopilot.com/mcp/",
    "timeout": 60,
    "http_timeout": 30
  }'
```

## Error Handling

The API uses standard HTTP status codes and provides detailed error messages:

### Common Error Responses

**400 Bad Request - Invalid URL:**
```json
{
  "success": false,
  "error": "URL is required",
  "timestamp": "2024-01-01T12:00:00.000Z"
}
```

**400 Bad Request - Empty URLs Array (Batch Scan):**
```json
{
  "success": false,
  "error": "URLs array is required",  
  "timestamp": "2024-01-01T12:00:00.000Z"
}
```

**400 Bad Request - Invalid Timeout:**
```json
{
  "success": false,
  "error": "Timeout must be between 1 and 3600 seconds",
  "timestamp": "2024-01-01T12:00:00.000Z"
}
```

**400 Bad Request - Unsupported Protocol:**
```json
{
  "success": false,
  "error": "HTTP URL must start with http:// or https://",
  "timestamp": "2024-01-01T12:00:00.000Z"
}
```

**400 Bad Request - Scan Failed:**
```json
{
  "success": false,
  "error": "Connection timeout after 30 seconds",
  "timestamp": "2024-01-01T12:00:00.000Z"
}
```

**500 Internal Server Error:**
```json
{
  "success": false,
  "error": "Internal server error occurred",
  "timestamp": "2024-01-01T12:00:00.000Z"
}
```

### CORS Support

- **Loopback bind** (the default): no CORS headers, so web pages can't call a scanner running on your machine.
- **Exposed bind** (`--host 0.0.0.0`): any origin is allowed, so browser clients work out of the box; use `RAMPARTS_API_TOKEN` for access control.
- **`RAMPARTS_CORS_ORIGINS`** (comma-separated, or `*`) restricts allowed origins on any bind.

Allowed methods are `GET, POST, OPTIONS`; any request header is allowed.

Invalid entries are ignored with a warning in the server log.

### Request Validation

All endpoints validate input parameters:
- **URL validation**: Checks for proper format and supported protocols
- **Timeout validation**: Ensures values are within acceptable ranges (1-3600 seconds)
- **JSON validation**: Validates request body structure and required fields
- **Auth headers**: Validates header format when provided