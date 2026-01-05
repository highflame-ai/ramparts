# Ramparts Features

If you're working with MCP servers, you probably want to know they're secure before connecting your AI agents to them. Ramparts gives you comprehensive security scanning that's designed for developers who need practical, actionable results.

## Security Scanning

### Complete MCP Analysis

When you run a scan, Ramparts hits all the MCP endpoints to get a complete picture of what the server can do. It's not just checking if the server responds—it's actually analyzing every tool, resource, and prompt to understand the full attack surface.

Think of it like a security audit that actually reads the documentation. Ramparts will find tools that aren't obvious from the server description, validate that everything follows the MCP protocol correctly, and map out how different tools might interact with each other. This is especially useful when you're evaluating third-party servers or want to make sure your own implementation doesn't have any surprises.

If you're working on a team, the detailed analysis becomes your documentation. Instead of manually cataloging what each MCP server can do, Ramparts gives you a complete inventory that you can share with colleagues or reference later.

### Security Vulnerability Detection

Ramparts looks for 11+ different types of security issues, from the obvious (like path traversal attacks) to the subtle (like tool poisoning where the tool description doesn't match what it actually does).

Here's what it catches: **Tool Poisoning** when tools lie about what they do, **Path Traversal** attacks like `../../../etc/passwd`, **Command Injection** where user input could execute system commands, **SQL Injection** vulnerabilities, **Cross-Origin Escalation** when tools span multiple domains unsafely, **Secret Leakage** of API keys and tokens, **Authentication Bypass** issues, **Prompt Injection** that could fool AI safety measures, **PII Leakage**, **Privilege Escalation**, and **Data Exfiltration** risks.

The cool thing is you can tune the scanning based on what you care about. If you only want to know about critical issues, just add `--min-severity HIGH` to your scan. Working in a regulated environment? Create custom rules for your specific compliance requirements.

```bash
# Only show me the serious stuff
ramparts scan https://your-mcp-server.com --min-severity HIGH

# Use our company's custom security rules
ramparts scan https://your-mcp-server.com --config custom-rules.yaml
```

### Advanced Pattern Detection (YARA-X)

Under the hood, Ramparts uses YARA-X rules to catch security patterns that static analysis might miss. We ship with rules for common vulnerabilities, MCP-specific attack vectors, and secret detection (AWS keys, GitHub tokens, etc.).

**Rich Security Context**: Each YARA rule includes comprehensive metadata to help you understand and prioritize security findings:

- **Severity Levels**: CRITICAL, HIGH, MEDIUM, LOW based on the security impact
- **Rule Details**: Name, author, version, and detailed descriptions
- **Categorization**: Tags like `secrets`, `path-traversal`, `command-injection` for filtering
- **Context Messages**: Human-readable explanations of what was detected

```json
{
  "rule_metadata": {
    "name": "Environment Variable Leakage",
    "author": "Ramparts Security Team",
    "version": "1.0", 
    "description": "Detects exposure of sensitive environment variables and API keys",
    "severity": "HIGH",
    "category": "environment,secrets,api-keys,credentials"
  },
  "status": "warning"
}
```

But here's where it gets interesting for your specific environment—you can write custom rules for your organization's unique security requirements. Maybe you have internal APIs that should never be exposed, or specific secret formats that need detection. Just drop your `.yar` files in the `rules/` directory and Ramparts will pick them up automatically.

The best part? Rules hot-reload, so you can iterate on your security policies without restarting anything. It's all pure Rust under the hood, so there are no system dependencies to manage.

## Developer Interfaces

### Command Line Interface

The CLI is probably how you'll start with Ramparts. `ramparts scan` for individual servers, `ramparts scan-config` to automatically find and scan MCP servers configured in your IDE (works with Cursor, VS Code, Windsurf, Claude Code), and `ramparts server` when you want to run it as a service.

You get flexible output formats depending on what you're doing—the default table format is great for humans, JSON is perfect for scripts and automation, and raw mode gives you the unprocessed MCP responses for debugging.

📖 **[Complete CLI Reference](cli.md)** has all the commands and options when you're ready to dig deeper.

### REST API Server

When you need Ramparts integrated into your existing systems, server mode transforms the CLI into a REST API. You get 6 endpoints covering everything from health checks to batch scanning, all with consistent JSON request/response formats.

The server handles concurrent requests, so your team can run multiple scans simultaneously. CORS support means you can call it from web applications, and the error handling is comprehensive enough that you can build reliable automation around it.

📚 **[Complete API Documentation](api.md)** covers all the endpoints with examples and integration patterns.

### Advanced Transport Support with Intelligent Fallback

Ramparts supports multiple MCP transport methods with intelligent fallback strategies to ensure maximum compatibility:

**Transport Methods:**
- **Simple HTTP**: Custom implementation optimized for most MCP servers
- **rmcp Streamable HTTP**: Standards-compliant streaming HTTP transport
- **rmcp SSE**: Server-Sent Events for real-time communication
- **STDIO/Subprocess**: Local executable communication

**Smart Connection Strategy:**
Ramparts automatically tries multiple transport methods and selects the most reliable one. For HTTP servers, it tests simple HTTP first, then falls back to rmcp streamable HTTP and SSE if needed. Each transport is validated with actual API calls to ensure full functionality before being selected.

**Session Management:**
For stateful MCP servers (like GitHub Copilot), Ramparts automatically handles session management:
- Extracts `mcp-session-id` from server responses
- Maintains session state across multiple API calls
- Ensures authentication headers are properly propagated
- Validates session functionality before proceeding

**Examples:**
```bash
# HTTP servers with automatic transport selection
ramparts scan https://api.githubcopilot.com/mcp/ --auth-headers "Authorization: Bearer $TOKEN"

# STDIO servers with multiple format support
ramparts scan "stdio:npx:mcp-server-commands"
ramparts scan "stdio:///usr/local/bin/python3:/path/to/server.py"
```

**STDIO servers get the same comprehensive security scanning as HTTP servers** - including YARA rule analysis, vulnerability detection, and detailed reporting. The `scan-config` command automatically detects and clearly labels STDIO vs HTTP servers from your IDE configurations.

## Output & Integration

### Flexible Output Formats

The default table format gives you a nice tree view of security issues with color coding for severity levels and inline details formatting for better readability.

When you need to integrate with other tools, JSON format provides structured data that's easy to parse and filter.

For debugging MCP protocol issues, raw format shows you exactly what the server responded with, which is invaluable when you're trying to figure out why something isn't working as expected.

The JSON structure is designed to be jq-friendly, so you can easily extract issue counts, filter by severity, or pull out specific findings for reporting.



### IDE Integration

If you're using modern AI-powered editors, Ramparts can automatically discover your MCP configurations. It knows where Cursor, Windsurf, VS Code, Claude Desktop, and Claude Code store their MCP settings, so `ramparts scan-config` just works without any setup.

This is probably the fastest way to get value from Ramparts—just run `ramparts scan-config` and see if any of your existing MCP integrations have security issues.

## Configuration & Customization

Ramparts uses YAML configuration files, but you can override any setting with environment variables if that fits your deployment better. The configuration hierarchy is designed to work well in different environments—development, staging, production—without duplicating settings.

You can customize security rules, tune performance settings, integrate with your preferred LLM provider, and set up YARA rules for your specific environment. The configuration is hierarchical, so you can have global defaults and environment-specific overrides.

⚙️ **[Complete Configuration Reference](configuration.md)** walks through all the options and patterns.

## CI/CD Integration

Ramparts is built to fit into modern development workflows. The CLI exits with appropriate status codes, the JSON output is designed for automation, and the server mode scales to handle CI/CD loads.

Whether you're using GitHub Actions, GitLab CI, Jenkins, or something else, the integration patterns are straightforward. Most teams start with CLI integration for quick wins, then move to server mode as their usage scales up.

🔧 **[Complete Integration Guide](integration.md)** has examples for all the major CI/CD platforms, plus Docker and Kubernetes deployment patterns.

## Performance & Scalability

### Batch Operations

When you need to scan multiple servers, batch mode handles the coordination for you. You can scan from a file list with the CLI, or send multiple URLs to the API's batch endpoint. Either way, Ramparts processes them concurrently and gives you aggregated results.

This is especially useful for teams managing lots of MCP servers—you can scan everything in one operation and get a unified view of your security posture.

### Performance Tuning

If you're hitting API rate limits or want to optimize for your specific environment, there are configuration options for concurrent processing, batch sizes, timeouts, and retry behavior.

```yaml
scanner:
  parallel: true              # Process multiple items concurrently
  llm_batch_size: 10         # How many tools to analyze together
  max_retries: 3             # Retry failed requests
  http_timeout: 30           # HTTP request timeout
```



For environments with strict rate limits, you can dial down the concurrency and add delays between requests. For fast internal networks, you can crank up the parallelism for faster scanning.

## Getting Help

If you run into connection issues, try increasing timeouts with `--timeout 60`. Authentication problems usually mean checking your header format with something like `curl -H "Authorization: Bearer $TOKEN"`. When things get weird, `RUST_LOG=debug ramparts scan <url>` shows you exactly what's happening under the hood.

🔍 **[Complete Troubleshooting Guide](troubleshooting.md)** has detailed solutions for common problems.

**Community Resources:**
- [GitHub Issues](https://github.com/highflame-ai/ramparts/issues) for bug reports and feature requests
- [Documentation](docs/) for comprehensive guides and references

The docs are designed to be practical—they focus on what you're trying to accomplish rather than just listing options. If something isn't clear or you think we're missing a use case, open an issue and let us know.