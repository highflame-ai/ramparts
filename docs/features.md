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

The cool thing is you can tune the scanning based on what you care about. If you only care about tool definitions in CI, scope the scan with `--only tools`. Working in a regulated environment? Create custom YARA rules for your specific compliance requirements (drop them in the `rules/` directory).

```bash
# Only scan tool definitions, skip prompts and resources
ramparts scan https://your-mcp-server.com --only tools

# Bound the scan and per-request timeouts from the CLI
ramparts scan https://your-mcp-server.com --timeout 90 --http-timeout 30
```

### OWASP MCP Top 10 Mapping

Every finding ramparts emits is tagged with one or more entries from the
**OWASP MCP Top 10** (2025 draft) so you can group results by category and
report against a recognized framework. Tags appear in:

- the terminal output (`OWASP MCP Top 10: MCP05, MCP06`)
- the JSON output (`owasp_tags` field on every finding)
- the SARIF output (`properties.tags` on every result and rule)
- the markdown report (grouped by category)

The taxonomy is pinned to a versioned YAML file
(`taxonomies/owasp-mcp-top-10/2025.yaml`) so future revisions are explicit
upgrades rather than silent churn.

### Supply-Chain Dependency Check

When a stdio MCP server is launched via `npx` or `uvx`, ramparts extracts
the package name + version from the launch command and queries
[OSV.dev](https://osv.dev) for known security advisories on that release.
Findings emit as `VulnerableDependency` entries (mapped to OWASP **MCP10
Supply Chain**), surface in every output format, and run in parallel with
the main scan so they don't slow you down. Real-world example — a scan of
`stdio:npx:lodash@4.17.20` surfaces 5+ known CVEs (ReDoS, command
injection, prototype pollution, code injection) directly in the report.

The check fails soft: a network error, OSV outage, or unrecognized launch
command logs a warning and is treated as "no findings" rather than a fatal
scan error.

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

### SARIF for Code Scanning

For teams that want findings to land in GitHub Advanced Security's code
scanning UI (or GitLab / Azure DevOps / Microsoft Defender), `--format
sarif` emits SARIF 2.1.0 directly:

```bash
ramparts scan-config --format sarif > ramparts.sarif
# Then in CI:
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ramparts.sarif
```

Each finding includes its OWASP MCP Top 10 ID as a SARIF tag and a
numeric `security-severity` (0–10) so the right severity badge renders.

### Skill Scanning

Ramparts also scans **agent skills** — markdown files containing prompt
instructions that an agent loads and executes by name (Claude Code's
`.claude/commands/*.md`, Cursor agent skills, etc.). Same threat model
as MCP prompts (untrusted instructions an agent may follow), so the
existing security pipeline applies directly:

```bash
# Scan a directory of skills
ramparts skills scan ./.claude/commands

# Discover and scan from well-known locations (~/.claude/commands etc.)
ramparts skills scan-config

# SARIF output for code-scanning ingestion
ramparts skills scan ./.claude/commands --format sarif > skills.sarif
```

The parser handles YAML frontmatter (`description`, `argument-hint`,
`name`, `allowed-tools` in both inline-string and YAML-list shapes)
plus a markdown body, treats each skill as an MCP prompt, and runs
LLM analysis + YARA + OWASP tagging over it. On top of that, it
emits structural findings the regex/LLM pipeline can't see:

- `OverbroadAllowedTools` — bare `Bash`, `Bash(*)`, `Bash(*:*)`, etc.
- `DataExfiltrationGrant` — `WebFetch` / `WebSearch` / `Fetch` /
  `Browse` grants that let the skill talk to the network
- `VagueSkillTrigger` — substantive body with a missing or one-word
  `description` (easy to mis-invoke)
- `SkillSensitiveFileReference` — Claude Code `@<path>` references
  pointing at SSH/AWS/GnuPG/kube/docker credentials, `.env`,
  `.netrc`, certificates, etc.

`scan-config` walks `~/<dotdir>/{commands,skills}` and the same paths
under the current workspace for every supported ecosystem (Claude
Code, Cursor, Codex, Windsurf, Gemini, OpenAI). Add extra roots
without rebuilding via `RAMPARTS_SKILL_ROOTS=path1,path2,...`. The
output flows through the same renderers you use for MCP server scans,
so SARIF / JSON / terminal output works identically.

📖 **[CLI reference](cli.md#skills-command)** for the full flag list and
supported skill formats.

### Replay Mode

Scan once, render many times. The `replay` subcommand reads a previously
emitted JSON scan result and re-emits it in any other format — no live
network or LLM calls. Handy when you want to:

- archive a scan as JSON in CI and convert to SARIF later as a separate
  step (so the SARIF upload doesn't block on a slow scan)
- view an archived multi-server scan-config result locally as a tree
- pipe an existing scan into a different consumer without rescanning

```bash
ramparts scan-config --format json > scan.json
ramparts replay scan.json --format sarif > scan.sarif
```



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