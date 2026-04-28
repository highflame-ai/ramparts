# Ramparts v0.8.0 Release Notes

This release shifts ramparts from "MCP scanner that produces text output" to "MCP scanner that fits cleanly into modern security tooling pipelines". The big themes:

- **CI/CD-native output** via SARIF 2.1.0 with OWASP MCP Top 10 tagging
- **Supply-chain coverage** via OSV.dev for stdio-launched MCP servers
- **Reliable startup** on minimal Linux/EC2 hosts (no more "No CA certificates were loaded")
- **Modern transport stack** via the rmcp 1.x SDK (ramparts was on 0.3 before this release)
- **A pile of CLI ergonomics fixes** that came out of dogfooding the migration

> **No code-level breaking changes.** Existing CLI invocations continue to work; existing JSON output adds new optional fields but doesn't remove any. The one user-visible behavior change is that the welcome banner is now suppressed for `--format json | raw | sarif` (so downstream parsers see clean stdout).

## ✨ New Features

### SARIF 2.1.0 output (#96)

```bash
ramparts scan-config --format sarif > ramparts.sarif
# Then in CI:
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ramparts.sarif
```

Each finding includes:

- `ruleId` — YARA rule name (e.g. `CrossDomainContamination`) or `ramparts.security.<IssueType>` for LLM-detected findings
- `level` — `error` (CRITICAL/HIGH), `warning` (MEDIUM), `note` (LOW)
- `properties.security-severity` — numeric 0–10 score so GitHub renders the right severity badge
- `properties.tags` — OWASP MCP Top 10 IDs (e.g. `owasp-mcp-top-10:2025-draft:MCP05`)

Each scanned server becomes its own `runs[]` entry; rules referenced by that run are deduped into `tool.driver.rules[]`. Suitable for GitHub Advanced Security code-scanning, GitLab, Azure DevOps, Microsoft Defender, and most enterprise security dashboards.

### OWASP MCP Top 10 taxonomy mapping (#101)

Every finding ramparts emits is now tagged with one or more entries from the OWASP MCP Top 10 (2025 draft). Tags appear in:

- terminal output (`OWASP MCP Top 10: MCP05, MCP06`)
- JSON output (`owasp_tags` field on every `SecurityIssue` and `YaraScanResult`)
- SARIF output (`properties.tags` on every `result` and `rule`)

The taxonomy is pinned to a versioned YAML file (`taxonomies/owasp-mcp-top-10/2025.yaml`) — when the official list publishes a new revision, it lands as a new file rather than mutating the existing one.

| ID | Category | Example findings |
|---|---|---|
| MCP01 | Prompt Injection | `PromptInjection`, `Jailbreak` |
| MCP02 | Tool Poisoning | `ToolPoisoning`, `MCPConfigChanged` |
| MCP03 | Excessive Agency | `Jailbreak` |
| MCP04 | Insecure Tool Output Handling | `PathTraversalVulnerability` |
| MCP05 | Cross-Origin Tool Confusion | `CrossDomainContamination`, `DomainOutlier`, `MixedSecuritySchemes` |
| MCP06 | Credential and Secret Leakage | `SecretsLeakage`, `EnvironmentVariableLeakage`, `SSHKeyExposure`, `PEMFileAccess` |
| MCP07 | Command and SQL Injection | `CommandInjection`, `SQLInjection`, `MCPConfigRisk` |
| MCP08 | Authentication & Authorization Bypass | `AuthBypass` |
| MCP09 | Sensitive Data Exposure | `PIILeakage`, secret findings |
| MCP10 | Supply Chain | `MCPConfigRisk`, `VulnerableDependency` |

### Supply-chain dependency scan via OSV.dev (#104)

When a stdio MCP server is launched via `npx` (npm) or `uvx` (PyPI), ramparts now extracts the package name + version from the launch command and queries [OSV.dev](https://osv.dev) for known security advisories. Findings emit as `VulnerableDependency` entries, mapped to OWASP **MCP10 Supply Chain**.

Verified end-to-end — `ramparts scan stdio:npx:lodash@4.17.20` surfaces 5+ real CVEs (ReDoS, command injection, prototype pollution, code injection) directly in the report.

The check runs in parallel with the main scan and fails soft — network errors / OSV outages are logged and treated as "no findings", never as a fatal scan error.

### `--root <PATH>` for scan-config (closes #51)

Walk an arbitrary directory (e.g. a checked-in repo of IDE configs) for `mcp.json` / `*.mcp.json` / `claude_desktop_config.json` / `settings.json` files instead of the user's home + IDE locations:

```bash
ramparts scan-config --root ./ide-configs --format sarif > ramparts.sarif
```

Recursive; symlinks are not followed; common build directories (`.git`, `node_modules`, `target`, `dist`, `build`, `.venv`, `venv`, `__pycache__`) are skipped; depth capped at 16.

### `replay` subcommand (#104)

Read a previously-emitted JSON scan result and re-emit it through any other format — no live network or LLM calls. The headline use case is "archive a JSON scan in CI and convert to SARIF later as a separate step":

```bash
ramparts scan-config --format json > scan.json
ramparts replay scan.json --format sarif > scan.sarif
```

Auto-detects single-server (`ScanResult`) vs multi-server (`Vec<ScanResult>`) shapes.

### `--only <KINDS>` filter (#104)

Restrict a scan to a subset of artifact kinds. Useful for CI gates that only care about one surface:

```bash
ramparts scan https://api.example.com/mcp/ --only tools
ramparts scan-config --only tools,prompts
```

Comma-separated; accepts `tools`, `prompts`, `resources` (singular forms also accepted). Unrecognized tokens fail with a clean error rather than silently scanning everything.

### `--timeout` / `--http-timeout` CLI flags (#103)

Bound a one-off scan from the CLI without editing `~/.config/ramparts/config.yaml`:

```bash
ramparts scan https://api.example.com/mcp/ --timeout 90 --http-timeout 30
```

`--timeout` is the overall scan budget (also applies to the stdio path now — a hung subprocess is killed at the timeout instead of hanging the CLI forever); `--http-timeout` bounds individual HTTP requests.

## 🛠️ Reliability fixes

### Bundled Mozilla CA list (#105)

reqwest 0.13's `rustls-platform-verifier` returns zero roots on hosts where the system CA bundle isn't populated — fresh EC2 ubuntu/debian AMIs, distroless containers, Debian slim without `ca-certificates`. Symptom: `Failed to create HTTP client: builder error: No CA certificates were loaded from the system`, ramparts fails before any HTTPS request.

ramparts now ships [Mozilla's CA list](https://github.com/rustls/webpki-roots) embedded in the binary and hands reqwest a preconfigured rustls `ClientConfig` whose trust store is that bundle. The config is built once via `LazyLock` and shared via `Arc` across every reqwest builder. There's no dependency on the host trust store anymore.

### Process-wide CryptoProvider install (#103)

rustls 0.23 requires a process-wide `CryptoProvider` before any HTTPS client is built. We now install `aws_lc_rs` explicitly at the top of `main()` (ignoring the `Err` returned when something else has already installed one) so startup is deterministic across environments.

### Improved error chain reporting (#103)

Failures from `reqwest::Client::builder().build()` used to surface as the bare string `"builder error"`. We now walk the `std::error::Error` source chain and join causes so the actual diagnosis (e.g. "No CA certificates were loaded from the system") is visible.

### `response_time_ms` always reported `0ms` (#103)

Internal timer was constructed *after* the scan rather than at entry, so the reported response time was always near zero. Fixed for both success and failure paths — failed scans (timeout, connection refused, etc.) now report their actual elapsed time instead of `0ms`.

### Spinner spam in non-TTY output (#103)

The "Scanning for security vulnerabilities..." spinner ran unconditionally, drowning machine-readable stdout with hundreds of frames per scan in CI logs and `--format json` pipelines. Now gated on `std::io::stdout().is_terminal()`.

### stdio URL display preserved (#103)

`ramparts scan stdio:npx:-y:@modelcontextprotocol/server-everything` previously rendered as `URL: stdio:npx[STDIO-npx]` because of a synthetic placeholder. The result now preserves the user's exact input string.

### `--http-timeout` plumbed to McpClient (#103)

The flag was getting into `ScanOptions` but the underlying `McpClient` was hardcoding a 30-second timeout. Now `MCPScanner::with_timeout` constructs the inner `McpClient::with_http_timeout(...)` so the flag actually bounds individual reqwest calls.

### stdio scan now respects `--timeout` (#103)

`scan_stdio_server` previously ran without a `tokio::time::timeout` wrap, so a hung subprocess could pin the CLI forever regardless of the configured timeout. The connect + scan pipeline is now wrapped, mirroring the HTTP path.

### VS Code parser silently produced empty configs (closes #85, #103)

A `.vscode/mcp.json` containing a Claude-Desktop-style `{"mcpServers": ...}` document parsed cleanly as a valid-but-empty `VSCodeMCPConfig`, so `scan-config` reported `0 servers` and dropped the file. The fix introduces `config_has_servers` and gates every "I parsed it, return" branch on a non-empty result; the first parser that yields servers wins.

## 🔧 Internal / dependency changes

### rmcp 0.3.2 → 1.5 migration (#102)

Major-version bump of the official Rust MCP SDK. Internal-only behavior changes:

- SSE is no longer a separate transport. `mcp-sse` CLI command is preserved and now delegates to the streamable HTTP server (rmcp 1.x folds SSE into HTTP for both client and server directions).
- `Parameters` import moved from `handler::server::tool` to `handler::server::wrapper`.
- `ServerInfo` switched to the `::new(...).with_instructions(...)` builder per the upstream migration guide.

### reqwest 0.12 → 0.13 (#102)

Required by rmcp 1.5 — having two reqwest versions in the dep tree broke the `StreamableHttpClient` trait impl. The TLS feature was renamed `rustls-tls` → `rustls`.

### yara-x 1.5 → 1.15.0 + transitive bumps (#102)

Cleared RUSTSEC-2026-0097 (rand unsoundness) and the older yara-x advisory chain. Pinned yara-x to a post-1.15.0 commit that ships wasmtime 43.0.1 to clear CVE-2026-34971 / CVE-2026-34987 (both critical) plus 12 lower-severity wasmtime advisories.

### Clippy / formatting hygiene (#102, #103)

- 4 `clippy::collapsible_match` errors fixed under clippy 1.95.0
- `severity_score` emitted as a JSON number in SARIF (was string)

## 🐛 Other bug fixes

- Failed scans now record their elapsed time (was leaking `0ms` for both stdio and HTTP) (#103)
- Single-source timing for stdio scans — no more double-counting between `scan_single` and `scan_stdio_server` (#103)
- `MCPScanner::Clone` now preserves the underlying `mcp_client` (with its session cache and configured timeout) instead of constructing a fresh default-timeout one (#103)

## 📚 Documentation

- `cli.md` — replaced the stale flag list (`--output`, `--detailed`, `--min-severity`, `--pretty` — none existed in the actual CLI) with the real flags, documented the new `--timeout` / `--http-timeout` / `--root` / `--only` / `--format sarif` / `replay` / `mcp-stdio|http|sse` surface, added a SARIF + GitHub Code Scanning integration example.
- `features.md` — added subsections covering OWASP MCP Top 10 mapping, OSV.dev supply-chain check, SARIF, and replay mode.
- `security-features.md` — added a "Vulnerable Dependencies (Supply Chain)" section under the threat catalog and a full OWASP MCP Top 10 mapping table.
- `troubleshooting.md` — replaced the generic SSL advice with the specific "No CA certificates were loaded" error and noted that the bundled Mozilla CA list makes the host trust store no longer load-bearing.

## 🚀 Migration guide

For most users, no action is required:

- All existing CLI invocations continue to work.
- All existing config-file fields are still honored.
- All existing JSON output fields are still present; new fields (`owasp_tags`, `VulnerableDependency` results) are additive.
- The one visible change: scripts that piped `--format json` / `--format raw` while expecting the welcome banner on stdout will now get only the JSON. (The banner went to stderr in some places before this; it's now consistently suppressed for machine-readable formats.)

For CI/CD integrators, the new high-leverage moves are:

- Switch `--format json` artifacts to `--format sarif` and upload via `github/codeql-action/upload-sarif@v3`.
- Use `replay` to convert archived JSON scans to SARIF as a separate step (decoupled from the actual scan).
- Use `--root <PATH>` to scan a checked-in repo of IDE configs.

For ramparts library / SDK consumers (Rust):

- `SecurityIssue` and `YaraScanResult` gained an `owasp_tags: Vec<OwaspTag>` field. It's `#[serde(default, skip_serializing_if = "Vec::is_empty")]` so old JSON deserializes fine.
- `ScanOptions` gained `only: Option<Vec<ArtifactKind>>`.

## 🎯 What's next

Tracked as open issues:

- `.ramparts.lock` tool-pinning lockfile (#97) — detect MCP tool drift via SHA-256 hash pinning
- Toxic-flow analysis (#98) — detect dangerous capability pairings across MCP servers
- YAML custom rule format (#99) — higher-level alternative to YARA for org-specific rules
- Auto-fix with backup/undo (#100) — opt-in remediation for IDE config findings

---

**Full Changelog**: https://github.com/highflame-ai/ramparts/compare/v0.7.0...v0.8.0
