# CLI Reference

This document provides detailed information about all Ramparts command-line interface options and commands.

## Basic Commands

```bash
# Scan an MCP server
ramparts scan <url> [options]

# Start Ramparts server mode
ramparts server [options]

# Scan from IDE configuration files
ramparts scan-config [options]

# Scan AI agent skills (Claude Code commands, etc.)
ramparts skills scan <path>      [options]
ramparts skills scan-config      [options]

# Re-emit a previously-saved scan result in another format
ramparts replay <path> [--format <FORMAT>]

# Initialize configuration file
ramparts init-config

# Run Ramparts itself as an MCP server
ramparts mcp-stdio
ramparts mcp-http  [--host HOST] [--port PORT]
ramparts mcp-sse   [--host HOST] [--port PORT]   # alias of mcp-http (rmcp 1.x folds SSE into streamable HTTP)

# Show help
ramparts --help
ramparts scan --help
ramparts skills --help
```

## Global Options

These options are available for all commands:

```bash
Options:
  -v, --verbose                   Enable verbose output
      --debug                     Enable debug logging
  -h, --help                      Print help information
  -V, --version                   Print version information
```

## Scan Command

Scan a single MCP server for tools, resources, and security vulnerabilities.

### Usage
```bash
ramparts scan <URL> [OPTIONS]
```

### Arguments
- `<URL>` - MCP server URL or endpoint to scan

### Options

```bash
Options:
      --auth-headers <HEADERS>    Authentication headers (format: "Header: Value", comma-separated)
      --format <FORMAT>           Output format [default: from config.yaml; usually `table`]
                                  [possible values: text, table, json, raw, sarif]
      --report                    Generate detailed markdown report (scan_YYYYMMDD_HHMMSS.md)
      --timeout <SECONDS>         Overall scan timeout. Overrides scanner.scan_timeout.
      --http-timeout <SECONDS>    Per-HTTP-request timeout. Overrides scanner.http_timeout.
      --only <KINDS>              Restrict scan to a subset of artifact kinds. Comma-separated:
                                  tools, prompts, resources (singular forms also accepted).
                                  Default: scan all kinds.
  -h, --help                      Print help information
```

> **Note**: `--format sarif` produces SARIF 2.1.0 output suitable for GitHub Advanced
> Security code-scanning, GitLab, and other SARIF consumers. OWASP MCP Top 10 IDs are
> included as `properties.tags` on every result and rule definition.

### Examples

**Basic scan:**
```bash
ramparts scan https://api.githubcopilot.com/mcp/
```

**Scan with authentication:**
```bash
ramparts scan https://api.githubcopilot.com/mcp/ \
  --auth-headers "Authorization: Bearer $TOKEN"
```

**JSON output:**
```bash
ramparts scan https://api.githubcopilot.com/mcp/ --format json
```

**SARIF output for GitHub code scanning:**
```bash
ramparts scan https://api.githubcopilot.com/mcp/ --format sarif > ramparts.sarif
# Then upload via github/codeql-action/upload-sarif in CI
```

**Custom timeout:**
```bash
ramparts scan https://api.githubcopilot.com/mcp/ \
  --timeout 120 \
  --http-timeout 45
```

**Scan only tool definitions (skip prompts and resources):**
```bash
ramparts scan https://api.githubcopilot.com/mcp/ --only tools
```

**Generate detailed markdown report:**
```bash
ramparts scan https://api.githubcopilot.com/mcp/ --report
```

**STDIO server scan:**
```bash
# Format: stdio:<command>:<arg1>:<arg2>:...
ramparts scan "stdio:npx:-y:@modelcontextprotocol/server-everything"
ramparts scan "stdio:python3:/path/to/server.py"
ramparts scan "stdio:node:/path/to/server.js"
```

> **Supply-chain check**: when the stdio command is `npx` or `uvx`, ramparts
> automatically queries [OSV.dev](https://osv.dev) for known advisories on the
> launched package@version and emits any findings as `VulnerableDependency`
> entries (mapped to OWASP MCP10 Supply Chain). The lookup runs in parallel with
> the main scan and fails soft — network errors are logged and treated as "no
> findings", never as a fatal scan error.

## Scan-Config Command

Scan MCP servers from IDE configuration files.

### Usage
```bash
ramparts scan-config [OPTIONS]
```

### Options

```bash
Options:
      --auth-headers <HEADERS>    Authentication headers for MCP servers
      --format <FORMAT>           Output format [default: from config.yaml]
                                  [possible values: text, table, json, raw, sarif]
      --report                    Generate detailed markdown report (scan_YYYYMMDD_HHMMSS.md)
      --timeout <SECONDS>         Overall per-server scan timeout
      --http-timeout <SECONDS>    Per-HTTP-request timeout
      --root <PATH>               Walk this directory for MCP config files instead of the
                                  user's home/IDE locations. Useful for scanning a
                                  checked-in repo of IDE configs in CI.
      --only <KINDS>              Restrict scan to a subset of artifact kinds
                                  (tools, prompts, resources)
  -h, --help                      Print help information
```

### Examples

**Scan from IDE configs:**
```bash
ramparts scan-config
```

**With authentication:**
```bash
ramparts scan-config \
  --auth-headers "Authorization: Bearer $TOKEN" \
  --format json
```

**Generate report:**
```bash
ramparts scan-config --report
```

**Scan a checked-in repo of IDE configs (e.g. in CI):**
```bash
# `--root` walks the directory recursively, picks up `mcp.json`,
# `*.mcp.json`, `claude_desktop_config.json`, `settings.json`, etc.
# Skips `.git`, `node_modules`, `target`, `dist`, `build`, `.venv`,
# and similar build directories. Symlinks are not followed.
ramparts scan-config --root ./ide-configs --format sarif > ramparts.sarif
```

**Only tool definitions (skip prompts/resources):**
```bash
ramparts scan-config --only tools
```

### Supported IDE Configuration Files

Ramparts automatically discovers and reads MCP server configurations from:

- **Cursor**: `~/.cursor/mcp.json`
- **Windsurf**: `~/.codeium/windsurf/mcp_config.json`
- **VS Code**: `~/.vscode/mcp.json`, `~/Library/Application Support/Code/User/mcp.json`
- **Claude Desktop**: `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS)
- **Claude Code**: `~/.claude/settings.json`, `~/.claude/settings.local.json`
- **Gemini CLI**: `~/.gemini/settings.json`, `.gemini/settings.json` (workspace)
- **Neovim**: `~/.config/nvim/mcp.json`
- **Helix**: `~/.config/helix/mcp.json`
- **Zed**: `~/.config/zed/mcp.json`

If a file's content uses a different schema than the path suggests (e.g. a
Claude-Desktop-style `{"mcpServers": ...}` document saved at a VS Code path),
ramparts falls through to the multi-format parser chain rather than silently
treating it as empty. Files that contain no recognizable MCP server entries
appear in the discovery summary with `0 servers` and are skipped.

## Skills Command

Scan AI agent skills (Claude Code custom slash commands, Cursor skills,
markdown skill repos) for security issues. Skills are markdown files
containing prompt instructions an agent loads and executes by name —
sharing a threat model with MCP prompts (untrusted instructions an agent
may follow). Ramparts parses each skill's frontmatter and body, treats
it as an MCP prompt, and runs the same security pipeline (LLM analysis,
YARA pre/post scan, OWASP tagging, terminal/JSON/SARIF rendering) used
for live MCP servers. No network calls — pure static analysis on disk.

### Subcommands

```bash
ramparts skills scan <PATH>          [OPTIONS]
ramparts skills scan-config          [OPTIONS]
```

### `skills scan`

Scan a single skill file or every `*.md` skill under a directory.

**Arguments**
- `<PATH>` — path to a skill file or a directory containing skill files

**Options**
```bash
Options:
      --format <FORMAT>     Output format [default: from config.yaml]
                            [possible values: text, table, json, raw, sarif]
      --report              Generate detailed markdown report
      --timeout <SECONDS>   Overall scan timeout
  -h, --help                Print help information
```

**Examples**
```bash
# Single skill
ramparts skills scan ./.claude/commands/deploy.md

# Every *.md skill under a directory (recursive; symlinks not followed;
# common build dirs like .git, node_modules, target are skipped)
ramparts skills scan ./.claude/commands

# SARIF output for GitHub Code Scanning
ramparts skills scan ./.claude/commands --format sarif > skills.sarif
```

### `skills scan-config`

Discover and scan skills from well-known locations across supported
IDE/agent ecosystems. Both the per-user (`$HOME`) and per-workspace
(`$CWD`) variants of each ecosystem are walked:

- `.claude/commands/`, `.claude/skills/` — Claude Code
- `.cursor/commands/`, `.cursor/skills/` — Cursor
- `.codex/commands/`, `.codex/skills/` — OpenAI Codex
- `.windsurf/commands/` — Windsurf
- `.gemini/commands/` — Gemini
- `.openai/commands/` — generic OpenAI agent skills

Add extra roots without rebuilding via the `RAMPARTS_SKILL_ROOTS`
environment variable (comma-separated paths; leading `~/` is expanded
to `$HOME`):

```bash
export RAMPARTS_SKILL_ROOTS="~/work/agent-skills,/srv/shared-skills"
ramparts skills scan-config
```

**Options** (same as `scan`):
```bash
Options:
      --format <FORMAT>     Output format [default: from config.yaml]
      --report              Generate detailed markdown report
      --timeout <SECONDS>   Overall scan timeout
```

### Skill File Format

Skill files are markdown with optional YAML frontmatter:

```markdown
---
description: One-liner shown in the agent's command picker
argument-hint: <env>
---

# Body of the skill

The body is the prompt the agent executes when this skill is invoked.
Ramparts treats this body as untrusted instructions and runs prompt-
injection / sensitive-data-exposure / jailbreak checks over it.
```

The parser is permissive: missing or malformed frontmatter is treated as
"no frontmatter" and the body is still scanned. The filename stem becomes
the skill name unless the frontmatter sets `name`. Anything in
`argument-hint` becomes the prompt's argument metadata for downstream
tools.

### What Skills Get Tagged

Findings on skills propagate the same OWASP MCP Top 10 tags as live MCP
prompt findings. The most common categories that fire on malicious
skills are:

- **MCP01 — Prompt Injection**: hidden instructions, "ignore previous
  prompts" patterns, role-override attempts
- **MCP02 — Tool Poisoning**: skills whose body conflicts with their
  stated description
- **MCP03 — Excessive Agency**: skills that assert elevated privileges
- **MCP06 / MCP09**: secrets / PII / sensitive-data exposure

In addition to the YARA pre-scan and LLM analysis, the parser emits
structural findings the regex/LLM pipeline can't see:

- **OverbroadAllowedTools** (MCP03): an `allowed-tools` grant gives
  unrestricted code execution — bare `Bash`, `Bash(*)`, `Bash(*:*)`,
  bare `*`, `rm:*`, `sudo:*`, etc.
- **DataExfiltrationGrant** (MCP06 + MCP09): a `WebFetch` /
  `WebSearch` / `Fetch` / `Browse` grant — flagged informationally so
  the operator knows the skill talks to the network.
- **VagueSkillTrigger** (MCP02 + MCP03): a substantive skill body
  with a missing or one-word `description` — easy to mis-invoke.
- **GenericSkillTrigger** (MCP02 + MCP03): the description is a
  semantically vacuous trigger phrase (`"help"`, `"assistant"`,
  `"a general purpose tool"`, `"do anything"`, ...) that causes the
  agent's router to invoke the skill on unrelated requests —
  trigger-hijack vector.
- **SkillSensitiveFileReference** (MCP06 + MCP09): the body uses
  Claude Code's `@<path>` syntax to inline a sensitive file
  (SSH/AWS/GnuPG/kube/docker credentials, `.env`, `.netrc`,
  `.npmrc`, `.pypirc`, certificates) into the prompt context.
- **SkillNameCollision** (MCP02 + MCP03): two or more skill files
  declare the same `name` (case-insensitive). One shadows the other
  in the agent's router — an attacker who can write a workspace-
  level skill with the same name as a trusted user-level skill can
  silently replace it. Cross-skill check; runs once per scan.
- **SkillEmbeddedPayload** (MCP01 + MCP10): the body contains a
  500-character-or-longer base64-shape (or hex-shape) blob. Embedded
  payloads bypass plaintext YARA rules and LLM analysis by deferring
  decoding to runtime — the LLM sees `aW1wb3J0IG9z...` and shrugs.
  Markdown image data URIs (`data:image/...;base64,...`) are
  excluded.

Three skill-targeted YARA rules complement the structural heuristics
above by scanning the body content itself:

- **SkillCredentialHarvesting** (MCP06 + MCP09): vendor-specific token
  formats (`AKIA...`, `ghp_...`, `sk-ant-api...`, `sk-proj-...`,
  `AIzaSy...`, `xox[abprs]-...`), inline PEM private-key blocks, and
  active credential-theft verbs (`steal/grab/exfiltrate <credential>`).
- **SkillToolChainingExfiltration** (MCP06 + MCP09): credential-file
  read combined with network egress to known exfil destinations
  (Discord webhooks, Telegram bot API, pastebin, ngrok / requestbin /
  webhook.site tunnels) or attacker-named hosts.
- **SkillSystemManipulation** (MCP03 + MCP04): destructive operations
  and privilege escalation — `dd if=/dev/zero`, `wipefs`, `shred`,
  recursive deletion of system roots, `chmod 777 /`, `sudo -i`,
  `LD_PRELOAD=` hijack, PATH poisoning, writes to `/etc/sudoers`.

## Replay Command

Re-emit a previously-saved scan result through a different output format
without re-connecting to the MCP server. The headline use case is **archive
a JSON scan in CI, then convert it to SARIF** for GitHub code-scanning
ingestion as a separate step.

### Usage
```bash
ramparts replay <PATH> [--format <FORMAT>]
```

### Arguments
- `<PATH>` — Path to a JSON file containing a `ScanResult` (single-server,
  emitted by `ramparts scan`) or a `Vec<ScanResult>` (multi-server, emitted
  by `ramparts scan-config`). The renderer auto-detects which shape is
  present.

### Options
```bash
Options:
      --format <FORMAT>   Output format [default: from config.yaml]
                          [possible values: text, table, json, raw, sarif]
  -h, --help              Print help information
```

### Examples

```bash
# Capture once in CI, convert to SARIF later
ramparts scan https://api.example.com/mcp/ --format json > scan.json
ramparts replay scan.json --format sarif > scan.sarif

# View an archived multi-server scan-config result locally
ramparts scan-config --format json > all-servers.json
ramparts replay all-servers.json
```

`replay` does no network or LLM calls — it's a pure format conversion of
already-emitted findings.

## Server Command

Start the MCP Scanner microservice.

### Usage
```bash
ramparts server [OPTIONS]
```

### Options

```bash
Options:
  -p, --port <PORT>               Server port [default: 3000]
      --host <HOST>               Server host [default: 0.0.0.0]
      --config <FILE>             Configuration file path
  -h, --help                      Print help information
```

### Examples

**Default server:**
```bash
ramparts server
```

**Custom port and host:**
```bash
ramparts server --port 8080 --host 127.0.0.1
```

**With custom config:**
```bash
ramparts server --config /path/to/custom-config.yaml
```

## Init-Config Command

Create a custom configuration file with default settings.

### Usage
```bash
ramparts init-config [OPTIONS]
```

### Options

```bash
Options:
  -f, --force                     Overwrite existing configuration file
  -h, --help                      Print help information
```

### Examples

**Create default config:**
```bash
ramparts init-config
```

**Overwrite existing config:**
```bash
ramparts init-config --force
```

This creates a `ramparts.yaml` file in the current directory with all configuration options and their default values.

## Output Formats

For machine-readable formats (`json`, `raw`, `sarif`), the welcome banner is
suppressed automatically so downstream parsers (jq, `codeql-action/upload-sarif`,
etc.) get clean stdout.

### Table Format (Default)
Human-readable table format with colored output:
```bash
ramparts scan <url>
ramparts scan <url> --format table
```

### JSON Format
Machine-readable structured output:
```bash
ramparts scan <url> --format json
```

### Text Format
Simple text output:
```bash
ramparts scan <url> --format text
```

### Raw Format
Raw JSON preserving original MCP server responses with embedded security data:
```bash
ramparts scan <url> --format raw
```

### SARIF Format
SARIF 2.1.0 output for GitHub Advanced Security code-scanning, GitLab, Azure
DevOps, Microsoft Defender, and most enterprise security dashboards:

```bash
ramparts scan <url> --format sarif > ramparts.sarif
```

Each finding includes:
- `ruleId` — YARA rule name or `ramparts.security.<IssueType>`
- `level` — `error` (CRITICAL/HIGH), `warning` (MEDIUM), `note` (LOW)
- `properties.security-severity` — numeric 0–10 score so GitHub renders the
  right severity badge
- `properties.tags` — OWASP MCP Top 10 IDs (e.g. `owasp-mcp-top-10:2025-draft:MCP05`)

CI integration example with GitHub Code Scanning:
```yaml
- name: Run ramparts
  run: ramparts scan-config --format sarif > ramparts.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ramparts.sarif
```

## Environment Variables

Ramparts respects the following environment variables:

### Logging
```bash
RUST_LOG=debug ramparts scan <url>        # Debug logging
RUST_LOG=info ramparts scan <url>         # Info logging
RUST_LOG=warn ramparts scan <url>         # Warning logging only
RUST_LOG=error ramparts scan <url>        # Error logging only
```

### Configuration
```bash
RAMPARTS_CONFIG=/path/to/config.yaml ramparts scan <url>
```

### API Keys
You can use environment variables in auth headers:
```bash
ramparts scan <url> --auth-headers "Authorization: Bearer $TOKEN"
ramparts scan <url> --auth-headers "X-API-Key: $API_KEY"
```

## Exit Codes

Ramparts uses standard exit codes:

- `0` - Success
- `1` - General error
- `2` - Configuration error
- `3` - Network/connection error
- `4` - Authentication error
- `5` - Timeout error

## Advanced Usage

### Batch Scanning from File
```bash
# Create a file with URLs
echo "https://server1.com/mcp/
https://server2.com/mcp/
stdio:///usr/local/bin/mcp-server" > servers.txt

# Scan each URL
while IFS= read -r url; do
  ramparts scan "$url" --output json >> results.json
done < servers.txt
```

### Using with jq for Processing
```bash
# Extract security issue count
ramparts scan <url> --output json | jq '.security_issues.total_issues'

# Filter high severity issues
ramparts scan <url> --output json | \
  jq '.security_issues.tool_issues[] | select(.severity == "HIGH")'

# Get all tool names
ramparts scan <url> --output json | jq -r '.tools[].name'
```

### Combining with Other Tools
```bash
# Save scan results with timestamp
ramparts scan <url> --output json > "scan-$(date +%Y%m%d-%H%M%S).json"

# Send results to webhook
ramparts scan <url> --output json | \
  curl -X POST -H "Content-Type: application/json" \
       -d @- https://webhook.example.com/ramparts

# Check exit code and send alert
if ! ramparts scan <url> --min-severity high; then
  echo "High severity issues found!" | mail -s "Security Alert" admin@example.com
fi
```

## Configuration File Locations

Ramparts looks for configuration files in the following order:

1. `--config` command line argument
2. `RAMPARTS_CONFIG` environment variable
3. `./ramparts.yaml` (current directory)
4. `~/.config/ramparts/config.yaml`
5. `/etc/ramparts/config.yaml`

## Shell Completion

Generate shell completion scripts:

### Bash
```bash
ramparts --generate-completion bash > /etc/bash_completion.d/ramparts
```

### Zsh
```bash
ramparts --generate-completion zsh > ~/.zsh/completions/_ramparts
```

### Fish
```bash
ramparts --generate-completion fish > ~/.config/fish/completions/ramparts.fish
```

### PowerShell
```powershell
ramparts --generate-completion powershell > ramparts.ps1
```

*Note: Completion generation may not be available in all versions.*

## Advanced Usage Examples

### Advanced Scanning Options

```bash
# Custom severity threshold
ramparts scan <url> --min-severity HIGH

# JSON output with formatting
ramparts scan <url> --output json --pretty

# Custom configuration file
ramparts scan <url> --config custom-ramparts.yaml

# Scan from IDE configurations
ramparts scan-config
```

### Server Mode

Ramparts can run as a REST API server for continuous monitoring:

```bash
# Start server (default: localhost:3000)
ramparts server

# Custom host and port
ramparts server --port 8080 --host 0.0.0.0
```

### Batch Scanning

```bash
# Create a servers list
echo "https://server1.com/mcp/
https://server2.com/mcp/
https://server3.com/mcp/" > servers.txt

# Run batch scan
ramparts scan --batch servers.txt
```

### Output Format Details

**Table Format (Default)**
- Human-readable with colored output
- Tree-style security issue display with inline details
- Progress indicators and summaries
- Color-coded severity levels (🔴 CRITICAL, 🟠 HIGH, 🟡 MEDIUM, 🟢 LOW)

**JSON Format**
- Machine-readable structured output
- Perfect for scripts and automation
- Use `--pretty` for formatted output

**Raw Format**
- Preserves original MCP server responses
- Useful for debugging and analysis
- Minimal processing of server data

### Integration Examples

**Server Mode Integration:**
- 📚 **[Complete API Documentation](docs/api.md)** - REST endpoints and request/response formats
- 🔧 **[Integration Patterns](docs/integration.md)** - CI/CD, Docker, Kubernetes, and monitoring examples