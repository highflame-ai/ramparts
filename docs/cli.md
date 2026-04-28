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

# Initialize configuration file
ramparts init-config

# Show help
ramparts --help
ramparts scan --help
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
  -a, --auth-headers <HEADERS>    Authentication headers (format: "Header: Value")
                                  Can be specified multiple times
  -o, --output <FORMAT>           Output format [default: table]
                                  [possible values: json, raw, table, text]
      --report                    Generate detailed markdown report (scan_YYYYMMDD_HHMMSS.md)
  -t, --timeout <SECONDS>         Request timeout in seconds [default: 60]
      --http-timeout <SECONDS>    HTTP timeout in seconds [default: 30]
      --detailed                  Enable detailed output
      --min-severity <LEVEL>      Minimum severity level to report
                                  [possible values: low, medium, high, critical]
      --config <FILE>             Custom configuration file path
      --pretty                    Pretty print JSON output (only with --output json)
  -h, --help                      Print help information
```

### Examples

**Basic scan:**

```bash
ramparts scan https://api.githubcopilot.com/mcp/
```

**Scan with authentication:**

```bash
ramparts scan https://api.githubcopilot.com/mcp/ \
  --auth-headers "Authorization: Bearer $TOKEN" \
  --auth-headers "X-API-Key: $API_KEY"
```

**Detailed JSON output:**

```bash
ramparts scan https://api.githubcopilot.com/mcp/ \
  --output json \
  --detailed \
  --pretty
```

**Custom timeout and severity:**

```bash
ramparts scan https://api.githubcopilot.com/mcp/ \
  --timeout 120 \
  --http-timeout 45 \
  --min-severity high
```

**Generate detailed report:**

```bash
ramparts scan https://api.githubcopilot.com/mcp/ --report
```

**STDIO server scan:**

```bash
ramparts scan "stdio:///usr/local/bin/mcp-server"
ramparts scan "node /path/to/server.js --config config.json"
ramparts scan "/usr/bin/python3 /path/to/server.py"
```

## Scan-Config Command

Scan MCP servers from IDE configuration files.

### Usage

```bash
ramparts scan-config [OPTIONS]
```

### Options

```bash
Options:
  -a, --auth-headers <HEADERS>    Authentication headers for MCP servers
  -o, --output <FORMAT>           Output format [default: table]
                                  [possible values: json, raw, table, text]
      --report                    Generate detailed markdown report (scan_YYYYMMDD_HHMMSS.md)
      --config <FILE>             Custom configuration file path
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
  --output json
```

**Generate report:**

```bash
ramparts scan-config --report
```

### Supported IDE Configuration Files

Ramparts automatically discovers and reads MCP server configurations from:

- **Cursor**: `~/.cursor/mcp.json`
- **Windsurf**: `~/.codeium/windsurf/mcp_config.json`
- **VS Code**: `~/.vscode/mcp.json`
- **Claude Desktop**: `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS)
- **Claude Code**: `~/.claude/settings.json`
- **Gemini CLI**: `~/.gemini/settings.json`, `.gemini/settings.json` (workspace)
- **Neovim**: `~/.config/nvim/mcp.json`
- **Helix**: `~/.config/helix/mcp.json`
- **Zed**: `~/.config/zed/mcp.json`

### Auto-Fix Mode (`--fix`, `--dry-run`, `--undo`)

> ⚠ **Auto-fix modifies your IDE configuration files in place.** It always
> writes a backup first (see "Backups" below), but you should still close
> your IDE before running `--fix --yes` so the IDE doesn't race-rewrite the
> file from its in-memory state.

Auto-fix applies a small, conservative set of deterministic remediations to
discovered IDE config files:

| Rule                     | What it does                                                                                      | Example                                                                                                                               |
| ------------------------ | ------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| `http-to-https`          | Rewrites `http://` URLs to `https://` for non-loopback hosts                                      | `http://api.example.com/mcp` → `https://api.example.com/mcp`                                                                          |
| `secret-externalization` | Replaces inline secret values with `${VAR}` references when the env key is `SCREAMING_SNAKE_CASE` | `"GITHUB_TOKEN": "ghp_xxxx"` → `"GITHUB_TOKEN": "${GITHUB_TOKEN}"`                                                                    |
| `dangerous-flag-removal` | Removes a closed list of opt-out flags that disable security checks                               | `NODE_TLS_REJECT_UNAUTHORIZED=0`, `DANGEROUSLY_OMIT_AUTH=true`, `MCP_DISABLE_AUTH=1`, `PYTHONHTTPSVERIFY=0`, `GIT_SSL_NO_VERIFY=true` |

Anything that requires LLM judgement, network resolution, or schema
inference is intentionally **not** auto-fixed.

#### Usage

```bash
# Show what would change. Exits 1 if any fixes would be applied (CI-usable).
ramparts scan-config --dry-run

# Same as --dry-run when --yes is omitted: prints the diff, doesn't write.
ramparts scan-config --fix

# Actually apply. Backs up every touched file first.
ramparts scan-config --fix --yes

# Restore the most recent fix run from backup, then delete the backup.
ramparts scan-config --undo
```

#### Backups and `--undo`

Every `--fix --yes` run creates a directory under
`~/.ramparts/fixes/<run-id>/` containing:

- `manifest.json` listing every file touched, with `sha256_before` and
  `sha256_after` fingerprints and the rules that fired.
- One `<hash>.bak` file per touched file, holding the pre-fix bytes.

`--undo` finds the most recent run-dir and restores each entry **only when
the current target file's SHA-256 still matches `sha256_after`**. If you
edited a file after the fix, undo skips that entry rather than clobber your
changes; the backup directory stays around so you can inspect or recover
manually.

A clean undo deletes the run-dir. A partial undo (anything skipped) leaves
the run-dir in place.

#### Refusal cases (the engine intentionally does nothing)

Auto-fix is conservative and refuses to touch any file where it can't
guarantee a lossless write-back:

- **The file uses formatting we don't preserve.** Before any fix, ramparts
  re-serializes the parsed JSON via `serde_json::to_string_pretty` and
  compares to the original bytes (modulo a single trailing newline). If
  they differ, the file likely contains comments, trailing commas, custom
  indentation, or fields outside the schemas ramparts understands. We
  refuse rather than mangle. JSONC files (VS Code `settings.json`,
  Claude Code `settings.json`) commonly fall into this bucket.
- **The file is a symlink.** We don't follow symlinks for fixes.
- **The file is not valid JSON.** Reported with a clear error; skipped.

Refused files are listed in the dry-run output. Other discovered files
that pass the round-trip check still get fixed.

#### Recovery

If something looks wrong after a fix:

1. Run `ramparts scan-config --undo` to revert the most recent run.
2. If undo reports drift on a file you intended to revert, the original
   bytes are still in `~/.ramparts/fixes/<run-id>/<hash>.bak` — copy them
   back manually.
3. If you've manually edited backup files or the manifest, restore can be
   done with `cp` from the backup directly to the target path.

#### Limitations and caveats

- **No git-cleanliness check.** Many MCP config files live outside any git
  repo (e.g. `~/Library/Application Support/Claude/claude_desktop_config.json`),
  so a "refuse if dirty" rule would have too many false negatives to be a
  meaningful safety. The backup is the safety.
- **`fsync(2)` only on Unix.** macOS's `fsync` does not guarantee
  platter-level durability — `F_FULLFSYNC` would. We accept this for v1;
  the backup makes a power-loss-during-fix recoverable on next boot.
- **Concurrent IDE writes can race.** If Cursor / Claude Desktop / VS Code
  is running, it may rewrite the config file from its in-memory state
  after the fix completes, silently undoing it. Close the IDE first.
- **Discovery scope.** `--fix` operates on the same file set as
  `scan-config`'s normal discovery — ramparts will not write to files
  outside that set.

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

### Table Format (Default)

Human-readable table format with colored output:

```bash
ramparts scan <url>
ramparts scan <url> --output table
```

### JSON Format

Machine-readable JSON output:

```bash
ramparts scan <url> --output json
ramparts scan <url> --output json --pretty
```

### Text Format

Simple text format:

```bash
ramparts scan <url> --output text
```

### Raw Format

Raw JSON format preserving original MCP server responses with embedded security data:

```bash
ramparts scan <url> --output raw
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

_Note: Completion generation may not be available in all versions._

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
