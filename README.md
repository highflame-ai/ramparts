<div align="center">

# Ramparts: security scanner for MCP servers and AI agent skills

<img src="assets/ramparts.png" alt="Ramparts Banner" width="250" />

*A fast, lightweight security scanner for the agent stack — Model Context Protocol (MCP) servers AND AI agent skills (Claude Code commands, [agentskills.io](https://github.com/agentskills/agentskills) bundles, Cursor / Codex / Windsurf / Gemini equivalents) — with built-in vulnerability detection.*

[![Crates.io](https://img.shields.io/crates/v/ramparts)](https://crates.io/crates/ramparts)
[![GitHub stars](https://img.shields.io/github/stars/highflame-ai/ramparts?style=social)](https://github.com/highflame-ai/ramparts)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.70+-blue.svg)](https://www.rust-lang.org/)
[![Tests](https://img.shields.io/github/actions/workflow/status/highflame-ai/ramparts/pr-check.yml?label=tests)](https://github.com/highflame-ai/ramparts/actions)
[![Clippy](https://img.shields.io/github/actions/workflow/status/highflame-ai/ramparts/pr-check.yml?label=lint)](https://github.com/highflame-ai/ramparts/actions)
[![Release](https://img.shields.io/github/release/highflame-ai/ramparts)](https://github.com/highflame-ai/ramparts/releases)

</div>

## Overview

**Ramparts** scans the two surfaces an AI agent trusts most: the **MCP servers** it talks to over the network, and the **skill files** it loads from disk and executes by name. Both deliver untrusted instructions and tool grants into the agent's loop; ramparts applies the same security pipeline (YARA, LLM analysis, OWASP MCP Top 10 tagging) to both.

- **MCP scanning** covers the [Model Context Protocol](https://modelcontextprotocol.io) — the open standard that lets AI assistants connect to databases, file systems, and APIs via tool-calling. Ramparts discovers a server's tools/resources/prompts and audits them for prompt injection, tool poisoning, secret leakage, path traversal, command injection, cross-origin escalation, supply-chain CVEs (via OSV.dev), and more.
- **Skill scanning** covers the markdown/YAML files an agent loads as named capabilities — Claude Code custom slash commands, Cursor / Codex / Windsurf / Gemini equivalents, and **first-class support for [agentskills.io](https://github.com/agentskills/agentskills) bundles** (`<name>/SKILL.md` directories with sibling `scripts/`, `references/`, `assets/`). Each skill body becomes a synthetic MCP prompt that runs through the same analyzers; bundled scripts get scanned through YARA, name-vs-directory mismatches surface as HIGH-severity deception findings, and the agentskills.io name/charset rules are validated.

Ramparts is under active development. Read our [launch blog](https://www.getjavelin.com/blogs/ramparts-mcp-scan).

### The Security Challenge

The MCP-and-skills attack surface is broad. MCP servers expose file systems, databases, APIs, and system commands — turning into attack vectors via tool poisoning, command injection, and data exfiltration without proper analysis. Agent skills carry the same risk profile (untrusted instructions an agent may follow) plus their own twists: skill-file `allowed-tools` grants that hand out unrestricted `Bash`, sensitive `@<path>` references that inline credentials into prompt context, name collisions that let one skill shadow another in the agent's router, and bundled scripts that ship arbitrary executable code. 📚 **[Security Features & Attack Vectors](docs/security-features.md)** documents every detector ramparts ships with — across both MCP and skill scanning.

### What Ramparts Does

Ramparts provides **security scanning** of the MCP-and-skill ecosystem by:

1. **MCP server discovery & analysis** — scans MCP endpoints for tools/resources/prompts; multi-transport (HTTP, SSE, stdio, subprocess) with intelligent fallback and session management
2. **Skill scanning** — same threat model applied to agent skill files on disk (Claude Code commands, agentskills.io bundles incl. bundled `scripts/` + `references/`, Cursor / Codex / Windsurf / Gemini variants)
3. **Static analysis (YARA)** — 40 pre-scan rules across both surfaces: 10 skill-targeted rules (prompt-injection variants, credential harvesting, tool-chaining exfil, system manipulation, authority abuse, covert exfiltration) plus malware-IOC rules adapted from [NVIDIA SkillSpector](https://github.com/NVIDIA/SkillSpector) (cryptominers, reverse shells / C2 / info-stealers, webshells, offensive hack tools)
4. **Evasion-resistant rescan** — every YARA rule is also run over a normalized view (invisible/zero-width chars stripped, NFKC homoglyph folding) and iteratively base64/hex-decoded views, so a keyword split by zero-width characters, spelled in fullwidth homoglyphs, or hidden in an encoded blob still matches
5. **LLM-powered analysis** — sophisticated semantic issues no static rule can spot (tool descriptions that lie about behavior, sneaky permission requests, etc.)
6. **Cross-origin analysis** — detects tools spanning multiple domains, a context-hijacking / injection vector
7. **Supply-chain coverage** — queries OSV.dev for known CVEs in npx/uvx-launched stdio MCP servers and in exactly-pinned dependencies declared by skill bundles (`requirements.txt`, `package.json`)
8. **Rug-pull / drift detection** — content-fingerprints MCP server configs, individual tool definitions, and skill files against a stored baseline; flags any post-approval swap (`MCPConfigChanged` / `MCPToolChanged` / `SkillContentChanged`)
9. **Structural skill heuristics** — overbroad `allowed-tools` grants, vague/generic triggers, sensitive `@<path>` references, embedded base64/hex payloads, skill-name collisions, agent identity/memory-file writes, undeclared network egress (manifest-vs-script mismatch), external-reference inventory, unsafe-YAML-deserialization tags, brand impersonation, JSON prototype pollution, and an explicit incomplete-coverage finding when files are skipped
10. **agentskills.io spec validation** — directory-vs-`name:` mismatch (deception), spec name-rule violations, unknown frontmatter fields
11. **OWASP taxonomy tagging** — every finding mapped to the versioned **OWASP MCP Top 10**; skill-surface findings additionally carry **OWASP Agentic Skills Top 10** (`AST01`–`AST10`) tags. Visible in terminal, JSON, SARIF, and markdown report output
12. **Multiple output formats** — terminal, JSON, **SARIF 2.1.0** (for GitHub Advanced Security / GitLab / Azure DevOps), and a detailed markdown report
>
> **💡 Jump directly to detailed Rampart features?**
> [**📚 Detailed Features**](docs/features.md)

## Who Ramparts is For

- **MCP users** — scan third-party MCP servers before connecting; validate local servers before production
- **MCP developers** — ensure your tools/resources/prompts don't expose vulnerabilities to AI agents
- **Skill authors** — validate agentskills.io bundles against the spec before publishing; catch overbroad tool grants and sensitive-file references in your `.claude/commands/` or bundled `scripts/`
- **Agent operators** — scan the skills your team has authored or installed; check that no bundle has been swapped under a deceptive directory name; surface findings in your existing SARIF/code-scanning workflow

## Use Cases

- **Security audits** — full assessment of an MCP server's posture or a skill repo's safety
- **Development** — fast feedback loop while building MCP servers or authoring skills
- **CI/CD integration** — gate PRs that add skills or change MCP server configs (SARIF flows directly into GitHub code-scanning, GitLab, Azure DevOps)
- **Compliance** — meet AI-agent deployment security requirements with OWASP MCP Top 10-tagged evidence

> **💡 Caution**: Ramparts analyzes static metadata, configurations, and skill files. For comprehensive security, combine with runtime MCP guardrails and adopt a layered security approach. The MCP+skills threat landscape is rapidly evolving, and ramparts is not perfect — inaccuracies are inevitable.

## Quick Start

**Installation**
```bash
cargo install ramparts
```

Ramparts has two top-level scan surfaces. Pick whichever (or both) match what
you're securing.

### 1. Scan MCP servers

```bash
# A specific MCP server (HTTP)
ramparts scan https://api.githubcopilot.com/mcp/ --auth-headers "Authorization: Bearer $TOKEN"

# stdio / subprocess MCP servers
ramparts scan "stdio:npx:mcp-server-commands"
ramparts scan "stdio:python3:/path/to/mcp_server.py"

# Auto-discover and scan every MCP server in your IDE configs
# (Cursor, Windsurf, VS Code, Claude Desktop, Claude Code, Cline)
ramparts scan-config

# Generate a detailed markdown report (scan_YYYYMMDD_HHMMSS.md)
ramparts scan-config --report

# Or walk a checked-in configs-only repo (great for CI)
ramparts scan-config --root ./ide-configs
```

### 2. Scan AI agent skills

```bash
# A single skill file or every *.md skill under a directory
ramparts skills scan ./.claude/commands

# An agentskills.io bundle directory — picks up SKILL.md +
# walks sibling scripts/ and references/ through YARA
ramparts skills scan ./my-skill-bundle

# Auto-discover skills across every supported ecosystem at the user
# and workspace level (.claude/, .cursor/, .codex/, .windsurf/,
# .gemini/, .openai/, ~/.skills/, probe-gated ./skills/).
# Add extra roots without rebuilding via RAMPARTS_SKILL_ROOTS=path1,path2.
ramparts skills scan-config

# SARIF output for code-scanning ingestion
ramparts skills scan ./.claude/commands --format sarif > skills.sarif
```

**Skill formats supported out of the box:**

- **Claude Code custom slash commands** — flat `.md` files under
  `.claude/commands/` (per-user and per-workspace)
- **[agentskills.io](https://github.com/agentskills/agentskills) bundles** —
  `<name>/SKILL.md` directories with optional sibling `scripts/` (`.py` / `.sh`
  / `.bash` / `.zsh` / `.js` / `.mjs` / `.cjs` / `.ts` / `.rb` / `.pl` / `.ps1`),
  `references/` (`.md`), and `assets/`. Bundle mode also validates the spec's
  `name:` field against the parent directory name, the 1–64 char
  `[a-z0-9-]` rule, and surfaces name-vs-directory mismatches as
  HIGH-severity deception findings (`AgentskillsNameMismatch`).
- **Cursor / OpenAI Codex / Windsurf / Gemini** skill repos that ship the same
  markdown + YAML frontmatter shape — supported via shared frontmatter fields
  and the per-ecosystem dotdir discovery roots.

> **💡 Did you know you can start Ramparts as a server?** Run `ramparts server` to get a REST API for continuous monitoring and CI/CD integration. See 📚 **[Ramparts Server Mode](docs/api.md)** 

### Run as an MCP server (stdio)

```bash
ramparts mcp-stdio
```

When publishing to Docker MCP Toolkit, configure the container command to `ramparts mcp-stdio` so the toolkit connects via stdio. Use `MCP-Dockerfile` to make this the default.

## Example Output

**Single server scan:**
```bash
ramparts scan https://api.githubcopilot.com/mcp/ --auth-headers "Authorization: Bearer $TOKEN"
```

```
RAMPARTS
MCP Security Scanner

Version: 0.7.0
Current Time: 2025-08-04 07:32:19 UTC
Git Commit: 9d0c37c

🌐 GitHub Copilot MCP Server
  ✅ All tools passed security checks

  └── push_files ✅ passed
  └── create_or_update_file ⚠️ 2 warnings
      │   └── 🟠 HIGH (LLM): Tool allowing directory traversal attacks
      │   └── 🟠 HIGH (YARA): EnvironmentVariableLeakage
  └── get_secret_scanning_alert ⚠️ 1 warning
      │   └── 🟠 HIGH (YARA): EnvironmentVariableLeakage

Summary:
  • Tools scanned: 83
  • Security issues: 3 findings
```

**IDE configuration scan:**
```bash
ramparts scan-config --report
```

```
🔍 Found 3 IDE config files:
  ✓ vscode IDE: /Users/user/.vscode/mcp.json
  ✓ claude IDE: /Users/user/Library/Application Support/Claude/claude_desktop_config.json
  ✓ cursor IDE: /Users/user/.cursor/mcp.json

📁 vscode IDE config: /Users/user/.vscode/mcp.json (2 servers)
  └─ github-copilot [HTTP]: https://api.githubcopilot.com/mcp/
  └─ local-tools [STDIO]: stdio:python[local-mcp-server]

🌍 MCP Servers Security Scan Summary
────────────────────────────────────────────────────────────
📊 Scan Summary:
  • Servers: 2 total (2 ✅ successful, 0 ❌ failed)
  • Resources: 81 tools, 0 resources, 2 prompts
  • Security: ✅ All servers passed security checks

📄 Detailed report generated: scan_20250804_073225.md
```

**Skill scan (agentskills.io bundle):**
```bash
ramparts skills scan ./my-skill
```

```
Path: ./my-skill
❌ 1 skill scanned, 4 findings (2 CRITICAL, 2 HIGH) · 0.6s

  ⚠️ evil-skill (4 findings)
    source: ./my-skill/SKILL.md
    [HIGH] SecretsLeakage in scripts/exfil.py [OWASP: MCP06, MCP09]
        Detects potential exposure of sensitive information like API keys, passwords, and tokens
    [CRITICAL] SSHKeyExposure in scripts/exfil.py [OWASP: MCP06]
        Detects SSH keys, authorized_keys files, and SSH configuration access
    [CRITICAL] SSHKeyExposure in references/api.md [OWASP: MCP06]
        Detects SSH keys, authorized_keys files, and SSH configuration access
    [HIGH] AgentskillsNameMismatch [OWASP: MCP02]
        SKILL.md declares `name: evil-skill` but its parent directory is `my-skill/`.
        agentskills.io requires the name to match the parent directory; the mismatch may
        indicate a deceptively-named bundle.
```

(`AgentskillsNameMismatch` is from agentskills.io spec validation; the
`SecretsLeakage` / `SSHKeyExposure` rows are bundled-script YARA findings —
ramparts walked `scripts/exfil.py` and `references/api.md` automatically.)

## Contributing

We welcome contributions to Ramparts. If you have suggestions, bug reports, or feature requests, please open an issue on our GitHub repository.

## Documentation
- 📖 **[CLI Reference](docs/cli.md)** — All commands (scan, scan-config, skills scan, skills scan-config, replay, server, mcp-stdio), options, and usage examples
- 🛡️ **[Security Features & Attack Vectors](docs/security-features.md)** — Every detector ramparts ships with, across MCP + skill scanning
- ⚙️ **[Configuration Reference](docs/configuration.md)** — Complete config file documentation + skill discovery root config
- 🔍 **[Troubleshooting Guide](docs/troubleshooting.md)** — Solutions to common issues
- 📚 **[Detailed Features](docs/features.md)** — How each capability works under the hood

## Additional Resources
- [Need Support?](https://github.com/highflame-ai/ramparts/issues)
- [MCP Protocol Documentation](https://modelcontextprotocol.io/)
// Examples folder was removed to reduce branch diff; see configuration docs instead.
- [Configuration Guide](docs/configuration.md)
