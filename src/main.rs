use clap::{Parser, Subcommand};
use tracing::{debug, error, warn, Level};
use tracing_subscriber::FmtSubscriber;

use crate::config::ScannerConfig;

mod banner;
mod baseline;
mod cache;
mod config;
mod constants;
mod core;
#[cfg(test)]
mod integration_tests;
mod mcp_client;
mod mcp_server;
mod normalize;
mod osv;
#[cfg(test)]
mod rule_eval;
mod sarif;
mod scanner;
mod security;
mod server;
mod skills;
mod taxonomy;
mod tls;

mod types;
mod utils;

use banner::display_banner;
use scanner::MCPScanner;
use server::MCPScannerServer;
use types::{config_utils, ScanConfigBuilder, ScanOptions};
use utils::error_utils;

#[derive(Parser)]
#[command(
    name = "ramparts",
    about = "A CLI tool for scanning Model Context Protocol (MCP) servers",
    version,
    long_about = "Scans MCP servers to discover available tools, resources, and capabilities with comprehensive security analysis.

SECURITY ASSESSMENTS:

Tool Security Assessments:
  • Tool Poisoning: Detects tools with destructive or malicious intent that could harm the system or data
  • SQL Injection: Identifies tools allowing SQL injection attacks that could compromise databases
  • Command Injection: Detects tools that may execute system commands, posing critical security risks
  • Path Traversal: Finds tools allowing directory traversal attacks to access unauthorized files
  • Authentication Bypass: Identifies tools that could allow unauthorized access to protected resources
  • Secrets Leakage: Detects tools processing sensitive credentials like API keys, passwords, tokens

Prompt Security Assessments:
  • Prompt Injection: Identifies prompts vulnerable to injection attacks that could override safety measures
  • Jailbreak: Detects prompts that could bypass AI safety measures and restrictions
  • PII Leakage: Finds prompts handling personal information like emails, addresses, SSNs, credit cards

Resource Security Assessments:
  • Path Traversal: Detects resources with directory traversal vulnerabilities in URIs
  • Sensitive Data Exposure: Identifies resources containing sensitive information or credentials

IMPACT LEVELS:
  • CRITICAL: Immediate security risk requiring immediate attention
  • HIGH: Significant security vulnerability that should be addressed promptly
  • MEDIUM: Moderate security concern that should be reviewed
  • LOW: Minor security issue that may need monitoring

EXAMPLES:
  • Basic scan: ramparts scan http://localhost:3000
  • Security scan: ramparts scan http://localhost:3000
  • From IDE config: ramparts scan-config
  • Initialize config: ramparts init-config"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Enable verbose logging for detailed operation tracking
    ///
    /// This provides detailed logs about:
    ///   • HTTP requests and responses
    ///   • Security assessment progress
    ///   • Tool, resource, and prompt discovery
    ///   • Error details and debugging information
    ///
    /// Useful for troubleshooting connection issues or understanding scan behavior.
    /// Note: Use --debug for JSON-RPC protocol debugging.
    #[arg(short, long)]
    verbose: bool,

    /// Enable debug output for detailed operation tracking
    ///
    /// This provides detailed logs about:
    ///   • HTTP requests and responses
    ///   • Security assessment progress
    ///   • Tool, resource, and prompt discovery
    ///   • Error details and debugging information
    ///   • JSON-RPC protocol communication
    ///
    /// Useful for troubleshooting connection issues or understanding scan behavior.
    #[arg(short, long)]
    debug: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a single MCP server for tools, resources, and security vulnerabilities
    Scan {
        /// MCP server URL or endpoint to scan
        #[arg(value_name = "URL")]
        url: String,

        /// Authentication headers for the MCP server (format: "Header: Value")
        #[arg(long, value_delimiter = ',')]
        auth_headers: Vec<String>,

        /// Output format (json, raw, table, text)
        #[arg(long, value_name = "FORMAT")]
        format: Option<String>,

        /// Generate a detailed markdown report with timestamp (`scan_YYYYMMDD_HHMMSS.md`)
        #[arg(long)]
        report: bool,

        /// Overall scan timeout in seconds. Overrides `scanner.scan_timeout` from config.yaml.
        #[arg(long, value_name = "SECONDS")]
        timeout: Option<u64>,

        /// Per-HTTP-request timeout in seconds. Overrides `scanner.http_timeout` from config.yaml.
        #[arg(long, value_name = "SECONDS")]
        http_timeout: Option<u64>,

        /// Restrict the scan to a subset of artifact kinds. Comma-separated:
        /// `tools`, `prompts`, `resources` (singular forms also accepted).
        /// When omitted, every kind is scanned. Useful for CI gates that
        /// only care about one surface (`--only tools`).
        #[arg(long, value_name = "KINDS")]
        only: Option<String>,
    },

    /// Scan MCP servers from IDE configuration files (~/.cursor/mcp.json, ~/.codeium/windsurf/mcp_config.json)
    ScanConfig {
        /// Authentication headers for the MCP servers (format: "Header: Value")
        #[arg(long, value_delimiter = ',')]
        auth_headers: Vec<String>,

        /// Output format (json, raw, table, text)
        #[arg(long, value_name = "FORMAT")]
        format: Option<String>,

        /// Generate a detailed markdown report with timestamp (`scan_YYYYMMDD_HHMMSS.md`)
        #[arg(long)]
        report: bool,

        /// Overall per-server scan timeout in seconds. Overrides `scanner.scan_timeout` from config.yaml.
        #[arg(long, value_name = "SECONDS")]
        timeout: Option<u64>,

        /// Per-HTTP-request timeout in seconds. Overrides `scanner.http_timeout` from config.yaml.
        #[arg(long, value_name = "SECONDS")]
        http_timeout: Option<u64>,

        /// Walk this directory (e.g. a checked-in repo of IDE configs) for MCP
        /// configuration files instead of looking at the user's home/IDE
        /// locations. Recursive; symlinks are not followed; common build
        /// directories like .git, node_modules, target are skipped.
        #[arg(long, value_name = "PATH")]
        root: Option<std::path::PathBuf>,

        /// Restrict the scan to a subset of artifact kinds. Comma-separated:
        /// `tools`, `prompts`, `resources` (singular forms also accepted).
        #[arg(long, value_name = "KINDS")]
        only: Option<String>,
    },

    /// Generate a default config.yaml file
    InitConfig {
        /// Overwrite existing config.yaml if it exists
        #[arg(short, long)]
        force: bool,
    },

    /// Start the MCP Scanner microservice
    Server {
        /// Port to run the server on
        #[arg(short, long, default_value = "3000")]
        port: u16,

        /// Host to bind the server to. Defaults to loopback because this
        /// service fetches caller-supplied URLs with caller-supplied headers.
        /// Binding a non-loopback interface requires RAMPARTS_API_TOKEN.
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
    },

    /// Run Ramparts as an MCP server over stdio (for MCP hosts / Docker MCP Toolkit)
    McpStdio,

    /// Run Ramparts as an MCP server over SSE (HTTP SSE endpoint)
    McpSse {
        /// Host to bind the server to
        #[arg(long, default_value = "0.0.0.0")]
        host: String,
        /// Port to run the SSE server on
        #[arg(short, long, default_value = "8000")]
        port: u16,
    },

    /// Run Ramparts as an MCP server over streamable HTTP
    McpHttp {
        /// Host to bind the server to
        #[arg(long, default_value = "0.0.0.0")]
        host: String,
        /// Port to run the HTTP server on
        #[arg(short, long, default_value = "8081")]
        port: u16,
    },

    /// Replay a previously-saved scan result.
    ///
    /// Reads a `ramparts scan` / `scan-config` JSON output and re-emits it
    /// through the requested format. Useful for: converting an archived JSON
    /// scan into SARIF for code-scanning ingestion, viewing a CI artifact
    /// locally, or chaining scan output into downstream tooling without
    /// re-connecting to the MCP server. No live network or LLM calls.
    Replay {
        /// Path to a JSON file containing a `ScanResult` (single-server) or
        /// `[ScanResult, ...]` (multi-server, as emitted by `scan-config`).
        #[arg(value_name = "PATH")]
        input: std::path::PathBuf,

        /// Output format (json, raw, table, text, sarif). Defaults to the
        /// configured scanner output format.
        #[arg(long, value_name = "FORMAT")]
        format: Option<String>,
    },

    /// Scan AI agent skills (Claude Code commands, etc.) for security issues.
    ///
    /// Skills are markdown files containing prompt instructions an agent
    /// loads and executes by name. ramparts parses each skill's frontmatter
    /// and body, treats it as an MCP prompt, and runs the same security
    /// pipeline (LLM analysis, YARA, OWASP tagging) used for live MCP
    /// servers. No network calls — pure static analysis on disk.
    Skills(SkillsArgs),
}

/// Arguments for the `skills` subcommand. Wrapped in its own struct so the
/// nested subcommand can have its own flags without ballooning `Commands`.
#[derive(clap::Args, Debug)]
struct SkillsArgs {
    #[command(subcommand)]
    command: SkillsCommand,
}

#[derive(Subcommand, Debug)]
enum SkillsCommand {
    /// Scan a single skill file or every `*.md` skill under a directory.
    Scan {
        /// Path to a skill file or a directory containing skill files.
        #[arg(value_name = "PATH")]
        path: std::path::PathBuf,

        /// Output format (text, table, json, raw, sarif). Use `--json` /
        /// `--sarif` as shortcuts.
        #[arg(long, value_name = "FORMAT", conflicts_with_all = ["json", "sarif"])]
        format: Option<String>,

        /// Shortcut for `--format json`. Useful for piping into `jq` or
        /// archiving for later replay.
        #[arg(long, conflicts_with = "sarif")]
        json: bool,

        /// Shortcut for `--format sarif`. Pipe to a file (`> skills.sarif`)
        /// for upload to GitHub Code Scanning, GitLab, etc.
        #[arg(long)]
        sarif: bool,

        /// Generate a detailed markdown report
        #[arg(long)]
        report: bool,

        /// Overall scan timeout in seconds
        #[arg(long, value_name = "SECONDS")]
        timeout: Option<u64>,
    },

    /// Discover and scan skills from well-known locations across supported
    /// IDE/agent ecosystems (Claude Code, Cursor, Codex, Windsurf, Gemini,
    /// OpenAI). Walks `~/<dotdir>/{commands,skills}` and the same paths
    /// under the current workspace. Set `RAMPARTS_SKILL_ROOTS` (comma-
    /// separated, `~`-expanded) to add extra roots without rebuilding.
    ScanConfig {
        /// Output format (text, table, json, raw, sarif). Use `--json` /
        /// `--sarif` as shortcuts.
        #[arg(long, value_name = "FORMAT", conflicts_with_all = ["json", "sarif"])]
        format: Option<String>,

        /// Shortcut for `--format json`.
        #[arg(long, conflicts_with = "sarif")]
        json: bool,

        /// Shortcut for `--format sarif`.
        #[arg(long)]
        sarif: bool,

        /// Generate a detailed markdown report
        #[arg(long)]
        report: bool,

        /// Overall scan timeout in seconds
        #[arg(long, value_name = "SECONDS")]
        timeout: Option<u64>,
    },
}

/// Resolve the effective output format from the CLI surface. `--format
/// <X>` wins (clap rejects combining with `--json`/`--sarif`); else
/// the boolean shortcuts; else `None` so the handler falls back to
/// the config default.
fn resolve_format(format: Option<String>, json: bool, sarif: bool) -> Option<String> {
    if format.is_some() {
        format
    } else if sarif {
        Some("sarif".to_string())
    } else if json {
        Some("json".to_string())
    } else {
        None
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Install the aws-lc-rs CryptoProvider as the process-wide default for
    // rustls 0.23. reqwest 0.13's `rustls` feature relies on a default
    // provider being available before any HTTPS client is built; in some
    // environments the implicit auto-init races or fails, surfacing as the
    // opaque `reqwest::Error("builder error")` from `Client::builder().build()`.
    // Doing this explicitly and ignoring the `Err` (returned only when
    // something else already installed a provider) makes startup deterministic.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let cli = Cli::parse();
    // Do not print the banner when:
    //   - running as stdio MCP server (would corrupt JSON-RPC stdout), or
    //   - emitting a machine-readable scan format (json/raw/sarif), since
    //     downstream tools like `jq`, GitHub code-scanning's SARIF
    //     uploader, etc. parse our stdout and choke on free-form text.
    if should_display_banner(&cli.command) {
        display_banner();
    }

    let scanner_config = load_scanner_config();
    setup_logging(&cli, &scanner_config);
    debug!("Starting MCP Scanner");

    let scanner = create_scanner_if_needed(&cli, &scanner_config);
    execute_command(cli, scanner_config, scanner).await?;

    Ok(())
}

/// Whether to print the welcome banner for the current command. Suppresses
/// it for the stdio MCP server (would corrupt JSON-RPC framing) and for
/// scan commands that produce machine-readable output.
fn should_display_banner(command: &Commands) -> bool {
    if matches!(command, Commands::McpStdio) {
        return false;
    }
    // Check both `--format <X>` and the boolean shortcuts (`--json`,
    // `--sarif`) — the banner corrupts machine-readable stdout
    // regardless of which form the user used to ask for it.
    let (format, machine_shortcut) = match command {
        Commands::Scan { format, .. }
        | Commands::ScanConfig { format, .. }
        | Commands::Replay { format, .. } => (format.as_deref(), false),
        Commands::Skills(args) => match &args.command {
            SkillsCommand::Scan {
                format,
                json,
                sarif,
                ..
            }
            | SkillsCommand::ScanConfig {
                format,
                json,
                sarif,
                ..
            } => (format.as_deref(), *json || *sarif),
        },
        _ => (None, false),
    };
    if machine_shortcut {
        return false;
    }
    !matches!(
        format.map(str::to_ascii_lowercase).as_deref(),
        Some("json") | Some("raw") | Some("sarif")
    )
}

/// Loads the scanner configuration, using defaults if loading fails
fn load_scanner_config() -> ScannerConfig {
    let config_manager = config::ScannerConfigManager::new();
    match config_manager.load_config() {
        Ok(config) => config,
        Err(e) => {
            warn!("Failed to load scanner config, using defaults: {}", e);
            ScannerConfig::default()
        }
    }
}

/// Sets up logging based on CLI arguments and configuration
fn setup_logging(cli: &Cli, scanner_config: &ScannerConfig) {
    let level = determine_log_level(cli, scanner_config);

    // Create a filter that shows ramparts logs at the configured level,
    // but suppresses INFO logs from external crates (like MCP servers)
    let filter = match level {
        Level::DEBUG | Level::TRACE => {
            // For debug/trace, show everything to help with troubleshooting
            tracing_subscriber::EnvFilter::from_default_env().add_directive(
                format!("ramparts={level}")
                    .parse()
                    .expect("Failed to parse logging directive for debug/trace level"),
            )
        }
        _ => {
            // For info/warn/error, only show ramparts at the configured level
            // and suppress INFO from external crates
            tracing_subscriber::EnvFilter::new("warn").add_directive(
                format!("ramparts={level}")
                    .parse()
                    .expect("Failed to parse logging directive for ramparts level"),
            )
        }
    };

    FmtSubscriber::builder()
        .with_max_level(Level::TRACE) // Allow all levels, let the filter decide
        .with_env_filter(filter)
        .with_target(false)
        .with_thread_ids(false)
        .with_thread_names(false)
        // Ensure logs go to stderr, not stdout (stdout reserved for MCP stdio JSON-RPC)
        .with_writer(std::io::stderr)
        .init();
}

/// Determines the appropriate log level from CLI args and config
fn determine_log_level(cli: &Cli, scanner_config: &ScannerConfig) -> Level {
    if cli.debug || cli.verbose {
        Level::DEBUG
    } else {
        match scanner_config.logging.level.to_lowercase().as_str() {
            "trace" => Level::TRACE,
            "debug" => Level::DEBUG,
            "warn" => Level::WARN,
            "error" => Level::ERROR,
            _ => Level::INFO,
        }
    }
}

/// Creates an MCP scanner instance if needed for the given command.
///
/// The CLI's `--http-timeout` flag (when present) takes precedence over the
/// config-file value here so the scanner's HTTP client is constructed with
/// the same timeout that ends up in `ScanOptions::http_timeout`.
fn create_scanner_if_needed(cli: &Cli, scanner_config: &ScannerConfig) -> Option<MCPScanner> {
    let http_timeout_override = match &cli.command {
        Commands::Scan { http_timeout, .. } | Commands::ScanConfig { http_timeout, .. } => {
            *http_timeout
        }
        _ => return None,
    };
    let http_timeout = http_timeout_override.unwrap_or(scanner_config.scanner.http_timeout);
    match MCPScanner::with_timeout(http_timeout) {
        Ok(scanner) => Some(scanner),
        Err(e) => {
            error!("Failed to create scanner: {}", e);
            std::process::exit(1);
        }
    }
}

/// Executes the specified command with the given configuration and scanner
async fn execute_command(
    cli: Cli,
    scanner_config: ScannerConfig,
    scanner: Option<MCPScanner>,
) -> Result<(), Box<dyn std::error::Error>> {
    match cli.command {
        Commands::Scan {
            url,
            auth_headers,
            format,
            report,
            timeout,
            http_timeout,
            only,
        } => {
            handle_scan_command(
                url,
                auth_headers,
                format,
                report,
                timeout,
                http_timeout,
                only,
                &scanner_config,
                scanner,
            )
            .await
        }
        Commands::ScanConfig {
            auth_headers,
            format,
            report,
            timeout,
            http_timeout,
            root,
            only,
        } => {
            handle_scan_config_command(
                auth_headers,
                format,
                report,
                timeout,
                http_timeout,
                root,
                only,
                &scanner_config,
                scanner,
            )
            .await
        }
        Commands::InitConfig { force } => {
            handle_init_config_command(force);
            Ok(())
        }
        Commands::Server { port, host } => handle_server_command(port, host).await,
        Commands::McpStdio => handle_mcp_stdio_command().await,
        Commands::McpSse { host, port } => handle_mcp_sse_command(host, port).await,
        Commands::McpHttp { host, port } => handle_mcp_http_command(host, port).await,
        Commands::Replay { input, format } => handle_replay_command(input, format, &scanner_config),
        Commands::Skills(args) => handle_skills_command(args, &scanner_config).await,
    }
}

/// Dispatcher for the `skills` namespace.
async fn handle_skills_command(
    args: SkillsArgs,
    scanner_config: &ScannerConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    match args.command {
        SkillsCommand::Scan {
            path,
            format,
            json,
            sarif,
            report,
            timeout,
        } => {
            let format = resolve_format(format, json, sarif);
            handle_skills_scan_command(vec![path], format, report, timeout, scanner_config).await
        }
        SkillsCommand::ScanConfig {
            format,
            json,
            sarif,
            report,
            timeout,
        } => {
            let format = resolve_format(format, json, sarif);
            let candidates = skills::default_discovery_roots();
            let existing: Vec<std::path::PathBuf> =
                candidates.iter().filter(|p| p.exists()).cloned().collect();
            if existing.is_empty() {
                // Return an error rather than `std::process::exit(1)` so
                // the tokio runtime can shut down cleanly (running other
                // tasks' destructors etc.). The top-level `main` turns
                // the returned Err into a non-zero exit code.
                let looked_at = candidates
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                error!("No skill discovery roots found. Looked at: {looked_at}");
                return Err(
                    format!("No skill discovery roots found. Looked at: {looked_at}").into(),
                );
            }
            handle_skills_scan_command(existing, format, report, timeout, scanner_config).await
        }
    }
}

/// Convert one or more skill paths into a synthetic `ScanResult` and run
/// the existing prompt-security pipeline over it.
///
/// Skills are routed through `MCPPrompt` (frontmatter description + body
/// concatenated into `description`) so every downstream check — LLM
/// analysis, YARA pre/post scan, OWASP taxonomy tagging, terminal /
/// JSON / SARIF rendering — runs without any new plumbing.
async fn handle_skills_scan_command(
    roots: Vec<std::path::PathBuf>,
    format: Option<String>,
    report: bool,
    timeout: Option<u64>,
    scanner_config: &ScannerConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let output_format = format.unwrap_or(scanner_config.scanner.format.clone());

    // Collect skill files from every root. A root may be a single file or
    // a directory we walk recursively. We dedupe by canonical path so a
    // user passing overlapping roots (e.g. `~/.claude/commands` AND
    // `~/.claude`) doesn't scan the same skill twice.
    let mut skill_paths: Vec<std::path::PathBuf> = Vec::new();
    let mut seen: std::collections::HashSet<std::path::PathBuf> = std::collections::HashSet::new();
    let push_unique =
        |p: std::path::PathBuf,
         skill_paths: &mut Vec<std::path::PathBuf>,
         seen: &mut std::collections::HashSet<std::path::PathBuf>| {
            let key = std::fs::canonicalize(&p).unwrap_or_else(|_| p.clone());
            if seen.insert(key) {
                skill_paths.push(p);
            }
        };
    for root in &roots {
        if root.is_file() {
            push_unique(root.clone(), &mut skill_paths, &mut seen);
        } else if root.is_dir() {
            match skills::discover_skills_in_root(root) {
                Ok(found) => {
                    for p in found {
                        push_unique(p, &mut skill_paths, &mut seen);
                    }
                }
                Err(e) => warn!("Skipping skill root {}: {e}", root.display()),
            }
        } else {
            warn!("Skill path not found: {}", root.display());
        }
    }

    if skill_paths.is_empty() {
        // See the note on the previous `process::exit` site above.
        let msg = format!("No skill files found in: {roots:?}");
        error!("{msg}");
        return Err(msg.into());
    }

    // agentskills.io bundle filter (two-pass). Pass 1: identify
    // bundle roots — every parent of a `SKILL.md` we discovered.
    // Pass 2: drop any discovered path that lives under one of those
    // bundles' `scripts/`/`references/`/`assets/` subdirectories,
    // because the bundle parser pulls those siblings in as synthetic
    // resources. Without this filter, a bundle's `references/api.md`
    // would also be parsed as a standalone flat skill, leading to
    // duplicate findings and a misleading skill name.
    let bundle_roots: std::collections::HashSet<std::path::PathBuf> = skill_paths
        .iter()
        .filter_map(|p| skills::bundle_root_of(p).map(std::path::Path::to_path_buf))
        .collect();
    if !bundle_roots.is_empty() {
        let before = skill_paths.len();
        skill_paths.retain(|p| !skills::is_under_bundle_sibling_dir(p, &bundle_roots));
        let dropped = before - skill_paths.len();
        if dropped > 0 {
            debug!(
                "Dropped {dropped} agentskills.io bundle-sibling path(s) from top-level walk \
                 (will be picked up by bundle parser)"
            );
        }
    }

    debug!("Found {} skill file(s) to scan", skill_paths.len());

    // Each skill yields a prompt (for LLM/YARA analysis) plus zero or more
    // heuristic findings produced during parsing (overbroad allowed-tools
    // grants, vague triggers, generic triggers, sensitive @-references).
    // We collect both up front; the prompt set feeds the existing
    // analyzers, the per-skill heuristic findings are appended to
    // `result.yara_results`, and a final cross-skill pass detects
    // collisions across the whole set (skills declaring the same name).
    //
    // agentskills.io bundles also produce a list of synthetic
    // `MCPResource` entries (one per bundled script/reference) that we
    // funnel through the YARA pre-scan via a scratch `ScanData`. They
    // never reach `result.resources` — see the rewrite step below.
    let mut prompts: Vec<types::MCPPrompt> = Vec::with_capacity(skill_paths.len());
    let mut prompt_paths: Vec<std::path::PathBuf> = Vec::with_capacity(skill_paths.len());
    let mut parser_findings: Vec<types::YaraScanResult> = Vec::new();
    let mut bundle_resources: Vec<types::MCPResource> = Vec::new();
    // Resolved bundle names (skill names from a `SKILL.md` parse). Used
    // below to scope the post-scan target_type rewrite — we only flip
    // resource-typed findings to prompt-typed when the finding's
    // target_name corresponds to one of *our* synthesized bundle
    // resources. Otherwise a future change that surfaces non-bundle
    // resource findings here would get silently retyped.
    let mut bundle_prompt_names: std::collections::HashSet<String> =
        std::collections::HashSet::new();
    // Content baselining (rug-pull detection, AST07): the skill body a
    // reviewer approved is pinned on first sight; any later edit — the
    // hot-reload-abuse / malicious-update pattern — fires
    // SkillContentChanged until re-baselined. One store load/save for
    // the whole scan. Bundle sibling scripts ride through the prompt
    // body indirectly only when referenced;
    // ponytail: SKILL.md content only — extend to bundled scripts if script-swap rug pulls show up
    let mut baseline_store = baseline::BaselineStore::load_default();
    for p in &skill_paths {
        let parsed_prompt = if skills::is_agentskills_bundle(p) {
            skills::parse_agentskills_bundle(p).map(|(parsed, resources)| {
                bundle_prompt_names.insert(parsed.prompt.name.clone());
                bundle_resources.extend(resources);
                parsed
            })
        } else {
            skills::parse_skill_file(p)
        };
        if let Some(parsed) = parsed_prompt {
            let path_key = std::fs::canonicalize(p)
                .unwrap_or_else(|_| p.clone())
                .display()
                .to_string();
            if let Some(finding) = baseline::check_skill_drift(
                &mut baseline_store,
                &path_key,
                parsed.prompt.description.as_deref().unwrap_or(""),
            ) {
                parser_findings.push(finding);
            }
            prompts.push(parsed.prompt);
            prompt_paths.push(p.clone());
            parser_findings.extend(parsed.heuristic_findings);
        }
    }
    baseline_store.save();

    // Supply-chain pass (OWASP AST02): dependency manifests bundled with a
    // skill are the actual delivery mechanism for staged-loader attacks —
    // the SKILL.md stays clean while requirements.txt pulls the payload.
    // Route exactly-pinned deps through the same OSV.dev lookup the stdio
    // launch commands already get. Fail-soft like the rest of OSV: a
    // network failure yields no findings, never a failed scan.
    let mut manifest_specs: Vec<osv::PackageSpec> = Vec::new();
    for root in &bundle_roots {
        for candidate in [
            "requirements.txt",
            "package.json",
            "scripts/requirements.txt",
            "scripts/package.json",
        ] {
            // Read through a symlink guard: a hostile bundle must not be
            // able to point `requirements.txt` at the operator's private
            // files and have their contents shipped to OSV.dev.
            let Some(content) = skills::read_bundle_file_no_escape(root, candidate) else {
                continue;
            };
            let fname = std::path::Path::new(candidate)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");
            manifest_specs.extend(osv::parse_manifest_specs(fname, &content));
        }
    }
    manifest_specs.sort_by(|a, b| {
        (a.ecosystem, &a.name, &a.version).cmp(&(b.ecosystem, &b.name, &b.version))
    });
    manifest_specs
        .dedup_by(|a, b| a.ecosystem == b.ecosystem && a.name == b.name && a.version == b.version);
    // ponytail: 64-dep cap bounds the network fan-out; raise if real bundles exceed it
    manifest_specs.truncate(64);
    // Spawn the OSV round-trips onto the runtime so they actually run
    // concurrently with the (synchronous) YARA pass and the LLM call
    // below — reqwest futures are lazy, so a bare `join_all` would only
    // start at its `.await`. Drained after the YARA pass.
    let osv_handle = if manifest_specs.is_empty() {
        None
    } else {
        let client = reqwest::Client::new();
        Some(tokio::spawn(futures::future::join_all(
            manifest_specs
                .into_iter()
                .map(|spec| osv::query_osv(client.clone(), spec)),
        )))
    };

    if prompts.is_empty() {
        let msg = "All discovered skill files failed to parse";
        error!("{msg}");
        return Err(msg.into());
    }

    // Cross-skill pass: look for name collisions across the parsed set.
    // Distinct from per-skill heuristics because it requires comparing
    // skills against each other. We zip borrows directly — no PathBuf
    // clones — since `analyze_skill_set` only reads the paths.
    let skill_set: Vec<(&std::path::Path, &types::MCPPrompt)> = prompt_paths
        .iter()
        .map(std::path::PathBuf::as_path)
        .zip(prompts.iter())
        .collect();
    parser_findings.extend(skills::analyze_skill_set(&skill_set));

    let scan_timer = utils::Timer::start();
    // Display URL pattern matches the rest of ramparts: `<scheme>:<target>`
    // where the target is meaningful enough to identify the scan in
    // SARIF / JSON output. Single-root scans use the path verbatim;
    // multi-root scans summarize roots + total file count.
    let display_url = match roots.as_slice() {
        [single] => format!("skills:{}", single.display()),
        many => {
            let joined = many
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(",");
            format!("skills:[{}]({} files)", joined, skill_paths.len())
        }
    };
    let mut result = types::ScanResult::new(display_url);
    result.prompts = prompts;

    // YARA pre-scan over the discovered skill prompts. We use the
    // middleware-chain plumbing the live scanners share so OWASP tagging
    // and result formatting behave identically.
    //
    // Note: we deliberately don't run post-scan YARA or the cross-origin
    // scanner here. Post-scan rules are stateful summaries the live MCP
    // path emits over a richer scan_data; cross-origin needs URLs that
    // skills don't have. Pre-scan covers the prompt-injection / autonomy
    // / capability-inflation rules ported from upstream.
    #[cfg(feature = "yara-x-scanning")]
    {
        use scanner::ScanPhase;
        let mut scan_data = scanner::ScanData::new();
        // Move the prompts into scan_data to avoid cloning the body of
        // every skill (large skill repos can have hundreds of files);
        // we move them back out after the YARA pass so the LLM analyzer
        // and the final renderer see the same prompt set.
        scan_data.prompts = std::mem::take(&mut result.prompts);
        // Synthetic resources for agentskills.io bundled scripts/refs.
        // Local scratch only — never copied into `result.resources`
        // (would bloat JSON output with kilobytes of raw script source
        // and trigger the wrong "Resource Security" assessment line).
        scan_data.resources = std::mem::take(&mut bundle_resources);
        match scanner::YaraScanner::new("rules", ScanPhase::PreScan) {
            Ok(yara) => {
                let mut chain = scanner::ScannerChain::new();
                chain.add(Box::new(yara));
                chain.run_pre_scan(&mut scan_data);
                // Rewrite resource-typed findings whose target_name is
                // a synthetic bundle resource (`<bundle_name>/...`) to
                // prompt-typed. The terminal renderer
                // (`print_skill_table_result`) filters yara_results to
                // `target_type == "prompt"`, so without this rewrite
                // bundled-script findings would be invisible in the
                // default output. The match is scoped to the bundle
                // names we resolved during parsing — non-bundle
                // resource findings (a future caller might surface
                // them through the same scratch) stay resource-typed
                // and aren't silently absorbed.
                // O(N) using `split_once` to extract the bundle name
                // in one pass and a single HashSet lookup, rather than
                // the previous O(N x M) where M was the number of
                // bundle names. Synthetic resource names are always
                // shaped `<bundle>/<subdir>/<file>` (see
                // `skills::walk_bundle_subdir`), so the slash is
                // guaranteed if the finding came from a bundle.
                //
                // The rewrite target stays `"prompt"` (NOT `"member"`).
                // `target_type` is a 3-value enum in `types.rs:37`
                // (`tool` / `prompt` / `resource`), and the renderers
                // in `utils.rs:200,806,882` filter on `"prompt"` to
                // pick up skill findings — rewriting to anything else
                // would make these findings invisible in terminal /
                // JSON / markdown report output.
                for finding in scan_data.yara_results.iter_mut() {
                    if finding.target_type != "resource" {
                        continue;
                    }
                    let Some((bundle_name, _)) = finding.target_name.split_once('/') else {
                        continue;
                    };
                    if bundle_prompt_names.contains(bundle_name) {
                        finding.target_type = "prompt".to_string();
                    }
                }
                result
                    .yara_results
                    .extend(std::mem::take(&mut scan_data.yara_results));
            }
            Err(e) => {
                // Surface this loudly: a missing or unreadable rules
                // directory means half the scanner's coverage silently
                // doesn't run, which would mask findings.
                warn!("Skipping YARA pre-scan for skills (rules dir unreadable): {e}");
            }
        }
        result.prompts = std::mem::take(&mut scan_data.prompts);
        // Discard scan_data.resources — synthetic, intermediate only.
    }

    // Append heuristic findings produced during parsing (overbroad
    // allowed-tools grants, vague triggers). They share the same
    // `YaraScanResult` shape and `target_type = "prompt"` so the
    // existing terminal / JSON / SARIF renderers and the OWASP rollup
    // treat them identically to YARA matches.
    result.yara_results.append(&mut parser_findings);

    // Drain the OSV manifest lookups (ran concurrently since being spawned).
    if let Some(handle) = osv_handle {
        match handle.await {
            Ok(all) => {
                for findings in all {
                    result.yara_results.extend(findings);
                }
            }
            Err(e) => warn!("OSV manifest lookup task failed: {e}"),
        }
    }

    // Run the existing security analyzer over the prompt set. We reuse the
    // batch analyzer so LLM batching, OWASP tagging, and result accounting
    // all behave the same as for live MCP scans.
    let security_scanner = if scanner_config.security.enabled {
        security::SecurityScanner::with_config(scanner_config.clone())
    } else {
        security::SecurityScanner::default()
    };
    let mut security_result = security::SecurityScanResult::new();

    // LLM analysis — applies the prompt batch scanner to skill bodies.
    // Bounded by the user-supplied timeout when set; otherwise the default
    // from config.
    let scan_timeout =
        std::time::Duration::from_secs(timeout.unwrap_or(scanner_config.scanner.scan_timeout));
    // On LLM failure or timeout we record the error on the ScanResult (in
    // addition to logging) so the scan transitions out of `Success`, the
    // SARIF / JSON / terminal renderers surface the failure, and the
    // process exit code reflects an incomplete scan. Silently completing
    // with zero findings would be misleading for a security tool.
    match tokio::time::timeout(
        scan_timeout,
        security_scanner.scan_skills_batch(&result.prompts, scanner_config.scanner.detailed),
    )
    .await
    {
        Ok(Ok(prompt_issues)) => security_result.add_prompt_issues(prompt_issues),
        Ok(Err(e)) => {
            let msg = format!("Skill LLM analysis failed: {e}");
            warn!("{msg}");
            result.add_error(msg);
        }
        Err(_) => {
            let msg = format!(
                "Skill LLM analysis timed out after {}s",
                scan_timeout.as_secs()
            );
            warn!("{msg}");
            result.add_error(msg);
        }
    }
    result.security_issues = Some(security_result);

    // Agentic Skills Top 10 tagging. This is the skill scan surface, so
    // every finding here also gets its OWASP AST tag(s) appended alongside
    // the MCP tags already present. MCP-server scans never reach this path,
    // so AST tags stay off MCP-surface findings (see taxonomy.rs docs).
    for finding in &mut result.yara_results {
        finding
            .owasp_tags
            .extend(taxonomy::ast_tags_for_rule(&finding.rule_name));
    }
    if let Some(sec) = result.security_issues.as_mut() {
        for issue in sec
            .tool_issues
            .iter_mut()
            .chain(sec.prompt_issues.iter_mut())
            .chain(sec.resource_issues.iter_mut())
        {
            issue
                .owasp_tags
                .extend(taxonomy::ast_tags_for_security_issue(issue.issue_type));
        }
    }

    result.response_time_ms = scan_timer.elapsed_ms();

    utils::print_result(&result, &output_format, scanner_config.scanner.detailed);

    if report {
        match utils::write_markdown_report(&[result]) {
            Ok(filename) => println!("\n📄 Detailed report generated: {filename}"),
            Err(e) => warn!("Failed to generate report: {e}"),
        }
    }

    Ok(())
}

/// Read a previously-emitted scan result JSON file and re-emit it through
/// the requested format. Accepts both single-server (`ScanResult`) and
/// multi-server (`Vec<ScanResult>`) shapes — sniffs which by attempting
/// the array first, then falling back to a single object.
fn handle_replay_command(
    input: std::path::PathBuf,
    format: Option<String>,
    scanner_config: &ScannerConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let bytes = std::fs::read(&input).map_err(|e| {
        Box::<dyn std::error::Error>::from(format!(
            "Failed to read replay input {}: {e}",
            input.display()
        ))
    })?;
    let output_format = format.unwrap_or(scanner_config.scanner.format.clone());
    // Try the multi-server shape first; the single-server shape fits inside
    // a 1-element Vec for `print_multi_server_results` so we can route both
    // through the same renderer below.
    if let Ok(results) = serde_json::from_slice::<Vec<types::ScanResult>>(&bytes) {
        utils::print_multi_server_results(
            &results,
            &output_format,
            scanner_config.scanner.detailed,
        );
        return Ok(());
    }
    let result: types::ScanResult = serde_json::from_slice(&bytes).map_err(|e| {
        Box::<dyn std::error::Error>::from(format!(
            "Replay input is neither a `ScanResult` nor a `Vec<ScanResult>`: {e}"
        ))
    })?;
    utils::print_result(&result, &output_format, scanner_config.scanner.detailed);
    Ok(())
}

/// Handles the scan command for a single URL
#[allow(clippy::too_many_arguments)]
async fn handle_scan_command(
    url: String,
    auth_headers: Vec<String>,
    format: Option<String>,
    report: bool,
    timeout: Option<u64>,
    http_timeout: Option<u64>,
    only: Option<String>,
    scanner_config: &ScannerConfig,
    scanner: Option<MCPScanner>,
) -> Result<(), Box<dyn std::error::Error>> {
    let auth_headers_map = parse_auth_headers(&auth_headers);
    let output_format = format.unwrap_or(scanner_config.scanner.format.clone());
    let only_kinds = parse_only_filter(only)?;
    let options = build_scan_options(
        scanner_config,
        &output_format,
        auth_headers_map,
        timeout,
        http_timeout,
        only_kinds,
    );

    validate_scan_config(&options);

    let scanner = scanner
        .as_ref()
        .expect("Scanner should be initialized for scan command");

    match scanner.scan_single(&url, options.clone()).await {
        Ok(result) => {
            utils::print_result(&result, &output_format, options.detailed);

            // Generate report if requested
            if report {
                match utils::write_markdown_report(&[result]) {
                    Ok(filename) => {
                        println!("\n📄 Detailed report generated: {filename}");
                    }
                    Err(e) => {
                        warn!("Failed to generate report: {}", e);
                    }
                }
            }

            Ok(())
        }
        Err(e) => {
            error!(
                "{}",
                error_utils::format_error("Scan operation", &e.to_string())
            );
            std::process::exit(1);
        }
    }
}

/// Handles the scan-config command for IDE configurations
#[allow(clippy::too_many_arguments)]
async fn handle_scan_config_command(
    auth_headers: Vec<String>,
    format: Option<String>,
    report: bool,
    timeout: Option<u64>,
    http_timeout: Option<u64>,
    root: Option<std::path::PathBuf>,
    only: Option<String>,
    scanner_config: &ScannerConfig,
    scanner: Option<MCPScanner>,
) -> Result<(), Box<dyn std::error::Error>> {
    let auth_headers_map = parse_auth_headers(&auth_headers);
    let output_format = format.unwrap_or(scanner_config.scanner.format.clone());
    let only_kinds = parse_only_filter(only)?;
    let options = build_scan_options(
        scanner_config,
        &output_format,
        auth_headers_map,
        timeout,
        http_timeout,
        only_kinds,
    );

    validate_scan_config(&options);

    let scanner = scanner
        .as_ref()
        .expect("Scanner should be initialized for scan-config command");

    let scan_outcome = match root.as_deref() {
        Some(root_path) => scanner.scan_config_in_root(root_path, options).await,
        None => scanner.scan_config_by_ide(options).await,
    };

    match scan_outcome {
        Ok(results) => {
            utils::print_multi_server_results(
                &results,
                &output_format,
                scanner_config.scanner.detailed,
            );

            // Generate report if requested
            if report {
                match utils::write_markdown_report(&results) {
                    Ok(filename) => {
                        println!("\n📄 Detailed report generated: {filename}");
                    }
                    Err(e) => {
                        warn!("Failed to generate report: {}", e);
                    }
                }
            }

            Ok(())
        }
        Err(e) => {
            error!(
                "{}",
                error_utils::format_error("IDE configuration scan operation", &e.to_string())
            );
            std::process::exit(1);
        }
    }
}

/// Handles the init-config command
fn handle_init_config_command(force: bool) {
    let config_manager = config::ScannerConfigManager::new();

    if config_manager.has_config_file() && !force {
        println!("config.yaml already exists. Use --force to overwrite.");
        std::process::exit(1);
    }

    match config_manager.save_config(&config::ScannerConfig::default()) {
        Ok(()) => {
            println!("Created config.yaml with default settings");
            println!(
                "📝 Edit the file to customize LLM settings, security checks, and other options"
            );
        }
        Err(e) => {
            error!("Failed to create config.yaml: {}", e);
            std::process::exit(1);
        }
    }
}

/// Handles the server command
async fn handle_server_command(port: u16, host: String) -> Result<(), Box<dyn std::error::Error>> {
    debug!("Starting MCP Scanner microservice on {}:{}", host, port);

    match MCPScannerServer::new() {
        Ok(server) => {
            let server = server.with_port(port).with_host(host);
            if let Err(e) = server.start().await {
                error!("Server failed: {}", e);
                std::process::exit(1);
            }
            Ok(())
        }
        Err(e) => {
            error!("Failed to create server: {}", e);
            std::process::exit(1);
        }
    }
}

/// Handles the mcp-stdio command
async fn handle_mcp_stdio_command() -> Result<(), Box<dyn std::error::Error>> {
    mcp_server::run_stdio_server().await
}

async fn handle_mcp_sse_command(host: String, port: u16) -> Result<(), Box<dyn std::error::Error>> {
    mcp_server::run_sse_server(&host, port).await
}

async fn handle_mcp_http_command(
    host: String,
    port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    mcp_server::run_streamable_http_server(&host, port).await
}

/// Builds scan options from configuration and parameters.
///
/// CLI overrides (`timeout_override`, `http_timeout_override`, `only_kinds`)
/// take precedence over the values in `scanner_config`. `only_kinds` is
/// `None` when the user didn't pass `--only`; in that case every artifact
/// kind is scanned.
fn build_scan_options(
    scanner_config: &ScannerConfig,
    output_format: &str,
    auth_headers_map: Option<std::collections::HashMap<String, String>>,
    timeout_override: Option<u64>,
    http_timeout_override: Option<u64>,
    only_kinds: Option<Vec<types::ArtifactKind>>,
) -> ScanOptions {
    ScanConfigBuilder::new()
        .timeout(timeout_override.unwrap_or(scanner_config.scanner.scan_timeout))
        .http_timeout(http_timeout_override.unwrap_or(scanner_config.scanner.http_timeout))
        .detailed(scanner_config.scanner.detailed)
        .format(output_format.to_string())
        .auth_headers(auth_headers_map)
        .only(only_kinds)
        .build()
}

/// Parse the `--only` CLI value (e.g. `"tools,prompts"`) into the `Vec` shape
/// `ScanOptions::only` expects, or surface a clean error when the value is
/// malformed.
fn parse_only_filter(
    raw: Option<String>,
) -> Result<Option<Vec<types::ArtifactKind>>, Box<dyn std::error::Error>> {
    match raw {
        None => Ok(None),
        Some(s) => {
            let kinds = types::ArtifactKind::parse_set(&s)
                .map_err(|e| Box::<dyn std::error::Error>::from(e.to_string()))?;
            // Empty string parses to empty vec; treat that as "no filter"
            // rather than "scan nothing".
            if kinds.is_empty() {
                Ok(None)
            } else {
                Ok(Some(kinds))
            }
        }
    }
}

/// Validates scan configuration and exits on error
fn validate_scan_config(options: &ScanOptions) {
    if let Err(e) = config_utils::validate_scan_config(options) {
        error!("Invalid configuration: {}", e);
        std::process::exit(1);
    }
}

fn parse_auth_headers(headers: &[String]) -> Option<std::collections::HashMap<String, String>> {
    if headers.is_empty() {
        return None;
    }

    let mut map = std::collections::HashMap::new();
    for header in headers {
        if let Some((key, value)) = header.split_once(':') {
            map.insert(key.trim().to_string(), value.trim().to_string());
        }
    }
    Some(map)
}
