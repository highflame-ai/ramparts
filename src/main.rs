use clap::{Parser, Subcommand};
use tracing::{debug, error, warn, Level};
use tracing_subscriber::FmtSubscriber;

use crate::config::ScannerConfig;

mod banner;
mod cache;
mod config;
mod constants;
mod core;
#[cfg(test)]
mod integration_tests;
mod mcp_client;
mod mcp_server;
mod osv;
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

        /// Host to bind the server to
        #[arg(long, default_value = "0.0.0.0")]
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

        /// Output format (text, table, json, raw, sarif)
        #[arg(long, value_name = "FORMAT")]
        format: Option<String>,

        /// Generate a detailed markdown report
        #[arg(long)]
        report: bool,

        /// Overall scan timeout in seconds
        #[arg(long, value_name = "SECONDS")]
        timeout: Option<u64>,
    },

    /// Discover and scan skills from well-known locations
    /// (`~/.claude/commands`, `./.claude/commands`).
    ScanConfig {
        /// Output format (text, table, json, raw, sarif)
        #[arg(long, value_name = "FORMAT")]
        format: Option<String>,

        /// Generate a detailed markdown report
        #[arg(long)]
        report: bool,

        /// Overall scan timeout in seconds
        #[arg(long, value_name = "SECONDS")]
        timeout: Option<u64>,
    },
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
    let format = match command {
        Commands::Scan { format, .. }
        | Commands::ScanConfig { format, .. }
        | Commands::Replay { format, .. } => format.as_deref(),
        Commands::Skills(args) => match &args.command {
            SkillsCommand::Scan { format, .. } | SkillsCommand::ScanConfig { format, .. } => {
                format.as_deref()
            }
        },
        _ => None,
    };
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
            report,
            timeout,
            ..
        } => handle_skills_scan_command(vec![path], format, report, timeout, scanner_config).await,
        SkillsCommand::ScanConfig {
            format,
            report,
            timeout,
        } => {
            let candidates = skills::default_discovery_roots();
            let existing: Vec<std::path::PathBuf> =
                candidates.iter().filter(|p| p.exists()).cloned().collect();
            if existing.is_empty() {
                error!(
                    "No skill discovery roots found. Looked at: {}",
                    candidates
                        .iter()
                        .map(|p| p.display().to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
                std::process::exit(1);
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
        error!("No skill files found in: {:?}", roots);
        std::process::exit(1);
    }

    debug!("Found {} skill file(s) to scan", skill_paths.len());

    let prompts: Vec<types::MCPPrompt> = skill_paths
        .iter()
        .filter_map(|p| skills::parse_skill_file(p))
        .collect();

    if prompts.is_empty() {
        error!("All discovered skill files failed to parse");
        std::process::exit(1);
    }

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
        match scanner::YaraScanner::new("rules", ScanPhase::PreScan) {
            Ok(yara) => {
                let mut chain = scanner::ScannerChain::new();
                chain.add(Box::new(yara));
                chain.run_pre_scan(&mut scan_data);
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
    match tokio::time::timeout(
        scan_timeout,
        security_scanner.scan_prompts_batch(&result.prompts, scanner_config.scanner.detailed),
    )
    .await
    {
        Ok(Ok(prompt_issues)) => security_result.add_prompt_issues(prompt_issues),
        Ok(Err(e)) => warn!("Skill LLM analysis failed: {e}"),
        Err(_) => warn!(
            "Skill LLM analysis timed out after {}s",
            scan_timeout.as_secs()
        ),
    }
    result.security_issues = Some(security_result);
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
