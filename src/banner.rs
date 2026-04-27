use colored::Colorize;
use std::env;

/// Print the startup banner: name, tagline, and a compact key/value
/// block of build info. Suppressed automatically for the stdio MCP
/// server (would corrupt JSON-RPC framing) and for machine-readable
/// scan formats (json / raw / sarif) — see `should_display_banner`
/// in `main.rs`. Never panics; all `env!` strings are build-time
/// constants set by `build.rs`.
pub fn display_banner() {
    let version = env!("CARGO_PKG_VERSION");
    let git_commit_short = env!("GIT_COMMIT_SHORT");
    let now = chrono::Utc::now()
        .format("%Y-%m-%d %H:%M:%S UTC")
        .to_string();

    println!();
    // Title + tagline. The tagline reflects the *current* surface —
    // ramparts scans both live MCP servers and on-disk agent skill
    // files (`ramparts skills scan`).
    println!("{}", "RAMPARTS".bright_cyan().bold());
    println!(
        "{}",
        "Security scanner for MCP servers and agent skills"
            .italic()
            .white()
    );
    println!();

    // Two-column key/value block. Width 9 covers the longest key
    // ("Support:") with one trailing space; trailing colon on every
    // key keeps alignment neat under the dimmed style.
    let build = if git_commit_short.is_empty() {
        version.bright_green().to_string()
    } else {
        format!(
            "{} ({})",
            version.bright_green(),
            git_commit_short.bright_cyan()
        )
    };
    println!("  {:<9} {}", "Build:".dimmed(), build);
    println!("  {:<9} {}", "Time:".dimmed(), now.bright_yellow());
    println!(
        "  {:<9} {}",
        "Repo:".dimmed(),
        "https://github.com/highflame-ai/ramparts".bright_blue()
    );
    println!(
        "  {:<9} {}",
        "Support:".dimmed(),
        "support@highflame.com".bright_blue()
    );
    println!();
}
