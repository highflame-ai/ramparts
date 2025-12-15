use colored::Colorize;
use std::env;

/// Displays a clean banner with version, date, git commit info, and other useful information
pub fn display_banner() {
    let version = env!("CARGO_PKG_VERSION");
    let name = env!("CARGO_PKG_NAME");
    let git_commit_short = env!("GIT_COMMIT_SHORT");
    let git_commit_full = env!("GIT_COMMIT_FULL");

    // Get current date/time
    let current_date = chrono::Utc::now()
        .format("%Y-%m-%d %H:%M:%S UTC")
        .to_string();

    // Create the banner
    println!();
    println!("{}", name.to_uppercase().bold().white());
    println!("{}", "MCP Security Scanner".italic().cyan());
    println!();
    println!("Version: {}", version.bright_green());
    println!("Current Time: {}", current_date.bright_yellow());
    println!();
    println!(
        "Git Commit: {} ({})",
        git_commit_short.bright_cyan(),
        git_commit_full[..std::cmp::min(8, git_commit_full.len())].bright_cyan()
    );
    println!(
        "Repository: {}",
        "https://github.com/highflame-ai/ramparts".bright_blue()
    );
    println!("Support: {}", "support@highflame.com".bright_blue());
    println!();
}
