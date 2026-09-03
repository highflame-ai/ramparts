use colored::Colorize;
use std::env;

/// Print the startup banner — a single tight line:
///
///   RAMPARTS v0.7.0 (c70cdce) · scanner for MCP + skills
///
/// We deliberately keep this to one line so it doesn't dominate
/// short-output scans (a clean skill scan is itself ~5 lines). Full
/// build / repo / support info is reachable via `ramparts --version`
/// and `ramparts --help`. Suppressed automatically for the stdio MCP
/// server (would corrupt JSON-RPC framing) and for machine-readable
/// scan formats (json / raw / sarif) — see `should_display_banner`
/// in `main.rs`. Never panics; all `env!` strings are build-time
/// constants set by `build.rs`.
pub fn display_banner() {
    let version = env!("CARGO_PKG_VERSION");
    let git_commit_short = env!("GIT_COMMIT_SHORT");

    // Suppress the `(<sha>)` suffix when there's no real commit info.
    // `build.rs` defaults `GIT_COMMIT_SHORT` to "unknown" for non-git
    // builds (e.g. `cargo install ramparts` from crates.io tarball),
    // but check both `""` and `"unknown"` so this renders correctly
    // even if build.rs's default ever changes.
    let build = if git_commit_short.is_empty() || git_commit_short == "unknown" {
        format!("v{version}")
    } else {
        format!("v{version} ({git_commit_short})")
    };

    println!(
        "{} {} · {}",
        "RAMPARTS".bright_cyan().bold(),
        build.bright_green(),
        "scanner for MCP + skills".italic().white()
    );
}
