//! Agent-skill scanning.
//!
//! "Skills" are markdown files containing prompt instructions that an
//! agent loads and executes by name (Claude Code's `.claude/commands/*.md`,
//! Cursor agent skills, OpenAI Codex skill repos, etc.). They share a
//! threat model with MCP prompts — both are untrusted instructions an
//! agent may follow — so this module is intentionally thin: it parses
//! skill files into `MCPPrompt` values and hands them straight to the
//! existing prompt-security pipeline (LLM analysis, YARA pre/post scan,
//! OWASP tagging, terminal/JSON/SARIF rendering).
//!
//! Supported formats today:
//!
//! - **Claude Code** custom slash commands: markdown files (with optional
//!   YAML frontmatter) under `~/.claude/commands/` or `.claude/commands/`
//!   in a workspace
//! - Generic markdown skill files (in lenient mode — anything ending in
//!   `.md` walked under `--root`)
//!
//! The frontmatter is parsed best-effort: a missing or malformed
//! frontmatter block still yields a usable skill (filename stem becomes
//! the name; body becomes the description). Anything that can't be read
//! as UTF-8 is skipped with a warning rather than failing the scan.

use crate::types::{MCPPrompt, MCPPromptArgument, YaraRuleMetadata, YaraScanResult};
use anyhow::{anyhow, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};
use tracing::{debug, warn};

/// Environment variable allowing operators to extend the default discovery
/// roots without rebuilding. Comma-separated absolute or `~`-prefixed paths.
pub const SKILL_ROOTS_ENV: &str = "RAMPARTS_SKILL_ROOTS";

/// A parsed skill file plus any structural / frontmatter-level findings
/// the parser produced (e.g. an `allowed-tools` grant that's too broad,
/// a missing description). Returned together so the caller can append
/// `heuristic_findings` to its `ScanResult.yara_results` and route them
/// through the existing rendering pipeline alongside YARA matches.
#[derive(Debug)]
pub struct ParsedSkill {
    pub prompt: MCPPrompt,
    pub heuristic_findings: Vec<YaraScanResult>,
}

/// Reject any individual skill file larger than this. Real skill files are
/// kilobytes; a multi-megabyte markdown is either a misclassification (e.g.
/// CHANGELOG sneaking through) or an attempt to DoS the scanner with a
/// pathological input. We log at warn and skip rather than reading.
const MAX_SKILL_FILE_BYTES: u64 = 2 * 1024 * 1024;

/// Filenames that are virtually never agent skills but commonly appear in
/// the same directories users point `skills scan` at (project README,
/// licenses, etc.). Matched case-insensitively and ignoring extension —
/// `README.md`, `Readme.markdown`, `LICENSE.md` all skip.
///
/// Add new entries when you find a recurring source of false positives in
/// real skill repos. Project-conventional names are stable enough that
/// this list rarely needs to change.
const NON_SKILL_FILENAME_STEMS: &[&str] = &[
    "readme",
    "changelog",
    "license",
    "licence",
    "contributing",
    "code_of_conduct",
    "security",
    "support",
    "authors",
    "notice",
    "history",
    "upgrade",
    "upgrading",
    "migration",
    "todo",
];

/// Returns true if a filename's stem matches a known non-skill convention.
fn is_non_skill_filename(name: &str) -> bool {
    let stem = name.rsplit_once('.').map_or(name, |(s, _)| s);
    let normalized = stem.to_ascii_lowercase().replace('-', "_");
    NON_SKILL_FILENAME_STEMS
        .iter()
        .any(|candidate| candidate == &normalized)
}

/// Frontmatter fields ramparts cares about across skill formats. Unknown
/// fields are ignored (serde defaults), so adding support for a new
/// ecosystem usually means adding a field here rather than introducing a
/// new struct. Today we cover Claude Code conventions; Cursor / OpenAI
/// Codex / generic skill repos that ship the same frontmatter shape work
/// out of the box.
///
/// All fields are optional because real-world skill files vary widely —
/// some have only a description, some have only an argument hint, some
/// have neither.
#[derive(Debug, Deserialize, Default)]
struct SkillFrontmatter {
    description: Option<String>,
    /// Claude Code's `argument-hint` — a one-liner describing parameters.
    /// Other ecosystems may use different field names; add a `#[serde(alias)]`
    /// attribute when expanding support rather than introducing a new struct.
    #[serde(rename = "argument-hint")]
    argument_hint: Option<String>,
    /// Some skill formats use `name` to override the filename-derived name.
    name: Option<String>,
    /// Claude Code's `allowed-tools` — comma- or newline-separated tool
    /// grants like `Bash(git status:*), Read, Write`. We surface this as
    /// a finding when the grant is overbroad (Bash with `*` wildcards,
    /// `rm:*`, `sudo:*`, etc.) since those are excessive-agency risks.
    #[serde(rename = "allowed-tools")]
    allowed_tools: Option<String>,
}

/// Parse a single skill file at `path`. Returns `None` (logging at warn)
/// when the file can't be read, exceeds `MAX_SKILL_FILE_BYTES`, or is
/// effectively empty. Errors are non-fatal so a single broken skill
/// can't break a directory scan.
pub fn parse_skill_file(path: &Path) -> Option<ParsedSkill> {
    // Cheap pre-check: stat the file before we open it. We could
    // alternatively let `read_to_string` succeed and then check the
    // resulting String length, but that risks reading a 2 GB file into
    // memory before deciding to drop it.
    if let Ok(metadata) = std::fs::metadata(path) {
        if metadata.len() > MAX_SKILL_FILE_BYTES {
            warn!(
                "Skipping skill file {} ({} bytes > {} byte limit)",
                path.display(),
                metadata.len(),
                MAX_SKILL_FILE_BYTES
            );
            return None;
        }
    }
    let content = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            warn!("Skipping skill file {}: {e}", path.display());
            return None;
        }
    };
    parse_skill_content(path, &content)
}

/// Pure-data version of `parse_skill_file` — useful for tests and for
/// callers that already have the content in memory (e.g. fetched from a
/// remote source). Returns `None` for an effectively empty file (no
/// frontmatter content and a body that's blank after trimming) so we
/// don't waste an LLM batch slot on something with nothing to analyze.
pub fn parse_skill_content(path: &Path, raw: &str) -> Option<ParsedSkill> {
    let (frontmatter, body) = split_frontmatter(raw);
    let parsed_fm: SkillFrontmatter = frontmatter
        .and_then(|fm| match serde_yaml::from_str(fm) {
            Ok(v) => Some(v),
            Err(e) => {
                debug!(
                    "Skill {} has unparseable frontmatter (treating as no frontmatter): {e}",
                    path.display()
                );
                None
            }
        })
        .unwrap_or_default();

    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("unnamed");
    let name = parsed_fm.name.unwrap_or_else(|| stem.to_string());

    // Try to lift real argument names out of an `argument-hint` string
    // like "<env>" or "<env> <region>". When that yields nothing usable
    // (free-form hint with no `<token>` pattern), append the raw hint to
    // the description below so the LLM analyzer still sees it — better
    // than fabricating an argument with a placeholder name like "args".
    let hint = parsed_fm
        .argument_hint
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let arguments = hint.and_then(parse_argument_hint);

    // Wire the body into `description` so it flows through every existing
    // prompt-security check that consumes `description` for LLM analysis,
    // formatting, etc. Prepending the frontmatter description (if any)
    // gives the analyzer the author's stated intent right next to what
    // the skill actually says — handy for catching mismatches. When we
    // couldn't parse argument names out of a free-form hint, append the
    // hint here so it isn't silently dropped from the analysis input.
    let fm_description = parsed_fm
        .description
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let body_trimmed = body.trim();

    // Skip skills that have nothing to analyze. A file with no description,
    // no body, and no hint contributes only noise to the LLM batch and
    // crowds the report. We log at debug because users frequently pass
    // directories that contain placeholder files (touched but unwritten).
    if fm_description.is_none() && body_trimmed.is_empty() && hint.is_none() {
        debug!(
            "Skipping {} (empty skill: no description, body, or argument hint)",
            path.display()
        );
        return None;
    }

    let mut parts: Vec<String> = Vec::new();
    if let Some(d) = fm_description {
        parts.push(d.to_string());
    }
    if !body_trimmed.is_empty() {
        parts.push(body_trimmed.to_string());
    }
    if arguments.is_none() {
        if let Some(h) = hint {
            parts.push(format!("Argument hint: {h}"));
        }
    }
    let description = Some(parts.join("\n\n"));
    // Source-path provenance lives on heuristic findings (via the
    // `context` field on `YaraScanResult`) rather than inside the
    // analyzed `description`. Putting absolute paths into text the
    // pre-scan YARA sees triggers spurious matches against rules that
    // flag paths like `/var/` or `/etc/` (path-traversal heuristics);
    // keeping provenance off the analyzed text avoids those false
    // positives while still preserving "which file did this come from"
    // on every parser-emitted finding.

    let prompt = MCPPrompt {
        name,
        description,
        arguments,
        raw_json: None,
    };

    let mut heuristic_findings: Vec<YaraScanResult> = Vec::new();
    if let Some(grant) = parsed_fm.allowed_tools.as_deref() {
        heuristic_findings.extend(analyze_allowed_tools(&prompt.name, path, grant));
    }
    heuristic_findings.extend(analyze_vague_trigger(
        &prompt.name,
        path,
        fm_description,
        body_trimmed,
    ));

    Some(ParsedSkill {
        prompt,
        heuristic_findings,
    })
}

/// Tokens in `allowed-tools` that grant unrestricted shell/filesystem access
/// when granted blanket. Hits here become an `OverbroadAllowedTools`
/// finding that maps to OWASP MCP03 (excessive agency). We deliberately
/// cast a narrow net — the goal is "this skill quietly asked for the keys
/// to the kingdom," not "this skill uses any tool we don't know about."
const DANGEROUS_GRANT_PATTERNS: &[&str] = &[
    "bash(*)", "bash:*", "shell(*)", "shell:*", "rm:*", "rm(*)", "sudo:*", "sudo(*)", "exec:*",
    "exec(*)", "eval:*", "eval(*)", "*",
];

/// Detect overbroad `allowed-tools` grants. The frontmatter is treated as
/// a comma- or newline-separated list of tokens like `Bash(git status:*),
/// Read, Write`. We normalize each token (lowercase, strip whitespace) and
/// flag matches against `DANGEROUS_GRANT_PATTERNS`.
fn analyze_allowed_tools(skill_name: &str, path: &Path, grant: &str) -> Vec<YaraScanResult> {
    let mut findings: Vec<YaraScanResult> = Vec::new();
    let tokens = grant
        .split([',', '\n'])
        .map(|t| t.trim())
        .filter(|t| !t.is_empty());
    for token in tokens {
        let normalized = token.to_ascii_lowercase();
        let normalized_collapsed: String = normalized.split_whitespace().collect();
        if DANGEROUS_GRANT_PATTERNS
            .iter()
            .any(|p| normalized == *p || normalized_collapsed == *p)
        {
            findings.push(make_heuristic_finding(
                "OverbroadAllowedTools",
                "high",
                format!(
                    "Skill '{skill_name}' grants tool '{token}' which permits unrestricted \
                     command execution. Restrict to specific subcommands (e.g. \
                     `Bash(git status:*)`) or remove the wildcard."
                ),
                skill_name,
                path,
            ));
            // One finding per unique pattern keeps the report readable; bail
            // after the first hit on a token rather than emitting one per
            // matching pattern entry.
            continue;
        }
    }
    findings
}

/// Minimum description length that we consider "specific enough." Skills
/// whose stated purpose is shorter than this and whose body is non-trivial
/// risk being invoked unintentionally — the agent's router has nothing to
/// disambiguate on. Tuned by inspecting real skill repos: descriptions
/// under ~24 chars are almost always single-word labels ("deploy", "test")
/// rather than triggers an LLM can match against intent.
const MIN_TRIGGER_DESCRIPTION_CHARS: usize = 24;

/// Body length above which a missing/vague trigger becomes worth flagging.
/// A 50-char body with no description is a stub; a multi-paragraph skill
/// with no description is a real footgun.
const SUBSTANTIVE_BODY_THRESHOLD_CHARS: usize = 200;

/// Detect skills that lack a clear invocation trigger. A skill with a
/// substantial body but no description (or a one-word description) is
/// easy for an agent to invoke by accident. Maps to OWASP MCP02
/// (supply-chain / hidden behavior) and MCP03 (excessive agency).
fn analyze_vague_trigger(
    skill_name: &str,
    path: &Path,
    description: Option<&str>,
    body: &str,
) -> Vec<YaraScanResult> {
    if body.chars().count() < SUBSTANTIVE_BODY_THRESHOLD_CHARS {
        return Vec::new();
    }
    let desc_chars = description.map(|d| d.chars().count()).unwrap_or(0);
    if desc_chars >= MIN_TRIGGER_DESCRIPTION_CHARS {
        return Vec::new();
    }
    let reason = if description.is_none() {
        format!(
            "Skill '{skill_name}' has a substantial body ({} chars) but no `description` \
             frontmatter. Without a clear trigger, an agent may invoke this skill \
             unintentionally. Add a one-line description that disambiguates intent.",
            body.chars().count()
        )
    } else {
        format!(
            "Skill '{skill_name}' has a body ({} chars) but only a {desc_chars}-char \
             description. Expand the description to clearly state when the skill should run.",
            body.chars().count()
        )
    };
    vec![make_heuristic_finding(
        "VagueSkillTrigger",
        "medium",
        reason,
        skill_name,
        path,
    )]
}

/// Build a `YaraScanResult` for a parser-emitted heuristic finding so it
/// rides the same rendering pipeline as real YARA matches. The synthetic
/// rule names are listed in `taxonomy::tags_for_yara_rule` so they pick
/// up OWASP tags too.
fn make_heuristic_finding(
    rule: &'static str,
    severity: &'static str,
    description: String,
    target: &str,
    path: &Path,
) -> YaraScanResult {
    YaraScanResult {
        rule_name: rule.to_string(),
        target_type: "prompt".to_string(),
        target_name: target.to_string(),
        rule_file: Some("skill_parser".to_string()),
        matched_text: None,
        context: format!("source: {}", path.display()),
        rule_metadata: Some(YaraRuleMetadata {
            name: Some(rule.to_string()),
            author: Some("ramparts".to_string()),
            date: None,
            version: Some(env!("CARGO_PKG_VERSION").to_string()),
            description: Some(description),
            severity: Some(severity.to_string()),
            category: Some("skill_security".to_string()),
            confidence: Some("high".to_string()),
            tags: Vec::new(),
        }),
        owasp_tags: crate::taxonomy::tags_for_yara_rule(rule),
        phase: None,
        rules_executed: None,
        security_issues_detected: None,
        total_items_scanned: None,
        total_matches: None,
        status: None,
    }
}

/// Lift argument names out of a Claude Code-style `argument-hint` string.
/// Recognizes `<token>` patterns (the convention for required positional
/// args) and emits one `MCPPromptArgument` per parsed token. Free-form
/// hints with no `<>` markers return `None` so the caller can fall back
/// to embedding the raw hint in the description rather than fabricating
/// argument metadata that isn't in the source.
///
/// Examples:
/// - `"<env>"`              -> `[arg(name="env")]`
/// - `"<env> <region>"`     -> `[arg(name="env"), arg(name="region")]`
/// - `"a free-form hint"`   -> `None`
/// - `"<>"` (empty bracket) -> `None`
fn parse_argument_hint(hint: &str) -> Option<Vec<MCPPromptArgument>> {
    let mut args: Vec<MCPPromptArgument> = Vec::new();
    let mut buf = String::new();
    let mut inside = false;
    for c in hint.chars() {
        match (c, inside) {
            ('<', false) => {
                inside = true;
                buf.clear();
            }
            ('>', true) => {
                let token = buf.trim();
                if !token.is_empty() {
                    args.push(MCPPromptArgument {
                        name: token.to_string(),
                        description: None,
                        required: None,
                    });
                }
                inside = false;
            }
            (_, true) => buf.push(c),
            (_, false) => {} // ignore characters outside of <...>
        }
    }
    if args.is_empty() {
        None
    } else {
        Some(args)
    }
}

/// Split a markdown document into `(frontmatter, body)`. Frontmatter is the
/// optional `---\n...\n---` block at the very top of the file. Anything
/// not matching that exact shape returns `(None, full_input)`.
fn split_frontmatter(raw: &str) -> (Option<&str>, &str) {
    let trimmed = raw.trim_start_matches('\u{feff}'); // strip BOM if present
    let stripped = match trimmed.strip_prefix("---") {
        Some(s) => s,
        None => return (None, raw),
    };
    // Frontmatter must be terminated by a line containing only "---".
    // Search from the next newline so we don't treat the opening "---"
    // as also being the closing marker.
    let after_open = match stripped.find('\n') {
        Some(i) => &stripped[i + 1..],
        None => return (None, raw),
    };
    if let Some(close_idx) = find_frontmatter_close(after_open) {
        let frontmatter = &after_open[..close_idx];
        let body_start = close_idx + after_open[close_idx..].find('\n').map_or(0, |n| n + 1);
        let body = &after_open[body_start..];
        return (Some(frontmatter), body);
    }
    (None, raw)
}

/// Returns the byte index in `s` where a line equal to `---` (with no
/// other content) starts, or `None`. Lines may end in `\n` or `\r\n`.
fn find_frontmatter_close(s: &str) -> Option<usize> {
    let mut start = 0;
    while start <= s.len() {
        let line_end = s[start..].find('\n').map_or(s.len(), |i| start + i);
        let line = s[start..line_end].trim_end_matches('\r');
        if line == "---" {
            return Some(start);
        }
        if line_end == s.len() {
            return None;
        }
        start = line_end + 1;
    }
    None
}

/// Walk `root` for skill files. Recursive; symlinks are not followed;
/// common build directories are skipped (mirrors the directory walker
/// used by `MCPConfigManager::with_root`). Anything ending in `.md` is
/// considered a candidate; the parser is permissive about content.
pub fn discover_skills_in_root(root: &Path) -> Result<Vec<PathBuf>> {
    if !root.exists() {
        return Err(anyhow!(
            "Skill root path does not exist: {}",
            root.display()
        ));
    }
    const SKIP_DIRS: &[&str] = &[
        ".git",
        "node_modules",
        "target",
        "dist",
        "build",
        ".venv",
        "venv",
        "__pycache__",
    ];
    const MAX_DEPTH: usize = 16;

    fn walk(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
        if depth > MAX_DEPTH {
            return;
        }
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_symlink() {
                continue;
            }
            if file_type.is_dir() {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if SKIP_DIRS.contains(&name) {
                        continue;
                    }
                    // Walk dotdirs only when they look like a known skill
                    // location — otherwise we descend into hidden dirs that
                    // aren't relevant (e.g. .vscode, .idea).
                    if name.starts_with('.') && !is_known_skill_dotdir(name) {
                        continue;
                    }
                }
                walk(&path, depth + 1, out);
            } else if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                // Only consider markdown files, and skip files whose names
                // match common non-skill conventions (README, CHANGELOG,
                // LICENSE, etc.) — these almost never represent agent
                // skills and they're a major false-positive source when
                // users point `skills scan` at a repo root.
                if ext.eq_ignore_ascii_case("md") {
                    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                    if is_non_skill_filename(name) {
                        debug!(
                            "Skipping {} (matches non-skill filename convention)",
                            path.display()
                        );
                        continue;
                    }
                    out.push(path);
                }
            }
        }
    }

    /// Dotdirs that are known to host agent skill content — kept in sync
    /// with the IDE config dotdir set in `MCPConfigManager::with_root` so
    /// behavior is consistent across `scan-config --root` and
    /// `skills scan`/`skills scan-config`. Add new ecosystems here as
    /// support grows.
    fn is_known_skill_dotdir(name: &str) -> bool {
        matches!(
            name,
            ".claude" | ".cursor" | ".codex" | ".openai" | ".windsurf" | ".gemini"
        )
    }

    let mut out = Vec::new();
    walk(root, 0, &mut out);
    out.sort();
    Ok(out)
}

/// Default discovery roots when `ramparts skills scan-config` runs with
/// no `--root`. Covers the user- and workspace-level skill directories
/// for the IDE/agent ecosystems we currently support. Operators can
/// supply additional roots via the `RAMPARTS_SKILL_ROOTS` env var
/// (comma-separated paths, `~` expanded) without rebuilding.
///
/// Order is: env-var entries first (operator override), then per-user
/// dotdirs under `$HOME`, then per-workspace dotdirs under the current
/// directory. Duplicates are filtered downstream by canonical-path dedup
/// in the scan handler.
pub fn default_discovery_roots() -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = Vec::new();

    if let Ok(extra) = std::env::var(SKILL_ROOTS_ENV) {
        for entry in extra.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            roots.push(expand_tilde(entry));
        }
    }

    // Per-ecosystem skill directories. These mirror the dotdirs we walk
    // in `is_known_skill_dotdir` so `skills scan-config` (no --root) and
    // `skills scan --path <repo>` cover the same ground.
    const PER_ECOSYSTEM: &[&[&str]] = &[
        &[".claude", "commands"],
        &[".claude", "skills"],
        &[".cursor", "commands"],
        &[".cursor", "skills"],
        &[".codex", "commands"],
        &[".codex", "skills"],
        &[".windsurf", "commands"],
        &[".gemini", "commands"],
        &[".openai", "commands"],
    ];

    if let Some(home) = dirs::home_dir() {
        for segments in PER_ECOSYSTEM {
            let mut p = home.clone();
            for s in *segments {
                p.push(s);
            }
            roots.push(p);
        }
    }
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    for segments in PER_ECOSYSTEM {
        let mut p = cwd.clone();
        for s in *segments {
            p.push(s);
        }
        roots.push(p);
    }
    roots
}

/// Expand a leading `~` or `~/` to the user's home directory. Other
/// `~user` forms aren't expanded (we don't want a libc dependency for
/// something this rarely useful in skill paths).
fn expand_tilde(input: &str) -> PathBuf {
    if let Some(rest) = input.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest);
        }
    } else if input == "~" {
        if let Some(home) = dirs::home_dir() {
            return home;
        }
    }
    PathBuf::from(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn parse(path: &str, raw: &str) -> ParsedSkill {
        parse_skill_content(&PathBuf::from(path), raw).expect("parsed skill")
    }

    #[test]
    fn parses_frontmatter_and_body() {
        let parsed = parse(
            "deploy.md",
            "---\ndescription: Ship to staging\n---\n\nDeploy the app, then notify the channel.\n",
        );
        assert_eq!(parsed.prompt.name, "deploy");
        let desc = parsed.prompt.description.expect("description");
        assert!(desc.contains("Ship to staging"));
        assert!(desc.contains("Deploy the app"));
    }

    #[test]
    fn description_excludes_source_path_to_avoid_yara_false_positives() {
        // Absolute paths inside the analyzed text would trip rules like
        // PathTraversalVulnerability that flag `/var/`, `/etc/`, etc.
        // Provenance lives on parser-emitted findings, not in the text
        // the YARA pre-scan and LLM analyzer see.
        let parsed = parse("/var/folders/xyz/deploy.md", "body");
        let desc = parsed.prompt.description.expect("description");
        assert!(
            !desc.contains("/var/"),
            "description leaked source path: {desc}"
        );
    }

    #[test]
    fn handles_missing_frontmatter() {
        let parsed = parse("no-frontmatter.md", "Just a body, no frontmatter at all.");
        assert_eq!(parsed.prompt.name, "no-frontmatter");
        let desc = parsed.prompt.description.expect("description");
        assert!(desc.contains("Just a body, no frontmatter at all."));
    }

    #[test]
    fn handles_malformed_frontmatter() {
        // Opening `---` with no closing marker — treat as no frontmatter
        // so the malformed YAML doesn't get hidden in `description`.
        let parsed = parse(
            "broken.md",
            "---\nthis is not valid yaml: [oops\n\nbody starts here\n",
        );
        assert_eq!(parsed.prompt.name, "broken");
        assert!(parsed.prompt.description.is_some());
    }

    #[test]
    fn yaml_parse_error_falls_back_to_no_frontmatter() {
        // Closing marker is present but the YAML between them doesn't parse.
        let parsed = parse(
            "badyaml.md",
            "---\nthis is not: valid: yaml: at: all\n---\nbody\n",
        );
        assert_eq!(parsed.prompt.name, "badyaml");
        let desc = parsed.prompt.description.expect("description");
        assert!(desc.contains("body"));
    }

    #[test]
    fn frontmatter_name_overrides_filename() {
        let parsed = parse("ignored.md", "---\nname: actual-name\n---\nhello\n");
        assert_eq!(parsed.prompt.name, "actual-name");
    }

    #[test]
    fn single_argument_hint_token_becomes_named_argument() {
        let parsed = parse(
            "with-args.md",
            "---\ndescription: Greets a user\nargument-hint: <name>\n---\nSay hello to the user.\n",
        );
        let args = parsed.prompt.arguments.expect("arguments");
        assert_eq!(args.len(), 1);
        assert_eq!(args[0].name, "name");
        assert!(args[0].description.is_none());
    }

    #[test]
    fn multiple_argument_hint_tokens_become_separate_arguments() {
        let parsed = parse(
            "multi.md",
            "---\nargument-hint: <env> <region>\n---\nbody\n",
        );
        let args = parsed.prompt.arguments.expect("arguments");
        let names: Vec<_> = args.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names, vec!["env", "region"]);
    }

    #[test]
    fn free_form_argument_hint_falls_back_to_description() {
        let parsed = parse(
            "free-form.md",
            "---\ndescription: Does a thing\nargument-hint: just type your message\n---\nbody\n",
        );
        assert!(parsed.prompt.arguments.is_none());
        let desc = parsed.prompt.description.expect("description");
        assert!(desc.contains("Argument hint: just type your message"));
        assert!(desc.contains("Does a thing"));
        assert!(desc.contains("body"));
    }

    #[test]
    fn empty_brackets_in_hint_yield_no_arguments() {
        let parsed = parse("empty-bracket.md", "---\nargument-hint: <>\n---\nbody\n");
        assert!(parsed.prompt.arguments.is_none());
    }

    #[test]
    fn strips_bom() {
        let parsed = parse("bom.md", "\u{feff}---\ndescription: x\n---\ny\n");
        let desc = parsed.prompt.description.unwrap();
        assert!(desc.contains('x'));
        assert!(desc.contains('y'));
    }

    #[test]
    fn empty_description_in_frontmatter_falls_back_to_body() {
        let parsed = parse(
            "empty-desc.md",
            "---\ndescription: \"\"\n---\nactual body\n",
        );
        let desc = parsed.prompt.description.expect("description");
        assert!(desc.contains("actual body"));
    }

    #[test]
    fn fully_empty_skill_returns_none() {
        let path = PathBuf::from("empty.md");
        // No frontmatter, blank body — nothing to analyze.
        assert!(parse_skill_content(&path, "   \n\t\n").is_none());
        // Empty frontmatter + blank body — same.
        assert!(parse_skill_content(&path, "---\n---\n").is_none());
    }

    #[test]
    fn dangerous_allowed_tools_grant_emits_finding() {
        let parsed = parse(
            "danger.md",
            "---\ndescription: A dangerous skill\nallowed-tools: Bash(*), Read\n---\nrm -rf /\n",
        );
        let rules: Vec<_> = parsed
            .heuristic_findings
            .iter()
            .map(|f| f.rule_name.as_str())
            .collect();
        assert!(
            rules.contains(&"OverbroadAllowedTools"),
            "expected OverbroadAllowedTools, got {rules:?}"
        );
    }

    #[test]
    fn safe_allowed_tools_grant_emits_no_finding() {
        let parsed = parse(
            "safe.md",
            "---\ndescription: A bounded skill\nallowed-tools: Bash(git status:*), Read, Write\n---\nbody\n",
        );
        assert!(parsed
            .heuristic_findings
            .iter()
            .all(|f| f.rule_name != "OverbroadAllowedTools"));
    }

    #[test]
    fn vague_trigger_with_substantial_body_emits_finding() {
        // Substantial body + missing description → flag.
        let body: String = "Do the thing. ".repeat(40);
        let raw = format!("---\nname: noisy\n---\n{body}\n");
        let parsed = parse("noisy.md", &raw);
        assert!(parsed
            .heuristic_findings
            .iter()
            .any(|f| f.rule_name == "VagueSkillTrigger"));
    }

    #[test]
    fn short_body_does_not_trigger_vague_finding() {
        // Stub skills (short body, no description) shouldn't pollute the report.
        let parsed = parse("stub.md", "tiny body");
        assert!(parsed
            .heuristic_findings
            .iter()
            .all(|f| f.rule_name != "VagueSkillTrigger"));
    }

    #[test]
    fn substantive_description_suppresses_vague_finding() {
        let body: String = "Do the thing. ".repeat(40);
        let raw = format!(
            "---\ndescription: Specifically deploys the staging environment after running tests\n---\n{body}\n"
        );
        let parsed = parse("clear.md", &raw);
        assert!(parsed
            .heuristic_findings
            .iter()
            .all(|f| f.rule_name != "VagueSkillTrigger"));
    }

    #[test]
    fn heuristic_findings_carry_owasp_tags() {
        let parsed = parse(
            "danger.md",
            "---\nallowed-tools: rm:*\n---\nA body that is long enough to be considered substantive content for trigger heuristics.\n",
        );
        let overbroad = parsed
            .heuristic_findings
            .iter()
            .find(|f| f.rule_name == "OverbroadAllowedTools")
            .expect("OverbroadAllowedTools finding");
        assert!(
            !overbroad.owasp_tags.is_empty(),
            "OverbroadAllowedTools should carry OWASP tags via taxonomy"
        );
    }

    #[test]
    fn discover_walks_recursively() {
        let tmp = tempfile::tempdir().unwrap();
        let nested = tmp.path().join("a").join("b");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(tmp.path().join("top.md"), "top").unwrap();
        std::fs::write(nested.join("nested.md"), "nested").unwrap();
        std::fs::write(tmp.path().join("not-a-skill.txt"), "ignored").unwrap();

        let mut found = discover_skills_in_root(tmp.path()).unwrap();
        found.sort();
        let names: Vec<_> = found
            .iter()
            .map(|p| p.file_name().unwrap().to_str().unwrap().to_string())
            .collect();
        assert_eq!(names, vec!["nested.md", "top.md"]);
    }

    #[test]
    fn discover_skips_build_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("target");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("artifact.md"), "should be skipped").unwrap();
        std::fs::write(tmp.path().join("real.md"), "should be found").unwrap();

        let found = discover_skills_in_root(tmp.path()).unwrap();
        assert_eq!(found.len(), 1);
        assert!(found[0].ends_with("real.md"));
    }
}
