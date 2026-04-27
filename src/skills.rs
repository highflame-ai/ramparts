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

use crate::types::{MCPPrompt, MCPPromptArgument};
use anyhow::{anyhow, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};
use tracing::{debug, warn};

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
}

/// Parse a single skill file at `path`. Returns `None` (logging at warn)
/// when the file can't be read, exceeds `MAX_SKILL_FILE_BYTES`, or is
/// otherwise unusable. Errors are non-fatal so a single broken skill
/// can't break a directory scan.
pub fn parse_skill_file(path: &Path) -> Option<MCPPrompt> {
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
    Some(parse_skill_content(path, &content))
}

/// Pure-data version of `parse_skill_file` — useful for tests and for
/// callers that already have the content in memory (e.g. fetched from a
/// remote source). Always succeeds: missing fields fall back to sensible
/// defaults derived from the file path.
pub fn parse_skill_content(path: &Path, raw: &str) -> MCPPrompt {
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
    let mut parts: Vec<String> = Vec::new();
    if let Some(d) = parsed_fm.description.as_deref() {
        let d = d.trim();
        if !d.is_empty() {
            parts.push(d.to_string());
        }
    }
    let body_trimmed = body.trim();
    if !body_trimmed.is_empty() {
        parts.push(body_trimmed.to_string());
    }
    if arguments.is_none() {
        if let Some(h) = hint {
            parts.push(format!("Argument hint: {h}"));
        }
    }
    let description = if parts.is_empty() {
        Some(String::new())
    } else {
        Some(parts.join("\n\n"))
    };

    MCPPrompt {
        name,
        description,
        arguments,
        raw_json: None,
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
/// no `--root`. Currently focused on Claude Code commands at both the
/// user and workspace level; other skill ecosystems can be added here as
/// support grows.
pub fn default_discovery_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(home) = dirs::home_dir() {
        roots.push(home.join(".claude").join("commands"));
    }
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    roots.push(cwd.join(".claude").join("commands"));
    roots
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn parses_frontmatter_and_body() {
        let path = PathBuf::from("deploy.md");
        let raw =
            "---\ndescription: Ship to staging\n---\n\nDeploy the app, then notify the channel.\n";
        let prompt = parse_skill_content(&path, raw);
        assert_eq!(prompt.name, "deploy");
        let desc = prompt.description.expect("description");
        assert!(desc.contains("Ship to staging"));
        assert!(desc.contains("Deploy the app"));
    }

    #[test]
    fn handles_missing_frontmatter() {
        let path = PathBuf::from("no-frontmatter.md");
        let raw = "Just a body, no frontmatter at all.";
        let prompt = parse_skill_content(&path, raw);
        assert_eq!(prompt.name, "no-frontmatter");
        assert_eq!(
            prompt.description.as_deref(),
            Some("Just a body, no frontmatter at all.")
        );
    }

    #[test]
    fn handles_malformed_frontmatter() {
        // Opening `---` with no closing marker — treat as no frontmatter
        // so the malformed YAML doesn't get hidden in `description`.
        let path = PathBuf::from("broken.md");
        let raw = "---\nthis is not valid yaml: [oops\n\nbody starts here\n";
        let prompt = parse_skill_content(&path, raw);
        // The opening `---` plus content is treated as the body when no
        // closing marker is found.
        assert_eq!(prompt.name, "broken");
        assert!(prompt.description.is_some());
    }

    #[test]
    fn yaml_parse_error_falls_back_to_no_frontmatter() {
        // Closing marker is present but the YAML between them doesn't parse.
        let path = PathBuf::from("badyaml.md");
        let raw = "---\nthis is not: valid: yaml: at: all\n---\nbody\n";
        let prompt = parse_skill_content(&path, raw);
        assert_eq!(prompt.name, "badyaml");
        // body still extracted
        assert_eq!(prompt.description.as_deref(), Some("body"));
    }

    #[test]
    fn frontmatter_name_overrides_filename() {
        let path = PathBuf::from("ignored.md");
        let raw = "---\nname: actual-name\n---\nhello\n";
        let prompt = parse_skill_content(&path, raw);
        assert_eq!(prompt.name, "actual-name");
    }

    #[test]
    fn single_argument_hint_token_becomes_named_argument() {
        let path = PathBuf::from("with-args.md");
        let raw =
            "---\ndescription: Greets a user\nargument-hint: <name>\n---\nSay hello to the user.\n";
        let prompt = parse_skill_content(&path, raw);
        let args = prompt.arguments.expect("arguments");
        assert_eq!(args.len(), 1);
        assert_eq!(args[0].name, "name");
        // We deliberately don't fabricate a description for the
        // synthesized argument — the source hint goes in the prompt's
        // description, not on every parsed token.
        assert!(args[0].description.is_none());
    }

    #[test]
    fn multiple_argument_hint_tokens_become_separate_arguments() {
        let path = PathBuf::from("multi.md");
        let raw = "---\nargument-hint: <env> <region>\n---\nbody\n";
        let prompt = parse_skill_content(&path, raw);
        let args = prompt.arguments.expect("arguments");
        let names: Vec<_> = args.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names, vec!["env", "region"]);
    }

    #[test]
    fn free_form_argument_hint_falls_back_to_description() {
        // No `<token>` pattern -> we don't fabricate an argument name;
        // instead we surface the hint in the description so LLM analysis
        // still sees it.
        let path = PathBuf::from("free-form.md");
        let raw =
            "---\ndescription: Does a thing\nargument-hint: just type your message\n---\nbody\n";
        let prompt = parse_skill_content(&path, raw);
        assert!(prompt.arguments.is_none());
        let desc = prompt.description.expect("description");
        assert!(desc.contains("Argument hint: just type your message"));
        assert!(desc.contains("Does a thing"));
        assert!(desc.contains("body"));
    }

    #[test]
    fn empty_brackets_in_hint_yield_no_arguments() {
        let path = PathBuf::from("empty-bracket.md");
        let raw = "---\nargument-hint: <>\n---\nbody\n";
        let prompt = parse_skill_content(&path, raw);
        assert!(prompt.arguments.is_none());
    }

    #[test]
    fn strips_bom() {
        let path = PathBuf::from("bom.md");
        let raw = "\u{feff}---\ndescription: x\n---\ny\n";
        let prompt = parse_skill_content(&path, raw);
        let desc = prompt.description.unwrap();
        assert!(desc.contains('x'));
        assert!(desc.contains('y'));
    }

    #[test]
    fn empty_description_in_frontmatter_falls_back_to_body() {
        let path = PathBuf::from("empty-desc.md");
        let raw = "---\ndescription: \"\"\n---\nactual body\n";
        let prompt = parse_skill_content(&path, raw);
        assert_eq!(prompt.description.as_deref(), Some("actual body"));
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
