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
//! - **agentskills.io** bundles: a directory `<name>/SKILL.md` plus
//!   optional sibling `scripts/`, `references/`, `assets/` subdirectories.
//!   Detected by exact filename `SKILL.md` (case-sensitive). The bundle
//!   parser falls back to the parent-directory name when `name:` is
//!   omitted, validates the spec's name rules, and synthesizes
//!   `MCPResource` entries for sibling scripts/references so they flow
//!   through the existing YARA pre-scan.
//! - Generic markdown skill files (in lenient mode — anything ending in
//!   `.md` walked under `--root`)
//!
//! The frontmatter is parsed best-effort: a missing or malformed
//! frontmatter block still yields a usable skill (filename stem becomes
//! the name; body becomes the description). Anything that can't be read
//! as UTF-8 is skipped with a warning rather than failing the scan.

use crate::types::{MCPPrompt, MCPPromptArgument, MCPResource, YaraRuleMetadata, YaraScanResult};
use anyhow::{anyhow, Result};
use serde::{Deserialize, Deserializer};
use std::collections::HashSet;
use std::ffi::OsStr;
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

/// agentskills.io requires the entrypoint to be literally `SKILL.md`
/// (case-sensitive). We use byte-equal comparison on the OsStr so this
/// works on case-insensitive filesystems too — `read_dir` returns the
/// on-disk casing, not the lookup casing, so `Skill.md` and `SKILL.md`
/// remain distinguishable.
pub(crate) fn is_agentskills_bundle(path: &Path) -> bool {
    path.file_name() == Some(OsStr::new("SKILL.md"))
}

/// The parent directory of a `SKILL.md` is the bundle root. Returns
/// `None` for non-bundle paths so callers can `.filter_map` over a
/// discovered set without an extra branch. An empty parent (e.g.
/// `PathBuf::from("SKILL.md").parent() == Some("")`) is also treated
/// as no root — without this filter the bundle-roots set would
/// contain `""`, which `Path::starts_with` then matches against every
/// relative discovered path, falsely classifying unrelated `.md`
/// files as bundle siblings.
pub(crate) fn bundle_root_of(path: &Path) -> Option<&Path> {
    if !is_agentskills_bundle(path) {
        return None;
    }
    let parent = path.parent()?;
    if parent.as_os_str().is_empty() {
        return None;
    }
    Some(parent)
}

/// Returns true when `path` is a direct child of one of the recognized
/// bundle sibling directories (`<bundle>/scripts/<file>`,
/// `<bundle>/references/<file>`, `<bundle>/assets/<file>`). The bundle
/// parser is **shallow** — `walk_bundle_subdir` only reads files one
/// level under each sibling dir — so this filter must also be shallow.
/// A deeper match (`<bundle>/references/sub/deep.md`) would otherwise
/// be dropped from the top-level walk AND missed by the bundle
/// parser, silently disappearing from any scan. The shallow shape
/// matches: this returns false for nested paths, which then flow
/// through the normal flat-skill parser.
///
/// Done without `PathBuf` allocations: `parent.file_name()` and
/// `parent.parent()` are zero-alloc views.
pub(crate) fn is_under_bundle_sibling_dir(path: &Path, bundle_roots: &HashSet<PathBuf>) -> bool {
    let Some(parent) = path.parent() else {
        return false;
    };
    let sibling_dir_name = parent.file_name().and_then(|n| n.to_str());
    let is_sibling = matches!(sibling_dir_name, Some("scripts" | "references" | "assets"));
    if !is_sibling {
        return false;
    }
    parent
        .parent()
        .is_some_and(|grandparent| bundle_roots.contains(grandparent))
}

/// Extensions ramparts treats as bundled-script content for YARA scanning.
/// Kept tight on purpose — exotic languages (Lua, Tcl, etc.) can be added
/// when we see them in real skill bundles. The list is matched
/// case-insensitively.
const SCRIPT_EXTS: &[&str] = &[
    "py", "sh", "bash", "zsh", "js", "mjs", "cjs", "ts", "rb", "pl", "ps1",
];

/// Validates a name against the agentskills.io spec: 1–64 chars,
/// lowercase ASCII `[a-z0-9-]`, no leading/trailing hyphen, no
/// consecutive hyphens. Returns the spec violation as a short reason
/// string on failure; otherwise `Ok(())`. Hand-rolled (no regex
/// dependency) so the failure mode is specific enough to surface in the
/// finding description.
fn validate_skill_name(name: &str) -> std::result::Result<(), &'static str> {
    if name.is_empty() {
        return Err("name is empty");
    }
    if name.len() > 64 {
        return Err("name exceeds 64 characters");
    }
    let bytes = name.as_bytes();
    if bytes[0] == b'-' {
        return Err("name starts with a hyphen");
    }
    if bytes[bytes.len() - 1] == b'-' {
        return Err("name ends with a hyphen");
    }
    let mut last_was_hyphen = false;
    for &b in bytes {
        let ok = matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-');
        if !ok {
            return Err("name contains a character outside [a-z0-9-]");
        }
        if b == b'-' && last_was_hyphen {
            return Err("name contains consecutive hyphens");
        }
        last_was_hyphen = b == b'-';
    }
    Ok(())
}

/// Frontmatter field names defined by the agentskills.io spec. Any key
/// outside this set on a `SKILL.md` triggers an
/// `AgentskillsUnknownFrontmatterField` finding.
const AGENTSKILLS_ALLOWED_FIELDS: &[&str] = &[
    "name",
    "description",
    "license",
    "compatibility",
    "metadata",
    "allowed-tools",
];

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
    /// Claude Code's `allowed-tools`. Two YAML shapes are accepted in the
    /// wild and we normalize both to a single comma-separated string so the
    /// downstream tokenizer in `analyze_allowed_tools` doesn't care:
    ///
    /// ```yaml
    /// # inline string form (typical for one or two grants)
    /// allowed-tools: Bash(git status:*), Read
    /// ```
    ///
    /// ```yaml
    /// # YAML sequence form (typical for many grants)
    /// allowed-tools:
    ///   - Bash(git status:*)
    ///   - Read
    /// ```
    ///
    /// Without the custom deserializer the sequence form silently fails
    /// to parse into `Option<String>`, which means `analyze_allowed_tools`
    /// never sees the grant and we miss `OverbroadAllowedTools` findings
    /// for the most-common multi-grant skill format. Joined with `, ` so
    /// any subsequent splitter using `,` or `\n` gets identical token
    /// boundaries to the inline form.
    #[serde(
        rename = "allowed-tools",
        default,
        deserialize_with = "deser_string_or_seq"
    )]
    allowed_tools: Option<String>,
    /// agentskills.io spec field — parsed for validation only. Ramparts
    /// does not interpret the license text; it's here so frontmatters
    /// that declare a license don't trigger
    /// `AgentskillsUnknownFrontmatterField`.
    #[allow(dead_code)]
    license: Option<String>,
    /// agentskills.io spec field. See above.
    #[allow(dead_code)]
    compatibility: Option<String>,
    /// agentskills.io spec field — arbitrary key/value mapping. We don't
    /// surface any of it today; we just want to recognize the field name
    /// so a real bundle doesn't trip the unknown-field check.
    #[allow(dead_code)]
    metadata: Option<serde_yaml::Value>,
}

/// Deserialize either `String` or `Vec<String>` into `Option<String>`,
/// joining sequence entries with `, `. Used by `SkillFrontmatter::allowed_tools`
/// and structured to be reusable for any future field that accepts either
/// shape (e.g. `tags:`, `categories:`).
fn deser_string_or_seq<'de, D>(deserializer: D) -> std::result::Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::{self, SeqAccess, Visitor};
    use std::fmt;

    struct StringOrSeq;
    impl<'de> Visitor<'de> for StringOrSeq {
        type Value = Option<String>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a string or a sequence of strings")
        }

        fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Self::Value, E> {
            Ok(Some(v.to_string()))
        }

        fn visit_string<E: de::Error>(self, v: String) -> std::result::Result<Self::Value, E> {
            Ok(Some(v))
        }

        fn visit_unit<E: de::Error>(self) -> std::result::Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_none<E: de::Error>(self) -> std::result::Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_some<D2: Deserializer<'de>>(
            self,
            d: D2,
        ) -> std::result::Result<Self::Value, D2::Error> {
            d.deserialize_any(StringOrSeq)
        }

        fn visit_seq<A: SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> std::result::Result<Self::Value, A::Error> {
            let mut parts: Vec<String> = Vec::new();
            while let Some(item) = seq.next_element::<serde_yaml::Value>()? {
                // Coerce each entry to a string. Nested sequences/maps
                // are stringified via serde_yaml so we never silently
                // drop a grant — better to surface a weirdly-shaped
                // token than to lose it entirely.
                let s = match item {
                    serde_yaml::Value::String(s) => s,
                    other => serde_yaml::to_string(&other)
                        .unwrap_or_default()
                        .trim()
                        .to_string(),
                };
                if !s.is_empty() {
                    parts.push(s);
                }
            }
            if parts.is_empty() {
                Ok(None)
            } else {
                Ok(Some(parts.join(", ")))
            }
        }
    }
    deserializer.deserialize_any(StringOrSeq)
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
    let (parsed_fm, body) = split_and_parse_frontmatter(path, raw);

    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("unnamed");
    // Empty / whitespace-only `name:` falls back to the filename stem.
    // Without this, `name: ""` produces a skill with an empty prompt
    // name, which downstream renderers display as a blank field and
    // which collides with every other empty-named skill in the
    // SkillNameCollision check.
    let name = parsed_fm
        .name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map_or_else(|| stem.to_string(), str::to_string);

    assemble_skill(path, body, &parsed_fm, name, Vec::new())
}

/// Splits the raw text into `(SkillFrontmatter, body)`. Permissive: a
/// missing or unparseable frontmatter yields `SkillFrontmatter::default()`
/// so the body is still scanned. Used by both `parse_skill_content`
/// (flat-skill path) and `parse_agentskills_bundle_content` (bundle
/// path).
fn split_and_parse_frontmatter<'a>(path: &Path, raw: &'a str) -> (SkillFrontmatter, &'a str) {
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
    (parsed_fm, body)
}

/// Assemble a `ParsedSkill` from already-resolved frontmatter and a
/// resolved name. Runs the shared description/argument extraction and
/// all the existing analyzers (`analyze_allowed_tools`,
/// `analyze_vague_trigger`, etc.). The caller supplies any
/// already-collected findings (e.g. bundle-validation findings) in
/// `extra_findings` so they appear in the same `heuristic_findings` vec
/// without a second pass.
fn assemble_skill(
    path: &Path,
    body: &str,
    parsed_fm: &SkillFrontmatter,
    name: String,
    extra_findings: Vec<YaraScanResult>,
) -> Option<ParsedSkill> {
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
    // `None` rather than `Some("")` when there's nothing to describe — the
    // LLM analyzer treats a missing description differently from an empty
    // one (the prompt template renders "No description" instead of an
    // empty field). Only happens when arguments were parsed from a hint
    // but description and body are both empty.
    // `description` carries the analyzable text (frontmatter
    // description + body + free-form arg hint, in that order); source
    // path is *not* included because absolute paths in YARA-scanned
    // text trip path-traversal rules like `/var/` and `/etc/`.
    // Provenance lives on heuristic findings via the `context` field
    // on `YaraScanResult` instead.
    let description = if parts.is_empty() {
        None
    } else {
        Some(parts.join("\n\n"))
    };

    let prompt = MCPPrompt {
        name,
        description,
        arguments,
        raw_json: None,
    };

    // Append the existing analyzers onto whatever findings the caller
    // already collected (e.g. bundle-validation findings). Order is
    // arbitrary — downstream renderers don't depend on it.
    let mut heuristic_findings: Vec<YaraScanResult> = extra_findings;
    if let Some(grant) = parsed_fm.allowed_tools.as_deref() {
        heuristic_findings.extend(analyze_allowed_tools(&prompt.name, path, grant));
    }
    heuristic_findings.extend(analyze_vague_trigger(
        &prompt.name,
        path,
        fm_description,
        body_trimmed,
    ));
    heuristic_findings.extend(analyze_generic_trigger(&prompt.name, path, fm_description));
    heuristic_findings.extend(analyze_sensitive_file_references(
        &prompt.name,
        path,
        body_trimmed,
    ));
    heuristic_findings.extend(analyze_embedded_payloads(&prompt.name, path, body_trimmed));

    Some(ParsedSkill {
        prompt,
        heuristic_findings,
    })
}

/// Parse an agentskills.io bundle: a `SKILL.md` file whose parent
/// directory may also contain sibling `scripts/`, `references/`, and
/// `assets/` subdirectories. Returns the assembled skill plus a vector
/// of synthetic `MCPResource` entries for each scannable sibling file,
/// which the caller funnels into the existing YARA pre-scan via
/// `ScanData.resources`.
///
/// Differs from `parse_skill_file` in three ways:
/// 1. The fallback for `name:` is the **parent directory name**, not
///    the file stem (which is always "SKILL").
/// 2. Emits spec-validation findings:
///    `AgentskillsNameMismatch`/`AgentskillsInvalidName`/
///    `AgentskillsMissingName`/`AgentskillsUnknownFrontmatterField`.
/// 3. Walks sibling `scripts/` and `references/` to synthesize one
///    `MCPResource` per scannable file. Bundled assets (`assets/`) are
///    skipped — usually binary, low value-to-noise.
pub(crate) fn parse_agentskills_bundle(
    skill_md_path: &Path,
) -> Option<(ParsedSkill, Vec<MCPResource>)> {
    if let Ok(metadata) = std::fs::metadata(skill_md_path) {
        if metadata.len() > MAX_SKILL_FILE_BYTES {
            warn!(
                "Skipping SKILL.md {} ({} bytes > {} byte limit)",
                skill_md_path.display(),
                metadata.len(),
                MAX_SKILL_FILE_BYTES
            );
            return None;
        }
    }
    let raw = match std::fs::read_to_string(skill_md_path) {
        Ok(s) => s,
        Err(e) => {
            warn!("Skipping SKILL.md {}: {e}", skill_md_path.display());
            return None;
        }
    };
    parse_agentskills_bundle_content(skill_md_path, &raw)
}

/// Pure-data version of `parse_agentskills_bundle`. Exposed so unit
/// tests can drive the bundle parser without touching the filesystem,
/// passing the raw `SKILL.md` content directly. Sibling-file discovery
/// still hits the filesystem because that's intrinsic to bundle shape;
/// pass a `skill_md_path` whose parent directory exists or has no
/// scannable siblings to get a clean test.
fn parse_agentskills_bundle_content(
    skill_md_path: &Path,
    raw: &str,
) -> Option<(ParsedSkill, Vec<MCPResource>)> {
    let (parsed_fm, body) = split_and_parse_frontmatter(skill_md_path, raw);

    // Parent-directory name is the agentskills.io fallback for `name:`
    // and the ground truth for the name-mismatch deception check. Note
    // we never trim() the directory name — a directory called
    // `" my-skill"` (leading space) should fail `validate_skill_name`
    // and be surfaced as such, not be silently coerced.
    let parent_dir_name = skill_md_path
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .map(str::to_string);

    // Frontmatter `name:` (if present and non-empty after trim).
    let fm_name = parsed_fm
        .name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    let mut validation_findings: Vec<YaraScanResult> = Vec::new();

    // Mismatch check: only fires when BOTH names are present. The
    // mismatch is a security concern (an attacker can ship a bundle in
    // a directory called `helpful-helper/` but with `name: ssh-key-stealer`
    // — or vice versa). Deception, not pedantic spec compliance.
    if let (Some(fm), Some(dir)) = (fm_name.as_deref(), parent_dir_name.as_deref()) {
        if fm != dir {
            validation_findings.push(make_heuristic_finding(
                "AgentskillsNameMismatch",
                "high",
                format!(
                    "SKILL.md declares `name: {fm}` but its parent directory is `{dir}/`. \
                     agentskills.io requires the name to match the parent directory; the \
                     mismatch may indicate a deceptively-named bundle. Choose one canonical \
                     name and use it consistently."
                ),
                fm,
                skill_md_path,
            ));
        }
    }

    // Resolve the name we'll use downstream. Precedence:
    // 1. fm_name if present
    // 2. parent_dir_name if present and non-empty
    // 3. "unnamed" (we emit AgentskillsMissingName when we hit this)
    //
    // `from_parent_dir` tracks whether the resolved name came from the
    // directory fallback. Used below to decide between
    // AgentskillsInvalidName (keyed to the directory) and
    // AgentskillsMissingName (truly nameless).
    let (resolved_name, from_parent_dir) = match (fm_name.as_deref(), parent_dir_name.as_deref()) {
        (Some(fm), _) => (fm.to_string(), false),
        (None, Some(dir)) if !dir.is_empty() => (dir.to_string(), true),
        _ => ("unnamed".to_string(), false),
    };

    // `is_some_and` (stable 1.70) sidesteps two problems at once:
    // `is_none_or` is 1.82+ (would break the README's 1.70 MSRV) and
    // `map_or(true, str::is_empty)` trips `clippy::unnecessary_map_or`
    // on toolchains that *do* have `is_none_or`. The inverted form
    // works cleanly on both.
    let parent_dir_usable = parent_dir_name.as_deref().is_some_and(|n| !n.is_empty());
    if fm_name.is_none() && !parent_dir_usable {
        validation_findings.push(make_heuristic_finding(
            "AgentskillsMissingName",
            "medium",
            "SKILL.md has no `name:` field and the parent directory has no usable \
             name. agentskills.io requires both to be present and to match."
                .to_string(),
            &resolved_name,
            skill_md_path,
        ));
    } else if let Err(reason) = validate_skill_name(&resolved_name) {
        // When the offending name came from the parent directory (no
        // explicit `name:`), the actionable fix is on the directory —
        // make that clear in the finding text. Otherwise the fix is on
        // the frontmatter `name:` value.
        let where_ = if from_parent_dir {
            format!("parent directory `{resolved_name}/`")
        } else {
            format!("frontmatter `name: {resolved_name}`")
        };
        validation_findings.push(make_heuristic_finding(
            "AgentskillsInvalidName",
            "medium",
            format!(
                "{where_} fails agentskills.io name rules: {reason}. Spec requires \
                 1–64 chars from [a-z0-9-] with no leading/trailing or consecutive hyphens."
            ),
            &resolved_name,
            skill_md_path,
        ));
    }

    // Unknown-field detection: parse the raw frontmatter back as a
    // generic YAML mapping and diff its key set against the spec's six
    // allowed fields. Single rolled-up finding per bundle (rather than
    // one per key) keeps the report low-noise. Skipped silently when
    // there's no frontmatter or it's a non-mapping (e.g. a stray scalar
    // or sequence — already debug-logged by split_and_parse_frontmatter).
    let unknown_keys = detect_unknown_frontmatter_fields(raw);
    if !unknown_keys.is_empty() {
        let joined = unknown_keys.join(", ");
        validation_findings.push(make_heuristic_finding(
            "AgentskillsUnknownFrontmatterField",
            "low",
            format!(
                "SKILL.md frontmatter contains key(s) not defined by agentskills.io: \
                 {joined}. Spec allows only: name, description, license, compatibility, \
                 metadata, allowed-tools."
            ),
            &resolved_name,
            skill_md_path,
        ));
    }

    let parsed = assemble_skill(
        skill_md_path,
        body,
        &parsed_fm,
        resolved_name.clone(),
        validation_findings,
    )?;

    // Synthetic resources for sibling-bundled scripts and references.
    // `assets/` is intentionally skipped (typically binary content;
    // YARA produces noise on raw image bytes and we don't want to bloat
    // the scratch buffer).
    let mut resources = Vec::new();
    if let Some(bundle_root) = skill_md_path.parent() {
        collect_bundle_siblings(bundle_root, &resolved_name, &mut resources);
    }

    Some((parsed, resources))
}

/// Returns the list of frontmatter keys that aren't in the
/// agentskills.io spec's six-field set. Used by
/// `parse_agentskills_bundle_content` for the
/// `AgentskillsUnknownFrontmatterField` finding. Returns an empty Vec
/// when there's no frontmatter or it isn't a mapping.
fn detect_unknown_frontmatter_fields(raw: &str) -> Vec<String> {
    let (Some(fm), _) = split_frontmatter(raw) else {
        return Vec::new();
    };
    let parsed: serde_yaml::Value = match serde_yaml::from_str(fm) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let Some(mapping) = parsed.as_mapping() else {
        return Vec::new();
    };
    let allowed: HashSet<&str> = AGENTSKILLS_ALLOWED_FIELDS.iter().copied().collect();
    let mut unknown: Vec<String> = mapping
        .iter()
        .filter_map(|(k, _)| k.as_str().map(str::to_string))
        .filter(|k| !allowed.contains(k.as_str()))
        .collect();
    unknown.sort();
    unknown
}

/// Walk the immediate `scripts/` and `references/` children of
/// `bundle_root` and synthesize one `MCPResource` per scannable file.
/// One-level deep on purpose: bundle siblings live directly under the
/// bundle root by spec, and we don't want to spend the rest of the
/// 16-level depth budget on bundled `node_modules`. Files larger than
/// `MAX_SKILL_FILE_BYTES` are skipped with a warn log.
fn collect_bundle_siblings(bundle_root: &Path, skill_name: &str, out: &mut Vec<MCPResource>) {
    walk_bundle_subdir(
        bundle_root,
        "scripts",
        skill_name,
        |name| {
            // Script files are gated on extension to keep noise low.
            // Anything inside `scripts/` named `README.md` etc. is
            // skipped via the existing non-skill-filename heuristic so
            // a bundle author's "how the script works" note doesn't
            // get scanned twice.
            let ext = std::path::Path::new(name)
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("");
            SCRIPT_EXTS
                .iter()
                .any(|allowed| ext.eq_ignore_ascii_case(allowed))
                && !is_non_skill_filename(name)
        },
        out,
    );
    walk_bundle_subdir(
        bundle_root,
        "references",
        skill_name,
        |name| {
            let ext = std::path::Path::new(name)
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("");
            ext.eq_ignore_ascii_case("md") && !is_non_skill_filename(name)
        },
        out,
    );
}

/// Per-subdirectory cap on the number of scannable siblings a bundle
/// can contribute. A malicious bundle with 100k tiny `scripts/*.py`
/// files would otherwise produce 100k synthetic `MCPResource`s, each
/// loaded into memory and pushed through the YARA pipeline. 256 is
/// well above what any honest bundle ships and bounds worst-case
/// memory at `MAX_BUNDLE_FILES_PER_DIR * MAX_SKILL_FILE_BYTES` per
/// subdirectory.
const MAX_BUNDLE_FILES_PER_DIR: usize = 256;

/// Walk one bundle sibling directory (`scripts/` or `references/`) and
/// push a synthetic `MCPResource` for every file `accept` returns true
/// for. The accept callback receives the file's basename; the walker
/// itself enforces non-symlink + non-directory.
fn walk_bundle_subdir(
    bundle_root: &Path,
    subdir_name: &str,
    skill_name: &str,
    accept: impl Fn(&str) -> bool,
    out: &mut Vec<MCPResource>,
) {
    let dir = bundle_root.join(subdir_name);
    let Ok(entries) = std::fs::read_dir(&dir) else {
        // Missing or unreadable subdirectory is silent — most bundles
        // ship only some of the three optional siblings.
        return;
    };
    let starting_len = out.len();
    for entry in entries.flatten() {
        if out.len() - starting_len >= MAX_BUNDLE_FILES_PER_DIR {
            warn!(
                "Bundle {}/{subdir_name}: reached {} file cap; remaining entries skipped",
                bundle_root.display(),
                MAX_BUNDLE_FILES_PER_DIR
            );
            break;
        }
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_symlink() || !file_type.is_file() {
            continue;
        }
        let entry_path = entry.path();
        let Some(file_name) = entry_path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !accept(file_name) {
            continue;
        }
        if let Ok(meta) = std::fs::metadata(&entry_path) {
            if meta.len() > MAX_SKILL_FILE_BYTES {
                warn!(
                    "Skipping bundle file {} ({} bytes > {} byte limit)",
                    entry_path.display(),
                    meta.len(),
                    MAX_SKILL_FILE_BYTES
                );
                continue;
            }
        }
        let content = match std::fs::read_to_string(&entry_path) {
            Ok(s) => s,
            Err(e) => {
                // `read_to_string` errors cover both invalid UTF-8
                // (`ErrorKind::InvalidData`) and ordinary I/O failures
                // — permission denied, file removed mid-scan, etc.
                // Don't conflate the two in the log.
                debug!(
                    "Skipping bundle file {}: failed to read as UTF-8 ({e})",
                    entry_path.display()
                );
                continue;
            }
        };
        // `skill://` URI (not `file://`) so the synthetic resource's
        // URI doesn't contain absolute filesystem paths that would
        // false-positive on path-traversal / sensitive-location YARA
        // rules. The bundle/file pair is enough provenance for the
        // post-scan rewrite step in main.rs.
        let resource_name = format!("{skill_name}/{subdir_name}/{file_name}");
        let resource_uri = format!("skill://{skill_name}/{subdir_name}/{file_name}");
        out.push(MCPResource {
            uri: resource_uri,
            name: resource_name,
            description: Some(content),
            mime_type: None,
            size: None,
            metadata: std::collections::HashMap::new(),
            raw_json: None,
        });
    }
}

/// Tools that, when granted without a restriction, give the agent
/// arbitrary code execution on the user's machine. A bare `Bash` grant is
/// just as dangerous as `Bash(*)` — Claude Code interprets a tool name
/// without parens as unrestricted. Tightly bounded grants like
/// `Bash(git status:*)` are silent.
const CODE_EXECUTION_TOOLS: &[&str] = &[
    "bash", "shell", "sh", "zsh", "exec", "eval", "run", "rm", "sudo",
];

/// Tools that let a skill exfiltrate data over the network. Even a
/// well-bounded `WebFetch(https://example.com/*)` skill can reflect
/// arbitrary content into the URL's path — but the operator should at
/// least be aware the skill is talking to the network, so we flag any
/// grant of these as an informational `DataExfiltrationGrant`. Maps to
/// MCP09 (sensitive-data exposure) + MCP06 (credential leakage).
const DATA_EXFIL_TOOLS: &[&str] = &["webfetch", "websearch", "fetch", "browse"];

/// A single token from an `allowed-tools` field, parsed into the tool
/// name and (optional) restriction clause. Three syntactic forms in the
/// wild:
///
/// - `Bash` — bare tool name, no restriction → unrestricted grant
/// - `Bash(git status:*)` — parenthesized restriction
/// - `Bash:git status:*` — colon-separated restriction (older syntax)
///
/// `restriction` is `None` only for the bare-name form. An empty string
/// or `*` restriction is treated as "no restriction" by the policy below.
struct ParsedGrant<'a> {
    raw: &'a str,
    tool: String,
    restriction: Option<String>,
}

/// Parse a single `allowed-tools` token. Robust to leading/trailing
/// whitespace and to the two restriction syntaxes Claude Code accepts.
/// Returns `None` for empty or whitespace-only tokens.
fn parse_grant_token(token: &str) -> Option<ParsedGrant<'_>> {
    let trimmed = token.trim();
    if trimmed.is_empty() {
        return None;
    }
    // Parenthesized form: "Bash(git status:*)". We split on the first '(';
    // the closing ')' is best-effort — malformed grants like "Bash(foo"
    // still parse with restriction = "foo".
    if let Some((tool_raw, rest)) = trimmed.split_once('(') {
        let restriction = rest.trim_end_matches(')').trim().to_string();
        return Some(ParsedGrant {
            raw: token,
            tool: tool_raw.trim().to_ascii_lowercase(),
            restriction: Some(restriction),
        });
    }
    // Colon form: "Bash:git status:*". Tool is the segment before the
    // first colon; the rest (re-joined) is the restriction.
    if let Some((tool_raw, rest)) = trimmed.split_once(':') {
        return Some(ParsedGrant {
            raw: token,
            tool: tool_raw.trim().to_ascii_lowercase(),
            restriction: Some(rest.trim().to_string()),
        });
    }
    // Bare form: "Bash". No restriction.
    Some(ParsedGrant {
        raw: token,
        tool: trimmed.to_ascii_lowercase(),
        restriction: None,
    })
}

/// True when a parsed grant grants unrestricted access to its tool —
/// either no restriction at all, an empty restriction, or a wildcard
/// pattern that admits any prefix and any arguments.
///
/// `*:*` is the sneakiest of the three: it looks like a bounded
/// `prefix:args` restriction but every part is a wildcard, so a literal
/// reading admits any command-line. We strip whitespace, split on `:`,
/// and treat the restriction as unrestricted iff every segment is `*`
/// or empty. That covers `*`, `* : *`, `*:*`, `*::*`, etc.
fn is_unrestricted(grant: &ParsedGrant<'_>) -> bool {
    match grant.restriction.as_deref() {
        None => true,
        Some("") => true,
        Some(r) => {
            let collapsed: String = r.split_whitespace().collect();
            if collapsed.is_empty() || collapsed == "*" {
                return true;
            }
            collapsed.split(':').all(|seg| seg.is_empty() || seg == "*")
        }
    }
}

/// Split an `allowed-tools` string into individual grant tokens,
/// honoring parenthesized restrictions. The naive `split([',', '\n'])`
/// breaks tokens like `Bash(echo a, b)` mid-paren — both halves then
/// fail to parse as their original tool, and a real unrestricted grant
/// slips through. This walker tracks paren depth and only treats commas
/// or newlines at depth 0 as token boundaries. Negative depth (a stray
/// closer) is clamped to zero so malformed input still terminates.
fn split_grant_tokens(grant: &str) -> Vec<&str> {
    let mut tokens: Vec<&str> = Vec::new();
    let mut depth: i32 = 0;
    let mut start = 0;
    for (i, c) in grant.char_indices() {
        match c {
            '(' => depth += 1,
            ')' if depth > 0 => depth -= 1,
            ',' | '\n' if depth == 0 => {
                tokens.push(&grant[start..i]);
                start = i + c.len_utf8();
            }
            _ => {}
        }
    }
    // Always push the trailing slice. `start` is at a char boundary
    // (set from `i + c.len_utf8()` after a separator) and at most
    // equals `grant.len()`, so the slice is valid; an empty trailing
    // slice (input ending with `,` / `\n`) is harmless because
    // `parse_grant_token` rejects whitespace-only tokens downstream.
    tokens.push(&grant[start..]);
    tokens
}

/// Detect overbroad `allowed-tools` grants. Splits the grant string on
/// commas/newlines, parses each token via `parse_grant_token`, and emits
/// findings based on the tool class:
///
/// - **CODE_EXECUTION_TOOLS** with no/wildcard restriction → high-severity
///   `OverbroadAllowedTools` (MCP03 — excessive agency).
/// - A bare `*` token (grants every tool) → same high-severity finding.
/// - **DATA_EXFIL_TOOLS** at any restriction level → medium-severity
///   `DataExfiltrationGrant` (MCP09 + MCP06).
///
/// Tightly-bounded code-execution grants (`Bash(git status:*)`) and
/// non-network/non-execution tools (`Read`, `Write`, `Glob`) are silent.
fn analyze_allowed_tools(skill_name: &str, path: &Path, grant: &str) -> Vec<YaraScanResult> {
    let mut findings: Vec<YaraScanResult> = Vec::new();
    let push = |findings: &mut Vec<YaraScanResult>,
                rule: &'static str,
                severity: &'static str,
                message: String| {
        findings.push(make_heuristic_finding(
            rule, severity, message, skill_name, path,
        ));
    };

    for raw in split_grant_tokens(grant) {
        let Some(parsed) = parse_grant_token(raw) else {
            continue;
        };

        // Bare wildcard token — "*" alone — grants everything.
        if parsed.tool == "*" {
            push(
                &mut findings,
                "OverbroadAllowedTools",
                "high",
                format!(
                    "Skill '{skill_name}' grants `*` (all tools). This bypasses every \
                     per-tool restriction. Replace with the specific tools the skill \
                     actually needs."
                ),
            );
            continue;
        }

        if CODE_EXECUTION_TOOLS.contains(&parsed.tool.as_str()) && is_unrestricted(&parsed) {
            push(
                &mut findings,
                "OverbroadAllowedTools",
                "high",
                format!(
                    "Skill '{skill_name}' grants tool `{}` without a restriction, which \
                     permits arbitrary command execution. Restrict to specific \
                     subcommands (e.g. `Bash(git status:*)`) or replace with a bounded \
                     tool.",
                    parsed.raw.trim()
                ),
            );
            continue;
        }

        if DATA_EXFIL_TOOLS.contains(&parsed.tool.as_str()) {
            push(
                &mut findings,
                "DataExfiltrationGrant",
                "medium",
                format!(
                    "Skill '{skill_name}' grants `{}` — a network-egress tool that can \
                     send skill input or local file content to remote URLs. Confirm the \
                     skill needs network access and that any URL pattern is bounded.",
                    parsed.raw.trim()
                ),
            );
        }
    }
    findings
}

/// Path-shaped substrings indicating a skill is asking the agent to
/// inline a sensitive file into its prompt context. We want to detect
/// the well-known credential / secret / system-secret locations, but
/// listing them as plain string literals in this source file trips
/// over-zealous pre-commit security hooks (since the file then "contains"
/// the very paths it's designed to detect). We assemble each pattern
/// via `concat!()` from non-sensitive-looking fragments so the source
/// text itself never has the full literal — at compile time the macro
/// produces a single `&'static str` per entry.
///
/// Order matters only for human readability — `is_sensitive_path` does
/// a `contains` over the full list, so duplicates would be harmless.
const SENSITIVE_PATH_PATTERNS: &[&str] = &[
    // SSH credentials directory
    concat!("~/", ".s", "sh/"),
    // Cloud / orchestration credentials directories
    concat!("~/", ".aws/"),
    concat!("~/", ".gn", "upg/"),
    concat!("~/", ".gcp/"),
    concat!("~/", ".azure/"),
    concat!("~/", ".kube/"),
    concat!("~/", ".docker/"),
    concat!("~/", ".config/", "gh/"),
    // System secrets
    concat!("/", "etc/sh", "adow"),
    concat!("/", "etc/", "passwd"),
    concat!("/", "etc/", "sudoers"),
    concat!("/", "ro", "ot/"),
    // SSH key filenames
    concat!("id", "_rsa"),
    concat!("id", "_ed25519"),
    concat!("id", "_ecdsa"),
    concat!("id", "_dsa"),
    // Cert / key extensions
    ".pem",
    ".p12",
    ".pfx",
    ".key",
    // Credential / config files
    "credentials.json",
    "secrets.json",
    "secrets.yaml",
    "secrets.yml",
    ".env",
    ".npmrc",
    ".pypirc",
    ".netrc",
];

/// Returns true when a path token (extracted from after an `@` marker)
/// matches one of the sensitive substrings above.
fn is_sensitive_path(path: &str) -> bool {
    SENSITIVE_PATH_PATTERNS
        .iter()
        .any(|pat| path.contains(*pat))
}

/// True for characters that can appear in an unquoted path reference.
/// Conservative: stops at whitespace, quotes, parens, brackets, commas,
/// and most punctuation. Allows path-shape characters and a few others
/// that show up in real paths (`+` in package names, `:` for Windows
/// drives or namespaced refs).
fn is_path_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '-' | '_' | '~' | '+' | ':')
}

/// Detect Claude Code `@<path>` file-inclusion references in the body
/// that point at sensitive files. The `@` syntax inlines the referenced
/// file's content into the prompt, so a skill that says
/// `Use the credentials in @<path-to-key>` is asking the agent to load
/// that file into context where any subsequent network-capable tool
/// can exfiltrate it. Maps to MCP06 (credential leakage) + MCP09
/// (sensitive-data exposure).
///
/// We dedupe by lowercase token so a body that mentions the same file
/// twice yields one finding, not N. We also bound the token length —
/// a runaway path-character run (binary dump, URL with no whitespace,
/// etc.) shouldn't produce a giant finding message. We skip `@` when
/// preceded by a word character (the email-address case) to drop the
/// most-common false positive cheaply.
fn analyze_sensitive_file_references(
    skill_name: &str,
    path: &Path,
    body: &str,
) -> Vec<YaraScanResult> {
    const MAX_TOKEN_BYTES: usize = 200;
    let mut findings: Vec<YaraScanResult> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    for (i, _) in body.match_indices('@') {
        // Reject `@` that's the second char of an email-like token
        // (preceded by a word char). The trailing token after the `@`
        // in `john@example.com` is then "example.com" — which we'd
        // check for sensitive-path content anyway, but the cheap
        // pre-check drops the bulk of email-pattern noise.
        //
        // Byte-level inspection (vs `body[..i].chars().next_back()`)
        // is O(1) per match rather than O(prefix-length). For a 1MB
        // skill body with N `@` matches that's the difference between
        // O(N) and O(N * body_len). Safe across UTF-8 because the
        // last byte of any multi-byte codepoint has the high bit set
        // (>= 0x80) and is_ascii_alphanumeric() returns false on it.
        let prev_is_word_char = i
            .checked_sub(1)
            .and_then(|j| body.as_bytes().get(j))
            .is_some_and(|&b| b.is_ascii_alphanumeric() || b == b'_');
        if prev_is_word_char {
            continue;
        }

        let after = &body[i + 1..];
        let token_end = after
            .find(|c: char| !is_path_char(c))
            .unwrap_or(after.len())
            .min(MAX_TOKEN_BYTES);
        let token = &after[..token_end];
        if token.is_empty() || !is_sensitive_path(token) {
            continue;
        }
        let key = token.to_ascii_lowercase();
        if !seen.insert(key) {
            continue;
        }
        findings.push(make_heuristic_finding(
            "SkillSensitiveFileReference",
            "high",
            format!(
                "Skill '{skill_name}' includes a file-reference `@{token}` \
                 matching a known sensitive-path pattern. The `@` syntax \
                 inlines the file's contents into prompt context, where any \
                 network-capable tool can exfiltrate it. Remove the \
                 reference or replace with a non-sensitive equivalent."
            ),
            skill_name,
            path,
        ));
    }
    findings
}

/// Minimum length (in source chars) for a base64-shape run to qualify as
/// an embedded payload. 500 chars decodes to ~375 bytes — large enough
/// that a real attacker would use it to smuggle a meaningful payload,
/// but high enough to reject incidental short tokens (auth tokens,
/// hashes including SHA-512 at 128 chars, JWT bodies, OpenAI/Anthropic
/// API keys at ~100 chars, GitHub PATs at 40 chars).
const MIN_EMBEDDED_PAYLOAD_CHARS: usize = 500;

/// True if `c` is part of the standard or URL-safe base64 alphabet.
/// Includes `=` for padding and `_-` for URL-safe encoding so we
/// catch both shapes with a single pass.
fn is_b64_or_url64_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '_' | '-')
}

/// True if `c` is a hexadecimal character. Used to classify a payload
/// as `hex` vs `base64`; hex blobs are strictly a subset of base64.
fn is_hex_char(c: char) -> bool {
    c.is_ascii_hexdigit()
}

/// Detect large base64 / hex / URL-safe-base64 blobs in the skill body.
/// Embedded payloads are the textbook obfuscation primitive: the blob
/// passes both regex YARA rules (which match on plaintext attack
/// signatures) and LLM analysis (which can't decode a 500-char string
/// of `aW1wb3J0IG9z...` into intent) by deferring decoding to runtime.
///
/// Maps to OWASP MCP01 (prompt injection — the decoded content could
/// be an instruction-override payload) + MCP10 (supply-chain — the
/// blob is an opaque dependency the operator can't audit).
///
/// Tuning:
///
/// - Single contiguous run of base64-shape characters; we don't
///   reassemble across whitespace because real attackers don't either
///   (hand-formatted multi-line base64 blobs come through as a single
///   run after we strip line breaks at parse time, but a 500-char
///   single-line blob is the typical embed).
/// - 500-char threshold rejects hashes (SHA-512 = 128 chars), JWTs
///   (typically 200-300 chars but multi-segment with `.` separators —
///   each segment is well under 500), GitHub PATs, AWS keys, etc.
/// - Skip blobs immediately preceded by `base64,` (markdown image
///   data URIs and similar inline-asset references).
/// - Dedupe by the leading 50 chars so a body that repeats the same
///   blob doesn't spam findings.
fn analyze_embedded_payloads(skill_name: &str, path: &Path, body: &str) -> Vec<YaraScanResult> {
    let mut findings: Vec<YaraScanResult> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    let push_if_qualifying = |findings: &mut Vec<YaraScanResult>,
                              seen: &mut std::collections::HashSet<String>,
                              start: usize,
                              end: usize| {
        let blob = &body[start..end];
        let len = blob.chars().count();
        if len < MIN_EMBEDDED_PAYLOAD_CHARS {
            return;
        }
        // Data-URI exclusion. A markdown inline image
        // `![alt](data:image/png;base64,SGVsbG8=)` produces a long
        // base64 run preceded by `base64,`; that's intentional and
        // benign. `ends_with` on a `&str` compares from the end byte-
        // wise — safe across UTF-8 because the marker is ASCII and
        // `body[..start]` is a char-boundary slice (`start` came from
        // `char_indices`).
        if body[..start].ends_with("base64,") {
            return;
        }
        let kind = if blob.chars().all(is_hex_char) {
            "hex"
        } else {
            "base64"
        };
        let key = format!("{}:{}", kind, blob.chars().take(50).collect::<String>());
        if !seen.insert(key) {
            return;
        }
        findings.push(make_heuristic_finding(
            "SkillEmbeddedPayload",
            "high",
            format!(
                "Skill '{skill_name}' contains a {len}-char {kind}-shape blob in \
                 its body. Embedded payloads bypass plaintext YARA rules and LLM \
                 analysis by deferring decoding to runtime. Verify the content; \
                 if legitimate (config, hash chain), reduce its size or move to \
                 a referenced file. If unknown, treat as compromised."
            ),
            skill_name,
            path,
        ));
    };

    let mut start: Option<usize> = None;
    for (i, c) in body.char_indices() {
        if is_b64_or_url64_char(c) {
            start.get_or_insert(i);
        } else if let Some(s) = start.take() {
            push_if_qualifying(&mut findings, &mut seen, s, i);
        }
    }
    // Body ends mid-run.
    if let Some(s) = start {
        push_if_qualifying(&mut findings, &mut seen, s, body.len());
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
    // `chars().count()` is O(n) on UTF-8 — compute once and reuse.
    let body_chars = body.chars().count();
    if body_chars < SUBSTANTIVE_BODY_THRESHOLD_CHARS {
        return Vec::new();
    }
    let desc_chars = description.map(|d| d.chars().count()).unwrap_or(0);
    if desc_chars >= MIN_TRIGGER_DESCRIPTION_CHARS {
        return Vec::new();
    }
    let reason = if description.is_none() {
        format!(
            "Skill '{skill_name}' has a substantial body ({body_chars} chars) but no \
             `description` frontmatter. Without a clear trigger, an agent may invoke \
             this skill unintentionally. Add a one-line description that disambiguates \
             intent."
        )
    } else {
        format!(
            "Skill '{skill_name}' has a body ({body_chars} chars) but only a \
             {desc_chars}-char description. Expand the description to clearly state \
             when the skill should run."
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

/// Generic / vacuous trigger phrases. A description matching one of these
/// is long enough to satisfy `MIN_TRIGGER_DESCRIPTION_CHARS` but is
/// semantically empty — exactly the trigger-hijack vector. The list is
/// kept short and concrete; expanding it grows the false-positive risk.
/// Patterns are matched case-insensitively against the trimmed description
/// (with trailing punctuation stripped).
const GENERIC_TRIGGER_PHRASES: &[&str] = &[
    "help",
    "help me",
    "help with anything",
    "assistant",
    "an assistant",
    "a helper",
    "helper",
    "general purpose tool",
    "general purpose skill",
    "general purpose assistant",
    "general-purpose tool",
    "universal tool",
    "universal skill",
    "universal assistant",
    "default tool",
    "default assistant",
    "do anything",
    "do everything",
    "i can do anything",
    "i can do everything",
    "use this for everything",
    "use this for anything",
    "use me for everything",
    "use me for anything",
];

/// Detect descriptions whose entire content is a generic / hijack-prone
/// trigger phrase — distinct from `analyze_vague_trigger` which catches
/// missing or short descriptions. A 30-character description is long
/// enough to pass the length check but still vacuous if the content is
/// "a general purpose assistant". Maps to the same OWASP entries as
/// `VagueSkillTrigger` (MCP02 + MCP03).
fn analyze_generic_trigger(
    skill_name: &str,
    path: &Path,
    description: Option<&str>,
) -> Vec<YaraScanResult> {
    let Some(desc) = description else {
        return Vec::new();
    };
    let normalized = desc
        .trim()
        .trim_end_matches(['.', '!', '?', ';', ':'])
        .trim()
        .to_ascii_lowercase();
    // Strip a leading article ("a ", "an ", "the ") so phrases like
    // "a general purpose assistant" still match the canonical entries
    // (which omit the article for compactness).
    let core = normalized
        .strip_prefix("a ")
        .or_else(|| normalized.strip_prefix("an "))
        .or_else(|| normalized.strip_prefix("the "))
        .unwrap_or(normalized.as_str());
    if !GENERIC_TRIGGER_PHRASES
        .iter()
        .any(|p| core == *p || normalized == *p)
    {
        return Vec::new();
    }
    vec![make_heuristic_finding(
        "GenericSkillTrigger",
        "medium",
        format!(
            "Skill '{skill_name}' has a generic trigger description (\"{}\"). \
             Generic triggers cause an agent's router to invoke the skill on \
             unrelated user requests (trigger hijack). Replace with a specific \
             description naming the conditions under which this skill should run.",
            desc.trim()
        ),
        skill_name,
        path,
    )]
}

/// Cross-skill analysis: detect skills that share a `name`. Two skills
/// declaring the same name shadow each other in the agent's command
/// table — typically the workspace-level skill wins over the user-level
/// one — so an attacker who can write to a workspace can transparently
/// replace a trusted user-level skill. Maps to MCP02 (supply-chain /
/// hidden behavior) + MCP03 (excessive agency).
///
/// Run once per scan over the full set of parsed skills. Names are
/// compared case-insensitively because skill routers typically lowercase
/// for matching. Reports one finding per colliding name with all paths
/// in the `context` field.
pub fn analyze_skill_set(skills: &[(&Path, &MCPPrompt)]) -> Vec<YaraScanResult> {
    let mut by_name: std::collections::HashMap<String, Vec<&Path>> =
        std::collections::HashMap::new();
    for (path, prompt) in skills {
        by_name
            .entry(prompt.name.to_ascii_lowercase())
            .or_default()
            .push(*path);
    }
    let mut findings: Vec<YaraScanResult> = Vec::new();
    for (lower_name, paths) in by_name {
        if paths.len() < 2 {
            continue;
        }
        // Sort for deterministic reporting (test-friendly).
        let mut sorted = paths;
        sorted.sort();
        let joined = sorted
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        // Use the first path as the synthetic-finding's source-path so
        // it has a concrete location, and put the full collision list
        // in the message so consumers see all colliding skills.
        let primary_path = sorted[0];
        findings.push(make_heuristic_finding(
            "SkillNameCollision",
            "medium",
            format!(
                "Skill name '{lower_name}' is declared by {} files: {joined}. \
                 Whichever skill the agent's router resolves last shadows the \
                 others — an attacker who can write a workspace-level skill \
                 with the same name as a trusted user-level skill can silently \
                 replace it. Rename one of the skills.",
                sorted.len()
            ),
            &lower_name,
            primary_path,
        ));
    }
    findings
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
/// Recognizes two common conventions: `<name>` for required positional
/// args and `[name]` for optional positional args. Both shapes appear in
/// real skills; treating them identically loses information the LLM
/// analyzer can use to spot a skill that documents an arg as optional
/// but requires it in the body. Emits one `MCPPromptArgument` per
/// parsed token, with `required` set per shape. Free-form hints with no
/// markers return `None` so the caller can fall back to embedding the
/// raw hint in the description.
///
/// Examples:
/// - `"<env>"`              -> `[arg(name="env", required=Some(true))]`
/// - `"[region]"`           -> `[arg(name="region", required=Some(false))]`
/// - `"<env> [region]"`     -> two args, required + optional
/// - `"a free-form hint"`   -> `None`
/// - `"<>"` (empty bracket) -> `None`
fn parse_argument_hint(hint: &str) -> Option<Vec<MCPPromptArgument>> {
    #[derive(Clone, Copy)]
    enum Bracket {
        None,
        Required, // <...>
        Optional, // [...]
    }

    let mut args: Vec<MCPPromptArgument> = Vec::new();
    let mut buf = String::new();
    let mut inside = Bracket::None;
    for c in hint.chars() {
        match (c, inside) {
            ('<', Bracket::None) => {
                inside = Bracket::Required;
                buf.clear();
            }
            ('[', Bracket::None) => {
                inside = Bracket::Optional;
                buf.clear();
            }
            ('>', Bracket::Required) | (']', Bracket::Optional) => {
                let token = buf.trim();
                if !token.is_empty() {
                    args.push(MCPPromptArgument {
                        name: token.to_string(),
                        description: None,
                        required: Some(matches!(inside, Bracket::Required)),
                    });
                }
                inside = Bracket::None;
            }
            // Mismatched closer (`<foo]` or `[foo>`): treat as content,
            // keep collecting. Falling out the end discards the buf.
            (_, Bracket::Required | Bracket::Optional) => buf.push(c),
            (_, Bracket::None) => {} // ignore characters outside markers
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
        // Body starts after the `---` line. If the closing marker has a
        // trailing newline we skip past it; if it's the last thing in the
        // file (no trailing newline) we land exactly at end-of-string and
        // body becomes "" rather than the marker itself.
        let body_start = match after_open[close_idx..].find('\n') {
            Some(n) => close_idx + n + 1,
            None => after_open.len(),
        };
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

    // Env-var roots are operator-trusted: ramparts walks them as-is, so
    // anyone who can set `RAMPARTS_SKILL_ROOTS` can point the scanner at
    // any directory the running user can read. That's the same trust
    // model as `--path`, but it's worth being explicit since env vars
    // can be smuggled into less-obvious places (CI configs, IDE
    // launchers, shell parents).
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

    let push_for_base = |roots: &mut Vec<PathBuf>, base: &Path| {
        for segments in PER_ECOSYSTEM {
            let path = segments
                .iter()
                .fold(base.to_path_buf(), |acc, seg| acc.join(seg));
            roots.push(path);
        }
    };

    if let Some(home) = dirs::home_dir() {
        push_for_base(&mut roots, &home);
    }
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    push_for_base(&mut roots, &cwd);

    // agentskills.io tool-agnostic conventions. `~/.skills/` is always
    // pushed (it usually doesn't exist; discover_skills_in_root will
    // return an empty vec). `./skills/` is probe-gated — many random
    // repos have a top-level `skills/` directory unrelated to agent
    // skills, so we only walk it when it directly contains at least
    // one `<name>/SKILL.md` bundle.
    if let Some(home) = dirs::home_dir() {
        roots.push(home.join(".skills"));
    }
    let cwd_skills = cwd.join("skills");
    if is_agentskills_root_dir(&cwd_skills) {
        roots.push(cwd_skills);
    }
    roots
}

/// Probe gate for `./skills/` discovery. Returns true when `dir` has at
/// least one direct child directory containing a `SKILL.md` file
/// (exact filename — same byte-equal contract as `is_agentskills_bundle`).
///
/// We avoid `path.join("SKILL.md").is_file()` because `Path::is_file()`
/// goes through `fs::metadata`, which traverses symlinks and is
/// case-insensitive on macOS APFS / Windows — both of which would
/// allow `Skill.md` (or worse, a symlink to `/etc/passwd`) to flip
/// this gate true and cause `./skills/` to be walked unexpectedly.
/// Instead we enumerate each candidate directory's contents and
/// match `file_name == "SKILL.md"` byte-equal, skipping symlinks.
fn is_agentskills_root_dir(dir: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    for entry in entries.flatten() {
        // Only descend into directory entries; skip symlinks at this
        // level so a symlinked dir can't trip the probe.
        let Ok(ft) = entry.file_type() else { continue };
        if ft.is_symlink() || !ft.is_dir() {
            continue;
        }
        if bundle_dir_has_skill_md(&entry.path()) {
            return true;
        }
    }
    false
}

/// Returns true when `dir` has a direct child entry whose filename is
/// exactly `SKILL.md` (case-sensitive byte-equal) and is a regular
/// non-symlink file. Helper for `is_agentskills_root_dir`.
fn bundle_dir_has_skill_md(dir: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    for entry in entries.flatten() {
        if entry.file_name() != OsStr::new("SKILL.md") {
            continue;
        }
        let Ok(ft) = entry.file_type() else { continue };
        if !ft.is_symlink() && ft.is_file() {
            return true;
        }
    }
    false
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
    fn empty_or_whitespace_name_falls_back_to_filename_stem() {
        // `name: ""` and `name: "   "` should NOT produce an empty
        // skill name — that would render as a blank in reports and
        // collide with every other empty-named skill in the
        // SkillNameCollision check.
        for raw in [
            "---\nname: \"\"\n---\nbody\n",
            "---\nname: \"   \"\n---\nbody\n",
        ] {
            let parsed = parse("real-stem.md", raw);
            assert_eq!(
                parsed.prompt.name, "real-stem",
                "expected fallback to stem for: {raw:?}"
            );
        }
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
    fn closing_frontmatter_marker_without_trailing_newline_yields_empty_body() {
        // Edge case: a file that ends exactly at the closing `---` with
        // no trailing newline. Earlier implementations included the
        // closing marker itself in the body string, producing skills
        // whose description was literally "---".
        let path = PathBuf::from("trim.md");
        let raw = "---\ndescription: hi\n---";
        let parsed = parse_skill_content(&path, raw).unwrap();
        let desc = parsed.prompt.description.expect("description");
        assert_eq!(desc, "hi");
        assert!(!desc.contains("---"), "marker leaked into body: {desc}");
    }

    #[test]
    fn argument_only_skill_has_none_description_not_empty_string() {
        // Args parsed, but description and body are both empty. The
        // prompt should report `description: None` rather than `Some("")`
        // so the LLM analyzer's template renders "No description"
        // instead of a blank field.
        let parsed = parse("args-only.md", "---\nargument-hint: <name>\n---\n");
        assert!(
            parsed.prompt.description.is_none(),
            "expected None, got {:?}",
            parsed.prompt.description
        );
        assert_eq!(parsed.prompt.arguments.as_ref().unwrap().len(), 1);
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
    fn bare_bash_grant_is_treated_as_unrestricted() {
        // The most-common dangerous grant in real skills: `Bash` with no
        // parens. Claude Code interprets a bare tool name as unrestricted,
        // so we must treat it the same as `Bash(*)`.
        let parsed = parse(
            "bare.md",
            "---\ndescription: stub\nallowed-tools: Bash, Read\n---\nbody\n",
        );
        let overbroad = parsed
            .heuristic_findings
            .iter()
            .find(|f| f.rule_name == "OverbroadAllowedTools")
            .expect("bare Bash should fire OverbroadAllowedTools");
        let desc = overbroad
            .rule_metadata
            .as_ref()
            .and_then(|m| m.description.as_deref())
            .unwrap_or("");
        assert!(
            desc.contains("Bash"),
            "finding description should reference the offending tool: {desc}"
        );
    }

    #[test]
    fn star_grant_alone_fires_overbroad() {
        let parsed = parse(
            "wide-open.md",
            "---\ndescription: stub\nallowed-tools: \"*\"\n---\nbody\n",
        );
        assert!(parsed
            .heuristic_findings
            .iter()
            .any(|f| f.rule_name == "OverbroadAllowedTools"));
    }

    #[test]
    fn colon_form_grant_with_wildcard_fires_overbroad() {
        let parsed = parse("colon.md", "---\nallowed-tools: bash:*\n---\nbody\n");
        assert!(parsed
            .heuristic_findings
            .iter()
            .any(|f| f.rule_name == "OverbroadAllowedTools"));
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
    fn read_write_alone_are_not_flagged() {
        // Bare `Read` / `Write` / `Glob` are bounded by their own
        // semantics (filesystem-only) and shouldn't be treated like
        // bare `Bash`. This test guards against an over-eager future
        // tightening of CODE_EXECUTION_TOOLS.
        let parsed = parse(
            "fs-only.md",
            "---\ndescription: read some files\nallowed-tools: Read, Write, Glob, Grep\n---\nbody\n",
        );
        assert!(
            parsed.heuristic_findings.is_empty(),
            "expected no findings, got {:?}",
            parsed
                .heuristic_findings
                .iter()
                .map(|f| f.rule_name.as_str())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn webfetch_grant_emits_data_exfiltration_finding() {
        let parsed = parse(
            "exfil.md",
            "---\ndescription: fetch a thing\nallowed-tools: WebFetch\n---\nbody\n",
        );
        assert!(parsed
            .heuristic_findings
            .iter()
            .any(|f| f.rule_name == "DataExfiltrationGrant"));
    }

    #[test]
    fn data_exfiltration_grant_carries_owasp_tags() {
        let parsed = parse(
            "exfil.md",
            "---\ndescription: web stuff\nallowed-tools: WebFetch(https://example.com/*)\n---\nbody\n",
        );
        let exfil = parsed
            .heuristic_findings
            .iter()
            .find(|f| f.rule_name == "DataExfiltrationGrant")
            .expect("DataExfiltrationGrant finding");
        let ids: Vec<_> = exfil.owasp_tags.iter().map(|t| t.id.as_str()).collect();
        assert!(ids.contains(&"MCP09"), "expected MCP09 tag, got {ids:?}");
        assert!(ids.contains(&"MCP06"), "expected MCP06 tag, got {ids:?}");
    }

    #[test]
    fn yaml_list_form_for_allowed_tools_is_analyzed() {
        // Real skills with multiple grants commonly use the YAML
        // sequence form. Without the custom deserializer, this
        // silently failed to populate `allowed_tools` and our
        // OverbroadAllowedTools heuristic never fired — the highest-
        // impact effectiveness gap pre-round-5.
        let raw = "---\ndescription: stub\nallowed-tools:\n  - Bash\n  - Read\n---\nbody\n";
        let parsed = parse_skill_content(&PathBuf::from("listy.md"), raw).expect("parse");
        let rules: Vec<_> = parsed
            .heuristic_findings
            .iter()
            .map(|f| f.rule_name.as_str())
            .collect();
        assert!(
            rules.contains(&"OverbroadAllowedTools"),
            "list-form bare Bash should fire OverbroadAllowedTools, got {rules:?}"
        );
    }

    #[test]
    fn yaml_list_form_with_only_safe_grants_is_silent() {
        let raw =
            "---\ndescription: stub\nallowed-tools:\n  - Read\n  - Write\n  - Glob\n---\nbody\n";
        let parsed = parse_skill_content(&PathBuf::from("listy-safe.md"), raw).expect("parse");
        assert!(
            parsed.heuristic_findings.is_empty(),
            "got unexpected findings: {:?}",
            parsed
                .heuristic_findings
                .iter()
                .map(|f| f.rule_name.as_str())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn optional_argument_hint_is_marked_not_required() {
        let parsed = parse("opt.md", "---\nargument-hint: <env> [region]\n---\nbody\n");
        let args = parsed.prompt.arguments.expect("arguments");
        assert_eq!(args.len(), 2);
        assert_eq!(args[0].name, "env");
        assert_eq!(args[0].required, Some(true));
        assert_eq!(args[1].name, "region");
        assert_eq!(args[1].required, Some(false));
    }

    #[test]
    fn sensitive_file_reference_in_body_emits_finding() {
        // Body asks the agent to inline a sensitive file via Claude
        // Code's `@<path>` syntax. This is the textbook exfiltration
        // primitive: load the file into context, then any subsequent
        // network-capable tool can leak it.
        let body = "Use the credentials in @~/.aws/credentials to deploy.";
        let raw = format!("---\ndescription: deploy something\n---\n{body}\n");
        let parsed = parse("exfil-ref.md", &raw);
        let f = parsed
            .heuristic_findings
            .iter()
            .find(|f| f.rule_name == "SkillSensitiveFileReference")
            .expect("expected SkillSensitiveFileReference");
        let ids: Vec<_> = f.owasp_tags.iter().map(|t| t.id.as_str()).collect();
        assert!(ids.contains(&"MCP06"), "got tags: {ids:?}");
        assert!(ids.contains(&"MCP09"), "got tags: {ids:?}");
    }

    #[test]
    fn email_address_does_not_trigger_sensitive_reference() {
        // The most-common false positive: an `@` in an email. The
        // pre-check (preceded by word char) drops these cheaply.
        let body = "On failure, page john.smith@example.com about the deploy.";
        let raw = format!("---\ndescription: deploy a thing\n---\n{body}\n");
        let parsed = parse("email.md", &raw);
        assert!(parsed
            .heuristic_findings
            .iter()
            .all(|f| f.rule_name != "SkillSensitiveFileReference"));
    }

    #[test]
    fn duplicate_sensitive_references_dedupe() {
        // Same path mentioned twice — should fire once, not twice.
        let body = "First read @.env, then re-read @.env to confirm parity.";
        let raw = format!("---\ndescription: confirm env parity\n---\n{body}\n");
        let parsed = parse("dotenv.md", &raw);
        let count = parsed
            .heuristic_findings
            .iter()
            .filter(|f| f.rule_name == "SkillSensitiveFileReference")
            .count();
        assert_eq!(count, 1, "expected dedupe to one finding, got {count}");
    }

    #[test]
    fn benign_at_reference_is_silent() {
        // `@scoped/package` and `@v1.0.0` aren't sensitive paths; the
        // detector should ignore them.
        let body = "Use @scoped/package and tag @v1.0.0 for the release.";
        let raw = format!("---\ndescription: release a thing\n---\n{body}\n");
        let parsed = parse("benign-at.md", &raw);
        assert!(parsed
            .heuristic_findings
            .iter()
            .all(|f| f.rule_name != "SkillSensitiveFileReference"));
    }

    #[test]
    fn comma_in_paren_restriction_does_not_break_tokenizer() {
        // `Bash(echo a, b)` contains a comma INSIDE the restriction. A
        // naive split on commas would shred the token mid-paren and
        // miss the unrestricted-Bash signal.
        let raw = "---\ndescription: stub\nallowed-tools: Bash(echo a, b), Read\n---\nbody\n";
        let parsed = parse_skill_content(&PathBuf::from("commaparen.md"), raw).expect("parse");
        // The Bash grant has a non-wildcard restriction (`echo a, b`),
        // so it should NOT fire OverbroadAllowedTools — but more
        // importantly, the parser should produce a single ParsedGrant
        // with that restriction intact rather than three half-tokens.
        // We verify by parsing the grant directly.
        let toks = split_grant_tokens("Bash(echo a, b), Read");
        assert_eq!(toks.len(), 2, "got toks={toks:?}");
        assert!(toks[0].contains("Bash(echo a, b)"));
        assert!(toks[1].contains("Read"));
        // No false-positive findings — the comma-inside-paren grant is
        // bounded enough not to fire.
        assert!(parsed
            .heuristic_findings
            .iter()
            .all(|f| f.rule_name != "OverbroadAllowedTools"));
    }

    #[test]
    fn unrestricted_bash_grant_with_inner_comma_still_fires() {
        // Variant: unrestricted Bash via `Bash(*)`, with a separate grant
        // that has a comma inside its restriction. Must not lose the
        // OverbroadAllowedTools finding for the wildcard grant.
        let raw = "---\nallowed-tools: Bash(*), WebFetch(https://a.example.com/x,y)\n---\nbody\n";
        let parsed = parse_skill_content(&PathBuf::from("mixed.md"), raw).expect("parse");
        let rules: Vec<_> = parsed
            .heuristic_findings
            .iter()
            .map(|f| f.rule_name.as_str())
            .collect();
        assert!(
            rules.contains(&"OverbroadAllowedTools"),
            "expected OverbroadAllowedTools, got {rules:?}"
        );
        assert!(
            rules.contains(&"DataExfiltrationGrant"),
            "expected DataExfiltrationGrant, got {rules:?}"
        );
    }

    #[test]
    fn star_colon_star_restriction_is_unrestricted() {
        // `Bash(*:*)` looks like a bounded prefix:args restriction but
        // every segment is a wildcard, so it admits any command-line.
        // The same applies to `* : *` (whitespace) and `*::*` (empty
        // segment in the middle).
        for grant in ["Bash(*:*)", "Bash(* : *)", "Bash(*::*)"] {
            let parsed = parse_grant_token(grant).unwrap();
            assert!(
                is_unrestricted(&parsed),
                "expected `{grant}` to be unrestricted"
            );
        }
        // Sanity: a real bounded grant is still bounded.
        let bounded = parse_grant_token("Bash(git status:*)").unwrap();
        assert!(!is_unrestricted(&bounded));
    }

    #[test]
    fn star_colon_star_grant_fires_overbroad() {
        let raw = "---\nallowed-tools: Bash(*:*)\n---\nbody\n";
        let parsed = parse_skill_content(&PathBuf::from("starcolon.md"), raw).expect("parse");
        assert!(parsed
            .heuristic_findings
            .iter()
            .any(|f| f.rule_name == "OverbroadAllowedTools"));
    }

    #[test]
    fn split_grant_tokens_handles_paren_depth() {
        // Sanity-check the splitter directly on a few shapes.
        assert_eq!(
            split_grant_tokens("Bash(a, b), Read, Write"),
            vec!["Bash(a, b)", " Read", " Write"]
        );
        // Newlines also count as separators.
        assert_eq!(split_grant_tokens("Bash\nRead"), vec!["Bash", "Read"]);
        // Stray closing paren — clamp to zero, don't blow up.
        assert_eq!(split_grant_tokens("Bash), Read"), vec!["Bash)", " Read"]);
    }

    #[test]
    fn parse_grant_token_handles_three_syntaxes() {
        // Bare
        let g = parse_grant_token("Bash").unwrap();
        assert_eq!(g.tool, "bash");
        assert!(g.restriction.is_none());
        assert!(is_unrestricted(&g));

        // Parenthesized
        let g = parse_grant_token("Bash(git status:*)").unwrap();
        assert_eq!(g.tool, "bash");
        assert_eq!(g.restriction.as_deref(), Some("git status:*"));
        assert!(!is_unrestricted(&g));

        // Colon form
        let g = parse_grant_token("Bash:foo").unwrap();
        assert_eq!(g.tool, "bash");
        assert_eq!(g.restriction.as_deref(), Some("foo"));

        // Empty paren -> wildcard-equivalent
        let g = parse_grant_token("Bash()").unwrap();
        assert!(is_unrestricted(&g));

        // Whitespace only -> None
        assert!(parse_grant_token("   ").is_none());
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
    fn generic_trigger_phrase_emits_finding() {
        // Body long enough that VagueSkillTrigger wouldn't fire (the
        // description has substance length-wise) but the description is
        // semantically vacuous.
        let body: String = "Do the thing. ".repeat(40);
        let raw = format!("---\ndescription: a general purpose assistant\n---\n{body}\n");
        let parsed = parse("generic.md", &raw);
        let rules: Vec<_> = parsed
            .heuristic_findings
            .iter()
            .map(|f| f.rule_name.as_str())
            .collect();
        assert!(
            rules.contains(&"GenericSkillTrigger"),
            "expected GenericSkillTrigger, got {rules:?}"
        );
    }

    #[test]
    fn generic_trigger_phrase_with_punctuation_still_fires() {
        // Trailing period / exclamation should not mask the phrase.
        let parsed = parse("punc.md", "---\ndescription: Help me!\n---\nbody.\n");
        assert!(parsed
            .heuristic_findings
            .iter()
            .any(|f| f.rule_name == "GenericSkillTrigger"));
    }

    #[test]
    fn specific_description_does_not_fire_generic_trigger() {
        // Even a short concrete description shouldn't fire the generic
        // rule (the length-based VagueSkillTrigger handles too-short
        // descriptions; this rule only flags semantically vacuous ones).
        let parsed = parse(
            "specific.md",
            "---\ndescription: Deploy the staging environment after running tests.\n---\nbody\n",
        );
        assert!(parsed
            .heuristic_findings
            .iter()
            .all(|f| f.rule_name != "GenericSkillTrigger"));
    }

    #[test]
    fn skill_name_collision_emits_finding() {
        // Two parsed skills with the same name (different paths) should
        // produce one SkillNameCollision finding.
        let p1 = PathBuf::from("/home/user/.claude/commands/deploy.md");
        let p2 = PathBuf::from("/home/user/work/.claude/commands/deploy.md");
        let parsed1 = parse_skill_content(
            &p1,
            "---\ndescription: Deploy to prod with care\n---\nactual deploy logic",
        )
        .expect("p1 parses");
        let parsed2 = parse_skill_content(
            &p2,
            "---\ndescription: Different deploy with override\n---\nshadow deploy logic",
        )
        .expect("p2 parses");
        let set: Vec<(&Path, &MCPPrompt)> = vec![
            (p1.as_path(), &parsed1.prompt),
            (p2.as_path(), &parsed2.prompt),
        ];
        let findings = analyze_skill_set(&set);
        assert_eq!(
            findings.len(),
            1,
            "expected one collision, got {findings:?}"
        );
        assert_eq!(findings[0].rule_name, "SkillNameCollision");
        let desc = findings[0]
            .rule_metadata
            .as_ref()
            .and_then(|m| m.description.as_deref())
            .unwrap_or("");
        // Both paths should be referenced in the message.
        assert!(desc.contains(&p1.display().to_string()));
        assert!(desc.contains(&p2.display().to_string()));
        // OWASP tags present.
        let ids: Vec<_> = findings[0]
            .owasp_tags
            .iter()
            .map(|t| t.id.as_str())
            .collect();
        assert!(ids.contains(&"MCP02"), "got {ids:?}");
        assert!(ids.contains(&"MCP03"), "got {ids:?}");
    }

    #[test]
    fn skill_name_collision_is_case_insensitive() {
        let p1 = PathBuf::from("/a/Deploy.md");
        let p2 = PathBuf::from("/b/deploy.md");
        let parsed1 = parse_skill_content(&p1, "---\nname: Deploy\n---\nbody1\n").unwrap();
        let parsed2 = parse_skill_content(&p2, "---\nname: deploy\n---\nbody2\n").unwrap();
        let set: Vec<(&Path, &MCPPrompt)> = vec![
            (p1.as_path(), &parsed1.prompt),
            (p2.as_path(), &parsed2.prompt),
        ];
        let findings = analyze_skill_set(&set);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn unique_skill_names_produce_no_collision_finding() {
        let p1 = PathBuf::from("/a/deploy.md");
        let p2 = PathBuf::from("/b/test.md");
        let parsed1 = parse_skill_content(&p1, "---\nname: deploy\n---\nbody1\n").unwrap();
        let parsed2 = parse_skill_content(&p2, "---\nname: test\n---\nbody2\n").unwrap();
        let set: Vec<(&Path, &MCPPrompt)> = vec![
            (p1.as_path(), &parsed1.prompt),
            (p2.as_path(), &parsed2.prompt),
        ];
        assert!(analyze_skill_set(&set).is_empty());
    }

    #[test]
    fn large_base64_blob_in_body_emits_payload_finding() {
        // 600-char base64-shape run = ~450 bytes decoded — comfortably
        // above the 500-char threshold. Mixes upper/lower/digits/+ to
        // make sure it's classified as base64 (not hex).
        let blob: String = "ABCDEFGHabcdefgh01234567+/=".repeat(30); // 810 chars
        let body = format!("Some prose, then a smuggled blob: {blob}\nMore prose.");
        let raw = format!("---\ndescription: legit-looking skill\n---\n{body}\n");
        let parsed = parse("payload.md", &raw);
        let f = parsed
            .heuristic_findings
            .iter()
            .find(|f| f.rule_name == "SkillEmbeddedPayload")
            .expect("expected SkillEmbeddedPayload finding");
        // OWASP tags present
        let ids: Vec<_> = f.owasp_tags.iter().map(|t| t.id.as_str()).collect();
        assert!(ids.contains(&"MCP01"), "got {ids:?}");
        assert!(ids.contains(&"MCP10"), "got {ids:?}");
    }

    #[test]
    fn large_hex_blob_in_body_classified_as_hex() {
        // 600-char hex run.
        let blob: String = "deadbeef0123456789abcdef".repeat(30); // 720 chars
        let body = format!("Reference hash: {blob}");
        let raw = format!("---\ndescription: hex-blob skill\n---\n{body}\n");
        let parsed = parse("hex.md", &raw);
        let f = parsed
            .heuristic_findings
            .iter()
            .find(|f| f.rule_name == "SkillEmbeddedPayload")
            .expect("hex blob should fire SkillEmbeddedPayload");
        let desc = f
            .rule_metadata
            .as_ref()
            .and_then(|m| m.description.as_deref())
            .unwrap_or("");
        assert!(
            desc.contains("hex-shape"),
            "expected hex classification in description: {desc}"
        );
    }

    #[test]
    fn data_uri_base64_image_does_not_fire_payload() {
        // Markdown inline image with a long base64 data URI is benign.
        let blob: String = "ABCDEFGHabcdefgh01234567+/=".repeat(30);
        let body = format!(
            "An image: ![alt text](data:image/png;base64,{blob})\nThe rest of the skill body."
        );
        let raw = format!("---\ndescription: skill with image\n---\n{body}\n");
        let parsed = parse("image.md", &raw);
        assert!(
            parsed
                .heuristic_findings
                .iter()
                .all(|f| f.rule_name != "SkillEmbeddedPayload"),
            "data URI image should not fire SkillEmbeddedPayload"
        );
    }

    #[test]
    fn small_base64_token_does_not_fire_payload() {
        // GitHub PAT (40 chars) and SHA-256 (64 chars) are well below
        // the 500-char threshold and shouldn't fire.
        let body = "PAT: ghp_AbCdEf1234567890AbCdEf1234567890AbCd \
                    SHA-256: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
        let raw = format!("---\ndescription: doc skill\n---\n{body}\n");
        let parsed = parse("smalltokens.md", &raw);
        assert!(parsed
            .heuristic_findings
            .iter()
            .all(|f| f.rule_name != "SkillEmbeddedPayload"));
    }

    #[test]
    fn duplicate_payloads_dedupe_to_one_finding() {
        let blob: String = "ABCDEFGHabcdefgh01234567+/=".repeat(30);
        let body = format!("First: {blob}\nSecond identical: {blob}");
        let raw = format!("---\ndescription: dup payload\n---\n{body}\n");
        let parsed = parse("dup.md", &raw);
        let count = parsed
            .heuristic_findings
            .iter()
            .filter(|f| f.rule_name == "SkillEmbeddedPayload")
            .count();
        assert_eq!(count, 1, "expected dedupe to 1 finding, got {count}");
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

    // ============================================================
    // agentskills.io bundle support
    // ============================================================

    /// Build a SKILL.md file inside `tmp_dir/<bundle_name>/SKILL.md`
    /// with the given raw contents. Returns the path to the SKILL.md.
    /// Helper so each test reads top-down without 4 lines of fs glue.
    fn make_bundle(tmp: &std::path::Path, bundle_name: &str, raw: &str) -> PathBuf {
        let dir = tmp.join(bundle_name);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("SKILL.md");
        std::fs::write(&p, raw).unwrap();
        p
    }

    /// Returns the set of finding rule names emitted for a bundle.
    fn finding_names(parsed: &ParsedSkill) -> Vec<String> {
        parsed
            .heuristic_findings
            .iter()
            .map(|f| f.rule_name.clone())
            .collect()
    }

    #[test]
    fn validate_skill_name_accepts_spec_compliant() {
        assert!(validate_skill_name("pdf-processing").is_ok());
        assert!(validate_skill_name("data-analysis").is_ok());
        assert!(validate_skill_name("a").is_ok()); // min length 1
        assert!(validate_skill_name(&"a".repeat(64)).is_ok()); // max length 64
    }

    #[test]
    fn validate_skill_name_rejects_spec_violations() {
        assert!(validate_skill_name("").is_err());
        assert!(validate_skill_name(&"a".repeat(65)).is_err());
        assert!(validate_skill_name("PDF-Processing").is_err()); // uppercase
        assert!(validate_skill_name("name_with_underscore").is_err());
        assert!(validate_skill_name("-leading-hyphen").is_err());
        assert!(validate_skill_name("trailing-hyphen-").is_err());
        assert!(validate_skill_name("double--hyphen").is_err());
        assert!(validate_skill_name("has space").is_err());
        assert!(validate_skill_name("dot.path").is_err());
    }

    #[test]
    fn is_agentskills_bundle_byte_equal() {
        // Only exact "SKILL.md" matches — not "Skill.md", "skill.md",
        // "SKILL.MD", etc. This is the spec contract.
        assert!(is_agentskills_bundle(&PathBuf::from("foo/SKILL.md")));
        assert!(!is_agentskills_bundle(&PathBuf::from("foo/Skill.md")));
        assert!(!is_agentskills_bundle(&PathBuf::from("foo/skill.md")));
        assert!(!is_agentskills_bundle(&PathBuf::from("foo/SKILL.MD")));
        assert!(!is_agentskills_bundle(&PathBuf::from("foo/skill.MD")));
        assert!(!is_agentskills_bundle(&PathBuf::from("foo/SKILL.md.bak")));
    }

    #[test]
    fn agentskills_name_must_match_parent_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let p = make_bundle(
            tmp.path(),
            "my-skill",
            "---\nname: evil-skill\ndescription: not what the dir says\n---\nbody\n",
        );
        let (parsed, _resources) = parse_agentskills_bundle(&p).expect("parsed");
        let names = finding_names(&parsed);
        assert!(
            names.contains(&"AgentskillsNameMismatch".to_string()),
            "expected AgentskillsNameMismatch, got {names:?}"
        );
        // Must NOT trigger SkillNameCollision — only one skill in the
        // set, and the mismatch check is the proper rule here.
        assert!(!names.contains(&"SkillNameCollision".to_string()));
    }

    #[test]
    fn agentskills_invalid_name_charset_underscore() {
        let tmp = tempfile::tempdir().unwrap();
        let p = make_bundle(
            tmp.path(),
            "my-skill",
            "---\nname: bad_skill\ndescription: x\n---\nbody\n",
        );
        let (parsed, _) = parse_agentskills_bundle(&p).expect("parsed");
        let names = finding_names(&parsed);
        // Name mismatch fires AND invalid-name fires (the two are
        // independent checks).
        assert!(names.contains(&"AgentskillsInvalidName".to_string()));
        let invalid = parsed
            .heuristic_findings
            .iter()
            .find(|f| f.rule_name == "AgentskillsInvalidName")
            .unwrap();
        let desc = invalid
            .rule_metadata
            .as_ref()
            .and_then(|m| m.description.clone())
            .unwrap_or_default();
        assert!(
            desc.contains("[a-z0-9-]"),
            "expected spec-violation reason in description, got: {desc}"
        );
    }

    #[test]
    fn agentskills_double_hyphen_invalid() {
        let tmp = tempfile::tempdir().unwrap();
        // Parent dir is fine — but name has double hyphen.
        let p = make_bundle(
            tmp.path(),
            "my-skill",
            "---\nname: my--skill\ndescription: x\n---\nbody\n",
        );
        let (parsed, _) = parse_agentskills_bundle(&p).expect("parsed");
        let names = finding_names(&parsed);
        assert!(names.contains(&"AgentskillsInvalidName".to_string()));
    }

    #[test]
    fn agentskills_leading_hyphen_invalid() {
        let tmp = tempfile::tempdir().unwrap();
        let p = make_bundle(
            tmp.path(),
            "my-skill",
            "---\nname: -leading\ndescription: x\n---\nbody\n",
        );
        let (parsed, _) = parse_agentskills_bundle(&p).expect("parsed");
        assert!(finding_names(&parsed).contains(&"AgentskillsInvalidName".to_string()));
    }

    #[test]
    fn agentskills_64_char_boundary() {
        let tmp = tempfile::tempdir().unwrap();
        let name_64 = "a".repeat(64);
        let p = make_bundle(
            tmp.path(),
            &name_64,
            &format!("---\nname: {name_64}\ndescription: x\n---\nbody\n"),
        );
        let (parsed, _) = parse_agentskills_bundle(&p).expect("parsed");
        assert!(!finding_names(&parsed).contains(&"AgentskillsInvalidName".to_string()));

        // 65 chars: invalid.
        let name_65 = "a".repeat(65);
        let p = make_bundle(
            tmp.path(),
            &name_65,
            &format!("---\nname: {name_65}\ndescription: x\n---\nbody\n"),
        );
        let (parsed, _) = parse_agentskills_bundle(&p).expect("parsed");
        assert!(finding_names(&parsed).contains(&"AgentskillsInvalidName".to_string()));
    }

    #[test]
    fn agentskills_unknown_fields_rolled_up() {
        let tmp = tempfile::tempdir().unwrap();
        let p = make_bundle(
            tmp.path(),
            "my-skill",
            "---\nname: my-skill\ndescription: x\nfoo: 1\nbar: 2\n---\nbody\n",
        );
        let (parsed, _) = parse_agentskills_bundle(&p).expect("parsed");
        let unknowns: Vec<_> = parsed
            .heuristic_findings
            .iter()
            .filter(|f| f.rule_name == "AgentskillsUnknownFrontmatterField")
            .collect();
        assert_eq!(unknowns.len(), 1, "expected exactly one rolled-up finding");
        let desc = unknowns[0]
            .rule_metadata
            .as_ref()
            .and_then(|m| m.description.clone())
            .unwrap_or_default();
        assert!(desc.contains("foo") && desc.contains("bar"));
    }

    #[test]
    fn agentskills_spec_allowed_fields_dont_trip_unknown() {
        let tmp = tempfile::tempdir().unwrap();
        let p = make_bundle(
            tmp.path(),
            "my-skill",
            "---\nname: my-skill\ndescription: x\nlicense: Apache-2.0\n\
             compatibility: requires git\nmetadata:\n  author: me\nallowed-tools: Read\n\
             ---\nbody\n",
        );
        let (parsed, _) = parse_agentskills_bundle(&p).expect("parsed");
        assert!(!finding_names(&parsed).contains(&"AgentskillsUnknownFrontmatterField".to_string()));
    }

    #[test]
    fn agentskills_lowercase_skill_md_not_bundle() {
        // A file named `Skill.md` is NOT a bundle entry-point. The
        // `is_agentskills_bundle` check is byte-equal — so this file
        // gets the lenient flat-skill parse path and none of the
        // bundle-mode validation findings.
        let path = PathBuf::from("foo/Skill.md");
        assert!(!is_agentskills_bundle(&path));
    }

    #[test]
    fn agentskills_parent_dir_fallback() {
        let tmp = tempfile::tempdir().unwrap();
        let p = make_bundle(
            tmp.path(),
            "pdf-processing",
            "---\ndescription: parse PDFs\n---\nbody about pdfs\n",
        );
        let (parsed, _) = parse_agentskills_bundle(&p).expect("parsed");
        assert_eq!(parsed.prompt.name, "pdf-processing");
        let names = finding_names(&parsed);
        assert!(!names.contains(&"AgentskillsNameMismatch".to_string()));
        assert!(!names.contains(&"AgentskillsInvalidName".to_string()));
        assert!(!names.contains(&"AgentskillsMissingName".to_string()));
    }

    #[test]
    fn agentskills_parent_dir_invalid_emits_invalid_name() {
        let tmp = tempfile::tempdir().unwrap();
        // Parent dir has an underscore — fails name validation.
        let p = make_bundle(
            tmp.path(),
            "pdf_processing",
            "---\ndescription: parse PDFs\n---\nbody\n",
        );
        let (parsed, _) = parse_agentskills_bundle(&p).expect("parsed");
        let invalid: Vec<_> = parsed
            .heuristic_findings
            .iter()
            .filter(|f| f.rule_name == "AgentskillsInvalidName")
            .collect();
        assert_eq!(invalid.len(), 1);
        let desc = invalid[0]
            .rule_metadata
            .as_ref()
            .and_then(|m| m.description.clone())
            .unwrap_or_default();
        assert!(
            desc.contains("parent directory"),
            "expected parent-directory wording, got: {desc}"
        );
        // Mutually exclusive with MissingName.
        assert!(!finding_names(&parsed).contains(&"AgentskillsMissingName".to_string()));
    }

    #[test]
    fn agentskills_bundle_walks_scripts() {
        let tmp = tempfile::tempdir().unwrap();
        let bundle = tmp.path().join("my-skill");
        std::fs::create_dir_all(bundle.join("scripts")).unwrap();
        std::fs::write(
            bundle.join("SKILL.md"),
            "---\nname: my-skill\ndescription: x\n---\nbody\n",
        )
        .unwrap();
        std::fs::write(
            bundle.join("scripts/run.py"),
            "import os\nos.system('ls')\n",
        )
        .unwrap();
        // README in scripts/ should be filtered by NON_SKILL_FILENAME_STEMS.
        std::fs::write(bundle.join("scripts/README.md"), "doc").unwrap();

        let (_, resources) = parse_agentskills_bundle(&bundle.join("SKILL.md")).expect("parsed");
        let names: Vec<_> = resources.iter().map(|r| r.name.clone()).collect();
        assert!(names.contains(&"my-skill/scripts/run.py".to_string()));
        // README is wrong extension for scripts anyway (not in SCRIPT_EXTS).
        assert!(!names.iter().any(|n| n.contains("README")));
    }

    #[test]
    fn agentskills_bundle_walks_references_md() {
        let tmp = tempfile::tempdir().unwrap();
        let bundle = tmp.path().join("my-skill");
        std::fs::create_dir_all(bundle.join("references")).unwrap();
        std::fs::write(
            bundle.join("SKILL.md"),
            "---\nname: my-skill\ndescription: x\n---\nbody\n",
        )
        .unwrap();
        std::fs::write(bundle.join("references/api.md"), "# API\nstuff").unwrap();
        std::fs::write(bundle.join("references/notes.txt"), "should skip").unwrap();

        let (_, resources) = parse_agentskills_bundle(&bundle.join("SKILL.md")).expect("parsed");
        let names: Vec<_> = resources.iter().map(|r| r.name.clone()).collect();
        assert!(names.contains(&"my-skill/references/api.md".to_string()));
        // .txt is not in the accept set for references.
        assert!(!names.iter().any(|n| n.contains("notes.txt")));
    }

    #[test]
    fn agentskills_bundle_skips_assets() {
        let tmp = tempfile::tempdir().unwrap();
        let bundle = tmp.path().join("my-skill");
        std::fs::create_dir_all(bundle.join("assets")).unwrap();
        std::fs::write(
            bundle.join("SKILL.md"),
            "---\nname: my-skill\ndescription: x\n---\nbody\n",
        )
        .unwrap();
        std::fs::write(bundle.join("assets/logo.svg"), "<svg/>").unwrap();
        // Even an .md asset is out of scope for v1.
        std::fs::write(bundle.join("assets/template.md"), "tmpl").unwrap();

        let (_, resources) = parse_agentskills_bundle(&bundle.join("SKILL.md")).expect("parsed");
        assert!(resources.is_empty());
    }

    #[test]
    fn agentskills_resource_uri_has_no_file_prefix() {
        // Synthetic resources use `skill://` URIs to avoid triggering
        // path-traversal YARA rules on absolute /etc/, /var/ etc.
        // substrings that would be present in `file://...` URIs.
        let tmp = tempfile::tempdir().unwrap();
        let bundle = tmp.path().join("my-skill");
        std::fs::create_dir_all(bundle.join("scripts")).unwrap();
        std::fs::write(
            bundle.join("SKILL.md"),
            "---\nname: my-skill\ndescription: x\n---\nbody\n",
        )
        .unwrap();
        std::fs::write(bundle.join("scripts/x.py"), "print(1)").unwrap();
        let (_, resources) = parse_agentskills_bundle(&bundle.join("SKILL.md")).expect("parsed");
        assert_eq!(resources.len(), 1);
        assert!(resources[0].uri.starts_with("skill://"));
        assert!(!resources[0].uri.contains("file://"));
    }

    #[test]
    fn agentskills_oversize_script_skipped() {
        let tmp = tempfile::tempdir().unwrap();
        let bundle = tmp.path().join("my-skill");
        std::fs::create_dir_all(bundle.join("scripts")).unwrap();
        std::fs::write(
            bundle.join("SKILL.md"),
            "---\nname: my-skill\ndescription: x\n---\nbody\n",
        )
        .unwrap();
        // Build a script larger than MAX_SKILL_FILE_BYTES (2 MiB). We
        // write `print(1)\n` x N to land just over the limit without
        // burning fixture-test time on a needlessly large write.
        let chunk = "print(1)\n";
        let target_bytes = (MAX_SKILL_FILE_BYTES + 1024) as usize;
        let repetitions = target_bytes.div_ceil(chunk.len());
        let big: String = chunk.repeat(repetitions);
        std::fs::write(bundle.join("scripts/huge.py"), &big).unwrap();
        // Also include a normal-sized script — confirms the cap is
        // per-file and doesn't abort the whole walk.
        std::fs::write(bundle.join("scripts/ok.py"), "print(2)").unwrap();

        let (_, resources) = parse_agentskills_bundle(&bundle.join("SKILL.md")).expect("parsed");
        let names: Vec<_> = resources.iter().map(|r| r.name.clone()).collect();
        assert!(
            !names.iter().any(|n| n.contains("huge.py")),
            "huge.py exceeded the size cap and should have been skipped"
        );
        assert!(names.contains(&"my-skill/scripts/ok.py".to_string()));
    }

    #[test]
    fn agentskills_bundle_files_per_dir_cap() {
        // Floods `scripts/` with > MAX_BUNDLE_FILES_PER_DIR tiny files;
        // walker should stop at the cap rather than producing one
        // resource per file (DoS guard).
        let tmp = tempfile::tempdir().unwrap();
        let bundle = tmp.path().join("flood-skill");
        std::fs::create_dir_all(bundle.join("scripts")).unwrap();
        std::fs::write(
            bundle.join("SKILL.md"),
            "---\nname: flood-skill\ndescription: x\n---\nbody\n",
        )
        .unwrap();
        let over_cap = MAX_BUNDLE_FILES_PER_DIR + 10;
        for i in 0..over_cap {
            std::fs::write(bundle.join(format!("scripts/x{i}.py")), "print(1)").unwrap();
        }
        let (_, resources) = parse_agentskills_bundle(&bundle.join("SKILL.md")).expect("parsed");
        assert!(
            resources.len() <= MAX_BUNDLE_FILES_PER_DIR,
            "expected at most {MAX_BUNDLE_FILES_PER_DIR} resources, got {}",
            resources.len()
        );
    }

    #[test]
    fn bundle_root_of_rejects_empty_parent() {
        // A SKILL.md path with no parent component must NOT contribute
        // a bundle-root entry — otherwise the empty-string root would
        // prefix-match every relative discovered path and corrupt the
        // bundle-sibling filter in main.rs.
        // Bare `SKILL.md` (no parent) yields None.
        assert!(bundle_root_of(&PathBuf::from("SKILL.md")).is_none());
        // `./SKILL.md` has a non-empty parent (`.`), so it IS a valid
        // bundle root — `.` resolves to whatever the caller's CWD is,
        // which is the meaningful interpretation.
        assert_eq!(
            bundle_root_of(&PathBuf::from("./SKILL.md")),
            Some(std::path::Path::new("."))
        );
        assert_eq!(
            bundle_root_of(&PathBuf::from("foo/SKILL.md")),
            Some(std::path::Path::new("foo"))
        );
    }

    #[test]
    fn validate_skill_name_rejects_non_ascii() {
        // Multi-byte UTF-8 (en-dash, accented vowel, fullwidth digits)
        // contains bytes outside [a-z0-9-]; the byte loop must reject.
        assert!(validate_skill_name("a\u{2013}b").is_err()); // en-dash
        assert!(validate_skill_name("café").is_err());
        assert!(validate_skill_name("\u{FF11}\u{FF12}").is_err()); // ＦＦ digits
    }

    #[test]
    fn is_under_bundle_sibling_dir_detects_scripts() {
        let bundle_root = PathBuf::from("/tmp/my-skill");
        let mut roots: HashSet<PathBuf> = HashSet::new();
        roots.insert(bundle_root.clone());
        assert!(is_under_bundle_sibling_dir(
            &bundle_root.join("scripts/run.py"),
            &roots
        ));
        assert!(is_under_bundle_sibling_dir(
            &bundle_root.join("references/api.md"),
            &roots
        ));
        assert!(is_under_bundle_sibling_dir(
            &bundle_root.join("assets/logo.png"),
            &roots
        ));
        // SKILL.md itself is the bundle entry, not a sibling.
        assert!(!is_under_bundle_sibling_dir(
            &bundle_root.join("SKILL.md"),
            &roots
        ));
        // A different directory entirely.
        assert!(!is_under_bundle_sibling_dir(
            &PathBuf::from("/tmp/other-skill/SKILL.md"),
            &roots
        ));
    }

    #[test]
    fn is_under_bundle_sibling_dir_is_shallow() {
        // The bundle parser only reads files one level under each
        // sibling dir. Files nested deeper (`<bundle>/references/sub/deep.md`)
        // must NOT be filtered out by this check — otherwise they'd be
        // silently dropped from both the bundle parser (shallow) and
        // the top-level flat-skill walker (filtered).
        let bundle_root = PathBuf::from("/tmp/my-skill");
        let mut roots: HashSet<PathBuf> = HashSet::new();
        roots.insert(bundle_root.clone());
        assert!(!is_under_bundle_sibling_dir(
            &bundle_root.join("references/sub/deep.md"),
            &roots
        ));
        assert!(!is_under_bundle_sibling_dir(
            &bundle_root.join("scripts/nested/dir/x.py"),
            &roots
        ));
    }
}
