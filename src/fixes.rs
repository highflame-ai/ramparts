//! Deterministic auto-fixes for IDE MCP config files.
//!
//! Each fix is a pure transformation on a `serde_json::Value`. The engine
//! never invents data: every fix either rewrites a known-shape field or
//! removes a closed-list entry. Fixes that would require LLM judgement
//! (e.g. inferring an env-var name from a non-conventional key) live
//! outside this module.
//!
//! Operating on raw `Value` rather than the typed `MCPConfig` is deliberate:
//! `MCPConfig` is the *normalized* internal representation that discards
//! IDE-specific schema. Writing it back would change the file's shape
//! (e.g. Cursor's `mcpServers.<name>` object form would become an array).
//! Working on `Value` preserves the source schema.
//!
//! # Supported shapes
//!
//! Three JSON shapes are recognized, covering every IDE Ramparts scans:
//!
//! 1. `mcpServers` object form — Cursor, Claude Desktop, Claude Code,
//!    Windsurf, Gemini.
//! 2. `servers` object form — VS Code `mcp.json`.
//! 3. `servers` array form — VS Code array variant.
//!
//! A file outside these three shapes yields zero fixes — the engine simply
//! reports nothing applies.

use serde_json::{Map, Value};

/// One fix that the engine applied to a single field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedFix {
    /// Stable identifier for the fix rule.
    pub rule: &'static str,
    /// Human-readable JSON-pointer-ish path to the changed field, for diff
    /// rendering. Not a real RFC 6901 pointer — uses dotted notation since
    /// that matches what users see in IDE config files.
    pub field: String,
    /// String description of the change ("http://x → https://x").
    pub summary: String,
}

/// Apply every fix rule to `value` in place. Returns the list of fixes
/// applied. The order is deterministic: rules run in the order returned by
/// `all_rules()`, and within a rule, fields are visited in the JSON's
/// natural map iteration order (which `serde_json` preserves via the
/// `preserve_order` feature — but we don't depend on that for correctness,
/// only for diff stability).
pub fn apply_all(value: &mut Value) -> Vec<AppliedFix> {
    let mut applied = Vec::new();
    for rule in all_rules() {
        rule.apply(value, &mut applied);
    }
    applied
}

/// All fix rules shipped in v1.
fn all_rules() -> Vec<Box<dyn FixRule>> {
    vec![
        Box::new(HttpToHttps),
        Box::new(SecretExternalization),
        Box::new(DangerousFlagRemoval),
    ]
}

trait FixRule {
    fn apply(&self, value: &mut Value, out: &mut Vec<AppliedFix>);
}

/// Visit every server entry across all three shapes, calling `f` with a
/// mutable `Map<String, Value>` (the server config) and a parent path
/// prefix for diagnostics.
fn for_each_server(value: &mut Value, mut f: impl FnMut(&str, &mut Map<String, Value>)) {
    let Value::Object(top) = value else {
        return;
    };

    // Shape 1: top.mcpServers as object-of-objects.
    if let Some(Value::Object(servers)) = top.get_mut("mcpServers") {
        for (name, server) in servers.iter_mut() {
            if let Value::Object(map) = server {
                f(&format!("mcpServers.{name}"), map);
            }
        }
    }

    // Shapes 2 & 3: top.servers as either object or array.
    if let Some(servers_val) = top.get_mut("servers") {
        match servers_val {
            Value::Object(servers) => {
                for (name, server) in servers.iter_mut() {
                    if let Value::Object(map) = server {
                        f(&format!("servers.{name}"), map);
                    }
                }
            }
            Value::Array(servers) => {
                for (i, server) in servers.iter_mut().enumerate() {
                    if let Value::Object(map) = server {
                        f(&format!("servers[{i}]"), map);
                    }
                }
            }
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// Rule 1: http:// → https:// for non-localhost URLs.
// ---------------------------------------------------------------------------

struct HttpToHttps;

impl FixRule for HttpToHttps {
    fn apply(&self, value: &mut Value, out: &mut Vec<AppliedFix>) {
        for_each_server(value, |path, server| {
            let Some(Value::String(url)) = server.get_mut("url") else {
                return;
            };
            if !url.starts_with("http://") {
                return;
            }
            // Conservative host check: don't touch loopback or unspecified.
            // Anything resembling localhost stays http.
            let after_scheme = &url[7..];
            let host = after_scheme
                .split(['/', '?', '#'])
                .next()
                .unwrap_or("")
                .split(':')
                .next()
                .unwrap_or("");
            if is_loopback_host(host) {
                return;
            }
            let original = url.clone();
            url.replace_range(0..7, "https://");
            out.push(AppliedFix {
                rule: "http-to-https",
                field: format!("{path}.url"),
                summary: format!("{original} → {url}"),
            });
        });
    }
}

fn is_loopback_host(host: &str) -> bool {
    matches!(
        host,
        "localhost" | "127.0.0.1" | "0.0.0.0" | "[::1]" | "::1"
    ) || host.starts_with("127.")
}

// ---------------------------------------------------------------------------
// Rule 2: secret externalization for SCREAMING_SNAKE_CASE env keys.
// ---------------------------------------------------------------------------

struct SecretExternalization;

impl FixRule for SecretExternalization {
    fn apply(&self, value: &mut Value, out: &mut Vec<AppliedFix>) {
        for_each_server(value, |path, server| {
            let Some(Value::Object(env)) = server.get_mut("env") else {
                return;
            };
            // Collect changes first so we don't mutate the map while iterating.
            let mut changes: Vec<(String, String)> = Vec::new();
            for (key, val) in env.iter() {
                if !is_screaming_snake(key) {
                    continue;
                }
                // Dangerous-flag keys are configuration toggles, not secrets
                // — never rewrite their values. `DangerousFlagRemoval` owns
                // them. This guard makes the two rules order-independent.
                if DANGEROUS_FLAGS.iter().any(|(k, _, _)| *k == key) {
                    continue;
                }
                let Value::String(s) = val else { continue };
                if is_already_envref(s) {
                    continue;
                }
                if s.is_empty() {
                    continue;
                }
                let replacement = format!("${{{key}}}");
                changes.push((key.clone(), replacement));
            }
            for (key, replacement) in changes {
                let old = env
                    .insert(key.clone(), Value::String(replacement.clone()))
                    .map(|v| match v {
                        Value::String(s) => s,
                        other => other.to_string(),
                    })
                    .unwrap_or_default();
                out.push(AppliedFix {
                    rule: "secret-externalization",
                    field: format!("{path}.env.{key}"),
                    summary: format!(
                        "{} → {} (set ${} in your shell)",
                        redact(&old),
                        replacement,
                        key
                    ),
                });
            }
        });
    }
}

fn is_screaming_snake(s: &str) -> bool {
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_uppercase() {
        return false;
    }
    s.chars()
        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

fn is_already_envref(s: &str) -> bool {
    // Matches `${NAME}` exactly where NAME is SCREAMING_SNAKE.
    let bytes = s.as_bytes();
    if bytes.len() < 4 {
        return false;
    }
    if bytes[0] != b'$' || bytes[1] != b'{' || *bytes.last().unwrap() != b'}' {
        return false;
    }
    is_screaming_snake(&s[2..s.len() - 1])
}

/// Redact a secret for diff display. Show first 4 + last 4 chars when long
/// enough; otherwise show `***`.
fn redact(s: &str) -> String {
    if s.len() <= 8 {
        "***".into()
    } else {
        format!("{}***{}", &s[..4], &s[s.len() - 4..])
    }
}

// ---------------------------------------------------------------------------
// Rule 3: removal of known dangerous opt-out flags from `env`.
// ---------------------------------------------------------------------------

struct DangerousFlagRemoval;

/// Closed list. Each entry: (env key, value pattern that triggers removal,
/// reason for the diff summary). Value pattern `*` means "any value".
const DANGEROUS_FLAGS: &[(&str, &str, &str)] = &[
    (
        "NODE_TLS_REJECT_UNAUTHORIZED",
        "0",
        "disables TLS certificate verification",
    ),
    (
        "DANGEROUSLY_OMIT_AUTH",
        "true",
        "disables MCP authentication",
    ),
    ("MCP_DISABLE_AUTH", "1", "disables MCP authentication"),
    ("PYTHONHTTPSVERIFY", "0", "disables Python TLS verification"),
    ("GIT_SSL_NO_VERIFY", "true", "disables Git TLS verification"),
];

impl FixRule for DangerousFlagRemoval {
    fn apply(&self, value: &mut Value, out: &mut Vec<AppliedFix>) {
        for_each_server(value, |path, server| {
            let Some(Value::Object(env)) = server.get_mut("env") else {
                return;
            };
            let mut to_remove: Vec<(&'static str, &'static str)> = Vec::new();
            for &(key, pattern, reason) in DANGEROUS_FLAGS {
                let Some(actual) = env.get(key) else { continue };
                let actual_str = match actual {
                    Value::String(s) => s.clone(),
                    Value::Bool(b) => b.to_string(),
                    Value::Number(n) => n.to_string(),
                    _ => continue,
                };
                if pattern == "*" || actual_str == pattern {
                    to_remove.push((key, reason));
                }
            }
            for (key, reason) in to_remove {
                env.remove(key);
                out.push(AppliedFix {
                    rule: "dangerous-flag-removal",
                    field: format!("{path}.env.{key}"),
                    summary: format!("removed: {reason}"),
                });
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixed(input: Value) -> (Value, Vec<AppliedFix>) {
        let mut v = input;
        let applied = apply_all(&mut v);
        (v, applied)
    }

    // ----- shape coverage -----

    #[test]
    fn http_to_https_cursor_shape() {
        let (v, applied) = fixed(json!({
            "mcpServers": {
                "x": { "url": "http://api.example.com/mcp" }
            }
        }));
        assert_eq!(applied.len(), 1);
        assert_eq!(applied[0].rule, "http-to-https");
        assert_eq!(v["mcpServers"]["x"]["url"], "https://api.example.com/mcp");
    }

    #[test]
    fn http_to_https_vscode_object_shape() {
        let (v, applied) = fixed(json!({
            "servers": {
                "y": { "url": "http://api.example.com/mcp" }
            }
        }));
        assert_eq!(applied.len(), 1);
        assert_eq!(v["servers"]["y"]["url"], "https://api.example.com/mcp");
    }

    #[test]
    fn http_to_https_vscode_array_shape() {
        let (v, applied) = fixed(json!({
            "servers": [
                { "name": "z", "url": "http://api.example.com/mcp" }
            ]
        }));
        assert_eq!(applied.len(), 1);
        assert_eq!(v["servers"][0]["url"], "https://api.example.com/mcp");
    }

    // ----- http-to-https edge cases -----

    #[test]
    fn http_to_https_skips_localhost() {
        let (v, applied) = fixed(json!({
            "mcpServers": {
                "a": { "url": "http://localhost:3000" },
                "b": { "url": "http://127.0.0.1:8080" },
                "c": { "url": "http://0.0.0.0:8000" },
                "d": { "url": "http://127.10.20.30/x" }
            }
        }));
        assert!(applied.is_empty(), "loopback hosts must not be rewritten");
        assert_eq!(v["mcpServers"]["a"]["url"], "http://localhost:3000");
    }

    #[test]
    fn http_to_https_skips_already_https() {
        let (_, applied) = fixed(json!({
            "mcpServers": { "x": { "url": "https://api.example.com" } }
        }));
        assert!(applied.is_empty());
    }

    #[test]
    fn http_to_https_handles_query_and_path() {
        let (v, _) = fixed(json!({
            "mcpServers": {
                "x": { "url": "http://api.example.com:443/mcp?token=abc" }
            }
        }));
        assert_eq!(
            v["mcpServers"]["x"]["url"],
            "https://api.example.com:443/mcp?token=abc"
        );
    }

    // ----- secret externalization -----

    #[test]
    fn secret_externalization_screaming_snake_only() {
        let (v, applied) = fixed(json!({
            "mcpServers": {
                "x": {
                    "env": {
                        "GITHUB_TOKEN": "ghp_realsecretvalue",
                        "lowercase_key": "ghp_should_not_be_touched",
                        "Mixed_Case": "also_skipped"
                    }
                }
            }
        }));
        assert_eq!(applied.len(), 1);
        assert_eq!(applied[0].rule, "secret-externalization");
        assert_eq!(
            v["mcpServers"]["x"]["env"]["GITHUB_TOKEN"],
            "${GITHUB_TOKEN}"
        );
        assert_eq!(
            v["mcpServers"]["x"]["env"]["lowercase_key"],
            "ghp_should_not_be_touched"
        );
    }

    #[test]
    fn secret_externalization_skips_already_referenced() {
        let (_, applied) = fixed(json!({
            "mcpServers": {
                "x": { "env": { "GITHUB_TOKEN": "${GITHUB_TOKEN}" } }
            }
        }));
        assert!(applied.is_empty());
    }

    #[test]
    fn secret_externalization_skips_empty_values() {
        let (_, applied) = fixed(json!({
            "mcpServers": { "x": { "env": { "GITHUB_TOKEN": "" } } }
        }));
        assert!(applied.is_empty());
    }

    #[test]
    fn secret_externalization_redacts_in_diff_summary() {
        let (_, applied) = fixed(json!({
            "mcpServers": {
                "x": { "env": { "GITHUB_TOKEN": "ghp_thisIsSensitive" } }
            }
        }));
        assert_eq!(applied.len(), 1);
        // Must not leak the full secret in the diff summary.
        assert!(
            !applied[0].summary.contains("ghp_thisIsSensitive"),
            "summary leaked secret: {}",
            applied[0].summary
        );
        assert!(applied[0].summary.contains("***"));
    }

    // ----- dangerous flag removal -----

    #[test]
    fn dangerous_flag_removed_when_value_matches() {
        let (v, applied) = fixed(json!({
            "mcpServers": {
                "x": {
                    "env": {
                        "NODE_TLS_REJECT_UNAUTHORIZED": "0",
                        "GITHUB_TOKEN": "${GITHUB_TOKEN}"
                    }
                }
            }
        }));
        assert_eq!(applied.len(), 1);
        assert_eq!(applied[0].rule, "dangerous-flag-removal");
        assert!(v["mcpServers"]["x"]["env"]
            .get("NODE_TLS_REJECT_UNAUTHORIZED")
            .is_none());
        // Other env var preserved.
        assert!(v["mcpServers"]["x"]["env"]["GITHUB_TOKEN"].is_string());
    }

    #[test]
    fn dangerous_flag_kept_when_value_does_not_match() {
        // NODE_TLS_REJECT_UNAUTHORIZED=1 means "do verify"; harmless.
        let (v, applied) = fixed(json!({
            "mcpServers": {
                "x": { "env": { "NODE_TLS_REJECT_UNAUTHORIZED": "1" } }
            }
        }));
        assert!(applied.is_empty());
        assert_eq!(
            v["mcpServers"]["x"]["env"]["NODE_TLS_REJECT_UNAUTHORIZED"],
            "1"
        );
    }

    // ----- non-applicable inputs -----

    #[test]
    fn no_fixes_for_unknown_shape() {
        let (_, applied) = fixed(json!({
            "completely": { "unrelated": "shape" }
        }));
        assert!(applied.is_empty());
    }

    #[test]
    fn no_fixes_for_clean_config() {
        let (_, applied) = fixed(json!({
            "mcpServers": {
                "x": {
                    "url": "https://api.example.com",
                    "env": { "GITHUB_TOKEN": "${GITHUB_TOKEN}" }
                }
            }
        }));
        assert!(applied.is_empty());
    }

    #[test]
    fn multiple_rules_apply_to_same_file() {
        let (v, applied) = fixed(json!({
            "mcpServers": {
                "a": { "url": "http://api.example.com" },
                "b": {
                    "env": {
                        "GITHUB_TOKEN": "ghp_realvalue1234567",
                        "NODE_TLS_REJECT_UNAUTHORIZED": "0"
                    }
                }
            }
        }));
        assert_eq!(applied.len(), 3);
        assert_eq!(v["mcpServers"]["a"]["url"], "https://api.example.com");
        assert_eq!(
            v["mcpServers"]["b"]["env"]["GITHUB_TOKEN"],
            "${GITHUB_TOKEN}"
        );
        assert!(v["mcpServers"]["b"]["env"]
            .get("NODE_TLS_REJECT_UNAUTHORIZED")
            .is_none());
    }
}
