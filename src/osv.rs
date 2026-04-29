//! OSV.dev integration for stdio MCP servers' transitive dependencies.
//!
//! When ramparts scans a stdio MCP server launched via `npx` (npm) or
//! `uvx` (PyPI), the scanner can extract the package name+version from
//! the command/args and ask OSV.dev whether that release has known
//! security advisories. Findings are surfaced through the existing YARA
//! result type (`rule_name = "VulnerableDependency"`) so they propagate
//! into terminal, JSON, markdown, and SARIF outputs without any new
//! plumbing.
//!
//! This is an opportunistic, fail-soft check: an OSV query that times
//! out, errors, or returns a non-200 status logs a warning and is
//! treated as "no known vulns" rather than failing the whole scan.
//! Downstream consumers should treat the absence of OSV findings as
//! "we didn't see any" rather than "definitely clean".
//!
//! Supports two ecosystems today (covering the two most common stdio
//! MCP server launch patterns); adding new ones is a matter of
//! extending `parse_package_spec_from_command` and the ecosystem
//! mapping in `query_osv`.

use crate::types::{YaraRuleMetadata, YaraScanResult};
use reqwest::Client;
use serde::Deserialize;
use std::time::Duration;
use tracing::{debug, warn};

const OSV_QUERY_URL: &str = "https://api.osv.dev/v1/query";
const OSV_QUERY_TIMEOUT_SECS: u64 = 5;

/// A parsed (ecosystem, name, version) triple ready to send to OSV.
#[derive(Debug, Clone)]
pub struct PackageSpec {
    pub ecosystem: &'static str,
    pub name: String,
    pub version: Option<String>,
}

/// Parse a stdio MCP launch command into a `PackageSpec` suitable for an
/// OSV query. Returns `None` when the command isn't a recognized package
/// runner or the args don't yield a clean package reference. We only
/// recognize the conservative subset we can parse without false positives:
///
/// - `npx [-y|--yes] [pkg@ver] [...rest]` → npm:pkg@ver
/// - `uvx [--from pkg[==ver]] [pkg[==ver]] [...rest]` → PyPI:pkg@ver
///
/// Anything more exotic (custom scripts, shell pipelines, npx-with-multiple-
/// packages) returns `None` so we don't emit false positives.
pub fn parse_package_spec_from_command(command: &str, args: &[String]) -> Option<PackageSpec> {
    match command {
        "npx" => parse_npx(args),
        "uvx" => parse_uvx(args),
        _ => None,
    }
}

fn parse_npx(args: &[String]) -> Option<PackageSpec> {
    // First positional arg that doesn't start with `-` is the package.
    let pkg_arg = args.iter().find(|a| !a.starts_with('-'))?;
    let (name, version) = split_npm_spec(pkg_arg)?;
    Some(PackageSpec {
        ecosystem: "npm",
        name,
        version,
    })
}

/// Split an npm package reference into (name, version). Handles scoped
/// packages (`@scope/pkg`) where the leading `@` must NOT be parsed as a
/// version separator.
fn split_npm_spec(raw: &str) -> Option<(String, Option<String>)> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    // Scoped package: @scope/pkg[@ver]
    if let Some(stripped) = raw.strip_prefix('@') {
        let (scope, rest) = stripped.split_once('/')?;
        if let Some((pkg, ver)) = rest.split_once('@') {
            return Some((format!("@{scope}/{pkg}"), version_or_none(ver)));
        }
        return Some((format!("@{scope}/{rest}"), None));
    }
    if let Some((name, ver)) = raw.split_once('@') {
        return Some((name.to_string(), version_or_none(ver)));
    }
    Some((raw.to_string(), None))
}

fn parse_uvx(args: &[String]) -> Option<PackageSpec> {
    // `uvx --from pkg[==ver] cmd ...` or `uvx pkg[==ver] [...]`. Take the
    // first non-flag token after a known flag, or the first non-flag token
    // overall.
    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.peek() {
        if *arg == "--from" {
            iter.next();
            if let Some(spec) = iter.next() {
                let (name, version) = split_pypi_spec(spec)?;
                return Some(PackageSpec {
                    ecosystem: "PyPI",
                    name,
                    version,
                });
            }
            return None;
        }
        if arg.starts_with('-') {
            iter.next();
            continue;
        }
        break;
    }
    let pkg = iter.next()?;
    let (name, version) = split_pypi_spec(pkg)?;
    Some(PackageSpec {
        ecosystem: "PyPI",
        name,
        version,
    })
}

fn split_pypi_spec(raw: &str) -> Option<(String, Option<String>)> {
    // PyPI version specifiers we care about: `pkg==1.2.3`, `pkg`. We leave
    // looser specs (`pkg>=1.0`) alone because OSV needs an exact version
    // to give a useful answer.
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    if let Some((name, ver)) = raw.split_once("==") {
        return Some((name.to_string(), version_or_none(ver)));
    }
    Some((raw.to_string(), None))
}

fn version_or_none(s: &str) -> Option<String> {
    let s = s.trim();
    // npm/PyPI both treat "latest" as a tag rather than a real version. OSV
    // can't resolve tags, so drop these and return the package alone — OSV
    // will tell us "any known vulns at all", which is still useful info.
    if s.is_empty() || s.eq_ignore_ascii_case("latest") {
        None
    } else {
        Some(s.to_string())
    }
}

#[derive(Debug, Deserialize)]
struct OsvQueryResponse {
    #[serde(default)]
    vulns: Vec<OsvVulnerability>,
}

#[derive(Debug, Deserialize)]
struct OsvVulnerability {
    id: String,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    details: Option<String>,
    #[serde(default)]
    severity: Vec<OsvSeverity>,
    #[serde(default)]
    aliases: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct OsvSeverity {
    #[serde(rename = "type")]
    severity_type: String,
    score: String,
}

/// Query OSV.dev for vulnerabilities affecting `spec`. Returns an empty
/// `Vec` on any failure (network error, non-200 status, parse error) — the
/// caller is responsible for treating "no findings" as "we didn't see any"
/// rather than "definitely clean".
///
/// Takes `Client` by reference (cheap clones internally via `Arc`) and
/// `PackageSpec` by value so callers can spawn the resulting future onto
/// a `tokio::task` without lifetime gymnastics.
pub async fn query_osv(client: Client, spec: PackageSpec) -> Vec<YaraScanResult> {
    debug!(
        "Querying OSV.dev for {}/{} ({:?})",
        spec.ecosystem, spec.name, spec.version
    );
    let request_body = build_osv_request(&spec);
    let response = match client
        .post(OSV_QUERY_URL)
        .timeout(Duration::from_secs(OSV_QUERY_TIMEOUT_SECS))
        .json(&request_body)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            warn!(
                "OSV query failed for {}/{}: {}",
                spec.ecosystem, spec.name, e
            );
            return Vec::new();
        }
    };
    if !response.status().is_success() {
        warn!(
            "OSV returned {} for {}/{}",
            response.status(),
            spec.ecosystem,
            spec.name
        );
        return Vec::new();
    }
    let body: OsvQueryResponse = match response.json().await {
        Ok(b) => b,
        Err(e) => {
            warn!(
                "Failed to parse OSV response for {}/{}: {}",
                spec.ecosystem, spec.name, e
            );
            return Vec::new();
        }
    };

    body.vulns
        .into_iter()
        .map(|v| osv_finding_to_yara_result(&spec, v))
        .collect()
}

fn build_osv_request(spec: &PackageSpec) -> serde_json::Value {
    let mut req = serde_json::json!({
        "package": {
            "name": spec.name,
            "ecosystem": spec.ecosystem,
        }
    });
    if let Some(version) = &spec.version {
        req["version"] = serde_json::Value::String(version.clone());
    }
    req
}

fn osv_finding_to_yara_result(spec: &PackageSpec, vuln: OsvVulnerability) -> YaraScanResult {
    let cvss = vuln
        .severity
        .iter()
        .find(|s| s.severity_type.starts_with("CVSS"))
        .map(|s| s.score.as_str())
        .unwrap_or("unknown");
    let severity = severity_label_for_cvss(cvss);
    let summary = vuln
        .summary
        .as_deref()
        .or(vuln.details.as_deref())
        .unwrap_or("No summary provided by OSV");
    let aliases = if vuln.aliases.is_empty() {
        String::new()
    } else {
        format!(" (aliases: {})", vuln.aliases.join(", "))
    };
    let context = format!(
        "{}/{} {}: {}{aliases}",
        spec.ecosystem,
        spec.name,
        spec.version.as_deref().unwrap_or("(any version)"),
        summary
    );
    YaraScanResult {
        target_type: "dependency".to_string(),
        target_name: format!(
            "{}/{}@{}",
            spec.ecosystem,
            spec.name,
            spec.version.as_deref().unwrap_or("?")
        ),
        rule_name: "VulnerableDependency".to_string(),
        rule_file: Some("osv".to_string()),
        matched_text: Some(vuln.id.clone()),
        context,
        rule_metadata: Some(YaraRuleMetadata {
            name: Some("Vulnerable Dependency".to_string()),
            author: Some("OSV.dev".to_string()),
            date: None,
            version: None,
            description: Some(summary.to_string()),
            severity: Some(severity.to_string()),
            category: Some("supply-chain".to_string()),
            confidence: Some("HIGH".to_string()),
            tags: vec!["dependency".to_string(), "osv".to_string()],
        }),
        owasp_tags: crate::taxonomy::tags_for_yara_rule("VulnerableDependency"),
        phase: Some("pre-scan".to_string()),
        rules_executed: None,
        security_issues_detected: None,
        total_items_scanned: None,
        total_matches: None,
        status: Some("warning".to_string()),
    }
}

/// Map a CVSS score string (e.g. "9.8", "CVSS:3.1/AV:N/...") to a coarse
/// severity label aligned with the rest of ramparts' severity vocabulary.
fn severity_label_for_cvss(score_text: &str) -> &'static str {
    // Some OSV records put the full CVSS vector in `score`; others put just
    // the numeric base score. Try to extract a leading float either way.
    let numeric = score_text
        .split('/')
        .find_map(|part| part.parse::<f32>().ok());
    match numeric {
        Some(n) if n >= 9.0 => "CRITICAL",
        Some(n) if n >= 7.0 => "HIGH",
        Some(n) if n >= 4.0 => "MEDIUM",
        Some(_) => "LOW",
        None => "MEDIUM",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_npx_pkg() {
        let spec = parse_package_spec_from_command(
            "npx",
            &[
                "-y".into(),
                "@modelcontextprotocol/server-everything".into(),
            ],
        )
        .expect("should parse");
        assert_eq!(spec.ecosystem, "npm");
        assert_eq!(spec.name, "@modelcontextprotocol/server-everything");
        assert_eq!(spec.version, None);
    }

    #[test]
    fn parses_npx_with_pinned_version() {
        let spec = parse_package_spec_from_command("npx", &["lodash@4.17.21".into()])
            .expect("should parse");
        assert_eq!(spec.name, "lodash");
        assert_eq!(spec.version, Some("4.17.21".into()));
    }

    #[test]
    fn parses_npx_scoped_with_version() {
        let spec = parse_package_spec_from_command("npx", &["@scope/pkg@1.2.3".into()])
            .expect("should parse");
        assert_eq!(spec.name, "@scope/pkg");
        assert_eq!(spec.version, Some("1.2.3".into()));
    }

    #[test]
    fn drops_latest_tag() {
        let spec = parse_package_spec_from_command("npx", &["lodash@latest".into()])
            .expect("should parse");
        assert_eq!(spec.version, None);
    }

    #[test]
    fn parses_uvx_with_from_flag() {
        let spec = parse_package_spec_from_command(
            "uvx",
            &["--from".into(), "ruff==0.8.4".into(), "ruff".into()],
        )
        .expect("should parse");
        assert_eq!(spec.ecosystem, "PyPI");
        assert_eq!(spec.name, "ruff");
        assert_eq!(spec.version, Some("0.8.4".into()));
    }

    #[test]
    fn parses_uvx_positional() {
        let spec = parse_package_spec_from_command("uvx", &["black".into()]).expect("should parse");
        assert_eq!(spec.ecosystem, "PyPI");
        assert_eq!(spec.name, "black");
    }

    #[test]
    fn rejects_unrecognized_runner() {
        assert!(parse_package_spec_from_command("python3", &["script.py".into()]).is_none());
        assert!(
            parse_package_spec_from_command("docker", &["run".into(), "image".into()]).is_none()
        );
    }

    #[test]
    fn cvss_severity_buckets() {
        assert_eq!(severity_label_for_cvss("9.8"), "CRITICAL");
        assert_eq!(severity_label_for_cvss("7.5"), "HIGH");
        assert_eq!(severity_label_for_cvss("5.0"), "MEDIUM");
        assert_eq!(severity_label_for_cvss("3.1"), "LOW");
        assert_eq!(
            severity_label_for_cvss("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            "MEDIUM"
        );
        assert_eq!(severity_label_for_cvss(""), "MEDIUM");
    }
}
