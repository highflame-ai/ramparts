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

/// OSV query endpoint. `RAMPARTS_OSV_URL` points the lookup at a mirror or
/// proxy for networks that can't reach api.osv.dev; it must be https.
fn osv_query_url() -> String {
    match std::env::var("RAMPARTS_OSV_URL") {
        Ok(url) if url.starts_with("https://") => url,
        Ok(url) if !url.is_empty() => {
            warn!("Ignoring RAMPARTS_OSV_URL={url}: must be an https:// URL");
            OSV_QUERY_URL.to_string()
        }
        _ => OSV_QUERY_URL.to_string(),
    }
}
const OSV_QUERY_TIMEOUT_SECS: u64 = 5;

/// A parsed (ecosystem, name, version) triple ready to send to OSV.
#[derive(Debug, Clone)]
pub struct PackageSpec {
    pub ecosystem: &'static str,
    pub name: String,
    pub version: Option<String>,
}

/// Parse a stdio MCP launch command into a `PackageSpec` suitable for an
/// OSV query. This is the gate that decides whether a launch package gets
/// checked before the server starts, so it recognizes every common runner:
///
/// - npm: `npx`, `bunx`, `bun x`, `pnpm dlx`, `yarn dlx`, `npm exec` / `npm x`
/// - PyPI: `uvx`, `uv tool run`, `pipx run`
/// - any of the above behind `cmd /c` (Windows configs)
///
/// The command is matched by file name, so `/usr/local/bin/npx`, `npx.cmd`
/// and `NPX.EXE` count too. Returns `None` for commands that aren't package
/// runners (`python3 server.py`, `node ./x.js`): there's nothing to look up.
pub fn parse_package_spec_from_command(command: &str, args: &[String]) -> Option<PackageSpec> {
    let name = command
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(command)
        .to_ascii_lowercase();
    let name = [".cmd", ".exe", ".ps1", ".bat"]
        .iter()
        .find_map(|ext| name.strip_suffix(ext))
        .unwrap_or(&name)
        .to_string();
    let first = args.first().map(|a| a.to_ascii_lowercase());
    let rest = || args.get(1..).unwrap_or(&[]);
    match (name.as_str(), first.as_deref()) {
        ("cmd", Some("/c" | "/k")) => {
            let inner = args.get(1)?;
            parse_package_spec_from_command(inner, args.get(2..).unwrap_or(&[]))
        }
        ("npx" | "bunx", _) => parse_npx(args),
        ("bun", Some("x")) | ("pnpm" | "yarn", Some("dlx")) | ("npm", Some("exec" | "x")) => {
            parse_npx(rest())
        }
        ("uvx", _) => parse_uvx(args),
        ("uv", Some("tool")) if args.get(1).is_some_and(|a| a == "run") => {
            parse_uvx(args.get(2..).unwrap_or(&[]))
        }
        ("pipx", Some("run")) => parse_uvx(rest()),
        _ => None,
    }
}

fn parse_npx(args: &[String]) -> Option<PackageSpec> {
    // An explicit `--package=<spec>` / `--package <spec>` / `-p <spec>` names
    // the package even when a different bin name follows it.
    let mut iter = args.iter();
    let mut positional = None;
    while let Some(arg) = iter.next() {
        if let Some(spec) = arg.strip_prefix("--package=") {
            return npm_spec(spec);
        }
        if arg == "--package" || arg == "-p" {
            return npm_spec(iter.next()?);
        }
        if (arg == "--call" || arg == "-c") && positional.is_none() {
            iter.next(); // the shell command string, not a package
            continue;
        }
        if !arg.starts_with('-') && positional.is_none() {
            positional = Some(arg);
        }
    }
    npm_spec(positional?)
}

fn npm_spec(raw: &str) -> Option<PackageSpec> {
    let (name, version) = split_npm_spec(raw)?;
    Some(PackageSpec {
        ecosystem: "npm",
        name,
        version,
    })
}

/// Split an npm package reference into (name, version). Handles scoped
/// packages (`@scope/pkg`) where the leading `@` must NOT be parsed as a
/// version separator. Ranges and tags (`^1.0`, `latest`) yield no version,
/// so OSV considers every release.
fn split_npm_spec(raw: &str) -> Option<(String, Option<String>)> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    // Scoped package: @scope/pkg[@ver]
    if let Some(stripped) = raw.strip_prefix('@') {
        let (scope, rest) = stripped.split_once('/')?;
        if let Some((pkg, ver)) = rest.split_once('@') {
            return Some((format!("@{scope}/{pkg}"), exact_version(ver)));
        }
        return Some((format!("@{scope}/{rest}"), None));
    }
    if let Some((name, ver)) = raw.split_once('@') {
        return Some((name.to_string(), exact_version(ver)));
    }
    Some((raw.to_string(), None))
}

fn parse_uvx(args: &[String]) -> Option<PackageSpec> {
    // `uvx --from pkg[==ver] cmd ...`, `pipx run --spec pkg cmd ...`, or the
    // first non-flag token.
    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.peek() {
        if let Some(spec) = arg
            .strip_prefix("--from=")
            .or_else(|| arg.strip_prefix("--spec="))
        {
            return pypi_spec(spec);
        }
        if *arg == "--from" || *arg == "--spec" {
            iter.next();
            return pypi_spec(iter.next()?);
        }
        if arg.starts_with('-') {
            iter.next();
            continue;
        }
        break;
    }
    pypi_spec(iter.next()?)
}

fn pypi_spec(raw: &str) -> Option<PackageSpec> {
    let (name, version) = split_pypi_spec(raw)?;
    Some(PackageSpec {
        ecosystem: "PyPI",
        name,
        version,
    })
}

/// `pkg==1.2.3` and uv's `pkg@1.2.3` give an exact version. Any other
/// specifier (`>=`, `~=`, `!=`, `<`, extras `[x]`) is stripped from the name
/// and yields no version, so OSV considers every release.
fn split_pypi_spec(raw: &str) -> Option<(String, Option<String>)> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let exact = raw
        .split_once("==")
        .or_else(|| raw.split_once('@'))
        .and_then(|(n, v)| exact_version(v).map(|v| (n, v)));
    let (name_part, version) = match exact {
        Some((n, v)) => (n, Some(v)),
        None => (raw, None),
    };
    let name = name_part
        .split(['[', '<', '>', '=', '!', '~', ';', '@', ' '])
        .next()
        .unwrap_or("")
        .trim();
    (!name.is_empty()).then(|| (name.to_string(), version))
}

/// An exact release version (`1.2.3`, `1.2.3-beta.1`), or `None` for a
/// range, tag or anything else OSV can't match as a single version.
fn exact_version(raw: &str) -> Option<String> {
    let v = raw.trim().trim_start_matches(['v', '=']);
    let exact = v.starts_with(|c: char| c.is_ascii_digit())
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+'))
        && !v.contains(['x', 'X']);
    exact.then(|| v.to_string())
}

/// Parse a dependency manifest bundled with a skill into OSV-queryable
/// specs (OWASP AST02: skill-bundle dependencies are the delivery
/// mechanism for staged-loader / dependency-confusion attacks; scanning
/// only the launch command misses them entirely).
///
/// Conservative on purpose: only exactly-pinned versions are returned.
/// - `requirements.txt`: `name==version` lines (extras and environment
///   markers stripped); ranges (`>=`) are skipped.
/// - `package.json`: `dependencies` + `devDependencies` entries whose
///   version is exact (no `^ ~ > < * x ||` range syntax).
pub fn parse_manifest_specs(filename: &str, content: &str) -> Vec<PackageSpec> {
    match filename {
        "requirements.txt" => content
            .lines()
            .filter_map(|line| {
                let line = line.split('#').next().unwrap_or("").trim();
                let (name, rest) = line.split_once("==")?;
                // strip extras: `pkg[extra]==1.0` -> `pkg`
                let name = name.split('[').next().unwrap_or(name).trim();
                // strip env markers / trailing tokens: `1.0 ; python<3` -> `1.0`
                let version = rest
                    .split(';')
                    .next()
                    .unwrap_or("")
                    .split_whitespace()
                    .next()
                    .unwrap_or("");
                if name.is_empty() || version.is_empty() {
                    return None;
                }
                Some(PackageSpec {
                    ecosystem: "PyPI",
                    name: name.to_string(),
                    version: Some(version.to_string()),
                })
            })
            .collect(),
        "package.json" => {
            let Ok(json) = serde_json::from_str::<serde_json::Value>(content) else {
                return Vec::new();
            };
            let mut specs = Vec::new();
            for section in ["dependencies", "devDependencies"] {
                let Some(deps) = json.get(section).and_then(|d| d.as_object()) else {
                    continue;
                };
                for (name, ver) in deps {
                    let Some(ver) = ver.as_str() else { continue };
                    let exact = ver.starts_with(|c: char| c.is_ascii_digit())
                        && !ver.contains(['^', '~', '>', '<', '*', 'x', '|', ' ']);
                    if exact {
                        specs.push(PackageSpec {
                            ecosystem: "npm",
                            name: name.clone(),
                            version: Some(ver.to_string()),
                        });
                    }
                }
            }
            specs
        }
        _ => Vec::new(),
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
    #[serde(default)]
    affected: Vec<OsvAffected>,
}

#[derive(Debug, Deserialize)]
struct OsvSeverity {
    #[serde(rename = "type")]
    severity_type: String,
    score: String,
}

/// Subset of OSV's `affected[]` we need to surface the fix version. OSV records
/// the release a vulnerability was fixed in inside `ranges[].events[].fixed`;
/// a record with no `fixed` event means no fix is available yet.
#[derive(Debug, Deserialize)]
struct OsvAffected {
    #[serde(default)]
    package: Option<OsvAffectedPackage>,
    #[serde(default)]
    ranges: Vec<OsvRange>,
}

#[derive(Debug, Deserialize)]
struct OsvAffectedPackage {
    #[serde(default)]
    name: String,
    #[serde(default)]
    ecosystem: String,
}

#[derive(Debug, Deserialize)]
struct OsvRange {
    #[serde(default)]
    events: Vec<OsvRangeEvent>,
}

#[derive(Debug, Deserialize)]
struct OsvRangeEvent {
    #[serde(default)]
    fixed: Option<String>,
    #[serde(default)]
    last_affected: Option<String>,
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
    check_osv(client, spec).await.unwrap_or_else(|e| {
        warn!("{e}");
        Vec::new()
    })
}

/// Like `query_osv`, but a failed lookup is an `Err` instead of an empty
/// list, so a caller that must not proceed without a verdict (starting a
/// stdio server) can tell "no advisories" from "couldn't check".
pub async fn check_osv(client: Client, spec: PackageSpec) -> Result<Vec<YaraScanResult>, String> {
    debug!(
        "Querying OSV.dev for {}/{} ({:?})",
        spec.ecosystem, spec.name, spec.version
    );
    let request_body = build_osv_request(&spec);
    let response = match client
        .post(osv_query_url())
        .timeout(Duration::from_secs(OSV_QUERY_TIMEOUT_SECS))
        .json(&request_body)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            return Err(format!(
                "OSV query failed for {}/{}: {}",
                spec.ecosystem, spec.name, e
            ))
        }
    };
    if !response.status().is_success() {
        return Err(format!(
            "OSV returned {} for {}/{}",
            response.status(),
            spec.ecosystem,
            spec.name
        ));
    }
    let body: OsvQueryResponse = response.json().await.map_err(|e| {
        format!(
            "Failed to parse OSV response for {}/{}: {}",
            spec.ecosystem, spec.name, e
        )
    })?;

    Ok(body
        .vulns
        .into_iter()
        .map(|v| osv_finding_to_yara_result(&spec, v))
        .collect())
}

/// Rule name for a launch package that is itself malware. The pre-launch
/// gate keys off this, so it lives in one place.
pub const MALICIOUS_DEPENDENCY_RULE: &str = "MaliciousDependency";

fn is_malicious_id(id: &str) -> bool {
    id.starts_with("MAL-")
}

/// True only when the record names affected ranges and every one of them
/// ends at a `fixed` version, so releases after it are known clean. An
/// entry with no ranges (a bare version list), an open range or a
/// `last_affected` bound is false: the newest release may be affected.
fn all_ranges_fixed(affected: &[OsvAffected]) -> bool {
    !affected.is_empty()
        && affected.iter().all(|a| {
            !a.ranges.is_empty()
                && a.ranges.iter().all(|r| {
                    r.events.iter().any(|e| e.fixed.is_some())
                        && r.events.iter().all(|e| e.last_affected.is_none())
                })
        })
}

/// True for an OSV finding that marks the package itself as malware.
pub fn is_malicious_finding(f: &YaraScanResult) -> bool {
    f.rule_name == MALICIOUS_DEPENDENCY_RULE
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
    let fixed_version = extract_fixed_version(spec, &vuln.affected);
    // OSV's malicious-package records use `MAL-` IDs (GitHub malware
    // advisories carry one as an alias). These aren't bugs to patch: the
    // package itself is the payload.
    let mal_record = is_malicious_id(&vuln.id) || vuln.aliases.iter().any(|a| is_malicious_id(a));
    // A pinned version only gets records that affect it. An unpinned launch
    // installs the newest release, which we can't see, so a record blocks it
    // unless every affected range is closed by a `fixed` version (the
    // incident is over and newer releases are clean). An ongoing hijack
    // (open range, `last_affected`, or a bare version list) still blocks.
    let malicious = mal_record && (spec.version.is_some() || !all_ranges_fixed(&vuln.affected));
    let (rule, name, severity, summary) = if malicious {
        (
            MALICIOUS_DEPENDENCY_RULE,
            "Malicious Dependency",
            "CRITICAL",
            summary.to_string(),
        )
    } else if mal_record {
        (
            "VulnerableDependency",
            "Vulnerable Dependency",
            "HIGH",
            format!("Malicious releases of this package were published ({summary}); pin a known-good version"),
        )
    } else {
        (
            "VulnerableDependency",
            "Vulnerable Dependency",
            severity,
            summary.to_string(),
        )
    };
    let summary = summary.as_str();
    YaraScanResult {
        target_type: "dependency".to_string(),
        target_name: format!(
            "{}/{}@{}",
            spec.ecosystem,
            spec.name,
            spec.version.as_deref().unwrap_or("?")
        ),
        rule_name: rule.to_string(),
        rule_file: Some("osv".to_string()),
        matched_text: Some(vuln.id.clone()),
        context,
        rule_metadata: Some(YaraRuleMetadata {
            name: Some(name.to_string()),
            author: Some("OSV.dev".to_string()),
            date: None,
            version: None,
            description: Some(summary.to_string()),
            severity: Some(severity.to_string()),
            category: Some("supply-chain".to_string()),
            confidence: Some("HIGH".to_string()),
            tags: vec!["dependency".to_string(), "osv".to_string()],
        }),
        owasp_tags: crate::taxonomy::tags_for_yara_rule(rule),
        installed_version: spec.version.clone(),
        fixed_version,
        phase: Some("pre-scan".to_string()),
        rules_executed: None,
        security_issues_detected: None,
        total_items_scanned: None,
        total_matches: None,
        status: Some("warning".to_string()),
    }
}

/// Compare two package names within an ecosystem. PyPI treats runs of `-`,
/// `_`, and `.` as equivalent and is case-insensitive (PEP 503), so
/// `pip_install_test` and `pip-install-test` are the same project; OSV returns
/// the canonical name while our spec carries the name as typed on the command
/// line. Other ecosystems compare case-insensitively as-is.
fn pkg_names_match(ecosystem: &str, a: &str, b: &str) -> bool {
    if ecosystem.eq_ignore_ascii_case("PyPI") {
        normalize_pypi_name(a) == normalize_pypi_name(b)
    } else {
        a.eq_ignore_ascii_case(b)
    }
}

/// PEP 503 name normalization: lowercase and collapse any run of `-`, `_`, or
/// `.` into a single `-`. PyPI names are ASCII, so ASCII lowercasing suffices.
fn normalize_pypi_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut prev_sep = false;
    for c in name.chars() {
        if matches!(c, '-' | '_' | '.') {
            if !prev_sep {
                out.push('-');
            }
            prev_sep = true;
        } else {
            out.push(c.to_ascii_lowercase());
            prev_sep = false;
        }
    }
    out
}

/// Best-effort "the advisory says this is fixed in version X" signal, pulled
/// from OSV's `affected[].ranges[].events[].fixed`. OSV can list several
/// affected packages; we only read `fixed` from the package we queried (or an
/// entry that carries no package object, which OSV occasionally omits), never
/// from a different package in a multi-package advisory. This is a surfacing
/// hint for the UI, not a precise range resolution: when a package has several
/// ranges (e.g. parallel release branches with separate fixes) we surface the
/// first `fixed` we find rather than resolving which range covers the installed
/// version, since that needs per-ecosystem version comparison. The result is
/// always a valid fix, just not necessarily the lowest one for the installed
/// branch. Returns `None` when OSV lists no fixed version for our package.
fn extract_fixed_version(spec: &PackageSpec, affected: &[OsvAffected]) -> Option<String> {
    fn first_fixed(a: &OsvAffected) -> Option<String> {
        a.ranges
            .iter()
            .flat_map(|r| r.events.iter())
            .find_map(|e| e.fixed.clone())
    }
    let names_our_pkg = |a: &OsvAffected| {
        a.package.as_ref().is_some_and(|p| {
            p.ecosystem.eq_ignore_ascii_case(spec.ecosystem)
                && pkg_names_match(spec.ecosystem, &p.name, &spec.name)
        })
    };
    // If the advisory explicitly names our package, trust only those entries so
    // a sibling package's fix never leaks in. Only when nothing names our
    // package do we fall back to entries with no package object, which OSV
    // occasionally omits.
    if affected.iter().any(&names_our_pkg) {
        return affected
            .iter()
            .filter(|a| names_our_pkg(a))
            .find_map(first_fixed);
    }
    affected
        .iter()
        .filter(|a| a.package.is_none())
        .find_map(first_fixed)
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
    fn launcher_forms_resolve_to_the_package() {
        let spec = |cmd: &str, args: &[&str]| {
            let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
            parse_package_spec_from_command(cmd, &args).map(|s| {
                format!(
                    "{}:{}@{}",
                    s.ecosystem,
                    s.name,
                    s.version.unwrap_or_default()
                )
            })
        };
        let cases: &[(&str, &[&str], &str)] = &[
            ("/usr/local/bin/npx", &["-y", "evil"], "npm:evil@"),
            ("npx.cmd", &["-y", "evil@1.2.3"], "npm:evil@1.2.3"),
            ("NPX.EXE", &["evil"], "npm:evil@"),
            (
                "cmd",
                &["/c", "npx", "-y", "@scope/evil@2.0.0"],
                "npm:@scope/evil@2.0.0",
            ),
            ("bunx", &["evil"], "npm:evil@"),
            ("bun", &["x", "evil"], "npm:evil@"),
            ("pnpm", &["dlx", "evil"], "npm:evil@"),
            ("yarn", &["dlx", "evil"], "npm:evil@"),
            ("npm", &["exec", "--yes", "evil"], "npm:evil@"),
            ("npx", &["--package=evil", "-y", "bin"], "npm:evil@"),
            ("npx", &["-p", "evil@1.0.0", "bin"], "npm:evil@1.0.0"),
            ("npx", &["-y", "evil@^1.0"], "npm:evil@"),
            ("npx", &["-y", "evil@latest"], "npm:evil@"),
            ("uvx", &["evil>=1.0"], "PyPI:evil@"),
            ("uvx", &["evil@1.0"], "PyPI:evil@1.0"),
            ("uvx", &["evil[extra]==2.1"], "PyPI:evil@2.1"),
            ("uv", &["tool", "run", "evil"], "PyPI:evil@"),
            (
                "pipx",
                &["run", "--spec", "evil==3.0", "evil-cli"],
                "PyPI:evil@3.0",
            ),
        ];
        for (cmd, args, want) in cases {
            assert_eq!(spec(cmd, args).as_deref(), Some(*want), "{cmd} {args:?}");
        }
        for (cmd, args) in [
            ("python3", &["server.py"][..]),
            ("node", &["./x.js"][..]),
            ("npm", &["run", "x"][..]),
        ] {
            assert!(spec(cmd, args).is_none(), "{cmd} {args:?}");
        }
    }

    #[test]
    fn unpinned_launch_blocks_unless_the_incident_is_fixed() {
        let unpinned = PackageSpec {
            ecosystem: "npm",
            name: "pkg".to_string(),
            version: None,
        };
        let rec = |ranges: serde_json::Value| -> OsvVulnerability {
            serde_json::from_value(serde_json::json!({
                "id": "MAL-2026-9",
                "affected": [{ "package": { "name": "pkg", "ecosystem": "npm" }, "ranges": ranges }]
            }))
            .unwrap()
        };
        let blocks = |ranges: serde_json::Value| {
            is_malicious_finding(&osv_finding_to_yara_result(&unpinned, rec(ranges)))
        };
        // Whole package, an ongoing hijack (open range), last_affected, and a
        // bare version list all block: the newest release may be affected.
        assert!(blocks(
            serde_json::json!([{ "type": "SEMVER", "events": [{ "introduced": "0" }] }])
        ));
        assert!(blocks(
            serde_json::json!([{ "type": "SEMVER", "events": [{ "introduced": "1.26.1" }] }])
        ));
        assert!(blocks(
            serde_json::json!([{ "type": "SEMVER", "events": [{ "introduced": "1.0.0" }, { "last_affected": "1.26.2" }] }])
        ));
        assert!(blocks(serde_json::json!([])));
        let one_release = osv_finding_to_yara_result(
            &unpinned,
            rec(
                serde_json::json!([{ "type": "SEMVER", "events": [{ "introduced": "4.1.1" }, { "fixed": "4.1.2" }] }]),
            ),
        );
        assert!(!is_malicious_finding(&one_release));
        assert_eq!(
            one_release
                .rule_metadata
                .as_ref()
                .unwrap()
                .severity
                .as_deref(),
            Some("HIGH")
        );
        // A pinned version only receives records that affect it: always blocks.
        let pinned = PackageSpec {
            version: Some("4.1.1".to_string()),
            ..unpinned.clone()
        };
        assert!(is_malicious_finding(&osv_finding_to_yara_result(
            &pinned,
            rec(
                serde_json::json!([{ "type": "SEMVER", "events": [{ "introduced": "4.1.1" }, { "fixed": "4.1.2" }] }])
            ),
        )));
    }

    #[test]
    fn malicious_package_records_are_classified_separately() {
        let spec = PackageSpec {
            ecosystem: "npm",
            name: "some-pkg".to_string(),
            version: Some("1.0.0".to_string()),
        };
        let vuln = |id: &str, aliases: &[&str]| -> OsvVulnerability {
            serde_json::from_value(serde_json::json!({ "id": id, "aliases": aliases })).unwrap()
        };
        let by_id = osv_finding_to_yara_result(&spec, vuln("MAL-2026-1", &[]));
        let by_alias =
            osv_finding_to_yara_result(&spec, vuln("GHSA-aaaa-bbbb-cccc", &["MAL-2026-2"]));
        let cve = osv_finding_to_yara_result(&spec, vuln("GHSA-dddd-eeee-ffff", &["CVE-2026-1"]));
        for f in [&by_id, &by_alias] {
            assert!(is_malicious_finding(f));
            assert_eq!(f.rule_name, "MaliciousDependency");
            assert_eq!(
                f.rule_metadata.as_ref().unwrap().severity.as_deref(),
                Some("CRITICAL")
            );
        }
        assert!(!is_malicious_finding(&cve));
        assert_eq!(cve.rule_name, "VulnerableDependency");
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

    #[test]
    fn extracts_fixed_version_from_affected() {
        let vuln: OsvVulnerability = serde_json::from_value(serde_json::json!({
            "id": "GHSA-test-fixed",
            "summary": "bad bug",
            "affected": [{
                "package": { "name": "lodash", "ecosystem": "npm" },
                "ranges": [{
                    "type": "SEMVER",
                    "events": [ { "introduced": "0" }, { "fixed": "4.17.21" } ]
                }]
            }]
        }))
        .expect("valid osv json");
        let spec = PackageSpec {
            ecosystem: "npm",
            name: "lodash".into(),
            version: Some("4.17.20".into()),
        };
        assert_eq!(
            extract_fixed_version(&spec, &vuln.affected),
            Some("4.17.21".to_string())
        );
    }

    #[test]
    fn no_fixed_version_when_absent() {
        // A record whose only event is `introduced` (no fix released yet).
        let vuln: OsvVulnerability = serde_json::from_value(serde_json::json!({
            "id": "GHSA-test-nofix",
            "affected": [{
                "package": { "name": "lodash", "ecosystem": "npm" },
                "ranges": [{ "type": "SEMVER", "events": [ { "introduced": "0" } ] }]
            }]
        }))
        .expect("valid osv json");
        let spec = PackageSpec {
            ecosystem: "npm",
            name: "lodash".into(),
            version: Some("4.17.20".into()),
        };
        assert_eq!(extract_fixed_version(&spec, &vuln.affected), None);
    }

    #[test]
    fn ignores_fix_from_a_different_package() {
        // Multi-package advisory: our package has no fix, a sibling does. We
        // must not borrow the sibling's fixed version.
        let vuln: OsvVulnerability = serde_json::from_value(serde_json::json!({
            "id": "GHSA-test-multi",
            "affected": [
                {
                    "package": { "name": "lodash", "ecosystem": "npm" },
                    "ranges": [{ "type": "SEMVER", "events": [ { "introduced": "0" } ] }]
                },
                {
                    "package": { "name": "other-pkg", "ecosystem": "npm" },
                    "ranges": [{
                        "type": "SEMVER",
                        "events": [ { "introduced": "0" }, { "fixed": "2.0.0" } ]
                    }]
                }
            ]
        }))
        .expect("valid osv json");
        let spec = PackageSpec {
            ecosystem: "npm",
            name: "lodash".into(),
            version: Some("4.17.20".into()),
        };
        assert_eq!(extract_fixed_version(&spec, &vuln.affected), None);
    }

    #[test]
    fn package_less_fallback_only_when_no_named_match() {
        let spec = PackageSpec {
            ecosystem: "npm",
            name: "lodash".into(),
            version: Some("4.17.20".into()),
        };

        // A named entry for our package (no fix) wins over a package-less entry
        // that does have one: a named-but-unfixed package reports no fix.
        let with_named: OsvVulnerability = serde_json::from_value(serde_json::json!({
            "id": "GHSA-test-mixed",
            "affected": [
                {
                    "package": { "name": "lodash", "ecosystem": "npm" },
                    "ranges": [{ "type": "SEMVER", "events": [ { "introduced": "0" } ] }]
                },
                { "ranges": [{ "type": "SEMVER", "events": [ { "fixed": "9.9.9" } ] }] }
            ]
        }))
        .expect("valid osv json");
        assert_eq!(extract_fixed_version(&spec, &with_named.affected), None);

        // With no named entry at all, the package-less fix is used.
        let unlabeled: OsvVulnerability = serde_json::from_value(serde_json::json!({
            "id": "GHSA-test-unlabeled",
            "affected": [
                { "ranges": [{ "type": "SEMVER", "events": [ { "fixed": "9.9.9" } ] }] }
            ]
        }))
        .expect("valid osv json");
        assert_eq!(
            extract_fixed_version(&spec, &unlabeled.affected),
            Some("9.9.9".to_string())
        );
    }

    #[test]
    fn matches_pypi_names_up_to_normalization() {
        // PyPI treats pip_install_test and pip-install-test as one project; the
        // OSV record's canonical name must still match our as-typed spec name.
        let vuln: OsvVulnerability = serde_json::from_value(serde_json::json!({
            "id": "GHSA-test-pypi",
            "affected": [{
                "package": { "name": "pip_install_test", "ecosystem": "PyPI" },
                "ranges": [{
                    "type": "ECOSYSTEM",
                    "events": [ { "introduced": "0" }, { "fixed": "1.2.0" } ]
                }]
            }]
        }))
        .expect("valid osv json");
        let spec = PackageSpec {
            ecosystem: "PyPI",
            name: "pip-install-test".into(),
            version: Some("1.1.0".into()),
        };
        assert_eq!(
            extract_fixed_version(&spec, &vuln.affected),
            Some("1.2.0".to_string())
        );
    }

    #[test]
    fn osv_finding_populates_installed_and_fixed() {
        let vuln: OsvVulnerability = serde_json::from_value(serde_json::json!({
            "id": "GHSA-test-full",
            "summary": "bug",
            "severity": [{ "type": "CVSS_V3", "score": "9.8" }],
            "affected": [{
                "package": { "name": "lodash", "ecosystem": "npm" },
                "ranges": [{
                    "type": "SEMVER",
                    "events": [ { "introduced": "0" }, { "fixed": "4.17.21" } ]
                }]
            }]
        }))
        .expect("valid osv json");
        let spec = PackageSpec {
            ecosystem: "npm",
            name: "lodash".into(),
            version: Some("4.17.20".into()),
        };
        let result = osv_finding_to_yara_result(&spec, vuln);
        assert_eq!(result.installed_version, Some("4.17.20".to_string()));
        assert_eq!(result.fixed_version, Some("4.17.21".to_string()));
        assert_eq!(result.target_type, "dependency");
    }

    #[test]
    fn parses_requirements_txt_pins_only() {
        let content = "requests==2.31.0\nflask>=2.0  # range, skipped\n\
                       pyyaml[safe]==6.0.1 ; python_version<'3.12'\n# comment\n";
        let specs = parse_manifest_specs("requirements.txt", content);
        assert_eq!(specs.len(), 2);
        assert_eq!(specs[0].name, "requests");
        assert_eq!(specs[0].version.as_deref(), Some("2.31.0"));
        assert_eq!(specs[1].name, "pyyaml");
        assert_eq!(specs[1].version.as_deref(), Some("6.0.1"));
    }

    #[test]
    fn parses_package_json_exact_versions_only() {
        let content = r#"{
            "dependencies": { "lodash": "4.17.20", "axios": "^1.0.0" },
            "devDependencies": { "left-pad": "1.3.0" }
        }"#;
        let specs = parse_manifest_specs("package.json", content);
        let names: Vec<&str> = specs.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"lodash"));
        assert!(names.contains(&"left-pad"));
        assert!(!names.contains(&"axios"));
    }

    #[test]
    fn unknown_manifest_yields_nothing() {
        assert!(parse_manifest_specs("Gemfile", "gem 'rails'").is_empty());
    }
}
