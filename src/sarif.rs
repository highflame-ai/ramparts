//! SARIF 2.1.0 output for ramparts scan results.
//!
//! Emits a single SARIF log per `print_result` / `print_multi_server_results`
//! call. We hand-build the JSON via `serde_json::Value` rather than defining
//! ~30 nested types we'd only use for one-way emission. The shape conforms
//! to SARIF 2.1.0 and uploads cleanly to GitHub Advanced Security via
//! `github/codeql-action/upload-sarif`.
//!
//! See ramparts#96 for the design discussion. OWASP MCP Top 10 IDs (see
//! ramparts#101) are emitted as `properties.tags` on each result so
//! downstream consumers can filter by category.

use crate::security::{SecurityIssue, SecurityIssueType};
use crate::types::{ScanResult, YaraScanResult};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

const SARIF_SCHEMA_URI: &str =
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";
const SARIF_VERSION: &str = "2.1.0";
const TOOL_INFO_URI: &str = "https://github.com/highflame-ai/ramparts";

/// Convert a single ScanResult into a SARIF log document. Useful for
/// `ramparts scan <url> --format sarif`.
pub fn scan_result_to_sarif(result: &ScanResult) -> Value {
    sarif_log(std::slice::from_ref(result))
}

/// Convert a batch of ScanResults (one per scanned server) into a single
/// SARIF log document. Each server becomes its own `runs[]` entry so
/// findings stay attributed to their source.
pub fn scan_results_to_sarif(results: &[ScanResult]) -> Value {
    sarif_log(results)
}

fn sarif_log(results: &[ScanResult]) -> Value {
    let runs: Vec<Value> = results.iter().map(build_run).collect();
    json!({
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": runs,
    })
}

/// Build a single SARIF `run` for one scanned server. Collects the rule
/// definitions actually referenced by this server's findings into
/// `tool.driver.rules` and emits the findings in `results`.
fn build_run(scan: &ScanResult) -> Value {
    // Collect (ruleId -> rule definition) so the driver carries one entry per
    // distinct rule we actually fired in this run. BTreeMap keeps the rule
    // list deterministic.
    let mut rules: BTreeMap<String, Value> = BTreeMap::new();
    let mut sarif_results: Vec<Value> = Vec::new();

    // Map YARA findings (and the in-process cross-origin scanner findings,
    // which use the same type).
    for yara in &scan.yara_results {
        // Skip the synthetic summary rows — they aren't real findings.
        if yara.target_type == "summary" {
            continue;
        }
        let rule_id = yara.rule_name.clone();
        rules
            .entry(rule_id.clone())
            .or_insert_with(|| build_rule_from_yara(yara));
        sarif_results.push(build_result_from_yara(scan, yara));
    }

    // Map LLM-detected security issues across tools/prompts/resources.
    if let Some(security) = &scan.security_issues {
        for issue in &security.tool_issues {
            let rule_id = security_issue_rule_id(issue.issue_type);
            rules
                .entry(rule_id.clone())
                .or_insert_with(|| build_rule_from_security_issue(issue));
            sarif_results.push(build_result_from_security_issue(scan, issue, "tool"));
        }
        for issue in &security.prompt_issues {
            let rule_id = security_issue_rule_id(issue.issue_type);
            rules
                .entry(rule_id.clone())
                .or_insert_with(|| build_rule_from_security_issue(issue));
            sarif_results.push(build_result_from_security_issue(scan, issue, "prompt"));
        }
        for issue in &security.resource_issues {
            let rule_id = security_issue_rule_id(issue.issue_type);
            rules
                .entry(rule_id.clone())
                .or_insert_with(|| build_rule_from_security_issue(issue));
            sarif_results.push(build_result_from_security_issue(scan, issue, "resource"));
        }
    }

    json!({
        "tool": {
            "driver": {
                "name": "ramparts",
                "version": env!("CARGO_PKG_VERSION"),
                "informationUri": TOOL_INFO_URI,
                "rules": rules.into_values().collect::<Vec<_>>(),
            }
        },
        "invocations": [{
            "executionSuccessful": matches!(scan.status, crate::types::ScanStatus::Success),
            "endTimeUtc": scan.timestamp.to_rfc3339(),
        }],
        "originalUriBaseIds": {
            "MCP_SERVER": { "uri": scan.url }
        },
        "results": sarif_results,
    })
}

fn build_rule_from_yara(yara: &YaraScanResult) -> Value {
    let mut rule = Map::new();
    rule.insert("id".into(), Value::String(yara.rule_name.clone()));
    rule.insert("name".into(), Value::String(yara.rule_name.clone()));

    if let Some(meta) = &yara.rule_metadata {
        if let Some(name) = meta.name.as_ref() {
            rule.insert("shortDescription".into(), json!({ "text": name }));
        }
        if let Some(desc) = meta.description.as_ref() {
            rule.insert("fullDescription".into(), json!({ "text": desc }));
        }
        if let Some(sev) = meta.severity.as_ref() {
            let mut props = Map::new();
            props.insert("severity".into(), Value::String(sev.clone()));
            props.insert(
                "security-severity".into(),
                Value::String(severity_score(sev).to_string()),
            );
            if !yara.owasp_tags.is_empty() {
                props.insert("tags".into(), owasp_tags_value(&yara.owasp_tags));
            }
            rule.insert("properties".into(), Value::Object(props));
        }
    } else if !yara.owasp_tags.is_empty() {
        rule.insert(
            "properties".into(),
            json!({ "tags": owasp_tags_value(&yara.owasp_tags) }),
        );
    }

    Value::Object(rule)
}

fn build_result_from_yara(scan: &ScanResult, yara: &YaraScanResult) -> Value {
    let severity = yara
        .rule_metadata
        .as_ref()
        .and_then(|m| m.severity.as_deref())
        .unwrap_or("MEDIUM");
    let level = severity_to_sarif_level(severity);

    let message = yara
        .matched_text
        .as_ref()
        .map(|t| format!("{}: {}", yara.context, t))
        .unwrap_or_else(|| yara.context.clone());

    let mut props = Map::new();
    props.insert(
        "security-severity".into(),
        Value::String(severity_score(severity).to_string()),
    );
    if !yara.owasp_tags.is_empty() {
        props.insert("tags".into(), owasp_tags_value(&yara.owasp_tags));
    }
    props.insert(
        "target".into(),
        json!({
            "type": yara.target_type,
            "name": yara.target_name,
        }),
    );

    json!({
        "ruleId": yara.rule_name,
        "level": level,
        "message": { "text": message },
        "locations": [logical_location(&scan.url, &yara.target_name)],
        "properties": Value::Object(props),
    })
}

fn build_rule_from_security_issue(issue: &SecurityIssue) -> Value {
    let id = security_issue_rule_id(issue.issue_type);
    let mut props = Map::new();
    props.insert("severity".into(), Value::String(issue.severity.clone()));
    props.insert(
        "security-severity".into(),
        Value::String(severity_score(&issue.severity).to_string()),
    );
    if !issue.owasp_tags.is_empty() {
        props.insert("tags".into(), owasp_tags_value(&issue.owasp_tags));
    }
    json!({
        "id": id,
        "name": format!("{:?}", issue.issue_type),
        "shortDescription": { "text": issue.message },
        "fullDescription": { "text": issue.description },
        "properties": Value::Object(props),
    })
}

fn build_result_from_security_issue(
    scan: &ScanResult,
    issue: &SecurityIssue,
    target_kind: &str,
) -> Value {
    let target_name = issue
        .tool_name
        .clone()
        .or_else(|| issue.prompt_name.clone())
        .or_else(|| issue.resource_uri.clone())
        .unwrap_or_else(|| target_kind.to_string());

    let mut props = Map::new();
    props.insert(
        "security-severity".into(),
        Value::String(severity_score(&issue.severity).to_string()),
    );
    if !issue.owasp_tags.is_empty() {
        props.insert("tags".into(), owasp_tags_value(&issue.owasp_tags));
    }
    props.insert(
        "target".into(),
        json!({ "type": target_kind, "name": target_name.clone() }),
    );

    let level = severity_to_sarif_level(&issue.severity);

    json!({
        "ruleId": security_issue_rule_id(issue.issue_type),
        "level": level,
        "message": { "text": issue.message },
        "locations": [logical_location(&scan.url, &target_name)],
        "properties": Value::Object(props),
    })
}

fn logical_location(server_url: &str, target_name: &str) -> Value {
    json!({
        "logicalLocations": [{
            "name": target_name,
            "fullyQualifiedName": format!("{server_url}::{target_name}"),
            "kind": "function"
        }]
    })
}

fn owasp_tags_value(tags: &[crate::taxonomy::OwaspTag]) -> Value {
    Value::Array(
        tags.iter()
            .map(|t| Value::String(format!("owasp-mcp-top-10:{}:{}", t.version, t.id)))
            .collect(),
    )
}

fn security_issue_rule_id(t: SecurityIssueType) -> String {
    format!("ramparts.security.{t:?}")
}

/// Map ramparts severity (CRITICAL/HIGH/MEDIUM/LOW) to a SARIF `level` value
/// (`error`, `warning`, `note`). SARIF doesn't have a CRITICAL level so we
/// fold it into `error`.
fn severity_to_sarif_level(sev: &str) -> &'static str {
    match sev.to_ascii_uppercase().as_str() {
        "CRITICAL" | "HIGH" => "error",
        "MEDIUM" => "warning",
        _ => "note",
    }
}

/// Map ramparts severity to a numeric `security-severity` (CVSS-like 0–10)
/// so GitHub code-scanning renders the right severity badge.
fn severity_score(sev: &str) -> f32 {
    match sev.to_ascii_uppercase().as_str() {
        "CRITICAL" => 9.5,
        "HIGH" => 7.5,
        "MEDIUM" => 5.0,
        "LOW" => 3.0,
        _ => 1.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ScanResult;

    #[test]
    fn empty_result_produces_valid_sarif_structure() {
        let result = ScanResult::new("http://localhost:3000".to_string());
        let log = scan_result_to_sarif(&result);
        assert_eq!(log["version"], "2.1.0");
        assert!(log["runs"].is_array());
        assert_eq!(log["runs"].as_array().unwrap().len(), 1);
        let run = &log["runs"][0];
        assert_eq!(run["tool"]["driver"]["name"], "ramparts");
        assert!(run["results"].is_array());
    }

    #[test]
    fn severity_mapping_covers_all_levels() {
        assert_eq!(severity_to_sarif_level("CRITICAL"), "error");
        assert_eq!(severity_to_sarif_level("HIGH"), "error");
        assert_eq!(severity_to_sarif_level("MEDIUM"), "warning");
        assert_eq!(severity_to_sarif_level("LOW"), "note");
        assert_eq!(severity_to_sarif_level("unknown"), "note");
    }
}
