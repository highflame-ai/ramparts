//! Rule-quality evaluation against a fixed corpus.
//!
//! The pattern rules were written to match content, but until the rule-scan
//! input was widened they only ever received a tool NAME — so nothing matched
//! and their precision was never exercised. The first real run against live
//! servers flagged 24 of 44 tools on GitHub's own MCP server.
//!
//! This module pins that down with two corpora:
//!
//! - `tests/corpus/benign.json` — 77 tools, resources, and prompts captured
//!   verbatim from three production servers (GitHub, `server-everything`,
//!   DeepWiki). Every match here is a false positive by definition.
//! - `tests/corpus/malicious.json` — hand-built tool-poisoning, injection,
//!   secret-leak, and traversal cases. Every miss here is a false negative.
//!
//! The thresholds below are deliberately strict: a scanner that cries wolf on
//! more than a couple of percent of a real server's tools trains its users to
//! ignore it, which is worse than not scanning.

// The module is already gated at its declaration in main.rs; a second
// `#![cfg(test)]` here would be a duplicated attribute.

use crate::scanner::ThreatRules;
use serde_json::Value;

/// Render a corpus entry the same way the scanner renders a live item, so the
/// evaluation exercises the real input shape rather than an approximation.
fn render(entry: &Value) -> String {
    let kind = entry.get("kind").and_then(Value::as_str).unwrap_or("tool");
    let name = entry.get("name").and_then(Value::as_str).unwrap_or("");
    let description = entry.get("description").and_then(Value::as_str);

    let mut text = format!("{}: {}\n", kind.to_uppercase(), name);
    if let Some(description) = description {
        text.push_str(&format!("DESCRIPTION: {description}\n"));
    }
    if let Some(uri) = entry.get("uri").and_then(Value::as_str) {
        text.push_str(&format!("URI: {uri}\n"));
    }
    if let Some(mime) = entry.get("mime_type").and_then(Value::as_str) {
        text.push_str(&format!("MIME_TYPE: {mime}\n"));
    }
    if let Some(schema) = entry.get("input_schema") {
        if !schema.is_null() {
            text.push_str(&format!("INPUT_SCHEMA: {schema}\n"));
        }
    }
    if let Some(arguments) = entry.get("arguments").and_then(Value::as_array) {
        for argument in arguments {
            let arg_name = argument.get("name").and_then(Value::as_str).unwrap_or("");
            let arg_desc = argument
                .get("description")
                .and_then(Value::as_str)
                .unwrap_or("");
            text.push_str(&format!("ARGUMENT: {arg_name} — {arg_desc}\n"));
        }
    }
    text
}

/// Scan the same way the live pipeline does: raw text first, then every
/// normalized/decoded view, deduped by rule name. Without this the corpus
/// would test `pre_scan` in isolation and never exercise the
/// evasion-resistant rescan that `scan_items_with_yara` applies in
/// production — so a Unicode/base64 evasion case would look "missed" here
/// even though the real scanner catches it.
fn scan_all_views(engine: &ThreatRules, text: &str) -> Vec<String> {
    let mut rules: Vec<String> = engine
        .pre_scan(text, "corpus")
        .into_iter()
        .map(|h| h.rule_name)
        .collect();
    for view in crate::normalize::additional_scan_views(text) {
        for h in engine.pre_scan(&view, "corpus") {
            rules.push(h.rule_name);
        }
    }
    rules.sort();
    rules.dedup();
    rules
}

fn load(path: &str) -> Vec<Value> {
    let raw = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("corpus {path} must be readable: {e}"));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("corpus {path} must be valid JSON: {e}"))
}

struct Outcome {
    benign_total: usize,
    benign_flagged: Vec<(String, String, Vec<String>)>,
    malicious_total: usize,
    malicious_missed: Vec<(String, String)>,
}

fn evaluate() -> Outcome {
    let engine = ThreatRules::new(
        &crate::scanner::resolve_rules_dir()
            .expect("rules directory must resolve when running the evaluation")
            .to_string_lossy(),
    )
    .expect("rules must compile");

    let benign = load("tests/corpus/benign.json");
    let malicious = load("tests/corpus/malicious.json");

    let mut benign_flagged = Vec::new();
    for entry in &benign {
        let rules = scan_all_views(&engine, &render(entry));
        if !rules.is_empty() {
            benign_flagged.push((
                entry["origin"].as_str().unwrap_or("?").to_string(),
                entry["name"].as_str().unwrap_or("?").to_string(),
                rules,
            ));
        }
    }

    let mut malicious_missed = Vec::new();
    for entry in &malicious {
        let rules = scan_all_views(&engine, &render(entry));
        if rules.is_empty() {
            malicious_missed.push((
                entry["id"].as_str().unwrap_or("?").to_string(),
                entry["attack"].as_str().unwrap_or("?").to_string(),
            ));
        }
    }

    Outcome {
        benign_total: benign.len(),
        benign_flagged,
        malicious_total: malicious.len(),
        malicious_missed,
    }
}

/// Report the current numbers. Always passes — this is the measurement, and
/// the two tests below are the gates.
#[test]
fn report_rule_quality() {
    let outcome = evaluate();
    let fp = outcome.benign_flagged.len();
    let tp = outcome.malicious_total - outcome.malicious_missed.len();

    println!("\n=== RULE QUALITY ===");
    println!(
        "false positives : {fp}/{} benign items ({:.0}%)",
        outcome.benign_total,
        100.0 * fp as f64 / outcome.benign_total as f64
    );
    println!(
        "true positives  : {tp}/{} malicious items ({:.0}%)",
        outcome.malicious_total,
        100.0 * tp as f64 / outcome.malicious_total as f64
    );
    if !outcome.benign_flagged.is_empty() {
        println!("\nfalse positives:");
        for (origin, name, rules) in &outcome.benign_flagged {
            println!("  [{origin}] {name} -> {rules:?}");
        }
    }
    if !outcome.malicious_missed.is_empty() {
        println!("\nmissed attacks:");
        for (id, attack) in &outcome.malicious_missed {
            println!("  {id} ({attack})");
        }
    }
    println!();
}

/// A benign production server must not be flagged. This is the gate that the
/// pre-rewrite rules fail badly.
#[test]
fn benign_servers_produce_no_findings() {
    let outcome = evaluate();
    assert!(
        outcome.benign_flagged.is_empty(),
        "{} of {} benign items flagged; every one is a false positive:\n{}",
        outcome.benign_flagged.len(),
        outcome.benign_total,
        outcome
            .benign_flagged
            .iter()
            .map(|(o, n, r)| format!("  [{o}] {n} -> {r:?}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// Every crafted attack must be caught. Cutting false positives by making the
/// rules inert would pass the test above and fail this one.
#[test]
fn known_attacks_are_all_detected() {
    let outcome = evaluate();
    assert!(
        outcome.malicious_missed.is_empty(),
        "{} of {} attacks missed:\n{}",
        outcome.malicious_missed.len(),
        outcome.malicious_total,
        outcome
            .malicious_missed
            .iter()
            .map(|(id, attack)| format!("  {id} ({attack})"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}
