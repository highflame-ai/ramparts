//! Content baselining for rug-pull detection (OWASP AST07 - Update Drift).
//!
//! `MCPConfigChanged` (scanner.rs) already catches a swapped server
//! *launch command*. This module pins the *content* an agent actually
//! trusts: individual tool definitions served by a live MCP server, and
//! skill files on disk. A definition that changes after first sight is
//! the rug-pull pattern — reviewed once, swapped later.
//!
//! Semantics match `MCPConfigChanged`: first sight silently baselines;
//! a change keeps firing until the stored entry is removed (delete
//! `~/.ramparts/content-baseline.json` to re-baseline).

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;
use tracing::debug;

use crate::types::{YaraRuleMetadata, YaraScanResult};

#[derive(Debug, PartialEq, Eq)]
pub enum Drift {
    New,
    Unchanged,
    Changed,
}

pub struct BaselineStore {
    path: PathBuf,
    map: HashMap<String, String>,
    dirty: bool,
}

impl BaselineStore {
    pub fn load_default() -> Self {
        let path = dirs::home_dir()
            .map(|mut p| {
                p.push(".ramparts");
                p.push("content-baseline.json");
                p
            })
            .unwrap_or_else(|| PathBuf::from(".ramparts/content-baseline.json"));
        Self::load_from(path)
    }

    pub fn load_from(path: PathBuf) -> Self {
        let map = std::fs::read_to_string(&path)
            .ok()
            .and_then(|c| serde_json::from_str(&c).ok())
            .unwrap_or_default();
        Self {
            path,
            map,
            dirty: false,
        }
    }

    /// Compare `fingerprint` against the stored entry for
    /// `namespace`/`key`. New entries are recorded; changed entries are
    /// NOT overwritten, so the finding persists until re-baselined.
    pub fn check(&mut self, namespace: &str, key: &str, fingerprint: &str) -> Drift {
        let store_key = format!("{namespace}\u{1f}{key}");
        match self.map.get(&store_key) {
            Some(stored) if stored == fingerprint => Drift::Unchanged,
            Some(_) => Drift::Changed,
            None => {
                self.map.insert(store_key, fingerprint.to_string());
                self.dirty = true;
                Drift::New
            }
        }
    }

    /// Persist new entries (best-effort, like the mcp-baseline writes).
    pub fn save(&mut self) {
        if !self.dirty {
            return;
        }
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(serialized) = serde_json::to_string_pretty(&self.map) {
            if std::fs::write(&self.path, serialized).is_ok() {
                self.dirty = false;
            }
        }
    }
}

/// sha256 over length-prefixed fields so ("ab","c") can't collide with ("a","bc").
pub fn fingerprint_fields(fields: &[(&str, &str)]) -> String {
    let mut hasher = Sha256::new();
    for (label, value) in fields {
        hasher.update(label.as_bytes());
        hasher.update(b"\x1f");
        hasher.update((value.len() as u64).to_le_bytes());
        hasher.update(value.as_bytes());
        hasher.update(b"\x1e");
    }
    format!("{:x}", hasher.finalize())
}

fn drift_finding(
    rule_name: &str,
    target_type: &str,
    target_name: &str,
    description: &str,
    context: String,
) -> YaraScanResult {
    YaraScanResult {
        target_type: target_type.to_string(),
        target_name: target_name.to_string(),
        rule_name: rule_name.to_string(),
        rule_file: None,
        matched_text: None,
        context,
        rule_metadata: Some(YaraRuleMetadata {
            name: Some("Baseline Change".to_string()),
            author: Some("Ramparts".to_string()),
            date: None,
            version: None,
            description: Some(description.to_string()),
            severity: Some("HIGH".to_string()),
            category: Some("supply-chain".to_string()),
            confidence: Some("MEDIUM".to_string()),
            tags: vec!["baseline".to_string(), "rug-pull".to_string()],
        }),
        owasp_tags: crate::taxonomy::tags_for_yara_rule(rule_name),
        installed_version: None,
        fixed_version: None,
        phase: None,
        rules_executed: None,
        security_issues_detected: None,
        total_items_scanned: None,
        total_matches: None,
        status: Some("warning".to_string()),
    }
}

/// Pin every tool definition served by `server_key`; emit `MCPToolChanged`
/// for any whose name/description/schema differs from the stored baseline.
pub fn check_tool_drift(server_key: &str, tools: &[crate::types::MCPTool]) -> Vec<YaraScanResult> {
    // A blank server key (e.g. the analyze-only HTTP path passes an empty
    // url) can't distinguish one server from another, so tools of the same
    // name from different servers would collide in the shared baseline —
    // producing false drift or masking real drift. Skip baselining rather
    // than key on an ambiguous identity.
    if server_key.is_empty() {
        debug!("Skipping tool-drift baseline: empty server key");
        return Vec::new();
    }
    let mut store = BaselineStore::load_default();
    let mut findings = Vec::new();
    for tool in tools {
        let schema = tool
            .input_schema
            .as_ref()
            .map(std::string::ToString::to_string)
            .unwrap_or_default();
        let fp = fingerprint_fields(&[
            ("name", &tool.name),
            ("description", tool.description.as_deref().unwrap_or("")),
            ("input_schema", &schema),
        ]);
        let key = format!("{server_key}\u{1f}{}", tool.name);
        if store.check("tool", &key, &fp) == Drift::Changed {
            findings.push(drift_finding(
                "MCPToolChanged",
                "tool",
                &tool.name,
                "Tool definition (description/schema) differs from the baseline recorded when this server was first scanned — post-approval swap / rug-pull pattern.",
                format!("Tool '{}' on '{server_key}' changed since last baseline", tool.name),
            ));
        }
    }
    store.save();
    findings
}

/// Pin a skill file's content; emit `SkillContentChanged` when the file
/// differs from the baseline recorded when it was first scanned.
/// Takes the store by reference so a scan over many skills does one
/// load/save cycle, not one per file.
pub fn check_skill_drift(
    store: &mut BaselineStore,
    path: &str,
    content: &str,
) -> Option<YaraScanResult> {
    let fp = fingerprint_fields(&[("content", content)]);
    let drift = store.check("skill", path, &fp);
    if drift == Drift::Changed {
        Some(drift_finding(
            "SkillContentChanged",
            "prompt",
            path,
            "Skill file content differs from the baseline recorded when it was first scanned — a reviewed skill was modified afterwards (hot-reload abuse / malicious update pattern).",
            format!("Skill file '{path}' changed since last baseline"),
        ))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> BaselineStore {
        let dir =
            std::env::temp_dir().join(format!("ramparts-baseline-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        BaselineStore::load_from(dir.join("content-baseline.json"))
    }

    #[test]
    fn first_sight_baselines_then_detects_change() {
        let mut store = temp_store();
        assert_eq!(store.check("tool", "srv\u{1f}read_file", "aaa"), Drift::New);
        assert_eq!(
            store.check("tool", "srv\u{1f}read_file", "aaa"),
            Drift::Unchanged
        );
        assert_eq!(
            store.check("tool", "srv\u{1f}read_file", "bbb"),
            Drift::Changed
        );
        // change is NOT absorbed: still flagged on the next scan
        assert_eq!(
            store.check("tool", "srv\u{1f}read_file", "bbb"),
            Drift::Changed
        );
    }

    #[test]
    fn store_roundtrips_through_disk() {
        let mut store = temp_store();
        let path = store.path.clone();
        store.check("skill", "/a/SKILL.md", "abc");
        store.save();
        let mut reloaded = BaselineStore::load_from(path);
        assert_eq!(
            reloaded.check("skill", "/a/SKILL.md", "abc"),
            Drift::Unchanged
        );
        assert_eq!(
            reloaded.check("skill", "/a/SKILL.md", "xyz"),
            Drift::Changed
        );
    }

    #[test]
    fn fingerprint_fields_are_length_prefixed() {
        assert_ne!(
            fingerprint_fields(&[("name", "ab"), ("url", "c")]),
            fingerprint_fields(&[("name", "a"), ("url", "bc")])
        );
    }
}
