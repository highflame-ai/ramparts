//! OWASP MCP Top 10 taxonomy mapping.
//!
//! Tags ramparts findings with their OWASP MCP Top 10 category so consumers
//! (terminal output, JSON, SARIF, the markdown report) can group and
//! prioritize findings against a recognized framework.
//!
//! The taxonomy itself lives in `taxonomies/owasp-mcp-top-10/<version>.yaml`.
//! Mappings from finding identifiers to taxonomy IDs are intentionally kept
//! in code (rather than per-rule YAML metadata) for now so we have one file
//! to audit when the OWASP list is refreshed. See ramparts#101.
//!
//! When the OWASP MCP Top 10 publishes a stable revision, add a new YAML
//! file with the new version key and update the constants below; we never
//! mutate published mappings in place so existing tagged findings remain
//! interpretable.

use crate::security::SecurityIssueType;
use serde::{Deserialize, Serialize};

/// The current taxonomy version Ramparts emits. Bumped explicitly when we
/// adopt a new OWASP MCP Top 10 revision so consumers can treat the change
/// as a deliberate upgrade.
pub const CURRENT_TAXONOMY_VERSION: &str = "2025-draft";

/// A reference to a single OWASP MCP Top 10 entry. Designed to be cheap to
/// clone and friendly to serde so it can be embedded directly in finding
/// types and propagate into JSON / SARIF / markdown outputs without any
/// extra plumbing. We use `String` rather than `&'static str` so the type
/// implements `Deserialize` (consumers may round-trip our JSON output back
/// through serde); the strings are short and the per-finding clone cost is
/// negligible relative to the rest of a scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwaspTag {
    pub id: String,
    pub version: String,
}

impl OwaspTag {
    pub fn new(id: &'static str) -> Self {
        Self {
            id: id.to_string(),
            version: CURRENT_TAXONOMY_VERSION.to_string(),
        }
    }
}

/// Map an LLM-detected `SecurityIssueType` to the OWASP MCP Top 10 entries
/// it belongs to. A single issue can map to multiple categories; e.g.
/// `SecretsLeakage` is both credential leakage (MCP06) and a sensitive-data
/// exposure (MCP09).
pub fn tags_for_security_issue(issue: SecurityIssueType) -> Vec<OwaspTag> {
    use SecurityIssueType::*;
    match issue {
        ToolPoisoning => vec![OwaspTag::new("MCP02"), OwaspTag::new("MCP03")],
        SQLInjection | CommandInjection => vec![OwaspTag::new("MCP07")],
        PathTraversal => vec![OwaspTag::new("MCP04")],
        AuthBypass => vec![OwaspTag::new("MCP08")],
        PromptInjection => vec![OwaspTag::new("MCP01")],
        Jailbreak => vec![OwaspTag::new("MCP01"), OwaspTag::new("MCP03")],
        PIILeakage => vec![OwaspTag::new("MCP09")],
        SecretsLeakage => vec![OwaspTag::new("MCP06"), OwaspTag::new("MCP09")],
    }
}

/// Map a YARA rule name (the value returned by yara-x's `Rule::identifier`)
/// to OWASP MCP Top 10 entries. Rule names not listed here are returned as
/// an empty Vec rather than an error — better to have a finding without
/// taxonomy tags than to drop the finding because we forgot to map a new
/// rule. Untagged findings are also useful telemetry: they tell us which
/// rules need taxonomy entries added.
pub fn tags_for_yara_rule(rule_name: &str) -> Vec<OwaspTag> {
    match rule_name {
        // secrets_leakage.yar
        "SecretsLeakage" | "EnvironmentVariableLeakage" => {
            vec![OwaspTag::new("MCP06"), OwaspTag::new("MCP09")]
        }
        "SSHKeyExposure" | "PEMFileAccess" => vec![OwaspTag::new("MCP06")],

        // command_injection.yar
        "CommandInjection" => vec![OwaspTag::new("MCP07")],

        // sql_injection.yar
        "SQLInjection" => vec![OwaspTag::new("MCP07")],

        // path_traversal.yar
        "PathTraversalVulnerability" => vec![OwaspTag::new("MCP04")],

        // mcp_config_risk.yar
        "MCPConfigRisk" => vec![OwaspTag::new("MCP10"), OwaspTag::new("MCP07")],

        // Synthetic rule emitted by the baseline-diff check when a previously
        // approved server's command/args/env fingerprint changes.
        "MCPConfigChanged" => vec![OwaspTag::new("MCP02")],

        // Emitted by the OSV.dev integration when a stdio MCP server's
        // npx/uvx package release has known security advisories. Pure
        // supply-chain finding.
        "VulnerableDependency" => vec![OwaspTag::new("MCP10")],

        // cross_origin_escalation.yar + the in-process cross-origin scanner
        "CrossOriginEscalation"
        | "CrossDomainContamination"
        | "DomainOutlier"
        | "MixedSecuritySchemes" => vec![OwaspTag::new("MCP05")],

        // skill_prompt_injection.yar — four rules covering classic
        // instruction-override signatures, invisible-unicode hiding,
        // mandatory-execution coercion, and indirect prompt injection
        // via untrusted external content.
        "PromptInjectionSignature" | "UnicodeSteganography" | "IndirectPromptInjection" => {
            vec![OwaspTag::new("MCP01")]
        }
        "CoerciveInjection" => vec![OwaspTag::new("MCP01"), OwaspTag::new("MCP02")],

        // skill_authority.yar — autonomy bypass + capability inflation.
        "AutonomyAbuse" => vec![OwaspTag::new("MCP03")],
        "CapabilityInflation" => vec![OwaspTag::new("MCP02"), OwaspTag::new("MCP03")],

        // skill_credential_harvesting.yar — vendor token formats, PEM
        // private-key blocks, active credential-theft verbs.
        "SkillCredentialHarvesting" => {
            vec![OwaspTag::new("MCP06"), OwaspTag::new("MCP09")]
        }

        // skill_tool_chaining_abuse.yar — credential read + network
        // egress to known exfil destinations, attacker-named hosts.
        "SkillToolChainingExfiltration" => {
            vec![OwaspTag::new("MCP06"), OwaspTag::new("MCP09")]
        }

        // skill_system_manipulation.yar — destructive ops, privilege
        // escalation, PATH hijack, critical-file writes.
        "SkillSystemManipulation" => {
            vec![OwaspTag::new("MCP03"), OwaspTag::new("MCP04")]
        }

        // cryptominers.yar — embedded mining payloads. The skill/tool is
        // doing something other than what it claims (tool poisoning).
        "CryptoStratumProtocol"
        | "CryptoMiningPools"
        | "CryptoMinerSoftware"
        | "CryptoCoinjacking" => vec![OwaspTag::new("MCP02")],

        // malware.yar — classic malware behavior embedded in skill/tool
        // content (ported from NVIDIA SkillSpector / signature-base).
        "ReverseShell" | "C2FrameworkIndicators" => {
            vec![OwaspTag::new("MCP02"), OwaspTag::new("MCP07")]
        }
        "BackdoorPersistence" | "RansomwareBehavior" => {
            vec![OwaspTag::new("MCP02"), OwaspTag::new("MCP03")]
        }
        "KeyloggerIndicators" => vec![OwaspTag::new("MCP02"), OwaspTag::new("MCP09")],
        "InfoStealer" => vec![OwaspTag::new("MCP06"), OwaspTag::new("MCP09")],

        // webshells.yar — remote command-execution backdoors.
        "PHPWebshellGeneric"
        | "PHPWebshellObfuscated"
        | "PHPWebshellKnown"
        | "PythonWebshell"
        | "JSPWebshell"
        | "ASPXWebshell" => {
            vec![OwaspTag::new("MCP02"), OwaspTag::new("MCP07")]
        }

        // hacktools.yar — offensive tooling, recon, and exploit
        // frameworks a legitimate skill should not invoke.
        "OffensiveToolReferences" | "NetworkReconnaissance" | "ExploitFramework" => {
            vec![OwaspTag::new("MCP02")]
        }
        "PrivilegeEscalationTools" => vec![OwaspTag::new("MCP02"), OwaspTag::new("MCP03")],
        "PhishingKit" => vec![OwaspTag::new("MCP02"), OwaspTag::new("MCP06")],

        // Synthetic findings emitted by the skill parser (src/skills.rs)
        // for structural risks the YARA passes can't see (frontmatter
        // grants, missing triggers, network-egress tool grants).
        "OverbroadAllowedTools" => vec![OwaspTag::new("MCP03")],
        "VagueSkillTrigger" => vec![OwaspTag::new("MCP02"), OwaspTag::new("MCP03")],
        "GenericSkillTrigger" => vec![OwaspTag::new("MCP02"), OwaspTag::new("MCP03")],
        "DataExfiltrationGrant" => vec![OwaspTag::new("MCP06"), OwaspTag::new("MCP09")],
        "SkillSensitiveFileReference" => vec![OwaspTag::new("MCP06"), OwaspTag::new("MCP09")],
        "SkillNameCollision" => vec![OwaspTag::new("MCP02"), OwaspTag::new("MCP03")],
        "SkillEmbeddedPayload" => vec![OwaspTag::new("MCP01"), OwaspTag::new("MCP10")],

        // agentskills.io spec-validation findings — all map to MCP02
        // (supply chain / hidden behavior). A bundle whose name doesn't
        // match its directory, has an invalid name, or has unknown
        // frontmatter fields is a candidate for deceptive shipping or
        // unintended-behavior surprise.
        "AgentskillsNameMismatch"
        | "AgentskillsInvalidName"
        | "AgentskillsMissingName"
        | "AgentskillsUnknownFrontmatterField" => vec![OwaspTag::new("MCP02")],

        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_security_issue_type_has_at_least_one_tag() {
        use SecurityIssueType::*;
        let all = [
            ToolPoisoning,
            SQLInjection,
            CommandInjection,
            PathTraversal,
            AuthBypass,
            PromptInjection,
            Jailbreak,
            PIILeakage,
            SecretsLeakage,
        ];
        for issue in all {
            assert!(
                !tags_for_security_issue(issue).is_empty(),
                "SecurityIssueType::{issue:?} has no OWASP tags — every \
                 detection class should map to at least one Top 10 entry"
            );
        }
    }

    #[test]
    fn known_yara_rules_have_tags() {
        for name in [
            "SecretsLeakage",
            "EnvironmentVariableLeakage",
            "SSHKeyExposure",
            "PEMFileAccess",
            "CommandInjection",
            "SQLInjection",
            "PathTraversalVulnerability",
            "MCPConfigRisk",
            "CrossOriginEscalation",
            "CrossDomainContamination",
            "DomainOutlier",
            "MixedSecuritySchemes",
            "PromptInjectionSignature",
            "UnicodeSteganography",
            "CoerciveInjection",
            "IndirectPromptInjection",
            "AutonomyAbuse",
            "CapabilityInflation",
            "SkillCredentialHarvesting",
            "SkillToolChainingExfiltration",
            "SkillSystemManipulation",
            // cryptominers.yar
            "CryptoStratumProtocol",
            "CryptoMiningPools",
            "CryptoMinerSoftware",
            "CryptoCoinjacking",
            // malware.yar
            "ReverseShell",
            "BackdoorPersistence",
            "KeyloggerIndicators",
            "RansomwareBehavior",
            "C2FrameworkIndicators",
            "InfoStealer",
            // webshells.yar
            "PHPWebshellGeneric",
            "PHPWebshellObfuscated",
            "PHPWebshellKnown",
            "PythonWebshell",
            "JSPWebshell",
            "ASPXWebshell",
            // hacktools.yar
            "OffensiveToolReferences",
            "NetworkReconnaissance",
            "PrivilegeEscalationTools",
            "ExploitFramework",
            "PhishingKit",
        ] {
            assert!(
                !tags_for_yara_rule(name).is_empty(),
                "YARA rule {name} should be tagged"
            );
        }
    }

    #[test]
    fn unknown_yara_rule_returns_empty_not_panic() {
        assert!(tags_for_yara_rule("totally-made-up-rule").is_empty());
    }
}
