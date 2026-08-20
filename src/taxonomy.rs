//! OWASP taxonomy mapping (MCP Top 10 + Agentic Skills Top 10).
//!
//! Tags ramparts findings with their OWASP category so consumers (terminal
//! output, JSON, SARIF, the markdown report) can group and prioritize
//! findings against a recognized framework. Two frameworks are emitted:
//!
//! - **OWASP MCP Top 10** (`MCP01`–`MCP10`) — attached to every finding,
//!   on both the MCP-server and skill surfaces.
//! - **OWASP Agentic Skills Top 10** (`AST01`–`AST10`) — attached only to
//!   findings produced on the *skill* scan surface, because AST is a
//!   skill-specific framework and MCP-server findings would be spurious
//!   under it. The skill scan path calls `ast_tags_for_*` and appends the
//!   result to each finding's `owasp_tags`.
//!
//! The taxonomies live in `taxonomies/owasp-mcp-top-10/<version>.yaml` and
//! `taxonomies/owasp-agentic-skills-top-10/<version>.yaml`. Mappings from
//! finding identifiers to taxonomy IDs are intentionally kept in code
//! (rather than per-rule YAML metadata) for now so we have one file to
//! audit when either OWASP list is refreshed. See ramparts#101.
//!
//! When a list publishes a stable revision, add a new YAML file with the
//! new version key and update the constants below; we never mutate
//! published mappings in place so existing tagged findings remain
//! interpretable.

use crate::security::SecurityIssueType;
use serde::{Deserialize, Serialize};

/// The current OWASP MCP Top 10 version Ramparts emits. Bumped explicitly
/// when we adopt a new revision so consumers can treat the change as a
/// deliberate upgrade.
pub const CURRENT_TAXONOMY_VERSION: &str = "2025-draft";

/// The current OWASP Agentic Skills Top 10 version (published Aug 2026).
pub const CURRENT_AST_VERSION: &str = "2026";

/// Framework identifier for OWASP MCP Top 10 tags.
pub const FRAMEWORK_MCP: &str = "owasp-mcp-top-10";

/// Framework identifier for OWASP Agentic Skills Top 10 tags.
pub const FRAMEWORK_AST: &str = "owasp-agentic-skills-top-10";

fn default_framework() -> String {
    FRAMEWORK_MCP.to_string()
}

/// A reference to a single OWASP taxonomy entry (MCP or AST). Designed to
/// be cheap to clone and friendly to serde so it can be embedded directly
/// in finding types and propagate into JSON / SARIF / markdown outputs
/// without any extra plumbing. We use `String` rather than `&'static str`
/// so the type implements `Deserialize` (consumers may round-trip our JSON
/// output back through serde); the strings are short and the per-finding
/// clone cost is negligible relative to the rest of a scan.
///
/// `framework` distinguishes MCP from AST tags. It carries a serde default
/// so JSON emitted before AST tagging existed (MCP-only, no `framework`
/// field) still deserializes on the replay path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwaspTag {
    #[serde(default = "default_framework")]
    pub framework: String,
    pub id: String,
    pub version: String,
}

impl OwaspTag {
    /// An OWASP MCP Top 10 tag (`MCP01`–`MCP10`).
    pub fn new(id: &'static str) -> Self {
        Self {
            framework: FRAMEWORK_MCP.to_string(),
            id: id.to_string(),
            version: CURRENT_TAXONOMY_VERSION.to_string(),
        }
    }

    /// An OWASP Agentic Skills Top 10 tag (`AST01`–`AST10`).
    pub fn ast(id: &'static str) -> Self {
        Self {
            framework: FRAMEWORK_AST.to_string(),
            id: id.to_string(),
            version: CURRENT_AST_VERSION.to_string(),
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
        "MCPToolChanged" => vec![OwaspTag::new("MCP02"), OwaspTag::new("MCP10")],
        "SkillContentChanged" => vec![OwaspTag::new("MCP10")],
        "AgentIdentityFileWrite" => vec![OwaspTag::new("MCP03"), OwaspTag::new("MCP09")],
        "ExternalReferenceInventory" => vec![OwaspTag::new("MCP10")],
        "UndeclaredNetworkEgress" => vec![OwaspTag::new("MCP02"), OwaspTag::new("MCP09")],
        // ScanCoverageIncomplete is a scanner-integrity meta-finding, not an
        // OWASP MCP category — deliberately untagged.

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

        // Instruction to move data offsite while hiding it from the user.
        // MCP01 is tool poisoning; MCP08 is the exfiltration half.
        "CovertExfiltration" => vec![OwaspTag::new("MCP01"), OwaspTag::new("MCP08")],

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

        // Insecure-metadata attacks: unsafe deserialization, brand
        // impersonation, JSON prototype pollution.
        "UnsafeYamlDeserialization" => vec![OwaspTag::new("MCP01"), OwaspTag::new("MCP10")],
        "BrandImpersonation" => vec![OwaspTag::new("MCP02")],
        "JsonPrototypePollution" => vec![OwaspTag::new("MCP10")],

        _ => Vec::new(),
    }
}

/// Map a rule/finding name to OWASP **Agentic Skills Top 10** entries.
/// Applied only on the skill scan surface (see module docs). Returns an
/// empty Vec for rules with no AST correspondent — including the generic
/// appsec rules (`CommandInjection`, `SQLInjection`, …), which in a skill
/// body are the AST01 "code layer" but are left to the LLM-issue mapping
/// so a rule that also fires on MCP tools isn't retagged by name alone.
///
/// AST references follow the OWASP Agentic Skills Top 10 (Aug 2026):
/// AST01 Malicious Skills, AST02 Supply Chain, AST03 Over-Privileged,
/// AST04 Insecure Metadata, AST05 Untrusted External Instructions,
/// AST06 Weak Isolation, AST07 Update Drift, AST08 Poor Scanning.
pub fn ast_tags_for_rule(rule_name: &str) -> Vec<OwaspTag> {
    match rule_name {
        // AST01 — Malicious Skills: hidden instructions, concealed
        // exfiltration, embedded payloads, malware IOCs in skill content.
        "PromptInjectionSignature"
        | "UnicodeSteganography"
        | "CoerciveInjection"
        | "CovertExfiltration"
        | "SkillEmbeddedPayload"
        | "SkillCredentialHarvesting"
        | "SkillToolChainingExfiltration"
        | "SkillSystemManipulation"
        | "ReverseShell"
        | "C2FrameworkIndicators"
        | "BackdoorPersistence"
        | "RansomwareBehavior"
        | "KeyloggerIndicators"
        | "InfoStealer"
        | "PHPWebshellGeneric"
        | "PHPWebshellObfuscated"
        | "PHPWebshellKnown"
        | "PythonWebshell"
        | "JSPWebshell"
        | "ASPXWebshell"
        | "OffensiveToolReferences"
        | "NetworkReconnaissance"
        | "ExploitFramework"
        | "PhishingKit"
        | "CryptoStratumProtocol"
        | "CryptoMiningPools"
        | "CryptoMinerSoftware"
        | "CryptoCoinjacking" => vec![OwaspTag::ast("AST01")],

        // AST02 — Supply Chain: vulnerable bundled deps, and manifest that
        // understates network capability (a supply-chain hiding vector).
        "VulnerableDependency" => vec![OwaspTag::ast("AST02")],
        "UndeclaredNetworkEgress" => vec![OwaspTag::ast("AST02"), OwaspTag::ast("AST04")],

        // AST03 — Over-Privileged Skills: broad grants, identity/memory
        // writes, autonomy bypass, privileged-tool references.
        "OverbroadAllowedTools" | "AutonomyAbuse" => vec![OwaspTag::ast("AST03")],
        "DataExfiltrationGrant" | "SkillSensitiveFileReference" => {
            vec![OwaspTag::ast("AST03")]
        }
        "AgentIdentityFileWrite" => vec![OwaspTag::ast("AST01"), OwaspTag::ast("AST03")],
        "PrivilegeEscalationTools" => vec![OwaspTag::ast("AST01"), OwaspTag::ast("AST03")],

        // AST04 — Insecure Metadata: deceptive/invalid manifests,
        // discovery manipulation, trigger hijacking.
        "AgentskillsNameMismatch"
        | "AgentskillsInvalidName"
        | "AgentskillsMissingName"
        | "AgentskillsUnknownFrontmatterField"
        | "CapabilityInflation"
        | "VagueSkillTrigger"
        | "GenericSkillTrigger"
        | "UnsafeYamlDeserialization"
        | "BrandImpersonation"
        | "JsonPrototypePollution" => vec![OwaspTag::ast("AST04")],

        // AST05 — Untrusted External Instructions: delegating to fetched
        // content, and the inventory of external sources a skill trusts.
        "IndirectPromptInjection" | "ExternalReferenceInventory" => {
            vec![OwaspTag::ast("AST05")]
        }

        // AST06 — Weak Isolation: one skill shadowing another in the router.
        "SkillNameCollision" => vec![OwaspTag::ast("AST06")],

        // AST07 — Update Drift: a reviewed skill edited after approval.
        "SkillContentChanged" => vec![OwaspTag::ast("AST07")],

        // AST08 — Poor Scanning: incomplete-coverage meta-finding.
        "ScanCoverageIncomplete" => vec![OwaspTag::ast("AST08")],

        _ => Vec::new(),
    }
}

/// Map an LLM-detected `SecurityIssueType` to OWASP Agentic Skills Top 10
/// entries, for findings on the skill surface. Direct injection / poisoning
/// in a skill body is a malicious skill (AST01); injection via untrusted
/// input is AST05.
pub fn ast_tags_for_security_issue(issue: SecurityIssueType) -> Vec<OwaspTag> {
    use SecurityIssueType::*;
    match issue {
        ToolPoisoning | Jailbreak | SQLInjection | CommandInjection | PathTraversal
        | SecretsLeakage | PIILeakage => vec![OwaspTag::ast("AST01")],
        PromptInjection => vec![OwaspTag::ast("AST01"), OwaspTag::ast("AST05")],
        AuthBypass => vec![OwaspTag::ast("AST03")],
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

    #[test]
    fn ast_tags_use_the_ast_framework_and_version() {
        for tag in ast_tags_for_rule("SkillContentChanged") {
            assert_eq!(tag.framework, FRAMEWORK_AST);
            assert_eq!(tag.version, CURRENT_AST_VERSION);
            assert!(tag.id.starts_with("AST"));
        }
    }

    #[test]
    fn mcp_tags_use_the_mcp_framework() {
        let tag = &tags_for_yara_rule("SkillContentChanged")[0];
        assert_eq!(tag.framework, FRAMEWORK_MCP);
        assert!(tag.id.starts_with("MCP"));
    }

    #[test]
    fn skill_surface_rules_carry_ast_tags() {
        // Representative rule per AST category we map.
        for (rule, expected) in [
            ("UnicodeSteganography", "AST01"),
            ("VulnerableDependency", "AST02"),
            ("OverbroadAllowedTools", "AST03"),
            ("AgentskillsNameMismatch", "AST04"),
            ("IndirectPromptInjection", "AST05"),
            ("SkillNameCollision", "AST06"),
            ("SkillContentChanged", "AST07"),
            ("ScanCoverageIncomplete", "AST08"),
        ] {
            let ids: Vec<String> = ast_tags_for_rule(rule).into_iter().map(|t| t.id).collect();
            assert!(
                ids.iter().any(|id| id == expected),
                "rule {rule} should carry {expected}; got {ids:?}"
            );
        }
    }

    #[test]
    fn every_security_issue_type_has_an_ast_tag() {
        use SecurityIssueType::*;
        for issue in [
            ToolPoisoning,
            SQLInjection,
            CommandInjection,
            PathTraversal,
            AuthBypass,
            PromptInjection,
            Jailbreak,
            PIILeakage,
            SecretsLeakage,
        ] {
            assert!(
                !ast_tags_for_security_issue(issue).is_empty(),
                "SecurityIssueType::{issue:?} has no AST tag"
            );
        }
    }

    #[test]
    fn generic_appsec_rules_are_not_ast_tagged_by_name() {
        // These fire on both MCP tools and skills; name-based AST tagging
        // would wrongly tag MCP-tool findings, so they stay empty here and
        // are covered via the LLM-issue mapping on the skill surface.
        for rule in [
            "CommandInjection",
            "SQLInjection",
            "PathTraversalVulnerability",
        ] {
            assert!(
                ast_tags_for_rule(rule).is_empty(),
                "{rule} should not be AST-tagged by rule name"
            );
        }
    }
}
