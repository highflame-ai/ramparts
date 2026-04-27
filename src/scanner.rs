use crate::config::{self, MCPConfig, MCPConfigManager, MCPServerConfig, ScannerConfig};
use crate::constants::{messages, protocol};
use crate::mcp_client::McpClient;
use crate::security::{
    cross_origin_scanner::CrossOriginScanner, BatchScannableItem, SecurityScanResult,
    SecurityScanner,
};
use crate::types::{
    LlmPrompt, MCPPrompt, MCPResource, MCPServerInfo, MCPTool, ScanOptions, ScanResult, ScanStatus,
    YaraScanResult,
};
use crate::utils::{error_utils, performance::track_performance, Timer};
use anyhow::{anyhow, Result};
use reqwest::Client;
use std::collections::HashMap;
use std::path::Path;
use tokio::time::{timeout, Duration};
use tracing::{debug, warn};

#[cfg(feature = "yara-x-scanning")]
use yara_x::Rules;

#[cfg(feature = "yara-x-scanning")]
type YaraRules = Rules;

#[cfg(not(feature = "yara-x-scanning"))]
type YaraRules = ();

/// Map rule names to their file names for consistent naming
fn rule_name_to_file_name(rule_name: &str) -> Option<String> {
    match rule_name {
        // secrets_leakage.yar rules
        "SecretsLeakage" | "SSHKeyExposure" | "PEMFileAccess" | "EnvironmentVariableLeakage" => {
            Some("secrets_leakage".to_string())
        }
        // cross_origin_escalation.yar rules
        "CrossOriginEscalation"
        | "CrossDomainContamination"
        | "DomainOutlier"
        | "MixedSecuritySchemes" => Some("cross_origin_escalation".to_string()),
        // Add more mappings as needed
        _ => None,
    }
}

/// Generate descriptive context messages based on rule names
fn generate_context_message(item_type: &str, rule_name: &str) -> String {
    match rule_name {
        // Secrets leakage rules
        "SecretsLeakage" => format!("Potential secret exposure detected in {item_type}"),
        "SSHKeyExposure" => format!("SSH key or configuration file access detected in {item_type}"),
        "PEMFileAccess" => format!("PEM certificate or private key access detected in {item_type}"),
        "EnvironmentVariableLeakage" => {
            format!("Sensitive environment variable pattern detected in {item_type}")
        }

        // Cross-origin rules
        "CrossOriginEscalation" => {
            format!("Cross-origin escalation vulnerability detected in {item_type}")
        }
        "CrossDomainContamination" => {
            format!("Cross-domain contamination detected across multiple domains in {item_type}")
        }
        "DomainOutlier" => {
            format!("Domain outlier detected - {item_type} uses different domain than majority")
        }
        "MixedSecuritySchemes" => format!("Mixed HTTP/HTTPS schemes detected in {item_type}"),

        // Command injection rules
        "CommandInjection" => format!("Command injection vulnerability detected in {item_type}"),

        // Default fallback
        _ => format!("{item_type} matched by security rule {rule_name}"),
    }
}

/// Check if YARA is available and enabled
fn is_yara_available(config_enabled: bool) -> bool {
    if !config_enabled {
        return false;
    }

    #[cfg(feature = "yara-x-scanning")]
    {
        true
    }

    #[cfg(not(feature = "yara-x-scanning"))]
    {
        false
    }
}

/// Print friendly message about YARA installation
fn print_yara_install_message() {
    println!("📋 YARA-X Scanning Disabled");
    println!();
    println!("YARA-X rule scanning is enabled in your config but YARA-X is not available.");
    println!("To enable YARA-X scanning, please:");
    println!();
    println!("1. Reinstall ramparts with YARA-X support:");
    println!("   cargo install ramparts --force");
    println!();
    println!("2. Or disable YARA-X in your config.yaml:");
    println!("   scanner:");
    println!("     enable_yara: false");
    println!();
    println!("Continuing without YARA-X scanning...");
    println!();
}

// ============================================================================
// TRANSPORT LAYER - Support for multiple MCP transport mechanisms
// ============================================================================

// ============================================================================
// SCAN CAPABILITIES - Middleware-like system for extensible scanning
// ============================================================================

// =====================
// CAPABILITY TRAIT & CHAIN (Composable Middleware)
// =====================

/// Represents the phase in which a scan capability is executed.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ScanPhase {
    /// Pre-scan phase: runs before the main security scan.
    PreScan,
    /// Post-scan phase: runs after the main security scan.
    PostScan,
}

/// Trait for a composable scan capability (middleware hook).
///
/// Implement this trait to add custom security, analysis, or filtering logic
/// to the scan pipeline. Scanners can be registered for the pre-scan phase.
pub trait Scanner: Send + Sync {
    /// Returns the name of the capability.
    fn name(&self) -> &'static str;
    /// Returns the phase in which this capability should run.
    fn phase(&self) -> ScanPhase;
    /// Runs the capability, modifying scan data or reporting issues as needed.
    fn run(&self, _scan_data: &mut ScanData) -> anyhow::Result<()>;
    /// Clones the scanner as a boxed trait object.
    fn box_clone(&self) -> Box<dyn Scanner>;
}

/// Chain of scanners (middleware hooks) for pre-scan processing.
///
/// Scanners are executed in the order they are added.
#[derive(Default)]
pub struct ScannerChain {
    pre_scan: Vec<Box<dyn Scanner>>,
    post_scan: Vec<Box<dyn Scanner>>,
}

impl ScannerChain {
    /// Creates a new, empty scanner chain.
    pub fn new() -> Self {
        Self {
            pre_scan: Vec::new(),
            post_scan: Vec::new(),
        }
    }
    /// Adds a scanner to the chain for its specified phase.
    pub fn add(&mut self, scanner: Box<dyn Scanner>) {
        match scanner.phase() {
            ScanPhase::PreScan => self.pre_scan.push(scanner),
            ScanPhase::PostScan => self.post_scan.push(scanner),
        }
    }
    /// Runs all pre-scan scanners on the provided scan data.
    pub fn run_pre_scan(&self, scan_data: &mut ScanData) {
        for scanner in &self.pre_scan {
            if let Err(e) = scanner.run(scan_data) {
                tracing::warn!("Pre-scan scanner '{}' failed: {}", scanner.name(), e);
            }
        }
    }

    /// Runs all post-scan scanners on the provided scan data.
    pub fn run_post_scan(&self, scan_data: &mut ScanData) {
        for scanner in &self.post_scan {
            if let Err(e) = scanner.run(scan_data) {
                tracing::warn!("Post-scan scanner '{}' failed: {}", scanner.name(), e);
            }
        }
    }
}

// Implement Clone for ScannerChain (requires dyn-clone for trait objects)
impl Clone for ScannerChain {
    fn clone(&self) -> Self {
        Self {
            pre_scan: self.pre_scan.iter().map(|c| c.box_clone()).collect(),
            post_scan: self.post_scan.iter().map(|c| c.box_clone()).collect(),
        }
    }
}

// =====================
// THREAT RULES ENGINE (Replaces hardcoded YaraScanner)
// =====================

#[cfg(feature = "yara-x-scanning")]
use glob::glob;
use std::sync::Arc;

/// Enhanced YARA match with rule metadata
#[cfg(feature = "yara-x-scanning")]
pub struct YaraMatchInfo {
    pub rule_name: String,
    pub metadata: Option<crate::types::YaraRuleMetadata>,
}

/// Enhanced YARA match with rule metadata (non-YARA fallback)
#[cfg(not(feature = "yara-x-scanning"))]
pub struct YaraMatchInfo {
    pub rule_name: String,
    pub metadata: Option<crate::types::YaraRuleMetadata>,
}

/// Threat detection rules engine that loads YARA-X rules from directory structure
pub struct ThreatRules {
    pre_scan_rules: Vec<Arc<YaraRules>>,
    post_scan_rules: Vec<Arc<YaraRules>>,
    rules_dir: String,
    rule_metadata: HashMap<String, RuleMetadata>,
    memory_usage_bytes: usize,
    last_load_time: std::time::Instant,
}

/// Metadata for YARA rules
#[derive(Debug, Clone)]
pub struct RuleMetadata {
    pub name: String,
}

impl ThreatRules {
    /// Creates a new threat rules engine with rules from the specified directory
    pub fn new(rules_dir: &str) -> Result<Self> {
        Self::with_config(rules_dir, true)
    }

    /// Creates a new threat rules engine with optional YARA support based on config
    pub fn with_config(rules_dir: &str, enable_yara: bool) -> Result<Self> {
        if !is_yara_available(enable_yara) {
            if enable_yara {
                print_yara_install_message();
            }
            // Return a scanner that will skip YARA operations
            return Ok(Self::new_disabled(rules_dir));
        }

        Self::new_enabled(rules_dir)
    }

    /// Creates a disabled threat rules engine (no rule loading)
    fn new_disabled(rules_dir: &str) -> Self {
        let start_time = std::time::Instant::now();
        Self {
            pre_scan_rules: Vec::new(),
            post_scan_rules: Vec::new(),
            rules_dir: rules_dir.to_string(),
            rule_metadata: HashMap::new(),
            memory_usage_bytes: 0,
            last_load_time: start_time,
        }
    }

    /// Creates an enabled threat rules engine (loads rules)
    #[cfg(feature = "yara-x-scanning")]
    fn new_enabled(rules_dir: &str) -> Result<Self> {
        let start_time = std::time::Instant::now();
        let mut scanner = Self {
            pre_scan_rules: Vec::new(),
            post_scan_rules: Vec::new(),
            rules_dir: rules_dir.to_string(),
            rule_metadata: HashMap::new(),
            memory_usage_bytes: 0,
            last_load_time: start_time,
        };

        scanner.load_rules()?;
        scanner.last_load_time = start_time;
        Ok(scanner)
    }

    /// Fallback for when YARA feature is not available
    #[cfg(not(feature = "yara-x-scanning"))]
    fn new_enabled(_rules_dir: &str) -> Result<Self> {
        Err(anyhow!("YARA-X scanning feature is not available"))
    }

    /// Loads all rules from the directory structure
    #[cfg(feature = "yara-x-scanning")]
    fn load_rules(&mut self) -> Result<()> {
        let start_time = std::time::Instant::now();

        // Load pre-scan rules
        let pre_dir = format!("{}/pre", self.rules_dir);
        if Path::new(&pre_dir).exists() {
            self.pre_scan_rules = self.load_rules_from_directory(&pre_dir, "pre")?;
        }

        // Load post-scan rules
        let post_dir = format!("{}/post", self.rules_dir);
        if Path::new(&post_dir).exists() {
            self.post_scan_rules = self.load_rules_from_directory(&post_dir, "post")?;
        }

        // Calculate memory usage
        self.calculate_memory_usage();

        let load_duration = start_time.elapsed();
        debug!(
            "Loaded {} pre-scan rules, {} post-scan rules in {}ms (memory: {}KB)",
            self.pre_scan_rules.len(),
            self.post_scan_rules.len(),
            load_duration.as_millis(),
            self.memory_usage_bytes / 1024
        );
        Ok(())
    }

    /// Calculates estimated memory usage of loaded rules
    #[cfg(feature = "yara-x-scanning")]
    fn calculate_memory_usage(&mut self) {
        // Estimate memory usage based on rule count and metadata
        let rule_memory = (self.pre_scan_rules.len() + self.post_scan_rules.len()) * 1024; // ~1KB per rule
        let metadata_memory = self.rule_metadata.len() * 256; // ~256 bytes per metadata entry

        self.memory_usage_bytes = rule_memory + metadata_memory;
    }

    /// Gets memory usage statistics
    #[cfg(test)]
    pub fn memory_stats(&self) -> RuleStats {
        RuleStats {
            pre_scan_count: self.pre_scan_rules.len(),
            post_scan_count: self.post_scan_rules.len(),
            pre_scan_rules: Vec::new(), // Empty for memory stats - not needed for this use case
            post_scan_rules: Vec::new(), // Empty for memory stats - not needed for this use case
        }
    }

    /// Loads all .yar files from a directory and their metadata
    #[cfg(feature = "yara-x-scanning")]
    fn load_rules_from_directory(
        &mut self,
        dir_path: &str,
        phase: &str,
    ) -> Result<Vec<Arc<YaraRules>>> {
        let mut rules = Vec::new();
        let pattern = format!("{dir_path}/*.yar");

        for entry in glob(&pattern).map_err(|e| anyhow!("Glob error: {}", e))? {
            match entry {
                Ok(path) => {
                    // Safely convert path to string, skipping files with non-UTF8 characters
                    if let Some(path_str) = path.to_str() {
                        // Read the rule file content
                        let rule_content = std::fs::read_to_string(path_str)
                            .map_err(|e| anyhow!("Failed to read rule file {}: {}", path_str, e))?;

                        // Compile the rule using YARA-X compiler
                        let mut compiler = yara_x::Compiler::new();
                        if let Err(e) = compiler.add_source(rule_content.as_str()) {
                            warn!("Failed to add rule source from {}: {}", path_str, e);
                            continue;
                        }

                        let rule = compiler.build();
                        let rule_name = path
                            .file_stem()
                            .and_then(|s| s.to_str())
                            .unwrap_or("unknown")
                            .to_string();

                        debug!("Loaded YARA-X rule: {} (phase: {})", path.display(), phase);

                        // Create metadata for the rule
                        let metadata = RuleMetadata {
                            name: rule_name.clone(),
                        };
                        let metadata_key = format!("{phase}:{rule_name}");
                        self.rule_metadata.insert(metadata_key, metadata);

                        rules.push(Arc::new(rule));
                    } else {
                        warn!(
                            "Skipping rule file with non-UTF8 characters: {}",
                            path.display()
                        );
                    }
                }
                Err(e) => warn!("Failed to read rule file: {}", e),
            }
        }

        Ok(rules)
    }

    /// Extract metadata from a YARA-X rule match
    #[cfg(feature = "yara-x-scanning")]
    fn extract_rule_metadata(rule_match: &yara_x::Rule) -> Option<crate::types::YaraRuleMetadata> {
        let metadata_iter = rule_match.metadata();
        let metadata_vec: Vec<(&str, yara_x::MetaValue)> = metadata_iter.collect();

        if metadata_vec.is_empty() {
            return None;
        }

        let mut rule_metadata = crate::types::YaraRuleMetadata {
            name: None,
            author: None,
            date: None,
            version: None,
            description: None,
            severity: None,
            category: None,
            confidence: None,
            tags: Vec::new(),
        };

        // Helper function to convert MetaValue to String
        let meta_value_to_string = |value: &yara_x::MetaValue| -> String {
            match value {
                yara_x::MetaValue::Integer(i) => i.to_string(),
                yara_x::MetaValue::Float(f) => f.to_string(),
                yara_x::MetaValue::Bool(b) => b.to_string(),
                yara_x::MetaValue::String(s) => (*s).to_string(),
                yara_x::MetaValue::Bytes(b) => String::from_utf8_lossy(b).to_string(),
            }
        };

        // Extract metadata fields
        for (key, value) in &metadata_vec {
            match *key {
                "name" => rule_metadata.name = Some(meta_value_to_string(value)),
                "author" => rule_metadata.author = Some(meta_value_to_string(value)),
                "date" => rule_metadata.date = Some(meta_value_to_string(value)),
                "version" => rule_metadata.version = Some(meta_value_to_string(value)),
                "description" => rule_metadata.description = Some(meta_value_to_string(value)),
                "severity" => rule_metadata.severity = Some(meta_value_to_string(value)),
                "category" => rule_metadata.category = Some(meta_value_to_string(value)),
                "confidence" => rule_metadata.confidence = Some(meta_value_to_string(value)),
                "tags" => {
                    // Handle tags as comma-separated string or array
                    let tags_str = meta_value_to_string(value);
                    rule_metadata.tags =
                        tags_str.split(',').map(|s| s.trim().to_string()).collect();
                }
                _ => {} // Ignore unknown metadata fields
            }
        }

        Some(rule_metadata)
    }

    /// Consolidated method to scan text with rules and return enhanced match information
    #[cfg(feature = "yara-x-scanning")]
    fn scan_with_rules_enhanced_internal(
        text: &str,
        context: &str,
        rules: &[Arc<YaraRules>],
        phase: &str,
    ) -> Vec<YaraMatchInfo> {
        let mut all_matches = Vec::new();

        for (i, rule_set) in rules.iter().enumerate() {
            let mut scanner = yara_x::Scanner::new(rule_set);
            match scanner.scan(text.as_bytes()) {
                Ok(scan_results) => {
                    for m in scan_results.matching_rules() {
                        all_matches.push(YaraMatchInfo {
                            rule_name: m.identifier().to_string(),
                            metadata: Self::extract_rule_metadata(&m),
                        });
                    }
                }
                Err(e) => warn!("Failed to scan with {}-rule {}: {}", phase, i, e),
            }
        }

        if !all_matches.is_empty() {
            debug!(
                "{}-scan matches in {}: {} rules triggered",
                phase,
                context,
                all_matches.len()
            );
        }

        all_matches
    }

    /// Scans text with pre-scan rules and returns enhanced match information
    #[cfg(feature = "yara-x-scanning")]
    pub fn pre_scan(&self, text: &str, context: &str) -> Vec<YaraMatchInfo> {
        Self::scan_with_rules_enhanced_internal(text, context, &self.pre_scan_rules, "pre")
    }

    /// Scans text with post-scan rules and returns enhanced match information
    #[cfg(feature = "yara-x-scanning")]
    pub fn post_scan(&self, text: &str, context: &str) -> Vec<YaraMatchInfo> {
        Self::scan_with_rules_enhanced_internal(text, context, &self.post_scan_rules, "post")
    }

    /// Gets statistics about loaded rules
    pub fn stats(&self) -> RuleStats {
        let mut pre_scan_rules = Vec::new();
        let mut post_scan_rules = Vec::new();

        // Collect rule names for pre-scan rules
        for (key, metadata) in &self.rule_metadata {
            if key.starts_with("pre:") {
                pre_scan_rules.push(metadata.name.clone());
            }
        }

        // Collect rule names for post-scan rules
        for (key, metadata) in &self.rule_metadata {
            if key.starts_with("post:") {
                post_scan_rules.push(metadata.name.clone());
            }
        }

        RuleStats {
            pre_scan_count: self.pre_scan_rules.len(),
            post_scan_count: self.post_scan_rules.len(),
            pre_scan_rules,
            post_scan_rules,
        }
    }

    /// Validates that all loaded rules are valid
    #[cfg(all(test, feature = "yara-x-scanning"))]
    pub fn validate(&self) -> Result<Vec<String>> {
        let mut issues = Vec::new();

        // Check pre-scan rules
        for (i, rules) in self.pre_scan_rules.iter().enumerate() {
            let mut scanner = yara_x::Scanner::new(rules);
            if let Err(e) = scanner.scan(b"test") {
                issues.push(format!("Pre-scan rule {i}: {e}"));
            }
        }

        // Check post-scan rules
        for (i, rules) in self.post_scan_rules.iter().enumerate() {
            let mut scanner = yara_x::Scanner::new(rules);
            if let Err(e) = scanner.scan(b"test") {
                issues.push(format!("Post-scan rule {i}: {e}"));
            }
        }

        if issues.is_empty() {
            Ok(issues)
        } else {
            Err(anyhow!("Rule validation failed: {}", issues.join(", ")))
        }
    }

    /// Fallback validation for when YARA feature is not available  
    #[cfg(all(test, not(feature = "yara-x-scanning")))]
    pub fn validate(&self) -> Result<Vec<String>> {
        Ok(Vec::new()) // Always pass validation when YARA is disabled
    }
}

/// Statistics about loaded YARA rules
#[derive(Debug)]
pub struct RuleStats {
    pub pre_scan_count: usize,
    pub post_scan_count: usize,
    pub pre_scan_rules: Vec<String>,
    pub post_scan_rules: Vec<String>,
}

impl Clone for ThreatRules {
    fn clone(&self) -> Self {
        // Clone that shares the same rules via Arc - efficient and safe
        Self {
            pre_scan_rules: self.pre_scan_rules.clone(), // Arc<Rules> can be cloned efficiently
            post_scan_rules: self.post_scan_rules.clone(),
            rules_dir: self.rules_dir.clone(),
            rule_metadata: self.rule_metadata.clone(),
            memory_usage_bytes: self.memory_usage_bytes,
            last_load_time: self.last_load_time,
        }
    }
}

/// Threat detection capability that loads rules from directory structure
pub struct YaraScanner {
    scanner: ThreatRules,
    phase: ScanPhase,
}

impl YaraScanner {
    /// Creates a new dynamic YARA capability
    pub fn new(rules_dir: &str, phase: ScanPhase) -> Result<Self> {
        let scanner = ThreatRules::new(rules_dir)?;
        Ok(Self { scanner, phase })
    }

    /// Generic YARA scanning method for any item type that implements `BatchScannableItem`
    fn scan_items_with_yara<T>(&self, items: &[T], phase: ScanPhase) -> Vec<YaraScanResult>
    where
        T: crate::security::BatchScannableItem,
    {
        let mut results = Vec::new();

        for item in items {
            let item_text = Self::format_item_for_yara_scan(item);
            let context = format!("{} '{}'", T::item_type(), item.name());

            // Use enhanced scanning methods that return metadata
            #[cfg(feature = "yara-x-scanning")]
            let enhanced_matches = match phase {
                ScanPhase::PreScan => self.scanner.pre_scan(&item_text, &context),
                ScanPhase::PostScan => self.scanner.post_scan(&item_text, &context),
            };

            #[cfg(not(feature = "yara-x-scanning"))]
            let enhanced_matches: Vec<YaraMatchInfo> = Vec::new();

            if !enhanced_matches.is_empty() {
                warn!(
                    "Security issue detected in {} '{}': {} rules matched",
                    T::item_type(),
                    item.name(),
                    enhanced_matches.len()
                );

                // Store YARA results for each match with metadata
                for match_info in enhanced_matches {
                    let yara_result =
                        Self::create_yara_result_with_metadata::<T>(item, &match_info);
                    results.push(yara_result);
                }
            }
        }
        results
    }

    /// Format an item for YARA scanning with specialized logic per type
    fn format_item_for_yara_scan<T>(item: &T) -> String
    where
        T: crate::security::BatchScannableItem,
    {
        // For YARA scanning, we want a simple format without numbering
        // to avoid confusion and focus on the actual content
        format!("{}: {}", T::item_type().to_uppercase(), item.name())
    }

    /// Create a YARA scan result with original rule metadata
    fn create_yara_result_with_metadata<T>(item: &T, match_info: &YaraMatchInfo) -> YaraScanResult
    where
        T: crate::security::BatchScannableItem,
    {
        YaraScanResult {
            target_type: T::item_type().to_string(),
            target_name: item.name().to_string(),
            rule_name: match_info.rule_name.clone(),
            rule_file: rule_name_to_file_name(&match_info.rule_name),
            matched_text: None,
            context: generate_context_message(T::item_type(), &match_info.rule_name),
            rule_metadata: match_info.metadata.clone(),
            phase: None,
            rules_executed: None,
            security_issues_detected: None,
            total_items_scanned: None,
            total_matches: None,
            status: Some("warning".to_string()),
        }
    }
}

impl Scanner for YaraScanner {
    fn name(&self) -> &'static str {
        "yara"
    }

    fn phase(&self) -> ScanPhase {
        self.phase
    }

    #[allow(clippy::too_many_lines)]
    fn run(&self, scan_data: &mut ScanData) -> anyhow::Result<()> {
        match self.phase {
            ScanPhase::PreScan => {
                let stats = self.scanner.stats();
                debug!("Running pre-scan with {} rules", stats.pre_scan_count);

                // Scan all item types using the generic scanner
                let tool_results = self.scan_items_with_yara(&scan_data.tools, ScanPhase::PreScan);
                let prompt_results =
                    self.scan_items_with_yara(&scan_data.prompts, ScanPhase::PreScan);
                let resource_results =
                    self.scan_items_with_yara(&scan_data.resources, ScanPhase::PreScan);

                // Count total matches found
                let total_matches =
                    tool_results.len() + prompt_results.len() + resource_results.len();
                let total_items =
                    scan_data.tools.len() + scan_data.prompts.len() + scan_data.resources.len();

                // Collect triggered rule names from all results and map them to file names for consistency
                let mut triggered_file_names = std::collections::HashSet::new();
                let mut triggered_rules = std::collections::HashSet::new();

                for result in &tool_results {
                    triggered_rules.insert(result.rule_name.clone());
                    // Map YARA rule name back to file name for consistent comparison
                    if let Some(file_name) = rule_name_to_file_name(&result.rule_name) {
                        triggered_file_names.insert(file_name);
                    } else {
                        // Fallback: use the rule name itself if no mapping found
                        triggered_file_names.insert(result.rule_name.clone());
                    }
                }
                for result in &prompt_results {
                    triggered_rules.insert(result.rule_name.clone());
                    if let Some(file_name) = rule_name_to_file_name(&result.rule_name) {
                        triggered_file_names.insert(file_name);
                    } else {
                        triggered_file_names.insert(result.rule_name.clone());
                    }
                }
                for result in &resource_results {
                    triggered_rules.insert(result.rule_name.clone());
                    if let Some(file_name) = rule_name_to_file_name(&result.rule_name) {
                        triggered_file_names.insert(file_name);
                    } else {
                        triggered_file_names.insert(result.rule_name.clone());
                    }
                }

                // Add all results to scan data
                scan_data.yara_results.extend(tool_results);
                scan_data.yara_results.extend(prompt_results);
                scan_data.yara_results.extend(resource_results);

                // Add a summary result
                let summary_result = YaraScanResult {
                    target_type: "summary".to_string(),
                    target_name: "pre-scan".to_string(),
                    rule_name: "YARA_PRE_SCAN_SUMMARY".to_string(),
                    rule_file: None,
                    matched_text: None,
                    context: format!(
                        "Pre-scan completed: {} rules executed on {} items",
                        stats.pre_scan_count, total_items
                    ),
                    rule_metadata: None,
                    phase: Some("pre-scan".to_string()),
                    rules_executed: if stats.pre_scan_rules.is_empty() {
                        None
                    } else {
                        Some(
                            stats
                                .pre_scan_rules
                                .iter()
                                .map(|f| format!("{f}:*"))
                                .collect(),
                        )
                    },
                    security_issues_detected: if total_matches > 0 {
                        // Show actual rules that triggered matches with filename:rulename format
                        let triggered_vec: Vec<String> = triggered_rules
                            .into_iter()
                            .map(|rule_name| {
                                // Get the file name for this rule
                                if let Some(file_name) = rule_name_to_file_name(&rule_name) {
                                    format!("{file_name}:{rule_name}")
                                } else {
                                    rule_name
                                }
                            })
                            .collect();
                        debug!("Pre-scan triggered rules: {:?}", triggered_vec);
                        Some(triggered_vec)
                    } else {
                        None
                    },
                    total_items_scanned: Some(total_items),
                    total_matches: Some(total_matches),
                    status: Some(if total_matches == 0 {
                        "passed".to_string()
                    } else {
                        "warning".to_string()
                    }),
                };
                scan_data.yara_results.push(summary_result);
            }
            ScanPhase::PostScan => {
                let stats = self.scanner.stats();
                debug!("Running post-scan with {} rules", stats.post_scan_count);

                // Scan all item types using the generic scanner
                let tool_results = self.scan_items_with_yara(&scan_data.tools, ScanPhase::PostScan);
                let prompt_results =
                    self.scan_items_with_yara(&scan_data.prompts, ScanPhase::PostScan);
                let resource_results =
                    self.scan_items_with_yara(&scan_data.resources, ScanPhase::PostScan);

                // Count total matches found
                let total_matches =
                    tool_results.len() + prompt_results.len() + resource_results.len();
                let total_items =
                    scan_data.tools.len() + scan_data.prompts.len() + scan_data.resources.len();

                // Collect triggered rule names from all results and map them to file names for consistency
                let mut triggered_file_names = std::collections::HashSet::new();
                let mut triggered_rules = std::collections::HashSet::new();

                for result in &tool_results {
                    triggered_rules.insert(result.rule_name.clone());
                    if let Some(file_name) = rule_name_to_file_name(&result.rule_name) {
                        triggered_file_names.insert(file_name);
                    } else {
                        triggered_file_names.insert(result.rule_name.clone());
                    }
                }
                for result in &prompt_results {
                    triggered_rules.insert(result.rule_name.clone());
                    if let Some(file_name) = rule_name_to_file_name(&result.rule_name) {
                        triggered_file_names.insert(file_name);
                    } else {
                        triggered_file_names.insert(result.rule_name.clone());
                    }
                }
                for result in &resource_results {
                    triggered_rules.insert(result.rule_name.clone());
                    if let Some(file_name) = rule_name_to_file_name(&result.rule_name) {
                        triggered_file_names.insert(file_name);
                    } else {
                        triggered_file_names.insert(result.rule_name.clone());
                    }
                }

                // Add all results to scan data
                scan_data.yara_results.extend(tool_results);
                scan_data.yara_results.extend(prompt_results);
                scan_data.yara_results.extend(resource_results);

                // Add a summary result
                let summary_result = YaraScanResult {
                    target_type: "summary".to_string(),
                    target_name: "post-scan".to_string(),
                    rule_name: "YARA_POST_SCAN_SUMMARY".to_string(),
                    rule_file: None,
                    matched_text: None,
                    context: format!(
                        "Post-scan completed: {} rules executed on {} items",
                        stats.post_scan_count, total_items
                    ),
                    rule_metadata: None,
                    phase: Some("post-scan".to_string()),
                    rules_executed: if stats.post_scan_rules.is_empty() {
                        None
                    } else {
                        Some(
                            stats
                                .post_scan_rules
                                .iter()
                                .map(|f| format!("{f}:*"))
                                .collect(),
                        )
                    },
                    security_issues_detected: if total_matches > 0 {
                        // Show actual rules that triggered matches with filename:rulename format
                        let triggered_vec: Vec<String> = triggered_rules
                            .into_iter()
                            .map(|rule_name| {
                                // Get the file name for this rule
                                if let Some(file_name) = rule_name_to_file_name(&rule_name) {
                                    format!("{file_name}:{rule_name}")
                                } else {
                                    rule_name
                                }
                            })
                            .collect();
                        debug!("Post-scan triggered rules: {:?}", triggered_vec);
                        Some(triggered_vec)
                    } else {
                        None
                    },
                    total_items_scanned: Some(total_items),
                    total_matches: Some(total_matches),
                    status: Some(if total_matches == 0 {
                        "passed".to_string()
                    } else {
                        "warning".to_string()
                    }),
                };
                scan_data.yara_results.push(summary_result);
            }
        }

        Ok(())
    }

    fn box_clone(&self) -> Box<dyn Scanner> {
        Box::new(Self {
            scanner: self.scanner.clone(),
            phase: self.phase,
        })
    }
}

// MCPScanner struct
pub struct MCPScanner {
    client: Client,
    http_timeout: u64,
    middleware_chain: ScannerChain, // New: pre/post scan hooks
    mcp_client: McpClient,          // Official rmcp SDK client
}

// MCPScanner implementation
impl MCPScanner {
    /// Creates a new `MCPScanner` with the specified HTTP timeout.
    pub fn with_timeout(http_timeout: u64) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(http_timeout))
            .user_agent(protocol::USER_AGENT)
            .build()
            .map_err(|e| anyhow!("Failed to create HTTP client: {}", e))?;

        // Set up middleware chain with dynamic YARA capabilities
        let mut middleware_chain = ScannerChain::new();

        // Fixed rules directory
        let rules_dir = "rules".to_string();

        // Add dynamic YARA pre-scan capability
        if let Ok(pre_cap) = YaraScanner::new(&rules_dir, ScanPhase::PreScan) {
            middleware_chain.add(Box::new(pre_cap));
            debug!("{}", messages::YARA_PRE_SCAN_LOADED);
        } else {
            warn!("{}", messages::YARA_PRE_SCAN_FAILED);
        }

        // Add dynamic YARA post-scan capability
        if let Ok(post_cap) = YaraScanner::new(&rules_dir, ScanPhase::PostScan) {
            middleware_chain.add(Box::new(post_cap));
            debug!("{}", messages::YARA_POST_SCAN_LOADED);
        } else {
            warn!("{}", messages::YARA_POST_SCAN_FAILED);
        }

        // Add cross-origin escalation scanner (pre-scan)
        let cross_origin_scanner = CrossOriginScanner::new(ScanPhase::PreScan);
        middleware_chain.add(Box::new(cross_origin_scanner));
        debug!("Cross-origin scanner loaded");

        Ok(Self {
            client,
            http_timeout,
            middleware_chain,
            mcp_client: McpClient::with_http_timeout(http_timeout),
        })
    }

    /// Scan a single MCP server
    pub async fn scan_single(&self, url: &str, options: ScanOptions) -> Result<ScanResult> {
        let scan_timer = Timer::start();
        let mut result = ScanResult::new(url.to_string());

        debug!("Scanning {}", url);

        // STDIO URLs route through `scan_stdio_url` -> `scan_stdio_server`,
        // which sets `response_time_ms` itself. Don't overwrite it here.
        if url.starts_with("stdio:") {
            return self.scan_stdio_url(url, options).await;
        }

        // Normalize URL with error context for HTTP URLs
        let normalized_url = Self::normalize_url(url);
        result.url.clone_from(&normalized_url);

        // Perform the scan with performance tracking using rmcp SDK
        let scan_result = track_performance("MCP server scan", || async {
            let scan_future = self.perform_scan_with_rmcp(&normalized_url, &options);
            match timeout(Duration::from_secs(options.timeout), scan_future).await {
                Ok(result) => result,
                Err(_) => Err(anyhow!("Scan operation timed out")),
            }
        })
        .await;

        match scan_result {
            Ok(mut scan_data) => {
                // === PRE-SCAN HOOKS ===
                self.middleware_chain.run_pre_scan(&mut scan_data);

                result.status = ScanStatus::Success;
                result.server_info.clone_from(&scan_data.server_info);
                result.tools.clone_from(&scan_data.tools);
                result.resources.clone_from(&scan_data.resources);
                result.prompts.clone_from(&scan_data.prompts);
                result.yara_results.clone_from(&scan_data.yara_results);

                // Add fetch errors to the result
                result.errors.extend(scan_data.fetch_errors.clone());

                // Load scanner configuration
                let config_manager = crate::config::ScannerConfigManager::new();
                let scanner_config = match config_manager.load_config() {
                    Ok(config) => config,
                    Err(e) => {
                        warn!("Failed to load scanner config, using defaults: {}", e);
                        result.errors.push(format!("Config loading failed: {e}"));
                        ScannerConfig::default()
                    }
                };

                // If caller wants prompts back instead of LLM call, skip LLM and populate prompts
                if options.return_prompts {
                    let mut prompts: Vec<LlmPrompt> = Vec::new();
                    // Tools
                    if !scan_data.tools.is_empty() {
                        let batch_size = scanner_config.scanner.llm_batch_size as usize;
                        for (batch_index, chunk) in scan_data.tools.chunks(batch_size).enumerate() {
                            let tools_info = chunk
                                .iter()
                                .enumerate()
                                .map(|(i, tool)| tool.format_for_analysis(i))
                                .collect::<String>();
                            let prompt_text =
                                SecurityScanner::create_tools_analysis_prompt(&tools_info);
                            let item_names = chunk.iter().map(|t| t.name.clone()).collect();
                            let request_body = SecurityScanner::with_config(scanner_config.clone())
                                .build_llm_request_body(&prompt_text);
                            let endpoint =
                                SecurityScanner::with_config(scanner_config.clone()).get_endpoint();
                            prompts.push(LlmPrompt {
                                target_type: "tool".to_string(),
                                batch_index,
                                prompt: prompt_text,
                                request_body: Some(request_body),
                                endpoint,
                                item_names,
                            });
                        }
                    }
                    // Prompts
                    if !scan_data.prompts.is_empty() {
                        let batch_size = scanner_config.scanner.llm_batch_size as usize;
                        for (batch_index, chunk) in scan_data.prompts.chunks(batch_size).enumerate()
                        {
                            let prompts_info = chunk
                                .iter()
                                .enumerate()
                                .map(|(i, p)| p.format_for_analysis(i))
                                .collect::<String>();
                            let prompt_text =
                                SecurityScanner::create_prompts_analysis_prompt(&prompts_info);
                            let item_names = chunk.iter().map(|p| p.name.clone()).collect();
                            let request_body = SecurityScanner::with_config(scanner_config.clone())
                                .build_llm_request_body(&prompt_text);
                            let endpoint =
                                SecurityScanner::with_config(scanner_config.clone()).get_endpoint();
                            prompts.push(LlmPrompt {
                                target_type: "prompt".to_string(),
                                batch_index,
                                prompt: prompt_text,
                                request_body: Some(request_body),
                                endpoint,
                                item_names,
                            });
                        }
                    }
                    // Resources
                    if !scan_data.resources.is_empty() {
                        let batch_size = scanner_config.scanner.llm_batch_size as usize;
                        for (batch_index, chunk) in
                            scan_data.resources.chunks(batch_size).enumerate()
                        {
                            let resources_info = chunk
                                .iter()
                                .enumerate()
                                .map(|(i, r)| r.format_for_analysis(i))
                                .collect::<String>();
                            let prompt_text =
                                SecurityScanner::create_resources_analysis_prompt(&resources_info);
                            let item_names = chunk.iter().map(|r| r.name.clone()).collect();
                            let request_body = SecurityScanner::with_config(scanner_config.clone())
                                .build_llm_request_body(&prompt_text);
                            let endpoint =
                                SecurityScanner::with_config(scanner_config.clone()).get_endpoint();
                            prompts.push(LlmPrompt {
                                target_type: "resource".to_string(),
                                batch_index,
                                prompt: prompt_text,
                                request_body: Some(request_body),
                                endpoint,
                                item_names,
                            });
                        }
                    }
                    result.llm_prompts = Some(prompts);
                } else {
                    // Perform security scanning with configuration
                    let security_scanner = if scanner_config.security.enabled {
                        SecurityScanner::with_config(scanner_config)
                    } else {
                        SecurityScanner::default()
                    };
                    let mut security_result = SecurityScanResult::new();

                    // Always perform the security scan (no enhanced/standard distinction)
                    // Batch scan tools for security issues
                    match security_scanner
                        .scan_tools_batch(&scan_data.tools, options.detailed)
                        .await
                    {
                        Ok((tool_issues, analysis_details)) => {
                            security_result.add_tool_issues(tool_issues);
                            // Store the analysis details for each tool
                            for (tool_name, details) in analysis_details {
                                security_result.add_tool_analysis_details(tool_name, details);
                            }
                        }
                        Err(e) => warn!("Failed to batch scan tools for security issues: {}", e),
                    }

                    // Batch scan prompts for security issues
                    if !scan_data.prompts.is_empty() {
                        match security_scanner
                            .scan_prompts_batch(&scan_data.prompts, options.detailed)
                            .await
                        {
                            Ok(prompt_issues) => security_result.add_prompt_issues(prompt_issues),
                            Err(e) => {
                                warn!("Failed to batch scan prompts for security issues: {}", e)
                            }
                        }
                    }

                    // Batch scan resources for security issues
                    if !scan_data.resources.is_empty() {
                        match security_scanner
                            .scan_resources_batch(&scan_data.resources, options.detailed)
                            .await
                        {
                            Ok(resource_issues) => {
                                security_result.add_resource_issues(resource_issues)
                            }
                            Err(e) => {
                                warn!("Failed to batch scan resources for security issues: {}", e);
                            }
                        }
                    }

                    if !options.return_prompts {
                        result.security_issues = Some(security_result);
                    }

                    // === POST-SCAN HOOKS ===
                    self.middleware_chain.run_post_scan(&mut scan_data);

                    // Update result with any post-scan changes
                    result.yara_results.clone_from(&scan_data.yara_results);

                    debug!("Scan completed in {}ms", scan_timer.elapsed_ms());
                }
            }
            Err(e) => {
                result.status = ScanStatus::Failed(e.to_string());
                result.add_error(error_utils::format_error("Scan operation", &e.to_string()));
                warn!("Scan failed: [\x1b[1m{}\x1b[0m]", e);
            }
        }

        // Record total scan duration on both the success and failure paths so
        // failed scans no longer report `0ms`.
        result.response_time_ms = scan_timer.elapsed_ms();
        Ok(result)
    }

    /// Parse and scan a STDIO URL (format: stdio:command:arg1:arg2... or stdio://command:arg1:arg2...)
    async fn scan_stdio_url(&self, stdio_url: &str, options: ScanOptions) -> Result<ScanResult> {
        // Parse the STDIO URL format: stdio:command:arg1:arg2:... or stdio://command:arg1:arg2:...
        let parts: Vec<&str> = stdio_url.splitn(3, ':').collect();
        if parts.len() < 2 {
            return Err(anyhow!(
                "Invalid STDIO URL format. Expected: stdio:command or stdio:command:args"
            ));
        }

        // Handle both stdio:command and stdio://command formats
        let command = parts[1].trim_start_matches("//");
        let args: Vec<String> = if parts.len() > 2 && !parts[2].is_empty() {
            parts[2]
                .split(':')
                .map(std::string::ToString::to_string)
                .collect()
        } else {
            Vec::new()
        };

        // Create a temporary server config for the STDIO URL. Leaving `name`
        // unset is intentional: the synthetic `STDIO-<command>` placeholder
        // pollutes `to_display_url` output with a useless suffix. We restore
        // the original `stdio_url` on the result below so the user sees the
        // exact string they typed.
        let server_config = MCPServerConfig {
            name: None,
            url: None,
            command: Some(command.to_string()),
            args: Some(args),
            env: None,
            description: Some(format!("STDIO server from URL: {stdio_url}")),
            auth_headers: None,
            options: None,
        };

        let mut result = self.scan_stdio_server(&server_config, options).await?;
        result.url = stdio_url.to_string();
        Ok(result)
    }

    /// Scan a STDIO MCP server using subprocess transport
    async fn scan_stdio_server(
        &self,
        server_config: &MCPServerConfig,
        options: ScanOptions,
    ) -> Result<ScanResult> {
        let scan_timer = Timer::start();
        let command = server_config
            .command
            .as_ref()
            .ok_or_else(|| anyhow!("STDIO server missing command"))?;

        let args = server_config.args.as_deref().unwrap_or(&[]);
        let display_url = server_config.to_display_url();

        debug!("Scanning STDIO MCP server: {}", display_url);

        let mut result = ScanResult::new(display_url.clone());

        // Wrap the entire connect-and-scan pipeline in `options.timeout` so a
        // hung subprocess (no MCP handshake response, deadlocked tool, etc.)
        // can't make the CLI hang forever — same overall budget the HTTP path
        // gets in `scan_single`.
        let scan_result = track_performance("STDIO MCP server scan", || async {
            match timeout(Duration::from_secs(options.timeout), async {
                let session = self
                    .mcp_client
                    .connect_subprocess(command, args, server_config.env.as_ref())
                    .await
                    .map_err(|e| anyhow!("Failed to connect to STDIO server {}: {}", command, e))?;
                let scan_data = self.perform_scan_with_session(&session, &options).await?;
                Ok::<_, anyhow::Error>((session, scan_data))
            })
            .await
            {
                Ok(inner) => inner,
                Err(_) => Err(anyhow!(
                    "STDIO scan operation timed out after {}s",
                    options.timeout
                )),
            }
        })
        .await;

        match scan_result {
            Ok((session, mut scan_data)) => {
                // Apply the same middleware chain as HTTP scanning
                self.middleware_chain.run_pre_scan(&mut scan_data);

                // === SECURITY ANALYSIS ===
                // Load scanner configuration for security analysis
                #[allow(clippy::single_match_else)]
                let scanner_config = match config::ScannerConfigManager::new().load_config() {
                    Ok(config) => config,
                    Err(_) => {
                        debug!("Failed to load scanner config for STDIO security analysis, using defaults");
                        ScannerConfig::default()
                    }
                };

                // Perform security scanning with configuration - same as HTTP flow
                let security_scanner = if scanner_config.security.enabled {
                    SecurityScanner::with_config(scanner_config)
                } else {
                    SecurityScanner::default()
                };
                let mut security_result = SecurityScanResult::new();

                // Batch scan tools for security issues
                match security_scanner
                    .scan_tools_batch(&scan_data.tools, options.detailed)
                    .await
                {
                    Ok((tool_issues, analysis_details)) => {
                        security_result.add_tool_issues(tool_issues);
                        // Store the analysis details for each tool
                        for (tool_name, details) in analysis_details {
                            security_result.add_tool_analysis_details(tool_name, details);
                        }
                    }
                    Err(e) => warn!(
                        "Failed to batch scan STDIO tools for security issues: {}",
                        e
                    ),
                }

                // Batch scan prompts for security issues
                if !scan_data.prompts.is_empty() {
                    match security_scanner
                        .scan_prompts_batch(&scan_data.prompts, options.detailed)
                        .await
                    {
                        Ok(prompt_issues) => security_result.add_prompt_issues(prompt_issues),
                        Err(e) => warn!(
                            "Failed to batch scan STDIO prompts for security issues: {}",
                            e
                        ),
                    }
                }

                // Batch scan resources for security issues
                if !scan_data.resources.is_empty() {
                    match security_scanner
                        .scan_resources_batch(&scan_data.resources, options.detailed)
                        .await
                    {
                        Ok(resource_issues) => security_result.add_resource_issues(resource_issues),
                        Err(e) => {
                            warn!(
                                "Failed to batch scan STDIO resources for security issues: {}",
                                e
                            );
                        }
                    }
                }

                // === POST-SCAN HOOKS ===
                self.middleware_chain.run_post_scan(&mut scan_data);

                // Populate result with scan data
                result.status = ScanStatus::Success;
                result.server_info.clone_from(&session.server_info);
                result.tools = scan_data.tools;
                result.resources = scan_data.resources;
                result.prompts = scan_data.prompts;
                result.yara_results = scan_data.yara_results;
                result.security_issues = Some(security_result);

                debug!("Successfully scanned STDIO server: {}", display_url);
            }
            Err(e) => {
                result.status = ScanStatus::Failed(e.to_string());
                result.add_error(format!("STDIO scan failed: {e}"));
                warn!("STDIO scan failed for {}: {}", display_url, e);
            }
        }

        result.response_time_ms = scan_timer.elapsed_ms();
        Ok(result)
    }

    /// Scan MCP servers from IDE configuration files
    /// Scan configuration files grouped by IDE  
    pub async fn scan_config_by_ide(&self, options: ScanOptions) -> Result<Vec<ScanResult>> {
        let config_manager = MCPConfigManager::new();

        if !config_manager.has_config_files() {
            return Err(anyhow!("No MCP IDE configuration files found"));
        }

        let config = config_manager.load_config();

        // Debug: Show that we loaded MCP config
        println!(
            "🔍 Loaded MCP configuration with {} servers",
            config.servers.as_ref().map(|s| s.len()).unwrap_or(0)
        );

        // =============================================================
        // Pre-connection static analysis of MCP server definitions
        // - Scan command/args/env with YARA pre-scan rules (if enabled)
        // - Heuristic checks for risky STDIO patterns (always on)
        // - Baseline/diff detection for post-approval swaps
        // =============================================================
        use std::collections::HashMap as StdHashMap;
        let mut server_config_yara: StdHashMap<String, Vec<YaraScanResult>> = StdHashMap::new();

        // Build initial baseline map from disk (best-effort)
        fn get_baseline_path() -> std::path::PathBuf {
            dirs::home_dir()
                .map(|mut p| {
                    p.push(".ramparts");
                    p.push("mcp-baseline.json");
                    p
                })
                .unwrap_or_else(|| std::path::PathBuf::from(".ramparts/mcp-baseline.json"))
        }

        fn compute_server_fingerprint(server: &MCPServerConfig) -> String {
            use std::hash::{Hash, Hasher};
            let mut s = String::new();
            if let Some(name) = &server.name {
                s.push_str(name);
            }
            if let Some(url) = &server.url {
                s.push_str(url);
            }
            if let Some(cmd) = &server.command {
                s.push_str(cmd);
            }
            if let Some(args) = &server.args {
                s.push_str(&args.join(" "));
            }
            if let Some(env) = &server.env {
                let mut kv: Vec<_> = env.iter().collect();
                kv.sort_by(|a, b| a.0.cmp(b.0));
                for (k, v) in kv {
                    s.push_str(k);
                    s.push('=');
                    s.push_str(v);
                }
            }
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            s.hash(&mut hasher);
            format!("{:016x}", hasher.finish())
        }

        let baseline_path = get_baseline_path();
        let mut baseline_map: StdHashMap<String, String> = StdHashMap::new();
        if baseline_path.exists() {
            if let Ok(content) = std::fs::read_to_string(&baseline_path) {
                if let Ok(map) = serde_json::from_str::<StdHashMap<String, String>>(&content) {
                    baseline_map = map;
                }
            }
        }

        // Prepare YARA rules engine for config scanning (feature-gated)
        #[cfg(feature = "yara-x-scanning")]
        let pre_rules_engine = ThreatRules::new("rules").ok(); // compile once for config scan

        if let Some(ref servers) = config.servers {
            for server in servers {
                let key = server.dedup_key();

                // Heuristic removed in favor of YARA (below). Keep vector for potential YARA additions
                let mut prefindings: Vec<YaraScanResult> = Vec::new();

                // YARA pre-scan on server definition text (if YARA enabled)
                #[cfg(feature = "yara-x-scanning")]
                if let Some(engine) = &pre_rules_engine {
                    let mut text = String::new();
                    if let Some(name) = &server.name {
                        text.push_str(&format!("NAME: {name}\n"));
                    }
                    if let Some(url) = &server.url {
                        text.push_str(&format!("URL: {url}\n"));
                    }
                    if let Some(cmd) = &server.command {
                        text.push_str(&format!("COMMAND: {cmd}\n"));
                    }
                    if let Some(args) = &server.args {
                        text.push_str(&format!("ARGS: {}\n", args.join(" ")));
                    }
                    if let Some(env) = &server.env {
                        // Only include environment VALUES that look non-placeholder and non-trivial,
                        // to avoid false positives from variable NAMES alone
                        let mut kv: Vec<_> = env.iter().collect();
                        kv.sort_by(|a, b| a.0.cmp(b.0));
                        for (_k, v) in kv {
                            let val = v.trim();
                            if val.is_empty() {
                                continue;
                            }
                            // Skip common placeholder syntaxes and trivial booleans
                            let is_placeholder = val.starts_with("${")
                                || val.starts_with("$(")
                                || val.contains("{{")
                                || val.contains('<')
                                || val.eq_ignore_ascii_case("true")
                                || val.eq_ignore_ascii_case("false");
                            if is_placeholder || val.len() < 8 {
                                continue;
                            }
                            text.push_str(&format!("ENV_VALUE:{val} "));
                        }
                        text.push('\n');
                    }
                    if let Some(desc) = &server.description {
                        text.push_str(&format!("DESCRIPTION: {desc}\n"));
                    }
                    let context = format!(
                        "server '{}'",
                        server.name.as_deref().unwrap_or(&server.to_display_url())
                    );
                    let matches = engine.pre_scan(&text, &context);
                    for m in matches {
                        prefindings.push(YaraScanResult {
                            target_type: "server".to_string(),
                            target_name: server
                                .name
                                .clone()
                                .unwrap_or_else(|| server.to_display_url()),
                            rule_name: m.rule_name.clone(),
                            rule_file: rule_name_to_file_name(&m.rule_name),
                            matched_text: None,
                            context: generate_context_message("server", &m.rule_name),
                            rule_metadata: m.metadata.clone(),
                            phase: Some("pre-config".to_string()),
                            rules_executed: None,
                            security_issues_detected: None,
                            total_items_scanned: None,
                            total_matches: None,
                            status: Some("warning".to_string()),
                        });
                    }
                }

                // Baseline/diff check (best-effort)
                let fp = compute_server_fingerprint(server);
                match baseline_map.get(&key) {
                    Some(stored) if stored == &fp => { /* unchanged */ }
                    Some(_different) => {
                        prefindings.push(YaraScanResult {
                            target_type: "server".to_string(),
                            target_name: server
                                .name
                                .clone()
                                .unwrap_or_else(|| server.to_display_url()),
                            rule_name: "MCPConfigChanged".to_string(),
                            rule_file: None,
                            matched_text: None,
                            context: "MCP server configuration changed since last baseline"
                                .to_string(),
                            rule_metadata: Some(crate::types::YaraRuleMetadata {
                                name: Some("Baseline Change".to_string()),
                                author: Some("Ramparts".to_string()),
                                date: None,
                                version: None,
                                description: Some(
                                    "Server command/args/env fingerprint differs from baseline."
                                        .to_string(),
                                ),
                                severity: Some("HIGH".to_string()),
                                category: Some("supply-chain".to_string()),
                                confidence: Some("MEDIUM".to_string()),
                                tags: vec!["baseline".to_string()],
                            }),
                            phase: Some("pre-config".to_string()),
                            rules_executed: None,
                            security_issues_detected: None,
                            total_items_scanned: None,
                            total_matches: None,
                            status: Some("warning".to_string()),
                        });
                    }
                    None => {
                        // First-run: populate baseline directory/file if missing (best-effort)
                        if !baseline_path.exists() {
                            if let Some(parent) = baseline_path.parent() {
                                let _ = std::fs::create_dir_all(parent);
                            }
                        }
                        baseline_map.insert(key.clone(), fp.clone());
                        // Write baseline silently
                        if let Ok(serialized) = serde_json::to_string_pretty(&baseline_map) {
                            let _ = std::fs::write(&baseline_path, serialized);
                        }
                    }
                }

                if !prefindings.is_empty() {
                    server_config_yara.insert(key, prefindings);
                }
            }
        }

        let server_config_yara = std::sync::Arc::new(server_config_yara);

        let mut results = Vec::new();

        if let Some(ref servers) = config.servers {
            debug!(
                "Found [\x1b[1m{}\x1b[0m] MCP servers to scan",
                servers.len()
            );

            // Parallel scanning implementation using futures
            use futures::future::join_all;

            // Create scanning tasks for parallel execution
            let scan_tasks: Vec<_> = servers
                .iter()
                .map(|server| {
                    let server = server.clone();
                    let config = config.clone();
                    let options = options.clone();
                    // Clone the scanner (shares compiled YARA rules, creates new McpClient)
                    let scanner = self.clone();
                    // Clone shared pre-config findings map into the task
                    let cfg_yara = server_config_yara.clone();

                    tokio::spawn(async move {
                        debug!(
                            "Scanning MCP server: [\x1b[1m{}\x1b[0m] ({})",
                            server.name.as_deref().unwrap_or("unnamed"),
                            server.to_display_url()
                        );

                        // Extract IDE name from description if available
                        let ide_source = server
                            .description
                            .as_ref()
                            .and_then(|desc| {
                                // Look for [IDE:name] pattern in description
                                if let Some(start) = desc.rfind("[IDE:") {
                                    if let Some(end) = desc[start..].find(']') {
                                        let ide_name = &desc[start + 5..start + end];
                                        return Some(ide_name.to_string());
                                    }
                                }
                                None
                            })
                            .unwrap_or_else(|| "IDE Configs".to_string());

                        let server_options =
                            MCPScanner::build_server_options(&options, &config, &server);

                        // Small helper to attach pre-config findings
                        let attach_findings = |res: &mut ScanResult| {
                            if let Some(findings) = cfg_yara.get(&server.dedup_key()) {
                                res.yara_results.extend(findings.clone());
                            }
                        };

                        // Scan the MCP server - HTTP or STDIO
                        let result = if let Some(url) = server.scan_url() {
                            // HTTP server scanning
                            match scanner.scan_single(url, server_options).await {
                                Ok(mut result) => {
                                    result.ide_source = Some(ide_source);
                                    // Append pre-config YARA/heuristic/baseline findings if any
                                    attach_findings(&mut result);
                                    result
                                }
                                Err(e) => {
                                    let mut failed_result = ScanResult::new(url.to_string());
                                    failed_result.status = ScanStatus::Failed(e.to_string());
                                    failed_result.ide_source = Some(ide_source);
                                    attach_findings(&mut failed_result);
                                    failed_result
                                }
                            }
                        } else if server.command.is_some() {
                            // STDIO server scanning
                            match scanner.scan_stdio_server(&server, server_options).await {
                                Ok(mut result) => {
                                    result.ide_source = Some(ide_source);
                                    attach_findings(&mut result);
                                    result
                                }
                                Err(e) => {
                                    let mut failed_result =
                                        ScanResult::new(server.to_display_url());
                                    failed_result.status = ScanStatus::Failed(e.to_string());
                                    failed_result.ide_source = Some(ide_source);
                                    attach_findings(&mut failed_result);
                                    failed_result
                                }
                            }
                        } else {
                            // Invalid server configuration
                            let mut failed_result = ScanResult::new("unknown".to_string());
                            failed_result.status =
                                ScanStatus::Failed("Invalid server configuration".to_string());
                            failed_result.ide_source = Some(ide_source);
                            attach_findings(&mut failed_result);
                            failed_result
                        };

                        result
                    })
                })
                .collect();

            // Execute all scans in parallel and collect results
            println!(
                "🚀 Starting parallel scan of {} servers...",
                scan_tasks.len()
            );

            // Add timeout to prevent tasks from hanging indefinitely
            let scan_results = tokio::time::timeout(
                std::time::Duration::from_secs(300), // 5 minute timeout for all tasks
                join_all(scan_tasks),
            )
            .await
            .unwrap_or_else(|_| {
                warn!("Parallel scan tasks timed out after 5 minutes");
                vec![] // Return empty results if timeout
            });

            // Extract results from join handles
            for task_result in scan_results {
                match task_result {
                    Ok(scan_result) => results.push(scan_result),
                    Err(e) => {
                        // Task panicked or was cancelled
                        let mut failed_result = ScanResult::new("task_failed".to_string());
                        failed_result.status = ScanStatus::Failed(format!("Scan task failed: {e}"));
                        failed_result.ide_source = Some("IDE Configs".to_string());
                        results.push(failed_result);
                    }
                }
            }

            // Clean up the main scanner after all parallel tasks complete
            if let Err(e) = self.mcp_client.cleanup_all_sessions().await {
                warn!("Failed to clean up main scanner sessions after parallel scan: {e}");
            }
        }

        Ok(results)
    }

    fn build_server_options(
        options: &ScanOptions,
        config: &MCPConfig,
        server: &MCPServerConfig,
    ) -> ScanOptions {
        let mut server_options = options.clone();

        // Apply global options from config
        if let Some(global_options) = &config.options {
            if let Some(timeout) = global_options.timeout {
                server_options.timeout = timeout;
            }
            if let Some(http_timeout) = global_options.http_timeout {
                server_options.http_timeout = http_timeout;
            }
            if let Some(format) = &global_options.format {
                server_options.format.clone_from(format);
            }
            if let Some(detailed) = global_options.detailed {
                server_options.detailed = detailed;
            }
        }

        // Apply server-specific options
        if let Some(server_specific_options) = &server.options {
            if let Some(timeout) = server_specific_options.timeout {
                server_options.timeout = timeout;
            }
            if let Some(http_timeout) = server_specific_options.http_timeout {
                server_options.http_timeout = http_timeout;
            }
            if let Some(format) = &server_specific_options.format {
                server_options.format.clone_from(format);
            }
            if let Some(detailed) = server_specific_options.detailed {
                server_options.detailed = detailed;
            }
        }

        // Merge authentication headers
        server_options.auth_headers = Self::build_auth_headers(options, config, server);

        server_options
    }

    fn build_auth_headers(
        options: &ScanOptions,
        config: &MCPConfig,
        server: &MCPServerConfig,
    ) -> Option<HashMap<String, String>> {
        let mut auth_headers = options.auth_headers.clone();

        // Add global auth headers
        if let Some(global_auth_headers) = &config.auth_headers {
            match &mut auth_headers {
                Some(headers) => {
                    for (key, value) in global_auth_headers {
                        headers.insert(key.clone(), value.clone());
                    }
                }
                None => {
                    auth_headers = Some(global_auth_headers.clone());
                }
            }
        }

        // Add server-specific auth headers
        if let Some(server_auth_headers) = &server.auth_headers {
            match &mut auth_headers {
                Some(headers) => {
                    for (key, value) in server_auth_headers {
                        headers.insert(key.clone(), value.clone());
                    }
                }
                None => {
                    auth_headers = Some(server_auth_headers.clone());
                }
            }
        }

        auth_headers
    }

    /// Perform the scan
    /// New rmcp-based scan implementation that replaces all legacy transport code
    async fn perform_scan_with_rmcp(&self, url: &str, options: &ScanOptions) -> Result<ScanData> {
        let mut scan_data = ScanData::new();

        // Connect to MCP server using smart transport selection
        let session = self
            .mcp_client
            .connect_smart(url, options.auth_headers.clone())
            .await?;

        // After connection, some servers need a brief settling period.
        // Instead of a fixed sleep, use a short exponential backoff on the first request.
        async fn fetch_with_backoff<T, F, Fut>(mut op: F, label: &str) -> anyhow::Result<T>
        where
            F: FnMut() -> Fut,
            Fut: std::future::Future<Output = anyhow::Result<T>>,
        {
            use std::time::Duration;
            use tokio::time::sleep;

            let mut delay = Duration::from_millis(100);
            let max_delay = Duration::from_millis(1000);
            let max_attempts = 5;

            for attempt in 1..=max_attempts {
                match op().await {
                    Ok(v) => return Ok(v),
                    Err(e) => {
                        let msg = e.to_string();
                        // Retry on likely initialization/transient errors
                        let retryable = msg.contains("initialization")
                            || msg.contains("before initialization was complete")
                            || msg.contains("transport")
                            || msg.contains("Failed to create MCP service")
                            || msg.contains("connection")
                            || msg.contains("temporarily");

                        if retryable && attempt < max_attempts {
                            tracing::warn!(
                                "{} attempt {} failed: {}. Retrying in {}ms",
                                label,
                                attempt,
                                msg,
                                delay.as_millis()
                            );
                            sleep(delay).await;
                            delay = std::cmp::min(delay * 2, max_delay);
                            continue;
                        }
                        return Err(e);
                    }
                }
            }
            unreachable!("backoff loop should return on success or error");
        }

        debug!("Starting to fetch tools, resources, and prompts after rmcp connection");

        // Get server info from initialization
        if let Some(ref server_info) = session.server_info {
            scan_data.server_info = Some(server_info.clone());
        }

        // Fetch tools, resources, and prompts using rmcp SDK with proper error handling
        let mut fetch_errors = Vec::new();

        scan_data.tools =
            match fetch_with_backoff(|| self.mcp_client.list_tools(&session), "list_tools").await {
                Ok(tools) => {
                    debug!("Successfully fetched {} tools via rmcp", tools.len());
                    tools
                }
                Err(e) => {
                    let error_msg = format!("Failed to fetch tools via rmcp: {e}");
                    warn!("{}", error_msg);
                    fetch_errors.push(error_msg);
                    Vec::new()
                }
            };

        scan_data.resources = match self.mcp_client.list_resources(&session).await {
            Ok(resources) => {
                debug!(
                    "Successfully fetched {} resources via rmcp",
                    resources.len()
                );
                resources
            }
            Err(e) => {
                let error_msg = format!("Failed to fetch resources via rmcp: {e}");
                warn!("{}", error_msg);
                fetch_errors.push(error_msg);
                Vec::new()
            }
        };

        scan_data.prompts = match self.mcp_client.list_prompts(&session).await {
            Ok(prompts) => {
                debug!("Successfully fetched {} prompts via rmcp", prompts.len());
                prompts
            }
            Err(e) => {
                let error_msg = format!("Failed to fetch prompts via rmcp: {e}");
                warn!("{}", error_msg);
                fetch_errors.push(error_msg);
                Vec::new()
            }
        };

        // Store fetch errors in scan_data for later inclusion in final result
        scan_data.fetch_errors = fetch_errors;

        // Clean up the session to prevent session deletion errors
        if let Err(e) = self.mcp_client.cleanup_session(&session).await {
            warn!("Failed to clean up MCP session: {}", e);
        }

        Ok(scan_data)
    }

    /// Perform scan with an existing MCP session (for STDIO transport)
    async fn perform_scan_with_session(
        &self,
        session: &crate::types::MCPSession,
        _options: &ScanOptions,
    ) -> Result<ScanData> {
        let mut scan_data = ScanData::new();

        async fn fetch_with_backoff<T, F, Fut>(mut op: F, label: &str) -> anyhow::Result<T>
        where
            F: FnMut() -> Fut,
            Fut: std::future::Future<Output = anyhow::Result<T>>,
        {
            use std::time::Duration;
            use tokio::time::sleep;

            let mut delay = Duration::from_millis(100);
            let max_delay = Duration::from_millis(1000);
            let max_attempts = 5;

            for attempt in 1..=max_attempts {
                match op().await {
                    Ok(v) => return Ok(v),
                    Err(e) => {
                        let msg = e.to_string();
                        let retryable = msg.contains("initialization")
                            || msg.contains("before initialization was complete")
                            || msg.contains("transport")
                            || msg.contains("Failed to create MCP service")
                            || msg.contains("connection")
                            || msg.contains("temporarily");
                        if retryable && attempt < max_attempts {
                            tracing::warn!(
                                "{} attempt {} failed: {}. Retrying in {}ms",
                                label,
                                attempt,
                                msg,
                                delay.as_millis()
                            );
                            sleep(delay).await;
                            delay = std::cmp::min(delay * 2, max_delay);
                            continue;
                        }
                        return Err(e);
                    }
                }
            }
            unreachable!("backoff loop should return on success or error");
        }

        debug!("Starting to fetch tools, resources, and prompts from existing session");

        // Get server info from session
        if let Some(ref server_info) = session.server_info {
            scan_data.server_info = Some(server_info.clone());
        }

        // Fetch tools, resources, and prompts using existing session with proper error handling
        let mut fetch_errors = Vec::new();

        scan_data.tools =
            match fetch_with_backoff(|| self.mcp_client.list_tools(session), "list_tools").await {
                Ok(tools) => {
                    debug!("Successfully fetched {} tools from session", tools.len());
                    tools
                }
                Err(e) => {
                    let error_msg = format!("Failed to fetch tools from session: {e}");
                    warn!("{}", error_msg);
                    fetch_errors.push(error_msg);
                    Vec::new()
                }
            };

        scan_data.resources = match self.mcp_client.list_resources(session).await {
            Ok(resources) => {
                debug!(
                    "Successfully fetched {} resources from session",
                    resources.len()
                );
                resources
            }
            Err(e) => {
                let error_msg = format!("Failed to fetch resources from session: {e}");
                warn!("{}", error_msg);
                fetch_errors.push(error_msg);
                Vec::new()
            }
        };

        scan_data.prompts = match self.mcp_client.list_prompts(session).await {
            Ok(prompts) => {
                debug!(
                    "Successfully fetched {} prompts from session",
                    prompts.len()
                );
                prompts
            }
            Err(e) => {
                let error_msg = format!("Failed to fetch prompts from session: {e}");
                warn!("{}", error_msg);
                fetch_errors.push(error_msg);
                Vec::new()
            }
        };

        // Store fetch errors in scan_data for later inclusion in final result
        scan_data.fetch_errors = fetch_errors;

        // Clean up the session to prevent session deletion errors
        if let Err(e) = self.mcp_client.cleanup_session(session).await {
            warn!("Failed to clean up MCP session: {}", e);
        }

        Ok(scan_data)
    }

    /// Simple URL normalization for rmcp-based scanning
    fn normalize_url(url: &str) -> String {
        let mut normalized_url = url.to_string();

        // Add http:// if no scheme is provided
        if !normalized_url.contains("://") {
            normalized_url = format!("http://{normalized_url}");
        }

        normalized_url
    }

    /// Connect to an MCP server and return a session
    #[allow(dead_code)] // Future feature - will be used when scheduler is re-enabled
    pub async fn connect_to_server(
        &self,
        url: &str,
        auth_headers: Option<HashMap<String, String>>,
    ) -> Result<crate::types::MCPSession> {
        self.mcp_client.connect_smart(url, auth_headers).await
    }

    /// List tools from an MCP server session
    #[allow(dead_code)] // Future feature - will be used when scheduler is re-enabled
    pub async fn list_tools_from_session(
        &self,
        session: &crate::types::MCPSession,
    ) -> Result<Vec<crate::types::MCPTool>> {
        self.mcp_client.list_tools(session).await
    }
}

// Clone the MCPScanner
impl Clone for MCPScanner {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            http_timeout: self.http_timeout,
            middleware_chain: self.middleware_chain.clone(),
            mcp_client: self.mcp_client.clone(),
        }
    }
}

// Scan data
pub(crate) struct ScanData {
    pub server_info: Option<MCPServerInfo>,
    pub tools: Vec<MCPTool>,
    pub resources: Vec<MCPResource>,
    pub prompts: Vec<MCPPrompt>,
    pub yara_results: Vec<YaraScanResult>,
    pub fetch_errors: Vec<String>,
}

// Scan data implementation
impl ScanData {
    fn new() -> Self {
        Self {
            server_info: None,
            tools: Vec::new(),
            resources: Vec::new(),
            prompts: Vec::new(),
            yara_results: Vec::new(),
            fetch_errors: Vec::new(),
        }
    }
}

// Implement Drop for MCPScanner to ensure proper cleanup
impl Drop for MCPScanner {
    fn drop(&mut self) {
        // Disable automatic cleanup in Drop to prevent race conditions in parallel scanning
        // Cleanup is now handled explicitly in scan methods
        debug!("MCPScanner dropped");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creates_threat_rules_with_and_without_yara_x() {
        // Use disabled YARA when feature is not available
        #[cfg(feature = "yara-x-scanning")]
        let scanner = ThreatRules::new("rules");
        #[cfg(not(feature = "yara-x-scanning"))]
        let scanner = ThreatRules::with_config("rules", false);

        assert!(
            scanner.is_ok(),
            "ThreatRules creation should succeed even when YARA is disabled"
        );

        let scanner = scanner.expect("Scanner creation should have succeeded");
        let stats = scanner.stats();

        // Should have loaded rules from the pre directory (only when YARA is enabled)
        #[cfg(feature = "yara-x-scanning")]
        assert!(stats.pre_scan_count > 0);
        #[cfg(not(feature = "yara-x-scanning"))]
        assert_eq!(stats.pre_scan_count, 0);

        println!("Loaded {} pre-scan rules", stats.pre_scan_count);
    }

    #[test]
    fn test_creates_yara_capability_with_correct_phase() {
        let scanner = YaraScanner::new("rules", ScanPhase::PreScan);
        assert!(
            scanner.is_ok(),
            "YaraScanner creation should succeed with valid rules directory"
        );

        let scanner_instance = scanner.expect("Scanner creation should have succeeded");
        assert_eq!(scanner_instance.name(), "yara");
        assert_eq!(scanner_instance.phase(), ScanPhase::PreScan);
    }

    #[test]
    fn test_reports_memory_usage_statistics() {
        #[cfg(feature = "yara-x-scanning")]
        let scanner = ThreatRules::new("rules")
            .expect("Should be able to create ThreatRules with rules directory");
        #[cfg(not(feature = "yara-x-scanning"))]
        let scanner = ThreatRules::with_config("rules", false)
            .expect("Should be able to create ThreatRules with YARA disabled");

        let memory_stats = scanner.memory_stats();

        #[cfg(feature = "yara-x-scanning")]
        assert!(memory_stats.pre_scan_count + memory_stats.post_scan_count > 0);
        #[cfg(not(feature = "yara-x-scanning"))]
        assert_eq!(
            memory_stats.pre_scan_count + memory_stats.post_scan_count,
            0
        );

        println!("Memory stats: {memory_stats:?}");
    }

    #[test]
    fn test_shares_rules_efficiently_via_arc_cloning() {
        // Create first scanner
        let scanner1 = ThreatRules::new("rules").unwrap();
        let memory1 = scanner1.memory_stats();

        // Clone should work without deadlocks
        let scanner2 = scanner1.clone();
        let memory2 = scanner2.memory_stats();

        // Both scanners should have same rule counts
        assert_eq!(memory1.pre_scan_count, memory2.pre_scan_count);
        assert_eq!(memory1.post_scan_count, memory2.post_scan_count);

        // Memory counts should match between cloned scanners
        assert_eq!(
            memory1.pre_scan_count + memory1.post_scan_count,
            memory2.pre_scan_count + memory2.post_scan_count
        );

        println!("Cache test passed - cloned scanner has identical memory usage");
    }

    #[test]
    fn test_validates_loaded_rules_successfully() {
        let scanner = ThreatRules::new("rules")
            .expect("Should be able to create ThreatRules with rules directory");
        let validation_result = scanner.validate();

        // Should not have validation errors
        assert!(
            validation_result.is_ok(),
            "YARA rule validation should pass for well-formed rules"
        );
        println!("Rule validation passed");
    }

    #[test]
    #[cfg(feature = "yara-x-scanning")]
    fn test_compiles_and_scans_with_yara_x_rules() {
        // Test actual YARA-X rule compilation from .yar files
        let test_rule = r#"
            rule TestRule {
                meta:
                    name = "Test Rule"
                    description = "A test rule for YARA-X integration"
                    severity = "MEDIUM"
                strings:
                    $test_string = "MALICIOUS_PATTERN"
                    $api_key = /[Aa][Pp][Ii].*[Kk][Ee][Yy]/
                condition:
                    $test_string or $api_key
            }
        "#;

        // Test compilation
        let mut compiler = yara_x::Compiler::new();
        assert!(
            compiler.add_source(test_rule).is_ok(),
            "Rule compilation should succeed"
        );

        let rules = compiler.build();

        // Test scanning with matches
        let mut scanner = yara_x::Scanner::new(&rules);
        let result = scanner.scan(b"This contains MALICIOUS_PATTERN text");
        assert!(result.is_ok(), "Scanning should succeed");

        let scan_results = result.expect("YARA-X scan should have succeeded");
        let matching_rules: Vec<_> = scan_results.matching_rules().collect();
        assert!(
            !matching_rules.is_empty(),
            "Should have matches for test pattern"
        );

        // Test scanning without matches
        let mut scanner2 = yara_x::Scanner::new(&rules);
        let result2 = scanner2.scan(b"Clean text with no malicious content");
        assert!(result2.is_ok(), "Scanning clean text should succeed");

        let scan_results2 = result2.expect("YARA-X scan on clean text should have succeeded");
        let matching_rules2: Vec<_> = scan_results2.matching_rules().collect();
        assert!(
            matching_rules2.is_empty(),
            "Should have no matches for clean text"
        );
    }

    #[test]
    #[cfg(feature = "yara-x-scanning")]
    fn test_extracts_metadata_from_yara_x_matches() {
        // Test metadata extraction from YARA-X rules
        let test_rule = r#"
            rule MetadataTest {
                meta:
                    name = "Metadata Test Rule"
                    author = "Test Author"
                    version = "2.0"
                    severity = "HIGH"
                    confidence = 0.95
                    tags = "test,metadata"
                strings:
                    $test = "test_pattern"
                condition:
                    $test
            }
        "#;

        let mut compiler = yara_x::Compiler::new();
        compiler
            .add_source(test_rule)
            .expect("Test rule should compile successfully with YARA-X");

        let rules = compiler.build();
        let mut scanner = yara_x::Scanner::new(&rules);
        let result = scanner.scan(b"test_pattern");
        assert!(
            result.is_ok(),
            "YARA-X scanning should succeed on test pattern"
        );

        let scan_results = result.expect("YARA-X scan should have succeeded");
        let matching_rules: Vec<_> = scan_results.matching_rules().collect();
        assert!(!matching_rules.is_empty());

        // Test metadata extraction
        let rule = &matching_rules[0];
        assert_eq!(rule.identifier(), "MetadataTest");

        let metadata: std::collections::HashMap<_, _> = rule.metadata().collect();
        assert!(metadata.contains_key("name"));
        assert!(metadata.contains_key("severity"));
        assert!(metadata.contains_key("confidence"));
    }

    #[test]
    #[cfg(feature = "yara-x-scanning")]
    fn test_rejects_malformed_yara_rules() {
        // Test error handling for malformed rules
        let malformed_rule = r#"
            rule MalformedRule {
                invalid_section:
                    this_is_not_valid_yara_syntax = "error"
                condition:
                    undefined_variable
            }
        "#;

        let mut compiler = yara_x::Compiler::new();
        let result = compiler.add_source(malformed_rule);
        assert!(
            result.is_err(),
            "Malformed rule should cause compilation error"
        );
    }

    #[test]
    fn test_loads_rules_from_filesystem() {
        // Test that the real YARA rules can be loaded
        let scanner = ThreatRules::new("rules")
            .expect("Should be able to create ThreatRules with rules directory");
        let stats = scanner.memory_stats();

        // Should have loaded the .yar rule files (only when YARA-X is enabled)
        #[cfg(feature = "yara-x-scanning")]
        {
            assert!(stats.pre_scan_count + stats.post_scan_count > 0);
            assert!(stats.pre_scan_count > 0);
        }

        #[cfg(not(feature = "yara-x-scanning"))]
        {
            // When YARA is disabled, rule counts should be 0
            assert_eq!(stats.pre_scan_count + stats.post_scan_count, 0);
        }

        // Test that the real Rules struct can be loaded (only when YARA-X is available)
        #[cfg(feature = "yara-x-scanning")]
        {
            // Load rules from .yar source file (YARA-X compiles on-the-fly)
            let rule_content = std::fs::read_to_string("rules/pre/secrets_leakage.yar")
                .expect("Should be able to read secrets_leakage.yar test rule file");

            let mut compiler = yara_x::Compiler::new();
            compiler
                .add_source(rule_content.as_str())
                .expect("Should be able to compile secrets_leakage.yar rule");

            let rules = compiler.build();

            // Test that the real scan method works
            let mut scanner = yara_x::Scanner::new(&rules);
            let scan_result = scanner.scan(b"test data");
            assert!(
                scan_result.is_ok(),
                "YARA-X scanning should succeed on test data"
            );

            // Real YARA-X may or may not have matches depending on rule content
            // Just verify we got a valid result (empty or with matches)
        }
    }

    #[test]
    fn test_runs_post_scan_capability_without_errors() {
        // Test that post-scan capability can be created and runs correctly
        let post_scanner = YaraScanner::new("rules", ScanPhase::PostScan);
        assert!(
            post_scanner.is_ok(),
            "YaraScanner creation should succeed for post-scan phase"
        );

        let scanner_instance =
            post_scanner.expect("Post-scan scanner creation should have succeeded");
        assert_eq!(scanner_instance.name(), "yara");
        assert_eq!(scanner_instance.phase(), ScanPhase::PostScan);

        // Create test scan data
        let mut scan_data = ScanData {
            server_info: None,
            tools: vec![],
            resources: vec![],
            prompts: vec![],
            yara_results: vec![],
            fetch_errors: vec![],
        };

        // Run post-scan scanner (should not error even with empty data)
        let result = scanner_instance.run(&mut scan_data);
        assert!(
            result.is_ok(),
            "Post-scan scanner should run successfully on scan data"
        );
        println!("Post-scan scanner test passed");
    }

    #[test]
    fn test_tracks_separate_pre_and_post_scan_statistics() {
        #[cfg(feature = "yara-x-scanning")]
        let scanner = ThreatRules::new("rules")
            .expect("Should be able to create ThreatRules with rules directory");
        #[cfg(not(feature = "yara-x-scanning"))]
        let scanner = ThreatRules::with_config("rules", false)
            .expect("Should be able to create ThreatRules with YARA disabled");

        let stats = scanner.stats();

        println!("Pre-scan rules: {}", stats.pre_scan_count);
        println!("Post-scan rules: {}", stats.post_scan_count);

        // Should have at least some pre-scan rules (only when YARA is enabled)
        #[cfg(feature = "yara-x-scanning")]
        assert!(stats.pre_scan_count > 0);
        #[cfg(not(feature = "yara-x-scanning"))]
        assert_eq!(stats.pre_scan_count, 0);

        // Should have post-scan rules if we created test rule
        if stats.post_scan_count > 0 {
            println!("Post-scan rules detected: {}", stats.post_scan_count);
        } else {
            println!("No post-scan rules found (this is expected if none were created)");
        }
    }

    #[test]
    fn test_collects_rule_names_from_loaded_files() {
        // Test that the dynamic rule names are being collected correctly
        let scanner = ThreatRules::new("rules")
            .expect("Should be able to create ThreatRules with rules directory");
        let stats = scanner.stats();

        // Should have the expected pre-scan rules
        #[cfg(feature = "yara-x-scanning")]
        {
            assert!(!stats.pre_scan_rules.is_empty());
            assert!(stats
                .pre_scan_rules
                .contains(&"command_injection".to_string()));
            assert!(stats.pre_scan_rules.contains(&"path_traversal".to_string()));
            assert!(stats
                .pre_scan_rules
                .contains(&"secrets_leakage".to_string()));
            println!("Pre-scan rules: {:?}", stats.pre_scan_rules);
        }

        #[cfg(not(feature = "yara-x-scanning"))]
        {
            assert!(stats.pre_scan_rules.is_empty());
        }

        // Post-scan rules should be empty for now
        assert!(stats.post_scan_rules.is_empty());
        println!("Post-scan rules: {:?}", stats.post_scan_rules);
    }
}
