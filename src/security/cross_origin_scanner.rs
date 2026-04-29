use crate::scanner::{ScanData, ScanPhase, Scanner};
use crate::types::{MCPResource, MCPTool, YaraRuleMetadata, YaraScanResult};
use anyhow::Result;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use tracing::{debug, warn};
use url::Url;

/// Dedicated Cross-Origin Scanner
///
/// Performs comprehensive analysis of all URLs across all tools and resources
/// to detect cross-domain contamination and ensure all tools belong to the same domain.
/// This complements the YARA rule by providing programmatic domain analysis.
#[derive(Clone)]
pub struct CrossOriginScanner {
    phase: ScanPhase,
}

#[derive(Debug, Clone)]
pub struct DomainInfo {
    pub scheme: String,
    pub host: String,
    pub root_domain: String,
}

#[derive(Debug, Clone)]
pub struct CrossOriginAnalysis {
    pub unique_root_domains: HashSet<String>,
    pub unique_hosts: HashSet<String>,
    pub mixed_schemes: bool,
    pub has_cross_domain_contamination: bool,
    pub domain_distribution: HashMap<String, Vec<String>>, // domain -> list of tools/resources using it
    pub outlier_analysis: Vec<String>, // tools/resources that use different domains
}

impl CrossOriginScanner {
    pub fn new(phase: ScanPhase) -> Self {
        Self { phase }
    }

    /// Extract all URLs from a JSON value recursively
    #[allow(clippy::only_used_in_recursion)]
    fn extract_urls_from_json(&self, value: &Value, urls: &mut Vec<String>) {
        match value {
            Value::String(s) if Self::is_url(s) => {
                urls.push(s.clone());
            }
            Value::Object(map) => {
                for (key, val) in map {
                    // Check both key and value for URLs
                    if Self::is_url(key) {
                        urls.push(key.clone());
                    }
                    self.extract_urls_from_json(val, urls);
                }
            }
            Value::Array(arr) => {
                for item in arr {
                    self.extract_urls_from_json(item, urls);
                }
            }
            _ => {}
        }
    }

    /// Check if a string looks like a URL
    fn is_url(s: &str) -> bool {
        s.starts_with("http://")
            || s.starts_with("https://")
            || s.starts_with("ws://")
            || s.starts_with("wss://")
    }

    /// Parse URL and extract detailed domain information
    fn parse_domain_info(url_str: &str) -> Option<DomainInfo> {
        if let Ok(url) = Url::parse(url_str) {
            if let Some(host) = url.host_str() {
                let root_domain = Self::extract_root_domain(host);

                return Some(DomainInfo {
                    scheme: url.scheme().to_string(),
                    host: host.to_string(),
                    root_domain,
                });
            }
        }
        None
    }

    /// Extract root domain from host (e.g., "api.example.com" -> "example.com")
    fn extract_root_domain(host: &str) -> String {
        // Handle IP addresses
        if host.chars().all(|c| c.is_numeric() || c == '.') {
            return host.to_string();
        }

        // Handle localhost
        if host == "localhost" {
            return host.to_string();
        }

        let parts: Vec<&str> = host.split('.').collect();
        if parts.len() >= 2 {
            // Take last two parts as root domain (handles most cases)
            // This is a simplified approach - production code might use a public suffix list
            format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1])
        } else {
            host.to_string()
        }
    }

    /// Extract URLs from a single tool
    fn extract_tool_urls(&self, tool: &MCPTool) -> Vec<String> {
        let mut urls = Vec::new();

        // Extract URLs from parameters
        for param_value in tool.parameters.values() {
            self.extract_urls_from_json(param_value, &mut urls);
        }

        // Extract URLs from schemas
        if let Some(input_schema) = &tool.input_schema {
            self.extract_urls_from_json(input_schema, &mut urls);
        }
        if let Some(output_schema) = &tool.output_schema {
            self.extract_urls_from_json(output_schema, &mut urls);
        }

        // Extract URLs from raw JSON
        if let Some(raw_json) = &tool.raw_json {
            self.extract_urls_from_json(raw_json, &mut urls);
        }

        // Also check description for URLs
        if let Some(description) = &tool.description {
            if Self::is_url(description) {
                urls.push(description.clone());
            }
        }

        urls
    }

    /// Extract URLs from a single resource
    fn extract_resource_urls(&self, resource: &MCPResource) -> Vec<String> {
        let mut urls = Vec::new();

        // Check URI field
        if Self::is_url(&resource.uri) {
            urls.push(resource.uri.clone());
        }

        // Extract from metadata
        for metadata_value in resource.metadata.values() {
            self.extract_urls_from_json(metadata_value, &mut urls);
        }

        // Check description for URLs
        if let Some(description) = &resource.description {
            if Self::is_url(description) {
                urls.push(description.clone());
            }
        }

        urls
    }

    /// Perform comprehensive cross-domain analysis
    fn analyze_cross_domain_contamination(&self, scan_data: &ScanData) -> CrossOriginAnalysis {
        let mut unique_root_domains = HashSet::new();
        let mut unique_hosts = HashSet::new();
        let mut schemes = HashSet::new();
        let mut domain_distribution: HashMap<String, Vec<String>> = HashMap::new();

        // Analyze tools
        for tool in &scan_data.tools {
            let urls = self.extract_tool_urls(tool);

            for url in urls {
                if let Some(domain_info) = Self::parse_domain_info(&url) {
                    unique_root_domains.insert(domain_info.root_domain.clone());
                    unique_hosts.insert(domain_info.host.clone());
                    schemes.insert(domain_info.scheme.clone());

                    // Track which tools use which domains
                    domain_distribution
                        .entry(domain_info.root_domain.clone())
                        .or_default()
                        .push(format!("tool:{}", tool.name));
                }
            }
        }

        // Analyze resources
        for resource in &scan_data.resources {
            let urls = self.extract_resource_urls(resource);

            for url in urls {
                if let Some(domain_info) = Self::parse_domain_info(&url) {
                    unique_root_domains.insert(domain_info.root_domain.clone());
                    unique_hosts.insert(domain_info.host.clone());
                    schemes.insert(domain_info.scheme.clone());

                    // Track which resources use which domains
                    domain_distribution
                        .entry(domain_info.root_domain.clone())
                        .or_default()
                        .push(format!("resource:{}", resource.name));
                }
            }
        }

        // Determine if there's cross-domain contamination
        let has_cross_domain_contamination = unique_root_domains.len() > 1;

        // Check for mixed schemes
        let mixed_schemes = schemes.contains("http") && schemes.contains("https");

        // Identify outliers (tools/resources using minority domains)
        let mut outlier_analysis = Vec::new();
        if has_cross_domain_contamination {
            // Find the most common domain
            let most_common_domain = domain_distribution
                .iter()
                .max_by_key(|(_, tools_resources)| tools_resources.len())
                .map(|(domain, _)| domain.clone());

            if let Some(common_domain) = most_common_domain {
                for (domain, tools_resources) in &domain_distribution {
                    if domain != &common_domain {
                        for item in tools_resources {
                            outlier_analysis.push(format!(
                                "{item} uses domain '{domain}' instead of common domain '{common_domain}'"
                            ));
                        }
                    }
                }
            }
        }

        CrossOriginAnalysis {
            unique_root_domains,
            unique_hosts,
            mixed_schemes,
            has_cross_domain_contamination,
            domain_distribution,
            outlier_analysis,
        }
    }

    /// Generate YARA-style scan results from the analysis
    fn create_scan_results(&self, analysis: &CrossOriginAnalysis) -> Vec<YaraScanResult> {
        let mut results = Vec::new();

        // Main cross-domain contamination result
        if analysis.has_cross_domain_contamination {
            let domains_list: Vec<String> = analysis.unique_root_domains.iter().cloned().collect();

            let metadata = YaraRuleMetadata {
                name: Some("Cross-Domain Contamination Detection".to_string()),
                author: Some("Ramparts Security Team".to_string()),
                date: Some("2025-01-29".to_string()),
                version: Some("1.0".to_string()),
                description: Some("Detected tools and resources spanning multiple domains, indicating potential cross-origin escalation risk".to_string()),
                severity: Some("HIGH".to_string()),
                category: Some("cross-domain-contamination".to_string()),
                confidence: Some("HIGH".to_string()),
                tags: vec!["cross-domain".to_string(), "contamination".to_string(), "security".to_string()],
            };

            results.push(YaraScanResult {
                target_type: "domain-analysis".to_string(),
                target_name: "cross-domain-detection".to_string(),
                rule_name: "CrossDomainContamination".to_string(),
                rule_file: Some("cross_origin_escalation".to_string()),
                matched_text: Some(format!(
                    "Cross-domain contamination detected across {} domains: {}",
                    domains_list.len(),
                    domains_list.join(", ")
                )),
                context: format!(
                    "Found tools and resources spanning {} different root domains",
                    analysis.unique_root_domains.len()
                ),
                rule_metadata: Some(metadata.clone()),
                owasp_tags: crate::taxonomy::tags_for_yara_rule("CrossDomainContamination"),
                phase: Some(match self.phase {
                    ScanPhase::PreScan => "pre-scan".to_string(),
                    ScanPhase::PostScan => "post-scan".to_string(),
                }),
                rules_executed: None,
                security_issues_detected: None,
                total_items_scanned: Some(
                    analysis.domain_distribution.values().map(Vec::len).sum(),
                ),
                total_matches: Some(1),
                status: Some("warning".to_string()),
            });

            // Create detailed outlier results
            for outlier in &analysis.outlier_analysis {
                results.push(YaraScanResult {
                    target_type: "outlier-analysis".to_string(),
                    target_name: "domain-outlier".to_string(),
                    rule_name: "DomainOutlier".to_string(),
                    rule_file: Some("cross_origin_escalation".to_string()),
                    matched_text: Some(outlier.clone()),
                    context: "Tool or resource using different domain than majority".to_string(),
                    rule_metadata: Some(metadata.clone()),
                    owasp_tags: crate::taxonomy::tags_for_yara_rule("DomainOutlier"),
                    phase: Some(match self.phase {
                        ScanPhase::PreScan => "pre-scan".to_string(),
                        ScanPhase::PostScan => "post-scan".to_string(),
                    }),
                    rules_executed: None,
                    security_issues_detected: None,
                    total_items_scanned: None,
                    total_matches: None,
                    status: Some("warning".to_string()),
                });
            }
        }

        // Mixed scheme detection
        if analysis.mixed_schemes {
            let metadata = YaraRuleMetadata {
                name: Some("Mixed Security Scheme Detection".to_string()),
                author: Some("Ramparts Security Team".to_string()),
                date: Some("2025-01-29".to_string()),
                version: Some("1.0".to_string()),
                description: Some(
                    "Detected mixed HTTP/HTTPS schemes which may create security vulnerabilities"
                        .to_string(),
                ),
                severity: Some("MEDIUM".to_string()),
                category: Some("mixed-schemes".to_string()),
                confidence: Some("HIGH".to_string()),
                tags: vec!["mixed-schemes".to_string(), "security".to_string()],
            };

            results.push(YaraScanResult {
                target_type: "scheme-analysis".to_string(),
                target_name: "mixed-schemes".to_string(),
                rule_name: "MixedSecuritySchemes".to_string(),
                rule_file: Some("cross_origin_escalation".to_string()),
                matched_text: Some("Mixed HTTP and HTTPS schemes detected".to_string()),
                context:
                    "Tools or resources use both secure (HTTPS) and insecure (HTTP) connections"
                        .to_string(),
                rule_metadata: Some(metadata.clone()),
                owasp_tags: crate::taxonomy::tags_for_yara_rule("MixedSecuritySchemes"),
                phase: Some(match self.phase {
                    ScanPhase::PreScan => "pre-scan".to_string(),
                    ScanPhase::PostScan => "post-scan".to_string(),
                }),
                rules_executed: None,
                security_issues_detected: None,
                total_items_scanned: Some(analysis.unique_hosts.len()),
                total_matches: Some(1),
                status: Some("warning".to_string()),
            });
        }

        results
    }
}

impl Scanner for CrossOriginScanner {
    fn name(&self) -> &'static str {
        "cross-origin-domain-analyzer"
    }

    fn phase(&self) -> ScanPhase {
        self.phase
    }

    fn run(&self, scan_data: &mut ScanData) -> Result<()> {
        debug!("Running cross-domain analysis");

        let analysis = self.analyze_cross_domain_contamination(scan_data);

        // Only log interesting findings
        if analysis.has_cross_domain_contamination {
            warn!(
                "Cross-domain contamination detected: {} different domains found",
                analysis.unique_root_domains.len()
            );

            for outlier in &analysis.outlier_analysis {
                warn!("Domain outlier: {}", outlier);
            }
        } else {
            debug!("No cross-domain contamination detected");
        }

        if analysis.mixed_schemes {
            warn!("Mixed HTTP/HTTPS schemes detected - security risk");
        }

        // Generate and add scan results
        let results = self.create_scan_results(&analysis);
        scan_data.yara_results.extend(results);

        Ok(())
    }

    fn box_clone(&self) -> Box<dyn Scanner> {
        Box::new(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::HashMap;

    fn create_test_tool(name: &str, url: &str) -> MCPTool {
        MCPTool {
            name: name.to_string(),
            description: Some(format!("Test tool {name}")),
            input_schema: Some(json!({
                "type": "object",
                "properties": {
                    "endpoint": {
                        "type": "string",
                        "default": url
                    }
                }
            })),
            output_schema: None,
            parameters: HashMap::from([("api_url".to_string(), json!(url))]),
            category: None,
            tags: vec![],
            deprecated: false,
            raw_json: None,
        }
    }

    fn create_test_scan_data_with_tools(tools: Vec<MCPTool>) -> ScanData {
        ScanData {
            server_info: None,
            tools,
            resources: vec![],
            prompts: vec![],
            yara_results: vec![],
            fetch_errors: vec![],
        }
    }

    #[test]
    fn test_cross_domain_contamination_detection() {
        let scanner = CrossOriginScanner::new(ScanPhase::PreScan);

        // Create test tools as described in the example
        let tool_a = create_test_tool("ToolA", "https://api.service1.com/data");
        let tool_b = create_test_tool("ToolB", "https://auth.service1.com/token");
        let tool_c = create_test_tool("ToolC", "https://api.service2.com/info");

        let mut scan_data = create_test_scan_data_with_tools(vec![tool_a, tool_b, tool_c]);

        // Run the scanner
        let result = scanner.run(&mut scan_data);
        assert!(result.is_ok(), "Scanner should run successfully");

        // Verify results
        assert!(
            !scan_data.yara_results.is_empty(),
            "Should have scan results"
        );

        // Find the cross-domain contamination result
        let contamination_result = scan_data
            .yara_results
            .iter()
            .find(|r| r.rule_name == "CrossDomainContamination");
        assert!(
            contamination_result.is_some(),
            "Should detect cross-domain contamination"
        );

        let contamination_result = contamination_result.unwrap();
        assert_eq!(contamination_result.target_type, "domain-analysis");
        assert_eq!(contamination_result.status, Some("warning".to_string()));

        // Verify the metadata severity
        let metadata = contamination_result
            .rule_metadata
            .as_ref()
            .expect("CrossDomainContamination result should have metadata");
        assert_eq!(
            metadata.severity,
            Some("HIGH".to_string()),
            "Should be HIGH severity"
        );

        // Find outlier results
        let outlier_results: Vec<_> = scan_data
            .yara_results
            .iter()
            .filter(|r| r.rule_name == "DomainOutlier")
            .collect();
        assert!(!outlier_results.is_empty(), "Should have outlier results");

        // Verify at least one outlier mentions ToolC and service2.com
        let has_tool_c_outlier = outlier_results.iter().any(|r| {
            if let Some(matched_text) = &r.matched_text {
                matched_text.contains("tool:ToolC") && matched_text.contains("service2.com")
            } else {
                false
            }
        });
        assert!(
            has_tool_c_outlier,
            "Should flag ToolC as outlier using service2.com"
        );
    }

    #[test]
    fn test_same_domain_no_contamination() {
        let scanner = CrossOriginScanner::new(ScanPhase::PreScan);

        // Create test tools all using the same root domain
        let tool_a = create_test_tool("ToolA", "https://api.service1.com/data");
        let tool_b = create_test_tool("ToolB", "https://auth.service1.com/token");
        let tool_c = create_test_tool("ToolC", "https://cdn.service1.com/assets");

        let mut scan_data = create_test_scan_data_with_tools(vec![tool_a, tool_b, tool_c]);

        // Run the scanner
        let result = scanner.run(&mut scan_data);
        assert!(result.is_ok(), "Scanner should run successfully");

        // Verify no cross-domain contamination detected
        let contamination_result = scan_data
            .yara_results
            .iter()
            .find(|r| r.rule_name == "CrossDomainContamination");
        assert!(
            contamination_result.is_none(),
            "Should not detect cross-domain contamination for same domain"
        );

        // Verify no outlier results
        let outlier_results: Vec<_> = scan_data
            .yara_results
            .iter()
            .filter(|r| r.rule_name == "DomainOutlier")
            .collect();
        assert!(
            outlier_results.is_empty(),
            "Should have no outlier results for same domain"
        );
    }

    #[test]
    fn test_domain_extraction() {
        let _scanner = CrossOriginScanner::new(ScanPhase::PreScan);

        // Test root domain extraction
        assert_eq!(
            CrossOriginScanner::extract_root_domain("api.service1.com"),
            "service1.com"
        );
        assert_eq!(
            CrossOriginScanner::extract_root_domain("auth.service1.com"),
            "service1.com"
        );
        assert_eq!(
            CrossOriginScanner::extract_root_domain("service2.com"),
            "service2.com"
        );
        assert_eq!(
            CrossOriginScanner::extract_root_domain("subdomain.example.org"),
            "example.org"
        );
        assert_eq!(
            CrossOriginScanner::extract_root_domain("localhost"),
            "localhost"
        );
        assert_eq!(
            CrossOriginScanner::extract_root_domain("127.0.0.1"),
            "127.0.0.1"
        );
    }

    #[test]
    fn test_mixed_schemes_detection() {
        let scanner = CrossOriginScanner::new(ScanPhase::PreScan);

        // Create test tools with mixed HTTP/HTTPS
        let tool_a = create_test_tool("ToolA", "https://api.service1.com/data");
        let tool_b = create_test_tool("ToolB", "http://api.service1.com/insecure");

        let mut scan_data = create_test_scan_data_with_tools(vec![tool_a, tool_b]);

        // Run the scanner
        let result = scanner.run(&mut scan_data);
        assert!(result.is_ok(), "Scanner should run successfully");

        // Verify mixed schemes detection
        let mixed_schemes_result = scan_data
            .yara_results
            .iter()
            .find(|r| r.rule_name == "MixedSecuritySchemes");
        assert!(
            mixed_schemes_result.is_some(),
            "Should detect mixed security schemes"
        );

        let mixed_schemes_result = mixed_schemes_result.unwrap();
        let metadata = mixed_schemes_result
            .rule_metadata
            .as_ref()
            .expect("MixedSecuritySchemes result should have metadata");
        assert_eq!(
            metadata.severity,
            Some("MEDIUM".to_string()),
            "Should be MEDIUM severity"
        );
    }

    #[test]
    fn test_url_extraction_from_tool_parameters() {
        let scanner = CrossOriginScanner::new(ScanPhase::PreScan);

        let tool = MCPTool {
            name: "TestTool".to_string(),
            description: Some("https://docs.example.com/test".to_string()),
            input_schema: Some(json!({
                "properties": {
                    "webhook_url": {
                        "default": "https://webhook.service1.com/callback"
                    }
                }
            })),
            output_schema: None,
            parameters: HashMap::from([
                (
                    "api_endpoint".to_string(),
                    json!("https://api.service1.com/v1"),
                ),
                (
                    "backup_url".to_string(),
                    json!("https://backup.service2.com/store"),
                ),
            ]),
            category: None,
            tags: vec![],
            deprecated: false,
            raw_json: Some(json!({
                "metadata": {
                    "docs_url": "https://help.service1.com/docs"
                }
            })),
        };

        let urls = scanner.extract_tool_urls(&tool);

        // Should extract URLs from description, input_schema, parameters, and raw_json
        assert!(urls.contains(&"https://docs.example.com/test".to_string()));
        assert!(urls.contains(&"https://webhook.service1.com/callback".to_string()));
        assert!(urls.contains(&"https://api.service1.com/v1".to_string()));
        assert!(urls.contains(&"https://backup.service2.com/store".to_string()));
        assert!(urls.contains(&"https://help.service1.com/docs".to_string()));

        // Should extract at least 5 URLs
        assert!(
            urls.len() >= 5,
            "Should extract multiple URLs from different fields"
        );
    }
}
