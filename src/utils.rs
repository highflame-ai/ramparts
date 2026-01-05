use crate::security::{SecurityIssue, SecurityIssueType};
use crate::types::{ScanResult, ScanStatus};
use anyhow::{anyhow, Result};
use colored::Colorize;
use std::fs::File;
use std::io::Write;
use std::time::Instant;
use tracing::{debug, warn};

use tabled::{Table, Tabled};

// ============================================================================
// UTILITY FUNCTIONS FOR REDUCING REDUNDANCY
// ============================================================================

/// Timing utility for measuring execution time
pub struct Timer {
    start_time: Instant,
}

impl Timer {
    pub fn start() -> Self {
        Self {
            start_time: Instant::now(),
        }
    }

    pub fn elapsed_ms(&self) -> u64 {
        #[allow(clippy::cast_possible_truncation)]
        {
            self.start_time.elapsed().as_millis() as u64
        }
    }
}

/// Enhanced error handling utilities
pub mod error_utils {
    use super::{anyhow, Result};

    /// Format a standardized error message
    pub fn format_error(operation: &str, details: &str) -> String {
        format!("{operation} failed: {details}")
    }

    /// Wrap an error with context
    /// Wraps an error with additional context information
    #[allow(dead_code)] // Used in tests and for error context enhancement
    pub fn wrap_error<T>(result: Result<T>, context: &str) -> Result<T> {
        result.map_err(|e| anyhow!("{context}: {e}"))
    }
}

/// Performance monitoring utilities
pub mod performance {
    use super::{debug, warn, Result, Timer};

    /// Track performance metrics
    pub struct PerformanceTracker {
        timer: Timer,
        operation_name: String,
    }

    impl PerformanceTracker {
        pub fn start(operation_name: &str) -> Self {
            Self {
                timer: Timer::start(),
                operation_name: operation_name.to_string(),
            }
        }

        pub fn finish(self) -> u64 {
            let elapsed = self.timer.elapsed_ms();
            if elapsed > 5000 {
                // Only warn if over 5 seconds
                warn!("Slow operation: {} took {}ms", self.operation_name, elapsed);
            } else if elapsed > 1000 {
                debug!("{} completed in {}ms", self.operation_name, elapsed);
            }
            elapsed
        }
    }

    /// Execute an operation with performance tracking
    pub async fn track_performance<F, Fut, T>(operation_name: &str, operation: F) -> Result<T>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        let tracker = PerformanceTracker::start(operation_name);
        let result = operation().await;
        let _elapsed = tracker.finish();
        result
    }
}

// ============================================================================
// EXISTING PRINTING FUNCTIONS
// ============================================================================

pub fn print_result(result: &ScanResult, format: &str, detailed: bool) {
    match format.to_lowercase().as_str() {
        "json" => print_json_result(result),
        "table" => print_table_result(result, detailed),
        "text" => print_text_result(result),
        "raw" => print_raw_json_result(result),
        _ => {
            eprintln!("Unknown format: {format}. Using table format.");
            print_table_result(result, detailed);
        }
    }
}

fn print_json_result(result: &ScanResult) {
    match serde_json::to_string_pretty(result) {
        Ok(json) => println!("{json}"),
        Err(e) => {
            eprintln!("Error serializing result to JSON: {e}");
            println!("{{\"error\": \"Failed to serialize scan result\"}}");
        }
    }
}

fn print_raw_json_result(result: &ScanResult) {
    let raw_result = build_raw_json_result(result);
    println!(
        "{}",
        serde_json::to_string_pretty(&raw_result)
            .unwrap_or_else(|e| { format!("{{\"error\": \"Failed to serialize result: {e}\"}}") })
    );
}

/// Builds a raw JSON structure that preserves the original MCP server schema with embedded security results
fn build_raw_json_result(result: &ScanResult) -> serde_json::Map<String, serde_json::Value> {
    let mut raw_result = serde_json::Map::new();

    add_basic_scan_info(&mut raw_result, result);
    add_server_info(&mut raw_result, result);
    add_tools_info(&mut raw_result, result);
    add_resources_info(&mut raw_result, result);
    add_prompts_info(&mut raw_result, result);
    add_errors_info(&mut raw_result, result);

    // Add comprehensive security issues section
    add_security_issues_section(&mut raw_result, result);

    // Add summary of security scan results
    add_security_summary(&mut raw_result, result);

    raw_result
}

/// Adds basic scan information to the raw JSON result
fn add_basic_scan_info(
    raw_result: &mut serde_json::Map<String, serde_json::Value>,
    result: &ScanResult,
) {
    raw_result.insert(
        "url".to_string(),
        serde_json::Value::String(result.url.clone()),
    );
    raw_result.insert(
        "status".to_string(),
        serde_json::Value::String(format!("{:?}", result.status)),
    );
    raw_result.insert(
        "response_time_ms".to_string(),
        serde_json::Value::Number(serde_json::Number::from(result.response_time_ms)),
    );
    raw_result.insert(
        "timestamp".to_string(),
        serde_json::Value::String(result.timestamp.to_rfc3339()),
    );
}

/// Adds server information to the raw JSON result
fn add_server_info(
    raw_result: &mut serde_json::Map<String, serde_json::Value>,
    result: &ScanResult,
) {
    if let Some(server_info) = &result.server_info {
        let mut server_info_obj = serde_json::Map::new();
        server_info_obj.insert(
            "name".to_string(),
            serde_json::Value::String(server_info.name.clone()),
        );
        server_info_obj.insert(
            "version".to_string(),
            serde_json::Value::String(server_info.version.clone()),
        );

        if let Some(desc) = &server_info.description {
            server_info_obj.insert(
                "description".to_string(),
                serde_json::Value::String(desc.clone()),
            );
        }

        server_info_obj.insert(
            "capabilities".to_string(),
            serde_json::Value::Array(
                server_info
                    .capabilities
                    .iter()
                    .map(|c| serde_json::Value::String(c.clone()))
                    .collect(),
            ),
        );

        raw_result.insert(
            "server_info".to_string(),
            serde_json::Value::Object(server_info_obj),
        );
    }
}

/// Adds tools information to the raw JSON result with embedded security and YARA results
fn add_tools_info(
    raw_result: &mut serde_json::Map<String, serde_json::Value>,
    result: &ScanResult,
) {
    if !result.tools.is_empty() {
        let tools_array = result
            .tools
            .iter()
            .map(|tool| {
                let mut tool_json = tool.raw_json.clone().unwrap_or_else(|| {
                    serde_json::to_value(tool).unwrap_or(serde_json::Value::Null)
                });

                // Add security scan results for this tool
                let mut security_results = Vec::new();
                if let Some(ref security_issues) = result.security_issues {
                    // Find LLM-based security issues for this tool
                    let tool_issues: Vec<_> = security_issues
                        .tool_issues
                        .iter()
                        .filter(|issue| issue.tool_name.as_ref() == Some(&tool.name))
                        .collect();

                    for issue in tool_issues {
                        security_results.push(serde_json::json!({
                            "scan_type": "llm_analysis",
                            "issue_type": issue.issue_type,
                            "severity": issue.severity,
                            "message": issue.message,
                            "description": issue.description,
                            "details": issue.details
                        }));
                    }

                    // Add LLM analysis details if available
                    if let Some(analysis_details) =
                        security_issues.tool_analysis_details.get(&tool.name)
                    {
                        if let Some(tool_obj) = tool_json.as_object_mut() {
                            tool_obj.insert(
                                "llm_analysis".to_string(),
                                serde_json::Value::String(analysis_details.clone()),
                            );
                        }
                    }
                }

                // Find YARA results for this tool
                let tool_yara_results: Vec<_> = result
                    .yara_results
                    .iter()
                    .filter(|yara| yara.target_type == "tool" && yara.target_name == tool.name)
                    .collect();

                for yara_result in tool_yara_results {
                    security_results.push(serde_json::json!({
                        "scan_type": "yara_rules",
                        "rule_name": yara_result.rule_name,
                        "rule_file": yara_result.rule_file,
                        "matched_text": yara_result.matched_text,
                        "context": yara_result.context,
                        "rule_metadata": yara_result.rule_metadata
                    }));
                }

                // Add security results to the tool JSON
                if !security_results.is_empty() {
                    if let Some(tool_obj) = tool_json.as_object_mut() {
                        tool_obj.insert(
                            "security_scan_results".to_string(),
                            serde_json::Value::Array(security_results),
                        );
                    }
                }

                tool_json
            })
            .collect();
        raw_result.insert("tools".to_string(), serde_json::Value::Array(tools_array));
    }
}

/// Adds resources information to the raw JSON result with embedded security and YARA results
fn add_resources_info(
    raw_result: &mut serde_json::Map<String, serde_json::Value>,
    result: &ScanResult,
) {
    if !result.resources.is_empty() {
        let resources_array = result
            .resources
            .iter()
            .map(|resource| {
                let mut resource_json = resource.raw_json.clone().unwrap_or_else(|| {
                    serde_json::to_value(resource).unwrap_or(serde_json::Value::Null)
                });

                // Add security scan results for this resource
                let mut security_results = Vec::new();
                if let Some(ref security_issues) = result.security_issues {
                    // Find LLM-based security issues for this resource
                    let resource_issues: Vec<_> = security_issues
                        .resource_issues
                        .iter()
                        .filter(|issue| issue.resource_uri.as_ref() == Some(&resource.uri))
                        .collect();

                    for issue in resource_issues {
                        security_results.push(serde_json::json!({
                            "scan_type": "llm_analysis",
                            "issue_type": issue.issue_type,
                            "severity": issue.severity,
                            "message": issue.message,
                            "description": issue.description,
                            "details": issue.details
                        }));
                    }
                }

                // Find YARA results for this resource
                let resource_yara_results: Vec<_> = result
                    .yara_results
                    .iter()
                    .filter(|yara| {
                        yara.target_type == "resource" && yara.target_name == resource.uri
                    })
                    .collect();

                for yara_result in resource_yara_results {
                    security_results.push(serde_json::json!({
                        "scan_type": "yara_rules",
                        "rule_name": yara_result.rule_name,
                        "rule_file": yara_result.rule_file,
                        "matched_text": yara_result.matched_text,
                        "context": yara_result.context,
                        "rule_metadata": yara_result.rule_metadata
                    }));
                }

                // Add security results to the resource JSON
                if !security_results.is_empty() {
                    if let Some(resource_obj) = resource_json.as_object_mut() {
                        resource_obj.insert(
                            "security_scan_results".to_string(),
                            serde_json::Value::Array(security_results),
                        );
                    }
                }

                resource_json
            })
            .collect();
        raw_result.insert(
            "resources".to_string(),
            serde_json::Value::Array(resources_array),
        );
    }
}

/// Adds prompts information to the raw JSON result with embedded security and YARA results
fn add_prompts_info(
    raw_result: &mut serde_json::Map<String, serde_json::Value>,
    result: &ScanResult,
) {
    if !result.prompts.is_empty() {
        let prompts_array = result
            .prompts
            .iter()
            .map(|prompt| {
                let mut prompt_json = prompt.raw_json.clone().unwrap_or_else(|| {
                    serde_json::to_value(prompt).unwrap_or(serde_json::Value::Null)
                });

                // Add security scan results for this prompt
                let mut security_results = Vec::new();
                if let Some(ref security_issues) = result.security_issues {
                    // Find LLM-based security issues for this prompt
                    let prompt_issues: Vec<_> = security_issues
                        .prompt_issues
                        .iter()
                        .filter(|issue| issue.prompt_name.as_ref() == Some(&prompt.name))
                        .collect();

                    for issue in prompt_issues {
                        security_results.push(serde_json::json!({
                            "scan_type": "llm_analysis",
                            "issue_type": issue.issue_type,
                            "severity": issue.severity,
                            "message": issue.message,
                            "description": issue.description,
                            "details": issue.details
                        }));
                    }
                }

                // Find YARA results for this prompt
                let prompt_yara_results: Vec<_> = result
                    .yara_results
                    .iter()
                    .filter(|yara| yara.target_type == "prompt" && yara.target_name == prompt.name)
                    .collect();

                for yara_result in prompt_yara_results {
                    security_results.push(serde_json::json!({
                        "scan_type": "yara_rules",
                        "rule_name": yara_result.rule_name,
                        "rule_file": yara_result.rule_file,
                        "matched_text": yara_result.matched_text,
                        "context": yara_result.context,
                        "rule_metadata": yara_result.rule_metadata
                    }));
                }

                // Add security results to the prompt JSON
                if !security_results.is_empty() {
                    if let Some(prompt_obj) = prompt_json.as_object_mut() {
                        prompt_obj.insert(
                            "security_scan_results".to_string(),
                            serde_json::Value::Array(security_results),
                        );
                    }
                }

                prompt_json
            })
            .collect();
        raw_result.insert(
            "prompts".to_string(),
            serde_json::Value::Array(prompts_array),
        );
    }
}

/// Adds comprehensive security issues section with both LLM and YARA results
fn add_security_issues_section(
    raw_result: &mut serde_json::Map<String, serde_json::Value>,
    result: &ScanResult,
) {
    let mut security_issues = serde_json::Map::new();
    let mut all_issues = Vec::new();

    // Add LLM-based security issues
    if let Some(ref sec_issues) = result.security_issues {
        // Tool issues
        for issue in &sec_issues.tool_issues {
            all_issues.push(serde_json::json!({
                "scan_type": "llm_analysis",
                "target_type": "tool",
                "target_name": issue.tool_name,
                "issue_type": issue.issue_type,
                "severity": issue.severity,
                "message": issue.message,
                "description": issue.description,
                "details": issue.details
            }));
        }

        // Resource issues
        for issue in &sec_issues.resource_issues {
            all_issues.push(serde_json::json!({
                "scan_type": "llm_analysis",
                "target_type": "resource",
                "target_name": issue.resource_uri,
                "issue_type": issue.issue_type,
                "severity": issue.severity,
                "message": issue.message,
                "description": issue.description,
                "details": issue.details
            }));
        }

        // Prompt issues
        for issue in &sec_issues.prompt_issues {
            all_issues.push(serde_json::json!({
                "scan_type": "llm_analysis",
                "target_type": "prompt",
                "target_name": issue.prompt_name,
                "issue_type": issue.issue_type,
                "severity": issue.severity,
                "message": issue.message,
                "description": issue.description,
                "details": issue.details
            }));
        }
    }

    // Add YARA scan results
    for yara_result in &result.yara_results {
        all_issues.push(serde_json::json!({
            "scan_type": "yara_rules",
            "target_type": yara_result.target_type,
            "target_name": yara_result.target_name,
            "rule_name": yara_result.rule_name,
            "rule_file": yara_result.rule_file,
            "matched_text": yara_result.matched_text,
            "context": yara_result.context,
            "rule_metadata": yara_result.rule_metadata
        }));
    }

    // Sort by severity (Critical > High > Medium > Low)
    all_issues.sort_by(|a, b| {
        let severity_a = a
            .get("severity")
            .or_else(|| a.get("rule_metadata").and_then(|m| m.get("severity")))
            .and_then(|s| s.as_str())
            .unwrap_or("LOW");
        let severity_b = b
            .get("severity")
            .or_else(|| b.get("rule_metadata").and_then(|m| m.get("severity")))
            .and_then(|s| s.as_str())
            .unwrap_or("LOW");

        let order_a = match severity_a {
            "CRITICAL" => 0,
            "HIGH" => 1,
            "MEDIUM" => 2,
            _ => 3,
        };
        let order_b = match severity_b {
            "CRITICAL" => 0,
            "HIGH" => 1,
            "MEDIUM" => 2,
            _ => 3,
        };

        order_a.cmp(&order_b)
    });

    security_issues.insert("issues".to_string(), serde_json::Value::Array(all_issues));

    // Add counts by type
    let llm_count = result.security_issues.as_ref().map_or(0, |si| {
        si.tool_issues.len() + si.resource_issues.len() + si.prompt_issues.len()
    });
    let yara_count = result.yara_results.len();

    security_issues.insert("llm_issues_count".to_string(), serde_json::json!(llm_count));
    security_issues.insert(
        "yara_issues_count".to_string(),
        serde_json::json!(yara_count),
    );
    security_issues.insert(
        "total_issues_count".to_string(),
        serde_json::json!(llm_count + yara_count),
    );

    raw_result.insert(
        "security_issues".to_string(),
        serde_json::Value::Object(security_issues),
    );
}

/// Adds security scan summary to the raw JSON result
fn add_security_summary(
    raw_result: &mut serde_json::Map<String, serde_json::Value>,
    result: &ScanResult,
) {
    let mut summary = serde_json::Map::new();

    // Count security issues by type and severity
    if let Some(ref security_issues) = result.security_issues {
        let total_tool_issues = security_issues.tool_issues.len();
        let total_resource_issues = security_issues.resource_issues.len();
        let total_prompt_issues = security_issues.prompt_issues.len();
        let total_llm_issues = total_tool_issues + total_resource_issues + total_prompt_issues;

        summary.insert(
            "llm_scan_issues".to_string(),
            serde_json::Value::Number(serde_json::Number::from(total_llm_issues)),
        );
        summary.insert(
            "tool_issues".to_string(),
            serde_json::Value::Number(serde_json::Number::from(total_tool_issues)),
        );
        summary.insert(
            "resource_issues".to_string(),
            serde_json::Value::Number(serde_json::Number::from(total_resource_issues)),
        );
        summary.insert(
            "prompt_issues".to_string(),
            serde_json::Value::Number(serde_json::Number::from(total_prompt_issues)),
        );
    } else {
        summary.insert(
            "llm_scan_issues".to_string(),
            serde_json::Value::Number(serde_json::Number::from(0)),
        );
        summary.insert(
            "tool_issues".to_string(),
            serde_json::Value::Number(serde_json::Number::from(0)),
        );
        summary.insert(
            "resource_issues".to_string(),
            serde_json::Value::Number(serde_json::Number::from(0)),
        );
        summary.insert(
            "prompt_issues".to_string(),
            serde_json::Value::Number(serde_json::Number::from(0)),
        );
    }

    // Count YARA scan results
    let total_yara_issues = result.yara_results.len();
    summary.insert(
        "yara_scan_issues".to_string(),
        serde_json::Value::Number(serde_json::Number::from(total_yara_issues)),
    );

    // Add total security issues
    let total_security_issues = summary
        .get("llm_scan_issues")
        .and_then(|v| v.as_u64())
        .unwrap_or(0)
        + summary
            .get("yara_scan_issues")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
    summary.insert(
        "total_security_issues".to_string(),
        serde_json::Value::Number(serde_json::Number::from(total_security_issues)),
    );

    raw_result.insert(
        "security_scan_summary".to_string(),
        serde_json::Value::Object(summary),
    );
}

/// Adds error information to the raw JSON result
fn add_errors_info(
    raw_result: &mut serde_json::Map<String, serde_json::Value>,
    result: &ScanResult,
) {
    if !result.errors.is_empty() {
        let errors_array = result
            .errors
            .iter()
            .map(|e| serde_json::Value::String(e.clone()))
            .collect();
        raw_result.insert("errors".to_string(), serde_json::Value::Array(errors_array));
    }
}

#[allow(clippy::too_many_lines)]
fn print_table_result(result: &ScanResult, detailed: bool) {
    println!("Ramparts MCP Server Scan Result");

    // Server Info
    println!("URL: {}", result.url.blue());
    println!("Status: {}", format_status(&result.status));
    println!("Response Time: {}ms", result.response_time_ms);
    println!(
        "Timestamp: {}",
        result.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
    );

    if let Some(server_info) = &result.server_info {
        println!("\n{}", "Server Information".bold());
        println!("Name: {}", server_info.name);
        println!("Version: {}", server_info.version);
        if let Some(desc) = &server_info.description {
            println!("Description: {desc}");
        }
        if !server_info.capabilities.is_empty() {
            println!("Capabilities: {}", server_info.capabilities.join(", "));
        }
    }

    // Tools
    if !result.tools.is_empty() {
        println!("\n{}", "Tools".bold());
        if detailed {
            // Show detailed tool information
            for tool in &result.tools {
                println!("Tool: {}", tool.name.bold());
                if let Some(desc) = &tool.description {
                    println!("Description: {desc}");
                }
                if let Some(category) = &tool.category {
                    println!("Category: {category}");
                }
                if !tool.tags.is_empty() {
                    println!("Tags: {}", tool.tags.join(", "));
                }
                if tool.deprecated {
                    println!("Status: {}", "DEPRECATED".red().bold());
                }
                if let Some(input_schema) = &tool.input_schema {
                    println!(
                        "Input Schema: {}",
                        serde_json::to_string_pretty(input_schema)
                            .unwrap_or_else(|_| "Invalid JSON".to_string())
                    );
                }
                if let Some(output_schema) = &tool.output_schema {
                    println!(
                        "Output Schema: {}",
                        serde_json::to_string_pretty(output_schema)
                            .unwrap_or_else(|_| "Invalid JSON".to_string())
                    );
                }
                if !tool.parameters.is_empty() {
                    println!("Parameters:");
                    for (key, value) in &tool.parameters {
                        println!(
                            "  {}: {}",
                            key,
                            serde_json::to_string_pretty(value)
                                .unwrap_or_else(|_| "Invalid JSON".to_string())
                        );
                    }
                }
                if let Some(raw_json) = &tool.raw_json {
                    println!("Raw JSON Schema:");
                    println!(
                        "{}",
                        serde_json::to_string_pretty(raw_json)
                            .unwrap_or_else(|_| "Invalid JSON".to_string())
                    );
                }
                println!();
            }
        } else {
            // Only print the number of tools
            println!("Number of tools: {}", result.tools.len());
        }
    }

    // Resources
    if !result.resources.is_empty() {
        println!("\n{}", "Resources".bold());
        let resource_table = Table::new(result.resources.iter().map(|r| ResourceRow {
            uri: r.uri.clone(),
            name: r.name.clone(),
            description: r.description.clone().unwrap_or_else(|| "N/A".to_string()),
            mime_type: r.mime_type.clone().unwrap_or_else(|| "N/A".to_string()),
        }))
        .with(tabled::settings::Style::empty())
        .to_string();
        println!("{resource_table}");
    }

    // Security Assessments Completed
    println!("\n{}", "Security Assessments".bold());
    let mut assessments = Vec::new();

    if !result.tools.is_empty() {
        assessments.push("Tool Security (Tool Poisoning, Secrets Leakage, SQL Injection, Command Injection, Path Traversal, Auth Bypass)");
    }
    if !result.tools.is_empty() || !result.prompts.is_empty() {
        assessments.push("Input Security (Prompt Injection, PII Leakage, Jailbreak)");
    }
    if !result.resources.is_empty() {
        assessments.push("Resource Security (Path Traversal, Sensitive Data)");
    }

    if assessments.is_empty() {
        println!("Assessments executed: None");
    } else {
        println!("Assessments executed: {}", assessments.join(", "));
    }

    // Security issues - use enhanced table format only
    if result.security_issues.is_some() {
        print_enhanced_security_table(result);
    }

    // YARA scan results
    if result.yara_results.is_empty() {
        // Show YARA execution status even when no results at all
        println!("\n{}", "YARA Scan Results".bold());
        println!("❌ YARA scanning not executed or no results available");
        println!();
    } else {
        println!("\n{}", "YARA Scan Results".bold());

        // Separate summary results from individual match results
        let summary_results: Vec<_> = result
            .yara_results
            .iter()
            .filter(|r| r.target_type == "summary")
            .collect();
        let match_results: Vec<_> = result
            .yara_results
            .iter()
            .filter(|r| r.target_type != "summary")
            .collect();

        // Show summary information first
        for summary in &summary_results {
            let status_icon = match summary.status.as_deref() {
                Some("passed") => "✅",
                Some("warning") => "⚠️",
                _ => "🔍",
            };

            let status_text = match summary.status.as_deref() {
                Some("passed") => "PASSED".green(),
                Some("warning") => "WARNING".yellow(),
                _ => "UNKNOWN".white(),
            };

            println!(
                "{} {} - {}",
                status_icon,
                summary.target_name.to_uppercase(),
                status_text
            );
            println!("  Context: {}", summary.context);

            if let Some(total_items) = summary.total_items_scanned {
                println!("  Items scanned: {total_items}");
            }
            if let Some(total_matches) = summary.total_matches {
                println!("  Security matches: {total_matches}");
            }
            if let Some(rules) = &summary.rules_executed {
                if !rules.is_empty() {
                    println!("  Rules executed: {}", rules.join(", "));
                }
            }
            if let Some(security_issues) = &summary.security_issues_detected {
                if !security_issues.is_empty() {
                    println!("  Security issues detected: {}", security_issues.join(", "));
                }
            }
            println!();
        }

        // Show individual match results if any
        if !match_results.is_empty() {
            println!(
                "🔍 {} Individual Security Matches:",
                "Detailed Results".bold()
            );
            println!();

            for yara_result in &match_results {
                let status_icon = match yara_result.status.as_deref() {
                    Some("warning") => "⚠️",
                    _ => "🔍",
                };

                println!(
                    "{} {} ({})",
                    status_icon, yara_result.target_name, yara_result.target_type
                );

                if let Some(metadata) = &yara_result.rule_metadata {
                    let severity = metadata.severity.as_deref().unwrap_or("MEDIUM");
                    let severity_color = match severity {
                        "CRITICAL" => severity.red().bold(),
                        "HIGH" => severity.yellow().bold(),
                        "MEDIUM" => severity.blue().bold(),
                        _ => severity.green().bold(),
                    };

                    println!("  Rule: {} ({})", yara_result.rule_name, severity_color);

                    if let Some(name) = &metadata.name {
                        println!("  Name: {name}");
                    }
                    if let Some(desc) = &metadata.description {
                        println!("  Description: {desc}");
                    }
                    if let Some(author) = &metadata.author {
                        println!("  Author: {author}");
                    }
                    if let Some(version) = &metadata.version {
                        println!("  Version: {version}");
                    }
                    if let Some(confidence) = &metadata.confidence {
                        println!("  Confidence: {confidence}");
                    }
                    if !metadata.tags.is_empty() {
                        println!("  Tags: {}", metadata.tags.join(", "));
                    }
                } else {
                    println!("  Rule: {} (MEDIUM)", yara_result.rule_name);
                }

                if let Some(matched_text) = &yara_result.matched_text {
                    println!("  Matched: {matched_text}");
                }
                println!("  Context: {}", yara_result.context);
                println!();
            }
        }
    }

    // Errors
    if !result.errors.is_empty() {
        println!("\n{}", "Errors".bold().red());
        for error in &result.errors {
            println!("- {error}");
        }
    }
}

#[allow(clippy::too_many_lines)]
fn print_text_result(result: &ScanResult) {
    println!("Scan Result for: {}", result.url);
    println!("Status: {}", format_status(&result.status));
    println!("Response Time: {}ms", result.response_time_ms);

    if let Some(server_info) = &result.server_info {
        println!("Server: {} v{}", server_info.name, server_info.version);
        if let Some(desc) = &server_info.description {
            println!("Description: {desc}");
        }
        if !server_info.capabilities.is_empty() {
            println!("Capabilities: {}", server_info.capabilities.join(", "));
        }
    }

    println!("Tools: {}", result.tools.len());
    for tool in &result.tools {
        println!("  - {}", tool.name);
    }

    println!("Resources: {}", result.resources.len());
    for resource in &result.resources {
        println!("  - {} ({})", resource.name, resource.uri);
    }

    println!("Prompts: {}", result.prompts.len());
    for prompt in &result.prompts {
        println!(
            "  - {} ({})",
            prompt.name,
            prompt.description.as_deref().unwrap_or("No description")
        );
    }

    // Security issues
    if let Some(security_issues) = &result.security_issues {
        println!("Security Issues: {}", security_issues.total_issues());
        if security_issues.has_critical_issues() {
            println!("  ⚠️  CRITICAL ISSUES DETECTED");
        }
        if security_issues.has_high_issues() {
            println!("  ⚠️  HIGH SEVERITY ISSUES DETECTED");
        }

        if !security_issues.tool_issues.is_empty() {
            println!("  Tool Issues: {}", security_issues.tool_issues.len());
            for issue in &security_issues.tool_issues {
                println!("    - {}: {}", issue.severity, issue.message);
            }
        }

        if !security_issues.prompt_issues.is_empty() {
            println!("  Prompt Issues: {}", security_issues.prompt_issues.len());
            for issue in &security_issues.prompt_issues {
                println!("    - {}: {}", issue.severity, issue.message);
            }
        }

        if !security_issues.resource_issues.is_empty() {
            println!(
                "  Resource Issues: {}",
                security_issues.resource_issues.len()
            );
            for issue in &security_issues.resource_issues {
                println!("    - {}: {}", issue.severity, issue.message);
            }
        }
    }

    // YARA scan results
    if !result.yara_results.is_empty() {
        // Separate summary and match results
        let summary_results: Vec<_> = result
            .yara_results
            .iter()
            .filter(|r| r.target_type == "summary")
            .collect();
        let match_results: Vec<_> = result
            .yara_results
            .iter()
            .filter(|r| r.target_type != "summary")
            .collect();

        println!(
            "YARA Scan Results: {} total results",
            result.yara_results.len()
        );

        // Show summary results
        for summary in &summary_results {
            let status = summary.status.as_deref().unwrap_or("unknown");
            println!(
                "  {} - {}: {}",
                summary.target_name.to_uppercase(),
                status.to_uppercase(),
                summary.context
            );
            if let Some(total_matches) = summary.total_matches {
                println!("    Security matches found: {total_matches}");
            }
        }

        // Show individual matches
        for yara_result in &match_results {
            let severity = yara_result
                .rule_metadata
                .as_ref()
                .and_then(|m| m.severity.as_ref())
                .map_or("MEDIUM", String::as_str);
            let status = yara_result.status.as_deref().unwrap_or("unknown");

            println!(
                "    {} ({}): {} - {} [{}]",
                yara_result.target_name,
                yara_result.target_type,
                yara_result.rule_name,
                severity,
                status.to_uppercase()
            );
        }
    }

    if !result.errors.is_empty() {
        println!("Errors:");
        for error in &result.errors {
            println!("  - {error}");
        }
    }
}

fn format_status(status: &ScanStatus) -> String {
    match status {
        ScanStatus::Success => "SUCCESS".green().to_string(),
        ScanStatus::Failed(msg) => format!("FAILED: {msg}").red().to_string(),
        ScanStatus::Timeout => "TIMEOUT".yellow().to_string(),
        ScanStatus::ConnectionError(msg) => format!("CONNECTION ERROR: {msg}").red().to_string(),
        ScanStatus::AuthenticationError(msg) => {
            format!("AUTHENTICATION ERROR: {msg}").red().to_string()
        }
    }
}

#[derive(Tabled)]
struct ResourceRow {
    #[tabled(rename = "URI")]
    uri: String,
    #[tabled(rename = "Name")]
    name: String,
    #[tabled(rename = "Description")]
    description: String,
    #[tabled(rename = "MIME Type")]
    mime_type: String,
}

/// Enhanced security assessment table with per-tool results
#[allow(clippy::too_many_lines)]
fn print_enhanced_security_table(result: &ScanResult) {
    if let Some(security_issues) = &result.security_issues {
        println!("\n{}", "Security Assessment Results".bold());

        // Get server name
        let server_name = if let Some(server_info) = &result.server_info {
            server_info.name.clone()
        } else {
            "Unknown MCP Server".to_string()
        };

        println!("🌐 {}", server_name.bold());

        let mut total_warnings = 0;
        let mut tools_with_warnings = 0;

        // Count warnings first for summary
        for tool in &result.tools {
            let tool_issues: Vec<&SecurityIssue> = security_issues
                .tool_issues
                .iter()
                .filter(|issue| issue.tool_name.as_ref() == Some(&tool.name))
                .collect();
            if !tool_issues.is_empty() {
                tools_with_warnings += 1;
                total_warnings += tool_issues.len();
            }
        }

        // Show quick summary
        if total_warnings == 0 {
            println!("  ✅ All tools passed security checks");
        } else {
            println!(
                "  ⚠️  {tools_with_warnings} tools have security warnings ({total_warnings} total warnings)"
            );
        }
        println!();

        for tool in &result.tools {
            let tool_issues: Vec<&SecurityIssue> = security_issues
                .tool_issues
                .iter()
                .filter(|issue| issue.tool_name.as_ref() == Some(&tool.name))
                .collect();

            let warning_count = tool_issues.len();

            // Determine overall status for this tool
            let status = if warning_count == 0 {
                "passed".green()
            } else {
                "warning".yellow()
            };

            // Print tool with tree structure
            println!("  └── {} {}", tool.name, status);

            // Show detailed analysis only for tools with issues
            if !tool_issues.is_empty() {
                // Show LLM analysis details for tools with issues
                if let Some(analysis_details) =
                    security_issues.tool_analysis_details.get(&tool.name)
                {
                    println!("      📋 Analysis: {analysis_details}");
                }

                // Show specific security issues
                for issue in tool_issues {
                    let severity_color = match issue.severity.as_str() {
                        "CRITICAL" => issue.severity.red().bold(),
                        "HIGH" => issue.severity.yellow().bold(),
                        "MEDIUM" => issue.severity.blue().bold(),
                        _ => issue.severity.green().bold(),
                    };
                    if let Some(details) = &issue.details {
                        println!(
                            "      ├── {}: {} - {}",
                            severity_color, issue.message, details
                        );
                    } else {
                        println!("      ├── {}: {}", severity_color, issue.message);
                    }
                }
            }
        }

        // Show prompt security issues if any
        if !security_issues.prompt_issues.is_empty() {
            println!("\n  📝 Prompts:");
            for issue in &security_issues.prompt_issues {
                let severity_color = match issue.severity.as_str() {
                    "CRITICAL" => issue.severity.red().bold(),
                    "HIGH" => issue.severity.yellow().bold(),
                    "MEDIUM" => issue.severity.blue().bold(),
                    _ => issue.severity.green().bold(),
                };
                println!(
                    "    └── {}: {} ({})",
                    severity_color,
                    issue.message,
                    issue.prompt_name.as_ref().unwrap_or(&"Unknown".to_string())
                );
                if let Some(details) = &issue.details {
                    println!("        Details: {details}");
                }
            }
        }

        // Show resource security issues if any
        if !security_issues.resource_issues.is_empty() {
            println!("\n  📁 Resources:");
            for issue in &security_issues.resource_issues {
                let severity_color = match issue.severity.as_str() {
                    "CRITICAL" => issue.severity.red().bold(),
                    "HIGH" => issue.severity.yellow().bold(),
                    "MEDIUM" => issue.severity.blue().bold(),
                    _ => issue.severity.green().bold(),
                };
                println!(
                    "    └── {}: {} ({})",
                    severity_color,
                    issue.message,
                    issue
                        .resource_uri
                        .as_ref()
                        .unwrap_or(&"Unknown".to_string())
                );
                if let Some(details) = &issue.details {
                    println!("        Details: {details}");
                }
            }
        }

        // Add summary
        println!("\n{}", "Summary:".bold());
        println!("  • Tools scanned: {}", result.tools.len());
        if total_warnings > 0 {
            println!(
                "  • Warnings found: {tools_with_warnings} tools with {total_warnings} total warnings"
            );
        } else {
            println!(
                "  • Status: {} All tools passed security checks",
                "PASSED".green()
            );
        }
    }
}

// ============================================================================
// MULTI-SERVER PRINTING FUNCTIONS
// ============================================================================

/// Print results from multiple MCP servers
pub fn print_multi_server_results(results: &[ScanResult], format: &str, detailed: bool) {
    match format.to_lowercase().as_str() {
        "json" => print_multi_server_json(results),
        "table" => print_multi_server_tree(results, detailed),
        "text" => print_multi_server_text(results),
        "raw" => print_multi_server_raw_json(results),
        _ => {
            eprintln!("Unknown format: {format}. Using tree view format.");
            print_multi_server_tree(results, detailed);
        }
    }
}

/// Enhanced tree view for multiple MCP servers grouped by IDE
#[allow(clippy::too_many_lines)]
fn print_multi_server_tree(results: &[ScanResult], _detailed: bool) {
    // Group results by IDE source
    let mut results_by_ide: std::collections::HashMap<String, Vec<&ScanResult>> =
        std::collections::HashMap::new();

    for result in results {
        let ide_name = result
            .ide_source
            .as_deref()
            .unwrap_or("UNKNOWN IDE")
            .to_string();
        results_by_ide.entry(ide_name).or_default().push(result);
    }

    // Print overall summary header
    println!("\n{}", "🌍 MCP Servers Security Scan Summary".bold());
    println!("{}", "─".repeat(60));

    let total_servers = results.len();
    let mut successful_servers = 0;
    let mut failed_servers = 0;
    let mut total_tools = 0;
    let mut total_resources = 0;
    let mut total_prompts = 0;
    let mut total_warnings = 0;
    let mut servers_with_warnings = 0;

    // Calculate summary statistics
    for result in results {
        match &result.status {
            crate::types::ScanStatus::Success => successful_servers += 1,
            _ => failed_servers += 1,
        }

        total_tools += result.tools.len();
        total_resources += result.resources.len();
        total_prompts += result.prompts.len();

        if let Some(security_issues) = &result.security_issues {
            let server_warnings = security_issues.tool_issues.len()
                + security_issues.prompt_issues.len()
                + security_issues.resource_issues.len();
            if server_warnings > 0 {
                servers_with_warnings += 1;
                total_warnings += server_warnings;
            }
        }
    }

    // Print scan summary statistics
    println!("📊 Scan Summary:");
    println!(
        "  • Servers: {total_servers} total ({successful_servers} ✅ successful, {failed_servers} ❌ failed)"
    );
    println!(
        "  • Resources: {total_tools} tools, {total_resources} resources, {total_prompts} prompts"
    );
    if total_warnings > 0 {
        println!(
            "  • Security: ⚠️  {servers_with_warnings} servers with {total_warnings} total warnings"
        );
    } else {
        println!("  • Security: ✅ All servers passed security checks");
    }

    println!("\n{}", "📋 Results by IDE:".bold());

    // Sort IDE names for consistent output
    let mut ide_names: Vec<&String> = results_by_ide.keys().collect();
    ide_names.sort();

    // Print results grouped by IDE
    for (ide_index, ide_name) in ide_names.iter().enumerate() {
        let ide_results = &results_by_ide[*ide_name];
        let is_last_ide = ide_index == ide_names.len() - 1;
        let ide_prefix = if is_last_ide {
            "└── "
        } else {
            "├── "
        };
        let ide_continuation = if is_last_ide { "    " } else { "│   " };

        println!("\n{}{} {}", ide_prefix, "🏢".bold(), ide_name.bold());

        // Print each server within this IDE
        for (i, result) in ide_results.iter().enumerate() {
            let is_last = i == ide_results.len() - 1;
            let prefix = if is_last { "└── " } else { "├── " };
            let continuation = if is_last { "    " } else { "│   " };

            // Server name and status
            let server_name = result
                .server_info
                .as_ref()
                .map_or_else(|| "Unknown Server".to_string(), |info| info.name.clone());

            let status_emoji = match &result.status {
                crate::types::ScanStatus::Success => "✅",
                crate::types::ScanStatus::Failed(_) => "❌",
                crate::types::ScanStatus::Timeout => "⏱️ ",
                crate::types::ScanStatus::ConnectionError(_) => "🔌",
                crate::types::ScanStatus::AuthenticationError(_) => "🔐",
            };

            println!(
                "{}{}{} {} ({})",
                ide_continuation,
                prefix,
                status_emoji,
                server_name.bold(),
                result.url
            );

            // Always show server-level YARA findings (even if scan failed)
            let server_yara_results: Vec<&crate::types::YaraScanResult> = result
                .yara_results
                .iter()
                .filter(|y| y.target_type == "server")
                .collect();

            if !server_yara_results.is_empty() {
                println!("{ide_continuation}{continuation}🔒 Server Security:");
                for (idx, yara_result) in server_yara_results.iter().enumerate() {
                    let is_last_server_issue = idx == server_yara_results.len() - 1;
                    let branch = if is_last_server_issue {
                        "└─"
                    } else {
                        "├─"
                    };

                    let severity = yara_result
                        .rule_metadata
                        .as_ref()
                        .and_then(|m| m.severity.as_ref())
                        .map(|s| s.as_str())
                        .unwrap_or("MEDIUM");
                    let severity_color = match severity {
                        "CRITICAL" => "🔴 CRITICAL".red(),
                        "HIGH" => "🟠 HIGH".yellow(),
                        "MEDIUM" => "🟡 MEDIUM".blue(),
                        _ => "🟢 LOW".green(),
                    };

                    if !yara_result.context.is_empty() {
                        println!(
                            "{}{}    {} {} (YARA) {} – {}",
                            ide_continuation,
                            continuation,
                            branch,
                            severity_color,
                            yara_result.rule_name,
                            yara_result.context
                        );
                    } else {
                        println!(
                            "{}{}    {} {} (YARA) {}",
                            ide_continuation,
                            continuation,
                            branch,
                            severity_color,
                            yara_result.rule_name
                        );
                    }
                }
            }

            // Show basic stats and detailed results for successful scans
            if matches!(result.status, crate::types::ScanStatus::Success) {
                println!(
                    "{}{}📋 {} tools, {} resources, {} prompts",
                    ide_continuation,
                    continuation,
                    result.tools.len(),
                    result.resources.len(),
                    result.prompts.len()
                );

                // Show individual tool results with security status
                if !result.tools.is_empty() {
                    println!("{ide_continuation}{continuation}🔧 Tools:");
                    if let Some(security_issues) = &result.security_issues {
                        for tool in &result.tools {
                            let tool_issues: Vec<&crate::security::SecurityIssue> = security_issues
                                .tool_issues
                                .iter()
                                .filter(|issue| issue.tool_name.as_ref() == Some(&tool.name))
                                .collect();

                            // Find YARA results for this tool
                            let tool_yara_results: Vec<&crate::types::YaraScanResult> = result
                                .yara_results
                                .iter()
                                .filter(|yara| {
                                    yara.target_type == "tool" && yara.target_name == tool.name
                                })
                                .collect();

                            let total_security_issues = tool_issues.len() + tool_yara_results.len();

                            if total_security_issues == 0 {
                                println!(
                                    "{}{}    ├── {} ✅",
                                    ide_continuation, continuation, tool.name
                                );
                            } else {
                                println!(
                                    "{}{}    ├── {} ⚠️  {} warning{}",
                                    ide_continuation,
                                    continuation,
                                    tool.name.bold(),
                                    total_security_issues,
                                    if total_security_issues == 1 { "" } else { "s" }
                                );

                                // Show LLM analysis issues
                                for issue in &tool_issues {
                                    let severity_color = match issue.severity.as_str() {
                                        "CRITICAL" => "🔴 CRITICAL".red(),
                                        "HIGH" => "🟠 HIGH".yellow(),
                                        "MEDIUM" => "🟡 MEDIUM".blue(),
                                        _ => "🟢 LOW".green(),
                                    };
                                    if let Some(details) = &issue.details {
                                        println!(
                                            "{}{}    │   └── {} (LLM): {} - {}",
                                            ide_continuation,
                                            continuation,
                                            severity_color,
                                            issue.description,
                                            details
                                        );
                                    } else {
                                        println!(
                                            "{}{}    │   └── {} (LLM): {}",
                                            ide_continuation,
                                            continuation,
                                            severity_color,
                                            issue.description
                                        );
                                    }
                                }

                                // Show YARA rule issues
                                for yara_result in &tool_yara_results {
                                    let severity = yara_result
                                        .rule_metadata
                                        .as_ref()
                                        .and_then(|m| m.severity.as_ref())
                                        .map(|s| s.as_str())
                                        .unwrap_or("MEDIUM");
                                    let severity_color = match severity {
                                        "CRITICAL" => "🔴 CRITICAL".red(),
                                        "HIGH" => "🟠 HIGH".yellow(),
                                        "MEDIUM" => "🟡 MEDIUM".blue(),
                                        _ => "🟢 LOW".green(),
                                    };
                                    if !yara_result.context.is_empty() {
                                        println!(
                                            "{}{}    │   └── {} (YARA): {} - {}",
                                            ide_continuation,
                                            continuation,
                                            severity_color,
                                            yara_result.rule_name,
                                            yara_result.context
                                        );
                                    } else {
                                        println!(
                                            "{}{}    │   └── {} (YARA): {}",
                                            ide_continuation,
                                            continuation,
                                            severity_color,
                                            yara_result.rule_name
                                        );
                                    }
                                }
                            }
                        }
                    } else {
                        // No security analysis available
                        for tool in &result.tools {
                            println!(
                                "{}{}    ├── {} ✅",
                                ide_continuation, continuation, tool.name
                            );
                        }
                    }
                }

                // Show resources if any
                if !result.resources.is_empty() {
                    println!("{ide_continuation}{continuation}📄 Resources:");
                    for resource in &result.resources {
                        println!(
                            "{}{}    ├── {} ✅",
                            ide_continuation, continuation, resource.name
                        );
                    }
                }

                // Show prompts if any
                if !result.prompts.is_empty() {
                    println!("{ide_continuation}{continuation}💬 Prompts:");
                    for prompt in &result.prompts {
                        println!(
                            "{}{}    ├── {} ✅",
                            ide_continuation, continuation, prompt.name
                        );
                    }
                }

                // YARA results are now embedded with each tool above
            } else {
                // Show enhanced error details for failed scans
                print_enhanced_error_details(result, ide_continuation, continuation);
            }
        }
    }

    println!(); // Final newline
}

/// Enhanced error details with troubleshooting suggestions
fn print_enhanced_error_details(result: &ScanResult, ide_continuation: &str, continuation: &str) {
    use colored::*;

    match &result.status {
        crate::types::ScanStatus::Failed(err) => {
            println!(
                "{ide_continuation}{continuation}🔴 {} {}",
                "FAILED:".red().bold(),
                result
                    .server_info
                    .as_ref()
                    .map_or("Unknown Server", |info| &info.name)
            );

            // Show concise, specific error details
            if err.contains("GITHUB_PERSONAL_ACCESS_TOKEN not set") {
                println!("{ide_continuation}{continuation}└─ {}: export GITHUB_PERSONAL_ACCESS_TOKEN=\"your_token\"",
                    "Solution".green().bold());
            } else if err.contains("mounts denied") || err.contains("not shared from the host") {
                println!("{ide_continuation}{continuation}└─ {}: Fix volume mount path (e.g., /Users/username:/workspace)", 
                    "Solution".green().bold());
            } else if err.contains("No such file or directory") {
                println!("{ide_continuation}{continuation}└─ {}: Check if Docker image exists: docker pull <image>", 
                    "Solution".green().bold());
            } else if err.contains("connection closed: initialize response") {
                println!("{ide_continuation}{continuation}└─ {}: Server failed to start - check Docker image and environment", 
                    "Error".red());
            } else {
                println!(
                    "{ide_continuation}{continuation}└─ {}: {}",
                    "Error".red(),
                    err.trim()
                );
            }
        }
        crate::types::ScanStatus::ConnectionError(err) => {
            println!(
                "{ide_continuation}{continuation}🔴 {} {}",
                "CONNECTION ERROR:".red().bold(),
                result
                    .server_info
                    .as_ref()
                    .map_or("Unknown Server", |info| &info.name)
            );

            println!(
                "{ide_continuation}{continuation}└─ {}: {}",
                "Error".red(),
                err.trim()
            );
        }
        crate::types::ScanStatus::AuthenticationError(err) => {
            println!(
                "{ide_continuation}{continuation}🔴 {} {}",
                "AUTHENTICATION ERROR:".red().bold(),
                result
                    .server_info
                    .as_ref()
                    .map_or("Unknown Server", |info| &info.name)
            );

            if err.contains("401") || err.contains("Unauthorized") {
                println!(
                    "{ide_continuation}{continuation}└─ {}: Check API key/token and permissions",
                    "Solution".green().bold()
                );
            } else {
                println!(
                    "{ide_continuation}{continuation}└─ {}: {}",
                    "Error".red(),
                    err.trim()
                );
            }
        }
        crate::types::ScanStatus::Timeout => {
            println!(
                "{ide_continuation}{continuation}🟡 {} {}",
                "TIMEOUT:".yellow().bold(),
                result
                    .server_info
                    .as_ref()
                    .map_or("Unknown Server", |info| &info.name)
            );
            println!(
                "{ide_continuation}{continuation}└─ {}: Increase timeout with --timeout <seconds>",
                "Solution".green().bold()
            );
        }
        crate::types::ScanStatus::Success => {}
    }
}

/// JSON format for multiple servers
fn print_multi_server_json(results: &[ScanResult]) {
    let json_output = serde_json::json!({
        "scan_type": "multi_server",
        "total_servers": results.len(),
        "results": results
    });

    match serde_json::to_string_pretty(&json_output) {
        Ok(json) => println!("{json}"),
        Err(e) => eprintln!("Error serializing multi-server results to JSON: {e}"),
    }
}

/// Raw JSON format for multiple servers
fn print_multi_server_raw_json(results: &[ScanResult]) {
    for result in results {
        print_raw_json_result(result);
    }
}

/// Text format for multiple servers
fn print_multi_server_text(results: &[ScanResult]) {
    println!("Multi-Server Scan Results");
    println!("========================");
    println!("Total servers scanned: {}", results.len());
    println!();

    for (i, result) in results.iter().enumerate() {
        println!("Server {}: {}", i + 1, result.url);
        print_text_result(result);
        println!();
    }
}

/// Generate a detailed markdown report from scan results
#[allow(clippy::too_many_lines)]
pub fn generate_markdown_report(results: &[ScanResult]) -> Result<String> {
    use chrono::Utc;
    use std::fmt::Write;

    let timestamp = Utc::now();
    let mut report = String::new();

    // Header
    writeln!(report, "# MCP Security Scan Report")?;
    writeln!(report)?;
    writeln!(
        report,
        "**Generated:** {}",
        timestamp.format("%Y-%m-%d %H:%M:%S UTC")
    )?;
    writeln!(report, "**Scanner:** Ramparts MCP Security Scanner")?;
    writeln!(report)?;

    // Executive Summary
    writeln!(report, "## Executive Summary")?;
    writeln!(report)?;

    let total_servers = results.len();
    let successful_scans = results
        .iter()
        .filter(|r| matches!(r.status, ScanStatus::Success))
        .count();
    let failed_scans = total_servers - successful_scans;

    // Count security issues by severity
    let mut critical_count = 0;
    let mut high_count = 0;
    let mut medium_count = 0;
    let mut low_count = 0;

    for result in results {
        if let Some(ref security_issues) = result.security_issues {
            for issue in &security_issues.tool_issues {
                match issue.severity.as_str() {
                    "CRITICAL" => critical_count += 1,
                    "HIGH" => high_count += 1,
                    "MEDIUM" => medium_count += 1,
                    _ => low_count += 1,
                }
            }
            for issue in &security_issues.prompt_issues {
                match issue.severity.as_str() {
                    "CRITICAL" => critical_count += 1,
                    "HIGH" => high_count += 1,
                    "MEDIUM" => medium_count += 1,
                    _ => low_count += 1,
                }
            }
            for issue in &security_issues.resource_issues {
                match issue.severity.as_str() {
                    "CRITICAL" => critical_count += 1,
                    "HIGH" => high_count += 1,
                    "MEDIUM" => medium_count += 1,
                    _ => low_count += 1,
                }
            }
        }
    }

    writeln!(report, "- **Total Servers Scanned:** {total_servers}")?;
    writeln!(report, "- **Successful Scans:** {successful_scans}")?;
    writeln!(report, "- **Failed Scans:** {failed_scans}")?;
    writeln!(report)?;
    writeln!(report, "### Security Issues Summary")?;
    if critical_count + high_count + medium_count + low_count == 0 {
        writeln!(report, "✅ **No security issues detected**")?;
    } else {
        writeln!(report, "| Severity | Count |")?;
        writeln!(report, "|----------|-------|")?;
        writeln!(report, "| 🔴 **CRITICAL** | {critical_count} |")?;
        writeln!(report, "| 🟠 **HIGH** | {high_count} |")?;
        writeln!(report, "| 🟡 **MEDIUM** | {medium_count} |")?;
        writeln!(report, "| 🟢 **LOW** | {low_count} |")?;
    }
    writeln!(report)?;

    // Detailed Results
    writeln!(report, "## Detailed Scan Results")?;

    for (i, result) in results.iter().enumerate() {
        writeln!(report, "### Server {} - {}", i + 1, result.url)?;

        // Server Info
        if let Some(ref server_info) = result.server_info {
            writeln!(report, "**Server Information:**")?;
            writeln!(report, "- **Name:** {}", server_info.name)?;
            writeln!(report, "- **Version:** {}", server_info.version)?;
            if let Some(ref description) = server_info.description {
                writeln!(report, "- **Description:** {description}")?;
            }
        }

        // Scan Status
        match &result.status {
            ScanStatus::Success => {
                writeln!(report, "**Status:** ✅ Success")?;
                writeln!(report, "**Response Time:** {}ms", result.response_time_ms)?;
            }
            ScanStatus::Failed(error) => {
                writeln!(report, "**Status:** ❌ Failed")?;
                writeln!(report, "**Error:** {error}")?;
                writeln!(report)?;
                continue;
            }
            ScanStatus::Timeout => {
                writeln!(report, "**Status:** ⏰ Timeout")?;
                writeln!(report)?;
                continue;
            }
            ScanStatus::ConnectionError(error) => {
                writeln!(report, "**Status:** ❌ Connection Error")?;
                writeln!(report, "**Error:** {error}")?;
                writeln!(report)?;
                continue;
            }
            ScanStatus::AuthenticationError(error) => {
                writeln!(report, "**Status:** 🔐 Authentication Error")?;
                writeln!(report, "**Error:** {error}")?;
                writeln!(report)?;
                continue;
            }
        }
        writeln!(report)?;

        // Tools - only show tools with security issues
        if let Some(ref security_issues) = result.security_issues {
            let tools_with_issues: Vec<_> = result
                .tools
                .iter()
                .filter(|tool| {
                    security_issues
                        .tool_issues
                        .iter()
                        .any(|issue| issue.tool_name.as_ref() == Some(&tool.name))
                })
                .collect();

            if !tools_with_issues.is_empty() {
                writeln!(
                    report,
                    "#### Tools with Security Issues ({} of {} total)",
                    tools_with_issues.len(),
                    result.tools.len()
                )?;
                writeln!(report)?;

                for tool in tools_with_issues {
                    writeln!(report, "##### {}", tool.name)?;

                    if let Some(ref description) = tool.description {
                        writeln!(report, "{description}")?;
                        writeln!(report)?;
                    }

                    let tool_issues: Vec<_> = security_issues
                        .tool_issues
                        .iter()
                        .filter(|issue| issue.tool_name.as_ref() == Some(&tool.name))
                        .collect();

                    writeln!(report, "**Security Issues:**")?;
                    for issue in tool_issues {
                        write_security_issue_details(&mut report, issue)?;
                    }
                    writeln!(report)?;
                }
            } else if !result.tools.is_empty() {
                writeln!(report, "#### Tools")?;
                writeln!(report)?;
                writeln!(
                    report,
                    "✅ All {} tools passed security checks",
                    result.tools.len()
                )?;
                writeln!(report)?;
            }
        } else if !result.tools.is_empty() {
            writeln!(report, "#### Tools")?;
            writeln!(report)?;
            writeln!(
                report,
                "⚠️ {} tools found but no security analysis available",
                result.tools.len()
            )?;
            writeln!(report)?;
        }

        // Resources - only show resources with security issues
        if let Some(ref security_issues) = result.security_issues {
            let resources_with_issues: Vec<_> = result
                .resources
                .iter()
                .filter(|resource| {
                    security_issues
                        .resource_issues
                        .iter()
                        .any(|issue| issue.resource_uri.as_ref() == Some(&resource.uri))
                })
                .collect();

            if !resources_with_issues.is_empty() {
                writeln!(
                    report,
                    "#### Resources with Security Issues ({} of {} total)",
                    resources_with_issues.len(),
                    result.resources.len()
                )?;
                writeln!(report)?;

                for resource in resources_with_issues {
                    writeln!(report, "##### {}", resource.name)?;
                    writeln!(report, "- **URI:** {}", resource.uri)?;
                    if let Some(ref description) = resource.description {
                        writeln!(report, "- **Description:** {description}")?;
                    }

                    let resource_issues: Vec<_> = security_issues
                        .resource_issues
                        .iter()
                        .filter(|issue| issue.resource_uri.as_ref() == Some(&resource.uri))
                        .collect();

                    writeln!(report)?;
                    writeln!(report, "**Security Issues:**")?;
                    for issue in resource_issues {
                        write_security_issue_details(&mut report, issue)?;
                    }
                    writeln!(report)?;
                }
            } else if !result.resources.is_empty() {
                writeln!(report, "#### Resources")?;
                writeln!(report)?;
                writeln!(
                    report,
                    "✅ All {} resources passed security checks",
                    result.resources.len()
                )?;
                writeln!(report)?;
            }
        } else if !result.resources.is_empty() {
            writeln!(report, "#### Resources")?;
            writeln!(report)?;
            writeln!(
                report,
                "⚠️ {} resources found but no security analysis available",
                result.resources.len()
            )?;
            writeln!(report)?;
        }

        // Prompts - only show prompts with security issues
        if let Some(ref security_issues) = result.security_issues {
            let prompts_with_issues: Vec<_> = result
                .prompts
                .iter()
                .filter(|prompt| {
                    security_issues
                        .prompt_issues
                        .iter()
                        .any(|issue| issue.prompt_name.as_ref() == Some(&prompt.name))
                })
                .collect();

            if !prompts_with_issues.is_empty() {
                writeln!(
                    report,
                    "#### Prompts with Security Issues ({} of {} total)",
                    prompts_with_issues.len(),
                    result.prompts.len()
                )?;
                writeln!(report)?;

                for prompt in prompts_with_issues {
                    writeln!(report, "##### {}", prompt.name)?;
                    if let Some(ref description) = prompt.description {
                        writeln!(report, "{description}")?;
                        writeln!(report)?;
                    }

                    let prompt_issues: Vec<_> = security_issues
                        .prompt_issues
                        .iter()
                        .filter(|issue| issue.prompt_name.as_ref() == Some(&prompt.name))
                        .collect();

                    writeln!(report, "**Security Issues:**")?;
                    for issue in prompt_issues {
                        write_security_issue_details(&mut report, issue)?;
                    }
                    writeln!(report)?;
                }
            } else if !result.prompts.is_empty() {
                writeln!(report, "#### Prompts")?;
                writeln!(report)?;
                writeln!(
                    report,
                    "✅ All {} prompts passed security checks",
                    result.prompts.len()
                )?;
                writeln!(report)?;
            }
        } else if !result.prompts.is_empty() {
            writeln!(report, "#### Prompts")?;
            writeln!(report)?;
            writeln!(
                report,
                "⚠️ {} prompts found but no security analysis available",
                result.prompts.len()
            )?;
            writeln!(report)?;
        }

        // YARA Scan Results - show detailed information for any matches
        if !result.yara_results.is_empty() {
            let match_results: Vec<_> = result
                .yara_results
                .iter()
                .filter(|r| r.target_type != "summary")
                .collect();

            if !match_results.is_empty() {
                writeln!(report, "#### YARA Security Detections")?;
                writeln!(report)?;
                writeln!(
                    report,
                    "**{} security pattern matches detected**",
                    match_results.len()
                )?;
                writeln!(report)?;

                for yara_result in match_results {
                    let severity = yara_result
                        .rule_metadata
                        .as_ref()
                        .and_then(|m| m.severity.as_ref())
                        .map(|s| s.as_str())
                        .unwrap_or("MEDIUM");
                    let severity_emoji = match severity {
                        "CRITICAL" => "🔴",
                        "HIGH" => "🟠",
                        "MEDIUM" => "🟡",
                        _ => "🟢",
                    };

                    writeln!(
                        report,
                        "##### {} **{}:** {}",
                        severity_emoji, severity, yara_result.rule_name
                    )?;

                    // Rule metadata information
                    if let Some(ref metadata) = yara_result.rule_metadata {
                        if let Some(ref description) = metadata.description {
                            writeln!(report, "**Description:** {description}")?;
                        }
                        if let Some(ref author) = metadata.author {
                            writeln!(report, "**Rule Author:** {author}")?;
                        }
                        if let Some(ref confidence) = metadata.confidence {
                            writeln!(
                                report,
                                "**Confidence Level:** {}",
                                confidence.to_uppercase()
                            )?;
                        }
                        if !metadata.tags.is_empty() {
                            writeln!(report, "**Tags:** {}", metadata.tags.join(", "))?;
                        }
                    }

                    // Target information
                    writeln!(
                        report,
                        "**Target:** {} ({})",
                        yara_result.target_name, yara_result.target_type
                    )?;

                    // Matched pattern
                    if let Some(ref matched_text) = yara_result.matched_text {
                        writeln!(report, "**Pattern Match:**")?;
                        writeln!(report, "```")?;
                        writeln!(report, "{matched_text}")?;
                        writeln!(report, "```")?;
                    }

                    // Context information
                    writeln!(report, "**Context:** {}", yara_result.context)?;

                    // Add remediation guidance based on rule name/type
                    let remediation = get_yara_remediation_guidance(&yara_result.rule_name);
                    if !remediation.is_empty() {
                        writeln!(report, "**🔧 Recommended Actions:**")?;
                        for action in remediation {
                            writeln!(report, "- {action}")?;
                        }
                    }

                    writeln!(report)?;
                }
            }
        }

        writeln!(report, "---")?;
        writeln!(report)?;
    }

    // Footer
    writeln!(report, "## Report Information")?;
    writeln!(report)?;
    writeln!(report, "This report was generated by [Ramparts](https://github.com/highflame-ai/ramparts), an MCP security scanner.")?;
    writeln!(report)?;
    writeln!(report, "For more information about security issues and remediation, see the [Ramparts documentation](https://github.com/highflame-ai/ramparts/blob/main/docs/security-features.md).")?;

    Ok(report)
}

/// Write markdown report to file with timestamp
pub fn write_markdown_report(results: &[ScanResult]) -> Result<String> {
    let report_content = generate_markdown_report(results)?;
    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    let filename = format!("scan_{timestamp}.md");

    let mut file = File::create(&filename)
        .map_err(|e| anyhow!("Failed to create report file {}: {}", filename, e))?;

    file.write_all(report_content.as_bytes())
        .map_err(|e| anyhow!("Failed to write report to {}: {}", filename, e))?;

    Ok(filename)
}

// ============================================================================
// THREAT ANALYSIS AND REMEDIATION HELPER FUNCTIONS
// ============================================================================

/// Write detailed security issue information to markdown report
fn write_security_issue_details(
    report: &mut String,
    issue: &crate::security::SecurityIssue,
) -> Result<()> {
    use std::fmt::Write;

    let severity_emoji = match issue.severity.as_str() {
        "CRITICAL" => "🔴",
        "HIGH" => "🟠",
        "MEDIUM" => "🟡",
        _ => "🟢",
    };

    // Main issue description
    writeln!(
        report,
        "- {} **{}:** {}",
        severity_emoji, issue.severity, issue.description
    )
    .map_err(|e| anyhow!("Failed to write to report: {}", e))?;

    // Detailed threat analysis
    if let Some(ref details) = issue.details {
        writeln!(report, "  - **Impact Analysis:** {details}")
            .map_err(|e| anyhow!("Failed to write to report: {}", e))?;
    }

    // Threat categorization and risk assessment
    let (threat_category, business_impact) = get_threat_category_and_impact(&issue.issue_type);
    writeln!(report, "  - **Threat Category:** {threat_category}")
        .map_err(|e| anyhow!("Failed to write to report: {}", e))?;
    writeln!(report, "  - **Business Impact:** {business_impact}")
        .map_err(|e| anyhow!("Failed to write to report: {}", e))?;

    // Exploitability assessment
    let exploitability = get_exploitability_assessment(&issue.issue_type, &issue.severity);
    writeln!(report, "  - **Exploitability:** {exploitability}")
        .map_err(|e| anyhow!("Failed to write to report: {}", e))?;

    // Attack vectors
    let attack_vectors = get_attack_vectors(&issue.issue_type);
    if !attack_vectors.is_empty() {
        writeln!(report, "  - **Potential Attack Vectors:**")
            .map_err(|e| anyhow!("Failed to write to report: {}", e))?;
        for vector in attack_vectors {
            writeln!(report, "    - {vector}")
                .map_err(|e| anyhow!("Failed to write to report: {}", e))?;
        }
    }

    // Comprehensive remediation steps
    let remediation_steps = get_comprehensive_remediation(&issue.issue_type);
    if !remediation_steps.is_empty() {
        writeln!(report, "  - **🔧 Remediation Steps:**")
            .map_err(|e| anyhow!("Failed to write to report: {}", e))?;
        for (i, step) in remediation_steps.iter().enumerate() {
            writeln!(report, "    {}. {step}", i + 1)
                .map_err(|e| anyhow!("Failed to write to report: {}", e))?;
        }
    }

    // Prevention best practices
    let prevention_practices = get_prevention_practices(&issue.issue_type);
    if !prevention_practices.is_empty() {
        writeln!(report, "  - **🛡️ Prevention Best Practices:**")
            .map_err(|e| anyhow!("Failed to write to report: {}", e))?;
        for practice in prevention_practices {
            writeln!(report, "    - {practice}")
                .map_err(|e| anyhow!("Failed to write to report: {}", e))?;
        }
    }

    writeln!(report).map_err(|e| anyhow!("Failed to write to report: {}", e))?; // Add spacing between issues

    Ok(())
}

/// Get threat category and business impact for a security issue type
fn get_threat_category_and_impact(issue_type: &SecurityIssueType) -> (&'static str, &'static str) {
    match issue_type {
        SecurityIssueType::ToolPoisoning => (
            "Malicious Tool Injection",
            "High - Could lead to unauthorized actions, data manipulation, or system compromise"
        ),
        SecurityIssueType::SQLInjection => (
            "Data Injection Attack",
            "Critical - Could result in data breach, data loss, or unauthorized database access"
        ),
        SecurityIssueType::CommandInjection => (
            "System Command Execution",
            "Critical - Could lead to complete system compromise, data theft, or service disruption"
        ),
        SecurityIssueType::PathTraversal => (
            "Directory Traversal Attack",
            "High - Could expose sensitive files, configuration data, or system information"
        ),
        SecurityIssueType::AuthBypass => (
            "Authentication Bypass",
            "Critical - Could allow unauthorized access to protected resources and data"
        ),
        SecurityIssueType::PromptInjection => (
            "AI Model Manipulation",
            "High - Could manipulate AI responses, extract sensitive data, or bypass content filters"
        ),
        SecurityIssueType::Jailbreak => (
            "AI Safety Bypass",
            "High - Could circumvent AI safety measures and generate harmful or inappropriate content"
        ),
        SecurityIssueType::PIILeakage => (
            "Personal Data Exposure",
            "Medium-High - Could violate privacy regulations and expose personal information"
        ),
        SecurityIssueType::SecretsLeakage => (
            "Credential Exposure",
            "High - Could expose API keys, passwords, or other sensitive authentication data"
        ),
    }
}

/// Get exploitability assessment based on issue type and severity
fn get_exploitability_assessment(issue_type: &SecurityIssueType, severity: &str) -> &'static str {
    match (issue_type, severity) {
        (SecurityIssueType::SQLInjection | SecurityIssueType::CommandInjection, "CRITICAL") => {
            "Very High - Easily exploitable with readily available tools and techniques"
        }
        (SecurityIssueType::AuthBypass, "CRITICAL") => {
            "Very High - Direct access bypass with minimal technical requirements"
        }
        (SecurityIssueType::PathTraversal, "HIGH") => {
            "High - Common attack patterns with well-documented exploitation methods"
        }
        (SecurityIssueType::ToolPoisoning, "CRITICAL" | "HIGH") => {
            "High - Requires social engineering or supply chain compromise"
        }
        (SecurityIssueType::PromptInjection | SecurityIssueType::Jailbreak, "HIGH") => {
            "Medium-High - Requires understanding of AI model behavior and prompt crafting"
        }
        (SecurityIssueType::SecretsLeakage, "HIGH") => {
            "Medium - Depends on secret exposure method and access controls"
        }
        (SecurityIssueType::PIILeakage, "MEDIUM") => {
            "Medium - Requires access to data processing functions"
        }
        _ => "Medium - Exploitation complexity varies based on implementation details",
    }
}

/// Get potential attack vectors for a security issue type
fn get_attack_vectors(issue_type: &SecurityIssueType) -> Vec<&'static str> {
    match issue_type {
        SecurityIssueType::ToolPoisoning => vec![
            "Malicious tool registration with legitimate-sounding names",
            "Supply chain attacks through compromised dependencies",
            "Social engineering to trick users into installing malicious tools",
        ],
        SecurityIssueType::SQLInjection => vec![
            "Malicious SQL payloads in user input fields",
            "Blind SQL injection through timing attacks",
            "Union-based injection to extract data",
            "Error-based injection exploiting database error messages",
        ],
        SecurityIssueType::CommandInjection => vec![
            "Shell metacharacters in user input",
            "Command chaining with semicolons or pipes",
            "Environment variable manipulation",
            "File upload with executable content",
        ],
        SecurityIssueType::PathTraversal => vec![
            "Directory traversal sequences (../, ....//)",
            "Absolute path manipulation",
            "URL encoding bypass techniques",
            "Symbolic link exploitation",
        ],
        SecurityIssueType::AuthBypass => vec![
            "Missing authentication checks on sensitive endpoints",
            "Token manipulation or forgery",
            "Session fixation or hijacking",
            "Privilege escalation through parameter tampering",
        ],
        SecurityIssueType::PromptInjection => vec![
            "Instruction injection to override system prompts",
            "Context manipulation to change AI behavior",
            "Multi-turn conversation exploitation",
            "Payload injection in user-provided data",
        ],
        SecurityIssueType::Jailbreak => vec![
            "Roleplay scenarios to bypass content filters",
            "Hypothetical question framing",
            "Character encoding or obfuscation techniques",
            "Indirect instruction through creative prompting",
        ],
        SecurityIssueType::PIILeakage => vec![
            "Data extraction through legitimate API calls",
            "Information disclosure in error messages",
            "Metadata leakage in responses",
            "Cross-user data contamination",
        ],
        SecurityIssueType::SecretsLeakage => vec![
            "Hardcoded credentials in source code",
            "Environment variable exposure",
            "Configuration file access",
            "Log file credential leakage",
        ],
    }
}

/// Get comprehensive remediation steps for a security issue type
fn get_comprehensive_remediation(issue_type: &SecurityIssueType) -> Vec<&'static str> {
    match issue_type {
        SecurityIssueType::ToolPoisoning => vec![
            "Implement tool verification and digital signatures",
            "Use allowlists for approved tools and sources",
            "Add user confirmation prompts for high-risk operations",
            "Monitor tool behavior and implement anomaly detection",
            "Regular security audits of installed tools",
        ],
        SecurityIssueType::SQLInjection => vec![
            "Use parameterized queries and prepared statements",
            "Implement input validation and sanitization",
            "Apply principle of least privilege to database accounts",
            "Enable database query logging and monitoring",
            "Use stored procedures with proper parameter handling",
            "Implement Web Application Firewall (WAF) rules",
        ],
        SecurityIssueType::CommandInjection => vec![
            "Avoid system command execution where possible",
            "Use safe APIs instead of shell commands",
            "Implement strict input validation and allowlists",
            "Sanitize all user input before command execution",
            "Run processes with minimal required privileges",
            "Use containerization to limit system access",
        ],
        SecurityIssueType::PathTraversal => vec![
            "Validate and sanitize all file path inputs",
            "Use allowlists for permitted file locations",
            "Implement proper access controls and file permissions",
            "Use absolute paths and avoid relative path construction",
            "Apply input validation to reject traversal sequences",
            "Implement file access logging and monitoring",
        ],
        SecurityIssueType::AuthBypass => vec![
            "Implement proper authentication checks on all endpoints",
            "Use secure session management practices",
            "Apply authorization controls consistently",
            "Implement multi-factor authentication where appropriate",
            "Regular security testing of authentication mechanisms",
            "Use established authentication frameworks",
        ],
        SecurityIssueType::PromptInjection => vec![
            "Implement input validation and sanitization",
            "Use system message protection techniques",
            "Apply content filtering and prompt analysis",
            "Implement context isolation between user inputs",
            "Monitor for injection attempt patterns",
            "Use structured input formats where possible",
        ],
        SecurityIssueType::Jailbreak => vec![
            "Implement robust content filtering systems",
            "Use multiple layers of safety checks",
            "Apply context-aware response filtering",
            "Monitor for jailbreak attempt patterns",
            "Implement response review and approval workflows",
            "Regular updates to safety detection mechanisms",
        ],
        SecurityIssueType::PIILeakage => vec![
            "Implement data classification and handling policies",
            "Use data anonymization and pseudonymization techniques",
            "Apply access controls based on data sensitivity",
            "Implement data loss prevention (DLP) controls",
            "Regular privacy impact assessments",
            "Ensure compliance with data protection regulations",
        ],
        SecurityIssueType::SecretsLeakage => vec![
            "Use secure credential management systems",
            "Implement environment-based configuration",
            "Apply secret scanning tools to code repositories",
            "Use encrypted storage for sensitive configuration",
            "Implement credential rotation policies",
            "Monitor for exposed secrets in logs and outputs",
        ],
    }
}

/// Get prevention best practices for a security issue type
fn get_prevention_practices(issue_type: &SecurityIssueType) -> Vec<&'static str> {
    match issue_type {
        SecurityIssueType::ToolPoisoning => vec![
            "Establish a secure tool development lifecycle",
            "Implement code review processes for all tools",
            "Use dependency scanning and vulnerability assessment",
            "Maintain an inventory of approved tools and versions",
            "Provide security training for tool developers",
        ],
        SecurityIssueType::SQLInjection => vec![
            "Follow secure coding practices for database interactions",
            "Regular security code reviews focusing on data access",
            "Use static analysis tools to detect SQL injection vulnerabilities",
            "Implement automated security testing in CI/CD pipelines",
            "Keep database systems and drivers updated",
        ],
        SecurityIssueType::CommandInjection => vec![
            "Design applications to minimize system command usage",
            "Use security-focused development frameworks",
            "Implement secure coding standards and guidelines",
            "Regular penetration testing and security assessments",
            "Security awareness training for development teams",
        ],
        SecurityIssueType::PathTraversal => vec![
            "Design file handling with security-first principles",
            "Use established libraries for file operations",
            "Implement defense-in-depth strategies",
            "Regular security architecture reviews",
            "Automated security testing for file handling functions",
        ],
        SecurityIssueType::AuthBypass => vec![
            "Follow security-by-design principles",
            "Implement consistent authentication patterns",
            "Use centralized authentication and authorization services",
            "Regular security audits and penetration testing",
            "Security training focused on authentication best practices",
        ],
        SecurityIssueType::PromptInjection => vec![
            "Design AI systems with security considerations",
            "Implement prompt security testing in development",
            "Use AI safety frameworks and guidelines",
            "Regular red team exercises for AI systems",
            "Stay updated on AI security research and best practices",
        ],
        SecurityIssueType::Jailbreak => vec![
            "Implement comprehensive AI safety measures",
            "Use multiple independent safety checking systems",
            "Regular evaluation of AI model behavior",
            "Implement human oversight for sensitive operations",
            "Stay current with AI safety research and techniques",
        ],
        SecurityIssueType::PIILeakage => vec![
            "Implement privacy-by-design principles",
            "Regular privacy training for development teams",
            "Use data minimization strategies",
            "Implement privacy-preserving technologies",
            "Regular compliance audits and assessments",
        ],
        SecurityIssueType::SecretsLeakage => vec![
            "Implement secure development practices",
            "Use automated secret scanning in development workflows",
            "Establish clear policies for credential management",
            "Regular security awareness training",
            "Implement secure configuration management practices",
        ],
    }
}

/// Get remediation guidance for YARA rule detections
fn get_yara_remediation_guidance(rule_name: &str) -> Vec<&'static str> {
    match rule_name {
        "EnvironmentVariableLeakage" | "SecretsLeakage" => vec![
            "Review the detected code for hardcoded credentials or secrets",
            "Use environment variables or secure credential management systems",
            "Implement secret scanning in your CI/CD pipeline",
            "Rotate any exposed credentials immediately",
        ],
        "PathTraversalVulnerability" => vec![
            "Validate and sanitize all file path inputs",
            "Use allowlists for permitted file locations",
            "Implement proper access controls on file operations",
            "Consider using absolute paths instead of relative paths",
        ],
        "SQLInjectionPattern" => vec![
            "Replace dynamic SQL with parameterized queries",
            "Implement input validation and sanitization",
            "Use prepared statements for database operations",
            "Apply principle of least privilege to database accounts",
        ],
        "CommandInjectionPattern" => vec![
            "Avoid executing system commands with user input",
            "Use safe APIs instead of shell command execution",
            "Implement strict input validation with allowlists",
            "Run processes with minimal required privileges",
        ],
        "CrossOriginContamination" => vec![
            "Review cross-origin resource sharing (CORS) policies",
            "Implement proper origin validation",
            "Use secure headers to prevent cross-origin attacks",
            "Audit and restrict cross-domain requests",
        ],
        "AIAgentInjection" => vec![
            "Implement input sanitization for AI prompts",
            "Use structured input validation",
            "Apply content filtering and safety checks",
            "Monitor for prompt injection attempt patterns",
        ],
        _ => vec![
            "Review the detected pattern for security implications",
            "Implement appropriate input validation and sanitization",
            "Follow security best practices for the identified vulnerability type",
            "Consider additional security testing and code review",
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::{error_utils, format_status, Timer};
    use anyhow::anyhow;

    #[test]
    fn test_timer_functionality() {
        let timer = Timer::start();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let elapsed = timer.elapsed_ms();

        assert!(elapsed >= 10);
        println!("Timer elapsed: {elapsed}ms");
    }

    #[test]
    fn test_error_utils() {
        // Test format_error
        let error_msg = error_utils::format_error("Test operation", "Something went wrong");
        assert_eq!(error_msg, "Test operation failed: Something went wrong");

        // Test wrap_error with success
        let result: Result<i32, anyhow::Error> = Ok(42);
        let wrapped = error_utils::wrap_error(result, "Test context");
        assert!(wrapped.is_ok());
        assert_eq!(wrapped.unwrap(), 42);

        // Test wrap_error with failure
        let result: Result<i32, anyhow::Error> = Err(anyhow!("Original error"));
        let wrapped = error_utils::wrap_error(result, "Test context");
        assert!(wrapped.is_err());
        let error_msg = wrapped.unwrap_err().to_string();
        assert!(error_msg.contains("Test context"));
        assert!(error_msg.contains("Original error"));
    }

    // TODO: Add test for track_performance when async closure type inference is resolved

    #[test]
    fn test_format_status() {
        use crate::types::ScanStatus;

        let success = format_status(&ScanStatus::Success);
        assert!(success.contains("SUCCESS"));

        let failed = format_status(&ScanStatus::Failed("Test error".to_string()));
        assert!(failed.contains("FAILED"));
        assert!(failed.contains("Test error"));

        let timeout = format_status(&ScanStatus::Timeout);
        assert!(timeout.contains("TIMEOUT"));

        let connection_error = format_status(&ScanStatus::ConnectionError(
            "Connection failed".to_string(),
        ));
        assert!(connection_error.contains("CONNECTION ERROR"));
        assert!(connection_error.contains("Connection failed"));

        let auth_error = format_status(&ScanStatus::AuthenticationError("Auth failed".to_string()));
        assert!(auth_error.contains("AUTHENTICATION ERROR"));
        assert!(auth_error.contains("Auth failed"));
    }
}
