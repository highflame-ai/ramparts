# Ramparts v0.7.0 Release Notes

## 🎉 Major Improvements

### Consolidated Security Output Format
- **Enhanced Console Output**: Security results now show both LLM analysis and YARA scan results embedded directly with each tool, resource, and prompt
- **Unified JSON Structure**: Security scan results are embedded within each tool/resource/prompt object for better programmatic processing
- **Clear Source Attribution**: Results are clearly marked as `(LLM)` or `(YARA)` in console output, and `llm_analysis` vs `yara_scan` in JSON
- **Improved Formatting**: Security issue details are displayed inline with proper tree structure formatting for better readability

**Before v0.7.0:**
```
Tools:
├── enhanced_calculate ⚠️  1 warning

YARA: 1 security issues detected
```

**New in v0.7.0:**
```
Tools:
├── enhanced_calculate ⚠️  2 warnings
│   └── 🟠 HIGH (LLM): Hidden command accesses system secrets - The tool includes hidden functionality that can access sensitive system data
│   └── 🔴 CRITICAL (YARA): CommandInjection - Command injection vulnerability detected in tool
```

### Performance Enhancements
- **Parallel Server Scanning**: The `scan-config` command now processes multiple MCP servers concurrently, dramatically reducing scan times
- **Improved Session Management**: Enhanced session handling prevents connection bottlenecks

### Reliability Improvements  
- **Session Cleanup**: Fixed session deletion errors by implementing proper MCP session cleanup after each scan
- **Enhanced Error Handling**: More informative error messages with actionable guidance
- **Resource Management**: Automatic cleanup prevents memory leaks and connection issues

## 🔧 Technical Changes

### Session Management
- Added `cleanup_session()` and `cleanup_all_sessions()` methods to `McpClient`
- Implemented `Drop` trait for `MCPScanner` to ensure proper cleanup
- Made `McpClient` cloneable to support parallel processing
- Sessions are now properly terminated after each scan operation

### Output Format Changes
- Security results embedded directly in tool/resource/prompt JSON objects
- Added `security_scan_results` array to each scanned item
- Consolidated separate security and YARA sections into unified format
- Enhanced console tree view with source attribution

### Performance Optimizations
- Parallel scanning using `tokio::spawn` and `futures::join_all`
- Each server scanned in its own task for maximum concurrency
- Proper error handling and result aggregation across parallel tasks

## 📚 Documentation Updates

### Updated Documentation
- **features.md**: Added consolidated output format examples and session management details
- **cli.md**: Updated output format documentation with v0.7.0 examples
- **troubleshooting.md**: Added session management troubleshooting section
- **latest-formats.md**: Updated version compatibility and new features

### New Examples
- Console output examples showing consolidated security results
- JSON structure examples with embedded security data
- Performance tuning guidance for parallel scanning

## 🚀 Migration Guide

### For Users
- **No breaking changes**: Existing commands work exactly the same
- **Enhanced output**: You'll see more detailed and organized security results
- **Faster scanning**: Multiple servers are now processed in parallel
- **Cleaner logs**: No more session deletion error messages

### For Integrators
- **JSON structure enhanced**: Security results are now embedded in each tool/resource/prompt
- **New fields**: Look for `security_scan_results` array in tool objects
- **Backward compatibility**: Old JSON fields are still present for compatibility

### Example JSON Structure Change

**Before v0.7.0:**
```diff
{
  "url": "http://localhost:8010/mcp",
  "status": "Success",
  "tools": [
    {
      "name": "authenticate",
      "description": "Authenticate a user with username and password...",
      "input_schema": {...}
-     // NO security information embedded here
    }
  ],
  "resources": [...],
  "prompts": [...],
  
- // SEPARATE SECTIONS (Hard to correlate)
- "security_issues": {
-   "tool_issues": [
-     {
-       "tool_name": "get_user_profile",
-       "severity": "HIGH",
-       "description": "Admin access requires hidden actions"
-     }
-   ],
-   "resource_issues": [],
-   "prompt_issues": []
- },
- "yara_results": [
-   {
-     "target_name": "authenticate",
-     "target_type": "tool", 
-     "rule_name": "EnvironmentVariableLeakage",
-     "severity": "HIGH"
-   }
- ]
}
```

**New in v0.7.0:**
```diff
{
+ "url": "http://localhost:8010/mcp",
+ "status": "Success",
  "tools": [
    {
-     "name": "tool_name",
+     "name": "authenticate",
+     "description": "Authenticate a user with username and password...",
+     "input_schema": {...},
+     
+     // ✅ NEW: LLM Analysis embedded
+     "llm_analysis": "Security analysis of the tool...",
+     
+     // ✅ NEW: Security results embedded within tool
+     "security_scan_results": [
+       {
+         "scan_type": "llm_analysis",
+         "issue_type": "ToolPoisoning",
+         "severity": "HIGH",
+         "message": "Security issue detected",
+         "description": "Security issue description",
+         "details": "Additional context and details"
+       },
+       {
+         "scan_type": "yara_rules",
+         "rule_name": "RuleName",
+         "rule_file": "rule_category",
+         "context": "Pattern context",
+         "rule_metadata": {
+           "severity": "CRITICAL",
+           "description": "Rule description"
+         }
+       }
+     ]
    }
  ],
+ "resources": [...],
+ "prompts": [...],
+ 
+ // ✅ NEW: Comprehensive top-level security issues section
+ "security_issues": {
+   "issues": [
+     {
+       "scan_type": "llm_analysis",
+       "target_type": "tool",
+       "target_name": "tool_name",
+       "issue_type": "ToolPoisoning",
+       "severity": "HIGH",
+       "message": "Security issue detected",
+       "description": "Security issue description",
+       "details": "Additional context and details"
+     },
+     {
+       "scan_type": "yara_rules",
+       "target_type": "tool",
+       "target_name": "tool_name",
+       "rule_name": "RuleName",
+       "rule_file": "rule_category",
+       "context": "Pattern context",
+       "rule_metadata": {
+         "severity": "CRITICAL",
+         "description": "Rule description"
+       }
+     }
+   ],
+   "llm_issues_count": 1,
+   "yara_issues_count": 1,
+   "total_issues_count": 2
+ },
+ 
+ // ✅ NEW: Consolidated security summary
+ "security_scan_summary": {
+   "llm_scan_issues": 1,
+   "yara_scan_issues": 1,
+   "tool_issues": 1,
+   "resource_issues": 0,
+   "prompt_issues": 0,
+   "total_security_issues": 2
+ }
}
```

## 🐛 Bug Fixes
- Fixed session deletion errors that appeared during MCP server cleanup
- Resolved connection hanging issues with stateful MCP servers
- Improved error messages for failed server connections
- Fixed resource management issues in concurrent scanning

## 🎯 What's Next
- Enhanced YARA rule coverage
- Additional output format options
- Performance optimizations for large-scale deployments
- Extended IDE configuration support

---

**Full Changelog**: https://github.com/highflame-ai/ramparts/compare/v0.6.9...v0.7.0
**Download**: https://github.com/highflame-ai/ramparts/releases/tag/v0.7.0
