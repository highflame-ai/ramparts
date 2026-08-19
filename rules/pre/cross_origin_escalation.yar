/*
 * Cross-Origin Escalation Detection Rule
 * 
 * This rule detects Cross-Origin Escalation vulnerabilities where an LLM agent
 * accesses tools hosted on multiple origins (domains), and one of those origins
 * can inject, override, or hijack context from another.
 * 
 * The rule focuses on detecting multiple different domains/origins within
 * tool and resource configurations, which is the primary indicator of
 * potential cross-origin escalation attacks.
 */

rule CrossOriginEscalation
{
    meta:
        name = "Cross-Origin Escalation Detection"
        author = "Ramparts Security Team"
        date = "2025-01-29"
        version = "1.0"
        description = "Detects multiple domains/origins in MCP tool configurations that could lead to cross-origin escalation attacks"
        severity = "HIGH"
        category = "cross-origin,escalation,security,multi-domain"
        confidence = "HIGH"
        
    strings:
        // Multiple HTTP/HTTPS URLs with different domains
        $multi_domain_1 = /https?:\/\/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}).*https?:\/\/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/
        
        // Mixed localhost/IP and external domain patterns
        $mixed_local_remote_1 = /https?:\/\/(localhost|127\.0\.0\.1|0\.0\.0\.0).*https?:\/\/[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/
        $mixed_local_remote_2 = /https?:\/\/[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}.*https?:\/\/(localhost|127\.0\.0\.1|0\.0\.0\.0)/
        
        // Different port numbers on same host (potential port-based escalation)
        $port_escalation = /https?:\/\/[a-zA-Z0-9.-]+:\d+.*https?:\/\/[a-zA-Z0-9.-]+:\d+/
        
        // Mixed secure/insecure schemes
        $mixed_schemes_1 = /https:\/\/.*http:\/\//
        $mixed_schemes_2 = /http:\/\/.*https:\/\//
        $mixed_ws_schemes = /wss:\/\/.*ws:\/\//
        
        // Subdomain variations that could indicate takeover
        $subdomain_variations = /https?:\/\/[a-zA-Z0-9-]+\.[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}.*https?:\/\/[a-zA-Z0-9-]+\.[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/
        
        // API endpoint variations across domains
        $api_multi_domain = /\/api\/.*https?:\/\/[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}.*\/api\//
        
        // Proxy or redirect patterns
        $proxy_patterns = /(proxy|redirect|forward).*https?:\/\/.*https?:\/\//i
        
        // URL parameters containing other URLs (potential injection)
        $url_in_params = /[?&](url|redirect|forward|proxy)=https?:\/\/.*https?:\/\//i
        
        // Common domain patterns that suggest different services
        $service_domains = /(api\.|auth\.|admin\.|secure\.).*\.(com|net|org|io).*\.(com|net|org|io)/i
        
        // Tool-specific patterns indicating multi-origin access
        $tool_multi_origin = /"(baseUrl|endpoint|url|host)".*https?:\/\/.*"(baseUrl|endpoint|url|host)".*https?:\/\//i
        
        // Configuration arrays with multiple URLs
        $url_array = /\[.*"https?:\/\/[^"]*".*,.*"https?:\/\/[^"]*".*\]/
        
        // JSON with multiple origin fields
        $json_multi_origin = /"origin".*:.*"https?:\/\/.*"origin".*:.*"https?:\/\//i
        
        // Legitimate patterns to reduce false positives
        // Specification and schema URLs are identifiers, not endpoints. Every
        // JSON Schema carries a `$schema` declaration pointing at
        // json-schema.org, so a schema plus a single example URL satisfied
        // `$multi_domain_1` and `$mixed_schemes_*`. That flagged
        // `gzip-file-as-resource` on the reference server-everything
        // implementation, whose schema is entirely ordinary.
        $excl_schema_url = /https?:\/\/(json-schema\.org|www\.w3\.org|schema\.org|spec\.openapis\.org|docs\.oasis-open\.org|modelcontextprotocol\.io)\//i

        $legitimate_cdn = /(cdn\.|static\.|assets\.|media\.)/i
        $legitimate_backup = /(backup|fallback|mirror)/i
        $legitimate_loadbalancer = /(lb\.|loadbalancer|ha\.)/i
        
    condition:
        // Primary detection: Multiple different domains.
        // Excludes specification/schema URLs — see $excl_schema_url.
        ($multi_domain_1 and not $excl_schema_url
            and not ($legitimate_cdn or $legitimate_backup or $legitimate_loadbalancer)) or
        
        // Mixed local/remote origins (high risk)
        ($mixed_local_remote_1 or $mixed_local_remote_2) or
        
        // Port-based escalation
        $port_escalation or
        
        // Mixed security schemes (HTTP/HTTPS mixing). A plaintext
        // json-schema.org identifier alongside an https example URL is not a
        // downgrade, so the schema exclusion applies here too.
        (($mixed_schemes_1 or $mixed_schemes_2 or $mixed_ws_schemes) and not $excl_schema_url) or
        
        // Subdomain variations (potential takeover)
        $subdomain_variations or
        
        // API endpoints across domains
        $api_multi_domain or
        
        // Proxy/redirect patterns
        $proxy_patterns or
        
        // URL injection in parameters
        $url_in_params or
        
        // Service domain mixing
        $service_domains or
        
        // Tool configuration with multiple origins
        $tool_multi_origin or
        
        // URL arrays
        $url_array or
        
        // JSON multi-origin
        $json_multi_origin
}