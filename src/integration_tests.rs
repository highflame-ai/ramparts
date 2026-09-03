#[cfg(test)]
mod tests {
    use crate::core::{MCPScannerCore, RegisterServerRequest};
    use serial_test::serial;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_server_registration_and_listing() {
        let _ = tracing_subscriber::fmt::try_init();

        let core = MCPScannerCore::new().expect("Failed to create core");

        // Test server registration
        let request = RegisterServerRequest {
            url: "https://api.example.com/mcp/".to_string(),
            auth_headers: Some({
                let mut headers = HashMap::new();
                headers.insert("Authorization".to_string(), "Bearer test-token".to_string());
                headers
            }),
            timeout: Some(30),
        };

        let response = core.register_server(request).await;
        assert!(
            !response.success,
            "Server registration should be deprecated"
        );
        assert!(response.message.contains("deprecated"));

        // Test listing registered servers (should also be deprecated)
        let list_response = core.list_registered_servers().await;
        assert!(
            !list_response.success,
            "Listing servers should be deprecated"
        );
        assert_eq!(list_response.count, 0, "Should have 0 registered servers");

        // Test unregistering server (should also be deprecated)
        let unregister_response = core.unregister_server("https://api.example.com/mcp/").await;
        assert!(
            !unregister_response.success,
            "Server unregistration should be deprecated"
        );
    }

    #[tokio::test]
    async fn test_refresh_tools_handles_server_failure() {
        let _ = tracing_subscriber::fmt::try_init();

        let core = MCPScannerCore::new().expect("Failed to create core");

        // Test with non-existent server
        let request = crate::core::RefreshToolsRequest {
            urls: vec!["http://localhost:99999".to_string()],
            auth_headers: None,
            timeout: Some(1),
        };

        let response = core.refresh_tools(request).await;

        // Verify deprecation behavior
        assert!(!response.success, "Should be deprecated");
        assert_eq!(response.total, 0);
        assert_eq!(response.successful, 0);
        assert_eq!(response.failed, 0);
        assert_eq!(response.results.len(), 0);
    }

    #[tokio::test]
    async fn test_config_persistence() {
        let _ = tracing_subscriber::fmt::try_init();

        let core = MCPScannerCore::new().expect("Failed to create core");

        // Test that registration is deprecated
        let request = RegisterServerRequest {
            url: "https://api.github.com/mcp/".to_string(),
            auth_headers: None,
            timeout: Some(30),
        };

        let response = core.register_server(request).await;
        assert!(!response.success, "Registration should be deprecated");
        assert!(response.message.contains("deprecated"));

        // Test that listing is deprecated
        let list_response = core.list_registered_servers().await;
        assert!(!list_response.success, "Listing should be deprecated");
        assert_eq!(list_response.count, 0, "Should have 0 servers");

        // Test that unregistration is deprecated
        let unregister_response = core.unregister_server("https://api.github.com/mcp/").await;
        assert!(
            !unregister_response.success,
            "Unregistration should be deprecated"
        );
    }

    #[tokio::test]
    #[serial(env_api_keys)]
    async fn test_environment_variable_mapping() {
        let _ = tracing_subscriber::fmt::try_init();

        // Set environment variable
        std::env::set_var("LLM_API_KEY", "test-llm-key");

        let core = MCPScannerCore::new().expect("Failed to create core");

        // Register server without explicit auth headers
        let request = RegisterServerRequest {
            url: "https://api.example.com/mcp/".to_string(),
            auth_headers: None, // No explicit auth headers
            timeout: Some(30),
        };

        let response = core.register_server(request).await;
        assert!(
            !response.success,
            "Server registration should be deprecated"
        );
        assert!(response.message.contains("deprecated"));

        // Clean up environment variable
        std::env::remove_var("LLM_API_KEY");
    }

    #[tokio::test]
    #[serial(env_api_keys)]
    async fn test_env_mapping_function() {
        // Clean up any existing env vars first
        std::env::remove_var("LLM_API_KEY");
        std::env::remove_var("X_API_KEY");
        std::env::remove_var("API_KEY");

        // Test the apply_env_mappings function directly
        std::env::set_var("LLM_API_KEY", "test-key-123");
        std::env::set_var("X_API_KEY", "x-api-key-456");

        let mut headers = HashMap::new();
        headers.insert("Custom-Header".to_string(), "custom-value".to_string());

        let result = crate::config::apply_env_mappings(headers);

        // Should have original header plus environment mappings
        assert_eq!(
            result.get("Custom-Header"),
            Some(&"custom-value".to_string())
        );
        assert_eq!(
            result.get("Authorization"),
            Some(&"Bearer test-key-123".to_string())
        );
        assert_eq!(result.get("X-API-Key"), Some(&"x-api-key-456".to_string()));

        // Clean up
        std::env::remove_var("LLM_API_KEY");
        std::env::remove_var("X_API_KEY");
    }

    #[tokio::test]
    #[serial(env_api_keys)]
    async fn test_env_mapping_respects_existing_headers() {
        // Clean up any existing env vars first
        std::env::remove_var("LLM_API_KEY");
        std::env::remove_var("X_API_KEY");
        std::env::remove_var("API_KEY");

        // Test that existing headers are not overridden
        std::env::set_var("LLM_API_KEY", "env-key");

        let mut headers = HashMap::new();
        headers.insert(
            "Authorization".to_string(),
            "Bearer existing-key".to_string(),
        );

        let result = crate::config::apply_env_mappings(headers);

        // Should keep existing Authorization header, not override with env var
        assert_eq!(
            result.get("Authorization"),
            Some(&"Bearer existing-key".to_string())
        );

        // Clean up
        std::env::remove_var("LLM_API_KEY");
    }

    #[tokio::test]
    async fn test_enhanced_scan_api_with_change_detection() {
        let _ = tracing_subscriber::fmt::try_init();

        let core = MCPScannerCore::new().expect("Failed to create core");

        // Test enhanced scan API with change detection
        let request = crate::core::ScanRequest {
            url: "https://api.example.com/mcp/".to_string(),
            timeout: Some(30),
            http_timeout: Some(30),
            detailed: Some(false),
            format: Some("json".to_string()),
            auth_headers: None,
            return_prompts: Some(true), // Return prompts to avoid LLM calls
            reference_url: Some("https://api.example.com/mcp/".to_string()),
        };

        let response = core.scan(request).await;

        // Verify response structure includes change detection fields
        // These fields should exist regardless of their values
        let _ = response.success; // Field exists
        let _ = response.refresh_happened; // Field exists
        let _ = response.changes_detected; // Field exists
        let _ = response.scan_skipped; // Field exists
        let _ = response.cache_hit; // Field exists

        // Change summary might be None if no changes or if servers are unreachable
        // This is expected behavior
    }
}
