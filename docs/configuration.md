# Configuration Reference

This document provides detailed information about configuring Ramparts through the `ramparts.yaml` configuration file.

## Getting Started

### Initialize Configuration

Create a custom configuration file with default settings:

```bash
ramparts init-config
```

This creates a `ramparts.yaml` file in the current directory with all available configuration options.

### Configuration File Locations

Ramparts looks for configuration files in the following order:

1. `--config` command line argument
2. `RAMPARTS_CONFIG` environment variable  
3. `./ramparts.yaml` (current directory)
4. `~/.config/ramparts/config.yaml`
5. `/etc/ramparts/config.yaml`

## Complete Configuration Reference

```yaml
# Ramparts Configuration File
# All values shown are defaults

# LLM Configuration for AI-powered security analysis
llm:
  provider: "${LLM_PROVIDER:-openai}"                    # LLM provider: "openai"
  model: "${LLM_MODEL:-gpt-4o}"                         # Model name
  base_url: "${LLM_URL:-https://api.openai.com/v1/chat/completions}" # Complete API endpoint URL
  api_key: "${LLM_API_KEY:-}"                           # API key (use environment variable LLM_API_KEY)
  timeout: 30                          # Request timeout in seconds
  max_tokens: 4000                     # Maximum tokens in response
  temperature: 0.1                     # Temperature for randomness (0.0-1.0)

# Scanner Configuration
scanner:
  http_timeout: 30                     # HTTP request timeout in seconds
  scan_timeout: 60                     # Total scan timeout in seconds
  detailed: false                      # Enable detailed analysis by default
  format: "table"                      # Default output format: "table", "json", "text", "raw"
  parallel: true                       # Enable parallel processing
  max_retries: 3                       # Maximum retry attempts
  retry_delay_ms: 1000                 # Delay between retries in milliseconds
  llm_batch_size: 10                   # Number of tools to analyze in one LLM request
  enable_yara: true                    # Enable/disable YARA-X scanning

# Security Analysis Configuration
security:
  enabled: true                        # Enable security analysis
  min_severity: "low"                  # Minimum severity to report: "low", "medium", "high", "critical"
  
  # Security check categories
  checks:
    tool_poisoning: true               # Detect malicious or destructive tools
    secrets_leakage: true              # Detect secret/credential exposure
    sql_injection: true                # Detect SQL injection vulnerabilities
    command_injection: true            # Detect command injection vulnerabilities
    path_traversal: true               # Detect path traversal vulnerabilities
    auth_bypass: true                  # Detect authentication bypass issues
    cross_origin_escalation: true      # Detect cross-origin escalation attacks
    prompt_injection: true             # Detect prompt injection vulnerabilities
    pii_leakage: true                  # Detect PII leakage
    jailbreak: true                    # Detect jailbreak attempts

# Logging Configuration
logging:
  level: "info"                        # Log level: "error", "warn", "info", "debug", "trace"
  colored: true                        # Enable colored output
  timestamps: true                     # Include timestamps in logs

# Performance Monitoring
performance:
  tracking: true                       # Enable performance tracking
  slow_threshold_ms: 5000              # Threshold for slow operation warnings
```

## Configuration Sections

### LLM Configuration

The `llm` section configures AI-powered security analysis:

```yaml
llm:
  provider: "${LLM_PROVIDER:-openai}"
  model: "${LLM_MODEL:-gpt-4o}"
  base_url: "${LLM_URL:-https://api.openai.com/v1/chat/completions}"  # Complete endpoint URL
  api_key: "${LLM_API_KEY:-}"  # Use LLM_API_KEY environment variable
  timeout: 30
  max_tokens: 4000
  temperature: 0.1
```

#### Environment Variable Support

Ramparts supports environment variable interpolation using the `${VAR:-default}` syntax:

- `${LLM_PROVIDER:-openai}` - Uses `LLM_PROVIDER` environment variable, defaults to "openai"
- `${LLM_MODEL:-gpt-4o}` - Uses `LLM_MODEL` environment variable, defaults to "gpt-4o"
- `${LLM_URL:-https://api.openai.com/v1/chat/completions}` - Uses `LLM_URL` environment variable, defaults to OpenAI endpoint
- `${LLM_API_KEY:-}` - Uses `LLM_API_KEY` environment variable, no default (empty if not set)

Example usage:
```bash
export LLM_PROVIDER="anthropic"
export LLM_MODEL="claude-3-sonnet-20240229"
export LLM_URL="https://api.anthropic.com/v1/messages"
export LLM_API_KEY="your-anthropic-api-key"
ramparts scan https://example.com
```

**Important Notes:**
- Set your API key via environment variable: `export OPENAI_API_KEY="your-key"`
- Never commit API keys to version control
- Lower temperature (0.0-0.2) recommended for consistent security analysis

#### Supported LLM Providers

Currently supported:
- **OpenAI**: GPT-4, GPT-4 Turbo, GPT-3.5 Turbo
- **Azure OpenAI**: Azure-hosted OpenAI models with api-version support
- **OpenAI-compatible APIs**: Any API that follows OpenAI's format

#### Azure OpenAI Configuration

For Azure OpenAI, provide the complete endpoint URL including the api-version parameter:

```yaml
llm:
  provider: "${LLM_PROVIDER:-openai}"
  model: "${LLM_MODEL:-gpt-4}"  # Your Azure deployment name
  base_url: "${LLM_URL:-https://your-resource.openai.azure.com/openai/deployments/your-deployment/chat/completions?api-version=2024-02-15-preview}"
  api_key: "${LLM_API_KEY:-}"
  timeout: 30
  max_tokens: 4000
  temperature: 0.1
```

Example environment variables for Azure OpenAI:
```bash
export LLM_PROVIDER="openai"
export LLM_MODEL="gpt-4"
export LLM_URL="https://your-resource.openai.azure.com/openai/deployments/your-deployment/chat/completions?api-version=2024-02-15-preview"
export LLM_API_KEY="your-azure-api-key"
```

#### Model Recommendations

- **gpt-4o**: Best accuracy, recommended for production
- **gpt-4-turbo**: Good balance of speed and accuracy
- **gpt-3.5-turbo**: Faster but less accurate

### Scanner Configuration

The `scanner` section controls core scanning behavior:

```yaml
scanner:
  http_timeout: 30        # Individual HTTP request timeout
  scan_timeout: 60        # Total scan operation timeout
  detailed: false         # Enable detailed analysis by default
  format: "table"         # Default output format
  parallel: true          # Process multiple items concurrently
  max_retries: 3          # Retry failed requests
  retry_delay_ms: 1000    # Wait between retries
  llm_batch_size: 10      # Tools per LLM request (1-50)
  enable_yara: true       # Enable YARA-X pattern scanning
```

**Performance Tuning:**
- Increase `llm_batch_size` for faster scanning of many tools
- Decrease `llm_batch_size` if hitting API rate limits
- Set `parallel: false` for debugging or rate-limited APIs
- Adjust timeouts based on network conditions

### Security Configuration

The `security` section controls security analysis:

```yaml
security:
  enabled: true
  min_severity: "low"
  checks:
    tool_poisoning: true
    secrets_leakage: true
    sql_injection: true
    command_injection: true
    path_traversal: true
    auth_bypass: true
    cross_origin_escalation: true
    prompt_injection: true
    pii_leakage: true
    jailbreak: true
```

**Security Check Types:**

- **tool_poisoning**: Detects tools that could harm systems or bypass AI safety measures
- **secrets_leakage**: Finds exposed API keys, passwords, tokens
- **sql_injection**: Identifies SQL injection vulnerabilities
- **command_injection**: Detects command injection risks
- **path_traversal**: Finds directory traversal vulnerabilities
- **auth_bypass**: Identifies authentication bypass issues
- **cross_origin_escalation**: Detects cross-domain contamination
- **prompt_injection**: Finds prompt injection vulnerabilities
- **pii_leakage**: Detects personally identifiable information exposure
- **jailbreak**: Identifies attempts to bypass AI safety measures

**Severity Levels:**
- **low**: All issues including minor concerns
- **medium**: Moderate security risks
- **high**: Serious security vulnerabilities
- **critical**: Severe security issues requiring immediate attention

### Logging Configuration

The `logging` section controls log output:

```yaml
logging:
  level: "info"           # Log verbosity
  colored: true           # Colored terminal output
  timestamps: true        # Include timestamps
```

**Log Levels:**
- **error**: Only errors
- **warn**: Warnings and errors
- **info**: General information (recommended)
- **debug**: Detailed debugging information
- **trace**: Very verbose debugging

### Performance Configuration

The `performance` section controls monitoring:

```yaml
performance:
  tracking: true          # Enable performance monitoring
  slow_threshold_ms: 5000 # Warn about slow operations
```

## Environment Variable Configuration

Ramparts supports two methods for environment variable configuration:

### 1. Inline Environment Variable Substitution (Recommended)

Use `${VAR:-default}` syntax directly in your `config.yaml`:

```yaml
llm:
  provider: ${LLM_PROVIDER:-openai}
  model: ${LLM_MODEL:-gpt-4o}
  base_url: ${LLM_URL:-https://api.openai.com/v1/chat/completions}
  api_key: ${LLM_API_KEY:-}
```

```bash
# Set environment variables
export LLM_PROVIDER="anthropic"
export LLM_MODEL="claude-3-sonnet-20240229"
export LLM_URL="https://api.anthropic.com/v1/messages"
export LLM_API_KEY="your-anthropic-api-key"
```

### 2. Legacy Environment Variable Override

Any configuration value can be overridden with environment variables using the format `RAMPARTS_SECTION_KEY`:

```bash
# Override LLM model
export RAMPARTS_LLM_MODEL="gpt-3.5-turbo"

# Override timeout
export RAMPARTS_SCANNER_HTTP_TIMEOUT="60"

# Override log level
export RAMPARTS_LOGGING_LEVEL="debug"

# Disable YARA scanning
export RAMPARTS_SCANNER_ENABLE_YARA="false"
```

### 3. Skill Discovery Roots

`ramparts skills scan-config` walks `~/<dotdir>/{commands,skills}` and
the same paths under the current workspace for the supported
ecosystems (`.claude`, `.cursor`, `.codex`, `.windsurf`, `.gemini`,
`.openai`). Operators can add extra roots without rebuilding via the
**`RAMPARTS_SKILL_ROOTS`** environment variable:

```bash
# Comma-separated list of paths; leading `~/` is expanded to $HOME.
# Other tilde forms (~user/) are not expanded — use absolute paths.
export RAMPARTS_SKILL_ROOTS="~/work/agent-skills,/srv/shared-skills"
ramparts skills scan-config
```

The env-var roots are walked in addition to the default per-ecosystem
locations (not instead of them). The trust model is the same as
`ramparts skills scan <PATH>`: anyone who can set the env var can
point the scanner at any directory the running user can read.
Duplicate paths across env-var entries and defaults are deduped at
scan time by canonical path, so overlapping entries are harmless.

## YARA-X Configuration

### Enabling/Disabling YARA

```yaml
scanner:
  enable_yara: true  # Set to false to disable YARA scanning
```

### Rules Directory Structure

```
rules/
├── pre/                 # Pre-scan rules (before LLM analysis)
│   ├── secrets_leakage.yar
│   ├── command_injection.yar
│   ├── path_traversal.yar
│   ├── sql_injection.yar
│   └── cross_origin_escalation.yar
└── post/               # Post-scan rules (after LLM analysis)
    └── custom_rules.yar
```

### Custom YARA Rules

Create custom `.yar` files in the `rules/pre/` or `rules/post/` directories:

```yara
rule CustomSecurityRule
{
    meta:
        name = "Custom Security Check"
        author = "Your Name"
        date = "2024-01-01"
        version = "1.0"
        description = "Custom security rule description"
        severity = "HIGH"
        category = "custom"
        confidence = "HIGH"
        tags = "security,custom"

    strings:
        $pattern1 = /dangerous_pattern/
        $pattern2 = "risky_string"

    condition:
        any of them
}
```

**YARA Rule Metadata Fields:**
- **name**: Human-readable rule name
- **author**: Rule author
- **date**: Creation date
- **version**: Rule version
- **description**: Detailed description
- **severity**: LOW, MEDIUM, HIGH, CRITICAL
- **category**: Rule category
- **confidence**: LOW, MEDIUM, HIGH
- **tags**: Comma-separated tags

## Configuration Examples

### High-Security Environment
```yaml
llm:
  provider: "openai"
  model: "gpt-4o"
  temperature: 0.0  # Most consistent results

scanner:
  detailed: true
  enable_yara: true

security:
  enabled: true
  min_severity: "medium"  # Only report medium+ issues
  checks:
    tool_poisoning: true
    secrets_leakage: true
    sql_injection: true
    command_injection: true
    path_traversal: true
    auth_bypass: true
    cross_origin_escalation: true
    prompt_injection: true
    pii_leakage: true
    jailbreak: true

logging:
  level: "info"
```

### Development Environment
```yaml
llm:
  provider: "openai"
  model: "gpt-3.5-turbo"  # Faster for development

scanner:
  detailed: false
  http_timeout: 15        # Shorter timeouts
  scan_timeout: 30
  enable_yara: false      # Disable for faster testing

security:
  enabled: true
  min_severity: "low"     # Show all issues

logging:
  level: "debug"          # Verbose logging
  colored: true
```

### CI/CD Environment
```yaml
llm:
  provider: "openai"
  model: "gpt-4o"

scanner:
  detailed: true
  parallel: true
  max_retries: 5          # More retries for reliability
  retry_delay_ms: 2000

security:
  enabled: true
  min_severity: "high"    # Only fail on serious issues

logging:
  level: "warn"           # Minimal logging
  colored: false          # No colors in CI
  timestamps: true

performance:
  tracking: false         # Disable in CI
```

### Rate-Limited Environment
```yaml
llm:
  provider: "openai"
  model: "gpt-3.5-turbo"
  timeout: 60             # Longer timeout

scanner:
  parallel: false         # Sequential processing
  llm_batch_size: 5       # Smaller batches
  max_retries: 10         # More retries
  retry_delay_ms: 5000    # Longer delays

security:
  enabled: true
  min_severity: "medium"

logging:
  level: "info"
```

## Validation

Validate your configuration:

```bash
# Test configuration
ramparts scan https://httpbin.org/json --config ramparts.yaml

# Validate configuration without scanning
ramparts init-config --force  # Recreate with defaults
```

## Security Best Practices

1. **API Keys**: Always use environment variables, never commit keys
2. **File Permissions**: Restrict config file access (`chmod 600 ramparts.yaml`)
3. **Network**: Use HTTPS endpoints when possible
4. **Logging**: Avoid logging sensitive data in debug mode
5. **Updates**: Keep configuration updated with new security checks

## Troubleshooting Configuration

### Common Issues

**LLM API Key Issues:**
```bash
# Check environment variable
echo $OPENAI_API_KEY

# Test API key
curl -H "Authorization: Bearer $OPENAI_API_KEY" \
     https://api.openai.com/v1/models
```

**YARA Rules Not Loading:**
```bash
# Check rules directory
ls -la rules/pre/

# Verify YARA is enabled
grep enable_yara ramparts.yaml
```

**Timeout Issues:**
```bash
# Increase timeouts for slow networks
ramparts scan <url> --timeout 120 --http-timeout 60
```

**Configuration Not Found:**
```bash
# Specify config explicitly
ramparts scan <url> --config /path/to/ramparts.yaml

# Check search paths
ramparts scan <url> --verbose  # Shows config loading
```