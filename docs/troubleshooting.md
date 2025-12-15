# Troubleshooting Guide

This document provides solutions to common issues you might encounter when using Ramparts.

## Installation Issues

### Cargo Installation Problems

**Issue: YARA-X compilation fails**
```bash
error: failed to compile `ramparts`
```

**Solutions:**
```bash
# Option 1: Install without YARA-X support (see README for details)
cargo install ramparts --no-default-features

# Option 2: Update Rust toolchain
rustup update stable

# Option 3: Clear cargo cache and retry
cargo clean
```

**Issue: Permission denied**
```bash
error: failed to create directory `/usr/local/cargo/bin`
```

**Solution:**
```bash
# Install to user directory
cargo install ramparts --root ~/.local
export PATH="$HOME/.local/bin:$PATH"
```

### Binary Download Issues

**Issue: Binary not executable**
```bash
ramparts: Permission denied
```

**Solution:**
```bash
chmod +x /path/to/ramparts
```

**Issue: macOS security warning**
```bash
"ramparts" cannot be opened because it is from an unidentified developer
```

**Solution:**
```bash
# Remove quarantine attribute
xattr -d com.apple.quarantine /path/to/ramparts

# Or allow in System Preferences > Security & Privacy
```

## Connection Issues

### HTTP Connection Problems

**Issue: Connection timeout**
```bash
error: Connection timeout after 30 seconds
```

**Solutions:**
```bash
# Increase timeout
ramparts scan <url> --timeout 120 --http-timeout 60

# Check network connectivity
curl -I <url>

# Test with simple endpoint
ramparts scan https://httpbin.org/json
```

**Issue: SSL/TLS certificate errors**
```bash
error: SSL certificate verify failed
```

**Solutions:**
```bash
# Update CA certificates (Ubuntu/Debian)
sudo apt-get update && sudo apt-get install ca-certificates

# Update CA certificates (macOS)
brew install ca-certificates

# For testing only (NOT recommended for production)
export RUSTLS_VERIFY_CERT=false
```

**Issue: HTTP 403 Forbidden**
```bash
error: HTTP 403 Forbidden
```

**Solutions:**
```bash
# Add authentication headers
ramparts scan <url> --auth-headers "Authorization: Bearer $TOKEN"

# Check API key permissions
curl -H "Authorization: Bearer $TOKEN" <url>

# Verify endpoint URL
ramparts scan <url> --verbose
```



### STDIO Connection Problems

**Issue: STDIO server not starting**
```bash
error: Failed to start MCP server subprocess
```

**Solutions:**
```bash
# Test command manually
/usr/local/bin/mcp-server --help

# Check file permissions
ls -la /usr/local/bin/mcp-server

# Verify Node.js/Python installation
node --version
python3 --version

# Use correct STDIO format (colon-separated)
ramparts scan "stdio:npx:mcp-server-commands"
ramparts scan "stdio:python3:/path/to/server.py"
ramparts scan "stdio:node:/path/to/server.js"

# Use full path if needed
ramparts scan "stdio:///usr/local/bin/python3:/path/to/server.py"
```

**Issue: STDIO URL format errors**
```bash
error: Invalid STDIO URL format
```

**Solutions:**
```bash
# Correct format: stdio:command:args (colon-separated)
ramparts scan "stdio:npx:mcp-server-commands"

# NOT: stdio://npx mcp-server-commands (space-separated)
# NOT: stdio://npx%20mcp-server-commands (URL-encoded)

# Multiple arguments example
ramparts scan "stdio:python3:/path/to/server.py:--port:8080"
```

### MCP stdio server exits immediately
**Issue:**
```bash
Error: ConnectionClosed("initialized request")
```

**Cause:**
- The MCP stdio server expects an MCP client to speak JSON-RPC over stdin/stdout. When run directly in a terminal, no `initialize` request is sent.

**Fix:**
- Run `ramparts mcp-stdio` under an MCP host (e.g., Docker MCP Toolkit, Cursor, Claude Desktop).
- For local testing, use an MCP inspector or a small client that spawns the binary and sends `initialize`.

**Issue: Environment variable issues**
```bash
error: Missing required environment variables
```

**Solutions:**
```bash
# Set environment variables
export API_KEY="your-key"
export DATABASE_URL="your-db-url"

# Check server requirements
head -20 /path/to/mcp-server.js  # Look for required env vars

# Use with env command (if supported by your shell)
env API_KEY=$API_KEY ramparts scan "stdio:node:server.js"
```

### Transport Fallback Issues

**Issue: Simple HTTP fails, need to force rmcp transport**
```bash
error: Simple HTTP connection failed, trying fallback transports
```

**Solutions:**
```bash
# Enable debug logging to see transport selection
ramparts --debug scan https://api.example.com/mcp/

# The system automatically tries:
# 1. Simple HTTP (custom implementation)
# 2. rmcp Streamable HTTP (standards-compliant)
# 3. rmcp SSE (Server-Sent Events)

# If all HTTP transports fail, check:
curl -v https://api.example.com/mcp/
```

**Issue: Session management problems**
```bash
error: Invalid session ID
```

**Solutions:**
```bash
# For stateful servers (like GitHub Copilot), ramparts automatically:
# 1. Extracts mcp-session-id from initialize response
# 2. Includes session ID in subsequent requests
# 3. Validates session with actual API calls

# If session issues persist:
ramparts --debug scan <url> --auth-headers "Authorization: Bearer $TOKEN"

# Check server logs for session requirements
```

**Issue: Transport detection problems**
```bash
error: No suitable transport found
```

**Solutions:**
```bash
# For HTTP URLs: ramparts tries multiple HTTP transports automatically
ramparts scan https://api.example.com/mcp/

# For STDIO: use proper format
ramparts scan "stdio:npx:mcp-server-commands"

# Debug transport selection
RUST_LOG=debug ramparts scan <url>
```

## Authentication Issues

### API Key Problems

**Issue: Invalid API key**
```bash
error: Authentication failed: Invalid API key
```

**Solutions:**
```bash
# Check API key format
echo $OPENAI_API_KEY | wc -c  # Should be ~51 characters for OpenAI

# Test API key directly
curl -H "Authorization: Bearer $OPENAI_API_KEY" \
     https://api.openai.com/v1/models

# Regenerate API key if needed
```

**Issue: Authentication headers not working**
```bash
error: HTTP 401 Unauthorized
```

**Solutions:**
```bash
# Check header format
ramparts scan <url> --auth-headers "Authorization: Bearer token123"

# Multiple headers
ramparts scan <url> \
  --auth-headers "Authorization: Bearer $TOKEN" \
  --auth-headers "X-API-Key: $API_KEY"

# Debug with curl
curl -H "Authorization: Bearer $TOKEN" <url>
```

## Configuration Issues

### Configuration File Problems

**Issue: Configuration file not found**
```bash
error: Configuration file not found
```

**Solutions:**
```bash
# Create default configuration
ramparts init-config

# Specify config path explicitly
ramparts scan <url> --config /path/to/config.yaml

# Check search paths
ramparts scan <url> --verbose
```

**Issue: Invalid YAML syntax**
```bash
error: Failed to parse configuration file
```

**Solutions:**
```bash
# Validate YAML syntax
python3 -c "import yaml; yaml.safe_load(open('ramparts.yaml'))"

# Check indentation (use spaces, not tabs)
cat -A ramparts.yaml

# Recreate from template
ramparts init-config --force
```

**Issue: Environment variable substitution not working**
```bash
error: API key is empty
```

**Solutions:**
```bash
# Check environment variable
echo $OPENAI_API_KEY

# Export in same shell session
export OPENAI_API_KEY="your-key"
ramparts scan <url>

# Use config file instead
echo "llm:\n  api_key: \"$OPENAI_API_KEY\"" >> ramparts.yaml
```

## YARA-X Issues

### Rule Loading Problems

**Issue: YARA rules not loading**
```bash
error: Failed to load YARA pre-scan scanner
```

**Solutions:**
```bash
# Check rules directory exists
ls -la rules/pre/

# Verify rule files
ls rules/pre/*.yar

# Check file permissions
chmod 644 rules/pre/*.yar

# Test with YARA disabled
echo "scanner:\n  enable_yara: false" > test-config.yaml
ramparts scan <url> --config test-config.yaml
```

**Issue: Rule syntax errors**
```bash
error: Failed to compile YARA rule
```

**Solutions:**
```bash
# Check rule syntax
cat rules/pre/custom_rule.yar

# Validate escaping (especially { characters)
# Bad:  $pattern = /interface{}/
# Good: $pattern = /interface\{\}/

# Check metadata format
# Ensure strings are quoted properly
```

**Issue: Performance issues with YARA**
```bash
# Scanning is very slow
```

**Solutions:**
```bash
# Disable YARA temporarily
ramparts scan <url> --config <(echo "scanner:\n  enable_yara: false")

# Optimize rules (remove complex regex)
# Reduce number of rules in rules/pre/

# Install without YARA-X
cargo install ramparts --no-default-features --force
```

### Custom Rules Issues

**Issue: Custom rules not working**
```bash
# Custom YARA rules not triggering
```

**Solutions:**
```bash
# Check rule syntax
yara-x rules/pre/custom.yar test_file  # If yara-x CLI available

# Verify rule placement
ls rules/pre/  # Should contain .yar files

# Test rule logic
echo "test content" | grep -E "your_pattern"

# Enable debug logging
RUST_LOG=debug ramparts scan <url>
```

## Performance Issues

### Slow Scanning

**Issue: Scans take too long**
```bash
# Scanning is extremely slow
```

**Solutions:**
```bash
# Reduce LLM batch size
echo "scanner:\n  llm_batch_size: 5" >> ramparts.yaml

# Disable detailed analysis
ramparts scan <url> --detailed false

# Disable parallel processing
echo "scanner:\n  parallel: false" >> ramparts.yaml

# Use faster model
echo "llm:\n  model: \"gpt-3.5-turbo\"" >> ramparts.yaml
```

**Issue: Memory usage too high**
```bash
# High memory consumption
```

**Solutions:**
```bash
# Reduce batch size
echo "scanner:\n  llm_batch_size: 3" >> ramparts.yaml

# Disable YARA scanning
echo "scanner:\n  enable_yara: false" >> ramparts.yaml

# Scan fewer items at once
# Break large scans into smaller batches
```

### Rate Limiting

**Issue: Rate limit exceeded**
```bash
error: Rate limit exceeded
```

**Solutions:**
```bash
# Reduce batch size
echo "scanner:\n  llm_batch_size: 1" >> ramparts.yaml

# Add delays between requests
echo "scanner:\n  retry_delay_ms: 5000" >> ramparts.yaml

# Disable parallel processing
echo "scanner:\n  parallel: false" >> ramparts.yaml

# Use server mode with queuing
ramparts server --port 3000 &
# Send requests individually with delays
```

## Output Issues

### JSON Parsing Problems

**Issue: Invalid JSON output**
```bash
error: Failed to parse JSON response
```

**Solutions:**
```bash
# Use raw output format
ramparts scan <url> --output raw

# Check for binary content in response
file output.json

# Enable verbose logging to see raw response
ramparts scan <url> --verbose --output json
```

**Issue: Missing fields in output**
```bash
# Expected fields not present in JSON
```

**Solutions:**
```bash
# Enable detailed output
ramparts scan <url> --detailed --output json

# Check scan success
ramparts scan <url> --output json | jq '.success'

# Verify server response
ramparts scan <url> --output raw | jq .
```

## Server Mode Issues

### Server Startup Problems

**Issue: Server won't start**
```bash
error: Address already in use
```

**Solutions:**
```bash
# Check what's using the port
lsof -i :3000
netstat -tulpn | grep 3000

# Use different port
ramparts server --port 8080

# Kill existing process
pkill -f "ramparts server"
```

**Issue: Server not accessible**
```bash
# Can't connect to http://localhost:3000
```

**Solutions:**
```bash
# Check server is running
ps aux | grep ramparts

# Test locally
curl http://localhost:3000/v1/ramparts/health

# Check host binding
ramparts server --host 0.0.0.0 --port 3000

# Check firewall
sudo ufw status
```

### API Issues

**Issue: 500 Internal Server Error**
```bash
{"success": false, "error": "Internal server error"}
```

**Solutions:**
```bash
# Check server logs
ramparts server --verbose

# Test configuration
ramparts scan <url> --config ramparts.yaml

# Check available memory/disk space
free -h
df -h
```

## Debugging Tips

### Enable Verbose Logging

```bash
# Enable debug logging
RUST_LOG=debug ramparts scan <url>

# Enable trace logging (very verbose)
RUST_LOG=trace ramparts scan <url>

# Log to file
RUST_LOG=debug ramparts scan <url> 2> debug.log
```

### Test with Simple Cases

```bash
# Test with httpbin (always responds)
ramparts scan https://httpbin.org/json

# Test STDIO with echo
ramparts scan "stdio://echo '{\"tools\": []}'"

# Test minimal configuration
ramparts scan <url> --config <(echo "{}")
```

### Validate Environment

```bash
# Check Rust installation
rustc --version
cargo --version

# Check network connectivity
ping google.com
curl -I https://api.openai.com

# Check file permissions
ls -la $(which ramparts)
ls -la ramparts.yaml
```

### Generate Debug Report

```bash
# Collect system information
cat > debug-report.txt << EOF
Ramparts Version: $(ramparts --version)
Rust Version: $(rustc --version)
OS: $(uname -a)
Date: $(date)

Configuration:
$(cat ramparts.yaml 2>/dev/null || echo "No config file")

Environment:
RUST_LOG=$RUST_LOG
OPENAI_API_KEY=$(echo $OPENAI_API_KEY | sed 's/./*/g')

Test Run:
$(RUST_LOG=debug ramparts scan https://httpbin.org/json 2>&1 | head -50)
EOF
```

## Getting Help

If you're still experiencing issues:

1. **Check GitHub Issues**: [https://github.com/highflame-ai/ramparts/issues](https://github.com/highflame-ai/ramparts/issues)
2. **Create Bug Report**: Include debug report and steps to reproduce
3. **Search Documentation**: Check all docs in the `docs/` directory
4. **Community Support**: Join discussions in GitHub Discussions

### Bug Report Template

```markdown
**Describe the bug**
A clear description of what the bug is.

**To Reproduce**
Steps to reproduce the behavior:
1. Run command: `ramparts scan ...`
2. See error: `...`

**Expected behavior**
What you expected to happen.

**Environment**
- OS: [e.g. macOS 13.0, Ubuntu 22.04]
- Ramparts version: [e.g. 0.6.3]
- Rust version: [e.g. 1.70.0]

**Configuration**
```yaml
# Your ramparts.yaml content (remove API keys)
```

**Debug output**
```
RUST_LOG=debug ramparts scan <url> output
```

**Additional context**
Any other information about the problem.
```