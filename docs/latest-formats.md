# Latest IDE Configuration Formats Supported by Ramparts

Ramparts supports scanning MCP (Model Context Protocol) servers from all major IDE configuration formats. This document shows the latest supported formats for each IDE.

## Overview

Ramparts automatically discovers and parses MCP configurations from the following IDEs:
- **VS Code** (Visual Studio Code)
- **Cursor** 
- **Windsurf** (Codeium)
- **Claude Desktop**
- **Claude Code** 
- **Zed**
- **Neovim**
- **Helix**
- **Zencoder**

## Configuration File Locations

### VS Code
- `~/.vscode/mcp.json`
- `~/.vscode/settings.json`
- `~/Library/Application Support/Code/User/mcp.json` (macOS)
- `%APPDATA%\Code\User\mcp.json` (Windows)
- `~/.config/Code/User/mcp.json` (Linux)

### Cursor
- `~/.cursor/mcp.json`
- `~/Library/Application Support/Cursor/User/mcp.json` (macOS)
- `%APPDATA%\Cursor\User\mcp.json` (Windows)

### Windsurf (Codeium)
- `~/.codeium/windsurf/mcp_config.json`
- `~/Library/Application Support/Codeium/Windsurf/mcp_config.json` (macOS)
- `%APPDATA%\Codeium\Windsurf\mcp_config.json` (Windows)

### Claude Desktop
- `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS)
- `%APPDATA%\Claude\claude_desktop_config.json` (Windows)

### Claude Code
- `~/.claude/settings.json` (User/Global)
- `.claude/settings.json` (Project shared)
- `.claude/settings.local.json` (Project personal)

### Zed
- `~/Library/Application Support/Zed/mcp.json` (macOS)
- `~/.config/zed/mcp.json` (Linux)

## Configuration Format Examples

### VS Code Format (mcp.json)

```json
{
    "servers": {
        "github": {
            "type": "http",
            "url": "https://api.githubcopilot.com/mcp/",
            "gallery": true
        },
        "local-fs": {
            "type": "stdio",
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
            "description": "Local filesystem access"
        },
        "memory": {
            "type": "stdio",
            "command": "npx", 
            "args": ["-y", "@modelcontextprotocol/server-memory"],
            "description": "Memory/Note-taking server"
        }
    },
    "inputs": []
}
```

### Cursor Format (mcp.json)

```json
{
    "mcpServers": {
        "airbnb": {
            "command": "npx",
            "args": ["-y", "@openbnb/mcp-server-airbnb"],
            "env": {
                "DEBUG": "1"
            }
        },
        "playwright": {
            "command": "npx",
            "args": ["-y", "@executeautomation/playwright-mcp-server"],
            "description": "Playwright automation server"
        },
        "time": {
            "command": "uvx",
            "args": ["mcp-server-time"],
            "env": {
                "TZ": "UTC"
            }
        }
    },
    "settings": {
        "enableLogging": true
    }
}
```

### Windsurf Format (mcp_config.json)

```json
{
    "servers": {
        "git": {
            "command": "uvx",
            "args": ["mcp-server-git"],
            "type": "stdio",
            "description": "Git operations server"
        },
        "filesystem": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
            "description": "File system access",
            "env": {
                "NODE_ENV": "development"
            }
        },
        "weather": {
            "url": "http://localhost:8080",
            "type": "http",
            "description": "Weather information service"
        }
    },
    "global": {
        "timeout": 30,
        "format": "json"
    }
}
```

### Claude Desktop Format (claude_desktop_config.json)

```json
{
    "mcpServers": {
        "brave-search": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-brave-search"],
            "env": {
                "BRAVE_API_KEY": "your-api-key"
            }
        },
        "filesystem": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users/username/Desktop"],
            "type": "stdio"
        },
        "disabled-server": {
            "command": "npx",
            "args": ["-y", "@disabled/server"],
            "disabled": true
        }
    },
    "globalShortcut": "Cmd+Shift+M"
}
```

### Zed Format (mcp.json)

```json
{
    "context_servers": [
        {
            "mcp-server-git": {
                "command": {
                    "path": "uvx",
                    "args": ["mcp-server-git"]
                }
            }
        },
        {
            "filesystem": {
                "command": {
                    "path": "node",
                    "args": ["/path/to/filesystem-server.js", "/tmp"]
                },
                "env": {
                    "NODE_ENV": "production"
                }
            }
        },
        {
            "web-search": {
                "url": "http://localhost:9000",
                "env": {
                    "API_KEY": "test-key"
                }
            }
        }
    ]
}
```

## Server Configuration Types

### STDIO Servers
For command-line MCP servers:
```json
{
    "command": "npx",
    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
    "env": {
        "NODE_ENV": "development"
    }
}
```

### Containerized Servers (Docker MCP Toolkit)
For servers running inside containers (e.g., Docker MCP Toolkit):
```json
{
    "image": "ghcr.io/highflame-ai/ramparts:latest",
    "command": ["/app/ramparts", "mcp-stdio"],
    "description": "Ramparts MCP server over stdio"
}
```

### HTTP Servers
For HTTP-based MCP servers:
```json
{
    "type": "http",
    "url": "https://api.githubcopilot.com/mcp/",
    "gallery": true
}
```

## Usage with Ramparts

To scan all configured MCP servers from your IDEs:

```bash
# Scan all discovered IDE configurations
ramparts scan-config

# Output in JSON format
ramparts scan-config --format json

# Output in table format
ramparts scan-config --format table

# Add authentication headers
ramparts scan-config --auth-headers "Authorization: Bearer token"
```

## Security Features

Ramparts performs comprehensive security analysis on all discovered MCP servers:

- **Tool Security**: Detects malicious tools, injection vulnerabilities
- **Resource Security**: Identifies path traversal, sensitive data exposure  
- **Prompt Security**: Finds injection attacks, jailbreaks, PII leakage
- **YARA Rule Scanning**: Advanced pattern matching for threats

## Supported Configuration Features

✅ **Server Discovery**: Automatic detection from all major IDEs  
✅ **Multiple Formats**: Support for different IDE-specific formats  
✅ **Environment Variables**: Full support for server environment configuration  
✅ **Transport Types**: Both STDIO and HTTP server types  
✅ **Server Metadata**: Descriptions, tags, and server information  
✅ **Global Settings**: IDE-wide configuration options  
✅ **Disabled Servers**: Proper handling of disabled/inactive servers  
✅ **Deduplication**: Automatic removal of duplicate server configurations  
✅ **Validation**: Comprehensive configuration validation and error reporting  

## Version Compatibility

- **Ramparts**: Latest version
- **MCP Protocol**: 2025-03-26
- **Node.js Servers**: All versions with MCP support
- **Python Servers**: All versions with MCP support
- **HTTP Servers**: Standard HTTP/HTTPS with MCP protocol



## Contributing

If you use an IDE or configuration format not listed here, please contribute by:
1. Filing an issue with your configuration format
2. Submitting a pull request with parser support
3. Providing example configuration files for testing 