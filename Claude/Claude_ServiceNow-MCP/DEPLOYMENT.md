# Deployment Guide

## 1. Prerequisites

- macOS endpoint
- Claude Code already installed for target user
- `claude` binary available at `~/.local/bin/claude`
- ServiceNow OAuth + API policy prerequisites completed by admin

## 2. Set Configuration

The script supports environment variable overrides.

Example:

```bash
export SN_BASE="https://your-instance.servicenowservices.com"
export SN_CLIENT_ID="your-client-id"
export SN_SCOPE="your-auth-scope"
export SN_REDIRECT_URI="http://localhost:8765/callback"
export SN_TOKEN_FILE_NAME=".servicenow_prod_tokens.json"
export MCP_SERVER_NAME="servicenow"
```

## 3. Run Installer

```bash
sudo bash servicenow_claude_bootstrap.sh
```

What it does:
- validates Python 3.11+
- creates/repairs `~/.servicenow_mcp/venv`
- installs `httpx` and `mcp`
- writes `~/.servicenow_mcp/servicenow_mcp.py`
- registers MCP in Claude user scope

## 4. First Authentication

On first tool call, browser OAuth login opens.
- authenticate to ServiceNow
- approve access
- callback returns to `http://localhost:8765/callback`

Token file is stored in:
- `~/<SN_TOKEN_FILE_NAME>`

## 5. Verify in Claude

From any directory:

1. Run Claude: `claude`
2. Confirm tools appear:
   - `servicenow_ping`
   - `get_recent_incidents`
   - `get_incident_by_number`
3. Test with:
   - `servicenow_ping`
   - `get_incident_by_number` for a known incident (example: `INC0013330`)

## 6. Reinstall / Recovery

```bash
sudo bash servicenow_claude_bootstrap.sh
```

If you need forced re-authentication, delete token cache first:

```bash
rm -f ~/.servicenow_prod_tokens.json
```

## 7. Common Issues

- `Missing state parameter`: ensure OAuth app is configured as public client and redirect URI exactly matches script.
- `No matching distribution found for mcp`: stale old venv; rerun script so it rebuilds venv with modern Python.
- Large result/token errors: use `get_incident_by_number` for direct lookup instead of very large recent queries.

