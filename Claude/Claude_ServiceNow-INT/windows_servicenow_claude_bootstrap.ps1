Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

<#
Script Name: ServiceNow MCP Setup (Windows PowerShell)
Purpose:
  - Ensure Python >= 3.11 is available
  - Create per-user venv under ~/.servicenow_mcp
  - Install deps (httpx + mcp) into that venv
  - Write ServiceNow MCP server (PKCE login + refresh)
  - Register MCP in Claude user scope so Claude works from any directory
#>

### ---------------------------------------------------------------------------
### REQUIRED PROJECT CONFIG (set these for your environment/GitHub repo)
### ---------------------------------------------------------------------------
function Get-ConfigValue {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$DefaultValue
    )

    $item = Get-Item -Path "Env:$Name" -ErrorAction SilentlyContinue
    if ($null -ne $item -and -not [string]::IsNullOrWhiteSpace($item.Value)) {
        return $item.Value
    }
    return $DefaultValue
}

$SN_BASE = Get-ConfigValue -Name "SN_BASE" -DefaultValue "https://INSTANCE.servicenowservices.com"
$SN_CLIENT_ID = Get-ConfigValue -Name "SN_CLIENT_ID" -DefaultValue "INPUT_ID"
# Must include write-capable auth scope if using approval tools (PATCH sysapproval_approver).
$SN_SCOPE = Get-ConfigValue -Name "SN_SCOPE" -DefaultValue "incident_read"
$SN_REDIRECT_URI = Get-ConfigValue -Name "SN_REDIRECT_URI" -DefaultValue "http://localhost:8765/callback"
$SN_TOKEN_FILE_NAME = Get-ConfigValue -Name "SN_TOKEN_FILE_NAME" -DefaultValue ".servicenow_prod_tokens.json"
$MCP_SERVER_NAME = Get-ConfigValue -Name "MCP_SERVER_NAME" -DefaultValue "servicenow"

### ---------------------------------------------------------------------------
### Runtime paths/config
### ---------------------------------------------------------------------------
$TargetHome = [Environment]::GetFolderPath("UserProfile")
if ([string]::IsNullOrWhiteSpace($TargetHome)) {
    throw "Could not determine current user profile path."
}

$MCP_DIR = Join-Path $TargetHome ".servicenow_mcp"
$VENV_DIR = Join-Path $MCP_DIR "venv"
$VENV_PYTHON = Join-Path $VENV_DIR "Scripts\python.exe"
$MCP_SCRIPT = Join-Path $MCP_DIR "servicenow_mcp.py"
$TOKENS_FILE = Join-Path $TargetHome $SN_TOKEN_FILE_NAME

function Write-Log {
    param([Parameter(Mandatory = $true)][string]$Message)
    Write-Host "[servicenow-mcp] $Message"
}

function Get-CommandOutput {
    param(
        [Parameter(Mandatory = $true)][string]$Exe,
        [Parameter(Mandatory = $true)][string[]]$Args
    )
    try {
        $output = & $Exe @Args 2>$null
        if ($LASTEXITCODE -ne 0) { return $null }
        return @($output)
    } catch {
        return $null
    }
}

function Get-PythonMajorMinor {
    param(
        [Parameter(Mandatory = $true)][string]$PythonExe,
        [string[]]$BaseArgs = @()
    )
    $args = @()
    $args += $BaseArgs
    $args += "-c"
    $args += "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
    $out = Get-CommandOutput -Exe $PythonExe -Args $args
    if ($null -eq $out -or $out.Count -eq 0) { return $null }
    return $out[0].ToString().Trim()
}

function Convert-ToPythonStringLiteral {
    param([Parameter(Mandatory = $true)][string]$Value)
    return ($Value -replace '\\', '\\\\' -replace '"', '\"')
}

### ---------------------------------------------------------------------------
### Keep token cache only if valid
### ---------------------------------------------------------------------------
Write-Log "Checking existing token cache: $TOKENS_FILE"
if (Test-Path -LiteralPath $TOKENS_FILE) {
    try {
        $token = Get-Content -LiteralPath $TOKENS_FILE -Raw -Encoding UTF8 | ConvertFrom-Json
        $expiresAt = [double]($token.expires_at)
        $now = [double][DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        if ($now -ge $expiresAt) {
            Write-Log "Token is expired, removing: $TOKENS_FILE"
            Remove-Item -LiteralPath $TOKENS_FILE -Force
        } else {
            Write-Log "Token is still valid, keeping cached credentials"
        }
    } catch {
        Write-Log "Token is invalid/corrupted, removing: $TOKENS_FILE"
        Remove-Item -LiteralPath $TOKENS_FILE -Force -ErrorAction SilentlyContinue
    }
}

### ---------------------------------------------------------------------------
### Ensure Python >= 3.11
### ---------------------------------------------------------------------------
$pythonCandidates = @(
    @{ Exe = "py"; BaseArgs = @("-3.13") },
    @{ Exe = "py"; BaseArgs = @("-3.12") },
    @{ Exe = "py"; BaseArgs = @("-3.11") },
    @{ Exe = "python"; BaseArgs = @() },
    @{ Exe = "python3"; BaseArgs = @() }
)

$SelectedPython = $null
foreach ($candidate in $pythonCandidates) {
    $probeArgs = @()
    $probeArgs += $candidate.BaseArgs
    $probeArgs += "-c"
    $probeArgs += "import sys; print(sys.executable); print('.'.join(map(str, sys.version_info[:3])))"

    $probe = Get-CommandOutput -Exe $candidate.Exe -Args $probeArgs
    if ($null -eq $probe -or $probe.Count -lt 2) { continue }

    $resolvedPath = $probe[0].ToString().Trim()
    $versionText = $probe[1].ToString().Trim()
    if ([string]::IsNullOrWhiteSpace($resolvedPath) -or [string]::IsNullOrWhiteSpace($versionText)) { continue }

    $parts = $versionText.Split(".")
    if ($parts.Count -lt 2) { continue }

    $major = [int]$parts[0]
    $minor = [int]$parts[1]

    if (($major -gt 3) -or ($major -eq 3 -and $minor -ge 11)) {
        $SelectedPython = [PSCustomObject]@{
            Exe = [string]$candidate.Exe
            BaseArgs = [string[]]$candidate.BaseArgs
            ExecutablePath = $resolvedPath
            Version = $versionText
            Major = $major
            Minor = $minor
        }
        break
    }
}

if ($null -eq $SelectedPython) {
    throw "Python 3.11+ is required. Install Python 3.11+ and re-run this script."
}

Write-Log ("Using Python: {0} ({1})" -f $SelectedPython.ExecutablePath, $SelectedPython.Version)

### ---------------------------------------------------------------------------
### Create MCP workspace + venv
### ---------------------------------------------------------------------------
New-Item -ItemType Directory -Path $MCP_DIR -Force | Out-Null

$selectedMM = "{0}.{1}" -f $SelectedPython.Major, $SelectedPython.Minor

if (Test-Path -LiteralPath $VENV_PYTHON) {
    $existingMM = Get-PythonMajorMinor -PythonExe $VENV_PYTHON
    if ([string]::IsNullOrWhiteSpace($existingMM)) {
        Write-Log "Existing venv is unreadable. Recreating: $VENV_DIR"
        Remove-Item -LiteralPath $VENV_DIR -Recurse -Force
    } elseif ($existingMM -ne $selectedMM) {
        Write-Log "Existing venv uses Python $existingMM; expected $selectedMM. Recreating."
        Remove-Item -LiteralPath $VENV_DIR -Recurse -Force
    } else {
        & $VENV_PYTHON -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)"
        if ($LASTEXITCODE -ne 0) {
            Write-Log "Existing venv Python is older than 3.11. Recreating: $VENV_DIR"
            Remove-Item -LiteralPath $VENV_DIR -Recurse -Force
        }
    }
}

if (-not (Test-Path -LiteralPath $VENV_PYTHON)) {
    Write-Log "Creating virtual environment: $VENV_DIR"
    $venvArgs = @()
    $venvArgs += $SelectedPython.BaseArgs
    $venvArgs += "-m"
    $venvArgs += "venv"
    $venvArgs += $VENV_DIR
    & $SelectedPython.Exe @venvArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to create virtual environment at $VENV_DIR"
    }
}

$venvMM = Get-PythonMajorMinor -PythonExe $VENV_PYTHON
if ($venvMM -ne $selectedMM) {
    throw "Venv Python mismatch (venv=$venvMM, selected=$selectedMM)."
}

Write-Log "Upgrading pip + installing dependencies into venv"
& $VENV_PYTHON -m pip install --upgrade pip
if ($LASTEXITCODE -ne 0) { throw "pip upgrade failed." }
& $VENV_PYTHON -m pip install --upgrade httpx mcp
if ($LASTEXITCODE -ne 0) { throw "Dependency installation failed." }

### ---------------------------------------------------------------------------
### Write ServiceNow MCP server script
### ---------------------------------------------------------------------------
Write-Log "Writing MCP server script: $MCP_SCRIPT"

$serverTemplate = @'
#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import http.server
import json
import logging
import os
import secrets
import sys
import threading
import time
import urllib.parse
import webbrowser
from typing import Any, Optional

import httpx
from mcp.server.fastmcp import FastMCP

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s: %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("servicenow-mcp")

SERVICENOW_BASE = "__SN_BASE__"
CLIENT_ID = "__SN_CLIENT_ID__"
SCOPE = "__SN_SCOPE__"
REDIRECT_URI = "__SN_REDIRECT_URI__"
TOKEN_FILE = os.path.expanduser("__TOKENS_FILE__")
MCP_SERVER_NAME = "__MCP_SERVER_NAME__"

HTTP_TIMEOUT = httpx.Timeout(connect=10.0, read=30.0, write=30.0, pool=30.0)

mcp = FastMCP(MCP_SERVER_NAME)


def generate_pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)[:64]
    digest = hashlib.sha256(verifier.encode("utf-8")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")
    return verifier, challenge


class OAuthHandler(http.server.BaseHTTPRequestHandler):
    auth_code: Optional[str] = None
    received_state: Optional[str] = None

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)

        if "code" in params:
            OAuthHandler.auth_code = params["code"][0]
            OAuthHandler.received_state = params.get("state", [None])[0]
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"Authentication successful. You may close this window.")
        else:
            self.send_response(400)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"Missing authorization code.")

    def log_message(self, format: str, *args: Any) -> None:
        return


def wait_for_code(expected_state: str, port: int = 8765, timeout_s: int = 180) -> str:
    OAuthHandler.auth_code = None
    OAuthHandler.received_state = None
    server = http.server.HTTPServer(("localhost", port), OAuthHandler)

    def _serve_one() -> None:
        server.handle_request()

    thread = threading.Thread(target=_serve_one, daemon=True)
    thread.start()

    start = time.time()
    while OAuthHandler.auth_code is None:
        if time.time() - start > timeout_s:
            server.server_close()
            raise RuntimeError("Timed out waiting for OAuth redirect (no code received).")
        time.sleep(0.2)

    server.server_close()

    if OAuthHandler.received_state != expected_state:
        raise RuntimeError(
            f"OAuth state mismatch (expected: {expected_state}, got: {OAuthHandler.received_state})."
        )

    return OAuthHandler.auth_code


def load_tokens() -> Optional[dict[str, Any]]:
    try:
        if not os.path.exists(TOKEN_FILE):
            return None
        with open(TOKEN_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.warning("Failed to load token file: %s", e)
        return None


def save_tokens(tokens: dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(TOKEN_FILE), exist_ok=True)
    tmp = TOKEN_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(tokens, f)
    os.replace(tmp, TOKEN_FILE)
    try:
        os.chmod(TOKEN_FILE, 0o600)
    except Exception:
        pass


async def oauth_authorize_code_flow() -> dict[str, Any]:
    verifier, challenge = generate_pkce()
    state = secrets.token_urlsafe(16)

    auth_url = (
        f"{SERVICENOW_BASE}/oauth_auth.do?"
        f"response_type=code"
        f"&client_id={urllib.parse.quote(CLIENT_ID)}"
        f"&redirect_uri={urllib.parse.quote(REDIRECT_URI)}"
        f"&scope={urllib.parse.quote(SCOPE)}"
        f"&state={urllib.parse.quote(state)}"
        f"&code_challenge={urllib.parse.quote(challenge)}"
        f"&code_challenge_method=S256"
    )

    logger.info("Opening browser for OAuth authentication...")
    webbrowser.open(auth_url)
    code = wait_for_code(expected_state=state)

    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
        r = await client.post(
            f"{SERVICENOW_BASE}/oauth_token.do",
            data={
                "grant_type": "authorization_code",
                "client_id": CLIENT_ID,
                "redirect_uri": REDIRECT_URI,
                "code": code,
                "code_verifier": verifier,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        r.raise_for_status()
        tok = r.json()

    now = time.time()
    token_data = {
        "access_token": tok["access_token"],
        "refresh_token": tok.get("refresh_token"),
        "expires_at": now + int(tok.get("expires_in", 1800)) - 60,
        "scope": tok.get("scope", SCOPE),
        "token_type": tok.get("token_type", "Bearer"),
    }
    save_tokens(token_data)
    return token_data


async def oauth_refresh_flow(refresh_token: str) -> dict[str, Any]:
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
        r = await client.post(
            f"{SERVICENOW_BASE}/oauth_token.do",
            data={
                "grant_type": "refresh_token",
                "client_id": CLIENT_ID,
                "refresh_token": refresh_token,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        r.raise_for_status()
        tok = r.json()

    now = time.time()
    token_data = {
        "access_token": tok["access_token"],
        "refresh_token": tok.get("refresh_token", refresh_token),
        "expires_at": now + int(tok.get("expires_in", 1800)) - 60,
        "scope": tok.get("scope", SCOPE),
        "token_type": tok.get("token_type", "Bearer"),
    }
    save_tokens(token_data)
    return token_data


async def get_access_token() -> str:
    tokens = load_tokens()
    if not tokens:
        tokens = await oauth_authorize_code_flow()
        return tokens["access_token"]

    if time.time() < float(tokens.get("expires_at", 0)):
        return tokens["access_token"]

    rt = tokens.get("refresh_token")
    if rt:
        try:
            tokens = await oauth_refresh_flow(rt)
            return tokens["access_token"]
        except Exception:
            pass

    tokens = await oauth_authorize_code_flow()
    return tokens["access_token"]


async def sn_get(path: str, params: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    token = await get_access_token()
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
        r = await client.get(f"{SERVICENOW_BASE}{path}", headers=headers, params=params)
        r.raise_for_status()
        return r.json()


async def sn_patch(path: str, payload: dict[str, Any]) -> dict[str, Any]:
    token = await get_access_token()
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
        r = await client.patch(f"{SERVICENOW_BASE}{path}", headers=headers, json=payload)
        r.raise_for_status()
        if not r.content:
            return {}
        return r.json()


INCIDENT_FIELDS = ",".join(
    [
        "number",
        "short_description",
        "description",
        "state",
        "priority",
        "urgency",
        "impact",
        "category",
        "subcategory",
        "assigned_to",
        "assignment_group",
        "opened_by",
        "sys_created_on",
        "sys_updated_on",
    ]
)

TABLE_PREFIX_MAP = {
    "INC": "incident",
    "RITM": "sc_req_item",
    "REQ": "sc_request",
    "SCTASK": "sc_task",
    "CHG": "change_request",
    "PRB": "problem",
}

RECORD_LOOKUP_FIELDS = ",".join(
    [
        "sys_id",
        "number",
        "short_description",
        "state",
        "priority",
        "sys_updated_on",
        "assigned_to",
    ]
)


def resolve_table_from_number(number: str) -> str:
    normalized = (number or "").strip().upper()
    for prefix, table in TABLE_PREFIX_MAP.items():
        if normalized.startswith(prefix):
            return table
    raise ValueError(f"Unsupported record prefix for number: {number}")


async def lookup_record_by_number(number: str) -> tuple[str, Optional[dict[str, Any]]]:
    record_number = (number or "").strip().upper()
    table = resolve_table_from_number(record_number)

    data = await sn_get(
        f"/api/now/table/{table}",
        {
            "sysparm_query": f"number={record_number}",
            "sysparm_limit": 1,
            "sysparm_fields": RECORD_LOOKUP_FIELDS,
            "sysparm_display_value": "true",
            "sysparm_exclude_reference_link": "true",
        },
    )
    results = data.get("result", [])
    if not results:
        return table, None
    return table, results[0]


def incident_params(limit: int = 5, query: Optional[str] = None) -> dict[str, Any]:
    safe_limit = max(1, min(int(limit), 50))
    order_clause = "ORDERBYDESCsys_created_on"
    full_query = f"{query}^{order_clause}" if query else order_clause
    return {
        "sysparm_limit": safe_limit,
        "sysparm_query": full_query,
        "sysparm_fields": INCIDENT_FIELDS,
        "sysparm_display_value": "true",
        "sysparm_exclude_reference_link": "true",
    }


@mcp.tool()
async def servicenow_ping() -> str:
    """Quick sanity check that the MCP server is running."""
    return "servicenow MCP server is running."


@mcp.tool()
async def get_recent_incidents(limit: int = 5) -> list[dict[str, Any]]:
    """Get recent incidents with a compact field set (limit is capped at 50)."""
    data = await sn_get("/api/now/table/incident", incident_params(limit=limit))
    return data.get("result", [])


@mcp.tool()
async def get_incident_by_number(number: str) -> dict[str, Any]:
    """Lookup a single incident by exact number, e.g. INC0013330."""
    incident_number = (number or "").strip().upper()
    if not incident_number:
        raise ValueError("Incident number is required")

    data = await sn_get(
        "/api/now/table/incident",
        incident_params(limit=1, query=f"number={incident_number}"),
    )
    results = data.get("result", [])
    if not results:
        return {"found": False, "number": incident_number}

    return {"found": True, "number": incident_number, "incident": results[0]}


@mcp.tool()
async def get_record_by_number(number: str) -> dict[str, Any]:
    """
    Retrieve a ServiceNow record by its number (INC, RITM, REQ, CHG, etc.)
    """
    record_number = (number or "").strip().upper()
    if not record_number:
        raise ValueError("Record number is required")

    table, record = await lookup_record_by_number(record_number)
    return {
        "table": table,
        "result": ([record] if record else []),
    }


@mcp.tool()
async def approve_record_by_number(number: str, comments: str = "Approved via MCP") -> dict[str, Any]:
    """
    Approve a pending approval for a record number (INC, RITM, REQ, SCTASK, CHG, PRB).
    Requires ServiceNow OAuth/API policy permission to PATCH sysapproval_approver.
    """
    record_number = (number or "").strip().upper()
    if not record_number:
        raise ValueError("Record number is required")

    table, record = await lookup_record_by_number(record_number)
    if not record:
        return {
            "approved": False,
            "reason": "record_not_found",
            "table": table,
            "number": record_number,
        }

    record_sys_id = str(record.get("sys_id", "")).strip()
    if not record_sys_id:
        return {
            "approved": False,
            "reason": "record_sys_id_missing",
            "table": table,
            "number": record_number,
            "record": record,
        }

    approvals = await sn_get(
        "/api/now/table/sysapproval_approver",
        {
            "sysparm_query": f"sysapproval={record_sys_id}^state=requested",
            "sysparm_limit": 1,
            "sysparm_fields": "sys_id,state,approver,sysapproval,sys_updated_on",
            "sysparm_display_value": "true",
            "sysparm_exclude_reference_link": "true",
        },
    )
    pending = approvals.get("result", [])
    if not pending:
        return {
            "approved": False,
            "reason": "no_pending_approval",
            "table": table,
            "number": record_number,
            "record": record,
        }

    approval = pending[0]
    approval_sys_id = str(approval.get("sys_id", "")).strip()
    if not approval_sys_id:
        return {
            "approved": False,
            "reason": "approval_sys_id_missing",
            "table": table,
            "number": record_number,
            "record": record,
            "approval": approval,
        }

    payload: dict[str, Any] = {"state": "approved"}
    cleaned_comments = (comments or "").strip()
    if cleaned_comments:
        payload["comments"] = cleaned_comments

    updated = await sn_patch(f"/api/now/table/sysapproval_approver/{approval_sys_id}", payload)

    return {
        "approved": True,
        "table": table,
        "number": record_number,
        "record_sys_id": record_sys_id,
        "approval_sys_id": approval_sys_id,
        "updated_approval": updated.get("result", updated),
    }


if __name__ == "__main__":
    mcp.run(transport="stdio")
'@

$serverScript = $serverTemplate
$serverScript = $serverScript.Replace("__SN_BASE__", (Convert-ToPythonStringLiteral -Value $SN_BASE))
$serverScript = $serverScript.Replace("__SN_CLIENT_ID__", (Convert-ToPythonStringLiteral -Value $SN_CLIENT_ID))
$serverScript = $serverScript.Replace("__SN_SCOPE__", (Convert-ToPythonStringLiteral -Value $SN_SCOPE))
$serverScript = $serverScript.Replace("__SN_REDIRECT_URI__", (Convert-ToPythonStringLiteral -Value $SN_REDIRECT_URI))
$serverScript = $serverScript.Replace("__TOKENS_FILE__", (Convert-ToPythonStringLiteral -Value $TOKENS_FILE))
$serverScript = $serverScript.Replace("__MCP_SERVER_NAME__", (Convert-ToPythonStringLiteral -Value $MCP_SERVER_NAME))

Set-Content -LiteralPath $MCP_SCRIPT -Value $serverScript -Encoding UTF8

### ---------------------------------------------------------------------------
### Register MCP in user scope
### ---------------------------------------------------------------------------
$claudePath = $null
$claudeOverride = Get-ConfigValue -Name "CLAUDE_BIN" -DefaultValue ""
if (-not [string]::IsNullOrWhiteSpace($claudeOverride)) {
    $claudePath = $claudeOverride
} else {
    $claudeCmd = Get-Command -Name "claude" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -ne $claudeCmd) {
        $claudePath = $claudeCmd.Path
    } else {
        $fallbacks = @(
            (Join-Path $TargetHome ".local\bin\claude.exe"),
            (Join-Path $TargetHome ".local\bin\claude.cmd"),
            (Join-Path $TargetHome ".local\bin\claude")
        )
        foreach ($item in $fallbacks) {
            if (Test-Path -LiteralPath $item) {
                $claudePath = $item
                break
            }
        }
    }
}

if ([string]::IsNullOrWhiteSpace($claudePath)) {
    throw "Claude binary not found. Ensure Claude Code is installed and available as 'claude'."
}

Write-Log "Registering MCP server in user scope"
try {
    & $claudePath "mcp" "remove" "-s" "user" $MCP_SERVER_NAME 2>$null
} catch {
    # Ignore remove errors.
}

& $claudePath "mcp" "add" "-s" "user" $MCP_SERVER_NAME "--" $VENV_PYTHON $MCP_SCRIPT
if ($LASTEXITCODE -ne 0) {
    throw "Failed to register MCP server with Claude."
}

Write-Log "Done."
Write-Log "ServiceNow MCP is now available from Claude in any working directory."
Write-Log "First time they call a ServiceNow tool, browser login will open for PKCE."
