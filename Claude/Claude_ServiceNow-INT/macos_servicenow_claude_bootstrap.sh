#!/usr/bin/env bash
set -euo pipefail

################################################################################
# Script Name: ServiceNow MCP Setup (PROD only, Jamf-safe)
# Purpose:
#   - Ensure Python >= 3.11 is available (installs python.org pkg if needed)
#   - Create per-user venv under ~/.servicenow_mcp
#   - Install deps (httpx + mcp) into that venv
#   - Write PROD-only ServiceNow MCP server (PKCE login + auto refresh)
#   - Register MCP in user scope so Claude can run from any directory
#
# Assumptions:
#   - Claude Code is already installed by your existing script
#   - Claude binary is available at: ~/.local/bin/claude
################################################################################

### ---------------------------------------------------------------------------
### REQUIRED PROJECT CONFIG (set these for your environment/GitHub repo)
### ---------------------------------------------------------------------------
SN_BASE="${SN_BASE:-https://INSTANCE.servicenowservices.com}"
SN_CLIENT_ID="${SN_CLIENT_ID:-INPUT_ID}"
# Must include write-capable auth scope if using approval tools (PATCH sysapproval_approver).
SN_SCOPE="${SN_SCOPE:-incident_read}"
SN_REDIRECT_URI="${SN_REDIRECT_URI:-http://localhost:8765/callback}"
SN_TOKEN_FILE_NAME="${SN_TOKEN_FILE_NAME:-.servicenow_prod_tokens.json}"
MCP_SERVER_NAME="${MCP_SERVER_NAME:-servicenow}"

### ---------------------------------------------------------------------------
### User targeting (Jamf-safe)
### ---------------------------------------------------------------------------
TARGET_USER="${SUDO_USER:-$(stat -f '%Su' /dev/console 2>/dev/null || true)}"
if [[ -z "$TARGET_USER" || "$TARGET_USER" == "root" ]]; then
  echo "ERROR: No active console user found"
  exit 1
fi

TARGET_HOME="$(dscl . -read "/Users/$TARGET_USER" NFSHomeDirectory 2>/dev/null | awk '{print $2}')"
[[ -z "$TARGET_HOME" ]] && TARGET_HOME="/Users/$TARGET_USER"

CLAUDE_BIN="$TARGET_HOME/.local/bin/claude"

if [[ ! -x "$CLAUDE_BIN" ]]; then
  echo "ERROR: Claude binary not found at $CLAUDE_BIN"
  exit 1
fi

### ---------------------------------------------------------------------------
### Runtime paths/config
### ---------------------------------------------------------------------------
MCP_DIR="$TARGET_HOME/.servicenow_mcp"
VENV_DIR="$MCP_DIR/venv"
MCP_SCRIPT="$MCP_DIR/servicenow_mcp.py"
TOKENS_FILE="$TARGET_HOME/$SN_TOKEN_FILE_NAME"


### ---------------------------------------------------------------------------
### Helpers
### ---------------------------------------------------------------------------
log() { echo "[servicenow-mcp] $*"; }

as_user() {
  # run a command as the target user with sane env
  sudo -u "$TARGET_USER" -H /usr/bin/env \
    PATH="$TARGET_HOME/.local/bin:/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin" \
    "$@"
}

# Only clear token cache if it's invalid or expired
log "Checking existing token cache: $TOKENS_FILE"
if [[ -f "$TOKENS_FILE" ]]; then
  # Check if token is expired (simple check - just see if file is readable)
  if ! as_user python3 -c "import json; f=open('$TOKENS_FILE'); d=json.load(f); import time; exit(0 if time.time() < d.get('expires_at', 0) else 1)" 2>/dev/null; then
    log "Token is expired or invalid, removing: $TOKENS_FILE"
    as_user rm -f "$TOKENS_FILE"
  else
    log "Token is still valid, keeping cached credentials"
  fi
fi

### ---------------------------------------------------------------------------
### Ensure Python >= 3.11 (prefers Homebrew, else python.org pkg install)
### ---------------------------------------------------------------------------
choose_python() {
  local candidates=(
    "/opt/homebrew/bin/python3"
    "/usr/local/bin/python3"
    "/Library/Frameworks/Python.framework/Versions/Current/bin/python3"
    "/usr/bin/python3"
  )

  for p in "${candidates[@]}"; do
    if [[ -x "$p" ]]; then
      local v
      v="$("$p" -c 'import sys; print(".".join(map(str, sys.version_info[:3])))' 2>/dev/null || true)"
      if [[ -n "$v" ]]; then
        echo "$p|$v"
        return 0
      fi
    fi
  done
  return 1
}

PY_PICK="$(choose_python || true)"
PY_BIN="${PY_PICK%%|*}"
PY_VER="${PY_PICK#*|}"

install_python_org_pkg() {
  # Installs python.org pkg (universal) if needed.
  # NOTE: This requires the Mac to have network access. Jamf typically does.
  # We install to system location; then we use it only to create a per-user venv.
  local PKG_URL="https://www.python.org/ftp/python/3.12.8/python-3.12.8-macos11.pkg"
  local PKG_PATH="/tmp/python-3.12.8-macos11.pkg"

  log "Installing Python via python.org pkg (3.12.8)..."
  curl -fsSL "$PKG_URL" -o "$PKG_PATH"
  /usr/sbin/installer -pkg "$PKG_PATH" -target /
  rm -f "$PKG_PATH"
}

# packaging may not exist on system python; avoid that dependency.
# We'll compare major/minor directly in bash.
py_is_modern_enough() {
  local bin="$1"
  local mm
  mm="$("$bin" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || true)"
  [[ -z "$mm" ]] && return 1
  local major="${mm%%.*}"
  local minor="${mm#*.}"
  if (( major > 3 )); then return 0; fi
  if (( major < 3 )); then return 1; fi
  (( minor >= 11 ))
}

if [[ -z "${PY_BIN:-}" || ! -x "${PY_BIN:-/nope}" ]]; then
  log "No python3 detected. Installing python.org Python..."
  install_python_org_pkg
  PY_PICK="$(choose_python || true)"
  PY_BIN="${PY_PICK%%|*}"
  PY_VER="${PY_PICK#*|}"
fi

if [[ -z "${PY_BIN:-}" || ! -x "${PY_BIN:-/nope}" ]]; then
  log "ERROR: Python install failed or python3 not found."
  exit 1
fi

if ! py_is_modern_enough "$PY_BIN"; then
  log "Detected Python is too old ($PY_BIN => $PY_VER). Installing python.org Python..."
  install_python_org_pkg
  PY_PICK="$(choose_python || true)"
  PY_BIN="${PY_PICK%%|*}"
  PY_VER="${PY_PICK#*|}"

  if [[ -z "${PY_BIN:-}" || ! -x "${PY_BIN:-/nope}" ]]; then
    log "ERROR: Python install failed or python3 not found after install."
    exit 1
  fi
  if ! py_is_modern_enough "$PY_BIN"; then
    log "ERROR: Still not seeing Python >= 3.11 after install. Found: $PY_BIN => $PY_VER"
    exit 1
  fi
fi

log "Using Python: $PY_BIN ($PY_VER)"

### ---------------------------------------------------------------------------
### Create MCP workspace + venv
### ---------------------------------------------------------------------------
py_major_minor() {
  local bin="$1"
  "$bin" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || true
}

SELECTED_PY_MM="$(py_major_minor "$PY_BIN")"

log "Creating MCP directory: $MCP_DIR"
as_user mkdir -p "$MCP_DIR"

if [[ -x "$VENV_DIR/bin/python" ]]; then
  EXISTING_VENV_MM="$(as_user "$VENV_DIR/bin/python" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || true)"
  if [[ -z "$EXISTING_VENV_MM" ]]; then
    log "Existing venv is unreadable. Recreating: $VENV_DIR"
    rm -rf "$VENV_DIR"
  elif [[ "$EXISTING_VENV_MM" != "$SELECTED_PY_MM" ]]; then
    log "Existing venv uses Python $EXISTING_VENV_MM; expected $SELECTED_PY_MM. Recreating."
    rm -rf "$VENV_DIR"
  elif ! as_user "$VENV_DIR/bin/python" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)'; then
    log "Existing venv Python is older than 3.11. Recreating: $VENV_DIR"
    rm -rf "$VENV_DIR"
  fi
fi

log "Creating virtual environment: $VENV_DIR"
as_user "$PY_BIN" -m venv "$VENV_DIR"

VENV_PY_MM="$(as_user "$VENV_DIR/bin/python" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
if [[ "$VENV_PY_MM" != "$SELECTED_PY_MM" ]]; then
  log "ERROR: Venv Python mismatch (venv=$VENV_PY_MM, selected=$SELECTED_PY_MM)."
  exit 1
fi

log "Upgrading pip + installing dependencies into venv"
as_user "$VENV_DIR/bin/python" -m pip install --upgrade pip
as_user "$VENV_DIR/bin/python" -m pip install --upgrade httpx mcp

### ---------------------------------------------------------------------------
### Write ServiceNow MCP server (PROD, PKCE + refresh)
### ---------------------------------------------------------------------------
log "Writing MCP server script: $MCP_SCRIPT"

cat > "$MCP_SCRIPT" <<PYEOF
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

# Setup basic logging
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s: %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("servicenow-mcp")

SERVICENOW_BASE = "${SN_BASE}"
CLIENT_ID = "${SN_CLIENT_ID}"
SCOPE = "${SN_SCOPE}"
REDIRECT_URI = "${SN_REDIRECT_URI}"
TOKEN_FILE = os.path.expanduser("${TOKENS_FILE}")
MCP_SERVER_NAME = "${MCP_SERVER_NAME}"

# Hardened timeouts
HTTP_TIMEOUT = httpx.Timeout(connect=10.0, read=30.0, write=30.0, pool=30.0)

mcp = FastMCP(MCP_SERVER_NAME)


# -----------------------------
# PKCE helpers
# -----------------------------
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
        # Suppress noisy logs
        return


def wait_for_code(expected_state: str, port: int = 8765, timeout_s: int = 180) -> str:
    server = http.server.HTTPServer(("localhost", port), OAuthHandler)

    def _serve_one():
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

    # Verify state parameter to prevent CSRF
    if OAuthHandler.received_state != expected_state:
        raise RuntimeError(
            f"OAuth state mismatch (expected: {expected_state}, got: {OAuthHandler.received_state}). "
            "Possible CSRF attack."
        )

    return OAuthHandler.auth_code


# -----------------------------
# Token persistence
# -----------------------------
def load_tokens() -> Optional[dict[str, Any]]:
    try:
        if not os.path.exists(TOKEN_FILE):
            return None
        with open(TOKEN_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return None
    except json.JSONDecodeError as e:
        logger.error(f"Token file is corrupted: {e}")
        return None
    except PermissionError as e:
        logger.error(f"Cannot read token file (permission denied): {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error loading tokens: {e}")
        return None


def save_tokens(tokens: dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(TOKEN_FILE), exist_ok=True)
    tmp = TOKEN_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(tokens, f)
    os.replace(tmp, TOKEN_FILE)

    # Secure token file permissions
    try:
        os.chmod(TOKEN_FILE, 0o600)
    except Exception as e:
        logger.error(f"WARNING: Failed to secure token file permissions: {e}")
        logger.error("Token file may be readable by other users!")


# -----------------------------
# OAuth flows
# -----------------------------
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
    logger.info("Authentication successful, tokens saved")
    return token_data


async def oauth_refresh_flow(refresh_token: str) -> dict[str, Any]:
    logger.info("Refreshing access token...")
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
    logger.info("Token refresh successful")
    return token_data


async def get_access_token() -> str:
    tokens = load_tokens()
    if not tokens:
        logger.info("No cached tokens found, starting OAuth flow...")
        tokens = await oauth_authorize_code_flow()
        return tokens["access_token"]

    if time.time() < float(tokens.get("expires_at", 0)):
        return tokens["access_token"]

    rt = tokens.get("refresh_token")
    if rt:
        try:
            tokens = await oauth_refresh_flow(rt)
            return tokens["access_token"]
        except httpx.HTTPStatusError as e:
            logger.warning(f"Token refresh failed (HTTP {e.response.status_code}), re-authenticating...")
        except Exception as e:
            logger.warning(f"Token refresh failed ({type(e).__name__}: {e}), re-authenticating...")

    tokens = await oauth_authorize_code_flow()
    return tokens["access_token"]


# -----------------------------
# ServiceNow REST helpers
# -----------------------------
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


# -----------------------------
# MCP Tools
# -----------------------------
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
    logger.info(f"Fetching {limit} recent incidents...")
    data = await sn_get("/api/now/table/incident", incident_params(limit=limit))
    results = data.get("result", [])
    logger.info(f"Retrieved {len(results)} incidents")
    return results


@mcp.tool()
async def get_incident_by_number(number: str) -> dict[str, Any]:
    """Lookup a single incident by exact number, e.g. INC0013330."""
    incident_number = (number or "").strip().upper()
    if not incident_number:
        raise ValueError("Incident number is required")

    logger.info(f"Looking up incident: {incident_number}")
    data = await sn_get(
        "/api/now/table/incident",
        incident_params(limit=1, query=f"number={incident_number}"),
    )
    results = data.get("result", [])
    if not results:
        logger.info(f"Incident not found: {incident_number}")
        return {"found": False, "number": incident_number}

    logger.info(f"Incident found: {incident_number}")
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
    logger.info(f"Looking up record: {record_number} in table: {table}")

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

    logger.info(f"Approving {record_number} using approval record {approval_sys_id}")
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
PYEOF

chmod +x "$MCP_SCRIPT"
chown "$TARGET_USER":staff "$MCP_SCRIPT"

### ---------------------------------------------------------------------------
### Register MCP in user scope (works from any directory)
### ---------------------------------------------------------------------------
log "Registering MCP server in user scope"

as_user "$CLAUDE_BIN" mcp remove -s user "$MCP_SERVER_NAME" 2>/dev/null || true
as_user "$CLAUDE_BIN" mcp add -s user "$MCP_SERVER_NAME" --   "$VENV_DIR/bin/python"   "$MCP_SCRIPT"

log "Done."
log "ServiceNow MCP is now available from Claude in any working directory."
log "First time they call a ServiceNow tool, browser login will open for PKCE."
