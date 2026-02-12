#!/usr/bin/env bash
set -euo pipefail

################################################################################
# Script Name: Claude Linear MCP Setup (macOS)
#
# Description:
#   If Claude Code is installed, automatically registers the Linear MCP server,
#   then opens a second Terminal session to launch Claude and prepare `/mcp`
#   so the user can complete OAuth authorization.
#
# Requirements:
#   - Claude Code already installed
#   - User logged in to macOS GUI
#
################################################################################

### ---------------------------------------------------------------------------
### Resolve logged-in user (Jamf-safe)
### ---------------------------------------------------------------------------
TARGET_USER="$(stat -f '%Su' /dev/console 2>/dev/null || true)"
if [[ -z "$TARGET_USER" || "$TARGET_USER" == "root" ]]; then
  echo "ERROR: No active console user found"
  exit 1
fi

TARGET_HOME="$(dscl . -read "/Users/$TARGET_USER" NFSHomeDirectory 2>/dev/null | awk '{print $2}')"
[[ -z "$TARGET_HOME" ]] && TARGET_HOME="/Users/$TARGET_USER"

INSTALL_BIN="$TARGET_HOME/Claude/claude"
CLAUDE_BIN="$INSTALL_BIN"

### ---------------------------------------------------------------------------
### Verify Claude Code exists
### ---------------------------------------------------------------------------
if [[ ! -x "$CLAUDE_BIN" ]]; then
  DETECTED_BIN="$(sudo -u "$TARGET_USER" -H /usr/bin/env PATH="$TARGET_HOME/Claude:$TARGET_HOME/.local/bin:/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin" /usr/bin/which claude 2>/dev/null || true)"
  if [[ -n "$DETECTED_BIN" && -x "$DETECTED_BIN" ]]; then
    CLAUDE_BIN="$DETECTED_BIN"
  else
    echo "Claude Code not installed for $TARGET_USER; skipping Linear MCP setup"
    exit 0
  fi
fi

### ---------------------------------------------------------------------------
### Check if Linear MCP already configured (idempotent)
### ---------------------------------------------------------------------------
if sudo -u "$TARGET_USER" "$CLAUDE_BIN" mcp list 2>/dev/null | grep -q "linear-server"; then
  echo "Linear MCP already configured; nothing to do"
  exit 0
fi

### ---------------------------------------------------------------------------
### Open Terminal and run MCP setup + Claude
### ---------------------------------------------------------------------------
DEFAULT_TERMINAL_BUNDLE_ID="$(sudo -u "$TARGET_USER" /usr/bin/defaults read \
  "$TARGET_HOME/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure" LSHandlers 2>/dev/null | \
  /usr/bin/awk '
    /LSHandlerContentType/ { ct=$3; gsub(/[;""]/, "", ct) }
    /LSHandlerRoleAll/ {
      ra=$3; gsub(/[;""]/, "", ra)
      if (ct=="public.shell-script" || ct=="public.unix-executable" || ct=="public.terminal") {
        print ra; exit
      }
    }
  '
)"

CLAUDE_CMD="$CLAUDE_BIN"
MCP_CMD="$CLAUDE_BIN mcp add --transport http linear-server https://mcp.linear.app/mcp"

if [[ "$DEFAULT_TERMINAL_BUNDLE_ID" == "com.googlecode.iterm2" ]]; then
  sudo -u "$TARGET_USER" osascript <<OSA
tell application id "com.googlecode.iterm2"
  activate
  set win1 to (create window with default profile)
  tell current session of win1 to write text "$MCP_CMD"
  delay 2
  set win2 to (create window with default profile)
  tell current session of win2 to write text "$CLAUDE_CMD"
  delay 1
  tell current session of win2 to write text "/mcp"
end tell
OSA
else
  sudo -u "$TARGET_USER" osascript <<OSA
tell application "Terminal"
  activate

  -- Window 1: register Linear MCP server
  set win1 to do script "$MCP_CMD"

  delay 2

  -- Window 2: launch Claude and pre-type /mcp
  set win2 to do script "$CLAUDE_CMD"
  delay 1
  do script "/mcp" in win2
end tell
OSA
fi

echo "Linear MCP setup initiated. User must complete OAuth approval."
