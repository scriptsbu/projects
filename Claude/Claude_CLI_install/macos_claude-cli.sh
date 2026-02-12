#!/usr/bin/env bash
set -euo pipefail

################################################################################
# Script Name: Claude Code Setup (macOS, Jamf-safe)
# Purpose:
#   - Install / reinstall Claude Code (official installer)
#   - Prompt user for API key, model, max tokens (UI)
#   - Persist config to ~/.config/claude/env
#   - NEVER shadow the claude binary
################################################################################

### ---------------------------------------------------------------------------
### User targeting (Jamf-safe)
### ---------------------------------------------------------------------------
TARGET_USER="${SUDO_USER:-$(stat -f '%Su' /dev/console 2>/dev/null || true)}"
if [[ -z "$TARGET_USER" || "$TARGET_USER" == "root" ]]; then
  echo "ERROR: No active console user found"
  exit 1
fi

TARGET_HOME=$(dscl . -read "/Users/$TARGET_USER" NFSHomeDirectory 2>/dev/null | awk '{print $2}')
[[ -z "$TARGET_HOME" ]] && TARGET_HOME="/Users/$TARGET_USER"

CONFIG_DIR="$TARGET_HOME/.config/claude"
ENV_FILE="$CONFIG_DIR/env"
INSTALL_DIR="$TARGET_HOME/Claude"
INSTALL_BIN="$INSTALL_DIR/claude"
CLAUDE_BIN="$TARGET_HOME/.local/bin/claude"
LOGO_PATH="PATH-TO-YOUR-LOGO"
JAMF_PROMPT="${4:-true}"

debug() {
  if [[ "${DEBUG:-0}" == "1" ]]; then
    echo "DEBUG: $*"
  fi
}

tolower() {
  echo "$1" | tr '[:upper:]' '[:lower:]'
}

is_truthy() {
  case "$(tolower "$1")" in
    1|true|yes|y|on) return 0 ;;
    *) return 1 ;;
  esac
}

is_falsy() {
  case "$(tolower "$1")" in
    0|false|no|n|off) return 0 ;;
    *) return 1 ;;
  esac
}

if ! is_truthy "$JAMF_PROMPT" && ! is_falsy "$JAMF_PROMPT"; then
  echo "ERROR: JAMF parameter 4 must be true/false (on/off). Got: $JAMF_PROMPT"
  exit 1
fi

### ---------------------------------------------------------------------------
### Remove legacy shell-function based claude (critical safety)
### ---------------------------------------------------------------------------
for rc in "$TARGET_HOME/.zshrc" "$TARGET_HOME/.bashrc" "$TARGET_HOME/.zprofile"; do
  [[ -f "$rc" ]] || continue
  if grep -q "claude () {" "$rc"; then
    echo "Removing legacy claude shell function from $rc"
    sed -i '' '/claude () {/,/}/d' "$rc"
  fi
done

### ---------------------------------------------------------------------------
### Install / reinstall Claude Code
### ---------------------------------------------------------------------------
mkdir -p "$TARGET_HOME/.local/bin" "$INSTALL_DIR"
chown "$TARGET_USER":staff "$TARGET_HOME/.local" "$TARGET_HOME/.local/bin" "$INSTALL_DIR"

if [[ -x "$CLAUDE_BIN" ]]; then
  echo "Claude Code detected – reinstalling to ensure clean state"
  rm -f "$CLAUDE_BIN"
fi

if [[ -x "$INSTALL_BIN" ]]; then
  echo "Claude Code detected in $INSTALL_DIR – reinstalling to ensure clean state"
  rm -f "$INSTALL_BIN"
fi

echo "Installing Claude Code…"
debug "TARGET_USER=$TARGET_USER"
debug "TARGET_HOME=$TARGET_HOME"
debug "INSTALL_DIR=$INSTALL_DIR"
debug "INSTALL_BIN=$INSTALL_BIN"
debug "CLAUDE_BIN=$CLAUDE_BIN"
curl -fsSL https://claude.ai/install.sh | sudo -u "$TARGET_USER" -H bash

DETECTED_BIN=""
if [[ -x "$CLAUDE_BIN" ]]; then
  DETECTED_BIN="$CLAUDE_BIN"
else
  DETECTED_BIN="$(sudo -u "$TARGET_USER" -H /usr/bin/env PATH="$TARGET_HOME/.local/bin:/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin" /usr/bin/which claude 2>/dev/null || true)"
fi
debug "DETECTED_BIN=$DETECTED_BIN"

if [[ -z "$DETECTED_BIN" || ! -x "$DETECTED_BIN" ]]; then
  echo "ERROR: Claude Code install failed"
  exit 1
fi

if [[ "$DETECTED_BIN" == "$TARGET_HOME/Claude/Claude/claude" ]]; then
  echo "Nested Claude install detected; moving binary up one level"
  mkdir -p "$INSTALL_DIR"
  mv -f "$DETECTED_BIN" "$INSTALL_BIN"
  chown "$TARGET_USER":staff "$INSTALL_BIN"
  rmdir "$TARGET_HOME/Claude/Claude" 2>/dev/null || true
elif [[ "$DETECTED_BIN" != "$INSTALL_BIN" ]]; then
  mv -f "$DETECTED_BIN" "$INSTALL_BIN"
  chown "$TARGET_USER":staff "$INSTALL_BIN"
fi

ln -sf "$INSTALL_BIN" "$CLAUDE_BIN"
chown "$TARGET_USER":staff "$CLAUDE_BIN"

### ---------------------------------------------------------------------------
### Ensure PATH includes ~/.local/bin
### ---------------------------------------------------------------------------
for file in "$TARGET_HOME/.zprofile" "$TARGET_HOME/.zshrc"; do
  if ! grep -q 'export PATH="$HOME/.local/bin:$PATH"' "$file" 2>/dev/null; then
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$file"
  fi
done

### ---------------------------------------------------------------------------
### Post-install message (Jamf-friendly)
### ---------------------------------------------------------------------------
sudo -u "$TARGET_USER" osascript <<OSA
set logoPath to "$LOGO_PATH"
set hasIcon to false
try
  do shell script "test -f " & quoted form of logoPath
  set iconAlias to (POSIX file logoPath) as alias
  set hasIcon to true
end try

set msgText to "Claude installation finished." & return & return & ¬
  "Open a new Terminal and type: claude" & return & return & ¬
  "Choose option 2: \"Anthropic Console account • API usage billing\" to set up."

if hasIcon then
  display dialog msgText buttons {"OK"} default button "OK" with title "Claude Setup" with icon iconAlias
else
  display dialog msgText buttons {"OK"} default button "OK" with title "Claude Setup"
end if
OSA

### ---------------------------------------------------------------------------
### Prompt user (Saronic-branded UI)
### ---------------------------------------------------------------------------
if is_truthy "$JAMF_PROMPT"; then
  UI_RESULT=$(sudo -u "$TARGET_USER" osascript <<OSA
set logoPath to "$LOGO_PATH"
set hasIcon to false
try
  do shell script "test -f " & quoted form of logoPath
  set iconAlias to (POSIX file logoPath) as alias
  set hasIcon to true
end try

set modelList to {"claude-sonnet-4-20250514", "claude-opus-4-20250514", "claude-haiku-4-20250514", "View Pricing Chart…"}

set pricingText to "Model pricing (USD per 1M tokens) + use cases:" & return & ¬
  "Opus 4.5: in $5 / out $25 — Peak reasoning" & return & ¬
  "Sonnet 4.5: in $3 / out $15 — Balanced" & return & ¬
  "Haiku 4.5: in $1 / out $5 — Fast prompts" & return & return & ¬
  "Typical output sizes:" & return & ¬
  "Short: 200–500" & return & ¬
  "Normal: 700–1500" & return & ¬
  "Long: 2000–4000" & return & ¬
  "Very long: 6000+ (costly)"

repeat
  set chosenModel to choose from list modelList with title "Claude Setup" with prompt "Select a model:"
  if chosenModel is false then return "CANCELLED"
  if (item 1 of chosenModel) is "View Pricing Chart…" then
    if hasIcon then
      display dialog pricingText buttons {"Continue"} with title "Claude Setup" with icon iconAlias
    else
      display dialog pricingText buttons {"Continue"} with title "Claude Setup"
    end if
  else
    exit repeat
  end if
end repeat

if hasIcon then
  set keyDlg to display dialog "Create your key at: https://platform.claude.com/settings/keys" & return & "Enter your Anthropic API key:" default answer "" with hidden answer with title "Claude Setup" with icon iconAlias
else
  set keyDlg to display dialog "Enter your Anthropic API key:" default answer "" with hidden answer with title "Claude Setup"
end if

set apiKey to text returned of keyDlg

set tokDlg to display dialog "Max tokens:" default answer "700" with title "Claude Setup"
set maxTokens to text returned of tokDlg

return (item 1 of chosenModel) & "||" & apiKey & "||" & maxTokens
OSA
)

  [[ "$UI_RESULT" == "CANCELLED" ]] && exit 0

  MODEL="${UI_RESULT%%||*}"
  REST="${UI_RESULT#*||}"
  ANTHROPIC_API_KEY="${REST%%||*}"
  MAX_TOKENS="${REST#*||}"
else
  echo "Jamf prompt disabled (parameter 4 = false). Skipping API/model/token setup."
  echo "You can configure API settings later by running 'claude' in Terminal."
  exit 0
fi

### ---------------------------------------------------------------------------
### Validate API key
### ---------------------------------------------------------------------------
[[ -z "$ANTHROPIC_API_KEY" ]] && { echo "ERROR: Empty API key"; exit 1; }
[[ ! "$MAX_TOKENS" =~ ^[0-9]+$ ]] && { echo "ERROR: Invalid token count"; exit 1; }
[[ -z "$MODEL" ]] && { echo "ERROR: Empty model"; exit 1; }

HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -H "anthropic-version: 2023-06-01" \
  https://api.anthropic.com/v1/models)

[[ "$HTTP_STATUS" != "200" ]] && {
  echo "ERROR: API key validation failed"
  exit 1
}

### ---------------------------------------------------------------------------
### Persist env (ONLY responsibility)
### ---------------------------------------------------------------------------
mkdir -p "$CONFIG_DIR"
cat > "$ENV_FILE" <<EOF_ENV
export ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY"
export ANTHROPIC_MODEL="$MODEL"
export ANTHROPIC_MAX_TOKENS="$MAX_TOKENS"
EOF_ENV

chmod 600 "$ENV_FILE"
chown -R "$TARGET_USER":staff "$CONFIG_DIR"

### ---------------------------------------------------------------------------
### Ensure env is sourced for interactive shells
### ---------------------------------------------------------------------------
for file in "$TARGET_HOME/.zprofile" "$TARGET_HOME/.zshrc"; do
  grep -q "source $ENV_FILE" "$file" 2>/dev/null || echo "source $ENV_FILE" >> "$file"
done

### ---------------------------------------------------------------------------
### Final status (Jamf-safe)
### ---------------------------------------------------------------------------
echo
echo "Claude Code installed correctly."
echo "Config file: $ENV_FILE"
echo "Binary: $INSTALL_BIN"
echo "Ready for interactive use and MCP integration."
echo
