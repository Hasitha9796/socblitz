#!/bin/sh
# ─────────────────────────────────────────────────────────────────────────────
# SocBlitz Agent installer (macOS)
# Installs the Wazuh agent (SIEM telemetry: logs, FIM, SCA, vulnerability data)
# and enrolls it with this server. Supports Apple Silicon (arm64) and Intel.
#
# Note: the Velociraptor forensics component is not bundled for macOS in this
# build — only the SIEM agent is installed on macOS endpoints.
#
# Served pre-templated by the SocBlitz backend — placeholders are substituted
# at download time.
# ─────────────────────────────────────────────────────────────────────────────
set -eu

# Normally substituted by the backend at download time. Running the raw
# template instead? Set them via env:
#   SOCBLITZ_SERVER=1.2.3.4 SOCBLITZ_KEY=<enroll-key> sh socblitz-agent-install-macos.sh
SERVER="${SOCBLITZ_SERVER:-__SOCBLITZ_SERVER__}"
KEY="${SOCBLITZ_KEY:-__ENROLL_KEY__}"
WAZUH_VERSION="4.14.5"

log()  { printf '\033[1;36m[socblitz-agent]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[socblitz-agent] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

case "$SERVER$KEY" in *__*) fail "unsubstituted placeholders — download this script from the server instead:
  curl -fsSk \"http://<socblitz-host>:5000/api/v1/agent-deploy/install-macos.sh?key=<AGENT_ENROLL_KEY>\" | sudo sh
(or run the raw template with SOCBLITZ_SERVER=... SOCBLITZ_KEY=... set)";; esac

[ "$(id -u)" = "0" ] || fail "run as root (sudo)"
command -v curl >/dev/null 2>&1 || fail "curl is required"

case "$(uname -m)" in
  arm64)  PKG_ARCH="arm64"   ;;
  x86_64) PKG_ARCH="intel64" ;;
  *)      fail "unsupported architecture: $(uname -m)" ;;
esac

# ── Wazuh agent (macOS .pkg) ─────────────────────────────────────────────────
if [ -x /Library/Ossec/bin/wazuh-control ]; then
  log "Wazuh agent already installed — updating manager address only"
else
  PKG_URL="https://packages.wazuh.com/4.x/macos/wazuh-agent-${WAZUH_VERSION}-1.${PKG_ARCH}.pkg"
  TMP_DIR="$(mktemp -d)"
  TMP_PKG="${TMP_DIR}/wazuh-agent.pkg"
  log "Downloading Wazuh agent ${WAZUH_VERSION} (${PKG_ARCH})…"
  curl -fsSL "$PKG_URL" -o "$TMP_PKG" || fail "download failed: $PKG_URL"
  # The macOS .pkg reads enrollment settings from /tmp/wazuh_envs during install.
  echo "WAZUH_MANAGER='${SERVER}'" > /tmp/wazuh_envs
  log "Installing Wazuh agent…"
  installer -pkg "$TMP_PKG" -target / || fail "pkg install failed"
  rm -f /tmp/wazuh_envs
  rm -rf "$TMP_DIR"
fi

# Point the agent at the manager even on re-runs / pre-existing installs.
if [ -f /Library/Ossec/etc/ossec.conf ]; then
  # BSD sed needs the empty '' argument for in-place editing.
  sed -i '' "s|<address>[^<]*</address>|<address>${SERVER}</address>|" /Library/Ossec/etc/ossec.conf
fi

/Library/Ossec/bin/wazuh-control restart >/dev/null 2>&1 || /Library/Ossec/bin/wazuh-control start

log "──────────────────────────────────────────────────────"
log "SocBlitz Agent (Wazuh) installed on $(hostname)"
log "  SIEM → enrolled to ${SERVER}:1514/1515"
log "It will appear in the SocBlitz UI (Agents) within ~1 minute."
