#!/bin/sh
# ─────────────────────────────────────────────────────────────────────────────
# SocBlitz Agent installer (Linux)
# One command installs BOTH endpoint components and enrolls them automatically:
#   · Wazuh agent          → SIEM telemetry (logs, FIM, SCA, vulnerability data)
#   · Velociraptor client  → DFIR forensics (artifact collection)
# Both are grouped under the systemd target `socblitz-agent.target`, so the
# host sees a single "SocBlitz Agent":  systemctl status socblitz-agent.target
#
# Served pre-templated by the SocBlitz backend — placeholders are substituted
# at download time.
# ─────────────────────────────────────────────────────────────────────────────
set -eu

# Normally these are substituted by the backend when you download the script.
# Running the raw template instead? Set them via env:
#   SOCBLITZ_SERVER=1.2.3.4 SOCBLITZ_KEY=<enroll-key> sh socblitz-agent-install.sh
SERVER="${SOCBLITZ_SERVER:-__SOCBLITZ_SERVER__}"
KEY="${SOCBLITZ_KEY:-__ENROLL_KEY__}"
BASE="http://${SERVER}:5000/api/v1/agent-deploy"
WAZUH_VERSION="4.14.5"

log()  { printf '\033[1;36m[socblitz-agent]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[socblitz-agent] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

case "$SERVER$KEY" in *__*) fail "unsubstituted placeholders — download this script from the server instead:
  curl -fsSk \"http://<socblitz-host>:5000/api/v1/agent-deploy/install.sh?key=<AGENT_ENROLL_KEY>\" | sudo sh
(or run the raw template with SOCBLITZ_SERVER=... SOCBLITZ_KEY=... set)";; esac

[ "$(id -u)" = "0" ] || fail "run as root (sudo)"
command -v curl >/dev/null 2>&1 || fail "curl is required"

ARCH=$(uname -m)
[ "$ARCH" = "x86_64" ] || [ "$ARCH" = "amd64" ] || fail "only x86_64 supported for now (got $ARCH)"

HAS_SYSTEMD=0
[ -d /run/systemd/system ] && HAS_SYSTEMD=1

# ── 1. Wazuh agent ───────────────────────────────────────────────────────────
if [ -x /var/ossec/bin/wazuh-control ]; then
  log "Wazuh agent already installed — skipping package install"
elif command -v apt-get >/dev/null 2>&1; then
  log "Installing Wazuh agent ${WAZUH_VERSION} (apt)…"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq >/dev/null 2>&1 || true
  apt-get install -y -qq gnupg >/dev/null 2>&1 || true
  curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH \
    | gpg --dearmor --yes -o /usr/share/keyrings/wazuh.gpg
  echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
    > /etc/apt/sources.list.d/wazuh.list
  apt-get update -qq
  WAZUH_MANAGER="$SERVER" apt-get install -y "wazuh-agent=${WAZUH_VERSION}-1"
elif command -v yum >/dev/null 2>&1 || command -v dnf >/dev/null 2>&1; then
  log "Installing Wazuh agent ${WAZUH_VERSION} (yum/dnf)…"
  rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
  cat > /etc/yum.repos.d/wazuh.repo <<'EOF'
[wazuh]
name=Wazuh repository
baseurl=https://packages.wazuh.com/4.x/yum/
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
EOF
  PKG=$(command -v dnf || command -v yum)
  WAZUH_MANAGER="$SERVER" "$PKG" install -y "wazuh-agent-${WAZUH_VERSION}"
else
  fail "no supported package manager found (apt/yum/dnf)"
fi

# Point the agent at the manager even on re-runs / pre-existing installs.
sed -i "s|<address>[^<]*</address>|<address>${SERVER}</address>|" /var/ossec/etc/ossec.conf

# ── 2. Velociraptor client ───────────────────────────────────────────────────
log "Installing Velociraptor client (binary + config from SocBlitz server)…"
curl -fsSk "${BASE}/velociraptor-linux-amd64?key=${KEY}" -o /usr/local/bin/velociraptor
chmod 755 /usr/local/bin/velociraptor
mkdir -p /etc/velociraptor
curl -fsSk "${BASE}/velociraptor.config.yaml?key=${KEY}" -o /etc/velociraptor/client.config.yaml
chmod 600 /etc/velociraptor/client.config.yaml

# ── 3. Register as ONE agent: socblitz-agent.target ─────────────────────────
if [ "$HAS_SYSTEMD" = "1" ]; then
  cat > /etc/systemd/system/velociraptor-client.service <<'EOF'
[Unit]
Description=Velociraptor client (SocBlitz Agent forensics component)
After=network.target
PartOf=socblitz-agent.target

[Service]
ExecStart=/usr/local/bin/velociraptor --config /etc/velociraptor/client.config.yaml client --quiet
Restart=always
RestartSec=10
LimitNOFILE=20000

[Install]
WantedBy=socblitz-agent.target
EOF

  cat > /etc/systemd/system/socblitz-agent.target <<'EOF'
[Unit]
Description=SocBlitz Agent (Wazuh SIEM + Velociraptor forensics)
Wants=wazuh-agent.service velociraptor-client.service

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable wazuh-agent velociraptor-client socblitz-agent.target >/dev/null 2>&1
  systemctl restart socblitz-agent.target
  log "Services started under socblitz-agent.target"
else
  # Containers / WSL / no-systemd hosts: start processes directly.
  log "No systemd detected — starting components directly"
  /var/ossec/bin/wazuh-control restart || /var/ossec/bin/wazuh-control start
  pkill -f 'velociraptor.*client' 2>/dev/null || true
  nohup /usr/local/bin/velociraptor --config /etc/velociraptor/client.config.yaml client --quiet \
    > /var/log/velociraptor-client.log 2>&1 &
fi

log "──────────────────────────────────────────────────────"
log "SocBlitz Agent installed on $(hostname)"
log "  SIEM      → Wazuh agent enrolled to ${SERVER}:1514/1515"
log "  Forensics → Velociraptor client enrolled to ${SERVER}:8010"
log "It will appear in the SocBlitz UI (Agents + Forensics) within ~1 minute."
