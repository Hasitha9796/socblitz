#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# SocBlitz VM install assistant — native (non-Docker) installation.
#
# Modeled on Wazuh's wazuh-install.sh: one script, role flags.
#
#   All-in-one (single VM, ≤ ~500 endpoints):
#     sudo bash socblitz-install.sh -a
#
#   Distributed (one role per VM — see deployment/vm/README.md):
#     sudo bash socblitz-install.sh -g                      # certs + secrets tarball
#     sudo bash socblitz-install.sh --wazuh-indexer NAME    # per indexer host
#     sudo bash socblitz-install.sh --start-cluster         # once, on one indexer
#     sudo bash socblitz-install.sh --wazuh-server NAME     # master + each worker
#     sudo bash socblitz-install.sh --load-balancer         # LB host
#     sudo bash socblitz-install.sh --app-tier              # SocBlitz app host
#
# Supported OS: Ubuntu 22.04/24.04, Debian 12 (apt-based, systemd).
# The app-tier / all-in-one roles must run from inside a repo checkout
# (this script lives at <repo>/deployment/vm/). Wazuh-only roles can run
# standalone next to the generated socblitz-install-files.tar.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

WAZUH_VERSION="4.14.5"
WAZUH_MAJOR="4.14"
NODE_MAJOR="20"
CLUSTER_NAME="socblitz-wazuh"
TAR_NAME="socblitz-install-files.tar"

SB_HOME="/opt/socblitz"
SB_ETC="/etc/socblitz"
PASSFILE="$SB_ETC/socblitz-passwords.txt"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." 2>/dev/null && pwd || echo "")"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${GREEN}[✓]${NC} $1"; }
warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
die()     { echo -e "${RED}[✗]${NC} $1" >&2; exit 1; }
section() { echo -e "\n${CYAN}━━━ $1 ━━━${NC}"; }

# ── Generic helpers ──────────────────────────────────────────────────────────

need_root() { [ "$(id -u)" -eq 0 ] || die "run as root: sudo bash $0 $*"; }

check_os() {
    command -v apt-get >/dev/null || die "apt-based OS required (Ubuntu 22.04/24.04, Debian 12)"
    command -v systemctl >/dev/null || die "systemd required"
}

arch_deb() {
    case "$(uname -m)" in
        x86_64)  echo amd64 ;;
        aarch64) echo arm64 ;;
        *) die "unsupported architecture: $(uname -m)" ;;
    esac
}

# Wazuh API password policy: upper + lower + digit + symbol, 8-64 chars
randpw() { echo "Sb1!$(openssl rand -hex 12)"; }

record_pw() {  # record_pw <label> <value>
    mkdir -p "$SB_ETC"; touch "$PASSFILE"; chmod 600 "$PASSFILE"
    sed -i "/^$1=/d" "$PASSFILE"
    echo "$1=$2" >> "$PASSFILE"
}

wait_for() {  # wait_for <description> <timeout-seconds> <command...>
    local desc="$1" timeout="$2"; shift 2
    local waited=0
    echo -n "  waiting for $desc "
    until "$@" >/dev/null 2>&1; do
        sleep 5; waited=$((waited+5)); echo -n "."
        [ "$waited" -ge "$timeout" ] && { echo ""; return 1; }
    done
    echo " ready"
}

apt_install() { DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$@"; }

set_max_map_count() {
    if [ "$(sysctl -n vm.max_map_count 2>/dev/null || echo 0)" -lt 262144 ]; then
        sysctl -w vm.max_map_count=262144
        echo "vm.max_map_count=262144" > /etc/sysctl.d/99-socblitz.conf
    fi
}

# ── config.yml parsing (distributed mode) ────────────────────────────────────
# config.yml is the standard wazuh-certs-tool format (see config.yml.example).
# Emits lines: "<section> <name> <ip> <node_type>" — parsed into bash arrays.

parse_config() {  # parse_config <config.yml>
    python3 - "$1" <<'PYEOF'
import re, sys
section, cur = None, None
rows = []
def flush():
    if cur and cur.get("name"):
        rows.append((section, cur["name"], cur.get("ip", ""), cur.get("node_type", "-")))
for raw in open(sys.argv[1]):
    line = raw.split("#", 1)[0].rstrip()
    if not line.strip():
        continue
    m = re.match(r"^  (indexer|server|dashboard):\s*$", line)
    if m:
        flush(); cur = None; section = m.group(1); continue
    if re.match(r"^\S", line):        # top-level key (e.g. "nodes:")
        continue
    m = re.match(r"^\s*-\s+name:\s*(\S+)", line)
    if m:
        flush(); cur = {"name": m.group(1).strip('"')}; continue
    m = re.match(r"^\s*(ip|node_type):\s*(\S+)", line)
    if m and cur is not None:
        cur[m.group(1)] = m.group(2).strip('"')
flush()
for r in rows:
    print(" ".join(r))
PYEOF
}

INDEXER_NAMES=(); INDEXER_IPS=(); SERVER_NAMES=(); SERVER_IPS=(); SERVER_TYPES=()

load_config() {  # load_config <config.yml>
    [ -f "$1" ] || die "config file not found: $1"
    while read -r sec name ip ntype; do
        case "$sec" in
            indexer) INDEXER_NAMES+=("$name"); INDEXER_IPS+=("$ip") ;;
            server)  SERVER_NAMES+=("$name"); SERVER_IPS+=("$ip"); SERVER_TYPES+=("$ntype") ;;
        esac
    done < <(parse_config "$1")
    [ "${#INDEXER_NAMES[@]}" -gt 0 ] || die "no indexer nodes found in $1"
    [ "${#SERVER_NAMES[@]}" -gt 0 ] || die "no server nodes found in $1"
}

master_ip() {
    local i
    for i in "${!SERVER_NAMES[@]}"; do
        [ "${SERVER_TYPES[$i]}" = "master" ] && { echo "${SERVER_IPS[$i]}"; return; }
    done
    echo "${SERVER_IPS[0]}"   # single-server cluster: first entry is the master
}

# ── Install-files tarball (distributed mode) ────────────────────────────────

WORKDIR=""
load_tar() {
    [ -f "./$TAR_NAME" ] || die "./$TAR_NAME not found — generate it with '-g' and copy it to this host"
    WORKDIR="$(mktemp -d /tmp/socblitz-install.XXXXXX)"
    tar -xf "./$TAR_NAME" -C "$WORKDIR"
    # shellcheck disable=SC1091
    . "$WORKDIR/socblitz-cluster.env"
    load_config "$WORKDIR/config.yml"
}

# ── Wazuh apt repository ─────────────────────────────────────────────────────

add_wazuh_repo() {
    if [ ! -f /usr/share/keyrings/wazuh.gpg ]; then
        apt_install curl gnupg apt-transport-https ca-certificates
        curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH \
            | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
        echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
            > /etc/apt/sources.list.d/wazuh.list
    fi
    apt-get update -qq
}

apt_install_wazuh_pkg() {  # apt_install_wazuh_pkg <package>
    local pkg="$1" ver
    ver="$(apt-cache madison "$pkg" | awk -v v="$WAZUH_VERSION" 'index($3, v) == 1 {print $3; exit}')"
    if [ -n "$ver" ]; then
        apt_install "$pkg=$ver"
    else
        warn "$pkg $WAZUH_VERSION not in repo — installing latest available"
        apt_install "$pkg"
    fi
    apt-mark hold "$pkg" >/dev/null
}

# ── Certificates ─────────────────────────────────────────────────────────────

fetch_certs_tool() {
    [ -f "$1/wazuh-certs-tool.sh" ] || curl -fsSo "$1/wazuh-certs-tool.sh" \
        "https://packages.wazuh.com/$WAZUH_MAJOR/wazuh-certs-tool.sh"
}

# ── ossec.conf writers ───────────────────────────────────────────────────────

indexer_hosts_xml() {  # one <host> line per indexer IP
    local ip out=""
    for ip in "$@"; do out+="      <host>https://${ip}:9200</host>\n"; done
    printf '%b' "$out"
}

write_ossec_conf() {  # write_ossec_conf <mode:standalone|master|worker> <node_name> <app_ip> <master_ip> <indexer_ips...>
    local mode="$1" node_name="$2" app_ip="$3" masterip="$4"; shift 4
    local hosts_xml auth_xml cluster_xml
    hosts_xml="$(indexer_hosts_xml "$@")"

    if [ "$mode" = "worker" ]; then
        auth_xml='  <auth>
    <disabled>yes</disabled>
  </auth>'
    else
        auth_xml='  <auth>
    <disabled>no</disabled>
    <port>1515</port>
    <use_source_ip>no</use_source_ip>
    <purge>yes</purge>
    <use_password>no</use_password>
  </auth>'
    fi

    if [ "$mode" = "standalone" ]; then
        cluster_xml=""
    else
        cluster_xml="  <cluster>
    <name>${CLUSTER_NAME}</name>
    <node_name>${node_name}</node_name>
    <node_type>${mode}</node_type>
    <key>${CLUSTER_KEY}</key>
    <port>1516</port>
    <bind_addr>0.0.0.0</bind_addr>
    <nodes>
      <node>${masterip}</node>
    </nodes>
    <hidden>no</hidden>
    <disabled>no</disabled>
  </cluster>"
    fi

    cat > /var/ossec/etc/ossec.conf <<EOF
<!-- Wazuh Manager ${WAZUH_VERSION} — ${mode} node (SocBlitz VM install) -->
<ossec_config>

  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>no</logall>
    <logall_json>no</logall_json>
    <email_notification>no</email_notification>
    <agents_disconnection_time>10m</agents_disconnection_time>
    <agents_disconnection_alert_time>0</agents_disconnection_alert_time>
  </global>

  <alerts>
    <log_alert_level>3</log_alert_level>
    <email_alert_level>12</email_alert_level>
  </alerts>

  <indexer>
    <enabled>yes</enabled>
    <hosts>
$(printf '%s' "$hosts_xml")
    </hosts>
    <ssl>
      <certificate_authorities>
        <ca>/var/ossec/etc/certs/root-ca.pem</ca>
      </certificate_authorities>
      <certificate>/var/ossec/etc/certs/node.pem</certificate>
      <key>/var/ossec/etc/certs/node-key.pem</key>
    </ssl>
  </indexer>

  <!-- SocBlitz SOAR webhook — the backend persists level >= 12 alerts -->
  <integration>
    <name>custom-socblitz</name>
    <hook_url>http://${app_ip}:5000/api/v1/soar/trigger/wazuh-alert</hook_url>
    <level>12</level>
    <alert_format>json</alert_format>
  </integration>

  <vulnerability-detection>
    <enabled>yes</enabled>
    <index-status>yes</index-status>
    <feed-update-interval>60m</feed-update-interval>
  </vulnerability-detection>

  <wodle name="syscollector">
    <disabled>no</disabled>
    <interval>1h</interval>
    <scan_on_start>yes</scan_on_start>
    <hardware>yes</hardware>
    <os>yes</os>
    <network>yes</network>
    <packages>yes</packages>
    <ports all="no">yes</ports>
    <processes>yes</processes>
  </wodle>

  <remote>
    <connection>secure</connection>
    <port>1514</port>
    <protocol>tcp</protocol>
    <queue_size>131072</queue_size>
  </remote>

${auth_xml}

${cluster_xml}

</ossec_config>
EOF
    chown root:wazuh /var/ossec/etc/ossec.conf
    chmod 640 /var/ossec/etc/ossec.conf
}

install_integration_scripts() {  # install_integration_scripts <src-dir>
    [ -f "$1/custom-socblitz" ] || die "integration scripts not found in $1"
    cp "$1/custom-socblitz" "$1/custom-socblitz.py" /var/ossec/integrations/
    chown root:wazuh /var/ossec/integrations/custom-socblitz*
    chmod 750 /var/ossec/integrations/custom-socblitz*
}

install_manager_certs() {  # install_manager_certs <certs-dir> <node-name>
    mkdir -p /var/ossec/etc/certs
    cp "$1/root-ca.pem"      /var/ossec/etc/certs/root-ca.pem
    cp "$1/$2.pem"           /var/ossec/etc/certs/node.pem
    cp "$1/$2-key.pem"       /var/ossec/etc/certs/node-key.pem
    chown -R root:wazuh /var/ossec/etc/certs
    chmod 750 /var/ossec/etc/certs; chmod 640 /var/ossec/etc/certs/*
}

set_wazuh_api_password() {  # set_wazuh_api_password <new-password>  (localhost API)
    local newpw="$1" token uid
    wait_for "Wazuh API (55000)" 300 curl -sk -o /dev/null "https://127.0.0.1:55000" || {
        warn "Wazuh API did not come up — API passwords left at defaults"; return 0; }
    token="$(curl -sk -u 'wazuh-wui:wazuh-wui' -X POST \
        'https://127.0.0.1:55000/security/user/authenticate?raw=true' || true)"
    if [ -z "$token" ] || [[ "$token" == *"title"* ]]; then
        warn "could not authenticate with default API credentials — set the API password manually"
        return 0
    fi
    for uid in 1 2; do   # 1 = wazuh, 2 = wazuh-wui on a fresh install
        curl -sk -X PUT "https://127.0.0.1:55000/security/users/$uid" \
            -H "Authorization: Bearer $token" -H 'Content-Type: application/json' \
            -d "{\"password\": \"$newpw\"}" -o /dev/null
    done
    record_pw "WAZUH_API_PASSWORD (users: wazuh, wazuh-wui)" "$newpw"
    info "Wazuh API passwords set"
}

# ── Wazuh indexer ────────────────────────────────────────────────────────────

install_indexer() {  # install_indexer <node-name> <bind-ip> <certs-dir> <admin-pw> <seed-ips-csv> <master-nodes-csv> <nodes-dn-block> <heap>
    local name="$1" ip="$2" certs="$3" adminpw="$4" seeds="$5" masters="$6" nodes_dn="$7" heap="$8"

    add_wazuh_repo
    apt_install_wazuh_pkg wazuh-indexer
    set_max_map_count

    mkdir -p /etc/wazuh-indexer/certs
    cp "$certs/root-ca.pem"    /etc/wazuh-indexer/certs/root-ca.pem
    cp "$certs/$name.pem"      /etc/wazuh-indexer/certs/indexer.pem
    cp "$certs/$name-key.pem"  /etc/wazuh-indexer/certs/indexer-key.pem
    cp "$certs/admin.pem"      /etc/wazuh-indexer/certs/admin.pem
    cp "$certs/admin-key.pem"  /etc/wazuh-indexer/certs/admin-key.pem
    chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/certs
    chmod 500 /etc/wazuh-indexer/certs; chmod 400 /etc/wazuh-indexer/certs/*

    local discovery
    if [ "$masters" = "single-node" ]; then
        discovery='discovery.type: single-node'
    else
        discovery="discovery.seed_hosts: [${seeds}]
cluster.initial_master_nodes: [${masters}]"
    fi

    cat > /etc/wazuh-indexer/opensearch.yml <<EOF
# Wazuh Indexer — SocBlitz VM install (node: ${name})
network.host: "${ip}"
node.name: ${name}
cluster.name: ${CLUSTER_NAME}-indexer
${discovery}

plugins.security.ssl.http.pemcert_filepath:       /etc/wazuh-indexer/certs/indexer.pem
plugins.security.ssl.http.pemkey_filepath:        /etc/wazuh-indexer/certs/indexer-key.pem
plugins.security.ssl.http.pemtrustedcas_filepath: /etc/wazuh-indexer/certs/root-ca.pem

plugins.security.ssl.transport.pemcert_filepath:       /etc/wazuh-indexer/certs/indexer.pem
plugins.security.ssl.transport.pemkey_filepath:        /etc/wazuh-indexer/certs/indexer-key.pem
plugins.security.ssl.transport.pemtrustedcas_filepath: /etc/wazuh-indexer/certs/root-ca.pem
plugins.security.ssl.transport.enforce_hostname_verification: false

plugins.security.ssl.http.enabled: true
plugins.security.enable_snapshot_restore_privilege: true
plugins.security.check_snapshot_restore_write_privileges: true

plugins.security.authcz.admin_dn:
  - "CN=admin,OU=Wazuh,O=Wazuh,L=California,C=US"

plugins.security.nodes_dn:
${nodes_dn}

plugins.security.audit.type: internal_opensearch
compatibility.override_main_response_version: true
cluster.routing.allocation.disk.threshold_enabled: true
EOF

    sed -i "s/^-Xms.*/-Xms${heap}/; s/^-Xmx.*/-Xmx${heap}/" /etc/wazuh-indexer/jvm.options

    # Bake the admin password hash before security init (deterministic, offline)
    local hash
    hash="$(JAVA_HOME=/usr/share/wazuh-indexer/jdk \
        bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p "$adminpw" | tail -1)"
    python3 - "$hash" <<'PYEOF'
import sys
path = "/etc/wazuh-indexer/opensearch-security/internal_users.yml"
lines = open(path).read().splitlines(True)
out, in_admin = [], False
for line in lines:
    if line.startswith("admin:"):
        in_admin = True
    elif line and not line[0].isspace():
        in_admin = False
    if in_admin and line.lstrip().startswith("hash:"):
        indent = line[:len(line) - len(line.lstrip())]
        line = f'{indent}hash: "{sys.argv[1]}"\n'
    out.append(line)
open(path, "w").writelines(out)
PYEOF

    systemctl daemon-reload
    systemctl enable --now wazuh-indexer
    record_pw "WAZUH_INDEXER_PASSWORD (user: admin)" "$adminpw"
}

run_security_init() {  # run_security_init <host-ip>
    wait_for "wazuh-indexer (9200)" 300 bash -c "curl -sk https://$1:9200 -o /dev/null" \
        || die "indexer did not come up on $1:9200"
    JAVA_HOME=/usr/share/wazuh-indexer/jdk \
    bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
        -cd /etc/wazuh-indexer/opensearch-security -icl -nhnv -p 9200 -h "$1" \
        -cacert /etc/wazuh-indexer/certs/root-ca.pem \
        -cert   /etc/wazuh-indexer/certs/admin.pem \
        -key    /etc/wazuh-indexer/certs/admin-key.pem
    info "indexer security initialized"
}

# ── App tier components ──────────────────────────────────────────────────────

install_node20() {
    if command -v node >/dev/null && [ "$(node -v | sed 's/v\([0-9]*\).*/\1/')" -ge "$NODE_MAJOR" ]; then
        return
    fi
    curl -fsSL "https://deb.nodesource.com/setup_${NODE_MAJOR}.x" | bash -
    apt_install nodejs
}

install_postgres() {  # install_postgres <db-password>
    apt_install postgresql
    systemctl enable --now postgresql
    sudo -u postgres psql -v ON_ERROR_STOP=1 <<EOF
DO \$\$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'socblitz') THEN
    CREATE ROLE socblitz LOGIN PASSWORD '$1';
  ELSE
    ALTER ROLE socblitz PASSWORD '$1';
  END IF;
END \$\$;
EOF
    sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='socblitz'" | grep -q 1 \
        || sudo -u postgres createdb -O socblitz socblitz
    record_pw "POSTGRES_PASSWORD (user: socblitz)" "$1"
}

install_redis() {  # install_redis <password>
    apt_install redis-server
    # Last directive wins in redis.conf — append our overrides once
    if ! grep -q "# socblitz" /etc/redis/redis.conf; then
        cat >> /etc/redis/redis.conf <<EOF

# socblitz
requirepass $1
maxmemory 512mb
maxmemory-policy allkeys-lru
EOF
    else
        sed -i "/^requirepass /c\\requirepass $1" /etc/redis/redis.conf
    fi
    systemctl enable --now redis-server
    systemctl restart redis-server
    record_pw "REDIS_PASSWORD" "$1"
}

install_minio() {  # install_minio <root-password>
    if [ ! -x /usr/local/bin/minio ]; then
        curl -fsSo /usr/local/bin/minio \
            "https://dl.min.io/server/minio/release/linux-$(arch_deb)/minio"
        chmod +x /usr/local/bin/minio
    fi
    id -u minio-user >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin minio-user
    mkdir -p /var/lib/minio && chown minio-user:minio-user /var/lib/minio
    cat > /etc/default/minio <<EOF
MINIO_ROOT_USER=socblitz
MINIO_ROOT_PASSWORD=$1
MINIO_VOLUMES=/var/lib/minio
MINIO_OPTS="--address 127.0.0.1:9000 --console-address :9001"
EOF
    chmod 600 /etc/default/minio
    cat > /etc/systemd/system/minio.service <<'EOF'
[Unit]
Description=MinIO object storage (SocBlitz)
After=network-online.target
Wants=network-online.target

[Service]
User=minio-user
Group=minio-user
EnvironmentFile=/etc/default/minio
ExecStart=/usr/local/bin/minio server $MINIO_OPTS $MINIO_VOLUMES
Restart=always
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now minio
    record_pw "MINIO_ROOT_PASSWORD (user: socblitz)" "$1"
}

install_ollama() {  # install_ollama <chat-model> <embed-model>
    if ! command -v ollama >/dev/null; then
        if ! curl -fsSL https://ollama.com/install.sh | sh; then
            warn "Ollama install failed (offline?) — AI dashboard features will be unavailable"
            return 0
        fi
    fi
    systemctl enable --now ollama 2>/dev/null || true
    wait_for "ollama (11434)" 60 curl -sf http://127.0.0.1:11434/api/tags || true
    timeout 900 ollama pull "$1" || warn "could not pull model $1 — run 'ollama pull $1' later"
    timeout 900 ollama pull "$2" || warn "could not pull model $2 — run 'ollama pull $2' later"
}

install_velociraptor() {  # install_velociraptor <public-ip> <admin-password>
    local pubip="$1" velopw="$2" bin=/usr/local/bin/velociraptor url
    if [ ! -x "$bin" ]; then
        url="$(curl -fsS https://api.github.com/repos/Velocidex/velociraptor/releases/latest \
            | grep -o "\"browser_download_url\": *\"[^\"]*linux-$(arch_deb)\"" \
            | head -1 | sed 's/.*"\(https[^"]*\)"/\1/')"
        [ -n "$url" ] || { warn "could not resolve Velociraptor release — forensics disabled; install manually and re-run"; return 0; }
        curl -fsSLo "$bin" "$url" && chmod +x "$bin"
    fi

    mkdir -p /etc/velociraptor /var/lib/velociraptor
    if [ ! -f /etc/velociraptor/server.config.yaml ]; then
        cat > /tmp/velo-merge.json <<EOF
{
  "Frontend":  {"hostname": "${pubip}", "bind_address": "0.0.0.0", "bind_port": 8010},
  "GUI":       {"bind_address": "0.0.0.0", "bind_port": 8889},
  "Client":    {"server_urls": ["https://velociraptor:8000/"], "use_self_signed_ssl": true},
  "Datastore": {"location": "/var/lib/velociraptor", "filestore_directory": "/var/lib/velociraptor"}
}
EOF
        "$bin" config generate --merge "$(cat /tmp/velo-merge.json)" \
            > /etc/velociraptor/server.config.yaml
        rm -f /tmp/velo-merge.json
        chmod 600 /etc/velociraptor/server.config.yaml
    fi

    "$bin" --config /etc/velociraptor/server.config.yaml \
        user add admin "$velopw" --role administrator >/dev/null 2>&1 || true

    # Version-matched client config + binary, served by the backend during enrolment.
    # The https://velociraptor:8000/ URL is a placeholder the backend rewrites to
    # <server>:8010 at download time (see backend agent-deploy routes).
    "$bin" --config /etc/velociraptor/server.config.yaml config client \
        > "$SB_HOME/deployment/velociraptor-client.config.yaml"
    mkdir -p /velociraptor-data
    cp "$bin" /velociraptor-data/velociraptor

    cat > /etc/systemd/system/velociraptor.service <<'EOF'
[Unit]
Description=Velociraptor DFIR server (SocBlitz)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/velociraptor --config /etc/velociraptor/server.config.yaml frontend -v
Restart=always
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now velociraptor
    record_pw "VELOCIRAPTOR_PASSWORD (user: admin)" "$velopw"
}

copy_repo() {
    [ -d "$REPO_ROOT/backend" ] && [ -d "$REPO_ROOT/frontend" ] \
        || die "app-tier install must run from a repo checkout (<repo>/deployment/vm/socblitz-install.sh)"
    apt_install rsync
    mkdir -p "$SB_HOME"
    rsync -a --delete \
        --exclude '.git' --exclude 'node_modules' --exclude 'dist' \
        --exclude 'data' --exclude '.env' \
        "$REPO_ROOT/" "$SB_HOME/"
}

write_app_env() {  # write_app_env <indexer-url> <indexer-pw> <manager-url> <api-pw> <public-host>
    local secret enrollkey
    secret="$(openssl rand -hex 32)"
    enrollkey="$(openssl rand -hex 16)"
    mkdir -p "$SB_ETC"
    cat > "$SB_ETC/socblitz.env" <<EOF
# SocBlitz application environment — generated by socblitz-install.sh
APP_ENV=production
SECRET_KEY=${secret}
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=480
FIRST_ADMIN_EMAIL=admin@socblitz.local
FIRST_ADMIN_PASSWORD=${ADMIN_UI_PASSWORD}

POSTGRES_HOST=127.0.0.1
POSTGRES_PORT=5432
POSTGRES_DB=socblitz
POSTGRES_USER=socblitz
POSTGRES_PASSWORD=${POSTGRES_PW}

REDIS_HOST=127.0.0.1
REDIS_PORT=6379
REDIS_PASSWORD=${REDIS_PW}
REDIS_DB=0

MINIO_ENDPOINT=127.0.0.1:9000
MINIO_ROOT_USER=socblitz
MINIO_ROOT_PASSWORD=${MINIO_PW}
MINIO_SECURE=false
MINIO_BUCKET_CASES=socblitz-cases
MINIO_BUCKET_REPORTS=socblitz-reports
MINIO_BUCKET_ARTIFACTS=socblitz-artifacts

WAZUH_INDEXER_URL=$1
WAZUH_INDEXER_USER=admin
WAZUH_INDEXER_PASSWORD=$2

WAZUH_MANAGER_URL=$3
WAZUH_MANAGER_USER=wazuh-wui
WAZUH_MANAGER_PASSWORD=$4

# MISP is not bundled in the VM install — point at an existing instance
# (or the Docker deployment's MISP) and add the key to enable it.
MISP_URL=
MISP_API_KEY=
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
OTX_API_KEY=

OPENAI_API_KEY=
OPENAI_MODEL=gpt-4o-mini
OLLAMA_MODEL=${OLLAMA_MODEL}
OLLAMA_EMBED_MODEL=${OLLAMA_EMBED_MODEL}
LOCAL_LLM_URL=http://127.0.0.1:11434/v1
LOCAL_LLM_MODEL=${OLLAMA_MODEL}
LOCAL_EMBED_MODEL=${OLLAMA_EMBED_MODEL}

VELOCIRAPTOR_URL=https://127.0.0.1:8889
VELOCIRAPTOR_USER=admin
VELOCIRAPTOR_PASSWORD=${VELO_PW}

SMTP_HOST=
SMTP_PORT=587
SMTP_USER=
SMTP_PASSWORD=
SMTP_FROM=socblitz@yourorg.com
SLACK_WEBHOOK_URL=
TEAMS_WEBHOOK_URL=

AGENT_ENROLL_KEY=${enrollkey}
AGENT_PUBLIC_HOST=$5
EOF
    chown root:socblitz "$SB_ETC/socblitz.env"
    chmod 640 "$SB_ETC/socblitz.env"
    record_pw "SOCBLITZ_UI_PASSWORD (admin@socblitz.local)" "$ADMIN_UI_PASSWORD"
    record_pw "AGENT_ENROLL_KEY" "$enrollkey"
}

install_backend_services() {
    id -u socblitz >/dev/null 2>&1 || useradd -r -d "$SB_HOME" -s /usr/sbin/nologin socblitz

    apt_install python3 python3-venv python3-dev build-essential libpq-dev curl git
    python3 -m venv "$SB_HOME/venv"
    "$SB_HOME/venv/bin/pip" install -q --upgrade pip wheel
    "$SB_HOME/venv/bin/pip" install -q -r "$SB_HOME/backend/requirements.txt"

    # The backend hardcodes /app/deployment (installer templates) and
    # /velociraptor-data (served client binary) — mirror the Docker layout.
    mkdir -p /app /velociraptor-data /var/lib/socblitz
    ln -sfn "$SB_HOME/deployment" /app/deployment
    mkdir -p /app/logs
    chown -R socblitz:socblitz "$SB_HOME" /app/logs /var/lib/socblitz
    chmod 755 /velociraptor-data
    [ -f /velociraptor-data/velociraptor ] && chmod 644 /velociraptor-data/velociraptor

    cat > /etc/systemd/system/socblitz-backend.service <<EOF
[Unit]
Description=SocBlitz backend API
After=network-online.target postgresql.service redis-server.service
Wants=network-online.target

[Service]
User=socblitz
Group=socblitz
WorkingDirectory=$SB_HOME/backend
EnvironmentFile=$SB_ETC/socblitz.env
Environment=PYTHONPATH=$SB_HOME/backend
ExecStart=$SB_HOME/venv/bin/uvicorn main:app --host 0.0.0.0 --port 5000 --workers 4
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    cat > /etc/systemd/system/socblitz-worker.service <<EOF
[Unit]
Description=SocBlitz Celery worker
After=network-online.target redis-server.service postgresql.service

[Service]
User=socblitz
Group=socblitz
WorkingDirectory=$SB_HOME/backend
EnvironmentFile=$SB_ETC/socblitz.env
Environment=PYTHONPATH=$SB_HOME/backend
ExecStart=$SB_HOME/venv/bin/celery -A app.workers.celery_app worker --loglevel=info --concurrency=4 -Q default,integrations,alerts
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    cat > /etc/systemd/system/socblitz-beat.service <<EOF
[Unit]
Description=SocBlitz Celery beat scheduler
After=network-online.target redis-server.service

[Service]
User=socblitz
Group=socblitz
WorkingDirectory=$SB_HOME/backend
EnvironmentFile=$SB_ETC/socblitz.env
Environment=PYTHONPATH=$SB_HOME/backend
ExecStart=$SB_HOME/venv/bin/celery -A app.workers.celery_app beat --loglevel=info --schedule=/var/lib/socblitz/celerybeat-schedule
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now socblitz-backend socblitz-worker socblitz-beat
}

install_frontend_nginx() {
    install_node20
    apt_install nginx
    ( cd "$SB_HOME/frontend" && npm install --no-audit --no-fund && npm run build )
    rm -rf /var/www/socblitz
    cp -r "$SB_HOME/frontend/dist" /var/www/socblitz

    mkdir -p /etc/nginx/certs
    if [ ! -f /etc/nginx/certs/socblitz.pem ]; then
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout /etc/nginx/certs/socblitz-key.pem \
            -out /etc/nginx/certs/socblitz.pem \
            -subj "/C=US/ST=State/L=City/O=SocBlitz/CN=$(hostname -f 2>/dev/null || hostname)"
    fi

    cat > /etc/nginx/sites-available/socblitz <<'EOF'
server {
    listen 80;
    server_name _;
    return 302 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name _;

    ssl_certificate     /etc/nginx/certs/socblitz.pem;
    ssl_certificate_key /etc/nginx/certs/socblitz-key.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    root /var/www/socblitz;
    index index.html;
    client_max_body_size 100m;

    location / {
        try_files $uri $uri/ /index.html;
    }

    location /api/ {
        proxy_pass         http://127.0.0.1:5000;
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
        proxy_read_timeout 120s;
    }

    location /ws/ {
        proxy_pass         http://127.0.0.1:5000;
        proxy_http_version 1.1;
        proxy_set_header   Upgrade $http_upgrade;
        proxy_set_header   Connection "upgrade";
        proxy_read_timeout 3600s;
    }

    gzip on;
    gzip_types text/plain application/javascript text/css application/json;
    gzip_min_length 1024;
}
EOF
    ln -sf /etc/nginx/sites-available/socblitz /etc/nginx/sites-enabled/socblitz
    rm -f /etc/nginx/sites-enabled/default
    nginx -t
    systemctl enable --now nginx
    systemctl reload nginx
}

install_app_tier_common() {  # install_app_tier_common <indexer-url> <indexer-pw> <manager-url> <api-pw> <public-host> <velo-public-ip>
    OLLAMA_MODEL="${OLLAMA_MODEL:-llama3.2:1b}"
    OLLAMA_EMBED_MODEL="${OLLAMA_EMBED_MODEL:-nomic-embed-text}"
    POSTGRES_PW="$(randpw)"; REDIS_PW="$(randpw)"; MINIO_PW="$(randpw)"
    VELO_PW="$(randpw)"; ADMIN_UI_PASSWORD="SocBlitz@Admin1!"

    section "Copying repository to $SB_HOME"
    copy_repo
    section "PostgreSQL";    install_postgres "$POSTGRES_PW"
    section "Redis";         install_redis "$REDIS_PW"
    section "MinIO";         install_minio "$MINIO_PW"
    section "Ollama (local LLM)"; install_ollama "$OLLAMA_MODEL" "$OLLAMA_EMBED_MODEL"
    section "Velociraptor";  install_velociraptor "$6" "$VELO_PW"
    section "SocBlitz backend"
    write_app_env "$1" "$2" "$3" "$4" "$5"
    install_backend_services
    section "SocBlitz frontend (nginx)"
    install_frontend_nginx

    wait_for "SocBlitz backend (5000)" 300 curl -sf http://127.0.0.1:5000/api/v1/health \
        || warn "backend not healthy yet — check: journalctl -u socblitz-backend -e"
}

print_summary() {
    local host="$1"
    echo ""
    echo "  ┌──────────────────────────────────────────────────────────────┐"
    echo "  │                 ⚡  SocBlitz is installed                     │"
    echo "  ├──────────────────────────────────────────────────────────────┤"
    echo "  │  SocBlitz UI    → https://${host}"
    echo "  │  Velociraptor   → https://${host}:8889"
    echo "  │  MinIO console  → http://${host}:9001"
    echo "  ├──────────────────────────────────────────────────────────────┤"
    echo "  │  Login: admin@socblitz.local  (password in $PASSFILE)"
    echo "  │  All credentials: $PASSFILE"
    echo "  └──────────────────────────────────────────────────────────────┘"
    echo ""
}

# ── Role commands ────────────────────────────────────────────────────────────

cmd_generate() {
    need_root "-g"
    local cfg="$SCRIPT_DIR/config.yml"
    [ -f "./config.yml" ] && cfg="./config.yml"
    [ -f "$cfg" ] || die "config.yml not found — copy config.yml.example, edit IPs, re-run"
    load_config "$cfg"

    [ -n "${APP_TIER_IP_ARG:-}" ] || die "-g requires --app-tier-ip <ip> (SocBlitz app host — webhook target)"
    [ -n "${LB_IP_ARG:-}" ] || warn "--lb-ip not set — agents will enroll against the master directly"

    local out; out="$(mktemp -d /tmp/socblitz-gen.XXXXXX)"
    section "Generating certificates (wazuh-certs-tool)"
    fetch_certs_tool "$out"
    cp "$cfg" "$out/config.yml"
    ( cd "$out" && bash wazuh-certs-tool.sh -A )
    [ -d "$out/wazuh-certificates" ] || die "certificate generation failed"

    section "Generating cluster secrets"
    cat > "$out/socblitz-cluster.env" <<EOF
CLUSTER_KEY=$(openssl rand -hex 16)
INDEXER_ADMIN_PASSWORD=$(randpw)
WAZUH_API_PASSWORD=$(randpw)
APP_TIER_IP=${APP_TIER_IP_ARG}
LB_IP=${LB_IP_ARG:-$(master_ip)}
EOF

    mkdir -p "$out/socblitz-integrations"
    cp "$SCRIPT_DIR/../wazuh-integrations/custom-socblitz" \
       "$SCRIPT_DIR/../wazuh-integrations/custom-socblitz.py" "$out/socblitz-integrations/"

    tar -cf "./$TAR_NAME" -C "$out" \
        wazuh-certificates socblitz-cluster.env config.yml socblitz-integrations
    chmod 600 "./$TAR_NAME"
    rm -rf "$out"
    info "wrote ./$TAR_NAME — copy it to every cluster host (contains keys: handle like a secret)"
}

cmd_indexer() {
    need_root; check_os
    local name="$1"
    load_tar
    local i ip="" seeds="" masters="" nodes_dn=""
    for i in "${!INDEXER_NAMES[@]}"; do
        [ "${INDEXER_NAMES[$i]}" = "$name" ] && ip="${INDEXER_IPS[$i]}"
        seeds+="${seeds:+, }\"${INDEXER_IPS[$i]}\""
        masters+="${masters:+, }\"${INDEXER_NAMES[$i]}\""
        nodes_dn+="  - \"CN=${INDEXER_NAMES[$i]},OU=Wazuh,O=Wazuh,L=California,C=US\"\n"
    done
    [ -n "$ip" ] || die "node '$name' not found in config.yml indexer section"
    [ "${#INDEXER_NAMES[@]}" -eq 1 ] && masters="single-node"

    local heap
    heap="$(awk '/MemTotal/ {h=int($2/1024/1024/2); if (h<1) h=1; if (h>16) h=16; print h"g"}' /proc/meminfo)"

    section "Installing wazuh-indexer node: $name ($ip)"
    install_indexer "$name" "$ip" "$WORKDIR/wazuh-certificates" \
        "$INDEXER_ADMIN_PASSWORD" "$seeds" "$masters" "$(printf '%b' "$nodes_dn")" "$heap"
    info "indexer '$name' started. After ALL indexer nodes are up, run once on any of them:"
    echo "      sudo bash $0 --start-cluster"
}

cmd_start_cluster() {
    need_root
    load_tar
    local i ip="127.0.0.1" local_ips
    local_ips="$(hostname -I 2>/dev/null || true)"
    for i in "${INDEXER_IPS[@]}"; do
        case " $local_ips " in *" $i "*) ip="$i" ;; esac
    done
    section "Initializing indexer cluster security ($ip)"
    run_security_init "$ip"
    wait_for "authenticated cluster API" 120 \
        curl -skf -u "admin:$INDEXER_ADMIN_PASSWORD" "https://$ip:9200/_cat/nodes" \
        || die "cluster did not authenticate — check journalctl -u wazuh-indexer"
    curl -sk -u "admin:$INDEXER_ADMIN_PASSWORD" "https://$ip:9200/_cat/nodes?v"
}

cmd_server() {
    need_root; check_os
    local name="$1"
    load_tar
    local i ip="" ntype=""
    for i in "${!SERVER_NAMES[@]}"; do
        if [ "${SERVER_NAMES[$i]}" = "$name" ]; then
            ip="${SERVER_IPS[$i]}"; ntype="${SERVER_TYPES[$i]}"
        fi
    done
    [ -n "$ip" ] || die "node '$name' not found in config.yml server section"
    [ "$ntype" = "-" ] && ntype="master"

    section "Installing wazuh-manager node: $name ($ip, $ntype)"
    add_wazuh_repo
    apt_install_wazuh_pkg wazuh-manager
    install_manager_certs "$WORKDIR/wazuh-certificates" "$name"
    write_ossec_conf "$ntype" "$name" "$APP_TIER_IP" "$(master_ip)" "${INDEXER_IPS[@]}"
    install_integration_scripts "$WORKDIR/socblitz-integrations"
    systemctl daemon-reload
    systemctl enable --now wazuh-manager

    if [ "$ntype" = "master" ]; then
        set_wazuh_api_password "$WAZUH_API_PASSWORD"
        info "verify the cluster once workers join: /var/ossec/bin/cluster_control -l"
    else
        info "worker started — verify from the master: /var/ossec/bin/cluster_control -l"
    fi
}

cmd_load_balancer() {
    need_root; check_os
    load_tar
    section "Installing nginx TCP load balancer"
    apt_install nginx libnginx-mod-stream

    local i upstreams=""
    for i in "${!SERVER_NAMES[@]}"; do
        [ "${SERVER_TYPES[$i]}" = "worker" ] && \
            upstreams+="        server ${SERVER_IPS[$i]}:1514 max_fails=3 fail_timeout=30s;\n"
    done
    # No workers defined → events also go to the master
    [ -n "$upstreams" ] || upstreams="        server $(master_ip):1514 max_fails=3 fail_timeout=30s;\n"

    mkdir -p /etc/nginx/streams-enabled
    grep -q "streams-enabled" /etc/nginx/nginx.conf \
        || echo 'include /etc/nginx/streams-enabled/*.conf;' >> /etc/nginx/nginx.conf

    cat > /etc/nginx/streams-enabled/socblitz-wazuh.conf <<EOF
# SocBlitz — Wazuh agent traffic load balancer (generated by socblitz-install.sh)
stream {
    upstream wazuh_events {
        hash \$remote_addr consistent;
$(printf '%b' "$upstreams")    }

    upstream wazuh_enrollment {
        server $(master_ip):1515;
    }

    server {
        listen 1514;
        proxy_pass wazuh_events;
        proxy_timeout 90s;
        proxy_connect_timeout 5s;
    }

    server {
        listen 1515;
        proxy_pass wazuh_enrollment;
        proxy_timeout 90s;
        proxy_connect_timeout 5s;
    }
}
EOF
    nginx -t
    systemctl enable --now nginx
    systemctl reload nginx
    info "load balancer up — point agents at this host (1514 events, 1515 enrollment)"
}

cmd_app_tier() {
    need_root; check_os
    load_tar
    section "SocBlitz app tier (distributed)"
    install_app_tier_common \
        "https://${INDEXER_IPS[0]}:9200" "$INDEXER_ADMIN_PASSWORD" \
        "https://$(master_ip):55000" "$WAZUH_API_PASSWORD" \
        "$LB_IP" "$LB_IP"
    record_pw "WAZUH_API_PASSWORD (users: wazuh, wazuh-wui)" "$WAZUH_API_PASSWORD"
    record_pw "WAZUH_INDEXER_PASSWORD (user: admin)" "$INDEXER_ADMIN_PASSWORD"
    print_summary "$(hostname -I | awk '{print $1}')"
    warn "webhook: managers POST to this host on :5000 — allow master/worker IPs through the firewall"
}

cmd_all_in_one() {
    need_root; check_os
    [ -d "$REPO_ROOT/backend" ] || die "all-in-one must run from a repo checkout"
    set_max_map_count

    local certdir="/tmp/socblitz-aio-certs"
    CLUSTER_KEY=""   # standalone manager: no cluster block
    INDEXER_ADMIN_PASSWORD="$(randpw)"
    local api_pw; api_pw="$(randpw)"

    section "Certificates (localhost)"
    if [ ! -d "$certdir/wazuh-certificates" ]; then
        mkdir -p "$certdir"
        cat > "$certdir/config.yml" <<'EOF'
nodes:
  indexer:
    - name: wazuh-indexer
      ip: "127.0.0.1"
  server:
    - name: wazuh-manager
      ip: "127.0.0.1"
EOF
        fetch_certs_tool "$certdir"
        ( cd "$certdir" && bash wazuh-certs-tool.sh -A )
    fi

    section "Wazuh indexer (single node)"
    install_indexer "wazuh-indexer" "127.0.0.1" "$certdir/wazuh-certificates" \
        "$INDEXER_ADMIN_PASSWORD" "" "single-node" \
        '  - "CN=wazuh-indexer,OU=Wazuh,O=Wazuh,L=California,C=US"' "1g"
    run_security_init "127.0.0.1"

    section "Wazuh manager (standalone)"
    add_wazuh_repo
    apt_install_wazuh_pkg wazuh-manager
    install_manager_certs "$certdir/wazuh-certificates" "wazuh-manager"
    write_ossec_conf "standalone" "wazuh-manager" "127.0.0.1" "" "127.0.0.1"
    install_integration_scripts "$SCRIPT_DIR/../wazuh-integrations"
    systemctl daemon-reload
    systemctl enable --now wazuh-manager
    set_wazuh_api_password "$api_pw"

    local host_ip; host_ip="$(hostname -I | awk '{print $1}')"
    install_app_tier_common \
        "https://127.0.0.1:9200" "$INDEXER_ADMIN_PASSWORD" \
        "https://127.0.0.1:55000" "$api_pw" \
        "" "$host_ip"

    rm -rf "$certdir"
    print_summary "$host_ip"
    echo "  Enroll agents: SocBlitz UI → Agents → Deploy (or GET /api/v1/agent-deploy/command)"
    echo ""
}

usage() {
    sed -n '3,23p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

# ── Argument parsing ─────────────────────────────────────────────────────────

ACTION=""; NODE_NAME=""; APP_TIER_IP_ARG=""; LB_IP_ARG=""
[ $# -gt 0 ] || usage 1
while [ $# -gt 0 ]; do
    case "$1" in
        -a|--all-in-one)          ACTION="aio" ;;
        -g|--generate-config-files) ACTION="generate" ;;
        --app-tier-ip)            APP_TIER_IP_ARG="$2"; shift ;;
        --lb-ip)                  LB_IP_ARG="$2"; shift ;;
        -wi|--wazuh-indexer)      ACTION="indexer"; NODE_NAME="$2"; shift ;;
        -s|--start-cluster)       ACTION="start-cluster" ;;
        -ws|--wazuh-server)       ACTION="server"; NODE_NAME="$2"; shift ;;
        -lb|--load-balancer)      ACTION="lb" ;;
        -at|--app-tier)           ACTION="app-tier" ;;
        -h|--help)                usage 0 ;;
        *) die "unknown option: $1 (see -h)" ;;
    esac
    shift
done

case "$ACTION" in
    aio)           cmd_all_in_one ;;
    generate)      cmd_generate ;;
    indexer)       cmd_indexer "$NODE_NAME" ;;
    start-cluster) cmd_start_cluster ;;
    server)        cmd_server "$NODE_NAME" ;;
    lb)            cmd_load_balancer ;;
    app-tier)      cmd_app_tier ;;
    *)             usage 1 ;;
esac
