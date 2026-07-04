#!/bin/bash
# SocBlitz — First-time setup
# Supports: arm64 (aarch64) and amd64 (x86_64) natively

set -e
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${GREEN}[✓]${NC} $1"; }
warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
error()   { echo -e "${RED}[✗]${NC} $1"; exit 1; }
section() { echo -e "\n${CYAN}━━━ $1 ━━━${NC}"; }

echo ""
echo "  ⚡  SocBlitz Setup"
echo ""

# ── 1. Check Docker ───────────────────────────────────────────────────────────
section "Checking Docker"
command -v docker &>/dev/null || error "Docker not found. Run: curl -fsSL https://get.docker.com | sudo sh"
docker compose version &>/dev/null || error "Docker Compose plugin missing. Run: sudo apt install docker-compose-plugin"
info "Docker $(docker --version | awk '{print $3}' | tr -d ',')"
info "Docker Compose $(docker compose version --short)"

# ── 2. Architecture ───────────────────────────────────────────────────────────
section "Architecture"
ARCH=$(uname -m)
info "Host: $ARCH"
# All services (including Wazuh 4.14.5) have native arm64 + amd64 images
[[ "$ARCH" == "aarch64" ]] && info "ARM64 — all images run natively (Wazuh 4.14.x added native ARM64)"
[[ "$ARCH" == "x86_64"  ]] && info "amd64 — all images run natively"

# ── 3. .env setup ─────────────────────────────────────────────────────────────
section "Environment"
if [ ! -f .env ]; then
    cp .env.example .env
    sed -i "s/CHANGE_ME_32/$(openssl rand -hex 32)/" .env
    info ".env created with auto-generated SECRET_KEY"
else
    warn ".env already exists — skipping"
fi

# ── 4. Directories ────────────────────────────────────────────────────────────
section "Creating directories"
mkdir -p config/wazuh_certs data/logs data/celery data/minio
info "Directories ready"

# ── 5. vm.max_map_count (required by OpenSearch / Wazuh indexer) ──────────────
section "System tuning"
CURRENT_MAP=$(sysctl -n vm.max_map_count 2>/dev/null || echo 0)
if [ "$CURRENT_MAP" -lt 262144 ]; then
    sudo sysctl -w vm.max_map_count=262144
    grep -q vm.max_map_count /etc/sysctl.conf \
        || echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf > /dev/null
    info "vm.max_map_count set to 262144"
else
    info "vm.max_map_count = $CURRENT_MAP (OK)"
fi

# ── 6. Wazuh SSL certificates (native OpenSSL — works on any arch) ────────────
section "Generating Wazuh SSL certificates"
if [ -f config/wazuh_certs/root-ca.pem ]; then
    warn "Certs already exist — skipping. Delete config/wazuh_certs/ to regenerate."
else
    chmod +x generate-certs.sh
    bash generate-certs.sh
fi

# ── 7. Build + start ──────────────────────────────────────────────────────────
section "Building SocBlitz images"
docker compose build

section "Starting all services"
# Start in dependency order so healthchecks pass before dependents start
echo "  [1/4] Infrastructure (postgres, redis, minio)..."
docker compose up -d postgres redis minio

echo "  [2/4] Monitoring (grafana, influxdb)..."
docker compose up -d grafana influxdb

echo "  [3/4] Graylog stack (mongo → opensearch → graylog)..."
docker compose up -d graylog-mongo graylog-opensearch
echo "  Waiting for Graylog OpenSearch..."
until docker compose exec -T graylog-opensearch curl -sf http://localhost:9200/_cluster/health 2>/dev/null | grep -q 'green\|yellow'; do
    printf "."; sleep 5
done; echo " ready"
docker compose up -d graylog

echo "  [4/4] Wazuh stack (indexer → manager) and SocBlitz..."
docker compose up -d wazuh-indexer
echo "  Waiting for Wazuh indexer..."
until docker compose exec -T wazuh-indexer curl -sk -u "admin:${WAZUH_INDEXER_PASSWORD:-SecretPassword}" https://localhost:9200/_cluster/health 2>/dev/null | grep -q 'green\|yellow'; do
    printf "."; sleep 10
done; echo " ready"
docker compose up -d wazuh-manager
docker compose up -d backend worker beat frontend

# ── 8. Wait for backend ───────────────────────────────────────────────────────
section "Waiting for SocBlitz"
echo -n "  "
for i in $(seq 1 30); do
    docker compose exec -T backend curl -sf http://localhost:5000/api/v1/health &>/dev/null && echo " ready!" && break
    printf "."; sleep 5
done

HOST_IP=$(hostname -I | awk '{print $1}')
echo ""
echo "  ┌─────────────────────────────────────────────────────────┐"
echo "  │           ⚡  SocBlitz is running!                       │"
echo "  ├─────────────────────────────────────────────────────────┤"
echo "  │  SocBlitz UI   → https://${HOST_IP}                    │"
echo "  │  Graylog       → http://${HOST_IP}:9000                │"
echo "  │  Grafana       → http://${HOST_IP}:3000                │"
echo "  │  InfluxDB      → http://${HOST_IP}:8086                │"
echo "  │  MinIO console → http://${HOST_IP}:9001                │"
echo "  │  Wazuh API     → https://${HOST_IP}:55000              │"
echo "  ├─────────────────────────────────────────────────────────┤"
echo "  │  SocBlitz:   admin@socblitz.local / SocBlitz@Admin1!   │"
echo "  │  Graylog:    admin / admin                              │"
echo "  │  Grafana:    admin / SocBlitz@Grafana1                 │"
echo "  └─────────────────────────────────────────────────────────┘"
echo ""
