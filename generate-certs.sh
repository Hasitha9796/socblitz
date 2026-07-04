#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# SocBlitz — Wazuh SSL certificate generator (native OpenSSL)
# Works on arm64 AND amd64 — no Docker image needed
# ─────────────────────────────────────────────────────────────────────────────

set -e

CERT_DIR="./config/wazuh_certs"
mkdir -p "$CERT_DIR"
cd "$CERT_DIR"

SUBJ_BASE="/C=US/L=California/O=Wazuh/OU=Wazuh"

echo "[1/6] Generating Root CA..."
openssl genrsa -out root-ca.key 2048 2>/dev/null
openssl req -new -x509 -days 3650 \
    -key root-ca.key \
    -out root-ca.pem \
    -subj "${SUBJ_BASE}/CN=Wazuh Root CA" 2>/dev/null
cp root-ca.pem root-ca-manager.pem
echo "      root-ca.pem ✓"

echo "[2/6] Generating Admin cert..."
openssl genrsa -out admin-key.pem 2048 2>/dev/null
openssl req -new -key admin-key.pem -out admin.csr \
    -subj "${SUBJ_BASE}/CN=admin" 2>/dev/null
openssl x509 -req -days 3650 \
    -in admin.csr -CA root-ca.pem -CAkey root-ca.key -CAcreateserial \
    -out admin.pem -extensions v3_req \
    -extfile <(printf "[v3_req]\nextendedKeyUsage=clientAuth\n") 2>/dev/null
rm -f admin.csr
echo "      admin.pem ✓"

echo "[3/6] Generating Wazuh Indexer cert..."
openssl genrsa -out wazuh-indexer-key.pem 2048 2>/dev/null
openssl req -new -key wazuh-indexer-key.pem -out wazuh-indexer.csr \
    -subj "${SUBJ_BASE}/CN=wazuh-indexer" 2>/dev/null
openssl x509 -req -days 3650 \
    -in wazuh-indexer.csr -CA root-ca.pem -CAkey root-ca.key -CAcreateserial \
    -out wazuh-indexer.pem -extensions v3_req \
    -extfile <(printf "[v3_req]\nsubjectAltName=DNS:wazuh-indexer,IP:127.0.0.1\n") 2>/dev/null
rm -f wazuh-indexer.csr
echo "      wazuh-indexer.pem ✓"

echo "[4/6] Generating Wazuh Manager cert..."
openssl genrsa -out wazuh-manager-key.pem 2048 2>/dev/null
openssl req -new -key wazuh-manager-key.pem -out wazuh-manager.csr \
    -subj "${SUBJ_BASE}/CN=wazuh-manager" 2>/dev/null
openssl x509 -req -days 3650 \
    -in wazuh-manager.csr -CA root-ca.pem -CAkey root-ca.key -CAcreateserial \
    -out wazuh-manager.pem \
    -extfile <(printf "[v3_req]\nsubjectAltName=DNS:wazuh-manager,IP:127.0.0.1\n") \
    -extensions v3_req 2>/dev/null
rm -f wazuh-manager.csr
echo "      wazuh-manager.pem ✓"

echo "[5/6] Generating Wazuh Dashboard cert..."
openssl genrsa -out wazuh-dashboard-key.pem 2048 2>/dev/null
openssl req -new -key wazuh-dashboard-key.pem -out wazuh-dashboard.csr \
    -subj "${SUBJ_BASE}/CN=wazuh-dashboard" 2>/dev/null
openssl x509 -req -days 3650 \
    -in wazuh-dashboard.csr -CA root-ca.pem -CAkey root-ca.key -CAcreateserial \
    -out wazuh-dashboard.pem 2>/dev/null
rm -f wazuh-dashboard.csr
echo "      wazuh-dashboard.pem ✓"

echo "[6/6] Setting permissions..."
chmod 644 ./*.pem
chmod 600 ./*-key.pem root-ca.key
rm -f root-ca.srl

echo ""
echo "Certificates ready in $CERT_DIR:"
ls -lh ./*.pem | awk '{print "  " $NF}'
echo ""
