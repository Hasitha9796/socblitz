#!/bin/bash
set -e
CERT_DIR="./config/wazuh_certs"
rm -rf "$CERT_DIR"
mkdir -p "$CERT_DIR"
cd "$CERT_DIR"

cat > ca.cnf << 'EOF'
[req]
distinguished_name = dn
x509_extensions = v3_ca
prompt = no
[dn]
C  = US
L  = California
O  = Wazuh
OU = Wazuh
CN = Wazuh-Root-CA
[v3_ca]
basicConstraints = critical, CA:true
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
EOF

echo "[1/4] Root CA..."
openssl genrsa -out root-ca.key 2048 2>/dev/null
openssl req -new -x509 -days 3650 -key root-ca.key -out root-ca.pem -config ca.cnf 2>/dev/null
cp root-ca.pem root-ca-manager.pem
cp root-ca.key root-ca-manager.key

gen_cert() {
  local name=$1 cn=$2 eku=$3 san=$4
  cat > $name-ext.cnf << EOF
basicConstraints = CA:false
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = $eku
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
EOF
  [ -n "$san" ] && echo "subjectAltName = $san" >> $name-ext.cnf
  openssl genrsa -out $name-key.pem 2048 2>/dev/null
  openssl req -new -key $name-key.pem -out $name.csr \
    -subj "/C=US/L=California/O=Wazuh/OU=Wazuh/CN=$cn" 2>/dev/null
  openssl x509 -req -days 3650 -in $name.csr \
    -CA root-ca.pem -CAkey root-ca.key -CAcreateserial \
    -out $name.pem -extfile $name-ext.cnf 2>/dev/null
  rm -f $name.csr $name-ext.cnf
}

echo "[2/4] Admin cert..."
gen_cert admin "admin" "clientAuth" ""
echo "[3/4] Indexer cert..."
gen_cert wazuh-indexer "wazuh-indexer" "serverAuth,clientAuth" "DNS:wazuh-indexer,DNS:localhost,IP:127.0.0.1"
echo "[4/4] Manager + dashboard..."
gen_cert wazuh-manager "wazuh-manager" "serverAuth,clientAuth" "DNS:wazuh-manager,DNS:localhost,IP:127.0.0.1"
gen_cert wazuh-dashboard "wazuh-dashboard" "serverAuth,clientAuth" "DNS:wazuh-dashboard,DNS:localhost,IP:127.0.0.1"

for k in admin wazuh-indexer wazuh-manager wazuh-dashboard; do
  openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in $k-key.pem -out $k-key-pkcs8.pem 2>/dev/null
  mv $k-key-pkcs8.pem $k-key.pem
done

rm -f ca.cnf root-ca.srl
chmod 644 *.pem
chmod 600 *-key.pem *.key

echo ""
echo "Chain verify:"
openssl verify -CAfile root-ca.pem wazuh-indexer.pem
openssl verify -CAfile root-ca.pem admin.pem
