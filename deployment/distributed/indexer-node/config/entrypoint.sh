#!/usr/bin/env bash
# Wazuh Docker Copyright (C) 2017, Wazuh Inc. (License GPLv2)
# Patched for MULTI-NODE clusters: securityadmin auto-init is gated on the
# SECURITY_INIT env var (set it on exactly ONE node — the first one) instead
# of on `discovery.type: single-node`.
set -e

umask 0002

export USER=wazuh-indexer
export INSTALLATION_DIR=/usr/share/wazuh-indexer
export OPENSEARCH_PATH_CONF=${INSTALLATION_DIR}/config
export JAVA_HOME=${INSTALLATION_DIR}/jdk
export CACERT=$(grep -oP "(?<=plugins.security.ssl.transport.pemtrustedcas_filepath: ).*" ${OPENSEARCH_PATH_CONF}/opensearch.yml)
export CERT="${OPENSEARCH_PATH_CONF}/certs/admin.pem"
export KEY="${OPENSEARCH_PATH_CONF}/certs/admin.key"

run_as_other_user_if_needed() {
  if [[ "$(id -u)" == "0" ]]; then
    exec chroot --userspec=1000:0 / "${@}"
  else
    exec "${@}"
  fi
}

if [[ "$1" != "opensearchwrapper" ]]; then
  if [[ "$(id -u)" == "0" && $(basename "$1") == "opensearch" ]]; then
    set -- "opensearch" "${@:2}"
    exec chroot --userspec=1000:0 / "$@"
  else
    exec "$@"
  fi
fi

source /usr/share/wazuh-indexer/bin/opensearch-env-from-file

if [[ -f bin/opensearch-users ]]; then
  if [[ -n "$INDEXER_PASSWORD" ]]; then
    [[ -f /usr/share/wazuh-indexer/opensearch.keystore ]] || (run_as_other_user_if_needed opensearch-keystore create)
    if ! (run_as_other_user_if_needed opensearch-keystore has-passwd --silent) ; then
      if ! (run_as_other_user_if_needed opensearch-keystore list | grep -q '^bootstrap.password$'); then
        (run_as_other_user_if_needed echo "$INDEXER_PASSWORD" | opensearch-keystore add -x 'bootstrap.password')
      fi
    else
      if ! (run_as_other_user_if_needed echo "$KEYSTORE_PASSWORD" \
          | opensearch-keystore list | grep -q '^bootstrap.password$') ; then
        COMMANDS="$(printf "%s\n%s" "$KEYSTORE_PASSWORD" "$INDEXER_PASSWORD")"
        (run_as_other_user_if_needed echo "$COMMANDS" | opensearch-keystore add -x 'bootstrap.password')
      fi
    fi
  fi
fi

if [[ "$(id -u)" == "0" ]]; then
  if [[ -n "$TAKE_FILE_OWNERSHIP" ]]; then
    chown -R 1000:0 /usr/share/wazuh-indexer/{data,logs}
  fi
fi

# Initialize the security index ONCE per cluster, on the node started with
# SECURITY_INIT=yes. Waits longer than the single-node variant because the
# cluster must first form and elect a master. The .flag file in the data
# volume prevents re-running on restarts.
# The flag is only written AFTER securityadmin succeeds — writing it up front
# meant one failed first attempt left the cluster permanently uninitialized.
if [[ "${SECURITY_INIT}" == "yes" ]] && [[ ! -f "/var/lib/wazuh-indexer/.flag" ]]; then
  nohup bash -c "
    sleep 90
    for attempt in \$(seq 1 20); do
      if JAVA_HOME=/usr/share/wazuh-indexer/jdk \
        /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
          -cd /usr/share/wazuh-indexer/config/opensearch-security/ \
          -nhnv -icl \
          -cacert ${CACERT} \
          -cert ${CERT} \
          -key ${KEY} \
          -p 9200; then
        touch /var/lib/wazuh-indexer/.flag
        echo \"securityadmin succeeded on attempt \$attempt\"
        break
      fi
      echo \"securityadmin attempt \$attempt failed, retrying in 30s\"
      sleep 30
    done
  " &>/var/log/wazuh-indexer/securityadmin.log &
fi

run_as_other_user_if_needed /usr/share/wazuh-indexer/bin/opensearch <<<"$KEYSTORE_PASSWORD"
