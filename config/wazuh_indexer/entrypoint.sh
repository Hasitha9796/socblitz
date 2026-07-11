#!/usr/bin/env bash
# Wazuh Docker Copyright (C) 2017, Wazuh Inc. (License GPLv2)
# Patched: uncomment securityadmin auto-init and fix config dir path
set -e

umask 0002

export USER=wazuh-indexer
export INSTALLATION_DIR=/usr/share/wazuh-indexer
export OPENSEARCH_PATH_CONF=${INSTALLATION_DIR}/config
export JAVA_HOME=${INSTALLATION_DIR}/jdk
export DISCOVERY=$(grep -oP "(?<=discovery.type: ).*" ${OPENSEARCH_PATH_CONF}/opensearch.yml)
export CACERT=$(grep -oP "(?<=plugins.security.ssl.transport.pemtrustedcas_filepath: ).*" ${OPENSEARCH_PATH_CONF}/opensearch.yml)
export CERT="${OPENSEARCH_PATH_CONF}/certs/admin.pem"
export KEY="${OPENSEARCH_PATH_CONF}/certs/admin.key"

run_as_other_user_if_needed() {
  if [[ "$(id -u)" == "0" ]]; then
    # If running as root, drop to specified UID and run command
    exec chroot --userspec=1000:0 / "${@}"
  else
    # Either we are running in Openshift with random uid and are a member of the root group
    # or with a custom --user
    exec "${@}"
  fi
}

# Allow user specify custom CMD, maybe bin/opensearch itself
# for example to directly specify `-E` style parameters for opensearch on k8s
# or simply to run /bin/bash to check the image
if [[ "$1" != "opensearchwrapper" ]]; then
  if [[ "$(id -u)" == "0" && $(basename "$1") == "opensearch" ]]; then
    # Rewrite CMD args to replace $1 with `opensearch` explicitly,
    # Without this, user could specify `opensearch -E x.y=z` but
    # `bin/opensearch -E x.y=z` would not work.
    set -- "opensearch" "${@:2}"
    # Use chroot to switch to UID 1000 / GID 0
    exec chroot --userspec=1000:0 / "$@"
  else
    # User probably wants to run something else, like /bin/bash, with another uid forced (Openshift?)
    exec "$@"
  fi
fi

# Allow environment variables to be set by creating a file with the
# contents, and setting an environment variable with the suffix _FILE to
# point to it. This can be used to provide secrets to a container, without
# the values being specified explicitly when running the container.
#
# This is also sourced in opensearch-env, and is only needed here
# as well because we use INDEXER_PASSWORD below. Sourcing this script
# is idempotent.
source /usr/share/wazuh-indexer/bin/opensearch-env-from-file

if [[ -f bin/opensearch-users ]]; then
  # Check for the INDEXER_PASSWORD environment variable to set the
  # bootstrap password for Security.
  #
  # This is only required for the first node in a cluster with Security
  # enabled, but we have no way of knowing which node we are yet. We'll just
  # honor the variable if it's present.
  if [[ -n "$INDEXER_PASSWORD" ]]; then
    [[ -f /usr/share/wazuh-indexer/opensearch.keystore ]] || (run_as_other_user_if_needed opensearch-keystore create)
    if ! (run_as_other_user_if_needed opensearch-keystore has-passwd --silent) ; then
      # keystore is unencrypted
      if ! (run_as_other_user_if_needed opensearch-keystore list | grep -q '^bootstrap.password$'); then
        (run_as_other_user_if_needed echo "$INDEXER_PASSWORD" | opensearch-keystore add -x 'bootstrap.password')
      fi
    else
      # keystore requires password
      if ! (run_as_other_user_if_needed echo "$KEYSTORE_PASSWORD" \
          | opensearch-keystore list | grep -q '^bootstrap.password$') ; then
        COMMANDS="$(printf "%s\n%s" "$KEYSTORE_PASSWORD" "$INDEXER_PASSWORD")"
        (run_as_other_user_if_needed echo "$COMMANDS" | opensearch-keystore add -x 'bootstrap.password')
      fi
    fi
  fi
fi

if [[ "$(id -u)" == "0" ]]; then
  # If requested and running as root, mutate the ownership of bind-mounts
  if [[ -n "$TAKE_FILE_OWNERSHIP" ]]; then
    chown -R 1000:0 /usr/share/wazuh-indexer/{data,logs}
  fi
fi

# Ensure the .opendistro_security index is initialized on every boot.
#
# We probe the LIVE cluster instead of trusting a .flag file. The old flag-only
# guard was unsafe: if the flag persisted in the data volume but the security
# index was actually absent (fresh/restored/wiped index), securityadmin was
# skipped and security stayed permanently uninitialized. That made the
# healthcheck fail forever (every dependent service hung on "waiting") AND
# stopped filebeat from shipping alerts — i.e. "no new logs received".
#
# Unauthenticated GET /_cluster/health tells us the true state:
#   * body "... not initialized" -> security index missing, run securityadmin
#   * HTTP 401 / "Unauthorized"   -> already initialized, nothing to do
# securityadmin is idempotent, so re-applying config is safe. The .flag is kept
# only as a fast-path marker; it is never trusted to SKIP a needed init.
if [[ "$DISCOVERY" == "single-node" ]]; then
  nohup bash -c "
    for attempt in \$(seq 1 30); do
      sleep 15
      probe=\$(curl -sk https://localhost:9200/_cluster/health 2>/dev/null || true)
      if echo \"\$probe\" | grep -qiE 'unauthorized|\"status\":401'; then
        touch /var/lib/wazuh-indexer/.flag
        echo \"security already initialized (attempt \$attempt)\"
        break
      fi
      if echo \"\$probe\" | grep -qi 'not initialized'; then
        if JAVA_HOME=/usr/share/wazuh-indexer/jdk \
          /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
            -cd /usr/share/wazuh-indexer/config/opensearch-security/ \
            -nhnv \
            -cacert ${CACERT} \
            -cert ${CERT} \
            -key ${KEY} \
            -p 9200 -icl; then
          touch /var/lib/wazuh-indexer/.flag
          echo \"securityadmin succeeded on attempt \$attempt\"
          break
        fi
        echo \"securityadmin attempt \$attempt failed, retrying\"
      fi
      # else: node not reachable yet (still starting) — keep waiting
    done
  " &>/var/log/wazuh-indexer/securityadmin.log &
fi

run_as_other_user_if_needed /usr/share/wazuh-indexer/bin/opensearch <<<"$KEYSTORE_PASSWORD"
