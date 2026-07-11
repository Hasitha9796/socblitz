# All-in-one deployment (single node)

The all-in-one deployment **is the root `docker-compose.yml`** of this
repository — one Wazuh manager, one single-node indexer, and the full SocBlitz
application stack on a single Docker host.

```bash
cd <repo-root>
./setup.sh          # first time (certs, .env, secrets)
docker compose up -d
```

## What it is good for

- Labs, demos, PoCs, development
- Small production sites up to **~500 endpoints**

## Hard limits — do not push past them

| Component | Limit | Why |
|---|---|---|
| Wazuh manager | single node, cluster disabled | one `remoted`/`analysisd` instance |
| Wazuh indexer | single node, 1 GB heap | no replicas, no quorum, heap-bound |
| Storage | one host's disk | no ILM/retention policy configured |
| Availability | none | any container restart = ingestion gap |

## Tuning headroom on a bigger single host

If you must stretch this topology toward its ceiling:

1. **Indexer heap** — raise `OPENSEARCH_JAVA_OPTS` in `docker-compose.yml`
   to `-Xms4g -Xmx4g` (or 50% of host RAM, max 31 GB).
2. **Retention** — add an ISM policy to roll over and delete
   `wazuh-alerts-*` indices (see `deployment/distributed/README.md`,
   "Index lifecycle" section — it applies here too).
3. **Webhook level** — in `config/wazuh_cluster/wazuh_manager.conf`, the
   `<integration>` block fires per alert at level ≥ 7. The backend only
   persists level ≥ 12; raise `<level>` to 12 to cut integration load ~100×.
4. **Enrollment hardening** — set `<use_password>yes</use_password>` in the
   `<auth>` block and provision `/var/ossec/etc/authd.pass` before exposing
   port 1515 beyond a trusted network.

When you outgrow this, move to `deployment/multi-node/` (same host, real
cluster) or `deployment/distributed/` (multiple hosts).
