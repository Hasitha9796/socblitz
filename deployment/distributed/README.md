# Distributed deployment (multiple hosts) — 3,000 to 20,000+ endpoints

Each subdirectory is a self-contained Docker Compose bundle for **one host
role**. Copy the bundle to its host (the `app-tier` bundle needs the full repo
checkout for image builds), fill in `.env` + placeholders, `docker compose up -d`.

```
                        agents (10,000+)
                              │
                     LB host (1514/1515)          ← load-balancer/
                    ┌─────────┴──────────┐
             1515 → │                    │ ← 1514 (source-IP hash)
              master host          worker hosts ×4     ← wazuh-master/  wazuh-worker/
              (enroll, API,       (~2,500 agents each)
               cluster mgmt)             │
                    └─────────┬──────────┘
                       indexer hosts ×3            ← indexer-node/
                    (OpenSearch cluster, replicas)
                              ▲
                        app-tier host              ← app-tier/
              (SocBlitz backend/frontend/celery,
               postgres, redis, minio, misp, ollama,
               velociraptor*)
```

## Reference sizing — 10,000 endpoints

| Role | Count | Per-host spec | Bundle |
|---|---|---|---|
| Load balancer | 1 (2 with keepalived for HA) | 2 vCPU / 4 GB | `load-balancer/` |
| Wazuh master | 1 | 8 vCPU / 16 GB / 200 GB SSD | `wazuh-master/` |
| Wazuh worker | 4 (~2,500 agents each) | 8 vCPU / 16 GB / 200 GB SSD | `wazuh-worker/` |
| Wazuh indexer | 3 | 16 vCPU / 64 GB / NVMe (see storage below) | `indexer-node/` |
| App tier | 1 | 8 vCPU / 16 GB / 200 GB SSD | `app-tier/` |
| Velociraptor* | 1 (recommended > 5k clients) | 8 vCPU / 16 GB / 1 TB | (move out of app-tier) |

**Indexer storage:** `daily_GB ≈ EPS × 1KB × 86400 / 2^30`; total =
`daily × retention_days × (1 + replicas)`, divided across the 3 nodes, plus
~30% headroom. Example: 5,000 EPS ≈ 400 GB/day → 90-day retention with 1
replica ≈ 72 TB cluster-wide ≈ 24 TB/node. If that's too much, cut retention
or ship cold indices to snapshots — do the math before buying disks.

## Deployment order

**0. Prerequisites**
- All hosts: Docker + Compose, `vm.max_map_count=262144`
  (`sysctl -w vm.max_map_count=262144`, persist in `/etc/sysctl.d/`).
- Generate one cluster key: `openssl rand -hex 16` — used on master + all workers.
- Firewall (see port matrix below).

**1. Certificates — generate once, distribute**

```bash
cd deployment/distributed
cp certs.yml.example certs.yml        # edit: real IPs for every node
docker compose -f generate-certs.yml run --rm generator
```

Then distribute out of `./certs/`:

| Destination host | Files → rename to |
|---|---|
| each indexer | `root-ca.pem`, `admin.pem`, `admin-key.pem → admin.key`, `wazuh-indexer-N.pem → node.pem`, `wazuh-indexer-N-key.pem → node.key` |
| master | `root-ca.pem`, `wazuh-master.pem → node.pem`, `wazuh-master-key.pem → node-key.pem` |
| each worker | `root-ca.pem`, `wazuh-worker-N.pem → node.pem`, `wazuh-worker-N-key.pem → node-key.pem` |

Place them in the bundle's `./certs/` directory on each host.

**2. Indexer hosts (all 3)** — `indexer-node/` on each; `SECURITY_INIT=yes`
only on `wazuh-indexer-1`'s `.env`. Start all three within a few minutes of
each other so the cluster can form. Verify:

```bash
curl -sk -u admin:$PW https://10.0.0.11:9200/_cat/nodes?v   # expect 3 nodes
```

**3. Master host** — `wazuh-master/`; sed the placeholders in
`config/master.conf` (instructions in the compose header), then up. Verify the
API: `curl -k https://10.0.0.21:55000` (expect 401 without credentials).

**4. Worker hosts** — `wazuh-worker/` per host with unique `NODE_NAME`. Verify
from the master:

```bash
docker exec socblitz-wazuh-master /var/ossec/bin/cluster_control -l
# expect: master + every worker, connected
```

**5. Load balancer host** — `load-balancer/`; fill IPs in `nginx.conf`, up.

**6. App tier host** — `app-tier/` (inside a full repo checkout);
`.env` points `WAZUH_MANAGER_URL` at the master and `WAZUH_INDEXER_URL` at an
indexer node. Workers/master POST webhooks to this host's `:5000` —
`{{APP_TIER_IP}}` in the manager configs must be this host.

**7. Agents** — enroll against the **LB address**. Set `AGENT_PUBLIC_HOST`
in the app-tier `.env` so generated installers embed it. Roll out in waves
(e.g. 500–1,000 at a time) — first enrollment triggers syscollector full
scans, and 10k simultaneous first-scans is a self-inflicted DDoS.

## Port matrix (host firewall rules)

| From | To | Port | Purpose |
|---|---|---|---|
| agents | LB | 1514, 1515/tcp | events, enrollment |
| LB | workers | 1514/tcp | events |
| LB | master | 1515/tcp | enrollment |
| workers | master | 1516/tcp | cluster sync |
| master, workers | indexers | 9200/tcp | alert/state indexing |
| indexers | indexers | 9300/tcp | cluster transport |
| app tier | master | 55000/tcp | Wazuh API |
| app tier | indexers | 9200/tcp | queries |
| master, workers | app tier | 5000/tcp | SOAR webhook |
| analysts | app tier | 8080/8443, 8889, 8091 | UI, Velociraptor, MISP |

## Index lifecycle management (required at this scale)

Without ISM the indexer disks simply fill. Apply once against any indexer node
(adjust ages to your retention policy):

```bash
curl -sk -u admin:$PW -X PUT "https://10.0.0.11:9200/_plugins/_ism/policies/wazuh-alerts-rollover" \
  -H 'Content-Type: application/json' -d '{
  "policy": {
    "description": "Roll over daily wazuh-alerts, delete after 90 days",
    "default_state": "hot",
    "ism_template": [{ "index_patterns": ["wazuh-alerts-*"], "priority": 50 }],
    "states": [
      { "name": "hot",
        "actions": [{ "rollover": { "min_index_age": "1d", "min_primary_shard_size": "25gb" } }],
        "transitions": [{ "state_name": "delete", "conditions": { "min_index_age": "90d" } }] },
      { "name": "delete", "actions": [{ "delete": {} }], "transitions": [] }
    ]
  }
}'
```

## Scaling / operations

- **Add a worker host:** add it to `certs.yml`, regenerate/distribute its cert,
  deploy the `wazuh-worker/` bundle with a new `NODE_NAME`, add one upstream
  line to the LB's `nginx.conf`, reload nginx. Agents rebalance automatically.
- **Add an indexer node:** deploy `indexer-node/` with the new name/IP, add its
  CN to `plugins.security.nodes_dn` in `opensearch.yml` on all nodes, and add
  its IP to every node's `SEED_HOSTS`.
- **Backups:** Postgres (`pg_dump`) + MinIO on the app tier; OpenSearch
  snapshots for the indexers; `/var/ossec/etc` volumes on the managers hold
  agent keys — losing the master's `client.keys` orphans the whole fleet, back
  it up.
- **Monitoring:** watch `analysisd` events-dropped counters on workers
  (`/var/ossec/var/run/wazuh-analysisd.state`), indexer heap + disk watermarks,
  Celery queue depth in Redis, and webhook 5xx rates on the backend.

## Hardening checklist (before agents leave the lab)

- [ ] Enrollment password: `<use_password>yes</use_password>` on the master +
      `/var/ossec/etc/authd.pass`, and pass the key to the agent installers.
- [ ] All `CHANGE_ME` values replaced; no defaults left (compose enforces most).
- [ ] TLS in front of the app tier (8443 or a reverse proxy) — the webhook
      port 5000 should be reachable **only** from manager/worker IPs.
- [ ] `verify_ssl` enabled in the backend connector layer once real certs are
      in place (it is currently hardcoded off in `backend/app/connectors/registry.py`).
- [ ] Indexer/manager ports (9200/9300/1516/55000) firewalled to cluster + app
      tier IPs only — never internet-exposed.
