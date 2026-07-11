# Multi-node deployment (single Docker host)

A real Wazuh cluster — 1 master + 2 workers behind an nginx TCP load balancer,
plus a 3-node indexer cluster — together with the full SocBlitz application
tier, all on **one large Docker host**.

```
                      agents (≤ ~3,000)
                            │
                      host:1514 / 1515
                            │
                     ┌──── nginx LB ────┐
              1515 → │                  │ ← 1514 (hash by source IP)
                 wazuh-master    wazuh-worker-1 / wazuh-worker-2
                     │                  │
                     └──┬───────────────┘
            wazuh-indexer-1 ─ wazuh-indexer-2 ─ wazuh-indexer-3
                            ▲
        backend · frontend · celery · postgres · redis · minio
                misp · ollama · velociraptor
```

**Use this when:** 500–3,000 endpoints, or you want cluster semantics
(worker failover, indexer replicas) before going fully distributed.
**Host sizing:** 16+ vCPU, 64+ GB RAM, NVMe. amd64 strongly recommended
(the Wazuh images are amd64-only; QEMU emulation at this scale is not viable).

## Setup

All commands run **from this directory** (`deployment/multi-node/`).

```bash
# 1. Cluster key — must be identical on master and workers
KEY=$(openssl rand -hex 16)
sed -i "s/CLUSTER_KEY_CHANGE_ME/$KEY/" config/wazuh_cluster/*.conf

# 2. Certificates for all 6 Wazuh nodes (writes ./certs/)
docker compose -f generate-certs.yml run --rm generator
sudo chmod -R 644 certs/*.pem 2>/dev/null || true

# 3. Secrets
cp .env.example .env
# edit .env — every CHANGE_ME must be replaced; compose fails fast otherwise

# 4. Bring it up (first boot: indexer cluster forms, then security init ~90s)
docker compose up -d --build
```

## Verify the cluster

```bash
# Indexer cluster: expect 3 nodes, status green
curl -sk -u admin:$INDEXER_PW https://localhost:9200/_cat/nodes?v   # via any indexer node's 9200 if exposed, or:
docker exec socblitz-wazuh-indexer-1 curl -sk -u admin:$INDEXER_PW https://localhost:9200/_cluster/health?pretty

# Manager cluster: expect master + worker-1 + worker-2
docker exec socblitz-wazuh-master /var/ossec/bin/cluster_control -l

# Agent connectivity: enroll a test agent against <host>:1515,
# events flow to <host>:1514 → nginx → a worker
```

## Enrolling agents

Point agents (and the SocBlitz agent installer scripts) at **this host's
address** — the LB listens on 1514/1515. Set `AGENT_PUBLIC_HOST` in `.env`
so generated installers embed the right address. Agents stick to a worker
via consistent source-IP hashing; if a worker dies, its agents reconnect
through the LB to the surviving worker automatically.

## Scaling within this topology

- **More workers:** copy the `wazuh-worker-2` service block (and its volume
  set + a `worker-3.conf` with a unique `node_name`), add the node to
  `certs.yml`, regenerate certs, and add the server to the `wazuh_events`
  upstream in `config/nginx/nginx.conf`.
- **Indexer heap:** raise `INDEXER_HEAP` in `.env` as fleet/EPS grows.
- **Celery:** `docker compose up -d --scale worker=4`.

When one host can't hold it (≳3,000 endpoints, or indexer heap needs exceed
host RAM), move to `deployment/distributed/` — the configs there are the
same shape, just split per host.

## Notes

- The `<integration>` webhook fires at **level ≥ 12** here (not 7 as in the
  all-in-one) — the backend only persists ≥ 12, and per-alert webhooks at
  level 7 don't survive cluster-scale alert volume.
- Retention: add an ISM policy for `wazuh-alerts-*` (see
  `../distributed/README.md`, "Index lifecycle management").
- Hardening: enable enrollment passwords (`<auth><use_password>yes`) and
  provision `/var/ossec/etc/authd.pass` on the master before exposing 1515.
