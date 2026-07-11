# SocBlitz Deployment Topologies

SocBlitz can be deployed with Docker (three topologies) or natively on VMs
without Docker (two topologies). Pick by fleet size and runtime preference:

| Topology | Runtime | Directory | Wazuh layout | Fleet size | Hosts |
|---|---|---|---|---|---|
| **All-in-one** | Docker | [`all-in-one/`](all-in-one/) | 1 manager + 1 indexer (single node) | ≤ 500 endpoints | 1 |
| **Multi-node (single host)** | Docker | [`multi-node/`](multi-node/) | 1 master + 2 workers + 3-node indexer cluster + LB | ≤ ~3,000 endpoints | 1 (large) |
| **Distributed** | Docker | [`distributed/`](distributed/) | Cluster spread across dedicated hosts | 3,000 – 20,000+ endpoints | 6+ |
| **VM all-in-one** | native (systemd) | [`vm/`](vm/) `socblitz-install.sh -a` | 1 manager + 1 indexer (single node) | ≤ 500 endpoints | 1 VM |
| **VM distributed** | native (systemd) | [`vm/`](vm/) role flags | Cluster spread across dedicated VMs | 3,000 – 20,000+ endpoints | 6+ VMs |

The native installs use the official Wazuh apt packages and a Wazuh-style
install assistant (`vm/socblitz-install.sh`) — quick install on one VM with
`-a`, or per-role commands for a multi-VM cluster. See [`vm/README.md`](vm/).

## How the topologies relate

All three run the **same SocBlitz application tier** (backend, frontend, Celery
workers, Postgres, Redis, MinIO, MISP, Ollama, Velociraptor). What changes is
the **Wazuh tier** underneath it:

```
all-in-one          multi-node (1 host)              distributed (N hosts)
───────────         ────────────────────             ─────────────────────────
manager ── indexer  nginx LB                         nginx LB host
                      ├─ master ──┐                    ├─ master host ──┐
app tier              ├─ worker-1 ├── indexer ×3       ├─ worker hosts  ├── indexer hosts ×3
                      └─ worker-2 ┘                    └─ (scale out)   ┘
                    app tier (same host)             app-tier host(s)
```

Agents always enroll and report **through the load balancer address** in the
multi-node and distributed topologies — never directly to a manager node —
so worker nodes can be added or replaced without touching agents.

## Sizing quick reference (rules of thumb)

- **Manager worker node:** ~2,000–3,000 agents per node (4–8 vCPU, 8–16 GB).
  The master coordinates the cluster and handles enrollment; keep agent event
  traffic on workers.
- **Indexer node:** size by events-per-second and retention, not agent count.
  3 nodes minimum for quorum. 8–16 vCPU, 32–64 GB RAM (heap = 50% of RAM,
  max 31 GB), NVMe/SSD storage.
- **Storage:** `daily GB ≈ EPS × avg_event_size(≈1 KB) × 86400 / 2^30`, then
  `total = daily × retention_days × (1 + replicas)`. A 10k fleet commonly
  lands at 30–100 GB/day of alerts + states.
- **App tier:** 8 vCPU / 16 GB covers the SocBlitz app comfortably; scale
  Celery workers (`--scale worker=N`) before scaling the API.
- **Velociraptor:** above ~5,000 clients move it to its own host.

## Prerequisite for > 500 endpoints (any topology)

The application code must be scale-fixed first — as shipped, agent sync is
capped at 500 agents (`backend/app/connectors/registry.py`), `GET /agents` is
unpaginated, and vulnerability sync is one serial API call per agent. Deploying
a bigger Wazuh cluster does not lift those limits; fix the app layer, then
choose the topology.
