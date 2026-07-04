# ⚡ SocBlitz — Open Source SOC Platform

Lightning-fast security operations centre built on open source.
Inspired by SOCFortress CoPilot — designed to be more powerful.

---

## What it does

SocBlitz is a single-pane-of-glass SOC platform that unifies:

- **Alerts** — ingest from Wazuh, Graylog, or webhook; auto-enriched with threat intel
- **Cases** — full incident lifecycle with timeline, observables, comments, TLP classification
- **Agents** — Wazuh + Velociraptor agent inventory, vulnerabilities, SCA
- **Threat Intelligence** — parallel VirusTotal + AbuseIPDB + MISP + OTX lookups
- **SOAR** — visual workflow automation; webhook endpoint for Wazuh active-response
- **Connectors** — health-monitored integrations with your full security stack
- **Multi-tenancy** — customer_code isolation at DB and infrastructure level (MSSP-ready)

---

## How SocBlitz differs from SOCFortress CoPilot

| Area | CoPilot | SocBlitz |
|------|---------|----------|
| Database | MySQL | **PostgreSQL** (JSONB, full-text, better JSON) |
| Task queue | APScheduler | **Celery + Redis** (distributed, scalable) |
| Caching | None | **Redis** (cache + pub/sub + real-time) |
| Frontend | Vue.js 3 + Naive UI | **React 18 + TypeScript + Tailwind** |
| Design | Blue/light | **Dark cyber — purple + cyan** |
| SOAR | Shuffle integration only | **Built-in SOAR engine** + Shuffle connector |
| AI | License-gated MCP | **Local LLM or OpenAI, no license required** |

---

## Quick start

```bash
# 1. Clone and configure
cp .env.example .env
# Edit .env — fill in connector URLs and passwords

# 2. Start everything
docker compose up -d

# 3. Get admin password
docker logs socblitz-backend 2>&1 | grep "Admin password"

# 4. Open https://localhost
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    SocBlitz stack                        │
│                                                          │
│  React SPA (Vite + Tailwind)                            │
│         ↕ HTTPS / WebSocket                             │
│  FastAPI backend (Python 3.12)                          │
│         ↕                    ↕                          │
│  PostgreSQL (data)     Redis (cache + Celery)           │
│         ↕                    ↕                          │
│  MinIO (artefacts)   Celery workers (background jobs)   │
└─────────────────────────────────────────────────────────┘
         ↕ REST APIs
┌────────────────────────────────────────────────────────┐
│               Your security stack                       │
│  Wazuh  ·  Graylog  ·  Velociraptor  ·  Grafana       │
│  MISP   ·  TheHive  ·  Shuffle  ·  CrowdStrike        │
└────────────────────────────────────────────────────────┘
```

---

## Connectors

Configure each connector URL + credentials in `.env`. SocBlitz seeds them on first boot and verifies health every 10 minutes.

| Connector | Purpose |
|-----------|---------|
| Wazuh Manager | Agent management, rules, active response |
| Wazuh Indexer | Alert and vulnerability data (OpenSearch) |
| Graylog | Log ingestion and stream management |
| Grafana | Dashboards and reporting |
| Velociraptor | DFIR and endpoint forensics |
| Shuffle | SOAR automation |
| TheHive | Case management |
| MISP | Threat intelligence platform |
| VirusTotal | IOC reputation |
| CrowdStrike | EDR isolation |

---

## API

All endpoints live under `/api/v1/`. Interactive docs: `http://localhost:5000/api/docs` (development mode).

| Endpoint | Description |
|----------|-------------|
| `POST /auth/login` | Login → JWT tokens |
| `GET /alerts` | List alerts with filters |
| `POST /alerts` | Ingest alert (triggers enrichment) |
| `GET /alerts/stats` | Severity + status counts |
| `GET /cases` | List cases |
| `POST /cases` | Create case |
| `POST /cases/{id}/observables` | Add observable (triggers TI enrichment) |
| `GET /agents` | List agents |
| `POST /agents/sync` | Trigger Wazuh agent sync |
| `POST /connectors/{id}/verify` | Test connector health |
| `POST /threat-intel/lookup` | Multi-source IOC lookup |
| `POST /soar/trigger/wazuh-alert` | Wazuh webhook endpoint |

---

## Adding a new connector

1. Add credentials to `.env`
2. Add `ConnectorType` enum value in `backend/app/models/__init__.py`
3. Add client class in `backend/app/connectors/`
4. Register verify function in `backend/app/connectors/registry.py`
5. Seed from env in `backend/app/db/init_db.py`
6. Add frontend card in `Connectors.tsx`

---

## Roadmap

- [ ] Real-time alert streaming via WebSocket
- [ ] SOAR visual canvas (drag-drop workflow builder)
- [ ] Automated customer provisioning (Graylog streams, Grafana orgs per tenant)
- [ ] ScoutSuite cloud security assessment integration
- [ ] Nuclei web vulnerability scanning integration  
- [ ] AI-powered alert summarisation (local LLM)
- [ ] Velociraptor artifact collection UI
- [ ] PDF case reports
- [ ] Customer portal (read-only view for end customers)
- [ ] Sigma rule management
- [ ] InfluxDB metrics integration

---

## License

Apache-2.0 — free to use, modify, and distribute.

Built by security engineers, for security engineers. ⚡
