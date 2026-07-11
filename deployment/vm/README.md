# SocBlitz VM deployment (native, no Docker)

Installs the same stack as the Docker topologies directly onto VMs with
systemd services and the official Wazuh apt packages — modeled on Wazuh's
`wazuh-install.sh` assistant. Two modes:

| Mode | Command | Mirrors (Docker) | Fleet size |
|---|---|---|---|
| **All-in-one** | `socblitz-install.sh -a` | root `docker-compose.yml` | ≤ ~500 endpoints |
| **Distributed** | role flags, one VM per role | `deployment/distributed/` | 3,000 – 20,000+ |

**Supported OS:** Ubuntu 22.04 / 24.04, Debian 12 (amd64 or arm64).
Internet access is required during install (Wazuh apt repo, NodeSource,
MinIO/Velociraptor/Ollama downloads).

## What gets installed

| Component | How | Service |
|---|---|---|
| Wazuh manager 4.14.5 | official apt package (held) | `wazuh-manager` |
| Wazuh indexer 4.14.5 | official apt package (held) | `wazuh-indexer` |
| SocBlitz backend | Python venv at `/opt/socblitz/venv` | `socblitz-backend` |
| Celery worker / beat | same venv | `socblitz-worker`, `socblitz-beat` |
| Frontend | built with Node 20, served by nginx on 80/443 | `nginx` |
| PostgreSQL | distro package | `postgresql` |
| Redis | distro package (password + 512 MB cap) | `redis-server` |
| MinIO | official binary, API on 127.0.0.1:9000, console :9001 | `minio` |
| Ollama + models | official installer (`llama3.2:1b`, `nomic-embed-text`) | `ollama` |
| Velociraptor | latest release binary, GUI :8889, agents :8010 | `velociraptor` |

Differences from the Docker stacks:

- **MISP is not bundled** (a native MISP install is its own project). Threat
  intel still works via VirusTotal/AbuseIPDB/OTX keys; to use MISP, point
  `MISP_URL` / `MISP_API_KEY` in `/etc/socblitz/socblitz.env` at an existing
  instance (e.g. the Docker deployment's MISP) and restart the backend.
- The UI is served on standard **80/443** (Docker uses 8080/8443).
- All generated credentials land in `/etc/socblitz/socblitz-passwords.txt`
  (mode 600) — the equivalent of Wazuh's `wazuh-passwords.txt`.

---

## All-in-one (single VM)

Minimum 8 GB RAM / 4 vCPU / 100 GB disk.

```bash
git clone <repo> socblitz && cd socblitz/deployment/vm
sudo bash socblitz-install.sh -a
```

Installs, in order: single-node Wazuh indexer (localhost-bound) → Wazuh
manager (standalone, SOAR webhook to the local backend) → PostgreSQL, Redis,
MinIO, Ollama, Velociraptor → SocBlitz backend/worker/beat → frontend behind
nginx. Then open `https://<vm-ip>` and log in as `admin@socblitz.local`
(password in the passwords file).

Agent enrollment one-liners: SocBlitz UI → Agents → Deploy.

---

## Distributed (one VM per role)

Same topology as `deployment/distributed/` — see that README for sizing,
storage math, and the port matrix; it all applies unchanged.

```
agents → LB (1514/1515) → master + workers → indexers ×3 ← app tier
```

**1. Describe the cluster and generate secrets** (on any machine with this
repo — the app-tier VM is convenient):

```bash
cd deployment/vm
cp config.yml.example config.yml     # edit every IP, add/remove workers
sudo bash socblitz-install.sh -g --app-tier-ip 10.0.0.40 --lb-ip 10.0.0.5
```

Produces `socblitz-install-files.tar` — certificates, the cluster key, and
generated passwords. **Treat it as a secret.** Copy it to every cluster VM
(the role commands expect it in the current directory) and copy
`socblitz-install.sh` alongside it.

**2. Indexer VMs** (all of them, within a few minutes of each other):

```bash
sudo bash socblitz-install.sh --wazuh-indexer wazuh-indexer-1   # name per VM
```

**3. Initialize cluster security** — once, on any indexer VM:

```bash
sudo bash socblitz-install.sh --start-cluster    # prints _cat/nodes — expect all nodes
```

**4. Manager VMs** — master first, then each worker:

```bash
sudo bash socblitz-install.sh --wazuh-server wazuh-master
sudo bash socblitz-install.sh --wazuh-server wazuh-worker-1
# verify on the master: /var/ossec/bin/cluster_control -l
```

**5. Load balancer VM:**

```bash
sudo bash socblitz-install.sh --load-balancer
```

**6. App-tier VM** — needs the full repo checkout (builds the frontend,
copies the backend), plus the tar in `deployment/vm/`:

```bash
cd socblitz/deployment/vm     # with socblitz-install-files.tar present
sudo bash socblitz-install.sh --app-tier
```

**7. Agents** enroll against the LB address (baked into generated installers
via `AGENT_PUBLIC_HOST`). Roll out in waves of 500–1,000.

### Scaling out later

- **Add a worker:** add it to `config.yml`, re-run `-g` (regenerates the tar;
  existing certs are re-created — distribute the new node's cert only, or keep
  the original tar and generate a single cert with wazuh-certs-tool), install
  with `--wazuh-server`, then re-run `--load-balancer` on the LB VM to pick up
  the new upstream.
- **Indexer ISM/retention policy:** required at scale — apply the policy from
  `../distributed/README.md` ("Index lifecycle management").

## Operations

```bash
systemctl status socblitz-backend socblitz-worker socblitz-beat
journalctl -u socblitz-backend -e          # backend logs
tail -f /var/ossec/logs/ossec.log          # manager
journalctl -u wazuh-indexer -e             # indexer
```

- App config: `/etc/socblitz/socblitz.env` (restart `socblitz-backend`,
  `socblitz-worker`, `socblitz-beat` after edits).
- Upgrade SocBlitz: pull the repo, re-run the app-tier/`-a` install — it
  rsyncs to `/opt/socblitz`, reinstalls deps, rebuilds the frontend.
- Wazuh packages are apt-held; upgrade deliberately with
  `apt-mark unhold wazuh-manager wazuh-indexer` and the Wazuh upgrade guide.

## Hardening (before production)

Same checklist as `../distributed/README.md`, plus VM-specific:

- Firewall every port to its consumers (matrix in the distributed README);
  nothing except the LB (1514/1515), the UI (443), and agent-deploy (5000,
  or proxy it) should be reachable from endpoint networks.
- Replace the self-signed nginx cert in `/etc/nginx/certs/`.
- Enrollment password: `<use_password>yes</use_password>` in
  `/var/ossec/etc/ossec.conf` on the master + `/var/ossec/etc/authd.pass`.
- `/etc/socblitz/socblitz-passwords.txt` and the install tar contain every
  secret — store them in your vault and delete from the VMs.
