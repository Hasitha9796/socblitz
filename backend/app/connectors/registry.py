"""
SocBlitz connector implementations.
Each connector wraps a specific tool's API.
"""
from __future__ import annotations
import asyncio
import json
import httpx
from abc import ABC, abstractmethod
from loguru import logger
from app.core.config import settings
from app.models import Connector, ConnectorType


# ─────────────────────────────────────────────────────────────────────────────
# Base connector
# ─────────────────────────────────────────────────────────────────────────────

class BaseConnector(ABC):
    timeout = httpx.Timeout(15.0, connect=5.0)
    verify_ssl = False  # Override per-connector

    def _client(self, base_url: str, headers: dict | None = None, auth=None) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=base_url,
            headers=headers or {},
            auth=auth,
            timeout=self.timeout,
            verify=self.verify_ssl,
        )

    @abstractmethod
    async def test_connection(self) -> tuple[bool, str]:
        ...


# ─────────────────────────────────────────────────────────────────────────────
# Wazuh Indexer (OpenSearch)
# ─────────────────────────────────────────────────────────────────────────────

class WazuhIndexerClient(BaseConnector):
    def __init__(self):
        self.url  = settings.WAZUH_INDEXER_URL
        self.user = settings.WAZUH_INDEXER_USER
        self.pwd  = settings.WAZUH_INDEXER_PASSWORD

    def _client(self, **kwargs):
        return super()._client(self.url, auth=(self.user, self.pwd))

    async def test_connection(self) -> tuple[bool, str]:
        try:
            async with self._client() as c:
                r = await c.get("/")
                return r.status_code < 400, r.text[:200]
        except Exception as e:
            return False, str(e)

    async def search(self, index: str, body: dict) -> dict:
        async with self._client() as c:
            r = await c.post(f"/{index}/_search", json=body)
            r.raise_for_status()
            return r.json()

    async def get_agent_vulnerabilities(self, agent_id: str) -> dict:
        body = {
            "query": {"bool": {"must": [{"match": {"agent.id": agent_id}}]}},
            "size": 100,
            "sort": [{"vulnerability.severity": {"order": "desc"}}],
        }
        return await self.search("wazuh-states-vulnerabilities-*", body)

    async def get_vulnerability_counts_by_agent(self) -> dict[str, dict]:
        """Total + critical vulnerability counts for the whole fleet in a
        handful of aggregation requests, instead of one search per agent.
        Returns {agent_id: {"total": int, "critical": int}}."""
        counts: dict[str, dict] = {}
        after_key = None
        async with self._client() as c:
            while True:
                composite: dict = {
                    "size": 1000,
                    "sources": [{"agent": {"terms": {"field": "agent.id"}}}],
                }
                if after_key:
                    composite["after"] = after_key
                body = {
                    "size": 0,
                    "aggs": {"by_agent": {
                        "composite": composite,
                        "aggs": {"critical": {"filter": {
                            "terms": {"vulnerability.severity": ["Critical", "critical"]}
                        }}},
                    }},
                }
                r = await c.post("/wazuh-states-vulnerabilities-*/_search", json=body)
                r.raise_for_status()
                agg = r.json().get("aggregations", {}).get("by_agent", {})
                for bucket in agg.get("buckets", []):
                    counts[str(bucket["key"]["agent"])] = {
                        "total": bucket["doc_count"],
                        "critical": bucket["critical"]["doc_count"],
                    }
                after_key = agg.get("after_key")
                if not after_key or not agg.get("buckets"):
                    return counts

    async def get_recent_alerts(self, hours: int = 24, size: int = 100,
                                start: str | None = None, end: str | None = None,
                                q: str | None = None) -> dict:
        # An explicit start/end window (ISO-8601) overrides the relative `hours`
        # lookback used by the default live view.
        if start or end:
            rng: dict = {}
            if start:
                rng["gte"] = start
            if end:
                rng["lte"] = end
        else:
            rng = {"gte": f"now-{hours}h"}

        must: list = [{"range": {"@timestamp": rng}}]
        # Optional Lucene query_string, e.g. `rule.level:>=10 AND agent.name:web-01`.
        # default_operator AND makes space-separated terms narrow (dashboard-like);
        # lenient tolerates type mismatches instead of erroring the whole search.
        if q and q.strip():
            must.append({
                "query_string": {
                    "query": q,
                    "default_operator": "AND",
                    "analyze_wildcard": True,
                    "lenient": True,
                }
            })

        body = {
            "query": {"bool": {"must": must}},
            "size": size,
            "sort": [{"@timestamp": {"order": "desc"}}],
        }
        return await self.search("wazuh-alerts-*", body)

    async def get_alert_by_id(self, doc_id: str) -> dict | None:
        body = {"query": {"ids": {"values": [doc_id]}}, "size": 1}
        result = await self.search("wazuh-alerts-*", body)
        hits = result.get("hits", {}).get("hits", [])
        return hits[0] if hits else None

    async def get_sca_results(self, agent_id: str) -> dict:
        body = {
            "query": {"match": {"agent.id": agent_id}},
            "size": 1,
            "sort": [{"@timestamp": {"order": "desc"}}],
        }
        return await self.search("wazuh-states-inventory-*", body)


# ─────────────────────────────────────────────────────────────────────────────
# Wazuh Manager API
# ─────────────────────────────────────────────────────────────────────────────

class WazuhManagerClient(BaseConnector):
    def __init__(self):
        self.url  = settings.WAZUH_MANAGER_URL
        self.user = settings.WAZUH_MANAGER_USER
        self.pwd  = settings.WAZUH_MANAGER_PASSWORD
        self._token: str | None = None

    async def _get_token(self) -> str:
        if self._token:
            return self._token
        async with httpx.AsyncClient(base_url=self.url, verify=False, timeout=self.timeout) as c:
            r = await c.get("/security/user/authenticate", auth=(self.user, self.pwd))
            r.raise_for_status()
            self._token = r.json()["data"]["token"]
            return self._token

    async def _authed_client(self) -> httpx.AsyncClient:
        token = await self._get_token()
        return httpx.AsyncClient(
            base_url=self.url,
            headers={"Authorization": f"Bearer {token}"},
            verify=False,
            timeout=self.timeout,
        )

    async def test_connection(self) -> tuple[bool, str]:
        try:
            token = await self._get_token()
            return bool(token), "Connected"
        except Exception as e:
            return False, str(e)

    async def list_agents(self, page_size: int = 500) -> list[dict]:
        """Fetch every agent, paginating past the Wazuh API's per-request cap."""
        agents: list[dict] = []
        offset = 0
        async with await self._authed_client() as c:
            while True:
                r = await c.get("/agents", params={
                    "limit": page_size,
                    "offset": offset,
                    "select": "id,name,ip,os.platform,os.version,status,version,group,lastKeepAlive",
                })
                r.raise_for_status()
                data = r.json().get("data", {})
                items = data.get("affected_items", [])
                agents.extend(items)
                offset += len(items)
                if not items or offset >= data.get("total_affected_items", 0):
                    return agents

    async def get_agent(self, agent_id: str) -> dict:
        async with await self._authed_client() as c:
            r = await c.get(f"/agents/{agent_id}")
            r.raise_for_status()
            return r.json()["data"]["affected_items"][0]

    async def run_active_response(self, agent_id: str, command: str, arguments: list | None = None) -> dict:
        payload = {"command": command, "arguments": arguments or [], "agents_list": [agent_id]}
        async with await self._authed_client() as c:
            r = await c.put("/active-response", json=payload)
            r.raise_for_status()
            return r.json()

    async def delete_agent(self, agent_id: str) -> dict:
        """Deregister an agent from the manager — the API equivalent of
        `/var/ossec/bin/manage_agents -r <id>`. `older_than=0s` removes it
        regardless of last-seen age (the API default is 7d), and purge drops
        it from the manager's key store entirely."""
        async with await self._authed_client() as c:
            r = await c.delete("/agents", params={
                "agents_list": agent_id,
                "status": "all",       # required by the API; "all" = any agent state
                "older_than": "0s",
                "purge": "true",
            })
            r.raise_for_status()
            return r.json()

    async def list_rules(self, limit: int = 500) -> list[dict]:
        async with await self._authed_client() as c:
            r = await c.get("/rules", params={"limit": limit})
            r.raise_for_status()
            return r.json()["data"].get("affected_items", [])

    async def get_manager_info(self) -> dict:
        async with await self._authed_client() as c:
            r = await c.get("/manager/info")
            r.raise_for_status()
            return r.json()["data"]


# ─────────────────────────────────────────────────────────────────────────────
# Velociraptor
# ─────────────────────────────────────────────────────────────────────────────

class VelociraptorClient(BaseConnector):
    """
    Velociraptor uses gorilla/csrf protection on its gRPC-gateway REST API.
    Auth flow: GET /app/index.html with Basic auth → receive _gorilla_csrf cookie
    + X-CSRF-Token response header → include both in subsequent POST requests.
    """

    def __init__(self):
        self.url  = settings.VELOCIRAPTOR_URL
        self.user = settings.VELOCIRAPTOR_USER
        self.pwd  = settings.VELOCIRAPTOR_PASSWORD

    def _new_client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=self.url,
            auth=(self.user, self.pwd),
            verify=False,
            timeout=self.timeout,
            follow_redirects=True,
        )

    async def test_connection(self) -> tuple[bool, str]:
        if not self.user or not self.pwd:
            return False, "VELOCIRAPTOR_USER / VELOCIRAPTOR_PASSWORD not configured"
        try:
            async with self._new_client() as c:
                prep = await c.get("/app/index.html")
                csrf = prep.headers.get("x-csrf-token", "")
                hdr = {"X-CSRF-Token": csrf, "Referer": self.url + "/"}
                r = await c.get("/api/v1/GetGlobalUsers", headers=hdr)
                if r.status_code == 200:
                    names = [u.get("name", "") for u in r.json().get("users", [])]
                    return True, f"Connected — users: {', '.join(names)}"
                return False, f"HTTP {r.status_code}: {r.text[:100]}"
        except Exception as e:
            return False, str(e)

    async def list_clients(self, limit: int = 200) -> list[dict]:
        async with self._new_client() as c:
            prep = await c.get("/app/index.html")
            csrf = prep.headers.get("x-csrf-token", "")
            hdr = {"X-CSRF-Token": csrf, "Referer": self.url + "/"}
            r = await c.get(
                "/api/v1/SearchClients",
                params={"query": "all", "count": limit, "type": "CLIENT"},
                headers=hdr,
            )
            if r.status_code != 200:
                return []
            return r.json().get("items", [])

    async def run_artifact(self, client_id: str, artifact: str, params: dict | None = None) -> dict:
        body = {
            "client_id": client_id,
            "artifacts": [artifact],
            "parameters": {"env": [{"key": k, "value": v} for k, v in (params or {}).items()]},
        }
        async with self._new_client() as c:
            prep = await c.get("/app/index.html")
            csrf = prep.headers.get("x-csrf-token", "")
            hdr = {"X-CSRF-Token": csrf, "Referer": self.url + "/"}
            r = await c.post("/api/v1/CollectArtifact", json=body, headers=hdr)
            r.raise_for_status()
            return r.json()

    async def list_flows(self, client_id: str, limit: int = 20) -> list[dict]:
        async with self._new_client() as c:
            prep = await c.get("/app/index.html")
            csrf = prep.headers.get("x-csrf-token", "")
            hdr = {"X-CSRF-Token": csrf, "Referer": self.url + "/"}
            # GetClientFlows takes client_id as a query param and returns a
            # table: {columns: [...], rows: [{json: "<array aligned to columns>"}]}
            r = await c.get(
                "/api/v1/GetClientFlows",
                params={"client_id": client_id, "count": limit},
                headers=hdr,
            )
            if r.status_code != 200:
                logger.warning(f"Velociraptor GetClientFlows {r.status_code}: {r.text[:200]}")
                return []
            data = r.json()
            cols = data.get("columns", [])
            flows = []
            for row in data.get("rows", []):
                vals = dict(zip(cols, json.loads(row.get("json", "[]"))))
                ctx = vals.get("_Flow") or {}
                ctx["session_id"] = ctx.get("session_id") or vals.get("FlowId")
                ctx["state"] = vals.get("State") or ctx.get("state")
                ctx["create_time"] = vals.get("Created") or ctx.get("create_time")
                ctx.setdefault("request", {})["artifacts"] = vals.get("Artifacts") or []
                ctx["total_collected_rows"] = vals.get("Rows", 0)
                # Multi-source artifacts store results under "Artifact/Source"
                # names — these are what GetTable accepts, not the request name.
                ctx["artifacts_with_results"] = (
                    vals.get("_ArtifactsWithResults") or ctx.get("artifacts_with_results") or []
                )
                flows.append(ctx)
            return flows

    async def get_flow_results(
        self, client_id: str, flow_id: str, artifact: str,
        start_row: int = 0, rows: int = 100,
    ) -> dict:
        async with self._new_client() as c:
            prep = await c.get("/app/index.html")
            csrf = prep.headers.get("x-csrf-token", "")
            hdr = {"X-CSRF-Token": csrf, "Referer": self.url + "/"}
            r = await c.get(
                "/api/v1/GetTable",
                params={
                    "client_id": client_id, "flow_id": flow_id, "artifact": artifact,
                    "type": "CLIENT", "start_row": start_row, "rows": rows,
                },
                headers=hdr,
            )
            r.raise_for_status()
            data = r.json()
            return {
                "columns": data.get("columns", []),
                "rows": [json.loads(row.get("json", "[]")) for row in data.get("rows", [])],
                "total_rows": int(data.get("total_rows", 0)),
            }


# ─────────────────────────────────────────────────────────────────────────────
# Connector registry — verify dispatch
# ─────────────────────────────────────────────────────────────────────────────

async def verify_connector(connector: Connector) -> tuple[bool, str]:
    from app.connectors.misp.client import MispClient
    client_map = {
        ConnectorType.WAZUH_INDEXER:  WazuhIndexerClient,
        ConnectorType.WAZUH_MANAGER:  WazuhManagerClient,
        ConnectorType.VELOCIRAPTOR:   VelociraptorClient,
        ConnectorType.MISP:           MispClient,
    }
    cls = client_map.get(connector.connector_type)
    if not cls:
        return False, f"No client registered for {connector.connector_type}"

    try:
        client = cls()
        return await client.test_connection()
    except Exception as e:
        return False, str(e)
