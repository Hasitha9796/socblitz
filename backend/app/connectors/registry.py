"""
SocBlitz connector implementations.
Each connector wraps a specific tool's API.
"""
from __future__ import annotations
import asyncio
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

    async def get_recent_alerts(self, hours: int = 24, size: int = 100) -> dict:
        body = {
            "query": {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
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

    async def list_agents(self, limit: int = 500) -> list[dict]:
        async with await self._authed_client() as c:
            r = await c.get("/agents", params={"limit": limit, "select": "id,name,ip,os.platform,os.version,status,version,group,lastKeepAlive"})
            r.raise_for_status()
            return r.json().get("data", {}).get("affected_items", [])

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
            r = await c.get(
                f"/api/v1/GetClientFlows/{client_id}",
                params={"count": limit},
                headers=hdr,
            )
            if r.status_code != 200:
                return []
            return r.json().get("items", [])


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
