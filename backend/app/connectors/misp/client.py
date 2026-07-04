"""MISP threat intelligence platform connector."""
from __future__ import annotations
from app.connectors.registry import BaseConnector
from app.core.config import settings


class MispClient(BaseConnector):
    def __init__(self):
        self.url     = settings.MISP_URL
        self.api_key = settings.MISP_API_KEY

    def _client(self, **kwargs):
        return super()._client(
            self.url,
            headers={
                "Authorization": self.api_key,
                "Accept":        "application/json",
                "Content-Type":  "application/json",
            },
        )

    async def test_connection(self) -> tuple[bool, str]:
        if not self.api_key:
            return False, "MISP_API_KEY not configured"
        try:
            async with self._client() as c:
                r = await c.get("/users/view/me.json")
                if r.status_code == 200:
                    email = r.json().get("User", {}).get("email", "")
                    return True, email or "Connected"
                return False, f"HTTP {r.status_code}"
        except Exception as e:
            return False, str(e)

    async def search_events(self, limit: int = 25) -> list[dict]:
        """Return recent MISP events."""
        async with self._client() as c:
            r = await c.post(
                "/events/restSearch",
                json={"limit": limit, "returnFormat": "json"},
            )
            if r.status_code != 200:
                return []
            resp = r.json()
            return resp.get("response", resp) if isinstance(resp, dict) else resp

    async def search_attributes(self, value: str, limit: int = 50) -> list[dict]:
        """Search MISP attributes (IOCs) by value."""
        async with self._client() as c:
            r = await c.post(
                "/attributes/restSearch",
                json={"value": value, "returnFormat": "json", "limit": limit},
            )
            if r.status_code != 200:
                return []
            return r.json().get("response", {}).get("Attribute", [])
