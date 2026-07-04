"""
SocBlitz threat intelligence service.
Parallel lookups across VirusTotal, AbuseIPDB, MISP, and OTX.
"""
import asyncio
import httpx
from loguru import logger
from app.core.config import settings


class ThreatIntelService:
    timeout = httpx.Timeout(15.0)

    async def lookup(self, value: str, ioc_type: str = "ip") -> dict:
        """Run all enabled TI sources in parallel and aggregate."""
        tasks = {}

        if settings.VIRUSTOTAL_API_KEY:
            tasks["virustotal"] = self._vt_lookup(value, ioc_type)
        if settings.ABUSEIPDB_API_KEY and ioc_type in ("ip", "ip-src", "ip-dst"):
            tasks["abuseipdb"] = self._abuseipdb_lookup(value)
        if settings.MISP_URL and settings.MISP_API_KEY:
            tasks["misp"] = self._misp_lookup(value)
        if settings.OTX_API_KEY:
            tasks["otx"] = self._otx_lookup(value, ioc_type)

        if not tasks:
            return {"value": value, "type": ioc_type, "note": "No TI API keys configured"}

        results = await asyncio.gather(*tasks.values(), return_exceptions=True)
        aggregated = {"value": value, "type": ioc_type, "sources": {}}

        for source, result in zip(tasks.keys(), results):
            if isinstance(result, Exception):
                aggregated["sources"][source] = {"error": str(result)}
            else:
                aggregated["sources"][source] = result

        # Compute overall verdict
        aggregated["verdict"] = self._compute_verdict(aggregated["sources"])
        return aggregated

    def _compute_verdict(self, sources: dict) -> dict:
        malicious = False
        confidence = 0
        reasons = []

        vt = sources.get("virustotal", {})
        if vt.get("malicious", 0) > 5:
            malicious = True
            confidence += 40
            reasons.append(f"VirusTotal: {vt['malicious']} detections")

        abuse = sources.get("abuseipdb", {})
        score = abuse.get("abuseConfidenceScore", 0)
        if score > 50:
            malicious = True
            confidence += score // 2
            reasons.append(f"AbuseIPDB: {score}% confidence")

        misp = sources.get("misp", {})
        if misp.get("hit", False):
            malicious = True
            confidence += 30
            reasons.append(f"MISP: {misp.get('count', 0)} indicators")

        return {
            "malicious": malicious,
            "confidence": min(100, confidence),
            "reasons": reasons,
        }

    async def _vt_lookup(self, value: str, ioc_type: str) -> dict:
        path_map = {"ip": "ip_addresses", "domain": "domains", "url": "urls", "hash": "files", "md5": "files", "sha256": "files"}
        endpoint = path_map.get(ioc_type, "ip_addresses")

        if endpoint == "urls":
            import base64
            value = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")

        async with httpx.AsyncClient(timeout=self.timeout) as c:
            r = await c.get(
                f"https://www.virustotal.com/api/v3/{endpoint}/{value}",
                headers={"x-apikey": settings.VIRUSTOTAL_API_KEY},
            )
            if r.status_code == 404:
                return {"found": False}
            r.raise_for_status()
            data = r.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            return {
                "found": True,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "reputation": data.get("reputation"),
                "tags": data.get("tags", []),
            }

    async def _abuseipdb_lookup(self, ip: str) -> dict:
        async with httpx.AsyncClient(timeout=self.timeout) as c:
            r = await c.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": settings.ABUSEIPDB_API_KEY, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            )
            r.raise_for_status()
            return r.json().get("data", {})

    async def _misp_lookup(self, value: str) -> dict:
        async with httpx.AsyncClient(timeout=self.timeout, verify=False) as c:
            r = await c.post(
                f"{settings.MISP_URL.rstrip('/')}/attributes/restSearch",
                headers={"Authorization": settings.MISP_API_KEY, "Accept": "application/json"},
                json={"returnFormat": "json", "value": value, "limit": 5},
            )
            r.raise_for_status()
            hits = r.json().get("response", {}).get("Attribute", [])
            return {"hit": len(hits) > 0, "count": len(hits), "indicators": hits[:3]}

    async def _otx_lookup(self, value: str, ioc_type: str) -> dict:
        type_map = {"ip": "IPv4", "domain": "domain", "hash": "FileHash-SHA256"}
        otx_type = type_map.get(ioc_type, "IPv4")

        async with httpx.AsyncClient(timeout=self.timeout) as c:
            r = await c.get(
                f"https://otx.alienvault.com/api/v1/indicators/{otx_type}/{value}/general",
                headers={"X-OTX-API-KEY": settings.OTX_API_KEY},
            )
            r.raise_for_status()
            data = r.json()
            pulses = data.get("pulse_info", {}).get("count", 0)
            return {"pulses": pulses, "found": pulses > 0, "validation": data.get("validation")}
