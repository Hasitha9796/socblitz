"""
SocBlitz threat intelligence service.

Tiered lookup: MISP (local, free) is checked first. Only when MISP has no hit
do we escalate to the rate-limited external reputation sources — VirusTotal
(all IOC types) and AbuseIPDB (IPs only), plus OTX if configured. This keeps
the VirusTotal free tier (500/day, 4/min) for the IOCs that actually need it.
"""
import asyncio
import httpx
from loguru import logger
from app.core.config import settings

# IOC types treated as IP addresses (AbuseIPDB-eligible).
_IP_TYPES = ("ip", "ip-src", "ip-dst")


class ThreatIntelService:
    timeout = httpx.Timeout(15.0)

    async def lookup(self, value: str, ioc_type: str = "ip") -> dict:
        """Tiered TI lookup.

        Tier 1 — MISP (local, no rate limit). If MISP already knows the IOC is
        bad, we stop there and don't spend external API quota.

        Tier 2 — external reputation. Runs only on a MISP miss: VirusTotal for
        every IOC type, AbuseIPDB for IPs, OTX when configured. These run in
        parallel with each other.
        """
        is_ip = ioc_type in _IP_TYPES
        skipped = []
        sources = {}

        # ---- Tier 1: MISP ----
        if settings.MISP_URL and settings.MISP_API_KEY:
            try:
                sources["misp"] = await self._misp_lookup(value)
            except Exception as e:
                sources["misp"] = {"error": str(e)}
                logger.warning(f"TI: MISP lookup failed for {value!r}: {e}")
        else:
            skipped.append("misp")

        misp_hit = bool(sources.get("misp", {}).get("hit"))

        # ---- Tier 2: external reputation (only when MISP can't confirm) ----
        escalated = not misp_hit
        if misp_hit:
            logger.info(f"TI: MISP hit for {value!r}; skipping external lookups to preserve quota")
            for name in ("virustotal", "otx"):
                skipped.append(f"{name} (skipped: MISP already flagged this IOC)")
            if is_ip:
                skipped.append("abuseipdb (skipped: MISP already flagged this IOC)")
        else:
            tasks = {}
            if settings.VIRUSTOTAL_API_KEY:
                tasks["virustotal"] = self._vt_lookup(value, ioc_type)
            else:
                skipped.append("virustotal")
            if is_ip:
                if settings.ABUSEIPDB_API_KEY:
                    tasks["abuseipdb"] = self._abuseipdb_lookup(value)
                else:
                    skipped.append("abuseipdb")
            if settings.OTX_API_KEY:
                tasks["otx"] = self._otx_lookup(value, ioc_type)
            else:
                skipped.append("otx")

            if tasks:
                results = await asyncio.gather(*tasks.values(), return_exceptions=True)
                for source, result in zip(tasks.keys(), results):
                    if isinstance(result, Exception):
                        sources[source] = {"error": str(result)}
                        logger.warning(f"TI: {source} lookup failed for {value!r}: {result}")
                    else:
                        sources[source] = result

        if not sources:
            return {"value": value, "type": ioc_type, "skipped": skipped, "note": "No TI sources configured"}

        return {
            "value": value,
            "type": ioc_type,
            "escalated": escalated,
            "sources": sources,
            "skipped": skipped,
            "verdict": self._compute_verdict(sources),
        }

    def _compute_verdict(self, sources: dict) -> dict:
        """Aggregate sources into a severity verdict.

        Severity tiers: malicious > suspicious > clean > unknown. Any single
        engine detection is enough to lift an IOC off "clean" into at least
        "suspicious" — a handful of AV vendors flagging something must never
        read as clean. A larger detection count promotes it to "malicious".
        """
        malicious = False
        suspicious = False
        has_reputation_data = False  # a source actually answered with intel on this IOC
        confidence = 0
        reasons = []

        vt = sources.get("virustotal", {})
        if vt.get("found"):
            has_reputation_data = True
            m = vt.get("malicious", 0)
            s = vt.get("suspicious", 0)
            if m >= 3:
                malicious = True
                confidence += min(60, 20 + m * 4)
                reasons.append(f"VirusTotal: {m} malicious" + (f", {s} suspicious" if s else ""))
            elif m >= 1 or s >= 2:
                suspicious = True
                confidence += min(35, 10 + m * 10 + s * 3)
                reasons.append(f"VirusTotal: {m} malicious, {s} suspicious")

        abuse = sources.get("abuseipdb", {})
        if "abuseConfidenceScore" in abuse:
            has_reputation_data = True
            score = abuse.get("abuseConfidenceScore", 0)
            reports = abuse.get("totalReports", 0)
            if score >= 50:
                malicious = True
                confidence += score // 2
                reasons.append(f"AbuseIPDB: {score}% confidence ({reports} reports)")
            elif score >= 20:
                suspicious = True
                confidence += score // 3
                reasons.append(f"AbuseIPDB: {score}% confidence ({reports} reports)")

        misp = sources.get("misp", {})
        if misp.get("hit", False):
            malicious = True
            has_reputation_data = True
            confidence += 30
            reasons.append(f"MISP: {misp.get('count', 0)} indicators")

        otx = sources.get("otx", {})
        if "pulses" in otx:
            has_reputation_data = True
            p = otx.get("pulses", 0)
            if p >= 3:
                malicious = True
                confidence += 20
                reasons.append(f"OTX: {p} pulses")
            elif p >= 1:
                suspicious = True
                confidence += 10
                reasons.append(f"OTX: {p} pulses")

        # A MISP miss alone is not evidence of cleanliness — it only means the
        # value isn't in the local MISP instance. Without a reputation source
        # answering, the honest verdict is "unknown".
        if malicious:
            status = "malicious"
        elif suspicious:
            status = "suspicious"
        elif has_reputation_data:
            status = "clean"
        else:
            status = "unknown"

        return {
            "status": status,
            "malicious": malicious,
            "suspicious": suspicious,
            "confidence": min(100, confidence),
            "reasons": reasons,
        }

    async def _vt_lookup(self, value: str, ioc_type: str) -> dict:
        path_map = {"ip": "ip_addresses", "ip-src": "ip_addresses", "ip-dst": "ip_addresses",
                    "domain": "domains", "url": "urls",
                    "hash": "files", "md5": "files", "sha1": "files", "sha256": "files"}
        endpoint = path_map.get(ioc_type, "files")

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
