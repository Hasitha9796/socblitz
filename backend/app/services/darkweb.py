"""
SocBlitz dark web / leak monitoring service.

Provider-agnostic, exactly like threat_intel.py: each adapter runs only when
its API key is configured, otherwise the source is reported under `skipped`.
Adapters fan out in parallel and every result is normalised into a common
finding shape so the API, the scheduled scanner, and the UI never care which
provider produced a given exposure.

Supported entity types: domain (company domain), email (a mailbox), keyword
(brand / product / executive name mentions).

Providers:
  - Have I Been Pwned  — domain breach list (no key) + per-account search (key)
  - Intelligence X     — darkweb/leak selector search (key)
  - Dehashed           — leaked-credential search (email + key, basic auth)
  - LeakCheck          — leaked-credential search (Pro key; public email fallback)
"""
import asyncio
import hashlib
import httpx
from loguru import logger

from app.core.config import settings

# Entity types each provider can meaningfully answer.
_ENTITY_DOMAIN = "domain"
_ENTITY_EMAIL = "email"
_ENTITY_KEYWORD = "keyword"

_USER_AGENT = "SocBlitz-DarkWeb-Monitor"

# Data-class keywords that, when exposed, escalate a finding's severity.
_CRITICAL_DATA = ("password", "credential", "credit card", "bank", "ssn",
                   "social security", "passport", "financial")
_HIGH_DATA = ("hash", "security question", "auth token", "private key",
              "government issued", "phone")


def _fingerprint(*parts: str) -> str:
    """A stable dedup key for a finding across repeated scans."""
    return hashlib.sha1("|".join(p or "" for p in parts).encode()).hexdigest()[:32]


def _severity_for(exposed: list[str], source: str) -> str:
    """Heuristic severity from the classes of data exposed."""
    blob = " ".join(exposed).lower()
    if any(k in blob for k in _CRITICAL_DATA):
        return "critical" if ("password" in blob or "credential" in blob) else "high"
    if any(k in blob for k in _HIGH_DATA):
        return "high"
    if exposed:
        return "medium"
    return "low"


class DarkWebService:
    timeout = httpx.Timeout(25.0, connect=8.0)

    async def search(self, query: str, entity_type: str = "domain") -> dict:
        """Fan out to every configured provider that supports `entity_type`.

        Returns a dict with normalised `findings`, the `sources` actually
        queried, `skipped` sources (no key / unsupported), and a `summary`.
        """
        query = (query or "").strip()
        if not query:
            return {"query": query, "entity_type": entity_type, "findings": [],
                    "skipped": [], "summary": self._summarize([])}

        tasks: dict[str, "asyncio.Future"] = {}
        skipped: list[str] = []

        # ── Have I Been Pwned ──────────────────────────────────────────────
        if entity_type == _ENTITY_DOMAIN:
            # Domain breach list is a public endpoint — works without a key.
            tasks["hibp"] = self._hibp_domain(query)
        elif entity_type == _ENTITY_EMAIL:
            if settings.HIBP_API_KEY:
                tasks["hibp"] = self._hibp_account(query)
            else:
                skipped.append("hibp (no HIBP_API_KEY — account search needs a key)")
        else:
            skipped.append("hibp (does not support keyword search)")

        # ── Intelligence X ─────────────────────────────────────────────────
        if settings.INTELX_API_KEY:
            tasks["intelx"] = self._intelx_search(query)
        else:
            skipped.append("intelx (no INTELX_API_KEY)")

        # ── Dehashed ───────────────────────────────────────────────────────
        if settings.DEHASHED_EMAIL and settings.DEHASHED_API_KEY:
            tasks["dehashed"] = self._dehashed_search(query, entity_type)
        else:
            skipped.append("dehashed (no DEHASHED_EMAIL / DEHASHED_API_KEY)")

        # ── LeakCheck ──────────────────────────────────────────────────────
        if settings.LEAKCHECK_API_KEY:
            tasks["leakcheck"] = self._leakcheck_pro(query, entity_type)
        elif entity_type == _ENTITY_EMAIL:
            tasks["leakcheck"] = self._leakcheck_public(query)   # public email fallback
        else:
            skipped.append("leakcheck (no LEAKCHECK_API_KEY)")

        findings: list[dict] = []
        errors: dict[str, str] = {}
        if tasks:
            results = await asyncio.gather(*tasks.values(), return_exceptions=True)
            for source, result in zip(tasks.keys(), results):
                if isinstance(result, Exception):
                    errors[source] = str(result)
                    logger.warning(f"DarkWeb: {source} search failed for {query!r}: {result}")
                else:
                    findings.extend(result)

        # Stamp entity + fingerprint onto each finding.
        for f in findings:
            f.setdefault("entity_type", entity_type)
            f.setdefault("entity_value", query)
            f.setdefault("fingerprint", _fingerprint(f["source"], query, f.get("breach_name") or f["title"]))

        findings.sort(key=lambda f: _SEV_RANK.get(f.get("severity", "low"), 0), reverse=True)

        return {
            "query": query,
            "entity_type": entity_type,
            "sources": list(tasks.keys()),
            "skipped": skipped,
            "errors": errors,
            "findings": findings,
            "summary": self._summarize(findings),
        }

    def _summarize(self, findings: list[dict]) -> dict:
        by_severity: dict[str, int] = {}
        by_source: dict[str, int] = {}
        latest = None
        for f in findings:
            by_severity[f.get("severity", "low")] = by_severity.get(f.get("severity", "low"), 0) + 1
            by_source[f["source"]] = by_source.get(f["source"], 0) + 1
            ld = f.get("leak_date")
            if ld and (latest is None or ld > latest):
                latest = ld
        return {
            "total": len(findings),
            "by_severity": by_severity,
            "by_source": by_source,
            "latest_leak": latest,
        }

    # ── Have I Been Pwned ──────────────────────────────────────────────────

    async def _hibp_domain(self, domain: str) -> list[dict]:
        """Public breach list filtered to a domain (no API key required)."""
        async with httpx.AsyncClient(timeout=self.timeout) as c:
            r = await c.get(
                "https://haveibeenpwned.com/api/v3/breaches",
                params={"Domain": domain},
                headers={"User-Agent": _USER_AGENT},
            )
            r.raise_for_status()
            return [self._hibp_breach_finding(b, domain) for b in (r.json() or [])]

    async def _hibp_account(self, email: str) -> list[dict]:
        """Per-account breach search — requires an HIBP subscription key."""
        async with httpx.AsyncClient(timeout=self.timeout) as c:
            r = await c.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                params={"truncateResponse": "false"},
                headers={"User-Agent": _USER_AGENT, "hibp-api-key": settings.HIBP_API_KEY},
            )
            if r.status_code == 404:
                return []           # no breaches for this account
            r.raise_for_status()
            return [self._hibp_breach_finding(b, email) for b in (r.json() or [])]

    def _hibp_breach_finding(self, b: dict, entity: str) -> dict:
        data_classes = b.get("DataClasses", []) or []
        name = b.get("Name") or b.get("Title") or "Unknown breach"
        return {
            "source": "hibp",
            "title": f"{b.get('Title', name)} breach" + (f" ({b.get('BreachDate', '')[:4]})" if b.get("BreachDate") else ""),
            "description": _strip_html(b.get("Description", "")),
            "severity": _severity_for(data_classes, "hibp"),
            "breach_name": name,
            "exposed_data": data_classes,
            "leak_date": b.get("BreachDate"),
            "raw": {"pwn_count": b.get("PwnCount"), "is_verified": b.get("IsVerified"),
                    "is_sensitive": b.get("IsSensitive"), "domain": b.get("Domain")},
            "fingerprint": _fingerprint("hibp", entity, name),
        }

    # ── Intelligence X ─────────────────────────────────────────────────────

    async def _intelx_search(self, term: str) -> list[dict]:
        base = settings.INTELX_URL.rstrip("/")
        headers = {"x-key": settings.INTELX_API_KEY, "User-Agent": _USER_AGENT}
        async with httpx.AsyncClient(timeout=self.timeout) as c:
            start = await c.post(
                f"{base}/intelligent/search",
                headers=headers,
                json={"term": term, "maxresults": 50, "media": 0, "sort": 2, "terminate": []},
            )
            start.raise_for_status()
            search_id = start.json().get("id")
            if not search_id:
                return []

            # Results stream in; poll a few times (status 0 = has results, 1 = no
            # more results but keep going, 2/3 = done/empty).
            records: list[dict] = []
            for _ in range(4):
                res = await c.get(
                    f"{base}/intelligent/search/result",
                    headers=headers,
                    params={"id": search_id, "limit": 50},
                )
                res.raise_for_status()
                body = res.json()
                records.extend(body.get("records", []) or [])
                if body.get("status") in (1, 2):    # no more results / search done
                    break
                await asyncio.sleep(1.0)

            # Collapse to unique leak buckets/systems rather than one row each.
            buckets: dict[str, dict] = {}
            for rec in records:
                key = rec.get("bucket") or rec.get("name") or rec.get("systemid") or "intelx"
                b = buckets.setdefault(key, {"count": 0, "date": rec.get("date"), "name": rec.get("name")})
                b["count"] += 1
                if rec.get("date") and (not b["date"] or rec["date"] > b["date"]):
                    b["date"] = rec["date"]
            return [
                {
                    "source": "intelx",
                    "title": f"Exposure in {bucket}" + (f" ({info['count']} records)" if info["count"] > 1 else ""),
                    "description": f"Intelligence X surfaced {info['count']} record(s) matching '{term}' in bucket '{bucket}'.",
                    "severity": "high" if "leak" in bucket.lower() or "dump" in bucket.lower() else "medium",
                    "breach_name": bucket,
                    "exposed_data": [],
                    "leak_date": (info.get("date") or "")[:10] or None,
                    "raw": {"records": info["count"], "sample_name": info.get("name")},
                    "fingerprint": _fingerprint("intelx", term, bucket),
                }
                for bucket, info in buckets.items()
            ]

    # ── Dehashed ───────────────────────────────────────────────────────────

    async def _dehashed_search(self, query: str, entity_type: str) -> list[dict]:
        selector = {"domain": "domain", "email": "email"}.get(entity_type)
        q = f"{selector}:{query}" if selector else query
        async with httpx.AsyncClient(timeout=self.timeout) as c:
            r = await c.get(
                "https://api.dehashed.com/search",
                params={"query": q, "size": 200},
                auth=(settings.DEHASHED_EMAIL, settings.DEHASHED_API_KEY),
                headers={"Accept": "application/json", "User-Agent": _USER_AGENT},
            )
            r.raise_for_status()
            entries = r.json().get("entries") or []

        # Group leaked records by the database they came from.
        dbs: dict[str, dict] = {}
        for e in entries:
            db = e.get("database_name") or "unknown"
            g = dbs.setdefault(db, {"count": 0, "fields": set()})
            g["count"] += 1
            for field in ("password", "hashed_password", "email", "username", "name",
                          "phone", "address", "ip_address"):
                if e.get(field):
                    g["fields"].add(field)
        findings = []
        for db, g in dbs.items():
            exposed = sorted(_DEHASHED_LABELS.get(f, f) for f in g["fields"])
            findings.append({
                "source": "dehashed",
                "title": f"Leaked credentials in {db}" + (f" ({g['count']} records)" if g["count"] > 1 else ""),
                "description": f"Dehashed matched {g['count']} leaked record(s) for '{query}' in database '{db}'.",
                "severity": _severity_for(exposed, "dehashed"),
                "breach_name": db,
                "exposed_data": exposed,
                "leak_date": None,
                "raw": {"records": g["count"]},
                "fingerprint": _fingerprint("dehashed", query, db),
            })
        return findings

    # ── LeakCheck ──────────────────────────────────────────────────────────

    async def _leakcheck_pro(self, query: str, entity_type: str) -> list[dict]:
        lc_type = {"domain": "domain", "email": "email", "keyword": "keyword"}.get(entity_type, "auto")
        async with httpx.AsyncClient(timeout=self.timeout) as c:
            r = await c.get(
                f"https://leakcheck.io/api/v2/query/{query}",
                params={"type": lc_type, "limit": 200},
                headers={"X-API-Key": settings.LEAKCHECK_API_KEY, "Accept": "application/json",
                         "User-Agent": _USER_AGENT},
            )
            if r.status_code == 404:
                return []
            r.raise_for_status()
            body = r.json()
            if not body.get("success") or not body.get("found"):
                return []

            sources: dict[str, dict] = {}
            for row in body.get("result", []) or []:
                src = row.get("source", {}) or {}
                name = src.get("name") or "LeakCheck"
                g = sources.setdefault(name, {"count": 0, "date": src.get("breach_date"), "fields": set()})
                g["count"] += 1
                for field in (row.get("fields") or []):
                    g["fields"].add(field)
            return [
                {
                    "source": "leakcheck",
                    "title": f"Leaked in {name}" + (f" ({g['count']} records)" if g["count"] > 1 else ""),
                    "description": f"LeakCheck matched {g['count']} record(s) for '{query}' in '{name}'.",
                    "severity": _severity_for(sorted(g["fields"]), "leakcheck"),
                    "breach_name": name,
                    "exposed_data": sorted(g["fields"]),
                    "leak_date": g.get("date"),
                    "raw": {"records": g["count"]},
                    "fingerprint": _fingerprint("leakcheck", query, name),
                }
                for name, g in sources.items()
            ]

    async def _leakcheck_public(self, email: str) -> list[dict]:
        """Public, keyless LeakCheck endpoint — email only, source names only."""
        async with httpx.AsyncClient(timeout=self.timeout) as c:
            r = await c.get(
                "https://leakcheck.io/api/public",
                params={"check": email},
                headers={"Accept": "application/json", "User-Agent": _USER_AGENT},
            )
            r.raise_for_status()
            body = r.json()
            if not body.get("success") or not body.get("found"):
                return []
            findings = []
            for src in body.get("sources", []) or []:
                name = src.get("name") or "unknown"
                findings.append({
                    "source": "leakcheck",
                    "title": f"Leaked in {name}",
                    "description": f"LeakCheck's public index reports '{email}' present in '{name}'.",
                    "severity": "medium",
                    "breach_name": name,
                    "exposed_data": [],
                    "leak_date": src.get("date"),
                    "raw": {"public": True},
                    "fingerprint": _fingerprint("leakcheck", email, name),
                })
            return findings


_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

_DEHASHED_LABELS = {
    "password": "Passwords", "hashed_password": "Password hashes",
    "email": "Email addresses", "username": "Usernames", "name": "Names",
    "phone": "Phone numbers", "address": "Physical addresses", "ip_address": "IP addresses",
}


def _strip_html(text: str, limit: int = 400) -> str:
    import re
    clean = re.sub(r"<[^>]+>", "", text or "")
    clean = clean.replace("&quot;", '"').replace("&amp;", "&").strip()
    return clean[:limit] + ("…" if len(clean) > limit else "")
