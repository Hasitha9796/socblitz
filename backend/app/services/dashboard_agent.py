"""
SocBlitz dashboard agent — heuristic (no external LLM required).

Analyzes live Wazuh events straight from the indexer to surface flooding
signal and quiet-but-risky signal, and assembles prompt-driven custom
dashboards from a small library of data generators. Each generator is a
self-contained (key -> widget) function; a keyword-based prompt parser
picks which ones to run. The registry/parser split is deliberately the
same shape an LLM function-calling loop would use, so swapping in real
model reasoning later only touches parse_prompt_to_generators().
"""
from __future__ import annotations
from loguru import logger

NOISE_LEVEL_THRESHOLD = 7   # flooding + below this level = safe-to-tune candidate
QUIET_MAX_COUNT = 3         # fires this few times or fewer in the window = "quiet"
QUIET_MIN_LEVEL = 8         # ...but still meaningful severity = "quiet but risky"

LEVEL_BANDS = [
    (12, "#f43f5e", "critical"),
    (8,  "#f97316", "high"),
    (4,  "#f59e0b", "medium"),
    (0,  "#67e8f9", "low"),
]
ACCENT = "#60a5fa"


def _level_band(level: int) -> tuple[str, str]:
    for min_level, color, label in LEVEL_BANDS:
        if level >= min_level:
            return color, label
    return "#64748b", "info"


async def _rule_terms_agg(hours: int, size: int = 50) -> list[dict]:
    """Aggregate wazuh-alerts-* by rule.id: count + description + level."""
    from app.connectors.registry import WazuhIndexerClient

    client = WazuhIndexerClient()
    body = {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
        "aggs": {
            "by_rule": {
                "terms": {"field": "rule.id", "size": size, "order": {"_count": "desc"}},
                "aggs": {
                    "description": {"terms": {"field": "rule.description", "size": 1}},
                    "level": {"max": {"field": "rule.level"}},
                },
            }
        },
    }
    result = await client.search("wazuh-alerts-*", body)
    buckets = result.get("aggregations", {}).get("by_rule", {}).get("buckets", [])
    out = []
    for b in buckets:
        desc_buckets = b.get("description", {}).get("buckets", [])
        out.append({
            "rule_id": b["key"],
            "count": b["doc_count"],
            "description": desc_buckets[0]["key"] if desc_buckets else str(b["key"]),
            "level": int(b.get("level", {}).get("value") or 0),
        })
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Generators — each returns a self-contained widget: {type, title, data, config}
# ─────────────────────────────────────────────────────────────────────────────

async def gen_flooding_rules(hours: int = 24, size: int = 10, **_) -> dict:
    """Top rules by volume — the noisiest signal generators right now."""
    rules = await _rule_terms_agg(hours, size=max(size, 50))
    rules.sort(key=lambda r: r["count"], reverse=True)
    top = rules[:size]
    return {
        "type": "bar",
        "title": f"Most flooding events ({hours}h)",
        "data": [{"name": r["description"][:44], "value": r["count"]} for r in top],
        "config": {"color": ACCENT, "valueLabel": "events"},
    }


async def gen_noise_candidates(hours: int = 24, **_) -> dict:
    """High volume + low severity — not risky, safe to silence/tune down."""
    rules = await _rule_terms_agg(hours, size=200)
    candidates = [r for r in rules if r["level"] < NOISE_LEVEL_THRESHOLD]
    candidates.sort(key=lambda r: r["count"], reverse=True)
    top = candidates[:10]
    return {
        "type": "table",
        "title": f"Noise candidates — not risky, high volume ({hours}h)",
        "columns": ["Rule", "Level", "Count", "Recommendation"],
        "data": [
            {"Rule": r["description"], "Level": r["level"], "Count": r["count"],
             "Recommendation": "Not risky — safe to silence or tune"}
            for r in top
        ],
        "config": {},
    }


async def gen_quiet_risky(hours: int = 24, **_) -> dict:
    """Low volume but meaningful severity — the signal that gets buried under the flood."""
    rules = await _rule_terms_agg(hours, size=200)
    candidates = [r for r in rules if r["level"] >= QUIET_MIN_LEVEL and r["count"] <= QUIET_MAX_COUNT]
    candidates.sort(key=lambda r: -r["level"])
    top = candidates[:10]
    return {
        "type": "table",
        "title": f"Quiet but risky — rare, high severity, easy to miss ({hours}h)",
        "columns": ["Rule", "Level", "Count", "Recommendation"],
        "data": [
            {"Rule": r["description"], "Level": r["level"], "Count": r["count"],
             "Recommendation": "Low volume — verify it isn't being missed"}
            for r in top
        ],
        "config": {},
    }


async def gen_event_level_breakdown(hours: int = 24, **_) -> dict:
    from app.connectors.registry import WazuhIndexerClient

    client = WazuhIndexerClient()
    body = {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
        "aggs": {"levels": {"histogram": {"field": "rule.level", "interval": 1, "min_doc_count": 1}}},
    }
    result = await client.search("wazuh-alerts-*", body)
    buckets = result.get("aggregations", {}).get("levels", {}).get("buckets", [])
    bands = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for b in buckets:
        _, label = _level_band(int(b["key"]))
        bands[label] = bands.get(label, 0) + b["doc_count"]
    colors = {"critical": "#f43f5e", "high": "#f97316", "medium": "#f59e0b", "low": "#67e8f9"}
    return {
        "type": "pie",
        "title": f"Event volume by severity band ({hours}h)",
        "data": [{"name": k.capitalize(), "value": v, "color": colors[k]} for k, v in bands.items() if v],
        "config": {},
    }


async def gen_top_source_ips(hours: int = 24, size: int = 10, **_) -> dict:
    from app.connectors.registry import WazuhIndexerClient

    client = WazuhIndexerClient()
    body = {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
        "aggs": {"ips": {"terms": {"field": "data.srcip", "size": size, "order": {"_count": "desc"}}}},
    }
    result = await client.search("wazuh-alerts-*", body)
    buckets = result.get("aggregations", {}).get("ips", {}).get("buckets", [])
    return {
        "type": "bar",
        "title": f"Top source IPs ({hours}h)",
        "data": [{"name": b["key"], "value": b["doc_count"]} for b in buckets],
        "config": {"color": "#f97316", "valueLabel": "events"},
    }


async def gen_mitre_tactics(hours: int = 24, size: int = 10, **_) -> dict:
    from app.connectors.registry import WazuhIndexerClient

    client = WazuhIndexerClient()
    body = {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
        "aggs": {"tactics": {"terms": {"field": "rule.mitre.tactic", "size": size, "order": {"_count": "desc"}}}},
    }
    result = await client.search("wazuh-alerts-*", body)
    buckets = result.get("aggregations", {}).get("tactics", {}).get("buckets", [])
    return {
        "type": "bar",
        "title": f"Top MITRE ATT&CK tactics ({hours}h)",
        "data": [{"name": b["key"], "value": b["doc_count"]} for b in buckets],
        "config": {"color": "#c084fc", "valueLabel": "events"},
    }


async def gen_top_agents(hours: int = 24, size: int = 10, **_) -> dict:
    from app.connectors.registry import WazuhIndexerClient

    client = WazuhIndexerClient()
    body = {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
        "aggs": {"agents": {"terms": {"field": "agent.name", "size": size, "order": {"_count": "desc"}}}},
    }
    result = await client.search("wazuh-alerts-*", body)
    buckets = result.get("aggregations", {}).get("agents", {}).get("buckets", [])
    return {
        "type": "bar",
        "title": f"Event volume by agent ({hours}h)",
        "data": [{"name": b["key"], "value": b["doc_count"]} for b in buckets],
        "config": {"color": "#4ade80", "valueLabel": "events"},
    }


async def gen_top_severe_rules(hours: int = 24, size: int = 10, **_) -> dict:
    """Top rule descriptions among HIGH/CRITICAL severity events (level >= 8)."""
    rules = await _rule_terms_agg(hours, size=200)
    severe = [r for r in rules if r["level"] >= 8]
    severe.sort(key=lambda r: r["count"], reverse=True)
    top = severe[:size]
    return {
        "type": "bar",
        "title": f"Top high-severity rules ({hours}h)",
        "data": [{"name": r["description"][:44], "value": r["count"]} for r in top],
        "config": {"color": "#f43f5e", "valueLabel": "events"},
    }


async def gen_events_over_time(hours: int = 24, **_) -> dict:
    """Event volume timeline — spot spikes and quiet periods at a glance."""
    from app.connectors.registry import WazuhIndexerClient

    interval = "1h" if hours <= 24 else "6h"
    client = WazuhIndexerClient()
    body = {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
        "aggs": {"timeline": {"date_histogram": {"field": "@timestamp", "fixed_interval": interval, "min_doc_count": 0}}},
    }
    result = await client.search("wazuh-alerts-*", body)
    buckets = result.get("aggregations", {}).get("timeline", {}).get("buckets", [])
    return {
        "type": "line",
        "title": f"Event volume over time ({hours}h)",
        "data": [{"name": b["key_as_string"][11:16] if hours <= 24 else b["key_as_string"][5:13].replace("T", " "),
                  "value": b["doc_count"]} for b in buckets],
        "config": {"color": ACCENT, "valueLabel": "events"},
    }


async def gen_mitre_techniques(hours: int = 24, size: int = 10, **_) -> dict:
    from app.connectors.registry import WazuhIndexerClient

    client = WazuhIndexerClient()
    body = {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
        "aggs": {"techniques": {"terms": {"field": "rule.mitre.technique", "size": size, "order": {"_count": "desc"}}}},
    }
    result = await client.search("wazuh-alerts-*", body)
    buckets = result.get("aggregations", {}).get("techniques", {}).get("buckets", [])
    return {
        "type": "bar",
        "title": f"Top MITRE ATT&CK techniques ({hours}h)",
        "data": [{"name": b["key"], "value": b["doc_count"]} for b in buckets],
        "config": {"color": "#a78bfa", "valueLabel": "events"},
    }


async def gen_top_users(hours: int = 24, size: int = 10, **_) -> dict:
    from app.connectors.registry import WazuhIndexerClient

    client = WazuhIndexerClient()
    body = {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
        "aggs": {"users": {"terms": {"field": "data.dstuser", "size": size, "order": {"_count": "desc"}}}},
    }
    result = await client.search("wazuh-alerts-*", body)
    buckets = result.get("aggregations", {}).get("users", {}).get("buckets", [])
    return {
        "type": "bar",
        "title": f"Top user accounts in events ({hours}h)",
        "data": [{"name": b["key"], "value": b["doc_count"]} for b in buckets],
        "config": {"color": "#4ade80", "valueLabel": "events"},
    }


async def gen_auth_failures(hours: int = 24, **_) -> dict:
    """Authentication failure timeline — brute-force / credential-stuffing signal."""
    from app.connectors.registry import WazuhIndexerClient

    interval = "1h" if hours <= 24 else "6h"
    client = WazuhIndexerClient()
    body = {
        "size": 0,
        "query": {"bool": {"must": [
            {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
            {"terms": {"rule.groups": ["authentication_failed", "authentication_failures"]}},
        ]}},
        "aggs": {"timeline": {"date_histogram": {"field": "@timestamp", "fixed_interval": interval, "min_doc_count": 0}}},
    }
    result = await client.search("wazuh-alerts-*", body)
    buckets = result.get("aggregations", {}).get("timeline", {}).get("buckets", [])
    return {
        "type": "line",
        "title": f"Authentication failures over time ({hours}h)",
        "data": [{"name": b["key_as_string"][11:16] if hours <= 24 else b["key_as_string"][5:13].replace("T", " "),
                  "value": b["doc_count"]} for b in buckets],
        "config": {"color": "#f43f5e", "valueLabel": "failures"},
    }


async def gen_top_rule_groups(hours: int = 24, size: int = 10, **_) -> dict:
    from app.connectors.registry import WazuhIndexerClient

    client = WazuhIndexerClient()
    body = {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
        "aggs": {"groups": {"terms": {"field": "rule.groups", "size": size, "order": {"_count": "desc"}}}},
    }
    result = await client.search("wazuh-alerts-*", body)
    buckets = result.get("aggregations", {}).get("groups", {}).get("buckets", [])
    return {
        "type": "bar",
        "title": f"Top event categories ({hours}h)",
        "data": [{"name": b["key"], "value": b["doc_count"]} for b in buckets],
        "config": {"color": "#67e8f9", "valueLabel": "events"},
    }


async def gen_total_events(hours: int = 24, **_) -> dict:
    from app.connectors.registry import WazuhIndexerClient

    client = WazuhIndexerClient()
    body = {"size": 0, "query": {"range": {"@timestamp": {"gte": f"now-{hours}h"}}}, "track_total_hits": True}
    result = await client.search("wazuh-alerts-*", body)
    total = result.get("hits", {}).get("total", {}).get("value", 0)
    return {"type": "stat", "title": f"Total events ({hours}h)", "data": total, "config": {}}


async def gen_severity_gauge(hours: int = 24, **_) -> dict:
    """Gauge: what share of all events are high/critical severity (level >= 8)."""
    from app.connectors.registry import WazuhIndexerClient

    client = WazuhIndexerClient()
    body = {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
        "aggs": {"severe": {"filter": {"range": {"rule.level": {"gte": 8}}}}},
        "track_total_hits": True,
    }
    result = await client.search("wazuh-alerts-*", body)
    total = result.get("hits", {}).get("total", {}).get("value", 0)
    severe = result.get("aggregations", {}).get("severe", {}).get("doc_count", 0)
    pct = round(100.0 * severe / total, 1) if total else 0.0
    return {
        "type": "gauge",
        "title": f"High-severity share ({hours}h)",
        "data": pct,
        "config": {"min": 0, "max": 100, "unit": "%",
                   "thresholds": [{"upto": 5, "color": "#22c55e"}, {"upto": 20, "color": "#f59e0b"}, {"upto": 100, "color": "#f43f5e"}],
                   "detail": f"{severe} of {total} events at level 8+"},
    }


_WEEKDAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]


async def gen_activity_heatmap(hours: int = 24, **_) -> dict:
    """Heatmap: event volume by day-of-week x hour-of-day."""
    from datetime import datetime
    from app.connectors.registry import WazuhIndexerClient

    window = max(hours, 168)  # a weekly rhythm needs at least a week of buckets
    client = WazuhIndexerClient()
    body = {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": f"now-{window}h"}}},
        "aggs": {"hourly": {"date_histogram": {"field": "@timestamp", "fixed_interval": "1h", "min_doc_count": 0}}},
    }
    result = await client.search("wazuh-alerts-*", body)
    buckets = result.get("aggregations", {}).get("hourly", {}).get("buckets", [])

    cells: dict[tuple[int, int], int] = {}
    for b in buckets:
        ts = datetime.fromisoformat(b["key_as_string"].replace("Z", "+00:00"))
        key = (ts.weekday(), ts.hour)
        cells[key] = cells.get(key, 0) + b["doc_count"]

    return {
        "type": "heatmap",
        "title": f"Activity heatmap — weekday × hour (last {window}h)",
        "data": [{"y": _WEEKDAYS[d], "x": h, "value": v} for (d, h), v in sorted(cells.items())],
        "config": {"xLabels": list(range(24)), "yLabels": _WEEKDAYS, "color": ACCENT},
    }


async def gen_level_histogram(hours: int = 24, **_) -> dict:
    """Histogram of event counts across the numeric rule-level scale."""
    from app.connectors.registry import WazuhIndexerClient

    client = WazuhIndexerClient()
    body = {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
        "aggs": {"levels": {"histogram": {"field": "rule.level", "interval": 1, "min_doc_count": 0}}},
    }
    result = await client.search("wazuh-alerts-*", body)
    buckets = result.get("aggregations", {}).get("levels", {}).get("buckets", [])
    return {
        "type": "histogram",
        "title": f"Rule level distribution ({hours}h)",
        "data": [{"name": str(int(b["key"])), "value": b["doc_count"]} for b in buckets],
        "config": {"color": "#fbbf24", "valueLabel": "events", "xLabel": "rule level"},
    }


# ─────────────────────────────────────────────────────────────────────────────
# Vulnerability generators — wazuh-states-vulnerabilities-* (current state
# snapshot, not time-bounded; the hours param is ignored)
# ─────────────────────────────────────────────────────────────────────────────

VULN_INDEX = "wazuh-states-vulnerabilities-*"
VULN_SEVERITY_COLORS = {"Critical": "#f43f5e", "High": "#f97316", "Medium": "#f59e0b", "Low": "#67e8f9", "Untriaged": "#64748b"}


async def _vuln_search(body: dict) -> dict:
    from app.connectors.registry import WazuhIndexerClient
    return await WazuhIndexerClient().search(VULN_INDEX, body)


async def gen_vuln_total(**_) -> dict:
    result = await _vuln_search({"size": 0, "track_total_hits": True})
    total = result.get("hits", {}).get("total", {}).get("value", 0)
    return {"type": "stat", "title": "Open vulnerabilities", "data": total, "config": {}}


async def gen_vuln_severity(**_) -> dict:
    body = {"size": 0, "aggs": {"sev": {"terms": {"field": "vulnerability.severity", "size": 10}}}}
    result = await _vuln_search(body)
    buckets = result.get("aggregations", {}).get("sev", {}).get("buckets", [])
    return {
        "type": "pie",
        "title": "Vulnerabilities by severity",
        "data": [{"name": b["key"], "value": b["doc_count"], "color": VULN_SEVERITY_COLORS.get(b["key"], "#94a3b8")}
                 for b in buckets],
        "config": {},
    }


async def gen_vuln_top_agents(size: int = 10, **_) -> dict:
    body = {"size": 0, "aggs": {"agents": {"terms": {"field": "agent.name", "size": size},
            "aggs": {"critical": {"filter": {"term": {"vulnerability.severity": "Critical"}}}}}}}
    result = await _vuln_search(body)
    buckets = result.get("aggregations", {}).get("agents", {}).get("buckets", [])
    return {
        "type": "bar",
        "title": "Most vulnerable agents",
        "data": [{"name": b["key"], "value": b["doc_count"]} for b in buckets],
        "config": {"color": "#f97316", "valueLabel": "vulnerabilities"},
    }


async def gen_vuln_top_packages(size: int = 10, **_) -> dict:
    body = {"size": 0, "aggs": {"pkgs": {"terms": {"field": "package.name", "size": size}}}}
    result = await _vuln_search(body)
    buckets = result.get("aggregations", {}).get("pkgs", {}).get("buckets", [])
    return {
        "type": "bar",
        "title": "Most vulnerable packages",
        "data": [{"name": b["key"], "value": b["doc_count"]} for b in buckets],
        "config": {"color": "#c084fc", "valueLabel": "findings"},
    }


async def gen_vuln_critical_cves(size: int = 10, **_) -> dict:
    body = {
        "size": 0,
        "query": {"terms": {"vulnerability.severity": ["Critical", "High"]}},
        "aggs": {"cves": {
            "terms": {"field": "vulnerability.id", "size": size},
            "aggs": {
                "score":    {"max": {"field": "vulnerability.score.base"}},
                "package":  {"terms": {"field": "package.name", "size": 1}},
                "agents":   {"cardinality": {"field": "agent.id"}},
                "severity": {"terms": {"field": "vulnerability.severity", "size": 1}},
            },
        }},
    }
    result = await _vuln_search(body)
    buckets = result.get("aggregations", {}).get("cves", {}).get("buckets", [])
    rows = []
    for b in buckets:
        pkg = b.get("package", {}).get("buckets", [])
        sev = b.get("severity", {}).get("buckets", [])
        score = b.get("score", {}).get("value")
        rows.append({
            "CVE": b["key"],
            "Severity": sev[0]["key"] if sev else "—",
            "CVSS": round(score, 1) if score is not None else "—",
            "Package": pkg[0]["key"] if pkg else "—",
            "Agents": b.get("agents", {}).get("value", 0),
        })
    rows.sort(key=lambda r: (r["CVSS"] if isinstance(r["CVSS"], float) else 0), reverse=True)
    return {
        "type": "table",
        "title": "Top critical & high CVEs",
        "columns": ["CVE", "Severity", "CVSS", "Package", "Agents"],
        "data": rows,
        "config": {},
    }


async def gen_vuln_critical_gauge(**_) -> dict:
    body = {
        "size": 0, "track_total_hits": True,
        "aggs": {"severe": {"filter": {"terms": {"vulnerability.severity": ["Critical", "High"]}}}},
    }
    result = await _vuln_search(body)
    total = result.get("hits", {}).get("total", {}).get("value", 0)
    severe = result.get("aggregations", {}).get("severe", {}).get("doc_count", 0)
    pct = round(100.0 * severe / total, 1) if total else 0.0
    return {
        "type": "gauge",
        "title": "Critical + high share",
        "data": pct,
        "config": {"min": 0, "max": 100, "unit": "%",
                   "thresholds": [{"upto": 10, "color": "#22c55e"}, {"upto": 30, "color": "#f59e0b"}, {"upto": 100, "color": "#f43f5e"}],
                   "detail": f"{severe} of {total} findings are Critical/High"},
    }


async def gen_alert_severity_breakdown(db=None, **_) -> dict:
    """Curated (triaged) alert severity — from the Postgres alerts table, not raw events."""
    from sqlalchemy import select, func
    from app.models import Alert, AlertSeverity

    colors = {"critical": "#f43f5e", "high": "#f97316", "medium": "#f59e0b", "low": "#67e8f9", "info": "#64748b"}
    data = []
    for sev in AlertSeverity:
        count = (await db.execute(
            select(func.count()).select_from(Alert).where(Alert.severity == sev)
        )).scalar_one()
        if count:
            data.append({"name": sev.value.capitalize(), "value": count, "color": colors[sev.value]})
    return {"type": "pie", "title": "Triaged alert severity", "data": data, "config": {}}


async def gen_agent_status(db=None, **_) -> dict:
    from sqlalchemy import select, func
    from app.models import Agent, AgentStatus

    colors = {"active": "#22c55e", "disconnected": "#f43f5e", "pending": "#f59e0b", "never_connected": "#64748b"}
    data = []
    for st in AgentStatus:
        count = (await db.execute(
            select(func.count()).select_from(Agent).where(Agent.status == st)
        )).scalar_one()
        if count:
            data.append({"name": st.value.replace("_", " ").capitalize(), "value": count, "color": colors[st.value]})
    return {"type": "pie", "title": "Agent status", "data": data, "config": {}}


GENERATORS = {
    "flooding_rules":           gen_flooding_rules,
    "top_severe_rules":         gen_top_severe_rules,
    "noise_candidates":         gen_noise_candidates,
    "quiet_risky":              gen_quiet_risky,
    "event_level_breakdown":    gen_event_level_breakdown,
    "top_source_ips":           gen_top_source_ips,
    "mitre_tactics":            gen_mitre_tactics,
    "mitre_techniques":         gen_mitre_techniques,
    "top_agents":               gen_top_agents,
    "events_over_time":         gen_events_over_time,
    "top_users":                gen_top_users,
    "auth_failures":            gen_auth_failures,
    "top_rule_groups":          gen_top_rule_groups,
    "total_events":             gen_total_events,
    "severity_gauge":           gen_severity_gauge,
    "activity_heatmap":         gen_activity_heatmap,
    "level_histogram":          gen_level_histogram,
    "alert_severity_breakdown": gen_alert_severity_breakdown,
    "agent_status":             gen_agent_status,
    "vuln_total":               gen_vuln_total,
    "vuln_severity":            gen_vuln_severity,
    "vuln_top_agents":          gen_vuln_top_agents,
    "vuln_top_packages":        gen_vuln_top_packages,
    "vuln_critical_cves":       gen_vuln_critical_cves,
    "vuln_critical_gauge":      gen_vuln_critical_gauge,
}

GENERATOR_LABELS = {
    "flooding_rules": "Most flooding events",
    "top_severe_rules": "Top high-severity rules",
    "noise_candidates": "Noise reduction candidates",
    "quiet_risky": "Quiet but risky events",
    "event_level_breakdown": "Event severity breakdown",
    "top_source_ips": "Top source IPs",
    "mitre_tactics": "Top MITRE tactics",
    "mitre_techniques": "Top MITRE techniques",
    "top_agents": "Event volume by agent",
    "events_over_time": "Event volume over time",
    "top_users": "Top user accounts",
    "auth_failures": "Authentication failures over time",
    "top_rule_groups": "Top event categories",
    "total_events": "Total events",
    "severity_gauge": "High-severity share",
    "activity_heatmap": "Activity heatmap",
    "level_histogram": "Rule level histogram",
    "alert_severity_breakdown": "Triaged alert severity",
    "agent_status": "Agent status",
    "vuln_total": "Open vulnerabilities",
    "vuln_severity": "Vulnerabilities by severity",
    "vuln_top_agents": "Most vulnerable agents",
    "vuln_top_packages": "Most vulnerable packages",
    "vuln_critical_cves": "Top critical & high CVEs",
    "vuln_critical_gauge": "Critical + high share",
}

INTENT_KEYWORDS = {
    "flooding_rules":           ["flood", "flooding", "noisy", "noise", "top rule", "most common", "spam"],
    "top_severe_rules":         ["high level", "high-level", "severe", "critical rule", "dangerous", "rule description", "rule.description", "worst rules", "top threats"],
    "noise_candidates":         ["silence", "suppress", "tune", "safe to ignore", "not risky", "false positive"],
    "quiet_risky":              ["quiet", "rare", "missed", "buried", "low volume", "hidden", "sneaky", "silent risk", "silent but"],
    "event_level_breakdown":    ["severity", "level breakdown", "by severity", "by level"],
    "top_source_ips":           ["source ip", "attacker", "top ip", "ip address", "srcip", "remote address"],
    "mitre_tactics":            ["tactic", "mitre", "att&ck"],
    "mitre_techniques":         ["technique"],
    "top_agents":               ["by agent", "per agent", "endpoint", "which host", "which agent", "by host", "per host", "top agent"],
    "events_over_time":         ["over time", "timeline", "trend", "spike", "history", "hourly", "time series", "when"],
    "top_users":                ["user", "account", "username", "who logged"],
    "auth_failures":            ["auth", "login", "logon", "brute", "failed password", "ssh fail", "credential", "password guess"],
    "top_rule_groups":          ["group", "category", "categories", "kind of event", "type of event", "types of event"],
    "total_events":             ["total", "how many events", "count of events", "event count"],
    "severity_gauge":           ["gauge", "threat level", "risk meter", "health score", "severity ratio", "share of"],
    "activity_heatmap":         ["heatmap", "heat map", "pattern", "off-hours", "weekend", "day of week", "hour of day"],
    "level_histogram":          ["histogram", "distribution", "spread of"],
    "alert_severity_breakdown": ["triaged", "alert severity", "escalated alerts"],
    "agent_status":             ["agent status", "online agents", "offline agents", "agent health"],
    "vuln_total":               ["how many vulnerabilities", "vulnerability count", "total vulnerabilities"],
    "vuln_severity":            ["vulnerability severity", "vulnerabilities by severity", "vuln breakdown"],
    "vuln_top_agents":          ["vulnerable agents", "vulnerable hosts", "vulnerable machines", "which agents are vulnerable"],
    "vuln_top_packages":        ["vulnerable packages", "vulnerable software", "outdated packages"],
    "vuln_critical_cves":       ["cve", "critical vulnerabilities", "top vulnerabilities", "worst cves", "cvss"],
    "vuln_critical_gauge":      ["vulnerability risk", "patch priority", "vuln ratio"],
}

# Generic fallback when nothing matches — a broad events overview, NOT the
# flooding view (that one has its own always-on insights panel).
DEFAULT_OVERVIEW = ["events_over_time", "event_level_breakdown", "top_agents", "top_rule_groups"]

_PIE_PALETTE = ["#60a5fa", "#f97316", "#22c55e", "#f43f5e", "#fbbf24", "#c084fc", "#67e8f9", "#94a3b8", "#4ade80", "#a78bfa"]


GENERATOR_DESCRIPTIONS = {
    "flooding_rules":           "Top rules by event volume — the noisiest signal generators (bar)",
    "top_severe_rules":         "Top rule descriptions among HIGH/CRITICAL severity events, level >= 8 (bar)",
    "noise_candidates":         "High-volume, low-severity rules that are safe to tune out (table)",
    "quiet_risky":              "Rare but high-severity rules that risk being missed (table)",
    "event_level_breakdown":    "Event volume split by severity band (pie)",
    "top_source_ips":           "Source IPs generating the most events (bar)",
    "mitre_tactics":            "Top MITRE ATT&CK tactics seen in events (bar)",
    "mitre_techniques":         "Top MITRE ATT&CK techniques seen in events (bar)",
    "top_agents":               "Event volume per agent/endpoint (bar)",
    "events_over_time":         "Event volume timeline to spot spikes (line)",
    "top_users":                "User accounts appearing most in events (bar)",
    "auth_failures":            "Authentication failure timeline — brute-force signal (line)",
    "top_rule_groups":          "Event volume by rule group/category (bar)",
    "total_events":             "Single total event count (stat)",
    "severity_gauge":           "Gauge of the percentage of events at high/critical severity (gauge)",
    "activity_heatmap":         "Event volume by day-of-week x hour-of-day (heatmap)",
    "level_histogram":          "Event counts across the numeric rule level scale (histogram)",
    "alert_severity_breakdown": "Triaged SocBlitz alert counts by severity (pie)",
    "agent_status":             "Agent online/offline status counts (pie)",
    "vuln_total":               "Total open vulnerability findings across all agents (stat)",
    "vuln_severity":            "Vulnerability findings split by severity (pie)",
    "vuln_top_agents":          "Agents with the most open vulnerabilities (bar)",
    "vuln_top_packages":        "Software packages with the most vulnerability findings (bar)",
    "vuln_critical_cves":       "Worst Critical/High CVEs with CVSS score, package and affected agents (table)",
    "vuln_critical_gauge":      "Percentage of findings at Critical/High severity (gauge)",
}


async def llm_parse_prompt(prompt: str, catalog_entries: list[dict] | None = None) -> dict | None:
    """Ask a configured LLM to pick generators + params for the prompt.

    Uses whichever is configured: OPENAI_API_KEY (api.openai.com) or
    LOCAL_LLM_URL (any OpenAI-compatible server, e.g. Ollama). When
    catalog_entries (RAG shortlist) is given, the model only chooses among
    those. Returns {"generators": [...], "size": int|None, "chart": str|None}
    or None if no LLM is configured / the call fails.
    """
    import json as _json
    import httpx

    from app.core.config import settings

    if settings.LOCAL_LLM_URL:
        base_url = settings.LOCAL_LLM_URL.rstrip("/")
        model = settings.LOCAL_LLM_MODEL or "llama3"
        headers = {}
    elif settings.OPENAI_API_KEY:
        base_url = "https://api.openai.com/v1"
        model = settings.OPENAI_MODEL
        headers = {"Authorization": f"Bearer {settings.OPENAI_API_KEY}"}
    else:
        return None

    if catalog_entries:
        catalog = "\n".join(
            f"- {e['generator']}: {e['title']} ({e['viz']}) — {e['doc'].split('. ')[0]}"
            for e in catalog_entries
        )
    else:
        catalog = "\n".join(f"- {k}: {v}" for k, v in GENERATOR_DESCRIPTIONS.items())
    system = (
        "You select dashboard widgets for a SOC analyst. Given the user's request, "
        "pick 1-4 generator keys from this catalog that best answer it:\n"
        f"{catalog}\n\n"
        "Respond with ONLY a JSON object, no prose. The generator keys MUST be "
        "copied exactly from the catalog above — never invent new keys:\n"
        '{"generators": ["key", ...], "size": <int top-N or null>, '
        '"chart": <"pie"|"bar"|"table"|"line"|null if the user asked for a specific chart shape>}'
    )

    try:
        async with httpx.AsyncClient(timeout=45.0) as c:
            r = await c.post(
                f"{base_url}/chat/completions",
                headers=headers,
                json={
                    "model": model,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": prompt},
                    ],
                    "temperature": 0,
                    "response_format": {"type": "json_object"},
                },
            )
            r.raise_for_status()
            content = r.json()["choices"][0]["message"]["content"].strip()
            # Small models sometimes wrap the JSON in prose/fences — dig it out.
            if not content.startswith("{"):
                import re
                m = re.search(r"\{.*\}", content, re.DOTALL)
                if not m:
                    return None
                content = m.group(0)
            parsed = _json.loads(content)
            generators = [g for g in parsed.get("generators", []) if g in GENERATORS]
            if not generators:
                return None
            return {
                "generators": generators,
                "size": parsed.get("size"),
                "chart": parsed.get("chart") if parsed.get("chart") in ("pie", "bar", "table", "line") else None,
            }
    except Exception as e:
        logger.warning(f"LLM prompt parsing failed, falling back to keywords: {e}")
        return None


def parse_prompt_to_generators(prompt: str) -> list[str]:
    p = (prompt or "").lower()
    matched = [key for key, kws in INTENT_KEYWORDS.items() if any(kw in p for kw in kws)]
    seen = set()
    matched = [k for k in matched if not (k in seen or seen.add(k))]
    return matched or list(DEFAULT_OVERVIEW)


def parse_prompt_params(prompt: str) -> dict:
    """Extract widget params from the prompt — currently 'top N' sizes."""
    import re
    params = {}
    m = re.search(r"\btop\s+(\d{1,3})\b", (prompt or "").lower())
    if m:
        params["size"] = max(3, min(25, int(m.group(1))))
    return params


def parse_chart_hint(prompt: str) -> str | None:
    """Did the user ask for a specific visualization shape?"""
    p = (prompt or "").lower()
    for hint in ("pie", "donut", "bar", "table", "line", "chart type"):
        if hint in p:
            return {"donut": "pie"}.get(hint, hint)
    return None


def apply_chart_hint(widget: dict, hint: str | None) -> dict:
    """Re-shape a widget to the requested chart type where the data allows it.
    bar <-> pie <-> table all share the name/value shape; line stays line."""
    if not hint or widget.get("type") == hint or widget.get("type") in ("stat", "line"):
        return widget

    data = widget.get("data") or []
    if widget["type"] == "table":
        return widget  # table columns are generator-specific; don't guess a chart from them

    if hint == "pie":
        widget["type"] = "pie"
        widget["data"] = [
            {**d, "color": d.get("color") or _PIE_PALETTE[i % len(_PIE_PALETTE)]}
            for i, d in enumerate(data)
        ]
    elif hint == "bar":
        widget["type"] = "bar"
        widget.setdefault("config", {}).setdefault("color", ACCENT)
    elif hint == "table":
        widget["type"] = "table"
        widget["columns"] = ["Name", "Count"]
        widget["data"] = [{"Name": d.get("name"), "Count": d.get("value")} for d in data]
    return widget


async def run_generator(key: str, db=None, hours: int = 24, params: dict | None = None) -> dict:
    fn = GENERATORS.get(key)
    if not fn:
        raise ValueError(f"Unknown generator: {key}")
    return await fn(hours=hours, db=db, **(params or {}))


async def analyze_vulnerabilities(db=None, hours: int = 24) -> dict:
    """Built-in vulnerability dashboard over wazuh-states-vulnerabilities-*."""
    import asyncio as _asyncio
    generators = [
        gen_vuln_total(), gen_vuln_critical_gauge(), gen_vuln_severity(),
        gen_vuln_top_agents(), gen_vuln_top_packages(), gen_vuln_critical_cves(),
    ]
    results = await _asyncio.gather(*generators, return_exceptions=True)
    widgets = []
    for r in results:
        if isinstance(r, Exception):
            logger.warning(f"vulnerability widget failed: {r}")
            continue
        widgets.append(r)
    return {"widgets": widgets, "hours": hours}


async def analyze_flooding_and_noise(db, hours: int = 24) -> dict:
    """The core ask: what's flooding, and what quiet-but-risky signal is it burying."""
    widgets = [
        await gen_flooding_rules(hours=hours, size=10),
        await gen_noise_candidates(hours=hours),
        await gen_quiet_risky(hours=hours),
    ]
    return {"widgets": widgets, "hours": hours}


async def build_dashboard(prompt: str, db, hours: int = 24) -> dict:
    # Tiered agentic flow:
    #   1. RAG retrieval shortlists the most relevant visualizations
    #   2. the LLM picks among the shortlist (mode "rag+llm")
    #   3. no LLM → the retrieval ranking itself decides (mode "rag")
    #   4. retrieval empty/broken → keyword heuristic (mode "keywords")
    from app.services.viz_rag import retrieve

    retrieved = []
    try:
        retrieved = await retrieve(prompt, k=6)
    except Exception as e:
        logger.warning(f"viz RAG retrieval failed: {e}")

    mode = "keywords"
    llm = await llm_parse_prompt(prompt, catalog_entries=retrieved or None)
    if llm:
        mode = "rag+llm" if retrieved else "llm"
        keys = llm["generators"]
        params = {}
        if llm.get("size"):
            params["size"] = max(3, min(25, int(llm["size"])))
        hint = llm.get("chart")
    elif retrieved and retrieved[0]["score"] > 0:
        # Retrieval-only: keep the top hit plus close runners-up (within 85%).
        mode = "rag"
        top = retrieved[0]["score"]
        keys = [e["generator"] for e in retrieved if e["score"] >= 0.85 * top][:3]
        params = parse_prompt_params(prompt)
        hint = parse_chart_hint(prompt)
    else:
        keys = parse_prompt_to_generators(prompt)
        params = parse_prompt_params(prompt)
        hint = parse_chart_hint(prompt)
    if hint:
        params["chart"] = hint

    widgets = []
    for key in keys:
        try:
            w = await run_generator(key, db=db, hours=hours, params={k: v for k, v in params.items() if k != "chart"})
        except Exception as e:
            logger.warning(f"dashboard generator {key} failed: {e}")
            continue
        w = apply_chart_hint(w, hint)
        w["id"] = key
        w["generator"] = key
        w["params"] = params
        widgets.append(w)

    if widgets:
        summary = f"Built {len(widgets)} widget(s) from your prompt: " + ", ".join(w["title"] for w in widgets)
    else:
        summary = "Couldn't build any widgets yet — there may not be enough event data in this window."
    return {
        "prompt": prompt, "matched": keys, "mode": mode, "widgets": widgets, "summary": summary,
        "retrieved": [{"generator": e["generator"], "viz": e["viz"], "score": e["score"], "method": e["method"]} for e in retrieved],
    }


async def resolve_widgets(recipes: list[dict], db, hours: int = 24) -> list[dict]:
    """Re-run stored generator recipes so a saved dashboard always shows fresh data."""
    resolved = []
    for r in recipes:
        key = r.get("generator")
        params = r.get("params") or {}
        try:
            w = await run_generator(
                key, db=db, hours=params.get("hours", hours),
                params={k: v for k, v in params.items() if k != "chart"},
            )
        except Exception as e:
            logger.warning(f"resolve widget {key} failed: {e}")
            continue
        w = apply_chart_hint(w, params.get("chart"))
        w["id"] = r.get("id") or key
        w["generator"] = key
        w["params"] = params
        if r.get("title"):
            w["title"] = r["title"]
        resolved.append(w)
    return resolved
