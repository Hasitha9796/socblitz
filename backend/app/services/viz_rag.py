"""
SocBlitz visualization RAG.

A retrieval layer over the widget-generator catalog. Each catalog entry is a
rich text document describing one visualization (what it shows, when to use
it, synonyms an analyst might type). At query time the user's prompt is
embedded via the local Ollama embedding model and matched against the catalog
by cosine similarity; when no embedding model is reachable, a lexical
token-overlap scorer keeps retrieval working with zero dependencies.

The catalog spans the full Grafana core panel set — time series, bar chart,
pie/donut, table, stat, gauge, heatmap, and histogram — so any Grafana-style
visualization an analyst asks for has a concrete SocBlitz generator behind it.
"""
from __future__ import annotations

import math
import re

import httpx
from loguru import logger

from app.core.config import settings

# ─────────────────────────────────────────────────────────────────────────────
# Visualization knowledge base
# Every entry: generator key (must exist in dashboard_agent.GENERATORS),
# the Grafana-equivalent panel type, and a retrieval document.
# ─────────────────────────────────────────────────────────────────────────────

VIZ_CATALOG = [
    {
        "generator": "events_over_time",
        "viz": "time series",
        "title": "Event volume over time",
        "doc": "Time series line chart of total event volume per hour. Use to spot spikes, "
               "surges, bursts, trends, drops, activity history, traffic over time, timeline "
               "of events, when things happened, hourly event rate.",
    },
    {
        "generator": "auth_failures",
        "viz": "time series",
        "title": "Authentication failures over time",
        "doc": "Time series line chart of failed logins per hour. Use for brute force attacks, "
               "password guessing, credential stuffing, SSH login failures, failed authentication "
               "attempts, account attacks over time.",
    },
    {
        "generator": "flooding_rules",
        "viz": "bar chart",
        "title": "Most flooding events",
        "doc": "Horizontal bar chart of the noisiest rules by event count. Use for flooding, "
               "noisy rules, spam events, most frequent events, top rules by volume, what is "
               "generating the most events.",
    },
    {
        "generator": "top_severe_rules",
        "viz": "bar chart",
        "title": "Top high-severity rules",
        "doc": "Bar chart of rule descriptions among high and critical severity events, rule "
               "level 8 and above. Use for high level rules, severe rules, dangerous events, "
               "worst threats, critical rule descriptions, serious detections.",
    },
    {
        "generator": "top_source_ips",
        "viz": "bar chart",
        "title": "Top source IPs",
        "doc": "Bar chart of source IP addresses generating the most events. Use for attackers, "
               "top talkers, remote addresses, scanning hosts, suspicious IPs, srcip, where "
               "attacks come from.",
    },
    {
        "generator": "top_agents",
        "viz": "bar chart",
        "title": "Event volume by agent",
        "doc": "Bar chart of event count per monitored agent or endpoint. Use for busiest hosts, "
               "loudest endpoints, per-machine activity, which server or workstation generates "
               "the most events.",
    },
    {
        "generator": "top_users",
        "viz": "bar chart",
        "title": "Top user accounts",
        "doc": "Bar chart of user accounts appearing most in events. Use for account activity, "
               "usernames, who is logging in, user behaviour, most active accounts.",
    },
    {
        "generator": "mitre_tactics",
        "viz": "bar chart",
        "title": "Top MITRE ATT&CK tactics",
        "doc": "Bar chart of MITRE ATT&CK tactics observed in events. Use for attack stages, "
               "adversary tactics, kill chain phases, lateral movement, persistence, privilege "
               "escalation categories.",
    },
    {
        "generator": "mitre_techniques",
        "viz": "bar chart",
        "title": "Top MITRE ATT&CK techniques",
        "doc": "Bar chart of specific MITRE ATT&CK techniques observed in events. Use for "
               "attack techniques, T-numbers, specific adversary behaviours.",
    },
    {
        "generator": "top_rule_groups",
        "viz": "bar chart",
        "title": "Top event categories",
        "doc": "Bar chart of event volume by rule group or category, such as syslog, sshd, "
               "firewall, web. Use for kinds of events, event classes, log sources, categories.",
    },
    {
        "generator": "event_level_breakdown",
        "viz": "pie chart",
        "title": "Event severity breakdown",
        "doc": "Pie or donut chart splitting event volume into critical, high, medium and low "
               "severity bands. Use for severity distribution, how bad is it overall, share of "
               "critical events, proportion by level.",
    },
    {
        "generator": "alert_severity_breakdown",
        "viz": "pie chart",
        "title": "Triaged alert severity",
        "doc": "Pie chart of curated SocBlitz alerts by severity, from the triage queue rather "
               "than raw events. Use for alert workload, triage backlog composition, escalated "
               "alert mix.",
    },
    {
        "generator": "agent_status",
        "viz": "pie chart",
        "title": "Agent status",
        "doc": "Pie chart of monitored agents by connection status: active, disconnected, "
               "pending. Use for fleet health, offline agents, coverage, are my sensors up.",
    },
    {
        "generator": "noise_candidates",
        "viz": "table",
        "title": "Noise reduction candidates",
        "doc": "Table of high-volume low-severity rules that are safe to tune out or silence. "
               "Use for noise reduction, tuning recommendations, false positives, what can I "
               "safely suppress.",
    },
    {
        "generator": "quiet_risky",
        "viz": "table",
        "title": "Quiet but risky events",
        "doc": "Table of rare but high-severity rules that risk being missed under the flood. "
               "Use for hidden threats, buried signal, low and slow attacks, easy to miss "
               "detections, needle in the haystack.",
    },
    {
        "generator": "total_events",
        "viz": "stat",
        "title": "Total events",
        "doc": "Single big number stat panel with the total event count in the window. Use for "
               "how many events, overall volume, headline number, KPI.",
    },
    {
        "generator": "severity_gauge",
        "viz": "gauge",
        "title": "High-severity share",
        "doc": "Gauge showing the percentage of events that are high or critical severity, with "
               "green, amber and red thresholds. Use for threat level, risk meter, how much of "
               "my traffic is serious, severity ratio, health score.",
    },
    {
        "generator": "activity_heatmap",
        "viz": "heatmap",
        "title": "Activity heatmap",
        "doc": "Heatmap grid of event volume by day of week and hour of day. Use for activity "
               "patterns, when are we attacked, off-hours activity, weekend anomalies, hourly "
               "and daily rhythm, calendar heat map.",
    },
    {
        "generator": "level_histogram",
        "viz": "histogram",
        "title": "Rule level histogram",
        "doc": "Histogram of event counts across the numeric rule level scale 0 to 15. Use for "
               "level distribution, spread of severities, histogram of rule levels, how events "
               "distribute across levels.",
    },
    {
        "generator": "vuln_total",
        "viz": "stat",
        "title": "Open vulnerabilities",
        "doc": "Single stat with the total number of open vulnerability findings across all "
               "agents. Use for how many vulnerabilities, vulnerability count, patch backlog "
               "size, exposure headline number.",
    },
    {
        "generator": "vuln_severity",
        "viz": "pie chart",
        "title": "Vulnerabilities by severity",
        "doc": "Pie chart of vulnerability findings split by Critical, High, Medium and Low "
               "severity. Use for vulnerability severity distribution, how bad is my exposure, "
               "share of critical vulnerabilities.",
    },
    {
        "generator": "vuln_top_agents",
        "viz": "bar chart",
        "title": "Most vulnerable agents",
        "doc": "Bar chart of agents and hosts with the most open vulnerability findings. Use "
               "for most vulnerable machines, which hosts need patching first, weakest "
               "endpoints, patch priority by host.",
    },
    {
        "generator": "vuln_top_packages",
        "viz": "bar chart",
        "title": "Most vulnerable packages",
        "doc": "Bar chart of software packages with the most vulnerability findings. Use for "
               "vulnerable software, outdated packages, which library or application causes "
               "the most exposure.",
    },
    {
        "generator": "vuln_critical_cves",
        "viz": "table",
        "title": "Top critical & high CVEs",
        "doc": "Table of the worst Critical and High CVEs with CVSS score, affected package "
               "and number of affected agents. Use for top CVEs, worst vulnerabilities, what "
               "to patch first, CVSS ranking, remediation priorities.",
    },
    {
        "generator": "vuln_critical_gauge",
        "viz": "gauge",
        "title": "Critical + high share",
        "doc": "Gauge of the percentage of vulnerability findings at Critical or High severity. "
               "Use for vulnerability risk level, exposure meter, patching urgency score.",
    },
]

_CATALOG_BY_GENERATOR = {e["generator"]: e for e in VIZ_CATALOG}

# Embedding cache: {model: {generator: vector}}
_embed_cache: dict[str, dict[str, list[float]]] = {}


def _embed_endpoint() -> tuple[str, str, dict] | None:
    """Return (url, model, headers) for the embeddings API, or None."""
    model = settings.LOCAL_EMBED_MODEL
    if settings.LOCAL_LLM_URL and model:
        return f"{settings.LOCAL_LLM_URL.rstrip('/')}/embeddings", model, {}
    if settings.OPENAI_API_KEY:
        return ("https://api.openai.com/v1/embeddings", "text-embedding-3-small",
                {"Authorization": f"Bearer {settings.OPENAI_API_KEY}"})
    return None


async def _embed(texts: list[str]) -> list[list[float]] | None:
    ep = _embed_endpoint()
    if not ep:
        return None
    url, model, headers = ep
    try:
        async with httpx.AsyncClient(timeout=30.0) as c:
            r = await c.post(url, headers=headers, json={"model": model, "input": texts})
            r.raise_for_status()
            data = sorted(r.json()["data"], key=lambda d: d["index"])
            return [d["embedding"] for d in data]
    except Exception as e:
        logger.warning(f"viz RAG embedding failed ({model}): {e}")
        return None


def _cosine(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(x * x for x in b))
    return dot / (na * nb) if na and nb else 0.0


async def _catalog_vectors(model_key: str) -> dict[str, list[float]] | None:
    if model_key in _embed_cache:
        return _embed_cache[model_key]
    docs = [f"{e['title']}. {e['viz']}. {e['doc']}" for e in VIZ_CATALOG]
    vectors = await _embed(docs)
    if vectors is None:
        return None
    _embed_cache[model_key] = {e["generator"]: v for e, v in zip(VIZ_CATALOG, vectors)}
    return _embed_cache[model_key]


def _tokenize(text: str) -> set[str]:
    return {t for t in re.findall(r"[a-z0-9.&]+", text.lower()) if len(t) > 2}


def _lexical_scores(query: str) -> list[tuple[str, float]]:
    """Dependency-free fallback: weighted token overlap between query and docs."""
    q_tokens = _tokenize(query)
    # Down-weight tokens that appear across many catalog docs (poor discriminators).
    doc_tokens = {e["generator"]: _tokenize(f"{e['title']} {e['viz']} {e['doc']}") for e in VIZ_CATALOG}
    df = {t: sum(1 for toks in doc_tokens.values() if t in toks) for t in q_tokens}
    scores = []
    for gen, toks in doc_tokens.items():
        s = sum(1.0 / df[t] for t in q_tokens if t in toks and df.get(t))
        scores.append((gen, s))
    return scores


async def retrieve(query: str, k: int = 6) -> list[dict]:
    """Top-k catalog entries most relevant to the prompt, each with a score
    and 'method' of retrieval ('embedding' or 'lexical')."""
    method = "lexical"
    scores: list[tuple[str, float]] = []

    ep = _embed_endpoint()
    if ep:
        vectors = await _catalog_vectors(ep[1])
        q_vec = (await _embed([query]) or [None])[0] if vectors else None
        if vectors and q_vec:
            method = "embedding"
            scores = [(gen, _cosine(q_vec, vec)) for gen, vec in vectors.items()]

    if not scores:
        scores = _lexical_scores(query)

    scores.sort(key=lambda t: t[1], reverse=True)
    out = []
    for gen, score in scores[:k]:
        if score <= 0:
            continue
        entry = dict(_CATALOG_BY_GENERATOR[gen])
        entry["score"] = round(float(score), 4)
        entry["method"] = method
        out.append(entry)
    # Never return empty — with no signal at all, hand back a general overview.
    if not out:
        for gen in ("events_over_time", "event_level_breakdown", "top_agents"):
            entry = dict(_CATALOG_BY_GENERATOR[gen])
            entry["score"] = 0.0
            entry["method"] = method
            out.append(entry)
    return out
