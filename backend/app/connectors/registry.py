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
# ClickHouse (analytics store — replaces the Wazuh Indexer / OpenSearch)
#
# The rest of the app (dashboard_agent generators, event views) was written
# against OpenSearch: it builds query-DSL bodies and reads `hits`/`aggregations`
# back. Rather than rewrite ~25 generators, this client keeps that exact
# contract — `search(index, body)` accepts the same DSL and returns the same
# response shape — but executes it against ClickHouse by translating the DSL
# subset the app actually uses into SQL. Vector loads the tables; see
# config/clickhouse/init.sql and config/vector/vector.toml.
# ─────────────────────────────────────────────────────────────────────────────

import re as _re


class _Table:
    """Column mapping + engine quirks for one ClickHouse table, so the DSL
    translator can turn dotted OpenSearch field names into real columns."""
    def __init__(self, name: str, fields: dict[str, str], arrays: set[str], final: bool):
        self.name = name
        self.fields = fields        # dotted OS field -> ClickHouse column
        self.arrays = arrays        # columns that are Array(String)
        self.final = final          # append FINAL (ReplacingMergeTree dedup)

    def col(self, dotted: str) -> str:
        if dotted not in self.fields:
            raise ValueError(f"field '{dotted}' not mapped for table {self.name}")
        return self.fields[dotted]

    @property
    def source(self) -> str:
        return f"wazuh.{self.name}" + (" FINAL" if self.final else "")


_ALERTS = _Table(
    "wazuh_alerts",
    {
        "@timestamp": "timestamp", "timestamp": "timestamp",
        "rule.id": "rule_id", "rule.level": "rule_level",
        "rule.description": "rule_description", "rule.groups": "rule_groups",
        "rule.mitre.tactic": "mitre_tactic", "rule.mitre.technique": "mitre_technique",
        "agent.id": "agent_id", "agent.name": "agent_name",
        "data.srcip": "data_srcip", "data.dstuser": "data_dstuser",
    },
    {"rule_groups", "mitre_tactic", "mitre_technique"},
    final=False,
)

_VULNS = _Table(
    "wazuh_vulnerabilities",
    {
        "@timestamp": "timestamp", "timestamp": "timestamp",
        "agent.id": "agent_id", "agent.name": "agent_name",
        "vulnerability.severity": "vuln_severity", "vulnerability.id": "vuln_id",
        "vulnerability.score.base": "vuln_score_base", "package.name": "package_name",
    },
    set(),
    final=True,
)


def _lit(v) -> str:
    """A safely-quoted SQL literal for a scalar value."""
    if isinstance(v, bool):
        return "1" if v else "0"
    if isinstance(v, (int, float)):
        return str(v)
    return "'" + str(v).replace("\\", "\\\\").replace("'", "\\'") + "'"


class ClickHouseClient(BaseConnector):
    verify_ssl = False

    def __init__(self):
        self.url = settings.CLICKHOUSE_URL.rstrip("/")
        self.user = settings.CLICKHOUSE_USER
        self.pwd = settings.CLICKHOUSE_PASSWORD

    def _http(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=self.url,
            headers={"X-ClickHouse-User": self.user, "X-ClickHouse-Key": self.pwd},
            timeout=self.timeout,
            verify=self.verify_ssl,
        )

    async def _rows(self, sql: str) -> list[dict]:
        """Run SQL and return the JSON `data` rows."""
        async with self._http() as c:
            r = await c.post("/", params={"database": "wazuh"},
                             content=(sql.rstrip().rstrip(";") + "\nFORMAT JSON"))
            r.raise_for_status()
            return r.json().get("data", [])

    async def test_connection(self) -> tuple[bool, str]:
        try:
            rows = await self._rows("SELECT count() AS n FROM wazuh.wazuh_alerts")
            return True, f"Connected — {rows[0]['n']} alerts indexed"
        except Exception as e:
            return False, str(e)

    # ── DSL → SQL translation ────────────────────────────────────────────────

    def _table_for(self, index: str) -> _Table:
        if index.startswith("wazuh-states-vulnerabilities"):
            return _VULNS
        return _ALERTS

    @staticmethod
    def _time_expr(val: str) -> str:
        """`now-24h` / `now` / an ISO-8601 string → a ClickHouse time expression."""
        if isinstance(val, str):
            m = _re.fullmatch(r"now-(\d+)([smhd])", val)
            if m:
                unit = {"s": "SECOND", "m": "MINUTE", "h": "HOUR", "d": "DAY"}[m.group(2)]
                return f"now() - INTERVAL {m.group(1)} {unit}"
            if val == "now":
                return "now()"
        return f"parseDateTime64BestEffort({_lit(val)})"

    def _clause(self, t: _Table, node: dict) -> str:
        """Translate one query-DSL node into a SQL boolean expression."""
        (op, spec), = node.items()
        if op == "bool":
            parts = [self._clause(t, sub) for sub in spec.get("must", [])]
            parts += [f"NOT ({self._clause(t, sub)})" for sub in spec.get("must_not", [])]
            should = [self._clause(t, sub) for sub in spec.get("should", [])]
            if should:
                parts.append("(" + " OR ".join(should) + ")")
            return "(" + " AND ".join(parts) + ")" if parts else "1"
        if op == "range":
            (field, bounds), = spec.items()
            col = t.col(field)
            ops = {"gte": ">=", "gt": ">", "lte": "<=", "lt": "<"}
            conds = []
            for bop, bval in bounds.items():
                if bop not in ops:
                    continue
                rhs = self._time_expr(bval) if col == "timestamp" else _lit(bval)
                conds.append(f"{col} {ops[bop]} {rhs}")
            return "(" + " AND ".join(conds) + ")" if conds else "1"
        if op in ("term", "match", "match_phrase"):
            (field, val), = spec.items()
            if isinstance(val, dict):          # {"field": {"value": v}} form
                val = val.get("value")
            col = t.col(field)
            return f"has({col}, {_lit(val)})" if col in t.arrays else f"{col} = {_lit(val)}"
        if op == "terms":
            (field, vals), = spec.items()
            col = t.col(field)
            arr = "[" + ", ".join(_lit(v) for v in vals) + "]"
            if col in t.arrays:
                return f"hasAny({col}, {arr})"
            return f"{col} IN (" + ", ".join(_lit(v) for v in vals) + ")"
        if op == "ids":
            vals = spec.get("values", [])
            return "alert_id IN (" + ", ".join(_lit(v) for v in vals) + ")"
        if op == "query_string":
            return self._lucene(t, spec.get("query", ""))
        if op == "match_all":
            return "1"
        raise ValueError(f"unsupported query clause: {op}")

    def _lucene(self, t: _Table, q: str) -> str:
        """Best-effort translation of the Lucene subset the UI exposes, e.g.
        `rule.level:>=10 AND agent.name:web-01`. Unmapped/free-text terms fall
        back to a substring match across the descriptive columns."""
        q = (q or "").strip()
        if not q:
            return "1"
        # Split on AND/OR keeping the operator; default operator is AND.
        tokens = _re.split(r"\s+(AND|OR)\s+", q)
        parts = [self._lucene_term(t, tokens[0])]
        i = 1
        while i < len(tokens) - 1:
            joiner = " OR " if tokens[i] == "OR" else " AND "
            parts.append(joiner)
            parts.append(self._lucene_term(t, tokens[i + 1]))
            i += 2
        return "(" + "".join(parts) + ")"

    def _lucene_term(self, t: _Table, term: str) -> str:
        term = term.strip()
        m = _re.fullmatch(r"([\w.@]+):(>=|<=|>|<)?(.+)", term)
        if m and m.group(1) in t.fields:
            col = t.col(m.group(1))
            cmp, val = m.group(2), m.group(3).strip().strip('"')
            if cmp:
                # numeric columns (e.g. rule.level) must compare against an
                # unquoted number, not a string literal
                rhs = val if _re.fullmatch(r"-?\d+(\.\d+)?", val) else _lit(val)
                return f"{col} {cmp} {rhs}"
            if "*" in val:
                return f"{col} ILIKE {_lit(val.replace('*', '%'))}"
            return f"has({col}, {_lit(val)})" if col in t.arrays else f"{col} = {_lit(val)}"
        # free text / unmapped field → substring over the human-readable columns
        text = term.split(":")[-1].strip('"*')
        cols = [c for c in ("rule_description", "agent_name", "data_srcip", "vuln_id")
                if c in t.fields.values()]
        return "(" + " OR ".join(f"{c} ILIKE {_lit('%' + text + '%')}" for c in cols) + ")"

    def _where(self, t: _Table, query: dict | None) -> str:
        return self._clause(t, query) if query else "1"

    # ── aggregations ─────────────────────────────────────────────────────────

    def _sub_agg_expr(self, t: _Table, spec: dict, alias: str) -> tuple[str, str]:
        """A per-bucket sub-aggregation → (SQL select expr, kind tag)."""
        (kind, body), = spec.items()
        if kind == "max":
            return f"max({t.col(body['field'])}) AS {alias}", "value"
        if kind == "min":
            return f"min({t.col(body['field'])}) AS {alias}", "value"
        if kind == "cardinality":
            return f"uniqExact({t.col(body['field'])}) AS {alias}", "value"
        if kind == "terms":                    # size-1 "pick a representative value"
            col = t.col(body["field"])
            expr = f"arrayElement(arrayJoin([{col}]),1)" if col in t.arrays else col
            return f"any({expr}) AS {alias}", "buckets"
        if kind == "filter":
            return f"countIf({self._clause(t, body)}) AS {alias}", "doc_count"
        raise ValueError(f"unsupported sub-agg: {kind}")

    async def _terms_agg(self, t: _Table, where: str, body: dict, subs: dict) -> dict:
        col = t.col(body["field"])
        group = f"arrayJoin({col})" if col in t.arrays else col
        size = int(body.get("size", 10))
        selects = [f"{group} AS k", "count() AS doc_count"]
        readers: list[tuple[str, str]] = []
        for name, sspec in (subs or {}).items():
            expr, kind = self._sub_agg_expr(t, sspec, f"sub_{name}")
            selects.append(expr)
            readers.append((name, kind))
        sql = (f"SELECT {', '.join(selects)} FROM {t.source} WHERE {where} "
               f"GROUP BY k HAVING doc_count > 0 ORDER BY doc_count DESC LIMIT {size}")
        rows = await self._rows(sql)
        buckets = []
        for row in rows:
            b = {"key": row["k"], "doc_count": int(row["doc_count"])}
            for name, kind in readers:
                v = row.get(f"sub_{name}")
                if kind == "value":
                    b[name] = {"value": v}
                elif kind == "doc_count":
                    b[name] = {"doc_count": int(v or 0)}
                else:  # buckets
                    b[name] = {"buckets": [{"key": v, "doc_count": 0}] if v not in (None, "") else []}
            buckets.append(b)
        return {"buckets": buckets}

    async def _histogram_agg(self, t: _Table, where: str, body: dict) -> dict:
        col = t.col(body["field"])
        interval = body.get("interval", 1)
        bucket = f"toInt64(floor({col} / {interval}) * {interval})"
        sql = (f"SELECT {bucket} AS k, count() AS doc_count FROM {t.source} "
               f"WHERE {where} GROUP BY k ORDER BY k")
        rows = await self._rows(sql)
        return {"buckets": [{"key": float(r["k"]), "doc_count": int(r["doc_count"])} for r in rows]}

    async def _date_histogram_agg(self, t: _Table, where: str, body: dict) -> dict:
        col = t.col(body.get("field", "@timestamp"))
        iv = body.get("fixed_interval") or body.get("calendar_interval") or "1h"
        m = _re.fullmatch(r"(\d+)([smhd])", iv)
        n, unit = (int(m.group(1)), {"s": "SECOND", "m": "MINUTE", "h": "HOUR", "d": "DAY"}[m.group(2)]) if m else (1, "HOUR")
        bucket = f"toStartOfInterval({col}, INTERVAL {n} {unit})"
        fill = ""
        if body.get("min_doc_count", 1) == 0:
            fill = f" WITH FILL STEP INTERVAL {n} {unit}"
        sql = (f"SELECT formatDateTime({bucket}, '%FT%T.000Z') AS kstr, "
               f"{bucket} AS kraw, count() AS doc_count FROM {t.source} "
               f"WHERE {where} GROUP BY kraw ORDER BY kraw{fill}")
        rows = await self._rows(sql)
        return {"buckets": [{"key_as_string": r["kstr"], "doc_count": int(r["doc_count"])} for r in rows]}

    async def _filter_agg(self, t: _Table, where: str, body: dict) -> dict:
        cond = self._clause(t, body)
        rows = await self._rows(
            f"SELECT countIf({cond}) AS n FROM {t.source} WHERE {where}")
        return {"doc_count": int(rows[0]["n"]) if rows else 0}

    async def _composite_agg(self, t: _Table, where: str, body: dict, subs: dict) -> dict:
        # Only the single-source `agent.id` composite is used (fleet vuln counts).
        source = body["sources"][0]
        (out_name, src_spec), = source.items()
        col = t.col(src_spec["terms"]["field"])
        selects = [f"{col} AS k", "count() AS doc_count"]
        readers = []
        for name, sspec in (subs or {}).items():
            expr, kind = self._sub_agg_expr(t, sspec, f"sub_{name}")
            selects.append(expr)
            readers.append((name, kind))
        rows = await self._rows(
            f"SELECT {', '.join(selects)} FROM {t.source} WHERE {where} GROUP BY k")
        buckets = []
        for row in rows:
            b = {"key": {out_name: row["k"]}, "doc_count": int(row["doc_count"])}
            for name, kind in readers:
                v = row.get(f"sub_{name}")
                b[name] = {"doc_count": int(v or 0)} if kind == "doc_count" else {"value": v}
            buckets.append(b)
        return {"buckets": buckets, "after_key": None}   # single page — caller stops

    async def _one_agg(self, t: _Table, where: str, spec: dict) -> dict:
        subs = spec.get("aggs") or spec.get("aggregations")
        if "terms" in spec:
            return await self._terms_agg(t, where, spec["terms"], subs)
        if "histogram" in spec:
            return await self._histogram_agg(t, where, spec["histogram"])
        if "date_histogram" in spec:
            return await self._date_histogram_agg(t, where, spec["date_histogram"])
        if "composite" in spec:
            return await self._composite_agg(t, where, spec["composite"], subs)
        if "filter" in spec:
            return await self._filter_agg(t, where, spec["filter"])
        raise ValueError(f"unsupported aggregation: {list(spec)}")

    async def _count(self, t: _Table, where: str) -> int:
        rows = await self._rows(f"SELECT count() AS n FROM {t.source} WHERE {where}")
        return int(rows[0]["n"]) if rows else 0

    def _order_by(self, t: _Table, sort: list | None) -> str:
        if not sort:
            return "timestamp DESC"
        clauses = []
        for item in sort:
            (field, opt), = item.items()
            order = (opt.get("order", "asc") if isinstance(opt, dict) else "asc").upper()
            try:
                clauses.append(f"{t.col(field)} {order}")
            except ValueError:
                continue
        return ", ".join(clauses) or "timestamp DESC"

    async def _docs(self, t: _Table, where: str, size: int, sort: list | None) -> list[dict]:
        sql = (f"SELECT alert_id, raw FROM {t.source} WHERE {where} "
               f"ORDER BY {self._order_by(t, sort)} LIMIT {size}")
        rows = await self._rows(sql)
        hits = []
        for r in rows:
            try:
                source = json.loads(r["raw"]) if r.get("raw") else {}
            except (json.JSONDecodeError, TypeError):
                source = {}
            hits.append({"_id": r.get("alert_id"), "_source": source})
        return hits

    async def search(self, index: str, body: dict) -> dict:
        """OpenSearch-compatible entry point. Accepts the same DSL bodies the
        dashboard generators build; returns `{aggregations, hits}`."""
        t = self._table_for(index)
        where = self._where(t, body.get("query"))
        result: dict = {}

        aggs = body.get("aggs") or body.get("aggregations")
        if aggs:
            result["aggregations"] = {name: await self._one_agg(t, where, spec)
                                      for name, spec in aggs.items()}

        size = body.get("size", 10)
        if body.get("track_total_hits") or (size and not aggs):
            result.setdefault("hits", {})["total"] = {"value": await self._count(t, where)}
        if size and not aggs:
            result.setdefault("hits", {})["hits"] = await self._docs(t, where, int(size), body.get("sort"))
        return result

    # ── high-level helpers (unchanged signatures) ─────────────────────────────

    async def get_agent_vulnerabilities(self, agent_id: str) -> dict:
        body = {
            "query": {"bool": {"must": [{"match": {"agent.id": agent_id}}]}},
            "size": 100,
            "sort": [{"vulnerability.severity": {"order": "desc"}}],
        }
        return await self.search("wazuh-states-vulnerabilities-*", body)

    async def get_vulnerability_counts_by_agent(self) -> dict[str, dict]:
        """Total + critical vulnerability counts for the whole fleet.
        Returns {agent_id: {"total": int, "critical": int}}."""
        counts: dict[str, dict] = {}
        body = {
            "size": 0,
            "aggs": {"by_agent": {
                "composite": {"size": 1000, "sources": [{"agent": {"terms": {"field": "agent.id"}}}]},
                "aggs": {"critical": {"filter": {
                    "terms": {"vulnerability.severity": ["Critical", "critical"]}
                }}},
            }},
        }
        result = await self.search("wazuh-states-vulnerabilities-*", body)
        for bucket in result.get("aggregations", {}).get("by_agent", {}).get("buckets", []):
            counts[str(bucket["key"]["agent"])] = {
                "total": bucket["doc_count"],
                "critical": bucket["critical"]["doc_count"],
            }
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
        if q and q.strip():
            must.append({"query_string": {"query": q}})

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
        return await self.search("wazuh-alerts-*", body)


# Backwards-compatible alias: the storage backend is ClickHouse now, but the
# connector type / call sites historically referenced the "Wazuh indexer".
WazuhIndexerClient = ClickHouseClient


# ─────────────────────────────────────────────────────────────────────────────
# SocBlitz Engine (custom detection engine — replaces the Wazuh manager)
# ─────────────────────────────────────────────────────────────────────────────

class EngineClient(BaseConnector):
    """Talks to the socblitz-engine management API. `list_agents` returns the
    same dict shape the agent-sync worker already expects from a Wazuh manager
    (id / name / ip / os{platform,version} / status / version / group), so the
    worker needed no changes beyond swapping the client."""

    def __init__(self):
        self.url = settings.ENGINE_URL.rstrip("/")
        self.key = settings.AGENT_ENROLL_KEY

    def _client(self, **kwargs):
        headers = {"X-Enroll-Key": self.key} if self.key else {}
        return super()._client(self.url, headers=headers)

    async def test_connection(self) -> tuple[bool, str]:
        try:
            async with self._client() as c:
                r = await c.get("/healthz")
                return r.status_code < 400, r.text[:200]
        except Exception as e:
            return False, str(e)

    async def list_agents(self) -> list[dict]:
        async with self._client() as c:
            r = await c.get("/agents")
            r.raise_for_status()
            data = r.json()
            return data if isinstance(data, list) else []

    # ── workbench (SocBlitz Engine UI: Extractor / Rule Generation / Test) ────

    async def _post(self, path: str, payload: dict) -> dict:
        async with self._client() as c:
            r = await c.post(path, json=payload)
            r.raise_for_status()
            return r.json()

    async def _get(self, path: str):
        async with self._client() as c:
            r = await c.get(path)
            r.raise_for_status()
            return r.json()

    async def test_log(self, message: str, program: str = "") -> dict:
        return await self._post("/test", {"message": message, "program": program})

    async def test_extractor(self, sample: str, yaml: str = "", pattern: str = "") -> dict:
        return await self._post("/extractor/test", {"yaml": yaml, "pattern": pattern, "sample": sample})

    async def test_rule(self, rule: dict, message: str, program: str = "") -> dict:
        return await self._post("/rules/test", {"rule": rule, "message": message, "program": program})

    async def list_rules(self) -> list[dict]:
        data = await self._get("/rules")
        return data if isinstance(data, list) else []

    # ── Chronicle-style: UDM normalization + YARA-L ───────────────────────────

    async def normalize(self, message: str, program: str = "") -> dict:
        return await self._post("/normalize", {"message": message, "program": program})

    async def test_parser(self, sample: str, yaml: str = "", program: str = "") -> dict:
        return await self._post("/parser/test", {"yaml": yaml, "sample": sample, "program": program})

    async def test_yaral(self, rule: str, messages: list[str], program: str = "") -> dict:
        return await self._post("/yaral/test", {"rule": rule, "messages": messages, "program": program})

    async def list_yaral(self) -> list[dict]:
        data = await self._get("/yaral/rules")
        return data if isinstance(data, list) else []

    # ── parser management (list / view / create / edit / delete) ──────────────

    async def list_parsers(self) -> list[dict]:
        data = await self._get("/parsers")
        return data if isinstance(data, list) else []

    async def get_parser(self, name: str) -> dict:
        return await self._get(f"/parsers/{name}")

    async def save_parser(self, yaml: str) -> dict:
        return await self._post("/parsers", {"yaml": yaml})

    async def delete_parser(self, name: str) -> dict:
        async with self._client() as c:
            r = await c.delete(f"/parsers/{name}")
            r.raise_for_status()
            return r.json()


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
        # WAZUH_INDEXER is ClickHouse now; WAZUH_MANAGER is the SocBlitz engine.
        ConnectorType.WAZUH_INDEXER:  ClickHouseClient,
        ConnectorType.WAZUH_MANAGER:  EngineClient,
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
