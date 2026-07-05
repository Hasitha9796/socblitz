"""
SocBlitz SOAR workflow engine.
A workflow is a small directed graph (React Flow nodes/edges) with one trigger
node feeding a chain of action/logic nodes. execute_workflow() walks that graph
and runs each node for real — no queueing framework, no external SOAR engine.
"""
import asyncio
import smtplib
from email.mime.text import MIMEText

import httpx
from loguru import logger

from app.core.config import settings

# ─────────────────────────────────────────────────────────────────────────────
# Node catalog — drives the frontend palette + config forms
# ─────────────────────────────────────────────────────────────────────────────

NODE_CATALOG = [
    {
        "type": "trigger.manual", "category": "trigger", "label": "Manual trigger",
        "description": "Starts only when a user clicks Run now.",
        "config_schema": [],
    },
    {
        "type": "trigger.alert", "category": "trigger", "label": "Alert trigger",
        "description": "Starts automatically when a Wazuh alert matches the severity filter.",
        "config_schema": [
            {"key": "severity", "label": "Minimum severity", "type": "select",
             "options": ["low", "medium", "high", "critical"], "default": "critical"},
        ],
    },
    {
        "type": "logic.condition", "category": "logic", "label": "Condition",
        "description": "Branches to the 'true' or 'false' output based on a field in the trigger data.",
        "config_schema": [
            {"key": "field", "label": "Field (dot path, e.g. alert.severity)", "type": "text", "default": ""},
            {"key": "operator", "label": "Operator", "type": "select",
             "options": ["equals", "not_equals", "contains", "gte", "lte"], "default": "equals"},
            {"key": "value", "label": "Value", "type": "text", "default": ""},
        ],
    },
    {
        "type": "logic.delay", "category": "logic", "label": "Delay",
        "description": "Pauses the workflow for N seconds (capped at 60s).",
        "config_schema": [
            {"key": "seconds", "label": "Seconds", "type": "number", "default": 5},
        ],
    },
    {
        "type": "action.slack_notify", "category": "action", "label": "Slack notify",
        "description": "Posts a message to the configured Slack webhook.",
        "config_schema": [
            {"key": "message", "label": "Message (supports {{field}} templating)", "type": "text", "default": ""},
        ],
    },
    {
        "type": "action.send_email", "category": "action", "label": "Send email",
        "description": "Sends an email via the configured SMTP relay.",
        "config_schema": [
            {"key": "to", "label": "To", "type": "text", "default": ""},
            {"key": "subject", "label": "Subject", "type": "text", "default": ""},
            {"key": "body", "label": "Body (supports {{field}} templating)", "type": "text", "default": ""},
        ],
    },
    {
        "type": "action.http_request", "category": "action", "label": "HTTP request",
        "description": "Calls an arbitrary URL — the generic webhook/integration node.",
        "config_schema": [
            {"key": "method", "label": "Method", "type": "select",
             "options": ["GET", "POST", "PUT"], "default": "POST"},
            {"key": "url", "label": "URL", "type": "text", "default": ""},
            {"key": "body", "label": "JSON body (supports {{field}} templating)", "type": "text", "default": ""},
        ],
    },
    {
        "type": "action.create_case", "category": "action", "label": "Create case",
        "description": "Opens a SocBlitz case.",
        "config_schema": [
            {"key": "title", "label": "Title (supports {{field}} templating)", "type": "text", "default": ""},
            {"key": "priority", "label": "Priority", "type": "select",
             "options": ["low", "medium", "high", "critical"], "default": "medium"},
        ],
    },
    {
        "type": "action.wazuh_active_response", "category": "action", "label": "Wazuh active response",
        "description": "Runs a Wazuh Manager active-response command against an agent (e.g. block an IP).",
        "config_schema": [
            {"key": "command", "label": "Command", "type": "text", "default": "firewall-drop"},
            {"key": "agent_id_field", "label": "Agent ID field (dot path)", "type": "text", "default": "agent_id"},
        ],
    },
]

NODE_TYPES = {n["type"] for n in NODE_CATALOG}


# ─────────────────────────────────────────────────────────────────────────────
# Templating / field lookup helpers
# ─────────────────────────────────────────────────────────────────────────────

def _dig(data: dict, dot_path: str):
    cur = data
    for part in dot_path.split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
    return cur


def _render(template: str, context: dict) -> str:
    if not template:
        return template
    import re

    def _sub(m):
        val = _dig(context, m.group(1))
        return "" if val is None else str(val)

    return re.sub(r"\{\{\s*([\w.]+)\s*\}\}", _sub, template)


# ─────────────────────────────────────────────────────────────────────────────
# Per-node executors — each returns a small JSON-serialisable result dict
# ─────────────────────────────────────────────────────────────────────────────

async def _exec_trigger(node: dict, context: dict) -> dict:
    return {"ok": True, "detail": "trigger fired"}


async def _exec_condition(node: dict, context: dict) -> dict:
    cfg = node.get("data", {}).get("config", {})
    actual = _dig(context, cfg.get("field", ""))
    expected = cfg.get("value", "")
    op = cfg.get("operator", "equals")

    if op == "equals":
        result = str(actual) == str(expected)
    elif op == "not_equals":
        result = str(actual) != str(expected)
    elif op == "contains":
        result = expected in str(actual or "")
    elif op == "gte":
        result = _num(actual) >= _num(expected)
    elif op == "lte":
        result = _num(actual) <= _num(expected)
    else:
        result = False

    return {"ok": True, "branch": "true" if result else "false", "detail": f"{actual!r} {op} {expected!r} -> {result}"}


def _num(v) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


async def _exec_delay(node: dict, context: dict) -> dict:
    seconds = min(60, max(0, int(node.get("data", {}).get("config", {}).get("seconds", 5) or 0)))
    await asyncio.sleep(seconds)
    return {"ok": True, "detail": f"waited {seconds}s"}


async def _exec_slack_notify(node: dict, context: dict) -> dict:
    if not settings.SLACK_WEBHOOK_URL:
        return {"ok": False, "detail": "SLACK_WEBHOOK_URL not configured"}
    cfg = node.get("data", {}).get("config", {})
    text = _render(cfg.get("message", ""), context)
    async with httpx.AsyncClient(timeout=10.0) as c:
        r = await c.post(settings.SLACK_WEBHOOK_URL, json={"text": text})
        return {"ok": r.status_code < 300, "detail": f"HTTP {r.status_code}"}


async def _exec_send_email(node: dict, context: dict) -> dict:
    if not settings.SMTP_HOST:
        return {"ok": False, "detail": "SMTP_HOST not configured"}
    cfg = node.get("data", {}).get("config", {})
    to = _render(cfg.get("to", ""), context)
    subject = _render(cfg.get("subject", ""), context)
    body = _render(cfg.get("body", ""), context)

    def _send():
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = settings.SMTP_FROM
        msg["To"] = to
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=10) as s:
            s.starttls()
            if settings.SMTP_USER:
                s.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            s.sendmail(settings.SMTP_FROM, [to], msg.as_string())

    await asyncio.get_event_loop().run_in_executor(None, _send)
    return {"ok": True, "detail": f"email sent to {to}"}


async def _exec_http_request(node: dict, context: dict) -> dict:
    cfg = node.get("data", {}).get("config", {})
    url = _render(cfg.get("url", ""), context)
    if not url:
        return {"ok": False, "detail": "no URL configured"}
    method = cfg.get("method", "POST")
    body_str = _render(cfg.get("body", ""), context)
    body = None
    if body_str:
        import json
        try:
            body = json.loads(body_str)
        except ValueError:
            body = {"raw": body_str}

    async with httpx.AsyncClient(timeout=15.0) as c:
        r = await c.request(method, url, json=body)
        return {"ok": r.status_code < 400, "detail": f"HTTP {r.status_code}"}


async def _exec_create_case(node: dict, context: dict) -> dict:
    from app.db.init_db import AsyncSessionLocal
    from app.models import Case, CasePriority
    from sqlalchemy import select, func

    cfg = node.get("data", {}).get("config", {})
    title = _render(cfg.get("title", ""), context) or "Workflow-created case"
    priority = CasePriority(cfg.get("priority", "medium"))

    async with AsyncSessionLocal() as db:
        count_r = await db.execute(select(func.count()).select_from(Case))
        case = Case(title=title, priority=priority, case_number=(count_r.scalar() or 0) + 1)
        db.add(case)
        await db.commit()
        await db.refresh(case)
        return {"ok": True, "detail": f"created case {case.case_number}", "case_id": case.id}


async def _exec_wazuh_active_response(node: dict, context: dict) -> dict:
    from app.connectors.registry import WazuhManagerClient

    cfg = node.get("data", {}).get("config", {})
    command = cfg.get("command", "firewall-drop")
    agent_id = _dig(context, cfg.get("agent_id_field", "agent_id"))
    if not agent_id:
        return {"ok": False, "detail": "no agent_id resolved from trigger data"}

    client = WazuhManagerClient()
    result = await client.run_active_response(str(agent_id), command)
    return {"ok": True, "detail": f"active response '{command}' sent to agent {agent_id}", "result": result}


_EXECUTORS = {
    "trigger.manual": _exec_trigger,
    "trigger.alert": _exec_trigger,
    "logic.condition": _exec_condition,
    "logic.delay": _exec_delay,
    "action.slack_notify": _exec_slack_notify,
    "action.send_email": _exec_send_email,
    "action.http_request": _exec_http_request,
    "action.create_case": _exec_create_case,
    "action.wazuh_active_response": _exec_wazuh_active_response,
}


# ─────────────────────────────────────────────────────────────────────────────
# Graph walk
# ─────────────────────────────────────────────────────────────────────────────

def _find_start_node(nodes: list[dict]) -> dict | None:
    for n in nodes:
        if str(n.get("type", "")).startswith("trigger."):
            return n
    return nodes[0] if nodes else None


def _next_nodes(node_id: str, branch: str | None, nodes_by_id: dict, edges: list[dict]) -> list[dict]:
    out = []
    for e in edges:
        if e.get("source") != node_id:
            continue
        handle = e.get("sourceHandle")
        if branch is not None and handle is not None and handle != branch:
            continue
        target = nodes_by_id.get(e.get("target"))
        if target:
            out.append(target)
    return out


async def execute_workflow(nodes: list[dict], edges: list[dict], trigger_data: dict) -> list[dict]:
    """Walk the graph from the trigger node, executing each reachable node once.

    Returns an ordered list of {node_id, type, label, result} log entries.
    """
    if not nodes:
        return [{"node_id": None, "type": None, "label": None,
                  "result": {"ok": False, "detail": "workflow has no nodes"}}]

    nodes_by_id = {n["id"]: n for n in nodes}
    start = _find_start_node(nodes)
    if not start:
        return [{"node_id": None, "type": None, "label": None,
                  "result": {"ok": False, "detail": "workflow has no start node"}}]

    context = {**trigger_data}
    log = []
    visited = set()
    queue = [start]

    while queue:
        node = queue.pop(0)
        node_id = node["id"]
        if node_id in visited:
            continue
        visited.add(node_id)

        node_type = node.get("type", "")
        label = node.get("data", {}).get("label", node_type)
        executor = _EXECUTORS.get(node_type)

        if executor is None:
            result = {"ok": False, "detail": f"unknown node type '{node_type}'"}
            branch = None
        else:
            try:
                result = await executor(node, context)
            except Exception as e:
                logger.warning(f"Workflow node {node_id} ({node_type}) failed: {e}")
                result = {"ok": False, "detail": str(e)}
            branch = result.get("branch")

        log.append({"node_id": node_id, "type": node_type, "label": label, "result": result})

        if not result.get("ok", False) and node_type != "logic.condition":
            # Stop the chain on a hard failure, but a failed condition still branches.
            continue

        queue.extend(_next_nodes(node_id, branch, nodes_by_id, edges))

    return log
