"""
SocBlitz background tasks (Celery workers).
All database access uses synchronous SQLAlchemy (Celery workers are synchronous).
"""
import asyncio
from datetime import datetime, timezone
from loguru import logger
from celery import shared_task
from app.workers.celery_app import celery_app


def _run_async(coro):
    """Run an async coroutine from a sync Celery task."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            raise RuntimeError
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)


# ─────────────────────────────────────────────────────────────────────────────
# Agent sync
# ─────────────────────────────────────────────────────────────────────────────

@celery_app.task(name="app.workers.tasks.sync_wazuh_agents", bind=True, max_retries=3)
def sync_wazuh_agents(self):
    """Pull all agents from Wazuh Manager and upsert into SocBlitz DB."""
    logger.info("Task: sync_wazuh_agents started")
    try:
        _run_async(_do_sync_agents())
        logger.info("Task: sync_wazuh_agents complete")
    except Exception as exc:
        logger.error(f"sync_wazuh_agents failed: {exc}")
        raise self.retry(exc=exc, countdown=60)


async def _do_sync_agents():
    from app.db.init_db import AsyncSessionLocal
    from app.connectors.registry import WazuhManagerClient
    from app.models import Agent, AgentOS, AgentStatus
    from sqlalchemy import select

    client = WazuhManagerClient()
    agents_raw = await client.list_agents()

    async with AsyncSessionLocal() as db:
        for raw in agents_raw:
            agent_id = str(raw.get("id", ""))
            if not agent_id:
                continue

            # OS detection
            os_info = raw.get("os", {})
            os_name = os_info.get("platform", "").lower() if isinstance(os_info, dict) else ""
            if "windows" in os_name:
                agent_os = AgentOS.WINDOWS
            elif "linux" in os_name:
                agent_os = AgentOS.LINUX
            elif "darwin" in os_name or "mac" in os_name:
                agent_os = AgentOS.MACOS
            else:
                agent_os = AgentOS.UNKNOWN

            # Status mapping
            status_map = {
                "active":       AgentStatus.ACTIVE,
                "disconnected": AgentStatus.DISCONNECTED,
                "pending":      AgentStatus.PENDING,
                "never_connected": AgentStatus.NEVER_CONN,
            }
            raw_status = raw.get("status", "").lower()
            agent_status = status_map.get(raw_status, AgentStatus.DISCONNECTED)

            # Upsert
            result = await db.execute(select(Agent).where(Agent.agent_id == agent_id))
            agent = result.scalar_one_or_none()
            if agent is None:
                agent = Agent(agent_id=agent_id)
                db.add(agent)

            agent.name       = raw.get("name")
            agent.ip         = raw.get("ip")
            agent.os         = agent_os
            agent.os_version = os_info.get("version") if isinstance(os_info, dict) else None
            agent.status     = agent_status
            agent.version    = raw.get("version")
            agent.group      = raw.get("group") if isinstance(raw.get("group"), str) else None
            agent.last_seen  = datetime.now(timezone.utc)
            agent.raw_data   = raw
            agent.synced_at  = datetime.now(timezone.utc)

        await db.commit()


# ─────────────────────────────────────────────────────────────────────────────
# Alert collection
# ─────────────────────────────────────────────────────────────────────────────

@celery_app.task(name="app.workers.tasks.collect_graylog_alerts", bind=True, max_retries=3)
def collect_graylog_alerts(self):
    logger.info("Task: collect_graylog_alerts")
    try:
        _run_async(_do_collect_alerts())
    except Exception as exc:
        logger.error(f"collect_graylog_alerts failed: {exc}")
        raise self.retry(exc=exc, countdown=30)


async def _do_collect_alerts():
    from app.core.config import settings
    if not settings.GRAYLOG_API_KEY:
        logger.debug("GRAYLOG_API_KEY not set — skipping collect_graylog_alerts")
        return
    from app.connectors.registry import GraylogClient
    from app.db.init_db import AsyncSessionLocal
    from app.models import Alert, AlertSeverity
    from sqlalchemy import select

    client = GraylogClient()
    # Example: collect unacknowledged alerts from last 2 minutes
    results = await client.search("NOT _exists_:socblitz_ingested", timerange_minutes=2)
    messages = []
    for query_result in results.get("results", {}).values():
        for st in query_result.get("search_types", {}).values():
            messages.extend(st.get("messages", []))

    if not messages:
        return

    async with AsyncSessionLocal() as db:
        for msg in messages:
            m = msg.get("message", {})
            source_id = m.get("_id") or m.get("id")
            if not source_id:
                continue

            # Deduplicate
            existing = await db.execute(select(Alert).where(Alert.source_id == source_id))
            if existing.scalar_one_or_none():
                continue

            alert = Alert(
                source="graylog",
                source_id=source_id,
                description=m.get("message") or m.get("short_message"),
                severity=AlertSeverity.MEDIUM,
                agent_name=m.get("source"),
                raw_data=m,
            )
            db.add(alert)

        await db.commit()


# ─────────────────────────────────────────────────────────────────────────────
# Alert enrichment
# ─────────────────────────────────────────────────────────────────────────────

@celery_app.task(name="app.workers.tasks.enrich_alert", bind=True, max_retries=2)
def enrich_alert(self, alert_id: str):
    logger.info(f"Task: enrich_alert {alert_id}")
    try:
        _run_async(_do_enrich_alert(alert_id))
    except Exception as exc:
        logger.warning(f"enrich_alert {alert_id} failed: {exc}")
        raise self.retry(exc=exc, countdown=15)


async def _do_enrich_alert(alert_id: str):
    from app.db.init_db import AsyncSessionLocal
    from app.models import Alert
    from app.services.threat_intel import ThreatIntelService
    from sqlalchemy import select
    import re

    svc = ThreatIntelService()
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Alert).where(Alert.id == alert_id))
        alert = result.scalar_one_or_none()
        if not alert:
            return

        enrichment = {}
        iocs = {}

        # Extract IPs from raw data
        raw_str = str(alert.raw_data or "")
        ips = list(set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', raw_str)))
        # Filter out private IPs
        public_ips = [ip for ip in ips if not any(ip.startswith(p) for p in ("10.", "192.168.", "172.", "127."))]

        if public_ips:
            iocs["ips"] = public_ips
            # Enrich first public IP
            try:
                result_ti = await svc.lookup(value=public_ips[0], ioc_type="ip")
                enrichment["threat_intel"] = result_ti
            except Exception as e:
                enrichment["threat_intel_error"] = str(e)

        alert.iocs = iocs
        alert.enrichment = enrichment
        await db.commit()


@celery_app.task(name="app.workers.tasks.enrich_pending_alerts")
def enrich_pending_alerts():
    """Enrich any NEW alerts that haven't been enriched yet."""
    _run_async(_do_enrich_pending())


async def _do_enrich_pending():
    from app.db.init_db import AsyncSessionLocal
    from app.models import Alert, AlertStatus
    from sqlalchemy import select

    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(Alert.id).where(Alert.status == AlertStatus.NEW, Alert.enrichment == None).limit(20)
        )
        ids = [row[0] for row in result.fetchall()]

    for alert_id in ids:
        enrich_alert.delay(alert_id)


@celery_app.task(name="app.workers.tasks.enrich_observable", bind=True, max_retries=2)
def enrich_observable(self, observable_id: str):
    logger.info(f"Task: enrich_observable {observable_id}")
    try:
        _run_async(_do_enrich_observable(observable_id))
    except Exception as exc:
        raise self.retry(exc=exc, countdown=10)


async def _do_enrich_observable(observable_id: str):
    from app.db.init_db import AsyncSessionLocal
    from app.models import Observable
    from app.services.threat_intel import ThreatIntelService
    from sqlalchemy import select

    svc = ThreatIntelService()
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Observable).where(Observable.id == observable_id))
        obs = result.scalar_one_or_none()
        if not obs:
            return

        try:
            enrichment = await svc.lookup(value=obs.value, ioc_type=obs.obs_type)
            obs.enrichment = enrichment
            await db.commit()
        except Exception as e:
            logger.warning(f"Observable enrichment failed: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# Vulnerability sync
# ─────────────────────────────────────────────────────────────────────────────

@celery_app.task(name="app.workers.tasks.sync_vulnerabilities", bind=True)
def sync_vulnerabilities(self):
    logger.info("Task: sync_vulnerabilities")
    try:
        _run_async(_do_sync_vulns())
    except Exception as exc:
        logger.error(f"sync_vulnerabilities failed: {exc}")


async def _do_sync_vulns():
    from app.db.init_db import AsyncSessionLocal
    from app.connectors.registry import WazuhIndexerClient
    from app.models import Agent
    from sqlalchemy import select

    client = WazuhIndexerClient()
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Agent))
        agents = result.scalars().all()

        for agent in agents:
            try:
                data = await client.get_agent_vulnerabilities(agent.agent_id)
                hits = data.get("hits", {}).get("hits", [])
                total = data.get("hits", {}).get("total", {}).get("value", 0)
                critical = sum(1 for h in hits if h.get("_source", {}).get("vulnerability", {}).get("severity", "").lower() == "critical")
                agent.vuln_count = total
                agent.critical_vulns = critical
            except Exception as e:
                logger.debug(f"Vuln sync failed for agent {agent.agent_id}: {e}")

        await db.commit()


# ─────────────────────────────────────────────────────────────────────────────
# SOAR workflow execution
# ─────────────────────────────────────────────────────────────────────────────

@celery_app.task(name="app.workers.tasks.run_workflow", bind=True, max_retries=1)
def run_workflow(self, workflow_id: str, trigger_data: dict):
    logger.info(f"Task: run_workflow {workflow_id}")
    try:
        result = _run_async(_do_run_workflow(workflow_id, trigger_data))
        return result
    except Exception as exc:
        logger.error(f"run_workflow {workflow_id} failed: {exc}")
        raise self.retry(exc=exc, countdown=5)


async def _do_run_workflow(workflow_id: str, trigger_data: dict):
    # SOAR engine integration point
    # In production this calls into the SOAR workflow engine built earlier
    logger.info(f"Executing workflow {workflow_id} with data: {list(trigger_data.keys())}")
    return {"status": "executed", "workflow_id": workflow_id}


@celery_app.task(name="app.workers.tasks.process_wazuh_webhook")
def process_wazuh_webhook(alert_data: dict):
    """Process incoming Wazuh alert webhook — ingest + trigger matching SOAR workflows."""
    _run_async(_do_process_wazuh_webhook(alert_data))


async def _do_process_wazuh_webhook(alert_data: dict):
    from app.db.init_db import AsyncSessionLocal
    from app.models import Alert, AlertSeverity

    rule = alert_data.get("rule", {})
    level = rule.get("level", 0)

    if level >= 15:
        severity = AlertSeverity.CRITICAL
    elif level >= 12:
        severity = AlertSeverity.HIGH
    elif level >= 8:
        severity = AlertSeverity.MEDIUM
    else:
        severity = AlertSeverity.LOW

    async with AsyncSessionLocal() as db:
        alert = Alert(
            source="wazuh",
            source_id=alert_data.get("id"),
            rule_id=str(rule.get("id", "")),
            rule_name=rule.get("description"),
            description=rule.get("description"),
            severity=severity,
            agent_name=alert_data.get("agent", {}).get("name"),
            agent_ip=alert_data.get("agent", {}).get("ip"),
            agent_id=alert_data.get("agent", {}).get("id"),
            mitre_id=rule.get("mitre", {}).get("id", [None])[0] if isinstance(rule.get("mitre", {}).get("id"), list) else None,
            mitre_tactic=rule.get("mitre", {}).get("tactic", [None])[0] if isinstance(rule.get("mitre", {}).get("tactic"), list) else None,
            raw_data=alert_data,
        )
        db.add(alert)
        await db.commit()
        await db.refresh(alert)

    enrich_alert.delay(alert.id)


# ─────────────────────────────────────────────────────────────────────────────
# Connector health check
# ─────────────────────────────────────────────────────────────────────────────

@celery_app.task(name="app.workers.tasks.health_check_connectors")
def health_check_connectors():
    logger.info("Task: health_check_connectors")
    _run_async(_do_health_check())


async def _do_health_check():
    from app.db.init_db import AsyncSessionLocal
    from app.connectors.registry import verify_connector
    from app.models import Connector
    from sqlalchemy import select
    from datetime import datetime, timezone

    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Connector).where(Connector.is_active == True))
        connectors = result.scalars().all()

        for connector in connectors:
            ok, detail = await verify_connector(connector)
            connector.verified = ok
            connector.last_verified = datetime.now(timezone.utc)
            if not ok:
                logger.warning(f"Connector {connector.connector_type.value} health check failed: {detail}")

        await db.commit()
