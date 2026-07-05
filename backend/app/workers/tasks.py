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

            agent.name       = "socblitz-manager" if agent_id == "000" else raw.get("name")
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

@celery_app.task(name="app.workers.tasks.run_workflow", bind=True, max_retries=0)
def run_workflow(self, workflow_id: str, run_id: str, trigger_data: dict):
    logger.info(f"Task: run_workflow {workflow_id} (run {run_id})")
    return _run_async(_do_run_workflow(workflow_id, run_id, trigger_data))


async def _do_run_workflow(workflow_id: str, run_id: str, trigger_data: dict):
    from app.db.init_db import AsyncSessionLocal
    from app.models import Workflow, WorkflowRun, TaskStatus
    from app.services.workflow_engine import execute_workflow
    from sqlalchemy import select

    async with AsyncSessionLocal() as db:
        wf_result = await db.execute(select(Workflow).where(Workflow.id == workflow_id))
        workflow = wf_result.scalar_one_or_none()
        run_result = await db.execute(select(WorkflowRun).where(WorkflowRun.id == run_id))
        run = run_result.scalar_one_or_none()

        if not workflow or not run:
            logger.warning(f"run_workflow: workflow {workflow_id} or run {run_id} not found")
            return {"status": "error", "detail": "workflow or run not found"}

        run.status = TaskStatus.RUNNING
        await db.commit()

        try:
            node_results = await execute_workflow(workflow.nodes or [], workflow.edges or [], trigger_data)
            failed = any(not entry["result"].get("ok", False) for entry in node_results)
            run.status = TaskStatus.FAILED if failed else TaskStatus.SUCCESS
            run.node_results = node_results
        except Exception as exc:
            logger.error(f"run_workflow {workflow_id} failed: {exc}")
            run.status = TaskStatus.FAILED
            run.error = str(exc)

        run.finished_at = datetime.now(timezone.utc)
        workflow.run_count = (workflow.run_count or 0) + 1
        workflow.last_run_at = run.finished_at
        await db.commit()

        return {"status": run.status.value, "run_id": run_id, "workflow_id": workflow_id}


@celery_app.task(name="app.workers.tasks.process_wazuh_webhook")
def process_wazuh_webhook(alert_data: dict):
    """Process incoming Wazuh alert webhook — ingest + trigger matching SOAR workflows."""
    _run_async(_do_process_wazuh_webhook(alert_data))


ALERT_MIN_LEVEL = 12  # only Wazuh rule level >= 12 becomes a SocBlitz Alert
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


async def _do_process_wazuh_webhook(alert_data: dict):
    from app.db.init_db import AsyncSessionLocal
    from app.models import Alert, AlertSeverity, Workflow, WorkflowRun, WorkflowTrigger, TaskStatus
    from sqlalchemy import select

    rule = alert_data.get("rule", {})
    level = rule.get("level", 0)

    if level < ALERT_MIN_LEVEL:
        logger.debug(f"Wazuh alert level {level} below threshold {ALERT_MIN_LEVEL} — skipping")
        return

    severity = AlertSeverity.CRITICAL if level >= 15 else AlertSeverity.HIGH

    async with AsyncSessionLocal() as db:
        alert = Alert(
            source="wazuh",
            source_id=alert_data.get("id"),
            rule_id=str(rule.get("id", "")),
            rule_name=rule.get("description"),
            level=level,
            description=rule.get("description"),
            severity=severity,
            agent_name=alert_data.get("agent", {}).get("name"),
            agent_ip=alert_data.get("agent", {}).get("ip"),
            agent_id=alert_data.get("agent", {}).get("id"),
            src_ip=alert_data.get("data", {}).get("srcip"),
            mitre_id=rule.get("mitre", {}).get("id", [None])[0] if isinstance(rule.get("mitre", {}).get("id"), list) else None,
            mitre_tactic=rule.get("mitre", {}).get("tactic", [None])[0] if isinstance(rule.get("mitre", {}).get("tactic"), list) else None,
            raw_data=alert_data,
        )
        db.add(alert)
        await db.commit()
        await db.refresh(alert)

        # Auto-trigger any active alert-type workflow whose severity threshold this alert clears.
        alert_rank = SEVERITY_RANK.get(severity.value, 0)
        wf_result = await db.execute(
            select(Workflow).where(Workflow.is_active == True, Workflow.trigger_type == WorkflowTrigger.ALERT)
        )
        matched = []
        for workflow in wf_result.scalars().all():
            threshold = (workflow.trigger_config or {}).get("severity", "critical")
            if SEVERITY_RANK.get(threshold, 4) > alert_rank:
                continue
            run = WorkflowRun(
                workflow_id=workflow.id,
                status=TaskStatus.PENDING,
                trigger_data={
                    "alert_id": alert.id, "rule_name": alert.rule_name, "level": alert.level,
                    "severity": severity.value, "agent_id": alert.agent_id, "agent_name": alert.agent_name,
                    "agent_ip": alert.agent_ip, "src_ip": alert.src_ip,
                    "mitre_id": alert.mitre_id, "mitre_tactic": alert.mitre_tactic,
                },
            )
            db.add(run)
            matched.append((workflow, run))

        if matched:
            await db.commit()
            for workflow, run in matched:
                await db.refresh(run)
                run_workflow.delay(workflow.id, run.id, run.trigger_data)

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
