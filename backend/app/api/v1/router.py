"""
SocBlitz API v1 — all route handlers in one organised file.
Each domain section maps to a separate router prefix.
"""
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status, BackgroundTasks
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from sqlalchemy import select, func, and_, desc, update
from sqlalchemy.ext.asyncio import AsyncSession
from loguru import logger

from app.core.auth import verify_password, create_access_token, create_refresh_token, hash_password
from app.core.deps import get_db, get_current_user, require_admin, require_analyst, DbDep, CurrentUser
from app.core.config import settings
from app.models import (
    User, UserRole, Tenant,
    Alert, AlertStatus, AlertSeverity,
    Case, CaseStatus, CasePriority, CaseComment, Observable,
    Agent, AgentStatus,
    Connector, ConnectorType,
    AuditLog,
)

api_router = APIRouter()


# ─────────────────────────────────────────────────────────────────────────────
# Health
# ─────────────────────────────────────────────────────────────────────────────

health_router = APIRouter(prefix="/health", tags=["health"])


@health_router.get("")
async def health_check():
    return {
        "status": "ok",
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@health_router.get("/detailed")
async def detailed_health(db: DbDep, _: CurrentUser):
    checks: dict[str, Any] = {}

    # Database
    try:
        await db.execute(select(func.now()))
        checks["database"] = "ok"
    except Exception as e:
        checks["database"] = f"error: {e}"

    # Redis
    try:
        from app.core.redis import get_redis
        r = await get_redis()
        await r.ping()
        checks["redis"] = "ok"
    except Exception as e:
        checks["redis"] = f"error: {e}"

    return {"status": "ok" if all(v == "ok" for v in checks.values()) else "degraded", "checks": checks}


api_router.include_router(health_router)


# ─────────────────────────────────────────────────────────────────────────────
# Auth
# ─────────────────────────────────────────────────────────────────────────────

auth_router = APIRouter(prefix="/auth", tags=["auth"])


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user_id: str
    role: str
    full_name: str | None


class UserCreate(BaseModel):
    email: EmailStr
    password: str
    full_name: str | None = None
    role: UserRole = UserRole.ANALYST
    tenant_id: str | None = None


class UserOut(BaseModel):
    id: str
    email: str
    full_name: str | None
    role: UserRole
    tenant_id: str | None
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


@auth_router.post("/login", response_model=TokenResponse)
async def login(form: OAuth2PasswordRequestForm = Depends(), db: DbDep = None):
    result = await db.execute(select(User).where(User.email == form.username, User.is_active == True))
    user = result.scalar_one_or_none()

    if not user or not verify_password(form.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    user.last_login = datetime.now(timezone.utc)
    await db.commit()

    return TokenResponse(
        access_token=create_access_token(user.id, scopes=[user.role.value]),
        refresh_token=create_refresh_token(user.id),
        user_id=user.id,
        role=user.role.value,
        full_name=user.full_name,
    )


@auth_router.get("/me", response_model=UserOut)
async def get_me(current_user: CurrentUser):
    return current_user


@auth_router.post("/users", response_model=UserOut, dependencies=[Depends(require_admin())])
async def create_user(payload: UserCreate, db: DbDep):
    existing = await db.execute(select(User).where(User.email == payload.email))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Email already registered")

    user = User(
        email=payload.email,
        hashed_password=hash_password(payload.password),
        full_name=payload.full_name,
        role=payload.role,
        tenant_id=payload.tenant_id,
        is_active=True,
        is_verified=True,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


@auth_router.get("/users", response_model=list[UserOut], dependencies=[Depends(require_admin())])
async def list_users(db: DbDep, skip: int = 0, limit: int = 50):
    result = await db.execute(select(User).offset(skip).limit(limit))
    return result.scalars().all()


api_router.include_router(auth_router)


# ─────────────────────────────────────────────────────────────────────────────
# Tenants
# ─────────────────────────────────────────────────────────────────────────────

tenant_router = APIRouter(prefix="/tenants", tags=["tenants"], dependencies=[Depends(require_admin())])


class TenantCreate(BaseModel):
    code: str
    name: str
    description: str | None = None


class TenantOut(BaseModel):
    id: str
    code: str
    name: str
    description: str | None
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


@tenant_router.get("", response_model=list[TenantOut])
async def list_tenants(db: DbDep):
    result = await db.execute(select(Tenant).order_by(Tenant.name))
    return result.scalars().all()


@tenant_router.post("", response_model=TenantOut, status_code=201)
async def create_tenant(payload: TenantCreate, db: DbDep):
    existing = await db.execute(select(Tenant).where(Tenant.code == payload.code))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Tenant code already exists")
    t = Tenant(**payload.model_dump())
    db.add(t)
    await db.commit()
    await db.refresh(t)
    return t


@tenant_router.get("/{tenant_id}", response_model=TenantOut)
async def get_tenant(tenant_id: str, db: DbDep):
    result = await db.execute(select(Tenant).where(Tenant.id == tenant_id))
    t = result.scalar_one_or_none()
    if not t:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return t


api_router.include_router(tenant_router)


# ─────────────────────────────────────────────────────────────────────────────
# Alerts
# ─────────────────────────────────────────────────────────────────────────────

alert_router = APIRouter(prefix="/alerts", tags=["alerts"])


class AlertOut(BaseModel):
    id: str
    source: str
    source_id: str | None
    rule_id: str | None
    rule_name: str | None
    description: str | None
    severity: AlertSeverity
    status: AlertStatus
    agent_name: str | None
    agent_ip: str | None
    src_ip: str | None
    mitre_id: str | None
    mitre_tactic: str | None
    tags: list | None
    case_id: str | None
    tenant_id: str | None
    alert_time: datetime
    created_at: datetime

    class Config:
        from_attributes = True


class AlertIngest(BaseModel):
    source: str
    source_id: str | None = None
    rule_id: str | None = None
    rule_name: str | None = None
    description: str | None = None
    severity: AlertSeverity = AlertSeverity.MEDIUM
    agent_name: str | None = None
    agent_ip: str | None = None
    agent_id: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    username: str | None = None
    mitre_id: str | None = None
    mitre_tactic: str | None = None
    raw_data: dict | None = None
    tags: list | None = None
    tenant_id: str | None = None


class AlertUpdate(BaseModel):
    status: AlertStatus | None = None
    case_id: str | None = None
    tags: list | None = None


@alert_router.get("", response_model=list[AlertOut])
async def list_alerts(
    db: DbDep,
    current_user: CurrentUser,
    status_filter: AlertStatus | None = Query(None, alias="status"),
    severity: AlertSeverity | None = None,
    tenant_id: str | None = None,
    skip: int = 0,
    limit: int = 50,
):
    q = select(Alert).order_by(desc(Alert.alert_time))

    if status_filter:
        q = q.where(Alert.status == status_filter)
    if severity:
        q = q.where(Alert.severity == severity)
    if tenant_id:
        q = q.where(Alert.tenant_id == tenant_id)
    elif current_user.role == UserRole.CUSTOMER_USER and current_user.tenant_id:
        q = q.where(Alert.tenant_id == current_user.tenant_id)

    result = await db.execute(q.offset(skip).limit(limit))
    return result.scalars().all()


@alert_router.get("/stats")
async def alert_stats(db: DbDep, current_user: CurrentUser):
    base = select(Alert)
    if current_user.role == UserRole.CUSTOMER_USER and current_user.tenant_id:
        base = base.where(Alert.tenant_id == current_user.tenant_id)

    severity_counts = {}
    for sev in AlertSeverity:
        r = await db.execute(
            base.where(Alert.severity == sev).with_only_columns(func.count())
        )
        severity_counts[sev.value] = r.scalar()

    status_counts = {}
    for st in AlertStatus:
        r = await db.execute(
            base.where(Alert.status == st).with_only_columns(func.count())
        )
        status_counts[st.value] = r.scalar()

    return {"severity": severity_counts, "status": status_counts}


@alert_router.post("", response_model=AlertOut, status_code=201)
async def ingest_alert(
    payload: AlertIngest,
    db: DbDep,
    background_tasks: BackgroundTasks,
    current_user: CurrentUser,
):
    alert = Alert(**payload.model_dump())
    db.add(alert)
    await db.commit()
    await db.refresh(alert)

    # Kick off enrichment in background
    background_tasks.add_task(_enrich_alert_background, alert.id)

    return alert


async def _enrich_alert_background(alert_id: str):
    """Background enrichment — extracts IOCs and queries threat intel."""
    try:
        from app.workers.celery_app import celery_app
        celery_app.send_task("app.workers.tasks.enrich_alert", args=[alert_id])
    except Exception as e:
        logger.warning(f"Failed to queue alert enrichment for {alert_id}: {e}")


@alert_router.get("/{alert_id}", response_model=AlertOut)
async def get_alert(alert_id: str, db: DbDep, current_user: CurrentUser):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@alert_router.patch("/{alert_id}", response_model=AlertOut)
async def update_alert(alert_id: str, payload: AlertUpdate, db: DbDep, current_user: CurrentUser):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    update_data = payload.model_dump(exclude_none=True)
    if payload.status in (AlertStatus.IN_TRIAGE, AlertStatus.RESOLVED):
        update_data["triaged_by"] = current_user.id
        update_data["triaged_at"] = datetime.now(timezone.utc)

    for k, v in update_data.items():
        setattr(alert, k, v)

    await db.commit()
    await db.refresh(alert)
    return alert


api_router.include_router(alert_router)


# ─────────────────────────────────────────────────────────────────────────────
# Cases
# ─────────────────────────────────────────────────────────────────────────────

case_router = APIRouter(prefix="/cases", tags=["cases"])


class CaseCreate(BaseModel):
    title: str
    description: str | None = None
    priority: CasePriority = CasePriority.MEDIUM
    tags: list | None = None
    assigned_to: str | None = None
    tlp: str = "AMBER"
    tenant_id: str | None = None


class CaseOut(BaseModel):
    id: str
    case_number: int
    title: str
    description: str | None
    status: CaseStatus
    priority: CasePriority
    tags: list | None
    assigned_to: str | None
    created_by: str | None
    tenant_id: str | None
    tlp: str
    summary: str | None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class CommentCreate(BaseModel):
    content: str
    is_internal: bool = True


class ObservableCreate(BaseModel):
    obs_type: str
    value: str
    description: str | None = None
    is_ioc: bool = False
    tlp: str = "AMBER"


@case_router.get("", response_model=list[CaseOut])
async def list_cases(
    db: DbDep,
    current_user: CurrentUser,
    status_filter: CaseStatus | None = Query(None, alias="status"),
    priority: CasePriority | None = None,
    skip: int = 0,
    limit: int = 50,
):
    q = select(Case).order_by(desc(Case.created_at))

    if status_filter:
        q = q.where(Case.status == status_filter)
    if priority:
        q = q.where(Case.priority == priority)
    if current_user.role == UserRole.CUSTOMER_USER and current_user.tenant_id:
        q = q.where(Case.tenant_id == current_user.tenant_id)

    result = await db.execute(q.offset(skip).limit(limit))
    return result.scalars().all()


@case_router.post("", response_model=CaseOut, status_code=201)
async def create_case(payload: CaseCreate, db: DbDep, current_user: CurrentUser):
    # Auto-increment case number per tenant
    tenant_id = payload.tenant_id or current_user.tenant_id
    count_r = await db.execute(select(func.count()).select_from(Case).where(Case.tenant_id == tenant_id))
    case_number = (count_r.scalar() or 0) + 1

    case = Case(
        **payload.model_dump(),
        case_number=case_number,
        created_by=current_user.id,
    )
    db.add(case)
    await db.commit()
    await db.refresh(case)
    return case


@case_router.get("/{case_id}", response_model=CaseOut)
async def get_case(case_id: str, db: DbDep, current_user: CurrentUser):
    result = await db.execute(select(Case).where(Case.id == case_id))
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return case


@case_router.patch("/{case_id}", response_model=CaseOut)
async def update_case(case_id: str, payload: dict, db: DbDep, current_user: CurrentUser):
    result = await db.execute(select(Case).where(Case.id == case_id))
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    allowed = {"title", "description", "status", "priority", "tags", "assigned_to", "tlp", "pap", "summary"}
    for k, v in payload.items():
        if k in allowed:
            setattr(case, k, v)

    if payload.get("status") in (CaseStatus.RESOLVED.value, CaseStatus.CLOSED.value):
        case.closed_at = datetime.now(timezone.utc)

    await db.commit()
    await db.refresh(case)
    return case


@case_router.post("/{case_id}/comments", status_code=201)
async def add_comment(case_id: str, payload: CommentCreate, db: DbDep, current_user: CurrentUser):
    comment = CaseComment(
        case_id=case_id,
        author_id=current_user.id,
        content=payload.content,
        is_internal=payload.is_internal,
    )
    db.add(comment)
    await db.commit()
    return {"id": comment.id, "content": comment.content, "created_at": comment.created_at}


@case_router.get("/{case_id}/comments")
async def get_comments(case_id: str, db: DbDep, current_user: CurrentUser):
    result = await db.execute(
        select(CaseComment).where(CaseComment.case_id == case_id).order_by(CaseComment.created_at)
    )
    return result.scalars().all()


@case_router.post("/{case_id}/observables", status_code=201)
async def add_observable(case_id: str, payload: ObservableCreate, db: DbDep, current_user: CurrentUser):
    obs = Observable(case_id=case_id, **payload.model_dump())
    db.add(obs)
    await db.commit()

    # Auto-enrich the observable
    from app.workers.celery_app import celery_app
    try:
        celery_app.send_task("app.workers.tasks.enrich_observable", args=[obs.id])
    except Exception:
        pass

    await db.refresh(obs)
    return obs


@case_router.get("/{case_id}/observables")
async def get_observables(case_id: str, db: DbDep, current_user: CurrentUser):
    result = await db.execute(
        select(Observable).where(Observable.case_id == case_id).order_by(Observable.created_at)
    )
    return result.scalars().all()


api_router.include_router(case_router)


# ─────────────────────────────────────────────────────────────────────────────
# Agents
# ─────────────────────────────────────────────────────────────────────────────

agent_router = APIRouter(prefix="/agents", tags=["agents"])


class AgentOut(BaseModel):
    id: str
    agent_id: str
    name: str | None
    hostname: str | None
    ip: str | None
    os: str
    os_version: str | None
    status: str
    version: str | None
    group: str | None
    last_seen: datetime | None
    vuln_count: int
    critical_vulns: int
    tenant_id: str | None

    class Config:
        from_attributes = True


@agent_router.get("", response_model=list[AgentOut])
async def list_agents(
    db: DbDep,
    current_user: CurrentUser,
    status_filter: AgentStatus | None = Query(None, alias="status"),
    tenant_id: str | None = None,
    skip: int = 0,
    limit: int = 100,
):
    q = select(Agent)
    if status_filter:
        q = q.where(Agent.status == status_filter)
    if tenant_id:
        q = q.where(Agent.tenant_id == tenant_id)
    elif current_user.role == UserRole.CUSTOMER_USER and current_user.tenant_id:
        q = q.where(Agent.tenant_id == current_user.tenant_id)

    result = await db.execute(q.order_by(Agent.name))
    return result.scalars().all()


@agent_router.post("/sync")
async def sync_agents(db: DbDep, current_user: CurrentUser):
    """Trigger agent sync from Wazuh."""
    try:
        from app.workers.celery_app import celery_app
        task = celery_app.send_task("app.workers.tasks.sync_wazuh_agents")
        return {"status": "queued", "task_id": task.id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@agent_router.get("/{agent_db_id}/vulnerabilities")
async def get_agent_vulnerabilities(agent_db_id: str, db: DbDep, current_user: CurrentUser):
    """Pull vulnerabilities for a specific agent from Wazuh indexer."""
    result = await db.execute(select(Agent).where(Agent.id == agent_db_id))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    from app.connectors.wazuh.client import WazuhIndexerClient
    client = WazuhIndexerClient()
    return await client.get_agent_vulnerabilities(agent.agent_id)


api_router.include_router(agent_router)


# ─────────────────────────────────────────────────────────────────────────────
# Connectors
# ─────────────────────────────────────────────────────────────────────────────

connector_router = APIRouter(prefix="/connectors", tags=["connectors"], dependencies=[Depends(require_admin())])


class ConnectorUpdate(BaseModel):
    url: str | None = None
    username: str | None = None
    password: str | None = None
    api_key: str | None = None
    extra_config: dict | None = None
    is_active: bool | None = None


class ConnectorOut(BaseModel):
    id: str
    connector_type: ConnectorType
    url: str | None
    username: str | None
    is_active: bool
    verified: bool
    last_verified: datetime | None
    created_at: datetime

    class Config:
        from_attributes = True


@connector_router.get("", response_model=list[ConnectorOut])
async def list_connectors(db: DbDep):
    result = await db.execute(select(Connector))
    return result.scalars().all()


@connector_router.get("/{connector_id}", response_model=ConnectorOut)
async def get_connector(connector_id: str, db: DbDep):
    result = await db.execute(select(Connector).where(Connector.id == connector_id))
    c = result.scalar_one_or_none()
    if not c:
        raise HTTPException(status_code=404, detail="Connector not found")
    return c


@connector_router.patch("/{connector_id}", response_model=ConnectorOut)
async def update_connector(connector_id: str, payload: ConnectorUpdate, db: DbDep):
    result = await db.execute(select(Connector).where(Connector.id == connector_id))
    c = result.scalar_one_or_none()
    if not c:
        raise HTTPException(status_code=404, detail="Connector not found")

    for k, v in payload.model_dump(exclude_none=True).items():
        setattr(c, k, v)

    await db.commit()
    await db.refresh(c)
    return c


@connector_router.post("/{connector_id}/verify")
async def verify_connector(connector_id: str, db: DbDep):
    """Test connectivity for a connector."""
    result = await db.execute(select(Connector).where(Connector.id == connector_id))
    c = result.scalar_one_or_none()
    if not c:
        raise HTTPException(status_code=404, detail="Connector not found")

    from app.connectors.registry import verify_connector as do_verify
    ok, detail = await do_verify(c)

    c.verified = ok
    c.last_verified = datetime.now(timezone.utc)
    await db.commit()

    return {"connected": ok, "detail": detail}


api_router.include_router(connector_router)


# ─────────────────────────────────────────────────────────────────────────────
# Threat Intelligence
# ─────────────────────────────────────────────────────────────────────────────

ti_router = APIRouter(prefix="/threat-intel", tags=["threat_intel"])


@ti_router.post("/lookup")
async def lookup_ioc(body: dict, current_user: CurrentUser):
    """Multi-source IOC lookup — VT + AbuseIPDB + MISP in parallel."""
    value = body.get("value")
    ioc_type = body.get("type", "ip")

    if not value:
        raise HTTPException(status_code=422, detail="value is required")

    from app.services.threat_intel import ThreatIntelService
    svc = ThreatIntelService()
    result = await svc.lookup(value=value, ioc_type=ioc_type)
    return result


@ti_router.get("/misp/events")
async def misp_events(current_user: CurrentUser, limit: int = 25):
    from app.connectors.misp.client import MispClient
    c = MispClient()
    return await c.search_events(limit=limit)


@ti_router.post("/misp/lookup")
async def misp_lookup(body: dict, current_user: CurrentUser):
    from app.connectors.misp.client import MispClient
    c = MispClient()
    return await c.search_attributes(value=body.get("value", ""))


api_router.include_router(ti_router)


# ─────────────────────────────────────────────────────────────────────────────
# SOAR Workflows (integrated from SOAR engine)
# ─────────────────────────────────────────────────────────────────────────────

soar_router = APIRouter(prefix="/soar", tags=["soar"])


@soar_router.get("/workflows")
async def list_workflows(db: DbDep, current_user: CurrentUser):
    # Implemented via saved objects or separate SOAR DB table
    return {"workflows": [], "note": "SOAR engine integrated — see /soar/workflows"}


@soar_router.post("/workflows/{wf_id}/run")
async def run_workflow(wf_id: str, body: dict, current_user: CurrentUser):
    try:
        from app.workers.celery_app import celery_app
        task = celery_app.send_task("app.workers.tasks.run_workflow", args=[wf_id, body])
        return {"status": "queued", "task_id": task.id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@soar_router.post("/trigger/wazuh-alert")
async def trigger_from_wazuh(body: dict):
    """Webhook endpoint — Wazuh calls this via active-response integration."""
    try:
        from app.workers.celery_app import celery_app
        celery_app.send_task("app.workers.tasks.process_wazuh_webhook", args=[body])
        return {"status": "accepted"}
    except Exception as e:
        logger.error(f"Webhook processing failed: {e}")
        return {"status": "error", "detail": str(e)}


api_router.include_router(soar_router)


# ─────────────────────────────────────────────────────────────────────────────
# Audit Logs
# ─────────────────────────────────────────────────────────────────────────────

audit_router = APIRouter(prefix="/audit", tags=["audit"], dependencies=[Depends(require_admin())])


@audit_router.get("")
async def list_audit_logs(
    db: DbDep,
    user_id: str | None = None,
    action: str | None = None,
    skip: int = 0,
    limit: int = 100,
):
    q = select(AuditLog).order_by(desc(AuditLog.timestamp))
    if user_id:
        q = q.where(AuditLog.user_id == user_id)
    if action:
        q = q.where(AuditLog.action.ilike(f"%{action}%"))
    result = await db.execute(q.offset(skip).limit(limit))
    return result.scalars().all()


api_router.include_router(audit_router)
