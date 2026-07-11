"""
SocBlitz API v1 — all route handlers in one organised file.
Each domain section maps to a separate router prefix.
"""
import asyncio
import base64
import hashlib
import io
import secrets as py_secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pyotp
import qrcode
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status, BackgroundTasks, Response
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from sqlalchemy import select, func, and_, desc, update
from sqlalchemy.ext.asyncio import AsyncSession
from loguru import logger

from app.core.auth import (
    verify_password, create_access_token, create_refresh_token, hash_password,
    create_mfa_token, decode_token,
)
from app.core.deps import get_db, get_current_user, require_admin, require_analyst, DbDep, CurrentUser
from app.core.config import settings
from app.models import (
    User, UserRole, Tenant,
    Alert, AlertStatus, AlertSeverity,
    Case, CaseStatus, CasePriority, CaseClassification, CaseComment, Observable, CaseTask, CaseTaskStatus,
    CaseAsset, AssetType, AssetCompromiseStatus, CaseEvidence, CaseNote,
    Agent, AgentStatus,
    Connector, ConnectorType,
    CustomDashboard,
    Workflow, WorkflowRun, WorkflowTrigger, TaskStatus,
    AuditLog,
    new_uuid,
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
    mfa_enabled: bool = False
    created_at: datetime

    class Config:
        from_attributes = True


class LoginResponse(BaseModel):
    """Either the final tokens, or an MFA challenge (mfa_required + mfa_token)."""
    mfa_required: bool = False
    mfa_token: str | None = None
    access_token: str | None = None
    refresh_token: str | None = None
    token_type: str = "bearer"
    user_id: str | None = None
    role: str | None = None
    full_name: str | None = None


class MFAVerifyRequest(BaseModel):
    mfa_token: str
    code: str


class MFACodeRequest(BaseModel):
    code: str


class MFADisableRequest(BaseModel):
    password: str
    code: str


def _hash_backup_code(code: str) -> str:
    return hashlib.sha256(code.strip().replace("-", "").lower().encode()).hexdigest()


def _check_mfa_code(user: User, code: str) -> bool:
    """Accept a current TOTP code, or consume a one-time backup code."""
    code = code.strip().replace(" ", "")
    if user.totp_secret and pyotp.TOTP(user.totp_secret).verify(code, valid_window=1):
        return True
    if user.mfa_backup_codes:
        hashed = _hash_backup_code(code)
        if hashed in user.mfa_backup_codes:
            user.mfa_backup_codes = [c for c in user.mfa_backup_codes if c != hashed]
            return True
    return False


async def _mfa_throttle(user_id: str, clear: bool = False) -> None:
    """Best-effort brute-force guard on MFA codes (fails open if Redis is down)."""
    try:
        from app.core.redis import get_redis
        r = await get_redis()
        key = f"mfa:attempts:{user_id}"
        if clear:
            await r.delete(key)
            return
        attempts = await r.incr(key)
        if attempts == 1:
            await r.expire(key, 300)
        if attempts > 8:
            raise HTTPException(status_code=429, detail="Too many MFA attempts — try again in a few minutes")
    except HTTPException:
        raise
    except Exception as e:
        logger.warning(f"MFA throttle unavailable: {e}")


def _issue_tokens(user: User) -> LoginResponse:
    return LoginResponse(
        access_token=create_access_token(user.id, scopes=[user.role.value]),
        refresh_token=create_refresh_token(user.id),
        user_id=user.id,
        role=user.role.value,
        full_name=user.full_name,
    )


@auth_router.post("/login", response_model=LoginResponse, response_model_exclude_none=True)
async def login(form: OAuth2PasswordRequestForm = Depends(), db: DbDep = None):
    result = await db.execute(select(User).where(User.email == form.username))
    user = result.scalar_one_or_none()

    # Same message for unknown email and wrong password — don't leak which
    # emails have accounts. Disabled accounts get a distinct message only
    # AFTER the password checks out, for the same reason.
    # bcrypt costs ~200ms of pure CPU — run it in a thread so one login
    # doesn't stall every other request on this worker's event loop.
    password_ok = user is not None and await asyncio.to_thread(
        verify_password, form.password, user.hashed_password
    )
    if not password_ok:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password")

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="This account is disabled — contact an administrator")

    if user.mfa_enabled:
        # Password OK — hand back a short-lived challenge token; real tokens
        # are only issued once /auth/mfa/verify accepts a TOTP/backup code.
        return LoginResponse(mfa_required=True, mfa_token=create_mfa_token(user.id))

    user.last_login = datetime.now(timezone.utc)
    await db.commit()
    return _issue_tokens(user)


@auth_router.post("/mfa/verify", response_model=LoginResponse, response_model_exclude_none=True)
async def mfa_verify(payload: MFAVerifyRequest, db: DbDep):
    try:
        claims = decode_token(payload.mfa_token)
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired MFA session — sign in again")
    if claims.get("type") != "mfa":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired MFA session — sign in again")

    result = await db.execute(select(User).where(User.id == claims.get("sub"), User.is_active == True))
    user = result.scalar_one_or_none()
    if not user or not user.mfa_enabled or not user.totp_secret:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired MFA session — sign in again")

    await _mfa_throttle(user.id)
    if not _check_mfa_code(user, payload.code):
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid verification code")

    await _mfa_throttle(user.id, clear=True)
    user.last_login = datetime.now(timezone.utc)
    await db.commit()
    return _issue_tokens(user)


@auth_router.post("/mfa/setup")
async def mfa_setup(current_user: CurrentUser, db: DbDep):
    """Generate a TOTP secret for the signed-in user. MFA stays off until /mfa/enable confirms a code."""
    if current_user.mfa_enabled:
        raise HTTPException(status_code=400, detail="MFA is already enabled — disable it first to re-enroll")

    secret = pyotp.random_base32()
    current_user.totp_secret = secret
    await db.commit()

    otpauth_uri = pyotp.TOTP(secret).provisioning_uri(name=current_user.email, issuer_name=settings.APP_NAME)
    buf = io.BytesIO()
    qrcode.make(otpauth_uri).save(buf)
    return {
        "secret": secret,
        "otpauth_uri": otpauth_uri,
        "qr_code": "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode(),
    }


@auth_router.post("/mfa/enable")
async def mfa_enable(payload: MFACodeRequest, current_user: CurrentUser, db: DbDep):
    """Confirm the first TOTP code and switch MFA on. Returns one-time backup codes — shown only once."""
    if current_user.mfa_enabled:
        raise HTTPException(status_code=400, detail="MFA is already enabled")
    if not current_user.totp_secret:
        raise HTTPException(status_code=400, detail="Run /auth/mfa/setup first")
    if not pyotp.TOTP(current_user.totp_secret).verify(payload.code.strip().replace(" ", ""), valid_window=1):
        raise HTTPException(status_code=400, detail="Invalid verification code — check your authenticator app")

    backup_codes = ["-".join(py_secrets.token_hex(2) for _ in range(3)) for _ in range(8)]
    current_user.mfa_backup_codes = [_hash_backup_code(c) for c in backup_codes]
    current_user.mfa_enabled = True
    await db.commit()
    logger.info(f"MFA enabled for user {current_user.email}")
    return {"mfa_enabled": True, "backup_codes": backup_codes}


@auth_router.post("/mfa/disable")
async def mfa_disable(payload: MFADisableRequest, current_user: CurrentUser, db: DbDep):
    """Turn MFA off — requires the account password plus a current TOTP or backup code."""
    if not current_user.mfa_enabled:
        raise HTTPException(status_code=400, detail="MFA is not enabled")
    # 400 (not 401) so the frontend's global 401 interceptor doesn't log the
    # user out over a typo'd password/code
    if not verify_password(payload.password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="Invalid password")
    await _mfa_throttle(current_user.id)
    if not _check_mfa_code(current_user, payload.code):
        await db.rollback()
        raise HTTPException(status_code=400, detail="Invalid verification code")

    await _mfa_throttle(current_user.id, clear=True)
    current_user.mfa_enabled = False
    current_user.totp_secret = None
    current_user.mfa_backup_codes = None
    await db.commit()
    logger.info(f"MFA disabled for user {current_user.email}")
    return {"mfa_enabled": False}


@auth_router.post("/users/{user_id}/mfa/reset", dependencies=[Depends(require_admin())])
async def admin_reset_mfa(user_id: str, db: DbDep):
    """Admin recovery path for users locked out of their authenticator."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.mfa_enabled = False
    user.totp_secret = None
    user.mfa_backup_codes = None
    await db.commit()
    logger.info(f"MFA reset by admin for user {user.email}")
    return {"mfa_enabled": False, "user_id": user.id}


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
    level: int | None
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


class AlertDetailOut(AlertOut):
    agent_id: str | None
    dst_ip: str | None
    username: str | None
    iocs: dict | None
    enrichment: dict | None
    raw_data: dict | None
    triaged_by: str | None
    triaged_at: datetime | None
    updated_at: datetime


class AlertIngest(BaseModel):
    source: str
    source_id: str | None = None
    rule_id: str | None = None
    rule_name: str | None = None
    level: int | None = None
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


def _parse_alert_query(text: str) -> list:
    """Parse a `field:value` mini-DSL into SQLAlchemy conditions (AND-combined).

    Supported fields: severity, status, agent, ip/srcip/dstip, rule, mitre,
    user, level (with >=, <=, >, <, = operators). Bare terms match across
    rule_name / description / agent_name / src_ip. Values support `*` wildcards.
    """
    import re
    import shlex
    from sqlalchemy import or_

    def like(col, val: str):
        if "*" in val:
            pattern = val.replace("%", r"\%").replace("_", r"\_").replace("*", "%")
        else:
            pattern = f"%{val}%"
        return col.ilike(pattern)

    def bare(val: str):
        return or_(like(Alert.rule_name, val), like(Alert.description, val),
                   like(Alert.agent_name, val), like(Alert.src_ip, val))

    try:
        tokens = shlex.split(text)
    except ValueError:
        tokens = text.split()

    conds = []
    for tok in tokens:
        field, sep, value = tok.partition(":")
        if not sep:
            conds.append(bare(tok))
            continue
        f = field.lower()
        if f == "severity":
            try: conds.append(Alert.severity == AlertSeverity(value.lower()))
            except ValueError: pass
        elif f == "status":
            try: conds.append(Alert.status == AlertStatus(value.lower()))
            except ValueError: pass
        elif f in ("agent", "agent_name"):
            conds.append(like(Alert.agent_name, value))
        elif f in ("srcip", "src_ip"):
            conds.append(like(Alert.src_ip, value))
        elif f in ("dstip", "dst_ip"):
            conds.append(like(Alert.dst_ip, value))
        elif f == "ip":
            conds.append(or_(like(Alert.src_ip, value), like(Alert.dst_ip, value), like(Alert.agent_ip, value)))
        elif f == "rule":
            conds.append(or_(like(Alert.rule_name, value), like(Alert.rule_id, value)))
        elif f == "mitre":
            conds.append(like(Alert.mitre_id, value))
        elif f in ("user", "username"):
            conds.append(like(Alert.username, value))
        elif f == "level":
            m = re.match(r"\s*(>=|<=|>|<|=)?\s*(\d+)\s*$", value)
            if m:
                op, num = m.group(1) or "=", int(m.group(2))
                conds.append({">=": Alert.level >= num, "<=": Alert.level <= num,
                              ">": Alert.level > num, "<": Alert.level < num,
                              "=": Alert.level == num}[op])
        else:
            # Unknown field name — fall back to matching the whole token as text.
            conds.append(bare(tok))
    return conds


@alert_router.get("", response_model=list[AlertOut])
async def list_alerts(
    db: DbDep,
    current_user: CurrentUser,
    status_filter: AlertStatus | None = Query(None, alias="status"),
    severity: AlertSeverity | None = None,
    tenant_id: str | None = None,
    case_id: str | None = None,
    query_str: str | None = Query(None, alias="q", description="field:value mini-DSL, e.g. `severity:critical agent:web-01 level:>=10`"),
    start: datetime | None = Query(None, description="ISO-8601: only alerts at/after this time"),
    end: datetime | None = Query(None, description="ISO-8601: only alerts at/before this time"),
    skip: int = 0,
    limit: int = 50,
):
    q = select(Alert).order_by(desc(Alert.alert_time))

    if status_filter:
        q = q.where(Alert.status == status_filter)
    if severity:
        q = q.where(Alert.severity == severity)
    if start:
        q = q.where(Alert.alert_time >= start)
    if end:
        q = q.where(Alert.alert_time <= end)
    if query_str and query_str.strip():
        for cond in _parse_alert_query(query_str):
            q = q.where(cond)
    if case_id:
        q = q.where(Alert.case_id == case_id)
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


@alert_router.get("/{alert_id}", response_model=AlertDetailOut)
async def get_alert(alert_id: str, db: DbDep, current_user: CurrentUser):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@alert_router.patch("/{alert_id}", response_model=AlertDetailOut)
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
# Events — raw Wazuh alert stream, every level, read live from the indexer.
# Distinct from /alerts, which only holds triaged level>=12 escalations.
# ─────────────────────────────────────────────────────────────────────────────

events_router = APIRouter(prefix="/events", tags=["events"])


class EventOut(BaseModel):
    id: str
    rule_id: str | None
    level: int
    description: str | None
    agent_name: str | None
    agent_id: str | None
    agent_ip: str | None
    src_ip: str | None
    mitre_id: str | None
    mitre_tactic: str | None
    full_log: str | None
    timestamp: datetime


@events_router.get("", response_model=list[EventOut])
async def list_events(
    current_user: CurrentUser,
    hours: int = Query(24, ge=1, le=168),
    size: int = Query(200, ge=1, le=1000),
    level_min: int | None = None,
    start: datetime | None = Query(None, description="ISO-8601 range start; overrides `hours`"),
    end: datetime | None = Query(None, description="ISO-8601 range end"),
    q: str | None = Query(None, description="Lucene query_string, e.g. `rule.level:>=10 AND agent.name:web-01`"),
):
    import httpx
    from app.connectors.registry import WazuhIndexerClient

    client = WazuhIndexerClient()
    try:
        raw = await client.get_recent_alerts(
            hours=hours, size=size,
            start=start.isoformat() if start else None,
            end=end.isoformat() if end else None,
            q=q,
        )
    except httpx.HTTPStatusError as e:
        # A 400 from OpenSearch almost always means a malformed query_string —
        # surface it as a 400 so the UI can flag the query, not the connection.
        if e.response is not None and e.response.status_code == 400:
            reason = e.response.text
            try:
                reason = e.response.json()["error"]["root_cause"][0]["reason"]
            except Exception:
                pass
            raise HTTPException(status_code=400, detail=f"Invalid query: {reason}")
        raise HTTPException(status_code=502, detail=f"Wazuh indexer error: {e}")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Wazuh indexer unavailable: {e}")

    events = []
    for hit in raw.get("hits", {}).get("hits", []):
        src = hit.get("_source", {})
        rule = src.get("rule", {})
        level = rule.get("level", 0)
        if level_min is not None and level < level_min:
            continue
        mitre = rule.get("mitre", {})
        mitre_ids = mitre.get("id")
        mitre_tactics = mitre.get("tactic")
        events.append({
            "id": hit.get("_id"),
            "rule_id": str(rule.get("id")) if rule.get("id") is not None else None,
            "level": level,
            "description": rule.get("description"),
            "agent_name": src.get("agent", {}).get("name"),
            "agent_id": src.get("agent", {}).get("id"),
            "agent_ip": src.get("agent", {}).get("ip"),
            "src_ip": src.get("data", {}).get("srcip"),
            "mitre_id": mitre_ids[0] if isinstance(mitre_ids, list) and mitre_ids else None,
            "mitre_tactic": mitre_tactics[0] if isinstance(mitre_tactics, list) and mitre_tactics else None,
            "full_log": src.get("full_log"),
            "timestamp": src.get("timestamp") or src.get("@timestamp"),
        })
    return events


@events_router.get("/{event_id}")
async def get_event(event_id: str, current_user: CurrentUser):
    """Full raw Wazuh document for one event — every field the indexer captured."""
    from app.connectors.registry import WazuhIndexerClient

    client = WazuhIndexerClient()
    try:
        hit = await client.get_alert_by_id(event_id)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Wazuh indexer unavailable: {e}")

    if not hit:
        raise HTTPException(status_code=404, detail="Event not found")

    return {**hit.get("_source", {}), "_id": hit.get("_id")}


api_router.include_router(events_router)


# ─────────────────────────────────────────────────────────────────────────────
# AI dashboard agent — flooding/noise insights + prompt-driven custom dashboards
# ─────────────────────────────────────────────────────────────────────────────

ai_router = APIRouter(prefix="/ai", tags=["ai"])


class DashboardGenerateRequest(BaseModel):
    prompt: str
    hours: int = 24


class DashboardSaveRequest(BaseModel):
    name: str = "My dashboard"
    widgets: list[dict]


@ai_router.get("/insights/flooding")
async def flooding_insights(
    db: DbDep,
    current_user: CurrentUser,
    hours: int = Query(24, ge=1, le=168),
):
    """Always-on agent view: what's flooding right now, and what quiet-but-risky
    signal is it burying."""
    from app.services.dashboard_agent import analyze_flooding_and_noise
    try:
        return await analyze_flooding_and_noise(db, hours=hours)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Wazuh indexer unavailable: {e}")


@ai_router.get("/insights/vulnerabilities")
async def vulnerability_insights(db: DbDep, current_user: CurrentUser, hours: int = Query(24, ge=1, le=168)):
    """Built-in vulnerability dashboard — wazuh-states-vulnerabilities-* index."""
    from app.services.dashboard_agent import analyze_vulnerabilities
    try:
        return await analyze_vulnerabilities(db, hours=hours)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Wazuh indexer unavailable: {e}")


@ai_router.get("/viz-catalog")
async def viz_catalog(current_user: CurrentUser, q: str | None = None):
    """The full visualization catalog (all Grafana-style panel types). Pass ?q=
    to preview RAG retrieval ranking for a prompt."""
    from app.services.viz_rag import VIZ_CATALOG, retrieve

    if q:
        return {"query": q, "results": await retrieve(q, k=10)}
    return {"catalog": VIZ_CATALOG}


@ai_router.post("/dashboard/generate")
async def generate_dashboard(payload: DashboardGenerateRequest, db: DbDep, current_user: CurrentUser):
    """Agentic dashboard builder — turns a prompt into a set of live widgets.
    Not persisted until the user explicitly saves it."""
    from app.services.dashboard_agent import build_dashboard
    try:
        return await build_dashboard(payload.prompt, db, hours=payload.hours)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Wazuh indexer unavailable: {e}")


class DashboardCreateRequest(BaseModel):
    name: str


def _widget_recipes(widgets: list[dict]) -> list[dict]:
    """Persist widget recipes (generator + params), not the data itself, so a
    saved dashboard always re-renders with fresh numbers."""
    return [
        {"id": w.get("id"), "generator": w.get("generator"), "title": w.get("title"), "params": w.get("params", {})}
        for w in widgets
        if w.get("generator")
    ]


async def _get_user_dashboard(db, dashboard_id: str, current_user) -> CustomDashboard:
    result = await db.execute(select(CustomDashboard).where(
        CustomDashboard.id == dashboard_id, CustomDashboard.user_id == current_user.id
    ))
    dashboard = result.scalar_one_or_none()
    if not dashboard:
        raise HTTPException(status_code=404, detail="Dashboard not found")
    return dashboard


@ai_router.get("/dashboards")
async def list_dashboards(db: DbDep, current_user: CurrentUser):
    result = await db.execute(
        select(CustomDashboard)
        .where(CustomDashboard.user_id == current_user.id)
        .order_by(CustomDashboard.created_at)
    )
    return [
        {"id": d.id, "name": d.name, "widget_count": len(d.widgets or [])}
        for d in result.scalars().all()
    ]


@ai_router.post("/dashboards", status_code=201)
async def create_dashboard(payload: DashboardCreateRequest, db: DbDep, current_user: CurrentUser):
    dashboard = CustomDashboard(
        user_id=current_user.id,
        tenant_id=current_user.tenant_id,
        name=payload.name.strip() or "New dashboard",
        widgets=[],
    )
    db.add(dashboard)
    await db.commit()
    await db.refresh(dashboard)
    return {"id": dashboard.id, "name": dashboard.name, "widgets": []}


@ai_router.get("/dashboards/{dashboard_id}")
async def get_dashboard(dashboard_id: str, db: DbDep, current_user: CurrentUser, hours: int = Query(24, ge=1, le=168)):
    """A saved dashboard, re-resolved against fresh data."""
    from app.services.dashboard_agent import resolve_widgets

    dashboard = await _get_user_dashboard(db, dashboard_id, current_user)
    resolved = await resolve_widgets(dashboard.widgets or [], db, hours=hours)
    return {"id": dashboard.id, "name": dashboard.name, "widgets": resolved}


@ai_router.put("/dashboards/{dashboard_id}")
async def save_dashboard(dashboard_id: str, payload: DashboardSaveRequest, db: DbDep, current_user: CurrentUser):
    from app.services.dashboard_agent import resolve_widgets

    dashboard = await _get_user_dashboard(db, dashboard_id, current_user)
    dashboard.name = payload.name
    dashboard.widgets = _widget_recipes(payload.widgets)
    await db.commit()
    await db.refresh(dashboard)

    resolved = await resolve_widgets(dashboard.widgets, db)
    return {"id": dashboard.id, "name": dashboard.name, "widgets": resolved}


@ai_router.delete("/dashboards/{dashboard_id}", status_code=204)
async def delete_dashboard(dashboard_id: str, db: DbDep, current_user: CurrentUser):
    dashboard = await _get_user_dashboard(db, dashboard_id, current_user)
    await db.delete(dashboard)
    await db.commit()
    return Response(status_code=204)


api_router.include_router(ai_router)


# ─────────────────────────────────────────────────────────────────────────────
# Cases
# ─────────────────────────────────────────────────────────────────────────────

case_router = APIRouter(prefix="/cases", tags=["cases"])


def _row_dict(obj) -> dict:
    return {c.name: getattr(obj, c.name) for c in obj.__table__.columns}


def _timeline_entry(
    event_type: str,
    description: str,
    user: "User",
    event_time: datetime | None = None,
    mitre_techniques: list[str] | None = None,
) -> dict:
    return {
        "id": new_uuid()[:8],
        "type": event_type,
        "description": description,
        "actor": user.full_name or user.email,
        "timestamp": (event_time or datetime.now(timezone.utc)).isoformat(),
        "mitre_techniques": mitre_techniques or [],
    }


async def _log_timeline(db: AsyncSession, case_id: str, event_type: str, description: str, user: "User") -> None:
    result = await db.execute(select(Case).where(Case.id == case_id))
    case = result.scalar_one_or_none()
    if case:
        case.timeline = (case.timeline or []) + [_timeline_entry(event_type, description, user)]


class CaseCreate(BaseModel):
    title: str
    description: str | None = None
    priority: CasePriority = CasePriority.MEDIUM
    tags: list | None = None
    assigned_to: str | None = None
    tlp: str = "AMBER"
    tenant_id: str | None = None
    template: str | None = None   # case_templates.py key — bulk-creates its task checklist


class CaseOut(BaseModel):
    id: str
    case_number: int
    title: str
    description: str | None
    status: CaseStatus
    priority: CasePriority
    classification: CaseClassification | None = None
    closure_note: str | None = None
    tags: list | None
    assigned_to: str | None
    assignee_name: str | None = None
    created_by: str | None
    tenant_id: str | None
    tlp: str
    pap: str
    summary: str | None
    timeline: list | None
    alert_count: int = 0
    closed_at: datetime | None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class CommentCreate(BaseModel):
    content: str
    is_internal: bool = True


class CommentUpdate(BaseModel):
    content: str


class CommentOut(BaseModel):
    id: str
    case_id: str
    author_id: str | None
    author_name: str | None = None
    content: str
    is_internal: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class ObservableCreate(BaseModel):
    obs_type: str
    value: str
    description: str | None = None
    is_ioc: bool = False
    tlp: str = "AMBER"
    asset_id: str | None = None


class ObservableUpdate(BaseModel):
    value: str | None = None
    description: str | None = None
    is_ioc: bool | None = None
    tlp: str | None = None
    asset_id: str | None = None


class ObservableOut(BaseModel):
    id: str
    case_id: str
    obs_type: str
    value: str
    description: str | None
    is_ioc: bool
    tlp: str
    enrichment: dict | None
    asset_id: str | None
    asset_name: str | None = None
    correlated_count: int = 0
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class CorrelatedCaseOut(BaseModel):
    case_id: str
    case_number: int
    title: str
    status: CaseStatus
    priority: CasePriority


class CaseTaskCreate(BaseModel):
    title: str
    description: str | None = None
    assigned_to: str | None = None
    due_date: datetime | None = None


class CaseTaskUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    status: CaseTaskStatus | None = None
    assigned_to: str | None = None
    due_date: datetime | None = None


class CaseTaskOut(BaseModel):
    id: str
    case_id: str
    title: str
    description: str | None
    status: CaseTaskStatus
    assigned_to: str | None
    assignee_name: str | None = None
    created_by: str | None
    due_date: datetime | None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class TimelineEventCreate(BaseModel):
    description: str
    event_type: str = "manual"
    event_time: datetime | None = None
    mitre_techniques: list[str] = []


class AssetCreate(BaseModel):
    name: str
    asset_type: AssetType = AssetType.OTHER
    ip_address: str | None = None
    description: str | None = None
    compromise_status: AssetCompromiseStatus = AssetCompromiseStatus.UNKNOWN


class AssetUpdate(BaseModel):
    name: str | None = None
    asset_type: AssetType | None = None
    ip_address: str | None = None
    description: str | None = None
    compromise_status: AssetCompromiseStatus | None = None


class AssetOut(BaseModel):
    id: str
    case_id: str
    name: str
    asset_type: AssetType
    ip_address: str | None
    description: str | None
    compromise_status: AssetCompromiseStatus
    created_by: str | None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class EvidenceCreate(BaseModel):
    filename: str
    description: str | None = None
    hash_md5: str | None = None
    hash_sha1: str | None = None
    hash_sha256: str | None = None
    size_bytes: int | None = None
    custody_notes: str | None = None
    acquired_at: datetime | None = None


class EvidenceUpdate(BaseModel):
    filename: str | None = None
    description: str | None = None
    hash_md5: str | None = None
    hash_sha1: str | None = None
    hash_sha256: str | None = None
    custody_notes: str | None = None


class EvidenceOut(BaseModel):
    id: str
    case_id: str
    filename: str
    description: str | None
    hash_md5: str | None
    hash_sha1: str | None
    hash_sha256: str | None
    size_bytes: int | None
    custody_notes: str | None
    acquired_by: str | None
    acquired_by_name: str | None = None
    acquired_at: datetime
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class NoteCreate(BaseModel):
    title: str
    content: str


class NoteUpdate(BaseModel):
    title: str | None = None
    content: str | None = None


class NoteOut(BaseModel):
    id: str
    case_id: str
    title: str
    content: str
    author_id: str | None
    author_name: str | None = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


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
    cases = result.scalars().all()
    if not cases:
        return []

    case_ids = [c.id for c in cases]
    assignee_ids = {c.assigned_to for c in cases if c.assigned_to}

    names = {}
    if assignee_ids:
        r = await db.execute(select(User.id, User.full_name).where(User.id.in_(assignee_ids)))
        names = dict(r.all())

    r = await db.execute(
        select(Alert.case_id, func.count()).where(Alert.case_id.in_(case_ids)).group_by(Alert.case_id)
    )
    counts = dict(r.all())

    return [
        CaseOut(**_row_dict(c), assignee_name=names.get(c.assigned_to), alert_count=counts.get(c.id, 0))
        for c in cases
    ]


def _assert_case_tenant_access(case: "Case", current_user: "User") -> None:
    """Customer users may only see/edit cases in their own tenant."""
    if current_user.role == UserRole.CUSTOMER_USER and current_user.tenant_id:
        if case.tenant_id != current_user.tenant_id:
            raise HTTPException(status_code=404, detail="Case not found")


@case_router.get("/templates")
async def list_case_templates(current_user: CurrentUser):
    from app.services.case_templates import list_templates
    return list_templates()


@case_router.post("", response_model=CaseOut, status_code=201)
async def create_case(payload: CaseCreate, db: DbDep, current_user: CurrentUser):
    # Auto-increment case number per tenant
    tenant_id = payload.tenant_id or current_user.tenant_id
    count_r = await db.execute(select(func.count()).select_from(Case).where(Case.tenant_id == tenant_id))
    case_number = (count_r.scalar() or 0) + 1

    data = payload.model_dump()
    template_key = data.pop("template", None)

    case = Case(
        **data,
        case_number=case_number,
        created_by=current_user.id,
    )
    case.timeline = [_timeline_entry("created", "Case opened", current_user)]
    db.add(case)
    await db.flush()

    if template_key:
        from app.services.case_templates import get_template
        template = get_template(template_key)
        if template:
            for title in template["tasks"]:
                db.add(CaseTask(case_id=case.id, title=title, created_by=current_user.id))
            case.timeline = case.timeline + [
                _timeline_entry("update", f"Applied '{template['label']}' template ({len(template['tasks'])} tasks)", current_user)
            ]

    await db.commit()
    await db.refresh(case)
    return CaseOut(**_row_dict(case), assignee_name=None, alert_count=0)


@case_router.get("/{case_id}", response_model=CaseOut)
async def get_case(case_id: str, db: DbDep, current_user: CurrentUser):
    result = await db.execute(select(Case).where(Case.id == case_id))
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    _assert_case_tenant_access(case, current_user)

    assignee_name = None
    if case.assigned_to:
        r = await db.execute(select(User.full_name).where(User.id == case.assigned_to))
        assignee_name = r.scalar_one_or_none()
    count_r = await db.execute(select(func.count()).select_from(Alert).where(Alert.case_id == case.id))

    return CaseOut(**_row_dict(case), assignee_name=assignee_name, alert_count=count_r.scalar() or 0)


@case_router.patch("/{case_id}", response_model=CaseOut)
async def update_case(case_id: str, payload: dict, db: DbDep, current_user: CurrentUser):
    result = await db.execute(select(Case).where(Case.id == case_id))
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    _assert_case_tenant_access(case, current_user)

    allowed = {
        "title", "description", "status", "priority", "classification", "closure_note",
        "tags", "assigned_to", "tlp", "pap", "summary",
    }

    closing_status = {CaseStatus.RESOLVED.value, CaseStatus.CLOSED.value}
    if payload.get("status") in closing_status:
        final_classification = payload.get("classification", case.classification)
        if not final_classification:
            raise HTTPException(
                status_code=400,
                detail="A classification (true positive / false positive / etc.) is required to resolve or close a case",
            )

    changes = []
    for k, v in payload.items():
        if k not in allowed:
            continue
        old = getattr(case, k)
        old_val = old.value if hasattr(old, "value") else old
        if old_val != v:
            if k == "status":
                changes.append(f"Status changed from {old_val} to {v}")
            elif k == "priority":
                changes.append(f"Priority changed from {old_val} to {v}")
            elif k == "assigned_to":
                changes.append("Assignee changed")
            elif k == "classification":
                changes.append(f"Classified as {v}")
        setattr(case, k, v)

    if payload.get("status") in closing_status:
        case.closed_at = datetime.now(timezone.utc)

    for change in changes:
        case.timeline = (case.timeline or []) + [_timeline_entry("update", change, current_user)]

    await db.commit()
    await db.refresh(case)

    assignee_name = None
    if case.assigned_to:
        r = await db.execute(select(User.full_name).where(User.id == case.assigned_to))
        assignee_name = r.scalar_one_or_none()
    count_r = await db.execute(select(func.count()).select_from(Alert).where(Alert.case_id == case.id))

    return CaseOut(**_row_dict(case), assignee_name=assignee_name, alert_count=count_r.scalar() or 0)


@case_router.get("/{case_id}/timeline")
async def get_timeline(case_id: str, db: DbDep, current_user: CurrentUser):
    result = await db.execute(select(Case.timeline).where(Case.id == case_id))
    row = result.first()
    if row is None:
        raise HTTPException(status_code=404, detail="Case not found")
    return sorted(row[0] or [], key=lambda e: e.get("timestamp", ""))


@case_router.post("/{case_id}/timeline", status_code=201)
async def add_timeline_event(case_id: str, payload: TimelineEventCreate, db: DbDep, current_user: CurrentUser):
    result = await db.execute(select(Case).where(Case.id == case_id))
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    entry = _timeline_entry(
        payload.event_type, payload.description, current_user, payload.event_time, payload.mitre_techniques
    )
    case.timeline = (case.timeline or []) + [entry]
    await db.commit()
    return entry


@case_router.post("/{case_id}/comments", response_model=CommentOut, status_code=201)
async def add_comment(case_id: str, payload: CommentCreate, db: DbDep, current_user: CurrentUser):
    comment = CaseComment(
        case_id=case_id,
        author_id=current_user.id,
        content=payload.content,
        is_internal=payload.is_internal,
    )
    db.add(comment)
    await _log_timeline(db, case_id, "comment", f"{current_user.full_name or current_user.email} commented", current_user)
    await db.commit()
    await db.refresh(comment)
    return CommentOut(**_row_dict(comment), author_name=current_user.full_name or current_user.email)


@case_router.get("/{case_id}/comments", response_model=list[CommentOut])
async def get_comments(case_id: str, db: DbDep, current_user: CurrentUser):
    q = (
        select(CaseComment, User.full_name)
        .outerjoin(User, User.id == CaseComment.author_id)
        .where(CaseComment.case_id == case_id)
        .order_by(CaseComment.created_at)
    )
    rows = (await db.execute(q)).all()
    return [CommentOut(**_row_dict(c), author_name=name) for c, name in rows]


@case_router.patch("/{case_id}/comments/{comment_id}", response_model=CommentOut)
async def update_comment(case_id: str, comment_id: str, payload: CommentUpdate, db: DbDep, current_user: CurrentUser):
    result = await db.execute(select(CaseComment).where(CaseComment.id == comment_id, CaseComment.case_id == case_id))
    comment = result.scalar_one_or_none()
    if not comment:
        raise HTTPException(status_code=404, detail="Comment not found")

    comment.content = payload.content
    await db.commit()
    await db.refresh(comment)

    author_name = None
    if comment.author_id:
        r = await db.execute(select(User.full_name).where(User.id == comment.author_id))
        author_name = r.scalar_one_or_none()
    return CommentOut(**_row_dict(comment), author_name=author_name)


@case_router.post("/{case_id}/observables", response_model=ObservableOut, status_code=201)
async def add_observable(case_id: str, payload: ObservableCreate, db: DbDep, current_user: CurrentUser):
    obs = Observable(case_id=case_id, **payload.model_dump())
    db.add(obs)
    await _log_timeline(db, case_id, "observable", f"Added {payload.obs_type} observable: {payload.value}", current_user)
    await db.commit()

    # Auto-enrich the observable
    from app.workers.celery_app import celery_app
    try:
        celery_app.send_task("app.workers.tasks.enrich_observable", args=[obs.id])
    except Exception:
        pass

    await db.refresh(obs)

    asset_name = None
    if obs.asset_id:
        r = await db.execute(select(CaseAsset.name).where(CaseAsset.id == obs.asset_id))
        asset_name = r.scalar_one_or_none()

    return ObservableOut(**_row_dict(obs), asset_name=asset_name, correlated_count=0)


@case_router.get("/{case_id}/observables", response_model=list[ObservableOut])
async def get_observables(case_id: str, db: DbDep, current_user: CurrentUser):
    q = (
        select(Observable, CaseAsset.name)
        .outerjoin(CaseAsset, CaseAsset.id == Observable.asset_id)
        .where(Observable.case_id == case_id)
        .order_by(Observable.created_at)
    )
    rows = (await db.execute(q)).all()
    observables = [(o, name) for o, name in rows]

    # Cross-case IOC correlation: how many *other* cases share each observable's value.
    values = {o.value for o, _ in observables}
    corr_counts: dict[str, int] = {}
    if values:
        corr_q = (
            select(Observable.value, func.count(func.distinct(Observable.case_id)))
            .where(Observable.value.in_(values), Observable.case_id != case_id)
            .group_by(Observable.value)
        )
        corr_counts = dict((await db.execute(corr_q)).all())

    return [
        ObservableOut(**_row_dict(o), asset_name=name, correlated_count=corr_counts.get(o.value, 0))
        for o, name in observables
    ]


@case_router.get("/{case_id}/observables/{observable_id}/correlate", response_model=list[CorrelatedCaseOut])
async def correlate_observable(case_id: str, observable_id: str, db: DbDep, current_user: CurrentUser):
    """Which other cases contain an observable with this same value."""
    result = await db.execute(
        select(Observable).where(Observable.id == observable_id, Observable.case_id == case_id)
    )
    obs = result.scalar_one_or_none()
    if not obs:
        raise HTTPException(status_code=404, detail="Observable not found")

    q = (
        select(Case.id, Case.case_number, Case.title, Case.status, Case.priority)
        .join(Observable, Observable.case_id == Case.id)
        .where(Observable.value == obs.value, Case.id != case_id)
        .distinct()
    )
    if current_user.role == UserRole.CUSTOMER_USER and current_user.tenant_id:
        q = q.where(Case.tenant_id == current_user.tenant_id)

    rows = (await db.execute(q)).all()
    return [
        CorrelatedCaseOut(case_id=r[0], case_number=r[1], title=r[2], status=r[3], priority=r[4])
        for r in rows
    ]


@case_router.patch("/{case_id}/observables/{observable_id}", response_model=ObservableOut)
async def update_observable(case_id: str, observable_id: str, payload: ObservableUpdate, db: DbDep, current_user: CurrentUser):
    result = await db.execute(
        select(Observable).where(Observable.id == observable_id, Observable.case_id == case_id)
    )
    obs = result.scalar_one_or_none()
    if not obs:
        raise HTTPException(status_code=404, detail="Observable not found")

    for k, v in payload.model_dump(exclude_unset=True).items():
        setattr(obs, k, v)

    await db.commit()
    await db.refresh(obs)

    asset_name = None
    if obs.asset_id:
        r = await db.execute(select(CaseAsset.name).where(CaseAsset.id == obs.asset_id))
        asset_name = r.scalar_one_or_none()
    return ObservableOut(**_row_dict(obs), asset_name=asset_name, correlated_count=0)


@case_router.delete("/{case_id}/observables/{observable_id}", status_code=204)
async def delete_observable(case_id: str, observable_id: str, db: DbDep, current_user: CurrentUser):
    result = await db.execute(
        select(Observable).where(Observable.id == observable_id, Observable.case_id == case_id)
    )
    obs = result.scalar_one_or_none()
    if not obs:
        raise HTTPException(status_code=404, detail="Observable not found")
    await db.delete(obs)
    await db.commit()


@case_router.get("/{case_id}/tasks", response_model=list[CaseTaskOut])
async def list_case_tasks(case_id: str, db: DbDep, current_user: CurrentUser):
    q = (
        select(CaseTask, User.full_name)
        .outerjoin(User, User.id == CaseTask.assigned_to)
        .where(CaseTask.case_id == case_id)
        .order_by(CaseTask.created_at)
    )
    rows = (await db.execute(q)).all()
    return [CaseTaskOut(**_row_dict(t), assignee_name=name) for t, name in rows]


@case_router.post("/{case_id}/tasks", response_model=CaseTaskOut, status_code=201)
async def create_case_task(case_id: str, payload: CaseTaskCreate, db: DbDep, current_user: CurrentUser):
    task = CaseTask(case_id=case_id, created_by=current_user.id, **payload.model_dump())
    db.add(task)
    await _log_timeline(db, case_id, "task", f"Task created: {task.title}", current_user)
    await db.commit()
    await db.refresh(task)

    assignee_name = None
    if task.assigned_to:
        r = await db.execute(select(User.full_name).where(User.id == task.assigned_to))
        assignee_name = r.scalar_one_or_none()

    return CaseTaskOut(**_row_dict(task), assignee_name=assignee_name)


@case_router.patch("/{case_id}/tasks/{task_id}", response_model=CaseTaskOut)
async def update_case_task(case_id: str, task_id: str, payload: CaseTaskUpdate, db: DbDep, current_user: CurrentUser):
    result = await db.execute(select(CaseTask).where(CaseTask.id == task_id, CaseTask.case_id == case_id))
    task = result.scalar_one_or_none()
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    update_data = payload.model_dump(exclude_unset=True)
    status_changed = "status" in update_data and update_data["status"] != task.status
    for k, v in update_data.items():
        setattr(task, k, v)

    if status_changed:
        await _log_timeline(db, case_id, "task", f"Task '{task.title}' marked {task.status.value}", current_user)

    await db.commit()
    await db.refresh(task)

    assignee_name = None
    if task.assigned_to:
        r = await db.execute(select(User.full_name).where(User.id == task.assigned_to))
        assignee_name = r.scalar_one_or_none()

    return CaseTaskOut(**_row_dict(task), assignee_name=assignee_name)


@case_router.delete("/{case_id}/tasks/{task_id}", status_code=204)
async def delete_case_task(case_id: str, task_id: str, db: DbDep, current_user: CurrentUser):
    result = await db.execute(select(CaseTask).where(CaseTask.id == task_id, CaseTask.case_id == case_id))
    task = result.scalar_one_or_none()
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    await db.delete(task)
    await db.commit()


# ── Assets ──────────────────────────────────────────────────────────────────

@case_router.get("/{case_id}/assets", response_model=list[AssetOut])
async def list_case_assets(case_id: str, db: DbDep, current_user: CurrentUser):
    result = await db.execute(
        select(CaseAsset).where(CaseAsset.case_id == case_id).order_by(CaseAsset.created_at)
    )
    return result.scalars().all()


@case_router.post("/{case_id}/assets", response_model=AssetOut, status_code=201)
async def create_case_asset(case_id: str, payload: AssetCreate, db: DbDep, current_user: CurrentUser):
    asset = CaseAsset(case_id=case_id, created_by=current_user.id, **payload.model_dump())
    db.add(asset)
    await _log_timeline(db, case_id, "asset", f"Asset added: {asset.name}", current_user)
    await db.commit()
    await db.refresh(asset)
    return asset


@case_router.patch("/{case_id}/assets/{asset_id}", response_model=AssetOut)
async def update_case_asset(case_id: str, asset_id: str, payload: AssetUpdate, db: DbDep, current_user: CurrentUser):
    result = await db.execute(select(CaseAsset).where(CaseAsset.id == asset_id, CaseAsset.case_id == case_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    update_data = payload.model_dump(exclude_unset=True)
    status_changed = "compromise_status" in update_data and update_data["compromise_status"] != asset.compromise_status
    for k, v in update_data.items():
        setattr(asset, k, v)

    if status_changed:
        await _log_timeline(db, case_id, "asset", f"Asset '{asset.name}' marked {asset.compromise_status.value}", current_user)

    await db.commit()
    await db.refresh(asset)
    return asset


@case_router.delete("/{case_id}/assets/{asset_id}", status_code=204)
async def delete_case_asset(case_id: str, asset_id: str, db: DbDep, current_user: CurrentUser):
    result = await db.execute(select(CaseAsset).where(CaseAsset.id == asset_id, CaseAsset.case_id == case_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    await db.delete(asset)
    await db.commit()


# ── Evidence ────────────────────────────────────────────────────────────────

@case_router.get("/{case_id}/evidence", response_model=list[EvidenceOut])
async def list_case_evidence(case_id: str, db: DbDep, current_user: CurrentUser):
    q = (
        select(CaseEvidence, User.full_name)
        .outerjoin(User, User.id == CaseEvidence.acquired_by)
        .where(CaseEvidence.case_id == case_id)
        .order_by(CaseEvidence.created_at)
    )
    rows = (await db.execute(q)).all()
    return [EvidenceOut(**_row_dict(e), acquired_by_name=name) for e, name in rows]


@case_router.post("/{case_id}/evidence", response_model=EvidenceOut, status_code=201)
async def create_case_evidence(case_id: str, payload: EvidenceCreate, db: DbDep, current_user: CurrentUser):
    data = payload.model_dump()
    if not data.get("acquired_at"):
        data["acquired_at"] = datetime.now(timezone.utc)
    evidence = CaseEvidence(case_id=case_id, acquired_by=current_user.id, **data)
    db.add(evidence)
    await _log_timeline(db, case_id, "evidence", f"Evidence added: {evidence.filename}", current_user)
    await db.commit()
    await db.refresh(evidence)
    return EvidenceOut(**_row_dict(evidence), acquired_by_name=current_user.full_name or current_user.email)


@case_router.patch("/{case_id}/evidence/{evidence_id}", response_model=EvidenceOut)
async def update_case_evidence(case_id: str, evidence_id: str, payload: EvidenceUpdate, db: DbDep, current_user: CurrentUser):
    result = await db.execute(select(CaseEvidence).where(CaseEvidence.id == evidence_id, CaseEvidence.case_id == case_id))
    evidence = result.scalar_one_or_none()
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence not found")

    for k, v in payload.model_dump(exclude_unset=True).items():
        setattr(evidence, k, v)

    await db.commit()
    await db.refresh(evidence)

    acquired_by_name = None
    if evidence.acquired_by:
        r = await db.execute(select(User.full_name).where(User.id == evidence.acquired_by))
        acquired_by_name = r.scalar_one_or_none()
    return EvidenceOut(**_row_dict(evidence), acquired_by_name=acquired_by_name)


@case_router.delete("/{case_id}/evidence/{evidence_id}", status_code=204)
async def delete_case_evidence(case_id: str, evidence_id: str, db: DbDep, current_user: CurrentUser):
    result = await db.execute(select(CaseEvidence).where(CaseEvidence.id == evidence_id, CaseEvidence.case_id == case_id))
    evidence = result.scalar_one_or_none()
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence not found")
    await db.delete(evidence)
    await db.commit()


# ── Notes ───────────────────────────────────────────────────────────────────

@case_router.get("/{case_id}/notes", response_model=list[NoteOut])
async def list_case_notes(case_id: str, db: DbDep, current_user: CurrentUser):
    q = (
        select(CaseNote, User.full_name)
        .outerjoin(User, User.id == CaseNote.author_id)
        .where(CaseNote.case_id == case_id)
        .order_by(CaseNote.created_at)
    )
    rows = (await db.execute(q)).all()
    return [NoteOut(**_row_dict(n), author_name=name) for n, name in rows]


@case_router.post("/{case_id}/notes", response_model=NoteOut, status_code=201)
async def create_case_note(case_id: str, payload: NoteCreate, db: DbDep, current_user: CurrentUser):
    note = CaseNote(case_id=case_id, author_id=current_user.id, **payload.model_dump())
    db.add(note)
    await _log_timeline(db, case_id, "note", f"Note added: {note.title}", current_user)
    await db.commit()
    await db.refresh(note)
    return NoteOut(**_row_dict(note), author_name=current_user.full_name or current_user.email)


@case_router.patch("/{case_id}/notes/{note_id}", response_model=NoteOut)
async def update_case_note(case_id: str, note_id: str, payload: NoteUpdate, db: DbDep, current_user: CurrentUser):
    result = await db.execute(select(CaseNote).where(CaseNote.id == note_id, CaseNote.case_id == case_id))
    note = result.scalar_one_or_none()
    if not note:
        raise HTTPException(status_code=404, detail="Note not found")

    for k, v in payload.model_dump(exclude_unset=True).items():
        setattr(note, k, v)

    await db.commit()
    await db.refresh(note)

    author_name = None
    if note.author_id:
        r = await db.execute(select(User.full_name).where(User.id == note.author_id))
        author_name = r.scalar_one_or_none()
    return NoteOut(**_row_dict(note), author_name=author_name)


@case_router.delete("/{case_id}/notes/{note_id}", status_code=204)
async def delete_case_note(case_id: str, note_id: str, db: DbDep, current_user: CurrentUser):
    result = await db.execute(select(CaseNote).where(CaseNote.id == note_id, CaseNote.case_id == case_id))
    note = result.scalar_one_or_none()
    if not note:
        raise HTTPException(status_code=404, detail="Note not found")
    await db.delete(note)
    await db.commit()


# ── Investigation report ─────────────────────────────────────────────────────

_REPORT_TEMPLATE = """<!doctype html>
<html><head><meta charset="utf-8"><title>{{ case.title }} — Investigation Report</title>
<style>
  body { font-family: -apple-system, Segoe UI, Roboto, Arial, sans-serif; color: #1a1f2b; max-width: 960px; margin: 32px auto; padding: 0 24px; line-height: 1.5; }
  h1 { font-size: 22px; margin-bottom: 2px; }
  h2 { font-size: 15px; text-transform: uppercase; letter-spacing: 0.04em; color: #475569; border-bottom: 1px solid #cbd5e1; padding-bottom: 6px; margin-top: 32px; }
  .sub { color: #64748b; font-size: 13px; }
  table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 13px; }
  th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid #e2e8f0; vertical-align: top; }
  th { color: #64748b; font-weight: 600; font-size: 11px; text-transform: uppercase; }
  .badge { display: inline-block; font-size: 11px; font-weight: 600; padding: 1px 8px; border-radius: 10px; background: #eef2ff; color: #3730a3; margin-right: 4px; }
  .meta-grid { display: flex; flex-wrap: wrap; gap: 24px; margin-top: 12px; }
  .meta-grid div { font-size: 13px; }
  .meta-grid b { display: block; font-size: 10px; text-transform: uppercase; color: #64748b; font-weight: 600; }
  .empty { color: #94a3b8; font-style: italic; font-size: 13px; }
  @media print { body { margin: 0; padding: 16px; } }
</style></head>
<body>
  <h1>Case #{{ case.case_number }} — {{ case.title }}</h1>
  <p class="sub">Generated {{ generated_at }} · SocBlitz Investigation Report</p>

  <div class="meta-grid">
    <div><b>Status</b>{{ case.status.value }}</div>
    <div><b>Priority</b>{{ case.priority.value }}</div>
    <div><b>TLP</b>{{ case.tlp }}</div>
    <div><b>PAP</b>{{ case.pap }}</div>
    <div><b>Assignee</b>{{ assignee_name or 'Unassigned' }}</div>
    <div><b>Opened</b>{{ case.created_at }}</div>
    {% if case.closed_at %}<div><b>Closed</b>{{ case.closed_at }}</div>{% endif %}
  </div>

  <h2>Summary</h2>
  {% if case.summary or case.description %}<p>{{ case.summary or case.description }}</p>{% else %}<p class="empty">No summary provided.</p>{% endif %}

  <h2>MITRE ATT&amp;CK techniques observed</h2>
  {% if mitre_techniques %}
    <p>{% for t in mitre_techniques %}<span class="badge">{{ t }}</span>{% endfor %}</p>
  {% else %}<p class="empty">No techniques tagged.</p>{% endif %}

  <h2>Investigation timeline</h2>
  {% if timeline %}
  <table><thead><tr><th>Time</th><th>Actor</th><th>Event</th><th>ATT&amp;CK</th></tr></thead><tbody>
    {% for e in timeline %}<tr><td>{{ e.timestamp }}</td><td>{{ e.actor }}</td><td>{{ e.description }}</td><td>{{ (e.mitre_techniques or [])|join(', ') }}</td></tr>{% endfor %}
  </tbody></table>
  {% else %}<p class="empty">No events logged.</p>{% endif %}

  <h2>Assets</h2>
  {% if assets %}
  <table><thead><tr><th>Name</th><th>Type</th><th>IP</th><th>Status</th><th>Description</th></tr></thead><tbody>
    {% for a in assets %}<tr><td>{{ a.name }}</td><td>{{ a.asset_type.value }}</td><td>{{ a.ip_address or '—' }}</td><td>{{ a.compromise_status.value }}</td><td>{{ a.description or '' }}</td></tr>{% endfor %}
  </tbody></table>
  {% else %}<p class="empty">No assets tracked.</p>{% endif %}

  <h2>Indicators of compromise</h2>
  {% if observables %}
  <table><thead><tr><th>Type</th><th>Value</th><th>TLP</th><th>Asset</th></tr></thead><tbody>
    {% for o in observables %}<tr><td>{{ o.obs_type }}</td><td>{{ o.value }}</td><td>{{ o.tlp }}</td><td>{{ o.asset_name or '—' }}</td></tr>{% endfor %}
  </tbody></table>
  {% else %}<p class="empty">No IOCs recorded.</p>{% endif %}

  <h2>Evidence</h2>
  {% if evidence %}
  <table><thead><tr><th>Filename</th><th>SHA256</th><th>Acquired by</th><th>Notes</th></tr></thead><tbody>
    {% for ev in evidence %}<tr><td>{{ ev.filename }}</td><td>{{ ev.hash_sha256 or '—' }}</td><td>{{ ev.acquired_by_name or '—' }}</td><td>{{ ev.custody_notes or '' }}</td></tr>{% endfor %}
  </tbody></table>
  {% else %}<p class="empty">No evidence registered.</p>{% endif %}

  <h2>Tasks</h2>
  {% if tasks %}
  <table><thead><tr><th>Task</th><th>Status</th><th>Assignee</th><th>Due</th></tr></thead><tbody>
    {% for t in tasks %}<tr><td>{{ t.title }}</td><td>{{ t.status.value }}</td><td>{{ t.assignee_name or '—' }}</td><td>{{ t.due_date or '—' }}</td></tr>{% endfor %}
  </tbody></table>
  {% else %}<p class="empty">No tasks.</p>{% endif %}

  <h2>Notes</h2>
  {% if notes %}
    {% for n in notes %}<h3 style="font-size:14px;margin-bottom:2px">{{ n.title }}</h3><p class="sub" style="margin-top:0">{{ n.author_name or 'Analyst' }} · {{ n.created_at }}</p><p>{{ n.content }}</p>{% endfor %}
  {% else %}<p class="empty">No notes recorded.</p>{% endif %}
</body></html>"""


@case_router.get("/{case_id}/report")
async def get_case_report(case_id: str, db: DbDep, current_user: CurrentUser):
    result = await db.execute(select(Case).where(Case.id == case_id))
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    assignee_name = None
    if case.assigned_to:
        r = await db.execute(select(User.full_name).where(User.id == case.assigned_to))
        assignee_name = r.scalar_one_or_none()

    obs_rows = (await db.execute(
        select(Observable, CaseAsset.name).outerjoin(CaseAsset, CaseAsset.id == Observable.asset_id)
        .where(Observable.case_id == case_id).order_by(Observable.created_at)
    )).all()
    observables = [{**_row_dict(o), "asset_name": name} for o, name in obs_rows]

    assets = (await db.execute(select(CaseAsset).where(CaseAsset.case_id == case_id).order_by(CaseAsset.created_at))).scalars().all()

    ev_rows = (await db.execute(
        select(CaseEvidence, User.full_name).outerjoin(User, User.id == CaseEvidence.acquired_by)
        .where(CaseEvidence.case_id == case_id).order_by(CaseEvidence.created_at)
    )).all()
    evidence = [{**_row_dict(e), "acquired_by_name": name} for e, name in ev_rows]

    task_rows = (await db.execute(
        select(CaseTask, User.full_name).outerjoin(User, User.id == CaseTask.assigned_to)
        .where(CaseTask.case_id == case_id).order_by(CaseTask.created_at)
    )).all()
    tasks = [{**_row_dict(t), "assignee_name": name} for t, name in task_rows]

    note_rows = (await db.execute(
        select(CaseNote, User.full_name).outerjoin(User, User.id == CaseNote.author_id)
        .where(CaseNote.case_id == case_id).order_by(CaseNote.created_at)
    )).all()
    notes = [{**_row_dict(n), "author_name": name} for n, name in note_rows]

    timeline = sorted(case.timeline or [], key=lambda e: e.get("timestamp", ""))
    mitre_techniques = sorted({t for e in timeline for t in (e.get("mitre_techniques") or [])})

    from jinja2 import Template
    html = Template(_REPORT_TEMPLATE).render(
        case=case,
        assignee_name=assignee_name,
        timeline=timeline,
        mitre_techniques=mitre_techniques,
        observables=observables,
        assets=assets,
        evidence=evidence,
        tasks=tasks,
        notes=notes,
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )

    filename = f"case-{case.case_number}-report.html"
    return Response(
        content=html,
        media_type="text/html",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


api_router.include_router(case_router)


# ─────────────────────────────────────────────────────────────────────────────
# MITRE ATT&CK reference
# ─────────────────────────────────────────────────────────────────────────────

mitre_router = APIRouter(prefix="/mitre", tags=["mitre"])

MITRE_TECHNIQUES = [
    {"id": "T1078", "name": "Valid Accounts", "tactic": "Initial Access"},
    {"id": "T1566", "name": "Phishing", "tactic": "Initial Access"},
    {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    {"id": "T1133", "name": "External Remote Services", "tactic": "Initial Access"},
    {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
    {"id": "T1204", "name": "User Execution", "tactic": "Execution"},
    {"id": "T1053", "name": "Scheduled Task/Job", "tactic": "Execution"},
    {"id": "T1569", "name": "System Services", "tactic": "Execution"},
    {"id": "T1547", "name": "Boot or Logon Autostart Execution", "tactic": "Persistence"},
    {"id": "T1136", "name": "Create Account", "tactic": "Persistence"},
    {"id": "T1098", "name": "Account Manipulation", "tactic": "Persistence"},
    {"id": "T1543", "name": "Create or Modify System Process", "tactic": "Persistence"},
    {"id": "T1055", "name": "Process Injection", "tactic": "Privilege Escalation"},
    {"id": "T1548", "name": "Abuse Elevation Control Mechanism", "tactic": "Privilege Escalation"},
    {"id": "T1068", "name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation"},
    {"id": "T1027", "name": "Obfuscated Files or Information", "tactic": "Defense Evasion"},
    {"id": "T1070", "name": "Indicator Removal", "tactic": "Defense Evasion"},
    {"id": "T1562", "name": "Impair Defenses", "tactic": "Defense Evasion"},
    {"id": "T1112", "name": "Modify Registry", "tactic": "Defense Evasion"},
    {"id": "T1003", "name": "OS Credential Dumping", "tactic": "Credential Access"},
    {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
    {"id": "T1552", "name": "Unsecured Credentials", "tactic": "Credential Access"},
    {"id": "T1087", "name": "Account Discovery", "tactic": "Discovery"},
    {"id": "T1082", "name": "System Information Discovery", "tactic": "Discovery"},
    {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
    {"id": "T1018", "name": "Remote System Discovery", "tactic": "Discovery"},
    {"id": "T1021", "name": "Remote Services", "tactic": "Lateral Movement"},
    {"id": "T1570", "name": "Lateral Tool Transfer", "tactic": "Lateral Movement"},
    {"id": "T1005", "name": "Data from Local System", "tactic": "Collection"},
    {"id": "T1114", "name": "Email Collection", "tactic": "Collection"},
    {"id": "T1560", "name": "Archive Collected Data", "tactic": "Collection"},
    {"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control"},
    {"id": "T1105", "name": "Ingress Tool Transfer", "tactic": "Command and Control"},
    {"id": "T1573", "name": "Encrypted Channel", "tactic": "Command and Control"},
    {"id": "T1090", "name": "Proxy", "tactic": "Command and Control"},
    {"id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
    {"id": "T1567", "name": "Exfiltration Over Web Service", "tactic": "Exfiltration"},
    {"id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact"},
    {"id": "T1490", "name": "Inhibit System Recovery", "tactic": "Impact"},
    {"id": "T1489", "name": "Service Stop", "tactic": "Impact"},
    {"id": "T1498", "name": "Network Denial of Service", "tactic": "Impact"},
]


@mitre_router.get("/techniques")
async def list_mitre_techniques(current_user: CurrentUser):
    return MITRE_TECHNIQUES


api_router.include_router(mitre_router)


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
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
):
    q = select(Agent)
    if status_filter:
        q = q.where(Agent.status == status_filter)
    if tenant_id:
        q = q.where(Agent.tenant_id == tenant_id)
    elif current_user.role == UserRole.CUSTOMER_USER and current_user.tenant_id:
        q = q.where(Agent.tenant_id == current_user.tenant_id)

    result = await db.execute(q.order_by(Agent.name).offset(skip).limit(limit))
    return result.scalars().all()


@agent_router.get("/stats")
async def agent_stats(db: DbDep, current_user: CurrentUser, tenant_id: str | None = None):
    """Fleet-wide counts by status — for dashboards, so they never pull the full agent list."""
    q = select(Agent.status, func.count()).group_by(Agent.status)
    if tenant_id:
        q = q.where(Agent.tenant_id == tenant_id)
    elif current_user.role == UserRole.CUSTOMER_USER and current_user.tenant_id:
        q = q.where(Agent.tenant_id == current_user.tenant_id)

    result = await db.execute(q)
    by_status = {status.value: count for status, count in result.all()}
    return {"total": sum(by_status.values()), "by_status": by_status}


@agent_router.post("/sync")
async def sync_agents(db: DbDep, current_user: CurrentUser):
    """Trigger agent sync from Wazuh."""
    try:
        from app.workers.celery_app import celery_app
        task = celery_app.send_task("app.workers.tasks.sync_wazuh_agents")
        return {"status": "queued", "task_id": task.id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@agent_router.delete("/{agent_db_id}", dependencies=[Depends(require_admin())])
async def delete_agent(agent_db_id: str, db: DbDep, current_user: CurrentUser):
    """Deregister an agent from the Wazuh manager and drop its local record.

    Uses the manager REST API — the equivalent of `/var/ossec/bin/manage_agents -r`.
    """
    import httpx
    import uuid as _uuid
    from app.connectors.registry import WazuhManagerClient

    try:
        _uuid.UUID(str(agent_db_id))
    except ValueError:
        raise HTTPException(status_code=404, detail="Agent not found")

    result = await db.execute(select(Agent).where(Agent.id == agent_db_id))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    if str(agent.agent_id) in ("000", "0"):
        raise HTTPException(status_code=400, detail="Cannot remove the manager itself (agent 000)")

    try:
        await WazuhManagerClient().delete_agent(str(agent.agent_id))
    except httpx.HTTPStatusError as e:
        detail = e.response.text if e.response is not None else str(e)
        raise HTTPException(status_code=502, detail=f"Manager rejected agent removal: {detail}")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Wazuh manager unavailable: {e}")

    await db.delete(agent)
    await db.commit()
    return {"status": "removed", "agent_id": agent.agent_id, "name": agent.name}


@agent_router.get("/{agent_db_id}/vulnerabilities")
async def get_agent_vulnerabilities(agent_db_id: str, db: DbDep, current_user: CurrentUser):
    """Pull vulnerabilities for a specific agent from Wazuh indexer."""
    result = await db.execute(select(Agent).where(Agent.id == agent_db_id))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    from app.connectors.registry import WazuhIndexerClient
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
# Forensics (Velociraptor)
# ─────────────────────────────────────────────────────────────────────────────

forensics_router = APIRouter(prefix="/forensics", tags=["forensics"])


@forensics_router.get("/clients")
async def forensics_clients(current_user: CurrentUser, limit: int = 200):
    """List endpoints enrolled in Velociraptor."""
    from app.connectors.registry import VelociraptorClient
    return await VelociraptorClient().list_clients(limit=limit)


@forensics_router.get("/clients/{client_id}/flows")
async def forensics_flows(client_id: str, current_user: CurrentUser, limit: int = 30):
    """List recent collection flows for one endpoint."""
    from app.connectors.registry import VelociraptorClient
    return await VelociraptorClient().list_flows(client_id, limit=limit)


@forensics_router.get("/clients/{client_id}/flows/{flow_id}/results")
async def forensics_flow_results(
    client_id: str, flow_id: str, artifact: str, current_user: CurrentUser,
    start: int = 0, rows: int = 100,
):
    """Fetch collected rows for one artifact of a finished flow."""
    from app.connectors.registry import VelociraptorClient
    try:
        return await VelociraptorClient().get_flow_results(
            client_id, flow_id, artifact, start_row=start, rows=min(rows, 500),
        )
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Velociraptor error: {e}")


@forensics_router.post("/collect", status_code=201)
async def forensics_collect(body: dict, current_user: CurrentUser):
    """Start an artifact collection on an endpoint."""
    client_id = body.get("client_id")
    artifact = body.get("artifact")
    if not client_id or not artifact:
        raise HTTPException(status_code=422, detail="client_id and artifact are required")

    from app.connectors.registry import VelociraptorClient
    try:
        return await VelociraptorClient().run_artifact(client_id, artifact, body.get("parameters"))
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Velociraptor error: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# Unified agent deployment (SocBlitz Agent = Wazuh agent + Velociraptor client)
#
# The install.sh / install.ps1 / config / binary routes are fetched by endpoints
# during enrolment, before they have any identity — so they are gated by a shared
# AGENT_ENROLL_KEY instead of a JWT. /command (used by the UI) requires login.
# ─────────────────────────────────────────────────────────────────────────────

deploy_router = APIRouter(prefix="/agent-deploy", tags=["agent-deploy"])

_DEPLOY_DIR = Path("/app/deployment")
_VELO_BINARY = Path("/velociraptor-data/velociraptor")


def _check_enroll_key(key: str) -> None:
    if not settings.AGENT_ENROLL_KEY:
        raise HTTPException(status_code=403, detail="AGENT_ENROLL_KEY is not configured on the server")
    if not py_secrets.compare_digest(key, settings.AGENT_ENROLL_KEY):
        raise HTTPException(status_code=403, detail="invalid enrollment key")


def _server_host(request: Request) -> str:
    if settings.AGENT_PUBLIC_HOST:
        return settings.AGENT_PUBLIC_HOST
    return (request.headers.get("host") or "").split(":")[0] or "localhost"


def _render_installer(name: str, request: Request) -> str:
    tpl = (_DEPLOY_DIR / name).read_text()
    return (tpl
            .replace("__SOCBLITZ_SERVER__", _server_host(request))
            .replace("__ENROLL_KEY__", settings.AGENT_ENROLL_KEY))


@deploy_router.get("/install.sh", response_class=PlainTextResponse)
async def agent_installer_linux(request: Request, key: str = ""):
    """Linux one-command installer for the unified SocBlitz Agent."""
    _check_enroll_key(key)
    return _render_installer("socblitz-agent-install.sh", request)


@deploy_router.get("/install.ps1", response_class=PlainTextResponse)
async def agent_installer_windows(request: Request, key: str = ""):
    """Windows one-command installer for the unified SocBlitz Agent."""
    _check_enroll_key(key)
    return _render_installer("socblitz-agent-install.ps1", request)


@deploy_router.get("/install-macos.sh", response_class=PlainTextResponse)
async def agent_installer_macos(request: Request, key: str = ""):
    """macOS one-command installer for the SocBlitz Agent (Wazuh SIEM)."""
    _check_enroll_key(key)
    return _render_installer("socblitz-agent-install-macos.sh", request)


@deploy_router.get("/velociraptor.config.yaml", response_class=PlainTextResponse)
async def agent_velociraptor_config(request: Request, key: str = ""):
    """Velociraptor client config, rewritten to point at this server's enrolment port."""
    _check_enroll_key(key)
    cfg = (_DEPLOY_DIR / "velociraptor-client.config.yaml").read_text()
    return cfg.replace("https://velociraptor:8000/", f"https://{_server_host(request)}:8010/")


@deploy_router.get("/velociraptor-linux-amd64")
async def agent_velociraptor_binary(key: str = ""):
    """Velociraptor Linux binary, served from the server's own volume (version-matched)."""
    _check_enroll_key(key)
    if not _VELO_BINARY.exists():
        raise HTTPException(status_code=503, detail="velociraptor binary volume not mounted")
    return FileResponse(_VELO_BINARY, media_type="application/octet-stream", filename="velociraptor")


@deploy_router.get("/command")
async def agent_deploy_command(request: Request, current_user: CurrentUser):
    """Copy-paste enrolment one-liners for the UI."""
    host = _server_host(request)
    if not settings.AGENT_ENROLL_KEY:
        return {"configured": False, "linux": "", "windows": "",
                "hint": "Set AGENT_ENROLL_KEY in .env and restart the backend."}
    base = f"http://{host}:5000/api/v1/agent-deploy"
    k = settings.AGENT_ENROLL_KEY
    return {
        "configured": True,
        "linux": f'curl -fsSk "{base}/install.sh?key={k}" | sudo sh',
        "macos": f'curl -fsSk "{base}/install-macos.sh?key={k}" | sudo sh',
        "windows": f'iwr -UseBasicParsing "{base}/install.ps1?key={k}" | select -Expand Content | iex',
    }


api_router.include_router(deploy_router)


api_router.include_router(forensics_router)


# ─────────────────────────────────────────────────────────────────────────────
# SOAR Workflows (integrated from SOAR engine)
# ─────────────────────────────────────────────────────────────────────────────

soar_router = APIRouter(prefix="/soar", tags=["soar"])


class WorkflowCreate(BaseModel):
    name: str
    description: str | None = None
    trigger_type: WorkflowTrigger = WorkflowTrigger.MANUAL
    trigger_config: dict = {}
    nodes: list[dict] = []
    edges: list[dict] = []


class WorkflowOut(BaseModel):
    id: str
    name: str
    description: str | None
    trigger_type: WorkflowTrigger
    trigger_config: dict | None
    nodes: list
    edges: list
    is_active: bool
    run_count: int
    last_run_at: datetime | None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class WorkflowRunOut(BaseModel):
    id: str
    workflow_id: str
    status: TaskStatus
    trigger_data: dict | None
    node_results: list | None
    error: str | None
    started_at: datetime
    finished_at: datetime | None

    class Config:
        from_attributes = True


@soar_router.get("/node-types")
async def list_node_types(current_user: CurrentUser):
    from app.services.workflow_engine import NODE_CATALOG
    return {"node_types": NODE_CATALOG}


@soar_router.get("/workflows", response_model=list[WorkflowOut])
async def list_workflows(db: DbDep, current_user: CurrentUser):
    q = select(Workflow).order_by(desc(Workflow.created_at))
    if current_user.role == UserRole.CUSTOMER_USER and current_user.tenant_id:
        q = q.where(Workflow.tenant_id == current_user.tenant_id)
    result = await db.execute(q)
    return result.scalars().all()


@soar_router.post("/workflows", response_model=WorkflowOut, status_code=201)
async def create_workflow(payload: WorkflowCreate, db: DbDep, current_user: CurrentUser):
    workflow = Workflow(
        **payload.model_dump(),
        tenant_id=current_user.tenant_id,
        created_by=current_user.id,
    )
    db.add(workflow)
    await db.commit()
    await db.refresh(workflow)
    return workflow


@soar_router.get("/workflows/{wf_id}", response_model=WorkflowOut)
async def get_workflow(wf_id: str, db: DbDep, current_user: CurrentUser):
    result = await db.execute(select(Workflow).where(Workflow.id == wf_id))
    workflow = result.scalar_one_or_none()
    if not workflow:
        raise HTTPException(status_code=404, detail="Workflow not found")
    return workflow


@soar_router.patch("/workflows/{wf_id}", response_model=WorkflowOut)
async def update_workflow(wf_id: str, payload: dict, db: DbDep, current_user: CurrentUser):
    result = await db.execute(select(Workflow).where(Workflow.id == wf_id))
    workflow = result.scalar_one_or_none()
    if not workflow:
        raise HTTPException(status_code=404, detail="Workflow not found")

    allowed = {"name", "description", "trigger_type", "trigger_config", "nodes", "edges", "is_active"}
    for k, v in payload.items():
        if k in allowed:
            setattr(workflow, k, v)

    await db.commit()
    await db.refresh(workflow)
    return workflow


@soar_router.delete("/workflows/{wf_id}", status_code=204)
async def delete_workflow(wf_id: str, db: DbDep, current_user: CurrentUser):
    result = await db.execute(select(Workflow).where(Workflow.id == wf_id))
    workflow = result.scalar_one_or_none()
    if not workflow:
        raise HTTPException(status_code=404, detail="Workflow not found")
    await db.delete(workflow)
    await db.commit()
    return Response(status_code=204)


@soar_router.post("/workflows/{wf_id}/run")
async def run_workflow(wf_id: str, body: dict, db: DbDep, current_user: CurrentUser):
    result = await db.execute(select(Workflow).where(Workflow.id == wf_id))
    workflow = result.scalar_one_or_none()
    if not workflow:
        raise HTTPException(status_code=404, detail="Workflow not found")

    run = WorkflowRun(workflow_id=wf_id, status=TaskStatus.PENDING, trigger_data=body or {})
    db.add(run)
    await db.commit()
    await db.refresh(run)

    try:
        from app.workers.celery_app import celery_app
        celery_app.send_task("app.workers.tasks.run_workflow", args=[wf_id, run.id, body or {}])
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    return {"status": "queued", "run_id": run.id}


@soar_router.get("/workflows/{wf_id}/runs", response_model=list[WorkflowRunOut])
async def list_workflow_runs(wf_id: str, db: DbDep, current_user: CurrentUser, limit: int = 20):
    result = await db.execute(
        select(WorkflowRun).where(WorkflowRun.workflow_id == wf_id)
        .order_by(desc(WorkflowRun.started_at)).limit(limit)
    )
    return result.scalars().all()


@soar_router.get("/runs/{run_id}", response_model=WorkflowRunOut)
async def get_workflow_run(run_id: str, db: DbDep, current_user: CurrentUser):
    result = await db.execute(select(WorkflowRun).where(WorkflowRun.id == run_id))
    run = result.scalar_one_or_none()
    if not run:
        raise HTTPException(status_code=404, detail="Workflow run not found")
    return run


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
