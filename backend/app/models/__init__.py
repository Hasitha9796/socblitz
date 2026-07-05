"""
SocBlitz database models — all tables in one file for clarity.
Each model maps directly to a PostgreSQL table.
"""
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from sqlalchemy import (
    Boolean, DateTime, ForeignKey, Integer, String, Text, JSON,
    Enum as SAEnum, UniqueConstraint, Index
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_uuid() -> str:
    return str(uuid.uuid4())


class Base(DeclarativeBase):
    pass


# ─────────────────────────────────────────────────────────────────────────────
# Enums
# ─────────────────────────────────────────────────────────────────────────────

class UserRole(str, Enum):
    ADMIN         = "admin"
    ANALYST       = "analyst"
    CUSTOMER_USER = "customer_user"
    VIEWER        = "viewer"


class AlertSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


class AlertStatus(str, Enum):
    NEW        = "new"
    IN_TRIAGE  = "in_triage"
    ESCALATED  = "escalated"
    RESOLVED   = "resolved"
    FALSE_POS  = "false_positive"


class CaseStatus(str, Enum):
    OPEN       = "open"
    IN_PROG    = "in_progress"
    PENDING    = "pending"
    RESOLVED   = "resolved"
    CLOSED     = "closed"


class CasePriority(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"


class ConnectorType(str, Enum):
    WAZUH_MANAGER    = "wazuh_manager"
    WAZUH_INDEXER    = "wazuh_indexer"
    VELOCIRAPTOR     = "velociraptor"
    SHUFFLE          = "shuffle"
    THEHIVE          = "thehive"
    MISP             = "misp"
    VIRUSTOTAL       = "virustotal"
    CROWDSTRIKE      = "crowdstrike"
    SENTINELONE      = "sentinelone"
    DFIR_IRIS        = "dfir_iris"


class AgentOS(str, Enum):
    WINDOWS = "windows"
    LINUX   = "linux"
    MACOS   = "macos"
    UNKNOWN = "unknown"


class AgentStatus(str, Enum):
    ACTIVE       = "active"
    DISCONNECTED = "disconnected"
    PENDING      = "pending"
    NEVER_CONN   = "never_connected"


class TaskStatus(str, Enum):
    PENDING  = "pending"
    RUNNING  = "running"
    SUCCESS  = "success"
    FAILED   = "failed"


class WorkflowTrigger(str, Enum):
    MANUAL   = "manual"
    ALERT    = "alert"
    SCHEDULE = "schedule"
    WEBHOOK  = "webhook"


class CaseTaskStatus(str, Enum):
    TODO        = "to_do"
    IN_PROGRESS = "in_progress"
    DONE        = "done"


class AssetType(str, Enum):
    SERVER      = "server"
    WORKSTATION = "workstation"
    LAPTOP      = "laptop"
    MOBILE      = "mobile"
    NETWORK     = "network"
    CLOUD       = "cloud"
    OTHER       = "other"


class AssetCompromiseStatus(str, Enum):
    COMPROMISED  = "compromised"
    INVESTIGATING= "investigating"
    CLEAN        = "clean"
    UNKNOWN      = "unknown"


# ─────────────────────────────────────────────────────────────────────────────
# Tenant (multi-tenancy)
# ─────────────────────────────────────────────────────────────────────────────

class Tenant(Base):
    __tablename__ = "tenants"

    id:           Mapped[str]  = mapped_column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    code:         Mapped[str]  = mapped_column(String(32), unique=True, nullable=False, index=True)
    name:         Mapped[str]  = mapped_column(String(128), nullable=False)
    description:  Mapped[str | None] = mapped_column(Text)
    is_active:    Mapped[bool] = mapped_column(Boolean, default=True)
    meta:         Mapped[dict | None] = mapped_column(JSONB)
    created_at:   Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at:   Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    users:    Mapped[list["User"]]   = relationship("User",    back_populates="tenant")
    alerts:   Mapped[list["Alert"]]  = relationship("Alert",   back_populates="tenant")
    cases:    Mapped[list["Case"]]   = relationship("Case",    back_populates="tenant")
    agents:   Mapped[list["Agent"]]  = relationship("Agent",   back_populates="tenant")


# ─────────────────────────────────────────────────────────────────────────────
# User
# ─────────────────────────────────────────────────────────────────────────────

class User(Base):
    __tablename__ = "users"

    id:             Mapped[str]  = mapped_column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    email:          Mapped[str]  = mapped_column(String(256), unique=True, nullable=False, index=True)
    hashed_password:Mapped[str]  = mapped_column(String(256), nullable=False)
    full_name:      Mapped[str | None] = mapped_column(String(128))
    role:           Mapped[UserRole] = mapped_column(SAEnum(UserRole), default=UserRole.ANALYST)
    tenant_id:      Mapped[str | None] = mapped_column(ForeignKey("tenants.id"), index=True)
    is_active:      Mapped[bool] = mapped_column(Boolean, default=True)
    is_verified:    Mapped[bool] = mapped_column(Boolean, default=False)
    last_login:     Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    preferences:    Mapped[dict | None] = mapped_column(JSONB)
    created_at:     Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at:     Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    tenant: Mapped["Tenant"] = relationship("Tenant", back_populates="users")
    cases:  Mapped[list["Case"]] = relationship("Case", back_populates="assigned_to_user",
                                         foreign_keys="Case.assigned_to")


# ─────────────────────────────────────────────────────────────────────────────
# Connector
# ─────────────────────────────────────────────────────────────────────────────

class Connector(Base):
    __tablename__ = "connectors"

    id:           Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    connector_type: Mapped[ConnectorType] = mapped_column(SAEnum(ConnectorType), nullable=False, unique=True)
    url:          Mapped[str | None] = mapped_column(String(512))
    username:     Mapped[str | None] = mapped_column(String(256))
    password:     Mapped[str | None] = mapped_column(String(512))    # encrypted at rest
    api_key:      Mapped[str | None] = mapped_column(String(512))    # encrypted at rest
    extra_config: Mapped[dict | None] = mapped_column(JSONB)
    is_active:    Mapped[bool] = mapped_column(Boolean, default=True)
    verified:     Mapped[bool] = mapped_column(Boolean, default=False)
    last_verified:Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at:   Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at:   Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


# ─────────────────────────────────────────────────────────────────────────────
# Custom Dashboard (AI-agent-built)
# ─────────────────────────────────────────────────────────────────────────────

class CustomDashboard(Base):
    __tablename__ = "custom_dashboards"

    id:          Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    tenant_id:   Mapped[str | None] = mapped_column(ForeignKey("tenants.id"), index=True)
    user_id:     Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    name:        Mapped[str] = mapped_column(String(256), default="My dashboard")
    widgets:     Mapped[list] = mapped_column(JSONB, default=list)   # [{id, generator, title, params}]
    created_at:  Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at:  Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


# ─────────────────────────────────────────────────────────────────────────────
# Alert
# ─────────────────────────────────────────────────────────────────────────────

class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (
        Index("ix_alerts_tenant_status", "tenant_id", "status"),
        Index("ix_alerts_tenant_severity", "tenant_id", "severity"),
        Index("ix_alerts_source_id", "source_id"),
    )

    id:          Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    tenant_id:   Mapped[str | None] = mapped_column(ForeignKey("tenants.id"), index=True)
    source:      Mapped[str] = mapped_column(String(64), nullable=False)    # wazuh | misp | etc.
    source_id:   Mapped[str | None] = mapped_column(String(256))           # original alert ID
    rule_id:     Mapped[str | None] = mapped_column(String(64))
    rule_name:   Mapped[str | None] = mapped_column(String(256))
    level:       Mapped[int | None] = mapped_column(Integer)               # Wazuh rule level
    description: Mapped[str | None] = mapped_column(Text)
    severity:    Mapped[AlertSeverity] = mapped_column(SAEnum(AlertSeverity), default=AlertSeverity.MEDIUM, index=True)
    status:      Mapped[AlertStatus]  = mapped_column(SAEnum(AlertStatus),  default=AlertStatus.NEW,     index=True)
    agent_name:  Mapped[str | None] = mapped_column(String(256))
    agent_ip:    Mapped[str | None] = mapped_column(String(64))
    agent_id:    Mapped[str | None] = mapped_column(String(64))
    src_ip:      Mapped[str | None] = mapped_column(String(64))
    dst_ip:      Mapped[str | None] = mapped_column(String(64))
    username:    Mapped[str | None] = mapped_column(String(256))
    mitre_id:    Mapped[str | None] = mapped_column(String(32))
    mitre_tactic:Mapped[str | None] = mapped_column(String(128))
    raw_data:    Mapped[dict | None] = mapped_column(JSONB)
    iocs:        Mapped[dict | None] = mapped_column(JSONB)              # extracted IOCs
    enrichment:  Mapped[dict | None] = mapped_column(JSONB)              # TI enrichment results
    tags:        Mapped[list | None] = mapped_column(JSONB)
    case_id:     Mapped[str | None] = mapped_column(ForeignKey("cases.id"), index=True)
    triaged_by:  Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    triaged_at:  Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    alert_time:  Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    created_at:  Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at:  Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    tenant: Mapped["Tenant"] = relationship("Tenant", back_populates="alerts")
    case:   Mapped["Case"]   = relationship("Case",   back_populates="alerts")


# ─────────────────────────────────────────────────────────────────────────────
# Case
# ─────────────────────────────────────────────────────────────────────────────

class Case(Base):
    __tablename__ = "cases"
    __table_args__ = (
        Index("ix_cases_tenant_status", "tenant_id", "status"),
    )

    id:          Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    case_number: Mapped[int] = mapped_column(Integer, nullable=False)
    tenant_id:   Mapped[str | None] = mapped_column(ForeignKey("tenants.id"), index=True)
    title:       Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    status:      Mapped[CaseStatus]   = mapped_column(SAEnum(CaseStatus),   default=CaseStatus.OPEN,   index=True)
    priority:    Mapped[CasePriority] = mapped_column(SAEnum(CasePriority), default=CasePriority.MEDIUM)
    tags:        Mapped[list | None]  = mapped_column(JSONB)
    assigned_to: Mapped[str | None]   = mapped_column(ForeignKey("users.id"))
    created_by:  Mapped[str | None]   = mapped_column(ForeignKey("users.id"))
    closed_at:   Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    tlp:         Mapped[str] = mapped_column(String(16), default="AMBER")  # TLP classification
    pap:         Mapped[str] = mapped_column(String(16), default="AMBER")  # PAP classification
    summary:     Mapped[str | None] = mapped_column(Text)                  # AI-generated summary
    timeline:    Mapped[list | None] = mapped_column(JSONB)                # investigation timeline entries
    created_at:  Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at:  Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    tenant:           Mapped["Tenant"] = relationship("Tenant", back_populates="cases")
    assigned_to_user: Mapped["User"]   = relationship("User",   back_populates="cases", foreign_keys=[assigned_to])
    alerts:           Mapped[list["Alert"]] = relationship("Alert", back_populates="case")
    comments:         Mapped[list["CaseComment"]] = relationship("CaseComment", back_populates="case")
    observables:      Mapped[list["Observable"]] = relationship("Observable", back_populates="case")
    tasks:            Mapped[list["CaseTask"]] = relationship("CaseTask", back_populates="case")
    assets:           Mapped[list["CaseAsset"]] = relationship("CaseAsset", back_populates="case")
    evidence:         Mapped[list["CaseEvidence"]] = relationship("CaseEvidence", back_populates="case")
    notes:            Mapped[list["CaseNote"]] = relationship("CaseNote", back_populates="case")


class CaseComment(Base):
    __tablename__ = "case_comments"

    id:         Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    case_id:    Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    author_id:  Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    content:    Mapped[str] = mapped_column(Text, nullable=False)
    is_internal:Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    case: Mapped["Case"] = relationship("Case", back_populates="comments")


class Observable(Base):
    """IOC observables attached to a case."""
    __tablename__ = "observables"

    id:          Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    case_id:     Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    obs_type:    Mapped[str] = mapped_column(String(64), nullable=False)  # ip, domain, hash, url, etc.
    value:       Mapped[str] = mapped_column(String(1024), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    is_ioc:      Mapped[bool] = mapped_column(Boolean, default=False)
    tlp:         Mapped[str] = mapped_column(String(16), default="AMBER")
    enrichment:  Mapped[dict | None] = mapped_column(JSONB)
    asset_id:    Mapped[str | None] = mapped_column(ForeignKey("case_assets.id", ondelete="SET NULL"), index=True)
    created_at:  Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    case: Mapped["Case"] = relationship("Case", back_populates="observables")


class CaseTask(Base):
    """Assignable checklist item on a case (IRIS-style task board)."""
    __tablename__ = "case_tasks"

    id:          Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    case_id:     Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    title:       Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    status:      Mapped[CaseTaskStatus] = mapped_column(SAEnum(CaseTaskStatus), default=CaseTaskStatus.TODO, index=True)
    assigned_to: Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    created_by:  Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    due_date:    Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at:  Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at:  Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    case: Mapped["Case"] = relationship("Case", back_populates="tasks")


class CaseAsset(Base):
    """Compromised / analyzed host or system tracked on a case (IRIS-style asset)."""
    __tablename__ = "case_assets"

    id:                Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    case_id:           Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    name:              Mapped[str] = mapped_column(String(255), nullable=False)
    asset_type:        Mapped[AssetType] = mapped_column(SAEnum(AssetType), default=AssetType.OTHER)
    ip_address:        Mapped[str | None] = mapped_column(String(64))
    description:       Mapped[str | None] = mapped_column(Text)
    compromise_status: Mapped[AssetCompromiseStatus] = mapped_column(SAEnum(AssetCompromiseStatus), default=AssetCompromiseStatus.UNKNOWN, index=True)
    created_by:        Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    created_at:        Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at:        Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    case:       Mapped["Case"] = relationship("Case", back_populates="assets")
    observables:Mapped[list["Observable"]] = relationship("Observable")


class CaseEvidence(Base):
    """Exhibit / evidence item tracked on a case (IRIS-style evidence register)."""
    __tablename__ = "case_evidence"

    id:            Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    case_id:       Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    filename:      Mapped[str] = mapped_column(String(512), nullable=False)
    description:   Mapped[str | None] = mapped_column(Text)
    hash_md5:      Mapped[str | None] = mapped_column(String(32))
    hash_sha1:     Mapped[str | None] = mapped_column(String(40))
    hash_sha256:   Mapped[str | None] = mapped_column(String(64))
    size_bytes:    Mapped[int | None] = mapped_column(Integer)
    custody_notes: Mapped[str | None] = mapped_column(Text)
    acquired_by:   Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    acquired_at:   Mapped[datetime]   = mapped_column(DateTime(timezone=True), default=utcnow)
    created_at:    Mapped[datetime]   = mapped_column(DateTime(timezone=True), default=utcnow)

    case: Mapped["Case"] = relationship("Case", back_populates="evidence")


class CaseNote(Base):
    """Structured, titled investigation note (IRIS-style note group)."""
    __tablename__ = "case_notes"

    id:         Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    case_id:    Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    title:      Mapped[str] = mapped_column(String(255), nullable=False)
    content:    Mapped[str] = mapped_column(Text, nullable=False)
    author_id:  Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    case: Mapped["Case"] = relationship("Case", back_populates="notes")


# ─────────────────────────────────────────────────────────────────────────────
# Agent
# ─────────────────────────────────────────────────────────────────────────────

class Agent(Base):
    __tablename__ = "agents"
    __table_args__ = (
        UniqueConstraint("tenant_id", "agent_id", name="uq_agent_per_tenant"),
    )

    id:           Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    tenant_id:    Mapped[str | None] = mapped_column(ForeignKey("tenants.id"), index=True)
    agent_id:     Mapped[str] = mapped_column(String(64), nullable=False)       # Wazuh agent ID
    name:         Mapped[str | None] = mapped_column(String(256))
    hostname:     Mapped[str | None] = mapped_column(String(256))
    ip:           Mapped[str | None] = mapped_column(String(64))
    os:           Mapped[AgentOS]     = mapped_column(SAEnum(AgentOS), default=AgentOS.UNKNOWN)
    os_version:   Mapped[str | None] = mapped_column(String(128))
    status:       Mapped[AgentStatus] = mapped_column(SAEnum(AgentStatus), default=AgentStatus.PENDING)
    version:      Mapped[str | None] = mapped_column(String(32))
    group:        Mapped[str | None] = mapped_column(String(128))
    last_seen:    Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    vuln_count:   Mapped[int] = mapped_column(Integer, default=0)
    critical_vulns:Mapped[int]= mapped_column(Integer, default=0)
    labels:       Mapped[dict | None] = mapped_column(JSONB)
    raw_data:     Mapped[dict | None] = mapped_column(JSONB)
    synced_at:    Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at:   Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at:   Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    tenant: Mapped["Tenant"] = relationship("Tenant", back_populates="agents")


# ─────────────────────────────────────────────────────────────────────────────
# Scheduler / Tasks
# ─────────────────────────────────────────────────────────────────────────────

class ScheduledTask(Base):
    __tablename__ = "scheduled_tasks"

    id:          Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    name:        Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    task_path:   Mapped[str] = mapped_column(String(256), nullable=False)
    schedule:    Mapped[str] = mapped_column(String(128), nullable=False)     # cron expression
    is_enabled:  Mapped[bool] = mapped_column(Boolean, default=True)
    last_run:    Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_status: Mapped[TaskStatus] = mapped_column(SAEnum(TaskStatus), default=TaskStatus.PENDING)
    last_error:  Mapped[str | None] = mapped_column(Text)
    run_count:   Mapped[int] = mapped_column(Integer, default=0)
    created_at:  Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


# ─────────────────────────────────────────────────────────────────────────────
# SOAR Workflows
# ─────────────────────────────────────────────────────────────────────────────

class Workflow(Base):
    """A SOAR automation graph: a set of trigger/action/logic nodes wired by edges."""
    __tablename__ = "workflows"

    id:             Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    tenant_id:      Mapped[str | None] = mapped_column(ForeignKey("tenants.id"), index=True)
    name:           Mapped[str] = mapped_column(String(256), nullable=False)
    description:    Mapped[str | None] = mapped_column(Text)
    trigger_type:   Mapped[WorkflowTrigger] = mapped_column(SAEnum(WorkflowTrigger), default=WorkflowTrigger.MANUAL)
    trigger_config: Mapped[dict | None] = mapped_column(JSONB)             # e.g. {"severity": "critical"}
    nodes:          Mapped[list] = mapped_column(JSONB, default=list)     # React Flow node objects
    edges:          Mapped[list] = mapped_column(JSONB, default=list)     # React Flow edge objects
    is_active:      Mapped[bool] = mapped_column(Boolean, default=True)
    run_count:      Mapped[int] = mapped_column(Integer, default=0)
    last_run_at:    Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by:     Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    created_at:     Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at:     Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    runs: Mapped[list["WorkflowRun"]] = relationship("WorkflowRun", back_populates="workflow")


class WorkflowRun(Base):
    """One execution of a Workflow, with a per-node result log."""
    __tablename__ = "workflow_runs"
    __table_args__ = (
        Index("ix_workflow_runs_workflow_started", "workflow_id", "started_at"),
    )

    id:           Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    workflow_id:  Mapped[str] = mapped_column(ForeignKey("workflows.id", ondelete="CASCADE"), index=True)
    status:       Mapped[TaskStatus] = mapped_column(SAEnum(TaskStatus), default=TaskStatus.PENDING, index=True)
    trigger_data: Mapped[dict | None] = mapped_column(JSONB)
    node_results: Mapped[list | None] = mapped_column(JSONB)              # ordered per-node execution log
    error:        Mapped[str | None] = mapped_column(Text)
    started_at:   Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at:  Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    workflow: Mapped["Workflow"] = relationship("Workflow", back_populates="runs")


# ─────────────────────────────────────────────────────────────────────────────
# Audit Log
# ─────────────────────────────────────────────────────────────────────────────

class AuditLog(Base):
    __tablename__ = "audit_logs"
    __table_args__ = (
        Index("ix_audit_user_ts", "user_id", "timestamp"),
        Index("ix_audit_action", "action"),
    )

    id:        Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True, default=new_uuid)
    user_id:   Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    tenant_id: Mapped[str | None] = mapped_column(String(64))
    action:    Mapped[str] = mapped_column(String(128), nullable=False)
    resource:  Mapped[str | None] = mapped_column(String(256))
    resource_id: Mapped[str | None] = mapped_column(String(64))
    ip_address:Mapped[str | None] = mapped_column(String(64))
    user_agent:Mapped[str | None] = mapped_column(String(512))
    detail:    Mapped[dict | None] = mapped_column(JSONB)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
