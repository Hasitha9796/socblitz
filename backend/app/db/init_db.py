"""Database session and initialization."""
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy import select
from loguru import logger
from app.core.config import settings
from app.models import Base

from sqlalchemy.engine.url import URL as SAUrl
_db_url = SAUrl.create("postgresql+asyncpg", username=settings.POSTGRES_USER, password=settings.POSTGRES_PASSWORD, host=settings.POSTGRES_HOST, port=settings.POSTGRES_PORT, database=settings.POSTGRES_DB)
engine = create_async_engine(
    _db_url,
    echo=settings.APP_ENV == "development",
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20,
    connect_args={"ssl": False},
)

AsyncSessionLocal = async_sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False
)


async def init_db() -> None:
    """Create tables and bootstrap admin user."""
    from sqlalchemy.exc import ProgrammingError, IntegrityError
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    except (ProgrammingError, IntegrityError) as e:
        if "already exists" in str(e):
            logger.warning("DB schema already exists — skipping create_all")
        else:
            raise

    # create_all only creates missing tables — it never adds columns to
    # existing ones, so evolve the users table for MFA explicitly.
    from sqlalchemy import text
    async with engine.begin() as conn:
        await conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE"))
        await conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret VARCHAR(64)"))
        await conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_backup_codes JSONB"))

    async with AsyncSessionLocal() as db:
        from app.models import User, UserRole, Tenant
        from app.core.auth import hash_password

        # ── Default tenant ───────────────────────────────────────────────
        from sqlalchemy.exc import IntegrityError as _IE
        try:
            result = await db.execute(select(Tenant).where(Tenant.code == "default"))
            if not result.scalar_one_or_none():
                tenant = Tenant(code="default", name="Default Organisation", is_active=True)
                db.add(tenant)
                await db.flush()
                logger.info("Created default tenant")

                admin = User(
                    email=settings.FIRST_ADMIN_EMAIL,
                    hashed_password=hash_password(settings.FIRST_ADMIN_PASSWORD),
                    full_name="SocBlitz Admin",
                    role=UserRole.ADMIN,
                    tenant_id=tenant.id,
                    is_active=True,
                    is_verified=True,
                )
                db.add(admin)
                logger.info(f"Created admin user: {settings.FIRST_ADMIN_EMAIL}")
                logger.warning(f"Admin password set — change immediately!")

            await db.commit()
        except _IE:
            await db.rollback()
            logger.warning("Tenant/admin already exists (worker race) — skipping")


async def seed_connectors_from_env() -> None:
    """Seed connector records from environment variables on first boot."""
    from app.models import Connector, ConnectorType

    connector_defaults = [
        {
            "connector_type": ConnectorType.WAZUH_INDEXER,
            "url": settings.WAZUH_INDEXER_URL,
            "username": settings.WAZUH_INDEXER_USER,
            "password": settings.WAZUH_INDEXER_PASSWORD,
        },
        {
            "connector_type": ConnectorType.WAZUH_MANAGER,
            "url": settings.WAZUH_MANAGER_URL,
            "username": settings.WAZUH_MANAGER_USER,
            "password": settings.WAZUH_MANAGER_PASSWORD,
        },
        {
            "connector_type": ConnectorType.VELOCIRAPTOR,
            "url": settings.VELOCIRAPTOR_URL,
            "api_key": settings.VELOCIRAPTOR_API_KEY,
        },
        {
            "connector_type": ConnectorType.MISP,
            "url": settings.MISP_URL,
            "api_key": settings.MISP_API_KEY,
        },
    ]

    async with AsyncSessionLocal() as db:
        for cfg in connector_defaults:
            ctype = cfg["connector_type"]
            result = await db.execute(
                select(Connector).where(Connector.connector_type == ctype)
            )
            if result.scalar_one_or_none():
                continue

            connector = Connector(**cfg)
            db.add(connector)
            logger.info(f"Seeded connector: {ctype.value}")

        await db.commit()


async def seed_example_workflows() -> None:
    """Seed a couple of real starter workflows on first boot, so the SOAR
    builder isn't an empty canvas — both use real node types end to end."""
    from app.models import Workflow, WorkflowTrigger

    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Workflow).limit(1))
        if result.scalar_one_or_none():
            return

        examples = [
            Workflow(
                name="Notify Slack on critical alert",
                description="Posts to Slack whenever a Wazuh alert at critical severity comes in.",
                trigger_type=WorkflowTrigger.ALERT,
                trigger_config={"severity": "critical"},
                nodes=[
                    {"id": "1", "type": "trigger.alert", "position": {"x": 60, "y": 120},
                     "data": {"label": "Critical alert", "config": {"severity": "critical"}}},
                    {"id": "2", "type": "action.slack_notify", "position": {"x": 340, "y": 120},
                     "data": {"label": "Notify Slack",
                              "config": {"message": "Critical alert: {{rule_name}} on agent {{agent_name}} ({{agent_ip}})"}}},
                ],
                edges=[{"id": "e1-2", "source": "1", "target": "2"}],
            ),
            Workflow(
                name="Block malicious IP",
                description="Manually block an IP on the reporting agent via Wazuh active response.",
                trigger_type=WorkflowTrigger.MANUAL,
                nodes=[
                    {"id": "1", "type": "trigger.manual", "position": {"x": 60, "y": 120},
                     "data": {"label": "Manual trigger"}},
                    {"id": "2", "type": "action.wazuh_active_response", "position": {"x": 340, "y": 120},
                     "data": {"label": "Block IP",
                              "config": {"command": "firewall-drop", "agent_id_field": "agent_id"}}},
                ],
                edges=[{"id": "e1-2", "source": "1", "target": "2"}],
            ),
        ]
        db.add_all(examples)
        await db.commit()
        logger.info(f"Seeded {len(examples)} example workflows")
