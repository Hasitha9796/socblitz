"""
SocBlitz — Open Source SOC Platform
FastAPI application entry point
"""
import asyncio
from contextlib import asynccontextmanager
from loguru import logger
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse

from app.core.config import settings
from app.db.session import engine
from app.db.init_db import init_db
from app.api.v1.router import api_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup + shutdown lifecycle."""
    logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION}")

    # ── Initialise database ──────────────────────────────────────────────
    await init_db()
    logger.info("Database ready")

    # ── Seed connectors from env ─────────────────────────────────────────
    from app.db.init_db import seed_connectors_from_env
    await seed_connectors_from_env()
    logger.info("Connectors seeded")

    # ── Seed example SOAR workflows ──────────────────────────────────────
    from app.db.init_db import seed_example_workflows
    await seed_example_workflows()
    logger.info("Workflows seeded")

    # ── MinIO buckets ────────────────────────────────────────────────────
    from app.services.storage import init_minio_buckets
    await asyncio.to_thread(init_minio_buckets)
    logger.info("MinIO buckets ready")

    logger.info(f"{settings.APP_NAME} is running ⚡")
    yield

    logger.info(f"{settings.APP_NAME} shutting down")
    await engine.dispose()


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.APP_NAME,
        description="Lightning-fast open-source SOC platform — alerts, cases, SOAR, threat intel",
        version=settings.APP_VERSION,
        docs_url="/api/docs" if settings.APP_ENV != "production" else None,
        redoc_url="/api/redoc" if settings.APP_ENV != "production" else None,
        lifespan=lifespan,
    )

    # ── CORS ────────────────────────────────────────────────────────────
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"] if settings.APP_ENV == "development" else [settings.VITE_API_URL if hasattr(settings, 'VITE_API_URL') else "*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Request ID middleware ────────────────────────────────────────────
    @app.middleware("http")
    async def add_request_id(request: Request, call_next):
        import uuid
        request_id = str(uuid.uuid4())[:8]
        request.state.request_id = request_id
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response

    # ── Exception handlers ───────────────────────────────────────────────
    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        logger.error(f"Unhandled exception: {exc}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"detail": "An unexpected error occurred", "error": str(exc)},
        )

    # ── Routes ───────────────────────────────────────────────────────────
    app.include_router(api_router, prefix="/api/v1")

    return app


app = create_app()
