"""
SocBlitz Celery — task broker configuration and all registered tasks.
"""
from celery import Celery
from app.core.config import settings

celery_app = Celery(
    "socblitz",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=["app.workers.tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    result_expires=3600,
    # ── Periodic tasks (Celery Beat) ──────────────────────────────────────
    beat_schedule={
        "sync-wazuh-agents": {
            "task": "app.workers.tasks.sync_wazuh_agents",
            "schedule": 300.0,  # every 5 minutes
        },
        "collect-graylog-alerts": {
            "task": "app.workers.tasks.collect_graylog_alerts",
            "schedule": 60.0,   # every minute
        },
        "sync-vulnerabilities": {
            "task": "app.workers.tasks.sync_vulnerabilities",
            "schedule": 3600.0, # hourly
        },
        "enrich-pending-alerts": {
            "task": "app.workers.tasks.enrich_pending_alerts",
            "schedule": 120.0,  # every 2 minutes
        },
        "health-check-connectors": {
            "task": "app.workers.tasks.health_check_connectors",
            "schedule": 600.0,  # every 10 minutes
        },
    },
    task_routes={
        "app.workers.tasks.sync_wazuh_agents":      {"queue": "integrations"},
        "app.workers.tasks.collect_graylog_alerts":  {"queue": "integrations"},
        "app.workers.tasks.sync_vulnerabilities":    {"queue": "integrations"},
        "app.workers.tasks.enrich_alert":            {"queue": "alerts"},
        "app.workers.tasks.enrich_observable":       {"queue": "alerts"},
        "app.workers.tasks.enrich_pending_alerts":   {"queue": "alerts"},
        "app.workers.tasks.run_workflow":            {"queue": "default"},
        "app.workers.tasks.process_wazuh_webhook":   {"queue": "alerts"},
        "app.workers.tasks.health_check_connectors": {"queue": "default"},
    },
)
