from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # ── App ─────────────────────────────────────────────────────────────────
    APP_ENV: str = "production"
    APP_NAME: str = "SocBlitz"
    APP_VERSION: str = "1.0.0"
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 480
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # ── Bootstrap admin ──────────────────────────────────────────────────────
    FIRST_ADMIN_EMAIL: str = "admin@socblitz.local"
    FIRST_ADMIN_PASSWORD: str = "SocBlitz@Admin1!"

    # ── PostgreSQL ───────────────────────────────────────────────────────────
    POSTGRES_HOST: str = "postgres"
    POSTGRES_PORT: int = 5432
    POSTGRES_DB: str = "socblitz"
    POSTGRES_USER: str = "socblitz"
    POSTGRES_PASSWORD: str

    @property
    def DATABASE_URL(self) -> str:
        from sqlalchemy.engine.url import URL
        return str(URL.create("postgresql+asyncpg", username=self.POSTGRES_USER, password=self.POSTGRES_PASSWORD, host=self.POSTGRES_HOST, port=self.POSTGRES_PORT, database=self.POSTGRES_DB))

    @property
    def SYNC_DATABASE_URL(self) -> str:
        from sqlalchemy.engine.url import URL
        return str(URL.create("postgresql+psycopg2", username=self.POSTGRES_USER, password=self.POSTGRES_PASSWORD, host=self.POSTGRES_HOST, port=self.POSTGRES_PORT, database=self.POSTGRES_DB))

    # ── Redis ────────────────────────────────────────────────────────────────
    REDIS_HOST: str = "redis"
    REDIS_PORT: int = 6379
    REDIS_PASSWORD: str = ""
    REDIS_DB: int = 0

    @property
    def REDIS_URL(self) -> str:
        if self.REDIS_PASSWORD:
            return f"redis://:{self.REDIS_PASSWORD}@{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB}"
        return f"redis://{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB}"

    # ── MinIO ────────────────────────────────────────────────────────────────
    MINIO_ENDPOINT: str = "minio:9000"
    MINIO_ROOT_USER: str = "socblitz"
    MINIO_ROOT_PASSWORD: str = ""
    MINIO_SECURE: bool = False
    MINIO_BUCKET_CASES: str = "socblitz-cases"
    MINIO_BUCKET_REPORTS: str = "socblitz-reports"
    MINIO_BUCKET_ARTIFACTS: str = "socblitz-artifacts"

    # ── ClickHouse (analytics store — replaces the Wazuh Indexer/OpenSearch) ──
    CLICKHOUSE_URL: str = "http://clickhouse:8123"
    CLICKHOUSE_USER: str = "socblitz"
    CLICKHOUSE_PASSWORD: str = ""

    # ── SocBlitz Engine (custom detection engine — replaces the Wazuh manager) ─
    ENGINE_URL: str = "http://engine:8090"   # auth reuses AGENT_ENROLL_KEY below

    # ── Wazuh ────────────────────────────────────────────────────────────────
    WAZUH_MANAGER_URL: str = ""
    WAZUH_MANAGER_USER: str = "wazuh-wui"
    WAZUH_MANAGER_PASSWORD: str = ""

    # ── Velociraptor ─────────────────────────────────────────────────────────
    VELOCIRAPTOR_URL: str = ""
    VELOCIRAPTOR_API_KEY: str = ""
    VELOCIRAPTOR_USER: str = "admin"
    VELOCIRAPTOR_PASSWORD: str = ""

    # ── Unified agent deployment ─────────────────────────────────────────────
    # Shared key required to download the SocBlitz Agent installer + Velociraptor
    # client config/binary (endpoints fetch these unauthenticated during enrol).
    AGENT_ENROLL_KEY: str = ""
    # Optional override for the address endpoints use to reach this server.
    # Empty → derived from the Host header of the request that fetched the installer.
    AGENT_PUBLIC_HOST: str = ""

    # ── Shuffle ──────────────────────────────────────────────────────────────
    SHUFFLE_URL: str = ""
    SHUFFLE_API_KEY: str = ""

    # ── Threat Intel ─────────────────────────────────────────────────────────
    VIRUSTOTAL_API_KEY: str = ""
    MISP_URL: str = ""
    MISP_API_KEY: str = ""
    ABUSEIPDB_API_KEY: str = ""
    OTX_API_KEY: str = ""

    # ── Dark Web / leak monitoring ───────────────────────────────────────────
    # Provider-agnostic: each adapter activates only when its key is present,
    # otherwise the source is reported as "skipped" (see services/darkweb.py).
    HIBP_API_KEY: str = ""                       # Have I Been Pwned (account/domain breach search)
    INTELX_API_KEY: str = ""                     # Intelligence X (darkweb/leak selector search)
    INTELX_URL: str = "https://2.intelx.io"
    DEHASHED_EMAIL: str = ""                     # Dehashed uses email + key basic auth
    DEHASHED_API_KEY: str = ""
    LEAKCHECK_API_KEY: str = ""                  # LeakCheck Pro (leaked-credential search)
    # How far back a scheduled asset rescan is considered "recent enough" to skip.
    DARKWEB_SCAN_INTERVAL_HOURS: int = 6

    # ── AI / LLM ─────────────────────────────────────────────────────────────
    OPENAI_API_KEY: str = ""
    OPENAI_MODEL: str = "gpt-4o-mini"
    LOCAL_LLM_URL: str = ""
    LOCAL_LLM_MODEL: str = ""
    LOCAL_EMBED_MODEL: str = "nomic-embed-text"

    # ── Notifications ────────────────────────────────────────────────────────
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM: str = "socblitz@yourorg.com"
    SLACK_WEBHOOK_URL: str = ""
    TEAMS_WEBHOOK_URL: str = ""


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
