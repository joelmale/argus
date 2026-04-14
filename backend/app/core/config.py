import secrets
from pathlib import Path

from pydantic import SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import URL


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    APP_ENV: str = "development"
    APP_SECRET_KEY: str = ""
    APP_DEBUG: bool = True
    SECRET_KEY_FILE: str = "/run/secrets/argus_secret_key"

    DATABASE_URL: SecretStr | None = None
    DATABASE_URL_DOCKER: SecretStr | None = None
    DATABASE_HOST: str = "db"
    DATABASE_PORT: int = 5432
    DATABASE_NAME: str = "argus"
    DATABASE_USER: str = "argus"
    DATABASE_PASSWORD: SecretStr | None = None
    REDIS_URL: str = "redis://redis:6379/0"

    SCANNER_DEFAULT_TARGETS: str = "192.168.1.0/24"
    SCANNER_INTERVAL_MINUTES: int = 60
    SCANNER_NMAP_ARGS: str = "-sV -O --osscan-guess -T4"
    SCANNER_PASSIVE_ARP: bool = True
    ASSET_HEARTBEAT_INTERVAL_SECONDS: int = 10
    ASSET_HEARTBEAT_TARGET_INTERVAL_SECONDS: int = 30
    ASSET_HEARTBEAT_MISS_THRESHOLD: int = 3
    ASSET_HEARTBEAT_TIMEOUT_SECONDS: int = 5
    ASSET_HEARTBEAT_BATCH_SIZE: int = 128

    SNMP_COMMUNITY: str = "public"
    SNMP_VERSION: str = "2c"
    SNMP_TIMEOUT: int = 5
    SNMP_V3_USERNAME: str = ""
    SNMP_V3_AUTH_KEY: str = ""
    SNMP_V3_PRIV_KEY: str = ""
    SNMP_V3_AUTH_PROTOCOL: str = "sha"
    SNMP_V3_PRIV_PROTOCOL: str = "aes"

    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 240
    JWT_REMEMBER_ME_EXPIRE_MINUTES: int = 5760

    ADMIN_USERNAME: str = ""
    ADMIN_PASSWORD: SecretStr | None = None

    ALLOWED_ORIGINS: list[str] = ["http://localhost:3000"]

    NOTIFY_WEBHOOK_URL: str = ""
    NOTIFY_OFFLINE_MINUTES: int = 0
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USERNAME: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM: str = ""
    SMTP_TO: str = ""

    # ── AI Agent ─────────────────────────────────────────────────────────────
    # AI_BACKEND: "ollama" | "anthropic" | "none"
    AI_BACKEND: str = "ollama"
    AI_ENABLE_PER_SCAN: bool = True
    AI_MAX_CONCURRENT_HOSTS: int = 5   # How many hosts the AI investigates in parallel

    # Ollama settings (primary — uses your local RTX A2000)
    OLLAMA_BASE_URL: str = "http://host.docker.internal:11434/v1"
    # Recommended models for tool use: qwen2.5:7b, llama3.1:8b, qwen2.5:14b
    OLLAMA_MODEL: str = "qwen2.5:7b"

    # OpenAI-compatible hosted settings
    OPENAI_BASE_URL: str = "https://api.openai.com/v1"
    OPENAI_API_KEY: str = ""
    OPENAI_MODEL: str = "gpt-5-mini"

    # Anthropic settings (optional fallback)
    ANTHROPIC_API_KEY: str = ""
    ANTHROPIC_MODEL: str = "claude-haiku-4-5-20251001"

    # ── Scanner profiles ──────────────────────────────────────────────────────
    SCANNER_DEFAULT_PROFILE: str = "balanced"
    SCANNER_CONCURRENT_HOSTS: int = 10
    SCANNER_PASSIVE_ARP_INTERFACE: str = "auto"
    TOPOLOGY_DEFAULT_SEGMENT_PREFIX_V4: int = 24

    @model_validator(mode="after")
    def _resolve_secret_key(self) -> "Settings":
        if self.APP_SECRET_KEY:
            return self
        key_file = Path(self.SECRET_KEY_FILE)
        if key_file.is_file():
            key = key_file.read_text().strip()
            if key:
                self.APP_SECRET_KEY = key
                return self
        key = secrets.token_hex(32)
        key_file.parent.mkdir(parents=True, exist_ok=True)
        key_file.write_text(key)
        self.APP_SECRET_KEY = key
        return self

    @model_validator(mode="after")
    def _populate_database_url(self) -> "Settings":
        if self.DATABASE_URL:
            self.DATABASE_URL = SecretStr(self.DATABASE_URL.get_secret_value())
            return self
        if self.DATABASE_URL_DOCKER:
            self.DATABASE_URL = SecretStr(self.DATABASE_URL_DOCKER.get_secret_value())
            return self
        password = self.DATABASE_PASSWORD.get_secret_value() if self.DATABASE_PASSWORD else ""
        if not password:
            raise ValueError(
                "DATABASE_PASSWORD is required when DATABASE_URL and DATABASE_URL_DOCKER are not provided."
            )
        self.DATABASE_URL = SecretStr(
            URL.create(
                "postgresql+asyncpg",
                username=self.DATABASE_USER,
                password=password,
                host=self.DATABASE_HOST,
                port=self.DATABASE_PORT,
                database=self.DATABASE_NAME,
            ).render_as_string(hide_password=False)
        )
        return self


settings = Settings()
