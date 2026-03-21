from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    APP_ENV: str = "development"
    APP_SECRET_KEY: str = "change-me"
    APP_DEBUG: bool = True

    DATABASE_URL: str = ""
    DATABASE_URL_DOCKER: str = ""
    DATABASE_HOST: str = "db"
    DATABASE_PORT: int = 5432
    DATABASE_NAME: str = "argus"
    DATABASE_USER: str = "argus"
    DATABASE_PASSWORD: str = ""
    REDIS_URL: str = "redis://redis:6379/0"

    SCANNER_DEFAULT_TARGETS: str = "192.168.1.0/24"
    SCANNER_INTERVAL_MINUTES: int = 60
    SCANNER_NMAP_ARGS: str = "-sV -O --osscan-guess -T4"
    SCANNER_PASSIVE_ARP: bool = True

    SNMP_COMMUNITY: str = "public"
    SNMP_VERSION: str = "2c"
    SNMP_TIMEOUT: int = 5
    SNMP_V3_USERNAME: str = ""
    SNMP_V3_AUTH_KEY: str = ""
    SNMP_V3_PRIV_KEY: str = ""
    SNMP_V3_AUTH_PROTOCOL: str = "sha"
    SNMP_V3_PRIV_PROTOCOL: str = "aes"

    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 1440

    ADMIN_USERNAME: str = "admin"
    ADMIN_PASSWORD: str = "changeme"

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
    OLLAMA_BASE_URL: str = "http://ollama:11434/v1"
    # Recommended models for tool use: qwen2.5:7b, llama3.1:8b, qwen2.5:14b
    OLLAMA_MODEL: str = "qwen2.5:7b"

    # Anthropic settings (optional fallback)
    ANTHROPIC_API_KEY: str = ""
    ANTHROPIC_MODEL: str = "claude-haiku-4-5-20251001"

    # ── Scanner profiles ──────────────────────────────────────────────────────
    SCANNER_DEFAULT_PROFILE: str = "balanced"
    SCANNER_CONCURRENT_HOSTS: int = 10
    SCANNER_PASSIVE_ARP_INTERFACE: str = "eth0"

    @model_validator(mode="after")
    def _populate_database_url(self) -> "Settings":
        if self.DATABASE_URL:
            return self
        if self.DATABASE_URL_DOCKER:
            self.DATABASE_URL = self.DATABASE_URL_DOCKER
            return self

        credentials = self.DATABASE_USER
        if self.DATABASE_PASSWORD:
            credentials = f"{credentials}:{self.DATABASE_PASSWORD}"
        self.DATABASE_URL = (
            f"postgresql+asyncpg://{credentials}@{self.DATABASE_HOST}:{self.DATABASE_PORT}/{self.DATABASE_NAME}"
        )
        return self


settings = Settings()
