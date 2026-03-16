from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    APP_ENV: str = "development"
    APP_SECRET_KEY: str = "change-me"
    APP_DEBUG: bool = True

    DATABASE_URL: str = "postgresql+asyncpg://argus:argus_dev_password@db:5432/argus"
    REDIS_URL: str = "redis://redis:6379/0"

    SCANNER_DEFAULT_TARGETS: str = "192.168.1.0/24"
    SCANNER_INTERVAL_MINUTES: int = 60
    SCANNER_NMAP_ARGS: str = "-sV -O --osscan-guess -T4"
    SCANNER_PASSIVE_ARP: bool = True

    SNMP_COMMUNITY: str = "public"
    SNMP_VERSION: str = "2c"
    SNMP_TIMEOUT: int = 5

    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 1440

    ADMIN_USERNAME: str = "admin"
    ADMIN_PASSWORD: str = "changeme"

    ALLOWED_ORIGINS: list[str] = ["http://localhost:3000"]

    NOTIFY_WEBHOOK_URL: str = ""


settings = Settings()
