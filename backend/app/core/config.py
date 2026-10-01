import os
from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    PROJECT_NAME: str = "Security Operations Agent"
    VERSION: str = "0.1.0"
    API_V1_STR: str = "/api/v1"
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    CORS_ORIGINS: List[str] = ["http://localhost:5173", "http://localhost:3000", "*"]
    
    # Database
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL", 
        "postgresql://secops_user:secops_password@localhost:5432/secops_db"
    )

    # Webhook Security
    WEBHOOK_SECRET: str = os.getenv("WEBHOOK_SECRET", "")
    WEBHOOK_FALLBACK_SECRETS: List[str] = [
        s.strip() for s in os.getenv("WEBHOOK_FALLBACK_SECRETS", "").split(",") if s.strip()
    ]
    WEBHOOK_MAX_DRIFT_SECONDS: int = int(os.getenv("WEBHOOK_MAX_DRIFT_SECONDS", "300"))

    # SIEM / Ingestion
    WAZUH_API_URL: str = os.getenv("WAZUH_API_URL", "https://localhost:55000")
    WAZUH_API_USER: str = os.getenv("WAZUH_API_USER", "wazuh-wui")
    WAZUH_API_PASSWORD: str = os.getenv("WAZUH_API_PASSWORD", "")
    WAZUH_VERIFY_SSL: bool = os.getenv("WAZUH_VERIFY_SSL", "false").lower() == "true"

    # Threat Intel
    ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")

    # LLM
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    LLM_MODEL: str = os.getenv("LLM_MODEL", "gpt-4o")

    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=True,
        extra="allow",
    )

settings = Settings()
