"""Application configuration and runtime environment validation."""
import os
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    project_name: str = "security-posture-scorer-alan-vo"
    version: str = "1.0.0"
    author_name: str = "Alan Vo"
    author_email: str = "alanvo@gmail.com"
    environment: str = os.getenv("ENVIRONMENT", "development")

    # Local demo mode: binds localhost only and startup refuses in production
    demo_mode: bool = os.getenv("DEMO_MODE", "true").lower() in ("true", "1", "yes")

    host: str = os.getenv("HOST", "127.0.0.1")
    port: int = int(os.getenv("PORT", "8000"))

    # SQLite persistent storage
    database_path: str = os.getenv(
        "DATABASE_PATH",
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "posture.db")
    )

    # Authentication & OIDC
    jwt_secret: str = os.getenv("JWT_SECRET", "dev-insecure-secret-key-change-in-production-123456")
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 480
    oidc_issuer_url: Optional[str] = os.getenv("OIDC_ISSUER_URL", None)
    oidc_client_id: str = os.getenv("OIDC_CLIENT_ID", "security-posture-scorer")
    oidc_client_secret: Optional[str] = os.getenv("OIDC_CLIENT_SECRET", None)

    # LLM Provider settings: LLM_API_KEY is the only secret credential variable
    llm_api_key: Optional[str] = os.getenv("LLM_API_KEY", None)
    llm_provider: str = os.getenv("LLM_PROVIDER", "openai-compatible")
    llm_model: str = os.getenv("LLM_MODEL", "gpt-4o")
    llm_base_url: str = os.getenv("LLM_BASE_URL", "https://api.openai.com/v1")
    llm_timeout_seconds: float = 25.0

    def validate_production_safety(self) -> None:
        """Enforce contract: startup refuses demo mode in production."""
        if self.environment.lower() == "production" and self.demo_mode:
            raise RuntimeError(
                "Security violation: Local demo mode is strictly forbidden when ENVIRONMENT=production. "
                "Set DEMO_MODE=false and configure an external OIDC/Keycloak identity provider."
            )


settings = Settings()
