"""
SENTINEL Application Configuration
Loads environment variables and enforces strict security controls.
"""

from functools import lru_cache
from typing import List, Literal
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings validated via Pydantic."""
    
    # Environment mode
    ENVIRONMENT: Literal["development", "testing", "production"] = "development"
    
    # Network binding - local development strictly binds to 127.0.0.1
    HOST: str = "127.0.0.1"
    PORT: int = 8000
    
    # Database configuration
    DATABASE_URL: str = Field(
        default="postgresql+psycopg://sentinel_user:sentinel_secure_pass@127.0.0.1:5432/sentinel_db",
        description="Database connection string (PostgreSQL or SQLite fallback for tests)"
    )
    DB_POOL_SIZE: int = 10
    DB_MAX_OVERFLOW: int = 20
    DB_POOL_TIMEOUT: int = 30
    
    # Security limits
    MAX_REQUEST_SIZE_BYTES: int = 1_048_576  # 1 MB maximum payload size to mitigate DoS
    
    # Monitoring scope
    ALLOWED_SOURCE_SYSTEMS: List[str] = ["LedgerOne", "HelpDeskr", "TallyBridge"]
    
    # Metadata
    PROJECT_NAME: str = "SENTINEL API Activity Monitor"
    VERSION: str = "1.0.0"
    API_V1_PREFIX: str = "/api/v1"
    LOG_LEVEL: str = "INFO"

    @field_validator("HOST")
    @classmethod
    def validate_host_binding(cls, v: str, info) -> str:
        """Enforce that local development binds strictly to localhost."""
        # In development, disallow 0.0.0.0 to prevent unintentional public network exposure
        # info.data might not have ENVIRONMENT if it's evaluated after, but default is development
        env = info.data.get("ENVIRONMENT", "development")
        if env == "development" and v not in ("127.0.0.1", "localhost"):
            raise ValueError(
                f"Security policy violation: Development server must bind to localhost/127.0.0.1, got '{v}'"
            )
        return v

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


@lru_cache
def get_settings() -> Settings:
    """Return cached application settings singleton."""
    return Settings()
