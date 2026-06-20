"""
matthunder backend configuration
"""
from typing import Optional
from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    """Application settings loaded from environment variables"""
    
    # Application
    APP_NAME: str = "matthunder"
    APP_VERSION: str = "2.0.0"
    DEBUG: bool = False
    SECRET_KEY: str = Field(default="your-secret-key-change-in-production")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    # Database - SQLite for local dev, PostgreSQL for production
    DATABASE_URL: str = Field(
        default="sqlite+aiosqlite:///./matthunder.db"
    )
    DATABASE_POOL_SIZE: int = 5
    DATABASE_MAX_OVERFLOW: int = 10
    
    # Redis (optional for local dev)
    REDIS_URL: str = Field(default="")
    
    # Celery (optional for local dev)
    CELERY_BROKER_URL: str = Field(default="")
    CELERY_RESULT_BACKEND: str = Field(default="")
    
    # CORS
    CORS_ORIGINS: list[str] = Field(
        default=[
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "http://localhost:3010",
            "http://127.0.0.1:3010",
            "http://localhost:8000",
            "http://127.0.0.1:8000",
            "http://localhost:8010",
            "http://127.0.0.1:8010",
        ]
    )
    
    # AI Providers (BYOK - Bring Your Own Key)
    OPENAI_API_KEY: Optional[str] = None
    ANTHROPIC_API_KEY: Optional[str] = None
    GEMINI_API_KEY: Optional[str] = None
    OPENROUTER_API_KEY: Optional[str] = None
    
    # Acunetix Integration
    ACUNETIX_URL: Optional[str] = None
    ACUNETIX_API_KEY: Optional[str] = None
    ACUNETIX_VERIFY_SSL: bool = True
    
    # File Storage
    UPLOAD_DIR: str = "./uploads"
    REPORTS_DIR: str = "./reports"
    SCANS_DIR: str = "./scans"
    
    # Scanner Configuration
    KATANA_LIMIT: int = 20
    SCAN_SPEED: str = "standard"  # low, standard, fast
    SCAN_TIMEOUT: int = 3600  # 1 hour default timeout
    
    # GitHub (for updates)
    GITHUB_USER: str = "hmad28"
    GITHUB_REPO: str = "matthunder"
    
    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
