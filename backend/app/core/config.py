"""Application Configuration."""

import os
from dotenv import load_dotenv

load_dotenv()


class Settings:
    """Application settings."""

    # App
    APP_NAME: str = "Advanced CVE Analysis System"
    APP_VERSION: str = "7.0.0"
    DEBUG: bool = os.getenv("DEBUG", "false").lower() == "true"

    # Database
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        "postgresql+psycopg2://cve_user:cve_password@db:5432/cve_db"
    )

    # NVD API
    NVD_API_KEY: str = os.getenv("NVD_API_KEY", "")

    # Pagination
    DEFAULT_PAGE_SIZE: int = 20
    MAX_PAGE_SIZE: int = 100

    # CORS - allow all origins
    ALLOWED_ORIGINS: list = ["*"]


settings = Settings()
