"""Application configuration."""

from pathlib import Path
from pydantic import BaseModel


class Settings(BaseModel):
    """Application settings."""

    # Application
    app_name: str = "Threat Hunting Workbench"
    app_version: str = "1.0.0-dev"
    debug: bool = False

    # Server
    host: str = "127.0.0.1"
    port: int = 8000

    # Database
    db_path: Path = Path("data/workbench.db")

    # File Storage
    evidence_dir: Path = Path("cases_data")
    reports_dir: Path = Path("reports_output")

    # Parser Settings
    max_file_size_mb: int = 2048  # 2 GB max per artifact
    batch_insert_size: int = 5000  # Events per batch insert

    # YARA
    yara_rules_dir: Path = Path("data/yara_rules")

    # IOC
    ioc_lists_dir: Path = Path("data/ioc_lists")


settings = Settings()
