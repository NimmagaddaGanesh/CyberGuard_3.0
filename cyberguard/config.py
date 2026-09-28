import os
from pathlib import Path
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict

PACKAGE_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_ROOT.parent
DEFAULT_DATASET = PROJECT_ROOT / "cyberguard_incidents_1000.json"


class Settings(BaseSettings):
    APP_NAME: str = "CyberGuard"
    APP_VERSION: str = "0.1.0"
    DEBUG: bool = False

    # Groq Settings
    GROQ_API_KEY: Optional[str] = None
    GROQ_MODEL: str = "openai/gpt-oss-120b"

    # Dataset path (can be overridden via CYBERGUARD_DATASET_PATH)
    CYBERGUARD_DATASET_PATH: str = str(DEFAULT_DATASET)

    model_config = SettingsConfigDict(
        env_file=str(PROJECT_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore"
    )


settings = Settings()
