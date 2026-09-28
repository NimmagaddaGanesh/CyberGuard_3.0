from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional


class Settings(BaseSettings):
    APP_NAME: str = "CyberGuard"
    APP_VERSION: str = "0.1.0"
    DEBUG: bool = False

    # Groq Settings
    GROQ_API_KEY: Optional[str] = None
    GROQ_MODEL: str = "openai/gpt-oss-120b"

    # Hindsight Settings (configured in later phase)
    HINDSIGHT_API_KEY: Optional[str] = None
    HINDSIGHT_API_URL: Optional[str] = None
    HINDSIGHT_PROJECT_ID: Optional[str] = None

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


settings = Settings()
