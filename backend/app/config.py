import os
from pathlib import Path
from dotenv import load_dotenv

# Automatically load .env from backend directory
BACKEND_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BACKEND_DIR / ".env")
load_dotenv()  # Fallback to local working directory


class Settings:
    APP_NAME: str = os.getenv("APP_NAME", "CyberGuard API Engine")
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", "8000"))

    # Hindsight Settings
    HINDSIGHT_API_KEY: str = os.getenv("HINDSIGHT_API_KEY", "")
    HINDSIGHT_BASE_URL: str = os.getenv("HINDSIGHT_BASE_URL", "https://api.hindsight.vectorize.io")
    HINDSIGHT_BANK_ID: str = os.getenv("HINDSIGHT_BANK_ID", "cyberguard-soc")

    # Groq Settings
    GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")
    GROQ_MODEL: str = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")

    # Bayesian Scoring Weights
    WEIGHT_SEMANTIC: float = float(os.getenv("WEIGHT_SEMANTIC", "0.40"))
    WEIGHT_EMPIRICAL: float = float(os.getenv("WEIGHT_EMPIRICAL", "0.60"))


settings = Settings()
