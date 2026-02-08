import os
from functools import lru_cache

from pydantic import BaseSettings, Field


class Settings(BaseSettings):
    app_name: str = "Encrypted Document Signing Platform"
    database_url: str = Field("postgresql://cryptouser:cryptopass@db:5432/cryptodb", env="DATABASE_URL")
    secret_key: str = Field(..., env="SECRET_KEY")
    session_secret: str = Field(..., env="SESSION_SECRET")
    session_max_age_seconds: int = Field(3600, env="SESSION_MAX_AGE")
    rate_limit_per_minute: int = Field(10, env="LOGIN_RATE_LIMIT")

    class Config:
        env_file = os.getenv("ENV_FILE", ".env")
        case_sensitive = True


@lru_cache()
def get_settings() -> Settings:
    return Settings()
