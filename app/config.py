import os
import secrets
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    jwt_secret: str = ""
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 7
    database_url: str = "sqlite+aiosqlite:///./app.db"

    model_config = {"env_file": ".env"}

    def validate_secret(self) -> None:
        if not self.jwt_secret or len(self.jwt_secret) < 32:
            raise RuntimeError(
                "JWT_SECRET must be set and at least 32 characters. "
                "Generate with: python -c \"import secrets; print(secrets.token_hex(32))\""
            )


settings = Settings()
