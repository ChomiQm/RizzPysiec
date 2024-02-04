from pydantic import BaseSettings


class Settings(BaseSettings):
    SECRET_KEY: str  # JWT on-write
    ALGORITHM: str = "HS256"  # Hash algorithm
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30  # Token duration

    class Config:
        env_file = ".env"


settings = Settings()
