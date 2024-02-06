from pydantic import BaseSettings
from decouple import config


class Settings(BaseSettings):
    SECRET_KEY: str = config('SECRET_KEY')
    ALGORITHM: str = config('ALGORITHM', default="HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = config('ACCESS_TOKEN_EXPIRE_MINUTES', cast=int, default=30)


settings = Settings()
