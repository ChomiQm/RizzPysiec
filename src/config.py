from pydantic import BaseSettings
from decouple import config


class Settings(BaseSettings):
    MONGODB_URI: str = config('MONGODB_URI')
    MONGO_DB: str = config('MONGO_DB')


settings = Settings()
