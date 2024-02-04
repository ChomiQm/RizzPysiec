from pydantic import BaseSettings


class Settings(BaseSettings):
    MONGODB_URI: str  # MongoDB Atlas connection string
    MONGO_DB: str     # Database name

    class Config:
        env_file = ".env"


settings = Settings()
