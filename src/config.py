from decouple import config


class Settings:
    MONGODB_URI: str = config('MONGODB_URI')
    MONGO_DB: str = config('MONGO_DB')

    MAIL_HOST: str = config('MAIL_HOST')
    MAIL_PORT: int = config('MAIL_PORT')
    MAIL_ENABLE_SSL: bool = config('MAIL_ENABLE_SSL')
    MAIL_USERNAME: str = config('MAIL_USERNAME')
    MAIL_PASSWORD: str = config('MAIL_PASSWORD')
    MAIL_FROM_EMAIL: str = config('MAIL_FROM_EMAIL')

    FRONTEND_URL = config('FRONTEND_URL', default='http://localhost:3000')


settings = Settings()
