from datetime import timedelta

from src.auth.config import settings
from src.auth.utils import create_access_token


def authenticate_user(username: str, password: str):
    user_id = "user_id_here"
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    return create_access_token(
        data={"sub": user_id}, expires_delta=access_token_expires
    )
