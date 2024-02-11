from datetime import timedelta
from typing import Optional

from fastapi import HTTPException, status
from src.auth.config import auth_settings
from src.auth.utils import verify_password, create_access_token, create_refresh_token, verify_2fa_code
from src.database import get_database


async def authenticate_user(username: str, password: str, two_fa_code: Optional[str] = None):
    db = get_database()
    user_in_db = await db["users"].find_one({"username": username})

    # Check that user exists and pass is ok
    if not user_in_db or not verify_password(password, user_in_db["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Check is acc confirmed
    if not user_in_db.get("account_confirmed", False):
        raise HTTPException(status_code=401, detail="Account not confirmed")

    # 2FA Auth if enabled
    if user_in_db.get("two_fa_secret"):
        if not two_fa_code or not verify_2fa_code(user_in_db["two_fa_secret"], two_fa_code):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid 2FA code",
                headers={"WWW-Authenticate": "Bearer"},
            )

    # Token gen
    access_token_expires = timedelta(minutes=auth_settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": str(user_in_db["_id"])}, expires_delta=access_token_expires
    )

    refresh_token = create_refresh_token(data={"sub": str(user_in_db["_id"])})

    return access_token, refresh_token
