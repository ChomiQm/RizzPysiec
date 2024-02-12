from datetime import timedelta, datetime
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

        # Token generation
    access_token_expires = timedelta(minutes=auth_settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": str(user_in_db["_id"])}, expires_delta=access_token_expires
    )

    refresh_token = create_refresh_token(data={"sub": str(user_in_db["_id"])})

    # Save the refresh token in the database and get its ID
    refresh_token_data = {
        "user_id": user_in_db["_id"],
        "refresh_token": refresh_token,
        "expires_at": datetime.utcnow() + timedelta(days=7)  # Example expiration
    }
    result = await db["refresh_tokens"].insert_one(refresh_token_data)
    refresh_token_id = str(result.inserted_id)

    return access_token, refresh_token, refresh_token_id
