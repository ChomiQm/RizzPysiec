from datetime import timedelta, datetime
from typing import Union
from fastapi import HTTPException, status
from src.auth.config import auth_settings
from src.auth.constants import MAX_FAILED_LOGIN_ATTEMPTS, LOCKOUT_DURATION_MINUTES, \
    RESET_FAILED_ATTEMPTS_DURATION_MINUTES
from src.auth.schemas import AccessTokenResponse, TwoFactorAuthResponse
from src.auth.utils import verify_password, create_access_token, create_refresh_token, \
    create_temporary_token_for_2fa
from src.database import get_database


async def authenticate_user(username: str, password: str) -> Union[AccessTokenResponse, TwoFactorAuthResponse]:
    db = get_database()
    user_in_db = await db["users"].find_one({"username": username})

    if not user_in_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Reset failed attempts if necessary and check account status
    await check_and_reset_failed_attempts(db, username, user_in_db)

    if user_in_db.get("lockout_time") and user_in_db["lockout_time"] > datetime.utcnow():
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Account is temporarily locked due to too many failed login attempts. Please try again later."
        )

    if not user_in_db.get("account_confirmed", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account not confirmed"
        )

    if not verify_password(password, user_in_db["hashed_password"]):
        await increment_failed_login_attempts(db, username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )

    # Check if 2FA via Google Authenticator or Email is enabled
    if user_in_db.get("two_fa_qr_secret") or user_in_db.get("two_fa_email_enabled", False):
        temporary_token = create_temporary_token_for_2fa(user_in_db["_id"])
        two_factor_method = "google_authenticator" if user_in_db.get("two_fa_qr_secret") else "email"
        return TwoFactorAuthResponse(
            message="2FA verification required.",
            temporary_token=temporary_token,
            two_factor_method=two_factor_method
        )

    # Generate access and refresh tokens if 2FA is not required
    token_response = await generate_tokens(db, user_in_db["_id"])
    return token_response


async def increment_failed_login_attempts(db, username):
    now = datetime.utcnow()
    user_update_result = await db["users"].update_one(
        {"username": username},
        {
            "$inc": {"failed_login_attempts": 1},
            "$set": {"last_failed_login_attempt": now}
        }
    )
    if user_update_result.modified_count:
        user_in_db = await db["users"].find_one({"username": username})
        if user_in_db["failed_login_attempts"] >= MAX_FAILED_LOGIN_ATTEMPTS:
            lockout_time = datetime.utcnow() + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
            await db["users"].update_one(
                {"username": username},
                {"$set": {"lockout_time": lockout_time}}
            )


async def reset_failed_login_attempts_and_lockout(db, username):
    await db["users"].update_one(
        {"username": username},
        {"$set": {"failed_login_attempts": 0, "lockout_time": None}}
    )


async def generate_tokens(db, user_in_db_id):
    access_token_expires = timedelta(minutes=auth_settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    user_in_db_id_str = str(user_in_db_id)
    access_token = create_access_token(
        data={"sub": user_in_db_id_str}, expires_delta=access_token_expires
    )
    refresh_token = create_refresh_token(data={"sub": user_in_db_id_str})
    refresh_token_data = {
        "user_id": user_in_db_id,
        "refresh_token": refresh_token,
        "expires_at": datetime.utcnow() + timedelta(days=7)
    }
    result = await db["refresh_tokens"].insert_one(refresh_token_data)
    refresh_token_id = str(result.inserted_id)

    return AccessTokenResponse(
        access_token=access_token,
        token_type="Bearer",
        refresh_token=refresh_token,
        refresh_token_id=refresh_token_id
    )


async def check_and_reset_failed_attempts(db, username, user_in_db):
    if user_in_db.get("last_failed_login_attempt"):
        time_since_last_attempt = datetime.utcnow() - user_in_db["last_failed_login_attempt"]
        if time_since_last_attempt > timedelta(minutes=RESET_FAILED_ATTEMPTS_DURATION_MINUTES):
            await reset_failed_login_attempts_and_lockout(db, username)
