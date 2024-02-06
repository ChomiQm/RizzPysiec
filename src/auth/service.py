from datetime import timedelta
from fastapi import HTTPException, status
from src.auth.config import settings
from src.auth.utils import verify_password, create_access_token
from src.database import get_database


async def authenticate_user(username: str, password: str):
    db = get_database()
    user_in_db = await db["users"].find_one({"username": username})

    if not user_in_db or not verify_password(password, user_in_db["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    return create_access_token(
        data={"sub": str(user_in_db["_id"])}, expires_delta=access_token_expires
    )
