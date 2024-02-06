from passlib.context import CryptContext
from datetime import datetime, timedelta, time
from jose import jwt
from fastapi import Depends, Response, Request
from src.auth.config import settings
import time

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt


def decode_jwt(token: str) -> dict:
    try:
        decoded_token = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        return decoded_token if decoded_token["expires"] >= time.time() else None
    except:
        return {}


async def check_jwt(request: Request, next_: callable = Depends):
    jwt_bearer = request.headers.get("Authorization")
    if jwt_bearer:
        if decode_jwt(jwt_bearer):
            return await next_(request)
        else:
            return Response("Invalid token or expired token", status_code=403)
    else:
        return Response("Not authorized", status_code=403)