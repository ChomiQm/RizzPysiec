from fastapi import APIRouter, HTTPException, status, Depends
from jose import JWTError
from pymongo import ReturnDocument
from src.auth.dependencies import get_current_user, JWTBearer
from src.auth.models import UserInDB
from src.auth.schemas import UserLogin, Token, UserOut, UserCreate
from src.auth.service import authenticate_user
from src.auth.utils import hash_password, verify_password, create_access_token, create_refresh_token, decode_jwt
from src.database import get_database
from datetime import datetime, timedelta
from src.auth.config import settings

auth_router = APIRouter()


@auth_router.post("/register", response_model=UserOut)
async def register_user(user: UserCreate, db=Depends(get_database)):
    # Check if the username is already in use
    existing_user = await db["users"].find_one({"username": user.username})
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already registered")

    # Hash the password
    hashed_password = hash_password(user.password.get_secret_value())

    # Create the UserInDB object
    user_in_db = UserInDB(
        username=user.username,
        hashed_password=hashed_password,
        full_name=user.full_name,
        phone_number=user.phone_number,
        date_of_birth=user.date_of_birth,
        join_date=datetime.utcnow(),  # Added join date here
        roles=["user"],  # Added default role here
    )

    # Save user to db
    result = await db["users"].insert_one(user_in_db.dict(by_alias=True))
    user_id = result.inserted_id

    # prepare data to response without password
    user_created = await db["users"].find_one({"_id": user_id})
    user_created["_id"] = str(user_created["_id"])  # ObjectId -> string

    # Prepare and return the response data
    user_out_data = {k: v for k, v in user_created.items() if k != "hashed_password"}
    user_out_data["id"] = user_created["_id"]

    return UserOut(**user_out_data)


@auth_router.post("/token/refresh")
async def refresh_token(token: str, db=Depends(get_database)):
    try:
        # Verify the refresh token
        payload = decode_jwt(token)
        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid refresh token")

        # Check if the refresh token exists in the database and has not expired
        stored_token_data = await db["refresh_tokens"].find_one(
            {"refresh_token": token}
        )
        if not stored_token_data or stored_token_data["user_id"] != user_id:
            raise HTTPException(
                status_code=401,
                detail="Refresh token not found or does not match user"
            )

        # Generate a new access token
        new_access_token = create_access_token(
            data={"sub": user_id},
            expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        )

        # Optionally, generate a new refresh token and update it in the database
        new_refresh_token = create_refresh_token({"sub": user_id})
        await db["refresh_tokens"].find_one_and_update(
            {"refresh_token": token},
            {"$set": {"refresh_token": new_refresh_token}},
            return_document=ReturnDocument.AFTER
        )

        return {
            "access_token": new_access_token,
            "token_type": "bearer",
            "refresh_token": new_refresh_token  # Optionally return new refresh token
        }
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")


@auth_router.post("/login", response_model=Token)
async def login_for_access_token(user: UserLogin):
    db = get_database()
    user_in_db = await db["users"].find_one({"username": user.username})
    if not user_in_db:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not verify_password(user.password.get_secret_value(), user_in_db["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Authenticate the user
    user_id = await authenticate_user(user.username, user.password.get_secret_value())
    if not user_id:
        # If authentication fails, raise an HTTP 401 Unauthorized error
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # JWT generation
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": str(user_in_db["_id"])},
        expires_delta=access_token_expires
    )

    return {"access_token": access_token, "token_type": "bearer"}


@auth_router.get("/user", response_model=UserOut, tags=["User"])
async def read_current_user(current_user: dict = Depends(get_current_user)):
    user_id = current_user["user_id"]
    db = get_database()
    user_in_db = await db["users"].find_one({"_id": user_id})
    if not user_in_db:
        raise HTTPException(status_code=404, detail="User not found")
    return user_in_db


@auth_router.get("/")
async def hello_world():
    return {"message": "Hello world"}


@auth_router.get("/token", response_model=UserOut, dependencies=[Depends(JWTBearer)])
async def get_jwt_bearer():
    return "Bearer token"
