from fastapi import APIRouter, HTTPException, status, Depends
from src.auth.dependencies import get_current_user, JWTBearer
from src.auth.schemas import UserLogin, Token, UserOut, UserCreate
from src.auth.utils import hash_password, verify_password, create_access_token
from src.database import get_database
from datetime import datetime, timedelta
from src.auth.config import settings

auth_router = APIRouter()


@auth_router.post("/register", response_model=UserCreate)
async def register_user(user: UserCreate):
    db = get_database()
    # await needed
    user_in_db = await db["users"].find_one({"username": user.username})
    if user_in_db:
        raise HTTPException(status_code=400, detail="Username already registered")

    hashed_password = hash_password(user.password.get_secret_value())
    user_dict = user.dict(exclude={"password"})
    user_dict["hashed_password"] = hashed_password
    user_dict["join_date"] = datetime.utcnow()
    # we can add more fields
    await db["users"].insert_one(user_dict)
    # return data without password and id
    return UserOut(**user_dict, id=str(user_dict["_id"]))


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
    return {"message": "world"}


@auth_router.get("/token", response_model=UserOut , dependencies=[Depends(JWTBearer)])
async def get_jwt_bearer ():
    return "Bearer token"
