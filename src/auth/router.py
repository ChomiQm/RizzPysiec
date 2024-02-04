from fastapi import APIRouter, HTTPException, status
from src.auth.schemas import UserCreate, UserLogin, UserOut, Token
from src.auth.utils import hash_password, verify_password
from src.database import get_database
from datetime import datetime
router = APIRouter()


@router.post("/register", response_model=UserOut)
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


@router.post("/login")
async def login(user: UserLogin):
    db = get_database()
    user_in_db = await db["users"].find_one({"username": user.username})
    if not user_in_db:
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    if not verify_password(user.password.get_secret_value(), user_in_db["hashed_password"]):
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    # JWT Generation
    # ...

    return {"message": "User logged in successfully"}
