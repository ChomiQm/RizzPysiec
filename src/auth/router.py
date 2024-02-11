from io import BytesIO
from typing import Annotated, Optional
import pyotp
import qrcode
from bson import ObjectId
from fastapi import APIRouter, HTTPException, status, Depends, Response, Form
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.responses import StreamingResponse
from jose import jwt, JWTError
from pydantic import SecretStr
from src.auth.dependencies import get_current_user, oauth2_scheme
from src.auth.models import UserInDB
from src.auth.schemas import Token, UserOut, UserCreate, UserUpdate, PasswordUpdate
from src.auth.service import authenticate_user
from src.auth.utils import hash_password, verify_password, create_access_token, \
    create_confirmation_token, send_email_with_template, generate_password_reset_token, verify_refresh_token, \
    generate_2fa_secret
from src.database import get_database
from datetime import datetime
from src.auth.config import auth_settings

auth_router = APIRouter()


@auth_router.post("/register", response_model=UserOut)
async def register_user(user: UserCreate, db=Depends(get_database)):
    existing_user = await db["users"].find_one({"username": user.username})
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already registered")

    hashed_password = hash_password(user.password.get_secret_value())
    user_in_db = UserInDB(
        username=user.username,
        hashed_password=hashed_password,
        full_name=user.full_name,
        phone_number=user.phone_number,
        date_of_birth=user.date_of_birth,
        join_date=datetime.utcnow(),
        roles=["user"],
        account_confirmed=False
    )

    result = await db["users"].insert_one(user_in_db.dict(by_alias=True))
    user_id = result.inserted_id
    email_user = str(user_id)

    confirmation_token = create_confirmation_token(email_user)
    confirmation_link = (
        f"http://localhost:8000/confirm/{confirmation_token}"
    )
    email_template = "email_confirmation.html"
    email_context = {
        "username": user.username,
        "confirmation_link": confirmation_link
    }
    await send_email_with_template(
        email_to=user.username,
        subject="Potwierdź swój adres e-mail",
        template_name=email_template,
        context=email_context
    )

    user_created = await db["users"].find_one({"_id": user_id})
    user_created["_id"] = str(user_created["_id"])

    user_out_data = {
        k: v for k, v in user_created.items() if k != "hashed_password"
    }
    user_out_data["id"] = user_created["_id"]

    return UserOut(**user_out_data)


@auth_router.post("/user/2fa/disable")
async def disable_2fa(
    password: str,
    current_user: dict = Depends(get_current_user),
    db=Depends(get_database)
):
    user = await db["users"].find_one({"_id": ObjectId(current_user["user_id"])})
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if not verify_password(password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Incorrect password")

    # Usuwanie sekretu 2FA z bazy danych
    await db["users"].update_one({"_id": ObjectId(current_user["user_id"])}, {"$unset": {"two_fa_secret": ""}})

    return {"message": "2FA has been disabled"}


@auth_router.post("/login", response_model=Token)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    two_fa_code: Optional[str] = Form(None)
):
    access_token, refresh_token = await authenticate_user(
        username=form_data.username,
        password=form_data.password,
        two_fa_code=two_fa_code
    )

    return Token(access_token=access_token, token_type="bearer", refresh_token=refresh_token)


@auth_router.post("/user/initiate-password-change")
async def initiate_password_change(request: PasswordUpdate, current_user: dict = Depends(get_current_user),
                                   db=Depends(get_database)):
    user = await db["users"].find_one({"_id": ObjectId(current_user["user_id"])})
    if not user or not verify_password(request.old_password.get_secret_value(), user["hashed_password"]):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Incorrect old password")

    reset_token = generate_password_reset_token(user['username'], request.new_password.get_secret_value())
    confirmation_link = f"http://localhost:8000/user/confirm-password-change/{reset_token}"

    email_template = "password_reset_confirmation.html"
    email_context = {"confirmation_link": confirmation_link}
    await send_email_with_template(
        email_to=user['username'],
        subject="Potwierdzenie zmiany hasła",
        template_name=email_template,
        context=email_context
    )

    return {"message": "Email to confirm password change has been sent."}


@auth_router.get("/user/confirm-password-change/{token}")
async def confirm_password_change(token: str, db=Depends(get_database)):
    try:
        payload = jwt.decode(token, auth_settings.SECRET_KEY, algorithms=[auth_settings.ALGORITHM])
        email = payload.get("email")  # Zmiana na sub jako identyfikator użytkownika
        user = await db["users"].find_one({"username": email})
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        new_hashed_password = hash_password(payload.get("new_password"))
        await db["users"].update_one({"_id": user["_id"]}, {"$set": {"hashed_password": new_hashed_password}})

        return {"message": "Password has been successfully changed."}
    except jwt.JWTError:
        raise HTTPException(status_code=400, detail="Invalid or expired token")


@auth_router.get("/confirm/{token}")
async def confirm_email(token: str, db=Depends(get_database)):
    try:

        payload = jwt.decode(token, auth_settings.SECRET_KEY, algorithms=[auth_settings.ALGORITHM])
        user_id = ObjectId(payload.get("user_id"))

        user_account_confirmed = await db["users"].find_one({"_id": ObjectId(user_id)})
        if user_account_confirmed['account_confirmed']:
            raise HTTPException(status_code=403, detail="User already confirmed")

        user = await db["users"].find_one_and_update(
            {"_id": user_id},
            {"$set": {"account_confirmed": True}},
            return_document=True
        )

        if user is None:
            raise HTTPException(status_code=404, detail="User not found")

        return {"message": "Account successfully confirmed."}

    except jwt.JWTError:
        raise HTTPException(status_code=400, detail="Invalid or expired token")


@auth_router.get("/user", response_model=UserOut, tags=["User"])
async def read_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    try:
        payload = jwt.decode(token, auth_settings.SECRET_KEY, algorithms=[auth_settings.ALGORITHM])
        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid JWT token")
        db = get_database()
        user_in_db = await db["users"].find_one({"_id": ObjectId(user_id)})
        if not user_in_db:
            raise HTTPException(status_code=404, detail="User not found")
        return user_in_db
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Could not validate credentials {e}",
            headers={"WWW-Authenticate": "Bearer"},
        )


@auth_router.get("/")
async def hello_world():
    return {"message": "Hello world"}


@auth_router.get("/refresh", status_code=status.HTTP_200_OK)
def get_new_access_token(token: str):
    refesh_data = verify_refresh_token(token)
    new_access_token = create_access_token(refesh_data)
    return {
        "access_token": new_access_token,
        "token_type": "Bearer",
        "status": status.HTTP_200_OK
    }


@auth_router.get("/user/2fa/enable")
async def enable_2fa(current_user: dict = Depends(get_current_user), db=Depends(get_database)):
    user = await db["users"].find_one({"_id": ObjectId(current_user["user_id"])})
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # Generowanie sekretu 2FA
    secret = generate_2fa_secret()
    await db["users"].update_one({"_id": ObjectId(current_user["user_id"])}, {"$set": {"two_fa_secret": secret}})

    # Generowanie URI dla TOTP
    username = user["username"]
    service_name = "RizzPysiec"
    uri = pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=service_name)

    # Tworzenie kodu QR
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill='black', back_color='white')

    # Zapisywanie obrazu kodu QR do bufora
    buf = BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)

    # Zwracanie kodu QR jako obrazu
    return StreamingResponse(buf, media_type="image/png")


@auth_router.put("/user/update", response_model=UserOut, tags=["update user stats"])
async def update_user(update_data: UserUpdate, current_user: dict = Depends(get_current_user)):
    db = get_database()
    query = {"_id": ObjectId(current_user["user_id"])}
    update = {"$set": update_data.dict(exclude_unset=True)}
    db.users.update_one(query, update, upsert=True)
    updated_user = await db.users.find_one(query)
    if not updated_user:
        raise HTTPException(status_code=404, detail="User not found")
    return updated_user


@auth_router.delete("/user/delete", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(password: SecretStr, current_user: dict = Depends(get_current_user)):
    db = get_database()
    user = await db.users.find_one({"_id": ObjectId(current_user["user_id"])})
    if not user or not verify_password(password.get_secret_value(), user["hashed_password"]):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Incorrect password")
    await db.users.delete_one({"_id": ObjectId(current_user["user_id"])})
    return Response(status_code=status.HTTP_204_NO_CONTENT)
