from io import BytesIO
from typing import Annotated
import pyotp
import qrcode
from bson import ObjectId
from fastapi import APIRouter, HTTPException, status, Depends, Response, Body
from fastapi.responses import StreamingResponse
from fastapi.security import OAuth2PasswordRequestForm
from jose import jwt, JWTError
from pydantic import SecretStr
from starlette.responses import JSONResponse
from src.auth.dependencies import get_current_user, oauth2_scheme
from src.auth.models import UserInDB
from src.auth.schemas import AccessTokenResponse, UserOut, UserCreate, UserUpdate, PasswordUpdate, Verify2FA,  \
    TwoFactorAuthResponse
from src.auth.service import authenticate_user, generate_tokens
from src.auth.utils import hash_password, verify_password, create_access_token, \
    create_confirmation_token, send_email_with_template, generate_password_reset_token, verify_refresh_token, \
    generate_2fa_qr_secret, verify_2fa_email_code, verify_temporary_token, verify_2fa_qr_code, generate_2fa_email_code
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


@auth_router.post("/user/2fa/disable-email")
async def disable_2fa_email(db=Depends(get_database), current_user: dict = Depends(get_current_user)):
    user_id = current_user.get("user_id")
    if not user_id:
        raise HTTPException(status_code=404, detail="User not found")

    await db["users"].update_one(
        {"_id": ObjectId(user_id)},
        {"$unset": {"two_fa_email_code": "", "two_fa_email_code_generated_at": "", "two_fa_email_enabled": ""}}
    )

    return {"message": "2FA email verification has been disabled."}


@auth_router.post("/verify-2fa", response_model=AccessTokenResponse)
async def verify_2fa(
    verification_info: Verify2FA = Body(...),
    db=Depends(get_database)
):
    # Weryfikacja tymczasowego tokena
    user_id = verify_temporary_token(verification_info.temporary_token)
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid or expired temporary token")

    user = await db["users"].find_one({"_id": ObjectId(user_id)})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Weryfikacja kodu 2FA
    valid_code = False
    if verification_info.method == "google_authenticator" and user.get("two_fa_qr_secret"):
        valid_code = verify_2fa_qr_code(user["two_fa_qr_secret"], verification_info.code)
    elif verification_info.method == "email" and user.get("two_fa_email_code"):
        valid_code = verify_2fa_email_code(user, verification_info.code)

    if not valid_code:
        raise HTTPException(status_code=401, detail="Invalid 2FA code")

    # Zwracamy tokeny dostępu
    token_response = await generate_tokens(db, user["_id"])
    return token_response


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

    # Delete 2FA from db
    await db["users"].update_one({"_id": ObjectId(current_user["user_id"])}, {"$unset": {"two_fa_qr_secret": ""}})

    return {"message": "2FA has been disabled"}


@auth_router.post("/login", response_model=AccessTokenResponse)
async def login_for_access_token(user_login: Annotated[OAuth2PasswordRequestForm, Depends()]):
    token_response = await authenticate_user(
        username=user_login.username,
        password=user_login.password
    )

    # Bezpośrednie zwrócenie token_response, jeśli jest odpowiedniego typu
    if isinstance(token_response, AccessTokenResponse):
        return token_response
    elif isinstance(token_response, TwoFactorAuthResponse):
        return JSONResponse(status_code=200, content=token_response.dict())
    elif isinstance(token_response, dict):
        return JSONResponse(status_code=200, content=token_response)
    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unexpected error during authentication"
        )


@auth_router.post("/logout")
async def logout(token: str = Depends(oauth2_scheme), db=Depends(get_database)):
    current_user = await get_current_user(token)
    user_id = current_user.get("user_id")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials")

    user_oid = ObjectId(user_id)
    result = await db["refresh_tokens"].delete_many({"user_id": user_oid})
    if result.deleted_count == 0:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="No refresh token found for the current user")

    return {"message": "Successfully logged out"}


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


@auth_router.get("/request-2fa-code")
async def request_2fa_code(temporary_token: str, db=Depends(get_database)):
    user_id_str = verify_temporary_token(temporary_token)
    if not user_id_str:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")

    user_id = ObjectId(user_id_str)
    user_in_db = await db["users"].find_one({"_id": user_id})
    if not user_in_db:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if user_in_db.get("two_fa_email_enabled", False):
        code = generate_2fa_email_code()
        await db["users"].update_one(
            {"_id": user_id},
            {
                "$set": {
                    "two_fa_email_code": code,
                    "two_fa_email_code_generated_at": datetime.utcnow()
                }
            }
        )
        await send_email_with_template(
            email_to=user_in_db['username'],
            subject="Your 2FA Code",
            template_name="two_factor_mail.html",
            context={"code": code}
        )
        return {"message": "2FA code has been sent to your email."}

    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="2FA is not enabled for this account.")


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


@auth_router.get("/user/2fa/enable-email")
async def enable_2fa_email(current_user: dict = Depends(get_current_user), db=Depends(get_database)):
    user_id = current_user.get("user_id")
    user = await db["users"].find_one({"_id": ObjectId(user_id)})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Ustaw tylko flagę two_fa_email_enabled na True
    await db["users"].update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"two_fa_email_enabled": True}}
    )

    return {"message": "2FA email verification has been enabled. "
                       "You will receive a 2FA code via email when you log in."}


@auth_router.get("/user/2fa/enable")
async def enable_2fa(current_user: dict = Depends(get_current_user), db=Depends(get_database)):
    user = await db["users"].find_one({"_id": ObjectId(current_user["user_id"])})
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # 2FA secret gen
    secret = generate_2fa_qr_secret()
    await db["users"].update_one({"_id": ObjectId(current_user["user_id"])}, {"$set": {"two_fa_qr_secret": secret}})

    # Uri for TOTP
    username = user["username"]
    service_name = "RizzPysiec"
    uri = pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=service_name)

    # QR code creation
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill='black', back_color='white')

    # QR to bufor write
    buf = BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)

    # return QR as img
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
