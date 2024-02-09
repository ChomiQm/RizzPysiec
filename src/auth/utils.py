from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import jwt, JWTError
from fastapi import HTTPException, status, Request
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
from jinja2 import Environment, FileSystemLoader, select_autoescape
from starlette.templating import Jinja2Templates

from src.auth.config import auth_settings  # Make sure this import path is correct
from src.config import settings  # Ensure this import is necessary or adjust accordingly

templates = Jinja2Templates(directory="src/templates")

# Password hashing context setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# Hashes the given password
def hash_password(password: str) -> str:
    return pwd_context.hash(password)


# Verifies a given plain password against the hashed password
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


# Creates a JWT access token
def create_access_token(data: dict, expires_delta: timedelta = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, auth_settings.SECRET_KEY, algorithm=auth_settings.ALGORITHM)


# Decodes a JWT token and verifies its validity
def decode_jwt(token: str) -> dict:
    try:
        decoded_token = jwt.decode(token, auth_settings.SECRET_KEY, algorithms=[auth_settings.ALGORITHM])
        if decoded_token["exp"] < datetime.now().timestamp():
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
        return decoded_token
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")


# Middleware to check JWT in the request
async def check_jwt(request: Request, call_next):
    jwt_bearer = request.headers.get("Authorization")
    if jwt_bearer and jwt_bearer.startswith("Bearer "):
        token = jwt_bearer.split(" ")[1]
        decode_jwt(token)  # Will raise HTTPException if token is invalid or expired
        return await call_next(request)
    else:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authorization header missing or invalid")


# Creates a JWT refresh token
def create_refresh_token(data: dict, expires_delta: timedelta = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(days=7))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, auth_settings.SECRET_KEY, algorithm=auth_settings.ALGORITHM)


def verify_refresh_token(token: str):
    credential_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"}
    )
    try:
        payload = jwt.decode(token, auth_settings.SECRET_KEY, algorithms=[auth_settings.ALGORITHM])
        sub = payload.get("sub")  # Ustawienie sub na podstawie danych z tokena odświeżającego
        if sub is None:
            raise credential_exception
        # Zwróć bezpośrednio dane zdekodowane z tokena odświeżającego
        return {"sub": sub}
    except JWTError:
        raise credential_exception


def get_new_access_token(token: str):
    try:
        token_data = verify_refresh_token(token)
        return create_access_token(token_data)
    except HTTPException as e:
        raise e
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred while processing the request."
        )


# Email configuration for sending emails
def get_mail_config() -> ConnectionConfig:
    print(settings.MAIL_USERNAME + "huj huj huj huj huj huj " + settings.MAIL_PASSWORD)
    return ConnectionConfig(
        MAIL_USERNAME=settings.MAIL_USERNAME,
        MAIL_PASSWORD=settings.MAIL_PASSWORD,
        MAIL_FROM=settings.MAIL_FROM_EMAIL,
        MAIL_PORT=settings.MAIL_PORT,
        MAIL_SERVER=settings.MAIL_HOST,
        MAIL_STARTTLS=False,
        MAIL_SSL_TLS=settings.MAIL_ENABLE_SSL,
        USE_CREDENTIALS=True,
        VALIDATE_CERTS=True
    )


# Sends an email to the specified recipient
async def send_email_with_template(email_to: str, subject: str, template_name: str, context: dict):
    env = Environment(
        loader=FileSystemLoader(searchpath="src/templates"),
        autoescape=select_autoescape(['html', 'xml'])
    )
    template = env.get_template(template_name)
    body = template.render(**context)

    message = MessageSchema(
        subject=subject,
        recipients=[email_to],
        body=body,
        subtype="html"
    )
    fm = FastMail(get_mail_config())
    await fm.send_message(message)


def create_confirmation_token(user_id: str) -> str:
    expire = datetime.utcnow() + timedelta(days=1)  # 1d lifetime
    to_encode = {"exp": expire, "user_id": user_id}
    return jwt.encode(to_encode, auth_settings.SECRET_KEY, algorithm=auth_settings.ALGORITHM)


def generate_password_reset_token(email: str, new_password) -> str:
    expire = datetime.utcnow() + timedelta(hours=1)  # Token valid for 1 hour
    to_encode = {"exp": expire, "email": email, "new_password": new_password}
    return jwt.encode(to_encode, auth_settings.SECRET_KEY, algorithm=auth_settings.ALGORITHM)
