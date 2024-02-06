from datetime import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr, SecretStr, validator
import pytz
# validators


def validate_date_in_the_past(date_field: datetime) -> datetime:
    utc = pytz.UTC
    now_aware = datetime.now(utc)
    if date_field.tzinfo is None:
        raise ValueError("Date of birth must be timezone aware")
    date_field = date_field.astimezone(utc)
    if date_field > now_aware:
        raise ValueError('Date must be in the past')
    return date_field

# Create user schema


class UserCreate(BaseModel):
    username: EmailStr
    password: SecretStr
    full_name: Optional[str] = None
    phone_number: Optional[str] = None  # Added phone number
    date_of_birth: Optional[datetime] = None

    _validate_date_of_birth = validator('date_of_birth', allow_reuse=True)(validate_date_in_the_past)

# User login schema


class UserLogin(BaseModel):
    username: EmailStr
    password: SecretStr

# Out data schema


class UserOut(BaseModel):
    username: EmailStr
    full_name: Optional[str] = None
    date_of_birth: Optional[datetime] = None
    join_date: datetime

    class Config:
        json_encoders = {
            datetime: lambda dt: dt.isoformat(),
        }

# User update schema


class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    phone_number: Optional[str] = None
    profile_info: Optional[str] = None
    date_of_birth: Optional[datetime] = None

    _validate_date_of_birth = validator('date_of_birth', allow_reuse=True)(validate_date_in_the_past)

# JWT token schema


class Token(BaseModel):
    access_token: str
    token_type: str


class RefreshToken(BaseModel):
    user_id: str
    refresh_token: str
    expires_at: datetime
