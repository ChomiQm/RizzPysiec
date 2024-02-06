from datetime import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr, SecretStr, validator

# validators


def validate_date_in_the_past(date_field: Optional[datetime]) -> Optional[datetime]:
    if date_field and date_field > datetime.utcnow():
        raise ValueError('Date must be in the past')
    return date_field

# Create user schema


class UserCreate(BaseModel):
    username: EmailStr
    password: SecretStr
    full_name: Optional[str] = None
    date_of_birth: Optional[datetime] = None

    _validate_date_of_birth = validator('date_of_birth', allow_reuse=True)(validate_date_in_the_past)

# User login schema


class UserLogin(BaseModel):
    username: EmailStr
    password: SecretStr

# Out data schema


class UserOut(BaseModel):
    id: str
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
