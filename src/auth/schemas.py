from datetime import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr, SecretStr, validator

# Schema to create usr


class UserCreate(BaseModel):
    username: EmailStr
    password: SecretStr
    full_name: Optional[str] = None
    date_of_birth: Optional[datetime] = None

    # BirthDate validator
    @validator('date_of_birth')
    def validate_date_of_birth(self, v):
        if v and v > datetime.utcnow():
            raise ValueError('Date of birth must be in the past')
        return v

# Login schema


class UserLogin(BaseModel):
    username: EmailStr
    password: SecretStr

# out user data


class UserOut(BaseModel):
    id: str
    username: EmailStr
    full_name: Optional[str] = None
    date_of_birth: Optional[datetime] = None
    join_date: datetime

    # Pydantic cfg
    class Config:
        json_encoders = {
            datetime: lambda dt: dt.isoformat(),
        }

# Update user schema


class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    phone_number: Optional[str] = None
    profile_info: Optional[str] = None
    date_of_birth: Optional[datetime] = None
    # we can add more info to update

    @validator('date_of_birth')
    def validate_date_of_birth(self, v):
        if v and v > datetime.utcnow():
            raise ValueError('Date of birth must be in the past')
        return v


class Token(BaseModel):
    access_token: str
    token_type: str
