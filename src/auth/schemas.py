from datetime import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr, SecretStr, Field, validator
import pytz


class UserCreate(BaseModel):
    username: EmailStr
    password: SecretStr
    full_name: Optional[str] = Field(default=None)
    phone_number: Optional[str] = Field(default=None)
    date_of_birth: Optional[datetime] = Field(default=None)

    @validator('date_of_birth', pre=True, allow_reuse=True)
    def validate_date_in_the_past(self, v):
        if v is not None:
            utc = pytz.UTC
            now_aware = datetime.utcnow().replace(tzinfo=utc)
            if v.tzinfo is None or v.tzinfo.utcoffset(v) is None:
                raise ValueError("Data urodzenia musi być świadoma strefy czasowej")
            v = v.astimezone(utc)
            if v > now_aware:
                raise ValueError('Data musi być w przeszłości')
        return v

    class Config:
        orm_mode = True
        json_encoders = {
            datetime: lambda dt: dt.isoformat(),
        }
        populate_by_name = True


class UserUpdate(UserCreate):
    # Nie trzeba ponownie definiować walidatora, jeśli jest on już w UserCreate
    pass


class UserLogin(BaseModel):
    username: EmailStr
    password: SecretStr


class UserOut(BaseModel):
    username: EmailStr
    full_name: Optional[str] = None
    date_of_birth: Optional[datetime] = None
    join_date: datetime

    class Config:
        json_encoders = {
            datetime: lambda dt: dt.isoformat(),
        }


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    refresh_token: str
    expires_in: int  # Access token expires in seconds
