from datetime import datetime, date
from typing import Optional
from pydantic import BaseModel, EmailStr, SecretStr, Field, field_validator


class UserCreate(BaseModel):
    username: EmailStr = Field(..., min_length=3, max_length=40, unique=True)
    password: SecretStr = Field(..., min_length=8, max_length=40)
    full_name: Optional[str] = Field(default=None)
    phone_number: Optional[str] = Field(default=None)
    date_of_birth: str = Field(default_factory=lambda: date(1900, 1, 1).isoformat())

    @field_validator('date_of_birth')
    def validate_date_in_the_past(cls, v: str):
        # Parse the date string to a date object
        birth_date = datetime.strptime(v, "%Y-%m-%d").date()
        if birth_date > date.today():
            raise ValueError("Stop cheating and give correct birth date")
        # Return the string representation of the date
        return birth_date.isoformat()

    class Config:
        from_attributes = True
        json_encoders = {
            datetime: lambda dt: dt.isoformat(),
        }
        date_parse_format = '%Y-%m-%d'
        # Pydantic V2 configuration keys
        populate_by_name = True


class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    phone_number: Optional[str] = None
    date_of_birth: str = Field(default_factory=lambda: date(1900, 1, 1).isoformat())
    profile_info: Optional[str] = None


class PasswordUpdate(BaseModel):
    old_password: SecretStr
    new_password: SecretStr


class UserLogin(BaseModel):
    username: EmailStr
    password: SecretStr


class UserOut(BaseModel):
    username: EmailStr
    full_name: Optional[str] = None
    date_of_birth: str = Field(default_factory=lambda: date(1900, 1, 1).isoformat())
    join_date: datetime

    class Config:
        json_encoders = {
            datetime: lambda dt: dt.isoformat(),
        }


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    refresh_token: str
