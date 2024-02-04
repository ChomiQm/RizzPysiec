from datetime import datetime
from typing import Optional, List
from bson import ObjectId
from pydantic import BaseModel, Field, EmailStr, validator


class PyObjectId(ObjectId):
    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v):
        if not ObjectId.is_valid(v):
            raise ValueError(f"Invalid ObjectId: {v}")
        return ObjectId(v)

    @classmethod
    def __modify_schema__(cls, field_schema):
        field_schema.update(type="string")


class UserInDB(BaseModel):
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    username: EmailStr
    hashed_password: str
    full_name: Optional[str] = None
    join_date: datetime = Field(default_factory=datetime.utcnow)
    is_active: bool = Field(default=True)
    roles: List[str] = []
    phone_number: Optional[str] = None
    profile_info: Optional[str] = None
    date_of_birth: Optional[datetime] = None
    last_activity: Optional[datetime] = None

    class Config:
        allow_population_by_field_name = True
        json_encoders = {ObjectId: str}
        schema_extra = {
            "example": {
                "username": "pysiec@google.com",
                "hashed_password": "HashedPassword",
                "full_name": "Jan Kowalski",
                "join_date": datetime.utcnow().isoformat(),
                "is_active": True,
                "roles": ["user"],
                "phone_number": "123-456-789",
                "profile_info": "Some info about user",
                "date_of_birth": "1990-01-01T00:00:00",
                "last_activity": datetime.utcnow().isoformat(),
            }
        }

    # date of birth validator
    @validator('date_of_birth')
    def validate_date_of_birth(self, v):
        if v and v > datetime.utcnow():
            raise ValueError('Date of birth must be in the past')
        return v
