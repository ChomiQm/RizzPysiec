from datetime import datetime
from typing import Optional, List
from bson import ObjectId
from pydantic import BaseModel, Field, EmailStr


class UserInDB(BaseModel):
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
