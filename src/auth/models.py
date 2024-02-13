from datetime import datetime, date
from typing import Optional, List
from bson import ObjectId
from pydantic import BaseModel, Field, EmailStr


class UserInDB(BaseModel):
    username: EmailStr
    hashed_password: str
    full_name: Optional[str] = None
    join_date: datetime = Field(default_factory=datetime.utcnow)
    is_active: bool = Field(default=False)
    roles: List[str] = []
    phone_number: Optional[str] = None
    profile_info: Optional[str] = None
    date_of_birth: str = Field(default_factory=lambda: date(1900, 1, 1).isoformat())
    last_activity: Optional[datetime] = None
    account_confirmed: bool = Field(default=False)
    failed_login_attempts: int = 0
    lockout_time: Optional[datetime] = None
    last_failed_login_attempt: Optional[datetime] = None
    two_fa_qr_secret: Optional[str] = None
    two_fa_email_code: Optional[str] = None
    two_fa_email_code_generated_at: Optional[datetime] = None
    two_fa_email_enabled: bool = Field(default=False)

    class Config:
        populate_by_name = True
        json_encoders = {ObjectId: str}
        json_schema_extra = {
            "example": {
                "username": "pysiec@google.com",
                "hashed_password": "HashedPassword",
                "full_name": "Jan Kowalski",
                "join_date": datetime.utcnow().isoformat(),
                "is_active": False,
                "roles": ["user"],
                "phone_number": "123-456-789",
                "profile_info": "Some info about user",
                "date_of_birth": "1990-01-01",
                "last_activity": datetime.utcnow().isoformat(),
                "account_confirmed": False,
            }
        }
