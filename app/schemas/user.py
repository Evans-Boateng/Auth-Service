from datetime import datetime, timezone
import uuid
from pydantic import EmailStr, Field, BaseModel
from sqlmodel import SQLModel


class UserBase(SQLModel):
  username: str = Field(index=True, unique=True)
  email: EmailStr = Field(index=True, unique=True)
  full_name: str

class UserCreate(UserBase):
  password: str
  
class UserOut(UserBase):
  id: uuid.UUID

class Token(BaseModel):
  access_token: str
  refresh_token: str | None = None
  token_type: str
  access_token_exiry: datetime
  refresh_token_expiry: datetime

class Refresh_Token(BaseModel):
  refresh_token: str

class Logout_Data(BaseModel):
  refresh_token: str
  client_id: str
  client_secret: str

class Refresh_Data(BaseModel):
  client_id: str
  client_secret: str
  refresh_token: str
  grant_type: str

class Access_Token(BaseModel):
  access_token: str

class PasswordReset(BaseModel):
  type: str
  value: str