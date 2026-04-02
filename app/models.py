from datetime import datetime
from sqlmodel import SQLModel, Field, Relationship
from pydantic import EmailStr, BaseModel
import uuid


class RefreshToken(SQLModel, table=True):
  id: uuid.UUID | None = Field(default_factory=uuid.uuid4, unique=True, primary_key=True)
  hashed_token: str = Field(unique=True)
  user: "User" = Relationship(back_populates="refresh_tokens")
  user_id: uuid.UUID = Field(foreign_key="user.id", ondelete="CASCADE")
  expires_at: datetime
  is_revoked: bool = False
  

class UserBase(SQLModel):
  username: str = Field(index=True, unique=True)
  email: EmailStr = Field(index=True, unique=True)
  full_name: str

class User(UserBase, table=True):
  id: uuid.UUID | None = Field(default_factory=uuid.uuid4, unique=True, primary_key=True)
  hashed_password: str
  refresh_tokens: RefreshToken | None = Relationship(back_populates="user")

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

class Access_Token(BaseModel):
  access_token: str

