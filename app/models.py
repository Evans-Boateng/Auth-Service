from sqlmodel import SQLModel, Field
from pydantic import EmailStr
import uuid


class UserBase(SQLModel):
  username: str = Field(index=True, unique=True)
  email: EmailStr = Field(index=True, unique=True)
  full_name: str

class User(UserBase, table=True):
  id: uuid.UUID | None = Field(default_factory=uuid.uuid4, unique=True, primary_key=True)
  hashed_password: str

class UserCreate(UserBase):
  password: str
  
class UserOut(UserBase):
  id: uuid.UUID
  

