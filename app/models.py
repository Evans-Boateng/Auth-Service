from datetime import datetime
from sqlmodel import SQLModel, Field, Relationship, UniqueConstraint
from pydantic import EmailStr, BaseModel
import uuid

from app.schemas.user import UserBase


class Client(SQLModel, table=True):
  id: str = Field(primary_key=True, unique=True)
  hashed_secret: str
  name: str = Field(unique=True)
  roles: list["Role"] | None = Relationship(back_populates="client")

class Role(SQLModel, table=True):
  __table_args__ = (UniqueConstraint("client_id", "name"),)

  id: uuid.UUID | None = Field(default_factory=uuid.uuid4, unique=True, primary_key=True)
  client_id: str = Field(foreign_key="client.id", ondelete="CASCADE")
  client: Client = Relationship(back_populates="roles")
  name: str = Field(index=True)


class UserRole(SQLModel, table=True):
  __tablename__ = "user_roles"

  user_id: uuid.UUID = Field(foreign_key="user.id", ondelete="CASCADE", primary_key=True)
  role_id: uuid.UUID = Field(foreign_key="role.id", ondelete="CASCADE", primary_key=True)

class RefreshToken(SQLModel, table=True):
  id: uuid.UUID | None = Field(default_factory=uuid.uuid4, unique=True, primary_key=True)
  hashed_token: str = Field(unique=True)
  user: "User" = Relationship(back_populates="refresh_tokens")
  user_id: uuid.UUID = Field(foreign_key="user.id", ondelete="CASCADE")
  expires_at: datetime
  is_revoked: bool = False

class User(UserBase, table=True):
  id: uuid.UUID | None = Field(default_factory=uuid.uuid4, unique=True, primary_key=True)
  hashed_password: str
  refresh_tokens: RefreshToken | None = Relationship(back_populates="user")
  created_at: datetime | None = Field(default_factory=datetime.now)
  updated_at: datetime | None = Field(default_factory=datetime.now)


