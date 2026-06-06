from fastapi import FastAPI, Depends, Form, status, APIRouter, Cookie
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.exceptions import HTTPException
from fastapi.responses import Response
from sqlmodel import Session, select, delete
from typing import Annotated

from app.schemas.client import ClientIn
from .database import create_db_and_tables
from .dependencies import SessionDp, get_session, check_limit
from .models import User, RefreshToken, Client, Role, UserRole
from .schemas.user import UserCreate, Token, Refresh_Token, Access_Token
from .core.security import harsh_password, authenticate_user, create_token, hash_token, verify_password, verify_token, generate_client_credentials
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
import hashlib
from jwt import InvalidTokenError
from pyrate_limiter import Rate, Duration
import uuid
from uuid import UUID
from sqlalchemy.exc import IntegrityError
from .routers import users

# @asynccontextmanager
# async def lifespan(app: FastAPI):
#   redis = await aioredis.from_url("redis://localhost:6379") # this runs before the application starts
#   yield

app = FastAPI()

router = APIRouter(prefix="/auth")

#testing
@router.get("/test", status_code=200)
async def test():
  return {"message": "success"}

@router.post("/admin/clients", status_code=200)
async def create_new_client(name: str, session: SessionDp):
  client_id, client_secret = generate_client_credentials()

  name_in_db = session.exec(
    select(Client).where(Client.name == name )
  ).first()
  if name_in_db:
    raise HTTPException(
      detail="Cannot create multiple clients with the same name",
      status_code=status.HTTP_400_BAD_REQUEST
    )
  
  hashed_secret = harsh_password(client_secret)
  
  client = Client(
    id = client_id,
    hashed_secret = hashed_secret,
    name = name
  )

  session.add(client)
  session.commit()

  return {"client_id": client_id, "client_secret": client_secret}

@router.post("/admin/clients/token", response_model=Access_Token, status_code=status.HTTP_200_OK)
async def login_admin(request_data: ClientIn, session: SessionDp):
  credentails_exception = HTTPException(
    detail="Invalid client",
    status_code=status.HTTP_401_UNAUTHORIZED
  )
  client = session.exec(
    select(Client).where(Client.id == request_data.client_id)
  ).first()
  if not client:
    raise credentails_exception
  
  if not verify_password(plain_password=request_data.client_secret, hashed_password=client.hashed_secret):
    raise credentails_exception
  
  if request_data.grant_type == "client_credentials":
    access_token_expiry = timedelta(minutes=1)

    access_token = create_token(
      data={
        "sub": str(client.id),
        "iss": client.name,
        "type": "access",
        "role": "master"
      },
      expires_delta=access_token_expiry,
      type="access"
    )
    return (Access_Token(access_token=access_token))
  
  raise HTTPException(
    detail="Invalid grant type",
    status_code=status.HTTP_400_BAD_REQUEST
  )
    

@router.post("/admin/clients/roles", status_code=status.HTTP_200_OK)
async def create_new_role(name: str, client_id: str, session: SessionDp):

  #check if client exists
  client = session.exec(
    select(Client).where(Client.id == client_id)
  ).first()

  if not client:
    raise HTTPException(
      detail="Client does not exist",
      status_code=status.HTTP_401_UNAUTHORIZED
    )
  
  try:
    new_role = Role(
      name = name,
      client = client
    )
    session.add(new_role)
    session.commit()
  except Exception as e:
    raise HTTPException(
      detail="Cannot create multiple roles with the same",
      status_code= status.HTTP_409_CONFLICT
    )

  return {"role": new_role.name, "client": new_role.client_id}

@router.delete("/admin/clients/{client_name}/delete")
async def delete_client(client_name:str, session: SessionDp):
  session.exec(
    delete(Client).where(Client.name == client_name)
  )
  session.commit()
  
  return {"message": "Client deleted"}

@router.post("/admin/clients/{client_id}/users/{user_id}/roles")
async def assign_role(client_id: str, user_id: UUID, roles: list[str], session: SessionDp):
  unauthorized_exception = HTTPException(
    status_code=status.HTTP_400_BAD_REQUEST,
    detail="User does not exist"
  )
  #check if user exists
  user = session.get(User, user_id)
  if not user:
    raise unauthorized_exception
  
  client = session.get(Client, client_id)
  if not client:
    raise HTTPException(
      detail="Client does not exist",
      status_code=status.HTTP_401_UNAUTHORIZED
    )
  
  for role in roles:
    role_in_db = session.exec(
      select(Role).where(Role.name == role)
    ).first()

    if role_in_db not in client.roles:
      raise HTTPException(
        detail=f"The role {role} does not exist",
        status_code=status.HTTP_409_CONFLICT
      )
    try:
      user_role = UserRole(
        user_id=user_id,
        role_id = role_in_db.id
      )
      session.add(user_role)
      session.commit()
      session.refresh(user_role)
    except IntegrityError:
      session.rollback()
      raise HTTPException(
        detail=f"The role {role} is already assigned to user",
        status_code = status.HTTP_400_BAD_REQUEST
      )

  return {"roles":roles, "client": client.roles }



app.include_router(router)
app.include_router(users.router)