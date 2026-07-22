from typing import Annotated
from fastapi import Depends, HTTPException, status
from jwt import InvalidTokenError
from sqlmodel import Session, select, SQLModel

from app.models import Client
from .database import engine
from .core.security import verify_token
from pyrate_limiter import Limiter, Rate
from fastapi_limiter.depends import RateLimiter
from fastapi.security import HTTPAuthorizationCredentials, HTTPBasic, HTTPBearer


def get_session():
  with Session(engine) as session:
    yield session

SessionDp = Annotated[Session, Depends(get_session)]

security = HTTPBearer()


def check_limit(rate: Rate):
  return RateLimiter(limiter=Limiter(rate))

def get_or_create(session, model: SQLModel, id: str) -> tuple:
  """
  Returns a 2-tuple: (object, created_boolean). The boolean indicates if a new object was created (True) or if it already existed (False).
  """
  # get the object
  instance = session.get(model, id)
  if instance:
    return instance, False
  else:
    instance = model(id=id) 
    session.add(instance)
    session.commit()
    session.refresh(instance)
    return instance, True
  
def verify_admin_token(credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)], session):
  credentials_exception = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Invalid token",
    headers={"WWW-Authenticate": "Bearer"},
  )
  token = credentials.credentials
  try:
    payload = verify_token(token)
    if payload.get("type") != "access" and payload.get("role") != "master":
      raise credentials_exception
  except InvalidTokenError:
    raise credentials_exception
  
  client = session.exec(
    select(Client).where(Client.id == payload.get("sub"))
  )
  if not client:
    credentials_exception
  
  return client

  # return {"credentials": credentials.credentails, "scheme": credentials.scheme}