from fastapi import FastAPI, Depends, Form, status, APIRouter, Cookie
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.exceptions import HTTPException
from fastapi.responses import Response
from sqlmodel import Session, select
from typing import Annotated
from .database import create_db_and_tables
from .dependencies import get_session
from .models import User, UserCreate, Token, RefreshToken, Refresh_Token
from .core.security import harsh_password, authenticate_user, create_token, hash_token, verify_token, check_limit
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
import hashlib
from jwt import InvalidTokenError
from pyrate_limiter import Rate, Duration



# @asynccontextmanager
# async def lifespan(app: FastAPI):
#   redis = await aioredis.from_url("redis://localhost:6379") # this runs before the application starts
#   yield

app = FastAPI()

router = APIRouter(prefix="/auth")

SessionDp = Annotated[Session, Depends(get_session)]

# Rate(2, Duration.SECOND * 5)



#testing
@router.get("/test", status_code=200)
async def test():
  return {"message": "success"}

@router.post("/register", status_code=status.HTTP_204_NO_CONTENT)
async def create_user(data: Annotated[UserCreate, Form()], session: SessionDp):
  credentails_exception = HTTPException(
    status_code = status.HTTP_400_BAD_REQUEST,
    detail= "Username or email already exists"
  )

  #now we hash the password and validate the request data with model_validate
  hashed_password = harsh_password(data.password)
  user = User.model_validate(data, update={"hashed_password": hashed_password})

  #check if the username or email already exists
  existing_username = session.exec(
    select(User).where(User.username == data.username)
  ).first()
  
  existing_email = session.exec(
    select(User).where(User.email == data.email)
  ).first()

  if existing_username or existing_email:
    raise credentails_exception
  
  session.add(user)
  session.commit()
  session.refresh(user)

@router.post("/token", response_model=Token, dependencies=[Depends(check_limit(Rate(5, Duration.MINUTE * 15)))])
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()], session: SessionDp, response: Response):
  credentials_exception = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Invalid username or password"
  )
  user = authenticate_user(username=form_data.username, password=form_data.password, session=session)
  if not user: 
    raise credentials_exception
  
  access_token_expiry = timedelta(minutes=7)
  refresh_token_expiry = timedelta(days=7)

  access_token = create_token(
    data={
      "sub": str(user.id),
      "username": user.username,
      "email": user.email,
      "type": "access"
    },
    expires_delta=access_token_expiry,
    type="access"
  )
  refresh_token = create_token(
    data={
      "sub": str(user.id),
      "type": "refresh"
    },
    expires_delta=refresh_token_expiry,
    type="refresh"
  )
  
  refresh_token_in_db = RefreshToken(
    hashed_token=hash_token(refresh_token),
    user_id=user.id,
    expires_at = datetime.now() + refresh_token_expiry
  )

  session.add(refresh_token_in_db)
  session.commit()
  token = Token(access_token=access_token, refresh_token=refresh_token, token_type="Bearer", access_token_exiry=datetime.now() + access_token_expiry, refresh_token_expiry=datetime.now() + refresh_token_expiry)
  return token

@router.post("/token/refresh/", response_model=Token, dependencies=[Depends(check_limit(Rate(20, Duration.HOUR * 1)))])
async def refresh_token(request_data: Refresh_Token, session: SessionDp, response: Response):
  credentials_exception = HTTPException(
    status_code=status.HTTP_403_FORBIDDEN,
    detail="Could not validate credentials"
  )

  payload = verify_token(request_data.refresh_token)
  if payload.get("type") != "refresh":
    raise credentials_exception

  refresh_in_db = session.exec(
    select(RefreshToken).where(RefreshToken.hashed_token == hash_token(request_data.refresh_token))
  ).first()

  if not refresh_in_db or refresh_in_db.is_revoked:
    raise credentials_exception
  
  #here we check if the user actually exists in the db
  user = session.get(User, refresh_in_db.user_id)
  if not user:
    raise credentials_exception
  
  #create the new access token and refresh token and delete the old refresh token(refresh rotation)
  access_token_expiry = timedelta(minutes=7)
  refresh_token_expiry = timedelta(days=7)

  new_access_token = create_token(
    data={
      "sub": str(user.id),
      "username": user.username,
      "email": user.email,
      "type": "access"
    },
    expires_delta= access_token_expiry,
    type="access"
  )
  new_refresh_token = create_token(
    data={
      "sub": str(user.id),
      "type": "refresh"
    },
    expires_delta= refresh_token_expiry,
    type="refresh"
  )
  
  session.delete(refresh_in_db)

  new_stored_refresh_token = RefreshToken(
    user_id=user.id,
    hashed_token=hash_token(new_refresh_token),
    expires_at = datetime.now() + refresh_token_expiry
  )
  session.add(new_stored_refresh_token)
  session.commit()

  token = Token(access_token=new_access_token, refresh_token=new_refresh_token, access_token_exiry= datetime.now() + access_token_expiry, refresh_token_expiry=datetime.now() + refresh_token_expiry, token_type="Bearer") 

  return token

@router.post("/logout/", dependencies=[Depends(check_limit(Rate(5, Duration.MINUTE * 15)))])
async def logout(request_data: Refresh_Token, session: SessionDp):
  access_exception = HTTPException(
    status_code=401,
    detail = "Access denied"
  )

  try:
    payload = verify_token(request_data.refresh_token)
    if payload.get("type") != "refresh":
      raise access_exception
  except InvalidTokenError:
    access_exception
  
  refresh_in_db = session.exec(
    select(RefreshToken).where(RefreshToken.hashed_token == hash_token(request_data.refresh_token))
  ).first()
  if not refresh_in_db or refresh_in_db.is_revoked:
    raise access_exception
  
  #revoke the token and commit to database
  refresh_in_db.is_revoked = True
  session.add(refresh_in_db)
  session.commit()

  return "User logged out successfully"

app.include_router(router)