from datetime import datetime, timedelta
import uuid
from fastapi import APIRouter, Depends, Form, HTTPException, Response, status
from typing import Annotated

from fastapi.security import OAuth2PasswordRequestForm
from jwt import InvalidTokenError
from pyrate_limiter import Duration, Rate
from sqlmodel import delete, select

from app.core.security import authenticate_user, create_token, harsh_password, hash_token, verify_client, verify_token
from app.dependencies import check_limit, verify_admin_token
from app.dependencies import SessionDp
from app.models import RefreshToken, User
from app.schemas.user import Access_Token, Logout_Data, Refresh_Data, Refresh_Token, Token, UserCreate

router = APIRouter()

@router.post("/admin/users/register", status_code=status.HTTP_204_NO_CONTENT)
async def create_user(data: Annotated[UserCreate, Form()], session: SessionDp, client: Annotated[str, Depends(verify_admin_token)]):
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
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()], session: SessionDp):
  credentials_exception = HTTPException(
    status_code=status.HTTP_400_BAD_REQUEST,
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

@router.post("/token/refresh", response_model=Token, dependencies=[Depends(check_limit(Rate(20, Duration.HOUR * 1)))])
async def refresh_token(request_data: Refresh_Data, session: SessionDp):
  credentials_exception = HTTPException(
    status_code=status.HTTP_403_FORBIDDEN,
    detail="Could not validate credentials"
  )

  client = verify_client(request_data.client_id, request_data.client_secret, session)
  if not client: 
    raise HTTPException(
      detail="Invalid client",
      status_code=status.HTTP_401_UNAUTHORIZED
    )
  
  if request_data.grant_type == "refresh_token":

    try:
      payload = verify_token(request_data.refresh_token)
      if payload.get("type") != "refresh":
        raise credentials_exception
    except InvalidTokenError:
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
  raise HTTPException(
    detail="Unsupported grant_type",
    status_code=status.HTTP_400_BAD_REQUEST
  )

@router.post("/logout", dependencies=[Depends(check_limit(Rate(5, Duration.MINUTE * 15)))])
async def logout(request_data: Logout_Data, session: SessionDp):
  access_exception = HTTPException(
    status_code=401,
    detail = "Access denied"
  )

  client = verify_client(request_data.client_id, request_data.client_secret, session)
  if not client:
    raise HTTPException(
      detail="Invalid client credentials",
      status_code=status.HTTP_401_UNAUTHORIZED
    )

  try:
    payload = verify_token(request_data.refresh_token)
    if payload.get("type") != "refresh":
      raise access_exception
  except InvalidTokenError:
    raise access_exception
  
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

@router.post("/logout-all")
async def logout_all(request_data: Access_Token, session: SessionDp):
  """
  This endpoint basically logs users out from all their devices -
  thus all refresh tokens are deleted from the db
  """
  access_exception = HTTPException(
    status_code=401,
    detail = "Access denied"
  )

  try:
    payload = verify_token(request_data.access_token)
    if payload.get("type") != "access":
      raise access_exception
  except InvalidTokenError:
    raise access_exception
  
  #delete all the refresh tokens associated with the user
  session.exec(
    delete(RefreshToken).where(RefreshToken.user_id == uuid.UUID(payload.get("sub")))
  )
  session.commit()

  return "User logged out from all devices successfully"

@router.delete("/admin/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(user_id: str, session: SessionDp, token: Annotated[str, Depends(verify_admin_token)]):
  user = session.get(User, user_id)
  if not user:
    raise HTTPException(
      detail="User does not exist",
      status_code= status.HTTP_400_BAD_REQUEST
    )
  
  session.delete(user)