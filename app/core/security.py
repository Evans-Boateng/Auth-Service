from pwdlib import PasswordHash
from fastapi import HTTPException
from sqlmodel import select
from datetime import datetime, timedelta
from ..models import User
import os
import jwt
from dotenv import load_dotenv
import hashlib
import base64
from fastapi_limiter.depends import RateLimiter
from pyrate_limiter import Limiter, Rate
import secrets

load_dotenv()

DUMMY_HASH = os.getenv("DUMMY_HASH")
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("JWT_ALGORITHM")
encoded_key = os.getenv("PRIVATE_KEY_B64")
PRIVATE_KEY = base64.b64decode(encoded_key)
encoded_public_key = os.getenv("PUBLIC_KEY_B64")
PUBLIC_KEY = base64.b64decode(encoded_public_key)


password_hash = PasswordHash.recommended()

def generate_client_credentials():
    client_id = secrets.token_hex(12)
    client_secret = secrets.token_urlsafe(32)
    return client_id,  client_secret

def harsh_password(password):
    hashed_password = password_hash.hash(password)
    return hashed_password

def verify_password(plain_password, hashed_password):
    return password_hash.verify(plain_password, hashed_password)

def hash_token(token:str):
    return hashlib.sha256(token.encode()).hexdigest()


def get_user(username, session):
    statement = select(User).where(User.username == username)
    user = session.exec(statement).first()
    return user

def authenticate_user(username: str, password: str, session):
    """
    This function authenticates the user by making sure the response time is the same
    whether user is valid or not and thus to prevent timing attacks
    """
    user = get_user(username, session)
    if not user:
       #here, were making sure that the endpoint takes the same time to respond, whether the user is valid or not
       #and that kinda confuse attackers by preventing timing attacks that could be use identify which username they tried is an actual user
       verify_password(plain_password=password, hashed_password=DUMMY_HASH)
       return False
    if not verify_password(plain_password=password, hashed_password=user.hashed_password):
        return False
    return user

def create_token(data: dict, expires_delta: datetime | None, type: str):
    to_encode = data.copy()
    
    if expires_delta: 
        expire = datetime.now() + expires_delta
    elif type == "access":
        expire = datetime.now() + timedelta(minutes=7)
    elif type == "refresh":
        expire = datetime.now() + timedelta(days=7)

    #here I'm adding expiration claim to the payload
    to_encode.update({"exp": expire})

    #encode and sign the token here
    #I used RS256 because this is a distributed service
    encoded_jwt = jwt.encode(
        to_encode,
        PRIVATE_KEY,
        ALGORITHM
    )
    return encoded_jwt

def verify_token(token: str):
    return jwt.decode(token, PUBLIC_KEY, algorithms=[ALGORITHM])

def check_limit(rate: Rate):
  return RateLimiter(limiter=Limiter(rate))
     