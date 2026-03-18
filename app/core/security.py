from pwdlib import PasswordHash
from fastapi import HTTPException
from sqlmodel import select
from datetime import datetime, timedelta
from ..models import User
import os
import jwt
from dotenv import load_dotenv

load_dotenv()

DUMMY_HASH = os.getenv("DUMMY_HASH")
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("JWT_ALGORITHM")


password_hash = PasswordHash.recommended()

def harsh_password(password):
    hashed_password = password_hash.hash(password)
    return hashed_password

def verify_password(plain_password, hashed_password):
    return password_hash.verify(plain_password, hashed_password)

def get_user(username, session):
    statement = select(User).where(User.username == username)
    user = session.exec(statement).first()
    return user

def authenticate_user(username: str, password: str, session):
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
        expire = datetime.now + timedelta(minutes=7)
    elif type == "refresh":
        expire = datetime.now + timedelta(days=7)

    #here I'm adding expiration claim to the payload
    to_encode.update({"exp": expire})

    #encode and sign the token here
    encoded_jwt = jwt.encode(
        to_encode,
        SECRET_KEY,
        ALGORITHM
    )
    return encoded_jwt
     