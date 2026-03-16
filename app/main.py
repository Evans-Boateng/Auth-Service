from fastapi import FastAPI, Depends, Form, status
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.exceptions import HTTPException
from sqlmodel import Session, select
from typing import Annotated
from .database import create_db_and_tables
from .dependencies import get_session
from .models import User, UserCreate
from .core.security import harsh_password
from contextlib import asynccontextmanager



@asynccontextmanager
async def lifespan(app: FastAPI):
  create_db_and_tables() # this runs before the application starts
  yield

app = FastAPI(lifespan=lifespan)

SessionDp = Annotated[Session, Depends(get_session)]



#testing
@app.get("/test", status_code=200)
async def test():
  return {"message": "success"}

@app.post("/register", status_code=status.HTTP_204_NO_CONTENT)
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



# @app.get("/user")
# async def get_user(session: SessionDp, user: User):
#   statement = select(User).where(user.username) == "Anelka"
#   user_in_db = session.exec(statement)
#   return user_in_db