from fastapi import FastAPI, Depends
from sqlmodel import Session
from typing import Annotated
from .database import create_db_and_tables, engine
from .dependencies import get_session



app = FastAPI()

SessionDp = Annotated[Session, Depends(get_session(engine))]

@app.on_event("startup")
def on_startup():
  create_db_and_tables

#testing
@app.get("/test", status_code=200)
async def test():
  return {"message": "success"}
