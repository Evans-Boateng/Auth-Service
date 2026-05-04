from sqlmodel import Session
from .database import engine
from pyrate_limiter import Limiter, Rate
from fastapi_limiter.depends import RateLimiter

def get_session():
  with Session(engine) as session:
    yield session

def check_limit(rate: Rate):
  return RateLimiter(limiter=Limiter(rate))