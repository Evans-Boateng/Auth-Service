from sqlmodel import Session

def get_session(engine):
  with Session(engine) as session:
    yield session