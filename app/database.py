from sqlmodel import create_engine, SQLModel, Field

sql_file = "database.db"
sql_url = f"sqlite:///{sql_file}"

connect_args = {"check_same_thread": False} # this argument allows fastapi to use the same SQLite in different threads
engine = create_engine(sql_url, connect_args=connect_args)

def create_db_and_tables():
  SQLModel.metadata.create_all(engine)
 