from sqlmodel import create_engine, SQLModel, Field

sql_file = "database.db"
sql_url = f"sqlite:///{sql_file}"
engine = create_engine(sql_url)

def create_db_and_tables():
  SQLModel.metadata.create_all(engine)
 