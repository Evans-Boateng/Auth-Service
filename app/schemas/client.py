from pydantic import BaseModel


class ClientIn(BaseModel):
  client_id: str
  client_secret: str
  grant_type: str