import base64
import os
from dotenv import load_dotenv

load_dotenv()

DUMMY_HASH = os.getenv("DUMMY_HASH")
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("JWT_ALGORITHM")
encoded_key = os.getenv("PRIVATE_KEY_B64")
PRIVATE_KEY = base64.b64decode(encoded_key)
encoded_public_key = os.getenv("PUBLIC_KEY_B64")
PUBLIC_KEY = base64.b64decode(encoded_public_key)