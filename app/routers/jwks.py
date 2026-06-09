from app.core.config import PUBLIC_KEY
from cryptography.hazmat.primitives import serialization
import base64
from fastapi import APIRouter

router = APIRouter()

public_key_bytes = PUBLIC_KEY
public_key_object = serialization.load_pem_public_key(public_key_bytes)

def get_jwks_dict():
  

  public_numbers = public_key_object.public_numbers()

  # Helper to base64url encode integers (required for JWK structure)
  def b64url_encode(val: int) -> str:
    bytes_val = val.to_bytes((val.bit_length() + 7) // 8, byteorder='big')
    return base64.urlsafe_b64encode(bytes_val).decode('utf-8').rstrip('=')
  
  return {
    "kty": "RSA",
    "use": "sig",
    "alg": "RS256",
    "kid": "auth-v1",
    "n": b64url_encode(public_numbers.n), # The modulus string
    "e": b64url_encode(public_numbers.e)  # The exponent string
  }

@router.get("/.well-known/jwks.json")
async def get_singing_key():
  return {
    "keys": [
      get_jwks_dict()
    ]
  }

