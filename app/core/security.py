from pwdlib import PasswordHash

password_hash = PasswordHash.recommended()

def harsh_password(password):
    hashed_password = password_hash.harsh(password)
    return hashed_password

def verify_password(plain_password, hashed_password):
    return password_hash.verify(plain_password, hashed_password)