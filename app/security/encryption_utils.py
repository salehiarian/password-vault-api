from cryptography.fernet import Fernet
from app.core.config import settings
import base64

key = base64.urlsafe_b64encode(settings.SECRET_KEY[:32].encode())
fernet = Fernet(key)

def encrypt_password(password: str) -> str:
    return fernet.encrypt(password.encode()).decode()

def decrypt_password(encrypted: str) -> str:
    return fernet.decrypt(encrypted.encode()).decode()