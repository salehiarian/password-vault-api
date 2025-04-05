from app.repository import user_repo
from app.security.hash_utils import hash_password, verify_password
from app.security.jwt_utils import create_access_token, create_refresh_token
from datetime import timedelta
from app.core.config import settings

def register_user(db, username, password):
    existing_user = user_repo.get_user_by_username(db, username)
    if existing_user:
        return None
    return user_repo.create_user(db, username, hash_password(password))

def authenticate_user(db, username, password):
    user = user_repo.get_user_by_username(db, username)
    if not user or not verify_password(password, user.password_hash):
        return None
    access = create_access_token({"sub": user.username}, timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    refresh = create_refresh_token({"sub": user.username}, timedelta(minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES))
    return access, refresh