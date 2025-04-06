from fastapi import APIRouter, Depends, HTTPException, Request, status, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import ExpiredSignatureError, JWTError
from sqlalchemy.orm import Session
from datetime import timedelta
import re

from app.core.config import settings
from app.core.constants import REGISTER_DESCRIPTION, LOGIN_DESCRIPTION, ADD_PASSWORD_DESCRIPTION, \
    GET_PASSWORD_DESCRIPTION, INJECTION_SAFE
from app.core.logging_config import logger
from app.db.database import SessionLocal
from app.core.rate_limit import limiter
from app.models.schemas import UserCreate, Token, PasswordCreate, PasswordOut, PasswordAddResponse
from app.repository.user_repo import update_user_record
from app.services import auth_service
from app.repository import password_repo, user_repo
from app.security import encryption_utils
from app.security.jwt_utils import decode_access_token, create_access_token, decode_refresh_token

router = APIRouter()
security = HTTPBearer()


def validate_query_site_username(site_username: str = Query(...)) -> str:
    site_username = site_username.strip()
    if not (settings.MIN_USERNAME_LENGTH <= len(site_username)):
        logger.debug(f"The site username is too short: {len(site_username)}")
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid input.")
    if not re.fullmatch(INJECTION_SAFE, site_username):
        logger.debug(f"The site username is dangerous.")
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid input.")
    return site_username


def validate_query_site_name(site_name: str = Query(...)) -> str:
    site_name = site_name.strip()
    if not re.fullmatch(INJECTION_SAFE, site_name):
        logger.debug(f"The site name is dangerous.")
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid input.")
    return site_name



def get_current_user_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    payload = decode_access_token(token)
    if not payload:
        logger.debug(f"Access token is either invalid or expired.")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")
    return payload

def get_refresh_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    payload = decode_refresh_token(token)
    if not payload:
        logger.debug(f"The refresh token is either invalid or expired.")
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    return payload


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.post("/refresh-token")
@limiter.limit("200/minute")
def refresh_token(request: Request, token: dict = Depends(get_refresh_token), db: Session = Depends(get_db)):
    try:
        if token.get("type") != "refresh" or "sub" not in token:
            logger.debug(f"Refresh token is invalid.")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

        username = token["sub"]
        user = user_repo.get_user_by_username(db, username)
        if not user:
            logger.debug(f"User '{username}' not found.")
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

        new_access_token = create_access_token({"sub": username}, timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
        return {"access_token": new_access_token}

    except ExpiredSignatureError:
        logger.debug(f"Refresh token expired")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token expired")
    except JWTError:
        logger.debug(f"Invalid refresh token.")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")


@router.post("/register", summary="Register a new user", description=REGISTER_DESCRIPTION, response_model=Token)
@limiter.limit("100/minute")
def register(request: Request, user: UserCreate, db: Session = Depends(get_db)):
    registration = auth_service.register_user(db, user.username, user.password)
    if not registration:
        logger.debug(f"User '{user.username}' already exists.")
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="User Already Exist.")

    access, refresh = auth_service.authenticate_user(db, user.username, user.password)
    update_user_record(db, user.username, refresh)
    return Token(access_token=access, refresh_token=refresh)


@router.post("/login", description=LOGIN_DESCRIPTION, response_model=Token)
@limiter.limit("100/minute")
def login(request: Request, user: UserCreate, db: Session = Depends(get_db)):
    tokens = auth_service.authenticate_user(db, user.username, user.password)
    if not tokens:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials.")
    return Token(access_token=tokens[0], refresh_token=tokens[1])


@router.post("/vault/add", description=ADD_PASSWORD_DESCRIPTION, response_model=PasswordAddResponse)
@limiter.limit("150/minute")
def add_password(request: Request, entry: PasswordCreate, token: dict = Depends(get_current_user_token), db: Session = Depends(get_db)):
    username = token["sub"]
    user = auth_service.user_repo.get_user_by_username(db, username)
    if not user:
        logger.debug(f"User {username} not found.")
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    encrypted_site_password = encryption_utils.encrypt_password(entry.site_password)
    record = password_repo.create_password_entry(db, user.id, entry.site_name, entry.site_username, encrypted_site_password)

    return PasswordAddResponse(
        message="Password stored successfully.",
        site_name=entry.site_name,
        created_at=record.created_at.isoformat()
    )


@router.get("/vault/", description=GET_PASSWORD_DESCRIPTION, response_model=PasswordOut)
@limiter.limit("100/minute")
def get_password(request: Request, site_name: str = Depends(validate_query_site_name), site_username: str = Depends(validate_query_site_username), token: dict = Depends(get_current_user_token), db: Session = Depends(get_db)):
    username = token["sub"]
    user = auth_service.user_repo.get_user_by_username(db, username)
    record = password_repo.get_site_password_by_site_username(db, site_name, site_username, user.id)
    if not record:
        logger.debug(f"Site username {site_name} not found.")
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Site username not found for this user")

    return PasswordOut(
        username=username,
        site_name=record.site_name,
        site_username= record.site_username,
        site_password=encryption_utils.decrypt_password(record.encrypted_site_password),
        created_at=record.created_at.isoformat()
    )
