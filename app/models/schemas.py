import re
from pydantic import BaseModel, field_validator, Field
from app.core.config import settings
from app.core.constants import INJECTION_SAFE, PASSWORD_SAFE


def validate_safe_username(value: str) -> str:
    value = value.strip()
    if not (settings.MIN_USERNAME_LENGTH <= len(value)):
        raise ValueError("Invalid input.")
    if not re.fullmatch(INJECTION_SAFE, value):
        raise ValueError("Invalid input.")
    return value


def validate_safe_password(value: str) -> str:
    value = value.strip()
    if not (settings.MIN_PASSWORD_LENGTH <= len(value)):
        raise ValueError("Invalid input.")
    if not re.fullmatch(INJECTION_SAFE, value):
        raise ValueError("Invalid input.")
    if not re.fullmatch(PASSWORD_SAFE, value):
        raise ValueError("Invalid input.")
    return value


class UserCreate(BaseModel):
    username: str
    password: str

    @field_validator("username", mode="before")
    @classmethod
    def validate_username(cls, value):
        return validate_safe_username(value)

    @field_validator("password", mode="before")
    @classmethod
    def validate_password(cls, value):
        return validate_safe_password(value)


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class PasswordCreate(BaseModel):
    site_name: str
    site_username: str
    site_password: str

    @field_validator("site_name", mode="before")
    @classmethod
    def validate_site_name(cls, value):
        value = value.strip()
        if not re.fullmatch(INJECTION_SAFE, value):
            raise ValueError("Invalid input.")
        return value

    @field_validator("site_username", mode="before")
    @classmethod
    def validate_username(cls, value):
        return validate_safe_username(value)

    @field_validator("site_password", mode="before")
    @classmethod
    def validate_password(cls, value):
        return validate_safe_password(value)

class PasswordOut(BaseModel):
    username: str
    site_name: str
    site_username: str
    site_password: str
    created_at: str

class PasswordAddResponse(BaseModel):
    message: str
    site_name: str
    created_at: str
