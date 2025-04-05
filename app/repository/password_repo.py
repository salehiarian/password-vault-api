from datetime import datetime

from fastapi import HTTPException, status
from sqlalchemy import and_
from sqlalchemy.orm import Session

from app.db.models import PasswordEntry

def create_password_entry(db: Session, user_id: int, site_name: str, site_username: str, encrypted_site_password: str):

    if does_password_entry_exist_for_user(db, site_username, user_id):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A password entry for site username '{site_username}' already exists."
        )

    entry = PasswordEntry(
        site_name=site_name,
        site_username=site_username,
        encrypted_site_password=encrypted_site_password,
        owner_id=user_id,
        created_at=datetime.utcnow(),
    )

    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry


def get_site_password_by_site_username(db: Session, site_name: str, site_username: str, user_id: int):
    return db.query(PasswordEntry).filter(
        and_(
            PasswordEntry.site_name == site_name,
            PasswordEntry.site_username == site_username,
            PasswordEntry.owner_id == user_id
        )
    ).first()

def does_password_entry_exist_for_user(db: Session, site_username: str, user_id: int) -> bool:
    return db.query(PasswordEntry).filter(
        and_(
            PasswordEntry.site_username == site_username,
            PasswordEntry.owner_id == user_id
        )
    ).first() is not None