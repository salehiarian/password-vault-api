from sqlalchemy.orm import Session
from app.db.models import User

def get_user_by_username(db: Session, username: str):
    return db.query(User).filter(
        User.username == username,
    ).first()


def create_user(db: Session, username: str, password_hash: str):
    user = User(username=username, password_hash=password_hash)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def update_user_record(db: Session, username: str, refresh_token: str):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        return None

    user.refresh_token = refresh_token
    db.commit()
    db.refresh(user)
    return user


