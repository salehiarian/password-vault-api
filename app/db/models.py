from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, func
from sqlalchemy.orm import relationship
from app.db.database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password_hash = Column(String)
    refresh_token = Column(String, nullable=True)
    created_at = Column(DateTime, server_default=func.now())
    passwords = relationship("PasswordEntry", back_populates="owner")

class PasswordEntry(Base):
    __tablename__ = "password_entries"

    id = Column(Integer, primary_key=True, index=True)
    site_name = Column(String)
    site_username = Column(String)
    encrypted_site_password = Column(String)
    owner_id = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime, server_default=func.now())

    owner = relationship("User", back_populates="passwords")