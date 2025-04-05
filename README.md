# 🔐 Password Vault API

A secure, RESTful API built with FastAPI for managing and encrypting personal credentials.

## 🚀 Features
- JWT authentication (access & refresh tokens)
- Bcrypt password hashing
- AES-256 password encryption
- Tag-based password organization
- Rate limiting on sensitive routes
- Clean, maintainable architecture

## 🧰 Tech Stack
- Python 3.11
- FastAPI
- PostgreSQL
- SQLAlchemy
- Docker + Docker Compose
- Render (Free HTTPS Hosting)

## 📦 API Endpoints
- `POST /register`: Register a user
- `POST /login`: Log in
- `POST /vault/add`: Add a site password (auth required)
- `GET /vault/`: Retrieve a saved password (auth required)
- `POST /refresh-token`: Get a new access token

## 🔐 Security
- All traffic is encrypted via HTTPS
- Passwords stored encrypted with AES-256 (Fernet)
- Access protected via JWT
- Rate-limiting protects against brute force attacks
