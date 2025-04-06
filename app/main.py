from fastapi import FastAPI
from contextlib import asynccontextmanager
from slowapi.errors import RateLimitExceeded
from slowapi import _rate_limit_exceeded_handler

from app.core.logging_config import logger
from app.core.rate_limit import limiter
from app.api.router import router as api_router
from app.db.database import Base, engine

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Creating tables if they don't exist...")
    Base.metadata.create_all(bind=engine)
    logger.info("Tables ready.")
    yield

app = FastAPI(
    title="Password Vault API",
    docs_url="/password-vault",
    redoc_url=None,
    lifespan=lifespan
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.include_router(api_router)


@app.get("/")
def read_root():
    return {"message": "Welcome to the Password Vault API 👋"}


