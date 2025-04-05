from fastapi import FastAPI
from contextlib import asynccontextmanager
import os
import shutil
import redis
from slowapi.errors import RateLimitExceeded
from slowapi import _rate_limit_exceeded_handler

from app.core.config import settings
from app.core.logging_config import logger
from app.core.rate_limit import limiter
from app.api.router import router as api_router
from app.db.database import Base, engine

redis_client = redis.Redis(
    host=settings.REDIS_HOST,
    port=settings.REDIS_PORT,
    db=0,
    decode_responses=True
)

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Creating tables if they don't exist...")
    Base.metadata.create_all(bind=engine)
    logger.info("Tables ready.")
    yield
    logger.info("Cleaning up resources...")

    try:
        redis_client.flushdb()
        logger.info("Flushed Redis cache.")
    except Exception as e:
        logger.info(f"Redis cleanup failed: {e}")

    logger.info(" Shutdown complete.")

app = FastAPI(
    title="Password Vault API",
    docs_url="/password-vault",
    redoc_url=None,
    lifespan=lifespan
)


app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.include_router(api_router)

