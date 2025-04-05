from slowapi import Limiter
from slowapi.util import get_remote_address
from app.core.config import settings

redis_uri = f"redis://{settings.REDIS_HOST}:{settings.REDIS_PORT}"

limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=redis_uri
)
