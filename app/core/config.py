from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    DATABASE_URL: str
    SECRET_KEY: str
    JWT_ALGORITHM: str
    ACCESS_TOKEN_EXPIRE_MINUTES: int
    REFRESH_TOKEN_EXPIRE_MINUTES: int
    REDIS_HOST: str
    REDIS_PORT: int
    MIN_PASSWORD_LENGTH: int
    MIN_USERNAME_LENGTH: int

    model_config = SettingsConfigDict(env_file=".env")

settings = Settings()

