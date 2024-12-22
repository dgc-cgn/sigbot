from pydantic_settings import BaseSettings

REDIR_PREFIX = "/r"

class Settings(BaseSettings):
    REDIS_SERVER: str = "not set"
    