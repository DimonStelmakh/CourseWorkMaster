from pydantic_settings import BaseSettings
from functools import lru_cache
from typing import Optional


class Settings(BaseSettings):
    # Database
    database_url: str = "postgresql://pba_user:pba_secret_password@localhost:5432/passive_biometric_auth"
    
    # Redis
    redis_url: str = "redis://:redis_secret@localhost:6379/0"
    
    # Security
    secret_key: str = "your-super-secret-key-change-in-production"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    
    # TOTP
    totp_issuer: str = "PassiveBiometricAuth"
    
    # Trust Score
    trust_score_threshold: float = 0.7
    min_training_samples: int = 30
    
    # Session
    session_timeout_minutes: int = 30
    max_failed_login_attempts: int = 5
    account_lockout_minutes: int = 30
    
    # Email
    smtp_host: Optional[str] = None
    smtp_port: int = 587
    smtp_user: Optional[str] = None
    smtp_password: Optional[str] = None
    
    # ML Models
    ml_models_path: str = "/app/ml_models"
    
    class Config:
        env_file = ".env"
        case_sensitive = False


@lru_cache()
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
