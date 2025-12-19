from sqlalchemy import (
    Column, String, Boolean, DateTime, Float, Integer, 
    ForeignKey, Text, ARRAY
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import uuid
import enum

from app.core.database import Base


class UserRole(str, enum.Enum):
    USER = "USER"
    ADMIN = "ADMIN"


class EventType(str, enum.Enum):
    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILED = "LOGIN_FAILED"
    LOGOUT = "LOGOUT"
    MFA_TRIGGERED = "MFA_TRIGGERED"
    MFA_SUCCESS = "MFA_SUCCESS"
    MFA_FAILED = "MFA_FAILED"
    ANOMALY_DETECTED = "ANOMALY_DETECTED"
    PASSWORD_RESET_REQUESTED = "PASSWORD_RESET_REQUESTED"
    PASSWORD_RESET_COMPLETED = "PASSWORD_RESET_COMPLETED"
    EMAIL_VERIFIED = "EMAIL_VERIFIED"
    ACCOUNT_LOCKED = "ACCOUNT_LOCKED"
    ACCOUNT_UNLOCKED = "ACCOUNT_UNLOCKED"
    SESSION_EXPIRED = "SESSION_EXPIRED"
    TRUST_SCORE_LOW = "TRUST_SCORE_LOW"


class BiometricType(str, enum.Enum):
    KEYSTROKE = "KEYSTROKE"
    MOUSE = "MOUSE"
    TOUCH = "TOUCH"
    SENSOR_FUSION = "SENSOR_FUSION"


class User(Base):
    __tablename__ = "users"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), default="USER")  # Використовуємо String замість Enum
    
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    
    # Email verification
    email_verification_token = Column(String(255))
    email_verification_expires = Column(DateTime)
    
    # Password reset
    password_reset_token = Column(String(255))
    password_reset_expires = Column(DateTime)
    
    # Account security
    failed_login_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime)
    
    # TOTP
    totp_secret = Column(String(32))
    totp_enabled = Column(Boolean, default=False)
    backup_codes = Column(ARRAY(Text))
    
    # Timestamps
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())
    
    # Relationships
    sessions = relationship("Session", back_populates="user", cascade="all, delete-orphan")
    biometric_data = relationship("BiometricData", back_populates="user", cascade="all, delete-orphan")
    biometric_profiles = relationship("BiometricProfile", back_populates="user", cascade="all, delete-orphan")
    security_events = relationship("SecurityEvent", back_populates="user")


class Session(Base):
    __tablename__ = "sessions"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    session_token = Column(String(255), unique=True, nullable=False, index=True)
    
    mfa_verified = Column(Boolean, default=False)
    trust_score = Column(Float, default=1.0)
    
    ip_address = Column(String(45))
    user_agent = Column(Text)
    device_fingerprint = Column(String(255))
    
    start_time = Column(DateTime, server_default=func.now())
    last_activity = Column(DateTime, server_default=func.now())
    expires_at = Column(DateTime, nullable=False)
    is_active = Column(Boolean, default=True)
    
    # Relationships
    user = relationship("User", back_populates="sessions")
    biometric_data = relationship("BiometricData", back_populates="session")
    trust_score_history = relationship("TrustScoreHistory", back_populates="session", cascade="all, delete-orphan")


class BiometricData(Base):
    __tablename__ = "biometric_data"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    session_id = Column(UUID(as_uuid=True), ForeignKey("sessions.id", ondelete="SET NULL"))
    
    data_type = Column(String(20), nullable=False)  # KEYSTROKE, MOUSE, TOUCH, SENSOR_FUSION
    device_category = Column(String(10), default='desktop')  # 'desktop' or 'mobile'
    raw_data = Column(JSONB, nullable=False)
    features = Column(JSONB)
    
    timestamp = Column(DateTime, server_default=func.now())
    is_training_data = Column(Boolean, default=False)
    
    # Relationships
    user = relationship("User", back_populates="biometric_data")
    session = relationship("Session", back_populates="biometric_data")


class BiometricProfile(Base):
    __tablename__ = "biometric_profiles"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    
    data_type = Column(String(20), nullable=False)  # KEYSTROKE, MOUSE, TOUCH, SENSOR_FUSION
    device_category = Column(String(10), default='desktop')  # 'desktop' or 'mobile'
    profile_data = Column(JSONB, nullable=False)
    sample_count = Column(Integer, default=0)
    last_updated = Column(DateTime, server_default=func.now())
    model_version = Column(String(50))
    
    # Relationships
    user = relationship("User", back_populates="biometric_profiles")
    
    __table_args__ = (
        # Unique constraint on user_id and data_type
        {'sqlite_autoincrement': True},
    )


class SecurityEvent(Base):
    __tablename__ = "security_events"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    session_id = Column(UUID(as_uuid=True), ForeignKey("sessions.id", ondelete="SET NULL"))
    
    event_type = Column(String(30), nullable=False)  # String замість Enum
    details = Column(JSONB)
    
    ip_address = Column(String(45))
    user_agent = Column(Text)
    
    timestamp = Column(DateTime, server_default=func.now(), index=True)
    
    # Relationships
    user = relationship("User", back_populates="security_events")


class TrustScoreHistory(Base):
    __tablename__ = "trust_score_history"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    session_id = Column(UUID(as_uuid=True), ForeignKey("sessions.id", ondelete="CASCADE"), nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    
    score = Column(Float, nullable=False)
    keystroke_score = Column(Float)
    mouse_score = Column(Float)
    touch_score = Column(Float)
    sensor_score = Column(Float)
    
    anomaly_details = Column(JSONB)
    timestamp = Column(DateTime, server_default=func.now())
    
    # Relationships
    session = relationship("Session", back_populates="trust_score_history")
