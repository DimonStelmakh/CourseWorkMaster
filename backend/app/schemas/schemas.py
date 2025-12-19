from pydantic import BaseModel, EmailStr, Field, field_validator
from typing import Optional, List, Dict, Any
from datetime import datetime
from uuid import UUID
from enum import Enum
import re


# Enums
class UserRole(str, Enum):
    USER = "USER"
    ADMIN = "ADMIN"


class BiometricType(str, Enum):
    KEYSTROKE = "KEYSTROKE"
    MOUSE = "MOUSE"
    TOUCH = "TOUCH"
    SENSOR_FUSION = "SENSOR_FUSION"


class EventType(str, Enum):
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


# User Schemas
class UserBase(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr


class UserCreate(UserBase):
    password: str = Field(..., min_length=8, max_length=100)
    
    @field_validator('password')
    @classmethod
    def validate_password(cls, v):
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not re.search(r'[a-z]', v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not re.search(r'\d', v):
            raise ValueError('Password must contain at least one digit')
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', v):
            raise ValueError('Password must contain at least one special character')
        return v


class UserUpdate(BaseModel):
    username: Optional[str] = Field(None, min_length=3, max_length=50)
    email: Optional[EmailStr] = None


class UserResponse(UserBase):
    id: UUID
    role: str  # String instead of enum for compatibility
    is_active: bool
    is_verified: bool
    totp_enabled: bool
    created_at: datetime
    
    class Config:
        from_attributes = True


class UserProfileResponse(UserResponse):
    trust_score: Optional[float] = None
    biometric_profile_ready: bool = False
    sample_counts: Dict[str, int] = {}


# Authentication Schemas
class LoginRequest(BaseModel):
    username: str
    password: str
    biometric_data: Optional[Dict[str, Any]] = None  # Keystroke data during login


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    requires_mfa: bool = False
    mfa_token: Optional[str] = None  # Temporary token for MFA flow
    mfa_reason: Optional[str] = None  # Why MFA is required
    trust_score: Optional[float] = None  # Trust score if biometric analysis was done
    user: UserResponse


class MFAVerifyRequest(BaseModel):
    mfa_token: str
    code: str = Field(..., min_length=6, max_length=8)  # 6 for TOTP, 8 for backup


class MFASetupResponse(BaseModel):
    secret: str
    qr_code: str  # Base64 encoded QR code
    backup_codes: List[str]


class TOTPConfirmRequest(BaseModel):
    code: str = Field(..., min_length=6, max_length=6)
    backup_codes: List[str]


class PasswordResetRequest(BaseModel):
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str = Field(..., min_length=8, max_length=100)
    
    @field_validator('new_password')
    @classmethod
    def validate_password(cls, v):
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not re.search(r'[a-z]', v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not re.search(r'\d', v):
            raise ValueError('Password must contain at least one digit')
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', v):
            raise ValueError('Password must contain at least one special character')
        return v


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=8, max_length=100)


# Biometric Schemas
class KeystrokeData(BaseModel):
    key: str
    key_down_time: float  # Timestamp
    key_up_time: float
    hold_time: float  # Key hold duration
    flight_time: Optional[float] = None  # Time between key releases


class MouseData(BaseModel):
    x: float
    y: float
    timestamp: float
    event_type: str  # 'move', 'click', 'scroll'
    button: Optional[str] = None
    velocity: Optional[float] = None
    acceleration: Optional[float] = None


class TouchData(BaseModel):
    x: float
    y: float
    timestamp: float
    event_type: str  # 'start', 'move', 'end'
    pressure: Optional[float] = None
    touch_area: Optional[float] = None
    velocity: Optional[float] = None


class SensorData(BaseModel):
    # Accelerometer & Gyroscope
    accelerometer: Optional[Dict[str, float]] = None  # {x, y, z}
    gyroscope: Optional[Dict[str, float]] = None  # {x, y, z}
    timestamp: float


class BiometricDataSubmit(BaseModel):
    data_type: BiometricType
    data: List[Dict[str, Any]]
    device_category: Optional[str] = 'desktop'  # 'desktop' or 'mobile'
    session_token: Optional[str] = None


class BiometricAnalysisResult(BaseModel):
    trust_score: float
    keystroke_score: Optional[float] = None
    mouse_score: Optional[float] = None
    touch_score: Optional[float] = None
    sensor_score: Optional[float] = None
    anomaly_detected: bool
    anomaly_details: Optional[Dict[str, Any]] = None
    requires_mfa: bool = False


# Session Schemas
class SessionInfo(BaseModel):
    id: UUID
    ip_address: Optional[str]
    user_agent: Optional[str]
    start_time: datetime
    last_activity: datetime
    trust_score: float
    is_active: bool
    mfa_verified: bool
    
    class Config:
        from_attributes = True


class SessionListResponse(BaseModel):
    sessions: List[SessionInfo]
    total: int


# Security Event Schemas
class SecurityEventResponse(BaseModel):
    id: UUID
    event_type: EventType
    details: Optional[Dict[str, Any]]
    ip_address: Optional[str]
    timestamp: datetime
    
    class Config:
        from_attributes = True


class SecurityEventListResponse(BaseModel):
    events: List[SecurityEventResponse]
    total: int
    page: int
    page_size: int


# Trust Score Schemas
class TrustScoreResponse(BaseModel):
    current_score: float
    threshold: float
    status: str  # 'normal', 'warning', 'critical'
    components: Dict[str, Optional[float]]
    last_updated: datetime


class TrustScoreHistoryItem(BaseModel):
    score: float
    keystroke_score: Optional[float]
    mouse_score: Optional[float]
    touch_score: Optional[float]
    sensor_score: Optional[float]
    timestamp: datetime
    
    class Config:
        from_attributes = True


# Dashboard Schemas
class DashboardStats(BaseModel):
    total_users: int
    active_sessions: int
    events_today: int
    anomalies_today: int
    average_trust_score: float


class UserDashboard(BaseModel):
    user: UserProfileResponse
    current_trust_score: float
    trust_score_history: List[TrustScoreHistoryItem]
    recent_events: List[SecurityEventResponse]
    active_sessions: List[SessionInfo]
    profile_completion: float  # Percentage of biometric profile completion


# Generic Response
class MessageResponse(BaseModel):
    message: str
    success: bool = True
