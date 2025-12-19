from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.redis import get_redis, RedisClient
from app.core.security import create_access_token
from app.services import AuthenticationService
from app.schemas import (
    UserCreate, UserResponse, LoginRequest, LoginResponse,
    MFAVerifyRequest, MFASetupResponse, PasswordResetRequest,
    PasswordResetConfirm, MessageResponse, TOTPConfirmRequest
)
from app.api.deps import get_current_user, get_current_session
from app.models import User, Session

router = APIRouter(prefix="/auth", tags=["Authentication"])


def get_client_info(request: Request):
    return {
        "ip": request.client.host if request.client else None,
        "user_agent": request.headers.get("user-agent")
    }


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(
    user_data: UserCreate,
    db: AsyncSession = Depends(get_db),
    redis: RedisClient = Depends(get_redis)
):
    auth_service = AuthenticationService(db, redis)
    try:
        user = await auth_service.register_user(user_data)
        await db.commit()
        return user
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/login", response_model=LoginResponse)
async def login(
    login_data: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    redis: RedisClient = Depends(get_redis)
):
    auth_service = AuthenticationService(db, redis)
    client_info = get_client_info(request)
    
    try:
        user, requires_mfa, mfa_token, mfa_reason, trust_score = await auth_service.authenticate(
            login_data, client_info["ip"], client_info["user_agent"]
        )
        
        if requires_mfa:
            await db.commit()
            return LoginResponse(
                access_token="", requires_mfa=True, mfa_token=mfa_token,
                mfa_reason=mfa_reason, trust_score=trust_score,
                user=UserResponse.model_validate(user)
            )
        
        session = await auth_service.create_session(
            user, mfa_verified=False,
            ip_address=client_info["ip"], user_agent=client_info["user_agent"]
        )
        
        access_token = create_access_token({"sub": str(user.id), "session": str(session.id)})
        await db.commit()
        
        return LoginResponse(
            access_token=access_token, requires_mfa=False, trust_score=trust_score,
            user=UserResponse.model_validate(user)
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))


@router.post("/verify-mfa", response_model=LoginResponse)
async def verify_mfa(
    mfa_data: MFAVerifyRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    redis: RedisClient = Depends(get_redis)
):
    auth_service = AuthenticationService(db, redis)
    client_info = get_client_info(request)
    
    try:
        user = await auth_service.verify_mfa(
            mfa_data.mfa_token, mfa_data.code,
            client_info["ip"], client_info["user_agent"]
        )
        
        session = await auth_service.create_session(
            user, mfa_verified=True,
            ip_address=client_info["ip"], user_agent=client_info["user_agent"]
        )
        
        access_token = create_access_token({"sub": str(user.id), "session": str(session.id)})
        await db.commit()
        
        return LoginResponse(
            access_token=access_token, requires_mfa=False,
            user=UserResponse.model_validate(user)
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))


@router.post("/logout", response_model=MessageResponse)
async def logout(
    session: Session = Depends(get_current_session),
    db: AsyncSession = Depends(get_db),
    redis: RedisClient = Depends(get_redis)
):
    auth_service = AuthenticationService(db, redis)
    await auth_service.logout(session.id)
    await db.commit()
    return MessageResponse(message="Successfully logged out")


@router.post("/setup-totp", response_model=MFASetupResponse)
async def setup_totp(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis: RedisClient = Depends(get_redis)
):
    if user.totp_enabled:
        raise HTTPException(status_code=400, detail="TOTP already enabled")
    
    auth_service = AuthenticationService(db, redis)
    secret, qr_code, backup_codes = await auth_service.setup_totp(user)
    
    return MFASetupResponse(secret=secret, qr_code=qr_code, backup_codes=backup_codes)


@router.post("/confirm-totp", response_model=MessageResponse)
async def confirm_totp(
    data: TOTPConfirmRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis: RedisClient = Depends(get_redis)
):
    auth_service = AuthenticationService(db, redis)
    try:
        await auth_service.confirm_totp_setup(user, data.code, data.backup_codes)
        await db.commit()
        return MessageResponse(message="TOTP enabled successfully")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/disable-totp", response_model=MessageResponse)
async def disable_totp(
    data: TOTPConfirmRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis: RedisClient = Depends(get_redis)
):
    from app.core.security import verify_totp
    
    if not user.totp_enabled:
        raise HTTPException(status_code=400, detail="TOTP is not enabled")
    
    # Verify the code first
    if not verify_totp(user.totp_secret, data.code):
        raise HTTPException(status_code=400, detail="Invalid TOTP code")
    
    # Disable TOTP
    user.totp_enabled = False
    user.totp_secret = None
    user.backup_codes = None
    await db.commit()
    
    return MessageResponse(message="TOTP disabled successfully")


@router.post("/request-password-reset", response_model=MessageResponse)
async def request_password_reset(
    data: PasswordResetRequest,
    db: AsyncSession = Depends(get_db),
    redis: RedisClient = Depends(get_redis)
):
    auth_service = AuthenticationService(db, redis)
    await auth_service.request_password_reset(data.email)
    await db.commit()
    return MessageResponse(message="If email exists, reset link will be sent")


@router.post("/reset-password", response_model=MessageResponse)
async def reset_password(
    data: PasswordResetConfirm,
    db: AsyncSession = Depends(get_db),
    redis: RedisClient = Depends(get_redis)
):
    auth_service = AuthenticationService(db, redis)
    try:
        await auth_service.reset_password(data.token, data.new_password)
        await db.commit()
        return MessageResponse(message="Password reset successfully")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/verify-email/{token}", response_model=MessageResponse)
async def verify_email(
    token: str,
    db: AsyncSession = Depends(get_db),
    redis: RedisClient = Depends(get_redis)
):
    auth_service = AuthenticationService(db, redis)
    try:
        await auth_service.verify_email(token)
        await db.commit()
        return MessageResponse(message="Email verified successfully")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(user: User = Depends(get_current_user)):
    return user
