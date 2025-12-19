from datetime import datetime, timedelta
from typing import Optional, Tuple
import secrets
import string

from jose import JWTError, jwt
from passlib.context import CryptContext
import pyotp
import qrcode
import qrcode.image.svg
from io import BytesIO
import base64

from app.core.config import settings


# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=settings.access_token_expire_minutes))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)


def decode_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        return payload
    except JWTError:
        return None


def generate_session_token() -> str:
    return secrets.token_urlsafe(32)


def generate_verification_token() -> str:
    return secrets.token_urlsafe(32)


# TOTP Functions
def generate_totp_secret() -> str:
    return pyotp.random_base32()


def get_totp_uri(secret: str, username: str) -> str:
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name=settings.totp_issuer)


def generate_totp_qr_code(secret: str, username: str) -> str:
    uri = get_totp_uri(secret, username)
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = BytesIO()
    img.save(buffer, format="PNG")
    buffer.seek(0)
    
    return base64.b64encode(buffer.getvalue()).decode()


def verify_totp(secret: str, code: str) -> bool:
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)  # Allow 30 seconds tolerance


def generate_backup_codes(count: int = 8) -> list[str]:
    codes = []
    for _ in range(count):
        code = ''.join(secrets.choice(string.digits) for _ in range(8))
        # Format: XXXX-XXXX
        codes.append(f"{code[:4]}-{code[4:]}")
    return codes


def hash_backup_codes(codes: list[str]) -> list[str]:
    return [get_password_hash(code.replace("-", "")) for code in codes]


def verify_backup_code(code: str, hashed_codes: list[str]) -> Tuple[bool, int]:
    clean_code = code.replace("-", "")
    for i, hashed in enumerate(hashed_codes):
        if verify_password(clean_code, hashed):
            return True, i
    return False, -1
