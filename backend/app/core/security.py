import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

MASKED_SENTINEL = "***"


def mask_secret(value: str | None) -> str:
    return MASKED_SENTINEL if value else ""


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_access_token(subject: str, expire_minutes: int | None = None, token_version: int = 0) -> str:
    minutes = expire_minutes if expire_minutes is not None else settings.JWT_EXPIRE_MINUTES
    expire = datetime.now(timezone.utc) + timedelta(minutes=minutes)
    return jwt.encode(
        {"sub": subject, "exp": expire, "tv": token_version},
        settings.APP_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )


def decode_access_token(token: str) -> tuple[str, int] | None:
    """(subject, token_version) of a login token, or None.

    Special-purpose tokens signed with the same key (e.g. password reset) carry a
    `purpose` claim and must never be accepted as a login token. The caller compares
    token_version with the user's current value so old tokens can be revoked.
    """
    try:
        payload = jwt.decode(token, settings.APP_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
    except JWTError:
        return None
    if payload.get("purpose") or not payload.get("sub"):
        return None
    try:
        version = int(payload.get("tv", 0))
    except (TypeError, ValueError):
        return None
    return payload["sub"], version


def decode_token(token: str) -> str | None:
    """Subject of a login token, or None (no revocation check; see decode_access_token)."""
    decoded = decode_access_token(token)
    return decoded[0] if decoded else None


def _password_fingerprint(hashed_password: str) -> str:
    return hashlib.sha256(hashed_password.encode()).hexdigest()[:16]


def create_password_reset_token(user_id: str, hashed_password: str) -> str:
    """Signed, short-lived token bound to the current password hash.

    Changing the password changes the fingerprint, so a reset link works once.
    """
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.PASSWORD_RESET_EXPIRE_MINUTES)
    return jwt.encode(
        {"sub": user_id, "exp": expire, "purpose": "password_reset", "pwf": _password_fingerprint(hashed_password)},
        settings.APP_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )


def decode_password_reset_token(token: str) -> tuple[str, str] | None:
    """Return (user_id, password_fingerprint) for a valid reset token, else None."""
    try:
        payload = jwt.decode(token, settings.APP_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
    except JWTError:
        return None
    if payload.get("purpose") != "password_reset" or not payload.get("sub") or not payload.get("pwf"):
        return None
    return payload["sub"], payload["pwf"]


def password_reset_token_matches(hashed_password: str, fingerprint: str) -> bool:
    return hmac.compare_digest(_password_fingerprint(hashed_password), fingerprint)


def generate_api_key() -> str:
    return f"argus_{secrets.token_urlsafe(24)}"


def api_key_prefix(api_key: str) -> str:
    return api_key[:18]


def hash_api_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode()).hexdigest()


def verify_api_key(api_key: str, hashed_value: str) -> bool:
    return hmac.compare_digest(hash_api_key(api_key), hashed_value)
