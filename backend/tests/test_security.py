from app.core.security import (
    create_access_token,
    decode_token,
    generate_api_key,
    hash_api_key,
    hash_password,
    verify_api_key,
    verify_password,
)
from app.db.models import User


def test_password_hash_round_trip():
    password = "argus-test-password"
    hashed = hash_password(password)

    assert hashed != password
    assert verify_password(password, hashed) is True
    assert verify_password("wrong-password", hashed) is False


def test_access_token_round_trip():
    token = create_access_token("user-123")

    assert decode_token(token) == "user-123"
    assert decode_token(f"{token}corrupted") is None


def test_user_is_admin_property():
    assert User(username="admin", hashed_password="x", role="admin").is_admin is True
    assert User(username="viewer", hashed_password="x", role="viewer").is_admin is False


def test_api_key_round_trip():
    api_key = generate_api_key()
    hashed = hash_api_key(api_key)

    assert verify_api_key(api_key, hashed) is True
    assert verify_api_key(f"{api_key}x", hashed) is False
