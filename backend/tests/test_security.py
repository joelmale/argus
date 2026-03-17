from app.core.security import create_access_token, decode_token, hash_password, verify_password


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
