"""Tests for authentication, role authorization, PKCE, and production safety."""
import pytest
from fastapi import HTTPException
from backend.app.core.config import Settings
from backend.app.core.security import (
    create_access_token,
    decode_token,
    verify_pkce,
    DEMO_USERS
)


def test_create_and_decode_valid_token():
    user = DEMO_USERS["analyst@demo.local"]
    token = create_access_token(
        subject=user["sub"],
        email=user["email"],
        name=user["name"],
        roles=user["roles"]
    )
    payload = decode_token(token)
    assert payload.sub == user["sub"]
    assert payload.email == user["email"]
    assert "analyst" in payload.roles


def test_decode_invalid_token_raises_401():
    with pytest.raises(HTTPException) as exc_info:
        decode_token("invalid.token.payload")
    assert exc_info.value.status_code == 401


def test_pkce_challenge_verification():
    import hashlib
    import base64
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

    assert verify_pkce(verifier, challenge) is True
    assert verify_pkce("wrong_verifier", challenge) is False
    assert verify_pkce("", "") is False


def test_production_safety_refuses_demo_mode():
    prod_settings = Settings(
        environment="production",
        demo_mode=True
    )
    with pytest.raises(RuntimeError) as exc_info:
        prod_settings.validate_production_safety()
    assert "strictly forbidden" in str(exc_info.value)
