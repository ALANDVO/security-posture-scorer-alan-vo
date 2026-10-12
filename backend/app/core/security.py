"""Authentication, role-based authorization, PKCE verification, and OIDC support."""
import base64
import hashlib
import time
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta, timezone
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
from pydantic import BaseModel
from backend.app.core.config import settings

bearer_scheme = HTTPBearer(auto_error=False)

DEMO_USERS: Dict[str, Dict[str, Any]] = {
    "admin@demo.local": {
        "sub": "usr-admin-01",
        "email": "admin@demo.local",
        "name": "Alan Vo (Admin)",
        "role": "admin",
        "roles": ["viewer", "analyst", "admin"]
    },
    "analyst@demo.local": {
        "sub": "usr-analyst-02",
        "email": "analyst@demo.local",
        "name": "Security Analyst",
        "role": "analyst",
        "roles": ["viewer", "analyst"]
    },
    "viewer@demo.local": {
        "sub": "usr-viewer-03",
        "email": "viewer@demo.local",
        "name": "Audit Viewer",
        "role": "viewer",
        "roles": ["viewer"]
    }
}


class TokenPayload(BaseModel):
    sub: str
    email: str
    name: str
    roles: List[str]
    exp: int


def verify_pkce(code_verifier: str, code_challenge: str) -> bool:
    """Verify standard PKCE S256 challenge string."""
    if not code_verifier or not code_challenge:
        return False
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    computed_challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return computed_challenge == code_challenge


def create_access_token(
    subject: str,
    email: str,
    name: str,
    roles: List[str],
    expires_delta: Optional[timedelta] = None
) -> str:
    """Create signed JWT access token for demo or session use."""
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.jwt_expire_minutes)

    payload = {
        "sub": subject,
        "email": email,
        "name": name,
        "roles": roles,
        "iss": settings.oidc_issuer_url or f"https://{settings.host}:{settings.port}",
        "aud": settings.oidc_client_id,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp())
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_token(token: str) -> TokenPayload:
    """Decode and validate JWT access token; rejects expired or tampered tokens."""
    try:
        # In production with OIDC Keycloak, verify issuer and audience
        claims = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
            audience=settings.oidc_client_id,
            options={"verify_aud": bool(settings.oidc_issuer_url)}
        )
        sub = claims.get("sub")
        email = claims.get("email", "")
        name = claims.get("name", "Unknown")
        roles = claims.get("roles", ["viewer"])
        exp = claims.get("exp", 0)

        if not sub or exp < time.time():
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token is expired or invalid",
                headers={"WWW-Authenticate": "Bearer"}
            )
        return TokenPayload(sub=sub, email=email, name=name, roles=roles, exp=exp)
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"}
        )


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme)
) -> TokenPayload:
    """Extract authenticated user from Authorization: Bearer <token>."""
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Provide a valid Bearer token.",
            headers={"WWW-Authenticate": "Bearer"}
        )
    return decode_token(credentials.credentials)


def require_role(allowed_roles: List[str]):
    """Role-based access control dependency ensuring user has one of allowed_roles."""
    async def role_checker(user: TokenPayload = Depends(get_current_user)) -> TokenPayload:
        if not any(role in user.roles for role in allowed_roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Requires one of roles: {', '.join(allowed_roles)}"
            )
        return user
    return role_checker
