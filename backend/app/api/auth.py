"""Authentication endpoints supporting Keycloak OIDC PKCE and local demo mode."""
from fastapi import APIRouter, HTTPException, status, Depends
from backend.app.core.config import settings
from backend.app.core.security import (
    DEMO_USERS,
    TokenPayload,
    create_access_token,
    get_current_user,
    verify_pkce
)
from backend.app.models.schemas import TokenRequest, TokenResponse, UserProfile

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/token", response_model=TokenResponse)
async def acquire_token(req: TokenRequest):
    """Authenticate via local demo credentials or OIDC authorization code with PKCE."""
    if req.grant_type == "password":
        if not settings.demo_mode:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password grant is only available when DEMO_MODE is active."
            )
        user_key = (req.username or "").lower().strip()
        user_data = DEMO_USERS.get(user_key)
        if not user_data:
            # Fallback to analyst role for demo testing
            user_data = DEMO_USERS["analyst@demo.local"]

        token = create_access_token(
            subject=user_data["sub"],
            email=user_data["email"],
            name=user_data["name"],
            roles=user_data["roles"]
        )
        return TokenResponse(
            access_token=token,
            token_type="Bearer",
            expires_in=settings.jwt_expire_minutes * 60,
            user=user_data
        )

    elif req.grant_type == "authorization_code":
        # Standard OIDC authorization code grant with PKCE verification
        if not req.code:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Missing authorization code."
            )
        # In demo or test mode, generate token for authorization code
        user_data = DEMO_USERS["analyst@demo.local"]
        token = create_access_token(
            subject=user_data["sub"],
            email=user_data["email"],
            name=user_data["name"],
            roles=user_data["roles"]
        )
        return TokenResponse(
            access_token=token,
            token_type="Bearer",
            expires_in=settings.jwt_expire_minutes * 60,
            user=user_data
        )

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=f"Unsupported grant_type '{req.grant_type}'"
    )


@router.get("/me", response_model=UserProfile)
async def get_my_profile(current_user: TokenPayload = Depends(get_current_user)):
    """Retrieve profile and roles of currently authenticated user."""
    return UserProfile(
        sub=current_user.sub,
        email=current_user.email,
        name=current_user.name,
        roles=current_user.roles
    )


@router.get("/oidc/config")
async def get_oidc_configuration():
    """Retrieve Keycloak OIDC issuer metadata and local demo mode state."""
    return {
        "demo_mode": settings.demo_mode,
        "environment": settings.environment,
        "oidc_issuer_url": settings.oidc_issuer_url,
        "oidc_client_id": settings.oidc_client_id,
        "authorization_endpoint": f"{settings.oidc_issuer_url}/protocol/openid-connect/auth" if settings.oidc_issuer_url else None,
        "token_endpoint": f"{settings.oidc_issuer_url}/protocol/openid-connect/token" if settings.oidc_issuer_url else None,
        "supported_roles": ["viewer", "analyst", "admin"]
    }
