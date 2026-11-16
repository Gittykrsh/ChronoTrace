"""Authentication Router — Google OAuth2 (PKCE) & Enterprise SSO."""

import uuid
import hashlib
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter
from database.db import create_or_update_user, get_users
from api.schemas import GoogleAuthRequest, EnterpriseSSORequest
import config

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])


@router.get("/google/url")
def get_google_auth_url(redirect_uri: Optional[str] = None):
    """
    Returns simulated Google OAuth2 2.0 authorization URL with PKCE challenge and security state.
    """
    target_redirect = redirect_uri or config.GOOGLE_REDIRECT_URI
    state = uuid.uuid4().hex[:16]
    code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    code_challenge = hashlib.sha256(code_verifier.encode()).hexdigest()

    auth_url = (
        f"https://accounts.google.com/o/oauth2/v2/auth?"
        f"client_id={config.GOOGLE_CLIENT_ID}&"
        f"redirect_uri={target_redirect}&"
        f"response_type=code&"
        f"scope={config.GOOGLE_AUTH_SCOPE.replace(' ', '%20')}&"
        f"state={state}&"
        f"code_challenge={code_challenge}&"
        f"code_challenge_method=S256"
    )

    return {
        "authorization_url": auth_url,
        "client_id": config.GOOGLE_CLIENT_ID,
        "code_verifier": code_verifier,
        "code_challenge": code_challenge,
        "state": state,
        "method": "PKCE S256",
        "notice": "Demo endpoint simulating Google Cloud Defense Identity Federation."
    }


@router.post("/google/verify")
def verify_google_token(req: GoogleAuthRequest):
    """
    Simulates Google OAuth2 token verification, decodes identity, and provisions investigator user session.
    """
    email = req.email or "analyst@chronotrace.soc"
    name = req.name or "Lead Forensic Specialist"

    # Persist or update user in SQLite database
    user = create_or_update_user(
        email=email,
        name=name,
        provider="google",
        agency=config.SSO_AGENCY_NAME,
        clearance_level=config.SSO_DEFAULT_CLEARANCE
    )

    # Generate mock defense JWT access token using configured secret
    token_payload = f"{config.JWT_SECRET_KEY}-{email}-{datetime.now(timezone.utc).timestamp()}"
    mock_token = hashlib.sha256(token_payload.encode()).hexdigest()

    return {
        "authenticated": True,
        "access_token": f"ct_sec_{mock_token[:32]}",
        "token_type": "Bearer",
        "expires_in": config.SESSION_EXPIRE_SECONDS,
        "user": user,
        "auth_provider": "google",
        "message": "Google Workspace session authenticated successfully under defense security profile."
    }


@router.post("/enterprise/sso")
def enterprise_sso_login(req: EnterpriseSSORequest):
    """
    Simulates Defense-Grade Enterprise SAML 2.0 / OIDC SSO Authentication.
    """
    email = req.username
    name = req.username.split("@")[0].capitalize()

    user = create_or_update_user(
        email=email,
        name=name,
        provider="enterprise_sso",
        agency=req.agency or config.SSO_AGENCY_NAME,
        clearance_level=req.clearance_level or config.SSO_DEFAULT_CLEARANCE
    )

    return {
        "authenticated": True,
        "session_token": f"ct_sso_{uuid.uuid4().hex}",
        "clearance_granted": req.clearance_level,
        "user": user,
        "status": "AUTHORIZED"
    }


@router.get("/users")
def list_registered_users():
    """Lists all registered investigators and forensic analysts in the local database."""
    return get_users()
