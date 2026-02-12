"""
frontend_tracking.py

Notes / How to run:
  - Example curl (must include a *user* access token where azp == "symfony_frontend"):
        curl -X POST 'https://api.networkengineertools.com:8443/frontend_tracking/log' \
          -H 'accept: application/json' \
          -H "Authorization: Bearer $TOKEN" \
          -H 'Content-Type: application/json' \
          -d '{
            "route": "/api/reporting/devices",
            "event": "fastapi_call.failed",
            "level": "error",
            "message": "FastAPI request failed",
            "context": {"endpoint":"/device_reporting/datatable/devices","status":502,"rid":"abc123"}
          }'
"""

from __future__ import annotations

from typing import Any, Dict, Literal, Optional

import os

import httpx
import jwt
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import PyJWKClient
from pydantic import BaseModel, ConfigDict, Field

from app.database_queries.postgres_insert_queries import (
    insert_app_frontend_tracking
)

from app.database import database

router = APIRouter(prefix="/frontend_tracking", tags=["frontend_tracking"])
bearer = HTTPBearer(auto_error=False)


# ----------------------------
# Auth (JWT + azp enforcement)
# ----------------------------

_jwks_client: Optional[PyJWKClient] = None

def _get_jwks_client() -> PyJWKClient:
    global _jwks_client
    if _jwks_client is None:
        jwks_url = os.getenv("KEYCLOAK_JWKS_URL", "").strip()
        if not jwks_url:
            raise RuntimeError("Missing KEYCLOAK_JWKS_URL env var for JWT verification.")
        _jwks_client = PyJWKClient(jwks_url)
    return _jwks_client


async def require_symfony_frontend_claims(
    creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer),
) -> Dict[str, Any]:

    if not creds or not creds.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "missing_bearer_token"},
        )

    token = creds.credentials
    issuer = os.getenv("KEYCLOAK_ISSUER", "").strip()  # e.g. https://auth.../realms/<realm>

    if not issuer:
        raise RuntimeError("Missing KEYCLOAK_ISSUER env var for JWT verification.")

    try:
        jwks_client = _get_jwks_client()
        signing_key = jwks_client.get_signing_key_from_jwt(token).key

        # Keycloak tokens can have varied 'aud'. We verify signature+exp+iss and then enforce azp.
        claims = jwt.decode(
            token,
            signing_key,
            algorithms=["RS256"],
            issuer=issuer,
            options={"verify_aud": False},
        )
    except Exception as e:

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "invalid_token", "message": str(e)},
        )

    azp = claims.get("azp")
    if azp != "symfony_frontend":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "invalid_azp", "azp": azp},
        )

    return claims


class FrontendTrackingLogIn(BaseModel):
    """
    Accepts the *core* fields you care about, and allows extra keys (future-proof).
    """
    model_config = ConfigDict(extra="allow")

    route: str = Field(..., min_length=1)
    event: str = Field(..., min_length=1)  # ex: fastapi_call.success / fastapi_call.failed
    level: Literal["debug", "info", "warning", "error", "critical"] = "info"
    message: str = Field(..., min_length=1)
    context: Dict[str, Any] = Field(default_factory=dict)


@router.post("/log", status_code=status.HTTP_201_CREATED)
async def frontend_tracking_log(
    payload: FrontendTrackingLogIn,
    request: Request,
    claims: Dict[str, Any] = Depends(require_symfony_frontend_claims),
) -> Dict[str, Any]:
    """
    Insert an audit/tracking row for frontend activity.

    Security:
      - Requires valid JWT
      - Requires azp == "symfony_frontend"
    """

    # best-effort username
    username = (
        claims.get("preferred_username")
        or claims.get("email")
        or claims.get("upn")
        or claims.get("sub")
    )

    info: Dict[str, Any] = payload.model_dump(mode="python")
    info["_meta"] = {
        "client_ip": request.client.host if request.client else None,
        "user_agent": request.headers.get("user-agent"),
        "azp": claims.get("azp"),
        "sub": claims.get("sub"),
    }

    res = await insert_app_frontend_tracking(
        username=username,
        route=payload.route,
        information=info,
    )

    if isinstance(res, dict) and res.get("error"):
        raise HTTPException(status_code=500, detail=res)

    return {"detail": {"ok": True, **(res or {})}}
