from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from fastapi import Depends, HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import jwt
from jose.exceptions import JWTError

from .jwks_cache import fetch_discovery, fetch_jwks
from .keycloak_settings import get_keycloak_settings

bearer = HTTPBearer(auto_error=False)

@dataclass(frozen=True)
class UserContext:
    sub: str
    username: Optional[str]
    email: Optional[str]
    azp: Optional[str]
    roles: List[str]
    claims: Dict[str, Any]

def _pick_jwk(jwks: Dict[str, Any], kid: str) -> Dict[str, Any]:
    for k in jwks.get("keys") or []:
        if k.get("kid") == kid:
            return k
    raise HTTPException(status_code=401, detail={"error": "unknown_kid"})

def _realm_roles(claims: Dict[str, Any]) -> List[str]:
    ra = claims.get("realm_access") or {}
    roles = ra.get("roles") or []
    return sorted({str(r) for r in roles})

def get_current_user(creds: HTTPAuthorizationCredentials = Security(bearer)) -> UserContext:
    if not creds or not creds.credentials:
        raise HTTPException(status_code=401, detail={"error": "missing_bearer_token"})

    token = creds.credentials
    settings = get_keycloak_settings()
    discovery = fetch_discovery()
    jwks = fetch_jwks()

    issuer = discovery.get("issuer")
    if not issuer:
        raise HTTPException(status_code=500, detail={"error": "discovery_missing_issuer"})

    try:
        header = jwt.get_unverified_header(token)
    except Exception:
        raise HTTPException(status_code=401, detail={"error": "invalid_token_header"})

    kid = header.get("kid")
    if not kid:
        raise HTTPException(status_code=401, detail={"error": "missing_kid"})

    jwk = _pick_jwk(jwks, kid)

    try:
        # Verify signature + issuer. Audience is optionally checked later.
        claims = jwt.decode(
            token,
            jwk,
            algorithms=[header.get("alg", "RS256")],
            issuer=issuer,
            options={"verify_aud": False},
        )
    except JWTError as e:
        raise HTTPException(status_code=401, detail={"error": "jwt_verify_failed", "detail": str(e)})

    # azp allow-list (optional but recommended)
    if settings.allowed_azp:
        azp = claims.get("azp")
        if not azp or str(azp) not in set(settings.allowed_azp):
            raise HTTPException(status_code=403, detail={"error": "invalid_azp", "azp": azp})

    roles = _realm_roles(claims)

    return UserContext(
        sub=str(claims.get("sub")),
        username=claims.get("preferred_username"),
        email=claims.get("email"),
        azp=claims.get("azp"),
        roles=roles,
        claims=claims,
    )

def require_roles(*required: str):
    required_set = set(required)

    def _dep(user: UserContext = Depends(get_current_user)) -> UserContext:
        if not required_set.issubset(set(user.roles)):
            raise HTTPException(
                status_code=403,
                detail={"error": "missing_required_roles", "required": sorted(required_set), "have": user.roles},
            )
        return user

    return _dep

def require_any_role(*required: str):
    required_set = set(required)

    def _dep(user: UserContext = Depends(get_current_user)) -> UserContext:
        have = set(user.roles or [])
        if not (have & required_set):
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "missing_any_required_role",
                    "required_any": sorted(required_set),
                    "have": sorted(have),
                },
            )
        return user

    return _dep