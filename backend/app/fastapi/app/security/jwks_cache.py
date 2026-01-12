from __future__ import annotations

from typing import Any, Dict, Optional

import httpx
from cachetools import TTLCache

from .keycloak_settings import get_keycloak_settings

_JWKS_CACHE: TTLCache[str, Dict[str, Any]] = TTLCache(maxsize=8, ttl=300)  # 5 minutes

def _http_client() -> httpx.Client:
    s = get_keycloak_settings()
    verify = s.oidc_ca_bundle if s.oidc_ca_bundle else True
    return httpx.Client(timeout=10, verify=verify, follow_redirects=True)

def fetch_discovery() -> Dict[str, Any]:
    s = get_keycloak_settings()
    url = f"{s.base_url}/realms/{s.realm}/.well-known/openid-configuration"
    cache_key = f"discovery::{url}"

    if cache_key in _JWKS_CACHE:
        return _JWKS_CACHE[cache_key]

    with _http_client() as client:
        r = client.get(url)
        r.raise_for_status()
        data = r.json()

    _JWKS_CACHE[cache_key] = data
    return data

def fetch_jwks() -> Dict[str, Any]:
    discovery = fetch_discovery()
    jwks_uri = discovery.get("jwks_uri")
    if not jwks_uri:
        raise RuntimeError("Keycloak discovery missing jwks_uri")

    cache_key = f"jwks::{jwks_uri}"
    if cache_key in _JWKS_CACHE:
        return _JWKS_CACHE[cache_key]

    with _http_client() as client:
        r = client.get(jwks_uri)
        r.raise_for_status()
        data = r.json()

    _JWKS_CACHE[cache_key] = data
    return data
