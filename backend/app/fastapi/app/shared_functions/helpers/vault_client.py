"""
Notes / How to run
------------------
This module is imported by FastAPI routes and Celery tasks.
It is not meant to be executed directly.

Purpose
-------
- Read the Vault Agent sink token file on-demand (per Vault call)
- So if the agent rotates the token, your app automatically uses the newest one
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional
import httpx



def _vault_token_file() -> str:
    return os.getenv("VAULT_TOKEN_FILE", "/run/vault/token")


def _read_vault_token() -> str:
    """
    Reads the Vault token from the sink file every time.
    (Deliberately NOT cached to handle token rotation.)
    """
    path = _vault_token_file()
    try:
        with open(path, "r", encoding="utf-8") as f:
            token = f.read().strip()
    except FileNotFoundError as exc:
        raise RuntimeError(f"Vault token file not found: {path}") from exc

    if not token:
        raise RuntimeError(f"Vault token file is empty: {path}")

    return token


def _vault_addr() -> str:
    addr = (os.getenv("VAULT_ADDR") or "").strip()
    if not addr:
        raise RuntimeError("VAULT_ADDR is not set")
    return addr.rstrip("/")


def _vault_verify() -> Any:
    """
    httpx 'verify' can be:
      - True/False
      - path to a CA bundle / CA cert file
    """
    cacert = (os.getenv("VAULT_CACERT") or "").strip()
    return cacert if cacert else True


def _vault_headers() -> Dict[str, str]:
    headers = {"X-Vault-Token": _read_vault_token()}
    ns = (os.getenv("VAULT_NAMESPACE") or "").strip()
    if ns:
        headers["X-Vault-Namespace"] = ns
    return headers


async def vault_kv2_read(*, mount: str, secret_path: str) -> Dict[str, Any]:
    """
    Read a KV v2 secret:
      GET /v1/<mount>/data/<secret_path>
    Returns only the "data.data" payload (the actual secret fields).
    """
    mount = mount.strip("/")

    # kv-v2: /data/ is required
    url = f"{_vault_addr()}/v1/{mount}/data/{secret_path.lstrip('/')}"

    try:
        async with httpx.AsyncClient(verify=_vault_verify(), timeout=10.0) as client:
            resp = await client.get(url, headers=_vault_headers())
    except httpx.ConnectError as exc:
        return {"error": "vault_connect_failed", "addr": _vault_addr(), "detail": str(exc)}

    if resp.status_code == 404:
        return {"error": "vault_secret_not_found", "mount": mount, "path": secret_path}

    if resp.status_code >= 400:
        # DO NOT include token; do not log token.
        return {
            "error": "vault_read_failed",
            "status_code": resp.status_code,
            "mount": mount,
            "path": secret_path,
            "detail": resp.text[:3000],
        }

    payload = resp.json()
    # KV v2 shape: {"data": {"data": {...}, "metadata": {...}}}
    data = (((payload or {}).get("data") or {}).get("data")) or {}
    if not isinstance(data, dict):
        return {"error": "vault_unexpected_response", "mount": mount, "path": secret_path}

    return data

async def vault_kv2_list(*, mount: str, prefix: str) -> Dict[str, Any]:
    """
    LIST keys under a KV v2 prefix (folder-like).
    Calls: LIST /v1/<mount>/metadata/<prefix>
    Returns: {"keys": [...]} or {"error": ...}
    """
    mount = mount.strip("/")
    prefix = prefix.strip("/")

    url = f"{_vault_addr()}/v1/{mount}/metadata/{prefix}"

    async with httpx.AsyncClient(verify=_vault_verify(), timeout=10.0) as client:
        # Vault uses LIST, which is an HTTP method.
        resp = await client.request("LIST", url, headers=_vault_headers())

    if resp.status_code == 404:
        return {"error": "vault_prefix_not_found", "mount": mount, "prefix": prefix}

    if resp.status_code >= 400:
        return {"error": "vault_list_failed", "status_code": resp.status_code, "detail": resp.text[:3000]}

    payload = resp.json()
    keys = (((payload or {}).get("data") or {}).get("keys")) or []
    if not isinstance(keys, list):
        return {"error": "vault_unexpected_list_response", "mount": mount, "prefix": prefix}

    return {"keys": keys}


async def vault_kv2_read_all_under_prefix(*, mount: str, prefix: str) -> Dict[str, Any]:
    """
    Lists keys under prefix and reads each secret.
    Returns: {"items": {key: secret_data, ...}, "errors": {key: err, ...}}
    """
    listing = await vault_kv2_list(mount=mount, prefix=prefix)
    if "error" in listing:
        return listing

    items: Dict[str, Any] = {}
    errors: Dict[str, Any] = {}

    for key in listing["keys"]:
        # Vault may return keys ending with "/" (subfolders)
        if isinstance(key, str) and key.endswith("/"):
            # skip subfolders (or recursively handle if you want)
            continue

        secret_path = f"{prefix.strip('/')}/{key}"
        data = await vault_kv2_read(mount=mount, secret_path=secret_path)

        if isinstance(data, dict) and "error" in data:
            errors[key] = data
        else:
            items[key] = data

    return {"items": items, "errors": errors}