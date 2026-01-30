"""
Cisco API reporting endpoints (CVE + EOX)

"""

from __future__ import annotations

import re
import json
import time
import asyncio
import random
from typing import Any, Dict, Optional, List
from urllib.parse import quote

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from starlette.status import HTTP_400_BAD_REQUEST, HTTP_500_INTERNAL_SERVER_ERROR

from app.security.auth import UserContext, get_current_user, require_any_role
from app.shared_functions.helpers.helpers_hashicorp_vault import vault_get_cisco_api_console_config
from app.database_queries.postgres_select_queries import select_unique_device_os_versions
from app.database import database
from app.database_queries.postgres_insert_queries import (
    insert_app_backend_tracking,
    upsert_reporting_cisco_api_cve_software,
    upsert_reporting_cisco_api_cve_software_from_payload,
    upsert_reporting_cisco_api_eox_from_payload,
)

import logging

logger = logging.getLogger("app.cisco_api_reporting")

router = APIRouter(
    prefix="/cisco_api_reporting",
    tags=["cisco_api_reporting"],
    dependencies=[Depends(get_current_user)],
)

CISCO_OAUTH_TOKEN_URL = "https://id.cisco.com/oauth2/default/v1/token"

# Currently these are the only supported os's from ciscos apix documentation
# See their page for information
# https://developer.cisco.com/docs/psirt/introduction
SUPPORTED_SOFTWARECHECKER_OS = {"aci", "asa", "fmc", "ftd", "fxos", "ios", "iosxe", "nxos"}

# These are here to induce a wait time for calls to ciscos rest api.
# If you go over the rate limit you will end up with 429 errors (Rate Limit Exceeded).
# Ciscos per application rules list
#
# 5 calls per second
# 30 calls per minute
# 5000 calls per day
_CISCO_RATE_LOCK = asyncio.Lock()
_CISCO_NEXT_ALLOWED = 0.0

class CiscoOSVersionRequest(BaseModel):
    os: str = Field(..., example="iosxe")
    version: Optional[str] = Field(default=None, example="17.06.05")
    product: Optional[str] = Field(
        default=None,
        example="Cisco NX-OS Software 4.2(1)SV1(4) (only used when os=by_product_id)",
    )

class CiscoEOXRequest(BaseModel):
    page_index: str = Field(..., example="1")
    product_id: str = Field(..., example="WS-C3560X-24P-L")

class CiscoBulkFromDevicesRequest(BaseModel):
    batch_size: int = Field(20, ge=1, le=200, description="How many (os, version) pairs per batch.")
    concurrency: int = Field(1, ge=1, le=1, description="Forced to 1 (serial requests) to avoid Cisco 429 rate limits.")
    max_pairs: Optional[int] = Field(None, ge=1, description="Optional cap on how many pairs to process total.")
    sleep_s_between_batches: float = Field(0.0, ge=0.0, le=10.0, description="Optional delay between batches.")
    include_raw: bool = Field(False, description="If true, include full Cisco JSON/text per pair (can be large).")
    os_allowlist: Optional[List[str]] = Field(None, description="Optional allowlist of OS values (lowercased).")


def _clean_version(ver: str) -> str:
    """
    Remove common marketing prefixes that appear in device-reported versions.
    The API is looking for something similar to XX.YY.ZZ
    Depending on how you pull the software, SNMP Vs CLI for example you may see
    items like Amsterdam XX.YY.ZZ
    """
    replace_list = ["Amsterdam ", "Bengaluru "]
    out = (ver or "").strip()
    for s in replace_list:
        out = re.sub(s, "", out)
    return out.strip()


def _safe_vault_meta(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Return safe metadata only (never secrets).
    This is used to log the items that are returned from vault for debugging purposes if needed.
    """
    meta = cfg.get("_meta") if isinstance(cfg, dict) else None
    if isinstance(meta, dict):
        return meta
    # fallback: safe list of keys only
    return {"present_keys": sorted([k for k in cfg.keys() if not k.startswith("_")])} if isinstance(cfg, dict) else {}

async def _load_cisco_cfg_or_500() -> Dict[str, Any]:
    cfg = await vault_get_cisco_api_console_config(include_meta=True)
    if isinstance(cfg, dict) and "error" in cfg:
        raise HTTPException(status_code=HTTP_500_INTERNAL_SERVER_ERROR, detail=cfg)
    return cfg

async def _cisco_get_oauth_token(*, client_id: str, client_secret: str) -> Dict[str, Any]:
    """
    Cisco OAuth2 client credentials token request.
    """

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded"
    }

    data = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret
    }

    async with httpx.AsyncClient(timeout=20.0) as client:
        r = await client.post(CISCO_OAUTH_TOKEN_URL, headers=headers, data=data)

    if r.status_code != 200:
        raise HTTPException(
            status_code=HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "cisco_oauth_failed",
                "status_code": r.status_code,
                "message": r.text[:500],
            },
        )

    reply = r.json()
    if reply.get("token_type") != "Bearer" or not reply.get("access_token"):
        raise HTTPException(
            status_code=HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "cisco_oauth_invalid_reply", "reply": reply},
        )

    return {
        "token_type": reply["token_type"],
        "access_token": reply["access_token"]
    }

async def _http_get_json_or_text(*, url: str, headers: Dict[str, str], timeout_s: float = 30.0) -> Dict[str, Any]:
    """
    Returns:
      {"ok": True, "status_code": ..., "json": <obj>}   or
      {"ok": True, "status_code": ..., "text": "<raw>"} or
      {"ok": False, "status_code": ..., "text": "<raw>"}
    """
    async with httpx.AsyncClient(timeout=timeout_s) as client:
        r = await client.get(url, headers=headers)

    out: Dict[str, Any] = {"status_code": r.status_code}
    if r.status_code != 200:
        out["ok"] = False
        out["text"] = r.text
        return out

    out["ok"] = True
    try:
        out["json"] = r.json()
    except Exception:
        out["text"] = r.text
    return out

def _vault_status_code_from_exc(exc: Exception) -> Optional[int]:
    """
    Best-effort extraction of an upstream HTTP status code from common client exceptions
    (aiohttp/httpx/requests) or from a FastAPI HTTPException detail payload.
    """
    status = getattr(exc, "status", None)
    if isinstance(status, int):
        return status

    resp = getattr(exc, "response", None)
    if resp is not None:
        sc = getattr(resp, "status_code", None)
        if isinstance(sc, int):
            return sc

    if isinstance(exc, HTTPException):
        if isinstance(exc.status_code, int) and exc.status_code == 403:
            return 403
        d = getattr(exc, "detail", None)
        if isinstance(d, dict):
            for k in ("vault_status_code", "vault_status", "status_code", "status", "http_status"):
                v = d.get(k)
                if isinstance(v, int):
                    return v
            vr = d.get("vault_response") or d.get("response")
            if isinstance(vr, dict):
                for k in ("status_code", "status"):
                    v = vr.get(k)
                    if isinstance(v, int):
                        return v

    return None


def _raise_vault_access_denied(payload: Dict[str, Any]) -> None:
    payload["vault_error"] = {
        "type": "forbidden",
        "message": (
            "Vault returned HTTP 403 (permission denied). "
            "This service is not authorized to read the Cisco API credentials from the Vault-rendered share."
        ),
        "hint": (
            "Check the Vault policy attached to the AppRole/token used by the vault-agent for this service. "
            "Ensure it has read access to the Cisco secrets path and that the agent is rendering the secrets file/volume correctly."
        ),
    }
    raise HTTPException(
        status_code=HTTP_500_INTERNAL_SERVER_ERROR,
        detail={"error": "vault_access_denied", **payload},
    )

async def _cisco_rate_wait(min_interval_s: float) -> float:
    """
    Enforce a minimum interval between *request attempts* across the process.
    Returns how long we slept (for metrics).
    """
    global _CISCO_NEXT_ALLOWED
    if not min_interval_s or min_interval_s <= 0:
        return 0.0

    async with _CISCO_RATE_LOCK:
        now = time.monotonic()
        wait_s = max(0.0, _CISCO_NEXT_ALLOWED - now)
        if wait_s > 0:
            await asyncio.sleep(wait_s)
        # reserve the next slot
        _CISCO_NEXT_ALLOWED = time.monotonic() + float(min_interval_s)
        return wait_s

def _parse_retry_after_seconds(v: Optional[str]) -> Optional[float]:
    if not v:
        return None
    v = v.strip()
    try:
        return max(0.0, float(v))
    except Exception:
        return None

def _version_candidates_for_query(version_raw: str) -> List[str]:
    """
    Generate a small set of version strings to try against Cisco's API.
    """
    import re

    raw = (version_raw or "").strip()
    if not raw:
        return []

    try:
        clean = _clean_version(raw)
    except Exception:
        clean = raw

    out: List[str] = []
    for v in (raw, clean):
        v = (v or "").strip()
        if v and v not in out:
            out.append(v)

    # Convert parenthetical patch: 9.12(4) -> 9.12.4
    v2 = re.sub(r"\((\d+)\)", r".\1", clean).replace("(", ".").replace(")", "")
    v2 = v2.replace(" ", "").strip(".")
    if v2 and v2 not in out:
        out.append(v2)

    return out[:3]


async def _cisco_get_with_429_backoff(
    client,
    *,
    url: str,
    headers: Dict[str, str],
    timeout_s: float,
    min_interval_s: float,
    max_attempts: int = 5,
) -> Tuple[Optional[Any], int, float, float, Optional[str]]:
    """
    Returns: (httpx.Response|None, attempts, slept_429_s, slept_pacing_s, last_err)
    """
    import httpx

    attempts = 0
    slept_429 = 0.0
    slept_pacing = 0.0
    last_err: Optional[str] = None
    last_resp: Optional[httpx.Response] = None

    for i in range(max_attempts):
        attempts += 1

        # --- THIS is where the lock/pacer goes (right before the outbound request) ---
        slept_pacing += await _cisco_rate_wait(min_interval_s)

        try:
            r = await client.get(url, headers=headers, timeout=timeout_s)
            last_resp = r
        except Exception as e:
            last_err = f"request_exception: {e!r}"
            break

        if r.status_code != 429:
            return r, attempts, slept_429, slept_pacing, None

        # 429 handling
        ra = _parse_retry_after_seconds(r.headers.get("retry-after"))
        backoff = ra if ra is not None else min(30.0, (2.0 ** i))
        # small jitter so we don't thundering-herd if multiple callers
        backoff += random.random() * 0.25
        slept_429 += backoff
        await asyncio.sleep(backoff)

    return last_resp, attempts, slept_429, slept_pacing, last_err or "rate_limited"


def _normalize_cve_ostype_base(url_base: str) -> str:
    """
    Normalize Vault-provided base so we always end up with:
      https://apix.cisco.com/security/advisories/v2/OSType/
    even if Vault accidentally contains /v2, /v2/OSType, or /v2/OSType/OSType.

    Vault should be seeded like below
    {
      "advisories_client_secret": "",
      "advisories_key": "",
      "cve_api_advisories_url": "https://apix.cisco.com/security/advisories/v2/product?product=Cisco",
      "eox_client_secret": "",
      "eox_key": "",
      "url_CVEAdvisoriesBaseURL": "https://apix.cisco.com/security/advisories/v2/OSType/",
      "url_CVEAdvisoriesByProductURL": "https://apix.cisco.com/security/advisories/v2/product?product=",
      "url_CVEAdvisoriesCiscoIOSXR": "https://apix.cisco.com/security/advisories/v2/product?product=Cisco%20IOS%20XR",
      "url_EOXByProductID": "https://apix.cisco.com/supporttools/eox/rest/5/EOXByProductID/"
    }

    """
    base = (url_base or "").strip().rstrip("/")

    # Collapse accidental double include: .../OSType/OSType
    base = re.sub(r"(?i)/ostype/ostype$", "/OSType", base)

    # If someone stored just .../v2, append /OSType
    if base.lower().endswith("/v2"):
        base = f"{base}/OSType"

    # If someone stored .../v2/OSType/<something>, trim back to .../v2/OSType
    m = re.match(r"(?i)^(.*?/v2/ostype)(?:/.*)?$", base)
    if m:
        base = m.group(1)

    return base.rstrip("/") + "/"

def _build_cve_url_for_os_version(
    *,
    os_name: str,
    ver_clean: str,
    url_base: str,
    url_iosxr: str,
) -> str:
    os_name = (os_name or "").strip().lower()
    qv = quote(ver_clean or "", safe="")

    if os_name == "iosxr":
        iosxr = (url_iosxr or "").strip()
        if not iosxr:
            raise ValueError("missing url_iosxr (cfg['url_CVEAdvisoriesCiscoIOSXR'])")

        # If url already contains version=, overwrite it; else append it.
        if re.search(r"(?i)([?&]version=)", iosxr):
            return re.sub(r"(?i)([?&]version=)[^&]*", r"\1" + qv, iosxr)

        return iosxr + ("&" if "?" in iosxr else "?") + "version=" + qv

    base = _normalize_cve_ostype_base(url_base)
    return f"{base}{os_name}?version={qv}"


@router.get(
    "/devices/unique_os_versions",
    summary="Return unique (os, version) combinations from devices table",
    status_code=200,
)

async def devices_unique_os_versions(
    request: Request,
):
    payload: Dict[str, Any] = {
        "route": "devices_unique_os_versions",
        "client": {"host": getattr(request.client, "host", None), "port": getattr(request.client, "port", None)},
    }

    result = await select_unique_device_os_versions()
    payload["data"] = result
    return {"detail": payload}



@router.post(
    "/get_cisco_cve_os_version",
    summary="Get Cisco CVE data by OS + version (or iosxr / by_product_id)",
    status_code=200,
)
async def get_cisco_cve_os_version(
    request: Request,
    body: CiscoOSVersionRequest,
    user: UserContext = Depends(require_any_role("fastapi_client")),
):
    payload: Dict[str, Any] = {
        "route": "get_cisco_cve_os_version",
        "client": {"host": getattr(request.client, "host", None), "port": getattr(request.client, "port", None)},
        "input": body.model_dump(),
    }

    # ---- Vault-backed config load with explicit 403 handling ----
    try:
        cfg = await _load_cisco_cfg_or_500()
    except Exception as e:
        if _vault_status_code_from_exc(e) == 403:
            _raise_vault_access_denied(payload)
        if isinstance(e, HTTPException):
            raise
        raise HTTPException(
            status_code=HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "cisco_cfg_load_failed", "detail": {"message": str(e)}, **payload},
        )

    payload["vault_meta"] = _safe_vault_meta(cfg)

    advisories_key = str(cfg["advisories_key"]).strip()
    advisories_client_secret = str(cfg["advisories_client_secret"]).strip()

    url_base = str(cfg["url_CVEAdvisoriesBaseURL"]).strip()
    url_by_product = str(cfg["url_CVEAdvisoriesByProductURL"]).strip()
    url_iosxr = str(cfg["url_CVEAdvisoriesCiscoIOSXR"]).strip()

    os_name = (body.os or "").strip().lower()
    if not os_name:
        raise HTTPException(
            status_code=HTTP_400_BAD_REQUEST,
            detail={"error": "missing_os", "message": "os is required"},
        )

    ver_raw = (body.version or "").strip()
    ver_clean = _clean_version(ver_raw) if ver_raw else ""

    # Build the Cisco URL using ONLY Vault-provided bases
    if os_name == "by_product_id":
        if not body.product:
            raise HTTPException(
                status_code=HTTP_400_BAD_REQUEST,
                detail={"error": "missing_product", "message": "product is required when os=by_product_id"},
            )
        cve_url = f"{url_by_product}{quote(body.product.strip(), safe='')}"
    elif os_name == "iosxr":
        if not ver_clean:
            raise HTTPException(
                status_code=HTTP_400_BAD_REQUEST,
                detail={"error": "missing_version", "message": "version is required for iosxr"},
            )
        cve_url = f"{url_iosxr}&version={quote(ver_clean, safe='')}"
    else:
        if not ver_clean:
            raise HTTPException(
                status_code=HTTP_400_BAD_REQUEST,
                detail={"error": "missing_version", "message": "version is required"},
            )
        cve_url = f"{url_base}{os_name}?version={quote(ver_clean, safe='')}"

    payload["normalized"] = {"os": os_name, "version_raw": ver_raw, "version_clean": ver_clean}
    payload["cisco_request"] = {"url": cve_url}

    token = await _cisco_get_oauth_token(client_id=advisories_key, client_secret=advisories_client_secret)
    headers = {"Accept": "application/json", "Authorization": f"Bearer {token['access_token']}"}

    resp = await _http_get_json_or_text(url=cve_url, headers=headers, timeout_s=30.0)
    payload["cisco_response"] = resp

    if not resp.get("ok"):
        raise HTTPException(
            status_code=HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "cisco_cve_os_version_fetch_failed", **payload},
        )

    return {"detail": payload}


@router.post(
    "/get_cisco_eox",
    summary="EOX by ProductID (page index + product_id). Supports Cisco wildcard rules.",
    status_code=200,
)
async def get_cisco_eox(
    request: Request,
    body: CiscoEOXRequest,
    user: UserContext = Depends(require_any_role("fastapi_client")),
):
    payload: Dict[str, Any] = {
        "route": "get_cisco_eox",
        "client": {"host": getattr(request.client, "host", None), "port": getattr(request.client, "port", None)},
        "input": body.model_dump(),
    }

    # ---- Vault-backed config load with explicit 403 handling ----
    try:
        cfg = await _load_cisco_cfg_or_500()
    except Exception as e:
        if _vault_status_code_from_exc(e) == 403:
            _raise_vault_access_denied(payload)
        if isinstance(e, HTTPException):
            raise
        raise HTTPException(
            status_code=HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "cisco_cfg_load_failed", "detail": {"message": str(e)}, **payload},
        )

    payload["vault_meta"] = _safe_vault_meta(cfg)

    eox_key = str(cfg["eox_key"]).strip()
    eox_client_secret = str(cfg["eox_client_secret"]).strip()
    eox_base = str(cfg["url_EOXByProductID"]).strip()

    # Keep '*' and ',' unescaped for Cisco wildcard/multi-PID behavior; escape everything else unsafe in a path segment.
    page_index = quote(body.page_index.strip(), safe="")
    product_id = quote(body.product_id.strip(), safe="*,")

    eox_url = f"{eox_base}{page_index}/{product_id}"
    payload["cisco_request"] = {"url": eox_url}

    token = await _cisco_get_oauth_token(client_id=eox_key, client_secret=eox_client_secret)
    headers = {"Accept": "application/json", "Authorization": f"Bearer {token['access_token']}"}

    resp = await _http_get_json_or_text(url=eox_url, headers=headers, timeout_s=30.0)
    payload["cisco_response"] = resp

    if not resp.get("ok"):
        raise HTTPException(
            status_code=HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "cisco_eox_fetch_failed", **payload},
        )

    db_res = await upsert_reporting_cisco_api_eox_from_payload(
        database=database,
        payload=payload,
    )
    payload["db_upsert"] = db_res

    if not db_res.get("ok"):
        raise HTTPException(
            status_code=HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "cisco_eox_db_upsert_failed", **payload},
        )

    return {"detail": payload}

@router.post(
    "/devices/unique_os_versions/cve",
    summary="Query Cisco CVE Advisories for each unique device (os, version) and upsert results",
    status_code=200,
)
async def devices_unique_os_versions_cve(
    request: Request,
    body: CiscoBulkFromDevicesRequest,
    user: UserContext = Depends(require_any_role("fastapi_client")),
):
    payload: Dict[str, Any] = {
        "route": "devices_unique_os_versions_cve",
        "client": {"host": getattr(request.client, "host", None), "port": getattr(request.client, "port", None)},
        "input": body.model_dump(),
    }

    # ---- Load Cisco config from Vault (NO tuple-unpack) ----
    cfg = await _load_cisco_cfg_or_500()  # type: ignore[name-defined]
    payload["vault_meta"] = _safe_vault_meta(cfg)  # type: ignore[name-defined]

    # ---- Pull unique pairs from DB (handle dict-return or list-return) ----
    raw_pairs = await select_unique_device_os_versions()  # type: ignore[name-defined]
    if isinstance(raw_pairs, dict):
        pairs_items = raw_pairs.get("items") or []
        db_pairs_total = int(raw_pairs.get("count") or len(pairs_items))
    elif isinstance(raw_pairs, list):
        pairs_items = raw_pairs
        db_pairs_total = len(raw_pairs)
    else:
        pairs_items = []
        db_pairs_total = 0

    payload["db_pairs_total"] = db_pairs_total

    # ---- Normalize & filter ----
    supported = {"ios", "iosxe", "nxos", "asa", "ftd"}
    allow = set((body.os_allowlist or []))
    allow = {x.strip().lower() for x in allow if isinstance(x, str) and x.strip()}
    effective_allow = (supported & allow) if allow else supported

    normalized: List[Dict[str, str]] = []
    for it in pairs_items:
        if not isinstance(it, dict):
            continue
        os_name = str(it.get("os") or it.get("os_name") or "").strip().lower()
        ver_raw = str(it.get("version") or it.get("version_raw") or "").strip()
        if not os_name or not ver_raw:
            continue
        if os_name not in effective_allow:
            continue
        normalized.append({"os": os_name, "version_raw": ver_raw})

    # optional cap
    max_pairs = int(getattr(body, "max_pairs", 0) or 0)
    if max_pairs > 0:
        normalized = normalized[:max_pairs]

    payload["pairs_after_normalize"] = len(normalized)
    payload["effective_concurrency"] = 1  # force serial

    # ---- Cisco OAuth token ----
    token = await _cisco_get_oauth_token(  # type: ignore[name-defined]
        client_id=cfg["advisories_key"],
        client_secret=cfg["advisories_client_secret"],
    )
    headers = {"Accept": "application/json", "Authorization": f"Bearer {token['access_token']}"}

    # ---- Pacing configuration ----
    # Cisco told you: 5/sec and 30/min => 2.0s is the binding constraint; use 2.25s buffer.
    min_delay_s = float(getattr(body, "min_delay_s_between_requests", 2.25) or 2.25)
    timeout_s = float(getattr(body, "timeout_s", 30.0) or 30.0)
    max_429_attempts = int(getattr(body, "max_429_attempts", 5) or 5)
    sleep_between_batches = float(getattr(body, "sleep_s_between_batches", 0.0) or 0.0)

    cisco_ok = cisco_fail = 0
    db_ok = db_fail = 0

    # batching purely for response structure (not concurrency)
    batch_size = max(1, int(getattr(body, "batch_size", 5) or 5))
    batches = [normalized[i : i + batch_size] for i in range(0, len(normalized), batch_size)]
    batches_out: List[Dict[str, Any]] = []

    await insert_app_backend_tracking(  # type: ignore[name-defined]
        database=database,
        route=request.url.path,
        information={"event": "start", "pairs_total": len(normalized), "min_delay_s": min_delay_s},
    )

    import httpx

    async with httpx.AsyncClient() as client:
        for batch_index, batch in enumerate(batches, start=1):
            results: List[Dict[str, Any]] = []

            for pair in batch:
                os_name = pair["os"]
                version_raw = pair["version_raw"]

                chosen_url = None
                chosen_version = None
                chosen_status = None
                last_err = None

                chosen_body_json = None
                chosen_body_text_preview = None

                # try a few version formats bail when one succeeds.
                # cisco devices will tend to show their version in a format
                # that apix does not like. Example 10.2(3) would fail
                # but 10.2.3 might succeed
                for cand in _version_candidates_for_query(version_raw):
                    try:
                        url = _build_cve_url_for_os_version(
                            os_name=os_name,
                            ver_clean=cand,
                            url_base=cfg["url_CVEAdvisoriesBaseURL"],
                            url_iosxr=cfg["url_CVEAdvisoriesCiscoIOSXR"],
                        )
                    except Exception as e:
                        last_err = f"url_build_failed: {e!r}"
                        break

                    r, attempts, slept_429, slept_pacing, err = await _cisco_get_with_429_backoff(
                        client,
                        url=url,
                        headers=headers,
                        timeout_s=timeout_s,
                        min_interval_s=min_delay_s,
                        max_attempts=max_429_attempts,
                    )

                    chosen_url = url
                    chosen_version = cand
                    last_err = err

                    if r is None:
                        chosen_status = None
                        break

                    chosen_status = r.status_code

                    ct = (r.headers.get("content-type") or "").lower()
                    if "json" in ct:
                        try:
                            chosen_body_json = r.json()
                        except Exception:
                            chosen_body_text_preview = (r.text or "")[:2000]
                    else:
                        chosen_body_text_preview = (r.text or "")[:2000]

                    # stop conditions
                    if r.status_code == 200:
                        break
                    if r.status_code not in (404, 406):
                        break

                ok = bool(chosen_status == 200)
                if ok:
                    cisco_ok += 1
                else:
                    cisco_fail += 1

                # ---- Store BIG body in Postgres regardless of include_raw ----
                info_to_store = {
                    "pair": {
                        "os": os_name,
                        "version_raw": version_raw,
                        "version_used_for_query": chosen_version,
                    },
                    "request": {"url": chosen_url},
                    "response": {
                        "ok": ok,
                        "status_code": chosen_status,
                        "attempts": attempts if "attempts" in locals() else None,
                        "slept_429_s": slept_429 if "slept_429" in locals() else None,
                        "slept_pacing_s": slept_pacing if "slept_pacing" in locals() else None,
                    },
                    "response_body": {
                        "json": chosen_body_json,
                        "text_preview": chosen_body_text_preview,
                    },
                    "vault_meta": payload.get("vault_meta"),
                }

                db_res = await upsert_reporting_cisco_api_cve_software(
                    database=database,
                    os_name=os_name,
                    version=version_raw,
                    information=info_to_store,
                )

                db_row_ok = bool(isinstance(db_res, dict) and db_res.get("ok"))
                if db_row_ok:
                    db_ok += 1
                else:
                    db_fail += 1

                result_row: Dict[str, Any] = {
                    "ok": ok,
                    "status_code": chosen_status,
                    "os_name": os_name,
                    "version_raw": version_raw,
                    "version_used_for_query": chosen_version,
                    "url": chosen_url,
                    "cisco_error": last_err,
                    "db": {
                        "ok": db_row_ok,
                        "error": (db_res.get("error") if isinstance(db_res, dict) else "db_upsert_failed"),
                        "id": (db_res.get("id") if isinstance(db_res, dict) else None),
                        "detail": (db_res.get("detail") if isinstance(db_res, dict) else None),
                    },
                }

                # Only include raw response in HTTP response when requested
                if bool(getattr(body, "include_raw", False)):
                    result_row["response"] = {
                        "json": chosen_body_json,
                        "text_preview": chosen_body_text_preview,
                    }

                results.append(result_row)

                # Tracking: keep it SMALL (don’t log the json body)
                await insert_app_backend_tracking(  # type: ignore[name-defined]
                    database=database,
                    route=request.url.path,
                    information={
                        "event": "pair_complete",
                        "os_name": os_name,
                        "version": version_raw,
                        "status_code": chosen_status,
                        "db_ok": db_row_ok,
                    },
                )

            batches_out.append({"batch_index": batch_index, "batch_size": len(batch), "results": results})

            await insert_app_backend_tracking(  # type: ignore[name-defined]
                database=database,
                route=request.url.path,
                information={
                    "event": "batch_complete",
                    "batch_index": batch_index,
                    "batch_size": len(batch),
                    "cisco_ok_total": cisco_ok,
                    "cisco_fail_total": cisco_fail,
                    "db_ok_total": db_ok,
                    "db_fail_total": db_fail,
                },
            )

            if sleep_between_batches > 0:
                await asyncio.sleep(sleep_between_batches)

    payload["ok_count"] = cisco_ok
    payload["fail_count"] = cisco_fail
    payload["db_upserts"] = {"ok": db_ok, "fail": db_fail}

    await insert_app_backend_tracking(  # type: ignore[name-defined]
        database=database,
        route=request.url.path,
        information={"event": "done", "ok": cisco_ok, "fail": cisco_fail, "db_ok": db_ok, "db_fail": db_fail},
    )

    return {"detail": {**payload, "batches": batches_out}}