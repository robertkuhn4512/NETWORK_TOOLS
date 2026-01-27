"""
Notes
-----
How to run (dev):
  uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

How to run (prod):
  gunicorn -k uvicorn.workers.UvicornWorker -w 2 -b 0.0.0.0:8000 app.main:app

Vault env:
- Expected at: /run/vault/fastapi_secrets.json
- This file should contain most configuration keys (APP_ENV, CORS_ALLOW_ORIGINS, LOG_LEVEL, TRUSTED_HOSTS, etc.)
"""

import os
import time
import logging
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.gzip import GZipMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.routers.auth_test import router as auth_test_router
from app.routers.device_discovery import router as device_discovery_router
from app.routers.celery_jobs import router as celery_jobs_router

from app.shared_functions.helpers.helpers_logging_config import setup_logging, load_env_from_vault_json
from app.database import connect_db, disconnect_db

# 1) Load env from Vault-rendered JSON FIRST (so LOG_LEVEL, CORS, etc. come from it)
load_env_from_vault_json("/run/vault/fastapi_secrets.json")

# 2) Configure logging SECOND
setup_logging()
logger = logging.getLogger(__name__)

access_logger = logging.getLogger("app.access")

def _parse_csv_env(name: str, default: Optional[list[str]] = None) -> Optional[list[str]]:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    items = [x.strip() for x in raw.split(",") if x.strip()]
    return items or default


def create_app() -> FastAPI:
    app = FastAPI()

    @app.middleware("http")
    async def access_log(request: Request, call_next):
        start = time.perf_counter()
        response = await call_next(request)
        ms = (time.perf_counter() - start) * 1000.0

        access_logger.info(
            "%s %s -> %s (%.2fms)",
            request.method,
            request.url.path,
            response.status_code,
            ms,
        )
        return response

    @app.get("/health", tags=["ops"])
    async def health():
        logger.debug("health called")
        return {"detail": {"status": "ok"}}

    # -------------------------
    # Middleware
    # -------------------------

    # gzip responses above threshold (optional; keep if you want app-side compression)
    app.add_middleware(GZipMiddleware, minimum_size=1000)

    # Trusted hosts (recommended in prod; configure via TRUSTED_HOSTS in vault json)
    app_env = os.getenv("APP_ENV", "dev").lower()
    trusted_hosts = _parse_csv_env(
        "TRUSTED_HOSTS",
        default=["localhost", "127.0.0.1"] if app_env != "prod" else ["networkengineertools.com", "*.networkengineertools.com"],
    )
    if trusted_hosts:
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=trusted_hosts)

    # CORS (configure via vault json)
    cors_allow_credentials = os.getenv("CORS_ALLOW_CREDENTIALS", "0") == "1"
    allow_origins = _parse_csv_env("CORS_ALLOW_ORIGINS", default=["*"] if app_env != "prod" else None)
    allow_origin_regex = os.getenv("CORS_ALLOW_ORIGIN_REGEX", "").strip() or None

    if cors_allow_credentials and allow_origins and "*" in allow_origins:
        raise RuntimeError('CORS misconfig: CORS_ALLOW_CREDENTIALS=1 cannot be used with CORS_ALLOW_ORIGINS="*"')

    if allow_origins or allow_origin_regex:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=allow_origins or [],
            allow_origin_regex=allow_origin_regex,
            allow_credentials=cors_allow_credentials,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    # -------------------------
    # Routers
    # -------------------------
    app.include_router(auth_test_router)
    app.include_router(device_discovery_router)
    app.include_router(celery_jobs_router)

    @app.on_event("startup")
    async def on_startup():
        await connect_db()
        logger.info(
            "startup complete (APP_ENV=%s LOG_LEVEL=%s)",
            os.getenv("APP_ENV", "dev"),
            os.getenv("LOG_LEVEL", "INFO"),
        )

    @app.on_event("shutdown")
    async def on_shutdown():
        logger.info("shutdown starting")
        await disconnect_db()

    return app


app = create_app()
