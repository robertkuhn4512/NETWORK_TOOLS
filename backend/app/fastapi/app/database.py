"""
Notes:
- How to run:
  - This module is imported by FastAPI (app.main) and provides a shared async
    database connector: `from app.database import database`
  - FastAPI should call `await connect_db()` on startup and `await disconnect_db()`
    on shutdown (see main.py patch below).

Purpose:
- Central Postgres connection pool for the FastAPI process using `databases`.
"""

from __future__ import annotations

import logging
import os
from urllib.parse import quote

from databases import Database

logger = logging.getLogger("app.db")

def _env_int(name: str, default: int) -> int:
    raw = (os.getenv(name) or "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default

def build_database_url() -> str:
    """
    Builds a DSN for databases+asyncpg using Vault-injected env vars.

    Env (from /run/vault/fastapi_secrets.json after load_env_from_vault_json runs):
      FASTAPI_DB_URL_HOST
      FASTAPI_DB_URL_PORT
      FASTAPI_DB_URL_DATABASE
      FASTAPI_DB_USERNAME
      FASTAPI_DB_PASSWORD

    Returns:
      postgresql+asyncpg://<urlencoded_user>:<urlencoded_pass>@host:port/db
    """
    host = os.getenv("FASTAPI_DB_URL_HOST", "localhost")
    port = os.getenv("FASTAPI_DB_URL_PORT", "5432")
    db = os.getenv("FASTAPI_DB_URL_DATABASE", "network_tools")

    user_raw = os.getenv("FASTAPI_DB_USERNAME", "")
    pw_raw = os.getenv("FASTAPI_DB_PASSWORD", "")

    user = quote(user_raw, safe="")
    pw = quote(pw_raw, safe="")
    db_enc = quote(db, safe="")

    return f"postgresql+asyncpg://{user}:{pw}@{host}:{port}/{db_enc}"


# Optional pool sizing (safe defaults)
# These currently are not wired into the environment variables but can be
# added into the vault fastapi_secrets endpoint if you need to adjust them

DB_POOL_MIN = _env_int("FASTAPI_DB_POOL_MIN", 1)
DB_POOL_MAX = _env_int("FASTAPI_DB_POOL_MAX", 5)

DATABASE_URL = build_database_url()
database = Database(DATABASE_URL, min_size=DB_POOL_MIN, max_size=DB_POOL_MAX)


async def connect_db() -> None:
    if database.is_connected:
        return
    # Don’t log DATABASE_URL (contains credentials).
    logger.info("connecting to postgres (pool min=%s max=%s)", DB_POOL_MIN, DB_POOL_MAX)
    await database.connect()


async def disconnect_db() -> None:
    if not database.is_connected:
        return
    logger.info("disconnecting from postgres")
    await database.disconnect()
