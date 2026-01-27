from __future__ import annotations

import json
import ipaddress
import os
from typing import Any, Dict, Optional
from urllib.parse import quote
from app.database import database
from uuid import uuid4

def build_postgres_async_dsn() -> str:
    """
    Builds an asyncpg DSN from Vault-injected env vars.

    Env:
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
    db_enc = quote(db, safe="")  # optional; safe either way

    return f"postgresql+asyncpg://{user}:{pw}@{host}:{port}/{db_enc}"

ACTIVE_STATUSES = ("QUEUED", "STARTED", "RETRY")

async def _reserve_job_row_queued(*, job_name: str, dedupe_key: str, request_payload: dict, correlation_id: str | None):
    job_id = str(uuid4())
    task_id = str(uuid4())  # pre-generate so task_id is never NULL

    insert_sql = """
    INSERT INTO app_tracking_celery (
        job_id, task_id, job_name, dedupe_key, correlation_id,
        status, request, created_at, updated_at
    )
    VALUES (
        :job_id, :task_id, :job_name, :dedupe_key, :correlation_id,
        'QUEUED', CAST(:request AS jsonb), now(), now()
    )
    ON CONFLICT (job_name, dedupe_key)
    WHERE is_deleted = FALSE AND status IN ('QUEUED','RECEIVED','STARTED','RETRY')
    DO NOTHING
    RETURNING job_id, task_id
    """

    row = await database.fetch_one(insert_sql, {
        "job_id": job_id,
        "task_id": task_id,
        "job_name": job_name,
        "dedupe_key": dedupe_key,
        "correlation_id": correlation_id,
        "request": json.dumps(request_payload),
    })

    if row:
        return {"created": True, "job_id": row["job_id"], "task_id": row["task_id"], "status": "QUEUED"}

    # duplicate active job exists
    select_sql = """
    SELECT job_id, task_id, status
    FROM app_tracking_celery
    WHERE is_deleted = FALSE
      AND job_name = :job_name
      AND dedupe_key = :dedupe_key
      AND status IN ('QUEUED','RECEIVED','STARTED','RETRY')
    ORDER BY created_at DESC
    LIMIT 1
    """
    existing = await database.fetch_one(select_sql, {"job_name": job_name, "dedupe_key": dedupe_key})
    if existing:
        return {"created": False, "job_id": existing["job_id"], "task_id": existing["task_id"], "status": existing["status"]}

    return {"error": "reserve_failed_unknown_state"}

async def _attach_task_id(*, job_id: str, task_id: str) -> None:
    sql = """
    UPDATE app_tracking_celery
    SET task_id = :task_id,
        updated_at = now()
    WHERE job_id = :job_id
    """
    await database.execute(sql, {"job_id": job_id, "task_id": task_id})

async def _mark_job_failed_enqueue(*, job_id: str, error_message: str) -> None:
    sql = """
    UPDATE app_tracking_celery
    SET status = 'FAILURE',
        error_message = :error_message,
        updated_at = now(),
        completed_at = now()
    WHERE job_id = :job_id
    """
    await database.execute(sql, {"job_id": job_id, "error_message": error_message[:2000]})