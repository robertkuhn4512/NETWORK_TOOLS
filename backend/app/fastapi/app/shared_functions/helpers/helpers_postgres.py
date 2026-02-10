from __future__ import annotations

import json
import ipaddress
import os
from typing import Any, Dict, Optional
from urllib.parse import quote
from app.database import database
from uuid import uuid4
from app.database_queries.postgres_insert_queries import insert_app_backend_tracking

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

ACTIVE_STATUSES = ("QUEUED", "RECEIVED", "STARTED", "RETRY")

def _is_active_dedupe_conflict(exc: Exception) -> bool:
    """
    Detect conflict with uq_app_tracking_celery_active_dedupe.
    We intentionally keep this string-based because exception wrapping varies.
    """
    msg = str(exc)
    return "uq_app_tracking_celery_active_dedupe" in msg or (
        "duplicate key value violates unique constraint" in msg
        and "uq_app_tracking_celery_active_dedupe" in msg
    )


async def _reserve_job_row_queued(
    *,
    job_name: str,
    dedupe_key: str,
    request_payload: Optional[Dict[str, Any]] = None,
    correlation_id: Optional[str] = None,
    queue: Optional[str] = None,
    routing_key: Optional[str] = None,
    exchange: Optional[str] = None,
    priority: Optional[int] = None,
    parent_job_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Reserve a row in public.app_tracking_celery BEFORE enqueue.

    Returns:
      {
        "created": bool,
        "job_id": str,
        "task_id": str,
        "status": str,
        "error": Optional[str],
        "detail": Optional[dict]
      }

    Behavior:
      - Creates a new job row with status QUEUED when no active dedupe exists.
      - If an active dedupe exists (uq_app_tracking_celery_active_dedupe), returns the existing job row with created=False.
    """
    route = (request_payload or {}).get("route") or "internal/_reserve_job_row_queued"
    requested_by = (request_payload or {}).get("requested_by")

    if not job_name or not str(job_name).strip():
        return {"error": "missing_job_name", "detail": {"message": "job_name is required"}}

    if not dedupe_key or not str(dedupe_key).strip():
        return {"error": "missing_dedupe_key", "detail": {"message": "dedupe_key is required"}}

    job_id = str(uuid4())
    task_id = job_id  # keep celery task id == job_id (simple + deterministic)

    req_json = json.dumps(request_payload or {}, default=str)

    insert_sql = """
    INSERT INTO public.app_tracking_celery (
        job_id,
        task_id,
        job_name,
        dedupe_key,
        status,
        correlation_id,
        queue,
        routing_key,
        exchange,
        priority,
        parent_job_id,
        request
    )
    VALUES (
        CAST(:job_id AS uuid),
        :task_id,
        :job_name,
        :dedupe_key,
        'QUEUED',
        :correlation_id,
        :queue,
        :routing_key,
        :exchange,
        :priority,
        CAST(:parent_job_id AS uuid),
        CAST(:request AS jsonb)
    )
    RETURNING job_id, task_id, status
    """

    values = {
        "job_id": job_id,
        "task_id": task_id,
        "job_name": job_name,
        "dedupe_key": dedupe_key,
        "correlation_id": correlation_id,
        "queue": queue,
        "routing_key": routing_key,
        "exchange": exchange,
        "priority": priority,
        "parent_job_id": parent_job_id,
        "request": req_json,
    }

    try:
        row = await database.fetch_one(query=insert_sql, values=values)

        await insert_app_backend_tracking(
            database=database,
            route=route,
            information={
                "event": "app_tracking_celery_reserved",
                "created": True,
                "job_id": job_id,
                "task_id": task_id,
                "job_name": job_name,
                "dedupe_key": dedupe_key,
                "correlation_id": correlation_id,
                "requested_by": requested_by,
            },
        )

        return {
            "created": True,
            "job_id": str(row["job_id"]) if row and "job_id" in row else job_id,
            "task_id": str(row["task_id"]) if row and "task_id" in row else task_id,
            "status": str(row["status"]) if row and "status" in row else "QUEUED",
        }

    except Exception as exc:
        # If we hit the active dedupe unique index, return the existing active job
        if _is_active_dedupe_conflict(exc):
            select_sql = """
            SELECT job_id, task_id, status
            FROM public.app_tracking_celery
            WHERE job_name = :job_name
              AND dedupe_key = :dedupe_key
              AND is_deleted = false
              AND status = ANY(:active_statuses)
            ORDER BY created_at DESC
            LIMIT 1
            """
            row = await database.fetch_one(
                query=select_sql,
                values={"job_name": job_name, "dedupe_key": dedupe_key, "active_statuses": list(ACTIVE_STATUSES)},
            )

            if row:
                await insert_app_backend_tracking(
                    database=database,
                    route=route,
                    information={
                        "event": "app_tracking_celery_reserved",
                        "created": False,
                        "job_id": str(row["job_id"]),
                        "task_id": str(row["task_id"]),
                        "job_name": job_name,
                        "dedupe_key": dedupe_key,
                        "correlation_id": correlation_id,
                        "requested_by": requested_by,
                        "note": "active_dedupe_exists",
                    },
                )

                return {
                    "created": False,
                    "job_id": str(row["job_id"]),
                    "task_id": str(row["task_id"]),
                    "status": str(row["status"]),
                }

            # Dedupe conflict but couldn't find the row (should be rare)
            await insert_app_backend_tracking(
                database=database,
                route=route,
                information={
                    "event": "app_tracking_celery_reserve_error",
                    "job_name": job_name,
                    "dedupe_key": dedupe_key,
                    "correlation_id": correlation_id,
                    "requested_by": requested_by,
                    "error": str(exc),
                    "note": "dedupe_conflict_but_no_row_found",
                },
            )
            return {"error": "dedupe_conflict_no_row", "detail": {"message": str(exc)}}

        # Real failure
        await insert_app_backend_tracking(
            database=database,
            route=route,
            information={
                "event": "app_tracking_celery_reserve_error",
                "job_id": job_id,
                "task_id": task_id,
                "job_name": job_name,
                "dedupe_key": dedupe_key,
                "correlation_id": correlation_id,
                "requested_by": requested_by,
                "error": str(exc),
            },
        )
        return {"error": "reserve_failed", "detail": {"message": str(exc)}}

async def _attach_task_id(*, job_id: str, task_id: str) -> Dict[str, Any]:
    sql = """
    UPDATE public.app_tracking_celery
    SET task_id = :task_id,
        updated_at = now()
    WHERE job_id = CAST(:job_id AS uuid)
    """
    await database.execute(query=sql, values={"job_id": job_id, "task_id": task_id})
    return {"detail": {"ok": True, "job_id": job_id, "task_id": task_id}}

async def _mark_job_failed_enqueue(*, job_id: str, error_message: str) -> Dict[str, Any]:
    sql = """
    UPDATE public.app_tracking_celery
    SET status = 'FAILURE',
        error_type = 'EnqueueError',
        error_message = :error_message,
        updated_at = now(),
        completed_at = now()
    WHERE job_id = CAST(:job_id AS uuid)
    """
    await database.execute(
        query=sql,
        values={"job_id": job_id, "error_message": (error_message or "")[:2000]},
    )
    return {"detail": {"ok": True, "job_id": job_id, "status": "FAILURE"}}