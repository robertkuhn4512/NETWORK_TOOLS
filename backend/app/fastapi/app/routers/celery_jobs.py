"""
celery_jobs router

Notes / How to run:
- Ensure the table exists by applying the SQL in app_tracking_celery.sql to your Postgres (network_tools DB).
- Ensure your app exposes the shared async connector as `database` (databases lib), and that it is connected on startup.
- Include this router in app.main (app.include_router(celery_jobs.router)).

Endpoints:
- GET    /celery_jobs
- GET    /celery_jobs/{job_id}
- GET    /celery_jobs/by_task/{task_id}
- DELETE /celery_jobs/{job_id}
- DELETE /celery_jobs/completed
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from datetime import datetime, timedelta, timezone
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query

# Assumptions based on your structure:
# - `database` is your shared async connector (databases lib)
# - `insert_app_backend_tracking` exists for structured logging/tracking
from app.database import database
from app.database_queries.postgres_insert_queries import (insert_app_backend_tracking)

router = APIRouter(prefix="/celery_jobs", tags=["celery_jobs"])


TERMINAL_STATUSES = {"SUCCESS", "FAILURE", "REVOKED", "EXPIRED", "CANCELED"}
ACTIVE_STATUSES = {"QUEUED", "RECEIVED", "STARTED", "RETRY"}


def _row_to_dict(row: Any) -> Dict[str, Any]:
    # databases returns Row objects; row._mapping is the safe dict view
    return dict(row._mapping) if row is not None else {}


@router.get("", status_code=200)
async def list_celery_jobs(
    status: Optional[List[str]] = Query(default=None, description="Filter by status (repeatable)."),
    include_deleted: bool = Query(default=False),
    job_name: Optional[str] = Query(default=None),
    correlation_id: Optional[str] = Query(default=None),
    created_after: Optional[datetime] = Query(default=None),
    created_before: Optional[datetime] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> Dict[str, Any]:
    """
    List jobs for UI (paged).
    """
    try:
        where: List[str] = []
        params: Dict[str, Any] = {
            "limit": limit,
            "offset": offset,
        }

        if not include_deleted:
            where.append("is_deleted = FALSE")

        if status:
            where.append("status = ANY(:status)")
            params["status"] = status

        if job_name:
            where.append("job_name = :job_name")
            params["job_name"] = job_name

        if correlation_id:
            where.append("correlation_id = :correlation_id")
            params["correlation_id"] = correlation_id

        if created_after:
            where.append("created_at >= :created_after")
            params["created_after"] = created_after

        if created_before:
            where.append("created_at <= :created_before")
            params["created_before"] = created_before

        where_sql = ("WHERE " + " AND ".join(where)) if where else ""

        sql = f"""
            SELECT
              job_id, task_id, job_name, queue, routing_key, exchange, priority,
              status, retries, max_retries, eta, expires_at,
              created_at, updated_at, started_at, completed_at, duration_ms,
              worker_hostname, worker_pid, correlation_id,
              parent_job_id, request, result, error_type, error_message,
              is_deleted, deleted_at, deleted_by
            FROM app_tracking_celery
            {where_sql}
            ORDER BY created_at DESC
            LIMIT :limit OFFSET :offset
        """

        rows = await database.fetch_all(sql, params)
        items = [_row_to_dict(r) for r in rows]

        # total count for pagination
        count_sql = f"SELECT COUNT(1) AS cnt FROM app_tracking_celery {where_sql}"
        count_params = dict(params)
        count_params.pop("limit", None)
        count_params.pop("offset", None)

        cnt_row = await database.fetch_one(count_sql, count_params)
        total = int(_row_to_dict(cnt_row).get("cnt", 0))

        await insert_app_backend_tracking(
            database=database,
            route="celery_jobs_list",
            information={
                "status": "success",
                "details": {"filters": {"status": status, "job_name": job_name, "correlation_id": correlation_id}}
            }

        )

        return {"detail": {"items": items, "total": total, "limit": limit, "offset": offset}}

    except Exception as exc:
        await insert_app_backend_tracking(
            database=database,
            route="celery_jobs_list",
            information={
                "status": "failure",
                "details": {"error": str(exc)}
            }

        )
        raise HTTPException(status_code=500, detail={"error": f"celery_jobs_list_failed: {exc}"})


@router.get("/{job_id}", status_code=200)
async def get_celery_job(job_id: UUID) -> Dict[str, Any]:
    """
    Fetch a job by job_id.
    """
    try:
        sql = """
            SELECT
              job_id, task_id, job_name, queue, routing_key, exchange, priority,
              status, retries, max_retries, eta, expires_at,
              created_at, updated_at, started_at, completed_at, duration_ms,
              worker_hostname, worker_pid, correlation_id,
              parent_job_id, request, result, error_type, error_message, traceback,
              is_deleted, deleted_at, deleted_by
            FROM app_tracking_celery
            WHERE job_id = :job_id
            LIMIT 1
        """
        row = await database.fetch_one(sql, {"job_id": job_id})
        if not row:
            raise HTTPException(status_code=404, detail={"error": "job_not_found"})

        await insert_app_backend_tracking(
            database=database,
            route="celery_jobs_get",
            information={
                "status": "success",
                "details": {"job_id": str(job_id)}
            }
        )

        return {"detail": _row_to_dict(row)}

    except HTTPException:
        raise
    except Exception as exc:
        await insert_app_backend_tracking(
            database=database,
            route="celery_jobs_get",
            information={
                "status": "failure",
                "details": {"job_id": str(job_id), "error": str(exc)}
            }

        )
        raise HTTPException(status_code=500, detail={"error": f"celery_jobs_get_failed: {exc}"})


@router.get("/by_task/{task_id}", status_code=200)
async def get_celery_job_by_task_id(task_id: str) -> Dict[str, Any]:
    """
    Fetch a job by Celery task_id.
    """
    try:
        sql = """
            SELECT
              job_id, task_id, job_name, queue, routing_key, exchange, priority,
              status, retries, max_retries, eta, expires_at,
              created_at, updated_at, started_at, completed_at, duration_ms,
              worker_hostname, worker_pid, correlation_id,
              parent_job_id, request, result, error_type, error_message, traceback,
              is_deleted, deleted_at, deleted_by
            FROM app_tracking_celery
            WHERE task_id = :task_id
            LIMIT 1
        """
        row = await database.fetch_one(sql, {"task_id": task_id})
        if not row:
            raise HTTPException(status_code=404, detail={"error": "job_not_found"})

        await insert_app_backend_tracking(
            database=database,
            route="celery_jobs_get_by_task",
            information={
                "status": "success",
                "details": {"task_id": task_id}
            }

        )

        return {"detail": _row_to_dict(row)}

    except HTTPException:
        raise
    except Exception as exc:
        await insert_app_backend_tracking(
            database=database,
            route="celery_jobs_get_by_task",
            information={
                "status": "failure",
                "details": {"task_id": task_id, "error": str(exc)}
            }

        )
        raise HTTPException(status_code=500, detail={"error": f"celery_jobs_get_by_task_failed: {exc}"})


@router.delete("/{job_id}", status_code=200)
async def delete_completed_job(
    job_id: UUID,
    hard: bool = Query(default=False, description="If true, permanently delete row (hard purge)."),
    deleted_by: Optional[str] = Query(default=None, description="Optional actor identifier for auditing."),
) -> Dict[str, Any]:
    """
    Delete a job ONLY if it is in a terminal state.
    - Default: soft delete (is_deleted=true)
    - hard=true: physical delete
    """
    try:
        # 1) verify terminal
        check_sql = """
            SELECT job_id, status, is_deleted
            FROM app_tracking_celery
            WHERE job_id = :job_id
            LIMIT 1
        """
        row = await database.fetch_one(check_sql, {"job_id": job_id})
        if not row:
            raise HTTPException(status_code=404, detail={"error": "job_not_found"})

        data = _row_to_dict(row)
        status = str(data.get("status", "")).upper()

        if status not in TERMINAL_STATUSES:
            raise HTTPException(
                status_code=409,
                detail={"error": f"job_not_terminal: status={status}"},
            )

        if hard:
            del_sql = "DELETE FROM app_tracking_celery WHERE job_id = :job_id"
            await database.execute(del_sql, {"job_id": job_id})
            await insert_app_backend_tracking(
                database=database,
                route="celery_jobs_delete_hard",
                information={
                    "status": "success",
                    "details": {"job_id": str(job_id), "status": status}
                }

            )
            return {"detail": {"deleted": 1, "hard": True, "job_id": str(job_id)}}

        # soft delete
        upd_sql = """
            UPDATE app_tracking_celery
            SET is_deleted = TRUE,
                deleted_at = now(),
                deleted_by = :deleted_by
            WHERE job_id = :job_id
              AND is_deleted = FALSE
        """
        await database.execute(upd_sql, {"job_id": job_id, "deleted_by": deleted_by})

        await insert_app_backend_tracking(
            database=database,
            route="celery_jobs_delete_soft",
            information={
                "status": "success",
                "details": {"job_id": str(job_id), "status": status}
            }

        )
        return {"detail": {"deleted": 1, "hard": False, "job_id": str(job_id)}}

    except HTTPException:
        raise
    except Exception as exc:
        await insert_app_backend_tracking(
            database=database,
            route="celery_jobs_delete",
            information={
                "status": "failure",
                "details": {"job_id": str(job_id), "error": str(exc)}
            }

        )
        raise HTTPException(status_code=500, detail={"error": f"celery_jobs_delete_failed: {exc}"})


@router.delete("/completed", status_code=200)
async def delete_completed_jobs_bulk(
    older_than_hours: int = Query(default=24, ge=0, le=24 * 365),
    hard: bool = Query(default=False),
    limit: int = Query(default=500, ge=1, le=5000),
    deleted_by: Optional[str] = Query(default=None),
) -> Dict[str, Any]:
    """
    Bulk delete completed jobs older than N hours.
    - Default: soft delete.
    - hard=true: hard purge (DELETE).
    """
    try:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=older_than_hours)

        if hard:
            # Hard purge with a limit using a CTE to avoid deleting huge sets at once
            sql = """
                WITH candidates AS (
                  SELECT job_id
                  FROM app_tracking_celery
                  WHERE status = ANY(:terminal_statuses)
                    AND completed_at IS NOT NULL
                    AND completed_at < :cutoff
                  ORDER BY completed_at ASC
                  LIMIT :limit
                )
                DELETE FROM app_tracking_celery t
                USING candidates c
                WHERE t.job_id = c.job_id
                RETURNING t.job_id
            """
            rows = await database.fetch_all(
                sql,
                {"terminal_statuses": list(TERMINAL_STATUSES), "cutoff": cutoff, "limit": limit},
            )
            deleted = len(rows)

            await insert_app_backend_tracking(
                database=database,
                route="celery_jobs_bulk_delete_hard",
                information={
                    "status": "success",
                    "details": {"older_than_hours": older_than_hours, "deleted": deleted}
                }

            )
            return {"detail": {"deleted": deleted, "hard": True, "older_than_hours": older_than_hours}}

        # Soft delete
        sql = """
            WITH candidates AS (
              SELECT job_id
              FROM app_tracking_celery
              WHERE is_deleted = FALSE
                AND status = ANY(:terminal_statuses)
                AND completed_at IS NOT NULL
                AND completed_at < :cutoff
              ORDER BY completed_at ASC
              LIMIT :limit
            )
            UPDATE app_tracking_celery t
            SET is_deleted = TRUE,
                deleted_at = now(),
                deleted_by = :deleted_by
            FROM candidates c
            WHERE t.job_id = c.job_id
            RETURNING t.job_id
        """
        rows = await database.fetch_all(
            sql,
            {
                "terminal_statuses": list(TERMINAL_STATUSES),
                "cutoff": cutoff,
                "limit": limit,
                "deleted_by": deleted_by,
            },
        )
        deleted = len(rows)

        await insert_app_backend_tracking(
            database=database,
            route="celery_jobs_bulk_delete_soft",
            information={
                "status": "success",
                "details": {"older_than_hours": older_than_hours, "deleted": deleted},
            }

        )
        return {"detail": {"deleted": deleted, "hard": False, "older_than_hours": older_than_hours}}

    except Exception as exc:
        await insert_app_backend_tracking(
            database=database,
            route="celery_jobs_bulk_delete",
            information={
                "status": "failure",
                "details": {"older_than_hours": older_than_hours, "error": str(exc)},
            }

        )
        raise HTTPException(status_code=500, detail={"error": f"celery_jobs_bulk_delete_failed: {exc}"})
