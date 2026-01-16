"""
Notes
-----
How to run (worker):
  celery -A app.celery_app:celery_app worker -l INFO

Purpose:
- Celery tasks for Network Tools, including device discovery offloads.

TODO : Setup to give this a larger subnet 10.0.0.0/24 for example, and have it save all the jobs for it
and execute 1 by 1 for each ip.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import traceback
from typing import Any, Dict

from app.celery_app import celery_app
from app.database import database, connect_db, disconnect_db
from app.database_queries.postgres_insert_queries import insert_app_backend_tracking
from app.shared_functions.helpers.helpers import scrub_secrets

from app.shared_functions.helpers.vault_client import (
    vault_kv2_read,
    vault_kv2_read_all_under_prefix
)

from app.network_utilities.icmp_check import pingOk

logger = logging.getLogger("app.celery.tasks")


def _run_async(coro):
    try:
        return asyncio.run(coro)
    except RuntimeError:
        loop = asyncio.get_event_loop()
        return loop.run_until_complete(coro)


async def _update_job(
    *,
    job_id: str,
    status: str,
    started: bool = False,
    completed: bool = False,
    duration_ms: int | None = None,
    worker_hostname: str | None = None,
    result: dict | None = None,
    error_type: str | None = None,
    error_message: str | None = None,
    tb: str | None = None,
):
    """
    Update your app_tracking_celery row. This matches what celery_jobs.py reads.
    """
    sql = """
    UPDATE app_tracking_celery
    SET
      status = :status,
      updated_at = now(),
      started_at = CASE WHEN :started THEN COALESCE(started_at, now()) ELSE started_at END,
      completed_at = CASE WHEN :completed THEN now() ELSE completed_at END,
      duration_ms = COALESCE(:duration_ms, duration_ms),
      worker_hostname = COALESCE(:worker_hostname, worker_hostname),
      result = COALESCE(CAST(:result_json AS jsonb), result),
      error_type = COALESCE(:error_type, error_type),
      error_message = COALESCE(:error_message, error_message),
      traceback = COALESCE(:traceback, traceback)
    WHERE job_id = :job_id
    """
    await database.execute(
        sql,
        {
            "job_id": job_id,
            "status": status,
            "started": started,
            "completed": completed,
            "duration_ms": duration_ms,
            "worker_hostname": worker_hostname,
            "result_json": json.dumps(result) if result is not None else None,
            "error_type": error_type,
            "error_message": error_message,
            "traceback": tb,
        },
    )


@celery_app.task(name="device_discovery.start_device_discovery", bind=True)
def device_discovery_start_device_discovery(self, meta: Dict[str, Any]) -> Dict[str, Any]:
    """
    meta must include:
      - job_id
      - target_ip
      - requested_by
      - route (optional)
    """
    t0 = time.perf_counter()
    task_id = getattr(self.request, "id", None)
    worker_hostname = getattr(self.request, "hostname", None)

    async def _run():
        await connect_db()
        try:
            job_id = str(meta.get("job_id", "")).strip()
            target_ip = str(meta.get("target_ip", "")).strip()
            route = str(meta.get("route") or "/device_discovery/start_device_discovery")

            if not job_id or not target_ip:
                err = {"error": "missing_required_meta", "job_id": job_id, "target_ip": target_ip}
                logger.error("icmp_ping bad meta: %s", err)
                return err

            # mark STARTED
            await _update_job(
                job_id=job_id,
                status="STARTED",
                started=True,
                worker_hostname=worker_hostname,
            )

            # run ICMP check (async helper)
            ok = bool(await pingOk(target_ip))

            ms = int((time.perf_counter() - t0) * 1000)

            result = {
                "ping_ok": ok,
                "target_ip": target_ip,
                "job_id": job_id,
                "celery_task_id": task_id,
                "requested_by": meta.get("requested_by"),
                "azp": meta.get("azp"),
                "roles": meta.get("roles") or [],
            }

            # Store results of the ICMP task
            await insert_app_backend_tracking(
                database=database,
                route=route,
                information={
                    "event": "icmp_ping_complete",
                    "result": scrub_secrets(result),
                    "meta": scrub_secrets(meta),
                },
            )


            # TODO Left off here!
            # Start SSH Discovery
            # If icmp_bypass == false and ok == true
            # or icmp_bypass == true

            # Temp logging to see how vault works with celery
            device_profiles = await vault_kv2_read(
                mount="app_network_tools_secrets",
                secret_path="device_login_profiles"
            )

            await insert_app_backend_tracking(
                database=database,
                route="Test device credential fetch",
                information={
                    "device_profiles": device_profiles
                },
            )

            # update the job details in the database
            await _update_job(
                job_id=job_id,
                status="SUCCESS" if ok else "FAILURE",
                completed=True,
                duration_ms=ms,
                worker_hostname=worker_hostname,
                result=result,
            )



            return {"detail": result}

        except Exception as exc:
            ms = int((time.perf_counter() - t0) * 1000)
            tb = traceback.format_exc()

            job_id = str(meta.get("job_id", "")).strip()
            if job_id:
                await _update_job(
                    job_id=job_id,
                    status="FAILURE",
                    completed=True,
                    duration_ms=ms,
                    worker_hostname=worker_hostname,
                    error_type=type(exc).__name__,
                    error_message=str(exc),
                    tb=tb,
                )

            logger.exception("icmp_ping failed job_id=%s task_id=%s", meta.get("job_id"), task_id)
            return {"error": f"celery_task_failed: {exc}"}

        finally:
            await disconnect_db()

    return _run_async(_run())
