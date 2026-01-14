"""
Notes
-----
How to run (worker):
  celery -A app.celery_app:celery_app worker -l INFO

Purpose:
- Minimal "prove Celery works" task that writes to the tracking DB
  using your existing insert_app_backend_tracking().
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict

from app.celery_app import celery_app
from app.database import database, connect_db, disconnect_db
from app.database_queries.postgres_insert_queries import insert_app_backend_tracking
from app.shared_functions.helpers.helpers import scrub_secrets

logger = logging.getLogger("app.celery.tasks")


def _run_async(coro):
    """
    Celery tasks are sync functions; your DB helpers are async.
    This safely runs an async coroutine in a sync context.
    """
    try:
        return asyncio.run(coro)
    except RuntimeError:
        # fallback for rare cases where an event loop already exists
        loop = asyncio.get_event_loop()
        return loop.run_until_complete(coro)


@celery_app.task(name="tracking.test", bind=True)
def tracking_test(self, meta: Dict[str, Any]) -> Dict[str, Any]:
    """
    Writes a tracking event to Postgres so you can verify:
    FastAPI -> Redis broker -> Celery worker -> Postgres
    """
    async def _inner():
        await connect_db()
        try:
            info = scrub_secrets(meta)
            info["event"] = info.get("event") or "celery_tracking_test"

            db_log = await insert_app_backend_tracking(
                database=database,
                route=info.get("route") or "/celery/tracking_test",
                information=scrub_secrets(info),
            )

            if "error" in db_log:
                logger.error("tracking_test db insert failed task_id=%s err=%s", self.request.id, db_log["error"])
                return {"error": db_log["error"]}

            logger.info("tracking_test inserted task_id=%s", self.request.id)
            return {"detail": {"ok": True, "celery_task_id": self.request.id, "db_log": db_log}}
        finally:
            await disconnect_db()

    try:
        return _run_async(_inner())
    except Exception as e:
        logger.exception("tracking_test crashed task_id=%s", getattr(self.request, "id", None))
        return {"error": f"celery_task_failed: {e}"}
