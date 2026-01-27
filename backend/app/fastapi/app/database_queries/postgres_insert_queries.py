"""
Notes:
- How to run:
  - Call from any endpoint:
      from app.database_queries.postgres_insert_queries import insert_app_backend_tracking
      await insert_app_backend_tracking(database=database, route="/path", information={"k":"v"})
  - Requires the shared async `database` connector (databases.Database) to be connected.

Purpose:
- Insert helpers for Postgres (network_tools DB).
"""

from __future__ import annotations

import logging
from typing import Any

from app.shared_functions.helpers.helpers_generic import pretty_json_any

logger = logging.getLogger("app.db.insert_queries")


async def insert_app_backend_tracking(
    *,
    database,
    route: str | None,
    information: Any,
) -> dict:
    """
    Writes a row into app_backend_tracking.

    Returns:
      {"detail": {"ok": True, "id": <int|None>}} on success
      {"error": "<message>"} on failure
    """
    sql = """
    INSERT INTO app_backend_tracking (route, datetimestamp, information)
    VALUES (:route, NOW(), :information)
    RETURNING id
    """

    params = {
        "route": route,
        "information": pretty_json_any(information),
    }

    try:
        row = await database.fetch_one(sql, params)
        new_id = None if row is None else row[0]
        return {"detail": {"ok": True, "id": new_id}}
    except Exception as e:
        logger.exception("insert_app_backend_tracking failed route=%s", route)
        return {"error": f"insert_app_backend_tracking failed: {e}"}
