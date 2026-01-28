"""
Notes:
- How to run:
  - Call from any endpoint:
      from app.database_queries.postgres_insert_queries import insert_app_backend_tracking
      await insert_app_backend_tracking(database=database, route="/path", information={"k":"v"})

  - Save a configuration backup location:
      from app.database_queries.postgres_insert_queries import insert_device_backup_location
      await insert_device_backup_location(database=database, device_name="sw1", ipv4_loopback="10.0.0.1", device_type="cisco_xe", file_location="/backups/.../sw1.enc")

  - Upsert devices with archive-on-change:
      from app.database_queries.postgres_insert_queries import upsert_device_with_archive
      await upsert_device_with_archive(database=database, device_name="sw1", ipv4_loopback="10.0.0.1", device_type="cisco_xe", information={"serial":"ABC"})

  - Requires the shared async `database` connector (databases.Database) to be connected.
Purpose:
- Insert helpers for Postgres (network_tools DB).
"""

from __future__ import annotations

import logging
import json
from typing import Any

from app.shared_functions.helpers.helpers_generic import pretty_json_any

logger = logging.getLogger("app.db.insert_queries")

def _jsonb_dump(value: Any) -> Optional[str]:
    """
    Prepare a value for jsonb insertion.

    - dict/list -> JSON string
    - str -> if valid JSON, normalize; else store as JSON string (so it's still valid jsonb)
    - None -> None
    """
    if value is None:
        return None

    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, default=str)

    if isinstance(value, str):
        s = value.strip()
        if not s:
            # store as empty JSON string
            return json.dumps("", ensure_ascii=False)
        try:
            parsed = json.loads(s)
            return json.dumps(parsed, ensure_ascii=False, default=str)
        except Exception:
            # JSONB can store a JSON string value
            return json.dumps(value, ensure_ascii=False)

    # fallback: serialize to JSON
    return json.dumps(value, ensure_ascii=False, default=str)

def _row_to_dict(row: Any) -> Dict[str, Any]:
    """Convert a databases/asyncpg row to a plain dict safely."""
    if row is None:
        return {}
    mapping = getattr(row, "_mapping", None)
    if mapping is not None:
        return dict(mapping)
    try:
        return dict(row)
    except Exception:
        return {"_row": repr(row)}

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

async def insert_device_backup_location(
    *,
    database,
    device_name: Optional[str] = None,
    ipv4_loopback: Optional[str] = None,
    ipv6_loopback: Optional[str] = None,
    device_type: Optional[str] = None,
    file_location: str,
) -> dict:
    """
    Insert a new row into device_backup_locations.
    This function never overwrites existing rows; it always appends.

    Returns:
      {"detail": {"ok": True, "id": <int|None>}} on success
      {"error": "<message>"} on failure
    """
    sql = """
    INSERT INTO device_backup_locations (
        device_name,
        ipv4_loopback,
        ipv6_loopback,
        device_type,
        file_location,
        datetimestamp
    )
    VALUES (
        :device_name,
        :ipv4_loopback,
        :ipv6_loopback,
        :device_type,
        :file_location,
        NOW()
    )
    RETURNING id
    """

    params = {
        "device_name": device_name,
        "ipv4_loopback": ipv4_loopback,
        "ipv6_loopback": ipv6_loopback,
        "device_type": device_type,
        "file_location": file_location,
    }

    try:
        row = await database.fetch_one(sql, params)
        new_id = None if row is None else row[0]
        return {"detail": {"ok": True, "id": new_id}}
    except Exception as e:
        logger.exception("insert_device_backup_location failed device=%r ipv4=%r", device_name, ipv4_loopback)
        return {"error": f"insert_device_backup_location failed: {e}"}


async def upsert_device_with_archive(
    *,
    database,
    device_name: str,
    ipv4_loopback: str,
    device_type: str,
    hub_id: Optional[str] = None,
    site_abbreviation: Optional[str] = None,
    os_name: Optional[str] = None,
    version: Optional[str] = None,
    chassis_model: Optional[str] = None,
    ipv6_loopback: Optional[str] = None,
    information: Any = None,
    information_detail: Any = None,
) -> dict:
    """
    Insert or update a row in `devices` using the rule:
      - match existing by ipv4_loopback OR device_name
      - if no match exists:
          - insert a new row into `devices`
      - if a match exists:
          - update `devices` with the new values when anything changes
          - ONLY copy the *previous* row into `devices_archive` when:
              - ipv4_loopback changes OR device_name changes
            (i.e., key/identity changed; snapshot the prior identity)

    IMPORTANT:
      - Requires `devices.information` and `devices.information_detail` to be jsonb.
      - Requires `devices_archive.information` and `devices_archive.information_detail` to be jsonb.

    Returns:
      {"detail": {"ok": True, "action": "inserted|updated|noop", "id": <int>, "archived_id": <int|None>, "archived": <bool>}}
      {"error": "<message>", ...}
    """

    device_name = (device_name or "").strip()
    ipv4_loopback = (ipv4_loopback or "").strip()
    device_type = (device_type or "").strip()

    if not device_name and not ipv4_loopback:
        return {"error": "device_key_missing", "detail": "device_name or ipv4_loopback is required"}

    if not device_type:
        return {"error": "device_type_missing", "detail": "device_type is required"}

    # Normalize JSONB inputs
    info_json = _jsonb_dump(information)
    info_detail_json = _jsonb_dump(information_detail)

    # Find existing by ipv4 OR name (protect against ambiguous matches)
    find_sql = """
    SELECT *
      FROM devices
     WHERE (:ipv4_loopback <> '' AND ipv4_loopback = :ipv4_loopback)
        OR (:device_name <> '' AND device_name = :device_name)
     ORDER BY id ASC
     LIMIT 2
    """

    try:
        rows = await database.fetch_all(find_sql, {"ipv4_loopback": ipv4_loopback, "device_name": device_name})
    except Exception as e:
        logger.exception("upsert_device_with_archive: lookup failed name=%r ipv4=%r", device_name, ipv4_loopback)
        return {"error": f"devices_lookup_failed: {e}"}

    if rows and len(rows) > 1:
        r0 = _row_to_dict(rows[0])
        r1 = _row_to_dict(rows[1])
        if r0.get("id") != r1.get("id"):
            return {
                "error": "devices_conflict_multiple_matches",
                "detail": "Both device_name and ipv4_loopback match different rows; refusing to overwrite.",
                "matches": [
                    {"id": r0.get("id"), "device_name": r0.get("device_name"), "ipv4_loopback": r0.get("ipv4_loopback")},
                    {"id": r1.get("id"), "device_name": r1.get("device_name"), "ipv4_loopback": r1.get("ipv4_loopback")},
                ],
            }

    existing = rows[0] if rows else None

    new_fields = {
        "device_name": device_name,
        "hub_id": hub_id,
        "site_abbreviation": site_abbreviation,
        "os": os_name,
        "version": version,
        "chassis_model": chassis_model,
        "ipv4_loopback": ipv4_loopback,
        "ipv6_loopback": ipv6_loopback,
        "device_type": device_type,
        "information": info_json,
        "information_detail": info_detail_json,
    }

    # INSERT path
    if existing is None:
        insert_sql = """
        INSERT INTO devices (
            device_name, 
            hub_id, 
            site_abbreviation, 
            os, 
            version, 
            chassis_model,
            ipv4_loopback, 
            ipv6_loopback, 
            device_type,
            information, 
            information_detail,
            datetimestamp
        )
        VALUES (
            :device_name, 
            :hub_id, 
            :site_abbreviation, 
            :os, 
            :version, 
            :chassis_model,
            :ipv4_loopback, 
            :ipv6_loopback, 
            :device_type,
            CAST(:information AS jsonb), 
            CAST(:information_detail AS jsonb),
            NOW()
        )
        RETURNING id
        """

        try:
            row = await database.fetch_one(insert_sql, new_fields)
            new_id = None if row is None else row[0]
            return {"detail": {"ok": True, "action": "inserted", "id": new_id, "archived_id": None, "archived": False}}
        except Exception as e:
            logger.exception("upsert_device_with_archive: insert failed name=%r ipv4_loopback=%r", device_name, ipv4_loopback)
            return {"error": f"devices_insert_failed: {e}"}

    # UPDATE path
    existing_d = _row_to_dict(existing)

    def _norm_scalar(v: Any) -> Any:
        if v is None:
            return None
        if isinstance(v, str):
            return v.strip()
        return v

    def _norm_json(v: Any) -> Any:
        if v is None:
            return None
        if isinstance(v, (dict, list)):
            return v
        if isinstance(v, str):
            s = v.strip()
            if not s:
                return ""
            try:
                return json.loads(s)
            except Exception:
                return s
        return v

    compare_fields = [
        "device_name", "hub_id", "site_abbreviation", "os", "version", "chassis_model",
        "ipv4_loopback", "ipv6_loopback", "device_type",
    ]

    changed = False
    diffs: Dict[str, Any] = {}

    for f in compare_fields:
        old = _norm_scalar(existing_d.get(f))
        new = _norm_scalar(new_fields.get(f))
        if old != new:
            changed = True
            diffs[f] = {"old": old, "new": new}

    old_info = _norm_json(existing_d.get("information"))
    new_info = _norm_json(information)
    if old_info != new_info:
        changed = True
        diffs["information"] = {"old": old_info, "new": new_info}

    old_detail = _norm_json(existing_d.get("information_detail"))
    new_detail = _norm_json(information_detail)
    if old_detail != new_detail:
        changed = True
        diffs["information_detail"] = {"old": old_detail, "new": new_detail}

    if not changed:
        return {"detail": {"ok": True, "action": "noop", "id": existing_d.get("id"), "archived_id": None, "archived": False}}

    # Only archive when identity changes (device_name or ipv4_loopback)
    old_name = _norm_scalar(existing_d.get("device_name"))
    old_ipv4 = _norm_scalar(existing_d.get("ipv4_loopback"))
    new_name = _norm_scalar(device_name)
    new_ipv4 = _norm_scalar(ipv4_loopback)

    identity_changed = (old_name != new_name) or (old_ipv4 != new_ipv4)

    archived_id: Optional[int] = None
    if identity_changed:
        archive_sql = """
        INSERT INTO devices_archive (
            device_name, hub_id, site_abbreviation, os, version, chassis_model,
            ipv4_loopback, ipv6_loopback, device_type,
            information, information_detail,
            datetimestamp
        )
        VALUES (
            :device_name, :hub_id, :site_abbreviation, :os, :version, :chassis_model,
            :ipv4_loopback, :ipv6_loopback, :device_type,
            CAST(:information AS jsonb), CAST(:information_detail AS jsonb),
            :datetimestamp
        )
        RETURNING id
        """

        archive_params = {
            "device_name": existing_d.get("device_name"),
            "hub_id": existing_d.get("hub_id"),
            "site_abbreviation": existing_d.get("site_abbreviation"),
            "os": existing_d.get("os"),
            "version": existing_d.get("version"),
            "chassis_model": existing_d.get("chassis_model"),
            "ipv4_loopback": existing_d.get("ipv4_loopback"),
            "ipv6_loopback": existing_d.get("ipv6_loopback"),
            "device_type": existing_d.get("device_type"),
            "information": _jsonb_dump(existing_d.get("information")),
            "information_detail": _jsonb_dump(existing_d.get("information_detail")),
            "datetimestamp": existing_d.get("datetimestamp"),
        }

        try:
            arch_row = await database.fetch_one(archive_sql, archive_params)
            archived_id = None if arch_row is None else arch_row[0]
        except Exception as e:
            logger.exception("upsert_device_with_archive: archive insert failed id=%r", existing_d.get("id"))
            return {"error": f"devices_archive_insert_failed: {e}", "diffs": diffs}

    update_sql = """
    UPDATE devices
       SET device_name = :device_name,
           hub_id = :hub_id,
           site_abbreviation = :site_abbreviation,
           os = :os,
           version = :version,
           chassis_model = :chassis_model,
           ipv4_loopback = :ipv4_loopback,
           ipv6_loopback = :ipv6_loopback,
           device_type = :device_type,
           information = CAST(:information AS jsonb),
           information_detail = CAST(:information_detail AS jsonb),
           datetimestamp = NOW()
     WHERE id = :id
     RETURNING id
    """

    update_params = dict(new_fields)
    update_params["id"] = existing_d.get("id")

    try:
        upd_row = await database.fetch_one(update_sql, update_params)
        upd_id = existing_d.get("id") if upd_row is None else upd_row[0]
        return {
            "detail": {
                "ok": True,
                "action": "updated",
                "id": upd_id,
                "archived_id": archived_id,
                "archived": bool(identity_changed),
                "identity_changed": bool(identity_changed),
                "diffs": diffs,
            }
        }
    except Exception as e:
        logger.exception("upsert_device_with_archive: update failed id=%r", existing_d.get("id"))
        return {"error": f"devices_update_failed: {e}", "archived_id": archived_id, "diffs": diffs}