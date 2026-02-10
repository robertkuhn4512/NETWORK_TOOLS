from __future__ import annotations

import os
import re
import uuid
from typing import Any, Dict, List, Optional, Sequence
from app.database import database

_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _uuid_or_none(val: Any) -> Optional[str]:
    if val in (None, ""):
        return None
    try:
        return str(uuid.UUID(str(val)))
    except Exception:
        return None

def _quote_ident(name: str) -> str:

    """
    Safely quote an SQL identifier (schema/table/column) that matches a conservative pattern.
    """

    if not name or not _IDENT_RE.match(name):
        raise ValueError(f"Unsafe SQL identifier: {name!r}")
    return f'"{name}"'

async def fetch_latest_device_backup_location_by_ipv4(
    *,
    ipv4_loopback: str,
) -> Dict[str, Any]:
    """
    Notes / How to run:
      - res = await fetch_latest_device_backup_location_by_ipv4(ipv4_loopback="10.0.0.101")
    """
    sql = """
    SELECT id, device_name, ipv4_loopback, ipv6_loopback, device_type, file_location, datetimestamp
    FROM public.device_backup_locations
    WHERE ipv4_loopback = :ipv4_loopback
    ORDER BY datetimestamp DESC NULLS LAST, id DESC
    LIMIT 1
    """
    try:
        row = await database.fetch_one(query=sql, values={"ipv4_loopback": ipv4_loopback})
        return {"ok": True, "row": (dict(row._mapping) if row else None)}
    except Exception as e:
        return {"error": "database_error", "detail": {"message": str(e), "ipv4_loopback": ipv4_loopback}}


async def fetch_latest_device_backup_locations_for_ipv4_list(
    *,
    ipv4_loopbacks: Sequence[str],
) -> Dict[str, Any]:
    """
    Notes / How to run:
      - res = await fetch_latest_device_backup_locations_for_ipv4_list(ipv4_loopbacks=["10.0.0.101", "10.0.0.102"])
      - Returns: {"ok": True, "by_ipv4": {"10.0.0.101": {...}, ...}}
    """
    if not ipv4_loopbacks:
        return {"ok": True, "by_ipv4": {}}

    # DISTINCT ON is perfect for "latest row per key"
    sql = """
    SELECT DISTINCT ON (ipv4_loopback)
      id, device_name, ipv4_loopback, ipv6_loopback, device_type, file_location, datetimestamp
    FROM public.device_backup_locations
    WHERE ipv4_loopback = ANY(:ips)
    ORDER BY ipv4_loopback, datetimestamp DESC NULLS LAST, id DESC
    """

    try:
        rows = await database.fetch_all(query=sql, values={"ips": list(ipv4_loopbacks)})
        by_ipv4: Dict[str, Dict[str, Any]] = {}
        for r in rows:
            d = dict(r._mapping)
            ip = d.get("ipv4_loopback")
            if ip:
                by_ipv4[ip] = d
        return {"ok": True, "by_ipv4": by_ipv4}
    except Exception as e:
        return {"error": "database_error", "detail": {"message": str(e), "count": len(ipv4_loopbacks)}}

async def select_unique_device_os_versions(
    *,
    schema: Optional[str] = None,
    table: str = "devices",
    normalize_os_lower: bool = True,
    strip_values: bool = True,
    include_nulls: bool = False,
) -> Dict[str, Any]:
    """
    Returns all unique (os, version) combinations from the devices table.

    Notes:
    - Uses the known column names: os + version (no auto-detection).
    - Quotes schema/table identifiers defensively.
    - Normalization (strip/lower) happens in Python; results are de-duped after normalization.
    """
    schema_name = schema or os.getenv("FASTAPI_DB_SCHEMA") or "public"

    result: Dict[str, Any] = {
        "source": "postgres_select_queries.select_unique_device_os_versions",
        "schema": schema_name,
        "table": table,
        "os_column": "os",
        "version_column": "version",
        "items": [],
        "count": 0,
    }

    try:
        qs = _quote_ident(schema_name)
        qt = _quote_ident(table)

        # Fixed columns per your schema
        q_os = _quote_ident("os")
        q_ver = _quote_ident("version")

        where = ""
        if not include_nulls:
            where = f"WHERE {q_os} IS NOT NULL AND {q_ver} IS NOT NULL"

        distinct_sql = f"""
            SELECT DISTINCT
                {q_os} AS os,
                {q_ver} AS version
            FROM {qs}.{qt}
            {where}
            ORDER BY 1, 2
        """

        rows = await database.fetch_all(distinct_sql)

        items: List[Dict[str, Any]] = []
        seen: set[Tuple[Any, Any]] = set()

        for r in rows:
            os_val = r._mapping["os"]
            ver_val = r._mapping["version"]

            # If include_nulls=True, allow None payloads; otherwise query already filtered them out.
            if os_val is None or ver_val is None:
                if include_nulls:
                    key = (os_val, ver_val)
                    if key not in seen:
                        seen.add(key)
                        items.append({"os": os_val, "version": ver_val})
                continue

            os_s = str(os_val)
            ver_s = str(ver_val)

            if strip_values:
                os_s = os_s.strip()
                ver_s = ver_s.strip()

            if normalize_os_lower:
                os_s = os_s.lower()

            key = (os_s, ver_s)
            if key in seen:
                continue
            seen.add(key)

            items.append({"os": os_s, "version": ver_s})

        result["items"] = items
        result["count"] = len(items)
        return result

    except ValueError as e:
        # Identifier validation failure
        return {
            "error": "unsafe_sql_identifier",
            "detail": {"message": str(e), "schema": schema_name, "table": table},
        }
    except Exception as e:
        return {
            "error": "database_error",
            "detail": {"message": str(e), "schema": schema_name, "table": table},
        }

async def select_jobs_tracking_information(*, database, job_id: str) -> Dict[str, Any]:
    jid = _uuid_or_none(job_id)
    if not jid:
        return {"error": "invalid_job_id"}

    sql = """
        SELECT *
        FROM public.jobs_tracking_information
        WHERE job_id = :job_id::uuid
        LIMIT 1
    """
    row = await database.fetch_one(query=sql, values={"job_id": jid})
    if not row:
        return {"detail": {"found": False, "job_id": jid}}
    return {"detail": {"found": True, "job": dict(row._mapping)}}

async def select_app_tracking_celery(*, database, job_id: str) -> Dict[str, Any]:
    jid = _uuid_or_none(job_id)
    if not jid:
        return {"error": "invalid_job_id"}

    sql = """
        SELECT *
        FROM public.app_tracking_celery
        WHERE job_id = :job_id::uuid
        LIMIT 1
    """
    row = await database.fetch_one(query=sql, values={"job_id": jid})
    if not row:
        return {"detail": {"found": False, "job_id": jid}}
    return {"detail": {"found": True, "job": dict(row._mapping)}}

async def fetch_device_listing(
    *,
    database,
    device_name: str | None = None,
    ipv4_loopback: str | None = None,
    backup_limit: int | None = 25,
) -> Dict[str, Any]:
    """
    Notes / How to run:
      - res = await fetch_device_listing(
            database=database,
            device_name="test_lab_device",
            ipv4_loopback="10.0.0.1",
            backup_limit=10,
        )

    Behavior:
      - If BOTH device_name + ipv4_loopback are provided:
          * device lookup is strict AND (must match the same row)
      - If only one is provided:
          * device lookup is by that key (protected against multiple matches)
      - Backup rows are returned for the resolved device key(s) (prefers keys from the found device row).

    """
    dn = (device_name or "").strip()
    ip = (ipv4_loopback or "").strip()

    if not dn and not ip:
        return {
            "error": "missing_device_key",
            "detail": {"message": "device_name or ipv4_loopback is required"},
        }

    try:
        limit = int(backup_limit if backup_limit is not None else 25)
    except Exception:
        return {
            "error": "invalid_backup_limit",
            "detail": {"message": "backup_limit must be an integer", "backup_limit": backup_limit},
        }

    if limit < 0:
        limit = 0

    # -------------------------
    # 1) Fetch the device row
    # -------------------------
    device_row = None
    try:
        if dn and ip:
            # strict match when both provided
            device_sql = """
                SELECT *
                FROM public.devices
                WHERE device_name = :device_name
                  AND ipv4_loopback = :ipv4_loopback
                LIMIT 1
            """
            device_row = await database.fetch_one(
                query=device_sql,
                values={"device_name": dn, "ipv4_loopback": ip},
            )
        else:
            # single-key lookup, still protected against ambiguity
            device_sql = """
                SELECT *
                FROM public.devices
                WHERE (:device_name <> '' AND device_name = :device_name)
                   OR (:ipv4_loopback <> '' AND ipv4_loopback = :ipv4_loopback)
                ORDER BY id ASC
                LIMIT 2
            """
            rows = await database.fetch_all(
                query=device_sql,
                values={"device_name": dn, "ipv4_loopback": ip},
            )
            if rows and len(rows) > 1:
                m0 = dict(rows[0]._mapping)
                m1 = dict(rows[1]._mapping)
                return {
                    "error": "devices_conflict_multiple_matches",
                    "detail": {
                        "message": "Multiple device rows matched this key; refusing to choose arbitrarily.",
                        "matches": [
                            {
                                "id": m0.get("id"),
                                "device_name": m0.get("device_name"),
                                "ipv4_loopback": m0.get("ipv4_loopback"),
                            },
                            {
                                "id": m1.get("id"),
                                "device_name": m1.get("device_name"),
                                "ipv4_loopback": m1.get("ipv4_loopback"),
                            },
                        ],
                    },
                }
            device_row = rows[0] if rows else None

    except Exception as e:
        return {"error": "database_error", "detail": {"message": str(e), "stage": "select_device"}}

    device = dict(device_row._mapping) if device_row else None

    # Prefer the keys from the found device row for the backup lookup
    dn_key = (device.get("device_name") if device else None) or dn
    ip_key = (device.get("ipv4_loopback") if device else None) or ip

    # -------------------------
    # 2) Fetch backup locations
    # -------------------------
    backups: list[dict] = []
    try:
        if limit > 0 and (dn_key or ip_key):
            if dn_key and ip_key:
                backup_sql = """
                    SELECT *
                    FROM public.device_backup_locations
                    WHERE device_name = :device_name
                      AND ipv4_loopback = :ipv4_loopback
                    ORDER BY datetimestamp DESC NULLS LAST, id DESC
                    LIMIT :limit
                """
                rows = await database.fetch_all(
                    query=backup_sql,
                    values={"device_name": dn_key, "ipv4_loopback": ip_key, "limit": limit},
                )
            elif ip_key:
                backup_sql = """
                    SELECT *
                    FROM public.device_backup_locations
                    WHERE ipv4_loopback = :ipv4_loopback
                    ORDER BY datetimestamp DESC NULLS LAST, id DESC
                    LIMIT :limit
                """
                rows = await database.fetch_all(
                    query=backup_sql,
                    values={"ipv4_loopback": ip_key, "limit": limit},
                )
            else:
                backup_sql = """
                    SELECT *
                    FROM public.device_backup_locations
                    WHERE device_name = :device_name
                    ORDER BY datetimestamp DESC NULLS LAST, id DESC
                    LIMIT :limit
                """
                rows = await database.fetch_all(
                    query=backup_sql,
                    values={"device_name": dn_key, "limit": limit},
                )

            backups = [dict(r._mapping) for r in (rows or [])]

    except Exception as e:
        return {"error": "database_error", "detail": {"message": str(e), "stage": "select_backups"}}

    return {
        "ok": True,
        "input": {"device_name": dn or None, "ipv4_loopback": ip or None, "backup_limit": limit},
        "device_found": bool(device),
        "device": device,
        "backup_limit": limit,
        "backup_count": len(backups),
        "backup_locations": backups,
    }


async def select_latest_device_backup_location_for_ipv4(
    *,
    ipv4_loopback: str,
) -> Dict[str, Any]:
    """
    Returns the newest row for ipv4_loopback by datetimestamp DESC.
    """
    try:
        ip = (ipv4_loopback or "").strip()
        if not ip:
            return {"detail": {"error": "invalid_input", "message": "ipv4_loopback is required"}}

        sql = """
            SELECT
                id,
                device_name,
                ipv4_loopback,
                ipv6_loopback,
                device_type,
                file_location,
                datetimestamp
            FROM public.device_backup_locations
            WHERE ipv4_loopback = :ipv4_loopback
            ORDER BY datetimestamp DESC NULLS LAST
            LIMIT 1
        """

        row = await database.fetch_one(query=sql, values={"ipv4_loopback": ip})

        if not row:
            return {"detail": {"found": False, "row": None}}

        return {"detail": {"found": True, "row": dict(row._mapping)}}

    except Exception as e:
        return {"detail": {"error": "database_error", "message": str(e)}}

async def select_device_backup_locations_for_ipv4(
    *,
    ipv4_loopback: str,
    direction: str = "desc",
    limit: int = 1,
) -> Dict[str, Any]:
    """
    Returns rows ordered by datetimestamp asc|desc.
    """
    try:
        ip = (ipv4_loopback or "").strip()
        if not ip:
            return {"detail": {"error": "invalid_input", "message": "ipv4_loopback is required"}}

        dir_norm = (direction or "").strip().lower()
        if dir_norm not in ("asc", "desc"):
            return {"detail": {"error": "invalid_input", "message": "direction must be 'asc' or 'desc'"}}

        lim = int(limit or 1)
        if lim < 1:
            lim = 1

        order = "ASC" if dir_norm == "asc" else "DESC"

        sql = f"""
            SELECT
                id,
                device_name,
                ipv4_loopback,
                ipv6_loopback,
                device_type,
                file_location,
                datetimestamp
            FROM public.device_backup_locations
            WHERE ipv4_loopback = :ipv4_loopback
            ORDER BY datetimestamp {order} NULLS LAST
            LIMIT :limit
        """

        rows = await database.fetch_all(query=sql, values={"ipv4_loopback": ip, "limit": lim})
        return {"detail": {"rows": [dict(r._mapping) for r in rows]}}

    except Exception as e:
        return {"detail": {"error": "database_error", "message": str(e)}}