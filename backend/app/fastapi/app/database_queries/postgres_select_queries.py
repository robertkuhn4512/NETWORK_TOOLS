from __future__ import annotations

import os
import re
import uuid
from typing import Any, Dict, List, Optional, Sequence, Tuple
from app.database import database

_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# Datatable Related Helpers
def _dt_int(val: Any, default: int) -> int:
    try:
        return int(val)
    except Exception:
        return default


def _dt_str(val: Any, default: str = "") -> str:
    try:
        s = str(val)
    except Exception:
        return default
    return s

def _dt_dir(val: Any, default: str = "desc") -> str:
    d = _dt_str(val, default).strip().lower()
    return d if d in ("asc", "desc") else default

# END Datatable Related Helpers

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


async def _datatable_select_all(
    *,
    schema: str,
    table: str,
    dt: Dict[str, Any],
    allowed_columns: List[str],
    searchable_columns: List[str],
    default_order: Tuple[str, str] = ("id", "desc"),
    max_length: int = 500,
) -> Dict[str, Any]:
    """
    Notes / How to run:
      - dt is the DataTables request object (what DataTables sends to your server).
      - Example:
            res = await _datatable_select_all(
                database=database,
                schema="public",
                table="devices",
                dt={"draw": 1, "start": 0, "length": 25, "search": {"value": "router"}},
                allowed_columns=[...],
                searchable_columns=[...],
            )
    """
    try:
        qs = _quote_ident(schema)
        qt = _quote_ident(table)

        # ---- paging ----
        draw = _dt_int(dt.get("draw"), 0)
        start = max(_dt_int(dt.get("start"), 0), 0)
        length = _dt_int(dt.get("length"), 25)
        if length < 0:
            length = max_length
        length = min(max(length, 0), max_length)

        # ---- ordering (DataTables order[0].column -> columns[idx].data/name) ----
        order_col, order_dir = default_order
        try:
            order = dt.get("order") or []
            cols = dt.get("columns") or []
            if isinstance(order, list) and order and isinstance(cols, list) and cols:
                o0 = order[0] if isinstance(order[0], dict) else {}
                idx = _dt_int(o0.get("column"), -1)
                req_dir = _dt_dir(o0.get("dir"), order_dir)

                if 0 <= idx < len(cols) and isinstance(cols[idx], dict):
                    cobj = cols[idx]
                    cname = cobj.get("data") or cobj.get("name")
                    if isinstance(cname, str) and cname in allowed_columns:
                        order_col = cname
                order_dir = req_dir
        except Exception:
            # fall back to default order
            pass

        if order_col not in allowed_columns:
            order_col = default_order[0]
        order_dir = _dt_dir(order_dir, default_order[1])

        q_order_col = _quote_ident(order_col)
        order_sql = f"{q_order_col} {'ASC' if order_dir == 'asc' else 'DESC'} NULLS LAST"

        # ---- filtering (global search + per-column search[value]) ----
        where_parts: List[str] = []
        values: Dict[str, Any] = {}

        global_search = ""
        try:
            search_obj = dt.get("search") or {}
            if isinstance(search_obj, dict):
                global_search = _dt_str(search_obj.get("value"), "").strip()
        except Exception:
            global_search = ""

        if global_search:
            values["global_search"] = f"%{global_search}%"
            ors = []
            for c in searchable_columns:
                if c not in allowed_columns:
                    continue
                qc = _quote_ident(c)
                ors.append(f"CAST({qc} AS text) ILIKE :global_search")
            if ors:
                where_parts.append("(" + " OR ".join(ors) + ")")

        # per-column search
        cols = dt.get("columns") or []
        if isinstance(cols, list) and cols:
            for i, cobj in enumerate(cols):
                if not isinstance(cobj, dict):
                    continue
                cname = cobj.get("data") or cobj.get("name")
                if not isinstance(cname, str) or cname not in allowed_columns:
                    continue
                s = cobj.get("search") or {}
                sval = ""
                if isinstance(s, dict):
                    sval = _dt_str(s.get("value"), "").strip()
                if not sval:
                    continue

                key = f"col_search_{i}"
                values[key] = f"%{sval}%"
                where_parts.append(f"CAST({_quote_ident(cname)} AS text) ILIKE :{key}")

        where_sql = ("WHERE " + " AND ".join(where_parts)) if where_parts else ""

        # ---- counts ----
        total_sql = f"SELECT COUNT(*) AS n FROM {qs}.{qt}"
        filtered_sql = f"SELECT COUNT(*) AS n FROM {qs}.{qt} {where_sql}"

        total_row = await database.fetch_one(query=total_sql)
        total_n = int((total_row._mapping["n"] if total_row else 0))

        filtered_row = await database.fetch_one(query=filtered_sql, values=values)
        filtered_n = int((filtered_row._mapping["n"] if filtered_row else 0))

        # ---- page data ----
        data_sql = f"""
            SELECT *
            FROM {qs}.{qt}
            {where_sql}
            ORDER BY {order_sql}
            LIMIT :limit OFFSET :offset
        """
        values_page = dict(values)
        values_page["limit"] = length
        values_page["offset"] = start

        rows = await database.fetch_all(query=data_sql, values=values_page)
        data = [dict(r._mapping) for r in (rows or [])]

        return {
            "ok": True,
            "draw": draw,
            "recordsTotal": total_n,
            "recordsFiltered": filtered_n,
            "data": data,
            "meta": {
                "schema": schema,
                "table": table,
                "start": start,
                "length": length,
                "order": {"column": order_col, "dir": order_dir},
                "global_search": global_search or None,
            },
        }

    except ValueError as e:
        # identifier validation failure via _quote_ident
        return {"error": f"unsafe_sql_identifier: {e}", "detail": {"schema": schema, "table": table}}
    except Exception as e:
        return {"error": f"database_error: {e}", "detail": {"schema": schema, "table": table}}


# -----------------------------
# Table-specific wrappers
# -----------------------------

async def fetch_devices_datatable(*, database, dt: Dict[str, Any]) -> Dict[str, Any]:
    """
    Notes / How to run:
      - res = await fetch_devices_datatable(database=database, dt=dt_payload)
    """
    cols = [
        "id",
        "device_name",
        "hub_id",
        "site_abbreviation",
        "os",
        "version",
        "chassis_model",
        "ipv4_loopback",
        "ipv6_loopback",
        "device_type",
        "information",
        "information_detail",
        "datetimestamp",
    ]
    # searchable can be the same list; trim later if performance dictates
    return await _datatable_select_all(
        schema="public",
        table="devices",
        dt=dt,
        allowed_columns=cols,
        searchable_columns=cols,
        default_order=("datetimestamp", "desc"),
        max_length=500,
    )


async def fetch_device_backup_locations_datatable(*, database, dt: Dict[str, Any]) -> Dict[str, Any]:
    """
    Notes / How to run:
      - res = await fetch_device_backup_locations_datatable(database=database, dt=dt_payload)
    """
    cols = [
        "id",
        "device_name",
        "ipv4_loopback",
        "ipv6_loopback",
        "device_type",
        "file_location",
        "datetimestamp",
    ]
    return await _datatable_select_all(
        database=database,
        schema="public",
        table="device_backup_locations",
        dt=dt,
        allowed_columns=cols,
        searchable_columns=cols,
        default_order=("datetimestamp", "desc"),
        max_length=500,
    )


async def fetch_reporting_cisco_api_cve_software_datatable(*, database, dt: Dict[str, Any]) -> Dict[str, Any]:
    """
    Notes / How to run:
      - res = await fetch_reporting_cisco_api_cve_software_datatable(database=database, dt=dt_payload)
    """
    cols = [
        "id",
        "os_name",
        "version",
        "information",
        "datetimestamp",
    ]
    return await _datatable_select_all(
        database=database,
        schema="public",
        table="reporting_cisco_api_cve_software",
        dt=dt,
        allowed_columns=cols,
        searchable_columns=cols,
        default_order=("datetimestamp", "desc"),
        max_length=500,
    )


async def fetch_reporting_cisco_api_eox_datatable(*, dt: Dict[str, Any]) -> Dict[str, Any]:
    """
    Notes / How to run:
      - res = await fetch_reporting_cisco_api_eox_datatable(database=database, dt=dt_payload)
    """
    cols = [
        "id",
        "product_id",
        "datetimestamp",
        "created_at",
        "updated_at",
        "product_id_description",
        "product_bulletin_number",
        "product_bulletin_url",
        "eox_external_announcement_date",
        "end_of_sale_date",
        "end_of_sw_maintenance_releases",
        "end_of_security_vul_support_date",
        "end_of_routine_failure_analysis_date",
        "end_of_service_contract_renewal",
        "end_of_svc_attach_date",
        "last_date_of_support",
        "updated_timestamp",
        "request_page_index",
        "request_product_query",
        "record_hash",
        "information",
    ]
    return await _datatable_select_all(
        schema="public",
        table="reporting_cisco_api_eox",
        dt=dt,
        allowed_columns=cols,
        searchable_columns=cols,
        default_order=("datetimestamp", "desc"),
        max_length=500,
    )
