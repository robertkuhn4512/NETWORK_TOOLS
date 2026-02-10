"""
Notes:
- How to run:
  - Call from any endpoint:
      from app.database_queries.postgres_insert_queries import insert_app_backend_tracking
      await insert_app_backend_tracking(database=database, route="/path", information={"k":"v"})

  - Save a configuration backup location:
      from app.database_queries.postgres_insert_queries import insert_device_backup_location
      await insert_device_backup_location(device_name="sw1", ipv4_loopback="10.0.0.1", device_type="cisco_xe", file_location="/backups/.../sw1.enc")

  - Upsert devices with archive-on-change:
      from app.database_queries.postgres_insert_queries import upsert_device_with_archive
      await upsert_device_with_archive(database=database, device_name="sw1", ipv4_loopback="10.0.0.1", device_type="cisco_xe", information={"serial":"ABC"})

  - Requires the shared async `database` connector (databases.Database) to be connected.
Purpose:
- Insert helpers for Postgres (network_tools DB).
"""

from __future__ import annotations
from datetime import datetime, timezone
import logging
import json
import uuid
from typing import Any, Dict, Optional, Sequence
from datetime import date
from app.database import database
from app.shared_functions.helpers.helpers_generic import pretty_json_any

logger = logging.getLogger("app.db.insert_queries")

def _json_dumps_safe(obj: Any) -> Optional[str]:
    if obj is None:
        return None
    try:
        return json.dumps(obj, default=str)
    except Exception:
        return json.dumps({"_repr": str(obj)}, default=str)


def _uuid_or_none(val: Any) -> Optional[str]:
    if val in (None, ""):
        return None
    try:
        return str(uuid.UUID(str(val)))
    except Exception:
        return None

def _normalize_app_tracking_status(status: Optional[str]) -> str:
    # app_tracking_celery has a CHECK constraint for allowed statuses
    if not status:
        return "QUEUED"
    s = str(status).strip().upper()
    mapping = {
        "PENDING": "QUEUED",
        "QUEUED": "QUEUED",
        "RECEIVED": "RECEIVED",
        "STARTED": "STARTED",
        "PROGRESS": "STARTED",
        "RETRY": "RETRY",
        "SUCCESS": "SUCCESS",
        "FAILURE": "FAILURE",
        "REVOKED": "REVOKED",
        "EXPIRED": "EXPIRED",
        "CANCELED": "CANCELED",
        "CANCELLED": "CANCELED",
    }
    return mapping.get(s, "QUEUED")


def _as_date(v) -> date | None:
    """
    Convert Cisco EOX date shapes to datetime.date.

    Accepts:
      - {"value": "YYYY-MM-DD", ...}
      - "YYYY-MM-DD"
      - datetime.date
      - None / "" -> None
    """
    if v is None:
        return None

    if isinstance(v, date):
        return v

    if isinstance(v, dict):
        return _as_date(v.get("value"))

    if isinstance(v, str):
        s = v.strip()
        if not s:
            return None
        try:
            return date.fromisoformat(s[:10])
        except Exception:
            return None

    return None

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
    device_name: Optional[str],
    ipv4_loopback: Optional[str],
    ipv6_loopback: Optional[str] | None = None,
    device_type: Optional[str] | None = None,
    file_location: str,
) -> Dict[str, Any]:
    """
    Notes / How to run:
      - await insert_device_backup_location(...)
      - Expects `public.device_backup_locations` to exist.
    """
    sql = """
    INSERT INTO public.device_backup_locations
      (
          device_name, 
          ipv4_loopback, 
          ipv6_loopback, 
          device_type, 
          file_location, 
          datetimestamp
      )
    VALUES
      (
          :device_name, 
          :ipv4_loopback, 
          :ipv6_loopback, 
          :device_type,
          :file_location,
          NOW()
      )
    RETURNING id, device_name, ipv4_loopback, ipv6_loopback, device_type, file_location, datetimestamp
    """

    values = {
        "device_name": device_name,
        "ipv4_loopback": ipv4_loopback,
        "ipv6_loopback": ipv6_loopback,
        "device_type": device_type,
        "file_location": file_location
    }

    try:
        row = await database.fetch_one(query=sql, values=values)
        if not row:
            return {"error": "insert_failed", "detail": {"message": "No row returned"}}
        return {"ok": True, "row": dict(row._mapping)}
    except Exception as e:
        return {"error": "database_error", "detail": {"message": str(e), "values": values}}


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

async def upsert_reporting_cisco_api_cve_software(
    *,
    database,
    os_name: str,
    version: str,
    information: dict,
) -> dict:
    sql = """
    INSERT INTO public.reporting_cisco_api_cve_software (os_name, version, information, datetimestamp)
    VALUES (:os_name, :version, CAST(:information AS jsonb), NOW())
    ON CONFLICT ON CONSTRAINT reporting_cisco_api_cve_software__os_version__uq DO UPDATE
      SET information   = EXCLUDED.information,
          datetimestamp = NOW()
    RETURNING id
    """
    try:
        params = {
            "os_name": os_name,
            "version": version,
            "information": _jsonb_dump(information) or "{}",
        }
        row = await database.fetch_one(sql, params)
        return {"ok": True, "id": int(row[0]) if row else None}
    except Exception as e:
        logger.exception("upsert_reporting_cisco_api_cve_software failed os_name=%r version=%r", os_name, version)
        return {"ok": False, "error": "db_upsert_failed", "detail": {"message": str(e)}}


async def upsert_reporting_cisco_api_cve_software_from_payload(
    *,
    database,
    payload: Dict[str, Any],
    default_os: str = "all",
    version_key: str = "advisoryId",
) -> Dict[str, Any]:
    """
    Takes the FastAPI payload from get_cisco_cve and inserts each advisory as one row.

    Keying:
      os      = advisory.get("osType") or default_os
      version = advisory.get(version_key) or advisory.get("cveId") or advisory.get("cve") or sha256(advisory)
    """
    try:
        resp = payload.get("cisco_response") or {}
        j = resp.get("json")

        if isinstance(j, dict) and isinstance(j.get("advisories"), list):
            items = j["advisories"]
        elif isinstance(j, list):
            items = j
        elif isinstance(j, dict):
            # fallback: treat as single item
            items = [j]
        else:
            return {"ok": False, "error": "no_json_to_insert", "detail": {"have_keys": sorted(list(resp.keys()))}}

        meta = {
            "route": payload.get("route"),
            "client": payload.get("client"),
            "vault_meta": payload.get("vault_meta"),
            "cisco_request": payload.get("cisco_request"),
            "cisco_response_meta": {"ok": resp.get("ok"), "status_code": resp.get("status_code")},
        }

        results: list[dict] = []
        import hashlib, json as _json

        for it in items:
            if not isinstance(it, dict):
                continue

            os_val = str(it.get("osType") or it.get("os_name") or it.get("os") or default_os).strip().lower() or default_os

            ver_val = str(
                it.get(version_key)
                or it.get("advisory_id")
                or it.get("advisoryId")
                or it.get("cveId")
                or it.get("cve")
                or it.get("id")
                or ""
            ).strip()

            if not ver_val:
                ver_val = hashlib.sha256(_json.dumps(it, sort_keys=True, default=str).encode("utf-8")).hexdigest()[:32]

            info = {"meta": meta, "entry": it}
            results.append(
                await upsert_reporting_cisco_api_cve_software(
                    database=database,
                    os_name=os_val,
                    version=ver_val,
                    information=info,
                )
            )

        ok_n = sum(1 for r in results if r.get("ok"))
        fail_n = len(results) - ok_n
        return {"ok": fail_n == 0, "rows_total": len(results), "rows_ok": ok_n, "rows_fail": fail_n, "results": results}

    except Exception as e:
        logger.exception("upsert_reporting_cisco_api_cve_software_from_payload failed")
        return {"ok": False, "error": "db_insert_failed", "detail": {"message": str(e)}}

async def upsert_reporting_cisco_api_eox(
    *,
    database,
    product_id: str,
    information: dict,
    product_id_description: str | None = None,
    product_bulletin_number: str | None = None,
    product_bulletin_url: str | None = None,
    eox_external_announcement_date: str | None = None,
    end_of_sale_date: str | None = None,
    end_of_sw_maintenance_releases: str | None = None,
    end_of_security_vul_support_date: str | None = None,
    end_of_routine_failure_analysis_date: str | None = None,
    end_of_service_contract_renewal: str | None = None,
    end_of_svc_attach_date: str | None = None,
    last_date_of_support: str | None = None,
    updated_timestamp: str | None = None,
    request_page_index: int | None = None,
    request_product_query: str | None = None,
    record_hash: str | None = None,
) -> dict:
    sql = """
    INSERT INTO public.reporting_cisco_api_eox (
        product_id,
        datetimestamp,
        created_at,
        product_id_description,
        product_bulletin_number,
        product_bulletin_url,
        eox_external_announcement_date,
        end_of_sale_date,
        end_of_sw_maintenance_releases,
        end_of_security_vul_support_date,
        end_of_routine_failure_analysis_date,
        end_of_service_contract_renewal,
        end_of_svc_attach_date,
        last_date_of_support,
        updated_timestamp,
        request_page_index,
        request_product_query,
        record_hash,
        information
    )
    VALUES (
        :product_id,
        NOW(),
        NOW(),
        :product_id_description,
        :product_bulletin_number,
        :product_bulletin_url,
        :eox_external_announcement_date,
        :end_of_sale_date,
        :end_of_sw_maintenance_releases,
        :end_of_security_vul_support_date,
        :end_of_routine_failure_analysis_date,
        :end_of_service_contract_renewal,
        :end_of_svc_attach_date,
        :last_date_of_support,
        :updated_timestamp,
        :request_page_index,
        :request_product_query,
        :record_hash,
        CAST(:information AS jsonb)
    )
    ON CONFLICT ON CONSTRAINT reporting_cisco_api_eox__product_id__uq DO UPDATE
      SET information = EXCLUDED.information,
          datetimestamp = NOW(),
          product_id_description = EXCLUDED.product_id_description,
          product_bulletin_number = EXCLUDED.product_bulletin_number,
          product_bulletin_url = EXCLUDED.product_bulletin_url,
          eox_external_announcement_date = EXCLUDED.eox_external_announcement_date,
          end_of_sale_date = EXCLUDED.end_of_sale_date,
          end_of_sw_maintenance_releases = EXCLUDED.end_of_sw_maintenance_releases,
          end_of_security_vul_support_date = EXCLUDED.end_of_security_vul_support_date,
          end_of_routine_failure_analysis_date = EXCLUDED.end_of_routine_failure_analysis_date,
          end_of_service_contract_renewal = EXCLUDED.end_of_service_contract_renewal,
          end_of_svc_attach_date = EXCLUDED.end_of_svc_attach_date,
          last_date_of_support = EXCLUDED.last_date_of_support,
          updated_timestamp = EXCLUDED.updated_timestamp,
          request_page_index = EXCLUDED.request_page_index,
          request_product_query = EXCLUDED.request_product_query,
          record_hash = EXCLUDED.record_hash
    RETURNING id
    """
    try:
        pid = (product_id or "").strip()
        if not pid:
            return {"ok": False, "error": "missing_product_id", "detail": {"message": "product_id is required"}}

        params = {
            "product_id": pid,
            "product_id_description": (product_id_description or None),
            "product_bulletin_number": (product_bulletin_number or None),
            "product_bulletin_url": (product_bulletin_url or None),

            "eox_external_announcement_date": _as_date(eox_external_announcement_date),
            "end_of_sale_date": _as_date(end_of_sale_date),
            "end_of_sw_maintenance_releases": _as_date(end_of_sw_maintenance_releases),
            "end_of_security_vul_support_date": _as_date(end_of_security_vul_support_date),
            "end_of_routine_failure_analysis_date": _as_date(end_of_routine_failure_analysis_date),
            "end_of_service_contract_renewal": _as_date(end_of_service_contract_renewal),
            "end_of_svc_attach_date": _as_date(end_of_svc_attach_date),
            "last_date_of_support": _as_date(last_date_of_support),
            "updated_timestamp": _as_date(updated_timestamp),

            "request_page_index": request_page_index,
            "request_product_query": (request_product_query or None),
            "record_hash": (record_hash or None),
            "information": _jsonb_dump(information) or "{}",
        }

        row = await database.fetch_one(sql, params)
        return {"ok": True, "id": int(row[0]) if row else None}
    except Exception as e:
        logger.exception("upsert_reporting_cisco_api_eox failed product_id=%r", product_id)
        return {"ok": False, "error": "db_upsert_failed", "detail": {"message": str(e)}}


def _eox_date_val(obj) -> str | None:
    """
    Cisco EOX date fields look like:
      {"value":"2009-04-25","dateFormat":"YYYY-MM-DD"}
    Return 'YYYY-MM-DD' or None.
    """
    try:
        if obj is None:
            return None
        if isinstance(obj, dict):
            v = obj.get("value")
        else:
            v = obj
        s = str(v or "").strip()
        if not s:
            return None
        # Basic ISO date sanity
        if len(s) >= 10:
            s10 = s[:10]
            # cheap validation; avoids throwing on junk
            import datetime as _dt
            _dt.date.fromisoformat(s10)
            return s10
        return None
    except Exception:
        return None


async def upsert_reporting_cisco_api_eox_from_payload(
    *,
    database,
    payload: dict,
) -> dict:
    """
    Takes the FastAPI payload from get_cisco_eox and inserts each EOXRecord entry as one row.

    Keying:
      product_id = record["EOLProductID"] (Cisco uses this field name in the response)
    """
    try:
        resp = payload.get("cisco_response") or {}
        j = resp.get("json")

        if not isinstance(j, dict):
            return {"ok": False, "error": "no_json_to_insert", "detail": {"message": "cisco_response.json is not an object"}}

        items = j.get("EOXRecord")
        if not isinstance(items, list):
            return {"ok": False, "error": "no_eoxrecord_list", "detail": {"have_keys": sorted(list(j.keys()))}}

        in_obj = payload.get("input") or {}
        page_index_raw = in_obj.get("page_index")
        req_pid = in_obj.get("product_id")

        page_index_int = None
        try:
            page_index_int = int(str(page_index_raw).strip())
        except Exception:
            page_index_int = None

        meta = {
            "route": payload.get("route"),
            "client": payload.get("client"),
            "vault_meta": payload.get("vault_meta"),
            "input": in_obj,
            "cisco_request": payload.get("cisco_request"),
            "cisco_response_meta": {"ok": resp.get("ok"), "status_code": resp.get("status_code")},
            "pagination": j.get("PaginationResponseRecord"),
        }

        results: list[dict] = []
        import hashlib, json as _json

        for it in items:
            if not isinstance(it, dict):
                continue

            pid = str(it.get("EOLProductID") or "").strip()
            if not pid:
                continue

            # full 64-char sha256 hex for change detection
            rh = hashlib.sha256(_json.dumps(it, sort_keys=True, default=str).encode("utf-8")).hexdigest()

            info = {"meta": meta, "entry": it}

            results.append(
                await upsert_reporting_cisco_api_eox(
                    database=database,
                    product_id=pid,
                    information=info,
                    product_id_description=(it.get("ProductIDDescription") or None),
                    product_bulletin_number=(it.get("ProductBulletinNumber") or None),
                    product_bulletin_url=(it.get("LinkToProductBulletinURL") or None),
                    eox_external_announcement_date=_eox_date_val(it.get("EOXExternalAnnouncementDate")),
                    end_of_sale_date=_eox_date_val(it.get("EndOfSaleDate")),
                    end_of_sw_maintenance_releases=_eox_date_val(it.get("EndOfSWMaintenanceReleases")),
                    end_of_security_vul_support_date=_eox_date_val(it.get("EndOfSecurityVulSupportDate")),
                    end_of_routine_failure_analysis_date=_eox_date_val(it.get("EndOfRoutineFailureAnalysisDate")),
                    end_of_service_contract_renewal=_eox_date_val(it.get("EndOfServiceContractRenewal")),
                    end_of_svc_attach_date=_eox_date_val(it.get("EndOfSvcAttachDate")),
                    last_date_of_support=_eox_date_val(it.get("LastDateOfSupport")),
                    updated_timestamp=_eox_date_val(it.get("UpdatedTimeStamp")),
                    request_page_index=page_index_int,
                    request_product_query=(str(req_pid).strip() if req_pid is not None else None),
                    record_hash=rh,
                )
            )

        ok_n = sum(1 for r in results if r.get("ok"))
        fail_n = len(results) - ok_n
        return {"ok": fail_n == 0, "rows_total": len(results), "rows_ok": ok_n, "rows_fail": fail_n, "results": results}

    except Exception as e:
        logger.exception("upsert_reporting_cisco_api_eox_from_payload failed")
        return {"ok": False, "error": "db_insert_failed", "detail": {"message": str(e)}}


async def upsert_app_tracking_celery_job(
    *,
    database,
    job_id: str,
    task_id: str | None = None,
    job_name: str | None = None,
    dedupe_key: str | None = None,
    status: str = "PENDING",
    route: str | None = None,
    request: dict | None = None
) -> dict:
    """
    Creates/updates a row in app_tracking_celery.

    Critical schema constraints (per your DB):
      - job_name   NOT NULL
      - dedupe_key NOT NULL

    Backward-compatible:
      - If callers don't supply job_name/dedupe_key, we fall back safely.
    """
    try:
        request = request or {}
        job_id_norm = (str(job_id).strip() if job_id is not None else "")
        if not job_id_norm:
            return {"error": "missing_required_fields: job_id"}

        task_id_norm = (str(task_id).strip() if task_id is not None else "") or job_id_norm
        status_norm = _normalize_app_tracking_status(status)

        # Must never be NULL in DB
        job_name_norm = (str(job_name).strip() if job_name is not None else "") or "unknown_job"
        dedupe_key_norm = (str(dedupe_key).strip() if dedupe_key is not None else "") or job_id_norm

        query = """
        INSERT INTO app_tracking_celery (
            job_id,
            task_id,
            job_name,
            dedupe_key,
            status,
            created_at,
            updated_at,
            completed_at,
            request
        )
        VALUES (
            CAST(:job_id AS UUID),
            :task_id,
            :job_name,
            :dedupe_key,
            :status,
            NOW(),
            NOW(),
            CASE
                WHEN :status IN ('SUCCESS','FAILURE','REVOKED','CANCELED','EXPIRED') THEN NOW()
                ELSE NULL
            END,
            CAST(:request AS jsonb)
        )
        ON CONFLICT (job_id) DO UPDATE SET
            task_id    = EXCLUDED.task_id,
            status     = EXCLUDED.status,
            updated_at = NOW(),
            job_name   = COALESCE(app_tracking_celery.job_name, EXCLUDED.job_name),
            dedupe_key = COALESCE(app_tracking_celery.dedupe_key, EXCLUDED.dedupe_key),
            completed_at = COALESCE(
                app_tracking_celery.completed_at,
                CASE
                    WHEN EXCLUDED.status IN ('SUCCESS','FAILURE','REVOKED','CANCELED','EXPIRED') THEN NOW()
                    ELSE NULL
                END
            ),
            request = EXCLUDED.request
        ;
        """

        await database.execute(
            query=query,
            values={
                "job_id": job_id_norm,
                "task_id": task_id_norm,
                "job_name": job_name_norm,
                "dedupe_key": dedupe_key_norm,
                "status": status_norm,
                "request": _json_dumps_safe(request)
            },
        )

        return {
            "detail": {
                "ok": True,
                "job_id": job_id_norm,
                "task_id": task_id_norm,
                "job_name": job_name_norm,
                "dedupe_key": dedupe_key_norm,
                "status": status_norm,
                "request": _json_dumps_safe(request)
            }
        }

    except Exception as e:
        # Never let logging errors mask the real DB exception
        try:
            await insert_app_backend_tracking(
                database=database,
                route=(route or "internal/upsert_app_tracking_celery_job"),
                information={
                    "event": "app_tracking_celery_upsert_failed",
                    "job_id": str(job_id),
                    "task_id": str(task_id or ""),
                    "job_name": str(job_name or ""),
                    "dedupe_key": str(dedupe_key or ""),
                    "status": str(status),
                    "exception": str(e),
                    "request": _json_dumps_safe(request)
                },
            )
        except Exception:
            pass

        return {"error": "database_error", "detail": {"message": str(e), "job_id": str(job_id)}}


async def upsert_jobs_tracking_information(
    *,
    database,
    job_id: str,
    job_type: str,
    status: str = "PENDING",
    celery_task_id: Optional[str] = None,
    requested_by: Optional[str] = None,
    route: Optional[str] = None,
    redacted: bool = False,
    progress_current: Optional[int] = None,
    progress_total: Optional[int] = None,
    progress_message: Optional[str] = None,
    # schema uses column name `input`
    input_payload: Optional[Any] = None,  # legacy kwarg
    input: Optional[Any] = None,          # alias
    result: Optional[Any] = None,
    error_type: Optional[str] = None,
    error_message: Optional[str] = None,
    tb: Optional[str] = None,
    traceback: Optional[str] = None,
    started_at: Optional[datetime] = None,
    completed_at: Optional[datetime] = None,
    ended_at: Optional[datetime] = None,   # ✅ legacy alias (was referenced but missing)
    duration_ms: Optional[int] = None,
    # legacy aliases used elsewhere
    progress: Optional[int] = None,
    details: Optional[Dict[str, Any]] = None,
    meta: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Notes / How to run:
      - Writes to public.jobs_tracking_information (schema-aligned).
      - Accepts legacy kwargs: input_payload, ended_at, progress/details/meta.
    """
    try:
        jid = _uuid_or_none(job_id)
        if not jid:
            return {"error": "invalid_job_id"}

        if not job_type or not str(job_type).strip():
            return {"error": "missing_required_fields: job_type"}

        # legacy mapping: progress (0-100) => progress_current/total if not provided
        if progress_current is None and progress is not None:
            progress_current = int(progress)
            if progress_total is None:
                progress_total = 100

        effective_input = input if input is not None else input_payload
        if effective_input is None and meta is not None:
            effective_input = meta

        # normalize / shape result payload
        result_obj: Dict[str, Any] = {}
        if details is not None:
            result_obj["details"] = details

        if isinstance(result, dict):
            # merge `details` into provided result dict if both exist
            if result_obj:
                for k, v in result_obj.items():
                    result.setdefault(k, v)
            result_obj = result
        elif result is not None:
            result_obj["result"] = result

        now_utc = datetime.now(timezone.utc)
        status_norm = str(status).strip().upper() if status else "PENDING"

        started_eff = started_at
        if started_eff is None and status_norm in ("STARTED", "PROGRESS", "SUCCESS", "FAILURE"):
            started_eff = now_utc

        completed_eff = completed_at or ended_at  # ✅ no NameError anymore
        if completed_eff is None and status_norm in ("SUCCESS", "FAILURE"):
            completed_eff = now_utc

        query = """
        INSERT INTO public.jobs_tracking_information (
            job_id,
            job_type,
            status,
            celery_task_id,
            requested_by,
            route,
            redacted,
            progress_current,
            progress_total,
            progress_message,
            input,
            result,
            error_type,
            error_message,
            traceback,
            started_at,
            completed_at,
            duration_ms,
            updated_at
        ) VALUES (
            CAST(:job_id AS uuid),
            :job_type,
            :status,
            :celery_task_id,
            :requested_by,
            :route,
            :redacted,
            :progress_current,
            :progress_total,
            :progress_message,
            CAST(:input AS jsonb),
            CAST(:result AS jsonb),
            :error_type,
            :error_message,
            :traceback,
            :started_at,
            :completed_at,
            :duration_ms,
            NOW()
        )
        ON CONFLICT (job_id) DO UPDATE SET
            job_type = EXCLUDED.job_type,
            status = EXCLUDED.status,
            celery_task_id = COALESCE(EXCLUDED.celery_task_id, public.jobs_tracking_information.celery_task_id),
            requested_by = COALESCE(EXCLUDED.requested_by, public.jobs_tracking_information.requested_by),
            route = COALESCE(EXCLUDED.route, public.jobs_tracking_information.route),
            redacted = COALESCE(EXCLUDED.redacted, public.jobs_tracking_information.redacted),
            progress_current = COALESCE(EXCLUDED.progress_current, public.jobs_tracking_information.progress_current),
            progress_total = COALESCE(EXCLUDED.progress_total, public.jobs_tracking_information.progress_total),
            progress_message = COALESCE(EXCLUDED.progress_message, public.jobs_tracking_information.progress_message),
            input = COALESCE(public.jobs_tracking_information.input, EXCLUDED.input),
            result = COALESCE(public.jobs_tracking_information.result, '{}'::jsonb) || COALESCE(EXCLUDED.result, '{}'::jsonb),
            error_type = COALESCE(EXCLUDED.error_type, public.jobs_tracking_information.error_type),
            error_message = COALESCE(EXCLUDED.error_message, public.jobs_tracking_information.error_message),
            traceback = COALESCE(EXCLUDED.traceback, public.jobs_tracking_information.traceback),
            started_at = COALESCE(public.jobs_tracking_information.started_at, EXCLUDED.started_at),
            completed_at = COALESCE(public.jobs_tracking_information.completed_at, EXCLUDED.completed_at),
            duration_ms = COALESCE(EXCLUDED.duration_ms, public.jobs_tracking_information.duration_ms),
            updated_at = NOW()
        ;
        """

        values = {
            "job_id": jid,
            "job_type": str(job_type).strip(),
            "status": status_norm,
            "celery_task_id": str(celery_task_id) if celery_task_id not in (None, "") else None,
            "requested_by": requested_by,
            "route": route,
            "redacted": bool(redacted),
            "progress_current": int(progress_current) if progress_current not in (None, "") else None,
            "progress_total": int(progress_total) if progress_total not in (None, "") else None,
            "progress_message": progress_message,
            "input": _json_dumps_safe(effective_input),
            "result": _json_dumps_safe(result_obj) if result_obj else None,
            "error_type": error_type,
            "error_message": error_message,
            "traceback": traceback or tb,
            "started_at": started_eff,
            "completed_at": completed_eff,
            "duration_ms": int(duration_ms) if duration_ms not in (None, "") else None,
        }

        await database.execute(query=query, values=values)
        return {"detail": {"ok": True, "job_id": jid}}

    except Exception as e:
        return {"error": "database_error", "detail": {"message": str(e), "job_id": job_id}}

