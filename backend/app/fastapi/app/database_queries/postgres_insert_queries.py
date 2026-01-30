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
from datetime import date

from app.shared_functions.helpers.helpers_generic import pretty_json_any

logger = logging.getLogger("app.db.insert_queries")

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

