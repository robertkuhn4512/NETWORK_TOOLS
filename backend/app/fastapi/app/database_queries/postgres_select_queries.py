from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional

from app.database import database

_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
def _quote_ident(name: str) -> str:

    """
    Safely quote an SQL identifier (schema/table/column) that matches a conservative pattern.
    """

    if not name or not _IDENT_RE.match(name):
        raise ValueError(f"Unsafe SQL identifier: {name!r}")
    return f'"{name}"'


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
