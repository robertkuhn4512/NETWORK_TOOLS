from __future__ import annotations

import json
import ipaddress
import os
from typing import Any, Dict, Optional
from datetime import datetime, date
from urllib.parse import quote
from app.database import database
from uuid import uuid4

def env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return str(raw).strip().lower() in {"1", "true", "t", "yes", "y", "on"}

def pretty_json_any(
    value: Any,
    *,
    pretty: bool = True,
    indent: int = 2,
    sort_keys: bool = True,
    ensure_ascii: bool = False,
    max_len: Optional[int] = None,
    parse_nested_json_strings: bool = True,
    max_depth: int = 3,
) -> str:
    """
    Notes / How to run:
    - Call pretty_json_any(value) anywhere you currently call payload_json/_pretty_json.
    - If `value` is a non-JSON string, it returns the string unchanged.
    - If `value` (or nested string values) contain JSON objects/arrays, it parses + pretty prints them.

    Behavior:
    - Strings:
        - If they look like JSON ({ or [), attempt json.loads
        - On failure, return original string
    - dict/list/etc:
        - dumps with a safe default serializer
    - Nested JSON strings:
        - If enabled, recursively parses string fields that look like JSON
    """

    def _json_default(o: Any):
        if isinstance(o, (datetime, date)):
            return o.isoformat()
        if isinstance(o, set):
            return sorted(o)
        if isinstance(o, bytes):
            return o.decode("utf-8", "replace")
        return repr(o)

    def _looks_like_json(s: str) -> bool:
        s2 = s.lstrip()
        return bool(s2) and s2[0] in "{["

    def _try_load_json_string(s: str) -> Any:
        # Only parse strings that look like JSON objects/arrays to avoid surprising coercions
        # (e.g. "123" -> 123).
        if not _looks_like_json(s):
            return s
        try:
            return json.loads(s)
        except json.JSONDecodeError:
            return s

    def _coerce(obj: Any, depth: int) -> Any:
        if not parse_nested_json_strings or depth >= max_depth:
            return obj

        if isinstance(obj, str):
            parsed = _try_load_json_string(obj)
            if parsed is obj:
                return obj
            return _coerce(parsed, depth + 1)

        if isinstance(obj, dict):
            return {k: _coerce(v, depth + 1) for k, v in obj.items()}

        if isinstance(obj, list):
            return [_coerce(v, depth + 1) for v in obj]

        return obj

    # If it's a string, return it unchanged unless it parses cleanly into JSON
    if isinstance(value, str):
        parsed = _try_load_json_string(value)
        if parsed is value:
            return value
        coerced = _coerce(parsed, 0)
        s = json.dumps(
            coerced,
            indent=indent if pretty else None,
            sort_keys=sort_keys,
            ensure_ascii=ensure_ascii,
            default=_json_default,
        )
    else:
        coerced = _coerce(value, 0)
        s = json.dumps(
            coerced,
            indent=indent if pretty else None,
            sort_keys=sort_keys,
            ensure_ascii=ensure_ascii,
            default=_json_default,
        )

    if max_len is not None and len(s) > max_len:
        if max_len <= 3:
            return s[:max_len]
        return s[: max_len - 3] + "..."

    return s

def _is_blank(v: Any) -> bool:
    return v is None or (isinstance(v, str) and v.strip() == "")