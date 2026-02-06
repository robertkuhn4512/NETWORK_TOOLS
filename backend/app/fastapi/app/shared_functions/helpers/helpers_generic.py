from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, Optional
from datetime import datetime, date




def env_bool_if_set(name: str) -> Optional[bool]:
    _TRUE = {"1", "true", "t", "yes", "y", "on"}
    _FALSE = {"0", "false", "f", "no", "n", "off"}

    """
    Returns:
      - True/False if env var exists and is parseable as boolean
      - None if env var is missing OR empty OR unparseable

    Missing -> None - Used if the variable is not set and I want to not proceed with something
    """
    raw = os.getenv(name)

    if raw is None:
        return None

    s = raw.strip().lower()

    if s == "":
        return None

    if s in _TRUE:
        return True

    if s in _FALSE:
        return False

    return None

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

def _as_str(v: Any) -> Optional[str]:
    if v is None:
        return None
    if isinstance(v, str):
        s = v.strip()
        return s if s != "" else None
    # avoid lossy conversions for nested structures
    if isinstance(v, (dict, list, tuple)):
        return None
    return str(v).strip() or None


def _as_int(v: Any) -> Optional[int]:
    if v is None:
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, float):
        return int(v)
    if isinstance(v, str):
        s = v.strip()
        if s == "":
            return None
        try:
            return int(s)
        except ValueError:
            return None
    return None


def _uptime_to_seconds(days: Optional[int], hours: Optional[int], mins: Optional[int], secs: Optional[int]) -> Optional[int]:
    if days is None and hours is None and mins is None and secs is None:
        return None
    d = days or 0
    h = hours or 0
    m = mins or 0
    s = secs or 0
    return (d * 86400) + (h * 3600) + (m * 60) + s


def _parse_dt_best_effort(s: Optional[str]) -> Dict[str, Any]:
    """
    Returns a structured dict so you keep the original string and any parsed form.
    We do NOT assume timezone; NX-OS strings are typically device-local time.
    """
    out = {"raw": s, "parsed": None, "format": None}
    if not s:
        return out

    # Try a small set of common NX-OS formats seen in your sample.
    fmts = [
        "%m/%d/%Y",              # 11/29/2023
        "%m/%d/%Y %H:%M:%S",     # 4/30/2024 12:00:00
        "%m/%d/%Y %H:%M:%S",     # 05/08/2024 05:39:13
        "%a %b %d %H:%M:%S %Y",  # Wed Jan  7 10:33:44 2026  (note double-space day handled by %d)
        "%a %b %d %H:%M:%S %Y",  # Wed Jan 07 10:33:44 2026
    ]

    for fmt in fmts:
        try:
            dt = datetime.strptime(s, fmt)
            out["parsed"] = dt.isoformat(sep=" ")
            out["format"] = fmt
            return out
        except Exception:
            continue

    return out

def _ensure_list(v: Any) -> List[Dict[str, Any]]:
    if v is None:
        return []
    if isinstance(v, list):
        return [x for x in v if isinstance(x, dict)]
    if isinstance(v, dict):
        return [v]
    return []

def _nxos_duration_to_seconds(value: Any) -> Optional[int]:
    """Convert NX-OS JSON `time-stamp` values to seconds (best-effort).

    Observed formats:
      - ISO-8601 duration: "PT11S", "PT2M13S", "PT1H"
      - hh:mm:ss (rare)
      - empty / None

    Returns None when unknown.
    """
    if value is None:
        return None
    s = str(value).strip()
    if not s:
        return None

    # hh:mm:ss
    m = re.match(r"^(?P<h>\d+):(?P<m>\d{1,2}):(?P<s>\d{1,2})$", s)
    if m:
        return int(m.group("h")) * 3600 + int(m.group("m")) * 60 + int(m.group("s"))

    # ISO-8601 duration PnDTnHnMnS (NX-OS typically PT..)
    m = re.match(
        r"^P(?:(?P<days>\d+)D)?(?:T(?:(?P<hours>\d+)H)?(?:(?P<minutes>\d+)M)?(?:(?P<seconds>\d+)S)?)?$",
        s,
        re.IGNORECASE,
    )
    if m:
        days = int(m.group("days") or 0)
        hours = int(m.group("hours") or 0)
        minutes = int(m.group("minutes") or 0)
        seconds = int(m.group("seconds") or 0)
        return days * 86400 + hours * 3600 + minutes * 60 + seconds

    return None

def _escape_controls_inside_json_strings(s: str) -> str:
    """
    Notes / How to run:
    - This is a pre-sanitizer for device JSON that sometimes gets corrupted by terminal line-wrapping /
      copy-paste (raw newlines inside quoted strings, or a backslash followed by a newline).
    - Call this before json.loads.

    What it fixes:
    - Raw control chars inside JSON strings: \n \r \t etc -> escaped forms
    - Backslash + raw newline inside a JSON string (invalid JSON) -> coerces into a valid \\n escape
    """
    in_str = False
    esc = False
    out: list[str] = []

    for ch in s:
        if not in_str:
            out.append(ch)
            if ch == '"':
                in_str = True
            continue

        if esc:
            # If the input was line-wrapped, you can end up with: \"as is,\ <newline> "
            # JSON does NOT allow backslash-newline escapes. Convert that newline into a legal \n.
            if ch == '\n':
                # replace the previously appended "\" with "\n"
                if out and out[-1] == '\\':
                    out[-1] = '\\n'
                else:
                    out.append('\\n')
                esc = False
                continue
            if ch == '\r':
                if out and out[-1] == '\\':
                    out[-1] = '\\r'
                else:
                    out.append('\\r')
                esc = False
                continue
            if ch == '\t':
                if out and out[-1] == '\\':
                    out[-1] = '\\t'
                else:
                    out.append('\\t')
                esc = False
                continue

            out.append(ch)
            esc = False
            continue

        if ch == '\\':
            out.append(ch)
            esc = True
            continue

        if ch == '"':
            out.append(ch)
            in_str = False
            continue

        o = ord(ch)
        if o < 0x20:  # illegal control char in JSON string
            if ch == '\n':
                out.append('\\n')
            elif ch == '\r':
                out.append('\\r')
            elif ch == '\t':
                out.append('\\t')
            else:
                out.append(f'\\u{o:04x}')
        else:
            out.append(ch)

    return ''.join(out)

def _json_load_dict_best_effort(output: Union[str, Dict[str, Any]]) -> Dict[str, Any]:
    """Best-effort JSON object loader for command outputs.

    Accepts:
      - dict (already-decoded JSON)
      - str (JSON text; will attempt to escape control chars inside JSON strings)

    Returns:
      - dict JSON object on success
      - {"error": "..."} on failure
    """
    if isinstance(output, dict):
        return output

    raw = "" if output is None else str(output)
    if not raw.strip():
        return {"error": "invalid_payload: expected non-empty json string or dict"}

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        try:
            fixed = _escape_controls_inside_json_strings(raw)
            data = json.loads(fixed)
        except Exception as exc:
            return {"error": f"invalid_json: {type(exc).__name__}: {exc}"}

    if not isinstance(data, dict):
        return {"error": "invalid_payload: expected JSON object"}

    return data