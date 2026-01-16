from __future__ import annotations

import json
import ipaddress
import os
from typing import Any, Dict, Optional
from urllib.parse import quote
from app.database import database
from uuid import uuid4

"""
Sanitation helper functions
"""

SECRET_KEYS = { s.lower() for s in {
    'password',
    'enable_secret',
    'community_string',
    'secret',
    'UsmUserData_password',
    'UsmUserData_username',
    'fast_api_mariadb_production_password',
    'private_key',
    'public_key',
    'api_key',
    'api_token',
    'token'
}}

def scrub_secrets(obj: Any) -> Any:
    if isinstance(obj, dict):
        clean = {}
        for k, v in obj.items():
            if isinstance(k, str) and k.lower() in SECRET_KEYS:
                clean[k] = "Redacted"
            else:
                clean[k] = scrub_secrets(v)
        return clean

    elif isinstance(obj, list):
        return [scrub_secrets(item) for item in obj]

    elif isinstance(obj, set):
        return [scrub_secrets(item) for item in obj]

    else:
        return obj

"""
Network related helper functions
"""

# Subnetting
def cidr_to_netmask(cidr: str):
    """
    Convert an IPv4 CIDR (e.g. "1.1.1.1/16") into a dotted-decimal subnet mask.

    :param cidr: IPv4 address in CIDR notation
    :return: Subnet mask as dotted-decimal string, or False if input is invalid
    """
    try:
        addr, prefix_str = cidr.split('/')
        prefix = int(prefix_str)
        if prefix < 0 or prefix > 32:
            return False
    except Exception:
        return False

    # Build a 32-bit mask with top `prefix` bits set
    mask_int = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    return '.'.join(str((mask_int >> offset) & 0xFF) for offset in (24, 16, 8, 0))

# Cisco
def parse_show_capabilities(output: str) -> Dict[str, Dict]:
    """
    Parse the output of `show capabilities` and return a dict keyed by
    interface long name, each containing:
      - long_name: full interface name
      - short_name: abbreviated interface name
      - model: device model
      - type: list of supported media types
      - speed: list of supported speeds
      - duplex: list of supported duplex modes
      - trunk_encap_type: trunk encapsulation type
      - trunk_mode: list of allowed trunk modes
    """
    # mapping of full interface prefixes to their short forms
    prefix_map = {
        'TenGigabitEthernet': 'Te',
        'GigabitEthernet':    'Gi',
        'FastEthernet':       'Fa',
        'Ethernet':           'Et',
        'Port-Channel':       'Po',
        'Vlan':               'Vl',
    }

    def short_name(long_name: str) -> str:
        for full, abbr in sorted(prefix_map.items(), key=lambda kv: -len(kv[0])):
            if long_name.startswith(full):
                return abbr + long_name[len(full):]
        return long_name

    # build a regex that matches any of the prefixes + port numbers (e.g. 1, 1/0, 1/0/1)
    prefixes = sorted(prefix_map.keys(), key=lambda x: -len(x))
    prefix_pattern = r'(?:' + '|'.join(re.escape(p) for p in prefixes) + r')'
    if_hdr = re.compile(
        rf'^\s*'                    # optional leading space
        rf'(?P<intf>{prefix_pattern}\d+(?:/\d+){0,2})\s*$'
    )

    # field patterns
    patterns = {
        'model': re.compile(r'^\s*Model:\s*(\S+)'),
        'type': re.compile(r'^\s*Type:\s*(.+)'),
        'speed': re.compile(r'^\s*Speed:\s*(.+)'),
        'duplex': re.compile(r'^\s*Duplex:\s*(.+)'),
        'trunk_encap_type': re.compile(r'^\s*Trunk encap\. type:\s*(.+)'),
        'trunk_mode': re.compile(r'^\s*Trunk mode:\s*(.+)'),
    }

    interfaces: Dict[str, Dict] = {}
    current = None

    for line in output.splitlines():
        m_hdr = if_hdr.match(line)
        if m_hdr:
            current = m_hdr.group('intf')
            interfaces[current] = {
                'long_name': current,
                'short_name': short_name(current),
                'model': None,
                'type': [],
                'speed': [],
                'duplex': [],
                'trunk_encap_type': None,
                'trunk_mode': [],
            }
            continue

        if not current:
            continue

        for key, pat in patterns.items():
            m = pat.match(line)
            if not m:
                continue
            val = m.group(1).strip()
            if key in ('type', 'speed', 'duplex', 'trunk_mode'):
                delim = ',' if ',' in val else '/'
                items = [v.strip() for v in val.split(delim) if v.strip()]
                interfaces[current][key] = items
            else:
                interfaces[current][key] = val
            break

    return interfaces


"""
Misc helper functions
"""


def env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return str(raw).strip().lower() in {"1", "true", "t", "yes", "y", "on"}

def json_dumps_safe(value: Any) -> str:
    """
    For storing structured data in text columns (like app_backend_tracking.information).
    - Strings pass through unchanged.
    - Dict/list/etc are JSON dumped with default=str for non-serializables.
    """
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)


def user_display(user: Any) -> str:
    """
    Your current whoami returns:
      {"sub", "username", "roles", "azp"}
    So "username" is the best display key; fallback to sub.
    Works with Pydantic models or dicts.
    """
    if user is None:
        return "unknown"

    if hasattr(user, "model_dump"):
        data = user.model_dump()
        return data.get("username") or data.get("sub") or "unknown"

    if isinstance(user, dict):
        return user.get("username") or user.get("sub") or "unknown"

    return getattr(user, "username", None) or getattr(user, "sub", None) or "unknown"

def _is_blank(v: Any) -> bool:
    return v is None or (isinstance(v, str) and v.strip() == "")


"""
SNMP Related helper functions
"""

"""
Useful Cisco OIDs for discovery / information gathering purposes
"""
_USEFUL_CISCO_OIDS: Dict[str, str] = {
    "vlan_mac_table": ".1.3.6.1.2.1.17.4.3.1.2",
    "bridge_port_id_mac": ".1.3.6.1.2.1.17.4.3.1.2",
    "bridge_ifindex": ".1.3.6.1.2.1.17.1.4.1.2",
}

def get_useful_cisco_oids() -> dict[str, str]:
    """
    Helper: return a dict of "friendly_name" -> "oid".

    Returns a copy to prevent callers from mutating the module constant.
    """
    return dict(_USEFUL_CISCO_OIDS)


"""
Database helper functions
"""

def build_postgres_async_dsn() -> str:
    """
    Builds an asyncpg DSN from Vault-injected env vars.

    Env:
      FASTAPI_DB_URL_HOST
      FASTAPI_DB_URL_PORT
      FASTAPI_DB_URL_DATABASE
      FASTAPI_DB_USERNAME
      FASTAPI_DB_PASSWORD

    Returns:
      postgresql+asyncpg://<urlencoded_user>:<urlencoded_pass>@host:port/db
    """
    host = os.getenv("FASTAPI_DB_URL_HOST", "localhost")
    port = os.getenv("FASTAPI_DB_URL_PORT", "5432")
    db = os.getenv("FASTAPI_DB_URL_DATABASE", "network_tools")

    user_raw = os.getenv("FASTAPI_DB_USERNAME", "")
    pw_raw = os.getenv("FASTAPI_DB_PASSWORD", "")

    user = quote(user_raw, safe="")
    pw = quote(pw_raw, safe="")
    db_enc = quote(db, safe="")  # optional; safe either way

    return f"postgresql+asyncpg://{user}:{pw}@{host}:{port}/{db_enc}"

ACTIVE_STATUSES = ("QUEUED", "STARTED", "RETRY")

async def _reserve_job_row_queued(*, job_name: str, dedupe_key: str, request_payload: dict, correlation_id: str | None):
    job_id = str(uuid4())
    task_id = str(uuid4())  # pre-generate so task_id is never NULL

    insert_sql = """
    INSERT INTO app_tracking_celery (
        job_id, task_id, job_name, dedupe_key, correlation_id,
        status, request, created_at, updated_at
    )
    VALUES (
        :job_id, :task_id, :job_name, :dedupe_key, :correlation_id,
        'QUEUED', CAST(:request AS jsonb), now(), now()
    )
    ON CONFLICT (job_name, dedupe_key)
    WHERE is_deleted = FALSE AND status IN ('QUEUED','RECEIVED','STARTED','RETRY')
    DO NOTHING
    RETURNING job_id, task_id
    """

    row = await database.fetch_one(insert_sql, {
        "job_id": job_id,
        "task_id": task_id,
        "job_name": job_name,
        "dedupe_key": dedupe_key,
        "correlation_id": correlation_id,
        "request": json.dumps(request_payload),
    })

    if row:
        return {"created": True, "job_id": row["job_id"], "task_id": row["task_id"], "status": "QUEUED"}

    # duplicate active job exists
    select_sql = """
    SELECT job_id, task_id, status
    FROM app_tracking_celery
    WHERE is_deleted = FALSE
      AND job_name = :job_name
      AND dedupe_key = :dedupe_key
      AND status IN ('QUEUED','RECEIVED','STARTED','RETRY')
    ORDER BY created_at DESC
    LIMIT 1
    """
    existing = await database.fetch_one(select_sql, {"job_name": job_name, "dedupe_key": dedupe_key})
    if existing:
        return {"created": False, "job_id": existing["job_id"], "task_id": existing["task_id"], "status": existing["status"]}

    return {"error": "reserve_failed_unknown_state"}

async def _attach_task_id(*, job_id: str, task_id: str) -> None:
    sql = """
    UPDATE app_tracking_celery
    SET task_id = :task_id,
        updated_at = now()
    WHERE job_id = :job_id
    """
    await database.execute(sql, {"job_id": job_id, "task_id": task_id})

async def _mark_job_failed_enqueue(*, job_id: str, error_message: str) -> None:
    sql = """
    UPDATE app_tracking_celery
    SET status = 'FAILURE',
        error_message = :error_message,
        updated_at = now(),
        completed_at = now()
    WHERE job_id = :job_id
    """
    await database.execute(sql, {"job_id": job_id, "error_message": error_message[:2000]})

"""
Subnetting helper functions
"""

def expand_ipv4_targets_max_24(cidr: str) -> tuple[str, list[str]]:
    net = ipaddress.ip_network(cidr.strip(), strict=False)

    if net.version != 4:
        raise ValueError("Only IPv4 is supported")

    # /24 max means prefixlen must be >= 24
    if net.prefixlen < 24:
        raise ValueError("Max subnet size is /24")

    cidr_norm = str(net)

    if net.prefixlen == 32:
        return cidr_norm, [str(net.network_address)]

    return cidr_norm, [str(ip) for ip in net.hosts()]