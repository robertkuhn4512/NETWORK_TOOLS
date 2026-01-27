from __future__ import annotations

import time
import re
import json
import os
import sys
import logging

from typing import Iterable, Any, Dict, List, Optional, Tuple, Union
from datetime import datetime, date, timezone
from pprint import pprint
from decouple import Config, RepositoryEnv
from contextlib import contextmanager
from pprint import pformat

logger = logging.getLogger(__name__)

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


def extract_snmp_value(poller_data: dict,
                        setting: dict,
                        error_msg: str) -> str:
    """
    Given the poller_data dict and a setting dict like
      {'mib': 'entPhysicalSoftwareRev', 'oid': '.1.3.…'},
    attempt to pull out poller_data[mib][oid].  On any failure, return error_msg.
    """
    # 1) get mib & oid
    mib = setting.get("mib")
    oid = setting.get("oid")
    if not mib or not oid:
        return error_msg

    # 2) fetch the raw blob
    blob = poller_data.get(mib)

    if blob is None:
        return error_msg

    try:
        # 3) if it's a JSON string, parse it
        if isinstance(blob, str):
            blob = json.loads(blob)

        # 4) ensure it's a dict
        if not isinstance(blob, dict):
            return error_msg

        # 5) pull the OID value (could be empty)
        value = blob.get(oid, "")
        return value or error_msg

    except (json.JSONDecodeError, TypeError, ValueError):
        return error_msg
    except Exception:
        return error_msg

def cast(value: Any) -> Any:
    """
    Given a pysnmp value object (or any other value), return a plain‐Python value:
      • SnmpEngineID → hex string
      • IpAddress     → dotted‐quad string
      • Any object that implements __bytes__ (OctetString, Counter64, etc.) →
          bytes(value) → decode as UTF-8 (fallback Latin-1) → replace CR/LF with space → strip →
          int/float if numeric → else decoded text
      • Otherwise, str(value) → replace CR/LF with space → strip → int/float if numeric → else string
    """
    cls = value.__class__.__name__

    # 1) SnmpEngineID → hexlify
    if cls == "SnmpEngineID":
        return binascii.hexlify(bytes(value)).decode("utf-8")

    # 2) IpAddress → dotted‐quad
    if cls == "IpAddress":
        hex_str = binascii.hexlify(bytes(value)).decode("utf-8")
        return str(ipaddress.ip_address(int(hex_str, 16)))

    # 3) If it implements __bytes__ (OctetString, Counter64, Gauge32, etc.)
    if not isinstance(value, (str, int, float, bool)) and hasattr(value, "__bytes__"):
        raw = bytes(value)  # get raw bytes
        if len(raw) == 0:
            return ""

        # Attempt UTF-8 decode, fallback to Latin-1 if needed
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = raw.decode("latin-1", errors="ignore")

        # Replace any CR/LF or LF with a single space, then strip
        text = text.replace("\r\n", " ").replace("\n", " ").strip()
        if not text:
            return ""

        # If the decoded text is an integer literal
        if re.fullmatch(r"-?\d+", text):
            return int(text)

        # If it’s a float literal
        try:
            return float(text)
        except ValueError:
            pass

        # Otherwise return the decoded string
        return text

    # 4) Otherwise, treat it as a primitive (e.g. pysnmp.Integer or a simple string/number)
    s = str(value)
    # Replace any CR/LF or LF with a single space, then strip
    s = s.replace("\r\n", " ").replace("\n", " ").strip()
    if not s:
        return ""

    # Try to coerce to int
    if re.fullmatch(r"-?\d+", s):
        return int(s)

    # Try to coerce to float
    try:
        return float(s)
    except ValueError:
        pass

    # Fallback: return as string
    return s








