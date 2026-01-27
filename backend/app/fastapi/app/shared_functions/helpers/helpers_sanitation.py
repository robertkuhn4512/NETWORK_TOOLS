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
    'enable_password',
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
    # If it's a JSON-looking string, try to parse and scrub the parsed structure
    if isinstance(obj, str):
        s = obj.lstrip()
        if s.startswith("{") or s.startswith("["):
            try:
                parsed = json.loads(obj)
                scrubbed = scrub_secrets(parsed)
                # return scrubbed structure (dict/list), not a string
                return scrubbed
            except json.JSONDecodeError:
                return obj
        return obj

    if isinstance(obj, dict):
        clean = {}
        for k, v in obj.items():
            if isinstance(k, str) and k.strip().lower() in SECRET_KEYS:
                clean[k] = "Redacted"
            else:
                clean[k] = scrub_secrets(v)
        return clean

    if isinstance(obj, list):
        return [scrub_secrets(item) for item in obj]

    if isinstance(obj, set):
        return [scrub_secrets(item) for item in obj]

    return obj