from __future__ import annotations

import json
import ipaddress
import os
from typing import Any, Dict, Optional
from urllib.parse import quote
from app.database import database
from uuid import uuid4

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