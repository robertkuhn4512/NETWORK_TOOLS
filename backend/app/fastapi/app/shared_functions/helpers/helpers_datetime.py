import time
import re
import json
from datetime import datetime, date, timezone
from typing import Any, Dict, Optional

# Coerce a value / string to be a strict date / time object
def coerce_dt(dt_in: Optional[str | datetime]) -> str:
    if dt_in is None:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if isinstance(dt_in, datetime):
        return dt_in.strftime("%Y-%m-%d %H:%M:%S")
    try:
        return datetime.fromisoformat(dt_in.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return dt_in.replace("T", " ").split(".")[0][:19]

