from __future__ import annotations

import json
import ipaddress
import os
from typing import Any, Dict, Optional
from urllib.parse import quote
from app.database import database
from uuid import uuid4

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