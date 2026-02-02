from __future__ import annotations

import json
import ipaddressfrom __future__ import annotations

import json
import ipaddress
import os
import re
from typing import Any, Dict, Optional, List, Tuple, Sequence, Union
from urllib.parse import quote
from app.database import database
from uuid import uuid4
import os
import re
from typing import Any, Dict, Optional, List, Tuple, Sequence, Union
from urllib.parse import quote
from app.database import database
from uuid import uuid4

def a10_allowed_backup_commands(device_type) -> Dict[str, str]:
    """

    :param device_type (a10) etc:
    :return: allowed commands that can be sent to a device for discovery / backup purposes

    Device types are based off what netmiko uses to describe a device using the autodiscover process
    The list can be found here
    https://ktbyers.github.io/netmiko/PLATFORMS.html

    """

    _SHOW_CMD_BY_DEVICE: Mapping[str, str] = {
        "a10": [
            "show version",
            "show interfaces",
            "show interfaces brief",
            "show running-config"
        ],
    }

    return _SHOW_CMD_BY_DEVICE.get(device_type)

def a10_allowed_show_version_commands(device_type) -> Dict[str, str]:
    """

    :param device_type (cisco_ios | cisco_xe | cisco_xr) etc:
    :return: allowed commands that can be sent to a device for discovery / backup purposes

    Device types are based off what netmiko uses to describe a device using the autodiscover process
    The list can be found here
    https://ktbyers.github.io/netmiko/PLATFORMS.html

    """

    _SHOW_VERSION_CMD_BY_DEVICE: Mapping[str, str] = {
        "a10": "show version",
    }

    return _SHOW_VERSION_CMD_BY_DEVICE.get(device_type)