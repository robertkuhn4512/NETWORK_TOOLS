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

def juniper_allowed_backup_commands(device_type) -> Dict[str, str]:
    """

    :param device_type (juniper) etc:
    :return: allowed commands that can be sent to a device for discovery / backup purposes

    Device types are based off what netmiko uses to describe a device using the autodiscover process
    The list can be found here
    https://ktbyers.github.io/netmiko/PLATFORMS.html

    """

    _SHOW_CMD_BY_DEVICE: Mapping[str, str] = {
        "juniper": [
            "show version",
            "show configuration | display set",
        ],
        "juniper_junos": [
            "show version",
            "show configuration | display set",
        ],
        "juniper_screenos": [
            "show version",
            "show configuration | display set",
        ],
        "juniper_junos_telnet": [
            "show version",
            "show configuration | display set",
        ],
    }

    return _SHOW_CMD_BY_DEVICE.get(device_type)

def juniper_srx5100_show_ip_arp(output):
    """
    MAC Address       Address         Name                      Interface               Flags
    ac:cc:8e:85:d9:83 10.25.0.4       10.25.0.4                 reth2.123               none
    00:40:8c:fa:8b:20 10.25.0.5       10.25.0.5                 reth2.123               none
    00:40:8c:fa:90:c2 10.25.0.6       10.25.0.6                 reth2.123               none
    ac:cc:8e:05:53:a7 10.25.0.7       10.25.0.7                 reth2.123               none
    """

    return_data = []

    """
    Regex - ip arp
    """

    regex_show_ip_arp_matches = re.compile(
        r'(?P<mac_address>([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})\s(?P<ipv4_address>([0-9]{1,3}\.){3}[0-9]{1,3})\s+(?P<name>[0-9a-zA-Z\.\-]+)\s+(?P<interface>[0-9a-zA-Z\.\-]+)')

    data = {}
    count = 0
    for line in output.splitlines():
        a = re.search(regex_show_ip_arp_matches, line.strip())
        if a is not None and line.strip() != "":
            data[count] = {
                'ipv4_address': a.groupdict()['ipv4_address'],
                'age': '',
                'mac_address': a.groupdict()['mac_address'],
                'mac_address_condensed': re.sub('(\.|:)', '', a.groupdict()['mac_address']),
                'interface': a.groupdict()['interface']
            }
            count = count + 1

    return data

def juniper_parse_show_run_interface_match_description(output):
    """
    show run interface <interface> | i description
    """

    regex = re.compile(
        r'^description\s(?P<description>.*);')

    data = {}

    data = {
        'description': ''
    }

    count = 0
    for line in output.splitlines():
        a = re.search(regex, line.strip())
        if a is not None and line.strip() != "":
            data = {
                'description': a.groupdict()['description']
            }
            return data
    return data
