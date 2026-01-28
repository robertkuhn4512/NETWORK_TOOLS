from __future__ import annotations

import json
import ipaddress
import os
import re
from typing import Any, Dict, Optional, List, Tuple, Sequence, Union
from urllib.parse import quote
from app.database import database
from uuid import uuid4


def cisco_allowed_backup_commands(device_type) -> Dict[str, str]:
    """

    :param device_type (cisco_ios | cisco_xe | cisco_xr) etc:
    :return: allowed commands that can be sent to a device for discovery / backup purposes

    Device types are based off what netmiko uses to describe a device using the autodiscover process
    The list can be found here
    https://ktbyers.github.io/netmiko/PLATFORMS.html

    """

    _SHOW_CMD_BY_DEVICE: Mapping[str, str] = {
        "cisco_ios": [
            "show version",
            "show interface description",
            "show interface brief",
            "show running-config",
            "show mac address-table count",
        ],
        "cisco_xe": [
            "show version",
            "show interface description",
            "show interface brief",
            "show running-config",
            "show mac address-table count",
        ],
        "cisco_xr": [
            "show version",
            "show interface description",
            "show interface brief",
            "show running-config",
            "show mac address-table count",
        ],
        "cisco_nxos": [
            "show version",
            "show inventory",
            "show interface description",
            "show interface status",
            "show running-config",
            # "show startup-config",
            "show mac address-table count",
        ],
    }

    return _SHOW_CMD_BY_DEVICE.get(device_type)

def cisco_map_device_type_os_type(device_type) -> Dict[str, str]:
    """
    This is used when saving devices to the devices table.
    This information is used when querying ciscos apis for info like cves etc

    """

    _OS_NAME_BY_DEVICE: Mapping[str, str] = {
        "cisco_ios": "ios",
        "cisco_xe":  "iosxe",
        "cisco_xr":  "iosxr",
        "cisco_nxos":  "nxos",
        "cisco_asa":  "asa",
    }

    return _OS_NAME_BY_DEVICE.get(device_type)

def cisco_allowed_show_version_commands(device_type) -> Dict[str, str]:
    """

    :param device_type (cisco_ios | cisco_xe | cisco_xr) etc:
    :return: allowed commands that can be sent to a device for discovery / backup purposes

    Device types are based off what netmiko uses to describe a device using the autodiscover process
    The list can be found here
    https://ktbyers.github.io/netmiko/PLATFORMS.html

    """

    _SHOW_VERSION_CMD_BY_DEVICE: Mapping[str, str] = {
        "cisco_ios": "show version",
        "cisco_xe":  "show version",
        "cisco_xr":  "show version",
        "cisco_nxos":  "show version",
    }

    return _SHOW_VERSION_CMD_BY_DEVICE.get(device_type)


def cisco_show_version_parse(output: str) -> Dict[str, str]:
    """
    Parse key bits out of Cisco 'show version' output (IOS-XE + older IOS/3x/4xx).

    Rules:
      - For each field, try regexes in priority order.
      - For each regex, scan lines top-to-bottom.
      - First match wins for that field (bail immediately).
      - Returns a flat dict of discovered fields:
          software_version, model_number, system_serial_number, base_ethernet_mac_address
    """

    lines = [ln.strip() for ln in output.splitlines() if ln.strip()]

    # Capture everything to a single key: software_version
    version_patterns: List[re.Pattern] = [
        # IOS-XE explicit
        re.compile(
            r"^Cisco IOS XE Software,\s*Version\s+"
            r"(?P<software_version>\d+(?:\.[0-9A-Za-z]+)+)",
            re.IGNORECASE,
        ),
        # Many platforms just have "Version X.Y..."
        re.compile(
            r"^(?:Cisco IOS XE Software,\s*Version|Version)\s+"
            r"(?P<software_version>\d+(?:\.[0-9A-Za-z]+)+)",
            re.IGNORECASE,
        ),
        # Older IOS: "Cisco IOS Software, ... Version 15.2(4)E10, ..."
        re.compile(
            r"^Cisco IOS Software,.*\bVersion\s+(?P<software_version>[^,]+)",
            re.IGNORECASE,
        ),
        # Fallback: any "Version <until comma>"
        re.compile(r"\bVersion\s+(?P<software_version>[^,]+)", re.IGNORECASE),
    ]

    field_patterns: List[Tuple[str, List[re.Pattern]]] = [
        (
            "software_version",
            version_patterns,
        ),
        (
            "model_number",
            [
                re.compile(
                    r"^Model\s+Number\s*:\s*(?P<model_number>[A-Za-z0-9\-]+)$",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"^License\s+Information\s+for\s+'(?P<model_number>[A-Za-z0-9\-]+)'$",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"^Cisco\s+(?P<model_number>WS-[A-Za-z0-9\-]+)\s*\(",
                    re.IGNORECASE,
                ),
            ],
        ),
        (
            "system_serial_number",
            [
                re.compile(
                    r"^System\s+Serial\s+Number\s*:\s*(?P<system_serial_number>[A-Za-z0-9\-]+)$",
                    re.IGNORECASE,
                ),
                re.compile(
                    r"^Processor\s+board\s+ID\s+(?P<system_serial_number>[A-Za-z0-9\-]+)$",
                    re.IGNORECASE,
                ),
            ],
        ),
        (
            "base_ethernet_mac_address",
            [
                re.compile(
                    r"^Base\s+Ethernet\s+MAC\s+Address\s*:\s*"
                    r"(?P<base_ethernet_mac_address>(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})$",
                    re.IGNORECASE,
                )
            ],
        ),
    ]

    results: Dict[str, str] = {}
    remaining = {field for field, _ in field_patterns}

    for field_name, regex_list in field_patterns:
        found = False
        for rx in regex_list:
            for ln in lines:
                m = rx.search(ln)
                if m:
                    results[field_name] = m.group(field_name).strip()
                    remaining.discard(field_name)
                    found = True
                    break
            if found:
                break

        if not remaining:
            break

    return results

def cisco_parse_show_interface_capabilities(output: str) -> Dict[str, Dict]:
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

def cisco_hostname(output):
    """
    parse the output of a show running-config | i hostname
    and return the hostname.
    """

    regex = re.compile(
        r'^hostname\s(?P<hostname>.*)')

    data = {}
    data = {
        'hostname': ''
    }
    count = 0
    for line in output.splitlines():
        a = re.search(regex, line.strip())
        if a is not None and line.strip() != "":
            data = {
                'hostname': a.groupdict()['hostname']
            }
            return data
    return data