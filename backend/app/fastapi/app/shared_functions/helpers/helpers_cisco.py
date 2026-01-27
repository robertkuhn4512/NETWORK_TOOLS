from __future__ import annotations

import json
import ipaddress
import os
from typing import Any, Dict, Optional
from urllib.parse import quote
from app.database import database
from uuid import uuid4

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