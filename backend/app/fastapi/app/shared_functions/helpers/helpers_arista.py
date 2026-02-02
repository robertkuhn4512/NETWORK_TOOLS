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

def arista_allowed_backup_commands(device_type) -> Dict[str, str]:
    """

    :param device_type (arista) etc:
    :return: allowed commands that can be sent to a device for discovery / backup purposes

    Device types are based off what netmiko uses to describe a device using the autodiscover process
    The list can be found here
    https://ktbyers.github.io/netmiko/PLATFORMS.html

    """

    _SHOW_CMD_BY_DEVICE: Mapping[str, str] = {
        "arista_eos": [
            "terminal length 0",
            "show version",
            "show interface description",
            "show interface status",
            "show running-config",
            "show ip ospf database",
            "show ip route",
            "show ip bgp",
            "show bgp summary",
            "show ip bgp summary",
            "sh ip bgp neighbors received-routes",
            "show bgp evpn summary",
            "show interfaces counters rates",
            "show port-channel dense",
            "show port-channel detailed",
            "show lldp neighbors",
            "show lldp neighbors detail",
        ],
        "arista_eos_telnet": [
            "terminal length 0",
            "show version",
            "show interface description",
            "show interface status",
            "show running-config",
            "show ip ospf database",
            "show ip route",
            "show ip bgp",
            "show bgp summary",
            "show ip bgp summary",
            "sh ip bgp neighbors received-routes",
            "show bgp evpn summary",
            "show interfaces counters rates",
            "show port-channel dense",
            "show port-channel detailed",
            "show lldp neighbors",
            "show lldp neighbors detail",
        ],
    }

    return _SHOW_CMD_BY_DEVICE.get(device_type)

def arista_parse_show_version_output(output: str) -> Dict[int, Dict[str, str]]:
    """
    Parse Arista EOS 'show version' output, extracting key fields.

    Returns a dict mapping index -> { field_name: value }.
    """

    FIELD_PATTERNS: List[tuple[str, List[Pattern[str]]]] = [
        (
            "model_number",
            [
                re.compile(r"^Arista\s+(?P<model_number>\S+)", re.IGNORECASE),
            ],
        ),
        (
            "hardware_version",
            [
                re.compile(r"^Hardware\s+version\s*:\s*(?P<hardware_version>[0-9\.]+)", re.IGNORECASE),
            ],
        ),
        (
            "serial_number",
            [
                re.compile(r"^Serial\s+number\s*:\s*(?P<serial_number>\S+)", re.IGNORECASE),
            ],
        ),
        (
            "hardware_mac_address",
            [
                re.compile(r"^Hardware\s+MAC\s+address\s*:\s*(?P<hardware_mac_address>[0-9A-Fa-f\.:]+)", re.IGNORECASE),
            ],
        ),
        (
            "system_mac_address",
            [
                re.compile(r"^System\s+MAC\s+address\s*:\s*(?P<system_mac_address>[0-9A-Fa-f\.:]+)", re.IGNORECASE),
            ],
        ),
        (
            "software_image_version",
            [
                re.compile(r"^Software\s+image\s+version\s*:\s*(?P<software_image_version>\S+)", re.IGNORECASE),
            ],
        ),
    ]

    lines = [ln.strip() for ln in output.splitlines() if ln.strip()]
    result: Dict[int, Dict[str, str]] = {}
    idx = 0

    for field_name, regex_list in FIELD_PATTERNS:
        found = False
        for rx in regex_list:
            for ln in lines:
                m = rx.match(ln)
                if m:
                    # Bail on first match for this field
                    result[idx] = {field_name: m.group(field_name)}
                    idx += 1
                    found = True
                    break
            if found:
                break
        # move on to next field regardless

    return result

def arista_parse_show_hostname(output):
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

def arista_allowed_show_version_commands(device_type) -> Dict[str, str]:
    """

    :param device_type (cisco_ios | cisco_xe | cisco_xr) etc:
    :return: allowed commands that can be sent to a device for discovery / backup purposes

    Device types are based off what netmiko uses to describe a device using the autodiscover process
    The list can be found here
    https://ktbyers.github.io/netmiko/PLATFORMS.html

    """

    _SHOW_VERSION_CMD_BY_DEVICE: Mapping[str, str] = {
        "arista_eos": "show version",
        "arista_eos_telnet":  "show version",
    }

    return _SHOW_VERSION_CMD_BY_DEVICE.get(device_type)

def arista_parse_show_ip_arp_output(output):
    """
    Parse the following output

    show ip arp
    Address         Age (sec)  Hardware Addr   Interface
    172.16.0.2        0:00:01  7483.ef2f.9c9b  Ethernet1/1
    172.16.0.6        0:00:28  d4af.f70a.35dd  Ethernet2/1
    172.16.0.10       0:00:09  7483.ef26.1972  Ethernet3/1
    172.16.0.14       0:00:01  7483.ef2f.43f7  Ethernet4/1
    172.16.0.34       0:00:01  985d.826f.9483  Ethernet6/1
    172.16.0.42       0:00:14  985d.826e.c1df  Ethernet8/1
    172.16.0.86       0:00:29  985d.8297.189d  Ethernet9/1
    172.16.0.94       0:00:27  985d.8297.3335  Ethernet10/1
    172.16.0.54       0:00:34  985d.8297.2a3f  Ethernet11/1
    172.16.0.62       0:00:01  7483.efe1.519f  Ethernet12/1
    172.16.0.98       0:00:01  985d.8297.320d  Ethernet13/1
    172.16.0.106      0:00:43  985d.8297.2555  Ethernet14/1
    """

    """
    Regex - ip arp
    """

    regex_show_ip_arp_matches = re.compile(
        r'^(?P<ipv4_address>([0-9]{1,3}\.){3}[0-9]{1,3})\s+(?P<age>([0-9:\.-]+|N\/A))\s+(?P<mac_address>([0-9a-fA-F]{4}\.){2}[0-9a-fA-F]{4}|INCOMPLETE)\s+(?P<interface>([a-zA-Z0-9,\s\-\/]+))$')

    data = {}
    count = 0
    for line in output.splitlines():
        a = re.search(regex_show_ip_arp_matches, line.strip())
        if a is not None and line.strip() != "":
            data[count] = {
                'ipv4_address': a.groupdict()['ipv4_address'],
                'age': a.groupdict()['age'],
                'mac_address': a.groupdict()['mac_address'].replace(".", ""),
                'interface': a.groupdict()['interface']
            }
            count = count + 1

    return data

def arista_parse_show_mac_address_table(output):
    """
    parse the following from the arista devices and return a dict of the information below

    show mac address_table

          Mac Address Table
    ------------------------------------------------------------------

    Vlan    Mac Address       Type        Ports      Moves   Last Move
    ----    -----------       ----        -----      -----   ---------
     299    0000.5e00.1234    DYNAMIC     Po1        1       560 days, 3:13:24 ago
     299    0024.81ae.2312    DYNAMIC     Po1        1       560 days, 3:12:21 ago

    """



    regex_show_mac_address = re.compile(
        r'^(?P<vlan_id>[0-9]+)\s+(?P<mac_address>(INCOMPLETE|([a-fA-F0-9]{4}\.){2}[a-fA-F0-9]{4}))\s+(?P<type>[a-zA-Z0-9]+)\s+(?P<interface>[a-zA-Z0-9\/]+)\s+(?P<moves>[0-9]+)\s+(?P<age>[a-zA-Z0-9\/\s,:]+ago)')

    data = {}
    count = 0
    for line in output.splitlines():
        a = re.search(regex_show_mac_address, line.strip())
        if a is not None and line.strip() != "":
            data[count] = {
                'vlan_id': a.groupdict()['vlan_id'],
                'mac_address': a.groupdict()['mac_address'],
                'type': a.groupdict()['type'],
                'interface': a.groupdict()['interface'],
                'moves': a.groupdict()['moves'],
                'age': a.groupdict()['age']
            }
            count = count + 1


    return data