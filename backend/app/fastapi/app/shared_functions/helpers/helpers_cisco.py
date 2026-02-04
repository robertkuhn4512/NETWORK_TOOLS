from __future__ import annotations

import json
import ipaddress
import os
import re
from typing import Any, Dict, Optional, List, Tuple, Sequence, Union
from urllib.parse import quote
from app.database import database
from uuid import uuid4


# Precompiled Regex's
# ---------------------------------------------------------------------------
# Unified MAC address-table parsers (IOS/IOS-XE/NX-OS; best-effort XR)
# ---------------------------------------------------------------------------

_MAC_TOKEN = re.compile(
    r'^(?:'
    r'(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}'          # xxxx.xxxx.xxxx
    r'|(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}'           # xx:xx:xx:xx:xx:xx
    r'|[0-9A-Fa-f]{12}'                                # xxxxxxxxxxxx
    r')$'
)

_AGE_TOKEN = re.compile(r'^(?:\d+|N/A|n/a|\-|\d+[:\.]\d+(?::\d+)?)$')

def _cisco_normalize_mac(mac: str) -> Dict[str, str]:
    """Return normalized MAC variants for downstream filters/joins."""
    mac_raw = (mac or '').strip()
    condensed = re.sub(r'[^0-9A-Fa-f]', '', mac_raw).lower()
    dotted = mac_raw.strip()
    if len(condensed) == 12:
        dotted = f"{condensed[0:4]}.{condensed[4:8]}.{condensed[8:12]}"
    return {
        'mac_address': dotted,
        'mac_address_condensed': condensed,
    }

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

def cisco_allowed_show_mac_address_table_commands(device_type) -> Dict[str, str]:
    """

    :param device_type (cisco_ios | cisco_xe | cisco_xr) etc:
    :return: allowed commands that can be sent to a device for mac address table reporting

    Device types are based off what netmiko uses to describe a device using the autodiscover process
    The list can be found here
    https://ktbyers.github.io/netmiko/PLATFORMS.html

    """

    _SHOW_VERSION_CMD_BY_DEVICE: Mapping[str, str] = {
        "cisco_ios": "show mac address-table",
        "cisco_xe":  "show mac address-table",
        "cisco_xr":  "show mac address-table",
        "cisco_nxos":  "show mac address-table",
    }

    return _SHOW_VERSION_CMD_BY_DEVICE.get(device_type)

def cisco_allowed_show_cdp_neighbor_commands(device_type) -> Dict[str, str]:
    """

    :param device_type (cisco_ios | cisco_xe | cisco_xr) etc:
    :return: allowed commands that can be sent to a device for mac address table reporting

    Device types are based off what netmiko uses to describe a device using the autodiscover process
    The list can be found here
    https://ktbyers.github.io/netmiko/PLATFORMS.html

    """

    _SHOW_VERSION_CMD_BY_DEVICE: Mapping[str, str] = {
        "cisco_ios": "show cdp neighbors",
        "cisco_xe":  "show cdp neighbors",
        "cisco_xr":  "show cdp neighbors",
        "cisco_nxos":  "show cdp neighbors",
    }

    return _SHOW_VERSION_CMD_BY_DEVICE.get(device_type)

def cisco_allowed_show_lldp_neighbor_commands(device_type) -> Dict[str, str]:
    """

    :param device_type (cisco_ios | cisco_xe | cisco_xr) etc:
    :return: allowed commands that can be sent to a device for mac address table reporting

    Device types are based off what netmiko uses to describe a device using the autodiscover process
    The list can be found here
    https://ktbyers.github.io/netmiko/PLATFORMS.html

    """

    _SHOW_VERSION_CMD_BY_DEVICE: Mapping[str, str] = {
        "cisco_ios": "show lldp neighbors",
        "cisco_xe":  "show lldp neighbors",
        "cisco_xr":  "show lldp neighbors",
        "cisco_nxos":  "show lldp neighbors",
    }

    return _SHOW_VERSION_CMD_BY_DEVICE.get(device_type)

def cisco_allowed_show_ip_arp_table_commands(device_type) -> Dict[str, str]:
    """

    :param device_type (cisco_ios | cisco_xe | cisco_xr) etc:
    :return: allowed commands that can be sent to a device for ip arp table reporting

    Device types are based off what netmiko uses to describe a device using the autodiscover process
    The list can be found here
    https://ktbyers.github.io/netmiko/PLATFORMS.html

    """

    _SHOW_VERSION_CMD_BY_DEVICE: Mapping[str, str] = {
        "cisco_ios": "show ip arp",
        "cisco_xe":  "show ip arp",
        "cisco_xr":  "show ip arp",
        "cisco_nxos":  "show ip arp",
    }

    return _SHOW_VERSION_CMD_BY_DEVICE.get(device_type)

def cisco_parse_show_version(output: str) -> Dict[str, str]:
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

def cisco_extract_interface_names(output: str) -> List[str]:
    """
    Extract all top-level Cisco interface names from a 'show interfaces description'
    dump, based on a built-in prefix_map.  Ignores sub-interfaces (those with a dot).
    """
    prefix_map = {
        'TenGigabitEthernet': 'Te',
        'GigabitEthernet':    'Gi',
        'FastEthernet':       'Fa',
        'Ethernet':           'Et',
        'Port-Channel':       'Po',
        'Vlan':               'Vl',
    }

    # build an alternation of the short prefixes: e.g. '(?:Te|Gi|Fa|Et|Po|Vl)'
    short_prefixes = list(prefix_map.values())
    prefix_pattern = '|'.join(re.escape(p) for p in short_prefixes)

    # regex: start of line + optional space + one of the prefixes + digits + any "/digits" segments
    # stops before a dot, so sub-interfaces (e.g. Te1/0/1.100) only match the base Te1/0/1
    regex = re.compile(rf'^\s*(?:{prefix_pattern})\d+(?:/\d+)*\b', re.MULTILINE)

    return regex.findall(output)

def cisco_parse_switchport(output):
    """
    Parse the output of `show interfaces <int> switchport` and return
    a dict keyed by interface name, each containing:
      - switchport_enabled
      - mode
      - access_vlan, access_vlan_name
      - native_vlan, native_vlan_name
      - voice_vlan, voice_vlan_name
      - trunk_vlans
      - pruning_vlans
      - port_type: 'access' or 'trunk'
    """
    patterns = {
        'switchport_enabled': re.compile(r'^\s*Switchport:\s*(\S+)', re.IGNORECASE),
        'mode':              re.compile(r'^\s*Administrative Mode:\s*(\S+)', re.IGNORECASE),
        'access_vlan':       re.compile(r'^\s*Access Mode VLAN:\s*(\d+)\s*\(([^)]+)\)', re.IGNORECASE),
        'native_vlan':       re.compile(r'^\s*(?:Trunking Native Mode VLAN|Native VLAN):\s*(\d+)\s*\(([^)]+)\)', re.IGNORECASE),
        'voice_vlan':        re.compile(r'^\s*Voice VLAN:\s*(\S+)\s*\(([^)]+)\)', re.IGNORECASE),
        'trunk_vlans':       re.compile(r'^\s*(?:Trunking VLANs Enabled|Allowed VLANs):\s*(.+)', re.IGNORECASE),
        'pruning_vlans':     re.compile(r'^\s*Pruning VLANs Enabled:\s*(.+)', re.IGNORECASE),
    }

    result = {}
    current_intf = None

    for line in output.splitlines():
        # 1) detect the interface line
        m = re.match(r'^\s*Name:\s*(\S+)', line, re.IGNORECASE)
        if m:
            current_intf = m.group(1)
            result[current_intf] = {}
            continue

        if not current_intf:
            continue

        # 2) once we're inside an interface section, apply each pattern
        for key, regex in patterns.items():
            m = regex.match(line)
            if not m:
                continue

            if key in ('access_vlan', 'native_vlan', 'voice_vlan'):
                vlan_id, vlan_name = m.groups()
                result[current_intf][key] = vlan_id
                result[current_intf][f"{key}_name"] = vlan_name
            else:
                result[current_intf][key] = m.group(1).strip()
            break

    # 3) determine access vs trunk for each interface
    for intf, data in result.items():
        mode = data.get('mode', '').lower()
        trunk_list = data.get('trunk_vlans', '').lower()
        # static with VLAN list → trunk, dynamic* → trunk, explicit trunk → trunk
        if (
            mode == 'trunk'
            or mode == 'static' and trunk_list and trunk_list not in ('none', 'all')
            or mode.startswith('dynamic')
        ):
            data['port_type'] = 'trunk'
        else:
            data['port_type'] = 'access'

    return result

def cisco_return_interface_description(output):
    """
    Extract and return the interface description from:
      show run interface <interface> | i description

    If no description line is present, returns an empty string.
    """
    regex = re.compile(r'^\s*description\s+(?P<description>.*)$', re.IGNORECASE)

    for line in output.splitlines():
        m = regex.match(line)
        if m:
            return m.group('description').strip()

    return ""


def cisco_ios_show_power_inline_police_C9300_24UX(output):
    """
    Parse the following output and send it back in dict form.
    123testlab-109-a4-3000#show environment power
    SW  PID                 Serial#     Status           Sys Pwr  PoE Pwr  Watts
    --  ------------------  ----------  ---------------  -------  -------  -----
    1A  PWR-C1-1100WAC-P    LIT2714AA6J  OK              Good     Good     1100
    1B  PWR-C1-1100WAC-P    ART2252P8UA  OK              Good     Good     1100

    123testlab-109-a4-3000#sh power inline police

    Module   Available     Used     Remaining
              (Watts)     (Watts)    (Watts)
    ------   ---------   --------   ---------
    1          1440.0      107.8      1332.2
    Interface Admin  Oper       Admin      Oper       Cutoff Oper
              State  State      Police     Police     Power  Power
    --------- ------ ---------- ---------- ---------- ------ -----
    Te1/0/1   auto   off        none       n/a        n/a    n/a
    Te1/0/2   auto   on         none       n/a        n/a    3.8
    Te1/0/3   auto   on         none       n/a        n/a    3.6
    Te1/0/4   auto   on         none       n/a        n/a    3.6
    Te1/0/5   auto   on         none       n/a        n/a    3.3
    Te1/0/6   auto   on         none       n/a        n/a    3.8
    Te1/0/7   auto   off        none       n/a        n/a    n/a
    Te1/0/8   auto   off        none       n/a        n/a    n/a
    Te1/0/9   auto   off        none       n/a        n/a    n/a
    Te1/0/10  auto   off        none       n/a        n/a    n/a
    Te1/0/11  auto   off        none       n/a        n/a    n/a
    Te1/0/12  auto   off        none       n/a        n/a    n/a
    Te1/0/13  auto   off        none       n/a        n/a    n/a
    Te1/0/14  auto   off        none       n/a        n/a    n/a
    Te1/0/15  auto   off        none       n/a        n/a    n/a
    Te1/0/16  auto   off        none       n/a        n/a    n/a
    Te1/0/17  auto   off        none       n/a        n/a    n/a
    Te1/0/18  auto   off        none       n/a        n/a    n/a
    Te1/0/19  auto   off        none       n/a        n/a    n/a
    Te1/0/20  auto   off        none       n/a        n/a    n/a
    Te1/0/21  auto   off        none       n/a        n/a    n/a
    Te1/0/22  auto   on         none       n/a        n/a    3.4
    Te1/0/23  auto   on         none       n/a        n/a    3.4
    Te1/0/24  auto   off        none       n/a        n/a    n/a
    --------- ------ ---------- ---------- ---------- ------ -----
    Totals:                                                  24.8


    Available POE power will change depending on the power supplies that are slotted.
    This will need to be taken into account during the power calculation.

    Adding a section in the main poller to pass in the equipped power supplies.

    Power Supply             | Available POE Power | With 350W Secondary PS | With 715W secondary PS | With 1100W Secondary PS | With 1900W Secondary PS
    PWR-C1-1900WAC-P Upgrade | 1360W               | 1440W*                 | 1440W*                 | 1440W*                  | 1440W*

    PWR-C1-1100WAC-P Default | 560W                | 910W                   | 1275W                  | 1440W*                  | 1440W*

    """

    """
    Regex to grab the information from any present modules
    Module   Available     Used     Remaining
              (Watts)     (Watts)    (Watts) 
    ------   ---------   --------   ---------
    1           595.0       46.2       548.8
    """

    regex_tLines = re.compile(
        r'(?P<module>^[0-9]+)\s+(?P<available>[0-9]+\.[0-9]+)\s+(?P<used>[0-9]+\.[0-9]+)\s+(?P<remaining>[0-9]+\.[0-9]+)')

    """
    Regex to grab the totals
    """

    regex_totals = re.compile(
        r'Totals:\s+(?P<totals>[0-9]+\.[0-9]+)')

    """
    Regex to parse the individual lines pertaining to the interfaces themselves
    """

    regex_iLines = re.compile(
        r'(?P<interface>(Gi|Te|Twe)[0-9]{1,2}/[0-9]{1,2}/[0-9]{1,2})\s+(?P<admin_state>[a-zA-Z]+)\s+(?P<operational_state>on|off)\s+(?P<admin_police>[a-zA-Z]+)\s+(?P<oper_police>n/a)\s+(?P<cutoff_power>n/a)\s+(?P<operational_power>n/a|[0-9]+\.[0-9]+)')

    """
    Regex to grab the slotted power supplies
    """

    regex_PS = re.compile(
        r'(?P<switch>^(1A|1B))\s+(?P<power_supply_model>([0-9a-zA-Z\-]+))\s+(?P<serial_number>[a-zA-Z0-9]+)\s+(?P<system_power_supply_status>[a-zA-Z0-9]+)\s+(?P<system_power_status>[a-zA-Z0-9]+)\s+(?P<system_poe_power_status>[a-zA-Z0-9]+)\s+(?P<power_supply_wattage>[0-9]+)')

    return_data = {}
    return_data['system_totals'] = {}
    return_data['system_totals']['power_supplies'] = {}
    return_data['system_totals']['modules'] = {}
    return_data['interfaces'] = {}
    ps_count = 0

    """
    Set to true initially - Once set to false, the loop will skip over these
    tests
    """

    for line in output.splitlines():

        """
        Process Totals
        """

        t = re.search(regex_tLines, line.strip())

        totals = re.search(regex_totals, line.strip())

        """
        Process Power Supplies
        """

        ps = re.search(regex_PS, line.strip())

        if ps is not None:
            return_data['system_totals']['power_supplies'][ps_count] = {
                'switch': ps.groupdict()['switch'],
                'power_supply_model': ps.groupdict()['power_supply_model'],
                'serial_number': ps.groupdict()['serial_number'],
                'system_power_supply_status': ps.groupdict()['system_power_supply_status'],
                'system_power_status': ps.groupdict()['system_power_status'],
                'system_poe_power_status': ps.groupdict()['system_poe_power_status'],
                'power_supply_wattage': ps.groupdict()['power_supply_wattage']
            }

            ps_count = ps_count + 1

        if t is not None:
            """
            Calculate the percentage of power used / power remaining
            """

            available_power_watts = float(t.groupdict()['available'].replace('(w)', ''))
            used_power_watts = float(t.groupdict()['used'].replace('(w)', ''))
            remaining_power_watts = float(t.groupdict()['remaining'].replace('(w)', ''))

            percentage_watts_used_total_system = round(((100 * used_power_watts) / available_power_watts), 2)
            percentage_watts_available_total_system = round((100 - percentage_watts_used_total_system), 2)

            return_data['system_totals']['modules'][t.groupdict()['module']] = {
                'total_system_wattage_available': available_power_watts,
                'total_system_wattage_used': used_power_watts,
                'total_system_wattage_remaining': remaining_power_watts,
                'percentage_total_system_wattage_available': percentage_watts_available_total_system,
                'percentage_total_system_wattage_used': percentage_watts_used_total_system
            }

        if totals is not None:
            return_data['system_totals']['totals'] = totals.groupdict()['totals']

        """
        Process individual interfaces
        """

        p = re.search(regex_iLines, line.strip())

        if p is not None:
            if p.groupdict()['operational_power'] == 'n/a':
                operational_power = 0
            else:
                operational_power = p.groupdict()['operational_power']

            return_data['interfaces'][p.groupdict()['interface']] = {
                'admin_state': p.groupdict()['admin_state'],
                'operational_state': p.groupdict()['operational_state'],
                'admin_police': p.groupdict()['admin_police'],
                'oper_police': p.groupdict()['oper_police'],
                'cutoff_power': p.groupdict()['cutoff_power'],
                'operational_power': operational_power
            }

    """
    Best guess POE wattage being supplied based on cisco docs
    https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-9300-series-switches/nb-06-cat9300-ser-data-sheet-cte-en.html
    """

    base_poe = 0
    total_ps_present = len(return_data['system_totals']['power_supplies'])

    count_ps = 0
    PWR_C1_1900WAC_flag = False
    PWR_C1_1100WAC_flag = False
    PWR_C1_715WAC_flag = False

    """
    Look at each PS for 1A | 1B
    Wattage will change dramatically depending on the PSU slotted

    If the primary PS is PWR-C1-1900WAC-P then the base POE power is ~1535W (This seems to differ between specs and switch output)
    If the primary PS is PWR-C1-1100WAC-P then the base POE power is ~735W
    """

    for ps in return_data['system_totals']['power_supplies']:

        """
        Don't process this if the higher PS value has already been seen as that would determine 
        a rough estimate for the base poe available
        """

        if return_data['system_totals']['power_supplies'][ps]['power_supply_model'] == 'PWR-C1-1900WAC-P' or return_data['system_totals']['power_supplies'][ps]['power_supply_model'] == 'PWR-C1-1900WAC':
            base_poe = 1360
            PWR_C1_1900WAC_flag = True
        elif PWR_C1_1900WAC_flag is not True and (return_data['system_totals']['power_supplies'][ps]['power_supply_model'] == 'PWR-C1-1100WAC-P' or return_data['system_totals']['power_supplies'][ps]['power_supply_model'] == 'PWR-C1-1100WAC'):
            base_poe = 560
            PWR_C1_1100WAC_flag = True
        elif PWR_C1_1100WAC_flag is not True and (
                return_data['system_totals']['power_supplies'][ps]['power_supply_model'] == 'PWR-C1-715WAC-P' or
                return_data['system_totals']['power_supplies'][ps]['power_supply_model'] == 'PWR-C1-715WAC'):
            base_poe = 560
            PWR_C1_715WAC_flag = True

    return_data['system_totals']['single_ps_potential_poe_available'] = base_poe

    """
    Use the above potential base_poe to calculate the threshold warnings in the event that a 
    ps is lost during an outage. 

    The issue will be if the current power usage is > 90% of the base poe
    """

    for module in return_data['system_totals']['modules']:

        percentage_wattage_used_base_poe = round((100 * return_data['system_totals']['modules'][module]['total_system_wattage_used'] / base_poe), 2)

        if percentage_wattage_used_base_poe > 90:
            single_ps_alarm_warning_set = True
        else:
            single_ps_alarm_warning_set = False
        return_data['system_totals']['modules'][module]['percentage_wattage_used_base_poe'] = percentage_wattage_used_base_poe
        return_data['system_totals']['modules'][module]['single_ps_alarm_warning_set'] = single_ps_alarm_warning_set

    """
    Generate commands the server will need to run to grab the following lines from each interface because
    cisco sucks

    123testlab-109-a4-3000#show power inline Te1/0/2 detail

    Actual consumption
    Measured at the port(watts) (Alt-A,B): 6.8
    Maximum Power drawn by the device since powered on: 7.1    
    """

    return_data['generated_commands_show_power_inline_detail'] = []
    for interface in return_data['interfaces']:
        return_data['generated_commands_show_power_inline_detail'].append(f"show power inline {interface} detail")

    return return_data

def cisco_ios_show_power_inline_police_C9300_48UXM(output):
    """
    Parse the following output and send it back in dict form.
    link-167-e208-9958#sh environment power
    SW  PID                 Serial#     Status           Sys Pwr  PoE Pwr  Watts
    --  ------------------  ----------  ---------------  -------  -------  -----
    1A  PWR-C1-1100WAC-P    DCC2435DBA2  OK              Good     Good     1100
    1B  PWR-C1-1100WAC-P    DCC2651DDEQ  OK              Good     Good     1100

    link-167-e208-9958#show power inline police

    Module   Available     Used     Remaining
              (Watts)     (Watts)    (Watts)
    ------   ---------   --------   ---------
    1          1625.0      180.6      1444.4
    Interface Admin  Oper       Admin      Oper       Cutoff Oper
              State  State      Police     Police     Power  Power
    --------- ------ ---------- ---------- ---------- ------ -----
    Tw1/0/1   auto   off        none       n/a        n/a    n/a
    Tw1/0/2   auto   off        none       n/a        n/a    n/a
    Tw1/0/3   auto   off        none       n/a        n/a    n/a
    Tw1/0/4   auto   off        none       n/a        n/a    n/a
    Tw1/0/5   auto   off        none       n/a        n/a    n/a
    Tw1/0/6   auto   off        none       n/a        n/a    n/a
    Tw1/0/7   auto   off        none       n/a        n/a    n/a
    Tw1/0/8   auto   off        none       n/a        n/a    n/a
    Tw1/0/9   auto   off        none       n/a        n/a    n/a
    Tw1/0/10  auto   off        none       n/a        n/a    n/a
    Tw1/0/11  auto   off        none       n/a        n/a    n/a
    Tw1/0/12  auto   off        none       n/a        n/a    n/a
    Tw1/0/13  auto   off        none       n/a        n/a    n/a
    Tw1/0/14  auto   off        none       n/a        n/a    n/a
    Tw1/0/15  auto   off        none       n/a        n/a    n/a
    Tw1/0/16  auto   off        none       n/a        n/a    n/a
    Tw1/0/17  auto   off        none       n/a        n/a    n/a
    Tw1/0/18  auto   off        none       n/a        n/a    n/a
    Tw1/0/19  auto   off        none       n/a        n/a    n/a
    Tw1/0/20  auto   off        none       n/a        n/a    n/a
    Tw1/0/21  auto   off        none       n/a        n/a    n/a
    Tw1/0/22  auto   off        none       n/a        n/a    n/a
    Tw1/0/23  auto   off        none       n/a        n/a    n/a
    Tw1/0/24  auto   off        none       n/a        n/a    n/a
    Tw1/0/25  auto   off        none       n/a        n/a    n/a
    Tw1/0/26  auto   off        none       n/a        n/a    n/a
    Tw1/0/27  auto   off        none       n/a        n/a    n/a
    Tw1/0/28  auto   off        none       n/a        n/a    n/a
    Tw1/0/29  auto   off        none       n/a        n/a    n/a
    Tw1/0/30  auto   off        none       n/a        n/a    n/a
    Tw1/0/31  auto   off        none       n/a        n/a    n/a
    Tw1/0/32  auto   off        none       n/a        n/a    n/a
    Tw1/0/33  auto   off        none       n/a        n/a    n/a
    Tw1/0/34  auto   off        none       n/a        n/a    n/a
    Tw1/0/35  auto   off        none       n/a        n/a    n/a
    Tw1/0/36  auto   off        none       n/a        n/a    n/a
    Te1/0/37  auto   off        none       n/a        n/a    n/a
    Te1/0/38  auto   off        none       n/a        n/a    n/a
    Te1/0/39  auto   on         none       n/a        n/a    12.5
    Te1/0/40  auto   off        none       n/a        n/a    n/a
    Te1/0/41  auto   on         none       n/a        n/a    12.8
    Te1/0/42  auto   on         none       n/a        n/a    12.6
    Te1/0/43  auto   on         none       n/a        n/a    13.7
    Te1/0/44  auto   on         none       n/a        n/a    12.4
    Te1/0/45  auto   off        none       n/a        n/a    n/a
    Te1/0/46  auto   off        none       n/a        n/a    n/a
    Te1/0/47  auto   on         none       n/a        n/a    12.7
    Te1/0/48  auto   on         none       n/a        n/a    12.7
    --------- ------ ---------- ---------- ---------- ------ -----
    Totals:                                                  89.5


    Available POE power will change depending on the power supplies that are slotted.
    This will need to be taken into account during the power calculation.

    Adding a section in the main poller to pass in the equipped power supplies.

    Power Supply             | Available POE Power | With 350W Secondary PS | With 715W secondary PS | With 1100W Secondary PS | With 1900W Secondary PS
    PWR-C1-1900WAC-P Upgrade | 1290W               | 1640W                  | 2005W                  | 2880W                   | 2880W*

    PWR-C1-1100WAC-P Default | 490W                | 840W                   | 1205W                  | 1590W                   | 2390W

    """

    """
    Regex to grab the information from any present modules
    Module   Available     Used     Remaining
              (Watts)     (Watts)    (Watts) 
    ------   ---------   --------   ---------
    1          1625.0      180.6      1444.4
    """

    regex_tLines = re.compile(
        r'(?P<module>^[0-9]+)\s+(?P<available>[0-9]+\.[0-9]+)\s+(?P<used>[0-9]+\.[0-9]+)\s+(?P<remaining>[0-9]+\.[0-9]+)')

    """
    Regex to grab the totals
    """

    regex_totals = re.compile(
        r'Totals:\s+(?P<totals>[0-9]+\.[0-9]+)')

    """
    Regex to parse the individual lines pertaining to the interfaces themselves
    """

    regex_iLines = re.compile(
        r'(?P<interface>(Gi|Te|Twe|Tw)[0-9]{1,2}/[0-9]{1,2}/[0-9]{1,2})\s+(?P<admin_state>[a-zA-Z]+)\s+(?P<operational_state>on|off)\s+(?P<admin_police>[a-zA-Z]+)\s+(?P<oper_police>n/a)\s+(?P<cutoff_power>n/a)\s+(?P<operational_power>n/a|[0-9]+\.[0-9]+)')

    """
    Regex to grab the slotted power supplies
    """

    regex_PS = re.compile(
        r'(?P<switch>^(1A|1B))\s+(?P<power_supply_model>([0-9a-zA-Z\-]+))\s+(?P<serial_number>[a-zA-Z0-9]+)\s+(?P<system_power_supply_status>[a-zA-Z0-9]+)\s+(?P<system_power_status>[a-zA-Z0-9]+)\s+(?P<system_poe_power_status>[a-zA-Z0-9]+)\s+(?P<power_supply_wattage>[0-9]+)')

    return_data = {}
    return_data['system_totals'] = {}
    return_data['system_totals']['power_supplies'] = {}
    return_data['system_totals']['modules'] = {}
    return_data['interfaces'] = {}
    ps_count = 0

    """
    Set to true initially - Once set to false, the loop will skip over these
    tests
    """

    for line in output.splitlines():

        """
        Process Totals
        """

        t = re.search(regex_tLines, line.strip())

        totals = re.search(regex_totals, line.strip())

        """
        Process Power Supplies
        """

        ps = re.search(regex_PS, line.strip())

        if ps is not None:
            return_data['system_totals']['power_supplies'][ps_count] = {
                'switch': ps.groupdict()['switch'],
                'power_supply_model': ps.groupdict()['power_supply_model'],
                'serial_number': ps.groupdict()['serial_number'],
                'system_power_supply_status': ps.groupdict()['system_power_supply_status'],
                'system_power_status': ps.groupdict()['system_power_status'],
                'system_poe_power_status': ps.groupdict()['system_poe_power_status'],
                'power_supply_wattage': ps.groupdict()['power_supply_wattage']
            }

            ps_count = ps_count + 1

        if t is not None:
            """
            Calculate the percentage of power used / power remaining
            """

            available_power_watts = float(t.groupdict()['available'].replace('(w)', ''))
            used_power_watts = float(t.groupdict()['used'].replace('(w)', ''))
            remaining_power_watts = float(t.groupdict()['remaining'].replace('(w)', ''))

            percentage_watts_used_total_system = round(((100 * used_power_watts) / available_power_watts), 2)
            percentage_watts_available_total_system = round((100 - percentage_watts_used_total_system), 2)

            return_data['system_totals']['modules'][t.groupdict()['module']] = {
                'total_system_wattage_available': available_power_watts,
                'total_system_wattage_used': used_power_watts,
                'total_system_wattage_remaining': remaining_power_watts,
                'percentage_total_system_wattage_available': percentage_watts_available_total_system,
                'percentage_total_system_wattage_used': percentage_watts_used_total_system
            }

        if totals is not None:
            return_data['system_totals']['totals'] = totals.groupdict()['totals']

        """
        Process individual interfaces
        """

        p = re.search(regex_iLines, line.strip())

        if p is not None:
            if p.groupdict()['operational_power'] == 'n/a':
                operational_power = 0
            else:
                operational_power = p.groupdict()['operational_power']

            return_data['interfaces'][p.groupdict()['interface']] = {
                'admin_state': p.groupdict()['admin_state'],
                'operational_state': p.groupdict()['operational_state'],
                'admin_police': p.groupdict()['admin_police'],
                'oper_police': p.groupdict()['oper_police'],
                'cutoff_power': p.groupdict()['cutoff_power'],
                'operational_power': operational_power
            }

    """
    Best guess POE wattage being supplied based on cisco docs
    https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-9300-series-switches/nb-06-cat9300-ser-data-sheet-cte-en.html
    """

    base_poe = 0
    total_ps_present = len(return_data['system_totals']['power_supplies'])

    count_ps = 0
    PWR_C1_1900WAC_flag = False
    PWR_C1_1100WAC_flag = False
    PWR_C1_715WAC_flag = False

    """
    Look at each PS for 1A | 1B
    Wattage will change dramatically depending on the PSU slotted

    If the primary PS is PWR-C1-1900WAC-P then the base POE power is ~1535W (This seems to differ between specs and switch output)
    If the primary PS is PWR-C1-1100WAC-P then the base POE power is ~735W
    """

    for ps in return_data['system_totals']['power_supplies']:

        """
        Don't process this if the higher PS value has already been seen as that would determine 
        a rough estimate for the base poe available
        """

        if return_data['system_totals']['power_supplies'][ps]['power_supply_model'] == 'PWR-C1-1900WAC-P' or return_data['system_totals']['power_supplies'][ps]['power_supply_model'] == 'PWR-C1-1900WAC':
            base_poe = 1290
            PWR_C1_1900WAC_flag = True
        elif PWR_C1_1900WAC_flag is not True and (
                return_data['system_totals']['power_supplies'][ps]['power_supply_model'] == 'PWR-C1-1100WAC-P' or
                return_data['system_totals']['power_supplies'][ps]['power_supply_model'] == 'PWR-C1-1100WAC'):
            base_poe = 490
            PWR_C1_1100WAC_flag = True

    return_data['system_totals']['single_ps_potential_poe_available'] = base_poe

    """
    Use the above potential base_poe to calculate the threshold warnings in the event that a 
    ps is lost during an outage. 

    The issue will be if the current power usage is > 90% of the base poe
    """

    for module in return_data['system_totals']['modules']:

        percentage_wattage_used_base_poe = round(
            (100 * return_data['system_totals']['modules'][module]['total_system_wattage_used'] / base_poe), 2)

        if percentage_wattage_used_base_poe > 90:
            single_ps_alarm_warning_set = True
        else:
            single_ps_alarm_warning_set = False
        return_data['system_totals']['modules'][module][
            'percentage_wattage_used_base_poe'] = percentage_wattage_used_base_poe
        return_data['system_totals']['modules'][module]['single_ps_alarm_warning_set'] = single_ps_alarm_warning_set

    """
    Generate commands the server will need to run to grab the following lines from each interface because
    cisco sucks


    123testlab-109-a4-3000#show power inline Te1/0/2 detail

    Actual consumption
    Measured at the port(watts) (Alt-A,B): 6.8
    Maximum Power drawn by the device since powered on: 7.1    
    """

    return_data['generated_commands_show_power_inline_detail'] = []
    for interface in return_data['interfaces']:
        return_data['generated_commands_show_power_inline_detail'].append(f"show power inline {interface} detail")

    return return_data

def cisco_ios_show_power_inline_detail_C9300_24UX(output):
    """
    Parse the following output and send it back in dict form.

    123testlab-109-a4-3000#show power inline Te1/0/2 detail
    Interface: Te1/0/2
    Inline Power Mode: auto
    Operational status (Alt-A,B): on,off
    Device Detected: yes
    Device Type: Ieee PD
    Connection Check: SS
    IEEE Class (Alt-A,B): 0
    Physical Assigned Class (Alt-A,B): 3
    Discovery mechanism used/configured: Ieee and Cisco
    Police: off

    Power Allocated
    Admin Value: 60.0
    Power drawn from the source: 15.4
    Power available to the device: 15.4
    Allocated Power (Alt-A,B): 15.4

    Actual consumption
    Measured at the port(watts) (Alt-A,B): 6.8
    Maximum Power drawn by the device since powered on: 7.1

    Absent Counter: 0
    Over Current Counter: 0
    Short Current Counter: 0
    Invalid Signature Counter: 0
    Power Denied Counter: 0

    Power Negotiation Used: None
    LLDP Power Negotiation       --Sent to PD--      --Rcvd from PD--
    Power Type:                  -                    -
    Power Source:                -                    -
    Power Priority:              -                    -
    Requested Power(W):          -                    -
    Allocated Power(W):          -                    -

    our-Pair PoE Supported: Yes
    pare Pair Power Enabled: No
    our-Pair PD Architecture: Shared

    """

    return_data = {}
    return_data['interface_detail'] = {}

    """
    Regex - Interface
    """

    regex_interface = re.compile(
        r'Interface:\s(?P<interface>(.*))')

    """
    Regex - Actual consumption measured at the port in watts
    """

    regex_ac_matp = re.compile(
        r'Measured\sat\sthe\sport.*:\s(?P<ac_matp>(.*))')

    """
    Regex - Maximum Power drawn by the device since powered on - Allocated Power
    """

    regex_pa_ap = re.compile(
        r'Maximum\sPower\sdrawn\sby\sthe\sdevice\ssince\spowered\son:\s(?P<ac_mpdspo>(.*))')

    """
    Regex - Power Allocated - Allocated Power in watts
    """

    regex_pa_apiw = re.compile(
        r'Allocated\sPower\s\(Alt-A,B\):\s(?P<pa_apiw>(.*))')



    break_main = False
    allocated_poe_power = False
    actual_consumption_matpiw = False

    for line in output.splitlines():
        i = re.search(regex_interface, line.strip())
        if i is not None:
            break_main = True
            interface = i.groupdict()['interface']
            return_data['interface_detail'][interface] = {}

            for line in output.splitlines():
                i = re.search(regex_pa_apiw, line.strip())
                if i is not None:
                    allocated_poe_power = i.groupdict()['pa_apiw']
                    break

            for line in output.splitlines():
                i = re.search(regex_ac_matp, line.strip())
                if i is not None:
                    actual_consumption_matpiw = i.groupdict()['ac_matp']
                    break

            for line in output.splitlines():
                i = re.search(regex_pa_ap, line.strip())
                if i is not None:
                    maximum_power_drawn_since_po = i.groupdict()['ac_mpdspo']
                    break

            return_data['interface_detail'][interface] = {
                'allocated_poe_power': allocated_poe_power,
                'actual_consumption_measured_at_the_port_in_watts': actual_consumption_matpiw,
                'maximum_power_drawn_since_power_on': maximum_power_drawn_since_po,
            }

        if break_main is True:
            break


    return return_data


def cisco_ios_show_power_inline_detail_C9300_48UXM(output):
    """
    Parse the following output and send it back in dict form.

    link-167-e208-9958#show power inline Te1/0/41 detail
    Interface: Te1/0/41
    Inline Power Mode: auto
    Operational status (Alt-A,B): on,off
    Device Detected: yes
    Device Type: cisco AIR-AP3802I-B
    Connection Check: SS
    IEEE Class (Alt-A,B): 4
    Physical Assigned Class (Alt-A,B): 4
    Discovery mechanism used/configured: Ieee and Cisco
    Police: off

    Power Allocated
    Admin Value: 60.0
    Power drawn from the source: 25.8
    Power available to the device: 25.8
    Allocated Power (Alt-A,B): 25.8

    Actual consumption
    Measured at the port(watts) (Alt-A,B): 12.4
    Maximum Power drawn by the device since powered on: 16.4

    Absent Counter: 0
    Over Current Counter: 0
    Short Current Counter: 0
    Invalid Signature Counter: 0
    Power Denied Counter: 0

    Power Negotiation Used: CDP
    LLDP Power Negotiation       --Sent to PD--      --Rcvd from PD--
    Power Type:                  -                    -
    Power Source:                -                    -
    Power Priority:              -                    -
    Requested Power(W):          -                    -
    Allocated Power(W):          -                    -

    Four-Pair PoE Supported: Yes
    Spare Pair Power Enabled: No
    Four-Pair PD Architecture: Shared

    """

    return_data = {}
    return_data['interface_detail'] = {}

    """
    Regex - Interface
    """

    regex_interface = re.compile(
        r'Interface:\s(?P<interface>(.*))')

    """
    Regex - Actual consumption measured at the port in watts
    """

    regex_ac_matp = re.compile(
        r'Measured\sat\sthe\sport.*:\s(?P<ac_matp>(.*))')

    """
    Regex - Maximum Power drawn by the device since powered on - Allocated Power
    """

    regex_pa_ap = re.compile(
        r'Maximum\sPower\sdrawn\sby\sthe\sdevice\ssince\spowered\son:\s(?P<ac_mpdspo>(.*))')

    """
    Regex - Power Allocated - Allocated Power in watts
    """

    regex_pa_apiw = re.compile(
        r'Allocated\sPower\s\(Alt-A,B\):\s(?P<pa_apiw>(.*))')



    break_main = False
    allocated_poe_power = False
    actual_consumption_matpiw = False

    for line in output.splitlines():
        i = re.search(regex_interface, line.strip())
        if i is not None:
            break_main = True
            interface = i.groupdict()['interface']
            return_data['interface_detail'][interface] = {}

            for line in output.splitlines():
                i = re.search(regex_pa_apiw, line.strip())
                if i is not None:
                    allocated_poe_power = i.groupdict()['pa_apiw']
                    break

            for line in output.splitlines():
                i = re.search(regex_ac_matp, line.strip())
                if i is not None:
                    actual_consumption_matpiw = i.groupdict()['ac_matp']
                    break

            for line in output.splitlines():
                i = re.search(regex_pa_ap, line.strip())
                if i is not None:
                    maximum_power_drawn_since_po = i.groupdict()['ac_mpdspo']
                    break

            return_data['interface_detail'][interface] = {
                'allocated_poe_power': allocated_poe_power,
                'actual_consumption_measured_at_the_port_in_watts': actual_consumption_matpiw,
                'maximum_power_drawn_since_power_on': maximum_power_drawn_since_po,
            }

        if break_main is True:
            break


    return return_data


def cisco_ios_show_power_inline_police_WS_C3560X_24P_L(output):
    """
    Parse the following output and send it back in dict form.
    C35|6 X
    123testlab-109-a440-10003#show power inline police
    Available:495.0(w)  Used:107.8(w)  Remaining:387.2(w)

    Interface Admin  Oper       Admin      Oper       Cutoff Oper
              State  State      Police     Police     Power  Power
    --------- ------ ---------- ---------- ---------- ------ -----
    Gi0/1     auto   off        none       n/a        n/a    n/a
    Gi0/2     auto   off        none       n/a        n/a    n/a
    Gi0/3     auto   on         none       n/a        n/a    3.3
    Gi0/4     auto   off        none       n/a        n/a    n/a
    Gi0/5     auto   on         none       n/a        n/a    4.2
    Gi0/6     auto   off        none       n/a        n/a    n/a
    Gi0/7     auto   on         none       n/a        n/a    3.5
    Gi0/8     auto   off        none       n/a        n/a    n/a
    Gi0/9     auto   on         none       n/a        n/a    3.9
    Gi0/10    auto   off        none       n/a        n/a    n/a
    Gi0/11    auto   on         none       n/a        n/a    3.3
    Gi0/12    auto   off        none       n/a        n/a    n/a
    Gi0/13    auto   off        none       n/a        n/a    n/a
    Gi0/14    auto   off        none       n/a        n/a    n/a
    Gi0/15    auto   off        none       n/a        n/a    n/a
    Gi0/16    auto   off        none       n/a        n/a    n/a
    Gi0/17    auto   off        none       n/a        n/a    n/a
    Gi0/18    auto   off        none       n/a        n/a    n/a
    Gi0/19    auto   off        none       n/a        n/a    n/a
    Gi0/20    auto   off        none       n/a        n/a    n/a
    Gi0/21    auto   off        none       n/a        n/a    n/a
    Gi0/22    auto   off        none       n/a        n/a    n/a
    Gi0/23    auto   on         none       n/a        n/a    3.2
    Gi0/24    auto   on         none       n/a        n/a    3.4
    --------- ------ ---------- ---------- ---------- ------ -----
    Totals:                                                  24.8


    https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-3560-x-series-switches/data_sheet_c78-584733.html
    WS-C3560X-24P-L 24 PoE+ (Default AC Power Supply) 715W (Available PoE Power) 435W

    """

    """
    Regex to grab the information from 
    Available:495.0(w)  Used:107.8(w)  Remaining:387.2(w)
    """

    regex_tLines = re.compile(
        r'Available:(?P<available>[0-9]+\.[0-9]+\(w\))\s+Used:(?P<used>[0-9]+\.[0-9]+\(w\))\s+Remaining:(?P<remaining>[0-9]+\.[0-9]+\(w\))')

    """
    Regex to grab the totals
    """

    regex_totals = re.compile(
        r'Totals:\s+(?P<totals>[0-9]+\.[0-9]+)')

    """
    Regex to parse the individual lines pertaining to the interfaces themselves
    """

    regex_iLines = re.compile(
        r'(?P<interface>Gi[0-9]{1,2}/[0-9]{1,2})\s+(?P<admin_state>[a-zA-Z]+)\s+(?P<operational_state>on|off)\s+(?P<admin_police>[a-zA-Z]+)\s+(?P<oper_police>n/a)\s+(?P<cutoff_power>n/a)\s+(?P<operational_power>n/a|[0-9]+\.[0-9]+)')

    return_data = {}
    return_data['system_totals'] = {}
    return_data['system_totals']['modules'] = {}
    return_data['interfaces'] = {}

    """
    Set to true initially - Once set to false, the loop will skip over these
    tests
    """

    process_t = True
    process_totals = True


    for line in output.splitlines():

        """
        Process Totals
        """
        if process_t is True:
            t = re.search(regex_tLines, line.strip())

        if process_totals is True:
            totals = re.search(regex_totals, line.strip())

        if t is not None and process_t is True:

            """
            Hard coding the module number for this device as there's only 1
            """

            """
            Calculate the percentage of power used / power remaining
            """

            available_power_watts = float(t.groupdict()['available'].replace('(w)', ''))
            used_power_watts = float(t.groupdict()['used'].replace('(w)', ''))
            remaining_power_watts = float(t.groupdict()['remaining'].replace('(w)', ''))

            percentage_watts_used_total_system = round(((100 * used_power_watts)/available_power_watts), 2)
            percentage_watts_available_total_system = round((100 - percentage_watts_used_total_system), 2)

            """
            Total poe power available for this switch model based on cisco docs
            """

            total_system_poe_watts_available = 435

            """
            Total poe power available after subtracting what's currently being drawn by devices
            """

            total_system_poe_watts_available_after_subtracting = (total_system_poe_watts_available - used_power_watts)

            return_data['system_totals']['modules'][1] = {
                'total_system_wattage_available': available_power_watts,
                'total_system_wattage_used': used_power_watts,
                'total_system_wattage_remaining': remaining_power_watts,
                'percentage_total_system_wattage_available': percentage_watts_available_total_system,
                'percentage_total_system_wattage_used': percentage_watts_used_total_system,
                'total_system_poe_wattage': total_system_poe_watts_available
            }

            process_t = False

        if totals is not None and process_totals is True:
            return_data['system_totals']['totals'] = totals.groupdict()['totals']
            return_data['system_totals']['modules'][1]['total_system_poe_wattage_available'] = (total_system_poe_watts_available - float(totals.groupdict()['totals'].replace('(w)', '')))
            process_totals = False

        """
        Process individual interfaces
        """

        p = re.search(regex_iLines, line.strip())

        if p is not None:
            if p.groupdict()['operational_power'] == 'n/a':
                operational_power = 0
            else:
                operational_power = p.groupdict()['operational_power']
            return_data['interfaces'][p.groupdict()['interface']] = {
                'admin_state': p.groupdict()['admin_state'],
                'operational_state': p.groupdict()['operational_state'],
                'admin_police': p.groupdict()['admin_police'],
                'oper_police': p.groupdict()['oper_police'],
                'cutoff_power': p.groupdict()['cutoff_power'],
                'operational_power': operational_power
            }

def cisco_asr_9k_show_run_formal_ipv4_access_list(output):
    """
    parse the following from the asrs and return a dict of the information below

    ipv4 access-list 100 10 remark FTP Inbound from something
    ipv4 access-list 100 11 permit tcp 192.30.5.0 0.0.0.127 host 10.120.8.107 eq ftp
    ipv4 access-list 100 12 permit tcp 14.18.1.0 0.0.0.127 host 10.120.8.107 eq ftp
    ipv4 access-list 100 13 permit tcp 10.7.84.192 0.0.0.15 host 10.120.8.107 eq ftp
    ipv4 access-list 100 14 permit tcp 10.6.82.80 0.0.0.15 host 10.120.8.107 eq ftp
    ipv4 access-list 100 15 permit tcp 10.6.80.74 0.0.0.1 host 10.120.8.107 eq ftp

    "ntp-server": {
        "10": "permit ipv4 host 10.120.1.72 any",
        "20": "permit ipv4 host 10.120.251.50 any",
        "30": "permit ipv4 host 10.120.251.51 any",
        "40": "deny ipv4 any any"
    }

    """

    access_list_data = {}

    """
    Regex - access list lines
    """

    regex_ipv4_access_list = re.compile(
        r'ipv4\saccess-list\s(?P<access_list_name>[0-9a-zA-Z\-_]+)\s(?P<sequence_number>[0-9]+)\s(?P<access_list_rule>.*)')

    for line in output.splitlines():
        i = re.search(regex_ipv4_access_list, line.strip())

        if i is not None:
            """
            Create the initial dict of the access-list rules
            """
            if i.groupdict()['access_list_name'] not in access_list_data:
                access_list_data[i.groupdict()['access_list_name']] = {}

            """
            Create the sequence number if it doesn't already exist
            then add the rule to it.
            """
            if i.groupdict()['sequence_number'] not in access_list_data[i.groupdict()['access_list_name']]:
                access_list_data[i.groupdict()['access_list_name']][i.groupdict()['sequence_number']] = i.groupdict()['access_list_rule']

    return access_list_data

def cisco_nexus_9xxx_parse_show_mac_address_table_count(output):
    """
    parse the following from the nexus 9k devices and return a dict of the information below

    core4-mh# show mac address-table count
    Legend:
    DLAC - Dynamic Local Address Count
    DRAC - Dynamic Remote Address Count
    SLAC - Static Local Address (User Defined) Count
    SRAC - Static Remote Address (User Defined) Count
    SAC - Secure Address Count

    MAC Entries for all VLANS:
    Dynamic Local Address Count:                                   53013
    Dynamic Remote Address Count:                                      0
    Static Remote Address (User-defined) Count:                        0
    Static Local Address (User-defined) Count:                         0
    Secure Address Count:                                              0
    Total MAC Addresses in Use (DLAC + DRAC + SLAC + SRAC + SAC):  53013

    """

    mac_address_count = {}

    """
    Regex - show mac address table count
    """

    regex_total_mac_addresses_in_use = re.compile(
        r'Total\sMAC\sAddresses\sin\sUse\s\(.*\):\s+(?P<total_mac_addresses_in_use>[0-9]+)')

    for line in output.splitlines():
        total_mac_addresses_in_use_results = re.search(regex_total_mac_addresses_in_use, line.strip())
        """
        Fetch Total mac address table count. 
        This can be modified if other lines need to be added. 
        Just modify the dictionary and return additional values.
        """
        if total_mac_addresses_in_use_results is not None:
            if total_mac_addresses_in_use_results.groupdict()['total_mac_addresses_in_use']:
                mac_address_count['total_mac_addresses_in_use'] = total_mac_addresses_in_use_results.groupdict()['total_mac_addresses_in_use']

    return mac_address_count

def cisco_C9xxx_parse_show_mac_address_table_count(output):
    """
    parse the following from cisco c9xxx devices and return a dict of the information below

    123testlab-109-a4-3000# show mac address-table count
    Mac Entries for Vlan 123:
    ---------------------------
    Dynamic Address Count  : 0
    Static  Address Count  : 1
    Total Mac Addresses    : 1

    Mac Entries for Vlan 10:
    ---------------------------
    Dynamic Address Count  : 27
    Static  Address Count  : 1
    Total Mac Addresses    : 28

    Total Dynamic Address Count  : 27
    Total Static  Address Count  : 2
    Total Mac Address In Use     : 29
    Total Mac Address Space Available: 32739

    """

    mac_address_count = {}

    """
    Regex - show mac address table count
    """

    regex_total_mac_addresses_in_use = re.compile(
        r'Total\sMac\sAddress\sIn\sUse\s+:\s(?P<total_mac_addresses_in_use>[0-9]+)')

    for line in output.splitlines():
        total_mac_addresses_in_use_results = re.search(regex_total_mac_addresses_in_use, line.strip())
        """
        Fetch Total mac address table count. 
        This can be modified if other lines need to be added. 
        Just modify the dictionary and return additional values.
        """
        if total_mac_addresses_in_use_results is not None:
            if total_mac_addresses_in_use_results.groupdict()['total_mac_addresses_in_use']:
                mac_address_count['total_mac_addresses_in_use'] = total_mac_addresses_in_use_results.groupdict()['total_mac_addresses_in_use']

    return mac_address_count

def cisco_asr_9k_parse_show_hardware_access_list_matches(output):

    """
    parse the following from the asr 9k devices and return a dict of the information below

    show access-lists <access list id> hardware ingress location 0/0/CPU0

    ipv4 access-list 123
     50 deny ipv4 10.0.0.0 0.255.255.255 any (3374541 hw matches)
     60 deny ipv4 172.16.0.0 0.15.255.255 any (775020 hw matches)
     70 deny ipv4 192.168.0.0 0.0.255.255 any (2958422 hw matches)
     ...
     ...

    """

    mac_address_count = {}

    """
    Regex - show mac address table count
    """

    regex_access_list_hw_matches = re.compile(
        r'^(?P<access_list_line>[0-9]+)\s(?P<access_list_rule>.*)\s\((?P<access_list_hw_matches>[0-9]+)\shw\s(matches|match)\)$')

    regex_access_list_none_hw_matches = re.compile(
        r'^(?P<access_list_line>[0-9]+)\s(?P<access_list_rule>.*)$')

    data = {}
    count = 0
    for line in output.splitlines():
        a = re.search(regex_access_list_hw_matches, line.strip())
        if a is not None and line.strip() != "":
            data[count] = {
                'access_list_line': a.groupdict()['access_list_line'],
                'access_list_rule': a.groupdict()['access_list_rule'],
                'access_list_hw_matches': a.groupdict()['access_list_hw_matches']
            }
            count = count + 1
        elif a is None and line.strip() != "":
            """
            Does not match the expected output with hw matches involved
            pull the rule information and 0 the matches
            """
            a = re.search(regex_access_list_none_hw_matches, line.strip())
            if a is not None:
                data[count] = {
                    'access_list_line': a.groupdict()['access_list_line'],
                    'access_list_rule': a.groupdict()['access_list_rule'],
                    'access_list_hw_matches': 0
                }
                count = count + 1

    return data

def cisco_nexus_parse_show_access_list_matches(output):
    """
    parse the following from the nexus 9k devices and return a dict of the information below

    show ip access-lists <access list id>

    IP access list 123
        statistics per-entry
        10 remark Super Cool Access List
        20 permit udp any any eq bootps [match=1361373]
        30 permit udp any any eq bootpc [match=0]
        40 permit ip any 10.8.0.0/16 [match=433189120]
        ...
        ...
        325 deny ip any any [match=29278]

    """

    mac_address_count = {}


    """
    Regex - show mac address table count
    """

    regex_access_list_hw_matches = re.compile(
        r'^(?P<access_list_line>[0-9]+)\s(?P<access_list_rule>(permit|deny)\s.*)\s\[match=(?P<access_list_hw_matches>[0-9]+)\]')

    regex_access_list_none_hw_matches = re.compile(
        r'^(?P<access_list_line>[0-9]+)\s(?P<access_list_rule>(permit|deny).*)$')

    data = {}
    count = 0
    for line in output.splitlines():
        a = re.search(regex_access_list_hw_matches, line.strip())
        if a is not None and line.strip() != "":
            data[count] = {
                'access_list_line': a.groupdict()['access_list_line'],
                'access_list_rule': a.groupdict()['access_list_rule'],
                'access_list_hw_matches': a.groupdict()['access_list_hw_matches']
            }
            count = count + 1
        elif a is None and line.strip() != "":
            """
            Does not match the expected output with hw matches involved
            pull the rule information and 0 the matches
            """
            a = re.search(regex_access_list_none_hw_matches, line.strip())
            if a is not None:
                data[count] = {
                    'access_list_line': a.groupdict()['access_list_line'],
                    'access_list_rule': a.groupdict()['access_list_rule'],
                    'access_list_hw_matches': 0
                }
                count = count + 1

    return data

def cisco_nexus_parse_show_ip_arp_matches(output):
    """
    parse the following from the nexus 9k devices and return a dict of the information below

    show ip arp

    IP ARP Table for context default
    Total number of entries: 25288
    Address         Age       MAC Address     Interface       Flags
    10.23.6.21      00:06:29  08f3.fbd6.3c3f  Vlan123
    10.23.6.22      00:00:19  INCOMPLETE      Vlan123
    ...
    10.2.8.6        00:00:25  INCOMPLETE      Ethernet1/2
    10.2.8.6        00:00:25  INCOMPLETE      Gi1/0/2
    """

    regex_show_ip_arp_matches = re.compile(
        r'^(?P<ipv4_address>([0-9]{1,3}\.){3}[0-9]{1,3})\s+(?P<age>(-|(([0-9]{1,2}:){2}[0-9]{1,2})))\s+(?P<mac_address>(INCOMPLETE|([a-fA-F0-9]{4}\.){2}[a-fA-F0-9]{4}))\s+(?P<interface>[a-zA-Z0-9\/]+)(\s+([a-zA-Z\*\+#]+)$|$)')

    data = {}
    count = 0
    for line in output.splitlines():
        a = re.search(regex_show_ip_arp_matches, line.strip())
        if a is not None and line.strip() != "":
            data[count] = {
                'ipv4_address': a.groupdict()['ipv4_address'],
                'age': a.groupdict()['age'],
                'mac_address': a.groupdict()['mac_address'],
                'mac_address_condensed': a.groupdict()['mac_address'].replace(".", ""),
                'interface': a.groupdict()['interface']
            }
            count = count + 1


    return data


def cisco_parse_show_capabilities(output: str) -> Dict[str, Dict]:
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

def cisco_parse_show_mac_address_table(
    output: str,
    device_type: Optional[str] = None,
    *,
    include_broadcast: bool = False,
    return_envelope: bool = False,
) -> Dict:
    """
    Parse Cisco MAC forwarding table output.

    Supported formats:
      - IOS / IOS-XE: `show mac address-table`
        Vlan  Mac Address       Type     Ports
      - NX-OS: `show mac address-table`
        VLAN  MAC Address       Type  age  Secure  NTF  Ports

    For IOS-XR: this is **best-effort**. XR commonly uses L2VPN/bridge-domain
    specific commands rather than `show mac address-table`. If you feed this
    function XR L2 forwarding output, you may need to add one more pattern
    once you have a sample.

    Returns:
      - default: dict[int, dict] (backwards compatible with existing parsers)
      - if return_envelope=True: {'rows': <dict[int,dict]>, 'meta': {...}, 'error': <str|None>}
    """
    raw = '' if output is None else str(output)
    lines = raw.splitlines()

    # quick negative signal; keep backwards compatibility by defaulting to empty dict
    error_markers = (
        'Invalid input detected',
        '% Invalid input',
        'Incomplete command',
        'Ambiguous command',
        'Unknown command',
    )
    parse_error = None
    if any(m in raw for m in error_markers):
        parse_error = 'command_not_supported_or_invalid'

    rows: Dict[int, Dict[str, Any]] = {}
    count = 0
    detected_style = None

    for line in lines:
        ln = (line or '').strip()
        if not ln:
            continue

        lnl = ln.lower()
        # headers / separators
        if (
            'mac address table' in lnl
            or lnl.startswith(('vlan', 'vlan,', '----', 'legend', 'mac entries', 'dynamic', 'static', 'total '))
        ):
            continue

        # NX-OS sometimes prefixes with "*"
        if ln.startswith('*'):
            ln = ln.lstrip('*').strip()

        parts = ln.split()
        if len(parts) < 4:
            continue

        # Find the MAC token (some outputs can have extra leading flags)
        mac_idx = None
        for i, tok in enumerate(parts):
            if _MAC_TOKEN.match(tok):
                mac_idx = i
                break
        if mac_idx is None:
            continue

        # Typical IOS/NX-OS layouts put VLAN immediately before the MAC
        if mac_idx < 1:
            # best-effort XR / odd outputs (MAC starts the line)
            if device_type and device_type.lower().startswith('cisco_xr') and len(parts) >= 3:
                mac_raw = parts[0]
                mac_norm = _cisco_normalize_mac(mac_raw)
                # heuristic: last token is interface, middle token is type, vlan unknown
                rows[count] = {
                    'vlan_id': '',
                    **mac_norm,
                    'type': parts[1],
                    'interface': parts[-1],
                    'age': '',
                    'raw': ln,
                    'source_os': device_type or '',
                }
                count += 1
            continue

        vlan = parts[0]
        mac_raw = parts[mac_idx]
        type_tok = parts[mac_idx + 1] if (mac_idx + 1) < len(parts) else ''
        remainder = parts[mac_idx + 2:] if (mac_idx + 2) < len(parts) else []

        # Normalize MAC and filter broadcast
        mac_norm = _cisco_normalize_mac(mac_raw)
        if not include_broadcast and mac_norm['mac_address_condensed'] == 'ffffffffffff':
            continue

        row: Dict[str, Any] = {
            'vlan_id': vlan,
            **mac_norm,
            'type': type_tok,
            'interface': '',
            'age': '',
            'raw': ln,
            'source_os': device_type or '',
        }

        if remainder:
            if (
                (device_type or '').lower() in ('cisco_nxos', 'nxos')
                or 'legend:' in lnl
                or 'secure' in raw.lower()
            ):
                # try 7-column NX-OS: age secure ntf ports...
                if len(remainder) >= 4 and _AGE_TOKEN.match(remainder[0]):
                    row['age'] = remainder[0]
                    row['secure'] = remainder[1]
                    row['ntf'] = remainder[2]
                    row['interface'] = ' '.join(remainder[3:]).strip()
                    detected_style = detected_style or 'nxos'
                # try shorter NX-OS: age ports...
                elif len(remainder) >= 2 and _AGE_TOKEN.match(remainder[0]):
                    row['age'] = remainder[0]
                    row['interface'] = ' '.join(remainder[1:]).strip()
                    detected_style = detected_style or 'nxos'
                else:
                    row['interface'] = ' '.join(remainder).strip()
            else:
                row['interface'] = ' '.join(remainder).strip()

        # common convenience: split multi-ports into a list
        if row['interface']:
            toks = []
            for chunk in row['interface'].split(','):
                toks.extend([t for t in chunk.strip().split() if t])
            row['interfaces'] = toks

        rows[count] = row
        count += 1
        detected_style = detected_style or 'ios'

    if return_envelope:
        return {'rows': rows, 'meta': {'detected_style': detected_style, 'device_type': device_type}, 'error': parse_error}

    # backwards compatible return (existing code expects dict[int] for success, {} for failure)
    return rows if rows else ({'error': parse_error} if parse_error else {})

def cisco_parse_show_ip_arp_table(
    output: str,
    device_type: Optional[str] = None,
    *,
    include_incomplete: bool = True,
    return_envelope: bool = False,
) -> Dict:
    """Parse Cisco ARP table output (IOS/IOS-XE/NX-OS best-effort).

    Supported formats (best-effort):
      - IOS / IOS-XE: `show ip arp`
        Protocol  Address  Age (min)  Hardware Addr  Type  Interface
        Internet  10.0.0.1        3    18e8.29bf.0a34 ARPA  Vlan10

      - NX-OS: `show ip arp`
        Address  Age  MAC Address  Interface  Flags
        10.23.6.21  00:06:29  08f3.fbd6.3c3f  Vlan123

    If device_type indicates XR, returns an error and you should call
    `cisco_parse_show_ip_arp_table_xr(...)`.

    Returns:
      - default: dict[int, dict]
      - if return_envelope=True: {'rows': <dict[int,dict]>, 'meta': {...}, 'error': <str|None>}
    """
    raw = '' if output is None else str(output)

    dt = (device_type or '').strip().lower()
    if dt in ('cisco_xr', 'xr', 'iosxr', 'cisco-iosxr'):
        err = 'unsupported_device_type: cisco_xr; use cisco_parse_show_ip_arp_table_xr'
        if return_envelope:
            return {'rows': {}, 'meta': {'device_type': device_type}, 'error': err}
        return {'error': err}

    error_markers = (
        'Invalid input detected',
        '% Invalid input',
        'Incomplete command',
        'Ambiguous command',
        'Unknown command',
    )
    parse_error = 'command_not_supported_or_invalid' if any(m in raw for m in error_markers) else None

    def _is_ipv4_token(tok: str) -> bool:
        t = (tok or '').strip()
        if not t or t.count('.') != 3:
            return False
        try:
            return ipaddress.ip_address(t).version == 4
        except Exception:
            return False

    def _looks_like_interface(tok: str) -> bool:
        t = (tok or '').strip()
        if not t:
            return False
        tl = t.lower()
        return (
            '/' in t
            or tl.startswith(('vlan', 'ethernet', 'port-channel', 'po', 'gi', 'te', 'fa', 'twe', 'tw', 'mgmt'))
        )

    rows: Dict[int, Dict[str, Any]] = {}
    count = 0

    detected_style = None
    if dt in ('cisco_nxos', 'nxos') or 'ip arp table for context' in raw.lower():
        detected_style = 'nxos'
    elif 'protocol' in raw.lower() and 'hardware' in raw.lower():
        detected_style = 'ios'

    for line in raw.splitlines():
        ln = (line or '').strip()
        if not ln:
            continue

        lnl = ln.lower()
        if (
            lnl.startswith(('protocol', 'address', 'ip arp table', 'total number', '----', 'flags'))
            or 'hardware addr' in lnl
            or ('mac address' in lnl and 'table' not in lnl)
        ):
            continue

        parts = ln.split()
        if len(parts) < 3:
            continue

        # Find IPv4 token
        ip_idx = None
        for i, tok in enumerate(parts):
            if _is_ipv4_token(tok):
                ip_idx = i
                break
        if ip_idx is None:
            continue

        protocol = parts[ip_idx - 1] if ip_idx >= 1 and parts[ip_idx - 1].isalpha() else ''
        ipv4 = parts[ip_idx]

        # Age token (optional)
        age = ''
        nxt = ip_idx + 1
        if nxt < len(parts) and _AGE_TOKEN.match(parts[nxt]):
            age = parts[nxt]
            nxt += 1

        # MAC token
        if nxt >= len(parts):
            continue
        mac_tok = parts[nxt]
        if not (_MAC_TOKEN.match(mac_tok) or mac_tok.upper() == 'INCOMPLETE'):
            continue
        nxt += 1

        if mac_tok.upper() == 'INCOMPLETE':
            if not include_incomplete:
                continue
            mac_norm = {'mac_address': 'INCOMPLETE', 'mac_address_condensed': ''}
        else:
            mac_norm = _cisco_normalize_mac(mac_tok)

        # Next token might be Type (ARPA) or Interface (NX-OS)
        type_tok = ''
        interface = ''
        flags = ''

        if nxt < len(parts) and not _looks_like_interface(parts[nxt]):
            type_tok = parts[nxt]
            nxt += 1

        if nxt < len(parts):
            interface = parts[nxt]
            nxt += 1

        if nxt < len(parts):
            tail = ' '.join(parts[nxt:]).strip()
            if tail:
                flags = tail

        row: Dict[str, Any] = {
            'ipv4_address': ipv4,
            'age': age,
            **mac_norm,
            'interface': interface,
            'protocol': protocol,
            'type': type_tok,
            'flags': flags,
            'raw': ln,
            'source_os': device_type or '',
        }

        if row.get('interface'):
            toks = []
            for chunk in str(row['interface']).split(','):
                toks.extend([t for t in chunk.strip().split() if t])
            row['interfaces'] = toks

        rows[count] = row
        count += 1

    if return_envelope:
        return {'rows': rows, 'meta': {'detected_style': detected_style, 'device_type': device_type}, 'error': parse_error}

    return rows if rows else ({'error': parse_error} if parse_error else {})


def cisco_parse_show_ip_arp_table_xr(
    output: str,
    *,
    include_incomplete: bool = True,
    return_envelope: bool = False,
) -> Dict:
    """Best-effort IOS-XR ARP parser (separate on purpose).

    IOS-XR ARP output varies a lot by platform/version/VRF.
    This parser:
      - finds an IPv4 token
      - finds the next MAC token (or INCOMPLETE)
      - treats the last token as interface when possible
      - stores middle tokens as state/type/flags-ish fields
    """
    raw = '' if output is None else str(output)

    error_markers = (
        'Invalid input detected',
        '% Invalid input',
        'Incomplete command',
        'Ambiguous command',
        'Unknown command',
    )
    parse_error = 'command_not_supported_or_invalid' if any(m in raw for m in error_markers) else None

    def _is_ipv4_token(tok: str) -> bool:
        t = (tok or '').strip()
        if not t or t.count('.') != 3:
            return False
        try:
            return ipaddress.ip_address(t).version == 4
        except Exception:
            return False

    rows: Dict[int, Dict[str, Any]] = {}
    count = 0

    for line in raw.splitlines():
        ln = (line or '').strip()
        if not ln:
            continue

        lnl = ln.lower()
        if ('address' in lnl and 'hardware' in lnl) or lnl.startswith(('---', '===', 'vrf', 'flags', 'protocol')):
            continue

        parts = ln.split()
        if len(parts) < 3:
            continue

        ip_idx = None
        for i, tok in enumerate(parts):
            if _is_ipv4_token(tok):
                ip_idx = i
                break
        if ip_idx is None:
            continue

        ipv4 = parts[ip_idx]
        age = parts[ip_idx + 1] if (ip_idx + 1) < len(parts) else ''

        mac_idx = None
        for j in range(ip_idx + 1, len(parts)):
            if _MAC_TOKEN.match(parts[j]) or parts[j].upper() == 'INCOMPLETE':
                mac_idx = j
                break
        if mac_idx is None:
            continue

        mac_tok = parts[mac_idx]
        if mac_tok.upper() == 'INCOMPLETE':
            if not include_incomplete:
                continue
            mac_norm = {'mac_address': 'INCOMPLETE', 'mac_address_condensed': ''}
        else:
            mac_norm = _cisco_normalize_mac(mac_tok)

        interface = parts[-1]
        middle = parts[mac_idx + 1:-1] if (mac_idx + 1) < (len(parts) - 1) else []
        state = middle[0] if len(middle) >= 1 else ''
        type_tok = middle[1] if len(middle) >= 2 else ''
        flags = ' '.join(middle[2:]).strip() if len(middle) >= 3 else ''

        rows[count] = {
            'ipv4_address': ipv4,
            'age': age,
            **mac_norm,
            'interface': interface,
            'state': state,
            'type': type_tok,
            'flags': flags,
            'raw': ln,
            'source_os': 'cisco_xr',
        }
        count += 1

    if return_envelope:
        return {'rows': rows, 'meta': {'detected_style': 'xr', 'device_type': 'cisco_xr'}, 'error': parse_error}

    return rows if rows else ({'error': parse_error} if parse_error else {})

# -----------------------------------------------------------------------------
# Neighbors: CDP + LLDP
# -----------------------------------------------------------------------------

def cisco_parse_show_cdp_neighbors(
    output: str,
    device_type: Optional[str] = None,
    *,
    return_envelope: bool = False,
) -> Dict:
    """Parse `show cdp neighbors` output (IOS / IOS-XE / NX-OS best-effort).

    Notes
    - For IOS-XR, this function returns an error and you should call
      `cisco_parse_show_cdp_neighbors_xr(...)`.
    - This parser targets the common tabular output:

        Device ID        Local Intrfce     Holdtme    Capability  Platform  Port ID

    Returns
    - default: dict[int, dict]
    - if return_envelope=True: {'rows': <dict>, 'meta': {...}, 'error': <str|None>}
    """
    raw = "" if output is None else str(output)
    dt = (device_type or "").strip().lower()

    if dt in ("cisco_xr", "xr", "iosxr", "cisco-iosxr"):
        err = "unsupported_device_type: cisco_xr; use cisco_parse_show_cdp_neighbors_xr"
        if return_envelope:
            return {"rows": {}, "meta": {"device_type": device_type}, "error": err}
        return {"error": err}

    error_markers = (
        "Invalid input detected",
        "% Invalid input",
        "Incomplete command",
        "Ambiguous command",
        "Unknown command",
    )
    parse_error = "command_not_supported_or_invalid" if any(m in raw for m in error_markers) else None

    def _capability_tokens(val: str) -> List[str]:
        s = (val or "").strip()
        if not s:
            return []
        s = s.replace(",", " ").replace("/", " ")
        toks = [t for t in s.split() if t]
        return toks

    def _build_spans(header: str) -> Optional[List[Tuple[str, int, int]]]:
        labels: List[Tuple[str, Sequence[str]]] = [
            ("device_id", ("Device ID", "Device-ID", "Device")),
            ("local_interface", ("Local Intrfce", "Local Interface", "Local Intf")),
            ("hold_time", ("Holdtme", "Holdtime", "Hold-time", "Hold Time")),
            ("capability", ("Capability", "Capabilities")),
            ("platform", ("Platform",)),
            ("port_id", ("Port ID", "PortID")),
        ]
        found: List[Tuple[str, int]] = []
        for key, variants in labels:
            pos = -1
            for v in variants:
                p = header.find(v)
                if p >= 0:
                    pos = p
                    break
            if pos >= 0:
                found.append((key, pos))

        keys = {k for k, _ in found}
        if not {"device_id", "local_interface", "hold_time", "port_id"}.issubset(keys):
            return None

        found.sort(key=lambda x: x[1])
        spans: List[Tuple[str, int, int]] = []
        for i, (key, start) in enumerate(found):
            end = found[i + 1][1] if i + 1 < len(found) else len(header)
            spans.append((key, start, end))
        return spans

    rows: Dict[int, Dict[str, Any]] = {}
    count = 0
    spans: Optional[List[Tuple[str, int, int]]] = None
    started = False
    detected_style = None

    for line in raw.splitlines():
        ln = (line or "").rstrip("\n")
        if not ln.strip():
            continue

        lnl = ln.lower().strip()

        if not started and "device id" in lnl and ("local" in lnl) and ("port" in lnl):
            spans = _build_spans(ln)
            started = True
            detected_style = "fixed_columns" if spans else "heuristic"
            continue

        if not started:
            continue

        if set(ln.strip()) <= {"-", " "}:
            continue
        if lnl.startswith(("capability codes", "capability code", "total cdp entries", "total entries")):
            continue

        if spans:
            parsed: Dict[str, str] = {}
            padded = ln + (" " * 4)
            for key, start, end in spans:
                parsed[key] = padded[start:end].strip()

            ht = parsed.get("hold_time", "").strip()
            if not ht.isdigit():
                continue

            row = {
                "device_id": parsed.get("device_id", "").strip(),
                "local_interface": parsed.get("local_interface", "").strip(),
                "hold_time": int(ht),
                "capability": parsed.get("capability", "").strip(),
                "capability_tokens": _capability_tokens(parsed.get("capability", "")),
                "platform": parsed.get("platform", "").strip(),
                "port_id": parsed.get("port_id", "").strip(),
                "raw": ln.strip(),
                "source_os": device_type or "",
            }
            rows[count] = row
            count += 1
            continue

        # heuristic fallback
        parts = ln.split()
        if len(parts) < 4:
            continue

        ht_idx = None
        for i in range(2, len(parts)):
            if parts[i].isdigit():
                ht_idx = i
                break
        if ht_idx is None:
            continue

        device_id = parts[0]
        local_interface = " ".join(parts[1:ht_idx])
        hold_time = int(parts[ht_idx])

        tail = parts[ht_idx + 1 :]
        if not tail:
            continue

        platform = tail[-2] if len(tail) >= 2 else ""
        port_id = tail[-1] if len(tail) >= 1 else ""
        capability = " ".join(tail[:-2]).strip() if len(tail) >= 2 else ""

        row = {
            "device_id": device_id,
            "local_interface": local_interface,
            "hold_time": hold_time,
            "capability": capability,
            "capability_tokens": _capability_tokens(capability),
            "platform": platform,
            "port_id": port_id,
            "raw": ln.strip(),
            "source_os": device_type or "",
        }
        rows[count] = row
        count += 1

    if return_envelope:
        return {
            "rows": rows,
            "meta": {"detected_style": detected_style, "device_type": device_type, "count": count},
            "error": parse_error,
        }

    return rows if rows else ({"error": parse_error} if parse_error else {})


def cisco_parse_show_cdp_neighbors_xr(
    output: str,
    *,
    return_envelope: bool = False,
) -> Dict:
    """Best-effort IOS-XR CDP neighbor parser.

    IOS-XR neighbor outputs can vary by platform/version.
    This function is intentionally tolerant and extracts:
      - device_id
      - local_interface (if present)
      - hold_time (if present)
      - port_id (if present)
      - platform/capability when they appear
    """
    raw = "" if output is None else str(output)

    error_markers = (
        "Invalid input detected",
        "% Invalid input",
        "Incomplete command",
        "Ambiguous command",
        "Unknown command",
    )
    parse_error = "command_not_supported_or_invalid" if any(m in raw for m in error_markers) else None

    rows: Dict[int, Dict[str, Any]] = {}
    count = 0
    started = False

    for line in raw.splitlines():
        ln = (line or "").rstrip("\n")
        if not ln.strip():
            continue

        lnl = ln.lower().strip()

        if not started and "device id" in lnl and "local" in lnl and "port" in lnl:
            started = True
            continue

        if not started:
            continue

        if set(ln.strip()) <= {"-", " "}:
            continue
        if lnl.startswith(("capability codes", "total", "entries", "capability code")):
            continue

        parts = ln.split()
        if len(parts) < 2:
            continue

        device_id = parts[0]

        ht_idx = None
        for i in range(1, len(parts)):
            if parts[i].isdigit():
                ht_idx = i
                break

        local_interface = " ".join(parts[1:ht_idx]) if ht_idx else ""
        hold_time = int(parts[ht_idx]) if ht_idx else None

        tail = parts[ht_idx + 1 :] if ht_idx is not None else []
        capability = ""
        platform = ""
        port_id = ""

        if tail:
            port_id = tail[-1]
            platform = tail[-2] if len(tail) >= 2 else ""
            capability = " ".join(tail[:-2]).strip() if len(tail) >= 2 else ""

        rows[count] = {
            "device_id": device_id,
            "local_interface": local_interface,
            "hold_time": hold_time,
            "capability": capability,
            "platform": platform,
            "port_id": port_id,
            "raw": ln.strip(),
            "source_os": "cisco_xr",
        }
        count += 1

    if return_envelope:
        return {"rows": rows, "meta": {"detected_style": "xr_heuristic", "count": count}, "error": parse_error}

    return rows if rows else ({"error": parse_error} if parse_error else {})


def cisco_parse_show_lldp_neighbors(
    output: str,
    device_type: Optional[str] = None,
    *,
    return_envelope: bool = False,
) -> Dict:
    """Parse `show lldp neighbors` output (IOS / IOS-XE / NX-OS best-effort).

    Notes
    - For IOS-XR, this function returns an error and you should call
      `cisco_parse_show_lldp_neighbors_xr(...)`.
    - Targets the common tabular output:

        Device ID           Local Intf     Hold-time  Capability      Port ID

    Returns
    - default: dict[int, dict]
    - if return_envelope=True: {'rows': <dict>, 'meta': {...}, 'error': <str|None>}
    """
    raw = "" if output is None else str(output)
    dt = (device_type or "").strip().lower()

    if dt in ("cisco_xr", "xr", "iosxr", "cisco-iosxr"):
        err = "unsupported_device_type: cisco_xr; use cisco_parse_show_lldp_neighbors_xr"
        if return_envelope:
            return {"rows": {}, "meta": {"device_type": device_type}, "error": err}
        return {"error": err}

    error_markers = (
        "Invalid input detected",
        "% Invalid input",
        "Incomplete command",
        "Ambiguous command",
        "Unknown command",
        "LLDP is not enabled",
        "lldp is not enabled",
    )
    parse_error = "command_not_supported_or_invalid" if any(m in raw for m in error_markers) else None

    def _capability_tokens(val: str) -> List[str]:
        s = (val or "").strip()
        if not s:
            return []
        s = s.replace(",", " ").replace("/", " ")
        toks = [t for t in s.split() if t]
        return toks

    def _build_spans(header: str) -> Optional[List[Tuple[str, int, int]]]:
        labels: List[Tuple[str, Sequence[str]]] = [
            ("device_id", ("Device ID", "System Name", "Chassis ID", "Device")),
            ("local_interface", ("Local Intf", "Local Interface", "Local Port", "Local Intrfce")),
            ("hold_time", ("Hold-time", "Hold Time", "Holdtime", "Holdtme")),
            ("capability", ("Capability", "Capabilities")),
            ("port_id", ("Port ID", "PortID", "Port Description", "Port Descr")),
        ]
        found: List[Tuple[str, int]] = []
        for key, variants in labels:
            pos = -1
            for v in variants:
                p = header.find(v)
                if p >= 0:
                    pos = p
                    break
            if pos >= 0:
                found.append((key, pos))

        keys = {k for k, _ in found}
        if not {"device_id", "local_interface", "hold_time", "port_id"}.issubset(keys):
            return None

        found.sort(key=lambda x: x[1])
        spans: List[Tuple[str, int, int]] = []
        for i, (key, start) in enumerate(found):
            end = found[i + 1][1] if i + 1 < len(found) else len(header)
            spans.append((key, start, end))
        return spans

    rows: Dict[int, Dict[str, Any]] = {}
    count = 0
    spans: Optional[List[Tuple[str, int, int]]] = None
    started = False
    detected_style = None

    for line in raw.splitlines():
        ln = (line or "").rstrip("\n")
        if not ln.strip():
            continue

        lnl = ln.lower().strip()

        if not started and ("device id" in lnl or "system name" in lnl) and ("local" in lnl) and ("port" in lnl):
            spans = _build_spans(ln)
            started = True
            detected_style = "fixed_columns" if spans else "heuristic"
            continue

        if not started:
            continue

        if set(ln.strip()) <= {"-", " "}:
            continue
        if lnl.startswith(("capability codes", "capability code", "total lldp entries", "total entries", "lldp neighbors")):
            continue

        if spans:
            parsed: Dict[str, str] = {}
            padded = ln + (" " * 4)
            for key, start, end in spans:
                parsed[key] = padded[start:end].strip()

            ht = parsed.get("hold_time", "").strip()
            if not ht.isdigit():
                continue

            cap = parsed.get("capability", "").strip()
            row = {
                "device_id": parsed.get("device_id", "").strip(),
                "local_interface": parsed.get("local_interface", "").strip(),
                "hold_time": int(ht),
                "capability": cap,
                "capability_tokens": _capability_tokens(cap),
                "port_id": parsed.get("port_id", "").strip(),
                "raw": ln.strip(),
                "source_os": device_type or "",
            }
            rows[count] = row
            count += 1
            continue

        parts = ln.split()
        if len(parts) < 4:
            continue

        ht_idx = None
        for i in range(2, len(parts)):
            if parts[i].isdigit():
                ht_idx = i
                break
        if ht_idx is None:
            continue

        device_id = parts[0]
        local_interface = " ".join(parts[1:ht_idx])
        hold_time = int(parts[ht_idx])

        tail = parts[ht_idx + 1 :]
        if not tail:
            continue

        port_id = tail[-1]
        capability = " ".join(tail[:-1]).strip()

        row = {
            "device_id": device_id,
            "local_interface": local_interface,
            "hold_time": hold_time,
            "capability": capability,
            "capability_tokens": _capability_tokens(capability),
            "port_id": port_id,
            "raw": ln.strip(),
            "source_os": device_type or "",
        }
        rows[count] = row
        count += 1

    if return_envelope:
        return {
            "rows": rows,
            "meta": {"detected_style": detected_style, "device_type": device_type, "count": count},
            "error": parse_error,
        }

    return rows if rows else ({"error": parse_error} if parse_error else {})


def cisco_parse_show_lldp_neighbors_xr(
    output: str,
    *,
    return_envelope: bool = False,
) -> Dict:
    """Best-effort IOS-XR LLDP neighbor parser.

    IOS-XR LLDP output varies. This parser looks for a common neighbor table:
      - device id / chassis id
      - local interface
      - hold-time
      - port id / port description

    """
    raw = "" if output is None else str(output)

    error_markers = (
        "Invalid input detected",
        "% Invalid input",
        "Incomplete command",
        "Ambiguous command",
        "Unknown command",
        "LLDP is not enabled",
        "lldp is not enabled",
    )
    parse_error = "command_not_supported_or_invalid" if any(m in raw for m in error_markers) else None

    rows: Dict[int, Dict[str, Any]] = {}
    count = 0
    started = False
    spans: Optional[List[Tuple[str, int, int]]] = None

    def _build_spans(header: str) -> Optional[List[Tuple[str, int, int]]]:
        labels: List[Tuple[str, Sequence[str]]] = [
            ("device_id", ("Device ID", "Chassis ID", "System Name", "Neighbor")),
            ("local_interface", ("Local Intf", "Local Interface", "Local Port")),
            ("hold_time", ("Hold-time", "Hold Time", "Holdtime", "Holdtme")),
            ("port_id", ("Port ID", "Port Description", "PortID")),
        ]
        found: List[Tuple[str, int]] = []
        for key, variants in labels:
            pos = -1
            for v in variants:
                p = header.find(v)
                if p >= 0:
                    pos = p
                    break
            if pos >= 0:
                found.append((key, pos))
        keys = {k for k, _ in found}
        if not {"device_id", "local_interface", "hold_time", "port_id"}.issubset(keys):
            return None
        found.sort(key=lambda x: x[1])
        spans: List[Tuple[str, int, int]] = []
        for i, (key, start) in enumerate(found):
            end = found[i + 1][1] if i + 1 < len(found) else len(header)
            spans.append((key, start, end))
        return spans

    for line in raw.splitlines():
        ln = (line or "").rstrip("\n")
        if not ln.strip():
            continue
        lnl = ln.lower().strip()

        if not started and ("device id" in lnl or "chassis id" in lnl or "system name" in lnl) and ("local" in lnl) and ("port" in lnl):
            spans = _build_spans(ln)
            started = True
            continue

        if not started:
            continue

        if set(ln.strip()) <= {"-", " "}:
            continue
        if lnl.startswith(("capability", "total", "entries", "lldp")):
            continue

        if spans:
            parsed: Dict[str, str] = {}
            padded = ln + (" " * 4)
            for key, start, end in spans:
                parsed[key] = padded[start:end].strip()
            ht = parsed.get("hold_time", "").strip()
            if not ht.isdigit():
                continue
            rows[count] = {
                "device_id": parsed.get("device_id", "").strip(),
                "local_interface": parsed.get("local_interface", "").strip(),
                "hold_time": int(ht),
                "port_id": parsed.get("port_id", "").strip(),
                "raw": ln.strip(),
                "source_os": "cisco_xr",
            }
            count += 1
            continue

        parts = ln.split()
        if len(parts) < 4:
            continue
        ht_idx = None
        for i in range(1, len(parts)):
            if parts[i].isdigit():
                ht_idx = i
                break
        if ht_idx is None:
            continue
        device_id = parts[0]
        local_interface = " ".join(parts[1:ht_idx])
        hold_time = int(parts[ht_idx])
        port_id = " ".join(parts[ht_idx + 1 :]).strip()
        rows[count] = {
            "device_id": device_id,
            "local_interface": local_interface,
            "hold_time": hold_time,
            "port_id": port_id,
            "raw": ln.strip(),
            "source_os": "cisco_xr",
        }
        count += 1

    if return_envelope:
        return {
            "rows": rows,
            "meta": {"detected_style": "xr_fixed_columns" if spans else "xr_heuristic", "count": count},
            "error": parse_error,
        }

    return rows if rows else ({"error": parse_error} if parse_error else {})
