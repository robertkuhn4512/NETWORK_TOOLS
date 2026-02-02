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

def cisco_c9xxx_parse_show_ip_arp_matches(output):
    """
    parse the following from the nexus 9k devices and return a dict of the information below

    show ip arp

    123testlab-109-a4-3000#sh ip arp
    Protocol  Address          Age (min)  Hardware Addr   Type   Interface
    Internet  10.0.0.1                3   18e8.29bf.0a34  ARPA   Vlan10
    Internet  10.0.0.10               0   e063.da30.fb4a  ARPA   Vlan10
    Internet  10.0.0.11               0   7483.c202.c627  ARPA   Vlan10
    Internet  10.0.0.51               0   1498.775b.71e3  ARPA   Vlan10
    Internet  10.0.0.98               2   9c8e.cd21.b298  ARPA   Vlan10
    Internet  10.0.0.99               0   9c8e.cd2d.0c35  ARPA   Vlan10
    Internet  10.0.0.101              -   0c75.bd90.f746  ARPA   Vlan10
    Internet  10.0.0.105             39   b4b6.768d.d943  ARPA   Vlan10
    Internet  10.0.0.106              0   e063.da3c.c279  ARPA   Vlan10
    Internet  10.0.0.107              1   603e.5f4d.f1f6  ARPA   Vlan10
    Internet  10.0.0.123            158   00e4.21c0.bd5f  ARPA   Vlan10
    Internet  10.0.0.125             75   18cc.18dd.1eea  ARPA   Vlan10
    Internet  10.0.0.138              0   000c.2920.ebc4  ARPA   Vlan10
    Internet  10.0.0.141            128   9ebe.4405.1b31  ARPA   Vlan10
    Internet  10.0.0.142              1   8e2e.8ad5.75ec  ARPA   Vlan10
    Internet  10.0.0.143              8   b827.eb87.278d  ARPA   Vlan10
    Internet  10.0.0.151              0   9c8e.cd2b.bb6a  ARPA   Vlan10
    Internet  10.0.0.152              0   9c8e.cd2b.bb87  ARPA   Vlan10
    Internet  10.0.0.153              0   9c8e.cd2b.bb80  ARPA   Vlan10
    Internet  10.0.0.154              0   9c8e.cd2b.bb83  ARPA   Vlan10
    Internet  10.0.0.155              0   4c11.bff5.0360  ARPA   Vlan10
    Internet  10.0.0.156              0   9c8e.cd19.407a  ARPA   Vlan10
    Internet  10.0.0.161              0   62ff.846b.8b0c  ARPA   Vlan10
    Internet  10.0.0.190              0   2eec.c48b.acaf  ARPA   Vlan10
    Internet  10.0.0.203             48   dccd.2f41.3b28  ARPA   Vlan10
    Internet  10.32.0.2               -   0c75.bd90.f75d  ARPA   Vlan440
    """

    regex_show_ip_arp_matches = re.compile(
        r'^(?P<protocol>[a-zA-Z0-9]+)\s+(?P<ipv4_address>([0-9]{1,3}\.){3}[0-9]{1,3})\s+(?P<age>([0-9:\.-]+|N\/A))\s+(?P<mac_address>([0-9a-fA-F]{4}\.){2}[0-9a-fA-F]{4}|INCOMPLETE)\s+(?P<type>[a-zA-Z0-9]+)\s+(?P<interface>([a-zA-Z0-9,\s\-\/]+))$')



    data = {}
    count = 0
    for line in output.splitlines():
        a = re.search(regex_show_ip_arp_matches, line.strip())
        if a is not None and line.strip() != "":
            data[count] = {
                'ipv4_address': a.groupdict()['ipv4_address'],
                'age': a.groupdict()['age'],
                'mac_address': a.groupdict()['mac_address'],
                'mac_address_condensed': re.sub('(\.|:)', '', a.groupdict()['mac_address']),
                'interface': a.groupdict()['interface']
            }
            count = count + 1


    return data

def cisco_3xxx_parse_show_mac_address_table(output):
    """
    parse the following from the c9xxx devices and return a dict of the information below

    show mac address_table

    123testlab-109-a4-3000#sh mac address-table
                            Mac Address Table
                        -------------------------------------------

                        Vlan    Mac Address       Type        Ports
                        ----    -----------       --------    -----
                         All    0100.0ccc.cccc    STATIC      CPU
                         All    0100.0ccc.cccd    STATIC      CPU
                         All    0180.c200.0000    STATIC      CPU
                         All    0180.c200.0001    STATIC      CPU
                         All    0180.c200.0002    STATIC      CPU
                         All    0180.c200.0003    STATIC      CPU
                         All    0180.c200.0004    STATIC      CPU
                         All    0180.c200.0005    STATIC      CPU
                         All    0180.c200.0006    STATIC      CPU
                         All    0180.c200.0007    STATIC      CPU
                         All    0180.c200.0008    STATIC      CPU
                         All    0180.c200.0009    STATIC      CPU
                         All    0180.c200.000a    STATIC      CPU
                         All    0180.c200.000b    STATIC      CPU
                         All    0180.c200.000c    STATIC      CPU
                         All    0180.c200.000d    STATIC      CPU
                         All    0180.c200.000e    STATIC      CPU
                         All    0180.c200.000f    STATIC      CPU
                         All    0180.c200.0010    STATIC      CPU
                         All    0180.c200.0021    STATIC      CPU
                         All    ffff.ffff.ffff    STATIC      CPU
                          10    000c.2920.ebc4    DYNAMIC     Te1/0/15
                          10    00c0.b7d8.afb0    DYNAMIC     Te1/0/13
                          10    00c0.b7d8.afb1    DYNAMIC     Te1/0/14
                          10    00e4.21c0.bd5f    DYNAMIC     Te1/0/22
                          10    0c75.bd90.f746    STATIC      Vl10
                          10    1498.775b.71e3    DYNAMIC     Te1/0/15
                          10    18cc.18dd.1eea    DYNAMIC     Te1/0/23
                          10    18e8.29bf.0a34    DYNAMIC     Te1/0/24
                          10    2eec.c48b.acaf    DYNAMIC     Te1/0/22
                          10    4c11.bff5.0360    DYNAMIC     Te1/0/22
                          10    603e.5f4d.f1f6    DYNAMIC     Te1/0/23
    """

    regex_show_mac_address = re.compile(
        r'^(?P<vlan_id>(All|[0-9]+))\s+(?P<mac_address>(INCOMPLETE|STATIC|DYNAMIC|([a-fA-F0-9]{4}\.){2}[a-fA-F0-9]{4}))\s+(?P<type>[a-zA-Z0-9]+)\s+(?P<interface>[a-zA-Z0-9\/]+)$')

    data = {}
    count = 0
    for line in output.splitlines():
        a = re.search(regex_show_mac_address, line.strip())
        if a is not None and line.strip() != "":
            if a.groupdict()['mac_address'] != 'ffffffffffff':
                data[count] = {
                    'vlan_id': a.groupdict()['vlan_id'],
                    'mac_address': a.groupdict()['mac_address'],
                    'type': a.groupdict()['type'],
                    'interface': a.groupdict()['interface'],
                    'age': ''
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