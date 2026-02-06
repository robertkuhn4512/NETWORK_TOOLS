from __future__ import annotations

import json
import ipaddress
import re
# Generic helpers that can be used anywhere that I do not want living in multiple files.
if __name__=='__main__':
    # I am running this locally to test some functions, This lets me call it
    # from where i'm running it. The else statement is required to run in the container
    from helpers_generic import (
        _as_str,
        _as_int,
        _uptime_to_seconds,
        _parse_dt_best_effort,
        _ensure_list,
        _nxos_duration_to_seconds,
        _json_load_dict_best_effort,
        _escape_controls_inside_json_strings
    )
else:
    from app.shared_functions.helpers.helpers_generic import (
        _as_str,
        _as_int,
        _uptime_to_seconds,
        _parse_dt_best_effort,
        _ensure_list,
        _nxos_duration_to_seconds,
        _json_load_dict_best_effort,
        _escape_controls_inside_json_strings
    )
from pathlib import Path
from typing import Any, Dict, Optional, List, Tuple, Sequence, Union


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

_MAC_COLON_RX = re.compile(r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
_MAC_DOT_RX = re.compile(r"^(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}$")
_MAC_PLAIN_RX = re.compile(r"^[0-9A-Fa-f]{12}$")

# Main function in regards to allowed commands that can be sent to devices for processing

# This is a profile dict that's used to tell the program what it can run, how to run it etc.
# Based on the netmiko device types when a device is auto discovered.
def cisco_allowed_commands(device_type) -> Dict[str, str]:
    """

        :param device_type (cisco_ios | cisco_xe | cisco_xr) etc:
        :return: allowed commands that can be sent to a device for discovery / backup / etc purposes

        Device types are based off what netmiko uses to describe a device using the autodiscover process
        The list can be found here
        https://ktbyers.github.io/netmiko/PLATFORMS.html


        To add more device profiles, follow the following layout

        "device_type": {
            "the_command_name_you_want_to_use": "The correct associated command to run for this command - Examples below",
            "show_interface_description_output_type": "cli",  # json | cli | xml (WIP) - Change the parsing type depending on this flag
            "show_cdp_neighbors": "show cdp neighbors", -> Currently commands like these have dedicated functions to process them. If you add a new one
            "show_cdp_neighbors_output_type": "cli",       you will need to make sure there's a function built to process them. Feel free if you want, and submit a PR
            "show_lldp_neighbors": "show lldp neighbors",  if you think it's useful and would like to add it to the main repo.
            "show_lldp_neighbors_output_type": "cli",
            "show_ip_arp_table": "show ip arp",
            "show_ip_arp_table_output_type": "cli",
            "show_mac_address_table": "show mac address-table",
            "show_mac_address_table_output_type": "cli",
            "show_version": "show version",
            "show_version_output_type": "cli",
            "os_name_by_device": "ios",
            "show_mac_address_table": "show mac address-table",
            "allowed_backup_commands": [ -> Allowed backup commands should be a list of commands you want to run on a backup job.
                "show version",
                "show interface description",
                "show interfaces status",
                "show running-config",
                "show mac address-table count",
            ]
        }

        """

    _SHOW_CMD_BY_DEVICE: Mapping[str, str] = {
        "cisco_ios": {
            "show_interface_description": "show interface description",
            "show_interface_description_output_type": "cli",  # json | cli - Change the parsing type depending on this flag
            "show_cdp_neighbors": "show cdp neighbors",
            "show_cdp_neighbors_output_type": "cli",  # json | cli - Change the parsing type depending on this flag
            "show_lldp_neighbors": "show lldp neighbors",
            "show_lldp_neighbors_output_type": "cli",  # json | cli - Change the parsing type depending on this flag
            "show_ip_arp_table": "show ip arp",
            "show_ip_arp_table_output_type": "cli",  # json | cli - Change the parsing type depending on this flag
            "show_mac_address_table": "show mac address-table",
            "show_mac_address_table_output_type": "cli",
            "show_mac_address_table_count": "show mac address-table count",
            "show_mac_address_table_count_output_type": "cli",
            "show_version": "show version",
            "show_version_output_type": "cli",  # json | cli - Change the parsing type depending on this flag
            "os_name_by_device": "ios",
            "show_mac_address_table": "show mac address-table",
            "allowed_backup_commands": [
                "show version",
                "show interface description",
                "show interfaces status",
                "show running-config",
                "show mac address-table count",
            ]
        },
        "cisco_xe": {
            "show_interface_description": "show interface description",
            "show_interface_description_output_type": "cli",  # json | cli - Change the parsing type depending on this flag
            "show_cdp_neighbors": "show cdp neighbors",
            "show_cdp_neighbors_output_type": "cli",  # json | cli - Change the parsing type depending on this flag
            "show_lldp_neighbors": "show lldp neighbors",
            "show_lldp_neighbors_output_type": "cli",  # json | cli - Change the parsing type depending on this flag
            "show_ip_arp_table": "show ip arp",
            "show_ip_arp_table_output_type": "cli",  # json | cli - Change the parsing type depending on this flag
            "show_mac_address_table": "show mac address-table",
            "show_mac_address_table_output_type": "cli",
            "show_mac_address_table_count": "show mac address-table count",
            "show_mac_address_table_count_output_type": "cli",
            "show_version": "show version",
            "show_version_output_type": "cli",  # json | cli - Change the parsing type depending on this flag
            "os_name_by_device": "iosxe",
            "allowed_backup_commands": [
                "show version",
                "show interface description",
                "show interfaces status",
                "show running-config",
                "show mac address-table count",
            ]
        },
        "cisco_xr": {
            "show_interface_description": "show interface description",
            "show_interface_description_output_type": "cli",  # json | cli - Change the parsing type depending on this flag
            "show_cdp_neighbors": "show cdp neighbors",
            "show_cdp_neighbors_output_type": "cli",  # json | cli - Change the parsing type depending on this flag
            "show_lldp_neighbors": "show lldp neighbors",
            "show_lldp_neighbors_output_type": "cli",  # json | cli - Change the parsing type depending on this flag
            "show_ip_arp_table": "show arp",
            "show_ip_arp_table_output_type": "cli",  # json | cli - Change the parsing type depending on this flag
            "show_mac_address_table": None,
            "show_mac_address_table_output_type": None,
            "show_mac_address_table_count": None,
            "show_mac_address_table_count_output_type": None,
            "show_version": "show version",
            "show_version_output_type": "cli",  # json | cli - Change the parsing type depending on this flag
            "os_name_by_device": "iosxr",
            "allowed_backup_commands": [
                "show version",
                "show interface description",
                "show interfaces brief",
                "show running-config",
                "show mac address-table count",
            ]
        },
        "cisco_nxos": {
            "show_interface_description": "show interface description | json-pretty",
            "show_interface_description_output_type": "json",  # json | cli - Change the parsing type depending on this flag
            "show_cdp_neighbors": "show cdp neighbors | json-pretty",
            "show_cdp_neighbors_output_type": "json",  # json | cli - Change the parsing type depending on this flag
            "show_lldp_neighbors": "show lldp neighbors | json-pretty",
            "show_lldp_neighbors_output_type": "json",  # json | cli - Change the parsing type depending on this flag
            "show_ip_arp_table": "show ip arp | json-pretty",
            "show_ip_arp_table_output_type": "json",  # json | cli - Change the parsing type depending on this flag
            "show_mac_address_table": "show mac address-table | json-pretty",
            "show_mac_address_table_output_type": "json",
            "show_mac_address_table_count": "show mac address-table count | json-pretty",
            "show_mac_address_table_count_output_type": "json",
            "show_version": "show version | json-pretty",
            "show_version_output_type": "json",  # json | cli - Change the parsing type depending on this flag
            "os_name_by_device": "nxos",
            "allowed_backup_commands": [
                "show version",
                "show inventory",
                "show interface description",
                "show interface status",
                "show running-config",
                # "show startup-config",
                "show mac address-table count",
            ]
        },
        "cisco_asa": {
            "show_interface_description": "show interface description",
            "show_interface_description_output_type": "cli",  # json | cli - Change the parsing type depending on this flag
            "show_cdp_neighbors": "show cdp neighbors",
            "show_cdp_neighbors_output_type": "cli",  # json | cli - Change the parsing type depending on this flag
            "show_lldp_neighbors": "show lldp neighbors",
            "show_lldp_neighbors_output_type": "cli",  # json | cli - Change the parsing type depending on this flag
            "show_ip_arp_table": "show arp",
            "show_ip_arp_table_output_type": "cli",  # json | cli - Change the parsing type depending on this flag
            "show_mac_address_table": None,  # TODO Need to research this. I believe it's show arp for routed mode
            "show_mac_address_table_output_type": None,
            "show_mac_address_table_count": None,
            "show_mac_address_table_count_output_type": None,
            "show_version": "show version",
            "show_version_output_type": "cli",  # json | cli - Change the parsing type depending on this flag
            "os_name_by_device": "asa",
            "allowed_backup_commands": [
                "show version",
                "show inventory",
                "show interface description",
                "show interfaces status",
                "show running-config"
            ]
        },
    }

    return _SHOW_CMD_BY_DEVICE.get(device_type)


# Basic Helper Functions for cisco use only
# Any other basic helpers should be located in the helpers_generic.py file

# TODO - Transfer over functionality that uses this to generate port profile maps for cisco switches
# To be used in device templating / device conversions etc.

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

    _IF_PREFIX_RX = re.compile(r"^[A-Za-z]{1,6}$")
    _IF_NUM_RX = re.compile(r"^\d+(?:/\d+)+$")

    def _is_split_iface_tail(tail: List[str]) -> bool:
        return (
            len(tail) >= 3
            and bool(_IF_PREFIX_RX.match(tail[-2]))
            and bool(_IF_NUM_RX.match(tail[-1]))
        )

    def _build_spans(header: str) -> Optional[List[Tuple[str, int, Optional[int]]]]:
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
        spans: List[Tuple[str, int, Optional[int]]] = []
        for i, (key, start) in enumerate(found):
            end = found[i + 1][1] if i + 1 < len(found) else None  # last column: slice to end of line
            spans.append((key, start, end))
        return spans

    rows: Dict[int, Dict[str, Any]] = {}
    count = 0
    spans: Optional[List[Tuple[str, int, Optional[int]]]] = None
    started = False
    detected_style = None

    # Handle IOS/XE line-wrapping where Device ID appears on its own line
    pending_device_id: Optional[str] = None

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

            # IOS/XE sometimes wraps the Device ID onto its own line.
            # Example:
            #   lab-109-a450-80000.syr.edu
            #                  Ten 1/0/12  133  R S I  C9300-48P  Gig 1/0/1
            if not ht.isdigit():
                # IOS/XE can wrap the device-id onto its own line. In that case the device-id may
                # "spill" into other fixed-width slices, so treat the *whole line* as the device-id
                # when the other columns are empty.
                if (
                    ln
                    and not ln.startswith((" ", "\t"))
                    and not parsed.get("capability", "").strip()
                    and not parsed.get("platform", "").strip()
                    and not parsed.get("port_id", "").strip()
                    and not lnl.startswith(("device id", "capability", "total"))
                ):
                    pending_device_id = ln.strip()
                continue

            device_id = parsed.get("device_id", "").strip()
            if not device_id and pending_device_id:
                device_id = pending_device_id
            pending_device_id = None

            row = {
                "device_id": device_id,
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
        if not parts:
            continue

        # device-id-only wrapped line
        if len(parts) == 1 and not any(ch.isdigit() for ch in parts[0]) and "." in parts[0]:
            pending_device_id = parts[0]
            continue

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

        if _is_split_iface_tail(tail):
            port_id = f"{tail[-2]} {tail[-1]}"
            platform = tail[-3]
            capability = " ".join(tail[:-3]).strip()
        else:
            platform = tail[-2] if len(tail) >= 2 else ""
            port_id = tail[-1] if len(tail) >= 1 else ""
            capability = " ".join(tail[:-2]).strip() if len(tail) >= 2 else ""

        if pending_device_id and not device_id:
            device_id = pending_device_id
        pending_device_id = None

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


def cisco_parse_show_mac_address_table_auto(
    device_type: str,
    output: Union[str, Dict[str, Any]],
    output_type_flag: str = "cli",  # cli | json | auto
    *,
    return_envelope: bool = False,
) -> Dict[str, Any]:
    """
    Notes / How to run:
      - Call with (device_type, output, output_type_flag)
      - output_type_flag:
          - "cli": treat output as CLI text
          - "json": treat output as NX-OS JSON (dict or JSON string)
          - "auto": try JSON first for NX-OS if it looks like JSON, else CLI
    """

    dt_raw = (device_type or "").strip()
    dt = dt_raw.lower()
    flag = (output_type_flag or "cli").strip().lower()

    is_nxos = dt in ("cisco_nxos", "nxos")

    def _wrap(rows: Dict[int, Dict[str, Any]], meta: Dict[str, Any], error: Optional[str]) -> Dict[str, Any]:
        if return_envelope:
            return {"rows": rows, "meta": meta, "error": error}
        return rows if error is None else {"error": error}

    # -------------------------
    # Forced JSON
    # -------------------------
    if flag == "json":
        if not is_nxos:
            return _wrap({}, {"device_type": dt_raw, "output_type": "json"}, "unsupported_json_for_device_type")

        if isinstance(output, dict):
            nx = cisco_nxos_parse_show_mac_address_table_json(output)
        else:
            raw = "" if output is None else str(output)
            d = _json_load_dict_best_effort(raw)
            if isinstance(d, dict) and d.get("error"):
                return _wrap({}, {"device_type": dt_raw, "output_type": "json"}, str(d.get("error")))
            nx = cisco_nxos_parse_show_mac_address_table_json(d)

        if isinstance(nx, dict) and nx.get("error"):
            return _wrap({}, {"device_type": dt_raw, "output_type": "json"}, str(nx.get("error")))

        rows = ((nx or {}).get("normalized") or {}).get("mac_address_table")
        if not isinstance(rows, dict):
            return _wrap({}, {"device_type": dt_raw, "output_type": "json"}, "unsupported_json_schema_for_mac_address_table")

        meta = (nx.get("meta") or {}) if isinstance(nx, dict) else {}
        meta.setdefault("device_type", dt_raw)
        meta.setdefault("detected_command", "show_mac_address_table")
        meta["output_type"] = "json"
        return _wrap(rows, meta, None)

    # -------------------------
    # Forced CLI
    # -------------------------
    if flag == "cli":
        if not isinstance(output, str):
            return _wrap({}, {"device_type": dt_raw, "output_type": "cli"}, "invalid_payload: expected cli string")
        return cisco_parse_show_mac_address_table_cli(output, device_type=dt_raw, return_envelope=return_envelope)

    # -------------------------
    # Auto
    # -------------------------
    if isinstance(output, dict):
        if not is_nxos:
            return _wrap({}, {"device_type": dt_raw, "output_type": "auto"}, "json_payload_only_supported_for_nxos_today")
        nx = cisco_nxos_parse_show_mac_address_table_json(output)
        rows = ((nx or {}).get("normalized") or {}).get("mac_address_table")
        if not isinstance(rows, dict):
            return _wrap({}, {"device_type": dt_raw, "output_type": "json"}, "unsupported_json_schema_for_mac_address_table")
        meta = nx.get("meta") or {}
        meta.setdefault("device_type", dt_raw)
        meta.setdefault("detected_command", "show_mac_address_table")
        meta["output_type"] = "json"
        return _wrap(rows, meta, None)

    raw = "" if output is None else str(output)
    raw_l = raw.lstrip()

    # NX-OS: if it looks like JSON, try JSON first
    if is_nxos and raw_l.startswith(("{", "[")):
        d = _json_load_dict_best_effort(raw)
        if isinstance(d, dict) and not d.get("error"):
            nx = cisco_nxos_parse_show_mac_address_table_json(d)
            if isinstance(nx, dict) and not nx.get("error"):
                rows = ((nx or {}).get("normalized") or {}).get("mac_address_table")
                if isinstance(rows, dict):
                    meta = nx.get("meta") or {}
                    meta.setdefault("device_type", dt_raw)
                    meta.setdefault("detected_command", "show_mac_address_table")
                    meta["output_type"] = "json"
                    return _wrap(rows, meta, None)

    # fallback to CLI
    return cisco_parse_show_mac_address_table_cli(raw, device_type=dt_raw, return_envelope=return_envelope)

def cisco_parse_show_mac_address_table_cli(
    output: str,
    *,
    device_type: str = "",
    return_envelope: bool = False,
) -> Dict[str, Any]:
    def _wrap(rows, meta, error):
        if return_envelope:
            return {"rows": rows, "meta": meta, "error": error}
        return rows if error is None else {"error": error}

    raw = "" if output is None else str(output)

    err_markers = (
        "Invalid input detected",
        "% Invalid input",
        "Incomplete command",
        "Ambiguous command",
        "Unknown command",
    )
    if any(m in raw for m in err_markers):
        return _wrap({}, {"device_type": device_type, "detected_command": "show_mac_address_table"}, "command_not_supported_or_invalid")

    rows: Dict[int, Dict[str, Any]] = {}
    i = 0

    for line in raw.splitlines():
        ln = (line or "").strip()
        if not ln:
            continue

        lnl = ln.lower()

        # skip prompts / legends / footers
        if lnl.startswith(("show ", "switch#", "router#", "nxos#", "ios#", "xr#")):
            continue
        if "total mac address" in lnl:
            continue
        if lnl.startswith(("legend:", "mac entries", "----")):
            continue

        parts = ln.split()
        if len(parts) < 3:
            continue

        # Handle common IOS/XE: VLAN MAC TYPE PORT
        vlan = None
        mac = None
        typ = None
        port = None
        age = None

        # Remove leading '*' markers if present
        if parts and parts[0].startswith("*") and len(parts[0]) > 1:
            parts[0] = parts[0].lstrip("*")

        # pattern A: vlan mac type port...
        if parts[0].isdigit() and _MAC_TOKEN.match(parts[1]):
            vlan, mac = parts[0], parts[1]
            # could be: vlan mac type port
            # or: vlan mac age type port
            if len(parts) >= 4 and parts[2].upper() in ("DYNAMIC", "STATIC", "SECURE", "SELF", "DROP"):
                typ = parts[2]
                port = parts[3]
            elif len(parts) >= 5 and _AGE_TOKEN.match(parts[2]) and parts[3].isalpha():
                age = parts[2]
                typ = parts[3]
                port = parts[4]
            elif len(parts) >= 5:
                # last-resort: assume type is 3rd, port is last
                typ = parts[2]
                port = parts[-1]

        # pattern B: mac vlan type port... (some platforms / variants)
        elif _MAC_TOKEN.match(parts[0]) and parts[1].isdigit():
            mac, vlan = parts[0], parts[1]
            if len(parts) >= 4:
                typ = parts[2]
                port = parts[3]

        else:
            continue

        if not mac or not port:
            continue

        mac_norm = _cisco_normalize_mac(mac)

        rows[i] = {
            "vlan": int(vlan) if vlan and vlan.isdigit() else vlan,
            **mac_norm,
            "mac_raw": mac,
            "type": (typ or "").strip(),
            "interface": port.strip(),
            "age": (age or "").strip(),
            "source_os": (device_type or "").strip() or "cisco",
            "raw": ln,
        }
        i += 1

    meta = {
        "device_type": device_type,
        "detected_command": "show_mac_address_table",
        "row_count": len(rows),
        "parsed_without_header_dependency": True,
    }
    return _wrap(rows, meta, None)

def cisco_parse_show_ip_arp_table_auto(
    device_type: str,
    output: Union[str, Dict[str, Any]],
    output_type_flag: str = "cli",  # cli | json | auto
    *,
    include_incomplete: bool = True,
    return_envelope: bool = False,
) -> Dict[str, Any]:
    """
    Notes / How to run:
      - device_type: cisco_ios | cisco_xe | cisco_xr | cisco_nxos
      - output: cli text, OR dict, OR json-string (nxos)
      - output_type_flag: cli|json|auto
    """
    dt_raw = (device_type or "").strip()
    dt = dt_raw.lower()
    flag = (output_type_flag or "cli").strip().lower()

    is_xr = dt in ("cisco_xr", "iosxr", "xr")
    is_nxos = dt in ("cisco_nxos", "nxos")

    def _wrap(rows: Dict[int, Dict[str, Any]], meta: Dict[str, Any], error: Optional[str]) -> Dict[str, Any]:
        if return_envelope:
            return {"rows": rows, "meta": meta, "error": error}
        return rows if error is None else {"error": error}

    # Forced JSON
    if flag == "json":
        if not is_nxos:
            return _wrap({}, {"device_type": dt_raw, "output_type": "json"}, "unsupported_json_for_device_type")
        nx = parse_device_json("cisco_nxos", output if isinstance(output, dict) else _json_load_dict_best_effort(str(output)))
        if isinstance(nx, dict) and nx.get("error"):
            return _wrap({}, {"device_type": dt_raw, "output_type": "json"}, str(nx.get("error")))
        rows = ((nx or {}).get("normalized") or {}).get("ip_arp_table")
        if not isinstance(rows, dict):
            return _wrap({}, {"device_type": dt_raw, "output_type": "json"}, "unsupported_json_schema_for_ip_arp_table")
        if not include_incomplete:
            rows = {k: v for k, v in rows.items() if isinstance(v, dict) and not v.get("incomplete")}
        meta = (nx.get("meta") or {}) if isinstance(nx, dict) else {}
        meta["row_count"] = len(rows)
        meta["incomplete_filtered"] = (not include_incomplete)
        meta.setdefault("device_type", dt_raw)
        meta.setdefault("detected_command", "show_ip_arp_table")
        meta["output_type"] = "json"
        return _wrap(rows, meta, None)

    # Forced CLI
    if flag == "cli":
        if not isinstance(output, str):
            return _wrap({}, {"device_type": dt_raw, "output_type": "cli"}, "invalid_payload: expected cli string")
        if is_xr:
            res = cisco_parse_show_ip_arp_table_xr(output, include_incomplete=include_incomplete, return_envelope=return_envelope)
            if return_envelope and isinstance(res, dict):
                meta = res.get("meta") or {}
                meta.setdefault("device_type", dt_raw)
                meta.setdefault("detected_command", "show_ip_arp_table")
                meta["output_type"] = "cli"
                res["meta"] = meta
            return res

        res = cisco_parse_show_ip_arp_table(output, device_type=dt_raw, include_incomplete=include_incomplete, return_envelope=return_envelope)
        if return_envelope and isinstance(res, dict):
            meta = res.get("meta") or {}
            meta.setdefault("device_type", dt_raw)
            meta.setdefault("detected_command", "show_ip_arp_table")
            meta["output_type"] = "cli"
            res["meta"] = meta
        return res

    # Auto mode
    if isinstance(output, dict):
        if not is_nxos:
            return _wrap({}, {"device_type": dt_raw, "output_type": "json"}, "unsupported_json_for_device_type")
        nx = parse_device_json("cisco_nxos", output)
        if isinstance(nx, dict) and nx.get("error"):
            return _wrap({}, {"device_type": dt_raw, "output_type": "json"}, str(nx.get("error")))
        rows = ((nx or {}).get("normalized") or {}).get("ip_arp_table")
        if not isinstance(rows, dict):
            return _wrap({}, {"device_type": dt_raw, "output_type": "json"}, "unsupported_json_schema_for_ip_arp_table")
        if not include_incomplete:
            rows = {k: v for k, v in rows.items() if isinstance(v, dict) and not v.get("incomplete")}
        meta = (nx.get("meta") or {}) if isinstance(nx, dict) else {}
        meta["row_count"] = len(rows)
        meta["incomplete_filtered"] = (not include_incomplete)
        meta.setdefault("device_type", dt_raw)
        meta.setdefault("detected_command", "show_ip_arp_table")
        meta["output_type"] = "json"
        return _wrap(rows, meta, None)

    raw = "" if output is None else str(output)
    raw_strip = raw.lstrip()

    if is_nxos and raw_strip.startswith("{"):
        nx = cisco_parse_device_json_from_string("cisco_nxos", raw)
        if isinstance(nx, dict) and not nx.get("error"):
            rows = ((nx or {}).get("normalized") or {}).get("ip_arp_table")
            if isinstance(rows, dict):
                if not include_incomplete:
                    rows = {k: v for k, v in rows.items() if isinstance(v, dict) and not v.get("incomplete")}
                meta = (nx.get("meta") or {}) if isinstance(nx, dict) else {}
                meta["row_count"] = len(rows)
                meta["incomplete_filtered"] = (not include_incomplete)
                meta.setdefault("device_type", dt_raw)
                meta.setdefault("detected_command", "show_ip_arp_table")
                meta["output_type"] = "json"
                return _wrap(rows, meta, None)

    # fallback to CLI
    if is_xr:
        return cisco_parse_show_ip_arp_table_xr(raw, include_incomplete=include_incomplete, return_envelope=return_envelope)
    return cisco_parse_show_ip_arp_table(raw, device_type=dt_raw, include_incomplete=include_incomplete, return_envelope=return_envelope)



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

def cisco_parse_show_lldp_neighbors_auto(
    device_type: str,
    output: Union[str, Dict[str, Any]],
    output_type_flag: str = "cli",  # cli | json | auto
    *,
    return_envelope: bool = False,
) -> Dict[str, Any]:
    """
    Notes / How to run:
      - device_type: cisco_ios | cisco_xe | cisco_xr | cisco_nxos
      - output: cli text, OR dict, OR json-string (nxos)
      - output_type_flag: cli|json|auto
    """
    dt_raw = (device_type or "").strip()
    dt = dt_raw.lower()
    flag = (output_type_flag or "cli").strip().lower()

    is_xr = dt in ("cisco_xr", "iosxr", "xr")
    is_nxos = dt in ("cisco_nxos", "nxos")

    def _wrap(rows: Dict[int, Dict[str, Any]], meta: Dict[str, Any], error: Optional[str]) -> Dict[str, Any]:
        if return_envelope:
            return {"rows": rows, "meta": meta, "error": error}
        return rows if error is None else {"error": error}

    # Forced JSON
    if flag == "json":
        if not is_nxos:
            return _wrap({}, {"device_type": dt_raw, "output_type": "json"}, "unsupported_json_for_device_type")

        if isinstance(output, dict):
            nx = cisco_nxos_parse_show_lldp_neighbors_json(output)
        else:
            raw = "" if output is None else str(output)
            d = _json_load_dict_best_effort(raw)
            if isinstance(d, dict) and d.get("error"):
                return _wrap({}, {"device_type": dt_raw, "output_type": "json"}, str(d.get("error")))
            nx = cisco_nxos_parse_show_lldp_neighbors_json(d)

        if isinstance(nx, dict) and nx.get("error"):
            return _wrap({}, {"device_type": dt_raw, "output_type": "json"}, str(nx.get("error")))

        neighbors = ((nx or {}).get("normalized") or {}).get("neighbors")
        if not isinstance(neighbors, dict):
            return _wrap({}, {"device_type": dt_raw, "output_type": "json"}, "unsupported_json_schema_for_lldp_neighbors")

        meta = nx.get("meta") or {}
        meta.setdefault("device_type", dt_raw)
        meta.setdefault("detected_command", "show_lldp_neighbors")
        meta["output_type"] = "json"
        return _wrap(neighbors, meta, None)

    raw = "" if output is None else str(output)
    raw_l = raw.lstrip()

    # Auto: NX-OS JSON if it looks like JSON
    if is_nxos and raw_l.startswith(("{", "[")):
        d = _json_load_dict_best_effort(raw)
        nx = cisco_nxos_parse_show_lldp_neighbors_json(d) if isinstance(d, dict) and not d.get("error") else {"error": str((d or {}).get("error"))}
        if isinstance(nx, dict) and not nx.get("error"):
            neighbors = ((nx or {}).get("normalized") or {}).get("neighbors")
            if isinstance(neighbors, dict):
                meta = nx.get("meta") or {}
                meta.setdefault("device_type", dt_raw)
                meta.setdefault("detected_command", "show_lldp_neighbors")
                meta["output_type"] = "json"
                return _wrap(neighbors, meta, None)

    # CLI
    if flag == "cli" or flag == "auto":
        if is_xr:
            res = cisco_parse_show_lldp_neighbors_xr(raw, return_envelope=return_envelope)
            if return_envelope and isinstance(res, dict):
                meta = res.get("meta") or {}
                meta.setdefault("device_type", dt_raw)
                meta.setdefault("detected_command", "show_lldp_neighbors")
                meta["output_type"] = "cli"
                res["meta"] = meta
            return res

        res = cisco_parse_show_lldp_neighbors(raw, device_type=device_type, return_envelope=return_envelope)
        if return_envelope and isinstance(res, dict):
            meta = res.get("meta") or {}
            meta.setdefault("device_type", dt_raw)
            meta.setdefault("detected_command", "show_lldp_neighbors")
            meta["output_type"] = "cli"
            res["meta"] = meta
        return res

    return _wrap({}, {"device_type": dt_raw, "output_type": str(flag)}, "unsupported_output_type_flag")


def cisco_normalize_device_type(device_type: Any) -> str:
    """
    Normalize device_type strings across netmiko / internal variants.

    Examples:
      - cisco_iosxr, iosxr, cisco-iosxr -> cisco_xr
      - cisco_nexus, nxos -> cisco_nxos
      - cisco_iosxe, iosxe -> cisco_xe
    """
    dt = str(device_type or "").strip().lower().replace("-", "_")
    if not dt:
        return ""

    # XR
    if dt in ("cisco_xr", "iosxr", "cisco_iosxr") or "iosxr" in dt or dt.endswith("_xr"):
        return "cisco_xr"

    # NX-OS
    if dt in ("cisco_nxos", "nxos", "nx_os", "cisco_nexus", "cisco_nx_os") or "nxos" in dt or "nexus" in dt:
        return "cisco_nxos"

    # IOS-XE
    if dt in ("cisco_xe", "iosxe", "cisco_iosxe") or "iosxe" in dt:
        return "cisco_xe"

    # IOS (avoid misclassifying XR/XE)
    if dt in ("cisco_ios", "ios") or (("ios" in dt) and ("iosxe" not in dt) and ("iosxr" not in dt)):
        return "cisco_ios"

    return dt

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

def _none_if_not_advertised(v: Any) -> Optional[str]:
    s = _as_str(v)
    if not s:
        return None
    sl = s.lower()
    if sl in {"not advertised", "address not advertised", "n/a", "-", "none"}:
        return None
    return s

def _split_device_id_paren(v: Any) -> Dict[str, Any]:
    """
    NX-OS CDP device_id sometimes comes as: "hostname(serial)".
    Return both pieces so you can join on hostname cleanly.
    """
    raw = _as_str(v)
    if not raw:
        return {"raw": None, "name": None, "serial": None}

    name = raw
    serial = None
    if "(" in raw and raw.endswith(")"):
        left, right = raw.split("(", 1)
        name = left.strip() or raw
        serial = right[:-1].strip() or None

    return {"raw": raw, "name": name, "serial": serial}

def _cisco_short_ifname(ifname: Any) -> Optional[str]:
    """
    Notes / How to run:
      - Internal helper: convert long interface names to a short-ish form.
      - Keeps unknown formats unchanged.
    """
    name = _as_str(ifname)
    if not name:
        return None

    s = name.strip()
    sl = s.lower()

    # Already-short formats (normalize a few common caps)
    if re.match(r"^(eth|gi|te|fa|fo|po|vl|lo|mgmt)\d", sl):
        if sl.startswith("eth"):
            return "Eth" + s[3:]
        if sl.startswith("gi"):
            return "Gi" + s[2:]
        if sl.startswith("te"):
            return "Te" + s[2:]
        if sl.startswith("fa"):
            return "Fa" + s[2:]
        if sl.startswith("fo"):
            return "Fo" + s[2:]
        if sl.startswith("po"):
            return "Po" + s[2:]
        if sl.startswith("vl"):
            return "Vl" + s[2:]
        if sl.startswith("lo"):
            return "Lo" + s[2:]
        if sl.startswith("mgmt"):
            return "mgmt" + s[4:]
        return s

    prefix_map = {
        "tengigabitethernet": "Te",
        "twentyfivegigabitethernet": "Twe",
        "fortygigabitethernet": "Fo",
        "hundredgigabitethernet": "Hu",
        "gigabitethernet": "Gi",
        "ethernet": "Eth",
        "port-channel": "Po",
        "portchannel": "Po",
        "loopback": "Lo",
        "vlan": "Vlan",
        "management": "mgmt",
        "mgmt": "mgmt",
    }

    for longp, shortp in prefix_map.items():
        if sl.startswith(longp):
            return shortp + s[len(longp) :]

    return s

def cisco_parse_show_interface_description_cli(
    output: str,
    *,
    device_type: str = "cisco",
    return_envelope: bool = True,
) -> Dict[str, Any]:
    """
    Notes / How to run:
      - Input: raw CLI output from `show interface description` (IOS/XE/XR/NXOS without JSON)
      - Goal: parse the common columns: Interface, Status, Protocol, Description
      - Handles "admin down" / "administratively down" as a 2-token Status

    Returns:
      - If return_envelope:
          {"rows": {0: {...}, ...}, "meta": {...}, "error": None|{...}}
      - Else:
          rows dict, or {"error": "..."} if parse_error
    """
    raw = "" if output is None else str(output)

    err_markers = (
        "Invalid input detected",
        "% Invalid input",
        "Incomplete command",
        "Ambiguous command",
        "Unknown command",
    )

    parse_error = "command_not_supported_or_invalid" if any(m in raw for m in err_markers) else None

    rows: Dict[int, Dict[str, Any]] = {}
    interfaces: Dict[str, Dict[str, Any]] = {}
    count = 0
    started = False

    for line in raw.splitlines():
        ln = (line or "").rstrip("\r\n")
        if not ln.strip():
            continue

        lnl = ln.strip().lower()

        # header-ish detection        # IOS-XR (and occasionally other platforms) may emit a leading timestamp line, e.g.
        #   Fri Feb  6 02:35:18.310 UTC
        # which is not a table row.
        if re.match(r"^(Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+\w+\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?\s+\w+", ln.strip()):
            continue


        if ("interface" in lnl and "description" in lnl) or lnl.startswith(("interface", "port", "----")):
            started = True
            continue
        if not started and lnl.startswith(("show ", "router#", "switch#", "nxos#", "ios#", "xr#")):
            continue

        parts = ln.split()
        if len(parts) < 3:
            continue

        intf = parts[0]
        rest = parts[1:]

        status: Optional[str]
        protocol: Optional[str]
        desc: Optional[str]

        # "admin down down ..." or "administratively down down ..."
        if len(rest) >= 3 and rest[0].lower() in ("admin", "administratively") and rest[1].lower() == "down":
            status = f"{rest[0]} {rest[1]}"
            protocol = rest[2]
            desc = " ".join(rest[3:]).strip() or None
        else:
            status = rest[0]
            protocol = rest[1] if len(rest) >= 2 else None
            desc = " ".join(rest[2:]).strip() or None

        ifname = _as_str(intf)
        if not ifname:
            continue

        entry = {
            "interface": ifname,
            "interface_short": _cisco_short_ifname(ifname),
            "status": _as_str(status),
            "protocol": _as_str(protocol),
            "description": _as_str(desc),
            "source_os": device_type,
            "raw": ln.strip(),
        }
        rows[count] = entry
        interfaces[ifname] = entry
        count += 1

    meta = {
        "detected_style": "cli",
        "detected_command": "show_interface_description",
        "count": count,
    }

    out = {
        "rows": rows,
        "interfaces": interfaces,
        "meta": meta,
        "error": ({"error": parse_error} if parse_error else None),
    }
    return out if return_envelope else (rows if rows else ({"error": parse_error} if parse_error else {}))

def cisco_parse_show_interface_description_auto(
    device_type: str,
    output: Union[str, Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Notes / How to run:
      - Prefer JSON parsing for NX-OS when the payload is JSON (string or dict).
      - Fall back to CLI parsing for everything else.

    Example:
      parsed = cisco_parse_show_interface_description_auto("cisco_nxos", output_string)
    """
    dt = (device_type or "").strip().lower()

    # If we already have a dict, try NX-OS JSON structure first
    if isinstance(output, dict):
        if dt in ("cisco_nxos", "nxos") and isinstance(output.get("TABLE_interface"), dict):
            tab = output.get("TABLE_interface") or {}
            if "ROW_interface" in tab:
                return cisco_nxos_parse_show_interface_description_json(output, return_envelope=True)
        # otherwise treat as “not supported here”
        return {"error": "unsupported_payload_shape_for_interface_description"}

    # string path: if NX-OS, attempt JSON-from-string pipeline, else CLI
    raw = "" if output is None else str(output)
    if dt in ("cisco_nxos", "nxos"):
        attempt = cisco_parse_device_json_from_string("cisco_nxos", raw)
        if isinstance(attempt, dict) and attempt.get("meta", {}).get("detected_command") == "show_interface_description":
            return attempt

    return cisco_parse_show_interface_description_cli(raw, device_type=device_type, return_envelope=True)

def cisco_parse_show_cdp_neighbors_auto(
    device_type: str,
    output: Union[str, Dict[str, Any]],
    output_type_flag: str = "cli",  # cli | json | auto
    *,
    return_envelope: bool = False,
) -> Dict[str, Any]:
    """
    Notes / How to run:
      - device_type: cisco_ios | cisco_xe | cisco_xr | cisco_nxos
      - output: cli text, OR dict, OR json-string (nxos)
      - output_type_flag: cli|json|auto
    """
    dt_raw = (device_type or "").strip()
    dt = dt_raw.lower()
    flag = (output_type_flag or "cli").strip().lower()

    is_xr = dt in ("cisco_xr", "iosxr", "xr")
    is_nxos = dt in ("cisco_nxos", "nxos")

    def _wrap(rows: Dict[int, Dict[str, Any]], meta: Dict[str, Any], error: Optional[str]) -> Dict[str, Any]:
        if return_envelope:
            return {"rows": rows, "meta": meta, "error": error}
        return rows if error is None else {"error": error}

    # Forced JSON
    if flag == "json":
        if not is_nxos:
            return _wrap({}, {"device_type": dt_raw, "output_type": "json"}, "unsupported_json_for_device_type")

        if isinstance(output, dict):
            nx = cisco_nxos_parse_show_cdp_neighbors_json(output)
        else:
            raw = "" if output is None else str(output)
            nx = cisco_parse_device_json_from_string("cisco_nxos", raw)

        if isinstance(nx, dict) and nx.get("error"):
            return _wrap({}, {"device_type": dt_raw, "output_type": "json"}, str(nx.get("error")))

        neighbors = ((nx or {}).get("normalized") or {}).get("neighbors")
        if not isinstance(neighbors, dict):
            return _wrap({}, {"device_type": dt_raw, "output_type": "json"}, "unsupported_json_schema_for_cdp_neighbors")

        meta = (nx.get("meta") or {}) if isinstance(nx, dict) else {}
        meta.setdefault("device_type", dt_raw)
        meta.setdefault("detected_command", "show_cdp_neighbors")
        meta["output_type"] = "json"
        return _wrap(neighbors, meta, None)

    # Forced CLI
    if flag == "cli":
        if not isinstance(output, str):
            return _wrap({}, {"device_type": dt_raw, "output_type": "cli"}, "invalid_payload: expected cli string")

        if is_xr:
            res = cisco_parse_show_cdp_neighbors_xr(output, return_envelope=return_envelope)
            if return_envelope and isinstance(res, dict):
                meta = res.get("meta") or {}
                meta.setdefault("device_type", dt_raw)
                meta.setdefault("detected_command", "show_cdp_neighbors")
                meta["output_type"] = "cli"
                res["meta"] = meta
            return res

        res = cisco_parse_show_cdp_neighbors(output, device_type=device_type, return_envelope=return_envelope)
        if return_envelope and isinstance(res, dict):
            meta = res.get("meta") or {}
            meta.setdefault("device_type", dt_raw)
            meta.setdefault("detected_command", "show_cdp_neighbors")
            meta["output_type"] = "cli"
            res["meta"] = meta
        return res

    # Auto
    if isinstance(output, dict):
        if not is_nxos:
            return _wrap({}, {"device_type": dt_raw, "output_type": "auto"}, "json_payload_only_supported_for_nxos_today")

        nx = cisco_nxos_parse_show_cdp_neighbors_json(output)
        neighbors = ((nx or {}).get("normalized") or {}).get("neighbors")
        if not isinstance(neighbors, dict):
            return _wrap({}, {"device_type": dt_raw, "output_type": "json"}, "unsupported_json_schema_for_cdp_neighbors")

        meta = nx.get("meta") or {}
        meta.setdefault("device_type", dt_raw)
        meta.setdefault("detected_command", "show_cdp_neighbors")
        meta["output_type"] = "json"
        return _wrap(neighbors, meta, None)

    raw = "" if output is None else str(output)
    raw_l = raw.lstrip()

    if is_nxos and raw_l.startswith(("{", "[")):
        nx = cisco_parse_device_json_from_string("cisco_nxos", raw)
        if isinstance(nx, dict) and not nx.get("error"):
            neighbors = ((nx or {}).get("normalized") or {}).get("neighbors")
            if isinstance(neighbors, dict):
                meta = nx.get("meta") or {}
                meta.setdefault("device_type", dt_raw)
                meta.setdefault("detected_command", "show_cdp_neighbors")
                meta["output_type"] = "json"
                return _wrap(neighbors, meta, None)

    # fallback: CLI parsing
    if is_xr:
        res = cisco_parse_show_cdp_neighbors_xr(raw, return_envelope=return_envelope)
        if return_envelope and isinstance(res, dict):
            meta = res.get("meta") or {}
            meta.setdefault("device_type", dt_raw)
            meta.setdefault("detected_command", "show_cdp_neighbors")
            meta["output_type"] = "cli"
            res["meta"] = meta
        return res

    res = cisco_parse_show_cdp_neighbors(raw, device_type=device_type, return_envelope=return_envelope)
    if return_envelope and isinstance(res, dict):
        meta = res.get("meta") or {}
        meta.setdefault("device_type", dt_raw)
        meta.setdefault("detected_command", "show_cdp_neighbors")
        meta["output_type"] = "cli"
        res["meta"] = meta
    return res

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

# Cisco iosxr parsers

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

def cisco_parse_show_version_xr(output: str, *, return_envelope: bool = False) -> Dict[str, Any]:
    """
    Parse IOS-XR "show version" CLI (best-effort).

    Extracts (when present):
      - software_version
      - chassis_model
      - system_serial_number (if present)
      - uptime
      - build_label (if present)

    Returns:
      - default: dict
      - if return_envelope=True: {"data": <dict>, "meta": {...}, "error": <str|None>}
    """
    raw = "" if output is None else str(output)
    lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]

    data: Dict[str, Any] = {}

    error_markers = (
        "Invalid input detected",
        "% Invalid input",
        "Incomplete command",
        "Ambiguous command",
        "Unknown command",
    )
    parse_error = "command_not_supported_or_invalid" if any(m in raw for m in error_markers) else None

    # Cisco IOS XR Software, Version 25.3.1 LNT
    for ln in lines:
        m = re.search(
            r"^(?:Cisco\s+)?IOS\s+XR\s+Software,\s*Version\s*:?\s*(?P<v>.+?)\s*$",
            ln,
            flags=re.IGNORECASE,
        )
        if m:
            data["software_version"] = m.group("v").strip()
            break

    # Label        : 25.3.1
    for ln in lines:
        m = re.search(r"^Label\s*:\s*(?P<label>\S+)\s*$", ln, flags=re.IGNORECASE)
        if m:
            data["build_label"] = m.group("label").strip()
            break

    # cisco XRd-CP-C-01 processor with 24GB of memory
    for ln in lines:
        m = re.search(r"^cisco\s+(?P<model>.+?)\s+processor\b", ln, flags=re.IGNORECASE)
        if m:
            data["chassis_model"] = m.group("model").strip()
            break

    # Additional model fallbacks (varies by platform)
    if not data.get("chassis_model"):
        for ln in lines:
            m = re.search(r"^(?:Platform|System\s+Type|Model|Hardware)\s*:\s*(?P<model>.+?)\s*$", ln, flags=re.IGNORECASE)
            if m:
                data["chassis_model"] = m.group("model").strip()
                break

    # xr1 uptime is 1 week, 4 days, 16 hours, 56 minutes
    for ln in lines:
        m = re.search(r"\buptime\s+is\s+(?P<uptime>.+?)\s*$", ln, flags=re.IGNORECASE)
        if m:
            data["uptime"] = m.group("uptime").strip()
            break

    # Serial is not always present in XR "show version", but keep a couple of common patterns
    for ln in lines:
        m = re.search(r"^(?:Processor\s+Board\s+ID|System\s+serial\s+number)\s*[: ]\s*(?P<sn>\S+)\s*$", ln, flags=re.IGNORECASE)
        if m:
            data["system_serial_number"] = m.group("sn").strip()
            break

    if return_envelope:
        return {
            "data": data,
            "meta": {"device_type": "cisco_xr", "detected_style": "xr_cli"},
            "error": parse_error,
        }

    return data if not parse_error else {"error": parse_error, **data}

def cisco_parse_show_version_auto(
    output: Any,
    *,
    device_type: Optional[str] = None,
    output_type: str = "auto",
) -> Dict[str, Any]:
    """
    Parse 'show version' across supported Cisco OS families.

    - If output_type is "json" (or "auto" and the payload looks JSON-ish),
      tries the NX-OS JSON parser pipeline (cisco_parse_device_json_from_string).
    - If output_type is "cli" (or JSON not detected), uses a device-specific CLI parser:
        * cisco_xr   -> cisco_parse_show_version_xr
        * cisco_nxos -> cisco_parse_show_version_nxos_cli
        * else       -> cisco_parse_show_version (IOS/IOS-XE)
    """
    dt = cisco_normalize_device_type(device_type)
    ot = (output_type or "auto").strip().lower()
    raw = "" if output is None else (output if isinstance(output, str) else str(output))
    raw_l = raw.lstrip()

    # Best-effort JSON path (NX-OS json-pretty)
    if ot in ("json", "auto"):
        # allow a little preamble before the first '{'/'['
        m = re.search(r"[\{\[]", raw)
        if m and m.start() < 2000:
            candidate = raw[m.start():].lstrip()
            if candidate.startswith(("{", "[")):
                parsed = cisco_parse_device_json_from_string(dt or "cisco_nxos", candidate)
                if isinstance(parsed, dict) and not parsed.get("error"):
                    return parsed

    # CLI path
    if dt == "cisco_xr":
        return cisco_parse_show_version_xr(raw, return_envelope=False)

    if dt == "cisco_nxos":
        return cisco_parse_show_version_nxos_cli(raw, return_envelope=False)

    # Default IOS / IOS-XE style
    return cisco_parse_show_version(raw)

def cisco_parse_show_version_auto(
    output: Any,
    *,
    device_type: Optional[str] = None,
    output_type: str = "auto",
) -> Dict[str, Any]:
    """
    Parse "show version" across supported Cisco OS families.

    - If output_type is "json" (or "auto" and the payload looks like JSON),
      tries the NX-OS JSON parser pipeline (cisco_parse_device_json_from_string).
      If JSON parsing fails, it falls back to CLI parsing.
    - If output_type is "cli" (or JSON not detected), uses a device-specific
      CLI parser:
        * cisco_xr   -> cisco_parse_show_version_xr
        * cisco_nxos -> cisco_parse_show_version_nxos_cli
        * else       -> cisco_parse_show_version (IOS/IOS-XE)

    Returns the parser's native dict. For NX-OS JSON, that is the normalized
    structure returned by _parse_cisco_nxos_show_version (raw + normalized).
    """
    dt = (device_type or "").strip().lower().replace("-", "_")
    ot = (output_type or "auto").strip().lower()
    raw = "" if output is None else (output if isinstance(output, str) else str(output))
    raw_strip = raw.lstrip()

    # --- JSON path (best-effort) ---
    if ot in ("json", "auto") and raw_strip.startswith(("{", "[")):
        # NX-OS json-pretty is the common case; the parser auto-detects show-version keys.
        parsed = cisco_parse_device_json_from_string(dt or "cisco_nxos", raw)
        if isinstance(parsed, dict) and not parsed.get("error"):
            return parsed
        # If the caller explicitly asked for json and we couldn't parse, fall through to CLI.

    # --- CLI path ---
    if dt in ("cisco_xr", "iosxr", "cisco_iosxr"):
        return cisco_parse_show_version_xr(raw, return_envelope=False)

    if dt in ("cisco_nxos", "nxos", "cisco_nexus"):
        return cisco_parse_show_version_nxos_cli(raw, return_envelope=False)

    # Default: IOS / IOS-XE style
    return cisco_parse_show_version(raw)

def cisco_extract_show_version_fields(
    *,
    device_type: Optional[str],
    show_version_parsed: Dict[str, Any],
    raw_output: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Normalize 'show version' into a stable, cross-platform field set.

    Output keys (when available):
      - software_version
      - chassis_model
      - system_serial_number
      - base_ethernet_mac_address
      - uptime
    """
    dt = cisco_normalize_device_type(device_type)
    parsed = show_version_parsed or {}

    out: Dict[str, Any] = {}

    # NX-OS normalized schema path
    normalized = parsed.get("normalized") if isinstance(parsed, dict) else None
    if isinstance(normalized, dict):
        versions = ((normalized.get("software") or {}).get("versions") or {})
        if isinstance(versions, dict):
            if dt == "cisco_nxos":
                out["software_version"] = _as_str(versions.get("nxos") or versions.get("kickstart") or versions.get("system"))
        chassis = normalized.get("chassis") or {}
        if isinstance(chassis, dict):
            out["chassis_model"] = _as_str(chassis.get("model") or chassis.get("description"))
            out["system_serial_number"] = _as_str(chassis.get("system_serial_number"))
            out["base_ethernet_mac_address"] = _as_str(chassis.get("base_mac_address"))
        if normalized.get("uptime"):
            out["uptime"] = _as_str(normalized.get("uptime"))

    # NX-OS raw fallback keys (if present)
    raw = parsed.get("raw") if isinstance(parsed, dict) else None
    if isinstance(raw, dict):
        if not out.get("software_version"):
            if raw.get("nxos_ver_str"):
                out["software_version"] = _as_str(raw.get("nxos_ver_str"))
            elif raw.get("kickstart_ver_str"):
                out["software_version"] = _as_str(raw.get("kickstart_ver_str"))

        if not out.get("chassis_model") and raw.get("chassis_id"):
            out["chassis_model"] = _as_str(raw.get("chassis_id"))

        if not out.get("system_serial_number") and raw.get("proc_board_id"):
            out["system_serial_number"] = _as_str(raw.get("proc_board_id"))

    # Flat schema fallback (IOS / IOS-XE / IOS-XR CLI parsers)
    if not out.get("software_version"):
        sv = parsed.get("software_version") or parsed.get("version")
        if sv:
            out["software_version"] = _as_str(sv)

    if not out.get("chassis_model"):
        cm = parsed.get("chassis_model") or parsed.get("model_number") or parsed.get("platform") or parsed.get("model") or parsed.get("hardware")
        if cm:
            out["chassis_model"] = _as_str(cm)

    if not out.get("system_serial_number"):
        sn = parsed.get("system_serial_number")
        if sn:
            out["system_serial_number"] = _as_str(sn)

    if not out.get("base_ethernet_mac_address"):
        mac = parsed.get("base_ethernet_mac_address") or parsed.get("system_mac") or parsed.get("base_mac_address")
        if mac:
            out["base_ethernet_mac_address"] = _as_str(mac)

    # Final CLI fallback if still missing key fields
    if raw_output:
        if dt == "cisco_xr" and not out.get("chassis_model"):
            extra = cisco_parse_show_version_xr(raw_output, return_envelope=False)
            if isinstance(extra, dict) and not extra.get("error"):
                out["chassis_model"] = out.get("chassis_model") or extra.get("chassis_model")
                out["system_serial_number"] = out.get("system_serial_number") or extra.get("system_serial_number")

        if dt == "cisco_nxos" and not out.get("software_version"):
            extra = cisco_parse_show_version_nxos_cli(raw_output, return_envelope=False)
            if isinstance(extra, dict) and not extra.get("error"):
                out["software_version"] = out.get("software_version") or extra.get("software_version")
                out["chassis_model"] = out.get("chassis_model") or extra.get("chassis_model")
                out["system_serial_number"] = out.get("system_serial_number") or extra.get("system_serial_number")

    return {k: v for k, v in out.items() if v not in (None, "", "None")}



















# Cisco nxos specific functions



# TODO Incorporate this with the collected nxos data
def cisco_nxos_parse_show_mac_address_table_count_json(
    data: Dict[str, Any],
    *,
    device_type: Optional[str] = None,
    return_envelope: bool = False,
) -> Dict[str, Any]:
    """
    NX-OS JSON parser for:
      show mac address-table count | json / json-pretty

    NX-OS schema example:
      {
        "TABLE-macaddtblcount": {
          "count_str": "MAC Entries for all vlans :",
          "dyn_cnt": "0",
          "static_cnt": "0",
          "secure_cnt": "0",
          "total_cnt": "0",
          "otv_cnt": "0",
          "rvtep_static_cnt": "0"
        }
      }
    """

    def _as_int_local(v: Any) -> Optional[int]:
        try:
            if v is None:
                return None
            s = str(v).strip()
            if not s or s == "-":
                return None
            return int(s)
        except Exception:
            return None

    table = data.get("TABLE-macaddtblcount") or data.get("TABLE_macaddtblcount") or {}
    if not isinstance(table, dict) or not table:
        err = {"error": "unsupported_nxos_json_schema_for_mac_count"}
        if return_envelope:
            return {"data": {}, "meta": {"device_type": device_type, "output_type": "json"}, "error": err["error"]}
        return err

    totals: Dict[str, Any] = {}

    # Keep consistent keys with your CLI output where possible
    dyn = _as_int_local(table.get("dyn_cnt"))
    sta = _as_int_local(table.get("static_cnt"))
    tot = _as_int_local(table.get("total_cnt"))
    sec = _as_int_local(table.get("secure_cnt"))
    otv = _as_int_local(table.get("otv_cnt"))
    rvtep_sta = _as_int_local(table.get("rvtep_static_cnt"))

    if dyn is not None:
        totals["total_dynamic"] = dyn
    if sta is not None:
        totals["total_static"] = sta
    if tot is not None:
        totals["total_in_use"] = tot  # NX-OS calls this total_cnt (for all VLANs)
    if sec is not None:
        totals["total_secure"] = sec
    if otv is not None:
        totals["total_otv"] = otv
    if rvtep_sta is not None:
        totals["total_rvtep_static"] = rvtep_sta

    out = {
        "per_vlan": {},  # NX-OS JSON sample is explicitly "all vlans"
        "totals": totals,
        "nxos": {
            "id_out": str(table.get("id-out") or "").strip() or None,
            "count_str": str(table.get("count_str") or "").strip() or None,
        },
    }

    meta = {
        "device_type": device_type,
        "detected_command": "show_mac_address_table_count",
        "output_type": "json",
        "schema": "nxos_TABLE-macaddtblcount",
    }

    if return_envelope:
        return {"data": out, "meta": meta, "error": None}
    return out


def cisco_parse_show_mac_address_table_count_cli(
    output: str,
    *,
    device_type: Optional[str] = None,
    return_envelope: bool = False,
) -> Dict[str, Any]:
    """
    Parse CLI output of: `show mac address-table count`

    Handles blocks like:
      Mac Entries for Vlan 123:
        Dynamic Address Count  : 0
        Static  Address Count  : 1
        Total Mac Addresses    : 1

    And totals like:
      Total Dynamic Address Count  : 27
      Total Static  Address Count  : 2
      Total Mac Address In Use     : 29
      Total Mac Address Space Available: 32739

    Returns:
      - default: {"per_vlan": {...}, "totals": {...}}
      - if return_envelope=True: {"data": <dict>, "meta": {...}, "error": <str|None>}
    """
    raw = "" if output is None else str(output)

    per_vlan: Dict[str, Dict[str, Any]] = {}
    totals: Dict[str, Any] = {}

    rx_vlan_hdr = re.compile(r"^Mac\s+Entries\s+for\s+Vlan\s+(?P<vlan>\d+)\s*:\s*$", re.IGNORECASE)

    rx_dyn = re.compile(r"^Dynamic\s+Address\s+Count\s*:\s*(?P<v>\d+)\s*$", re.IGNORECASE)
    rx_sta = re.compile(r"^Static\s+Address\s+Count\s*:\s*(?P<v>\d+)\s*$", re.IGNORECASE)
    rx_tot = re.compile(r"^Total\s+Mac\s+Addresses?\s*:\s*(?P<v>\d+)\s*$", re.IGNORECASE)

    rx_total_dyn = re.compile(r"^Total\s+Dynamic\s+Address\s+Count\s*:\s*(?P<v>\d+)\s*$", re.IGNORECASE)
    rx_total_sta = re.compile(r"^Total\s+Static\s+Address\s+Count\s*:\s*(?P<v>\d+)\s*$", re.IGNORECASE)
    rx_in_use = re.compile(r"^Total\s+Mac\s+Address(?:es)?\s+In\s+Use\s*:\s*(?P<v>\d+)\s*$", re.IGNORECASE)
    rx_space = re.compile(r"^Total\s+Mac\s+Address\s+Space\s+Available\s*:\s*(?P<v>\d+)\s*$", re.IGNORECASE)

    current_vlan: Optional[str] = None

    for line in raw.splitlines():
        ln = (line or "").strip()
        if not ln:
            continue

        m = rx_vlan_hdr.match(ln)
        if m:
            current_vlan = m.group("vlan")
            per_vlan.setdefault(current_vlan, {})
            continue

        # per-vlan lines
        if current_vlan:
            md = rx_dyn.match(ln)
            if md:
                per_vlan[current_vlan]["dynamic"] = int(md.group("v"))
                continue
            ms = rx_sta.match(ln)
            if ms:
                per_vlan[current_vlan]["static"] = int(ms.group("v"))
                continue
            mt = rx_tot.match(ln)
            if mt:
                per_vlan[current_vlan]["total"] = int(mt.group("v"))
                continue

        # totals lines (outside vlan blocks)
        md = rx_total_dyn.match(ln)
        if md:
            totals["total_dynamic"] = int(md.group("v"))
            continue
        ms = rx_total_sta.match(ln)
        if ms:
            totals["total_static"] = int(ms.group("v"))
            continue
        mu = rx_in_use.match(ln)
        if mu:
            totals["total_in_use"] = int(mu.group("v"))
            continue
        ma = rx_space.match(ln)
        if ma:
            totals["total_space_available"] = int(ma.group("v"))
            continue

    data = {"per_vlan": per_vlan, "totals": totals}

    meta = {
        "device_type": device_type,
        "detected_command": "show_mac_address_table_count",
        "output_type": "cli",
        "vlan_blocks": len(per_vlan),
    }

    if return_envelope:
        return {"data": data, "meta": meta, "error": None}
    return data


def cisco_parse_show_mac_address_table_count_json(
    data: Dict[str, Any],
    *,
    device_type: Optional[str] = None,
    return_envelope: bool = False,
) -> Dict[str, Any]:
    """
    JSON parser for `show mac address-table count`.

    - If NX-OS schema TABLE-macaddtblcount is present, use the NX-OS parser.
    - Otherwise keep best-effort deep-search for common total keys.
    """
    if isinstance(data, dict) and ("TABLE-macaddtblcount" in data or "TABLE_macaddtblcount" in data):
        return cisco_nxos_parse_show_mac_address_table_count_json(
            data, device_type=device_type, return_envelope=return_envelope
        )

    # ---- existing best-effort fallback (keep your current logic) ----
    def _deep_iter(obj: Any):
        if isinstance(obj, dict):
            for k, v in obj.items():
                yield (k, v)
                yield from _deep_iter(v)
        elif isinstance(obj, list):
            for it in obj:
                yield from _deep_iter(it)

    def _key_norm(k: Any) -> str:
        return str(k).strip().lower().replace(" ", "_")

    def _as_int_local(v: Any) -> Optional[int]:
        try:
            if v is None:
                return None
            s = str(v).strip()
            if not s or s == "-":
                return None
            return int(s)
        except Exception:
            return None

    per_vlan: Dict[str, Dict[str, Any]] = {}
    totals: Dict[str, Any] = {}

    key_map = {
        "total_mac_address_in_use": "total_in_use",
        "total_mac_addresses_in_use": "total_in_use",
        "total_mac_address_in_use_count": "total_in_use",
        "total_dynamic_address_count": "total_dynamic",
        "total_static_address_count": "total_static",
        "total_mac_address_space_available": "total_space_available",
        "total_mac_address_space_avail": "total_space_available",
    }

    for k, v in _deep_iter(data):
        kn = _key_norm(k)
        if kn in key_map:
            iv = _as_int_local(v)
            if iv is not None:
                totals[key_map[kn]] = iv

    out = {"per_vlan": per_vlan, "totals": totals}

    meta = {
        "device_type": device_type,
        "detected_command": "show_mac_address_table_count",
        "output_type": "json",
        "schema": "best_effort",
        "totals_found": sorted(list(totals.keys())),
    }

    if return_envelope:
        return {"data": out, "meta": meta, "error": None}
    return out


def cisco_parse_show_mac_address_table_count_auto(
    device_type: str,
    output: Union[str, Dict[str, Any]],
    output_type_flag: str = "cli",   # "cli" | "json" | "auto"
    *,
    return_envelope: bool = False,
) -> Dict[str, Any]:
    """
    Auto wrapper for `show mac address-table count`.

    - cli: uses cisco_parse_show_mac_address_table_count_cli
    - json: loads JSON (dict or string) then uses cisco_parse_show_mac_address_table_count_json
    - auto:
        * dict -> json
        * str starting with "{" -> json
        * else -> cli
    """
    dt_raw = (device_type or "").strip()
    flag = (output_type_flag or "cli").strip().lower()

    if flag not in ("cli", "json", "auto"):
        err = {"error": "invalid_output_type_flag"}
        if return_envelope:
            return {"data": {}, "meta": {"device_type": dt_raw, "output_type": flag}, "error": err["error"]}
        return err

    # ---------- json forced / inferred ----------
    if flag == "json" or (flag == "auto" and isinstance(output, dict)):
        if isinstance(output, dict):
            return cisco_parse_show_mac_address_table_count_json(output, device_type=dt_raw, return_envelope=return_envelope)

        raw = "" if output is None else str(output)
        d = _json_load_dict_best_effort(raw)
        if isinstance(d, dict) and d.get("error"):
            if return_envelope:
                return {"data": {}, "meta": {"device_type": dt_raw, "output_type": "json"}, "error": str(d.get("error"))}
            return {"error": str(d.get("error"))}

        return cisco_parse_show_mac_address_table_count_json(d, device_type=dt_raw, return_envelope=return_envelope)

    # ---------- auto: try json if it looks like json ----------
    if flag == "auto" and isinstance(output, str) and output.lstrip().startswith("{"):
        d = _json_load_dict_best_effort(output)
        if isinstance(d, dict) and not d.get("error"):
            return cisco_parse_show_mac_address_table_count_json(d, device_type=dt_raw, return_envelope=return_envelope)

    # ---------- cli ----------
    if not isinstance(output, str):
        err = {"error": "invalid_payload: expected cli string"}
        if return_envelope:
            return {"data": {}, "meta": {"device_type": dt_raw, "output_type": "cli"}, "error": err["error"]}
        return err

    return cisco_parse_show_mac_address_table_count_cli(output, device_type=dt_raw, return_envelope=return_envelope)

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

def cisco_nxos_parse_show_mac_address_table_json(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Notes / How to run:
      - Input is NX-OS JSON (dict) for: `show mac address-table | json` (or json-pretty).
      - Returns:
          {
            "device_type": "cisco_nxos",
            "meta": {...},
            "normalized": {"mac_address_table": {0:{...}, 1:{...}, ...}},
            "raw": <original dict>
          }
    """

    def _boolish(v: Any) -> Optional[bool]:
        if v is None:
            return None
        s = str(v).strip().lower()
        if s in ("t", "true", "1", "yes", "y"):
            return True
        if s in ("f", "false", "0", "no", "n"):
            return False
        if s in ("-", ""):
            return None
        return None

    def _as_int(v: Any) -> Optional[int]:
        try:
            if v is None:
                return None
            s = str(v).strip()
            if s == "" or s == "-":
                return None
            return int(s)
        except Exception:
            return None

    try:
        table = data.get("TABLE_mac_address") or {}
        rows = _ensure_list(table.get("ROW_mac_address"))

        out: Dict[int, Dict[str, Any]] = {}
        i = 0

        for r in rows:
            if not isinstance(r, dict):
                continue

            mac_raw = (
                r.get("disp_mac_addr")
                or r.get("mac")
                or r.get("mac_addr")
                or r.get("mac-address")
                or r.get("mac_address")
            )
            vlan_raw = r.get("disp_vlan") or r.get("vlan") or r.get("vlan_id")
            port = r.get("disp_port") or r.get("port") or r.get("interface") or r.get("intf") or ""
            typ = r.get("disp_type") or r.get("type") or ""
            age_raw = r.get("disp_age") or r.get("age")

            if not mac_raw or not vlan_raw or not port:
                # still keep it if it has mac+port; VLAN is typically always present though
                if not mac_raw or not port:
                    continue

            mac_norm = _cisco_normalize_mac(str(mac_raw))
            vlan_i = _as_int(vlan_raw)
            age_i = _as_int(age_raw)

            out[i] = {
                "vlan": vlan_i if vlan_i is not None else str(vlan_raw).strip(),
                **mac_norm,
                "mac_raw": str(mac_raw).strip(),
                "type": str(typ).strip(),
                "interface": str(port).strip(),
                "age": str(age_raw).strip() if age_raw is not None else "",
                "age_int": age_i,
                "is_secure": _boolish(r.get("disp_is_secure")),
                "is_notify": _boolish(r.get("disp_is_ntfy")),
                "raw": r,
                "source_os": "nxos",
            }
            i += 1

        meta = {
            "device_type": "cisco_nxos",
            "detected_command": "show_mac_address_table",
            "row_count": len(out),
        }

        return {
            "device_type": "cisco_nxos",
            "meta": meta,
            "normalized": {"mac_address_table": out},
            "raw": data,
        }

    except Exception as exc:
        return {"error": f"parse_failed: cisco_nxos_show_mac_address_table_json: {type(exc).__name__}: {exc}"}




def cisco_parse_show_version_nxos_cli(output: str, *, return_envelope: bool = False) -> Dict[str, Any]:
    """
    Parse NX-OS "show version" CLI (best-effort).

    Many NX-OS devices support JSON via "| json-pretty", but some do not.
    This function is used as a fallback when JSON parsing fails or when the
    device is configured to return CLI output.

    Extracts (when present):
      - software_version (NX-OS)
      - chassis_model
      - system_serial_number
      - uptime
    """
    raw = "" if output is None else str(output)
    lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]

    data: Dict[str, Any] = {}

    # NXOS: version 10.3(8)
    for ln in lines:
        m = re.search(r"\bNXOS\s*:\s*version\s+(?P<v>\S+)", ln, flags=re.IGNORECASE)
        if m:
            data["software_version"] = m.group("v").strip()
            break

    # system: version 10.3(8)
    if not data.get("software_version"):
        for ln in lines:
            m = re.search(r"\bsystem\s*:\s*version\s+(?P<v>\S+)", ln, flags=re.IGNORECASE)
            if m:
                data["software_version"] = m.group("v").strip()
                break

    # fallback generic "Version X"
    if not data.get("software_version"):
        for ln in lines:
            m = re.search(r"\bVersion\s+(?P<v>\S+)", ln, flags=re.IGNORECASE)
            if m:
                data["software_version"] = m.group("v").strip()
                break

    # chassis model line: "cisco Nexus9000 C9300v Chassis"
    for ln in lines:
        m = re.search(r"^cisco\s+(?P<model>.+?)\s+Chassis\b", ln, flags=re.IGNORECASE)
        if m:
            data["chassis_model"] = f"cisco {m.group('model').strip()} Chassis"
            break

    # serial: "Processor Board ID FOC..."
    for ln in lines:
        m = re.search(r"^Processor\s+Board\s+ID\s+(?P<sn>\S+)$", ln, flags=re.IGNORECASE)
        if m:
            data["system_serial_number"] = m.group("sn").strip()
            break

    # uptime: "Kernel uptime is 12 day(s), 3 hour(s), 4 minute(s), 5 second(s)"
    for ln in lines:
        m = re.search(r"Kernel\s+uptime\s+is\s+(?P<uptime>.+)$", ln, flags=re.IGNORECASE)
        if m:
            data["uptime"] = m.group("uptime").strip()
            break

    if return_envelope:
        return {"data": data, "meta": {"device_type": "cisco_nxos", "detected_style": "nxos_cli"}, "error": None}

    return data

def cisco_nxos_parse_show_ip_arp_table_json(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Notes / How to run:
    - Input is NX-OS JSON (dict) for: `show ip arp | json` (or json-pretty)
    - Returns:
        {
          "device_type": "cisco_nxos",
          "meta": {...},
          "normalized": {"ip_arp_table": {0:{...}, 1:{...}, ...}},
          "raw": <original dict>
        }

    Observed NX-OS schema (example):
      {
        "TABLE_vrf": {
          "ROW_vrf": {
            "vrf-name-out": "default",
            "cnt-total": "123",
            "TABLE_adj": {
              "ROW_adj": [
                {"intf-out": "Vlan10", "ip-addr-out": "10.0.0.1", "time-stamp": "PT11S", "mac": "aabb.ccdd.eeff", "flags": null},
                {"intf-out": "Vlan10", "ip-addr-out": "10.0.0.2", "time-stamp": "PT26S", "incomplete": "true", "flags": null}
              ]
            }
          }
        }
      }
    """
    table_vrf = data.get("TABLE_vrf") or {}
    vrf_rows = _ensure_list(table_vrf.get("ROW_vrf"))

    rows_out: Dict[int, Dict[str, Any]] = {}
    count = 0
    vrf_names: List[str] = []

    for vrf in vrf_rows:
        if not isinstance(vrf, dict):
            continue

        vrf_name = (
            vrf.get("vrf-name-out")
            or vrf.get("vrf_name")
            or vrf.get("vrf-name")
            or vrf.get("vrf")
            or ""
        )
        if vrf_name and vrf_name not in vrf_names:
            vrf_names.append(str(vrf_name))

        table_adj = vrf.get("TABLE_adj") or {}
        adj_rows = _ensure_list(table_adj.get("ROW_adj"))

        for r in adj_rows:
            if not isinstance(r, dict):
                continue

            ip = r.get("ip-addr-out") or r.get("ip_addr") or r.get("ip") or r.get("address")
            if not ip:
                continue

            ip = str(ip).strip()
            try:
                if ipaddress.ip_address(ip).version != 4:
                    continue
            except Exception:
                # skip any weird tokens; NX-OS output should be IPv4 here
                continue

            intf = r.get("intf-out") or r.get("interface") or r.get("intf") or ""
            ts = r.get("time-stamp") or r.get("age") or r.get("time_stamp") or ""
            mac = r.get("mac")
            incomplete = str(r.get("incomplete") or "").strip().lower() in ("true", "1", "yes")

            if mac:
                mac_norm = _cisco_normalize_mac(str(mac))
            else:
                if not incomplete:
                    # treat as incomplete if field missing but no explicit marker
                    incomplete = True
                mac_norm = {"mac_address": "INCOMPLETE", "mac_address_condensed": ""}

            age_seconds = _nxos_duration_to_seconds(ts)

            rows_out[count] = {
                "ipv4_address": ip,
                **mac_norm,
                "interface": str(intf).strip(),
                "age": str(ts).strip(),
                "age_seconds": age_seconds,
                "flags": r.get("flags"),
                "vrf": str(vrf_name).strip(),
                "incomplete": bool(incomplete),
                "raw": r,
                "source_os": "nxos",
            }
            count += 1

    meta = {
        "device_type": "cisco_nxos",
        "detected_command": "show_ip_arp_table",
        "vrf_names": vrf_names,
        "vrf_count": len(vrf_names),
        "row_count": count,
    }

    return {
        "device_type": "cisco_nxos",
        "meta": meta,
        "normalized": {"ip_arp_table": rows_out},
        "raw": data,
    }


def cisco_parse_show_version_nxos_cli(output: str, *, return_envelope: bool = False) -> Dict[str, Any]:
    """
    Parse NX-OS "show version" CLI (best-effort).

    Extracts (when present):
      - software_version (NX-OS)
      - chassis_model
      - system_serial_number
      - uptime
    """
    raw = "" if output is None else str(output)
    lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]

    data: Dict[str, Any] = {}

    error_markers = (
        "Invalid input detected",
        "% Invalid input",
        "Incomplete command",
        "Ambiguous command",
        "Unknown command",
    )
    parse_error = "command_not_supported_or_invalid" if any(m in raw for m in error_markers) else None

    # NXOS: version 10.3(8)  OR  NX-OS: version 10.3(8)
    for ln in lines:
        m = re.search(r"\bNX-?OS\b\s*:\s*version\s+(?P<v>\S+)", ln, flags=re.IGNORECASE)
        if m:
            data["software_version"] = m.group("v").strip()
            break

    # system: version 10.3(8)
    if not data.get("software_version"):
        for ln in lines:
            m = re.search(r"\bsystem\s*:\s*version\s+(?P<v>\S+)", ln, flags=re.IGNORECASE)
            if m:
                data["software_version"] = m.group("v").strip()
                break

    # fallback generic "Version X"
    if not data.get("software_version"):
        for ln in lines:
            m = re.search(r"\bVersion\s+(?P<v>\S+)", ln, flags=re.IGNORECASE)
            if m:
                data["software_version"] = m.group("v").strip()
                break

    # chassis model line: "cisco Nexus9000 C9300v Chassis"
    for ln in lines:
        m = re.search(r"^cisco\s+(?P<model>.+?)\s+Chassis\b", ln, flags=re.IGNORECASE)
        if m:
            data["chassis_model"] = f"cisco {m.group('model').strip()} Chassis"
            break

    # serial: "Processor Board ID FOC..."
    for ln in lines:
        m = re.search(r"^Processor\s+Board\s+ID\s+(?P<sn>\S+)$", ln, flags=re.IGNORECASE)
        if m:
            data["system_serial_number"] = m.group("sn").strip()
            break

    # uptime: "Kernel uptime is ..."
    for ln in lines:
        m = re.search(r"Kernel\s+uptime\s+is\s+(?P<uptime>.+)$", ln, flags=re.IGNORECASE)
        if m:
            data["uptime"] = m.group("uptime").strip()
            break

    if return_envelope:
        return {"data": data, "meta": {"device_type": "cisco_nxos", "detected_style": "nxos_cli"}, "error": parse_error}

    return data if not parse_error else {"error": parse_error, **data}


def cisco_nxos_parse_show_cdp_neighbors_json(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Notes / How to run:
    - Input is NX-OS JSON (dict) for: show cdp neighbors | json / json-pretty
    - Returns:
        {
          "device_type": "cisco_nxos",
          "meta": {...},
          "normalized": {"neighbors": {0:{...}, 1:{...}, ...}},
          "raw": <original dict>
        }
    """
    table = data.get("TABLE_cdp_neighbor_brief_info") or {}
    rows_in = _ensure_list(table.get("ROW_cdp_neighbor_brief_info"))

    neighbors: Dict[int, Dict[str, Any]] = {}
    for i, row in enumerate(rows_in):
        caps = row.get("capability")
        if isinstance(caps, str):
            caps_list = [caps]
        elif isinstance(caps, list):
            caps_list = [str(x) for x in caps if x is not None]
        else:
            caps_list = []

        dev_id = _split_device_id_paren(row.get("device_id"))

        neighbors[i] = {
            "device_id": dev_id,  # raw/name/serial split
            "local_interface": _as_str(row.get("intf_id")),
            "hold_time": _as_int(row.get("ttl")),
            "capability": caps_list,
            "platform": _as_str(row.get("platform_id")),
            "port_id": _as_str(row.get("port_id")),
            "ifindex": _as_int(row.get("ifindex")),
            "source_os": "cisco_nxos",
        }

    declared = _as_int(data.get("neigh_count"))
    return {
        "device_type": "cisco_nxos",
        "meta": {
            "detected_command": "show_cdp_neighbors",
            "count": len(neighbors),
            "declared_count": declared,
        },
        "normalized": {"neighbors": neighbors},
        "raw": data,
    }

# Parse lldp neighbor output data from an nxos device.
# The data should be in json format from the switches
def cisco_nxos_parse_show_lldp_neighbors_json(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Notes / How to run:
    - Input is NX-OS JSON (dict) for: show lldp neighbors | json / json-pretty
      (your payload uses TABLE_nbor/ROW_nbor)
    """
    table = data.get("TABLE_nbor") or {}
    rows_in = _ensure_list(table.get("ROW_nbor"))

    neighbors: Dict[int, Dict[str, Any]] = {}
    for i, row in enumerate(rows_in):
        chassis_id = _as_str(row.get("chassis_id"))
        chassis_norm = _cisco_normalize_mac(chassis_id) if chassis_id and _MAC_TOKEN.match(chassis_id) else None

        port_id = _as_str(row.get("port_id"))
        port_norm = _cisco_normalize_mac(port_id) if port_id and _MAC_TOKEN.match(port_id) else None

        mgmt_type = _as_str(row.get("mgmt_addr_type"))
        mgmt_addr = _none_if_not_advertised(row.get("mgmt_addr"))

        mgmt: Dict[str, Any] = {"type": mgmt_type, "raw": mgmt_addr}
        if mgmt_type and mgmt_type.upper() == "IPV4":
            mgmt["ipv4"] = mgmt_addr
        elif mgmt_type and mgmt_type.upper() in {"802", "MAC", "MAC_ADDRESS"}:
            mgmt["mac"] = _cisco_normalize_mac(mgmt_addr) if mgmt_addr and _MAC_TOKEN.match(mgmt_addr) else None

        mgmt6_type = _as_str(row.get("mgmt_addr_ipv6_type"))
        mgmt6_addr = _none_if_not_advertised(row.get("mgmt_addr_ipv6"))

        mgmt6: Dict[str, Any] = {"type": mgmt6_type, "raw": mgmt6_addr}
        if mgmt6_type and mgmt6_type.upper() == "IPV6":
            mgmt6["ipv6"] = mgmt6_addr
        elif mgmt6_type and mgmt6_type.upper() in {"802", "MAC", "MAC_ADDRESS"}:
            mgmt6["mac"] = _cisco_normalize_mac(mgmt6_addr) if mgmt6_addr and _MAC_TOKEN.match(mgmt6_addr) else None

        neighbors[i] = {
            "chassis_type": _as_str(row.get("chassis_type")),
            "chassis_id": chassis_id,
            "chassis_id_norm": chassis_norm,
            "local_interface": _as_str(row.get("l_port_id")),
            "hold_time": _as_int(row.get("hold_time")),
            "system_capability": _as_str(row.get("system_capability")),
            "enabled_capability": _as_str(row.get("enabled_capability")),
            "port_type": _as_str(row.get("port_type")),
            "port_id": port_id,
            "port_id_norm": port_norm,
            "mgmt": mgmt,
            "mgmt_ipv6": mgmt6,
            "source_os": "cisco_nxos",
        }

    declared = _as_int(data.get("neigh_count"))
    return {
        "device_type": "cisco_nxos",
        "meta": {
            "detected_command": "show_lldp_neighbors",
            "count": len(neighbors),
            "declared_count": declared,
        },
        "normalized": {"neighbors": neighbors},
        "raw": data,
    }

def cisco_nxos_parse_show_interface_description_json(
    data: Dict[str, Any],
    *,
    return_envelope: bool = True,
) -> Dict[str, Any]:
    """
    Notes / How to run:
      - Input: NX-OS JSON dict from `show interface description | json`
      - Example:
            payload_path = Path("test_payloads") / "test_nxos_show_interface_description.json"
            raw = payload_path.read_text(encoding="utf-8")
            parsed = cisco_parse_device_json_from_string("cisco_nxos", raw)
            # OR:
            data = json.loads(raw)
            parsed = cisco_nxos_parse_show_interface_description_json(data)

    Returns:
      - If return_envelope:
          {"rows": {0: {...}, ...}, "meta": {...}, "error": None}
      - Else:
          rows dict, or {"error": "..."} if parse_error
    """
    table = data.get("TABLE_interface") or {}
    rows_in = _ensure_list(table.get("ROW_interface"))

    rows: Dict[int, Dict[str, Any]] = {}
    interfaces: Dict[str, Dict[str, Any]] = {}

    count = 0
    for row in rows_in:
        ifname = _as_str(row.get("interface"))
        if not ifname:
            continue

        entry = {
            "interface": ifname,
            "interface_short": _cisco_short_ifname(ifname),
            "type": _as_str(row.get("type")),
            "speed": _as_str(row.get("speed")),
            "description": _as_str(row.get("desc")),
            "source_os": "cisco_nxos",
            "raw_row": row,
        }
        rows[count] = entry
        interfaces[ifname] = entry
        count += 1

    meta = {
        "detected_style": "nxos_json",
        "detected_command": "show_interface_description",
        "count": count,
        "has_table_interface": bool(rows_in),
    }

    out = {
        "rows": rows,
        "interfaces": interfaces,  # convenient lookup by exact interface name
        "meta": meta,
        "error": None,
    }
    return out if return_envelope else (rows if rows else {})

def _parse_cisco_nxos_auto(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Auto-detect which NX-OS JSON blob we got (show version vs neighbors) and dispatch.
    Keeps your call style: parse_device_json("cisco_nxos", data)
    """

    if "TABLE_cdp_neighbor_brief_info" in data:
        return cisco_nxos_parse_show_cdp_neighbors_json(data)

    if "TABLE_nbor" in data:
        return cisco_nxos_parse_show_lldp_neighbors_json(data)

    # NX-OS: show interface description | json
    if "TABLE_interface" in data and isinstance(data.get("TABLE_interface"), dict):
        tab = data.get("TABLE_interface") or {}
        if "ROW_interface" in tab:
            return cisco_nxos_parse_show_interface_description_json(data)

    # NX-OS: show ip arp | json
    if "TABLE_vrf" in data and isinstance(data.get("TABLE_vrf"), dict):
        tab = data.get("TABLE_vrf") or {}
        if "ROW_vrf" in tab:
            # NX-OS uses TABLE_adj/ROW_adj for ARP entries
            return cisco_nxos_parse_show_ip_arp_table_json(data)

    # fallback: original show version parser signature (your keys like nxos_ver_str, etc.)
    if any(k in data for k in ("nxos_ver_str", "kickstart_ver_str", "chassis_id", "host_name")):
        return _parse_cisco_nxos_show_version(data)

    return {
        "error": "unsupported_nxos_json_schema",
        "hint": "Expected NX-OS JSON keys for show version, show cdp neighbors, or show lldp neighbors.",
        "keys": sorted(list(data.keys()))[:50],
    }

def cisco_parse_device_json_from_string(device_type: str, output: Union[str, Dict[str, Any]]) -> Dict[str, Any]:
    if isinstance(output, dict):
        return parse_device_json(device_type, output)
    if not isinstance(output, str) or not output.strip():
        return {"error": "invalid_payload: expected non-empty json string or dict"}

    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        try:
            fixed = _escape_controls_inside_json_strings(output)
            data = json.loads(fixed)
        except Exception as e:
            return {"error": f"invalid_json: {type(e).__name__}: {e}"}

    if not isinstance(data, dict):
        return {"error": "invalid_payload: expected JSON object"}

    return parse_device_json(device_type, data)


def _extract_nxos_packages(table_pkg: Any) -> List[str]:
    """
    NX-OS JSON often looks like:
      "TABLE_package_list": {"ROW_package_list": {"package_id": null}}
    but can also be a list of rows or missing.
    """
    rows = None
    if isinstance(table_pkg, dict):
        rows = table_pkg.get("ROW_package_list")

    pkg_ids: List[str] = []

    if isinstance(rows, dict):
        pid = rows.get("package_id")
        s = _as_str(pid)
        if s:
            pkg_ids.append(s)

    elif isinstance(rows, list):
        for row in rows:
            if isinstance(row, dict):
                s = _as_str(row.get("package_id"))
                if s:
                    pkg_ids.append(s)

    return pkg_ids

# -----------------------------
# Cisco NX-OS parser
# -----------------------------

def _parse_cisco_nxos_show_version(data: Dict[str, Any]) -> Dict[str, Any]:
    # Core strings
    hostname = _as_str(data.get("host_name"))
    manufacturer = _as_str(data.get("manufacturer"))
    chassis = _as_str(data.get("chassis_id"))
    module = _as_str(data.get("module_id"))

    # Versions / images
    bios_ver = _as_str(data.get("bios_ver_str"))
    kick_ver = _as_str(data.get("kickstart_ver_str"))
    nxos_ver = _as_str(data.get("nxos_ver_str"))
    release_type = _as_str(data.get("release_type"))

    kick_image = _as_str(data.get("kick_file_name"))
    nxos_image = _as_str(data.get("nxos_file_name"))

    # Compile / timestamps (keep raw + parsed best-effort)
    bios_compile_raw = _as_str(data.get("bios_cmpl_time"))
    kick_compile_raw = _as_str(data.get("kick_cmpl_time"))
    nxos_compile_raw = _as_str(data.get("nxos_cmpl_time"))

    kick_ts_raw = _as_str(data.get("kick_tmstmp"))
    nxos_ts_raw = _as_str(data.get("nxos_tmstmp"))

    # HW / resources
    cpu = _as_str(data.get("cpu_name"))
    mem_raw = _as_str(data.get("memory"))
    mem_type = _as_str(data.get("mem_type"))  # e.g. "kB"
    mem_kb = _as_int(mem_raw)

    bootflash_raw = _as_str(data.get("bootflash_size"))
    bootflash_bytes = _as_int(bootflash_raw)

    serial = _as_str(data.get("proc_board_id"))

    # Uptime
    up_days = _as_int(_as_str(data.get("kern_uptm_days")))
    up_hrs = _as_int(_as_str(data.get("kern_uptm_hrs")))
    up_mins = _as_int(_as_str(data.get("kern_uptm_mins")))
    up_secs = _as_int(_as_str(data.get("kern_uptm_secs")))
    uptime_total_seconds = _uptime_to_seconds(up_days, up_hrs, up_mins, up_secs)

    # Reset / reload info
    rr_ctime_raw = _as_str(data.get("rr_ctime"))
    rr_usecs = _as_int(_as_str(data.get("rr_usecs")))
    rr_reason = _as_str(data.get("rr_reason"))
    rr_sys_ver = _as_str(data.get("rr_sys_ver"))
    rr_service = data.get("rr_service")  # may be null

    plugins = _as_str(data.get("plugins"))

    # Packages table can be dict, list, empty, etc.
    packages = _extract_nxos_packages(data.get("TABLE_package_list"))

    # Keep the entire original blob too (so you truly "return everything")
    # while also providing normalized fields.
    out: Dict[str, Any] = {
        "device_type": "cisco_nxos",
        "normalized": {
            "hostname": hostname,
            "manufacturer": manufacturer,
            "chassis": chassis,
            "module": module,
            "serial": serial,
            "cpu": cpu,
            "memory": {
                "value_raw": mem_raw,
                "unit_raw": mem_type,
                "kb": mem_kb,
                "bytes": (mem_kb * 1024) if mem_kb is not None and (mem_type or "").lower() == "kb" else None,
            },
            "bootflash": {
                "bytes_raw": bootflash_raw,
                "bytes": bootflash_bytes,
            },
            "software": {
                "release_type": release_type,
                "versions": {
                    "bios": bios_ver,
                    "kickstart": kick_ver,
                    "nxos": nxos_ver,
                },
                "images": {
                    "kickstart": kick_image,
                    "nxos": nxos_image,
                },
                "times": {
                    "bios_compile_time": _parse_dt_best_effort(bios_compile_raw),
                    "kick_compile_time": _parse_dt_best_effort(kick_compile_raw),
                    "nxos_compile_time": _parse_dt_best_effort(nxos_compile_raw),
                    "kick_timestamp": _parse_dt_best_effort(kick_ts_raw),
                    "nxos_timestamp": _parse_dt_best_effort(nxos_ts_raw),
                },
            },
            "uptime": {
                "days": up_days,
                "hours": up_hrs,
                "minutes": up_mins,
                "seconds": up_secs,
                "total_seconds": uptime_total_seconds,
            },
            "reset_reason": {
                "rr_ctime": _parse_dt_best_effort(rr_ctime_raw),
                "rr_usecs": rr_usecs,
                "rr_reason": rr_reason,
                "rr_sys_ver": rr_sys_ver,
                "rr_service": rr_service,
            },
            "plugins": plugins,
            "packages": packages,
        },
        "raw": data,
    }

    return out

_PARSERS: Dict[str, Callable[[Dict[str, Any]], Dict[str, Any]]] = {
    "cisco_nxos": _parse_cisco_nxos_auto,
}

def parse_device_json(device_type: str, data: Any) -> Dict[str, Any]:
    """
    Parse structured (JSON) command output from a network device into a normalized dict.

    Notes / How to run:
      1) Put this in a helpers module, e.g. `app/helpers_device_parsers.py`
      2) Call it with the device_type and the decoded JSON dict:
           parsed = parse_device_json("cisco_nxos", nxos_json_dict)
      3) On success you get a normalized dict. On failure you get:
           {"error": "<message>"}

    Supported device_type values (normalized):
      - cisco_nxos (aliases: "cisco nx_os", "nxos", "nx_os", "cisco-nxos")
    """
    if not isinstance(device_type, str) or not device_type.strip():
        return {"error": "missing_required_fields: device_type"}

    dev = cisco_normalize_device_type(device_type)
    if dev is None:
        return {"error": "invalid_device_type"}

    if not isinstance(data, dict):
        return {"error": "invalid_payload: expected dict (decoded JSON object)"}

    parser = _PARSERS.get(dev)
    if not parser:
        return {"error": f"unsupported_device_type: {dev}"}

    try:
        return parser(data)
    except Exception as e:
        # Keep this intentionally non-verbose; upstream can log exception details.
        return {"error": f"parse_failed: {dev}: {type(e).__name__}: {e}"}


# -----------------------------
# Cisco NX-OS parser
# -----------------------------

def _parse_cisco_nxos_show_version(data: Dict[str, Any]) -> Dict[str, Any]:
    # Core strings
    hostname = _as_str(data.get("host_name"))
    manufacturer = _as_str(data.get("manufacturer"))
    chassis = _as_str(data.get("chassis_id"))
    module = _as_str(data.get("module_id"))

    # Versions / images
    bios_ver = _as_str(data.get("bios_ver_str"))
    kick_ver = _as_str(data.get("kickstart_ver_str"))
    nxos_ver = _as_str(data.get("nxos_ver_str"))
    release_type = _as_str(data.get("release_type"))

    kick_image = _as_str(data.get("kick_file_name"))
    nxos_image = _as_str(data.get("nxos_file_name"))

    # Compile / timestamps (keep raw + parsed best-effort)
    bios_compile_raw = _as_str(data.get("bios_cmpl_time"))
    kick_compile_raw = _as_str(data.get("kick_cmpl_time"))
    nxos_compile_raw = _as_str(data.get("nxos_cmpl_time"))

    kick_ts_raw = _as_str(data.get("kick_tmstmp"))
    nxos_ts_raw = _as_str(data.get("nxos_tmstmp"))

    # HW / resources
    cpu = _as_str(data.get("cpu_name"))
    mem_raw = _as_str(data.get("memory"))
    mem_type = _as_str(data.get("mem_type"))  # e.g. "kB"
    mem_kb = _as_int(mem_raw)

    bootflash_raw = _as_str(data.get("bootflash_size"))
    bootflash_bytes = _as_int(bootflash_raw)

    serial = _as_str(data.get("proc_board_id"))

    # Uptime
    up_days = _as_int(_as_str(data.get("kern_uptm_days")))
    up_hrs = _as_int(_as_str(data.get("kern_uptm_hrs")))
    up_mins = _as_int(_as_str(data.get("kern_uptm_mins")))
    up_secs = _as_int(_as_str(data.get("kern_uptm_secs")))
    uptime_total_seconds = _uptime_to_seconds(up_days, up_hrs, up_mins, up_secs)

    # Reset / reload info
    rr_ctime_raw = _as_str(data.get("rr_ctime"))
    rr_usecs = _as_int(_as_str(data.get("rr_usecs")))
    rr_reason = _as_str(data.get("rr_reason"))
    rr_sys_ver = _as_str(data.get("rr_sys_ver"))
    rr_service = data.get("rr_service")  # may be null

    plugins = _as_str(data.get("plugins"))

    # Packages table can be dict, list, empty, etc.
    packages = _extract_nxos_packages(data.get("TABLE_package_list"))

    # Keep the entire original blob too (so you truly "return everything")
    # while also providing normalized fields.
    out: Dict[str, Any] = {
        "device_type": "cisco_nxos",
        "normalized": {
            "hostname": hostname,
            "manufacturer": manufacturer,
            "chassis": chassis,
            "module": module,
            "serial": serial,
            "cpu": cpu,
            "memory": {
                "value_raw": mem_raw,
                "unit_raw": mem_type,
                "kb": mem_kb,
                "bytes": (mem_kb * 1024) if mem_kb is not None and (mem_type or "").lower() == "kb" else None,
            },
            "bootflash": {
                "bytes_raw": bootflash_raw,
                "bytes": bootflash_bytes,
            },
            "software": {
                "release_type": release_type,
                "versions": {
                    "bios": bios_ver,
                    "kickstart": kick_ver,
                    "nxos": nxos_ver,
                },
                "images": {
                    "kickstart": kick_image,
                    "nxos": nxos_image,
                },
                "times": {
                    "bios_compile_time": _parse_dt_best_effort(bios_compile_raw),
                    "kick_compile_time": _parse_dt_best_effort(kick_compile_raw),
                    "nxos_compile_time": _parse_dt_best_effort(nxos_compile_raw),
                    "kick_timestamp": _parse_dt_best_effort(kick_ts_raw),
                    "nxos_timestamp": _parse_dt_best_effort(nxos_ts_raw),
                },
            },
            "uptime": {
                "days": up_days,
                "hours": up_hrs,
                "minutes": up_mins,
                "seconds": up_secs,
                "total_seconds": uptime_total_seconds,
            },
            "reset_reason": {
                "rr_ctime": _parse_dt_best_effort(rr_ctime_raw),
                "rr_usecs": rr_usecs,
                "rr_reason": rr_reason,
                "rr_sys_ver": rr_sys_ver,
                "rr_service": rr_service,
            },
            "plugins": plugins,
            "packages": packages,
        },
        "raw": data,
    }

    return out




























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







































# Leaving for local testing of functions
if __name__ == "__main__":
    # I did not include test files in the git repo, you can build your own to test
    # against. They should live here
    # backend/app/fastapi/app/shared_functions/helpers/test_payloads/test_nxos_show_cdp_neighbors.json
    # backend/app/fastapi/app/shared_functions/helpers/test_payloads/test_nxos_show_lldp_neighbors.json
    # backend/app/fastapi/app/shared_functions/helpers/test_payloads/test_nxos_show_version.json
    # backend/app/fastapi/app/shared_functions/helpers/test_payloads/test_nxos_show_interface_description.json
    # backend/app/fastapi/app/shared_functions/helpers/test_payloads/test_nxos_show_ip_arp.json
    # backend/app/fastapi/app/shared_functions/helpers/test_payloads/test_nxos_show_mac_address.json

    #payload_path = Path("test_payloads") / "test_nxos_show_version.json"
    #output = payload_path.read_text(encoding="utf-8")
    #parsed = cisco_parse_device_json_from_string("cisco_nxos", output)
    #print(json.dumps(parsed, indent=2))

    #payload_path = Path("test_payloads") / "test_nxos_show_cdp_neighbors.json"
    #output = payload_path.read_text(encoding="utf-8")
    #parsed = cisco_parse_device_json_from_string("cisco_nxos", output)
    #print(json.dumps(parsed, indent=2))

    #payload_path = Path("test_payloads") / "test_nxos_show_lldp_neighbors.json"
    #output = payload_path.read_text(encoding="utf-8")
    #parsed = cisco_parse_device_json_from_string("cisco_nxos", output)
    #print(json.dumps(parsed, indent=2))

    #payload_path = Path("test_payloads") / "test_nxos_show_interface_description.json"
    #output = payload_path.read_text(encoding="utf-8")
    #parsed = cisco_parse_device_json_from_string("cisco_nxos", output)
    #print(json.dumps(parsed, indent=2))

    #payload_path = Path("test_payloads") / "test_nxos_show_ip_arp.json"
    #output = payload_path.read_text(encoding="utf-8")
    #print(output)
    #parsed = cisco_parse_show_ip_arp_table_auto("cisco_nxos", output, "json")
    #print(json.dumps(parsed, indent=2))

    #payload_path = Path("test_payloads") / "test_nxos_show_mac_address.json"
    #output = payload_path.read_text(encoding="utf-8")
    #print(output)
    #parsed = cisco_parse_show_mac_address_table_auto("cisco_nxos", output, "json")
    #print(json.dumps(parsed, indent=2))

    output = """
Mac Address Table\n-------------------------------------------\n\nVlan Mac Address Type Ports\n---- ----------- -------- -----\n All 0100.0ccc.cccc STATIC CPU\n All 0100.0ccc.cccd STATIC CPU\n All 0180.c200.0000 STATIC CPU\n All 0180.c200.0001 STATIC CPU\n All 0180.c200.0002 STATIC CPU\n All 0180.c200.0003 STATIC CPU\n All 0180.c200.0004 STATIC CPU\n All 0180.c200.0005 STATIC CPU\n All 0180.c200.0006 STATIC CPU\n All 0180.c200.0007 STATIC CPU\n All 0180.c200.0008 STATIC CPU\n All 0180.c200.0009 STATIC CPU\n All 0180.c200.000a STATIC CPU\n All 0180.c200.000b STATIC CPU\n All 0180.c200.000c STATIC CPU\n All 0180.c200.000d STATIC CPU\n All 0180.c200.000e STATIC CPU\n All 0180.c200.000f STATIC CPU\n All 0180.c200.0010 STATIC CPU\n All 0180.c200.0021 STATIC CPU\n All ffff.ffff.ffff STATIC CPU\n 1 84eb.efd9.9381 DYNAMIC Po1\n 10 000c.2920.ebc4 DYNAMIC Te1/0/15\n 10 001d.a2cf.bf08 DYNAMIC Te1/0/10\n 10 00c0.b7d8.afb0 DYNAMIC Te1/0/13\n 10 00c0.b7d8.afb1 DYNAMIC Te1/0/14\n 10 00e4.21c0.bd5f DYNAMIC Te1/0/21\n 10 0c75.bd90.f746 STATIC Vl10 \n 10 0ec1.b0ce.2706 DYNAMIC Te1/0/22\n 10 1020.ba3d.ccb8 DYNAMIC Te1/0/21\n 10 1498.775b.71e3 DYNAMIC Te1/0/15\n 10 18cc.18dd.1eea DYNAMIC Te1/0/21\n 10 18e8.29bf.0a34 DYNAMIC Te1/0/24\n 10 3cef.8c96.e934 DYNAMIC Te1/0/1\n 10 3cef.8c96.ea86 DYNAMIC Te1/0/11\n 10 4831.7703.5578 DYNAMIC Te1/0/22\n 10 4c11.bff5.0360 DYNAMIC Te1/0/21\n 10 603e.5f4d.f1f6 DYNAMIC Te1/0/21\n 10 7483.c202.c627 DYNAMIC Te1/0/22\n 10 8095.3a9f.06d8 DYNAMIC Te1/0/21\n 10 8ae1.f974.815d DYNAMIC Te1/0/22\n 10 9c8e.cd00.1cdb DYNAMIC Te1/0/8\n 10 9c8e.cd19.407a DYNAMIC Te1/0/5\n 10 9c8e.cd21.b298 DYNAMIC Te1/0/18\n 10 9c8e.cd2b.bb6a DYNAMIC Te1/0/2\n 10 9c8e.cd2b.bb80 DYNAMIC Te1/0/3\n 10 9c8e.cd2b.bb83 DYNAMIC Te1/0/6\n 10 9c8e.cd2b.bb87 DYNAMIC Te1/0/4\n 10 9c8e.cd2d.0c35 DYNAMIC Te1/0/17\n 10 e063.da30.fb4a DYNAMIC Te1/0/21\n 10 e063.da3c.c279 DYNAMIC Te1/0/22\n 440 0c75.bd90.f75d STATIC Vl440 \n 440 84eb.efd9.9381 DYNAMIC Po1\n 500 0c75.bd90.f750 STATIC Vl500 \n1000 0c75.bd90.f75f STATIC Vl1000 \n1000 18e8.29bf.0a35 DYNAMIC Te1/0/9\n1000 84eb.efd9.93df DYNAMIC Po1\nTotal Mac Addresses for this criterion: 57
    """
    print(cisco_parse_show_mac_address_table_auto('cisco_xe', output, 'cli', return_envelope=True))
    print(cisco_parse_show_mac_address_table_cli(output, device_type='cisco_xe', return_envelope=True))