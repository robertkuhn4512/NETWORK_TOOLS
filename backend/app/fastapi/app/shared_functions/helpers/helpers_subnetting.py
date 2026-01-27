from __future__ import annotations

import json
import ipaddress


# Subnetting
def cidr_to_netmask(cidr: str):
    """
    Convert an IPv4 CIDR (e.g. "1.1.1.1/16") into a dotted-decimal subnet mask.

    :param cidr: IPv4 address in CIDR notation
    :return: Subnet mask as dotted-decimal string, or False if input is invalid
    """
    try:
        addr, prefix_str = cidr.split('/')
        prefix = int(prefix_str)
        if prefix < 0 or prefix > 32:
            return False
    except Exception:
        return False

    # Build a 32-bit mask with top `prefix` bits set
    mask_int = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    return '.'.join(str((mask_int >> offset) & 0xFF) for offset in (24, 16, 8, 0))

def expand_ipv4_targets_max_value(cidr: str) -> tuple[str, list[str]]:
    net = ipaddress.ip_network(cidr.strip(), strict=False)

    if net.version != 4:
        raise ValueError("Only IPv4 is supported")

    # /20 max means prefixlen must be >= 20
    if net.prefixlen < 20:
        raise ValueError("Max subnet size is /20")

    cidr_norm = str(net)

    # Iterating an IPv4Network yields *all* addresses in the range,
    # including network and broadcast
    return cidr_norm, [str(ip) for ip in net]

