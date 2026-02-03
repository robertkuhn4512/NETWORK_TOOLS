from __future__ import annotations

import re
import json
import logging
import ipaddress
import sys
import os
import time
import binascii
import asyncio
import struct
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union, Mapping
from pysnmp.proto.rfc1902 import ObjectIdentifier
from pysnmp.hlapi.v3arch.asyncio import (
    SnmpEngine,
    UdpTransportTarget,
    ContextData,
    CommunityData,
    UsmUserData,
    ObjectType,
    ObjectIdentity,
    get_cmd,
    bulk_walk_cmd,
    # Common protocol constants (you can pass raw OIDs too)
    usmNoAuthProtocol,
    usmNoPrivProtocol,
    usmHMACMD5AuthProtocol,
    usmHMACSHAAuthProtocol,
    usmDESPrivProtocol,
    usm3DESEDEPrivProtocol,
    usmAesCfb128Protocol,
    usmAesCfb192Protocol,
    usmAesCfb256Protocol,
)

ProtocolRaw = Optional[Union[str, Tuple[int, ...], List[int], ObjectIdentifier]]


from typing import Iterable, Any, Dict, List, Optional, Tuple, Union

logger = logging.getLogger(__name__)

"""
Pre compile regex statements
"""

_dot_regex = re.compile(r"^\..*")


def _to_object_types(oids: Iterable[OidLike]) -> list[ObjectType]:
    out: list[ObjectType] = []
    for oid in oids:
        if isinstance(oid, ObjectType):
            out.append(oid)
        elif isinstance(oid, ObjectIdentity):
            out.append(ObjectType(oid))
        else:
            out.append(ObjectType(ObjectIdentity(str(oid))))
    return out

def _oid_to_numeric_dot(oid_obj: Any) -> str:
    """
    Always return numeric OID with leading dot, e.g. ".1.3.6.1.2.1.1.1.0"
    """
    try:
        tup = oid_obj.asTuple()
        return "." + ".".join(str(int(x)) for x in tup)
    except Exception:
        try:
            s = oid_obj.prettyPrint()
        except Exception:
            s = str(oid_obj)
        return "." + str(s).lstrip(".")

"""
This is used because the snmpv3 credentials are saved inside the vault instance as a string that resembles
the protocols pysnmp is looking for. This will convert them into usable data tuples.
"""

def _parse_protocol(raw: ProtocolRaw, *, kind: str) -> ObjectIdentifier:
    """
    kind: "auth" or "priv"
    Accepts:
      - None -> default
      - ObjectIdentifier -> as-is
      - tuple/list ints -> converted to dotted OID
      - "(1,3,6,...)" string -> parsed
      - "1.3.6...." string -> parsed
      - friendly names: auth: none|md5|sha|sha1 ; priv: none|des|3des|aes|aes128|aes192|aes256
    """
    if raw is None:
        return usmNoAuthProtocol if kind == "auth" else usmNoPrivProtocol

    if isinstance(raw, ObjectIdentifier):
        return raw

    if isinstance(raw, (tuple, list)):
        dotted = ".".join(str(int(x)) for x in raw)
        return ObjectIdentifier(dotted)

    s = str(raw).strip()
    if not s:
        return usmNoAuthProtocol if kind == "auth" else usmNoPrivProtocol

    if s.startswith("(") and s.endswith(")"):
        inner = s[1:-1].strip()
        parts = [p.strip() for p in inner.split(",") if p.strip()]
        if not parts:
            return usmNoAuthProtocol if kind == "auth" else usmNoPrivProtocol
        dotted = ".".join(str(int(p)) for p in parts)
        return ObjectIdentifier(dotted)

    sl = s.lower()

    if all(ch.isdigit() or ch == "." for ch in sl):
        return ObjectIdentifier(sl)

    if kind == "auth":
        auth_map = {
            "none": usmNoAuthProtocol,
            "md5": usmHMACMD5AuthProtocol,
            "sha": usmHMACSHAAuthProtocol,
            "sha1": usmHMACSHAAuthProtocol,
        }
        if sl in auth_map:
            return auth_map[sl]
    else:
        priv_map = {
            "none": usmNoPrivProtocol,
            "des": usmDESPrivProtocol,
            "3des": usm3DESEDEPrivProtocol,
            "aes": usmAesCfb128Protocol,
            "aes128": usmAesCfb128Protocol,
            "aes192": usmAesCfb192Protocol,
            "aes256": usmAesCfb256Protocol,
        }
        if sl in priv_map:
            return priv_map[sl]

    raise ValueError(f"Unsupported {kind}Protocol value: {raw!r}")


def _extract_v2_communities(snmp_v2: Any) -> List[str]:
    """
    Accepts:
      - {"string": ["public", "private"]}
      - ["public", "private"]
      - "public"
    """
    if snmp_v2 is None:
        return []
    if isinstance(snmp_v2, str):
        s = snmp_v2.strip()
        return [s] if s else []
    if isinstance(snmp_v2, list):
        out = []
        for x in snmp_v2:
            if x is None:
                continue
            s = str(x).strip()
            if s:
                out.append(s)
        return out
    if isinstance(snmp_v2, dict):
        vals = snmp_v2.get("string")
        return _extract_v2_communities(vals)
    return []

def _iter_v3_profiles(snmp_v3: Any) -> Iterable[Tuple[str, Mapping[str, Any]]]:
    """
    Accepts:
      - {"profile_name": { ...fields... }, "profile2": {...}}
    """
    if not snmp_v3:
        return []
    if isinstance(snmp_v3, dict):
        return list(snmp_v3.items())
    return []

def _build_usm_user_data(profile: Mapping[str, Any]) -> Union[UsmUserData, Dict[str, str]]:
    """
    Profile fields expected (your schema):
      - UsmUserData_username
      - UsmUserData_password   (authKey)
      - private_key            (privKey)
      - authProtocol           (OID / "(1,3,...)" / friendly)
      - privProtocol           (OID / "(1,3,...)" / friendly)
    """
    username = (profile.get("UsmUserData_username") or profile.get("username") or "").strip()
    password = profile.get("UsmUserData_password") or profile.get("password") or profile.get("authKey")
    priv_key = profile.get("private_key") or profile.get("privKey")

    if not username:
        return {"error": "missing_v3_username"}

    # parse protocols (or defaults)
    try:
        auth_proto = _parse_protocol(profile.get("authProtocol"), kind="auth")
        priv_proto = _parse_protocol(profile.get("privProtocol"), kind="priv")
    except Exception as e:
        return {"error": f"invalid_protocol: {e}"}

    # auto-normalize if keys not provided
    auth_key = str(password) if password not in (None, "") else None
    privKey = str(priv_key) if priv_key not in (None, "") else None
    if auth_key is None:
        auth_proto = usmNoAuthProtocol
    if privKey is None:
        priv_proto = usmNoPrivProtocol

    return UsmUserData(
        userName=str(username),
        authKey=auth_key,
        privKey=privKey,
        authProtocol=auth_proto,
        privProtocol=priv_proto,
    )

def decimalToHexadecimal(decimal):
    conversion_table = {0: '0', 1: '1', 2: '2', 3: '3', 4: '4',
                        5: '5', 6: '6', 7: '7',
                        8: '8', 9: '9', 10: 'A', 11: 'B', 12: 'C',
                        13: 'D', 14: 'E', 15: 'F'}

    hexadecimal = ''
    if decimal == 0:
        value = str(0).zfill(2)
        return value
    else:
        while (decimal > 0):
            remainder = decimal % 16
            hexadecimal = conversion_table[remainder] + hexadecimal
            decimal = decimal // 16
        return hexadecimal.zfill(2)

def construct_object_types(list_of_oids):
    object_types = []
    for oid in list_of_oids:
        object_types.append(hlapi.ObjectType(hlapi.ObjectIdentity(oid)))
    return object_types



def convertDecToHex(dec):
    mac = []
    mac_address = dec.split('.')
    for i in range(len(mac_address)):
        output = decimalToHexadecimal(int(mac_address[i]))
        mac.append(output)
    mac = ':'.join(mac)
    return mac

def _suffix_to_macs(suffix: str) -> Optional[Dict[str, str]]:
    """
    Convert OID suffix "a.b.c.d.e.f" (decimal bytes) to MAC formats.

    Returns:
      {
        "plain": "aabbccddeeff",
        "colon": "aa:bb:cc:dd:ee:ff",
        "cisco": "aabb.ccdd.eeff"
      }
    """
    parts = [p for p in suffix.strip(".").split(".") if p != ""]
    if not parts:
        return None

    try:
        nums = [int(p) for p in parts]
    except Exception:
        return None

    if len(nums) < 6:
        return None

    # Some agents tack on extra indexes; MAC is usually the last 6 bytes.
    nums = nums[-6:]

    if any(n < 0 or n > 255 for n in nums):
        return None

    hexpairs = [f"{n:02x}" for n in nums]

    mac_plain = "".join(hexpairs)
    mac_colon = ":".join(hexpairs)
    mac_cisco = f"{hexpairs[0]}{hexpairs[1]}.{hexpairs[2]}{hexpairs[3]}.{hexpairs[4]}{hexpairs[5]}"

    return {"plain": mac_plain, "colon": mac_colon, "cisco": mac_cisco}

"""
BEGIN - SNMP GET Functions
"""

async def snmp_get_one_auto(
    target: str,
    oid: str,
    *,
    snmp_v2: Optional[Union[Dict[str, List[str]], List[str], str]] = None,
    snmp_v3: Optional[Dict[str, Dict[str, Any]]] = None,
    port: int = 161,
    timeout: float = 3,
    retries: int = 0,
    engine: Optional[SnmpEngine] = None,
    context: Optional[ContextData] = None,
    prefer: str = "v3_then_v2",  # or "v2_then_v3"
) -> Dict[str, Any]:
    """
    One-OID SNMP GET that tries v3 profiles and/or v2 communities until success.

    Inputs:
      - snmp_v2: {"string": ["public","private"]} OR ["public","private"] OR "public"
      - snmp_v3: {"profile_one": {...}, "profile_two": {...}}

    Returns on success:
      {
        "detail": {".<oid>": "<value>"},
        "used": { ... credential payload ... }
      }

    Returns on failure:
      {"error": "no_valid_credentials", "attempts": [...]}  (attempts are brief)
    """
    if not target or not oid:
        return {"error": "missing_required_fields: target and oid are required"}

    snmp_engine = engine or SnmpEngine()
    ctx = context or ContextData()

    # v7+ pattern: create target once
    try:
        transport = await UdpTransportTarget.create((str(target), int(port)), timeout=float(timeout), retries=int(retries))
    except Exception as e:
        return {"error": "snmp_transport_init_error", "detail": str(e)}

    obj = ObjectType(ObjectIdentity(str(oid).lstrip(".")))

    v2_candidates = _extract_v2_communities(snmp_v2)
    v3_candidates = list(_iter_v3_profiles(snmp_v3))

    attempts: List[Dict[str, Any]] = []

    def _order() -> List[str]:
        if prefer == "v2_then_v3":
            return ["v2", "v3"]
        return ["v3", "v2"]

    for mode in _order():
        if mode == "v3":
            for profile_name, profile in v3_candidates:
                usm = _build_usm_user_data(profile)
                if isinstance(usm, dict) and usm.get("error"):
                    attempts.append({"version": "3", "profile": profile_name, "error": usm["error"]})
                    continue

                try:
                    err_ind, err_stat, err_idx, var_binds = await get_cmd(
                        snmp_engine,
                        usm,
                        transport,
                        ctx,
                        obj,
                    )
                except Exception as e:
                    attempts.append({"version": "3", "profile": profile_name, "error": cast(e)})
                    continue

                if err_ind:
                    attempts.append({"version": "3", "profile": profile_name, "error": cast(err_ind)})
                    continue

                if err_stat:
                    attempts.append({"version": "3", "profile": profile_name, "error": cast(err_stat), "index": int(err_idx or 0)})
                    continue

                # success
                out: Dict[str, str] = {}
                for oid_obj, value_obj in var_binds:
                    out[f".{oid_obj.prettyPrint()}"] = cast(value_obj)

                # return the EXACT profile used (so you can inject it later)
                used = {"version": "3", "profile": profile_name, **dict(profile)}
                return {"detail": out, "used": used}

        else:  # v2
            for community in v2_candidates:
                creds = CommunityData(str(community), mpModel=1)  # SNMPv2c

                try:
                    err_ind, err_stat, err_idx, var_binds = await get_cmd(
                        snmp_engine,
                        creds,
                        transport,
                        ctx,
                        obj,
                    )
                except Exception as e:
                    attempts.append({"version": "2c", "community": community, "error": cast(e)})
                    continue

                if err_ind:
                    attempts.append({"version": "2c", "community": community, "error": cast(err_ind)})
                    continue

                if err_stat:
                    attempts.append({"version": "2c", "community": community, "error": cast(err_stat), "index": int(err_idx or 0)})
                    continue

                out: Dict[str, str] = {}
                for oid_obj, value_obj in var_binds:
                    out[f".{oid_obj.prettyPrint()}"] = cast(value_obj)

                used = {"version": "2c", "community": community}
                return {"detail": out, "used": used}

    return {"error": "no_valid_credentials", "attempts": attempts}

async def snmp_bulk_auto(
    target: str,
    oid: str,
    *,
    snmp_v2: Optional[Union[Dict[str, List[str]], List[str], str]] = None,
    snmp_v3: Optional[Dict[str, Dict[str, Any]]] = None,
    port: int = 161,
    max_repetitions: int = 25,
    timeout: float = 10,
    retries: int = 0,
    engine: Optional[SnmpEngine] = None,
    context: Optional[ContextData] = None,
    prefer: str = "v3_then_v2",  # or "v2_then_v3"
    # bulk walk options
    non_repeaters: int = 0,
    max_rows: int = 0,   # 0 = unlimited
    max_calls: int = 0,  # 0 = unlimited
) -> Dict[str, Any]:
    """
    BULK-WALK a subtree starting at `oid` using SNMPv3 profiles and/or SNMPv2c communities.
    Tries each credential until one succeeds.

    Success:
      {
        "detail": {".1.3.6....": <casted value>, ...},
        "used":   { ...credential payload used... }
      }

    Failure:
      {"error": "no_valid_credentials", "attempts": [...]}
    """
    if not target or not oid:
        return {"error": "missing_required_fields: target and oid are required"}

    snmp_engine = engine or SnmpEngine()
    ctx = context or ContextData()

    try:
        transport = await UdpTransportTarget.create(
            (str(target), int(port)),
            timeout=float(timeout),
            retries=int(retries),
        )
    except Exception as e:
        return {"error": "snmp_transport_init_error", "detail": str(e)}

    root_obj = ObjectType(ObjectIdentity(str(oid).lstrip(".")))

    v2_candidates = _extract_v2_communities(snmp_v2)
    v3_candidates = list(_iter_v3_profiles(snmp_v3))

    attempts: List[Dict[str, Any]] = []
    order = ["v3", "v2"] if prefer != "v2_then_v3" else ["v2", "v3"]

    async def _run_bulk(auth_data: Union[CommunityData, UsmUserData]) -> Tuple[Optional[str], Optional[str], Dict[str, Any]]:
        """
        Returns: (err_indication, err_status, out_dict)
        """
        out: Dict[str, Any] = {}

        try:
            async for err_ind, err_stat, err_idx, var_binds in bulk_walk_cmd(
                snmp_engine,
                auth_data,
                transport,
                ctx,
                int(non_repeaters),
                int(max_repetitions),
                root_obj,
                lexicographicMode=False,
                lookupMib=False,
                ignoreNonIncreasingOid=True,
                maxRows=int(max_rows),
                maxCalls=int(max_calls),
            ):
                if err_ind:
                    return (str(err_ind), None, {})
                if err_stat:
                    return (None, str(err_stat), {})

                for vb in var_binds:
                    # vb is an ObjectType; indexable as (name, value)
                    name_obj = vb[0]
                    val_obj = vb[1]

                    # skip exception values if they show up
                    cls = getattr(val_obj, "__class__", type(val_obj)).__name__
                    if cls in ("NoSuchObject", "NoSuchInstance", "EndOfMibView"):
                        continue

                    key = _oid_to_numeric_dot(name_obj)
                    val = cast(val_obj)

                    if val is None:
                        continue
                    if isinstance(val, str):
                        val = val.strip()
                        if val == "":
                            continue

                    out[key] = val

        except Exception as e:
            return (str(e), None, {})

        return (None, None, out)

    # try credentials until one succeeds
    for mode in order:
        if mode == "v3":
            for profile_name, profile in v3_candidates:
                usm = _build_usm_user_data(profile)
                if isinstance(usm, dict) and usm.get("error"):
                    attempts.append({"version": "3", "profile": profile_name, "error": usm["error"]})
                    continue

                err_ind, err_stat, out = await _run_bulk(usm)
                if err_ind or err_stat:
                    attempts.append({
                        "version": "3",
                        "profile": profile_name,
                        "error": err_ind or err_stat,
                    })
                    continue

                used = {"version": "3", "profile": profile_name, **dict(profile)}
                return {"detail": out, "used": used}

        else:  # v2c
            for community in v2_candidates:
                creds = CommunityData(str(community), mpModel=1)  # SNMPv2c
                err_ind, err_stat, out = await _run_bulk(creds)
                if err_ind or err_stat:
                    attempts.append({
                        "version": "2c",
                        "community": community,
                        "error": err_ind or err_stat,
                    })
                    continue

                used = {"version": "2c", "community": community}
                return {"detail": out, "used": used}

    return {"error": "no_valid_credentials", "attempts": attempts}

async def get_bulk_vlan_mac_table_cisco_auto(**kwargs) -> Dict[str, Any]:
    """
    Tries SNMPv3 (context vlan-<id>) and SNMPv2c (community@vlan) until one works.

    Required:
      vlan_id, host/target_ip, oid

    v3:
      snmp_v3 = { "profile": {...}, ... }   OR inline username/password/privKey/authProtocol/privProtocol

    v2:
      snmp_v2 = {"string": ["public", ...]} OR community/credentials

    Returns:
      {"detail": {...}, "used": {...}} or {"error": "...", "attempts": [...]}
    """
    vlan_id = kwargs.get("vlan_id")
    host = kwargs.get("host") or kwargs.get("target_ip")
    walk_oid = kwargs.get("oid")

    if vlan_id in (None, "") or not host or not walk_oid:
        return {"error": "missing_required_fields: vlan_id, host/target_ip, oid"}

    port = int(kwargs.get("port", 161))
    max_repetitions = int(kwargs.get("max_repetitions", 25))
    timeout = float(kwargs.get("timeout", 1.0))
    retries = int(kwargs.get("retries", 5))
    prefer = str(kwargs.get("prefer", "v3_then_v2")).strip() or "v3_then_v2"
    debug = bool(kwargs.get("debug", False))

    # ---- v3 candidates ----
    v3_candidates: List[Tuple[str, Dict[str, Any]]] = []
    snmp_v3_profiles = kwargs.get("snmp_v3")
    if isinstance(snmp_v3_profiles, dict) and snmp_v3_profiles:
        for profile_name, profile in snmp_v3_profiles.items():
            if isinstance(profile, dict):
                v3_candidates.append((str(profile_name), dict(profile)))

    if kwargs.get("username"):
        v3_candidates.append((
            "inline",
            {
                "UsmUserData_username": kwargs.get("username"),
                "UsmUserData_password": kwargs.get("password"),
                "private_key": kwargs.get("privKey"),
                "authProtocol": kwargs.get("authProtocol"),
                "privProtocol": kwargs.get("privProtocol"),
            },
        ))

    # ---- v2 candidates ----
    v2_communities: List[str] = []
    snmp_v2 = kwargs.get("snmp_v2")
    if isinstance(snmp_v2, dict):
        vals = snmp_v2.get("string")
        if isinstance(vals, list):
            v2_communities.extend([str(x).strip() for x in vals if str(x).strip()])

    legacy_comm = kwargs.get("community") or kwargs.get("credentials")
    if legacy_comm and str(legacy_comm).strip():
        v2_communities.append(str(legacy_comm).strip())

    # dedupe preserving order
    seen: Dict[str, bool] = {}
    v2_communities = [c for c in v2_communities if not (c in seen or seen.setdefault(c, True))]

    if not v3_candidates and not v2_communities:
        return {"error": "no_credentials_provided"}

    engine = SnmpEngine()
    root_norm = "." + str(walk_oid).lstrip(".")
    root_obj = ObjectType(ObjectIdentity(str(walk_oid).lstrip(".")))

    attempts: List[Dict[str, Any]] = []

    async def _walk(auth_data: Any, ctx: ContextData) -> Tuple[Optional[str], bool, Dict[str, Any]]:
        # transport-per-attempt
        transport = await UdpTransportTarget.create((str(host), port), timeout=timeout, retries=retries)

        macs_seen: Dict[str, bool] = {}
        mac_plain: List[str] = []
        mac_colon: List[str] = []
        mac_cisco: List[str] = []
        mac_to_port_colon: Dict[str, Any] = {}
        mac_to_port_plain: Dict[str, Any] = {}

        saw_any = False

        try:
            async for err_ind, err_stat, err_idx, var_binds in bulk_walk_cmd(
                engine,
                auth_data,
                transport,
                ctx,
                0,
                max_repetitions,
                root_obj,
                lexicographicMode=False,
                lookupMib=False,
                ignoreNonIncreasingOid=True,
            ):
                saw_any = True

                if err_ind:
                    return str(err_ind), saw_any, {}
                if err_stat:
                    return str(err_stat), saw_any, {}

                for vb in var_binds:
                    name_obj = vb[0]
                    val_obj = vb[1]

                    cls = getattr(val_obj, "__class__", type(val_obj)).__name__
                    if cls in ("NoSuchObject", "NoSuchInstance", "EndOfMibView"):
                        continue

                    name_num = _oid_to_numeric_dot(name_obj)
                    if not name_num.startswith(root_norm + "."):
                        continue

                    suffix = name_num[len(root_norm) + 1 :]
                    macs = _suffix_to_macs(suffix)
                    if not macs:
                        continue

                    mp, mc, ms = macs["plain"], macs["colon"], macs["cisco"]

                    if mc not in macs_seen:
                        macs_seen[mc] = True
                        mac_plain.append(mp)
                        mac_colon.append(mc)
                        mac_cisco.append(ms)

                    port_val = _safe_cast(val_obj)
                    if port_val is None:
                        continue
                    if isinstance(port_val, str):
                        port_val = port_val.strip()
                        if not port_val:
                            continue

                    mac_to_port_colon[mc] = port_val
                    mac_to_port_plain[mp] = port_val

        except Exception as e:
            return str(e), saw_any, {}

        return None, saw_any, {
            "mac_addresses_plain": mac_plain,
            "mac_addresses": mac_colon,
            "mac_addresses_cisco": mac_cisco,
            "mac_to_port": mac_to_port_colon,
            "mac_to_port_plain": mac_to_port_plain,
        }

    order = ("v3", "v2") if prefer != "v2_then_v3" else ("v2", "v3")

    for fam in order:
        if fam == "v3":
            ctx_v3 = ContextData(contextName=f"vlan-{int(vlan_id)}")

            for profile_name, profile in v3_candidates:
                usm = _build_usm_user_data(profile)
                if isinstance(usm, dict) and usm.get("error"):
                    attempts.append({"version": "3", "profile": profile_name, "error": usm["error"]})
                    continue

                if debug:
                    u = profile.get("UsmUserData_username") or profile.get("username") or "<?>"
                    print(f"[DEBUG] v3 attempt profile={profile_name} user={u} ctx=vlan-{int(vlan_id)} host={host}")

                err, saw_any, results = await _walk(usm, ctx_v3)
                if err:
                    attempts.append({"version": "3", "profile": profile_name, "error": err})
                    continue

                if saw_any and not results.get("mac_addresses"):
                    return {
                        "detail": {
                            "vlan_id": int(vlan_id),
                            "walk_oid": root_norm,
                            "context": f"vlan-{int(vlan_id)}",
                            "warning": "walk_completed_but_no_rows",
                            **results,
                        },
                        "used": {"version": "3", "profile": profile_name, **profile},
                    }

                if results.get("mac_addresses"):
                    return {
                        "detail": {
                            "vlan_id": int(vlan_id),
                            "walk_oid": root_norm,
                            "context": f"vlan-{int(vlan_id)}",
                            **results,
                        },
                        "used": {"version": "3", "profile": profile_name, **profile},
                    }

                attempts.append({"version": "3", "profile": profile_name, "error": "no_results"})

        else:
            ctx_v2 = ContextData()

            for community in v2_communities:
                comm_used = f"{community}@{int(vlan_id)}"
                auth_v2 = CommunityData(comm_used, mpModel=1)

                if debug:
                    print(f"[DEBUG] v2 attempt community={community} comm_used={comm_used} host={host}")

                err, saw_any, results = await _walk(auth_v2, ctx_v2)
                if err:
                    attempts.append({"version": "2c", "community": community, "community_used": comm_used, "error": err})
                    continue

                if saw_any and not results.get("mac_addresses"):
                    return {
                        "detail": {
                            "vlan_id": int(vlan_id),
                            "walk_oid": root_norm,
                            "community_indexing": True,
                            "warning": "walk_completed_but_no_rows",
                            **results,
                        },
                        "used": {"version": "2c", "community": community, "community_used": comm_used},
                    }

                if results.get("mac_addresses"):
                    return {
                        "detail": {
                            "vlan_id": int(vlan_id),
                            "walk_oid": root_norm,
                            "community_indexing": True,
                            **results,
                        },
                        "used": {"version": "2c", "community": community, "community_used": comm_used},
                    }

                attempts.append({"version": "2c", "community": community, "community_used": comm_used, "error": "no_results"})

    return {"error": "no_valid_credentials", "attempts": attempts}
"""
This is a library of snmp mibs I want to pull instead of walking the entire device. 
Feel free to update for your preferences. 
"""

def library(device_type):
    if device_type == "FSP150CC-GE206V":
        library = {
            'get': {
                'sysName': '.1.3.6.1.2.1.1.5.0',
                'sysLocation': '.1.3.6.1.2.1.1.6.0',
                'sysDescr': '.1.3.6.1.2.1.1.1.0',
                'chassis_serial_number': '.1.3.6.1.2.1.47.1.1.1.1.11.1', #Device Chassis Serial Number
                'chassis_part_number': '.1.3.6.1.4.1.2544.1.12.3.1.3.1.8.1.1.1', #Device Chassis Part Number
                'chassis_active_software': '.1.3.6.1.4.1.2544.1.12.3.1.3.1.10.1.1.1', #Device Active Software
                'chassis_standby_software': '.1.3.6.1.4.1.2544.1.12.2.1.7.4.1.3.2', #Device Standby Software
                'chassis_download_software': '.1.3.6.1.4.1.2544.1.12.2.1.7.4.1.3.3', #Device Download Software
                'snmpEngineID': '.1.3.6.1.6.3.10.2.1.1.0' #SNMP Engine ID
            },
            'walk': {
                'remote_authentication_targets': '.1.3.6.1.4.1.2544.1.12.10.1.6.1.4',# remote authentication ipv4 targets
                'ifName': '.1.3.6.1.2.1.31.1.1.1.1',
                'ifIndex': '.1.3.6.1.2.1.2.2.1.1',
                'network_port_interface_index_id': '.1.3.6.1.4.1.2544.1.12.4.1.7.1.2',
                'access_port_interface_index_id': '.1.3.6.1.4.1.2544.1.12.4.1.1.1.2',
                'ifAlias': '.1.3.6.1.2.1.31.1.1.1.18',
                'ifAdminStatus': '.1.3.6.1.2.1.2.2.1.7',
                'ifOperStatus': '.1.3.6.1.2.1.2.2.1.8',
                'etherStatsCRCAlignErrors': '.1.3.6.1.2.1.16.1.1.1.8',

                'network_interface_sfp_vendor_name': '.1.3.6.1.4.1.2544.1.12.4.1.7.1.13',
                'network_interface_sfp_wave_length': '.1.3.6.1.4.1.2544.1.12.4.1.7.1.70',               #This object provides the SFP Laser Wave Length in nano meters. This is applicable only when cmEthernetNetPortMediaType is fiber.
                'network_interface_sfp_part_number': '.1.3.6.1.4.1.2544.1.12.4.1.7.1.14',
                'network_interface_optical_rx_value_dbm': '.1.3.6.1.4.1.2544.1.12.5.1.5.1.34',         # neIndex, shelfIndex, slotIndex, cmEthernetAccPortIndex, cmEthernetAccPortStatsIndex
                'network_interface_optical_tx_value_dbm': '.1.3.6.1.4.1.2544.1.12.5.1.5.1.33',         # neIndex, shelfIndex, slotIndex, cmEthernetAccPortIndex, cmEthernetAccPortStatsIndex

                'access_interface_sfp_vendor_name': '.1.3.6.1.4.1.2544.1.12.4.1.1.1.13',
                'access_interface_sfp_wave_length': '.1.3.6.1.4.1.2544.1.12.4.1.1.1.72',               # This object provides the SFP Laser Wave Length in nano meters. This is applicable only when cmEthernetNetPortMediaType is fiber.
                'access_interface_sfp_part_number': '.1.3.6.1.4.1.2544.1.12.4.1.1.1.14',
                'access_interface_optical_rx_value_dbm': '.1.3.6.1.4.1.2544.1.12.5.1.1.1.34',          # neIndex, shelfIndex, slotIndex, cmEthernetAccPortIndex, cmEthernetAccPortStatsIndex
                'access_interface_optical_tx_value_dbm': '.1.3.6.1.4.1.2544.1.12.5.1.1.1.33',          # neIndex, shelfIndex, slotIndex, cmEthernetAccPortIndex, cmEthernetAccPortStatsIndex


                'network_port_stats_average_bitrate_N2A_direction': '.1.3.6.1.4.1.2544.1.12.5.1.5.1.37', # neIndex, shelfIndex, slotIndex, cmEthernetNetPortIndex, cmEthernetNetPortStatsIndex
                'network_port_stats_average_bitrate_A2N_direction': '.1.3.6.1.4.1.2544.1.12.5.1.5.1.38', # neIndex, shelfIndex, slotIndex, cmEthernetNetPortIndex, cmEthernetNetPortStatsIndex
                                                                                                         # An arbitrary integer index value used to uniquely identify
                                                                                                         #    this Ethernet Network Port statistics entry.
                                                                                                         #    1 - 15min
                                                                                                         #    2 - 1day
                                                                                                         #    3 - rollover
                                                                                                         #    4 - 5min

                'access_port_stats_average_bitrate_N2A_direction': '.1.3.6.1.4.1.2544.1.12.5.1.1.1.38',  # Same as above
                'access_port_stats_average_bitrate_A2N_direction': '.1.3.6.1.4.1.2544.1.12.5.1.1.1.37',
            }
        }
    elif device_type == "FSP150CC-GE114":
        library = {
            'get': {
                'sysName': '.1.3.6.1.2.1.1.5.0',
                'sysLocation': '.1.3.6.1.2.1.1.6.0',
                'sysDescr': '.1.3.6.1.2.1.1.1.0',
                'chassis_serial_number': '.1.3.6.1.2.1.47.1.1.1.1.11.1', #Device Chassis Serial Number
                'chassis_part_number': '.1.3.6.1.4.1.2544.1.12.3.1.3.1.8.1.1.1', #Device Chassis Part Number
                'chassis_active_software': '.1.3.6.1.4.1.2544.1.12.3.1.3.1.10.1.1.1', #Device Active Software
                'chassis_standby_software': '.1.3.6.1.4.1.2544.1.12.2.1.7.4.1.3.2', #Device Standby Software
                'chassis_download_software': '.1.3.6.1.4.1.2544.1.12.2.1.7.4.1.3.3', #Device Download Software
                'snmpEngineID': '.1.3.6.1.6.3.10.2.1.1.0' #SNMP Engine ID
            },
            'walk': {
                'remote_authentication_targets': '.1.3.6.1.4.1.2544.1.12.10.1.6.1.4',# remote authentication ipv4 targets
                'ifName': '.1.3.6.1.2.1.31.1.1.1.1',
                'ifIndex': '.1.3.6.1.2.1.2.2.1.1',
                'network_port_interface_index_id': '.1.3.6.1.4.1.2544.1.12.4.1.7.1.2',
                'access_port_interface_index_id': '.1.3.6.1.4.1.2544.1.12.4.1.1.1.2',
                'ifAlias': '.1.3.6.1.2.1.31.1.1.1.18',
                'ifAdminStatus': '.1.3.6.1.2.1.2.2.1.7',
                'ifOperStatus': '.1.3.6.1.2.1.2.2.1.8',
                'etherStatsCRCAlignErrors': '.1.3.6.1.2.1.16.1.1.1.8',

                'network_interface_sfp_vendor_name': '.1.3.6.1.4.1.2544.1.12.4.1.7.1.13',
                'network_interface_sfp_wave_length': '.1.3.6.1.4.1.2544.1.12.4.1.7.1.70',               #This object provides the SFP Laser Wave Length in nano meters. This is applicable only when cmEthernetNetPortMediaType is fiber.
                'network_interface_sfp_part_number': '.1.3.6.1.4.1.2544.1.12.4.1.7.1.14',
                'network_interface_optical_rx_value_dbm': '.1.3.6.1.4.1.2544.1.12.5.1.5.1.34',         # neIndex, shelfIndex, slotIndex, cmEthernetAccPortIndex, cmEthernetAccPortStatsIndex
                'network_interface_optical_tx_value_dbm': '.1.3.6.1.4.1.2544.1.12.5.1.5.1.33',         # neIndex, shelfIndex, slotIndex, cmEthernetAccPortIndex, cmEthernetAccPortStatsIndex

                'access_interface_sfp_vendor_name': '.1.3.6.1.4.1.2544.1.12.4.1.1.1.13',
                'access_interface_sfp_wave_length': '.1.3.6.1.4.1.2544.1.12.4.1.1.1.72',               # This object provides the SFP Laser Wave Length in nano meters. This is applicable only when cmEthernetNetPortMediaType is fiber.
                'access_interface_sfp_part_number': '.1.3.6.1.4.1.2544.1.12.4.1.1.1.14',
                'access_interface_optical_rx_value_dbm': '.1.3.6.1.4.1.2544.1.12.5.1.1.1.34',          # neIndex, shelfIndex, slotIndex, cmEthernetAccPortIndex, cmEthernetAccPortStatsIndex
                'access_interface_optical_tx_value_dbm': '.1.3.6.1.4.1.2544.1.12.5.1.1.1.33',          # neIndex, shelfIndex, slotIndex, cmEthernetAccPortIndex, cmEthernetAccPortStatsIndex


                'network_port_stats_average_bitrate_N2A_direction': '.1.3.6.1.4.1.2544.1.12.5.1.5.1.37', # neIndex, shelfIndex, slotIndex, cmEthernetNetPortIndex, cmEthernetNetPortStatsIndex
                'network_port_stats_average_bitrate_A2N_direction': '.1.3.6.1.4.1.2544.1.12.5.1.5.1.38', # neIndex, shelfIndex, slotIndex, cmEthernetNetPortIndex, cmEthernetNetPortStatsIndex
                                                                                                         # An arbitrary integer index value used to uniquely identify
                                                                                                         #    this Ethernet Network Port statistics entry.
                                                                                                         #    1 - 15min
                                                                                                         #    2 - 1day
                                                                                                         #    3 - rollover
                                                                                                         #    4 - 5min

                'access_port_stats_average_bitrate_N2A_direction': '.1.3.6.1.4.1.2544.1.12.5.1.1.1.38',  # Same as above
                'access_port_stats_average_bitrate_A2N_direction': '.1.3.6.1.4.1.2544.1.12.5.1.1.1.37',
            }
        }
    elif device_type == "FSP150CC-825":
        library = {
            'get': {
                'sysName': '.1.3.6.1.2.1.1.5.0',
                'sysLocation': '.1.3.6.1.2.1.1.6.0',
                'sysDescr': '.1.3.6.1.2.1.1.1.0',
                'chassis_serial_number': '.1.3.6.1.2.1.47.1.1.1.1.11.1', #Device Chassis Serial Number
                'chassis_part_number': '.1.3.6.1.4.1.2544.1.12.3.1.3.1.8.1.1.1', #Device Chassis Part Number
                'probeSoftwareRev': '.1.3.6.1.2.1.16.19.2.0', #Device Active Software
                'snmpEngineID': '.1.3.6.1.6.3.10.2.1.1.0' #SNMP Engine ID
            },
            'walk': {
                'ifName': '.1.3.6.1.2.1.31.1.1.1.1',
                'ifIndex': '.1.3.6.1.2.1.2.2.1.1',
                'ifAlias': '.1.3.6.1.2.1.31.1.1.1.18',
                'ifAdminStatus': '.1.3.6.1.2.1.2.2.1.7',
                'ifOperStatus': '.1.3.6.1.2.1.2.2.1.8'
            }
        }
    elif device_type == "JUNIPER_JRR":
        library = {
            'get': {
                'sysName': '.1.3.6.1.2.1.1.5.0',
                'sysDescr': '.1.3.6.1.2.1.1.1.0',
                'sysLocation': '.1.3.6.1.2.1.1.6.0',
                'snmpEngineID': '1.3.6.1.6.3.10.2.1.1.0',
                'sysUpTime': '.1.3.6.1.2.1.1.3.0',
            },
            'walk': {
                'dot1dBasePortIfIndex': '.1.3.6.1.2.1.17.1.4.1.2', #The value of the instance of the ifIndex object, defined in IF-MIB, for the interface corresponding to this port
                'ifIndex': '.1.3.6.1.2.1.2.2.1.1',
                'ifDescr': '.1.3.6.1.2.1.2.2.1.2',
                'ifAlias': '.1.3.6.1.2.1.31.1.1.1.18',
                'ifAdminStatus': '.1.3.6.1.2.1.2.2.1.7',
                'ifOperStatus': '.1.3.6.1.2.1.2.2.1.8',
                'etherStatsDropEvents': '1.3.6.1.2.1.16.1.1.1.3',
                'ifLastChange': '.1.3.6.1.2.1.2.2.1.9',

            }
        }
    elif device_type == "FSP 150-GE114Pro":
        library = {
            'get': {
                'sysName': '.1.3.6.1.2.1.1.5.0',
                'sysLocation': '.1.3.6.1.2.1.1.6.0',
                'sysDescr': '.1.3.6.1.2.1.1.1.0',
                'chassis_serial_number': '.1.3.6.1.2.1.47.1.1.1.1.11.1', #Device Chassis Serial Number
                'chassis_part_number': '.1.3.6.1.4.1.2544.1.12.3.1.3.1.8.1.1.1', #Device Chassis Part Number
                'chassis_active_software': '.1.3.6.1.4.1.2544.1.12.3.1.3.1.10.1.1.1', #Device Active Software
                'chassis_standby_software': '.1.3.6.1.4.1.2544.1.12.2.1.7.4.1.3.2', #Device Standby Software
                'chassis_download_software': '.1.3.6.1.4.1.2544.1.12.2.1.7.4.1.3.3', #Device Download Software
                'snmpEngineID': '.1.3.6.1.6.3.10.2.1.1.0' #SNMP Engine ID
            },
            'walk': {
                'remote_authentication_targets': '.1.3.6.1.4.1.2544.1.12.10.1.6.1.4',# remote authentication ipv4 targets
                'ifName': '.1.3.6.1.2.1.31.1.1.1.1',
                'ifIndex': '.1.3.6.1.2.1.2.2.1.1',
                'network_port_interface_index_id': '.1.3.6.1.4.1.2544.1.12.4.1.7.1.2',
                'access_port_interface_index_id': '.1.3.6.1.4.1.2544.1.12.4.1.1.1.2',
                'ifAlias': '.1.3.6.1.2.1.31.1.1.1.18',
                'ifAdminStatus': '.1.3.6.1.2.1.2.2.1.7',
                'ifOperStatus': '.1.3.6.1.2.1.2.2.1.8',
                'etherStatsCRCAlignErrors': '.1.3.6.1.2.1.16.1.1.1.8',

                'network_interface_sfp_vendor_name': '.1.3.6.1.4.1.2544.1.12.4.1.7.1.13',
                'network_interface_sfp_wave_length': '.1.3.6.1.4.1.2544.1.12.4.1.7.1.70',               #This object provides the SFP Laser Wave Length in nano meters. This is applicable only when cmEthernetNetPortMediaType is fiber.
                'network_interface_sfp_part_number': '.1.3.6.1.4.1.2544.1.12.4.1.7.1.14',
                'network_interface_optical_rx_value_dbm': '.1.3.6.1.4.1.2544.1.12.5.1.5.1.34',         # neIndex, shelfIndex, slotIndex, cmEthernetAccPortIndex, cmEthernetAccPortStatsIndex
                'network_interface_optical_tx_value_dbm': '.1.3.6.1.4.1.2544.1.12.5.1.5.1.33',         # neIndex, shelfIndex, slotIndex, cmEthernetAccPortIndex, cmEthernetAccPortStatsIndex

                'access_interface_sfp_vendor_name': '.1.3.6.1.4.1.2544.1.12.4.1.1.1.13',
                'access_interface_sfp_wave_length': '.1.3.6.1.4.1.2544.1.12.4.1.1.1.72',               # This object provides the SFP Laser Wave Length in nano meters. This is applicable only when cmEthernetNetPortMediaType is fiber.
                'access_interface_sfp_part_number': '.1.3.6.1.4.1.2544.1.12.4.1.1.1.14',
                'access_interface_optical_rx_value_dbm': '.1.3.6.1.4.1.2544.1.12.5.1.1.1.34',          # neIndex, shelfIndex, slotIndex, cmEthernetAccPortIndex, cmEthernetAccPortStatsIndex
                'access_interface_optical_tx_value_dbm': '.1.3.6.1.4.1.2544.1.12.5.1.1.1.33',          # neIndex, shelfIndex, slotIndex, cmEthernetAccPortIndex, cmEthernetAccPortStatsIndex


                'network_port_stats_average_bitrate_N2A_direction': '.1.3.6.1.4.1.2544.1.12.5.1.5.1.37', # neIndex, shelfIndex, slotIndex, cmEthernetNetPortIndex, cmEthernetNetPortStatsIndex
                'network_port_stats_average_bitrate_A2N_direction': '.1.3.6.1.4.1.2544.1.12.5.1.5.1.38', # neIndex, shelfIndex, slotIndex, cmEthernetNetPortIndex, cmEthernetNetPortStatsIndex
                                                                                                         # An arbitrary integer index value used to uniquely identify
                                                                                                         #    this Ethernet Network Port statistics entry.
                                                                                                         #    1 - 15min
                                                                                                         #    2 - 1day
                                                                                                         #    3 - rollover
                                                                                                         #    4 - 5min

                'access_port_stats_average_bitrate_N2A_direction': '.1.3.6.1.4.1.2544.1.12.5.1.1.1.38',  # Same as above
                'access_port_stats_average_bitrate_A2N_direction': '.1.3.6.1.4.1.2544.1.12.5.1.1.1.37',
            }
        }
    elif device_type == "FSP150CC-XG120PRO":
        library = {
            'get': {
                'sysName': '.1.3.6.1.2.1.1.5.0',
                'sysLocation': '.1.3.6.1.2.1.1.6.0',
                'sysDescr': '.1.3.6.1.2.1.1.1.0',
                'chassis_serial_number': '.1.3.6.1.2.1.47.1.1.1.1.11.1', #Device Chassis Serial Number
                'chassis_part_number': '.1.3.6.1.4.1.2544.1.12.3.1.3.1.8.1.1.1', #Device Chassis Part Number
                'chassis_active_software': '.1.3.6.1.4.1.2544.1.12.3.1.3.1.10.1.1.1', #Device Active Software
                'chassis_standby_software': '.1.3.6.1.4.1.2544.1.12.2.1.7.4.1.3.2', #Device Standby Software
                'chassis_download_software': '.1.3.6.1.4.1.2544.1.12.2.1.7.4.1.3.3', #Device Download Software
                'snmpEngineID': '.1.3.6.1.6.3.10.2.1.1.0' #SNMP Engine ID
            },
            'walk': {
                'remote_authentication_targets': '.1.3.6.1.4.1.2544.1.12.10.1.6.1.4', #remote authentication ipv4 targets
                'ifName': '.1.3.6.1.2.1.31.1.1.1.1', #Interface name
                'ifAlias': '.1.3.6.1.2.1.31.1.1.1.18', #interface alias
                'ifAdminStatus': '.1.3.6.1.2.1.2.2.1.7', #interface admin status
                'ifOperStatus': '.1.3.6.1.2.1.2.2.1.8', #interface oper status
                'etherStatsCRCAlignErrors': '.1.3.6.1.2.1.16.1.1.1.8', #interface crc errors
                'sfp_vendor_name': '.1.3.6.1.4.1.2544.1.12.4.1.27.1.13.1.1.1', #SFP Vendor name
                'sfp_vendor_part_number': '.1.3.6.1.4.1.2544.1.12.4.1.27.1.14.1.1.1', #SFP Vendor part number
                'sfp_vendor_part_serial_number': '.1.3.6.1.4.1.2544.1.12.4.1.27.1.15.1.1.1', #SFP Vendor part serial number
                'sfp_vendor_wavelength': '.1.3.6.1.4.1.2544.1.12.4.1.27.1.19.1.1.1', #SFP wavelength
                'ethernet_traffic_port_stats_interval_type': '.1.3.6.1.4.1.2544.1.12.5.1.21.1.2', #Syntax CmPmIntervalType (INTEGER) {interval-15min (1),interval-1day (2),rollover (3), interval-5min (4)
                'cmEthernetTrafficPortStatsABRRx': '.1.3.6.1.4.1.2544.1.12.5.1.21.1.37', # Indexes	 neIndex, shelfIndex, slotIndex, cmEthernetTrafficPortIndex, cmEthernetTrafficPortStatsIndex
                'cmEthernetTrafficPortStatsABRTx': '.1.3.6.1.4.1.2544.1.12.5.1.21.1.38', # Indexes	 neIndex, shelfIndex, slotIndex, cmEthernetTrafficPortIndex, cmEthernetTrafficPortStatsIndex

            }
        }
    elif device_type == "CIENA_SWITCH":
        library = {
            'get': {
                'sysName': '.1.3.6.1.2.1.1.5.0',
                'sysDescr': '.1.3.6.1.2.1.1.1.0',
                'sysLocation': '.1.3.6.1.2.1.1.6.0',
                'snmpEngineID': '1.3.6.1.6.3.10.2.1.1.0',
            },
            'walk': {
                'ifName': '.1.3.6.1.2.1.31.1.1.1.1',
                'ifIndex': '.1.3.6.1.2.1.2.2.1.1',
                'ifAlias': '.1.3.6.1.2.1.31.1.1.1.18',
                'ifAdminStatus': '.1.3.6.1.2.1.2.2.1.7',
                'ifOperStatus': '.1.3.6.1.2.1.2.2.1.8',
            }
        }
    elif device_type == "QFX-51XX":
        library = {
            'get': {
                'sysName': '.1.3.6.1.2.1.1.5.0',
                'sysDescr': '.1.3.6.1.2.1.1.1.0',
                'sysLocation': '.1.3.6.1.2.1.1.6.0',
                'snmpEngineID': '1.3.6.1.6.3.10.2.1.1.0',
                'sysUpTime': '.1.3.6.1.2.1.1.3.0',
            },
            'walk': {
                'dot1dBasePortIfIndex': '.1.3.6.1.2.1.17.1.4.1.2', #The value of the instance of the ifIndex object, defined in IF-MIB, for the interface corresponding to this port
                'ifIndex': '.1.3.6.1.2.1.2.2.1.1',
                'ifDescr': '.1.3.6.1.2.1.2.2.1.2',
                'ifAlias': '.1.3.6.1.2.1.31.1.1.1.18',
                'ifAdminStatus': '.1.3.6.1.2.1.2.2.1.7',
                'ifOperStatus': '.1.3.6.1.2.1.2.2.1.8',
                'etherStatsCRCAlignErrors': '1.3.6.1.2.1.16.1.1.1.8',
                'etherStatsCollisions': '1.3.6.1.2.1.16.1.1.1.13', # The best estimate of the total number of collisions on this Ethernet segment.
                                                                   # The value returned will depend on the location of the RMON probe. Section 8.2.1.3 (10BASE-5) and section 10.3.1.3
                                                                   # (10BASE-2) of IEEE standard 802.3 states that a station must detect a collision, in the receive mode, if three or
                                                                   # more stations are transmitting simultaneously. A repeater port must detect a collision when two or more stations are
                                                                   # transmitting simultaneously. Thus a probe placed on a repeater port could record more collisions than a probe connected
                                                                   # to a station on the same segment would.
                                                                   # Probe location plays a much smaller role when considering 10BASE-T. 14.2.1.4 (10BASE-T) of IEEE standard 802.3 defines a collision
                                                                   # as the simultaneous presence of signals on the DO and RD circuits (transmitting and receiving at the same time). A 10BASE-T station
                                                                   # can only detect collisions when it is transmitting. Thus probes placed on a station and a repeater, should report the same number of collisions.
                                                                   # Note also that an RMON probe inside a repeater should ideally report collisions between the repeater and one or more other hosts (transmit collisions
                                                                   # as defined by IEEE 802.3k) plus receiver collisions observed on any coax segments to which the repeater is connected.
                'etherStatsDropEvents': '1.3.6.1.2.1.16.1.1.1.3',
                'ifLastChange': '.1.3.6.1.2.1.2.2.1.9',
                'jnxL2aldVlanName': '.1.3.6.1.4.1.2636.3.48.1.3.1.1.2',
                'dot1qVlanStaticName': '1.3.6.1.2.1.17.7.1.4.3.1.1', #Vlan name configured on the device + vlan id in string form
                'dot1qVlanStaticEgressPorts': '1.3.6.1.2.1.17.7.1.4.3.1.2', #Egress ports assigned to each vlan.
                'dot1qVlanStaticRowStatus': '.1.3.6.1.2.1.17.7.1.4.3.1.5', #Status of each vlan -> {active(1), notInService(2), notReady(3), createAndGo(4), createAndWait(5), destroy(6) }
                'jnxL2aldVlanFdbId': '1.3.6.1.4.1.2636.3.48.1.3.1.1.5', #Vlan forwarding database reference id. Ex output -> .1.3.6.1.4.1.2636.3.48.1.3.1.1.5.174 = Gauge32: 11403264
                'dot1qTpFdbPort': '1.3.6.1.2.1.17.7.1.2.2.1.2', # Either the value '0', or the port number of the port on which a frame having a source address equal to the value
                                                                # of the corresponding instance of dot1qTpFdbAddress has been seen. A value of '0'
                                                                # indicates that the port number has not been learned but that the device does have some
                                                                # forwarding/filtering information about this address (e.g., in the dot1qStaticUnicastTable). Implementors are encouraged to
                                                                # assign the port value to this object whenever it is learned, even for addresses for which the corresponding value of dot1qTpFdbStatus
                                                                # is not learned(3).
                                                                # Example call / Filter 1.3.6.1.2.1.17.7.1.2.2.1.2.jnxL2aldVlanFdbId => Will return interface ids and mac addresses
                                                                # The End will need to be converted from decimal to hex to obtain the mac address.
                'ipNetToMediaPhysAddress': '.1.3.6.1.2.1.4.22.1.2',
                'lldpRemPortId': '.1.0.8802.1.1.2.1.4.1.1.7',  # Remote port id of the connected device using lldp
                'lldpRemPortDesc': '.1.0.8802.1.1.2.1.4.1.1.8',
                'lldpRemSysName': '.1.0.8802.1.1.2.1.4.1.1.9',
            }
        }
    elif device_type == "EX4200":
        library = {
            'get': {
                'sysName': '.1.3.6.1.2.1.1.5.0',
                'sysDescr': '.1.3.6.1.2.1.1.1.0',
                'sysLocation': '.1.3.6.1.2.1.1.6.0',
                'snmpEngineID': '1.3.6.1.6.3.10.2.1.1.0',
                'sysUpTime': '.1.3.6.1.2.1.1.3.0',
            },
            'walk': {
                'dot1dBasePortIfIndex': '.1.3.6.1.2.1.17.1.4.1.2', #The value of the instance of the ifIndex object, defined in IF-MIB, for the interface corresponding to this port
                'ifIndex': '.1.3.6.1.2.1.2.2.1.1',
                'ifDescr': '.1.3.6.1.2.1.2.2.1.2',
                'ifAlias': '.1.3.6.1.2.1.31.1.1.1.18',
                'ifAdminStatus': '.1.3.6.1.2.1.2.2.1.7',
                'ifOperStatus': '.1.3.6.1.2.1.2.2.1.8',
                'etherStatsCRCAlignErrors': '1.3.6.1.2.1.16.1.1.1.8',
                'etherStatsCollisions': '1.3.6.1.2.1.16.1.1.1.13', # The best estimate of the total number of collisions on this Ethernet segment.
                                                                   # The value returned will depend on the location of the RMON probe. Section 8.2.1.3 (10BASE-5) and section 10.3.1.3
                                                                   # (10BASE-2) of IEEE standard 802.3 states that a station must detect a collision, in the receive mode, if three or
                                                                   # more stations are transmitting simultaneously. A repeater port must detect a collision when two or more stations are
                                                                   # transmitting simultaneously. Thus a probe placed on a repeater port could record more collisions than a probe connected
                                                                   # to a station on the same segment would.
                                                                   # Probe location plays a much smaller role when considering 10BASE-T. 14.2.1.4 (10BASE-T) of IEEE standard 802.3 defines a collision
                                                                   # as the simultaneous presence of signals on the DO and RD circuits (transmitting and receiving at the same time). A 10BASE-T station
                                                                   # can only detect collisions when it is transmitting. Thus probes placed on a station and a repeater, should report the same number of collisions.
                                                                   # Note also that an RMON probe inside a repeater should ideally report collisions between the repeater and one or more other hosts (transmit collisions
                                                                   # as defined by IEEE 802.3k) plus receiver collisions observed on any coax segments to which the repeater is connected.
                'etherStatsDropEvents': '1.3.6.1.2.1.16.1.1.1.3',
                'ifLastChange': '.1.3.6.1.2.1.2.2.1.9',
                'jnxL2aldVlanName': '.1.3.6.1.4.1.2636.3.48.1.3.1.1.2',
                'dot1qVlanStaticName': '1.3.6.1.2.1.17.7.1.4.3.1.1', #Vlan name configured on the device + vlan id in string form
                'dot1qVlanStaticRowStatus': '.1.3.6.1.2.1.17.7.1.4.3.1.5', #Status of each vlan -> {active(1), notInService(2), notReady(3), createAndGo(4), createAndWait(5), destroy(6) }
                'dot1qTpFdbPort': '1.3.6.1.2.1.17.7.1.2.2.1.2', # Either the value '0', or the port number of the port on which a frame having a source address equal to the value
                                                                # of the corresponding instance of dot1qTpFdbAddress has been seen. A value of '0'
                                                                # indicates that the port number has not been learned but that the device does have some
                                                                # forwarding/filtering information about this address (e.g., in the dot1qStaticUnicastTable). Implementors are encouraged to
                                                                # assign the port value to this object whenever it is learned, even for addresses for which the corresponding value of dot1qTpFdbStatus
                                                                # is not learned(3).
                                                                # Example call / Filter 1.3.6.1.2.1.17.7.1.2.2.1.2.jnxL2aldVlanFdbId => Will return interface ids and mac addresses
                                                                # The End will need to be converted from decimal to hex to obtain the mac address.
                'ipNetToMediaPhysAddress': '.1.3.6.1.2.1.4.22.1.2',

            }
        }
    elif device_type == "MX":
        library = {
            'get': {
                'sysName': '.1.3.6.1.2.1.1.5.0',
                'sysDescr': '.1.3.6.1.2.1.1.1.0',
                'sysLocation': '.1.3.6.1.2.1.1.6.0',
                'snmpEngineID': '1.3.6.1.6.3.10.2.1.1.0',
                'sysUpTime': '.1.3.6.1.2.1.1.3.0',
            },
            'walk': {
                'dot1dBasePortIfIndex': '.1.3.6.1.2.1.17.1.4.1.2', #The value of the instance of the ifIndex object, defined in IF-MIB, for the interface corresponding to this port
                'ifIndex': '.1.3.6.1.2.1.2.2.1.1',
                'ifDescr': '.1.3.6.1.2.1.2.2.1.2',
                'ifAlias': '.1.3.6.1.2.1.31.1.1.1.18',
                'ifAdminStatus': '.1.3.6.1.2.1.2.2.1.7',
                'ifOperStatus': '.1.3.6.1.2.1.2.2.1.8',
                'etherStatsCRCAlignErrors': '1.3.6.1.2.1.16.1.1.1.8',
                'etherStatsCollisions': '1.3.6.1.2.1.16.1.1.1.13', # The best estimate of the total number of collisions on this Ethernet segment.
                                                                   # The value returned will depend on the location of the RMON probe. Section 8.2.1.3 (10BASE-5) and section 10.3.1.3
                                                                   # (10BASE-2) of IEEE standard 802.3 states that a station must detect a collision, in the receive mode, if three or
                                                                   # more stations are transmitting simultaneously. A repeater port must detect a collision when two or more stations are
                                                                   # transmitting simultaneously. Thus a probe placed on a repeater port could record more collisions than a probe connected
                                                                   # to a station on the same segment would.
                                                                   # Probe location plays a much smaller role when considering 10BASE-T. 14.2.1.4 (10BASE-T) of IEEE standard 802.3 defines a collision
                                                                   # as the simultaneous presence of signals on the DO and RD circuits (transmitting and receiving at the same time). A 10BASE-T station
                                                                   # can only detect collisions when it is transmitting. Thus probes placed on a station and a repeater, should report the same number of collisions.
                                                                   # Note also that an RMON probe inside a repeater should ideally report collisions between the repeater and one or more other hosts (transmit collisions
                                                                   # as defined by IEEE 802.3k) plus receiver collisions observed on any coax segments to which the repeater is connected.
                'etherStatsDropEvents': '1.3.6.1.2.1.16.1.1.1.3',
                'ifLastChange': '.1.3.6.1.2.1.2.2.1.9',
                'jnxL2aldVlanFdbId': '1.3.6.1.4.1.2636.3.48.1.3.1.1.5', #Vlan forwarding database reference id. Ex output -> .1.3.6.1.4.1.2636.3.48.1.3.1.1.5.174 = Gauge32: 11403264
                'dot1qTpFdbPort': '1.3.6.1.2.1.17.7.1.2.2.1.2',         # Either the value '0', or the port number of the port on which a frame having a source address equal to the value
                                                                        # of the corresponding instance of dot1qTpFdbAddress has been seen. A value of '0'
                                                                        # indicates that the port number has not been learned but that the device does have some
                                                                        # forwarding/filtering information about this address (e.g., in the dot1qStaticUnicastTable). Implementors are encouraged to
                                                                        # assign the port value to this object whenever it is learned, even for addresses for which the corresponding value of dot1qTpFdbStatus
                                                                        # is not learned(3).
                                                                        # Example call / Filter 1.3.6.1.2.1.17.7.1.2.2.1.2.jnxL2aldVlanFdbId => Will return interface ids and mac addresses
                                                                        # The End will need to be converted from decimal to hex to obtain the mac address.
                'ipNetToMediaPhysAddress': '.1.3.6.1.2.1.4.22.1.2',      # Depending on your needs you could blank this out if you are not interested in the layer 3 arp table
                'lldpRemPortId': '.1.0.8802.1.1.2.1.4.1.1.7',           # Remote port id of the connected device using lldp
                                                                        # .1.0.8802.1.1.2.1.4.1.1.7.22188102.[Local device snmp ifindex id]1733.{Remote port snmp if index}446
                'lldpRemPortDesc': '.1.0.8802.1.1.2.1.4.1.1.8',
                'lldpRemSysName': '.1.0.8802.1.1.2.1.4.1.1.9',
            }
        }
    elif device_type == "NOKIA_7750":
        library = {
            'get': {
                'sysName': '.1.3.6.1.2.1.1.5.0',
                'sysDescr': '.1.3.6.1.2.1.1.1.0',
                'sysLocation': '.1.3.6.1.2.1.1.6.0',
                'snmpEngineID': '1.3.6.1.6.3.10.2.1.1.0',
                'sysUpTime': '.1.3.6.1.2.1.1.3.0',
            },
            'walk': {
                'ifIndex': '.1.3.6.1.2.1.2.2.1.1',
                'ipAdEntIfIndex': '.1.3.6.1.2.1.4.20.1.2',
                'ifType': '.1.3.6.1.2.1.2.2.1.3',
                'ifDescr': '.1.3.6.1.2.1.2.2.1.2',
                'ipNetToMediaPhysAddress': '.1.3.6.1.2.1.4.22.1.2',
            }
        }
    elif device_type == "NOKIA_7210":
        library = {
            'get': {
                'sysName': '.1.3.6.1.2.1.1.5.0',
                'sysDescr': '.1.3.6.1.2.1.1.1.0',
                'sysLocation': '.1.3.6.1.2.1.1.6.0',
                'snmpEngineID': '1.3.6.1.6.3.10.2.1.1.0',
                'sysUpTime': '.1.3.6.1.2.1.1.3.0',
            },
            'walk': {
                'ifIndex': '.1.3.6.1.2.1.2.2.1.1',
                'ipAdEntIfIndex': '.1.3.6.1.2.1.4.20.1.2',
                'ifType': '.1.3.6.1.2.1.2.2.1.3',
                'ifDescr': '.1.3.6.1.2.1.2.2.1.2',
                'ipNetToMediaPhysAddress': '.1.3.6.1.2.1.4.22.1.2',
            }
        }
    elif device_type == "NOKIA_7705":
        library = {
            'get': {
                'sysName': '.1.3.6.1.2.1.1.5.0',
                'sysDescr': '.1.3.6.1.2.1.1.1.0',
                'sysLocation': '.1.3.6.1.2.1.1.6.0',
                'snmpEngineID': '1.3.6.1.6.3.10.2.1.1.0',
                'sysUpTime': '.1.3.6.1.2.1.1.3.0',
            },
            'walk': {
                'ifIndex': '.1.3.6.1.2.1.2.2.1.1',
                'ipAdEntIfIndex': '.1.3.6.1.2.1.4.20.1.2',
                'ifType': '.1.3.6.1.2.1.2.2.1.3',
                'ifDescr': '.1.3.6.1.2.1.2.2.1.2',
                'ipNetToMediaPhysAddress': '.1.3.6.1.2.1.4.22.1.2',
            }
        }
    elif device_type == "FSP150CC-XG116PRO (H)":
        library = {
            'get': {
                'sysName': '.1.3.6.1.2.1.1.5.0',
                'sysLocation': '.1.3.6.1.2.1.1.6.0',
                'sysDescr': '.1.3.6.1.2.1.1.1.0',
                'chassis_serial_number': '.1.3.6.1.2.1.47.1.1.1.1.11.1', #Device Chassis Serial Number
                'chassis_part_number': '.1.3.6.1.4.1.2544.1.12.3.1.3.1.8.1.1.1', #Device Chassis Part Number
                'chassis_active_software': '.1.3.6.1.4.1.2544.1.12.3.1.3.1.10.1.1.1', #Device Active Software
                'chassis_standby_software': '.1.3.6.1.4.1.2544.1.12.2.1.7.4.1.3.2', #Device Standby Software
                'chassis_download_software': '.1.3.6.1.4.1.2544.1.12.2.1.7.4.1.3.3', #Device Download Software
                'snmpEngineID': '.1.3.6.1.6.3.10.2.1.1.0' #SNMP Engine ID
            },
            'walk': {
                'remote_authentication_targets': '.1.3.6.1.4.1.2544.1.12.10.1.6.1.4', #remote authentication ipv4 targets
                'ifName': '.1.3.6.1.2.1.31.1.1.1.1', #Interface name
                'ifAlias': '.1.3.6.1.2.1.31.1.1.1.18', #interface alias
                'ifAdminStatus': '.1.3.6.1.2.1.2.2.1.7', #interface admin status
                'ifOperStatus': '.1.3.6.1.2.1.2.2.1.8', #interface oper status
                'etherStatsCRCAlignErrors': '.1.3.6.1.2.1.16.1.1.1.8',  # interface crc errors
                'sfp_vendor_name': '.1.3.6.1.4.1.2544.1.12.4.1.27.1.13.1.1.1', #SFP Vendor name
                'sfp_vendor_part_number': '.1.3.6.1.4.1.2544.1.12.4.1.27.1.14.1.1.1', #SFP Vendor part number
                'sfp_vendor_part_serial_number': '.1.3.6.1.4.1.2544.1.12.4.1.27.1.15.1.1.1', #SFP Vendor part serial number
                'sfp_vendor_wavelength': '.1.3.6.1.4.1.2544.1.12.4.1.27.1.19.1.1.1', #SFP wavelength
                'ethernet_traffic_port_stats_interval_type': '.1.3.6.1.4.1.2544.1.12.5.1.21.1.2', #Syntax CmPmIntervalType (INTEGER) {interval-15min (1),interval-1day (2),rollover (3), interval-5min (4)
                'cmEthernetTrafficPortStatsABRRx': '.1.3.6.1.4.1.2544.1.12.5.1.21.1.37', #Indexes	 neIndex, shelfIndex, slotIndex, cmEthernetTrafficPortIndex, cmEthernetTrafficPortStatsIndex
                'cmEthernetTrafficPortStatsABRTx': '.1.3.6.1.4.1.2544.1.12.5.1.21.1.38',# Indexes	 neIndex, shelfIndex, slotIndex, cmEthernetTrafficPortIndex, cmEthernetTrafficPortStatsIndex

            }

        }
    elif device_type == "FSP150EG-X":
        library = {
            'get': {
                'sysName': '.1.3.6.1.2.1.1.5.0',
                'sysLocation': '.1.3.6.1.2.1.1.6.0',
                'sysDescr': '.1.3.6.1.2.1.1.1.0',
                'chassis_serial_number': '.1.3.6.1.2.1.47.1.1.1.1.11.1', #Device Chassis Serial Number
                'chassis_part_number': '.1.3.6.1.4.1.2544.1.12.3.1.3.1.8.1.1.1', #Device Chassis Part Number
                'chassis_active_software': '.1.3.6.1.4.1.2544.1.12.3.1.3.1.10.1.1.1', #Device Active Software
                'chassis_standby_software': '.1.3.6.1.4.1.2544.1.12.2.1.7.4.1.3.2', #Device Standby Software
                'chassis_download_software': '.1.3.6.1.4.1.2544.1.12.2.1.7.4.1.3.3', #Device Download Software
                'snmpEngineID': '.1.3.6.1.6.3.10.2.1.1.0' #SNMP Engine ID
            }
        }
    elif device_type == "ETX-203AX":
        library = {
            'get': {
                'sysName': '.1.3.6.1.2.1.1.5.0',
                'sysDescr': '.1.3.6.1.2.1.1.1.0',
                'chassis_mac_address': '.1.3.6.1.2.1.47.1.1.1.1.11.1001',
                'chassis_active_software': '.1.3.6.1.2.1.47.1.1.1.1.10.1001',
                'chassis_active_software_sw_pack_1': '.1.3.6.1.4.1.164.6.2.67.4.1.1.1.0.24.9.115.119.45.112.97.99.107.45.49',
                'chassis_active_software_sw_pack_2': '.1.3.6.1.4.1.164.6.2.67.4.1.1.1.0.24.9.115.119.45.112.97.99.107.45.50',
                'snmpEngineID': '.1.3.6.1.6.3.10.2.1.1.0'  # SNMP Engine ID
            },
            'walk': {
                'ifIndex': '.1.3.6.1.2.1.2.2.1.1',
                'ifAlias': '.1.3.6.1.2.1.31.1.1.1.18',
                'ifDescr': '.1.3.6.1.2.1.2.2.1.2',
                'ifAdminStatus': '.1.3.6.1.2.1.2.2.1.7',
                'ifOperStatus': '.1.3.6.1.2.1.2.2.1.8',
                'ifHighSpeed': '.1.3.6.1.2.1.31.1.1.1.15',
                'interface_optical_rx': '.1.3.6.1.4.1.164.6.2.15.8.1.1.6',
                'interface_optical_tx': '.1.3.6.1.4.1.164.6.2.15.8.1.1.3',
                'sfp_connector_type': '.1.3.6.1.4.1.164.6.2.15.1.1.2',
                'sfp_connector_wavelength': '.1.3.6.1.4.1.164.6.2.15.1.1.3',
                'sfp_connector_optical_mode': '.1.3.6.1.4.1.164.6.2.15.1.1.4',
                'sfp_mfg_name': '.1.3.6.1.4.1.164.6.2.15.1.1.7',
                'sfp_part_number': '.1.3.6.1.4.1.164.6.2.15.1.1.10',
                'etherStatsCRCAlignErrors': '.1.3.6.1.2.1.16.1.1.1.8',
                'etherStatsCollisions': '.1.3.6.1.2.1.16.1.1.1.13',
                'ifInOctets': '.1.3.6.1.2.1.2.2.1.10',
                'ifOutOctets': '.1.3.6.1.2.1.2.2.1.16',
                'flow_name': '.1.3.6.1.4.1.164.20.8.1.6.3.1.3',
                'flow_outer_vlan_tagging': '.1.3.6.1.4.1.164.20.8.1.6.3.1.12',
                'flow_outer_vlan': '.1.3.6.1.4.1.164.20.8.1.6.3.1.13',
                'flow_inner_vlan_tagging': '.1.3.6.1.4.1.164.20.8.1.6.3.1.14',
                'flow_inner_vlan': '.1.3.6.1.4.1.164.20.8.1.6.3.1.15',
                'flow_egress_port': '.1.3.6.1.4.1.164.20.8.1.6.3.1.16',
                'flow_ingress_port': '.1.3.6.1.4.1.164.20.8.1.6.3.1.17',
                'flow_mark_outer_vlan_tagging': '.1.3.6.1.4.1.164.20.8.1.6.3.1.26',
                'flow_mark_outer_vlan': '.1.3.6.1.4.1.164.20.8.1.6.3.1.27',
                'flow_mark_inner_vlan_tagging': '.1.3.6.1.4.1.164.20.8.1.6.3.1.28',
                'flow_mark_inner_vlan': '.1.3.6.1.4.1.164.20.8.1.6.3.1.29',
                'service_stat_table': '.1.3.6.1.4.1.164.6.3.8', # RAD-MIB -> serviceStatTable - Traffic stats for all flows
            }

        }
    elif device_type == "ETX-220A":
        library = {
            'get': {
                'sysName': '.1.3.6.1.2.1.1.5.0',
                'sysDescr': '.1.3.6.1.2.1.1.1.0',
                'chassis_mac_address': '.1.3.6.1.2.1.47.1.1.1.1.11.1001',
                'chassis_active_software': '.1.3.6.1.2.1.47.1.1.1.1.10.1001',
                'chassis_active_software_sw_pack_1': '.1.3.6.1.4.1.164.6.2.67.4.1.1.1.0.24.9.115.119.45.112.97.99.107.45.49',
                'chassis_active_software_sw_pack_2': '.1.3.6.1.4.1.164.6.2.67.4.1.1.1.0.24.9.115.119.45.112.97.99.107.45.50',
                'snmpEngineID': '.1.3.6.1.6.3.10.2.1.1.0'  # SNMP Engine ID
            },
            'walk': {
                'ifIndex': '.1.3.6.1.2.1.2.2.1.1',
                'ifAlias': '.1.3.6.1.2.1.31.1.1.1.18',
                'ifDescr': '.1.3.6.1.2.1.2.2.1.2',
                'ifAdminStatus': '.1.3.6.1.2.1.2.2.1.7',
                'ifOperStatus': '.1.3.6.1.2.1.2.2.1.8',
                'ifHighSpeed': '.1.3.6.1.2.1.31.1.1.1.15',
                'interface_optical_rx': '.1.3.6.1.4.1.164.6.2.15.8.1.1.6',
                'interface_optical_tx': '.1.3.6.1.4.1.164.6.2.15.8.1.1.3',
                'sfp_connector_type': '.1.3.6.1.4.1.164.6.2.15.1.1.2',
                'sfp_connector_wavelength': '.1.3.6.1.4.1.164.6.2.15.1.1.3',
                'sfp_connector_optical_mode': '.1.3.6.1.4.1.164.6.2.15.1.1.4',
                'sfp_mfg_name': '.1.3.6.1.4.1.164.6.2.15.1.1.7',
                'sfp_part_number': '.1.3.6.1.4.1.164.6.2.15.1.1.10',
                'etherStatsCRCAlignErrors': '.1.3.6.1.2.1.16.1.1.1.8',
                'etherStatsCollisions': '.1.3.6.1.2.1.16.1.1.1.13',
                'ifInOctets': '.1.3.6.1.2.1.2.2.1.10',
                'ifOutOctets': '.1.3.6.1.2.1.2.2.1.16',
                'flow_name': '.1.3.6.1.4.1.164.20.8.1.6.3.1.3',
                'flow_outer_vlan_tagging': '.1.3.6.1.4.1.164.20.8.1.6.3.1.12',
                'flow_outer_vlan': '.1.3.6.1.4.1.164.20.8.1.6.3.1.13',
                'flow_inner_vlan_tagging': '.1.3.6.1.4.1.164.20.8.1.6.3.1.14',
                'flow_inner_vlan': '.1.3.6.1.4.1.164.20.8.1.6.3.1.15',
                'flow_egress_port': '.1.3.6.1.4.1.164.20.8.1.6.3.1.16',
                'flow_ingress_port': '.1.3.6.1.4.1.164.20.8.1.6.3.1.17',
                'flow_mark_outer_vlan_tagging': '.1.3.6.1.4.1.164.20.8.1.6.3.1.26',
                'flow_mark_outer_vlan': '.1.3.6.1.4.1.164.20.8.1.6.3.1.27',
                'flow_mark_inner_vlan_tagging': '.1.3.6.1.4.1.164.20.8.1.6.3.1.28',
                'flow_mark_inner_vlan': '.1.3.6.1.4.1.164.20.8.1.6.3.1.29',
                'service_stat_table': '.1.3.6.1.4.1.164.6.3.8', # RAD-MIB -> serviceStatTable - Traffic stats for all flows
            }

        }
    elif device_type == "ETX-2I-10G":
        library = {
            'get': {
                'sysName': '.1.3.6.1.2.1.1.5.0',
                'sysDescr': '.1.3.6.1.2.1.1.1.0',
                'chassis_mac_address': '.1.3.6.1.2.1.47.1.1.1.1.11.1001',
                'chassis_active_software': '.1.3.6.1.2.1.47.1.1.1.1.10.1001',
                'chassis_active_software_sw_pack_1': '.1.3.6.1.4.1.164.6.2.67.4.1.1.1.0.24.9.115.119.45.112.97.99.107.45.49',
                'chassis_active_software_sw_pack_2': '.1.3.6.1.4.1.164.6.2.67.4.1.1.1.0.24.9.115.119.45.112.97.99.107.45.50',
                'snmpEngineID': '.1.3.6.1.6.3.10.2.1.1.0'  # SNMP Engine ID
            },
            'walk': {
                'ifIndex': '.1.3.6.1.2.1.2.2.1.1',
                'ifAlias': '.1.3.6.1.2.1.31.1.1.1.18',
                'ifDescr': '.1.3.6.1.2.1.2.2.1.2',
                'ifAdminStatus': '.1.3.6.1.2.1.2.2.1.7',
                'ifOperStatus': '.1.3.6.1.2.1.2.2.1.8',
                'ifHighSpeed': '.1.3.6.1.2.1.31.1.1.1.15',
                'interface_optical_rx': '.1.3.6.1.4.1.164.6.2.15.8.1.1.6',
                'interface_optical_tx': '.1.3.6.1.4.1.164.6.2.15.8.1.1.3',
                'sfp_connector_type': '.1.3.6.1.4.1.164.6.2.15.1.1.2',
                'sfp_connector_wavelength': '.1.3.6.1.4.1.164.6.2.15.1.1.3',
                'sfp_connector_optical_mode': '.1.3.6.1.4.1.164.6.2.15.1.1.4',
                'sfp_mfg_name': '.1.3.6.1.4.1.164.6.2.15.1.1.7',
                'sfp_part_number': '.1.3.6.1.4.1.164.6.2.15.1.1.10',
                'etherStatsCRCAlignErrors': '.1.3.6.1.2.1.16.1.1.1.8',
                'etherStatsCollisions': '.1.3.6.1.2.1.16.1.1.1.13',
                'ifInOctets': '.1.3.6.1.2.1.2.2.1.10',
                'ifOutOctets': '.1.3.6.1.2.1.2.2.1.16',
                'flow_name': '.1.3.6.1.4.1.164.20.8.1.6.3.1.3',
                'flow_outer_vlan_tagging': '.1.3.6.1.4.1.164.20.8.1.6.3.1.12',
                'flow_outer_vlan': '.1.3.6.1.4.1.164.20.8.1.6.3.1.13',
                'flow_inner_vlan_tagging': '.1.3.6.1.4.1.164.20.8.1.6.3.1.14',
                'flow_inner_vlan': '.1.3.6.1.4.1.164.20.8.1.6.3.1.15',
                'flow_egress_port': '.1.3.6.1.4.1.164.20.8.1.6.3.1.16',
                'flow_ingress_port': '.1.3.6.1.4.1.164.20.8.1.6.3.1.17',
                'flow_mark_outer_vlan_tagging': '.1.3.6.1.4.1.164.20.8.1.6.3.1.26',
                'flow_mark_outer_vlan': '.1.3.6.1.4.1.164.20.8.1.6.3.1.27',
                'flow_mark_inner_vlan_tagging': '.1.3.6.1.4.1.164.20.8.1.6.3.1.28',
                'flow_mark_inner_vlan': '.1.3.6.1.4.1.164.20.8.1.6.3.1.29',
                'service_stat_table': '.1.3.6.1.4.1.164.6.3.8', # RAD-MIB -> serviceStatTable - Traffic stats for all flows
            }

        }
    elif device_type == "ETX-2I-10G-LC":
        library = {
            'get': {
                'sysName': '.1.3.6.1.2.1.1.5.0',
                'sysDescr': '.1.3.6.1.2.1.1.1.0',
                'chassis_mac_address': '.1.3.6.1.2.1.47.1.1.1.1.11.1001',
                'chassis_active_software': '.1.3.6.1.2.1.47.1.1.1.1.10.1001',
                'chassis_active_software_sw_pack_1': '.1.3.6.1.4.1.164.6.2.67.4.1.1.1.0.24.9.115.119.45.112.97.99.107.45.49',
                'chassis_active_software_sw_pack_2': '.1.3.6.1.4.1.164.6.2.67.4.1.1.1.0.24.9.115.119.45.112.97.99.107.45.50',
                'snmpEngineID': '.1.3.6.1.6.3.10.2.1.1.0'  # SNMP Engine ID
            },
            'walk': {
                'ifIndex': '.1.3.6.1.2.1.2.2.1.1',
                'ifAlias': '.1.3.6.1.2.1.31.1.1.1.18',
                'ifDescr': '.1.3.6.1.2.1.2.2.1.2',
                'ifAdminStatus': '.1.3.6.1.2.1.2.2.1.7',
                'ifOperStatus': '.1.3.6.1.2.1.2.2.1.8',
                'ifHighSpeed': '.1.3.6.1.2.1.31.1.1.1.15',
                'interface_optical_rx': '.1.3.6.1.4.1.164.6.2.15.8.1.1.6',
                'interface_optical_tx': '.1.3.6.1.4.1.164.6.2.15.8.1.1.3',
                'sfp_connector_type': '.1.3.6.1.4.1.164.6.2.15.1.1.2',
                'sfp_connector_wavelength': '.1.3.6.1.4.1.164.6.2.15.1.1.3',
                'sfp_connector_optical_mode': '.1.3.6.1.4.1.164.6.2.15.1.1.4',
                'sfp_mfg_name': '.1.3.6.1.4.1.164.6.2.15.1.1.7',
                'sfp_part_number': '.1.3.6.1.4.1.164.6.2.15.1.1.10',
                'etherStatsCRCAlignErrors': '.1.3.6.1.2.1.16.1.1.1.8',
                'etherStatsCollisions': '.1.3.6.1.2.1.16.1.1.1.13',
                'ifInOctets': '.1.3.6.1.2.1.2.2.1.10',
                'ifOutOctets': '.1.3.6.1.2.1.2.2.1.16',
                'flow_name': '.1.3.6.1.4.1.164.20.8.1.6.3.1.3',
                'flow_outer_vlan_tagging': '.1.3.6.1.4.1.164.20.8.1.6.3.1.12',
                'flow_outer_vlan': '.1.3.6.1.4.1.164.20.8.1.6.3.1.13',
                'flow_inner_vlan_tagging': '.1.3.6.1.4.1.164.20.8.1.6.3.1.14',
                'flow_inner_vlan': '.1.3.6.1.4.1.164.20.8.1.6.3.1.15',
                'flow_egress_port': '.1.3.6.1.4.1.164.20.8.1.6.3.1.16',
                'flow_ingress_port': '.1.3.6.1.4.1.164.20.8.1.6.3.1.17',
                'flow_mark_outer_vlan_tagging': '.1.3.6.1.4.1.164.20.8.1.6.3.1.26',
                'flow_mark_outer_vlan': '.1.3.6.1.4.1.164.20.8.1.6.3.1.27',
                'flow_mark_inner_vlan_tagging': '.1.3.6.1.4.1.164.20.8.1.6.3.1.28',
                'flow_mark_inner_vlan': '.1.3.6.1.4.1.164.20.8.1.6.3.1.29',
                'service_stat_table': '.1.3.6.1.4.1.164.6.3.8', # RAD-MIB -> serviceStatTable - Traffic stats for all flows
            }

        }
    elif device_type == "FSP150CC-XG116PRO":
        library = {
            'get': {
                'sysName': '.1.3.6.1.2.1.1.5.0',
                'sysLocation': '.1.3.6.1.2.1.1.6.0',
                'sysDescr': '.1.3.6.1.2.1.1.1.0',
                'chassis_serial_number': '.1.3.6.1.2.1.47.1.1.1.1.11.1', #Device Chassis Serial Number
                'chassis_part_number': '.1.3.6.1.4.1.2544.1.12.3.1.3.1.8.1.1.1', #Device Chassis Part Number
                'chassis_active_software': '.1.3.6.1.4.1.2544.1.12.3.1.3.1.10.1.1.1', #Device Active Software
                'chassis_standby_software': '.1.3.6.1.4.1.2544.1.12.2.1.7.4.1.3.2', #Device Standby Software
                'chassis_download_software': '.1.3.6.1.4.1.2544.1.12.2.1.7.4.1.3.3', #Device Download Software
                'snmpEngineID': '.1.3.6.1.6.3.10.2.1.1.0' #SNMP Engine ID
            },
            'walk': {
                'remote_authentication_targets': '.1.3.6.1.4.1.2544.1.12.10.1.6.1.4', #remote authentication ipv4 targets
                'ifName': '.1.3.6.1.2.1.31.1.1.1.1', #Interface name
                'ifAlias': '.1.3.6.1.2.1.31.1.1.1.18', #interface alias
                'ifAdminStatus': '.1.3.6.1.2.1.2.2.1.7', #interface admin status
                'ifOperStatus': '.1.3.6.1.2.1.2.2.1.8', #interface oper status
                'etherStatsCRCAlignErrors': '.1.3.6.1.2.1.16.1.1.1.8', #interface crc errors
                'sfp_vendor_name': '.1.3.6.1.4.1.2544.1.12.4.1.27.1.13.1.1.1', #SFP Vendor name
                'sfp_vendor_part_number': '.1.3.6.1.4.1.2544.1.12.4.1.27.1.14.1.1.1', #SFP Vendor part number
                'sfp_vendor_part_serial_number': '.1.3.6.1.4.1.2544.1.12.4.1.27.1.15.1.1.1', #SFP Vendor part serial number
                'sfp_vendor_wavelength': '.1.3.6.1.4.1.2544.1.12.4.1.27.1.19.1.1.1', #SFP wavelength
                'ethernet_traffic_port_stats_interval_type': '.1.3.6.1.4.1.2544.1.12.5.1.21.1.2', #Syntax CmPmIntervalType (INTEGER) {interval-15min (1),interval-1day (2),rollover (3), interval-5min (4)
                'cmEthernetTrafficPortStatsABRRx': '.1.3.6.1.4.1.2544.1.12.5.1.21.1.37', # Indexes	 neIndex, shelfIndex, slotIndex, cmEthernetTrafficPortIndex, cmEthernetTrafficPortStatsIndex
                'cmEthernetTrafficPortStatsABRTx': '.1.3.6.1.4.1.2544.1.12.5.1.21.1.38', # Indexes	 neIndex, shelfIndex, slotIndex, cmEthernetTrafficPortIndex, cmEthernetTrafficPortStatsIndex

            }

        }
    elif device_type == "RE-NFX250-S1-JDM":
        library = {
            'get': {
                'sysName': '.1.3.6.1.2.1.1.5.0',
                'sysLocation': '.1.3.6.1.2.1.1.6.0',
                'sysDescr': '.1.3.6.1.2.1.1.1.0',
                'snmpEngineID': '.1.3.6.1.6.3.10.2.1.1.0' #SNMP Engine ID
            }

        }
    elif device_type == "C3560E":
        library = {
            'get': {
                'sysName': '.1.3.6.1.2.1.1.5.0',
                'domain': '.1.3.6.1.4.1.9.2.1.4.0',
                'sysName': '.1.3.6.1.2.1.1.5.0',
                'sysDescr': '.1.3.6.1.2.1.1.1.0',
                'sysLocation': '.1.3.6.1.2.1.1.6.0'
            },
            'walk': {
                'ifIndex': '.1.3.6.1.2.1.2.2.1.1',
                'ifDescr': '.1.3.6.1.2.1.2.2.1.2',
                'ifName': '.1.3.6.1.2.1.31.1.1.1.1',
                'ifAlias': '.1.3.6.1.2.1.31.1.1.1.18',
                'ifType': '.1.3.6.1.2.1.2.2.1.3',
                'ifMtu': '.1.3.6.1.2.1.2.2.1.4',
                'ifSpeed': '.1.3.6.1.2.1.2.2.1.5',
                'ifAdminStatus': '.1.3.6.1.2.1.2.2.1.7',
                'ifOperStatus': '.1.3.6.1.2.1.2.2.1.8',
                'dot1dBasePortIfIndex': '.1.3.6.1.2.1.17.1.4.1.2',
                'vtpVlanState': '.1.3.6.1.4.1.9.9.46.1.3.1.1.2',
                'cviRoutedVlanIfIndex': '.1.3.6.1.4.1.9.9.128.1.1.1.1.3', # cviVlanId, cviPhysicalifindex - The index for the ifTable entry associated with this routed VLAN interface
                'cdpInterfaceName': '.1.3.6.1.4.1.9.9.23.1.1.1.1.6',      # The name of the local interface as advertised by CDP in the PORT TLV
                'cdpCacheDeviceId': '.1.3.6.1.4.1.9.9.23.1.2.1.1.6',      # The Device-ID string as reported in the most recent CDP message.
                                                                          # The zero-length string indicates no Device-ID
                                                                          # field (TLV) was reported in the most recent CDP message.

                'cdpCacheDevicePort': '.1.3.6.1.4.1.9.9.23.1.2.1.1.7',    # The Port-ID string as reported in the most recent CDP
                                                                          # message.  This will typically be the value of the ifName
                                                                          # object (e.g., 'Ethernet0').  The zero-length string
                                                                          # indicates no Port-ID field (TLV) was reported in the
                                                                          # most recent CDP message.
                'cdpCachePlatform': '.1.3.6.1.4.1.9.9.23.1.2.1.1.8',      # The Device's Hardware Platform as reported in the most
                                                                          # recent CDP message.  The zero-length string indicates
                                                                          # that no Platform field (TLV) was reported in the most
                                                                          # recent CDP message.
                'vtpVlanName': '.1.3.6.1.4.1.9.9.46.1.3.1.1.4',
                'vtpVlanType': '.1.3.6.1.4.1.9.9.46.1.3.1.1.3',           # Type of vlan -Syntax	 VlanType (INTEGER) {ethernet(1),
                                                                          # fddi(2),
                                                                          # tokenRing(3), fddiNet(4),
                                                                          # trNet(5), deprecated(6)
                'dot1dTpFdbPort': '.1.3.6.1.2.1.17.4.3.1.2',              # Either the value '0', or the port number of the port on
                                                                          # which a frame having a source address equal to the value
                                                                          # of the corresponding instance of dot1dTpFdbAddress has
                                                                          # been seen.  A value of '0' indicates that the port
                                                                          # number has not been learned, but that the bridge does
                                                                          # have some forwarding/filtering information about this
                                                                          # address (e.g., in the dot1dStaticTable).  Implementors
                                                                          # are encouraged to assign the port value to this object
                                                                          # whenever it is learned, even for addresses for which the
                                                                          # corresponding value of dot1dTpFdbStatus is not
                                                                          # learned(3).
                                                                          # For cisco - Filter out the first .1.3.6.1.2.1.17.4.3.1.2. then convert
                                                                          # the rest from decimal to hex
                #'cefcFRUPowerAdminStatus': '.1.3.6.1.4.1.9.9.117.1.1.2.1.1', # Syntax	 PowerAdminType (INTEGER) {on(1), off(2), inlineAuto(3), inlineOn(4), powerCycle(5)
                #'cefcFRUPowerOperStatus': '.1.3.6.1.4.1.9.9.117.1.1.2.1.2', # PowerOperType (INTEGER) {offEnvOther(1), on(2), offAdmin(3), offDenied(4), offEnvPower(5), offEnvTemp(6), offEnvFan(7), failed(8), onButFanFail(9), offCooling(10), offConnectorRating(11), onButInlinePowerFail(12)
                'entPhysicalDescr': '.1.3.6.1.2.1.47.1.1.1.1.2', # A textual description of physical entity.  This object should contain a string that identifies the manufacturer's name for the physical entity, and should be set to a distinct value for each version or model of the physical entity.
                'entPhysicalHardwareRev': '.1.3.6.1.2.1.47.1.1.1.1.8',
                'entPhysicalFirmwareRev': '.1.3.6.1.2.1.47.1.1.1.1.9',
                'entPhysicalSoftwareRev': '.1.3.6.1.2.1.47.1.1.1.1.10',
                'entPhysicalSerialNum': '.1.3.6.1.2.1.47.1.1.1.1.11',
                'entPhysicalModelName': '.1.3.6.1.2.1.47.1.1.1.1.13',
                'lldpRemChassisId': '.1.0.8802.1.1.2.1.4.1.1.5',          # The string value used to identify the chassis component associated with the remote system
                'lldpRemPortIdSubtype': '.1.0.8802.1.1.2.1.4.1.1.6',      # The type of port identifier encoding used in the associated 'lldpRemPortId' object
                'lldpRemPortDesc': '.1.0.8802.1.1.2.1.4.1.1.8',           # The string value used to identify the description of the given port associated with the remote system.
                'lldpRemSysName': '.1.0.8802.1.1.2.1.4.1.1.9',            # The string value used to identify the system name of the of the remote system.
                'lldpRemSysDesc': '.1.0.8802.1.1.2.1.4.1.1.10',           # The string value used to identify the system description of the remote system.
                'lldpRemChassisIdSubtype': '.1.0.8802.1.1.2.1.4.1.1.4',   # The type of encoding used to identify the chassis associated with the remote system.
                'lldpRemSysCapSupported': '.1.0.8802.1.1.2.1.4.1.1.11',   # The bitmap value used to identify which system capabilities are supported on the remote system.
                'lldpRemSysCapEnabled': '.1.0.8802.1.1.2.1.4.1.1.12',     # The bitmap value used to identify which system capabilities are enabled on the remote system.
                'lldpLocPortIdSubtype': '.1.0.8802.1.1.2.1.3.7.1.2',      # The type of port identifier encoding used in the associated
                'lldpLocPortId': '.1.0.8802.1.1.2.1.3.7.1.3',             # The string value used to identify the port component associated with a given port in the local system.
                'lldpLocPortDesc': '.1.0.8802.1.1.2.1.3.7.1.4',           # The string value used to identify the 802 LAN station's port description associated with the local system.  If the local agent supports IETF RFC 2863, lldpLocPortDesc object should have the same value of ifDescr object
                'entPhysicalAlias': '.1.3.6.1.2.1.47.1.1.1.1.14',         # This will alow you to reference the pyhsical entity with another associated value like the plugable information.
                                                                          # This will refer to the ifIndex as well
                'ipAdEntAddr': '.1.3.6.1.2.1.4.20.1.1',                   # Returns any ip addresses configured
                'ipAdEntNetMask': '.1.3.6.1.2.1.4.20.1.3',                   # Returns any ip subnet configured for the above
                'ipAdEntIfIndex': '.1.3.6.1.2.1.4.20.1.2',                # Ip address and interface index the address is tied too
            },
            'values': {
                'ifAdminStatus': {
                    '1': 'Up',
                    '2': 'Down',
                    '3': 'Testing'
                },
                'ifOperStatus': {
                    '1': 'Up',
                    '2': 'Down',
                    '3': 'Testing',
                    '4': 'Unknown',
                    '5': 'Dormant',
                    '6': 'Not Present',
                    '7': 'Lower Layer Down',
                },
                'lldpRemChassisIdSubtype': {
                    '1': 'chassisComponent',
                    '2': 'interfaceAlias',
                    '3': 'portComponent',
                    '4': 'macAddress',
                    '5': 'networkAddress',
                    '6': 'interfaceName',
                    '7': 'local'
                },
                'lldpRemPortIdSubtype': {
                    '1': 'interfaceAlias',
                    '2': 'portComponent',
                    '3': 'macAddress',
                    '4': 'networkAddress',
                    '5': 'interfaceName',
                    '6': 'agentCircuitId',
                    '7': 'local',
                },
                'lldpRemSysCapSupported': {
                    '0': 'other',
                    '1': 'repeater',
                    '2': 'bridge',
                    '3': 'wlanAccessPoint',
                    '4': 'router',
                    '5': 'telephone',
                    '6': 'docsisCableDevice',
                    '7': 'stationOnly'
                },
                'lldpRemSysCapEnabled': {
                    '0': 'other',
                    '1': 'repeater',
                    '2': 'bridge',
                    '3': 'wlanAccessPoint',
                    '4': 'router',
                    '5': 'telephone',
                    '6': 'docsisCableDevice',
                    '7': 'stationOnly'
                },
                'lldpLocPortIdSubtype': {
                    '1': 'interfaceAlias',
                    '2': 'portComponent',
                    '3': 'macAddress',
                    '4': 'networkAddress',
                    '5': 'interfaceName',
                    '6': 'agentCircuitId',
                    '7': 'local',
                },
                'vtpVlanType': {
                    '1': 'ethernet',
                    '2': 'fddi',
                    '3': 'tokenRing',
                    '4': 'fddiNet',
                    '5': 'trNet',
                    '6': 'deprecated',
                }
            }
        }
    elif device_type == "WS-C3650":
        library = {
            'get': {
                'sysName': '.1.3.6.1.2.1.1.5.0',
                'domain': '.1.3.6.1.4.1.9.2.1.4.0',
                'sysName': '.1.3.6.1.2.1.1.5.0',
                'sysDescr': '.1.3.6.1.2.1.1.1.0',
                'sysLocation': '.1.3.6.1.2.1.1.6.0'
            },
            'walk': {
                'ifIndex': '.1.3.6.1.2.1.2.2.1.1',
                'ifDescr': '.1.3.6.1.2.1.2.2.1.2',
                'ifName': '.1.3.6.1.2.1.31.1.1.1.1',
                'ifAlias': '.1.3.6.1.2.1.31.1.1.1.18',
                'ifType': '.1.3.6.1.2.1.2.2.1.3',
                'ifMtu': '.1.3.6.1.2.1.2.2.1.4',
                'ifSpeed': '.1.3.6.1.2.1.2.2.1.5',
                'ifAdminStatus': '.1.3.6.1.2.1.2.2.1.7',
                'ifOperStatus': '.1.3.6.1.2.1.2.2.1.8',
                'dot1dBasePortIfIndex': '.1.3.6.1.2.1.17.1.4.1.2',
                'vtpVlanState': '.1.3.6.1.4.1.9.9.46.1.3.1.1.2',
                'cviRoutedVlanIfIndex': '.1.3.6.1.4.1.9.9.128.1.1.1.1.3', # cviVlanId, cviPhysicalifindex - The index for the ifTable entry associated with this routed VLAN interface
                'cdpInterfaceName': '.1.3.6.1.4.1.9.9.23.1.1.1.1.6',      # The name of the local interface as advertised by CDP in the PORT TLV
                'cdpCacheDeviceId': '.1.3.6.1.4.1.9.9.23.1.2.1.1.6',      # The Device-ID string as reported in the most recent CDP message.
                                                                          # The zero-length string indicates no Device-ID
                                                                          # field (TLV) was reported in the most recent CDP message.

                'cdpCacheDevicePort': '.1.3.6.1.4.1.9.9.23.1.2.1.1.7',    # The Port-ID string as reported in the most recent CDP
                                                                          # message.  This will typically be the value of the ifName
                                                                          # object (e.g., 'Ethernet0').  The zero-length string
                                                                          # indicates no Port-ID field (TLV) was reported in the
                                                                          # most recent CDP message.
                'cdpCachePlatform': '.1.3.6.1.4.1.9.9.23.1.2.1.1.8',      # The Device's Hardware Platform as reported in the most
                                                                          # recent CDP message.  The zero-length string indicates
                                                                          # that no Platform field (TLV) was reported in the most
                                                                          # recent CDP message.
                'vtpVlanName': '.1.3.6.1.4.1.9.9.46.1.3.1.1.4',
                'vtpVlanType': '.1.3.6.1.4.1.9.9.46.1.3.1.1.3',           # Type of vlan -Syntax	 VlanType (INTEGER) {ethernet(1),
                                                                          # fddi(2),
                                                                          # tokenRing(3), fddiNet(4),
                                                                          # trNet(5), deprecated(6)
                'dot1dTpFdbPort': '.1.3.6.1.2.1.17.4.3.1.2',              # Either the value '0', or the port number of the port on
                                                                          # which a frame having a source address equal to the value
                                                                          # of the corresponding instance of dot1dTpFdbAddress has
                                                                          # been seen.  A value of '0' indicates that the port
                                                                          # number has not been learned, but that the bridge does
                                                                          # have some forwarding/filtering information about this
                                                                          # address (e.g., in the dot1dStaticTable).  Implementors
                                                                          # are encouraged to assign the port value to this object
                                                                          # whenever it is learned, even for addresses for which the
                                                                          # corresponding value of dot1dTpFdbStatus is not
                                                                          # learned(3).
                                                                          # For cisco - Filter out the first .1.3.6.1.2.1.17.4.3.1.2. then convert
                                                                          # the rest from decimal to hex
                #'cefcFRUPowerAdminStatus': '.1.3.6.1.4.1.9.9.117.1.1.2.1.1', # Syntax	 PowerAdminType (INTEGER) {on(1), off(2), inlineAuto(3), inlineOn(4), powerCycle(5)
                #'cefcFRUPowerOperStatus': '.1.3.6.1.4.1.9.9.117.1.1.2.1.2', # PowerOperType (INTEGER) {offEnvOther(1), on(2), offAdmin(3), offDenied(4), offEnvPower(5), offEnvTemp(6), offEnvFan(7), failed(8), onButFanFail(9), offCooling(10), offConnectorRating(11), onButInlinePowerFail(12)
                'entPhysicalDescr': '.1.3.6.1.2.1.47.1.1.1.1.2', # A textual description of physical entity.  This object should contain a string that identifies the manufacturer's name for the physical entity, and should be set to a distinct value for each version or model of the physical entity.
                'entPhysicalHardwareRev': '.1.3.6.1.2.1.47.1.1.1.1.8',
                'entPhysicalFirmwareRev': '.1.3.6.1.2.1.47.1.1.1.1.9',
                'entPhysicalSoftwareRev': '.1.3.6.1.2.1.47.1.1.1.1.10',
                'entPhysicalSerialNum': '.1.3.6.1.2.1.47.1.1.1.1.11',
                'entPhysicalModelName': '.1.3.6.1.2.1.47.1.1.1.1.13',
                'lldpRemChassisId': '.1.0.8802.1.1.2.1.4.1.1.5',          # The string value used to identify the chassis component associated with the remote system
                'lldpRemPortIdSubtype': '.1.0.8802.1.1.2.1.4.1.1.6',      # The type of port identifier encoding used in the associated 'lldpRemPortId' object
                'lldpRemPortDesc': '.1.0.8802.1.1.2.1.4.1.1.8',           # The string value used to identify the description of the given port associated with the remote system.
                'lldpRemSysName': '.1.0.8802.1.1.2.1.4.1.1.9',            # The string value used to identify the system name of the of the remote system.
                'lldpRemSysDesc': '.1.0.8802.1.1.2.1.4.1.1.10',           # The string value used to identify the system description of the remote system.
                'lldpRemChassisIdSubtype': '.1.0.8802.1.1.2.1.4.1.1.4',   # The type of encoding used to identify the chassis associated with the remote system.
                'lldpRemSysCapSupported': '.1.0.8802.1.1.2.1.4.1.1.11',   # The bitmap value used to identify which system capabilities are supported on the remote system.
                'lldpRemSysCapEnabled': '.1.0.8802.1.1.2.1.4.1.1.12',     # The bitmap value used to identify which system capabilities are enabled on the remote system.
                'lldpLocPortIdSubtype': '.1.0.8802.1.1.2.1.3.7.1.2',      # The type of port identifier encoding used in the associated
                'lldpLocPortId': '.1.0.8802.1.1.2.1.3.7.1.3',             # The string value used to identify the port component associated with a given port in the local system.
                'lldpLocPortDesc': '.1.0.8802.1.1.2.1.3.7.1.4',           # The string value used to identify the 802 LAN station's port description associated with the local system.  If the local agent supports IETF RFC 2863, lldpLocPortDesc object should have the same value of ifDescr object
                'entPhysicalAlias': '.1.3.6.1.2.1.47.1.1.1.1.14',         # This will alow you to reference the pyhsical entity with another associated value like the plugable information.
                                                                          # This will refer to the ifIndex as well
                'ipAdEntAddr': '.1.3.6.1.2.1.4.20.1.1',                   # Returns any ip addresses configured
                'ipAdEntNetMask': '.1.3.6.1.2.1.4.20.1.3',                   # Returns any ip subnet configured for the above
                'ipAdEntIfIndex': '.1.3.6.1.2.1.4.20.1.2',                # Ip address and interface index the address is tied too
            },
            'values': {
                'ifAdminStatus': {
                    '1': 'Up',
                    '2': 'Down',
                    '3': 'Testing'
                },
                'ifOperStatus': {
                    '1': 'Up',
                    '2': 'Down',
                    '3': 'Testing',
                    '4': 'Unknown',
                    '5': 'Dormant',
                    '6': 'Not Present',
                    '7': 'Lower Layer Down',
                },
                'lldpRemChassisIdSubtype': {
                    '1': 'chassisComponent',
                    '2': 'interfaceAlias',
                    '3': 'portComponent',
                    '4': 'macAddress',
                    '5': 'networkAddress',
                    '6': 'interfaceName',
                    '7': 'local'
                },
                'lldpRemPortIdSubtype': {
                    '1': 'interfaceAlias',
                    '2': 'portComponent',
                    '3': 'macAddress',
                    '4': 'networkAddress',
                    '5': 'interfaceName',
                    '6': 'agentCircuitId',
                    '7': 'local',
                },
                'lldpRemSysCapSupported': {
                    '0': 'other',
                    '1': 'repeater',
                    '2': 'bridge',
                    '3': 'wlanAccessPoint',
                    '4': 'router',
                    '5': 'telephone',
                    '6': 'docsisCableDevice',
                    '7': 'stationOnly'
                },
                'lldpRemSysCapEnabled': {
                    '0': 'other',
                    '1': 'repeater',
                    '2': 'bridge',
                    '3': 'wlanAccessPoint',
                    '4': 'router',
                    '5': 'telephone',
                    '6': 'docsisCableDevice',
                    '7': 'stationOnly'
                },
                'lldpLocPortIdSubtype': {
                    '1': 'interfaceAlias',
                    '2': 'portComponent',
                    '3': 'macAddress',
                    '4': 'networkAddress',
                    '5': 'interfaceName',
                    '6': 'agentCircuitId',
                    '7': 'local',
                },
                'vtpVlanType': {
                    '1': 'ethernet',
                    '2': 'fddi',
                    '3': 'tokenRing',
                    '4': 'fddiNet',
                    '5': 'trNet',
                    '6': 'deprecated',
                }
            }
        }
    elif device_type == "WS-C3750":
        library = {
            'get': {
                'sysName': '.1.3.6.1.2.1.1.5.0',
                'domain': '.1.3.6.1.4.1.9.2.1.4.0',
                'sysName': '.1.3.6.1.2.1.1.5.0',
                'sysDescr': '.1.3.6.1.2.1.1.1.0',
                'sysLocation': '.1.3.6.1.2.1.1.6.0'
            },
            'walk': {
                'ifIndex': '.1.3.6.1.2.1.2.2.1.1',
                'ifDescr': '.1.3.6.1.2.1.2.2.1.2',
                'ifName': '.1.3.6.1.2.1.31.1.1.1.1',
                'ifAlias': '.1.3.6.1.2.1.31.1.1.1.18',
                'ifType': '.1.3.6.1.2.1.2.2.1.3',
                'ifMtu': '.1.3.6.1.2.1.2.2.1.4',
                'ifSpeed': '.1.3.6.1.2.1.2.2.1.5',
                'ifAdminStatus': '.1.3.6.1.2.1.2.2.1.7',
                'ifOperStatus': '.1.3.6.1.2.1.2.2.1.8',
                'dot1dBasePortIfIndex': '.1.3.6.1.2.1.17.1.4.1.2',
                'vtpVlanState': '.1.3.6.1.4.1.9.9.46.1.3.1.1.2',
                'cviRoutedVlanIfIndex': '.1.3.6.1.4.1.9.9.128.1.1.1.1.3', # cviVlanId, cviPhysicalifindex - The index for the ifTable entry associated with this routed VLAN interface
                'cdpInterfaceName': '.1.3.6.1.4.1.9.9.23.1.1.1.1.6',      # The name of the local interface as advertised by CDP in the PORT TLV
                'cdpCacheDeviceId': '.1.3.6.1.4.1.9.9.23.1.2.1.1.6',      # The Device-ID string as reported in the most recent CDP message.
                                                                          # The zero-length string indicates no Device-ID
                                                                          # field (TLV) was reported in the most recent CDP message.

                'cdpCacheDevicePort': '.1.3.6.1.4.1.9.9.23.1.2.1.1.7',    # The Port-ID string as reported in the most recent CDP
                                                                          # message.  This will typically be the value of the ifName
                                                                          # object (e.g., 'Ethernet0').  The zero-length string
                                                                          # indicates no Port-ID field (TLV) was reported in the
                                                                          # most recent CDP message.
                'cdpCachePlatform': '.1.3.6.1.4.1.9.9.23.1.2.1.1.8',      # The Device's Hardware Platform as reported in the most
                                                                          # recent CDP message.  The zero-length string indicates
                                                                          # that no Platform field (TLV) was reported in the most
                                                                          # recent CDP message.
                'vtpVlanName': '.1.3.6.1.4.1.9.9.46.1.3.1.1.4',
                'vtpVlanType': '.1.3.6.1.4.1.9.9.46.1.3.1.1.3',           # Type of vlan -Syntax	 VlanType (INTEGER) {ethernet(1),
                                                                          # fddi(2),
                                                                          # tokenRing(3), fddiNet(4),
                                                                          # trNet(5), deprecated(6)
                'dot1dTpFdbPort': '.1.3.6.1.2.1.17.4.3.1.2',              # Either the value '0', or the port number of the port on
                                                                          # which a frame having a source address equal to the value
                                                                          # of the corresponding instance of dot1dTpFdbAddress has
                                                                          # been seen.  A value of '0' indicates that the port
                                                                          # number has not been learned, but that the bridge does
                                                                          # have some forwarding/filtering information about this
                                                                          # address (e.g., in the dot1dStaticTable).  Implementors
                                                                          # are encouraged to assign the port value to this object
                                                                          # whenever it is learned, even for addresses for which the
                                                                          # corresponding value of dot1dTpFdbStatus is not
                                                                          # learned(3).
                                                                          # For cisco - Filter out the first .1.3.6.1.2.1.17.4.3.1.2. then convert
                                                                          # the rest from decimal to hex
                #'cefcFRUPowerAdminStatus': '.1.3.6.1.4.1.9.9.117.1.1.2.1.1', # Syntax	 PowerAdminType (INTEGER) {on(1), off(2), inlineAuto(3), inlineOn(4), powerCycle(5)
                #'cefcFRUPowerOperStatus': '.1.3.6.1.4.1.9.9.117.1.1.2.1.2', # PowerOperType (INTEGER) {offEnvOther(1), on(2), offAdmin(3), offDenied(4), offEnvPower(5), offEnvTemp(6), offEnvFan(7), failed(8), onButFanFail(9), offCooling(10), offConnectorRating(11), onButInlinePowerFail(12)
                'entPhysicalDescr': '.1.3.6.1.2.1.47.1.1.1.1.2', # A textual description of physical entity.  This object should contain a string that identifies the manufacturer's name for the physical entity, and should be set to a distinct value for each version or model of the physical entity.
                'entPhysicalHardwareRev': '.1.3.6.1.2.1.47.1.1.1.1.8',
                'entPhysicalFirmwareRev': '.1.3.6.1.2.1.47.1.1.1.1.9',
                'entPhysicalSoftwareRev': '.1.3.6.1.2.1.47.1.1.1.1.10',
                'entPhysicalSerialNum': '.1.3.6.1.2.1.47.1.1.1.1.11',
                'entPhysicalModelName': '.1.3.6.1.2.1.47.1.1.1.1.13',
                'lldpRemChassisId': '.1.0.8802.1.1.2.1.4.1.1.5',          # The string value used to identify the chassis component associated with the remote system
                'lldpRemPortIdSubtype': '.1.0.8802.1.1.2.1.4.1.1.6',      # The type of port identifier encoding used in the associated 'lldpRemPortId' object
                'lldpRemPortDesc': '.1.0.8802.1.1.2.1.4.1.1.8',           # The string value used to identify the description of the given port associated with the remote system.
                'lldpRemSysName': '.1.0.8802.1.1.2.1.4.1.1.9',            # The string value used to identify the system name of the of the remote system.
                'lldpRemSysDesc': '.1.0.8802.1.1.2.1.4.1.1.10',           # The string value used to identify the system description of the remote system.
                'lldpRemChassisIdSubtype': '.1.0.8802.1.1.2.1.4.1.1.4',   # The type of encoding used to identify the chassis associated with the remote system.
                'lldpRemSysCapSupported': '.1.0.8802.1.1.2.1.4.1.1.11',   # The bitmap value used to identify which system capabilities are supported on the remote system.
                'lldpRemSysCapEnabled': '.1.0.8802.1.1.2.1.4.1.1.12',     # The bitmap value used to identify which system capabilities are enabled on the remote system.
                'lldpLocPortIdSubtype': '.1.0.8802.1.1.2.1.3.7.1.2',      # The type of port identifier encoding used in the associated
                'lldpLocPortId': '.1.0.8802.1.1.2.1.3.7.1.3',             # The string value used to identify the port component associated with a given port in the local system.
                'lldpLocPortDesc': '.1.0.8802.1.1.2.1.3.7.1.4',           # The string value used to identify the 802 LAN station's port description associated with the local system.  If the local agent supports IETF RFC 2863, lldpLocPortDesc object should have the same value of ifDescr object
                'entPhysicalAlias': '.1.3.6.1.2.1.47.1.1.1.1.14',         # This will alow you to reference the pyhsical entity with another associated value like the plugable information.
                                                                          # This will refer to the ifIndex as well
                'ipAdEntAddr': '.1.3.6.1.2.1.4.20.1.1',                   # Returns any ip addresses configured
                'ipAdEntNetMask': '.1.3.6.1.2.1.4.20.1.3',                   # Returns any ip subnet configured for the above
                'ipAdEntIfIndex': '.1.3.6.1.2.1.4.20.1.2',                # Ip address and interface index the address is tied too
            },
            'values': {
                'ifAdminStatus': {
                    '1': 'Up',
                    '2': 'Down',
                    '3': 'Testing'
                },
                'ifOperStatus': {
                    '1': 'Up',
                    '2': 'Down',
                    '3': 'Testing',
                    '4': 'Unknown',
                    '5': 'Dormant',
                    '6': 'Not Present',
                    '7': 'Lower Layer Down',
                },
                'lldpRemChassisIdSubtype': {
                    '1': 'chassisComponent',
                    '2': 'interfaceAlias',
                    '3': 'portComponent',
                    '4': 'macAddress',
                    '5': 'networkAddress',
                    '6': 'interfaceName',
                    '7': 'local'
                },
                'lldpRemPortIdSubtype': {
                    '1': 'interfaceAlias',
                    '2': 'portComponent',
                    '3': 'macAddress',
                    '4': 'networkAddress',
                    '5': 'interfaceName',
                    '6': 'agentCircuitId',
                    '7': 'local',
                },
                'lldpRemSysCapSupported': {
                    '0': 'other',
                    '1': 'repeater',
                    '2': 'bridge',
                    '3': 'wlanAccessPoint',
                    '4': 'router',
                    '5': 'telephone',
                    '6': 'docsisCableDevice',
                    '7': 'stationOnly'
                },
                'lldpRemSysCapEnabled': {
                    '0': 'other',
                    '1': 'repeater',
                    '2': 'bridge',
                    '3': 'wlanAccessPoint',
                    '4': 'router',
                    '5': 'telephone',
                    '6': 'docsisCableDevice',
                    '7': 'stationOnly'
                },
                'lldpLocPortIdSubtype': {
                    '1': 'interfaceAlias',
                    '2': 'portComponent',
                    '3': 'macAddress',
                    '4': 'networkAddress',
                    '5': 'interfaceName',
                    '6': 'agentCircuitId',
                    '7': 'local',
                },
                'vtpVlanType': {
                    '1': 'ethernet',
                    '2': 'fddi',
                    '3': 'tokenRing',
                    '4': 'fddiNet',
                    '5': 'trNet',
                    '6': 'deprecated',
                }
            }
        }
    elif device_type == "WS-C4500":
        library = {
            'get': {
                'sysName': '.1.3.6.1.2.1.1.5.0',
                'domain': '.1.3.6.1.4.1.9.2.1.4.0',
                'sysName': '.1.3.6.1.2.1.1.5.0',
                'sysDescr': '.1.3.6.1.2.1.1.1.0',
                'sysLocation': '.1.3.6.1.2.1.1.6.0'
            },
            'walk': {
                'ifIndex': '.1.3.6.1.2.1.2.2.1.1',
                'ifDescr': '.1.3.6.1.2.1.2.2.1.2',
                'ifName': '.1.3.6.1.2.1.31.1.1.1.1',
                'ifAlias': '.1.3.6.1.2.1.31.1.1.1.18',
                'ifType': '.1.3.6.1.2.1.2.2.1.3',
                'ifMtu': '.1.3.6.1.2.1.2.2.1.4',
                'ifSpeed': '.1.3.6.1.2.1.2.2.1.5',
                'ifAdminStatus': '.1.3.6.1.2.1.2.2.1.7',
                'ifOperStatus': '.1.3.6.1.2.1.2.2.1.8',
                'dot1dBasePortIfIndex': '.1.3.6.1.2.1.17.1.4.1.2',
                'vtpVlanState': '.1.3.6.1.4.1.9.9.46.1.3.1.1.2',
                'cviRoutedVlanIfIndex': '.1.3.6.1.4.1.9.9.128.1.1.1.1.3', # cviVlanId, cviPhysicalifindex - The index for the ifTable entry associated with this routed VLAN interface
                'cdpInterfaceName': '.1.3.6.1.4.1.9.9.23.1.1.1.1.6',      # The name of the local interface as advertised by CDP in the PORT TLV
                'cdpCacheDeviceId': '.1.3.6.1.4.1.9.9.23.1.2.1.1.6',      # The Device-ID string as reported in the most recent CDP message.
                                                                          # The zero-length string indicates no Device-ID
                                                                          # field (TLV) was reported in the most recent CDP message.

                'cdpCacheDevicePort': '.1.3.6.1.4.1.9.9.23.1.2.1.1.7',    # The Port-ID string as reported in the most recent CDP
                                                                          # message.  This will typically be the value of the ifName
                                                                          # object (e.g., 'Ethernet0').  The zero-length string
                                                                          # indicates no Port-ID field (TLV) was reported in the
                                                                          # most recent CDP message.
                'cdpCachePlatform': '.1.3.6.1.4.1.9.9.23.1.2.1.1.8',      # The Device's Hardware Platform as reported in the most
                                                                          # recent CDP message.  The zero-length string indicates
                                                                          # that no Platform field (TLV) was reported in the most
                                                                          # recent CDP message.
                'vtpVlanName': '.1.3.6.1.4.1.9.9.46.1.3.1.1.4',
                'vtpVlanType': '.1.3.6.1.4.1.9.9.46.1.3.1.1.3',           # Type of vlan -Syntax	 VlanType (INTEGER) {ethernet(1),
                                                                          # fddi(2),
                                                                          # tokenRing(3), fddiNet(4),
                                                                          # trNet(5), deprecated(6)
                'dot1dTpFdbPort': '.1.3.6.1.2.1.17.4.3.1.2',              # Either the value '0', or the port number of the port on
                                                                          # which a frame having a source address equal to the value
                                                                          # of the corresponding instance of dot1dTpFdbAddress has
                                                                          # been seen.  A value of '0' indicates that the port
                                                                          # number has not been learned, but that the bridge does
                                                                          # have some forwarding/filtering information about this
                                                                          # address (e.g., in the dot1dStaticTable).  Implementors
                                                                          # are encouraged to assign the port value to this object
                                                                          # whenever it is learned, even for addresses for which the
                                                                          # corresponding value of dot1dTpFdbStatus is not
                                                                          # learned(3).
                                                                          # For cisco - Filter out the first .1.3.6.1.2.1.17.4.3.1.2. then convert
                                                                          # the rest from decimal to hex
                #'cefcFRUPowerAdminStatus': '.1.3.6.1.4.1.9.9.117.1.1.2.1.1', # Syntax	 PowerAdminType (INTEGER) {on(1), off(2), inlineAuto(3), inlineOn(4), powerCycle(5)
                #'cefcFRUPowerOperStatus': '.1.3.6.1.4.1.9.9.117.1.1.2.1.2', # PowerOperType (INTEGER) {offEnvOther(1), on(2), offAdmin(3), offDenied(4), offEnvPower(5), offEnvTemp(6), offEnvFan(7), failed(8), onButFanFail(9), offCooling(10), offConnectorRating(11), onButInlinePowerFail(12)
                'entPhysicalDescr': '.1.3.6.1.2.1.47.1.1.1.1.2', # A textual description of physical entity.  This object should contain a string that identifies the manufacturer's name for the physical entity, and should be set to a distinct value for each version or model of the physical entity.
                'entPhysicalHardwareRev': '.1.3.6.1.2.1.47.1.1.1.1.8',
                'entPhysicalFirmwareRev': '.1.3.6.1.2.1.47.1.1.1.1.9',
                'entPhysicalSoftwareRev': '.1.3.6.1.2.1.47.1.1.1.1.10',
                'entPhysicalSerialNum': '.1.3.6.1.2.1.47.1.1.1.1.11',
                'entPhysicalModelName': '.1.3.6.1.2.1.47.1.1.1.1.13',
                'lldpRemChassisId': '.1.0.8802.1.1.2.1.4.1.1.5',          # The string value used to identify the chassis component associated with the remote system
                'lldpRemPortIdSubtype': '.1.0.8802.1.1.2.1.4.1.1.6',      # The type of port identifier encoding used in the associated 'lldpRemPortId' object
                'lldpRemPortDesc': '.1.0.8802.1.1.2.1.4.1.1.8',           # The string value used to identify the description of the given port associated with the remote system.
                'lldpRemSysName': '.1.0.8802.1.1.2.1.4.1.1.9',            # The string value used to identify the system name of the of the remote system.
                'lldpRemSysDesc': '.1.0.8802.1.1.2.1.4.1.1.10',           # The string value used to identify the system description of the remote system.
                'lldpRemChassisIdSubtype': '.1.0.8802.1.1.2.1.4.1.1.4',   # The type of encoding used to identify the chassis associated with the remote system.
                'lldpRemSysCapSupported': '.1.0.8802.1.1.2.1.4.1.1.11',   # The bitmap value used to identify which system capabilities are supported on the remote system.
                'lldpRemSysCapEnabled': '.1.0.8802.1.1.2.1.4.1.1.12',     # The bitmap value used to identify which system capabilities are enabled on the remote system.
                'lldpLocPortIdSubtype': '.1.0.8802.1.1.2.1.3.7.1.2',      # The type of port identifier encoding used in the associated
                'lldpLocPortId': '.1.0.8802.1.1.2.1.3.7.1.3',             # The string value used to identify the port component associated with a given port in the local system.
                'lldpLocPortDesc': '.1.0.8802.1.1.2.1.3.7.1.4',           # The string value used to identify the 802 LAN station's port description associated with the local system.  If the local agent supports IETF RFC 2863, lldpLocPortDesc object should have the same value of ifDescr object
                'entPhysicalAlias': '.1.3.6.1.2.1.47.1.1.1.1.14',         # This will alow you to reference the pyhsical entity with another associated value like the plugable information.
                                                                          # This will refer to the ifIndex as well
                'ipAdEntAddr': '.1.3.6.1.2.1.4.20.1.1',                   # Returns any ip addresses configured
                'ipAdEntNetMask': '.1.3.6.1.2.1.4.20.1.3',                   # Returns any ip subnet configured for the above
                'ipAdEntIfIndex': '.1.3.6.1.2.1.4.20.1.2',                # Ip address and interface index the address is tied too
            },
            'values': {
                'ifAdminStatus': {
                    '1': 'Up',
                    '2': 'Down',
                    '3': 'Testing'
                },
                'ifOperStatus': {
                    '1': 'Up',
                    '2': 'Down',
                    '3': 'Testing',
                    '4': 'Unknown',
                    '5': 'Dormant',
                    '6': 'Not Present',
                    '7': 'Lower Layer Down',
                },
                'lldpRemChassisIdSubtype': {
                    '1': 'chassisComponent',
                    '2': 'interfaceAlias',
                    '3': 'portComponent',
                    '4': 'macAddress',
                    '5': 'networkAddress',
                    '6': 'interfaceName',
                    '7': 'local'
                },
                'lldpRemPortIdSubtype': {
                    '1': 'interfaceAlias',
                    '2': 'portComponent',
                    '3': 'macAddress',
                    '4': 'networkAddress',
                    '5': 'interfaceName',
                    '6': 'agentCircuitId',
                    '7': 'local',
                },
                'lldpRemSysCapSupported': {
                    '0': 'other',
                    '1': 'repeater',
                    '2': 'bridge',
                    '3': 'wlanAccessPoint',
                    '4': 'router',
                    '5': 'telephone',
                    '6': 'docsisCableDevice',
                    '7': 'stationOnly'
                },
                'lldpRemSysCapEnabled': {
                    '0': 'other',
                    '1': 'repeater',
                    '2': 'bridge',
                    '3': 'wlanAccessPoint',
                    '4': 'router',
                    '5': 'telephone',
                    '6': 'docsisCableDevice',
                    '7': 'stationOnly'
                },
                'lldpLocPortIdSubtype': {
                    '1': 'interfaceAlias',
                    '2': 'portComponent',
                    '3': 'macAddress',
                    '4': 'networkAddress',
                    '5': 'interfaceName',
                    '6': 'agentCircuitId',
                    '7': 'local',
                },
                'vtpVlanType': {
                    '1': 'ethernet',
                    '2': 'fddi',
                    '3': 'tokenRing',
                    '4': 'fddiNet',
                    '5': 'trNet',
                    '6': 'deprecated',
                }
            }
        }
    elif device_type == "WSCBS3X":
        library = {
            'get': {
                'sysName': '.1.3.6.1.2.1.1.5.0',
                'domain': '.1.3.6.1.4.1.9.2.1.4.0',
                'sysName': '.1.3.6.1.2.1.1.5.0',
                'sysDescr': '.1.3.6.1.2.1.1.1.0',
                'sysLocation': '.1.3.6.1.2.1.1.6.0'
            },
            'walk': {
                'ifIndex': '.1.3.6.1.2.1.2.2.1.1',
                'ifDescr': '.1.3.6.1.2.1.2.2.1.2',
                'ifName': '.1.3.6.1.2.1.31.1.1.1.1',
                'ifAlias': '.1.3.6.1.2.1.31.1.1.1.18',
                'ifType': '.1.3.6.1.2.1.2.2.1.3',
                'ifMtu': '.1.3.6.1.2.1.2.2.1.4',
                'ifSpeed': '.1.3.6.1.2.1.2.2.1.5',
                'ifAdminStatus': '.1.3.6.1.2.1.2.2.1.7',
                'ifOperStatus': '.1.3.6.1.2.1.2.2.1.8',
                'dot1dBasePortIfIndex': '.1.3.6.1.2.1.17.1.4.1.2',
                'vtpVlanState': '.1.3.6.1.4.1.9.9.46.1.3.1.1.2',
                'cviRoutedVlanIfIndex': '.1.3.6.1.4.1.9.9.128.1.1.1.1.3', # cviVlanId, cviPhysicalifindex - The index for the ifTable entry associated with this routed VLAN interface
                'cdpInterfaceName': '.1.3.6.1.4.1.9.9.23.1.1.1.1.6',      # The name of the local interface as advertised by CDP in the PORT TLV
                'cdpCacheDeviceId': '.1.3.6.1.4.1.9.9.23.1.2.1.1.6',      # The Device-ID string as reported in the most recent CDP message.
                                                                          # The zero-length string indicates no Device-ID
                                                                          # field (TLV) was reported in the most recent CDP message.

                'cdpCacheDevicePort': '.1.3.6.1.4.1.9.9.23.1.2.1.1.7',    # The Port-ID string as reported in the most recent CDP
                                                                          # message.  This will typically be the value of the ifName
                                                                          # object (e.g., 'Ethernet0').  The zero-length string
                                                                          # indicates no Port-ID field (TLV) was reported in the
                                                                          # most recent CDP message.
                'cdpCachePlatform': '.1.3.6.1.4.1.9.9.23.1.2.1.1.8',      # The Device's Hardware Platform as reported in the most
                                                                          # recent CDP message.  The zero-length string indicates
                                                                          # that no Platform field (TLV) was reported in the most
                                                                          # recent CDP message.
                'vtpVlanName': '.1.3.6.1.4.1.9.9.46.1.3.1.1.4',
                'vtpVlanType': '.1.3.6.1.4.1.9.9.46.1.3.1.1.3',           # Type of vlan -Syntax	 VlanType (INTEGER) {ethernet(1),
                                                                          # fddi(2),
                                                                          # tokenRing(3), fddiNet(4),
                                                                          # trNet(5), deprecated(6)
                'dot1dTpFdbPort': '.1.3.6.1.2.1.17.4.3.1.2',              # Either the value '0', or the port number of the port on
                                                                          # which a frame having a source address equal to the value
                                                                          # of the corresponding instance of dot1dTpFdbAddress has
                                                                          # been seen.  A value of '0' indicates that the port
                                                                          # number has not been learned, but that the bridge does
                                                                          # have some forwarding/filtering information about this
                                                                          # address (e.g., in the dot1dStaticTable).  Implementors
                                                                          # are encouraged to assign the port value to this object
                                                                          # whenever it is learned, even for addresses for which the
                                                                          # corresponding value of dot1dTpFdbStatus is not
                                                                          # learned(3).
                                                                          # For cisco - Filter out the first .1.3.6.1.2.1.17.4.3.1.2. then convert
                                                                          # the rest from decimal to hex
                #'cefcFRUPowerAdminStatus': '.1.3.6.1.4.1.9.9.117.1.1.2.1.1', # Syntax	 PowerAdminType (INTEGER) {on(1), off(2), inlineAuto(3), inlineOn(4), powerCycle(5)
                #'cefcFRUPowerOperStatus': '.1.3.6.1.4.1.9.9.117.1.1.2.1.2', # PowerOperType (INTEGER) {offEnvOther(1), on(2), offAdmin(3), offDenied(4), offEnvPower(5), offEnvTemp(6), offEnvFan(7), failed(8), onButFanFail(9), offCooling(10), offConnectorRating(11), onButInlinePowerFail(12)
                'entPhysicalDescr': '.1.3.6.1.2.1.47.1.1.1.1.2', # A textual description of physical entity.  This object should contain a string that identifies the manufacturer's name for the physical entity, and should be set to a distinct value for each version or model of the physical entity.
                'entPhysicalHardwareRev': '.1.3.6.1.2.1.47.1.1.1.1.8',
                'entPhysicalFirmwareRev': '.1.3.6.1.2.1.47.1.1.1.1.9',
                'entPhysicalSoftwareRev': '.1.3.6.1.2.1.47.1.1.1.1.10',
                'entPhysicalSerialNum': '.1.3.6.1.2.1.47.1.1.1.1.11',
                'entPhysicalModelName': '.1.3.6.1.2.1.47.1.1.1.1.13',
                'lldpRemChassisId': '.1.0.8802.1.1.2.1.4.1.1.5',          # The string value used to identify the chassis component associated with the remote system
                'lldpRemPortIdSubtype': '.1.0.8802.1.1.2.1.4.1.1.6',      # The type of port identifier encoding used in the associated 'lldpRemPortId' object
                'lldpRemPortDesc': '.1.0.8802.1.1.2.1.4.1.1.8',           # The string value used to identify the description of the given port associated with the remote system.
                'lldpRemSysName': '.1.0.8802.1.1.2.1.4.1.1.9',            # The string value used to identify the system name of the of the remote system.
                'lldpRemSysDesc': '.1.0.8802.1.1.2.1.4.1.1.10',           # The string value used to identify the system description of the remote system.
                'lldpRemChassisIdSubtype': '.1.0.8802.1.1.2.1.4.1.1.4',   # The type of encoding used to identify the chassis associated with the remote system.
                'lldpRemSysCapSupported': '.1.0.8802.1.1.2.1.4.1.1.11',   # The bitmap value used to identify which system capabilities are supported on the remote system.
                'lldpRemSysCapEnabled': '.1.0.8802.1.1.2.1.4.1.1.12',     # The bitmap value used to identify which system capabilities are enabled on the remote system.
                'lldpLocPortIdSubtype': '.1.0.8802.1.1.2.1.3.7.1.2',      # The type of port identifier encoding used in the associated
                'lldpLocPortId': '.1.0.8802.1.1.2.1.3.7.1.3',             # The string value used to identify the port component associated with a given port in the local system.
                'lldpLocPortDesc': '.1.0.8802.1.1.2.1.3.7.1.4',           # The string value used to identify the 802 LAN station's port description associated with the local system.  If the local agent supports IETF RFC 2863, lldpLocPortDesc object should have the same value of ifDescr object
                'entPhysicalAlias': '.1.3.6.1.2.1.47.1.1.1.1.14',         # This will alow you to reference the pyhsical entity with another associated value like the plugable information.
                                                                          # This will refer to the ifIndex as well
                'ipAdEntAddr': '.1.3.6.1.2.1.4.20.1.1',                   # Returns any ip addresses configured
                'ipAdEntNetMask': '.1.3.6.1.2.1.4.20.1.3',                   # Returns any ip subnet configured for the above
                'ipAdEntIfIndex': '.1.3.6.1.2.1.4.20.1.2',                # Ip address and interface index the address is tied too
            },
            'values': {
                'ifAdminStatus': {
                    '1': 'Up',
                    '2': 'Down',
                    '3': 'Testing'
                },
                'ifOperStatus': {
                    '1': 'Up',
                    '2': 'Down',
                    '3': 'Testing',
                    '4': 'Unknown',
                    '5': 'Dormant',
                    '6': 'Not Present',
                    '7': 'Lower Layer Down',
                },
                'lldpRemChassisIdSubtype': {
                    '1': 'chassisComponent',
                    '2': 'interfaceAlias',
                    '3': 'portComponent',
                    '4': 'macAddress',
                    '5': 'networkAddress',
                    '6': 'interfaceName',
                    '7': 'local'
                },
                'lldpRemPortIdSubtype': {
                    '1': 'interfaceAlias',
                    '2': 'portComponent',
                    '3': 'macAddress',
                    '4': 'networkAddress',
                    '5': 'interfaceName',
                    '6': 'agentCircuitId',
                    '7': 'local',
                },
                'lldpRemSysCapSupported': {
                    '0': 'other',
                    '1': 'repeater',
                    '2': 'bridge',
                    '3': 'wlanAccessPoint',
                    '4': 'router',
                    '5': 'telephone',
                    '6': 'docsisCableDevice',
                    '7': 'stationOnly'
                },
                'lldpRemSysCapEnabled': {
                    '0': 'other',
                    '1': 'repeater',
                    '2': 'bridge',
                    '3': 'wlanAccessPoint',
                    '4': 'router',
                    '5': 'telephone',
                    '6': 'docsisCableDevice',
                    '7': 'stationOnly'
                },
                'lldpLocPortIdSubtype': {
                    '1': 'interfaceAlias',
                    '2': 'portComponent',
                    '3': 'macAddress',
                    '4': 'networkAddress',
                    '5': 'interfaceName',
                    '6': 'agentCircuitId',
                    '7': 'local',
                },
                'vtpVlanType': {
                    '1': 'ethernet',
                    '2': 'fddi',
                    '3': 'tokenRing',
                    '4': 'fddiNet',
                    '5': 'trNet',
                    '6': 'deprecated',
                }
            }
        }
    elif device_type == "A10":
        library = {
            'get': {
                'sysName': '.1.3.6.1.2.1.1.5.0',
                'sysName': '.1.3.6.1.2.1.1.5.0',
                'sysDescr': '.1.3.6.1.2.1.1.1.0',
                'sysLocation': '.1.3.6.1.2.1.1.6.0',
                'chassis_active_software': '.1.3.6.1.4.1.22610.2.4.1.1.2.0',
            },
            'walk': {
                'ifIndex': '.1.3.6.1.2.1.2.2.1.1',
                'ifDescr': '.1.3.6.1.2.1.2.2.1.2',
                'ifName': '.1.3.6.1.2.1.31.1.1.1.1',
                'entPhysicalSoftwareRev': '.1.3.6.1.4.1.22610.2.4.1.1',
                'entPhysicalModelName': '.1.3.6.1.2.1.47.1.1.1.1.13',  # ENTITY-MIB::entPhysicalModelName (walk/table root)

            },
            'values': {
                'ifAdminStatus': {
                    '1': 'Up',
                    '2': 'Down',
                    '3': 'Testing'
                },
                'ifOperStatus': {
                    '1': 'Up',
                    '2': 'Down',
                    '3': 'Testing',
                    '4': 'Unknown',
                    '5': 'Dormant',
                    '6': 'Not Present',
                    '7': 'Lower Layer Down',
                }
            }
        }
    elif device_type == "C9300":
        library = {
            'get': {
                'sysName': '.1.3.6.1.2.1.1.5.0',
                'domain': '.1.3.6.1.4.1.9.2.1.4.0',
                'sysName': '.1.3.6.1.2.1.1.5.0',
                'sysDescr': '.1.3.6.1.2.1.1.1.0',
                'sysLocation': '.1.3.6.1.2.1.1.6.0',
                'chassis_type': '.1.3.6.1.2.1.47.1.1.1.1.13.1'
            },
            'walk': {
                'ifIndex': '.1.3.6.1.2.1.2.2.1.1',
                'ifDescr': '.1.3.6.1.2.1.2.2.1.2',
                'ifName': '.1.3.6.1.2.1.31.1.1.1.1',
                'ifAlias': '.1.3.6.1.2.1.31.1.1.1.18',
                'ifType': '.1.3.6.1.2.1.2.2.1.3',
                'ifMtu': '.1.3.6.1.2.1.2.2.1.4',
                'ifSpeed': '.1.3.6.1.2.1.2.2.1.5',
                'ifAdminStatus': '.1.3.6.1.2.1.2.2.1.7',
                'ifOperStatus': '.1.3.6.1.2.1.2.2.1.8',
                'dot1dBasePortIfIndex': '.1.3.6.1.2.1.17.1.4.1.2',
                'vtpVlanState': '.1.3.6.1.4.1.9.9.46.1.3.1.1.2',
                'cviRoutedVlanIfIndex': '.1.3.6.1.4.1.9.9.128.1.1.1.1.3', # cviVlanId, cviPhysicalifindex - The index for the ifTable entry associated with this routed VLAN interface
                'cdpInterfaceName': '.1.3.6.1.4.1.9.9.23.1.1.1.1.6',      # The name of the local interface as advertised by CDP in the PORT TLV
                'cdpCacheDeviceId': '.1.3.6.1.4.1.9.9.23.1.2.1.1.6',      # The Device-ID string as reported in the most recent CDP message.
                                                                          # The zero-length string indicates no Device-ID
                                                                          # field (TLV) was reported in the most recent CDP message.

                'cdpCacheDevicePort': '.1.3.6.1.4.1.9.9.23.1.2.1.1.7',    # The Port-ID string as reported in the most recent CDP
                                                                          # message.  This will typically be the value of the ifName
                                                                          # object (e.g., 'Ethernet0').  The zero-length string
                                                                          # indicates no Port-ID field (TLV) was reported in the
                                                                          # most recent CDP message.
                'cdpCachePlatform': '.1.3.6.1.4.1.9.9.23.1.2.1.1.8',      # The Device's Hardware Platform as reported in the most
                                                                          # recent CDP message.  The zero-length string indicates
                                                                          # that no Platform field (TLV) was reported in the most
                                                                          # recent CDP message.
                'vtpVlanName': '.1.3.6.1.4.1.9.9.46.1.3.1.1.4',
                'vtpVlanType': '.1.3.6.1.4.1.9.9.46.1.3.1.1.3',           # Type of vlan -Syntax	 VlanType (INTEGER) {ethernet(1),
                                                                          # fddi(2),
                                                                          # tokenRing(3), fddiNet(4),
                                                                          # trNet(5), deprecated(6)
                'dot1dTpFdbPort': '.1.3.6.1.2.1.17.4.3.1.2',              # Either the value '0', or the port number of the port on
                                                                          # which a frame having a source address equal to the value
                                                                          # of the corresponding instance of dot1dTpFdbAddress has
                                                                          # been seen.  A value of '0' indicates that the port
                                                                          # number has not been learned, but that the bridge does
                                                                          # have some forwarding/filtering information about this
                                                                          # address (e.g., in the dot1dStaticTable).  Implementors
                                                                          # are encouraged to assign the port value to this object
                                                                          # whenever it is learned, even for addresses for which the
                                                                          # corresponding value of dot1dTpFdbStatus is not
                                                                          # learned(3).
                                                                          # For cisco - Filter out the first .1.3.6.1.2.1.17.4.3.1.2. then convert
                                                                          # the rest from decimal to hex
                #'cefcFRUPowerAdminStatus': '.1.3.6.1.4.1.9.9.117.1.1.2.1.1', # Syntax	 PowerAdminType (INTEGER) {on(1), off(2), inlineAuto(3), inlineOn(4), powerCycle(5)
                #'cefcFRUPowerOperStatus': '.1.3.6.1.4.1.9.9.117.1.1.2.1.2', # PowerOperType (INTEGER) {offEnvOther(1), on(2), offAdmin(3), offDenied(4), offEnvPower(5), offEnvTemp(6), offEnvFan(7), failed(8), onButFanFail(9), offCooling(10), offConnectorRating(11), onButInlinePowerFail(12)
                'entPhysicalDescr': '.1.3.6.1.2.1.47.1.1.1.1.2', # A textual description of physical entity.  This object should contain a string that identifies the manufacturer's name for the physical entity, and should be set to a distinct value for each version or model of the physical entity.
                'entPhysicalHardwareRev': '.1.3.6.1.2.1.47.1.1.1.1.8',
                'entPhysicalFirmwareRev': '.1.3.6.1.2.1.47.1.1.1.1.9',
                'entPhysicalSoftwareRev': '.1.3.6.1.2.1.47.1.1.1.1.10',
                'entPhysicalSerialNum': '.1.3.6.1.2.1.47.1.1.1.1.11',
                'entPhysicalModelName': '.1.3.6.1.2.1.47.1.1.1.1.13',
                #'dot1dBaseBridgeAddress': '.1.3.6.1.2.1.17.1.1.0',
                'lldpRemChassisId': '.1.0.8802.1.1.2.1.4.1.1.5',          # The string value used to identify the chassis component associated with the remote system
                'lldpRemPortIdSubtype': '.1.0.8802.1.1.2.1.4.1.1.6',      # The type of port identifier encoding used in the associated 'lldpRemPortId' object
                'lldpRemPortDesc': '.1.0.8802.1.1.2.1.4.1.1.8',           # The string value used to identify the description of the given port associated with the remote system.
                'lldpRemSysName': '.1.0.8802.1.1.2.1.4.1.1.9',            # The string value used to identify the system name of the of the remote system.
                'lldpRemSysDesc': '.1.0.8802.1.1.2.1.4.1.1.10',           # The string value used to identify the system description of the remote system.
                'lldpRemChassisIdSubtype': '.1.0.8802.1.1.2.1.4.1.1.4',   # The type of encoding used to identify the chassis associated with the remote system.
                'lldpRemSysCapSupported': '.1.0.8802.1.1.2.1.4.1.1.11',   # The bitmap value used to identify which system capabilities are supported on the remote system.
                'lldpRemSysCapEnabled': '.1.0.8802.1.1.2.1.4.1.1.12',     # The bitmap value used to identify which system capabilities are enabled on the remote system.
                'lldpLocPortIdSubtype': '.1.0.8802.1.1.2.1.3.7.1.2',      # The type of port identifier encoding used in the associated
                'lldpLocPortId': '.1.0.8802.1.1.2.1.3.7.1.3',             # The string value used to identify the port component associated with a given port in the local system.
                'lldpLocPortDesc': '.1.0.8802.1.1.2.1.3.7.1.4',           # The string value used to identify the 802 LAN station's port description associated with the local system.  If the local agent supports IETF RFC 2863, lldpLocPortDesc object should have the same value of ifDescr object
                'entPhysicalAlias': '.1.3.6.1.2.1.47.1.1.1.1.14',         # This will alow you to reference the pyhsical entity with another associated value like the plugable information.
                                                                          # This will refer to the ifIndex as well
                'ipAdEntAddr': '.1.3.6.1.2.1.4.20.1.1',                   # Returns any ip addresses configured
                'ipAdEntNetMask': '.1.3.6.1.2.1.4.20.1.3',                   # Returns any ip subnet configured for the above
                'ipAdEntIfIndex': '.1.3.6.1.2.1.4.20.1.2',                # Ip address and interface index the address is tied too
            },
            'values': {
                'ifAdminStatus': {
                    '1': 'Up',
                    '2': 'Down',
                    '3': 'Testing'
                },
                'ifOperStatus': {
                    '1': 'Up',
                    '2': 'Down',
                    '3': 'Testing',
                    '4': 'Unknown',
                    '5': 'Dormant',
                    '6': 'Not Present',
                    '7': 'Lower Layer Down',
                },
                'lldpRemChassisIdSubtype': {
                    '1': 'chassisComponent',
                    '2': 'interfaceAlias',
                    '3': 'portComponent',
                    '4': 'macAddress',
                    '5': 'networkAddress',
                    '6': 'interfaceName',
                    '7': 'local'
                },
                'lldpRemPortIdSubtype': {
                    '1': 'interfaceAlias',
                    '2': 'portComponent',
                    '3': 'macAddress',
                    '4': 'networkAddress',
                    '5': 'interfaceName',
                    '6': 'agentCircuitId',
                    '7': 'local',
                },
                'lldpRemSysCapSupported': {
                    '0': 'other',
                    '1': 'repeater',
                    '2': 'bridge',
                    '3': 'wlanAccessPoint',
                    '4': 'router',
                    '5': 'telephone',
                    '6': 'docsisCableDevice',
                    '7': 'stationOnly'
                },
                'lldpRemSysCapEnabled': {
                    '0': 'other',
                    '1': 'repeater',
                    '2': 'bridge',
                    '3': 'wlanAccessPoint',
                    '4': 'router',
                    '5': 'telephone',
                    '6': 'docsisCableDevice',
                    '7': 'stationOnly'
                },
                'lldpLocPortIdSubtype': {
                    '1': 'interfaceAlias',
                    '2': 'portComponent',
                    '3': 'macAddress',
                    '4': 'networkAddress',
                    '5': 'interfaceName',
                    '6': 'agentCircuitId',
                    '7': 'local',
                },
                'vtpVlanType': {
                    '1': 'ethernet',
                    '2': 'fddi',
                    '3': 'tokenRing',
                    '4': 'fddiNet',
                    '5': 'trNet',
                    '6': 'deprecated',
                }
            }
        }
    elif device_type == "ASR_IOS_XR":
        library = {
            'get': {
                'sysName': '.1.3.6.1.2.1.1.5.0',
                'domain': '.1.3.6.1.4.1.9.2.1.4.0',
                'sysName': '.1.3.6.1.2.1.1.5.0',
                'sysDescr': '.1.3.6.1.2.1.1.1.0',
                'sysLocation': '.1.3.6.1.2.1.1.6.0',
                'chassis_type': '.1.3.6.1.2.1.47.1.1.1.1.13.8384513'
            },
            'walk': {
                'ifIndex': '.1.3.6.1.2.1.2.2.1.1',
                'ifDescr': '.1.3.6.1.2.1.2.2.1.2',
                'ifName': '.1.3.6.1.2.1.31.1.1.1.1',
                'ifAlias': '.1.3.6.1.2.1.31.1.1.1.18',
                'ifType': '.1.3.6.1.2.1.2.2.1.3',
                'ifMtu': '.1.3.6.1.2.1.2.2.1.4',
                'ifSpeed': '.1.3.6.1.2.1.2.2.1.5',
                'ifAdminStatus': '.1.3.6.1.2.1.2.2.1.7',
                'ifOperStatus': '.1.3.6.1.2.1.2.2.1.8',
                #'dot1dBasePortIfIndex': '.1.3.6.1.2.1.17.1.4.1.2',
                'cdpInterfaceName': '.1.3.6.1.4.1.9.9.23.1.1.1.1.6',      # The name of the local interface as advertised by CDP in the PORT TLV
                'cdpCacheDeviceId': '.1.3.6.1.4.1.9.9.23.1.2.1.1.6',      # The Device-ID string as reported in the most recent CDP message.
                                                                          # The zero-length string indicates no Device-ID
                                                                          # field (TLV) was reported in the most recent CDP message.

                'cdpCacheDevicePort': '.1.3.6.1.4.1.9.9.23.1.2.1.1.7',    # The Port-ID string as reported in the most recent CDP
                                                                          # message.  This will typically be the value of the ifName
                                                                          # object (e.g., 'Ethernet0').  The zero-length string
                                                                          # indicates no Port-ID field (TLV) was reported in the
                                                                          # most recent CDP message.
                'cdpCachePlatform': '.1.3.6.1.4.1.9.9.23.1.2.1.1.8',      # The Device's Hardware Platform as reported in the most
                                                                          # recent CDP message.  The zero-length string indicates
                                                                          # that no Platform field (TLV) was reported in the most
                                                                          # recent CDP message.

                'entPhysicalDescr': '.1.3.6.1.2.1.47.1.1.1.1.2', # A textual description of physical entity.  This object should contain a string that identifies the manufacturer's name for the physical entity, and should be set to a distinct value for each version or model of the physical entity.
                'entPhysicalHardwareRev': '.1.3.6.1.2.1.47.1.1.1.1.8',
                'entPhysicalFirmwareRev': '.1.3.6.1.2.1.47.1.1.1.1.9',
                'entPhysicalSoftwareRev': '.1.3.6.1.2.1.47.1.1.1.1.10',
                'entPhysicalSerialNum': '.1.3.6.1.2.1.47.1.1.1.1.11',
                'entPhysicalModelName': '.1.3.6.1.2.1.47.1.1.1.1.13',
                #'lldpRemChassisId': '.1.0.8802.1.1.2.1.4.1.1.5',          # The string value used to identify the chassis component associated with the remote system
                #'lldpRemPortIdSubtype': '.1.0.8802.1.1.2.1.4.1.1.6',      # The type of port identifier encoding used in the associated 'lldpRemPortId' object
                #'lldpRemPortDesc': '.1.0.8802.1.1.2.1.4.1.1.8',           # The string value used to identify the description of the given port associated with the remote system.
                #'lldpRemSysName': '.1.0.8802.1.1.2.1.4.1.1.9',            # The string value used to identify the system name of the of the remote system.
                #'lldpRemSysDesc': '.1.0.8802.1.1.2.1.4.1.1.10',           # The string value used to identify the system description of the remote system.
                #'lldpRemChassisIdSubtype': '.1.0.8802.1.1.2.1.4.1.1.4',   # The type of encoding used to identify the chassis associated with the remote system.
                #'lldpRemSysCapSupported': '.1.0.8802.1.1.2.1.4.1.1.11',   # The bitmap value used to identify which system capabilities are supported on the remote system.
                #'lldpRemSysCapEnabled': '.1.0.8802.1.1.2.1.4.1.1.12',     # The bitmap value used to identify which system capabilities are enabled on the remote system.
                #'lldpLocPortIdSubtype': '.1.0.8802.1.1.2.1.3.7.1.2',      # The type of port identifier encoding used in the associated
                #'lldpLocPortId': '.1.0.8802.1.1.2.1.3.7.1.3',             # The string value used to identify the port component associated with a given port in the local system.
                #'lldpLocPortDesc': '.1.0.8802.1.1.2.1.3.7.1.4',           # The string value used to identify the 802 LAN station's port description associated with the local system.  If the local agent supports IETF RFC 2863, lldpLocPortDesc object should have the same value of ifDescr object
                'entPhysicalAlias': '.1.3.6.1.2.1.47.1.1.1.1.14',         # This will alow you to reference the pyhsical entity with another associated value like the plugable information.
                                                                          # This will refer to the ifIndex as well
                #'ipAdEntAddr': '.1.3.6.1.2.1.4.20.1.1',                   # Returns any ip addresses configured
                #'ipAdEntNetMask': '.1.3.6.1.2.1.4.20.1.3',                   # Returns any ip subnet configured for the above
                #'ipAdEntIfIndex': '.1.3.6.1.2.1.4.20.1.2',                # Ip address and interface index the address is tied too
            },
            'values': {
                'ifAdminStatus': {
                    '1': 'Up',
                    '2': 'Down',
                    '3': 'Testing'
                },
                'ifOperStatus': {
                    '1': 'Up',
                    '2': 'Down',
                    '3': 'Testing',
                    '4': 'Unknown',
                    '5': 'Dormant',
                    '6': 'Not Present',
                    '7': 'Lower Layer Down',
                },
                'lldpRemChassisIdSubtype': {
                    '1': 'chassisComponent',
                    '2': 'interfaceAlias',
                    '3': 'portComponent',
                    '4': 'macAddress',
                    '5': 'networkAddress',
                    '6': 'interfaceName',
                    '7': 'local'
                },
                'lldpRemPortIdSubtype': {
                    '1': 'interfaceAlias',
                    '2': 'portComponent',
                    '3': 'macAddress',
                    '4': 'networkAddress',
                    '5': 'interfaceName',
                    '6': 'agentCircuitId',
                    '7': 'local',
                },
                'lldpRemSysCapSupported': {
                    '0': 'other',
                    '1': 'repeater',
                    '2': 'bridge',
                    '3': 'wlanAccessPoint',
                    '4': 'router',
                    '5': 'telephone',
                    '6': 'docsisCableDevice',
                    '7': 'stationOnly'
                },
                'lldpRemSysCapEnabled': {
                    '0': 'other',
                    '1': 'repeater',
                    '2': 'bridge',
                    '3': 'wlanAccessPoint',
                    '4': 'router',
                    '5': 'telephone',
                    '6': 'docsisCableDevice',
                    '7': 'stationOnly'
                },
                'lldpLocPortIdSubtype': {
                    '1': 'interfaceAlias',
                    '2': 'portComponent',
                    '3': 'macAddress',
                    '4': 'networkAddress',
                    '5': 'interfaceName',
                    '6': 'agentCircuitId',
                    '7': 'local',
                },
                'vtpVlanType': {
                    '1': 'ethernet',
                    '2': 'fddi',
                    '3': 'tokenRing',
                    '4': 'fddiNet',
                    '5': 'trNet',
                    '6': 'deprecated',
                }
            }
        }
    elif device_type == "CATALYST_4000_L3_SWITCH":
        library = {
            'get': {
                'sysName': '.1.3.6.1.2.1.1.5.0',
                'domain': '.1.3.6.1.4.1.9.2.1.4.0',
                'sysName': '.1.3.6.1.2.1.1.5.0',
                'sysDescr': '.1.3.6.1.2.1.1.1.0',
                'sysLocation': '.1.3.6.1.2.1.1.6.0'
            },
            'walk': {
                'ifIndex': '.1.3.6.1.2.1.2.2.1.1',
                'ifDescr': '.1.3.6.1.2.1.2.2.1.2',
                'ifName': '.1.3.6.1.2.1.31.1.1.1.1',
                'ifAlias': '.1.3.6.1.2.1.31.1.1.1.18',
                'ifType': '.1.3.6.1.2.1.2.2.1.3',
                'ifMtu': '.1.3.6.1.2.1.2.2.1.4',
                'ifSpeed': '.1.3.6.1.2.1.2.2.1.5',
                'ifAdminStatus': '.1.3.6.1.2.1.2.2.1.7',
                'ifOperStatus': '.1.3.6.1.2.1.2.2.1.8',
                'cviRoutedVlanIfIndex': '.1.3.6.1.4.1.9.9.128.1.1.1.1.3', # cviVlanId, cviPhysicalifindex - The index for the ifTable entry associated with this routed VLAN interface
                'cdpInterfaceName': '.1.3.6.1.4.1.9.9.23.1.1.1.1.6',      # The name of the local interface as advertised by CDP in the PORT TLV
                'cdpCacheDeviceId': '.1.3.6.1.4.1.9.9.23.1.2.1.1.6',      # The Device-ID string as reported in the most recent CDP message.
                                                                          # The zero-length string indicates no Device-ID
                                                                          # field (TLV) was reported in the most recent CDP message.

                'cdpCacheDevicePort': '.1.3.6.1.4.1.9.9.23.1.2.1.1.7',    # The Port-ID string as reported in the most recent CDP
                                                                          # message.  This will typically be the value of the ifName
                                                                          # object (e.g., 'Ethernet0').  The zero-length string
                                                                          # indicates no Port-ID field (TLV) was reported in the
                                                                          # most recent CDP message.
                'cdpCachePlatform': '.1.3.6.1.4.1.9.9.23.1.2.1.1.8',      # The Device's Hardware Platform as reported in the most
                                                                          # recent CDP message.  The zero-length string indicates
                                                                          # that no Platform field (TLV) was reported in the most
                                                                          # recent CDP message.
                'vtpVlanName': '.1.3.6.1.4.1.9.9.46.1.3.1.1.4',
                'vtpVlanType': '.1.3.6.1.4.1.9.9.46.1.3.1.1.3',           # Type of vlan -Syntax	 VlanType (INTEGER) {ethernet(1),
                                                                          # fddi(2),
                                                                          # tokenRing(3), fddiNet(4),
                                                                          # trNet(5), deprecated(6)
                'dot1dTpFdbPort': '.1.3.6.1.2.1.17.4.3.1.2',              # Either the value '0', or the port number of the port on
                                                                          # which a frame having a source address equal to the value
                                                                          # of the corresponding instance of dot1dTpFdbAddress has
                                                                          # been seen.  A value of '0' indicates that the port
                                                                          # number has not been learned, but that the bridge does
                                                                          # have some forwarding/filtering information about this
                                                                          # address (e.g., in the dot1dStaticTable).  Implementors
                                                                          # are encouraged to assign the port value to this object
                                                                          # whenever it is learned, even for addresses for which the
                                                                          # corresponding value of dot1dTpFdbStatus is not
                                                                          # learned(3).
                                                                          # For cisco - Filter out the first .1.3.6.1.2.1.17.4.3.1.2. then convert
                                                                          # the rest from decimal to hex
                #'cefcFRUPowerAdminStatus': '.1.3.6.1.4.1.9.9.117.1.1.2.1.1', # Syntax	 PowerAdminType (INTEGER) {on(1), off(2), inlineAuto(3), inlineOn(4), powerCycle(5)
                #'cefcFRUPowerOperStatus': '.1.3.6.1.4.1.9.9.117.1.1.2.1.2', # PowerOperType (INTEGER) {offEnvOther(1), on(2), offAdmin(3), offDenied(4), offEnvPower(5), offEnvTemp(6), offEnvFan(7), failed(8), onButFanFail(9), offCooling(10), offConnectorRating(11), onButInlinePowerFail(12)
                'entPhysicalDescr': '.1.3.6.1.2.1.47.1.1.1.1.2', # A textual description of physical entity.  This object should contain a string that identifies the manufacturer's name for the physical entity, and should be set to a distinct value for each version or model of the physical entity.
                'entPhysicalHardwareRev': '.1.3.6.1.2.1.47.1.1.1.1.8',
                'entPhysicalFirmwareRev': '.1.3.6.1.2.1.47.1.1.1.1.9',
                'entPhysicalSoftwareRev': '.1.3.6.1.2.1.47.1.1.1.1.10',
                'entPhysicalSerialNum': '.1.3.6.1.2.1.47.1.1.1.1.11',
                'entPhysicalModelName': '.1.3.6.1.2.1.47.1.1.1.1.13',
                'lldpRemChassisId': '.1.0.8802.1.1.2.1.4.1.1.5',          # The string value used to identify the chassis component associated with the remote system
                'lldpRemPortIdSubtype': '.1.0.8802.1.1.2.1.4.1.1.6',      # The type of port identifier encoding used in the associated 'lldpRemPortId' object
                'lldpRemPortDesc': '.1.0.8802.1.1.2.1.4.1.1.8',           # The string value used to identify the description of the given port associated with the remote system.
                'lldpRemSysName': '.1.0.8802.1.1.2.1.4.1.1.9',            # The string value used to identify the system name of the of the remote system.
                'lldpRemSysDesc': '.1.0.8802.1.1.2.1.4.1.1.10',           # The string value used to identify the system description of the remote system.
                'lldpRemChassisIdSubtype': '.1.0.8802.1.1.2.1.4.1.1.4',   # The type of encoding used to identify the chassis associated with the remote system.
                'lldpRemSysCapSupported': '.1.0.8802.1.1.2.1.4.1.1.11',   # The bitmap value used to identify which system capabilities are supported on the remote system.
                'lldpRemSysCapEnabled': '.1.0.8802.1.1.2.1.4.1.1.12',     # The bitmap value used to identify which system capabilities are enabled on the remote system.
                'lldpLocPortIdSubtype': '.1.0.8802.1.1.2.1.3.7.1.2',      # The type of port identifier encoding used in the associated
                'lldpLocPortId': '.1.0.8802.1.1.2.1.3.7.1.3',             # The string value used to identify the port component associated with a given port in the local system.
                'lldpLocPortDesc': '.1.0.8802.1.1.2.1.3.7.1.4',           # The string value used to identify the 802 LAN station's port description associated with the local system.  If the local agent supports IETF RFC 2863, lldpLocPortDesc object should have the same value of ifDescr object
                'entPhysicalAlias': '.1.3.6.1.2.1.47.1.1.1.1.14',         # This will alow you to reference the pyhsical entity with another associated value like the plugable information.
                                                                          # This will refer to the ifIndex as well
                'ipAdEntAddr': '.1.3.6.1.2.1.4.20.1.1',                   # Returns any ip addresses configured
                'ipAdEntNetMask': '.1.3.6.1.2.1.4.20.1.3',                   # Returns any ip subnet configured for the above
                'ipAdEntIfIndex': '.1.3.6.1.2.1.4.20.1.2',                # Ip address and interface index the address is tied too
            },
            'values': {
                'ifAdminStatus': {
                    '1': 'Up',
                    '2': 'Down',
                    '3': 'Testing'
                },
                'ifOperStatus': {
                    '1': 'Up',
                    '2': 'Down',
                    '3': 'Testing',
                    '4': 'Unknown',
                    '5': 'Dormant',
                    '6': 'Not Present',
                    '7': 'Lower Layer Down',
                },
                'lldpRemChassisIdSubtype': {
                    '1': 'chassisComponent',
                    '2': 'interfaceAlias',
                    '3': 'portComponent',
                    '4': 'macAddress',
                    '5': 'networkAddress',
                    '6': 'interfaceName',
                    '7': 'local'
                },
                'lldpRemPortIdSubtype': {
                    '1': 'interfaceAlias',
                    '2': 'portComponent',
                    '3': 'macAddress',
                    '4': 'networkAddress',
                    '5': 'interfaceName',
                    '6': 'agentCircuitId',
                    '7': 'local',
                },
                'lldpRemSysCapSupported': {
                    '0': 'other',
                    '1': 'repeater',
                    '2': 'bridge',
                    '3': 'wlanAccessPoint',
                    '4': 'router',
                    '5': 'telephone',
                    '6': 'docsisCableDevice',
                    '7': 'stationOnly'
                },
                'lldpRemSysCapEnabled': {
                    '0': 'other',
                    '1': 'repeater',
                    '2': 'bridge',
                    '3': 'wlanAccessPoint',
                    '4': 'router',
                    '5': 'telephone',
                    '6': 'docsisCableDevice',
                    '7': 'stationOnly'
                },
                'lldpLocPortIdSubtype': {
                    '1': 'interfaceAlias',
                    '2': 'portComponent',
                    '3': 'macAddress',
                    '4': 'networkAddress',
                    '5': 'interfaceName',
                    '6': 'agentCircuitId',
                    '7': 'local',
                },
                'vtpVlanType': {
                    '1': 'ethernet',
                    '2': 'fddi',
                    '3': 'tokenRing',
                    '4': 'fddiNet',
                    '5': 'trNet',
                    '6': 'deprecated',
                }
            }
        }
    elif device_type == "C9508":
        library = {
            'get': {
                'sysName': '.1.3.6.1.2.1.1.5.0',
                'domain': '.1.3.6.1.4.1.9.9.436.1.1.5.0',
                'sysName': '.1.3.6.1.2.1.1.5.0',
                'sysDescr': '.1.3.6.1.2.1.1.1.0',
                'sysLocation': '.1.3.6.1.2.1.1.6.0',
                'chassis_type': '.1.3.6.1.2.1.47.1.1.1.1.13.10',
                'snmp_chassisSWVersionSupervisorModuleOne': '.1.3.6.1.2.1.47.1.1.1.1.10.48',
                'snmp_chassisSWVersionSupervisorModuleTwo': '.1.3.6.1.2.1.47.1.1.1.1.10.49'
            },
            'walk': {
                'ifIndex': '.1.3.6.1.2.1.2.2.1.1',
                'ifDescr': '.1.3.6.1.2.1.2.2.1.2',
                'ifName': '.1.3.6.1.2.1.31.1.1.1.1',
                'ifAlias': '.1.3.6.1.2.1.31.1.1.1.18',
                'ifType': '.1.3.6.1.2.1.2.2.1.3',
                'ifMtu': '.1.3.6.1.2.1.2.2.1.4',
                'ifSpeed': '.1.3.6.1.2.1.2.2.1.5',
                'ifAdminStatus': '.1.3.6.1.2.1.2.2.1.7',
                'ifOperStatus': '.1.3.6.1.2.1.2.2.1.8',
                'dot1dBasePortIfIndex': '.1.3.6.1.2.1.17.1.4.1.2',
                'vtpVlanState': '.1.3.6.1.4.1.9.9.46.1.3.1.1.2',
                'cviRoutedVlanIfIndex': '.1.3.6.1.4.1.9.9.128.1.1.1.1.3',
                # cviVlanId, cviPhysicalifindex - The index for the ifTable entry associated with this routed VLAN interface
                'cdpInterfaceName': '.1.3.6.1.4.1.9.9.23.1.1.1.1.6',
                # The name of the local interface as advertised by CDP in the PORT TLV
                'cdpCacheDeviceId': '.1.3.6.1.4.1.9.9.23.1.2.1.1.6',
                # The Device-ID string as reported in the most recent CDP message.
                # The zero-length string indicates no Device-ID
                # field (TLV) was reported in the most recent CDP message.

                'cdpCacheDevicePort': '.1.3.6.1.4.1.9.9.23.1.2.1.1.7',
                # The Port-ID string as reported in the most recent CDP
                # message.  This will typically be the value of the ifName
                # object (e.g., 'Ethernet0').  The zero-length string
                # indicates no Port-ID field (TLV) was reported in the
                # most recent CDP message.
                'cdpCachePlatform': '.1.3.6.1.4.1.9.9.23.1.2.1.1.8',
                # The Device's Hardware Platform as reported in the most
                # recent CDP message.  The zero-length string indicates
                # that no Platform field (TLV) was reported in the most
                # recent CDP message.
                'vtpVlanName': '.1.3.6.1.4.1.9.9.46.1.3.1.1.4',
                'vtpVlanType': '.1.3.6.1.4.1.9.9.46.1.3.1.1.3',
                # Type of vlan -Syntax	 VlanType (INTEGER) {ethernet(1),
                # fddi(2),
                # tokenRing(3), fddiNet(4),
                # trNet(5), deprecated(6)
                'dot1dTpFdbPort': '.1.3.6.1.2.1.17.4.3.1.2',  # Either the value '0', or the port number of the port on
                # which a frame having a source address equal to the value
                # of the corresponding instance of dot1dTpFdbAddress has
                # been seen.  A value of '0' indicates that the port
                # number has not been learned, but that the bridge does
                # have some forwarding/filtering information about this
                # address (e.g., in the dot1dStaticTable).  Implementors
                # are encouraged to assign the port value to this object
                # whenever it is learned, even for addresses for which the
                # corresponding value of dot1dTpFdbStatus is not
                # learned(3).
                # For cisco - Filter out the first .1.3.6.1.2.1.17.4.3.1.2. then convert
                # the rest from decimal to hex
                # 'cefcFRUPowerAdminStatus': '.1.3.6.1.4.1.9.9.117.1.1.2.1.1', # Syntax	 PowerAdminType (INTEGER) {on(1), off(2), inlineAuto(3), inlineOn(4), powerCycle(5)
                # 'cefcFRUPowerOperStatus': '.1.3.6.1.4.1.9.9.117.1.1.2.1.2', # PowerOperType (INTEGER) {offEnvOther(1), on(2), offAdmin(3), offDenied(4), offEnvPower(5), offEnvTemp(6), offEnvFan(7), failed(8), onButFanFail(9), offCooling(10), offConnectorRating(11), onButInlinePowerFail(12)
                'entPhysicalDescr': '.1.3.6.1.2.1.47.1.1.1.1.2',
                # A textual description of physical entity.  This object should contain a string that identifies the manufacturer's name for the physical entity, and should be set to a distinct value for each version or model of the physical entity.
                'entPhysicalHardwareRev': '.1.3.6.1.2.1.47.1.1.1.1.8',
                'entPhysicalFirmwareRev': '.1.3.6.1.2.1.47.1.1.1.1.9',
                'entPhysicalSoftwareRev': '.1.3.6.1.2.1.47.1.1.1.1.10',
                'entPhysicalSerialNum': '.1.3.6.1.2.1.47.1.1.1.1.11',
                'entPhysicalModelName': '.1.3.6.1.2.1.47.1.1.1.1.13',
                'lldpRemChassisId': '.1.0.8802.1.1.2.1.4.1.1.5',
                # The string value used to identify the chassis component associated with the remote system
                'lldpRemPortIdSubtype': '.1.0.8802.1.1.2.1.4.1.1.6',
                # The type of port identifier encoding used in the associated 'lldpRemPortId' object
                'lldpRemPortDesc': '.1.0.8802.1.1.2.1.4.1.1.8',
                # The string value used to identify the description of the given port associated with the remote system.
                'lldpRemSysName': '.1.0.8802.1.1.2.1.4.1.1.9',
                # The string value used to identify the system name of the of the remote system.
                'lldpRemSysDesc': '.1.0.8802.1.1.2.1.4.1.1.10',
                # The string value used to identify the system description of the remote system.
                'lldpRemChassisIdSubtype': '.1.0.8802.1.1.2.1.4.1.1.4',
                # The type of encoding used to identify the chassis associated with the remote system.
                'lldpRemSysCapSupported': '.1.0.8802.1.1.2.1.4.1.1.11',
                # The bitmap value used to identify which system capabilities are supported on the remote system.
                'lldpRemSysCapEnabled': '.1.0.8802.1.1.2.1.4.1.1.12',
                # The bitmap value used to identify which system capabilities are enabled on the remote system.
                'lldpLocPortIdSubtype': '.1.0.8802.1.1.2.1.3.7.1.2',
                # The type of port identifier encoding used in the associated
                'lldpLocPortId': '.1.0.8802.1.1.2.1.3.7.1.3',
                # The string value used to identify the port component associated with a given port in the local system.
                'lldpLocPortDesc': '.1.0.8802.1.1.2.1.3.7.1.4',
                # The string value used to identify the 802 LAN station's port description associated with the local system.  If the local agent supports IETF RFC 2863, lldpLocPortDesc object should have the same value of ifDescr object
                'entPhysicalAlias': '.1.3.6.1.2.1.47.1.1.1.1.14',
                # This will alow you to reference the pyhsical entity with another associated value like the plugable information.
                # This will refer to the ifIndex as well
                #'ipAdEntAddr': '.1.3.6.1.2.1.4.20.1.1',  # Returns any ip addresses configured
                #'ipAdEntNetMask': '.1.3.6.1.2.1.4.20.1.3',  # Returns any ip subnet configured for the above
                #'ipAdEntIfIndex': '.1.3.6.1.2.1.4.20.1.2',  # Ip address and interface index the address is tied too
            },
            'values': {
                'ifAdminStatus': {
                    '1': 'Up',
                    '2': 'Down',
                    '3': 'Testing'
                },
                'ifOperStatus': {
                    '1': 'Up',
                    '2': 'Down',
                    '3': 'Testing',
                    '4': 'Unknown',
                    '5': 'Dormant',
                    '6': 'Not Present',
                    '7': 'Lower Layer Down',
                },
                'lldpRemChassisIdSubtype': {
                    '1': 'chassisComponent',
                    '2': 'interfaceAlias',
                    '3': 'portComponent',
                    '4': 'macAddress',
                    '5': 'networkAddress',
                    '6': 'interfaceName',
                    '7': 'local'
                },
                'lldpRemPortIdSubtype': {
                    '1': 'interfaceAlias',
                    '2': 'portComponent',
                    '3': 'macAddress',
                    '4': 'networkAddress',
                    '5': 'interfaceName',
                    '6': 'agentCircuitId',
                    '7': 'local',
                },
                'lldpRemSysCapSupported': {
                    '0': 'other',
                    '1': 'repeater',
                    '2': 'bridge',
                    '3': 'wlanAccessPoint',
                    '4': 'router',
                    '5': 'telephone',
                    '6': 'docsisCableDevice',
                    '7': 'stationOnly'
                },
                'lldpRemSysCapEnabled': {
                    '0': 'other',
                    '1': 'repeater',
                    '2': 'bridge',
                    '3': 'wlanAccessPoint',
                    '4': 'router',
                    '5': 'telephone',
                    '6': 'docsisCableDevice',
                    '7': 'stationOnly'
                },
                'lldpLocPortIdSubtype': {
                    '1': 'interfaceAlias',
                    '2': 'portComponent',
                    '3': 'macAddress',
                    '4': 'networkAddress',
                    '5': 'interfaceName',
                    '6': 'agentCircuitId',
                    '7': 'local',
                },
                'vtpVlanType': {
                    '1': 'ethernet',
                    '2': 'fddi',
                    '3': 'tokenRing',
                    '4': 'fddiNet',
                    '5': 'trNet',
                    '6': 'deprecated',
                }
            }
        }
    elif device_type == "C9504":
        library = {
            'get': {
                'sysName': '.1.3.6.1.2.1.1.5.0',
                'domain': '.1.3.6.1.4.1.9.9.436.1.1.5.0',
                'sysName': '.1.3.6.1.2.1.1.5.0',
                'sysDescr': '.1.3.6.1.2.1.1.1.0',
                'sysLocation': '.1.3.6.1.2.1.1.6.0',
                'chassis_type': '.1.3.6.1.2.1.47.1.1.1.1.13.10',
                'snmp_chassisSWVersionSupervisorModuleOne': '.1.3.6.1.2.1.47.1.1.1.1.10.48',
                'snmp_chassisSWVersionSupervisorModuleTwo': '.1.3.6.1.2.1.47.1.1.1.1.10.49'
            },
            'walk': {
                'ifIndex': '.1.3.6.1.2.1.2.2.1.1',
                'ifDescr': '.1.3.6.1.2.1.2.2.1.2',
                'ifName': '.1.3.6.1.2.1.31.1.1.1.1',
                'ifAlias': '.1.3.6.1.2.1.31.1.1.1.18',
                'ifType': '.1.3.6.1.2.1.2.2.1.3',
                'ifMtu': '.1.3.6.1.2.1.2.2.1.4',
                'ifSpeed': '.1.3.6.1.2.1.2.2.1.5',
                'ifAdminStatus': '.1.3.6.1.2.1.2.2.1.7',
                'ifOperStatus': '.1.3.6.1.2.1.2.2.1.8',
                'dot1dBasePortIfIndex': '.1.3.6.1.2.1.17.1.4.1.2',
                'vtpVlanState': '.1.3.6.1.4.1.9.9.46.1.3.1.1.2',
                'cviRoutedVlanIfIndex': '.1.3.6.1.4.1.9.9.128.1.1.1.1.3',
                # cviVlanId, cviPhysicalifindex - The index for the ifTable entry associated with this routed VLAN interface
                'cdpInterfaceName': '.1.3.6.1.4.1.9.9.23.1.1.1.1.6',
                # The name of the local interface as advertised by CDP in the PORT TLV
                'cdpCacheDeviceId': '.1.3.6.1.4.1.9.9.23.1.2.1.1.6',
                # The Device-ID string as reported in the most recent CDP message.
                # The zero-length string indicates no Device-ID
                # field (TLV) was reported in the most recent CDP message.

                'cdpCacheDevicePort': '.1.3.6.1.4.1.9.9.23.1.2.1.1.7',
                # The Port-ID string as reported in the most recent CDP
                # message.  This will typically be the value of the ifName
                # object (e.g., 'Ethernet0').  The zero-length string
                # indicates no Port-ID field (TLV) was reported in the
                # most recent CDP message.
                'cdpCachePlatform': '.1.3.6.1.4.1.9.9.23.1.2.1.1.8',
                # The Device's Hardware Platform as reported in the most
                # recent CDP message.  The zero-length string indicates
                # that no Platform field (TLV) was reported in the most
                # recent CDP message.
                'vtpVlanName': '.1.3.6.1.4.1.9.9.46.1.3.1.1.4',
                'vtpVlanType': '.1.3.6.1.4.1.9.9.46.1.3.1.1.3',
                # Type of vlan -Syntax	 VlanType (INTEGER) {ethernet(1),
                # fddi(2),
                # tokenRing(3), fddiNet(4),
                # trNet(5), deprecated(6)
                'dot1dTpFdbPort': '.1.3.6.1.2.1.17.4.3.1.2',  # Either the value '0', or the port number of the port on
                # which a frame having a source address equal to the value
                # of the corresponding instance of dot1dTpFdbAddress has
                # been seen.  A value of '0' indicates that the port
                # number has not been learned, but that the bridge does
                # have some forwarding/filtering information about this
                # address (e.g., in the dot1dStaticTable).  Implementors
                # are encouraged to assign the port value to this object
                # whenever it is learned, even for addresses for which the
                # corresponding value of dot1dTpFdbStatus is not
                # learned(3).
                # For cisco - Filter out the first .1.3.6.1.2.1.17.4.3.1.2. then convert
                # the rest from decimal to hex
                # 'cefcFRUPowerAdminStatus': '.1.3.6.1.4.1.9.9.117.1.1.2.1.1', # Syntax	 PowerAdminType (INTEGER) {on(1), off(2), inlineAuto(3), inlineOn(4), powerCycle(5)
                # 'cefcFRUPowerOperStatus': '.1.3.6.1.4.1.9.9.117.1.1.2.1.2', # PowerOperType (INTEGER) {offEnvOther(1), on(2), offAdmin(3), offDenied(4), offEnvPower(5), offEnvTemp(6), offEnvFan(7), failed(8), onButFanFail(9), offCooling(10), offConnectorRating(11), onButInlinePowerFail(12)
                'entPhysicalDescr': '.1.3.6.1.2.1.47.1.1.1.1.2',
                # A textual description of physical entity.  This object should contain a string that identifies the manufacturer's name for the physical entity, and should be set to a distinct value for each version or model of the physical entity.
                'entPhysicalHardwareRev': '.1.3.6.1.2.1.47.1.1.1.1.8',
                'entPhysicalFirmwareRev': '.1.3.6.1.2.1.47.1.1.1.1.9',
                'entPhysicalSoftwareRev': '.1.3.6.1.2.1.47.1.1.1.1.10',
                'entPhysicalSerialNum': '.1.3.6.1.2.1.47.1.1.1.1.11',
                'entPhysicalModelName': '.1.3.6.1.2.1.47.1.1.1.1.13',
                'lldpRemChassisId': '.1.0.8802.1.1.2.1.4.1.1.5',
                # The string value used to identify the chassis component associated with the remote system
                'lldpRemPortIdSubtype': '.1.0.8802.1.1.2.1.4.1.1.6',
                # The type of port identifier encoding used in the associated 'lldpRemPortId' object
                'lldpRemPortDesc': '.1.0.8802.1.1.2.1.4.1.1.8',
                # The string value used to identify the description of the given port associated with the remote system.
                'lldpRemSysName': '.1.0.8802.1.1.2.1.4.1.1.9',
                # The string value used to identify the system name of the of the remote system.
                'lldpRemSysDesc': '.1.0.8802.1.1.2.1.4.1.1.10',
                # The string value used to identify the system description of the remote system.
                'lldpRemChassisIdSubtype': '.1.0.8802.1.1.2.1.4.1.1.4',
                # The type of encoding used to identify the chassis associated with the remote system.
                'lldpRemSysCapSupported': '.1.0.8802.1.1.2.1.4.1.1.11',
                # The bitmap value used to identify which system capabilities are supported on the remote system.
                'lldpRemSysCapEnabled': '.1.0.8802.1.1.2.1.4.1.1.12',
                # The bitmap value used to identify which system capabilities are enabled on the remote system.
                'lldpLocPortIdSubtype': '.1.0.8802.1.1.2.1.3.7.1.2',
                # The type of port identifier encoding used in the associated
                'lldpLocPortId': '.1.0.8802.1.1.2.1.3.7.1.3',
                # The string value used to identify the port component associated with a given port in the local system.
                'lldpLocPortDesc': '.1.0.8802.1.1.2.1.3.7.1.4',
                # The string value used to identify the 802 LAN station's port description associated with the local system.  If the local agent supports IETF RFC 2863, lldpLocPortDesc object should have the same value of ifDescr object
                'entPhysicalAlias': '.1.3.6.1.2.1.47.1.1.1.1.14',
                # This will alow you to reference the pyhsical entity with another associated value like the plugable information.
                # This will refer to the ifIndex as well
                #'ipAdEntAddr': '.1.3.6.1.2.1.4.20.1.1',  # Returns any ip addresses configured
                #'ipAdEntNetMask': '.1.3.6.1.2.1.4.20.1.3',  # Returns any ip subnet configured for the above
                #'ipAdEntIfIndex': '.1.3.6.1.2.1.4.20.1.2',  # Ip address and interface index the address is tied too
            },
            'values': {
                'ifAdminStatus': {
                    '1': 'Up',
                    '2': 'Down',
                    '3': 'Testing'
                },
                'ifOperStatus': {
                    '1': 'Up',
                    '2': 'Down',
                    '3': 'Testing',
                    '4': 'Unknown',
                    '5': 'Dormant',
                    '6': 'Not Present',
                    '7': 'Lower Layer Down',
                },
                'lldpRemChassisIdSubtype': {
                    '1': 'chassisComponent',
                    '2': 'interfaceAlias',
                    '3': 'portComponent',
                    '4': 'macAddress',
                    '5': 'networkAddress',
                    '6': 'interfaceName',
                    '7': 'local'
                },
                'lldpRemPortIdSubtype': {
                    '1': 'interfaceAlias',
                    '2': 'portComponent',
                    '3': 'macAddress',
                    '4': 'networkAddress',
                    '5': 'interfaceName',
                    '6': 'agentCircuitId',
                    '7': 'local',
                },
                'lldpRemSysCapSupported': {
                    '0': 'other',
                    '1': 'repeater',
                    '2': 'bridge',
                    '3': 'wlanAccessPoint',
                    '4': 'router',
                    '5': 'telephone',
                    '6': 'docsisCableDevice',
                    '7': 'stationOnly'
                },
                'lldpRemSysCapEnabled': {
                    '0': 'other',
                    '1': 'repeater',
                    '2': 'bridge',
                    '3': 'wlanAccessPoint',
                    '4': 'router',
                    '5': 'telephone',
                    '6': 'docsisCableDevice',
                    '7': 'stationOnly'
                },
                'lldpLocPortIdSubtype': {
                    '1': 'interfaceAlias',
                    '2': 'portComponent',
                    '3': 'macAddress',
                    '4': 'networkAddress',
                    '5': 'interfaceName',
                    '6': 'agentCircuitId',
                    '7': 'local',
                },
                'vtpVlanType': {
                    '1': 'ethernet',
                    '2': 'fddi',
                    '3': 'tokenRing',
                    '4': 'fddiNet',
                    '5': 'trNet',
                    '6': 'deprecated',
                }
            }
        }
    elif device_type == "C9500":
        library = {
            'get': {
                'sysName': '.1.3.6.1.2.1.1.5.0',
                'domain': '.1.3.6.1.4.1.9.2.1.4.0',
                'sysName': '.1.3.6.1.2.1.1.5.0',
                'sysDescr': '.1.3.6.1.2.1.1.1.0',
                'sysLocation': '.1.3.6.1.2.1.1.6.0',
                'chassis_type': '.1.3.6.1.2.1.47.1.1.1.1.13.1'
            },
            'walk': {
                'ifIndex': '.1.3.6.1.2.1.2.2.1.1',
                'ifDescr': '.1.3.6.1.2.1.2.2.1.2',
                'ifName': '.1.3.6.1.2.1.31.1.1.1.1',
                'ifAlias': '.1.3.6.1.2.1.31.1.1.1.18',
                'ifType': '.1.3.6.1.2.1.2.2.1.3',
                'ifMtu': '.1.3.6.1.2.1.2.2.1.4',
                'ifSpeed': '.1.3.6.1.2.1.2.2.1.5',
                'ifAdminStatus': '.1.3.6.1.2.1.2.2.1.7',
                'ifOperStatus': '.1.3.6.1.2.1.2.2.1.8',
                'dot1dBasePortIfIndex': '.1.3.6.1.2.1.17.1.4.1.2',
                'vtpVlanState': '.1.3.6.1.4.1.9.9.46.1.3.1.1.2',
                'cviRoutedVlanIfIndex': '.1.3.6.1.4.1.9.9.128.1.1.1.1.3',
                # cviVlanId, cviPhysicalifindex - The index for the ifTable entry associated with this routed VLAN interface
                'cdpInterfaceName': '.1.3.6.1.4.1.9.9.23.1.1.1.1.6',
                # The name of the local interface as advertised by CDP in the PORT TLV
                'cdpCacheDeviceId': '.1.3.6.1.4.1.9.9.23.1.2.1.1.6',
                # The Device-ID string as reported in the most recent CDP message.
                # The zero-length string indicates no Device-ID
                # field (TLV) was reported in the most recent CDP message.

                'cdpCacheDevicePort': '.1.3.6.1.4.1.9.9.23.1.2.1.1.7',
                # The Port-ID string as reported in the most recent CDP
                # message.  This will typically be the value of the ifName
                # object (e.g., 'Ethernet0').  The zero-length string
                # indicates no Port-ID field (TLV) was reported in the
                # most recent CDP message.
                'cdpCachePlatform': '.1.3.6.1.4.1.9.9.23.1.2.1.1.8',
                # The Device's Hardware Platform as reported in the most
                # recent CDP message.  The zero-length string indicates
                # that no Platform field (TLV) was reported in the most
                # recent CDP message.
                'vtpVlanName': '.1.3.6.1.4.1.9.9.46.1.3.1.1.4',
                'vtpVlanType': '.1.3.6.1.4.1.9.9.46.1.3.1.1.3',
                # Type of vlan -Syntax	 VlanType (INTEGER) {ethernet(1),
                # fddi(2),
                # tokenRing(3), fddiNet(4),
                # trNet(5), deprecated(6)
                'dot1dTpFdbPort': '.1.3.6.1.2.1.17.4.3.1.2',  # Either the value '0', or the port number of the port on
                # which a frame having a source address equal to the value
                # of the corresponding instance of dot1dTpFdbAddress has
                # been seen.  A value of '0' indicates that the port
                # number has not been learned, but that the bridge does
                # have some forwarding/filtering information about this
                # address (e.g., in the dot1dStaticTable).  Implementors
                # are encouraged to assign the port value to this object
                # whenever it is learned, even for addresses for which the
                # corresponding value of dot1dTpFdbStatus is not
                # learned(3).
                # For cisco - Filter out the first .1.3.6.1.2.1.17.4.3.1.2. then convert
                # the rest from decimal to hex
                # 'cefcFRUPowerAdminStatus': '.1.3.6.1.4.1.9.9.117.1.1.2.1.1', # Syntax	 PowerAdminType (INTEGER) {on(1), off(2), inlineAuto(3), inlineOn(4), powerCycle(5)
                # 'cefcFRUPowerOperStatus': '.1.3.6.1.4.1.9.9.117.1.1.2.1.2', # PowerOperType (INTEGER) {offEnvOther(1), on(2), offAdmin(3), offDenied(4), offEnvPower(5), offEnvTemp(6), offEnvFan(7), failed(8), onButFanFail(9), offCooling(10), offConnectorRating(11), onButInlinePowerFail(12)
                'entPhysicalDescr': '.1.3.6.1.2.1.47.1.1.1.1.2',
                # A textual description of physical entity.  This object should contain a string that identifies the manufacturer's name for the physical entity, and should be set to a distinct value for each version or model of the physical entity.
                'entPhysicalHardwareRev': '.1.3.6.1.2.1.47.1.1.1.1.8',
                'entPhysicalFirmwareRev': '.1.3.6.1.2.1.47.1.1.1.1.9',
                'entPhysicalSoftwareRev': '.1.3.6.1.2.1.47.1.1.1.1.10',
                'entPhysicalSerialNum': '.1.3.6.1.2.1.47.1.1.1.1.11',
                'entPhysicalModelName': '.1.3.6.1.2.1.47.1.1.1.1.13',
                'lldpRemChassisId': '.1.0.8802.1.1.2.1.4.1.1.5',
                # The string value used to identify the chassis component associated with the remote system
                'lldpRemPortIdSubtype': '.1.0.8802.1.1.2.1.4.1.1.6',
                # The type of port identifier encoding used in the associated 'lldpRemPortId' object
                'lldpRemPortDesc': '.1.0.8802.1.1.2.1.4.1.1.8',
                # The string value used to identify the description of the given port associated with the remote system.
                'lldpRemSysName': '.1.0.8802.1.1.2.1.4.1.1.9',
                # The string value used to identify the system name of the of the remote system.
                'lldpRemSysDesc': '.1.0.8802.1.1.2.1.4.1.1.10',
                # The string value used to identify the system description of the remote system.
                'lldpRemChassisIdSubtype': '.1.0.8802.1.1.2.1.4.1.1.4',
                # The type of encoding used to identify the chassis associated with the remote system.
                'lldpRemSysCapSupported': '.1.0.8802.1.1.2.1.4.1.1.11',
                # The bitmap value used to identify which system capabilities are supported on the remote system.
                'lldpRemSysCapEnabled': '.1.0.8802.1.1.2.1.4.1.1.12',
                # The bitmap value used to identify which system capabilities are enabled on the remote system.
                'lldpLocPortIdSubtype': '.1.0.8802.1.1.2.1.3.7.1.2',
                # The type of port identifier encoding used in the associated
                'lldpLocPortId': '.1.0.8802.1.1.2.1.3.7.1.3',
                # The string value used to identify the port component associated with a given port in the local system.
                'lldpLocPortDesc': '.1.0.8802.1.1.2.1.3.7.1.4',
                # The string value used to identify the 802 LAN station's port description associated with the local system.  If the local agent supports IETF RFC 2863, lldpLocPortDesc object should have the same value of ifDescr object
                'entPhysicalAlias': '.1.3.6.1.2.1.47.1.1.1.1.14',
                # This will alow you to reference the pyhsical entity with another associated value like the plugable information.
                # This will refer to the ifIndex as well
                'ipAdEntAddr': '.1.3.6.1.2.1.4.20.1.1',  # Returns any ip addresses configured
                'ipAdEntNetMask': '.1.3.6.1.2.1.4.20.1.3',  # Returns any ip subnet configured for the above
                'ipAdEntIfIndex': '.1.3.6.1.2.1.4.20.1.2',  # Ip address and interface index the address is tied too
            },
            'values': {
                'ifAdminStatus': {
                    '1': 'Up',
                    '2': 'Down',
                    '3': 'Testing'
                },
                'ifOperStatus': {
                    '1': 'Up',
                    '2': 'Down',
                    '3': 'Testing',
                    '4': 'Unknown',
                    '5': 'Dormant',
                    '6': 'Not Present',
                    '7': 'Lower Layer Down',
                },
                'lldpRemChassisIdSubtype': {
                    '1': 'chassisComponent',
                    '2': 'interfaceAlias',
                    '3': 'portComponent',
                    '4': 'macAddress',
                    '5': 'networkAddress',
                    '6': 'interfaceName',
                    '7': 'local'
                },
                'lldpRemPortIdSubtype': {
                    '1': 'interfaceAlias',
                    '2': 'portComponent',
                    '3': 'macAddress',
                    '4': 'networkAddress',
                    '5': 'interfaceName',
                    '6': 'agentCircuitId',
                    '7': 'local',
                },
                'lldpRemSysCapSupported': {
                    '0': 'other',
                    '1': 'repeater',
                    '2': 'bridge',
                    '3': 'wlanAccessPoint',
                    '4': 'router',
                    '5': 'telephone',
                    '6': 'docsisCableDevice',
                    '7': 'stationOnly'
                },
                'lldpRemSysCapEnabled': {
                    '0': 'other',
                    '1': 'repeater',
                    '2': 'bridge',
                    '3': 'wlanAccessPoint',
                    '4': 'router',
                    '5': 'telephone',
                    '6': 'docsisCableDevice',
                    '7': 'stationOnly'
                },
                'lldpLocPortIdSubtype': {
                    '1': 'interfaceAlias',
                    '2': 'portComponent',
                    '3': 'macAddress',
                    '4': 'networkAddress',
                    '5': 'interfaceName',
                    '6': 'agentCircuitId',
                    '7': 'local',
                },
                'vtpVlanType': {
                    '1': 'ethernet',
                    '2': 'fddi',
                    '3': 'tokenRing',
                    '4': 'fddiNet',
                    '5': 'trNet',
                    '6': 'deprecated',
                }
            }
        }
    elif device_type == "N9K-C9336C-FX2":
        library = {
            'get': {
                'sysName': '.1.3.6.1.2.1.1.5.0',
                'domain': '.1.3.6.1.4.1.9.9.436.1.1.5.0',
                'sysName': '.1.3.6.1.2.1.1.5.0',
                'sysDescr': '.1.3.6.1.2.1.1.1.0',
                'sysLocation': '.1.3.6.1.2.1.1.6.0',
                'chassis_type': '.1.3.6.1.2.1.47.1.1.1.1.13.10',
                'snmp_chassisSWVersionSupervisorModuleOne': '.1.3.6.1.2.1.47.1.1.1.1.10.48',
                'snmp_chassisSWVersionSupervisorModuleTwo': '.1.3.6.1.2.1.47.1.1.1.1.10.49'
            },
            'walk': {
                'ifIndex': '.1.3.6.1.2.1.2.2.1.1',
                'ifDescr': '.1.3.6.1.2.1.2.2.1.2',
                'ifName': '.1.3.6.1.2.1.31.1.1.1.1',
                'ifAlias': '.1.3.6.1.2.1.31.1.1.1.18',
                'ifType': '.1.3.6.1.2.1.2.2.1.3',
                'ifMtu': '.1.3.6.1.2.1.2.2.1.4',
                'ifSpeed': '.1.3.6.1.2.1.2.2.1.5',
                'ifAdminStatus': '.1.3.6.1.2.1.2.2.1.7',
                'ifOperStatus': '.1.3.6.1.2.1.2.2.1.8',
                'dot1dBasePortIfIndex': '.1.3.6.1.2.1.17.1.4.1.2',
                'vtpVlanState': '.1.3.6.1.4.1.9.9.46.1.3.1.1.2',
                'cviRoutedVlanIfIndex': '.1.3.6.1.4.1.9.9.128.1.1.1.1.3',
                # cviVlanId, cviPhysicalifindex - The index for the ifTable entry associated with this routed VLAN interface
                'cdpInterfaceName': '.1.3.6.1.4.1.9.9.23.1.1.1.1.6',
                # The name of the local interface as advertised by CDP in the PORT TLV
                'cdpCacheDeviceId': '.1.3.6.1.4.1.9.9.23.1.2.1.1.6',
                # The Device-ID string as reported in the most recent CDP message.
                # The zero-length string indicates no Device-ID
                # field (TLV) was reported in the most recent CDP message.

                'cdpCacheDevicePort': '.1.3.6.1.4.1.9.9.23.1.2.1.1.7',
                # The Port-ID string as reported in the most recent CDP
                # message.  This will typically be the value of the ifName
                # object (e.g., 'Ethernet0').  The zero-length string
                # indicates no Port-ID field (TLV) was reported in the
                # most recent CDP message.
                'cdpCachePlatform': '.1.3.6.1.4.1.9.9.23.1.2.1.1.8',
                # The Device's Hardware Platform as reported in the most
                # recent CDP message.  The zero-length string indicates
                # that no Platform field (TLV) was reported in the most
                # recent CDP message.
                'vtpVlanName': '.1.3.6.1.4.1.9.9.46.1.3.1.1.4',
                'vtpVlanType': '.1.3.6.1.4.1.9.9.46.1.3.1.1.3',
                # Type of vlan -Syntax	 VlanType (INTEGER) {ethernet(1),
                # fddi(2),
                # tokenRing(3), fddiNet(4),
                # trNet(5), deprecated(6)
                'dot1dTpFdbPort': '.1.3.6.1.2.1.17.4.3.1.2',  # Either the value '0', or the port number of the port on
                # which a frame having a source address equal to the value
                # of the corresponding instance of dot1dTpFdbAddress has
                # been seen.  A value of '0' indicates that the port
                # number has not been learned, but that the bridge does
                # have some forwarding/filtering information about this
                # address (e.g., in the dot1dStaticTable).  Implementors
                # are encouraged to assign the port value to this object
                # whenever it is learned, even for addresses for which the
                # corresponding value of dot1dTpFdbStatus is not
                # learned(3).
                # For cisco - Filter out the first .1.3.6.1.2.1.17.4.3.1.2. then convert
                # the rest from decimal to hex
                # 'cefcFRUPowerAdminStatus': '.1.3.6.1.4.1.9.9.117.1.1.2.1.1', # Syntax	 PowerAdminType (INTEGER) {on(1), off(2), inlineAuto(3), inlineOn(4), powerCycle(5)
                # 'cefcFRUPowerOperStatus': '.1.3.6.1.4.1.9.9.117.1.1.2.1.2', # PowerOperType (INTEGER) {offEnvOther(1), on(2), offAdmin(3), offDenied(4), offEnvPower(5), offEnvTemp(6), offEnvFan(7), failed(8), onButFanFail(9), offCooling(10), offConnectorRating(11), onButInlinePowerFail(12)
                'entPhysicalDescr': '.1.3.6.1.2.1.47.1.1.1.1.2',
                # A textual description of physical entity.  This object should contain a string that identifies the manufacturer's name for the physical entity, and should be set to a distinct value for each version or model of the physical entity.
                'entPhysicalHardwareRev': '.1.3.6.1.2.1.47.1.1.1.1.8',
                'entPhysicalFirmwareRev': '.1.3.6.1.2.1.47.1.1.1.1.9',
                'entPhysicalSoftwareRev': '.1.3.6.1.2.1.47.1.1.1.1.10',
                'entPhysicalSerialNum': '.1.3.6.1.2.1.47.1.1.1.1.11',
                'entPhysicalModelName': '.1.3.6.1.2.1.47.1.1.1.1.13',
                'lldpRemChassisId': '.1.0.8802.1.1.2.1.4.1.1.5',
                # The string value used to identify the chassis component associated with the remote system
                'lldpRemPortIdSubtype': '.1.0.8802.1.1.2.1.4.1.1.6',
                # The type of port identifier encoding used in the associated 'lldpRemPortId' object
                'lldpRemPortDesc': '.1.0.8802.1.1.2.1.4.1.1.8',
                # The string value used to identify the description of the given port associated with the remote system.
                'lldpRemSysName': '.1.0.8802.1.1.2.1.4.1.1.9',
                # The string value used to identify the system name of the of the remote system.
                'lldpRemSysDesc': '.1.0.8802.1.1.2.1.4.1.1.10',
                # The string value used to identify the system description of the remote system.
                'lldpRemChassisIdSubtype': '.1.0.8802.1.1.2.1.4.1.1.4',
                # The type of encoding used to identify the chassis associated with the remote system.
                'lldpRemSysCapSupported': '.1.0.8802.1.1.2.1.4.1.1.11',
                # The bitmap value used to identify which system capabilities are supported on the remote system.
                'lldpRemSysCapEnabled': '.1.0.8802.1.1.2.1.4.1.1.12',
                # The bitmap value used to identify which system capabilities are enabled on the remote system.
                'lldpLocPortIdSubtype': '.1.0.8802.1.1.2.1.3.7.1.2',
                # The type of port identifier encoding used in the associated
                'lldpLocPortId': '.1.0.8802.1.1.2.1.3.7.1.3',
                # The string value used to identify the port component associated with a given port in the local system.
                'lldpLocPortDesc': '.1.0.8802.1.1.2.1.3.7.1.4',
                # The string value used to identify the 802 LAN station's port description associated with the local system.  If the local agent supports IETF RFC 2863, lldpLocPortDesc object should have the same value of ifDescr object
                'entPhysicalAlias': '.1.3.6.1.2.1.47.1.1.1.1.14',
                # This will alow you to reference the pyhsical entity with another associated value like the plugable information.
                # This will refer to the ifIndex as well
                'ipAdEntAddr': '.1.3.6.1.2.1.4.20.1.1',  # Returns any ip addresses configured
                'ipAdEntNetMask': '.1.3.6.1.2.1.4.20.1.3',  # Returns any ip subnet configured for the above
                'ipAdEntIfIndex': '.1.3.6.1.2.1.4.20.1.2',  # Ip address and interface index the address is tied too
            },
            'values': {
                'ifAdminStatus': {
                    '1': 'Up',
                    '2': 'Down',
                    '3': 'Testing'
                },
                'ifOperStatus': {
                    '1': 'Up',
                    '2': 'Down',
                    '3': 'Testing',
                    '4': 'Unknown',
                    '5': 'Dormant',
                    '6': 'Not Present',
                    '7': 'Lower Layer Down',
                },
                'lldpRemChassisIdSubtype': {
                    '1': 'chassisComponent',
                    '2': 'interfaceAlias',
                    '3': 'portComponent',
                    '4': 'macAddress',
                    '5': 'networkAddress',
                    '6': 'interfaceName',
                    '7': 'local'
                },
                'lldpRemPortIdSubtype': {
                    '1': 'interfaceAlias',
                    '2': 'portComponent',
                    '3': 'macAddress',
                    '4': 'networkAddress',
                    '5': 'interfaceName',
                    '6': 'agentCircuitId',
                    '7': 'local',
                },
                'lldpRemSysCapSupported': {
                    '0': 'other',
                    '1': 'repeater',
                    '2': 'bridge',
                    '3': 'wlanAccessPoint',
                    '4': 'router',
                    '5': 'telephone',
                    '6': 'docsisCableDevice',
                    '7': 'stationOnly'
                },
                'lldpRemSysCapEnabled': {
                    '0': 'other',
                    '1': 'repeater',
                    '2': 'bridge',
                    '3': 'wlanAccessPoint',
                    '4': 'router',
                    '5': 'telephone',
                    '6': 'docsisCableDevice',
                    '7': 'stationOnly'
                },
                'lldpLocPortIdSubtype': {
                    '1': 'interfaceAlias',
                    '2': 'portComponent',
                    '3': 'macAddress',
                    '4': 'networkAddress',
                    '5': 'interfaceName',
                    '6': 'agentCircuitId',
                    '7': 'local',
                },
                'vtpVlanType': {
                    '1': 'ethernet',
                    '2': 'fddi',
                    '3': 'tokenRing',
                    '4': 'fddiNet',
                    '5': 'trNet',
                    '6': 'deprecated',
                }
            }
        }
    elif device_type == "N9K-C9336C-FX2-E":
        library = {
            'get': {
                'sysName': '.1.3.6.1.2.1.1.5.0',
                'domain': '.1.3.6.1.4.1.9.9.436.1.1.5.0',
                'sysName': '.1.3.6.1.2.1.1.5.0',
                'sysDescr': '.1.3.6.1.2.1.1.1.0',
                'sysLocation': '.1.3.6.1.2.1.1.6.0',
                'chassis_type': '.1.3.6.1.2.1.47.1.1.1.1.13.10',
                'snmp_chassisSWVersionSupervisorModuleOne': '.1.3.6.1.2.1.47.1.1.1.1.10.48',
                'snmp_chassisSWVersionSupervisorModuleTwo': '.1.3.6.1.2.1.47.1.1.1.1.10.49'
            },
            'walk': {
                'ifIndex': '.1.3.6.1.2.1.2.2.1.1',
                'ifDescr': '.1.3.6.1.2.1.2.2.1.2',
                'ifName': '.1.3.6.1.2.1.31.1.1.1.1',
                'ifAlias': '.1.3.6.1.2.1.31.1.1.1.18',
                'ifType': '.1.3.6.1.2.1.2.2.1.3',
                'ifMtu': '.1.3.6.1.2.1.2.2.1.4',
                'ifSpeed': '.1.3.6.1.2.1.2.2.1.5',
                'ifAdminStatus': '.1.3.6.1.2.1.2.2.1.7',
                'ifOperStatus': '.1.3.6.1.2.1.2.2.1.8',
                'dot1dBasePortIfIndex': '.1.3.6.1.2.1.17.1.4.1.2',
                'vtpVlanState': '.1.3.6.1.4.1.9.9.46.1.3.1.1.2',
                'cviRoutedVlanIfIndex': '.1.3.6.1.4.1.9.9.128.1.1.1.1.3',
                # cviVlanId, cviPhysicalifindex - The index for the ifTable entry associated with this routed VLAN interface
                'cdpInterfaceName': '.1.3.6.1.4.1.9.9.23.1.1.1.1.6',
                # The name of the local interface as advertised by CDP in the PORT TLV
                'cdpCacheDeviceId': '.1.3.6.1.4.1.9.9.23.1.2.1.1.6',
                # The Device-ID string as reported in the most recent CDP message.
                # The zero-length string indicates no Device-ID
                # field (TLV) was reported in the most recent CDP message.

                'cdpCacheDevicePort': '.1.3.6.1.4.1.9.9.23.1.2.1.1.7',
                # The Port-ID string as reported in the most recent CDP
                # message.  This will typically be the value of the ifName
                # object (e.g., 'Ethernet0').  The zero-length string
                # indicates no Port-ID field (TLV) was reported in the
                # most recent CDP message.
                'cdpCachePlatform': '.1.3.6.1.4.1.9.9.23.1.2.1.1.8',
                # The Device's Hardware Platform as reported in the most
                # recent CDP message.  The zero-length string indicates
                # that no Platform field (TLV) was reported in the most
                # recent CDP message.
                'vtpVlanName': '.1.3.6.1.4.1.9.9.46.1.3.1.1.4',
                'vtpVlanType': '.1.3.6.1.4.1.9.9.46.1.3.1.1.3',
                # Type of vlan -Syntax	 VlanType (INTEGER) {ethernet(1),
                # fddi(2),
                # tokenRing(3), fddiNet(4),
                # trNet(5), deprecated(6)
                'dot1dTpFdbPort': '.1.3.6.1.2.1.17.4.3.1.2',  # Either the value '0', or the port number of the port on
                # which a frame having a source address equal to the value
                # of the corresponding instance of dot1dTpFdbAddress has
                # been seen.  A value of '0' indicates that the port
                # number has not been learned, but that the bridge does
                # have some forwarding/filtering information about this
                # address (e.g., in the dot1dStaticTable).  Implementors
                # are encouraged to assign the port value to this object
                # whenever it is learned, even for addresses for which the
                # corresponding value of dot1dTpFdbStatus is not
                # learned(3).
                # For cisco - Filter out the first .1.3.6.1.2.1.17.4.3.1.2. then convert
                # the rest from decimal to hex
                # 'cefcFRUPowerAdminStatus': '.1.3.6.1.4.1.9.9.117.1.1.2.1.1', # Syntax	 PowerAdminType (INTEGER) {on(1), off(2), inlineAuto(3), inlineOn(4), powerCycle(5)
                # 'cefcFRUPowerOperStatus': '.1.3.6.1.4.1.9.9.117.1.1.2.1.2', # PowerOperType (INTEGER) {offEnvOther(1), on(2), offAdmin(3), offDenied(4), offEnvPower(5), offEnvTemp(6), offEnvFan(7), failed(8), onButFanFail(9), offCooling(10), offConnectorRating(11), onButInlinePowerFail(12)
                'entPhysicalDescr': '.1.3.6.1.2.1.47.1.1.1.1.2',
                # A textual description of physical entity.  This object should contain a string that identifies the manufacturer's name for the physical entity, and should be set to a distinct value for each version or model of the physical entity.
                'entPhysicalHardwareRev': '.1.3.6.1.2.1.47.1.1.1.1.8',
                'entPhysicalFirmwareRev': '.1.3.6.1.2.1.47.1.1.1.1.9',
                'entPhysicalSoftwareRev': '.1.3.6.1.2.1.47.1.1.1.1.10',
                'entPhysicalSerialNum': '.1.3.6.1.2.1.47.1.1.1.1.11',
                'entPhysicalModelName': '.1.3.6.1.2.1.47.1.1.1.1.13',
                'lldpRemChassisId': '.1.0.8802.1.1.2.1.4.1.1.5',
                # The string value used to identify the chassis component associated with the remote system
                'lldpRemPortIdSubtype': '.1.0.8802.1.1.2.1.4.1.1.6',
                # The type of port identifier encoding used in the associated 'lldpRemPortId' object
                'lldpRemPortDesc': '.1.0.8802.1.1.2.1.4.1.1.8',
                # The string value used to identify the description of the given port associated with the remote system.
                'lldpRemSysName': '.1.0.8802.1.1.2.1.4.1.1.9',
                # The string value used to identify the system name of the of the remote system.
                'lldpRemSysDesc': '.1.0.8802.1.1.2.1.4.1.1.10',
                # The string value used to identify the system description of the remote system.
                'lldpRemChassisIdSubtype': '.1.0.8802.1.1.2.1.4.1.1.4',
                # The type of encoding used to identify the chassis associated with the remote system.
                'lldpRemSysCapSupported': '.1.0.8802.1.1.2.1.4.1.1.11',
                # The bitmap value used to identify which system capabilities are supported on the remote system.
                'lldpRemSysCapEnabled': '.1.0.8802.1.1.2.1.4.1.1.12',
                # The bitmap value used to identify which system capabilities are enabled on the remote system.
                'lldpLocPortIdSubtype': '.1.0.8802.1.1.2.1.3.7.1.2',
                # The type of port identifier encoding used in the associated
                'lldpLocPortId': '.1.0.8802.1.1.2.1.3.7.1.3',
                # The string value used to identify the port component associated with a given port in the local system.
                'lldpLocPortDesc': '.1.0.8802.1.1.2.1.3.7.1.4',
                # The string value used to identify the 802 LAN station's port description associated with the local system.  If the local agent supports IETF RFC 2863, lldpLocPortDesc object should have the same value of ifDescr object
                'entPhysicalAlias': '.1.3.6.1.2.1.47.1.1.1.1.14',
                # This will alow you to reference the pyhsical entity with another associated value like the plugable information.
                # This will refer to the ifIndex as well
                'ipAdEntAddr': '.1.3.6.1.2.1.4.20.1.1',  # Returns any ip addresses configured
                'ipAdEntNetMask': '.1.3.6.1.2.1.4.20.1.3',  # Returns any ip subnet configured for the above
                'ipAdEntIfIndex': '.1.3.6.1.2.1.4.20.1.2',  # Ip address and interface index the address is tied too
            },
            'values': {
                'ifAdminStatus': {
                    '1': 'Up',
                    '2': 'Down',
                    '3': 'Testing'
                },
                'ifOperStatus': {
                    '1': 'Up',
                    '2': 'Down',
                    '3': 'Testing',
                    '4': 'Unknown',
                    '5': 'Dormant',
                    '6': 'Not Present',
                    '7': 'Lower Layer Down',
                },
                'lldpRemChassisIdSubtype': {
                    '1': 'chassisComponent',
                    '2': 'interfaceAlias',
                    '3': 'portComponent',
                    '4': 'macAddress',
                    '5': 'networkAddress',
                    '6': 'interfaceName',
                    '7': 'local'
                },
                'lldpRemPortIdSubtype': {
                    '1': 'interfaceAlias',
                    '2': 'portComponent',
                    '3': 'macAddress',
                    '4': 'networkAddress',
                    '5': 'interfaceName',
                    '6': 'agentCircuitId',
                    '7': 'local',
                },
                'lldpRemSysCapSupported': {
                    '0': 'other',
                    '1': 'repeater',
                    '2': 'bridge',
                    '3': 'wlanAccessPoint',
                    '4': 'router',
                    '5': 'telephone',
                    '6': 'docsisCableDevice',
                    '7': 'stationOnly'
                },
                'lldpRemSysCapEnabled': {
                    '0': 'other',
                    '1': 'repeater',
                    '2': 'bridge',
                    '3': 'wlanAccessPoint',
                    '4': 'router',
                    '5': 'telephone',
                    '6': 'docsisCableDevice',
                    '7': 'stationOnly'
                },
                'lldpLocPortIdSubtype': {
                    '1': 'interfaceAlias',
                    '2': 'portComponent',
                    '3': 'macAddress',
                    '4': 'networkAddress',
                    '5': 'interfaceName',
                    '6': 'agentCircuitId',
                    '7': 'local',
                },
                'vtpVlanType': {
                    '1': 'ethernet',
                    '2': 'fddi',
                    '3': 'tokenRing',
                    '4': 'fddiNet',
                    '5': 'trNet',
                    '6': 'deprecated',
                }
            }
        }
    elif device_type == "N9K-C9396PX":
        library = {
            'get': {
                'sysName': '.1.3.6.1.2.1.1.5.0',
                'domain': '.1.3.6.1.4.1.9.9.436.1.1.5.0',
                'sysName': '.1.3.6.1.2.1.1.5.0',
                'sysDescr': '.1.3.6.1.2.1.1.1.0',
                'sysLocation': '.1.3.6.1.2.1.1.6.0',
                'chassis_type': '.1.3.6.1.2.1.47.1.1.1.1.13.10',
                'snmp_chassisSWVersionSupervisorModuleOne': '.1.3.6.1.2.1.47.1.1.1.1.10.48',
                'snmp_chassisSWVersionSupervisorModuleTwo': '.1.3.6.1.2.1.47.1.1.1.1.10.49'
            },
            'walk': {
                'ifIndex': '.1.3.6.1.2.1.2.2.1.1',
                'ifDescr': '.1.3.6.1.2.1.2.2.1.2',
                'ifName': '.1.3.6.1.2.1.31.1.1.1.1',
                'ifAlias': '.1.3.6.1.2.1.31.1.1.1.18',
                'ifType': '.1.3.6.1.2.1.2.2.1.3',
                'ifMtu': '.1.3.6.1.2.1.2.2.1.4',
                'ifSpeed': '.1.3.6.1.2.1.2.2.1.5',
                'ifAdminStatus': '.1.3.6.1.2.1.2.2.1.7',
                'ifOperStatus': '.1.3.6.1.2.1.2.2.1.8',
                'dot1dBasePortIfIndex': '.1.3.6.1.2.1.17.1.4.1.2',
                'vtpVlanState': '.1.3.6.1.4.1.9.9.46.1.3.1.1.2',
                'cviRoutedVlanIfIndex': '.1.3.6.1.4.1.9.9.128.1.1.1.1.3',
                # cviVlanId, cviPhysicalifindex - The index for the ifTable entry associated with this routed VLAN interface
                'cdpInterfaceName': '.1.3.6.1.4.1.9.9.23.1.1.1.1.6',
                # The name of the local interface as advertised by CDP in the PORT TLV
                'cdpCacheDeviceId': '.1.3.6.1.4.1.9.9.23.1.2.1.1.6',
                # The Device-ID string as reported in the most recent CDP message.
                # The zero-length string indicates no Device-ID
                # field (TLV) was reported in the most recent CDP message.

                'cdpCacheDevicePort': '.1.3.6.1.4.1.9.9.23.1.2.1.1.7',
                # The Port-ID string as reported in the most recent CDP
                # message.  This will typically be the value of the ifName
                # object (e.g., 'Ethernet0').  The zero-length string
                # indicates no Port-ID field (TLV) was reported in the
                # most recent CDP message.
                'cdpCachePlatform': '.1.3.6.1.4.1.9.9.23.1.2.1.1.8',
                # The Device's Hardware Platform as reported in the most
                # recent CDP message.  The zero-length string indicates
                # that no Platform field (TLV) was reported in the most
                # recent CDP message.
                'vtpVlanName': '.1.3.6.1.4.1.9.9.46.1.3.1.1.4',
                'vtpVlanType': '.1.3.6.1.4.1.9.9.46.1.3.1.1.3',
                # Type of vlan -Syntax	 VlanType (INTEGER) {ethernet(1),
                # fddi(2),
                # tokenRing(3), fddiNet(4),
                # trNet(5), deprecated(6)
                'dot1dTpFdbPort': '.1.3.6.1.2.1.17.4.3.1.2',  # Either the value '0', or the port number of the port on
                # which a frame having a source address equal to the value
                # of the corresponding instance of dot1dTpFdbAddress has
                # been seen.  A value of '0' indicates that the port
                # number has not been learned, but that the bridge does
                # have some forwarding/filtering information about this
                # address (e.g., in the dot1dStaticTable).  Implementors
                # are encouraged to assign the port value to this object
                # whenever it is learned, even for addresses for which the
                # corresponding value of dot1dTpFdbStatus is not
                # learned(3).
                # For cisco - Filter out the first .1.3.6.1.2.1.17.4.3.1.2. then convert
                # the rest from decimal to hex
                # 'cefcFRUPowerAdminStatus': '.1.3.6.1.4.1.9.9.117.1.1.2.1.1', # Syntax	 PowerAdminType (INTEGER) {on(1), off(2), inlineAuto(3), inlineOn(4), powerCycle(5)
                # 'cefcFRUPowerOperStatus': '.1.3.6.1.4.1.9.9.117.1.1.2.1.2', # PowerOperType (INTEGER) {offEnvOther(1), on(2), offAdmin(3), offDenied(4), offEnvPower(5), offEnvTemp(6), offEnvFan(7), failed(8), onButFanFail(9), offCooling(10), offConnectorRating(11), onButInlinePowerFail(12)
                'entPhysicalDescr': '.1.3.6.1.2.1.47.1.1.1.1.2',
                # A textual description of physical entity.  This object should contain a string that identifies the manufacturer's name for the physical entity, and should be set to a distinct value for each version or model of the physical entity.
                'entPhysicalHardwareRev': '.1.3.6.1.2.1.47.1.1.1.1.8',
                'entPhysicalFirmwareRev': '.1.3.6.1.2.1.47.1.1.1.1.9',
                'entPhysicalSoftwareRev': '.1.3.6.1.2.1.47.1.1.1.1.10',
                'entPhysicalSerialNum': '.1.3.6.1.2.1.47.1.1.1.1.11',
                'entPhysicalModelName': '.1.3.6.1.2.1.47.1.1.1.1.13',
                'lldpRemChassisId': '.1.0.8802.1.1.2.1.4.1.1.5',
                # The string value used to identify the chassis component associated with the remote system
                'lldpRemPortIdSubtype': '.1.0.8802.1.1.2.1.4.1.1.6',
                # The type of port identifier encoding used in the associated 'lldpRemPortId' object
                'lldpRemPortDesc': '.1.0.8802.1.1.2.1.4.1.1.8',
                # The string value used to identify the description of the given port associated with the remote system.
                'lldpRemSysName': '.1.0.8802.1.1.2.1.4.1.1.9',
                # The string value used to identify the system name of the of the remote system.
                'lldpRemSysDesc': '.1.0.8802.1.1.2.1.4.1.1.10',
                # The string value used to identify the system description of the remote system.
                'lldpRemChassisIdSubtype': '.1.0.8802.1.1.2.1.4.1.1.4',
                # The type of encoding used to identify the chassis associated with the remote system.
                'lldpRemSysCapSupported': '.1.0.8802.1.1.2.1.4.1.1.11',
                # The bitmap value used to identify which system capabilities are supported on the remote system.
                'lldpRemSysCapEnabled': '.1.0.8802.1.1.2.1.4.1.1.12',
                # The bitmap value used to identify which system capabilities are enabled on the remote system.
                'lldpLocPortIdSubtype': '.1.0.8802.1.1.2.1.3.7.1.2',
                # The type of port identifier encoding used in the associated
                'lldpLocPortId': '.1.0.8802.1.1.2.1.3.7.1.3',
                # The string value used to identify the port component associated with a given port in the local system.
                'lldpLocPortDesc': '.1.0.8802.1.1.2.1.3.7.1.4',
                # The string value used to identify the 802 LAN station's port description associated with the local system.  If the local agent supports IETF RFC 2863, lldpLocPortDesc object should have the same value of ifDescr object
                'entPhysicalAlias': '.1.3.6.1.2.1.47.1.1.1.1.14',
                # This will alow you to reference the pyhsical entity with another associated value like the plugable information.
                # This will refer to the ifIndex as well
                'ipAdEntAddr': '.1.3.6.1.2.1.4.20.1.1',  # Returns any ip addresses configured
                'ipAdEntNetMask': '.1.3.6.1.2.1.4.20.1.3',  # Returns any ip subnet configured for the above
                'ipAdEntIfIndex': '.1.3.6.1.2.1.4.20.1.2',  # Ip address and interface index the address is tied too
            },
            'values': {
                'ifAdminStatus': {
                    '1': 'Up',
                    '2': 'Down',
                    '3': 'Testing'
                },
                'ifOperStatus': {
                    '1': 'Up',
                    '2': 'Down',
                    '3': 'Testing',
                    '4': 'Unknown',
                    '5': 'Dormant',
                    '6': 'Not Present',
                    '7': 'Lower Layer Down',
                },
                'lldpRemChassisIdSubtype': {
                    '1': 'chassisComponent',
                    '2': 'interfaceAlias',
                    '3': 'portComponent',
                    '4': 'macAddress',
                    '5': 'networkAddress',
                    '6': 'interfaceName',
                    '7': 'local'
                },
                'lldpRemPortIdSubtype': {
                    '1': 'interfaceAlias',
                    '2': 'portComponent',
                    '3': 'macAddress',
                    '4': 'networkAddress',
                    '5': 'interfaceName',
                    '6': 'agentCircuitId',
                    '7': 'local',
                },
                'lldpRemSysCapSupported': {
                    '0': 'other',
                    '1': 'repeater',
                    '2': 'bridge',
                    '3': 'wlanAccessPoint',
                    '4': 'router',
                    '5': 'telephone',
                    '6': 'docsisCableDevice',
                    '7': 'stationOnly'
                },
                'lldpRemSysCapEnabled': {
                    '0': 'other',
                    '1': 'repeater',
                    '2': 'bridge',
                    '3': 'wlanAccessPoint',
                    '4': 'router',
                    '5': 'telephone',
                    '6': 'docsisCableDevice',
                    '7': 'stationOnly'
                },
                'lldpLocPortIdSubtype': {
                    '1': 'interfaceAlias',
                    '2': 'portComponent',
                    '3': 'macAddress',
                    '4': 'networkAddress',
                    '5': 'interfaceName',
                    '6': 'agentCircuitId',
                    '7': 'local',
                },
                'vtpVlanType': {
                    '1': 'ethernet',
                    '2': 'fddi',
                    '3': 'tokenRing',
                    '4': 'fddiNet',
                    '5': 'trNet',
                    '6': 'deprecated',
                }
            }
        }
    elif device_type == "N5K-C5596UP":
        library = {
            'get': {
                'sysName': '.1.3.6.1.2.1.1.5.0',
                'domain': '.1.3.6.1.4.1.9.9.436.1.1.5.0',
                'sysName': '.1.3.6.1.2.1.1.5.0',
                'sysDescr': '.1.3.6.1.2.1.1.1.0',
                'sysLocation': '.1.3.6.1.2.1.1.6.0',
                'chassis_type': '.1.3.6.1.2.1.47.1.1.1.1.13.10',
                'snmp_chassisSWVersionSupervisorModuleOne': '.1.3.6.1.2.1.47.1.1.1.1.10.48',
                'snmp_chassisSWVersionSupervisorModuleTwo': '.1.3.6.1.2.1.47.1.1.1.1.10.49'
            },
            'walk': {
                'ifIndex': '.1.3.6.1.2.1.2.2.1.1',
                'ifDescr': '.1.3.6.1.2.1.2.2.1.2',
                'ifName': '.1.3.6.1.2.1.31.1.1.1.1',
                'ifAlias': '.1.3.6.1.2.1.31.1.1.1.18',
                'ifType': '.1.3.6.1.2.1.2.2.1.3',
                'ifMtu': '.1.3.6.1.2.1.2.2.1.4',
                'ifSpeed': '.1.3.6.1.2.1.2.2.1.5',
                'ifAdminStatus': '.1.3.6.1.2.1.2.2.1.7',
                'ifOperStatus': '.1.3.6.1.2.1.2.2.1.8',
                'dot1dBasePortIfIndex': '.1.3.6.1.2.1.17.1.4.1.2',
                'vtpVlanState': '.1.3.6.1.4.1.9.9.46.1.3.1.1.2',
                'cviRoutedVlanIfIndex': '.1.3.6.1.4.1.9.9.128.1.1.1.1.3',
                # cviVlanId, cviPhysicalifindex - The index for the ifTable entry associated with this routed VLAN interface
                'cdpInterfaceName': '.1.3.6.1.4.1.9.9.23.1.1.1.1.6',
                # The name of the local interface as advertised by CDP in the PORT TLV
                'cdpCacheDeviceId': '.1.3.6.1.4.1.9.9.23.1.2.1.1.6',
                # The Device-ID string as reported in the most recent CDP message.
                # The zero-length string indicates no Device-ID
                # field (TLV) was reported in the most recent CDP message.

                'cdpCacheDevicePort': '.1.3.6.1.4.1.9.9.23.1.2.1.1.7',
                # The Port-ID string as reported in the most recent CDP
                # message.  This will typically be the value of the ifName
                # object (e.g., 'Ethernet0').  The zero-length string
                # indicates no Port-ID field (TLV) was reported in the
                # most recent CDP message.
                'cdpCachePlatform': '.1.3.6.1.4.1.9.9.23.1.2.1.1.8',
                # The Device's Hardware Platform as reported in the most
                # recent CDP message.  The zero-length string indicates
                # that no Platform field (TLV) was reported in the most
                # recent CDP message.
                'vtpVlanName': '.1.3.6.1.4.1.9.9.46.1.3.1.1.4',
                'vtpVlanType': '.1.3.6.1.4.1.9.9.46.1.3.1.1.3',
                # Type of vlan -Syntax	 VlanType (INTEGER) {ethernet(1),
                # fddi(2),
                # tokenRing(3), fddiNet(4),
                # trNet(5), deprecated(6)
                'dot1dTpFdbPort': '.1.3.6.1.2.1.17.4.3.1.2',  # Either the value '0', or the port number of the port on
                # which a frame having a source address equal to the value
                # of the corresponding instance of dot1dTpFdbAddress has
                # been seen.  A value of '0' indicates that the port
                # number has not been learned, but that the bridge does
                # have some forwarding/filtering information about this
                # address (e.g., in the dot1dStaticTable).  Implementors
                # are encouraged to assign the port value to this object
                # whenever it is learned, even for addresses for which the
                # corresponding value of dot1dTpFdbStatus is not
                # learned(3).
                # For cisco - Filter out the first .1.3.6.1.2.1.17.4.3.1.2. then convert
                # the rest from decimal to hex
                # 'cefcFRUPowerAdminStatus': '.1.3.6.1.4.1.9.9.117.1.1.2.1.1', # Syntax	 PowerAdminType (INTEGER) {on(1), off(2), inlineAuto(3), inlineOn(4), powerCycle(5)
                # 'cefcFRUPowerOperStatus': '.1.3.6.1.4.1.9.9.117.1.1.2.1.2', # PowerOperType (INTEGER) {offEnvOther(1), on(2), offAdmin(3), offDenied(4), offEnvPower(5), offEnvTemp(6), offEnvFan(7), failed(8), onButFanFail(9), offCooling(10), offConnectorRating(11), onButInlinePowerFail(12)
                'entPhysicalDescr': '.1.3.6.1.2.1.47.1.1.1.1.2',
                # A textual description of physical entity.  This object should contain a string that identifies the manufacturer's name for the physical entity, and should be set to a distinct value for each version or model of the physical entity.
                'entPhysicalHardwareRev': '.1.3.6.1.2.1.47.1.1.1.1.8',
                'entPhysicalFirmwareRev': '.1.3.6.1.2.1.47.1.1.1.1.9',
                'entPhysicalSoftwareRev': '.1.3.6.1.2.1.47.1.1.1.1.10',
                'entPhysicalSerialNum': '.1.3.6.1.2.1.47.1.1.1.1.11',
                'entPhysicalModelName': '.1.3.6.1.2.1.47.1.1.1.1.13',
                'lldpRemChassisId': '.1.0.8802.1.1.2.1.4.1.1.5',
                # The string value used to identify the chassis component associated with the remote system
                'lldpRemPortIdSubtype': '.1.0.8802.1.1.2.1.4.1.1.6',
                # The type of port identifier encoding used in the associated 'lldpRemPortId' object
                'lldpRemPortDesc': '.1.0.8802.1.1.2.1.4.1.1.8',
                # The string value used to identify the description of the given port associated with the remote system.
                'lldpRemSysName': '.1.0.8802.1.1.2.1.4.1.1.9',
                # The string value used to identify the system name of the of the remote system.
                'lldpRemSysDesc': '.1.0.8802.1.1.2.1.4.1.1.10',
                # The string value used to identify the system description of the remote system.
                'lldpRemChassisIdSubtype': '.1.0.8802.1.1.2.1.4.1.1.4',
                # The type of encoding used to identify the chassis associated with the remote system.
                'lldpRemSysCapSupported': '.1.0.8802.1.1.2.1.4.1.1.11',
                # The bitmap value used to identify which system capabilities are supported on the remote system.
                'lldpRemSysCapEnabled': '.1.0.8802.1.1.2.1.4.1.1.12',
                # The bitmap value used to identify which system capabilities are enabled on the remote system.
                'lldpLocPortIdSubtype': '.1.0.8802.1.1.2.1.3.7.1.2',
                # The type of port identifier encoding used in the associated
                'lldpLocPortId': '.1.0.8802.1.1.2.1.3.7.1.3',
                # The string value used to identify the port component associated with a given port in the local system.
                'lldpLocPortDesc': '.1.0.8802.1.1.2.1.3.7.1.4',
                # The string value used to identify the 802 LAN station's port description associated with the local system.  If the local agent supports IETF RFC 2863, lldpLocPortDesc object should have the same value of ifDescr object
                'entPhysicalAlias': '.1.3.6.1.2.1.47.1.1.1.1.14',
                # This will alow you to reference the pyhsical entity with another associated value like the plugable information.
                # This will refer to the ifIndex as well
                'ipAdEntAddr': '.1.3.6.1.2.1.4.20.1.1',  # Returns any ip addresses configured
                'ipAdEntNetMask': '.1.3.6.1.2.1.4.20.1.3',  # Returns any ip subnet configured for the above
                'ipAdEntIfIndex': '.1.3.6.1.2.1.4.20.1.2',  # Ip address and interface index the address is tied too
            },
            'values': {
                'ifAdminStatus': {
                    '1': 'Up',
                    '2': 'Down',
                    '3': 'Testing'
                },
                'ifOperStatus': {
                    '1': 'Up',
                    '2': 'Down',
                    '3': 'Testing',
                    '4': 'Unknown',
                    '5': 'Dormant',
                    '6': 'Not Present',
                    '7': 'Lower Layer Down',
                },
                'lldpRemChassisIdSubtype': {
                    '1': 'chassisComponent',
                    '2': 'interfaceAlias',
                    '3': 'portComponent',
                    '4': 'macAddress',
                    '5': 'networkAddress',
                    '6': 'interfaceName',
                    '7': 'local'
                },
                'lldpRemPortIdSubtype': {
                    '1': 'interfaceAlias',
                    '2': 'portComponent',
                    '3': 'macAddress',
                    '4': 'networkAddress',
                    '5': 'interfaceName',
                    '6': 'agentCircuitId',
                    '7': 'local',
                },
                'lldpRemSysCapSupported': {
                    '0': 'other',
                    '1': 'repeater',
                    '2': 'bridge',
                    '3': 'wlanAccessPoint',
                    '4': 'router',
                    '5': 'telephone',
                    '6': 'docsisCableDevice',
                    '7': 'stationOnly'
                },
                'lldpRemSysCapEnabled': {
                    '0': 'other',
                    '1': 'repeater',
                    '2': 'bridge',
                    '3': 'wlanAccessPoint',
                    '4': 'router',
                    '5': 'telephone',
                    '6': 'docsisCableDevice',
                    '7': 'stationOnly'
                },
                'lldpLocPortIdSubtype': {
                    '1': 'interfaceAlias',
                    '2': 'portComponent',
                    '3': 'macAddress',
                    '4': 'networkAddress',
                    '5': 'interfaceName',
                    '6': 'agentCircuitId',
                    '7': 'local',
                },
                'vtpVlanType': {
                    '1': 'ethernet',
                    '2': 'fddi',
                    '3': 'tokenRing',
                    '4': 'fddiNet',
                    '5': 'trNet',
                    '6': 'deprecated',
                }
            }
        }
    elif device_type == "N9K-C93180YC-FX3":
        library = {
            'get': {
                'sysName': '.1.3.6.1.2.1.1.5.0',
                'domain': '.1.3.6.1.4.1.9.9.436.1.1.5.0',
                'sysName': '.1.3.6.1.2.1.1.5.0',
                'sysDescr': '.1.3.6.1.2.1.1.1.0',
                'sysLocation': '.1.3.6.1.2.1.1.6.0',
                'chassis_type': '.1.3.6.1.2.1.47.1.1.1.1.13.10',
                'snmp_chassisSWVersionSupervisorModuleOne': '.1.3.6.1.2.1.47.1.1.1.1.10.48',
                'snmp_chassisSWVersionSupervisorModuleTwo': '.1.3.6.1.2.1.47.1.1.1.1.10.49'
            },
            'walk': {
                'ifIndex': '.1.3.6.1.2.1.2.2.1.1',
                'ifDescr': '.1.3.6.1.2.1.2.2.1.2',
                'ifName': '.1.3.6.1.2.1.31.1.1.1.1',
                'ifAlias': '.1.3.6.1.2.1.31.1.1.1.18',
                'ifType': '.1.3.6.1.2.1.2.2.1.3',
                'ifMtu': '.1.3.6.1.2.1.2.2.1.4',
                'ifSpeed': '.1.3.6.1.2.1.2.2.1.5',
                'ifAdminStatus': '.1.3.6.1.2.1.2.2.1.7',
                'ifOperStatus': '.1.3.6.1.2.1.2.2.1.8',
                'dot1dBasePortIfIndex': '.1.3.6.1.2.1.17.1.4.1.2',
                'vtpVlanState': '.1.3.6.1.4.1.9.9.46.1.3.1.1.2',
                'cviRoutedVlanIfIndex': '.1.3.6.1.4.1.9.9.128.1.1.1.1.3',
                # cviVlanId, cviPhysicalifindex - The index for the ifTable entry associated with this routed VLAN interface
                'cdpInterfaceName': '.1.3.6.1.4.1.9.9.23.1.1.1.1.6',
                # The name of the local interface as advertised by CDP in the PORT TLV
                'cdpCacheDeviceId': '.1.3.6.1.4.1.9.9.23.1.2.1.1.6',
                # The Device-ID string as reported in the most recent CDP message.
                # The zero-length string indicates no Device-ID
                # field (TLV) was reported in the most recent CDP message.

                'cdpCacheDevicePort': '.1.3.6.1.4.1.9.9.23.1.2.1.1.7',
                # The Port-ID string as reported in the most recent CDP
                # message.  This will typically be the value of the ifName
                # object (e.g., 'Ethernet0').  The zero-length string
                # indicates no Port-ID field (TLV) was reported in the
                # most recent CDP message.
                'cdpCachePlatform': '.1.3.6.1.4.1.9.9.23.1.2.1.1.8',
                # The Device's Hardware Platform as reported in the most
                # recent CDP message.  The zero-length string indicates
                # that no Platform field (TLV) was reported in the most
                # recent CDP message.
                'vtpVlanName': '.1.3.6.1.4.1.9.9.46.1.3.1.1.4',
                'vtpVlanType': '.1.3.6.1.4.1.9.9.46.1.3.1.1.3',
                # Type of vlan -Syntax	 VlanType (INTEGER) {ethernet(1),
                # fddi(2),
                # tokenRing(3), fddiNet(4),
                # trNet(5), deprecated(6)
                'dot1dTpFdbPort': '.1.3.6.1.2.1.17.4.3.1.2',  # Either the value '0', or the port number of the port on
                # which a frame having a source address equal to the value
                # of the corresponding instance of dot1dTpFdbAddress has
                # been seen.  A value of '0' indicates that the port
                # number has not been learned, but that the bridge does
                # have some forwarding/filtering information about this
                # address (e.g., in the dot1dStaticTable).  Implementors
                # are encouraged to assign the port value to this object
                # whenever it is learned, even for addresses for which the
                # corresponding value of dot1dTpFdbStatus is not
                # learned(3).
                # For cisco - Filter out the first .1.3.6.1.2.1.17.4.3.1.2. then convert
                # the rest from decimal to hex
                # 'cefcFRUPowerAdminStatus': '.1.3.6.1.4.1.9.9.117.1.1.2.1.1', # Syntax	 PowerAdminType (INTEGER) {on(1), off(2), inlineAuto(3), inlineOn(4), powerCycle(5)
                # 'cefcFRUPowerOperStatus': '.1.3.6.1.4.1.9.9.117.1.1.2.1.2', # PowerOperType (INTEGER) {offEnvOther(1), on(2), offAdmin(3), offDenied(4), offEnvPower(5), offEnvTemp(6), offEnvFan(7), failed(8), onButFanFail(9), offCooling(10), offConnectorRating(11), onButInlinePowerFail(12)
                'entPhysicalDescr': '.1.3.6.1.2.1.47.1.1.1.1.2',
                # A textual description of physical entity.  This object should contain a string that identifies the manufacturer's name for the physical entity, and should be set to a distinct value for each version or model of the physical entity.
                'entPhysicalHardwareRev': '.1.3.6.1.2.1.47.1.1.1.1.8',
                'entPhysicalFirmwareRev': '.1.3.6.1.2.1.47.1.1.1.1.9',
                'entPhysicalSoftwareRev': '.1.3.6.1.2.1.47.1.1.1.1.10',
                'entPhysicalSerialNum': '.1.3.6.1.2.1.47.1.1.1.1.11',
                'entPhysicalModelName': '.1.3.6.1.2.1.47.1.1.1.1.13',
                'lldpRemChassisId': '.1.0.8802.1.1.2.1.4.1.1.5',
                # The string value used to identify the chassis component associated with the remote system
                'lldpRemPortIdSubtype': '.1.0.8802.1.1.2.1.4.1.1.6',
                # The type of port identifier encoding used in the associated 'lldpRemPortId' object
                'lldpRemPortDesc': '.1.0.8802.1.1.2.1.4.1.1.8',
                # The string value used to identify the description of the given port associated with the remote system.
                'lldpRemSysName': '.1.0.8802.1.1.2.1.4.1.1.9',
                # The string value used to identify the system name of the of the remote system.
                'lldpRemSysDesc': '.1.0.8802.1.1.2.1.4.1.1.10',
                # The string value used to identify the system description of the remote system.
                'lldpRemChassisIdSubtype': '.1.0.8802.1.1.2.1.4.1.1.4',
                # The type of encoding used to identify the chassis associated with the remote system.
                'lldpRemSysCapSupported': '.1.0.8802.1.1.2.1.4.1.1.11',
                # The bitmap value used to identify which system capabilities are supported on the remote system.
                'lldpRemSysCapEnabled': '.1.0.8802.1.1.2.1.4.1.1.12',
                # The bitmap value used to identify which system capabilities are enabled on the remote system.
                'lldpLocPortIdSubtype': '.1.0.8802.1.1.2.1.3.7.1.2',
                # The type of port identifier encoding used in the associated
                'lldpLocPortId': '.1.0.8802.1.1.2.1.3.7.1.3',
                # The string value used to identify the port component associated with a given port in the local system.
                'lldpLocPortDesc': '.1.0.8802.1.1.2.1.3.7.1.4',
                # The string value used to identify the 802 LAN station's port description associated with the local system.  If the local agent supports IETF RFC 2863, lldpLocPortDesc object should have the same value of ifDescr object
                'entPhysicalAlias': '.1.3.6.1.2.1.47.1.1.1.1.14',
                # This will alow you to reference the pyhsical entity with another associated value like the plugable information.
                # This will refer to the ifIndex as well
                'ipAdEntAddr': '.1.3.6.1.2.1.4.20.1.1',  # Returns any ip addresses configured
                'ipAdEntNetMask': '.1.3.6.1.2.1.4.20.1.3',  # Returns any ip subnet configured for the above
                'ipAdEntIfIndex': '.1.3.6.1.2.1.4.20.1.2',  # Ip address and interface index the address is tied too
            },
            'values': {
                'ifAdminStatus': {
                    '1': 'Up',
                    '2': 'Down',
                    '3': 'Testing'
                },
                'ifOperStatus': {
                    '1': 'Up',
                    '2': 'Down',
                    '3': 'Testing',
                    '4': 'Unknown',
                    '5': 'Dormant',
                    '6': 'Not Present',
                    '7': 'Lower Layer Down',
                },
                'lldpRemChassisIdSubtype': {
                    '1': 'chassisComponent',
                    '2': 'interfaceAlias',
                    '3': 'portComponent',
                    '4': 'macAddress',
                    '5': 'networkAddress',
                    '6': 'interfaceName',
                    '7': 'local'
                },
                'lldpRemPortIdSubtype': {
                    '1': 'interfaceAlias',
                    '2': 'portComponent',
                    '3': 'macAddress',
                    '4': 'networkAddress',
                    '5': 'interfaceName',
                    '6': 'agentCircuitId',
                    '7': 'local',
                },
                'lldpRemSysCapSupported': {
                    '0': 'other',
                    '1': 'repeater',
                    '2': 'bridge',
                    '3': 'wlanAccessPoint',
                    '4': 'router',
                    '5': 'telephone',
                    '6': 'docsisCableDevice',
                    '7': 'stationOnly'
                },
                'lldpRemSysCapEnabled': {
                    '0': 'other',
                    '1': 'repeater',
                    '2': 'bridge',
                    '3': 'wlanAccessPoint',
                    '4': 'router',
                    '5': 'telephone',
                    '6': 'docsisCableDevice',
                    '7': 'stationOnly'
                },
                'lldpLocPortIdSubtype': {
                    '1': 'interfaceAlias',
                    '2': 'portComponent',
                    '3': 'macAddress',
                    '4': 'networkAddress',
                    '5': 'interfaceName',
                    '6': 'agentCircuitId',
                    '7': 'local',
                },
                'vtpVlanType': {
                    '1': 'ethernet',
                    '2': 'fddi',
                    '3': 'tokenRing',
                    '4': 'fddiNet',
                    '5': 'trNet',
                    '6': 'deprecated',
                }
            }
        }
    elif device_type == "N5K-C5020P-BF":
        library = {
            'get': {
                'sysName': '.1.3.6.1.2.1.1.5.0',
                'domain': '.1.3.6.1.4.1.9.9.436.1.1.5.0',
                'sysName': '.1.3.6.1.2.1.1.5.0',
                'sysDescr': '.1.3.6.1.2.1.1.1.0',
                'sysLocation': '.1.3.6.1.2.1.1.6.0',
                'chassis_type': '.1.3.6.1.2.1.47.1.1.1.1.13.10',
                'snmp_chassisSWVersionSupervisorModuleOne': '.1.3.6.1.2.1.47.1.1.1.1.10.48',
                'snmp_chassisSWVersionSupervisorModuleTwo': '.1.3.6.1.2.1.47.1.1.1.1.10.49'
            },
            'walk': {
                'ifIndex': '.1.3.6.1.2.1.2.2.1.1',
                'ifDescr': '.1.3.6.1.2.1.2.2.1.2',
                'ifName': '.1.3.6.1.2.1.31.1.1.1.1',
                'ifAlias': '.1.3.6.1.2.1.31.1.1.1.18',
                'ifType': '.1.3.6.1.2.1.2.2.1.3',
                'ifMtu': '.1.3.6.1.2.1.2.2.1.4',
                'ifSpeed': '.1.3.6.1.2.1.2.2.1.5',
                'ifAdminStatus': '.1.3.6.1.2.1.2.2.1.7',
                'ifOperStatus': '.1.3.6.1.2.1.2.2.1.8',
                'dot1dBasePortIfIndex': '.1.3.6.1.2.1.17.1.4.1.2',
                'vtpVlanState': '.1.3.6.1.4.1.9.9.46.1.3.1.1.2',
                'cviRoutedVlanIfIndex': '.1.3.6.1.4.1.9.9.128.1.1.1.1.3',
                # cviVlanId, cviPhysicalifindex - The index for the ifTable entry associated with this routed VLAN interface
                'cdpInterfaceName': '.1.3.6.1.4.1.9.9.23.1.1.1.1.6',
                # The name of the local interface as advertised by CDP in the PORT TLV
                'cdpCacheDeviceId': '.1.3.6.1.4.1.9.9.23.1.2.1.1.6',
                # The Device-ID string as reported in the most recent CDP message.
                # The zero-length string indicates no Device-ID
                # field (TLV) was reported in the most recent CDP message.

                'cdpCacheDevicePort': '.1.3.6.1.4.1.9.9.23.1.2.1.1.7',
                # The Port-ID string as reported in the most recent CDP
                # message.  This will typically be the value of the ifName
                # object (e.g., 'Ethernet0').  The zero-length string
                # indicates no Port-ID field (TLV) was reported in the
                # most recent CDP message.
                'cdpCachePlatform': '.1.3.6.1.4.1.9.9.23.1.2.1.1.8',
                # The Device's Hardware Platform as reported in the most
                # recent CDP message.  The zero-length string indicates
                # that no Platform field (TLV) was reported in the most
                # recent CDP message.
                'vtpVlanName': '.1.3.6.1.4.1.9.9.46.1.3.1.1.4',
                'vtpVlanType': '.1.3.6.1.4.1.9.9.46.1.3.1.1.3',
                # Type of vlan -Syntax	 VlanType (INTEGER) {ethernet(1),
                # fddi(2),
                # tokenRing(3), fddiNet(4),
                # trNet(5), deprecated(6)
                'dot1dTpFdbPort': '.1.3.6.1.2.1.17.4.3.1.2',  # Either the value '0', or the port number of the port on
                # which a frame having a source address equal to the value
                # of the corresponding instance of dot1dTpFdbAddress has
                # been seen.  A value of '0' indicates that the port
                # number has not been learned, but that the bridge does
                # have some forwarding/filtering information about this
                # address (e.g., in the dot1dStaticTable).  Implementors
                # are encouraged to assign the port value to this object
                # whenever it is learned, even for addresses for which the
                # corresponding value of dot1dTpFdbStatus is not
                # learned(3).
                # For cisco - Filter out the first .1.3.6.1.2.1.17.4.3.1.2. then convert
                # the rest from decimal to hex
                # 'cefcFRUPowerAdminStatus': '.1.3.6.1.4.1.9.9.117.1.1.2.1.1', # Syntax	 PowerAdminType (INTEGER) {on(1), off(2), inlineAuto(3), inlineOn(4), powerCycle(5)
                # 'cefcFRUPowerOperStatus': '.1.3.6.1.4.1.9.9.117.1.1.2.1.2', # PowerOperType (INTEGER) {offEnvOther(1), on(2), offAdmin(3), offDenied(4), offEnvPower(5), offEnvTemp(6), offEnvFan(7), failed(8), onButFanFail(9), offCooling(10), offConnectorRating(11), onButInlinePowerFail(12)
                'entPhysicalDescr': '.1.3.6.1.2.1.47.1.1.1.1.2',
                # A textual description of physical entity.  This object should contain a string that identifies the manufacturer's name for the physical entity, and should be set to a distinct value for each version or model of the physical entity.
                'entPhysicalHardwareRev': '.1.3.6.1.2.1.47.1.1.1.1.8',
                'entPhysicalFirmwareRev': '.1.3.6.1.2.1.47.1.1.1.1.9',
                'entPhysicalSoftwareRev': '.1.3.6.1.2.1.47.1.1.1.1.10',
                'entPhysicalSerialNum': '.1.3.6.1.2.1.47.1.1.1.1.11',
                'entPhysicalModelName': '.1.3.6.1.2.1.47.1.1.1.1.13',
                'lldpRemChassisId': '.1.0.8802.1.1.2.1.4.1.1.5',
                # The string value used to identify the chassis component associated with the remote system
                'lldpRemPortIdSubtype': '.1.0.8802.1.1.2.1.4.1.1.6',
                # The type of port identifier encoding used in the associated 'lldpRemPortId' object
                'lldpRemPortDesc': '.1.0.8802.1.1.2.1.4.1.1.8',
                # The string value used to identify the description of the given port associated with the remote system.
                'lldpRemSysName': '.1.0.8802.1.1.2.1.4.1.1.9',
                # The string value used to identify the system name of the of the remote system.
                'lldpRemSysDesc': '.1.0.8802.1.1.2.1.4.1.1.10',
                # The string value used to identify the system description of the remote system.
                'lldpRemChassisIdSubtype': '.1.0.8802.1.1.2.1.4.1.1.4',
                # The type of encoding used to identify the chassis associated with the remote system.
                'lldpRemSysCapSupported': '.1.0.8802.1.1.2.1.4.1.1.11',
                # The bitmap value used to identify which system capabilities are supported on the remote system.
                'lldpRemSysCapEnabled': '.1.0.8802.1.1.2.1.4.1.1.12',
                # The bitmap value used to identify which system capabilities are enabled on the remote system.
                'lldpLocPortIdSubtype': '.1.0.8802.1.1.2.1.3.7.1.2',
                # The type of port identifier encoding used in the associated
                'lldpLocPortId': '.1.0.8802.1.1.2.1.3.7.1.3',
                # The string value used to identify the port component associated with a given port in the local system.
                'lldpLocPortDesc': '.1.0.8802.1.1.2.1.3.7.1.4',
                # The string value used to identify the 802 LAN station's port description associated with the local system.  If the local agent supports IETF RFC 2863, lldpLocPortDesc object should have the same value of ifDescr object
                'entPhysicalAlias': '.1.3.6.1.2.1.47.1.1.1.1.14',
                # This will alow you to reference the pyhsical entity with another associated value like the plugable information.
                # This will refer to the ifIndex as well
                'ipAdEntAddr': '.1.3.6.1.2.1.4.20.1.1',  # Returns any ip addresses configured
                'ipAdEntNetMask': '.1.3.6.1.2.1.4.20.1.3',  # Returns any ip subnet configured for the above
                'ipAdEntIfIndex': '.1.3.6.1.2.1.4.20.1.2',  # Ip address and interface index the address is tied too
            },
            'values': {
                'ifAdminStatus': {
                    '1': 'Up',
                    '2': 'Down',
                    '3': 'Testing'
                },
                'ifOperStatus': {
                    '1': 'Up',
                    '2': 'Down',
                    '3': 'Testing',
                    '4': 'Unknown',
                    '5': 'Dormant',
                    '6': 'Not Present',
                    '7': 'Lower Layer Down',
                },
                'lldpRemChassisIdSubtype': {
                    '1': 'chassisComponent',
                    '2': 'interfaceAlias',
                    '3': 'portComponent',
                    '4': 'macAddress',
                    '5': 'networkAddress',
                    '6': 'interfaceName',
                    '7': 'local'
                },
                'lldpRemPortIdSubtype': {
                    '1': 'interfaceAlias',
                    '2': 'portComponent',
                    '3': 'macAddress',
                    '4': 'networkAddress',
                    '5': 'interfaceName',
                    '6': 'agentCircuitId',
                    '7': 'local',
                },
                'lldpRemSysCapSupported': {
                    '0': 'other',
                    '1': 'repeater',
                    '2': 'bridge',
                    '3': 'wlanAccessPoint',
                    '4': 'router',
                    '5': 'telephone',
                    '6': 'docsisCableDevice',
                    '7': 'stationOnly'
                },
                'lldpRemSysCapEnabled': {
                    '0': 'other',
                    '1': 'repeater',
                    '2': 'bridge',
                    '3': 'wlanAccessPoint',
                    '4': 'router',
                    '5': 'telephone',
                    '6': 'docsisCableDevice',
                    '7': 'stationOnly'
                },
                'lldpLocPortIdSubtype': {
                    '1': 'interfaceAlias',
                    '2': 'portComponent',
                    '3': 'macAddress',
                    '4': 'networkAddress',
                    '5': 'interfaceName',
                    '6': 'agentCircuitId',
                    '7': 'local',
                },
                'vtpVlanType': {
                    '1': 'ethernet',
                    '2': 'fddi',
                    '3': 'tokenRing',
                    '4': 'fddiNet',
                    '5': 'trNet',
                    '6': 'deprecated',
                }
            }
        }
    elif device_type == "N5K-C5696Q":
        library = {
            'get': {
                'sysName': '.1.3.6.1.2.1.1.5.0',
                'domain': '.1.3.6.1.4.1.9.9.436.1.1.5.0',
                'sysName': '.1.3.6.1.2.1.1.5.0',
                'sysDescr': '.1.3.6.1.2.1.1.1.0',
                'sysLocation': '.1.3.6.1.2.1.1.6.0',
                'chassis_type': '.1.3.6.1.2.1.47.1.1.1.1.13.10',
                'snmp_chassisSWVersionSupervisorModuleOne': '.1.3.6.1.2.1.47.1.1.1.1.10.48',
                'snmp_chassisSWVersionSupervisorModuleTwo': '.1.3.6.1.2.1.47.1.1.1.1.10.49'
            },
            'walk': {
                'ifIndex': '.1.3.6.1.2.1.2.2.1.1',
                'ifDescr': '.1.3.6.1.2.1.2.2.1.2',
                'ifName': '.1.3.6.1.2.1.31.1.1.1.1',
                'ifAlias': '.1.3.6.1.2.1.31.1.1.1.18',
                'ifType': '.1.3.6.1.2.1.2.2.1.3',
                'ifMtu': '.1.3.6.1.2.1.2.2.1.4',
                'ifSpeed': '.1.3.6.1.2.1.2.2.1.5',
                'ifAdminStatus': '.1.3.6.1.2.1.2.2.1.7',
                'ifOperStatus': '.1.3.6.1.2.1.2.2.1.8',
                'dot1dBasePortIfIndex': '.1.3.6.1.2.1.17.1.4.1.2',
                'vtpVlanState': '.1.3.6.1.4.1.9.9.46.1.3.1.1.2',
                'cviRoutedVlanIfIndex': '.1.3.6.1.4.1.9.9.128.1.1.1.1.3',
                # cviVlanId, cviPhysicalifindex - The index for the ifTable entry associated with this routed VLAN interface
                'cdpInterfaceName': '.1.3.6.1.4.1.9.9.23.1.1.1.1.6',
                # The name of the local interface as advertised by CDP in the PORT TLV
                'cdpCacheDeviceId': '.1.3.6.1.4.1.9.9.23.1.2.1.1.6',
                # The Device-ID string as reported in the most recent CDP message.
                # The zero-length string indicates no Device-ID
                # field (TLV) was reported in the most recent CDP message.

                'cdpCacheDevicePort': '.1.3.6.1.4.1.9.9.23.1.2.1.1.7',
                # The Port-ID string as reported in the most recent CDP
                # message.  This will typically be the value of the ifName
                # object (e.g., 'Ethernet0').  The zero-length string
                # indicates no Port-ID field (TLV) was reported in the
                # most recent CDP message.
                'cdpCachePlatform': '.1.3.6.1.4.1.9.9.23.1.2.1.1.8',
                # The Device's Hardware Platform as reported in the most
                # recent CDP message.  The zero-length string indicates
                # that no Platform field (TLV) was reported in the most
                # recent CDP message.
                'vtpVlanName': '.1.3.6.1.4.1.9.9.46.1.3.1.1.4',
                'vtpVlanType': '.1.3.6.1.4.1.9.9.46.1.3.1.1.3',
                # Type of vlan -Syntax	 VlanType (INTEGER) {ethernet(1),
                # fddi(2),
                # tokenRing(3), fddiNet(4),
                # trNet(5), deprecated(6)
                'dot1dTpFdbPort': '.1.3.6.1.2.1.17.4.3.1.2',  # Either the value '0', or the port number of the port on
                # which a frame having a source address equal to the value
                # of the corresponding instance of dot1dTpFdbAddress has
                # been seen.  A value of '0' indicates that the port
                # number has not been learned, but that the bridge does
                # have some forwarding/filtering information about this
                # address (e.g., in the dot1dStaticTable).  Implementors
                # are encouraged to assign the port value to this object
                # whenever it is learned, even for addresses for which the
                # corresponding value of dot1dTpFdbStatus is not
                # learned(3).
                # For cisco - Filter out the first .1.3.6.1.2.1.17.4.3.1.2. then convert
                # the rest from decimal to hex
                # 'cefcFRUPowerAdminStatus': '.1.3.6.1.4.1.9.9.117.1.1.2.1.1', # Syntax	 PowerAdminType (INTEGER) {on(1), off(2), inlineAuto(3), inlineOn(4), powerCycle(5)
                # 'cefcFRUPowerOperStatus': '.1.3.6.1.4.1.9.9.117.1.1.2.1.2', # PowerOperType (INTEGER) {offEnvOther(1), on(2), offAdmin(3), offDenied(4), offEnvPower(5), offEnvTemp(6), offEnvFan(7), failed(8), onButFanFail(9), offCooling(10), offConnectorRating(11), onButInlinePowerFail(12)
                'entPhysicalDescr': '.1.3.6.1.2.1.47.1.1.1.1.2',
                # A textual description of physical entity.  This object should contain a string that identifies the manufacturer's name for the physical entity, and should be set to a distinct value for each version or model of the physical entity.
                'entPhysicalHardwareRev': '.1.3.6.1.2.1.47.1.1.1.1.8',
                'entPhysicalFirmwareRev': '.1.3.6.1.2.1.47.1.1.1.1.9',
                'entPhysicalSoftwareRev': '.1.3.6.1.2.1.47.1.1.1.1.10',
                'entPhysicalSerialNum': '.1.3.6.1.2.1.47.1.1.1.1.11',
                'entPhysicalModelName': '.1.3.6.1.2.1.47.1.1.1.1.13',
                'lldpRemChassisId': '.1.0.8802.1.1.2.1.4.1.1.5',
                # The string value used to identify the chassis component associated with the remote system
                'lldpRemPortIdSubtype': '.1.0.8802.1.1.2.1.4.1.1.6',
                # The type of port identifier encoding used in the associated 'lldpRemPortId' object
                'lldpRemPortDesc': '.1.0.8802.1.1.2.1.4.1.1.8',
                # The string value used to identify the description of the given port associated with the remote system.
                'lldpRemSysName': '.1.0.8802.1.1.2.1.4.1.1.9',
                # The string value used to identify the system name of the of the remote system.
                'lldpRemSysDesc': '.1.0.8802.1.1.2.1.4.1.1.10',
                # The string value used to identify the system description of the remote system.
                'lldpRemChassisIdSubtype': '.1.0.8802.1.1.2.1.4.1.1.4',
                # The type of encoding used to identify the chassis associated with the remote system.
                'lldpRemSysCapSupported': '.1.0.8802.1.1.2.1.4.1.1.11',
                # The bitmap value used to identify which system capabilities are supported on the remote system.
                'lldpRemSysCapEnabled': '.1.0.8802.1.1.2.1.4.1.1.12',
                # The bitmap value used to identify which system capabilities are enabled on the remote system.
                'lldpLocPortIdSubtype': '.1.0.8802.1.1.2.1.3.7.1.2',
                # The type of port identifier encoding used in the associated
                'lldpLocPortId': '.1.0.8802.1.1.2.1.3.7.1.3',
                # The string value used to identify the port component associated with a given port in the local system.
                'lldpLocPortDesc': '.1.0.8802.1.1.2.1.3.7.1.4',
                # The string value used to identify the 802 LAN station's port description associated with the local system.  If the local agent supports IETF RFC 2863, lldpLocPortDesc object should have the same value of ifDescr object
                'entPhysicalAlias': '.1.3.6.1.2.1.47.1.1.1.1.14',
                # This will alow you to reference the pyhsical entity with another associated value like the plugable information.
                # This will refer to the ifIndex as well
                'ipAdEntAddr': '.1.3.6.1.2.1.4.20.1.1',  # Returns any ip addresses configured
                'ipAdEntNetMask': '.1.3.6.1.2.1.4.20.1.3',  # Returns any ip subnet configured for the above
                'ipAdEntIfIndex': '.1.3.6.1.2.1.4.20.1.2',  # Ip address and interface index the address is tied too
            },
            'values': {
                'ifAdminStatus': {
                    '1': 'Up',
                    '2': 'Down',
                    '3': 'Testing'
                },
                'ifOperStatus': {
                    '1': 'Up',
                    '2': 'Down',
                    '3': 'Testing',
                    '4': 'Unknown',
                    '5': 'Dormant',
                    '6': 'Not Present',
                    '7': 'Lower Layer Down',
                },
                'lldpRemChassisIdSubtype': {
                    '1': 'chassisComponent',
                    '2': 'interfaceAlias',
                    '3': 'portComponent',
                    '4': 'macAddress',
                    '5': 'networkAddress',
                    '6': 'interfaceName',
                    '7': 'local'
                },
                'lldpRemPortIdSubtype': {
                    '1': 'interfaceAlias',
                    '2': 'portComponent',
                    '3': 'macAddress',
                    '4': 'networkAddress',
                    '5': 'interfaceName',
                    '6': 'agentCircuitId',
                    '7': 'local',
                },
                'lldpRemSysCapSupported': {
                    '0': 'other',
                    '1': 'repeater',
                    '2': 'bridge',
                    '3': 'wlanAccessPoint',
                    '4': 'router',
                    '5': 'telephone',
                    '6': 'docsisCableDevice',
                    '7': 'stationOnly'
                },
                'lldpRemSysCapEnabled': {
                    '0': 'other',
                    '1': 'repeater',
                    '2': 'bridge',
                    '3': 'wlanAccessPoint',
                    '4': 'router',
                    '5': 'telephone',
                    '6': 'docsisCableDevice',
                    '7': 'stationOnly'
                },
                'lldpLocPortIdSubtype': {
                    '1': 'interfaceAlias',
                    '2': 'portComponent',
                    '3': 'macAddress',
                    '4': 'networkAddress',
                    '5': 'interfaceName',
                    '6': 'agentCircuitId',
                    '7': 'local',
                },
                'vtpVlanType': {
                    '1': 'ethernet',
                    '2': 'fddi',
                    '3': 'tokenRing',
                    '4': 'fddiNet',
                    '5': 'trNet',
                    '6': 'deprecated',
                }
            }
        }
    elif device_type == "N3K-C3548P-10GX":
        library = {
            'get': {
                'sysName': '.1.3.6.1.2.1.1.5.0',
                'domain': '.1.3.6.1.4.1.9.9.436.1.1.5.0',
                'sysName': '.1.3.6.1.2.1.1.5.0',
                'sysDescr': '.1.3.6.1.2.1.1.1.0',
                'sysLocation': '.1.3.6.1.2.1.1.6.0',
                'chassis_type': '.1.3.6.1.2.1.47.1.1.1.1.13.10',
                'snmp_chassisSWVersionSupervisorModuleOne': '.1.3.6.1.2.1.47.1.1.1.1.10.48',
                'snmp_chassisSWVersionSupervisorModuleTwo': '.1.3.6.1.2.1.47.1.1.1.1.10.49'
            },
            'walk': {
                'ifIndex': '.1.3.6.1.2.1.2.2.1.1',
                'ifDescr': '.1.3.6.1.2.1.2.2.1.2',
                'ifName': '.1.3.6.1.2.1.31.1.1.1.1',
                'ifAlias': '.1.3.6.1.2.1.31.1.1.1.18',
                'ifType': '.1.3.6.1.2.1.2.2.1.3',
                'ifMtu': '.1.3.6.1.2.1.2.2.1.4',
                'ifSpeed': '.1.3.6.1.2.1.2.2.1.5',
                'ifAdminStatus': '.1.3.6.1.2.1.2.2.1.7',
                'ifOperStatus': '.1.3.6.1.2.1.2.2.1.8',
                'dot1dBasePortIfIndex': '.1.3.6.1.2.1.17.1.4.1.2',
                'vtpVlanState': '.1.3.6.1.4.1.9.9.46.1.3.1.1.2',
                'cviRoutedVlanIfIndex': '.1.3.6.1.4.1.9.9.128.1.1.1.1.3',
                # cviVlanId, cviPhysicalifindex - The index for the ifTable entry associated with this routed VLAN interface
                'cdpInterfaceName': '.1.3.6.1.4.1.9.9.23.1.1.1.1.6',
                # The name of the local interface as advertised by CDP in the PORT TLV
                'cdpCacheDeviceId': '.1.3.6.1.4.1.9.9.23.1.2.1.1.6',
                # The Device-ID string as reported in the most recent CDP message.
                # The zero-length string indicates no Device-ID
                # field (TLV) was reported in the most recent CDP message.

                'cdpCacheDevicePort': '.1.3.6.1.4.1.9.9.23.1.2.1.1.7',
                # The Port-ID string as reported in the most recent CDP
                # message.  This will typically be the value of the ifName
                # object (e.g., 'Ethernet0').  The zero-length string
                # indicates no Port-ID field (TLV) was reported in the
                # most recent CDP message.
                'cdpCachePlatform': '.1.3.6.1.4.1.9.9.23.1.2.1.1.8',
                # The Device's Hardware Platform as reported in the most
                # recent CDP message.  The zero-length string indicates
                # that no Platform field (TLV) was reported in the most
                # recent CDP message.
                'vtpVlanName': '.1.3.6.1.4.1.9.9.46.1.3.1.1.4',
                'vtpVlanType': '.1.3.6.1.4.1.9.9.46.1.3.1.1.3',
                # Type of vlan -Syntax	 VlanType (INTEGER) {ethernet(1),
                # fddi(2),
                # tokenRing(3), fddiNet(4),
                # trNet(5), deprecated(6)
                'dot1dTpFdbPort': '.1.3.6.1.2.1.17.4.3.1.2',  # Either the value '0', or the port number of the port on
                # which a frame having a source address equal to the value
                # of the corresponding instance of dot1dTpFdbAddress has
                # been seen.  A value of '0' indicates that the port
                # number has not been learned, but that the bridge does
                # have some forwarding/filtering information about this
                # address (e.g., in the dot1dStaticTable).  Implementors
                # are encouraged to assign the port value to this object
                # whenever it is learned, even for addresses for which the
                # corresponding value of dot1dTpFdbStatus is not
                # learned(3).
                # For cisco - Filter out the first .1.3.6.1.2.1.17.4.3.1.2. then convert
                # the rest from decimal to hex
                # 'cefcFRUPowerAdminStatus': '.1.3.6.1.4.1.9.9.117.1.1.2.1.1', # Syntax	 PowerAdminType (INTEGER) {on(1), off(2), inlineAuto(3), inlineOn(4), powerCycle(5)
                # 'cefcFRUPowerOperStatus': '.1.3.6.1.4.1.9.9.117.1.1.2.1.2', # PowerOperType (INTEGER) {offEnvOther(1), on(2), offAdmin(3), offDenied(4), offEnvPower(5), offEnvTemp(6), offEnvFan(7), failed(8), onButFanFail(9), offCooling(10), offConnectorRating(11), onButInlinePowerFail(12)
                'entPhysicalDescr': '.1.3.6.1.2.1.47.1.1.1.1.2',
                # A textual description of physical entity.  This object should contain a string that identifies the manufacturer's name for the physical entity, and should be set to a distinct value for each version or model of the physical entity.
                'entPhysicalHardwareRev': '.1.3.6.1.2.1.47.1.1.1.1.8',
                'entPhysicalFirmwareRev': '.1.3.6.1.2.1.47.1.1.1.1.9',
                'entPhysicalSoftwareRev': '.1.3.6.1.2.1.47.1.1.1.1.10',
                'entPhysicalSerialNum': '.1.3.6.1.2.1.47.1.1.1.1.11',
                'entPhysicalModelName': '.1.3.6.1.2.1.47.1.1.1.1.13',
                'lldpRemChassisId': '.1.0.8802.1.1.2.1.4.1.1.5',
                # The string value used to identify the chassis component associated with the remote system
                'lldpRemPortIdSubtype': '.1.0.8802.1.1.2.1.4.1.1.6',
                # The type of port identifier encoding used in the associated 'lldpRemPortId' object
                'lldpRemPortDesc': '.1.0.8802.1.1.2.1.4.1.1.8',
                # The string value used to identify the description of the given port associated with the remote system.
                'lldpRemSysName': '.1.0.8802.1.1.2.1.4.1.1.9',
                # The string value used to identify the system name of the of the remote system.
                'lldpRemSysDesc': '.1.0.8802.1.1.2.1.4.1.1.10',
                # The string value used to identify the system description of the remote system.
                'lldpRemChassisIdSubtype': '.1.0.8802.1.1.2.1.4.1.1.4',
                # The type of encoding used to identify the chassis associated with the remote system.
                'lldpRemSysCapSupported': '.1.0.8802.1.1.2.1.4.1.1.11',
                # The bitmap value used to identify which system capabilities are supported on the remote system.
                'lldpRemSysCapEnabled': '.1.0.8802.1.1.2.1.4.1.1.12',
                # The bitmap value used to identify which system capabilities are enabled on the remote system.
                'lldpLocPortIdSubtype': '.1.0.8802.1.1.2.1.3.7.1.2',
                # The type of port identifier encoding used in the associated
                'lldpLocPortId': '.1.0.8802.1.1.2.1.3.7.1.3',
                # The string value used to identify the port component associated with a given port in the local system.
                'lldpLocPortDesc': '.1.0.8802.1.1.2.1.3.7.1.4',
                # The string value used to identify the 802 LAN station's port description associated with the local system.  If the local agent supports IETF RFC 2863, lldpLocPortDesc object should have the same value of ifDescr object
                'entPhysicalAlias': '.1.3.6.1.2.1.47.1.1.1.1.14',
                # This will alow you to reference the pyhsical entity with another associated value like the plugable information.
                # This will refer to the ifIndex as well
                'ipAdEntAddr': '.1.3.6.1.2.1.4.20.1.1',  # Returns any ip addresses configured
                'ipAdEntNetMask': '.1.3.6.1.2.1.4.20.1.3',  # Returns any ip subnet configured for the above
                'ipAdEntIfIndex': '.1.3.6.1.2.1.4.20.1.2',  # Ip address and interface index the address is tied too
            },
            'values': {
                'ifAdminStatus': {
                    '1': 'Up',
                    '2': 'Down',
                    '3': 'Testing'
                },
                'ifOperStatus': {
                    '1': 'Up',
                    '2': 'Down',
                    '3': 'Testing',
                    '4': 'Unknown',
                    '5': 'Dormant',
                    '6': 'Not Present',
                    '7': 'Lower Layer Down',
                },
                'lldpRemChassisIdSubtype': {
                    '1': 'chassisComponent',
                    '2': 'interfaceAlias',
                    '3': 'portComponent',
                    '4': 'macAddress',
                    '5': 'networkAddress',
                    '6': 'interfaceName',
                    '7': 'local'
                },
                'lldpRemPortIdSubtype': {
                    '1': 'interfaceAlias',
                    '2': 'portComponent',
                    '3': 'macAddress',
                    '4': 'networkAddress',
                    '5': 'interfaceName',
                    '6': 'agentCircuitId',
                    '7': 'local',
                },
                'lldpRemSysCapSupported': {
                    '0': 'other',
                    '1': 'repeater',
                    '2': 'bridge',
                    '3': 'wlanAccessPoint',
                    '4': 'router',
                    '5': 'telephone',
                    '6': 'docsisCableDevice',
                    '7': 'stationOnly'
                },
                'lldpRemSysCapEnabled': {
                    '0': 'other',
                    '1': 'repeater',
                    '2': 'bridge',
                    '3': 'wlanAccessPoint',
                    '4': 'router',
                    '5': 'telephone',
                    '6': 'docsisCableDevice',
                    '7': 'stationOnly'
                },
                'lldpLocPortIdSubtype': {
                    '1': 'interfaceAlias',
                    '2': 'portComponent',
                    '3': 'macAddress',
                    '4': 'networkAddress',
                    '5': 'interfaceName',
                    '6': 'agentCircuitId',
                    '7': 'local',
                },
                'vtpVlanType': {
                    '1': 'ethernet',
                    '2': 'fddi',
                    '3': 'tokenRing',
                    '4': 'fddiNet',
                    '5': 'trNet',
                    '6': 'deprecated',
                }
            }
        }
    elif device_type == "N3K-C3132Q-V":
        library = {
            'get': {
                'sysName': '.1.3.6.1.2.1.1.5.0',
                'domain': '.1.3.6.1.4.1.9.9.436.1.1.5.0',
                'sysName': '.1.3.6.1.2.1.1.5.0',
                'sysDescr': '.1.3.6.1.2.1.1.1.0',
                'sysLocation': '.1.3.6.1.2.1.1.6.0',
                'chassis_type': '.1.3.6.1.2.1.47.1.1.1.1.13.10',
                'snmp_chassisSWVersionSupervisorModuleOne': '.1.3.6.1.2.1.47.1.1.1.1.10.48',
                'snmp_chassisSWVersionSupervisorModuleTwo': '.1.3.6.1.2.1.47.1.1.1.1.10.49'
            },
            'walk': {
                'ifIndex': '.1.3.6.1.2.1.2.2.1.1',
                'ifDescr': '.1.3.6.1.2.1.2.2.1.2',
                'ifName': '.1.3.6.1.2.1.31.1.1.1.1',
                'ifAlias': '.1.3.6.1.2.1.31.1.1.1.18',
                'ifType': '.1.3.6.1.2.1.2.2.1.3',
                'ifMtu': '.1.3.6.1.2.1.2.2.1.4',
                'ifSpeed': '.1.3.6.1.2.1.2.2.1.5',
                'ifAdminStatus': '.1.3.6.1.2.1.2.2.1.7',
                'ifOperStatus': '.1.3.6.1.2.1.2.2.1.8',
                'dot1dBasePortIfIndex': '.1.3.6.1.2.1.17.1.4.1.2',
                'vtpVlanState': '.1.3.6.1.4.1.9.9.46.1.3.1.1.2',
                'cviRoutedVlanIfIndex': '.1.3.6.1.4.1.9.9.128.1.1.1.1.3',
                # cviVlanId, cviPhysicalifindex - The index for the ifTable entry associated with this routed VLAN interface
                'cdpInterfaceName': '.1.3.6.1.4.1.9.9.23.1.1.1.1.6',
                # The name of the local interface as advertised by CDP in the PORT TLV
                'cdpCacheDeviceId': '.1.3.6.1.4.1.9.9.23.1.2.1.1.6',
                # The Device-ID string as reported in the most recent CDP message.
                # The zero-length string indicates no Device-ID
                # field (TLV) was reported in the most recent CDP message.

                'cdpCacheDevicePort': '.1.3.6.1.4.1.9.9.23.1.2.1.1.7',
                # The Port-ID string as reported in the most recent CDP
                # message.  This will typically be the value of the ifName
                # object (e.g., 'Ethernet0').  The zero-length string
                # indicates no Port-ID field (TLV) was reported in the
                # most recent CDP message.
                'cdpCachePlatform': '.1.3.6.1.4.1.9.9.23.1.2.1.1.8',
                # The Device's Hardware Platform as reported in the most
                # recent CDP message.  The zero-length string indicates
                # that no Platform field (TLV) was reported in the most
                # recent CDP message.
                'vtpVlanName': '.1.3.6.1.4.1.9.9.46.1.3.1.1.4',
                'vtpVlanType': '.1.3.6.1.4.1.9.9.46.1.3.1.1.3',
                # Type of vlan -Syntax	 VlanType (INTEGER) {ethernet(1),
                # fddi(2),
                # tokenRing(3), fddiNet(4),
                # trNet(5), deprecated(6)
                'dot1dTpFdbPort': '.1.3.6.1.2.1.17.4.3.1.2',  # Either the value '0', or the port number of the port on
                # which a frame having a source address equal to the value
                # of the corresponding instance of dot1dTpFdbAddress has
                # been seen.  A value of '0' indicates that the port
                # number has not been learned, but that the bridge does
                # have some forwarding/filtering information about this
                # address (e.g., in the dot1dStaticTable).  Implementors
                # are encouraged to assign the port value to this object
                # whenever it is learned, even for addresses for which the
                # corresponding value of dot1dTpFdbStatus is not
                # learned(3).
                # For cisco - Filter out the first .1.3.6.1.2.1.17.4.3.1.2. then convert
                # the rest from decimal to hex
                # 'cefcFRUPowerAdminStatus': '.1.3.6.1.4.1.9.9.117.1.1.2.1.1', # Syntax	 PowerAdminType (INTEGER) {on(1), off(2), inlineAuto(3), inlineOn(4), powerCycle(5)
                # 'cefcFRUPowerOperStatus': '.1.3.6.1.4.1.9.9.117.1.1.2.1.2', # PowerOperType (INTEGER) {offEnvOther(1), on(2), offAdmin(3), offDenied(4), offEnvPower(5), offEnvTemp(6), offEnvFan(7), failed(8), onButFanFail(9), offCooling(10), offConnectorRating(11), onButInlinePowerFail(12)
                'entPhysicalDescr': '.1.3.6.1.2.1.47.1.1.1.1.2',
                # A textual description of physical entity.  This object should contain a string that identifies the manufacturer's name for the physical entity, and should be set to a distinct value for each version or model of the physical entity.
                'entPhysicalHardwareRev': '.1.3.6.1.2.1.47.1.1.1.1.8',
                'entPhysicalFirmwareRev': '.1.3.6.1.2.1.47.1.1.1.1.9',
                'entPhysicalSoftwareRev': '.1.3.6.1.2.1.47.1.1.1.1.10',
                'entPhysicalSerialNum': '.1.3.6.1.2.1.47.1.1.1.1.11',
                'entPhysicalModelName': '.1.3.6.1.2.1.47.1.1.1.1.13',
                'lldpRemChassisId': '.1.0.8802.1.1.2.1.4.1.1.5',
                # The string value used to identify the chassis component associated with the remote system
                'lldpRemPortIdSubtype': '.1.0.8802.1.1.2.1.4.1.1.6',
                # The type of port identifier encoding used in the associated 'lldpRemPortId' object
                'lldpRemPortDesc': '.1.0.8802.1.1.2.1.4.1.1.8',
                # The string value used to identify the description of the given port associated with the remote system.
                'lldpRemSysName': '.1.0.8802.1.1.2.1.4.1.1.9',
                # The string value used to identify the system name of the of the remote system.
                'lldpRemSysDesc': '.1.0.8802.1.1.2.1.4.1.1.10',
                # The string value used to identify the system description of the remote system.
                'lldpRemChassisIdSubtype': '.1.0.8802.1.1.2.1.4.1.1.4',
                # The type of encoding used to identify the chassis associated with the remote system.
                'lldpRemSysCapSupported': '.1.0.8802.1.1.2.1.4.1.1.11',
                # The bitmap value used to identify which system capabilities are supported on the remote system.
                'lldpRemSysCapEnabled': '.1.0.8802.1.1.2.1.4.1.1.12',
                # The bitmap value used to identify which system capabilities are enabled on the remote system.
                'lldpLocPortIdSubtype': '.1.0.8802.1.1.2.1.3.7.1.2',
                # The type of port identifier encoding used in the associated
                'lldpLocPortId': '.1.0.8802.1.1.2.1.3.7.1.3',
                # The string value used to identify the port component associated with a given port in the local system.
                'lldpLocPortDesc': '.1.0.8802.1.1.2.1.3.7.1.4',
                # The string value used to identify the 802 LAN station's port description associated with the local system.  If the local agent supports IETF RFC 2863, lldpLocPortDesc object should have the same value of ifDescr object
                'entPhysicalAlias': '.1.3.6.1.2.1.47.1.1.1.1.14',
                # This will alow you to reference the pyhsical entity with another associated value like the plugable information.
                # This will refer to the ifIndex as well
                'ipAdEntAddr': '.1.3.6.1.2.1.4.20.1.1',  # Returns any ip addresses configured
                'ipAdEntNetMask': '.1.3.6.1.2.1.4.20.1.3',  # Returns any ip subnet configured for the above
                'ipAdEntIfIndex': '.1.3.6.1.2.1.4.20.1.2',  # Ip address and interface index the address is tied too
            },
            'values': {
                'ifAdminStatus': {
                    '1': 'Up',
                    '2': 'Down',
                    '3': 'Testing'
                },
                'ifOperStatus': {
                    '1': 'Up',
                    '2': 'Down',
                    '3': 'Testing',
                    '4': 'Unknown',
                    '5': 'Dormant',
                    '6': 'Not Present',
                    '7': 'Lower Layer Down',
                },
                'lldpRemChassisIdSubtype': {
                    '1': 'chassisComponent',
                    '2': 'interfaceAlias',
                    '3': 'portComponent',
                    '4': 'macAddress',
                    '5': 'networkAddress',
                    '6': 'interfaceName',
                    '7': 'local'
                },
                'lldpRemPortIdSubtype': {
                    '1': 'interfaceAlias',
                    '2': 'portComponent',
                    '3': 'macAddress',
                    '4': 'networkAddress',
                    '5': 'interfaceName',
                    '6': 'agentCircuitId',
                    '7': 'local',
                },
                'lldpRemSysCapSupported': {
                    '0': 'other',
                    '1': 'repeater',
                    '2': 'bridge',
                    '3': 'wlanAccessPoint',
                    '4': 'router',
                    '5': 'telephone',
                    '6': 'docsisCableDevice',
                    '7': 'stationOnly'
                },
                'lldpRemSysCapEnabled': {
                    '0': 'other',
                    '1': 'repeater',
                    '2': 'bridge',
                    '3': 'wlanAccessPoint',
                    '4': 'router',
                    '5': 'telephone',
                    '6': 'docsisCableDevice',
                    '7': 'stationOnly'
                },
                'lldpLocPortIdSubtype': {
                    '1': 'interfaceAlias',
                    '2': 'portComponent',
                    '3': 'macAddress',
                    '4': 'networkAddress',
                    '5': 'interfaceName',
                    '6': 'agentCircuitId',
                    '7': 'local',
                },
                'vtpVlanType': {
                    '1': 'ethernet',
                    '2': 'fddi',
                    '3': 'tokenRing',
                    '4': 'fddiNet',
                    '5': 'trNet',
                    '6': 'deprecated',
                }
            }
        }
    elif device_type == "ARISTA":
        library = {
            'get': {
                'sysName': '.1.3.6.1.2.1.1.5.0',
                'domain': '.1.3.6.1.4.1.9.9.436.1.1.5.0',
                'sysName': '.1.3.6.1.2.1.1.5.0',
                'sysDescr': '.1.3.6.1.2.1.1.1.0',
                'sysLocation': '.1.3.6.1.2.1.1.6.0',
                'chassis_type': '.1.3.6.1.2.1.47.1.1.1.1.13'
            },
            'walk': {
                'ifIndex': '.1.3.6.1.2.1.2.2.1.1',
                'ifDescr': '.1.3.6.1.2.1.2.2.1.2',
                'ifName': '.1.3.6.1.2.1.31.1.1.1.1',
                'ifAlias': '.1.3.6.1.2.1.31.1.1.1.18',
                'ifType': '.1.3.6.1.2.1.2.2.1.3',
                'ifMtu': '.1.3.6.1.2.1.2.2.1.4',
                'ifSpeed': '.1.3.6.1.2.1.2.2.1.5',
                'ifAdminStatus': '.1.3.6.1.2.1.2.2.1.7',
                'ifOperStatus': '.1.3.6.1.2.1.2.2.1.8',
                'entPhysicalHardwareRev': '.1.3.6.1.2.1.47.1.1.1.1.8',
                'entPhysicalFirmwareRev': '.1.3.6.1.2.1.47.1.1.1.1.9',
                'entPhysicalSoftwareRev': '.1.3.6.1.2.1.47.1.1.1.1.10',
                'entPhysicalModelName': '.1.3.6.1.2.1.47.1.1.1.1.13',
                'entPhysicalSerialNum': '.1.3.6.1.2.1.47.1.1.1.1.11',
            },
            'values': {
                'ifAdminStatus': {
                    '1': 'Up',
                    '2': 'Down',
                    '3': 'Testing'
                },
                'ifOperStatus': {
                    '1': 'Up',
                    '2': 'Down',
                    '3': 'Testing',
                    '4': 'Unknown',
                    '5': 'Dormant',
                    '6': 'Not Present',
                    '7': 'Lower Layer Down',
                },
                'lldpRemChassisIdSubtype': {
                    '1': 'chassisComponent',
                    '2': 'interfaceAlias',
                    '3': 'portComponent',
                    '4': 'macAddress',
                    '5': 'networkAddress',
                    '6': 'interfaceName',
                    '7': 'local'
                },
                'lldpRemPortIdSubtype': {
                    '1': 'interfaceAlias',
                    '2': 'portComponent',
                    '3': 'macAddress',
                    '4': 'networkAddress',
                    '5': 'interfaceName',
                    '6': 'agentCircuitId',
                    '7': 'local',
                },
                'lldpRemSysCapSupported': {
                    '0': 'other',
                    '1': 'repeater',
                    '2': 'bridge',
                    '3': 'wlanAccessPoint',
                    '4': 'router',
                    '5': 'telephone',
                    '6': 'docsisCableDevice',
                    '7': 'stationOnly'
                },
                'lldpRemSysCapEnabled': {
                    '0': 'other',
                    '1': 'repeater',
                    '2': 'bridge',
                    '3': 'wlanAccessPoint',
                    '4': 'router',
                    '5': 'telephone',
                    '6': 'docsisCableDevice',
                    '7': 'stationOnly'
                },
                'lldpLocPortIdSubtype': {
                    '1': 'interfaceAlias',
                    '2': 'portComponent',
                    '3': 'macAddress',
                    '4': 'networkAddress',
                    '5': 'interfaceName',
                    '6': 'agentCircuitId',
                    '7': 'local',
                },
                'vtpVlanType': {
                    '1': 'ethernet',
                    '2': 'fddi',
                    '3': 'tokenRing',
                    '4': 'fddiNet',
                    '5': 'trNet',
                    '6': 'deprecated',
                }
            }
        }
    elif device_type == "GENERIC_NXOS":
        library = {
            'get': {
                'sysName': '.1.3.6.1.2.1.1.5.0',
                'domain': '.1.3.6.1.4.1.9.9.436.1.1.5.0',
                'sysName': '.1.3.6.1.2.1.1.5.0',
                'sysDescr': '.1.3.6.1.2.1.1.1.0',
                'sysLocation': '.1.3.6.1.2.1.1.6.0',
                'chassis_type': '.1.3.6.1.2.1.47.1.1.1.1.13.10',
                'snmp_chassisSWVersionSupervisorModuleOne': '.1.3.6.1.2.1.47.1.1.1.1.10.48',
                'snmp_chassisSWVersionSupervisorModuleTwo': '.1.3.6.1.2.1.47.1.1.1.1.10.49'
            },
            'walk': {
                'ifIndex': '.1.3.6.1.2.1.2.2.1.1',
                'ifDescr': '.1.3.6.1.2.1.2.2.1.2',
                'ifName': '.1.3.6.1.2.1.31.1.1.1.1',
                'ifAlias': '.1.3.6.1.2.1.31.1.1.1.18',
                'ifType': '.1.3.6.1.2.1.2.2.1.3',
                'ifMtu': '.1.3.6.1.2.1.2.2.1.4',
                'ifSpeed': '.1.3.6.1.2.1.2.2.1.5',
                'ifAdminStatus': '.1.3.6.1.2.1.2.2.1.7',
                'ifOperStatus': '.1.3.6.1.2.1.2.2.1.8',
                'dot1dBasePortIfIndex': '.1.3.6.1.2.1.17.1.4.1.2',
                'vtpVlanState': '.1.3.6.1.4.1.9.9.46.1.3.1.1.2',
                'cviRoutedVlanIfIndex': '.1.3.6.1.4.1.9.9.128.1.1.1.1.3',
                # cviVlanId, cviPhysicalifindex - The index for the ifTable entry associated with this routed VLAN interface
                'cdpInterfaceName': '.1.3.6.1.4.1.9.9.23.1.1.1.1.6',
                # The name of the local interface as advertised by CDP in the PORT TLV
                'cdpCacheDeviceId': '.1.3.6.1.4.1.9.9.23.1.2.1.1.6',
                # The Device-ID string as reported in the most recent CDP message.
                # The zero-length string indicates no Device-ID
                # field (TLV) was reported in the most recent CDP message.

                'cdpCacheDevicePort': '.1.3.6.1.4.1.9.9.23.1.2.1.1.7',
                # The Port-ID string as reported in the most recent CDP
                # message.  This will typically be the value of the ifName
                # object (e.g., 'Ethernet0').  The zero-length string
                # indicates no Port-ID field (TLV) was reported in the
                # most recent CDP message.
                'cdpCachePlatform': '.1.3.6.1.4.1.9.9.23.1.2.1.1.8',
                # The Device's Hardware Platform as reported in the most
                # recent CDP message.  The zero-length string indicates
                # that no Platform field (TLV) was reported in the most
                # recent CDP message.
                'vtpVlanName': '.1.3.6.1.4.1.9.9.46.1.3.1.1.4',
                'vtpVlanType': '.1.3.6.1.4.1.9.9.46.1.3.1.1.3',
                # Type of vlan -Syntax	 VlanType (INTEGER) {ethernet(1),
                # fddi(2),
                # tokenRing(3), fddiNet(4),
                # trNet(5), deprecated(6)
                'dot1dTpFdbPort': '.1.3.6.1.2.1.17.4.3.1.2',  # Either the value '0', or the port number of the port on
                # which a frame having a source address equal to the value
                # of the corresponding instance of dot1dTpFdbAddress has
                # been seen.  A value of '0' indicates that the port
                # number has not been learned, but that the bridge does
                # have some forwarding/filtering information about this
                # address (e.g., in the dot1dStaticTable).  Implementors
                # are encouraged to assign the port value to this object
                # whenever it is learned, even for addresses for which the
                # corresponding value of dot1dTpFdbStatus is not
                # learned(3).
                # For cisco - Filter out the first .1.3.6.1.2.1.17.4.3.1.2. then convert
                # the rest from decimal to hex
                # 'cefcFRUPowerAdminStatus': '.1.3.6.1.4.1.9.9.117.1.1.2.1.1', # Syntax	 PowerAdminType (INTEGER) {on(1), off(2), inlineAuto(3), inlineOn(4), powerCycle(5)
                # 'cefcFRUPowerOperStatus': '.1.3.6.1.4.1.9.9.117.1.1.2.1.2', # PowerOperType (INTEGER) {offEnvOther(1), on(2), offAdmin(3), offDenied(4), offEnvPower(5), offEnvTemp(6), offEnvFan(7), failed(8), onButFanFail(9), offCooling(10), offConnectorRating(11), onButInlinePowerFail(12)
                'entPhysicalDescr': '.1.3.6.1.2.1.47.1.1.1.1.2',
                # A textual description of physical entity.  This object should contain a string that identifies the manufacturer's name for the physical entity, and should be set to a distinct value for each version or model of the physical entity.
                'entPhysicalHardwareRev': '.1.3.6.1.2.1.47.1.1.1.1.8',
                'entPhysicalFirmwareRev': '.1.3.6.1.2.1.47.1.1.1.1.9',
                'entPhysicalSoftwareRev': '.1.3.6.1.2.1.47.1.1.1.1.10',
                'entPhysicalSerialNum': '.1.3.6.1.2.1.47.1.1.1.1.11',
                'entPhysicalModelName': '.1.3.6.1.2.1.47.1.1.1.1.13',
                'lldpRemChassisId': '.1.0.8802.1.1.2.1.4.1.1.5',
                # The string value used to identify the chassis component associated with the remote system
                'lldpRemPortIdSubtype': '.1.0.8802.1.1.2.1.4.1.1.6',
                # The type of port identifier encoding used in the associated 'lldpRemPortId' object
                'lldpRemPortDesc': '.1.0.8802.1.1.2.1.4.1.1.8',
                # The string value used to identify the description of the given port associated with the remote system.
                'lldpRemSysName': '.1.0.8802.1.1.2.1.4.1.1.9',
                # The string value used to identify the system name of the of the remote system.
                'lldpRemSysDesc': '.1.0.8802.1.1.2.1.4.1.1.10',
                # The string value used to identify the system description of the remote system.
                'lldpRemChassisIdSubtype': '.1.0.8802.1.1.2.1.4.1.1.4',
                # The type of encoding used to identify the chassis associated with the remote system.
                'lldpRemSysCapSupported': '.1.0.8802.1.1.2.1.4.1.1.11',
                # The bitmap value used to identify which system capabilities are supported on the remote system.
                'lldpRemSysCapEnabled': '.1.0.8802.1.1.2.1.4.1.1.12',
                # The bitmap value used to identify which system capabilities are enabled on the remote system.
                'lldpLocPortIdSubtype': '.1.0.8802.1.1.2.1.3.7.1.2',
                # The type of port identifier encoding used in the associated
                'lldpLocPortId': '.1.0.8802.1.1.2.1.3.7.1.3',
                # The string value used to identify the port component associated with a given port in the local system.
                'lldpLocPortDesc': '.1.0.8802.1.1.2.1.3.7.1.4',
                # The string value used to identify the 802 LAN station's port description associated with the local system.  If the local agent supports IETF RFC 2863, lldpLocPortDesc object should have the same value of ifDescr object
                'entPhysicalAlias': '.1.3.6.1.2.1.47.1.1.1.1.14',
                # This will alow you to reference the pyhsical entity with another associated value like the plugable information.
                # This will refer to the ifIndex as well
                'ipAdEntAddr': '.1.3.6.1.2.1.4.20.1.1',  # Returns any ip addresses configured
                'ipAdEntNetMask': '.1.3.6.1.2.1.4.20.1.3',  # Returns any ip subnet configured for the above
                'ipAdEntIfIndex': '.1.3.6.1.2.1.4.20.1.2',  # Ip address and interface index the address is tied too
            },
            'values': {
                'ifAdminStatus': {
                    '1': 'Up',
                    '2': 'Down',
                    '3': 'Testing'
                },
                'ifOperStatus': {
                    '1': 'Up',
                    '2': 'Down',
                    '3': 'Testing',
                    '4': 'Unknown',
                    '5': 'Dormant',
                    '6': 'Not Present',
                    '7': 'Lower Layer Down',
                },
                'lldpRemChassisIdSubtype': {
                    '1': 'chassisComponent',
                    '2': 'interfaceAlias',
                    '3': 'portComponent',
                    '4': 'macAddress',
                    '5': 'networkAddress',
                    '6': 'interfaceName',
                    '7': 'local'
                },
                'lldpRemPortIdSubtype': {
                    '1': 'interfaceAlias',
                    '2': 'portComponent',
                    '3': 'macAddress',
                    '4': 'networkAddress',
                    '5': 'interfaceName',
                    '6': 'agentCircuitId',
                    '7': 'local',
                },
                'lldpRemSysCapSupported': {
                    '0': 'other',
                    '1': 'repeater',
                    '2': 'bridge',
                    '3': 'wlanAccessPoint',
                    '4': 'router',
                    '5': 'telephone',
                    '6': 'docsisCableDevice',
                    '7': 'stationOnly'
                },
                'lldpRemSysCapEnabled': {
                    '0': 'other',
                    '1': 'repeater',
                    '2': 'bridge',
                    '3': 'wlanAccessPoint',
                    '4': 'router',
                    '5': 'telephone',
                    '6': 'docsisCableDevice',
                    '7': 'stationOnly'
                },
                'lldpLocPortIdSubtype': {
                    '1': 'interfaceAlias',
                    '2': 'portComponent',
                    '3': 'macAddress',
                    '4': 'networkAddress',
                    '5': 'interfaceName',
                    '6': 'agentCircuitId',
                    '7': 'local',
                },
                'vtpVlanType': {
                    '1': 'ethernet',
                    '2': 'fddi',
                    '3': 'tokenRing',
                    '4': 'fddiNet',
                    '5': 'trNet',
                    '6': 'deprecated',
                }
            }
        }
    else:
        """
        Get the device type for any unknown devices and store them in the database to get
        back to them later.
        """
        library = {
            'get': {
                'sysName': '.1.3.6.1.2.1.1.5.0',
                'sysLocation': '.1.3.6.1.2.1.1.6.0',
                'sysDescr': '.1.3.6.1.2.1.1.1.0'
            }
        }

    return library

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


def extract_snmp_value(poller_data: dict,
                        setting: dict,
                        error_msg: str) -> str:
    """
    Given the poller_data dict and a setting dict like
      {'mib': 'entPhysicalSoftwareRev', 'oid': '.1.3.…'},
    attempt to pull out poller_data[mib][oid].  On any failure, return error_msg.
    """
    # 1) get mib & oid
    mib = setting.get("mib")
    oid = setting.get("oid")
    if not mib or not oid:
        return error_msg

    # 2) fetch the raw blob
    blob = poller_data.get(mib)

    if blob is None:
        return error_msg

    try:
        # 3) if it's a JSON string, parse it
        if isinstance(blob, str):
            blob = json.loads(blob)

        # 4) ensure it's a dict
        if not isinstance(blob, dict):
            return error_msg

        # 5) pull the OID value (could be empty)
        value = blob.get(oid, "")
        return value or error_msg

    except (json.JSONDecodeError, TypeError, ValueError):
        return error_msg
    except Exception:
        return error_msg

def cast(value: Any) -> Any:
    """
    Given a pysnmp value object (or any other value), return a plain‐Python value:
      • SnmpEngineID → hex string
      • IpAddress     → dotted‐quad string
      • Any object that implements __bytes__ (OctetString, Counter64, etc.) →
          bytes(value) → decode as UTF-8 (fallback Latin-1) → replace CR/LF with space → strip →
          int/float if numeric → else decoded text
      • Otherwise, str(value) → replace CR/LF with space → strip → int/float if numeric → else string
    """
    cls = value.__class__.__name__

    # 1) SnmpEngineID → hexlify
    if cls == "SnmpEngineID":
        return binascii.hexlify(bytes(value)).decode("utf-8")

    # 2) IpAddress → dotted‐quad
    if cls == "IpAddress":
        hex_str = binascii.hexlify(bytes(value)).decode("utf-8")
        return str(ipaddress.ip_address(int(hex_str, 16)))

    # 3) If it implements __bytes__ (OctetString, Counter64, Gauge32, etc.)
    if not isinstance(value, (str, int, float, bool)) and hasattr(value, "__bytes__"):
        raw = bytes(value)  # get raw bytes
        if len(raw) == 0:
            return ""

        # Attempt UTF-8 decode, fallback to Latin-1 if needed
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = raw.decode("latin-1", errors="ignore")

        # Replace any CR/LF or LF with a single space, then strip
        text = text.replace("\r\n", " ").replace("\n", " ").strip()
        if not text:
            return ""

        # If the decoded text is an integer literal
        if re.fullmatch(r"-?\d+", text):
            return int(text)

        # If it’s a float literal
        try:
            return float(text)
        except ValueError:
            pass

        # Otherwise return the decoded string
        return text

    # 4) Otherwise, treat it as a primitive (e.g. pysnmp.Integer or a simple string/number)
    s = str(value)
    # Replace any CR/LF or LF with a single space, then strip
    s = s.replace("\r\n", " ").replace("\n", " ").strip()
    if not s:
        return ""

    # Try to coerce to int
    if re.fullmatch(r"-?\d+", s):
        return int(s)

    # Try to coerce to float
    try:
        return float(s)
    except ValueError:
        pass

    # Fallback: return as string
    return s





if __name__ == '__main__':
    # Use the below if you wish to test each snmp function. Replace with your own credentials
    snmp_v2 = {"string": ["public", "private"]}

    snmp_v3 = {
        "snmp_v3_profile_two": {
            "UsmUserData_username": "SNMPV3UserNetworking",
            "UsmUserData_password": "SNMPV3AuthSHANetworking",
            "authProtocol": "(1, 3, 6, 1, 6, 3, 10, 1, 1, 3)",
            "privProtocol": "(1, 3, 6, 1, 6, 3, 10, 1, 2, 4)",
            "private_key": "SNMPV3aes128Networking",
        },
    }

    #print(asyncio.run(snmp_get_one_auto(
    #    target="10.0.0.101",
    #    oid=".1.3.6.1.2.1.1.1.0",
    #    snmp_v2=snmp_v2,
    #    snmp_v3=snmp_v3,
    #    prefer="v3_then_v2",
    #    #prefer="v3_then_v2",
    #)))

    res = asyncio.run(get_bulk_vlan_mac_table_cisco_auto(
        vlan_id=10,
        host="10.0.0.101",
        oid="1.3.6.1.2.1.17.4.3.1.2",
        snmp_v3=snmp_v3,
        prefer="v3_then_v2",
        timeout=1,
        retries=5,
    ))
    print(res)

