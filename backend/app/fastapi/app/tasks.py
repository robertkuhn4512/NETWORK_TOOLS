"""
Notes
-----
How to run (worker):
  celery -A app.celery_app:celery_app worker -l INFO

Purpose:
- Celery tasks for Network Tools, including device discovery offloads.

TODO : Setup to give this a larger subnet 10.0.0.0/24 for example, and have it save all the jobs for it
and execute 1 by 1 for each ip.
"""

from __future__ import annotations
from pathlib import Path
import os
import re
import asyncio
import json
import logging
import time
import traceback
from typing import Any, Dict
from datetime import datetime
from fastapi import HTTPException

from starlette.status import (
    HTTP_400_BAD_REQUEST,
    HTTP_403_FORBIDDEN,
    HTTP_404_NOT_FOUND,
    HTTP_413_REQUEST_ENTITY_TOO_LARGE,
    HTTP_500_INTERNAL_SERVER_ERROR,
)

from app.celery_app import celery_app
from app.database import database, connect_db, disconnect_db

from app.shared_functions.helpers.helpers_logging_config import load_env_from_vault_json, setup_logging

from app.database_queries.postgres_insert_queries import (
    insert_app_backend_tracking,
    insert_device_backup_location,
    upsert_device_with_archive,
    upsert_app_tracking_celery_job,
    upsert_jobs_tracking_information
)

from app.database_queries.postgres_select_queries import (
    select_latest_device_backup_location_for_ipv4,
    select_device_backup_locations_for_ipv4,
)

from app.shared_functions.helpers.helpers_sanitation import scrub_secrets

from app.shared_functions.helpers.helpers_configuration_backups import (
    save_device_backup_text,
    gzip_file_verified
)

from app.shared_functions.helpers.helpers_file_encryption import (
    encrypt_backup_gz_to_enc,
    read_backup_enc_gz_text
)

from app.shared_functions.helpers.helpers_netmiko import (
    ssh_session,
    netmiko_autodiscover,
    netmiko_fetch_command_output
)

from app.shared_functions.helpers.helpers_cisco import (
    cisco_hostname,
    cisco_allowed_commands,
    cisco_extract_show_version_fields,
    cisco_parse_show_interface_description_auto,
    cisco_parse_show_cdp_neighbors_auto,
    cisco_parse_show_lldp_neighbors_auto,
    cisco_parse_show_mac_address_table_auto,
    cisco_parse_show_ip_arp_table_auto,
    cisco_parse_show_version_auto,
    cisco_parse_show_mac_address_table_count_auto
)

from app.shared_functions.helpers.helpers_generic import (
    pretty_json_any,
    env_bool_if_set
)

from app.shared_functions.helpers.helpers_hashicorp_vault import (
    vault_kv2_read,
    vault_kv2_read_all_under_prefix
)

from app.network_utilities.icmp_check import pingOk

load_env_from_vault_json(os.getenv("VAULT_SECRETS_JSON", "/run/vault/fastapi_secrets.json"))

setup_logging()

logger = logging.getLogger("app.celery.tasks")


def _run_async(coro):
    try:
        return asyncio.run(coro)
    except RuntimeError:
        loop = asyncio.get_event_loop()
        return loop.run_until_complete(coro)

def _get_cmd_output(outputs: Any, cmd: Optional[str]) -> Optional[Any]:
    """
    Netmiko output dict keys are not always identical to the command string
    (e.g. pipe modifiers removed). This helper tries reasonable fallbacks.
    """
    if not isinstance(outputs, dict) or not cmd:
        return None

    if cmd in outputs:
        return outputs[cmd]

    cmd_norm = " ".join(cmd.split())
    if cmd_norm in outputs:
        return outputs[cmd_norm]

    # Strip pipe modifiers: "show version | json-pretty" -> "show version"
    base = cmd.split("|", 1)[0].strip()
    if base in outputs:
        return outputs[base]

    base_norm = " ".join(base.split())
    if base_norm in outputs:
        return outputs[base_norm]

    return None

async def _update_job(
    *,
    database=database,
    job_id: str,
    celery_task_id: str | None = None,
    job_name: str | None = None,
    status: str = "PENDING",
    route: str | None = None,
    meta: dict | None = None,
    **legacy,
) -> None:
    """
    Canonical Celery job tracking update for **app_tracking_celery**.

    Backward-compatible with older call sites that used:
      started/completed/duration_ms/worker_hostname/result/task_id
    """
    job_id_norm = (str(job_id).strip() if job_id is not None else "")
    if not job_id_norm:
        return

    celery_task_id_norm = (
        (str(celery_task_id).strip() if celery_task_id is not None else "")
        or (str(legacy.get("task_id")).strip() if legacy.get("task_id") else "")
        or job_id_norm
    )

    meta_out = dict(meta or {})

    job_name_norm = (
            (str(job_name).strip() if job_name else "")
            or (str(meta_out.get("job_name")).strip() if meta_out.get("job_name") else "")
            or (str(legacy.get("job_name")).strip() if legacy.get("job_name") else "")
            or "unknown_job"
    )

    dedupe_key_norm = (
            (str(meta_out.get("dedupe_key")).strip() if meta_out.get("dedupe_key") else "")
            or (str(legacy.get("dedupe_key")).strip() if legacy.get("dedupe_key") else "")
            or job_id_norm
    )

    res = await upsert_app_tracking_celery_job(
        database=database,
        job_id=job_id_norm,
        task_id=celery_task_id_norm,
        job_name=job_name_norm,
        dedupe_key=dedupe_key_norm,
        status=status,
        route=route,
    )

    if isinstance(res, dict) and res.get("error"):
        await insert_app_backend_tracking(
            database=database,
            route=(route or "internal/_update_job"),
            information={
                "event": "job_tracking_update_failed",
                "job_id": job_id_norm,
                "celery_task_id": celery_task_id_norm,
                "status": status,
                "error": res.get("detail", res.get("error")),
            },
        )

def _is_path_within_base(*, candidate: Path, base: Path) -> bool:
    try:
        base_r = base.resolve()
        cand_r = candidate.resolve()
        return cand_r == base_r or str(cand_r).startswith(str(base_r) + os.sep)
    except Exception:
        return False

def _safe_read_plain_text(path: Path, *, max_bytes: int) -> dict:
    try:
        # NOTE: limit raw reads too
        data = path.read_bytes()
        if max_bytes and max_bytes > 0 and len(data) > max_bytes:
            return {"error": "file_too_large", "bytes": len(data), "max_bytes": max_bytes}
        try:
            return {"ok": True, "content": data.decode("utf-8", errors="replace")}
        except Exception:
            return {"ok": True, "content": data.decode(errors="replace")}
    except Exception as e:
        return {"error": f"read_failed: {e}"}

def _search_text(
    *,
    text: str,
    query: str,
    mode: str,
    ignore_case: bool,
    regex_multiline: bool,
    context_lines: int,
    max_matches_per_file: int,
    remaining_budget: int,
    redact_output: bool,
) -> dict:
    query = (query or "")
    if not query:
        return {"ok": False, "error": "search_query_empty"}

    mode = (mode or "string").strip().lower()
    ignore_case = bool(ignore_case)
    regex_multiline = bool(regex_multiline)
    context_lines = max(0, int(context_lines or 0))
    max_matches_per_file = max(1, int(max_matches_per_file or 200))

    matches: list[dict] = []
    lines = text.splitlines()

    if mode == "string":
        needle = query.lower() if ignore_case else query
        for idx, line in enumerate(lines, start=1):
            hay = line.lower() if ignore_case else line
            if needle in hay:
                if len(matches) >= max_matches_per_file or len(matches) >= remaining_budget:
                    break
                if redact_output:
                    matches.append({"line_no": idx})
                else:
                    ctx_start = max(0, (idx - 1) - context_lines)
                    ctx_end = min(len(lines), (idx - 1) + context_lines + 1)
                    matches.append(
                        {
                            "line_no": idx,
                            "line": line,
                            "context": lines[ctx_start:ctx_end] if context_lines else None,
                        }
                    )
        return {"ok": True, "mode": "string", "matches": matches}

    if mode == "regex":
        flags = re.MULTILINE
        if ignore_case:
            flags |= re.IGNORECASE

        try:
            rx = re.compile(query, flags | (re.DOTALL if regex_multiline else 0))
        except Exception as e:
            return {"ok": False, "error": f"invalid_regex: {e}"}

        if regex_multiline:
            # Whole-text regex finditer; return offsets + line number
            for m in rx.finditer(text):
                if len(matches) >= max_matches_per_file or len(matches) >= remaining_budget:
                    break
                start = m.start()
                line_no = text.count("\n", 0, start) + 1
                if redact_output:
                    matches.append({"line_no": line_no, "start": start, "end": m.end()})
                else:
                    snippet = m.group(0)
                    if len(snippet) > 800:
                        snippet = snippet[:800] + "…"
                    matches.append({"line_no": line_no, "start": start, "end": m.end(), "match": snippet})
            return {"ok": True, "mode": "regex_multiline", "matches": matches}

        # Line-by-line regex search
        for idx, line in enumerate(lines, start=1):
            if rx.search(line):
                if len(matches) >= max_matches_per_file or len(matches) >= remaining_budget:
                    break
                if redact_output:
                    matches.append({"line_no": idx})
                else:
                    ctx_start = max(0, (idx - 1) - context_lines)
                    ctx_end = min(len(lines), (idx - 1) + context_lines + 1)
                    matches.append(
                        {
                            "line_no": idx,
                            "line": line,
                            "context": lines[ctx_start:ctx_end] if context_lines else None,
                        }
                    )
        return {"ok": True, "mode": "regex", "matches": matches}

    return {"ok": False, "error": f"invalid_mode: {mode}"}

@celery_app.task(name="device_discovery.start_device_discovery", bind=True)
def device_discovery_start_device_discovery(self, meta: Dict[str, Any]) -> Dict[str, Any]:
    """
    meta must include:
      - job_id
      - target_ip
      - requested_by
      - route (optional)
    """
    t0 = time.perf_counter()
    task_id = getattr(self.request, "id", None)
    worker_hostname = getattr(self.request, "hostname", None)
    async def _run():
        await connect_db()
        try:
            job_id = str(meta.get("job_id", "")).strip()
            target_ip = str(meta.get("target_ip", "")).strip()
            route = str(meta.get("route") or "/device_discovery/start_device_discovery")

            if not job_id or not target_ip:
                err = {"error": "missing_required_meta", "job_id": job_id, "target_ip": target_ip}
                logger.error("icmp_ping bad meta: %s", err)
                return err

            # mark STARTED

            await _update_job(
                job_id=job_id,
                status="STARTED",
                started=True,
                worker_hostname=worker_hostname,
                task_id=task_id
            )

            # run ICMP check (async helper)
            # Only if bypass_icmp is false
            # bypass_icmp = true means attempt ssh if the device is pingable. false means try anyways

            fetch_bypass_icmp = meta['payload'].get("bypass_icmp", None)

            # If able to fetch the bypass_icmp flag and it is not true
            # Then the device will get an icmp test

            if fetch_bypass_icmp is not None and not meta['payload'].get("bypass_icmp"):
                ok = bool(await pingOk(target_ip))
            else:
                # Bypass the icmp test
                ok = False

            ms = int((time.perf_counter() - t0) * 1000)

            # Start SSH Discovery
            # If icmp_bypass == false and ok == true
            # or icmp_bypass == true

            device_profiles_raw = await vault_kv2_read(mount="app_network_tools_secrets", secret_path="device_login_profiles")
            device_profiles_error = device_profiles_raw.get("error", False)

            device_profiles: dict[str, dict] = {}
            if not device_profiles_error and isinstance(device_profiles_raw, dict):
                for name, val in device_profiles_raw.items():
                    if isinstance(val, dict):
                        device_profiles[name] = val
                    elif isinstance(val, str):
                        try:
                            parsed = json.loads(val)
                            if isinstance(parsed, dict):
                                device_profiles[name] = parsed
                        except Exception:
                            pass


            """
            Check to see if vault returned any errors. 
            If no errors device_profiles_error is None
            """

            # device_profiles is whatever vault_kv2_read returned (dict)
            device_profiles_error = (device_profiles or {}).get("error", False)

            # Treat "empty dict" as an error message (but don't overwrite a real error)
            device_profiles_error_out = device_profiles_error
            if not device_profiles_error_out and isinstance(device_profiles, dict) and not device_profiles:
                device_profiles_error_out = "Unable to fetch device profiles"

            result = {
                "ping_ok": ok,
                "target_ip": target_ip,
                "job_id": job_id,
                "celery_task_id": task_id,
                "requested_by": meta.get("requested_by"),
                "azp": meta.get("azp"),
                "roles": meta.get("roles") or [],
                "device_profiles_error": device_profiles_error_out,
                "device_profiles": scrub_secrets(pretty_json_any(device_profiles)),
            }

            await insert_app_backend_tracking(
                database=database,
                route=route,
                information={
                    "event": "icmp_ping_complete",
                    "result": scrub_secrets(result),
                    "meta": scrub_secrets(meta),
                },
            )

            # If no errors from vault but there were no credentials returned (Empty dict)
            # The discovery will fail

            if not device_profiles_error and not device_profiles:

                await _update_job(
                    job_id=job_id,
                    status="FAILURE",
                    completed=True,
                    duration_ms=ms,
                    worker_hostname=worker_hostname,
                    result=result,
                    task_id=task_id
                )

            elif not device_profiles_error and device_profiles:
                # If no errors from vault and there are profiles returned from vault attempt to do the targeted discovery

                task = meta['payload'].get("task", None)
                target_ip = meta.get("target_ip", None)

                await insert_app_backend_tracking(
                    database=database,
                    route=route,
                    information={
                        "event": "device_discovery.start_device_discovery.starting_ssh",
                        "result": scrub_secrets(result),
                        "meta": scrub_secrets(meta),
                        "task": task,
                        "target_ip": target_ip,
                    },
                )

                if task is not None:
                    if task == 'ssh':
                        # Attempt SSH discovery with all the profiles found in vault
                        for profile_name, p in (device_profiles or {}).items():

                            if not isinstance(p, dict):
                                continue

                            await insert_app_backend_tracking(
                                database=database,
                                route=route,
                                information={
                                    "event": "device_discovery.start_device_discovery.starting_ssh",
                                    "result": scrub_secrets(result),
                                    "meta": scrub_secrets(meta),
                                    "device_profile_tried": {profile_name: scrub_secrets(p)},
                                },
                            )

                            if target_ip is not None:
                                proceed = False

                                # If the user selected bypass_icmp = True (Do not ping the device before attempting auto discover)
                                if meta['payload'].get("bypass_icmp"):
                                    proceed = True

                                # If the user selected bypass_icmp = False (Ping the device and only attempt ssh discovery if a reply was seen)
                                if not meta['payload'].get("bypass_icmp") and ok:
                                    proceed = True

                                await insert_app_backend_tracking(
                                    database=database,
                                    route=route,
                                    information={
                                        "event": f"device_discovery.start_device_discovery.starting_ssh.proceed.{proceed}",
                                        "result": scrub_secrets(result),
                                        "meta": scrub_secrets(meta),
                                        "device_profile": {profile_name: scrub_secrets(p)},
                                        "proceed": proceed,
                                    },
                                )

                                if proceed:

                                    # Attempt to auto discover the device via ssh

                                    ad = await netmiko_autodiscover(
                                        host=target_ip,
                                        username=p.get("username", ""),
                                        password=p.get("password", ""),
                                        port=int(p.get("ssh_port", 22)),
                                        enable_secret=p.get("enable_password"),
                                    )

                                    logger.info(ad)

                                    # Auto discover has the following info in the ad dict
                                    # "autodiscover": {
                                    #     "ok": true,
                                    #     "host": "10.0.0.101",
                                    #     "output": "",
                                    #     "command": "No commands sent during discovery",
                                    #     "device_type": "cisco_xe",
                                    #     "detected_device_type": "cisco_xe"
                                    # }

                                    # if autodiscover has completed successfully then attempt to fetch
                                    # any other device details.

                                    if ad.get("ok", False):

                                        # Batch commands to run in the same session.
                                        # These are currently used for stats gathering and the like.
                                        batch_commands = []
                                        batch_commands_output = {}

                                        # Show version parsing. Items like sw version, model, etc
                                        show_version_command = cisco_allowed_commands(ad['device_type']).get('show_version', None)

                                        # Commands to run during a backup event
                                        backup_commands = cisco_allowed_commands(ad['device_type']).get('allowed_backup_commands', None)

                                        os_name = cisco_allowed_commands(ad.get("device_type")).get('os_name_by_device', None)
                                        show_interface_description_command = cisco_allowed_commands(ad.get("device_type")).get('show_interface_description', None)
                                        hostname = None
                                        show_version_command_output = ''
                                        device_backup_location = ''
                                        show_version_parsed = {}
                                        show_mac_address_table_output = {}
                                        show_mac_address_table_output_parsed = {}
                                        show_interface_description_output = {}
                                        show_interface_description_output_parsed = {}
                                        show_cdp_neighbors_output = {}
                                        show_cdp_neighbors_output_parsed = {}
                                        show_lldp_neighbors_output = {}
                                        show_lldp_neighbors_output_parsed = {}
                                        show_ip_arp_output = {}
                                        show_ip_arp_output_parsed = {}
                                        show_mac_address_table_count_output = {}
                                        show_mac_address_table_count_output_parsed = {}

                                        # Add commands to the batch commands list if they are present in the
                                        # device dictionary

                                        if show_version_command is not None:
                                            batch_commands.append(show_version_command)

                                        if show_interface_description_command is not None:
                                            batch_commands.append(show_interface_description_command)

                                        show_cdp_neighbors_command = cisco_allowed_commands(ad.get("device_type")).get('show_cdp_neighbors', None)
                                        show_cdp_neighbors_command_flag = cisco_allowed_commands(ad.get("device_type")).get('show_cdp_neighbors_output_type', 'cli')

                                        if show_cdp_neighbors_command is not None:
                                            batch_commands.append(show_cdp_neighbors_command)

                                        show_lldp_neighbors_command = cisco_allowed_commands(ad.get("device_type")).get('show_lldp_neighbors', None)
                                        show_lldp_neighbors_command_flag = cisco_allowed_commands(ad.get("device_type")).get('show_lldp_neighbors_output_type', 'cli')

                                        if show_lldp_neighbors_command is not None:
                                            batch_commands.append(show_lldp_neighbors_command)

                                        show_mac_address_table_command = cisco_allowed_commands(ad.get("device_type")).get('show_mac_address_table', None)
                                        show_mac_address_command_flag = cisco_allowed_commands(ad.get("device_type")).get('show_mac_address_table_output_type', 'cli')

                                        if show_mac_address_table_command is not None:
                                            batch_commands.append(show_mac_address_table_command)

                                        show_ip_arp_table_command = cisco_allowed_commands(ad.get("device_type")).get('show_ip_arp_table', None)
                                        show_ip_arp_command_flag = cisco_allowed_commands(ad.get("device_type")).get('show_ip_arp_table_output_type', 'cli')

                                        if show_ip_arp_table_command is not None:
                                            batch_commands.append(show_ip_arp_table_command)

                                        show_mac_address_table_count_command = cisco_allowed_commands(ad.get("device_type")).get('show_mac_address_table_count', None)
                                        show_mac_address_table_count_command_flag = cisco_allowed_commands(ad.get("device_type")).get('show_mac_address_table_count_output_type', 'cli')

                                        if show_mac_address_table_count_command is not None:
                                            batch_commands.append(show_mac_address_table_count_command)

                                        # Run all batch commands

                                        batch_commands_output = await netmiko_fetch_command_output(
                                            host=target_ip,
                                            username=p.get("username", ""),
                                            password=p.get("password", ""),
                                            port=int(p.get("ssh_port", 22)),
                                            enable_secret=p.get("enable_password"),
                                            device_type=ad.get("device_type"),
                                            command=batch_commands
                                        )

                                        # Process all batch commands output
                                        logger.info(json.dumps(batch_commands_output, indent=4))

                                        outputs = batch_commands_output.get("outputs") or {}

                                        show_version_command_output_type = cisco_allowed_commands(ad.get("device_type")).get("show_version_output_type", None)

                                        show_version_command_output = _get_cmd_output(outputs, show_version_command)

                                        show_version_parsed = cisco_parse_show_version_auto(
                                            show_version_command_output or "",
                                            device_type=ad.get("device_type"),
                                            output_type=show_version_command_output_type or "auto",
                                        )

                                        show_version_fields = cisco_extract_show_version_fields(
                                            device_type=ad.get("device_type"),
                                            show_version_parsed=show_version_parsed,
                                            raw_output=show_version_command_output,
                                        )

                                        show_interface_description_output = batch_commands_output['outputs'].get(show_interface_description_command, None)
                                        show_interface_description_output_parsed = cisco_parse_show_interface_description_auto(ad.get("device_type"), batch_commands_output['outputs'].get(show_interface_description_command, None))

                                        # Parse CDP output
                                        show_cdp_neighbors_output = batch_commands_output['outputs'].get(show_cdp_neighbors_command, None)
                                        show_cdp_neighbors_output_parsed = cisco_parse_show_cdp_neighbors_auto(ad.get("device_type"), batch_commands_output['outputs'].get(show_cdp_neighbors_command, None), show_cdp_neighbors_command_flag)

                                        # Parse LLDP output
                                        show_lldp_neighbors_output = batch_commands_output['outputs'].get(show_lldp_neighbors_command, None)
                                        show_lldp_neighbors_output_parsed = cisco_parse_show_lldp_neighbors_auto(ad.get("device_type"), batch_commands_output['outputs'].get(show_lldp_neighbors_command, None), show_lldp_neighbors_command_flag)

                                        # Parse ip arp output
                                        show_ip_arp_output = batch_commands_output['outputs'].get(show_ip_arp_table_command, None)
                                        show_ip_arp_output_parsed = cisco_parse_show_ip_arp_table_auto(ad.get("device_type"), batch_commands_output['outputs'].get(show_ip_arp_table_command, None), show_ip_arp_command_flag)

                                        # Parse mac address table output
                                        show_mac_address_table_output = batch_commands_output['outputs'].get(show_mac_address_table_command, None)
                                        show_mac_address_table_output_parsed = cisco_parse_show_mac_address_table_auto(ad.get("device_type"), batch_commands_output['outputs'].get(show_mac_address_table_command, None), show_mac_address_command_flag)

                                        # Parse mac address table count output
                                        show_mac_address_table_count_output = batch_commands_output['outputs'].get(show_mac_address_table_count_command, None)
                                        show_mac_address_table_count_output_parsed = cisco_parse_show_mac_address_table_count_auto(ad.get("device_type"), batch_commands_output['outputs'].get(show_mac_address_table_count_command, None), show_mac_address_table_count_command_flag)

                                        # Perform a backup of the device

                                        if backup_commands is not None:

                                            backup_commands_output = await netmiko_fetch_command_output(
                                                host=target_ip,
                                                username=p.get("username", ""),
                                                password=p.get("password", ""),
                                                port=int(p.get("ssh_port", 22)),
                                                enable_secret=p.get("enable_password"),
                                                device_type=ad.get("device_type"),
                                                command=backup_commands
                                            )

                                            hostname = cisco_hostname(backup_commands_output.get('output', '')).get('hostname', 'Unable to determine hostname')

                                            # Save the raw configuration backup

                                            now = datetime.now()
                                            day_folder = now.strftime("%Y_%m_%d")

                                            backup_task = save_device_backup_text(
                                                target_ip=target_ip,
                                                raw_text=backup_commands_output.get('output', 'No output found'),
                                                subfolder=f"{ad.get('device_type')}/{day_folder}/{target_ip}",
                                            )

                                            if backup_task.get("error"):
                                                original_backup_file_path = None
                                            else:
                                                original_backup_file_path = backup_task["path"]

                                                # Compress and remove the old file

                                                compress_task = gzip_file_verified(
                                                    input_path=original_backup_file_path,
                                                    verify=True,
                                                    remove_original_on_success=True,
                                                )

                                                # Encrypt the file if the ENV Variable ENABLE_FILE_ENCRYPTION is set to true
                                                # If the variable is set to false, or not present at all no encryption will be
                                                # Done.

                                                encryption_warning_message = ''

                                                if env_bool_if_set('ENABLE_FILE_ENCRYPTION') is True:
                                                    # Encrypt the backup file

                                                    encryption_task = encrypt_backup_gz_to_enc(
                                                        input_gz_path=compress_task.get('output_path', None),
                                                    )

                                                    device_backup_location = (encryption_task.get('output_path') if isinstance(encryption_task, dict) else None) or compress_task.get('output_path', None) or 'Error fetching file location'

                                                    decrypt_task = read_backup_enc_gz_text(
                                                        enc_path=encryption_task.get('output_path', None),
                                                    )

                                                elif os.getenv("ENABLE_FILE_ENCRYPTION") is not None and env_bool_if_set('ENABLE_FILE_ENCRYPTION') is None:
                                                    encryption_warning_message = f"ENABLE_FILE_ENCRYPTION is set but not a valid bool: %r", os.getenv("ENABLE_FILE_ENCRYPTION")
                                                    encryption_task = False
                                                    decrypt_task = False
                                                else:
                                                    encryption_warning_message = "File encryption variable missing or set to false. No encryption task is being run"
                                                    encryption_task = False
                                                    decrypt_task = False
                                                    device_backup_location = (encryption_task.get('output_path') if isinstance(encryption_task, dict) else None) or compress_task.get('output_path', None) or 'Error fetching file location'

                                                # Save the location of the backup file if present
                                                await insert_device_backup_location(
                                                    device_name=hostname,
                                                    ipv4_loopback=target_ip,
                                                    device_type=ad.get("device_type"),
                                                    file_location=device_backup_location
                                                )

                                        await upsert_device_with_archive(
                                            database=database,
                                            device_name=hostname,
                                            ipv4_loopback=target_ip,
                                            device_type=ad.get("device_type"),
                                            hub_id=None, # Need to update eventually - per user case - requires custom checks
                                            site_abbreviation=None, # Need to update eventually - per user case - requires custom checks
                                            os_name=os_name,
                                            version=show_version_fields.get('software_version', None),
                                            chassis_model=show_version_fields.get('chassis_model', None),
                                            information={
                                                "event": "device_discovery.start_device_discovery.finished_ssh.success",
                                                "result": {**scrub_secrets(result), "device_profiles": {}},
                                                "meta": scrub_secrets(meta),
                                                "device_profile": {profile_name: scrub_secrets(p)},
                                                "autodiscover": ad,
                                                "hostname": hostname,
                                                "show_version_command_output": "Redacted - Only saved in the file system",
                                                "show_version_command_output_parsed": show_version_parsed,
                                                "backup_commands_output": ({**backup_commands_output, "output": "Redacted - Only saved in the file system"} if isinstance(backup_commands_output, dict) and "output" in backup_commands_output else backup_commands_output),
                                                "batch_commands": batch_commands,
                                                #"batch_commands_output": batch_commands_output,
                                                "backup_task": backup_task,
                                                "original_backup_file_path": original_backup_file_path,
                                                "compress_task": compress_task,
                                                "encryption_warning_message": encryption_warning_message,
                                                "encryption_task": encryption_task,
                                                "decrypt_task": ({**decrypt_task, "content": "Redacted - This was a test to see if the file could be decrypted"} if isinstance(decrypt_task, dict) and "content" in decrypt_task else decrypt_task),
                                                "show_mac_address_table_output": show_mac_address_table_output,
                                                "show_mac_address_table_output_parsed": show_mac_address_table_output_parsed,
                                                "show_interface_description_output": show_interface_description_output,
                                                "show_interface_description_output_parsed": show_interface_description_output_parsed,
                                                "show_cdp_neighbors_output": show_cdp_neighbors_output,
                                                "show_cdp_neighbors_output_parsed": show_cdp_neighbors_output_parsed,
                                                "show_lldp_neighbors_output": show_lldp_neighbors_output,
                                                "show_lldp_neighbors_output_parsed": show_lldp_neighbors_output_parsed,
                                                "show_ip_arp_output": show_ip_arp_output,
                                                "show_ip_arp_output_parsed": show_ip_arp_output_parsed,
                                                "show_mac_address_table_count_output": show_mac_address_table_count_output,
                                                "show_mac_address_table_count_output_parsed": show_mac_address_table_count_output_parsed
                                            },
                                            information_detail={}
                                        )

                                        await insert_app_backend_tracking(
                                            database=database,
                                            route=route,
                                            information={
                                                "event": "device_discovery.start_device_discovery.finished_ssh.success",
                                                "result": scrub_secrets(result),
                                                "meta": scrub_secrets(meta),
                                                "device_profile": {profile_name: scrub_secrets(p)},
                                                "autodiscover": ad,
                                                "hostname": hostname,
                                                "show_version_command_output": "Redacted - Only saved in the file system",
                                                "show_version_command_output_parsed": show_version_parsed,
                                                "backup_commands_output": ({**backup_commands_output, "output": "Redacted - Only saved in the file system"} if isinstance(backup_commands_output, dict) and "output" in backup_commands_output else backup_commands_output),
                                                "backup_task": backup_task,
                                                "original_backup_file_path": original_backup_file_path,
                                                "compress_task": compress_task,
                                                "encryption_warning_message": encryption_warning_message,
                                                "encryption_task": encryption_task,
                                                "decrypt_task": ({**decrypt_task, "content": "Redacted - This was a test to see if the file could be decrypted"} if isinstance(decrypt_task, dict) and "content" in decrypt_task else decrypt_task),
                                            },
                                        )



                                        result = {
                                            "ping_ok": ok,
                                            "target_ip": target_ip,
                                            "job_id": job_id,
                                            "celery_task_id": task_id,
                                            "requested_by": meta.get("requested_by"),
                                            "azp": meta.get("azp"),
                                            "roles": meta.get("roles") or [],
                                            "device_profiles_error": device_profiles_error,
                                            "device_profiles": scrub_secrets(pretty_json_any(device_profiles)),
                                            "autodiscover": ad,
                                        }

                                        await _update_job(
                                            job_id=job_id,
                                            status="SUCCESS",
                                            completed=True,
                                            duration_ms=ms,
                                            worker_hostname=worker_hostname,
                                            result=result,
                                            task_id=task_id
                                        )

                                        # Add to a device discovery table / devices table
                                        # from here get the device type and add some device specific command to use for discovery

                                        # Break out upon successful autodiscover.
                                        # This prevents logging in with multiple accounts.

                                        if ad.get("ok", False):
                                            break
                                    else:
                                        await insert_app_backend_tracking(
                                            database=database,
                                            route=route,
                                            information={
                                                "event": "device_discovery.start_device_discovery.finished_ssh.failed_autodiscovery",
                                                "result": scrub_secrets(result),
                                                "meta": scrub_secrets(meta),
                                                "device_profile": {profile_name: scrub_secrets(p)},
                                                "autodiscover": ad
                                            },
                                        )

                                        result = {
                                            "ping_ok": ok,
                                            "target_ip": target_ip,
                                            "job_id": job_id,
                                            "celery_task_id": task_id,
                                            "requested_by": meta.get("requested_by"),
                                            "azp": meta.get("azp"),
                                            "roles": meta.get("roles") or [],
                                            "device_profiles_error": device_profiles_error,
                                            "device_profiles": scrub_secrets(pretty_json_any(device_profiles)),
                                            "autodiscover": ad,
                                        }

                                        await _update_job(
                                            job_id=job_id,
                                            status="FAILURE",
                                            completed=False,
                                            duration_ms=ms,
                                            worker_hostname=worker_hostname,
                                            result=result,
                                            task_id=task_id
                                        )

                                        ad = None
                                else:
                                    await insert_app_backend_tracking(
                                        database=database,
                                        route=route,
                                        information={
                                            "event": "device_discovery.start_device_discovery.starting_ssh.failed.unable_to_proceed",
                                            "result": scrub_secrets(result),
                                            "meta": scrub_secrets(meta),
                                            "device_profile": {profile_name: scrub_secrets(p)},
                                        },
                                    )

                                    ad = None

                                    break
                            else:
                                await insert_app_backend_tracking(
                                    database=database,
                                    route=route,
                                    information={
                                        "event": "device_discovery.start_device_discovery.starting_ssh.failed.invalid_target_ip",
                                        "result": scrub_secrets(result),
                                        "meta": scrub_secrets(meta),
                                        "device_profile": {profile_name: scrub_secrets(p)},
                                    },
                                )

                                ad = None

                                break

            else:
                # update the job details in the database
                await _update_job(
                    job_id=job_id,
                    status="SUCCESS" if ok else "FAILURE",
                    completed=True,
                    duration_ms=ms,
                    worker_hostname=worker_hostname,
                    result=result,
                    task_id=task_id
                )



            return {"detail": result}

        except Exception as exc:
            ms = int((time.perf_counter() - t0) * 1000)
            tb = traceback.format_exc()

            job_id = str(meta.get("job_id", "")).strip()
            if job_id:
                await _update_job(
                    job_id=job_id,
                    status="FAILURE",
                    completed=True,
                    duration_ms=ms,
                    worker_hostname=worker_hostname,
                    error_type=type(exc).__name__,
                    error_message=str(exc),
                    tb=tb,
                    task_id=task_id
                )

            logger.exception("icmp_ping failed job_id=%s task_id=%s", meta.get("job_id"), task_id)
            return {"error": f"celery_task_failed: {exc}"}

        finally:
            await disconnect_db()

    return _run_async(_run())

@celery_app.task(name="device_backups.search_configuration_files", bind=True)
def device_backups_search_configuration_files(self, meta: Dict[str, Any]) -> Dict[str, Any]:
    """
    meta must include:
      - job_id
      - requested_by
      - route (optional)
      - roles (optional)
      - payload:
          - file_location (str) OR file_locations (list[str])
          - search (str)
          - mode ('string'|'regex')
          - ignore_case (bool)
          - regex_multiline (bool)
          - context_lines (int)
          - max_matches_per_file (int)
          - max_total_matches (int)
          - redact_output (bool)
    """

    t0 = time.perf_counter()
    task_id = getattr(self.request, "id", None)
    worker_hostname = getattr(self.request, "hostname", None)
    task_id = getattr(self.request, "id", None)
    route = str(meta.get("route") or "/device_backups/search_configuration_files")
    processed = 0
    async def _run():
        await connect_db()
        try:
            payload = meta.get("payload") or {}
            logger.info(f"meta: {meta}")
            logger.info(f"payload: {payload}")
            context_lines = int(payload.get("context_lines", 0) or 0)

            device_ip = (payload.get("device_ip") or "").strip()
            direction = (payload.get("direction") or "").strip().lower() if payload.get("direction") else None

            file_location = (payload.get("file_location") or "").strip()
            file_locations = payload.get("file_locations") or []
            files: list[str] = []

            ignore_case = bool(payload.get("ignore_case", True))

            job_id = str(meta.get("job_id", "")).strip()

            max_matches_per_file = int(payload.get("max_matches_per_file", 200) or 200)
            max_total_matches = int(payload.get("max_total_matches", 5000) or 5000)
            mode = payload.get("mode") or "string"

            number_of_files_to_search = int(payload.get("number_of_files_to_search") or 1)

            redact_output = bool(payload.get("redact_output", False))
            regex_multiline = bool(payload.get("regex_multiline", False))
            requested_by = meta.get("requested_by")

            resolved_file_locations: list[str] = []

            search_history = bool(payload.get("search_history", False))
            search_q = payload.get("search") or ""

            use_device_ip = bool(payload.get("use_device_ip", False))
            use_file_list = bool(payload.get("use_file_list", False))
            use_single_file = bool(payload.get("use_single_file", False))

            # validate mutually exclusive mode again (defensive)
            enabled = sum(bool(x) for x in [use_device_ip, use_single_file, use_file_list])

            if enabled != 1:
                raise ValueError("Exactly one of use_device_ip, use_single_file, use_file_list must be true in worker payload.")

            if use_device_ip:
                if not device_ip:
                    raise ValueError("device_ip is required when use_device_ip=true")

                if search_history:

                    if direction not in ("asc", "desc"):
                        raise ValueError("direction must be 'asc' or 'desc' when search_history=true")

                    resp = await select_device_backup_locations_for_ipv4(
                        ipv4_loopback=device_ip,
                        direction=direction,
                        limit=number_of_files_to_search,
                    )

                    rows = resp.get("detail", {}).get("rows", [])
                    resolved_file_locations = [r["file_location"] for r in rows if r.get("file_location")]

                else:
                    resp = await select_latest_device_backup_location_for_ipv4(
                        ipv4_loopback=device_ip,
                    )
                    logger.info(f"resp: {resp}")

                    found = resp.get("detail", {}).get("found")

                    row = resp.get("detail", {}).get("row") if found else None

                    if row and row.get("file_location"):
                        resolved_file_locations = [row["file_location"]]

            elif use_single_file:
                if not file_location:
                    raise ValueError("file_location is required when use_single_file=true")
                resolved_file_locations = [file_location]

            else:  # use_file_list
                if not isinstance(file_locations, list) or len(file_locations) == 0:
                    raise ValueError("file_locations must be a non-empty list when use_file_list=true")
                resolved_file_locations = [str(x).strip() for x in file_locations if str(x).strip()]


            logger.info(f"resolved_file_locations: {resolved_file_locations}")

            if isinstance(resolved_file_locations, list) and resolved_file_locations:
                files = [str(x).strip() for x in resolved_file_locations if str(x).strip()]
            elif file_location:
                files = [resolved_file_locations]

            if not job_id or not files or not str(search_q).strip():
                err = {"error": "missing_required_fields", "job_id": job_id, "files_count": len(files)}
                return err

            logger.info(f"files: {files}")

            # base dir enforcement (same idea as device_backups.py)
            base_dir = (os.getenv("CELERY_WORKER_DEVICE_BACKUP_FILE_LOCATION") or "/backups/device_configuration_backups").strip()
            base_path = Path(base_dir)

            max_bytes = int(os.getenv("DEVICE_BACKUP_MAX_DECOMPRESSED_BYTES", "10485760") or "10485760")
            if max_bytes < 0:
                max_bytes = 0  # treat negative as unlimited

            # mark STARTED in both tables
            await _update_job(
                job_id=job_id,
                job_name=(meta.get("job_name") or getattr(self, "name", None)),
                status="STARTED",
                started=True,
                worker_hostname=worker_hostname,
                task_id=task_id
            )

            jt_init = await upsert_jobs_tracking_information(
                database=database,
                job_id=job_id,
                job_type="configuration_search",
                status="STARTED",
                requested_by=requested_by,
                route=route,
                celery_task_id=str(task_id) if task_id else None,
                redacted=redact_output,
                input={
                    "file_locations": files,
                    "search": search_q,
                    "mode": mode,
                    "ignore_case": ignore_case,
                    "regex_multiline": regex_multiline,
                    "context_lines": context_lines,
                    "max_matches_per_file": max_matches_per_file,
                    "max_total_matches": max_total_matches,
                },
                progress_current=0,
                progress_total=len(files),
                progress_message="starting",
            )

            if isinstance(jt_init, dict) and jt_init.get("error"):
                raise HTTPException(
                    status_code=HTTP_500_INTERNAL_SERVER_ERROR,
                    detail={"error": "job_tracking_init_failed", "detail": jt_init},
                )

            results: list[dict] = []
            processed = 0
            matches_budget = max(1, max_total_matches)

            for f in files:
                processed += 1
                p = Path(f)

                item: dict = {"file_location": f}

                if not p.is_absolute():
                    item.update({"ok": False, "error": "file_location_must_be_absolute"})
                    results.append(item)
                elif not _is_path_within_base(candidate=p, base=base_path):
                    item.update({"ok": False, "error": "file_location_outside_allowed_base", "allowed_base": str(base_path)})
                    results.append(item)
                elif not p.exists():
                    item.update({"ok": False, "error": "file_not_found"})
                    results.append(item)
                else:
                    ext = p.suffix.lower()

                    # read file content (enc/gz/plain)
                    if ext == ".enc":
                        r = read_backup_enc_gz_text(enc_path=p, max_decompressed_bytes=(max_bytes or None))
                        if isinstance(r, dict) and r.get("ok"):
                            content = r.get("content") or ""
                            item["backup_meta"] = {
                                "target_ip": r.get("target_ip"),
                                "timestamp": r.get("timestamp"),
                            }
                        else:
                            item.update({"ok": False, "error": (r.get("error") if isinstance(r, dict) else "decrypt_failed")})
                            results.append(item)
                            content = None
                    elif ext == ".gz":
                        r = await read_gz_text_file(gz_path=p, max_decompressed_bytes=(max_bytes or None))
                        if isinstance(r, dict) and r.get("ok"):
                            content = r.get("content") or ""
                        else:
                            item.update({"ok": False, "error": (r.get("error") if isinstance(r, dict) else "gunzip_failed")})
                            results.append(item)
                            content = None
                    else:
                        r = _safe_read_plain_text(p, max_bytes=max_bytes)
                        if r.get("ok"):
                            content = r.get("content") or ""
                        else:
                            item.update({"ok": False, "error": r.get("error")})
                            results.append(item)
                            content = None

                    if content is not None:
                        s = _search_text(
                            text=content,
                            query=str(search_q),
                            mode=str(mode),
                            ignore_case=ignore_case,
                            regex_multiline=regex_multiline,
                            context_lines=context_lines,
                            max_matches_per_file=max_matches_per_file,
                            remaining_budget=matches_budget,
                            redact_output=redact_output,
                        )
                        if s.get("ok"):
                            m = s.get("matches") or []
                            matches_budget -= len(m)
                            item.update({"ok": True, "match_count": len(m), "matches": m, "search_mode": s.get("mode")})
                        else:
                            item.update({"ok": False, "error": s.get("error")})
                        results.append(item)

                # stream progress update after each file
                await upsert_jobs_tracking_information(
                    database=database,
                    job_id=job_id,
                    job_type="configuration_search",
                    status="PROGRESS",
                    progress_current=processed,
                    progress_total=len(files),
                    progress_message=f"processed {processed}/{len(files)}",
                )

                await _update_job(
                    job_id=job_id,
                    job_name=(meta.get("job_name") or getattr(self, "name", None)),
                    status="PROGRESS",
                    completed=False,
                    worker_hostname=worker_hostname,
                    result={
                        "files_total": len(files),
                        "files_processed": processed,
                    },
                    task_id=task_id
                )

            ms = int((time.perf_counter() - t0) * 1000)

            final = {
                "job_id": job_id,
                "celery_task_id": task_id,
                "requested_by": requested_by,
                "route": route,
                "files_total": len(files),
                "files_processed": processed,
                "results": results,
                "truncation": {
                    "max_matches_per_file": max_matches_per_file,
                    "max_total_matches": max_total_matches,
                },
                "redacted": redact_output,
            }

            await upsert_jobs_tracking_information(
                database=database,
                job_id=job_id,
                job_type="configuration_search",
                status="SUCCESS",
                progress_current=processed,
                progress_total=len(files),
                progress_message="complete",
                result=final,
                duration_ms=ms
            )

            await _update_job(
                job_id=job_id,
                job_name=(meta.get("job_name") or getattr(self, "name", None)),
                status="SUCCESS",
                completed=True,
                duration_ms=ms,
                worker_hostname=worker_hostname,
                result=final,
                task_id=task_id
            )

            return {"detail": final}

        except Exception as exc:
            ms = int((time.perf_counter() - t0) * 1000)
            tb = traceback.format_exc()
            job_id = str(meta.get("job_id", "")).strip()

            await insert_app_backend_tracking(
                database=database,
                route=route,
                information={
                    "event": "device_backups_search_configuration_files.Exception",
                    "job_id": job_id,
                    "job_name": (meta.get("job_name") or getattr(self, "name", None)),
                    "job_type": "configuration_search",
                    "ms": ms,
                    "tb": tb,
                    "error_type": type(exc).__name__,
                    "error_message": str(exc),
                    "status": "FAILURE",
                    "meta": meta
                },
            )

            if job_id:
                await upsert_jobs_tracking_information(
                    database=database,
                    job_id=job_id,
                    job_type="configuration_search",
                    status="FAILURE",
                    progress_message=f"failed: {type(exc).__name__}: {str(exc)}",
                    error_type=type(exc).__name__,
                    error_message=str(exc),
                    traceback=tb,
                    duration_ms=ms,
                    meta=meta
                )

                await _update_job(
                    job_id=job_id,
                    celery_task_id=str(task_id) if task_id else job_id,
                    status="FAILURE",
                    #meta={"worker_hostname": worker_hostname, "duration_ms": ms},
                )

            logger.exception("search_configuration_files failed job_id=%s task_id=%s", meta.get("job_id"), task_id)
            return {"error": f"celery_task_failed: {exc}"}

        finally:
            await disconnect_db()

    return _run_async(_run())