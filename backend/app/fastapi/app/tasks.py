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
import os
import asyncio
import json
import logging
import time
import traceback
from typing import Any, Dict
from datetime import datetime

from app.celery_app import celery_app
from app.database import database, connect_db, disconnect_db

from app.shared_functions.helpers.helpers_logging_config import load_env_from_vault_json, setup_logging

from app.database_queries.postgres_insert_queries import (
    insert_app_backend_tracking,
    insert_device_backup_location,
    upsert_device_with_archive
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
    cisco_allowed_show_version_commands,
    cisco_show_version_parse,
    cisco_allowed_backup_commands,
    cisco_hostname,
    cisco_map_device_type_os_type
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


async def _update_job(
    *,
    job_id: str,
    status: str,
    started: bool = False,
    completed: bool = False,
    duration_ms: int | None = None,
    worker_hostname: str | None = None,
    result: dict | None = None,
    error_type: str | None = None,
    error_message: str | None = None,
    tb: str | None = None,
):
    """
    Update your app_tracking_celery row. This matches what celery_jobs.py reads.
    """
    sql = """
    UPDATE app_tracking_celery
    SET
      status = :status,
      updated_at = now(),
      started_at = CASE WHEN :started THEN COALESCE(started_at, now()) ELSE started_at END,
      completed_at = CASE WHEN :completed THEN now() ELSE completed_at END,
      duration_ms = COALESCE(:duration_ms, duration_ms),
      worker_hostname = COALESCE(:worker_hostname, worker_hostname),
      result = COALESCE(CAST(:result_json AS jsonb), result),
      error_type = COALESCE(:error_type, error_type),
      error_message = COALESCE(:error_message, error_message),
      traceback = COALESCE(:traceback, traceback)
    WHERE job_id = :job_id
    """
    await database.execute(
        sql,
        {
            "job_id": job_id,
            "status": status,
            "started": started,
            "completed": completed,
            "duration_ms": duration_ms,
            "worker_hostname": worker_hostname,
            "result_json": json.dumps(result) if result is not None else None,
            "error_type": error_type,
            "error_message": error_message,
            "traceback": tb,
        },
    )


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

                                        # Fetch version information

                                        # Fetched version based on device type
                                        # I am going to hard code ish this check for now.
                                        # Device types to flag off of can be found here
                                        # https://ktbyers.github.io/netmiko/PLATFORMS.html
                                        # TODO - Find a cleaner way to impliment this check.

                                        if 'cisco' in ad.get("device_type"):
                                            show_version_command = cisco_allowed_show_version_commands(ad['device_type'])
                                            backup_commands = cisco_allowed_backup_commands(ad['device_type'])
                                            os_name = cisco_map_device_type_os_type(ad['device_type'])
                                        else:
                                            os_name = None
                                            hostname = None
                                            backup_commands = None
                                            show_version_command = None
                                            show_version_command_output = ''
                                            device_backup_location = ''
                                            show_version_parsed = {}

                                        if show_version_command is not None:
                                            show_version_command_output = await netmiko_fetch_command_output(
                                                host=target_ip,
                                                username=p.get("username", ""),
                                                password=p.get("password", ""),
                                                port=int(p.get("ssh_port", 22)),
                                                enable_secret=p.get("enable_password"),
                                                device_type=ad.get("device_type"),
                                                command=show_version_command
                                            )

                                            if 'cisco' in ad.get("device_type"):
                                                show_version_parsed = cisco_show_version_parse(show_version_command_output.get('output', ''))

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

                                            # Fetch specific items based on device type. Some devices may have
                                            # different ways of saving X data.

                                            if 'cisco' in ad.get("device_type"):
                                                hostname = cisco_hostname(backup_commands_output.get('output', '')).get('hostname', 'Unable to determine hostname')


                                            # Save the raw configuration backup
                                            now = datetime.now()
                                            day_folder = now.strftime("%Y_%m_%d")

                                            backup_task = save_device_backup_text(
                                                target_ip=target_ip,
                                                raw_text=backup_commands_output.get('output', 'No output found'),
                                                subfolder=f"{ad.get("device_type")}/{day_folder}/{target_ip}",
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

                                                    device_backup_location = encryption_task.get('output_path', 'Error fetching file location')

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
                                                    device_backup_location = encryption_task.get('output_path', 'Error fetching file location')

                                                # Save the location of the backup file if present
                                                await insert_device_backup_location(
                                                    database=database,
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
                                            version=show_version_parsed.get('software_version', None),
                                            chassis_model=show_version_parsed.get('model_number', None),
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
                                                "backup_task": backup_task,
                                                "original_backup_file_path": original_backup_file_path,
                                                "compress_task": compress_task,
                                                "encryption_warning_message": encryption_warning_message,
                                                "encryption_task": encryption_task,
                                                "decrypt_task": ({**decrypt_task, "content": "Redacted - This was a test to see if the file could be decrypted"} if isinstance(decrypt_task, dict) and "content" in decrypt_task else decrypt_task),
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
                                        )
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
                )

            logger.exception("icmp_ping failed job_id=%s task_id=%s", meta.get("job_id"), task_id)
            return {"error": f"celery_task_failed: {exc}"}

        finally:
            await disconnect_db()

    return _run_async(_run())
