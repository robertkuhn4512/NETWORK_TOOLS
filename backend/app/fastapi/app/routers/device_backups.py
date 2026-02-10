"""
Device backups endpoints
    fetch_device_backup_file
"""

from __future__ import annotations

import os
import uuid
from pathlib import Path
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from starlette.status import (
    HTTP_400_BAD_REQUEST,
    HTTP_403_FORBIDDEN,
    HTTP_404_NOT_FOUND,
    HTTP_413_REQUEST_ENTITY_TOO_LARGE,
    HTTP_500_INTERNAL_SERVER_ERROR,
)

from app.security.auth import UserContext, get_current_user, require_any_role

from app.database_queries.postgres_insert_queries import (
    insert_app_backend_tracking,
    upsert_jobs_tracking_information,
    upsert_app_tracking_celery_job
)

from app.database_queries.postgres_select_queries import (
    select_jobs_tracking_information,
    select_app_tracking_celery
)

from app.shared_functions.helpers.helpers_environment import (
    _env_int
)

from app.shared_functions.helpers.helpers_file_encryption import (
    read_backup_enc_gz_text,
    read_gz_text_file,
)

from app.database import database
from app.celery_app import celery_app

import logging

logger = logging.getLogger("app.device_backups")

router = APIRouter(
    prefix="/device_backups",
    tags=["device_backups"],
    dependencies=[Depends(get_current_user)],
)


class TargetFile(BaseModel):
    file_location: str | None = Field(
        default=None,
        example="/backups/device_configuration_backups/cisco_xe/2026_01_28/10.0.0.101/10.0.0.101_2026_01_28_19_15_59.enc|.gz",
    )

class ConfigurationSearchRequest(BaseModel):
    file_location: str | None = Field(default=None, description="Absolute path to one backup file")
    file_locations: List[str] | None = Field(default=None, description="Absolute paths to many backup files")

    search: str = Field(..., description="String or regex pattern to search for")
    mode: str = Field(default="string", description="string|regex")
    ignore_case: bool = Field(default=True)
    regex_multiline: bool = Field(default=False, description="If true, run regex across the whole config text (DOTALL).")

    context_lines: int = Field(default=0, ge=0, le=25)
    max_matches_per_file: int = Field(default=200, ge=1, le=5000)
    max_total_matches: int = Field(default=5000, ge=1, le=200000)



def _is_path_within_base(*, candidate: Path, base: Path) -> bool:
    """
    True if candidate resolves under base.
    """
    try:
        base_r = base.resolve()
        cand_r = candidate.resolve()
        return cand_r == base_r or str(cand_r).startswith(str(base_r) + os.sep)
    except Exception:
        return False

@router.post(
    "/fetch_device_backup_file",
    summary="Fetch the file details and the contents for a specific backup file.",
    status_code=200,
)
async def fetch_device_backup_file(
    payload: TargetFile,
    request: Request,
    user: UserContext = Depends(require_any_role("device_backup_file_admin", "device_backup_file_user"))
):
    # Roles
    #
    # device_backup_file_admin (Can see full configurations)
    # device_backup_file_admin (WIP : Will be able to see redacted configurations - Users choice - remove credentials etc)

    file_location = (payload.file_location or "").strip()
    if not file_location:
        raise HTTPException(
            status_code=HTTP_400_BAD_REQUEST,
            detail={"error": "file_location_missing"},
        )

    p = Path(file_location)
    if not p.is_absolute():
        raise HTTPException(
            status_code=HTTP_400_BAD_REQUEST,
            detail={"error": "file_location_must_be_absolute", "file_location": file_location},
        )

    # Enforce a safe base directory so callers can’t read arbitrary files
    base_dir = (os.getenv("CELERY_WORKER_DEVICE_BACKUP_FILE_LOCATION") or "/backups/device_configuration_backups").strip()
    base_path = Path(base_dir)

    if not _is_path_within_base(candidate=p, base=base_path):
        raise HTTPException(
            status_code=HTTP_403_FORBIDDEN,
            detail={
                "error": "file_location_outside_allowed_base",
                "allowed_base": str(base_path),
                "file_location": str(p),
            },
        )

    ext = p.suffix.lower()

    # Limit how much we will decompress into memory (configurable)
    # - Set DEVICE_BACKUP_MAX_DECOMPRESSED_BYTES=0 to allow unlimited (not recommended)
    # This variable is set in the fastapi_secrets section in vault

    max_bytes = _env_int("DEVICE_BACKUP_MAX_DECOMPRESSED_BYTES", 10 * 1024 * 1024)
    max_bytes_opt: Optional[int] = None if max_bytes <= 0 else max_bytes

    try:
        if ext == ".enc":
            res = read_backup_enc_gz_text(
                enc_path=p
            )
            if res.get("error"):
                code = res.get("error")

                if code in {"decrypt_input_not_found"}:
                    raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail=res)
                if code in {"backup_master_key_missing", "backup_master_key_invalid_base64", "backup_master_key_wrong_length"}:
                    raise HTTPException(status_code=HTTP_500_INTERNAL_SERVER_ERROR, detail=res)
                if code in {"gz_decompressed_too_large"}:
                    raise HTTPException(status_code=HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail=res)

                raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail=res)

            return {
                "detail": {
                    "ok": True,
                    "file_location": str(p),
                    "file_type": "enc+gz",
                    "target_ip": res.get("target_ip"),
                    "timestamp": res.get("timestamp"),
                    "bytes_decompressed": res.get("bytes_decompressed"),
                    "content": res.get("content", ""),
                }
            }

        if ext == ".gz":
            res = read_gz_text_file(gz_path=p, max_bytes=max_bytes_opt)
            if res.get("error"):
                code = res.get("error")
                if code in {"gz_not_found"}:
                    raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail=res)
                raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail=res)

            return {
                "detail": {
                    "ok": True,
                    "file_location": str(p),
                    "file_type": "gz",
                    "bytes_read": res.get("bytes_read"),
                    "content": res.get("content", ""),
                }
            }

        raise HTTPException(
            status_code=HTTP_400_BAD_REQUEST,
            detail={
                "error": "unsupported_backup_file_extension",
                "file_location": str(p),
                "ext": ext,
                "allowed": [".enc", ".gz"],
            },
        )

    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("fetch_device_backup_file failed: %s", exc)
        raise HTTPException(
            status_code=HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "fetch_device_backup_file_failed", "detail": str(exc)},
        )

@router.post(
    "/search_configuration_files",
    summary="Start a background search across one or many configuration backup files.",
    status_code=200,
)
async def search_configuration_files(
    payload: ConfigurationSearchRequest,
    request: Request,
    user: UserContext = Depends(require_any_role("device_backup_file_admin", "device_backup_file_user")),
):
    route = str(request.url.path)

    files: list[str] = []

    if isinstance(payload.file_locations, list) and payload.file_locations:
        files = [str(x).strip() for x in payload.file_locations if str(x).strip()]
    elif payload.file_location:
        files = [str(payload.file_location).strip()]

    if not files:
        raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail={"error": "file_location_missing"})

    q = (payload.search or "").strip()
    if not q:
        raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail={"error": "search_missing"})

    # Lock file searches to files in the backups directory
    base_dir = (os.getenv("CELERY_WORKER_DEVICE_BACKUP_FILE_LOCATION") or "/backups/device_configuration_backups").strip()
    base_path = Path(base_dir)

    for f in files:
        p = Path(f)
        if not p.is_absolute():
            raise HTTPException(status_code=HTTP_400_BAD_REQUEST, detail={"error": "file_location_must_be_absolute", "file_location": f})
        if not _is_path_within_base(candidate=p, base=base_path):
            raise HTTPException(
                status_code=HTTP_403_FORBIDDEN,
                detail={"error": "file_location_outside_allowed_base", "allowed_base": str(base_path), "file_location": f},
            )

    # Redaction policy (safe default):
    roles = getattr(user, "roles", None) or []
    is_admin = "device_backup_file_admin" in roles
    redact_output = not is_admin  # admin sees line content, non-admin sees line numbers only

    job_id = str(uuid.uuid4())

    requested_by = (
        getattr(user, "preferred_username", None)
        or getattr(user, "username", None)
        or getattr(user, "email", None)
        or "unknown"
    )

    # Create/initialize BOTH tracking rows up front (so polls never 404)
    job_name = "device_backups.search_configuration_files"
    dedupe_key = job_id

    res_celery_track = await upsert_app_tracking_celery_job(
        database=database,
        job_id=job_id,
        task_id=job_id,
        job_name=job_name,
        dedupe_key=dedupe_key,
        status="PENDING",
        route=route,
    )

    if isinstance(res_celery_track, dict) and res_celery_track.get("error"):
        # don't enqueue a job you can't track
        raise HTTPException(
            status_code=HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "job_tracking_init_failed", "detail": res_celery_track},
        )

    await upsert_jobs_tracking_information(
        database=database,
        job_id=job_id,
        job_type="configuration_search",
        status="PENDING",
        requested_by=requested_by,
        route=route,
        celery_task_id=job_id,  # set Celery task_id == job_id below
        redacted=redact_output,
        input_payload={
            "file_locations": files,
            "search": q,
            "mode": payload.mode,
            "ignore_case": payload.ignore_case,
            "regex_multiline": payload.regex_multiline,
            "context_lines": payload.context_lines,
            "max_matches_per_file": payload.max_matches_per_file,
            "max_total_matches": payload.max_total_matches,
            "redact_output": redact_output,
        },
        progress_current=0,
        progress_total=len(files),
        progress_message="queued",
    )

    meta = {
        "job_id": job_id,
        "job_name": job_name,
        "dedupe_key": dedupe_key,
        "requested_by": requested_by,
        "route": route,
        "roles": roles,
        "payload": {
            "file_locations": files,
            "search": q,
            "mode": payload.mode,
            "ignore_case": payload.ignore_case,
            "regex_multiline": payload.regex_multiline,
            "context_lines": payload.context_lines,
            "max_matches_per_file": payload.max_matches_per_file,
            "max_total_matches": payload.max_total_matches,
            "redact_output": redact_output,
        },
    }

    # Tie Celery’s task_id to the job_id so everything correlates cleanly
    celery_app.send_task(
        "device_backups.search_configuration_files",
        args=[meta],
        task_id=job_id,
    )

    await insert_app_backend_tracking(
        database=database,
        route=request.url.path,
        information={
            "event": "job_enqueued",
            "job_id": job_id,
            "celery_task_id": job_id,
            "requested_by": requested_by,
            "azp": getattr(user, "azp", None),
            "roles": user.roles or [],
        },
    )

    return {"detail": {"ok": True, "job_id": job_id}}


@router.get(
    "/search_configuration_files/{job_id}",
    summary="Poll job status/results for a configuration search.",
    status_code=200,
)
async def get_search_configuration_job(
    job_id: str,
    request: Request,
    user: UserContext = Depends(require_any_role("device_backup_file_admin", "device_backup_file_user")),
):
    requested_by = (
            getattr(user, "preferred_username", None)
            or getattr(user, "username", None)
            or getattr(user, "email", None)
            or "unknown"
    )

    jt = await select_jobs_tracking_information(job_id=job_id)
    ct = await select_app_tracking_celery(job_id=job_id)

    await insert_app_backend_tracking(
        database=database,
        route=request.url.path,
        information={
            "event": "get_search_configuration_job",
            "job_id": job_id,
            "jt": jt,
            "ct": ct,
            "requested_by": requested_by,
            "azp": getattr(user, "azp", None),
            "roles": user.roles or [],
        },
    )

    if jt.get("error"):
        raise HTTPException(status_code=HTTP_500_INTERNAL_SERVER_ERROR, detail=jt)
    if jt.get("detail") is None:
        raise HTTPException(status_code=HTTP_404_NOT_FOUND, detail={"error": "job_not_found", "job_id": job_id})

    return {"detail": {"jobs_tracking_information": jt.get("detail"), "celery_tracking": ct.get("detail")}}