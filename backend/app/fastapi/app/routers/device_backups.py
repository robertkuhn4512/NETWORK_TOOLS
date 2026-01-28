"""
Device backups endpoints
    fetch_device_backup_file
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

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

from app.shared_functions.helpers.helpers_environment import (
    _env_int
)

from app.shared_functions.helpers.helpers_file_encryption import (
    read_backup_enc_gz_text,
    read_gz_text_file,
)

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
