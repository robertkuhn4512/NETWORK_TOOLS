"""
Helper functions that aid in saving any device configurations that have been pulled.
This will have the option to encrypt / decrypt the files depending on whether specific environment
variables are present and set.

If any of the required variables are missing, All configuration files will be saved in plain text.
Dealers choice on whether you want encrypted or decrypted configuration files present on your system.

My opinion is encrypt as rest, and call the fastapi endpoint to fetch the decrypted file.

By default my operational choice is

->Compress the file to gz
->Encrypt the file

Set the following variables in the vault fastapi_secrets location

"""

from __future__ import annotations

import os
import gzip
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Union

def save_device_backup_text(
    *,
    target_ip: str,
    raw_text: Union[str, bytes],
    subfolder: Optional[str] = None,
    env_var: str = "CELERY_WORKER_DEVICE_BACKUP_FILE_LOCATION",
    ext: str = ".txt",
    when: Optional[datetime] = None,
    use_utc: bool = True,
    safe_filename: bool = True,
) -> Dict[str, Any]:
    """
    Save a raw device backup string to disk under a base directory specified by an env var.

    Notes / How to run:
      - Ensure the base directory env var is set in the container:
          export CELERY_WORKER_DEVICE_BACKUP_FILE_LOCATION=/backups/device_configuration_backups
      - Then call:
          save_device_backup_text(target_ip="10.0.0.101", raw_text=cfg, subfolder="cisco_ios")

    File naming:
      - Requested shape: <target_ip>_YYYY-MM-DD HH:MI:SS.txt
      - By default, this function makes a filesystem-safer variant:
          <target_ip>_YYYY-MM-DD HH-MM-SS.txt
        (colon is replaced with '-'). Set safe_filename=False to keep ':'.

    Returns:
      - {"ok": True, "path": "...", "filename": "...", "bytes_written": 1234}
      - {"error": "<message>", ...}
    """

    base_dir = (os.getenv(env_var) or "").strip()
    if not base_dir:
        return {"error": "backup_base_dir_env_missing", "env_var": env_var}

    base_path = Path(base_dir)

    # Validate and normalize subfolder (must be relative; prevent path traversal)
    rel_sub = None
    if subfolder is not None:
        sub = str(subfolder).strip().strip("/").strip()
        if sub:
            p = Path(sub)
            if p.is_absolute() or ".." in p.parts:
                return {"error": "invalid_subfolder", "subfolder": subfolder}
            rel_sub = p

    out_dir = base_path / rel_sub if rel_sub else base_path

    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except Exception as exc:
        return {"error": "backup_dir_create_failed", "path": str(out_dir), "detail": str(exc)}

    # Normalize content
    if isinstance(raw_text, bytes):
        content = raw_text.decode("utf-8", "replace")
    else:
        content = str(raw_text)

    # Timestamp
    now = when or (datetime.now(timezone.utc) if use_utc else datetime.now())
    ts = now.strftime("%Y_%m_%d_%H_%M_%S")  # requested "YYYY-MM-DD HH:MI:SS"
    ts_for_filename = ts.replace(":", "-") if safe_filename else ts

    # Extension
    ext = (ext or ".txt").strip()
    if not ext.startswith("."):
        ext = "." + ext

    filename = f"{target_ip}_{ts_for_filename}{ext}"
    final_path = out_dir / filename
    tmp_path = out_dir / f".{filename}.tmp"

    try:
        # Atomic write (same filesystem): write tmp then replace
        tmp_path.write_text(content, encoding="utf-8", errors="replace")
        os.replace(tmp_path, final_path)
    except Exception as exc:
        # Best-effort cleanup
        try:
            if tmp_path.exists():
                tmp_path.unlink()
        except Exception:
            pass
        return {"error": "backup_write_failed", "path": str(final_path), "detail": str(exc)}

    try:
        bytes_written = final_path.stat().st_size
    except Exception:
        bytes_written = None

    return {
        "ok": True,
        "path": str(final_path),
        "filename": filename,
        "bytes_written": bytes_written,
        "base_dir": str(base_path),
        "subfolder": str(rel_sub) if rel_sub else None,
    }

def _normalize_exts(exts: Sequence[str]) -> set[str]:
    out: set[str] = set()
    for e in exts or []:
        e = str(e).strip().lower()
        if not e:
            continue
        if not e.startswith("."):
            e = "." + e
        out.add(e)
    return out


def gzip_file_verified(
    *,
    input_path: Union[str, Path],
    output_path: Optional[Union[str, Path]] = None,
    compresslevel: int = 6,
    verify: bool = True,
    remove_original_on_success: bool = True,
    allowed_extensions: Sequence[str] = (".txt", ".cfg", ".log"),  # <--- configure this if you wish to allow other files to be compressed
) -> Dict[str, Any]:
    """
    Gzip an existing file if its extension is allowed.
    Default output replaces the original extension, e.g.:
      /path/file.txt -> /path/file.gz
    """

    in_path = Path(str(input_path)).expanduser()

    if not in_path.exists() or not in_path.is_file():
        return {"error": "gzip_input_not_found", "input_path": str(in_path)}

    allowed = _normalize_exts(allowed_extensions)
    if not allowed:
        return {"error": "gzip_allowed_extensions_empty"}

    in_ext = in_path.suffix.lower()  # ".txt"
    if in_ext not in allowed:
        return {
            "error": "gzip_extension_not_allowed",
            "input_path": str(in_path),
            "ext": in_ext,
            "allowed_extensions": sorted(allowed),
        }

    # Default: replace suffix (.txt -> .gz) instead of appending (.txt.gz)
    if output_path is None:
        out_path = in_path.with_suffix(".gz") if in_path.suffix else Path(str(in_path) + ".gz")
    else:
        out_path = Path(str(output_path)).expanduser()

    # Optional: enforce .gz extension when caller passes output_path
    if out_path.suffix.lower() != ".gz":
        return {"error": "gzip_output_must_end_with_gz", "output_path": str(out_path)}

    try:
        out_path.parent.mkdir(parents=True, exist_ok=True)

        bytes_in = in_path.stat().st_size

        # 1) Write .gz (streaming)
        with in_path.open("rb") as f_in, gzip.open(out_path, "wb", compresslevel=int(compresslevel)) as f_out:
            while True:
                chunk = f_in.read(1024 * 1024)
                if not chunk:
                    break
                f_out.write(chunk)

        bytes_out = out_path.stat().st_size

        # 2) Verify by reading the ENTIRE decompressed stream (CRC/trailer check)
        verified_ok = False
        if verify:
            try:
                with gzip.open(out_path, "rb") as f:
                    while f.read(1024 * 1024):
                        pass
                verified_ok = True
            except OSError as exc:
                return {
                    "error": "gzip_verify_failed",
                    "input_path": str(in_path),
                    "output_path": str(out_path),
                    "detail": str(exc),
                }
        else:
            verified_ok = True

        # 3) Remove original only after successful gzip + verify
        if remove_original_on_success:
            try:
                in_path.unlink()
            except Exception as exc:
                return {
                    "error": "gzip_remove_original_failed",
                    "input_path": str(in_path),
                    "output_path": str(out_path),
                    "detail": str(exc),
                }

        return {
            "ok": True,
            "input_path": str(in_path),
            "output_path": str(out_path),
            "bytes_in": bytes_in,
            "bytes_out": bytes_out,
            "verified": verified_ok,
            "removed_original": bool(remove_original_on_success),
        }

    except Exception as exc:
        return {"error": "gzip_failed", "input_path": str(in_path), "output_path": str(out_path), "detail": str(exc)}

def read_gz_text(
    *,
    gz_path: Union[str, Path],
    encoding: str = "utf-8",
    errors: str = "replace",
    max_bytes: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Read a .gz file and return its decompressed contents as text.
    """
    p = Path(str(gz_path)).expanduser()

    if not p.exists() or not p.is_file():
        return {"error": "gz_not_found", "path": str(p)}

    try:
        with gzip.open(p, "rb") as f:
            data = f.read(max_bytes) if max_bytes is not None else f.read()
        return {"ok": True, "path": str(p), "content": data.decode(encoding, errors=errors), "bytes_read": len(data)}
    except OSError as exc:
        return {"error": "gz_read_failed", "path": str(p), "detail": str(exc)}
    except Exception as exc:
        return {"error": "gz_unhandled_error", "path": str(p), "detail": str(exc)}