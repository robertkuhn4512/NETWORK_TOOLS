"""
Notes
-----
How to run:
- main.py should call, in this order:
    1) load_env_from_vault_json()
    2) setup_logging()
- Then any module/router uses:
    import logging
    logger = logging.getLogger(__name__)

Environment variables (preferably injected via /run/vault/fastapi_secrets.json):
  LOG_LEVEL=INFO|DEBUG|WARNING|ERROR
  LOG_TO_STDOUT=1|0
  LOG_DIR=/var/log/network_tools/fastapi
  LOG_FILE=network_tools_fastapi.log

Vault env loader controls:
  VAULT_ENV_JSON=/run/vault/fastapi_secrets.json
  VAULT_ENV_OVERRIDE=1|0        (default 1; JSON wins for keys it contains)
  VAULT_ENV_STRICT=1|0          (default 0; if 1, missing JSON is fatal)
"""

from __future__ import annotations

import json
import logging
import logging.config
import os
import sys
from pathlib import Path


_VAULT_ENV_LOADED = False


def load_env_from_vault_json(
    path: str | None = None,
    *,
    override_existing: bool | None = None,
    strict: bool | None = None,
) -> dict:
    """
    Load key/value pairs from Vault-rendered JSON into os.environ.

    - By default, JSON keys override existing env vars (for those keys).
    - If strict=True and file is missing/unreadable/invalid JSON, raises RuntimeError.

    Returns a small stats dict for debugging (safe: does not include values).
    """
    global _VAULT_ENV_LOADED

    if path is None:
        path = os.getenv("VAULT_ENV_JSON", "/run/vault/fastapi_secrets.json")

    if override_existing is None:
        override_existing = os.getenv("VAULT_ENV_OVERRIDE", "1").strip() == "1"

    if strict is None:
        strict = os.getenv("VAULT_ENV_STRICT", "0").strip() == "1"

    stats = {"path": path, "loaded": 0, "skipped": 0, "already_loaded": _VAULT_ENV_LOADED}

    # Avoid repeated reloads unless you explicitly want that behavior
    if _VAULT_ENV_LOADED:
        return stats

    p = Path(path)

    if not p.exists() or not p.is_file():
        msg = f"Vault env JSON not found/readable: {path}"
        if strict:
            raise RuntimeError(msg)
        print(f"[vault_env] WARN: {msg}", file=sys.stderr)
        return stats

    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("Vault env JSON must be an object/dict at top level")
    except Exception as exc:
        msg = f"Vault env JSON invalid: {path} ({exc})"
        if strict:
            raise RuntimeError(msg)
        print(f"[vault_env] WARN: {msg}", file=sys.stderr)
        return stats

    for k, v in data.items():
        # Only string keys; coerce values to strings to match env semantics
        if not isinstance(k, str):
            stats["skipped"] += 1
            continue

        if (k in os.environ) and (not override_existing):
            stats["skipped"] += 1
            continue

        os.environ[k] = "" if v is None else str(v)
        stats["loaded"] += 1

    _VAULT_ENV_LOADED = True
    #print(f"[vault_env] loaded={stats['loaded']} skipped={stats['skipped']} path={path}", file=sys.stderr)
    return stats


def setup_logging() -> None:
    """
    Configure logging using env vars (expected to be present via Vault env JSON).
    """
    level = os.getenv("LOG_LEVEL", "INFO").upper()
    log_to_stdout = os.getenv("LOG_TO_STDOUT", "1").strip() == "1"
    log_dir = os.getenv("LOG_DIR", "").strip()
    log_file = os.getenv("LOG_FILE", "network_tools_fastapi.log").strip()

    handlers: dict = {}
    root_handlers: list[str] = []

    if log_to_stdout:
        handlers["console"] = {
            "class": "logging.StreamHandler",
            "level": level,
            "formatter": "standard",
            "stream": sys.stdout,
        }
        root_handlers.append("console")

    if log_dir:
        Path(log_dir).mkdir(parents=True, exist_ok=True)
        handlers["file"] = {
            # Works well with host-side logrotate; avoids many multi-worker rotation issues.
            "class": "logging.handlers.WatchedFileHandler",
            "level": level,
            "formatter": "standard",
            "filename": str(Path(log_dir) / log_file),
        }
        root_handlers.append("file")

    if not root_handlers:
        raise RuntimeError("Logging misconfig: no handlers (set LOG_TO_STDOUT=1 and/or LOG_DIR)")

    config = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "standard": {
                "format": "%(asctime)s %(levelname)s %(name)s %(message)s",
                "datefmt": "%Y-%m-%d %H:%M:%S",
            },
        },
        "handlers": handlers,
        "root": {"level": level, "handlers": root_handlers},
        "loggers": {
            # Keep uvicorn/gunicorn consistent with your root handler set
            "uvicorn": {"level": level, "handlers": root_handlers, "propagate": False},
            "uvicorn.error": {"level": level, "handlers": root_handlers, "propagate": False},
            "uvicorn.access": {"level": level, "handlers": root_handlers, "propagate": False},
            "gunicorn": {"level": level, "handlers": root_handlers, "propagate": False},
            "gunicorn.error": {"level": level, "handlers": root_handlers, "propagate": False},
            "gunicorn.access": {"level": level, "handlers": root_handlers, "propagate": False},
        },
    }

    logging.config.dictConfig(config)


def setup_logging_for_router(logger_name: str) -> logging.Logger:
    """
    Backwards-compatible helper.
    Prefer: setup_logging(); then logging.getLogger(__name__) everywhere.
    """
    if not logging.getLogger().handlers:
        setup_logging()
    return logging.getLogger(logger_name)
