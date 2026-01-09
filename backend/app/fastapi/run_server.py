#!/usr/bin/env python3
"""
run_server.py

Notes / How to run
- Container entrypoint command should be:
    python /app/run_server.py
- This script delegates to vault_env_exec.py to:
  1) wait for /run/vault/fastapi_secrets.json
  2) inject all keys into environment
  3) exec Gunicorn with uvicorn worker

Env vars
- VAULT_SECRETS_JSON (default: /run/vault/fastapi_secrets.json)
- APP_MODULE (default: app.main:app)
- WEB_CONCURRENCY (default: 2)
- BIND_HOST (default: 0.0.0.0)
- BIND_PORT (default: 8000)
"""
import os
import sys

from vault_env_exec import main as vault_exec_main


def build_cmd() -> list[str]:
    app_module = os.getenv("APP_MODULE", "app.main:app")

    return [
        "gunicorn",
        "-c",
        "/app/gunicorn_conf.py",
        app_module,
    ]


if __name__ == "__main__":
    sys.argv = [sys.argv[0], *build_cmd()]
    raise SystemExit(vault_exec_main())
