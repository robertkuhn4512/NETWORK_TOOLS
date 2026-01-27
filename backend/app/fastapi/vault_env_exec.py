#!/usr/bin/env python3
"""
vault_env_exec.py

Notes / How to run
- This is not meant to be called by humans directly.
- It is used as a wrapper:
    python /app/vault_env_exec.py <cmd> [args...]
- It waits for VAULT_SECRETS_JSON (default: /run/vault/fastapi_secrets.json),
  loads it as a JSON object, exports ALL valid keys as environment variables,
  then exec()s the requested command.

Security
- This script does NOT print secret values.
- It only logs counts and file readiness.
"""
import json
import os
import re
import sys
import time
from typing import Dict, Any

VALID_ENV_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def wait_for_file(path: str, timeout_s: int) -> None:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if os.path.isfile(path) and os.path.getsize(path) > 0:
            return
        time.sleep(0.5)
    raise RuntimeError(f"Vault secrets file not ready: {path}")


def load_secrets(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("Vault secrets JSON must be a JSON object at top level")
    return data


def inject_env(secrets: Dict[str, Any]) -> int:
    injected = 0
    skipped = 0

    # Match helpers_logging_config semantics:
    # VAULT_ENV_OVERRIDE=1 means JSON wins (default)
    # VAULT_ENV_OVERRIDE=0 means keep existing env vars (Compose wins)
    override_existing = os.getenv("VAULT_ENV_OVERRIDE", "1").strip() == "1"

    for k, v in secrets.items():
        if not isinstance(k, str) or not VALID_ENV_KEY.match(k):
            skipped += 1
            continue

        if (k in os.environ) and (not override_existing):
            skipped += 1
            continue

        os.environ[k] = "" if v is None else str(v)
        injected += 1

    print(
        f"[vault_env_exec] injected={injected} skipped={skipped} override_existing={int(override_existing)}",
        flush=True,
    )
    return injected


def main() -> int:
    secrets_path = (
        os.getenv("VAULT_SECRETS_JSON")
        or "/run/vault/fastapi_secrets.json"
    )
    timeout_s = int(os.getenv("VAULT_WAIT_TIMEOUT", "90"))

    if len(sys.argv) < 2:
        print("usage: vault_env_exec.py <cmd> [args...]", file=sys.stderr)
        return 2

    print(f"[vault_env_exec] waiting_for={secrets_path} timeout={timeout_s}s", flush=True)
    wait_for_file(secrets_path, timeout_s)

    secrets = load_secrets(secrets_path)
    inject_env(secrets)

    cmd = sys.argv[1:]
    os.execvp(cmd[0], cmd)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
