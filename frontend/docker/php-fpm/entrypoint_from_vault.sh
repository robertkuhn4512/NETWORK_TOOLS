#!/usr/bin/env bash
set -euo pipefail

# Prefer the path used by your PHP-FPM container mount.
SECRETS_ENV="${VAULT_SECRETS_ENV:-/run/vault/frontend.env}"

if [[ ! -r "${SECRETS_ENV}" ]]; then
  echo "ERROR: missing/unreadable Vault-rendered env file: ${SECRETS_ENV}" >&2
  ls -lha "$(dirname "${SECRETS_ENV}")" 2>/dev/null || true
  exit 1
fi

set -a
# shellcheck disable=SC1090
. "${SECRETS_ENV}"
set +a

APP_ENV="${APP_ENV:-prod}"
APP_DEBUG="${APP_DEBUG:-0}"

# ... keep the rest of your script unchanged ...
exec "$@"
