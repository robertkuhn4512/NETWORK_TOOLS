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

# -------------------------------------------------------------------
# Ensure Symfony writable dirs exist on the mounted var volume.
#
# Your container is read_only, so Symfony can only write under the
# /var/www/html/var volume. If the dev cache dir isn't pre-created,
# Symfony will fail with:
#   Unable to create the "cache" directory (/var/www/html/var/cache/dev).
# -------------------------------------------------------------------
SYMFONY_VAR_DIR="${SYMFONY_VAR_DIR:-/var/www/html/var}"
CACHE_DIR="${SYMFONY_VAR_DIR}/cache/${APP_ENV}"
LOG_DIR="${SYMFONY_VAR_DIR}/log"

umask 0002

# Make sure the paths exist (no-op if they already do)
mkdir -p "${CACHE_DIR}" "${LOG_DIR}"

# Best-effort perms so uid 82 (www-data) can write even if the volume
# was initialized as root-owned. Ignore failures if we don't have perms.
chmod -R u+rwX,g+rwX "${SYMFONY_VAR_DIR}" 2>/dev/null || true
find "${SYMFONY_VAR_DIR}" -type d -exec chmod 2770 {} + 2>/dev/null || true
find "${SYMFONY_VAR_DIR}" -type f -exec chmod 0660 {} + 2>/dev/null || true

echo "entrypoint_from_vault: ensured cache dir ${CACHE_DIR} (APP_ENV=${APP_ENV}, APP_DEBUG=${APP_DEBUG})"

exec "$@"
