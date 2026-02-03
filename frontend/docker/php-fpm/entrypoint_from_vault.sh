#!/usr/bin/env bash
set -euo pipefail

# Notes / How to run:
# - This script is intended to be used as the container ENTRYPOINT for the Symfony PHP-FPM image.
# - It loads Vault-rendered environment variables (default: /run/vault/frontend.env),
#   prepares writable Symfony runtime directories, optionally warms the Symfony cache once,
#   then execs the container CMD (e.g., php-fpm -F).

SECRETS_ENV="${VAULT_SECRETS_ENV:-/run/vault/frontend.env}"

if [[ ! -s "${SECRETS_ENV}" ]]; then
  echo "ERROR: missing Vault-rendered env file: ${SECRETS_ENV}" >&2
  exit 1
fi

# Export env vars into this process (and therefore php-fpm master)
set -a
# shellcheck disable=SC1090
. "${SECRETS_ENV}"
set +a

APP_ENV="${APP_ENV:-prod}"
SYMFONY_CACHE_WARMUP="${SYMFONY_CACHE_WARMUP:-1}"

# Ensure writable runtime dirs exist (mounted from host in compose)
mkdir -p /var/www/html/var/cache /var/www/html/var/log
chown -R 82:82 /var/www/html/var || true

# Optional: warm Symfony cache once after Vault env is present.
# - Avoids running composer auto-scripts at build time (which often need APP_SECRET, etc.).
# - Guarded by a marker file inside var/cache/<env>/.
if [[ "${SYMFONY_CACHE_WARMUP}" == "1" && -x /var/www/html/bin/console ]]; then
  MARK="/var/www/html/var/cache/${APP_ENV}/.vault_warmup_done"
  if [[ ! -f "${MARK}" ]]; then
    echo "INFO: warming Symfony cache (env=${APP_ENV})..."
    # Best-effort: don't hard-fail container start if warmup trips on first boot.
    php /var/www/html/bin/console cache:clear --no-warmup --env="${APP_ENV}" || true
    php /var/www/html/bin/console cache:warmup --env="${APP_ENV}" || true
    mkdir -p "$(dirname "${MARK}")"
    touch "${MARK}" || true
  fi
fi

exec "$@"
