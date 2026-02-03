#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# Notes / How to run:
#   - This entrypoint is intended for the frontend PHP-FPM container.
#   - It loads Vault-rendered environment variables from VAULT_SECRETS_ENV
#     (default: /run/vault/frontend.env), then (optionally) resets Symfony runtime
#     state when switching between dev/prod builds, and finally (optionally)
#     clears/warms the Symfony cache before starting php-fpm.
#
#   - Typical php-fpm CMD:
#       ["php-fpm", "-F"]
#
# Runtime knobs (all optional; sensible defaults):
#   - SYMFONY_RESET_ON_FINGERPRINT_CHANGE=1   # default 1
#       If the runtime "fingerprint" changes (env + installed deps), wipe:
#         /var/www/html/var/cache/* and /var/www/html/var/log/*
#       This prevents stale caches compiled against different vendor deps when
#       you rebuild from dev -> prod (or vice versa) but keep the same var volume.
#
#   - SYMFONY_RESET_ALWAYS=0                  # default 0
#       If set to 1, always wipe cache/log on container start.
#
#   - SYMFONY_CACHE_WARMUP=1                  # default 0
#       If set to 1 and bin/console exists, run cache:clear + cache:warmup.
#
#   - SYMFONY_CACHE_WARMUP_ALWAYS=0           # default 0
#       If 1, run warmup on every start. If 0, run warmup once per cache dir
#       using a marker file in var/cache/<env>/.vault_warmup_done.
#
#   - SYMFONY_RUNTIME_REINSTALL_VENDOR=0      # default 0 (NOT recommended for prod)
#       If 1 and vendor/ is writable, run composer install at container start.
###############################################################################

SECRETS_ENV="${VAULT_SECRETS_ENV:-/run/vault/frontend.env}"

if [[ ! -r "${SECRETS_ENV}" ]]; then
  echo "ERROR: missing/unreadable Vault-rendered env file: ${SECRETS_ENV}" >&2
  ls -lha "$(dirname "${SECRETS_ENV}")" 2>/dev/null || true
  exit 1
fi

# Export env vars into this process (and therefore php-fpm master)
set -a
# shellcheck disable=SC1090
. "${SECRETS_ENV}"
set +a

# Symfony expects these in most deployments; ensure sane defaults if Vault omits them.
APP_ENV="${APP_ENV:-prod}"
APP_DEBUG="${APP_DEBUG:-0}"

# Make new runtime artifacts group-writable but not world-writable/readable.
umask 0007

APP_DIR="/var/www/html"
VAR_DIR="${APP_DIR}/var"
CACHE_ENV_DIR="${VAR_DIR}/cache/${APP_ENV}"
LOG_DIR="${VAR_DIR}/log"
FP_FILE="${VAR_DIR}/.symfony_runtime_fingerprint"
WARM_MARK="${CACHE_ENV_DIR}/.vault_warmup_done"

mkdir -p "${CACHE_ENV_DIR}" "${LOG_DIR}"

# Compute a fingerprint that changes when:
#   - APP_ENV/APP_DEBUG changes, OR
#   - Composer deps differ (vendor/composer/installed.json), OR
#   - composer.lock changes (less common across dev/prod but cheap to include)
LOCK_HASH="no-lock"
INST_HASH="no-installed"

if [[ -f "${APP_DIR}/composer.lock" ]]; then
  LOCK_HASH="$(sha256sum "${APP_DIR}/composer.lock" | awk '{print $1}')"
fi
if [[ -f "${APP_DIR}/vendor/composer/installed.json" ]]; then
  INST_HASH="$(sha256sum "${APP_DIR}/vendor/composer/installed.json" | awk '{print $1}')"
fi

FINGERPRINT="env=${APP_ENV};debug=${APP_DEBUG};lock=${LOCK_HASH};installed=${INST_HASH}"

_reset_var_dirs() {
  echo "INFO: resetting Symfony runtime dirs under ${VAR_DIR} ..."
  rm -rf "${VAR_DIR}/cache/"* "${VAR_DIR}/log/"* 2>/dev/null || true
  # remove any prior warmup markers
  find "${VAR_DIR}/cache" -maxdepth 3 -name ".vault_warmup_done" -type f -delete 2>/dev/null || true
  echo "${FINGERPRINT}" > "${FP_FILE}" 2>/dev/null || true
}

# Optional: reinstall vendor at runtime (only if writable). This is generally NOT
# what you want in prod; prefer rebuilding the image.
if [[ "${SYMFONY_RUNTIME_REINSTALL_VENDOR:-0}" == "1" ]]; then
  if command -v composer >/dev/null 2>&1 && [[ -w "${APP_DIR}/vendor" || ! -d "${APP_DIR}/vendor" ]]; then
    echo "INFO: SYMFONY_RUNTIME_REINSTALL_VENDOR=1 -> running composer install (env=${APP_ENV})..."
    if [[ "${APP_ENV}" == "prod" ]]; then
      COMPOSER_ALLOW_SUPERUSER=1 composer install --no-dev --prefer-dist --no-interaction --no-progress --optimize-autoloader
    else
      COMPOSER_ALLOW_SUPERUSER=1 composer install --prefer-dist --no-interaction --no-progress
    fi
  else
    echo "WARN: SYMFONY_RUNTIME_REINSTALL_VENDOR=1 but vendor/ isn't writable (or composer missing); skipping."
  fi
fi

# Reset cache/log when switching between dev/prod builds (vendor deps differ)
if [[ "${SYMFONY_RESET_ALWAYS:-0}" == "1" ]]; then
  _reset_var_dirs
else
  if [[ "${SYMFONY_RESET_ON_FINGERPRINT_CHANGE:-1}" == "1" ]]; then
    if [[ ! -f "${FP_FILE}" ]] || [[ "$(cat "${FP_FILE}" 2>/dev/null || true)" != "${FINGERPRINT}" ]]; then
      echo "INFO: runtime fingerprint changed -> wiping cache/log to prevent stale container issues"
      echo "INFO: new fingerprint: ${FINGERPRINT}"
      _reset_var_dirs
    fi
  fi
fi

# Optional cache warmup
if [[ "${SYMFONY_CACHE_WARMUP:-0}" == "1" && -x "${APP_DIR}/bin/console" ]]; then
  if [[ "${SYMFONY_CACHE_WARMUP_ALWAYS:-0}" == "1" ]]; then
    echo "INFO: warming Symfony cache (always) (env=${APP_ENV}, debug=${APP_DEBUG})..."
    php "${APP_DIR}/bin/console" cache:clear --no-warmup --env="${APP_ENV}" || true
    php "${APP_DIR}/bin/console" cache:warmup --env="${APP_ENV}" || true
  else
    if [[ ! -f "${WARM_MARK}" ]]; then
      echo "INFO: warming Symfony cache (env=${APP_ENV}, debug=${APP_DEBUG})..."
      php "${APP_DIR}/bin/console" cache:clear --no-warmup --env="${APP_ENV}" || true
      php "${APP_DIR}/bin/console" cache:warmup --env="${APP_ENV}" || true
      mkdir -p "$(dirname "${WARM_MARK}")" 2>/dev/null || true
      touch "${WARM_MARK}" 2>/dev/null || true
    else
      echo "INFO: cache warmup marker present; skipping warmup (set SYMFONY_CACHE_WARMUP_ALWAYS=1 to force)."
    fi
  fi
fi

exec "$@"
