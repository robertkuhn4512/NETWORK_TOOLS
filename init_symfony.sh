#!/usr/bin/env bash
set -euo pipefail

# -----------------------------------------------------------------------------
# init_symfony.sh
# Bootstrap / re-bootstrap the Symfony frontend project in ./frontend
#
# - Uses symfony/skeleton + symfony/webapp-pack (supported "full stack" path)
# - Removes Doctrine (frontend talks to FastAPI, no DB needed)
# - Preserves infra folders: ./frontend/docker and ./frontend/vault_agent
# - Preserves optional: ./frontend/public/healthz
#
# Notes:
# - This script DELETES most contents under ./frontend and replaces it with
#   the newly scaffolded project (except preserved infra folders).
# - Requires: php (8.4+), composer
# -----------------------------------------------------------------------------

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FRONTEND_DIR="${ROOT_DIR}/frontend"

if ! command -v composer >/dev/null 2>&1; then
  echo "ERROR: composer is not installed or not on PATH" >&2
  exit 1
fi

if ! command -v php >/dev/null 2>&1; then
  echo "ERROR: php is not installed or not on PATH" >&2
  exit 1
fi

cd "${FRONTEND_DIR}"

# 1) Preserve infra folders you already have
tmp_overlay="$(mktemp -d)"
cleanup() {
  rm -rf "${tmp_overlay}" "${tmp_symfony:-}"
}
trap cleanup EXIT

# Preserve only infra directories that should not overwrite Symfony scaffolding.
# (Do NOT preserve ./bin, ./src, ./config, etc.)
if [ -d docker ]; then
  cp -a docker "${tmp_overlay}/"
fi
if [ -d vault_agent ]; then
  cp -a vault_agent "${tmp_overlay}/"
fi

# Preserve healthz endpoint if present
if [ -f public/healthz ] || [ -d public/healthz ]; then
  mkdir -p "${tmp_overlay}/public"
  cp -a public/healthz "${tmp_overlay}/public/"
fi

# 2) Scaffold Symfony into a temp dir (Symfony 8.x)
tmp_symfony="$(mktemp -d)"
echo "Scaffolding Symfony into: ${tmp_symfony}"

# Base skeleton (version-pinnable)
composer create-project symfony/skeleton:"8.0.*" "${tmp_symfony}" --no-interaction --no-progress

cd "${tmp_symfony}"

# "Full stack" set (supported replacement for deprecated website-skeleton)
composer require symfony/webapp-pack --no-interaction --no-progress

# Ensure runtime exists (needed for bin/console autoload_runtime.php)
composer require symfony/runtime --no-interaction --no-progress

# Ensure HTTP client for Symfony -> Keycloak token calls and Symfony -> FastAPI requests
composer require symfony/http-client --no-interaction --no-progress

# Local scaffolding tools
composer require symfony/maker-bundle --dev --no-interaction --no-progress

# 3) Remove Doctrine (you said you don’t need it)
composer remove symfony/orm-pack doctrine/doctrine-bundle doctrine/orm doctrine/doctrine-migrations-bundle \
  --no-interaction --no-progress || true
rm -f config/packages/doctrine*.yaml config/routes/doctrine*.yaml || true

# 4) Replace ./frontend contents with the scaffold (restore overlay dirs after)
cd "${FRONTEND_DIR}"

# Wipe everything EXCEPT the preserved infra directories (docker/, vault_agent/)
find . -mindepth 1 -maxdepth 1 \
  ! -name docker \
  ! -name vault_agent \
  -exec rm -rf {} +

# Copy scaffold into ./frontend
cp -a "${tmp_symfony}/." .

# Restore infra dirs (overwrite with your versions)
if [ -d "${tmp_overlay}/docker" ]; then
  rm -rf docker
  cp -a "${tmp_overlay}/docker" .
fi
if [ -d "${tmp_overlay}/vault_agent" ]; then
  rm -rf vault_agent
  cp -a "${tmp_overlay}/vault_agent" .
fi

# Restore healthz if preserved
if [ -e "${tmp_overlay}/public/healthz" ]; then
  mkdir -p public
  rm -rf public/healthz
  cp -a "${tmp_overlay}/public/healthz" public/
fi

# 5) Install deps (creates vendor/)
composer install --no-interaction --no-progress

# 6) Verify console + maker works
php bin/console --version
php bin/console list make | head -n 40

echo
echo "OK: Symfony frontend initialized in ${FRONTEND_DIR}"
echo "Next: php bin/console make:controller Main"
