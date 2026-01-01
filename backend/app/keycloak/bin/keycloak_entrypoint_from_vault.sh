#!/usr/bin/env bash
#------------------------------------------------------------------------------
# keycloak_entrypoint_from_vault.sh
#
# Notes / How to run
#   - Mount rendered secrets at /run/vault (read-only)
#   - Ensure /run/vault/keycloak.env exists (rendered by Vault Agent)
#   - Start Keycloak with:
#       entrypoint: ["/opt/keycloak/bin/keycloak_entrypoint_from_vault.sh"]
#       command: ["start"]
#------------------------------------------------------------------------------

set -euo pipefail

ENV_FILE="${KEYCLOAK_VAULT_ENV_FILE:-/run/vault/keycloak.env}"

if [[ ! -r "${ENV_FILE}" ]]; then
  echo "ERROR: Missing or unreadable Keycloak env file: ${ENV_FILE}" >&2
  exit 1
fi

# shellcheck disable=SC1090
set -a
. "${ENV_FILE}"
set +a

required_vars=(
  KC_DB
  KC_DB_URL_HOST
  KC_DB_URL_PORT
  KC_DB_URL_DATABASE
  KC_DB_USERNAME
  KC_DB_PASSWORD
  KC_BOOTSTRAP_ADMIN_USERNAME
  KC_BOOTSTRAP_ADMIN_PASSWORD
)

for v in "${required_vars[@]}"; do
  if [[ -z "${!v:-}" ]]; then
    echo "ERROR: Required variable ${v} is empty/missing (check Vault + template rendering)" >&2
    exit 1
  fi
done

# If these are not present in Vault, keep sane defaults.
: "${KC_HEALTH_ENABLED:=true}"
: "${KC_METRICS_ENABLED:=true}"
: "${KC_PROXY_HEADERS:=xforwarded}"


# Keycloak launcher: newer images use kc.sh; some older docs reference kc.
if [[ -x /opt/keycloak/bin/kc.sh ]]; then
  exec /opt/keycloak/bin/kc.sh "$@"
elif [[ -x /opt/keycloak/bin/kc ]]; then
  exec /opt/keycloak/bin/kc "$@"
else
  echo "ERROR: Could not find Keycloak launcher (expected /opt/keycloak/bin/kc.sh). Contents of /opt/keycloak/bin:" >&2
  ls -lah /opt/keycloak/bin >&2 || true
  exit 127
fi
