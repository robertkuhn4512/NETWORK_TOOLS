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

# Map bootstrap vars (used by your templates) to the vars Keycloak actually consumes.
if [[ -z "${KEYCLOAK_ADMIN:-}" && -n "${KC_BOOTSTRAP_ADMIN_USERNAME:-}" ]]; then
  export KEYCLOAK_ADMIN="${KC_BOOTSTRAP_ADMIN_USERNAME}"
fi
if [[ -z "${KEYCLOAK_ADMIN_PASSWORD:-}" && -n "${KC_BOOTSTRAP_ADMIN_PASSWORD:-}" ]]; then
  export KEYCLOAK_ADMIN_PASSWORD="${KC_BOOTSTRAP_ADMIN_PASSWORD}"
fi

# Defaults aligned with "HTTP behind nginx (TLS termination)".
: "${KC_HTTP_ENABLED:=true}"
: "${KC_HTTP_PORT:=8080}"
: "${KC_PROXY_HEADERS:=xforwarded}"
: "${KC_HEALTH_ENABLED:=true}"
: "${KC_METRICS_ENABLED:=true}"
: "${KC_DB_URL_PROPERTIES:=sslmode=disable}"

# If we're intentionally HTTP-only, strip any HTTPS material that would force Keycloak
# to require cert/key files.
if [[ "${KC_HTTP_ENABLED}" == "true" || "${KC_HTTP_ENABLED}" == "TRUE" ]]; then
  unset KC_HTTPS_CERTIFICATE_FILE || true
  unset KC_HTTPS_CERTIFICATE_KEY_FILE || true
  unset KC_HTTPS_KEY_STORE_FILE || true
  unset KC_HTTPS_KEY_STORE_PASSWORD || true
  unset KC_HTTPS_TRUST_STORE_FILE || true
  unset KC_HTTPS_TRUST_STORE_PASSWORD || true
fi

required_vars=(
  KC_DB
  KC_DB_URL_HOST
  KC_DB_URL_PORT
  KC_DB_URL_DATABASE
  KC_DB_USERNAME
  KC_DB_PASSWORD
  KEYCLOAK_ADMIN
  KEYCLOAK_ADMIN_PASSWORD
)

for v in "${required_vars[@]}"; do
  if [[ -z "${!v:-}" ]]; then
    echo "ERROR: Required variable ${v} is empty/missing (check Vault + template rendering)" >&2
    exit 1
  fi
done

echo "INFO: Keycloak config summary:"
echo "  KC_HOSTNAME=${KC_HOSTNAME:-<unset>}"
echo "  KC_HTTP_ENABLED=${KC_HTTP_ENABLED} (port ${KC_HTTP_PORT})"
echo "  KC_PROXY_HEADERS=${KC_PROXY_HEADERS}"
echo "  KC_DB_URL_HOST=${KC_DB_URL_HOST}:${KC_DB_URL_PORT} db=${KC_DB_URL_DATABASE} (KC_DB_URL_PROPERTIES=${KC_DB_URL_PROPERTIES})"

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
