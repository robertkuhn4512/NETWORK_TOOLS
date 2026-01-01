#!/usr/bin/env bash
#------------------------------------------------------------------------------
# generate_postgres_pgadmin_bootstrap_creds_and_seed.sh (NO-PYTHON, VAULT-FETCH, APPLY)
#
# Notes / How to run
#
# 1) Standard first-time init (idempotent):
#    - In --mode generate (default), this script prefers EXISTING values:
#        A) Existing local bootstrap artifacts (postgres_pgadmin.env), else
#        B) Existing Vault KV values (if present), else
#        C) Generates new values.
#    - Then it seeds Vault (default) and writes artifacts.
#
#    cd "$HOME/NETWORK_TOOLS"
#    bash ./backend/build_scripts/generate_postgres_pgadmin_bootstrap_creds_and_seed.sh \
#      --vault-addr "https://vault_production_node:8200" \
#      --ca-cert "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt" \
#      --unseal-required 3
#
#    NOTE: If <bootstrap_dir>/root_token exists, the seed step will use it automatically.
#          Only use --prompt-token if you WANT to be prompted.
#
# 2) First-time init + apply DB objects (works even if Postgres is not running yet):
#    - Ensures credentials exist (load local or fetch Vault or generate+seed).
#    - Attempts to start postgres_primary (compose or docker start).
#    - Applies roles/db/schema inside Postgres to match Vault values.
#
#    bash ./backend/build_scripts/generate_postgres_pgadmin_bootstrap_creds_and_seed.sh \
#      --vault-addr "https://vault_production_node:8200" \
#      --ca-cert "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt" \
#      --unseal-required 3 \
#      --apply-to-postgres
#
# 3) Rotation (new passwords) + apply:
#    bash ./backend/build_scripts/generate_postgres_pgadmin_bootstrap_creds_and_seed.sh \
#      --mode rotate \
#      --vault-addr "https://vault_production_node:8200" \
#      --ca-cert "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt" \
#      --unseal-required 3 \
#      --apply-to-postgres
#
# This script is intentionally NO-PYTHON:
#   - Password generation uses openssl (or /dev/urandom + base64).
#   - JSON parsing/building uses jq.
#------------------------------------------------------------------------------

set -euo pipefail

log()  { printf '%s\n' "INFO: $*"; }
warn() { printf '%s\n' "WARN: $*" >&2; }
err()  { printf '%s\n' "ERROR: $*" >&2; exit 1; }

need_cmd() { command -v "$1" >/dev/null 2>&1 || err "Missing required command: $1"; }

# --- Defaults ---
ROOT_DIR="${HOME}/NETWORK_TOOLS"
BOOTSTRAP_DIR="${ROOT_DIR}/backend/app/security/configuration_files/vault/bootstrap"

# network_tools Postgres
POSTGRES_DB="network_tools"
POSTGRES_USER="network_tools_user"
POSTGRES_PASSWORD=""

# pgAdmin
PGADMIN_DEFAULT_EMAIL="admin@example.com"
PGADMIN_DEFAULT_PASSWORD=""

# Keycloak -> Postgres (seed for Keycloak service)
INCLUDE_KEYCLOAK=1
KEYCLOAK_DB_URL_HOST="postgres_primary"
KEYCLOAK_DB_URL_PORT="5432"
KEYCLOAK_DB_URL_DATABASE="keycloak"
KEYCLOAK_DB_USERNAME="keycloak"
KEYCLOAK_DB_PASSWORD=""
KEYCLOAK_DB_SCHEMA="keycloak"

# Keycloak bootstrap (initial admin) — stored in Vault at: keycloak_bootstrap
INCLUDE_KEYCLOAK_BOOTSTRAP=1
KEYCLOAK_BOOTSTRAP_ADMIN_USERNAME="admin"
KEYCLOAK_BOOTSTRAP_ADMIN_PASSWORD=""

# Keycloak runtime (hostname / server settings) — stored in Vault at: keycloak_runtime
INCLUDE_KEYCLOAK_RUNTIME=1

# Keycloak TLS material (cert/key/CA) — stored in Vault at: keycloak_tls
# - This script stores TLS material as BASE64 (single-line) to avoid newline/quoting issues.
# - By default, this does NOT store the CA private key (ca.key). Keep CA key offline/admin-only.
INCLUDE_KEYCLOAK_TLS=1
KEYCLOAK_TLS_REQUIRED=0
KEYCLOAK_TLS_DIR="${ROOT_DIR}/backend/app/keycloak/certs"
KEYCLOAK_TLS_CERT_FILE="cert.crt"
KEYCLOAK_TLS_KEY_FILE="cert.key"
KEYCLOAK_TLS_CA_FILE="ca.crt"

# Populated at runtime (base64 PEM)
KEYCLOAK_TLS_CERT_PEM_B64=""
KEYCLOAK_TLS_KEY_PEM_B64=""
KEYCLOAK_TLS_CA_PEM_B64=""

#This will need to change or be updated in the TLS certs if / when it's on a normal FQDN
KEYCLOAK_HOSTNAME="keycloak"
KEYCLOAK_HOSTNAME_STRICT="true"
KEYCLOAK_HTTP_ENABLED="false"
KEYCLOAK_HTTPS_PORT="8443"
KEYCLOAK_HEALTH_ENABLED="true"
KEYCLOAK_METRICS_ENABLED="true"
KEYCLOAK_HTTP_MANAGEMENT_PORT="9000"
KEYCLOAK_HTTP_MANAGEMENT_SCHEME="http"

# Vault KV v2
VAULT_MOUNT="app_postgres_secrets"
VAULT_PREFIX=""

# Vault connectivity
VAULT_ADDR="https://vault_production_node:8200"
CA_CERT=""
TLS_SKIP_VERIFY=0
UNSEAL_REQUIRED=3

PROMPT_TOKEN=0
TOKEN_FILE="${BOOTSTRAP_DIR}/root_token"

# Behavior toggles
MODE="generate"            # generate|rotate
SEED_VAULT=1
SEED_SCRIPT="${ROOT_DIR}/backend/build_scripts/vault_unseal_multi_kv_seed_bootstrap_rootless.sh"
APPLY_TO_POSTGRES=0

# Prefer existing artifacts on filesystem in generate mode (default ON)
PREFER_LOCAL=1
PREFER_VAULT=1

# Apply options
POSTGRES_CONTAINER="postgres_primary"
POSTGRES_ADMIN_DB="postgres"
AUTO_START_POSTGRES=1
COMPOSE_FILE="${ROOT_DIR}/docker-compose.prod.yml"
WAIT_POSTGRES_SECONDS=180

PRINT=0
PRINT_SECRETS=0

usage() {
  cat <<'USAGE'
Usage:
  generate_postgres_pgadmin_bootstrap_creds_and_seed.sh [options]

Modes:
  --mode <generate|rotate>       generate: prefer existing local/Vault values (default)
                                rotate:   generate NEW passwords (unless explicitly provided)

Local/Vault preference (generate mode):
  --no-prefer-local             Do not reuse existing postgres_pgadmin.env if present
  --no-prefer-vault             Do not reuse existing Vault KV values if present

Postgres (network_tools):
  --postgres-db <name>
  --postgres-user <name>
  --postgres-password <value>

pgAdmin:
  --pgadmin-default-email <val>
  --pgadmin-password <value>

Keycloak (Postgres-backed):
Keycloak (Postgres-backed):
  --no-keycloak
  --no-keycloak-bootstrap         Skip seeding keycloak_bootstrap
  --no-keycloak-runtime           Skip seeding keycloak_runtime

  # Database secret (Vault: keycloak_postgres)
  --keycloak-db-host <host>
  --keycloak-db-port <port>
  --keycloak-db <name>
  --keycloak-user <name>
  --keycloak-password <value>
  --keycloak-schema <name>

  # Bootstrap admin secret (Vault: keycloak_bootstrap)
  --keycloak-admin-user <name>
  --keycloak-admin-password <value>

  # Runtime secret (Vault: keycloak_runtime)
  --keycloak-hostname <fqdn>
  --keycloak-hostname-strict <true|false>
  --keycloak-http-enabled <true|false>
  --keycloak-https-port <port>
  --keycloak-health-enabled <true|false>
  --keycloak-metrics-enabled <true|false>
  --keycloak-management-port <port>
  --keycloak-management-scheme <http|https>


# TLS material (Vault: keycloak_tls)
# Stores PEM files as base64 (single line): cert.crt, cert.key, ca.crt
--no-keycloak-tls               Skip seeding Keycloak TLS material
--keycloak-tls-required         Fail if TLS files are missing and Vault has no TLS values
--keycloak-tls-dir <dir>        Default: $HOME/NETWORK_TOOLS/backend/app/keycloak/certs
--keycloak-tls-cert-file <fn>   Default: cert.crt
--keycloak-tls-key-file <fn>    Default: cert.key
--keycloak-tls-ca-file <fn>     Default: ca.crt

Vault / seeding:
  --vault-addr <url>
  --ca-cert <path>
  --tls-skip-verify
  --unseal-required <n>
  --prompt-token                 Force prompt for Vault token (otherwise uses --token-file if present)
  --token-file <path>
  --seed-script <path>
  --no-seed

Apply to Postgres:
  --apply-to-postgres
  --postgres-container <name>
  --postgres-admin-db <name>
  --compose-file <path>
  --no-auto-start-postgres
  --wait-postgres-seconds <n>

Printing:
  --print
  --print-secrets

USAGE
}

# --- Parse args ---
while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) MODE="${2:-}"; shift 2;;

    --no-prefer-local) PREFER_LOCAL=0; shift 1;;
    --no-prefer-vault) PREFER_VAULT=0; shift 1;;

    --postgres-db) POSTGRES_DB="${2:-}"; shift 2;;
    --postgres-user) POSTGRES_USER="${2:-}"; shift 2;;
    --postgres-password) POSTGRES_PASSWORD="${2:-}"; shift 2;;

    --pgadmin-default-email) PGADMIN_DEFAULT_EMAIL="${2:-}"; shift 2;;
    --pgadmin-password) PGADMIN_DEFAULT_PASSWORD="${2:-}"; shift 2;;

    --no-keycloak) INCLUDE_KEYCLOAK=0; shift 1;;
    --keycloak-db-host) KEYCLOAK_DB_URL_HOST="${2:-}"; shift 2;;
    --keycloak-db-port) KEYCLOAK_DB_URL_PORT="${2:-}"; shift 2;;
    --keycloak-db) KEYCLOAK_DB_URL_DATABASE="${2:-}"; shift 2;;
    --keycloak-user) KEYCLOAK_DB_USERNAME="${2:-}"; shift 2;;
    --keycloak-password) KEYCLOAK_DB_PASSWORD="${2:-}"; shift 2;;
    --keycloak-schema) KEYCLOAK_DB_SCHEMA="${2:-}"; shift 2;;

    --no-keycloak-bootstrap) INCLUDE_KEYCLOAK_BOOTSTRAP=0; shift 1;;
    --no-keycloak-runtime) INCLUDE_KEYCLOAK_RUNTIME=0; shift 1;;

    --keycloak-admin-user) KEYCLOAK_BOOTSTRAP_ADMIN_USERNAME="${2:-}"; shift 2;;
    --keycloak-admin-password) KEYCLOAK_BOOTSTRAP_ADMIN_PASSWORD="${2:-}"; shift 2;;

    --keycloak-hostname) KEYCLOAK_HOSTNAME="${2:-}"; shift 2;;
    --keycloak-hostname-strict) KEYCLOAK_HOSTNAME_STRICT="${2:-}"; shift 2;;
    --keycloak-http-enabled) KEYCLOAK_HTTP_ENABLED="${2:-}"; shift 2;;
    --keycloak-https-port) KEYCLOAK_HTTPS_PORT="${2:-}"; shift 2;;
    --keycloak-health-enabled) KEYCLOAK_HEALTH_ENABLED="${2:-}"; shift 2;;
    --keycloak-metrics-enabled) KEYCLOAK_METRICS_ENABLED="${2:-}"; shift 2;;
    --keycloak-management-port) KEYCLOAK_HTTP_MANAGEMENT_PORT="${2:-}"; shift 2;;
    --keycloak-management-scheme) KEYCLOAK_HTTP_MANAGEMENT_SCHEME="${2:-}"; shift 2;;


    --no-keycloak-tls) INCLUDE_KEYCLOAK_TLS=0; shift 1;;
    --keycloak-tls-required) KEYCLOAK_TLS_REQUIRED=1; shift 1;;
    --keycloak-tls-dir) KEYCLOAK_TLS_DIR="${2:-}"; shift 2;;
    --keycloak-tls-cert-file) KEYCLOAK_TLS_CERT_FILE="${2:-}"; shift 2;;
    --keycloak-tls-key-file) KEYCLOAK_TLS_KEY_FILE="${2:-}"; shift 2;;
    --keycloak-tls-ca-file) KEYCLOAK_TLS_CA_FILE="${2:-}"; shift 2;;

    --vault-addr) VAULT_ADDR="${2:-}"; shift 2;;
    --ca-cert) CA_CERT="${2:-}"; shift 2;;
    --tls-skip-verify) TLS_SKIP_VERIFY=1; shift 1;;
    --unseal-required) UNSEAL_REQUIRED="${2:-}"; shift 2;;
    --prompt-token) PROMPT_TOKEN=1; shift 1;;
    --token-file) TOKEN_FILE="${2:-}"; shift 2;;
    --seed-script) SEED_SCRIPT="${2:-}"; shift 2;;
    --no-seed) SEED_VAULT=0; shift 1;;
    --vault-prefix) VAULT_PREFIX="${2:-}"; shift 2;;

    --apply-to-postgres) APPLY_TO_POSTGRES=1; shift 1;;
    --postgres-container) POSTGRES_CONTAINER="${2:-}"; shift 2;;
    --postgres-admin-db) POSTGRES_ADMIN_DB="${2:-}"; shift 2;;
    --compose-file) COMPOSE_FILE="${2:-}"; shift 2;;
    --no-auto-start-postgres) AUTO_START_POSTGRES=0; shift 1;;
    --wait-postgres-seconds) WAIT_POSTGRES_SECONDS="${2:-}"; shift 2;;

    --print) PRINT=1; shift 1;;
    --print-secrets) PRINT_SECRETS=1; shift 1;;
    -h|--help) usage; exit 0;;
    *) err "Unknown argument: $1 (use --help)";;
  esac
done

[[ "${MODE}" == "generate" || "${MODE}" == "rotate" ]] || err "--mode must be generate|rotate"

need_cmd curl
need_cmd jq
need_cmd date
need_cmd mkdir
need_cmd chmod

# Secure perms for generated artifacts
umask 077
mkdir -p "${BOOTSTRAP_DIR}"

# --- Random generator (URL-safe) ---
gen_urlsafe() {
  local bytes="${1:-32}"
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -base64 "${bytes}" | tr '+/' '-_' | tr -d '=' | tr -d '\n'
    return 0
  fi
  if command -v base64 >/dev/null 2>&1; then
    dd if=/dev/urandom bs=1 count="${bytes}" 2>/dev/null | base64 | tr '+/' '-_' | tr -d '=' | tr -d '\n'
    return 0
  fi
  err "Need openssl or base64 to generate random strings."
}

b64_file_single_line() {
  # Base64-encode a file to a single line (no trailing newline).
  # Prefer openssl -A, otherwise base64 + strip newlines.
  local f="$1"
  [[ -f "${f}" ]] || return 1

  if command -v openssl >/dev/null 2>&1; then
    openssl base64 -A -in "${f}" 2>/dev/null || true
    return 0
  fi

  if command -v base64 >/dev/null 2>&1; then
    base64 < "${f}" | tr -d '
'
    return 0
  fi

  return 2
}

strip_quotes() {
  # Remove surrounding single/double quotes (one level) and trim whitespace.
  local v="${1:-}"
  v="${v#"${v%%[![:space:]]*}"}"
  v="${v%"${v##*[![:space:]]}"}"
  v="${v#\"}"; v="${v%\"}"
  v="${v#\'}"; v="${v%\'}"
  printf '%s' "${v}"
}

normalize_bool() {
  # Accept: true/false, "true"/"false", 'true'/'false', yes/no, y/n, 1/0
  local v
  v="$(strip_quotes "${1:-}")"
  v="$(printf '%s' "${v}" | tr '[:upper:]' '[:lower:]')"
  case "${v}" in
    true|false) printf '%s' "${v}"; return 0;;
    1|yes|y)    printf '%s' "true"; return 0;;
    0|no|n)     printf '%s' "false"; return 0;;
    *)          return 1;;
  esac
}

dotenv_get() {
  # Usage: dotenv_get <file> <KEY>
  local f="$1"
  local k="$2"
  [[ -f "${f}" ]] || return 1
  local line
  line="$(grep -E "^${k}=" "${f}" 2>/dev/null | head -n 1 || true)"
  [[ -n "${line}" ]] || return 1
  strip_quotes "$(printf '%s' "${line#${k}=}")"
}

ensure_keycloak_hostname() {
  # Prefer CLI -> existing value -> repo .env -> prompt
  [[ -n "${KEYCLOAK_HOSTNAME}" ]] && return 0

  local dotenv="${ROOT_DIR}/.env"
  local v=""

  v="$(dotenv_get "${dotenv}" "KEYCLOAK_HOSTNAME" 2>/dev/null || true)"
  [[ -z "${v}" ]] && v="$(dotenv_get "${dotenv}" "KC_HOSTNAME" 2>/dev/null || true)"
  [[ -z "${v}" ]] && v="$(dotenv_get "${dotenv}" "KEYCLOAK_FQDN" 2>/dev/null || true)"
  [[ -z "${v}" ]] && v="$(dotenv_get "${dotenv}" "KEYCLOAK_FQDN_FULL" 2>/dev/null || true)"

  if [[ -n "${v}" ]]; then
    KEYCLOAK_HOSTNAME="${v}"
    return 0
  fi

  read -r -p "Keycloak hostname (FQDN, e.g. keycloak.example.edu): " KEYCLOAK_HOSTNAME
  [[ -n "${KEYCLOAK_HOSTNAME}" ]] || return 1
  return 0
}

# -----------------------------------------------------------------------------
# Local artifact loading (filesystem bootstrap)
# -----------------------------------------------------------------------------
ENV_FILE="${BOOTSTRAP_DIR}/postgres_pgadmin.env"
JSON_FILE="${BOOTSTRAP_DIR}/postgres_pgadmin_credentials.json"
SPEC_FILE="${BOOTSTRAP_DIR}/seed_kv_spec.postgres_pgadmin.json"

load_env_value() {
  # Usage: load_env_value <file> <KEY>
  local f="$1"
  local k="$2"
  grep -E "^${k}=" "$f" 2>/dev/null | head -n 1 | cut -d= -f2- || true
}

load_from_local_env_if_present() {
  [[ -f "${ENV_FILE}" ]] || return 1

  local p_db p_user p_pass a_email a_pass
  p_db="$(load_env_value "${ENV_FILE}" "POSTGRES_DB")"
  p_user="$(load_env_value "${ENV_FILE}" "POSTGRES_USER")"
  p_pass="$(load_env_value "${ENV_FILE}" "POSTGRES_PASSWORD")"
  a_email="$(load_env_value "${ENV_FILE}" "PGADMIN_DEFAULT_EMAIL")"
  a_pass="$(load_env_value "${ENV_FILE}" "PGADMIN_DEFAULT_PASSWORD")"

  if [[ -n "${p_db}" && -n "${p_user}" && -n "${p_pass}" && -n "${a_email}" && -n "${a_pass}" ]]; then
    POSTGRES_DB="${p_db}"
    POSTGRES_USER="${p_user}"
    POSTGRES_PASSWORD="${p_pass}"
    PGADMIN_DEFAULT_EMAIL="${a_email}"
    PGADMIN_DEFAULT_PASSWORD="${a_pass}"
  else
    return 1
  fi

  if [[ "${INCLUDE_KEYCLOAK}" -eq 1 ]]; then
    local kc_host kc_port kc_db kc_user kc_pass kc_schema
    kc_host="$(load_env_value "${ENV_FILE}" "KC_DB_URL_HOST")"
    kc_port="$(load_env_value "${ENV_FILE}" "KC_DB_URL_PORT")"
    kc_db="$(load_env_value "${ENV_FILE}" "KC_DB_URL_DATABASE")"
    kc_user="$(load_env_value "${ENV_FILE}" "KC_DB_USERNAME")"
    kc_pass="$(load_env_value "${ENV_FILE}" "KC_DB_PASSWORD")"
    kc_schema="$(load_env_value "${ENV_FILE}" "KC_DB_SCHEMA")"

    # Keycloak bootstrap (optional)
    local kc_admin_user kc_admin_pass
    kc_admin_user="$(load_env_value "${ENV_FILE}" "KC_BOOTSTRAP_ADMIN_USERNAME")"
    kc_admin_pass="$(load_env_value "${ENV_FILE}" "KC_BOOTSTRAP_ADMIN_PASSWORD")"
    [[ -n "${kc_admin_user}" ]] && KEYCLOAK_BOOTSTRAP_ADMIN_USERNAME="${kc_admin_user}"
    [[ -n "${kc_admin_pass}" ]] && KEYCLOAK_BOOTSTRAP_ADMIN_PASSWORD="${kc_admin_pass}"

    # Keycloak runtime (optional)
    local kc_hostname kc_hostname_strict kc_http_enabled kc_https_port kc_health kc_metrics kc_mgmt_port kc_mgmt_scheme
    kc_hostname="$(load_env_value "${ENV_FILE}" "KC_HOSTNAME")"
    kc_hostname_strict="$(load_env_value "${ENV_FILE}" "KC_HOSTNAME_STRICT")"
    kc_http_enabled="$(load_env_value "${ENV_FILE}" "KC_HTTP_ENABLED")"
    kc_https_port="$(load_env_value "${ENV_FILE}" "KC_HTTPS_PORT")"
    kc_health="$(load_env_value "${ENV_FILE}" "KC_HEALTH_ENABLED")"
    kc_metrics="$(load_env_value "${ENV_FILE}" "KC_METRICS_ENABLED")"
    kc_mgmt_port="$(load_env_value "${ENV_FILE}" "KC_HTTP_MANAGEMENT_PORT")"
    kc_mgmt_scheme="$(load_env_value "${ENV_FILE}" "KC_HTTP_MANAGEMENT_SCHEME")"

    [[ -n "${kc_hostname}" ]] && KEYCLOAK_HOSTNAME="${kc_hostname}"
    [[ -n "${kc_hostname_strict}" ]] && KEYCLOAK_HOSTNAME_STRICT="${kc_hostname_strict}"
    [[ -n "${kc_http_enabled}" ]] && KEYCLOAK_HTTP_ENABLED="${kc_http_enabled}"
    [[ -n "${kc_https_port}" ]] && KEYCLOAK_HTTPS_PORT="${kc_https_port}"
    [[ -n "${kc_health}" ]] && KEYCLOAK_HEALTH_ENABLED="${kc_health}"
    [[ -n "${kc_metrics}" ]] && KEYCLOAK_METRICS_ENABLED="${kc_metrics}"
    [[ -n "${kc_mgmt_port}" ]] && KEYCLOAK_HTTP_MANAGEMENT_PORT="${kc_mgmt_port}"
    [[ -n "${kc_mgmt_scheme}" ]] && KEYCLOAK_HTTP_MANAGEMENT_SCHEME="${kc_mgmt_scheme}"

    if [[ -n "${kc_db}" && -n "${kc_user}" && -n "${kc_pass}" ]]; then
      [[ -n "${kc_host}" ]] && KEYCLOAK_DB_URL_HOST="${kc_host}"
      [[ -n "${kc_port}" ]] && KEYCLOAK_DB_URL_PORT="${kc_port}"
      KEYCLOAK_DB_URL_DATABASE="${kc_db}"
      KEYCLOAK_DB_USERNAME="${kc_user}"
      KEYCLOAK_DB_PASSWORD="${kc_pass}"
      [[ -n "${kc_schema}" ]] && KEYCLOAK_DB_SCHEMA="${kc_schema}"
    fi
  fi

  return 0
}

load_keycloak_tls_from_local_files_if_present() {
  # Loads Keycloak TLS PEM material from files and stores as base64 (single line).
  # Requires: cert + key. CA is optional.
  [[ "${INCLUDE_KEYCLOAK}" -eq 1 ]] || return 1
  [[ "${INCLUDE_KEYCLOAK_TLS}" -eq 1 ]] || return 1

  local dir="${KEYCLOAK_TLS_DIR}"
  local crt="${dir%/}/${KEYCLOAK_TLS_CERT_FILE}"
  local key="${dir%/}/${KEYCLOAK_TLS_KEY_FILE}"
  local ca="${dir%/}/${KEYCLOAK_TLS_CA_FILE}"

  [[ -f "${crt}" ]] || return 1
  [[ -f "${key}" ]] || return 1

  KEYCLOAK_TLS_CERT_PEM_B64="$(b64_file_single_line "${crt}" || true)"
  KEYCLOAK_TLS_KEY_PEM_B64="$(b64_file_single_line "${key}" || true)"

  if [[ -f "${ca}" ]]; then
    KEYCLOAK_TLS_CA_PEM_B64="$(b64_file_single_line "${ca}" || true)"
  else
    KEYCLOAK_TLS_CA_PEM_B64=""
  fi

  [[ -n "${KEYCLOAK_TLS_CERT_PEM_B64}" && -n "${KEYCLOAK_TLS_KEY_PEM_B64}" ]] || return 2
  return 0
}

# -----------------------------------------------------------------------------
# Vault helpers (KV v2 HTTP API) — no python
# -----------------------------------------------------------------------------
VAULT_TOKEN=""

vault_token_acquire_if_needed() {
  # Only acquire token if we will interact with Vault (fetch or seed).
  # Seed script can also prompt; we keep behavior consistent here.
  if [[ -n "${VAULT_TOKEN}" ]]; then
    return 0
  fi

  if [[ "${PROMPT_TOKEN}" -eq 1 ]]; then
    read -r -s -p "Vault token (input hidden): " VAULT_TOKEN
    echo ""
  else
    if [[ -f "${TOKEN_FILE}" ]]; then
      VAULT_TOKEN="$(tr -d '\r\n' < "${TOKEN_FILE}")"
    else
      # Do not prompt here unless we actually need Vault; caller decides.
      return 1
    fi
  fi

  [[ -n "${VAULT_TOKEN}" ]] || return 1
  return 0
}

vault_curl() {
  local method="$1"
  local path="$2"
  local payload="${3:-}"
  local url="${VAULT_ADDR%/}/v1/${path#/}"

  local args=( -sS -X "${method}" -H "Accept: application/json" -H "X-Vault-Token: ${VAULT_TOKEN}" )
  if [[ -n "${payload}" ]]; then
    args+=( -H "Content-Type: application/json" --data "${payload}" )
  fi

  if [[ -n "${CA_CERT}" ]]; then
    args+=( --cacert "${CA_CERT}" )
  elif [[ "${TLS_SKIP_VERIFY}" -eq 1 ]]; then
    args+=( -k )
  else
    err "No --ca-cert provided and --tls-skip-verify not set. Refusing insecure Vault call."
  fi

  curl "${args[@]}" "${url}"
}

prefixed_path() {
  local p="$1"
  if [[ -n "${VAULT_PREFIX}" ]]; then
    printf '%s' "${VAULT_PREFIX%/}/${p}"
  else
    printf '%s' "${p}"
  fi
}

vault_kv2_get_data_json() {
  # Prints KV v2 data.data as JSON, or returns non-zero.
  local mount="$1"
  local path="$2"
  local resp
  resp="$(vault_curl GET "${mount}/data/${path}")" || return 1
  echo "${resp}" | jq -e '.data.data' >/dev/null 2>&1 || return 2
  echo "${resp}" | jq -c '.data.data'
}

vault_try_load_from_vault() {
  # Only used in generate mode when prefer vault and token is available.
  vault_token_acquire_if_needed || return 1

  local postgres_path pgadmin_path keycloak_path
  postgres_path="$(prefixed_path "postgres")"
  pgadmin_path="$(prefixed_path "pgadmin")"
  keycloak_path="$(prefixed_path "keycloak_postgres")"

  # Postgres
  if data="$(vault_kv2_get_data_json "${VAULT_MOUNT}" "${postgres_path}" 2>/dev/null || true)"; then
    echo "${data}" | jq -e '.POSTGRES_DB and .POSTGRES_USER and .POSTGRES_PASSWORD' >/dev/null 2>&1 && {
      POSTGRES_DB="$(echo "${data}" | jq -r '.POSTGRES_DB')"
      POSTGRES_USER="$(echo "${data}" | jq -r '.POSTGRES_USER')"
      POSTGRES_PASSWORD="$(echo "${data}" | jq -r '.POSTGRES_PASSWORD')"
      log "Using existing Vault secret for network_tools Postgres: ${VAULT_MOUNT}/${postgres_path}"
    }
  fi

  # pgAdmin
  if data="$(vault_kv2_get_data_json "${VAULT_MOUNT}" "${pgadmin_path}" 2>/dev/null || true)"; then
    echo "${data}" | jq -e '.PGADMIN_DEFAULT_EMAIL and .PGADMIN_DEFAULT_PASSWORD' >/dev/null 2>&1 && {
      PGADMIN_DEFAULT_EMAIL="$(echo "${data}" | jq -r '.PGADMIN_DEFAULT_EMAIL')"
      PGADMIN_DEFAULT_PASSWORD="$(echo "${data}" | jq -r '.PGADMIN_DEFAULT_PASSWORD')"
      log "Using existing Vault secret for pgAdmin: ${VAULT_MOUNT}/${pgadmin_path}"
    }
  fi

  # Keycloak
  if [[ "${INCLUDE_KEYCLOAK}" -eq 1 ]]; then
    if data="$(vault_kv2_get_data_json "${VAULT_MOUNT}" "${keycloak_path}" 2>/dev/null || true)"; then
      # Require minimum fields
      echo "${data}" | jq -e '.KC_DB_URL_DATABASE and .KC_DB_USERNAME and .KC_DB_PASSWORD' >/dev/null 2>&1 && {
        KEYCLOAK_DB_URL_DATABASE="$(echo "${data}" | jq -r '.KC_DB_URL_DATABASE')"
        KEYCLOAK_DB_USERNAME="$(echo "${data}" | jq -r '.KC_DB_USERNAME')"
        KEYCLOAK_DB_PASSWORD="$(echo "${data}" | jq -r '.KC_DB_PASSWORD')"
        KEYCLOAK_DB_SCHEMA="$(echo "${data}" | jq -r '.KC_DB_SCHEMA // "keycloak"')"
        KEYCLOAK_DB_URL_HOST="$(echo "${data}" | jq -r '.KC_DB_URL_HOST // "postgres_primary"')"
        KEYCLOAK_DB_URL_PORT="$(echo "${data}" | jq -r '.KC_DB_URL_PORT // "5432"')"
        log "Using existing Vault secret for Keycloak Postgres: ${VAULT_MOUNT}/${keycloak_path}"
      }
    fi
  fi

  return 0
}

vault_try_load_keycloak_extras_from_vault() {
  [[ "${INCLUDE_KEYCLOAK}" -eq 1 ]] || return 0
  vault_token_acquire_if_needed || return 1

  local bootstrap_path runtime_path
  bootstrap_path="$(prefixed_path "keycloak_bootstrap")"
  runtime_path="$(prefixed_path "keycloak_runtime")"

  local data

  if [[ "${INCLUDE_KEYCLOAK_BOOTSTRAP}" -eq 1 ]]; then
    if data="$(vault_kv2_get_data_json "${VAULT_MOUNT}" "${bootstrap_path}" 2>/dev/null || true)"; then
      echo "${data}" | jq -e '.KC_BOOTSTRAP_ADMIN_USERNAME and .KC_BOOTSTRAP_ADMIN_PASSWORD' >/dev/null 2>&1 && {
        [[ -n "${KEYCLOAK_BOOTSTRAP_ADMIN_USERNAME}" ]] || KEYCLOAK_BOOTSTRAP_ADMIN_USERNAME="$(echo "${data}" | jq -r '.KC_BOOTSTRAP_ADMIN_USERNAME')"
        [[ -n "${KEYCLOAK_BOOTSTRAP_ADMIN_PASSWORD}" ]] || KEYCLOAK_BOOTSTRAP_ADMIN_PASSWORD="$(echo "${data}" | jq -r '.KC_BOOTSTRAP_ADMIN_PASSWORD')"
        log "Using existing Vault secret for Keycloak bootstrap: ${VAULT_MOUNT}/${bootstrap_path}"
      }
    fi
  fi

  if [[ "${INCLUDE_KEYCLOAK_RUNTIME}" -eq 1 ]]; then
    if data="$(vault_kv2_get_data_json "${VAULT_MOUNT}" "${runtime_path}" 2>/dev/null || true)"; then
      echo "${data}" | jq -e '.KC_HOSTNAME' >/dev/null 2>&1 && {
        [[ -n "${KEYCLOAK_HOSTNAME}" ]] || KEYCLOAK_HOSTNAME="$(echo "${data}" | jq -r '.KC_HOSTNAME')"
        [[ -n "${KEYCLOAK_HOSTNAME_STRICT}" ]] || KEYCLOAK_HOSTNAME_STRICT="$(echo "${data}" | jq -r '.KC_HOSTNAME_STRICT // "true"')"
        [[ -n "${KEYCLOAK_HTTP_ENABLED}" ]] || KEYCLOAK_HTTP_ENABLED="$(echo "${data}" | jq -r '.KC_HTTP_ENABLED // "false"')"
        [[ -n "${KEYCLOAK_HTTPS_PORT}" ]] || KEYCLOAK_HTTPS_PORT="$(echo "${data}" | jq -r '.KC_HTTPS_PORT // "8443"')"
        [[ -n "${KEYCLOAK_HEALTH_ENABLED}" ]] || KEYCLOAK_HEALTH_ENABLED="$(echo "${data}" | jq -r '.KC_HEALTH_ENABLED // "true"')"
        [[ -n "${KEYCLOAK_METRICS_ENABLED}" ]] || KEYCLOAK_METRICS_ENABLED="$(echo "${data}" | jq -r '.KC_METRICS_ENABLED // "true"')"
        [[ -n "${KEYCLOAK_HTTP_MANAGEMENT_PORT}" ]] || KEYCLOAK_HTTP_MANAGEMENT_PORT="$(echo "${data}" | jq -r '.KC_HTTP_MANAGEMENT_PORT // "9000"')"
        [[ -n "${KEYCLOAK_HTTP_MANAGEMENT_SCHEME}" ]] || KEYCLOAK_HTTP_MANAGEMENT_SCHEME="$(echo "${data}" | jq -r '.KC_HTTP_MANAGEMENT_SCHEME // "http"')"
        log "Using existing Vault secret for Keycloak runtime: ${VAULT_MOUNT}/${runtime_path}"
      }
    fi
  fi

  return 0
}
vault_try_load_keycloak_tls_from_vault() {
  # Attempts to load Keycloak TLS (base64 PEM) from Vault path: keycloak_tls
  # Expected keys:
  #   - KC_HTTPS_CERTIFICATE_PEM_B64
  #   - KC_HTTPS_CERTIFICATE_KEY_PEM_B64
  #   - KC_HTTPS_CA_CERT_PEM_B64 (optional)
  [[ "${INCLUDE_KEYCLOAK}" -eq 1 ]] || return 0
  [[ "${INCLUDE_KEYCLOAK_TLS}" -eq 1 ]] || return 0

  vault_token_acquire_if_needed || return 1

  local tls_path data
  tls_path="$(prefixed_path keycloak_tls)"

  # If the secret doesn't exist yet, kv2 read returns non-zero; treat that as "not present".
  data="$(vault_kv2_get_data_json "${VAULT_MOUNT}" "${tls_path}" 2>/dev/null || true)"
  [[ -n "${data}" ]] || return 0

  local crt key ca
  crt="$(jq -r '.KC_HTTPS_CERTIFICATE_PEM_B64 // ""' <<<"${data}")"
  key="$(jq -r '.KC_HTTPS_CERTIFICATE_KEY_PEM_B64 // ""' <<<"${data}")"
  ca="$(jq -r '.KC_HTTPS_CA_CERT_PEM_B64 // ""' <<<"${data}")"

  if [[ -n "${crt}" && -n "${key}" ]]; then
    KEYCLOAK_TLS_CERT_PEM_B64="${crt}"
    KEYCLOAK_TLS_KEY_PEM_B64="${key}"
    KEYCLOAK_TLS_CA_PEM_B64="${ca}"
    log "Using existing Vault secret for Keycloak TLS: ${VAULT_MOUNT}/${tls_path}"
  fi

  return 0
}


# -----------------------------------------------------------------------------
# Resolve credentials
# -----------------------------------------------------------------------------
LOCAL_LOADED=0
if [[ "${MODE}" == "generate" && "${PREFER_LOCAL}" -eq 1 ]]; then
  if load_from_local_env_if_present; then
    LOCAL_LOADED=1
    log "Using existing local bootstrap artifacts: ${ENV_FILE}"
  fi
fi

# In generate mode, if we didn't load local and prefer vault, try vault
if [[ "${MODE}" == "generate" && "${LOCAL_LOADED}" -eq 0 && "${PREFER_VAULT}" -eq 1 ]]; then
  vault_try_load_from_vault || true
fi

# Even if local artifacts were loaded, Keycloak runtime/bootstrap may still live only in Vault.
if [[ "${MODE}" == "generate" && "${PREFER_VAULT}" -eq 1 && "${INCLUDE_KEYCLOAK}" -eq 1 ]]; then
  vault_try_load_keycloak_extras_from_vault || true
  vault_try_load_keycloak_tls_from_vault || true
fi

# Generate missing values (or new ones on rotate)
if [[ "${MODE}" == "rotate" ]]; then
  # Rotate passwords; keep names from args/defaults (or from local/Vault load if present)
  POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-$(gen_urlsafe 32)}"
  PGADMIN_DEFAULT_PASSWORD="${PGADMIN_DEFAULT_PASSWORD:-$(gen_urlsafe 32)}"
  if [[ "${INCLUDE_KEYCLOAK}" -eq 1 ]]; then
    KEYCLOAK_DB_PASSWORD="${KEYCLOAK_DB_PASSWORD:-$(gen_urlsafe 32)}"
  fi
else
  [[ -n "${POSTGRES_PASSWORD}" ]] || POSTGRES_PASSWORD="$(gen_urlsafe 32)"
  [[ -n "${PGADMIN_DEFAULT_PASSWORD}" ]] || PGADMIN_DEFAULT_PASSWORD="$(gen_urlsafe 32)"
  if [[ "${INCLUDE_KEYCLOAK}" -eq 1 ]]; then
    [[ -n "${KEYCLOAK_DB_PASSWORD}" ]] || KEYCLOAK_DB_PASSWORD="$(gen_urlsafe 32)"
  fi
fi

# Keycloak bootstrap/runtime defaults (and validation)
if [[ "${INCLUDE_KEYCLOAK}" -eq 1 ]]; then
  if [[ "${INCLUDE_KEYCLOAK_BOOTSTRAP}" -eq 1 ]]; then
    [[ -n "${KEYCLOAK_BOOTSTRAP_ADMIN_USERNAME}" ]] || KEYCLOAK_BOOTSTRAP_ADMIN_USERNAME="admin"
    if [[ "${MODE}" == "rotate" ]]; then
      KEYCLOAK_BOOTSTRAP_ADMIN_PASSWORD="${KEYCLOAK_BOOTSTRAP_ADMIN_PASSWORD:-$(gen_urlsafe 32)}"
    else
      [[ -n "${KEYCLOAK_BOOTSTRAP_ADMIN_PASSWORD}" ]] || KEYCLOAK_BOOTSTRAP_ADMIN_PASSWORD="$(gen_urlsafe 32)"
    fi
  fi

  if [[ "${INCLUDE_KEYCLOAK_RUNTIME}" -eq 1 ]]; then
    # Ensure hostname exists (prefer existing value -> .env -> prompt)
    ensure_keycloak_hostname || err "Keycloak hostname is required to seed keycloak_runtime."

    # Normalize booleans and apply defaults
    KEYCLOAK_HOSTNAME_STRICT="$(normalize_bool "${KEYCLOAK_HOSTNAME_STRICT}" 2>/dev/null || true)"
    [[ -n "${KEYCLOAK_HOSTNAME_STRICT}" ]] || err "Invalid boolean for --keycloak-hostname-strict (expected true|false)."

    KEYCLOAK_HTTP_ENABLED="$(normalize_bool "${KEYCLOAK_HTTP_ENABLED}" 2>/dev/null || true)"
    [[ -n "${KEYCLOAK_HTTP_ENABLED}" ]] || err "Invalid boolean for --keycloak-http-enabled (expected true|false)."

    KEYCLOAK_HEALTH_ENABLED="$(normalize_bool "${KEYCLOAK_HEALTH_ENABLED}" 2>/dev/null || true)"
    [[ -n "${KEYCLOAK_HEALTH_ENABLED}" ]] || err "Invalid boolean for --keycloak-health-enabled (expected true|false)."

    KEYCLOAK_METRICS_ENABLED="$(normalize_bool "${KEYCLOAK_METRICS_ENABLED}" 2>/dev/null || true)"
    [[ -n "${KEYCLOAK_METRICS_ENABLED}" ]] || err "Invalid boolean for --keycloak-metrics-enabled (expected true|false)."

    [[ -n "${KEYCLOAK_HTTPS_PORT}" ]] || KEYCLOAK_HTTPS_PORT="8443"
    [[ -n "${KEYCLOAK_HTTP_MANAGEMENT_PORT}" ]] || KEYCLOAK_HTTP_MANAGEMENT_PORT="9000"
    [[ -n "${KEYCLOAK_HTTP_MANAGEMENT_SCHEME}" ]] || KEYCLOAK_HTTP_MANAGEMENT_SCHEME="http"

    case "${KEYCLOAK_HTTP_MANAGEMENT_SCHEME}" in
      http|https) : ;;
      *) err "Invalid --keycloak-management-scheme (expected http|https).";;
    esac
  fi
fi

# -----------------------------------------------------------------------------
# -----------------------------------------------------------------------------
# Keycloak TLS (optional)
# -----------------------------------------------------------------------------
KEYCLOAK_TLS_PRESENT=0
if [[ "${INCLUDE_KEYCLOAK}" -eq 1 && "${INCLUDE_KEYCLOAK_TLS}" -eq 1 ]]; then
  # Prefer local files if present (so generate_local_keycloak_certs.sh output can be seeded).
  if load_keycloak_tls_from_local_files_if_present; then
    KEYCLOAK_TLS_PRESENT=1
    log "Loaded Keycloak TLS material from local files: ${KEYCLOAK_TLS_DIR}"
  elif [[ -n "${KEYCLOAK_TLS_CERT_PEM_B64}" && -n "${KEYCLOAK_TLS_KEY_PEM_B64}" ]]; then
    KEYCLOAK_TLS_PRESENT=1
    log "Keycloak TLS material is available from Vault: ${VAULT_MOUNT}/$(prefixed_path keycloak_tls)"
  else
    if [[ "${KEYCLOAK_TLS_REQUIRED}" -eq 1 ]]; then
      err "Keycloak TLS required but not found. Expected files: ${KEYCLOAK_TLS_DIR}/{${KEYCLOAK_TLS_CERT_FILE},${KEYCLOAK_TLS_KEY_FILE}} or existing Vault secret ${VAULT_MOUNT}/$(prefixed_path keycloak_tls)"
    fi
    warn "Keycloak TLS material not found; skipping keycloak_tls seeding."
  fi
fi

# Write artifacts (env/json/spec) — no python; use jq to build JSON
# -----------------------------------------------------------------------------
cat > "${ENV_FILE}" <<EOF
# Generated: $(date -u +'%Y-%m-%dT%H:%M:%SZ')
# Store securely. Do not commit.

# network_tools Postgres
POSTGRES_DB=${POSTGRES_DB}
POSTGRES_USER=${POSTGRES_USER}
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}

# pgAdmin
PGADMIN_DEFAULT_EMAIL=${PGADMIN_DEFAULT_EMAIL}
PGADMIN_DEFAULT_PASSWORD=${PGADMIN_DEFAULT_PASSWORD}
EOF

if [[ "${INCLUDE_KEYCLOAK}" -eq 1 ]]; then
  cat >> "${ENV_FILE}" <<EOF

# Keycloak (Postgres-backed) — database
KC_DB=postgres
KC_DB_URL_HOST=${KEYCLOAK_DB_URL_HOST}
KC_DB_URL_PORT=${KEYCLOAK_DB_URL_PORT}
KC_DB_URL_DATABASE=${KEYCLOAK_DB_URL_DATABASE}
KC_DB_USERNAME=${KEYCLOAK_DB_USERNAME}
KC_DB_PASSWORD=${KEYCLOAK_DB_PASSWORD}
KC_DB_SCHEMA=${KEYCLOAK_DB_SCHEMA}
EOF

  if [[ "${INCLUDE_KEYCLOAK_BOOTSTRAP}" -eq 1 ]]; then
    cat >> "${ENV_FILE}" <<EOF

# Keycloak bootstrap (initial admin)
KC_BOOTSTRAP_ADMIN_USERNAME=${KEYCLOAK_BOOTSTRAP_ADMIN_USERNAME}
KC_BOOTSTRAP_ADMIN_PASSWORD=${KEYCLOAK_BOOTSTRAP_ADMIN_PASSWORD}
EOF
  fi

  if [[ "${INCLUDE_KEYCLOAK_RUNTIME}" -eq 1 ]]; then
    cat >> "${ENV_FILE}" <<EOF

# Keycloak runtime (hostname / server settings)
KC_HOSTNAME=${KEYCLOAK_HOSTNAME}
KC_HOSTNAME_STRICT=${KEYCLOAK_HOSTNAME_STRICT}
KC_HTTP_ENABLED=${KEYCLOAK_HTTP_ENABLED}
KC_HTTPS_PORT=${KEYCLOAK_HTTPS_PORT}
KC_HEALTH_ENABLED=${KEYCLOAK_HEALTH_ENABLED}
KC_METRICS_ENABLED=${KEYCLOAK_METRICS_ENABLED}
KC_HTTP_MANAGEMENT_PORT=${KEYCLOAK_HTTP_MANAGEMENT_PORT}
KC_HTTP_MANAGEMENT_SCHEME=${KEYCLOAK_HTTP_MANAGEMENT_SCHEME}
EOF
  fi
fi

# Credentials JSON
if [[ "${INCLUDE_KEYCLOAK}" -eq 1 ]]; then
  jq -n     --arg generated_at_utc "$(date -u +'%Y-%m-%dT%H:%M:%SZ')"     --arg vault_mount "${VAULT_MOUNT}"     --arg vault_prefix "${VAULT_PREFIX}"     --arg POSTGRES_DB "${POSTGRES_DB}"     --arg POSTGRES_USER "${POSTGRES_USER}"     --arg POSTGRES_PASSWORD "${POSTGRES_PASSWORD}"     --arg PGADMIN_DEFAULT_EMAIL "${PGADMIN_DEFAULT_EMAIL}"     --arg PGADMIN_DEFAULT_PASSWORD "${PGADMIN_DEFAULT_PASSWORD}"     --arg KC_DB "postgres"     --arg KC_DB_URL_HOST "${KEYCLOAK_DB_URL_HOST}"     --arg KC_DB_URL_PORT "${KEYCLOAK_DB_URL_PORT}"     --arg KC_DB_URL_DATABASE "${KEYCLOAK_DB_URL_DATABASE}"     --arg KC_DB_USERNAME "${KEYCLOAK_DB_USERNAME}"     --arg KC_DB_PASSWORD "${KEYCLOAK_DB_PASSWORD}"     --arg KC_DB_SCHEMA "${KEYCLOAK_DB_SCHEMA}"     --arg KC_BOOTSTRAP_ADMIN_USERNAME "${KEYCLOAK_BOOTSTRAP_ADMIN_USERNAME}"     --arg KC_BOOTSTRAP_ADMIN_PASSWORD "${KEYCLOAK_BOOTSTRAP_ADMIN_PASSWORD}"     --arg KC_HOSTNAME "${KEYCLOAK_HOSTNAME}"     --arg KC_HOSTNAME_STRICT "${KEYCLOAK_HOSTNAME_STRICT}"     --arg KC_HTTP_ENABLED "${KEYCLOAK_HTTP_ENABLED}"     --arg KC_HTTPS_PORT "${KEYCLOAK_HTTPS_PORT}"     --arg KC_HEALTH_ENABLED "${KEYCLOAK_HEALTH_ENABLED}"     --arg KC_METRICS_ENABLED "${KEYCLOAK_METRICS_ENABLED}"     --arg KC_HTTP_MANAGEMENT_PORT "${KEYCLOAK_HTTP_MANAGEMENT_PORT}"     --arg KC_HTTP_MANAGEMENT_SCHEME "${KEYCLOAK_HTTP_MANAGEMENT_SCHEME}"     --arg KEYCLOAK_TLS_PRESENT "${KEYCLOAK_TLS_PRESENT}"     --arg KC_HTTPS_CERTIFICATE_PEM_B64 "${KEYCLOAK_TLS_CERT_PEM_B64}"     --arg KC_HTTPS_CERTIFICATE_KEY_PEM_B64 "${KEYCLOAK_TLS_KEY_PEM_B64}"     --arg KC_HTTPS_CA_CERT_PEM_B64 "${KEYCLOAK_TLS_CA_PEM_B64}"     '{
      generated_at_utc: $generated_at_utc,
      vault: { mount: $vault_mount, prefix: $vault_prefix },
      postgres: { POSTGRES_DB: $POSTGRES_DB, POSTGRES_USER: $POSTGRES_USER, POSTGRES_PASSWORD: $POSTGRES_PASSWORD },
      pgadmin: { PGADMIN_DEFAULT_EMAIL: $PGADMIN_DEFAULT_EMAIL, PGADMIN_DEFAULT_PASSWORD: $PGADMIN_DEFAULT_PASSWORD },
      keycloak_postgres: {
        KC_DB: $KC_DB,
        KC_DB_URL_HOST: $KC_DB_URL_HOST,
        KC_DB_URL_PORT: $KC_DB_URL_PORT,
        KC_DB_URL_DATABASE: $KC_DB_URL_DATABASE,
        KC_DB_USERNAME: $KC_DB_USERNAME,
        KC_DB_PASSWORD: $KC_DB_PASSWORD,
        KC_DB_SCHEMA: $KC_DB_SCHEMA
      },
      keycloak_bootstrap: {
        KC_BOOTSTRAP_ADMIN_USERNAME: $KC_BOOTSTRAP_ADMIN_USERNAME,
        KC_BOOTSTRAP_ADMIN_PASSWORD: $KC_BOOTSTRAP_ADMIN_PASSWORD
      },
      keycloak_runtime: {
        KC_HOSTNAME: $KC_HOSTNAME,
        KC_HOSTNAME_STRICT: $KC_HOSTNAME_STRICT,
        KC_HTTP_ENABLED: $KC_HTTP_ENABLED,
        KC_HTTPS_PORT: $KC_HTTPS_PORT,
        KC_HEALTH_ENABLED: $KC_HEALTH_ENABLED,
        KC_METRICS_ENABLED: $KC_METRICS_ENABLED,
        KC_HTTP_MANAGEMENT_PORT: $KC_HTTP_MANAGEMENT_PORT,
        KC_HTTP_MANAGEMENT_SCHEME: $KC_HTTP_MANAGEMENT_SCHEME
      },
      keycloak_tls: (if $KEYCLOAK_TLS_PRESENT == "1" then {
        KC_HTTPS_CERTIFICATE_PEM_B64: $KC_HTTPS_CERTIFICATE_PEM_B64,
        KC_HTTPS_CERTIFICATE_KEY_PEM_B64: $KC_HTTPS_CERTIFICATE_KEY_PEM_B64,
        KC_HTTPS_CA_CERT_PEM_B64: $KC_HTTPS_CA_CERT_PEM_B64
      } else null end)
    }' > "${JSON_FILE}"
else
  jq -n     --arg generated_at_utc "$(date -u +'%Y-%m-%dT%H:%M:%SZ')"     --arg vault_mount "${VAULT_MOUNT}"     --arg vault_prefix "${VAULT_PREFIX}"     --arg POSTGRES_DB "${POSTGRES_DB}"     --arg POSTGRES_USER "${POSTGRES_USER}"     --arg POSTGRES_PASSWORD "${POSTGRES_PASSWORD}"     --arg PGADMIN_DEFAULT_EMAIL "${PGADMIN_DEFAULT_EMAIL}"     --arg PGADMIN_DEFAULT_PASSWORD "${PGADMIN_DEFAULT_PASSWORD}"     '{
      generated_at_utc: $generated_at_utc,
      vault: { mount: $vault_mount, prefix: $vault_prefix },
      postgres: { POSTGRES_DB: $POSTGRES_DB, POSTGRES_USER: $POSTGRES_USER, POSTGRES_PASSWORD: $POSTGRES_PASSWORD },
      pgadmin: { PGADMIN_DEFAULT_EMAIL: $PGADMIN_DEFAULT_EMAIL, PGADMIN_DEFAULT_PASSWORD: $PGADMIN_DEFAULT_PASSWORD }
    }' > "${JSON_FILE}"
fi

export INCLUDE_KEYCLOAK_BOOTSTRAP INCLUDE_KEYCLOAK_RUNTIME KEYCLOAK_TLS_PRESENT
# Seed spec JSON (KV v2)
# Structure required by vault_unseal_multi_kv_seed_bootstrap_rootless.sh:
# { mounts: [ { mount, version, prefix?, secrets: {...} } ] }
if [[ "${INCLUDE_KEYCLOAK}" -eq 1 ]]; then
  if [[ -n "${VAULT_PREFIX}" ]]; then
    jq -n       --arg mount "${VAULT_MOUNT}"       --arg prefix "${VAULT_PREFIX}"       --arg POSTGRES_DB "${POSTGRES_DB}"       --arg POSTGRES_USER "${POSTGRES_USER}"       --arg POSTGRES_PASSWORD "${POSTGRES_PASSWORD}"       --arg PGADMIN_DEFAULT_EMAIL "${PGADMIN_DEFAULT_EMAIL}"       --arg PGADMIN_DEFAULT_PASSWORD "${PGADMIN_DEFAULT_PASSWORD}"       --arg KC_DB "postgres"       --arg KC_DB_URL_HOST "${KEYCLOAK_DB_URL_HOST}"       --arg KC_DB_URL_PORT "${KEYCLOAK_DB_URL_PORT}"       --arg KC_DB_URL_DATABASE "${KEYCLOAK_DB_URL_DATABASE}"       --arg KC_DB_USERNAME "${KEYCLOAK_DB_USERNAME}"       --arg KC_DB_PASSWORD "${KEYCLOAK_DB_PASSWORD}"       --arg KC_DB_SCHEMA "${KEYCLOAK_DB_SCHEMA}"       --arg KC_BOOTSTRAP_ADMIN_USERNAME "${KEYCLOAK_BOOTSTRAP_ADMIN_USERNAME}"       --arg KC_BOOTSTRAP_ADMIN_PASSWORD "${KEYCLOAK_BOOTSTRAP_ADMIN_PASSWORD}"       --arg KC_HOSTNAME "${KEYCLOAK_HOSTNAME}"       --arg KC_HOSTNAME_STRICT "${KEYCLOAK_HOSTNAME_STRICT}"       --arg KC_HTTP_ENABLED "${KEYCLOAK_HTTP_ENABLED}"       --arg KC_HTTPS_PORT "${KEYCLOAK_HTTPS_PORT}"       --arg KC_HEALTH_ENABLED "${KEYCLOAK_HEALTH_ENABLED}"       --arg KC_METRICS_ENABLED "${KEYCLOAK_METRICS_ENABLED}"       --arg KC_HTTP_MANAGEMENT_PORT "${KEYCLOAK_HTTP_MANAGEMENT_PORT}"       --arg KC_HTTP_MANAGEMENT_SCHEME "${KEYCLOAK_HTTP_MANAGEMENT_SCHEME}"       --arg KC_HTTPS_CERTIFICATE_PEM_B64 "${KEYCLOAK_TLS_CERT_PEM_B64}"       --arg KC_HTTPS_CERTIFICATE_KEY_PEM_B64 "${KEYCLOAK_TLS_KEY_PEM_B64}"       --arg KC_HTTPS_CA_CERT_PEM_B64 "${KEYCLOAK_TLS_CA_PEM_B64}"       '{
        mounts: [
          {
            mount: $mount,
            version: 2,
            prefix: $prefix,
            secrets: (
              {
                postgres: { POSTGRES_DB: $POSTGRES_DB, POSTGRES_USER: $POSTGRES_USER, POSTGRES_PASSWORD: $POSTGRES_PASSWORD },
                pgadmin:  { PGADMIN_DEFAULT_EMAIL: $PGADMIN_DEFAULT_EMAIL, PGADMIN_DEFAULT_PASSWORD: $PGADMIN_DEFAULT_PASSWORD },
                keycloak_postgres: { KC_DB: $KC_DB, KC_DB_URL_HOST: $KC_DB_URL_HOST, KC_DB_URL_PORT: $KC_DB_URL_PORT, KC_DB_URL_DATABASE: $KC_DB_URL_DATABASE,
                                     KC_DB_USERNAME: $KC_DB_USERNAME, KC_DB_PASSWORD: $KC_DB_PASSWORD, KC_DB_SCHEMA: $KC_DB_SCHEMA }
              }
              + (if env.INCLUDE_KEYCLOAK_BOOTSTRAP == "1" then { keycloak_bootstrap: { KC_BOOTSTRAP_ADMIN_USERNAME: $KC_BOOTSTRAP_ADMIN_USERNAME, KC_BOOTSTRAP_ADMIN_PASSWORD: $KC_BOOTSTRAP_ADMIN_PASSWORD } } else {} end)
              + (if env.INCLUDE_KEYCLOAK_RUNTIME == "1" then { keycloak_runtime: { KC_HOSTNAME: $KC_HOSTNAME, KC_HOSTNAME_STRICT: $KC_HOSTNAME_STRICT, KC_HTTP_ENABLED: $KC_HTTP_ENABLED, KC_HTTPS_PORT: $KC_HTTPS_PORT,
                                                                                 KC_HEALTH_ENABLED: $KC_HEALTH_ENABLED, KC_METRICS_ENABLED: $KC_METRICS_ENABLED, KC_HTTP_MANAGEMENT_PORT: $KC_HTTP_MANAGEMENT_PORT,
                                                                                 KC_HTTP_MANAGEMENT_SCHEME: $KC_HTTP_MANAGEMENT_SCHEME } } else {} end)
              + (if env.KEYCLOAK_TLS_PRESENT == "1" then { keycloak_tls: { KC_HTTPS_CERTIFICATE_PEM_B64: $KC_HTTPS_CERTIFICATE_PEM_B64, KC_HTTPS_CERTIFICATE_KEY_PEM_B64: $KC_HTTPS_CERTIFICATE_KEY_PEM_B64, KC_HTTPS_CA_CERT_PEM_B64: $KC_HTTPS_CA_CERT_PEM_B64 } } else {} end)
            )
          }
        ]
      }' > "${SPEC_FILE}"
  else
    jq -n       --arg mount "${VAULT_MOUNT}"       --arg POSTGRES_DB "${POSTGRES_DB}"       --arg POSTGRES_USER "${POSTGRES_USER}"       --arg POSTGRES_PASSWORD "${POSTGRES_PASSWORD}"       --arg PGADMIN_DEFAULT_EMAIL "${PGADMIN_DEFAULT_EMAIL}"       --arg PGADMIN_DEFAULT_PASSWORD "${PGADMIN_DEFAULT_PASSWORD}"       --arg KC_DB "postgres"       --arg KC_DB_URL_HOST "${KEYCLOAK_DB_URL_HOST}"       --arg KC_DB_URL_PORT "${KEYCLOAK_DB_URL_PORT}"       --arg KC_DB_URL_DATABASE "${KEYCLOAK_DB_URL_DATABASE}"       --arg KC_DB_USERNAME "${KEYCLOAK_DB_USERNAME}"       --arg KC_DB_PASSWORD "${KEYCLOAK_DB_PASSWORD}"       --arg KC_DB_SCHEMA "${KEYCLOAK_DB_SCHEMA}"       --arg KC_BOOTSTRAP_ADMIN_USERNAME "${KEYCLOAK_BOOTSTRAP_ADMIN_USERNAME}"       --arg KC_BOOTSTRAP_ADMIN_PASSWORD "${KEYCLOAK_BOOTSTRAP_ADMIN_PASSWORD}"       --arg KC_HOSTNAME "${KEYCLOAK_HOSTNAME}"       --arg KC_HOSTNAME_STRICT "${KEYCLOAK_HOSTNAME_STRICT}"       --arg KC_HTTP_ENABLED "${KEYCLOAK_HTTP_ENABLED}"       --arg KC_HTTPS_PORT "${KEYCLOAK_HTTPS_PORT}"       --arg KC_HEALTH_ENABLED "${KEYCLOAK_HEALTH_ENABLED}"       --arg KC_METRICS_ENABLED "${KEYCLOAK_METRICS_ENABLED}"       --arg KC_HTTP_MANAGEMENT_PORT "${KEYCLOAK_HTTP_MANAGEMENT_PORT}"       --arg KC_HTTP_MANAGEMENT_SCHEME "${KEYCLOAK_HTTP_MANAGEMENT_SCHEME}"       --arg KC_HTTPS_CERTIFICATE_PEM_B64 "${KEYCLOAK_TLS_CERT_PEM_B64}"       --arg KC_HTTPS_CERTIFICATE_KEY_PEM_B64 "${KEYCLOAK_TLS_KEY_PEM_B64}"       --arg KC_HTTPS_CA_CERT_PEM_B64 "${KEYCLOAK_TLS_CA_PEM_B64}"       '{
        mounts: [
          {
            mount: $mount,
            version: 2,
            secrets: (
              {
                postgres: { POSTGRES_DB: $POSTGRES_DB, POSTGRES_USER: $POSTGRES_USER, POSTGRES_PASSWORD: $POSTGRES_PASSWORD },
                pgadmin:  { PGADMIN_DEFAULT_EMAIL: $PGADMIN_DEFAULT_EMAIL, PGADMIN_DEFAULT_PASSWORD: $PGADMIN_DEFAULT_PASSWORD },
                keycloak_postgres: { KC_DB: $KC_DB, KC_DB_URL_HOST: $KC_DB_URL_HOST, KC_DB_URL_PORT: $KC_DB_URL_PORT, KC_DB_URL_DATABASE: $KC_DB_URL_DATABASE,
                                     KC_DB_USERNAME: $KC_DB_USERNAME, KC_DB_PASSWORD: $KC_DB_PASSWORD, KC_DB_SCHEMA: $KC_DB_SCHEMA }
              }
              + (if env.INCLUDE_KEYCLOAK_BOOTSTRAP == "1" then { keycloak_bootstrap: { KC_BOOTSTRAP_ADMIN_USERNAME: $KC_BOOTSTRAP_ADMIN_USERNAME, KC_BOOTSTRAP_ADMIN_PASSWORD: $KC_BOOTSTRAP_ADMIN_PASSWORD } } else {} end)
              + (if env.INCLUDE_KEYCLOAK_RUNTIME == "1" then { keycloak_runtime: { KC_HOSTNAME: $KC_HOSTNAME, KC_HOSTNAME_STRICT: $KC_HOSTNAME_STRICT, KC_HTTP_ENABLED: $KC_HTTP_ENABLED, KC_HTTPS_PORT: $KC_HTTPS_PORT,
                                                                                 KC_HEALTH_ENABLED: $KC_HEALTH_ENABLED, KC_METRICS_ENABLED: $KC_METRICS_ENABLED, KC_HTTP_MANAGEMENT_PORT: $KC_HTTP_MANAGEMENT_PORT,
                                                                                 KC_HTTP_MANAGEMENT_SCHEME: $KC_HTTP_MANAGEMENT_SCHEME } } else {} end)
              + (if env.KEYCLOAK_TLS_PRESENT == "1" then { keycloak_tls: { KC_HTTPS_CERTIFICATE_PEM_B64: $KC_HTTPS_CERTIFICATE_PEM_B64, KC_HTTPS_CERTIFICATE_KEY_PEM_B64: $KC_HTTPS_CERTIFICATE_KEY_PEM_B64, KC_HTTPS_CA_CERT_PEM_B64: $KC_HTTPS_CA_CERT_PEM_B64 } } else {} end)
            )
          }
        ]
      }' > "${SPEC_FILE}"
  fi
else
  if [[ -n "${VAULT_PREFIX}" ]]; then
    jq -n       --arg mount "${VAULT_MOUNT}"       --arg prefix "${VAULT_PREFIX}"       --arg POSTGRES_DB "${POSTGRES_DB}"       --arg POSTGRES_USER "${POSTGRES_USER}"       --arg POSTGRES_PASSWORD "${POSTGRES_PASSWORD}"       --arg PGADMIN_DEFAULT_EMAIL "${PGADMIN_DEFAULT_EMAIL}"       --arg PGADMIN_DEFAULT_PASSWORD "${PGADMIN_DEFAULT_PASSWORD}"       '{
        mounts: [
          {
            mount: $mount,
            version: 2,
            prefix: $prefix,
            secrets: {
              postgres: { POSTGRES_DB: $POSTGRES_DB, POSTGRES_USER: $POSTGRES_USER, POSTGRES_PASSWORD: $POSTGRES_PASSWORD },
              pgadmin:  { PGADMIN_DEFAULT_EMAIL: $PGADMIN_DEFAULT_EMAIL, PGADMIN_DEFAULT_PASSWORD: $PGADMIN_DEFAULT_PASSWORD }
            }
          }
        ]
      }' > "${SPEC_FILE}"
  else
    jq -n       --arg mount "${VAULT_MOUNT}"       --arg POSTGRES_DB "${POSTGRES_DB}"       --arg POSTGRES_USER "${POSTGRES_USER}"       --arg POSTGRES_PASSWORD "${POSTGRES_PASSWORD}"       --arg PGADMIN_DEFAULT_EMAIL "${PGADMIN_DEFAULT_EMAIL}"       --arg PGADMIN_DEFAULT_PASSWORD "${PGADMIN_DEFAULT_PASSWORD}"       '{
        mounts: [
          {
            mount: $mount,
            version: 2,
            secrets: {
              postgres: { POSTGRES_DB: $POSTGRES_DB, POSTGRES_USER: $POSTGRES_USER, POSTGRES_PASSWORD: $POSTGRES_PASSWORD },
              pgadmin:  { PGADMIN_DEFAULT_EMAIL: $PGADMIN_DEFAULT_EMAIL, PGADMIN_DEFAULT_PASSWORD: $PGADMIN_DEFAULT_PASSWORD }
            }
          }
        ]
      }' > "${SPEC_FILE}"
  fi
fi

chmod 600 "${ENV_FILE}" "${JSON_FILE}" "${SPEC_FILE}" || true

log "Wrote credential artifacts:"
log "  ENV:  ${ENV_FILE}"
log "  JSON: ${JSON_FILE}"
log "  SPEC: ${SPEC_FILE}"
log ""

if [[ "${PRINT}" -eq 1 ]]; then
  warn "--print enabled. Printing secrets to stdout (sensitive):"
  cat "${ENV_FILE}"
fi

# -----------------------------------------------------------------------------
# Seed Vault using your existing seed script
# -----------------------------------------------------------------------------
if [[ "${SEED_VAULT}" -eq 1 ]]; then
  [[ -f "${SEED_SCRIPT}" ]] || err "Seed script not found at: ${SEED_SCRIPT}"
  [[ -f "${SPEC_FILE}" ]] || err "Spec file missing at: ${SPEC_FILE}"

  log "Seeding Vault from generated spec..."
  log "  VAULT_ADDR: ${VAULT_ADDR}"
  log "  Seed script: ${SEED_SCRIPT}"
  [[ -n "${CA_CERT}" ]] && log "  CA cert:    ${CA_CERT}"

  seed_args=( --vault-addr "${VAULT_ADDR}" --spec-json "${SPEC_FILE}" --unseal-required "${UNSEAL_REQUIRED}" )

  if [[ -n "${CA_CERT}" ]]; then
    seed_args+=( --ca-cert "${CA_CERT}" )
  elif [[ "${TLS_SKIP_VERIFY}" -eq 1 ]]; then
    seed_args+=( --tls-skip-verify )
  else
    err "Provide --ca-cert (recommended) or --tls-skip-verify (dev only)."
  fi

  if [[ "${PROMPT_TOKEN}" -eq 1 ]]; then
    seed_args+=( --prompt-token )
  else
    if [[ -f "${TOKEN_FILE}" ]]; then
      seed_args+=( --token-file "${TOKEN_FILE}" )
    else
      warn "Token file not found at: ${TOKEN_FILE} (falling back to --prompt-token)"
      seed_args+=( --prompt-token )
    fi
  fi

  if [[ "${PRINT_SECRETS}" -eq 1 ]]; then
    seed_args+=( --print-secrets )
  fi

  bash "${SEED_SCRIPT}" "${seed_args[@]}"
  log "Vault seeding completed."
else
  log "Vault seeding skipped (--no-seed)."
fi

# -----------------------------------------------------------------------------
# Apply to Postgres (roles/db/schema) — fetch from Vault if possible, else use current values
# -----------------------------------------------------------------------------
docker_compose_cmd() {
  if command -v docker >/dev/null 2>&1; then
    if docker compose version >/dev/null 2>&1; then
      echo "docker compose"
      return 0
    fi
  fi
  if command -v docker-compose >/dev/null 2>&1; then
    echo "docker-compose"
    return 0
  fi
  return 1
}

postgres_is_running() {
  docker inspect -f '{{.State.Running}}' "${POSTGRES_CONTAINER}" 2>/dev/null | grep -q '^true$'
}

wait_for_postgres_ready() {
  local seconds="${1}"
  local start now
  start="$(date +%s)"
  while true; do
    if docker exec -u postgres "${POSTGRES_CONTAINER}" pg_isready -q >/dev/null 2>&1; then
      return 0
    fi
    now="$(date +%s)"
    if (( now - start >= seconds )); then
      return 1
    fi
    sleep 2
  done
}

if [[ "${APPLY_TO_POSTGRES}" -eq 1 ]]; then
  need_cmd docker

  # Re-fetch from Vault before applying if we can (source-of-truth)
  if [[ "${PREFER_VAULT}" -eq 1 ]]; then
    vault_try_load_from_vault || true
  fi

  log "Applying Postgres objects in container: ${POSTGRES_CONTAINER}"
  log "  network_tools: role=${POSTGRES_USER} db=${POSTGRES_DB}"
  if [[ "${INCLUDE_KEYCLOAK}" -eq 1 ]]; then
    log "  keycloak:      role=${KEYCLOAK_DB_USERNAME} db=${KEYCLOAK_DB_URL_DATABASE} schema=${KEYCLOAK_DB_SCHEMA}"
  fi

  if ! postgres_is_running; then
    if [[ "${AUTO_START_POSTGRES}" -eq 1 ]]; then
      if [[ -f "${COMPOSE_FILE}" ]]; then
        dc="$(docker_compose_cmd || true)"
        [[ -n "${dc}" ]] || err "Unable to find docker compose command (docker compose or docker-compose)"
        log "Postgres is not running. Starting via: ${dc} -f ${COMPOSE_FILE} up -d ${POSTGRES_CONTAINER}"
        ${dc} -f "${COMPOSE_FILE}" up -d "${POSTGRES_CONTAINER}" || err "Failed to start ${POSTGRES_CONTAINER} via compose"
      else
        if docker inspect "${POSTGRES_CONTAINER}" >/dev/null 2>&1; then
          log "Postgres is not running. Starting via: docker start ${POSTGRES_CONTAINER}"
          docker start "${POSTGRES_CONTAINER}" >/dev/null || err "Failed to start ${POSTGRES_CONTAINER}"
        else
          err "Postgres container not found: ${POSTGRES_CONTAINER} (and compose file missing at ${COMPOSE_FILE})"
        fi
      fi
    else
      err "Postgres is not running and --no-auto-start-postgres was set."
    fi
  fi

  log "Waiting for Postgres readiness (up to ${WAIT_POSTGRES_SECONDS}s)..."
  wait_for_postgres_ready "${WAIT_POSTGRES_SECONDS}" || err "Postgres not ready within ${WAIT_POSTGRES_SECONDS}s"

  docker exec -i -u postgres \
    -e POSTGRES_ADMIN_DB="${POSTGRES_ADMIN_DB}" \
    -e NT_DB="${POSTGRES_DB}" \
    -e NT_USER="${POSTGRES_USER}" \
    -e NT_PASS="${POSTGRES_PASSWORD}" \
    -e INCLUDE_KEYCLOAK="${INCLUDE_KEYCLOAK}" \
    -e KC_DB="${KEYCLOAK_DB_URL_DATABASE}" \
    -e KC_USER="${KEYCLOAK_DB_USERNAME}" \
    -e KC_PASS="${KEYCLOAK_DB_PASSWORD}" \
    -e KC_SCHEMA="${KEYCLOAK_DB_SCHEMA}" \
    "${POSTGRES_CONTAINER}" bash -s -- <<'EOS'
set -euo pipefail

apply_role_and_db() {
  local dbname="$1"
  local username="$2"
  local password="$3"
  local admin_db="${POSTGRES_ADMIN_DB}"

  psql -v ON_ERROR_STOP=1 --username=postgres --dbname="${admin_db}" \
    -v dbname="${dbname}" -v username="${username}" -v password="${password}" <<'SQL'
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'username') THEN
    EXECUTE format('CREATE ROLE %I LOGIN PASSWORD %L', :'username', :'password');
  ELSE
    EXECUTE format('ALTER ROLE %I WITH LOGIN PASSWORD %L', :'username', :'password');
  END IF;
END$$;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = :'dbname') THEN
    EXECUTE format('CREATE DATABASE %I OWNER %I ENCODING ''UTF8''', :'dbname', :'username');
  END IF;
END$$;

ALTER DATABASE :"dbname" OWNER TO :"username";
GRANT ALL PRIVILEGES ON DATABASE :"dbname" TO :"username";
SQL
}

apply_schema() {
  local dbname="$1"
  local schema="$2"
  local username="$3"

  psql -v ON_ERROR_STOP=1 --username=postgres --dbname="${dbname}" \
    -v schema="${schema}" -v username="${username}" <<'SQL'
DO $$
BEGIN
  EXECUTE format('CREATE SCHEMA IF NOT EXISTS %I AUTHORIZATION %I', :'schema', :'username');
END$$;

GRANT ALL ON SCHEMA :"schema" TO :"username";
SQL
}

apply_role_and_db "${NT_DB}" "${NT_USER}" "${NT_PASS}"
echo "INFO: Ensured network_tools role/db exist: user=${NT_USER} db=${NT_DB}"

if [[ "${INCLUDE_KEYCLOAK}" == "1" ]]; then
  apply_role_and_db "${KC_DB}" "${KC_USER}" "${KC_PASS}"
  apply_schema "${KC_DB}" "${KC_SCHEMA}" "${KC_USER}"
  echo "INFO: Ensured keycloak role/db/schema exist: user=${KC_USER} db=${KC_DB} schema=${KC_SCHEMA}"
fi
EOS

  log "Postgres apply completed."
fi

log "Done."
