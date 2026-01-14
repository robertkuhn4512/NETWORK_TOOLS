#!/usr/bin/env bash
#------------------------------------------------------------------------------
# generate_bootstrap_creds_and_seed.sh (NO-PYTHON, VAULT-FETCH, APPLY)
#
# Notes / How to run
# - Env: auto-loads <repo-root>/.env by default.
#   Optional flags: --env-file PATH | --no-env-file | --env-override
#
# 1) Standard first-time init (idempotent):
#    - In --mode generate (default), this script prefers EXISTING values:
#        A) Existing local bootstrap artifacts (bootstrap_creds.env; legacy: postgres_pgadmin.env), else
#        B) Existing Vault KV values (if present), else
#        C) Generates new values.
#    - Then it seeds Vault (default) and writes artifacts.
#
#    Use the below command and rely on the .env file having the correct fqdn populated under PRIMARY_SERVER_FQDN
#
#    cd "$HOME/NETWORK_TOOLS"
#    bash ./backend/build_scripts/generate_bootstrap_creds_and_seed.sh \
#      --ca-cert "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt" \
#      --unseal-required 3
#
#    Or, below with either the vault container name, or another vault fqdn.
#
#    cd "$HOME/NETWORK_TOOLS"
#    bash ./backend/build_scripts/generate_bootstrap_creds_and_seed.sh \
#      --vault-addr "https://vault_production_node:8200" \
#      --ca-cert "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt" \
#      --unseal-required 3
#
#
#    NOTE: If <bootstrap_dir>/root_token exists, the seed step will use it automatically.
#          Only use --prompt-token if you WANT to be prompted.
#
# 2) First-time init + apply DB objects (works even if Postgres is not running yet):
#    - Ensures credentials exist (load local or fetch Vault or generate+seed).
#    - Attempts to start postgres_primary (compose or docker start).
#    - Applies roles/db/schema inside Postgres to match Vault values.
#
#    bash ./backend/build_scripts/generate_bootstrap_creds_and_seed.sh \
#      --vault-addr "https://vault_production_node:8200" \
#      --ca-cert "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt" \
#      --unseal-required 3 \
#      --apply-to-postgres
#
# 3) Rotation (new passwords) + apply:
#    bash ./backend/build_scripts/generate_bootstrap_creds_and_seed.sh \
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
# -----------------------------------------------------------------------------
# Env loading (default: <repo-root>/.env)
# -----------------------------------------------------------------------------
# This script will prefer values provided via environment variables (including .env),
# and will fall back to Docker container names when needed.
#
# Security note: .env is treated as data (KEY=VALUE). Lines that do not match this
# format are ignored; no code is executed.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="${PROJECT_ROOT:-$(cd "${SCRIPT_DIR}/../.." && pwd -P)}"

# Basic log helpers (only defined if the script didn't already define them)
if ! declare -F log >/dev/null 2>&1; then
  log()  { echo "INFO: $*" >&2; }
  warn() { echo "INFO: WARN: $*" >&2; }
  err()  { echo "ERROR: $*" >&2; }
fi

dotenv_load() {
  local env_file="$1"
  local override="${2:-0}"   # 0 = do not override non-empty vars; 1 = override
  [[ -n "${env_file}" && -f "${env_file}" ]] || return 0

  local line key val
  while IFS= read -r line || [[ -n "${line}" ]]; do
    line="${line//$'\r'/}"
    [[ -z "${line}" || "${line}" =~ ^[[:space:]]*# ]] && continue
    [[ "${line}" =~ ^[[:space:]]*([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]] || continue
    key="${BASH_REMATCH[1]}"
    val="${BASH_REMATCH[2]}"
    val="${val#"${val%%[![:space:]]*}"}"
    val="${val%"${val##*[![:space:]]}"}"
    if [[ "${val}" =~ ^\"(.*)\"$ ]]; then val="${BASH_REMATCH[1]}"; fi
    if [[ "${val}" =~ ^\'(.*)\'$ ]]; then val="${BASH_REMATCH[1]}"; fi

    if [[ "${override}" == "1" ]]; then
      export "${key}=${val}"
    else
      if [[ -z "${!key:-}" ]]; then
        export "${key}=${val}"
      fi
    fi
  done < "${env_file}"
}

# Pre-parse env options so that .env can affect defaults, while CLI args still win.
ENV_FILE=""
ENV_DISABLE=0
ENV_OVERRIDE=0
for ((i=1; i<=$#; i++)); do
  case "${!i}" in
    --env-file) ENV_FILE="${!((i+1)):-}";;
    --no-env-file) ENV_DISABLE=1;;
    --env-override) ENV_OVERRIDE=1;;
  esac
done

log()  { printf '%s\n' "INFO: $*"; }
warn() { printf '%s\n' "WARN: $*" >&2; }
err()  { printf '%s\n' "ERROR: $*" >&2; exit 1; }

need_cmd() { command -v "$1" >/dev/null 2>&1 || err "Missing required command: $1"; }

# --- Defaults ---
ROOT_DIR="${ROOT_DIR:-${HOME}/NETWORK_TOOLS}"

if [[ "${ENV_DISABLE:-0}" != "1" ]]; then
  if [[ -z "${ENV_FILE:-}" ]]; then ENV_FILE="${ROOT_DIR}/.env"; fi
  if [[ -f "${ENV_FILE}" ]]; then
    log "Loading env defaults from: ${ENV_FILE}"
    dotenv_load "${ENV_FILE}" "${ENV_OVERRIDE:-0}"
  else
    warn "Env file not found (continuing): ${ENV_FILE}"
  fi
fi

# Preferred Vault TLS hostname (cert SAN), if provided
PREFERRED_VAULT_HOST=""
if [[ -n "${PRIMARY_VAULT_SERVER_FQDN_FULL:-}" ]]; then
  PREFERRED_VAULT_HOST="${PRIMARY_VAULT_SERVER_FQDN_FULL}"
elif [[ -n "${PRIMARY_SERVER_FQDN:-}" ]]; then
  PREFERRED_VAULT_HOST="vault.${PRIMARY_SERVER_FQDN}"
fi

VAULT_CONTAINER="${VAULT_CONTAINER:-${VAULT_CONTAINER_NAME:-vault_production_node}}"

BOOTSTRAP_DIR="${ROOT_DIR}/backend/app/security/configuration_files/vault/bootstrap"

# network_tools Postgres
POSTGRES_DB="network_tools"
POSTGRES_USER="network_tools_user"
POSTGRES_PASSWORD=""

# FastAPI -> Postgres (network_tools DB, limited DML user)
INCLUDE_FASTAPI=1
FASTAPI_DB_URL_HOST="postgres_primary"
FASTAPI_DB_URL_PORT="5432"
FASTAPI_DB_URL_DATABASE="network_tools"
FASTAPI_DB_USERNAME="network_tools_fastapi"
FASTAPI_DB_PASSWORD=""
FASTAPI_DB_SCHEMA="public"

# FastAPI runtime / auth / logging (stored in Vault under fastapi_secrets)
# Note: These are non-secret config defaults. Override via env/.env if desired.
APP_ENV="${APP_ENV:-}"

CORS_ALLOW_CREDENTIALS="${CORS_ALLOW_CREDENTIALS:-}"
CORS_ALLOW_ORIGINS="${CORS_ALLOW_ORIGINS:-}"
# Regex as a literal string; jq will escape backslashes as needed in JSON output.
CORS_ALLOW_ORIGIN_REGEX="${CORS_ALLOW_ORIGIN_REGEX:-}"

FASTAPI_ALLOWED_AZP="${FASTAPI_ALLOWED_AZP:-}"
FASTAPI_VERIFY_AUDIENCE="${FASTAPI_VERIFY_AUDIENCE:-}"

KEYCLOAK_BASE_URL="${KEYCLOAK_BASE_URL:-}"
KEYCLOAK_REALM="${KEYCLOAK_REALM:-}"
# Optional; only required if you choose token introspection instead of JWT validation.
KEYCLOAK_INTROSPECTION_CLIENT_ID="${KEYCLOAK_INTROSPECTION_CLIENT_ID:-}"
KEYCLOAK_INTROSPECTION_CLIENT_SECRET="${KEYCLOAK_INTROSPECTION_CLIENT_SECRET:-}"

LOG_DIR="${LOG_DIR:-}"
LOG_FILE="${LOG_FILE:-}"
LOG_LEVEL="${LOG_LEVEL:-}"
LOG_TO_STDOUT="${LOG_TO_STDOUT:-}"

TRUSTED_HOSTS="${TRUSTED_HOSTS:-}"



# Redis / Celery (FastAPI background jobs)
INCLUDE_REDIS=1
REDIS_HOST="redis"
REDIS_PORT="6379"
REDIS_PASSWORD=""

# Celery (uses Redis as broker/result backend by default)
INCLUDE_CELERY=1
CELERY_BROKER_DB="0"
CELERY_RESULT_DB="1"
CELERY_BROKER_URL=""
CELERY_RESULT_BACKEND=""

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
KEYCLOAK_DB_URL_PROPERTIES="sslmode=disable"

# Keycloak bootstrap (initial admin) — stored in Vault at: keycloak_bootstrap
INCLUDE_KEYCLOAK_BOOTSTRAP=1
KEYCLOAK_BOOTSTRAP_ADMIN_USERNAME="admin"
KEYCLOAK_BOOTSTRAP_ADMIN_PASSWORD=""

# Keycloak runtime (hostname / server settings) — stored in Vault at: keycloak_runtime
INCLUDE_KEYCLOAK_RUNTIME=1

# Keycloak TLS material (cert/key/CA) — stored in Vault at: keycloak_tls
# - This script stores TLS material as BASE64 (single-line) to avoid newline/quoting issues.
# - By default, this does NOT store the CA private key (ca.key). Keep CA key offline/admin-only.
INCLUDE_KEYCLOAK_TLS=0
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
KEYCLOAK_HOSTNAME="auth.${PRIMARY_SERVER_FQDN:-keycloak}"
KEYCLOAK_HOSTNAME_STRICT="false"
KEYCLOAK_HTTP_ENABLED="true"
KEYCLOAK_HTTP_PORT="8080"
KEYCLOAK_PROXY_HEADERS="xforwarded"
KEYCLOAK_PROXY_TRUSTED_ADDRESSES="172.30.20.0/24,172.30.0.0/16"
KEYCLOAK_HTTPS_PORT="8443"
KEYCLOAK_HEALTH_ENABLED="true"
KEYCLOAK_METRICS_ENABLED="true"
KEYCLOAK_HTTP_MANAGEMENT_PORT="9000"
KEYCLOAK_HTTP_MANAGEMENT_SCHEME="http"

# Vault KV v2
VAULT_MOUNT="app_network_tools_secrets"
VAULT_PREFIX=""

# Vault connectivity
VAULT_ADDR="${VAULT_ADDR:-}"
if [[ -z "${VAULT_ADDR}" && -n "${PREFERRED_VAULT_HOST:-}" ]]; then
  VAULT_ADDR="https://${PREFERRED_VAULT_HOST}:8200"
fi
VAULT_ADDR="${VAULT_ADDR:-https://${VAULT_CONTAINER}:8200}"
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
POSTGRES_CONTAINER="${POSTGRES_CONTAINER:-${POSTGRES_CONTAINER_NAME:-postgres_primary}}"
POSTGRES_ADMIN_DB="postgres"
# Postgres admin credentials for apply-to-postgres.
# If not provided explicitly, the script will try to read them from:
#   1) /run/vault/postgres_user and /run/vault/postgres_password inside the Postgres container, else
#   2) the resolved POSTGRES_USER/POSTGRES_PASSWORD values (from local bootstrap artifacts or Vault).
POSTGRES_ADMIN_USER=""
POSTGRES_ADMIN_PASSWORD=""
POSTGRES_ADMIN_CREDS_SOURCE=""
AUTO_START_POSTGRES=1
COMPOSE_FILE="${ROOT_DIR}/docker-compose.prod.yml"
WAIT_POSTGRES_SECONDS=180
# How long to wait for /run/vault/* Postgres credentials to appear inside the container when applying.
WAIT_VAULT_CREDS_SECONDS=30

PRINT=0
PRINT_SECRETS=0

usage() {
  cat <<'USAGE'
Usage:
  generate_bootstrap_creds_and_seed.sh [options]

Modes:
  --mode <generate|rotate>       generate: prefer existing local/Vault values (default)
                                rotate:   generate NEW passwords (unless explicitly provided)

Local/Vault preference (generate mode):
  --no-prefer-local             Do not reuse existing bootstrap_creds.env (legacy: postgres_pgadmin.env) if present
  --no-prefer-vault             Do not reuse existing Vault KV values if present

Postgres (network_tools):
  --postgres-db <name>
  --postgres-user <name>
  --postgres-password <value>

FastAPI (Postgres-backed; limited DML user for network_tools DB):
  --no-fastapi
  --fastapi-db-host <host>
  --fastapi-db-port <port>
  --fastapi-db <name>
  --fastapi-user <name>
  --fastapi-password <value>
  --fastapi-schema <name>

Redis / Celery (stored under fastapi_secrets):
  --no-redis
  --redis-host <host>
  --redis-port <port>
  --redis-password <value>
  --no-celery
  --celery-broker-db <n>
  --celery-result-db <n>
  --celery-broker-url <url>       Overrides computed URL (includes password)
  --celery-result-backend <url>   Overrides computed backend URL (includes password)

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
  --postgres-admin-user <name>                 (optional override)
  --postgres-admin-password <value>             (optional override; avoid on shared shells)
  --wait-vault-credentials-seconds <n>          (default 30)
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
    --env-file) ENV_FILE="$2"; shift 2;;
    --no-env-file) ENV_DISABLE=1; shift;;
    --env-override) ENV_OVERRIDE=1; shift;;
    --mode) MODE="${2:-}"; shift 2;;

    --no-prefer-local) PREFER_LOCAL=0; shift 1;;
    --no-prefer-vault) PREFER_VAULT=0; shift 1;;

    --postgres-db) POSTGRES_DB="${2:-}"; shift 2;;
    --postgres-user) POSTGRES_USER="${2:-}"; shift 2;;
    --postgres-password) POSTGRES_PASSWORD="${2:-}"; shift 2;;

    --no-fastapi) INCLUDE_FASTAPI=0; shift 1;;
    --fastapi-db-host) FASTAPI_DB_URL_HOST="${2:-}"; shift 2;;
    --fastapi-db-port) FASTAPI_DB_URL_PORT="${2:-}"; shift 2;;
    --fastapi-db) FASTAPI_DB_URL_DATABASE="${2:-}"; shift 2;;
    --fastapi-user) FASTAPI_DB_USERNAME="${2:-}"; shift 2;;
    --fastapi-password) FASTAPI_DB_PASSWORD="${2:-}"; shift 2;;
    --fastapi-schema) FASTAPI_DB_SCHEMA="${2:-}"; shift 2;;

    --no-redis) INCLUDE_REDIS=0; shift 1;;
    --redis-host) REDIS_HOST="${2:-}"; shift 2;;
    --redis-port) REDIS_PORT="${2:-}"; shift 2;;
    --redis-password) REDIS_PASSWORD="${2:-}"; shift 2;;

    --no-celery) INCLUDE_CELERY=0; shift 1;;
    --celery-broker-db) CELERY_BROKER_DB="${2:-}"; shift 2;;
    --celery-result-db) CELERY_RESULT_DB="${2:-}"; shift 2;;
    --celery-broker-url) CELERY_BROKER_URL="${2:-}"; shift 2;;
    --celery-result-backend) CELERY_RESULT_BACKEND="${2:-}"; shift 2;;


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
    --postgres-admin-user) POSTGRES_ADMIN_USER="${2:-}"; shift 2;;
    --postgres-admin-password) POSTGRES_ADMIN_PASSWORD="${2:-}"; shift 2;;
    --wait-vault-credentials-seconds) WAIT_VAULT_CREDS_SECONDS="${2:-}"; shift 2;;
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
ENV_FILE="${BOOTSTRAP_DIR}/bootstrap_creds.env"
JSON_FILE="${BOOTSTRAP_DIR}/bootstrap_credentials.json"
SPEC_FILE="${BOOTSTRAP_DIR}/seed_kv_spec.bootstrap_creds.json"

LEGACY_ENV_FILE="${BOOTSTRAP_DIR}/postgres_pgadmin.env"
LEGACY_JSON_FILE="${BOOTSTRAP_DIR}/postgres_pgadmin_credentials.json"
LEGACY_SPEC_FILE="${BOOTSTRAP_DIR}/seed_kv_spec.postgres_pgadmin.json"
LOCAL_ENV_SOURCE=""

load_env_value() {
  # Usage: load_env_value <file> <KEY>
  local f="$1"
  local k="$2"
  grep -E "^${k}=" "$f" 2>/dev/null | head -n 1 | cut -d= -f2- || true
}

load_from_local_env_if_present() {
  local src="${ENV_FILE}"
  if [[ ! -f "${src}" && -f "${LEGACY_ENV_FILE}" ]]; then
    src="${LEGACY_ENV_FILE}"
  fi
  [[ -f "${src}" ]] || return 1

  LOCAL_ENV_SOURCE="${src}"

  local p_db p_user p_pass a_email a_pass
  p_db="$(load_env_value "${src}" "POSTGRES_DB")"
  p_user="$(load_env_value "${src}" "POSTGRES_USER")"
  p_pass="$(load_env_value "${src}" "POSTGRES_PASSWORD")"
  a_email="$(load_env_value "${src}" "PGADMIN_DEFAULT_EMAIL")"
  a_pass="$(load_env_value "${src}" "PGADMIN_DEFAULT_PASSWORD")"

  if [[ -n "${p_db}" && -n "${p_user}" && -n "${p_pass}" && -n "${a_email}" && -n "${a_pass}" ]]; then
    POSTGRES_DB="${p_db}"
    POSTGRES_USER="${p_user}"
    POSTGRES_PASSWORD="${p_pass}"
    PGADMIN_DEFAULT_EMAIL="${a_email}"
    PGADMIN_DEFAULT_PASSWORD="${a_pass}"
  else
    return 1
  fi

  # FastAPI (optional)
  local fa_inc fa_host fa_port fa_db fa_user fa_pass fa_schema
  fa_inc="$(load_env_value "${src}" "INCLUDE_FASTAPI")"
  [[ "${fa_inc}" == "0" || "${fa_inc}" == "1" ]] && INCLUDE_FASTAPI="${fa_inc}"

  fa_host="$(load_env_value "${src}" "FASTAPI_DB_URL_HOST")"
  fa_port="$(load_env_value "${src}" "FASTAPI_DB_URL_PORT")"
  fa_db="$(load_env_value "${src}" "FASTAPI_DB_URL_DATABASE")"
  fa_user="$(load_env_value "${src}" "FASTAPI_DB_USERNAME")"
  fa_pass="$(load_env_value "${src}" "FASTAPI_DB_PASSWORD")"
  fa_schema="$(load_env_value "${src}" "FASTAPI_DB_SCHEMA")"

  if [[ -n "${fa_db}" && -n "${fa_user}" && -n "${fa_pass}" ]]; then
    [[ -n "${fa_host}" ]] && FASTAPI_DB_URL_HOST="${fa_host}"
    [[ -n "${fa_port}" ]] && FASTAPI_DB_URL_PORT="${fa_port}"
    FASTAPI_DB_URL_DATABASE="${fa_db}"
    FASTAPI_DB_USERNAME="${fa_user}"
    FASTAPI_DB_PASSWORD="${fa_pass}"
    [[ -n "${fa_schema}" ]] && FASTAPI_DB_SCHEMA="${fa_schema}"

  # FastAPI runtime/auth/logging (optional)
  local fa_app_env fa_cors_creds fa_cors_origins fa_cors_regex fa_allowed_azp fa_verify_aud
  local fa_kc_base_url fa_kc_realm fa_kc_introspect_id fa_kc_introspect_secret
  local fa_log_dir fa_log_file fa_log_level fa_log_to_stdout fa_trusted_hosts

  fa_app_env="$(load_env_value "${src}" "APP_ENV")"
  fa_cors_creds="$(load_env_value "${src}" "CORS_ALLOW_CREDENTIALS")"
  fa_cors_origins="$(load_env_value "${src}" "CORS_ALLOW_ORIGINS")"
  fa_cors_regex="$(load_env_value "${src}" "CORS_ALLOW_ORIGIN_REGEX")"
  fa_allowed_azp="$(load_env_value "${src}" "FASTAPI_ALLOWED_AZP")"
  fa_verify_aud="$(load_env_value "${src}" "FASTAPI_VERIFY_AUDIENCE")"

  fa_kc_base_url="$(load_env_value "${src}" "KEYCLOAK_BASE_URL")"
  fa_kc_realm="$(load_env_value "${src}" "KEYCLOAK_REALM")"
  fa_kc_introspect_id="$(load_env_value "${src}" "KEYCLOAK_INTROSPECTION_CLIENT_ID")"
  fa_kc_introspect_secret="$(load_env_value "${src}" "KEYCLOAK_INTROSPECTION_CLIENT_SECRET")"

  fa_log_dir="$(load_env_value "${src}" "LOG_DIR")"
  fa_log_file="$(load_env_value "${src}" "LOG_FILE")"
  fa_log_level="$(load_env_value "${src}" "LOG_LEVEL")"
  fa_log_to_stdout="$(load_env_value "${src}" "LOG_TO_STDOUT")"
  fa_trusted_hosts="$(load_env_value "${src}" "TRUSTED_HOSTS")"

  [[ -n "${fa_app_env}" ]] && APP_ENV="${fa_app_env}"
  [[ -n "${fa_cors_creds}" ]] && CORS_ALLOW_CREDENTIALS="${fa_cors_creds}"
  [[ -n "${fa_cors_origins}" ]] && CORS_ALLOW_ORIGINS="${fa_cors_origins}"
  [[ -n "${fa_cors_regex}" ]] && CORS_ALLOW_ORIGIN_REGEX="${fa_cors_regex}"
  [[ -n "${fa_allowed_azp}" ]] && FASTAPI_ALLOWED_AZP="${fa_allowed_azp}"
  [[ -n "${fa_verify_aud}" ]] && FASTAPI_VERIFY_AUDIENCE="${fa_verify_aud}"

  [[ -n "${fa_kc_base_url}" ]] && KEYCLOAK_BASE_URL="${fa_kc_base_url}"
  [[ -n "${fa_kc_realm}" ]] && KEYCLOAK_REALM="${fa_kc_realm}"
  # These may intentionally be empty; only override if present.
  [[ -n "${fa_kc_introspect_id}" ]] && KEYCLOAK_INTROSPECTION_CLIENT_ID="${fa_kc_introspect_id}"
  [[ -n "${fa_kc_introspect_secret}" ]] && KEYCLOAK_INTROSPECTION_CLIENT_SECRET="${fa_kc_introspect_secret}"

  [[ -n "${fa_log_dir}" ]] && LOG_DIR="${fa_log_dir}"
  [[ -n "${fa_log_file}" ]] && LOG_FILE="${fa_log_file}"
  [[ -n "${fa_log_level}" ]] && LOG_LEVEL="${fa_log_level}"
  [[ -n "${fa_log_to_stdout}" ]] && LOG_TO_STDOUT="${fa_log_to_stdout}"
  [[ -n "${fa_trusted_hosts}" ]] && TRUSTED_HOSTS="${fa_trusted_hosts}"
  fi

  # Redis / Celery (optional)
  local r_inc r_host r_port r_pass c_inc c_broker_db c_result_db c_broker_url c_backend
  r_inc="$(load_env_value "${src}" "INCLUDE_REDIS")"
  [[ "${r_inc}" == "0" || "${r_inc}" == "1" ]] && INCLUDE_REDIS="${r_inc}"

  r_host="$(load_env_value "${src}" "REDIS_HOST")"
  r_port="$(load_env_value "${src}" "REDIS_PORT")"
  r_pass="$(load_env_value "${src}" "REDIS_PASSWORD")"

  [[ -n "${r_host}" ]] && REDIS_HOST="${r_host}"
  [[ -n "${r_port}" ]] && REDIS_PORT="${r_port}"
  [[ -n "${r_pass}" ]] && REDIS_PASSWORD="${r_pass}"

  c_inc="$(load_env_value "${src}" "INCLUDE_CELERY")"
  [[ "${c_inc}" == "0" || "${c_inc}" == "1" ]] && INCLUDE_CELERY="${c_inc}"

  c_broker_db="$(load_env_value "${src}" "CELERY_BROKER_DB")"
  c_result_db="$(load_env_value "${src}" "CELERY_RESULT_DB")"
  c_broker_url="$(load_env_value "${src}" "CELERY_BROKER_URL")"
  c_backend="$(load_env_value "${src}" "CELERY_RESULT_BACKEND")"

  [[ -n "${c_broker_db}" ]] && CELERY_BROKER_DB="${c_broker_db}"
  [[ -n "${c_result_db}" ]] && CELERY_RESULT_DB="${c_result_db}"
  [[ -n "${c_broker_url}" ]] && CELERY_BROKER_URL="${c_broker_url}"
  [[ -n "${c_backend}" ]] && CELERY_RESULT_BACKEND="${c_backend}"


  if [[ "${INCLUDE_KEYCLOAK}" -eq 1 ]]; then
    local kc_host kc_port kc_db kc_user kc_pass kc_schema
    kc_host="$(load_env_value "${src}" "KC_DB_URL_HOST")"
    kc_port="$(load_env_value "${src}" "KC_DB_URL_PORT")"
    kc_db="$(load_env_value "${src}" "KC_DB_URL_DATABASE")"
    kc_user="$(load_env_value "${src}" "KC_DB_USERNAME")"
    kc_pass="$(load_env_value "${src}" "KC_DB_PASSWORD")"
    kc_schema="$(load_env_value "${src}" "KC_DB_SCHEMA")"

    # Keycloak bootstrap (optional)
    local kc_admin_user kc_admin_pass
    kc_admin_user="$(load_env_value "${src}" "KC_BOOTSTRAP_ADMIN_USERNAME")"
    kc_admin_pass="$(load_env_value "${src}" "KC_BOOTSTRAP_ADMIN_PASSWORD")"
    [[ -n "${kc_admin_user}" ]] && KEYCLOAK_BOOTSTRAP_ADMIN_USERNAME="${kc_admin_user}"
    [[ -n "${kc_admin_pass}" ]] && KEYCLOAK_BOOTSTRAP_ADMIN_PASSWORD="${kc_admin_pass}"

    # Keycloak runtime (optional)
    local kc_hostname kc_hostname_strict kc_http_enabled kc_https_port kc_health kc_metrics kc_mgmt_port kc_mgmt_scheme
    kc_hostname="$(load_env_value "${src}" "KC_HOSTNAME")"
    kc_hostname_strict="$(load_env_value "${src}" "KC_HOSTNAME_STRICT")"
    kc_http_enabled="$(load_env_value "${src}" "KC_HTTP_ENABLED")"
    kc_https_port="$(load_env_value "${src}" "KC_HTTPS_PORT")"
    kc_health="$(load_env_value "${src}" "KC_HEALTH_ENABLED")"
    kc_metrics="$(load_env_value "${src}" "KC_METRICS_ENABLED")"
    kc_mgmt_port="$(load_env_value "${src}" "KC_HTTP_MANAGEMENT_PORT")"
    kc_mgmt_scheme="$(load_env_value "${src}" "KC_HTTP_MANAGEMENT_SCHEME")"

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

  # Try preferred VAULT_ADDR first; if it fails, fall back to container address.
  if curl "${args[@]}" "${url}"; then
    return 0
  fi

  local fallback_addr="https://${VAULT_CONTAINER}:8200"
  if [[ "${VAULT_ADDR%/}" != "${fallback_addr%/}" ]]; then
    warn "Vault call failed against ${VAULT_ADDR}. Retrying via container address: ${fallback_addr}"
    url="${fallback_addr%/}/v1/${path#/}"
    curl "${args[@]}" "${url}"
    return $?
  fi

  return 1
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

ensure_fastapi_secrets_complete_in_vault() {
  # Non-destructive: only fills keys that are missing or empty.
  # Uses Vault KV v2 write to create a new version containing the existing keys plus defaults.
  [[ "${INCLUDE_FASTAPI}" -eq 1 ]] || return 0

  vault_token_acquire_if_needed || {
    warn "Skipping fastapi_secrets convergence: VAULT_TOKEN not available"
    return 0
  }

  need_cmd jq

  local fastapi_path existing desired payload
  fastapi_path="$(prefixed_path "fastapi_secrets")"

  existing="$(vault_kv2_get_data_json "${VAULT_MOUNT}" "${fastapi_path}" 2>/dev/null || echo '{}')"
  # Defensive: if Vault returns non-object, treat as empty.
  echo "${existing}" | jq -e 'type=="object"' >/dev/null 2>&1 || existing='{}'

  desired="$(jq -n \
    --argjson existing "${existing}" \
    --arg FASTAPI_DB_URL_HOST "${FASTAPI_DB_URL_HOST}" \
    --arg FASTAPI_DB_URL_PORT "${FASTAPI_DB_URL_PORT}" \
    --arg FASTAPI_DB_URL_DATABASE "${FASTAPI_DB_URL_DATABASE}" \
    --arg FASTAPI_DB_USERNAME "${FASTAPI_DB_USERNAME}" \
    --arg FASTAPI_DB_PASSWORD "${FASTAPI_DB_PASSWORD}" \
    --arg FASTAPI_DB_SCHEMA "${FASTAPI_DB_SCHEMA}" \
    --arg APP_ENV "${APP_ENV}" \
    --arg CORS_ALLOW_CREDENTIALS "${CORS_ALLOW_CREDENTIALS}" \
    --arg CORS_ALLOW_ORIGINS "${CORS_ALLOW_ORIGINS}" \
    --arg CORS_ALLOW_ORIGIN_REGEX "${CORS_ALLOW_ORIGIN_REGEX}" \
    --arg FASTAPI_ALLOWED_AZP "${FASTAPI_ALLOWED_AZP}" \
    --arg FASTAPI_VERIFY_AUDIENCE "${FASTAPI_VERIFY_AUDIENCE}" \
    --arg KEYCLOAK_BASE_URL "${KEYCLOAK_BASE_URL}" \
    --arg KEYCLOAK_REALM "${KEYCLOAK_REALM}" \
    --arg KEYCLOAK_INTROSPECTION_CLIENT_ID "${KEYCLOAK_INTROSPECTION_CLIENT_ID}" \
    --arg KEYCLOAK_INTROSPECTION_CLIENT_SECRET "${KEYCLOAK_INTROSPECTION_CLIENT_SECRET}" \
    --arg LOG_DIR "${LOG_DIR}" \
    --arg LOG_FILE "${LOG_FILE}" \
    --arg LOG_LEVEL "${LOG_LEVEL}" \
    --arg LOG_TO_STDOUT "${LOG_TO_STDOUT}" \
    --arg TRUSTED_HOSTS "${TRUSTED_HOSTS}" \
    --arg REDIS_HOST "${REDIS_HOST}" \
    --arg REDIS_PORT "${REDIS_PORT}" \
    --arg REDIS_PASSWORD "${REDIS_PASSWORD}" \
    --arg CELERY_BROKER_DB "${CELERY_BROKER_DB}" \
    --arg CELERY_RESULT_DB "${CELERY_RESULT_DB}" \
    --arg CELERY_BROKER_URL "${CELERY_BROKER_URL}" \
    --arg CELERY_RESULT_BACKEND "${CELERY_RESULT_BACKEND}" \
    --arg INCLUDE_REDIS "${INCLUDE_REDIS}" \
    --arg INCLUDE_CELERY "${INCLUDE_CELERY}" \
    '
    def missing($v):
      ($v == null)
      or ($v | type == "string" and ($v | length) == 0);

    ($existing
      | .FASTAPI_DB_URL_HOST = (if missing(.FASTAPI_DB_URL_HOST) then $FASTAPI_DB_URL_HOST else .FASTAPI_DB_URL_HOST end)
      | .FASTAPI_DB_URL_PORT = (if missing(.FASTAPI_DB_URL_PORT) then $FASTAPI_DB_URL_PORT else .FASTAPI_DB_URL_PORT end)
      | .FASTAPI_DB_URL_DATABASE = (if missing(.FASTAPI_DB_URL_DATABASE) then $FASTAPI_DB_URL_DATABASE else .FASTAPI_DB_URL_DATABASE end)
      | .FASTAPI_DB_USERNAME = (if missing(.FASTAPI_DB_USERNAME) then $FASTAPI_DB_USERNAME else .FASTAPI_DB_USERNAME end)
      | .FASTAPI_DB_PASSWORD = (if missing(.FASTAPI_DB_PASSWORD) then $FASTAPI_DB_PASSWORD else .FASTAPI_DB_PASSWORD end)
      | .FASTAPI_DB_SCHEMA = (if missing(.FASTAPI_DB_SCHEMA) then $FASTAPI_DB_SCHEMA else .FASTAPI_DB_SCHEMA end)

      | .APP_ENV = (if missing(.APP_ENV) then $APP_ENV else .APP_ENV end)
      | .CORS_ALLOW_CREDENTIALS = (if missing(.CORS_ALLOW_CREDENTIALS) then $CORS_ALLOW_CREDENTIALS else .CORS_ALLOW_CREDENTIALS end)
      | .CORS_ALLOW_ORIGINS = (if missing(.CORS_ALLOW_ORIGINS) then $CORS_ALLOW_ORIGINS else .CORS_ALLOW_ORIGINS end)
      | .CORS_ALLOW_ORIGIN_REGEX = (if missing(.CORS_ALLOW_ORIGIN_REGEX) then $CORS_ALLOW_ORIGIN_REGEX else .CORS_ALLOW_ORIGIN_REGEX end)
      | .FASTAPI_ALLOWED_AZP = (if missing(.FASTAPI_ALLOWED_AZP) then $FASTAPI_ALLOWED_AZP else .FASTAPI_ALLOWED_AZP end)
      | .FASTAPI_VERIFY_AUDIENCE = (if missing(.FASTAPI_VERIFY_AUDIENCE) then $FASTAPI_VERIFY_AUDIENCE else .FASTAPI_VERIFY_AUDIENCE end)

      | .KEYCLOAK_BASE_URL = (if missing(.KEYCLOAK_BASE_URL) then $KEYCLOAK_BASE_URL else .KEYCLOAK_BASE_URL end)
      | .KEYCLOAK_REALM = (if missing(.KEYCLOAK_REALM) then $KEYCLOAK_REALM else .KEYCLOAK_REALM end)
      | .KEYCLOAK_INTROSPECTION_CLIENT_ID = (if .KEYCLOAK_INTROSPECTION_CLIENT_ID == null then $KEYCLOAK_INTROSPECTION_CLIENT_ID else .KEYCLOAK_INTROSPECTION_CLIENT_ID end)
      | .KEYCLOAK_INTROSPECTION_CLIENT_SECRET = (if .KEYCLOAK_INTROSPECTION_CLIENT_SECRET == null then $KEYCLOAK_INTROSPECTION_CLIENT_SECRET else .KEYCLOAK_INTROSPECTION_CLIENT_SECRET end)

      | .LOG_DIR = (if missing(.LOG_DIR) then $LOG_DIR else .LOG_DIR end)
      | .LOG_FILE = (if missing(.LOG_FILE) then $LOG_FILE else .LOG_FILE end)
      | .LOG_LEVEL = (if missing(.LOG_LEVEL) then $LOG_LEVEL else .LOG_LEVEL end)
      | .LOG_TO_STDOUT = (if missing(.LOG_TO_STDOUT) then $LOG_TO_STDOUT else .LOG_TO_STDOUT end)
      | .TRUSTED_HOSTS = (if missing(.TRUSTED_HOSTS) then $TRUSTED_HOSTS else .TRUSTED_HOSTS end)

      | (if $INCLUDE_REDIS == "1" then
            .REDIS_HOST = (if missing(.REDIS_HOST) then $REDIS_HOST else .REDIS_HOST end)
          | .REDIS_PORT = (if missing(.REDIS_PORT) then $REDIS_PORT else .REDIS_PORT end)
          | .REDIS_PASSWORD = (if missing(.REDIS_PASSWORD) then $REDIS_PASSWORD else .REDIS_PASSWORD end)
        else . end)

      | (if $INCLUDE_CELERY == "1" then
            .CELERY_BROKER_DB = (if missing(.CELERY_BROKER_DB) then $CELERY_BROKER_DB else .CELERY_BROKER_DB end)
          | .CELERY_RESULT_DB = (if missing(.CELERY_RESULT_DB) then $CELERY_RESULT_DB else .CELERY_RESULT_DB end)
          | .CELERY_BROKER_URL = (if missing(.CELERY_BROKER_URL) then $CELERY_BROKER_URL else .CELERY_BROKER_URL end)
          | .CELERY_RESULT_BACKEND = (if missing(.CELERY_RESULT_BACKEND) then $CELERY_RESULT_BACKEND else .CELERY_RESULT_BACKEND end)
        else . end)
    )
  ')" || return 1

  # No-op if nothing would change.
  if jq -e --argjson a "${existing}" --argjson b "${desired}" '$a == $b' >/dev/null 2>&1; then
    log "Vault fastapi_secrets already contains all required keys: ${VAULT_MOUNT}/${fastapi_path}"
    return 0
  fi

  payload="$(jq -cn --argjson data "${desired}" '{data: $data}')" || return 1

  log "Converging Vault secret (fill missing keys only): ${VAULT_MOUNT}/${fastapi_path}"
  vault_curl "POST" "${VAULT_MOUNT}/data/${fastapi_path}" "${payload}" >/dev/null || return 1
  return 0
}


vault_try_load_from_vault() {
  # Only used in generate mode when prefer vault and token is available.
  vault_token_acquire_if_needed || return 1

  local postgres_path pgadmin_path fastapi_path keycloak_path
  postgres_path="$(prefixed_path "postgres")"
  pgadmin_path="$(prefixed_path "pgadmin")"
  fastapi_path="$(prefixed_path "fastapi_secrets")"
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

  # FastAPI secrets (optional)
  if [[ "${INCLUDE_FASTAPI}" -eq 1 ]]; then
    if data="$(vault_kv2_get_data_json "${VAULT_MOUNT}" "${fastapi_path}" 2>/dev/null || true)"; then
      # FastAPI -> Postgres (minimum fields)
      if echo "${data}" | jq -e '.FASTAPI_DB_URL_DATABASE and .FASTAPI_DB_USERNAME and .FASTAPI_DB_PASSWORD' >/dev/null 2>&1; then
        [[ -n "${FASTAPI_DB_URL_DATABASE}" ]] || FASTAPI_DB_URL_DATABASE="$(echo "${data}" | jq -r '.FASTAPI_DB_URL_DATABASE')"
        [[ -n "${FASTAPI_DB_USERNAME}" ]]     || FASTAPI_DB_USERNAME="$(echo "${data}" | jq -r '.FASTAPI_DB_USERNAME')"
        [[ -n "${FASTAPI_DB_PASSWORD}" ]]     || FASTAPI_DB_PASSWORD="$(echo "${data}" | jq -r '.FASTAPI_DB_PASSWORD')"
        [[ -n "${FASTAPI_DB_SCHEMA}" ]]       || FASTAPI_DB_SCHEMA="$(echo "${data}" | jq -r '.FASTAPI_DB_SCHEMA // "public"')"
        [[ -n "${FASTAPI_DB_URL_HOST}" ]]     || FASTAPI_DB_URL_HOST="$(echo "${data}" | jq -r '.FASTAPI_DB_URL_HOST // "postgres_primary"')"
        [[ -n "${FASTAPI_DB_URL_PORT}" ]]     || FASTAPI_DB_URL_PORT="$(echo "${data}" | jq -r '.FASTAPI_DB_URL_PORT // "5432"')"
        log "Using existing Vault secret for FastAPI DB credentials: ${VAULT_MOUNT}/${fastapi_path}"
      fi

      # Redis / Celery (optional; also stored under fastapi_secrets)
      local v
      v="$(echo "${data}" | jq -r '.REDIS_PASSWORD // ""')"
      [[ -n "${REDIS_PASSWORD}" ]] || REDIS_PASSWORD="${v}"

      v="$(echo "${data}" | jq -r '.REDIS_HOST // ""')"
      [[ -n "${REDIS_HOST}" ]] || REDIS_HOST="${v}"

      v="$(echo "${data}" | jq -r '.REDIS_PORT // ""')"
      [[ -n "${REDIS_PORT}" ]] || REDIS_PORT="${v}"

      v="$(echo "${data}" | jq -r '.CELERY_BROKER_DB // ""')"
      [[ -n "${CELERY_BROKER_DB}" ]] || CELERY_BROKER_DB="${v}"

      v="$(echo "${data}" | jq -r '.CELERY_RESULT_DB // ""')"
      [[ -n "${CELERY_RESULT_DB}" ]] || CELERY_RESULT_DB="${v}"

      v="$(echo "${data}" | jq -r '.CELERY_BROKER_URL // ""')"
      [[ -n "${CELERY_BROKER_URL}" ]] || CELERY_BROKER_URL="${v}"

      v="$(echo "${data}" | jq -r '.CELERY_RESULT_BACKEND // ""')"
      [[ -n "${CELERY_RESULT_BACKEND}" ]] || CELERY_RESULT_BACKEND="${v}"

      if [[ -n "${REDIS_PASSWORD}" || -n "${CELERY_BROKER_URL}" || -n "${CELERY_RESULT_BACKEND}" ]]; then
        log "Using existing Vault secret for Redis/Celery (fastapi_secrets): ${VAULT_MOUNT}/${fastapi_path}"
      fi
    fi
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
    log "Using existing local bootstrap artifacts: ${LOCAL_ENV_SOURCE:-${ENV_FILE}}"
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
  if [[ "${INCLUDE_FASTAPI}" -eq 1 ]]; then
    FASTAPI_DB_PASSWORD="${FASTAPI_DB_PASSWORD:-$(gen_urlsafe 32)}"
  fi
  if [[ "${INCLUDE_KEYCLOAK}" -eq 1 ]]; then
    KEYCLOAK_DB_PASSWORD="${KEYCLOAK_DB_PASSWORD:-$(gen_urlsafe 32)}"
  fi
  if [[ "${INCLUDE_REDIS}" -eq 1 ]]; then
    REDIS_PASSWORD="${REDIS_PASSWORD:-$(gen_urlsafe 32)}"
  fi
else
  [[ -n "${POSTGRES_PASSWORD}" ]] || POSTGRES_PASSWORD="$(gen_urlsafe 32)"
  [[ -n "${PGADMIN_DEFAULT_PASSWORD}" ]] || PGADMIN_DEFAULT_PASSWORD="$(gen_urlsafe 32)"
  if [[ "${INCLUDE_FASTAPI}" -eq 1 ]]; then
    [[ -n "${FASTAPI_DB_PASSWORD}" ]] || FASTAPI_DB_PASSWORD="$(gen_urlsafe 32)"
  fi
  if [[ "${INCLUDE_KEYCLOAK}" -eq 1 ]]; then
    [[ -n "${KEYCLOAK_DB_PASSWORD}" ]] || KEYCLOAK_DB_PASSWORD="$(gen_urlsafe 32)"
  fi
  if [[ "${INCLUDE_REDIS}" -eq 1 ]]; then
    [[ -n "${REDIS_PASSWORD}" ]] || REDIS_PASSWORD="$(gen_urlsafe 32)"
  fi
fi

# FastAPI defaults
if [[ "${INCLUDE_FASTAPI}" -eq 1 ]]; then
  [[ -n "${FASTAPI_DB_URL_DATABASE}" ]] || FASTAPI_DB_URL_DATABASE="${POSTGRES_DB}"
  [[ -n "${FASTAPI_DB_URL_HOST}" ]] || FASTAPI_DB_URL_HOST="postgres_primary"
  [[ -n "${FASTAPI_DB_URL_PORT}" ]] || FASTAPI_DB_URL_PORT="5432"
  [[ -n "${FASTAPI_DB_SCHEMA}" ]] || FASTAPI_DB_SCHEMA="public"
fi

# Redis / Celery defaults (and derived URLs)
if [[ "${INCLUDE_CELERY}" -eq 1 && "${INCLUDE_REDIS}" -ne 1 ]]; then
  err "Celery is enabled but Redis is disabled. Either enable Redis or pass explicit broker/result URLs."
fi

if [[ "${INCLUDE_REDIS}" -eq 1 ]]; then
  [[ -n "${REDIS_HOST}" ]] || REDIS_HOST="redis"
  [[ -n "${REDIS_PORT}" ]] || REDIS_PORT="6379"
  [[ -n "${REDIS_PASSWORD}" ]] || err "Redis is enabled but REDIS_PASSWORD is empty."

  if [[ "${INCLUDE_CELERY}" -eq 1 ]]; then
    [[ -n "${CELERY_BROKER_DB}" ]] || CELERY_BROKER_DB="0"
    [[ -n "${CELERY_RESULT_DB}" ]] || CELERY_RESULT_DB="1"

    # If the URLs are not explicitly provided, compute them from the Redis settings.
    # Note: the password is embedded in the URL, so treat these as secrets.
    if [[ -z "${CELERY_BROKER_URL}" ]]; then
      CELERY_BROKER_URL="redis://:${REDIS_PASSWORD}@${REDIS_HOST}:${REDIS_PORT}/${CELERY_BROKER_DB}"
    fi
    if [[ -z "${CELERY_RESULT_BACKEND}" ]]; then
      CELERY_RESULT_BACKEND="redis://:${REDIS_PASSWORD}@${REDIS_HOST}:${REDIS_PORT}/${CELERY_RESULT_DB}"
    fi
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

INCLUDE_FASTAPI=${INCLUDE_FASTAPI}

# FastAPI (network_tools DB — limited DML user)
FASTAPI_DB_URL_HOST=${FASTAPI_DB_URL_HOST}
FASTAPI_DB_URL_PORT=${FASTAPI_DB_URL_PORT}
FASTAPI_DB_URL_DATABASE=${FASTAPI_DB_URL_DATABASE}
FASTAPI_DB_USERNAME=${FASTAPI_DB_USERNAME}
FASTAPI_DB_PASSWORD=${FASTAPI_DB_PASSWORD}
FASTAPI_DB_SCHEMA=${FASTAPI_DB_SCHEMA}

# FastAPI runtime / auth / logging
APP_ENV=${APP_ENV}
CORS_ALLOW_CREDENTIALS=${CORS_ALLOW_CREDENTIALS}
CORS_ALLOW_ORIGINS=${CORS_ALLOW_ORIGINS}
CORS_ALLOW_ORIGIN_REGEX=${CORS_ALLOW_ORIGIN_REGEX}
FASTAPI_ALLOWED_AZP=${FASTAPI_ALLOWED_AZP}
FASTAPI_VERIFY_AUDIENCE=${FASTAPI_VERIFY_AUDIENCE}
KEYCLOAK_BASE_URL=${KEYCLOAK_BASE_URL}
KEYCLOAK_REALM=${KEYCLOAK_REALM}
KEYCLOAK_INTROSPECTION_CLIENT_ID=${KEYCLOAK_INTROSPECTION_CLIENT_ID}
KEYCLOAK_INTROSPECTION_CLIENT_SECRET=${KEYCLOAK_INTROSPECTION_CLIENT_SECRET}
LOG_DIR=${LOG_DIR}
LOG_FILE=${LOG_FILE}
LOG_LEVEL=${LOG_LEVEL}
LOG_TO_STDOUT=${LOG_TO_STDOUT}
TRUSTED_HOSTS=${TRUSTED_HOSTS}

# Redis / Celery
INCLUDE_REDIS=${INCLUDE_REDIS}
INCLUDE_CELERY=${INCLUDE_CELERY}
REDIS_HOST=${REDIS_HOST}
REDIS_PORT=${REDIS_PORT}
REDIS_PASSWORD=${REDIS_PASSWORD}
CELERY_BROKER_DB=${CELERY_BROKER_DB}
CELERY_RESULT_DB=${CELERY_RESULT_DB}
CELERY_BROKER_URL=${CELERY_BROKER_URL}
CELERY_RESULT_BACKEND=${CELERY_RESULT_BACKEND}

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
KC_DB_URL_PROPERTIES=${KEYCLOAK_DB_URL_PROPERTIES}
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
KC_PROXY_HEADERS=${KEYCLOAK_PROXY_HEADERS}
KC_PROXY_TRUSTED_ADDRESSES=${KEYCLOAK_PROXY_TRUSTED_ADDRESSES}
KC_HTTP_ENABLED=${KEYCLOAK_HTTP_ENABLED}
KC_HTTP_PORT=${KEYCLOAK_HTTP_PORT}
KC_HTTPS_PORT=${KEYCLOAK_HTTPS_PORT}
KC_HEALTH_ENABLED=${KEYCLOAK_HEALTH_ENABLED}
KC_METRICS_ENABLED=${KEYCLOAK_METRICS_ENABLED}
KC_HTTP_MANAGEMENT_PORT=${KEYCLOAK_HTTP_MANAGEMENT_PORT}
KC_HTTP_MANAGEMENT_SCHEME=${KEYCLOAK_HTTP_MANAGEMENT_SCHEME}
EOF
  fi
fi

# Credentials JSON
export INCLUDE_FASTAPI INCLUDE_REDIS INCLUDE_CELERY INCLUDE_KEYCLOAK INCLUDE_KEYCLOAK_BOOTSTRAP INCLUDE_KEYCLOAK_RUNTIME KEYCLOAK_TLS_PRESENT

jq -n \
    --arg INCLUDE_REDIS "$INCLUDE_REDIS" \
    --arg INCLUDE_CELERY "$INCLUDE_CELERY" \
  --arg generated_at_utc "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
  --arg vault_mount "${VAULT_MOUNT}" \
  --arg vault_prefix "${VAULT_PREFIX}" \
  --arg POSTGRES_DB "${POSTGRES_DB}" \
  --arg POSTGRES_USER "${POSTGRES_USER}" \
  --arg POSTGRES_PASSWORD "${POSTGRES_PASSWORD}" \
  --arg PGADMIN_DEFAULT_EMAIL "${PGADMIN_DEFAULT_EMAIL}" \
  --arg PGADMIN_DEFAULT_PASSWORD "${PGADMIN_DEFAULT_PASSWORD}" \
  --arg FASTAPI_DB_URL_HOST "${FASTAPI_DB_URL_HOST}" \
  --arg FASTAPI_DB_URL_PORT "${FASTAPI_DB_URL_PORT}" \
  --arg FASTAPI_DB_URL_DATABASE "${FASTAPI_DB_URL_DATABASE}" \
  --arg FASTAPI_DB_USERNAME "${FASTAPI_DB_USERNAME}" \
  --arg FASTAPI_DB_PASSWORD "${FASTAPI_DB_PASSWORD}" \
  --arg FASTAPI_DB_SCHEMA "${FASTAPI_DB_SCHEMA}" \
  --arg APP_ENV "${APP_ENV}" \
  --arg CORS_ALLOW_CREDENTIALS "${CORS_ALLOW_CREDENTIALS}" \
  --arg CORS_ALLOW_ORIGINS "${CORS_ALLOW_ORIGINS}" \
  --arg CORS_ALLOW_ORIGIN_REGEX "${CORS_ALLOW_ORIGIN_REGEX}" \
  --arg FASTAPI_ALLOWED_AZP "${FASTAPI_ALLOWED_AZP}" \
  --arg FASTAPI_VERIFY_AUDIENCE "${FASTAPI_VERIFY_AUDIENCE}" \
  --arg KEYCLOAK_BASE_URL "${KEYCLOAK_BASE_URL}" \
  --arg KEYCLOAK_REALM "${KEYCLOAK_REALM}" \
  --arg KEYCLOAK_INTROSPECTION_CLIENT_ID "${KEYCLOAK_INTROSPECTION_CLIENT_ID}" \
  --arg KEYCLOAK_INTROSPECTION_CLIENT_SECRET "${KEYCLOAK_INTROSPECTION_CLIENT_SECRET}" \
  --arg LOG_DIR "${LOG_DIR}" \
  --arg LOG_FILE "${LOG_FILE}" \
  --arg LOG_LEVEL "${LOG_LEVEL}" \
  --arg LOG_TO_STDOUT "${LOG_TO_STDOUT}" \
  --arg TRUSTED_HOSTS "${TRUSTED_HOSTS}" \
  --arg REDIS_HOST "${REDIS_HOST}" \
  --arg REDIS_PORT "${REDIS_PORT}" \
  --arg REDIS_PASSWORD "${REDIS_PASSWORD}" \
  --arg CELERY_BROKER_DB "${CELERY_BROKER_DB}" \
  --arg CELERY_RESULT_DB "${CELERY_RESULT_DB}" \
  --arg CELERY_BROKER_URL "${CELERY_BROKER_URL}" \
  --arg CELERY_RESULT_BACKEND "${CELERY_RESULT_BACKEND}" \
  --arg KC_DB "postgres" \
  --arg KC_DB_URL_HOST "${KEYCLOAK_DB_URL_HOST}" \
  --arg KC_DB_URL_PORT "${KEYCLOAK_DB_URL_PORT}" \
  --arg KC_DB_URL_DATABASE "${KEYCLOAK_DB_URL_DATABASE}" \
  --arg KC_DB_USERNAME "${KEYCLOAK_DB_USERNAME}" \
  --arg KC_DB_PASSWORD "${KEYCLOAK_DB_PASSWORD}" \
  --arg KC_DB_SCHEMA "${KEYCLOAK_DB_SCHEMA}" \
  --arg KC_DB_URL_PROPERTIES "${KEYCLOAK_DB_URL_PROPERTIES}" \
  --arg KEYCLOAK_ADMIN "${KEYCLOAK_BOOTSTRAP_ADMIN_USERNAME}" \
  --arg KEYCLOAK_ADMIN_PASSWORD "${KEYCLOAK_BOOTSTRAP_ADMIN_PASSWORD}" \
  --arg KC_PROXY_HEADERS "${KEYCLOAK_PROXY_HEADERS}" \
  --arg KC_PROXY_TRUSTED_ADDRESSES "${KEYCLOAK_PROXY_TRUSTED_ADDRESSES}" \
  --arg KC_HTTP_PORT "${KEYCLOAK_HTTP_PORT}" \
  --arg KC_BOOTSTRAP_ADMIN_USERNAME "${KEYCLOAK_BOOTSTRAP_ADMIN_USERNAME}" \
  --arg KC_BOOTSTRAP_ADMIN_PASSWORD "${KEYCLOAK_BOOTSTRAP_ADMIN_PASSWORD}" \
  --arg KC_HOSTNAME "${KEYCLOAK_HOSTNAME}" \
  --arg KC_HOSTNAME_STRICT "${KEYCLOAK_HOSTNAME_STRICT}" \
  --arg KC_HTTP_ENABLED "${KEYCLOAK_HTTP_ENABLED}" \
  --arg KC_HTTPS_PORT "${KEYCLOAK_HTTPS_PORT}" \
  --arg KC_HEALTH_ENABLED "${KEYCLOAK_HEALTH_ENABLED}" \
  --arg KC_METRICS_ENABLED "${KEYCLOAK_METRICS_ENABLED}" \
  --arg KC_HTTP_MANAGEMENT_PORT "${KEYCLOAK_HTTP_MANAGEMENT_PORT}" \
  --arg KC_HTTP_MANAGEMENT_SCHEME "${KEYCLOAK_HTTP_MANAGEMENT_SCHEME}" \
  --arg KC_HTTPS_CERTIFICATE_PEM_B64 "${KEYCLOAK_TLS_CERT_PEM_B64}" \
  --arg KC_HTTPS_CERTIFICATE_KEY_PEM_B64 "${KEYCLOAK_TLS_KEY_PEM_B64}" \
  --arg KC_HTTPS_CA_CERT_PEM_B64 "${KEYCLOAK_TLS_CA_PEM_B64}" \
  '{
    generated_at_utc: $generated_at_utc,
    vault: { mount: $vault_mount, prefix: $vault_prefix },
    postgres: { POSTGRES_DB: $POSTGRES_DB, POSTGRES_USER: $POSTGRES_USER, POSTGRES_PASSWORD: $POSTGRES_PASSWORD },
    pgadmin: { PGADMIN_DEFAULT_EMAIL: $PGADMIN_DEFAULT_EMAIL, PGADMIN_DEFAULT_PASSWORD: $PGADMIN_DEFAULT_PASSWORD }
  }
  + (if env.INCLUDE_FASTAPI == "1" then { fastapi_secrets: (
        {
          FASTAPI_DB_URL_HOST: $FASTAPI_DB_URL_HOST,
          FASTAPI_DB_URL_PORT: $FASTAPI_DB_URL_PORT,
          FASTAPI_DB_URL_DATABASE: $FASTAPI_DB_URL_DATABASE,
          FASTAPI_DB_USERNAME: $FASTAPI_DB_USERNAME,
          FASTAPI_DB_PASSWORD: $FASTAPI_DB_PASSWORD,
          FASTAPI_DB_SCHEMA: $FASTAPI_DB_SCHEMA,
          APP_ENV: $APP_ENV,
          CORS_ALLOW_CREDENTIALS: $CORS_ALLOW_CREDENTIALS,
          CORS_ALLOW_ORIGINS: $CORS_ALLOW_ORIGINS,
          CORS_ALLOW_ORIGIN_REGEX: $CORS_ALLOW_ORIGIN_REGEX,
          FASTAPI_ALLOWED_AZP: $FASTAPI_ALLOWED_AZP,
          FASTAPI_VERIFY_AUDIENCE: $FASTAPI_VERIFY_AUDIENCE,
          KEYCLOAK_BASE_URL: $KEYCLOAK_BASE_URL,
          KEYCLOAK_REALM: $KEYCLOAK_REALM,
          KEYCLOAK_INTROSPECTION_CLIENT_ID: $KEYCLOAK_INTROSPECTION_CLIENT_ID,
          KEYCLOAK_INTROSPECTION_CLIENT_SECRET: $KEYCLOAK_INTROSPECTION_CLIENT_SECRET,
          LOG_DIR: $LOG_DIR,
          LOG_FILE: $LOG_FILE,
          LOG_LEVEL: $LOG_LEVEL,
          LOG_TO_STDOUT: $LOG_TO_STDOUT,
          TRUSTED_HOSTS: $TRUSTED_HOSTS
        }
        + (if $INCLUDE_REDIS == "1" then {
              REDIS_HOST: $REDIS_HOST,
              REDIS_PORT: $REDIS_PORT,
              REDIS_PASSWORD: $REDIS_PASSWORD
            } else {} end)
        + (if $INCLUDE_CELERY == "1" then {
              CELERY_BROKER_DB: $CELERY_BROKER_DB,
              CELERY_RESULT_DB: $CELERY_RESULT_DB,
              CELERY_BROKER_URL: $CELERY_BROKER_URL,
              CELERY_RESULT_BACKEND: $CELERY_RESULT_BACKEND
            } else {} end)
      ) } else {} end)
  + (if env.INCLUDE_KEYCLOAK == "1" then { keycloak_postgres: {
        KC_DB: $KC_DB,
        KC_DB_URL_HOST: $KC_DB_URL_HOST,
        KC_DB_URL_PORT: $KC_DB_URL_PORT,
        KC_DB_URL_DATABASE: $KC_DB_URL_DATABASE,
        KC_DB_USERNAME: $KC_DB_USERNAME,
        KC_DB_PASSWORD: $KC_DB_PASSWORD,
        KC_DB_URL_PROPERTIES: $KC_DB_URL_PROPERTIES,
        KC_DB_SCHEMA: $KC_DB_SCHEMA
      } } else {} end)
  + (if env.INCLUDE_KEYCLOAK_BOOTSTRAP == "1" then { keycloak_bootstrap: {
        KEYCLOAK_ADMIN: $KEYCLOAK_ADMIN,
        KEYCLOAK_ADMIN_PASSWORD: $KEYCLOAK_ADMIN_PASSWORD,
        KC_BOOTSTRAP_ADMIN_USERNAME: $KC_BOOTSTRAP_ADMIN_USERNAME,
        KC_BOOTSTRAP_ADMIN_PASSWORD: $KC_BOOTSTRAP_ADMIN_PASSWORD
      } } else {} end)
  + (if env.INCLUDE_KEYCLOAK_RUNTIME == "1" then { keycloak_runtime: {
        KC_HOSTNAME: $KC_HOSTNAME,
        KC_HOSTNAME_STRICT: $KC_HOSTNAME_STRICT,
        KC_PROXY_HEADERS: $KC_PROXY_HEADERS,
        KC_PROXY_TRUSTED_ADDRESSES: $KC_PROXY_TRUSTED_ADDRESSES,
        KC_HTTP_ENABLED: $KC_HTTP_ENABLED,
        KC_HTTP_PORT: $KC_HTTP_PORT,
        KC_HTTPS_PORT: $KC_HTTPS_PORT,
        KC_HEALTH_ENABLED: $KC_HEALTH_ENABLED,
        KC_METRICS_ENABLED: $KC_METRICS_ENABLED,
        KC_HTTP_MANAGEMENT_PORT: $KC_HTTP_MANAGEMENT_PORT,
        KC_HTTP_MANAGEMENT_SCHEME: $KC_HTTP_MANAGEMENT_SCHEME
      } } else {} end)
  + (if env.KEYCLOAK_TLS_PRESENT == "1" then { keycloak_tls: {
        KC_HTTPS_CERTIFICATE_PEM_B64: $KC_HTTPS_CERTIFICATE_PEM_B64,
        KC_HTTPS_CERTIFICATE_KEY_PEM_B64: $KC_HTTPS_CERTIFICATE_KEY_PEM_B64,
        KC_HTTPS_CA_CERT_PEM_B64: $KC_HTTPS_CA_CERT_PEM_B64
      } } else {} end)
  ' > "${JSON_FILE}"

export INCLUDE_FASTAPI INCLUDE_REDIS INCLUDE_CELERY INCLUDE_KEYCLOAK_BOOTSTRAP INCLUDE_KEYCLOAK_RUNTIME KEYCLOAK_TLS_PRESENT
# Seed spec JSON (KV v2)
# Structure required by vault_unseal_multi_kv_seed_bootstrap_rootless.sh:
# { mounts: [ { mount, version, prefix?, secrets: {...} } ] }

export INCLUDE_FASTAPI INCLUDE_REDIS INCLUDE_CELERY INCLUDE_KEYCLOAK INCLUDE_KEYCLOAK_BOOTSTRAP INCLUDE_KEYCLOAK_RUNTIME KEYCLOAK_TLS_PRESENT

if [[ -n "${VAULT_PREFIX}" ]]; then
  jq -n \
    --arg INCLUDE_REDIS "$INCLUDE_REDIS" \
    --arg INCLUDE_CELERY "$INCLUDE_CELERY" \
    --arg mount "${VAULT_MOUNT}" \
    --arg prefix "${VAULT_PREFIX}" \
    --arg POSTGRES_DB "${POSTGRES_DB}" \
    --arg POSTGRES_USER "${POSTGRES_USER}" \
    --arg POSTGRES_PASSWORD "${POSTGRES_PASSWORD}" \
    --arg PGADMIN_DEFAULT_EMAIL "${PGADMIN_DEFAULT_EMAIL}" \
    --arg PGADMIN_DEFAULT_PASSWORD "${PGADMIN_DEFAULT_PASSWORD}" \
    --arg FASTAPI_DB_URL_HOST "${FASTAPI_DB_URL_HOST}" \
    --arg FASTAPI_DB_URL_PORT "${FASTAPI_DB_URL_PORT}" \
    --arg FASTAPI_DB_URL_DATABASE "${FASTAPI_DB_URL_DATABASE}" \
    --arg FASTAPI_DB_USERNAME "${FASTAPI_DB_USERNAME}" \
    --arg FASTAPI_DB_PASSWORD "${FASTAPI_DB_PASSWORD}" \
    --arg FASTAPI_DB_SCHEMA "${FASTAPI_DB_SCHEMA}" \
    --arg APP_ENV "${APP_ENV}" \
    --arg CORS_ALLOW_CREDENTIALS "${CORS_ALLOW_CREDENTIALS}" \
    --arg CORS_ALLOW_ORIGINS "${CORS_ALLOW_ORIGINS}" \
    --arg CORS_ALLOW_ORIGIN_REGEX "${CORS_ALLOW_ORIGIN_REGEX}" \
    --arg FASTAPI_ALLOWED_AZP "${FASTAPI_ALLOWED_AZP}" \
    --arg FASTAPI_VERIFY_AUDIENCE "${FASTAPI_VERIFY_AUDIENCE}" \
    --arg KEYCLOAK_BASE_URL "${KEYCLOAK_BASE_URL}" \
    --arg KEYCLOAK_REALM "${KEYCLOAK_REALM}" \
    --arg KEYCLOAK_INTROSPECTION_CLIENT_ID "${KEYCLOAK_INTROSPECTION_CLIENT_ID}" \
    --arg KEYCLOAK_INTROSPECTION_CLIENT_SECRET "${KEYCLOAK_INTROSPECTION_CLIENT_SECRET}" \
    --arg LOG_DIR "${LOG_DIR}" \
    --arg LOG_FILE "${LOG_FILE}" \
    --arg LOG_LEVEL "${LOG_LEVEL}" \
    --arg LOG_TO_STDOUT "${LOG_TO_STDOUT}" \
    --arg TRUSTED_HOSTS "${TRUSTED_HOSTS}" \
    --arg REDIS_HOST "${REDIS_HOST}" \
    --arg REDIS_PORT "${REDIS_PORT}" \
    --arg REDIS_PASSWORD "${REDIS_PASSWORD}" \
    --arg CELERY_BROKER_DB "${CELERY_BROKER_DB}" \
    --arg CELERY_RESULT_DB "${CELERY_RESULT_DB}" \
    --arg CELERY_BROKER_URL "${CELERY_BROKER_URL}" \
    --arg CELERY_RESULT_BACKEND "${CELERY_RESULT_BACKEND}" \
    --arg KC_DB "postgres" \
    --arg KC_DB_URL_HOST "${KEYCLOAK_DB_URL_HOST}" \
    --arg KC_DB_URL_PORT "${KEYCLOAK_DB_URL_PORT}" \
    --arg KC_DB_URL_DATABASE "${KEYCLOAK_DB_URL_DATABASE}" \
    --arg KC_DB_USERNAME "${KEYCLOAK_DB_USERNAME}" \
    --arg KC_DB_PASSWORD "${KEYCLOAK_DB_PASSWORD}" \
    --arg KC_DB_URL_PROPERTIES "${KEYCLOAK_DB_URL_PROPERTIES}" \
    --arg KC_DB_SCHEMA "${KEYCLOAK_DB_SCHEMA}" \
    --arg KC_BOOTSTRAP_ADMIN_USERNAME "${KEYCLOAK_BOOTSTRAP_ADMIN_USERNAME}" \
    --arg KC_BOOTSTRAP_ADMIN_PASSWORD "${KEYCLOAK_BOOTSTRAP_ADMIN_PASSWORD}" \
    --arg KEYCLOAK_ADMIN "${KEYCLOAK_BOOTSTRAP_ADMIN_USERNAME}" \
    --arg KEYCLOAK_ADMIN_PASSWORD "${KEYCLOAK_BOOTSTRAP_ADMIN_PASSWORD}" \
    --arg KC_HOSTNAME "${KEYCLOAK_HOSTNAME}" \
    --arg KC_HOSTNAME_STRICT "${KEYCLOAK_HOSTNAME_STRICT}" \
    --arg KC_PROXY_HEADERS "${KEYCLOAK_PROXY_HEADERS}" \
    --arg KC_PROXY_TRUSTED_ADDRESSES "${KEYCLOAK_PROXY_TRUSTED_ADDRESSES}" \
    --arg KC_HTTP_ENABLED "${KEYCLOAK_HTTP_ENABLED}" \
    --arg KC_HTTP_PORT "${KEYCLOAK_HTTP_PORT}" \
    --arg KC_HTTPS_PORT "${KEYCLOAK_HTTPS_PORT}" \
    --arg KC_HEALTH_ENABLED "${KEYCLOAK_HEALTH_ENABLED}" \
    --arg KC_METRICS_ENABLED "${KEYCLOAK_METRICS_ENABLED}" \
    --arg KC_HTTP_MANAGEMENT_PORT "${KEYCLOAK_HTTP_MANAGEMENT_PORT}" \
    --arg KC_HTTP_MANAGEMENT_SCHEME "${KEYCLOAK_HTTP_MANAGEMENT_SCHEME}" \
    --arg KC_HTTPS_CERTIFICATE_PEM_B64 "${KEYCLOAK_TLS_CERT_PEM_B64}" \
    --arg KC_HTTPS_CERTIFICATE_KEY_PEM_B64 "${KEYCLOAK_TLS_KEY_PEM_B64}" \
    --arg KC_HTTPS_CA_CERT_PEM_B64 "${KEYCLOAK_TLS_CA_PEM_B64}" \
    '{
      mounts: [
        {
          mount: $mount,
          version: 2,
          prefix: $prefix,
          secrets: (
            { postgres: { POSTGRES_DB: $POSTGRES_DB, POSTGRES_USER: $POSTGRES_USER, POSTGRES_PASSWORD: $POSTGRES_PASSWORD },
              pgadmin: { PGADMIN_DEFAULT_EMAIL: $PGADMIN_DEFAULT_EMAIL, PGADMIN_DEFAULT_PASSWORD: $PGADMIN_DEFAULT_PASSWORD } }
            + (if env.INCLUDE_FASTAPI == "1" then { fastapi_secrets: (
        {
          FASTAPI_DB_URL_HOST: $FASTAPI_DB_URL_HOST,
          FASTAPI_DB_URL_PORT: $FASTAPI_DB_URL_PORT,
          FASTAPI_DB_URL_DATABASE: $FASTAPI_DB_URL_DATABASE,
          FASTAPI_DB_USERNAME: $FASTAPI_DB_USERNAME,
          FASTAPI_DB_PASSWORD: $FASTAPI_DB_PASSWORD,
          FASTAPI_DB_SCHEMA: $FASTAPI_DB_SCHEMA,
          APP_ENV: $APP_ENV,
          CORS_ALLOW_CREDENTIALS: $CORS_ALLOW_CREDENTIALS,
          CORS_ALLOW_ORIGINS: $CORS_ALLOW_ORIGINS,
          CORS_ALLOW_ORIGIN_REGEX: $CORS_ALLOW_ORIGIN_REGEX,
          FASTAPI_ALLOWED_AZP: $FASTAPI_ALLOWED_AZP,
          FASTAPI_VERIFY_AUDIENCE: $FASTAPI_VERIFY_AUDIENCE,
          KEYCLOAK_BASE_URL: $KEYCLOAK_BASE_URL,
          KEYCLOAK_REALM: $KEYCLOAK_REALM,
          KEYCLOAK_INTROSPECTION_CLIENT_ID: $KEYCLOAK_INTROSPECTION_CLIENT_ID,
          KEYCLOAK_INTROSPECTION_CLIENT_SECRET: $KEYCLOAK_INTROSPECTION_CLIENT_SECRET,
          LOG_DIR: $LOG_DIR,
          LOG_FILE: $LOG_FILE,
          LOG_LEVEL: $LOG_LEVEL,
          LOG_TO_STDOUT: $LOG_TO_STDOUT,
          TRUSTED_HOSTS: $TRUSTED_HOSTS
        }
        + (if $INCLUDE_REDIS == "1" then {
              REDIS_HOST: $REDIS_HOST,
              REDIS_PORT: $REDIS_PORT,
              REDIS_PASSWORD: $REDIS_PASSWORD
            } else {} end)
        + (if $INCLUDE_CELERY == "1" then {
              CELERY_BROKER_DB: $CELERY_BROKER_DB,
              CELERY_RESULT_DB: $CELERY_RESULT_DB,
              CELERY_BROKER_URL: $CELERY_BROKER_URL,
              CELERY_RESULT_BACKEND: $CELERY_RESULT_BACKEND
            } else {} end)
      ) } else {} end)
            + (if env.INCLUDE_KEYCLOAK == "1" then { keycloak_postgres: {
                  KC_DB: $KC_DB,
                  KC_DB_URL_HOST: $KC_DB_URL_HOST,
                  KC_DB_URL_PORT: $KC_DB_URL_PORT,
                  KC_DB_URL_DATABASE: $KC_DB_URL_DATABASE,
                  KC_DB_USERNAME: $KC_DB_USERNAME,
                  KC_DB_PASSWORD: $KC_DB_PASSWORD,
                  KC_DB_SCHEMA: $KC_DB_SCHEMA
                } } else {} end)
            + (if env.INCLUDE_KEYCLOAK_BOOTSTRAP == "1" then { keycloak_bootstrap: {
                  KC_BOOTSTRAP_ADMIN_USERNAME: $KC_BOOTSTRAP_ADMIN_USERNAME,
                  KC_BOOTSTRAP_ADMIN_PASSWORD: $KC_BOOTSTRAP_ADMIN_PASSWORD
                } } else {} end)
            + (if env.INCLUDE_KEYCLOAK_RUNTIME == "1" then { keycloak_runtime: {
                  KC_HOSTNAME: $KC_HOSTNAME,
                  KC_HOSTNAME_STRICT: $KC_HOSTNAME_STRICT,
                  KC_HTTP_ENABLED: $KC_HTTP_ENABLED,
                  KC_HTTPS_PORT: $KC_HTTPS_PORT,
                  KC_HEALTH_ENABLED: $KC_HEALTH_ENABLED,
                  KC_METRICS_ENABLED: $KC_METRICS_ENABLED,
                  KC_HTTP_MANAGEMENT_PORT: $KC_HTTP_MANAGEMENT_PORT,
                  KC_HTTP_MANAGEMENT_SCHEME: $KC_HTTP_MANAGEMENT_SCHEME
                } } else {} end)
            + (if env.KEYCLOAK_TLS_PRESENT == "1" then { keycloak_tls: {
                  KC_HTTPS_CERTIFICATE_PEM_B64: $KC_HTTPS_CERTIFICATE_PEM_B64,
                  KC_HTTPS_CERTIFICATE_KEY_PEM_B64: $KC_HTTPS_CERTIFICATE_KEY_PEM_B64,
                  KC_HTTPS_CA_CERT_PEM_B64: $KC_HTTPS_CA_CERT_PEM_B64
                } } else {} end)
          )
        }
      ]
    }' > "${SPEC_FILE}"
else
  jq -n \
    --arg INCLUDE_REDIS "$INCLUDE_REDIS" \
    --arg INCLUDE_CELERY "$INCLUDE_CELERY" \
    --arg mount "${VAULT_MOUNT}" \
    --arg POSTGRES_DB "${POSTGRES_DB}" \
    --arg POSTGRES_USER "${POSTGRES_USER}" \
    --arg POSTGRES_PASSWORD "${POSTGRES_PASSWORD}" \
    --arg PGADMIN_DEFAULT_EMAIL "${PGADMIN_DEFAULT_EMAIL}" \
    --arg PGADMIN_DEFAULT_PASSWORD "${PGADMIN_DEFAULT_PASSWORD}" \
    --arg FASTAPI_DB_URL_HOST "${FASTAPI_DB_URL_HOST}" \
    --arg FASTAPI_DB_URL_PORT "${FASTAPI_DB_URL_PORT}" \
    --arg FASTAPI_DB_URL_DATABASE "${FASTAPI_DB_URL_DATABASE}" \
    --arg FASTAPI_DB_USERNAME "${FASTAPI_DB_USERNAME}" \
    --arg FASTAPI_DB_PASSWORD "${FASTAPI_DB_PASSWORD}" \
    --arg FASTAPI_DB_SCHEMA "${FASTAPI_DB_SCHEMA}" \
    --arg APP_ENV "${APP_ENV:-}" \
    --arg CORS_ALLOW_CREDENTIALS "${CORS_ALLOW_CREDENTIALS:-}" \
    --arg CORS_ALLOW_ORIGINS "${CORS_ALLOW_ORIGINS:-}" \
    --arg CORS_ALLOW_ORIGIN_REGEX "${CORS_ALLOW_ORIGIN_REGEX:-}" \
    --arg FASTAPI_ALLOWED_AZP "${FASTAPI_ALLOWED_AZP:-}" \
    --arg FASTAPI_VERIFY_AUDIENCE "${FASTAPI_VERIFY_AUDIENCE:-}" \
    --arg KEYCLOAK_BASE_URL "${KEYCLOAK_BASE_URL:-}" \
    --arg KEYCLOAK_REALM "${KEYCLOAK_REALM:-}" \
    --arg KEYCLOAK_INTROSPECTION_CLIENT_ID "${KEYCLOAK_INTROSPECTION_CLIENT_ID:-}" \
    --arg KEYCLOAK_INTROSPECTION_CLIENT_SECRET "${KEYCLOAK_INTROSPECTION_CLIENT_SECRET:-}" \
    --arg LOG_DIR "${LOG_DIR:-}" \
    --arg LOG_FILE "${LOG_FILE:-}" \
    --arg LOG_LEVEL "${LOG_LEVEL:-}" \
    --arg LOG_TO_STDOUT "${LOG_TO_STDOUT:-}" \
    --arg TRUSTED_HOSTS "${TRUSTED_HOSTS:-}" \
    --arg INCLUDE_REDIS "${INCLUDE_REDIS:-1}" \
    --arg INCLUDE_CELERY "${INCLUDE_CELERY:-1}" \
    --arg REDIS_HOST "${REDIS_HOST}" \
    --arg REDIS_PORT "${REDIS_PORT}" \
    --arg REDIS_PASSWORD "${REDIS_PASSWORD}" \
    --arg CELERY_BROKER_DB "${CELERY_BROKER_DB}" \
    --arg CELERY_RESULT_DB "${CELERY_RESULT_DB}" \
    --arg CELERY_BROKER_URL "${CELERY_BROKER_URL}" \
    --arg CELERY_RESULT_BACKEND "${CELERY_RESULT_BACKEND}" \
    --arg KC_DB "postgres" \
    --arg KC_DB_URL_HOST "${KEYCLOAK_DB_URL_HOST}" \
    --arg KC_DB_URL_PORT "${KEYCLOAK_DB_URL_PORT}" \
    --arg KC_DB_URL_DATABASE "${KEYCLOAK_DB_URL_DATABASE}" \
    --arg KC_DB_USERNAME "${KEYCLOAK_DB_USERNAME}" \
    --arg KC_DB_PASSWORD "${KEYCLOAK_DB_PASSWORD}" \
    --arg KC_DB_URL_PROPERTIES "${KEYCLOAK_DB_URL_PROPERTIES}" \
    --arg KC_DB_SCHEMA "${KEYCLOAK_DB_SCHEMA}" \
    --arg KC_BOOTSTRAP_ADMIN_USERNAME "${KEYCLOAK_BOOTSTRAP_ADMIN_USERNAME}" \
    --arg KC_BOOTSTRAP_ADMIN_PASSWORD "${KEYCLOAK_BOOTSTRAP_ADMIN_PASSWORD}" \
    --arg KEYCLOAK_ADMIN "${KEYCLOAK_BOOTSTRAP_ADMIN_USERNAME}" \
    --arg KEYCLOAK_ADMIN_PASSWORD "${KEYCLOAK_BOOTSTRAP_ADMIN_PASSWORD}" \
    --arg KC_HOSTNAME "${KEYCLOAK_HOSTNAME}" \
    --arg KC_HOSTNAME_STRICT "${KEYCLOAK_HOSTNAME_STRICT}" \
    --arg KC_PROXY_HEADERS "${KEYCLOAK_PROXY_HEADERS}" \
    --arg KC_PROXY_TRUSTED_ADDRESSES "${KEYCLOAK_PROXY_TRUSTED_ADDRESSES}" \
    --arg KC_HTTP_ENABLED "${KEYCLOAK_HTTP_ENABLED}" \
    --arg KC_HTTP_PORT "${KEYCLOAK_HTTP_PORT}" \
    --arg KC_HTTPS_PORT "${KEYCLOAK_HTTPS_PORT}" \
    --arg KC_HEALTH_ENABLED "${KEYCLOAK_HEALTH_ENABLED}" \
    --arg KC_METRICS_ENABLED "${KEYCLOAK_METRICS_ENABLED}" \
    --arg KC_HTTP_MANAGEMENT_PORT "${KEYCLOAK_HTTP_MANAGEMENT_PORT}" \
    --arg KC_HTTP_MANAGEMENT_SCHEME "${KEYCLOAK_HTTP_MANAGEMENT_SCHEME}" \
    --arg KC_HTTPS_CERTIFICATE_PEM_B64 "${KEYCLOAK_TLS_CERT_PEM_B64}" \
    --arg KC_HTTPS_CERTIFICATE_KEY_PEM_B64 "${KEYCLOAK_TLS_KEY_PEM_B64}" \
    --arg KC_HTTPS_CA_CERT_PEM_B64 "${KEYCLOAK_TLS_CA_PEM_B64}" \
    '{
      mounts: [
        {
          mount: $mount,
          version: 2,
          secrets: (
            { postgres: { POSTGRES_DB: $POSTGRES_DB, POSTGRES_USER: $POSTGRES_USER, POSTGRES_PASSWORD: $POSTGRES_PASSWORD },
              pgadmin: { PGADMIN_DEFAULT_EMAIL: $PGADMIN_DEFAULT_EMAIL, PGADMIN_DEFAULT_PASSWORD: $PGADMIN_DEFAULT_PASSWORD } }
            + (if env.INCLUDE_FASTAPI == "1" then { fastapi_secrets: (
        {
          FASTAPI_DB_URL_HOST: $FASTAPI_DB_URL_HOST,
          FASTAPI_DB_URL_PORT: $FASTAPI_DB_URL_PORT,
          FASTAPI_DB_URL_DATABASE: $FASTAPI_DB_URL_DATABASE,
          FASTAPI_DB_USERNAME: $FASTAPI_DB_USERNAME,
          FASTAPI_DB_PASSWORD: $FASTAPI_DB_PASSWORD,
          FASTAPI_DB_SCHEMA: $FASTAPI_DB_SCHEMA,
          APP_ENV: $APP_ENV,
          CORS_ALLOW_CREDENTIALS: $CORS_ALLOW_CREDENTIALS,
          CORS_ALLOW_ORIGINS: $CORS_ALLOW_ORIGINS,
          CORS_ALLOW_ORIGIN_REGEX: $CORS_ALLOW_ORIGIN_REGEX,
          FASTAPI_ALLOWED_AZP: $FASTAPI_ALLOWED_AZP,
          FASTAPI_VERIFY_AUDIENCE: $FASTAPI_VERIFY_AUDIENCE,
          KEYCLOAK_BASE_URL: $KEYCLOAK_BASE_URL,
          KEYCLOAK_REALM: $KEYCLOAK_REALM,
          KEYCLOAK_INTROSPECTION_CLIENT_ID: $KEYCLOAK_INTROSPECTION_CLIENT_ID,
          KEYCLOAK_INTROSPECTION_CLIENT_SECRET: $KEYCLOAK_INTROSPECTION_CLIENT_SECRET,
          LOG_DIR: $LOG_DIR,
          LOG_FILE: $LOG_FILE,
          LOG_LEVEL: $LOG_LEVEL,
          LOG_TO_STDOUT: $LOG_TO_STDOUT,
          TRUSTED_HOSTS: $TRUSTED_HOSTS
        }
        + (if $INCLUDE_REDIS == "1" then {
              REDIS_HOST: $REDIS_HOST,
              REDIS_PORT: $REDIS_PORT,
              REDIS_PASSWORD: $REDIS_PASSWORD
            } else {} end)
        + (if $INCLUDE_CELERY == "1" then {
              CELERY_BROKER_DB: $CELERY_BROKER_DB,
              CELERY_RESULT_DB: $CELERY_RESULT_DB,
              CELERY_BROKER_URL: $CELERY_BROKER_URL,
              CELERY_RESULT_BACKEND: $CELERY_RESULT_BACKEND
            } else {} end)
      ) } else {} end)
            + (if env.INCLUDE_KEYCLOAK == "1" then { keycloak_postgres: {
                  KC_DB: $KC_DB,
                  KC_DB_URL_HOST: $KC_DB_URL_HOST,
                  KC_DB_URL_PORT: $KC_DB_URL_PORT,
                  KC_DB_URL_DATABASE: $KC_DB_URL_DATABASE,
                  KC_DB_USERNAME: $KC_DB_USERNAME,
                  KC_DB_PASSWORD: $KC_DB_PASSWORD,
                  KC_DB_SCHEMA: $KC_DB_SCHEMA
                } } else {} end)
            + (if env.INCLUDE_KEYCLOAK_BOOTSTRAP == "1" then { keycloak_bootstrap: {
                  KC_BOOTSTRAP_ADMIN_USERNAME: $KC_BOOTSTRAP_ADMIN_USERNAME,
                  KC_BOOTSTRAP_ADMIN_PASSWORD: $KC_BOOTSTRAP_ADMIN_PASSWORD
                } } else {} end)
            + (if env.INCLUDE_KEYCLOAK_RUNTIME == "1" then { keycloak_runtime: {
                  KC_HOSTNAME: $KC_HOSTNAME,
                  KC_HOSTNAME_STRICT: $KC_HOSTNAME_STRICT,
                  KC_HTTP_ENABLED: $KC_HTTP_ENABLED,
                  KC_HTTPS_PORT: $KC_HTTPS_PORT,
                  KC_HEALTH_ENABLED: $KC_HEALTH_ENABLED,
                  KC_METRICS_ENABLED: $KC_METRICS_ENABLED,
                  KC_HTTP_MANAGEMENT_PORT: $KC_HTTP_MANAGEMENT_PORT,
                  KC_HTTP_MANAGEMENT_SCHEME: $KC_HTTP_MANAGEMENT_SCHEME
                } } else {} end)
            + (if env.KEYCLOAK_TLS_PRESENT == "1" then { keycloak_tls: {
                  KC_HTTPS_CERTIFICATE_PEM_B64: $KC_HTTPS_CERTIFICATE_PEM_B64,
                  KC_HTTPS_CERTIFICATE_KEY_PEM_B64: $KC_HTTPS_CERTIFICATE_KEY_PEM_B64,
                  KC_HTTPS_CA_CERT_PEM_B64: $KC_HTTPS_CA_CERT_PEM_B64
                } } else {} end)
          )
        }
      ]
    }' > "${SPEC_FILE}"
fi

# Backward-compatible copies (legacy filenames)
# - The script was renamed/broadened, but older docs/automation may still expect the legacy artifact names.
# - Keep these in sync so either set can be used.
if [[ "${ENV_FILE}" != "${LEGACY_ENV_FILE}" ]]; then
  cp -f "${ENV_FILE}" "${LEGACY_ENV_FILE}" 2>/dev/null || true
fi
if [[ "${JSON_FILE}" != "${LEGACY_JSON_FILE}" ]]; then
  cp -f "${JSON_FILE}" "${LEGACY_JSON_FILE}" 2>/dev/null || true
fi
if [[ "${SPEC_FILE}" != "${LEGACY_SPEC_FILE}" ]]; then
  cp -f "${SPEC_FILE}" "${LEGACY_SPEC_FILE}" 2>/dev/null || true
fi

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

  # Ensure fastapi_secrets contains a complete key set (non-destructive fill).
  ensure_fastapi_secrets_complete_in_vault || err "Failed to converge fastapi_secrets in Vault"

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

read_container_file_trimmed() {
  # Usage: read_container_file_trimmed <container> <path>
  # Tries as 'postgres' first, then as 'root' (in case /run/vault is root-owned).
  local c="$1"
  local p="$2"
  local v=""

  v="$(docker exec -u postgres "${c}" sh -lc "cat '${p}' 2>/dev/null" | tr -d '\r' | head -n 1 || true)"
  if [[ -z "${v}" ]]; then
    v="$(docker exec -u root "${c}" sh -lc "cat '${p}' 2>/dev/null" | tr -d '\r' | head -n 1 || true)"
  fi
  printf '%s' "${v}"
}

wait_for_container_vault_creds() {
  # Usage: wait_for_container_vault_creds <container> <seconds>
  local c="$1"
  local seconds="$2"
  local start now
  start="$(date +%s)"
  while true; do
    if docker exec -u root "${c}" sh -lc 'test -s /run/vault/postgres_user -a -s /run/vault/postgres_password' >/dev/null 2>&1; then
      return 0
    fi
    now="$(date +%s)"
    if (( now - start >= seconds )); then
      return 1
    fi
    sleep 1
  done
}

resolve_postgres_admin_creds() {
  # Resolves POSTGRES_ADMIN_USER / POSTGRES_ADMIN_PASSWORD.
  # Priority:
  #   1) Explicit overrides (CLI/env): POSTGRES_ADMIN_USER + POSTGRES_ADMIN_PASSWORD
  #   2) /run/vault/postgres_user + /run/vault/postgres_password inside the container (if present)
  #   3) Resolved POSTGRES_USER + POSTGRES_PASSWORD in this script
  local wait_seconds="${1:-${WAIT_VAULT_CREDS_SECONDS}}"

  if [[ -n "${POSTGRES_ADMIN_USER}" && -n "${POSTGRES_ADMIN_PASSWORD}" ]]; then
    POSTGRES_ADMIN_CREDS_SOURCE="override"
    return 0
  fi

  # Attempt container /run/vault creds if the container exists
  if docker inspect "${POSTGRES_CONTAINER}" >/dev/null 2>&1; then
    # If a Vault agent is expected, wait briefly for rendered files to appear.
    wait_for_container_vault_creds "${POSTGRES_CONTAINER}" "${wait_seconds}" >/dev/null 2>&1 || true

    local c_user c_pass
    c_user="$(read_container_file_trimmed "${POSTGRES_CONTAINER}" "/run/vault/postgres_user")"
    c_pass="$(read_container_file_trimmed "${POSTGRES_CONTAINER}" "/run/vault/postgres_password")"

    if [[ -n "${c_user}" && -n "${c_pass}" ]]; then
      POSTGRES_ADMIN_USER="${c_user}"
      POSTGRES_ADMIN_PASSWORD="${c_pass}"
      POSTGRES_ADMIN_CREDS_SOURCE="/run/vault"
      return 0
    fi
  fi

  # Fallback to locally-resolved values (from local env artifacts, Vault load, or generated values)
  if [[ -n "${POSTGRES_USER}" && -n "${POSTGRES_PASSWORD}" ]]; then
    POSTGRES_ADMIN_USER="${POSTGRES_USER}"
    POSTGRES_ADMIN_PASSWORD="${POSTGRES_PASSWORD}"
    POSTGRES_ADMIN_CREDS_SOURCE="resolved-vars"
    return 0
  fi

  err "Unable to resolve Postgres admin credentials. Ensure bootstrap artifacts exist (${ENV_FILE}) or that /run/vault/postgres_user and /run/vault/postgres_password are present in ${POSTGRES_CONTAINER}."
}

if [[ "${APPLY_TO_POSTGRES}" -eq 1 ]]; then
  need_cmd docker
  need_cmd jq

  # ---------------------------------------------------------------------------
  # APPLY-TO-POSTGRES IS VAULT-AUTHORITATIVE
  #
  # Contract:
  #   - Vault is the source of truth.
  #   - We read credentials from Vault, then validate they work against Postgres.
  #   - If the "master/admin" credentials from Vault cannot authenticate, FAIL.
  #   - If master works, converge required DB objects (create if missing, update
  #     role passwords to match Vault values).
  # ---------------------------------------------------------------------------

  vault_token_acquire_if_needed || err "Vault token is required for --apply-to-postgres (Vault is source-of-truth). Provide ${TOKEN_FILE} or use --prompt-token."

  # Load the current values from Vault (do not rely on /run/vault or local files for apply)
  vault_try_load_from_vault || true

  local postgres_path keycloak_path fastapi_path
  postgres_path="$(prefixed_path "postgres")"
  keycloak_path="$(prefixed_path "keycloak_postgres")"
  fastapi_path="$(prefixed_path "fastapi_secrets")"

  [[ -n "${POSTGRES_DB}" && -n "${POSTGRES_USER}" && -n "${POSTGRES_PASSWORD}" ]] || err "Missing required Postgres admin values from Vault. Expected keys POSTGRES_DB/POSTGRES_USER/POSTGRES_PASSWORD at: ${VAULT_ADDR%/}/v1/${VAULT_MOUNT}/data/${postgres_path}"

  if [[ "${INCLUDE_KEYCLOAK}" -eq 1 ]]; then
    [[ -n "${KEYCLOAK_DB_URL_DATABASE}" && -n "${KEYCLOAK_DB_USERNAME}" && -n "${KEYCLOAK_DB_PASSWORD}" ]] || err "Missing required Keycloak Postgres values from Vault. Expected keys KC_DB_URL_DATABASE/KC_DB_USERNAME/KC_DB_PASSWORD at: ${VAULT_ADDR%/}/v1/${VAULT_MOUNT}/data/${keycloak_path}"
  fi

  if [[ "${INCLUDE_FASTAPI}" -eq 1 ]]; then
    # FastAPI is optional, but if enabled we require the minimum fields.
    [[ -n "${FASTAPI_DB_URL_DATABASE}" && -n "${FASTAPI_DB_USERNAME}" && -n "${FASTAPI_DB_PASSWORD}" ]] || err "Missing required FastAPI DB values from Vault. Expected keys FASTAPI_DB_URL_DATABASE/FASTAPI_DB_USERNAME/FASTAPI_DB_PASSWORD at: ${VAULT_ADDR%/}/v1/${VAULT_MOUNT}/data/${fastapi_path}"
  fi

  # Master/admin creds are whatever Vault says they are.
  POSTGRES_ADMIN_USER="${POSTGRES_USER}"
  POSTGRES_ADMIN_PASSWORD="${POSTGRES_PASSWORD}"
  POSTGRES_ADMIN_CREDS_SOURCE="vault:${VAULT_MOUNT}/${postgres_path}"

  log "Applying Postgres objects in container: ${POSTGRES_CONTAINER}"
  log "  master/admin:   user=${POSTGRES_ADMIN_USER} db=${POSTGRES_ADMIN_DB} (source=${POSTGRES_ADMIN_CREDS_SOURCE})"
  log "  network_tools:  role=${POSTGRES_USER} db=${POSTGRES_DB}"
  if [[ "${INCLUDE_KEYCLOAK}" -eq 1 ]]; then
    log "  keycloak:       role=${KEYCLOAK_DB_USERNAME} db=${KEYCLOAK_DB_URL_DATABASE} schema=${KEYCLOAK_DB_SCHEMA}"
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

    wait_for_postgres || err "Postgres did not become ready inside ${POSTGRES_CONTAINER}"
  fi

  # NOTE: We intentionally do NOT fall back to peer/trust auth here.
  # If Vault admin creds do not authenticate, we fail out as requested.
  docker exec     -e ADMIN_USER="${POSTGRES_ADMIN_USER}"     -e ADMIN_PASS="${POSTGRES_ADMIN_PASSWORD}"     -e POSTGRES_ADMIN_DB="${POSTGRES_ADMIN_DB}"     -e NT_DB="${POSTGRES_DB}"     -e NT_USER="${POSTGRES_USER}"     -e NT_PASS="${POSTGRES_PASSWORD}"     -e INCLUDE_FASTAPI="${INCLUDE_FASTAPI}"     -e FASTAPI_DB="${FASTAPI_DB_URL_DATABASE}"     -e FASTAPI_USER="${FASTAPI_DB_USERNAME}"     -e FASTAPI_PASS="${FASTAPI_DB_PASSWORD}"     -e FASTAPI_SCHEMA="${FASTAPI_DB_SCHEMA}"     -e INCLUDE_KEYCLOAK="${INCLUDE_KEYCLOAK}"     -e KC_DB="${KEYCLOAK_DB_URL_DATABASE}"     -e KC_USER="${KEYCLOAK_DB_USERNAME}"     -e KC_PASS="${KEYCLOAK_DB_PASSWORD}"     -e KC_SCHEMA="${KEYCLOAK_DB_SCHEMA}"     "${POSTGRES_CONTAINER}" bash -s -- <<'EOS'
set -euo pipefail

# DB authentication (non-interactive)
POSTGRES_ADMIN_DB="${POSTGRES_ADMIN_DB:-postgres}"

ADMIN_USER="${ADMIN_USER:?missing ADMIN_USER}"
ADMIN_PASS="${ADMIN_PASS:-}"

# Prefer TCP to localhost so we hit host/hostssl rules (not "local" peer),
# which avoids peer-auth failures when local connections are configured as peer.
PSQL_HOST="${PSQL_HOST:-127.0.0.1}"
PSQL_PORT="${PSQL_PORT:-5432}"
export PGSSLMODE="${PGSSLMODE:-disable}"

psql_conn_flags_tcp=(--host="${PSQL_HOST}" --port="${PSQL_PORT}")

psql_try_tcp() {
  local user="$1"
  local pass="$2"
  if [[ -n "${pass}" ]]; then
    PGPASSWORD="${pass}" psql -v ON_ERROR_STOP=1 --no-password "${psql_conn_flags_tcp[@]}" --username="${user}" --dbname="${POSTGRES_ADMIN_DB}" -c "SELECT 1" >/dev/null 2>&1
  else
    psql -v ON_ERROR_STOP=1 --no-password "${psql_conn_flags_tcp[@]}" --username="${user}" --dbname="${POSTGRES_ADMIN_DB}" -c "SELECT 1" >/dev/null 2>&1
  fi
}

if ! psql_try_tcp "${ADMIN_USER}" "${ADMIN_PASS}"; then
  echo "ERROR: Vault master/admin credentials failed to authenticate to Postgres."
  echo "  user=${ADMIN_USER} db=${POSTGRES_ADMIN_DB} host=${PSQL_HOST} port=${PSQL_PORT} sslmode=${PGSSLMODE}"
  echo "  This is an intentional hard-fail. Fix the mismatch (Vault vs Postgres) or pg_hba.conf, then re-run."
  exit 2
fi

export PGPASSWORD="${ADMIN_PASS}"
echo "INFO: Postgres apply auth verified: ${ADMIN_USER} via TCP (${PSQL_HOST}:${PSQL_PORT}, sslmode=${PGSSLMODE})"

psql_admin() {
  psql -v ON_ERROR_STOP=1 --no-password "${psql_conn_flags_tcp[@]}" --username="${ADMIN_USER}" "$@"
}

apply_role_and_db() {
  local dbname="$1"
  local username="$2"
  local password="$3"
  local admin_db="${POSTGRES_ADMIN_DB}"

  # NOTE:
  #   psql variable substitution does not occur inside dollar-quoted strings (e.g., DO $$ ... $$).
  #   Use plain SQL + \gexec for idempotent creation with proper quoting via format(%I/%L).
  psql_admin --dbname="${admin_db}"     --set=db_name="${dbname}" --set=role_name="${username}" --set=role_pass="${password}" <<'SQL'
-- Create role if missing
SELECT format('CREATE ROLE %I LOGIN PASSWORD %L;', :'role_name', :'role_pass')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'role_name')
\gexec

-- Ensure password is set/updated (idempotent)
SELECT format('ALTER ROLE %I WITH LOGIN PASSWORD %L;', :'role_name', :'role_pass')
\gexec

-- Create database if missing
SELECT format('CREATE DATABASE %I OWNER %I ENCODING ''UTF8'';', :'db_name', :'role_name')
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = :'db_name')
\gexec

-- Ensure ownership and privileges
SELECT format('ALTER DATABASE %I OWNER TO %I;', :'db_name', :'role_name')
\gexec

SELECT format('GRANT CONNECT, TEMPORARY ON DATABASE %I TO %I;', :'db_name', :'role_name')
\gexec
SQL
}

apply_schema() {
  local dbname="$1"
  local schema="$2"
  local owner_role="$3"

  psql_admin --dbname="${dbname}"     --set=schema_name="${schema}" --set=owner_role="${owner_role}" <<'SQL'
-- Create schema if missing and ensure ownership
SELECT format('CREATE SCHEMA %I AUTHORIZATION %I;', :'schema_name', :'owner_role')
WHERE NOT EXISTS (
  SELECT 1
  FROM information_schema.schemata
  WHERE schema_name = :'schema_name'
)
\gexec

SELECT format('ALTER SCHEMA %I OWNER TO %I;', :'schema_name', :'owner_role')
\gexec

-- Allow owner_role to use/create in the schema (belt-and-suspenders)
SELECT format('GRANT USAGE, CREATE ON SCHEMA %I TO %I;', :'schema_name', :'owner_role')
\gexec
SQL
}

apply_app_dml_user() {
  # Creates a DML-only user for an application schema (tables/sequences) in an existing DB.
  # Args:
  #   1) dbname
  #   2) schema_name
  #   3) role_name
  #   4) role_pass
  #   5) owner_role (role that owns the schema objects; we set default privileges for future objects)
  local dbname="$1"
  local schema="$2"
  local username="$3"
  local password="$4"
  local owner_role="$5"
  local admin_db="${POSTGRES_ADMIN_DB}"

  # Create role if missing + set password at admin DB scope
  psql_admin --dbname="${admin_db}"     --set=role_name="${username}" --set=role_pass="${password}" <<'SQL'
SELECT format('CREATE ROLE %I LOGIN PASSWORD %L;', :'role_name', :'role_pass')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'role_name')
\gexec

SELECT format('ALTER ROLE %I WITH LOGIN PASSWORD %L;', :'role_name', :'role_pass')
\gexec
SQL

  # Schema grants within target DB
  psql_admin --dbname="${dbname}"     --set=schema_name="${schema}" --set=role_name="${username}" --set=owner_role="${owner_role}" <<'SQL'
-- Ensure schema exists (do not change owner here)
SELECT format('CREATE SCHEMA %I;', :'schema_name')
WHERE NOT EXISTS (
  SELECT 1
  FROM information_schema.schemata
  WHERE schema_name = :'schema_name'
)
\gexec

-- Current objects
SELECT format('GRANT USAGE ON SCHEMA %I TO %I;', :'schema_name', :'role_name')
\gexec
SELECT format('GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA %I TO %I;', :'schema_name', :'role_name')
\gexec
SELECT format('GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA %I TO %I;', :'schema_name', :'role_name')
\gexec

-- Future objects created by the owner role
SELECT format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA %I GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO %I;', :'owner_role', :'schema_name', :'role_name')
\gexec
SELECT format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA %I GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO %I;', :'owner_role', :'schema_name', :'role_name')
\gexec
SQL
}

NT_DB="${NT_DB:?missing NT_DB}"
NT_USER="${NT_USER:?missing NT_USER}"
NT_PASS="${NT_PASS:?missing NT_PASS}"

apply_role_and_db "${NT_DB}" "${NT_USER}" "${NT_PASS}"
echo "INFO: Ensured network_tools role/db exist: user=${NT_USER} db=${NT_DB}"

if [[ "${INCLUDE_FASTAPI}" == "1" ]]; then
  FASTAPI_DB="${FASTAPI_DB:?missing FASTAPI_DB}"
  FASTAPI_SCHEMA="${FASTAPI_SCHEMA:-public}"
  FASTAPI_USER="${FASTAPI_USER:?missing FASTAPI_USER}"
  FASTAPI_PASS="${FASTAPI_PASS:?missing FASTAPI_PASS}"
  apply_app_dml_user "${FASTAPI_DB}" "${FASTAPI_SCHEMA}" "${FASTAPI_USER}" "${FASTAPI_PASS}" "${NT_USER}"
  echo "INFO: Ensured fastapi DML grants: user=${FASTAPI_USER} db=${FASTAPI_DB} schema=${FASTAPI_SCHEMA}"
fi

if [[ "${INCLUDE_KEYCLOAK}" == "1" ]]; then
  KC_DB="${KC_DB:?missing KC_DB}"
  KC_USER="${KC_USER:?missing KC_USER}"
  KC_PASS="${KC_PASS:?missing KC_PASS}"
  KC_SCHEMA="${KC_SCHEMA:-keycloak}"

  # Create/ensure the DB and role, then ensure the schema exists and is owned by the Keycloak role.
  apply_role_and_db "${KC_DB}" "${KC_USER}" "${KC_PASS}"
  apply_schema "${KC_DB}" "${KC_SCHEMA}" "${KC_USER}"
  echo "INFO: Ensured keycloak role/db/schema exist: user=${KC_USER} db=${KC_DB} schema=${KC_SCHEMA}"

  # Verify Keycloak credentials can authenticate (Vault authoritative).
  if ! PGPASSWORD="${KC_PASS}" psql -v ON_ERROR_STOP=1 --no-password "${psql_conn_flags_tcp[@]}" --username="${KC_USER}" --dbname="${KC_DB}" -c "SELECT 1" >/dev/null 2>&1; then
    echo "ERROR: Keycloak credentials from Vault failed to authenticate after apply."
    echo "  user=${KC_USER} db=${KC_DB} host=${PSQL_HOST} port=${PSQL_PORT} sslmode=${PGSSLMODE}"
    exit 3
  fi
  echo "INFO: Verified keycloak login works with Vault credentials."
fi
EOS

  log "Postgres apply completed."
fi

log "Done."
