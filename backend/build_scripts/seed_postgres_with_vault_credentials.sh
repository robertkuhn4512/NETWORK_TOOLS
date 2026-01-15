#!/usr/bin/env bash
set -euo pipefail

# seed_postgres_with_vault_credentials.sh
#
# Notes
# - Purpose: Make PostgreSQL match the authoritative credentials stored in Vault.
# - Vault paths are HARD-CODED (as requested), with one added for FastAPI:
#     - /v1/app_network_tools_secrets/data/postgres
#     - /v1/app_network_tools_secrets/data/keycloak_postgres
#     - /v1/app_network_tools_secrets/data/fastapi_runtime   (default; override via --fastapi-secret-path)
#
# - This script:
#     1) Reads master Postgres credentials from Vault (POSTGRES_USER/POSTGRES_PASSWORD).
#     2) Reads Keycloak DB credentials from Vault (KC_DB_URL_DATABASE/KC_DB_USERNAME/KC_DB_PASSWORD, optional KC_DB_SCHEMA).
#     3) Reads FastAPI DB credentials from Vault (FASTAPI_DB_URL_DATABASE/FASTAPI_DB_USERNAME/FASTAPI_DB_PASSWORD, optional FASTAPI_DB_SCHEMA).
#     4) Connects to the Postgres container using the master credentials (TCP 127.0.0.1, so password auth is tested).
#     5) Ensures Keycloak role/db/schema exist and are configured.
#     6) Ensures FastAPI role exists and grants least-privilege (no CREATE on schema; no ownership; no DROP-type permissions).
#     7) Verifies Keycloak role can log in.
#     8) Verifies FastAPI role can log in.
#
# How to run
#   chmod +x ./backend/build_scripts/seed_postgres_with_vault_credentials.sh
#   ./backend/build_scripts/seed_postgres_with_vault_credentials.sh \
#     --ca-cert "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt"
#
# Optional:
#   --fastapi-secret-path fastapi_runtime|fastapi_postgres|...  (default: fastapi_runtime)
#
# Exit codes
#   0  success
#   1  usage / validation failures
#   2  Vault read failures
#   3  Postgres connection / seeding failures

#######################################
# Defaults
#######################################
DEFAULT_VAULT_HOST="vault_production_node"
DEFAULT_VAULT_PORT="8200"
DEFAULT_VAULT_SCHEME="https"
DEFAULT_VAULT_MOUNT="app_network_tools_secrets"

KEYCLOAK_SECRET_PATH="keycloak_postgres"
POSTGRES_SECRET_PATH="postgres"
FASTAPI_SECRET_PATH_DEFAULT="fastapi_runtime"

DEFAULT_BOOTSTRAP_DIR="${HOME}/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap"
DEFAULT_TOKEN_FILE="${DEFAULT_BOOTSTRAP_DIR}/root_token"

DEFAULT_POSTGRES_CONTAINER="postgres_primary"
DEFAULT_PG_PORT="5432"

#######################################
# Logging / helpers
#######################################
log()  { printf 'INFO: %s\n' "$*"; }
warn() { printf 'WARN: %s\n' "$*" >&2; }
err()  { printf 'ERROR: %s\n' "$*" >&2; }

die() {
  local msg="$1"
  local code="${2:-1}"
  err "$msg"
  exit "$code"
}

usage() {
  cat <<'USAGE'
seed_postgres_with_vault_credentials.sh

Required:
  --ca-cert PATH
    Path to the Vault CA certificate used for curl TLS verification.

Optional:
  --env-file PATH              Default: auto-detect repo .env; fallback: $HOME/NETWORK_TOOLS/.env
  --vault-host HOST             Default: PRIMARY_SERVER_FQDN (if set in env file), else vault_production_node
  --vault-port PORT             Default: 8200
  --vault-scheme http|https     Default: https
  --vault-addr URL              Full URL (overrides scheme/host/port), e.g. https://vault_production_node:8200
  --vault-mount NAME            Default: app_network_tools_secrets
  --token-file PATH             Default: $HOME/NETWORK_TOOLS/.../bootstrap/root_token (prompts if missing)
  --postgres-container NAME     Default: postgres_primary
  --pg-port PORT                Default: 5432
  --fastapi-secret-path NAME    Default: fastapi_runtime
  --insecure                    Skip TLS verification for Vault curl (dev-only)
  -h, --help                    Show this help.

Example:
  ./seed_postgres_with_vault_credentials.sh \
    --ca-cert "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt" \
    --vault-host vault_production_node \
    --postgres-container postgres_primary
USAGE
}

need_bin() { command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"; }

# Safe SQL quoting helpers
sql_ident() {
  local s="$1"
  s="${s//\"/\"\"}"
  printf '"%s"' "$s"
}
sql_lit() {
  local s="$1"
  s="${s//\'/\'\'}"
  printf "'%s'" "$s"
}

validate_name_soft() {
  local v="$1"
  [[ -n "$v" ]] || return 1
  [[ "$v" != *$'\n'* ]] || return 1
  [[ "$v" != *$'\r'* ]] || return 1
  return 0
}

#######################################
# Repo/env discovery (for PRIMARY_SERVER_FQDN)
#######################################
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

derive_repo_root() {
  local d="$SCRIPT_DIR"
  while [[ "$d" != "/" && -n "$d" ]]; do
    if [[ -d "$d/backend/build_scripts" ]]; then
      echo "$d"
      return 0
    fi
    d="$(dirname "$d")"
  done
  return 1
}

REPO_ROOT="$(derive_repo_root 2>/dev/null || true)"

DEFAULT_ENV_FILE=""
if [[ -n "$REPO_ROOT" && -r "$REPO_ROOT/.env" ]]; then
  DEFAULT_ENV_FILE="$REPO_ROOT/.env"
elif [[ -r "$HOME/NETWORK_TOOLS/.env" ]]; then
  DEFAULT_ENV_FILE="$HOME/NETWORK_TOOLS/.env"
elif [[ -r "$PWD/.env" ]]; then
  DEFAULT_ENV_FILE="$PWD/.env"
fi

read_env_var_from_file() {
  local key="$1"
  local file="$2"
  [[ -r "$file" ]] || return 1

  local line
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line#"${line%%[![:space:]]*}"}"
    [[ -z "$line" ]] && continue
    [[ "$line" == \#* ]] && continue

    if [[ "$line" == export\ * ]]; then
      line="${line#export }"
      line="${line#"${line%%[![:space:]]*}"}"
    fi

    if [[ "$line" == "$key="* ]]; then
      local val="${line#*=}"
      val="${val#"${val%%[![:space:]]*}"}"
      val="${val%"${val##*[![:space:]]}"}"

      if [[ "$val" =~ ^\"(.*)\"$ ]]; then
        val="${BASH_REMATCH[1]}"
      elif [[ "$val" =~ ^\'(.*)\'$ ]]; then
        val="${BASH_REMATCH[1]}"
      fi

      printf '%s' "$val"
      return 0
    fi
  done < "$file"

  return 1
}

#######################################
# Args
#######################################
VAULT_HOST="$DEFAULT_VAULT_HOST"
VAULT_PORT="$DEFAULT_VAULT_PORT"
VAULT_SCHEME="$DEFAULT_VAULT_SCHEME"
VAULT_ADDR=""
VAULT_MOUNT="$DEFAULT_VAULT_MOUNT"
CA_CERT=""
TOKEN_FILE="$DEFAULT_TOKEN_FILE"
INSECURE="0"

POSTGRES_CONTAINER="$DEFAULT_POSTGRES_CONTAINER"
PG_PORT="$DEFAULT_PG_PORT"

FASTAPI_SECRET_PATH="$FASTAPI_SECRET_PATH_DEFAULT"

ENV_FILE="${ENV_FILE:-$DEFAULT_ENV_FILE}"
VAULT_HOST_SET_BY_CLI="0"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --env-file) ENV_FILE="$2"; shift 2;;
    --vault-host) VAULT_HOST="$2"; VAULT_HOST_SET_BY_CLI="1"; shift 2;;
    --vault-port) VAULT_PORT="$2"; shift 2;;
    --vault-scheme) VAULT_SCHEME="$2"; shift 2;;
    --vault-addr) VAULT_ADDR="$2"; VAULT_HOST_SET_BY_CLI="1"; shift 2;;
    --vault-mount) VAULT_MOUNT="$2"; shift 2;;
    --ca-cert) CA_CERT="$2"; shift 2;;
    --token-file) TOKEN_FILE="$2"; shift 2;;
    --postgres-container) POSTGRES_CONTAINER="$2"; shift 2;;
    --pg-port) PG_PORT="$2"; shift 2;;
    --fastapi-secret-path) FASTAPI_SECRET_PATH="$2"; shift 2;;
    --insecure) INSECURE="1"; shift 1;;
    -h|--help) usage; exit 0;;
    *) die "Unknown argument: $1" 1;;
  esac
done

#######################################
# Env-based Vault host defaulting (PRIMARY_SERVER_FQDN)
#######################################
PRIMARY_SERVER_FQDN_EFFECTIVE="${PRIMARY_SERVER_FQDN:-}"

if [[ -z "$PRIMARY_SERVER_FQDN_EFFECTIVE" ]]; then
  if [[ -n "$ENV_FILE" && -r "$ENV_FILE" ]]; then
    PRIMARY_SERVER_FQDN_EFFECTIVE="$(read_env_var_from_file "PRIMARY_SERVER_FQDN" "$ENV_FILE" || true)"
    if [[ -n "$PRIMARY_SERVER_FQDN_EFFECTIVE" ]]; then
      log "Loaded PRIMARY_SERVER_FQDN from env file: $ENV_FILE"
    fi
  else
    if [[ -n "$ENV_FILE" ]]; then
      warn "Env file not found/readable (skipping): $ENV_FILE"
    fi
  fi
fi

if [[ -z "$VAULT_ADDR" && "$VAULT_HOST_SET_BY_CLI" == "0" ]]; then
  if [[ -n "$PRIMARY_SERVER_FQDN_EFFECTIVE" ]]; then
    VAULT_HOST="$PRIMARY_SERVER_FQDN_EFFECTIVE"
    log "Using Vault host from PRIMARY_SERVER_FQDN: ${VAULT_HOST}"
  else
    log "PRIMARY_SERVER_FQDN not set; falling back to Vault container host: ${VAULT_HOST}"
  fi
fi

#######################################
# Validation
#######################################
need_bin curl
need_bin jq
need_bin docker

[[ -n "$CA_CERT" || "$INSECURE" == "1" ]] || die "--ca-cert is required unless --insecure is used" 1
if [[ "$INSECURE" != "1" ]]; then
  [[ -f "$CA_CERT" ]] || die "CA cert not found: $CA_CERT" 1
fi

if [[ -z "$VAULT_ADDR" ]]; then
  VAULT_ADDR="${VAULT_SCHEME}://${VAULT_HOST}:${VAULT_PORT}"
fi

docker inspect "$POSTGRES_CONTAINER" >/dev/null 2>&1 || die "Postgres container not found: ${POSTGRES_CONTAINER}" 3

#######################################
# Vault token acquisition
#######################################
VAULT_TOKEN=""
if [[ -f "$TOKEN_FILE" ]]; then
  VAULT_TOKEN="$(tr -d ' \t\r\n' < "$TOKEN_FILE")"
  if [[ -n "$VAULT_TOKEN" ]]; then
    log "Using Vault token from: $TOKEN_FILE"
  fi
fi

if [[ -z "$VAULT_TOKEN" ]]; then
  warn "Vault token file not found or empty: $TOKEN_FILE"
  read -r -s -p "Enter Vault token: " VAULT_TOKEN
  echo
  [[ -n "$VAULT_TOKEN" ]] || die "Vault token is required" 2
fi

#######################################
# Vault reads (KV v2)
#######################################
vault_curl_common=(
  -sS
  -H "accept: application/json"
  -H "X-Vault-Token: ${VAULT_TOKEN}"
)

if [[ "$INSECURE" == "1" ]]; then
  vault_tls_args=( -k )
else
  vault_tls_args=( --cacert "$CA_CERT" )
fi

vault_get_kv2() {
  local secret_path="$1"
  local url="${VAULT_ADDR}/v1/${VAULT_MOUNT}/data/${secret_path}"
  curl "${vault_tls_args[@]}" "${vault_curl_common[@]}" -X GET "$url"
}

log "Reading Keycloak Postgres secret from Vault: /v1/${VAULT_MOUNT}/data/${KEYCLOAK_SECRET_PATH}"
KC_JSON="$(vault_get_kv2 "$KEYCLOAK_SECRET_PATH")" || die "Failed to read Vault keycloak_postgres" 2

KC_DB_URL_DATABASE="$(echo "$KC_JSON" | jq -r '.data.data.KC_DB_URL_DATABASE // empty')"
KC_DB_USERNAME="$(echo "$KC_JSON" | jq -r '.data.data.KC_DB_USERNAME // empty')"
KC_DB_PASSWORD="$(echo "$KC_JSON" | jq -r '.data.data.KC_DB_PASSWORD // empty')"
KC_DB_SCHEMA="$(echo "$KC_JSON" | jq -r '.data.data.KC_DB_SCHEMA // "public"')"

validate_name_soft "$KC_DB_URL_DATABASE" || die "Invalid KC_DB_URL_DATABASE value" 2
validate_name_soft "$KC_DB_USERNAME" || die "Invalid KC_DB_USERNAME value" 2
[[ -n "$KC_DB_PASSWORD" ]] || die "Vault missing: KC_DB_PASSWORD at ${VAULT_MOUNT}/${KEYCLOAK_SECRET_PATH}" 2
validate_name_soft "$KC_DB_SCHEMA" || die "Invalid KC_DB_SCHEMA value" 2

log "Reading Postgres master secret from Vault: /v1/${VAULT_MOUNT}/data/${POSTGRES_SECRET_PATH}"
PG_JSON="$(vault_get_kv2 "$POSTGRES_SECRET_PATH")" || die "Failed to read Vault postgres" 2

POSTGRES_USER="$(echo "$PG_JSON" | jq -r '.data.data.POSTGRES_USER // empty')"
POSTGRES_PASSWORD="$(echo "$PG_JSON" | jq -r '.data.data.POSTGRES_PASSWORD // empty')"

validate_name_soft "$POSTGRES_USER" || die "Invalid POSTGRES_USER value" 2
[[ -n "$POSTGRES_PASSWORD" ]] || die "Vault missing: POSTGRES_PASSWORD at ${VAULT_MOUNT}/${POSTGRES_SECRET_PATH}" 2

log "Reading FastAPI Postgres secret from Vault: /v1/${VAULT_MOUNT}/data/${FASTAPI_SECRET_PATH}"
FAPI_JSON="$(vault_get_kv2 "$FASTAPI_SECRET_PATH")" || die "Failed to read Vault fastapi secret path: ${FASTAPI_SECRET_PATH}" 2

# Support the keys you showed in /run/vault/fastapi_secrets.json
FASTAPI_DB_URL_DATABASE="$(echo "$FAPI_JSON" | jq -r '.data.data.FASTAPI_DB_URL_DATABASE // empty')"
FASTAPI_DB_USERNAME="$(echo "$FAPI_JSON" | jq -r '.data.data.FASTAPI_DB_USERNAME // empty')"
FASTAPI_DB_PASSWORD="$(echo "$FAPI_JSON" | jq -r '.data.data.FASTAPI_DB_PASSWORD // empty')"
FASTAPI_DB_SCHEMA="$(echo "$FAPI_JSON" | jq -r '.data.data.FASTAPI_DB_SCHEMA // "public"')"

validate_name_soft "$FASTAPI_DB_URL_DATABASE" || die "Invalid FASTAPI_DB_URL_DATABASE value" 2
validate_name_soft "$FASTAPI_DB_USERNAME" || die "Invalid FASTAPI_DB_USERNAME value" 2
[[ -n "$FASTAPI_DB_PASSWORD" ]] || die "Vault missing: FASTAPI_DB_PASSWORD at ${VAULT_MOUNT}/${FASTAPI_SECRET_PATH}" 2
validate_name_soft "$FASTAPI_DB_SCHEMA" || die "Invalid FASTAPI_DB_SCHEMA value" 2

log "Vault values loaded:"
log "  Keycloak DB:     ${KC_DB_URL_DATABASE}"
log "  Keycloak Role:   ${KC_DB_USERNAME}"
log "  Keycloak Schema: ${KC_DB_SCHEMA}"
log "  FastAPI DB:      ${FASTAPI_DB_URL_DATABASE}"
log "  FastAPI Role:    ${FASTAPI_DB_USERNAME}"
log "  FastAPI Schema:  ${FASTAPI_DB_SCHEMA}"
log "  Postgres Master: ${POSTGRES_USER}"
log "  Vault addr:      ${VAULT_ADDR}"
log "  Vault mount:     ${VAULT_MOUNT}"
log "  PG container:    ${POSTGRES_CONTAINER}"
log "  PG port:         ${PG_PORT}"

#######################################
# Postgres readiness + master login validation
#######################################
log "Waiting for Postgres readiness (up to 180s)..."
READY="0"
for _ in $(seq 1 180); do
  if docker exec "$POSTGRES_CONTAINER" pg_isready -h 127.0.0.1 -p "$PG_PORT" >/dev/null 2>&1; then
    READY="1"
    break
  fi
  sleep 1
done
[[ "$READY" == "1" ]] || die "Postgres did not become ready in ${POSTGRES_CONTAINER}" 3

docker exec "$POSTGRES_CONTAINER" sh -lc 'command -v psql >/dev/null 2>&1' || die "psql not found in ${POSTGRES_CONTAINER}" 3

psql_master() {
  local db="$1"
  local sql="$2"
  docker exec -i \
    -e PGPASSWORD="$POSTGRES_PASSWORD" \
    "$POSTGRES_CONTAINER" \
    psql --no-password -v ON_ERROR_STOP=1 \
      -h 127.0.0.1 -p "$PG_PORT" -U "$POSTGRES_USER" -d "$db" \
      -c "$sql"
}
psql_master_ta() {
  local db="$1"
  local sql="$2"
  docker exec -i \
    -e PGPASSWORD="$POSTGRES_PASSWORD" \
    "$POSTGRES_CONTAINER" \
    psql --no-password -v ON_ERROR_STOP=1 -tA \
      -h 127.0.0.1 -p "$PG_PORT" -U "$POSTGRES_USER" -d "$db" \
      -c "$sql"
}

log "Testing master login against catalog DB 'postgres'..."
psql_master "postgres" "SELECT 1;" >/dev/null
log "Master login OK."

log "Sanity check: wrong-password login must fail (proves password auth is enforced)..."
if docker exec -i -e PGPASSWORD="${POSTGRES_PASSWORD}__WRONG__" "$POSTGRES_CONTAINER" \
     psql --no-password -h 127.0.0.1 -p "$PG_PORT" -U "$POSTGRES_USER" -d postgres -c "SELECT 1;" >/dev/null 2>&1; then
  die "Wrong-password login succeeded. Password auth may not be enforced for this path; refusing to proceed." 3
fi
log "Wrong-password login failed as expected."

#######################################
# Seed Keycloak role + DB
#######################################
KC_DB_SQL_IDENT="$(sql_ident "$KC_DB_URL_DATABASE")"
KC_ROLE_SQL_IDENT="$(sql_ident "$KC_DB_USERNAME")"
KC_PASS_SQL_LIT="$(sql_lit "$KC_DB_PASSWORD")"
KC_SCHEMA_SQL_IDENT="$(sql_ident "$KC_DB_SCHEMA")"

log "Ensuring Keycloak role exists..."
ROLE_EXISTS="$(psql_master_ta "postgres" "SELECT 1 FROM pg_roles WHERE rolname = $(sql_lit "$KC_DB_USERNAME") LIMIT 1;" || true)"
if [[ "$ROLE_EXISTS" != "1" ]]; then
  log "Creating role '${KC_DB_USERNAME}'..."
  psql_master "postgres" "CREATE ROLE ${KC_ROLE_SQL_IDENT} LOGIN;"
else
  log "Role '${KC_DB_USERNAME}' already exists."
fi

log "Setting Keycloak role password to match Vault..."
psql_master "postgres" "ALTER ROLE ${KC_ROLE_SQL_IDENT} WITH LOGIN PASSWORD ${KC_PASS_SQL_LIT};"

log "Checking whether Keycloak database exists..."
DB_EXISTS="$(psql_master_ta "postgres" "SELECT 1 FROM pg_database WHERE datname = $(sql_lit "$KC_DB_URL_DATABASE") LIMIT 1;" || true)"
if [[ "$DB_EXISTS" != "1" ]]; then
  log "Creating database '${KC_DB_URL_DATABASE}' owned by '${KC_DB_USERNAME}'..."
  psql_master "postgres" "CREATE DATABASE ${KC_DB_SQL_IDENT} OWNER ${KC_ROLE_SQL_IDENT};"
else
  log "Database '${KC_DB_URL_DATABASE}' already exists."
fi

log "Ensuring database owner is '${KC_DB_USERNAME}'..."
psql_master "postgres" "ALTER DATABASE ${KC_DB_SQL_IDENT} OWNER TO ${KC_ROLE_SQL_IDENT};" >/dev/null

log "Granting CONNECT and TEMPORARY on Keycloak DB..."
psql_master "postgres" "GRANT CONNECT, TEMPORARY ON DATABASE ${KC_DB_SQL_IDENT} TO ${KC_ROLE_SQL_IDENT};" >/dev/null

log "Ensuring schema '${KC_DB_SCHEMA}' exists and privileges are set..."
if [[ "$KC_DB_SCHEMA" != "public" ]]; then
  psql_master "$KC_DB_URL_DATABASE" "CREATE SCHEMA IF NOT EXISTS ${KC_SCHEMA_SQL_IDENT} AUTHORIZATION ${KC_ROLE_SQL_IDENT};"
  psql_master "$KC_DB_URL_DATABASE" "GRANT USAGE, CREATE ON SCHEMA ${KC_SCHEMA_SQL_IDENT} TO ${KC_ROLE_SQL_IDENT};"
  psql_master "$KC_DB_URL_DATABASE" "ALTER ROLE ${KC_ROLE_SQL_IDENT} IN DATABASE ${KC_DB_SQL_IDENT} SET search_path TO ${KC_SCHEMA_SQL_IDENT}, public;" >/dev/null
else
  psql_master "$KC_DB_URL_DATABASE" "GRANT USAGE, CREATE ON SCHEMA public TO ${KC_ROLE_SQL_IDENT};"
fi

#######################################
# Seed FastAPI least-privilege role
#######################################
FAPI_DB_SQL_IDENT="$(sql_ident "$FASTAPI_DB_URL_DATABASE")"
FAPI_ROLE_SQL_IDENT="$(sql_ident "$FASTAPI_DB_USERNAME")"
FAPI_PASS_SQL_LIT="$(sql_lit "$FASTAPI_DB_PASSWORD")"
FAPI_SCHEMA_SQL_IDENT="$(sql_ident "$FASTAPI_DB_SCHEMA")"

log "Ensuring FastAPI role exists..."
FAPI_ROLE_EXISTS="$(psql_master_ta "postgres" "SELECT 1 FROM pg_roles WHERE rolname = $(sql_lit "$FASTAPI_DB_USERNAME") LIMIT 1;" || true)"
if [[ "$FAPI_ROLE_EXISTS" != "1" ]]; then
  log "Creating role '${FASTAPI_DB_USERNAME}'..."
  psql_master "postgres" "CREATE ROLE ${FAPI_ROLE_SQL_IDENT} LOGIN;"
else
  log "Role '${FASTAPI_DB_USERNAME}' already exists."
fi

log "Setting FastAPI role password to match Vault..."
psql_master "postgres" "ALTER ROLE ${FAPI_ROLE_SQL_IDENT} WITH LOGIN PASSWORD ${FAPI_PASS_SQL_LIT};"

log "Checking whether FastAPI database exists..."
FAPI_DB_EXISTS="$(psql_master_ta "postgres" "SELECT 1 FROM pg_database WHERE datname = $(sql_lit "$FASTAPI_DB_URL_DATABASE") LIMIT 1;" || true)"
if [[ "$FAPI_DB_EXISTS" != "1" ]]; then
  log "Creating database '${FASTAPI_DB_URL_DATABASE}' owned by '${POSTGRES_USER}' (NOT FastAPI role)..."
  psql_master "postgres" "CREATE DATABASE ${FAPI_DB_SQL_IDENT} OWNER $(sql_ident "$POSTGRES_USER");"
else
  log "Database '${FASTAPI_DB_URL_DATABASE}' already exists."
fi

log "Granting CONNECT on FastAPI DB (no TEMP granted)..."
psql_master "postgres" "GRANT CONNECT ON DATABASE ${FAPI_DB_SQL_IDENT} TO ${FAPI_ROLE_SQL_IDENT};" >/dev/null

log "Ensuring schema '${FASTAPI_DB_SCHEMA}' exists and granting least-privilege..."
if [[ "$FASTAPI_DB_SCHEMA" != "public" ]]; then
  # Create schema owned by master role, not the FastAPI role.
  psql_master "$FASTAPI_DB_URL_DATABASE" "CREATE SCHEMA IF NOT EXISTS ${FAPI_SCHEMA_SQL_IDENT} AUTHORIZATION $(sql_ident "$POSTGRES_USER");"
fi

# Ensure FastAPI can use schema but cannot create objects there.
psql_master "$FASTAPI_DB_URL_DATABASE" "GRANT USAGE ON SCHEMA ${FAPI_SCHEMA_SQL_IDENT} TO ${FAPI_ROLE_SQL_IDENT};" >/dev/null
psql_master "$FASTAPI_DB_URL_DATABASE" "REVOKE CREATE ON SCHEMA ${FAPI_SCHEMA_SQL_IDENT} FROM ${FAPI_ROLE_SQL_IDENT};" >/dev/null

log "Granting non-destructive DML privileges to FastAPI role (existing objects)..."
psql_master "$FASTAPI_DB_URL_DATABASE" "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ${FAPI_SCHEMA_SQL_IDENT} TO ${FAPI_ROLE_SQL_IDENT};" >/dev/null
psql_master "$FASTAPI_DB_URL_DATABASE" "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ${FAPI_SCHEMA_SQL_IDENT} TO ${FAPI_ROLE_SQL_IDENT};" >/dev/null

log "Setting default privileges for future tables/sequences created by '${POSTGRES_USER}' in schema '${FASTAPI_DB_SCHEMA}'..."
# Default privileges apply to objects created by the role that runs this statement (here: POSTGRES_USER).
psql_master "$FASTAPI_DB_URL_DATABASE" "ALTER DEFAULT PRIVILEGES IN SCHEMA ${FAPI_SCHEMA_SQL_IDENT} GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO ${FAPI_ROLE_SQL_IDENT};" >/dev/null
psql_master "$FASTAPI_DB_URL_DATABASE" "ALTER DEFAULT PRIVILEGES IN SCHEMA ${FAPI_SCHEMA_SQL_IDENT} GRANT USAGE, SELECT ON SEQUENCES TO ${FAPI_ROLE_SQL_IDENT};" >/dev/null

#######################################
# Verify Keycloak login
#######################################
log "Verifying Keycloak role can log in to '${KC_DB_URL_DATABASE}'..."
docker exec -i \
  -e PGPASSWORD="$KC_DB_PASSWORD" \
  "$POSTGRES_CONTAINER" \
  psql --no-password -v ON_ERROR_STOP=1 \
    -h 127.0.0.1 -p "$PG_PORT" -U "$KC_DB_USERNAME" -d "$KC_DB_URL_DATABASE" \
    -c "SELECT current_user, current_database();" >/dev/null

log "SUCCESS: Keycloak verified login."

#######################################
# Verify FastAPI login
#######################################
log "Verifying FastAPI role can log in to '${FASTAPI_DB_URL_DATABASE}'..."
docker exec -i \
  -e PGPASSWORD="$FASTAPI_DB_PASSWORD" \
  "$POSTGRES_CONTAINER" \
  psql --no-password -v ON_ERROR_STOP=1 \
    -h 127.0.0.1 -p "$PG_PORT" -U "$FASTAPI_DB_USERNAME" -d "$FASTAPI_DB_URL_DATABASE" \
    -c "SELECT current_user, current_database(); SHOW search_path;" >/dev/null

log "SUCCESS: FastAPI verified login and least-privilege grants applied."
log "DONE: Postgres seeded to match Vault for Keycloak + FastAPI."
