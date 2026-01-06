#!/usr/bin/env bash
set -euo pipefail

# seed_postgres_with_vault_credentials.sh
#
# Notes
# - Purpose: Make PostgreSQL match the authoritative credentials stored in Vault.
# - Vault paths are HARD-CODED (as requested):
#     - /v1/app_network_tools_secrets/data/postgres
#     - /v1/app_network_tools_secrets/data/keycloak_postgres
# - This script:
#     1) Reads master Postgres credentials from Vault (POSTGRES_USER/POSTGRES_PASSWORD).
#     2) Reads Keycloak DB credentials from Vault (KC_DB_URL_DATABASE/KC_DB_USERNAME/KC_DB_PASSWORD, optional KC_DB_SCHEMA).
#     3) Connects to the Postgres container using the master credentials (TCP 127.0.0.1, so password auth is tested).
#     4) Ensures the Keycloak database exists (create if missing).
#     5) Ensures the Keycloak role exists (create if missing) and sets its password to the Vault value.
#     6) Ensures the schema exists (KC_DB_SCHEMA; default "public") and grants required privileges.
#     7) Verifies the Keycloak role can log in and access the Keycloak database.
#
# How to run
#   chmod +x ./backend/build_scripts/seed_postgres_with_vault_credentials.sh
#   ./backend/build_scripts/seed_postgres_with_vault_credentials.sh \
#     --ca-cert "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt"
#
# Common overrides
#   --vault-host <FQDN|container_name>   (default: vault_production_node)
#   --vault-addr <https://host:8200>    (overrides --vault-host/--vault-port)
#   --token-file <path>                (default: $HOME/NETWORK_TOOLS/.../bootstrap/root_token; prompts if missing)
#   --postgres-container <name>         (default: postgres_primary)
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
  --vault-host HOST             Default: vault_production_node
  --vault-port PORT             Default: 8200
  --vault-scheme http|https     Default: https
  --vault-addr URL              Full URL (overrides scheme/host/port), e.g. https://vault_production_node:8200
  --vault-mount NAME            Default: app_network_tools_secrets
  --token-file PATH             Default: $HOME/NETWORK_TOOLS/.../bootstrap/root_token (prompts if missing)
  --postgres-container NAME     Default: postgres_primary
  --pg-port PORT                Default: 5432
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
  # Double-quote an identifier, escaping embedded quotes.
  # Usage: sql_ident "myRole" -> "myRole"
  local s="$1"
  s="${s//\"/\"\"}"
  printf '"%s"' "$s"
}
sql_lit() {
  # Single-quote a literal, escaping embedded quotes.
  # Usage: sql_lit "pa'ss" -> 'pa''ss'
  local s="$1"
  s="${s//\'/\'\'}"
  printf "'%s'" "$s"
}

validate_name_soft() {
  # Basic guardrail: disallow empty and whitespace-only; allow most printable.
  # (Keycloak/user/db names are expected to be simple.)
  local v="$1"
  [[ -n "$v" ]] || return 1
  [[ "$v" != *$'\n'* ]] || return 1
  [[ "$v" != *$'\r'* ]] || return 1
  return 0
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

while [[ $# -gt 0 ]]; do
  case "$1" in
    --vault-host) VAULT_HOST="$2"; shift 2;;
    --vault-port) VAULT_PORT="$2"; shift 2;;
    --vault-scheme) VAULT_SCHEME="$2"; shift 2;;
    --vault-addr) VAULT_ADDR="$2"; shift 2;;
    --vault-mount) VAULT_MOUNT="$2"; shift 2;;
    --ca-cert) CA_CERT="$2"; shift 2;;
    --token-file) TOKEN_FILE="$2"; shift 2;;
    --postgres-container) POSTGRES_CONTAINER="$2"; shift 2;;
    --pg-port) PG_PORT="$2"; shift 2;;
    --insecure) INSECURE="1"; shift 1;;
    -h|--help) usage; exit 0;;
    *) die "Unknown argument: $1" 1;;
  esac
done

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

log "Vault values loaded:"
log "  Keycloak DB:     ${KC_DB_URL_DATABASE}"
log "  Keycloak Role:   ${KC_DB_USERNAME}"
log "  Keycloak Schema: ${KC_DB_SCHEMA}"
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
# Seed role + DB (no psql :var expansion; use safe quoting)
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
  # Keycloak commonly uses search_path; set it per DB for the role
  psql_master "$KC_DB_URL_DATABASE" "ALTER ROLE ${KC_ROLE_SQL_IDENT} IN DATABASE ${KC_DB_SQL_IDENT} SET search_path TO ${KC_SCHEMA_SQL_IDENT}, public;" >/dev/null
else
  psql_master "$KC_DB_URL_DATABASE" "GRANT USAGE, CREATE ON SCHEMA public TO ${KC_ROLE_SQL_IDENT};"
fi

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

log "SUCCESS: Postgres seeded to match Vault for Keycloak (db/role/schema) and verified login."
