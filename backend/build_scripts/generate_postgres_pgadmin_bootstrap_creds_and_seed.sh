#!/usr/bin/env bash
#------------------------------------------------------------------------------
# generate_postgres_pgadmin_bootstrap_creds_and_seed.sh
#
# NOTES / How to run
#
# First-time init (generate + seed into Vault)
#   Run from the repo root as the same non-root user that runs rootless Docker:
#
#     cd "$HOME/NETWORK_TOOLS"
#
#     bash ./backend/build_scripts/generate_postgres_pgadmin_bootstrap_creds_and_seed.sh \
#       --vault-addr "https://vault_production_node:8200" \
#       --ca-cert "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt" \
#       --unseal-required 3 \
#       --prompt-token
#
#   Then bring up the Vault Agent + Postgres + pgAdmin stack (compose wiring must
#   mount the shared rendered-secrets volume at /run/vault in postgres_primary and pgadmin):
#
#     docker compose -f docker-compose.prod.yml up -d \
#       vault_agent_postgres_pgadmin postgres_primary pgadmin
#
#   Verify secrets are rendered:
#     docker exec -it vault_agent_postgres_pgadmin sh -lc 'ls -lah /vault/rendered'
#     docker exec -it postgres_primary sh -lc 'ls -lah /run/vault'
#
#   IMPORTANT: Postgres only uses POSTGRES_*_FILE values when its data directory is EMPTY.
#   If you are reusing an existing PGDATA volume, use --mode rotate + --apply-to-postgres.
#
# What this script is for
#   This script is the "bootstrap generator" for your Postgres + pgAdmin secrets:
#     - Generates or accepts a Postgres DB/user/password and a pgAdmin admin password
#     - Produces small artifacts (.env + json + vault seeding spec) under the Vault
#       bootstrap directory (umask 077, chmod 600)
#     - Optionally seeds those values into Vault KV (default ON)
#     - Optionally applies (rotates) the Postgres role password in a RUNNING Postgres
#       container to match Vault (useful after the database has already been initialized)
#
# Why the docker-compose integration uses *_FILE
#   The official Postgres image supports reading these init variables from files by
#   appending _FILE (e.g., POSTGRES_PASSWORD_FILE). It also supports _FILE for
#   POSTGRES_USER and POSTGRES_DB. This is intended for Docker secrets style
#   usage and prevents putting credentials directly in compose files or env.
#
#   IMPORTANT: The Postgres image only consumes these init variables when the data
#   directory is EMPTY (first init). On subsequent restarts, the entrypoint will not
#   recreate users or reset passwords automatically.
#
# How your compose is intended to work (high level)
#   1) This script seeds Vault KV paths:
#         <mount>/postgres  -> POSTGRES_DB, POSTGRES_USER, POSTGRES_PASSWORD
#         <mount>/pgadmin   -> PGADMIN_DEFAULT_PASSWORD
#         <mount>/pgadmin   -> PGADMIN_DEFAULT_EMAIL (This needs to be set in the .env file as well. Seeded here in case it's needed from another program accessing vault)
#      (Your compose already wires Postgres/pgAdmin to read rendered values from
#       /run/vault/* files.)
#
#   2) A Vault Agent sidecar renders those KV values to a shared volume.
#      (Your service vault_agent_postgres_pgadmin.)
#
#   3) Postgres starts and uses *_FILE ONLY on first init (empty data dir),
#      creating the DB/user and setting the password.
#
#   4) After first init, password rotation requires an explicit SQL ALTER ROLE.
#      This script can optionally apply that change to the running container.
#
# Password rotation recommendation (what to put in your runbook)
#   A) Preferred "maintenance window" rotation (simple and safe):
#      1) Stop application services that connect to Postgres (FastAPI, workers, etc.)
#      2) Run this script in rotation mode (generates a new password and seeds Vault):
#           bash ./backend/build_scripts/generate_postgres_pgadmin_bootstrap_creds_and_seed.sh \
#             --mode rotate \
#             --vault-addr "https://vault_production_node:8200" \
#             --ca-cert "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt" \
#             --unseal-required 3 \
#             --prompt-token
#
#      3) Apply the new password to Postgres (either with --apply-to-postgres in the
#         same run, or manually using the command printed by the script).
#
#      4) Start your application services again so they reconnect using the new
#         password (the Vault Agent will have re-rendered it).
#
#   B) pgAdmin password rotation
#      pgAdmin supports PGADMIN_DEFAULT_PASSWORD_FILE at container launch time.
#      If you do not persist pgAdmin state (no volume mounted), the simplest method
#      is to force-recreate the pgAdmin container after updating the Vault secret.
#
# Security notes
#   - Avoid printing secrets in terminals and logs (use --print only when needed).
#   - Keep the bootstrap artifacts only long enough to verify they were seeded, then remove.
#------------------------------------------------------------------------------

set -euo pipefail

log()  { printf '%s\n' "INFO: $*"; }
warn() { printf '%s\n' "WARN: $*" >&2; }
err()  { printf '%s\n' "ERROR: $*" >&2; exit 1; }

# --- Defaults ---
ROOT_DIR="${HOME}/NETWORK_TOOLS"
BOOTSTRAP_DIR="${ROOT_DIR}/backend/app/security/configuration_files/vault/bootstrap"

POSTGRES_DB="network_tools"
POSTGRES_USER="network_tools_user"
POSTGRES_PASSWORD=""
PGADMIN_DEFAULT_PASSWORD=""
PGADMIN_DEFAULT_EMAIL="admin@example.com"

# IMPORTANT: requested mount name
VAULT_MOUNT="app_postgres_secrets"

# IMPORTANT: user requested NO prefix (e.g., "postgres", not "bootstrap/postgres")
VAULT_PREFIX=""

# Vault connectivity / seeding
SEED_VAULT=1
SEED_SCRIPT="${ROOT_DIR}/backend/build_scripts/vault_unseal_multi_kv_seed_bootstrap_rootless.sh"
VAULT_ADDR_DEFAULT="https://vault_production_node:8200"
VAULT_ADDR="${VAULT_ADDR_DEFAULT}"
CA_CERT=""
UNSEAL_REQUIRED=3

PROMPT_TOKEN=0
TOKEN_FILE="${BOOTSTRAP_DIR}/root_token"

# Rotation/apply options
MODE="generate"                 # generate|rotate
APPLY_TO_POSTGRES=0             # if 1, run ALTER ROLE inside running container after seeding
POSTGRES_CONTAINER="postgres_primary"
POSTGRES_ADMIN_DB="postgres"    # where to connect for ALTER ROLE (postgres is safe)

PRINT=0
PRINT_SECRETS=0

usage() {
  cat <<'USAGE'
Usage:
  generate_postgres_pgadmin_bootstrap_creds_and_seed.sh [options]

Modes:
  --mode <generate|rotate>       generate: create artifacts + optionally seed Vault (default)
                                rotate:   generate NEW passwords (even if old existed) and seed Vault

Credential options:
  --postgres-db <name>                POSTGRES_DB value (default: network_tools)
  --postgres-user <name>              POSTGRES_USER value (default: network_tools_user)
  --postgres-password <value>         POSTGRES_PASSWORD (if omitted, generated)
  --pgadmin-password <value>          PGADMIN_DEFAULT_PASSWORD (if omitted, generated)
  --pgadmin-default-email <value>     PGADMIN_DEFAULT_EMAIL (if omitted, it get hardcoded to admin@example.com)

Vault seeding options (default: seeds Vault):
  --vault-addr <url>             Vault address (default: https://vault_production_node:8200)
  --ca-cert <path>               CA cert to verify Vault TLS (recommended)
  --unseal-required <n>          Unseal threshold (default: 3)
  --prompt-token                 Prompt for a Vault token (preferred for one-off runs)
  --token-file <path>            Read token from file (default: <bootstrap_dir>/root_token)
  --seed-script <path>           Path to vault_unseal_multi_kv_seed_bootstrap_rootless.sh
  --no-seed                      Only generate files; do not seed Vault

Optional path prefixing (default: none):
  --vault-prefix <path>          If set, secrets will be written under <prefix>/<path>
                                Example: --vault-prefix bootstrap -> bootstrap/postgres

Apply rotation into running Postgres (optional):
  --apply-to-postgres            After seeding Vault, run ALTER ROLE to set the Postgres
                                role password to the value rendered at /run/vault/postgres_password
  --postgres-container <name>    Container name (default: postgres_primary)
  --postgres-admin-db <name>     Admin DB to connect to for ALTER ROLE (default: postgres)

Printing:
  --print                        Print generated values (sensitive)
  --print-secrets                Also pass --print-secrets to the seeding script (sensitive)
  -h, --help                     Show help

Outputs (in bootstrap dir):
  postgres_pgadmin.env
  postgres_pgadmin_credentials.json
  seed_kv_spec.postgres_pgadmin.json

USAGE
}

# --- Parse args ---
while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) MODE="${2:-}"; shift 2;;
    --root-dir) ROOT_DIR="${2:-}"; shift 2;;
    --bootstrap-dir) BOOTSTRAP_DIR="${2:-}"; shift 2;;
    --postgres-db) POSTGRES_DB="${2:-}"; shift 2;;
    --postgres-user) POSTGRES_USER="${2:-}"; shift 2;;
    --postgres-password) POSTGRES_PASSWORD="${2:-}"; shift 2;;
    --pgadmin-password) PGADMIN_DEFAULT_PASSWORD="${2:-}"; shift 2;;
    --pgadmin-default-email) PGADMIN_DEFAULT_EMAIL="${2:-}"; shift 2;;
    --vault-addr) VAULT_ADDR="${2:-}"; shift 2;;
    --ca-cert) CA_CERT="${2:-}"; shift 2;;
    --unseal-required) UNSEAL_REQUIRED="${2:-}"; shift 2;;
    --prompt-token) PROMPT_TOKEN=1; shift 1;;
    --token-file) TOKEN_FILE="${2:-}"; shift 2;;
    --seed-script) SEED_SCRIPT="${2:-}"; shift 2;;
    --vault-prefix) VAULT_PREFIX="${2:-}"; shift 2;;
    --no-seed) SEED_VAULT=0; shift 1;;
    --apply-to-postgres) APPLY_TO_POSTGRES=1; shift 1;;
    --postgres-container) POSTGRES_CONTAINER="${2:-}"; shift 2;;
    --postgres-admin-db) POSTGRES_ADMIN_DB="${2:-}"; shift 2;;
    --print-secrets) PRINT_SECRETS=1; shift 1;;
    --print) PRINT=1; shift 1;;
    -h|--help) usage; exit 0;;
    *) err "Unknown argument: $1 (use --help)";;
  esac
done

[[ -n "${ROOT_DIR}" ]] || err "--root-dir cannot be empty"
[[ -n "${BOOTSTRAP_DIR}" ]] || err "--bootstrap-dir cannot be empty"
[[ "${MODE}" == "generate" || "${MODE}" == "rotate" ]] || err "--mode must be generate|rotate"

# --- Random generators ---
gen_urlsafe() {
  # Generates a URL-safe random string.
  # Arg1: bytes (default 32)
  local bytes="${1:-32}"

  if command -v python3 >/dev/null 2>&1; then
    python3 - <<PY
import secrets
print(secrets.token_urlsafe(${bytes}))
PY
    return 0
  fi

  if command -v openssl >/dev/null 2>&1; then
    openssl rand -base64 "${bytes}" | tr '+/' '-_' | tr -d '=' | tr -d '\n'
    return 0
  fi

  err "Need python3 or openssl to generate secrets"
}

# --- Ensure bootstrap dir exists; lock down perms ---
umask 077
mkdir -p "${BOOTSTRAP_DIR}"

# In rotate mode, always generate new passwords unless explicitly provided
if [[ "${MODE}" == "rotate" ]]; then
  [[ -n "${POSTGRES_PASSWORD}" ]] || POSTGRES_PASSWORD="$(gen_urlsafe 32)"
  [[ -n "${PGADMIN_DEFAULT_PASSWORD}" ]] || PGADMIN_DEFAULT_PASSWORD="$(gen_urlsafe 32)"
else
  # If passwords weren't passed, generate them
  [[ -n "${POSTGRES_PASSWORD}" ]] || POSTGRES_PASSWORD="$(gen_urlsafe 32)"
  [[ -n "${PGADMIN_DEFAULT_PASSWORD}" ]] || PGADMIN_DEFAULT_PASSWORD="$(gen_urlsafe 32)"
fi

# --- Output files ---
ENV_FILE="${BOOTSTRAP_DIR}/postgres_pgadmin.env"
JSON_FILE="${BOOTSTRAP_DIR}/postgres_pgadmin_credentials.json"
SPEC_FILE="${BOOTSTRAP_DIR}/seed_kv_spec.postgres_pgadmin.json"

# .env file for docker-compose usage
cat > "${ENV_FILE}" <<EOF
# Generated: $(date -u +'%Y-%m-%dT%H:%M:%SZ')
# Store securely. Do not commit to git.

# postgres
POSTGRES_DB=${POSTGRES_DB}
POSTGRES_USER=${POSTGRES_USER}
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}

# pgAdmin
PGADMIN_DEFAULT_PASSWORD=${PGADMIN_DEFAULT_PASSWORD}
PGADMIN_DEFAULT_EMAIL=${PGADMIN_DEFAULT_EMAIL}
EOF

# JSON artifact (human-readable)
json_escape() { printf '%s' "$1" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read())[1:-1])' 2>/dev/null || printf '%s' "$1" | sed 's/"/\\"/g'; }

cat > "${JSON_FILE}" <<EOF
{
  "generated_at_utc": "$(date -u +'%Y-%m-%dT%H:%M:%SZ')",
  "postgres": {
    "POSTGRES_DB": "$(json_escape "${POSTGRES_DB}")",
    "POSTGRES_USER": "$(json_escape "${POSTGRES_USER}")",
    "POSTGRES_PASSWORD": "$(json_escape "${POSTGRES_PASSWORD}")"
  },
  "pgadmin": {
    "PGADMIN_DEFAULT_PASSWORD": "$(json_escape "${PGADMIN_DEFAULT_PASSWORD}")",
    "PGADMIN_DEFAULT_EMAIL": "$(json_escape "${PGADMIN_DEFAULT_EMAIL}")"
  }
}
EOF

# Multi-seed spec file for vault_unseal_multi_kv_seed_bootstrap_rootless.sh
# Default is NO prefix: "postgres" and "pgadmin" (not "bootstrap/postgres").
PREFIX_LINE=""
if [[ -n "${VAULT_PREFIX}" ]]; then
  PREFIX_LINE=$'      "prefix": "'"${VAULT_PREFIX}"$'",\n'
fi

cat > "${SPEC_FILE}" <<EOF
{
  "mounts": [
    {
      "mount": "${VAULT_MOUNT}",
      "version": 2,
${PREFIX_LINE}      "secrets": {
        "postgres": {
          "POSTGRES_DB": "$(json_escape "${POSTGRES_DB}")",
          "POSTGRES_USER": "$(json_escape "${POSTGRES_USER}")",
          "POSTGRES_PASSWORD": "$(json_escape "${POSTGRES_PASSWORD}")"
        },
        "pgadmin": {
          "PGADMIN_DEFAULT_PASSWORD": "$(json_escape "${PGADMIN_DEFAULT_PASSWORD}")",
          "PGADMIN_DEFAULT_EMAIL": "$(json_escape "${PGADMIN_DEFAULT_EMAIL}")"
        }
      }
    }
  ]
}
EOF

chmod 600 "${ENV_FILE}" "${JSON_FILE}" "${SPEC_FILE}" || true

log "Wrote credential artifacts:"
log "  ENV:  ${ENV_FILE}"
log "  JSON: ${JSON_FILE}"
log "  SPEC: ${SPEC_FILE}"
log ""

log "Vault targets (from spec):"
log "  KV mount: ${VAULT_MOUNT}"
if [[ -n "${VAULT_PREFIX}" ]]; then
  log "  Paths:    ${VAULT_PREFIX}/postgres  and  ${VAULT_PREFIX}/pgadmin"
else
  log "  Paths:    postgres  and  pgadmin"
fi
log ""

if [[ "${PRINT}" -eq 1 ]]; then
  warn ""
  warn "--print enabled. Printing secrets to stdout:"
  cat <<EOF

POSTGRES_DB=${POSTGRES_DB}
POSTGRES_USER=${POSTGRES_USER}
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
PGADMIN_DEFAULT_PASSWORD=${PGADMIN_DEFAULT_PASSWORD}
PGADMIN_DEFAULT_EMAIL=${PGADMIN_DEFAULT_EMAIL}

EOF
fi

# --- Seed Vault automatically (default ON) ---
if [[ "${SEED_VAULT}" -eq 1 ]]; then
  log ""
  log "Seeding Vault from generated spec..."
  log "  VAULT_ADDR: ${VAULT_ADDR}"
  log "  Seed script: ${SEED_SCRIPT}"
  [[ -n "${CA_CERT}" ]] && log "  CA cert:    ${CA_CERT}"

  [[ -f "${SEED_SCRIPT}" ]] || err "Seed script not found at: ${SEED_SCRIPT}"
  [[ -f "${SPEC_FILE}" ]] || err "Spec file missing at: ${SPEC_FILE}"

  seed_args=( --vault-addr "${VAULT_ADDR}" --spec-json "${SPEC_FILE}" --unseal-required "${UNSEAL_REQUIRED}" )

  if [[ -n "${CA_CERT}" ]]; then
    seed_args+=( --ca-cert "${CA_CERT}" )
  fi

  if [[ "${PROMPT_TOKEN}" -eq 1 ]]; then
    seed_args+=( --prompt-token )
  else
    if [[ -f "${TOKEN_FILE}" ]]; then
      seed_args+=( --token-file "${TOKEN_FILE}" )
    else
      warn "Token file not found at: ${TOKEN_FILE}"
      warn "Falling back to --prompt-token."
      seed_args+=( --prompt-token )
    fi
  fi

  if [[ "${PRINT_SECRETS}" -eq 1 ]]; then
    seed_args+=( --print-secrets )
  fi

  bash "${SEED_SCRIPT}" "${seed_args[@]}"

  log "Vault seeding completed (see output above)."
else
  log "Vault seeding skipped (--no-seed)."
fi

# --- Optional: Apply Postgres role password inside a running container ---
#
# This is meant for AFTER the database has already been initialized and is running.
# It expects your compose to mount the Vault Agent rendered secrets to /run/vault
# inside the postgres container.
#
# Implementation detail:
#   - Avoid nested shell quoting (easy to break, especially with passwords).
#   - Read the rendered values inside the container, then use psql variable
#     substitution (:'var') so quoting is handled safely.
if [[ "${APPLY_TO_POSTGRES}" -eq 1 ]]; then
  command -v docker >/dev/null 2>&1 || err "--apply-to-postgres requires docker CLI on the host"

  log ""
  log "Applying Postgres role password in container: ${POSTGRES_CONTAINER}"
  log "  (reading /run/vault/postgres_user and /run/vault/postgres_password inside the container)"
  log ""

  docker exec -i -u postgres     -e POSTGRES_ADMIN_DB="${POSTGRES_ADMIN_DB}"     "${POSTGRES_CONTAINER}" bash -s -- <<'EOS'
set -euo pipefail

APPUSER="$(cat /run/vault/postgres_user 2>/dev/null || true)"
NEWPASS="$(cat /run/vault/postgres_password 2>/dev/null || true)"

if [ -z "${APPUSER}" ] || [ -z "${NEWPASS}" ]; then
  echo "ERROR: missing /run/vault/postgres_user or /run/vault/postgres_password" >&2
  exit 1
fi

psql -v ON_ERROR_STOP=1 --username=postgres --dbname="${POSTGRES_ADMIN_DB}"   -v appuser="${APPUSER}" -v newpass="${NEWPASS}"   -c "ALTER ROLE :\"appuser\" WITH PASSWORD :'newpass';"
EOS

  log "Postgres password apply completed."
else
  log ""
  log "Rotation apply skipped (use --apply-to-postgres if you want to run ALTER ROLE automatically)."
  log "Manual apply command (runs inside postgres container as OS user 'postgres'):"
  cat <<EOF
docker exec -i -u postgres -e POSTGRES_ADMIN_DB=${POSTGRES_ADMIN_DB} ${POSTGRES_CONTAINER} bash -s -- <<'EOS'
set -euo pipefail
APPUSER="\$(cat /run/vault/postgres_user)"
NEWPASS="\$(cat /run/vault/postgres_password)"
psql -v ON_ERROR_STOP=1 --username=postgres --dbname="\${POSTGRES_ADMIN_DB}" \
  -v appuser="\${APPUSER}" -v newpass="\${NEWPASS}" \
  -c "ALTER ROLE :\\"appuser\\" WITH PASSWORD :'newpass';"
EOS
EOF
fi

warn ""

warn "These files contain sensitive credentials."
warn "Download them to a secure location and then remove them from the server."
warn "Suggested cleanup command (after verifying downloads and Vault seeding):"
cat <<EOF
rm -f "${ENV_FILE}" "${JSON_FILE}" "${SPEC_FILE}"
EOF
