\
#!/usr/bin/env bash
#------------------------------------------------------------------------------
# generate_postgres_pgadmin_bootstrap_creds_and_seed.sh
#
# NOTES / How to run
#   1) Place this script at:
#        $HOME/NETWORK_TOOLS/backend/build_scripts/generate_postgres_pgadmin_bootstrap_creds_and_seed.sh
#
#   2) Run (generates creds + seeds Vault automatically):
#        bash ./backend/build_scripts/generate_postgres_pgadmin_bootstrap_creds_and_seed.sh \
#          --vault-addr "https://vault_production_node:8200" \
#          --ca-cert "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt" \
#          --unseal-required 3 \
#          --prompt-token
#
# What it produces (by default in the Vault bootstrap dir):
#   - postgres_pgadmin.env
#   - postgres_pgadmin_credentials.json
#   - seed_kv_spec.postgres_pgadmin.json
#
# Vault seeding (default ON):
#   - Uses vault_unseal_multi_kv_seed_bootstrap_rootless.sh
#   - Seeds KV mount: app_postgres_secrets (default)
#   - Seeds paths (NO prefix by default):
#       <mount>/postgres
#       <mount>/pgadmin
#
# Security:
#   - Files are created with umask 077 and chmod 600.
#   - Download these files to a secure location and then remove them from the server.
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

PRINT=0
PRINT_SECRETS=0

usage() {
  cat <<'USAGE'
Usage:
  generate_postgres_pgadmin_bootstrap_creds_and_seed.sh [options]

Credential options:
  --postgres-db <name>         POSTGRES_DB value (default: network_tools)
  --postgres-user <name>       POSTGRES_USER value (default: network_tools_user)
  --postgres-password <value>  POSTGRES_PASSWORD (if omitted, generated)
  --pgadmin-password <value>   PGADMIN_DEFAULT_PASSWORD (if omitted, generated)

Output location options:
  --root-dir <path>            Repo root (default: $HOME/NETWORK_TOOLS)
  --bootstrap-dir <path>       Vault bootstrap directory (default: under root-dir)

Vault seeding options (default: seeds Vault):
  --vault-addr <url>           Vault address (default: https://vault_production_node:8200)
  --ca-cert <path>             CA cert to verify Vault TLS (recommended)
  --unseal-required <n>        Unseal threshold (default: 3)
  --prompt-token               Prompt for a Vault token (preferred for one-off runs)
  --token-file <path>          Read token from file (default: <bootstrap_dir>/root_token)
  --seed-script <path>         Path to vault_unseal_multi_kv_seed_bootstrap_rootless.sh
  --no-seed                    Only generate files; do not seed Vault
  --print-secrets              Also pass --print-secrets to the seeding script (sensitive)

Optional path prefixing (default: none):
  --vault-prefix <path>        If set, secrets will be written under <prefix>/<path>
                               Example: --vault-prefix bootstrap -> bootstrap/postgres

Printing:
  --print                      Print generated values (sensitive)
  -h, --help                   Show help

Outputs (in bootstrap dir):
  postgres_pgadmin.env
  postgres_pgadmin_credentials.json
  seed_kv_spec.postgres_pgadmin.json

USAGE
}

# --- Parse args ---
while [[ $# -gt 0 ]]; do
  case "$1" in
    --root-dir) ROOT_DIR="${2:-}"; shift 2;;
    --bootstrap-dir) BOOTSTRAP_DIR="${2:-}"; shift 2;;
    --postgres-db) POSTGRES_DB="${2:-}"; shift 2;;
    --postgres-user) POSTGRES_USER="${2:-}"; shift 2;;
    --postgres-password) POSTGRES_PASSWORD="${2:-}"; shift 2;;
    --pgadmin-password) PGADMIN_DEFAULT_PASSWORD="${2:-}"; shift 2;;
    --vault-addr) VAULT_ADDR="${2:-}"; shift 2;;
    --ca-cert) CA_CERT="${2:-}"; shift 2;;
    --unseal-required) UNSEAL_REQUIRED="${2:-}"; shift 2;;
    --prompt-token) PROMPT_TOKEN=1; shift 1;;
    --token-file) TOKEN_FILE="${2:-}"; shift 2;;
    --seed-script) SEED_SCRIPT="${2:-}"; shift 2;;
    --vault-prefix) VAULT_PREFIX="${2:-}"; shift 2;;
    --no-seed) SEED_VAULT=0; shift 1;;
    --print-secrets) PRINT_SECRETS=1; shift 1;;
    --print) PRINT=1; shift 1;;
    -h|--help) usage; exit 0;;
    *) err "Unknown argument: $1 (use --help)";;
  esac
done

[[ -n "${ROOT_DIR}" ]] || err "--root-dir cannot be empty"
[[ -n "${BOOTSTRAP_DIR}" ]] || err "--bootstrap-dir cannot be empty"

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

# If passwords weren't passed, generate them
if [[ -z "${POSTGRES_PASSWORD}" ]]; then
  POSTGRES_PASSWORD="$(gen_urlsafe 32)"
fi

if [[ -z "${PGADMIN_DEFAULT_PASSWORD}" ]]; then
  PGADMIN_DEFAULT_PASSWORD="$(gen_urlsafe 32)"
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
    "PGADMIN_DEFAULT_PASSWORD": "$(json_escape "${PGADMIN_DEFAULT_PASSWORD}")"
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
          "PGADMIN_DEFAULT_PASSWORD": "$(json_escape "${PGADMIN_DEFAULT_PASSWORD}")"
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

warn "These files contain sensitive credentials."
warn "Download them to a secure location and then remove them from the server."
warn "Suggested download commands:"
cat <<EOF
scp -p <user>@<server>:"${ENV_FILE}" .
scp -p <user>@<server>:"${JSON_FILE}" .
scp -p <user>@<server>:"${SPEC_FILE}" .
EOF
log ""
warn "Suggested cleanup command (after verifying downloads):"
cat <<EOF
ssh <user>@<server> 'rm -f "${ENV_FILE}" "${JSON_FILE}" "${SPEC_FILE}"'
EOF

if [[ "${PRINT}" -eq 1 ]]; then
  warn ""
  warn "--print enabled. Printing secrets to stdout:"
  cat <<EOF

POSTGRES_DB=${POSTGRES_DB}
POSTGRES_USER=${POSTGRES_USER}
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
PGADMIN_DEFAULT_PASSWORD=${PGADMIN_DEFAULT_PASSWORD}

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
