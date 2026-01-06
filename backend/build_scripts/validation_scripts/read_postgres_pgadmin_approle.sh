#!/usr/bin/env bash
set -euo pipefail

# -----------------------------------------------------------------------------
# read_postgres_pgadmin_approle.sh
#
# Notes / How to run:
#   chmod +x ./backend/build_scripts/validation_scripts/read_postgres_pgadmin_approle.sh
#   bash ./backend/build_scripts/validation_scripts/read_postgres_pgadmin_approle.sh
#
# What it does:
#   - Reads Vault root token + CA cert from your bootstrap directory
#   - Uses Vault CLI inside the vault_production_node container to read:
#       auth/approle/role/postgres_pgadmin_agent
#
# Optional overrides:
#   --vault-container vault_production_node
#   --role-name       postgres_pgadmin_agent
#   --vault-addr      https://vault_production_node:8200
#   --ca-cert         <path to ca.crt on host>
#   --root-token-file <path to root_token on host>
# -----------------------------------------------------------------------------

err() { echo "{\"error\":\"$*\"}" >&2; exit 1; }

VAULT_CONTAINER="vault_production_node"
ROLE_NAME="postgres_pgadmin_agent"
VAULT_ADDR="https://vault_production_node:8200"

CA_CERT_HOST="$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt"
ROOT_TOKEN_FILE_HOST="$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --vault-container) VAULT_CONTAINER="${2:-}"; shift 2 ;;
    --role-name)       ROLE_NAME="${2:-}"; shift 2 ;;
    --vault-addr)      VAULT_ADDR="${2:-}"; shift 2 ;;
    --ca-cert)         CA_CERT_HOST="${2:-}"; shift 2 ;;
    --root-token-file) ROOT_TOKEN_FILE_HOST="${2:-}"; shift 2 ;;
    -h|--help)
      cat <<EOF
Usage:
  read_postgres_pgadmin_approle.sh [options]

Options:
  --vault-container <name>   Vault container name (default: vault_production_node)
  --role-name <name>         AppRole name (default: postgres_pgadmin_agent)
  --vault-addr <url>         Vault address (default: https://vault_production_node:8200)
  --ca-cert <path>           Host path to CA cert (default: $CA_CERT_HOST)
  --root-token-file <path>   Host path to root token (default: $ROOT_TOKEN_FILE_HOST)
EOF
      exit 0
      ;;
    *) err "Unknown argument: $1" ;;
  esac
done

[[ -n "$VAULT_CONTAINER" ]] || err "--vault-container is required"
[[ -n "$ROLE_NAME" ]] || err "--role-name is required"
[[ -n "$VAULT_ADDR" ]] || err "--vault-addr is required"
[[ -f "$CA_CERT_HOST" ]] || err "CA cert not found: $CA_CERT_HOST"
[[ -f "$ROOT_TOKEN_FILE_HOST" ]] || err "Root token file not found: $ROOT_TOKEN_FILE_HOST"

command -v docker >/dev/null 2>&1 || err "docker not found in PATH"

ROOT_TOKEN="$(cat "$ROOT_TOKEN_FILE_HOST")"
[[ -n "$ROOT_TOKEN" ]] || err "Root token file is empty: $ROOT_TOKEN_FILE_HOST"

# In your compose, the Vault container uses /vault/certs/cert.crt + /vault/certs/cert.key
# The CA is available on the host; for in-container calls, use the container path if mounted.
# If you do not mount ca.crt into /vault/certs/ca.crt, Vault CLI can still work if VAULT_CACERT points to cert.crt,
# but for correct verification you should mount the CA into the container and use it.
VAULT_CACERT_IN_CONTAINER="/vault/certs/ca.crt"
FALLBACK_CACERT_IN_CONTAINER="/vault/certs/cert.crt"

echo "=== Reading AppRole config from Vault ==="
echo "Vault container: $VAULT_CONTAINER"
echo "Vault addr:      $VAULT_ADDR"
echo "AppRole:         $ROLE_NAME"
echo

docker exec -i \
  -e "VAULT_ADDR=$VAULT_ADDR" \
  -e "VAULT_TOKEN=$ROOT_TOKEN" \
  "$VAULT_CONTAINER" sh -lc "
    set -e
    if [ -f '$VAULT_CACERT_IN_CONTAINER' ]; then
      export VAULT_CACERT='$VAULT_CACERT_IN_CONTAINER'
    elif [ -f '$FALLBACK_CACERT_IN_CONTAINER' ]; then
      echo 'WARN: /vault/certs/ca.crt not found; falling back to /vault/certs/cert.crt for VAULT_CACERT' >&2
      export VAULT_CACERT='$FALLBACK_CACERT_IN_CONTAINER'
    else
      echo '{\"error\":\"No CA/cert found inside vault container at /vault/certs/ca.crt or /vault/certs/cert.crt\"}' >&2
      exit 1
    fi

    vault read auth/approle/role/$ROLE_NAME
  "
