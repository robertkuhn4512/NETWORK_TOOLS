#!/usr/bin/env bash
#
# check_approle_presence_and_ids_in_vault.sh (env + seamless FQDN fallback v4)
#
# -------------------------------------------------------------------
# Notes / How to run
# -------------------------------------------------------------------
# Purpose:
#   Compare host RoleID artifacts against what Vault reports for each AppRole.
#   (Do NOT test secret_id via a login here; in this repo it is commonly configured as single-use.)
#
# How to run (recommended):
#   bash ./backend/build_scripts/validation_scripts/check_approle_presence_and_ids_in_vault.sh
#
# Dependencies (host):
#   - docker
#   - jq
#
# Environment:
#   This script will load <repo-root>/.env by default so it can prefer the FQDN-based Vault
#   address (which matches your TLS certificate SANs) before falling back to the container name.
#
#   Expected variables (recommended in .env):
#     PRIMARY_SERVER_FQDN=networkengineertools.com
#       -> preferred Vault TLS hostname becomes: vault.${PRIMARY_SERVER_FQDN}
#
#   Optional (if you already have an explicit Vault hostname):
#     PRIMARY_VAULT_SERVER_FQDN_FULL=vault.networkengineertools.com
#
#   Optional overrides:
#     VAULT_CONTAINER_NAME=vault_production_node
#
# Caveats / TLS:
#   - Using https://vault_production_node:8200 from the host often fails TLS hostname verification
#     because your cert SAN typically contains vault.<FQDN>, not the docker service name.
#   - This script tries:
#       1) https://vault.<FQDN>:8200   (from inside the Vault container)
#       2) https://<vault-container>:8200 with VAULT_TLS_SERVER_NAME=vault.<FQDN>
#     so you get valid TLS verification without needing to add container names to cert SANs.
#
# Options:
#   --env-file PATH     Load defaults from PATH instead of <repo-root>/.env
#   --no-env-file       Do not load any env file
#   --env-override      Allow env file to override already-set variables
#   --vault-container   Override vault container name (also supports VAULT_CONTAINER_NAME env)
#

set -Eeuo pipefail


# -------------------------------------------------------------------
# Repo root detection (so .env and bootstrap files resolve correctly)
# -------------------------------------------------------------------
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

find_repo_root() {
  local d="$1"
  while [[ "$d" != "/" && -n "$d" ]]; do
    # Heuristics: repo root contains docker-compose.prod.yml and/or a backend/ folder
    if [[ -f "$d/docker-compose.prod.yml" || -f "$d/docker-compose.yml" || -d "$d/backend" ]]; then
      echo "$d"
      return 0
    fi
    d="$(dirname "$d")"
  done
  return 1
}

REPO_ROOT="$(find_repo_root "$SCRIPT_DIR" || true)"
if [[ -z "$REPO_ROOT" ]]; then
  # Fall back to current working directory (best-effort)
  REPO_ROOT="$PWD"
fi

ROOT_TOKEN_FILE="${ROOT_TOKEN_FILE:-$REPO_ROOT/backend/app/security/configuration_files/vault/bootstrap/root_token}"
# -------------------------------------------------------------------
# Logging helpers (must be defined before first use)
# -------------------------------------------------------------------
log()  { echo "INFO: $*" >&2; }
warn() { echo "INFO: WARN: $*" >&2; }
err()  { echo "ERROR: $*" >&2; }
die()  { err "$*"; exit 1; }
dbg()  { [[ "${DEBUG:-0}" == "1" ]] && echo "DEBUG: $*" >&2 || true; }

# -------------------------------------------------------------------
# .env loader (minimal, safe-ish)
# -------------------------------------------------------------------
load_env_file() {
  local file="$1"
  local override="${2:-0}"
  [[ -n "$file" && -r "$file" ]] || return 0

  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    [[ -z "$line" ]] && continue
    [[ "$line" == \#* ]] && continue
    [[ "$line" == export\ * ]] && line="${line#export }"
    [[ "$line" == *"="* ]] || continue

    local key="${line%%=*}"
    local val="${line#*=}"
    key="${key#"${key%%[![:space:]]*}"}"
    key="${key%"${key##*[![:space:]]}"}"
    [[ "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || continue

    val="${val#"${val%%[![:space:]]*}"}"
    val="${val%"${val##*[![:space:]]}"}"

    if [[ ${#val} -ge 2 && "$val" == \"*\" && "$val" == *\" ]]; then
      val="${val:1:${#val}-2}"
    elif [[ ${#val} -ge 2 && "$val" == \'*\' && "$val" == *\' ]]; then
      val="${val:1:${#val}-2}"
    fi

    if (( ! override )); then
      [[ -n "${!key:-}" ]] && continue
    fi

    printf -v "$key" '%s' "$val"
    export "$key"
  done < "$file"
}

strip_scheme_port_path() {
  # Convert things like:
  #   https://vault.example.com:8200  -> vault.example.com
  #   vault.example.com:8200         -> vault.example.com
  #   vault.example.com              -> vault.example.com
  local s="${1:-}"
  s="${s#http://}"
  s="${s#https://}"
  s="${s%%/*}"
  s="${s%%:*}"
  printf '%s' "$s"
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"
}

# -------------------------------------------------------------------
# Arg parsing
# -------------------------------------------------------------------
ENV_FILE=""
LOAD_ENV=1
ENV_OVERRIDE=0
VAULT_CONTAINER_NAME="${VAULT_CONTAINER_NAME:-vault_production_node}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --env-file)
      ENV_FILE="${2:-}"; [[ -n "$ENV_FILE" ]] || die "--env-file requires a path"; shift 2 ;;
    --no-env-file)
      LOAD_ENV=0; shift ;;
    --env-override)
      ENV_OVERRIDE=1; shift ;;
    --vault-container)
      VAULT_CONTAINER_NAME="${2:-}"; [[ -n "$VAULT_CONTAINER_NAME" ]] || die "--vault-container requires a name"; shift 2 ;;
    -h|--help)
      sed -n '1,120p' "$0"
      exit 0 ;;
    *)
      die "Unknown argument: $1" ;;
  esac
done

# Default env file: <repo-root>/.env unless user provided --env-file
if [[ -z "${ENV_FILE:-}" ]]; then
  ENV_FILE="$REPO_ROOT/.env"
fi

# If repo-root .env is missing (repo-root detection/cwd edge cases), also try current working directory.
if [[ ! -r "${ENV_FILE}" && -r "${PWD}/.env" ]]; then
  ENV_FILE="${PWD}/.env"
fi

require_cmd docker
require_cmd jq

# -------------------------------------------------------------------
# Load .env (defaults)
# -------------------------------------------------------------------
if (( LOAD_ENV )); then
  if [[ -z "$ENV_FILE" ]]; then
    ENV_FILE="${REPO_ROOT}/.env"
  fi
  if [[ -r "$ENV_FILE" ]]; then
    log "Loading env defaults from: ${ENV_FILE}"
    load_env_file "$ENV_FILE" "$ENV_OVERRIDE"
  else
    warn "Env file not found/readable (skipping): ${ENV_FILE}"
  fi
fi

# -------------------------------------------------------------------
# Resolve preferred Vault hostname (FQDN) from env
# -------------------------------------------------------------------
PREFERRED_VAULT_HOST=""

if [[ -n "${PRIMARY_VAULT_SERVER_FQDN_FULL:-}" ]]; then
  PREFERRED_VAULT_HOST="$(strip_scheme_port_path "${PRIMARY_VAULT_SERVER_FQDN_FULL}")"
elif [[ -n "${PRIMARY_SERVER_FQDN:-}" ]]; then
  PREFERRED_VAULT_HOST="vault.${PRIMARY_SERVER_FQDN}"
fi

# Vault bootstrap artifacts and host RoleID files (make paths independent of cwd)
BOOTSTRAP_DIR="${REPO_ROOT}/backend/app/security/configuration_files/vault/bootstrap"

# Allow overrides for the root token file path (prefer explicit env var, then default repo path).
VAULT_TOKEN_FILE_DEFAULT="${BOOTSTRAP_DIR}/root_token"
VAULT_TOKEN_FILE="${VAULT_ROOT_TOKEN_FILE:-${ROOT_TOKEN_FILE:-${VAULT_TOKEN_FILE:-${VAULT_TOKEN_FILE_DEFAULT}}}}"

[[ -r "$VAULT_TOKEN_FILE" ]] || die "Vault root token file not found/readable: ${VAULT_TOKEN_FILE}"
VAULT_TOKEN="$(tr -d '\r\n' < "$VAULT_TOKEN_FILE")"

ROLE_BASE_DIR="${REPO_ROOT}/container_data/vault/approle"

# Determine CA path inside the Vault container (prefer ca.crt; fallback to cert.crt)
detect_ca_path_in_container() {
  local c="$1"
  if docker exec "$c" sh -lc 'test -f /vault/certs/ca.crt'; then
    echo "/vault/certs/ca.crt"
    return 0
  fi
  if docker exec "$c" sh -lc 'test -f /vault/certs/cert.crt'; then
    warn "VAULT_CACERT_IN_CONTAINER '/vault/certs/ca.crt' not found in container; using /vault/certs/cert.crt"
    echo "/vault/certs/cert.crt"
    return 0
  fi
  echo ""
  return 0
}

VAULT_CACERT_IN_CONTAINER="$(detect_ca_path_in_container "$VAULT_CONTAINER_NAME")"
[[ -n "$VAULT_CACERT_IN_CONTAINER" ]] || die "Could not find /vault/certs/ca.crt or /vault/certs/cert.crt inside container '${VAULT_CONTAINER_NAME}'."

vault_read_role_id_json() {
  local role_name="$1"
  local vault_addr="$2"
  local tls_server_name="${3:-}"

  local envs=(
    -e "VAULT_ADDR=${vault_addr}"
    -e "VAULT_CACERT=${VAULT_CACERT_IN_CONTAINER}"
    -e "VAULT_TOKEN=${VAULT_TOKEN}"
  )
  if [[ -n "$tls_server_name" ]]; then
    envs+=(-e "VAULT_TLS_SERVER_NAME=${tls_server_name}")
  fi

  docker exec "${envs[@]}" "$VAULT_CONTAINER_NAME" \
    vault read -format=json "auth/approle/role/${role_name}/role-id"
}

get_role_id_from_vault() {
  local role_name="$1"
  local json out rc
  local tried=()

  # 1) Try preferred FQDN first (if provided). This may fail if the container cannot resolve DNS.
  if [[ -n "$PREFERRED_VAULT_HOST" ]]; then
    local addr1="https://${PREFERRED_VAULT_HOST}:8200"
    tried+=("$addr1")
    if out="$(vault_read_role_id_json "$role_name" "$addr1" "" 2>&1)"; then
      echo "$out" | jq -r '.data.role_id'
      return 0
    else
      warn "Vault CLI read failed for ${addr1}: $(echo "$out" | tr '\n' ' ')"
    fi
  fi

  # 2) Fallback to container name, but preserve TLS verification using VAULT_TLS_SERVER_NAME (if available).
  local addr2="https://${VAULT_CONTAINER_NAME}:8200"
  tried+=("$addr2")
  local tls_name=""
  if [[ -n "$PREFERRED_VAULT_HOST" ]]; then
    tls_name="$PREFERRED_VAULT_HOST"
  fi

  if out="$(vault_read_role_id_json "$role_name" "$addr2" "$tls_name" 2>&1)"; then
    echo "$out" | jq -r '.data.role_id'
    return 0
  fi

  # If we got here, both attempts failed.
  err "Vault CLI is not reachable from inside container '${VAULT_CONTAINER_NAME}'."
  err "Tried: ${tried[*]}"
  if [[ -z "$PREFERRED_VAULT_HOST" ]]; then
    err "No PRIMARY_SERVER_FQDN / PRIMARY_VAULT_SERVER_FQDN_FULL detected; set one in .env so TLS can validate against vault.<FQDN>."
  else
    err "Preferred Vault host from env: ${PREFERRED_VAULT_HOST}"
  fi
  err "Last error: $(echo "$out" | tr '\n' ' ')"
  return 1
}

check_role_id() {
  local role_name="$1"
  local role_dir="${ROLE_BASE_DIR}/${role_name}"
  local host_role_id_file="${role_dir}/role_id"

  [[ -r "$host_role_id_file" ]] || die "Host role_id file not found/readable: ${host_role_id_file}"

  local role_id_host
  role_id_host="$(cat "$host_role_id_file")"

  local role_id_vault
  role_id_vault="$(get_role_id_from_vault "$role_name")"

  echo
  echo "${role_name} role_id (host):  ${role_id_host}"
  echo "${role_name} role_id (vault): ${role_id_vault}"
}

check_role_id "postgres_pgadmin_agent"
check_role_id "keycloak_agent"
