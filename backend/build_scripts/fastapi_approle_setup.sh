#!/usr/bin/env bash
#
# fastapi_approle_setup.sh
#
# Notes / How to run:
#   1) Ensure Vault is running (example):
#        docker compose -f docker-compose.prod.yml up -d vault_production_node
#
#   2) Ensure a Vault token is available via ONE of these host-side files:
#        ./backend/app/security/configuration_files/vault/bootstrap/root_token
#        ./backend/app/security/configuration_files/vault/bootstrap/root_token.json   (expects .root_token)
#
#      If neither file exists, the script will securely prompt you (input hidden).
#
#   3) Run:
#        chmod +x ./backend/build_scripts/fastapi_approle_setup.sh
#        ROLE_NAME=fastapi_agent ./backend/build_scripts/fastapi_approle_setup.sh
#
# What this script does:
#   - Executes *all* Vault CLI operations via docker exec into: vault_production_node
#   - Forces the in-container Vault CLI to talk to:
#       VAULT_ADDR=${VAULT_ADDR_IN_CONTAINER}     (default: https://<PRIMARY_SERVER_FQDN or vault_production_node>:8200)
#       VAULT_CACERT=${VAULT_CACERT_IN_CONTAINER} (default: /vault/certs/ca.crt, with fallback)
#   - Reads the AppRole role_id and generates a secret_id
#   - Writes host files used for Vault Agent auto-auth bootstrapping:
#       <OUT_DIR>/role_id
#       <OUT_DIR>/secret_id
#
# Optional env vars:
#   ENV_FILE=<repo>/.env (default: <repo>/.env; used to read PRIMARY_SERVER_FQDN if not already set)
#   PRIMARY_SERVER_FQDN=networkengineertools.com   (if set or found in ENV_FILE, used to build default VAULT_ADDR_IN_CONTAINER)
#   VAULT_CONTAINER=vault_production_node          (default: vault_production_node)
#   ROLE_NAME=fastapi_agent                  (default: fastapi_agent)
#   OUT_DIR=<repo>/container_data/vault/approle/<ROLE_NAME>
#   ROTATE_SECRET_ID=1                             (default: 1; set 0 to keep existing secret_id if present)
#
#   # TLS behavior for the in-container Vault CLI:
#   VAULT_ADDR_IN_CONTAINER=https://<PRIMARY_SERVER_FQDN or VAULT_CONTAINER>:8200   (default if not set; derived at runtime)
#   VAULT_CACERT_IN_CONTAINER=/vault/certs/ca.crt                (default; if missing, falls back to /vault/certs/cert.crt if present)
#   VAULT_SKIP_VERIFY_IN_CONTAINER=0                             (default: 0; set 1 only if you must)
#
#   # Token file locations (host-side)
#   ROOT_TOKEN_FILE=/custom/path/root_token
#   ROOT_TOKEN_JSON=/custom/path/root_token.json
#
# Important:
#   If your Vault server certificate does NOT include "vault_production_node" in its SANs/CN,
#   TLS hostname verification may fail. In that case either:
#     - Regenerate the cert with "vault_production_node" as a SAN (recommended), OR
#     - Set VAULT_SKIP_VERIFY_IN_CONTAINER=1 (not recommended, but available).

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="${PROJECT_ROOT:-$(cd "${SCRIPT_DIR}/../.." && pwd -P)}"

VAULT_CONTAINER="${VAULT_CONTAINER:-vault_production_node}"
ROLE_NAME="${ROLE_NAME:-fastapi_agent}"
OUT_DIR="${OUT_DIR:-${REPO_ROOT}/container_data/vault/approle/${ROLE_NAME}}"
ROTATE_SECRET_ID="${ROTATE_SECRET_ID:-1}"

# Optional: path to host-side env file to pull defaults from (PRIMARY_SERVER_FQDN, etc.)
ENV_FILE_DEFAULT="${REPO_ROOT}/.env"
ENV_FILE="${ENV_FILE:-${ENV_FILE_DEFAULT}}"

# If PRIMARY_SERVER_FQDN is not set in the environment, we will attempt to read it from ENV_FILE.
PRIMARY_SERVER_FQDN="${PRIMARY_SERVER_FQDN:-}"

# If not explicitly set, VAULT_ADDR_IN_CONTAINER will be derived at runtime as:
#   https://${PRIMARY_SERVER_FQDN:-$VAULT_CONTAINER}:8200
VAULT_ADDR_IN_CONTAINER="${VAULT_ADDR_IN_CONTAINER:-}"
VAULT_CACERT_IN_CONTAINER="${VAULT_CACERT_IN_CONTAINER:-/vault/certs/ca.crt}"
VAULT_SKIP_VERIFY_IN_CONTAINER="${VAULT_SKIP_VERIFY_IN_CONTAINER:-0}"

BOOTSTRAP_DIR_DEFAULT="${REPO_ROOT}/backend/app/security/configuration_files/vault/bootstrap"
ROOT_TOKEN_FILE="${ROOT_TOKEN_FILE:-${BOOTSTRAP_DIR_DEFAULT}/root_token}"
ROOT_TOKEN_JSON="${ROOT_TOKEN_JSON:-${BOOTSTRAP_DIR_DEFAULT}/root_token.json}"

need_bin() { command -v "$1" >/dev/null 2>&1 || { echo "ERROR: missing required binary: $1" >&2; exit 1; }; }
need_bin docker
need_bin sed
need_bin grep

trim() {
  local t="${1:-}"
  t="${t//$'\r'/}"
  t="${t//$'\n'/}"
  # shellcheck disable=SC2001
  t="$(echo -n "$t" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
  echo -n "$t"
}


load_primary_server_fqdn_from_env_file() {
  # If PRIMARY_SERVER_FQDN is already set, keep it.
  if [[ -n "${PRIMARY_SERVER_FQDN:-}" ]]; then
    return 0
  fi

  if [[ -f "${ENV_FILE}" && -s "${ENV_FILE}" ]]; then
    # Match: PRIMARY_SERVER_FQDN=...   (optionally prefixed with 'export')
    local line=""
    line="$(grep -E '^[[:space:]]*(export[[:space:]]+)?PRIMARY_SERVER_FQDN=' "${ENV_FILE}" | tail -n 1 || true)"
    if [[ -n "${line}" ]]; then
      local val=""
      val="${line#*=}"
      val="$(trim "${val}")"

      # Strip trailing inline comments for unquoted values (best-effort).
      if [[ "${val}" != \"* && "${val}" != \'* ]]; then
        val="${val%%#*}"
        val="$(trim "${val}")"
      fi

      # Strip wrapping quotes.
      if [[ "${val}" == \"*\" ]]; then
        val="${val#\"}"
        val="${val%\"}"
      fi
      if [[ "${val}" == \'*\' ]]; then
        val="${val#\'}"
        val="${val%\'}"
      fi

      val="$(trim "${val}")"
      if [[ -n "${val}" ]]; then
        PRIMARY_SERVER_FQDN="${val}"
        export PRIMARY_SERVER_FQDN
      fi
    fi
  fi
}


load_token() {
  # 1) plain token file
  if [[ -f "${ROOT_TOKEN_FILE}" && -s "${ROOT_TOKEN_FILE}" ]]; then
    local t
    t="$(trim "$(cat "${ROOT_TOKEN_FILE}")")"
    if [[ -n "${t}" ]]; then
      echo -n "${t}"
      return 0
    fi
  fi

  # 2) json token file (expects .root_token)
  if [[ -f "${ROOT_TOKEN_JSON}" && -s "${ROOT_TOKEN_JSON}" ]]; then
    need_bin jq
    local t=""
    t="$(jq -r '.root_token // empty' "${ROOT_TOKEN_JSON}" 2>/dev/null || true)"
    t="$(trim "${t}")"
    if [[ -n "${t}" ]]; then
      echo -n "${t}"
      return 0
    fi
  fi

  # 3) interactive prompt
  if [[ -t 0 ]]; then
    local prompted=""
    read -r -s -p "Enter Vault token (input hidden): " prompted
    echo >&2
    prompted="$(trim "${prompted}")"
    if [[ -n "${prompted}" ]]; then
      echo -n "${prompted}"
      return 0
    fi
  fi

  echo "ERROR: Could not obtain a Vault token." >&2
  echo "Looked for:" >&2
  echo "  - ${ROOT_TOKEN_FILE}" >&2
  echo "  - ${ROOT_TOKEN_JSON}" >&2
  echo "Run interactively or create one of the files above." >&2
  exit 1
}

container_running() {
  docker ps --format '{{.Names}}' | grep -qx "${VAULT_CONTAINER}"
}

maybe_fix_cacert_path_in_container() {
  # If the configured CA cert path doesn't exist in the container, attempt a safe fallback.
  if docker exec "${VAULT_CONTAINER}" sh -lc "test -f '${VAULT_CACERT_IN_CONTAINER}'" >/dev/null 2>&1; then
    return 0
  fi

  # Common fallback used in some layouts
  if docker exec "${VAULT_CONTAINER}" sh -lc "test -f '/vault/certs/cert.crt'" >/dev/null 2>&1; then
    echo "WARNING: VAULT_CACERT_IN_CONTAINER '${VAULT_CACERT_IN_CONTAINER}' not found in container; using /vault/certs/cert.crt" >&2
    VAULT_CACERT_IN_CONTAINER="/vault/certs/cert.crt"
    return 0
  fi

  echo "WARNING: Unable to verify CA cert path inside container." >&2
  echo "         CA:   ${VAULT_CACERT_IN_CONTAINER}" >&2
  echo "         You may need to set VAULT_CACERT_IN_CONTAINER explicitly." >&2
  return 0
}

vault_in_container() {
  # Runs `vault ...` inside the Vault container using docker exec.
  # All connectivity is forced to VAULT_ADDR_IN_CONTAINER.
  # If not explicitly set, VAULT_ADDR_IN_CONTAINER is derived from PRIMARY_SERVER_FQDN (ENV_FILE) or falls back to the container name.
  local -a exec_env
  exec_env=(
    -e "VAULT_TOKEN=${VAULT_TOKEN}"
    -e "VAULT_ADDR=${VAULT_ADDR_IN_CONTAINER}"
    -e "VAULT_CACERT=${VAULT_CACERT_IN_CONTAINER}"
  )

  if [[ "${VAULT_SKIP_VERIFY_IN_CONTAINER}" == "1" ]]; then
    exec_env+=(-e "VAULT_SKIP_VERIFY=true")
  fi

  docker exec "${exec_env[@]}" "${VAULT_CONTAINER}" vault "$@"
}

# Temp files must be global (EXIT trap runs after locals are out of scope, and set -u would error)
tmp_role_id=""
tmp_secret_id=""
cleanup() {
  [[ -n "${tmp_role_id:-}" ]] && rm -f -- "${tmp_role_id}" || true
  [[ -n "${tmp_secret_id:-}" ]] && rm -f -- "${tmp_secret_id}" || true
}
trap cleanup EXIT

main() {
  # Derive VAULT_ADDR_IN_CONTAINER if not explicitly provided.
  if [[ -z "${VAULT_ADDR_IN_CONTAINER:-}" ]]; then
    load_primary_server_fqdn_from_env_file
    local vault_host=""
    if [[ -n "${PRIMARY_SERVER_FQDN:-}" ]]; then
      vault_host="${PRIMARY_SERVER_FQDN}"
    else
      vault_host="${VAULT_CONTAINER}"
    fi
    VAULT_ADDR_IN_CONTAINER="https://${vault_host}:8200"
    if [[ -n "${PRIMARY_SERVER_FQDN:-}" ]]; then
      echo "INFO: Using PRIMARY_SERVER_FQDN from env file for Vault address: ${PRIMARY_SERVER_FQDN}" >&2
      echo "INFO: Env file: ${ENV_FILE}" >&2
    else
      echo "INFO: PRIMARY_SERVER_FQDN not found; falling back to Vault container name: ${VAULT_CONTAINER}" >&2
      echo "INFO: Env file tried: ${ENV_FILE}" >&2
    fi
    echo "INFO: VAULT_ADDR_IN_CONTAINER resolved to: ${VAULT_ADDR_IN_CONTAINER}" >&2
  fi

  if ! container_running; then
    echo "ERROR: Vault container '${VAULT_CONTAINER}' is not running." >&2
    echo "Start it, e.g.: docker compose -f docker-compose.prod.yml up -d vault_production_node" >&2
    exit 1
  fi

  maybe_fix_cacert_path_in_container

  VAULT_TOKEN="$(load_token)"
  export VAULT_TOKEN

  umask 077
  mkdir -p "${OUT_DIR}"
  chmod 700 "${OUT_DIR}"
  tmp_role_id="$(mktemp)"
  tmp_secret_id="$(mktemp)"

  # Verify Vault is reachable and unsealed (best-effort; gives better errors)
  if command -v jq >/dev/null 2>&1; then
    local status_json sealed
    status_json="$(vault_in_container status -format=json 2>/dev/null || true)"
    if [[ -n "${status_json}" ]]; then
      sealed="$(echo "${status_json}" | jq -r '.sealed // empty' 2>/dev/null || true)"
      if [[ "${sealed}" == "true" ]]; then
        echo "ERROR: Vault is sealed. Unseal it before exporting AppRole credentials." >&2
        exit 1
      fi
    else
      echo "WARNING: Unable to read Vault status as JSON. Continuing, but auth may fail." >&2
      echo "         Addr: ${VAULT_ADDR_IN_CONTAINER}" >&2
      echo "         CA:   ${VAULT_CACERT_IN_CONTAINER}" >&2
    fi
  else
    # jq not available; fall back to simple status
    if ! vault_in_container status >/dev/null 2>&1; then
      echo "WARNING: 'vault status' failed inside container '${VAULT_CONTAINER}'." >&2
      echo "         Addr: ${VAULT_ADDR_IN_CONTAINER}" >&2
      echo "         CA:   ${VAULT_CACERT_IN_CONTAINER}" >&2
    fi
  fi

  # Read role_id
  vault_in_container read -field=role_id "auth/approle/role/${ROLE_NAME}/role-id" > "${tmp_role_id}"
  if [[ ! -s "${tmp_role_id}" ]]; then
    echo "ERROR: role_id read returned empty output." >&2
    echo "       Path: auth/approle/role/${ROLE_NAME}/role-id" >&2
    exit 1
  fi

  # Generate or reuse secret_id
  if [[ "${ROTATE_SECRET_ID}" == "0" && -s "${OUT_DIR}/secret_id" ]]; then
    echo "Keeping existing secret_id at: ${OUT_DIR}/secret_id (ROTATE_SECRET_ID=0)"
  else
    vault_in_container write -field=secret_id -f "auth/approle/role/${ROLE_NAME}/secret-id" > "${tmp_secret_id}"
    if [[ ! -s "${tmp_secret_id}" ]]; then
      echo "ERROR: secret_id generation returned empty output." >&2
      echo "       Path: auth/approle/role/${ROLE_NAME}/secret-id" >&2
      exit 1
    fi
  fi

  mv -f "${tmp_role_id}" "${OUT_DIR}/role_id"
  chmod 600 "${OUT_DIR}/role_id"

  if [[ -s "${tmp_secret_id}" ]]; then
    mv -f "${tmp_secret_id}" "${OUT_DIR}/secret_id"
    chmod 600 "${OUT_DIR}/secret_id"
  fi

  echo "Wrote AppRole bootstrap files:"
  ls -l "${OUT_DIR}/role_id" "${OUT_DIR}/secret_id" 2>/dev/null || true
}

main "$@"
