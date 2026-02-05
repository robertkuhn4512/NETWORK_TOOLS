#!/usr/bin/env bash
set -euo pipefail

# -----------------------------------------------------------------------------
# approle_setup_all.sh
#
# Notes / How to run:
#   1) Ensure your Vault container is running (default: vault_production_node)
#   2) Prefer a token file:
#        chmod 0400 /path/to/approle_minter_token
#        ./backend/build_scripts/approle_setup_all.sh bootstrap --token-file /path/to/approle_minter_token
#
#   3) Rotate SecretIDs (cron/pipeline friendly):
#        ./backend/build_scripts/approle_setup_all.sh rotate --token-file /path/to/approle_minter_token
#
#   4) Non-interactive pipelines:
#        export VAULT_TOKEN="..."   # best via CI secret store
#        ./backend/build_scripts/approle_setup_all.sh rotate --non-interactive
#
#      OR pipe token via stdin:
#        printf '%s' "$VAULT_TOKEN" | ./backend/build_scripts/approle_setup_all.sh rotate --token-stdin
#
# Defaults:
#   - Roles: frontend_agent fastapi_agent keycloak_agent postgres_pgadmin_agent
#   - Writes to: <repo>/container_data/vault/approle/<role>/{role_id,secret_id}
#
# Exit codes:
#   2  usage / args error
#   10 missing prereqs (docker/vault container)
#   20 auth/token error
#   30 vault command failure
# -----------------------------------------------------------------------------

SCRIPT_NAME="$(basename "$0")"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Defaults (override via flags)
VAULT_CONTAINER="vault_production_node"
OUT_BASE="${REPO_ROOT}/container_data/vault/approle"
MODE=""
TOKEN_FILE=""                  # optional
TOKEN_STDIN="0"                # 1 => read token from stdin
NON_INTERACTIVE="0"            # 1 => no prompting (pipeline mode)
RESTART_AGENTS="0"             # 1 => restart vault_agent_* containers
ROTATE_SECRET_ID="1"           # bootstrap honors; rotate forces 1
QUIET="0"

# Default roles
ROLES=("frontend_agent" "fastapi_agent" "keycloak_agent" "postgres_pgadmin_agent")

log() {
  [[ "${QUIET}" == "1" ]] && return 0
  echo "INFO: $*" >&2
}
warn() { echo "WARN: $*" >&2; }
err()  { echo "ERROR: $*" >&2; }

usage() {
  cat >&2 <<EOF
Usage:
  ${SCRIPT_NAME} <bootstrap|rotate> [options]

Options:
  --vault-container NAME      Vault container name (default: ${VAULT_CONTAINER})
  --out-base PATH             Output base dir (default: ${OUT_BASE})
  --roles "r1 r2 ..."         Space-delimited role list (default: ${ROLES[*]})
  --token-file PATH           Read Vault token from file (preferred)
  --token-stdin               Read Vault token from stdin (pipeline safe)
  --non-interactive           Fail instead of prompting for token
  --restart-agents            Restart vault_agent_* containers after writing files
  --keep-secret-on-bootstrap  On bootstrap, do NOT mint new SecretID if one exists
  --quiet                     Reduce logs
  -h, --help                  Show help

Examples:
  ${SCRIPT_NAME} bootstrap --token-file backend/app/security/configuration_files/vault/bootstrap/approle_minter_token
  ${SCRIPT_NAME} rotate --token-file /run/user/1000/network_tools/approle_minter_token
  printf '%s' "\$VAULT_TOKEN" | ${SCRIPT_NAME} rotate --token-stdin --non-interactive
EOF
  exit 2
}

need_bin() {
  command -v "$1" >/dev/null 2>&1 || { err "missing required binary: $1"; exit 10; }
}

is_tty() {
  [[ -t 0 && -t 1 ]]
}

trim() {
  local s="${1:-}"
  s="${s//$'\r'/}"
  s="${s//$'\n'/}"
  # shellcheck disable=SC2001
  s="$(echo -n "$s" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
  echo -n "$s"
}

container_running() {
  docker ps --format '{{.Names}}' | grep -qx "${VAULT_CONTAINER}"
}

vault_in_container() {
  # Use VAULT_TOKEN env set in caller
  docker exec -e "VAULT_TOKEN=${VAULT_TOKEN}" "${VAULT_CONTAINER}" vault "$@"
}

read_token_from_file() {
  local f="$1"
  [[ -f "$f" ]] || return 1
  [[ -s "$f" ]] || return 1
  local t
  t="$(trim "$(cat "$f")")"
  [[ -n "$t" ]] || return 1
  echo -n "$t"
  return 0
}

read_token_from_stdin() {
  # Reads *all* stdin, trims whitespace
  local t
  t="$(cat - 2>/dev/null || true)"
  t="$(trim "$t")"
  [[ -n "$t" ]] || return 1
  echo -n "$t"
  return 0
}

prompt_token_securely() {
  local t=""
  # Prompt on stderr so stdout remains clean for pipelines
  read -r -s -p "Enter Vault token (input hidden): " t >&2
  echo >&2
  t="$(trim "$t")"
  [[ -n "$t" ]] || return 1
  echo -n "$t"
  return 0
}

load_token() {
  # 1) VAULT_TOKEN env (best for pipelines)
  if [[ -n "${VAULT_TOKEN:-}" ]]; then
    echo -n "$(trim "${VAULT_TOKEN}")"
    return 0
  fi

  # 2) token file
  if [[ -n "${TOKEN_FILE}" ]]; then
    if t="$(read_token_from_file "${TOKEN_FILE}")"; then
      echo -n "$t"
      return 0
    fi
    warn "token file not present/usable: ${TOKEN_FILE}"
  fi

  # 3) stdin token
  if [[ "${TOKEN_STDIN}" == "1" ]]; then
    if t="$(read_token_from_stdin)"; then
      echo -n "$t"
      return 0
    fi
    err "--token-stdin set but no token was provided on stdin"
    exit 20
  fi

  # 4) interactive prompt (only if allowed)
  if [[ "${NON_INTERACTIVE}" == "1" ]]; then
    err "No Vault token available. Provide VAULT_TOKEN, --token-file, or --token-stdin (non-interactive)."
    exit 20
  fi

  if is_tty; then
    if t="$(prompt_token_securely)"; then
      echo -n "$t"
      return 0
    fi
    err "Token prompt returned empty input."
    exit 20
  fi

  err "No Vault token available and not running in an interactive TTY."
  err "Provide VAULT_TOKEN, --token-file, or use --token-stdin."
  exit 20
}

ensure_out_dir() {
  local d="$1"
  umask 077
  mkdir -p "$d"
  chmod 700 "$d" || true
}

atomic_write_file() {
  # atomic_write_file <dest_path> <content_file>
  local dest="$1"
  local src="$2"
  local dir
  dir="$(dirname "$dest")"
  ensure_out_dir "$dir"

  # Create temp file in same directory to ensure atomic mv
  local tmp
  tmp="$(mktemp "${dir}/.tmp.$(basename "$dest").XXXXXX")"
  chmod 600 "$tmp"
  cat "$src" > "$tmp"
  mv -f "$tmp" "$dest"
  chmod 600 "$dest" || true
}

write_role_files() {
  local role_name="$1"
  local out_dir="${OUT_BASE}/${role_name}"

  ensure_out_dir "$out_dir"

  local role_id_file secret_id_file
  role_id_file="${out_dir}/role_id"
  secret_id_file="${out_dir}/secret_id"

  local tmp_role_id tmp_secret_id
  tmp_role_id="$(mktemp)"
  tmp_secret_id="$(mktemp)"
  trap 'rm -f "${tmp_role_id}" "${tmp_secret_id}" 2>/dev/null || true' RETURN

  # role-id
  if ! vault_in_container read -field=role_id "auth/approle/role/${role_name}/role-id" > "${tmp_role_id}" 2>/dev/null; then
    err "Failed to read role-id for '${role_name}'. Does the AppRole exist?"
    exit 30
  fi
  if [[ ! -s "${tmp_role_id}" ]]; then
    err "role-id empty for '${role_name}'"
    exit 30
  fi
  atomic_write_file "${role_id_file}" "${tmp_role_id}"

  # secret-id
  if [[ "${ROTATE_SECRET_ID}" == "0" && -s "${secret_id_file}" ]]; then
    log "${role_name}: keeping existing secret_id (bootstrap + --keep-secret-on-bootstrap)"
  else
    if ! vault_in_container write -field=secret_id -f "auth/approle/role/${role_name}/secret-id" > "${tmp_secret_id}" 2>/dev/null; then
      err "Failed to mint secret-id for '${role_name}'"
      exit 30
    fi
    if [[ ! -s "${tmp_secret_id}" ]]; then
      err "secret-id empty for '${role_name}'"
      exit 30
    fi
    atomic_write_file "${secret_id_file}" "${tmp_secret_id}"
  fi

  log "wrote: ${out_dir}/role_id and ${out_dir}/secret_id"
}

restart_agents_if_requested() {
  [[ "${RESTART_AGENTS}" == "1" ]] || return 0

  local agents=("vault_agent_frontend" "vault_agent_fastapi" "vault_agent_keycloak" "vault_agent_postgres_pgadmin")

  log "Restarting vault agents..."
  for c in "${agents[@]}"; do
    if docker ps --format '{{.Names}}' | grep -qx "${c}"; then
      docker restart "${c}" >/dev/null
      log "  restarted: ${c}"
    else
      warn "  not running: ${c}"
    fi
  done
}

validate_vault_access() {
  # quick sanity check: vault status
  if ! vault_in_container status >/dev/null 2>&1; then
    err "Vault CLI inside container '${VAULT_CONTAINER}' failed 'vault status'."
    err "Check container name, Vault readiness, and VAULT_TOKEN permissions."
    exit 30
  fi
}

parse_args() {
  [[ $# -ge 1 ]] || usage
  MODE="$1"
  shift

  case "${MODE}" in
    bootstrap|rotate) ;;
    -h|--help) usage ;;
    *) usage ;;
  esac

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --vault-container)
        [[ $# -ge 2 ]] || usage
        VAULT_CONTAINER="$2"; shift 2
        ;;
      --out-base)
        [[ $# -ge 2 ]] || usage
        OUT_BASE="$2"; shift 2
        ;;
      --roles)
        [[ $# -ge 2 ]] || usage
        # shellcheck disable=SC2206
        ROLES=($2); shift 2
        ;;
      --token-file)
        [[ $# -ge 2 ]] || usage
        TOKEN_FILE="$2"; shift 2
        ;;
      --token-stdin)
        TOKEN_STDIN="1"; shift
        ;;
      --non-interactive)
        NON_INTERACTIVE="1"; shift
        ;;
      --restart-agents)
        RESTART_AGENTS="1"; shift
        ;;
      --keep-secret-on-bootstrap)
        ROTATE_SECRET_ID="0"; shift
        ;;
      --quiet)
        QUIET="1"; shift
        ;;
      -h|--help)
        usage
        ;;
      *)
        err "Unknown argument: $1"
        usage
        ;;
    esac
  done
}

main() {
  need_bin docker
  need_bin sed
  need_bin grep

  parse_args "$@"

  if ! container_running; then
    err "Vault container '${VAULT_CONTAINER}' is not running."
    exit 10
  fi

  # rotate always rotates secret IDs
  if [[ "${MODE}" == "rotate" ]]; then
    ROTATE_SECRET_ID="1"
  fi

  # Load token (secure prompt if needed/allowed)
  VAULT_TOKEN="$(load_token)"
  export VAULT_TOKEN

  validate_vault_access

  # Ensure output base exists
  ensure_out_dir "${OUT_BASE}"

  for r in "${ROLES[@]}"; do
    write_role_files "${r}"
  done

  restart_agents_if_requested

  log "Done (${MODE})."
}

main "$@"
