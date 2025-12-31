#!/usr/bin/env bash
#------------------------------------------------------------------------------
# keycloak_approle_setup.sh
#
# Notes / How to run
# -----------------------------------------------------------------------------
# This script creates/updates the Vault policy + AppRole for the Keycloak Vault
# Agent and exports role_id/secret_id to the host for Docker volume mounts.
#
# IMPORTANT (read-only Vault container rootfs):
# - This script DOES NOT docker-cp anything into the Vault container.
# - It uses a short-lived Vault CLI container (hashicorp/vault) to talk to your
#   running Vault server over the Vault container's network namespace.
# - This avoids errors like: "container rootfs is marked read-only".
#
# Run (recommended):
#   cd "$HOME/NETWORK_TOOLS"
#   bash ./backend/build_scripts/keycloak_approle_setup.sh \
#     --ca-cert "./backend/app/security/configuration_files/vault/certs/ca.crt"
#
# Output files:
#   ./container_data/vault/approle/keycloak_agent/role_id
#   ./container_data/vault/approle/keycloak_agent/secret_id
#
# Requirements:
# - docker (host)
# - jq (host)
# - Vault server running in container (default name: vault_production_node)
#
# Security:
# - Uses an admin/root token only for admin operations (policy/AppRole/secret-id).
# - Prompts for token if bootstrap token file is missing/empty.
# - Writes role_id/secret_id with umask 077 and chmod 600; role dir chmod 700.
#------------------------------------------------------------------------------

set -euo pipefail
IFS=$' \t\n'

# ------------------------------- helpers -------------------------------------

log()  { printf '%s\n' "INFO: $*"; }
warn() { printf '%s\n' "WARN: $*" >&2; }
err()  { printf '%s\n' "ERROR: $*" >&2; exit 1; }

need_cmd() { command -v "$1" >/dev/null 2>&1 || err "Missing required command: $1"; }

usage() {
  cat <<'USAGE'
Usage: keycloak_approle_setup.sh [options]

Vault target:
  --vault-container <name>    Vault container name (default: vault_production_node)
  --vault-addr <url>          Vault address as seen FROM INSIDE that container's network namespace
                              (default: https://127.0.0.1:8200)
  --vault-cli-image <image>   Vault CLI image to use (default: hashicorp/vault:1.21.1)

TLS:
  --ca-cert <path>            Host path to Vault CA cert (recommended)
  --tls-skip-verify           Skip TLS verification (NOT recommended)

Role/policy:
  --role-name <name>          AppRole name (default: keycloak_agent)
  --policy-name <name>        Policy name (default: keycloak_agent)
  --policy-file <path>        Host path to policy HCL (default derived from repo)

Output:
  --role-dir <path>           Host directory to write role_id/secret_id
                              (default: $HOME/NETWORK_TOOLS/container_data/vault/approle/<role-name>)

Token:
  --token-file <path>         Host path to root/admin token file
                              (default: $HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token)
  --prompt-token              Always prompt for token (ignores --token-file)

Hardening knobs (optional):
  --token-ttl <dur>           (default: 1h)
  --token-max-ttl <dur>       (default: 24h)
  --secret-id-ttl <dur>       (default: 24h)
  --secret-id-num-uses <n>    (default: 0 => unlimited; consider setting to 1 for one-time bootstrap)
  --token-num-uses <n>        (default: 0 => unlimited)

Help:
  -h, --help

USAGE
}

# ------------------------------ defaults -------------------------------------

need_cmd docker
need_cmd jq

ROOT_DIR="${HOME}/NETWORK_TOOLS"

VAULT_CONTAINER="vault_production_node"
VAULT_ADDR="https://vault_production_node:8200"
VAULT_CLI_IMAGE="hashicorp/vault:1.21.1"

DEFAULT_CA_CERT="${ROOT_DIR}/backend/app/security/configuration_files/vault/certs/ca.crt"
CA_CERT="${DEFAULT_CA_CERT}"
TLS_SKIP_VERIFY=0

ROLE_NAME="keycloak_agent"
POLICY_NAME="keycloak_agent"
DEFAULT_POLICY_FILE="${ROOT_DIR}/backend/app/keycloak/vault_agent/keycloak_agent_policy.hcl"
POLICY_FILE="${DEFAULT_POLICY_FILE}"

TOKEN_FILE="${ROOT_DIR}/backend/app/security/configuration_files/vault/bootstrap/root_token"
PROMPT_TOKEN=0

TOKEN_TTL="1h"
TOKEN_MAX_TTL="24h"
SECRET_ID_TTL="24h"
SECRET_ID_NUM_USES="0"
TOKEN_NUM_USES="0"

ROLE_DIR=""

# ------------------------------ arg parse ------------------------------------

while [[ $# -gt 0 ]]; do
  case "$1" in
    --vault-container) VAULT_CONTAINER="${2:-}"; shift 2;;
    --vault-addr) VAULT_ADDR="${2:-}"; shift 2;;
    --vault-cli-image) VAULT_CLI_IMAGE="${2:-}"; shift 2;;

    --ca-cert) CA_CERT="${2:-}"; shift 2;;
    --tls-skip-verify) TLS_SKIP_VERIFY=1; shift 1;;

    --role-name) ROLE_NAME="${2:-}"; shift 2;;
    --policy-name) POLICY_NAME="${2:-}"; shift 2;;
    --policy-file) POLICY_FILE="${2:-}"; shift 2;;

    --role-dir) ROLE_DIR="${2:-}"; shift 2;;

    --token-file) TOKEN_FILE="${2:-}"; shift 2;;
    --prompt-token) PROMPT_TOKEN=1; shift 1;;

    --token-ttl) TOKEN_TTL="${2:-}"; shift 2;;
    --token-max-ttl) TOKEN_MAX_TTL="${2:-}"; shift 2;;
    --secret-id-ttl) SECRET_ID_TTL="${2:-}"; shift 2;;
    --secret-id-num-uses) SECRET_ID_NUM_USES="${2:-}"; shift 2;;
    --token-num-uses) TOKEN_NUM_USES="${2:-}"; shift 2;;

    -h|--help) usage; exit 0;;
    *) err "Unknown argument: $1 (use --help)";;
  esac
done

if [[ -z "${ROLE_DIR}" ]]; then
  ROLE_DIR="${ROOT_DIR}/container_data/vault/approle/${ROLE_NAME}"
fi

# ------------------------------ preflight ------------------------------------

if ! docker inspect "${VAULT_CONTAINER}" >/dev/null 2>&1; then
  err "Vault container not found: ${VAULT_CONTAINER}"
fi

if [[ "$(docker inspect -f '{{.State.Running}}' "${VAULT_CONTAINER}")" != "true" ]]; then
  err "Vault container is not running: ${VAULT_CONTAINER}"
fi

[[ -f "${POLICY_FILE}" ]] || err "Policy file not found: ${POLICY_FILE}"

if [[ "${TLS_SKIP_VERIFY}" -eq 0 ]]; then
  [[ -f "${CA_CERT}" ]] || err "CA cert not found: ${CA_CERT}. Provide --ca-cert or use --tls-skip-verify (not recommended)."
fi

# --------------------------- token acquisition --------------------------------

VAULT_TOKEN=""

token_from_file() {
  [[ -f "${TOKEN_FILE}" ]] || return 1
  VAULT_TOKEN="$(tr -d '\r\n' < "${TOKEN_FILE}" || true)"
  [[ -n "${VAULT_TOKEN}" ]] || return 2
  return 0
}

token_prompt() {
  local t=""
  read -r -s -p "Vault admin/root token (input hidden): " t
  echo ""
  [[ -n "${t}" ]] || return 1
  VAULT_TOKEN="${t}"
  return 0
}

if [[ "${PROMPT_TOKEN}" -eq 1 ]]; then
  token_prompt || err "No token provided."
else
  if ! token_from_file; then
    warn "Token file not found/empty: ${TOKEN_FILE}"
    token_prompt || err "No token provided."
  fi
fi

# ----------------------------- vault cli runner -------------------------------

# Run a Vault CLI command in a short-lived container that shares the Vault server's
# network namespace. This avoids writing into the Vault server container filesystem.
vault_cli() {
  local cmd="$1"

  if [[ "${TLS_SKIP_VERIFY}" -eq 1 ]]; then
    docker run --rm \
      --network "container:${VAULT_CONTAINER}" \
      -e VAULT_ADDR="${VAULT_ADDR}" \
      -e VAULT_SKIP_VERIFY="1" \
      -e VAULT_TOKEN="${VAULT_TOKEN}" \
      "${VAULT_CLI_IMAGE}" sh -lc "${cmd}"
  else
    docker run --rm \
      --network "container:${VAULT_CONTAINER}" \
      -v "${CA_CERT}:/tmp/vault_ca.crt:ro" \
      -e VAULT_ADDR="${VAULT_ADDR}" \
      -e VAULT_CACERT="/tmp/vault_ca.crt" \
      -e VAULT_TOKEN="${VAULT_TOKEN}" \
      "${VAULT_CLI_IMAGE}" sh -lc "${cmd}"
  fi
}

# Validate token early (fail fast)
if ! vault_cli "vault token lookup >/dev/null 2>&1"; then
  err "Vault token lookup failed. Token invalid, expired, or VAULT_ADDR/CA mismatch."
fi

log "Vault connectivity OK (via CLI container) using VAULT_ADDR='${VAULT_ADDR}'."

# ------------------------ enable approle if needed ----------------------------

if ! vault_cli "vault auth list" | grep -qE '^approle/'; then
  log "AppRole auth not enabled; enabling it now."
  vault_cli "vault auth enable approle" >/dev/null
else
  log "AppRole auth already enabled."
fi

# --------------------------- write policy (stdin) -----------------------------

log "Writing policy '${POLICY_NAME}' from: ${POLICY_FILE}"
# Use '-' to read policy from stdin; no file copies into Vault container.
if [[ "${TLS_SKIP_VERIFY}" -eq 1 ]]; then
  cat "${POLICY_FILE}" | docker run --rm -i \
    --network "container:${VAULT_CONTAINER}" \
    -e VAULT_ADDR="${VAULT_ADDR}" \
    -e VAULT_SKIP_VERIFY="1" \
    -e VAULT_TOKEN="${VAULT_TOKEN}" \
    "${VAULT_CLI_IMAGE}" sh -lc "vault policy write '${POLICY_NAME}' -"
else
  cat "${POLICY_FILE}" | docker run --rm -i \
    --network "container:${VAULT_CONTAINER}" \
    -v "${CA_CERT}:/tmp/vault_ca.crt:ro" \
    -e VAULT_ADDR="${VAULT_ADDR}" \
    -e VAULT_CACERT="/tmp/vault_ca.crt" \
    -e VAULT_TOKEN="${VAULT_TOKEN}" \
    "${VAULT_CLI_IMAGE}" sh -lc "vault policy write '${POLICY_NAME}' -"
fi

# --------------------------- write role ---------------------------------------

log "Creating/updating AppRole '${ROLE_NAME}' (policy: ${POLICY_NAME})"
vault_cli "\
  vault write auth/approle/role/${ROLE_NAME} \
    token_policies='${POLICY_NAME}' \
    token_ttl='${TOKEN_TTL}' \
    token_max_ttl='${TOKEN_MAX_TTL}' \
    token_num_uses='${TOKEN_NUM_USES}' \
    secret_id_ttl='${SECRET_ID_TTL}' \
    secret_id_num_uses='${SECRET_ID_NUM_USES}' \
    bind_secret_id='true' \
" >/dev/null

# ---------------------- export role_id / secret_id ----------------------------

mkdir -p "${ROLE_DIR}"
chmod 700 "${ROLE_DIR}" || true

log "Exporting role_id + new secret_id to: ${ROLE_DIR}"

ROLE_ID_JSON="$(vault_cli "vault read -format=json auth/approle/role/${ROLE_NAME}/role-id")"
ROLE_ID="$(printf '%s' "${ROLE_ID_JSON}" | jq -r '.data.role_id // empty')"
[[ -n "${ROLE_ID}" ]] || err "Failed to parse role_id from Vault output."

SECRET_ID_JSON="$(vault_cli "vault write -format=json -f auth/approle/role/${ROLE_NAME}/secret-id")"
SECRET_ID="$(printf '%s' "${SECRET_ID_JSON}" | jq -r '.data.secret_id // empty')"
[[ -n "${SECRET_ID}" ]] || err "Failed to parse secret_id from Vault output."

umask 077
printf '%s\n' "${ROLE_ID}" > "${ROLE_DIR}/role_id"
printf '%s\n' "${SECRET_ID}" > "${ROLE_DIR}/secret_id"
chmod 600 "${ROLE_DIR}/role_id" "${ROLE_DIR}/secret_id" || true

log "Done."
log "Next: docker compose -f docker-compose.prod.yml -f docker-compose.keycloak.prod.yml up -d vault_agent_keycloak"
