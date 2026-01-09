#!/usr/bin/env bash
# vault_first_time_init_only_rootless.sh (env + seamless TLS fallback v3)
#
# NOTES
#   Purpose:
#     Rootless-first bootstrap for Vault in NETWORK_TOOLS:
#       1) Bring up the Vault container via docker compose (no sudo)
#       2) Initialize Vault if not initialized
#       3) Unseal Vault if sealed
#
#   How to run:
#     # Recommended (loads .env automatically; derives vault.<PRIMARY_SERVER_FQDN> when available):
#     bash ./backend/build_scripts/vault_first_time_init_only_rootless.sh \
#       --ca-cert "$HOME/NETWORK_TOOLS/backend/app/nginx/certs/ca.crt" \
#       --init-shares 5 --init-threshold 3
#
#     # If you want to force a specific address:
#     #   --vault-addr "https://vault.networkengineertools.com:8200"
#
#     # If your .env is not in the compose directory:
#     #   --env-file "/path/to/.env"
#
#   Caveats / gotchas:
#     - TLS hostname validation is strict. The Vault server certificate must match the host used in VAULT_ADDR.
#       This script will prefer vault.<PRIMARY_SERVER_FQDN> for TLS/SNI (from .env) and will fall back to the
#       docker service name (vault_production_node) only when the preferred path fails.
#     - If the cert does NOT include the docker service name (usual), ensure PRIMARY_SERVER_FQDN is set and
#       the cert includes vault.<PRIMARY_SERVER_FQDN> in SANs.
#     - When using curl --resolve mapping to 127.0.0.1, the Vault container must publish 8200 to the host.
#       If you remove published ports, use --resolve-ip (container IP) or run this script from a container on
#       the same docker network.
#     - --ca-cert must point at the CA that signed Vault's server certificate. If you standardize on the nginx
#       cert generator, copy/sync its ca.crt/cert.crt/cert.key into Vault's cert directory and use nginx/ca.crt here.
#
#
#     # Disable AppRole + policy bootstrap (optional):
#     #   --no-setup-postgres-pgadmin-approle
#
#     Optional (first-time init convenience; AppRole + ACL bootstrap for Vault Agents):
#
#       Postgres/pgAdmin Vault Agent:
#         - Enable AppRole auth (if not already enabled) unless --no-setup-postgres-pgadmin-approle
#         - Create a baseline ACL policy (default: postgres_pgadmin_read)
#         - Create a baseline AppRole role bound to that policy (default: postgres_pgadmin_agent)
#
#       Keycloak Vault Agent:
#         - Enable AppRole auth (if not already enabled) unless --no-setup-keycloak-approle
#         - Create a baseline ACL policy (default: keycloak_read)
#         - Create a baseline AppRole role bound to that policy (default: keycloak_agent)
#
#       FastAPI Vault Agent:
#         - Enable AppRole auth (if not already enabled) unless --no-setup-fastapi-approle
#         - Create a baseline ACL policy (default: fastapi_read)
#         - Create a baseline AppRole role bound to that policy (default: fastapi_agent)
#
#     This script still intentionally does NOT:
#       - Enable secrets engines (KV, etc.)
#       - Seed/overwrite KV secrets (use the KV seed/bootstrap scripts)
#       - Export role_id / secret_id files to the host (use export_approle_from_vault_container.sh)
#
#     Optional (recommended hardening):
#       - Enable a file audit device writing to /vault/logs/audit.log (disable with --no-enable-audit)
#
#   Security:
#     This script writes unseal keys + root token to disk (0600) for the bootstrap phase.
#     Move them to your secure storage immediately, or delete once you have your operational model.
#
#
#   Caveats / TLS notes:
#     - This script loads <compose-dir>/.env by default (or --env-file PATH).
#     - If PRIMARY_SERVER_FQDN is set, the script prefers to verify TLS using:
#         https://vault.<PRIMARY_SERVER_FQDN>:8200
#       even if DNS is not ready, by using curl --resolve to map that name to an IP.
#     - By default it maps to 127.0.0.1 (requires Vault port 8200 published on the host).
#       If that fails, it automatically falls back to the Vault container IP via docker inspect.
#     - If you only probe https://vault_production_node:8200 from the host, TLS will usually fail
#       because the cert SAN does not include the container name. The resolve/SNI approach avoids that.
#
# HOW TO RUN
#   cd "$HOME/NETWORK_TOOLS"
#
#   # Recommended (loads .env automatically; uses vault.<PRIMARY_SERVER_FQDN> for TLS/SNI when available):
#   bash backend/build_scripts/vault_first_time_init_only_rootless.sh \
#     --ca-cert "$HOME/NETWORK_TOOLS/backend/app/nginx/certs/ca.crt" \
#     --init-shares 5 --init-threshold 3
#
#   # If needed, point at a specific Vault address explicitly:
#   #   --vault-addr "https://vault.${PRIMARY_SERVER_FQDN}:8200"
#
#   # If .env is not located next to your compose file:
#   #   --env-file "/path/to/.env"
#
# REQUIREMENTS
#   - docker (rootless context)
#   - docker compose (plugin)
#   - bash, curl, jq
#
# -------------------------------------------------------------------
# Logging helpers (must be defined before first use)
# -------------------------------------------------------------------
log()  { echo "INFO: $*" >&2; }
warn() { echo "INFO: WARN: $*" >&2; }
err()  { echo "ERROR: $*" >&2; }
die()  { err "$*"; exit 1; }

# DEBUG is intentionally referenced safely because this script runs with `set -u`.
dbg()  { [[ "${DEBUG:-0}" == "1" ]] && echo "DEBUG: $*" >&2 || true; }

set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage:
  vault_first_time_init_only_rootless.sh [--vault-addr URL] [options]

Vault address:
  --vault-addr URL                Vault address (e.g., https://vault.networkengineertools.com:8200)
                                 If omitted, the script will try .env (VAULT_ADDR, PRIMARY_VAULT_SERVER_FQDN_FULL,
                                 PRIMARY_SERVER_FQDN) and finally fall back to https://vault_production_node:8200.

Optional TLS:
  --namespace NS                  Vault namespace (Enterprise/HCP)
  --ca-cert PATH                  CA bundle PEM for HTTPS verification (recommended)

Env defaults:
  --env-file PATH               Load KEY=VALUE defaults from a .env file.
                                 Default: <compose-dir>/.env (where <compose-dir> is the directory containing the compose file).
  --no-env-file                 Do not load any env file.
  --env-override                Allow the env file to override already-set (non-empty) variables.

Hostname / SNI helpers:
  --primary-server-fqdn FQDN       Used to derive vault.<FQDN> for TLS/SNI when --vault-addr is a container/localhost
                                  (default: $PRIMARY_SERVER_FQDN env var, if set)
  --vault-public-host HOST         Explicit host to use for TLS/SNI (overrides vault.<PRIMARY_SERVER_FQDN>)
  --resolve-ip IP                 IP to map HOST:PORT to when using curl --resolve (default: 127.0.0.1)
  --no-auto-resolve-public-host    Disable the automatic vault.<FQDN> + --resolve behavior

Init parameters:
  --init-shares N                 Default 5
  --init-threshold N              Default 3

Bootstrap output:
  --bootstrap-dir DIR             Default: $HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap
  --unseal-keys-file PATH         Default: <bootstrap-dir>/unseal_keys.json   (written as pretty JSON)
  --root-token-file PATH          Default: <bootstrap-dir>/root_token         (plain token)
  --root-token-json-file PATH     Default: <bootstrap-dir>/root_token.json    (pretty JSON)

Compose behavior (rootless; no sudo):
  --compose-project NAME          Default: network_tools
  --compose-file PATH             Default: $HOME/NETWORK_TOOLS/docker-compose.prod.yml
  --service-name NAME             Default: vault_production_node
  --compose-build                 Add --build to compose up

Unseal behavior:
  --no-unseal                     Skip unseal step (init only)

Audit logging (recommended):
  --no-enable-audit              Skip enabling the file audit device
  --audit-path NAME               Audit device mount path (default: file)
  --audit-file-path PATH          Audit log file path inside Vault container (default: /vault/logs/audit.log)
  --audit-description TEXT        Optional description for the audit device
  --audit-token-file PATH         Token file to use for audit enable/list (default: <root-token-file>)

AppRole + ACL bootstrap (first-time convenience; postgres/pgAdmin Vault Agent):
  --no-setup-postgres-pgadmin-approle   Skip enabling AppRole + creating the postgres/pgAdmin policy/role
  --force-postgres-pgadmin-approle      Re-write the policy/role even if they already exist
  --postgres-pgadmin-role-name NAME     Default: postgres_pgadmin_agent
  --postgres-pgadmin-policy-name NAME   Default: postgres_pgadmin_read
  --postgres-pgadmin-kv-mount NAME      Default: app_network_tools_secrets
  --postgres-pgadmin-kv-version 1|2     Default: 2

AppRole + ACL bootstrap (first-time convenience; Keycloak Vault Agent):
  --no-setup-keycloak-approle            Skip enabling AppRole + creating the Keycloak policy/role
  --force-keycloak-approle               Re-write the policy/role even if they already exist
  --keycloak-role-name NAME              Default: keycloak_agent
  --keycloak-policy-name NAME            Default: keycloak_read
  --keycloak-kv-mount NAME               Default: app_network_tools_secrets
  --keycloak-kv-version 1|2              Default: 2

AppRole + ACL bootstrap (first-time convenience; FastAPI Vault Agent):
  --no-setup-fastapi-approle             Skip enabling AppRole + creating the FastAPI policy/role
  --force-fastapi-approle                Re-write the policy/role even if they already exist
  --fastapi-role-name NAME               Default: fastapi_agent
  --fastapi-policy-name NAME             Default: fastapi_read
  --fastapi-kv-mount NAME                Default: app_network_tools_secrets
  --fastapi-kv-version 1|2               Default: 2


Pretty output:
  --no-pretty-output              Disable pretty JSON formatting (writes unseal_keys.json compact)
  --no-print-artifact-contents    Do NOT print the contents of the key/token JSON files to the terminal

Debug:
  --debug                         Verbose flow logging
  --debug-http                    curl -v

EOF
}

# -------------------- Small helpers (must be defined before first use) --------------------


# -------------------- Defaults --------------------
VAULT_ADDR=""
VAULT_NAMESPACE="${VAULT_NAMESPACE:-}"
CA_CERT=""

ENV_FILE=""
LOAD_ENV_FILE=1
ENV_OVERRIDE=0

PRIMARY_SERVER_FQDN_ARG=""
VAULT_PUBLIC_HOST=""
RESOLVE_IP="127.0.0.1"
AUTO_RESOLVE_PUBLIC_HOST=1
CURL_RESOLVE_ARGS=()
LAST_CURL_WARN=""
LAST_CURL_RC=0


INIT_SHARES=5
INIT_THRESHOLD=3

BOOTSTRAP_DIR="${BOOTSTRAP_DIR:-$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap}"
UNSEAL_KEYS_FILE=""
ROOT_TOKEN_FILE=""
ROOT_TOKEN_JSON_FILE=""

COMPOSE_PROJECT="network_tools"
COMPOSE_FILE_DEFAULT="$HOME/NETWORK_TOOLS/docker-compose.prod.yml"
COMPOSE_FILE=""
SERVICE_NAME="vault_production_node"
COMPOSE_BUILD=0

NO_UNSEAL=0
PRETTY_OUTPUT=1
PRINT_ARTIFACT_CONTENTS=1
VERBOSE=0
HTTP_DEBUG=0

# Audit logging (file device)
ENABLE_AUDIT=1
AUDIT_PATH="file"
AUDIT_FILE_PATH="/vault/logs/audit.log"
AUDIT_DESCRIPTION=""
AUDIT_TOKEN_FILE=""

# AppRole + ACL bootstrap (postgres/pgAdmin Vault Agent)
# AppRole + ACL bootstrap (Keycloak Vault Agent)
SETUP_KEYCLOAK_APPROLE=1
FORCE_KEYCLOAK_APPROLE=0
KEYCLOAK_ROLE_NAME="keycloak_agent"
KEYCLOAK_POLICY_NAME="keycloak_read"
KEYCLOAK_KV_MOUNT="app_network_tools_secrets"
KEYCLOAK_KV_VERSION="2"
KEYCLOAK_TOKEN_TTL="1h"
KEYCLOAK_TOKEN_MAX_TTL="4h"
KEYCLOAK_SECRET_ID_TTL="24h"
KEYCLOAK_SECRET_ID_NUM_USES="1"
KEYCLOAK_SETUP_DONE=0

SETUP_POSTGRES_PGADMIN_APPROLE=1
FORCE_POSTGRES_PGADMIN_APPROLE=0
POSTGRES_PGADMIN_ROLE_NAME="postgres_pgadmin_agent"
POSTGRES_PGADMIN_POLICY_NAME="postgres_pgadmin_read"
POSTGRES_PGADMIN_KV_MOUNT="app_network_tools_secrets"
POSTGRES_PGADMIN_KV_VERSION="2"
POSTGRES_PGADMIN_TOKEN_TTL="1h"
POSTGRES_PGADMIN_TOKEN_MAX_TTL="4h"
POSTGRES_PGADMIN_SECRET_ID_TTL="24h"
POSTGRES_PGADMIN_SECRET_ID_NUM_USES="1"
POSTGRES_PGADMIN_SETUP_DONE=0
# AppRole + ACL bootstrap (FastAPI Vault Agent)
SETUP_FASTAPI_APPROLE=1
FORCE_FASTAPI_APPROLE=0
FASTAPI_ROLE_NAME="fastapi_agent"
FASTAPI_POLICY_NAME="fastapi_read"
FASTAPI_KV_MOUNT="app_network_tools_secrets"
FASTAPI_KV_VERSION="2"
FASTAPI_TOKEN_TTL="1h"
FASTAPI_TOKEN_MAX_TTL="4h"
FASTAPI_SECRET_ID_TTL="24h"
FASTAPI_SECRET_ID_NUM_USES="1"
FASTAPI_SETUP_DONE=0


# -------------------- Parser helpers --------------------
_require_val() { [[ -n "${2-}" && "${2:0:1}" != "-" ]] || { echo "ERROR: Missing value for $1" >&2; exit 2; }; }
_set_opt() {
  local opt="$1" tok="$2" next="${3-}" var="$4"
  if [[ "$tok" == "$opt="* ]]; then printf -v "$var" '%s' "${tok#*=}"
  else _require_val "$opt" "$next"; printf -v "$var" '%s' "$next"; return 1; fi; return 0;
}

load_env_file() {
  # Minimal .env loader:
  # - reads KEY=VALUE lines
  # - ignores blanks and lines starting with '#'
  # - strips surrounding single/double quotes
  # - by default only fills currently-empty (non-set) variables; with override, replaces non-empty vars too
  local file="$1"
  local override="${2:-0}"
  [[ -n "$file" && -r "$file" ]] || return 0

  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"

    # trim leading/trailing whitespace
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"

    [[ -z "$line" ]] && continue
    [[ "$line" == \#* ]] && continue
    [[ "$line" == export\ * ]] && line="${line#export }"
    [[ "$line" == *"="* ]] || continue

    local key="${line%%=*}"
    local val="${line#*=}"

    # trim whitespace around key/val
    key="${key#"${key%%[![:space:]]*}"}"
    key="${key%"${key##*[![:space:]]}"}"
    [[ "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || continue

    val="${val#"${val%%[![:space:]]*}"}"
    val="${val%"${val##*[![:space:]]}"}"

    # strip surrounding quotes
    if [[ ${#val} -ge 2 && "$val" == \"*\" && "$val" == *\" ]]; then
      val="${val:1:${#val}-2}"
    elif [[ ${#val} -ge 2 && "$val" == \'*\' && "$val" == *\' ]]; then
      val="${val:1:${#val}-2}"
    fi

    # If not overriding, only fill empty/non-set vars
    if (( ! override )); then
      if [[ -n "${!key-}" ]]; then
        continue
      fi
    fi

    printf -v "$key" '%s' "$val"
    export "$key"
  done < "$file"
}


# -------------------- Parse args --------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;

    --vault-addr|--vault-addr=*)           if _set_opt --vault-addr "$1" "${2-}" VAULT_ADDR; then shift 1; else shift 2; fi ;;
    --namespace|--namespace=*)             if _set_opt --namespace "$1" "${2-}" VAULT_NAMESPACE; then shift 1; else shift 2; fi ;;
    --ca-cert|--ca-cert=*)                 if _set_opt --ca-cert "$1" "${2-}" CA_CERT; then shift 1; else shift 2; fi ;;

    --init-shares|--init-shares=*)         if _set_opt --init-shares "$1" "${2-}" INIT_SHARES; then shift 1; else shift 2; fi ;;
    --init-threshold|--init-threshold=*)   if _set_opt --init-threshold "$1" "${2-}" INIT_THRESHOLD; then shift 1; else shift 2; fi ;;

    --bootstrap-dir|--bootstrap-dir=*)     if _set_opt --bootstrap-dir "$1" "${2-}" BOOTSTRAP_DIR; then shift 1; else shift 2; fi ;;
    --unseal-keys-file|--unseal-keys-file=*)
                                           if _set_opt --unseal-keys-file "$1" "${2-}" UNSEAL_KEYS_FILE; then shift 1; else shift 2; fi ;;
    --root-token-file|--root-token-file=*)
                                           if _set_opt --root-token-file "$1" "${2-}" ROOT_TOKEN_FILE; then shift 1; else shift 2; fi ;;
    --root-token-json-file|--root-token-json-file=*)
                                           if _set_opt --root-token-json-file "$1" "${2-}" ROOT_TOKEN_JSON_FILE; then shift 1; else shift 2; fi ;;

    --compose-project|--compose-project=*) if _set_opt --compose-project "$1" "${2-}" COMPOSE_PROJECT; then shift 1; else shift 2; fi ;;
    --compose-file|--compose-file=*)       if _set_opt --compose-file "$1" "${2-}" COMPOSE_FILE; then shift 1; else shift 2; fi ;;
    --service-name|--service-name=*)       if _set_opt --service-name "$1" "${2-}" SERVICE_NAME; then shift 1; else shift 2; fi ;;
    --compose-build)                       COMPOSE_BUILD=1; shift ;;

    --no-unseal)                           NO_UNSEAL=1; shift ;;

    --no-enable-audit)                     ENABLE_AUDIT=0; shift ;;
    --audit-path|--audit-path=*)           if _set_opt --audit-path "$1" "${2-}" AUDIT_PATH; then shift 1; else shift 2; fi ;;
    --audit-file-path|--audit-file-path=*) if _set_opt --audit-file-path "$1" "${2-}" AUDIT_FILE_PATH; then shift 1; else shift 2; fi ;;
    --audit-description|--audit-description=*)
                                           if _set_opt --audit-description "$1" "${2-}" AUDIT_DESCRIPTION; then shift 1; else shift 2; fi ;;
    --audit-token-file|--audit-token-file=*)
                                           if _set_opt --audit-token-file "$1" "${2-}" AUDIT_TOKEN_FILE; then shift 1; else shift 2; fi ;;

    --no-setup-postgres-pgadmin-approle)     SETUP_POSTGRES_PGADMIN_APPROLE=0; shift ;;
    --force-postgres-pgadmin-approle)        FORCE_POSTGRES_PGADMIN_APPROLE=1; shift ;;
    --postgres-pgadmin-role-name|--postgres-pgadmin-role-name=*)
                                             if _set_opt --postgres-pgadmin-role-name "$1" "${2-}" POSTGRES_PGADMIN_ROLE_NAME; then shift 1; else shift 2; fi ;;
    --postgres-pgadmin-policy-name|--postgres-pgadmin-policy-name=*)
                                             if _set_opt --postgres-pgadmin-policy-name "$1" "${2-}" POSTGRES_PGADMIN_POLICY_NAME; then shift 1; else shift 2; fi ;;
    --postgres-pgadmin-kv-mount|--postgres-pgadmin-kv-mount=*)
                                             if _set_opt --postgres-pgadmin-kv-mount "$1" "${2-}" POSTGRES_PGADMIN_KV_MOUNT; then shift 1; else shift 2; fi ;;
    --postgres-pgadmin-kv-version|--postgres-pgadmin-kv-version=*)
                                             if _set_opt --postgres-pgadmin-kv-version "$1" "${2-}" POSTGRES_PGADMIN_KV_VERSION; then shift 1; else shift 2; fi ;;
    --no-pretty-output)                    PRETTY_OUTPUT=0; shift ;;
    --no-print-artifact-contents)         PRINT_ARTIFACT_CONTENTS=0; shift ;;

    --debug)                               VERBOSE=1; shift ;;
    --debug-http)                          HTTP_DEBUG=1; shift ;;

    -*) echo "ERROR: Unknown option: $1" >&2; usage; exit 2 ;;
    *)  echo "ERROR: Unexpected positional argument: $1" >&2; usage; exit 2 ;;
  esac
done

# Determine compose file now (needed for default .env path)
COMPOSE_FILE="${COMPOSE_FILE:-$COMPOSE_FILE_DEFAULT}"

# Load .env defaults so PRIMARY_SERVER_FQDN / VAULT_ADDR are available when this script is run from the host.
if (( LOAD_ENV_FILE )); then
  if [[ -z "$ENV_FILE" ]]; then
    ENV_FILE="$(dirname -- "$COMPOSE_FILE")/.env"
  fi
  if [[ -r "$ENV_FILE" ]]; then
    echo "INFO: Loading env defaults from: $ENV_FILE" >&2
    load_env_file "$ENV_FILE" "$ENV_OVERRIDE"
  else
    echo "INFO: Env file not found/readable (skipping): $ENV_FILE" >&2
  fi
fi

# If --vault-addr was not provided, try env-derived values in order:
#   1) VAULT_ADDR (direct)
#   2) PRIMARY_VAULT_SERVER_FQDN_FULL (hostname only; scheme is forced to https)
#   3) PRIMARY_SERVER_FQDN -> vault.<PRIMARY_SERVER_FQDN>
#   4) Fallback to docker service name (vault_production_node)
if [[ -z "$VAULT_ADDR" ]]; then
  if [[ -n "${VAULT_ADDR-}" ]]; then
    : # already set by env file
  elif [[ -n "${PRIMARY_VAULT_SERVER_FQDN_FULL:-}" ]]; then
    _h="${PRIMARY_VAULT_SERVER_FQDN_FULL#https://}"
    _h="${_h#http://}"
    _h="${_h%/}"
    VAULT_ADDR="https://${_h}:8200"
  elif [[ -n "${PRIMARY_SERVER_FQDN:-}" ]]; then
    VAULT_ADDR="https://vault.${PRIMARY_SERVER_FQDN}:8200"
  else
    VAULT_ADDR="https://${SERVICE_NAME}:8200"
  fi
fi

[[ -n "$VAULT_ADDR" ]] || { echo "ERROR: Unable to determine Vault address. Provide --vault-addr or set PRIMARY_SERVER_FQDN / PRIMARY_VAULT_SERVER_FQDN_FULL / VAULT_ADDR in .env." >&2; exit 2; }

VAULT_ADDR="${VAULT_ADDR%/}"


# Derive a TLS/SNI-friendly public host when --vault-addr points at a container name or localhost.
# This avoids hostname mismatch errors when the Vault server certificate is issued to vault.<PRIMARY_SERVER_FQDN>.
PRIMARY_SERVER_FQDN="${PRIMARY_SERVER_FQDN_ARG:-${PRIMARY_SERVER_FQDN:-}}"
if [[ -z "$VAULT_PUBLIC_HOST" && -n "${PRIMARY_SERVER_FQDN:-}" ]]; then
  VAULT_PUBLIC_HOST="vault.${PRIMARY_SERVER_FQDN}"
fi

# Parse VAULT_ADDR into scheme/host/port.
VAULT_SCHEME=""
VAULT_HOST=""
VAULT_PORT=""
if [[ "$VAULT_ADDR" =~ ^(https?)://([^:/]+)(:([0-9]+))?$ ]]; then
  VAULT_SCHEME="${BASH_REMATCH[1]}"
  VAULT_HOST="${BASH_REMATCH[2]}"
  VAULT_PORT="${BASH_REMATCH[4]:-8200}"
else
  die "Invalid --vault-addr (expected scheme://host[:port]): $VAULT_ADDR"
fi

if (( AUTO_RESOLVE_PUBLIC_HOST )) && [[ -n "${VAULT_PUBLIC_HOST:-}" ]]; then
  # If user provided a docker service name or localhost, use the public hostname for SNI,
  # and map it to a local IP (default 127.0.0.1) via curl --resolve.
  if [[ "$VAULT_HOST" == "vault_production_node" || "$VAULT_HOST" == "localhost" || "$VAULT_HOST" == "127.0.0.1" ]]; then
    log "Using public host for TLS/SNI: ${VAULT_PUBLIC_HOST} (mapped to ${RESOLVE_IP} via curl --resolve)"
    VAULT_ADDR="${VAULT_SCHEME}://${VAULT_PUBLIC_HOST}:${VAULT_PORT}"
    CURL_RESOLVE_ARGS=(--resolve "${VAULT_PUBLIC_HOST}:${VAULT_PORT}:${RESOLVE_IP}")
  else
    # If the requested host does not resolve locally, optionally map it to RESOLVE_IP.
    if command -v getent >/dev/null 2>&1; then
      if ! getent hosts "$VAULT_HOST" >/dev/null 2>&1; then
        log "WARN: ${VAULT_HOST} does not resolve locally; using curl --resolve to ${RESOLVE_IP} for this host."
        CURL_RESOLVE_ARGS=(--resolve "${VAULT_HOST}:${VAULT_PORT}:${RESOLVE_IP}")
      fi
    fi
  fi
fi

if (( SETUP_POSTGRES_PGADMIN_APPROLE )); then
  if [[ "$POSTGRES_PGADMIN_KV_VERSION" != "1" && "$POSTGRES_PGADMIN_KV_VERSION" != "2" ]]; then
    echo "ERROR: --postgres-pgadmin-kv-version must be 1 or 2 (got: $POSTGRES_PGADMIN_KV_VERSION)" >&2
    exit 2
  fi
fi
AUDIT_PATH="${AUDIT_PATH%/}"
COMPOSE_FILE="${COMPOSE_FILE:-$COMPOSE_FILE_DEFAULT}"

UNSEAL_KEYS_FILE="${UNSEAL_KEYS_FILE:-$BOOTSTRAP_DIR/unseal_keys.json}"
ROOT_TOKEN_FILE="${ROOT_TOKEN_FILE:-$BOOTSTRAP_DIR/root_token}"
ROOT_TOKEN_JSON_FILE="${ROOT_TOKEN_JSON_FILE:-$BOOTSTRAP_DIR/root_token.json}"

AUDIT_TOKEN_FILE="${AUDIT_TOKEN_FILE:-$ROOT_TOKEN_FILE}"

command -v docker >/dev/null 2>&1 || { echo "ERROR: docker is required" >&2; exit 3; }
command -v curl  >/dev/null 2>&1 || { echo "ERROR: curl is required"  >&2; exit 3; }
command -v jq    >/dev/null 2>&1 || { echo "ERROR: jq is required"    >&2; exit 3; }


curl_warn_once() {
  # Log a curl stderr message once per distinct (context, rc, http, stderr) to avoid log spam.
  local context="$1" stderr_tmp="$2" rc="$3" http="$4"
  [[ -s "$stderr_tmp" ]] || return 0
  local msg key
  msg="$(tr '\n' ' ' <"$stderr_tmp" 2>/dev/null || true)"
  # Normalize whitespace a bit
  msg="${msg//$'\t'/ }"
  while [[ "$msg" == *"  "* ]]; do msg="${msg//  / }"; done
  key="${context}|${rc}|${http}|${msg}"
  if [[ "$key" != "${LAST_CURL_WARN:-}" ]]; then
    log "WARN: ${context} curl failed (rc=${rc}, http=${http}): ${msg}"
    LAST_CURL_WARN="$key"
  fi
}

# Curl common args
CURL_COMMON=(-sS --retry 3 --retry-delay 1 --connect-timeout 3 --max-time 10)
(( HTTP_DEBUG )) && CURL_COMMON+=(-v)

# TLS handling
# Behavior:
#   - If --ca-cert is provided: always use it for verification
#   - If no --ca-cert and HTTPS:
#       1) try system trust (no -k)
#       2) if that fails, retry with -k and warn with the original error
CURL_TLS_ARGS=()
AUTO_INSECURE_FALLBACK=0
if [[ "$VAULT_ADDR" =~ ^https:// ]]; then
  if [[ -n "$CA_CERT" ]]; then
    [[ -f "$CA_CERT" && -r "$CA_CERT" ]] || die "CA cert not found or unreadable: $CA_CERT"
    CURL_TLS_ARGS+=(--cacert "$CA_CERT")
  else
    AUTO_INSECURE_FALLBACK=1
  fi
fi

# Namespace header (optional)
NS_HDR=()
[[ -n "$VAULT_NAMESPACE" ]] && NS_HDR+=(-H "X-Vault-Namespace: ${VAULT_NAMESPACE}")

# File perms
umask 077
mkdir -p "$BOOTSTRAP_DIR"
chmod 700 "$BOOTSTRAP_DIR" || true

write_atomic_600() {
  local content="$1" dest="$2" tmp dir
  dir="$(dirname -- "$dest")"
  mkdir -p -- "$dir"
  chmod 700 -- "$dir" || true
  tmp="${dest}.tmp"
  rm -f -- "$tmp" 2>/dev/null || true
  printf '%s\n' "$content" > "$tmp"
  chmod 600 "$tmp" || true
  mv -f -- "$tmp" "$dest"
  chmod 600 "$dest" || true
}

write_pretty_json_600() {
  # Pretty-print JSON deterministically (sorted keys), write 0600.
  # Does NOT echo to stdout.
  local json="$1" dest="$2" tmp dir
  dir="$(dirname -- "$dest")"
  mkdir -p -- "$dir"
  chmod 700 -- "$dir" || true
  tmp="${dest}.tmp"
  rm -f -- "$tmp" 2>/dev/null || true
  if (( PRETTY_OUTPUT )); then
    printf '%s' "$json" | jq -S . > "$tmp" || return 1
  else
    # raw/compact
    printf '%s' "$json" > "$tmp"
  fi
  chmod 600 "$tmp" || true
  mv -f -- "$tmp" "$dest"
  chmod 600 "$dest" || true
}

RESP_JSON=""
HTTP_CODE=""

request_public() {
  local method="$1" path="$2" body="${3-}"
  local url="${VAULT_ADDR}${path}"

  # Build curl args (do not include any sensitive headers here).
  local -a args=("${CURL_COMMON[@]}" "${CURL_RESOLVE_ARGS[@]}" "${CURL_TLS_ARGS[@]}" "${NS_HDR[@]}" -X "$method")
  if [[ -n "$body" ]]; then args+=(-H "Content-Type: application/json" -d "$body"); fi

  # We want:
  #   - body in RESP_JSON (may be empty on TLS failure)
  #   - http_code in HTTP_CODE (may be 000 on TLS failure)
  #   - If HTTPS and no CA cert was provided: try system trust first; if that fails, retry with -k once.
  local stderr_tmp body_and_code rc
  stderr_tmp="$(mktemp)"

  set +e
  body_and_code="$(curl "${args[@]}" "$url" -w $'\n%{http_code}' 2>"$stderr_tmp")"
  rc=$?
  LAST_CURL_RC=$rc
  set -e

  HTTP_CODE="${body_and_code##*$'\n'}"
  RESP_JSON="${body_and_code%$'\n'$HTTP_CODE}"
  dbg "public $method $path -> http=$HTTP_CODE rc=$rc"
  if (( rc != 0 )) || [[ "$HTTP_CODE" == "000" ]]; then
    curl_warn_once "public ${method} ${path}" "$stderr_tmp" "$rc" "$HTTP_CODE"
  fi

  if (( rc != 0 )) && (( AUTO_INSECURE_FALLBACK )) && [[ "${#CURL_TLS_ARGS[@]}" -eq 0 ]]; then
    # First attempt failed using system trust. Capture the error and retry with -k.
    local err
    err="$(cat "$stderr_tmp" 2>/dev/null || true)"

    log "WARN: TLS verification failed using system trust store (no --ca-cert provided)."
    if [[ -n "$err" ]]; then
      log "WARN: curl error: ${err//$'\n'/ | }"
    fi
    log "WARN: Retrying with -k (insecure). For proper TLS verification, provide --ca-cert <path-to-ca.crt>."

    CURL_TLS_ARGS=(-k)

    rm -f "$stderr_tmp" 2>/dev/null || true
    stderr_tmp="$(mktemp)"

    args=("${CURL_COMMON[@]}" "${CURL_TLS_ARGS[@]}" "${NS_HDR[@]}" -X "$method")
    if [[ -n "$body" ]]; then args+=(-H "Content-Type: application/json" -d "$body"); fi

    set +e
    body_and_code="$(curl "${args[@]}" "$url" -w $'\n%{http_code}' 2>"$stderr_tmp")"
    rc=$?
    set -e

    HTTP_CODE="${body_and_code##*$'\n'}"
    RESP_JSON="${body_and_code%$'\n'$HTTP_CODE}"
    dbg "public retry(insecure) $method $path -> http=$HTTP_CODE rc=$rc"
  fi

  rm -f "$stderr_tmp" 2>/dev/null || true
}
request_authed() {
  # Authenticated Vault API call using X-Vault-Token read from a token file or provided by caller.
  # Stores response body in RESP_JSON and HTTP status in HTTP_CODE.
  local token="$1" method="$2" path="$3" body="${4-}"
  local url="${VAULT_ADDR}${path}"

  [[ -n "$token" ]] || die "request_authed called with empty token"

  local -a args=("${CURL_COMMON[@]}" "${CURL_RESOLVE_ARGS[@]}" "${CURL_TLS_ARGS[@]}" "${NS_HDR[@]}" -H "X-Vault-Token: ${token}" -X "$method")
  if [[ -n "$body" ]]; then args+=(-H "Content-Type: application/json" -d "$body"); fi

  local stderr_tmp body_and_code rc
  stderr_tmp="$(mktemp)"

  set +e
  body_and_code="$(curl "${args[@]}" "$url" -w $'\n%{http_code}' 2>"$stderr_tmp")"
  rc=$?
  set -e

  HTTP_CODE="${body_and_code##*$'\n'}"
  RESP_JSON="${body_and_code%$'\n'$HTTP_CODE}"
  dbg "authed $method $path -> http=$HTTP_CODE rc=$rc"
  if (( rc != 0 )) || [[ "$HTTP_CODE" == "000" ]]; then
    curl_warn_once "authed ${method} ${path}" "$stderr_tmp" "$rc" "$HTTP_CODE"
  fi

  if (( rc != 0 )) && (( AUTO_INSECURE_FALLBACK )) && [[ "${#CURL_TLS_ARGS[@]}" -eq 0 ]]; then
    local err
    err="$(cat "$stderr_tmp" 2>/dev/null || true)"

    log "WARN: TLS verification failed using system trust store (no --ca-cert provided)."
    if [[ -n "$err" ]]; then
      log "WARN: curl error: ${err//$'\n'/ | }"
    fi
    log "WARN: Retrying with -k (insecure). For proper TLS verification, provide --ca-cert <path-to-ca.crt>."

    CURL_TLS_ARGS=(-k)

    rm -f "$stderr_tmp" 2>/dev/null || true
    stderr_tmp="$(mktemp)"

    args=("${CURL_COMMON[@]}" "${CURL_TLS_ARGS[@]}" "${NS_HDR[@]}" -H "X-Vault-Token: ${token}" -X "$method")
    if [[ -n "$body" ]]; then args+=(-H "Content-Type: application/json" -d "$body"); fi

    set +e
    body_and_code="$(curl "${args[@]}" "$url" -w $'\n%{http_code}' 2>"$stderr_tmp")"
    rc=$?
    set -e

    HTTP_CODE="${body_and_code##*$'\n'}"
    RESP_JSON="${body_and_code%$'\n'$HTTP_CODE}"
    dbg "authed retry(insecure) $method $path -> http=$HTTP_CODE rc=$rc"
  fi

  rm -f "$stderr_tmp" 2>/dev/null || true
}

enable_file_audit_if_needed() {
  (( ENABLE_AUDIT )) || { log "Audit enable disabled (--no-enable-audit)."; return 0; }

  # Vault must be unsealed for authenticated sys/audit operations.
  request_public GET "/v1/sys/seal-status"
  [[ "$HTTP_CODE" =~ ^2 ]] || die "seal-status read failed before audit enable (${HTTP_CODE}): ${RESP_JSON}"
  if [[ "$(jq -r '.sealed' <<<"$RESP_JSON")" == "true" ]]; then
    log "WARN: Vault is sealed; skipping audit enable."
    return 0
  fi

  [[ -f "$AUDIT_TOKEN_FILE" ]] || die "Audit token file not found: $AUDIT_TOKEN_FILE (use --audit-token-file or --no-enable-audit)"
  local token
  token="$(tr -d '
' < "$AUDIT_TOKEN_FILE" | head -c 4096)"
  [[ -n "$token" ]] || die "Audit token file is empty: $AUDIT_TOKEN_FILE"

  # List enabled audit devices
  request_authed "$token" GET "/v1/sys/audit"
  if [[ "$HTTP_CODE" == "403" ]]; then
    die "Permission denied listing audit devices (need sudo on sys/audit). Token file: $AUDIT_TOKEN_FILE"
  fi
  [[ "$HTTP_CODE" =~ ^2 ]] || die "sys/audit list failed (${HTTP_CODE}): ${RESP_JSON}"

  if jq -e --arg p "$AUDIT_PATH" 'has($p)' >/dev/null 2>&1 <<<"$RESP_JSON"; then
    log "Audit device already enabled at path: ${AUDIT_PATH}/"
    return 0
  fi

  log "Enabling file audit device at path '${AUDIT_PATH}/' -> ${AUDIT_FILE_PATH}"
  local payload
  if [[ -n "$AUDIT_DESCRIPTION" ]]; then
    payload="$(jq -n --arg t "file" --arg d "$AUDIT_DESCRIPTION" --arg fp "$AUDIT_FILE_PATH" '{type:$t, description:$d, options:{file_path:$fp}}')"
  else
    payload="$(jq -n --arg t "file" --arg fp "$AUDIT_FILE_PATH" '{type:$t, options:{file_path:$fp}}')"
  fi

  request_authed "$token" POST "/v1/sys/audit/${AUDIT_PATH}" "$payload"
  if [[ "$HTTP_CODE" == "403" ]]; then
    die "Permission denied enabling audit device (need sudo on sys/audit/${AUDIT_PATH}). Token file: $AUDIT_TOKEN_FILE"
  fi
  [[ "$HTTP_CODE" =~ ^2 ]] || die "sys/audit enable failed (${HTTP_CODE}): ${RESP_JSON}"

  # Generate at least one authenticated request post-enable (helps ensure the file is created)
  request_authed "$token" GET "/v1/sys/audit"
  [[ "$HTTP_CODE" =~ ^2 ]] || true

  log "Audit device enabled successfully."
}



setup_postgres_pgadmin_approle_if_needed() {
  (( SETUP_POSTGRES_PGADMIN_APPROLE )) || { log "Postgres/pgAdmin AppRole bootstrap disabled (--no-setup-postgres-pgadmin-approle)."; return 0; }

  # Root token is required for sys/auth + sys/policy + AppRole role management.
  if [[ ! -f "$ROOT_TOKEN_FILE" ]]; then
    log "WARN: Root token file not found ($ROOT_TOKEN_FILE). Skipping Postgres/pgAdmin AppRole bootstrap."
    return 0
  fi

  local token=""
  token="$(cat "$ROOT_TOKEN_FILE" 2>/dev/null || true)"
  token="$(printf '%s' "$token" | tr -d '\r\n' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"

  # Fallbacks (in case the plain file was written but read failed for any reason)
  if [[ -z "$token" && -f "$ROOT_TOKEN_JSON_FILE" ]]; then
    token="$(jq -r '.root_token // empty' "$ROOT_TOKEN_JSON_FILE" 2>/dev/null | head -n1 | tr -d '\r\n' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
  fi
  if [[ -z "$token" && -f "$UNSEAL_KEYS_FILE" ]]; then
    token="$(jq -r '.root_token // empty' "$UNSEAL_KEYS_FILE" 2>/dev/null | head -n1 | tr -d '\r\n' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
  fi

  if [[ -z "$token" ]]; then
    log "WARN: Root token could not be read (empty/unreadable). Checked: $ROOT_TOKEN_FILE, $ROOT_TOKEN_JSON_FILE, $UNSEAL_KEYS_FILE. Skipping Postgres/pgAdmin AppRole bootstrap."
    return 0
  fi

  # Vault must be unsealed for authenticated sys/auth operations.
  request_public GET "/v1/sys/seal-status"
  [[ "$HTTP_CODE" =~ ^2 ]] || die "seal-status read failed before AppRole bootstrap (${HTTP_CODE}): ${RESP_JSON}"
  if [[ "$(jq -r '.sealed' <<<"$RESP_JSON")" == "true" ]]; then
    log "WARN: Vault is sealed; skipping Postgres/pgAdmin AppRole bootstrap."
    return 0
  fi

  # KV policy path differs between v1 and v2.
  local kv_prefix
  if [[ "$POSTGRES_PGADMIN_KV_VERSION" == "2" ]]; then
    kv_prefix="${POSTGRES_PGADMIN_KV_MOUNT}/data"
  else
    kv_prefix="${POSTGRES_PGADMIN_KV_MOUNT}"
  fi

  local policy_hcl
  policy_hcl="$(cat <<HCL
# Read secrets (KV v1 or KV v2 data paths)
path "${kv_prefix}/postgres*" {
  capabilities = ["read"]
}

path "${kv_prefix}/pgadmin*" {
  capabilities = ["read"]
}

# If KV v2, allow listing metadata (helps `vault kv list`/UI and some tooling)
path "${POSTGRES_PGADMIN_KV_MOUNT}/metadata/postgres*" {
  capabilities = ["list"]
}

path "${POSTGRES_PGADMIN_KV_MOUNT}/metadata/pgadmin*" {
  capabilities = ["list"]
}
HCL
)"

  # 1) Ensure ACL policy exists (or force re-write).
  local need_policy=0
  request_authed "$token" GET "/v1/sys/policy/${POSTGRES_PGADMIN_POLICY_NAME}"
  if [[ "$HTTP_CODE" == "404" ]]; then
    need_policy=1
  elif [[ "$HTTP_CODE" =~ ^2 ]]; then
    need_policy=0
  else
    die "policy read failed (${HTTP_CODE}): ${RESP_JSON}"
  fi

  if (( FORCE_POSTGRES_PGADMIN_APPROLE )) || (( need_policy )); then
    local policy_body
    policy_body="$(jq -n --arg pol "$policy_hcl" '{policy:$pol}')"
    request_authed "$token" PUT "/v1/sys/policy/${POSTGRES_PGADMIN_POLICY_NAME}" "$policy_body"
    [[ "$HTTP_CODE" =~ ^2 ]] || die "policy write failed (${HTTP_CODE}): ${RESP_JSON}"
    log "Ensured ACL policy: ${POSTGRES_PGADMIN_POLICY_NAME}"
  else
    log "ACL policy already exists: ${POSTGRES_PGADMIN_POLICY_NAME}"
  fi

  # 2) Ensure AppRole auth method is enabled at approle/.
  request_authed "$token" GET "/v1/sys/auth"
  [[ "$HTTP_CODE" =~ ^2 ]] || die "sys/auth read failed (${HTTP_CODE}): ${RESP_JSON}"

  if jq -e '.data["approle/"]? // empty' <<<"$RESP_JSON" >/dev/null 2>&1; then
    log "Auth method already enabled: approle/"
  else
    local auth_body
    auth_body="$(jq -n --arg t "approle" --arg d "AppRole auth (bootstrap)" '{type:$t, description:$d}')"
    request_authed "$token" POST "/v1/sys/auth/approle" "$auth_body"
    [[ "$HTTP_CODE" =~ ^2 ]] || die "approle auth enable failed (${HTTP_CODE}): ${RESP_JSON}"
    log "Enabled auth method: approle/"
  fi

  # 3) Ensure AppRole role exists (or force re-write).
  local need_role=0
  request_authed "$token" GET "/v1/auth/approle/role/${POSTGRES_PGADMIN_ROLE_NAME}/role-id"
  if [[ "$HTTP_CODE" == "404" ]]; then
    need_role=1
  elif [[ "$HTTP_CODE" =~ ^2 ]]; then
    need_role=0
  else
    die "approle role-id read failed (${HTTP_CODE}): ${RESP_JSON}"
  fi

  if (( FORCE_POSTGRES_PGADMIN_APPROLE )) || (( need_role )); then
    local role_body
    role_body="$(jq -n \
      --arg pol "${POSTGRES_PGADMIN_POLICY_NAME}" \
      --arg token_ttl "${POSTGRES_PGADMIN_TOKEN_TTL}" \
      --arg token_max_ttl "${POSTGRES_PGADMIN_TOKEN_MAX_TTL}" \
      --arg secret_id_ttl "${POSTGRES_PGADMIN_SECRET_ID_TTL}" \
      --argjson secret_id_num_uses "${POSTGRES_PGADMIN_SECRET_ID_NUM_USES}" \
      '{token_policies:[$pol], token_ttl:$token_ttl, token_max_ttl:$token_max_ttl, secret_id_ttl:$secret_id_ttl, secret_id_num_uses:$secret_id_num_uses}')"

    request_authed "$token" POST "/v1/auth/approle/role/${POSTGRES_PGADMIN_ROLE_NAME}" "$role_body"
    [[ "$HTTP_CODE" =~ ^2 ]] || die "approle role write failed (${HTTP_CODE}): ${RESP_JSON}"
    log "Ensured AppRole role: ${POSTGRES_PGADMIN_ROLE_NAME} (policy: ${POSTGRES_PGADMIN_POLICY_NAME})"
  else
    log "AppRole role already exists: ${POSTGRES_PGADMIN_ROLE_NAME}"
  fi

  POSTGRES_PGADMIN_SETUP_DONE=1
}

setup_keycloak_approle_if_needed() {
  (( SETUP_KEYCLOAK_APPROLE )) || { log "Keycloak AppRole + ACL bootstrap disabled (--no-setup-keycloak-approle)."; return 0; }

  # Root token is required for sys/auth + sys/policy + AppRole role management.
  if [[ ! -f "$ROOT_TOKEN_FILE" ]]; then
    log "WARN: Root token file not found ($ROOT_TOKEN_FILE). Skipping Keycloak AppRole bootstrap."
    return 0
  fi

  local token=""
  token="$(cat "$ROOT_TOKEN_FILE" 2>/dev/null || true)"
  token="$(printf '%s' "$token" | tr -d '\r\n' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"

  # Fallbacks (in case the plain file was written but read failed for any reason)
  if [[ -z "$token" && -f "$ROOT_TOKEN_JSON_FILE" ]]; then
    token="$(jq -r '.root_token // empty' "$ROOT_TOKEN_JSON_FILE" 2>/dev/null || true)"
    token="$(printf '%s' "$token" | tr -d '\r\n' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
  fi
  if [[ -z "$token" && -f "$UNSEAL_KEYS_FILE" ]]; then
    token="$(jq -r '.root_token // empty' "$UNSEAL_KEYS_FILE" 2>/dev/null || true)"
    token="$(printf '%s' "$token" | tr -d '\r\n' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
  fi

  [[ -n "$token" ]] || { log "WARN: Root token not available; skipping Keycloak AppRole bootstrap."; return 0; }

  # Determine KV prefix for policy. KV v2 uses <mount>/data/<path>.
  local kv_prefix
  if [[ "${KEYCLOAK_KV_VERSION}" == "2" ]]; then
    kv_prefix="${KEYCLOAK_KV_MOUNT}/data"
  else
    kv_prefix="${KEYCLOAK_KV_MOUNT}"
  fi

  local policy_hcl
  policy_hcl="$(cat <<HCL
# Read secrets (KV v1 or KV v2 data paths)
path "${kv_prefix}/keycloak*" {
  capabilities = ["read"]
}

# If KV v2, allow listing metadata (helps `vault kv list`/UI and some tooling)
path "${KEYCLOAK_KV_MOUNT}/metadata/keycloak*" {
  capabilities = ["list"]
}
HCL
)"

  # 1) Ensure ACL policy exists (or force re-write).
  local need_policy=0
  request_authed "$token" GET "/v1/sys/policy/${KEYCLOAK_POLICY_NAME}"
  if [[ "$HTTP_CODE" == "404" ]]; then
    need_policy=1
  elif [[ "$HTTP_CODE" =~ ^2 ]]; then
    need_policy=0
  else
    die "policy read failed (${HTTP_CODE}): ${RESP_JSON}"
  fi

  if (( FORCE_KEYCLOAK_APPROLE )) || (( need_policy )); then
    local policy_body
    policy_body="$(jq -n --arg pol "$policy_hcl" '{policy:$pol}')"
    request_authed "$token" PUT "/v1/sys/policy/${KEYCLOAK_POLICY_NAME}" "$policy_body"
    [[ "$HTTP_CODE" =~ ^2 ]] || die "policy write failed (${HTTP_CODE}): ${RESP_JSON}"
    log "Ensured ACL policy: ${KEYCLOAK_POLICY_NAME}"
  else
    log "ACL policy already exists: ${KEYCLOAK_POLICY_NAME}"
  fi

  # 2) Ensure AppRole auth method is enabled at approle/.
  request_authed "$token" GET "/v1/sys/auth"
  [[ "$HTTP_CODE" =~ ^2 ]] || die "sys/auth read failed (${HTTP_CODE}): ${RESP_JSON}"

  if jq -e '.data["approle/"]? // empty' <<<"$RESP_JSON" >/dev/null 2>&1; then
    log "Auth method already enabled: approle/"
  else
    local auth_body
    auth_body="$(jq -n --arg t "approle" --arg d "AppRole auth (bootstrap)" '{type:$t, description:$d}')"
    request_authed "$token" POST "/v1/sys/auth/approle" "$auth_body"
    [[ "$HTTP_CODE" =~ ^2 ]] || die "auth enable approle failed (${HTTP_CODE}): ${RESP_JSON}"
    log "Enabled auth method: approle/"
  fi

  # 3) Ensure the AppRole role exists (or force re-write).
  local need_role=0
  request_authed "$token" GET "/v1/auth/approle/role/${KEYCLOAK_ROLE_NAME}/role-id"
  if [[ "$HTTP_CODE" == "404" ]]; then
    need_role=1
  elif [[ "$HTTP_CODE" =~ ^2 ]]; then
    need_role=0
  else
    die "approle role-id read failed (${HTTP_CODE}): ${RESP_JSON}"
  fi

  if (( FORCE_KEYCLOAK_APPROLE )) || (( need_role )); then
    local role_body
    role_body="$(jq -n \
      --arg pol "${KEYCLOAK_POLICY_NAME}" \
      --arg token_ttl "${KEYCLOAK_TOKEN_TTL}" \
      --arg token_max_ttl "${KEYCLOAK_TOKEN_MAX_TTL}" \
      --arg secret_id_ttl "${KEYCLOAK_SECRET_ID_TTL}" \
      --argjson secret_id_num_uses "${KEYCLOAK_SECRET_ID_NUM_USES}" \
      '{token_policies:[$pol], token_ttl:$token_ttl, token_max_ttl:$token_max_ttl, secret_id_ttl:$secret_id_ttl, secret_id_num_uses:$secret_id_num_uses}')"

    request_authed "$token" POST "/v1/auth/approle/role/${KEYCLOAK_ROLE_NAME}" "$role_body"
    [[ "$HTTP_CODE" =~ ^2 ]] || die "approle role write failed (${HTTP_CODE}): ${RESP_JSON}"
    log "Ensured AppRole role: ${KEYCLOAK_ROLE_NAME} (policy: ${KEYCLOAK_POLICY_NAME})"
  else
    log "AppRole role already exists: ${KEYCLOAK_ROLE_NAME}"
  fi

  KEYCLOAK_SETUP_DONE=1
}

setup_fastapi_approle_if_needed() {
  (( SETUP_FASTAPI_APPROLE )) || { log "FastAPI AppRole + ACL bootstrap disabled (--no-setup-fastapi-approle)."; return 0; }

  # Root token is required for sys/auth + sys/policy + AppRole role management.
  if [[ ! -f "$ROOT_TOKEN_FILE" ]]; then
    log "WARN: Root token file not found ($ROOT_TOKEN_FILE). Skipping FastAPI AppRole bootstrap."
    return 0
  fi

  local token=""
  token="$(cat "$ROOT_TOKEN_FILE" 2>/dev/null || true)"
  token="$(printf '%s' "$token" | tr -d '\r\n' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"

  # Fallbacks (in case the plain file was written but read failed for any reason)
  if [[ -z "$token" && -f "$ROOT_TOKEN_JSON_FILE" ]]; then
    token="$(jq -r '.root_token // empty' "$ROOT_TOKEN_JSON_FILE" 2>/dev/null || true)"
    token="$(printf '%s' "$token" | tr -d '\r\n' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
  fi
  if [[ -z "$token" && -f "$UNSEAL_KEYS_FILE" ]]; then
    token="$(jq -r '.root_token // empty' "$UNSEAL_KEYS_FILE" 2>/dev/null || true)"
    token="$(printf '%s' "$token" | tr -d '\r\n' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
  fi

  [[ -n "$token" ]] || { log "WARN: Root token not available; skipping FastAPI AppRole bootstrap."; return 0; }

  # Determine KV prefix for policy. KV v2 uses <mount>/data/<path>.
  local kv_prefix
  if [[ "${FASTAPI_KV_VERSION}" == "2" ]]; then
    kv_prefix="${FASTAPI_KV_MOUNT}/data"
  else
    kv_prefix="${FASTAPI_KV_MOUNT}"
  fi

  local policy_hcl
  policy_hcl="$(cat <<HCL
# Read secrets (KV v1 or KV v2 data paths)
path "${kv_prefix}/fastapi*" {
  capabilities = ["read"]
}

# If KV v2, allow listing metadata (helps `vault kv list`/UI and some tooling)
path "${FASTAPI_KV_MOUNT}/metadata/fastapi*" {
  capabilities = ["list"]
}
HCL
)"

  # 1) Ensure ACL policy exists (or force re-write).
  local need_policy=0
  request_authed "$token" GET "/v1/sys/policy/${FASTAPI_POLICY_NAME}"
  if [[ "$HTTP_CODE" == "404" ]]; then
    need_policy=1
  elif [[ "$HTTP_CODE" =~ ^2 ]]; then
    need_policy=0
  else
    die "policy read failed (${HTTP_CODE}): ${RESP_JSON}"
  fi

  if (( FORCE_FASTAPI_APPROLE )) || (( need_policy )); then
    local policy_body
    policy_body="$(jq -n --arg pol "$policy_hcl" '{policy:$pol}')"
    request_authed "$token" PUT "/v1/sys/policy/${FASTAPI_POLICY_NAME}" "$policy_body"
    [[ "$HTTP_CODE" =~ ^2 ]] || die "policy write failed (${HTTP_CODE}): ${RESP_JSON}"
    log "Ensured ACL policy: ${FASTAPI_POLICY_NAME}"
  else
    log "ACL policy already exists: ${FASTAPI_POLICY_NAME}"
  fi

  # 2) Ensure AppRole auth method is enabled at approle/.
  request_authed "$token" GET "/v1/sys/auth"
  [[ "$HTTP_CODE" =~ ^2 ]] || die "sys/auth read failed (${HTTP_CODE}): ${RESP_JSON}"

  if jq -e '.data["approle/"]? // empty' <<<"$RESP_JSON" >/dev/null 2>&1; then
    log "Auth method already enabled: approle/"
  else
    local auth_body
    auth_body="$(jq -n --arg t "approle" --arg d "AppRole auth (bootstrap)" '{type:$t, description:$d}')"
    request_authed "$token" POST "/v1/sys/auth/approle" "$auth_body"
    [[ "$HTTP_CODE" =~ ^2 ]] || die "auth enable approle failed (${HTTP_CODE}): ${RESP_JSON}"
    log "Enabled auth method: approle/"
  fi

  # 3) Ensure the AppRole role exists (or force re-write).
  local need_role=0
  request_authed "$token" GET "/v1/auth/approle/role/${FASTAPI_ROLE_NAME}/role-id"
  if [[ "$HTTP_CODE" == "404" ]]; then
    need_role=1
  elif [[ "$HTTP_CODE" =~ ^2 ]]; then
    need_role=0
  else
    die "approle role-id read failed (${HTTP_CODE}): ${RESP_JSON}"
  fi

  if (( FORCE_FASTAPI_APPROLE )) || (( need_role )); then
    local role_body
    role_body="$(jq -n \
      --arg pol "${FASTAPI_POLICY_NAME}" \
      --arg token_ttl "${FASTAPI_TOKEN_TTL}" \
      --arg token_max_ttl "${FASTAPI_TOKEN_MAX_TTL}" \
      --arg secret_id_ttl "${FASTAPI_SECRET_ID_TTL}" \
      --argjson secret_id_num_uses "${FASTAPI_SECRET_ID_NUM_USES}" \
      '{token_policies:[$pol], token_ttl:$token_ttl, token_max_ttl:$token_max_ttl, secret_id_ttl:$secret_id_ttl, secret_id_num_uses:$secret_id_num_uses}')"

    request_authed "$token" POST "/v1/auth/approle/role/${FASTAPI_ROLE_NAME}" "$role_body"
    [[ "$HTTP_CODE" =~ ^2 ]] || die "approle role write failed (${HTTP_CODE}): ${RESP_JSON}"
    log "Ensured AppRole role: ${FASTAPI_ROLE_NAME} (policy: ${FASTAPI_POLICY_NAME})"
  else
    log "AppRole role already exists: ${FASTAPI_ROLE_NAME}"
  fi

  FASTAPI_SETUP_DONE=1
}



compose_up() {
  [[ -f "$COMPOSE_FILE" ]] || die "Compose file missing: $COMPOSE_FILE"
  local -a cmd=(docker compose -p "$COMPOSE_PROJECT" -f "$COMPOSE_FILE" up -d)
  (( COMPOSE_BUILD )) && cmd+=(--build)
  cmd+=("$SERVICE_NAME")

  log "Starting Vault container: ${cmd[*]}"
  "${cmd[@]}"
}

wait_for_vault() {
  local deadline="$((SECONDS + 75))"
  local start_ts="$SECONDS"
  local switched_to_container_ip=0

  echo "INFO: Waiting for Vault endpoint: ${VAULT_ADDR}" >&2

  while (( SECONDS < deadline )); do
    request_public GET "/v1/sys/health"
    # 200 = active, 429 = standby, 501 = not init, 503 = sealed
    if [[ "$HTTP_CODE" =~ ^(200|429|501|503)$ ]]; then
      return 0
    fi

    # Seamless fallback:
    # If we're using curl --resolve to 127.0.0.1 (common for host-side bootstrap),
    # but Vault is still not reachable, fall back to resolving to the container IP.
    #
    # This helps in cases where you later remove port publishing (8200:8200) and need to reach Vault via Docker networking.
    if (( ! switched_to_container_ip )) \
       && (( AUTO_RESOLVE_PUBLIC_HOST )) \
       && [[ "${#CURL_RESOLVE_ARGS[@]}" -gt 0 ]] \
       && [[ "${RESOLVE_IP}" == "127.0.0.1" ]] \
       && (( SECONDS - start_ts >= 10 )) \
       && [[ "$HTTP_CODE" == "000" ]]; then

      local cip=""
      if command -v docker >/dev/null 2>&1; then
        cip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${SERVICE_NAME}" 2>/dev/null | awk '{print $1}')"
      fi

      if [[ -n "$cip" ]]; then
        echo "INFO: WARN: Vault not reachable yet via ${RESOLVE_IP}; falling back to container IP ${cip} for curl --resolve" >&2
        RESOLVE_IP="$cip"

        # Rebuild resolve args for current VAULT_ADDR host:port
        if [[ "$VAULT_ADDR" =~ ^(https?)://([^:/]+)(:([0-9]+))?$ ]]; then
          local host="${BASH_REMATCH[2]}"
          local port="${BASH_REMATCH[4]:-8200}"
          CURL_RESOLVE_ARGS=(--resolve "${host}:${port}:${RESOLVE_IP}")
        fi

        switched_to_container_ip=1
      fi
    fi

    sleep 1
  done

  die "Vault did not become reachable at ${VAULT_ADDR} within 75 seconds (last HTTP ${HTTP_CODE}). Check: docker compose logs -f ${SERVICE_NAME}"
}

init_if_needed() {
  request_public GET "/v1/sys/init"
  [[ "$HTTP_CODE" =~ ^2 ]] || die "sys/init read failed (${HTTP_CODE}): ${RESP_JSON}"

  local initialized
  initialized="$(jq -r '.initialized' <<<"$RESP_JSON")"
  if [[ "$initialized" == "true" ]]; then
    log "Vault already initialized."
    return 0
  fi

  log "Vault not initialized; initializing (shares=$INIT_SHARES, threshold=$INIT_THRESHOLD)…"
  local body
  body="$(jq -n --argjson s "$INIT_SHARES" --argjson t "$INIT_THRESHOLD" '{secret_shares:$s, secret_threshold:$t}')"
  request_public POST "/v1/sys/init" "$body"
  [[ "$HTTP_CODE" =~ ^2 ]] || die "sys/init failed (${HTTP_CODE}): ${RESP_JSON}"

  # Persist sensitive artifacts (pretty JSON for readability)
  write_pretty_json_600 "$RESP_JSON" "$UNSEAL_KEYS_FILE" || die "Failed writing unseal keys JSON to: $UNSEAL_KEYS_FILE"

  local root_token
  root_token="$(jq -r '.root_token // empty' <<<"$RESP_JSON")"
  [[ -n "$root_token" ]] || die "Init response missing root_token."
  write_atomic_600 "$root_token" "$ROOT_TOKEN_FILE"

  # Also write root token in JSON form (pretty)
  local root_token_json
  root_token_json="$(jq -n --arg t "$root_token" '{root_token:$t}')"
  write_pretty_json_600 "$root_token_json" "$ROOT_TOKEN_JSON_FILE" || die "Failed writing root token JSON to: $ROOT_TOKEN_JSON_FILE"

  log "Init complete. Wrote (0600):"
  log "  Unseal keys JSON     : $UNSEAL_KEYS_FILE"
  log "  Root token (plain)   : $ROOT_TOKEN_FILE"
  log "  Root token (JSON)    : $ROOT_TOKEN_JSON_FILE"
}

unseal_if_needed() {
  (( NO_UNSEAL )) && { log "--no-unseal set; skipping unseal."; return 0; }

  request_public GET "/v1/sys/seal-status"
  [[ "$HTTP_CODE" =~ ^2 ]] || die "seal-status read failed (${HTTP_CODE}): ${RESP_JSON}"

  local sealed
  sealed="$(jq -r '.sealed' <<<"$RESP_JSON")"
  if [[ "$sealed" == "false" ]]; then
    log "Vault already unsealed."
    return 0
  fi

  [[ -f "$UNSEAL_KEYS_FILE" ]] || die "Unseal keys file not found: $UNSEAL_KEYS_FILE"

  local keys_count
  keys_count="$(jq -r '.keys_base64 | length' "$UNSEAL_KEYS_FILE" 2>/dev/null || echo 0)"
  (( keys_count >= INIT_THRESHOLD )) || die "Not enough unseal keys (have $keys_count, need $INIT_THRESHOLD)."

  log "Unsealing Vault using $INIT_THRESHOLD key(s)…"
  for ((i=0; i<INIT_THRESHOLD; i++)); do
    local key
    key="$(jq -r ".keys_base64[$i]" "$UNSEAL_KEYS_FILE")"
    request_public POST "/v1/sys/unseal" "$(jq -n --arg k "$key" '{key:$k}')"
    [[ "$HTTP_CODE" =~ ^2 ]] || die "Unseal failed at key index $i (${HTTP_CODE}): ${RESP_JSON}"
    if [[ "$(jq -r '.sealed' <<<"$RESP_JSON")" == "false" ]]; then
      log "Vault unsealed."
      return 0
    fi
  done

  request_public GET "/v1/sys/seal-status"
  [[ "$(jq -r '.sealed' <<<"$RESP_JSON")" == "false" ]] || die "Vault still sealed after submitting threshold keys."
  log "Vault unsealed."
}

print_bootstrap_artifacts_instructions() {
  echo ""
  echo "============================================================"
  echo "VAULT BOOTSTRAP ARTIFACTS (SENSITIVE) - DOWNLOAD THEN REMOVE"
  echo "============================================================"
  echo "Bootstrap directory:"
  echo "  ${BOOTSTRAP_DIR}"
  echo ""
  echo "Files written/used by this script:"
  for f in "${UNSEAL_KEYS_FILE}" "${ROOT_TOKEN_FILE}" "${ROOT_TOKEN_JSON_FILE}"; do
    if [[ -f "$f" ]]; then
      # GNU stat (Ubuntu). If stat fails for any reason, fall back to basic output.
      if stat -c '%a %U:%G' "$f" >/dev/null 2>&1; then
        echo "  - $f  (exists; perms/owner: $(stat -c '%a %U:%G' "$f"))"
      else
        echo "  - $f  (exists)"
      fi
    else
      echo "  - $f  (NOT FOUND on disk)"
    fi
  done
  echo ""
  echo "IMPORTANT:"
  echo "  - This script is configured to print key/token JSON contents to the terminal by default."
  echo "    Use --no-print-artifact-contents to suppress that output."
  echo "  1) Download these files to a secure location (password manager / offline vault / secure storage)."
  echo "  2) Do NOT commit these files to Git."
  echo "  3) After you have securely stored them, delete them from this server."
  echo ""
  echo "Example download (from your workstation):"
  echo "  scp -p <user>@<server>:'${UNSEAL_KEYS_FILE}' ."
  echo "  scp -p <user>@<server>:'${ROOT_TOKEN_FILE}' ."
  echo "  scp -p <user>@<server>:'${ROOT_TOKEN_JSON_FILE}' ."
  echo ""
  echo "Example removal (run on this server AFTER downloading):"
  echo "  rm -f '${UNSEAL_KEYS_FILE}' '${ROOT_TOKEN_FILE}' '${ROOT_TOKEN_JSON_FILE}'"
  echo ""
  echo "If you want a stronger delete (optional; not always effective on all storage):"
  echo "  shred -u '${UNSEAL_KEYS_FILE}' '${ROOT_TOKEN_FILE}' '${ROOT_TOKEN_JSON_FILE}'"
  echo ""
}

print_bootstrap_artifacts_contents() {
  (( PRINT_ARTIFACT_CONTENTS )) || return 0

  echo ""
  echo "============================================================"
  echo "BOOTSTRAP FILE CONTENTS (HIGHLY SENSITIVE) - TERMINAL OUTPUT"
  echo "============================================================"
  echo "WARNING: The contents below include unseal keys and root token."
  echo "Do NOT paste this output into tickets, chat, or logs."
  echo "============================================================"
  echo ""

  if [[ -f "${UNSEAL_KEYS_FILE}" ]]; then
    echo "----- ${UNSEAL_KEYS_FILE} -----"
    cat "${UNSEAL_KEYS_FILE}"
    echo ""
  else
    echo "MISSING: ${UNSEAL_KEYS_FILE}"
    echo ""
  fi

  if [[ -f "${ROOT_TOKEN_JSON_FILE}" ]]; then
    echo "----- ${ROOT_TOKEN_JSON_FILE} -----"
    cat "${ROOT_TOKEN_JSON_FILE}"
    echo ""
  else
    echo "MISSING: ${ROOT_TOKEN_JSON_FILE}"
    echo ""
  fi
}



main() {
  compose_up
  wait_for_vault
  init_if_needed
  unseal_if_needed
  enable_file_audit_if_needed
  setup_postgres_pgadmin_approle_if_needed
  setup_keycloak_approle_if_needed
  setup_fastapi_approle_if_needed
  print_bootstrap_artifacts_instructions
  print_bootstrap_artifacts_contents

  # Emit JSON summary (no sensitive leakage)
  jq -n \
    --arg vault_addr "$VAULT_ADDR" \
    --arg bootstrap_dir "$BOOTSTRAP_DIR" \
    --arg unseal_keys_file "$UNSEAL_KEYS_FILE" \
    --arg root_token_file "$ROOT_TOKEN_FILE" \
    --arg root_token_json_file "$ROOT_TOKEN_JSON_FILE" \
    --arg service_name "$SERVICE_NAME" \
    --arg compose_file "$COMPOSE_FILE" \
    --arg compose_project "$COMPOSE_PROJECT" \
    --argjson pretty_output "$PRETTY_OUTPUT" \
    --argjson print_artifact_contents "$PRINT_ARTIFACT_CONTENTS" \
    --argjson enable_audit "$ENABLE_AUDIT" \
    --arg audit_path "$AUDIT_PATH" \
    --arg audit_file_path "$AUDIT_FILE_PATH" \
    --arg postgres_pgadmin_role_name "$POSTGRES_PGADMIN_ROLE_NAME" \
    --arg postgres_pgadmin_policy_name "$POSTGRES_PGADMIN_POLICY_NAME" \
    --argjson postgres_pgadmin_setup_done "$POSTGRES_PGADMIN_SETUP_DONE" \
    --arg keycloak_role_name "$KEYCLOAK_ROLE_NAME" \
    --arg keycloak_policy_name "$KEYCLOAK_POLICY_NAME" \
    --arg fastapi_role_name "$FASTAPI_ROLE_NAME" \
    --arg fastapi_policy_name "$FASTAPI_POLICY_NAME" \
    --argjson keycloak_setup_done "$KEYCLOAK_SETUP_DONE" \
    --argjson fastapi_setup_done "$FASTAPI_SETUP_DONE" \
    --argjson keycloak_setup_enabled "$SETUP_KEYCLOAK_APPROLE" \
    --argjson keycloak_setup_force "$FORCE_KEYCLOAK_APPROLE" \
    --argjson fastapi_setup_enabled "$SETUP_FASTAPI_APPROLE" \
    --argjson fastapi_setup_force "$FORCE_FASTAPI_APPROLE" \
    --argjson postgres_pgadmin_setup_enabled "$SETUP_POSTGRES_PGADMIN_APPROLE" \
    --argjson postgres_pgadmin_setup_force "$FORCE_POSTGRES_PGADMIN_APPROLE" \
    '{
      vault_addr: $vault_addr,
      compose: { project: $compose_project, file: $compose_file, service: $service_name },
      bootstrap_dir: $bootstrap_dir,
      files: {
        unseal_keys_json: $unseal_keys_file,
        root_token: $root_token_file,
        root_token_json: $root_token_json_file
      },
      pretty_output: ($pretty_output == 1),
      postgres_pgadmin_approle_bootstrap: {
        enabled: ($postgres_pgadmin_setup_enabled == 1),
        force: ($postgres_pgadmin_setup_force == 1),
        setup_done: ($postgres_pgadmin_setup_done == 1),
        role_name: $postgres_pgadmin_role_name,
        policy_name: $postgres_pgadmin_policy_name
      },
      keycloak_approle_bootstrap: {
        enabled: ($keycloak_setup_enabled == 1),
        force: ($keycloak_setup_force == 1),
        setup_done: ($keycloak_setup_done == 1),
        role_name: $keycloak_role_name,
        policy_name: $keycloak_policy_name
      },
      fastapi_approle_bootstrap: {
        enabled: ($fastapi_setup_enabled == 1),
        force: ($fastapi_setup_force == 1),
        setup_done: ($fastapi_setup_done == 1),
        role_name: $fastapi_role_name,
        policy_name: $fastapi_policy_name
      },
      print_artifact_contents: ($print_artifact_contents == 1),
      audit: { enabled: ($enable_audit == 1), path: $audit_path, file_path: $audit_file_path },
      initialized: true,
      unsealed: true
    }'
}

main
