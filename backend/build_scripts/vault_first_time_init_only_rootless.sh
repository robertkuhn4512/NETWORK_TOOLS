#!/usr/bin/env bash
# vault_first_time_init_only_rootless.sh
#
# NOTES
#   Purpose:
#     Rootless-first bootstrap for Vault in NETWORK_TOOLS:
#       1) Bring up the Vault container via docker compose (no sudo)
#       2) Initialize Vault if not initialized
#       3) Unseal Vault if sealed
#
#     This script intentionally does NOT:
#       - Enable AppRole or any other auth method
#       - Enable secrets engines (KV, etc.)
#       - Create policies/roles, write secrets, or test AppRole logins
#
#   Security:
#     This script writes unseal keys + root token to disk (0600) for the bootstrap phase.
#     Move them to your secure storage immediately, or delete once you have your operational model.
#
# HOW TO RUN
#   cd "$HOME/NETWORK_TOOLS"
#   bash backend/build_scripts/vault_first_time_init_only_rootless.sh \
#     --vault-addr https://vault_production_node:8200 \
#     --ca-cert "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt"
#
# REQUIREMENTS
#   - docker (rootless context)
#   - docker compose (plugin)
#   - bash, curl, jq
#
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage:
  vault_first_time_init_only_rootless.sh --vault-addr URL [options]

Required:
  --vault-addr URL                Vault address (e.g., https://vault_production_node:8200)

Optional TLS:
  --namespace NS                  Vault namespace (Enterprise/HCP)
  --ca-cert PATH                  CA bundle PEM for HTTPS verification (recommended)

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

Pretty output:
  --no-pretty-output              Disable pretty JSON formatting (writes unseal_keys.json compact)
  --no-print-artifact-contents    Do NOT print the contents of the key/token JSON files to the terminal

Debug:
  --debug                         Verbose flow logging
  --debug-http                    curl -v

EOF
}

# -------------------- Defaults --------------------
VAULT_ADDR=""
VAULT_NAMESPACE="${VAULT_NAMESPACE:-}"
CA_CERT=""

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

# -------------------- Parser helpers --------------------
_require_val() { [[ -n "${2-}" && "${2:0:1}" != "-" ]] || { echo "ERROR: Missing value for $1" >&2; exit 2; }; }
_set_opt() {
  local opt="$1" tok="$2" next="${3-}" var="$4"
  if [[ "$tok" == "$opt="* ]]; then printf -v "$var" '%s' "${tok#*=}"
  else _require_val "$opt" "$next"; printf -v "$var" '%s' "$next"; return 1; fi; return 0;
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
    --no-pretty-output)                    PRETTY_OUTPUT=0; shift ;;
    --no-print-artifact-contents)         PRINT_ARTIFACT_CONTENTS=0; shift ;;

    --debug)                               VERBOSE=1; shift ;;
    --debug-http)                          HTTP_DEBUG=1; shift ;;

    -*) echo "ERROR: Unknown option: $1" >&2; usage; exit 2 ;;
    *)  echo "ERROR: Unexpected positional argument: $1" >&2; usage; exit 2 ;;
  esac
done

[[ -n "$VAULT_ADDR" ]] || { echo "ERROR: --vault-addr is required" >&2; exit 2; }

VAULT_ADDR="${VAULT_ADDR%/}"
COMPOSE_FILE="${COMPOSE_FILE:-$COMPOSE_FILE_DEFAULT}"

UNSEAL_KEYS_FILE="${UNSEAL_KEYS_FILE:-$BOOTSTRAP_DIR/unseal_keys.json}"
ROOT_TOKEN_FILE="${ROOT_TOKEN_FILE:-$BOOTSTRAP_DIR/root_token}"
ROOT_TOKEN_JSON_FILE="${ROOT_TOKEN_JSON_FILE:-$BOOTSTRAP_DIR/root_token.json}"

command -v docker >/dev/null 2>&1 || { echo "ERROR: docker is required" >&2; exit 3; }
command -v curl  >/dev/null 2>&1 || { echo "ERROR: curl is required"  >&2; exit 3; }
command -v jq    >/dev/null 2>&1 || { echo "ERROR: jq is required"    >&2; exit 3; }

log() { echo "INFO: $*" >&2; }
dbg() { (( VERBOSE )) && echo "DEBUG: $*" >&2 || true; }
die() { echo "ERROR: $*" >&2; exit 1; }

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
  local -a args=("${CURL_COMMON[@]}" "${CURL_TLS_ARGS[@]}" "${NS_HDR[@]}" -X "$method")
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
  set -e

  HTTP_CODE="${body_and_code##*$'\n'}"
  RESP_JSON="${body_and_code%$'\n'$HTTP_CODE}"
  dbg "public $method $path -> http=$HTTP_CODE rc=$rc"

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
  log "Waiting for Vault endpoint: ${VAULT_ADDR}"
  while (( SECONDS < deadline )); do
    request_public GET "/v1/sys/health"
    # 200 = active, 429 = standby, 501 = not init, 503 = sealed
    if [[ "$HTTP_CODE" =~ ^(200|429|501|503)$ ]]; then
      return 0
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
      print_artifact_contents: ($print_artifact_contents == 1),
      initialized: true,
      unsealed: true
    }'
}

main
