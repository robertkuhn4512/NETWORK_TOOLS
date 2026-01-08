#!/usr/bin/env bash
# vault_unseal_kv_seed_bootstrap_rootless.sh
#
# NOTES / HOW TO RUN
# -----------------------------------------------------------------------------
# Goal:
#   - Unseal Vault if sealed (using Shamir unseal keys in unseal_keys.json)
#   - Optionally enable a KV mount (v1 or v2) and apply KV v2 config options
#   - Optionally seed secrets from a JSON template file into that KV mount
#   - Optionally pretty-print seeded secrets AND/OR write a resolved artifact
#
# How to run (examples):
#
# 1) Unseal only (will skip if already unsealed):
#   bash ./backend/helper_scripts/vault_unseal_kv_seed_bootstrap_rootless.sh \
#     --vault-addr "https://vault_production_node:8200" \
#     --ca-cert "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt"
#
# 2) Unseal (if needed) + create KV v2 mount + seed secrets:
#   bash ./backend/helper_scripts/vault_unseal_kv_seed_bootstrap_rootless.sh \
#     --vault-addr "https://vault_production_node:8200" \
#     --ca-cert "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt" \
#     --unseal-required 3 \
#     --create-kv "app_secrets" \
#     --kv-version 2 \
#     --kv-description "Network Tools app secrets (dev)" \
#     --kv-max-versions 20 \
#     --kv-cas-required true \
#     --kv-delete-version-after 0s \
#     --prompt-token \
#     --secrets-json "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/seed_secrets.template.json" \
#     --secrets-prefix "bootstrap" \
#     --print-secrets
#
# Security notes:
#   - Resolved secrets can be printed with --print-secrets (use with caution).
#   - Resolved secrets are written to an artifact file under bootstrap/ so you
#     can download and store securely elsewhere.
#
# -----------------------------------------------------------------------------

set -Eeuo pipefail

# -----------------------------
# Defaults
# -----------------------------
VAULT_ADDR_DEFAULT="https://vault_production_node:8200"
BOOTSTRAP_DIR_DEFAULT="$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap"

VAULT_ADDR="$VAULT_ADDR_DEFAULT"
BOOTSTRAP_DIR="$BOOTSTRAP_DIR_DEFAULT"

CA_CERT=""
AUTO_INSECURE_FALLBACK=0

UNSEAL_KEYS_FILE=""
UNSEAL_REQUIRED=""  # integer, optional override; if empty will use seal-status .t when available
NO_UNSEAL=0

TOKEN_FILE=""
TOKEN_VALUE=""
PROMPT_TOKEN=0

CREATE_KV_PATH=""
KV_VERSION="2"
KV_DESCRIPTION=""
KV_MAX_VERSIONS=""
KV_CAS_REQUIRED=""
KV_DELETE_VERSION_AFTER=""

# Seeding
KV_MOUNT_PATH=""       # if seeding without --create-kv
SECRETS_JSON=""
SECRETS_PREFIX=""
SECRETS_CAS="0"        # KV v2 CAS default
SECRETS_DRY_RUN=0
PRINT_SECRETS=0
OUTPUT_SECRETS_FILE="" # default derived per mount
OUTPUT_FORMAT="pretty" # pretty|compact

# Utility
LIST_MOUNTS=0
VERBOSE=0

# -----------------------------
# Logging / helpers
# -----------------------------
log()  { printf '%s\n' "$*" >&2; }
dbg()  { if (( VERBOSE )); then log "DEBUG: $*"; fi; }
die()  { log "ERROR: $*"; exit 1; }

need_cmd() { command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"; }

trim_slashes() { local s="$1"; s="${s#/}"; s="${s%/}"; printf '%s' "$s"; }

join_path() {
  local a="${1:-}" b="${2:-}"
  a="$(trim_slashes "$a")"
  b="$(trim_slashes "$b")"
  if [[ -z "$a" ]]; then printf '%s' "$b"; return 0; fi
  if [[ -z "$b" ]]; then printf '%s' "$a"; return 0; fi
  printf '%s/%s' "$a" "$b"
}

set_secure_umask() { umask 077; }

# -----------------------------
# Random generation helpers
# -----------------------------
have_openssl=0
have_python=0
command -v openssl >/dev/null 2>&1 && have_openssl=1
command -v python3 >/dev/null 2>&1 && have_python=1

gen_hex() {
  local bytes="${1:-32}"
  if (( have_openssl )); then openssl rand -hex "$bytes" | tr -d '\n'; return 0; fi
  if (( have_python )); then
    python3 - <<PY
import secrets
print(secrets.token_hex(int("${bytes}")))
PY
    return 0
  fi
  die "Need openssl or python3 to generate secrets."
}

gen_base64() {
  local bytes="${1:-32}"
  if (( have_openssl )); then openssl rand -base64 "$bytes" | tr -d '\n'; return 0; fi
  if (( have_python )); then
    python3 - <<PY
import os, base64
print(base64.b64encode(os.urandom(int("${bytes}"))).decode("ascii"))
PY
    return 0
  fi
  die "Need openssl or python3 to generate secrets."
}

gen_urlsafe() {
  local bytes="${1:-32}"
  if (( have_python )); then
    python3 - <<PY
import secrets
print(secrets.token_urlsafe(int("${bytes}")))
PY
    return 0
  fi
  gen_base64 "$bytes"
}

gen_uuid() {
  if command -v uuidgen >/dev/null 2>&1; then uuidgen | tr '[:upper:]' '[:lower:]'; return 0; fi
  if (( have_python )); then
    python3 - <<PY
import uuid
print(str(uuid.uuid4()))
PY
    return 0
  fi
  die "Need uuidgen or python3 to generate UUID."
}

# -----------------------------
# TLS + HTTP handling
# -----------------------------
CURL_COMMON=(-sS --connect-timeout 5 --max-time 25)
CURL_TLS_ARGS=()
NS_HDR=(-H "Accept: application/json")

RESP_JSON=""
HTTP_CODE=""

request_public() {
  local method="$1" path="$2" body="${3-}"
  local url="${VAULT_ADDR}${path}"

  local -a args=("${CURL_COMMON[@]}" "${CURL_TLS_ARGS[@]}" "${NS_HDR[@]}" -X "$method")
  if [[ -n "$body" ]]; then args+=(-H "Content-Type: application/json" -d "$body"); fi

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
    local err
    err="$(cat "$stderr_tmp" 2>/dev/null || true)"
    log "WARN: TLS verification failed using system trust store (no --ca-cert provided)."
    [[ -n "$err" ]] && log "WARN: curl error: ${err//$'\n'/ | }"
    log "WARN: Retrying with -k (insecure). Provide --ca-cert <ca.crt> for proper verification."
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

request_priv() {
  local method="$1" path="$2" token="$3" body="${4-}"
  local url="${VAULT_ADDR}${path}"
  [[ -n "$token" ]] || die "Internal: request_priv called with empty token"

  local -a args=("${CURL_COMMON[@]}" "${CURL_TLS_ARGS[@]}" "${NS_HDR[@]}" -H "X-Vault-Token: $token" -X "$method")
  if [[ -n "$body" ]]; then args+=(-H "Content-Type: application/json" -d "$body"); fi

  local stderr_tmp body_and_code rc
  stderr_tmp="$(mktemp)"
  set +e
  body_and_code="$(curl "${args[@]}" "$url" -w $'\n%{http_code}' 2>"$stderr_tmp")"
  rc=$?
  set -e

  HTTP_CODE="${body_and_code##*$'\n'}"
  RESP_JSON="${body_and_code%$'\n'$HTTP_CODE}"
  dbg "priv $method $path -> http=$HTTP_CODE rc=$rc"

  rm -f "$stderr_tmp" 2>/dev/null || true
}

# -----------------------------
# Usage
# -----------------------------
usage() {
  cat <<'EOF'
Usage:
  vault_unseal_kv_seed_bootstrap_rootless.sh [options]

Core:
  --vault-addr URL               Vault base URL (default: https://vault_production_node:8200)
  --ca-cert PATH                 CA cert to verify Vault TLS (recommended for local CA)
  -v, --verbose                  Verbose debug logging

Unseal:
  --bootstrap-dir PATH           Bootstrap dir (default: $HOME/NETWORK_TOOLS/.../vault/bootstrap)
  --unseal-keys PATH             Unseal keys JSON (default: <bootstrap-dir>/unseal_keys.json)
  --unseal-required N            Require at least N keys (and only try N keys). If omitted, uses seal-status .t when available.
  --no-unseal                    Skip unseal

Token (for enable/seed/list):
  --token VALUE                  Token value
  --token-file PATH              Token file (plaintext or JSON; defaults under bootstrap dir)
  --prompt-token                 Prompt for token if none found

KV mount:
  --create-kv PATH               Enable KV engine at PATH (e.g. app_secrets)
  --kv-version {1|2}             KV version (default: 2)
  --kv-description TEXT          Mount description
  --kv-max-versions N            (KV v2) Max versions to keep
  --kv-cas-required {true|false} (KV v2) Require CAS
  --kv-delete-version-after D    (KV v2) e.g. 0s, 24h

Seeding:
  --kv-mount PATH                Mount to seed into (defaults to --create-kv)
  --secrets-json PATH            Secrets template JSON to write (MUST be valid JSON; test with: jq . file)
  --secrets-prefix PATH          Optional prefix under mount
  --secrets-cas N                (KV v2) CAS to use on writes (default: 0)
  --secrets-dry-run              Only show what would be written (paths only)
  --print-secrets                Pretty-print resolved secrets to terminal (SENSITIVE)
  --output-secrets-file PATH     Where to store resolved secrets artifact (default: <bootstrap-dir>/seeded_secrets_<mount>.json)
  --output-format {pretty|compact} File format (default: pretty)

Utility:
  --list-mounts                  List mounts (requires token)

Secrets template formats:
  A) Map of secret paths -> data object (recommended):
     {
       "app/config": { "username": "u", "password": {"generate":{"type":"url_safe","bytes":32}} },
       "jwt": { "secret": {"generate":{"type":"hex","bytes":32}} }
     }

  B) List form:
     [
       {"path":"app/config","data":{"username":"u","password":{"generate":{"type":"base64","bytes":32}}}, "cas":0}
     ]

Supported generators:
  - hex (bytes)
  - base64 (bytes)
  - url_safe (bytes)
  - uuid

ENV injection (optional):
  {"env":"ENV_VAR_NAME"} or {"env":"ENV_VAR_NAME","optional":true}

EOF
}

# -----------------------------
# Arg parsing
# -----------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --vault-addr) VAULT_ADDR="${2:?missing}"; shift 2 ;;
    --ca-cert) CA_CERT="${2:?missing}"; shift 2 ;;
    --bootstrap-dir) BOOTSTRAP_DIR="${2:?missing}"; shift 2 ;;
    --unseal-keys) UNSEAL_KEYS_FILE="${2:?missing}"; shift 2 ;;
    --unseal-required) UNSEAL_REQUIRED="${2:?missing}"; shift 2 ;;
    --no-unseal) NO_UNSEAL=1; shift ;;
    --token) TOKEN_VALUE="${2:?missing}"; shift 2 ;;
    --token-file) TOKEN_FILE="${2:?missing}"; shift 2 ;;
    --prompt-token) PROMPT_TOKEN=1; shift ;;
    --create-kv) CREATE_KV_PATH="${2:?missing}"; shift 2 ;;
    --kv-version) KV_VERSION="${2:?missing}"; shift 2 ;;
    --kv-description) KV_DESCRIPTION="${2:?missing}"; shift 2 ;;
    --kv-max-versions) KV_MAX_VERSIONS="${2:?missing}"; shift 2 ;;
    --kv-cas-required) KV_CAS_REQUIRED="${2:?missing}"; shift 2 ;;
    --kv-delete-version-after) KV_DELETE_VERSION_AFTER="${2:?missing}"; shift 2 ;;
    --kv-mount) KV_MOUNT_PATH="${2:?missing}"; shift 2 ;;
    --secrets-json) SECRETS_JSON="${2:?missing}"; shift 2 ;;
    --secrets-prefix) SECRETS_PREFIX="${2:?missing}"; shift 2 ;;
    --secrets-cas) SECRETS_CAS="${2:?missing}"; shift 2 ;;
    --secrets-dry-run) SECRETS_DRY_RUN=1; shift ;;
    --print-secrets) PRINT_SECRETS=1; shift ;;
    --output-secrets-file) OUTPUT_SECRETS_FILE="${2:?missing}"; shift 2 ;;
    --output-format) OUTPUT_FORMAT="${2:?missing}"; shift 2 ;;
    --list-mounts) LIST_MOUNTS=1; shift ;;
    -v|--verbose) VERBOSE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown argument: $1 (use --help)" ;;
  esac
done

need_cmd curl
need_cmd jq

[[ "$VAULT_ADDR" =~ ^https?:// ]] || die "--vault-addr must start with http:// or https://"

if [[ -z "$UNSEAL_KEYS_FILE" ]]; then
  UNSEAL_KEYS_FILE="$BOOTSTRAP_DIR/unseal_keys.json"
fi

if [[ -z "$TOKEN_FILE" ]]; then
  if [[ -f "$BOOTSTRAP_DIR/root_token" ]]; then
    TOKEN_FILE="$BOOTSTRAP_DIR/root_token"
  elif [[ -f "$BOOTSTRAP_DIR/root_token.json" ]]; then
    TOKEN_FILE="$BOOTSTRAP_DIR/root_token.json"
  fi
fi

# TLS args
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

# -----------------------------
# Vault helpers
# -----------------------------
vault_status_json() {
  request_public GET "/v1/sys/seal-status"
  if [[ "$HTTP_CODE" == "404" || -z "$RESP_JSON" ]]; then
    request_public GET "/v1/sys/health"
  fi
  [[ -n "$RESP_JSON" ]] || die "No response from Vault at $VAULT_ADDR"
}

vault_is_sealed() {
  vault_status_json
  if ! jq -e 'has("sealed")' >/dev/null 2>&1 <<<"$RESP_JSON"; then
    log "Vault status response (HTTP $HTTP_CODE):"
    log "$RESP_JSON"
    die "Vault response did not contain .sealed; check VAULT_ADDR and TLS."
  fi

  local sealed
  sealed="$(jq -r '.sealed' <<<"$RESP_JSON" 2>/dev/null || true)"
  if [[ "$sealed" != "true" && "$sealed" != "false" ]]; then
    log "Vault status response (HTTP $HTTP_CODE):"
    log "$RESP_JSON"
    die "Vault .sealed was not boolean; check VAULT_ADDR and TLS."
  fi
  printf '%s' "$sealed"
}

vault_threshold_t() {
  vault_status_json
  local t
  t="$(jq -r '.t // empty' <<<"$RESP_JSON" 2>/dev/null || true)"
  [[ "$t" =~ ^[0-9]+$ ]] && printf '%s' "$t" || true
}

read_unseal_keys() {
  local f="$1"
  [[ -f "$f" && -r "$f" ]] || die "Unseal keys file not found or unreadable: $f"

  local keys
  keys="$(jq -er '
    if (.keys? and (.keys|type)=="array") then .keys
    elif (.keys_base64? and (.keys_base64|type)=="array") then .keys_base64
    elif (.unseal_keys_b64? and (.unseal_keys_b64|type)=="array") then .unseal_keys_b64
    elif (.unseal_keys_hex? and (.unseal_keys_hex|type)=="array") then .unseal_keys_hex
    else empty end
    | .[]
  ' "$f" 2>/dev/null || true)"

  [[ -n "$keys" ]] || die "Could not find unseal keys array in: $f"
  mapfile -t UNSEAL_KEYS <<<"$keys"
  (( ${#UNSEAL_KEYS[@]} > 0 )) || die "Parsed 0 unseal keys from $f"
}

validate_unseal_key_count() {
  local required="$1" have="$2"
  [[ -z "$required" ]] && return 0
  [[ "$required" =~ ^[0-9]+$ ]] || die "--unseal-required must be an integer"
  if (( have < required )); then
    die "Not enough unseal keys available. Required=${required}, have=${have}. Aborting."
  fi
}

read_token_from_file() {
  [[ -n "${TOKEN_FILE:-}" ]] || return 1
  [[ -f "$TOKEN_FILE" && -r "$TOKEN_FILE" ]] || return 1
  if [[ "$TOKEN_FILE" == *.json ]]; then
    TOKEN_VALUE="$(jq -er '.root_token // .token // .auth.client_token' "$TOKEN_FILE" 2>/dev/null || true)"
  else
    TOKEN_VALUE="$(tr -d '\r\n' <"$TOKEN_FILE" || true)"
  fi
  [[ -n "$TOKEN_VALUE" ]] || return 1
  return 0
}

ensure_token() {
  [[ -n "$TOKEN_VALUE" ]] && return 0
  if read_token_from_file; then return 0; fi
  if (( PROMPT_TOKEN )); then
    log "INFO: Token not found in default locations; prompting..."
    read -rsp "Enter Vault token: " TOKEN_VALUE
    echo >&2
    [[ -n "$TOKEN_VALUE" ]] || die "No token provided."
    return 0
  fi
  return 1
}

vault_unseal_if_needed() {
  local sealed
  sealed="$(vault_is_sealed)"

  if [[ "$sealed" == "false" ]]; then
    log "INFO: Vault is already unsealed. Skipping unseal."
    return 0
  fi

  log "INFO: Vault is sealed. Attempting unseal..."
  read_unseal_keys "$UNSEAL_KEYS_FILE"

  local required="$UNSEAL_REQUIRED"
  if [[ -z "$required" ]]; then
    required="$(vault_threshold_t || true)"
  fi

  validate_unseal_key_count "$required" "${#UNSEAL_KEYS[@]}"

  local limit="${#UNSEAL_KEYS[@]}"
  if [[ -n "$required" && "$required" =~ ^[0-9]+$ ]]; then
    limit="$required"
  fi

  local i key body sealed_now progress tval
  for (( i=0; i<limit; i++ )); do
    key="${UNSEAL_KEYS[$i]}"
    body="$(jq -cn --arg k "$key" '{key:$k}')"
    request_public POST "/v1/sys/unseal" "$body"

    sealed_now="$(jq -r '.sealed // empty' <<<"$RESP_JSON" 2>/dev/null || true)"
    progress="$(jq -r '.progress // empty' <<<"$RESP_JSON" 2>/dev/null || true)"
    tval="$(jq -r '.t // empty' <<<"$RESP_JSON" 2>/dev/null || true)"

    if [[ "$sealed_now" == "true" && -n "$progress" && -n "$tval" ]]; then
      log "INFO: Unseal progress: ${progress}/${tval}"
    fi

    if [[ "$sealed_now" == "false" ]]; then
      log "INFO: Vault is now unsealed."
      return 0
    fi
  done

  sealed_now="$(vault_is_sealed)"
  [[ "$sealed_now" == "false" ]] && { log "INFO: Vault is now unsealed."; return 0; }

  die "Tried ${limit} keys but Vault is still sealed."
}

list_mounts() {
  local token="$1"
  request_priv GET "/v1/sys/mounts" "$token"
  [[ "$HTTP_CODE" == "200" ]] || die "Failed to list mounts (HTTP $HTTP_CODE)."
  log "INFO: Vault mounts:"
  jq -r 'keys[]' <<<"$RESP_JSON" | sort >&2
}

kv_mount_exists() {
  local token="$1" mount="$2"
  request_priv GET "/v1/sys/mounts" "$token"
  jq -e --arg k "${mount}/" 'has($k)' <<<"$RESP_JSON" >/dev/null 2>&1
}

kv_mount_version() {
  local token="$1" mount="$2"
  request_priv GET "/v1/sys/mounts" "$token"
  jq -r --arg k "${mount}/" '.[$k].options.version // "2"' <<<"$RESP_JSON" 2>/dev/null || printf '2'
}

kv_enable_mount() {
  local token="$1" mount="$2" version="$3" desc="$4"
  [[ "$version" == "1" || "$version" == "2" ]] || die "--kv-version must be 1 or 2"
  local body
  if [[ -n "$desc" ]]; then
    body="$(jq -cn --arg v "$version" --arg d "$desc" '{type:"kv",options:{version:$v},description:$d}')"
  else
    body="$(jq -cn --arg v "$version" '{type:"kv",options:{version:$v}}')"
  fi
  request_priv POST "/v1/sys/mounts/${mount}" "$token" "$body"
  [[ "$HTTP_CODE" == "204" ]] || die "Failed to enable KV mount at ${mount} (HTTP $HTTP_CODE): $RESP_JSON"
  log "INFO: Enabled KV v${version} at ${mount}/"
}

kv_configure_v2() {
  local token="$1" mount="$2"
  local body='{}' changed=0

  if [[ -n "$KV_MAX_VERSIONS" ]]; then
    body="$(jq -c --argjson n "$KV_MAX_VERSIONS" '. + {max_versions:$n}' <<<"$body")"
    changed=1
  fi

  if [[ -n "$KV_CAS_REQUIRED" ]]; then
    local b
    case "$KV_CAS_REQUIRED" in
      true|TRUE|1|yes|YES) b=true ;;
      false|FALSE|0|no|NO) b=false ;;
      *) die "--kv-cas-required must be true/false" ;;
    esac
    body="$(jq -c --argjson b "$b" '. + {cas_required:$b}' <<<"$body")"
    changed=1
  fi

  if [[ -n "$KV_DELETE_VERSION_AFTER" ]]; then
    body="$(jq -c --arg d "$KV_DELETE_VERSION_AFTER" '. + {delete_version_after:$d}' <<<"$body")"
    changed=1
  fi

  (( changed )) || return 0
  request_priv POST "/v1/${mount}/config" "$token" "$body"
  [[ "$HTTP_CODE" == "204" ]] || die "Failed to configure KV v2 options (HTTP $HTTP_CODE): $RESP_JSON"
  log "INFO: Applied KV v2 config at ${mount}/config"
}

# -----------------------------
# Secrets template resolution + seeding
# -----------------------------
normalize_secret_items() {
  local f="$1"
  [[ -f "$f" && -r "$f" ]] || die "Secrets JSON not found or unreadable: $f"

  jq -e . "$f" >/dev/null 2>&1 || die "Secrets file is not valid JSON: $f (test with: jq . \"$f\")"

  jq -cr '
    def item(p; d; c): {path:p, data:d, cas:(c//0)};
    if type=="object" and has("path") and has("data") then
      item(.path; .data; (.cas//0))
    elif type=="array" then
      .[] | select(type=="object" and has("path") and has("data")) | item(.path; .data; (.cas//0))
    elif type=="object" then
      # Map format: {"path1": {...}, "path2": {...}}
      # Reject scalars/arrays/etc. to avoid silently writing empty secrets.
      if any(to_entries[]; (.value|type)!="object") then
        error("Invalid secrets template: map values must be JSON objects. Example: { \"creds\": { \"un\": \"user\", \"pw\": \"pass\" } }")
      else
        to_entries[] | item(.key; .value; 0)
      end
    else
      empty
    end
  ' "$f"
}

resolve_value() {
  local v="$1"

  if jq -e 'type=="object" and has("generate")' >/dev/null 2>&1 <<<"$v"; then
    local t bytes
    t="$(jq -r '.generate.type // "url_safe"' <<<"$v")"
    bytes="$(jq -r '.generate.bytes // 32' <<<"$v")"
    case "$t" in
      hex)        jq -Rn --arg s "$(gen_hex "$bytes")" '$s' ;;
      base64)     jq -Rn --arg s "$(gen_base64 "$bytes")" '$s' ;;
      url_safe|urlsafe|url-safe) jq -Rn --arg s "$(gen_urlsafe "$bytes")" '$s' ;;
      uuid)       jq -Rn --arg s "$(gen_uuid)" '$s' ;;
      *) die "Unsupported generator type: $t (supported: hex, base64, url_safe, uuid)" ;;
    esac
    return 0
  fi

  if jq -e 'type=="object" and has("env")' >/dev/null 2>&1 <<<"$v"; then
    local envname optional ev
    envname="$(jq -r '.env' <<<"$v")"
    optional="$(jq -r '.optional // false' <<<"$v")"
    ev="${!envname:-}"
    if [[ -z "$ev" ]]; then
      if [[ "$optional" == "true" ]]; then printf 'null'; return 0; fi
      die "Required env var not set: $envname"
    fi
    jq -Rn --arg s "$ev" '$s'
    return 0
  fi

  printf '%s' "$v"
}

resolve_secret_item() {
  local item="$1"
  local path cas data keys resolved
  path="$(jq -r '.path' <<<"$item")"
  cas="$(jq -r '.cas // 0' <<<"$item")"
  data="$(jq -c '.data' <<<"$item")"
  # Data must be an object (KV expects a JSON object of key/value pairs)
  if ! jq -e 'type=="object"' >/dev/null 2>&1 <<<"$data"; then
    die "Secrets template item data for path \"$path\" must be a JSON object (key/value map).\nFix your template. Example:\n{ \"creds\": { \"un\": \"something\", \"pw\": \"password\" } }"
  fi
  [[ -n "$path" && "$path" != "null" ]] || die "Secrets item missing .path"

  resolved='{}'
  mapfile -t keys < <(jq -r 'keys[]' <<<"$data" 2>/dev/null || true)

  local k raw rv
  for k in "${keys[@]}"; do
    raw="$(jq -c --arg k "$k" '.[$k]' <<<"$data")"
    rv="$(resolve_value "$raw")"
    [[ "$rv" == "null" ]] && continue
    resolved="$(jq -c --arg k "$k" --argjson v "$rv" '. + {($k): $v}' <<<"$resolved")"
  done

  jq -cn --arg p "$path" --argjson d "$resolved" --argjson c "$cas" '{path:$p, data:$d, cas:$c}'
}

kv_put_v1() {
  local token="$1" mount="$2" p="$3" data_json="$4"
  request_priv POST "/v1/${mount}/$(trim_slashes "$p")" "$token" "$data_json"
  [[ "$HTTP_CODE" == "200" || "$HTTP_CODE" == "204" ]]
}

kv_put_v2() {
  local token="$1" mount="$2" p="$3" data_json="$4" cas="$5"
  local body
  body="$(jq -cn --argjson d "$data_json" --argjson c "$cas" '{data:$d, options:{cas:$c}}')"
  request_priv POST "/v1/${mount}/data/$(trim_slashes "$p")" "$token" "$body"
  [[ "$HTTP_CODE" == "200" || "$HTTP_CODE" == "204" ]]
}

write_artifact_file() {
  local file="$1" json="$2"
  set_secure_umask
  mkdir -p "$(dirname "$file")"

  if [[ "$OUTPUT_FORMAT" == "compact" ]]; then
    printf '%s\n' "$json" >"$file"
  else
    jq '.' <<<"$json" >"$file"
  fi

  chmod 600 "$file" 2>/dev/null || true
}

seed_secrets() {
  local token="$1" mount="$2" prefix="$3" secrets_file="$4"
  local mount_version
  mount_version="$(kv_mount_version "$token" "$mount")"
  [[ "$mount_version" == "1" || "$mount_version" == "2" ]] || mount_version="2"

  log "INFO: Seeding secrets into ${mount}/ (KV v${mount_version})"
  [[ -n "$prefix" ]] && log "INFO: Using prefix: $(trim_slashes "$prefix")/"
  log "INFO: Template file: $secrets_file"

  local resolved_items='[]'
  local ok=0 fail=0

  while IFS= read -r item; do
    [[ -n "$item" ]] || continue

    local resolved path data cas full_path
    resolved="$(resolve_secret_item "$item")"
    path="$(jq -r '.path' <<<"$resolved")"
    data="$(jq -c '.data' <<<"$resolved")"
    cas="$(jq -r '.cas' <<<"$resolved")"
    full_path="$(join_path "$prefix" "$path")"

    resolved_items="$(jq -c --arg p "$full_path" --argjson d "$data" '. + [{path:$p,data:$d}]' <<<"$resolved_items")"

    if (( SECRETS_DRY_RUN )); then
      log "DRY-RUN: would write -> ${mount}/$(trim_slashes "$full_path")"
      ok=$((ok+1))
      continue
    fi

    if [[ "$mount_version" == "2" ]]; then
      local cas_eff="$SECRETS_CAS"
      [[ -n "$cas" && "$cas" != "null" ]] && cas_eff="$cas"
      if kv_put_v2 "$token" "$mount" "$full_path" "$data" "$cas_eff"; then
        log "INFO: wrote -> ${mount}/$(trim_slashes "$full_path")"
        ok=$((ok+1))
      else
        log "WARN: failed -> ${mount}/$(trim_slashes "$full_path") (HTTP $HTTP_CODE)"
        dbg "$RESP_JSON"
        fail=$((fail+1))
      fi
    else
      if kv_put_v1 "$token" "$mount" "$full_path" "$data"; then
        log "INFO: wrote -> ${mount}/$(trim_slashes "$full_path")"
        ok=$((ok+1))
      else
        log "WARN: failed -> ${mount}/$(trim_slashes "$full_path") (HTTP $HTTP_CODE)"
        dbg "$RESP_JSON"
        fail=$((fail+1))
      fi
    fi
  done < <(normalize_secret_items "$secrets_file")

  log "INFO: Secret seeding complete. success=${ok} failed=${fail}"
  (( fail == 0 )) || die "One or more secrets failed to write."

  local artifact
  artifact="$(jq -cn \
    --arg vault_addr "$VAULT_ADDR" \
    --arg mount "$mount" \
    --arg prefix "$(trim_slashes "$prefix")" \
    --arg created_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --argjson secrets "$resolved_items" \
    '{vault_addr:$vault_addr, mount:$mount, prefix:$prefix, created_at:$created_at, secrets:$secrets}')"

  if [[ -z "$OUTPUT_SECRETS_FILE" ]]; then
    local safe_mount
    safe_mount="$(trim_slashes "$mount")"
    OUTPUT_SECRETS_FILE="$BOOTSTRAP_DIR/seeded_secrets_${safe_mount}.json"
  fi

  write_artifact_file "$OUTPUT_SECRETS_FILE" "$artifact"
  log "INFO: Wrote resolved secrets artifact:"
  log "      $OUTPUT_SECRETS_FILE"

  if (( PRINT_SECRETS )); then
    log ""
    log "==================== RESOLVED SECRETS (SENSITIVE) ===================="
    log "WARN: The following output contains secret values. Copy/store securely."
    jq '.' <<<"$artifact" >&2
    log "======================================================================"
    log ""
  else
    log "INFO: (Not printing secrets; use --print-secrets to print.)"
  fi

  log "INFO: Recommended next steps:"
  log "  1) Securely download required artifacts (examples):"
  log "     scp -p <user>@<server>:\"$OUTPUT_SECRETS_FILE\" ."
  log "     scp -p <user>@<server>:\"$BOOTSTRAP_DIR/unseal_keys.json\" ."
  log "     scp -p <user>@<server>:\"$BOOTSTRAP_DIR/root_token\" ."
  log "     scp -p <user>@<server>:\"$BOOTSTRAP_DIR/root_token.json\" ."
  log "  2) After verifying downloads, remove sensitive files from the server:"
  log "     rm -f \"$OUTPUT_SECRETS_FILE\" \"$BOOTSTRAP_DIR/unseal_keys.json\" \"$BOOTSTRAP_DIR/root_token\" \"$BOOTSTRAP_DIR/root_token.json\""
}

# -----------------------------
# Main
# -----------------------------
log "INFO: Vault address: $VAULT_ADDR"
log "INFO: Bootstrap dir: $BOOTSTRAP_DIR"
log "INFO: Unseal keys file: $UNSEAL_KEYS_FILE"
if [[ -n "$CA_CERT" ]]; then
  log "INFO: CA cert: $CA_CERT"
else
  [[ "$VAULT_ADDR" =~ ^https:// ]] && log "WARN: No --ca-cert provided for HTTPS. Will try system trust; may fall back to -k."
fi

if (( ! NO_UNSEAL )); then
  vault_unseal_if_needed
else
  log "INFO: --no-unseal specified; skipping unseal."
fi

if [[ -z "$KV_MOUNT_PATH" && -n "$CREATE_KV_PATH" ]]; then
  KV_MOUNT_PATH="$CREATE_KV_PATH"
fi

if [[ -n "$CREATE_KV_PATH" || -n "$SECRETS_JSON" || $LIST_MOUNTS -eq 1 ]]; then
  ensure_token || die "Token not available. Provide:
  - --token <value>
  - --token-file <path>
  - --prompt-token
Default expected token files:
  $BOOTSTRAP_DIR/root_token
  $BOOTSTRAP_DIR/root_token.json"
fi

if (( LIST_MOUNTS )); then
  list_mounts "$TOKEN_VALUE"
fi

if [[ -n "$CREATE_KV_PATH" ]]; then
  mount="$(trim_slashes "$CREATE_KV_PATH")"
  [[ -n "$mount" ]] || die "--create-kv PATH cannot be empty"
  CREATE_KV_PATH="$mount"

  if kv_mount_exists "$TOKEN_VALUE" "$CREATE_KV_PATH"; then
    log "INFO: Mount exists at ${CREATE_KV_PATH}/. Skipping enable."
  else
    kv_enable_mount "$TOKEN_VALUE" "$CREATE_KV_PATH" "$KV_VERSION" "$KV_DESCRIPTION"
  fi

  if [[ "$KV_VERSION" == "2" ]]; then
    kv_configure_v2 "$TOKEN_VALUE" "$CREATE_KV_PATH"
  fi
fi

if [[ -n "$SECRETS_JSON" ]]; then
  [[ -n "$KV_MOUNT_PATH" ]] || die "You provided --secrets-json but no mount. Provide --kv-mount <mount> or --create-kv <mount>."
  KV_MOUNT_PATH="$(trim_slashes "$KV_MOUNT_PATH")"
  [[ -n "$KV_MOUNT_PATH" ]] || die "--kv-mount cannot be empty"

  (( PRINT_SECRETS )) && log "WARN: --print-secrets enabled. Secret values WILL be printed."

  seed_secrets "$TOKEN_VALUE" "$KV_MOUNT_PATH" "$SECRETS_PREFIX" "$SECRETS_JSON"
fi

log "INFO: Done."
