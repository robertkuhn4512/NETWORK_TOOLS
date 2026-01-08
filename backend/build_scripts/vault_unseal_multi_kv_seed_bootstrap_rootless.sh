#!/usr/bin/env bash
# vault_unseal_multi_kv_seed_bootstrap_rootless.sh
#
# NOTES / HOW TO RUN
# -----------------------------------------------------------------------------
# Purpose:
#   - Unseal Vault if sealed (This will require the unseal keys)
#   - In one run, enable/configure MULTIPLE KV mounts and seed secrets into each (This will require the root token for initial setup)
#   - Store a single consolidated artifact of resolved secrets under bootstrap/
#
# Recommended workflow:
#   1) Run your Vault init/unseal script once to create unseal keys + root token
#   2) Run THIS script to create KV mounts + seed all bootstrap secrets at once (Or use vault_unseal_kv_seed_bootstrap_rootless.sh if you only want to seed one at a time with individual files)
#
# If your URL is changed from the default dev url of vault_production_node then replace this with the new url.
#
# Example:
#   bash ./backend/helper_scripts/vault_unseal_multi_kv_seed_bootstrap_rootless.sh \
#     --vault-addr "https://vault_production_node:8200" \
#     --ca-cert "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt" \
#     --unseal-required 3 \
#     --prompt-token \
#     --spec-json "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/seed_kv_spec.json" \
#     --print-secrets
#
# Security:
#   - --print-secrets prints secret values to terminal (SENSITIVE).
#   - Resolved secrets are written to an artifact file in bootstrap/ for download;
#     after downloading, remove them from the server.
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
UNSEAL_REQUIRED=""
NO_UNSEAL=0

TOKEN_FILE=""
TOKEN_VALUE=""
PROMPT_TOKEN=0

SPEC_JSON=""
DRY_RUN=0
PRINT_SECRETS=0
OUTPUT_ARTIFACT_FILE=""
OUTPUT_FORMAT="pretty" # pretty|compact
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
CURL_COMMON=(-sS --connect-timeout 5 --max-time 30)
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
  vault_unseal_multi_kv_seed_bootstrap_rootless.sh [options]

Core:
  --vault-addr URL               Vault base URL (default: https://vault_production_node:8200)
  --ca-cert PATH                 CA cert to verify Vault TLS (recommended for local CA)
  --bootstrap-dir PATH           Bootstrap dir (default: $HOME/NETWORK_TOOLS/.../vault/bootstrap)
  --spec-json PATH               JSON spec describing mounts + secrets (required)

Unseal:
  --unseal-keys PATH             Unseal keys JSON (default: <bootstrap-dir>/unseal_keys.json)
  --unseal-required N            Require at least N keys (and only try N keys). If omitted uses seal-status .t when available.
  --no-unseal                    Skip unseal

Token:
  --token VALUE                  Token value
  --token-file PATH              Token file (plaintext or JSON; defaults under bootstrap dir)
  --prompt-token                 Prompt for token if none found

Output:
  --dry-run                      Resolve/generate secrets but do NOT write to Vault
  --print-secrets                Pretty-print resolved secrets to terminal (SENSITIVE)
  --output-artifact PATH         Consolidated artifact file path (default: <bootstrap-dir>/seeded_secrets_all.json)
  --output-format {pretty|compact}
  -v, --verbose

Spec format (recommended):
- Root should be a single JSON object. A single-element array wrapper is also accepted: [ { ... } ].
- Legacy mode is also supported: { "mounts": [...], "writes": [...] } (writes are merged into mount secrets).

{
  "mounts": [
    {
      "mount": "app_secrets",
      "version": 2,
      "description": "Network Tools app secrets (dev)",
      "v2_config": { "max_versions": 20, "cas_required": true, "delete_version_after": "0s" },
      "prefix": "bootstrap",
      "secrets": [
        { "path": "creds", "data": { "un": "something", "pw": "password" } },
        { "path": "jwt", "data": { "signing_key": { "generate": { "type":"hex", "bytes":32 } } } }
      ]
    },
    {
      "mount": "frontend_secrets",
      "version": 2,
      "prefix": "bootstrap",
      "secrets": {
        "keycloak": { "client_secret": { "generate": { "type":"url_safe", "bytes":32 } } }
      }
    }
  ]
}

Secrets "data" values support:
  - literal values (string/number/bool/object/array)
  - {"generate":{"type":"hex|base64|url_safe|uuid","bytes":N}}
  - {"env":"ENV_VAR_NAME"} or {"env":"ENV_VAR_NAME","optional":true}
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
    --spec-json) SPEC_JSON="${2:?missing}"; shift 2 ;;
    --unseal-keys) UNSEAL_KEYS_FILE="${2:?missing}"; shift 2 ;;
    --unseal-required) UNSEAL_REQUIRED="${2:?missing}"; shift 2 ;;
    --no-unseal) NO_UNSEAL=1; shift ;;
    --token) TOKEN_VALUE="${2:?missing}"; shift 2 ;;
    --token-file) TOKEN_FILE="${2:?missing}"; shift 2 ;;
    --prompt-token) PROMPT_TOKEN=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    --print-secrets) PRINT_SECRETS=1; shift ;;
    --output-artifact) OUTPUT_ARTIFACT_FILE="${2:?missing}"; shift 2 ;;
    --output-format) OUTPUT_FORMAT="${2:?missing}"; shift 2 ;;
    -v|--verbose) VERBOSE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown argument: $1 (use --help)" ;;
  esac
done

need_cmd curl
need_cmd jq

[[ "$VAULT_ADDR" =~ ^https?:// ]] || die "--vault-addr must start with http:// or https://"

[[ -n "$SPEC_JSON" ]] || die "--spec-json is required (use --help)"
[[ -f "$SPEC_JSON" && -r "$SPEC_JSON" ]] || die "Spec JSON not found or unreadable: $SPEC_JSON"
jq -e . "$SPEC_JSON" >/dev/null 2>&1 || die "Spec file is not valid JSON: $SPEC_JSON (test with: jq . \"$SPEC_JSON\")"

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
  [[ "$sealed" == "true" || "$sealed" == "false" ]] || die "Vault .sealed was not boolean; check VAULT_ADDR and TLS."
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

# -----------------------------
# KV helpers
# -----------------------------
fetch_mounts_json() {
  local token="$1"
  request_priv GET "/v1/sys/mounts" "$token"
  [[ "$HTTP_CODE" == "200" ]] || die "Failed to list mounts (HTTP $HTTP_CODE): $RESP_JSON"
  printf '%s' "$RESP_JSON"
}

kv_mount_exists() {
  local mounts_json="$1" mount="$2"
  jq -e --arg k "${mount}/" 'has($k)' <<<"$mounts_json" >/dev/null 2>&1
}

kv_mount_version() {
  local mounts_json="$1" mount="$2"
  jq -r --arg k "${mount}/" '.[$k].options.version // "2"' <<<"$mounts_json" 2>/dev/null || printf '2'
}

kv_enable_mount() {
  local token="$1" mount="$2" version="$3" desc="$4"
  [[ "$version" == "1" || "$version" == "2" ]] || die "Spec mount ${mount}: version must be 1 or 2"
  local body
  if [[ -n "$desc" && "$desc" != "null" ]]; then
    body="$(jq -cn --arg v "$version" --arg d "$desc" '{type:"kv",options:{version:$v},description:$d}')"
  else
    body="$(jq -cn --arg v "$version" '{type:"kv",options:{version:$v}}')"
  fi
  request_priv POST "/v1/sys/mounts/${mount}" "$token" "$body"
  [[ "$HTTP_CODE" == "204" ]] || die "Failed to enable KV mount at ${mount} (HTTP $HTTP_CODE): $RESP_JSON"
  log "INFO: Enabled KV v${version} at ${mount}/"
}

kv_configure_v2() {
  local token="$1" mount="$2" cfg_json="$3"
  [[ -n "$cfg_json" && "$cfg_json" != "null" ]] || return 0

  # Only send allowed keys if present
  local body='{}' changed=0

  if jq -e 'has("max_versions")' >/dev/null 2>&1 <<<"$cfg_json"; then
    body="$(jq -c '. + {max_versions:.max_versions}' <<<"$cfg_json")"
    changed=1
  fi

  # Merge cas_required, delete_version_after if present
  if jq -e 'has("cas_required")' >/dev/null 2>&1 <<<"$cfg_json"; then
    body="$(jq -c --argjson b "$(jq -r '.cas_required' <<<"$cfg_json")" '. + {cas_required:$b}' <<<"$body")" || true
    # Above can fail if cas_required isn't boolean; validate:
    jq -e '.cas_required|type=="boolean"' <<<"$cfg_json" >/dev/null 2>&1 || die "Spec mount ${mount}: v2_config.cas_required must be boolean"
    body="$(jq -c '. + {cas_required:.cas_required}' <<<"$body" <<<"$cfg_json")" 2>/dev/null || body="$body"
    changed=1
  fi

  if jq -e 'has("delete_version_after")' >/dev/null 2>&1 <<<"$cfg_json"; then
    jq -e '.delete_version_after|type=="string"' <<<"$cfg_json" >/dev/null 2>&1 || die "Spec mount ${mount}: v2_config.delete_version_after must be a string (e.g. \"0s\")"
    body="$(jq -c --arg d "$(jq -r '.delete_version_after' <<<"$cfg_json")" '. + {delete_version_after:$d}' <<<"$body")"
    changed=1
  fi

  (( changed )) || return 0
  request_priv POST "/v1/${mount}/config" "$token" "$body"
  [[ "$HTTP_CODE" == "204" ]] || die "Failed to configure KV v2 options at ${mount}/config (HTTP $HTTP_CODE): $RESP_JSON"
  log "INFO: Applied KV v2 config at ${mount}/config"
}

# -----------------------------
# Secrets resolution + writes
# -----------------------------
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

# Convert secrets for a specific mount spec into newline-delimited items:
# Each line is {"path":"...","data":{...},"cas":0}
emit_secret_items_for_mount() {
  local mount_obj="$1"

  # Determine secrets node
  local secrets_type
  secrets_type="$(jq -r '.secrets|type' <<<"$mount_obj")"

  if [[ "$secrets_type" == "array" ]]; then
    jq -cr '
      .secrets[]
      | select(type=="object" and has("path") and has("data"))
      | {path:.path, data:.data, cas:(.cas//0)}
    ' <<<"$mount_obj"
    return 0
  fi

  if [[ "$secrets_type" == "object" ]]; then
    # Map format: {"path1": {...}, "path2": {...}} (values must be objects)
    if jq -e 'any(.secrets|to_entries[]; (.value|type)!="object")' >/dev/null 2>&1 <<<"$mount_obj"; then
      die "Invalid secrets map: all values must be objects (key/value maps)."
    fi
    jq -cr '
      .secrets
      | to_entries[]
      | {path:.key, data:.value, cas:0}
    ' <<<"$mount_obj"
    return 0
  fi

  die "Spec mount secrets must be an array or object."
}

resolve_secret_item() {
  local item="$1"
  local path cas data
  path="$(jq -r '.path' <<<"$item")"
  cas="$(jq -r '.cas // 0' <<<"$item")"
  data="$(jq -c '.data' <<<"$item")"

  [[ -n "$path" && "$path" != "null" ]] || die "Secrets item missing .path"
  jq -e 'type=="object"' >/dev/null 2>&1 <<<"$data" || die "Secrets item data for path \"$path\" must be a JSON object (key/value map)."

  local resolved='{}'
  local keys
  mapfile -t keys < <(jq -r 'keys[]' <<<"$data")

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

write_file() {
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

# -----------------------------
# Spec parsing
# -----------------------------
# Supports:
#   - Preferred: {"mounts":[ ... ]} with per-mount "secrets" (array or object)
#   - Also accepted: legacy {"mounts":[ ... ], "writes":[ ... ]} (writes are merged into mount secrets)
#   - Also accepted: a single-element array wrapper: [ { ... } ]
#

normalize_spec_json() {
  # Normalizes the spec JSON into a single JSON object for consistent parsing.
  #
  # Accepted inputs:
  #   1) Preferred:
  #        { "mounts": [ { "mount": "...", "secrets": ... , ... } ] }
  #   2) Legacy (supported for backward-compatibility):
  #        { "mounts": [ ... ], "writes": [ { "mount": "...", "path": "...", "data": {...} } ] }
  #      - If a mount already has "secrets", "writes" will be appended to it.
  #      - Best practice: in legacy mode, keep write.path RELATIVE (do not include mount prefix).
  #   3) Wrapper:
  #        [ { ... } ]  (single-element array containing the object above)
  #
  # Output: pretty JSON object printed to stdout.
  local in="$1"
  [[ -f "$in" ]] || die "Spec file not found: $in"

  local raw
  raw="$(jq -c '.' "$in" 2>/dev/null)" || die "Spec file is not valid JSON: $in"

  # Unwrap single-element array wrapper: [ { ... } ]
  if jq -e 'type=="array"' >/dev/null 2>&1 <<<"$raw"; then
    jq -e 'length==1 and (.[0]|type=="object")' >/dev/null 2>&1 <<<"$raw" \
      || die "Spec root must be a JSON object (or a single-element array containing an object)."
    raw="$(jq -c '.[0]' <<<"$raw")"
  fi

  # Require an object at the root.
  jq -e 'type=="object"' >/dev/null 2>&1 <<<"$raw" || die "Spec root must be a JSON object."

  # If legacy "writes" are present, validate and merge them into per-mount secrets.
  if jq -e 'has("writes") and (.writes|type=="array") and (.writes|length>0)' >/dev/null 2>&1 <<<"$raw"; then
    # Ensure mounts exist and are an array (we'll validate non-empty later in main)
    jq -e 'has("mounts") and (.mounts|type=="array")' >/dev/null 2>&1 <<<"$raw" \
      || die "Legacy spec mode requires .mounts as an array when .writes is present."

    # Validate that every .writes[].mount is declared in .mounts[].mount (avoid silent typos)
    local unknown
    unknown="$(jq -r '
      ([.mounts[].mount] | map(select(.!=null and .!="")) | unique) as $m
      | ([.writes[].mount] | map(select(.!=null and .!="")) | unique)
      | map(select(. as $x | ($m|index($x))|not))
      | .[]?
    ' <<<"$raw")"
    if [[ -n "$unknown" ]]; then
      die "Spec .writes references mount(s) not declared in .mounts: $(tr '\n' ' ' <<<"$unknown")"
    fi

    raw="$(jq -c '
      def writes_norm:
        (.writes // []) | map({
          mount: (.mount // ""),
          path: (.path // ""),
          data: (.data // {}),
          cas: (.cas // null)
        }) | map(select(.mount != "" and .path != "" ));

      def secrets_to_array:
        if . == null then []
        elif (type=="array") then
          map({path:(.path//""), data:(.data//{}), cas:(.cas//null)}) | map(select(.path!=""))
        elif (type=="object") then
          to_entries | map({path:.key, data:(.value//{}), cas:null})
        else [] end;

      . as $root
      | (writes_norm) as $w
      | .mounts |= map(
          . as $m
          | ($m.secrets | secrets_to_array) as $existing
          | ($w | map(select(.mount == ($m.mount // ""))) | map({path:.path, data:.data, cas:.cas})) as $from_writes
          | $m + {secrets: ($existing + $from_writes)}
        )
      | del(.writes)
    ' <<<"$raw")"
  fi

  jq '.' <<<"$raw"
}

get_mount_count() {
  jq -r '.mounts | length' "$SPEC_JSON"
}

get_mount_obj_by_index() {
  local idx="$1"
  jq -c --argjson i "$idx" '.mounts[$i]' "$SPEC_JSON"
}

# -----------------------------
# Main
# -----------------------------
log "INFO: Vault address: $VAULT_ADDR"
log "INFO: Bootstrap dir: $BOOTSTRAP_DIR"
log "INFO: Spec file: $SPEC_JSON"
log "INFO: Unseal keys file: ${UNSEAL_KEYS_FILE:-$BOOTSTRAP_DIR/unseal_keys.json}"
if [[ -n "$CA_CERT" ]]; then
  log "INFO: CA cert: $CA_CERT"
else
  [[ "$VAULT_ADDR" =~ ^https:// ]] && log "WARN: No --ca-cert provided for HTTPS. Will try system trust; may fall back to -k."
fi
(( DRY_RUN )) && log "WARN: --dry-run enabled. Secrets will be resolved/generated but NOT written to Vault."
(( PRINT_SECRETS )) && log "WARN: --print-secrets enabled. Secret values WILL be printed."

if [[ -z "$OUTPUT_ARTIFACT_FILE" ]]; then
  OUTPUT_ARTIFACT_FILE="$BOOTSTRAP_DIR/seeded_secrets_all.json"
fi

if (( ! NO_UNSEAL )); then
  vault_unseal_if_needed
else
  log "INFO: --no-unseal specified; skipping unseal."
fi

ensure_token || die "Token not available. Provide:
  - --token <value>
  - --token-file <path>
  - --prompt-token
Default expected token files:
  $BOOTSTRAP_DIR/root_token
  $BOOTSTRAP_DIR/root_token.json"

# Fetch mounts once (we'll refresh if we create new mounts)
MOUNTS_JSON="$(fetch_mounts_json "$TOKEN_VALUE")"

# Validate spec shape
jq -e '(.mounts|type=="array") and (.mounts|length>0)' "$SPEC_JSON" >/dev/null 2>&1 || die "Spec must include .mounts as a non-empty array."

mount_count="$(get_mount_count)"
log "INFO: Spec mounts: $mount_count"

resolved_all='[]'
created_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

for (( idx=0; idx<mount_count; idx++ )); do
  mount_obj="$(get_mount_obj_by_index "$idx")"
  jq -e 'type=="object" and has("mount")' >/dev/null 2>&1 <<<"$mount_obj" || die "Spec mounts[$idx] must be an object with a .mount field."

  mount="$(jq -r '.mount' <<<"$mount_obj")"
  mount="$(trim_slashes "$mount")"
  [[ -n "$mount" ]] || die "Spec mounts[$idx].mount is empty."

  version="$(jq -r '.version // 2' <<<"$mount_obj")"
  desc="$(jq -r '.description // empty' <<<"$mount_obj")"
  prefix="$(jq -r '.prefix // ""' <<<"$mount_obj")"
  v2cfg="$(jq -c '.v2_config // null' <<<"$mount_obj")"

  log "INFO: --- Mount [$idx]: ${mount} (version=${version}) ---"

  if kv_mount_exists "$MOUNTS_JSON" "$mount"; then
    actual_version="$(kv_mount_version "$MOUNTS_JSON" "$mount")"
    log "INFO: Mount exists: ${mount}/ (KV v${actual_version})"
    if [[ "$actual_version" != "$version" ]]; then
      log "WARN: Spec requests KV v${version} but existing mount is KV v${actual_version}. Using existing mount version."
      version="$actual_version"
    fi
  else
    if (( DRY_RUN )); then
      log "DRY-RUN: would enable KV v${version} at ${mount}/"
    else
      kv_enable_mount "$TOKEN_VALUE" "$mount" "$version" "$desc"
      MOUNTS_JSON="$(fetch_mounts_json "$TOKEN_VALUE")"
    fi
  fi

  if [[ "$version" == "2" && "$v2cfg" != "null" ]]; then
    if (( DRY_RUN )); then
      log "DRY-RUN: would apply KV v2 config at ${mount}/config: $(jq -c '.' <<<"$v2cfg")"
    else
      kv_configure_v2 "$TOKEN_VALUE" "$mount" "$v2cfg"
    fi
  fi

  # Seed secrets
  secrets_type="$(jq -r '.secrets|type' <<<"$mount_obj")"
  [[ "$secrets_type" == "array" || "$secrets_type" == "object" ]] || die "Spec mount ${mount}: .secrets must be array or object."

  ok=0
  fail=0
  resolved_items='[]'

  while IFS= read -r item; do
    [[ -n "$item" ]] || continue

    resolved="$(resolve_secret_item "$item")"
    path="$(jq -r '.path' <<<"$resolved")"
    data="$(jq -c '.data' <<<"$resolved")"
    cas="$(jq -r '.cas' <<<"$resolved")"

    full_path="$(join_path "$prefix" "$path")"

    resolved_items="$(jq -c --arg p "$full_path" --argjson d "$data" '. + [{path:$p,data:$d}]' <<<"$resolved_items")"

    if (( DRY_RUN )); then
      log "DRY-RUN: would write -> ${mount}/$(trim_slashes "$full_path")"
      ok=$((ok+1))
      continue
    fi

    if [[ "$version" == "2" ]]; then
      if kv_put_v2 "$TOKEN_VALUE" "$mount" "$full_path" "$data" "$cas"; then
        log "INFO: wrote -> ${mount}/$(trim_slashes "$full_path")"
        ok=$((ok+1))
      else
        log "WARN: failed -> ${mount}/$(trim_slashes "$full_path") (HTTP $HTTP_CODE)"
        dbg "$RESP_JSON"
        fail=$((fail+1))
      fi
    else
      if kv_put_v1 "$TOKEN_VALUE" "$mount" "$full_path" "$data"; then
        log "INFO: wrote -> ${mount}/$(trim_slashes "$full_path")"
        ok=$((ok+1))
      else
        log "WARN: failed -> ${mount}/$(trim_slashes "$full_path") (HTTP $HTTP_CODE)"
        dbg "$RESP_JSON"
        fail=$((fail+1))
      fi
    fi
  done < <(emit_secret_items_for_mount "$mount_obj")

  log "INFO: Mount ${mount}: seed complete. success=${ok} failed=${fail}"
  (( fail == 0 )) || die "Seeding failed for mount ${mount}."

  resolved_all="$(jq -c \
    --arg m "$mount" \
    --arg v "$version" \
    --arg p "$(trim_slashes "$prefix")" \
    --argjson s "$resolved_items" \
    '. + [{mount:$m, version:$v, prefix:$p, secrets:$s}]' <<<"$resolved_all")"
done

artifact="$(jq -cn \
  --arg vault_addr "$VAULT_ADDR" \
  --arg created_at "$created_at" \
  --arg spec_file "$SPEC_JSON" \
  --argjson mounts "$resolved_all" \
  --argjson dry_run "$DRY_RUN" \
  '{vault_addr:$vault_addr, created_at:$created_at, spec_file:$spec_file, dry_run:$dry_run, mounts:$mounts}')"

write_file "$OUTPUT_ARTIFACT_FILE" "$artifact"
log "INFO: Wrote consolidated secrets artifact:"
log "      $OUTPUT_ARTIFACT_FILE"

if (( PRINT_SECRETS )); then
  log ""
  log "==================== RESOLVED SECRETS (SENSITIVE) ===================="
  jq '.' <<<"$artifact" >&2
  log "======================================================================"
  log ""
else
  log "INFO: (Not printing secrets; use --print-secrets to print.)"
fi

log "INFO: Recommended next steps:"
log "  1) Securely download required artifacts (examples):"
log "     scp -p <user>@<server>:\"$OUTPUT_ARTIFACT_FILE\" ."
log "     scp -p <user>@<server>:\"$BOOTSTRAP_DIR/unseal_keys.json\" ."
log "     scp -p <user>@<server>:\"$BOOTSTRAP_DIR/root_token\" ."
log "     scp -p <user>@<server>:\"$BOOTSTRAP_DIR/root_token.json\" ."
log "  2) After verifying downloads, remove sensitive files from the server:"
log "     rm -f \"$OUTPUT_ARTIFACT_FILE\" \"$BOOTSTRAP_DIR/unseal_keys.json\" \"$BOOTSTRAP_DIR/root_token\" \"$BOOTSTRAP_DIR/root_token.json\""

log "INFO: Done."
