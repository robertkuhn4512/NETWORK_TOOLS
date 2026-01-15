#!/usr/bin/env bash
#==============================================================================
# test_fastapi_keycloak_cc.sh
#
# How to run:
#   chmod +x ./test_fastapi_keycloak_cc.sh
#
#   # Example (GET):
#   ./test_fastapi_keycloak_cc.sh \
#     --api-base "https://api.networkengineertools.com:8443" \
#     --api-path "/healthz" \
#     --method GET \
#     --ca-bundle "./backend/app/fastapi/certs/networktools_ca.crt"
#
#   # Example (POST with payload file):
#   printf '{"hello":"world"}\n' > /tmp/payload.json
#   ./test_fastapi_keycloak_cc.sh \
#     --api-base "https://api.networkengineertools.com:8443" \
#     --api-path "/api/v1/echo" \
#     --method POST \
#     --payload-file "./backend/build_scripts/documentation/fastapi/test_scripts/test_payloads/device_discovery_start_device_discovery.json" \
#     --ca-bundle "./backend/app/fastapi/certs/networktools_ca.crt"
#
#   Test the device discovery endpoint
#   bash ./backend/build_scripts/documentation/fastapi/test_scripts/test_fastapi_keycloak_cc.sh \
#     --api-base "https://api.networkengineertools.com:8443" \
#     --api-path "/device_discovery/start_device_discovery" \
#     --method POST \
#     --payload-file "./backend/build_scripts/documentation/fastapi/test_scripts/test_payloads/device_discovery_start_device_discovery.json" \
#     --ca-bundle "./backend/app/fastapi/certs/networktools_ca.crt"
#
#
#
#
#
#
#
#
#
#
#
#
#
# Notes:
# - Uses Keycloak Client Credentials Grant to obtain an access token, then calls
#   a FastAPI endpoint with Authorization: Bearer <token>.
#==============================================================================
set -euo pipefail

KC_BASE_DEFAULT="https://auth.networkengineertools.com:8443"
REALM_DEFAULT="network_tools"
CLIENT_ID_DEFAULT="fastapi-client"
CLIENT_SECRET_DEFAULT='fc7ZYdFnesHnFSB5O0Oi6ESD6xRv5253'

API_BASE=""
API_PATH="/"
METHOD="POST"
PAYLOAD_FILE=""
CA_BUNDLE="./backend/app/fastapi/certs/networktools_ca.crt"
INSECURE_TLS="0"
VERBOSE="0"
TIMEOUT_SECS="20"

usage() {
  cat <<'EOF'
Usage:
  test_fastapi_keycloak_cc.sh [options]

Required:
  --api-base <url>          Base URL for FastAPI (e.g., https://api.example.com)

Optional:
  --api-path <path>         Endpoint path (default: /)
  --method <GET|POST|PUT|PATCH|DELETE>  HTTP method (default: POST)
  --payload-file <file>     JSON payload file for POST/PUT/PATCH (default: none)
  --ca-bundle <file>        CA bundle for TLS validation (default: ./backend/app/fastapi/certs/networktools_ca.crt)
  --insecure                Disable TLS verification (curl -k). Not recommended.
  --timeout <seconds>       Curl timeout (default: 20)
  --verbose                 Verbose curl output

Keycloak (defaults already set to your provided credentials):
  --kc-base <url>           (default: https://auth.networkengineertools.com:8443)
  --realm <name>            (default: network_tools)
  --client-id <id>          (default: fastapi-client)
  --client-secret <secret>  (default: provided in script)

Examples:
  ./test_fastapi_keycloak_cc.sh --api-base "https://api.networkengineertools.com" --api-path "/healthz" --method GET
  ./test_fastapi_keycloak_cc.sh --api-base "https://api.networkengineertools.com" --api-path "/api/v1/echo" --method POST --payload-file /tmp/payload.json
EOF
}

die() {
  echo "ERROR: $*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"
}

KC_BASE="$KC_BASE_DEFAULT"
REALM="$REALM_DEFAULT"
CLIENT_ID="$CLIENT_ID_DEFAULT"
CLIENT_SECRET="$CLIENT_SECRET_DEFAULT"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --api-base) API_BASE="${2:-}"; shift 2;;
    --api-path) API_PATH="${2:-}"; shift 2;;
    --method) METHOD="${2:-}"; shift 2;;
    --payload-file) PAYLOAD_FILE="${2:-}"; shift 2;;
    --ca-bundle) CA_BUNDLE="${2:-}"; shift 2;;
    --kc-base) KC_BASE="${2:-}"; shift 2;;
    --realm) REALM="${2:-}"; shift 2;;
    --client-id) CLIENT_ID="${2:-}"; shift 2;;
    --client-secret) CLIENT_SECRET="${2:-}"; shift 2;;
    --timeout) TIMEOUT_SECS="${2:-}"; shift 2;;
    --insecure) INSECURE_TLS="1"; shift 1;;
    --verbose) VERBOSE="1"; shift 1;;
    -h|--help) usage; exit 0;;
    *) die "Unknown argument: $1 (use --help)";;
  esac
done

need_cmd curl
need_cmd jq

# Validate CA bundle when provided and not using --insecure.
validate_ca_bundle() {
  local f="$1"
  [[ -n "$f" ]] || return 0
  [[ -f "$f" ]] || die "--ca-bundle not found: $f"
  # Basic sanity: require PEM-like cert content (avoid accidental JSON payload paths)
  if ! grep -q "BEGIN CERTIFICATE" "$f" 2>/dev/null; then
    die "--ca-bundle does not look like a PEM certificate (missing 'BEGIN CERTIFICATE'): $f"
  fi
}

validate_payload_file() {
  local method="$1"
  local f="$2"
  if [[ "$method" == "POST" || "$method" == "PUT" || "$method" == "PATCH" ]]; then
    if [[ -n "$f" ]]; then
      [[ -f "$f" ]] || die "--payload-file not found: $f"
    fi
  fi
}

[[ -n "$API_BASE" ]] || { usage; die "--api-base is required"; }

# Normalize API_PATH
if [[ "$API_PATH" != /* ]]; then
  API_PATH="/$API_PATH"
fi

TOKEN_URL="${KC_BASE%/}/realms/${REALM}/protocol/openid-connect/token"

# Validate inputs early (fail fast with clear errors)
validate_payload_file "$METHOD" "$PAYLOAD_FILE"
if [[ "$INSECURE_TLS" != "1" ]]; then
  validate_ca_bundle "$CA_BUNDLE"
fi

CURL_BASE_ARGS=(--silent --show-error --fail --max-time "$TIMEOUT_SECS")

if [[ "$VERBOSE" == "1" ]]; then
  CURL_BASE_ARGS+=(--verbose)
fi

if [[ "$INSECURE_TLS" == "1" ]]; then
  CURL_BASE_ARGS+=(-k)
else
  if [[ -n "$CA_BUNDLE" && -f "$CA_BUNDLE" ]]; then
    CURL_BASE_ARGS+=(--cacert "$CA_BUNDLE")
  fi
fi

echo "INFO: Requesting Keycloak token (client_credentials) from: $TOKEN_URL" >&2

token_json="$(
  curl "${CURL_BASE_ARGS[@]}" \
    -X POST "$TOKEN_URL" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "grant_type=client_credentials" \
    --data-urlencode "client_id=$CLIENT_ID" \
    --data-urlencode "client_secret=$CLIENT_SECRET"
)"

access_token="$(echo "$token_json" | jq -r '.access_token // empty')"
token_type="$(echo "$token_json" | jq -r '.token_type // empty')"
expires_in="$(echo "$token_json" | jq -r '.expires_in // empty')"

[[ -n "$access_token" ]] || die "Keycloak token response did not include access_token. Full response: $token_json"
[[ -n "$token_type" ]] || token_type="Bearer"

echo "INFO: Got token_type=$token_type expires_in=${expires_in:-unknown}s" >&2

API_URL="${API_BASE%/}${API_PATH}"
echo "INFO: Calling FastAPI endpoint: $METHOD $API_URL" >&2

REQ_ARGS=("${CURL_BASE_ARGS[@]}" -X "$METHOD" "$API_URL" -H "Authorization: $token_type $access_token")

if [[ "$METHOD" == "POST" || "$METHOD" == "PUT" || "$METHOD" == "PATCH" ]]; then
  REQ_ARGS+=(-H "Content-Type: application/json")
  if [[ -n "$PAYLOAD_FILE" ]]; then
    [[ -f "$PAYLOAD_FILE" ]] || die "--payload-file not found: $PAYLOAD_FILE"
    REQ_ARGS+=(--data-binary "@${PAYLOAD_FILE}")
  else
    REQ_ARGS+=(--data-binary "{}")
  fi
fi

tmp_body="$(mktemp)"
cleanup() { rm -f "$tmp_body" 2>/dev/null || true; }
trap cleanup EXIT

http_code="$(curl "${REQ_ARGS[@]}" -o "$tmp_body" -w "%{http_code}")"

# Print status to stderr so stdout remains clean JSON/text (safe to pipe to jq).
echo "HTTP_STATUS=$http_code" >&2

# Pretty-print JSON responses when possible; otherwise print raw body.
if jq -e . "$tmp_body" >/dev/null 2>&1; then
  jq . "$tmp_body"
else
  cat "$tmp_body"
fi
