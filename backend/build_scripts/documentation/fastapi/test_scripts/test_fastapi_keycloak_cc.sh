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
#   Test the cisco api endpoint unique os versions
#   bash ./backend/build_scripts/documentation/fastapi/test_scripts/test_fastapi_keycloak_cc.sh \
#     --api-base "https://api.networkengineertools.com:8443" \
#     --api-path "/cisco_api_reporting/devices/unique_os_versions" \
#     --method GET \
#     --ca-bundle "./backend/app/fastapi/certs/networktools_ca.crt"
#
#   bash ./backend/build_scripts/documentation/fastapi/test_scripts/test_fastapi_keycloak_cc.sh \
#     --api-base "https://api.networkengineertools.com:8443" \
#     --api-path "/cisco_api_reporting/get_cisco_cve" \
#     --method GET \
#     --ca-bundle "./backend/app/fastapi/certs/networktools_ca.crt"
#
#   Test the device cisco api endpoint cisco_api_reporting/get_cisco_cve_os_version
#   bash ./backend/build_scripts/documentation/fastapi/test_scripts/test_fastapi_keycloak_cc.sh \
#     --api-base "https://api.networkengineertools.com:8443" \
#     --api-path "/cisco_api_reporting/get_cisco_cve_os_version" \
#     --method POST \
#     --payload-file "./backend/build_scripts/documentation/fastapi/test_scripts/test_payloads/get_cisco_cve_os_version.json" \
#     --ca-bundle "./backend/app/fastapi/certs/networktools_ca.crt"
#
#
#   Test the device cisco api endpoint cisco_api_reporting/get_cisco_eox
#   bash ./backend/build_scripts/documentation/fastapi/test_scripts/test_fastapi_keycloak_cc.sh \
#     --api-base "https://api.networkengineertools.com:8443" \
#     --api-path "/cisco_api_reporting/get_cisco_eox" \
#     --method POST \
#     --payload-file "./backend/build_scripts/documentation/fastapi/test_scripts/test_payloads/get_cisco_eox.json" \
#     --ca-bundle "./backend/app/fastapi/certs/networktools_ca.crt"
#
#
#   Test the device cisco api endpoint cisco_api_reporting/devices/unique_os_versions/cve
#   bash ./backend/build_scripts/documentation/fastapi/test_scripts/test_fastapi_keycloak_cc.sh \
#     --api-base "https://api.networkengineertools.com:8443" \
#     --api-path "/cisco_api_reporting/devices/unique_os_versions/cve" \
#     --method POST \
#     --payload-file "./backend/build_scripts/documentation/fastapi/test_scripts/test_payloads/unique_os_versions_cve.json" \
#     --ca-bundle "./backend/app/fastapi/certs/networktools_ca.crt"
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
CLIENT_SECRET_DEFAULT='783ndpvErPxMZeT8OcpkphmquhGO6tHK'

API_BASE=""
API_PATH="/"
METHOD="POST"
PAYLOAD_FILE=""
CA_BUNDLE="./backend/app/fastapi/certs/networktools_ca.crt"
INSECURE_TLS="0"
VERBOSE="0"
TIMEOUT_SECS="360"

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
  --timeout <seconds>       Curl timeout (default: 360)
  --verbose                 Verbose curl output

Keycloak:
  --kc-base <url>           (default: https://auth.networkengineertools.com:8443)
  --realm <name>            (default: network_tools)
  --client-id <id>          (default: fastapi-client)
  --client-secret <secret>  (default: provided in script)
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

validate_ca_bundle() {
  local f="$1"
  [[ -n "$f" ]] || return 0
  [[ -f "$f" ]] || die "--ca-bundle not found: $f"
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

if [[ "$API_PATH" != /* ]]; then
  API_PATH="/$API_PATH"
fi

TOKEN_URL="${KC_BASE%/}/realms/${REALM}/protocol/openid-connect/token"

validate_payload_file "$METHOD" "$PAYLOAD_FILE"
if [[ "$INSECURE_TLS" != "1" ]]; then
  validate_ca_bundle "$CA_BUNDLE"
fi

# IMPORTANT: no --fail here; we handle HTTP errors manually so we can show bodies.
CURL_BASE_ARGS=(--silent --show-error --max-time "$TIMEOUT_SECS")

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

print_body() {
  local f="$1"
  if jq -e . "$f" >/dev/null 2>&1; then
    jq . "$f"
  else
    cat "$f"
  fi
}

curl_capture() {
  # Usage: curl_capture <out_file> <curl args...>
  local out_file="$1"; shift
  local http_code
  # Always capture the body; never abort the whole script from inside this helper.
  set +e
  http_code="$(curl "$@" -o "$out_file" -w "%{http_code}")"
  local rc=$?
  set -e
  echo "$http_code"
  return $rc
}

tmp_token="$(mktemp)"
tmp_body="$(mktemp)"
cleanup() { rm -f "$tmp_token" "$tmp_body" 2>/dev/null || true; }
trap cleanup EXIT

echo "INFO: Requesting Keycloak token (client_credentials) from: $TOKEN_URL" >&2

token_rc=0
token_http_code="$(
  curl_capture "$tmp_token" \
    "${CURL_BASE_ARGS[@]}" \
    -X POST "$TOKEN_URL" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "grant_type=client_credentials" \
    --data-urlencode "client_id=$CLIENT_ID" \
    --data-urlencode "client_secret=$CLIENT_SECRET"
)" || token_rc=$?

echo "TOKEN_HTTP_STATUS=$token_http_code" >&2

# Transport failure (DNS/TLS/connect/etc.) -> curl returns non-zero and http_code is usually 000
if [[ "$token_rc" -ne 0 && "$token_http_code" == "000" ]]; then
  echo "ERROR: Token request failed at transport layer (curl_rc=$token_rc)." >&2
  echo "----- Token Response Body (if any) -----" >&2
  print_body "$tmp_token" >&2 || true
  die "Keycloak token request transport failure"
fi

# If Keycloak returned a non-2xx, print body and fail with a clear message.
if [[ "$token_http_code" =~ ^[0-9]+$ ]] && (( token_http_code >= 400 )); then
  echo "ERROR: Keycloak token request returned HTTP $token_http_code" >&2
  echo "----- Keycloak Token Error Body -----" >&2
  print_body "$tmp_token" >&2 || true
  die "Keycloak token request failed"
fi

token_json="$(cat "$tmp_token")"
access_token="$(echo "$token_json" | jq -r '.access_token // empty')"
token_type="$(echo "$token_json" | jq -r '.token_type // empty')"
expires_in="$(echo "$token_json" | jq -r '.expires_in // empty')"

[[ -n "$access_token" ]] || {
  echo "ERROR: Keycloak token response did not include access_token." >&2
  echo "----- Keycloak Token Body -----" >&2
  print_body "$tmp_token" >&2 || true
  die "Missing access_token"
}
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

req_rc=0
http_code="$(curl_capture "$tmp_body" "${REQ_ARGS[@]}")" || req_rc=$?

echo "HTTP_STATUS=$http_code" >&2

# Transport failure (DNS/TLS/connect/etc.)
if [[ "$req_rc" -ne 0 && "$http_code" == "000" ]]; then
  echo "ERROR: Request failed at transport layer (curl_rc=$req_rc)." >&2
  echo "----- Response Body (if any) -----" >&2
  print_body "$tmp_body" >&2 || true
  exit 2
fi

# Always print the body to stdout (so you can pipe to jq, save it, etc.)
print_body "$tmp_body"

# If server returned an HTTP error, exit non-zero *after* printing the body.
if [[ "$http_code" =~ ^[0-9]+$ ]] && (( http_code >= 400 )); then
  if (( http_code >= 500 )); then
    echo "ERROR: Server returned HTTP $http_code (showing payload above)." >&2
  else
    echo "ERROR: Client returned HTTP $http_code (showing payload above)." >&2
  fi
  exit 1
fi