#!/usr/bin/env bash
# keycloak_all_in_one.sh
#
# Notes / How to run
# ------------------
# This script is an all-in-one Keycloak test utility for:
#   - OIDC discovery
#   - Token acquisition:
#       * client_credentials (service account for a confidential client)
#       * password grant (Direct Grant) - DISCOURAGED; include for testing/automation only
#       * device authorization flow (recommended for CLI logins without a browser redirect)
#   - userinfo (OIDC)
#   - token decoding (claims inspection)
#   - OPTIONAL admin REST API calls (list users, user role mappings)
#
# IMPORTANT REALITY CHECK:
# - With client_credentials using "fastapi-client", you are authenticating as:
#     service-account-fastapi-client
#   and you can ONLY access Keycloak Admin REST API if you *explicitly* grant that
#   service account realm-management permissions (not recommended for least privilege).
# - To "test fastapi-user" roles/claims without FastAPI, you need a token minted
#   for that user (password grant, device flow, or auth-code+PKCE).
#
# Examples
# --------
# 1) Discovery:
#   bash $HOME/NETWORK_TOOLS/backend/build_scripts/documentation/keycloak/test_scripts/keycloak_all_in_one.sh discovery \
#     --kc-base https://auth.networkengineertools.com:8443 \
#     --realm network_tools \
#     --ca-bundle ./backend/app/fastapi/certs/networktools_ca.crt | jq .
#
# 2) Token (client_credentials) for fastapi-client:
#   bash $HOME/NETWORK_TOOLS/backend/build_scripts/documentation/keycloak/test_scripts/keycloak_all_in_one.sh token-cc \
#     --kc-base https://auth.networkengineertools.com:8443 \
#     --realm network_tools \
#     --client-id networktools-automation \
#     --client-secret 'VHQhQbiIcXGtdSdhVmKaVAbDOnBWhzj9' \
#     --ca-bundle ./backend/app/fastapi/certs/networktools_ca.crt | jq .
#
#   bash $HOME/NETWORK_TOOLS/backend/build_scripts/documentation/keycloak/test_scripts/keycloak_all_in_one.sh token-cc \
#     --kc-base https://auth.networkengineertools.com:8443 \
#     --realm network_tools \
#     --client-id fastapi-client \
#     --client-secret 'fc7ZYdFnesHnFSB5O0Oi6ESD6xRv5253' \
#     --ca-bundle ./backend/app/fastapi/certs/networktools_ca.crt | jq .
#
# 3) Whoami (claims + userinfo) using client_credentials:
#   bash $HOME/NETWORK_TOOLS/backend/build_scripts/documentation/keycloak/test_scripts/keycloak_all_in_one.sh whoami --from cc \
#     --kc-base https://auth.networkengineertools.com:8443 \
#     --realm network_tools \
#     --client-id fastapi-client \
#     --client-secret 'fc7ZYdFnesHnFSB5O0Oi6ESD6xRv5253' \
#     --ca-bundle ./backend/app/fastapi/certs/networktools_ca.crt | jq .
#
# 4) Token (password grant) for fastapi-user (DISCOURAGED; testing only):
#   bash $HOME/NETWORK_TOOLS/backend/build_scripts/documentation/keycloak/test_scripts/keycloak_all_in_one.sh token-password \
#     --kc-base https://auth.networkengineertools.com:8443 \
#     --realm network_tools \
#     --client-id fastapi-client \
#     --client-secret 'fc7ZYdFnesHnFSB5O0Oi6ESD6xRv5253' \
#     --username fastapi-user \
#     --password 'gQWw-xDJYinc53NJeL1iYcnk2clInmcSsyZ1B_ywWJE' \
#     --ca-bundle ./backend/app/fastapi/certs/networktools_ca.crt | jq .
#
# 5) Device flow (recommended for CLI user login):
#   bash $HOME/NETWORK_TOOLS/backend/build_scripts/documentation/keycloak/test_scripts/keycloak_all_in_one.sh device-start \
#     --kc-base https://auth.networkengineertools.com:8443 \
#     --realm network_tools \
#     --client-id fastapi-client \
#     --ca-bundle ./backend/app/fastapi/certs/networktools_ca.crt | jq .
#
#   Then poll (after completing verification URL):
#   bash $HOME/NETWORK_TOOLS/backend/build_scripts/documentation/keycloak/test_scripts/keycloak_all_in_one.sh device-poll \
#     --kc-base https://auth.networkengineertools.com:8443 \
#     --realm network_tools \
#     --client-id fastapi-client \
#     --device-code '<device_code>' \
#     --ca-bundle ./backend/app/fastapi/certs/networktools_ca.crt | jq .
#
# 6) Admin API calls (will likely 403 unless service-account has realm-management perms):
#   bash $HOME/NETWORK_TOOLS/backend/build_scripts/documentation/keycloak/test_scripts/keycloak_all_in_one.sh admin-list-users --from cc \
#     --kc-base https://auth.networkengineertools.com:8443 \
#     --realm network_tools \
#     --client-id fastapi-client \
#     --client-secret '***' \
#     --ca-bundle ./backend/app/fastapi/certs/networktools_ca.crt | jq .
#
set -euo pipefail

KNOWN_COMMANDS=(
  discovery token-cc token-password device-start device-poll userinfo whoami decode
  introspect admin-list-users admin-user-roles
)

# Legacy compatibility:
# Some users mistakenly invoke commands as flags (e.g., --discovery instead of "discovery").
# Support --<command> as an alias for the positional <command>.
LEGACY_FLAG_COMMAND=""
for _a in "$@"; do
  case "$_a" in
    --discovery) LEGACY_FLAG_COMMAND="discovery" ;;
    --token-cc) LEGACY_FLAG_COMMAND="token-cc" ;;
    --token-password) LEGACY_FLAG_COMMAND="token-password" ;;
    --device-start) LEGACY_FLAG_COMMAND="device-start" ;;
    --device-poll) LEGACY_FLAG_COMMAND="device-poll" ;;
    --userinfo) LEGACY_FLAG_COMMAND="userinfo" ;;
    --whoami) LEGACY_FLAG_COMMAND="whoami" ;;
    --decode) LEGACY_FLAG_COMMAND="decode" ;;
    --introspect) LEGACY_FLAG_COMMAND="introspect" ;;
    --admin-list-users) LEGACY_FLAG_COMMAND="admin-list-users" ;;
    --admin-user-roles) LEGACY_FLAG_COMMAND="admin-user-roles" ;;
  esac
done

# If a legacy flag command was provided, rebuild argv without that flag and append the command.
if [[ -n "$LEGACY_FLAG_COMMAND" ]]; then
  _new=()
  for _a in "$@"; do
    if [[ "$_a" == "--${LEGACY_FLAG_COMMAND}" ]]; then
      continue
    fi
    _new+=("$_a")
  done
  set -- "$LEGACY_FLAG_COMMAND" "${_new[@]}"
fi

KC_BASE=""
REALM=""
CLIENT_ID="fastapi-client"
CLIENT_SECRET=""
CA_BUNDLE=""
INSECURE="0"
TIMEOUT="20"
DEBUG_CURL="0"
RAW="0"

# token sourcing
FROM="cc"            # cc|password|device|token
TOKEN=""
TOKEN_FILE=""

# password grant
USERNAME=""
PASSWORD=""
PASSWORD_FILE=""
SCOPE="profile email openid"

# device flow
DEVICE_CODE=""

# introspection
INTROSPECT_CLIENT_ID=""
INTROSPECT_CLIENT_SECRET=""

# admin commands
MAX_RESULTS="50"
SEARCH=""
ROLE_USERNAME=""
FOR_CLIENT=""

JQ_BIN="${JQ_BIN:-jq}"

json_str() { printf '%s' "$1" | "$JQ_BIN" -Rs .; }

die() {
  local msg="$1"; shift || true
  local detail="${1:-}"
  if [[ -n "$detail" ]]; then
    printf '{\n  "error": "%s",\n  "detail": %s\n}\n' "$msg" "$detail"
  else
    printf '{\n  "error": "%s"\n}\n' "$msg"
  fi
  exit 2
}

need() {
  command -v "$1" >/dev/null 2>&1 || die "missing_dependency" "$(json_str "Missing $1 in PATH")"
}

usage() {
  cat <<'EOF'
Usage:
  keycloak_all_in_one.sh [flags] <command> [flags]

Core flags:
  --kc-base URL
  --realm REALM
  --ca-bundle PATH
  --insecure
  --timeout SECONDS
  --debug-curl
  --raw

Client flags (for token acquisition):
  --client-id ID              (default: fastapi-client)
  --client-secret SECRET

Token selection:
  --from cc|password|device|token   (default: cc)
  --token JWT
  --token-file PATH

Password grant flags (DISCOURAGED):
  --username NAME
  --password PASS
  --password-file PATH
  --scope "openid profile email"   (default: "profile email openid")

Device flow flags:
  --device-code CODE

Admin flags:
  --max N
  --search TEXT
  --role-username NAME
  --for-client CLIENTID

Commands:
  discovery

Legacy aliases (optional):
  --discovery, --token-cc, --whoami, etc.

Commands:
  discovery
  token-cc
  token-password
  device-start
  device-poll
  userinfo
  whoami
  decode
  introspect
  admin-list-users
  admin-user-roles

EOF
}

is_command() {
  local x="$1"
  for c in "${KNOWN_COMMANDS[@]}"; do
    [[ "$x" == "$c" ]] && return 0
  done
  return 1
}

curl_common() {
  local -a args=()
  args+=("--connect-timeout" "$TIMEOUT" "--max-time" "$TIMEOUT" "-sS")
  if [[ "$DEBUG_CURL" == "1" ]]; then
    args+=("-v")
  fi
  if [[ "$INSECURE" == "1" ]]; then
    args+=("-k")
  else
    if [[ -n "$CA_BUNDLE" ]]; then
      args+=("--cacert" "$CA_BUNDLE")
    fi
  fi
  echo "${args[@]}"
}

require_base_realm() {
  [[ -n "$KC_BASE" ]] || die "missing_kc_base" "$(json_str "Provide --kc-base")"
  [[ -n "$REALM" ]] || die "missing_realm" "$(json_str "Provide --realm")"
}

require_client_secret_if_needed() {
  [[ -n "$CLIENT_ID" ]] || die "missing_client_id" "$(json_str "Provide --client-id")"
  [[ -n "$CLIENT_SECRET" ]] || die "missing_client_secret" "$(json_str "Provide --client-secret")"
}

read_file_or_die() {
  local p="$1"
  [[ -r "$p" ]] || die "file_not_readable" "$(printf '{ "path": %s }' "$(json_str "$p")")"
  cat "$p"
}

http_json_or_error() {
  local method="$1"; shift
  local url="$1"; shift

  local bodyf headf status
  bodyf="$(mktemp)"
  headf="$(mktemp)"
  trap 'rm -f "${bodyf:-}" "${headf:-}"' RETURN

  # shellcheck disable=SC2086
  if ! curl $(curl_common) -X "$method" -o "$bodyf" -D "$headf" \
      -H "Accept: application/json" \
      "$url" "$@"; then
    die "curl_failed" "$(printf '{ "url": %s, "hint": %s }' "$(json_str "$url")" "$(json_str "Rerun with --debug-curl to see TLS/connect details")")"
  fi

  status="$(awk 'NR==1{print $2}' "$headf" | tr -d '\r')"

  if [[ "$RAW" == "1" ]]; then
    cat "$bodyf"
    return 0
  fi

  if "$JQ_BIN" -e . "$bodyf" >/dev/null 2>&1; then
    cat "$bodyf" | "$JQ_BIN" .
    return 0
  fi

  die "non_json_response" "$(printf '{ "http_status": %s, "url": %s, "body": %s }' \
    "$(json_str "${status:-unknown}")" "$(json_str "$url")" "$(json_str "$(cat "$bodyf")")")"
}

oidc_discovery() {
  require_base_realm
  http_json_or_error GET "${KC_BASE%/}/realms/${REALM}/.well-known/openid-configuration"
}

token_cc() {
  require_base_realm
  require_client_secret_if_needed
  http_json_or_error POST "${KC_BASE%/}/realms/${REALM}/protocol/openid-connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "grant_type=client_credentials" \
    --data-urlencode "client_id=${CLIENT_ID}" \
    --data-urlencode "client_secret=${CLIENT_SECRET}" \
    --data-urlencode "scope=${SCOPE}"
}

token_password() {
  require_base_realm
  require_client_secret_if_needed
  [[ -n "$USERNAME" ]] || die "missing_username" "$(json_str "Provide --username")"

  if [[ -z "$PASSWORD" ]]; then
    if [[ -n "$PASSWORD_FILE" ]]; then
      PASSWORD="$(read_file_or_die "$PASSWORD_FILE" | tr -d '\r\n')"
    else
      die "missing_password" "$(json_str "Provide --password or --password-file")"
    fi
  fi

  http_json_or_error POST "${KC_BASE%/}/realms/${REALM}/protocol/openid-connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "grant_type=password" \
    --data-urlencode "client_id=${CLIENT_ID}" \
    --data-urlencode "client_secret=${CLIENT_SECRET}" \
    --data-urlencode "username=${USERNAME}" \
    --data-urlencode "password=${PASSWORD}" \
    --data-urlencode "scope=${SCOPE}"
}

device_start() {
  require_base_realm
  [[ -n "$CLIENT_ID" ]] || die "missing_client_id" "$(json_str "Provide --client-id")"
  http_json_or_error POST "${KC_BASE%/}/realms/${REALM}/protocol/openid-connect/auth/device" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "client_id=${CLIENT_ID}" \
    --data-urlencode "scope=${SCOPE}"
}

device_poll() {
  require_base_realm
  [[ -n "$CLIENT_ID" ]] || die "missing_client_id" "$(json_str "Provide --client-id")"
  [[ -n "$DEVICE_CODE" ]] || die "missing_device_code" "$(json_str "Provide --device-code <device_code>")"

  local url="${KC_BASE%/}/realms/${REALM}/protocol/openid-connect/token"
  local -a extra=()
  if [[ -n "$CLIENT_SECRET" ]]; then
    extra+=(--data-urlencode "client_secret=${CLIENT_SECRET}")
  fi

  http_json_or_error POST "$url" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
    --data-urlencode "client_id=${CLIENT_ID}" \
    --data-urlencode "device_code=${DEVICE_CODE}" \
    "${extra[@]}"
}

load_token_from_sources() {
  case "$FROM" in
    token)
      if [[ -n "$TOKEN" ]]; then
        printf '%s' "$TOKEN"
        return 0
      fi
      if [[ -n "$TOKEN_FILE" ]]; then
        read_file_or_die "$TOKEN_FILE" | tr -d '\r\n'
        return 0
      fi
      die "missing_token" "$(json_str "Provide --token or --token-file when --from token")"
      ;;
    cc)
      token_cc | "$JQ_BIN" -r '.access_token'
      ;;
    password)
      token_password | "$JQ_BIN" -r '.access_token'
      ;;
    device)
      die "device_flow_requires_poll" "$(json_str "Use device-start to obtain device_code, then device-poll to obtain an access token. Pass it with --from token --token <JWT> or --token-file.")"
      ;;
    *)
      die "invalid_from" "$(json_str "Invalid --from. Use cc|password|device|token")"
      ;;
  esac
}

userinfo_cmd() {
  require_base_realm
  local disc endpoint tok
  disc="$(oidc_discovery | "$JQ_BIN" -c .)"
  endpoint="$(printf '%s' "$disc" | "$JQ_BIN" -r '.userinfo_endpoint')"
  tok="$(load_token_from_sources)"
  http_json_or_error GET "$endpoint" -H "Authorization: Bearer ${tok}"
}

decode_cmd() {
  local tok
  tok="$(load_token_from_sources)"
  python3 - <<'PY' "$tok"
import sys, json, base64
tok = sys.argv[1].strip()
parts = tok.split(".")
if len(parts) < 2:
    print(json.dumps({"error":"invalid_jwt","detail":"token must have 2+ parts"}, indent=2))
    sys.exit(2)
def b64u(s):
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s.encode("ascii"))
hdr = json.loads(b64u(parts[0]).decode("utf-8", "replace"))
pld = json.loads(b64u(parts[1]).decode("utf-8", "replace"))
print(json.dumps({"header": hdr, "payload": pld}, indent=2))
PY
}

whoami_cmd() {
  require_base_realm
  local tok payload username azp sub exp iat realm_roles client_roles
  tok="$(load_token_from_sources)"
  payload="$(python3 - <<'PY' "$tok"
import sys, json, base64
tok=sys.argv[1].strip()
p=tok.split('.')[1]
p += '=' * (-len(p)%4)
claims=json.loads(base64.urlsafe_b64decode(p).decode())
print(json.dumps(claims))
PY
)"
  username="$(printf '%s' "$payload" | "$JQ_BIN" -r '.preferred_username // .username // empty')"
  azp="$(printf '%s' "$payload" | "$JQ_BIN" -r '.azp // empty')"
  sub="$(printf '%s' "$payload" | "$JQ_BIN" -r '.sub // empty')"
  exp="$(printf '%s' "$payload" | "$JQ_BIN" -r '.exp // empty')"
  iat="$(printf '%s' "$payload" | "$JQ_BIN" -r '.iat // empty')"
  realm_roles="$(printf '%s' "$payload" | "$JQ_BIN" -c '.realm_access.roles // []')"
  client_roles="$(printf '%s' "$payload" | "$JQ_BIN" -c --arg cid "$CLIENT_ID" '.resource_access[$cid].roles // []')"

  # userinfo call is best-effort; do not fail whoami if it is restricted.
  local ui
  ui="$(http_json_or_error GET "${KC_BASE%/}/realms/${REALM}/protocol/openid-connect/userinfo" \
        -H "Authorization: Bearer ${tok}" 2>/dev/null || true)"

  "$JQ_BIN" -n \
    --arg sub "$sub" \
    --arg username "$username" \
    --arg azp "$azp" \
    --arg exp "$exp" \
    --arg iat "$iat" \
    --argjson realm_roles "$realm_roles" \
    --argjson client_roles "$client_roles" \
    --argjson userinfo "$(printf '%s' "$ui" | "$JQ_BIN" -e . >/dev/null 2>&1 && printf '%s' "$ui" || printf 'null')" \
    '{
      sub: $sub,
      username: $username,
      azp: $azp,
      exp: $exp,
      iat: $iat,
      realm_roles: $realm_roles,
      client_roles_for_client_id: $client_roles,
      userinfo: $userinfo
    }'
}

introspect_cmd() {
  require_base_realm
  local tok cid csec
  tok="$(load_token_from_sources)"

  cid="${INTROSPECT_CLIENT_ID:-$CLIENT_ID}"
  csec="${INTROSPECT_CLIENT_SECRET:-$CLIENT_SECRET}"
  [[ -n "$cid" ]] || die "missing_introspection_client_id" "$(json_str "Provide --introspect-client-id or --client-id")"
  [[ -n "$csec" ]] || die "missing_introspection_client_secret" "$(json_str "Provide --introspect-client-secret or --client-secret")"

  http_json_or_error POST "${KC_BASE%/}/realms/${REALM}/protocol/openid-connect/token/introspect" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "client_id=${cid}" \
    --data-urlencode "client_secret=${csec}" \
    --data-urlencode "token=${tok}"
}

admin_list_users_cmd() {
  require_base_realm
  local tok url
  tok="$(load_token_from_sources)"
  url="${KC_BASE%/}/admin/realms/${REALM}/users?max=${MAX_RESULTS}"
  if [[ -n "$SEARCH" ]]; then
    url="${url}&search=${SEARCH}"
  fi
  http_json_or_error GET "$url" -H "Authorization: Bearer ${tok}"
}

admin_user_roles_cmd() {
  require_base_realm
  [[ -n "$ROLE_USERNAME" ]] || die "missing_role_username" "$(json_str "Provide --role-username <username>")"
  local tok base users uid realm_roles client_roles client_uuid cid
  tok="$(load_token_from_sources)"
  base="${KC_BASE%/}/admin/realms/${REALM}"

  users="$(http_json_or_error GET "${base}/users?search=${ROLE_USERNAME}&max=50" -H "Authorization: Bearer ${tok}")"
  uid="$(printf '%s' "$users" | "$JQ_BIN" -r --arg u "$ROLE_USERNAME" '((map(select(.username == $u)) | .[0].id) // .[0].id) // empty')"
  [[ -n "$uid" ]] || die "user_not_found" "$(printf '{ "username": %s }' "$(json_str "$ROLE_USERNAME")")"

  realm_roles="$(http_json_or_error GET "${base}/users/${uid}/role-mappings/realm" -H "Authorization: Bearer ${tok}")"

  client_roles="null"
  if [[ -n "$FOR_CLIENT" ]]; then
    cid="$(http_json_or_error GET "${base}/clients?clientId=${FOR_CLIENT}" -H "Authorization: Bearer ${tok}")"
    client_uuid="$(printf '%s' "$cid" | "$JQ_BIN" -r '.[0].id // empty')"
    [[ -n "$client_uuid" ]] || die "client_not_found" "$(printf '{ "clientId": %s }' "$(json_str "$FOR_CLIENT")")"
    client_roles="$(http_json_or_error GET "${base}/users/${uid}/role-mappings/clients/${client_uuid}" -H "Authorization: Bearer ${tok}")"
  fi

  "$JQ_BIN" -n \
    --arg username "$ROLE_USERNAME" \
    --arg user_id "$uid" \
    --arg for_client "$FOR_CLIENT" \
    --argjson realm_roles "$realm_roles" \
    --argjson client_roles "$client_roles" \
    '{
      username: $username,
      user_id: $user_id,
      realm_roles: $realm_roles,
      client_roles: $client_roles,
      for_client: (if $for_client == "" then null else $for_client end)
    }'
}

# ---------------- parsing (command can appear anywhere) ----------------
COMMAND=""
REMAINING=()

for a in "$@"; do
  if [[ -z "$COMMAND" ]] && is_command "$a"; then
    COMMAND="$a"
  else
    REMAINING+=("$a")
  fi
done

[[ -n "$COMMAND" ]] || die "missing_command" "$(printf '{"hint": %s, "commands": %s}' "$(json_str 'Provide a command (e.g., discovery, token-cc, whoami). Use --help for usage.')" "$(printf '["%s"]' "$(IFS='","' ; echo "${KNOWN_COMMANDS[*]}")")")"

i=0
while [[ $i -lt ${#REMAINING[@]} ]]; do
  arg="${REMAINING[$i]}"
  case "$arg" in
    --kc-base) KC_BASE="${REMAINING[$((i+1))]}"; i=$((i+2)) ;;
    --realm) REALM="${REMAINING[$((i+1))]}"; i=$((i+2)) ;;
    --ca-bundle) CA_BUNDLE="${REMAINING[$((i+1))]}"; i=$((i+2)) ;;
    --insecure) INSECURE="1"; i=$((i+1)) ;;
    --timeout) TIMEOUT="${REMAINING[$((i+1))]}"; i=$((i+2)) ;;
    --debug-curl) DEBUG_CURL="1"; i=$((i+1)) ;;
    --raw) RAW="1"; i=$((i+1)) ;;

    --client-id) CLIENT_ID="${REMAINING[$((i+1))]}"; i=$((i+2)) ;;
    --client-secret) CLIENT_SECRET="${REMAINING[$((i+1))]}"; i=$((i+2)) ;;

    --from) FROM="${REMAINING[$((i+1))]}"; i=$((i+2)) ;;
    --token) TOKEN="${REMAINING[$((i+1))]}"; FROM="token"; i=$((i+2)) ;;
    --token-file) TOKEN_FILE="${REMAINING[$((i+1))]}"; FROM="token"; i=$((i+2)) ;;

    --username) USERNAME="${REMAINING[$((i+1))]}"; i=$((i+2)) ;;
    --password) PASSWORD="${REMAINING[$((i+1))]}"; i=$((i+2)) ;;
    --password-file) PASSWORD_FILE="${REMAINING[$((i+1))]}"; i=$((i+2)) ;;
    --scope) SCOPE="${REMAINING[$((i+1))]}"; i=$((i+2)) ;;

    --device-code) DEVICE_CODE="${REMAINING[$((i+1))]}"; i=$((i+2)) ;;

    --introspect-client-id) INTROSPECT_CLIENT_ID="${REMAINING[$((i+1))]}"; i=$((i+2)) ;;
    --introspect-client-secret) INTROSPECT_CLIENT_SECRET="${REMAINING[$((i+1))]}"; i=$((i+2)) ;;

    --max) MAX_RESULTS="${REMAINING[$((i+1))]}"; i=$((i+2)) ;;
    --search) SEARCH="${REMAINING[$((i+1))]}"; i=$((i+2)) ;;
    --role-username) ROLE_USERNAME="${REMAINING[$((i+1))]}"; i=$((i+2)) ;;
    --for-client) FOR_CLIENT="${REMAINING[$((i+1))]}"; i=$((i+2)) ;;

    -h|--help) usage; exit 0 ;;
    *)
      die "unknown_argument" "$(json_str "$arg")"
      ;;
  esac
done

main() {
  need curl
  need "$JQ_BIN"
  need python3

  case "$COMMAND" in
    discovery) oidc_discovery ;;
    token-cc) token_cc ;;
    token-password) token_password ;;
    device-start) device_start ;;
    device-poll) device_poll ;;
    userinfo) userinfo_cmd ;;
    whoami) whoami_cmd ;;
    decode) decode_cmd ;;
    introspect) introspect_cmd ;;
    admin-list-users) admin_list_users_cmd ;;
    admin-user-roles) admin_user_roles_cmd ;;
    *) die "unknown_command" "$(json_str "$COMMAND")" ;;
  esac
}

main
