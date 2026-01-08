#!/usr/bin/env bash
#
# generate_local_networkengineertools_certs.sh
#
# Generates a local CA + a single TLS server certificate/key for:
#   - networkengineertools.com
#   - *.networkengineertools.com
#   - (optionally) auth.networkengineertools.com, api.networkengineertools.com, etc.
#
# NOTES / HOW TO RUN
#   1) Place this script at:
#        $HOME/NETWORK_TOOLS/backend/build_scripts/generate_local_networkengineertools_certs.sh
#      Then:
#        chmod +x $HOME/NETWORK_TOOLS/backend/build_scripts/generate_local_networkengineertools_certs.sh
#
#   2) Ensure OpenSSL exists:
#        sudo apt update && sudo apt install -y openssl
#
#   3) Run:
#        $HOME/NETWORK_TOOLS/backend/build_scripts/generate_local_networkengineertools_certs.sh
#
#   4) Overwrite existing certs/keys:
#        $HOME/NETWORK_TOOLS/backend/build_scripts/generate_local_networkengineertools_certs.sh --force
#
# OUTPUTS (default):
#   $HOME/NETWORK_TOOLS/backend/app/nginx/certs/
#     cert.key        (server private key)
#     cert.crt        (fullchain: leaf + CA)
#     cert.leaf.crt   (leaf only)
#     ca.crt          (CA cert - import into trust store for clean browser UX)
#     ca.key          (CA key - protect this file)
#
# Tip (local name resolution):
#   Add these to /etc/hosts on your client machine (or equivalent):
#     <server-ip> networkengineertools.com auth.networkengineertools.com api.networkengineertools.com
#
set -Eeuo pipefail
umask 077

PROJECT_ROOT_DEFAULT="$HOME/NETWORK_TOOLS"
OUT_DIR_DEFAULT="$PROJECT_ROOT_DEFAULT/backend/app/nginx/certs"
VAULT_CERT_DIR_DEFAULT="$PROJECT_ROOT_DEFAULT/backend/app/security/configuration_files/vault/certs"
SYNC_VAULT_CERTS_DEFAULT="1"
VALUES_FILE_DEFAULT="$PROJECT_ROOT_DEFAULT/backend/build_scripts/networkengineertools_cert_values.env"

FORCE="0"
SKIP_VALUES_FILE="0"

CN_DEFAULT="networkengineertools.com"
CA_CN_DEFAULT="NETWORK_TOOLS Local Dev CA"
CA_DAYS_DEFAULT="3650"
LEAF_DAYS_DEFAULT="825"

# Hardcoded SAN defaults (NO autodetect)
DEFAULT_DNS_SANS=(
  "networkengineertools.com"
  "*.networkengineertools.com"
  "auth.networkengineertools.com"
  "api.networkengineertools.com"
  "pgadmin.networkengineertools.com"
  "localhost"
)
DEFAULT_IP_SANS=(
  "127.0.0.1"
)

usage() {
  cat <<EOF
Usage: $0 [options]

Options:
  --out-dir DIR        Output directory (default: ${OUT_DIR_DEFAULT})
  --vault-cert-dir DIR Vault cert directory to sync into (default: ${VAULT_CERT_DIR_DEFAULT})
  --no-vault-sync      Do not sync certs into the Vault cert directory
  --values-file FILE   Values file to load (default: ${VALUES_FILE_DEFAULT})
  --no-values-file     Do not load any values file (even if default exists)

  --cn NAME            Leaf certificate Common Name (default: ${CN_DEFAULT})
  --ca-cn NAME         CA Common Name (default: ${CA_CN_DEFAULT})
  --dns NAME           Add a DNS SAN (repeatable)
  --ip  ADDR           Add an IP SAN (repeatable)

  --leaf-days N        Leaf cert validity days (default: ${LEAF_DAYS_DEFAULT})
  --ca-days N          CA cert validity days (default: ${CA_DAYS_DEFAULT})
  --force              Overwrite existing cert/key material
  -h, --help           Show help

Examples:
  $0
  $0 --force
  $0 --dns vault.networkengineertools.com
EOF
}

log() { printf '%s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

need_cmd() { command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"; }

trim() {
  local s="${1-}"
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  printf '%s' "$s"
}

dedup_lines() { awk 'NF && !seen[$0]++ { print $0 }'; }

split_csv() {
  local s
  s="$(trim "${1-}")"
  [[ -z "$s" ]] && return 0
  printf '%s\n' "$s" | tr ',' '\n' | while IFS= read -r line; do
    line="$(trim "$line")"
    [[ -n "$line" ]] && printf '%s\n' "$line"
  done
}

must_not_overwrite() {
  local f="$1"
  if [[ -e "$f" && "$FORCE" != "1" ]]; then
    die "Refusing to overwrite existing file (use --force): $f"
  fi
}

write_extfile() {
  local extfile="$1"; shift
  local -a dns_list=()
  local -a ip_list=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --dns) dns_list+=("$2"); shift 2 ;;
      --ip)  ip_list+=("$2"); shift 2 ;;
      *) die "write_extfile: unknown arg $1" ;;
    esac
  done

  {
    echo "basicConstraints=CA:FALSE"
    echo "keyUsage=digitalSignature,keyEncipherment"
    echo "extendedKeyUsage=serverAuth"
    echo "subjectAltName=@alt_names"
    echo ""
    echo "[alt_names]"

    local i=1
    for d in "${dns_list[@]}"; do
      d="$(trim "$d")"
      [[ -n "$d" ]] && echo "DNS.${i}=${d}" && i=$((i+1))
    done

    i=1
    for ip in "${ip_list[@]}"; do
      ip="$(trim "$ip")"
      [[ -n "$ip" ]] && echo "IP.${i}=${ip}" && i=$((i+1))
    done
  } > "$extfile"
}

parse_args() {
  OUT_DIR="$OUT_DIR_DEFAULT"
  VAULT_CERT_DIR="$VAULT_CERT_DIR_DEFAULT"
  SYNC_VAULT_CERTS="$SYNC_VAULT_CERTS_DEFAULT"
  VALUES_FILE="$VALUES_FILE_DEFAULT"
  CN="$CN_DEFAULT"
  CA_CN="$CA_CN_DEFAULT"
  CA_DAYS="$CA_DAYS_DEFAULT"
  LEAF_DAYS="$LEAF_DAYS_DEFAULT"
  USER_DNS_SANS=()
  USER_IP_SANS=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --out-dir) OUT_DIR="$2"; shift 2 ;;
      --vault-cert-dir) VAULT_CERT_DIR="$2"; shift 2 ;;
      --no-vault-sync) SYNC_VAULT_CERTS="0"; shift ;;
      --values-file) VALUES_FILE="$2"; shift 2 ;;
      --no-values-file) SKIP_VALUES_FILE="1"; shift ;;
      --cn) CN="$2"; shift 2 ;;
      --ca-cn) CA_CN="$2"; shift 2 ;;
      --leaf-days) LEAF_DAYS="$2"; shift 2 ;;
      --ca-days) CA_DAYS="$2"; shift 2 ;;
      --dns) USER_DNS_SANS+=("$2"); shift 2 ;;
      --ip) USER_IP_SANS+=("$2"); shift 2 ;;
      --force) FORCE="1"; shift ;;
      -h|--help) usage; exit 0 ;;
      *) die "Unknown arg: $1" ;;
    esac
  done
}

load_values_file() {
  [[ "$SKIP_VALUES_FILE" == "1" ]] && return 0
  [[ -f "$VALUES_FILE" ]] || return 0

  log "==> Loading values file: ${VALUES_FILE}"
  # shellcheck disable=SC1090
  set -a
  source "${VALUES_FILE}"
  set +a

  OUT_DIR="${NETWORKENGINEERTOOLS_CERT_OUT_DIR:-$OUT_DIR}"
  VAULT_CERT_DIR="${NETWORKENGINEERTOOLS_VAULT_CERT_DIR:-$VAULT_CERT_DIR}"
  SYNC_VAULT_CERTS="${NETWORKENGINEERTOOLS_CERT_SYNC_VAULT:-$SYNC_VAULT_CERTS}"
  CN="${NETWORKENGINEERTOOLS_CERT_CN:-$CN}"
  CA_CN="${NETWORKENGINEERTOOLS_CERT_CA_CN:-$CA_CN}"
  CA_DAYS="${NETWORKENGINEERTOOLS_CERT_CA_DAYS:-$CA_DAYS}"
  LEAF_DAYS="${NETWORKENGINEERTOOLS_CERT_LEAF_DAYS:-$LEAF_DAYS}"

  VALUES_DNS_SANS_CSV="${NETWORKENGINEERTOOLS_CERT_DNS_SANS:-}"
  VALUES_IP_SANS_CSV="${NETWORKENGINEERTOOLS_CERT_IP_SANS:-}"
}

create_ca_if_needed() {
  local ca_crt="$1"
  local ca_key="$2"

  if [[ -f "$ca_crt" && -f "$ca_key" && "$FORCE" != "1" ]]; then
    log "==> Reusing existing CA: ${ca_crt}"
    return 0
  fi

  must_not_overwrite "$ca_crt"
  must_not_overwrite "$ca_key"

  log "==> Creating CA"
  openssl genrsa -out "$ca_key" 4096
  chmod 600 "$ca_key"
  openssl req -x509 -new -nodes \
    -key "$ca_key" -sha256 -days "$CA_DAYS" \
    -out "$ca_crt" -subj "/CN=${CA_CN}"
  chmod 644 "$ca_crt"
}

main() {
  need_cmd openssl
  need_cmd realpath

  parse_args "$@"

  [[ -d "$PROJECT_ROOT_DEFAULT/backend" ]] || die "Expected repo at: $PROJECT_ROOT_DEFAULT (missing: $PROJECT_ROOT_DEFAULT/backend)"

  load_values_file

  local project_root_real out_dir_real vault_cert_dir_real
  project_root_real="$(realpath -m "$PROJECT_ROOT_DEFAULT")"
  out_dir_real="$(realpath -m "$OUT_DIR")"
  vault_cert_dir_real="$(realpath -m "$VAULT_CERT_DIR")"

  case "$out_dir_real" in
    "$project_root_real"/*) ;;
    *) die "Refusing to write outside $project_root_real. OUT_DIR resolves to: $out_dir_real" ;;
  esac

  mkdir -p "$out_dir_real"
  chmod 700 "$out_dir_real" || true
  OUT_DIR="$out_dir_real"

  local ca_crt="${OUT_DIR}/ca.crt"
  local ca_key="${OUT_DIR}/ca.key"
  local ca_srl="${OUT_DIR}/ca.srl"

  local srv_key="${OUT_DIR}/cert.key"
  local srv_csr="${OUT_DIR}/cert.csr"
  local srv_leaf="${OUT_DIR}/cert.leaf.crt"
  local srv_crt="${OUT_DIR}/cert.crt"
  local ext="${OUT_DIR}/cert.v3.ext"

  must_not_overwrite "$srv_key"
  must_not_overwrite "$srv_crt"

  log "==> Output directory: ${OUT_DIR}"
  log "==> CN: ${CN}"

  {
    printf '%s\n' "${DEFAULT_DNS_SANS[@]}"
    split_csv "${VALUES_DNS_SANS_CSV:-}"
    printf '%s\n' "${USER_DNS_SANS[@]}"
  } | sed 's/[[:space:]]*$//' | dedup_lines > "${OUT_DIR}/.dns.tmp"

  {
    printf '%s\n' "${DEFAULT_IP_SANS[@]}"
    split_csv "${VALUES_IP_SANS_CSV:-}"
    printf '%s\n' "${USER_IP_SANS[@]}"
  } | sed 's/[[:space:]]*$//' | dedup_lines > "${OUT_DIR}/.ip.tmp"

  mapfile -t DNS_SANS < "${OUT_DIR}/.dns.tmp"
  mapfile -t IP_SANS  < "${OUT_DIR}/.ip.tmp"
  rm -f "${OUT_DIR}/.dns.tmp" "${OUT_DIR}/.ip.tmp"

  [[ "${#DNS_SANS[@]}" -gt 0 ]] || die "No DNS SANs found."

  log "==> SANs (DNS):"
  printf '    - %s\n' "${DNS_SANS[@]}"
  if [[ "${#IP_SANS[@]}" -gt 0 ]]; then
    log "==> SANs (IP):"
    printf '    - %s\n' "${IP_SANS[@]}"
  fi

  create_ca_if_needed "$ca_crt" "$ca_key"

  log "==> Creating server key and CSR"
  openssl genrsa -out "$srv_key" 4096
  chmod 600 "$srv_key"
  openssl req -new -key "$srv_key" -out "$srv_csr" -subj "/CN=${CN}"

  write_extfile "$ext" \
    $(for d in "${DNS_SANS[@]}"; do echo --dns "$d"; done) \
    $(for i in "${IP_SANS[@]}"; do echo --ip "$i"; done)

  log "==> Signing leaf certificate"
  openssl x509 -req -in "$srv_csr" \
    -CA "$ca_crt" -CAkey "$ca_key" -CAcreateserial -CAserial "$ca_srl" \
    -out "$srv_leaf" -days "$LEAF_DAYS" -sha256 -extfile "$ext"
  chmod 644 "$srv_leaf"

  # Fullchain for nginx convenience (leaf + CA)
  cat "$srv_leaf" "$ca_crt" > "$srv_crt"
  chmod 644 "$srv_crt"
# Optional: sync the generated server cert into Vault's cert directory so Vault and nginx
# use the same leaf certificate/CA. This avoids "unknown certificate" and hostname mismatch
# issues during bootstrap, especially when probing via vault.${PRIMARY_SERVER_FQDN}.
if [[ "$SYNC_VAULT_CERTS" != "0" ]]; then
  log "==> Syncing certs into Vault cert dir: ${VAULT_CERT_DIR}"
  mkdir -p "$VAULT_CERT_DIR"
  chmod 700 "$VAULT_CERT_DIR" || true

  # Do NOT copy the CA private key (ca.key) into the Vault runtime cert directory.
  install -m 0644 "$ca_crt"   "$VAULT_CERT_DIR/ca.crt"
  install -m 0644 "$srv_crt"  "$VAULT_CERT_DIR/cert.crt"
  install -m 0600 "$srv_key"  "$VAULT_CERT_DIR/cert.key"
else
  log "==> Vault cert sync disabled (--no-vault-sync)."
fi

  rm -f "$srv_csr" "$ext" || true

  log "==> Done. Files:"
  ls -lah "$OUT_DIR"
  log ""
  log "Next step: trust the CA (ca.crt) on your client machine for clean browser UX."
}

main "$@"
