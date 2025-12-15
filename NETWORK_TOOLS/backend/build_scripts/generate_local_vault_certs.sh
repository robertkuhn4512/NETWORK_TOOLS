#!/usr/bin/env bash
#
# generate_local_vault_certs.sh
#
# Generates a local CA + a single Vault server certificate/key for the Network Tools project.
#
# NOTES / HOW TO RUN
#   1) Place this script at:
#        $HOME/NETWORK_TOOLS/backend/build_scripts/generate_local_vault_certs.sh
#      Then:
#        chmod +x $HOME/NETWORK_TOOLS/backend/build_scripts/generate_local_vault_certs.sh
#
#   2) Ensure OpenSSL exists:
#        sudo apt update && sudo apt install -y openssl
#
#   3) Run (uses only hardcoded SAN defaults + optional values file + CLI flags; NO hostname/IP autodetect):
#        $HOME/NETWORK_TOOLS/backend/build_scripts/generate_local_vault_certs.sh
#
#   4) Overwrite existing certs/keys:
#        $HOME/NETWORK_TOOLS/backend/build_scripts/generate_local_vault_certs.sh --force
#
#   5) Add additional SANs on-demand:
#        $HOME/NETWORK_TOOLS/backend/build_scripts/generate_local_vault_certs.sh --dns network_tools.local --dns network_tools.local --ip 172.16.99.130
#
#   6) Values file (optional, auto-loaded if present):
#        Default: $HOME/NETWORK_TOOLS/backend/build_scripts/vault_cert_values.env
#
#        Example contents:
#          VAULT_CERT_CN="network_tools.local"
#          VAULT_CERT_DNS_SANS="network_tools.local"
#          VAULT_CERT_IP_SANS="172.16.99.130"
#          VAULT_CERT_OUT_DIR="$PROJECT_ROOT_DEFAULT/backend/app/security/configuration_files/vault/certs"
#
# OUTPUTS (default):
#   $HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/
#     cert.key   (server key)
#     cert.crt   (fullchain: leaf + CA)
#     ca.crt     (CA cert)
#     ca.key     (CA key - protect this file)
#

set -Eeuo pipefail

# Ensure private key material is created with restrictive permissions by default
umask 077

# ====== Defaults (project-relative; do not write outside $HOME/NETWORK_TOOLS by default) ======
PROJECT_ROOT_DEFAULT="$HOME/NETWORK_TOOLS"
OUT_DIR_DEFAULT="$PROJECT_ROOT_DEFAULT/backend/app/security/configuration_files/vault/certs"
VALUES_FILE_DEFAULT="$PROJECT_ROOT_DEFAULT/backend/build_scripts/vault_cert_values.env"

FORCE="0"
SKIP_VALUES_FILE="0"

CN_DEFAULT="vault_production_node"
CA_CN_DEFAULT="NETWORK_TOOLS Local Vault CA"
CA_DAYS_DEFAULT="3650"
LEAF_DAYS_DEFAULT="825"

# ====== Hardcoded SAN defaults (NO autodetect) ======
# Update these arrays directly to reflect the names/IPs you will actually use.
# Requirement: include "vault_production_node" in DNS SANs if you access Vault via https://vault_production_node:8200

DEFAULT_DNS_SANS=(
  "vault_production_node"
)
DEFAULT_IP_SANS=(
  "172.16.99.130"
)

usage() {
  cat <<EOF
Usage: $0 [options]

Options:
  --out-dir DIR        Output directory (default: ${OUT_DIR_DEFAULT})
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
  $0 --dns vault_production_node --dns vault.my.domain --ip 172.16.99.130 --ip 127.0.0.1
EOF
}

log() { printf '%s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"
}

# De-dup preserving order
dedup_lines() {
  awk 'NF && !seen[$0]++ { print $0 }'
}

trim() {
  # trims leading/trailing whitespace
  local s="${1-}"
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  printf '%s' "$s"
}

split_csv() {
  # prints items, one per line
  local s
  s="$(trim "${1-}")"
  [[ -z "$s" ]] && return 0
  printf '%s' "$s" | tr ',' '\n' | while IFS= read -r line; do
    line="$(trim "$line")"
    [[ -n "$line" ]] && printf '%s\n' "$line"
  done
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
  OUT_DIR="${OUT_DIR_DEFAULT}"
  VALUES_FILE="${VALUES_FILE_DEFAULT}"
  CN="${CN_DEFAULT}"
  CA_CN="${CA_CN_DEFAULT}"
  CA_DAYS="${CA_DAYS_DEFAULT}"
  LEAF_DAYS="${LEAF_DAYS_DEFAULT}"
  USER_DNS_SANS=()
  USER_IP_SANS=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --out-dir) OUT_DIR="$2"; shift 2 ;;
      --values-file) VALUES_FILE="$2"; shift 2 ;;
      --no-values-file) SKIP_VALUES_FILE="1"; shift ;;
      --cn) CN="$2"; shift 2 ;;
      --ca-cn) CA_CN="$2"; shift 2 ;;
      --dns) USER_DNS_SANS+=("$2"); shift 2 ;;
      --ip) USER_IP_SANS+=("$2"); shift 2 ;;
      --leaf-days) LEAF_DAYS="$2"; shift 2 ;;
      --ca-days) CA_DAYS="$2"; shift 2 ;;
      --force) FORCE="1"; shift ;;
      -h|--help) usage; exit 0 ;;
      *) die "Unknown argument: $1" ;;
    esac
  done
}

must_not_overwrite() {
  local f="$1"
  if [[ -e "$f" && "$FORCE" != "1" ]]; then
    die "Refusing to overwrite existing file: $f (use --force)"
  fi
}

load_values_file() {
  # Loads optional settings without any server autodetection.
  #
  # Supported variables in the values file:
  #   VAULT_CERT_OUT_DIR="$PROJECT_ROOT_DEFAULT/backend/app/security/configuration_files/vault/certs"
  #   VAULT_CERT_CN="vault_production_node"
  #   VAULT_CERT_CA_CN="NETWORK_TOOLS Local Vault CA"
  #   VAULT_CERT_CA_DAYS="3650"
  #   VAULT_CERT_LEAF_DAYS="825"
  #   VAULT_CERT_DNS_SANS="vault_production_node,localhost"
  #   VAULT_CERT_IP_SANS="172.16.99.130,127.0.0.1"
  #
  [[ "$SKIP_VALUES_FILE" == "1" ]] && return 0

  [[ -n "${VALUES_FILE}" ]] || return 0
  [[ -f "${VALUES_FILE}" ]] || return 0

  log "==> Loading values file: ${VALUES_FILE}"

  # shellcheck disable=SC1090
  set -a
  source "${VALUES_FILE}"
  set +a

  OUT_DIR="${VAULT_CERT_OUT_DIR:-$OUT_DIR}"
  CN="${VAULT_CERT_CN:-$CN}"
  CA_CN="${VAULT_CERT_CA_CN:-$CA_CN}"
  CA_DAYS="${VAULT_CERT_CA_DAYS:-$CA_DAYS}"
  LEAF_DAYS="${VAULT_CERT_LEAF_DAYS:-$LEAF_DAYS}"

  VALUES_DNS_SANS_CSV="${VAULT_CERT_DNS_SANS:-}"
  VALUES_IP_SANS_CSV="${VAULT_CERT_IP_SANS:-}"
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

  openssl req -x509 -new -nodes     -key "$ca_key"     -sha256 -days "$CA_DAYS"     -out "$ca_crt"     -subj "/CN=${CA_CN}"
  chmod 644 "$ca_crt"
}

main() {
  need_cmd openssl
  need_cmd realpath
  parse_args "$@"

  [[ -d "$PROJECT_ROOT_DEFAULT/backend" ]] || die "This script expects the repo at: $PROJECT_ROOT_DEFAULT (missing: $PROJECT_ROOT_DEFAULT/backend)"

  load_values_file

  # Safety: refuse to write outside the project root (evaluate paths before creating anything)
local project_root_real out_dir_real
project_root_real="$(realpath -m "$PROJECT_ROOT_DEFAULT")"
out_dir_real="$(realpath -m "$OUT_DIR")"

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

  # For the leaf outputs we always require --force to overwrite.
  must_not_overwrite "$srv_key"
  must_not_overwrite "$srv_crt"

  log "==> Output directory: ${OUT_DIR}"
  log "==> Generating (or reusing) CA and issuing one Vault server certificate."
  log "    CN: ${CN}"

  # Build SAN lists: hardcoded defaults + values-file CSV + CLI flags
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

  [[ "${#DNS_SANS[@]}" -gt 0 ]] || die "No DNS SANs found. Set DEFAULT_DNS_SANS, values file VAULT_CERT_DNS_SANS, or pass --dns."

  log "==> SANs (DNS):"
  printf '    - %s\n' "${DNS_SANS[@]}"
  if [[ "${#IP_SANS[@]}" -gt 0 ]]; then
    log "==> SANs (IP):"
    printf '    - %s\n' "${IP_SANS[@]}"
  fi

  # Create or reuse CA
  create_ca_if_needed "$ca_crt" "$ca_key"

  # Create server key + CSR
  log "==> Creating server key and CSR"
  openssl genrsa -out "$srv_key" 4096
  chmod 600 "$srv_key"
  openssl req -new -key "$srv_key" -out "$srv_csr" -subj "/CN=${CN}"

  # Extensions (SANs, serverAuth)
  write_extfile "$ext"     $(for d in "${DNS_SANS[@]}"; do echo --dns "$d"; done)     $(for i in "${IP_SANS[@]}"; do echo --ip "$i"; done)

  # Sign leaf with CA (use stable serial file if it already exists)
  log "==> Signing leaf certificate"
  if [[ -f "$ca_srl" ]]; then
    openssl x509 -req       -in "$srv_csr"       -CA "$ca_crt"       -CAkey "$ca_key"       -CAserial "$ca_srl"       -out "$srv_leaf"       -days "$LEAF_DAYS" -sha256       -extfile "$ext"
  else
    openssl x509 -req       -in "$srv_csr"       -CA "$ca_crt"       -CAkey "$ca_key"       -CAcreateserial -CAserial "$ca_srl"       -out "$srv_leaf"       -days "$LEAF_DAYS" -sha256       -extfile "$ext"
  fi

  # Serial file is not sensitive, but should not be group-writable
  chmod 644 "$ca_srl" || true

  # Fullchain (leaf + CA) for Vault tls_cert_file convenience
  cat "$srv_leaf" "$ca_crt" > "$srv_crt"
  chmod 644 "$srv_crt"

  rm -f "$srv_csr" "$srv_leaf" "$ext" 2>/dev/null || true

  log ""
  log "Done. Generated:"
  log "  CA cert : ${ca_crt}"
  log "  CA key  : ${ca_key}   (protect this file)"
  log "  Server  : ${srv_crt}"
  log "  Key     : ${srv_key}"
  log ""
  log "Compose mounts should point to:"
  log "  ${OUT_DIR}/cert.crt  -> /vault/certs/cert.crt"
  log "  ${OUT_DIR}/cert.key  -> /vault/certs/cert.key"
  log ""

  log "Permissions applied (recommended defaults):"
  log "  Directory: 700  (contains private keys)"
  log "  ca.crt    : 644"
  log "  ca.key    : 600"
  log "  ca.srl    : 644"
  log "  cert.crt  : 644"
  log "  cert.key  : 600"
  log ""
  log "Recommended (more correct) client trust mount:"
  log "  ${OUT_DIR}/ca.crt    -> /vault/certs/ca.crt"
  log "  VAULT_CACERT=/vault/certs/ca.crt"
}

main "$@"