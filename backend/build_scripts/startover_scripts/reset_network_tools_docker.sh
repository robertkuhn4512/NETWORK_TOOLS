#!/usr/bin/env bash
# ==============================================================================
# reset_network_tools_docker.sh
#
# Location:
#   ./backend/build_scripts/startover_scripts/reset_network_tools_docker.sh
#
# How to run (from repo root):
#   chmod +x ./backend/build_scripts/startover_scripts/reset_network_tools_docker.sh
#
#   # Reset the Network Tools stack + wipe data + wipe cert folders (default)
#   ./backend/build_scripts/startover_scripts/reset_network_tools_docker.sh
#
#   # Non-interactive (assume "yes")
#   ./backend/build_scripts/startover_scripts/reset_network_tools_docker.sh --yes
#
#   # Also wipe Vault bootstrap artifacts (root_token/unseal/init jsons)
#   ./backend/build_scripts/startover_scripts/reset_network_tools_docker.sh --wipe-bootstrap
#
#   # Preview actions only
#   ./backend/build_scripts/startover_scripts/reset_network_tools_docker.sh --dry-run
#
#   # NUCLEAR OPTION (host-wide Docker wipe; impacts ALL projects on this host)
#   ./backend/build_scripts/startover_scripts/reset_network_tools_docker.sh --nuclear
#
# What it does (project reset mode):
#   1) docker compose down for docker-compose.prod.yml (removes containers, networks, named volumes, local images)
#   2) force-remove known project containers by name (safety net)
#   3) remove bind-mounted persistent data: <repo_root>/container_data
#   4) ALWAYS purge cert directories (keeps .gitkeep if present):
#        - <repo_root>/backend/app/security/configuration_files/vault/certs
#        - <repo_root>/backend/app/postgres/certs
#        - <repo_root>/app/keycloak/certs (if present)
#   5) remove named volumes by explicit name (extra guarantee, matches your compose "name:" fields)
#
# No sudo:
#   - If deletion fails due to ownership, attempts an ownership reclaim using a short-lived helper container.
# ==============================================================================

set -euo pipefail

info() { echo "==> $*"; }
warn() { echo "WARNING: $*" >&2; }
die()  { echo "ERROR: $*" >&2; exit 1; }

DRY_RUN=0
YES=0
NUCLEAR=0
WIPE_BOOTSTRAP=0

need_cmd() { command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"; }

run() {
  if [ "$DRY_RUN" -eq 1 ]; then
    echo "[dry-run] $*"
  else
    eval "$@"
  fi
}

confirm() {
  local prompt="$1"
  if [ "$YES" -eq 1 ]; then
    return 0
  fi
  read -r -p "$prompt [y/N]: " ans
  case "${ans:-}" in
    y|Y|yes|YES) return 0 ;;
    *) return 1 ;;
  esac
}

usage() {
  cat <<'EOF'
Usage:
  reset_network_tools_docker.sh [options]

Options:
  --repo <path>       Repo root (default: auto-detected)
  --wipe-bootstrap    Also remove Vault bootstrap artifacts
  --dry-run           Print actions without executing
  --yes               Do not prompt; assume "yes"
  --nuclear           HOST-WIDE Docker wipe (impacts other projects)
  -h, --help          Help
EOF
}

realpath_safe() {
  if command -v realpath >/dev/null 2>&1; then
    realpath "$1"
  else
    python3 - <<'PY' "$1"
import os, sys
print(os.path.realpath(sys.argv[1]))
PY
  fi
}

# --- repo root detection (script is in ./backend/build_scripts/startover_scripts) ---
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT_DEFAULT="$(realpath_safe "$SCRIPT_DIR/../../..")"
REPO_ROOT="$REPO_ROOT_DEFAULT"

# --- ownership reclaim (no sudo) ---
reclaim_ownership_with_docker() {
  local target_path="$1"
  local uid gid
  uid="$(id -u)"
  gid="$(id -g)"

  info "Attempting ownership reclaim via helper container (no sudo): $target_path"
  run "docker run --rm -u 0 -v \"${target_path}:/mnt\" alpine:3.20 sh -lc \
    \"chown -R ${uid}:${gid} /mnt || true; \
     find /mnt -type d -exec chmod u+rwx {} + 2>/dev/null || true; \
     find /mnt -type f -exec chmod u+rw  {} + 2>/dev/null || true\""
}

rm_rf_no_sudo() {
  local target_path="$1"
  [ -e "$target_path" ] || return 0

  if run "rm -rf \"${target_path}\""; then
    return 0
  fi

  warn "Initial delete failed (likely permissions): $target_path"
  reclaim_ownership_with_docker "$target_path"

  run "rm -rf \"${target_path}\"" || die "Unable to delete: $target_path"
}

purge_dir_keep_gitkeep_no_sudo() {
  # Removes all contents of directory, preserving .gitkeep if present.
  local dir="$1"
  [ -d "$dir" ] || return 0

  if run "find \"${dir}\" -mindepth 1 -maxdepth 1 -name '.gitkeep' -prune -o -exec rm -rf {} +"; then
    :
  else
    warn "Initial purge failed (likely permissions): $dir"
    reclaim_ownership_with_docker "$dir"
    run "find \"${dir}\" -mindepth 1 -maxdepth 1 -name '.gitkeep' -prune -o -exec rm -rf {} +"
  fi
}

# --- args ---
while [ $# -gt 0 ]; do
  case "$1" in
    --repo) shift; [ $# -gt 0 ] || die "--repo requires a path"; REPO_ROOT="$1" ;;
    --wipe-bootstrap) WIPE_BOOTSTRAP=1 ;;
    --dry-run) DRY_RUN=1 ;;
    --yes) YES=1 ;;
    --nuclear) NUCLEAR=1 ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown argument: $1 (use --help)" ;;
  esac
  shift
done

need_cmd docker

nuclear_reset() {
  warn "NUCLEAR mode selected: this will wipe ALL Docker containers/volumes/images on this host."
  warn "This will affect OTHER projects and services using Docker."

  if ! confirm "Proceed with HOST-WIDE Docker wipe?"; then
    info "Aborted."
    exit 0
  fi

  run "docker rm -f \$(docker ps -aq) 2>/dev/null || true"
  run "docker volume rm \$(docker volume ls -q) 2>/dev/null || true"
  run "docker network prune -f"
  run "docker system prune -a -f --volumes"

  info "Done (nuclear)."
}

project_reset() {
  local rr
  rr="$(realpath_safe "$REPO_ROOT")"
  [ -d "$rr" ] || die "Repo root not found: $rr"
  cd "$rr"

  local compose_file="$rr/docker-compose.prod.yml"
  [ -f "$compose_file" ] || die "Compose file not found: $compose_file"

  local container_data="$rr/container_data"

  # Cert folders (always purged)
  local vault_certs="$rr/backend/app/security/configuration_files/vault/certs"
  local pg_certs="$rr/backend/app/postgres/certs"
  local kc_certs="$rr/app/keycloak/certs"

  # Optional bootstrap artifacts
  local bootstrap_dir="$rr/backend/app/security/configuration_files/vault/bootstrap"

  # Containers (from your compose file container_name fields)
  local containers=(
    "vault_production_node"
    "vault_agent_postgres_pgadmin"
    "vault_agent_keycloak"
    "keycloak"
    "postgres_certs_init"
    "postgres_primary"
    "pgadmin"
  )

  # Named volumes (from your compose file volumes:name fields)
  local volumes=(
    "network_tools_postgres_data"
    "network_tools_postgres_certs"
    "network_tools_postgres_vault_rendered"
    "network_tools_keycloak_data"
    "network_tools_keycloak_vault_rendered"
  )

  info "Repo root: $rr"
  info "Planned actions:"
  info "  - docker compose down (with volumes + local images): $compose_file"
  info "  - remove bind-mounted data dir: $container_data"
  info "  - purge cert dirs (always):"
  info "      * $vault_certs"
  info "      * $pg_certs"
  info "      * $kc_certs (if present)"
  if [ "$WIPE_BOOTSTRAP" -eq 1 ]; then
    info "  - purge bootstrap artifacts: $bootstrap_dir"
  fi

  if ! confirm "Proceed with reset?"; then
    info "Aborted."
    exit 0
  fi

  # 1) Compose down (removes containers, networks, named volumes, local images)
  info "docker compose down..."
  run "docker compose -f \"$compose_file\" down --remove-orphans --volumes --rmi local || true"

  # 2) Safety: force-remove known container names (in case they were started outside compose)
  info "Force-removing known project containers (if present)..."
  for c in "${containers[@]}"; do
    run "docker rm -f \"$c\" 2>/dev/null || true"
  done

  # 3) Remove bind-mounted persistent data
  if [ -d "$container_data" ]; then
    info "Removing bind-mounted data: $container_data"
    rm_rf_no_sudo "$container_data"
  else
    info "No container_data directory found; skipping."
  fi

  # 4) ALWAYS purge cert directories (keep .gitkeep if present)
  info "Purging Vault certs: $vault_certs"
  purge_dir_keep_gitkeep_no_sudo "$vault_certs"

  info "Purging Postgres certs: $pg_certs"
  purge_dir_keep_gitkeep_no_sudo "$pg_certs"

  if [ -d "$kc_certs" ]; then
    info "Purging Keycloak certs: $kc_certs"
    purge_dir_keep_gitkeep_no_sudo "$kc_certs"
  fi

  # 5) Optional: wipe bootstrap artifacts
  if [ "$WIPE_BOOTSTRAP" -eq 1 ] && [ -d "$bootstrap_dir" ]; then
    info "Purging Vault bootstrap artifacts: $bootstrap_dir"
    purge_dir_keep_gitkeep_no_sudo "$bootstrap_dir"
  fi

  # 6) Extra guarantee: remove volumes by explicit name (matches your compose `volumes: name:`)
  info "Removing named volumes by explicit name (extra guarantee)..."
  for v in "${volumes[@]}"; do
    run "docker volume rm \"$v\" 2>/dev/null || true"
  done

  info "Remaining running containers (global):"
  run "docker ps --format \"table {{.Names}}\t{{.Image}}\t{{.Status}}\""

  info "Remaining volumes matching network_tools_* (global):"
  run "docker volume ls --format \"{{.Name}}\" | grep -E '^network_tools_' || true"

  info "Reset complete."
}

if [ "$NUCLEAR" -eq 1 ]; then
  nuclear_reset
else
  project_reset
fi
