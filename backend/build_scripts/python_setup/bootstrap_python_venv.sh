#!/usr/bin/env bash
#
# bootstrap_python_venv.sh
#
# Ensures a venv exists at:
#   NETWORK_TOOLS/backend/build_scripts/python_setup/venv
# and that it uses the *target* Python version (åmajor.minor).
#
# Target selection:
#   - If PYTHON_VERSION is set (e.g. 3.12, 3.13, 3.13.1), target is its major.minor.
#   - Otherwise, target defaults to system python3 major.minor.
#
# Behavior:
#   - If venv exists and venv/bin/python matches target -> reuse and exit 0.
#   - Otherwise -> rebuild venv in-place (moves old venv aside).
#
# Creation strategy:
#   - Default: system python (python3 or pythonX.Y) with `-m venv`.
#   - Optional: USE_UV=1 uses uv with --managed-python (downloads Python if missing).
#
# This script does NOT activate the venv. It prints the activation command.
#
# Examples:
#   bash ./backend/build_scripts/python_setup/bootstrap_python_venv.sh
#   PYTHON_VERSION=3.13 bash ./backend/build_scripts/python_setup/bootstrap_python_venv.sh
#   USE_UV=1 PYTHON_VERSION=3.13 bash ./backend/build_scripts/python_setup/bootstrap_python_venv.sh
#   FORCE_RECREATE=1 bash ./backend/build_scripts/python_setup/bootstrap_python_venv.sh
#
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${SCRIPT_DIR}/venv"

log()  { printf '%s\n' "$*"; }
warn() { printf 'WARN: %s\n' "$*" >&2; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"
}

detect_target_mm() {
  local target="${PYTHON_VERSION:-}"
  if [[ -n "${target}" ]]; then
    if [[ "${target}" =~ ^([0-9]+)\.([0-9]+) ]]; then
      printf '%s.%s\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
      return 0
    fi
    die "Invalid PYTHON_VERSION='${target}'. Use like 3.12, 3.13, or 3.13.1"
  fi
  need_cmd python3
  python3 - <<'PY'
import sys
print(f"{sys.version_info.major}.{sys.version_info.minor}")
PY
}

venv_python_mm() {
  if [[ ! -x "${VENV_DIR}/bin/python" ]]; then
    echo ""
    return 0
  fi
  "${VENV_DIR}/bin/python" - <<'PY'
import sys
print(f"{sys.version_info.major}.{sys.version_info.minor}")
PY
}

is_valid_venv() {
  [[ -f "${VENV_DIR}/bin/activate" ]] && [[ -x "${VENV_DIR}/bin/python" ]]
}

move_existing_venv_aside() {
  [[ -d "${VENV_DIR}" ]] || return 0
  local ts bk
  ts="$(date +%Y%m%d_%H%M%S)"
  bk="${VENV_DIR}.replaced.${ts}"
  log "[bootstrap] Moving existing venv aside: ${bk}"
  mv "${VENV_DIR}" "${bk}"
}

ensure_uv() {
  export PATH="${HOME}/.local/bin:${PATH}"
  if command -v uv >/dev/null 2>&1; then
    return 0
  fi
  need_cmd curl
  log "[bootstrap] Installing uv (user-local)..."
  curl -LsSf https://astral.sh/uv/install.sh | sh
  export PATH="${HOME}/.local/bin:${PATH}"
  command -v uv >/dev/null 2>&1 || die "uv not found after install. Ensure ${HOME}/.local/bin is on PATH."
}

create_venv_system_python() {
  local mm="$1"
  local interp="python3"

  # If explicitly pinned, prefer pythonX.Y if it exists.
  if [[ -n "${PYTHON_VERSION:-}" ]]; then
    if command -v "python${mm}" >/dev/null 2>&1; then
      interp="python${mm}"
    fi
  fi

  command -v "${interp}" >/dev/null 2>&1 || die "Interpreter '${interp}' not found. Install it, or set USE_UV=1 to let uv provision Python."

  log "[bootstrap] Creating venv with ${interp} at: ${VENV_DIR}"
  "${interp}" -m venv "${VENV_DIR}"

  local got
  got="$(venv_python_mm || true)"
  if [[ -n "${mm}" && -n "${got}" && "${got}" != "${mm}" ]]; then
    die "Created venv uses Python ${got}, but target is ${mm}. Install python${mm} (or set USE_UV=1) and re-run."
  fi
}

create_venv_uv() {
  local mm="$1"
  ensure_uv
  log "[bootstrap] Creating venv with uv at: ${VENV_DIR}"
  if [[ -n "${PYTHON_VERSION:-}" ]]; then
    uv venv "${VENV_DIR}" --managed-python --python "${PYTHON_VERSION}"
  else
    uv venv "${VENV_DIR}" --managed-python
  fi

  local got
  got="$(venv_python_mm || true)"
  if [[ -n "${mm}" && -n "${got}" && "${got}" != "${mm}" ]]; then
    die "uv created venv uses Python ${got}, but target is ${mm}. Pin PYTHON_VERSION explicitly (e.g. 3.13) and re-run."
  fi
}

main() {
  local target_mm
  target_mm="$(detect_target_mm)"
  log "[bootstrap] Target Python major.minor: ${target_mm}"

  if [[ "${FORCE_RECREATE:-}" == "1" ]]; then
    move_existing_venv_aside
  elif [[ -d "${VENV_DIR}" ]]; then
    if is_valid_venv; then
      local got
      got="$(venv_python_mm || true)"
      if [[ "${got}" == "${target_mm}" ]]; then
        log "Venv already exists and matches target Python ${target_mm}: ${VENV_DIR}"
        log "Activate with:"
        log "  source '${VENV_DIR}/bin/activate'"
        exit 0
      fi
      warn "Existing venv Python ${got:-<unknown>} does not match target ${target_mm}; rebuilding."
      move_existing_venv_aside
    else
      warn "Existing venv directory is missing expected files; rebuilding."
      move_existing_venv_aside
    fi
  fi

  mkdir -p "${SCRIPT_DIR}"

  if [[ "${USE_UV:-}" == "1" ]]; then
    create_venv_uv "${target_mm}"
  else
    create_venv_system_python "${target_mm}"
  fi

  if ! is_valid_venv; then
    die "Venv creation failed; missing ${VENV_DIR}/bin/activate or ${VENV_DIR}/bin/python"
  fi

  local final_mm
  final_mm="$(venv_python_mm || true)"
  if [[ "${final_mm}" != "${target_mm}" ]]; then
    die "Venv Python ${final_mm} does not match target ${target_mm}."
  fi

  log ""
  log "[bootstrap] Done. Venv is ready at: ${VENV_DIR}"
  log "Activate with:"
  log "  source '${VENV_DIR}/bin/activate'"
  log ""
  log "Then run:"
  log "  python '${SCRIPT_DIR}/network_tools_setup.py' --all"
}

main "$@"
