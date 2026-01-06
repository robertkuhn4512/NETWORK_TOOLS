#!/usr/bin/env bash
set -euo pipefail

# -----------------------------------------------------------------------------
# postgres_inventory.sh
#
# Notes / How to run:
#   chmod +x ./backend/build_scripts/validation_scripts/postgres_inventory.sh
#   bash ./backend/build_scripts/validation_scripts/postgres_inventory.sh
#
# What it does:
#   - Loads bootstrap env: ./backend/app/security/configuration_files/vault/bootstrap/postgres_pgadmin.env
#   - Connects to Postgres *inside the container* over TCP (127.0.0.1) using SSL
#   - Prints roles/users and databases
#
# Optional overrides:
#   --container postgres_primary
#   --env-file  ./backend/app/security/configuration_files/vault/bootstrap/postgres_pgadmin.env
#   --host      127.0.0.1
#   --port      5432
#   --db        postgres
# -----------------------------------------------------------------------------

err() { echo "{\"error\":\"$*\"}" >&2; exit 1; }

CONTAINER="postgres_primary"
ENV_FILE="./backend/app/security/configuration_files/vault/bootstrap/postgres_pgadmin.env"
PGHOST="127.0.0.1"
PGPORT="5432"
PGDB="postgres"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --container) CONTAINER="${2:-}"; shift 2 ;;
    --env-file)  ENV_FILE="${2:-}"; shift 2 ;;
    --host)      PGHOST="${2:-}"; shift 2 ;;
    --port)      PGPORT="${2:-}"; shift 2 ;;
    --db)        PGDB="${2:-}"; shift 2 ;;
    -h|--help)
      cat <<EOF
Usage:
  postgres_inventory.sh [--container NAME] [--env-file PATH] [--host HOST] [--port PORT] [--db DB]

Defaults:
  --container  postgres_primary
  --env-file   ./backend/app/security/configuration_files/vault/bootstrap/postgres_pgadmin.env
  --host       127.0.0.1
  --port       5432
  --db         postgres
EOF
      exit 0
      ;;
    *) err "Unknown argument: $1" ;;
  esac
done

[[ -n "$CONTAINER" ]] || err "--container is required"
[[ -f "$ENV_FILE" ]] || err "Bootstrap env file not found: $ENV_FILE"

command -v docker >/dev/null 2>&1 || err "docker not found in PATH"

# Load env file safely (expects KEY=VALUE pairs)
# shellcheck disable=SC1090
set -a
source "$ENV_FILE"
set +a

# Accept common naming conventions from your bootstrap file
PGUSER="${POSTGRES_USER:-${PG_USER:-postgres}}"
PGPASS="${POSTGRES_PASSWORD:-${PG_PASSWORD:-}}"

[[ -n "$PGPASS" ]] || err "Password not found in env file (expected POSTGRES_PASSWORD or PG_PASSWORD)."

# Sanity check container exists / running
if ! docker ps --format '{{.Names}}' | grep -qx "$CONTAINER"; then
  err "Container not running or not found: $CONTAINER"
fi

echo "=== Postgres inventory (container: $CONTAINER) ==="
echo "Using bootstrap env: $ENV_FILE"
echo "Connecting as user: $PGUSER"
echo "Target: ${PGHOST}:${PGPORT}/${PGDB} (TCP + SSL)"
echo

docker exec -i \
  -e "PGPASSWORD=$PGPASS" \
  -e "PGHOST=$PGHOST" \
  -e "PGPORT=$PGPORT" \
  -e "PGDATABASE=$PGDB" \
  -e "PGUSER=$PGUSER" \
  "$CONTAINER" sh -lc '
    set -e

    command -v psql >/dev/null 2>&1 || { echo "{\"error\":\"psql not found inside container\"}" >&2; exit 1; }

    # Prefer verify-ca if we have the CA file inside the container
    if [ -f /etc/postgres/certs/ca.crt ]; then
      export PGSSLMODE="verify-ca"
      export PGSSLROOTCERT="/etc/postgres/certs/ca.crt"
    else
      # Still enforce TLS if CA isn’t available (no hostname verification)
      export PGSSLMODE="require"
      unset PGSSLROOTCERT || true
    fi

    echo "--- Server / session info ---"
    psql -v ON_ERROR_STOP=1 -P pager=off -c "SELECT version();"
    psql -v ON_ERROR_STOP=1 -P pager=off -c "SELECT current_user, current_database(), inet_server_addr(), inet_server_port();"

    echo
    echo "--- Roles / Users (SQL) ---"
    psql -v ON_ERROR_STOP=1 -P pager=off -c "
      SELECT
        rolname AS role,
        rolcanlogin AS can_login,
        rolsuper AS superuser,
        rolcreatedb AS create_db,
        rolcreaterole AS create_role,
        rolreplication AS replication
      FROM pg_roles
      ORDER BY rolname;
    "

    echo
    echo "--- Databases (SQL) ---"
    psql -v ON_ERROR_STOP=1 -P pager=off -c "
      SELECT
        datname AS database,
        pg_get_userbyid(datdba) AS owner,
        datallowconn AS allow_conn,
        datistemplate AS is_template
      FROM pg_database
      ORDER BY datname;
    "

    echo
    echo "--- Roles / Users (\\du+) ---"
    psql -v ON_ERROR_STOP=1 -P pager=off -c "\\du+"

    echo
    echo "--- Databases (\\l+) ---"
    psql -v ON_ERROR_STOP=1 -P pager=off -c "\\l+"
  '

echo
echo "Done."
