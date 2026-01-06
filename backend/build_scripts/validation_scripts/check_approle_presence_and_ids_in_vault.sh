#!/usr/bin/env bash
# Run with the command below. Example output included
#
# bash ./backend/build_scripts/validation_scripts/check_approle_presence_and_ids_in_vault.sh
#
# postgres_pgadmin_agent role_id (host):  2330ad1b-7e23-2e35-975d-659dc2029065
# postgres_pgadmin_agent role_id (vault): 2330ad1b-7e23-2e35-975d-659dc2029065
#
# keycloak_agent role_id (host):  8d2b6102-9be8-1521-7f4d-4d097bac60a7
# keycloak_agent role_id (vault): 8d2b6102-9be8-1521-7f4d-4d097bac60a7
#
# Compare host RoleID artifacts against what Vault reports for each AppRole.
# (Do NOT test secret_id via a login here; in this repo it is commonly configured as single-use.)

BOOTSTRAP_DIR="./backend/app/security/configuration_files/vault/bootstrap"
VAULT_TOKEN="$(cat "$BOOTSTRAP_DIR/root_token")"

check_role_id() {
  local role_name="$1"
  local role_dir="./container_data/vault/approle/${role_name}"
  local role_id_host role_id_vault

  role_id_host="$(cat "$role_dir/role_id")"

  role_id_vault="$(
  docker exec \
    -e VAULT_ADDR="https://vault_production_node:8200" \
    -e VAULT_CACERT="/vault/certs/cert.crt" \
    -e VAULT_TOKEN="$VAULT_TOKEN" \
    vault_production_node \
    vault read -format=json "auth/approle/role/${role_name}/role-id" \
  | jq -r '.data.role_id'
  )"

  echo
  echo "${role_name} role_id (host):  ${role_id_host}"
  echo "${role_name} role_id (vault): ${role_id_vault}"
}

check_role_id "postgres_pgadmin_agent"
check_role_id "keycloak_agent"
