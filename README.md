# Network Tools — Production Deployment (Containers / Rootless Docker)

This README is the **production deployment runbook** for the container stack (Vault, Vault agents, Postgres, pgAdmin, Keycloak).
It is organized in the execution order you will actually follow in production.

- **Server/OS provisioning** is intentionally out of scope here.
- A **verbatim backup** of the original `README.full.md` is included at the end (Appendix C) to ensure no details are lost.

---
>ITEMS OF NOTE:
> The repository is being converted to be able to use a single domain name. Currently it's coded to use
> the one I recently registered. For now, on my local development machine The hosts file points to my VM. 
> You can use that locally yourself, or change it to the value you want in the .env file. Once done you build / rebuild
> as normal and it should flow to the rest of the system. 

---

## Table of Contents

- [1. Setup via build scripts (certificate + bootstrap + AppRole)](#1-setup-via-build-scripts-certificate--bootstrap--approle)
- [2. Bring-up order (containers)](#2-bring-up-order-containers)
- [3. Verify health (required checks)](#3-verify-health-required-checks)
- [4. Smoke tests (minimal production validation)](#4-smoke-tests-minimal-production-validation)
- [Appendix A — Troubleshooting / Gotchas](#appendix-a--troubleshooting--gotchas)
- [Appendix B — Additional How-Tos](#appendix-b--additional-how-tos)

---

## 1. Setup via build scripts (certificate + bootstrap + AppRole)

All scripts below are expected to be run from the repo root (e.g., `~/NETWORK_TOOLS`) as the rootless Docker user.

### 1.1 Recommended script execution order

Run these **in order**:

The original steps 1 - 4 have been replaced with generate_local_networkengineertools_certs.sh, but I left them here for now for reference as this is being 
moved to a single domain, and single cert requirement. You could use these if you wish to convert one of these containers to a 
solo setup. IE you could run a local version of vault/keycloak etc on your system wih it's own local certificate file without needing to boot
the rest of the containers (Specifically NGINX)


---

Legacy / not in use (kept for reference):
- `./backend/build_scripts/generate_local_vault_certs.sh`
- `./backend/build_scripts/generate_local_postgres_certs.sh`
- `./backend/build_scripts/generate_local_pgadmin_certs.sh`
- `./backend/build_scripts/generate_local_keycloak_certs.sh`
---

---
>NOTE: This build is going off my one domain setup. This can be set / changed in the .env file.

1` ./backend/build_scripts/generate_local_networkengineertools_certs.sh`
2` ./backend/build_scripts/vault_first_time_init_only_rootless.sh` *(first-time Vault only)*  
3` ./backend/build_scripts/generate_postgres_pgadmin_bootstrap_creds_and_seed.sh`  
4` ./backend/build_scripts/postgress_approle_setup.sh` (Step 2 must create the approle auth method or this will fail)  
5` ./backend/build_scripts/keycloak_approle_setup.sh` (Step 2 must create the approle auth method or this will fail)  
---

### 1.0 Initial BASE File system structure
```bash
developer_network_tools@networktoolsvm:~/NETWORK_TOOLS$ tree --charset ascii
.
|-- backend
|   |-- app
|   |   |-- fastapi
|   |   |   `-- vault_agent
|   |   |       |-- agent.hcl
|   |   |       `-- templates
|   |   |           `-- fastapi_secrets.json.ctmpl
|   |   |-- keycloak
|   |   |   |-- bin
|   |   |   |   `-- keycloak_entrypoint_from_vault.sh
|   |   |   `-- vault_agent
|   |   |       |-- agent.hcl
|   |   |       |-- keycloak_agent_policy.hcl
|   |   |       `-- templates
|   |   |           |-- keycloak.env.ctmpl
|   |   |           |-- keycloak_tls.crt.ctmpl
|   |   |           `-- keycloak_tls.key.ctmpl
|   |   |-- nginx
|   |   |   |-- certs
|   |   |   `-- templates
|   |   |       |-- networktools.conf.template
|   |   |       `-- vault.conf.template
|   |   |-- pgadmin
|   |   |   `-- certs
|   |   |-- postgres
|   |   |   |-- certs
|   |   |   |-- config
|   |   |   |   |-- pg_hba.conf
|   |   |   |   `-- postgres.conf
|   |   |   `-- vault_agent
|   |   |       |-- agent.hcl
|   |   |       `-- templates
|   |   |           |-- pgadmin_password.ctmpl
|   |   |           |-- postgres_db.ctmpl
|   |   |           |-- postgres_password.ctmpl
|   |   |           |-- postgres_user.ctmpl
|   |   |           `-- servers.json.ctmpl
|   |   |-- routers
|   |   `-- security
|   |       `-- configuration_files
|   |           `-- vault
|   |               |-- config
|   |               |   |-- certs
|   |               |   |-- keycloak_kv_read.hcl
|   |               |   |-- postgres_pgadmin_kv_read.hcl
|   |               |   `-- vault_configuration_primary_node.hcl
|   |               `-- Dockerfile
|   |-- build_scripts
|   |   |-- generate_local_keycloak_certs.sh
|   |   |-- generate_local_networkengineertools_certs.sh
|   |   |-- generate_local_pgadmin_certs.sh
|   |   |-- generate_local_postgres_certs.sh
|   |   |-- generate_local_vault_certs.sh
|   |   |-- generate_postgres_pgadmin_bootstrap_creds_and_seed.sh
|   |   |-- guides
|   |   |   |-- seed_kv_spec.example.json
|   |   |   `-- seed_kv_spec.GUIDE.md
|   |   |-- keycloak_approle_setup.sh
|   |   |-- postgress_approle_setup.sh
|   |   |-- seed_postgres_with_vault_credentials.sh
|   |   |-- startover_scripts
|   |   |   `-- reset_network_tools_docker.sh
|   |   |-- validation_scripts
|   |   |   |-- check_approle_presence_and_ids_in_vault.sh
|   |   |   |-- postgres_inventory.sh
|   |   |   `-- read_postgres_pgadmin_approle.sh
|   |   |-- vault_first_time_init_only_rootless.sh
|   |   |-- vault_unseal_kv_seed_bootstrap_rootless.sh
|   |   `-- vault_unseal_multi_kv_seed_bootstrap_rootless.sh
|   `-- nginx
|-- docker-compose.prod.yml
|-- frontend
|-- LICENSE
|-- README.full.md
`-- README.md
```

### 1.2 Build Scripts - Generate Local Certificates

#### First-time local certificate file creation. You can skip this step if you are using your own CA. You need to place the files in the same locations though. 

>NOTE: This script is hardcoded to the domain of my choice and does not pull from the .env file. If you wish to use it with another domain
> you need to update it manually for now. 

```bash
bash $HOME/NETWORK_TOOLS/backend/build_scripts/generate_local_networkengineertools_certs.sh
```

>NOTE: The new directory structure below<br>
> Walkthrough video [can be found here](https://youtu.be/w5MW_b8s0Rc)
```bash
developer_network_tools@networktoolsvm:~/NETWORK_TOOLS$ tree --charset ascii
.
|-- backend
|   |-- app
|   |   |-- fastapi
|   |   |   `-- vault_agent
|   |   |       |-- agent.hcl
|   |   |       `-- templates
|   |   |           `-- fastapi_secrets.json.ctmpl
|   |   |-- keycloak
|   |   |   |-- bin
|   |   |   |   `-- keycloak_entrypoint_from_vault.sh
|   |   |   `-- vault_agent
|   |   |       |-- agent.hcl
|   |   |       |-- keycloak_agent_policy.hcl
|   |   |       `-- templates
|   |   |           |-- keycloak.env.ctmpl
|   |   |           |-- keycloak_tls.crt.ctmpl
|   |   |           `-- keycloak_tls.key.ctmpl
|   |   |-- nginx
|   |   |   |-- certs
|   |   |   |   |-- ca.crt          (NEW: CA public certificate (public key + CA identity))
|   |   |   |   |-- ca.key          (NEW: CA private key)
|   |   |   |   |-- ca.srl          (NEW: OpenSSL serial number tracking file for the CA, Remove from runtime after issuance, Keep only with the CA signing material (with ca.key) in a secure PKI workspace if you will continue issuing certs.)
|   |   |   |   |-- cert.crt        (NEW: private key corresponding to the certificate Nginx presents)
|   |   |   |   |-- cert.key        (NEW: Keep, but treat as sensitive, chmod 600, owned by root (or the Nginx runtime user), readable only by Nginx.)
|   |   |   |   `-- cert.leaf.crt   (NEW: The leaf/server certificate only (no chain), Keep only if your Nginx config or your tooling explicitly uses it. Remove and keep safe wih the others.)
|   |   |   `-- templates
|   |   |       |-- networktools.conf.template
|   |   |       `-- vault.conf.template
|   |   |-- pgadmin
|   |   |   `-- certs
|   |   |-- postgres
|   |   |   |-- certs
|   |   |   |-- config
|   |   |   |   |-- pg_hba.conf
|   |   |   |   `-- postgres.conf
|   |   |   `-- vault_agent
|   |   |       |-- agent.hcl
|   |   |       `-- templates
|   |   |           |-- pgadmin_password.ctmpl
|   |   |           |-- postgres_db.ctmpl
|   |   |           |-- postgres_password.ctmpl
|   |   |           |-- postgres_user.ctmpl
|   |   |           `-- servers.json.ctmpl
|   |   |-- routers
|   |   `-- security
|   |       `-- configuration_files
|   |           `-- vault
|   |               |-- certs
|   |               |   |-- ca.crt      (NEW: CA public certificate (public key + CA identity))
|   |               |   |-- cert.crt    (NEW: CA private key - Remove from the production runtime host/container path immediately after issuance.)
|   |               |   `-- cert.key    (NEW)
|   |               |-- config
|   |               |   |-- certs
|   |               |   |-- keycloak_kv_read.hcl
|   |               |   |-- postgres_pgadmin_kv_read.hcl
|   |               |   `-- vault_configuration_primary_node.hcl
|   |               `-- Dockerfile
|   |-- build_scripts
|   |   |-- generate_local_keycloak_certs.sh
|   |   |-- generate_local_networkengineertools_certs.sh
|   |   |-- generate_local_pgadmin_certs.sh
|   |   |-- generate_local_postgres_certs.sh
|   |   |-- generate_local_vault_certs.sh
|   |   |-- generate_postgres_pgadmin_bootstrap_creds_and_seed.sh
|   |   |-- guides
|   |   |   |-- seed_kv_spec.example.json
|   |   |   `-- seed_kv_spec.GUIDE.md
|   |   |-- keycloak_approle_setup.sh
|   |   |-- postgress_approle_setup.sh
|   |   |-- seed_postgres_with_vault_credentials.sh
|   |   |-- startover_scripts
|   |   |   `-- reset_network_tools_docker.sh
|   |   |-- validation_scripts
|   |   |   |-- check_approle_presence_and_ids_in_vault.sh
|   |   |   |-- postgres_inventory.sh
|   |   |   `-- read_postgres_pgadmin_approle.sh
|   |   |-- vault_first_time_init_only_rootless.sh
|   |   |-- vault_unseal_kv_seed_bootstrap_rootless.sh
|   |   `-- vault_unseal_multi_kv_seed_bootstrap_rootless.sh
|   `-- nginx
|-- docker-compose.prod.yml
|-- frontend
|-- LICENSE
|-- README.full.md
`-- README.md

33 directories, 53 files
```

# First-time Vault only (creates root_token + init json artifacts)
>NOTE:<br>init-shares -> How many password shards you want to generate<br> init-threshold -> How many of those shards are required to unseal the vault

>NOTE:The vault address is derived from the .env file, or if will fail to the container name if it's missing. <br>https://vault.${PRIMARY_SERVER_FQDN}

```bash
bash ./backend/build_scripts/vault_first_time_init_only_rootless.sh \
  --ca-cert "$HOME/NETWORK_TOOLS/backend/app/nginx/certs/ca.crt" \
  --init-shares 5 --init-threshold 3
```

# Generate and Seed Postgres/pgAdmin/Keycloak bootstrap credentials + KV spec artifacts

>NOTE: --unseal-required should match --init-threshold.<br> 
> This tells the script how many keys are required to unseal vault if it's sealed.
> This script will generate all the initial credentials you need to configure and use each service as well as seeding vault with them. <br><br>
> <b>Make sure you REMOVE THEM afterwards and do not leave them on your filesystem!</b>

```bash
bash ./backend/build_scripts/generate_postgres_pgadmin_bootstrap_creds_and_seed.sh \
  --ca-cert "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt" \
  --unseal-required 3
```

# Create AppRoles (writes role_id + secret_id artifacts to ./container_data/vault/approle/*)
>NOTE: Very important Gotcha. These scripts will generate a 1 time use only token for the secret id. 
> Meaning, if the vault agent was ever restarted / recreated it would fail authentication to vault. 
> You will need to re run these to generate a new secret id each time. If not it would not be able to fetch any 
> environment or secret variables from vault and inject them into their sister containers. EG keycloak/pgadmin/postgres
> and depending on what you're doing would cause a boot failure.

```bash
chmod +x ./backend/build_scripts/keycloak_approle_setup.sh
ROLE_NAME=keycloak_agent ./backend/build_scripts/keycloak_approle_setup.sh
```

```bash
chmod +x ./backend/build_scripts/postgress_approle_setup.sh
ROLE_NAME=postgres_pgadmin_agent ./backend/build_scripts/postgress_approle_setup.sh
```

>NOTE: There is a helper script that will query vault and show you the values stored there as well as the local copies.
> This helps ensure vault is ready to bring up the vault_agent containers

```bash
bash ./backend/build_scripts/validation_scripts/check_approle_presence_and_ids_in_vault.sh
```
<br>

>Example output below

```bash
developer_network_tools@networktoolsvm:~/NETWORK_TOOLS$ bash ./backend/build_scripts/validation_scripts/check_approle_presence_and_ids_in_vault.sh
INFO: Loading env defaults from: /home/developer_network_tools/NETWORK_TOOLS/.env
INFO: WARN: VAULT_CACERT_IN_CONTAINER '/vault/certs/ca.crt' not found in container; using /vault/certs/cert.crt

postgres_pgadmin_agent role_id (host):  8b1fa843-462e-5d0e-29f7-eb6f8c8f1dd8
postgres_pgadmin_agent role_id (vault): 8b1fa843-462e-5d0e-29f7-eb6f8c8f1dd8

keycloak_agent role_id (host):  8ba04cd6-1f55-505c-65e6-c89823db8575
keycloak_agent role_id (vault): 8ba04cd6-1f55-505c-65e6-c89823db8575
```

>NOTE: A few points on the approle scripts

```text
- Both `./backend/build_scripts/postgress_approle_setup.sh` and `./backend/build_scripts/keycloak_approle_setup.sh`:
  - read the Vault admin token from `./backend/app/security/configuration_files/vault/bootstrap/root_token` (or `root_token.json`), and securely prompt if missing
  - write artifacts to `./container_data/vault/approle/<ROLE_NAME>/{role_id,secret_id}`
  - rotate `secret_id` by default (`ROTATE_SECRET_ID=1`)
- Optional overrides (same for both scripts):
  - `ROLE_NAME="<name>" ./backend/build_scripts/<script>.sh`
  - `ROTATE_SECRET_ID=0 ./backend/build_scripts/<script>.sh`
  - `OUT_DIR="/custom/path" ./backend/build_scripts/<script>.sh`
```

Skip to section 2.3 if the above completed successfully. 






### 1.3 Validate the script artifacts exist

```bash
# Vault init artifacts
ls -lah ./backend/app/security/configuration_files/vault/bootstrap/ || true
ls -lah ./backend/app/security/configuration_files/vault/bootstrap/root_token || true

# AppRole artifacts (created by the AppRole setup scripts)
find ./container_data/vault/approle -maxdepth 3 -type f \( -name role_id -o -name secret_id \) -print

# Certs (locations vary; see Appendix C for the full tree + paths used in this repo)
find ./backend -maxdepth 6 -type f \( -name "ca.crt" -o -name "cert.crt" -o -name "cert.key" -o -name "*.pem" \) -print | head -n 200
```

---

## 2. Bring-up order (containers)
### 2.1 Removed this section - Completed with the init script
### 2.2 Prepare AppRole artifacts (RoleID + SecretID) **before** starting Vault Agents

Vault Agents authenticate using **AppRole**. They require host-side artifacts mounted into the agent container(s):

- `./container_data/vault/approle/postgres_pgadmin_agent/{role_id,secret_id}`
- `./container_data/vault/approle/keycloak_agent/{role_id,secret_id}`

If you already ran the AppRole setup scripts in **Section 1**, you can skip the script run and just verify the files exist.

```bash
# (Re)export AppRole artifacts (recommended on first deploy and after any Vault reset)
bash ./backend/build_scripts/postgress_approle_setup.sh
bash ./backend/build_scripts/keycloak_approle_setup.sh

# Verify artifacts exist (host)
ls -lah ./container_data/vault/approle/postgres_pgadmin_agent
ls -lah ./container_data/vault/approle/keycloak_agent
```

Notes:

- The Keycloak and Postgres/pgAdmin AppRole setup scripts are intentionally **standardized** (same behaviors; different default role/output paths).
- Defaults:
  - `postgress_approle_setup.sh` → `ROLE_NAME=postgres_pgadmin_agent`, `OUT_DIR=./container_data/vault/approle/postgres_pgadmin_agent`
  - `keycloak_approle_setup.sh` → `ROLE_NAME=keycloak_agent`, `OUT_DIR=./container_data/vault/approle/keycloak_agent`
- `ROTATE_SECRET_ID=1` by default (recommended). Set `ROTATE_SECRET_ID=0` only if you explicitly want to keep the existing `secret_id`.
- If the Vault data volume was wiped/recreated, you **must** re-run these scripts (old RoleID/SecretID artifacts will not match the new Vault state).


### 2.3 Start Vault Agents (must authenticate before dependent services)

```bash
docker compose -f docker-compose.prod.yml up -d vault_agent_postgres_pgadmin vault_agent_keycloak

docker compose -f docker-compose.prod.yml ps

docker logs --tail 200 -f vault_agent_postgres_pgadmin
docker logs --tail 200 -f vault_agent_keycloak

```

### 2.4 Start Postgres

```bash
docker compose -f docker-compose.prod.yml up -d postgres_primary
docker compose -f docker-compose.prod.yml ps
docker logs --tail 200 -f postgres_primary
```

When postgres is started and confirmed up and running, You will need to configure it with the generated credentials so 
keycloak / fastapi and any future containers can connect to it.
This will seed any configured logins destined for postgres as well as create any needed databases in postgres

```bash
chmod +x ./backend/build_scripts/seed_postgres_with_vault_credentials.sh
./backend/build_scripts/seed_postgres_with_vault_credentials.sh \
  --ca-cert "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt"
```

### 2.5 Start pgAdmin

>NOTE: pgAdmin configurations include a servers.json file that gets populated with the main postgres database information 
> so it will connect to it automatically. Right now, it will connect with the root account. In future updates, there will be 
> user accounts created with limited access. This is just part of the init process for testing. In practice, the root account should be behind the vault
> and locked behind a key.

```bash
docker compose -f docker-compose.prod.yml up -d pgadmin
docker compose -f docker-compose.prod.yml ps
docker logs --tail 200 -f pgadmin
```

### 2.6 Start Keycloak

```bash
docker compose -f docker-compose.prod.yml up -d keycloak
docker compose -f docker-compose.prod.yml ps
docker logs --tail 200 -f keycloak
```

### 2.7 Start NGINX
>NOTE: NGINX is dependent on the primary containers it proxys in order for it to come up.
> Those are
> -Vault
> -Keycloak
> -FastAPI
> -PGadmin

```bash
docker compose -f docker-compose.prod.yml up -d --no-deps --build --force-recreate nginx_gateway
docker logs --tail 200 -f nginx_gateway
```

---

## 3. Verify health (required checks)

### 3.1 Global container health

```bash
docker compose -f docker-compose.prod.yml ps
```

### 3.2 Vault health (must be OK before anything else is “real”)

```bash
docker exec -it vault_production_node sh -lc '
  export VAULT_ADDR="https://127.0.0.1:8200"
  export VAULT_CACERT="/vault/certs/ca.crt"
  vault status
'
```

### 3.3 AppRole presence and IDs in Vault

```bash
# A helper script has been added for this in 
#
# NETWORK_TOOLS/backend/build_scripts/validation_scripts/check_approle_presence_and_ids_in_vault.sh
# Run with 
# bash ./backend/build_scripts/validation_scripts/check_approle_presence_and_ids_in_vault.sh
#
# Compare host RoleID artifacts against what Vault reports for each AppRole.
# (Do NOT test secret_id via a login here; in this repo it is commonly configured as single-use.)

BOOTSTRAP_DIR="./backend/app/security/configuration_files/vault/bootstrap"
VAULT_TOKEN="$(cat "$BOOTSTRAP_DIR/root_token")"

check_role_id() {
  local role_name="$1"
  local role_dir="./container_data/vault/approle/${role_name}"
  local role_id_host role_id_vault

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

```

### 3.4 Vault Agent rendered files (pgAdmin/Postgres)

```bash
docker exec -it vault_agent_postgres_pgadmin sh -lc 'ls -lah /vault/rendered || true'
docker exec -it pgadmin sh -lc 'ls -lah /run/vault || true'
```

### 3.5 Postgres connectivity (from inside the container)

```bash
docker exec -it postgres_primary sh -lc '
  set -e
  DB="$(cat /run/vault/postgres_db 2>/dev/null || echo postgres)"
  PASS="$(cat /run/vault/postgres_password 2>/dev/null)"
  export PGPASSWORD="$PASS"
  psql -h 127.0.0.1 -U network_tools_user -d "$DB" -c "\conninfo"
'
```

### 3.6 pgAdmin server registration and password behavior

- `servers.json` can pre-register server(s), but pgAdmin has security controls around how passwords are supplied/saved in server mode.
- If you use `PasswordExecCommand`, ensure server-mode support is enabled (see Appendix A).
- `servers.json` is only loaded on **first launch** when the pgAdmin configuration DB is created.

### 3.7 Keycloak readiness

```bash
docker logs --tail 200 -f keycloak
```

---

## 4. Smoke tests (minimal production validation)

1) Vault: `vault status` is unsealed.  
2) Vault agent: rendered secrets exist and are updated.  
3) Postgres: `psql \conninfo` succeeds via TLS as configured.  
4) pgAdmin: server is present; connection succeeds without manual password entry (if configured accordingly).  
5) Keycloak: UI loads and reaches the login page; logs show successful startup; DB connectivity is healthy.

---


---

## 5. Validate GUI access to the containers through NGINX and access via the credentials saved in the vault.

Access via the bootstrapped root token at first. 

```bash
cat ./backend/app/security/configuration_files/vault/bootstrap/root_token
```

URL<br>

https://vault.networkengineertools.com:8200

Vault Path

Secrets<br>
app_network_tools_secrets<br>
keycloak_bootstrap<br>
KC_BOOTSTRAP_ADMIN_PASSWORD<br>
KC_BOOTSTRAP_ADMIN_USERNAME<br>

URL

https://auth.networkengineertools.com:8443


Vault Path

Secrets<br>
app_network_tools_secrets<br>
pgadmin<br>
PGADMIN_DEFAULT_EMAIL<br>
PGADMIN_DEFAULT_PASSWORD<br>

URL

https://pgadmin.networkengineertools.com:8443

---

## Appendix A — Troubleshooting / Gotchas

### A.1 pgAdmin prompts for the database password even though `PasswordExecCommand` is set in `servers.json`

In pgAdmin **server mode**, the Password Exec Command feature is disabled by default unless enabled explicitly via configuration.
In container deployments, `PGADMIN_CONFIG_*` environment overrides are only written once unless you instead mount `config_local.py`.

Recommended production fix:

- Add to pgAdmin environment:
  - `PGADMIN_CONFIG_ENABLE_SERVER_PASS_EXEC_CMD=True`

Or mount `/pgadmin4/config_local.py` with:

```python
ENABLE_SERVER_PASS_EXEC_CMD = True
```

Also confirm:
- `servers.json` was imported (first launch only unless you reload explicitly)
- `/run/vault/postgres_password` is readable by UID/GID 5050 inside the pgAdmin container

### A.2 `servers.json` changes do not show up

If you persist `/var/lib/pgadmin`, editing `servers.json` and restarting will not re-import it.
Reload explicitly (Appendix B) or wipe the pgAdmin config DB volume.

### A.3 Vault Agent says “no known role ID”

Usually:
- RoleID/SecretID artifacts are missing or paths/mounts don’t match the Agent’s expected locations
- Vault is sealed, wrong CA, wrong VAULT_ADDR, or wrong AppRole name

---

## Appendix B — Additional How-Tos

### B.1 Force pgAdmin to reload server definitions from `servers.json`

Option 1 (cleanest): wipe the pgAdmin config DB volume and restart with the desired `servers.json`.

Option 2: Load/replace servers using the setup tooling:

```bash
docker exec -it pgadmin sh -lc '
  python /pgadmin4/setup.py load-servers /pgadmin4/servers.json --replace
'
```