# Network Tools — Production Deployment README (Containers / Rootless Docker)

This file is a **re-organization** of the existing `README.full.md` into a production-first flow focused on **containers** and their supporting **build/bootstrap scripts**.

Key goals:

- Provide a single, predictable **execution order** (scripts → Vault → AppRoles → agents → services).
- Provide explicit **health/verification checks** after each phase.
- Move “gotchas” and failure modes into a **Troubleshooting appendix**.
- Preserve full reference material to ensure nothing is lost.

> Note: The prior `README.production.md` that was generated earlier was a shortened runbook. This revision preserves the complete reference content and adds a production-first organization layer.

## Table of Contents (Production Flow)

- [1. Setup via build scripts](#1-setup-via-build-scripts)
- [2. Bring-up order (containers)](#2-bring-up-order-containers)
- [3. Verify container health and service readiness](#3-verify-container-health-and-service-readiness)
- [4. Detailed Reference (re-ordered)](#4-detailed-reference-re-ordered)
- [Appendix A — Troubleshooting / Gotchas](#appendix-a--troubleshooting--gotchas)
- [Appendix B — Additional How-Tos](#appendix-b--additional-how-tos)
- [Appendix C — Original README.full.md (verbatim backup)](#appendix-c--original-readmefullmd-verbatim-backup)

## 1. Setup via build scripts

Run the build/bootstrap scripts from the repo root (`$HOME/NETWORK_TOOLS`) as the same non-root user that runs rootless Docker (e.g., `developer_network_tools`).

### 1.1 Recommended execution order

1) Vault TLS certificates
2) Postgres TLS certificates
3) Keycloak TLS certificates
4) Vault first-time init + unseal (first run only)
5) Seed initial Postgres/pgAdmin credentials into Vault
6) Create/export AppRole artifacts for the Postgres/pgAdmin Vault Agent
7) Create/export AppRole artifacts for the Keycloak Vault Agent

### 1.2 Script quick commands (as documented in the full README)

```bash
# 1) Vault TLS (required before Vault starts)
chmod +x ./backend/build_scripts/generate_local_vault_certs.sh
./backend/build_scripts/generate_local_vault_certs.sh --force

# 2) Postgres TLS (required before Postgres starts if TLS is enabled)
bash ./backend/build_scripts/generate_local_postgres_certs.sh

# 3) Keycloak TLS (used for KC HTTPS material seeded to Vault for the Keycloak Agent)
bash ./backend/build_scripts/generate_local_keycloak_certs.sh

# 4) Vault first-time init + unseal (first-time Vault only)
chmod +x ./backend/build_scripts/vault_first_time_init_only_rootless.sh
./backend/build_scripts/vault_first_time_init_only_rootless.sh

# 5) Generate + seed Postgres/pgAdmin bootstrap credentials into Vault
chmod +x ./backend/build_scripts/generate_postgres_pgadmin_bootstrap_creds_and_seed.sh
./backend/build_scripts/generate_postgres_pgadmin_bootstrap_creds_and_seed.sh \
  --vault-addr "https://vault_production_node:8200" \
  --ca-cert "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt" \
  --unseal-required 3

# 6) AppRole export for Postgres/pgAdmin agent
chmod +x ./backend/build_scripts/postgress_approle_setup.sh
./backend/build_scripts/postgress_approle_setup.sh

# 7) AppRole export for Keycloak agent
bash ./backend/build_scripts/keycloak_approle_setup.sh \
  --ca-cert "./backend/app/security/configuration_files/vault/certs/ca.crt"
```

### 1.3 Where the scripts write artifacts

- Vault bootstrap artifacts (root token / unseal keys) are written under:
  - `./backend/app/security/configuration_files/vault/bootstrap/`
- AppRole artifacts are written under:
  - `./container_data/vault/approle/<ROLE_NAME>/{role_id,secret_id}`

The detailed, existing script documentation is preserved below under **Detailed Reference**.

## 2. Bring-up order (containers)

Bring services up in this order so that dependencies are satisfied and Vault Agents can render secrets before dependent services start:

1) Vault
2) AppRole creation + export (host artifacts)
3) Vault Agents (render secrets)
4) Postgres
5) pgAdmin
6) Keycloak

Example (adjust service names to match your compose file if different):

```bash
# Vault first
docker compose -f docker-compose.prod.yml up -d vault_production_node

# Vault Agents next (so they can render /run/vault/* into target containers)
docker compose -f docker-compose.prod.yml up -d vault_agent_postgres_pgadmin vault_agent_keycloak

# Then core services
docker compose -f docker-compose.prod.yml up -d postgres_primary pgadmin keycloak
```

## 3. Verify container health and service readiness

### 3.1 Compose-level status

```bash
docker compose -f docker-compose.prod.yml ps
```

### 3.2 Vault (must be first)

```bash
docker exec -e VAULT_ADDR="https://vault_production_node:8200" \
  -e VAULT_CACERT="/vault/certs/ca.crt" \
  vault_production_node vault status
```

Minimum expectations:
- `Initialized: true`
- `Sealed: false`
- No TLS errors when communicating with `https://vault_production_node:8200`

### 3.3 AppRoles (verify they exist in Vault)

Use the existing working steps in **0.1 Vault AppRole Authentication** (preserved below) to:
- List AppRoles
- Read a role’s `role_id`
- Generate a `secret_id`
- Optionally validate a login

Also verify host artifacts exist:

```bash
ls -lah ./container_data/vault/approle/ || true
```

### 3.4 Vault Agents (rendered secrets present)

Check that the agent authenticated and rendered files:

```bash
# Agent logs should NOT show: "no known role ID"
docker logs --tail 200 vault_agent_postgres_pgadmin
docker logs --tail 200 vault_agent_keycloak

# Rendered secrets (paths vary by container; these commands match common patterns in this repo)
docker exec -it vault_agent_postgres_pgadmin sh -lc 'ls -lah /vault/rendered || true'
docker exec -it pgadmin sh -lc 'ls -lah /run/vault || true'
```

### 3.5 Postgres

```bash
docker exec -it postgres_primary sh -lc '
  set -e
  DB="$(cat /run/vault/postgres_db 2>/dev/null || echo postgres)"
  PASS="$(cat /run/vault/postgres_password 2>/dev/null)"
  export PGPASSWORD="$PASS"
  psql -h 127.0.0.1 -U network_tools_user -d "$DB" -c "\\conninfo"
'
```

### 3.6 pgAdmin

- Confirm the container is running and that `PGADMIN_DEFAULT_PASSWORD_FILE` (or your chosen mechanism) is present and readable.
- Confirm you can log in to the pgAdmin UI and connect to the Postgres service.

### 3.7 Keycloak

- Confirm Keycloak starts without DB errors (e.g., `FATAL: database "keycloak" does not exist`).
- Confirm the HTTPS/UI endpoint is reachable from your workstation (hostname + port mapping).
- Confirm the Keycloak Vault Agent rendered the runtime env and TLS material expected by the entrypoint.

## 4. Detailed Reference (re-ordered)

The sections below are pulled from the original `README.full.md`, **re-ordered** to match the production execution flow.

> If you prefer to keep the original ordering, see **Appendix C** which contains the original `README.full.md` verbatim.

## 0. Repository File Structure

```text
Base Directory Structure - This is what you should start with prior to running any scripts.

developer_network_tools@networktoolsvm:~$ tree NETWORK_TOOLS --charset ascii
NETWORK_TOOLS
|-- backend
|   |-- app
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
|   |   |-- mariadb_queries
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
|   |   |           `-- postgres_user.ctmpl
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
|   |   |-- generate_local_postgres_certs.sh
|   |   |-- generate_local_vault_certs.sh
|   |   |-- generate_postgres_pgadmin_bootstrap_creds_and_seed.sh
|   |   |-- guides
|   |   |   |-- seed_kv_spec.example.json (I haven't decided if i'm keeping these. I need to test them more and possibly rewrite them
|   |   |   `-- seed_kv_spec.GUIDE.md
|   |   |-- keycloak_approle_setup.sh
|   |   |-- postgress_approle_setup.sh
|   |   |-- startover_scripts
|   |   |   `-- reset_network_tools_docker.sh
|   |   |-- vault_first_time_init_only_rootless.sh
|   |   |-- vault_unseal_kv_seed_bootstrap_rootless.sh
|   |   `-- vault_unseal_multi_kv_seed_bootstrap_rootless.sh
|   `-- nginx
|-- docker-compose.prod.yml
|-- environment_variable_guide.md
|-- frontend
|-- how_to_videos (TODO: Add updated how to Videos
|
`-- readme.md

```

---

## 0.1 Vault AppRole Authentication (Role ID and Secret ID)

This project uses Vault **AppRole** auth for non-interactive services (for example, the Postgres/pgAdmin Vault Agent) to obtain a Vault token at runtime.

Key concepts:

- **role_id**: a stable identifier for an AppRole (does not change unless the role is re-created).
- **secret_id**: a credential generated for the AppRole (rotate as often as you want).
- **login**: exchange `role_id + secret_id` for a Vault token via `auth/approle/login`.

When bootstrap scripts create an AppRole, they persist the artifacts on the **host** so other scripts/containers can consume them:

```text
./container_data/vault/approle/<ROLE_NAME>/
  role_id
  secret_id
```

Example (postgres/pgadmin agent):

```text
./container_data/vault/approle/postgres_pgadmin_agent/
  role_id
  secret_id
```

> Important: paths under `$HOME/NETWORK_TOOLS/...` are **host-only** paths.  
> When you run Vault commands via `docker exec`, the Vault CLI runs **inside the container**, where those host paths do not exist.

### 0.1.1 Validate that an AppRole exists and retrieve the Role ID

This repository assumes you **do not** have the Vault CLI installed on the host. Run the Vault CLI **inside the Vault container** using `docker exec`.

#### Recommended (readable): environment variables on the host

```bash
#####################################################################################
# AppRole Role ID (The host OS writes artifacts; Vault CLI runs inside the container)
#####################################################################################

# Host-side paths (exist on the VM host; NOT inside the container)
BOOTSTRAP_DIR="$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap"
ROLE_DIR="$HOME/NETWORK_TOOLS/container_data/vault/approle/postgres_pgadmin_agent"

# Vault container context
VAULT_ADDR="https://vault_production_node:8200"
VAULT_CONTAINER="vault_production_node"
VAULT_CACERT_CONTAINER="/vault/certs/cert.crt"

# Admin token (root token during first-time init)
VAULT_TOKEN="$(cat "$BOOTSTRAP_DIR/root_token")"

mkdir -p "$ROLE_DIR"

# Helper: run Vault CLI inside the Vault container with the right env vars
vaultc() {
  docker exec \
    -e VAULT_ADDR="$VAULT_ADDR" \
    -e VAULT_CACERT="$VAULT_CACERT_CONTAINER" \
    -e VAULT_TOKEN="$VAULT_TOKEN" \
    "$VAULT_CONTAINER" \
    vault "$@"
}

# List AppRoles (optional)
vaultc list auth/approle/role

# Read role_id (human-readable output)
vaultc read auth/approle/role/postgres_pgadmin_agent/role-id

# Persist role_id to host artifact file (JSON parsed on host via jq)
vaultc read -format=json auth/approle/role/postgres_pgadmin_agent/role-id \
  | jq -r '.data.role_id' > "$ROLE_DIR/role_id"

chmod 600 "$ROLE_DIR/role_id"
```

#### Fully expanded (no environment variables)

```bash
ROLE_DIR="$HOME/NETWORK_TOOLS/container_data/vault/approle/postgres_pgadmin_agent"
mkdir -p "$ROLE_DIR"

VAULT_TOKEN="$(cat "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token")"

docker exec \
  -e VAULT_ADDR="https://vault_production_node:8200" \
  -e VAULT_CACERT="/vault/certs/ca.crt" \
  -e VAULT_TOKEN="$VAULT_TOKEN" \
  vault_production_node \
  vault read -format=json auth/approle/role/postgres_pgadmin_agent/role-id \
| jq -r '.data.role_id' > "$ROLE_DIR/role_id"

chmod 600 "$ROLE_DIR/role_id"
```

### 0.1.2 Generate a new Secret ID

Generate a new `secret_id` for the AppRole and persist it to the host artifact directory.

#### Recommended (readable): environment variables on the host

```bash
BOOTSTRAP_DIR="$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap"
ROLE_DIR="$HOME/NETWORK_TOOLS/container_data/vault/approle/postgres_pgadmin_agent"
mkdir -p "$ROLE_DIR"

VAULT_TOKEN="$(cat "$BOOTSTRAP_DIR/root_token")"

docker exec \
  -e VAULT_ADDR="https://vault_production_node:8200" \
  -e VAULT_CACERT="/vault/certs/ca.crt" \
  -e VAULT_TOKEN="$VAULT_TOKEN" \
  vault_production_node \
  vault write -format=json -f auth/approle/role/postgres_pgadmin_agent/secret-id \
| jq -r '.data.secret_id' > "$ROLE_DIR/secret_id"

chmod 600 "$ROLE_DIR/secret_id"

```

#### Fully expanded (no environment variables)

```bash
ROLE_DIR="$HOME/NETWORK_TOOLS/container_data/vault/approle/postgres_pgadmin_agent"
mkdir -p "$ROLE_DIR"

VAULT_ADDR="https://vault_production_node:8200"
VAULT_CONTAINER="vault_production_node"
VAULT_CACERT_CONTAINER="/vault/certs/ca.crt"
VAULT_TOKEN="$(cat "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token")"

vaultc() {
  docker exec \
    -e VAULT_ADDR="$VAULT_ADDR" \
    -e VAULT_CACERT="$VAULT_CACERT_CONTAINER" \
    -e VAULT_TOKEN="$VAULT_TOKEN" \
    "$VAULT_CONTAINER" \
    vault "$@"
}

vaultc write -format=json -f auth/approle/role/postgres_pgadmin_agent/secret-id \
  | jq -r '.data.secret_id' > "$ROLE_DIR/secret_id"

chmod 600 "$ROLE_DIR/secret_id"
```

### 0.1.3 Optional: validate AppRole login

This confirms that `role_id + secret_id` can be exchanged for a token.

```bash
### This can be used if vaultc has already been defined from above. If not skip to the next block ###
ROLE_DIR="$HOME/NETWORK_TOOLS/container_data/vault/approle/postgres_pgadmin_agent"

ROLE_ID="$(cat "$ROLE_DIR/role_id")"
SECRET_ID="$(cat "$ROLE_DIR/secret_id")"

# Assumes VAULT_ADDR / VAULT_CONTAINER / VAULT_CACERT_CONTAINER already set
vaultc write -format=json auth/approle/login \
  role_id="$ROLE_ID" \
  secret_id="$SECRET_ID" \
| jq -r '.auth.client_token'
```

```bash
ROLE_DIR="$HOME/NETWORK_TOOLS/container_data/vault/approle/postgres_pgadmin_agent"

ROLE_ID="$(cat "$ROLE_DIR/role_id")"
SECRET_ID="$(cat "$ROLE_DIR/secret_id")"

docker exec \
  -e VAULT_ADDR="https://vault_production_node:8200" \
  -e VAULT_CACERT="/vault/certs/ca.crt" \
  vault_production_node \
  vault write -format=json auth/approle/login \
    role_id="$ROLE_ID" \
    secret_id="$SECRET_ID" \
| jq -r '.auth.client_token'
```

The returned token will have the policies assigned to the AppRole (for example, `postgres_pgadmin_read`).

## 0.2 Conventions (recommended environment variables)

To keep commands readable, the examples in this README are often provided in two forms:

- **Environment-variable form**: set a few variables once per shell session, then run shorter commands.
- **Fully expanded form**: no environment variables required.

### 0.2.1 Recommended host-side variables (run once per shell session)

```bash
export NT_ROOT="$HOME/NETWORK_TOOLS"
export COMPOSE_FILE="$NT_ROOT/docker-compose.prod.yml"

# Vault endpoint (host-side; used by scripts and curl)
export VAULT_ADDR="https://vault_production_node:8200"
export VAULT_CA_CERT="$NT_ROOT/backend/app/security/configuration_files/vault/certs/ca.crt"

# Bootstrap artifacts (written by the first-time init script)
export VAULT_BOOTSTRAP_DIR="$NT_ROOT/backend/app/security/configuration_files/vault/bootstrap"
export VAULT_ROOT_TOKEN_FILE="$VAULT_BOOTSTRAP_DIR/root_token"

# KV mount that stores the Postgres + pgAdmin credentials
# Repo default: app_network_tools_secrets
# Legacy/typo variant sometimes seen: app_postgress_secrets
export POSTGRES_KV_MOUNT="app_network_tools_secrets"
```

### 0.2.2 Container-side notes (Vault CLI via `docker exec`)

Many setup/validation commands below run the Vault CLI **inside** the Vault container so you do not need to install the Vault CLI on the host.

- Vault container name (repo default): `vault_production_node`
- Container-side CA path (mounted): `/vault/certs/ca.crt`

## 3. Vault Bring-up

This section documents how to generate local TLS material and start the **Vault** container using
`docker-compose.prod.yml` under **rootless Docker**.

Current target URL (may change later in production):

- `https://vault_production_node:8200`

> Note: For this URL to work from the *host* (browser/curl), the hostname `vault_production_node` must resolve to the host
running Docker (see Section 3.4).

### 3.1 Generate TLS Certificates

> Run the generator as **developer_network_tools** (no sudo).  
> Ensure OpenSSL is installed first (admin user).

1. Install OpenSSL (admin / sudo-capable user):

   ```bash
   sudo apt update
   sudo apt install -y openssl
   ```
<span id="vault-bootstrap-create-local-certs"></span>Run the certificate generator (developer user):

2. Run the certificate generator (developer user):

   ```bash
   cd ~/NETWORK_TOOLS
   chmod +x ./backend/build_scripts/generate_local_vault_certs.sh
   ./backend/build_scripts/generate_local_vault_certs.sh --force
   ```

>#Note: When these are locally generated and not populated from a trusted CA, Your file system will have<br>
>The following files created.

   ```bash
   developer_network_tools@networktoolsvm:~/NETWORK_TOOLS$ tree --charset ascii
    .
    |-- backend
    |   |-- app
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
    |   |   |-- mariadb_queries
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
    |   |   |           `-- postgres_user.ctmpl
    |   |   |-- routers
    |   |   `-- security
    |   |       `-- configuration_files
    |   |           `-- vault
    |   |               |-- certs
    |   |               |   |-- ca.crt <- NEW
    |   |               |   |-- ca.key <- NEW - Can be removed to safe storage
    |   |               |   |-- ca.srl <- NEW - Can be removed to safe storage
    |   |               |   |-- cert.crt <- NEW
    |   |               |   `-- cert.key <- NEW
    |   |               |-- config
    |   |               |   |-- certs
    |   |               |   |-- keycloak_kv_read.hcl
    |   |               |   |-- postgres_pgadmin_kv_read.hcl
    |   |               |   `-- vault_configuration_primary_node.hcl
    |   |               `-- Dockerfile
    |   |-- build_scripts
    |   |   |-- generate_local_keycloak_certs.sh
    |   |   |-- generate_local_postgres_certs.sh
    |   |   |-- generate_local_vault_certs.sh
    |   |   |-- generate_postgres_pgadmin_bootstrap_creds_and_seed.sh
    |   |   |-- guides
    |   |   |   |-- seed_kv_spec.example.json
    |   |   |   `-- seed_kv_spec.GUIDE.md
    |   |   |-- keycloak_approle_setup.sh
    |   |   |-- postgress_approle_setup.sh
    |   |   |-- startover_scripts
    |   |   |   `-- reset_network_tools_docker.sh
    |   |   |-- vault_first_time_init_only_rootless.sh
    |   |   |-- vault_unseal_kv_seed_bootstrap_rootless.sh
    |   |   `-- vault_unseal_multi_kv_seed_bootstrap_rootless.sh
    |   `-- nginx
    |-- docker-compose.prod.yml
    |-- environment_variable_guide.md
    |-- frontend
    |-- how_to_videos
    |   |-- HOW_TO_3.2 Validate Certificates.mov
    |   |-- HOW_TO_3.3 Start Vault with Docker Compose.mov
    |   |-- HOW_TO_3.6 Initialize and Unseal Vault (First Run).mov
    |   |-- HOW_TO_3.8.3 Single-Mount Seeder (vault_unseal_kv_seed_bootstrap_rootless.sh).mov
    |   `-- HOW_TO_3.8.4 Multi-Mount Seeder (vault_unseal_multi_kv_seed_bootstrap_rootless.sh).mov
    |-- README.full.md
    `-- README.md
   ```

3. Confirm expected outputs exist:

   ```bash
   ls -lh ./backend/app/security/configuration_files/vault/certs/
   ```

### 3.2 Validate Certificates

Run these checks on the server:

```bash
CERT_DIR="$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs"
CERT="$CERT_DIR/cert.crt"
KEY="$CERT_DIR/cert.key"
CA="$CERT_DIR/ca.crt"

# Key parses cleanly
openssl pkey -in "$KEY" -check -noout

# Cert metadata
openssl x509 -in "$CERT" -noout -subject -issuer -dates

# Cert matches key (hashes must match)
openssl x509 -noout -modulus -in "$CERT" | openssl sha256
openssl rsa  -noout -modulus -in "$KEY"  | openssl sha256

# SANs include vault_production_node
openssl x509 -in "$CERT" -noout -text | sed -n '/Subject Alternative Name/,+2p'

# Verify leaf chains to CA
LEAF_ONLY="$CERT_DIR/cert.leaf.only.crt"
if [[ -f "$LEAF_ONLY" ]]; then
  openssl verify -CAfile "$CA" "$LEAF_ONLY"
else
  # Best-effort fallback (may fail if CERT is a fullchain)
  openssl verify -CAfile "$CA" "$CERT" || true
fi

See below for the expected output you should see. 
Your output may vary a bit depending on how your server is setup.

(LOCAL CERTIFICATES BEING USED)

Key is valid
subject=CN = vault_production_node
issuer=CN = NETWORK_TOOLS Local Vault CA
notBefore=Jan  1 03:13:33 2026 GMT
notAfter=Apr  5 03:13:33 2028 GMT
SHA2-256(stdin)= 4148080bacac7a147981ef2d6e0608dc135d1685fffb4da16748fbd0300e6193
SHA2-256(stdin)= 4148080bacac7a147981ef2d6e0608dc135d1685fffb4da16748fbd0300e6193
            X509v3 Subject Alternative Name: 
                DNS:vault_production_node, IP Address:172.16.99.130
            X509v3 Subject Key Identifier: 
/home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/cert.crt: OK
developer_network_tools@networktoolsvm:~/NETWORK_TOOLS$ 

```

### 3.3 Start Vault with Docker Compose

> Run these commands as **developer_network_tools**.

1. Confirm your CLI is talking to the **rootless** Docker daemon:

   ```bash
   docker context ls
   docker context use rootless || true
   docker context show
   ```

2. Ensure the local Vault data directories exist (bind mounts):

   ```bash
   cd ~/NETWORK_TOOLS
   mkdir -p ./container_data/vault/data ./container_data/vault/data/logs
   ```

3. Validate the Compose file renders:

   ```bash
   docker compose -f docker-compose.prod.yml config > /tmp/network_tools.compose.rendered.yml
   ```

4. Start Vault (Or use the initial init script to bring up a new vault instance See [3.6.1 Run the Init + Unseal Script](#361-run-the-init--unseal-script)):
   The init script has been updated to call the docker command to bring up the container, and it will setup 
   unseal and setup the initial settings required by the other containers. 
   ```bash
   docker compose -f docker-compose.prod.yml up -d vault_production_node
   ```


5. Follow logs:

   ```bash
   docker compose -f docker-compose.prod.yml logs -f vault_production_node
   ```

### 3.4 Confirm Vault is Reachable

If you are testing from the **same server** running Docker, add a hosts entry so `vault_production_node` resolves locally:

```bash
echo "127.0.0.1 vault_production_node" | sudo tee -a /etc/hosts
```

Then validate TLS from the host:

```bash
CA="$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt"
openssl s_client -connect vault_production_node:8200 -servername vault_production_node -CAfile "$CA" </dev/null
```

And validate HTTP response (Vault may return 503 until initialized/unsealed):

```bash
curl --cacert "$CA" -v https://vault_production_node:8200/v1/sys/health
```

### 3.5 Vault Bring-up Troubleshooting

**1) TLS errors (x509 hostname mismatch)**
- Ensure `vault_production_node` appears under *Subject Alternative Name* (Section 3.2).
- Ensure you are connecting using the same hostname that is present in the SAN list.

**2) “Connection refused” or cannot reach port 8200**
- Confirm the service is running and ports are published:

  ```bash
  docker compose -f docker-compose.prod.yml ps
  ss -lntp | egrep ':8200|:8201' || true
  ```

**3) Permission denied writing under `/vault/data`**
- Confirm `./container_data/vault/data` exists and is writable by your rootless user.
- If still failing, consider adding `user: "0:0"` to the Compose service for Vault (still rootless on the host).

---


### 3.6 Initialize and Unseal Vault (First Run)

This step is required **one time** for a brand-new Vault instance. It will:

- Start the Vault container with Docker Compose (rootless; no sudo)
- Initialize Vault (generates unseal keys + root token)
- Unseal Vault

> **Security note:** The init artifacts (unseal keys + root token) are highly sensitive. This script will save them to disk and (by default) print some contents to the terminal. Treat the output like production secrets.

#### 3.6.1 Run the Init + Unseal Script

> Run these commands as **developer_network_tools** (no sudo).

This script is intended for a **first-time** Vault bring-up. It will:

- Start Vault (optional; if you already started the container, it will reuse it)
- Initialize Vault (`vault operator init`)
- Unseal Vault using the configured threshold
- Enable the file audit device (if configured)
- **Create required ACL policy + AppRole for Postgres/pgAdmin** (first-run convenience; enabled by default in this repo)

1) Ensure Vault is running (skip if already up):

```bash
cd "$HOME/NETWORK_TOOLS"
docker compose -p network_tools -f docker-compose.prod.yml up -d vault_production_node
```

2) Ensure the script is executable:

```bash
cd "$HOME/NETWORK_TOOLS"
chmod +x ./backend/build_scripts/vault_first_time_init_only_rootless.sh
```

3) Run the script (recommended: pass the local CA and make init parameters explicit).

Environment-variable form:

```bash
cd "$HOME/NETWORK_TOOLS"
bash ./backend/build_scripts/vault_first_time_init_only_rootless.sh \
  --vault-addr "https://vault_production_node:8200" \
  --ca-cert "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt" \
  --init-shares 5 --init-threshold 3
```

Fully expanded form:

```bash
cd "$HOME/NETWORK_TOOLS"
bash ./backend/build_scripts/vault_first_time_init_only_rootless.sh \
  --vault-addr "https://vault_production_node:8200" \
  --ca-cert "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt" \
  --init-shares 5 \
  --init-threshold 3
```

Expected output from the vault init script below for comparison.

```bash
developer_network_tools@networktoolsvm:~/NETWORK_TOOLS$ cd "$HOME/NETWORK_TOOLS"
bash ./backend/build_scripts/vault_first_time_init_only_rootless.sh \
  --vault-addr "https://vault_production_node:8200" \
  --ca-cert "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt" \
  --init-shares 5 \
  --init-threshold 3
INFO: Starting Vault container: docker compose -p network_tools -f /home/developer_network_tools/NETWORK_TOOLS/docker-compose.prod.yml up -d vault_production_node
[+] up 2/2
 ✔ Network network_tools_default   Created                                                                                                                                                                                       0.0s 
 ✔ Container vault_production_node Created                                                                                                                                                                                       0.1s 
INFO: Waiting for Vault endpoint: https://vault_production_node:8200
INFO: Vault not initialized; initializing (shares=5, threshold=3)…
INFO: Init complete. Wrote (0600):
INFO:   Unseal keys JSON     : /home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/unseal_keys.json
INFO:   Root token (plain)   : /home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token
INFO:   Root token (JSON)    : /home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token.json
INFO: Unsealing Vault using 3 key(s)…
INFO: Vault unsealed.
INFO: Enabling file audit device at path 'file/' -> /vault/logs/audit.log
INFO: Audit device enabled successfully.
INFO: Ensured ACL policy: postgres_pgadmin_read
INFO: Enabled auth method: approle/
INFO: Ensured AppRole role: postgres_pgadmin_agent (policy: postgres_pgadmin_read)

============================================================
VAULT BOOTSTRAP ARTIFACTS (SENSITIVE) - DOWNLOAD THEN REMOVE
============================================================
Bootstrap directory:
  /home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap

Files written/used by this script:
  - /home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/unseal_keys.json  (exists; perms/owner: 600 developer_network_tools:developer_network_tools)
  - /home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token  (exists; perms/owner: 600 developer_network_tools:developer_network_tools)
  - /home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token.json  (exists; perms/owner: 600 developer_network_tools:developer_network_tools)

IMPORTANT:
  - This script is configured to print key/token JSON contents to the terminal by default.
    Use --no-print-artifact-contents to suppress that output.
  1) Download these files to a secure location (password manager / offline vault / secure storage).
  2) Do NOT commit these files to Git.
  3) After you have securely stored them, delete them from this server.

Example download (from your workstation):
  scp -p <user>@<server>:'/home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/unseal_keys.json' .
  scp -p <user>@<server>:'/home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token' .
  scp -p <user>@<server>:'/home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token.json' .

Example removal (run on this server AFTER downloading):
  rm -f '/home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/unseal_keys.json' '/home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token' '/home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token.json'

If you want a stronger delete (optional; not always effective on all storage):
  shred -u '/home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/unseal_keys.json' '/home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token' '/home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token.json'


============================================================
BOOTSTRAP FILE CONTENTS (HIGHLY SENSITIVE) - TERMINAL OUTPUT
============================================================
WARNING: The contents below include unseal keys and root token.
Do NOT paste this output into tickets, chat, or logs.
============================================================

----- /home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/unseal_keys.json -----
{
  "keys": [
    "6a25353dc991c0d743a1bb5f0d11f11fb4e6f9a65646c093a4e46e2aca78db6ed9",
    "436e62004ddfcfbe69ee60de5f7275d04bf4caa95bae89435d4501273817c3a48b",
    "3514f5c6e49850bdd1f3f9b885af60207756a79aab245b6ca5138ba51e84c024a8",
    "95accca297de7f6fd9d545845eb33ca5ba371a9e34b724ff75719cabfb5e368786",
    "13e27fd7fc783143a6d6c19d990949a6c7ef0d456d261cfcd046c75c065f63c338"
  ],
  "keys_base64": [
    "aiU1PcmRwNdDobtfDRHxH7Tm+aZWRsCTpORuKsp4227Z",
    "Q25iAE3fz75p7mDeX3J10Ev0yqlbrolDXUUBJzgXw6SL",
    "NRT1xuSYUL3R8/m4ha9gIHdWp5qrJFtspROLpR6EwCSo",
    "lazMopfef2/Z1UWEXrM8pbo3Gp40tyT/dXGcq/teNoeG",
    "E+J/1/x4MUOm1sGdmQlJpsfvDUVtJhz80EbHXAZfY8M4"
  ],
  "root_token": "hvs.zeGCweGZR0du66ONKG32enpy"
}

----- /home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token.json -----
{
  "root_token": "hvs.zeGCweGZR0du66ONKG32enpy"
}

{
  "vault_addr": "https://vault_production_node:8200",
  "compose": {
    "project": "network_tools",
    "file": "/home/developer_network_tools/NETWORK_TOOLS/docker-compose.prod.yml",
    "service": "vault_production_node"
  },
  "bootstrap_dir": "/home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap",
  "files": {
    "unseal_keys_json": "/home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/unseal_keys.json",
    "root_token": "/home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token",
    "root_token_json": "/home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token.json"
  },
  "pretty_output": true,
  "postgres_pgadmin_approle_bootstrap": {
    "enabled": true,
    "force": false,
    "setup_done": true,
    "role_name": "postgres_pgadmin_agent",
    "policy_name": "postgres_pgadmin_read"
  },
  "print_artifact_contents": true,
  "audit": {
    "enabled": true,
    "path": "file",
    "file_path": "/vault/logs/audit.log"
  },
  "initialized": true,
  "unsealed": true
}
```



4) If you omit `--ca-cert`, the script will:

- Try the system trust store first (no `-k`)
- If that fails, retry with `-k` and print a warning with the TLS verification error

```bash
bash ./backend/build_scripts/vault_first_time_init_only_rootless.sh \
  --vault-addr "https://vault_production_node:8200"
```

#### 3.6.2 Bootstrap Artifacts (Download Then Remove AFTER every container is brought up and initialized)

By default, the init/unseal script writes bootstrap artifacts here:

```text
Your directory structure should now resemble below

developer_network_tools@networktoolsvm:~/NETWORK_TOOLS$ tree --charset ascii
.
|-- backend
|   |-- app
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
|   |   |-- mariadb_queries
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
|   |   |           `-- postgres_user.ctmpl
|   |   |-- routers
|   |   `-- security
|   |       `-- configuration_files
|   |           `-- vault
|   |               |-- bootstrap
|   |               |   |-- root_token <-- NEW (Download and save somewhere offline or online in a secure location AFTER all bootstrapping is completed)
|   |               |   |-- root_token.json <-- NEW (Download and save somewhere offline or online in a secure location AFTER all bootstrapping is completed)
|   |               |   `-- unseal_keys.json <-- NEW (Download and save somewhere offline or online in a secure location AFTER all bootstrapping is completed)
|   |               |-- certs
|   |               |   |-- ca.crt
|   |               |   |-- ca.key
|   |               |   |-- ca.srl
|   |               |   |-- cert.crt
|   |               |   `-- cert.key
|   |               |-- config
|   |               |   |-- certs
|   |               |   |-- keycloak_kv_read.hcl
|   |               |   |-- postgres_pgadmin_kv_read.hcl
|   |               |   `-- vault_configuration_primary_node.hcl
|   |               `-- Dockerfile
|   |-- build_scripts
|   |   |-- generate_local_keycloak_certs.sh
|   |   |-- generate_local_postgres_certs.sh
|   |   |-- generate_local_vault_certs.sh
|   |   |-- generate_postgres_pgadmin_bootstrap_creds_and_seed.sh
|   |   |-- guides
|   |   |   |-- seed_kv_spec.example.json
|   |   |   `-- seed_kv_spec.GUIDE.md
|   |   |-- keycloak_approle_setup.sh
|   |   |-- postgress_approle_setup.sh
|   |   |-- startover_scripts
|   |   |   `-- reset_network_tools_docker.sh
|   |   |-- vault_first_time_init_only_rootless.sh
|   |   |-- vault_unseal_kv_seed_bootstrap_rootless.sh
|   |   `-- vault_unseal_multi_kv_seed_bootstrap_rootless.sh
|   `-- nginx
|-- container_data
|   `-- vault
|       `-- data
|           |-- logs
|           |   `-- audit.log <-- NEW Vault log file mapped to the Host OS Mount
|           |-- raft
|           |   |-- raft.db <-- NEW Vault raft database. This is where your secrets are stored
|           |   `-- snapshots
|           `-- vault.db
|-- docker-compose.prod.yml
|-- environment_variable_guide.md
|-- frontend
|-- how_to_videos
|-- README.full.md
`-- README.md
```

These files are **credentials**. Treat them as highly sensitive.

- `unseal_keys.json` contains the unseal key shares (and the root token in JSON form, depending on init output).
- `root_token` / `root_token.json` contain the initial root token.

Example structure (values redacted):

```json
{
  "keys_base64": ["<UNSEAL_KEY_1_B64>", "<UNSEAL_KEY_2_B64>", "<...>"],
  "root_token": "<VAULT_ROOT_TOKEN>"
}
```

**Operational guidance**

- Download the artifacts to a secure location immediately (password manager / offline vault / secure storage).
- Do **not** commit these files to Git.
- After you have secured them, remove them from the server.

Example download (from your workstation) — environment-variable form:

```bash
scp -p <user>@<server>:"$VAULT_BOOTSTRAP_DIR/unseal_keys.json" .
scp -p <user>@<server>:"$VAULT_BOOTSTRAP_DIR/root_token" .
scp -p <user>@<server>:"$VAULT_BOOTSTRAP_DIR/root_token.json" .
```

Example download — fully expanded form:

```bash
scp -p <user>@<server>:"$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/unseal_keys.json" .
scp -p <user>@<server>:"$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token" .
scp -p <user>@<server>:"$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token.json" .
```

Example removal (run on the server after download):

```bash
rm -f \
  "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/unseal_keys.json" \
  "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token" \
  "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token.json"
```

Optional stronger delete (not always effective on all storage):

```bash
shred -u \
  "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/unseal_keys.json" \
  "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token" \
  "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token.json"
```

### 3.7 TLS Certificate Trust and Best Practices

This repository currently uses a **locally generated CA** and a **locally issued Vault server certificate** for development.
That is appropriate for local/dev, but the “right” trust model differs in production.

#### 3.7.1 Local Development (Self-Signed CA)

In local/dev, it is normal for `curl` or client libraries to fail verification unless you explicitly trust the CA.

- Strict verification (recommended even in dev):

  ```bash
  CA="$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt"
  curl --cacert "$CA" https://vault_production_node:8200/v1/sys/health
  ```

- Temporary bypass (avoid when possible; never use in production):

  ```bash
  curl -k https://vault_production_node:8200/v1/sys/health
  ```

**Developer machine trust:** In most cases, you do **not** need to install the dev CA into your workstation’s system trust store.
Instead, point tooling at the CA file (`--cacert` or `VAULT_CACERT`) as needed.

Example (host CLI use):

```bash
export VAULT_ADDR="https://vault_production_node:8200"
export VAULT_CACERT="$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt"
# vault status   # if the vault CLI is installed on the host
```

#### 3.7.2 Production Environments (Recommended)

For production, avoid shipping a “dev CA” and avoid `-k` entirely. Typical patterns:

- Use an enterprise PKI / internal CA trusted by servers and automation clients
- Or use publicly trusted certificates (e.g., ACME/Let’s Encrypt) when appropriate and permitted

**Key principles:**

- The Vault server certificate must include the correct DNS names in **Subject Alternative Name (SAN)** for the production URL(s).
- Clients should validate:
  - Certificate chain (issuer trust)
  - Hostname (SAN match)
  - Validity dates / rotation
- The **CA private key** should not be widely distributed (and should not live in the repo). In production, certificate issuance and private key handling should follow your organization’s security controls.

#### 3.7.3 Practical Guidance for This Repo

- Local/dev scripts support both:
  - Proper verification with `--ca-cert <path-to-ca.crt>`
  - A fallback path that can use `-k` when the local CA is not installed in the trust store (with a warning)
- When moving to production, expect to:
  - Replace the dev CA/cert material with your production certificate chain
  - Update your Vault listener config (`tls_cert_file`, `tls_key_file`) and Compose mounts accordingly
  - Remove any “insecure fallback” behavior from operational runbooks


---


### 3.8 Vault Unseal and KV Seeding Bootstrap Scripts

This repo intentionally keeps **two** seeding approaches so you have more than one option:
These can be used to create custom seed files. Or you can manually enter them into vault. Dealers choice.

- **Single-mount seeder**: `./backend/build_scripts/vault_unseal_kv_seed_bootstrap_rootless.sh`  
  Best for the common case: unseal Vault (if needed), optionally create **one** KV mount, then seed **one JSON input** into that mount.
<br><br>
- **Multi-mount seeder**: `./backend/build_scripts/vault_unseal_multi_kv_seed_bootstrap_rootless.sh`  
  Best when you want to create/seed **multiple** KV mounts and paths in a single run (one “spec” file that defines the whole bootstrap).

Both scripts are designed for **rootless Docker** workflows and default to using artifact files produced by the first-time init/unseal script under:

- Bootstrap artifacts directory (default):  
  `$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap`

> Security note: these scripts can optionally print secrets to the terminal. Assume terminal output may be logged or captured. Prefer storing resolved secrets in the artifact file and moving them off-host immediately.

#### 3.8.1 Overview (Which Script to Use)

Use the **single-mount seeder** when you:
- only need one KV engine mount (example: `app_secrets`)
- want a simple JSON “template” checked into git (optionally using generators/env injection), and a resolved artifact JSON saved under the bootstrap dir

Use the **multi-mount seeder** when you:
- want to stand up multiple KV mounts (example: `app_secrets`, `frontend_environment_variables`, `fastapi_environment_variables`, etc.)
- want a single input file that declares *all* mounts + *all* secret writes in order

#### 3.8.2 Unseal-Only Usage

If you only need to **unseal** Vault and do not want to create mounts or seed secrets, run the single-mount script without any `--create-kv` / `--secrets-json` options:

```bash
cd ~/NETWORK_TOOLS

bash ./backend/build_scripts/vault_unseal_kv_seed_bootstrap_rootless.sh \
  --vault-addr "https://vault_production_node:8200" \
  --ca-cert "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt"
```

Notes:
- If Vault is already unsealed, the script should detect that and exit cleanly.
- If you previously downloaded and removed `unseal_keys.json` (recommended), pass it back in for that run via `--unseal-keys /path/to/unseal_keys.json`.

#### 3.8.3 Single-Mount Seeder (vault_unseal_kv_seed_bootstrap_rootless.sh)

**Primary goal**: unseal Vault (if sealed), optionally create a KV mount (v1 or v2), and seed one or more secrets under that mount from a JSON template file. The script also writes a **resolved artifact** (with generated values) into the bootstrap directory next to the root token so you can download/store it securely.

Key flags (seeding-related):
- `--secrets-json <file>`: JSON template describing what to write (validate with `jq -e . <file> >/dev/null` (or `jq . <file>` if you have jq installed)).
- `--secrets-prefix <prefix>`: optional prefix under the mount (recommended for bootstraps).
- `--secrets-cas <N>`: KV v2 CAS value used for writes (default `0`, meaning **create-only**).
- `--secrets-dry-run`: resolves/generates values but does not write; prints only target paths.
- `--print-secrets`: prints resolved secret values to the terminal (sensitive).

##### Working example (recommended): create mount + seed secrets under a prefix (no double-prefix)

This pattern produces secrets at:

- `app_secrets/bootstrap/creds`
- `app_secrets/bootstrap/crypto`

1) Create a template file (map format). **Note**: paths in the file are **relative** (no `bootstrap/`), because we pass `--secrets-prefix bootstrap`.

```bash
BOOTSTRAP_DIR="$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap"

cat > "${BOOTSTRAP_DIR}/seed_app_secrets.json" <<'EOF'
{
  "creds": {
    "username": "example_user",
    "password": { "generate": { "type": "url_safe", "bytes": 24 } }
  },
  "crypto": {
    "jwt_secret": { "generate": { "type": "hex", "bytes": 32 } },
    "fernet_key": { "generate": { "type": "base64", "bytes": 32 } }
  }
}
EOF

# Always validate before running the seeder
jq -e . "${BOOTSTRAP_DIR}/seed_app_secrets.json" >/dev/null
```

2) Run the seeder (unseal + create KV v2 mount + seed):

```bash
bash ./backend/build_scripts/vault_unseal_kv_seed_bootstrap_rootless.sh \
  --vault-addr "https://vault_production_node:8200" \
  --ca-cert "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt" \
  --unseal-keys "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/unseal_keys.json" \
  --unseal-required 3 \
  --prompt-token \
  --create-kv "app_secrets" \
  --kv-version 2 \
  --kv-description "Network Tools app secrets (dev)" \
  --kv-max-versions 20 \
  --kv-cas-required true \
  --kv-delete-version-after 0s \
  --secrets-json "${BOOTSTRAP_DIR}/seed_app_secrets.json" \
  --secrets-prefix "bootstrap" \
  --secrets-cas 0
```

3) Optional verification (example):

```bash
vault kv get app_secrets/bootstrap/creds
vault kv get app_secrets/bootstrap/crypto
```

##### Reseeding note (KV v2 CAS)

By default, the seeder uses `--secrets-cas 0` (create-only). If you re-run the seeder against a path that already exists, Vault will typically return a 400 and the script will report failure for that secret.

For iterative development, you have three practical options:
- Seed into **new paths** (e.g., change the prefix from `bootstrap` to `bootstrap_2025_12_25`).
- **Delete** the existing secret paths before reseeding (safe only in non-production environments).
- Use list format (Section 3.8.5-B) and set per-secret `cas` to the current version (obtained via `vault kv metadata get`), if you need controlled overwrites.

Output artifacts (defaults):
- Resolved secrets JSON artifact: `$BOOTSTRAP_DIR/seeded_secrets_<mount>.json` (override with `--output-secrets-file`)

#### 3.8.4 Multi-Mount Seeder (vault_unseal_multi_kv_seed_bootstrap_rootless.sh)

**Primary goal**: unseal/token handling plus a single “spec” file that can:
- ensure multiple KV mounts exist (optionally configuring KV v2 behavior per mount)
- write multiple secret objects across multiple paths/mounts
- store a resolved “what was written” artifact under the same bootstrap directory

Typical usage (example):

```bash
bash ./backend/build_scripts/vault_unseal_multi_kv_seed_bootstrap_rootless.sh \
  --vault-addr "https://vault_production_node:8200" \
  --ca-cert "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt" \
  --unseal-required 3 \
  --prompt-token \
  --spec-json "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/seed_kv_spec.json"
```

Useful flags:
- `--dry-run`: resolves/generates values but does not write; prints only target paths.
- `--print-secrets`: prints resolved secret values to the terminal (sensitive).
- `--output-artifact <file>`: override the output artifact path (default: `$BOOTSTRAP_DIR/seeded_secrets_all.json`).
- `--output-format {pretty|compact}`: control artifact formatting.

#### 3.8.5 Seed Input Formats

The **single-mount seeder** supports two JSON formats for `--secrets-json`.

##### A) Map format (recommended): “path -> data object”

Use this format for the common case (simple, readable). Paths are **relative** to the mount (and also relative to `--secrets-prefix` if you pass it).

```json
{
  "app/config": {
    "db_username": "example_user",
    "db_password": { "generate": { "type": "url_safe", "bytes": 32 } }
  },
  "jwt": {
    "secret": { "generate": { "type": "hex", "bytes": 32 } }
  }
}
```

Notes:
- Map format defaults each item’s CAS to `0` (create-only) for KV v2.
- Use `--secrets-prefix` to keep the JSON paths clean (avoid repeating `bootstrap/` in every key).

##### B) List format: supports per-secret CAS overrides (KV v2)

Use this when you need different CAS behavior per secret (or when you prefer explicit objects).

```json
[
  {
    "path": "app/config",
    "data": {
      "db_username": "example_user",
      "db_password": { "generate": { "type": "url_safe", "bytes": 32 } }
    },
    "cas": 0
  },
  {
    "path": "jwt",
    "data": {
      "secret": { "generate": { "type": "hex", "bytes": 32 } }
    },
    "cas": 0
  }
]
```

##### Supported generators

- `hex` (requires `bytes`)
- `base64` (requires `bytes`)
- `url_safe` (requires `bytes`)
- `uuid`

##### Optional “ENV injection” values

Useful when you must avoid putting a plaintext secret value into a file:

- Required env var: `{ "env": "ENV_VAR_NAME" }`
- Optional env var: `{ "env": "ENV_VAR_NAME", "optional": true }`

##### Prefix rule (avoid double-prefix)

Choose exactly one approach:
- Use `--secrets-prefix bootstrap` and keep paths in JSON **relative** (e.g., `creds`, `jwt`), or
- Put `bootstrap/...` directly in the JSON paths and **do not** pass `--secrets-prefix`.

#### 3.8.6 Multi Spec JSON Schema

The multi-mount seeder uses a single JSON file (a “spec”) that defines mounts and the secrets to write under each mount.

Supported top-level shapes:
- Preferred: `{ "mounts": [ ... ] }`
- Wrapper: `[ { "mounts": [ ... ] } ]` (single-element array)
- Legacy (supported): `{ "mounts": [ ... ], "writes": [ ... ] }` (writes are merged into per-mount secrets)

##### Preferred schema (per-mount secrets)

```json
{
  "mounts": [
    {
      "mount": "frontend_app_secrets",
      "version": 2,
      "description": "Frontend secrets",
      "prefix": "bootstrap",
      "v2_config": {
        "max_versions": 20,
        "cas_required": true,
        "delete_version_after": "0s"
      },
      "secrets": {
        "keycloak": {
          "client_secret": { "generate": { "type": "url_safe", "bytes": 32 } }
        }
      }
    },
    {
      "mount": "app_secrets",
      "version": 2,
      "description": "Network Tools app secrets (dev)",
      "prefix": "bootstrap",
      "secrets": [
        {
          "path": "creds",
          "data": {
            "username": "example_user",
            "password": { "generate": { "type": "url_safe", "bytes": 24 } }
          },
          "cas": 0
        },
        {
          "path": "jwt",
          "data": {
            "secret": { "generate": { "type": "hex", "bytes": 32 } }
          },
          "cas": 0
        }
      ]
    }
  ]
}
```

Notes:
- `.secrets` may be either:
  - an **object map** (`{"path": {...}}`) or
  - an **array** of `{path,data,cas}` objects (useful when you want per-secret CAS in KV v2).
- `.prefix` is applied to every secret path for that mount. Keep secret paths **relative** when you use `.prefix`.
- `.v2_config` is only relevant for KV v2 mounts and matches what the multi seeder validates:
  - `max_versions` (int), `cas_required` (bool), `delete_version_after` (string like `"0s"`, `"24h"`).

#### 3.8.7 Example Seed Files

Below are **copy/paste-valid** examples that match what the scripts accept.

##### Single-mount template example (map format) + `--secrets-prefix bootstrap`

This file is intended to be used with:

- `--create-kv app_secrets`
- `--secrets-prefix bootstrap`

So the keys below are **relative** (no `bootstrap/` in the JSON):

```json
{
  "creds": {
    "un": "example_user",
    "pw": { "generate": { "type": "url_safe", "bytes": 24 } }
  },
  "crypto": {
    "jwt_secret": { "generate": { "type": "hex", "bytes": 32 } },
    "fernet_key": { "generate": { "type": "base64", "bytes": 32 } }
  }
}
```

##### Single-mount template example (list format) with per-secret CAS (KV v2)

```json
[
  {
    "path": "creds",
    "data": {
      "un": "example_user",
      "pw": { "generate": { "type": "url_safe", "bytes": 24 } }
    },
    "cas": 0
  },
  {
    "path": "crypto",
    "data": {
      "jwt_secret": { "generate": { "type": "hex", "bytes": 32 } },
      "fernet_key": { "generate": { "type": "base64", "bytes": 32 } }
    },
    "cas": 0
  }
]
```

##### Multi spec example (preferred: per-mount secrets)

This example creates two mounts and writes multiple paths under the `bootstrap/` prefix in each:

```json
{
  "mounts": [
    {
      "mount": "app_secrets",
      "version": 2,
      "description": "Network Tools app secrets (dev)",
      "prefix": "bootstrap",
      "v2_config": {
        "max_versions": 20,
        "cas_required": true,
        "delete_version_after": "0s"
      },
      "secrets": {
        "creds": {
          "un": "example_user",
          "pw": { "generate": { "type": "url_safe", "bytes": 24 } }
        },
        "jwt": {
          "secret": { "generate": { "type": "hex", "bytes": 32 } }
        }
      }
    },
    {
      "mount": "frontend_app_secrets",
      "version": 2,
      "description": "Frontend secrets (dev)",
      "prefix": "bootstrap",
      "secrets": {
        "keycloak": {
          "client_secret": { "generate": { "type": "url_safe", "bytes": 32 } }
        }
      }
    }
  ]
}
```

Validation tip (before running the seeder):

```bash
jq -e . seed_kv_spec.json >/dev/null
```

#### 3.8.8 Output, Artifact Storage, and Security Notes

When you run init/unseal and seed operations, treat these as **sensitive artifacts**:

- `unseal_keys.json`
- `root_token` / `root_token.json`
- any `seeded_secrets_*.json` output artifacts

Artifact defaults:
- Single-mount seeder: `$BOOTSTRAP_DIR/seeded_secrets_<mount>.json`
- Multi-mount seeder: `$BOOTSTRAP_DIR/seeded_secrets_all.json` (override with `--output-artifact <file>`)

Recommended flow:
1. Run the script(s) on the server.
2. `scp -p` the required artifacts to a secure workstation or secrets storage location.
3. Verify the downloads.
4. Remove sensitive artifacts from the server (or move into an encrypted/controlled location).

Security note: avoid `--print-secrets` except during controlled debugging; it will print plaintext values to your terminal history/logs.

#### 3.8.9 Troubleshooting


Common seeding issues and what they usually mean:

- **“Spec file is not valid JSON” / “Secrets file is not valid JSON”**  
  Validate with `jq -e . <file> >/dev/null` (or `jq . <file>` if jq is installed) and correct trailing commas, unquoted keys, or incomplete objects.

- **Paths end up as `bootstrap/bootstrap/...`**  
  You likely used both:
  - `--secrets-prefix bootstrap` (or mount `.prefix: "bootstrap"`) **and**
  - JSON paths that already include `bootstrap/...`  
  Fix by keeping JSON paths relative when using a prefix.

- **KV v2 write fails with HTTP 400 after a successful first run**  
  This is commonly CAS behavior. If you are using CAS create-only (`cas: 0` / `--secrets-cas 0`) and the secret already exists, Vault will reject the write. Options are described in the “Reseeding note” in Section 3.8.3.

- **“permission denied” / HTTP 403**  
  The token in use does not have write access to the target mount/path. Verify policies and confirm you are using the intended token.

- **TLS/cert errors**  
  Ensure `--ca-cert` points to the CA that issued Vault’s server cert (or ensure the CA is trusted by the OS). As a last resort for diagnostics, some scripts may fall back to insecure validation; do not rely on that in production.

#### 3.8.10 Spec Format Notes, Validation Checks, and Common Pitfalls (Updated)

Validation checks enforced by the scripts (high-level):

Single-mount seeder (`--secrets-json`):
- Must be valid JSON.
- Accepts either:
  - map format: `{ "path": { ...data... }, ... }` (all values must be JSON objects), or
  - list format: `[ { "path": "...", "data": { ... }, "cas": 0 }, ... ]`.

Multi-mount seeder (`--spec-json`):
- Must be valid JSON.
- Root must be an object (or a single-element array containing an object).
- Preferred: `.mounts` is an array of mount objects with:
  - `mount` (string), `version` (1 or 2), optional `description`, optional `prefix`
  - `secrets` as an object map or an array of `{path,data,cas}`.
- Optional KV v2 config per mount via `.v2_config`:
  - `max_versions` (int)
  - `cas_required` (bool)
  - `delete_version_after` (string like `"0s"`, `"24h"`)

Common pitfalls:
- **Prefix duplication** (most common): use a prefix in exactly one place (CLI `--secrets-prefix` or spec `.prefix`, not also in every JSON path).
- **Invalid JSON in examples**: do not use placeholders like `...` inside JSON. Always validate with `jq -e . <file> >/dev/null` (or `jq . <file>` if jq is installed).
- **CAS expectations**: `cas: 0` is create-only. If you want rerunnable/idempotent behavior, plan for either deletion, new paths, or explicit CAS updates (KV v2).
- **Wrong “path” semantics in legacy `writes`**: in multi legacy mode, `.writes[].path` must be relative (do not include the mount name, and do not include `.prefix` if you set one on the mount).

#### 3.8.11 Updated Multi-Mount Spec Example (Preferred)

This is the **preferred** format: all secrets are nested under each mount (no top-level `writes`).

```json
{
  "mounts": [
    {
      "mount": "app_secrets",
      "version": 2,
      "description": "Network Tools app secrets (dev)",
      "prefix": "bootstrap",
      "v2_config": {
        "max_versions": 20,
        "cas_required": true,
        "delete_version_after": "0s"
      },
      "secrets": {
        "creds": {
          "un": "example_user",
          "pw": { "generate": { "type": "url_safe", "bytes": 24 } }
        },
        "jwt": {
          "secret": { "generate": { "type": "hex", "bytes": 32 } }
        },
        "crypto": {
          "fernet_key": { "generate": { "type": "base64", "bytes": 32 } }
        }
      }
    },
    {
      "mount": "frontend_app_secrets",
      "version": 2,
      "description": "Frontend secrets (dev)",
      "prefix": "bootstrap",
      "secrets": [
        {
          "path": "keycloak",
          "data": {
            "client_secret": { "generate": { "type": "url_safe", "bytes": 32 } }
          },
          "cas": 0
        }
      ]
    }
  ]
}
```

#### 3.8.12 Legacy Spec Example (mounts + writes)

Legacy mode is supported for backward compatibility: top-level `writes` entries are merged into the matching mount’s `.secrets`.

Important rules:
- Every `.writes[].mount` must match an entry in `.mounts[].mount` (the script validates this).
- `.writes[].path` must be **relative** (do not include the mount name).
- If the mount defines a `.prefix`, `.writes[].path` should be relative to that prefix (do not repeat it).

```json
{
  "mounts": [
    {
      "mount": "app_secrets",
      "version": 2,
      "description": "Network Tools app secrets (dev)",
      "prefix": "bootstrap",
      "v2_config": {
        "max_versions": 20,
        "cas_required": true,
        "delete_version_after": "0s"
      }
    }
  ],
  "writes": [
    {
      "mount": "app_secrets",
      "path": "creds",
      "data": {
        "un": "example_user",
        "pw": { "generate": { "type": "url_safe", "bytes": 24 } }
      },
      "cas": 0
    },
    {
      "mount": "app_secrets",
      "path": "jwt",
      "data": {
        "secret": { "generate": { "type": "hex", "bytes": 32 } }
      },
      "cas": 0
    }
  ]
}
```

#### 3.8.13 About `"generate": { ... }` Values

The `"generate": { ... }` blocks are **not** a native Vault feature. They are a **bootstrap-script convention**:

- The script generates the value at seed time (once), then writes the generated literal value into the KV path.
- Vault will **not** regenerate the value on read.
- To rotate, you re-run the seeding process (or build a dedicated rotation workflow) and write a new value.

If you want dynamic per-request credentials/keys, use a Vault secrets engine designed for that (for example: Database secrets engine, Transit, PKI), not KV.

## 6. Postgres and pgAdmin Vault Integration Bootstrapping

This section consolidates the “integration” story end-to-end: how Postgres and pgAdmin can start with credentials stored in Vault, while still supporting a fallback to locally stored bootstrap artifacts.

### 6.1 Overview and constraints

Key points to internalize up front:

- **Postgres and pgAdmin do not natively query Vault.** Something else must authenticate to Vault and deliver the values to the containers (host scripting, init containers, or a Vault Agent sidecar).
- **Prefer file-based secrets over environment variables** where possible:
  - The official Postgres image supports `_FILE` variants for `POSTGRES_DB`, `POSTGRES_USER`, and `POSTGRES_PASSWORD` (and a few others), meaning you can supply those values from files (e.g., Docker secrets or a rendered file).
  - pgAdmin supports `PGADMIN_DEFAULT_PASSWORD_FILE`, meaning the admin password can be supplied from a file.
- **Initialization behavior matters:** these variables affect initialization **only** when the Postgres data directory is empty. If your Postgres data volume already contains a database cluster, changing `POSTGRES_*` values will not automatically rotate users/passwords. Rotation requires explicit SQL (`ALTER USER ...`) and controlled restarts.

Vault KV paths and mounts used in this repo:
- The bootstrap seeding flow in **4.1** writes `postgres` and `pgadmin` under the configured mount (commonly `app_network_tools_secrets`).
- If you used a different mount name (for example, a spelling variation), use that consistently in policies, templates, and read paths.

### 6.2 Option A – Keep env file (.env) as the runtime source of truth

This is the simplest operationally because it requires **no changes** to the current `docker-compose.prod.yml` Postgres/pgAdmin services.

#### When to use this option
- You want the stack to start even if Vault is down.
- You accept that secrets will exist (briefly or persistently) in `.env` on the host.
- You primarily use Vault as your “system of record” (seed/backup), not as a hard runtime dependency.

#### Steps

1) **Generate and seed** using the existing repo script (see **4.1** and **5.1**).
2) **Choose the fallback file location** (these are created by the script):
   - `./backend/app/security/configuration_files/vault/bootstrap/postgres_pgadmin.env`
   - `./backend/app/security/configuration_files/vault/bootstrap/postgres_pgadmin_credentials.json`
3) **Populate `.env` for Compose**.

Example: merge only the postgres/pgAdmin values into your existing `.env`:

```bash
cd "$HOME/NETWORK_TOOLS"

BOOT_ENV="./backend/app/security/configuration_files/vault/bootstrap/postgres_pgadmin.env"
test -f "$BOOT_ENV" || { echo "Missing: $BOOT_ENV"; exit 1; }

# Create a backup copy the first time
cp -n .env ".env.bak.$(date +%Y%m%d_%H%M%S)" || true

# Remove any prior definitions, then append the new ones (keeps .env clean)
grep -vE '^(POSTGRES_DB|POSTGRES_USER|POSTGRES_PASSWORD|PGADMIN_DEFAULT_PASSWORD)=' .env > .env.tmp || true
cat "$BOOT_ENV" >> .env.tmp
mv .env.tmp .env
chmod 600 .env
```

4) Bring up the services normally:

```bash
docker compose -f docker-compose.prod.yml up -d postgres_certs_init postgres_primary pgadmin
```

Security note:
- If you use this option, treat `.env` as a **secret-bearing file**: permissions `600`, do not commit it, and limit access to the docker host.

### 6.3 Option B – Vault Agent sidecar renders file-based secrets at container start

This pattern is the closest to “Postgres boots and obtains credentials from Vault,” while still remaining idiomatic for containers:
- A **Vault Agent** container authenticates to Vault using **AppRole**.
- The agent renders secrets into **files** inside a shared volume.
- Postgres and pgAdmin read those values using their supported `*_FILE` environment variables.

#### High-level flow

1) Vault is running, initialized, unsealed, and seeded with the `postgres` and `pgadmin` KV entries.
2) You create a Vault policy that can only read those two secrets.
3) You create an AppRole bound to that policy.
4) A Vault Agent container uses the AppRole to obtain a short-lived token.
5) The Vault Agent templates render:
   - `postgres_db`, `postgres_user`, `postgres_password`
   - `pgadmin_password`
6) Postgres uses:
   - `POSTGRES_DB_FILE=/run/vault/postgres_db`
   - `POSTGRES_USER_FILE=/run/vault/postgres_user`
   - `POSTGRES_PASSWORD_FILE=/run/vault/postgres_password`
7) pgAdmin uses:
   - `PGADMIN_DEFAULT_PASSWORD_FILE=/run/vault/pgadmin_password`

### 6.3.1 Create a least-privilege Vault policy

Create an ACL policy that can only read the two KV secrets needed at runtime (Postgres + pgAdmin).

If your mount is KV v2 (the repo default), the paths include `/data/`:

```hcl
# postgres + pgAdmin runtime reads (KV v2)
path "app_network_tools_secrets/data/postgres" {
  capabilities = ["read"]
}

path "app_network_tools_secrets/data/pgadmin" {
  capabilities = ["read"]
}
```

If your mount is KV v1, remove `/data/`:

```hcl
# postgres + pgAdmin runtime reads (KV v1)
path "app_network_tools_secrets/postgres" {
  capabilities = ["read"]
}

path "app_network_tools_secrets/pgadmin" {
  capabilities = ["read"]
}
```

> If your KV mount name differs (for example, legacy `app_network_tools_secrets`), replace `app_network_tools_secrets` everywhere in the policy, templates, and validation commands.

Apply the policy (run from the host using `docker exec` into the Vault container; requires a Vault admin/root token for setup tasks).

Environment-variable form:

```bash
cd "$NT_ROOT"

VAULT_CONTAINER="vault_production_node"
VAULT_ADDR_INTERNAL="$VAULT_ADDR"
VAULT_TOKEN="$(cat "$VAULT_ROOT_TOKEN_FILE")"

docker exec -i \
  -e VAULT_ADDR="$VAULT_ADDR_INTERNAL" \
  -e VAULT_TOKEN="$VAULT_TOKEN" \
  -e VAULT_CACERT="/vault/certs/ca.crt" \
  "$VAULT_CONTAINER" \
  sh -lc 'cat >/tmp/postgres_pgadmin_read.hcl && vault policy write postgres_pgadmin_read /tmp/postgres_pgadmin_read.hcl' <<'HCL'
path "app_network_tools_secrets/data/postgres" {
  capabilities = ["read"]
}

path "app_network_tools_secrets/data/pgadmin" {
  capabilities = ["read"]
}
HCL
```

Fully expanded form:

```bash
cd "$HOME/NETWORK_TOOLS"

docker exec -i \
  -e VAULT_ADDR="https://vault_production_node:8200" \
  -e VAULT_TOKEN="$(cat ./backend/app/security/configuration_files/vault/bootstrap/root_token)" \
  -e VAULT_CACERT="/vault/certs/ca.crt" \
  vault_production_node \
  sh -lc 'cat >/tmp/postgres_pgadmin_read.hcl && vault policy write postgres_pgadmin_read /tmp/postgres_pgadmin_read.hcl' <<'HCL'
path "app_network_tools_secrets/data/postgres" {
  capabilities = ["read"]
}

path "app_network_tools_secrets/data/pgadmin" {
  capabilities = ["read"]
}
HCL
```

Validation (optional):

```bash
docker exec -it \
  -e VAULT_ADDR="https://vault_production_node:8200" \
  -e VAULT_TOKEN="$(cat ./backend/app/security/configuration_files/vault/bootstrap/root_token)" \
  -e VAULT_CACERT="/vault/certs/ca.crt" \
  vault_production_node \
  sh -lc 'vault policy read postgres_pgadmin_read'
```

### 6.3.2 Create an AppRole for the agent

Enable AppRole auth (one-time):

```bash
docker exec -it \
  -e VAULT_ADDR="https://vault_production_node:8200" \
  -e VAULT_TOKEN="$(cat ./backend/app/security/configuration_files/vault/bootstrap/root_token)" \
  -e VAULT_CACERT="/vault/certs/ca.crt" \
  vault_production_node \
  sh -lc 'vault auth enable approle || true'
```

Create (or update) the role. This repo uses the AppRole name `postgres_pgadmin_agent`.

Environment-variable form:

```bash
cd "$NT_ROOT"

VAULT_CONTAINER="vault_production_node"
ROLE_NAME="postgres_pgadmin_agent"
VAULT_TOKEN="$(cat "$VAULT_ROOT_TOKEN_FILE")"

docker exec -it \
  -e VAULT_ADDR="$VAULT_ADDR" \
  -e VAULT_TOKEN="$VAULT_TOKEN" \
  -e VAULT_CACERT="/vault/certs/ca.crt" \
  "$VAULT_CONTAINER" \
  sh -lc "
    vault write auth/approle/role/${ROLE_NAME} \
      token_policies=postgres_pgadmin_read \
      token_ttl=1h \
      token_max_ttl=4h \
      secret_id_ttl=24h \
      secret_id_num_uses=1
  "
```

Fully expanded form:

```bash
docker exec -it \
  -e VAULT_ADDR="https://vault_production_node:8200" \
  -e VAULT_TOKEN="$(cat ./backend/app/security/configuration_files/vault/bootstrap/root_token)" \
  -e VAULT_CACERT="/vault/certs/ca.crt" \
  vault_production_node \
  sh -lc "
    vault write auth/approle/role/postgres_pgadmin_agent \
      token_policies=postgres_pgadmin_read \
      token_ttl=1h \
      token_max_ttl=4h \
      secret_id_ttl=24h \
      secret_id_num_uses=1
  "
```

Validate that the role exists and retrieve the Role ID:

```bash
docker exec -it \
  -e VAULT_ADDR="https://vault_production_node:8200" \
  -e VAULT_TOKEN="$(cat ./backend/app/security/configuration_files/vault/bootstrap/root_token)" \
  -e VAULT_CACERT="/vault/certs/ca.crt" \
  vault_production_node \
  sh -lc 'vault read -field=role_id auth/approle/role/postgres_pgadmin_agent/role-id'
```

Generate a new Secret ID:

```bash
docker exec -it \
  -e VAULT_ADDR="https://vault_production_node:8200" \
  -e VAULT_TOKEN="$(cat ./backend/app/security/configuration_files/vault/bootstrap/root_token)" \
  -e VAULT_CACERT="/vault/certs/ca.crt" \
  vault_production_node \
  sh -lc 'vault write -f -field=secret_id auth/approle/role/postgres_pgadmin_agent/secret-id'
```

### 6.3.3 Export Role ID and Secret ID for the Vault Agent

The Vault Agent container expects to read AppRole artifacts from the **host** export directory (bind-mounted read-only into the agent at `/vault/approle`):

```text
./container_data/vault/approle/postgres_pgadmin_agent/
  role_id
  secret_id
```

This section provides two options:

- **Recommended:** use the repo export script (if present) to (re)export the files.
- **Manual:** copy/paste commands that run the Vault CLI inside the Vault container (no Vault CLI on host; no `jq` required).

> Note: Host paths (for example, `./container_data/...`) do not exist inside the Vault container.  
> When you run Vault commands via `docker exec`, you must write the output to host files from the host shell.

#### 6.3.3.1 Recommended: use the repo AppRole bootstrap script (build_scripts)

The legacy export scripts have been removed. Use the build-script version instead:

- `./backend/build_scripts/postgress_approle_setup.sh`

This script runs the Vault CLI **inside** the Vault container and writes the AppRole artifacts to the host:

```text
./container_data/vault/approle/<ROLE_NAME>/
  role_id
  secret_id
```

Key behaviors:

- Defaults: `VAULT_CONTAINER=vault_production_node`, `ROLE_NAME=postgres_pgadmin_agent`
- Reads the Vault admin token from:
  - `./backend/app/security/configuration_files/vault/bootstrap/root_token`, or
  - `./backend/app/security/configuration_files/vault/bootstrap/root_token.json` (expects `.root_token`)
- If neither token file exists, it securely prompts for a token (input hidden).
- Rotates `secret_id` by default (`ROTATE_SECRET_ID=1`). Set `ROTATE_SECRET_ID=0` to keep the existing `secret_id`.

```bash
cd "$HOME/NETWORK_TOOLS"
chmod +x ./backend/build_scripts/postgress_approle_setup.sh

# Default behavior (recommended):
# - exports role_id
# - rotates secret_id
./backend/build_scripts/postgress_approle_setup.sh

# Override the role name (rare):
ROLE_NAME="postgres_pgadmin_agent" ./backend/build_scripts/postgress_approle_setup.sh

# Do NOT rotate secret_id (keep current secret_id if present):
ROTATE_SECRET_ID=0 ./backend/build_scripts/postgress_approle_setup.sh

# Custom output directory (optional):
OUT_DIR="$HOME/NETWORK_TOOLS/container_data/vault/approle/postgres_pgadmin_agent"   ./backend/build_scripts/postgress_approle_setup.sh
```

If the Vault Agent is logging **`no known role ID`**, re-run the script above and confirm the following files exist on the host and are readable by the container bind mount:

- `./container_data/vault/approle/postgres_pgadmin_agent/role_id`
- `./container_data/vault/approle/postgres_pgadmin_agent/secret_id`

#### 6.3.3.2 Manual commands (fully expanded; no script)


```bash
set -euo pipefail

cd "$HOME/NETWORK_TOOLS"
umask 077

# --- Vault container/CLI context ------------------------------------------------
VAULT_CONTAINER="vault_production_node"
VAULT_ADDR="https://vault_production_node:8200"
VAULT_CACERT_CONTAINER="/vault/certs/ca.crt"

# --- AppRole -------------------------------------------------------------------
ROLE_NAME="postgres_pgadmin_agent"

# --- Bootstrap token (host) ----------------------------------------------------
BOOTSTRAP_DIR="$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap"
VAULT_TOKEN="$(cat "$BOOTSTRAP_DIR/root_token")"

# --- Output directory (host) ---------------------------------------------------
OUT_DIR="$HOME/NETWORK_TOOLS/container_data/vault/approle/${ROLE_NAME}"
mkdir -p "$OUT_DIR"

# --- Fetch role_id -> host file ------------------------------------------------
docker exec \
  -e VAULT_ADDR="$VAULT_ADDR" \
  -e VAULT_CACERT="$VAULT_CACERT_CONTAINER" \
  -e VAULT_TOKEN="$VAULT_TOKEN" \
  "$VAULT_CONTAINER" \
  vault read -format=json "auth/approle/role/${ROLE_NAME}/role-id" \
| jq -r '.data.role_id' > "$OUT_DIR/role_id"

# --- Generate secret_id -> host file ------------------------------------------
docker exec \
  -e VAULT_ADDR="$VAULT_ADDR" \
  -e VAULT_CACERT="$VAULT_CACERT_CONTAINER" \
  -e VAULT_TOKEN="$VAULT_TOKEN" \
  "$VAULT_CONTAINER" \
  vault write -format=json -f "auth/approle/role/${ROLE_NAME}/secret-id" \
| jq -r '.data.secret_id' > "$OUT_DIR/secret_id"

# --- Lock down permissions and show results -----------------------------------
chmod 600 "$OUT_DIR/role_id" "$OUT_DIR/secret_id"
ls -lah "$OUT_DIR"

```

Operational notes:

- The Vault Agent’s AppRole auto-auth can delete the `secret_id` file after it reads it (recommended).
- If your AppRole is configured with `secret_id_num_uses=1`, you must generate a new `secret_id` when the agent restarts (depending on caching and how you tune the role).
- If the agent cannot authenticate, re-export the artifacts, then restart the agent container.


### 6.3.4 Vault Agent config + templates

Recommended repo paths (create these files in git, but do **not** commit role_id/secret_id):

```text
./backend/app/postgres/vault_agent/
  agent.hcl
  templates/
    postgres_db.ctmpl
    postgres_user.ctmpl
    postgres_password.ctmpl
    pgadmin_password.ctmpl
```

Example `agent.hcl` (KV v2 paths shown):

```hcl
pid_file = "/tmp/vault-agent.pid"

vault {
  address = "https://vault_production_node:8200"
  ca_cert = "/vault/ca/ca.crt"
}

auto_auth {
  method "approle" {
    config = {
      role_id_file_path                   = "/vault/approle/role_id"
      secret_id_file_path                 = "/vault/approle/secret_id"
      remove_secret_id_file_after_reading = true
    }
  }

  sink "file" {
    config = {
      path = "/vault/agent/token"
    }
  }
}

cache {
  use_auto_auth_token = true
}

template {
  source      = "/vault/templates/postgres_db.ctmpl"
  destination = "/vault/rendered/postgres_db"
  perms       = "0640"
}

template {
  source      = "/vault/templates/postgres_user.ctmpl"
  destination = "/vault/rendered/postgres_user"
  perms       = "0640"
}

template {
  source      = "/vault/templates/postgres_password.ctmpl"
  destination = "/vault/rendered/postgres_password"
  perms       = "0600"
}

template {
  source      = "/vault/templates/pgadmin_password.ctmpl"
  destination = "/vault/rendered/pgadmin_password"
  perms       = "0600"
}
```

Template examples (KV v2):

`postgres_db.ctmpl`
```ctmpl
{{- with secret "app_network_tools_secrets/data/postgres" -}}
{{ .Data.data.POSTGRES_DB }}
{{- end }}
```

`postgres_user.ctmpl`
```ctmpl
{{- with secret "app_network_tools_secrets/data/postgres" -}}
{{ .Data.data.POSTGRES_USER }}
{{- end }}
```

`postgres_password.ctmpl`
```ctmpl
{{- with secret "app_network_tools_secrets/data/postgres" -}}
{{ .Data.data.POSTGRES_PASSWORD }}
{{- end }}
```

`pgadmin_password.ctmpl`
```ctmpl
{{- with secret "app_network_tools_secrets/data/pgadmin" -}}
{{ .Data.data.PGADMIN_DEFAULT_PASSWORD }}
{{- end }}
```

### 6.3.5 Docker Compose wiring (vault-agent + shared secrets volume)

> **UPDATE (2025-12-23): the Vault Agent + shared rendered-secrets volume is implemented directly in `docker-compose.prod.yml`.**
>
> Canonical names in this repo:
> - Agent: `vault_agent_postgres_pgadmin`
> - Render volume: `postgres_vault_rendered`
> - Postgres: `postgres_primary`
> - pgAdmin: `pgadmin`

Key behaviors:

- The agent authenticates to Vault (AppRole material bind-mounted read-only at `/vault/approle`) and renders these files into the shared volume (mounted in the agent at `/vault/rendered`):
  - `postgres_db`
  - `postgres_user`
  - `postgres_password`
  - `pgadmin_password`

- `postgres_primary` mounts the same volume read-only at `/run/vault` and uses file-based inputs:
  - `POSTGRES_DB_FILE=/run/vault/postgres_db`
  - `POSTGRES_USER_FILE=/run/vault/postgres_user`
  - `POSTGRES_PASSWORD_FILE=/run/vault/postgres_password`

- `pgadmin` mounts the same volume read-only at `/run/vault` and uses:
  - `PGADMIN_DEFAULT_PASSWORD_FILE=/run/vault/pgadmin_password`

This is the “**always Vault**” posture: Postgres + pgAdmin do not rely on cleartext passwords in `.env` at runtime.

**Recommended hardening: agent healthcheck should verify all required rendered files**

If you use `depends_on: condition: service_healthy` (as this repo does for `postgres_primary` and `pgadmin`), ensure the agent only reports “healthy” once **all** required files exist and are non-empty. Example:

```yaml
healthcheck:
  test: ["CMD-SHELL", "test -s /vault/rendered/postgres_db && test -s /vault/rendered/postgres_user && test -s /vault/rendered/postgres_password && test -s /vault/rendered/pgadmin_password" ]
  interval: 5s
  timeout: 3s
  retries: 30
```

Notes:

- **Important:** If a container was created *before* you added these mounts/envs, you must **recreate** it to pick up the new wiring (see **6.3.6**).
- Legacy pattern: if you prefer keeping `docker-compose.prod.yml` unchanged, you can implement the same wiring in an override file; the repo no longer requires this.
### 6.3.6 Bring-up and verification


> **UPDATE (2025-12-23): bring-up order that matches tonight’s working stack**
>
> The correct ordering is:
>
> 1) Vault up → 2) Vault initialized/unsealed/seeded → 3) AppRole exported to host → 4) Vault Agent renders files → 5) Postgres consumes `*_FILE` → 6) pgAdmin consumes `*_FILE`
>
> If you run `docker compose up` on a service and Compose decides it must **recreate** a dependency, Vault may restart and return to a **sealed** state (expected behavior). To avoid accidental restarts while iterating, prefer `--no-deps` and/or `--no-recreate` when bringing up leaf services.



#### 6.3.6.1 Current bring-up commands (Approach 2: single compose file)

Run from the repo root (`~/NETWORK_TOOLS`) as your rootless Docker user.

1) Start Vault:

```bash
docker compose -f docker-compose.prod.yml up -d vault_production_node
docker logs --tail 200 -f vault_production_node
```

2) Initialize + unseal Vault if this is a brand-new instance (see Section 3.6). If Vault restarted and is sealed, **unseal** it again (Section 3.8).

3) Ensure the KV seed for Postgres/pgAdmin exists (this is the data your agent templates read):

```bash
# validate the secret exists (path may vary by your seeding convention)
docker exec -it vault_production_node sh -lc '
  export VAULT_ADDR=https://vault_production_node:8200
  export VAULT_CACERT=/vault/certs/ca.crt
  export VAULT_TOKEN="$(cat /vault/bootstrap/root_token 2>/dev/null || true)"
  vault kv get app_network_tools_secrets/postgres 2>/dev/null || true
  vault kv get app_network_tools_secrets/pgadmin 2>/dev/null || true
'
```

> Note: The KV mount name is currently `app_network_tools_secrets` (historical spelling). If you standardize the mount to `app_network_tools_secrets`, update the Vault Agent templates and validation commands accordingly.

4) Export AppRole `role_id` + `secret_id` onto the host (Section 6.3.3). This produces:

```text
./container_data/vault/approle/postgres_pgadmin_agent/role_id
./container_data/vault/approle/postgres_pgadmin_agent/secret_id
```

5) Start the Vault Agent and wait for it to be healthy:

```bash
docker compose -f docker-compose.prod.yml up -d vault_agent_postgres_pgadmin
docker logs --tail 200 -f vault_agent_postgres_pgadmin
docker compose -f docker-compose.prod.yml ps
```

6) Confirm rendered files exist inside the agent:

```bash
docker exec -it vault_agent_postgres_pgadmin sh -lc '
  ls -lah /vault/rendered &&
  echo &&
  for f in /vault/rendered/*; do
    echo "== $f ==";
    wc -c "$f";
  done
'
```

Expected files:

- `/vault/rendered/postgres_db`
- `/vault/rendered/postgres_user`
- `/vault/rendered/postgres_password`
- `/vault/rendered/pgadmin_password`

7) Start Postgres:

```bash
docker compose -f docker-compose.prod.yml up -d postgres_certs_init
docker logs postgres_certs_init

docker compose -f docker-compose.prod.yml up -d postgres_primary
docker logs --tail 200 -f postgres_primary
```

8) Start pgAdmin:

```bash
# If pgadmin was previously created without the /run/vault mount, force recreation:
docker compose -f docker-compose.prod.yml up -d --force-recreate pgadmin
docker logs --tail 200 -f pgadmin
```

9) If you want to bring up pgAdmin without touching dependencies (to avoid Vault restarts):

```bash
docker compose -f docker-compose.prod.yml up -d --no-deps --no-recreate pgadmin
```

#### 6.3.6.2 Troubleshooting: common Vault Agent errors

**A) Vault Agent: `error validating configuration: no auto_auth, cache, or listener block found`**

- Your `agent.hcl` is missing required blocks.
- Fix by ensuring `auto_auth { ... }` exists, and you are using a `template { ... }` stanza (or `template_config`) to render secrets.

**B) Vault Agent: `failed to read template: open /vault/templates/<name>.ctmpl: no such file or directory`**

- Your templates directory is not mounted, or the filename in `agent.hcl` does not match the template file on disk.
- Confirm the mount and paths:

**C) Vault Agent: `error creating file sink: ... open /run/vault/.vault-token.tmp... no such file or directory`**

- Cause: the sink directory does not exist (Vault Agent does not create it), or it is not writable.
- Fix (recommended): set the sink path to a directory that always exists and is writable in a hardened container, e.g. `/tmp/.vault-token` (with `tmpfs: ["/tmp"]`).
- Fix (alternative): pre-create the directory in the container entrypoint before starting the agent:

```sh
mkdir -p /run/vault
exec vault agent -config=/vault/agent/agent.hcl
```

**D) Vault Agent: `error getting path or data from method: error="no known role ID"`**

- Cause: `role_id` is missing/empty in the mounted AppRole directory, or the agent is pointed at the wrong path.
- Confirm from inside the agent container:

```bash
docker exec -it vault_agent_postgres_pgadmin sh -lc 'ls -lah /vault/approle && sed -n "1,2p" /vault/approle/role_id'
```

- If the file is missing, re-run the host-side export step (see **6.3.3**) to regenerate `role_id` and `secret_id`.

```bash
docker exec -it vault_agent_postgres_pgadmin sh -lc '
  ls -lah /vault/agent &&
  ls -lah /vault/templates &&
  grep -RIn "ctmpl" /vault/agent/agent.hcl || true
'
```

**C) pgAdmin: `/run/vault/pgadmin_password: No such file or directory`**

Root causes:
- `pgadmin` was created without the `postgres_vault_rendered:/run/vault:ro` mount, or
- the agent is not rendering the file yet.

Fix:
- Ensure `vault_agent_postgres_pgadmin` is **healthy** and the file exists in `/vault/rendered`.
- Recreate pgAdmin so it picks up the mount:

```bash
docker compose -f docker-compose.prod.yml up -d --force-recreate pgadmin
```


1) Ensure Vault is up and healthy:

```bash
docker compose -f docker-compose.prod.yml up -d vault_production_node
docker logs --tail 200 -f vault_production_node
```

2) Initialize/unseal/seed Vault (use your existing repo procedures in section 3.x).

3) Confirm the postgres + pgAdmin secrets exist in Vault (see **4.2** and **5.2**).

4) Export `role_id` + `secret_id` onto the host (see **6.3.3**).

5) Start the Vault Agent service:

```bash
docker compose -f docker-compose.prod.yml -f docker-compose.postgres_vault.override.yml up -d vault_agent_postgres_pgadmin
docker logs --tail 200 -f vault_agent_postgres_pgadmin
```

6) Confirm rendered files exist (example):

```bash
docker exec -it vault_agent_postgres_pgadmin sh -lc 'ls -lah /vault/rendered && echo "----" && sed -n "1,3p" /vault/rendered/postgres_user'
```

7) Start Postgres and pgAdmin:

```bash
docker compose -f docker-compose.prod.yml -f docker-compose.postgres_vault.override.yml up -d postgres_certs_init postgres_primary pgadmin
docker logs --tail 200 -f postgres_primary
docker logs --tail 200 -f pgadmin
```

### 6.3.7 Rotation and operational notes

- **Rotate the rendered secret files (AppRole `secret_id`)**
  - Generate a new `secret_id` (see **6.3.3**) and restart `vault_agent_postgres_pgadmin`.
  - If you configured `remove_secret_id_file_after_reading=true` in `agent.hcl`, the agent will delete the `secret_id` file after reading it; your operational runbook must account for recreating it before restarts.

- **Rotate the Postgres application user password (static credential)**
  - Important: updating Vault KV (or updating the rendered `/run/vault/postgres_password` file) does **not** rotate an already-initialized Postgres cluster. The password is stored inside Postgres.
  - Rotation requires two coordinated actions:

    1) **Change the password inside Postgres** (superuser action)

       Preferred (scripted): run the bootstrap script in rotate mode and apply the change to the running container:

       ```bash
       cd "$HOME/NETWORK_TOOLS"

       bash ./backend/build_scripts/generate_postgres_pgadmin_bootstrap_creds_and_seed.sh          --mode rotate          --vault-addr "https://vault_production_node:8200"          --ca-cert "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt"          --unseal-required 3          --prompt-token          --apply-to-postgres
       ```

       Manual (if you prefer not to exec from the script):

       ```bash
       NEW_PASSWORD="paste_a_new_password_here"

       APPUSER="$(docker exec -it postgres_primary sh -lc 'cat /run/vault/postgres_user' | tr -d '\r')"
       DBNAME="$(docker exec -it postgres_primary sh -lc 'cat /run/vault/postgres_db' | tr -d '\r')"

       docker exec -u postgres -it postgres_primary sh -lc          "psql -v ON_ERROR_STOP=1 -U postgres -d \"$DBNAME\" -c \"ALTER ROLE \\\"$APPUSER\\\" WITH PASSWORD '$NEW_PASSWORD';\""
       ```

       Notes:
       - Restarting `postgres_primary` without the `ALTER ROLE` step will **not** change the password.
       - This uses the local socket inside the container. Ensure your `pg_hba.conf` permits local superuser access.

    2) **Update Vault KV** so the rendered secret matches the new database value  
       If you used `--mode rotate`, the script already updated Vault. Otherwise:

       ```bash
       vault kv patch app_network_tools_secrets/postgres POSTGRES_PASSWORD="$NEW_PASSWORD"
       ```

    3) **Restart or reload clients** that authenticate using that password (pgAdmin, backend apps, etc.).

- **Rotate the pgAdmin default password (static credential)**
  - `PGADMIN_DEFAULT_PASSWORD(_FILE)` is used only for initial admin account creation.
  - To rotate it non-interactively, the simplest approach is to:
    1) update Vault KV (`app_network_tools_secrets/pgadmin`), and
    2) recreate the `pgadmin` container so it re-initializes (or change the password from the UI).

- **Prefer dynamic credentials for applications**
  - When you are ready, move application authentication to Vault dynamic database credentials (see **6.4**). This avoids long-lived static passwords and simplifies rotation.
### 6.4 Option C – Advanced: Vault Database secrets engine (dynamic credentials)


#### 6.4.1 What this enables (and what it is *not*)

Vault’s **database secrets engine** is for issuing **dynamic, time-bound database credentials** to applications and operators (for example: “give me a user that can read/write schema X for 1 hour”). It is also the mechanism Vault uses to **rotate** privileged database credentials (including “root rotation”) in a controlled way.

It is **not** a mechanism for Postgres to “phone home” to Vault on its own. Postgres will not natively call Vault at boot. Instead:

- **Option B (Vault Agent)** bootstraps Postgres/pgAdmin at container start by rendering files from Vault KV.
- **Option C (database secrets engine)** issues *new* Postgres users/passwords on-demand for your apps, and supports rotation.

You can (and usually should) run **both**: Option B for initial boot + Option C for app credentials and rotation.

#### 6.4.2 Prerequisites

- Vault is initialized and unsealed.
- Postgres (`postgres_primary`) is running and reachable from the Vault container over the Compose network.
- You have a Postgres “management” login that Vault will use to create/revoke dynamic users (recommended: a dedicated role, not your app user).
- Vault can validate Postgres TLS (recommended). If Postgres uses a different CA than Vault, mount the Postgres CA into `vault_production_node` (read-only) and use it in the connection URL.

**Recommended Compose hardening for this step (TLS verification):**

Add this mount to `vault_production_node`:

```yaml
services:
  vault_production_node:
    volumes:
      - ./backend/app/postgres/certs/ca.crt:/vault/postgres_certs/ca.crt:ro
```

#### 6.4.3 Create a dedicated Postgres management role for Vault

From the host, exec into Postgres and create a role with the minimum privileges needed to manage users.

Example (adjust DB name and privileges to your standards):

```bash
docker exec -it postgres_primary sh -lc '
  DB="$(cat /run/vault/postgres_db)"
  APPUSER="$(cat /run/vault/postgres_user)"
  APPPASS="$(cat /run/vault/postgres_password)"

  export PGSSLMODE=verify-full
  export PGSSLROOTCERT=/etc/postgres/certs/ca.crt
  export PGPASSWORD="$APPPASS"

  psql -h 127.0.0.1 -U "$APPUSER" -d "$DB" <<SQL
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = ''vault_admin'') THEN
    CREATE ROLE vault_admin WITH LOGIN CREATEROLE;
  END IF;
END
\$\$;

-- Set/rotate the password (you can generate a strong value and store it in Vault KV)
ALTER ROLE vault_admin WITH PASSWORD ''REPLACE_ME_STRONG_PASSWORD'';

-- Optional: if you need Vault to manage objects in a specific schema, grant accordingly
GRANT CONNECT ON DATABASE "'$DB'" TO vault_admin;
SQL
'
```

**Operational note:** Store `vault_admin`’s password in Vault KV and treat it like a managed secret. It is used only by Vault’s database plugin, not by application workloads.

#### 6.4.4 Enable and configure Vault’s PostgreSQL database connection

Enable the database secrets engine once:

```bash
docker exec -it vault_production_node sh -lc '
  export VAULT_ADDR=https://vault_production_node:8200
  export VAULT_CACERT=/vault/certs/ca.crt
  export VAULT_TOKEN="$(cat /vault/bootstrap/root_token 2>/dev/null || true)"

  vault secrets list | grep -q "^database/" || vault secrets enable database
'
```

Configure the connection (replace password and SSL parameters to match your setup):

```bash
docker exec -it vault_production_node sh -lc '
  export VAULT_ADDR=https://vault_production_node:8200
  export VAULT_CACERT=/vault/certs/ca.crt
  export VAULT_TOKEN="$(cat /vault/bootstrap/root_token 2>/dev/null || true)"

  vault write database/config/network_tools_pg     plugin_name=postgresql-database-plugin     allowed_roles="network_tools_app"     connection_url="postgresql://{{username}}:{{password}}@postgres_primary:5432/network_tools?sslmode=verify-full&sslrootcert=/vault/postgres_certs/ca.crt"     username="vault_admin"     password="REPLACE_ME_STRONG_PASSWORD"
'
```

If you cannot mount the Postgres CA yet, a temporary (less desirable) fallback is `sslmode=require`, but you should move to `verify-full` as soon as you can.

#### 6.4.5 Create a Vault role that defines how dynamic users are created

This is where you define the SQL Vault will run to create and revoke users.

Example role that grants basic DML on the `public` schema:

```bash
docker exec -it vault_production_node sh -lc '
  export VAULT_ADDR=https://vault_production_node:8200
  export VAULT_CACERT=/vault/certs/ca.crt
  export VAULT_TOKEN="$(cat /vault/bootstrap/root_token 2>/dev/null || true)"

  vault write database/roles/network_tools_app     db_name=network_tools_pg     default_ttl="1h"     max_ttl="24h"     creation_statements="
      CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD ''{{password}}'' VALID UNTIL ''{{expiration}}'';
      GRANT CONNECT ON DATABASE network_tools TO \"{{name}}\";
      GRANT USAGE ON SCHEMA public TO \"{{name}}\";
      GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO \"{{name}}\";
      ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO \"{{name}}\";
    "     revocation_statements="
      REASSIGN OWNED BY \"{{name}}\" TO vault_admin;
      DROP OWNED BY \"{{name}}\";
      DROP ROLE IF EXISTS \"{{name}}\";
    "
'
```

Adjust privileges (schema-specific, read-only, migrations, etc.) to match your application model.

#### 6.4.6 Fetch credentials and validate

Fetch a new set of credentials:

```bash
docker exec -it vault_production_node sh -lc '
  export VAULT_ADDR=https://vault_production_node:8200
  export VAULT_CACERT=/vault/certs/ca.crt
  export VAULT_TOKEN="$(cat /vault/bootstrap/root_token 2>/dev/null || true)"

  vault read -format=json database/creds/network_tools_app
'
```

Test from a one-off Postgres client container (recommended) or from within `postgres_primary`.

#### 6.4.7 Rotation (future-facing)

Once the database config is correct, Vault can rotate the management user password:

```bash
docker exec -it vault_production_node sh -lc '
  export VAULT_ADDR=https://vault_production_node:8200
  export VAULT_CACERT=/vault/certs/ca.crt
  export VAULT_TOKEN="$(cat /vault/bootstrap/root_token 2>/dev/null || true)"

  vault write -f database/rotate-root/network_tools_pg
'
```

This is the foundation for “eventually, Vault will generate DB passwords / rotate etc.”


This option is the most secure pattern for **applications** connecting to Postgres:
- Vault issues short-lived, revocable Postgres credentials on demand.
- Your application fetches credentials from Vault (or via Vault Agent templates) and renews them automatically.

Important limitation:
- This does **not** change how the `postgres` container itself initializes the database. It primarily improves how *other services* authenticate to Postgres after it is up.

High-level steps (outline):
1) Enable the database secrets engine in Vault (`vault secrets enable database`).
2) Configure a Postgres connection in Vault using an admin credential (managed carefully).
3) Create Vault roles that define SQL for creating/revoking users with TTLs.
4) Update your apps to request credentials from Vault at runtime.

When you adopt this, keep the initial bootstrap password in Vault as a break-glass/admin secret, but prefer dynamic roles for day-to-day service auth.

## 4. postgres

This section documents how we generate and store **initial postgres bootstrap credentials** for the Network Tools stack. The intent is that the rest of the containerized services (postgres itself, application backends, migrations, etc.) can pull their required values from **Vault KV** rather than hard-coding credentials into the repository or long-lived `.env` files.

### 4.1 Bootstrap credentials (generate + seed)

**Run as the same non-root user that runs rootless Docker** (e.g., `developer_network_tools`) from the repo root:

```bash
Exclude the '--prompt-token' if you left the root token files in the bootstrap directory 
as this script will default to looking there first on an initial install and setup.

cd "$HOME/NETWORK_TOOLS"

bash ./backend/build_scripts/generate_postgres_pgadmin_bootstrap_creds_and_seed.sh \
  --vault-addr "https://vault_production_node:8200" \
  --ca-cert "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt" \
  --unseal-required 3 \
  --prompt-token
```

```bash
Example output without the '--prompt-token' flag

developer_network_tools@networktoolsvm:~/NETWORK_TOOLS$ bash ./backend/build_scripts/generate_postgres_pgadmin_bootstrap_creds_and_seed.sh \
  --vault-addr "https://vault_production_node:8200" \
  --ca-cert "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt" \
  --unseal-required 3
WARN: Keycloak TLS material not found; skipping keycloak_tls seeding.
INFO: Wrote credential artifacts:
INFO:   ENV:  /home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/postgres_pgadmin.env
INFO:   JSON: /home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/postgres_pgadmin_credentials.json
INFO:   SPEC: /home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/seed_kv_spec.postgres_pgadmin.json
INFO: 
INFO: Seeding Vault from generated spec...
INFO:   VAULT_ADDR: https://vault_production_node:8200
INFO:   Seed script: /home/developer_network_tools/NETWORK_TOOLS/backend/build_scripts/vault_unseal_multi_kv_seed_bootstrap_rootless.sh
INFO:   CA cert:    /home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt
INFO: Vault address: https://vault_production_node:8200
INFO: Bootstrap dir: /home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap
INFO: Spec file: /home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/seed_kv_spec.postgres_pgadmin.json
INFO: Unseal keys file: /home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/unseal_keys.json
INFO: CA cert: /home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt
INFO: Vault is already unsealed. Skipping unseal.
INFO: Spec mounts: 1
INFO: --- Mount [0]: app_network_tools_secrets (version=2) ---
INFO: Enabled KV v2 at app_network_tools_secrets/
INFO: wrote -> app_network_tools_secrets/postgres
INFO: wrote -> app_network_tools_secrets/pgadmin
INFO: wrote -> app_network_tools_secrets/keycloak_postgres
INFO: wrote -> app_network_tools_secrets/keycloak_bootstrap
INFO: wrote -> app_network_tools_secrets/keycloak_runtime
INFO: Mount app_network_tools_secrets: seed complete. success=5 failed=0
INFO: Wrote consolidated secrets artifact:
      /home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/seeded_secrets_all.json
INFO: (Not printing secrets; use --print-secrets to print.)
INFO: Recommended next steps:
  1) Securely download required artifacts (examples):
     scp -p <user>@<server>:"/home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/seeded_secrets_all.json" .
     scp -p <user>@<server>:"/home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/unseal_keys.json" .
     scp -p <user>@<server>:"/home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token" .
     scp -p <user>@<server>:"/home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token.json" .
  2) After verifying downloads, remove sensitive files from the server:
     rm -f "/home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/seeded_secrets_all.json" "/home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/unseal_keys.json" "/home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token" "/home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token.json"
INFO: Done.
INFO: Vault seeding completed.
INFO: Done.

```

```text
Your file structure should look similar to below.

developer_network_tools@networktoolsvm:~/NETWORK_TOOLS$ tree --charset ascii
.
|-- backend
|   |-- app
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
|   |   |-- mariadb_queries
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
|   |   |           `-- postgres_user.ctmpl
|   |   |-- routers
|   |   `-- security
|   |       `-- configuration_files
|   |           `-- vault
|   |               |-- bootstrap
|   |               |   |-- postgres_pgadmin_credentials.json <-- NEW Generated for bootstrap use for the other containers
|   |               |   |-- postgres_pgadmin.env <-- NEW Generated for bootstrap use for the other containers
|   |               |   |-- root_token
|   |               |   |-- root_token.json
|   |               |   |-- seeded_secrets_all.json <-- NEW Generated for bootstrap use for the other containers
|   |               |   |-- seed_kv_spec.postgres_pgadmin.json <-- NEW Generated for bootstrap use for the other containers
|   |               |   `-- unseal_keys.json
|   |               |-- certs
|   |               |   |-- ca.crt
|   |               |   |-- ca.key
|   |               |   |-- ca.srl
|   |               |   |-- cert.crt
|   |               |   `-- cert.key
|   |               |-- config
|   |               |   |-- certs
|   |               |   |-- keycloak_kv_read.hcl
|   |               |   |-- postgres_pgadmin_kv_read.hcl
|   |               |   `-- vault_configuration_primary_node.hcl
|   |               `-- Dockerfile
|   |-- build_scripts
|   |   |-- generate_local_keycloak_certs.sh
|   |   |-- generate_local_postgres_certs.sh
|   |   |-- generate_local_vault_certs.sh
|   |   |-- generate_postgres_pgadmin_bootstrap_creds_and_seed.sh
|   |   |-- guides
|   |   |   |-- seed_kv_spec.example.json
|   |   |   `-- seed_kv_spec.GUIDE.md
|   |   |-- keycloak_approle_setup.sh
|   |   |-- postgress_approle_setup.sh
|   |   |-- startover_scripts
|   |   |   `-- reset_network_tools_docker.sh
|   |   |-- vault_first_time_init_only_rootless.sh
|   |   |-- vault_unseal_kv_seed_bootstrap_rootless.sh
|   |   `-- vault_unseal_multi_kv_seed_bootstrap_rootless.sh
|   `-- nginx
|-- container_data
|   `-- vault
|       `-- data
|           |-- logs
|           |   `-- audit.log
|           |-- raft
|           |   |-- raft.db
|           |   `-- snapshots
|           `-- vault.db
|-- docker-compose.prod.yml
|-- environment_variable_guide.md
|-- frontend
|-- how_to_videos
|   |-- HOW_TO_3.2 Validate Certificates.mov
|   |-- HOW_TO_3.3 Start Vault with Docker Compose.mov
|   |-- HOW_TO_3.6 Initialize and Unseal Vault (First Run).mov
|   |-- HOW_TO_3.8.3 Single-Mount Seeder (vault_unseal_kv_seed_bootstrap_rootless.sh).mov
|   `-- HOW_TO_3.8.4 Multi-Mount Seeder (vault_unseal_multi_kv_seed_bootstrap_rootless.sh).mov
|-- README.full.md
`-- README.md
```

```text
Example secrets that have been auto generated and seeded into vault

developer_network_tools@networktoolsvm:~/NETWORK_TOOLS$ cat ./backend/app/security/configuration_files/vault/bootstrap/seed_kv_spec.postgres_pgadmin.json
{
  "mounts": [
    {
      "mount": "app_network_tools_secrets",
      "version": 2,
      "secrets": {
        "postgres": {
          "POSTGRES_DB": "network_tools",
          "POSTGRES_USER": "network_tools_user",
          "POSTGRES_PASSWORD": "l8iJmim6SQGLDILfKJgGUvckyK16PL_bO03AVpMWYI4"
        },
        "pgadmin": {
          "PGADMIN_DEFAULT_EMAIL": "admin@example.com",
          "PGADMIN_DEFAULT_PASSWORD": "wYrip91EtXhSn3XihLB23Z_LckULaIjlIukpYA0hoIk"
        },
        "keycloak_postgres": {
          "KC_DB": "postgres",
          "KC_DB_URL_HOST": "postgres_primary",
          "KC_DB_URL_PORT": "5432",
          "KC_DB_URL_DATABASE": "keycloak",
          "KC_DB_USERNAME": "keycloak",
          "KC_DB_PASSWORD": "-eQZOS4Dp0Ts2a9BpUXf6hPuweEGjUdmgSTpGpoHiFw",
          "KC_DB_SCHEMA": "keycloak"
        },
        "keycloak_bootstrap": {
          "KC_BOOTSTRAP_ADMIN_USERNAME": "admin",
          "KC_BOOTSTRAP_ADMIN_PASSWORD": "nx6a6NmP4LGtnSRteTrAX46VAyY4OfDF0ANNGxpucg0"
        },
        "keycloak_runtime": {
          "KC_HOSTNAME": "keycloak",
          "KC_HOSTNAME_STRICT": "true",
          "KC_HTTP_ENABLED": "false",
          "KC_HTTPS_PORT": "8443",
          "KC_HEALTH_ENABLED": "true",
          "KC_METRICS_ENABLED": "true",
          "KC_HTTP_MANAGEMENT_PORT": "9000",
          "KC_HTTP_MANAGEMENT_SCHEME": "http"
        }
      }
    }
  ]
}
```

What the script does:

- Generates:
  - `POSTGRES_DB` (default: `network_tools`)
  - `POSTGRES_USER` (default: `network_tools_user`)
  - `POSTGRES_PASSWORD` (generated if not supplied)
- Creates local **bootstrap artifacts** under:

  ```text
  $HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/
  ```

  Files created:
  - `postgres_pgadmin.env` (shell env format)
  - `postgres_pgadmin_credentials.json` (human-readable credentials JSON)
  - `seed_kv_spec.postgres_pgadmin.json` (the spec used to seed Vault)

- Seeds Vault KV mount **`app_network_tools_secrets`** (default) with two secret paths:
  - `postgres` (postgres values)
  - `pgadmin` (pgAdmin values)

Notes:

- By default, the script writes to `postgres` and `pgadmin` **without** a prefix (this matches the desired layout: `postgres`, not `bootstrap/postgres`).
- If you explicitly want a prefix later, use `--vault-prefix "<prefix>"`.

Rotation (long-term operations):

- The same script supports rotating the **static** Postgres application password stored in Vault.
- Rotation has two required steps:
  1) Update Vault KV (so the agent will render the new value).
  2) Update the password inside the running Postgres cluster (because `POSTGRES_*` init vars are only applied on first initialization).
- Use `--mode rotate` to generate a new password and re-seed Vault. To also apply it to a running container, add `--apply-to-postgres`:

```bash
cd "$HOME/NETWORK_TOOLS"

VAULT_ADDR="https://vault_production_node:8200"
VAULT_CA_CERT="$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt"

bash ./backend/build_scripts/generate_postgres_pgadmin_bootstrap_creds_and_seed.sh \
  --mode rotate \
  --vault-addr "$VAULT_ADDR" \
  --ca-cert "$VAULT_CA_CERT" \
  --unseal-required 3 \
  --prompt-token \
  --apply-to-postgres
```

- If you prefer to do the Postgres `ALTER ROLE` step manually (or if `--apply-to-postgres` fails), see **6.3.7**.

Security and operational guidance:

- These files contain plaintext credentials.
- Immediately download them to a secure location and remove them from the server once you have verified the secrets are stored in Vault.
- In production, prefer:
  - short-lived bootstrap tokens,
  - scoped policies,
  - rotation workflows,
  - and (where practical) Vault dynamic secrets engines instead of long-lived static passwords.

### 4.2 Retrieve credentials from Vault

The seeding script writes using the Vault HTTP API. If your mount is **KV v2** (the default in the generated spec), read secrets like this:

```bash
VAULT_ADDR="https://vault_production_node:8200"
CA_CERT="$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt"
TOKEN="$(cat "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token")"

# postgres secret (KV v2)
curl -sS --cacert "$CA_CERT" \
  -H "X-Vault-Token: $TOKEN" \
  "$VAULT_ADDR/v1/app_network_tools_secrets/data/postgres" | jq .
```

To extract a single value (example: password):

```bash
curl -sS --cacert "$CA_CERT" \
  -H "X-Vault-Token: $TOKEN" \
  "$VAULT_ADDR/v1/app_network_tools_secrets/data/postgres" | jq -r '.data.data.POSTGRES_PASSWORD'
```

If you later choose to use **KV v1**, the read path will not include `/data/`:

```bash
curl -sS --cacert "$CA_CERT" \
  -H "X-Vault-Token: $TOKEN" \
  "$VAULT_ADDR/v1/app_network_tools_secrets/postgres" | jq .
```

### 4.3 Use with Docker Compose

**Before you start: generate local Postgres TLS certs (one-time per environment)**

If Postgres TLS is enabled (the default in this repo), make sure the Postgres certificate files exist **before** bringing the Compose stack up. From the repo root:

```bash
cd "$HOME/NETWORK_TOOLS"
bash ./backend/build_scripts/generate_local_postgres_certs.sh
```

```bash
developer_network_tools@networktoolsvm:~/NETWORK_TOOLS$ tree --charset ascii
.
|-- backend
|   |-- app
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
|   |   |-- mariadb_queries
|   |   |-- postgres
|   |   |   |-- certs
|   |   |   |   |-- ca.crt
|   |   |   |   |-- ca.key <- NEW - Can be removed to safe storage
|   |   |   |   |-- ca.srl <- NEW - Can be removed to safe storage
|   |   |   |   |-- cert.crt
|   |   |   |   `-- cert.key
|   |   |   |-- config
|   |   |   |   |-- pg_hba.conf
|   |   |   |   `-- postgres.conf
|   |   |   `-- vault_agent
|   |   |       |-- agent.hcl
|   |   |       `-- templates
|   |   |           |-- pgadmin_password.ctmpl
|   |   |           |-- postgres_db.ctmpl
|   |   |           |-- postgres_password.ctmpl
|   |   |           `-- postgres_user.ctmpl
|   |   |-- routers
|   |   `-- security
|   |       `-- configuration_files
|   |           `-- vault
|   |               |-- bootstrap
|   |               |   |-- postgres_pgadmin_credentials.json
|   |               |   |-- postgres_pgadmin.env
|   |               |   |-- root_token
|   |               |   |-- root_token.json
|   |               |   |-- seeded_secrets_all.json
|   |               |   |-- seed_kv_spec.postgres_pgadmin.json
|   |               |   `-- unseal_keys.json
|   |               |-- certs
|   |               |   |-- ca.crt <- NEW
|   |               |   |-- ca.key <- NEW - Can be removed to safe storage
|   |               |   |-- ca.srl <- NEW - Can be removed to safe storage
|   |               |   |-- cert.crt <- NEW
|   |               |   `-- cert.key <- NEW
|   |               |-- config
|   |               |   |-- certs
|   |               |   |-- keycloak_kv_read.hcl
|   |               |   |-- postgres_pgadmin_kv_read.hcl
|   |               |   `-- vault_configuration_primary_node.hcl
|   |               `-- Dockerfile
|   |-- build_scripts
|   |   |-- generate_local_keycloak_certs.sh
|   |   |-- generate_local_postgres_certs.sh
|   |   |-- generate_local_vault_certs.sh
|   |   |-- generate_postgres_pgadmin_bootstrap_creds_and_seed.sh
|   |   |-- guides
|   |   |   |-- seed_kv_spec.example.json
|   |   |   `-- seed_kv_spec.GUIDE.md
|   |   |-- keycloak_approle_setup.sh
|   |   |-- postgress_approle_setup.sh
|   |   |-- startover_scripts
|   |   |   `-- reset_network_tools_docker.sh
|   |   |-- vault_first_time_init_only_rootless.sh
|   |   |-- vault_unseal_kv_seed_bootstrap_rootless.sh
|   |   `-- vault_unseal_multi_kv_seed_bootstrap_rootless.sh
|   `-- nginx
|-- container_data
|   `-- vault
|       |-- approle
|       |   `-- postgres_pgadmin_agent
|       `-- data
|           |-- logs
|           |   `-- audit.log
|           |-- raft
|           |   |-- raft.db
|           |   `-- snapshots
|           `-- vault.db
|-- docker-compose.prod.yml
|-- environment_variable_guide.md
|-- frontend
|-- how_to_videos
|   |-- HOW_TO_3.2 Validate Certificates.mov
|   |-- HOW_TO_3.3 Start Vault with Docker Compose.mov
|   |-- HOW_TO_3.6 Initialize and Unseal Vault (First Run).mov
|   |-- HOW_TO_3.8.3 Single-Mount Seeder (vault_unseal_kv_seed_bootstrap_rootless.sh).mov
|   `-- HOW_TO_3.8.4 Multi-Mount Seeder (vault_unseal_multi_kv_seed_bootstrap_rootless.sh).mov
|-- README.full.md
`-- README.md

```


Verify the expected cert files were created (these are the files mounted into the Postgres container):

```bash
ls -lah ./backend/app/postgres/certs/
# Expected (minimum): ca.crt, cert.crt, cert.key
```

You have two common patterns:

**Option A (simple dev bootstrap): use the generated env file**

This is convenient, but treat it as sensitive:

```bash
set -a
# shellcheck disable=SC1090
source "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/postgres_pgadmin.env"
set +a
```

You can then reference the exported variables when starting one-off Postgres/pgAdmin containers (or for manual troubleshooting). In production, prefer the Vault Agent `*_FILE` pattern described in **6.3.5**.

**Option B (preferred): pull from Vault at runtime**

For production-like workflows, prefer fetching secrets from Vault at container start using the Vault Agent sidecar pattern (`*_FILE` env vars). This is implemented in `docker-compose.prod.yml`; see **6.3.5**.


#### 4.3.1 Compose prerequisites

Run these checks from the repository root (`~/NETWORK_TOOLS`) as the same non-root user that runs **rootless Docker** (e.g., `developer_network_tools`):

1) Confirm the source certificate files exist on the host:

```bash
ls -lh ./backend/app/postgres/certs/
```

Expected (minimum) inputs:

- `ca.crt`
- `cert.crt`
- `cert.key`

2) Confirm the Postgres config files exist and are **not empty**:

```bash
ls -lh ./backend/app/postgres/config/postgres.conf ./backend/app/postgres/config/pg_hba.conf
wc -l  ./backend/app/postgres/config/postgres.conf ./backend/app/postgres/config/pg_hba.conf
```

3) Validate the Compose file renders cleanly (this catches YAML formatting/indentation issues early):

```bash
docker compose -f docker-compose.prod.yml config > /tmp/network_tools.compose.rendered.yml
```

#### 4.3.2 Initialize the Postgres certs volume

In this stack, Postgres TLS material is delivered via a **named volume** populated by a short-lived init container (`postgres_certs_init`). The primary Postgres service mounts that volume read-only at `/etc/postgres/certs`.

Bring-up pattern:

1) (Optional but recommended during troubleshooting) reset the cert volume and the init container:

```bash
docker compose -f docker-compose.prod.yml rm -sf postgres_primary postgres_certs_init

# The actual on-disk volume name is prefixed by the compose project name (e.g., network_tools_postgres_certs)
docker volume rm network_tools_postgres_certs 2>/dev/null || true
```

2) Start the init container and confirm it successfully populated the volume:

```bash
docker compose -f docker-compose.prod.yml up -d postgres_certs_init
docker logs postgres_certs_init
```

You should see a file listing of `/dest` at the end of the logs with:

- `ca.crt`
- `server.crt`
- `server.key`

3) (Optional) validate the volume contents directly:

```bash
docker run --rm -v network_tools_postgres_certs:/dest alpine ls -l /dest
```

Note: In rootless Docker, owners may appear as numeric IDs (e.g., `999`). That is expected.

#### 4.3.3 Start postgres_primary

Start the primary Postgres service after the init container has completed successfully:

```bash
docker compose -f docker-compose.prod.yml up -d postgres_primary
docker logs --tail 200 -f postgres_primary
```

A successful start ends with:

- `database system is ready to accept connections`

#### 4.3.4 Verify and connect

1) Confirm the container is up:

```bash
docker compose -f docker-compose.prod.yml ps
docker ps --format "table {{.Names}}	{{.Status}}	{{.Ports}}"
```

2) Confirm the expected files exist inside the container:

```bash
docker exec -it postgres_primary sh -lc 'ls -lah /etc/postgres/certs && ls -lah /etc/postgres/postgres.conf /etc/postgres/pg_hba.conf'
```

3) Verify effective runtime settings (inside Postgres):

```bash
docker exec -it postgres_primary sh -lc 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "SHOW ssl; SHOW ssl_cert_file; SHOW ssl_key_file; SHOW ssl_ca_file; SHOW config_file; SHOW hba_file;"'
```

If you expect host connectivity, ensure your `postgres.conf` includes an appropriate `listen_addresses` value (e.g., `'*'`) and that the Compose service publishes `5432:5432`.

#### 4.3.5 Troubleshooting

**1) Mount error: “read-only file system” when creating `/etc/postgres/certs/*.crt` mountpoints**

Symptom (example):

- `create mountpoint "/etc/postgres/certs/ca.crt": read-only file system`

Common cause:

- The Compose service attempts to mount **individual cert files** into a path that is already covered by a **read-only directory mount** (for example, a named volume mounted at `/etc/postgres/certs:ro`).

Fix (recommended):

- Choose one approach. For this project, keep the **named volume** (`postgres_certs:/etc/postgres/certs:ro`) and remove file-level mounts to `/etc/postgres/certs/*`. Let `postgres_certs_init` populate the volume.

**2) FATAL: could not load server certificate file (missing file)**

Symptoms (examples):

- `could not load server certificate file "/etc/postgres/certs/server.crt": No such file or directory`
- `could not load server certificate file "/etc/postgres/certs/cert.crt": No such file or directory`

Checklist:

- Confirm `postgres_certs_init` completed successfully and the volume contains `server.crt` and `server.key` (Section **4.3.2**).
- Confirm Postgres is configured to reference the filenames that actually exist.

Recommendation:

- Standardize on `server.crt` / `server.key` inside the container (as produced by `postgres_certs_init`), and set:

  - `ssl_cert_file=/etc/postgres/certs/server.crt`
  - `ssl_key_file=/etc/postgres/certs/server.key`
  - `ssl_ca_file=/etc/postgres/certs/ca.crt`

If your `postgres.conf` currently references `cert.crt`, update it (or alternately, add a copy step in `postgres_certs_init` so both names exist).

**3) pg_hba.conf errors (empty or unreadable)**

Symptoms:

- `configuration file "/etc/postgres/pg_hba.conf" contains no entries`
- `FATAL: could not load /etc/postgres/pg_hba.conf`

Checklist:

```bash
# Host file must exist and be non-empty
wc -l ./backend/app/postgres/config/pg_hba.conf

# Container must see the same file (and it must be readable)
docker exec -it postgres_primary sh -lc 'ls -l /etc/postgres/pg_hba.conf && wc -l /etc/postgres/pg_hba.conf'
```

Minimal example (tighten for your environment; do not use `trust` broadly in production):

```conf
# TYPE  DATABASE        USER            ADDRESS                 METHOD
local   all             all                                     peer
host    all             all             127.0.0.1/32            scram-sha-256
host    all             all             ::1/128                 scram-sha-256

# Example: allow app subnet over TLS (adjust CIDR)
hostssl all             all             10.0.0.0/8              scram-sha-256
```

**4) “PostgreSQL Database directory appears to contain a database; Skipping initialization”**

This is informational. It means your bound data directory already has an initialized cluster. If you intend a clean rebuild, stop Postgres and remove the data directory contents (or move them aside), then restart.

**5) postgres_certs_init logs show only environment variables / no `/dest` listing**

This typically indicates the init container did not execute the intended copy commands.

- Re-check the rendered Compose output:

  ```bash
  docker compose -f docker-compose.prod.yml config | sed -n '/postgres_certs_init:/,/postgres_primary:/p'
  ```

- Confirm `entrypoint` and `command` match the expected script, then recreate the init container:

  ```bash
  docker compose -f docker-compose.prod.yml rm -sf postgres_certs_init
  docker compose -f docker-compose.prod.yml up -d --force-recreate --no-deps postgres_certs_init
  docker logs postgres_certs_init
  ```


### 4.4 Startup credential options (choose one)

Postgres does **not** natively “connect to Vault” on startup. In Docker, you typically implement that behavior using one of the following patterns:

1) **Baseline (current Compose approach): `.env` / `env_file`**
   - The host (or a build script) populates `POSTGRES_DB`, `POSTGRES_USER`, and `POSTGRES_PASSWORD` in `.env`.
   - `docker-compose.prod.yml` consumes those values (see **4.3**).

2) **Vault Agent sidecar (recommended when you want Vault dependency at container start)**
   - A Vault Agent container authenticates to Vault and renders secrets into files in a shared volume.
   - The official Postgres image supports file-based inputs via `POSTGRES_DB_FILE`, `POSTGRES_USER_FILE`, and `POSTGRES_PASSWORD_FILE`.
   - See **Section 6** for the full wiring and bootstrapping procedure.

3) **Host “pre-flight” fetch from Vault (simple, but less ideal)**
   - A host script reads secrets from Vault and writes them into `.env` immediately before `docker compose up`.
   - This is easy to operate, but it places secrets back into `.env` (which you should treat as sensitive).

Operational note:
- `POSTGRES_DB(_FILE)`, `POSTGRES_USER(_FILE)`, and `POSTGRES_PASSWORD(_FILE)` are consumed by the official Postgres image **only when initializing a brand-new data directory** (no existing cluster under `PGDATA`).
- After the cluster exists, changing Vault KV (or changing the rendered files) will **not** rotate the database user's password by itself.
- Password rotation requires (a) `ALTER ROLE ... WITH PASSWORD ...` executed as a superuser inside Postgres, and (b) updating Vault KV so the rendered secret matches.
- The bootstrap script supports this workflow via `--mode rotate` (and optionally `--apply-to-postgres`). See **4.1** and **6.3.7**.



### 4.5 Apply Vault credentials to an existing Postgres cluster

Use this when **secrets already exist** (local bootstrap file and/or Vault), but the Postgres data directory has already been initialized and you need to **create/align roles and databases** inside the running cluster.

Key points:

- `POSTGRES_DB`, `POSTGRES_USER`, and `POSTGRES_PASSWORD` are only consumed by the Postgres image **on first initialization** (when the data directory is empty).
- After that, changing env values (or Vault values) does **not** change users/passwords inside Postgres; you must apply changes with SQL (for example, `ALTER ROLE ... WITH PASSWORD ...`).

Recommended “sync/apply” command (does **not** re-seed Vault):

```bash
cd "$HOME/NETWORK_TOOLS"

bash ./backend/build_scripts/generate_postgres_pgadmin_bootstrap_creds_and_seed.sh \
  --vault-addr "https://vault_production_node:8200" \
  --ca-cert "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt" \
  --unseal-required 3 \
  --no-seed \
  --apply-to-postgres

```

Operational notes:

- By default, `--apply-to-postgres` will try to bring up `postgres_primary` (via Compose) if it is not already running, then wait for it to accept connections.
- If you want to manage Postgres startup yourself, add `--no-auto-start-postgres`.
- If Postgres is slow to start (first init, fsync, etc.), increase `--wait-postgres-seconds`.

### 4.6 Rotation runbook (static credentials)

This repo currently uses **static** database credentials stored in Vault KV (as opposed to Vault’s database secrets engine issuing dynamic, leased credentials). Static creds are simple, but rotation must be handled intentionally.

Rotation always has two parts:

1) **Rotate in Vault** so the new value is the source of truth (and so Vault Agent sidecars render the updated secret).
2) **Rotate in Postgres** so the role password in the cluster matches Vault.

Rotate + apply in one workflow (recommended):

```bash
cd "$HOME/NETWORK_TOOLS"

bash ./backend/build_scripts/generate_postgres_pgadmin_bootstrap_creds_and_seed.sh   --vault-addr "https://vault_production_node:8200"   --ca-cert "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt"   --unseal-required 3   --mode rotate   --apply-to-postgres
```

What this accomplishes:

- Generates new passwords (unless you explicitly pass values).
- Writes updated values to Vault KV (unless `--no-seed`).
- Updates Postgres roles/databases to match the new Vault values.

After rotation:

- Restart dependent services (pgAdmin, Keycloak, application backends) so they pick up the new rendered credentials.
- If using Vault Agent sidecars, confirm the rendered files have changed before restarting application containers.

If you want to rotate only a subset:

- Prefer `--mode rotate` plus explicit values for the passwords you want to rotate, and reuse existing values for everything else.
- Use `--no-keycloak` / `--no-keycloak-bootstrap` / `--no-keycloak-runtime` (as applicable) when you want to avoid updating Keycloak-related secrets.

## 5. pgAdmin

This section documents the bootstrap credential(s) used by **pgAdmin** and how they are stored alongside the postgres credentials.

### 5.1 Bootstrap credentials (generate + seed)

The postgres/pgAdmin bootstrap script generates *both* Postgres and pgAdmin credentials in one run:

```bash
cd "$HOME/NETWORK_TOOLS"

bash ./backend/build_scripts/generate_postgres_pgadmin_bootstrap_creds_and_seed.sh \
  --vault-addr "https://vault_production_node:8200" \
  --ca-cert "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt" \
  --unseal-required 3 \
  --prompt-token
```

The pgAdmin secret is stored under:

- KV mount: `app_network_tools_secrets`
- Secret path: `pgadmin`
- Key: `PGADMIN_DEFAULT_PASSWORD`

### 5.2 Retrieve credentials from Vault

For KV v2 (default):

```bash
VAULT_ADDR="https://vault_production_node:8200"
CA_CERT="$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt"
TOKEN="$(cat "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token")"

curl -sS --cacert "$CA_CERT" \
  -H "X-Vault-Token: $TOKEN" \
  "$VAULT_ADDR/v1/app_network_tools_secrets/data/pgadmin" | jq .
```

Example extracting the password only:

```bash
curl -sS --cacert "$CA_CERT" \
  -H "X-Vault-Token: $TOKEN" \
  "$VAULT_ADDR/v1/app_network_tools_secrets/data/pgadmin" | jq -r '.data.data.PGADMIN_DEFAULT_PASSWORD'
```

### 5.3 Use with Docker Compose

When you define the pgAdmin service, you will typically provide:

- `PGADMIN_DEFAULT_EMAIL` (you choose this value; it is not generated by the script)
- `PGADMIN_DEFAULT_PASSWORD` (seeded in Vault, or sourced from the generated env file)

For dev-only usage, you may source the generated env file (see section **4.3**) and reference the environment variables in your compose file.




### 5.4 Startup credential options (choose one)

pgAdmin also does not “pull from Vault” by itself. The common approaches are the same as Postgres:

1) **Baseline (current Compose approach): `.env` / `env_file`**
   - `PGADMIN_DEFAULT_EMAIL` and `PGADMIN_DEFAULT_PASSWORD` are provided via `.env`.

2) **Vault Agent sidecar (recommended when you want Vault dependency at container start)**
   - A Vault Agent container renders the admin password into a file in a shared volume.
   - pgAdmin supports `PGADMIN_DEFAULT_PASSWORD_FILE`, allowing you to source the password from a file (Docker secret / rendered file).
   - See **Section 6** for the full wiring and bootstrapping procedure.

3) **Host “pre-flight” fetch from Vault (simple, but less ideal)**
   - A host script reads the pgAdmin password from Vault and writes it into `.env` immediately before `docker compose up`.

Operational note:
- pgAdmin persists its own internal configuration database. On first startup it initializes the admin account based on the provided variables. If you rotate the password later, treat it like an application credential rotation (update Vault, update the container inputs, and restart).

## 7. Keycloak Vault Integration Bootstrapping

This section mirrors the Postgres/pgAdmin pattern in **6.3** (Vault Agent renders secrets to a shared volume), but adapts it for Keycloak’s configuration model.

Keycloak is **not** expected to talk to Vault directly. Instead:

- A **Vault Agent** container authenticates with **AppRole**, reads KV secrets, and renders a file.
- The **Keycloak container** reads that rendered output at startup (via an entrypoint wrapper script).

### 7.1 Vault KV paths and required keys

This repo assumes KV v2 mounted at `app_network_tools_secrets`, and the following **existing** paths (you confirmed these are the canonical locations):

- `app_network_tools_secrets/keycloak_postgres`  
  Database connection settings for Keycloak (schema/user/password/host/port/database).

- `app_network_tools_secrets/keycloak_bootstrap`  
  Bootstrap admin credentials for first startup (or controlled re-bootstrap).

- `app_network_tools_secrets/keycloak_runtime`  
  Runtime settings such as hostname/proxy mode/listeners/observability flags.

- `app_network_tools_secrets/keycloak_tls`  
  TLS material for Keycloak (server certificate and private key). This repo stores PEM values as **base64 strings** in Vault and decodes them in Vault Agent templates.

For KV v2, the Vault API paths used by the agent include `/data/` (example: `app_network_tools_secrets/data/keycloak_postgres`).

Minimum recommended keys per path:

**A) `app_network_tools_secrets/keycloak_postgres`**

- `KC_DB` (recommended: `postgres`)
- `KC_DB_URL_HOST` (example: `postgres_primary`)
- `KC_DB_URL_PORT` (example: `5432`)
- `KC_DB_URL_DATABASE` (example: `keycloak`)
- `KC_DB_USERNAME` (example: `keycloak`)
- `KC_DB_PASSWORD` (random, high-entropy)
- `KC_DB_SCHEMA` (example: `keycloak`)

**B) `app_network_tools_secrets/keycloak_bootstrap`**

- `KC_BOOTSTRAP_ADMIN_USERNAME` (example: `admin`)
- `KC_BOOTSTRAP_ADMIN_PASSWORD` (random, high-entropy)

**C) `app_network_tools_secrets/keycloak_runtime`** (optional keys; only set what you need)

- `KC_HOSTNAME` (example: `keycloak.yourdomain.edu`)
- `KC_HOSTNAME_STRICT` (`true` or `false`)
- `KC_PROXY_HEADERS` (typical values depend on your L7 proxy; confirm in Keycloak docs)
- `KC_HTTP_ENABLED` (`true` or `false`)
- `KC_HTTPS_PORT` (example: `8443` when exposing 8443)
- `KC_HEALTH_ENABLED` (`true` or `false`)
- `KC_METRICS_ENABLED` (`true` or `false`)
- `KC_LOG_LEVEL` (example: `INFO`)

`keycloak_tls` (TLS material, base64-encoded PEM):

- `KC_HTTPS_CERTIFICATE_PEM_B64` (base64 of the server certificate PEM)
- `KC_HTTPS_CERTIFICATE_KEY_PEM_B64` (base64 of the server private key PEM)

### 7.2 Seeding Keycloak secrets into Vault

You can seed Keycloak secrets either via the repo seeding workflow (recommended), or via direct `vault kv put` commands.

Manual seeding examples (from the host, using `docker exec` into the Vault container):

```bash
# DB config
docker exec -e VAULT_ADDR="https://vault_production_node:8200" \
  -e VAULT_CACERT="/vault/certs/ca.crt" \
  -e VAULT_TOKEN="$(cat ./backend/app/security/configuration_files/vault/bootstrap/root_token)" \
  vault_production_node \
  vault kv put app_network_tools_secrets/keycloak_postgres \
    KC_DB="postgres" \
    KC_DB_URL_HOST="postgres_primary" \
    KC_DB_URL_PORT="5432" \
    KC_DB_URL_DATABASE="keycloak" \
    KC_DB_USERNAME="keycloak" \
    KC_DB_PASSWORD="<REDACTED>" \
    KC_DB_SCHEMA="keycloak"

# Bootstrap admin (treat as sensitive; rotate after first use)
docker exec -e VAULT_ADDR="https://vault_production_node:8200" \
  -e VAULT_CACERT="/vault/certs/ca.crt" \
  -e VAULT_TOKEN="$(cat ./backend/app/security/configuration_files/vault/bootstrap/root_token)" \
  vault_production_node \
  vault kv put app_network_tools_secrets/keycloak_bootstrap \
    KC_BOOTSTRAP_ADMIN_USERNAME="admin" \
    KC_BOOTSTRAP_ADMIN_PASSWORD="<REDACTED>"

# Runtime knobs
docker exec -e VAULT_ADDR="https://vault_production_node:8200" \
  -e VAULT_CACERT="/vault/certs/ca.crt" \
  -e VAULT_TOKEN="$(cat ./backend/app/security/configuration_files/vault/bootstrap/root_token)" \
  vault_production_node \
  vault kv put app_network_tools_secrets/keycloak_runtime \
    KC_HOSTNAME="keycloak.yourdomain.edu" \
    KC_HOSTNAME_STRICT="true" \
    KC_HTTP_ENABLED="false" \
    KC_HTTPS_PORT="8443" \
    KC_HEALTH_ENABLED="true" \
    KC_METRICS_ENABLED="true" \
    KC_LOG_LEVEL="INFO"
```

Validation (KV v2):

```bash
docker exec -e VAULT_ADDR="https://vault_production_node:8200" \
  -e VAULT_CACERT="/vault/certs/ca.crt" \
  -e VAULT_TOKEN="$(cat ./backend/app/security/configuration_files/vault/bootstrap/root_token)" \
  vault_production_node \
  vault kv get -format=json app_network_tools_secrets/keycloak_postgres | jq -r '.data.data'
```


#### 7.2.1 TLS material (local certs → Vault KV)

If you run Keycloak in production mode with HTTPS enabled (`KC_HTTP_ENABLED="false"`), you must provide Keycloak with a certificate and private key.

This repo’s Vault Agent templates expect **base64-encoded PEM** values stored in Vault:

- `KC_HTTPS_CERTIFICATE_PEM_B64`
- `KC_HTTPS_CERTIFICATE_KEY_PEM_B64`

Recommended workflow:

1) Generate local Keycloak TLS material (repo-managed files):

```bash
cd "$HOME/NETWORK_TOOLS"
HERE!
# Generates backend/app/keycloak/certs/{server.crt,server.key,ca.crt}
bash ./backend/build_scripts/generate_local_keycloak_certs.sh
```

```bash
Your file structure should look similar to this now. 

developer_network_tools@networktoolsvm:~/NETWORK_TOOLS$ tree --charset ascii
.
|-- backend
|   |-- app
|   |   |-- keycloak
|   |   |   |-- bin
|   |   |   |   `-- keycloak_entrypoint_from_vault.sh
|   |   |   |-- certs
|   |   |   |   |-- ca.crt
|   |   |   |   |-- ca.key
|   |   |   |   |-- ca.srl
|   |   |   |   |-- cert.crt
|   |   |   |   `-- cert.key
|   |   |   `-- vault_agent
|   |   |       |-- agent.hcl
|   |   |       |-- keycloak_agent_policy.hcl
|   |   |       `-- templates
|   |   |           |-- keycloak.env.ctmpl
|   |   |           |-- keycloak_tls.crt.ctmpl
|   |   |           `-- keycloak_tls.key.ctmpl
|   |   |-- mariadb_queries
|   |   |-- postgres
|   |   |   |-- certs
|   |   |   |   |-- ca.crt
|   |   |   |   |-- ca.key
|   |   |   |   |-- ca.srl
|   |   |   |   |-- cert.crt
|   |   |   |   `-- cert.key
|   |   |   |-- config
|   |   |   |   |-- pg_hba.conf
|   |   |   |   `-- postgres.conf
|   |   |   `-- vault_agent
|   |   |       |-- agent.hcl
|   |   |       `-- templates
|   |   |           |-- pgadmin_password.ctmpl
|   |   |           |-- postgres_db.ctmpl
|   |   |           |-- postgres_password.ctmpl
|   |   |           `-- postgres_user.ctmpl
|   |   |-- routers
|   |   `-- security
|   |       `-- configuration_files
|   |           `-- vault
|   |               |-- bootstrap
|   |               |   |-- postgres_pgadmin_credentials.json
|   |               |   |-- postgres_pgadmin.env
|   |               |   |-- root_token
|   |               |   |-- root_token.json
|   |               |   |-- seeded_secrets_all.json
|   |               |   |-- seed_kv_spec.postgres_pgadmin.json
|   |               |   `-- unseal_keys.json
|   |               |-- certs
|   |               |   |-- ca.crt
|   |               |   |-- ca.key
|   |               |   |-- ca.srl
|   |               |   |-- cert.crt
|   |               |   `-- cert.key
|   |               |-- config
|   |               |   |-- certs
|   |               |   |-- keycloak_kv_read.hcl
|   |               |   |-- postgres_pgadmin_kv_read.hcl
|   |               |   `-- vault_configuration_primary_node.hcl
|   |               `-- Dockerfile
|   |-- build_scripts
|   |   |-- generate_local_keycloak_certs.sh
|   |   |-- generate_local_postgres_certs.sh
|   |   |-- generate_local_vault_certs.sh
|   |   |-- generate_postgres_pgadmin_bootstrap_creds_and_seed.sh
|   |   |-- guides
|   |   |   |-- seed_kv_spec.example.json
|   |   |   `-- seed_kv_spec.GUIDE.md
|   |   |-- keycloak_approle_setup.sh
|   |   |-- postgress_approle_setup.sh
|   |   |-- startover_scripts
|   |   |   `-- reset_network_tools_docker.sh
|   |   |-- vault_first_time_init_only_rootless.sh
|   |   |-- vault_unseal_kv_seed_bootstrap_rootless.sh
|   |   `-- vault_unseal_multi_kv_seed_bootstrap_rootless.sh
|   `-- nginx
|-- container_data
|   `-- vault
|       |-- approle
|       |   `-- postgres_pgadmin_agent
|       `-- data
|           |-- logs
|           |   `-- audit.log
|           |-- raft
|           |   |-- raft.db
|           |   `-- snapshots
|           `-- vault.db
|-- docker-compose.prod.yml
|-- environment_variable_guide.md
|-- frontend
|-- how_to_videos
|   |-- HOW_TO_3.2 Validate Certificates.mov
|   |-- HOW_TO_3.3 Start Vault with Docker Compose.mov
|   |-- HOW_TO_3.6 Initialize and Unseal Vault (First Run).mov
|   |-- HOW_TO_3.8.3 Single-Mount Seeder (vault_unseal_kv_seed_bootstrap_rootless.sh).mov
|   `-- HOW_TO_3.8.4 Multi-Mount Seeder (vault_unseal_multi_kv_seed_bootstrap_rootless.sh).mov
|-- README.full.md
`-- README.md
```
2) Seed those files into Vault (encode as base64 to preserve newlines safely):

```bash
cd "$HOME/NETWORK_TOOLS"

CERT_B64="$(base64 -w0 ./backend/app/keycloak/certs/server.crt)"
KEY_B64="$(base64 -w0 ./backend/app/keycloak/certs/server.key)"

docker exec -e VAULT_ADDR="https://vault_production_node:8200"   -e VAULT_CACERT="/vault/certs/ca.crt"   -e VAULT_TOKEN="$(cat ./backend/app/security/configuration_files/vault/bootstrap/root_token)"   vault_production_node   vault kv put app_network_tools_secrets/keycloak_tls     KC_HTTPS_CERTIFICATE_PEM_B64="$CERT_B64"     KC_HTTPS_CERTIFICATE_KEY_PEM_B64="$KEY_B64"
```

3) Verify:

```bash
docker exec -e VAULT_ADDR="https://vault_production_node:8200"   -e VAULT_CACERT="/vault/certs/ca.crt"   -e VAULT_TOKEN="$(cat ./backend/app/security/configuration_files/vault/bootstrap/root_token)"   vault_production_node   vault kv get app_network_tools_secrets/keycloak_tls
```

Vault Agent will decode and render:

- `/run/vault/tls/server.crt`
- `/run/vault/tls/server.key`



### 7.3 Vault Agent sidecar for Keycloak

The Keycloak Vault Agent follows the same primitives as Postgres/pgAdmin:

1) Least-privilege policy
2) AppRole bound to that policy
3) Host-side export of `role_id` + `secret_id`
4) Agent renders `/run/vault/keycloak.env` (mounted as a shared volume)

#### 7.3.1 Create a least-privilege Vault policy

Create a dedicated policy (example name: `keycloak_agent`) that grants **read-only** access to the three KV paths:

```hcl
# keycloak_agent_policy.hcl
path "auth/token/lookup-self" { capabilities = ["read"] }
path "auth/token/renew-self"  { capabilities = ["update"] }

path "app_network_tools_secrets/data/keycloak_postgres"   { capabilities = ["read"] }
path "app_network_tools_secrets/data/keycloak_bootstrap" { capabilities = ["read"] }
path "app_network_tools_secrets/data/keycloak_runtime"   { capabilities = ["read"] }

# Optional metadata access for troubleshooting
path "app_network_tools_secrets/metadata/keycloak_postgres"   { capabilities = ["list","read"] }
path "app_network_tools_secrets/metadata/keycloak_bootstrap" { capabilities = ["list","read"] }
path "app_network_tools_secrets/metadata/keycloak_runtime"   { capabilities = ["list","read"] }
```

Apply it:

```bash
docker exec -e VAULT_ADDR="https://vault_production_node:8200" \
  -e VAULT_CACERT="/vault/certs/ca.crt" \
  -e VAULT_TOKEN="$(cat ./backend/app/security/configuration_files/vault/bootstrap/root_token)" \
  vault_production_node \
  vault policy write keycloak_agent /vault/policies/keycloak_agent_policy.hcl
```

#### 7.3.2 Create an AppRole for the Keycloak agent

```bash
docker exec -e VAULT_ADDR="https://vault_production_node:8200" \
  -e VAULT_CACERT="/vault/certs/ca.crt" \
  -e VAULT_TOKEN="$(cat ./backend/app/security/configuration_files/vault/bootstrap/root_token)" \
  vault_production_node \
  vault write auth/approle/role/keycloak_agent \
    token_policies="keycloak_agent" \
    token_ttl="20m" token_max_ttl="60m" \
    secret_id_ttl="24h" secret_id_num_uses=1
```

#### 7.3.3 Host-side export script (role_id + secret_id)

Standardize on the same host artifact pattern used elsewhere:

- Host directory: `./container_data/vault/approle/keycloak_agent/`
- Files:
  - `role_id`
  - `secret_id`

Recommended: use the repo script:

```bash
bash ./backend/build_scripts/keycloak_approle_setup.sh \
  --ca-cert "./backend/app/security/configuration_files/vault/certs/ca.crt"
```

```bash
|-- backend
|   |-- app
|   |   |-- keycloak
|   |   |   |-- bin
|   |   |   |   `-- keycloak_entrypoint_from_vault.sh
|   |   |   |-- certs
|   |   |   |   |-- ca.crt
|   |   |   |   |-- ca.key
|   |   |   |   |-- ca.srl
|   |   |   |   |-- cert.crt
|   |   |   |   `-- cert.key
|   |   |   `-- vault_agent
|   |   |       |-- agent.hcl
|   |   |       |-- keycloak_agent_policy.hcl
|   |   |       `-- templates
|   |   |           |-- keycloak.env.ctmpl
|   |   |           |-- keycloak_tls.crt.ctmpl
|   |   |           `-- keycloak_tls.key.ctmpl
|   |   |-- mariadb_queries
|   |   |-- postgres
|   |   |   |-- certs
|   |   |   |   |-- ca.crt
|   |   |   |   |-- ca.key
|   |   |   |   |-- ca.srl
|   |   |   |   |-- cert.crt
|   |   |   |   `-- cert.key
|   |   |   |-- config
|   |   |   |   |-- pg_hba.conf
|   |   |   |   `-- postgres.conf
|   |   |   `-- vault_agent
|   |   |       |-- agent.hcl
|   |   |       `-- templates
|   |   |           |-- pgadmin_password.ctmpl
|   |   |           |-- postgres_db.ctmpl
|   |   |           |-- postgres_password.ctmpl
|   |   |           `-- postgres_user.ctmpl
|   |   |-- routers
|   |   `-- security
|   |       `-- configuration_files
|   |           `-- vault
|   |               |-- bootstrap
|   |               |   |-- postgres_pgadmin_credentials.json
|   |               |   |-- postgres_pgadmin.env
|   |               |   |-- root_token
|   |               |   |-- root_token.json
|   |               |   |-- seeded_secrets_all.json
|   |               |   |-- seed_kv_spec.postgres_pgadmin.json
|   |               |   `-- unseal_keys.json
|   |               |-- certs
|   |               |   |-- ca.crt
|   |               |   |-- ca.key
|   |               |   |-- ca.srl
|   |               |   |-- cert.crt
|   |               |   `-- cert.key
|   |               |-- config
|   |               |   |-- certs
|   |               |   |-- keycloak_kv_read.hcl
|   |               |   |-- postgres_pgadmin_kv_read.hcl
|   |               |   `-- vault_configuration_primary_node.hcl
|   |               `-- Dockerfile
|   |-- build_scripts
|   |   |-- generate_local_keycloak_certs.sh
|   |   |-- generate_local_postgres_certs.sh
|   |   |-- generate_local_vault_certs.sh
|   |   |-- generate_postgres_pgadmin_bootstrap_creds_and_seed.sh
|   |   |-- guides
|   |   |   |-- seed_kv_spec.example.json
|   |   |   `-- seed_kv_spec.GUIDE.md
|   |   |-- keycloak_approle_setup.sh
|   |   |-- postgress_approle_setup.sh
|   |   |-- startover_scripts
|   |   |   `-- reset_network_tools_docker.sh
|   |   |-- vault_first_time_init_only_rootless.sh
|   |   |-- vault_unseal_kv_seed_bootstrap_rootless.sh
|   |   `-- vault_unseal_multi_kv_seed_bootstrap_rootless.sh
|   `-- nginx
|-- container_data
|   `-- vault
|       |-- approle
|       |   |-- keycloak_agent
|       |   |   |-- role_id <-- NEW
|       |   |   `-- secret_id <-- NEW
|       |   `-- postgres_pgadmin_agent
|       `-- data
|           |-- logs
|           |   `-- audit.log
|           |-- raft
|           |   |-- raft.db
|           |   `-- snapshots
|           `-- vault.db
|-- docker-compose.prod.yml
|-- environment_variable_guide.md
|-- frontend
|-- how_to_videos
|   |-- HOW_TO_3.2 Validate Certificates.mov
|   |-- HOW_TO_3.3 Start Vault with Docker Compose.mov
|   |-- HOW_TO_3.6 Initialize and Unseal Vault (First Run).mov
|   |-- HOW_TO_3.8.3 Single-Mount Seeder (vault_unseal_kv_seed_bootstrap_rootless.sh).mov
|   `-- HOW_TO_3.8.4 Multi-Mount Seeder (vault_unseal_multi_kv_seed_bootstrap_rootless.sh).mov
|-- README.full.md
`-- README.md
```

Validate the files:

```bash
ls -lah ./container_data/vault/approle/keycloak_agent
sed -n "1,2p" ./container_data/vault/approle/keycloak_agent/role_id
sed -n "1,2p" ./container_data/vault/approle/keycloak_agent/secret_id
```

#### 7.3.4 Vault Agent config + template

Recommended directory layout:

```
backend/app/keycloak/vault_agent/
  agent.hcl
  templates/
    keycloak.env.ctmpl
```

Key guidance based on observed failures:

- Vault Agent templates do **not** support Sprig’s `default` function. Use `or`, `if`, and `with`.
- Avoid `%!q(<nil>)` output by guarding optional values (only emit lines when keys exist).
- Prefer the token sink under `/tmp` (tmpfs) to avoid `/run/vault` directory issues.

Template destination:

- Agent writes: `/vault/rendered/keycloak.env`
- Keycloak container mounts the same volume at: `/run/vault/keycloak.env`

#### 7.3.5 Docker Compose wiring

High-level compose requirements:

- A named volume (example): `keycloak_vault_rendered`
- `vault_agent_keycloak` mounts it at `/vault/rendered`
- `keycloak` mounts it read-only at `/run/vault`

A minimal (representative) pattern:

```yaml
volumes:
  keycloak_vault_rendered:

services:
  vault_agent_keycloak:
    image: hashicorp/vault:1.21.1
    container_name: vault_agent_keycloak
    restart: unless-stopped
    depends_on:
      - vault_production_node
    entrypoint: ["/bin/sh","-lc","exec vault agent -config=/vault/agent/agent.hcl" ]
    read_only: true
    tmpfs:
      - /tmp
      - /run
    volumes:
      - ./backend/app/security/configuration_files/vault/certs/ca.crt:/vault/ca/ca.crt:ro
      - ./backend/app/keycloak/vault_agent/agent.hcl:/vault/agent/agent.hcl:ro
      - ./backend/app/keycloak/vault_agent/templates:/vault/templates:ro
      - ./container_data/vault/approle/keycloak_agent:/vault/approle:ro
      - keycloak_vault_rendered:/vault/rendered
    healthcheck:
      test: ["CMD-SHELL","test -s /vault/rendered/keycloak.env" ]
      interval: 5s
      timeout: 3s
      retries: 30

  keycloak:
    # Pin a specific stable version (do not use :latest)
    image: quay.io/keycloak/keycloak:<PINNED_VERSION>
    container_name: keycloak
    restart: unless-stopped
    depends_on:
      vault_agent_keycloak:
        condition: service_healthy
      postgres_primary:
        condition: service_started
    volumes:
      - keycloak_vault_rendered:/run/vault:ro
      - ./backend/app/keycloak/scripts/keycloak_entrypoint_from_vault.sh:/opt/keycloak/bin/keycloak_entrypoint_from_vault.sh:ro
    entrypoint: ["/bin/bash","/opt/keycloak/bin/keycloak_entrypoint_from_vault.sh"]
    command: ["start","--optimized"]
```

#### 7.3.6 Bring-up and verification

1) Ensure Vault is initialized/unsealed and seeded.

2) Ensure the Keycloak AppRole artifacts exist (see **7.3.3**).

3) Start the agent and confirm it is healthy:

```bash
docker compose -f docker-compose.prod.yml up -d vault_agent_keycloak
docker logs --tail 200 -f vault_agent_keycloak
docker exec -it vault_agent_keycloak sh -lc 'ls -lah /vault/rendered && echo "----" && sed -n "1,40p" /vault/rendered/keycloak.env'
```

4) Start Keycloak:

```bash
docker compose -f docker-compose.prod.yml up -d keycloak
docker logs --tail 200 -f keycloak
```

#### 7.3.7 Troubleshooting

**A) Agent log: `vault.read(...): no secret exists at app_network_tools_secrets/data/keycloak_runtime`**

- Cause: the KV path has not been seeded (or you seeded a different mount/path).
- Confirm with KV v2 aware command:

```bash
docker exec -e VAULT_ADDR="https://vault_production_node:8200" \
  -e VAULT_CACERT="/vault/certs/ca.crt" \
  -e VAULT_TOKEN="$(cat ./backend/app/security/configuration_files/vault/bootstrap/root_token)" \
  vault_production_node \
  vault kv get app_network_tools_secrets/keycloak_runtime
```

**B) Agent log: `parse: template: ... function "default" not defined`**

- Fix: remove `default` usage; use `or` / `if` / `with`.

**C) Rendered env shows `%!q(<nil>)`**

- Cause: template is calling `printf "%q"` on a missing key.
- Fix: guard optional keys and only emit the line if the key exists and is non-empty.

**D) Agent log: `error creating file sink ... /run/vault/.vault-token.tmp... no such file or directory`**

- Fix: change sink path to `/tmp/.vault-token` (with `tmpfs: ["/tmp"]`), or create the directory before starting the agent.

**E) Agent log: `no known role ID`**

- Cause: `/vault/approle/role_id` is missing or empty.
- Fix: confirm the mount, then regenerate artifacts by re-running **7.3.3**.


**F) Agent log: `error creating file sink: could not parse 'mode' as integer`**

- Cause: `mode` was provided as a string (quoted) or as a symbolic mode (example: `-r--------`). Vault Agent expects an **integer** file mode.
- Fix: use an unquoted numeric value (example: `mode = 0400`) in the sink stanza.

**G) Agent log: `template: :3: function "fail" not defined`**

- Cause: Vault Agent templating does not expose a `fail` function in the function set you are using.
- Fix: remove `fail` calls and instead guard keys with `if` checks. Rely on the agent healthcheck (or application start checks) to catch missing required values.

**H) Rendered env file header is glued to the first variable (example: `#---KC_DB="postgres"`), and Keycloak reports `KC_DB` missing**

- Cause: the template does not emit a newline after the header comment block.
- Fix: ensure there is a real newline after the header so the first exported variable starts on its own line, then restart the Vault Agent container.

**I) Keycloak container logs: `/opt/keycloak/bin/kc: No such file or directory`**

- Cause: modern Keycloak images ship the CLI as `kc.sh`, not `kc`.
- Fix: call `/opt/keycloak/bin/kc.sh` from your entrypoint script.

**J) Keycloak logs: `FATAL: password authentication failed for user "keycloak"`**

- Cause: the `keycloak` role exists in Postgres but the password in the cluster does not match the password stored in Vault (or the role/database is missing).
- Fix: run the Postgres “apply/sync” step (see **4.5**). This aligns Postgres roles/databases with Vault and is the required step whenever you rotate credentials.


#### 7.3.8 Rotation and operational notes

- **Bootstrap admin credentials:** treat `KC_BOOTSTRAP_ADMIN_*` as a bootstrap mechanism. After initial admin setup, rotate and/or restrict access to the `keycloak_bootstrap` secret.
- **Database password rotation:** rotating `KC_DB_PASSWORD` requires updating Postgres (ALTER ROLE/USER) and then updating the Vault secret; coordinate controlled restarts.
- **AppRole Secret IDs:** if you enforce `secret_id_num_uses=1`, regeneration is expected. Re-run **7.3.3** to mint a new `secret_id` after redeployments.

### 7.4 Keycloak hardening notes

Practical hardening items that typically apply cleanly in this deployment model:

- Pin Keycloak image version and treat upgrades as change-controlled.
- Run Keycloak as a non-root user (the upstream image defaults to non-root; keep it that way).
- Set `security_opt: ["no-new-privileges:true"]` and drop Linux capabilities (`cap_drop: ["ALL"]`) unless you have a measured need.
- Restrict published ports (prefer internal networking + reverse proxy / load balancer when available).
- Keep the Vault Agent container read-only, with `tmpfs` for `/tmp` and a dedicated secrets-render volume for `/vault/rendered`.

## Appendix A — Troubleshooting / Gotchas

This appendix consolidates common failures and recovery steps.

## 8. Lessons learned and common issues

This section captures the operational issues encountered during the Vault + Postgres + Keycloak integration and the “why” behind each fix.

### 8.1 Vault Agent sidecar gotchas

- **Do you need a token sink file?**  
  Not always. If Vault Agent’s only job is to render templates (env files, certs) into a shared volume, it can keep the token in memory and you can omit exposing a token to other containers.  
  Use a **file sink** when another process must read the token (for example, an application that talks directly to Vault). If you do use a file sink:
  - keep the sink path in `tmpfs` (example: `/run` or `/tmp`),
  - do not mount the token file into other containers unless necessary,
  - restrict permissions (`mode = 0400`) and confirm the directory exists before agent start.

- **`/run/vault` must exist** if you use it as a sink or render destination. `tmpfs: ["/run"]` does not automatically create `/run/vault`.

### 8.2 Template and rendering pitfalls

- **Avoid `fail` in templates.** Guard missing keys with `if` checks and let healthchecks/startup checks catch missing required values.
- **Prefer base64 for PEM blobs** stored in Vault KV. It avoids newline/escaping issues and makes templates deterministic (decode at render time).
- **Watch for newline issues** in generated env files. One missing newline can invalidate the entire first variable and cause “missing env” failures (as you saw with `KC_DB`).

### 8.3 Container entrypoint and permissions pitfalls

- **Bind-mounted scripts must be executable.** If your container entrypoint is a bind-mounted script, the executable bit must be set on the host (`chmod +x ...`) or you will get `permission denied`.
- **Keycloak CLI path:** for Keycloak 17+ (Quarkus-based images), use `/opt/keycloak/bin/kc.sh`, not `kc`.

### 8.4 Postgres credential drift and how to fix it

The most common root cause of “password authentication failed” during bring-up is **credential drift**:

- Vault KV contains one password.
- Postgres role password is different (or the role/database does not exist).
- Keycloak (or another service) reads the Vault-rendered password and fails to authenticate.

Fix pattern:

1) Treat Vault as the source of truth.
2) Run the apply/sync workflow (**4.5**) to align the running Postgres cluster with Vault values.
3) Restart the dependent service (Keycloak, pgAdmin, app backends).

## Appendix B — Additional How-Tos

This appendix contains supporting reference material that is useful in production but not part of the primary bring-up flow.

### B.1 Legacy preface + original table of contents (reference)

```text
This block is preserved for reference from the original README.full.md.
```

# Ubuntu ARM Development Server – NETWORK_TOOLS Setup

This document describes how to prepare a fresh **Ubuntu ARM** server (running in your preferred VM platform) as a development platform for the **NETWORK_TOOLS** ecosystem.

Initial focus:

- Rootless Docker for running these services under a non-privileged account
- Basic system preparation
- Fixing a common slow `sudo` issue
- Creating a dedicated development user and code root
- Setting up SSH keys
- Hardening SSH access (while keeping a safe fallback
- postgres
- HashiCorp Vault
- Keycloak

Later, this server will host:

- FastAPI applications



---

## Table of Contents



- [0. Repository File Structure](#0-repository-file-structure)
- [0.1 Vault AppRole Authentication (Role ID and Secret ID)](#01-vault-approle-authentication-role-id-and-secret-id)
  - [0.1.1 Validate that an AppRole exists and retrieve the Role ID](#011-validate-that-an-approle-exists-and-retrieve-the-role-id)
  - [0.1.2 Generate a new Secret ID](#012-generate-a-new-secret-id)
  - [0.1.3 Optional validation of the Role ID and Secret ID pair](#013-optional-validation-of-the-role-id-and-secret-id-pair)
- [0.2 Conventions (recommended environment variables)](#02-conventions-recommended-environment-variables)
  - [0.2.1 Recommended host-side variables (run once per shell session)](#021-recommended-host-side-variables-run-once-per-shell-session)
  - [0.2.2 Container-side notes (Vault CLI via `docker exec`)](#022-container-side-notes-vault-cli-via-docker-exec)
- [1. System Preparation](#1-system-preparation)
  - [1.1 Assumptions](#11-assumptions)
  - [1.2 Update the Operating System](#12-update-the-operating-system)
  - [1.3 Address Slow `sudo` Response (Optional)](#13-address-slow-sudo-response-optional)
  - [1.4 Create a Dedicated Development User and Code Root](#14-create-a-dedicated-development-user-and-code-root)
    - [1.4.1 Create the `developer_network_tools` User](#141-create-the-developer_network_tools-user)
    - [1.4.2 Create the `NETWORK_TOOLS` Code Root](#142-create-the-network_tools-code-root)
    - [1.4.3 Verify the Setup from the Development User](#143-verify-the-setup-from-the-development-user)
  - [1.5 SSH Key Setup and Hardening](#15-ssh-key-setup-and-hardening)
    - [1.5.1 Generate an SSH Key Pair on the Developer Machine](#151-generate-an-ssh-key-pair-on-the-developer-machine)
    - [1.5.2 Install the SSH Key for the Administrative User](#152-install-the-ssh-key-for-the-administrative-user)
    - [1.5.3 Install the SSH Key for `developer_network_tools`](#153-install-the-ssh-key-for-developer_network_tools)
    - [1.5.4 Harden the SSH Server Configuration](#154-harden-the-ssh-server-configuration)
    - [1.5.5 Verify Access and Fallback Plan](#155-verify-access-and-fallback-plan)
- [2. Rootless Docker Install](#2-rootless-docker-install)
  - [2.1 Install Docker Engine Packages](#21-install-docker-engine-packages)
  - [2.2 Install Rootless Prerequisites](#22-install-rootless-prerequisites)
  - [2.3 Configure Subordinate UID/GID Ranges](#23-configure-subordinate-uidgid-ranges)
  - [2.4 Disable Rootful Docker Daemon (Recommended)](#24-disable-rootful-docker-daemon-recommended)
  - [2.5 Install and Start Rootless Docker](#25-install-and-start-rootless-docker)
  - [2.6 Enable Rootless Docker at Boot](#26-enable-rootless-docker-at-boot)
  - [2.7 Configure Shell Environment](#27-configure-shell-environment)
  - [2.8 Validate Rootless Docker](#28-validate-rootless-docker)
  - [2.9 Rootless Notes and Troubleshooting](#29-rootless-notes-and-troubleshooting)
- [3. Vault Bring-up](#3-vault-bring-up)
  - [3.1 Generate TLS Certificates](#31-generate-tls-certificates)
  - [3.2 Validate Certificates](#32-validate-certificates)
  - [3.3 Start Vault with Docker Compose](#33-start-vault-with-docker-compose)
  - [3.4 Confirm Vault is Reachable](#34-confirm-vault-is-reachable)
  - [3.5 Vault Bring-up Troubleshooting](#35-vault-bring-up-troubleshooting)
  - [3.6 Initialize and Unseal Vault (First Run)](#36-initialize-and-unseal-vault-first-run)
    - [3.6.1 Run the Init + Unseal Script](#361-run-the-init--unseal-script)
    - [3.6.2 Bootstrap Artifacts (Download Then Remove)](#362-bootstrap-artifacts-download-then-remove)
  - [3.7 TLS Certificate Trust and Best Practices](#37-tls-certificate-trust-and-best-practices)
    - [3.7.1 Local Development (Self-Signed CA)](#371-local-development-self-signed-ca)
    - [3.7.2 Production Environments (Recommended)](#372-production-environments-recommended)
    - [3.7.3 Practical Guidance for This Repo](#373-practical-guidance-for-this-repo)
  - [3.8 Vault Unseal and KV Seeding Bootstrap Scripts](#38-vault-unseal-and-kv-seeding-bootstrap-scripts)
    - [3.8.1 Overview (Which Script to Use)](#381-overview-which-script-to-use)
    - [3.8.2 Unseal-Only Usage](#382-unseal-only-usage)
    - [3.8.3 Single-Mount Seeder (vault_unseal_kv_seed_bootstrap_rootless.sh)](#383-single-mount-seeder-vault_unseal_kv_seed_bootstrap_rootlesssh)
    - [3.8.4 Multi-Mount Seeder (vault_unseal_multi_kv_seed_bootstrap_rootless.sh)](#384-multi-mount-seeder-vault_unseal_multi_kv_seed_bootstrap_rootlesssh)
    - [3.8.5 Seed Input Formats](#385-seed-input-formats)
    - [3.8.6 Multi Spec JSON Schema](#386-multi-spec-json-schema)
    - [3.8.7 Example Seed Files](#387-example-seed-files)
    - [3.8.8 Output, Artifact Storage, and Security Notes](#388-output-artifact-storage-and-security-notes)
    - [3.8.9 Troubleshooting](#389-troubleshooting)
    - [3.8.10 Spec Format Notes, Validation Checks, and Common Pitfalls (Updated)](#3810-spec-format-notes-validation-checks-and-common-pitfalls-updated)
    - [3.8.11 Updated Multi-Mount Spec Example (Preferred)](#3811-updated-multi-mount-spec-example-preferred)
    - [3.8.12 Legacy Spec Example (mounts + writes)](#3812-legacy-spec-example-mounts--writes)
    - [3.8.13 About `"generate": { ... }` Values](#3813-about-generate----values)
- [4. postgres](#4-postgres)
  - [4.1 Bootstrap credentials (generate + seed)](#41-bootstrap-credentials-generate--seed)
  - [4.2 Retrieve credentials from Vault](#42-retrieve-credentials-from-vault)
  - [4.3 Use with Docker Compose](#43-use-with-docker-compose)
    - [4.3.1 Compose prerequisites](#431-compose-prerequisites)
    - [4.3.2 Initialize the Postgres certs volume](#432-initialize-the-postgres-certs-volume)
    - [4.3.3 Start postgres_primary](#433-start-postgres_primary)
    - [4.3.4 Verify and connect](#434-verify-and-connect)
    - [4.3.5 Troubleshooting](#435-troubleshooting)
  - [4.4 Startup credential options (choose one)](#44-startup-credential-options-choose-one)
  - [4.5 Apply Vault credentials to an existing Postgres cluster](#45-apply-vault-credentials-to-an-existing-postgres-cluster)
  - [4.6 Rotation runbook (static credentials)](#46-rotation-runbook-static-credentials)
- [5. pgAdmin](#5-pgadmin)
  - [5.1 Bootstrap credentials (generate + seed)](#51-bootstrap-credentials-generate--seed)
  - [5.2 Retrieve credentials from Vault](#52-retrieve-credentials-from-vault)
  - [5.3 Use with Docker Compose](#53-use-with-docker-compose)
  - [5.4 Startup credential options (choose one)](#54-startup-credential-options-choose-one)
- [6. Postgres and pgAdmin Vault Integration Bootstrapping](#6-postgres-and-pgadmin-vault-integration-bootstrapping)
  - [6.1 Overview and constraints](#61-overview-and-constraints)
  - [6.2 Option A – Keep env file (.env) as the runtime source of truth](#62-option-a--keep-env-file-env-as-the-runtime-source-of-truth)
    - [When to use this option](#when-to-use-this-option)
    - [Steps](#steps)
  - [6.3 Option B – Vault Agent sidecar renders file-based secrets at container start](#63-option-b--vault-agent-sidecar-renders-file-based-secrets-at-container-start)
    - [High-level flow](#high-level-flow)
  - [6.3.1 Create a least-privilege Vault policy](#631-create-a-least-privilege-vault-policy)
  - [6.3.2 Create an AppRole for the agent](#632-create-an-approle-for-the-agent)
  - [6.3.3 Host-side export script (role_id + secret_id)](#633-host-side-export-script-role_id--secret_id)
    - [6.3.3.1 Recommended: use the repo script (docker exec into Vault container)](#6331-recommended-use-the-repo-script-docker-exec-into-vault-container)
    - [6.3.3.2 Manual commands (fully expanded; no script)](#6332-manual-commands-fully-expanded-no-script)
  - [6.3.4 Vault Agent config + templates](#634-vault-agent-config--templates)
  - [6.3.5 Docker Compose wiring (vault-agent + shared secrets volume)](#635-docker-compose-wiring-vault-agent--shared-secrets-volume)
  - [6.3.6 Bring-up and verification](#636-bring-up-and-verification)
    - [6.3.6.1 Current bring-up commands (Approach 2: single compose file)](#6361-current-bring-up-commands-approach-2-single-compose-file)
    - [6.3.6.2 Troubleshooting: common Vault Agent errors](#6362-troubleshooting-common-vault-agent-errors)
  - [6.3.7 Rotation and operational notes](#637-rotation-and-operational-notes)
  - [6.4 Option C – Advanced: Vault Database secrets engine (dynamic credentials)](#64-option-c--advanced-vault-database-secrets-engine-dynamic-credentials)
    - [6.4.1 What this enables (and what it is *not*)](#641-what-this-enables-and-what-it-is-not)
    - [6.4.2 Prerequisites](#642-prerequisites)
    - [6.4.3 Create a dedicated Postgres management role for Vault](#643-create-a-dedicated-postgres-management-role-for-vault)
    - [6.4.4 Enable and configure Vault’s PostgreSQL database connection](#644-enable-and-configure-vaults-postgresql-database-connection)
    - [6.4.5 Create a Vault role that defines how dynamic users are created](#645-create-a-vault-role-that-defines-how-dynamic-users-are-created)
    - [6.4.6 Fetch credentials and validate](#646-fetch-credentials-and-validate)
    - [6.4.7 Rotation (future-facing)](#647-rotation-future-facing)
- [7. Keycloak Vault Integration Bootstrapping](#7-keycloak-vault-integration-bootstrapping)
  - [7.1 Vault KV paths and required keys](#71-vault-kv-paths-and-required-keys)
  - [7.2 Seeding Keycloak secrets into Vault](#72-seeding-keycloak-secrets-into-vault)
  - [7.3 Vault Agent sidecar for Keycloak](#73-vault-agent-sidecar-for-keycloak)
    - [7.3.1 Create a least-privilege Vault policy](#731-create-a-least-privilege-vault-policy)
    - [7.3.2 Create an AppRole for the Keycloak agent](#732-create-an-approle-for-the-keycloak-agent)
    - [7.3.3 Host-side export script (role_id + secret_id)](#733-host-side-export-script-role_id--secret_id)
    - [7.3.4 Vault Agent config + template](#734-vault-agent-config--template)
    - [7.3.5 Docker Compose wiring](#735-docker-compose-wiring)
    - [7.3.6 Bring-up and verification](#736-bring-up-and-verification)
    - [7.3.7 Troubleshooting](#737-troubleshooting)
    - [7.3.8 Rotation and operational notes](#738-rotation-and-operational-notes)
  - [7.4 Keycloak hardening notes](#74-keycloak-hardening-notes)

- [Appendix A – Certificate Management](#appendix-a--certificate-management)
  - [A.1 Vault TLS Certificates – What to Keep and Where](#a1-vault-tls-certificates--what-to-keep-and-where)
    - [1. Files That Must Be Treated as Secrets](#1-files-that-must-be-treated-as-secrets)
    - [2. Files That Can Be Safely Distributed](#2-files-that-can-be-safely-distributed)
    - [3. Recommended Project Layout and Git Hygiene](#3-recommended-project-layout-and-git-hygiene)
    - [4. Minimal “Must-Keep” List](#4-minimal-must-keep-list)
- [A.2 Rootless Docker and Subordinate UID/GID Ranges (subuid/subgid)](#a2-rootless-docker-and-subordinate-uidgid-ranges-subuidsubgid)
- [What are UID/GID ranges?](#what-are-uidgid-ranges)
- [Why “at least 65,536”?](#why-at-least-65536)
- [How to check your current ranges](#how-to-check-your-current-ranges)
- [How to set the ranges (Ubuntu)](#how-to-set-the-ranges-ubuntu)
- [Common symptoms when this is missing or wrong](#common-symptoms-when-this-is-missing-or-wrong)
- [Appendix B – Container Hardening Recommendations (Vault / Vault Agent / Postgres / pgAdmin)](#appendix-b--container-hardening-recommendations-vault--vault-agent--postgres--pgadmin)
  - [B.1 Network and port exposure](#b1-network-and-port-exposure)
  - [B.2 Drop privileges, reduce Linux capabilities, and prevent privilege escalation](#b2-drop-privileges-reduce-linux-capabilities-and-prevent-privilege-escalation)
  - [B.3 Read-only root filesystem + tmpfs](#b3-read-only-root-filesystem--tmpfs)
  - [B.4 Tighten service dependencies to avoid accidental Vault restarts](#b4-tighten-service-dependencies-to-avoid-accidental-vault-restarts)
  - [B.5 Secrets hygiene](#b5-secrets-hygiene)
  - [B.6 Image pinning and update discipline](#b6-image-pinning-and-update-discipline)
  - [B.7 Vault-specific hardening (forward-looking)](#b7-vault-specific-hardening-forward-looking)



- [8. Lessons learned and common issues](#8-lessons-learned-and-common-issues)
  - [8.1 Vault Agent sidecar gotchas](#81-vault-agent-sidecar-gotchas)
  - [8.2 Template and rendering pitfalls](#82-template-and-rendering-pitfalls)
  - [8.3 Container entrypoint and permissions pitfalls](#83-container-entrypoint-and-permissions-pitfalls)
  - [8.4 Postgres credential drift and how to fix it](#84-postgres-credential-drift-and-how-to-fix-it)
---

### B.2 Server/host preparation (reference; not the primary focus for production)

## 1. System Preparation

### 1.1 Assumptions

- Ubuntu Server **22.04 LTS** or **24.04 LTS**, ARM build.
- The server is running in a VM (e.g., VMware Fusion, Proxmox, ESXi, etc.).
- You have SSH access as a user with `sudo` privileges (or as `root` initially).
- You intend to:
  - Use a **non-root user** for day-to-day work and development.
  - Restrict SSH to **key-based authentication**.
  - Run **rootless Docker** under a dedicated development account.
  - Host **postgres**, **Vault**, and **Keycloak** in containers later.

> **Note:** For commands prefixed with `sudo`, run them from your normal user.  
> If you are logged in as `root`, you can omit `sudo`.

---

### 1.2 Update the Operating System

Update package metadata and upgrade all installed packages:

```bash
sudo apt update
sudo apt install -y openssl
sudo apt full-upgrade -y
```

A reboot is recommended after major upgrades, especially if a new kernel or critical libraries are installed:

```bash
sudo reboot
```

Log back in and continue with the steps below.

---

### 1.3 Address Slow `sudo` Response (Optional)

On some installations, `sudo` can appear noticeably slow. 
A common cause is a hostname resolution problem (the system tries to reverse-lookup its own hostname and times out).

You can mitigate this by ensuring the server’s hostname resolves quickly via `/etc/hosts`.

1. Check the current hostname:

   ```bash
   hostname
   ```

   Example output:

   ```text
   networktoolsvm
   ```

2. Inspect `/etc/hosts`:

   ```bash
   sudo cat /etc/hosts
   ```

   Example of a problematic configuration:

   ```text
   127.0.0.1   localhost
   127.0.1.1   network_tools_vm   # DOES NOT match the actual hostname "networktoolsvm"
   # The following lines are desirable for IPv6 capable hosts
   ::1     ip6-localhost ip6-loopback
   fe00::0 ip6-localnet
   ff00::0 ip6-mcastprefix
   ff02::1 ip6-allnodes
   ff02::2 ip6-allrouters
   ```

3. Ensure your hostname appears on a `127.x.x.x` line. For example, if the hostname is `networktoolsvm`, you can adjust the file to:

   ```text
   127.0.0.1   localhost networktoolsvm
   127.0.1.1   network_tools_vm
   ```

4. Edit `/etc/hosts`:

   ```bash
   sudo nano /etc/hosts
   ```

   Apply the appropriate changes for your environment and save.

5. Retry a `sudo` command:

   ```bash
   sudo true
   ```

   If the hostname was the issue, `sudo` should feel more responsive after this change.

---

### 1.4 Create a Dedicated Development User and Code Root

To keep application development, containers, and 
code ownership cleanly separated from your admin account, 
create a dedicated non-root user. This user will later run **rootless Docker** and 
own all of the **NETWORK_TOOLS** source code.

#### 1.4.1 Create the `developer_network_tools` User

Log in as an existing sudo-capable user (e.g., the account created during installation) and run:

```bash
sudo adduser developer_network_tools
```

Follow the prompts to set:

- A password for the new user.
- Optional full name and contact details (press Enter to accept defaults if you prefer).

This account is intentionally created **without** `sudo` privileges to reduce risk. You will continue using your primary admin user for system-level configuration and package management.

> **Optional:** If you later decide that `developer_network_tools` needs `sudo` access, you can run:
>
> ```bash
> sudo usermod -aG sudo developer_network_tools
> ```

#### 1.4.2 Create the `NETWORK_TOOLS` Code Root

All application code and related repositories will live under a single directory owned by the development user:

```text
/home/developer_network_tools/NETWORK_TOOLS
```

Create this directory and ensure it is owned by `developer_network_tools`:

```bash
sudo mkdir -p /home/developer_network_tools/NETWORK_TOOLS
sudo chown -R developer_network_tools:developer_network_tools /home/developer_network_tools/NETWORK_TOOLS
```

This establishes a clear, isolated home for all network tools and services that will be developed and run under this account.

#### 1.4.3 Verify the Setup from the Development User

Switch to the `developer_network_tools` account and confirm the directory layout:

```bash
sudo -iu developer_network_tools
pwd        # Expect: /home/developer_network_tools
ls         # Expect: NETWORK_TOOLS
cd NETWORK_TOOLS
pwd        # Expect: /home/developer_network_tools/NETWORK_TOOLS
```

At this point:

- The `developer_network_tools` user exists and can log in.
- The `NETWORK_TOOLS` directory is ready to hold all application repositories and configuration.
- This user will later be used to run rootless Docker and associated development services.

---

### 1.5 SSH Key Setup and Hardening

This section covers:

- Generating an SSH key pair on a **developer machine**.
- Installing that key for both:
  - Your **administrative user** (the one with `sudo`).
  - The **`developer_network_tools`** user.
- Hardening the SSH server configuration to require key-based auth and disallow direct root logins.

> **Terminology:**
> - **Developer machine**: The workstation or laptop you will use to connect to the server (e.g., macOS or Linux desktop).
> - **Server**: The Ubuntu VM or host you are configuring.

#### 1.5.1 Generate an SSH Key Pair on the Developer Machine

On your **developer machine** (not on the server):

1. Open a terminal and generate an Ed25519 SSH key:

   ```bash
   ssh-keygen -t ed25519 -C "developer_network_tools@ubuntu-dev"
   ```

2. When prompted:
   - Accept the default file location (`~/.ssh/id_ed25519`) or choose a custom name.
   - Set a passphrase for the key (recommended).

This creates two files on the developer machine:

- `~/.ssh/id_ed25519` (private key – **keep this safe**).
- `~/.ssh/id_ed25519.pub` (public key – safe to copy to servers).

#### 1.5.2 Install the SSH Key for the Administrative User

First, configure key-based access for your existing administrative user (e.g., `your_name`). 
This ensures you always have a way to log in with `sudo` privileges.

On your **developer machine**:

```bash
ssh-copy-id -i ~/.ssh/id_ed25519.pub <USER>@<SERVER_HOSTNAME_OR_IP>
```

Replace `<USER>` and `<SERVER_HOSTNAME_OR_IP>` with your actual admin username and server address.

If `ssh-copy-id` is not available, you can manually copy the public key:

1. On the developer machine:

   ```bash
   cat ~/.ssh/id_ed25519.pub
   ```

2. On the server, as the admin user:

   ```bash
    mkdir -p ~/.ssh
    chmod 700 ~/.ssh                   # directory permissions
    nano ~/.ssh/authorized_keys
    chmod 600 ~/.ssh/authorized_keys   # file permissions
   ```

   Paste the public key line, save, then:

   ```bash
   chmod 600 ~/.ssh/authorized_keys
   ```

Test login from the developer machine:

```bash
ssh <USER>@<SERVER_HOSTNAME_OR_IP>
```

You should be prompted for the **key passphrase** (if you set one), 
but not for the server account password.

#### 1.5.3 Install the SSH Key for `developer_network_tools`

Repeat the process for the `developer_network_tools` 
account so you can log in directly as the development user.

From the **developer machine**:

```bash
ssh-copy-id -i ~/.ssh/id_ed25519.pub developer_network_tools@<SERVER_HOSTNAME_OR_IP>
```

Again, if you need to do this manually:

1. On the developer machine:

   ```bash
   cat ~/.ssh/id_ed25519.pub
   ```

2. On the server, as an admin user:

   ```bash
   sudo -iu developer_network_tools
   mkdir -p ~/.ssh
   chmod 700 ~/.ssh
   nano ~/.ssh/authorized_keys
   ```

   Paste the public key line, save, then:

   ```bash
   chmod 600 ~/.ssh/authorized_keys
   ```

Test login from the developer machine:

```bash
ssh developer_network_tools@<SERVER_HOSTNAME_OR_IP>
```

You should now have key-based access to both:

- `<USER>@<SERVER_HOSTNAME_OR_IP>` (or your chosen admin user)
- `developer_network_tools@<SERVER_HOSTNAME_OR_IP>`

**NOTE:** If key-based SSH does not automatically select the correct identity, explicitly set it in your SSH client config.

Example (`~/.ssh/config` on Linux/macOS):

```text
Host network_tools network_tools.local
  HostName network_tools.local
  User developer_network_tools
  IdentityFile ~/.ssh/id_ed25519
  IdentitiesOnly yes
```

Replace the `Host` alias and `HostName` to match your environment (for example, if you mapped your VM name in `/etc/hosts`).


#### 1.5.4 Harden the SSH Server Configuration

Once key-based access is confirmed for at least one administrative user, you can safely harden SSH.

On the **server**, edit or create a dedicated SSH configuration snippet:

```bash
sudo nano /etc/ssh/sshd_config.d/99-hardening.conf
```

Add the following:

```text
# Disable SSH password authentication; require keys
PasswordAuthentication no

# Disallow direct root login
PermitRootLogin no

# Ensure public key auth is enabled
PubkeyAuthentication yes

# Optional: reduce attack surface slightly
ChallengeResponseAuthentication no
UsePAM yes
```

Save the file, then reload the SSH daemon:

```bash
sudo systemctl reload ssh
```

> **Important:** Do **not** close your existing SSH session until you have verified that you can open a new session with the hardened settings.

#### 1.5.5 Verify Access and Fallback Plan

From your **developer machine**, verify:

1. You can still log in as the admin user:

   ```bash
   ssh <USER>@<SERVER_HOSTNAME_OR_IP>
   ```

2. You can still log in as the development user:

   ```bash
   ssh developer_network_tools@<SERVER_HOSTNAME_OR_IP>
   ```

3. Attempting to log in with only a password (no key) should now fail, confirming that password authentication is disabled.

If something goes wrong (e.g., you cannot log in with SSH keys):

- Use an existing open SSH session (if still available) to revert changes in `/etc/ssh/sshd_config.d/99-hardening.conf`, **or**
- Use the VM/console access provided by your hypervisor or cloud platform to log in directly and adjust the SSH configuration.

Once verified, SSH is now:

- Key-only (no password logins).
- Root logins disabled.
- Ready for you to continue with additional hardening and service deployment (Docker, databases, Vault, and Keycloak configuration in subsequent sections).

---

## 2. Rootless Docker Install

This section installs **Docker Engine** and configures it in **rootless mode** so containers run under the dedicated
`developer_network_tools` account (recommended for development and for running services without granting root-level Docker access).

### 2.1 Install Docker Engine Packages

> Run these commands as your **admin (sudo-capable) user**.

1. (Optional) Remove conflicting packages that may be present from older installs:

   ```bash
   sudo apt remove -y docker.io docker-doc docker-compose podman-docker containerd runc || true
   ```

2. Install prerequisites and add Docker’s official APT repository:

   ```bash
   sudo apt update
   sudo apt install -y ca-certificates curl

   sudo install -m 0755 -d /etc/apt/keyrings
   sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
   sudo chmod a+r /etc/apt/keyrings/docker.asc

   sudo tee /etc/apt/sources.list.d/docker.sources >/dev/null <<'EOF'
   Types: deb
   URIs: https://download.docker.com/linux/ubuntu
   Suites: $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")
   Components: stable
   Signed-By: /etc/apt/keyrings/docker.asc
   EOF

   sudo apt update
   ```

3. Install Docker Engine + CLI + container runtime + Buildx + Compose plugin:

   ```bash
   sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
   ```

### 2.2 Install Rootless Prerequisites

> Run these commands as your **admin (sudo-capable) user**.

Install the packages required for rootless Docker:

```bash
sudo apt install -y uidmap docker-ce-rootless-extras
```

Recommended (rootless networking + storage helpers):

```bash
sudo apt install -y slirp4netns fuse-overlayfs
```

### 2.3 Configure Subordinate UID/GID Ranges

Rootless Docker relies on subordinate UID/GID ranges. Your user should have at least **65,536** IDs allocated in both files.

> Run these commands as your **admin (sudo-capable) user**.

1. Check current allocations:

   ```bash
   sudo grep '^developer_network_tools:' /etc/subuid || true
   sudo grep '^developer_network_tools:' /etc/subgid || true
   ```

2. If you do not see a line for `developer_network_tools`, add one (choose a range that does not overlap existing entries):

   ```bash
   echo 'developer_network_tools:100000:65536' | sudo tee -a /etc/subuid
   echo 'developer_network_tools:100000:65536' | sudo tee -a /etc/subgid
   ```

3. Re-check:

   ```bash
   sudo grep '^developer_network_tools:' /etc/subuid
   sudo grep '^developer_network_tools:' /etc/subgid
   ```

### 2.4 Disable Rootful Docker Daemon (Recommended)

If you intend to use **rootless Docker only**, disable the system-wide daemon and socket to avoid confusion over which daemon your CLI is talking to.

> Run these commands as your **admin (sudo-capable) user**.

```bash
sudo systemctl disable --now docker.service docker.socket || true
sudo rm -f /var/run/docker.sock || true
```

### 2.5 Install and Start Rootless Docker

> Run these commands as the **developer user**.

1. Switch into the development account:

   ```bash
   sudo -iu developer_network_tools
   ```

2. Install the rootless Docker user-service:

   ```bash
   dockerd-rootless-setuptool.sh install
   ```

3. Start the daemon (user-level systemd service):

   ```bash
   systemctl --user start docker
   systemctl --user status docker --no-pager
   ```

4. Confirm the Docker CLI is using the rootless context:

   ```bash
   docker context ls
   docker context use rootless || true
   docker info | sed -n '1,80p'
   ```

### 2.6 Enable Rootless Docker at Boot

Rootless Docker runs as a **user service**, so to have it start on boot (without an interactive login), enable “linger” for the user.

> Run this command as your **admin (sudo-capable) user**.

```bash
sudo loginctl enable-linger developer_network_tools
```

You can confirm linger status with:

```bash
loginctl show-user developer_network_tools -p Linger
```

### 2.7 Configure Shell Environment

In most cases, the setup tool configures a Docker context so the CLI finds the rootless socket automatically.
If you prefer to pin it explicitly, add `DOCKER_HOST` to the developer user’s shell profile.

> Run these commands as **developer_network_tools**.

```bash
echo 'export DOCKER_HOST=unix:///run/user/$(id -u)/docker.sock' >> ~/.bashrc
source ~/.bashrc
```

### 2.8 Validate Rootless Docker

> Run these commands as **developer_network_tools**.

1. Verify versions:

   ```bash
   docker version
   docker compose version
   ```

2. Run a test container:

   ```bash
   docker run --rm hello-world
   ```

3. Confirm rootless is in effect:

   ```bash
   docker info | grep -i rootless || true
   ```

### 2.9 Rootless Notes and Troubleshooting

**1) Ports below 1024**
- Rootless containers cannot bind privileged ports (e.g., 80/443) by default.
- Use high ports during development (e.g., `8080:80`, `8443:443`).

**2) User namespace restrictions on Ubuntu 24.04+**
- If rootless setup fails with `permission denied` / `operation not permitted` around `unshare` or user namespaces, check:

  ```bash
  cat /proc/sys/user/max_user_namespaces
  cat /proc/sys/kernel/unprivileged_userns_clone 2>/dev/null || true
  sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null || true
  ```

  If your environment restricts unprivileged user namespaces (often via AppArmor policy), rootless Docker will not start until that policy is adjusted.
  Prefer a targeted policy change over disabling protections globally.

**3) Networking expectations**
- Rootless uses user-space networking. Services should be accessed via published ports (`-p` / `ports:` in Compose), not via container IPs.

**4) “Which Docker am I talking to?”**
- If you see `/var/run/docker.sock`, you are talking to **rootful** Docker.
- Rootless uses: `unix:///run/user/<UID>/docker.sock`.

To confirm which socket is active:

```bash
echo "${DOCKER_HOST-<unset>}"
docker context show
docker info | sed -n '1,35p'
```

---

### B.3 Certificate management (reference)

## Appendix A – Certificate Management

### A.1 Vault TLS Certificates – What to Keep and Where

The local Vault TLS setup uses a small script to generate a private CA and a server certificate for the Vault container. The script typically produces the following key files:

- `ca.crt`   – CA certificate (public)
- `ca.key`   – CA private key (**sensitive**)
- `cert.crt` – Vault server certificate (full chain; public)
- `cert.key` – Vault server private key (**sensitive**)

Any intermediate files (CSRs, temporary leaf certs, extfiles, etc.) are treated as ephemeral and can be discarded after a successful run.

#### 1. Files That Must Be Treated as Secrets

These files **must never** be committed to git or shared outside secure channels:

- **`ca.key` (CA private key)**  
  - This is the root of trust for this local CA.  
  - Anyone who obtains this can mint certificates that will be trusted wherever `ca.crt` is trusted.  
  - Keep it only:
    - On your admin machine, or
    - In a designated secure location on the server with restricted permissions.
  - Back it up to encrypted/offline storage (e.g., password manager attachment, encrypted archive, secure USB).
  - If/when you rotate the CA, this is the file you intentionally retire or destroy.

- **`cert.key` (Vault server private key)**  
  - Needed by Vault at runtime but must remain private.  
  - Should only live on the Vault host, under tight permissions (e.g., `chmod 600`).  
  - Never commit this to git. If backed up, treat it as any other secret (encrypted backup, not stored in the repo).

#### 2. Files That Can Be Safely Distributed

These files are public by design and can be shared with clients/services that need to trust Vault:

- **`ca.crt` (CA certificate)**  
  - Public certificate corresponding to `ca.key`.  
  - Clients and tools that need to trust Vault’s TLS certificate import this CA.  
  - It is acceptable to distribute this to any system that should trust Vault.  
  - Even though it is public, it is still recommended to keep it out of the application source tree and treat it as generated data rather than source code.

- **`cert.crt` (Vault server certificate / full chain)**  
  - Contains the Vault server certificate (and usually the CA chain).  
  - No private key material is present.  
  - Safe to inspect, copy, and distribute as needed.  
  - Can be regenerated as long as `ca.key` is available.

#### 3. Recommended Project Layout and Git Hygiene

By default, the script writes certs to a path similar to:

```text
backend/app/security/configuration_files/vault/certs/
```

Recommended practices:

1. **Ignore the cert directory / Other important files in git**

   Add the following to `.gitignore` (from the project root):

   ```gitignore
   # OS-specific junk
    .DS_Store
    Thumbs.db
    
    # Python artifacts
    __pycache__/
    *.py[cod]
    *.pyo
    
    # Virtual environments
    .venv/
    venv/
    
    # Logs
    logs/
    *.log
    
    # Local override files
    .env
    .env.*
    
    # Cert Directory
    backend/app/security/configuration_files/vault/certs/
    
    # JetBrains IDE
    .idea/
    
    # --- TLS private keys (never commit) ---
    *.key
    *.key.pem
    *.p12
    *.pfx
    
    # --- Certificates (optional: ignore if you generate locally) ---
    *.crt
    *.cer
    *.pem
    *.der
    
    # --- Vault bootstrap artifacts (never commit) ---
    **/bootstrap/**
    **/unseal_keys*.json
    **/root_token*
    **/seeded_secrets*.json
    
    # --- CA serial files ---
    *.srl
   ```

   This prevents accidental commits of `ca.key`, `cert.key`, `ca.crt`, or `cert.crt` and any other important files.


2. **Use the cert directory as the runtime mount for Vault**

   - Keep all cert-related files under `backend/app/security/configuration_files/vault/certs/`.
   - Mount that directory into the Vault container (e.g., `/vault/certs`) via `docker-compose`.
   - Recommended permissions on the host:

     ```bash
     chmod 700 backend/app/security/configuration_files/vault/certs
     chmod 600 backend/app/security/configuration_files/vault/certs/ca.key
     chmod 600 backend/app/security/configuration_files/vault/certs/cert.key
     chmod 644 backend/app/security/configuration_files/vault/certs/ca.crt
     chmod 644 backend/app/security/configuration_files/vault/certs/ca.crt
     ```

3. **Perform a one-time secure backup of critical keys**

   After the script runs and Vault is confirmed working, back up at least:

   - `ca.key` (mandatory)
   - `cert.key` (optional, but convenient if you don’t want to reissue)

   Store these backups in encrypted/offline storage (not in the repo, not on shared drives).

#### 4. Minimal “Must-Keep” List

If you are comfortable re-running the script and re-issuing certificates when needed:

- **Absolutely must keep and protect securely:**
  - `ca.key`

- **Should be kept with Vault for runtime and may be backed up:**
  - `cert.key`
  - `ca.crt`
  - `cert.crt`

In short:

- `ca.key` and `cert.key` are **secrets**. Protect them and never commit them.  
- `ca.crt` and `cert.crt` are **public certs**. Safe to distribute, but best kept in a non-versioned `certs/` directory rather than in the source tree.  
- The entire `vault/certs` directory should be treated as generated runtime data and excluded from git.



## A.2 Rootless Docker and Subordinate UID/GID Ranges (subuid/subgid)

Rootless Docker runs containers **without using real root** on the host. Inside a container, processes may think they are running as `root` (UID `0`), but on the host we **must not** grant real root privileges.

Linux solves this using **user namespaces**: container user IDs (UIDs) and group IDs (GIDs) are **mapped** to a block of normal, unprivileged IDs on the host. That block is called your **subordinate UID/GID ranges**.

## What are UID/GID ranges?

- **UID** = user ID (who owns files / runs processes)
- **GID** = group ID (group ownership/permissions)
- **Subordinate range** = a block of IDs your user is allowed to use inside a user namespace

These are configured in:

- `/etc/subuid` (UID ranges)
- `/etc/subgid` (GID ranges)

A typical entry looks like:

```text
developer_network_tools:100000:65536
```

Meaning:

- `developer_network_tools` = the username
- `100000` = starting ID
- `65536` = how many IDs are allocated

This grants a host-side range of:

- `100000` through `165535` (65,536 IDs total)

## Why “at least 65,536”?

Many container images and tooling expect a reasonably large ID space for creating users/groups inside containers. The common default is **65,536** (`2^16`). Smaller ranges can cause unexpected permission errors or failures when containers try to create additional users/groups.

## How to check your current ranges

```bash
whoami
grep "^$(whoami):" /etc/subuid
grep "^$(whoami):" /etc/subgid
```

You should see **one line in each file** for your user, and the last number should be **65536** (or higher).

## How to set the ranges (Ubuntu)

Run as an admin user (or via sudo):

```bash
sudo usermod --add-subuids 100000-165535 --add-subgids 100000-165535 $(whoami)
```

Re-check:

```bash
grep "^$(whoami):" /etc/subuid /etc/subgid
```

Then **log out and log back in** (or reboot) so the session picks up the changes.

## Common symptoms when this is missing or wrong

- Rootless Docker daemon fails to start
- Containers fail to run, or fail on file permission operations
- Bind mounts/volumes create files owned by “weird” numeric IDs (because mappings are broken)

This is expected behavior when user namespace ID mapping is not configured correctly.

### B.4 Container hardening recommendations (reference)

## Appendix B – Container Hardening Recommendations (Vault / Vault Agent / Postgres / pgAdmin)

The current Compose stack is functional and aligned with the “always Vault” goal. The items below are recommended hardening improvements you can apply incrementally.

### B.1 Network and port exposure

- Prefer binding ports to loopback when you only need local access on the host:
  - Vault: `127.0.0.1:8200:8200`
  - pgAdmin: `127.0.0.1:8081:80`
  - Postgres: consider **no host port** in production; use internal Docker networking only.
- Consider isolating admin surfaces (Vault UI, pgAdmin) behind an authenticated reverse proxy (mTLS, SSO) rather than publishing ports broadly.

### B.2 Drop privileges, reduce Linux capabilities, and prevent privilege escalation

Where images support it, add:

```yaml
security_opt:
  - no-new-privileges:true
cap_drop:
  - ALL
```

Notes:
- Vault may require `IPC_LOCK` if you later enable `mlock` (recommended on non-rootless setups). With rootless Docker you often keep `VAULT_DISABLE_MLOCK=true`, but revisit when you move to a hardened runtime.
- Postgres generally does not need extra capabilities.

### B.3 Read-only root filesystem + tmpfs

For services that do not need to write to their root FS, consider:

```yaml
read_only: true
tmpfs:
  - /tmp
  - /run
```

Notes:
- Vault Agent writes to its rendered directory (the named volume). Keep that volume RW for the agent, RO for consumers.
- pgAdmin writes application state under `/var/lib/pgadmin`; ensure that path remains writable (named volume or bind mount).

### B.4 Tighten service dependencies to avoid accidental Vault restarts

- When iterating on leaf services, use:

```bash
docker compose -f docker-compose.prod.yml up -d --no-deps --no-recreate pgadmin
```

- Only use `--force-recreate` when you need new mounts/env changes to take effect.
- Avoid frequent changes to `vault_production_node`’s config/volumes while the cluster is running; any restart returns Vault to **sealed**.

### B.5 Secrets hygiene

- Keep the AppRole export directory `./container_data/vault/approle/postgres_pgadmin_agent/` readable only by the service account that runs rootless Docker (`chmod 700`).
- Mount secrets read-only into consumer containers (`:ro`), as you are doing for `/run/vault`.
- Avoid writing plaintext DB passwords into `.env` for production. Keep `.env` limited to non-secret toggles, hostnames, and emails.

### B.6 Image pinning and update discipline

- Pin images by digest for production (or at least pin minor versions) and create an update cadence.
- Consider scanning images with Trivy/Grype in CI.

### B.7 Vault-specific hardening (forward-looking)

- Prefer auto-unseal (KMS/HSM) for production so Vault can restart without manual unseal.
- Restrict Vault token usage: minimize root-token presence on disk after bootstrap; rely on AppRole and policies.
- Reduce `VAULT_LOG_LEVEL` from `debug` to `info` (or `warn`) outside troubleshooting windows.

## Appendix C — Original README.full.md (verbatim backup)

The full original `README.full.md` content is included below as a safety net to ensure **no content is missing**.

---

# Ubuntu ARM Development Server – NETWORK_TOOLS Setup

This document describes how to prepare a fresh **Ubuntu ARM** server (running in your preferred VM platform) as a development platform for the **NETWORK_TOOLS** ecosystem.

Initial focus:

- Rootless Docker for running these services under a non-privileged account
- Basic system preparation
- Fixing a common slow `sudo` issue
- Creating a dedicated development user and code root
- Setting up SSH keys
- Hardening SSH access (while keeping a safe fallback
- postgres
- HashiCorp Vault
- Keycloak

Later, this server will host:

- FastAPI applications



---

## Table of Contents



- [0. Repository File Structure](#0-repository-file-structure)
- [0.1 Vault AppRole Authentication (Role ID and Secret ID)](#01-vault-approle-authentication-role-id-and-secret-id)
  - [0.1.1 Validate that an AppRole exists and retrieve the Role ID](#011-validate-that-an-approle-exists-and-retrieve-the-role-id)
  - [0.1.2 Generate a new Secret ID](#012-generate-a-new-secret-id)
  - [0.1.3 Optional validation of the Role ID and Secret ID pair](#013-optional-validation-of-the-role-id-and-secret-id-pair)
- [0.2 Conventions (recommended environment variables)](#02-conventions-recommended-environment-variables)
  - [0.2.1 Recommended host-side variables (run once per shell session)](#021-recommended-host-side-variables-run-once-per-shell-session)
  - [0.2.2 Container-side notes (Vault CLI via `docker exec`)](#022-container-side-notes-vault-cli-via-docker-exec)
- [1. System Preparation](#1-system-preparation)
  - [1.1 Assumptions](#11-assumptions)
  - [1.2 Update the Operating System](#12-update-the-operating-system)
  - [1.3 Address Slow `sudo` Response (Optional)](#13-address-slow-sudo-response-optional)
  - [1.4 Create a Dedicated Development User and Code Root](#14-create-a-dedicated-development-user-and-code-root)
    - [1.4.1 Create the `developer_network_tools` User](#141-create-the-developer_network_tools-user)
    - [1.4.2 Create the `NETWORK_TOOLS` Code Root](#142-create-the-network_tools-code-root)
    - [1.4.3 Verify the Setup from the Development User](#143-verify-the-setup-from-the-development-user)
  - [1.5 SSH Key Setup and Hardening](#15-ssh-key-setup-and-hardening)
    - [1.5.1 Generate an SSH Key Pair on the Developer Machine](#151-generate-an-ssh-key-pair-on-the-developer-machine)
    - [1.5.2 Install the SSH Key for the Administrative User](#152-install-the-ssh-key-for-the-administrative-user)
    - [1.5.3 Install the SSH Key for `developer_network_tools`](#153-install-the-ssh-key-for-developer_network_tools)
    - [1.5.4 Harden the SSH Server Configuration](#154-harden-the-ssh-server-configuration)
    - [1.5.5 Verify Access and Fallback Plan](#155-verify-access-and-fallback-plan)
- [2. Rootless Docker Install](#2-rootless-docker-install)
  - [2.1 Install Docker Engine Packages](#21-install-docker-engine-packages)
  - [2.2 Install Rootless Prerequisites](#22-install-rootless-prerequisites)
  - [2.3 Configure Subordinate UID/GID Ranges](#23-configure-subordinate-uidgid-ranges)
  - [2.4 Disable Rootful Docker Daemon (Recommended)](#24-disable-rootful-docker-daemon-recommended)
  - [2.5 Install and Start Rootless Docker](#25-install-and-start-rootless-docker)
  - [2.6 Enable Rootless Docker at Boot](#26-enable-rootless-docker-at-boot)
  - [2.7 Configure Shell Environment](#27-configure-shell-environment)
  - [2.8 Validate Rootless Docker](#28-validate-rootless-docker)
  - [2.9 Rootless Notes and Troubleshooting](#29-rootless-notes-and-troubleshooting)
- [3. Vault Bring-up](#3-vault-bring-up)
  - [3.1 Generate TLS Certificates](#31-generate-tls-certificates)
  - [3.2 Validate Certificates](#32-validate-certificates)
  - [3.3 Start Vault with Docker Compose](#33-start-vault-with-docker-compose)
  - [3.4 Confirm Vault is Reachable](#34-confirm-vault-is-reachable)
  - [3.5 Vault Bring-up Troubleshooting](#35-vault-bring-up-troubleshooting)
  - [3.6 Initialize and Unseal Vault (First Run)](#36-initialize-and-unseal-vault-first-run)
    - [3.6.1 Run the Init + Unseal Script](#361-run-the-init--unseal-script)
    - [3.6.2 Bootstrap Artifacts (Download Then Remove)](#362-bootstrap-artifacts-download-then-remove)
  - [3.7 TLS Certificate Trust and Best Practices](#37-tls-certificate-trust-and-best-practices)
    - [3.7.1 Local Development (Self-Signed CA)](#371-local-development-self-signed-ca)
    - [3.7.2 Production Environments (Recommended)](#372-production-environments-recommended)
    - [3.7.3 Practical Guidance for This Repo](#373-practical-guidance-for-this-repo)
  - [3.8 Vault Unseal and KV Seeding Bootstrap Scripts](#38-vault-unseal-and-kv-seeding-bootstrap-scripts)
    - [3.8.1 Overview (Which Script to Use)](#381-overview-which-script-to-use)
    - [3.8.2 Unseal-Only Usage](#382-unseal-only-usage)
    - [3.8.3 Single-Mount Seeder (vault_unseal_kv_seed_bootstrap_rootless.sh)](#383-single-mount-seeder-vault_unseal_kv_seed_bootstrap_rootlesssh)
    - [3.8.4 Multi-Mount Seeder (vault_unseal_multi_kv_seed_bootstrap_rootless.sh)](#384-multi-mount-seeder-vault_unseal_multi_kv_seed_bootstrap_rootlesssh)
    - [3.8.5 Seed Input Formats](#385-seed-input-formats)
    - [3.8.6 Multi Spec JSON Schema](#386-multi-spec-json-schema)
    - [3.8.7 Example Seed Files](#387-example-seed-files)
    - [3.8.8 Output, Artifact Storage, and Security Notes](#388-output-artifact-storage-and-security-notes)
    - [3.8.9 Troubleshooting](#389-troubleshooting)
    - [3.8.10 Spec Format Notes, Validation Checks, and Common Pitfalls (Updated)](#3810-spec-format-notes-validation-checks-and-common-pitfalls-updated)
    - [3.8.11 Updated Multi-Mount Spec Example (Preferred)](#3811-updated-multi-mount-spec-example-preferred)
    - [3.8.12 Legacy Spec Example (mounts + writes)](#3812-legacy-spec-example-mounts--writes)
    - [3.8.13 About `"generate": { ... }` Values](#3813-about-generate----values)
- [4. postgres](#4-postgres)
  - [4.1 Bootstrap credentials (generate + seed)](#41-bootstrap-credentials-generate--seed)
  - [4.2 Retrieve credentials from Vault](#42-retrieve-credentials-from-vault)
  - [4.3 Use with Docker Compose](#43-use-with-docker-compose)
    - [4.3.1 Compose prerequisites](#431-compose-prerequisites)
    - [4.3.2 Initialize the Postgres certs volume](#432-initialize-the-postgres-certs-volume)
    - [4.3.3 Start postgres_primary](#433-start-postgres_primary)
    - [4.3.4 Verify and connect](#434-verify-and-connect)
    - [4.3.5 Troubleshooting](#435-troubleshooting)
  - [4.4 Startup credential options (choose one)](#44-startup-credential-options-choose-one)
  - [4.5 Apply Vault credentials to an existing Postgres cluster](#45-apply-vault-credentials-to-an-existing-postgres-cluster)
  - [4.6 Rotation runbook (static credentials)](#46-rotation-runbook-static-credentials)
- [5. pgAdmin](#5-pgadmin)
  - [5.1 Bootstrap credentials (generate + seed)](#51-bootstrap-credentials-generate--seed)
  - [5.2 Retrieve credentials from Vault](#52-retrieve-credentials-from-vault)
  - [5.3 Use with Docker Compose](#53-use-with-docker-compose)
  - [5.4 Startup credential options (choose one)](#54-startup-credential-options-choose-one)
- [6. Postgres and pgAdmin Vault Integration Bootstrapping](#6-postgres-and-pgadmin-vault-integration-bootstrapping)
  - [6.1 Overview and constraints](#61-overview-and-constraints)
  - [6.2 Option A – Keep env file (.env) as the runtime source of truth](#62-option-a--keep-env-file-env-as-the-runtime-source-of-truth)
    - [When to use this option](#when-to-use-this-option)
    - [Steps](#steps)
  - [6.3 Option B – Vault Agent sidecar renders file-based secrets at container start](#63-option-b--vault-agent-sidecar-renders-file-based-secrets-at-container-start)
    - [High-level flow](#high-level-flow)
  - [6.3.1 Create a least-privilege Vault policy](#631-create-a-least-privilege-vault-policy)
  - [6.3.2 Create an AppRole for the agent](#632-create-an-approle-for-the-agent)
  - [6.3.3 Host-side export script (role_id + secret_id)](#633-host-side-export-script-role_id--secret_id)
    - [6.3.3.1 Recommended: use the repo script (docker exec into Vault container)](#6331-recommended-use-the-repo-script-docker-exec-into-vault-container)
    - [6.3.3.2 Manual commands (fully expanded; no script)](#6332-manual-commands-fully-expanded-no-script)
  - [6.3.4 Vault Agent config + templates](#634-vault-agent-config--templates)
  - [6.3.5 Docker Compose wiring (vault-agent + shared secrets volume)](#635-docker-compose-wiring-vault-agent--shared-secrets-volume)
  - [6.3.6 Bring-up and verification](#636-bring-up-and-verification)
    - [6.3.6.1 Current bring-up commands (Approach 2: single compose file)](#6361-current-bring-up-commands-approach-2-single-compose-file)
    - [6.3.6.2 Troubleshooting: common Vault Agent errors](#6362-troubleshooting-common-vault-agent-errors)
  - [6.3.7 Rotation and operational notes](#637-rotation-and-operational-notes)
  - [6.4 Option C – Advanced: Vault Database secrets engine (dynamic credentials)](#64-option-c--advanced-vault-database-secrets-engine-dynamic-credentials)
    - [6.4.1 What this enables (and what it is *not*)](#641-what-this-enables-and-what-it-is-not)
    - [6.4.2 Prerequisites](#642-prerequisites)
    - [6.4.3 Create a dedicated Postgres management role for Vault](#643-create-a-dedicated-postgres-management-role-for-vault)
    - [6.4.4 Enable and configure Vault’s PostgreSQL database connection](#644-enable-and-configure-vaults-postgresql-database-connection)
    - [6.4.5 Create a Vault role that defines how dynamic users are created](#645-create-a-vault-role-that-defines-how-dynamic-users-are-created)
    - [6.4.6 Fetch credentials and validate](#646-fetch-credentials-and-validate)
    - [6.4.7 Rotation (future-facing)](#647-rotation-future-facing)
- [7. Keycloak Vault Integration Bootstrapping](#7-keycloak-vault-integration-bootstrapping)
  - [7.1 Vault KV paths and required keys](#71-vault-kv-paths-and-required-keys)
  - [7.2 Seeding Keycloak secrets into Vault](#72-seeding-keycloak-secrets-into-vault)
  - [7.3 Vault Agent sidecar for Keycloak](#73-vault-agent-sidecar-for-keycloak)
    - [7.3.1 Create a least-privilege Vault policy](#731-create-a-least-privilege-vault-policy)
    - [7.3.2 Create an AppRole for the Keycloak agent](#732-create-an-approle-for-the-keycloak-agent)
    - [7.3.3 Host-side export script (role_id + secret_id)](#733-host-side-export-script-role_id--secret_id)
    - [7.3.4 Vault Agent config + template](#734-vault-agent-config--template)
    - [7.3.5 Docker Compose wiring](#735-docker-compose-wiring)
    - [7.3.6 Bring-up and verification](#736-bring-up-and-verification)
    - [7.3.7 Troubleshooting](#737-troubleshooting)
    - [7.3.8 Rotation and operational notes](#738-rotation-and-operational-notes)
  - [7.4 Keycloak hardening notes](#74-keycloak-hardening-notes)

- [Appendix A – Certificate Management](#appendix-a--certificate-management)
  - [A.1 Vault TLS Certificates – What to Keep and Where](#a1-vault-tls-certificates--what-to-keep-and-where)
    - [1. Files That Must Be Treated as Secrets](#1-files-that-must-be-treated-as-secrets)
    - [2. Files That Can Be Safely Distributed](#2-files-that-can-be-safely-distributed)
    - [3. Recommended Project Layout and Git Hygiene](#3-recommended-project-layout-and-git-hygiene)
    - [4. Minimal “Must-Keep” List](#4-minimal-must-keep-list)
- [A.2 Rootless Docker and Subordinate UID/GID Ranges (subuid/subgid)](#a2-rootless-docker-and-subordinate-uidgid-ranges-subuidsubgid)
- [What are UID/GID ranges?](#what-are-uidgid-ranges)
- [Why “at least 65,536”?](#why-at-least-65536)
- [How to check your current ranges](#how-to-check-your-current-ranges)
- [How to set the ranges (Ubuntu)](#how-to-set-the-ranges-ubuntu)
- [Common symptoms when this is missing or wrong](#common-symptoms-when-this-is-missing-or-wrong)
- [Appendix B – Container Hardening Recommendations (Vault / Vault Agent / Postgres / pgAdmin)](#appendix-b--container-hardening-recommendations-vault--vault-agent--postgres--pgadmin)
  - [B.1 Network and port exposure](#b1-network-and-port-exposure)
  - [B.2 Drop privileges, reduce Linux capabilities, and prevent privilege escalation](#b2-drop-privileges-reduce-linux-capabilities-and-prevent-privilege-escalation)
  - [B.3 Read-only root filesystem + tmpfs](#b3-read-only-root-filesystem--tmpfs)
  - [B.4 Tighten service dependencies to avoid accidental Vault restarts](#b4-tighten-service-dependencies-to-avoid-accidental-vault-restarts)
  - [B.5 Secrets hygiene](#b5-secrets-hygiene)
  - [B.6 Image pinning and update discipline](#b6-image-pinning-and-update-discipline)
  - [B.7 Vault-specific hardening (forward-looking)](#b7-vault-specific-hardening-forward-looking)



- [8. Lessons learned and common issues](#8-lessons-learned-and-common-issues)
  - [8.1 Vault Agent sidecar gotchas](#81-vault-agent-sidecar-gotchas)
  - [8.2 Template and rendering pitfalls](#82-template-and-rendering-pitfalls)
  - [8.3 Container entrypoint and permissions pitfalls](#83-container-entrypoint-and-permissions-pitfalls)
  - [8.4 Postgres credential drift and how to fix it](#84-postgres-credential-drift-and-how-to-fix-it)
---

## 0. Repository File Structure

```text
Base Directory Structure - This is what you should start with prior to running any scripts.

developer_network_tools@networktoolsvm:~$ tree NETWORK_TOOLS --charset ascii
NETWORK_TOOLS
|-- backend
|   |-- app
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
|   |   |-- mariadb_queries
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
|   |   |           `-- postgres_user.ctmpl
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
|   |   |-- generate_local_postgres_certs.sh
|   |   |-- generate_local_vault_certs.sh
|   |   |-- generate_postgres_pgadmin_bootstrap_creds_and_seed.sh
|   |   |-- guides
|   |   |   |-- seed_kv_spec.example.json (I haven't decided if i'm keeping these. I need to test them more and possibly rewrite them
|   |   |   `-- seed_kv_spec.GUIDE.md
|   |   |-- keycloak_approle_setup.sh
|   |   |-- postgress_approle_setup.sh
|   |   |-- startover_scripts
|   |   |   `-- reset_network_tools_docker.sh
|   |   |-- vault_first_time_init_only_rootless.sh
|   |   |-- vault_unseal_kv_seed_bootstrap_rootless.sh
|   |   `-- vault_unseal_multi_kv_seed_bootstrap_rootless.sh
|   `-- nginx
|-- docker-compose.prod.yml
|-- environment_variable_guide.md
|-- frontend
|-- how_to_videos (TODO: Add updated how to Videos
|
`-- readme.md

```

---
## 0.1 Vault AppRole Authentication (Role ID and Secret ID)

This project uses Vault **AppRole** auth for non-interactive services (for example, the Postgres/pgAdmin Vault Agent) to obtain a Vault token at runtime.

Key concepts:

- **role_id**: a stable identifier for an AppRole (does not change unless the role is re-created).
- **secret_id**: a credential generated for the AppRole (rotate as often as you want).
- **login**: exchange `role_id + secret_id` for a Vault token via `auth/approle/login`.

When bootstrap scripts create an AppRole, they persist the artifacts on the **host** so other scripts/containers can consume them:

```text
./container_data/vault/approle/<ROLE_NAME>/
  role_id
  secret_id
```

Example (postgres/pgadmin agent):

```text
./container_data/vault/approle/postgres_pgadmin_agent/
  role_id
  secret_id
```

> Important: paths under `$HOME/NETWORK_TOOLS/...` are **host-only** paths.  
> When you run Vault commands via `docker exec`, the Vault CLI runs **inside the container**, where those host paths do not exist.

### 0.1.1 Validate that an AppRole exists and retrieve the Role ID

This repository assumes you **do not** have the Vault CLI installed on the host. Run the Vault CLI **inside the Vault container** using `docker exec`.

#### Recommended (readable): environment variables on the host

```bash
#####################################################################################
# AppRole Role ID (The host OS writes artifacts; Vault CLI runs inside the container)
#####################################################################################

# Host-side paths (exist on the VM host; NOT inside the container)
BOOTSTRAP_DIR="$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap"
ROLE_DIR="$HOME/NETWORK_TOOLS/container_data/vault/approle/postgres_pgadmin_agent"

# Vault container context
VAULT_ADDR="https://vault_production_node:8200"
VAULT_CONTAINER="vault_production_node"
VAULT_CACERT_CONTAINER="/vault/certs/cert.crt"

# Admin token (root token during first-time init)
VAULT_TOKEN="$(cat "$BOOTSTRAP_DIR/root_token")"

mkdir -p "$ROLE_DIR"

# Helper: run Vault CLI inside the Vault container with the right env vars
vaultc() {
  docker exec \
    -e VAULT_ADDR="$VAULT_ADDR" \
    -e VAULT_CACERT="$VAULT_CACERT_CONTAINER" \
    -e VAULT_TOKEN="$VAULT_TOKEN" \
    "$VAULT_CONTAINER" \
    vault "$@"
}

# List AppRoles (optional)
vaultc list auth/approle/role

# Read role_id (human-readable output)
vaultc read auth/approle/role/postgres_pgadmin_agent/role-id

# Persist role_id to host artifact file (JSON parsed on host via jq)
vaultc read -format=json auth/approle/role/postgres_pgadmin_agent/role-id \
  | jq -r '.data.role_id' > "$ROLE_DIR/role_id"

chmod 600 "$ROLE_DIR/role_id"
```

#### Fully expanded (no environment variables)

```bash
ROLE_DIR="$HOME/NETWORK_TOOLS/container_data/vault/approle/postgres_pgadmin_agent"
mkdir -p "$ROLE_DIR"

VAULT_TOKEN="$(cat "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token")"

docker exec \
  -e VAULT_ADDR="https://vault_production_node:8200" \
  -e VAULT_CACERT="/vault/certs/ca.crt" \
  -e VAULT_TOKEN="$VAULT_TOKEN" \
  vault_production_node \
  vault read -format=json auth/approle/role/postgres_pgadmin_agent/role-id \
| jq -r '.data.role_id' > "$ROLE_DIR/role_id"

chmod 600 "$ROLE_DIR/role_id"
```

### 0.1.2 Generate a new Secret ID

Generate a new `secret_id` for the AppRole and persist it to the host artifact directory.

#### Recommended (readable): environment variables on the host

```bash
BOOTSTRAP_DIR="$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap"
ROLE_DIR="$HOME/NETWORK_TOOLS/container_data/vault/approle/postgres_pgadmin_agent"
mkdir -p "$ROLE_DIR"

VAULT_TOKEN="$(cat "$BOOTSTRAP_DIR/root_token")"

docker exec \
  -e VAULT_ADDR="https://vault_production_node:8200" \
  -e VAULT_CACERT="/vault/certs/ca.crt" \
  -e VAULT_TOKEN="$VAULT_TOKEN" \
  vault_production_node \
  vault write -format=json -f auth/approle/role/postgres_pgadmin_agent/secret-id \
| jq -r '.data.secret_id' > "$ROLE_DIR/secret_id"

chmod 600 "$ROLE_DIR/secret_id"

```

#### Fully expanded (no environment variables)

```bash
ROLE_DIR="$HOME/NETWORK_TOOLS/container_data/vault/approle/postgres_pgadmin_agent"
mkdir -p "$ROLE_DIR"

VAULT_ADDR="https://vault_production_node:8200"
VAULT_CONTAINER="vault_production_node"
VAULT_CACERT_CONTAINER="/vault/certs/ca.crt"
VAULT_TOKEN="$(cat "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token")"

vaultc() {
  docker exec \
    -e VAULT_ADDR="$VAULT_ADDR" \
    -e VAULT_CACERT="$VAULT_CACERT_CONTAINER" \
    -e VAULT_TOKEN="$VAULT_TOKEN" \
    "$VAULT_CONTAINER" \
    vault "$@"
}

vaultc write -format=json -f auth/approle/role/postgres_pgadmin_agent/secret-id \
  | jq -r '.data.secret_id' > "$ROLE_DIR/secret_id"

chmod 600 "$ROLE_DIR/secret_id"
```

### 0.1.3 Optional: validate AppRole login

This confirms that `role_id + secret_id` can be exchanged for a token.

```bash
### This can be used if vaultc has already been defined from above. If not skip to the next block ###
ROLE_DIR="$HOME/NETWORK_TOOLS/container_data/vault/approle/postgres_pgadmin_agent"

ROLE_ID="$(cat "$ROLE_DIR/role_id")"
SECRET_ID="$(cat "$ROLE_DIR/secret_id")"

# Assumes VAULT_ADDR / VAULT_CONTAINER / VAULT_CACERT_CONTAINER already set
vaultc write -format=json auth/approle/login \
  role_id="$ROLE_ID" \
  secret_id="$SECRET_ID" \
| jq -r '.auth.client_token'
```

```bash
ROLE_DIR="$HOME/NETWORK_TOOLS/container_data/vault/approle/postgres_pgadmin_agent"

ROLE_ID="$(cat "$ROLE_DIR/role_id")"
SECRET_ID="$(cat "$ROLE_DIR/secret_id")"

docker exec \
  -e VAULT_ADDR="https://vault_production_node:8200" \
  -e VAULT_CACERT="/vault/certs/ca.crt" \
  vault_production_node \
  vault write -format=json auth/approle/login \
    role_id="$ROLE_ID" \
    secret_id="$SECRET_ID" \
| jq -r '.auth.client_token'
```

The returned token will have the policies assigned to the AppRole (for example, `postgres_pgadmin_read`).

## 0.2 Conventions (recommended environment variables)

To keep commands readable, the examples in this README are often provided in two forms:

- **Environment-variable form**: set a few variables once per shell session, then run shorter commands.
- **Fully expanded form**: no environment variables required.

### 0.2.1 Recommended host-side variables (run once per shell session)

```bash
export NT_ROOT="$HOME/NETWORK_TOOLS"
export COMPOSE_FILE="$NT_ROOT/docker-compose.prod.yml"

# Vault endpoint (host-side; used by scripts and curl)
export VAULT_ADDR="https://vault_production_node:8200"
export VAULT_CA_CERT="$NT_ROOT/backend/app/security/configuration_files/vault/certs/ca.crt"

# Bootstrap artifacts (written by the first-time init script)
export VAULT_BOOTSTRAP_DIR="$NT_ROOT/backend/app/security/configuration_files/vault/bootstrap"
export VAULT_ROOT_TOKEN_FILE="$VAULT_BOOTSTRAP_DIR/root_token"

# KV mount that stores the Postgres + pgAdmin credentials
# Repo default: app_network_tools_secrets
# Legacy/typo variant sometimes seen: app_postgress_secrets
export POSTGRES_KV_MOUNT="app_network_tools_secrets"
```

### 0.2.2 Container-side notes (Vault CLI via `docker exec`)

Many setup/validation commands below run the Vault CLI **inside** the Vault container so you do not need to install the Vault CLI on the host.

- Vault container name (repo default): `vault_production_node`
- Container-side CA path (mounted): `/vault/certs/ca.crt`


## 1. System Preparation

### 1.1 Assumptions

- Ubuntu Server **22.04 LTS** or **24.04 LTS**, ARM build.
- The server is running in a VM (e.g., VMware Fusion, Proxmox, ESXi, etc.).
- You have SSH access as a user with `sudo` privileges (or as `root` initially).
- You intend to:
  - Use a **non-root user** for day-to-day work and development.
  - Restrict SSH to **key-based authentication**.
  - Run **rootless Docker** under a dedicated development account.
  - Host **postgres**, **Vault**, and **Keycloak** in containers later.

> **Note:** For commands prefixed with `sudo`, run them from your normal user.  
> If you are logged in as `root`, you can omit `sudo`.

---

### 1.2 Update the Operating System

Update package metadata and upgrade all installed packages:

```bash
sudo apt update
sudo apt install -y openssl
sudo apt full-upgrade -y
```

A reboot is recommended after major upgrades, especially if a new kernel or critical libraries are installed:

```bash
sudo reboot
```

Log back in and continue with the steps below.

---

### 1.3 Address Slow `sudo` Response (Optional)

On some installations, `sudo` can appear noticeably slow. 
A common cause is a hostname resolution problem (the system tries to reverse-lookup its own hostname and times out).

You can mitigate this by ensuring the server’s hostname resolves quickly via `/etc/hosts`.

1. Check the current hostname:

   ```bash
   hostname
   ```

   Example output:

   ```text
   networktoolsvm
   ```

2. Inspect `/etc/hosts`:

   ```bash
   sudo cat /etc/hosts
   ```

   Example of a problematic configuration:

   ```text
   127.0.0.1   localhost
   127.0.1.1   network_tools_vm   # DOES NOT match the actual hostname "networktoolsvm"
   # The following lines are desirable for IPv6 capable hosts
   ::1     ip6-localhost ip6-loopback
   fe00::0 ip6-localnet
   ff00::0 ip6-mcastprefix
   ff02::1 ip6-allnodes
   ff02::2 ip6-allrouters
   ```

3. Ensure your hostname appears on a `127.x.x.x` line. For example, if the hostname is `networktoolsvm`, you can adjust the file to:

   ```text
   127.0.0.1   localhost networktoolsvm
   127.0.1.1   network_tools_vm
   ```

4. Edit `/etc/hosts`:

   ```bash
   sudo nano /etc/hosts
   ```

   Apply the appropriate changes for your environment and save.

5. Retry a `sudo` command:

   ```bash
   sudo true
   ```

   If the hostname was the issue, `sudo` should feel more responsive after this change.

---

### 1.4 Create a Dedicated Development User and Code Root

To keep application development, containers, and 
code ownership cleanly separated from your admin account, 
create a dedicated non-root user. This user will later run **rootless Docker** and 
own all of the **NETWORK_TOOLS** source code.

#### 1.4.1 Create the `developer_network_tools` User

Log in as an existing sudo-capable user (e.g., the account created during installation) and run:

```bash
sudo adduser developer_network_tools
```

Follow the prompts to set:

- A password for the new user.
- Optional full name and contact details (press Enter to accept defaults if you prefer).

This account is intentionally created **without** `sudo` privileges to reduce risk. You will continue using your primary admin user for system-level configuration and package management.

> **Optional:** If you later decide that `developer_network_tools` needs `sudo` access, you can run:
>
> ```bash
> sudo usermod -aG sudo developer_network_tools
> ```

#### 1.4.2 Create the `NETWORK_TOOLS` Code Root

All application code and related repositories will live under a single directory owned by the development user:

```text
/home/developer_network_tools/NETWORK_TOOLS
```

Create this directory and ensure it is owned by `developer_network_tools`:

```bash
sudo mkdir -p /home/developer_network_tools/NETWORK_TOOLS
sudo chown -R developer_network_tools:developer_network_tools /home/developer_network_tools/NETWORK_TOOLS
```

This establishes a clear, isolated home for all network tools and services that will be developed and run under this account.

#### 1.4.3 Verify the Setup from the Development User

Switch to the `developer_network_tools` account and confirm the directory layout:

```bash
sudo -iu developer_network_tools
pwd        # Expect: /home/developer_network_tools
ls         # Expect: NETWORK_TOOLS
cd NETWORK_TOOLS
pwd        # Expect: /home/developer_network_tools/NETWORK_TOOLS
```

At this point:

- The `developer_network_tools` user exists and can log in.
- The `NETWORK_TOOLS` directory is ready to hold all application repositories and configuration.
- This user will later be used to run rootless Docker and associated development services.

---

### 1.5 SSH Key Setup and Hardening

This section covers:

- Generating an SSH key pair on a **developer machine**.
- Installing that key for both:
  - Your **administrative user** (the one with `sudo`).
  - The **`developer_network_tools`** user.
- Hardening the SSH server configuration to require key-based auth and disallow direct root logins.

> **Terminology:**
> - **Developer machine**: The workstation or laptop you will use to connect to the server (e.g., macOS or Linux desktop).
> - **Server**: The Ubuntu VM or host you are configuring.

#### 1.5.1 Generate an SSH Key Pair on the Developer Machine

On your **developer machine** (not on the server):

1. Open a terminal and generate an Ed25519 SSH key:

   ```bash
   ssh-keygen -t ed25519 -C "developer_network_tools@ubuntu-dev"
   ```

2. When prompted:
   - Accept the default file location (`~/.ssh/id_ed25519`) or choose a custom name.
   - Set a passphrase for the key (recommended).

This creates two files on the developer machine:

- `~/.ssh/id_ed25519` (private key – **keep this safe**).
- `~/.ssh/id_ed25519.pub` (public key – safe to copy to servers).

#### 1.5.2 Install the SSH Key for the Administrative User

First, configure key-based access for your existing administrative user (e.g., `your_name`). 
This ensures you always have a way to log in with `sudo` privileges.

On your **developer machine**:

```bash
ssh-copy-id -i ~/.ssh/id_ed25519.pub <USER>@<SERVER_HOSTNAME_OR_IP>
```

Replace `<USER>` and `<SERVER_HOSTNAME_OR_IP>` with your actual admin username and server address.

If `ssh-copy-id` is not available, you can manually copy the public key:

1. On the developer machine:

   ```bash
   cat ~/.ssh/id_ed25519.pub
   ```

2. On the server, as the admin user:

   ```bash
    mkdir -p ~/.ssh
    chmod 700 ~/.ssh                   # directory permissions
    nano ~/.ssh/authorized_keys
    chmod 600 ~/.ssh/authorized_keys   # file permissions
   ```

   Paste the public key line, save, then:

   ```bash
   chmod 600 ~/.ssh/authorized_keys
   ```

Test login from the developer machine:

```bash
ssh <USER>@<SERVER_HOSTNAME_OR_IP>
```

You should be prompted for the **key passphrase** (if you set one), 
but not for the server account password.

#### 1.5.3 Install the SSH Key for `developer_network_tools`

Repeat the process for the `developer_network_tools` 
account so you can log in directly as the development user.

From the **developer machine**:

```bash
ssh-copy-id -i ~/.ssh/id_ed25519.pub developer_network_tools@<SERVER_HOSTNAME_OR_IP>
```

Again, if you need to do this manually:

1. On the developer machine:

   ```bash
   cat ~/.ssh/id_ed25519.pub
   ```

2. On the server, as an admin user:

   ```bash
   sudo -iu developer_network_tools
   mkdir -p ~/.ssh
   chmod 700 ~/.ssh
   nano ~/.ssh/authorized_keys
   ```

   Paste the public key line, save, then:

   ```bash
   chmod 600 ~/.ssh/authorized_keys
   ```

Test login from the developer machine:

```bash
ssh developer_network_tools@<SERVER_HOSTNAME_OR_IP>
```

You should now have key-based access to both:

- `<USER>@<SERVER_HOSTNAME_OR_IP>` (or your chosen admin user)
- `developer_network_tools@<SERVER_HOSTNAME_OR_IP>`

**NOTE:** If key-based SSH does not automatically select the correct identity, explicitly set it in your SSH client config.

Example (`~/.ssh/config` on Linux/macOS):

```text
Host network_tools network_tools.local
  HostName network_tools.local
  User developer_network_tools
  IdentityFile ~/.ssh/id_ed25519
  IdentitiesOnly yes
```

Replace the `Host` alias and `HostName` to match your environment (for example, if you mapped your VM name in `/etc/hosts`).


#### 1.5.4 Harden the SSH Server Configuration

Once key-based access is confirmed for at least one administrative user, you can safely harden SSH.

On the **server**, edit or create a dedicated SSH configuration snippet:

```bash
sudo nano /etc/ssh/sshd_config.d/99-hardening.conf
```

Add the following:

```text
# Disable SSH password authentication; require keys
PasswordAuthentication no

# Disallow direct root login
PermitRootLogin no

# Ensure public key auth is enabled
PubkeyAuthentication yes

# Optional: reduce attack surface slightly
ChallengeResponseAuthentication no
UsePAM yes
```

Save the file, then reload the SSH daemon:

```bash
sudo systemctl reload ssh
```

> **Important:** Do **not** close your existing SSH session until you have verified that you can open a new session with the hardened settings.

#### 1.5.5 Verify Access and Fallback Plan

From your **developer machine**, verify:

1. You can still log in as the admin user:

   ```bash
   ssh <USER>@<SERVER_HOSTNAME_OR_IP>
   ```

2. You can still log in as the development user:

   ```bash
   ssh developer_network_tools@<SERVER_HOSTNAME_OR_IP>
   ```

3. Attempting to log in with only a password (no key) should now fail, confirming that password authentication is disabled.

If something goes wrong (e.g., you cannot log in with SSH keys):

- Use an existing open SSH session (if still available) to revert changes in `/etc/ssh/sshd_config.d/99-hardening.conf`, **or**
- Use the VM/console access provided by your hypervisor or cloud platform to log in directly and adjust the SSH configuration.

Once verified, SSH is now:

- Key-only (no password logins).
- Root logins disabled.
- Ready for you to continue with additional hardening and service deployment (Docker, databases, Vault, and Keycloak configuration in subsequent sections).

---




## 2. Rootless Docker Install

This section installs **Docker Engine** and configures it in **rootless mode** so containers run under the dedicated
`developer_network_tools` account (recommended for development and for running services without granting root-level Docker access).

### 2.1 Install Docker Engine Packages

> Run these commands as your **admin (sudo-capable) user**.

1. (Optional) Remove conflicting packages that may be present from older installs:

   ```bash
   sudo apt remove -y docker.io docker-doc docker-compose podman-docker containerd runc || true
   ```

2. Install prerequisites and add Docker’s official APT repository:

   ```bash
   sudo apt update
   sudo apt install -y ca-certificates curl

   sudo install -m 0755 -d /etc/apt/keyrings
   sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
   sudo chmod a+r /etc/apt/keyrings/docker.asc

   sudo tee /etc/apt/sources.list.d/docker.sources >/dev/null <<'EOF'
   Types: deb
   URIs: https://download.docker.com/linux/ubuntu
   Suites: $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")
   Components: stable
   Signed-By: /etc/apt/keyrings/docker.asc
   EOF

   sudo apt update
   ```

3. Install Docker Engine + CLI + container runtime + Buildx + Compose plugin:

   ```bash
   sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
   ```

### 2.2 Install Rootless Prerequisites

> Run these commands as your **admin (sudo-capable) user**.

Install the packages required for rootless Docker:

```bash
sudo apt install -y uidmap docker-ce-rootless-extras
```

Recommended (rootless networking + storage helpers):

```bash
sudo apt install -y slirp4netns fuse-overlayfs
```

### 2.3 Configure Subordinate UID/GID Ranges

Rootless Docker relies on subordinate UID/GID ranges. Your user should have at least **65,536** IDs allocated in both files.

> Run these commands as your **admin (sudo-capable) user**.

1. Check current allocations:

   ```bash
   sudo grep '^developer_network_tools:' /etc/subuid || true
   sudo grep '^developer_network_tools:' /etc/subgid || true
   ```

2. If you do not see a line for `developer_network_tools`, add one (choose a range that does not overlap existing entries):

   ```bash
   echo 'developer_network_tools:100000:65536' | sudo tee -a /etc/subuid
   echo 'developer_network_tools:100000:65536' | sudo tee -a /etc/subgid
   ```

3. Re-check:

   ```bash
   sudo grep '^developer_network_tools:' /etc/subuid
   sudo grep '^developer_network_tools:' /etc/subgid
   ```

### 2.4 Disable Rootful Docker Daemon (Recommended)

If you intend to use **rootless Docker only**, disable the system-wide daemon and socket to avoid confusion over which daemon your CLI is talking to.

> Run these commands as your **admin (sudo-capable) user**.

```bash
sudo systemctl disable --now docker.service docker.socket || true
sudo rm -f /var/run/docker.sock || true
```

### 2.5 Install and Start Rootless Docker

> Run these commands as the **developer user**.

1. Switch into the development account:

   ```bash
   sudo -iu developer_network_tools
   ```

2. Install the rootless Docker user-service:

   ```bash
   dockerd-rootless-setuptool.sh install
   ```

3. Start the daemon (user-level systemd service):

   ```bash
   systemctl --user start docker
   systemctl --user status docker --no-pager
   ```

4. Confirm the Docker CLI is using the rootless context:

   ```bash
   docker context ls
   docker context use rootless || true
   docker info | sed -n '1,80p'
   ```

### 2.6 Enable Rootless Docker at Boot

Rootless Docker runs as a **user service**, so to have it start on boot (without an interactive login), enable “linger” for the user.

> Run this command as your **admin (sudo-capable) user**.

```bash
sudo loginctl enable-linger developer_network_tools
```

You can confirm linger status with:

```bash
loginctl show-user developer_network_tools -p Linger
```

### 2.7 Configure Shell Environment

In most cases, the setup tool configures a Docker context so the CLI finds the rootless socket automatically.
If you prefer to pin it explicitly, add `DOCKER_HOST` to the developer user’s shell profile.

> Run these commands as **developer_network_tools**.

```bash
echo 'export DOCKER_HOST=unix:///run/user/$(id -u)/docker.sock' >> ~/.bashrc
source ~/.bashrc
```

### 2.8 Validate Rootless Docker

> Run these commands as **developer_network_tools**.

1. Verify versions:

   ```bash
   docker version
   docker compose version
   ```

2. Run a test container:

   ```bash
   docker run --rm hello-world
   ```

3. Confirm rootless is in effect:

   ```bash
   docker info | grep -i rootless || true
   ```

### 2.9 Rootless Notes and Troubleshooting

**1) Ports below 1024**
- Rootless containers cannot bind privileged ports (e.g., 80/443) by default.
- Use high ports during development (e.g., `8080:80`, `8443:443`).

**2) User namespace restrictions on Ubuntu 24.04+**
- If rootless setup fails with `permission denied` / `operation not permitted` around `unshare` or user namespaces, check:

  ```bash
  cat /proc/sys/user/max_user_namespaces
  cat /proc/sys/kernel/unprivileged_userns_clone 2>/dev/null || true
  sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null || true
  ```

  If your environment restricts unprivileged user namespaces (often via AppArmor policy), rootless Docker will not start until that policy is adjusted.
  Prefer a targeted policy change over disabling protections globally.

**3) Networking expectations**
- Rootless uses user-space networking. Services should be accessed via published ports (`-p` / `ports:` in Compose), not via container IPs.

**4) “Which Docker am I talking to?”**
- If you see `/var/run/docker.sock`, you are talking to **rootful** Docker.
- Rootless uses: `unix:///run/user/<UID>/docker.sock`.

To confirm which socket is active:

```bash
echo "${DOCKER_HOST-<unset>}"
docker context show
docker info | sed -n '1,35p'
```

---
## 3. Vault Bring-up

This section documents how to generate local TLS material and start the **Vault** container using
`docker-compose.prod.yml` under **rootless Docker**.

Current target URL (may change later in production):

- `https://vault_production_node:8200`

> Note: For this URL to work from the *host* (browser/curl), the hostname `vault_production_node` must resolve to the host
running Docker (see Section 3.4).

### 3.1 Generate TLS Certificates

> Run the generator as **developer_network_tools** (no sudo).  
> Ensure OpenSSL is installed first (admin user).

1. Install OpenSSL (admin / sudo-capable user):

   ```bash
   sudo apt update
   sudo apt install -y openssl
   ```
<span id="vault-bootstrap-create-local-certs"></span>Run the certificate generator (developer user):

2. Run the certificate generator (developer user):

   ```bash
   cd ~/NETWORK_TOOLS
   chmod +x ./backend/build_scripts/generate_local_vault_certs.sh
   ./backend/build_scripts/generate_local_vault_certs.sh --force
   ```

>#Note: When these are locally generated and not populated from a trusted CA, Your file system will have<br>
>The following files created.

   ```bash
   developer_network_tools@networktoolsvm:~/NETWORK_TOOLS$ tree --charset ascii
    .
    |-- backend
    |   |-- app
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
    |   |   |-- mariadb_queries
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
    |   |   |           `-- postgres_user.ctmpl
    |   |   |-- routers
    |   |   `-- security
    |   |       `-- configuration_files
    |   |           `-- vault
    |   |               |-- certs
    |   |               |   |-- ca.crt <- NEW
    |   |               |   |-- ca.key <- NEW - Can be removed to safe storage
    |   |               |   |-- ca.srl <- NEW - Can be removed to safe storage
    |   |               |   |-- cert.crt <- NEW
    |   |               |   `-- cert.key <- NEW
    |   |               |-- config
    |   |               |   |-- certs
    |   |               |   |-- keycloak_kv_read.hcl
    |   |               |   |-- postgres_pgadmin_kv_read.hcl
    |   |               |   `-- vault_configuration_primary_node.hcl
    |   |               `-- Dockerfile
    |   |-- build_scripts
    |   |   |-- generate_local_keycloak_certs.sh
    |   |   |-- generate_local_postgres_certs.sh
    |   |   |-- generate_local_vault_certs.sh
    |   |   |-- generate_postgres_pgadmin_bootstrap_creds_and_seed.sh
    |   |   |-- guides
    |   |   |   |-- seed_kv_spec.example.json
    |   |   |   `-- seed_kv_spec.GUIDE.md
    |   |   |-- keycloak_approle_setup.sh
    |   |   |-- postgress_approle_setup.sh
    |   |   |-- startover_scripts
    |   |   |   `-- reset_network_tools_docker.sh
    |   |   |-- vault_first_time_init_only_rootless.sh
    |   |   |-- vault_unseal_kv_seed_bootstrap_rootless.sh
    |   |   `-- vault_unseal_multi_kv_seed_bootstrap_rootless.sh
    |   `-- nginx
    |-- docker-compose.prod.yml
    |-- environment_variable_guide.md
    |-- frontend
    |-- how_to_videos
    |   |-- HOW_TO_3.2 Validate Certificates.mov
    |   |-- HOW_TO_3.3 Start Vault with Docker Compose.mov
    |   |-- HOW_TO_3.6 Initialize and Unseal Vault (First Run).mov
    |   |-- HOW_TO_3.8.3 Single-Mount Seeder (vault_unseal_kv_seed_bootstrap_rootless.sh).mov
    |   `-- HOW_TO_3.8.4 Multi-Mount Seeder (vault_unseal_multi_kv_seed_bootstrap_rootless.sh).mov
    |-- README.full.md
    `-- README.md
   ```

3. Confirm expected outputs exist:

   ```bash
   ls -lh ./backend/app/security/configuration_files/vault/certs/
   ```

### 3.2 Validate Certificates

Run these checks on the server:

```bash
CERT_DIR="$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs"
CERT="$CERT_DIR/cert.crt"
KEY="$CERT_DIR/cert.key"
CA="$CERT_DIR/ca.crt"

# Key parses cleanly
openssl pkey -in "$KEY" -check -noout

# Cert metadata
openssl x509 -in "$CERT" -noout -subject -issuer -dates

# Cert matches key (hashes must match)
openssl x509 -noout -modulus -in "$CERT" | openssl sha256
openssl rsa  -noout -modulus -in "$KEY"  | openssl sha256

# SANs include vault_production_node
openssl x509 -in "$CERT" -noout -text | sed -n '/Subject Alternative Name/,+2p'

# Verify leaf chains to CA
LEAF_ONLY="$CERT_DIR/cert.leaf.only.crt"
if [[ -f "$LEAF_ONLY" ]]; then
  openssl verify -CAfile "$CA" "$LEAF_ONLY"
else
  # Best-effort fallback (may fail if CERT is a fullchain)
  openssl verify -CAfile "$CA" "$CERT" || true
fi

See below for the expected output you should see. 
Your output may vary a bit depending on how your server is setup.

(LOCAL CERTIFICATES BEING USED)

Key is valid
subject=CN = vault_production_node
issuer=CN = NETWORK_TOOLS Local Vault CA
notBefore=Jan  1 03:13:33 2026 GMT
notAfter=Apr  5 03:13:33 2028 GMT
SHA2-256(stdin)= 4148080bacac7a147981ef2d6e0608dc135d1685fffb4da16748fbd0300e6193
SHA2-256(stdin)= 4148080bacac7a147981ef2d6e0608dc135d1685fffb4da16748fbd0300e6193
            X509v3 Subject Alternative Name: 
                DNS:vault_production_node, IP Address:172.16.99.130
            X509v3 Subject Key Identifier: 
/home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/cert.crt: OK
developer_network_tools@networktoolsvm:~/NETWORK_TOOLS$ 

```

### 3.3 Start Vault with Docker Compose

> Run these commands as **developer_network_tools**.

1. Confirm your CLI is talking to the **rootless** Docker daemon:

   ```bash
   docker context ls
   docker context use rootless || true
   docker context show
   ```

2. Ensure the local Vault data directories exist (bind mounts):

   ```bash
   cd ~/NETWORK_TOOLS
   mkdir -p ./container_data/vault/data ./container_data/vault/data/logs
   ```

3. Validate the Compose file renders:

   ```bash
   docker compose -f docker-compose.prod.yml config > /tmp/network_tools.compose.rendered.yml
   ```

4. Start Vault (Or use the initial init script to bring up a new vault instance See [3.6.1 Run the Init + Unseal Script](#361-run-the-init--unseal-script)):
   The init script has been updated to call the docker command to bring up the container, and it will setup 
   unseal and setup the initial settings required by the other containers. 
   ```bash
   docker compose -f docker-compose.prod.yml up -d vault_production_node
   ```


5. Follow logs:

   ```bash
   docker compose -f docker-compose.prod.yml logs -f vault_production_node
   ```

### 3.4 Confirm Vault is Reachable

If you are testing from the **same server** running Docker, add a hosts entry so `vault_production_node` resolves locally:

```bash
echo "127.0.0.1 vault_production_node" | sudo tee -a /etc/hosts
```

Then validate TLS from the host:

```bash
CA="$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt"
openssl s_client -connect vault_production_node:8200 -servername vault_production_node -CAfile "$CA" </dev/null
```

And validate HTTP response (Vault may return 503 until initialized/unsealed):

```bash
curl --cacert "$CA" -v https://vault_production_node:8200/v1/sys/health
```

### 3.5 Vault Bring-up Troubleshooting

**1) TLS errors (x509 hostname mismatch)**
- Ensure `vault_production_node` appears under *Subject Alternative Name* (Section 3.2).
- Ensure you are connecting using the same hostname that is present in the SAN list.

**2) “Connection refused” or cannot reach port 8200**
- Confirm the service is running and ports are published:

  ```bash
  docker compose -f docker-compose.prod.yml ps
  ss -lntp | egrep ':8200|:8201' || true
  ```

**3) Permission denied writing under `/vault/data`**
- Confirm `./container_data/vault/data` exists and is writable by your rootless user.
- If still failing, consider adding `user: "0:0"` to the Compose service for Vault (still rootless on the host).

---


### 3.6 Initialize and Unseal Vault (First Run)

This step is required **one time** for a brand-new Vault instance. It will:

- Start the Vault container with Docker Compose (rootless; no sudo)
- Initialize Vault (generates unseal keys + root token)
- Unseal Vault

> **Security note:** The init artifacts (unseal keys + root token) are highly sensitive. This script will save them to disk and (by default) print some contents to the terminal. Treat the output like production secrets.

#### 3.6.1 Run the Init + Unseal Script

> Run these commands as **developer_network_tools** (no sudo).

This script is intended for a **first-time** Vault bring-up. It will:

- Start Vault (optional; if you already started the container, it will reuse it)
- Initialize Vault (`vault operator init`)
- Unseal Vault using the configured threshold
- Enable the file audit device (if configured)
- **Create required ACL policy + AppRole for Postgres/pgAdmin** (first-run convenience; enabled by default in this repo)

1) Ensure Vault is running (skip if already up):

```bash
cd "$HOME/NETWORK_TOOLS"
docker compose -p network_tools -f docker-compose.prod.yml up -d vault_production_node
```

2) Ensure the script is executable:

```bash
cd "$HOME/NETWORK_TOOLS"
chmod +x ./backend/build_scripts/vault_first_time_init_only_rootless.sh
```

3) Run the script (recommended: pass the local CA and make init parameters explicit).

Environment-variable form:

```bash
cd "$HOME/NETWORK_TOOLS"
bash ./backend/build_scripts/vault_first_time_init_only_rootless.sh \
  --vault-addr "https://vault_production_node:8200" \
  --ca-cert "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt" \
  --init-shares 5 --init-threshold 3
```

Fully expanded form:

```bash
cd "$HOME/NETWORK_TOOLS"
bash ./backend/build_scripts/vault_first_time_init_only_rootless.sh \
  --vault-addr "https://vault_production_node:8200" \
  --ca-cert "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt" \
  --init-shares 5 \
  --init-threshold 3
```

Expected output from the vault init script below for comparison.

```bash
developer_network_tools@networktoolsvm:~/NETWORK_TOOLS$ cd "$HOME/NETWORK_TOOLS"
bash ./backend/build_scripts/vault_first_time_init_only_rootless.sh \
  --vault-addr "https://vault_production_node:8200" \
  --ca-cert "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt" \
  --init-shares 5 \
  --init-threshold 3
INFO: Starting Vault container: docker compose -p network_tools -f /home/developer_network_tools/NETWORK_TOOLS/docker-compose.prod.yml up -d vault_production_node
[+] up 2/2
 ✔ Network network_tools_default   Created                                                                                                                                                                                       0.0s 
 ✔ Container vault_production_node Created                                                                                                                                                                                       0.1s 
INFO: Waiting for Vault endpoint: https://vault_production_node:8200
INFO: Vault not initialized; initializing (shares=5, threshold=3)…
INFO: Init complete. Wrote (0600):
INFO:   Unseal keys JSON     : /home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/unseal_keys.json
INFO:   Root token (plain)   : /home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token
INFO:   Root token (JSON)    : /home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token.json
INFO: Unsealing Vault using 3 key(s)…
INFO: Vault unsealed.
INFO: Enabling file audit device at path 'file/' -> /vault/logs/audit.log
INFO: Audit device enabled successfully.
INFO: Ensured ACL policy: postgres_pgadmin_read
INFO: Enabled auth method: approle/
INFO: Ensured AppRole role: postgres_pgadmin_agent (policy: postgres_pgadmin_read)

============================================================
VAULT BOOTSTRAP ARTIFACTS (SENSITIVE) - DOWNLOAD THEN REMOVE
============================================================
Bootstrap directory:
  /home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap

Files written/used by this script:
  - /home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/unseal_keys.json  (exists; perms/owner: 600 developer_network_tools:developer_network_tools)
  - /home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token  (exists; perms/owner: 600 developer_network_tools:developer_network_tools)
  - /home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token.json  (exists; perms/owner: 600 developer_network_tools:developer_network_tools)

IMPORTANT:
  - This script is configured to print key/token JSON contents to the terminal by default.
    Use --no-print-artifact-contents to suppress that output.
  1) Download these files to a secure location (password manager / offline vault / secure storage).
  2) Do NOT commit these files to Git.
  3) After you have securely stored them, delete them from this server.

Example download (from your workstation):
  scp -p <user>@<server>:'/home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/unseal_keys.json' .
  scp -p <user>@<server>:'/home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token' .
  scp -p <user>@<server>:'/home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token.json' .

Example removal (run on this server AFTER downloading):
  rm -f '/home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/unseal_keys.json' '/home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token' '/home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token.json'

If you want a stronger delete (optional; not always effective on all storage):
  shred -u '/home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/unseal_keys.json' '/home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token' '/home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token.json'


============================================================
BOOTSTRAP FILE CONTENTS (HIGHLY SENSITIVE) - TERMINAL OUTPUT
============================================================
WARNING: The contents below include unseal keys and root token.
Do NOT paste this output into tickets, chat, or logs.
============================================================

----- /home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/unseal_keys.json -----
{
  "keys": [
    "6a25353dc991c0d743a1bb5f0d11f11fb4e6f9a65646c093a4e46e2aca78db6ed9",
    "436e62004ddfcfbe69ee60de5f7275d04bf4caa95bae89435d4501273817c3a48b",
    "3514f5c6e49850bdd1f3f9b885af60207756a79aab245b6ca5138ba51e84c024a8",
    "95accca297de7f6fd9d545845eb33ca5ba371a9e34b724ff75719cabfb5e368786",
    "13e27fd7fc783143a6d6c19d990949a6c7ef0d456d261cfcd046c75c065f63c338"
  ],
  "keys_base64": [
    "aiU1PcmRwNdDobtfDRHxH7Tm+aZWRsCTpORuKsp4227Z",
    "Q25iAE3fz75p7mDeX3J10Ev0yqlbrolDXUUBJzgXw6SL",
    "NRT1xuSYUL3R8/m4ha9gIHdWp5qrJFtspROLpR6EwCSo",
    "lazMopfef2/Z1UWEXrM8pbo3Gp40tyT/dXGcq/teNoeG",
    "E+J/1/x4MUOm1sGdmQlJpsfvDUVtJhz80EbHXAZfY8M4"
  ],
  "root_token": "hvs.zeGCweGZR0du66ONKG32enpy"
}

----- /home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token.json -----
{
  "root_token": "hvs.zeGCweGZR0du66ONKG32enpy"
}

{
  "vault_addr": "https://vault_production_node:8200",
  "compose": {
    "project": "network_tools",
    "file": "/home/developer_network_tools/NETWORK_TOOLS/docker-compose.prod.yml",
    "service": "vault_production_node"
  },
  "bootstrap_dir": "/home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap",
  "files": {
    "unseal_keys_json": "/home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/unseal_keys.json",
    "root_token": "/home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token",
    "root_token_json": "/home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token.json"
  },
  "pretty_output": true,
  "postgres_pgadmin_approle_bootstrap": {
    "enabled": true,
    "force": false,
    "setup_done": true,
    "role_name": "postgres_pgadmin_agent",
    "policy_name": "postgres_pgadmin_read"
  },
  "print_artifact_contents": true,
  "audit": {
    "enabled": true,
    "path": "file",
    "file_path": "/vault/logs/audit.log"
  },
  "initialized": true,
  "unsealed": true
}
```



4) If you omit `--ca-cert`, the script will:

- Try the system trust store first (no `-k`)
- If that fails, retry with `-k` and print a warning with the TLS verification error

```bash
bash ./backend/build_scripts/vault_first_time_init_only_rootless.sh \
  --vault-addr "https://vault_production_node:8200"
```

#### 3.6.2 Bootstrap Artifacts (Download Then Remove AFTER every container is brought up and initialized)

By default, the init/unseal script writes bootstrap artifacts here:

```text
Your directory structure should now resemble below

developer_network_tools@networktoolsvm:~/NETWORK_TOOLS$ tree --charset ascii
.
|-- backend
|   |-- app
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
|   |   |-- mariadb_queries
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
|   |   |           `-- postgres_user.ctmpl
|   |   |-- routers
|   |   `-- security
|   |       `-- configuration_files
|   |           `-- vault
|   |               |-- bootstrap
|   |               |   |-- root_token <-- NEW (Download and save somewhere offline or online in a secure location AFTER all bootstrapping is completed)
|   |               |   |-- root_token.json <-- NEW (Download and save somewhere offline or online in a secure location AFTER all bootstrapping is completed)
|   |               |   `-- unseal_keys.json <-- NEW (Download and save somewhere offline or online in a secure location AFTER all bootstrapping is completed)
|   |               |-- certs
|   |               |   |-- ca.crt
|   |               |   |-- ca.key
|   |               |   |-- ca.srl
|   |               |   |-- cert.crt
|   |               |   `-- cert.key
|   |               |-- config
|   |               |   |-- certs
|   |               |   |-- keycloak_kv_read.hcl
|   |               |   |-- postgres_pgadmin_kv_read.hcl
|   |               |   `-- vault_configuration_primary_node.hcl
|   |               `-- Dockerfile
|   |-- build_scripts
|   |   |-- generate_local_keycloak_certs.sh
|   |   |-- generate_local_postgres_certs.sh
|   |   |-- generate_local_vault_certs.sh
|   |   |-- generate_postgres_pgadmin_bootstrap_creds_and_seed.sh
|   |   |-- guides
|   |   |   |-- seed_kv_spec.example.json
|   |   |   `-- seed_kv_spec.GUIDE.md
|   |   |-- keycloak_approle_setup.sh
|   |   |-- postgress_approle_setup.sh
|   |   |-- startover_scripts
|   |   |   `-- reset_network_tools_docker.sh
|   |   |-- vault_first_time_init_only_rootless.sh
|   |   |-- vault_unseal_kv_seed_bootstrap_rootless.sh
|   |   `-- vault_unseal_multi_kv_seed_bootstrap_rootless.sh
|   `-- nginx
|-- container_data
|   `-- vault
|       `-- data
|           |-- logs
|           |   `-- audit.log <-- NEW Vault log file mapped to the Host OS Mount
|           |-- raft
|           |   |-- raft.db <-- NEW Vault raft database. This is where your secrets are stored
|           |   `-- snapshots
|           `-- vault.db
|-- docker-compose.prod.yml
|-- environment_variable_guide.md
|-- frontend
|-- how_to_videos
|-- README.full.md
`-- README.md
```

These files are **credentials**. Treat them as highly sensitive.

- `unseal_keys.json` contains the unseal key shares (and the root token in JSON form, depending on init output).
- `root_token` / `root_token.json` contain the initial root token.

Example structure (values redacted):

```json
{
  "keys_base64": ["<UNSEAL_KEY_1_B64>", "<UNSEAL_KEY_2_B64>", "<...>"],
  "root_token": "<VAULT_ROOT_TOKEN>"
}
```

**Operational guidance**

- Download the artifacts to a secure location immediately (password manager / offline vault / secure storage).
- Do **not** commit these files to Git.
- After you have secured them, remove them from the server.

Example download (from your workstation) — environment-variable form:

```bash
scp -p <user>@<server>:"$VAULT_BOOTSTRAP_DIR/unseal_keys.json" .
scp -p <user>@<server>:"$VAULT_BOOTSTRAP_DIR/root_token" .
scp -p <user>@<server>:"$VAULT_BOOTSTRAP_DIR/root_token.json" .
```

Example download — fully expanded form:

```bash
scp -p <user>@<server>:"$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/unseal_keys.json" .
scp -p <user>@<server>:"$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token" .
scp -p <user>@<server>:"$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token.json" .
```

Example removal (run on the server after download):

```bash
rm -f \
  "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/unseal_keys.json" \
  "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token" \
  "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token.json"
```

Optional stronger delete (not always effective on all storage):

```bash
shred -u \
  "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/unseal_keys.json" \
  "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token" \
  "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token.json"
```

### 3.7 TLS Certificate Trust and Best Practices

This repository currently uses a **locally generated CA** and a **locally issued Vault server certificate** for development.
That is appropriate for local/dev, but the “right” trust model differs in production.

#### 3.7.1 Local Development (Self-Signed CA)

In local/dev, it is normal for `curl` or client libraries to fail verification unless you explicitly trust the CA.

- Strict verification (recommended even in dev):

  ```bash
  CA="$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt"
  curl --cacert "$CA" https://vault_production_node:8200/v1/sys/health
  ```

- Temporary bypass (avoid when possible; never use in production):

  ```bash
  curl -k https://vault_production_node:8200/v1/sys/health
  ```

**Developer machine trust:** In most cases, you do **not** need to install the dev CA into your workstation’s system trust store.
Instead, point tooling at the CA file (`--cacert` or `VAULT_CACERT`) as needed.

Example (host CLI use):

```bash
export VAULT_ADDR="https://vault_production_node:8200"
export VAULT_CACERT="$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt"
# vault status   # if the vault CLI is installed on the host
```

#### 3.7.2 Production Environments (Recommended)

For production, avoid shipping a “dev CA” and avoid `-k` entirely. Typical patterns:

- Use an enterprise PKI / internal CA trusted by servers and automation clients
- Or use publicly trusted certificates (e.g., ACME/Let’s Encrypt) when appropriate and permitted

**Key principles:**

- The Vault server certificate must include the correct DNS names in **Subject Alternative Name (SAN)** for the production URL(s).
- Clients should validate:
  - Certificate chain (issuer trust)
  - Hostname (SAN match)
  - Validity dates / rotation
- The **CA private key** should not be widely distributed (and should not live in the repo). In production, certificate issuance and private key handling should follow your organization’s security controls.

#### 3.7.3 Practical Guidance for This Repo

- Local/dev scripts support both:
  - Proper verification with `--ca-cert <path-to-ca.crt>`
  - A fallback path that can use `-k` when the local CA is not installed in the trust store (with a warning)
- When moving to production, expect to:
  - Replace the dev CA/cert material with your production certificate chain
  - Update your Vault listener config (`tls_cert_file`, `tls_key_file`) and Compose mounts accordingly
  - Remove any “insecure fallback” behavior from operational runbooks


---


### 3.8 Vault Unseal and KV Seeding Bootstrap Scripts

This repo intentionally keeps **two** seeding approaches so you have more than one option:
These can be used to create custom seed files. Or you can manually enter them into vault. Dealers choice.

- **Single-mount seeder**: `./backend/build_scripts/vault_unseal_kv_seed_bootstrap_rootless.sh`  
  Best for the common case: unseal Vault (if needed), optionally create **one** KV mount, then seed **one JSON input** into that mount.
<br><br>
- **Multi-mount seeder**: `./backend/build_scripts/vault_unseal_multi_kv_seed_bootstrap_rootless.sh`  
  Best when you want to create/seed **multiple** KV mounts and paths in a single run (one “spec” file that defines the whole bootstrap).

Both scripts are designed for **rootless Docker** workflows and default to using artifact files produced by the first-time init/unseal script under:

- Bootstrap artifacts directory (default):  
  `$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap`

> Security note: these scripts can optionally print secrets to the terminal. Assume terminal output may be logged or captured. Prefer storing resolved secrets in the artifact file and moving them off-host immediately.

#### 3.8.1 Overview (Which Script to Use)

Use the **single-mount seeder** when you:
- only need one KV engine mount (example: `app_secrets`)
- want a simple JSON “template” checked into git (optionally using generators/env injection), and a resolved artifact JSON saved under the bootstrap dir

Use the **multi-mount seeder** when you:
- want to stand up multiple KV mounts (example: `app_secrets`, `frontend_environment_variables`, `fastapi_environment_variables`, etc.)
- want a single input file that declares *all* mounts + *all* secret writes in order

#### 3.8.2 Unseal-Only Usage

If you only need to **unseal** Vault and do not want to create mounts or seed secrets, run the single-mount script without any `--create-kv` / `--secrets-json` options:

```bash
cd ~/NETWORK_TOOLS

bash ./backend/build_scripts/vault_unseal_kv_seed_bootstrap_rootless.sh \
  --vault-addr "https://vault_production_node:8200" \
  --ca-cert "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt"
```

Notes:
- If Vault is already unsealed, the script should detect that and exit cleanly.
- If you previously downloaded and removed `unseal_keys.json` (recommended), pass it back in for that run via `--unseal-keys /path/to/unseal_keys.json`.

#### 3.8.3 Single-Mount Seeder (vault_unseal_kv_seed_bootstrap_rootless.sh)

**Primary goal**: unseal Vault (if sealed), optionally create a KV mount (v1 or v2), and seed one or more secrets under that mount from a JSON template file. The script also writes a **resolved artifact** (with generated values) into the bootstrap directory next to the root token so you can download/store it securely.

Key flags (seeding-related):
- `--secrets-json <file>`: JSON template describing what to write (validate with `jq -e . <file> >/dev/null` (or `jq . <file>` if you have jq installed)).
- `--secrets-prefix <prefix>`: optional prefix under the mount (recommended for bootstraps).
- `--secrets-cas <N>`: KV v2 CAS value used for writes (default `0`, meaning **create-only**).
- `--secrets-dry-run`: resolves/generates values but does not write; prints only target paths.
- `--print-secrets`: prints resolved secret values to the terminal (sensitive).

##### Working example (recommended): create mount + seed secrets under a prefix (no double-prefix)

This pattern produces secrets at:

- `app_secrets/bootstrap/creds`
- `app_secrets/bootstrap/crypto`

1) Create a template file (map format). **Note**: paths in the file are **relative** (no `bootstrap/`), because we pass `--secrets-prefix bootstrap`.

```bash
BOOTSTRAP_DIR="$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap"

cat > "${BOOTSTRAP_DIR}/seed_app_secrets.json" <<'EOF'
{
  "creds": {
    "username": "example_user",
    "password": { "generate": { "type": "url_safe", "bytes": 24 } }
  },
  "crypto": {
    "jwt_secret": { "generate": { "type": "hex", "bytes": 32 } },
    "fernet_key": { "generate": { "type": "base64", "bytes": 32 } }
  }
}
EOF

# Always validate before running the seeder
jq -e . "${BOOTSTRAP_DIR}/seed_app_secrets.json" >/dev/null
```

2) Run the seeder (unseal + create KV v2 mount + seed):

```bash
bash ./backend/build_scripts/vault_unseal_kv_seed_bootstrap_rootless.sh \
  --vault-addr "https://vault_production_node:8200" \
  --ca-cert "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt" \
  --unseal-keys "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/unseal_keys.json" \
  --unseal-required 3 \
  --prompt-token \
  --create-kv "app_secrets" \
  --kv-version 2 \
  --kv-description "Network Tools app secrets (dev)" \
  --kv-max-versions 20 \
  --kv-cas-required true \
  --kv-delete-version-after 0s \
  --secrets-json "${BOOTSTRAP_DIR}/seed_app_secrets.json" \
  --secrets-prefix "bootstrap" \
  --secrets-cas 0
```

3) Optional verification (example):

```bash
vault kv get app_secrets/bootstrap/creds
vault kv get app_secrets/bootstrap/crypto
```

##### Reseeding note (KV v2 CAS)

By default, the seeder uses `--secrets-cas 0` (create-only). If you re-run the seeder against a path that already exists, Vault will typically return a 400 and the script will report failure for that secret.

For iterative development, you have three practical options:
- Seed into **new paths** (e.g., change the prefix from `bootstrap` to `bootstrap_2025_12_25`).
- **Delete** the existing secret paths before reseeding (safe only in non-production environments).
- Use list format (Section 3.8.5-B) and set per-secret `cas` to the current version (obtained via `vault kv metadata get`), if you need controlled overwrites.

Output artifacts (defaults):
- Resolved secrets JSON artifact: `$BOOTSTRAP_DIR/seeded_secrets_<mount>.json` (override with `--output-secrets-file`)

#### 3.8.4 Multi-Mount Seeder (vault_unseal_multi_kv_seed_bootstrap_rootless.sh)

**Primary goal**: unseal/token handling plus a single “spec” file that can:
- ensure multiple KV mounts exist (optionally configuring KV v2 behavior per mount)
- write multiple secret objects across multiple paths/mounts
- store a resolved “what was written” artifact under the same bootstrap directory

Typical usage (example):

```bash
bash ./backend/build_scripts/vault_unseal_multi_kv_seed_bootstrap_rootless.sh \
  --vault-addr "https://vault_production_node:8200" \
  --ca-cert "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt" \
  --unseal-required 3 \
  --prompt-token \
  --spec-json "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/seed_kv_spec.json"
```

Useful flags:
- `--dry-run`: resolves/generates values but does not write; prints only target paths.
- `--print-secrets`: prints resolved secret values to the terminal (sensitive).
- `--output-artifact <file>`: override the output artifact path (default: `$BOOTSTRAP_DIR/seeded_secrets_all.json`).
- `--output-format {pretty|compact}`: control artifact formatting.

#### 3.8.5 Seed Input Formats

The **single-mount seeder** supports two JSON formats for `--secrets-json`.

##### A) Map format (recommended): “path -> data object”

Use this format for the common case (simple, readable). Paths are **relative** to the mount (and also relative to `--secrets-prefix` if you pass it).

```json
{
  "app/config": {
    "db_username": "example_user",
    "db_password": { "generate": { "type": "url_safe", "bytes": 32 } }
  },
  "jwt": {
    "secret": { "generate": { "type": "hex", "bytes": 32 } }
  }
}
```

Notes:
- Map format defaults each item’s CAS to `0` (create-only) for KV v2.
- Use `--secrets-prefix` to keep the JSON paths clean (avoid repeating `bootstrap/` in every key).

##### B) List format: supports per-secret CAS overrides (KV v2)

Use this when you need different CAS behavior per secret (or when you prefer explicit objects).

```json
[
  {
    "path": "app/config",
    "data": {
      "db_username": "example_user",
      "db_password": { "generate": { "type": "url_safe", "bytes": 32 } }
    },
    "cas": 0
  },
  {
    "path": "jwt",
    "data": {
      "secret": { "generate": { "type": "hex", "bytes": 32 } }
    },
    "cas": 0
  }
]
```

##### Supported generators

- `hex` (requires `bytes`)
- `base64` (requires `bytes`)
- `url_safe` (requires `bytes`)
- `uuid`

##### Optional “ENV injection” values

Useful when you must avoid putting a plaintext secret value into a file:

- Required env var: `{ "env": "ENV_VAR_NAME" }`
- Optional env var: `{ "env": "ENV_VAR_NAME", "optional": true }`

##### Prefix rule (avoid double-prefix)

Choose exactly one approach:
- Use `--secrets-prefix bootstrap` and keep paths in JSON **relative** (e.g., `creds`, `jwt`), or
- Put `bootstrap/...` directly in the JSON paths and **do not** pass `--secrets-prefix`.

#### 3.8.6 Multi Spec JSON Schema

The multi-mount seeder uses a single JSON file (a “spec”) that defines mounts and the secrets to write under each mount.

Supported top-level shapes:
- Preferred: `{ "mounts": [ ... ] }`
- Wrapper: `[ { "mounts": [ ... ] } ]` (single-element array)
- Legacy (supported): `{ "mounts": [ ... ], "writes": [ ... ] }` (writes are merged into per-mount secrets)

##### Preferred schema (per-mount secrets)

```json
{
  "mounts": [
    {
      "mount": "frontend_app_secrets",
      "version": 2,
      "description": "Frontend secrets",
      "prefix": "bootstrap",
      "v2_config": {
        "max_versions": 20,
        "cas_required": true,
        "delete_version_after": "0s"
      },
      "secrets": {
        "keycloak": {
          "client_secret": { "generate": { "type": "url_safe", "bytes": 32 } }
        }
      }
    },
    {
      "mount": "app_secrets",
      "version": 2,
      "description": "Network Tools app secrets (dev)",
      "prefix": "bootstrap",
      "secrets": [
        {
          "path": "creds",
          "data": {
            "username": "example_user",
            "password": { "generate": { "type": "url_safe", "bytes": 24 } }
          },
          "cas": 0
        },
        {
          "path": "jwt",
          "data": {
            "secret": { "generate": { "type": "hex", "bytes": 32 } }
          },
          "cas": 0
        }
      ]
    }
  ]
}
```

Notes:
- `.secrets` may be either:
  - an **object map** (`{"path": {...}}`) or
  - an **array** of `{path,data,cas}` objects (useful when you want per-secret CAS in KV v2).
- `.prefix` is applied to every secret path for that mount. Keep secret paths **relative** when you use `.prefix`.
- `.v2_config` is only relevant for KV v2 mounts and matches what the multi seeder validates:
  - `max_versions` (int), `cas_required` (bool), `delete_version_after` (string like `"0s"`, `"24h"`).

#### 3.8.7 Example Seed Files

Below are **copy/paste-valid** examples that match what the scripts accept.

##### Single-mount template example (map format) + `--secrets-prefix bootstrap`

This file is intended to be used with:

- `--create-kv app_secrets`
- `--secrets-prefix bootstrap`

So the keys below are **relative** (no `bootstrap/` in the JSON):

```json
{
  "creds": {
    "un": "example_user",
    "pw": { "generate": { "type": "url_safe", "bytes": 24 } }
  },
  "crypto": {
    "jwt_secret": { "generate": { "type": "hex", "bytes": 32 } },
    "fernet_key": { "generate": { "type": "base64", "bytes": 32 } }
  }
}
```

##### Single-mount template example (list format) with per-secret CAS (KV v2)

```json
[
  {
    "path": "creds",
    "data": {
      "un": "example_user",
      "pw": { "generate": { "type": "url_safe", "bytes": 24 } }
    },
    "cas": 0
  },
  {
    "path": "crypto",
    "data": {
      "jwt_secret": { "generate": { "type": "hex", "bytes": 32 } },
      "fernet_key": { "generate": { "type": "base64", "bytes": 32 } }
    },
    "cas": 0
  }
]
```

##### Multi spec example (preferred: per-mount secrets)

This example creates two mounts and writes multiple paths under the `bootstrap/` prefix in each:

```json
{
  "mounts": [
    {
      "mount": "app_secrets",
      "version": 2,
      "description": "Network Tools app secrets (dev)",
      "prefix": "bootstrap",
      "v2_config": {
        "max_versions": 20,
        "cas_required": true,
        "delete_version_after": "0s"
      },
      "secrets": {
        "creds": {
          "un": "example_user",
          "pw": { "generate": { "type": "url_safe", "bytes": 24 } }
        },
        "jwt": {
          "secret": { "generate": { "type": "hex", "bytes": 32 } }
        }
      }
    },
    {
      "mount": "frontend_app_secrets",
      "version": 2,
      "description": "Frontend secrets (dev)",
      "prefix": "bootstrap",
      "secrets": {
        "keycloak": {
          "client_secret": { "generate": { "type": "url_safe", "bytes": 32 } }
        }
      }
    }
  ]
}
```

Validation tip (before running the seeder):

```bash
jq -e . seed_kv_spec.json >/dev/null
```

#### 3.8.8 Output, Artifact Storage, and Security Notes

When you run init/unseal and seed operations, treat these as **sensitive artifacts**:

- `unseal_keys.json`
- `root_token` / `root_token.json`
- any `seeded_secrets_*.json` output artifacts

Artifact defaults:
- Single-mount seeder: `$BOOTSTRAP_DIR/seeded_secrets_<mount>.json`
- Multi-mount seeder: `$BOOTSTRAP_DIR/seeded_secrets_all.json` (override with `--output-artifact <file>`)

Recommended flow:
1. Run the script(s) on the server.
2. `scp -p` the required artifacts to a secure workstation or secrets storage location.
3. Verify the downloads.
4. Remove sensitive artifacts from the server (or move into an encrypted/controlled location).

Security note: avoid `--print-secrets` except during controlled debugging; it will print plaintext values to your terminal history/logs.

#### 3.8.9 Troubleshooting


Common seeding issues and what they usually mean:

- **“Spec file is not valid JSON” / “Secrets file is not valid JSON”**  
  Validate with `jq -e . <file> >/dev/null` (or `jq . <file>` if jq is installed) and correct trailing commas, unquoted keys, or incomplete objects.

- **Paths end up as `bootstrap/bootstrap/...`**  
  You likely used both:
  - `--secrets-prefix bootstrap` (or mount `.prefix: "bootstrap"`) **and**
  - JSON paths that already include `bootstrap/...`  
  Fix by keeping JSON paths relative when using a prefix.

- **KV v2 write fails with HTTP 400 after a successful first run**  
  This is commonly CAS behavior. If you are using CAS create-only (`cas: 0` / `--secrets-cas 0`) and the secret already exists, Vault will reject the write. Options are described in the “Reseeding note” in Section 3.8.3.

- **“permission denied” / HTTP 403**  
  The token in use does not have write access to the target mount/path. Verify policies and confirm you are using the intended token.

- **TLS/cert errors**  
  Ensure `--ca-cert` points to the CA that issued Vault’s server cert (or ensure the CA is trusted by the OS). As a last resort for diagnostics, some scripts may fall back to insecure validation; do not rely on that in production.

#### 3.8.10 Spec Format Notes, Validation Checks, and Common Pitfalls (Updated)

Validation checks enforced by the scripts (high-level):

Single-mount seeder (`--secrets-json`):
- Must be valid JSON.
- Accepts either:
  - map format: `{ "path": { ...data... }, ... }` (all values must be JSON objects), or
  - list format: `[ { "path": "...", "data": { ... }, "cas": 0 }, ... ]`.

Multi-mount seeder (`--spec-json`):
- Must be valid JSON.
- Root must be an object (or a single-element array containing an object).
- Preferred: `.mounts` is an array of mount objects with:
  - `mount` (string), `version` (1 or 2), optional `description`, optional `prefix`
  - `secrets` as an object map or an array of `{path,data,cas}`.
- Optional KV v2 config per mount via `.v2_config`:
  - `max_versions` (int)
  - `cas_required` (bool)
  - `delete_version_after` (string like `"0s"`, `"24h"`)

Common pitfalls:
- **Prefix duplication** (most common): use a prefix in exactly one place (CLI `--secrets-prefix` or spec `.prefix`, not also in every JSON path).
- **Invalid JSON in examples**: do not use placeholders like `...` inside JSON. Always validate with `jq -e . <file> >/dev/null` (or `jq . <file>` if jq is installed).
- **CAS expectations**: `cas: 0` is create-only. If you want rerunnable/idempotent behavior, plan for either deletion, new paths, or explicit CAS updates (KV v2).
- **Wrong “path” semantics in legacy `writes`**: in multi legacy mode, `.writes[].path` must be relative (do not include the mount name, and do not include `.prefix` if you set one on the mount).

#### 3.8.11 Updated Multi-Mount Spec Example (Preferred)

This is the **preferred** format: all secrets are nested under each mount (no top-level `writes`).

```json
{
  "mounts": [
    {
      "mount": "app_secrets",
      "version": 2,
      "description": "Network Tools app secrets (dev)",
      "prefix": "bootstrap",
      "v2_config": {
        "max_versions": 20,
        "cas_required": true,
        "delete_version_after": "0s"
      },
      "secrets": {
        "creds": {
          "un": "example_user",
          "pw": { "generate": { "type": "url_safe", "bytes": 24 } }
        },
        "jwt": {
          "secret": { "generate": { "type": "hex", "bytes": 32 } }
        },
        "crypto": {
          "fernet_key": { "generate": { "type": "base64", "bytes": 32 } }
        }
      }
    },
    {
      "mount": "frontend_app_secrets",
      "version": 2,
      "description": "Frontend secrets (dev)",
      "prefix": "bootstrap",
      "secrets": [
        {
          "path": "keycloak",
          "data": {
            "client_secret": { "generate": { "type": "url_safe", "bytes": 32 } }
          },
          "cas": 0
        }
      ]
    }
  ]
}
```

#### 3.8.12 Legacy Spec Example (mounts + writes)

Legacy mode is supported for backward compatibility: top-level `writes` entries are merged into the matching mount’s `.secrets`.

Important rules:
- Every `.writes[].mount` must match an entry in `.mounts[].mount` (the script validates this).
- `.writes[].path` must be **relative** (do not include the mount name).
- If the mount defines a `.prefix`, `.writes[].path` should be relative to that prefix (do not repeat it).

```json
{
  "mounts": [
    {
      "mount": "app_secrets",
      "version": 2,
      "description": "Network Tools app secrets (dev)",
      "prefix": "bootstrap",
      "v2_config": {
        "max_versions": 20,
        "cas_required": true,
        "delete_version_after": "0s"
      }
    }
  ],
  "writes": [
    {
      "mount": "app_secrets",
      "path": "creds",
      "data": {
        "un": "example_user",
        "pw": { "generate": { "type": "url_safe", "bytes": 24 } }
      },
      "cas": 0
    },
    {
      "mount": "app_secrets",
      "path": "jwt",
      "data": {
        "secret": { "generate": { "type": "hex", "bytes": 32 } }
      },
      "cas": 0
    }
  ]
}
```

#### 3.8.13 About `"generate": { ... }` Values

The `"generate": { ... }` blocks are **not** a native Vault feature. They are a **bootstrap-script convention**:

- The script generates the value at seed time (once), then writes the generated literal value into the KV path.
- Vault will **not** regenerate the value on read.
- To rotate, you re-run the seeding process (or build a dedicated rotation workflow) and write a new value.

If you want dynamic per-request credentials/keys, use a Vault secrets engine designed for that (for example: Database secrets engine, Transit, PKI), not KV.


## 4. postgres

This section documents how we generate and store **initial postgres bootstrap credentials** for the Network Tools stack. The intent is that the rest of the containerized services (postgres itself, application backends, migrations, etc.) can pull their required values from **Vault KV** rather than hard-coding credentials into the repository or long-lived `.env` files.

### 4.1 Bootstrap credentials (generate + seed)

**Run as the same non-root user that runs rootless Docker** (e.g., `developer_network_tools`) from the repo root:

```bash
Exclude the '--prompt-token' if you left the root token files in the bootstrap directory 
as this script will default to looking there first on an initial install and setup.

cd "$HOME/NETWORK_TOOLS"

bash ./backend/build_scripts/generate_postgres_pgadmin_bootstrap_creds_and_seed.sh \
  --vault-addr "https://vault_production_node:8200" \
  --ca-cert "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt" \
  --unseal-required 3 \
  --prompt-token
```

```bash
Example output without the '--prompt-token' flag

developer_network_tools@networktoolsvm:~/NETWORK_TOOLS$ bash ./backend/build_scripts/generate_postgres_pgadmin_bootstrap_creds_and_seed.sh \
  --vault-addr "https://vault_production_node:8200" \
  --ca-cert "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt" \
  --unseal-required 3
WARN: Keycloak TLS material not found; skipping keycloak_tls seeding.
INFO: Wrote credential artifacts:
INFO:   ENV:  /home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/postgres_pgadmin.env
INFO:   JSON: /home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/postgres_pgadmin_credentials.json
INFO:   SPEC: /home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/seed_kv_spec.postgres_pgadmin.json
INFO: 
INFO: Seeding Vault from generated spec...
INFO:   VAULT_ADDR: https://vault_production_node:8200
INFO:   Seed script: /home/developer_network_tools/NETWORK_TOOLS/backend/build_scripts/vault_unseal_multi_kv_seed_bootstrap_rootless.sh
INFO:   CA cert:    /home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt
INFO: Vault address: https://vault_production_node:8200
INFO: Bootstrap dir: /home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap
INFO: Spec file: /home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/seed_kv_spec.postgres_pgadmin.json
INFO: Unseal keys file: /home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/unseal_keys.json
INFO: CA cert: /home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt
INFO: Vault is already unsealed. Skipping unseal.
INFO: Spec mounts: 1
INFO: --- Mount [0]: app_network_tools_secrets (version=2) ---
INFO: Enabled KV v2 at app_network_tools_secrets/
INFO: wrote -> app_network_tools_secrets/postgres
INFO: wrote -> app_network_tools_secrets/pgadmin
INFO: wrote -> app_network_tools_secrets/keycloak_postgres
INFO: wrote -> app_network_tools_secrets/keycloak_bootstrap
INFO: wrote -> app_network_tools_secrets/keycloak_runtime
INFO: Mount app_network_tools_secrets: seed complete. success=5 failed=0
INFO: Wrote consolidated secrets artifact:
      /home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/seeded_secrets_all.json
INFO: (Not printing secrets; use --print-secrets to print.)
INFO: Recommended next steps:
  1) Securely download required artifacts (examples):
     scp -p <user>@<server>:"/home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/seeded_secrets_all.json" .
     scp -p <user>@<server>:"/home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/unseal_keys.json" .
     scp -p <user>@<server>:"/home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token" .
     scp -p <user>@<server>:"/home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token.json" .
  2) After verifying downloads, remove sensitive files from the server:
     rm -f "/home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/seeded_secrets_all.json" "/home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/unseal_keys.json" "/home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token" "/home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token.json"
INFO: Done.
INFO: Vault seeding completed.
INFO: Done.

```

```text
Your file structure should look similar to below.

developer_network_tools@networktoolsvm:~/NETWORK_TOOLS$ tree --charset ascii
.
|-- backend
|   |-- app
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
|   |   |-- mariadb_queries
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
|   |   |           `-- postgres_user.ctmpl
|   |   |-- routers
|   |   `-- security
|   |       `-- configuration_files
|   |           `-- vault
|   |               |-- bootstrap
|   |               |   |-- postgres_pgadmin_credentials.json <-- NEW Generated for bootstrap use for the other containers
|   |               |   |-- postgres_pgadmin.env <-- NEW Generated for bootstrap use for the other containers
|   |               |   |-- root_token
|   |               |   |-- root_token.json
|   |               |   |-- seeded_secrets_all.json <-- NEW Generated for bootstrap use for the other containers
|   |               |   |-- seed_kv_spec.postgres_pgadmin.json <-- NEW Generated for bootstrap use for the other containers
|   |               |   `-- unseal_keys.json
|   |               |-- certs
|   |               |   |-- ca.crt
|   |               |   |-- ca.key
|   |               |   |-- ca.srl
|   |               |   |-- cert.crt
|   |               |   `-- cert.key
|   |               |-- config
|   |               |   |-- certs
|   |               |   |-- keycloak_kv_read.hcl
|   |               |   |-- postgres_pgadmin_kv_read.hcl
|   |               |   `-- vault_configuration_primary_node.hcl
|   |               `-- Dockerfile
|   |-- build_scripts
|   |   |-- generate_local_keycloak_certs.sh
|   |   |-- generate_local_postgres_certs.sh
|   |   |-- generate_local_vault_certs.sh
|   |   |-- generate_postgres_pgadmin_bootstrap_creds_and_seed.sh
|   |   |-- guides
|   |   |   |-- seed_kv_spec.example.json
|   |   |   `-- seed_kv_spec.GUIDE.md
|   |   |-- keycloak_approle_setup.sh
|   |   |-- postgress_approle_setup.sh
|   |   |-- startover_scripts
|   |   |   `-- reset_network_tools_docker.sh
|   |   |-- vault_first_time_init_only_rootless.sh
|   |   |-- vault_unseal_kv_seed_bootstrap_rootless.sh
|   |   `-- vault_unseal_multi_kv_seed_bootstrap_rootless.sh
|   `-- nginx
|-- container_data
|   `-- vault
|       `-- data
|           |-- logs
|           |   `-- audit.log
|           |-- raft
|           |   |-- raft.db
|           |   `-- snapshots
|           `-- vault.db
|-- docker-compose.prod.yml
|-- environment_variable_guide.md
|-- frontend
|-- how_to_videos
|   |-- HOW_TO_3.2 Validate Certificates.mov
|   |-- HOW_TO_3.3 Start Vault with Docker Compose.mov
|   |-- HOW_TO_3.6 Initialize and Unseal Vault (First Run).mov
|   |-- HOW_TO_3.8.3 Single-Mount Seeder (vault_unseal_kv_seed_bootstrap_rootless.sh).mov
|   `-- HOW_TO_3.8.4 Multi-Mount Seeder (vault_unseal_multi_kv_seed_bootstrap_rootless.sh).mov
|-- README.full.md
`-- README.md
```

```text
Example secrets that have been auto generated and seeded into vault

developer_network_tools@networktoolsvm:~/NETWORK_TOOLS$ cat ./backend/app/security/configuration_files/vault/bootstrap/seed_kv_spec.postgres_pgadmin.json
{
  "mounts": [
    {
      "mount": "app_network_tools_secrets",
      "version": 2,
      "secrets": {
        "postgres": {
          "POSTGRES_DB": "network_tools",
          "POSTGRES_USER": "network_tools_user",
          "POSTGRES_PASSWORD": "l8iJmim6SQGLDILfKJgGUvckyK16PL_bO03AVpMWYI4"
        },
        "pgadmin": {
          "PGADMIN_DEFAULT_EMAIL": "admin@example.com",
          "PGADMIN_DEFAULT_PASSWORD": "wYrip91EtXhSn3XihLB23Z_LckULaIjlIukpYA0hoIk"
        },
        "keycloak_postgres": {
          "KC_DB": "postgres",
          "KC_DB_URL_HOST": "postgres_primary",
          "KC_DB_URL_PORT": "5432",
          "KC_DB_URL_DATABASE": "keycloak",
          "KC_DB_USERNAME": "keycloak",
          "KC_DB_PASSWORD": "-eQZOS4Dp0Ts2a9BpUXf6hPuweEGjUdmgSTpGpoHiFw",
          "KC_DB_SCHEMA": "keycloak"
        },
        "keycloak_bootstrap": {
          "KC_BOOTSTRAP_ADMIN_USERNAME": "admin",
          "KC_BOOTSTRAP_ADMIN_PASSWORD": "nx6a6NmP4LGtnSRteTrAX46VAyY4OfDF0ANNGxpucg0"
        },
        "keycloak_runtime": {
          "KC_HOSTNAME": "keycloak",
          "KC_HOSTNAME_STRICT": "true",
          "KC_HTTP_ENABLED": "false",
          "KC_HTTPS_PORT": "8443",
          "KC_HEALTH_ENABLED": "true",
          "KC_METRICS_ENABLED": "true",
          "KC_HTTP_MANAGEMENT_PORT": "9000",
          "KC_HTTP_MANAGEMENT_SCHEME": "http"
        }
      }
    }
  ]
}
```

What the script does:

- Generates:
  - `POSTGRES_DB` (default: `network_tools`)
  - `POSTGRES_USER` (default: `network_tools_user`)
  - `POSTGRES_PASSWORD` (generated if not supplied)
- Creates local **bootstrap artifacts** under:

  ```text
  $HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/
  ```

  Files created:
  - `postgres_pgadmin.env` (shell env format)
  - `postgres_pgadmin_credentials.json` (human-readable credentials JSON)
  - `seed_kv_spec.postgres_pgadmin.json` (the spec used to seed Vault)

- Seeds Vault KV mount **`app_network_tools_secrets`** (default) with two secret paths:
  - `postgres` (postgres values)
  - `pgadmin` (pgAdmin values)

Notes:

- By default, the script writes to `postgres` and `pgadmin` **without** a prefix (this matches the desired layout: `postgres`, not `bootstrap/postgres`).
- If you explicitly want a prefix later, use `--vault-prefix "<prefix>"`.

Rotation (long-term operations):

- The same script supports rotating the **static** Postgres application password stored in Vault.
- Rotation has two required steps:
  1) Update Vault KV (so the agent will render the new value).
  2) Update the password inside the running Postgres cluster (because `POSTGRES_*` init vars are only applied on first initialization).
- Use `--mode rotate` to generate a new password and re-seed Vault. To also apply it to a running container, add `--apply-to-postgres`:

```bash
cd "$HOME/NETWORK_TOOLS"

VAULT_ADDR="https://vault_production_node:8200"
VAULT_CA_CERT="$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt"

bash ./backend/build_scripts/generate_postgres_pgadmin_bootstrap_creds_and_seed.sh \
  --mode rotate \
  --vault-addr "$VAULT_ADDR" \
  --ca-cert "$VAULT_CA_CERT" \
  --unseal-required 3 \
  --prompt-token \
  --apply-to-postgres
```

- If you prefer to do the Postgres `ALTER ROLE` step manually (or if `--apply-to-postgres` fails), see **6.3.7**.

Security and operational guidance:

- These files contain plaintext credentials.
- Immediately download them to a secure location and remove them from the server once you have verified the secrets are stored in Vault.
- In production, prefer:
  - short-lived bootstrap tokens,
  - scoped policies,
  - rotation workflows,
  - and (where practical) Vault dynamic secrets engines instead of long-lived static passwords.

### 4.2 Retrieve credentials from Vault

The seeding script writes using the Vault HTTP API. If your mount is **KV v2** (the default in the generated spec), read secrets like this:

```bash
VAULT_ADDR="https://vault_production_node:8200"
CA_CERT="$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt"
TOKEN="$(cat "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token")"

# postgres secret (KV v2)
curl -sS --cacert "$CA_CERT" \
  -H "X-Vault-Token: $TOKEN" \
  "$VAULT_ADDR/v1/app_network_tools_secrets/data/postgres" | jq .
```

To extract a single value (example: password):

```bash
curl -sS --cacert "$CA_CERT" \
  -H "X-Vault-Token: $TOKEN" \
  "$VAULT_ADDR/v1/app_network_tools_secrets/data/postgres" | jq -r '.data.data.POSTGRES_PASSWORD'
```

If you later choose to use **KV v1**, the read path will not include `/data/`:

```bash
curl -sS --cacert "$CA_CERT" \
  -H "X-Vault-Token: $TOKEN" \
  "$VAULT_ADDR/v1/app_network_tools_secrets/postgres" | jq .
```

### 4.3 Use with Docker Compose

**Before you start: generate local Postgres TLS certs (one-time per environment)**

If Postgres TLS is enabled (the default in this repo), make sure the Postgres certificate files exist **before** bringing the Compose stack up. From the repo root:

```bash
cd "$HOME/NETWORK_TOOLS"
bash ./backend/build_scripts/generate_local_postgres_certs.sh
```

```bash
developer_network_tools@networktoolsvm:~/NETWORK_TOOLS$ tree --charset ascii
.
|-- backend
|   |-- app
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
|   |   |-- mariadb_queries
|   |   |-- postgres
|   |   |   |-- certs
|   |   |   |   |-- ca.crt
|   |   |   |   |-- ca.key <- NEW - Can be removed to safe storage
|   |   |   |   |-- ca.srl <- NEW - Can be removed to safe storage
|   |   |   |   |-- cert.crt
|   |   |   |   `-- cert.key
|   |   |   |-- config
|   |   |   |   |-- pg_hba.conf
|   |   |   |   `-- postgres.conf
|   |   |   `-- vault_agent
|   |   |       |-- agent.hcl
|   |   |       `-- templates
|   |   |           |-- pgadmin_password.ctmpl
|   |   |           |-- postgres_db.ctmpl
|   |   |           |-- postgres_password.ctmpl
|   |   |           `-- postgres_user.ctmpl
|   |   |-- routers
|   |   `-- security
|   |       `-- configuration_files
|   |           `-- vault
|   |               |-- bootstrap
|   |               |   |-- postgres_pgadmin_credentials.json
|   |               |   |-- postgres_pgadmin.env
|   |               |   |-- root_token
|   |               |   |-- root_token.json
|   |               |   |-- seeded_secrets_all.json
|   |               |   |-- seed_kv_spec.postgres_pgadmin.json
|   |               |   `-- unseal_keys.json
|   |               |-- certs
|   |               |   |-- ca.crt <- NEW
|   |               |   |-- ca.key <- NEW - Can be removed to safe storage
|   |               |   |-- ca.srl <- NEW - Can be removed to safe storage
|   |               |   |-- cert.crt <- NEW
|   |               |   `-- cert.key <- NEW
|   |               |-- config
|   |               |   |-- certs
|   |               |   |-- keycloak_kv_read.hcl
|   |               |   |-- postgres_pgadmin_kv_read.hcl
|   |               |   `-- vault_configuration_primary_node.hcl
|   |               `-- Dockerfile
|   |-- build_scripts
|   |   |-- generate_local_keycloak_certs.sh
|   |   |-- generate_local_postgres_certs.sh
|   |   |-- generate_local_vault_certs.sh
|   |   |-- generate_postgres_pgadmin_bootstrap_creds_and_seed.sh
|   |   |-- guides
|   |   |   |-- seed_kv_spec.example.json
|   |   |   `-- seed_kv_spec.GUIDE.md
|   |   |-- keycloak_approle_setup.sh
|   |   |-- postgress_approle_setup.sh
|   |   |-- startover_scripts
|   |   |   `-- reset_network_tools_docker.sh
|   |   |-- vault_first_time_init_only_rootless.sh
|   |   |-- vault_unseal_kv_seed_bootstrap_rootless.sh
|   |   `-- vault_unseal_multi_kv_seed_bootstrap_rootless.sh
|   `-- nginx
|-- container_data
|   `-- vault
|       |-- approle
|       |   `-- postgres_pgadmin_agent
|       `-- data
|           |-- logs
|           |   `-- audit.log
|           |-- raft
|           |   |-- raft.db
|           |   `-- snapshots
|           `-- vault.db
|-- docker-compose.prod.yml
|-- environment_variable_guide.md
|-- frontend
|-- how_to_videos
|   |-- HOW_TO_3.2 Validate Certificates.mov
|   |-- HOW_TO_3.3 Start Vault with Docker Compose.mov
|   |-- HOW_TO_3.6 Initialize and Unseal Vault (First Run).mov
|   |-- HOW_TO_3.8.3 Single-Mount Seeder (vault_unseal_kv_seed_bootstrap_rootless.sh).mov
|   `-- HOW_TO_3.8.4 Multi-Mount Seeder (vault_unseal_multi_kv_seed_bootstrap_rootless.sh).mov
|-- README.full.md
`-- README.md

```


Verify the expected cert files were created (these are the files mounted into the Postgres container):

```bash
ls -lah ./backend/app/postgres/certs/
# Expected (minimum): ca.crt, cert.crt, cert.key
```

You have two common patterns:

**Option A (simple dev bootstrap): use the generated env file**

This is convenient, but treat it as sensitive:

```bash
set -a
# shellcheck disable=SC1090
source "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/postgres_pgadmin.env"
set +a
```

You can then reference the exported variables when starting one-off Postgres/pgAdmin containers (or for manual troubleshooting). In production, prefer the Vault Agent `*_FILE` pattern described in **6.3.5**.

**Option B (preferred): pull from Vault at runtime**

For production-like workflows, prefer fetching secrets from Vault at container start using the Vault Agent sidecar pattern (`*_FILE` env vars). This is implemented in `docker-compose.prod.yml`; see **6.3.5**.


#### 4.3.1 Compose prerequisites

Run these checks from the repository root (`~/NETWORK_TOOLS`) as the same non-root user that runs **rootless Docker** (e.g., `developer_network_tools`):

1) Confirm the source certificate files exist on the host:

```bash
ls -lh ./backend/app/postgres/certs/
```

Expected (minimum) inputs:

- `ca.crt`
- `cert.crt`
- `cert.key`

2) Confirm the Postgres config files exist and are **not empty**:

```bash
ls -lh ./backend/app/postgres/config/postgres.conf ./backend/app/postgres/config/pg_hba.conf
wc -l  ./backend/app/postgres/config/postgres.conf ./backend/app/postgres/config/pg_hba.conf
```

3) Validate the Compose file renders cleanly (this catches YAML formatting/indentation issues early):

```bash
docker compose -f docker-compose.prod.yml config > /tmp/network_tools.compose.rendered.yml
```

#### 4.3.2 Initialize the Postgres certs volume

In this stack, Postgres TLS material is delivered via a **named volume** populated by a short-lived init container (`postgres_certs_init`). The primary Postgres service mounts that volume read-only at `/etc/postgres/certs`.

Bring-up pattern:

1) (Optional but recommended during troubleshooting) reset the cert volume and the init container:

```bash
docker compose -f docker-compose.prod.yml rm -sf postgres_primary postgres_certs_init

# The actual on-disk volume name is prefixed by the compose project name (e.g., network_tools_postgres_certs)
docker volume rm network_tools_postgres_certs 2>/dev/null || true
```

2) Start the init container and confirm it successfully populated the volume:

```bash
docker compose -f docker-compose.prod.yml up -d postgres_certs_init
docker logs postgres_certs_init
```

You should see a file listing of `/dest` at the end of the logs with:

- `ca.crt`
- `server.crt`
- `server.key`

3) (Optional) validate the volume contents directly:

```bash
docker run --rm -v network_tools_postgres_certs:/dest alpine ls -l /dest
```

Note: In rootless Docker, owners may appear as numeric IDs (e.g., `999`). That is expected.

#### 4.3.3 Start postgres_primary

Start the primary Postgres service after the init container has completed successfully:

```bash
docker compose -f docker-compose.prod.yml up -d postgres_primary
docker logs --tail 200 -f postgres_primary
```

A successful start ends with:

- `database system is ready to accept connections`

#### 4.3.4 Verify and connect

1) Confirm the container is up:

```bash
docker compose -f docker-compose.prod.yml ps
docker ps --format "table {{.Names}}	{{.Status}}	{{.Ports}}"
```

2) Confirm the expected files exist inside the container:

```bash
docker exec -it postgres_primary sh -lc 'ls -lah /etc/postgres/certs && ls -lah /etc/postgres/postgres.conf /etc/postgres/pg_hba.conf'
```

3) Verify effective runtime settings (inside Postgres):

```bash
docker exec -it postgres_primary sh -lc 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "SHOW ssl; SHOW ssl_cert_file; SHOW ssl_key_file; SHOW ssl_ca_file; SHOW config_file; SHOW hba_file;"'
```

If you expect host connectivity, ensure your `postgres.conf` includes an appropriate `listen_addresses` value (e.g., `'*'`) and that the Compose service publishes `5432:5432`.

#### 4.3.5 Troubleshooting

**1) Mount error: “read-only file system” when creating `/etc/postgres/certs/*.crt` mountpoints**

Symptom (example):

- `create mountpoint "/etc/postgres/certs/ca.crt": read-only file system`

Common cause:

- The Compose service attempts to mount **individual cert files** into a path that is already covered by a **read-only directory mount** (for example, a named volume mounted at `/etc/postgres/certs:ro`).

Fix (recommended):

- Choose one approach. For this project, keep the **named volume** (`postgres_certs:/etc/postgres/certs:ro`) and remove file-level mounts to `/etc/postgres/certs/*`. Let `postgres_certs_init` populate the volume.

**2) FATAL: could not load server certificate file (missing file)**

Symptoms (examples):

- `could not load server certificate file "/etc/postgres/certs/server.crt": No such file or directory`
- `could not load server certificate file "/etc/postgres/certs/cert.crt": No such file or directory`

Checklist:

- Confirm `postgres_certs_init` completed successfully and the volume contains `server.crt` and `server.key` (Section **4.3.2**).
- Confirm Postgres is configured to reference the filenames that actually exist.

Recommendation:

- Standardize on `server.crt` / `server.key` inside the container (as produced by `postgres_certs_init`), and set:

  - `ssl_cert_file=/etc/postgres/certs/server.crt`
  - `ssl_key_file=/etc/postgres/certs/server.key`
  - `ssl_ca_file=/etc/postgres/certs/ca.crt`

If your `postgres.conf` currently references `cert.crt`, update it (or alternately, add a copy step in `postgres_certs_init` so both names exist).

**3) pg_hba.conf errors (empty or unreadable)**

Symptoms:

- `configuration file "/etc/postgres/pg_hba.conf" contains no entries`
- `FATAL: could not load /etc/postgres/pg_hba.conf`

Checklist:

```bash
# Host file must exist and be non-empty
wc -l ./backend/app/postgres/config/pg_hba.conf

# Container must see the same file (and it must be readable)
docker exec -it postgres_primary sh -lc 'ls -l /etc/postgres/pg_hba.conf && wc -l /etc/postgres/pg_hba.conf'
```

Minimal example (tighten for your environment; do not use `trust` broadly in production):

```conf
# TYPE  DATABASE        USER            ADDRESS                 METHOD
local   all             all                                     peer
host    all             all             127.0.0.1/32            scram-sha-256
host    all             all             ::1/128                 scram-sha-256

# Example: allow app subnet over TLS (adjust CIDR)
hostssl all             all             10.0.0.0/8              scram-sha-256
```

**4) “PostgreSQL Database directory appears to contain a database; Skipping initialization”**

This is informational. It means your bound data directory already has an initialized cluster. If you intend a clean rebuild, stop Postgres and remove the data directory contents (or move them aside), then restart.

**5) postgres_certs_init logs show only environment variables / no `/dest` listing**

This typically indicates the init container did not execute the intended copy commands.

- Re-check the rendered Compose output:

  ```bash
  docker compose -f docker-compose.prod.yml config | sed -n '/postgres_certs_init:/,/postgres_primary:/p'
  ```

- Confirm `entrypoint` and `command` match the expected script, then recreate the init container:

  ```bash
  docker compose -f docker-compose.prod.yml rm -sf postgres_certs_init
  docker compose -f docker-compose.prod.yml up -d --force-recreate --no-deps postgres_certs_init
  docker logs postgres_certs_init
  ```


### 4.4 Startup credential options (choose one)

Postgres does **not** natively “connect to Vault” on startup. In Docker, you typically implement that behavior using one of the following patterns:

1) **Baseline (current Compose approach): `.env` / `env_file`**
   - The host (or a build script) populates `POSTGRES_DB`, `POSTGRES_USER`, and `POSTGRES_PASSWORD` in `.env`.
   - `docker-compose.prod.yml` consumes those values (see **4.3**).

2) **Vault Agent sidecar (recommended when you want Vault dependency at container start)**
   - A Vault Agent container authenticates to Vault and renders secrets into files in a shared volume.
   - The official Postgres image supports file-based inputs via `POSTGRES_DB_FILE`, `POSTGRES_USER_FILE`, and `POSTGRES_PASSWORD_FILE`.
   - See **Section 6** for the full wiring and bootstrapping procedure.

3) **Host “pre-flight” fetch from Vault (simple, but less ideal)**
   - A host script reads secrets from Vault and writes them into `.env` immediately before `docker compose up`.
   - This is easy to operate, but it places secrets back into `.env` (which you should treat as sensitive).

Operational note:
- `POSTGRES_DB(_FILE)`, `POSTGRES_USER(_FILE)`, and `POSTGRES_PASSWORD(_FILE)` are consumed by the official Postgres image **only when initializing a brand-new data directory** (no existing cluster under `PGDATA`).
- After the cluster exists, changing Vault KV (or changing the rendered files) will **not** rotate the database user's password by itself.
- Password rotation requires (a) `ALTER ROLE ... WITH PASSWORD ...` executed as a superuser inside Postgres, and (b) updating Vault KV so the rendered secret matches.
- The bootstrap script supports this workflow via `--mode rotate` (and optionally `--apply-to-postgres`). See **4.1** and **6.3.7**.



### 4.5 Apply Vault credentials to an existing Postgres cluster

Use this when **secrets already exist** (local bootstrap file and/or Vault), but the Postgres data directory has already been initialized and you need to **create/align roles and databases** inside the running cluster.

Key points:

- `POSTGRES_DB`, `POSTGRES_USER`, and `POSTGRES_PASSWORD` are only consumed by the Postgres image **on first initialization** (when the data directory is empty).
- After that, changing env values (or Vault values) does **not** change users/passwords inside Postgres; you must apply changes with SQL (for example, `ALTER ROLE ... WITH PASSWORD ...`).

Recommended “sync/apply” command (does **not** re-seed Vault):

```bash
cd "$HOME/NETWORK_TOOLS"

bash ./backend/build_scripts/generate_postgres_pgadmin_bootstrap_creds_and_seed.sh \
  --vault-addr "https://vault_production_node:8200" \
  --ca-cert "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt" \
  --unseal-required 3 \
  --no-seed \
  --apply-to-postgres

```

Operational notes:

- By default, `--apply-to-postgres` will try to bring up `postgres_primary` (via Compose) if it is not already running, then wait for it to accept connections.
- If you want to manage Postgres startup yourself, add `--no-auto-start-postgres`.
- If Postgres is slow to start (first init, fsync, etc.), increase `--wait-postgres-seconds`.

### 4.6 Rotation runbook (static credentials)

This repo currently uses **static** database credentials stored in Vault KV (as opposed to Vault’s database secrets engine issuing dynamic, leased credentials). Static creds are simple, but rotation must be handled intentionally.

Rotation always has two parts:

1) **Rotate in Vault** so the new value is the source of truth (and so Vault Agent sidecars render the updated secret).
2) **Rotate in Postgres** so the role password in the cluster matches Vault.

Rotate + apply in one workflow (recommended):

```bash
cd "$HOME/NETWORK_TOOLS"

bash ./backend/build_scripts/generate_postgres_pgadmin_bootstrap_creds_and_seed.sh   --vault-addr "https://vault_production_node:8200"   --ca-cert "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt"   --unseal-required 3   --mode rotate   --apply-to-postgres
```

What this accomplishes:

- Generates new passwords (unless you explicitly pass values).
- Writes updated values to Vault KV (unless `--no-seed`).
- Updates Postgres roles/databases to match the new Vault values.

After rotation:

- Restart dependent services (pgAdmin, Keycloak, application backends) so they pick up the new rendered credentials.
- If using Vault Agent sidecars, confirm the rendered files have changed before restarting application containers.

If you want to rotate only a subset:

- Prefer `--mode rotate` plus explicit values for the passwords you want to rotate, and reuse existing values for everything else.
- Use `--no-keycloak` / `--no-keycloak-bootstrap` / `--no-keycloak-runtime` (as applicable) when you want to avoid updating Keycloak-related secrets.



## 5. pgAdmin

This section documents the bootstrap credential(s) used by **pgAdmin** and how they are stored alongside the postgres credentials.

### 5.1 Bootstrap credentials (generate + seed)

The postgres/pgAdmin bootstrap script generates *both* Postgres and pgAdmin credentials in one run:

```bash
cd "$HOME/NETWORK_TOOLS"

bash ./backend/build_scripts/generate_postgres_pgadmin_bootstrap_creds_and_seed.sh \
  --vault-addr "https://vault_production_node:8200" \
  --ca-cert "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt" \
  --unseal-required 3 \
  --prompt-token
```

The pgAdmin secret is stored under:

- KV mount: `app_network_tools_secrets`
- Secret path: `pgadmin`
- Key: `PGADMIN_DEFAULT_PASSWORD`

### 5.2 Retrieve credentials from Vault

For KV v2 (default):

```bash
VAULT_ADDR="https://vault_production_node:8200"
CA_CERT="$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt"
TOKEN="$(cat "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token")"

curl -sS --cacert "$CA_CERT" \
  -H "X-Vault-Token: $TOKEN" \
  "$VAULT_ADDR/v1/app_network_tools_secrets/data/pgadmin" | jq .
```

Example extracting the password only:

```bash
curl -sS --cacert "$CA_CERT" \
  -H "X-Vault-Token: $TOKEN" \
  "$VAULT_ADDR/v1/app_network_tools_secrets/data/pgadmin" | jq -r '.data.data.PGADMIN_DEFAULT_PASSWORD'
```

### 5.3 Use with Docker Compose

When you define the pgAdmin service, you will typically provide:

- `PGADMIN_DEFAULT_EMAIL` (you choose this value; it is not generated by the script)
- `PGADMIN_DEFAULT_PASSWORD` (seeded in Vault, or sourced from the generated env file)

For dev-only usage, you may source the generated env file (see section **4.3**) and reference the environment variables in your compose file.




### 5.4 Startup credential options (choose one)

pgAdmin also does not “pull from Vault” by itself. The common approaches are the same as Postgres:

1) **Baseline (current Compose approach): `.env` / `env_file`**
   - `PGADMIN_DEFAULT_EMAIL` and `PGADMIN_DEFAULT_PASSWORD` are provided via `.env`.

2) **Vault Agent sidecar (recommended when you want Vault dependency at container start)**
   - A Vault Agent container renders the admin password into a file in a shared volume.
   - pgAdmin supports `PGADMIN_DEFAULT_PASSWORD_FILE`, allowing you to source the password from a file (Docker secret / rendered file).
   - See **Section 6** for the full wiring and bootstrapping procedure.

3) **Host “pre-flight” fetch from Vault (simple, but less ideal)**
   - A host script reads the pgAdmin password from Vault and writes it into `.env` immediately before `docker compose up`.

Operational note:
- pgAdmin persists its own internal configuration database. On first startup it initializes the admin account based on the provided variables. If you rotate the password later, treat it like an application credential rotation (update Vault, update the container inputs, and restart).

## 6. Postgres and pgAdmin Vault Integration Bootstrapping

This section consolidates the “integration” story end-to-end: how Postgres and pgAdmin can start with credentials stored in Vault, while still supporting a fallback to locally stored bootstrap artifacts.

### 6.1 Overview and constraints

Key points to internalize up front:

- **Postgres and pgAdmin do not natively query Vault.** Something else must authenticate to Vault and deliver the values to the containers (host scripting, init containers, or a Vault Agent sidecar).
- **Prefer file-based secrets over environment variables** where possible:
  - The official Postgres image supports `_FILE` variants for `POSTGRES_DB`, `POSTGRES_USER`, and `POSTGRES_PASSWORD` (and a few others), meaning you can supply those values from files (e.g., Docker secrets or a rendered file).
  - pgAdmin supports `PGADMIN_DEFAULT_PASSWORD_FILE`, meaning the admin password can be supplied from a file.
- **Initialization behavior matters:** these variables affect initialization **only** when the Postgres data directory is empty. If your Postgres data volume already contains a database cluster, changing `POSTGRES_*` values will not automatically rotate users/passwords. Rotation requires explicit SQL (`ALTER USER ...`) and controlled restarts.

Vault KV paths and mounts used in this repo:
- The bootstrap seeding flow in **4.1** writes `postgres` and `pgadmin` under the configured mount (commonly `app_network_tools_secrets`).
- If you used a different mount name (for example, a spelling variation), use that consistently in policies, templates, and read paths.

### 6.2 Option A – Keep env file (.env) as the runtime source of truth

This is the simplest operationally because it requires **no changes** to the current `docker-compose.prod.yml` Postgres/pgAdmin services.

#### When to use this option
- You want the stack to start even if Vault is down.
- You accept that secrets will exist (briefly or persistently) in `.env` on the host.
- You primarily use Vault as your “system of record” (seed/backup), not as a hard runtime dependency.

#### Steps

1) **Generate and seed** using the existing repo script (see **4.1** and **5.1**).
2) **Choose the fallback file location** (these are created by the script):
   - `./backend/app/security/configuration_files/vault/bootstrap/postgres_pgadmin.env`
   - `./backend/app/security/configuration_files/vault/bootstrap/postgres_pgadmin_credentials.json`
3) **Populate `.env` for Compose**.

Example: merge only the postgres/pgAdmin values into your existing `.env`:

```bash
cd "$HOME/NETWORK_TOOLS"

BOOT_ENV="./backend/app/security/configuration_files/vault/bootstrap/postgres_pgadmin.env"
test -f "$BOOT_ENV" || { echo "Missing: $BOOT_ENV"; exit 1; }

# Create a backup copy the first time
cp -n .env ".env.bak.$(date +%Y%m%d_%H%M%S)" || true

# Remove any prior definitions, then append the new ones (keeps .env clean)
grep -vE '^(POSTGRES_DB|POSTGRES_USER|POSTGRES_PASSWORD|PGADMIN_DEFAULT_PASSWORD)=' .env > .env.tmp || true
cat "$BOOT_ENV" >> .env.tmp
mv .env.tmp .env
chmod 600 .env
```

4) Bring up the services normally:

```bash
docker compose -f docker-compose.prod.yml up -d postgres_certs_init postgres_primary pgadmin
```

Security note:
- If you use this option, treat `.env` as a **secret-bearing file**: permissions `600`, do not commit it, and limit access to the docker host.

### 6.3 Option B – Vault Agent sidecar renders file-based secrets at container start

This pattern is the closest to “Postgres boots and obtains credentials from Vault,” while still remaining idiomatic for containers:
- A **Vault Agent** container authenticates to Vault using **AppRole**.
- The agent renders secrets into **files** inside a shared volume.
- Postgres and pgAdmin read those values using their supported `*_FILE` environment variables.

#### High-level flow

1) Vault is running, initialized, unsealed, and seeded with the `postgres` and `pgadmin` KV entries.
2) You create a Vault policy that can only read those two secrets.
3) You create an AppRole bound to that policy.
4) A Vault Agent container uses the AppRole to obtain a short-lived token.
5) The Vault Agent templates render:
   - `postgres_db`, `postgres_user`, `postgres_password`
   - `pgadmin_password`
6) Postgres uses:
   - `POSTGRES_DB_FILE=/run/vault/postgres_db`
   - `POSTGRES_USER_FILE=/run/vault/postgres_user`
   - `POSTGRES_PASSWORD_FILE=/run/vault/postgres_password`
7) pgAdmin uses:
   - `PGADMIN_DEFAULT_PASSWORD_FILE=/run/vault/pgadmin_password`

### 6.3.1 Create a least-privilege Vault policy

Create an ACL policy that can only read the two KV secrets needed at runtime (Postgres + pgAdmin).

If your mount is KV v2 (the repo default), the paths include `/data/`:

```hcl
# postgres + pgAdmin runtime reads (KV v2)
path "app_network_tools_secrets/data/postgres" {
  capabilities = ["read"]
}

path "app_network_tools_secrets/data/pgadmin" {
  capabilities = ["read"]
}
```

If your mount is KV v1, remove `/data/`:

```hcl
# postgres + pgAdmin runtime reads (KV v1)
path "app_network_tools_secrets/postgres" {
  capabilities = ["read"]
}

path "app_network_tools_secrets/pgadmin" {
  capabilities = ["read"]
}
```

> If your KV mount name differs (for example, legacy `app_network_tools_secrets`), replace `app_network_tools_secrets` everywhere in the policy, templates, and validation commands.

Apply the policy (run from the host using `docker exec` into the Vault container; requires a Vault admin/root token for setup tasks).

Environment-variable form:

```bash
cd "$NT_ROOT"

VAULT_CONTAINER="vault_production_node"
VAULT_ADDR_INTERNAL="$VAULT_ADDR"
VAULT_TOKEN="$(cat "$VAULT_ROOT_TOKEN_FILE")"

docker exec -i \
  -e VAULT_ADDR="$VAULT_ADDR_INTERNAL" \
  -e VAULT_TOKEN="$VAULT_TOKEN" \
  -e VAULT_CACERT="/vault/certs/ca.crt" \
  "$VAULT_CONTAINER" \
  sh -lc 'cat >/tmp/postgres_pgadmin_read.hcl && vault policy write postgres_pgadmin_read /tmp/postgres_pgadmin_read.hcl' <<'HCL'
path "app_network_tools_secrets/data/postgres" {
  capabilities = ["read"]
}

path "app_network_tools_secrets/data/pgadmin" {
  capabilities = ["read"]
}
HCL
```

Fully expanded form:

```bash
cd "$HOME/NETWORK_TOOLS"

docker exec -i \
  -e VAULT_ADDR="https://vault_production_node:8200" \
  -e VAULT_TOKEN="$(cat ./backend/app/security/configuration_files/vault/bootstrap/root_token)" \
  -e VAULT_CACERT="/vault/certs/ca.crt" \
  vault_production_node \
  sh -lc 'cat >/tmp/postgres_pgadmin_read.hcl && vault policy write postgres_pgadmin_read /tmp/postgres_pgadmin_read.hcl' <<'HCL'
path "app_network_tools_secrets/data/postgres" {
  capabilities = ["read"]
}

path "app_network_tools_secrets/data/pgadmin" {
  capabilities = ["read"]
}
HCL
```

Validation (optional):

```bash
docker exec -it \
  -e VAULT_ADDR="https://vault_production_node:8200" \
  -e VAULT_TOKEN="$(cat ./backend/app/security/configuration_files/vault/bootstrap/root_token)" \
  -e VAULT_CACERT="/vault/certs/ca.crt" \
  vault_production_node \
  sh -lc 'vault policy read postgres_pgadmin_read'
```

### 6.3.2 Create an AppRole for the agent

Enable AppRole auth (one-time):

```bash
docker exec -it \
  -e VAULT_ADDR="https://vault_production_node:8200" \
  -e VAULT_TOKEN="$(cat ./backend/app/security/configuration_files/vault/bootstrap/root_token)" \
  -e VAULT_CACERT="/vault/certs/ca.crt" \
  vault_production_node \
  sh -lc 'vault auth enable approle || true'
```

Create (or update) the role. This repo uses the AppRole name `postgres_pgadmin_agent`.

Environment-variable form:

```bash
cd "$NT_ROOT"

VAULT_CONTAINER="vault_production_node"
ROLE_NAME="postgres_pgadmin_agent"
VAULT_TOKEN="$(cat "$VAULT_ROOT_TOKEN_FILE")"

docker exec -it \
  -e VAULT_ADDR="$VAULT_ADDR" \
  -e VAULT_TOKEN="$VAULT_TOKEN" \
  -e VAULT_CACERT="/vault/certs/ca.crt" \
  "$VAULT_CONTAINER" \
  sh -lc "
    vault write auth/approle/role/${ROLE_NAME} \
      token_policies=postgres_pgadmin_read \
      token_ttl=1h \
      token_max_ttl=4h \
      secret_id_ttl=24h \
      secret_id_num_uses=1
  "
```

Fully expanded form:

```bash
docker exec -it \
  -e VAULT_ADDR="https://vault_production_node:8200" \
  -e VAULT_TOKEN="$(cat ./backend/app/security/configuration_files/vault/bootstrap/root_token)" \
  -e VAULT_CACERT="/vault/certs/ca.crt" \
  vault_production_node \
  sh -lc "
    vault write auth/approle/role/postgres_pgadmin_agent \
      token_policies=postgres_pgadmin_read \
      token_ttl=1h \
      token_max_ttl=4h \
      secret_id_ttl=24h \
      secret_id_num_uses=1
  "
```

Validate that the role exists and retrieve the Role ID:

```bash
docker exec -it \
  -e VAULT_ADDR="https://vault_production_node:8200" \
  -e VAULT_TOKEN="$(cat ./backend/app/security/configuration_files/vault/bootstrap/root_token)" \
  -e VAULT_CACERT="/vault/certs/ca.crt" \
  vault_production_node \
  sh -lc 'vault read -field=role_id auth/approle/role/postgres_pgadmin_agent/role-id'
```

Generate a new Secret ID:

```bash
docker exec -it \
  -e VAULT_ADDR="https://vault_production_node:8200" \
  -e VAULT_TOKEN="$(cat ./backend/app/security/configuration_files/vault/bootstrap/root_token)" \
  -e VAULT_CACERT="/vault/certs/ca.crt" \
  vault_production_node \
  sh -lc 'vault write -f -field=secret_id auth/approle/role/postgres_pgadmin_agent/secret-id'
```

### 6.3.3 Export Role ID and Secret ID for the Vault Agent

The Vault Agent container expects to read AppRole artifacts from the **host** export directory (bind-mounted read-only into the agent at `/vault/approle`):

```text
./container_data/vault/approle/postgres_pgadmin_agent/
  role_id
  secret_id
```

This section provides two options:

- **Recommended:** use the repo export script (if present) to (re)export the files.
- **Manual:** copy/paste commands that run the Vault CLI inside the Vault container (no Vault CLI on host; no `jq` required).

> Note: Host paths (for example, `./container_data/...`) do not exist inside the Vault container.  
> When you run Vault commands via `docker exec`, you must write the output to host files from the host shell.

#### 6.3.3.1 Recommended: use the repo AppRole bootstrap script (build_scripts)

The legacy export scripts have been removed. Use the build-script version instead:

- `./backend/build_scripts/postgress_approle_setup.sh`

This script runs the Vault CLI **inside** the Vault container and writes the AppRole artifacts to the host:

```text
./container_data/vault/approle/<ROLE_NAME>/
  role_id
  secret_id
```

Key behaviors:

- Defaults: `VAULT_CONTAINER=vault_production_node`, `ROLE_NAME=postgres_pgadmin_agent`
- Reads the Vault admin token from:
  - `./backend/app/security/configuration_files/vault/bootstrap/root_token`, or
  - `./backend/app/security/configuration_files/vault/bootstrap/root_token.json` (expects `.root_token`)
- If neither token file exists, it securely prompts for a token (input hidden).
- Rotates `secret_id` by default (`ROTATE_SECRET_ID=1`). Set `ROTATE_SECRET_ID=0` to keep the existing `secret_id`.

```bash
cd "$HOME/NETWORK_TOOLS"
chmod +x ./backend/build_scripts/postgress_approle_setup.sh

# Default behavior (recommended):
# - exports role_id
# - rotates secret_id
./backend/build_scripts/postgress_approle_setup.sh

# Override the role name (rare):
ROLE_NAME="postgres_pgadmin_agent" ./backend/build_scripts/postgress_approle_setup.sh

# Do NOT rotate secret_id (keep current secret_id if present):
ROTATE_SECRET_ID=0 ./backend/build_scripts/postgress_approle_setup.sh

# Custom output directory (optional):
OUT_DIR="$HOME/NETWORK_TOOLS/container_data/vault/approle/postgres_pgadmin_agent"   ./backend/build_scripts/postgress_approle_setup.sh
```

If the Vault Agent is logging **`no known role ID`**, re-run the script above and confirm the following files exist on the host and are readable by the container bind mount:

- `./container_data/vault/approle/postgres_pgadmin_agent/role_id`
- `./container_data/vault/approle/postgres_pgadmin_agent/secret_id`

#### 6.3.3.2 Manual commands (fully expanded; no script)


```bash
set -euo pipefail

cd "$HOME/NETWORK_TOOLS"
umask 077

# --- Vault container/CLI context ------------------------------------------------
VAULT_CONTAINER="vault_production_node"
VAULT_ADDR="https://vault_production_node:8200"
VAULT_CACERT_CONTAINER="/vault/certs/ca.crt"

# --- AppRole -------------------------------------------------------------------
ROLE_NAME="postgres_pgadmin_agent"

# --- Bootstrap token (host) ----------------------------------------------------
BOOTSTRAP_DIR="$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap"
VAULT_TOKEN="$(cat "$BOOTSTRAP_DIR/root_token")"

# --- Output directory (host) ---------------------------------------------------
OUT_DIR="$HOME/NETWORK_TOOLS/container_data/vault/approle/${ROLE_NAME}"
mkdir -p "$OUT_DIR"

# --- Fetch role_id -> host file ------------------------------------------------
docker exec \
  -e VAULT_ADDR="$VAULT_ADDR" \
  -e VAULT_CACERT="$VAULT_CACERT_CONTAINER" \
  -e VAULT_TOKEN="$VAULT_TOKEN" \
  "$VAULT_CONTAINER" \
  vault read -format=json "auth/approle/role/${ROLE_NAME}/role-id" \
| jq -r '.data.role_id' > "$OUT_DIR/role_id"

# --- Generate secret_id -> host file ------------------------------------------
docker exec \
  -e VAULT_ADDR="$VAULT_ADDR" \
  -e VAULT_CACERT="$VAULT_CACERT_CONTAINER" \
  -e VAULT_TOKEN="$VAULT_TOKEN" \
  "$VAULT_CONTAINER" \
  vault write -format=json -f "auth/approle/role/${ROLE_NAME}/secret-id" \
| jq -r '.data.secret_id' > "$OUT_DIR/secret_id"

# --- Lock down permissions and show results -----------------------------------
chmod 600 "$OUT_DIR/role_id" "$OUT_DIR/secret_id"
ls -lah "$OUT_DIR"

```

Operational notes:

- The Vault Agent’s AppRole auto-auth can delete the `secret_id` file after it reads it (recommended).
- If your AppRole is configured with `secret_id_num_uses=1`, you must generate a new `secret_id` when the agent restarts (depending on caching and how you tune the role).
- If the agent cannot authenticate, re-export the artifacts, then restart the agent container.


### 6.3.4 Vault Agent config + templates

Recommended repo paths (create these files in git, but do **not** commit role_id/secret_id):

```text
./backend/app/postgres/vault_agent/
  agent.hcl
  templates/
    postgres_db.ctmpl
    postgres_user.ctmpl
    postgres_password.ctmpl
    pgadmin_password.ctmpl
```

Example `agent.hcl` (KV v2 paths shown):

```hcl
pid_file = "/tmp/vault-agent.pid"

vault {
  address = "https://vault_production_node:8200"
  ca_cert = "/vault/ca/ca.crt"
}

auto_auth {
  method "approle" {
    config = {
      role_id_file_path                   = "/vault/approle/role_id"
      secret_id_file_path                 = "/vault/approle/secret_id"
      remove_secret_id_file_after_reading = true
    }
  }

  sink "file" {
    config = {
      path = "/vault/agent/token"
    }
  }
}

cache {
  use_auto_auth_token = true
}

template {
  source      = "/vault/templates/postgres_db.ctmpl"
  destination = "/vault/rendered/postgres_db"
  perms       = "0640"
}

template {
  source      = "/vault/templates/postgres_user.ctmpl"
  destination = "/vault/rendered/postgres_user"
  perms       = "0640"
}

template {
  source      = "/vault/templates/postgres_password.ctmpl"
  destination = "/vault/rendered/postgres_password"
  perms       = "0600"
}

template {
  source      = "/vault/templates/pgadmin_password.ctmpl"
  destination = "/vault/rendered/pgadmin_password"
  perms       = "0600"
}
```

Template examples (KV v2):

`postgres_db.ctmpl`
```ctmpl
{{- with secret "app_network_tools_secrets/data/postgres" -}}
{{ .Data.data.POSTGRES_DB }}
{{- end }}
```

`postgres_user.ctmpl`
```ctmpl
{{- with secret "app_network_tools_secrets/data/postgres" -}}
{{ .Data.data.POSTGRES_USER }}
{{- end }}
```

`postgres_password.ctmpl`
```ctmpl
{{- with secret "app_network_tools_secrets/data/postgres" -}}
{{ .Data.data.POSTGRES_PASSWORD }}
{{- end }}
```

`pgadmin_password.ctmpl`
```ctmpl
{{- with secret "app_network_tools_secrets/data/pgadmin" -}}
{{ .Data.data.PGADMIN_DEFAULT_PASSWORD }}
{{- end }}
```

### 6.3.5 Docker Compose wiring (vault-agent + shared secrets volume)

> **UPDATE (2025-12-23): the Vault Agent + shared rendered-secrets volume is implemented directly in `docker-compose.prod.yml`.**
>
> Canonical names in this repo:
> - Agent: `vault_agent_postgres_pgadmin`
> - Render volume: `postgres_vault_rendered`
> - Postgres: `postgres_primary`
> - pgAdmin: `pgadmin`

Key behaviors:

- The agent authenticates to Vault (AppRole material bind-mounted read-only at `/vault/approle`) and renders these files into the shared volume (mounted in the agent at `/vault/rendered`):
  - `postgres_db`
  - `postgres_user`
  - `postgres_password`
  - `pgadmin_password`

- `postgres_primary` mounts the same volume read-only at `/run/vault` and uses file-based inputs:
  - `POSTGRES_DB_FILE=/run/vault/postgres_db`
  - `POSTGRES_USER_FILE=/run/vault/postgres_user`
  - `POSTGRES_PASSWORD_FILE=/run/vault/postgres_password`

- `pgadmin` mounts the same volume read-only at `/run/vault` and uses:
  - `PGADMIN_DEFAULT_PASSWORD_FILE=/run/vault/pgadmin_password`

This is the “**always Vault**” posture: Postgres + pgAdmin do not rely on cleartext passwords in `.env` at runtime.

**Recommended hardening: agent healthcheck should verify all required rendered files**

If you use `depends_on: condition: service_healthy` (as this repo does for `postgres_primary` and `pgadmin`), ensure the agent only reports “healthy” once **all** required files exist and are non-empty. Example:

```yaml
healthcheck:
  test: ["CMD-SHELL", "test -s /vault/rendered/postgres_db && test -s /vault/rendered/postgres_user && test -s /vault/rendered/postgres_password && test -s /vault/rendered/pgadmin_password" ]
  interval: 5s
  timeout: 3s
  retries: 30
```

Notes:

- **Important:** If a container was created *before* you added these mounts/envs, you must **recreate** it to pick up the new wiring (see **6.3.6**).
- Legacy pattern: if you prefer keeping `docker-compose.prod.yml` unchanged, you can implement the same wiring in an override file; the repo no longer requires this.
### 6.3.6 Bring-up and verification


> **UPDATE (2025-12-23): bring-up order that matches tonight’s working stack**
>
> The correct ordering is:
>
> 1) Vault up → 2) Vault initialized/unsealed/seeded → 3) AppRole exported to host → 4) Vault Agent renders files → 5) Postgres consumes `*_FILE` → 6) pgAdmin consumes `*_FILE`
>
> If you run `docker compose up` on a service and Compose decides it must **recreate** a dependency, Vault may restart and return to a **sealed** state (expected behavior). To avoid accidental restarts while iterating, prefer `--no-deps` and/or `--no-recreate` when bringing up leaf services.



#### 6.3.6.1 Current bring-up commands (Approach 2: single compose file)

Run from the repo root (`~/NETWORK_TOOLS`) as your rootless Docker user.

1) Start Vault:

```bash
docker compose -f docker-compose.prod.yml up -d vault_production_node
docker logs --tail 200 -f vault_production_node
```

2) Initialize + unseal Vault if this is a brand-new instance (see Section 3.6). If Vault restarted and is sealed, **unseal** it again (Section 3.8).

3) Ensure the KV seed for Postgres/pgAdmin exists (this is the data your agent templates read):

```bash
# validate the secret exists (path may vary by your seeding convention)
docker exec -it vault_production_node sh -lc '
  export VAULT_ADDR=https://vault_production_node:8200
  export VAULT_CACERT=/vault/certs/ca.crt
  export VAULT_TOKEN="$(cat /vault/bootstrap/root_token 2>/dev/null || true)"
  vault kv get app_network_tools_secrets/postgres 2>/dev/null || true
  vault kv get app_network_tools_secrets/pgadmin 2>/dev/null || true
'
```

> Note: The KV mount name is currently `app_network_tools_secrets` (historical spelling). If you standardize the mount to `app_network_tools_secrets`, update the Vault Agent templates and validation commands accordingly.

4) Export AppRole `role_id` + `secret_id` onto the host (Section 6.3.3). This produces:

```text
./container_data/vault/approle/postgres_pgadmin_agent/role_id
./container_data/vault/approle/postgres_pgadmin_agent/secret_id
```

5) Start the Vault Agent and wait for it to be healthy:

```bash
docker compose -f docker-compose.prod.yml up -d vault_agent_postgres_pgadmin
docker logs --tail 200 -f vault_agent_postgres_pgadmin
docker compose -f docker-compose.prod.yml ps
```

6) Confirm rendered files exist inside the agent:

```bash
docker exec -it vault_agent_postgres_pgadmin sh -lc '
  ls -lah /vault/rendered &&
  echo &&
  for f in /vault/rendered/*; do
    echo "== $f ==";
    wc -c "$f";
  done
'
```

Expected files:

- `/vault/rendered/postgres_db`
- `/vault/rendered/postgres_user`
- `/vault/rendered/postgres_password`
- `/vault/rendered/pgadmin_password`

7) Start Postgres:

```bash
docker compose -f docker-compose.prod.yml up -d postgres_certs_init
docker logs postgres_certs_init

docker compose -f docker-compose.prod.yml up -d postgres_primary
docker logs --tail 200 -f postgres_primary
```

8) Start pgAdmin:

```bash
# If pgadmin was previously created without the /run/vault mount, force recreation:
docker compose -f docker-compose.prod.yml up -d --force-recreate pgadmin
docker logs --tail 200 -f pgadmin
```

9) If you want to bring up pgAdmin without touching dependencies (to avoid Vault restarts):

```bash
docker compose -f docker-compose.prod.yml up -d --no-deps --no-recreate pgadmin
```

#### 6.3.6.2 Troubleshooting: common Vault Agent errors

**A) Vault Agent: `error validating configuration: no auto_auth, cache, or listener block found`**

- Your `agent.hcl` is missing required blocks.
- Fix by ensuring `auto_auth { ... }` exists, and you are using a `template { ... }` stanza (or `template_config`) to render secrets.

**B) Vault Agent: `failed to read template: open /vault/templates/<name>.ctmpl: no such file or directory`**

- Your templates directory is not mounted, or the filename in `agent.hcl` does not match the template file on disk.
- Confirm the mount and paths:

**C) Vault Agent: `error creating file sink: ... open /run/vault/.vault-token.tmp... no such file or directory`**

- Cause: the sink directory does not exist (Vault Agent does not create it), or it is not writable.
- Fix (recommended): set the sink path to a directory that always exists and is writable in a hardened container, e.g. `/tmp/.vault-token` (with `tmpfs: ["/tmp"]`).
- Fix (alternative): pre-create the directory in the container entrypoint before starting the agent:

```sh
mkdir -p /run/vault
exec vault agent -config=/vault/agent/agent.hcl
```

**D) Vault Agent: `error getting path or data from method: error="no known role ID"`**

- Cause: `role_id` is missing/empty in the mounted AppRole directory, or the agent is pointed at the wrong path.
- Confirm from inside the agent container:

```bash
docker exec -it vault_agent_postgres_pgadmin sh -lc 'ls -lah /vault/approle && sed -n "1,2p" /vault/approle/role_id'
```

- If the file is missing, re-run the host-side export step (see **6.3.3**) to regenerate `role_id` and `secret_id`.

```bash
docker exec -it vault_agent_postgres_pgadmin sh -lc '
  ls -lah /vault/agent &&
  ls -lah /vault/templates &&
  grep -RIn "ctmpl" /vault/agent/agent.hcl || true
'
```

**C) pgAdmin: `/run/vault/pgadmin_password: No such file or directory`**

Root causes:
- `pgadmin` was created without the `postgres_vault_rendered:/run/vault:ro` mount, or
- the agent is not rendering the file yet.

Fix:
- Ensure `vault_agent_postgres_pgadmin` is **healthy** and the file exists in `/vault/rendered`.
- Recreate pgAdmin so it picks up the mount:

```bash
docker compose -f docker-compose.prod.yml up -d --force-recreate pgadmin
```


1) Ensure Vault is up and healthy:

```bash
docker compose -f docker-compose.prod.yml up -d vault_production_node
docker logs --tail 200 -f vault_production_node
```

2) Initialize/unseal/seed Vault (use your existing repo procedures in section 3.x).

3) Confirm the postgres + pgAdmin secrets exist in Vault (see **4.2** and **5.2**).

4) Export `role_id` + `secret_id` onto the host (see **6.3.3**).

5) Start the Vault Agent service:

```bash
docker compose -f docker-compose.prod.yml -f docker-compose.postgres_vault.override.yml up -d vault_agent_postgres_pgadmin
docker logs --tail 200 -f vault_agent_postgres_pgadmin
```

6) Confirm rendered files exist (example):

```bash
docker exec -it vault_agent_postgres_pgadmin sh -lc 'ls -lah /vault/rendered && echo "----" && sed -n "1,3p" /vault/rendered/postgres_user'
```

7) Start Postgres and pgAdmin:

```bash
docker compose -f docker-compose.prod.yml -f docker-compose.postgres_vault.override.yml up -d postgres_certs_init postgres_primary pgadmin
docker logs --tail 200 -f postgres_primary
docker logs --tail 200 -f pgadmin
```

### 6.3.7 Rotation and operational notes

- **Rotate the rendered secret files (AppRole `secret_id`)**
  - Generate a new `secret_id` (see **6.3.3**) and restart `vault_agent_postgres_pgadmin`.
  - If you configured `remove_secret_id_file_after_reading=true` in `agent.hcl`, the agent will delete the `secret_id` file after reading it; your operational runbook must account for recreating it before restarts.

- **Rotate the Postgres application user password (static credential)**
  - Important: updating Vault KV (or updating the rendered `/run/vault/postgres_password` file) does **not** rotate an already-initialized Postgres cluster. The password is stored inside Postgres.
  - Rotation requires two coordinated actions:

    1) **Change the password inside Postgres** (superuser action)

       Preferred (scripted): run the bootstrap script in rotate mode and apply the change to the running container:

       ```bash
       cd "$HOME/NETWORK_TOOLS"

       bash ./backend/build_scripts/generate_postgres_pgadmin_bootstrap_creds_and_seed.sh          --mode rotate          --vault-addr "https://vault_production_node:8200"          --ca-cert "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt"          --unseal-required 3          --prompt-token          --apply-to-postgres
       ```

       Manual (if you prefer not to exec from the script):

       ```bash
       NEW_PASSWORD="paste_a_new_password_here"

       APPUSER="$(docker exec -it postgres_primary sh -lc 'cat /run/vault/postgres_user' | tr -d '\r')"
       DBNAME="$(docker exec -it postgres_primary sh -lc 'cat /run/vault/postgres_db' | tr -d '\r')"

       docker exec -u postgres -it postgres_primary sh -lc          "psql -v ON_ERROR_STOP=1 -U postgres -d \"$DBNAME\" -c \"ALTER ROLE \\\"$APPUSER\\\" WITH PASSWORD '$NEW_PASSWORD';\""
       ```

       Notes:
       - Restarting `postgres_primary` without the `ALTER ROLE` step will **not** change the password.
       - This uses the local socket inside the container. Ensure your `pg_hba.conf` permits local superuser access.

    2) **Update Vault KV** so the rendered secret matches the new database value  
       If you used `--mode rotate`, the script already updated Vault. Otherwise:

       ```bash
       vault kv patch app_network_tools_secrets/postgres POSTGRES_PASSWORD="$NEW_PASSWORD"
       ```

    3) **Restart or reload clients** that authenticate using that password (pgAdmin, backend apps, etc.).

- **Rotate the pgAdmin default password (static credential)**
  - `PGADMIN_DEFAULT_PASSWORD(_FILE)` is used only for initial admin account creation.
  - To rotate it non-interactively, the simplest approach is to:
    1) update Vault KV (`app_network_tools_secrets/pgadmin`), and
    2) recreate the `pgadmin` container so it re-initializes (or change the password from the UI).

- **Prefer dynamic credentials for applications**
  - When you are ready, move application authentication to Vault dynamic database credentials (see **6.4**). This avoids long-lived static passwords and simplifies rotation.
### 6.4 Option C – Advanced: Vault Database secrets engine (dynamic credentials)


#### 6.4.1 What this enables (and what it is *not*)

Vault’s **database secrets engine** is for issuing **dynamic, time-bound database credentials** to applications and operators (for example: “give me a user that can read/write schema X for 1 hour”). It is also the mechanism Vault uses to **rotate** privileged database credentials (including “root rotation”) in a controlled way.

It is **not** a mechanism for Postgres to “phone home” to Vault on its own. Postgres will not natively call Vault at boot. Instead:

- **Option B (Vault Agent)** bootstraps Postgres/pgAdmin at container start by rendering files from Vault KV.
- **Option C (database secrets engine)** issues *new* Postgres users/passwords on-demand for your apps, and supports rotation.

You can (and usually should) run **both**: Option B for initial boot + Option C for app credentials and rotation.

#### 6.4.2 Prerequisites

- Vault is initialized and unsealed.
- Postgres (`postgres_primary`) is running and reachable from the Vault container over the Compose network.
- You have a Postgres “management” login that Vault will use to create/revoke dynamic users (recommended: a dedicated role, not your app user).
- Vault can validate Postgres TLS (recommended). If Postgres uses a different CA than Vault, mount the Postgres CA into `vault_production_node` (read-only) and use it in the connection URL.

**Recommended Compose hardening for this step (TLS verification):**

Add this mount to `vault_production_node`:

```yaml
services:
  vault_production_node:
    volumes:
      - ./backend/app/postgres/certs/ca.crt:/vault/postgres_certs/ca.crt:ro
```

#### 6.4.3 Create a dedicated Postgres management role for Vault

From the host, exec into Postgres and create a role with the minimum privileges needed to manage users.

Example (adjust DB name and privileges to your standards):

```bash
docker exec -it postgres_primary sh -lc '
  DB="$(cat /run/vault/postgres_db)"
  APPUSER="$(cat /run/vault/postgres_user)"
  APPPASS="$(cat /run/vault/postgres_password)"

  export PGSSLMODE=verify-full
  export PGSSLROOTCERT=/etc/postgres/certs/ca.crt
  export PGPASSWORD="$APPPASS"

  psql -h 127.0.0.1 -U "$APPUSER" -d "$DB" <<SQL
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = ''vault_admin'') THEN
    CREATE ROLE vault_admin WITH LOGIN CREATEROLE;
  END IF;
END
\$\$;

-- Set/rotate the password (you can generate a strong value and store it in Vault KV)
ALTER ROLE vault_admin WITH PASSWORD ''REPLACE_ME_STRONG_PASSWORD'';

-- Optional: if you need Vault to manage objects in a specific schema, grant accordingly
GRANT CONNECT ON DATABASE "'$DB'" TO vault_admin;
SQL
'
```

**Operational note:** Store `vault_admin`’s password in Vault KV and treat it like a managed secret. It is used only by Vault’s database plugin, not by application workloads.

#### 6.4.4 Enable and configure Vault’s PostgreSQL database connection

Enable the database secrets engine once:

```bash
docker exec -it vault_production_node sh -lc '
  export VAULT_ADDR=https://vault_production_node:8200
  export VAULT_CACERT=/vault/certs/ca.crt
  export VAULT_TOKEN="$(cat /vault/bootstrap/root_token 2>/dev/null || true)"

  vault secrets list | grep -q "^database/" || vault secrets enable database
'
```

Configure the connection (replace password and SSL parameters to match your setup):

```bash
docker exec -it vault_production_node sh -lc '
  export VAULT_ADDR=https://vault_production_node:8200
  export VAULT_CACERT=/vault/certs/ca.crt
  export VAULT_TOKEN="$(cat /vault/bootstrap/root_token 2>/dev/null || true)"

  vault write database/config/network_tools_pg     plugin_name=postgresql-database-plugin     allowed_roles="network_tools_app"     connection_url="postgresql://{{username}}:{{password}}@postgres_primary:5432/network_tools?sslmode=verify-full&sslrootcert=/vault/postgres_certs/ca.crt"     username="vault_admin"     password="REPLACE_ME_STRONG_PASSWORD"
'
```

If you cannot mount the Postgres CA yet, a temporary (less desirable) fallback is `sslmode=require`, but you should move to `verify-full` as soon as you can.

#### 6.4.5 Create a Vault role that defines how dynamic users are created

This is where you define the SQL Vault will run to create and revoke users.

Example role that grants basic DML on the `public` schema:

```bash
docker exec -it vault_production_node sh -lc '
  export VAULT_ADDR=https://vault_production_node:8200
  export VAULT_CACERT=/vault/certs/ca.crt
  export VAULT_TOKEN="$(cat /vault/bootstrap/root_token 2>/dev/null || true)"

  vault write database/roles/network_tools_app     db_name=network_tools_pg     default_ttl="1h"     max_ttl="24h"     creation_statements="
      CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD ''{{password}}'' VALID UNTIL ''{{expiration}}'';
      GRANT CONNECT ON DATABASE network_tools TO \"{{name}}\";
      GRANT USAGE ON SCHEMA public TO \"{{name}}\";
      GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO \"{{name}}\";
      ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO \"{{name}}\";
    "     revocation_statements="
      REASSIGN OWNED BY \"{{name}}\" TO vault_admin;
      DROP OWNED BY \"{{name}}\";
      DROP ROLE IF EXISTS \"{{name}}\";
    "
'
```

Adjust privileges (schema-specific, read-only, migrations, etc.) to match your application model.

#### 6.4.6 Fetch credentials and validate

Fetch a new set of credentials:

```bash
docker exec -it vault_production_node sh -lc '
  export VAULT_ADDR=https://vault_production_node:8200
  export VAULT_CACERT=/vault/certs/ca.crt
  export VAULT_TOKEN="$(cat /vault/bootstrap/root_token 2>/dev/null || true)"

  vault read -format=json database/creds/network_tools_app
'
```

Test from a one-off Postgres client container (recommended) or from within `postgres_primary`.

#### 6.4.7 Rotation (future-facing)

Once the database config is correct, Vault can rotate the management user password:

```bash
docker exec -it vault_production_node sh -lc '
  export VAULT_ADDR=https://vault_production_node:8200
  export VAULT_CACERT=/vault/certs/ca.crt
  export VAULT_TOKEN="$(cat /vault/bootstrap/root_token 2>/dev/null || true)"

  vault write -f database/rotate-root/network_tools_pg
'
```

This is the foundation for “eventually, Vault will generate DB passwords / rotate etc.”


This option is the most secure pattern for **applications** connecting to Postgres:
- Vault issues short-lived, revocable Postgres credentials on demand.
- Your application fetches credentials from Vault (or via Vault Agent templates) and renews them automatically.

Important limitation:
- This does **not** change how the `postgres` container itself initializes the database. It primarily improves how *other services* authenticate to Postgres after it is up.

High-level steps (outline):
1) Enable the database secrets engine in Vault (`vault secrets enable database`).
2) Configure a Postgres connection in Vault using an admin credential (managed carefully).
3) Create Vault roles that define SQL for creating/revoking users with TTLs.
4) Update your apps to request credentials from Vault at runtime.

When you adopt this, keep the initial bootstrap password in Vault as a break-glass/admin secret, but prefer dynamic roles for day-to-day service auth.


## 7. Keycloak Vault Integration Bootstrapping

This section mirrors the Postgres/pgAdmin pattern in **6.3** (Vault Agent renders secrets to a shared volume), but adapts it for Keycloak’s configuration model.

Keycloak is **not** expected to talk to Vault directly. Instead:

- A **Vault Agent** container authenticates with **AppRole**, reads KV secrets, and renders a file.
- The **Keycloak container** reads that rendered output at startup (via an entrypoint wrapper script).

### 7.1 Vault KV paths and required keys

This repo assumes KV v2 mounted at `app_network_tools_secrets`, and the following **existing** paths (you confirmed these are the canonical locations):

- `app_network_tools_secrets/keycloak_postgres`  
  Database connection settings for Keycloak (schema/user/password/host/port/database).

- `app_network_tools_secrets/keycloak_bootstrap`  
  Bootstrap admin credentials for first startup (or controlled re-bootstrap).

- `app_network_tools_secrets/keycloak_runtime`  
  Runtime settings such as hostname/proxy mode/listeners/observability flags.

- `app_network_tools_secrets/keycloak_tls`  
  TLS material for Keycloak (server certificate and private key). This repo stores PEM values as **base64 strings** in Vault and decodes them in Vault Agent templates.

For KV v2, the Vault API paths used by the agent include `/data/` (example: `app_network_tools_secrets/data/keycloak_postgres`).

Minimum recommended keys per path:

**A) `app_network_tools_secrets/keycloak_postgres`**

- `KC_DB` (recommended: `postgres`)
- `KC_DB_URL_HOST` (example: `postgres_primary`)
- `KC_DB_URL_PORT` (example: `5432`)
- `KC_DB_URL_DATABASE` (example: `keycloak`)
- `KC_DB_USERNAME` (example: `keycloak`)
- `KC_DB_PASSWORD` (random, high-entropy)
- `KC_DB_SCHEMA` (example: `keycloak`)

**B) `app_network_tools_secrets/keycloak_bootstrap`**

- `KC_BOOTSTRAP_ADMIN_USERNAME` (example: `admin`)
- `KC_BOOTSTRAP_ADMIN_PASSWORD` (random, high-entropy)

**C) `app_network_tools_secrets/keycloak_runtime`** (optional keys; only set what you need)

- `KC_HOSTNAME` (example: `keycloak.yourdomain.edu`)
- `KC_HOSTNAME_STRICT` (`true` or `false`)
- `KC_PROXY_HEADERS` (typical values depend on your L7 proxy; confirm in Keycloak docs)
- `KC_HTTP_ENABLED` (`true` or `false`)
- `KC_HTTPS_PORT` (example: `8443` when exposing 8443)
- `KC_HEALTH_ENABLED` (`true` or `false`)
- `KC_METRICS_ENABLED` (`true` or `false`)
- `KC_LOG_LEVEL` (example: `INFO`)

`keycloak_tls` (TLS material, base64-encoded PEM):

- `KC_HTTPS_CERTIFICATE_PEM_B64` (base64 of the server certificate PEM)
- `KC_HTTPS_CERTIFICATE_KEY_PEM_B64` (base64 of the server private key PEM)

### 7.2 Seeding Keycloak secrets into Vault

You can seed Keycloak secrets either via the repo seeding workflow (recommended), or via direct `vault kv put` commands.

Manual seeding examples (from the host, using `docker exec` into the Vault container):

```bash
# DB config
docker exec -e VAULT_ADDR="https://vault_production_node:8200" \
  -e VAULT_CACERT="/vault/certs/ca.crt" \
  -e VAULT_TOKEN="$(cat ./backend/app/security/configuration_files/vault/bootstrap/root_token)" \
  vault_production_node \
  vault kv put app_network_tools_secrets/keycloak_postgres \
    KC_DB="postgres" \
    KC_DB_URL_HOST="postgres_primary" \
    KC_DB_URL_PORT="5432" \
    KC_DB_URL_DATABASE="keycloak" \
    KC_DB_USERNAME="keycloak" \
    KC_DB_PASSWORD="<REDACTED>" \
    KC_DB_SCHEMA="keycloak"

# Bootstrap admin (treat as sensitive; rotate after first use)
docker exec -e VAULT_ADDR="https://vault_production_node:8200" \
  -e VAULT_CACERT="/vault/certs/ca.crt" \
  -e VAULT_TOKEN="$(cat ./backend/app/security/configuration_files/vault/bootstrap/root_token)" \
  vault_production_node \
  vault kv put app_network_tools_secrets/keycloak_bootstrap \
    KC_BOOTSTRAP_ADMIN_USERNAME="admin" \
    KC_BOOTSTRAP_ADMIN_PASSWORD="<REDACTED>"

# Runtime knobs
docker exec -e VAULT_ADDR="https://vault_production_node:8200" \
  -e VAULT_CACERT="/vault/certs/ca.crt" \
  -e VAULT_TOKEN="$(cat ./backend/app/security/configuration_files/vault/bootstrap/root_token)" \
  vault_production_node \
  vault kv put app_network_tools_secrets/keycloak_runtime \
    KC_HOSTNAME="keycloak.yourdomain.edu" \
    KC_HOSTNAME_STRICT="true" \
    KC_HTTP_ENABLED="false" \
    KC_HTTPS_PORT="8443" \
    KC_HEALTH_ENABLED="true" \
    KC_METRICS_ENABLED="true" \
    KC_LOG_LEVEL="INFO"
```

Validation (KV v2):

```bash
docker exec -e VAULT_ADDR="https://vault_production_node:8200" \
  -e VAULT_CACERT="/vault/certs/ca.crt" \
  -e VAULT_TOKEN="$(cat ./backend/app/security/configuration_files/vault/bootstrap/root_token)" \
  vault_production_node \
  vault kv get -format=json app_network_tools_secrets/keycloak_postgres | jq -r '.data.data'
```


#### 7.2.1 TLS material (local certs → Vault KV)

If you run Keycloak in production mode with HTTPS enabled (`KC_HTTP_ENABLED="false"`), you must provide Keycloak with a certificate and private key.

This repo’s Vault Agent templates expect **base64-encoded PEM** values stored in Vault:

- `KC_HTTPS_CERTIFICATE_PEM_B64`
- `KC_HTTPS_CERTIFICATE_KEY_PEM_B64`

Recommended workflow:

1) Generate local Keycloak TLS material (repo-managed files):

```bash
cd "$HOME/NETWORK_TOOLS"
HERE!
# Generates backend/app/keycloak/certs/{server.crt,server.key,ca.crt}
bash ./backend/build_scripts/generate_local_keycloak_certs.sh
```

```bash
Your file structure should look similar to this now. 

developer_network_tools@networktoolsvm:~/NETWORK_TOOLS$ tree --charset ascii
.
|-- backend
|   |-- app
|   |   |-- keycloak
|   |   |   |-- bin
|   |   |   |   `-- keycloak_entrypoint_from_vault.sh
|   |   |   |-- certs
|   |   |   |   |-- ca.crt
|   |   |   |   |-- ca.key
|   |   |   |   |-- ca.srl
|   |   |   |   |-- cert.crt
|   |   |   |   `-- cert.key
|   |   |   `-- vault_agent
|   |   |       |-- agent.hcl
|   |   |       |-- keycloak_agent_policy.hcl
|   |   |       `-- templates
|   |   |           |-- keycloak.env.ctmpl
|   |   |           |-- keycloak_tls.crt.ctmpl
|   |   |           `-- keycloak_tls.key.ctmpl
|   |   |-- mariadb_queries
|   |   |-- postgres
|   |   |   |-- certs
|   |   |   |   |-- ca.crt
|   |   |   |   |-- ca.key
|   |   |   |   |-- ca.srl
|   |   |   |   |-- cert.crt
|   |   |   |   `-- cert.key
|   |   |   |-- config
|   |   |   |   |-- pg_hba.conf
|   |   |   |   `-- postgres.conf
|   |   |   `-- vault_agent
|   |   |       |-- agent.hcl
|   |   |       `-- templates
|   |   |           |-- pgadmin_password.ctmpl
|   |   |           |-- postgres_db.ctmpl
|   |   |           |-- postgres_password.ctmpl
|   |   |           `-- postgres_user.ctmpl
|   |   |-- routers
|   |   `-- security
|   |       `-- configuration_files
|   |           `-- vault
|   |               |-- bootstrap
|   |               |   |-- postgres_pgadmin_credentials.json
|   |               |   |-- postgres_pgadmin.env
|   |               |   |-- root_token
|   |               |   |-- root_token.json
|   |               |   |-- seeded_secrets_all.json
|   |               |   |-- seed_kv_spec.postgres_pgadmin.json
|   |               |   `-- unseal_keys.json
|   |               |-- certs
|   |               |   |-- ca.crt
|   |               |   |-- ca.key
|   |               |   |-- ca.srl
|   |               |   |-- cert.crt
|   |               |   `-- cert.key
|   |               |-- config
|   |               |   |-- certs
|   |               |   |-- keycloak_kv_read.hcl
|   |               |   |-- postgres_pgadmin_kv_read.hcl
|   |               |   `-- vault_configuration_primary_node.hcl
|   |               `-- Dockerfile
|   |-- build_scripts
|   |   |-- generate_local_keycloak_certs.sh
|   |   |-- generate_local_postgres_certs.sh
|   |   |-- generate_local_vault_certs.sh
|   |   |-- generate_postgres_pgadmin_bootstrap_creds_and_seed.sh
|   |   |-- guides
|   |   |   |-- seed_kv_spec.example.json
|   |   |   `-- seed_kv_spec.GUIDE.md
|   |   |-- keycloak_approle_setup.sh
|   |   |-- postgress_approle_setup.sh
|   |   |-- startover_scripts
|   |   |   `-- reset_network_tools_docker.sh
|   |   |-- vault_first_time_init_only_rootless.sh
|   |   |-- vault_unseal_kv_seed_bootstrap_rootless.sh
|   |   `-- vault_unseal_multi_kv_seed_bootstrap_rootless.sh
|   `-- nginx
|-- container_data
|   `-- vault
|       |-- approle
|       |   `-- postgres_pgadmin_agent
|       `-- data
|           |-- logs
|           |   `-- audit.log
|           |-- raft
|           |   |-- raft.db
|           |   `-- snapshots
|           `-- vault.db
|-- docker-compose.prod.yml
|-- environment_variable_guide.md
|-- frontend
|-- how_to_videos
|   |-- HOW_TO_3.2 Validate Certificates.mov
|   |-- HOW_TO_3.3 Start Vault with Docker Compose.mov
|   |-- HOW_TO_3.6 Initialize and Unseal Vault (First Run).mov
|   |-- HOW_TO_3.8.3 Single-Mount Seeder (vault_unseal_kv_seed_bootstrap_rootless.sh).mov
|   `-- HOW_TO_3.8.4 Multi-Mount Seeder (vault_unseal_multi_kv_seed_bootstrap_rootless.sh).mov
|-- README.full.md
`-- README.md
```
2) Seed those files into Vault (encode as base64 to preserve newlines safely):

```bash
cd "$HOME/NETWORK_TOOLS"

CERT_B64="$(base64 -w0 ./backend/app/keycloak/certs/server.crt)"
KEY_B64="$(base64 -w0 ./backend/app/keycloak/certs/server.key)"

docker exec -e VAULT_ADDR="https://vault_production_node:8200"   -e VAULT_CACERT="/vault/certs/ca.crt"   -e VAULT_TOKEN="$(cat ./backend/app/security/configuration_files/vault/bootstrap/root_token)"   vault_production_node   vault kv put app_network_tools_secrets/keycloak_tls     KC_HTTPS_CERTIFICATE_PEM_B64="$CERT_B64"     KC_HTTPS_CERTIFICATE_KEY_PEM_B64="$KEY_B64"
```

3) Verify:

```bash
docker exec -e VAULT_ADDR="https://vault_production_node:8200"   -e VAULT_CACERT="/vault/certs/ca.crt"   -e VAULT_TOKEN="$(cat ./backend/app/security/configuration_files/vault/bootstrap/root_token)"   vault_production_node   vault kv get app_network_tools_secrets/keycloak_tls
```

Vault Agent will decode and render:

- `/run/vault/tls/server.crt`
- `/run/vault/tls/server.key`



### 7.3 Vault Agent sidecar for Keycloak

The Keycloak Vault Agent follows the same primitives as Postgres/pgAdmin:

1) Least-privilege policy
2) AppRole bound to that policy
3) Host-side export of `role_id` + `secret_id`
4) Agent renders `/run/vault/keycloak.env` (mounted as a shared volume)

#### 7.3.1 Create a least-privilege Vault policy

Create a dedicated policy (example name: `keycloak_agent`) that grants **read-only** access to the three KV paths:

```hcl
# keycloak_agent_policy.hcl
path "auth/token/lookup-self" { capabilities = ["read"] }
path "auth/token/renew-self"  { capabilities = ["update"] }

path "app_network_tools_secrets/data/keycloak_postgres"   { capabilities = ["read"] }
path "app_network_tools_secrets/data/keycloak_bootstrap" { capabilities = ["read"] }
path "app_network_tools_secrets/data/keycloak_runtime"   { capabilities = ["read"] }

# Optional metadata access for troubleshooting
path "app_network_tools_secrets/metadata/keycloak_postgres"   { capabilities = ["list","read"] }
path "app_network_tools_secrets/metadata/keycloak_bootstrap" { capabilities = ["list","read"] }
path "app_network_tools_secrets/metadata/keycloak_runtime"   { capabilities = ["list","read"] }
```

Apply it:

```bash
docker exec -e VAULT_ADDR="https://vault_production_node:8200" \
  -e VAULT_CACERT="/vault/certs/ca.crt" \
  -e VAULT_TOKEN="$(cat ./backend/app/security/configuration_files/vault/bootstrap/root_token)" \
  vault_production_node \
  vault policy write keycloak_agent /vault/policies/keycloak_agent_policy.hcl
```

#### 7.3.2 Create an AppRole for the Keycloak agent

```bash
docker exec -e VAULT_ADDR="https://vault_production_node:8200" \
  -e VAULT_CACERT="/vault/certs/ca.crt" \
  -e VAULT_TOKEN="$(cat ./backend/app/security/configuration_files/vault/bootstrap/root_token)" \
  vault_production_node \
  vault write auth/approle/role/keycloak_agent \
    token_policies="keycloak_agent" \
    token_ttl="20m" token_max_ttl="60m" \
    secret_id_ttl="24h" secret_id_num_uses=1
```

#### 7.3.3 Host-side export script (role_id + secret_id)

Standardize on the same host artifact pattern used elsewhere:

- Host directory: `./container_data/vault/approle/keycloak_agent/`
- Files:
  - `role_id`
  - `secret_id`

Recommended: use the repo script:

```bash
bash ./backend/build_scripts/keycloak_approle_setup.sh \
  --ca-cert "./backend/app/security/configuration_files/vault/certs/ca.crt"
```

```bash
|-- backend
|   |-- app
|   |   |-- keycloak
|   |   |   |-- bin
|   |   |   |   `-- keycloak_entrypoint_from_vault.sh
|   |   |   |-- certs
|   |   |   |   |-- ca.crt
|   |   |   |   |-- ca.key
|   |   |   |   |-- ca.srl
|   |   |   |   |-- cert.crt
|   |   |   |   `-- cert.key
|   |   |   `-- vault_agent
|   |   |       |-- agent.hcl
|   |   |       |-- keycloak_agent_policy.hcl
|   |   |       `-- templates
|   |   |           |-- keycloak.env.ctmpl
|   |   |           |-- keycloak_tls.crt.ctmpl
|   |   |           `-- keycloak_tls.key.ctmpl
|   |   |-- mariadb_queries
|   |   |-- postgres
|   |   |   |-- certs
|   |   |   |   |-- ca.crt
|   |   |   |   |-- ca.key
|   |   |   |   |-- ca.srl
|   |   |   |   |-- cert.crt
|   |   |   |   `-- cert.key
|   |   |   |-- config
|   |   |   |   |-- pg_hba.conf
|   |   |   |   `-- postgres.conf
|   |   |   `-- vault_agent
|   |   |       |-- agent.hcl
|   |   |       `-- templates
|   |   |           |-- pgadmin_password.ctmpl
|   |   |           |-- postgres_db.ctmpl
|   |   |           |-- postgres_password.ctmpl
|   |   |           `-- postgres_user.ctmpl
|   |   |-- routers
|   |   `-- security
|   |       `-- configuration_files
|   |           `-- vault
|   |               |-- bootstrap
|   |               |   |-- postgres_pgadmin_credentials.json
|   |               |   |-- postgres_pgadmin.env
|   |               |   |-- root_token
|   |               |   |-- root_token.json
|   |               |   |-- seeded_secrets_all.json
|   |               |   |-- seed_kv_spec.postgres_pgadmin.json
|   |               |   `-- unseal_keys.json
|   |               |-- certs
|   |               |   |-- ca.crt
|   |               |   |-- ca.key
|   |               |   |-- ca.srl
|   |               |   |-- cert.crt
|   |               |   `-- cert.key
|   |               |-- config
|   |               |   |-- certs
|   |               |   |-- keycloak_kv_read.hcl
|   |               |   |-- postgres_pgadmin_kv_read.hcl
|   |               |   `-- vault_configuration_primary_node.hcl
|   |               `-- Dockerfile
|   |-- build_scripts
|   |   |-- generate_local_keycloak_certs.sh
|   |   |-- generate_local_postgres_certs.sh
|   |   |-- generate_local_vault_certs.sh
|   |   |-- generate_postgres_pgadmin_bootstrap_creds_and_seed.sh
|   |   |-- guides
|   |   |   |-- seed_kv_spec.example.json
|   |   |   `-- seed_kv_spec.GUIDE.md
|   |   |-- keycloak_approle_setup.sh
|   |   |-- postgress_approle_setup.sh
|   |   |-- startover_scripts
|   |   |   `-- reset_network_tools_docker.sh
|   |   |-- vault_first_time_init_only_rootless.sh
|   |   |-- vault_unseal_kv_seed_bootstrap_rootless.sh
|   |   `-- vault_unseal_multi_kv_seed_bootstrap_rootless.sh
|   `-- nginx
|-- container_data
|   `-- vault
|       |-- approle
|       |   |-- keycloak_agent
|       |   |   |-- role_id <-- NEW
|       |   |   `-- secret_id <-- NEW
|       |   `-- postgres_pgadmin_agent
|       `-- data
|           |-- logs
|           |   `-- audit.log
|           |-- raft
|           |   |-- raft.db
|           |   `-- snapshots
|           `-- vault.db
|-- docker-compose.prod.yml
|-- environment_variable_guide.md
|-- frontend
|-- how_to_videos
|   |-- HOW_TO_3.2 Validate Certificates.mov
|   |-- HOW_TO_3.3 Start Vault with Docker Compose.mov
|   |-- HOW_TO_3.6 Initialize and Unseal Vault (First Run).mov
|   |-- HOW_TO_3.8.3 Single-Mount Seeder (vault_unseal_kv_seed_bootstrap_rootless.sh).mov
|   `-- HOW_TO_3.8.4 Multi-Mount Seeder (vault_unseal_multi_kv_seed_bootstrap_rootless.sh).mov
|-- README.full.md
`-- README.md
```

Validate the files:

```bash
ls -lah ./container_data/vault/approle/keycloak_agent
sed -n "1,2p" ./container_data/vault/approle/keycloak_agent/role_id
sed -n "1,2p" ./container_data/vault/approle/keycloak_agent/secret_id
```

#### 7.3.4 Vault Agent config + template

Recommended directory layout:

```
backend/app/keycloak/vault_agent/
  agent.hcl
  templates/
    keycloak.env.ctmpl
```

Key guidance based on observed failures:

- Vault Agent templates do **not** support Sprig’s `default` function. Use `or`, `if`, and `with`.
- Avoid `%!q(<nil>)` output by guarding optional values (only emit lines when keys exist).
- Prefer the token sink under `/tmp` (tmpfs) to avoid `/run/vault` directory issues.

Template destination:

- Agent writes: `/vault/rendered/keycloak.env`
- Keycloak container mounts the same volume at: `/run/vault/keycloak.env`

#### 7.3.5 Docker Compose wiring

High-level compose requirements:

- A named volume (example): `keycloak_vault_rendered`
- `vault_agent_keycloak` mounts it at `/vault/rendered`
- `keycloak` mounts it read-only at `/run/vault`

A minimal (representative) pattern:

```yaml
volumes:
  keycloak_vault_rendered:

services:
  vault_agent_keycloak:
    image: hashicorp/vault:1.21.1
    container_name: vault_agent_keycloak
    restart: unless-stopped
    depends_on:
      - vault_production_node
    entrypoint: ["/bin/sh","-lc","exec vault agent -config=/vault/agent/agent.hcl" ]
    read_only: true
    tmpfs:
      - /tmp
      - /run
    volumes:
      - ./backend/app/security/configuration_files/vault/certs/ca.crt:/vault/ca/ca.crt:ro
      - ./backend/app/keycloak/vault_agent/agent.hcl:/vault/agent/agent.hcl:ro
      - ./backend/app/keycloak/vault_agent/templates:/vault/templates:ro
      - ./container_data/vault/approle/keycloak_agent:/vault/approle:ro
      - keycloak_vault_rendered:/vault/rendered
    healthcheck:
      test: ["CMD-SHELL","test -s /vault/rendered/keycloak.env" ]
      interval: 5s
      timeout: 3s
      retries: 30

  keycloak:
    # Pin a specific stable version (do not use :latest)
    image: quay.io/keycloak/keycloak:<PINNED_VERSION>
    container_name: keycloak
    restart: unless-stopped
    depends_on:
      vault_agent_keycloak:
        condition: service_healthy
      postgres_primary:
        condition: service_started
    volumes:
      - keycloak_vault_rendered:/run/vault:ro
      - ./backend/app/keycloak/scripts/keycloak_entrypoint_from_vault.sh:/opt/keycloak/bin/keycloak_entrypoint_from_vault.sh:ro
    entrypoint: ["/bin/bash","/opt/keycloak/bin/keycloak_entrypoint_from_vault.sh"]
    command: ["start","--optimized"]
```

#### 7.3.6 Bring-up and verification

1) Ensure Vault is initialized/unsealed and seeded.

2) Ensure the Keycloak AppRole artifacts exist (see **7.3.3**).

3) Start the agent and confirm it is healthy:

```bash
docker compose -f docker-compose.prod.yml up -d vault_agent_keycloak
docker logs --tail 200 -f vault_agent_keycloak
docker exec -it vault_agent_keycloak sh -lc 'ls -lah /vault/rendered && echo "----" && sed -n "1,40p" /vault/rendered/keycloak.env'
```

4) Start Keycloak:

```bash
docker compose -f docker-compose.prod.yml up -d keycloak
docker logs --tail 200 -f keycloak
```

#### 7.3.7 Troubleshooting

**A) Agent log: `vault.read(...): no secret exists at app_network_tools_secrets/data/keycloak_runtime`**

- Cause: the KV path has not been seeded (or you seeded a different mount/path).
- Confirm with KV v2 aware command:

```bash
docker exec -e VAULT_ADDR="https://vault_production_node:8200" \
  -e VAULT_CACERT="/vault/certs/ca.crt" \
  -e VAULT_TOKEN="$(cat ./backend/app/security/configuration_files/vault/bootstrap/root_token)" \
  vault_production_node \
  vault kv get app_network_tools_secrets/keycloak_runtime
```

**B) Agent log: `parse: template: ... function "default" not defined`**

- Fix: remove `default` usage; use `or` / `if` / `with`.

**C) Rendered env shows `%!q(<nil>)`**

- Cause: template is calling `printf "%q"` on a missing key.
- Fix: guard optional keys and only emit the line if the key exists and is non-empty.

**D) Agent log: `error creating file sink ... /run/vault/.vault-token.tmp... no such file or directory`**

- Fix: change sink path to `/tmp/.vault-token` (with `tmpfs: ["/tmp"]`), or create the directory before starting the agent.

**E) Agent log: `no known role ID`**

- Cause: `/vault/approle/role_id` is missing or empty.
- Fix: confirm the mount, then regenerate artifacts by re-running **7.3.3**.


**F) Agent log: `error creating file sink: could not parse 'mode' as integer`**

- Cause: `mode` was provided as a string (quoted) or as a symbolic mode (example: `-r--------`). Vault Agent expects an **integer** file mode.
- Fix: use an unquoted numeric value (example: `mode = 0400`) in the sink stanza.

**G) Agent log: `template: :3: function "fail" not defined`**

- Cause: Vault Agent templating does not expose a `fail` function in the function set you are using.
- Fix: remove `fail` calls and instead guard keys with `if` checks. Rely on the agent healthcheck (or application start checks) to catch missing required values.

**H) Rendered env file header is glued to the first variable (example: `#---KC_DB="postgres"`), and Keycloak reports `KC_DB` missing**

- Cause: the template does not emit a newline after the header comment block.
- Fix: ensure there is a real newline after the header so the first exported variable starts on its own line, then restart the Vault Agent container.

**I) Keycloak container logs: `/opt/keycloak/bin/kc: No such file or directory`**

- Cause: modern Keycloak images ship the CLI as `kc.sh`, not `kc`.
- Fix: call `/opt/keycloak/bin/kc.sh` from your entrypoint script.

**J) Keycloak logs: `FATAL: password authentication failed for user "keycloak"`**

- Cause: the `keycloak` role exists in Postgres but the password in the cluster does not match the password stored in Vault (or the role/database is missing).
- Fix: run the Postgres “apply/sync” step (see **4.5**). This aligns Postgres roles/databases with Vault and is the required step whenever you rotate credentials.


#### 7.3.8 Rotation and operational notes

- **Bootstrap admin credentials:** treat `KC_BOOTSTRAP_ADMIN_*` as a bootstrap mechanism. After initial admin setup, rotate and/or restrict access to the `keycloak_bootstrap` secret.
- **Database password rotation:** rotating `KC_DB_PASSWORD` requires updating Postgres (ALTER ROLE/USER) and then updating the Vault secret; coordinate controlled restarts.
- **AppRole Secret IDs:** if you enforce `secret_id_num_uses=1`, regeneration is expected. Re-run **7.3.3** to mint a new `secret_id` after redeployments.

### 7.4 Keycloak hardening notes

Practical hardening items that typically apply cleanly in this deployment model:

- Pin Keycloak image version and treat upgrades as change-controlled.
- Run Keycloak as a non-root user (the upstream image defaults to non-root; keep it that way).
- Set `security_opt: ["no-new-privileges:true"]` and drop Linux capabilities (`cap_drop: ["ALL"]`) unless you have a measured need.
- Restrict published ports (prefer internal networking + reverse proxy / load balancer when available).
- Keep the Vault Agent container read-only, with `tmpfs` for `/tmp` and a dedicated secrets-render volume for `/vault/rendered`.



## Appendix A – Certificate Management

### A.1 Vault TLS Certificates – What to Keep and Where

The local Vault TLS setup uses a small script to generate a private CA and a server certificate for the Vault container. The script typically produces the following key files:

- `ca.crt`   – CA certificate (public)
- `ca.key`   – CA private key (**sensitive**)
- `cert.crt` – Vault server certificate (full chain; public)
- `cert.key` – Vault server private key (**sensitive**)

Any intermediate files (CSRs, temporary leaf certs, extfiles, etc.) are treated as ephemeral and can be discarded after a successful run.

#### 1. Files That Must Be Treated as Secrets

These files **must never** be committed to git or shared outside secure channels:

- **`ca.key` (CA private key)**  
  - This is the root of trust for this local CA.  
  - Anyone who obtains this can mint certificates that will be trusted wherever `ca.crt` is trusted.  
  - Keep it only:
    - On your admin machine, or
    - In a designated secure location on the server with restricted permissions.
  - Back it up to encrypted/offline storage (e.g., password manager attachment, encrypted archive, secure USB).
  - If/when you rotate the CA, this is the file you intentionally retire or destroy.

- **`cert.key` (Vault server private key)**  
  - Needed by Vault at runtime but must remain private.  
  - Should only live on the Vault host, under tight permissions (e.g., `chmod 600`).  
  - Never commit this to git. If backed up, treat it as any other secret (encrypted backup, not stored in the repo).

#### 2. Files That Can Be Safely Distributed

These files are public by design and can be shared with clients/services that need to trust Vault:

- **`ca.crt` (CA certificate)**  
  - Public certificate corresponding to `ca.key`.  
  - Clients and tools that need to trust Vault’s TLS certificate import this CA.  
  - It is acceptable to distribute this to any system that should trust Vault.  
  - Even though it is public, it is still recommended to keep it out of the application source tree and treat it as generated data rather than source code.

- **`cert.crt` (Vault server certificate / full chain)**  
  - Contains the Vault server certificate (and usually the CA chain).  
  - No private key material is present.  
  - Safe to inspect, copy, and distribute as needed.  
  - Can be regenerated as long as `ca.key` is available.

#### 3. Recommended Project Layout and Git Hygiene

By default, the script writes certs to a path similar to:

```text
backend/app/security/configuration_files/vault/certs/
```

Recommended practices:

1. **Ignore the cert directory / Other important files in git**

   Add the following to `.gitignore` (from the project root):

   ```gitignore
   # OS-specific junk
    .DS_Store
    Thumbs.db
    
    # Python artifacts
    __pycache__/
    *.py[cod]
    *.pyo
    
    # Virtual environments
    .venv/
    venv/
    
    # Logs
    logs/
    *.log
    
    # Local override files
    .env
    .env.*
    
    # Cert Directory
    backend/app/security/configuration_files/vault/certs/
    
    # JetBrains IDE
    .idea/
    
    # --- TLS private keys (never commit) ---
    *.key
    *.key.pem
    *.p12
    *.pfx
    
    # --- Certificates (optional: ignore if you generate locally) ---
    *.crt
    *.cer
    *.pem
    *.der
    
    # --- Vault bootstrap artifacts (never commit) ---
    **/bootstrap/**
    **/unseal_keys*.json
    **/root_token*
    **/seeded_secrets*.json
    
    # --- CA serial files ---
    *.srl
   ```

   This prevents accidental commits of `ca.key`, `cert.key`, `ca.crt`, or `cert.crt` and any other important files.


2. **Use the cert directory as the runtime mount for Vault**

   - Keep all cert-related files under `backend/app/security/configuration_files/vault/certs/`.
   - Mount that directory into the Vault container (e.g., `/vault/certs`) via `docker-compose`.
   - Recommended permissions on the host:

     ```bash
     chmod 700 backend/app/security/configuration_files/vault/certs
     chmod 600 backend/app/security/configuration_files/vault/certs/ca.key
     chmod 600 backend/app/security/configuration_files/vault/certs/cert.key
     chmod 644 backend/app/security/configuration_files/vault/certs/ca.crt
     chmod 644 backend/app/security/configuration_files/vault/certs/ca.crt
     ```

3. **Perform a one-time secure backup of critical keys**

   After the script runs and Vault is confirmed working, back up at least:

   - `ca.key` (mandatory)
   - `cert.key` (optional, but convenient if you don’t want to reissue)

   Store these backups in encrypted/offline storage (not in the repo, not on shared drives).

#### 4. Minimal “Must-Keep” List

If you are comfortable re-running the script and re-issuing certificates when needed:

- **Absolutely must keep and protect securely:**
  - `ca.key`

- **Should be kept with Vault for runtime and may be backed up:**
  - `cert.key`
  - `ca.crt`
  - `cert.crt`

In short:

- `ca.key` and `cert.key` are **secrets**. Protect them and never commit them.  
- `ca.crt` and `cert.crt` are **public certs**. Safe to distribute, but best kept in a non-versioned `certs/` directory rather than in the source tree.  
- The entire `vault/certs` directory should be treated as generated runtime data and excluded from git.



## A.2 Rootless Docker and Subordinate UID/GID Ranges (subuid/subgid)

Rootless Docker runs containers **without using real root** on the host. Inside a container, processes may think they are running as `root` (UID `0`), but on the host we **must not** grant real root privileges.

Linux solves this using **user namespaces**: container user IDs (UIDs) and group IDs (GIDs) are **mapped** to a block of normal, unprivileged IDs on the host. That block is called your **subordinate UID/GID ranges**.

## What are UID/GID ranges?

- **UID** = user ID (who owns files / runs processes)
- **GID** = group ID (group ownership/permissions)
- **Subordinate range** = a block of IDs your user is allowed to use inside a user namespace

These are configured in:

- `/etc/subuid` (UID ranges)
- `/etc/subgid` (GID ranges)

A typical entry looks like:

```text
developer_network_tools:100000:65536
```

Meaning:

- `developer_network_tools` = the username
- `100000` = starting ID
- `65536` = how many IDs are allocated

This grants a host-side range of:

- `100000` through `165535` (65,536 IDs total)

## Why “at least 65,536”?

Many container images and tooling expect a reasonably large ID space for creating users/groups inside containers. The common default is **65,536** (`2^16`). Smaller ranges can cause unexpected permission errors or failures when containers try to create additional users/groups.

## How to check your current ranges

```bash
whoami
grep "^$(whoami):" /etc/subuid
grep "^$(whoami):" /etc/subgid
```

You should see **one line in each file** for your user, and the last number should be **65536** (or higher).

## How to set the ranges (Ubuntu)

Run as an admin user (or via sudo):

```bash
sudo usermod --add-subuids 100000-165535 --add-subgids 100000-165535 $(whoami)
```

Re-check:

```bash
grep "^$(whoami):" /etc/subuid /etc/subgid
```

Then **log out and log back in** (or reboot) so the session picks up the changes.

## Common symptoms when this is missing or wrong

- Rootless Docker daemon fails to start
- Containers fail to run, or fail on file permission operations
- Bind mounts/volumes create files owned by “weird” numeric IDs (because mappings are broken)

This is expected behavior when user namespace ID mapping is not configured correctly.


## Appendix B – Container Hardening Recommendations (Vault / Vault Agent / Postgres / pgAdmin)

The current Compose stack is functional and aligned with the “always Vault” goal. The items below are recommended hardening improvements you can apply incrementally.

### B.1 Network and port exposure

- Prefer binding ports to loopback when you only need local access on the host:
  - Vault: `127.0.0.1:8200:8200`
  - pgAdmin: `127.0.0.1:8081:80`
  - Postgres: consider **no host port** in production; use internal Docker networking only.
- Consider isolating admin surfaces (Vault UI, pgAdmin) behind an authenticated reverse proxy (mTLS, SSO) rather than publishing ports broadly.

### B.2 Drop privileges, reduce Linux capabilities, and prevent privilege escalation

Where images support it, add:

```yaml
security_opt:
  - no-new-privileges:true
cap_drop:
  - ALL
```

Notes:
- Vault may require `IPC_LOCK` if you later enable `mlock` (recommended on non-rootless setups). With rootless Docker you often keep `VAULT_DISABLE_MLOCK=true`, but revisit when you move to a hardened runtime.
- Postgres generally does not need extra capabilities.

### B.3 Read-only root filesystem + tmpfs

For services that do not need to write to their root FS, consider:

```yaml
read_only: true
tmpfs:
  - /tmp
  - /run
```

Notes:
- Vault Agent writes to its rendered directory (the named volume). Keep that volume RW for the agent, RO for consumers.
- pgAdmin writes application state under `/var/lib/pgadmin`; ensure that path remains writable (named volume or bind mount).

### B.4 Tighten service dependencies to avoid accidental Vault restarts

- When iterating on leaf services, use:

```bash
docker compose -f docker-compose.prod.yml up -d --no-deps --no-recreate pgadmin
```

- Only use `--force-recreate` when you need new mounts/env changes to take effect.
- Avoid frequent changes to `vault_production_node`’s config/volumes while the cluster is running; any restart returns Vault to **sealed**.

### B.5 Secrets hygiene

- Keep the AppRole export directory `./container_data/vault/approle/postgres_pgadmin_agent/` readable only by the service account that runs rootless Docker (`chmod 700`).
- Mount secrets read-only into consumer containers (`:ro`), as you are doing for `/run/vault`.
- Avoid writing plaintext DB passwords into `.env` for production. Keep `.env` limited to non-secret toggles, hostnames, and emails.

### B.6 Image pinning and update discipline

- Pin images by digest for production (or at least pin minor versions) and create an update cadence.
- Consider scanning images with Trivy/Grype in CI.

### B.7 Vault-specific hardening (forward-looking)

- Prefer auto-unseal (KMS/HSM) for production so Vault can restart without manual unseal.
- Restrict Vault token usage: minimize root-token presence on disk after bootstrap; rely on AppRole and policies.
- Reduce `VAULT_LOG_LEVEL` from `debug` to `info` (or `warn`) outside troubleshooting windows.

## 8. Lessons learned and common issues

This section captures the operational issues encountered during the Vault + Postgres + Keycloak integration and the “why” behind each fix.

### 8.1 Vault Agent sidecar gotchas

- **Do you need a token sink file?**  
  Not always. If Vault Agent’s only job is to render templates (env files, certs) into a shared volume, it can keep the token in memory and you can omit exposing a token to other containers.  
  Use a **file sink** when another process must read the token (for example, an application that talks directly to Vault). If you do use a file sink:
  - keep the sink path in `tmpfs` (example: `/run` or `/tmp`),
  - do not mount the token file into other containers unless necessary,
  - restrict permissions (`mode = 0400`) and confirm the directory exists before agent start.

- **`/run/vault` must exist** if you use it as a sink or render destination. `tmpfs: ["/run"]` does not automatically create `/run/vault`.

### 8.2 Template and rendering pitfalls

- **Avoid `fail` in templates.** Guard missing keys with `if` checks and let healthchecks/startup checks catch missing required values.
- **Prefer base64 for PEM blobs** stored in Vault KV. It avoids newline/escaping issues and makes templates deterministic (decode at render time).
- **Watch for newline issues** in generated env files. One missing newline can invalidate the entire first variable and cause “missing env” failures (as you saw with `KC_DB`).

### 8.3 Container entrypoint and permissions pitfalls

- **Bind-mounted scripts must be executable.** If your container entrypoint is a bind-mounted script, the executable bit must be set on the host (`chmod +x ...`) or you will get `permission denied`.
- **Keycloak CLI path:** for Keycloak 17+ (Quarkus-based images), use `/opt/keycloak/bin/kc.sh`, not `kc`.

### 8.4 Postgres credential drift and how to fix it

The most common root cause of “password authentication failed” during bring-up is **credential drift**:

- Vault KV contains one password.
- Postgres role password is different (or the role/database does not exist).
- Keycloak (or another service) reads the Vault-rendered password and fails to authenticate.

Fix pattern:

1) Treat Vault as the source of truth.
2) Run the apply/sync workflow (**4.5**) to align the running Postgres cluster with Vault values.
3) Restart the dependent service (Keycloak, pgAdmin, app backends).
