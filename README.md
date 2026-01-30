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
  (See Appendix B for required Vault variables needed as well)
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

>NOTE: This build is going off my one domain setup. This can be set / changed in the .env file.

---
1. `bash ./backend/build_scripts/generate_local_networkengineertools_certs.sh`

```bash
If you are using self generated scripts your output should look like the following.
developer_network_tools@networktoolsvm:~/NETWORK_TOOLS$ bash ./backend/build_scripts/generate_local_networkengineertools_certs.sh
==> Output directory: /home/developer_network_tools/NETWORK_TOOLS/backend/app/nginx/certs
==> CN: networkengineertools.com
==> SANs (DNS):
    - networkengineertools.com
    - *.networkengineertools.com
    - auth.networkengineertools.com
    - api.networkengineertools.com
    - pgadmin.networkengineertools.com
    - flower.networkengineertools.com
    - vault.networkengineertools.com
    - localhost
==> SANs (IP):
    - 127.0.0.1
==> Creating CA (with proper v3 CA extensions)
==> Creating server key and CSR
==> Signing leaf certificate
Certificate request self-signature ok
subject=CN = networkengineertools.com
==> Syncing certs into Vault cert dir: /home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs
==> Syncing CA into FastAPI build context: /home/developer_network_tools/NETWORK_TOOLS/backend/app/fastapi/certs
==> Done. Files:
total 36K
drwx------ 2 developer_network_tools developer_network_tools 4.0K Jan 30 21:27 .
drwxr-xr-x 4 developer_network_tools developer_network_tools 4.0K Jan  6 21:41 ..
-rw-r--r-- 1 developer_network_tools developer_network_tools 1.9K Jan 30 21:27 ca.crt
-rw------- 1 developer_network_tools developer_network_tools 3.2K Jan 30 21:27 ca.key
-rw------- 1 developer_network_tools developer_network_tools   41 Jan 30 21:27 ca.srl
-rw-r--r-- 1 developer_network_tools developer_network_tools 4.1K Jan 30 21:27 cert.crt
-rw------- 1 developer_network_tools developer_network_tools 3.2K Jan 30 21:27 cert.key
-rw-r--r-- 1 developer_network_tools developer_network_tools 2.2K Jan 30 21:27 cert.leaf.crt

Next step: trust the CA (ca.crt) on your client machine for clean browser UX.
```
2. `bash ./backend/build_scripts/vault_first_time_init_only_rootless.sh` *(first-time Vault only)*

```bash
Your output should look similar to below

developer_network_tools@networktoolsvm:~/NETWORK_TOOLS$ bash ./backend/build_scripts/vault_first_time_init_only_rootless.sh
INFO: Loading env defaults from: /home/developer_network_tools/NETWORK_TOOLS/.env
INFO: Starting Vault container: docker compose -p network_tools -f /home/developer_network_tools/NETWORK_TOOLS/docker-compose.prod.yml up -d vault_production_node
[+] up 10/10
 ✔ Image hashicorp/vault:1.21.1     Pulled                                                                                                                                                                                                                69.8s 
 ✔ Network network_tools_public_net Created                                                                                                                                                                                                                0.0s 
 ✔ Container vault_production_node  Created                                                                                                                                                                                                                0.1s 
INFO: Waiting for Vault endpoint: https://vault.networkengineertools.com:8200
INFO: WARN: public GET /v1/sys/health curl failed (rc=35, http=000): curl: (35) OpenSSL SSL_connect: SSL_ERROR_SYSCALL in connection to vault.networkengineertools.com:8200 
INFO: WARN: TLS verification failed using system trust store (no --ca-cert provided).
INFO: WARN: curl error: curl: (35) OpenSSL SSL_connect: SSL_ERROR_SYSCALL in connection to vault.networkengineertools.com:8200 
INFO: WARN: Retrying with -k (insecure). For proper TLS verification, provide --ca-cert <path-to-ca.crt>.
INFO: Vault not initialized; initializing (shares=5, threshold=3)…
INFO: Init complete. Wrote (0600):
INFO:   Unseal keys JSON     : /home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/unseal_keys.json
INFO:   Root token (plain)   : /home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token
INFO:   Root token (JSON)    : /home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token.json
INFO: Unsealing Vault using 3 key(s)…
INFO: Vault unsealed.
INFO: Enabling file audit device at path 'file/' -> /vault/logs/audit.log
INFO: Audit device enabled successfully.
./backend/build_scripts/vault_first_time_init_only_rootless.sh: line 814: vault: command not found
INFO: Ensured ACL policy: postgres_pgadmin_read
INFO: Enabled auth method: approle/
INFO: Ensured AppRole role: postgres_pgadmin_agent (policy: postgres_pgadmin_read)
./backend/build_scripts/vault_first_time_init_only_rootless.sh: line 927: vault: command not found
INFO: Ensured ACL policy: keycloak_read
INFO: Auth method already enabled: approle/
INFO: Ensured AppRole role: keycloak_agent (policy: keycloak_read)
INFO: Ensured ACL policy: fastapi_read
INFO: Auth method already enabled: approle/
INFO: Ensured AppRole role: fastapi_agent (policy: fastapi_read)

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
    "7fda417808b008aa1847d6fdf1e90aad17929c25249f4f66da6b170f954ed22e4f",
    "2b698adcad5931f7a1b44fb60c852ba91b7c47b96bfdddf12793cfa0a48ecfb0f6",
    "3bf139186e1d914f8ec72dfa0c203fad26adcb94156beae553005a0e934c81cdeb",
    "d48b333ffd8048ef972d4ffa89cfb472827ab2b47d53fac29aabca57d4eea2dac3",
    "cc1da92bf9cbca714feea45f31feb5a385f95007df459047047d0fc47f98ed6b8e"
  ],
  "keys_base64": [
    "f9pBeAiwCKoYR9b98ekKrReSnCUkn09m2msXD5VO0i5P",
    "K2mK3K1ZMfehtE+2DIUrqRt8R7lr/d3xJ5PPoKSOz7D2",
    "O/E5GG4dkU+Oxy36DCA/rSaty5QVa+rlUwBaDpNMgc3r",
    "1IszP/2ASO+XLU/6ic+0coJ6srR9U/rCmqvKV9TuotrD",
    "zB2pK/nLynFP7qRfMf61o4X5UAffRZBHBH0PxH+Y7WuO"
  ],
  "root_token": "hvs.0k2BGarvgQvQyz7hA1Z93Lpw"
}

----- /home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token.json -----
{
  "root_token": "hvs.0k2BGarvgQvQyz7hA1Z93Lpw"
}

{
  "vault_addr": "https://vault.networkengineertools.com:8200",
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
  "keycloak_approle_bootstrap": {
    "enabled": true,
    "force": false,
    "setup_done": true,
    "role_name": "keycloak_agent",
    "policy_name": "keycloak_read"
  },
  "fastapi_approle_bootstrap": {
    "enabled": true,
    "force": false,
    "setup_done": true,
    "role_name": "fastapi_agent",
    "policy_name": "fastapi_read"
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
3. `bash ./backend/build_scripts/generate_bootstrap_creds_and_seed.sh \
  --ca-cert "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt" \
  --unseal-required 3`

```bash
Your output should look like below

developer_network_tools@networktoolsvm:~/NETWORK_TOOLS$ bash ./backend/build_scripts/generate_bootstrap_creds_and_seed.sh \
  --ca-cert "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt" \
  --unseal-required 3
INFO: Loading env defaults from: /home/developer_network_tools/NETWORK_TOOLS/.env
INFO: Using existing local bootstrap artifacts: /home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/bootstrap_creds.env
INFO: Wrote credential artifacts:
INFO:   ENV:  /home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/bootstrap_creds.env
INFO:   JSON: /home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/bootstrap_credentials.json
INFO:   SPEC: /home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/seed_kv_spec.bootstrap_creds.json
INFO: 
INFO: Seeding Vault from generated spec...
INFO:   VAULT_ADDR: https://vault.networkengineertools.com:8200
INFO:   Seed script: /home/developer_network_tools/NETWORK_TOOLS/backend/build_scripts/vault_unseal_multi_kv_seed_bootstrap_rootless.sh
INFO:   CA cert:    /home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt
INFO: Vault address: https://vault.networkengineertools.com:8200
INFO: Bootstrap dir: /home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap
INFO: Spec file: /home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/seed_kv_spec.bootstrap_creds.json
INFO: Unseal keys file: /home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/unseal_keys.json
INFO: CA cert: /home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt
INFO: Vault is already unsealed. Skipping unseal.
INFO: Spec mounts: 1
INFO: --- Mount [0]: app_network_tools_secrets (version=2) ---
INFO: Enabled KV v2 at app_network_tools_secrets/
INFO: wrote -> app_network_tools_secrets/postgres
INFO: wrote -> app_network_tools_secrets/pgadmin
INFO: wrote -> app_network_tools_secrets/device_login_profiles
INFO: wrote -> app_network_tools_secrets/fastapi_secrets
INFO: wrote -> app_network_tools_secrets/keycloak_postgres
INFO: wrote -> app_network_tools_secrets/keycloak_bootstrap
INFO: wrote -> app_network_tools_secrets/keycloak_runtime
INFO: Mount app_network_tools_secrets: seed complete. success=7 failed=0
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


NOTE:
There are other credentials that must be seeded manually if you wish to enable certain features like 
ciscos apix reporting, or file encryption for device backups. See the file backend/build_scripts/documentation/fastapi/example_vault_data/fastapi_secrets.json for the examples
```

*(Step 2 must create the AppRole auth method or these will fail.)*

4. `chmod +x ./backend/build_scripts/keycloak_approle_setup.sh
ROLE_NAME=keycloak_agent ./backend/build_scripts/keycloak_approle_setup.sh`
5. `chmod +x ./backend/build_scripts/postgress_approle_setup.sh
ROLE_NAME=postgres_pgadmin_agent ./backend/build_scripts/postgress_approle_setup.sh` 
6. `chmod +x ./backend/build_scripts/fastapi_approle_setup.sh
ROLE_NAME=fastapi_agent ./backend/build_scripts/fastapi_approle_setup.sh`
---

### 1.0 Initial BASE File system structure
```bash
developer_network_tools@networktoolsvm:~/NETWORK_TOOLS$ tree --charset ascii

```

### 1.2 Build Scripts - Generate Local Certificates

#### First-time local certificate file creation. You can skip this step if you are using your own CA. You need to place the files in the same locations though. 

>NOTE: This script is hardcoded to the domain of my choice and does not pull from the .env file. If you wish to use it with another domain
> you need to update it manually for now. 

```bash
bash $HOME/NETWORK_TOOLS/backend/build_scripts/generate_local_networkengineertools_certs.sh
```


> Walkthrough video [can be found here](https://youtu.be/w5MW_b8s0Rc)

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
bash ./backend/build_scripts/generate_bootstrap_creds_and_seed.sh \
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

```bash
chmod +x ./backend/build_scripts/fastapi_approle_setup.sh
ROLE_NAME=fastapi_agent ./backend/build_scripts/fastapi_approle_setup.sh
```

>NOTE: There is a helper script that will query vault and show you the values stored there as well as the local copies.
> This helps ensure vault is ready to bring up the vault_agent containers

TODO - Update this script to check for the fastapi one as well 
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
docker compose -f docker-compose.prod.yml up -d vault_agent_postgres_pgadmin vault_agent_keycloak vault_agent_fastapi

docker compose -f docker-compose.prod.yml ps

docker logs --tail 200 -f vault_agent_postgres_pgadmin
docker logs --tail 200 -f vault_agent_keycloak
docker logs --tail 200 -f vault_agent_fastapi

# Confirm the rendered files exist for fastapi
docker exec -it vault_agent_fastapi sh -lc 'ls -lah /vault/rendered && echo && sed -n "1,80p" /vault/rendered/redis.conf'

```

### 2.4 Start Postgres

```bash
docker compose -f docker-compose.prod.yml up -d postgres_primary
docker compose -f docker-compose.prod.yml ps
docker logs --tail 200 -f postgres_primary
```

Seed any postgres user information and permissions

```bash
chmod +x ./backend/build_scripts/seed_postgres_with_vault_credentials.sh
./backend/build_scripts/seed_postgres_with_vault_credentials.sh \
  --ca-cert "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt"
```

Your output should resemble below

```bash
developer_network_tools@networktoolsvm:~/NETWORK_TOOLS$ chmod +x ./backend/build_scripts/seed_postgres_with_vault_credentials.sh
./backend/build_scripts/seed_postgres_with_vault_credentials.sh \
  --ca-cert "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt"
INFO: Loaded PRIMARY_SERVER_FQDN from env file: /home/developer_network_tools/NETWORK_TOOLS/.env
INFO: Using Vault host from PRIMARY_SERVER_FQDN: networkengineertools.com
INFO: Using Vault token from: /home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token
INFO: Reading Keycloak Postgres secret from Vault: /v1/app_network_tools_secrets/data/keycloak_postgres
INFO: Reading Postgres master secret from Vault: /v1/app_network_tools_secrets/data/postgres
INFO: Reading FastAPI Postgres secret from Vault: /v1/app_network_tools_secrets/data/fastapi_secrets
INFO: Vault values loaded:
INFO:   Keycloak DB:     keycloak
INFO:   Keycloak Role:   keycloak
INFO:   Keycloak Schema: keycloak
INFO:   FastAPI DB:      network_tools
INFO:   FastAPI Role:    network_tools_fastapi
INFO:   FastAPI Schema:  public
INFO:   Postgres Master: network_tools_user
INFO:   Vault addr:      https://networkengineertools.com:8200
INFO:   Vault mount:     app_network_tools_secrets
INFO:   PG container:    postgres_primary
INFO:   PG port:         5432
INFO: Waiting for Postgres readiness (up to 180s)...
INFO: Testing master login against catalog DB 'postgres'...
INFO: Master login OK.
INFO: Sanity check: wrong-password login must fail (proves password auth is enforced)...
INFO: Wrong-password login failed as expected.
INFO: Ensuring Keycloak role exists...
INFO: Creating role 'keycloak'...
CREATE ROLE
INFO: Setting Keycloak role password to match Vault...
ALTER ROLE
INFO: Checking whether Keycloak database exists...
INFO: Creating database 'keycloak' owned by 'keycloak'...
CREATE DATABASE
INFO: Ensuring database owner is 'keycloak'...
INFO: Granting CONNECT and TEMPORARY on Keycloak DB...
INFO: Ensuring schema 'keycloak' exists and privileges are set...
CREATE SCHEMA
GRANT
INFO: Ensuring FastAPI role exists...
INFO: Creating role 'network_tools_fastapi'...
CREATE ROLE
INFO: Setting FastAPI role password to match Vault...
ALTER ROLE
INFO: Checking whether FastAPI database exists...
INFO: Database 'network_tools' already exists.
INFO: Granting CONNECT on FastAPI DB (no TEMP granted)...
INFO: Ensuring schema 'public' exists and granting least-privilege...
INFO: Granting non-destructive DML privileges to FastAPI role (existing objects)...
INFO: Setting default privileges for future tables/sequences created by 'network_tools_user' in schema 'public'...
INFO: Verifying Keycloak role can log in to 'keycloak'...
INFO: SUCCESS: Keycloak verified login.
INFO: Verifying FastAPI role can log in to 'network_tools'...
INFO: SUCCESS: FastAPI verified login and least-privilege grants applied.
INFO: DONE: Postgres seeded to match Vault for Keycloak + FastAPI.
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

### 2.7 Start Redis

```bash
docker compose -f docker-compose.prod.yml up -d --no-deps --build --force-recreate redis
docker logs --tail 200 -f redis
```

### 2.8 Start FastAPI and Celery
```bash
docker compose -f docker-compose.prod.yml up -d --no-deps --build --force-recreate fastapi_api celery_worker flower
docker logs --tail 200 -f fastapi_api
docker logs --tail 200 -f celery_worker
```

### 2.9 Start NGINX
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

### B.2 Vault — `fastapi_secrets.json` keys (FastAPI + Celery + device configuration backups)

FastAPI and the Celery worker load their runtime configuration from the Vault Agent rendered JSON file (the path is
controlled by `VAULT_SECRETS_JSON`). The keys below are required for device backup creation **and** for reading backups
back through the API without writing anything to disk.

#### Device backup + encryption keys (required for this feature)

- `CELERY_WORKER_DEVICE_BACKUP_FILE_LOCATION`  
  Base directory where device configuration backups are stored (and later read from).  
  Example: `/backups/device_configuration_backups`

- `ENABLE_FILE_ENCRYPTION`  
  `true|false`. When `true`, backups are written as `*.enc` (AES-GCM) after gzip compression.  
  When `false`, the system may leave backups as plain `*.txt` / `*.gz` depending on your pipeline.

- `DEVICE_BACKUP_MASTER_KEY_B64`  
  Base64-encoded **32-byte** master key (AES-256). This must be present to decrypt `*.enc` files.  
  Generate: `openssl rand -base64 32`

- `DEVICE_BACKUP_KDF_PEPPER`  
  Additional “pepper” input into the key-derivation (KDF). Treat as a secret and keep stable.  
  Changing this will prevent decrypting previously-encrypted backups unless you re-encrypt them.

- `DEVICE_BACKUP_MAX_DECOMPRESSED_BYTES`  
  Hard cap for in-memory decompression when reading backups through the API (protects against huge files).  
  Recommended: **50 MiB** → `52428800`

#### Example `fastapi_secrets.json` (Vault-rendered)

> **Do not commit real secrets.** Keep the real values in Vault and render them via Vault Agent templates.

```json
{
  "APP_ENV": "prod",

  "CELERY_BROKER_DB": "0",
  "CELERY_BROKER_URL": "redis://:<REDIS_PASSWORD>@redis:6379/0",
  "CELERY_RESULT_BACKEND": "redis://:<REDIS_PASSWORD>@redis:6379/1",
  "CELERY_RESULT_DB": "1",

  "CELERY_WORKER_DEVICE_BACKUP_FILE_LOCATION": "/backups/device_configuration_backups",
  "ENABLE_FILE_ENCRYPTION": "true",
  "DEVICE_BACKUP_MASTER_KEY_B64": "<BASE64_32_BYTES>",
  "DEVICE_BACKUP_KDF_PEPPER": "<SECRET_PEPPER>",
  "DEVICE_BACKUP_MAX_DECOMPRESSED_BYTES": "52428800",

  "CORS_ALLOW_CREDENTIALS": "0",
  "CORS_ALLOW_ORIGINS": "https://networkengineertools.com,https://www.networkengineertools.com",
  "CORS_ALLOW_ORIGIN_REGEX": "^https://([a-z0-9-]+\\\\.)?networkengineertools\\\\.com(:\\\\d+)?$",

  "FASTAPI_ALLOWED_AZP": "networktools-web,networktools-cli,networktools-automation,fastapi-client",
  "FASTAPI_DB_PASSWORD": "<DB_PASSWORD>",
  "FASTAPI_DB_SCHEMA": "public",
  "FASTAPI_DB_URL_DATABASE": "network_tools",
  "FASTAPI_DB_URL_HOST": "postgres_primary",
  "FASTAPI_DB_URL_PORT": "5432",
  "FASTAPI_DB_USERNAME": "network_tools_fastapi",
  "FASTAPI_VERIFY_AUDIENCE": "false",

  "KEYCLOAK_BASE_URL": "https://auth.networkengineertools.com:8443",
  "KEYCLOAK_REALM": "network_tools",
  "KEYCLOAK_INTROSPECTION_CLIENT_ID": "<OPTIONAL_IF_USING_INTROSPECTION>",
  "KEYCLOAK_INTROSPECTION_CLIENT_SECRET": "<OPTIONAL_IF_USING_INTROSPECTION>",

  "LOG_DIR": "/var/log/network_tools/fastapi",
  "LOG_FILE": "network_tools_fastapi.log",
  "LOG_LEVEL": "DEBUG",
  "LOG_TO_STDOUT": "1",

  "REDIS_HOST": "redis",
  "REDIS_PASSWORD": "<REDIS_PASSWORD>",
  "REDIS_PORT": "6379",

  "TRUSTED_HOSTS": "networkengineertools.com,*.networkengineertools.com,localhost,127.0.0.1",
  "VAULT_ADDR": "https://vault.networkengineertools.com:8200"
}
```


## Appendix C - Final Directory Structure (Prior to removing sensitive files)
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
|   |   |   |   |-- ca.crt
|   |   |   |   |-- ca.key
|   |   |   |   |-- ca.srl
|   |   |   |   |-- cert.crt
|   |   |   |   |-- cert.key
|   |   |   |   `-- cert.leaf.crt
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
|   |   |-- generate_local_networkengineertools_certs.sh
|   |   |-- generate_local_pgadmin_certs.sh
|   |   |-- generate_local_postgres_certs.sh
|   |   |-- generate_local_vault_certs.sh
|   |   |-- generate_bootstrap_creds_and_seed.sh
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
|-- container_data
|   `-- vault
|       |-- approle
|       |   |-- keycloak_agent
|       |   |   |-- role_id
|       |   |   `-- secret_id
|       |   `-- postgres_pgadmin_agent
|       |       |-- role_id
|       |       `-- secret_id
|       `-- data
|           |-- logs
|           |   `-- audit.log
|           |-- raft
|           |   |-- raft.db
|           |   `-- snapshots
|           `-- vault.db
|-- docker-compose.prod.yml
|-- frontend
|-- LICENSE
|-- README.full.md
`-- README.md
```