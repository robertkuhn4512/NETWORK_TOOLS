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

>NOTE: This build is going off my one domain setup. This can be set / changed in the .env file.
Once changed there, The FQDN settings will propagate to the rest of the containers / setup files. 
> So you should be able to run your own domain. The local certificates generator will also generate certificates based on 
> the name you choose, and it will fail back to the original if there is not one set in the .env file.
---
1. *(Generate local certificates if you are not using your own)*
```bash
chmod +x ./backend/build_scripts/generate_local_networkengineertools_certs.sh
./backend/build_scripts/generate_local_networkengineertools_certs.sh
```

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

2. *(first-time Vault only)*
```bash
chmod +x ./backend/build_scripts/vault_first_time_init_only_rootless.sh
./backend/build_scripts/vault_first_time_init_only_rootless.sh
```

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
  "frontend_approle_bootstrap": {
    "enabled": true,
    "force": false,
    "setup_done": true,
    "role_name": "frontend_agent",
    "policy_name": "frontend_read"
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
3. 
```bash 
chmod +x ./backend/build_scripts/generate_bootstrap_creds_and_seed.sh
./backend/build_scripts/generate_bootstrap_creds_and_seed.sh \
  --ca-cert "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt" \
  --unseal-required 3
```


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

*(Step 2 must create the AppRole auth method or the following will fail will fail.)*

>NOTE: Run the below steps (4-7) to create new secret_ids one at a time for an individual service, or run the command below to create / recreate them all.
> The current plan is to use this script to rotate all the secret ids on a cron, Or switch to a trust build between vault and the vault agent containers.

```bash
bash ./backend/build_scripts/approle_setup_all.sh bootstrap --token-file $HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token
```

4. 
```bash
chmod +x ./backend/build_scripts/keycloak_approle_setup.sh
ROLE_NAME=keycloak_agent ./backend/build_scripts/keycloak_approle_setup.sh
```

5. 
```bash
chmod +x ./backend/build_scripts/postgress_approle_setup.sh
ROLE_NAME=postgres_pgadmin_agent ./backend/build_scripts/postgress_approle_setup.sh
```

6. 
```bash
chmod +x ./backend/build_scripts/fastapi_approle_setup.sh
ROLE_NAME=fastapi_agent ./backend/build_scripts/fastapi_approle_setup.sh
```

7. 
```bash
chmod +x ./backend/build_scripts/frontend_approle_setup.sh
ROLE_NAME=frontend_agent ./backend/build_scripts/frontend_approle_setup.sh
```

# Generate and Seed Postgres/pgAdmin/Keycloak bootstrap credentials + KV spec artifacts
8

>NOTE: --unseal-required should match --init-threshold.<br> 
> This tells the script how many keys are required to unseal vault if it's sealed.
> This script will generate all the initial credentials you need to configure and use each service as well as seeding vault with them.<br>
> If you choose your own credentials, you can run this, log into vault and change them prior to building the rest of the containers.<br>
> <b>Make sure you REMOVE THEM afterward and do not leave them on your filesystem!</b>

```bash
bash ./backend/build_scripts/generate_bootstrap_creds_and_seed.sh \
  --ca-cert "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt" \
  --unseal-required 3
```

>NOTE: This seed script is a first time run only. If the endpoints and credentials already exist it will not
> overwrite them. If you want it to you will need to delete them from vault first then rerun. Example below
> of the output you will see if it fails
> 
> INFO: Mount exists: app_network_tools_secrets/ (KV v2)<br>
WARN: failed -> app_network_tools_secrets/postgres (HTTP 400)
WARN: failed -> app_network_tools_secrets/pgadmin (HTTP 400)
WARN: failed -> app_network_tools_secrets/device_login_profiles (HTTP 400)
WARN: failed -> app_network_tools_secrets/fastapi_secrets (HTTP 400)
WARN: failed -> app_network_tools_secrets/keycloak_postgres (HTTP 400)
WARN: failed -> app_network_tools_secrets/keycloak_bootstrap (HTTP 400)
WARN: failed -> app_network_tools_secrets/keycloak_runtime (HTTP 400)
---

### 1.0 Initial BASE File system structure
```bash
developer_network_tools@networktoolsvm:~/NETWORK_TOOLS$ tree --charset ascii
.
|-- backend
|   |-- app
|   |   |-- celery
|   |   |-- fastapi
|   |   |   |-- app
|   |   |   |   |-- celery_app.py
|   |   |   |   |-- database.py
|   |   |   |   |-- database_queries
|   |   |   |   |   |-- __init__.py
|   |   |   |   |   |-- postgres_insert_queries.py
|   |   |   |   |   `-- postgres_select_queries.py
|   |   |   |   |-- __init__.py
|   |   |   |   |-- main.py
|   |   |   |   |-- network_utilities
|   |   |   |   |   |-- icmp_check.py
|   |   |   |   |   `-- __init__.py
|   |   |   |   |-- routers
|   |   |   |   |   |-- auth_test.py
|   |   |   |   |   |-- celery_jobs.py
|   |   |   |   |   |-- cisco_api_reporting.py
|   |   |   |   |   |-- device_backups.py
|   |   |   |   |   `-- device_discovery.py
|   |   |   |   |-- security
|   |   |   |   |   |-- auth.py
|   |   |   |   |   |-- jwks_cache.py
|   |   |   |   |   `-- keycloak_settings.py
|   |   |   |   |-- shared_functions
|   |   |   |   |   |-- helpers
|   |   |   |   |   |   |-- helpers_a10.py
|   |   |   |   |   |   |-- helpers_arista.py
|   |   |   |   |   |   |-- helpers_authentication.py
|   |   |   |   |   |   |-- helpers_cisco.py
|   |   |   |   |   |   |-- helpers_configuration_backups.py
|   |   |   |   |   |   |-- helpers_datetime.py
|   |   |   |   |   |   |-- helpers_environment.py
|   |   |   |   |   |   |-- helpers_file_encryption.py
|   |   |   |   |   |   |-- helpers_generic.py
|   |   |   |   |   |   |-- helpers_hashicorp_vault.py
|   |   |   |   |   |   |-- helpers_juniper.py
|   |   |   |   |   |   |-- helpers_logging_config.py
|   |   |   |   |   |   |-- helpers_netmiko.py
|   |   |   |   |   |   |-- helpers_postgres.py
|   |   |   |   |   |   |-- helpers_sanitation.py
|   |   |   |   |   |   |-- helpers_snmp.py
|   |   |   |   |   |   |-- helpers_subnetting.py
|   |   |   |   |   |   `-- __init__.py
|   |   |   |   |   `-- __init__.py
|   |   |   |   `-- tasks.py
|   |   |   |-- bin
|   |   |   |   `-- entrypoint.sh
|   |   |   |-- certs
|   |   |   |   `-- networktools_ca.crt
|   |   |   |-- Dockerfile
|   |   |   |-- gunicorn_conf.py
|   |   |   |-- __init__.py
|   |   |   |-- requirements.txt
|   |   |   |-- run_server.py
|   |   |   |-- vault_agent
|   |   |   |   |-- agent.hcl
|   |   |   |   `-- templates
|   |   |   |       |-- fastapi_secrets.json.ctmpl
|   |   |   |       |-- redis.conf.ctmpl
|   |   |   |       `-- redis_password.ctmpl
|   |   |   `-- vault_env_exec.py
|   |   |-- __init__.py
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
|   |   |-- postgres
|   |   |   |-- certs
|   |   |   |-- config
|   |   |   |   |-- pg_hba.conf
|   |   |   |   `-- postgres.conf
|   |   |   |-- init
|   |   |   |   |-- 01_network_tools_schema_dump.sql
|   |   |   |   `-- initial_reference_network_tools_schema.sql
|   |   |   `-- vault_agent
|   |   |       |-- agent.hcl
|   |   |       `-- templates
|   |   |           |-- pgadmin_password.ctmpl
|   |   |           |-- postgres_db.ctmpl
|   |   |           |-- postgres_password.ctmpl
|   |   |           |-- postgres_user.ctmpl
|   |   |           `-- servers.json.ctmpl
|   |   `-- security
|   |       `-- configuration_files
|   |           `-- vault
|   |               |-- bootstrap
|   |               |   |-- bootstrap_credentials.json
|   |               |   |-- bootstrap_creds.env
|   |               |   |-- postgres_pgadmin_credentials.json
|   |               |   |-- postgres_pgadmin.env
|   |               |   |-- root_token
|   |               |   |-- root_token.json
|   |               |   |-- seeded_secrets_all.json
|   |               |   |-- seed_kv_spec.bootstrap_creds.json
|   |               |   |-- seed_kv_spec.postgres_pgadmin.json
|   |               |   `-- unseal_keys.json
|   |               |-- certs
|   |               |   |-- ca.crt
|   |               |   |-- cert.crt
|   |               |   `-- cert.key
|   |               |-- config
|   |               |   |-- certs
|   |               |   |-- fastapi_read.hcl
|   |               |   |-- keycloak_kv_read.hcl
|   |               |   |-- postgres_pgadmin_kv_read.hcl
|   |               |   `-- vault_configuration_primary_node.hcl
|   |               `-- Dockerfile
|   |-- backup_scripts
|   |-- build_scripts
|   |   |-- documentation
|   |   |   |-- celery
|   |   |   |   `-- troubleshooting
|   |   |   |       `-- celery_troubleshooting.md
|   |   |   |-- fastapi
|   |   |   |   |-- example_json_outputs
|   |   |   |   |   `-- get_cisco_eox
|   |   |   |   |       `-- example_reply_get_cisco_eox.json
|   |   |   |   |-- example_vault_data
|   |   |   |   |   |-- device_login_profiles_secrets.json
|   |   |   |   |   `-- fastapi_secrets.json
|   |   |   |   `-- test_scripts
|   |   |   |       |-- test_fastapi_keycloak_cc.sh
|   |   |   |       `-- test_payloads
|   |   |   |           |-- device_discovery_icmp.json
|   |   |   |           |-- device_discovery_start_device_discovery.json
|   |   |   |           |-- get_cisco_cve_os_version.json
|   |   |   |           |-- get_cisco_eox.json
|   |   |   |           `-- unique_os_versions_cve.json
|   |   |   |-- keycloak
|   |   |   |   |-- keycloak_how_to
|   |   |   |   |-- keycloak_realm_files
|   |   |   |   |   `-- initial_realm-export.json
|   |   |   |   |-- keycloak_setup_network_tools_fastapi.md
|   |   |   |   `-- test_scripts
|   |   |   |       `-- keycloak_all_in_one.sh
|   |   |   `-- postgres
|   |   |       `-- test_data_seed_files
|   |   |           `-- seed_devices_table.sql
|   |   |-- fastapi_approle_setup.sh
|   |   |-- generate_bootstrap_creds_and_seed.sh
|   |   |-- generate_local_networkengineertools_certs.sh
|   |   |-- guides
|   |   |   |-- seed_kv_spec.example.json
|   |   |   `-- seed_kv_spec.GUIDE.md
|   |   |-- keycloak_approle_setup.sh
|   |   |-- postgress_approle_setup.sh
|   |   |-- seed_postgres_with_vault_credentials.sh
|   |   |-- startover_scripts
|   |   |   |-- database_related
|   |   |   |   |-- drop_all_tables_network_tools.sql
|   |   |   |   `-- drop_specific_tables_network_tools.sql
|   |   |   `-- reset_network_tools_docker.sh
|   |   |-- validation_scripts
|   |   |   |-- check_approle_presence_and_ids_in_vault.sh
|   |   |   |-- postgres_inventory.sh
|   |   |   `-- read_postgres_pgadmin_approle.sh
|   |   |-- vault_first_time_init_only_rootless.sh
|   |   |-- vault_unseal_kv_seed_bootstrap_rootless.sh
|   |   `-- vault_unseal_multi_kv_seed_bootstrap_rootless.sh
|   |-- __init__.py
|   `-- nginx
|-- container_data
|   `-- vault
|       |-- approle
|       |   |-- fastapi_agent
|       |   |   |-- role_id
|       |   |   `-- secret_id
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
|-- __init__.py
|-- LICENSE
|-- README.full.md
`-- README.md
```

>NOTE:
> Pre flight check to see if the approle role_id and secret_id's match on both the vault instance and local server
> prior to turning up the vault agent containers.

TODO - Update this script to check for the fastapi one as well 
```bash
chmod +x ./backend/build_scripts/validation_scripts/check_approle_presence_and_ids_in_vault.sh
./backend/build_scripts/validation_scripts/check_approle_presence_and_ids_in_vault.sh
```
<br>

>Example output below

```bash
developer_network_tools@networktoolsvm:~/NETWORK_TOOLS$ bash ./backend/build_scripts/validation_scripts/check_approle_presence_and_ids_in_vault.sh
INFO: Loading env defaults from: /home/developer_network_tools/NETWORK_TOOLS/.env
INFO: WARN: VAULT_CACERT_IN_CONTAINER '/vault/certs/ca.crt' not found in container; using /vault/certs/cert.crt

postgres_pgadmin_agent role_id (host):         54ccfb7e-0093-4510-ef4f-796dbc7b01f1
postgres_pgadmin_agent role_id (vault):        54ccfb7e-0093-4510-ef4f-796dbc7b01f1
postgres_pgadmin_agent secret_id (host file):  present (36 bytes)

keycloak_agent role_id (host):         e9a30576-7208-966a-1cef-b81857a5b95b
keycloak_agent role_id (vault):        e9a30576-7208-966a-1cef-b81857a5b95b
keycloak_agent secret_id (host file):  present (36 bytes)

fastapi_agent role_id (host):         400804e8-c448-86ec-e7e3-98f562770f4e
fastapi_agent role_id (vault):        400804e8-c448-86ec-e7e3-98f562770f4e
fastapi_agent secret_id (host file):  present (36 bytes)

frontend_agent role_id (host):         1b886aa9-09d0-0781-e08b-1f954972e760
frontend_agent role_id (vault):        1b886aa9-09d0-0781-e08b-1f954972e760
frontend_agent secret_id (host file):  present (36 bytes)
```

>NOTE: A few points on the approle scripts

```text
- All approle setup scripts:
  - read the Vault admin token from `./backend/app/security/configuration_files/vault/bootstrap/root_token` (or `root_token.json`), and securely prompt if missing
  - write artifacts to `./container_data/vault/approle/<ROLE_NAME>/{role_id,secret_id}`
  - rotate `secret_id` by default (`ROTATE_SECRET_ID=1`)
- Optional overrides (same for all scripts):
  - `ROLE_NAME="<name>" ./backend/build_scripts/<script>.sh`
  - `ROTATE_SECRET_ID=0 ./backend/build_scripts/<script>.sh`
  - `OUT_DIR="/custom/path" ./backend/build_scripts/<script>.sh`
```

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

Vault Agents authenticate using **AppRole**. They require host-side artifacts mounted into the agent container(s):

- `./container_data/vault/approle/postgres_pgadmin_agent/{role_id,secret_id}`
- `./container_data/vault/approle/keycloak_agent/{role_id,secret_id}`
- `./container_data/vault/approle/fastapi_agent/{role_id,secret_id}`

### 2.1 Start Vault Agents (must authenticate before dependent services)

```bash
docker compose -f docker-compose.prod.yml up -d vault_agent_postgres_pgadmin vault_agent_keycloak vault_agent_fastapi vault_agent_frontend
```
```bash
docker logs --tail 200 -f vault_agent_postgres_pgadmin
```
```bash
docker logs --tail 200 -f vault_agent_keycloak
```
```bash
docker logs --tail 200 -f vault_agent_fastapi
```
```bash
docker logs --tail 200 -f vault_agent_frontend
```

# Confirm the rendered files exist for fastapi
```bash
docker exec -it vault_agent_fastapi sh -lc 'ls -lah /vault/rendered && echo && sed -n "1,80p" /vault/rendered/redis.conf'
```

### 2.2 Start Postgres

```bash
docker compose -f docker-compose.prod.yml up -d postgres_primary
```
```bash
docker logs --tail 200 -f postgres_primary
```

>NOTE: Once postgres is up and running, Run the following script which will configure the rest of the settings
> for postgress. This includes configuring needed databases, users and permissions for services like fastapi, keycloak etc

```bash
chmod +x ./backend/build_scripts/seed_postgres_with_vault_credentials.sh
./backend/build_scripts/seed_postgres_with_vault_credentials.sh \
  --ca-cert "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt"
```

>NOTE: Your output should resemble below

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

### 2.3 Start pgAdmin

>TODO: Integrate access with pgAdmin with keycloak
>NOTE: pgAdmin configurations include a servers.json file that gets populated with the main postgres database information 
> so it will connect to it automatically. Right now, it will connect with the root account. In future updates, there will be 
> user accounts created with limited access. This is just part of the init process for testing. In practice, the root account should be behind the vault
> and locked behind a key and each user who needs access should get their own individual accounts.

>NOTE:Default FQDN: Replace if you changed the FQDN in the .env file<br>
> https://pgadmin.networkengineertools.com:8443
```bash
docker compose -f docker-compose.prod.yml up -d --no-deps --build --force-recreate pgadmin
docker logs --tail 200 -f pgadmin
```

### 2.4 Start Keycloak
>NOTE:Default FQDN: Replace if you changed the FQDN in the .env file<br>
> I included a first time realm export file that you can import to setup the base information needed for 
> fastapi access. See file - backend/build_scripts/documentation/keycloak/keycloak_realm_files/initial_realm-export.json
> TODO: Build walkthrough's on creating accounts with proper roles assigned.
> TODO: Build this files creation into the init scripts and tie it into the chosen fqdn
> https://auth.networkengineertools.com:8443

```bash
docker compose -f docker-compose.prod.yml up -d --no-deps --build --force-recreate keycloak
```

```bash
docker logs --tail 200 -f keycloak
```

### 2.5 Start Redis

```bash
docker compose -f docker-compose.prod.yml up -d --no-deps --build --force-recreate redis
```

```bash
docker logs --tail 200 -f redis
```

### 2.6 Start FastAPI and Celery (In the long term flower is optional. You can use it for a quick look into celery jobs)

>NOTE:Default FQDN: Replace if you changed the FQDN in the .env file<br>
> https://api.networkengineertools.com:8443/docs
> https://flower.networkengineertools.com:8443

```bash
docker compose -f docker-compose.prod.yml up -d --no-deps --build --force-recreate fastapi_api celery_worker flower
```

```bash
docker logs --tail 200 -f fastapi_api
```

```bash
docker logs --tail 200 -f celery_worker
```

```bash
docker logs --tail 200 -f flower
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
```
```bash
docker logs --tail 200 -f nginx_gateway
```

### 2.8 Start PHP, Symfony, Nginx entrypoint for symfony

```bash
docker compose -f docker-compose.prod.yml up -d --no-deps --build --force-recreate frontend_nginx frontend_php_fpm
```

```bash
docker logs --tail 200 -f frontend_nginx
```

```bash
docker logs --tail 200 -f frontend_php_fpm
```

### 2.9 If any changes to the frontend Symfony side has been made, A cache clear / warmup must be done before changes take effect.
This should be baked into the rebuild, but in case it flakes out then the manual command is listed below for reference. 

```bash
docker exec -u 82:82 -it frontend_php_fpm sh -lc \
  'php bin/console cache:clear --env=prod && php bin/console cache:warmup --env=prod'
```

>NOTE: Here for reference in case you ever need to teardown and rebuild the frontend container set. 
> Sometimes it may flake or have issues with file permissions which cause the cache folders to not be 
> created correctly and with the wrong permisssions. 
 
### 2.9.1 Remove and recreate all frontend containers and volumes and rebuild
Run commands 2.9.1.1-.5
### 2.9.1.1
```bash
docker stop frontend_php_fpm vault_agent_frontend
```
### 2.9.1.2
```bash
docker rm frontend_php_fpm vault_agent_frontend frontend_var_init
```
### 2.9.1.3
```bash
docker volume rm network_tools_frontend_vault_rendered
```
### 2.9.1.4
```bash
chmod +x ./backend/build_scripts/frontend_approle_setup.sh
ROLE_NAME=frontend_agent ./backend/build_scripts/frontend_approle_setup.sh
```
### 2.9.1.5 (Production mode)
```bash
docker compose -f docker-compose.prod.yml up -d --no-deps --build --force-recreate vault_agent_frontend frontend_php_fpm
```

### 2.9.1.5.1 (Development mode - Enable symfony debugging tools / packages for developing locally)

#### Remove the containers completely then rebuild
```bash
docker stop frontend_php_fpm frontend_nginx
```

```bash
docker rm frontend_php_fpm frontend_nginx
```

```bash
docker compose -f docker-compose.prod.yml up -d --no-deps --build --force-recreate vault_agent_frontend
```

```bash
docker compose -f docker-compose.prod.yml --env-file .env.dev up -d --no-deps --build --force-recreate frontend_php_fpm frontend_nginx
```


---

## 3. Verify health (required checks)

### 3.1 Global container health

```bash
docker compose -f docker-compose.prod.yml ps
```

### 3.2 Verify Vault Agent Rendered Files exist and present in their target containers.

```bash
docker exec -it vault_agent_postgres_pgadmin sh -lc 'ls -lah /vault/rendered || true'
docker exec -it vault_agent_fastapi sh -lc 'ls -lah /vault/rendered || true'
docker exec -it vault_agent_keycloak sh -lc 'ls -lah /vault/rendered || true'
docker exec -it pgadmin sh -lc 'ls -lah /run/vault || true'
docker exec -it fastapi_api sh -lc 'ls -lah /run/vault || true'
docker exec -it keycloak sh -lc 'ls -lah /run/vault || true'
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

>NOTE: Example output
 
```bash
developer_network_tools@networktoolsvm:~/NETWORK_TOOLS$ docker exec -it postgres_primary sh -lc '
  set -e
  DB="$(cat /run/vault/postgres_db 2>/dev/null || echo postgres)"
  PASS="$(cat /run/vault/postgres_password 2>/dev/null)"
  export PGPASSWORD="$PASS"
  psql -h 127.0.0.1 -U network_tools_user -d "$DB" -c "\conninfo"
'
          Connection Information
      Parameter       |       Value        
----------------------+--------------------
 Database             | network_tools
 Client User          | network_tools_user
 Host                 | 127.0.0.1
 Server Port          | 5432
 Options              | 
 Protocol Version     | 3.0
 Password Used        | true
 GSSAPI Authenticated | false
 Backend PID          | 361
 SSL Connection       | false
 Superuser            | on
 Hot Standby          | off
(12 rows)

```

### 3.6 pgAdmin server registration and password behavior

- `servers.json` can pre-register server(s), but pgAdmin has security controls around how passwords are supplied/saved in server mode.
- If you use `PasswordExecCommand`, ensure server-mode support is enabled (see Appendix A).
- `servers.json` is only loaded on **first launch** when the pgAdmin configuration DB is created.

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

#### Example `cisco_api_console_secrets.json` (BASE Vault-rendered - You need your own development api keys!)

```json
{
  "advisories_client_secret ": "some key",
  "advisories_key": "some key",
  "cve_api_advisories_url": "https://apix.cisco.com/security/advisories/v2/product?product=Cisco",
  "eox_client_secret": "some secret",
  "eox_key": "some key",
  "url_CVEAdvisoriesBaseURL": "https://apix.cisco.com/security/advisories/v2/OSType/",
  "url_CVEAdvisoriesByProductURL": "https://apix.cisco.com/security/advisories/v2/product?product=",
  "url_CVEAdvisoriesCiscoIOSXR": "https://apix.cisco.com/security/advisories/v2/product?product=Cisco%20IOS%20XR",
  "url_EOXByProductID": "https://apix.cisco.com/supporttools/eox/rest/5/EOXByProductID/"
}
```

#### Example `device_login_profile_secrets.json` (BASE Vault-rendered - You need to fill out your own credentials)

```json
{
  "profile_one": {
    "enable_secret": "",
    "password": "",
    "ssh_port": 22,
    "username": "",
    "notes": "Optional notes describing this login credential"
  },
  "profile_two": {
    "enable_secret": "",
    "password": "",
    "ssh_port": 22,
    "username": "",
    "notes": "Optional notes describing this login credential"
  }
}
```

#### Example `frontend_secrets.json` (BASE Vault-rendered)

>NOTE: APP_DEBUG and APP_ENV are optional. 
> If they are not configured in vault (You need to set these manually) the container will default to production mode
> See notes below from the docker compose file.

```text
  # These need to be set to toggle your container from prod <-> dev
  # dev: target=dev, APP_ENV=dev, APP_DEBUG=1
  # prod: target=prod, APP_ENV=prod, APP_DEBUG=0
  #
  # Compose command to turn up a development container. Defaults to production
  # docker compose -f docker-compose.prod.yml up -d --env-file .env.dev --no-deps --build --force-recreate frontend_php_fpm
  #
  # If production is chosen, Default to the normal command in the readme.md file. See below as well.
  # docker compose -f docker-compose.prod.yml up -d --no-deps --build --force-recreate frontend_php_fpm
```

```json
{
  "APP_DEBUG": "1",
  "APP_ENV": "dev",
  "APP_SECRET": "clkKk_Uows26uP51U1kk8CNwGCQa1LZT8KkmatwlrbW1PjoTah8gIx4-74DLU5XOJWaYAzFGvNHQkF2ia3y4XA",
  "FASTAPI_OIDC_CLIENT_ID": "networktools-automation",
  "FASTAPI_OIDC_CLIENT_SECRET": "",
  "KEYCLOAK_CLIENT_ID": "networktools-web",
  "KEYCLOAK_CLIENT_SECRET": "",
  "KEYCLOAK_REALM": "network_tools"
}
```


## Appendix C - Final Directory Structure (Prior to removing sensitive files)
```bash
developer_network_tools@networktoolsvm:~/NETWORK_TOOLS$ tree --charset ascii
.
|-- backend
|   |-- app
|   |   |-- celery
|   |   |-- fastapi
|   |   |   |-- app
|   |   |   |   |-- celery_app.py
|   |   |   |   |-- database.py
|   |   |   |   |-- database_queries
|   |   |   |   |   |-- __init__.py
|   |   |   |   |   |-- postgres_insert_queries.py
|   |   |   |   |   `-- postgres_select_queries.py
|   |   |   |   |-- __init__.py
|   |   |   |   |-- main.py
|   |   |   |   |-- network_utilities
|   |   |   |   |   |-- icmp_check.py
|   |   |   |   |   `-- __init__.py
|   |   |   |   |-- routers
|   |   |   |   |   |-- auth_test.py
|   |   |   |   |   |-- celery_jobs.py
|   |   |   |   |   |-- cisco_api_reporting.py
|   |   |   |   |   |-- device_backups.py
|   |   |   |   |   `-- device_discovery.py
|   |   |   |   |-- security
|   |   |   |   |   |-- auth.py
|   |   |   |   |   |-- jwks_cache.py
|   |   |   |   |   `-- keycloak_settings.py
|   |   |   |   |-- shared_functions
|   |   |   |   |   |-- helpers
|   |   |   |   |   |   |-- helpers_a10.py
|   |   |   |   |   |   |-- helpers_arista.py
|   |   |   |   |   |   |-- helpers_authentication.py
|   |   |   |   |   |   |-- helpers_cisco.py
|   |   |   |   |   |   |-- helpers_configuration_backups.py
|   |   |   |   |   |   |-- helpers_datetime.py
|   |   |   |   |   |   |-- helpers_environment.py
|   |   |   |   |   |   |-- helpers_file_encryption.py
|   |   |   |   |   |   |-- helpers_generic.py
|   |   |   |   |   |   |-- helpers_hashicorp_vault.py
|   |   |   |   |   |   |-- helpers_juniper.py
|   |   |   |   |   |   |-- helpers_logging_config.py
|   |   |   |   |   |   |-- helpers_netmiko.py
|   |   |   |   |   |   |-- helpers_postgres.py
|   |   |   |   |   |   |-- helpers_sanitation.py
|   |   |   |   |   |   |-- helpers_snmp.py
|   |   |   |   |   |   |-- helpers_subnetting.py
|   |   |   |   |   |   `-- __init__.py
|   |   |   |   |   `-- __init__.py
|   |   |   |   `-- tasks.py
|   |   |   |-- bin
|   |   |   |   `-- entrypoint.sh
|   |   |   |-- certs
|   |   |   |   `-- networktools_ca.crt
|   |   |   |-- Dockerfile
|   |   |   |-- gunicorn_conf.py
|   |   |   |-- __init__.py
|   |   |   |-- requirements.txt
|   |   |   |-- run_server.py
|   |   |   |-- vault_agent
|   |   |   |   |-- agent.hcl
|   |   |   |   `-- templates
|   |   |   |       |-- fastapi_secrets.json.ctmpl
|   |   |   |       |-- redis.conf.ctmpl
|   |   |   |       `-- redis_password.ctmpl
|   |   |   `-- vault_env_exec.py
|   |   |-- __init__.py
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
|   |   |-- postgres
|   |   |   |-- certs
|   |   |   |-- config
|   |   |   |   |-- pg_hba.conf
|   |   |   |   `-- postgres.conf
|   |   |   |-- init
|   |   |   |   |-- 01_network_tools_schema_dump.sql
|   |   |   |   `-- initial_reference_network_tools_schema.sql
|   |   |   `-- vault_agent
|   |   |       |-- agent.hcl
|   |   |       `-- templates
|   |   |           |-- pgadmin_password.ctmpl
|   |   |           |-- postgres_db.ctmpl
|   |   |           |-- postgres_password.ctmpl
|   |   |           |-- postgres_user.ctmpl
|   |   |           `-- servers.json.ctmpl
|   |   `-- security
|   |       `-- configuration_files
|   |           `-- vault
|   |               |-- bootstrap
|   |               |   |-- bootstrap_credentials.json
|   |               |   |-- bootstrap_creds.env
|   |               |   |-- postgres_pgadmin_credentials.json
|   |               |   |-- postgres_pgadmin.env
|   |               |   |-- root_token
|   |               |   |-- root_token.json
|   |               |   |-- seeded_secrets_all.json
|   |               |   |-- seed_kv_spec.bootstrap_creds.json
|   |               |   |-- seed_kv_spec.postgres_pgadmin.json
|   |               |   `-- unseal_keys.json
|   |               |-- certs
|   |               |   |-- ca.crt
|   |               |   |-- cert.crt
|   |               |   `-- cert.key
|   |               |-- config
|   |               |   |-- certs
|   |               |   |-- fastapi_read.hcl
|   |               |   |-- keycloak_kv_read.hcl
|   |               |   |-- postgres_pgadmin_kv_read.hcl
|   |               |   `-- vault_configuration_primary_node.hcl
|   |               `-- Dockerfile
|   |-- backup_scripts
|   |-- build_scripts
|   |   |-- documentation
|   |   |   |-- celery
|   |   |   |   `-- troubleshooting
|   |   |   |       `-- celery_troubleshooting.md
|   |   |   |-- fastapi
|   |   |   |   |-- example_json_outputs
|   |   |   |   |   `-- get_cisco_eox
|   |   |   |   |       `-- example_reply_get_cisco_eox.json
|   |   |   |   |-- example_vault_data
|   |   |   |   |   |-- device_login_profiles_secrets.json
|   |   |   |   |   `-- fastapi_secrets.json
|   |   |   |   `-- test_scripts
|   |   |   |       |-- test_fastapi_keycloak_cc.sh
|   |   |   |       `-- test_payloads
|   |   |   |           |-- device_discovery_icmp.json
|   |   |   |           |-- device_discovery_start_device_discovery.json
|   |   |   |           |-- get_cisco_cve_os_version.json
|   |   |   |           |-- get_cisco_eox.json
|   |   |   |           `-- unique_os_versions_cve.json
|   |   |   |-- keycloak
|   |   |   |   |-- keycloak_how_to
|   |   |   |   |-- keycloak_realm_files
|   |   |   |   |   `-- initial_realm-export_26_4_7.json
|   |   |   |   |-- keycloak_setup_network_tools_fastapi.md
|   |   |   |   `-- test_scripts
|   |   |   |       `-- keycloak_all_in_one.sh
|   |   |   `-- postgres
|   |   |       `-- test_data_seed_files
|   |   |           `-- seed_devices_table.sql
|   |   |-- fastapi_approle_setup.sh
|   |   |-- generate_bootstrap_creds_and_seed.sh
|   |   |-- generate_local_networkengineertools_certs.sh
|   |   |-- guides
|   |   |   |-- seed_kv_spec.example.json
|   |   |   `-- seed_kv_spec.GUIDE.md
|   |   |-- keycloak_approle_setup.sh
|   |   |-- postgress_approle_setup.sh
|   |   |-- seed_postgres_with_vault_credentials.sh
|   |   |-- startover_scripts
|   |   |   |-- database_related
|   |   |   |   |-- drop_all_tables_network_tools.sql
|   |   |   |   `-- drop_specific_tables_network_tools.sql
|   |   |   `-- reset_network_tools_docker.sh
|   |   |-- validation_scripts
|   |   |   |-- check_approle_presence_and_ids_in_vault.sh
|   |   |   |-- postgres_inventory.sh
|   |   |   `-- read_postgres_pgadmin_approle.sh
|   |   |-- vault_first_time_init_only_rootless.sh
|   |   |-- vault_unseal_kv_seed_bootstrap_rootless.sh
|   |   `-- vault_unseal_multi_kv_seed_bootstrap_rootless.sh
|   |-- __init__.py
|   `-- nginx
|-- container_data
|   |-- backups
|   |   `-- device_configuration_backups
|   |-- logs
|   |   |-- celery
|   |   |   `-- network_tools_celery.log
|   |   `-- fastapi
|   |       `-- network_tools_fastapi.log
|   |-- postgres_backups
|   |-- postgres_primary
|   `-- vault
|       |-- approle
|       |   |-- fastapi_agent
|       |   |   |-- role_id
|       |   |   `-- secret_id
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
|-- __init__.py
|-- LICENSE
|-- README.full.md
`-- README.md

```