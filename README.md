## This file contains links to only the steps needed to bring up all the containers and services on a fresh install (This assumes your Host OS is all set). See the full readme file for longer explinations.
### Some sections may not hyperlink correctly, Until I figure out why you should be able to search for the listed section number.

- [Full README](./README.full.md)
- [Ubuntu ARM Development Server – NETWORK_TOOLS Setup](./README.full.md#ubuntu-arm-development-server-network_tools-setup)
  - [Table of Contents](./README.full.md#table-of-contents)

Generate Self Signed Certificates (Or you can replace with your own:Procedure is WIP)

1.[generate_local_keycloak_certs.sh](backend%2Fbuild_scripts%2Fgenerate_local_keycloak_certs.sh)

```bash
$HOME/NETWORK_TOOLS/backend/build_scripts/generate_local_keycloak_certs.sh
```
Or to overwrite existing certificate files
```bash
$HOME/NETWORK_TOOLS/backend/build_scripts/generate_local_keycloak_certs.sh --force
```

2.[generate_local_postgres_certs.sh](backend%2Fbuild_scripts%2Fgenerate_local_postgres_certs.sh)

```bash
$HOME/NETWORK_TOOLS/backend/build_scripts/generate_local_postgres_certs.sh
```
Or to overwrite existing certificate files
```bash
$HOME/NETWORK_TOOLS/backend/build_scripts/generate_local_postgres_certs.sh --force
```

3.[generate_local_vault_certs.sh](backend%2Fbuild_scripts%2Fgenerate_local_vault_certs.sh)

```bash
$HOME/NETWORK_TOOLS/backend/build_scripts/generate_local_vault_certs.sh
```
Or to overwrite existing certificate files
```bash
$HOME/NETWORK_TOOLS/backend/build_scripts/generate_local_vault_certs.sh --force
```

4.[generate_local_pgadmin_certs.sh](backend%2Fbuild_scripts%2Fgenerate_local_pgadmin_certs.sh)

```bash
$HOME/NETWORK_TOOLS/backend/build_scripts/generate_local_pgadmin_certs.sh
```
Or to overwrite existing certificate files
```bash
$HOME/NETWORK_TOOLS/backend/build_scripts/generate_local_pgadmin_certs.sh --force
```

5.[vault_first_time_init_only_rootless.sh](backend%2Fbuild_scripts%2Fvault_first_time_init_only_rootless.sh)

CLI Command<br>
Initial vault build command
```bash
bash ./backend/build_scripts/vault_first_time_init_only_rootless.sh \
  --vault-addr "https://vault_production_node:8200" \
  --ca-cert "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt" \
  --init-shares 5 --init-threshold 3
```

6.[generate_postgres_pgadmin_bootstrap_creds_and_seed.sh](backend%2Fbuild_scripts%2Fgenerate_postgres_pgadmin_bootstrap_creds_and_seed.sh)
```bash
bash ./backend/build_scripts/generate_postgres_pgadmin_bootstrap_creds_and_seed.sh \
  --vault-addr "https://vault_production_node:8200" \
  --ca-cert "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt" \
  --unseal-required 3
```