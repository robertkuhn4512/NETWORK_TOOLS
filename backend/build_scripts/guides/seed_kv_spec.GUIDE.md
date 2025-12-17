# Multi-mount Vault KV seed spec guide

This guide describes the JSON spec consumed by `vault_unseal_multi_kv_seed_bootstrap_rootless.sh`.

## What the script does

In one run, it can:

1) Unseal Vault (if sealed) using `unseal_keys.json`  
2) Enable and configure one or more KV mounts (KV v1 or KV v2)  
3) Seed one or more secret paths under each mount  
4) Write a consolidated “resolved secrets” artifact under `bootstrap/` (for download + secure storage)

## Spec file location (recommended)

Store the spec alongside your other bootstrap artifacts:

`$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/seed_kv_spec.json`

## Top-level schema

The spec must be a JSON object with:

- `mounts` (array, required): each entry defines a KV mount and its secrets.

### Mount object fields

Required:
- `mount` (string): mount path, e.g. `"app_secrets"` (the script treats it as a mount and will use `mount/` in Vault)

Optional:
- `version` (number 1 or 2, default 2): KV engine version
- `description` (string): mount description (when enabling)
- `v2_config` (object): only used for KV v2
  - `max_versions` (number)
  - `cas_required` (boolean)
  - `delete_version_after` (string, e.g. `"0s"`, `"24h"`)
- `prefix` (string): prepends all secret paths, e.g. `"bootstrap"` so `creds` becomes `bootstrap/creds`
- `secrets` (required): either an array of items or a map of path -> data

## `secrets` formats

### A) Array format (most explicit)

Each item is:

- `path` (string): secret path under the mount (and under `prefix` if provided)
- `data` (object): key/value pairs stored in Vault
- `cas` (number, optional): KV v2 CAS value. Default is 0.

Example:
```json
[
  {
    "path": "creds",
    "data": { "username": "api_user", "password": "secret" },
    "cas": 0
  }
]
```

### B) Map format (compact)

Keys are secret paths; values are *data objects*:

```json
{
  "creds": { "username": "api_user", "password": "secret" },
  "jwt":   { "signing_key_hex": "..." }
}
```

Important: in map format, each value must be a JSON object. Scalars are not allowed.

## Supported value types inside `data`

For each key in `data`, values may be:

### 1) Literal values
- string, number, boolean
- arrays
- nested objects

Example:
```json
{
  "enabled": true,
  "port": 3306,
  "allowed_subnets": ["10.0.0.0/8"],
  "nested": { "a": 1, "b": 2 }
}
```

### 2) Generated values
Use:
```json
{ "generate": { "type": "hex|base64|url_safe|uuid", "bytes": 32 } }
```

- `hex`: `bytes` = number of random bytes before hex encoding (32 bytes => 64 hex chars)
- `base64`: random bytes base64 encoded
- `url_safe`: URL-safe token (uses Python if available; otherwise base64)
- `uuid`: ignores bytes

Examples:
```json
{
  "api_key": { "generate": { "type": "url_safe", "bytes": 32 } },
  "aes_key_b64": { "generate": { "type": "base64", "bytes": 32 } },
  "signing_key_hex": { "generate": { "type": "hex", "bytes": 64 } },
  "install_id": { "generate": { "type": "uuid" } }
}
```

### 3) Environment variable injection
Use:
```json
{ "env": "ENV_VAR_NAME" }
```

Optional env:
```json
{ "env": "ENV_VAR_NAME", "optional": true }
```

If optional and missing, the key is skipped (not written).

## Recommended command line usage

Validate your spec:
```bash
jq . "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/seed_kv_spec.json" >/dev/null
```

Dry-run (resolve/generate but don’t write):
```bash
bash ./backend/build_scripts/vault_unseal_multi_kv_seed_bootstrap_rootless.sh \
  --vault-addr "https://vault_production_node:8200" \
  --ca-cert "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt" \
  --prompt-token \
  --spec-json "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/seed_kv_spec.json" \
  --dry-run
```

Real run:
```bash
bash ./backend/build_scripts/vault_unseal_multi_kv_seed_bootstrap_rootless.sh \
  --vault-addr "https://vault_production_node:8200" \
  --ca-cert "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt" \
  --unseal-required 3 \
  --prompt-token \
  --spec-json "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/seed_kv_spec.json"
```

Printing secrets (sensitive):
- Add `--print-secrets` only when you are in a controlled environment and you intend to capture/store output securely.

## Artifact output and operational hygiene

The script writes a consolidated artifact under `bootstrap/`, default:

`.../bootstrap/seeded_secrets_all.json`

Recommended workflow:
1) Download the artifact + your init artifacts (unseal keys and root token) to a secure offline location
2) Remove them from the server after you verify the downloads

Example:
```bash
scp -p <user>@<server>:"$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/seeded_secrets_all.json" .
scp -p <user>@<server>:"$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/unseal_keys.json" .
scp -p <user>@<server>:"$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token" .
scp -p <user>@<server>:"$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token.json" .

# After verification:
ssh <user>@<server> 'rm -f "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/seeded_secrets_all.json" \
  "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/unseal_keys.json" \
  "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token" \
  "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token.json"'
```
