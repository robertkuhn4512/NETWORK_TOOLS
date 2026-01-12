# Keycloak (26.4.7) configuration for FastAPI authentication (JWT) + RBAC

This README walks you through configuring **Keycloak 26.4.7** (`quay.io/keycloak/keycloak:26.4.7`) so that:

- **Keycloak** is the **authentication mechanism** (users/scripts get tokens from Keycloak).
- **FastAPI** is the **resource server** (FastAPI validates JWT access tokens and enforces role-based access control).

Naming note (consistency)
- This document uses the prefix **`networktools`** everywhere (clients/roles/groups), per your request.
- Realm name used in examples: **`network_tools`** (you can rename if you prefer; just keep it consistent with your FastAPI config).

---

## Table of contents

- [Target architecture](#target-architecture)
- [Prerequisites](#prerequisites)
- [Step 0: Make Keycloak proxy-correct (issuer must be HTTPS)](#step-0-make-keycloak-proxy-correct-issuer-must-be-https)
- [Step 1: Create the realm](#step-1-create-the-realm)
- [Step 2: Create roles and groups (RBAC model)](#step-2-create-roles-and-groups-rbac-model)
- [Step 3: Create clients](#step-3-create-clients)
  - [Client: networktools-web (browser UI; Auth Code + PKCE)](#client-networktools-web-browser-ui-auth-code--pkce)
  - [Client: networktools-cli (human-run CLI; Device Authorization Grant)](#client-networktools-cli-human-run-cli-device-authorization-grant)
  - [Client: networktools-automation (unattended jobs; Client Credentials/service account)](#client-networktools-automation-unattended-jobs-client-credentialssvc-account)
  - [Optional client: fastapi (introspection/admin use only)](#optional-client-fastapi-introspectionadmin-use-only)
- [Step 4: Create users and assign access](#step-4-create-users-and-assign-access)
- [Step 5: Validate tokens contain what FastAPI needs](#step-5-validate-tokens-contain-what-fastapi-needs)
- [Step 6: Vault injection expectations for FastAPI](#step-6-vault-injection-expectations-for-fastapi)
- [Recommended screenshots to capture](#recommended-screenshots-to-capture)
- [References](#references)

---

## Target architecture

```mermaid
flowchart LR
  U[User / CLI / Job] -->|Get token| KC[Keycloak (OIDC)]
  U -->|Authorization: Bearer <token>| API[FastAPI (Resource Server)]
  API -->|OIDC discovery + JWKS (cached)| KC
  API -->|Vault Agent rendered config| V[/run/vault/fastapi_secrets.json]
```

Key point: **FastAPI does not receive user passwords**. It receives **bearer tokens** (JWTs) and validates them.

---

## Prerequisites

- Keycloak reachable at: `https://auth.networkengineertools.com`
- You can log into the Keycloak Admin Console
- You have a reverse proxy (Nginx) terminating TLS in front of Keycloak

---

## Step 0: Make Keycloak proxy-correct (issuer must be HTTPS)

This is the single most important correctness check for FastAPI JWT validation.

1. Open the realm discovery document:

   `https://auth.networkengineertools.com/realms/network_tools/.well-known/openid-configuration`

2. Confirm the JSON values are **externally correct**:
   - `issuer` starts with: `https://auth.networkengineertools.com/realms/network_tools`
   - `jwks_uri` is on the same HTTPS host

If you see `http://keycloak:8080/...` or an internal hostname/IP, fix your Keycloak reverse-proxy/hostname settings.

Common container env settings behind an HTTPS reverse proxy:

```yaml
keycloak:
  image: quay.io/keycloak/keycloak:26.4.7
  environment:
    KC_PROXY_HEADERS: "xforwarded"       # or "forwarded"
    KC_HOSTNAME: "https://auth.networkengineertools.com"
    KC_HOSTNAME_STRICT: "false"
    KC_HTTP_ENABLED: "true"              # if TLS terminates at Nginx and Keycloak listens HTTP internally
  command: ["start"]
```

See Keycloak docs: reverse proxy + hostname configuration.

---

## Step 1: Create the realm

1. Log into the **Admin Console**
2. Use the realm dropdown (top-left) → **Create realm**
3. Name it: `network_tools` (or your preferred realm name)
4. Create

---

## Step 2: Create roles and groups (RBAC model)

### 2.1 Create realm roles

Create these realm roles:

- `networktools_admin`
- `networktools_operator`
- `networktools_readonly`

Admin Console path (typical):
- **Realm roles** → **Create role**

### 2.2 Create groups and map roles (recommended)

Create these groups:

- `networktools-admins` → assign role `networktools_admin`
- `networktools-operators` → assign role `networktools_operator`
- `networktools-readonly` → assign role `networktools_readonly`

This makes onboarding easy: **add user to group** instead of managing roles one-by-one.

Admin Console path (typical):
- **Groups** → **Create group**
- Open group → **Role mapping** → add realm roles

---

## Step 3: Create clients

You want three practical client types for your roadmap:

1. **Web frontend** (Authorization Code + PKCE): `networktools-web`
2. **User-run CLI** (Device Authorization Grant): `networktools-cli`
3. **Unattended automation** (Client Credentials): `networktools-automation`

### Client: networktools-web (browser UI; Auth Code + PKCE)

Create an OIDC client:

- **Client ID:** `networktools-web`
- **Client authentication:** OFF (public client)
- **Standard flow:** ON
- **PKCE:** Required / S256
- **Valid redirect URIs:** your frontend URLs, e.g. `https://networkengineertools.com/*`
- **Web origins:** your frontend origin (as appropriate)

This client is for your future web UI and also provides a clean Swagger UI “Authorize” experience later if you choose.

### Client: networktools-cli (human-run CLI; Device Authorization Grant)

Create an OIDC client:

- **Client ID:** `networktools-cli`
- **Client authentication:** OFF (public client)
- Enable **Device Authorization Grant** in the client capability settings
- Optional: also enable **Standard flow + PKCE** if you want browser-based login from CLI

This supports a secure “terminal login” pattern without embedding user passwords into scripts.

### Client: networktools-automation (unattended jobs; Client Credentials/svc account)

Create an OIDC client:

- **Client ID:** `networktools-automation`
- **Client authentication:** ON (confidential)
- Enable **Service accounts**
- Disable interactive flows you don’t need (Standard flow OFF, etc.)

Then assign roles to the service account:

- Open client → **Service account roles** (or equivalent UI section)
- Grant one or more roles, e.g. `networktools_operator` (or `networktools_admin` for break-glass only)

Store the **client secret** for `networktools-automation` in Vault (preferred), not in code.

### Optional client: fastapi (introspection/admin use only)

FastAPI does **not** need a client secret to validate JWTs via JWKS.

Only create a `fastapi` confidential client if you explicitly want:
- Token introspection, or
- Keycloak Admin API calls

If you do create it:

- **Client ID:** `fastapi`
- **Client authentication:** ON
- Service accounts: ON (optional)
- Store `fastapi` client secret into `/run/vault/fastapi_secrets.json` for FastAPI use

---

## Step 4: Create users and assign access

Create your human users (examples):
- `rob`
- `alice`
- `bob`

Then assign access via groups (recommended):

- Add admins to `networktools-admins`
- Add operators to `networktools-operators`
- Add readonly users to `networktools-readonly`

Admin Console path (typical):
- **Users** → **Create user**
- **Credentials** → set password
- **Groups** → join appropriate group(s)

---

## Step 5: Validate tokens contain what FastAPI needs

FastAPI’s authorization logic typically needs:

- `iss` (issuer): must match your realm issuer exactly
- `exp` (expiry)
- `azp` (authorized party): identifies which client obtained the token
- roles:
  - realm roles typically appear in `realm_access.roles`
  - client roles may appear under `resource_access.<client_id>.roles`

### Quick validation endpoints

- Discovery:
  - `https://auth.networkengineertools.com/realms/network_tools/.well-known/openid-configuration`
- JWKS:
  - `https://auth.networkengineertools.com/realms/network_tools/protocol/openid-connect/certs`

### Practical “token sanity” workflow

1. Obtain an access token via any of the above clients
2. Decode JWT (locally) and confirm:
   - `iss` is correct (HTTPS external host)
   - `azp` is one of: `networktools-web`, `networktools-cli`, `networktools-automation`
   - roles are present as expected

---

## Step 6: Vault injection expectations for FastAPI

You stated FastAPI receives injected configuration at:

- `/run/vault/fastapi_secrets.json`

Recommended keys to render into that file (minimum):

```json
{
  "KEYCLOAK_BASE_URL": "https://auth.networkengineertools.com",
  "KEYCLOAK_REALM": "network_tools",
  "FASTAPI_ALLOWED_AZP": "networktools-web,networktools-cli,networktools-automation"
}
```

Optional keys (only if you want them):

```json
{
  "FASTAPI_VERIFY_AUDIENCE": "false",
  "FASTAPI_EXPECTED_AUDIENCE": "networktools-api",
  "FASTAPI_USE_INTROSPECTION": "false",
  "KEYCLOAK_INTROSPECTION_CLIENT_ID": "fastapi",
  "KEYCLOAK_INTROSPECTION_CLIENT_SECRET": "********"
}
```

Recommendation:
- Prefer JWKS/JWT validation and enforce `FASTAPI_ALLOWED_AZP` (client allowlist).
- Enable introspection only if you have a specific need for “active right now” checks.

---

## Recommended screenshots to capture

Because you asked for screenshot guidance and you’re on **Keycloak 26.4.7**, here are the exact screens worth capturing for documentation and troubleshooting.

1. **Realm creation**
   - Realm dropdown → Create realm
2. **Realm roles**
   - Realm roles list + one role detail (`networktools_admin`)
3. **Groups + role mapping**
   - Group list + group role mappings (showing `networktools-admins` → `networktools_admin`)
4. **Client creation (networktools-web)**
   - Client settings showing public client + standard flow + PKCE + redirect URIs
5. **Client creation (networktools-cli)**
   - Client settings showing device authorization grant enabled
6. **Client creation (networktools-automation)**
   - Client settings showing confidential client + service accounts enabled
7. **Service account roles**
   - `service-account-networktools-automation` role mappings
8. **User detail + groups**
   - Example user assigned to `networktools-operators`
9. **Discovery doc sanity check**
   - Screenshot of `.well-known/openid-configuration` showing correct `issuer` and `jwks_uri`

If you paste any one of these screenshots back into chat, I can annotate exactly which toggles to flip on that screen for your setup.

---

## References

Keycloak:
- Reverse proxy: https://www.keycloak.org/server/reverseproxy
- Hostname configuration: https://www.keycloak.org/server/hostname
- OIDC layers / endpoints and guidance: https://www.keycloak.org/securing-apps/oidc-layers

OAuth standards:
- OAuth 2.1 overview: https://oauth.net/2.1/
- OAuth 2.1 draft: https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/
- Device Flow (RFC 8628): https://datatracker.ietf.org/doc/html/rfc8628
