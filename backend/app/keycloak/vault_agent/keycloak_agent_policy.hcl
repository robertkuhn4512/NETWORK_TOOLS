#------------------------------------------------------------------------------
# keycloak_agent_policy.hcl
#
# Minimal read-only policy for the Keycloak Vault Agent.
# KV engine: app_postgres_secrets (KV v2)
#------------------------------------------------------------------------------

path "auth/token/lookup-self" {
  capabilities = ["read"]
}

path "auth/token/renew-self" {
  capabilities = ["update"]
}

path "app_postgres_secrets/data/keycloak_bootstrap" {
  capabilities = ["read"]
}

path "app_postgres_secrets/data/keycloak_postgres" {
  capabilities = ["read"]
}

path "app_postgres_secrets/data/keycloak_runtime" {
  capabilities = ["read"]
}

path "app_postgres_secrets/metadata/keycloak_bootstrap" {
  capabilities = ["list", "read"]
}

path "app_postgres_secrets/metadata/keycloak_postgres" {
  capabilities = ["list", "read"]
}

path "app_postgres_secrets/metadata/keycloak_runtime" {
  capabilities = ["list", "read"]
}
