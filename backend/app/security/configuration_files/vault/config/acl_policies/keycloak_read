# --- Allow KV v2 reads for the exact Keycloak secrets this agent renders

# keycloak_tls
path "app_network_tools_secrets/data/keycloak_tls" {
  capabilities = ["read"]
}
path "app_network_tools_secrets/data/keycloak_tls/*" {
  capabilities = ["read"]
}

# keycloak_postgres
path "app_network_tools_secrets/data/keycloak_postgres" {
  capabilities = ["read"]
}
path "app_network_tools_secrets/data/keycloak_postgres/*" {
  capabilities = ["read"]
}

# OPTIONAL (include if your templates also read these; you had them in earlier logs)
# keycloak_bootstrap
path "app_network_tools_secrets/data/keycloak_bootstrap" {
  capabilities = ["read"]
}
path "app_network_tools_secrets/data/keycloak_bootstrap/*" {
  capabilities = ["read"]
}

# keycloak_runtime
path "app_network_tools_secrets/data/keycloak_runtime" {
  capabilities = ["read"]
}
path "app_network_tools_secrets/data/keycloak_runtime/*" {
  capabilities = ["read"]
}

# --- KV v2 metadata (optional, but helps if anything lists/checks metadata)
path "app_network_tools_secrets/metadata/keycloak_tls" {
  capabilities = ["read", "list"]
}
path "app_network_tools_secrets/metadata/keycloak_tls/*" {
  capabilities = ["read", "list"]
}

path "app_network_tools_secrets/metadata/keycloak_postgres" {
  capabilities = ["read", "list"]
}
path "app_network_tools_secrets/metadata/keycloak_postgres/*" {
  capabilities = ["read", "list"]
}

# OPTIONAL (if you included bootstrap/runtime above, include their metadata too)
path "app_network_tools_secrets/metadata/keycloak_bootstrap" {
  capabilities = ["read", "list"]
}
path "app_network_tools_secrets/metadata/keycloak_bootstrap/*" {
  capabilities = ["read", "list"]
}

path "app_network_tools_secrets/metadata/keycloak_runtime" {
  capabilities = ["read", "list"]
}
path "app_network_tools_secrets/metadata/keycloak_runtime/*" {
  capabilities = ["read", "list"]
}

# --- Allow Vault Agent KV-v2 mount preflight checks, but scoped to this mount
path "sys/internal/ui/mounts/app_network_tools_secrets/*" {
  capabilities = ["read"]
}
