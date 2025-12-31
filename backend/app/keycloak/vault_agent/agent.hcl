# keycloak_vault_agent.hcl
# Vault Agent config for Keycloak (AppRole). Mirrors your existing postgres/pgadmin agent pattern.

pid_file = "/tmp/vault-agent.pid"

vault {
  address = "https://vault_production_node:8200"
  ca_cert = "/vault/ca/ca.crt"
}

auto_auth {
  method "approle" {
    mount_path = "auth/approle"
    config = {
      role_id_file_path   = "/vault/approle/role_id"
      secret_id_file_path = "/vault/approle/secret_id"
      remove_secret_id_file_after_reading = false
    }
  }

  sink "file" {
    config = {
      path = "/vault/rendered/.vault-token"
      mode = 0400
    }
  }
}

# Render env file for Keycloak container to source
template {
  source      = "/vault/templates/keycloak.env.ctmpl"
  destination = "/vault/rendered/keycloak.env"
  perms       = "0400"
}

# Render TLS cert + key (Keycloak HTTPS). These must exist for production.
template {
  source      = "/vault/templates/keycloak_tls.crt.ctmpl"
  destination = "/vault/rendered/keycloak_tls.crt"
  perms       = "0400"
}

template {
  source      = "/vault/templates/keycloak_tls.key.ctmpl"
  destination = "/vault/rendered/keycloak_tls.key"
  perms       = "0400"
}

# Optional: Postgres CA for verify-full JDBC settings
template {
  source      = "/vault/templates/postgres_ca.crt.ctmpl"
  destination = "/vault/rendered/postgres_ca.crt"
  perms       = "0400"
}
