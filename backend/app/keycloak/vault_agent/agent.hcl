#------------------------------------------------------------------------------
# keycloak_vault_agent.hcl
#
# Notes / How to run
#   1) Mount templates into /vault/templates:
#        - keycloak.env.ctmpl
#   2) Mount AppRole credentials into /vault/approle:
#        - role_id
#        - secret_id
#   3) Mount CA cert into /vault/ca/ca.crt
#   4) Start the agent and confirm it renders:
#        - /vault/rendered/keycloak.env
#------------------------------------------------------------------------------

pid_file = "/tmp/vault-agent.pid"

vault {
  address = "https://vault_production_node:8200"
  ca_cert = "/vault/ca/ca.crt"
}

auto_auth {
  method "approle" {
    mount_path = "auth/approle"
    config = {
      role_id_file_path                   = "/vault/approle/role_id"
      secret_id_file_path                 = "/vault/approle/secret_id"
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

template {
  source      = "/vault/templates/keycloak.env.ctmpl"
  destination = "/vault/rendered/keycloak.env"
  perms       = "0444"
}

template {
  source      = "/vault/templates/keycloak_tls.crt.ctmpl"
  destination = "/vault/rendered/tls/server.crt"
  create_dest_dirs = true
  perms       = "0644"
}

template {
  source      = "/vault/templates/keycloak_tls.key.ctmpl"
  destination = "/vault/rendered/tls/server.key"
  create_dest_dirs = true
  perms       = "0644"
}
