pid_file = "/tmp/vault-agent.pid"

vault {
  address = "https://vault_production_node:8200"
  # Use your dev CA if available; otherwise this can point to whatever CA file you mount.
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
    }
  }
}

template {
  source      = "/vault/templates/postgres_db.ctmpl"
  destination = "/vault/rendered/postgres_db"
  perms       = "0444"
}

template {
  source      = "/vault/templates/postgres_user.ctmpl"
  destination = "/vault/rendered/postgres_user"
  perms       = "0444"
}

template {
  source      = "/vault/templates/postgres_password.ctmpl"
  destination = "/vault/rendered/postgres_password"
  perms       = "0444"
}

template {
  source      = "/vault/templates/pgadmin_password.ctmpl"
  destination = "/vault/rendered/pgadmin_password"
  perms       = "0444"
}

template {
  source      = "/vault/templates/servers.json.ctmpl"
  destination = "/vault/rendered/servers.json"
  perms       = "0644"
}
