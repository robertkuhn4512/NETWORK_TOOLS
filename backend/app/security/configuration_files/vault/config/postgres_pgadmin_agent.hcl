pid_file = "/tmp/vault-agent.pid"

auto_auth {
  method "approle" {
    mount_path = "auth/approle"
    config = {
      role_id_file_path                   = "/run/secrets/vault_postgres_pgadmin_role_id"
      secret_id_file_path                 = "/run/secrets/vault_postgres_pgadmin_secret_id"
      remove_secret_id_file_after_reading = false
    }
  }

  sink "file" {
    config = {
      path = "/run/postgres_secrets/vault/.vault-token"
    }
  }
}

vault {
  address = "https://${PRIMARY_VAULT_SERVER_FQDN_FULL}:8200"
  ca_cert = "/vault/certs/ca.crt"
}

template {
  destination = "/run/postgres_secrets/vault/postgres_db"
  perms       = "0644"
  contents    = "{{ with secret \"app_postgress_secrets/data/postgres\" }}{{ .Data.data.POSTGRES_DB }}{{ end }}\n"
}

template {
  destination = "/run/postgres_secrets/vault/postgres_user"
  perms       = "0644"
  contents    = "{{ with secret \"app_postgress_secrets/data/postgres\" }}{{ .Data.data.POSTGRES_USER }}{{ end }}\n"
}

template {
  destination = "/run/postgres_secrets/vault/postgres_password"
  perms       = "0644"
  contents    = "{{ with secret \"app_postgress_secrets/data/postgres\" }}{{ .Data.data.POSTGRES_PASSWORD }}{{ end }}\n"
}

template {
  destination = "/run/postgres_secrets/vault/pgadmin_password"
  perms       = "0644"
  contents    = "{{ with secret \"app_postgress_secrets/data/pgadmin\" }}{{ .Data.data.PGADMIN_DEFAULT_PASSWORD }}{{ end }}\n"
}

# Marker file used by the boot wrappers to decide "Vault is ready"
template {
  destination = "/run/postgres_secrets/vault/.ready"
  perms       = "0644"
  contents    = "{{ with secret \"app_postgress_secrets/data/postgres\" }}{{ end }}{{ with secret \"app_postgress_secrets/data/pgadmin\" }}{{ end }}ready\n"
}