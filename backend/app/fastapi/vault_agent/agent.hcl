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
    }
  }
}

template_config {
  exit_on_retry_failure = false
  static_secret_render_interval = "30s"
}

template {
  source      = "/vault/templates/fastapi_secrets.json.ctmpl"
  destination = "/vault/rendered/fastapi_secrets.json"
  perms       = "0444"
}
