pid_file = "/tmp/vault-agent.pid"

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
  source      = "/vault/templates/frontend.env.ctmpl"
  destination = "/vault/rendered/frontend.env"
  perms       = "0640"

  exec = {
    command = [
      "sh", "-lc",
      "chown 0:82 /vault/rendered && chmod 2750 /vault/rendered && chown 0:82 /vault/rendered/frontend.env && chmod 0640 /vault/rendered/frontend.env"
    ]
    timeout = "10s"
  }
}
