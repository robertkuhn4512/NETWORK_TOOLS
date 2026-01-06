path "app_network_tools_secrets/data/pgadmin" {
  capabilities = ["read"]
}
path "app_network_tools_secrets/data/pgadmin/*" {
  capabilities = ["read"]
}

path "app_network_tools_secrets/data/postgres" {
  capabilities = ["read"]
}
path "app_network_tools_secrets/data/postgres/*" {
  capabilities = ["read"]
}

path "app_network_tools_secrets/metadata/pgadmin" {
  capabilities = ["read", "list"]
}
path "app_network_tools_secrets/metadata/pgadmin/*" {
  capabilities = ["read", "list"]
}

path "app_network_tools_secrets/metadata/postgres" {
  capabilities = ["read", "list"]
}
path "app_network_tools_secrets/metadata/postgres/*" {
  capabilities = ["read", "list"]
}

path "sys/internal/ui/mounts/*" {
  capabilities = ["read"]
}
