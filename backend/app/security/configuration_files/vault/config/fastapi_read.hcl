# Read secrets (KV v1 or KV v2 data paths)
path "app_network_tools_secrets/data/fastapi*" {
  capabilities = ["read"]
}

# If KV v2, allow listing metadata (helps /UI and some tooling)
path "app_network_tools_secrets/metadata/fastapi*" {
  capabilities = ["list"]
}

# Allow read access to the 'device_login_profiles' secret
path "app_network_tools_secrets/data/device_login_profiles" {
    capabilities = ["read"]
}

# Allow listing of secrets within the 'app_network_tools_secrets' mount for UI/CLI navigation
path "app_network_tools_secrets/metadata/device_login_profiles/*" {
    capabilities = ["list"]
}