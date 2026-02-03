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


# Allow read access to the 'cisco_api_console' secret
path "app_network_tools_secrets/data/cisco_api_console" {
    capabilities = ["read"]
}

# Allow listing of secrets within the 'app_network_tools_secrets' mount for UI/CLI navigation
path "app_network_tools_secrets/metadata/cisco_api_console/*" {
    capabilities = ["list"]
}

# Allow read access to the 'snmp_v2' secret
path "app_network_tools_secrets/data/snmp_v2" {
    capabilities = ["read"]
}

# Allow listing of secrets within the 'app_network_tools_secrets' mount for UI/CLI navigation
path "app_network_tools_secrets/metadata/snmp_v2/*" {
    capabilities = ["list"]
}

# Allow read access to the 'snmp_v3' secret
path "app_network_tools_secrets/data/snmp_v3" {
    capabilities = ["read"]
}

# Allow listing of secrets within the 'app_network_tools_secrets' mount for UI/CLI navigation
path "app_network_tools_secrets/metadata/snmp_v3/*" {
    capabilities = ["list"]
}

# Allow read access to the 'frontend_secrets' secret
path "app_network_tools_secrets/data/frontend_secrets" {
    capabilities = ["read"]
}

# Allow listing of secrets within the 'app_network_tools_secrets' mount for UI/CLI navigation
path "app_network_tools_secrets/metadata/frontend_secrets/*" {
    capabilities = ["list"]
}