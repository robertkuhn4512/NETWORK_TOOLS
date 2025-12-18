# docker/vault.Dockerfile

FROM hashicorp/vault:1.21.1

# Switch to root to install packages
USER root

# Install jq and a few useful CLI tools for debugging
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      jq \
      curl \
      bash \
      less \
 && rm -rf /var/lib/apt/lists/*

# Switch back to the vault user (matches the official image default)
USER vault