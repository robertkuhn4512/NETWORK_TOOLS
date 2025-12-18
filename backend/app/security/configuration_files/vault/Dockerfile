# docker/vault.Dockerfile

# NOTE: I am leaving this for now. This does NOT Apply to this build as the container is using
# a base image with nothing special. These commands will not work as they are unavailable.
# This would mainly be needed if I wanted to do any debugging in the container itself. and
# Packages like curl and jq are useful. I can currently do any debugging on the host OS
# Just using the docker exec -it commands.

# These commands would pair with the following docker-compose lines. Just unhash them if I decide to swap this container
# to a custom linux build

    #build:
    #  context: backend/app/security/configuration_files/vault
    #  dockerfile: Dockerfile

# FROM hashicorp/vault:1.21.1

# Switch to root to install packages
# USER root

# Install jq and a few useful CLI tools for debugging
# RUN apt-get update \
#  && apt-get install -y --no-install-recommends \
#       jq \
#       curl \
#       bash \
#       less \
#  && rm -rf /var/lib/apt/lists/*

# Switch back to the vault user (matches the official image default)
# USER vault