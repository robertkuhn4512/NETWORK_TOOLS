# Ubuntu ARM Development Server – NETWORK_TOOLS Setup

This document describes how to prepare a fresh **Ubuntu ARM** server (running in your preferred VM platform) as a development platform for the **NETWORK_TOOLS** ecosystem.

Initial focus:

- Basic system preparation
- Fixing a common slow `sudo` issue
- Creating a dedicated development user and code root
- Setting up SSH keys
- Hardening SSH access (while keeping a safe fallback)

Later, this server will host:

- FastAPI applications
- MariaDB
- postgres
- HashiCorp Vault
- Keycloak
- Rootless Docker for running these services under a non-privileged account

---

## Table of Contents

- [0. Repository File Structure](#0-repository-file-structure)  
- [1. System Preparation](#1-system-preparation)  
  - [1.1 Assumptions](#11-assumptions)  
  - [1.2 Update the Operating System](#12-update-the-operating-system)  
  - [1.3 Address Slow `sudo` Response (Optional)](#13-address-slow-sudo-response-optional)  
  - [1.4 Create a Dedicated Development User and Code Root](#14-create-a-dedicated-development-user-and-code-root)  
    - [1.4.1 Create the `developer_network_tools` User](#141-create-the-developer_network_tools-user)  
    - [1.4.2 Create the `NETWORK_TOOLS` Code Root](#142-create-the-network_tools-code-root)  
    - [1.4.3 Verify the Setup from the Development User](#143-verify-the-setup-from-the-development-user)  
  - [1.5 SSH Key Setup and Hardening](#15-ssh-key-setup-and-hardening)  
    - [1.5.1 Generate an SSH Key Pair on the Developer Machine](#151-generate-an-ssh-key-pair-on-the-developer-machine)  
    - [1.5.2 Install the SSH Key for the Administrative User](#152-install-the-ssh-key-for-the-administrative-user)  
    - [1.5.3 Install the SSH Key for `developer_network_tools`](#153-install-the-ssh-key-for-developer_network_tools)  
    - [1.5.4 Harden the SSH Server Configuration](#154-harden-the-ssh-server-configuration)  
    - [1.5.5 Verify Access and Fallback Plan](#155-verify-access-and-fallback-plan)  
- [2. Rootless Docker Install](#2-rootless-docker-install)  
  - [2.1 Install Docker Engine Packages](#21-install-docker-engine-packages)  
  - [2.2 Install Rootless Prerequisites](#22-install-rootless-prerequisites)  
  - [2.3 Configure Subordinate UID/GID Ranges](#23-configure-subordinate-uidgid-ranges)  
  - [2.4 Disable Rootful Docker Daemon (Recommended)](#24-disable-rootful-docker-daemon-recommended)  
  - [2.5 Install and Start Rootless Docker](#25-install-and-start-rootless-docker)  
  - [2.6 Enable Rootless Docker at Boot](#26-enable-rootless-docker-at-boot)  
  - [2.7 Configure Shell Environment](#27-configure-shell-environment)  
  - [2.8 Validate Rootless Docker](#28-validate-rootless-docker)  
  - [2.9 Rootless Notes and Troubleshooting](#29-rootless-notes-and-troubleshooting)
- [3. Vault Bring-up](#3-vault-bring-up)  
  - [3.1 Generate TLS Certificates](#31-generate-tls-certificates)  
  - [3.2 Validate Certificates](#32-validate-certificates)  
  - [3.3 Start Vault with Docker Compose](#33-start-vault-with-docker-compose)  
  - [3.4 Confirm Vault is Reachable](#34-confirm-vault-is-reachable)  
  - [3.5 Vault Bring-up Troubleshooting](#35-vault-bring-up-troubleshooting)  
  - [3.6 Initialize and Unseal Vault (First Run)](#36-initialize-and-unseal-vault-first-run)  
    - [3.6.1 Run the Init + Unseal Script](#361-run-the-init--unseal-script)  
    - [3.6.2 Bootstrap Artifacts (Download Then Remove)](#362-bootstrap-artifacts-download-then-remove)  
  - [3.7 TLS Certificate Trust and Best Practices](#37-tls-certificate-trust-and-best-practices)  
    - [3.7.1 Local Development (Self-Signed CA)](#371-local-development-self-signed-ca)  
    - [3.7.2 Production Environments (Recommended)](#372-production-environments-recommended)  
    - [3.7.3 Practical Guidance for This Repo](#373-practical-guidance-for-this-repo)  
  - [3.8 Vault Unseal and KV Seeding Bootstrap Scripts](#38-vault-unseal-and-kv-seeding-bootstrap-scripts)  
    - [3.8.1 Overview (Which Script to Use)](#381-overview-which-script-to-use)  
    - [3.8.2 Unseal-Only Usage](#382-unseal-only-usage)  
    - [3.8.3 Single-Mount Seeder (vault_unseal_kv_seed_bootstrap_rootless.sh)](#383-single-mount-seeder-vault_unseal_kv_seed_bootstrap_rootlesssh)  
    - [3.8.4 Multi-Mount Seeder (vault_unseal_multi_kv_seed_bootstrap_rootless.sh)](#384-multi-mount-seeder-vault_unseal_multi_kv_seed_bootstrap_rootlesssh)  
    - [3.8.5 Seed Input Formats](#385-seed-input-formats)  
    - [3.8.6 Multi Spec JSON Schema](#386-multi-spec-json-schema)  
    - [3.8.7 Example Seed Files](#387-example-seed-files)  
    - [3.8.8 Output, Artifact Storage, and Security Notes](#388-output-artifact-storage-and-security-notes)  
    - [3.8.9 Troubleshooting](#389-troubleshooting)  
- [4. postgres](#4-postgres)  
  - [4.1 Bootstrap credentials (generate + seed)](#41-bootstrap-credentials-generate--seed)  
  - [4.2 Retrieve credentials from Vault](#42-retrieve-credentials-from-vault)  
  - [4.3 Use with Docker Compose](#43-use-with-docker-compose)  
    - [4.3.1 Compose prerequisites](#431-compose-prerequisites)  
    - [4.3.2 Initialize the Postgres certs volume](#432-initialize-the-postgres-certs-volume)  
    - [4.3.3 Start postgres_primary](#433-start-postgres_primary)  
    - [4.3.4 Verify and connect](#434-verify-and-connect)  
    - [4.3.5 Troubleshooting](#435-troubleshooting)  
  - [4.4 Startup credential options (choose one)](#44-startup-credential-options-choose-one)  
- [5. pgAdmin](#5-pgadmin)  
  - [5.1 Bootstrap credentials (generate + seed)](#51-bootstrap-credentials-generate--seed)  
  - [5.2 Retrieve credentials from Vault](#52-retrieve-credentials-from-vault)  
  - [5.3 Use with Docker Compose](#53-use-with-docker-compose)  
  - [5.4 Startup credential options (choose one)](#54-startup-credential-options-choose-one)  
- [6. Postgres and pgAdmin Vault Integration Bootstrapping](#6-postgres-and-pgadmin-vault-integration-bootstrapping)  
  - [6.1 Overview and constraints](#61-overview-and-constraints)  
  - [6.2 Option A – Keep env file (.env) as the runtime source of truth](#62-option-a--keep-env-file-env-as-the-runtime-source-of-truth)  
  - [6.3 Option B – Vault Agent sidecar renders file-based secrets at container start](#63-option-b--vault-agent-sidecar-renders-file-based-secrets-at-container-start)  
    - [6.3.1 Create a least-privilege Vault policy](#631-create-a-least-privilege-vault-policy)  
    - [6.3.2 Create an AppRole for the agent](#632-create-an-approle-for-the-agent)  
    - [6.3.3 Host-side export script (role_id + secret_id)](#633-host-side-export-script-role_id--secret_id)  
    - [6.3.4 Vault Agent config + templates](#634-vault-agent-config--templates)  
    - [6.3.5 Docker Compose wiring (vault-agent + shared secrets volume)](#635-docker-compose-wiring-vault-agent--shared-secrets-volume)  
    - [6.3.6 Bring-up and verification](#636-bring-up-and-verification)  
    - [6.3.7 Rotation and operational notes](#637-rotation-and-operational-notes)  
  - [6.4 Option C – Advanced: Vault Database secrets engine (dynamic credentials)](#64-option-c--advanced-vault-database-secrets-engine-dynamic-credentials)  
- [Appendix A – Certificate Management](#appendix-a--certificate-management)  
  - [A.1 Vault TLS Certificates – What to Keep and Where](#a1-vault-tls-certificates--what-to-keep-and-where)  
  - [A.2 Rootless Docker and Subordinate UID/GID Ranges (subuid/subgid)](#a2-rootless-docker-and-subordinate-uidgid-ranges-subuidsubgid)
---

## 0. Repository File Structure

Use this section to document the repository layout on the server. The easiest way to keep it current is to run
`tree` at the project root and paste the output into the fenced block below.

> Suggested command: `tree -a -L 8`

```text
developer_network_tools@networktoolsvm:~/NETWORK_TOOLS$ tree --charset ascii
.
|-- backend
|   |-- app
|   |   |-- mariadb_queries
|   |   |-- postgres
|   |   |   |-- certs
|   |   |   |   |-- ca.crt
|   |   |   |   |-- ca.key
|   |   |   |   |-- ca.srl
|   |   |   |   |-- cert.crt
|   |   |   |   `-- cert.key
|   |   |   |-- config
|   |   |   |   |-- pg_hba.conf
|   |   |   |   |-- postgres.conf
|   |   |   |   `-- postgresql.conf
|   |   |   `-- scripts
|   |   |       `-- export_approle_from_vault_container.sh
|   |   |-- routers
|   |   `-- security
|   |       `-- configuration_files
|   |           `-- vault
|   |               |-- bootstrap
|   |               |   |-- postgres_pgadmin_credentials.json
|   |               |   |-- postgres_pgadmin.env
|   |               |   |-- root_token
|   |               |   |-- root_token.json
|   |               |   |-- seeded_secrets_all.json
|   |               |   |-- seed_kv_spec.postgres_pgadmin.json
|   |               |   `-- unseal_keys.json
|   |               |-- certs
|   |               |   |-- ca.crt
|   |               |   |-- ca.key
|   |               |   |-- ca.srl
|   |               |   |-- cert.crt
|   |               |   `-- cert.key
|   |               |-- config
|   |               |   |-- certs
|   |               |   |-- postgres_pgadmin_agent.hcl
|   |               |   |-- postgres_pgadmin_kv_read.hcl
|   |               |   `-- vault_configuration_primary_node.hcl
|   |               `-- Dockerfile
|   |-- build_scripts
|   |   |-- generate_local_postgres_certs.sh
|   |   |-- generate_local_vault_certs.sh
|   |   |-- generate_postgres_pgadmin_bootstrap_creds_and_seed.sh
|   |   |-- guides
|   |   |   |-- seed_kv_spec.example.json
|   |   |   `-- seed_kv_spec.GUIDE.md
|   |   |-- vault_first_time_init_only_rootless.sh
|   |   |-- vault_unseal_kv_seed_bootstrap_rootless.sh
|   |   `-- vault_unseal_multi_kv_seed_bootstrap_rootless.sh
|   `-- nginx
|-- container_data
|   |-- postgres
|   |   `-- data
|   |       `-- pgdata  [error opening dir]
|   `-- vault
|       |-- approle
|       |   `-- postgres_pgadmin_agent
|       |       |-- role_id
|       |       `-- secret_id
|       `-- data
|           |-- logs
|           |-- raft
|           |   |-- raft.db
|           |   `-- snapshots
|           `-- vault.db
|-- docker-compose.prod.yml
|-- environment_variable_guide.md
|-- frontend
|-- how_to_videos
|   |-- HOW_TO_3.2 Validate Certificates.mov
|   |-- HOW_TO_3.3 Start Vault with Docker Compose.mov
|   |-- HOW_TO_3.6 Initialize and Unseal Vault (First Run).mov
|   |-- HOW_TO_3.8.3 Single-Mount Seeder (vault_unseal_kv_seed_bootstrap_rootless.sh).mov
|   `-- HOW_TO_3.8.4 Multi-Mount Seeder (vault_unseal_multi_kv_seed_bootstrap_rootless.sh).mov
`-- readme.md
```

---

## 1. System Preparation

### 1.1 Assumptions

- Ubuntu Server **22.04 LTS** or **24.04 LTS**, ARM build.
- The server is running in a VM (e.g., VMware Fusion, Proxmox, ESXi, etc.).
- You have SSH access as a user with `sudo` privileges (or as `root` initially).
- You intend to:
  - Use a **non-root user** for day-to-day work and development.
  - Restrict SSH to **key-based authentication**.
  - Run **rootless Docker** under a dedicated development account.
  - Host **MariaDB**, **postgres**, **Vault**, and **Keycloak** in containers later.

> **Note:** For commands prefixed with `sudo`, run them from your normal user.  
> If you are logged in as `root`, you can omit `sudo`.

---

### 1.2 Update the Operating System

Update package metadata and upgrade all installed packages:

```bash
sudo apt update
sudo apt install -y openssl
sudo apt full-upgrade -y
```

A reboot is recommended after major upgrades, especially if a new kernel or critical libraries are installed:

```bash
sudo reboot
```

Log back in and continue with the steps below.

---

### 1.3 Address Slow `sudo` Response (Optional)

On some installations, `sudo` can appear noticeably slow. 
A common cause is a hostname resolution problem (the system tries to reverse-lookup its own hostname and times out).

You can mitigate this by ensuring the server’s hostname resolves quickly via `/etc/hosts`.

1. Check the current hostname:

   ```bash
   hostname
   ```

   Example output:

   ```text
   networktoolsvm
   ```

2. Inspect `/etc/hosts`:

   ```bash
   sudo cat /etc/hosts
   ```

   Example of a problematic configuration:

   ```text
   127.0.0.1   localhost
   127.0.1.1   network_tools_vm   # DOES NOT match the actual hostname "networktoolsvm"
   # The following lines are desirable for IPv6 capable hosts
   ::1     ip6-localhost ip6-loopback
   fe00::0 ip6-localnet
   ff00::0 ip6-mcastprefix
   ff02::1 ip6-allnodes
   ff02::2 ip6-allrouters
   ```

3. Ensure your hostname appears on a `127.x.x.x` line. For example, if the hostname is `networktoolsvm`, you can adjust the file to:

   ```text
   127.0.0.1   localhost networktoolsvm
   127.0.1.1   network_tools_vm
   ```

4. Edit `/etc/hosts`:

   ```bash
   sudo nano /etc/hosts
   ```

   Apply the appropriate changes for your environment and save.

5. Retry a `sudo` command:

   ```bash
   sudo true
   ```

   If the hostname was the issue, `sudo` should feel more responsive after this change.

---

### 1.4 Create a Dedicated Development User and Code Root

To keep application development, containers, and 
code ownership cleanly separated from your admin account, 
create a dedicated non-root user. This user will later run **rootless Docker** and 
own all of the **NETWORK_TOOLS** source code.

#### 1.4.1 Create the `developer_network_tools` User

Log in as an existing sudo-capable user (e.g., the account created during installation) and run:

```bash
sudo adduser developer_network_tools
```

Follow the prompts to set:

- A password for the new user.
- Optional full name and contact details (press Enter to accept defaults if you prefer).

This account is intentionally created **without** `sudo` privileges to reduce risk. You will continue using your primary admin user for system-level configuration and package management.

> **Optional:** If you later decide that `developer_network_tools` needs `sudo` access, you can run:
>
> ```bash
> sudo usermod -aG sudo developer_network_tools
> ```

#### 1.4.2 Create the `NETWORK_TOOLS` Code Root

All application code and related repositories will live under a single directory owned by the development user:

```text
/home/developer_network_tools/NETWORK_TOOLS
```

Create this directory and ensure it is owned by `developer_network_tools`:

```bash
sudo mkdir -p /home/developer_network_tools/NETWORK_TOOLS
sudo chown -R developer_network_tools:developer_network_tools /home/developer_network_tools/NETWORK_TOOLS
```

This establishes a clear, isolated home for all network tools and services that will be developed and run under this account.

#### 1.4.3 Verify the Setup from the Development User

Switch to the `developer_network_tools` account and confirm the directory layout:

```bash
sudo -iu developer_network_tools
pwd        # Expect: /home/developer_network_tools
ls         # Expect: NETWORK_TOOLS
cd NETWORK_TOOLS
pwd        # Expect: /home/developer_network_tools/NETWORK_TOOLS
```

At this point:

- The `developer_network_tools` user exists and can log in.
- The `NETWORK_TOOLS` directory is ready to hold all application repositories and configuration.
- This user will later be used to run rootless Docker and associated development services.

---

### 1.5 SSH Key Setup and Hardening

This section covers:

- Generating an SSH key pair on a **developer machine**.
- Installing that key for both:
  - Your **administrative user** (the one with `sudo`).
  - The **`developer_network_tools`** user.
- Hardening the SSH server configuration to require key-based auth and disallow direct root logins.

> **Terminology:**
> - **Developer machine**: The workstation or laptop you will use to connect to the server (e.g., macOS or Linux desktop).
> - **Server**: The Ubuntu VM or host you are configuring.

#### 1.5.1 Generate an SSH Key Pair on the Developer Machine

On your **developer machine** (not on the server):

1. Open a terminal and generate an Ed25519 SSH key:

   ```bash
   ssh-keygen -t ed25519 -C "developer_network_tools@ubuntu-dev"
   ```

2. When prompted:
   - Accept the default file location (`~/.ssh/id_ed25519`) or choose a custom name.
   - Set a passphrase for the key (recommended).

This creates two files on the developer machine:

- `~/.ssh/id_ed25519` (private key – **keep this safe**).
- `~/.ssh/id_ed25519.pub` (public key – safe to copy to servers).

#### 1.5.2 Install the SSH Key for the Administrative User

First, configure key-based access for your existing administrative user (e.g., `your_name`). 
This ensures you always have a way to log in with `sudo` privileges.

On your **developer machine**:

```bash
ssh-copy-id -i ~/.ssh/id_ed25519.pub <USER>@<SERVER_HOSTNAME_OR_IP>
```

Replace `<USER>' and `<SERVER_HOSTNAME_OR_IP>` with your actual admin username and server address.

If `ssh-copy-id` is not available, you can manually copy the public key:

1. On the developer machine:

   ```bash
   cat ~/.ssh/id_ed25519.pub
   ```

2. On the server, as the admin user:

   ```bash
    mkdir -p ~/.ssh
    chmod 700 ~/.ssh                   # directory permissions
    nano ~/.ssh/authorized_keys
    chmod 600 ~/.ssh/authorized_keys   # file permissions
   ```

   Paste the public key line, save, then:

   ```bash
   chmod 600 ~/.ssh/authorized_keys
   ```

Test login from the developer machine:

```bash
ssh <USER>>@<SERVER_HOSTNAME_OR_IP>
```

You should be prompted for the **key passphrase** (if you set one), 
but not for the server account password.

#### 1.5.3 Install the SSH Key for `developer_network_tools`

Repeat the process for the `developer_network_tools` 
account so you can log in directly as the development user.

From the **developer machine**:

```bash
ssh-copy-id -i ~/.ssh/id_ed25519.pub developer_network_tools@<SERVER_HOSTNAME_OR_IP>
```

Again, if you need to do this manually:

1. On the developer machine:

   ```bash
   cat ~/.ssh/id_ed25519.pub
   ```

2. On the server, as an admin user:

   ```bash
   sudo -iu developer_network_tools
   mkdir -p ~/.ssh
   chmod 700 ~/.ssh
   nano ~/.ssh/authorized_keys
   ```

   Paste the public key line, save, then:

   ```bash
   chmod 600 ~/.ssh/authorized_keys
   ```

Test login from the developer machine:

```bash
ssh developer_network_tools@<SERVER_HOSTNAME_OR_IP>
```

You should now have key-based access to both:

- `<USER>@<SERVER_HOSTNAME_OR_IP>` (or your chosen admin user)
- `developer_network_tools@<SERVER_HOSTNAME_OR_IP>`

> **NOTE:**
> - If you are unable to ssh to the development server with the key automatically, you can try altering
your ssh configuration to use the key explicitely 
> 
```bash
Linux / Mac example

Add the following to your ssh config file
network_tools.local is local to my development machine and is pointed to my VM via the /etc/hosts file, you may have it setup as something else.

<USER>@<DEVICE NAME> % cat ~/.ssh/config
Host network_tools network_tools.local
    HostName network_tools.local
    User developer_network_tools
    IdentityFile ~/.ssh/id_ed25519
    IdentitiesOnly yes
```

#### 1.5.4 Harden the SSH Server Configuration

Once key-based access is confirmed for at least one administrative user, you can safely harden SSH.

On the **server**, edit or create a dedicated SSH configuration snippet:

```bash
sudo nano /etc/ssh/sshd_config.d/99-hardening.conf
```

Add the following:

```text
# Disable SSH password authentication; require keys
PasswordAuthentication no

# Disallow direct root login
PermitRootLogin no

# Ensure public key auth is enabled
PubkeyAuthentication yes

# Optional: reduce attack surface slightly
ChallengeResponseAuthentication no
UsePAM yes
```

Save the file, then reload the SSH daemon:

```bash
sudo systemctl reload ssh
```

> **Important:** Do **not** close your existing SSH session until you have verified that you can open a new session with the hardened settings.

#### 1.5.5 Verify Access and Fallback Plan

From your **developer machine**, verify:

1. You can still log in as the admin user:

   ```bash
   ssh <USER>@<SERVER_HOSTNAME_OR_IP>
   ```

2. You can still log in as the development user:

   ```bash
   ssh developer_network_tools@<SERVER_HOSTNAME_OR_IP>
   ```

3. Attempting to log in with only a password (no key) should now fail, confirming that password authentication is disabled.

If something goes wrong (e.g., you cannot log in with SSH keys):

- Use an existing open SSH session (if still available) to revert changes in `/etc/ssh/sshd_config.d/99-hardening.conf`, **or**
- Use the VM/console access provided by your hypervisor or cloud platform to log in directly and adjust the SSH configuration.

Once verified, SSH is now:

- Key-only (no password logins).
- Root logins disabled.
- Ready for you to continue with additional hardening and service deployment (Docker, databases, Vault, and Keycloak configuration in subsequent sections).

---




## 2. Rootless Docker Install

This section installs **Docker Engine** and configures it in **rootless mode** so containers run under the dedicated
`developer_network_tools` account (recommended for development and for running services without granting root-level Docker access).

### 2.1 Install Docker Engine Packages

> Run these commands as your **admin (sudo-capable) user**.

1. (Optional) Remove conflicting packages that may be present from older installs:

   ```bash
   sudo apt remove -y docker.io docker-doc docker-compose podman-docker containerd runc || true
   ```

2. Install prerequisites and add Docker’s official APT repository:

   ```bash
   sudo apt update
   sudo apt install -y ca-certificates curl

   sudo install -m 0755 -d /etc/apt/keyrings
   sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
   sudo chmod a+r /etc/apt/keyrings/docker.asc

   sudo tee /etc/apt/sources.list.d/docker.sources >/dev/null <<'EOF'
   Types: deb
   URIs: https://download.docker.com/linux/ubuntu
   Suites: $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")
   Components: stable
   Signed-By: /etc/apt/keyrings/docker.asc
   EOF

   sudo apt update
   ```

3. Install Docker Engine + CLI + container runtime + Buildx + Compose plugin:

   ```bash
   sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
   ```

### 2.2 Install Rootless Prerequisites

> Run these commands as your **admin (sudo-capable) user**.

Install the packages required for rootless Docker:

```bash
sudo apt install -y uidmap docker-ce-rootless-extras
```

Recommended (rootless networking + storage helpers):

```bash
sudo apt install -y slirp4netns fuse-overlayfs
```

### 2.3 Configure Subordinate UID/GID Ranges

Rootless Docker relies on subordinate UID/GID ranges. Your user should have at least **65,536** IDs allocated in both files.

> Run these commands as your **admin (sudo-capable) user**.

1. Check current allocations:

   ```bash
   sudo grep '^developer_network_tools:' /etc/subuid || true
   sudo grep '^developer_network_tools:' /etc/subgid || true
   ```

2. If you do not see a line for `developer_network_tools`, add one (choose a range that does not overlap existing entries):

   ```bash
   echo 'developer_network_tools:100000:65536' | sudo tee -a /etc/subuid
   echo 'developer_network_tools:100000:65536' | sudo tee -a /etc/subgid
   ```

3. Re-check:

   ```bash
   sudo grep '^developer_network_tools:' /etc/subuid
   sudo grep '^developer_network_tools:' /etc/subgid
   ```

### 2.4 Disable Rootful Docker Daemon (Recommended)

If you intend to use **rootless Docker only**, disable the system-wide daemon and socket to avoid confusion over which daemon your CLI is talking to.

> Run these commands as your **admin (sudo-capable) user**.

```bash
sudo systemctl disable --now docker.service docker.socket || true
sudo rm -f /var/run/docker.sock || true
```

### 2.5 Install and Start Rootless Docker

> Run these commands as the **developer user**.

1. Switch into the development account:

   ```bash
   sudo -iu developer_network_tools
   ```

2. Install the rootless Docker user-service:

   ```bash
   dockerd-rootless-setuptool.sh install
   ```

3. Start the daemon (user-level systemd service):

   ```bash
   systemctl --user start docker
   systemctl --user status docker --no-pager
   ```

4. Confirm the Docker CLI is using the rootless context:

   ```bash
   docker context ls
   docker context use rootless || true
   docker info | sed -n '1,80p'
   ```

### 2.6 Enable Rootless Docker at Boot

Rootless Docker runs as a **user service**, so to have it start on boot (without an interactive login), enable “linger” for the user.

> Run this command as your **admin (sudo-capable) user**.

```bash
sudo loginctl enable-linger developer_network_tools
```

You can confirm linger status with:

```bash
loginctl show-user developer_network_tools -p Linger
```

### 2.7 Configure Shell Environment

In most cases, the setup tool configures a Docker context so the CLI finds the rootless socket automatically.
If you prefer to pin it explicitly, add `DOCKER_HOST` to the developer user’s shell profile.

> Run these commands as **developer_network_tools**.

```bash
echo 'export DOCKER_HOST=unix:///run/user/$(id -u)/docker.sock' >> ~/.bashrc
source ~/.bashrc
```

### 2.8 Validate Rootless Docker

> Run these commands as **developer_network_tools**.

1. Verify versions:

   ```bash
   docker version
   docker compose version
   ```

2. Run a test container:

   ```bash
   docker run --rm hello-world
   ```

3. Confirm rootless is in effect:

   ```bash
   docker info | grep -i rootless || true
   ```

### 2.9 Rootless Notes and Troubleshooting

**1) Ports below 1024**
- Rootless containers cannot bind privileged ports (e.g., 80/443) by default.
- Use high ports during development (e.g., `8080:80`, `8443:443`).

**2) User namespace restrictions on Ubuntu 24.04+**
- If rootless setup fails with `permission denied` / `operation not permitted` around `unshare` or user namespaces, check:

  ```bash
  cat /proc/sys/user/max_user_namespaces
  cat /proc/sys/kernel/unprivileged_userns_clone 2>/dev/null || true
  sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null || true
  ```

  If your environment restricts unprivileged user namespaces (often via AppArmor policy), rootless Docker will not start until that policy is adjusted.
  Prefer a targeted policy change over disabling protections globally.

**3) Networking expectations**
- Rootless uses user-space networking. Services should be accessed via published ports (`-p` / `ports:` in Compose), not via container IPs.

**4) “Which Docker am I talking to?”**
- If you see `/var/run/docker.sock`, you are talking to **rootful** Docker.
- Rootless uses: `unix:///run/user/<UID>/docker.sock`.

To confirm which socket is active:

```bash
echo "${DOCKER_HOST-<unset>}"
docker context show
docker info | sed -n '1,35p'
```

---
## 3. Vault Bring-up

This section documents how to generate local TLS material and start the **Vault** container using
`docker-compose.prod.yml` under **rootless Docker**.

Current target URL (may change later in production):

- `https://vault_production_node:8200`

> Note: For this URL to work from the *host* (browser/curl), the hostname `vault_production_node` must resolve to the host
running Docker (see Section 3.4).

### 3.1 Generate TLS Certificates

> Run the generator as **developer_network_tools** (no sudo).  
> Ensure OpenSSL is installed first (admin user).

1. Install OpenSSL (admin / sudo-capable user):

   ```bash
   sudo apt update
   sudo apt install -y openssl
   ```

2. Run the certificate generator (developer user):

   ```bash
   cd ~/NETWORK_TOOLS
   chmod +x ./backend/build_scripts/generate_local_vault_certs.sh
   ./backend/build_scripts/generate_local_vault_certs.sh --force
   ```

3. Confirm expected outputs exist:

   ```bash
   ls -lh ./backend/app/security/configuration_files/vault/certs/
   ```

### 3.2 Validate Certificates

Run these checks on the server:

```bash
CERT_DIR="$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs"
CERT="$CERT_DIR/cert.crt"
KEY="$CERT_DIR/cert.key"
CA="$CERT_DIR/ca.crt"

# Key parses cleanly
openssl pkey -in "$KEY" -check -noout

# Cert metadata
openssl x509 -in "$CERT" -noout -subject -issuer -dates

# Cert matches key (hashes must match)
openssl x509 -noout -modulus -in "$CERT" | openssl sha256
openssl rsa  -noout -modulus -in "$KEY"  | openssl sha256

# SANs include vault_production_node
openssl x509 -in "$CERT" -noout -text | sed -n '/Subject Alternative Name/,+2p'

# Verify leaf chains to CA
LEAF_ONLY="$CERT_DIR/cert.leaf.only.crt"
if [[ -f "$LEAF_ONLY" ]]; then
  openssl verify -CAfile "$CA" "$LEAF_ONLY"
else
  # Best-effort fallback (may fail if CERT is a fullchain)
  openssl verify -CAfile "$CA" "$CERT" || true
fi
```

### 3.3 Start Vault with Docker Compose

> Run these commands as **developer_network_tools**.

1. Confirm your CLI is talking to the **rootless** Docker daemon:

   ```bash
   docker context ls
   docker context use rootless || true
   docker context show
   ```

2. Ensure the local Vault data directories exist (bind mounts):

   ```bash
   cd ~/NETWORK_TOOLS
   mkdir -p ./container_data/vault/data ./container_data/vault/data/logs
   ```

3. Validate the Compose file renders:

   ```bash
   docker compose -f docker-compose.prod.yml config > /tmp/network_tools.compose.rendered.yml
   ```

4. Start Vault:

   ```bash
   docker compose -f docker-compose.prod.yml up -d vault_production_node
   ```

5. Follow logs:

   ```bash
   docker compose -f docker-compose.prod.yml logs -f vault_production_node
   ```

### 3.4 Confirm Vault is Reachable

If you are testing from the **same server** running Docker, add a hosts entry so `vault_production_node` resolves locally:

```bash
echo "127.0.0.1 vault_production_node" | sudo tee -a /etc/hosts
```

Then validate TLS from the host:

```bash
CA="$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt"
openssl s_client -connect vault_production_node:8200 -servername vault_production_node -CAfile "$CA" </dev/null
```

And validate HTTP response (Vault may return 503 until initialized/unsealed):

```bash
curl --cacert "$CA" -v https://vault_production_node:8200/v1/sys/health
```

### 3.5 Vault Bring-up Troubleshooting

**1) TLS errors (x509 hostname mismatch)**
- Ensure `vault_production_node` appears under *Subject Alternative Name* (Section 3.2).
- Ensure you are connecting using the same hostname that is present in the SAN list.

**2) “Connection refused” or cannot reach port 8200**
- Confirm the service is running and ports are published:

  ```bash
  docker compose -f docker-compose.prod.yml ps
  ss -lntp | egrep ':8200|:8201' || true
  ```

**3) Permission denied writing under `/vault/data`**
- Confirm `./container_data/vault/data` exists and is writable by your rootless user.
- If still failing, consider adding `user: "0:0"` to the Compose service for Vault (still rootless on the host).

---


### 3.6 Initialize and Unseal Vault (First Run)

This step is required **one time** for a brand-new Vault instance. It will:

- Start the Vault container with Docker Compose (rootless; no sudo)
- Initialize Vault (generates unseal keys + root token)
- Unseal Vault

> **Security note:** The init artifacts (unseal keys + root token) are highly sensitive. This script will save them to disk and (by default) print some contents to the terminal. Treat the output like production secrets.

#### 3.6.1 Run the Init + Unseal Script

> Run these commands as **developer_network_tools** (no sudo).

1. Ensure Vault is running (the script can run compose for you, but it’s still useful to know the manual command):

   ```bash
   cd ~/NETWORK_TOOLS
   docker compose -p network_tools -f docker-compose.prod.yml up -d vault_production_node
   ```

2. Ensure the init/unseal script is executable:

   ```bash
   cd ~/NETWORK_TOOLS
   chmod +x ./backend/build_scripts/vault_first_time_init_only_rootless.sh
   ```

3. Run it with your local CA (recommended):

   ```bash
   bash ./backend/build_scripts/vault_first_time_init_only_rootless.sh \
     --vault-addr https://vault_production_node:8200 \
     --ca-cert "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt"
   ```

4. If you do **not** pass `--ca-cert`, the script will:
   - Try the system trust store first (no `-k`)
   - If that fails, it will retry with `-k` and print a warning with the TLS verification error

   ```bash
   bash ./backend/build_scripts/vault_first_time_init_only_rootless.sh \
     --vault-addr https://vault_production_node:8200
   ```

#### 3.6.2 Bootstrap Artifacts (Download Then Remove)

By default, the init/unseal script writes the bootstrap artifacts here:

```text
$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/
  - unseal_keys.json
  - root_token
  - root_token.json
  
  Example data below with a default setting of shares=5, threshold=3
  Meaning, it will create a password shard 5 long, but require only 3 to unseal the vault instance. 
  By default the init script will do the initial unseal process for you. But everytime the server
  is shutdown and restarted it will go back to being sealed.
  
    ----- /home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/unseal_keys.json -----
    {
      "keys": [
        "0fc7e06a4b4f428ec6703af5144752e95dc5e813b8ec5f4731f7f703ff885e14ad",
        "fcc27fcf8b26b15cefc6ddfdab2323efe90ce302c70899ee75889fcdc2c6664ac0",
        "4bf02b6140139e9c302765ca7ec53fbc5f332e8f31e87b48127aeee055a3e1141b",
        "e242d0d470a123c7d132a377be1a04d670fd1d2c806fe3f5f6339749782483e0c4",
        "64d0c9dee98e759b4fe9f91f263fca866c790b65087200cd522bac3d0548c85dbd"
      ],
      "keys_base64": [
        "D8fgaktPQo7GcDr1FEdS6V3F6BO47F9HMff3A/+IXhSt",
        "/MJ/z4smsVzvxt39qyMj7+kM4wLHCJnudYifzcLGZkrA",
        "S/ArYUATnpwwJ2XKfsU/vF8zLo8x6HtIEnru4FWj4RQb",
        "4kLQ1HChI8fRMqN3vhoE1nD9HSyAb+P19jOXSXgkg+DE",
        "ZNDJ3umOdZtP6fkfJj/Khmx5C2UIcgDNUiusPQVIyF29"
      ],
      "root_token": "hvs.qMX2xsnXzINWiTAByu3fy6SR"
    }
    
    ----- /home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token.json -----
    {
      "root_token": "hvs.qMX2xsnXzINWiTAByu3fy6SR" <--- REMOVE THIS FROM THE SERVER AND REVOKE FROM VAULT WHEN YOU ARE DONE WITH IT !!!
                                                        BEST PRACTICE IS TO SET EVERYTHING UP THE WAY YOU NEED IT 
                                                        AND REMOVE THE ROOT TOKEN COMPLETELY. A NEW ONE CAN BE REGENERATED LATER IF NEEDED
                                                        [HashiCorp Vault – Generate root token docs](https://developer.hashicorp.com/vault/docs/troubleshoot/generate-root-token)
                                                        
                                                        ONLY REVOKE WHEN EVERYTHING IS SETUP
                                                        vault token revoke <your-root-token-string>
    }
    
    {
      "vault_addr": "https://vault_production_node:8200",
      "compose": {
        "project": "network_tools",
        "file": "/home/developer_network_tools/NETWORK_TOOLS/docker-compose.prod.yml",
        "service": "vault_production_node"
      },
      "bootstrap_dir": "/home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap",
      "files": {
        "unseal_keys_json": "/home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/unseal_keys.json",
        "root_token": "/home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token",
        "root_token_json": "/home/developer_network_tools/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token.json"
      },
      "pretty_output": true,
      "print_artifact_contents": true,
      "initialized": true,
      "unsealed": true
    }


  
```

**Best practice (local/dev and production alike):**

- Download the artifacts to a secure location immediately (password manager / offline vault / secure storage).
- Do **not** commit these files to Git.
- After you have secured them, remove them from the server.

Example download (from your workstation):

```bash
scp -p <user>@<server>:"$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/unseal_keys.json" .
scp -p <user>@<server>:"$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token" .
scp -p <user>@<server>:"$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token.json" .
```

Example removal (run on the server after download):

```bash
rm -f \
  "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/unseal_keys.json" \
  "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token" \
  "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token.json"
```

If you do **not** want the script to print sensitive JSON contents to your terminal, use:

```bash
bash ./backend/build_scripts/vault_init_unseal_rootless_pretty_v6.sh \
  --vault-addr https://vault_production_node:8200 \
  --ca-cert "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt" \
  --no-print-artifact-contents
```

---

### 3.7 TLS Certificate Trust and Best Practices

This repository currently uses a **locally generated CA** and a **locally issued Vault server certificate** for development.
That is appropriate for local/dev, but the “right” trust model differs in production.

#### 3.7.1 Local Development (Self-Signed CA)

In local/dev, it is normal for `curl` or client libraries to fail verification unless you explicitly trust the CA.

- Strict verification (recommended even in dev):

  ```bash
  CA="$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt"
  curl --cacert "$CA" https://vault_production_node:8200/v1/sys/health
  ```

- Temporary bypass (avoid when possible; never use in production):

  ```bash
  curl -k https://vault_production_node:8200/v1/sys/health
  ```

**Developer machine trust:** In most cases, you do **not** need to install the dev CA into your workstation’s system trust store.
Instead, point tooling at the CA file (`--cacert` or `VAULT_CACERT`) as needed.

Example (host CLI use):

```bash
export VAULT_ADDR="https://vault_production_node:8200"
export VAULT_CACERT="$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt"
# vault status   # if the vault CLI is installed on the host
```

#### 3.7.2 Production Environments (Recommended)

For production, avoid shipping a “dev CA” and avoid `-k` entirely. Typical patterns:

- Use an enterprise PKI / internal CA trusted by servers and automation clients
- Or use publicly trusted certificates (e.g., ACME/Let’s Encrypt) when appropriate and permitted

**Key principles:**

- The Vault server certificate must include the correct DNS names in **Subject Alternative Name (SAN)** for the production URL(s).
- Clients should validate:
  - Certificate chain (issuer trust)
  - Hostname (SAN match)
  - Validity dates / rotation
- The **CA private key** should not be widely distributed (and should not live in the repo). In production, certificate issuance and private key handling should follow your organization’s security controls.

#### 3.7.3 Practical Guidance for This Repo

- Local/dev scripts support both:
  - Proper verification with `--ca-cert <path-to-ca.crt>`
  - A fallback path that can use `-k` when the local CA is not installed in the trust store (with a warning)
- When moving to production, expect to:
  - Replace the dev CA/cert material with your production certificate chain
  - Update your Vault listener config (`tls_cert_file`, `tls_key_file`) and Compose mounts accordingly
  - Remove any “insecure fallback” behavior from operational runbooks






---


### 3.8 Vault Unseal and KV Seeding Bootstrap Scripts

This repo intentionally keeps **two** seeding approaches so you have more than one option:

- **Single-mount seeder**: `./backend/build_scripts/vault_unseal_kv_seed_bootstrap_rootless.sh`  
  Best for the common case: unseal Vault (if needed), optionally create **one** KV mount, then seed **one JSON input** into that mount.
- **Multi-mount seeder**: `./backend/build_scripts/vault_unseal_multi_kv_seed_bootstrap_rootless.sh`  
  Best when you want to create/seed **multiple** KV mounts and paths in a single run (one “spec” file that defines the whole bootstrap).

Both scripts are designed for **rootless Docker** workflows and default to using artifact files produced by the first-time init/unseal script under:

- Bootstrap artifacts directory (default):  
  `$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap`

> Security note: these scripts can optionally print secrets to the terminal. Assume terminal output may be logged or captured. Prefer storing resolved secrets in the artifact file and moving them off-host immediately.

#### 3.8.1 Overview (Which Script to Use)

Use the **single-mount seeder** when you:
- only need one KV engine mount (example: `app_secrets`)
- want a simple JSON “template” checked into git (optionally using generators/env injection), and a resolved artifact JSON saved under the bootstrap dir

Use the **multi-mount seeder** when you:
- want to stand up multiple KV mounts (example: `app_secrets`, `frontend_environment_variables`, `fastapi_environment_variables`, etc.)
- want a single input file that declares *all* mounts + *all* secret writes in order

#### 3.8.2 Unseal-Only Usage

If you only need to **unseal** Vault and do not want to create mounts or seed secrets, run the single-mount script without any `--create-kv` / `--secrets-json` options:

```bash
cd ~/NETWORK_TOOLS

bash ./backend/build_scripts/vault_unseal_kv_seed_bootstrap_rootless.sh \
  --vault-addr "https://vault_production_node:8200" \
  --ca-cert "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt"
```

Notes:
- If Vault is already unsealed, the script should detect that and exit cleanly.
- If you previously downloaded and removed `unseal_keys.json` (recommended), pass it back in for that run via `--unseal-keys /path/to/unseal_keys.json`.

#### 3.8.3 Single-Mount Seeder (vault_unseal_kv_seed_bootstrap_rootless.sh)

**Primary goal**: unseal Vault (if sealed), optionally create a KV mount, then seed secrets from JSON, and write a “resolved secrets” artifact file next to the root token so you can download/store it securely.

Typical usage:

```bash
bash ./backend/build_scripts/vault_unseal_kv_seed_bootstrap_rootless.sh \
  --vault-addr "https://vault_production_node:8200" \
  --ca-cert "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt" \
  --unseal-keys "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/unseal_keys.json" \
  --unseal-required 3 \
  --create-kv "app_secrets" \
  --kv-version 2 \
  --kv-description "Network Tools app secrets (dev)" \
  --kv-max-versions 20 \
  --kv-cas-required true \
  --kv-delete-version-after 0s \
  --prompt-token \
  --secrets-json "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/seed_secrets.template.json" \
  --secrets-prefix "bootstrap" \
  --print-secrets
```

Key options (common):
- `--vault-addr`  
  Defaults to `https://vault_production_node:8200`
- `--ca-cert`  
  Strongly recommended for HTTPS in dev (your local CA). If omitted, the script will try system trust and may fall back to insecure `-k` behavior with a warning.
- `--unseal-keys`  
  Defaults to: `$BOOTSTRAP_DIR/unseal_keys.json`
- `--unseal-required <N>`  
  Optional, but recommended. If set, the script validates you have at least **N** keys and only attempts **N** unseal operations.
- `--prompt-token` / `--token` / `--token-file`  
  Provide a Vault token. If not provided, the script attempts the default bootstrap token files.
- `--create-kv <mount>`  
  Enables the KV engine at `<mount>/` (for example `app_secrets/`)
- `--secrets-json <file>`  
  Your template JSON file describing what to write.
- `--secrets-prefix <prefix>`  
  Optional prefix under the mount (example: `bootstrap/app/config` instead of `app/config`).

Output artifacts (defaults):
- Resolved secrets JSON artifact:  
  `$BOOTSTRAP_DIR/seeded_secrets_<mount>.json`

The script will also echo “recommended next steps” that include `scp` commands to download artifacts and a `rm -f` example to remove sensitive files from the server after verifying the download.

#### 3.8.4 Multi-Mount Seeder (vault_unseal_multi_kv_seed_bootstrap_rootless.sh)

**Primary goal**: perform the same unseal/token handling, but allow a single “spec” file that:
- creates multiple KV mounts (optional per mount)
- writes multiple secret objects across multiple paths/mounts
- stores a resolved “what was written” artifact under the same bootstrap directory

This is intended for “bootstrap the whole cluster in one run” operations.

Typical usage (example):

```bash
bash ./backend/build_scripts/vault_unseal_multi_kv_seed_bootstrap_rootless.sh \
  --vault-addr "https://vault_production_node:8200" \
  --ca-cert "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt" \
  --unseal-required 3 \
  --prompt-token \
  --spec-json "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/seed_kv_spec.json" \
  --print-secrets
```

#### 3.8.5 Seed Input Formats

The **single-mount seeder** supports two JSON formats for `--secrets-json`.

**A) Map format (recommended): “path -> data object”**

```json
{
  "app/config": {
    "db_username": "example_user",
    "db_password": { "generate": { "type": "url_safe", "bytes": 32 } }
  },
  "jwt": {
    "secret": { "generate": { "type": "hex", "bytes": 32 } }
  }
}
```

**B) List format: “explicit path + data (+ optional CAS per secret)”**

```json
[
  {
    "path": "app/config",
    "data": {
      "db_username": "example_user",
      "db_password": { "generate": { "type": "base64", "bytes": 32 } }
    },
    "cas": 0
  }
]
```

Supported generators:
- `hex` (requires `bytes`)
- `base64` (requires `bytes`)
- `url_safe` (requires `bytes`)
- `uuid`

Optional “ENV injection” values (useful when you *must* avoid putting secrets into a file):
- Required env var: `{ "env": "ENV_VAR_NAME" }`
- Optional env var: `{ "env": "ENV_VAR_NAME", "optional": true }`

#### 3.8.6 Multi Spec JSON Schema

The multi-mount seeder uses a single JSON file (a “spec”) that defines:
- mounts to ensure exist (optional per item)
- writes to perform (mount + path + data)

A typical pattern is:

```json

{
  "mounts": [
    {
      "mount": "frontend_app_secrets",
      "version": 2,
      "description": "Frontend Secrets!",
      "v2_config": {
        "max_versions": 20,
        "cas_required": true,
        "delete_version_after": "0s"
      },
      "prefix": "my_favorite_creds",
      "secrets": [
        {
          "path": "creds",
          "data": {
            "un": "something",
            "pw": "password"
          }
        },
        {
          "path": "creds_two",
          "data": {
            "un": "something",
            "pw": "password"
          }
        }
      ]
    }
  ]
}

```

Notes:
- Keep the spec **template-safe** (use `generate` directives and/or env injection) whenever possible.
- The “resolved” output (actual generated values) should be written as an artifact file under the bootstrap directory for secure download.

#### 3.8.7 Example Seed Files

**Single-mount template example** (map format):

```json
{
  "bootstrap/creds": {
    "un": "example_user",
    "pw": { "generate": { "type": "url_safe", "bytes": 24 } }
  },
  "bootstrap/crypto": {
    "jwt_secret": { "generate": { "type": "hex", "bytes": 32 } },
    "fernet_key": { "generate": { "type": "base64", "bytes": 32 } }
  }
}
```

**Multi spec example** (mount + multiple writes):

```json
{
  "mounts": [
    { "mount": "app_secrets", "type": "kv", "version": 2, "description": "Network Tools app secrets (dev)" }
  ],
  "writes": [
    { "mount": "app_secrets", "path": "bootstrap/creds", "data": { "un": "example_user", "pw": { "generate": { "type": "url_safe", "bytes": 24 } } } },
    { "mount": "app_secrets", "path": "bootstrap/jwt", "data": { "secret": { "generate": { "type": "hex", "bytes": 32 } } } }
  ]
}
```

#### 3.8.8 Output, Artifact Storage, and Security Notes

When you run init/unseal and seed operations, you should treat these as sensitive artifacts:

- `unseal_keys.json`
- `root_token` / `root_token.json`
- any `seeded_secrets_*.json` output artifacts

Recommended flow:
1. Run the script(s) on the server.
2. `scp -p` the required artifacts to a secure workstation or secrets storage location.
3. Verify the downloads.
4. Remove sensitive artifacts from the server (or move into an encrypted/controlled location).

Example (download from server):

```bash
scp -p <user>@<server>:"$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/unseal_keys.json" .
scp -p <user>@<server>:"$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token" .
scp -p <user>@<server>:"$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token.json" .
# Optional: resolved seed artifact(s)
scp -p <user>@<server>:"$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/seeded_secrets_app_secrets.json" .
```

#### 3.8.9 Troubleshooting


- **Secrets file is not valid JSON**  
  Ensure your `--secrets-json` file is strict JSON (double quotes, `:` between keys/values, no trailing commas). For example, this is **invalid**: `{'un':'x', 'pw','y'}`. This is valid:

  ```json
  { "un": "x", "pw": "y" }
  ```
- **Vault health response parsing errors (missing `.sealed`)**  
  Some endpoints differ (`/v1/sys/health` vs `/v1/sys/seal-status`). Use `--verbose` and ensure TLS is configured correctly. If you can `curl --cacert "$CA" https://.../v1/sys/health` successfully, then fix the script inputs accordingly.

- **TLS errors (`unknown CA`, `self-signed certificate in chain`)**  
  Provide `--ca-cert` pointing at your local CA file, or install the CA into the host trust store (preferred for dev). Avoid relying on `-k` except temporarily for diagnostics.


#### 3.8.10 Spec Format Notes, Validation Checks, and Common Pitfalls (Updated)

This repo supports **two** JSON formats for the multi-mount seeder:

- **Preferred (recommended):** a single JSON object with `mounts[]`, and each mount contains `secrets` (either an **object map** or an **array**).
- **Legacy (supported):** a single JSON object with `mounts[]` plus a top-level `writes[]` list. The script will merge `writes[]` into each mount’s `secrets`.

In addition, the script accepts a convenience wrapper where the **root** is a single-element array, e.g. `[ { ... } ]`. Internally, the script unwraps it.

Validation commands (run on the server):

```bash
# Must be valid JSON (object or [object])
jq -e '.' seed_kv_spec.json >/dev/null && echo "OK: valid JSON"

# Prefer a single object root (recommended)
jq -e 'type=="object"' seed_kv_spec.json >/dev/null && echo "OK: object root"

# Accept [ { ... } ] wrapper as well
jq -e '(type=="object") or (type=="array" and length==1 and (.[0]|type=="object"))' seed_kv_spec.json >/dev/null \
  && echo "OK: object or [object]"

# Must include a non-empty mounts array
jq -e 'type=="object" and (.mounts|type=="array") and (.mounts|length>0)' seed_kv_spec.json >/dev/null \
  && echo "OK: mounts[] present"
```

Common pitfalls that lead to confusing errors:

- **Accidentally creating an array root** (e.g., starting the file with `[` … `]`) when your script version expects an object root.
- **Mount name mismatch:** `writes[].mount` must match one of `mounts[].mount` (typos are easy to miss).
- **Including the prefix twice:** if your mount uses `"prefix": "bootstrap"`, then write paths should be **relative** (e.g., `"creds"`, not `"bootstrap/creds"`).

---

#### 3.8.11 Updated Multi-Mount Spec Example (Preferred)

This format keeps *everything* for a mount in one place (mount config + the secrets to write).

Notes:
- `prefix` is optional. If set, it is prepended to each secret path.
- `secrets` can be either:
  - an **object map** of `{ "<path>": { ...data... } }`, or
  - an **array** of `{ "path": "...", "data": {...} }`

Example (`seed_kv_spec.json`):

```json
{
  "mounts": [
    {
      "mount": "app_secrets",
      "type": "kv",
      "version": 2,
      "description": "Network Tools application secrets (dev)",
      "prefix": "bootstrap",
      "v2_config": {
        "max_versions": 20,
        "cas_required": true,
        "delete_version_after": "0s"
      },
      "secrets": {
        "creds": {
          "db_username": "example_user",
          "db_password": {
            "generate": { "type": "url_safe", "bytes": 32 }
          }
        },
        "jwt": {
          "secret": {
            "generate": { "type": "hex", "bytes": 32 }
          },
          "issuer": "network_tools_dev"
        }
      }
    },
    {
      "mount": "frontend_app_secrets",
      "type": "kv",
      "version": 2,
      "description": "Network Tools frontend secrets (dev)",
      "prefix": "bootstrap",
      "v2_config": {
        "max_versions": 10,
        "cas_required": false,
        "delete_version_after": "0s"
      },
      "secrets": [
        {
          "path": "oidc",
          "data": {
            "client_id": "example_client_id",
            "client_secret": {
              "generate": { "type": "url_safe", "bytes": 48 }
            }
          }
        }
      ]
    }
  ]
}
```

---

#### 3.8.12 Legacy Spec Example (mounts + writes)

This format is supported for compatibility and can be useful if you prefer a single flat list of writes.

Best practice: if you define a `prefix` in the mount object, then keep each `writes[].path` **relative** (do not include the prefix).

```json
{
  "mounts": [
    {
      "mount": "app_secrets",
      "type": "kv",
      "version": 2,
      "description": "Network Tools application secrets (dev)",
      "prefix": "bootstrap",
      "v2_config": {
        "max_versions": 20,
        "cas_required": true,
        "delete_version_after": "0s"
      }
    }
  ],
  "writes": [
    {
      "mount": "app_secrets",
      "path": "creds",
      "data": {
        "db_username": "example_user",
        "db_password": { "generate": { "type": "url_safe", "bytes": 32 } }
      }
    },
    {
      "mount": "app_secrets",
      "path": "jwt",
      "data": {
        "secret": { "generate": { "type": "hex", "bytes": 32 } }
      }
    }
  ]
}
```

---

#### 3.8.13 About `"generate": { ... }` Values

The `"generate": { ... }` blocks are **not** a native Vault feature. They are a **bootstrap-script convention**:

- The script generates the value at seed time (once), then writes the generated literal value into the KV path.
- Vault will **not** regenerate the value on read.
- To rotate, you re-run the seeding process (or build a dedicated rotation workflow) and write a new value.

If you want dynamic per-request credentials/keys, use a Vault secrets engine designed for that (e.g., Database secrets engine, Transit, etc.), not KV.

---

## 4. postgres

This section documents how we generate and store **initial postgres bootstrap credentials** for the Network Tools stack. The intent is that the rest of the containerized services (postgres itself, application backends, migrations, etc.) can pull their required values from **Vault KV** rather than hard-coding credentials into the repository or long-lived `.env` files.

### 4.1 Bootstrap credentials (generate + seed)

**Run as the same non-root user that runs rootless Docker** (e.g., `developer_network_tools`) from the repo root:

```bash
cd "$HOME/NETWORK_TOOLS"

bash ./backend/build_scripts/generate_postgres_pgadmin_bootstrap_creds_and_seed.sh \
  --vault-addr "https://vault_production_node:8200" \
  --ca-cert "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt" \
  --unseal-required 3 \
  --prompt-token
```

What the script does:

- Generates:
  - `POSTGRES_DB` (default: `network_tools`)
  - `POSTGRES_USER` (default: `network_tools_user`)
  - `POSTGRES_PASSWORD` (generated if not supplied)
- Creates local **bootstrap artifacts** under:

  ```text
  $HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/
  ```

  Files created:
  - `postgres_pgadmin.env` (shell env format)
  - `postgres_pgadmin_credentials.json` (human-readable credentials JSON)
  - `seed_kv_spec.postgres_pgadmin.json` (the spec used to seed Vault)

- Seeds Vault KV mount **`app_postgres_secrets`** (default) with two secret paths:
  - `postgres` (postgres values)
  - `pgadmin` (pgAdmin values)

Notes:

- By default, the script writes to `postgres` and `pgadmin` **without** a prefix (this matches the desired layout: `postgres`, not `bootstrap/postgres`).
- If you explicitly want a prefix later, use `--vault-prefix "<prefix>"`.

Security and operational guidance:

- These files contain plaintext credentials.
- Immediately download them to a secure location and remove them from the server once you have verified the secrets are stored in Vault.
- In production, prefer:
  - short-lived bootstrap tokens,
  - scoped policies,
  - rotation workflows,
  - and (where practical) Vault dynamic secrets engines instead of long-lived static passwords.

### 4.2 Retrieve credentials from Vault

The seeding script writes using the Vault HTTP API. If your mount is **KV v2** (the default in the generated spec), read secrets like this:

```bash
VAULT_ADDR="https://vault_production_node:8200"
CA_CERT="$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt"
TOKEN="$(cat "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token")"

# postgres secret (KV v2)
curl -sS --cacert "$CA_CERT" \
  -H "X-Vault-Token: $TOKEN" \
  "$VAULT_ADDR/v1/app_postgres_secrets/data/postgres" | jq .
```

To extract a single value (example: password):

```bash
curl -sS --cacert "$CA_CERT" \
  -H "X-Vault-Token: $TOKEN" \
  "$VAULT_ADDR/v1/app_postgres_secrets/data/postgres" | jq -r '.data.data.POSTGRES_PASSWORD'
```

If you later choose to use **KV v1**, the read path will not include `/data/`:

```bash
curl -sS --cacert "$CA_CERT" \
  -H "X-Vault-Token: $TOKEN" \
  "$VAULT_ADDR/v1/app_postgres_secrets/postgres" | jq .
```

### 4.3 Use with Docker Compose

You have two common patterns:

**Option A (simple dev bootstrap): use the generated env file**

This is convenient, but treat it as sensitive:

```bash
set -a
# shellcheck disable=SC1090
source "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/postgres_pgadmin.env"
set +a
```

You can then reference the exported variables when starting your postgres container(s). (Compose examples will be added when the postgres compose/service definition is finalized.)

**Option B (preferred): pull from Vault at runtime**

For production-like workflows, prefer fetching secrets from Vault during deployment/startup (or using an agent/injector pattern), rather than persisting them as `.env` files on disk.


#### 4.3.1 Compose prerequisites

Run these checks from the repository root (`~/NETWORK_TOOLS`) as the same non-root user that runs **rootless Docker** (e.g., `developer_network_tools`):

1) Confirm the source certificate files exist on the host:

```bash
ls -lh ./backend/app/postgres/certs/
```

Expected (minimum) inputs:

- `ca.crt`
- `cert.crt`
- `cert.key`

2) Confirm the Postgres config files exist and are **not empty**:

```bash
ls -lh ./backend/app/postgres/config/postgres.conf ./backend/app/postgres/config/pg_hba.conf
wc -l  ./backend/app/postgres/config/postgres.conf ./backend/app/postgres/config/pg_hba.conf
```

3) Validate the Compose file renders cleanly (this catches YAML formatting/indentation issues early):

```bash
docker compose -f docker-compose.prod.yml config > /tmp/network_tools.compose.rendered.yml
```

#### 4.3.2 Initialize the Postgres certs volume

In this stack, Postgres TLS material is delivered via a **named volume** populated by a short-lived init container (`postgres_certs_init`). The primary Postgres service mounts that volume read-only at `/etc/postgres/certs`.

Bring-up pattern:

1) (Optional but recommended during troubleshooting) reset the cert volume and the init container:

```bash
docker compose -f docker-compose.prod.yml rm -sf postgres_primary postgres_certs_init

# The actual on-disk volume name is prefixed by the compose project name (e.g., network_tools_postgres_certs)
docker volume rm network_tools_postgres_certs 2>/dev/null || true
```

2) Start the init container and confirm it successfully populated the volume:

```bash
docker compose -f docker-compose.prod.yml up -d postgres_certs_init
docker logs postgres_certs_init
```

You should see a file listing of `/dest` at the end of the logs with:

- `ca.crt`
- `server.crt`
- `server.key`

3) (Optional) validate the volume contents directly:

```bash
docker run --rm -v network_tools_postgres_certs:/dest alpine ls -l /dest
```

Note: In rootless Docker, owners may appear as numeric IDs (e.g., `999`). That is expected.

#### 4.3.3 Start postgres_primary

Start the primary Postgres service after the init container has completed successfully:

```bash
docker compose -f docker-compose.prod.yml up -d postgres_primary
docker logs --tail 200 -f postgres_primary
```

A successful start ends with:

- `database system is ready to accept connections`

#### 4.3.4 Verify and connect

1) Confirm the container is up:

```bash
docker compose -f docker-compose.prod.yml ps
docker ps --format "table {{.Names}}	{{.Status}}	{{.Ports}}"
```

2) Confirm the expected files exist inside the container:

```bash
docker exec -it postgres_primary sh -lc 'ls -lah /etc/postgres/certs && ls -lah /etc/postgres/postgres.conf /etc/postgres/pg_hba.conf'
```

3) Verify effective runtime settings (inside Postgres):

```bash
docker exec -it postgres_primary sh -lc 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "SHOW ssl; SHOW ssl_cert_file; SHOW ssl_key_file; SHOW ssl_ca_file; SHOW config_file; SHOW hba_file;"'
```

If you expect host connectivity, ensure your `postgres.conf` includes an appropriate `listen_addresses` value (e.g., `'*'`) and that the Compose service publishes `5432:5432`.

#### 4.3.5 Troubleshooting

**1) Mount error: “read-only file system” when creating `/etc/postgres/certs/*.crt` mountpoints**

Symptom (example):

- `create mountpoint "/etc/postgres/certs/ca.crt": read-only file system`

Common cause:

- The Compose service attempts to mount **individual cert files** into a path that is already covered by a **read-only directory mount** (for example, a named volume mounted at `/etc/postgres/certs:ro`).

Fix (recommended):

- Choose one approach. For this project, keep the **named volume** (`postgres_certs:/etc/postgres/certs:ro`) and remove file-level mounts to `/etc/postgres/certs/*`. Let `postgres_certs_init` populate the volume.

**2) FATAL: could not load server certificate file (missing file)**

Symptoms (examples):

- `could not load server certificate file "/etc/postgres/certs/server.crt": No such file or directory`
- `could not load server certificate file "/etc/postgres/certs/cert.crt": No such file or directory`

Checklist:

- Confirm `postgres_certs_init` completed successfully and the volume contains `server.crt` and `server.key` (Section **4.3.2**).
- Confirm Postgres is configured to reference the filenames that actually exist.

Recommendation:

- Standardize on `server.crt` / `server.key` inside the container (as produced by `postgres_certs_init`), and set:

  - `ssl_cert_file=/etc/postgres/certs/server.crt`
  - `ssl_key_file=/etc/postgres/certs/server.key`
  - `ssl_ca_file=/etc/postgres/certs/ca.crt`

If your `postgres.conf` currently references `cert.crt`, update it (or alternately, add a copy step in `postgres_certs_init` so both names exist).

**3) pg_hba.conf errors (empty or unreadable)**

Symptoms:

- `configuration file "/etc/postgres/pg_hba.conf" contains no entries`
- `FATAL: could not load /etc/postgres/pg_hba.conf`

Checklist:

```bash
# Host file must exist and be non-empty
wc -l ./backend/app/postgres/config/pg_hba.conf

# Container must see the same file (and it must be readable)
docker exec -it postgres_primary sh -lc 'ls -l /etc/postgres/pg_hba.conf && wc -l /etc/postgres/pg_hba.conf'
```

Minimal example (tighten for your environment; do not use `trust` broadly in production):

```conf
# TYPE  DATABASE        USER            ADDRESS                 METHOD
local   all             all                                     peer
host    all             all             127.0.0.1/32            scram-sha-256
host    all             all             ::1/128                 scram-sha-256

# Example: allow app subnet over TLS (adjust CIDR)
hostssl all             all             10.0.0.0/8              scram-sha-256
```

**4) “PostgreSQL Database directory appears to contain a database; Skipping initialization”**

This is informational. It means your bound data directory already has an initialized cluster. If you intend a clean rebuild, stop Postgres and remove the data directory contents (or move them aside), then restart.

**5) postgres_certs_init logs show only environment variables / no `/dest` listing**

This typically indicates the init container did not execute the intended copy commands.

- Re-check the rendered Compose output:

  ```bash
  docker compose -f docker-compose.prod.yml config | sed -n '/postgres_certs_init:/,/postgres_primary:/p'
  ```

- Confirm `entrypoint` and `command` match the expected script, then recreate the init container:

  ```bash
  docker compose -f docker-compose.prod.yml rm -sf postgres_certs_init
  docker compose -f docker-compose.prod.yml up -d --force-recreate --no-deps postgres_certs_init
  docker logs postgres_certs_init
  ```


### 4.4 Startup credential options (choose one)

Postgres does **not** natively “connect to Vault” on startup. In Docker, you typically implement that behavior using one of the following patterns:

1) **Baseline (current Compose approach): `.env` / `env_file`**
   - The host (or a build script) populates `POSTGRES_DB`, `POSTGRES_USER`, and `POSTGRES_PASSWORD` in `.env`.
   - `docker-compose.prod.yml` consumes those values (see **4.3**).

2) **Vault Agent sidecar (recommended when you want Vault dependency at container start)**
   - A Vault Agent container authenticates to Vault and renders secrets into files in a shared volume.
   - The official Postgres image supports file-based inputs via `POSTGRES_DB_FILE`, `POSTGRES_USER_FILE`, and `POSTGRES_PASSWORD_FILE`.
   - See **Section 6** for the full wiring and bootstrapping procedure.

3) **Host “pre-flight” fetch from Vault (simple, but less ideal)**
   - A host script reads secrets from Vault and writes them into `.env` immediately before `docker compose up`.
   - This is easy to operate, but it places secrets back into `.env` (which you should treat as sensitive).

Operational note:
- These variables are only used by the Postgres image when initializing an **empty** data directory. If your Postgres volume already contains a database cluster, changing the values will not automatically rotate users/passwords.

## 5. pgAdmin

This section documents the bootstrap credential(s) used by **pgAdmin** and how they are stored alongside the postgres credentials.

### 5.1 Bootstrap credentials (generate + seed)

The postgres/pgAdmin bootstrap script generates *both* Postgres and pgAdmin credentials in one run:

```bash
cd "$HOME/NETWORK_TOOLS"

bash ./backend/build_scripts/generate_postgres_pgadmin_bootstrap_creds_and_seed.sh \
  --vault-addr "https://vault_production_node:8200" \
  --ca-cert "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt" \
  --unseal-required 3 \
  --prompt-token
```

The pgAdmin secret is stored under:

- KV mount: `app_postgres_secrets`
- Secret path: `pgadmin`
- Key: `PGADMIN_DEFAULT_PASSWORD`

### 5.2 Retrieve credentials from Vault

For KV v2 (default):

```bash
VAULT_ADDR="https://vault_production_node:8200"
CA_CERT="$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/certs/ca.crt"
TOKEN="$(cat "$HOME/NETWORK_TOOLS/backend/app/security/configuration_files/vault/bootstrap/root_token")"

curl -sS --cacert "$CA_CERT" \
  -H "X-Vault-Token: $TOKEN" \
  "$VAULT_ADDR/v1/app_postgres_secrets/data/pgadmin" | jq .
```

Example extracting the password only:

```bash
curl -sS --cacert "$CA_CERT" \
  -H "X-Vault-Token: $TOKEN" \
  "$VAULT_ADDR/v1/app_postgres_secrets/data/pgadmin" | jq -r '.data.data.PGADMIN_DEFAULT_PASSWORD'
```

### 5.3 Use with Docker Compose

When you define the pgAdmin service, you will typically provide:

- `PGADMIN_DEFAULT_EMAIL` (you choose this value; it is not generated by the script)
- `PGADMIN_DEFAULT_PASSWORD` (seeded in Vault, or sourced from the generated env file)

For dev-only usage, you may source the generated env file (see section **4.3**) and reference the environment variables in your compose file.




### 5.4 Startup credential options (choose one)

pgAdmin also does not “pull from Vault” by itself. The common approaches are the same as Postgres:

1) **Baseline (current Compose approach): `.env` / `env_file`**
   - `PGADMIN_DEFAULT_EMAIL` and `PGADMIN_DEFAULT_PASSWORD` are provided via `.env`.

2) **Vault Agent sidecar (recommended when you want Vault dependency at container start)**
   - A Vault Agent container renders the admin password into a file in a shared volume.
   - pgAdmin supports `PGADMIN_DEFAULT_PASSWORD_FILE`, allowing you to source the password from a file (Docker secret / rendered file).
   - See **Section 6** for the full wiring and bootstrapping procedure.

3) **Host “pre-flight” fetch from Vault (simple, but less ideal)**
   - A host script reads the pgAdmin password from Vault and writes it into `.env` immediately before `docker compose up`.

Operational note:
- pgAdmin persists its own internal configuration database. On first startup it initializes the admin account based on the provided variables. If you rotate the password later, treat it like an application credential rotation (update Vault, update the container inputs, and restart).

## 6. Postgres and pgAdmin Vault Integration Bootstrapping

This section consolidates the “integration” story end-to-end: how Postgres and pgAdmin can start with credentials stored in Vault, while still supporting a fallback to locally stored bootstrap artifacts.

### 6.1 Overview and constraints

Key points to internalize up front:

- **Postgres and pgAdmin do not natively query Vault.** Something else must authenticate to Vault and deliver the values to the containers (host scripting, init containers, or a Vault Agent sidecar).
- **Prefer file-based secrets over environment variables** where possible:
  - The official Postgres image supports `_FILE` variants for `POSTGRES_DB`, `POSTGRES_USER`, and `POSTGRES_PASSWORD` (and a few others), meaning you can supply those values from files (e.g., Docker secrets or a rendered file).
  - pgAdmin supports `PGADMIN_DEFAULT_PASSWORD_FILE`, meaning the admin password can be supplied from a file.
- **Initialization behavior matters:** these variables affect initialization **only** when the Postgres data directory is empty. If your Postgres data volume already contains a database cluster, changing `POSTGRES_*` values will not automatically rotate users/passwords. Rotation requires explicit SQL (`ALTER USER ...`) and controlled restarts.

Vault KV paths and mounts used in this repo:
- The bootstrap seeding flow in **4.1** writes `postgres` and `pgadmin` under the configured mount (commonly `app_postgres_secrets`).
- If you used a different mount name (for example, a spelling variation), use that consistently in policies, templates, and read paths.

### 6.2 Option A – Keep env file (.env) as the runtime source of truth

This is the simplest operationally because it requires **no changes** to the current `docker-compose.prod.yml` Postgres/pgAdmin services.

#### When to use this option
- You want the stack to start even if Vault is down.
- You accept that secrets will exist (briefly or persistently) in `.env` on the host.
- You primarily use Vault as your “system of record” (seed/backup), not as a hard runtime dependency.

#### Steps

1) **Generate and seed** using the existing repo script (see **4.1** and **5.1**).
2) **Choose the fallback file location** (these are created by the script):
   - `./backend/app/security/configuration_files/vault/bootstrap/postgres_pgadmin.env`
   - `./backend/app/security/configuration_files/vault/bootstrap/postgres_pgadmin_credentials.json`
3) **Populate `.env` for Compose**.

Example: merge only the postgres/pgAdmin values into your existing `.env`:

```bash
cd "$HOME/NETWORK_TOOLS"

BOOT_ENV="./backend/app/security/configuration_files/vault/bootstrap/postgres_pgadmin.env"
test -f "$BOOT_ENV" || { echo "Missing: $BOOT_ENV"; exit 1; }

# Create a backup copy the first time
cp -n .env ".env.bak.$(date +%Y%m%d_%H%M%S)" || true

# Remove any prior definitions, then append the new ones (keeps .env clean)
grep -vE '^(POSTGRES_DB|POSTGRES_USER|POSTGRES_PASSWORD|PGADMIN_DEFAULT_PASSWORD)=' .env > .env.tmp || true
cat "$BOOT_ENV" >> .env.tmp
mv .env.tmp .env
chmod 600 .env
```

4) Bring up the services normally:

```bash
docker compose -f docker-compose.prod.yml up -d postgres_certs_init postgres_primary pgadmin
```

Security note:
- If you use this option, treat `.env` as a **secret-bearing file**: permissions `600`, do not commit it, and limit access to the docker host.

### 6.3 Option B – Vault Agent sidecar renders file-based secrets at container start

This pattern is the closest to “Postgres boots and obtains credentials from Vault,” while still remaining idiomatic for containers:
- A **Vault Agent** container authenticates to Vault using **AppRole**.
- The agent renders secrets into **files** inside a shared volume.
- Postgres and pgAdmin read those values using their supported `*_FILE` environment variables.

#### High-level flow

1) Vault is running, initialized, unsealed, and seeded with the `postgres` and `pgadmin` KV entries.
2) You create a Vault policy that can only read those two secrets.
3) You create an AppRole bound to that policy.
4) A Vault Agent container uses the AppRole to obtain a short-lived token.
5) The Vault Agent templates render:
   - `postgres_db`, `postgres_user`, `postgres_password`
   - `pgadmin_password`
6) Postgres uses:
   - `POSTGRES_DB_FILE=/run/vault/postgres_db`
   - `POSTGRES_USER_FILE=/run/vault/postgres_user`
   - `POSTGRES_PASSWORD_FILE=/run/vault/postgres_password`
7) pgAdmin uses:
   - `PGADMIN_DEFAULT_PASSWORD_FILE=/run/vault/pgadmin_password`

### 6.3.1 Create a least-privilege Vault policy

Create a policy that can only read the two KV secrets.

If your mount is KV v2 (the repo default), the paths include `/data/`:

```hcl
# postgres + pgAdmin runtime reads (KV v2)
path "app_postgres_secrets/data/postgres" {
  capabilities = ["read"]
}

path "app_postgres_secrets/data/pgadmin" {
  capabilities = ["read"]
}
```

If your mount is KV v1, remove `/data/`:

```hcl
# postgres + pgAdmin runtime reads (KV v1)
path "app_postgres_secrets/postgres" {
  capabilities = ["read"]
}

path "app_postgres_secrets/pgadmin" {
  capabilities = ["read"]
}
```

Apply the policy (run from the host using `docker exec` into the Vault container; this assumes you have a Vault admin/root token available for setup tasks):

```bash
cd "$HOME/NETWORK_TOOLS"

VAULT_CONTAINER="vault_production_node"
VAULT_ADDR_INTERNAL="https://vault_production_node:8200"
VAULT_TOKEN="$(cat ./backend/app/security/configuration_files/vault/bootstrap/root_token)"

docker exec -i       -e VAULT_ADDR="$VAULT_ADDR_INTERNAL"       -e VAULT_TOKEN="$VAULT_TOKEN"       -e VAULT_CACERT="/vault/certs/cert.crt"       "$VAULT_CONTAINER"       sh -lc 'cat > /tmp/postgres_pgadmin_read.hcl && vault policy write postgres_pgadmin_read /tmp/postgres_pgadmin_read.hcl' <<'HCL'
path "app_postgres_secrets/data/postgres" {
  capabilities = ["read"]
}
path "app_postgres_secrets/data/pgadmin" {
  capabilities = ["read"]
}
HCL
```

### 6.3.2 Create an AppRole for the agent

Enable AppRole auth (one-time):

```bash
docker exec -it       -e VAULT_ADDR="https://vault_production_node:8200"       -e VAULT_TOKEN="$(cat ./backend/app/security/configuration_files/vault/bootstrap/root_token)"       -e VAULT_CACERT="/vault/certs/cert.crt"       vault_production_node       sh -lc 'vault auth enable approle || true'
```

Create the role (tune TTLs and constraints as you prefer):

```bash
docker exec -it       -e VAULT_ADDR="https://vault_production_node:8200"       -e VAULT_TOKEN="$(cat ./backend/app/security/configuration_files/vault/bootstrap/root_token)"       -e VAULT_CACERT="/vault/certs/cert.crt"       vault_production_node       sh -lc '
    vault write auth/approle/role/postgres-pgadmin           token_policies="postgres_pgadmin_read"           token_ttl="1h"           token_max_ttl="4h"           secret_id_ttl="24h"           secret_id_num_uses="1"
  '
```

### 6.3.3 Host-side export script (role_id + secret_id)

Your requirement: “from the host OS, log into the Vault container, read the role id and secret id, then populate it in the files.”

Recommended on-host destination (rootless-friendly, not committed to git):

```text
./container_data/vault/approle/postgres-pgadmin/
  role_id
  secret_id
```

#### 6.3.3.1 Recommended: use the repo script (docker exec into Vault container)

This repo includes a host-side helper script that performs the required `docker exec` calls against the **known Vault container name** and writes `role_id` / `secret_id` into the expected on-host directory.

Script location (repo):

- `./backend/app/postgres/scripts/export_approle_from_vault_container.sh`

What it does:

- Reads the AppRole `role_id`
- Generates (optionally rotates) a `secret_id`
- Writes both to: `./container_data/vault/approle/<ROLE_NAME>/{role_id,secret_id}` with restrictive permissions

Run it from the project root:

```bash
cd "$HOME/NETWORK_TOOLS"

# Ensure Vault is running
docker compose -f docker-compose.prod.yml up -d vault_production_node

# Ensure the root token exists (this is produced by your init/unseal workflow)
ls -lah ./backend/app/security/configuration_files/vault/bootstrap/root_token*

# Run the export (defaults: VAULT_CONTAINER=vault_production_node, ROLE_NAME=postgres_pgadmin_agent)
chmod +x ./backend/app/postgres/scripts/export_approle_from_vault_container.sh
./backend/app/postgres/scripts/export_approle_from_vault_container.sh

# If your role name differs (example: you created 'postgres-pgadmin' earlier), override ROLE_NAME:
ROLE_NAME="postgres-pgadmin" ./backend/app/postgres/scripts/export_approle_from_vault_container.sh

# If you do NOT want to rotate secret_id on every run:
ROTATE_SECRET_ID=0 ./backend/app/postgres/scripts/export_approle_from_vault_container.sh

# Verify outputs
ls -lah ./container_data/vault/approle/
```

Notes:

- The script uses `root_token` / `root_token.json` under the bootstrap directory by default, and will securely prompt if neither exists. See the script header for details.
- The script relies on the Vault container’s internal `VAULT_ADDR` / `VAULT_CACERT` environment. If you are running Vault in “production FQDN mode” and the container cannot resolve that FQDN internally, switch Vault’s `VAULT_ADDR` back to `https://vault_production_node:8200` (see `docker-compose.prod.yml`) while running bootstrap tasks.

#### 6.3.3.2 Manual commands (fully expanded; no script)

If you prefer copy/paste commands (or need to troubleshoot the script), this is the complete sequence:

```bash
cd "$HOME/NETWORK_TOOLS"
umask 077

VAULT_CONTAINER="vault_production_node"
VAULT_ADDR_INTERNAL="https://vault_production_node:8200"
VAULT_CACERT_INTERNAL="/vault/certs/cert.crt"

# Choose the AppRole name you created
ROLE_NAME="postgres_pgadmin_agent"   # repo default
# ROLE_NAME="postgres-pgadmin"       # older example

VAULT_TOKEN="$(cat ./backend/app/security/configuration_files/vault/bootstrap/root_token)"

OUT_DIR="./container_data/vault/approle/${ROLE_NAME}"
mkdir -p "$OUT_DIR"
chmod 700 "$OUT_DIR"

ROLE_ID="$(
  docker exec -i     -e VAULT_ADDR="$VAULT_ADDR_INTERNAL"     -e VAULT_TOKEN="$VAULT_TOKEN"     -e VAULT_CACERT="$VAULT_CACERT_INTERNAL"     "$VAULT_CONTAINER"     sh -lc "vault read -field=role_id auth/approle/role/${ROLE_NAME}/role-id"
)"

SECRET_ID="$(
  docker exec -i     -e VAULT_ADDR="$VAULT_ADDR_INTERNAL"     -e VAULT_TOKEN="$VAULT_TOKEN"     -e VAULT_CACERT="$VAULT_CACERT_INTERNAL"     "$VAULT_CONTAINER"     sh -lc "vault write -field=secret_id -f auth/approle/role/${ROLE_NAME}/secret-id"
)"

printf '%s' "$ROLE_ID"   > "$OUT_DIR/role_id"
printf '%s' "$SECRET_ID" > "$OUT_DIR/secret_id"
chmod 600 "$OUT_DIR/role_id" "$OUT_DIR/secret_id"

ls -lah "$OUT_DIR"
```


Manual commands (copy/paste):

```bash
cd "$HOME/NETWORK_TOOLS"

VAULT_CONTAINER="vault_production_node"
VAULT_ADDR_INTERNAL="https://vault_production_node:8200"
VAULT_TOKEN="$(cat ./backend/app/security/configuration_files/vault/bootstrap/root_token)"

ROLE_ID="$(
  docker exec -i         -e VAULT_ADDR="$VAULT_ADDR_INTERNAL"         -e VAULT_TOKEN="$VAULT_TOKEN"         -e VAULT_CACERT="/vault/certs/cert.crt"         "$VAULT_CONTAINER"         sh -lc 'vault read -format=json auth/approle/role/postgres-pgadmin/role-id'       | jq -r '.data.role_id'
)"

SECRET_ID="$(
  docker exec -i         -e VAULT_ADDR="$VAULT_ADDR_INTERNAL"         -e VAULT_TOKEN="$VAULT_TOKEN"         -e VAULT_CACERT="/vault/certs/cert.crt"         "$VAULT_CONTAINER"         sh -lc 'vault write -f -format=json auth/approle/role/postgres-pgadmin/secret-id'       | jq -r '.data.secret_id'
)"

OUT_DIR="./container_data/vault/approle/postgres-pgadmin"
mkdir -p "$OUT_DIR"

printf '%s' "$ROLE_ID"   > "$OUT_DIR/role_id"
printf '%s' "$SECRET_ID" > "$OUT_DIR/secret_id"

chmod 600 "$OUT_DIR/role_id" "$OUT_DIR/secret_id"
ls -lah "$OUT_DIR"
```

Operational notes:
- Vault Agent’s AppRole auto-auth can delete the `secret_id` file after it reads it (recommended).
- With `secret_id_num_uses=1`, you will need to generate a new `secret_id` whenever you restart the agent (depending on caching and how you tune the role).

### 6.3.4 Vault Agent config + templates

Recommended repo paths (create these files in git, but do **not** commit role_id/secret_id):

```text
./backend/app/postgres/vault_agent/
  agent.hcl
  templates/
    postgres_db.ctmpl
    postgres_user.ctmpl
    postgres_password.ctmpl
    pgadmin_password.ctmpl
```

Example `agent.hcl` (KV v2 paths shown):

```hcl
pid_file = "/tmp/vault-agent.pid"

vault {
  address = "https://vault_production_node:8200"
  ca_cert = "/vault/ca/ca.crt"
}

auto_auth {
  method "approle" {
    config = {
      role_id_file_path                   = "/vault/approle/role_id"
      secret_id_file_path                 = "/vault/approle/secret_id"
      remove_secret_id_file_after_reading = true
    }
  }

  sink "file" {
    config = {
      path = "/vault/agent/token"
    }
  }
}

cache {
  use_auto_auth_token = true
}

template {
  source      = "/vault/templates/postgres_db.ctmpl"
  destination = "/vault/rendered/postgres_db"
  perms       = "0640"
}

template {
  source      = "/vault/templates/postgres_user.ctmpl"
  destination = "/vault/rendered/postgres_user"
  perms       = "0640"
}

template {
  source      = "/vault/templates/postgres_password.ctmpl"
  destination = "/vault/rendered/postgres_password"
  perms       = "0600"
}

template {
  source      = "/vault/templates/pgadmin_password.ctmpl"
  destination = "/vault/rendered/pgadmin_password"
  perms       = "0600"
}
```

Template examples (KV v2):

`postgres_db.ctmpl`
```ctmpl
{{- with secret "app_postgres_secrets/data/postgres" -}}
{{ .Data.data.POSTGRES_DB }}
{{- end }}
```

`postgres_user.ctmpl`
```ctmpl
{{- with secret "app_postgres_secrets/data/postgres" -}}
{{ .Data.data.POSTGRES_USER }}
{{- end }}
```

`postgres_password.ctmpl`
```ctmpl
{{- with secret "app_postgres_secrets/data/postgres" -}}
{{ .Data.data.POSTGRES_PASSWORD }}
{{- end }}
```

`pgadmin_password.ctmpl`
```ctmpl
{{- with secret "app_postgres_secrets/data/pgadmin" -}}
{{ .Data.data.PGADMIN_DEFAULT_PASSWORD }}
{{- end }}
```

### 6.3.5 Docker Compose wiring (vault-agent + shared secrets volume)

This repo currently wires Postgres/pgAdmin via `.env` (see `docker-compose.prod.yml`). To support the Vault Agent pattern cleanly, use **one of these approaches**:

**Approach 1 (recommended): add an override compose file**
- Keep `docker-compose.prod.yml` unchanged.
- Create `docker-compose.postgres_vault.override.yml` that:
  - Adds a `vault_agent_postgres_pgadmin` service.
  - Adds a named volume (example: `postgres_vault_rendered`) mounted at `/run/vault` in Postgres and pgAdmin.
  - Switches Postgres env to use `*_FILE` variables.
  - Switches pgAdmin to use `PGADMIN_DEFAULT_PASSWORD_FILE`.

Conceptual example (trimmed for clarity):

```yaml
services:
  vault_agent_postgres_pgadmin:
    image: hashicorp/vault:1.21.1
    container_name: vault_agent_postgres_pgadmin
    restart: unless-stopped
    depends_on:
      - vault_production_node
    entrypoint: ["/bin/sh","-lc","exec vault agent -config=/vault/agent/agent.hcl"]
    volumes:
      - ./backend/app/security/configuration_files/vault/certs/ca.crt:/vault/ca/ca.crt:ro
      - ./backend/app/postgres/vault_agent/agent.hcl:/vault/agent/agent.hcl:ro
      - ./backend/app/postgres/vault_agent/templates:/vault/templates:ro
      - ./container_data/vault/approle/postgres-pgadmin:/vault/approle:ro
      - postgres_vault_rendered:/vault/rendered

  postgres_primary:
    environment:
      POSTGRES_DB_FILE: "/run/vault/postgres_db"
      POSTGRES_USER_FILE: "/run/vault/postgres_user"
      POSTGRES_PASSWORD_FILE: "/run/vault/postgres_password"
    volumes:
      - postgres_vault_rendered:/run/vault:ro
    depends_on:
      - vault_agent_postgres_pgadmin

  pgadmin:
    environment:
      PGADMIN_DEFAULT_PASSWORD_FILE: "/run/vault/pgadmin_password"
    volumes:
      - postgres_vault_rendered:/run/vault:ro
    depends_on:
      - vault_agent_postgres_pgadmin

volumes:
  postgres_vault_rendered:
```

Bring up with both files:

```bash
docker compose -f docker-compose.prod.yml -f docker-compose.postgres_vault.override.yml up -d
```

**Approach 2: modify `docker-compose.prod.yml` directly**
- Suitable if you are comfortable committing the changes and keeping Vault Agent as the default.

### 6.3.6 Bring-up and verification

1) Ensure Vault is up and healthy:

```bash
docker compose -f docker-compose.prod.yml up -d vault_production_node
docker logs --tail 200 -f vault_production_node
```

2) Initialize/unseal/seed Vault (use your existing repo procedures in section 3.x).

3) Confirm the postgres + pgAdmin secrets exist in Vault (see **4.2** and **5.2**).

4) Export `role_id` + `secret_id` onto the host (see **6.3.3**).

5) Start the Vault Agent service:

```bash
docker compose -f docker-compose.prod.yml -f docker-compose.postgres_vault.override.yml up -d vault_agent_postgres_pgadmin
docker logs --tail 200 -f vault_agent_postgres_pgadmin
```

6) Confirm rendered files exist (example):

```bash
docker exec -it vault_agent_postgres_pgadmin sh -lc 'ls -lah /vault/rendered && echo "----" && sed -n "1,3p" /vault/rendered/postgres_user'
```

7) Start Postgres and pgAdmin:

```bash
docker compose -f docker-compose.prod.yml -f docker-compose.postgres_vault.override.yml up -d postgres_certs_init postgres_primary pgadmin
docker logs --tail 200 -f postgres_primary
docker logs --tail 200 -f pgadmin
```

### 6.3.7 Rotation and operational notes

- **Rotate the rendered secret files**
  - Generate a new `secret_id` (see **6.3.3**) and restart the agent container.
  - If you configured `remove_secret_id_file_after_reading=true`, the agent will remove the file after it reads it; your operational runbook should account for regenerating it.

- **Rotate the Postgres user password**
  - Changing the KV value alone is not sufficient if the database cluster is already initialized.
  - You must:
    1) Update the password in Postgres:
       ```bash
       docker exec -it postgres_primary sh -lc 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "ALTER USER \"$POSTGRES_USER\" WITH PASSWORD \"NEW_PASSWORD\";"'
       ```
    2) Update Vault KV (`POSTGRES_PASSWORD`).
    3) Restart clients that authenticate using that password (pgAdmin, apps, etc.).

- **Prefer dynamic credentials for applications**
  - When you are ready, move application authentication to Vault dynamic database credentials (see **6.4**). This reduces long-lived static passwords.

### 6.4 Option C – Advanced: Vault Database secrets engine (dynamic credentials)

This option is the most secure pattern for **applications** connecting to Postgres:
- Vault issues short-lived, revocable Postgres credentials on demand.
- Your application fetches credentials from Vault (or via Vault Agent templates) and renews them automatically.

Important limitation:
- This does **not** change how the `postgres` container itself initializes the database. It primarily improves how *other services* authenticate to Postgres after it is up.

High-level steps (outline):
1) Enable the database secrets engine in Vault (`vault secrets enable database`).
2) Configure a Postgres connection in Vault using an admin credential (managed carefully).
3) Create Vault roles that define SQL for creating/revoking users with TTLs.
4) Update your apps to request credentials from Vault at runtime.

When you adopt this, keep the initial bootstrap password in Vault as a break-glass/admin secret, but prefer dynamic roles for day-to-day service auth.

## Appendix A – Certificate Management

### A.1 Vault TLS Certificates – What to Keep and Where

The local Vault TLS setup uses a small script to generate a private CA and a server certificate for the Vault container. The script typically produces the following key files:

- `ca.crt`   – CA certificate (public)
- `ca.key`   – CA private key (**sensitive**)
- `cert.crt` – Vault server certificate (full chain; public)
- `cert.key` – Vault server private key (**sensitive**)

Any intermediate files (CSRs, temporary leaf certs, extfiles, etc.) are treated as ephemeral and can be discarded after a successful run.

#### 1. Files That Must Be Treated as Secrets

These files **must never** be committed to git or shared outside secure channels:

- **`ca.key` (CA private key)**  
  - This is the root of trust for this local CA.  
  - Anyone who obtains this can mint certificates that will be trusted wherever `ca.crt` is trusted.  
  - Keep it only:
    - On your admin machine, or
    - In a designated secure location on the server with restricted permissions.
  - Back it up to encrypted/offline storage (e.g., password manager attachment, encrypted archive, secure USB).
  - If/when you rotate the CA, this is the file you intentionally retire or destroy.

- **`cert.key` (Vault server private key)**  
  - Needed by Vault at runtime but must remain private.  
  - Should only live on the Vault host, under tight permissions (e.g., `chmod 600`).  
  - Never commit this to git. If backed up, treat it as any other secret (encrypted backup, not stored in the repo).

#### 2. Files That Can Be Safely Distributed

These files are public by design and can be shared with clients/services that need to trust Vault:

- **`ca.crt` (CA certificate)**  
  - Public certificate corresponding to `ca.key`.  
  - Clients and tools that need to trust Vault’s TLS certificate import this CA.  
  - It is acceptable to distribute this to any system that should trust Vault.  
  - Even though it is public, it is still recommended to keep it out of the application source tree and treat it as generated data rather than source code.

- **`cert.crt` (Vault server certificate / full chain)**  
  - Contains the Vault server certificate (and usually the CA chain).  
  - No private key material is present.  
  - Safe to inspect, copy, and distribute as needed.  
  - Can be regenerated as long as `ca.key` is available.

#### 3. Recommended Project Layout and Git Hygiene

By default, the script writes certs to a path similar to:

```text
backend/app/security/configuration_files/vault/certs/
```

Recommended practices:

1. **Ignore the cert directory / Other important files in git**

   Add the following to `.gitignore` (from the project root):

   ```gitignore
   # OS-specific junk
    .DS_Store
    Thumbs.db
    
    # Python artifacts
    __pycache__/
    *.py[cod]
    *.pyo
    
    # Virtual environments
    .venv/
    venv/
    
    # Logs
    logs/
    *.log
    
    # Local override files
    .env
    .env.*
    
    # Cert Directory
    backend/app/security/configuration_files/vault/certs/
    
    # JetBrains IDE
    .idea/
    
    # --- TLS private keys (never commit) ---
    *.key
    *.key.pem
    *.p12
    *.pfx
    
    # --- Certificates (optional: ignore if you generate locally) ---
    *.crt
    *.cer
    *.pem
    *.der
    
    # --- Vault bootstrap artifacts (never commit) ---
    **/bootstrap/**
    **/unseal_keys*.json
    **/root_token*
    **/seeded_secrets*.json
    
    # --- CA serial files ---
    *.srl
   ```

   This prevents accidental commits of `ca.key`, `cert.key`, `ca.crt`, or `cert.crt` and any other important files.


2. **Use the cert directory as the runtime mount for Vault**

   - Keep all cert-related files under `backend/app/security/configuration_files/vault/certs/`.
   - Mount that directory into the Vault container (e.g., `/vault/certs`) via `docker-compose`.
   - Recommended permissions on the host:

     ```bash
     chmod 700 backend/app/security/configuration_files/vault/certs
     chmod 600 backend/app/security/configuration_files/vault/certs/ca.key
     chmod 600 backend/app/security/configuration_files/vault/certs/cert.key
     chmod 644 backend/app/security/configuration_files/vault/certs/ca.crt
     chmod 644 backend/app/security/configuration_files/vault/certs/cert.crt
     ```

3. **Perform a one-time secure backup of critical keys**

   After the script runs and Vault is confirmed working, back up at least:

   - `ca.key` (mandatory)
   - `cert.key` (optional, but convenient if you don’t want to reissue)

   Store these backups in encrypted/offline storage (not in the repo, not on shared drives).

#### 4. Minimal “Must-Keep” List

If you are comfortable re-running the script and re-issuing certificates when needed:

- **Absolutely must keep and protect securely:**
  - `ca.key`

- **Should be kept with Vault for runtime and may be backed up:**
  - `cert.key`
  - `ca.crt`
  - `cert.crt`

In short:

- `ca.key` and `cert.key` are **secrets**. Protect them and never commit them.  
- `ca.crt` and `cert.crt` are **public certs**. Safe to distribute, but best kept in a non-versioned `certs/` directory rather than in the source tree.  
- The entire `vault/certs` directory should be treated as generated runtime data and excluded from git.



## A.2 Rootless Docker and Subordinate UID/GID Ranges (subuid/subgid)

Rootless Docker runs containers **without using real root** on the host. Inside a container, processes may think they are running as `root` (UID `0`), but on the host we **must not** grant real root privileges.

Linux solves this using **user namespaces**: container user IDs (UIDs) and group IDs (GIDs) are **mapped** to a block of normal, unprivileged IDs on the host. That block is called your **subordinate UID/GID ranges**.

## What are UID/GID ranges?

- **UID** = user ID (who owns files / runs processes)
- **GID** = group ID (group ownership/permissions)
- **Subordinate range** = a block of IDs your user is allowed to use inside a user namespace

These are configured in:

- `/etc/subuid` (UID ranges)
- `/etc/subgid` (GID ranges)

A typical entry looks like:

```text
developer_network_tools:100000:65536
```

Meaning:

- `developer_network_tools` = the username
- `100000` = starting ID
- `65536` = how many IDs are allocated

This grants a host-side range of:

- `100000` through `165535` (65,536 IDs total)

## Why “at least 65,536”?

Many container images and tooling expect a reasonably large ID space for creating users/groups inside containers. The common default is **65,536** (`2^16`). Smaller ranges can cause unexpected permission errors or failures when containers try to create additional users/groups.

## How to check your current ranges

```bash
whoami
grep "^$(whoami):" /etc/subuid
grep "^$(whoami):" /etc/subgid
```

You should see **one line in each file** for your user, and the last number should be **65536** (or higher).

## How to set the ranges (Ubuntu)

Run as an admin user (or via sudo):

```bash
sudo usermod --add-subuids 100000-165535 --add-subgids 100000-165535 $(whoami)
```

Re-check:

```bash
grep "^$(whoami):" /etc/subuid /etc/subgid
```

Then **log out and log back in** (or reboot) so the session picks up the changes.

## Common symptoms when this is missing or wrong

- Rootless Docker daemon fails to start
- Containers fail to run, or fail on file permission operations
- Bind mounts/volumes create files owned by “weird” numeric IDs (because mappings are broken)

This is expected behavior when user namespace ID mapping is not configured correctly.
