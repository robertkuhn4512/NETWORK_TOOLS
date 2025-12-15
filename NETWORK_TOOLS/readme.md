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
- PostgreSQL
- HashiCorp Vault
- Keycloak
- Rootless Docker for running these services under a non-privileged account

---

## Table of Contents

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
  - Host **MariaDB**, **PostgreSQL**, **Vault**, and **Keycloak** in containers later.

> **Note:** For commands prefixed with `sudo`, run them from your normal user.  
> If you are logged in as `root`, you can omit `sudo`.

---

### 1.2 Update the Operating System

Update package metadata and upgrade all installed packages:

```bash
sudo apt update
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
