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

You should be prompted for the **key passphrase** (if you set one), but not for the server account password.

#### 1.5.3 Install the SSH Key for `developer_network_tools`

Repeat the process for the `developer_network_tools` account so you can log in directly as the development user.

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
