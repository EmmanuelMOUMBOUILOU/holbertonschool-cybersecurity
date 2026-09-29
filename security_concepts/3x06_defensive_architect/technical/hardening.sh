#!/bin/bash

set -e

# Nexus Financial - System Hardening Script
# Establishes a repeatable security baseline for Ubuntu servers.

if [ "$EUID" -ne 0 ]; then
    echo "Error: this script must be run as root."
    exit 1
fi

echo "[+] Starting system hardening..."

# --------------------------------------------------
# 1. System Updates
# --------------------------------------------------

echo "[+] Updating package lists and applying security updates..."

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y

# --------------------------------------------------
# 2. Install Security Packages
# --------------------------------------------------

echo "[+] Installing required security packages..."

DEBIAN_FRONTEND=noninteractive apt-get install -y \
    openssh-server \
    ufw \
    apparmor \
    apparmor-utils \
    unattended-upgrades

# --------------------------------------------------
# 3. SSH Hardening
# --------------------------------------------------

echo "[+] Hardening SSH configuration..."

SSHD_CONFIG="/etc/ssh/sshd_config"

cp -n "$SSHD_CONFIG" "${SSHD_CONFIG}.backup" || true

set_sshd_option() {
    local key="$1"
    local value="$2"

    if grep -qE "^[#[:space:]]*${key}[[:space:]]+" "$SSHD_CONFIG"; then
        sed -i -E "s|^[#[:space:]]*${key}[[:space:]]+.*|${key} ${value}|" "$SSHD_CONFIG"
    else
        echo "${key} ${value}" >> "$SSHD_CONFIG"
    fi
}

set_sshd_option "PermitRootLogin" "no"
set_sshd_option "PasswordAuthentication" "no"
set_sshd_option "PubkeyAuthentication" "yes"
set_sshd_option "PermitEmptyPasswords" "no"
set_sshd_option "X11Forwarding" "no"
set_sshd_option "MaxAuthTries" "3"

if sshd -t; then
    systemctl reload ssh
else
    echo "Error: invalid SSH configuration."
    exit 1
fi

# --------------------------------------------------
# 4. Firewall Baseline
# --------------------------------------------------

echo "[+] Configuring firewall baseline..."

ufw default deny incoming
ufw default allow outgoing

# SSH remains available for administration.
ufw allow 22/tcp

ufw --force enable

# --------------------------------------------------
# 5. AppArmor
# --------------------------------------------------

echo "[+] Enabling AppArmor..."

systemctl enable apparmor
systemctl restart apparmor

# --------------------------------------------------
# 6. Automatic Security Updates
# --------------------------------------------------

echo "[+] Enabling unattended security updates..."

dpkg-reconfigure -f noninteractive unattended-upgrades

# --------------------------------------------------
# 7. Disable Unnecessary Legacy Services
# --------------------------------------------------

echo "[+] Disabling unnecessary legacy services when present..."

for service in telnet rsh rlogin; do
    if systemctl list-unit-files | grep -q "^${service}\.service"; then
        systemctl disable --now "${service}.service" || true
    fi
done

# --------------------------------------------------
# 8. Secure Sensitive System Files
# --------------------------------------------------

echo "[+] Applying secure permissions..."

chmod 644 /etc/passwd
chmod 640 /etc/shadow
chmod 644 /etc/group
chmod 640 /etc/gshadow

# --------------------------------------------------
# 9. Final Validation
# --------------------------------------------------

echo "[+] Validating hardening configuration..."

sshd -t
ufw status
aa-status || true

echo "[+] System hardening completed successfully."