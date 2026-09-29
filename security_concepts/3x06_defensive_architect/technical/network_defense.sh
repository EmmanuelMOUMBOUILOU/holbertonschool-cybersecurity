#!/bin/bash

set -e

# Nexus Financial - Network Defense
# Usage: sudo ./network_defense.sh <WEB_SERVER_PRIVATE_IP> <BASTION_HOST_IP>

if [ "$EUID" -ne 0 ]; then
    echo "Error: this script must be run as root."
    exit 1
fi

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <WEB_SERVER_PRIVATE_IP> <BASTION_HOST_IP>"
    exit 1
fi

ufw allow from "$WEB_SERVER_PRIVATE_IP" to any port 5432 proto tcp

echo "[+] Configuring Nexus Financial network defense..."

# Install UFW if necessary.
if ! command -v ufw > /dev/null 2>&1; then
    apt-get update
    apt-get install -y ufw
fi

# --------------------------------------------------
# 1. Default Deny Policy
# --------------------------------------------------

ufw default deny incoming
ufw default allow outgoing

# --------------------------------------------------
# 2. PostgreSQL Protection
# --------------------------------------------------

# Block public access to PostgreSQL.
ufw deny 5432/tcp

# Allow PostgreSQL only from the Web Server private IP.
ufw allow from "$WEB_SERVER_PRIVATE_IP" to any port 5432 proto tcp

# --------------------------------------------------
# 3. SSH Protection
# --------------------------------------------------

# Block public SSH access.
ufw deny 22/tcp

# Allow SSH only from the Bastion Host.
ufw allow from "$BASTION_HOST_IP" to any port 22 proto tcp

# --------------------------------------------------
# 4. Enable Firewall
# --------------------------------------------------

ufw --force enable

# --------------------------------------------------
# 5. Validation
# --------------------------------------------------

echo "[+] Network defense configured successfully."
echo "[+] PostgreSQL 5432 allowed from: $WEB_SERVER_PRIVATE_IP"
echo "[+] SSH 22 allowed from: $BASTION_HOST_IP"

ufw status verbose