#!/bin/bash

set -e

# Nexus Financial - Centralized Logging and Audit Setup

if [ "$EUID" -ne 0 ]; then
    echo "Error: this script must be run as root."
    exit 1
fi

echo "[+] Installing logging and auditing packages..."

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y rsyslog auditd audispd-plugins

# --------------------------------------------------
# 1. Centralized rsyslog Forwarding
# --------------------------------------------------

echo "[+] Configuring centralized logging..."

RSYSLOG_CONF="/etc/rsyslog.d/60-nexus-central.conf"

cat > "$RSYSLOG_CONF" <<'EOF'
# Nexus Financial centralized logging

# Forward critical logs to the central log server.
*.crit @@10.0.1.20:514

# Forward authentication and authorization logs.
auth,authpriv.* @@10.0.1.20:514
EOF

# Validate rsyslog configuration before restarting.
rsyslogd -N1

systemctl enable rsyslog
systemctl restart rsyslog

# --------------------------------------------------
# 2. auditd Rules
# --------------------------------------------------

echo "[+] Configuring auditd monitoring..."

AUDIT_RULES="/etc/audit/rules.d/nexus.rules"

cat > "$AUDIT_RULES" <<'EOF'
# Nexus Financial audit rules

# Monitor identity and authentication files.
-w /etc/passwd -p wa -k identity_changes
-w /etc/group -p wa -k identity_changes
-w /etc/shadow -p wa -k credential_changes
-w /etc/gshadow -p wa -k credential_changes

# Monitor sudo configuration.
-w /etc/sudoers -p wa -k sudoers_changes
-w /etc/sudoers.d/ -p wa -k sudoers_changes

# Monitor SSH configuration.
-w /etc/ssh/sshd_config -p wa -k ssh_changes

# Monitor privileged command execution.
-a always,exit -F arch=b64 -F euid=0 -S execve -k privileged_commands
-a always,exit -F arch=b32 -F euid=0 -S execve -k privileged_commands

# Make audit configuration immutable until reboot.
-e 2
EOF

# --------------------------------------------------
# 3. Load Audit Rules
# --------------------------------------------------

echo "[+] Loading audit rules..."

augenrules --load

systemctl enable auditd

# --------------------------------------------------
# 4. Validation
# --------------------------------------------------

echo "[+] Validating logging configuration..."

auditctl -l

echo "[+] Centralized logging configured."
echo "[+] Critical logs forwarded to 10.0.1.20:514."
echo "[+] Sensitive files monitored by auditd."
echo "[+] Privileged command execution monitored."
echo "[+] Audit rules are immutable until reboot."