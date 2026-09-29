#!/bin/bash

set -e

# Nexus Financial - RBAC Setup
# Implements least privilege and separation of duties.

if [ "$EUID" -ne 0 ]; then
    echo "Error: this script must be run as root."
    exit 1
fi

echo "[+] Configuring RBAC..."

# --------------------------------------------------
# 1. Create RBAC Groups
# --------------------------------------------------

if ! getent group devs > /dev/null; then
    groupadd devs
    echo "[+] Created group: devs"
fi

if ! getent group ops > /dev/null; then
    groupadd ops
    echo "[+] Created group: ops"
fi

if ! getent group auditors > /dev/null; then
    groupadd auditors
    echo "[+] Created group: auditors"
fi

# --------------------------------------------------
# 2. Create Dummy Users
# --------------------------------------------------

create_user() {
    local user="$1"

    if ! id "$user" > /dev/null 2>&1; then
        useradd -m -s /bin/bash "$user"
        echo "[+] Created user: $user"
    fi
}

create_user sarah
create_user opsuser
create_user dave

# --------------------------------------------------
# 3. Assign Users to Roles
# --------------------------------------------------

usermod -aG devs sarah
usermod -aG ops opsuser
usermod -aG auditors dave

# --------------------------------------------------
# 4. Configure Sudoers
# --------------------------------------------------

echo "[+] Configuring sudo privileges..."

SUDOERS_FILE="/etc/sudoers.d/nexus-rbac"

cat > "$SUDOERS_FILE" <<'EOF'
# Nexus Financial RBAC

# Developers may restart and check the status of Nginx.
%devs ALL=(root) /bin/systemctl restart nginx
%devs ALL=(root) /bin/systemctl status nginx

# Operations personnel may manage Nginx.
%ops ALL=(root) /bin/systemctl start nginx
%ops ALL=(root) /bin/systemctl stop nginx
%ops ALL=(root) /bin/systemctl restart nginx
%ops ALL=(root) /bin/systemctl reload nginx
%ops ALL=(root) /bin/systemctl status nginx

# Auditors receive no sudo privileges.
# Log access is provided through group permissions.
EOF

chmod 440 "$SUDOERS_FILE"

if ! visudo -cf "$SUDOERS_FILE"; then
    echo "Error: invalid sudoers configuration."
    exit 1
fi

# --------------------------------------------------
# 5. Configure Read-Only Log Access
# --------------------------------------------------

echo "[+] Configuring auditor log access..."

if [ -d /var/log ]; then
    setfacl -m g:auditors:rx /var/log 2>/dev/null || true

    find /var/log -type f -exec setfacl -m g:auditors:r {} \; 2>/dev/null || true
    find /var/log -type d -exec setfacl -m g:auditors:rx {} \; 2>/dev/null || true
fi

# --------------------------------------------------
# 6. Protect Home Directories
# --------------------------------------------------

echo "[+] Securing home directories..."

for user in sarah opsuser dave; do
    home=$(getent passwd "$user" | cut -d: -f6)

    if [ -n "$home" ] && [ -d "$home" ]; then
        chown "$user:$user" "$home"
        chmod 700 "$home"
    fi
done

# --------------------------------------------------
# 7. Validation
# --------------------------------------------------

echo "[+] Validating RBAC configuration..."

getent group devs
getent group ops
getent group auditors

id sarah
id opsuser
id dave

visudo -cf "$SUDOERS_FILE"

echo "[+] RBAC configuration completed successfully."