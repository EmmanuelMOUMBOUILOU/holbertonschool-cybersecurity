#!/bin/bash
set -eu

# LogiCorp Capstone - System hardening
# Run as root on the LogiCorp Gateway.

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: run this script as root."
    exit 1
fi

BACKUP_DIR="/root/logicorp-hardening-backup"
mkdir -p "$BACKUP_DIR"

backup_once() {
    src="$1"
    name="$(echo "$src" | sed 's#/#_#g' | sed 's/^_//')"
    if [ -e "$src" ] && [ ! -e "$BACKUP_DIR/$name" ]; then
        cp -a "$src" "$BACKUP_DIR/$name"
    fi
}

echo "[1/5] Preserving current configuration..."
backup_once /etc/ssh/sshd_config
backup_once /etc/vsftpd.conf
backup_once /etc/cron.d/logicorp

echo "[2/5] Removing unnecessary / suspicious services and persistence..."
# Telnet/inetd are not required by the approved design.
service openbsd-inetd stop 2>/dev/null || true
pkill -x in.telnetd 2>/dev/null || true

# Preserve the cron artifact in the backup, then disable the audited backdoor.
if [ -f /etc/cron.d/logicorp ]; then
    mv /etc/cron.d/logicorp "$BACKUP_DIR/logicorp.disabled"
fi

echo "[3/5] Hardening SSH..."
# Do not disable password authentication unless the authorized key exists.
if [ ! -s /home/student/.ssh/authorized_keys ]; then
    echo "ERROR: /home/student/.ssh/authorized_keys is missing or empty."
    echo "Refusing to disable SSH password authentication."
    exit 1
fi

set_sshd_option() {
    key="$1"
    value="$2"
    if grep -Eqi "^[[:space:]#]*${key}[[:space:]]+" /etc/ssh/sshd_config; then
        sed -ri "s|^[[:space:]#]*${key}[[:space:]]+.*|${key} ${value}|I" /etc/ssh/sshd_config
    else
        printf '%s %s\n' "$key" "$value" >> /etc/ssh/sshd_config
    fi
}

set_sshd_option PermitRootLogin no
set_sshd_option PasswordAuthentication no
set_sshd_option PubkeyAuthentication yes

# Keep the approved administrative account explicitly allowed.
if ! grep -Eq '^[[:space:]]*AllowUsers([[:space:]]+.*[[:space:]])?student([[:space:]]|$)' /etc/ssh/sshd_config; then
    printf '%s\n' 'AllowUsers student' >> /etc/ssh/sshd_config
fi

/usr/sbin/sshd -t
service ssh reload 2>/dev/null || service ssh restart

echo "[4/5] Securing the legacy FTP service..."
set_vsftpd_option() {
    key="$1"
    value="$2"
    sed -i "/^[[:space:]]*${key}=/d" /etc/vsftpd.conf
    printf '%s=%s\n' "$key" "$value" >> /etc/vsftpd.conf
}

# FTP is temporarily retained for Finance but must not allow anonymous access.
set_vsftpd_option anonymous_enable NO
set_vsftpd_option local_enable YES
set_vsftpd_option write_enable YES
set_vsftpd_option ssl_enable NO

# Fixed passive range so the firewall can permit only what Finance needs.
set_vsftpd_option pasv_min_port 30000
set_vsftpd_option pasv_max_port 30100

service vsftpd restart

echo "[5/5] Applying basic secure file permissions..."
chmod 700 /home/student/.ssh
chmod 600 /home/student/.ssh/authorized_keys
chown -R student:student /home/student/.ssh

echo
echo "System hardening completed."
echo "Backups: $BACKUP_DIR"
echo "IMPORTANT: keep the current SSH session open until VPN + firewall validation is complete."
