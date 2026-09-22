#!/bin/bash
set -eu

# LogiCorp Capstone - WireGuard deployment
# Generates one Admin client and one Finance client configuration.
# Client private configurations stay under /root and MUST NOT be committed.

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: run this script as root."
    exit 1
fi

if ! command -v wg >/dev/null 2>&1 || ! command -v wg-quick >/dev/null 2>&1; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y wireguard-tools
fi

WG_DIR="/etc/wireguard"
CLIENT_DIR="/root/logicorp-vpn-clients"
mkdir -p "$WG_DIR" "$CLIENT_DIR"
chmod 700 "$WG_DIR" "$CLIENT_DIR"

umask 077

generate_keypair() {
    name="$1"
    if [ ! -s "$WG_DIR/${name}.key" ]; then
        wg genkey | tee "$WG_DIR/${name}.key" | wg pubkey > "$WG_DIR/${name}.pub"
    fi
}

generate_keypair server
generate_keypair admin
generate_keypair finance

SERVER_PRIV="$(cat "$WG_DIR/server.key")"
SERVER_PUB="$(cat "$WG_DIR/server.pub")"
ADMIN_PUB="$(cat "$WG_DIR/admin.pub")"
FINANCE_PUB="$(cat "$WG_DIR/finance.pub")"

cat > "$WG_DIR/wg0.conf" <<EOF
[Interface]
Address = 10.200.0.1/24
ListenPort = 51820
PrivateKey = $SERVER_PRIV

# Administrator
[Peer]
PublicKey = $ADMIN_PUB
AllowedIPs = 10.200.0.10/32

# Finance
[Peer]
PublicKey = $FINANCE_PUB
AllowedIPs = 10.200.0.50/32
EOF

chmod 600 "$WG_DIR/wg0.conf"

# Enable routing persistently where supported.
cat > /etc/sysctl.d/99-logicorp-forwarding.conf <<'EOF'
net.ipv4.ip_forward=1
EOF
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true

# The endpoint is intentionally a placeholder because the public WAN address
# must be confirmed from the real environment, not guessed.
ADMIN_PRIV="$(cat "$WG_DIR/admin.key")"
FINANCE_PRIV="$(cat "$WG_DIR/finance.key")"

cat > "$CLIENT_DIR/admin-client.conf" <<EOF
[Interface]
Address = 10.200.0.10/32
PrivateKey = $ADMIN_PRIV

[Peer]
PublicKey = $SERVER_PUB
Endpoint = REPLACE_WITH_CONFIRMED_WAN_IP:51820
AllowedIPs = 10.200.0.0/24, 192.168.10.0/24, 192.168.20.0/24, 192.168.30.0/24, 192.168.40.0/24
PersistentKeepalive = 25
EOF

cat > "$CLIENT_DIR/finance-client.conf" <<EOF
[Interface]
Address = 10.200.0.50/32
PrivateKey = $FINANCE_PRIV

[Peer]
PublicKey = $SERVER_PUB
Endpoint = REPLACE_WITH_CONFIRMED_WAN_IP:51820
AllowedIPs = 10.200.0.0/24, 192.168.20.0/24
PersistentKeepalive = 25
EOF

chmod 600 "$CLIENT_DIR/"*.conf

echo "WireGuard configuration generated."
echo "Server config:  $WG_DIR/wg0.conf"
echo "Admin client:   $CLIENT_DIR/admin-client.conf"
echo "Finance client: $CLIENT_DIR/finance-client.conf"
echo
echo "Before distributing client configs:"
echo "  - Replace REPLACE_WITH_CONFIRMED_WAN_IP with the verified public endpoint."
echo "  - Never commit the generated private keys or client configs to Git."

# Attempt activation. Some training containers intentionally lack CAP_NET_ADMIN.
wg-quick down wg0 >/dev/null 2>&1 || true
if wg-quick up "$WG_DIR/wg0.conf"; then
    echo "WireGuard interface wg0 is UP."
    wg show
else
    echo "WARNING: WireGuard configuration is validly generated but could not be activated."
    echo "If this is the Holberton container lab, verify whether CAP_NET_ADMIN is available."
    exit 1
fi
