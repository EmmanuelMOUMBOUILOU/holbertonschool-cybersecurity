#!/bin/bash
set -eu

# LogiCorp Capstone - Zero-Trust nftables policy
# IMPORTANT:
#   1. Bring up and test WireGuard first.
#   2. Run ./panic.sh arm before this script.
#   3. Keep the current administrative session open.
#
# The database TCP port is intentionally NOT guessed.
# Export DB_PORT with the confirmed application port before running:
#   export DB_PORT=<confirmed_port>

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: run this script as root."
    exit 1
fi

command -v nft >/dev/null 2>&1 || {
    echo "ERROR: nft command not found."
    exit 1
}

if [ ! -f /run/logicorp-panic.pid ] || ! kill -0 "$(cat /run/logicorp-panic.pid)" 2>/dev/null; then
    echo "ERROR: panic rollback is not armed."
    echo "Run: ./panic.sh arm"
    exit 1
fi

: "${DB_PORT:?ERROR: export DB_PORT with the confirmed database TCP port before applying the firewall.}"

WAN_IF="${WAN_IF:-$(ip route show default | awk '/default/ {print $5; exit}')}"
VPN_IF="${VPN_IF:-wg0}"

VPN_NET="${VPN_NET:-10.200.0.0/24}"
ADMIN_VPN_NET="${ADMIN_VPN_NET:-10.200.0.0/27}"
FINANCE_VPN_NET="${FINANCE_VPN_NET:-10.200.0.32/27}"

LAN_NET="${LAN_NET:-192.168.10.0/24}"
FINANCE_NET="${FINANCE_NET:-192.168.20.0/24}"
DB_NET="${DB_NET:-192.168.30.0/24}"
DMZ_NET="${DMZ_NET:-192.168.40.0/24}"
GUEST_NET="${GUEST_NET:-192.168.50.0/24}"

RULESET="/tmp/logicorp-firewall.nft"

cat > "$RULESET" <<EOF
flush ruleset

table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;

        iifname "lo" accept
        ct state established,related accept
        ct state invalid drop

        # WireGuard from WAN.
        iifname "$WAN_IF" udp dport 51820 accept

        # Administrative SSH only through the VPN.
        iifname "$VPN_IF" ip saddr $ADMIN_VPN_NET tcp dport 22 accept

        # Finance legacy FTP only through the VPN.
        iifname "$VPN_IF" ip saddr $FINANCE_VPN_NET tcp dport 21 accept
        iifname "$VPN_IF" ip saddr $FINANCE_VPN_NET tcp dport 30000-30100 accept

        # Essential diagnostics.
        ip protocol icmp accept
        ip6 nexthdr icmpv6 accept

        limit rate 10/second log prefix "NFT-INPUT-DROP: " flags all counter
    }

    chain forward {
        type filter hook forward priority 0; policy drop;

        ct state established,related accept
        ct state invalid drop

        # Guest is Internet-only.
        ip saddr $GUEST_NET ip daddr { $LAN_NET, $FINANCE_NET, $DB_NET, $DMZ_NET } drop
        ip saddr $GUEST_NET oifname "$WAN_IF" udp dport 53 accept
        ip saddr $GUEST_NET oifname "$WAN_IF" tcp dport { 53, 80, 443 } accept

        # Only approved LAN application systems may initiate DB traffic.
        # Source range can be narrowed further with APP_NET if required.
        ip saddr $LAN_NET ip daddr $DB_NET tcp dport $DB_PORT accept

        # VPN administrators: approved management path only.
        ip saddr $ADMIN_VPN_NET ip daddr { $LAN_NET, $FINANCE_NET, $DB_NET, $DMZ_NET } tcp dport 22 accept

        # Finance VPN users may reach only the Finance FTP service/zone.
        ip saddr $FINANCE_VPN_NET ip daddr $FINANCE_NET tcp dport 21 accept
        ip saddr $FINANCE_VPN_NET ip daddr $FINANCE_NET tcp dport 30000-30100 accept

        # General business web/DNS egress.
        ip saddr { $LAN_NET, $FINANCE_NET, $DMZ_NET } oifname "$WAN_IF" udp dport 53 accept
        ip saddr { $LAN_NET, $FINANCE_NET, $DMZ_NET } oifname "$WAN_IF" tcp dport { 53, 80, 443 } accept

        limit rate 10/second log prefix "NFT-FWD-DROP: " flags all counter
    }

    chain output {
        type filter hook output priority 0; policy drop;

        oifname "lo" accept
        ct state established,related accept
        ct state invalid drop

        # Required gateway services.
        udp dport { 53, 123, 51820 } accept
        tcp dport { 53, 80, 443 } accept

        ip protocol icmp accept
        ip6 nexthdr icmpv6 accept

        limit rate 10/second log prefix "NFT-OUTPUT-DROP: " flags all counter
    }
}

table ip nat {
    chain postrouting {
        type nat hook postrouting priority 100; policy accept;

        ip saddr $VPN_NET oifname "$WAN_IF" masquerade
        ip saddr { $LAN_NET, $FINANCE_NET, $DMZ_NET, $GUEST_NET } oifname "$WAN_IF" masquerade
    }
}
EOF

echo "Validating nftables ruleset..."
nft -c -f "$RULESET"

echo "Applying nftables ruleset..."
nft -f "$RULESET"

echo
echo "Firewall applied."
echo "WAN interface: $WAN_IF"
echo "VPN interface: $VPN_IF"
echo "Database TCP port: $DB_PORT"
echo
echo "Validate VPN, SSH, FTP and database access NOW."
echo "If successful: ./panic.sh cancel"
echo "If not:        ./panic.sh restore"
