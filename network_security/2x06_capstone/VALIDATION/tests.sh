#!/bin/bash

# LogiCorp Capstone - Automated Compliance Check
# Run on the LogiCorp Gateway after HARDENING deployment.
# Read-only: this script validates posture and does not modify the system.

PASS_COUNT=0
FAIL_COUNT=0
TOTAL_COUNT=0

pass() {
    TOTAL_COUNT=$((TOTAL_COUNT + 1))
    PASS_COUNT=$((PASS_COUNT + 1))
    echo "[PASS] $1"
}

fail() {
    TOTAL_COUNT=$((TOTAL_COUNT + 1))
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo "[FAIL] $1"
}

contains_line() {
    printf '%s\n' "$1" | grep -Eq "$2"
}

echo "LogiCorp Security Compliance Check"
echo "================================="
echo

# 1. FIREWALL STATUS
NFT_RULESET=""

if command -v nft >/dev/null 2>&1 && NFT_RULESET="$(nft list ruleset 2>/dev/null)"; then
    INPUT_CHAIN="$(nft list chain inet filter input 2>/dev/null || true)"
    FORWARD_CHAIN="$(nft list chain inet filter forward 2>/dev/null || true)"
    OUTPUT_CHAIN="$(nft list chain inet filter output 2>/dev/null || true)"

    if contains_line "$INPUT_CHAIN" 'policy drop'; then
        pass "Firewall default INPUT policy is DROP"
    else
        fail "Firewall default INPUT policy is not DROP"
    fi

    if contains_line "$FORWARD_CHAIN" 'policy drop'; then
        pass "Firewall default FORWARD policy is DROP"
    else
        fail "Firewall default FORWARD policy is not DROP"
    fi

    if contains_line "$OUTPUT_CHAIN" 'policy drop'; then
        pass "Firewall default OUTPUT policy is DROP"
    else
        fail "Firewall default OUTPUT policy is not DROP"
    fi

    if contains_line "$NFT_RULESET" 'udp dport 51820.*accept'; then
        pass "WireGuard UDP/51820 allow rule exists"
    else
        fail "WireGuard UDP/51820 allow rule is missing"
    fi

    if contains_line "$NFT_RULESET" 'ct state (established,related|related,established).*accept'; then
        pass "Established/related traffic rule exists"
    else
        fail "Established/related traffic rule is missing"
    fi
else
    fail "Firewall default INPUT policy could not be verified"
    fail "Firewall default FORWARD policy could not be verified"
    fail "Firewall default OUTPUT policy could not be verified"
    fail "WireGuard UDP/51820 firewall rule could not be verified"
    fail "Established/related firewall rule could not be verified"
fi

# 2. SERVICE STATUS
if pgrep -x sshd >/dev/null 2>&1; then
    pass "SSH service is running"
else
    fail "SSH service is not running"
fi

if ip link show wg0 >/dev/null 2>&1 && ip link show wg0 | grep -q 'state UP'; then
    pass "VPN interface wg0 is UP"
else
    fail "VPN interface wg0 is not UP"
fi

if pgrep -x inetd >/dev/null 2>&1 || pgrep -x in.telnetd >/dev/null 2>&1; then
    fail "Unnecessary Telnet/inetd service is running"
else
    pass "Unnecessary Telnet/inetd service is stopped"
fi

if pgrep -x vsftpd >/dev/null 2>&1; then
    pass "Required Finance FTP service is running"
else
    fail "Required Finance FTP service is not running"
fi

# 3. ACCESS CONTROL
SSHD_EFFECTIVE="$(/usr/sbin/sshd -T 2>/dev/null || true)"

if contains_line "$SSHD_EFFECTIVE" '^permitrootlogin no$'; then
    pass "SSH root login disabled"
else
    fail "SSH root login is not disabled"
fi

if contains_line "$SSHD_EFFECTIVE" '^passwordauthentication no$'; then
    pass "SSH password authentication disabled"
else
    fail "SSH password authentication is still enabled"
fi

if contains_line "$SSHD_EFFECTIVE" '^pubkeyauthentication yes$'; then
    pass "SSH public-key authentication enabled"
else
    fail "SSH public-key authentication is not enabled"
fi

SUDO_MEMBERS="$(getent group sudo | awk -F: '{print $4}')"
if [ -z "$SUDO_MEMBERS" ]; then
    pass "No unauthorized users are present in the sudo group"
else
    fail "Unexpected sudo-group members found: $SUDO_MEMBERS"
fi

if grep -Eq '^[[:space:]]*anonymous_enable=NO[[:space:]]*$' /etc/vsftpd.conf 2>/dev/null \
   && ! grep -Eq '^[[:space:]]*anonymous_enable=YES[[:space:]]*$' /etc/vsftpd.conf 2>/dev/null; then
    pass "Anonymous FTP access disabled"
else
    fail "Anonymous FTP access is enabled or ambiguous"
fi

if [ ! -e /etc/cron.d/logicorp ]; then
    pass "Suspicious LogiCorp cron task removed"
else
    fail "Suspicious LogiCorp cron task still exists"
fi

# 4. NETWORK CONFIGURATION
IP_FORWARD="$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)"
if [ "$IP_FORWARD" = "1" ]; then
    pass "IPv4 forwarding is enabled"
else
    fail "IPv4 forwarding is disabled"
fi

if ip -4 addr show dev wg0 2>/dev/null | grep -q '10\.200\.0\.1/24'; then
    pass "WireGuard interface has address 10.200.0.1/24"
else
    fail "WireGuard interface does not have address 10.200.0.1/24"
fi

if ip route show default 2>/dev/null | grep -q '^default '; then
    pass "Default network route exists"
else
    fail "Default network route is missing"
fi

echo
echo "================================="
echo "RESULT: ${PASS_COUNT}/${TOTAL_COUNT} checks passed"

if [ "$FAIL_COUNT" -eq 0 ]; then
    exit 0
else
    exit 1
fi
