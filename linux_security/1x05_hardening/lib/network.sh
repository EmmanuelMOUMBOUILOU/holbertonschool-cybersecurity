#!/bin/bash

set_sysctl_value() {
    local key="$1"
    local value="$2"

    if grep -Eq "^[[:space:]]*${key//./\\.}[[:space:]]*=" "$SYSCTL_FILE"; then
        sed -i -E "s|^[[:space:]]*${key//./\\.}[[:space:]]*=.*|${key}=${value}|" "$SYSCTL_FILE"
    else
        printf '%s=%s\n' "$key" "$value" >> "$SYSCTL_FILE"
    fi

    log "SUCCESS" "Kernel parameter $key set to $value"
}

configure_firewall_policy() {
    install -d -m 755 "$(dirname "$FIREWALL_RULES_FILE")"

    {
        echo "DEFAULT_INPUT=deny"
        echo "DEFAULT_OUTPUT=allow"
        echo "ALLOW_TCP=$SSH_PORT"

        if [ "$ALLOW_HTTP" = "yes" ]; then
            echo "ALLOW_TCP=80"
        fi

        if [ "$ALLOW_HTTPS" = "yes" ]; then
            echo "ALLOW_TCP=443"
        fi
    } > "$FIREWALL_RULES_FILE"

    chmod 600 "$FIREWALL_RULES_FILE"
    log "SUCCESS" "Firewall policy written to $FIREWALL_RULES_FILE"
}

harden_kernel_network() {
    set_sysctl_value "net.ipv4.ip_forward" "0"
    set_sysctl_value "net.ipv4.icmp_echo_ignore_all" "1"

    log "SUCCESS" "Persistent network kernel hardening configured"
}

harden_network() {
    configure_firewall_policy
    harden_kernel_network
    log "SUCCESS" "Network hardening completed"
}
