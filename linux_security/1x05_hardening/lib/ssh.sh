#!/bin/bash

set_sshd_option() {
    local option="$1"
    local value="$2"

    sed -i -E "/^[#[:space:]]*${option}[[:space:]]+/d" "$SSHD_CONFIG"
    printf '%s %s\n' "$option" "$value" >> "$SSHD_CONFIG"

    log "SUCCESS" "SSH option $option set to $value"
}

harden_ssh() {
    set_sshd_option "PasswordAuthentication" "$PASSWORD_AUTHENTICATION"
    set_sshd_option "PubkeyAuthentication" "$PUBKEY_AUTHENTICATION"
    set_sshd_option "PermitRootLogin" "$PERMIT_ROOT_LOGIN"

    if sshd -t -f "$SSHD_CONFIG"; then
        log "SUCCESS" "SSH configuration validation passed"
    else
        log "ERROR" "SSH configuration validation failed"
        return 1
    fi

    log "SUCCESS" "SSH hardening completed"
}
