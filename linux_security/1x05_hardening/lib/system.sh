#!/bin/bash

update_system() {
    if DEBIAN_FRONTEND=noninteractive apt-get update -y >/dev/null 2>&1; then
        log "SUCCESS" "Package repositories updated"
    else
        log "ERROR" "Failed to update package repositories"
        return 1
    fi

    if DEBIAN_FRONTEND=noninteractive apt-get upgrade -y >/dev/null 2>&1; then
        log "SUCCESS" "Installed package upgrades"
    else
        log "ERROR" "Failed to upgrade packages"
        return 1
    fi
}

remove_bloatware() {
    local package

    for package in "${BLOATWARE_PACKAGES[@]}"; do
        if dpkg-query -W -f='${Status}' "$package" 2>/dev/null | grep -q "install ok installed"; then
            if DEBIAN_FRONTEND=noninteractive apt-get remove -y "$package" >/dev/null 2>&1; then
                log "SUCCESS" "Removed package $package"
            else
                log "ERROR" "Failed to remove package $package"
                return 1
            fi
        else
            log "SUCCESS" "Package $package already absent"
        fi
    done
}

install_security_tools() {
    local package

    for package in "${SECURITY_PACKAGES[@]}"; do
        if dpkg-query -W -f='${Status}' "$package" 2>/dev/null | grep -q "install ok installed"; then
            log "SUCCESS" "Package $package already installed"
        else
            if DEBIAN_FRONTEND=noninteractive apt-get install -y "$package" >/dev/null 2>&1; then
                log "SUCCESS" "Installed package $package"
            else
                log "ERROR" "Failed to install package $package"
                return 1
            fi
        fi
    done
}

harden_system() {
    update_system || return 1
    remove_bloatware || return 1
    install_security_tools || return 1

    log "SUCCESS" "System hardening completed"
}
