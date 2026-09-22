#!/bin/bash

update_system() {
    local output
    local rc

    output=$(DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout="$APT_LOCK_TIMEOUT" update 2>&1)
    rc=$?

    if [ "$rc" -ne 0 ]; then
        log "ERROR" "Failed to update package repositories (exit $rc): $(printf '%s\n' "$output" | tail -n 5 | tr '\n' ' ')"
        return 1
    fi

    log "INFO" "Package repositories updated"

    output=$(DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout="$APT_LOCK_TIMEOUT" upgrade -y 2>&1)
    rc=$?

    if [ "$rc" -ne 0 ]; then
        log "ERROR" "Failed to upgrade packages (exit $rc): $(printf '%s\n' "$output" | tail -n 5 | tr '\n' ' ')"
        return 1
    fi

    if printf '%s\n' "$output" | grep -Eq '^0 upgraded, 0 newly installed, 0 to remove'; then
        log "WARN" "Package updates skipped (already up to date)"
    else
        log "INFO" "Package upgrades installed"
    fi
}

remove_bloatware() {
    local package

    for package in "${BLOATWARE_PACKAGES[@]}"; do
        if dpkg-query -W -f='${Status}' "$package" 2>/dev/null | grep -q "install ok installed"; then
            if DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout="$APT_LOCK_TIMEOUT" remove -y "$package" >/dev/null 2>&1; then
                REMOVED_PACKAGES+=("$package")
                log "INFO" "Removed package $package"
            else
                log "ERROR" "Failed to remove package $package"
                return 1
            fi
        else
            log "INFO" "Package $package already absent"
        fi
    done
}

install_security_tools() {
    local package

    for package in "${SECURITY_PACKAGES[@]}"; do
        if dpkg-query -W -f='${Status}' "$package" 2>/dev/null | grep -q "install ok installed"; then
            log "INFO" "Package $package already installed"
        else
            if DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout="$APT_LOCK_TIMEOUT" install -y "$package" >/dev/null 2>&1; then
                INSTALLED_PACKAGES+=("$package")
                log "INFO" "Installed package $package"
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

    log "INFO" "System hardening completed"
}
