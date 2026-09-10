#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="$SCRIPT_DIR/config/harden.cfg"

if [ ! -f "$CONFIG_FILE" ]; then
    echo "ERROR: Configuration file not found: $CONFIG_FILE" >&2
    exit 1
fi

source "$CONFIG_FILE"

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp

    timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf '%s [%s] %s\n' "$timestamp" "$level" "$message" >> "$LOG_FILE"
}

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: harden.sh must be run as root" >&2
    exit 1
fi

touch "$LOG_FILE" || {
    echo "ERROR: Unable to access $LOG_FILE" >&2
    exit 1
}

log "INFO" "Hardening framework initialized"

for library in network ssh identity system; do
    library_file="$SCRIPT_DIR/lib/${library}.sh"

    if [ ! -f "$library_file" ]; then
        log "ERROR" "Missing library: $library_file"
        exit 1
    fi

    source "$library_file" || {
        log "ERROR" "Failed to load library: $library_file"
        exit 1
    }

    log "INFO" "Loaded library: $library"
done

harden_system || {
    log "ERROR" "System hardening failed"
    exit 1
}

harden_network || {
    log "ERROR" "Network hardening failed"
    exit 1
}

harden_ssh || {
    log "ERROR" "SSH hardening failed"
    exit 1
}

harden_identity || {
    log "ERROR" "Identity hardening failed"
    exit 1
}

log "INFO" "Hardening framework execution completed"
