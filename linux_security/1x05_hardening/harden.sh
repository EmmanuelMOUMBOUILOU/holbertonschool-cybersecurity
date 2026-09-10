#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="$SCRIPT_DIR/config/harden.cfg"

WARNINGS=()
ERRORS=()
INSTALLED_PACKAGES=()
REMOVED_PACKAGES=()
REMOVED_USERS=()

if [ ! -f "$CONFIG_FILE" ]; then
    echo "ERROR: Configuration file not found: $CONFIG_FILE" >&2
    exit 1
fi

source "$CONFIG_FILE"

AUDIT_REPORT="$PWD/$AUDIT_REPORT_NAME"

format_list() {
    local result=""
    local item

    for item in "$@"; do
        if [ -n "$result" ]; then
            result+=", "
        fi
        result+="$item"
    done

    printf '%s' "$result"
}

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp

    case "$level" in
        INFO|WARN|ERROR)
            ;;
        *)
            level="INFO"
            ;;
    esac

    timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf '%s [%s] %s\n' "$timestamp" "$level" "$message" >> "$LOG_FILE"

    case "$level" in
        WARN)
            WARNINGS+=("$message")
            ;;
        ERROR)
            ERRORS+=("$message")
            ;;
    esac
}

generate_audit_report() {
    local exit_code="$1"
    local compliance_status="PASS"
    local procedure_status="[INFO] Hardening procedure completed successfully."
    local allowed_ports="$SSH_PORT"
    local item

    [ "$ALLOW_HTTP" = "yes" ] && allowed_ports+=", $HTTP_PORT"
    [ "$ALLOW_HTTPS" = "yes" ] && allowed_ports+=", $HTTPS_PORT"

    if [ "$exit_code" -ne 0 ] || [ "${#ERRORS[@]}" -gt 0 ]; then
        compliance_status="FAIL"
        procedure_status="[ERROR] Hardening procedure completed with errors."
    fi

    {
        echo "==============================================="
        echo " HARDENING AUDIT REPORT - $(date '+%Y-%m-%d %H:%M:%S')"
        echo "==============================================="
        echo
        echo "$procedure_status"
        echo "[INFO] SSH configured on port $SSH_PORT."
        echo "[INFO] SSH password authentication: $PASSWORD_AUTHENTICATION."
        echo "[INFO] SSH public key authentication: $PUBKEY_AUTHENTICATION."
        echo "[INFO] SSH root login: $PERMIT_ROOT_LOGIN."
        echo "[INFO] Firewall policy file: $FIREWALL_RULES_FILE."
        echo "[INFO] Firewall allowed TCP ports: $allowed_ports."

        if [ "${#REMOVED_USERS[@]}" -gt 0 ]; then
            echo "[INFO] ${#REMOVED_USERS[@]} unauthorized users removed: $(format_list "${REMOVED_USERS[@]}")."
        else
            echo "[INFO] 0 unauthorized users removed; no non-compliant users found."
        fi

        if [ "${#INSTALLED_PACKAGES[@]}" -gt 0 ]; then
            echo "[INFO] Installed this run: $(format_list "${INSTALLED_PACKAGES[@]}")."
        else
            echo "[INFO] Installed this run: none; required packages were already present."
        fi

        echo "[INFO] Required security packages verified: $(format_list "${SECURITY_PACKAGES[@]}")."

        if [ "${#REMOVED_PACKAGES[@]}" -gt 0 ]; then
            echo "[INFO] Removed this run: $(format_list "${REMOVED_PACKAGES[@]}")."
        else
            echo "[INFO] Removed this run: none; prohibited packages were already absent."
        fi

        echo "[INFO] Prohibited packages verified absent: $(format_list "${BLOATWARE_PACKAGES[@]}")."

        for item in "${WARNINGS[@]}"; do
            echo "[WARN] $item"
        done

        for item in "${ERRORS[@]}"; do
            echo "[ERROR] $item"
        done

        echo
        echo "==============================================="
        echo " COMPLIANCE STATUS: $compliance_status"
        echo "==============================================="
    } > "$AUDIT_REPORT"

    chmod 644 "$AUDIT_REPORT"
}

finalize() {
    local exit_code=$?
    generate_audit_report "$exit_code"
}

trap finalize EXIT

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
