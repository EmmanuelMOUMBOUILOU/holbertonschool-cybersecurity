#!/bin/bash
set -eu

# LogiCorp Capstone - nftables panic button
# Usage:
#   ./panic.sh arm [seconds]
#   ./panic.sh cancel
#   ./panic.sh restore

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: run this script as root."
    exit 1
fi

BACKUP="/root/logicorp-nftables-before-hardening.nft"
PIDFILE="/run/logicorp-panic.pid"
LOG="/root/logicorp-panic.log"

case "${1:-}" in
    arm)
        DELAY="${2:-180}"
        if ! nft list ruleset >/dev/null 2>&1; then
            echo "ERROR: nftables cannot be managed in this environment."
            echo "The lab/container may be missing CAP_NET_ADMIN."
            exit 1
        fi

        {
            echo "flush ruleset"
            nft list ruleset
        } > "$BACKUP"

        if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
            echo "A panic rollback is already armed."
            exit 1
        fi

        nohup sh -c "sleep $DELAY; nft -f '$BACKUP'; echo \"Automatic rollback executed at \$(date)\" >> '$LOG'; rm -f '$PIDFILE'" \
            >/dev/null 2>&1 &
        echo $! > "$PIDFILE"

        echo "Panic rollback armed for ${DELAY}s."
        echo "Backup: $BACKUP"
        echo "After successful validation run: ./panic.sh cancel"
        ;;
    cancel)
        if [ -f "$PIDFILE" ]; then
            kill "$(cat "$PIDFILE")" 2>/dev/null || true
            rm -f "$PIDFILE"
            echo "Automatic rollback cancelled."
        else
            echo "No armed rollback found."
        fi
        ;;
    restore)
        if [ ! -f "$BACKUP" ]; then
            echo "ERROR: no backup found at $BACKUP"
            exit 1
        fi
        nft -f "$BACKUP"
        echo "Previous nftables configuration restored."
        ;;
    *)
        echo "Usage: $0 {arm [seconds]|cancel|restore}"
        exit 1
        ;;
esac
